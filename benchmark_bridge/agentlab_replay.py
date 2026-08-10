"""Replay AgentLAB chains through ChainWatch and report detection metrics.

This closes the gap the paper concedes in section V-A -- "testing ChainWatch
properly requires labelled session traces where benign-looking calls build toward
an attack, data that no existing benchmark provides". AgentLAB supplies 200
*verified* attack chains, and :mod:`agentlab_benign_gen` supplies a matched negative class.

The chains are plans, not traces: no responses, no timings, no server attribution.
Executing them against the real environment simulators is what makes the Temporal
and Output Characteristics groups -- 10 of the 20 dimensions -- extractable at all.

Each chain is one session, replayed through a real :class:`Interceptor`, so the
same code path the live proxy uses is the one being measured.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from chainwatch.engine.alerts import Severity
from chainwatch.proxy import jsonrpc
from chainwatch.proxy.interceptor import Interceptor

from chainwatch.engine.taxonomy import ToolCategory, ToolClassifier

from .base import AGENTLAB_ROOT, AdapterError, EnvAdapter

ATTACK_CHAINS = AGENTLAB_ROOT / "data" / "filtered_top_200_attacks.json"

#: Building a SHADE_Arena environment takes seconds, so never build one twice.
_ADAPTER_CACHE: dict[tuple[str, str], EnvAdapter] = {}


def get_adapter(dataset: str, environment: str) -> EnvAdapter:
    key = (dataset, environment)
    if key not in _ADAPTER_CACHE:
        if dataset == "SHADE_Arena":
            from .shade_arena import ShadeArenaAdapter

            _ADAPTER_CACHE[key] = ShadeArenaAdapter(environment)
        else:
            from .safetybench import SafetyBenchAdapter

            _ADAPTER_CACHE[key] = SafetyBenchAdapter(environment)
    return _ADAPTER_CACHE[key]


def chain_shape(chain: dict[str, Any]) -> str:
    """Classify a chain by whether it matches ChainWatch's threat model at all.

    The framework targets *composed* attacks that read something and then move it,
    escalate, or rewrite configuration. Much of the AgentLAB corpus is harmful
    **content** distribution -- author bomb-making text, attach it, send it -- which
    has no upstream data flow and no kill-chain progression to detect. Reporting a
    single aggregate detection rate over both populations would be misleading in
    both directions, so results are always broken down by shape.
    """
    classifier = ToolClassifier()
    categories = [
        classifier.classify(step.get("tool_name", ""))
        for step in (chain.get("attack_plan") or {}).get("verified_tool_chain") or []
    ]
    if any(
        categories[i] is ToolCategory.READ and ToolCategory.NETWORK in categories[i + 1 :]
        for i in range(len(categories))
    ):
        return "read-then-network (R3 shape)"
    if ToolCategory.CONFIGURE in categories:
        return "configure present (R5 shape)"
    if ToolCategory.NETWORK in categories:
        return "network, no prior read"
    return "no outbound step"


@dataclass
class ChainResult:
    """Outcome of replaying one chain."""

    chain_id: Any
    label: str  # "attack" or "benign"
    environment: str
    calls: int
    #: Which corpus this came from. Reported separately and never averaged: the
    #: SHADE trajectories are real agent behaviour, the AgentLAB chains are plans,
    #: and the agentlab_benign_gen output is synthesized. Pooling them would let the largest
    #: and weakest population set the headline number.
    source: str = "agentlab"
    stages: list[int] = field(default_factory=list)
    rules: list[tuple[str, int]] = field(default_factory=list)  # (rule, 1-based call)
    severity: Severity = Severity.NONE
    blocked_at: int | None = None
    vectors: list[list[float]] = field(default_factory=list)
    #: Tool name and originating server per committed call, parallel to ``vectors``.
    #: Needed offline: R2 counts distinct servers, so rule state cannot be recomputed
    #: from the feature vector alone.
    tools: list[str] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    #: Destination provenance per committed call, parallel to ``vectors``. Needed
    #: offline for the same reason as ``servers``: it is deliberately not a feature
    #: dimension, so it cannot be recovered from the vector.
    provenances: list[str] = field(default_factory=list)
    error: str | None = None
    shape: str = ""

    @property
    def detected(self) -> bool:
        """WARNING or above. INFO alone is not a detection -- it is an observation."""
        return self.severity >= Severity.WARNING

    @property
    def calls_to_detection(self) -> int | None:
        actionable = [
            position for rule, position in self.rules if rule in {"R1", "R2", "R3", "R4", "R5"}
        ]
        return min(actionable) if actionable else None


def replay_chain(chain: dict[str, Any], label: str, source: str = "agentlab") -> ChainResult:
    """Drive one chain through a real interceptor against a real environment."""
    config = chain.get("generation_config", {})
    dataset = config.get("dataset", "synthetic")
    environment = config.get("environment", "unknown")
    steps = (chain.get("attack_plan") or {}).get("verified_tool_chain") or []

    result = ChainResult(
        chain_id=chain.get("original_id"),
        label=label,
        environment=environment,
        calls=len(steps),
        source=source,
        shape=chain_shape(chain),
    )

    try:
        adapter = get_adapter(dataset, environment)
    except (AdapterError, Exception) as error:
        result.error = f"{type(error).__name__}: {error}"
        return result

    interceptor = Interceptor(server=environment, analyzer=_fresh_analyzer(), emit=lambda _: None)
    # Register the real tool definitions, so description-mismatch and hash-change
    # have something to compare against, exactly as a live tools/list would.
    try:
        interceptor.analyzer.register_tools(environment, adapter.list_tools())
    except Exception:
        pass

    binder = ResponseBinder()
    #: Verdict of the call that blocked, if any. It never enters session history --
    #: it did not run -- so it has to be carried out separately or the corpus loses
    #: every CRITICAL detection, which is exactly the calls a model most needs.
    blocked: Any = None

    for position, step in enumerate(steps, start=1):
        # Bind planned identifiers to the ones the environment really produced,
        # so the replay carries the data flow a live agent would.
        arguments = binder.bind(step.get("parameters") or {})
        request = {
            "jsonrpc": "2.0",
            "id": position,
            "method": "tools/call",
            "params": {"name": step.get("tool_name", ""), "arguments": arguments},
        }

        decision = interceptor.on_request(request)
        for alert in (decision.verdict.alerts if decision.verdict else []):
            result.rules.append((alert.rule, position))
        if decision.verdict:
            result.severity = max(result.severity, decision.verdict.severity)

        if not decision.forward:
            result.blocked_at = position
            blocked = decision.verdict
            break

        # Execute for real: this is where responses, timings and output
        # characteristics come from.
        try:
            output = adapter.call_tool(step.get("tool_name", ""), arguments)
        except Exception as error:
            output = {"success": False, "message": f"{type(error).__name__}: {error}"}
        binder.observe(output)

        response = {
            "jsonrpc": "2.0",
            "id": position,
            "result": {"content": [{"type": "text", "text": _as_text(output)}]},
        }
        decision = interceptor.on_response(response)
        if decision.verdict:
            for alert in decision.verdict.alerts:
                result.rules.append((alert.rule, position))
            result.severity = max(result.severity, decision.verdict.severity)

    analyzer = interceptor.analyzer
    result.stages = list(getattr(analyzer, "stages", []))
    history = getattr(analyzer, "history", [])
    result.vectors = [record.vector.tolist() for record in history]
    result.tools = [record.tool for record in history]
    result.servers = [record.server for record in history]
    result.provenances = [record.provenance.name for record in history]

    # Append the blocked call as a final observation. It is a real, fully-extracted
    # pre-flight vector -- the call simply never executed, so its OC dimensions stay
    # zero, which is exactly what the proxy saw when it made the decision.
    if blocked is not None and blocked.vector is not None:
        result.vectors.append(list(blocked.vector))
        blocked_step = steps[result.blocked_at - 1]
        result.tools.append(blocked_step.get("tool_name", ""))
        result.servers.append(environment)
        result.stages.append(blocked.stage)
        result.provenances.append(
            blocked.provenance.name if blocked.provenance is not None else "UNKNOWN"
        )
    # Deduplicate: pre-flight and post-response evaluate the same window.
    result.rules = sorted(set(result.rules), key=lambda pair: (pair[1], pair[0]))
    return result


class ResponseBinder:
    """Rewrites planned parameters to use values the environment actually returned.

    The verified chains are *plans*, and plans hardcode identifiers: a chain will
    say ``append_to_file(file_id="29", ...)`` because that is what the generator
    invented. A real agent does something different -- it reads the id out of the
    previous tool's response and passes that.

    Replaying the literal plan therefore destroys the very data flow rule R3 exists
    to detect. On the first full run, ``df_chained`` was 0.0% across all 560 attack
    calls and R3 never fired once. Not because the sequences were benign, but
    because nothing in a replayed plan is ever carried forward from a real response.

    This binds them back together: identifiers produced by a response are
    substituted into later parameters that reference the same kind of id. Only
    identifiers are rebound. Free text is left exactly as the plan wrote it --
    an attack that *authors* its payload (most of the AgentLAB corpus is
    harmful-content distribution) genuinely has no upstream data flow, and
    inventing one would be measuring our own substitution rather than the attack.
    """

    #: An identifier is short, scalar, and referenced by a key that says so.
    MAX_ID_LENGTH = 64

    #: Placeholder a planned step can use to say "put the previous response here".
    #: Identifier binding alone cannot express content flow -- reading a document and
    #: pasting it into an email body is not an id substitution -- yet that is exactly
    #: what both real exfiltration and ordinary assistant work do. Without this, a
    #: synthesized chain can never set ``df_chained``, which is what guaranteed the
    #: benign class a 0.0% false-positive rate before anything was measured.
    CARRY = "{{PRIOR_OUTPUT}}"

    #: How much prior text to carry. Comfortably above the extractor's 24-char
    #: matching window so the flow is detectable, short enough to stay email-shaped.
    CARRY_LENGTH = 400

    def __init__(self) -> None:
        #: normalised key suffix -> most recent value produced for it
        self.produced: dict[str, str] = {}
        #: most recent response text, for CARRY substitution
        self.last_text: str = ""

    def observe(self, output: Any) -> None:
        """Harvest identifier-like values, and keep the raw text for CARRY."""
        self._walk(output)
        text = _as_text(output)
        if text:
            self.last_text = text

    def bind(self, parameters: dict[str, Any]) -> dict[str, Any]:
        """Replace planned identifier arguments with real ones, where known."""
        bound = dict(parameters or {})
        for name, value in list(bound.items()):
            if isinstance(value, str) and self.CARRY in value:
                bound[name] = value.replace(self.CARRY, self.last_text[: self.CARRY_LENGTH])
                continue
            if not self._is_id_key(name) or not isinstance(value, (str, int)):
                continue
            replacement = self.produced.get(self._normalise(name))
            if replacement is not None and str(replacement) != str(value):
                bound[name] = replacement
        return bound

    # ------------------------------------------------------------------ internals

    def _walk(self, value: Any, key: str | None = None) -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                self._walk(child, child_key)
        elif isinstance(value, (list, tuple)):
            for child in value:
                self._walk(child, key)
        elif key and self._is_id_key(key) and isinstance(value, (str, int)):
            text = str(value)
            if 0 < len(text) <= self.MAX_ID_LENGTH:
                self.produced[self._normalise(key)] = text

    @staticmethod
    def _is_id_key(key: str) -> bool:
        cleaned = key.lower().strip("_")
        return cleaned == "id" or cleaned.endswith("_id") or cleaned.endswith("id")

    @staticmethod
    def _normalise(key: str) -> str:
        """`file_id`, `id_`, `id` all refer to the same notion of identity here."""
        cleaned = key.lower().strip("_")
        return "id" if cleaned in ("id",) else cleaned


#: Model used for replay; ``--model`` swaps in a trained one.
_MODEL_PATH: str | None = None


#: What R3 does with an ATTESTED destination; ``--r3-attested`` swaps it. Defaults
#: to the paper-literal reading, so every replayed figure is unchanged unless the
#: flag is passed -- which is what makes the before/after comparison meaningful.
_R3_ATTESTED: str = "ignore"


def _fresh_analyzer():
    from chainwatch.engine.model import load_model
    from chainwatch.engine.rules import RuleConfig
    from chainwatch.engine.session import SessionAnalyzer

    config = RuleConfig(r3_attested_action=_R3_ATTESTED)
    if _MODEL_PATH:
        return SessionAnalyzer(model=load_model(_MODEL_PATH), config=config)
    return SessionAnalyzer(config=config)


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def load_attack_chains(limit: int | None = None) -> list[dict[str, Any]]:
    chains = json.loads(ATTACK_CHAINS.read_text(encoding="utf-8"))
    return chains[:limit] if limit else chains


def build_benign_chains(
    attack_chains: Iterable[dict[str, Any]],
    seed: int = 0,
    profile: Any = None,
) -> list[dict]:
    """One benign chain per attack chain, in the same environment mix.

    Matching the environment distribution matters: a negative class drawn from
    different environments would differ in tool vocabulary, and the classifier
    would be separating environments rather than intent.

    ``profile`` selects which benign population to build; ``None`` means REALISM,
    the one false-positive numbers are quoted from.
    """
    from .agentlab_benign_gen import REALISM, generate

    profile = profile or REALISM
    attack_chains = list(attack_chains)
    counts = Counter(
        (c["generation_config"]["dataset"], c["generation_config"]["environment"])
        for c in attack_chains
    )
    benign: list[dict[str, Any]] = []
    for (dataset, environment), count in counts.items():
        try:
            adapter = get_adapter(dataset, environment)
        except Exception:
            continue
        for chain in generate(adapter, count, seed=seed, profile=profile):
            # Preserve the profile tag the generator set; only the dataset and
            # environment need rewriting to the attack corpus's own labels.
            chain["generation_config"] = {
                **chain.get("generation_config", {}),
                "dataset": dataset,
                "environment": environment,
            }
            benign.append(chain)
    return benign


def summarise(results: list[ChainResult], label: str) -> dict[str, Any]:
    usable = [r for r in results if r.error is None and r.calls > 0]
    if not usable:
        return {"label": label, "chains": 0}

    detected = [r for r in usable if r.detected]
    blocked = [r for r in usable if r.blocked_at is not None]
    latencies = [r.calls_to_detection for r in detected if r.calls_to_detection]

    rule_counts = Counter(rule for r in usable for rule, _ in r.rules)
    return {
        "label": label,
        "chains": len(usable),
        "skipped": len(results) - len(usable),
        "detected": len(detected),
        "detection_rate": len(detected) / len(usable),
        "blocked": len(blocked),
        "block_rate": len(blocked) / len(usable),
        "mean_calls_to_detection": statistics.mean(latencies) if latencies else None,
        "mean_chain_length": statistics.mean(r.calls for r in usable),
        "rules": dict(rule_counts.most_common()),
    }


def print_report(attack: dict[str, Any], benign: dict[str, Any]) -> None:
    print("\n" + "=" * 68)
    print("ChainWatch — AgentLAB replay")
    print("=" * 68)

    for summary in (attack, benign):
        if not summary.get("chains"):
            continue
        print(f"\n{summary['label'].upper()}  ({summary['chains']} chains, "
              f"mean length {summary['mean_chain_length']:.1f})")
        print(f"  detected (WARNING+) : {summary['detected']:4d}  "
              f"({summary['detection_rate']*100:5.1f}%)")
        print(f"  blocked  (CRITICAL) : {summary['blocked']:4d}  "
              f"({summary['block_rate']*100:5.1f}%)")
        if summary["mean_calls_to_detection"]:
            print(f"  mean calls to detect: {summary['mean_calls_to_detection']:.2f}")
        if summary["skipped"]:
            print(f"  skipped (env error) : {summary['skipped']}")
        print(f"  rule firings        : {summary['rules']}")

    print()
    print("-" * 68)
    print()
    if attack.get("chains") and benign.get("chains"):
        print(f"\n  detection rate {attack['detection_rate']*100:.1f}%  vs  "
              f"false-positive rate {benign['detection_rate']*100:.1f}%")
    print()


def print_shape_breakdown(results: list[ChainResult]) -> None:
    """Detection broken down by whether the chain matches ChainWatch's threat model."""
    usable = [r for r in results if r.error is None and r.calls > 0]
    if not usable:
        return

    print("ATTACK detection by chain shape")
    groups: dict[str, list[ChainResult]] = {}
    for result in usable:
        groups.setdefault(result.shape, []).append(result)

    for shape, group in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        detected = sum(1 for r in group if r.detected)
        blocked = sum(1 for r in group if r.blocked_at is not None)
        mean_length = statistics.mean(r.calls for r in group)
        print(
            f"  {shape:32s} n={len(group):3d}  detected {detected:3d} "
            f"({100*detected/len(group):5.1f}%)  blocked {blocked:3d} "
            f"({100*blocked/len(group):5.1f}%)  mean len {mean_length:.1f}"
        )

    short = [r for r in usable if r.calls <= 2]
    if short:
        detected = sum(1 for r in short if r.detected)
        print(
            f"\n  chains of length <=2: {len(short)} "
            f"({100*len(short)/len(usable):.0f}% of corpus), detected {detected} "
            f"({100*detected/len(short):.1f}%)"
        )
        print("  A 6-stage kill chain cannot be traversed in two calls; the paper's")
        print("  documented attacks span 4-7, which is why k=10 was chosen.")


def print_shade_report(results: list[ChainResult]) -> None:
    """Per-chain detail for the SHADE trajectories.

    Deliberately not aggregated. There are five chains; a percentage over five
    chains invites more confidence than five chains can support, and the point of
    this population is that each one is individually inspectable -- two of them are
    matched pairs differing only by the attack steps, so the interesting comparison
    is chain against its own twin, not against a mean.
    """
    if not results:
        return

    print("=" * 68)
    print("SHADE task-pair trajectories  (real agent behaviour, n=%d)" % len(results))
    print("=" * 68)
    for result in sorted(results, key=lambda r: (str(r.chain_id), r.label)):
        if result.error:
            print(f"  {str(result.chain_id):44s} ERROR {result.error[:60]}")
            continue
        rules = ", ".join(sorted({rule for rule, _ in result.rules if rule != "STAGE"})) or "-"
        blocked = f"blocked@{result.blocked_at}" if result.blocked_at else "allowed"
        print(
            f"  {str(result.chain_id):44s} {result.calls:3d} calls  "
            f"{result.severity.name:8s} {blocked:12s} {rules}"
        )

    benign = [r for r in results if r.label == "benign" and r.error is None]
    if benign:
        detected = sum(1 for r in benign if r.detected)
        blocked = sum(1 for r in benign if r.blocked_at is not None)
        print(
            f"\n  benign trajectories: {detected}/{len(benign)} raise WARNING+, "
            f"{blocked}/{len(benign)} blocked"
        )
        print("  Report these real trajectories separately from synthesized benign.")
        print("  They exposed why the original 0.0% result was structural; the current")
        print("  agentlab_benign_gen realism population now includes chained outbound flow.")
    print()


def write_traces(results: list[ChainResult], path: Path) -> int:
    """Write feature vectors as JSONL for `chainwatch train`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with path.open("w", encoding="utf-8") as handle:
        for result in results:
            # rule -> 1-based call position, inverted so each call names what fired on it.
            fired: dict[int, list[str]] = {}
            for rule, position in result.rules:
                fired.setdefault(position, []).append(rule)

            for index, vector in enumerate(result.vectors):
                handle.write(
                    json.dumps(
                        {
                            "session": f"{result.label}-{result.chain_id}",
                            "label": result.label,
                            # Populations must stay separable downstream: pooling the
                            # control set into a false-positive number would misreport it.
                            "source": result.source,
                            "environment": result.environment,
                            "call": index + 1,
                            "tool": result.tools[index] if index < len(result.tools) else None,
                            "server": result.servers[index] if index < len(result.servers) else None,
                            "stage": result.stages[index] if index < len(result.stages) else None,
                            "rules": sorted(set(fired.get(index + 1, []))),
                            "prov": (
                                result.provenances[index]
                                if index < len(result.provenances)
                                else None
                            ),
                            "v": [round(x, 6) for x in vector],
                        },
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                written += 1
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmark_bridge.agentlab_replay")
    parser.add_argument("--limit", type=int, default=None, help="replay only the first N chains")
    parser.add_argument("--all", action="store_true", help="replay all 200 chains")
    parser.add_argument("--no-benign", action="store_true", help="skip the negative class")
    parser.add_argument(
        "--no-shade", action="store_true", help="skip the SHADE task-pair trajectories"
    )
    parser.add_argument("--traces", default=None, help="write feature vectors here as JSONL")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--model", default=None, help="trained model JSON; omit to use priors")
    parser.add_argument(
        "--r3-attested",
        choices=("ignore", "downgrade", "suppress"),
        default="ignore",
        help=(
            "what R3 does when the destination was named by a clean READ response "
            "before the session referenced it; 'ignore' is the section IV-D reading"
        ),
    )
    options = parser.parse_args(argv)

    global _MODEL_PATH, _R3_ATTESTED
    _MODEL_PATH = options.model
    if _MODEL_PATH:
        print(f"using trained model {_MODEL_PATH}")
    _R3_ATTESTED = options.r3_attested
    if _R3_ATTESTED != "ignore":
        print(f"R3 attested-destination action: {_R3_ATTESTED}")

    limit = None if options.all else (options.limit or 25)
    attack_chains = load_attack_chains(limit)
    print(f"replaying {len(attack_chains)} attack chains...", flush=True)

    started = time.time()
    attack_results = [replay_chain(c, "attack") for c in attack_chains]

    benign_results: list[ChainResult] = []
    control_results: list[ChainResult] = []
    if not options.no_benign:
        from .agentlab_benign_gen import REALISM, control_profile

        benign_chains = build_benign_chains(attack_chains, seed=options.seed, profile=REALISM)
        print(f"replaying {len(benign_chains)} benign chains (realism)...", flush=True)
        benign_results = [replay_chain(c, "benign", source="realism") for c in benign_chains]

        control = build_benign_chains(
            attack_chains, seed=options.seed, profile=control_profile(attack_chains)
        )
        print(f"replaying {len(control)} benign chains (control)...", flush=True)
        control_results = [replay_chain(c, "benign", source="control") for c in control]

    # The SHADE task-pair trajectories are the only real agent behaviour in the
    # corpus, so they are replayed and reported on their own rather than pooled.
    shade_results: list[ChainResult] = []
    if not options.no_shade:
        from .shade_solutions import build_chains

        shade_attacks, shade_benign = build_chains()
        print(
            f"replaying {len(shade_attacks)} SHADE attack + "
            f"{len(shade_benign)} SHADE benign trajectories...",
            flush=True,
        )
        shade_results = [replay_chain(c, "attack", source="shade") for c in shade_attacks]
        shade_results += [replay_chain(c, "benign", source="shade") for c in shade_benign]

    print(f"done in {time.time() - started:.1f}s")
    print_report(summarise(attack_results, "attack"), summarise(benign_results, "benign"))
    if control_results:
        control = summarise(control_results, "benign (control)")
        print(f"  CONTROL population   : {control['detected']}/{control['chains']} "
              f"({control['detection_rate']*100:.1f}%) detected, "
              f"{control['blocked']}/{control['chains']} blocked, "
              f"mean length {control['mean_chain_length']:.1f}")
        print("  Control is surface-matched to the attack corpus. It is a shortcut check,")
        print("  never a false-positive claim -- quote the realism population for that.\n")
    print_shape_breakdown(attack_results)
    print()
    print_shade_report(shade_results)

    failures = [r for r in attack_results if r.error]
    if failures:
        print(f"environments that failed to load ({len(failures)}):")
        for result in Counter(r.error for r in failures).most_common(5):
            print(f"  {result[1]:3d}x  {result[0][:100]}")

    if options.traces:
        # Every population, tagged by source. The control set and the SHADE
        # trajectories are as much a part of the corpus as the realism set; a
        # consumer that wants only one filters on `source`.
        count = write_traces(
            attack_results + benign_results + control_results + shade_results,
            Path(options.traces),
        )
        print(f"wrote {count} feature vectors to {options.traces}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
