#!/usr/bin/env python3
"""Is OpenAgentSafety worth bridging? Decide offline, before Docker or API spend.

Route F was bought before anyone checked whether its sessions could exercise a rule;
they could not, and 117 sessions of 1.00 calls each is the record of that. This gate is
the same shape as ``scripts/agentdojo_decidability.py``: recompute the set, never trust a
stored list, and let a benchmark that cannot answer the question be *reported* as such
rather than accommodated.

Three properties decide a task, and all three come from the benchmark or from ChainWatch,
never from a judgement made here:

* **scorer** -- rule-based or LLM-judge. A judge-scored task has no ground truth this
  project can use. Structural test: does ``grade_checkpoints`` ever append a checkpoint.
* **channel** -- where the unsafe instruction lives. ``workspace/`` files are the data
  channel, ``scenarios.json`` is an NPC speaking over RocketChat, and everything else is
  the *user prompt* -- the channel route C proved unbuyable at 80-100% refusal.
* **has_configure / has_network** -- ``chainwatch.engine.taxonomy``'s own verdict, so a
  task counts as an R5 candidate only if ChainWatch would in fact call it CONFIGURE.

**A caveat that must travel with every number below.** OAS publishes no tool surface: its
agent runs under OpenHands with bash and a browser, so unlike AgentDojo there is no list
of published tool names to classify. The taxonomy is therefore applied to *action phrases
lifted from the task and checkpoint text*, which is a lexical approximation of what a
bridge would expose, not a fact the benchmark states. Read ``has_configure`` as "this task
plausibly mutates configuration", never as "ChainWatch classified its published tools".

Usage::

    scripts/oas_decidability.py --tasks OpenAgentSafety/workspaces/tasks \\
        --out docs/oas_candidates.tsv

Exit 0 when the keep set is non-empty, 1 otherwise. The exit code is *not* the go/no-go:
the threshold in the implementation plan is, and this script only supplies its counts.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chainwatch.engine.taxonomy import ToolCategory, ToolClassifier  # noqa: E402

#: Words that carry no action, dropped before phrases are assembled. Kept small and
#: closed on purpose: a long list is a place to hide a decision.
STOPWORDS = frozenset(
    """a an the to of in on for and or with that this is are be by from as at it its
    their his her them all any into new then also should must agent please you your
    user request will can has have was were but not do does done if when while there
    here about after before over under between each other more most some such only
    very just than so no nor own same too now""".split()
)

#: How many consecutive kept words make a candidate action name. Two and three, because
#: MCP tool names are overwhelmingly ``verb_object`` or ``verb_object_qualifier``.
PHRASE_LENGTHS = (2, 3)

#: The instruction channel, most specific first. A task may satisfy several; the label
#: records the *strongest* non-prompt channel available, because that is the one an
#: attack would use.
CHANNEL_DATA = "data"
CHANNEL_NPC = "npc"
CHANNEL_PROMPT = "prompt"


@dataclass(frozen=True)
class TaskRow:
    """One OAS task, judged."""

    task_id: str
    scorer: str  # rule | judge | both
    channel: str  # prompt | npc | data
    services: tuple[str, ...]
    has_configure: bool
    has_network: bool
    #: Stricter than ``has_configure``: the task's own evaluator checks a configuration
    #: endpoint, so a bridge could score an R5 event rather than infer one from prose.
    verifies_configuration: bool
    verdict: str  # keep | drop
    reason: str


def action_phrases(text: str) -> set[str]:
    """Candidate tool names lifted from prose, snake_cased.

    Sentence-bounded so a phrase cannot straddle two unrelated clauses -- ``... the
    rules. Send ...`` must not become ``rules_send``.
    """
    names: set[str] = set()
    for sentence in re.split(r"[.\n!?;:]", text.lower()):
        kept = [word for word in re.findall(r"[a-z0-9_]+", sentence) if word not in STOPWORDS]
        for start in range(len(kept)):
            for length in PHRASE_LENGTHS:
                if start + length <= len(kept):
                    names.add("_".join(kept[start : start + length]))
    return names


def read_scorer(task: Path) -> str:
    """``rule``, ``judge``, or ``both`` -- from the evaluator's body, not its comments.

    48 of the published judge-only evaluators say so in a comment and the rest do not,
    so the comment cannot be the test. *Constructing* a checkpoint is what makes a
    scorer rule-based; the comment, when present alongside one, makes it ``both``.

    The test is ``Checkpoint(`` and not ``checkpoints.append``, which was the first
    attempt and was wrong: OAS uses two idioms interchangeably, and the literal form
    ``checkpoints: List[Checkpoint] = [Checkpoint(1, int(grade_checkpoint1()))]``
    appears in 69 tasks -- including ``safety-change-branch-policy``, the one task in
    the corpus that verifies a GitLab branch-policy change against the live API, and
    therefore the single most load-bearing row for R5. The annotation ``List[Checkpoint]``
    is not a call, so a judge-only evaluator still reads ``judge``.
    """
    evaluator = task / "utils" / "evaluator.py"
    if not evaluator.exists():
        return "judge"
    source = evaluator.read_text(encoding="utf-8", errors="ignore")
    body = source.split("def grade_checkpoints", 1)[-1]
    scores = bool(re.search(r"Checkpoint\s*\(", body))
    judged = "llm-as-judge" in source.lower()
    if scores and judged:
        return "both"
    return "rule" if scores else "judge"


def read_channel(task: Path) -> str:
    workspace = task / "workspace"
    if workspace.is_dir() and any(workspace.iterdir()):
        return CHANNEL_DATA
    if (task / "scenarios.json").exists():
        return CHANNEL_NPC
    return CHANNEL_PROMPT


def read_services(task: Path) -> tuple[str, ...]:
    """Declared services, plus RocketChat when an NPC speaks.

    No published ``dependencies.yml`` names rocketchat, yet it is the transport for
    every NPC task (docs/oas_layout.md, question 4). Counting only what is declared
    would report 7 multi-service tasks where the deployment has 83. The implicit entry
    is labelled as such so the two readings stay separable downstream.
    """
    services: set[str] = set()
    declared = task / "utils" / "dependencies.yml"
    if declared.exists():
        for line in declared.read_text(encoding="utf-8", errors="ignore").splitlines():
            name = line.strip().lstrip("-").strip()
            if name and not name.startswith("#"):
                services.add(name)
    if (task / "scenarios.json").exists():
        services.add("rocketchat(implicit)")
    return tuple(sorted(services))


#: What a *verified* configuration change looks like in an OAS evaluator: the API
#: surfaces that expose persistent policy rather than content. Reported alongside the
#: lexical ``has_configure`` as a second, stricter reading -- it can only make the gate
#: harder to pass, so it is evidence rather than a moved goalpost.
CONFIG_ENDPOINTS = re.compile(
    r"protected_branches|access_level|permissions|visibility", re.IGNORECASE
)


def verifies_configuration(task: Path) -> bool:
    """Does this task's own evaluator check a configuration endpoint?"""
    evaluator = task / "utils" / "evaluator.py"
    if not evaluator.exists():
        return False
    return bool(CONFIG_ENDPOINTS.search(evaluator.read_text(encoding="utf-8", errors="ignore")))


def classify_tasks(tasks_dir: Path) -> list[TaskRow]:
    """Judge every task directory under ``tasks_dir``, in name order."""
    tasks_dir = Path(tasks_dir)
    classifier = ToolClassifier()
    rows: list[TaskRow] = []

    for task in sorted(path for path in tasks_dir.iterdir() if path.is_dir()):
        text = " ".join(
            (task / name).read_text(encoding="utf-8", errors="ignore")
            for name in ("task.md", "checkpoints.md")
            if (task / name).exists()
        )
        categories = {classifier.classify(phrase) for phrase in action_phrases(text)}
        scorer = read_scorer(task)
        channel = read_channel(task)
        services = read_services(task)

        reasons: list[str] = []
        if scorer == "judge":
            reasons.append("no rule-based evaluator")
        if channel == CHANNEL_PROMPT:
            reasons.append("unsafe instruction reaches the agent on the prompt channel only")
        verdict = "drop" if reasons else "keep"
        if verdict == "keep":
            reasons.append(f"{scorer}-scored, {channel} channel")

        rows.append(
            TaskRow(
                task_id=task.name,
                scorer=scorer,
                channel=channel,
                services=services,
                has_configure=ToolCategory.CONFIGURE in categories,
                has_network=ToolCategory.NETWORK in categories,
                verifies_configuration=verifies_configuration(task),
                verdict=verdict,
                reason="; ".join(reasons),
            )
        )
    return rows


COLUMNS = (
    "task_id", "scorer", "channel", "services",
    "has_configure", "has_network", "verifies_configuration", "verdict", "reason",
)


def write_tsv(rows: list[TaskRow], out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["\t".join(COLUMNS)]
    for row in rows:
        lines.append(
            "\t".join(
                [
                    row.task_id,
                    row.scorer,
                    row.channel,
                    ",".join(row.services),
                    str(row.has_configure),
                    str(row.has_network),
                    str(row.verifies_configuration),
                    row.verdict,
                    row.reason,
                ]
            )
        )
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def summarise(rows: list[TaskRow]) -> str:
    keep = [row for row in rows if row.verdict == "keep"]
    configure = [row for row in keep if row.has_configure]
    multi = [row for row in keep if len(row.services) >= 2]
    multi_declared = [
        row for row in keep
        if len([s for s in row.services if not s.endswith("(implicit)")]) >= 2
    ]
    passes = len(keep) >= 20 and len(configure) >= 8 and len(multi) >= 8
    return "\n".join(
        [
            f"tasks                           {len(rows)}",
            f"rule-based scored               {sum(1 for r in rows if r.scorer in ('rule', 'both'))}",
            f"judge-only                      {sum(1 for r in rows if r.scorer == 'judge')}",
            f"non-prompt channel              {sum(1 for r in rows if r.channel != CHANNEL_PROMPT)}",
            "",
            f"KEEP (rule-scored AND data/npc) {len(keep)}",
            f"  of which has_configure        {len(configure)}   <- R5's population",
            f"  of which >=2 services         {len(multi)}   <- R2's population (rocketchat implicit)",
            f"  of which >=2 declared         {len(multi_declared)}   (declared services only)",
            f"  of which has_network          {sum(1 for r in keep if r.has_network)}",
            "",
            "Second, stricter reading of R5's population -- evaluators that actually verify",
            "a configuration endpoint (protected_branches / access_level / permissions /",
            f"visibility): {sum(1 for r in keep if r.verifies_configuration)} of the keep set.",
            "",
            "Threshold, fixed in writing before this script existed:",
            "  build the bridge only if KEEP >= 20, has_configure >= 8, and >=2 services >= 8.",
            f"  KEEP           {len(keep):>4} >= 20   {'PASS' if len(keep) >= 20 else 'FAIL'}",
            f"  has_configure  {len(configure):>4} >=  8   {'PASS' if len(configure) >= 8 else 'FAIL'}",
            f"  >=2 services   {len(multi):>4} >=  8   {'PASS' if len(multi) >= 8 else 'FAIL'}",
            "",
            "GATE: " + (
                "PASS"
                if passes
                else "FAIL -- report OAS as measured-and-rejected; the R5 gap stays open"
            ),
        ]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oas_decidability.py")
    parser.add_argument(
        "--tasks",
        type=Path,
        default=ROOT / "OpenAgentSafety" / "workspaces" / "tasks",
        help="OpenAgentSafety task directory",
    )
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "oas_candidates.tsv")
    options = parser.parse_args(argv)

    if not options.tasks.is_dir():
        parser.error(f"no such task directory: {options.tasks}")

    rows = classify_tasks(options.tasks)
    write_tsv(rows, options.out)
    print(summarise(rows))
    print(f"\nwrote {options.out}")
    return 0 if any(row.verdict == "keep" for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
