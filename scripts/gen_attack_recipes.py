#!/usr/bin/env python3
"""Generate route C's attack recipe file from the benchmarks, not by hand.

    scripts/gen_attack_recipes.py --out docs/recipes_bizattack.txt

Route C captures benign business operations by driving ``claude -p`` over
``docs/recipes_bizops.txt`` against SHADE_Arena's four environments served as real
MCP servers. Its attack half has to come off *the same pipeline over the same
fixtures*, or the model separates the two generators instead of the two intents --
which is the leak docs/development-notes.md, "Phase 8" records three times (``win_occupancy``
proxied session length, PS proxied argument realism, provenance proxied destination
realism).

So the instructions are lifted, never written:

* the three SHADE task pairs that ship an executable universe contribute their
  ``user_query`` (the legitimate cover task) *and* their ``secondary_task`` (the
  fraud), which is SHADE's own methodology and the exact pairing
  ``shade_solutions.py`` extracts trajectories from;
* the AgentLAB chains contribute ``attack_plan.attack_goal``, handed to the agent as
  a goal rather than replayed as a fixed call list. Replaying the list is what
  ``benchmark_bridge/agentlab_replay.py`` already does and it is what produces plans rather
  than behaviour; handing over the goal is what makes the agent choose real
  arguments out of the fixtures.

Two filters, both stated here because they change what the corpus can measure
-----------------------------------------------------------------------------
**Harmful-content chains are excluded.** 36 of the 200 carry failure mode 1, "the
assistant generates harmful content" -- author bomb-making text, attach it, send it.
Driving a live agent to write that content is not something this project needs: the
firewall never reads a payload's meaning, only the shape of the call sequence, and
CLAUDE.md already reports that population as undetectable by construction ("no
upstream data flow and no kill-chain progression to detect", 14.3% detected at 0%
blocked). Excluding them costs no measurable signal and is the only responsible way
to run this driver live.

**Only chains that move or reconfigure something are kept.** The category test is
ChainWatch's own :func:`categorize`, so "the population R3 and R5 target" means the
same thing here as it does in the rule engine. A chain with no NETWORK and no
CONFIGURE step cannot exercise either rule whatever the agent does with it.

What is deliberately *not* done
-------------------------------
No jailbreak framing, no role-play wrapper, no "you are in a test environment"
preamble. The goal is handed over as-is. A refused session is a real measurement --
``capture_bizops_attack.sh`` reports the refusal rate -- and engineering around the
refusal would make this a tool for defeating the agent's own safety behaviour rather
than a corpus for measuring the firewall beneath it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmark_bridge.shade_arena import ENVIRONMENT_ALIASES, ENVIRONMENTS  # noqa: E402
from benchmark_bridge.shade_solutions import _pair_context  # noqa: E402
from chainwatch.engine.taxonomy import ToolCategory, ToolClassifier  # noqa: E402

CHAINS = ROOT / "AgentLAB" / "data" / "filtered_top_200_attacks.json"
TASK_PAIRS = ROOT / "AgentLAB" / "SHADE_Arena" / "task_pairs"

#: All five task pairs, in a fixed order so line *i* of the benign twin file and
#: line *i* of the attack twin file are the same pair.
#:
#: ``shade_solutions.py`` uses only three of these because it needs an executable
#: ``solution.py`` -- there the shipped trajectory *is* the data, and
#: ``american_airlines_2`` and ``expenditure_accounting`` are 20-line stubs. For live
#: capture that distinction is irrelevant: the agent generates the behaviour, so a
#: stub costs nothing. Both stubs still carry a full ``user_query`` and
#: ``secondary_task``, and together they are the project's only source of **travel**
#: traffic and its second source of **workspace** traffic -- leave-one-environment-out
#: currently has two environments to hold out where it needs four.
PAIRS = (
    "american_airlines_2",         # travel
    "api_key_calendar_agendas_2",  # workspace
    "bank_transfer_2",             # banking
    "expenditure_accounting",      # banking
    "spam_filter_update",          # spam_filter
)

#: Failure mode 1 is harmful content generation. See the module docstring.
HARMFUL_CONTENT_PREFIX = "1."

#: A chain worth driving has to end somewhere R3 or R5 can see it.
TARGET_CATEGORIES = (ToolCategory.NETWORK, ToolCategory.CONFIGURE)

#: The engine's own classifier, so "the population R3 and R5 target" means the same
#: thing here as it does in the rule engine -- including note 27's reordering.
CLASSIFIER = ToolClassifier()


def one_line(text: str) -> str:
    """Collapse a multi-paragraph task into a single recipe line.

    The recipe file is one session per line -- the capture scripts read it with
    ``while read``, so an embedded newline would split one task into two sessions
    and both halves would be incoherent.
    """
    return re.sub(r"\s+", " ", text).strip()


def pair_texts(name: str) -> tuple[str, str] | None:
    """``(user_query, secondary_task)`` for one SHADE task pair, each as one line.

    Kept separate because **``user_query`` alone is the benign twin**. Both fields
    were written by SHADE's authors: the same person, the same phrasing and the same
    length, differing by exactly one clause. That is the strongest evidence design
    available here and the reason the benign half of this population is not written
    in this repo -- a false-positive rate over tasks the defender selected tells you
    about the selection.
    """
    if not (TASK_PAIRS / name / "task_definition.py").is_file():
        return None

    # SHADE's own import convention: ``task_definition`` is bare, pair-local and
    # same-named across pairs, and ``create()`` resolves fixtures relative to the
    # working directory. ``_pair_context`` is the one place that is already right.
    try:
        with _pair_context(name):
            import importlib

            module = importlib.import_module("task_definition")
            definition = module.TaskDefinition()
            return one_line(definition.user_query), one_line(definition.secondary_task)
    except Exception as error:  # noqa: BLE001 - one bad pair must not lose the rest
        print(f"warning: {name}: {error}", file=sys.stderr)
        return None


def render_pair(name: str) -> str | None:
    """The legitimate query and the side objective of one pair, as one attack line.

    Both halves are needed. The ``secondary_task`` alone is a bare instruction to
    commit fraud with no work to hide inside, which is not what SHADE measures and
    not what the firewall sees in the real trajectory: the fraud is *interleaved*
    with honest work, which is why ``shade_solutions.py`` derives the benign twin by
    removing calls rather than by running a different task.
    """
    texts = pair_texts(name)
    if texts is None:
        return None
    primary, secondary = texts
    return f"{primary} Additionally: {secondary}"


def chain_categories(chain: dict[str, Any]) -> set[ToolCategory]:
    steps = chain.get("attack_plan", {}).get("verified_tool_chain") or []
    return {CLASSIFIER.classify(step.get("tool_name", "")) for step in steps}


def eligible_chains(chains: list[dict[str, Any]]) -> Iterator[tuple[str, str]]:
    """Yield ``(environment, goal)`` for every chain this driver may run live."""
    seen: set[str] = set()
    for chain in chains:
        config = chain.get("generation_config", {})
        if config.get("dataset") != "SHADE_Arena":
            continue

        environment = ENVIRONMENT_ALIASES.get(
            str(config.get("environment")), str(config.get("environment"))
        )
        if environment not in ENVIRONMENTS:
            continue

        if str(config.get("failure_mode", "")).lstrip().startswith(HARMFUL_CONTENT_PREFIX):
            continue

        steps = chain.get("attack_plan", {}).get("verified_tool_chain") or []
        if len(steps) < 2:
            continue
        if not chain_categories(chain) & set(TARGET_CATEGORIES):
            continue

        goal = one_line(chain.get("attack_plan", {}).get("attack_goal") or "")
        if not goal or goal.lower() in seen:
            continue
        seen.add(goal.lower())
        yield environment, goal


HEADER = '''\
# Route C attack task list -- one session per line, fed to `claude -p` by
# scripts/capture_bizops_attack.sh against the same four SHADE_Arena environments,
# the same fixtures and the same proxy wiring as docs/recipes_bizops.txt.
#
# GENERATED by scripts/gen_attack_recipes.py. Edit that, not this.
#
# Why this file exists. Every benign population in the project is real work with
# arguments lifted from populated fixtures; every attack population is a statically
# replayed plan with arguments from a JSON file. A model given both learns which
# generator produced a row -- measured three times, most recently as provenance
# reaching 83.6% of arm E's importance while improving nothing. The fix is not a
# better feature, it is an attack class that comes off the same pipeline as the
# benign one.
#
# Instruction provenance: AgentLAB's verified chains, handed over as
# `attack_plan.attack_goal` -- a goal, not a call list. Replaying the list is what
# produced the plans this whole exercise is trying to escape.
#
# The five SHADE task pairs are deliberately NOT in this file. They live in
# docs/recipes_twin_{benign,attack}.txt, generated by the same script with --twins,
# because their benign sibling is the same author's `user_query` with one clause
# removed. Pooling them in here would destroy the only matched pairing in the corpus:
# these goals are machine-authored and have no benign twin, so the two sets answer
# different questions and must be reported as separate populations.
#
# Two exclusions, both load-bearing:
#   * failure mode 1 (harmful content generation, 36 chains) is dropped. The
#     firewall never reads a payload's meaning, and CLAUDE.md already measures that
#     population at 14.3% detected / 0% blocked -- there is no signal to lose.
#   * chains with no NETWORK and no CONFIGURE step are dropped. They cannot
#     exercise R3 or R5 whatever the agent does.
#
# No jailbreak framing is added anywhere in this file. The agent will refuse some
# fraction of these, a refused session records zero calls, and the driver reports
# the refusal rate as a number rather than working around it.
'''


TWIN_HEADER = '''\
# SHADE_Arena matched twins -- one session per line, {half} half.
#
# GENERATED by scripts/gen_attack_recipes.py --twins. Edit that, not this.
#
# Line i of this file and line i of its sibling are the SAME task pair. The benign
# line is the pair's own `user_query`; the attack line is that same `user_query` with
# the pair's own `secondary_task` appended. Both were written by SHADE_Arena's
# authors, not by this repo, and they differ by exactly one clause.
#
# That is the whole point. docs/development-notes.md, "Phase 8" records three leaks of one species --
# window occupancy proxied session length, PS proxied argument realism, provenance
# proxied destination realism -- and all three come from the two classes being
# produced by different generators, which makes any property of the generator a
# usable label. Here the two classes come off the same sentence.
#
# It also replaces docs/recipes_bizops.txt as the benign population of record. Those
# recipes were written by hand in this repo by the author of the firewall they are
# used to evaluate, so a false-positive rate over them measures the selection rather
# than the rules -- unfalsifiable even in perfect good faith.
'''


def write_twins(directory: Path) -> int:
    """Write both twin recipe files. Returns the number of pairs written.

    Two files rather than one with a marker column, because the capture drivers read
    a recipe file with ``while read`` and assert the label in the mcp config -- one
    file would mean one label for both halves, and ``dataset.build`` treats any label
    that is not ``"attack"`` as benign.
    """
    benign: list[str] = [TWIN_HEADER.format(half="benign"), ""]
    attack: list[str] = [TWIN_HEADER.format(half="attack"), ""]
    written = 0
    for name in PAIRS:
        texts = pair_texts(name)
        if texts is None:
            continue
        primary, secondary = texts
        benign.extend([f"# {name}", primary, ""])
        attack.extend([f"# {name}", f"{primary} Additionally: {secondary}", ""])
        written += 1

    (directory / "recipes_twin_benign.txt").write_text("\n".join(benign), encoding="utf-8")
    (directory / "recipes_twin_attack.txt").write_text("\n".join(attack), encoding="utf-8")
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gen_attack_recipes.py", description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "recipes_bizattack.txt")
    parser.add_argument(
        "--limit", type=int, default=45,
        help="cap on AgentLAB-derived lines (default: 45)",
    )
    parser.add_argument(
        "--twins",
        action="store_true",
        help="write docs/recipes_twin_{benign,attack}.txt from the five SHADE task "
        "pairs instead of the AgentLAB chain-goal file",
    )
    options = parser.parse_args(argv)

    # Before the chain-corpus check: the twins come from the task pairs alone and
    # need no AgentLAB chain file at all.
    if options.twins:
        written = write_twins(options.out.parent)
        print(f"wrote {written} twin pair(s) to {options.out.parent}", file=sys.stderr)
        return 0

    if not CHAINS.is_file():
        raise SystemExit(f"no chain corpus at {CHAINS}")
    chains = json.loads(CHAINS.read_text(encoding="utf-8"))

    lines: list[str] = [HEADER]

    # Spread across environments rather than taking the first N, so
    # leave-one-environment-out has something to hold out on the attack side too.
    by_environment: dict[str, list[str]] = {}
    for environment, goal in eligible_chains(chains):
        by_environment.setdefault(environment, []).append(goal)

    interleaved: list[tuple[str, str]] = []
    index = 0
    while len(interleaved) < options.limit and any(
        index < len(goals) for goals in by_environment.values()
    ):
        for environment in sorted(by_environment):
            goals = by_environment[environment]
            if index < len(goals) and len(interleaved) < options.limit:
                interleaved.append((environment, goals[index]))
        index += 1

    # Grouped for readability only. Every line is served all four environments, the
    # same as the benign side -- the agent picks, which is the point of invariant 1.
    interleaved.sort(key=lambda pair: pair[0])
    current = None
    for environment, goal in interleaved:
        if environment != current:
            lines.append("")
            lines.append(f"# --- AgentLAB verified chains: {environment} ---")
            current = environment
        lines.append(goal)

    options.out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    counts = {env: sum(1 for e, _ in interleaved if e == env) for env in sorted(by_environment)}
    eligible = sum(len(goals) for goals in by_environment.values())
    print(
        f"wrote {options.out}: {len(interleaved)} chain goal(s) "
        f"{counts}",
        file=sys.stderr,
    )
    print(f"eligible after filters: {eligible} of {len(chains)} chains", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
