#!/usr/bin/env python
"""Does the supervised advantage grow with session length, or is it already spent?

Section 10.5's arms carry ``window`` aggregates, so a longer session gives them more to
aggregate. That predicts the gap over the rule engine should widen with call count. The
prediction has never been tested, because every arm figure in this repo is reported over a
whole partition whose sessions average 4.3 calls.

**This is one step from the ``win_occupancy`` leak, so the design has to say how it avoids
it.** Phase 8's leak was that attacks and benign came off different generators with
different lengths, making length itself a usable label. Two things stop that here: both
classes come off one generator (same task, same executor, same environment, differing only
by ``--inject``), and stratifying holds length approximately fixed *inside* each stratum,
so a within-stratum difference cannot be length carrying the label. What it can still be is
small-sample noise, which is why no stratum under ``MIN_SESSIONS`` is reported at all and
every row prints its own n.

Folds are task-grouped -- ``Dataset.groups`` is the manifest ``fold_group`` -- so the same
AgentDojo user_task never appears in train and test.

The ``all`` stratum is not padding: it must reproduce GPT_GRID_RESULTS.md section 10.7.3,
which is what establishes that the strata partition a checked baseline rather than a fresh
and unvalidated computation. ``--self-check`` asserts it instead of inviting a reader to
compare by eye.

This is a report, not a gate. It exits 0 and states verdicts; no number here authorises a
change to a rule, a prior, or a slide.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chainwatch.ml.dataset import ARMS, build, load_sessions  # noqa: E402
from chainwatch.ml.evaluate import (  # noqa: E402
    POPULATIONS,
    evaluate_arm,
    out_of_fold_scores,
    rule_baseline,
)
from chainwatch.ml.native import is_native_valid, native_outcomes  # noqa: E402

#: Where the split falls. Declared as a constant rather than only a flag default because
#: choosing it after seeing the result is how a stratification becomes a fishing
#: expedition; 5 is the boundary of CLAUDE.md section 5's documented 4-7 call attack span.
LENGTH_SPLIT = 5

#: A stratum thinner than this is not reported. At n=10 one session is ten percentage
#: points, and a false-positive rate quoted to three decimals over ten sessions invites a
#: precision the corpus cannot support.
MIN_SESSIONS = 10

#: Section 10.7.3's native-valid row, for --self-check. Held to two decimals because the
#: published table is given to one -- asserting more would fail on rounding, not on drift.
SELF_CHECK = {
    "A (rules)": (1.00, 0.55),
    "B": (1.00, 0.00),
    "D": (1.00, 0.00),
    "E": (1.00, 0.47),
}


def session_lengths(paths) -> dict[str, int]:
    """session id -> call count, read off the traces themselves.

    Counted from the trace rather than the manifest's ``calls`` field so the denominator
    is the same rows the arms are built from. The two agree by construction (publication
    requires native == executor == trace counts, CLAUDE.md section 14) and a divergence
    would mean a corpus defect worth failing on rather than papering over.
    """
    return {str(calls[0].get("session")): len(calls) for calls in load_sessions(paths)}


def session_labels(paths) -> dict[str, str]:
    """session id -> asserted label. Never inferred -- CLAUDE.md section 10."""
    return {
        str(calls[0].get("session")): str(calls[0].get("label"))
        for calls in load_sessions(paths)
    }


def select(lengths, labels, outcomes, *, native_valid: bool, low: int, high: int):
    """Sessions whose call count is in ``[low, high]``, native-valid ones only if asked."""
    keep = []
    for session, count in sorted(lengths.items()):
        if not low <= count <= high:
            continue
        if native_valid and not is_native_valid(session, labels.get(session, ""), outcomes):
            continue
        keep.append(session)
    return keep


def strata(split: int = LENGTH_SPLIT):
    """(name, low, high). ``all`` last, so it reads as the check on the two above it."""
    return (
        (f"<={split} calls", 1, split),
        (f">{split} calls", split + 1, 1 << 30),
        ("all", 1, 1 << 30),
    )


def measure_stratum(paths, sessions, arms, populations, *, folds: int, seed: int) -> dict:
    """Arm A plus every learned arm, pinned to arm A's detection *in this stratum*.

    Matching detection within the stratum rather than against a global target is what
    makes false positives comparable across strata: a shared threshold would let a
    stratum's own difficulty masquerade as an arm's performance.
    """
    arm_a = rule_baseline(paths, populations, sessions=sessions)
    rows = [
        {
            "arm": "A (rules)",
            "detection": arm_a.detection,
            "false_positives": arm_a.false_positives,
            "auc": None,
        }
    ]
    for arm in arms:
        dataset = build(paths, groups=ARMS[arm], sessions=sessions)
        if len(set(dataset.labels.tolist())) < 2:
            rows.append({"arm": arm, "skipped": "single-class stratum"})
            continue
        scores = out_of_fold_scores(dataset, k=folds, seed=seed)
        point = evaluate_arm(arm, dataset, scores, arm_a.detection, populations)
        rows.append(
            {
                "arm": arm,
                "detection": point.detection,
                "false_positives": point.false_positives,
                "auc": point.auc,
            }
        )
    return {
        "sessions": len(sessions),
        "n_attack": arm_a.n_attack,
        "n_benign": arm_a.n_benign,
        "arms": rows,
    }


def format_row(row: dict) -> str:
    if "skipped" in row:
        return f"  {row['arm']:10s} {row['skipped']}"
    auc = row.get("auc")
    shown = "  -  " if auc is None else f"{auc:.3f}"
    return (
        f"  {row['arm']:10s} det {row['detection']:.3f}   "
        f"FP {row['false_positives']:.3f}   AUC {shown}"
    )


def self_check(result: dict) -> list[str]:
    """Complaints about the ``all`` stratum against section 10.7.3. Empty means agreement."""
    problems = []
    for row in result["arms"]:
        expected = SELF_CHECK.get(row.get("arm", ""))
        if expected is None or "skipped" in row:
            continue
        for value, want, field in (
            (row["detection"], expected[0], "detection"),
            (row["false_positives"], expected[1], "false_positives"),
        ):
            if abs(value - want) > 0.005:
                problems.append(
                    f"{row['arm']} {field}: measured {value:.3f}, "
                    f"section 10.7.3 published {want:.2f}"
                )
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(prog="arms_by_length")
    parser.add_argument("--traces", nargs="*", default=None)
    parser.add_argument("--source", default="agentdojo-gpt4omini")
    parser.add_argument("--population", default="agentdojo-gpt4omini", choices=sorted(POPULATIONS))
    parser.add_argument("--arms", default="B,D,E")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--split", type=int, default=LENGTH_SPLIT)
    parser.add_argument("--json", type=Path, default=None, help="also write the raw numbers here")
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="fail if the 'all' stratum disagrees with GPT_GRID_RESULTS.md section 10.7.3",
    )
    options = parser.parse_args(argv)

    home = Path(os.environ.get("CHAINWATCH_HOME", Path.home() / ".chainwatch"))
    paths = options.traces or sorted(
        glob.glob(str(home / "logs" / f"{options.source}-*.jsonl"))
    )
    if not paths:
        sys.stderr.write(f"arms_by_length: no trace files for source {options.source!r}\n")
        return 2

    lengths = session_lengths(paths)
    labels = session_labels(paths)
    outcomes = native_outcomes(sorted(home.glob("*_manifest.jsonl")))
    if not outcomes:
        # The native-valid partition is the primary analysis and is_native_valid fails
        # closed, so a missing manifest would silently print an empty primary table under
        # a heading claiming it had been measured. Refuse, as ml-eval does.
        sys.stderr.write("arms_by_length: no manifest found; native-valid cannot be selected\n")
        return 2

    arms = [a.strip() for a in options.arms.split(",") if a.strip()]
    unknown = [a for a in arms if a not in ARMS]
    if unknown:
        sys.stderr.write(f"arms_by_length: unknown arms {unknown}; have {sorted(ARMS)}\n")
        return 2

    populations = POPULATIONS[options.population]
    print("=" * 78)
    print("Arms by session length -- does the supervised advantage grow with call count?")
    print(f"source {options.source}  |  {len(paths)} trace files  |  split at {options.split}")
    print("metric: false positives at arm A's detection, matched within each stratum")
    print("=" * 78)

    payload: dict = {"source": options.source, "split": options.split, "results": []}
    checked = None
    for partition, native_valid in (
        ("native-valid (primary)", True),
        ("all-attempts (sensitivity)", False),
    ):
        print(f"\n-- {partition} " + "-" * max(0, 60 - len(partition)))
        for name, low, high in strata(options.split):
            sessions = select(
                lengths, labels, outcomes, native_valid=native_valid, low=low, high=high
            )
            if len(sessions) < MIN_SESSIONS:
                print(
                    f"  {name:12s} {len(sessions)} sessions: under "
                    f"MIN_SESSIONS={MIN_SESSIONS}; no verdict stated"
                )
                payload["results"].append(
                    {
                        "partition": partition,
                        "stratum": name,
                        "sessions": len(sessions),
                        "skipped": "under MIN_SESSIONS",
                    }
                )
                continue
            result = measure_stratum(
                paths, sessions, arms, populations, folds=options.folds, seed=options.seed
            )
            print(
                f"  {name:12s} {result['sessions']} sessions "
                f"({result['n_attack']} attack / {result['n_benign']} benign)"
            )
            for row in result["arms"]:
                print(format_row(row))
            payload["results"].append({"partition": partition, "stratum": name, **result})
            if native_valid and name == "all":
                checked = result

    if options.json:
        options.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    if options.self_check:
        if checked is None:
            sys.stderr.write("arms_by_length: --self-check had no native-valid 'all' stratum\n")
            return 2
        problems = self_check(checked)
        if problems:
            sys.stderr.write("arms_by_length: disagrees with section 10.7.3:\n")
            for problem in problems:
                sys.stderr.write(f"  {problem}\n")
            return 1
        print("\nself-check: the 'all' stratum reproduces section 10.7.3.")

    print("\nA report, not a gate: no verdict here authorises a change.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
