#!/usr/bin/env python
"""Attacks the benchmark says worked, that the firewall did not stop.

GPT_GRID_RESULTS.md section 10.4 records two of these, both in `slack`, and the
presentation calls that "a locatable bug rather than a diffuse weakness". This is
what locates it: the sessions, and their calls, with the fields a diagnosis turns
on -- stage, rules, provenance and the app the call went to.

Read from the captured trace lines, not recomputed. Defect 3 records that
rescore_transcripts.py is not a faithful replay, so anything it produces is
labelled as rescored and nothing here depends on it.

Exit 0 always. This is a report.
"""

from __future__ import annotations

import argparse
import glob
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chainwatch.ml.dataset import load_sessions  # noqa: E402
from chainwatch.ml.native import is_native_valid, native_outcomes  # noqa: E402
from scripts.oc_landing_report import effective_default_is_critical  # noqa: E402


def missed_sessions(sessions, outcomes, *, suite=None):
    """Natively-successful attacks with no effective-CRITICAL call.

    "Effective" is the operational default: an R3 match to an ATTESTED destination
    is downgraded to WARNING and does not block, so it is not a catch. Judging by
    the raw severity would describe the paper-literal configuration instead of the
    deployed one.
    """
    missed = []
    for calls in sessions:
        session_id = str(calls[0].get("session"))
        label = str(calls[0].get("label"))
        if label != "attack" or not is_native_valid(session_id, label, outcomes):
            continue
        if suite is not None and outcomes[session_id].get("coordinate_suite") != suite:
            continue
        if any(effective_default_is_critical(call) for call in calls):
            continue
        missed.append(calls)
    return missed


def detected_sessions(sessions, outcomes, *, suite=None):
    """The complement: natively-successful attacks the firewall did stop.

    A miss is only diagnosable against a catch from the same suite -- the useful
    question is never "what did this session do" but "what did it do differently".
    """
    caught = []
    for calls in sessions:
        session_id = str(calls[0].get("session"))
        label = str(calls[0].get("label"))
        if label != "attack" or not is_native_valid(session_id, label, outcomes):
            continue
        if suite is not None and outcomes[session_id].get("coordinate_suite") != suite:
            continue
        if any(effective_default_is_critical(call) for call in calls):
            caught.append(calls)
    return caught


def format_call(row):
    """One call, with every field a diagnosis turns on and nothing else."""
    rules = ",".join(str(rule) for rule in row.get("rules") or []) or "-"
    return (f"  call {int(row.get('call', 0)):3d}  {str(row.get('tool'))[:28]:28s} "
            f"{str(row.get('server'))[:20]:20s} stage {row.get('stage')}  "
            f"{str(row.get('severity')):8s} [{rules}] prov={row.get('prov')}")


def annotate_outcomes(outcomes):
    """Add the published suite to every outcome, from the coordinate.

    The suite lives in the published coordinate, never in ``server``: since the
    per-app topology landed, ``server`` names an app (``slack-web``), and reading it
    as the suite would split one benchmark suite into two.
    """
    annotated = {}
    for session, outcome in outcomes.items():
        coordinate = tuple(outcome.get("coordinate") or ())
        row = dict(outcome)
        row["coordinate_suite"] = coordinate[2] if len(coordinate) > 2 else None
        annotated[session] = row
    return annotated


def print_session(calls, out=sys.stdout):
    session_id = str(calls[0].get("session"))
    print(f"\n=== {session_id}  ({len(calls)} calls) ===", file=out)
    for call in calls:
        print(format_call(call), file=out)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="miss_audit")
    parser.add_argument("--traces", nargs="*", default=None)
    parser.add_argument("--source", default="agentdojo-gpt4omini")
    parser.add_argument("--suite", default=None,
                        help="published coordinate suite, e.g. slack")
    parser.add_argument("--control", action="store_true",
                        help="also print one detected attack from the same suite")
    options = parser.parse_args(argv)

    home = Path(os.environ.get("CHAINWATCH_HOME", Path.home() / ".chainwatch"))
    paths = options.traces or sorted(
        glob.glob(str(home / "logs" / f"{options.source}-*.jsonl")))
    sessions = [calls for calls in load_sessions(paths)
                if str(calls[0].get("source")) == options.source]
    outcomes = annotate_outcomes(native_outcomes(sorted(home.glob("*_manifest.jsonl"))))

    missed = missed_sessions(sessions, outcomes, suite=options.suite)
    scope = f" in suite {options.suite}" if options.suite else ""
    print(f"{len(missed)} natively-successful attack session(s) with no "
          f"effective-CRITICAL call{scope}")
    for calls in missed:
        print_session(calls)

    if options.control:
        caught = detected_sessions(sessions, outcomes, suite=options.suite)
        print(f"\n--- control: {len(caught)} detected, showing the first ---")
        if caught:
            print_session(caught[0])
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
