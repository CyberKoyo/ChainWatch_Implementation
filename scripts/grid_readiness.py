#!/usr/bin/env python
"""What the grid holds, what it is missing, and what finishing it would cost.

Every number here is measured or explicitly labelled as a projection from a
measured basis. A partition with no native-valid attacks has no primary analysis,
and this says so rather than printing a rate over nothing -- note 31's defect was
exactly a table of nan under a headline that looked like a measurement.

Exit 0 always. This is a report; the gates are oc_landing_report.py and
rescore_transcripts.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chainwatch.capture import manifest as manifest_module  # noqa: E402
from chainwatch.ml import native  # noqa: E402
from scripts import capture_agentdojo_openai as agentdojo  # noqa: E402
from scripts import capture_injecagent_openai as injecagent  # noqa: E402

#: Basis of last resort, from the pre-v2 archive's recorded usage. Named on every
#: line that uses it, because a projection whose basis is invisible is a guess.
ARCHIVED_MEAN_USD = {"agentdojo-gpt4omini": 0.000675, "injecagent-gpt4omini": 0.000190}
ARCHIVED_MAX_USD = {"agentdojo-gpt4omini": 0.001416, "injecagent-gpt4omini": 0.000190}

ROUTES = (
    ("agentdojo-gpt4omini", agentdojo, ROOT / "docs/recipes_agentdojo.tsv",
     "scripts/capture_agentdojo_openai.py"),
    ("injecagent-gpt4omini", injecagent, ROOT / "docs/recipes_injecagent.tsv",
     "scripts/capture_injecagent_openai.py"),
)


def format_native_line(*, partition: str, benign_valid: int, benign_total: int,
                       attack_valid: int, attack_total: int) -> str:
    """One partition's native outcomes, or an honest refusal to state a rate.

    A partition with zero native-valid attacks has no primary analysis. Printing
    0.0% there reads as "we measured, and it was zero"; it means "we could not
    measure". Note 31 is exactly that confusion, one layer up.
    """
    benign = f"benign native-valid {benign_valid}/{benign_total}"
    if attack_valid == 0:
        return (f"{partition}: {benign}; attack primary analysis unavailable "
                f"(0 of {attack_total} attempts succeeded natively)")
    rate = attack_valid / attack_total
    return f"{partition}: {benign}; attack native-valid {attack_valid}/{attack_total} ({rate:.1%})"


def format_cost_projection(*, remaining: int, mean_usd: float, max_usd: float) -> str:
    """A projection with its basis on the same line, and the tail stated separately."""
    return (f"{remaining} coordinates remaining: ~${remaining * mean_usd:.2f} "
            f"at the observed mean of ${mean_usd:.6f}/session; "
            f"~${remaining * max_usd:.2f} at the observed maximum of ${max_usd:.6f}")


def format_resume_command(*, script: str, corpus_revision: str, cap_usd: float) -> str:
    """The exact command an approval prompt shows, resumable by construction."""
    return (f".venv/bin/python {script} --corpus-revision {corpus_revision} "
            f"--resume --require-clean-git --max-cost-usd {cap_usd} --confirm-api-usage")


def format_depth_line(*, partition: str, sessions: int, mean_calls: float,
                      attack_mean_calls: float) -> str:
    """Call depth against the >=4 quality signal -- a signal, not an authorization."""
    flag = "" if attack_mean_calls >= 4.0 else "  <-- below the >=4 attack-depth signal"
    return (f"{partition}: {sessions} sessions, mean {mean_calls:.2f} calls, "
            f"attack mean {attack_mean_calls:.2f}{flag}")


def usage_rows(state: Path, source: str) -> list[dict]:
    """Session usage rows, live and archived.

    Cost basis is legitimately historical -- what a session cost does not change
    when the trace moves -- so the archive counts here even though completeness
    deliberately does not.
    """
    rows: list[dict] = []
    patterns = (f"{source}_usage-*.jsonl", f"archive/*/{source}_usage-*.jsonl")
    for pattern in patterns:
        for path in sorted(state.glob(pattern)):
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                if row.get("type") == "session":
                    rows.append(row)
    return rows


def report(state: Path, *, corpus_revision: str = "v2") -> tuple[str, int]:
    """The whole report as text, plus the exit code (always 0)."""
    state = Path(state)
    lines: list[str] = []

    for source, driver, recipes_path, script in ROUTES:
        recipes = driver.load_recipes(recipes_path)
        planned = {driver.recipe_coordinate(recipe) for recipe in recipes}
        manifest_path = state / f"{source}_manifest.jsonl"
        entries = manifest_module.read_entries(manifest_path)
        # Completeness is reported per fingerprint, never pooled across them. Two
        # configurations that each captured half the grid have not captured the
        # grid, and a single merged count would say they had.
        fingerprints = sorted({entry.fingerprint for entry in entries})
        completed: set[tuple[str, ...]] = set()
        for fingerprint in fingerprints:
            completed |= manifest_module.completed_coordinates(
                entries, fingerprint=fingerprint)
        dupes = manifest_module.duplicate_coordinates(entries)
        remaining = len(planned - completed)

        lines.append(f"\n== {source} " + "=" * max(4, 60 - len(source)))
        lines.append(f"coordinates: {len(completed)} of {len(planned)} complete, "
                     f"{remaining} remaining, {len(dupes)} duplicated")
        for key, count in sorted(dupes.items()):
            lines.append(f"  duplicate {key}: {count} entries")
        if len(fingerprints) > 1:
            lines.append(f"  WARNING: {len(fingerprints)} configurations present "
                         f"({', '.join(fingerprints)}); per-fingerprint counts follow")
            for fingerprint in fingerprints:
                done = manifest_module.completed_coordinates(entries, fingerprint=fingerprint)
                lines.append(f"    {fingerprint}: {len(done)} of {len(planned)}")

        outcomes = native.native_outcomes([manifest_path])
        labels = {session: outcome["label"] for session, outcome in outcomes.items()}
        benign = [session for session, value in labels.items() if value == "benign"]
        attack = [session for session, value in labels.items() if value == "attack"]
        benign_valid, benign_attempts = native.partition_sessions(benign, labels, outcomes)
        attack_valid, attack_attempts = native.partition_sessions(attack, labels, outcomes)
        lines.append("  " + format_native_line(
            partition=source,
            benign_valid=len(benign_valid), benign_total=len(benign_attempts),
            attack_valid=len(attack_valid), attack_total=len(attack_attempts)))
        lines.append(f"  sample sizes: native-valid {len(benign_valid) + len(attack_valid)}, "
                     f"all-attempts {len(benign_attempts) + len(attack_attempts)}")

        calls = [entry.calls for entry in entries]
        attack_calls = [entry.calls for entry in entries if entry.coordinate[1] == "attack"]
        if calls:
            lines.append("  " + format_depth_line(
                partition=source, sessions=len(calls),
                mean_calls=sum(calls) / len(calls),
                attack_mean_calls=(sum(attack_calls) / len(attack_calls))
                if attack_calls else 0.0))
        else:
            lines.append("  depth: no sessions captured under this configuration")

        usage = usage_rows(state, source)
        costs = [float(row.get("estimated_cost_usd", 0.0)) for row in usage]
        if costs:
            mean_usd, max_usd = sum(costs) / len(costs), max(costs)
            basis = f"observed over {len(costs)} recorded session(s)"
        else:
            mean_usd, max_usd = ARCHIVED_MEAN_USD[source], ARCHIVED_MAX_USD[source]
            basis = "archived pre-v2 usage; no session recorded under this configuration"
        lines.append(f"  cost basis: {basis}")
        lines.append("  " + format_cost_projection(
            remaining=remaining, mean_usd=mean_usd, max_usd=max_usd))
        # A cap sized on the observed maximum, plus a stated margin, because the
        # budget is an observed-spend stop and can overshoot by one in-flight call.
        cap = max(round(remaining * max_usd * 1.25, 2), 0.01)
        lines.append("  cap = remaining x observed max x 1.25 (margin stated, not hidden)")
        lines.append("  " + format_resume_command(
            script=script, corpus_revision=corpus_revision, cap_usd=cap))

    return "\n".join(lines) + "\n", 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".chainwatch")
    parser.add_argument("--corpus-revision", default="v2")
    options = parser.parse_args(argv)
    text, code = report(options.state_dir, corpus_revision=options.corpus_revision)
    print(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
