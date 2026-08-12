#!/usr/bin/env python
"""What does ChainWatch cost per call, and which stage costs it?

Nothing in this repo has ever measured latency -- ``perf_counter`` appears nowhere, and
section 12 carries no timing row. So every performance statement about the engine has been
an argument from structure, and two such arguments turned out to be wrong when measured:
the Viterbi decode is not negligible (it is the largest single stage, and it runs twice per
call), and the XGBoost arms are not microseconds (a one-row ``predict_proba`` is dominated
by wrapper overhead rather than by tree traversal).

**Real responses, not stand-ins.** The Output Characteristics regexes sweep the response
body, so timing them over invented text would measure nothing. The executor transcripts
carry each call's actual ``result``, so the sweep is timed over the bytes the deployment
saw. A session whose trace and transcript disagree on call count is skipped whole rather
than mispaired -- ``fixture_audit.py``'s discipline, one layer over.

**Method.** The pipeline runs for real, in order, one fresh ``SessionAnalyzer`` per session,
so every stage sees the state it would see in production. The two coarse boundaries
(``submit``, ``complete``) are timed once each because they mutate. The pure sub-stages are
re-timed ``REPEATS`` times against the analyzer's own live objects and the minimum kept,
which removes scheduler noise without inventing a warm cache the proxy would not have.

Two fidelity limits, both deliberate and neither fixable by measuring more:

* ``extract`` is re-timed after ``commit`` has advanced ``last_timestamp``, so its TF dims
  differ from the pre-flight pass -- ``features.py``'s own docstring warns about exactly
  this. Only dims 10 and 12 change; the regex work being timed is identical.
* Observe-only is reproduced: ``complete`` runs even when ``submit`` blocks, so every call
  is traversed instead of truncating each session at its first CRITICAL. An enforcing
  deployment would do less work, so these figures are the ceiling.

This is a report, not a gate. No number here authorises a change to a rule or a prior.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chainwatch.engine.features import FeatureExtractor, ObservedCall  # noqa: E402
from chainwatch.engine.rules import RuleConfig, evaluate  # noqa: E402
from chainwatch.engine.session import SessionAnalyzer  # noqa: E402

#: How many times each pure stage is re-timed, keeping the minimum. Seven is enough for the
#: minimum to settle without making the run quadratic in the corpus.
REPEATS = 7

#: Where the per-position report splits. Chosen to match scripts/arms_by_length.py's
#: LENGTH_SPLIT so the latency and capability stories are cut the same way.
POSITION_BUCKETS = ((0, 2, "call 1-2"), (2, 5, "call 3-5"), (5, 1 << 30, "call 6+"))

#: Stage labels, in the order they are reported. Indentation encodes containment: an
#: indented row is a component of the row above it, not a peer, and the totals are the
#: unindented ones.
STAGES = (
    "submit (preflight total)",
    "  extract (TC/PS/DF/TF)",
    "  viterbi (HMM decode)",
    "  evaluate (R1-R5)",
    "complete (post-response total)",
    "  output characteristics (OC regex)",
    "TOTAL per call (submit+complete)",
)


def as_text(value) -> str:
    """The response as the wire carried it.

    Mirrors ``benchmark_bridge.env_mcp_server._as_text``: a string passes through, anything
    else is JSON. Re-encoding a dict differently here would change the byte count the OC
    regexes are timed over, which is the one quantity this script must not get wrong.
    """
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def pair_session(trace_rows, transcript_rows):
    """Pair a session's trace rows with its executor tool results, or return ``None``.

    Strict pairing by order. ``None`` on any count mismatch, because a mispairing would
    time the wrong response against the wrong call and silently shift the byte
    distribution the whole report rests on -- a wrong number that still looks like a
    number, note 31's species.
    """
    results = [row for row in transcript_rows if "result" in row and "tool" in row]
    if not trace_rows or len(results) != len(trace_rows):
        return None
    paired = []
    for entry, result in zip(trace_rows, results, strict=True):
        paired.append(
            {
                "tool": entry["tool"],
                "arguments": entry.get("args") or {},
                "server": entry.get("server", "default"),
                "response": as_text(result["result"]),
            }
        )
    return paired


def read_jsonl(path):
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_corpus(home: Path, source: str):
    """[(session, [call specs])] for every session whose trace and transcript agree."""
    sessions, skipped = [], []
    for trace_path in sorted(glob.glob(str(home / "logs" / f"{source}-*.jsonl"))):
        session = Path(trace_path).name[: -len(".jsonl")]
        transcript = home / "transcripts" / f"{session}.jsonl"
        if not transcript.exists():
            skipped.append(session)
            continue
        paired = pair_session(read_jsonl(trace_path), read_jsonl(transcript))
        if paired is None:
            skipped.append(session)
            continue
        sessions.append((session, paired))
    return sessions, skipped


def bench_min(fn, repeats: int = REPEATS) -> int:
    """Nanoseconds for the fastest of ``repeats`` runs of ``fn``."""
    best = None
    for _ in range(repeats):
        start = time.perf_counter_ns()
        fn()
        elapsed = time.perf_counter_ns() - start
        best = elapsed if best is None else min(best, elapsed)
    return best


def percentile(values, quantile: float) -> float:
    """Nearest-rank percentile, in the input's own units."""
    ordered = sorted(values)
    if not ordered:
        return float("nan")
    index = min(int(quantile * len(ordered)), len(ordered) - 1)
    return float(ordered[index])


def report(stage: str, values) -> dict:
    """One stage's distribution, in microseconds.

    Percentiles rather than a mean alone: the tail is the operationally interesting half
    here, since a 30 KB response costs two orders of magnitude more than a 250-byte one and
    a mean hides that entirely.
    """
    return {
        "stage": stage,
        "n": len(values),
        "p50_us": round(percentile(values, 0.50) / 1000.0, 2),
        "p90_us": round(percentile(values, 0.90) / 1000.0, 2),
        "p99_us": round(percentile(values, 0.99) / 1000.0, 2),
        "max_us": round(max(values) / 1000.0, 2),
        "mean_us": round(statistics.mean(values) / 1000.0, 2),
    }


def position_bucket(position: int) -> str:
    """Which per-position row a call at ``position`` (0-based) belongs to."""
    for low, high, name in POSITION_BUCKETS:
        if low <= position < high:
            return name
    return POSITION_BUCKETS[-1][2]


def time_engine(sessions, repeats: int = REPEATS):
    """Time every rule-engine stage over every call. Returns (timings, bytes, positions)."""
    timings = defaultdict(list)
    response_bytes = []
    positions = []
    config = RuleConfig()

    for _session, calls in sessions:
        analyzer = SessionAnalyzer()
        extractor: FeatureExtractor = analyzer.extractor
        model = analyzer.model
        for position, spec in enumerate(calls):
            call = ObservedCall(
                tool=spec["tool"], arguments=spec["arguments"], server=spec["server"]
            )
            response = spec["response"]
            response_bytes.append(len(response.encode("utf-8")))

            start = time.perf_counter_ns()
            analyzer.submit(call)
            submit_ns = time.perf_counter_ns() - start
            timings[STAGES[0]].append(submit_ns)

            window = analyzer.window
            observations = np.array([record.vector for record in window])
            timings[STAGES[1]].append(bench_min(lambda: extractor.extract(call), repeats))
            timings[STAGES[2]].append(bench_min(lambda: model.viterbi(observations), repeats))
            timings[STAGES[3]].append(bench_min(lambda: evaluate(window, config), repeats))

            start = time.perf_counter_ns()
            analyzer.complete(call, response)
            complete_ns = time.perf_counter_ns() - start
            timings[STAGES[4]].append(complete_ns)

            # The OC group in isolation. patch_output_characteristics also remembers output
            # tokens and attests destinations, both of which mutate, so only the regex fill
            # can be repeated -- the rest stays inside the coarse figure above.
            vector = analyzer.history[-1].vector
            timings[STAGES[5]].append(
                bench_min(
                    lambda: extractor._fill_output_characteristics(vector.copy(), call), repeats
                )
            )

            timings[STAGES[6]].append(submit_ns + complete_ns)
            positions.append((position, submit_ns + complete_ns))

    return timings, response_bytes, positions


def time_scorer(home: Path, source: str, arms, repeats: int = REPEATS):
    """Train each arm on the corpus, then time the inference the proxy would actually do.

    One row and a ten-row window are both timed because the difference between them is the
    answer to whether the cost is the model or the call overhead. It is the overhead.
    """
    from chainwatch.ml.dataset import ARMS, build
    from chainwatch.ml.scorer import Scorer

    paths = sorted(glob.glob(str(home / "logs" / f"{source}-*.jsonl")))
    rows = []
    for arm in arms:
        dataset = build(paths, groups=ARMS[arm])
        scorer = Scorer.train(dataset)
        one, window = dataset.rows[-1:], dataset.rows[-10:]
        scorer.score_window(window)  # the first predict pays a one-off; do not time it
        rows.append(
            {
                "arm": arm,
                "features": int(dataset.rows.shape[1]),
                "groups": list(ARMS[arm]),
                "score_window_10row_us": round(
                    bench_min(lambda: scorer.score_window(window), repeats * 20) / 1000.0, 2
                ),
                "score_1row_us": round(
                    bench_min(lambda: scorer.score(one), repeats * 20) / 1000.0, 2
                ),
            }
        )
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(prog="engine_latency")
    parser.add_argument("--source", default="agentdojo-gpt4omini")
    parser.add_argument("--repeats", type=int, default=REPEATS)
    parser.add_argument("--arms", default="B,D", help="empty string to skip the scorer")
    parser.add_argument("--json", type=Path, default=None)
    options = parser.parse_args(argv)

    home = Path(os.environ.get("CHAINWATCH_HOME", Path.home() / ".chainwatch"))
    sessions, skipped = load_corpus(home, options.source)
    calls = sum(len(spec) for _, spec in sessions)
    if not calls:
        # Note 14's shape: a measurement run that measured nothing must not exit 0.
        sys.stderr.write(
            f"engine_latency: no session paired for source {options.source!r} "
            f"({len(skipped)} skipped for a missing or mismatched transcript)\n"
        )
        return 2

    timings, response_bytes, positions = time_engine(sessions, options.repeats)
    arms = [a.strip() for a in options.arms.split(",") if a.strip()]
    scorer_rows = time_scorer(home, options.source, arms, options.repeats) if arms else []

    buckets = defaultdict(list)
    for position, total in positions:
        buckets[position_bucket(position)].append(total)

    payload = {
        "source": options.source,
        "sessions": len(sessions),
        "skipped_sessions": len(skipped),
        "calls": calls,
        "repeats": options.repeats,
        "response_bytes": {
            "p50": round(percentile(response_bytes, 0.50)),
            "mean": round(statistics.mean(response_bytes)),
            "p99": round(percentile(response_bytes, 0.99)),
            "max": max(response_bytes),
        },
        "engine": [report(stage, timings[stage]) for stage in STAGES],
        "scorer": scorer_rows,
        "by_position": [
            {
                "bucket": name,
                "n": len(buckets[name]),
                "p50_us": round(percentile(buckets[name], 0.5) / 1000.0, 2),
            }
            for _low, _high, name in POSITION_BUCKETS
            if buckets[name]
        ],
    }

    print("=" * 84)
    print("Per-call latency -- rule engine by stage, and the supervised arms beside it")
    print(
        f"source {options.source}  |  {len(sessions)} sessions  |  {calls} calls  "
        f"|  {len(skipped)} skipped"
    )
    print(
        f"response bytes: p50 {payload['response_bytes']['p50']}  "
        f"mean {payload['response_bytes']['mean']}  max {payload['response_bytes']['max']}"
    )
    print("=" * 84)
    print(f"\n{'stage':40s} {'p50':>9s} {'p90':>9s} {'p99':>9s} {'max':>9s}   (microseconds)")
    for row in payload["engine"]:
        print(
            f"{row['stage']:40s} {row['p50_us']:9.1f} {row['p90_us']:9.1f} "
            f"{row['p99_us']:9.1f} {row['max_us']:9.1f}"
        )

    if scorer_rows:
        print(f"\n{'arm':40s} {'1 row':>9s} {'10 rows':>9s}   (microseconds)")
        for row in scorer_rows:
            label = f"  arm {row['arm']} ({row['features']} features)"
            print(f"{label:40s} {row['score_1row_us']:9.1f} {row['score_window_10row_us']:9.1f}")

    print("\nper position in session (total per call, p50):")
    for row in payload["by_position"]:
        print(f"  {row['bucket']:12s} n={row['n']:5d}   {row['p50_us']:9.1f} us")

    if options.json:
        options.json.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print("\nA report, not a gate: no number here authorises a change.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
