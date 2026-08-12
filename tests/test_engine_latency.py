"""The latency report's correctness, which is entirely about what it pairs and reports.

A timing number cannot be asserted -- it is different on every machine and every run. What
*can* be asserted is everything that decides which bytes get timed and how the result is
labelled: the response pairing, the unit conversion, the percentile convention, and the
containment structure of the stage table. Those are where a wrong latency figure would come
from, so those are what is tested.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import engine_latency  # noqa: E402


def _trace(tool="read_file", **extra):
    return {"tool": tool, "args": {"path": "x"}, "server": "suite-app", **extra}


def _result(tool="read_file", result="body"):
    return {"type": "tool_result", "tool": tool, "result": result}


def test_as_text_passes_a_string_through_unchanged():
    """The byte count the OC regexes are timed over must be the wire's, not a re-encoding."""
    assert engine_latency.as_text("already text") == "already text"


def test_as_text_encodes_a_structure_the_way_the_bridge_does():
    """env_mcp_server._as_text uses ensure_ascii=False; diverging would change the bytes."""
    encoded = engine_latency.as_text({"note": "café"})

    assert "café" in encoded, "ensure_ascii=False, or the byte count inflates"
    assert encoded == '{"note": "café"}'


def test_pair_session_pairs_by_order_and_carries_the_per_call_server():
    """``server`` comes from the trace, since v3 asserts the topology per call."""
    paired = engine_latency.pair_session(
        [_trace("read_file"), _trace("send_money", server="banking-banking")],
        [_result("read_file", "the file"), _result("send_money", {"ok": True})],
    )

    assert [row["tool"] for row in paired] == ["read_file", "send_money"]
    assert [row["server"] for row in paired] == ["suite-app", "banking-banking"]
    assert paired[0]["response"] == "the file"
    assert paired[1]["response"] == '{"ok": true}'


def test_pair_session_ignores_transcript_rows_that_are_not_tool_results():
    """A transcript interleaves assistant messages with results; only results pair."""
    paired = engine_latency.pair_session(
        [_trace()],
        [{"message": "thinking out loud"}, _result(), {"message": "done"}],
    )

    assert paired is not None and len(paired) == 1


def test_pair_session_refuses_a_count_mismatch_rather_than_truncating():
    """Mispairing would time the wrong response against the wrong call.

    That is a wrong number that still looks like a number, so the session is dropped whole
    -- fixture_audit.py's rule that a session with a bad call excised is a sequence that
    never occurred.
    """
    assert engine_latency.pair_session([_trace(), _trace()], [_result()]) is None
    assert engine_latency.pair_session([_trace()], [_result(), _result()]) is None


def test_pair_session_refuses_an_empty_trace():
    """Zero calls paired is not a session; it would contribute nothing but a denominator."""
    assert engine_latency.pair_session([], []) is None


def test_pair_session_defaults_a_missing_server_rather_than_raising():
    """Pre-topology traces carry no ``server``; they are still timeable."""
    paired = engine_latency.pair_session([{"tool": "t"}], [_result("t")])

    assert paired[0]["server"] == "default"
    assert paired[0]["arguments"] == {}


def test_percentile_is_nearest_rank_and_keeps_the_input_units():
    values = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]

    assert engine_latency.percentile(values, 0.50) == 60.0
    assert engine_latency.percentile(values, 0.0) == 10.0
    # Never indexes past the end, which is what makes p99 safe on a short list.
    assert engine_latency.percentile(values, 1.0) == 100.0
    assert engine_latency.percentile([42], 0.99) == 42.0


def test_percentile_of_nothing_is_nan_rather_than_an_index_error():
    result = engine_latency.percentile([], 0.5)

    assert result != result, "nan, so an empty stage cannot print as a plausible number"


def test_report_converts_nanoseconds_to_microseconds():
    """The table header says microseconds; the timers produce nanoseconds."""
    row = engine_latency.report("stage", [1_000, 2_000, 3_000, 4_000])

    assert row["stage"] == "stage"
    assert row["n"] == 4
    assert row["max_us"] == 4.0
    assert row["mean_us"] == 2.5
    assert row["p50_us"] == 3.0


def test_bench_min_returns_the_fastest_run_and_runs_the_body_every_time():
    calls = []

    engine_latency.bench_min(lambda: calls.append(1), repeats=5)

    assert len(calls) == 5, "every repeat must actually execute, or the minimum is a fiction"


def test_bench_min_never_returns_a_negative_or_none():
    assert engine_latency.bench_min(lambda: None, repeats=3) >= 0


def test_position_buckets_tile_every_position_with_no_gap():
    """A call falling into no bucket would vanish from the per-position table."""
    seen = {engine_latency.position_bucket(index) for index in range(0, 40)}

    assert seen == {name for _low, _high, name in engine_latency.POSITION_BUCKETS}
    assert engine_latency.position_bucket(0) == "call 1-2"
    assert engine_latency.position_bucket(1) == "call 1-2"
    assert engine_latency.position_bucket(2) == "call 3-5"
    assert engine_latency.position_bucket(4) == "call 3-5"
    assert engine_latency.position_bucket(5) == "call 6+"
    assert engine_latency.position_bucket(10_000) == "call 6+"


def test_the_position_split_matches_the_capability_report():
    """The latency and capability stories must be cut the same way to be read together."""
    from scripts import arms_by_length

    first_of_last_bucket = engine_latency.POSITION_BUCKETS[-1][0]

    assert first_of_last_bucket == arms_by_length.LENGTH_SPLIT


def test_stage_labels_encode_containment_by_indentation():
    """An indented row is a component of the row above it, and the totals are flush left.

    Asserted because the table is read as a decomposition: if a component were rendered
    flush left it would be summed with its own parent by any reader.
    """
    stages = engine_latency.STAGES

    assert len(stages) == 7
    assert not stages[0].startswith(" ") and stages[0].startswith("submit")
    assert all(stages[i].startswith("  ") for i in (1, 2, 3, 5))
    assert not stages[4].startswith(" ") and stages[4].startswith("complete")
    assert stages[6].startswith("TOTAL")


def test_main_refuses_when_no_session_pairs(tmp_path, monkeypatch):
    """Exit 2, not 0. Note 14: a run that measured nothing must not look like a clean one."""
    monkeypatch.setenv("CHAINWATCH_HOME", str(tmp_path))

    assert engine_latency.main(["--source", "does-not-exist"]) == 2


def test_main_refuses_when_traces_exist_but_no_transcript_does(tmp_path, monkeypatch):
    """The responses are the point; without them there is nothing to sweep."""
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "fake-001.jsonl").write_text(
        '{"session":"fake-001","tool":"read_file","args":{},"server":"s","call":1}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("CHAINWATCH_HOME", str(tmp_path))

    assert engine_latency.main(["--source", "fake"]) == 2
