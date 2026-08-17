"""The stratification's own logic, tested the way tests/test_tf_confound.py tests its script.

The report in scripts/arms_by_length.py is only as trustworthy as three things: that a
stratum contains exactly the sessions whose length belongs in it, that the native-valid
filter is applied rather than merely offered, and that the self-check against
GPT_GRID_RESULTS.md section 10.7.3 actually fails when the numbers drift. The corpus itself
is not exercised here -- that is what ``--self-check`` is for, against the real grid.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import arms_by_length  # noqa: E402


def _lengths(**pairs):
    return dict(pairs)


def test_strata_partition_every_length_exactly_once():
    """The two reported strata must tile the line, or a session vanishes from both."""
    (low_name, low_lo, low_hi), (high_name, high_lo, high_hi), (all_name, *_) = (
        arms_by_length.strata(5)
    )

    assert low_name == "<=5 calls" and (low_lo, low_hi) == (1, 5)
    assert high_name == ">5 calls" and high_lo == 6
    assert all_name == "all"
    # No gap and no overlap at the boundary: 5 falls in the first, 6 in the second.
    assert low_hi + 1 == high_lo
    assert high_hi > 10**6, "the upper stratum must not silently cap session length"


def test_the_split_is_a_named_constant_at_the_documented_attack_span():
    """CLAUDE.md, "Sequential Pattern Analyzer (§IV-D)" documents 4-7 call attacks; the split is its lower boundary.

    Asserted because a split chosen after seeing the result is a fished stratification,
    and the defence against that is that the number is fixed in the module.
    """
    assert arms_by_length.LENGTH_SPLIT == 5
    assert arms_by_length.strata()[0][2] == arms_by_length.LENGTH_SPLIT


def test_select_keeps_only_sessions_inside_the_length_band():
    lengths = _lengths(a=1, b=5, c=6, d=26)
    labels = {k: "benign" for k in lengths}

    low = arms_by_length.select(lengths, labels, {}, native_valid=False, low=1, high=5)
    high = arms_by_length.select(lengths, labels, {}, native_valid=False, low=6, high=1 << 30)

    assert low == ["a", "b"]
    assert high == ["c", "d"]
    assert set(low) & set(high) == set(), "a session must not be in both strata"


def test_native_valid_selection_drops_sessions_the_benchmark_did_not_validate():
    """A resisted attack and an uncompleted benign task are both excluded.

    Without this the primary partition would silently become all-attempts, which is the
    sensitivity analysis -- the two answer different questions and section 10.7 keeps them
    apart.
    """
    lengths = _lengths(succeeded=3, resisted=3, completed=3, incomplete=3)
    labels = {
        "succeeded": "attack",
        "resisted": "attack",
        "completed": "benign",
        "incomplete": "benign",
    }
    # ``route`` is load-bearing: native_outcomes reads it off the manifest coordinate,
    # and is_native_valid dispatches on it before looking at either check.
    outcomes = {
        "succeeded": {"route": "agentdojo", "security": True, "utility": None},
        "resisted": {"route": "agentdojo", "security": False, "utility": None},
        "completed": {"route": "agentdojo", "security": None, "utility": True},
        "incomplete": {"route": "agentdojo", "security": None, "utility": False},
    }

    kept = arms_by_length.select(
        lengths, labels, outcomes, native_valid=True, low=1, high=1 << 30
    )

    assert kept == ["completed", "succeeded"]


def test_a_session_whose_route_is_unrecognised_is_excluded():
    """is_native_valid dispatches on route and returns False for anything else.

    A legacy population carries no published check, so an unrecognised route must not
    reach the primary analysis -- the analysis that exists to be verified.
    """
    lengths = _lengths(legacy=4)
    outcomes = {"legacy": {"route": "agentlab", "security": True}}

    kept = arms_by_length.select(
        lengths, {"legacy": "attack"}, outcomes, native_valid=True, low=1, high=1 << 30
    )

    assert kept == []


def test_an_unknown_session_is_excluded_rather_than_assumed_valid():
    """is_native_valid fails closed, and the selection must not undo that."""
    lengths = _lengths(unknown=4)

    kept = arms_by_length.select(
        lengths, {"unknown": "attack"}, {}, native_valid=True, low=1, high=1 << 30
    )

    assert kept == []


def test_min_sessions_floor_is_high_enough_that_one_session_is_not_a_decimal_place():
    """Below MIN_SESSIONS a rate printed to three decimals overstates its precision."""
    assert arms_by_length.MIN_SESSIONS >= 10


def test_self_check_passes_on_the_published_section_10_7_3_numbers():
    result = {
        "arms": [
            {"arm": "A (rules)", "detection": 1.0, "false_positives": 0.5526, "auc": None},
            {"arm": "B", "detection": 1.0, "false_positives": 0.0, "auc": 1.0},
            {"arm": "D", "detection": 1.0, "false_positives": 0.0, "auc": 1.0},
            {"arm": "E", "detection": 1.0, "false_positives": 0.4737, "auc": 0.943},
        ]
    }

    assert arms_by_length.self_check(result) == []


def test_self_check_fails_and_names_the_arm_when_a_number_drifts():
    """A self-check that cannot fail is decoration. Arm B's 0.0 is the load-bearing one."""
    result = {
        "arms": [
            {"arm": "B", "detection": 1.0, "false_positives": 0.25, "auc": 0.9},
        ]
    }

    problems = arms_by_length.self_check(result)

    assert len(problems) == 1
    assert "B" in problems[0] and "false_positives" in problems[0]
    assert "0.250" in problems[0] and "0.00" in problems[0]


def test_self_check_ignores_a_skipped_arm_rather_than_reading_a_missing_key():
    """A single-class stratum yields no numbers; that is not a drift to report."""
    result = {"arms": [{"arm": "B", "skipped": "single-class stratum"}]}

    assert arms_by_length.self_check(result) == []


def test_format_row_prints_a_dash_for_the_rule_arm_rather_than_a_fabricated_auc():
    """Arm A is a hard predicate, so it has no ranking and therefore no AUC."""
    rendered = arms_by_length.format_row(
        {"arm": "A (rules)", "detection": 1.0, "false_positives": 0.553, "auc": None}
    )

    assert "AUC   -" in rendered
    assert "nan" not in rendered


def test_main_refuses_when_no_trace_files_match_the_source(tmp_path, monkeypatch):
    """Exit 2, not 0: a run that measured nothing must not look like a clean report.

    Note 14's shape -- a capture run that captures nothing exiting 0 -- one layer up.
    """
    monkeypatch.setenv("CHAINWATCH_HOME", str(tmp_path))

    assert arms_by_length.main(["--source", "does-not-exist"]) == 2


def test_main_refuses_when_the_manifest_is_missing(tmp_path, monkeypatch):
    """Without a manifest the primary partition would print empty under its own heading."""
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "fake-001.jsonl").write_text(
        '{"session":"fake-001","label":"benign","source":"fake","call":1,'
        '"v":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("CHAINWATCH_HOME", str(tmp_path))

    assert arms_by_length.main(["--source", "fake"]) == 2


def test_main_rejects_an_unknown_arm_by_name(tmp_path, monkeypatch):
    monkeypatch.setenv("CHAINWATCH_HOME", str(tmp_path))

    assert arms_by_length.main(["--source", "nope", "--arms", "Z"]) == 2
