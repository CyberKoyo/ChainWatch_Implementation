"""The arithmetic scripts/inverted_pin.py turns on, tested the way
tests/test_arms_by_length.py tests its script.

The report's whole claim is a threshold chosen to respect a false-positive
budget. If that choice is wrong the detection number beside it is wrong, so
the cases below are the ones the choice can get wrong: ties at the boundary,
budgets it must never exceed, and agreement with the direction ml-eval
already pins.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from chainwatch.ml.evaluate import (  # noqa: E402
    POPULATIONS,
    rule_baseline,
    threshold_for_detection,
)
from scripts import inverted_pin  # noqa: E402


def test_a_tie_at_the_boundary_cannot_buy_detection():
    """The defect the sweep exists to avoid.

    A quantile solve lands on 0.5, sees "one benign at or above" as the
    boundary case and reports 0% FP. The threshold does not deliver it: at
    0.5 the benign session is flagged, so the honest answer is that no
    detection is purchasable at a zero budget.
    """
    attack = np.array([0.5, 0.5])
    benign = np.array([0.5])

    detection, achieved, _ = inverted_pin.pin_at_fp(attack, benign, 0.0)

    assert detection == 0.0
    assert achieved == 0.0


def test_the_budget_is_never_exceeded():
    rng = np.random.default_rng(0)
    for _ in range(50):
        attack = rng.random(20)
        benign = rng.random(20)
        target = float(rng.random())
        _, achieved, _ = inverted_pin.pin_at_fp(attack, benign, target)
        assert achieved <= target + 1e-12


def test_a_larger_budget_never_returns_less_detection():
    rng = np.random.default_rng(1)
    attack = rng.random(30)
    benign = rng.random(30)
    previous = -1.0
    for target in (0.0, 0.1, 0.25, 0.5, 1.0):
        detection, _, _ = inverted_pin.pin_at_fp(attack, benign, target)
        assert detection >= previous
        previous = detection


def test_pinning_at_the_fp_that_detection_pinning_achieves_recovers_it():
    """The two directions must agree where they meet.

    ml-eval fixes detection and reads FP. Feed that FP back in and the
    inverted pin must return at least that detection -- otherwise one of the
    two is leaving achievable operating points on the table.
    """
    rng = np.random.default_rng(2)
    attack = rng.random(40)
    benign = rng.random(40)

    threshold = threshold_for_detection(attack, 0.75)
    detection_there = float((attack >= threshold).mean())
    fp_there = float((benign >= threshold).mean())

    detection, achieved, _ = inverted_pin.pin_at_fp(attack, benign, fp_there)

    assert detection >= detection_there - 1e-12
    assert achieved <= fp_there + 1e-12


def test_an_empty_benign_class_is_refused_rather_than_scored():
    """(benign >= t).mean() on an empty array is nan, and nan reads as a
    number in a report. Same argument as scripts/tf_confound.py's
    _ZERO_VARIANCE guard."""
    with pytest.raises(ValueError):
        inverted_pin.pin_at_fp(np.array([0.4, 0.6]), np.array([]), 0.1)


def _write_traces(directory: Path) -> list[Path]:
    """Two sessions: one attack with three CRITICAL calls, one clean benign.

    Written in the schema CLAUDE.md section 10 specifies, because both trace
    consumers group on ``session`` and skip any line whose ``v`` is not a list.
    """
    rows = [
        {"session": "aaaa0000", "label": "attack", "source": "agentdojo-gpt4omini",
         "call": 1, "severity": "CRITICAL", "rules": ["R3"], "v": [0.0] * 20},
        {"session": "aaaa0000", "label": "attack", "source": "agentdojo-gpt4omini",
         "call": 2, "severity": "CRITICAL", "rules": ["R3"], "v": [0.0] * 20},
        {"session": "aaaa0000", "label": "attack", "source": "agentdojo-gpt4omini",
         "call": 3, "severity": "CRITICAL", "rules": ["R3"], "v": [0.0] * 20},
        {"session": "bbbb1111", "label": "benign", "source": "agentdojo-gpt4omini",
         "call": 1, "severity": "WARNING", "rules": ["R4"], "v": [0.0] * 20},
        {"session": "bbbb1111", "label": "benign", "source": "agentdojo-gpt4omini",
         "call": 2, "severity": "NONE", "rules": [], "v": [0.0] * 20},
    ]
    path = directory / "agentdojo-gpt4omini-test.jsonl"
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    return [path]


def test_critical_baseline_counts_sessions_not_calls(tmp_path):
    """Three CRITICAL calls in one session are one detection, not three."""
    paths = _write_traces(tmp_path)
    populations = POPULATIONS["agentdojo-gpt4omini"]

    point = inverted_pin.critical_baseline(paths, populations)

    assert point.n_attack == 1
    assert point.n_benign == 1
    assert point.detection == 1.0


def test_critical_baseline_ignores_warnings(tmp_path):
    """The benign session fires R4 at WARNING. The loose predicate counts it and
    the CRITICAL predicate must not -- that difference is the whole point of
    reporting both."""
    paths = _write_traces(tmp_path)
    populations = POPULATIONS["agentdojo-gpt4omini"]

    loose = rule_baseline(paths, populations)
    critical = inverted_pin.critical_baseline(paths, populations)

    assert loose.false_positives == 1.0
    assert critical.false_positives == 0.0


def test_self_check_complains_when_the_detection_pin_drifts():
    """The published all-attempts row is A 63.7 / 38.1. A run that no longer
    reproduces it must say so rather than printing the new column beside it."""
    agreeing = {"partition": "all-attempts (sensitivity)",
                "arms": [{"arm": "A (rules)", "detection": 0.637,
                          "false_positives": 0.381}]}
    drifted = {"partition": "all-attempts (sensitivity)",
               "arms": [{"arm": "A (rules)", "detection": 0.500,
                         "false_positives": 0.381}]}

    assert inverted_pin.self_check(agreeing) == []
    problems = inverted_pin.self_check(drifted)
    assert len(problems) == 1
    assert "detection" in problems[0]
