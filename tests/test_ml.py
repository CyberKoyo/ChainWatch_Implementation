"""Tests for the supervised layer.

These guard the *protocol*, not the model's accuracy. A number produced by a leaky
split is worse than no number, so what is asserted here is that folds cannot leak,
that excluded features stay excluded, and that the numpy-only install path is
unchanged by any of this.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from chainwatch.engine.session import SessionAnalyzer
from chainwatch.ml import dataset as ds

xgboost = pytest.importorskip("xgboost", reason="requires the [ml] extra")

from chainwatch.ml.evaluate import (  # noqa: E402 -- must follow importorskip
    _auc,
    _folds,
    rule_baseline,
    threshold_for_detection,
)
from chainwatch.ml.scorer import Scorer, session_scores  # noqa: E402


def write_traces(path, sessions):
    """Write a minimal JSONL trace file. ``sessions`` maps id -> list of call dicts."""
    with path.open("w", encoding="utf-8") as handle:
        for session, calls in sessions.items():
            for index, call in enumerate(calls, start=1):
                handle.write(
                    json.dumps(
                        {
                            "session": session,
                            "label": call.get("label", "benign"),
                            "source": call.get("source", "realism"),
                            "environment": call.get("environment", "banking"),
                            "call": index,
                            "tool": call.get("tool", "get_file"),
                            "server": call.get("server", "banking"),
                            "stage": call.get("stage", 1),
                            "rules": call.get("rules", []),
                            "v": call["v"],
                        }
                    )
                    + "\n"
                )
    return path


def vector(**overrides):
    """A 20-dim feature vector, READ by default."""
    v = [0.0] * 20
    v[0] = 1.0
    for index, value in overrides.items():
        v[int(index)] = value
    return v


@pytest.fixture
def traces(tmp_path):
    return write_traces(
        tmp_path / "t.jsonl",
        {
            "attack-1": [
                {"v": vector(), "label": "attack", "source": "agentlab"},
                {"v": vector(**{"3": 1.0, "0": 0.0, "8": 1.0}), "label": "attack",
                 "source": "agentlab", "stage": 6, "rules": ["R3"], "tool": "post_webhook"},
            ],
            "benign-1": [
                {"v": vector()},
                {"v": vector(**{"5": 0.2})},
            ],
        },
    )


# ------------------------------------------------------------------ feature groups


def test_temporal_dims_never_reach_the_model(traces):
    """TF dims 10-12 are replay artifacts: call_rate hit 1816/sec under batch replay."""
    built = ds.build(traces, groups=("current",))
    assert len(built.names) == 17
    assert not any("tf_" in name or "interval" in name or "rate" in name for name in built.names)


def test_no_feature_correlates_with_session_length(tmp_path):
    """Benign realism averages 26.3 calls vs attacks' 2.8 -- length is a corpus artifact.

    Regression test for a real leak: a ``win_occupancy`` feature (``len(window)/size``)
    read as innocuous, correlated almost perfectly with session length, became arm D's
    single most important feature and pushed the false-positive rate to 0.0%.

    Asserting a feature's *range* proves nothing; this asserts its *correlation*.
    """
    path = write_traces(
        tmp_path / "len.jsonl",
        {
            "short": [{"v": vector()} for _ in range(2)],
            "long": [{"v": vector()} for _ in range(30)],
        },
    )
    built = ds.build(path, groups=("current", "window"))
    lengths = np.array(
        [(built.sessions == session).sum() for session in built.sessions], dtype=float
    )

    for index, name in enumerate(built.names):
        column = built.rows[:, index]
        if column.std() == 0:
            continue
        correlation = abs(float(np.corrcoef(column, lengths)[0, 1]))
        assert correlation < 0.9, f"{name} tracks session length (r={correlation:.2f})"


def test_arm_groups_are_nested_as_documented(traces):
    widths = {arm: ds.build(traces, groups=groups).rows.shape[1] for arm, groups in ds.ARMS.items()}
    assert widths["E"] < widths["B"] < widths["D"]
    assert widths["C"] < widths["D"]


def test_rule_features_read_the_fired_rules(traces):
    built = ds.build(traces, groups=("rules",))
    column = built.names.index("rule_r3")
    assert built.rows[:, column].max() == 1.0


def test_later_calls_carry_more_weight(traces):
    """Call 1 of an attack chain is indistinguishable from benign but shares its label."""
    built = ds.build(traces, groups=("current",))
    assert built.weights.max() > built.weights.min()


# ------------------------------------------------------------------- populations


def test_shade_is_excluded_from_training_sources(tmp_path):
    path = write_traces(
        tmp_path / "s.jsonl",
        {
            "a": [{"v": vector(), "label": "attack", "source": "agentlab"}],
            "s": [{"v": vector(), "label": "attack", "source": "shade"}],
        },
    )
    built = ds.build(path, sources=("agentlab", "realism", "control"))
    assert "shade" not in set(built.sources.tolist())


def test_false_positive_source_is_realism_only(tmp_path):
    """Control is surface-matched to attacks; quoting it as an FP rate misreports it."""
    path = write_traces(
        tmp_path / "c.jsonl",
        {
            "a": [{"v": vector(), "label": "attack", "source": "agentlab", "rules": ["R3"]}],
            "r": [{"v": vector(), "source": "realism", "rules": ["R3"]}],
            "c": [{"v": vector(), "source": "control", "rules": ["R3"]}],
        },
    )
    baseline = rule_baseline(path)
    assert baseline.false_positives == 1.0
    assert baseline.control_rate == 1.0
    assert baseline.n_benign == 1  # control is not in the benign denominator


def test_rule_baseline_ignores_shade(tmp_path):
    path = write_traces(
        tmp_path / "b.jsonl",
        {
            "a": [{"v": vector(), "label": "attack", "source": "agentlab"}],
            "s": [{"v": vector(), "label": "attack", "source": "shade", "rules": ["R3"]}],
        },
    )
    assert rule_baseline(path).n_attack == 1


# ---------------------------------------------------------------------- protocol


def test_folds_never_split_a_session():
    sessions = np.array(["a", "a", "a", "b", "b", "c"], dtype=object)
    folds = _folds(sessions, k=3, seed=0)
    seen = [set(fold.tolist()) for fold in folds]
    for left in range(len(seen)):
        for right in range(left + 1, len(seen)):
            assert not seen[left] & seen[right]
    assert set().union(*seen) == {"a", "b", "c"}


def test_threshold_hits_the_requested_detection():
    scores = np.array([0.9, 0.8, 0.7, 0.2, 0.1])
    threshold = threshold_for_detection(scores, 0.6)
    assert (scores >= threshold).mean() >= 0.6


def test_auc_is_half_when_scores_are_tied():
    assert _auc(np.array([0.5, 0.5]), np.array([0.5, 0.5])) == 0.5


def test_session_score_takes_the_maximum(traces):
    """Rules count a chain as detected if any rule fired anywhere; match that."""
    built = ds.build(traces, groups=("current",))
    scores = np.linspace(0.1, 0.9, len(built))
    reduced = session_scores(built, scores)
    assert max(reduced.values()) == pytest.approx(0.9)


# ------------------------------------------------------------------------ scorer


def test_scorer_round_trips(traces, tmp_path):
    built = ds.build(traces, groups=("current", "window"))
    model = Scorer.train(built, seed=0)
    before = model.score(built.rows)

    model.save(tmp_path / "m")
    after = Scorer.load(tmp_path / "m").score(built.rows)
    assert np.allclose(before, after)


def test_unfitted_scorer_refuses_to_guess():
    with pytest.raises(RuntimeError):
        Scorer().score(np.zeros((1, 3)))


# ------------------------------------------------------------------ engine intact


def test_engine_has_no_scorer_by_default():
    """The numpy-only install path must behave exactly as before."""
    analyzer = SessionAnalyzer()
    assert getattr(analyzer, "scorer", None) is None
