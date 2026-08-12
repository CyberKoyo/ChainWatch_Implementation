"""Stage 1's arithmetic, tested the way tests/test_grid_readiness.py tests its script.

The gate in scripts/tf_confound.py is only as trustworthy as its partial correlation,
so the cases that matter are the two the gate turns on: a variable that is nothing but
a control (correlation must collapse to ~0) and one that is independent of the control
(correlation must survive intact).
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import tf_confound  # noqa: E402


def test_a_pure_function_of_the_control_has_no_partial_correlation():
    """A length proxy must fail G2. This is the win_occupancy shape, in miniature."""
    lengths = np.array([2.0, 4.0, 6.0, 8.0, 10.0, 12.0])
    label = np.array([0.0, 0.0, 0.0, 1.0, 1.0, 1.0])
    # x is length and nothing else, so once length is residualised out nothing remains.
    x = lengths * 3.0

    raw = float(np.corrcoef(x, label)[0, 1])
    partial = tf_confound.partial_correlation(x, label, lengths[:, None])

    assert abs(raw) > 0.8
    assert abs(partial) < 1e-6


def test_a_signal_independent_of_the_control_keeps_its_correlation():
    lengths = np.array([5.0, 5.0, 5.0, 5.0, 5.0, 5.0])
    label = np.array([0.0, 0.0, 0.0, 1.0, 1.0, 1.0])
    x = np.array([0.1, 0.2, 0.15, 0.9, 0.85, 0.95])

    raw = float(np.corrcoef(x, label)[0, 1])
    partial = tf_confound.partial_correlation(x, label, lengths[:, None])

    assert partial == pytest.approx(raw, abs=1e-9)


def test_a_constant_column_reports_zero_rather_than_nan():
    """np.corrcoef on a zero-variance column yields nan, which reads as a number."""
    controls = np.array([1.0, 2.0, 3.0, 4.0])[:, None]
    constant = np.array([0.0, 0.0, 0.0, 0.0])
    label = np.array([0.0, 0.0, 1.0, 1.0])

    assert tf_confound.partial_correlation(constant, label, controls) == 0.0


def test_the_verdict_names_the_criterion_that_decided_it():
    """A bare pass/fail cannot be audited; every rejection says which gate it failed."""
    uninformative = tf_confound.format_verdict("tf_call_rate", "mean", 0.01, 0.01)
    length_proxy = tf_confound.format_verdict("tf_session_age", "max", 0.40, 0.05)
    admitted = tf_confound.format_verdict("tf_interval", "mean", 0.30, 0.25)

    assert "REJECTED uninformative" in uninformative and "G1" in uninformative
    assert "REJECTED length proxy" in length_proxy and "G2" in length_proxy
    assert "ADMITTED" in admitted
