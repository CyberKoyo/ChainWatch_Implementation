#!/usr/bin/env python
"""Do the temporal features carry the label, or do they carry session length?

Phase 8's ``win_occupancy`` was session length wearing a feature's name: attacks
averaged 2.8 calls against 26-call benign sessions, so a depth-3 tree split on it
once and the corpus looked separable. Dims 10-12 are the temporal group, and the
same question has never been asked of them on the v3 grid.

The answer is a partial correlation: correlate each dimension with the label after
residualising *both* on the session's call count. A dimension that is nothing but a
length proxy loses its correlation entirely; one that carries independent signal
keeps it.

This is a report, not a gate. It exits 0 and prints a verdict per dimension; no
threshold here authorises a change to a rule, a prior, or a slide.
"""

from __future__ import annotations

import numpy as np

#: Below this raw correlation there is nothing for the control to explain, so the
#: partial correlation is uninterpretable rather than reassuring. Reported as G1.
G1_MIN_RAW = 0.05

#: A dimension keeping less than this fraction of its raw correlation once length
#: is residualised out was reporting length. Reported as G2.
G2_RETAINED_FRACTION = 0.5

#: Below this standard deviation a residual is constant, and ``np.corrcoef`` on a
#: constant column returns nan -- which reads as a number in a report table.
_ZERO_VARIANCE = 1e-12


def _residualise(values: np.ndarray, controls: np.ndarray) -> np.ndarray:
    """What is left of ``values`` once the controls have explained what they can.

    Least squares against an intercept plus the controls. ``lstsq`` is used rather
    than a normal-equations solve because a constant control column makes the
    design singular, and the minimum-norm solution is the right answer there: with
    nothing to regress out, the residual is the centred variable.
    """
    design = np.column_stack([np.ones(len(values)), controls])
    coefficients, *_ = np.linalg.lstsq(design, values, rcond=None)
    return values - design @ coefficients


def partial_correlation(
    x: np.ndarray, label: np.ndarray, controls: np.ndarray
) -> float:
    """Correlation of ``x`` with ``label``, holding ``controls`` fixed.

    Returns 0.0, never nan, when either residual is constant. A nan in this column
    would print as a value and be read as one -- note 31's species, one layer up.
    """
    x = np.asarray(x, dtype=np.float64)
    label = np.asarray(label, dtype=np.float64)
    controls = np.asarray(controls, dtype=np.float64)
    if controls.ndim == 1:
        controls = controls[:, None]

    residual_x = _residualise(x, controls)
    residual_label = _residualise(label, controls)
    if residual_x.std() < _ZERO_VARIANCE or residual_label.std() < _ZERO_VARIANCE:
        return 0.0
    return float(np.corrcoef(residual_x, residual_label)[0, 1])


def format_verdict(name: str, stat: str, raw: float, partial: float) -> str:
    """One dimension's verdict, naming the criterion that decided it.

    A bare pass/fail cannot be audited six weeks later. Every rejection says which
    gate rejected it and what that gate's threshold was.
    """
    if abs(raw) < G1_MIN_RAW:
        verdict = f"REJECTED uninformative (G1: |raw| < {G1_MIN_RAW:.2f})"
    elif abs(partial) < G2_RETAINED_FRACTION * abs(raw):
        verdict = (
            f"REJECTED length proxy "
            f"(G2: |partial| < {G2_RETAINED_FRACTION:.2f} x |raw|)"
        )
    else:
        verdict = (
            f"ADMITTED (G1 |raw| >= {G1_MIN_RAW:.2f}, "
            f"G2 |partial| >= {G2_RETAINED_FRACTION:.2f} x |raw|)"
        )
    return f"{name:16s} {stat:4s}  raw {raw:+.3f}  partial {partial:+.3f}  {verdict}"
