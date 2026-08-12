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

import argparse
import glob
import os
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chainwatch.ml.dataset import load_sessions  # noqa: E402
from chainwatch.ml.native import is_native_valid, native_outcomes  # noqa: E402

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


#: The TF group from CLAUDE.md section 5, by fixed index. The names are the ones
#: dataset.py already uses for these columns, so a reader can cross-reference.
TF_DIMENSIONS = ((10, "tf_interval"), (11, "tf_call_rate"), (12, "tf_session_age"))


def session_table(sessions):
    """One row per session: mean and max of each TF dimension, plus the control.

    Aggregated per session rather than per call because the label is a property of
    the session, and a per-call table would weight a 40-call session forty times
    while the thing being tested *is* the influence of call count.
    """
    features, labels, lengths, ids = [], [], [], []
    for calls in sessions:
        vectors = np.array([np.asarray(call["v"], dtype=np.float64) for call in calls])
        row = []
        for index, _name in TF_DIMENSIONS:
            column = vectors[:, index]
            row.extend([float(column.mean()), float(column.max())])
        features.append(row)
        labels.append(1.0 if calls[0].get("label") == "attack" else 0.0)
        lengths.append(float(len(calls)))
        ids.append(str(calls[0].get("session")))
    return np.array(features), np.array(labels), np.array(lengths), ids


def report_partition(name, sessions, out=sys.stdout):
    """Both statistics of all three dimensions, for one partition.

    Partitions are printed separately and never merged: native-valid is the primary
    analysis and all-attempts the sensitivity, and a table that pooled them would be
    a rate over two different questions.
    """
    print(f"\n-- {name} " + "-" * max(0, 60 - len(name)), file=out)
    if len(sessions) < 3:
        print(f"  {len(sessions)} sessions: too few to correlate; no verdict stated",
              file=out)
        return
    features, labels, lengths, _ = session_table(sessions)
    print(f"  {len(sessions)} sessions, control = session call count "
          f"(mean {lengths.mean():.1f}, max {lengths.max():.0f})", file=out)
    if labels.std() < _ZERO_VARIANCE:
        print("  one class only: nothing to correlate against", file=out)
        return
    for column, (_index, dimension) in enumerate(TF_DIMENSIONS):
        for offset, stat in ((0, "mean"), (1, "max")):
            values = features[:, column * 2 + offset]
            raw = 0.0 if values.std() < _ZERO_VARIANCE else float(
                np.corrcoef(values, labels)[0, 1])
            partial = partial_correlation(values, labels, lengths[:, None])
            print("  " + format_verdict(dimension, stat, raw, partial), file=out)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="tf_confound")
    parser.add_argument("--traces", nargs="*", default=None)
    parser.add_argument("--source", default="agentdojo-gpt4omini")
    options = parser.parse_args(argv)

    home = Path(os.environ.get("CHAINWATCH_HOME", Path.home() / ".chainwatch"))
    paths = options.traces or sorted(
        glob.glob(str(home / "logs" / f"{options.source}-*.jsonl")))
    if not paths:
        sys.stderr.write(f"tf_confound: no trace files for source {options.source!r}\n")
        return 2

    sessions = [calls for calls in load_sessions(paths)
                if str(calls[0].get("source")) == options.source]
    outcomes = native_outcomes(sorted(home.glob("*_manifest.jsonl")))

    print("=" * 72)
    print("TF confound gate -- do dims 10-12 survive controlling for session length?")
    print(f"source {options.source}  |  {len(paths)} trace files")
    print("=" * 72)

    valid = [calls for calls in sessions
             if is_native_valid(str(calls[0].get("session")),
                                str(calls[0].get("label")), outcomes)]
    report_partition("native-valid (primary)", valid)
    report_partition("all-attempts (sensitivity)", sessions)
    print("\nA report, not a gate: no verdict here authorises a change.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
