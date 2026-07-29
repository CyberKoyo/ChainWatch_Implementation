"""XGBoost wrapper: fit per call, decide per session.

Thin on purpose. The interesting decisions are in :mod:`chainwatch.ml.dataset`
(which features exist) and :mod:`chainwatch.ml.evaluate` (how it is measured); this
module only has to train honestly and produce a probability.

Per call, per session
---------------------
Rows are per call, because that is the granularity the proxy decides at. But a
*session* is what carries a label, and the rule engine's own notion of "detected" is
"any rule fired at any point in the chain". :func:`session_scores` therefore reduces
a session to the maximum score over its calls, so model and rules are compared on
the same definition rather than on two different ones.

Depth is capped hard. 605 sessions with a label that is inherited rather than
observed does not support a deep model, and an unconstrained tree will happily carve
out individual chains.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from .dataset import Dataset

#: Conservative defaults for a small, noisily-labelled corpus.
DEFAULT_PARAMS: dict[str, Any] = {
    "max_depth": 3,
    "n_estimators": 120,
    "learning_rate": 0.08,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "min_child_weight": 5.0,
    "reg_lambda": 2.0,
    "objective": "binary:logistic",
    "eval_metric": "logloss",
    "tree_method": "hist",
}


class Scorer:
    """A fitted attack-probability model over :class:`Dataset` rows."""

    def __init__(self, booster: Any = None, names: list[str] | None = None) -> None:
        self.booster = booster
        self.names = names or []

    # ------------------------------------------------------------------ training

    @classmethod
    def train(
        cls,
        dataset: Dataset,
        params: dict[str, Any] | None = None,
        seed: int = 0,
    ) -> "Scorer":
        """Fit on every row of ``dataset``. Splitting is the caller's job."""
        import xgboost  # noqa: PLC0415 -- optional dependency, imported only here

        settings = {**DEFAULT_PARAMS, **(params or {}), "random_state": seed}
        # Class balance is roughly 1:2 attack:benign once both benign populations are
        # present; let xgboost correct for it rather than resampling, which would
        # interact badly with the session grouping.
        positives = max(int((dataset.labels == 1).sum()), 1)
        negatives = max(int((dataset.labels == 0).sum()), 1)
        settings.setdefault("scale_pos_weight", negatives / positives)

        model = xgboost.XGBClassifier(**settings)
        model.fit(dataset.rows, dataset.labels, sample_weight=dataset.weights)
        return cls(booster=model, names=list(dataset.names))

    # ------------------------------------------------------------------ inference

    def score(self, rows: np.ndarray) -> np.ndarray:
        """Attack probability per row."""
        if self.booster is None:
            raise RuntimeError("Scorer has no fitted model; call train() or load()")
        rows = np.atleast_2d(rows)
        return np.asarray(self.booster.predict_proba(rows))[:, 1]

    def score_window(self, rows: np.ndarray) -> float:
        """Probability for the most recent call in a window. Used by the proxy."""
        return float(self.score(rows)[-1])

    # ------------------------------------------------------------------ persistence

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.booster.save_model(str(path.with_suffix(".ubj")))
        path.with_suffix(".json").write_text(
            json.dumps({"names": self.names}, indent=2), encoding="utf-8"
        )

    @classmethod
    def load(cls, path: str | Path) -> "Scorer":
        import xgboost  # noqa: PLC0415

        path = Path(path)
        model = xgboost.XGBClassifier()
        model.load_model(str(path.with_suffix(".ubj")))
        meta = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
        return cls(booster=model, names=meta.get("names", []))


def session_scores(dataset: Dataset, scores: np.ndarray) -> dict[str, float]:
    """Reduce per-call scores to one score per session, by maximum.

    Maximum rather than mean, to match the rule engine: a chain counts as detected if
    *any* rule fired anywhere in it, so a mean would quietly hold the model to a
    stricter standard and make the comparison meaningless.
    """
    best: dict[str, float] = {}
    for session, score in zip(dataset.sessions, scores):
        key = str(session)
        if score > best.get(key, -np.inf):
            best[key] = float(score)
    return best


def session_labels(dataset: Dataset) -> tuple[dict[str, int], dict[str, str]]:
    """Per-session label and source, for scoring populations separately."""
    labels: dict[str, int] = {}
    sources: dict[str, str] = {}
    for session, label, source in zip(dataset.sessions, dataset.labels, dataset.sources):
        labels[str(session)] = int(label)
        sources[str(session)] = str(source)
    return labels, sources
