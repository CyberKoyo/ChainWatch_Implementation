"""Five arms, one protocol, one honest number.

The question is narrow and worth stating precisely, because a looser one is easy to
answer and useless: **can a learned model reduce the false-positive rate without
giving up detection?**

Not "can it score well". The rule engine already detects 38.5% of attack chains, and
its problem is that it also blocks 17.5% of legitimate ones -- and because R3 is
CRITICAL, every one of those is a killed tool call rather than a flagged one. R3 is a
hard predicate with no threshold to turn, so it cannot trade a little detection for a
lot of precision. A probability can. That is the entire hypothesis.

So the headline metric is **false positives at matched detection**: pin each arm to
the rule engine's own detection rate, then read off what it costs in false alarms.
An arm that raises detection while raising false positives has not helped.

Arms
----
======  ====================================  ===========================================
A       rule engine                           baseline
B       current + window                      can a tree find it without kill-chain state?
C       hmm + rules                           is the HMM's conclusion alone enough?
D       everything                            does stacking beat either half?
E       current only                          would a tree replace the whole design?
======  ====================================  ===========================================

Protocol, and why each piece is there
-------------------------------------
*Session-grouped CV* -- calls from one chain must never straddle a fold, or the model
is scored on chains it partly memorised.

*Leave-one-environment-out* -- only 126 distinct tool names exist across four
environments. Memorising them is trivial and looks like learning. Holding out a whole
environment is the closest available proxy for meeting unfamiliar tools in production.

*Permutation floor* -- with 605 sessions and a flexible model, some apparent skill is
luck. Shuffling labels and refitting says how much. A result inside the floor is not
a result.

*Population discipline* -- false-positive numbers come from ``realism`` only.
``control`` is surface-matched to the attack corpus on length and category mix, so it
answers a different question: is the model exploiting shape rather than behaviour?
``shade`` is never trained on and is reported per chain, because five chains cannot
carry a percentage but two of them are matched attack/benign twins -- the only place
in the corpus where a model can be asked to separate an attack from the same work
without the attack.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import numpy as np

from ..engine.taxonomy import ToolCategory, ToolClassifier
from .dataset import ARMS, Dataset, build, load_sessions
from .scorer import Scorer, session_labels, session_scores

#: Populations the model may learn from. SHADE is deliberately absent.
TRAIN_SOURCES = ("agentlab", "realism", "control")

#: Where false-positive claims come from.
FP_SOURCE = "realism"


@dataclass
class Operating:
    """One arm at one operating point."""

    arm: str
    detection: float
    false_positives: float
    control_rate: float
    threshold: float
    auc: float
    n_attack: int
    n_benign: int
    notes: list[str] = field(default_factory=list)


# ------------------------------------------------------------------------- metrics


def _auc(positive: np.ndarray, negative: np.ndarray) -> float:
    """Rank-based AUC. Ties contribute a half, as they should."""
    if positive.size == 0 or negative.size == 0:
        return float("nan")
    comparisons = positive[:, None] - negative[None, :]
    return float((np.sum(comparisons > 0) + 0.5 * np.sum(comparisons == 0)) / comparisons.size)


def threshold_for_detection(attack: np.ndarray, target: float) -> float:
    """Lowest threshold achieving at least ``target`` detection on attacks."""
    if attack.size == 0:
        return 1.0
    ordered = np.sort(attack)[::-1]
    index = min(int(np.ceil(target * attack.size)) - 1, attack.size - 1)
    return float(ordered[max(index, 0)])


# ------------------------------------------------------------------------ arm A


def rule_baseline(path: str | Path) -> Operating:
    """The rule engine's own numbers, read straight out of the traces.

    Recomputed here rather than quoted from CLAUDE.md so the comparison is against
    the same corpus file the models are trained on, not a remembered figure.
    """
    attack = benign = control = 0
    detected_attack = detected_benign = detected_control = 0

    for calls in load_sessions(path):
        source = str(calls[0].get("source"))
        if source == "shade":
            continue
        # R1-R5 only. "STAGE" is the INFO-level suspicious-stage signal, which
        # ChainResult.detected explicitly does not count as a detection -- counting it
        # here would inflate the baseline and mis-pin every arm's threshold.
        fired = any(set(call.get("rules") or []) - {"STAGE"} for call in calls)
        if calls[0].get("label") == "attack":
            attack += 1
            detected_attack += fired
        elif source == FP_SOURCE:
            benign += 1
            detected_benign += fired
        elif source == "control":
            control += 1
            detected_control += fired

    return Operating(
        arm="A (rules)",
        detection=detected_attack / max(attack, 1),
        false_positives=detected_benign / max(benign, 1),
        control_rate=detected_control / max(control, 1),
        threshold=float("nan"),
        auc=float("nan"),
        n_attack=attack,
        n_benign=benign,
        notes=["hard predicate: no threshold to tune"],
    )


# ------------------------------------------------------------- cross-validation


def _folds(sessions: np.ndarray, k: int, seed: int) -> list[np.ndarray]:
    """Split *sessions* (not rows) into k groups, so no chain straddles a fold."""
    unique = np.array(sorted(set(sessions.tolist())), dtype=object)
    rng = np.random.default_rng(seed)
    rng.shuffle(unique)
    return [unique[i::k] for i in range(k)]


def out_of_fold_scores(dataset: Dataset, k: int = 5, seed: int = 0) -> np.ndarray:
    """Score every row from a model that never saw its session."""
    scores = np.zeros(len(dataset))
    for held_out in _folds(dataset.sessions, k, seed):
        test_mask = np.isin(dataset.sessions, held_out)
        if not test_mask.any() or test_mask.all():
            continue
        model = Scorer.train(dataset.select(~test_mask), seed=seed)
        scores[test_mask] = model.score(dataset.rows[test_mask])
    return scores


def environment_holdout_scores(dataset: Dataset, seed: int = 0) -> np.ndarray:
    """Score every row from a model trained without that row's environment."""
    scores = np.zeros(len(dataset))
    for environment in sorted(set(dataset.environments.tolist())):
        test_mask = dataset.environments == environment
        if not test_mask.any() or test_mask.all():
            continue
        model = Scorer.train(dataset.select(~test_mask), seed=seed)
        scores[test_mask] = model.score(dataset.rows[test_mask])
    return scores


def evaluate_arm(
    arm: str,
    dataset: Dataset,
    scores: np.ndarray,
    target_detection: float,
) -> Operating:
    """Reduce per-call scores to a session-level operating point."""
    by_session = session_scores(dataset, scores)
    labels, sources = session_labels(dataset)

    attack = np.array([s for k, s in by_session.items() if labels[k] == 1])
    benign = np.array(
        [s for k, s in by_session.items() if labels[k] == 0 and sources[k] == FP_SOURCE]
    )
    control = np.array([s for k, s in by_session.items() if sources[k] == "control"])

    threshold = threshold_for_detection(attack, target_detection)
    return Operating(
        arm=arm,
        detection=float((attack >= threshold).mean()) if attack.size else float("nan"),
        false_positives=float((benign >= threshold).mean()) if benign.size else float("nan"),
        control_rate=float((control >= threshold).mean()) if control.size else float("nan"),
        threshold=threshold,
        auc=_auc(attack, benign),
        n_attack=int(attack.size),
        n_benign=int(benign.size),
    )


# --------------------------------------------------------------- permutation floor


def permutation_floor(dataset: Dataset, trials: int = 20, k: int = 5, seed: int = 0) -> float:
    """Mean AUC obtained after shuffling labels *by session*.

    Shuffling per row would break the session structure and understate the floor, so
    whole sessions swap labels together -- exactly the structure real labels have.
    """
    labels, _ = session_labels(dataset)
    keys = list(labels)
    aucs: list[float] = []

    for trial in range(trials):
        rng = np.random.default_rng(seed + trial)
        shuffled = list(labels.values())
        rng.shuffle(shuffled)
        mapping = dict(zip(keys, shuffled))

        permuted = Dataset(
            rows=dataset.rows,
            labels=np.array([mapping[str(s)] for s in dataset.sessions], dtype=int),
            weights=dataset.weights,
            sessions=dataset.sessions,
            sources=dataset.sources,
            environments=dataset.environments,
            names=dataset.names,
        )
        scores = out_of_fold_scores(permuted, k=k, seed=seed + trial)
        by_session = session_scores(permuted, scores)
        positive = np.array([v for key, v in by_session.items() if mapping[key] == 1])
        negative = np.array([v for key, v in by_session.items() if mapping[key] == 0])
        aucs.append(_auc(positive, negative))

    return float(np.nanmean(aucs)) if aucs else float("nan")


# -------------------------------------------------------------------- shade study


def shade_case_study(
    path: str | Path, groups: Iterable[str], seed: int = 0
) -> list[tuple[str, float]]:
    """Score the held-out SHADE trajectories with a model that never saw them."""
    training = build(path, groups=groups, sources=TRAIN_SOURCES)
    held = build(path, groups=groups, sources=("shade",))
    if not len(held) or not len(training):
        return []

    model = Scorer.train(training, seed=seed)
    by_session = session_scores(held, model.score(held.rows))
    return sorted(by_session.items())


# ------------------------------------------------------------------ shape breakdown


def shape_of(calls: list[dict]) -> str:
    """Classify a session the way ``replay.chain_shape`` classifies a chain."""
    classifier = ToolClassifier()
    categories = [classifier.classify(call.get("tool") or "") for call in calls]
    if any(
        categories[i] is ToolCategory.READ and ToolCategory.NETWORK in categories[i + 1 :]
        for i in range(len(categories))
    ):
        return "read-then-network (R3 shape)"
    if ToolCategory.CONFIGURE in categories:
        return "configure present (R5 shape)"
    if ToolCategory.NETWORK in categories:
        return "network, no prior read"
    return "no outbound step"


# --------------------------------------------------------------------------- report


def _row(point: Operating) -> str:
    return (
        f"  {point.arm:26s} detection {point.detection * 100:5.1f}%   "
        f"FP {point.false_positives * 100:5.1f}%   control {point.control_rate * 100:5.1f}%   "
        f"AUC {point.auc:.3f}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chainwatch ml-eval")
    parser.add_argument("--traces", default="traces/agentlab.jsonl")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--permutations", type=int, default=20)
    parser.add_argument("--skip-permutation", action="store_true")
    parser.add_argument("--arms", default="B,C,D,E")
    options = parser.parse_args(argv)

    path = Path(options.traces)
    if not path.is_file():
        sys.stderr.write(f"ml-eval: no trace file at {path}\n")
        return 2

    print("=" * 78)
    print("ChainWatch — supervised arms vs the rule engine")
    print("=" * 78)

    baseline = rule_baseline(path)
    print(f"\nBaseline over {baseline.n_attack} attack / {baseline.n_benign} benign "
          f"({FP_SOURCE}) sessions")
    print(_row(baseline))
    print("  Every false positive here is a *block*: R3 is CRITICAL.\n")

    target = baseline.detection
    print(f"All arms pinned to the baseline's detection rate ({target * 100:.1f}%),")
    print("so the comparable number is what each pays in false positives.\n")

    print("-- session-grouped cross-validation " + "-" * 42)
    results: dict[str, Operating] = {}
    for arm in [a.strip() for a in options.arms.split(",") if a.strip()]:
        dataset = build(path, groups=ARMS[arm], sources=TRAIN_SOURCES)
        scores = out_of_fold_scores(dataset, k=options.folds, seed=options.seed)
        point = evaluate_arm(f"{arm} ({'+'.join(ARMS[arm])})", dataset, scores, target)
        results[arm] = point
        print(_row(point))

    print("\n-- leave-one-environment-out " + "-" * 49)
    for arm in results:
        dataset = build(path, groups=ARMS[arm], sources=TRAIN_SOURCES)
        scores = environment_holdout_scores(dataset, seed=options.seed)
        print(_row(evaluate_arm(f"{arm} (env holdout)", dataset, scores, target)))

    if not options.skip_permutation:
        print("\n-- permutation floor " + "-" * 57)
        dataset = build(path, groups=ARMS["D"], sources=TRAIN_SOURCES)
        floor = permutation_floor(
            dataset, trials=options.permutations, k=options.folds, seed=options.seed
        )
        real = results.get("D")
        print(f"  arm D AUC on shuffled labels: {floor:.3f}   "
              f"(real: {real.auc if real else float('nan'):.3f})")
        print("  A real AUC near this value is indistinguishable from luck at n=605.")

    print("\n-- SHADE held-out trajectories " + "-" * 47)
    print("  Never trained on. The two matched pairs differ only by their attack steps.")
    for arm in ("D",) if "D" in results else tuple(results)[:1]:
        for session, score in shade_case_study(path, ARMS[arm], seed=options.seed):
            print(f"  [{arm}] {session:50s} {score:.3f}")

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
