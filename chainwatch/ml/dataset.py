"""Turn captured traces into supervised feature rows.

One row per call. Features come in four groups, and which groups are switched on is
what distinguishes the evaluation arms -- so the group boundaries here *are* the
experiment, not an implementation detail:

``current``  the call's own 17 informative dimensions, plus destination provenance
``window``   what the trailing k calls did
``hmm``      the HMM's stage posteriors and Viterbi score
``rules``    which of R1-R5 fired

Arm A is the rule engine alone (no rows needed). B is ``current`` + ``window``.
C is ``hmm`` + ``rules``. D is everything. E is ``current`` alone -- the question of
whether a tree over raw dimensions replaces the design.

Two exclusions, both deliberate
-------------------------------
**TF dims 10-12.** ``call_rate`` reached 1816 calls/sec during batch replay
(CLAUDE.md section 12, decision 7) because replay has no think-time. A model given
those dimensions learns "fast is malicious", which is a property of the harness.

**Session length.** The realism benign population averages 26.3 calls against the
attack corpus's 2.8. That gap describes how AgentLAB was built -- its chains are
terse *plans*, not observed traces -- so length would be the first split a tree
makes and the first thing to fail against live traffic. No feature here is derived
from how long the session is; window counts are capped by ``RuleConfig.window`` and
expressed as fractions of the window's own occupancy.

One inclusion that needs justifying
-----------------------------------
**Destination provenance.** :class:`~chainwatch.engine.features.Provenance` is
deliberately *not* a dimension of the 20-dim vector -- its own docstring says so, and
that must stay true: ``FEATURE_DIM`` is the contract every trained HMM and every
captured trace was written against, and a 21st dimension would let a signal the paper
never specified move the section V-B stage labels.

None of that applies here. This module builds a *supervised* feature matrix that no
HMM ever sees and that no trace format depends on. Provenance is the only measured
signal that separates a real exfiltration from its honest siblings -- call 36 of
``api_key_calendar_agendas_2`` reads ``INTRODUCED`` while the three legitimate sends at
17/25/44 read ``ATTESTED`` -- so excluding it from the model too would be excluding it
for a reason that does not hold on this side of the wall.

Two cautions when reading its importance. It is only extractable on NETWORK calls, so
it is ``UNKNOWN`` on 92.7% of the corpus; if it ranks high, check the model is not using
"provenance is extractable at all" as a NETWORK detector, which ``tc_network`` already
encodes. And ``UNKNOWN`` is ``Provenance``'s fail-closed value *and* ``IntEnum`` 0, so
per CLAUDE.md note 28 every test of it is ``is not None``, never truthiness.

Labels are per session
----------------------
The corpus labels whole chains, and every call inherits its chain's label. Call 1 of
an attack chain is ``list_repos`` -- indistinguishable from benign, and labelled
attack. That noise is irreducible without per-call annotation, so it is dampened
rather than ignored: :func:`build` returns weights that rise along the chain, so the
calls where an attack is actually visible dominate the fit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np

from ..engine.features import DF_SLICE, OC_SLICE, PS_INDEX, TC_SLICE, Provenance
from ..engine.hmm import N_STAGES
from ..engine.model import build_prior_model
from ..engine.rules import RuleConfig
from ..engine.taxonomy import ToolCategory

#: Feature groups, in the order columns are laid out.
GROUPS = ("current", "window", "hmm", "rules")

#: The five rules, fixed order so a column always means the same rule.
RULE_NAMES = ("R1", "R2", "R3", "R4", "R5")

#: Arm definitions from the plan. Arm A needs no rows -- it is the engine itself.
ARMS: dict[str, tuple[str, ...]] = {
    "B": ("current", "window"),
    "C": ("hmm", "rules"),
    "D": ("current", "window", "hmm", "rules"),
    "E": ("current",),
}


@dataclass
class Dataset:
    """Feature matrix plus everything the protocol needs to split it honestly."""

    rows: np.ndarray  # (n_calls, n_features)
    labels: np.ndarray  # 1 = attack, 0 = benign
    weights: np.ndarray  # per-call fit weight
    sessions: np.ndarray  # session id, for grouped CV
    #: Published task id where the manifest knows one, else the session id. A
    #: benign AgentDojo task and its injected twin share this, which is what keeps
    #: them in one fold; a legacy population falls back and folds as it always did.
    groups: np.ndarray
    # agentlab / realism / control / shade / bizops / twin / agentdojo / injecagent.
    # Free-form on purpose: ``build(sources=...)`` is a whitelist the caller supplies,
    # so a new capture route needs a Populations entry in evaluate.py and nothing here.
    sources: np.ndarray
    environments: np.ndarray  # for leave-one-environment-out
    names: list[str]

    def __len__(self) -> int:
        return int(self.rows.shape[0])

    def select(self, mask: np.ndarray) -> "Dataset":
        """Subset every parallel array at once."""
        return Dataset(
            rows=self.rows[mask],
            labels=self.labels[mask],
            weights=self.weights[mask],
            sessions=self.sessions[mask],
            groups=self.groups[mask],
            sources=self.sources[mask],
            environments=self.environments[mask],
            names=self.names,
        )


#: What a trace path may be: one file, or several to read as one corpus.
TracePaths = str | Path | Iterable[str | Path]


def _as_paths(paths: TracePaths) -> list[Path]:
    """One path or many, normalized. A bare string is a path, not an iterable of chars."""
    if isinstance(paths, (str, Path)):
        return [Path(paths)]
    return [Path(p) for p in paths]


def load_sessions(paths: TracePaths) -> list[list[dict[str, Any]]]:
    """Group JSONL trace files into per-session call lists, order preserved.

    Several files are read as *one* corpus rather than concatenated session lists,
    because a single capture session legitimately spans files: the audit log rolls
    daily, and the replay corpus lives beside ``~/.chainwatch/logs/`` where the live
    routes write. Grouping on ``session`` across all of them and then sorting on
    ``call`` is what reunites those pieces -- and is why ``call`` had to become
    globally unique within a session (CLAUDE.md note 13).
    """
    sessions: dict[str, list[dict[str, Any]]] = {}
    for path in _as_paths(paths):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry.get("v"), list):
                continue
            sessions.setdefault(str(entry.get("session", "unknown")), []).append(entry)

    for calls in sessions.values():
        calls.sort(key=lambda e: e.get("call", 0))
    return list(sessions.values())


# --------------------------------------------------------------------------- groups


def _current_names() -> list[str]:
    return (
        [f"tc_{c.name.lower()}" for c in ToolCategory]
        + ["ps"]
        + [f"df_{n}" for n in ("internal_read", "external_write", "chained", "cross_server")]
        + [
            f"oc_{n}"
            for n in (
                "imperative", "xml", "mismatch", "volume", "hash_change", "encoded", "external_url",
            )
        ]
        + [f"prov_{p.name.lower()}" for p in Provenance]
    )


def _provenance(entry: dict[str, Any]) -> np.ndarray:
    """One-hot over :class:`Provenance`, falling back to ``UNKNOWN``.

    ``prov`` is absent from every trace written before Phase 13, and ``UNKNOWN`` is
    already the fail-closed answer for a call whose destination could not be read --
    so an old trace and an unreadable destination land in the same column, which is
    the honest place for both.
    """
    raw = entry.get("prov")
    try:
        value = Provenance[raw] if isinstance(raw, str) else Provenance.UNKNOWN
    except KeyError:
        value = Provenance.UNKNOWN
    one_hot = np.zeros(len(Provenance))
    one_hot[list(Provenance).index(value)] = 1.0
    return one_hot


def _current(vector: np.ndarray, entry: dict[str, Any]) -> np.ndarray:
    """The call's own dimensions, minus the three temporal ones, plus provenance."""
    return np.concatenate(
        [
            vector[TC_SLICE],
            [vector[PS_INDEX]],
            vector[DF_SLICE],
            vector[OC_SLICE],
            _provenance(entry),
        ]
    )


def _window_names() -> list[str]:
    return (
        [f"win_{c.name.lower()}_frac" for c in ToolCategory]
        + ["win_ps_max", "win_ps_mean", "win_chained_any", "win_cross_server_any",
           "win_external_write_any", "win_oc_flags", "win_calls_since_read"]
    )


def _window(vectors: Sequence[np.ndarray], index: int, size: int) -> np.ndarray:
    """Context over the trailing ``size`` calls, ending at ``index`` inclusive.

    Counts are expressed as *fractions of the window*, never as raw counts, so a
    short session and a long one are described on the same scale.

    That is not sufficient on its own. An earlier version also emitted window
    *occupancy* (``len(window) / size``), which reads as innocuous and is a session
    length proxy in disguise: attack chains average 2.8 calls so occupancy never
    exceeds 0.28, while a 26-call benign session sits at 1.0 for most of its length.
    It became the single most important feature in arm D (0.316) and drove the false
    positive rate to an implausible 0.0%. Removed. Nothing here may depend on how
    many calls the session has, only on what they did.
    """
    start = max(0, index + 1 - size)
    window = vectors[start : index + 1]
    occupancy = len(window)

    categories = np.zeros(len(ToolCategory))
    for vector in window:
        categories[int(np.argmax(vector[TC_SLICE]))] += 1
    categories /= occupancy

    ps_values = [float(v[PS_INDEX]) for v in window]
    chained = max(float(v[DF_SLICE][2]) for v in window)
    cross_server = max(float(v[DF_SLICE][3]) for v in window)
    external_write = max(float(v[DF_SLICE][1]) for v in window)
    oc_flags = float(np.max([v[OC_SLICE].sum() for v in window]))

    reads = [
        position
        for position, vector in enumerate(window)
        if int(np.argmax(vector[TC_SLICE])) == ToolCategory.READ
    ]
    # Capped at the window, so this is "recency of a read", not "session length".
    since_read = float(occupancy - 1 - reads[-1]) if reads else float(size)

    return np.concatenate(
        [
            categories,
            [
                max(ps_values),
                float(np.mean(ps_values)),
                chained,
                cross_server,
                external_write,
                oc_flags,
                since_read,
            ],
        ]
    )


def _hmm_names() -> list[str]:
    return [f"hmm_posterior_{s + 1}" for s in range(N_STAGES)] + ["hmm_stage", "hmm_logprob"]


def _rules_names() -> list[str]:
    return [f"rule_{name.lower()}" for name in RULE_NAMES]


def _rules(entry: dict[str, Any]) -> np.ndarray:
    fired = set(entry.get("rules") or [])
    return np.array([1.0 if name in fired else 0.0 for name in RULE_NAMES])


# ---------------------------------------------------------------------------- build


def _manifest_groups() -> dict[str, str]:
    """Session id -> published fold group, from every manifest on disk.

    Read once per :func:`build` rather than per row. A missing manifest is not an
    error: it means this corpus predates the manifest, and the caller falls back
    to the session id.
    """
    import os

    from chainwatch.capture.manifest import read_entries

    home = Path(os.environ.get("CHAINWATCH_HOME", Path.home() / ".chainwatch"))
    mapping: dict[str, str] = {}
    for path in sorted(home.glob("*_manifest.jsonl")):
        for entry in read_entries(path):
            mapping[entry.session] = entry.fold_group
    return mapping


def build(
    path: TracePaths,
    groups: Iterable[str] = GROUPS,
    config: RuleConfig | None = None,
    sources: Iterable[str] | None = None,
) -> Dataset:
    """Assemble a :class:`Dataset` from one trace file or several read as one corpus.

    ``sources`` filters populations. The SHADE trajectories are excluded from
    training everywhere -- they are the only real agent behaviour in the corpus and
    the only place a model can be asked to separate an attack from its own twin, so
    spending them on fitting would leave nothing to test against.
    """
    groups = tuple(groups)
    unknown = set(groups) - set(GROUPS)
    if unknown:
        raise ValueError(f"unknown feature groups: {sorted(unknown)}")

    config = config or RuleConfig()
    model = build_prior_model() if "hmm" in groups else None
    keep = set(sources) if sources is not None else None

    rows: list[np.ndarray] = []
    labels: list[int] = []
    weights: list[float] = []
    session_ids: list[str] = []
    group_ids: list[str] = []
    source_ids: list[str] = []
    environments: list[str] = []
    manifest_groups = _manifest_groups()

    for calls in load_sessions(path):
        if keep is not None and str(calls[0].get("source")) not in keep:
            continue

        vectors = [np.asarray(entry["v"], dtype=np.float64) for entry in calls]
        label = 1 if calls[0].get("label") == "attack" else 0

        posteriors = logprob = None
        if model is not None:
            observations = np.array(vectors)
            posteriors = model.posterior(observations)
            _, raw_logprob = model.viterbi(observations)
            # One score for the whole sequence; per-call scaling keeps it on a
            # comparable footing across sessions of different length.
            logprob = float(raw_logprob) / len(vectors)

        for index, entry in enumerate(calls):
            parts: list[np.ndarray] = []
            if "current" in groups:
                parts.append(_current(vectors[index], entry))
            if "window" in groups:
                parts.append(_window(vectors, index, config.window))
            if "hmm" in groups:
                stage = float(entry.get("stage") or np.argmax(posteriors[index]) + 1)
                parts.append(np.concatenate([posteriors[index], [stage, logprob]]))
            if "rules" in groups:
                parts.append(_rules(entry))

            rows.append(np.concatenate(parts))
            labels.append(label)
            # Rises along the chain: an attack is visible at its payload, not at its
            # first reconnaissance call, yet both carry the same session label.
            weights.append(0.25 + 0.75 * ((index + 1) / len(calls)))
            session_id = str(entry.get("session"))
            session_ids.append(session_id)
            # No manifest entry means a legacy population, where the session *is*
            # the only grouping available. Falling back keeps every existing number
            # in CLAUDE.md section 12 reproducible while the benchmark populations
            # get the stronger grouping they need.
            group_ids.append(manifest_groups.get(session_id, session_id))
            source_ids.append(str(entry.get("source")))
            # Replayed lines carry `environment`; live capture carries `server`
            # instead, and a bizops line has only the latter. Falling back keeps
            # leave-one-environment-out able to hold out a real population rather
            # than lumping every captured session into a single "None" stratum.
            environment = entry.get("environment")
            if environment is None:
                environment = entry.get("server")
            environments.append(str(environment) if environment is not None else "unknown")

    names: list[str] = []
    for group in GROUPS:
        if group not in groups:
            continue
        names += {
            "current": _current_names,
            "window": _window_names,
            "hmm": _hmm_names,
            "rules": _rules_names,
        }[group]()

    if not rows:
        empty_object = np.empty(0, dtype=object)
        return Dataset(
            np.empty((0, len(names))), np.empty(0), np.empty(0),
            empty_object, empty_object, empty_object, empty_object, names,
        )

    return Dataset(
        rows=np.vstack(rows),
        labels=np.array(labels, dtype=int),
        weights=np.array(weights, dtype=np.float64),
        sessions=np.array(session_ids, dtype=object),
        groups=np.array(group_ids, dtype=object),
        sources=np.array(source_ids, dtype=object),
        environments=np.array(environments, dtype=object),
        names=names,
    )
