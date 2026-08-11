"""The authoritative record of what was captured, and under what.

A trace row says what the firewall saw. It cannot say whether the benchmark's own
check called the session a success, which coordinate of the published grid it is,
or whether the run it came from is comparable to the next one. Duplicating all of
that onto every trace row would be a second schema to keep in step -- note 10's
"two writers, not one" one layer up -- so it lives here, keyed by session id.

Two keys do the work:

* the **coordinate** identifies a published grid point, so a resumed run can skip
  what it already has and a duplicate is an error rather than a silent extra row;
* the **fold group** identifies the published *task*, so a benign session and its
  injected variant cannot land in different cross-validation folds. Grouping on
  session id looks equivalent and is not: those two rows share a user task, and a
  model that has seen one has seen most of the other.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ManifestEntry:
    coordinate: tuple[str, ...]
    fold_group: str
    session: str
    source: str
    fingerprint: str
    corpus_revision: str
    git_commit: str
    native: dict
    calls: int
    cost_usd: float
    status: str
    artifacts: dict = field(default_factory=dict)


def _route(row: dict) -> str:
    """Which benchmark a score row came from, decided by its own keys.

    Deliberately structural rather than reading `source`: the source string is an
    assertion the capture wrapper makes, and a row whose keys say AgentDojo while
    its source says otherwise is a bug we want to see, not paper over.
    """
    if "suite" in row and "user_task" in row:
        return "agentdojo"
    if "split" in row and "case_index" in row:
        return "injecagent"
    raise ValueError(f"unrecognised score row keys: {sorted(row)}")


def coordinate(row: dict) -> tuple[str, ...]:
    """The published grid point this row occupies.

    Every component is stringified, including ``None``, so a coordinate that has
    been through JSON compares equal to one that has not.
    """
    route = _route(row)
    if route == "agentdojo":
        return ("agentdojo", str(row["label"]), str(row["suite"]),
                str(row["user_task"]), str(row.get("injection_task")))
    return ("injecagent", str(row["label"]), str(row["split"]), str(row["variant"]),
            str(row["case_index"]), str(row["user_tool"]))


def fold_group(row: dict) -> str:
    """The published *task*, which a benign row and its attack twin share."""
    route = _route(row)
    if route == "agentdojo":
        return f"agentdojo:{row['suite']}:{row['user_task']}"
    return f"injecagent:{row['split']}:{row['case_index']}"


def config_fingerprint(*, model: str, system_prompt_sha256: str, max_turns: int,
                       corpus_revision: str) -> str:
    """Everything that changes the agent's behaviour, in one comparable string.

    Note 30 and note 33 are both the same failure: the subject of the measurement
    was modified without the record saying so. A fingerprint makes a mixed corpus
    loud instead of silent -- resume refuses to treat two configurations as one.
    """
    payload = json.dumps(
        {"model": model, "system_prompt_sha256": system_prompt_sha256,
         "max_turns": max_turns, "corpus_revision": corpus_revision},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def append_entry(path: Path, entry: ManifestEntry) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        row = asdict(entry)
        row["coordinate"] = list(entry.coordinate)
        handle.write(json.dumps(row, separators=(",", ":")) + "\n")


def read_entries(path: Path) -> list[ManifestEntry]:
    path = Path(path)
    if not path.exists():
        return []
    entries: list[ManifestEntry] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            row["coordinate"] = tuple(row["coordinate"])
            entries.append(ManifestEntry(**row))
    return entries


def completed_coordinates(entries, *, fingerprint: str) -> set[tuple[str, ...]]:
    """Coordinates a resumed run may skip: complete, and from this configuration.

    A zero-call session is not complete. It is exactly what a resumed run exists
    to retry, and skipping it would bake a quiet session into the grid.
    """
    return {
        entry.coordinate
        for entry in entries
        if entry.fingerprint == fingerprint and entry.status == "completed" and entry.calls > 0
    }


def duplicate_coordinates(entries) -> dict[tuple[str, ...], int]:
    counts: dict[tuple[str, ...], int] = {}
    for entry in entries:
        counts[entry.coordinate] = counts.get(entry.coordinate, 0) + 1
    return {key: value for key, value in counts.items() if value > 1}
