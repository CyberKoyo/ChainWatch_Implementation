"""JSON Lines audit trail, doubling as the trace corpus.

Deliberately mirrors mcpwall's format and location conventions -- one file per day
under a dotted home directory, one compact JSON object per line, ISO-8601 UTC
timestamps -- so both layers of the stack can be read with the same tooling.

One file, two readers
---------------------
A line carries both the operational fields a human wants (``ts``, ``severity``,
``blocked``) and the corpus fields the trainers need (``session``, ``label``,
``source``, ``call``, ``v``). That makes it a superset consumable *unchanged* by
:func:`chainwatch.ml.dataset.load_sessions` and ``cli._load_sequences``, which both
group on ``session``, sort on ``call``, and skip any line whose ``v`` is not a list.
A second writer in a second format would only be a thing to keep in sync.

``label`` is asserted by the operator, never inferred. ``dataset.build`` treats any
label that is not ``"attack"`` as benign, so an unlabelled session would quietly
become a benign training example -- which is why the proxy refuses to log without one.

``source`` keeps populations separable. Phase 7 found that pooling a weak population
into a false-positive number misreports it; a consumer that wants one population
filters on this field.

Arguments
---------
Redacted on block, exactly as mcpwall does: a blocked call is by definition the one
most likely to contain something that should not be written to disk. Set
``include_arguments=False`` to omit them entirely -- training reads only ``v``, so a
corpus captured for that purpose has no reason to retain the contents of real files.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def state_home() -> Path:
    """Where trace logs and the daemon socket live.

    ``CHAINWATCH_HOME`` is honoured because every capture script already reads it
    (``scripts/capture*.sh``) to decide where to look for the socket. Until this
    existed the variable was a fiction: the scripts relocated and the Python did
    not, so setting it made a script watch a directory the daemon would never
    create. The only symptom was cross-server state silently falling back to
    per-process -- dim 9 and R2 dead, with nothing in the output to say so.
    """
    return Path(os.environ.get("CHAINWATCH_HOME") or (Path.home() / ".chainwatch"))


DEFAULT_LOG_DIR = state_home() / "logs"

REDACTED = "[REDACTED]"


def utc_now() -> str:
    """ISO-8601 UTC, seconds precision -- the format mcpwall writes."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_trace_line(
    *,
    server: str,
    tool: str,
    stage: Any,
    severity: str,
    rules: Any,
    blocked: bool,
    session: str = "",
    label: str = "",
    source: str = "",
    call: int = 0,
    arguments: Any = None,
    include_arguments: bool = False,
    vector: Any = None,
    provenance: Any = None,
    model: str | None = None,
) -> dict[str, Any]:
    """Assemble one JSONL trace line.

    Pure, and free of the verdict object, so the schema is testable on its own --
    which is the point of extracting it: a field that matters and is absent gets
    silently defaulted downstream (§10, and note 32 for ``model``).

    Identity first, then evidence, so a line stays readable at a glance and sorts
    sensibly when a day's log is eyeballed rather than parsed.
    """
    entry: dict[str, Any] = {"ts": utc_now()}
    if session:
        entry["session"] = session
    if label:
        entry["label"] = label
    if source:
        entry["source"] = source
    if call:
        entry["call"] = call

    entry.update(
        {
            "server": server,
            "tool": tool,
            "stage": stage,
            "severity": severity,
            "rules": rules,
            "blocked": blocked,
        }
    )
    if include_arguments:
        entry["args"] = REDACTED if blocked else arguments
    if vector is not None:
        entry["v"] = [round(float(x), 4) for x in vector]

    # Additive and optional, so both trace consumers keep working unchanged --
    # they key on `session`, `call` and `v`, and skip what they do not know.
    # Arrives as a Provenance in-process and as a bare string from the daemon.
    if provenance is not None:
        entry["prov"] = provenance if isinstance(provenance, str) else provenance.name

    # note 32: which model produced this session. Written even when unknown -- an
    # explicit null asserts "the capture named no model", which is a different fact
    # from a reader that never looked, and it cannot be recovered afterwards.
    entry["model"] = model
    return entry


class AuditLog:
    """Append-only daily log. Failures here never propagate to the proxy."""

    def __init__(
        self,
        directory: Path | str = DEFAULT_LOG_DIR,
        enabled: bool = True,
        include_arguments: bool = True,
        model: str | None = None,
    ) -> None:
        self.directory = Path(directory)
        self.enabled = enabled
        self.include_arguments = include_arguments
        # note 32: the producing model is a property of the whole capture, not of a
        # call, so it is held here and stamped on every line rather than threaded
        # through the interceptor on each record().
        self.model = model

    def record(
        self,
        server: str,
        tool: str,
        arguments: Any,
        verdict: Any,
        vector: Any = None,
        session: str = "",
        label: str = "",
        source: str = "",
        call: int = 0,
        blocked: bool | None = None,
    ) -> None:
        if not self.enabled:
            return

        # ``blocked`` is whether the call was actually stopped, which is not the same as
        # whether a CRITICAL rule fired: an observe-only proxy forwards it anyway. The
        # rule-level fact is already in ``severity`` and ``rules``, so this field is free
        # to mean the operational truth -- and must, or a corpus captured in observe-only
        # would report blocks that never happened.
        if blocked is None:
            blocked = verdict.blocked

        entry = build_trace_line(
            server=server,
            tool=tool,
            stage=verdict.stage,
            severity=verdict.severity.name,
            rules=verdict.rules_fired,
            blocked=blocked,
            session=session,
            label=label,
            source=source,
            call=call,
            arguments=arguments,
            include_arguments=self.include_arguments,
            vector=vector,
            provenance=getattr(verdict, "provenance", None),
            model=self.model,
        )

        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            path = self.directory / f"{datetime.now(timezone.utc):%Y-%m-%d}.jsonl"
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, separators=(",", ":"), default=str) + "\n")
        except OSError:
            # Losing an audit line must never break the proxy in front of a user's
            # editor. The stderr stream already carries the alert.
            pass
