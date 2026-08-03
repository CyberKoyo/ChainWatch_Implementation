"""Alert severities and verdicts -- ChainWatch section IV-D.

Section IV-D fixes the severity of each rule: "R3 and R5 trigger CRITICAL alerts
and block the pending call. R1, R2, and R4 trigger WARNING alerts for human
review. Suspicious stage assignments generate INFO alerts."

Blocking is therefore a property of the rule, not a separate policy knob: a rule
that fires CRITICAL blocks, and nothing else does.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered so ``max()`` over a set of alerts yields the session verdict."""

    NONE = 0
    INFO = 1
    WARNING = 2
    CRITICAL = 3


@dataclass(frozen=True)
class Alert:
    """One rule firing on one call."""

    rule: str
    severity: Severity
    call_index: int
    stage: int
    message: str

    @property
    def blocks(self) -> bool:
        """Only CRITICAL blocks -- section IV-D ties the two together."""
        return self.severity is Severity.CRITICAL

    def __str__(self) -> str:
        return f"[{self.severity.name}] {self.rule} @ call {self.call_index + 1} (stage {self.stage}): {self.message}"


@dataclass
class Verdict:
    """The outcome of evaluating one call against the window."""

    call_index: int
    stage: int
    alerts: list[Alert] = field(default_factory=list)
    #: The observation this verdict judged. Carried so a *blocked* call can still be
    #: recorded downstream. Blocked calls are never committed to session history --
    #: correctly, since they did not run -- but that left every CRITICAL detection
    #: absent from captured traces, because CRITICAL is exactly what blocks. R3 and
    #: R5 appeared zero times across 6396 captured calls before this was fixed.
    #: Typed loosely to keep this module free of numpy.
    vector: Any = None
    #: Where this call's destination came from, as a ``features.Provenance``.
    #: Recorded in the trace so a captured corpus can be re-scored offline without
    #: replaying it. Typed loosely for the same reason as ``vector`` -- and because
    #: the daemon sends it across the socket as a bare string.
    provenance: Any = None

    @property
    def severity(self) -> Severity:
        return max((a.severity for a in self.alerts), default=Severity.NONE)

    @property
    def blocked(self) -> bool:
        return any(a.blocks for a in self.alerts)

    @property
    def rules_fired(self) -> list[str]:
        # Deduplicated but order-preserving: a rule can only fire once per call,
        # but keeping this explicit makes the property safe to call anywhere.
        seen: dict[str, None] = {}
        for alert in self.alerts:
            seen.setdefault(alert.rule, None)
        return list(seen)
