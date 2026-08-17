"""The five session-level detection rules -- ChainWatch section IV-D.

Quoting the paper directly, since these definitions are the specification:

    R1 detects reconnaissance directly followed by sensitive data access.
    R2 identifies two or more servers accessed with sensitive data flow flags active.
    R3 identifies the read-then-transmit exfiltration signature: a high-stage READ
       followed within m steps by a NETWORK call carrying that data.
    R4 detects rapid kill chain acceleration -- a stage jump of two or more positions.
    R5 detects late-stage configuration writes at Stage 4 or above.

Each rule is a plain function over the current window, returning an ``Alert`` or
``None``. They are deliberately independent and side-effect free, so a deployment
can disable one without disturbing the others.

On R3 and the "high-stage READ" ambiguity
-----------------------------------------
Read literally, R3 requires the READ itself to be at a high stage. That holds in
scenario S2 (``read_file`` at Stage 4) and S5 (``read_env`` at Stage 4), but *not*
in S1, whose only READs are ``get_balance`` at Stage 1 and ``list_payees`` at
Stage 2 -- and yet section V-B states plainly that "R3 would fire at call 4".

The reading that satisfies all three scenarios is that "high-stage" qualifies the
NETWORK call. That is the default here (``r3_network_stage_min``). The strict
literal reading is one config change away via ``r3_read_stage_min``.
See CLAUDE.md, ambiguity A1.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np

from .alerts import Alert, Severity
from .features import (
    DF_CHAINED,
    DF_CROSS_SERVER,
    DF_EXTERNAL_WRITE,
    PS_INDEX,
    Provenance,
)
from .taxonomy import ToolCategory


@dataclass(frozen=True)
class CallRecord:
    """One analysed call: the observation, its inferred stage, and its origin."""

    index: int
    tool: str
    server: str
    vector: np.ndarray
    stage: int  # 1-6, matching the paper's numbering
    #: Where this call's destination came from. Deliberately *not* a feature
    #: dimension -- see features.Provenance. Defaults to UNKNOWN so every existing
    #: construction site stays valid and fails closed.
    provenance: Provenance = Provenance.UNKNOWN

    @property
    def category(self) -> ToolCategory:
        return ToolCategory(int(np.argmax(self.vector[0:5])))

    @property
    def sensitivity(self) -> float:
        return float(self.vector[PS_INDEX])

    @property
    def chained(self) -> bool:
        return bool(self.vector[DF_CHAINED])

    @property
    def cross_server(self) -> bool:
        return bool(self.vector[DF_CROSS_SERVER])

    @property
    def external_write(self) -> bool:
        return bool(self.vector[DF_EXTERNAL_WRITE])


@dataclass(frozen=True)
class RuleConfig:
    """Thresholds for the Sequential Pattern Analyzer.

    Section IV-D: "Both parameters are configurable deployment choices" (k and m)
    and "All thresholds are configurable based on each deployment's false positive
    tolerance."
    """

    #: Sliding window length. Section IV-D: k=10, "chosen to exceed the 4-7 call
    #: spans of documented attacks".
    window: int = 10
    #: Step threshold. Section IV-D: m=5, so "a rule would trigger within half a
    #: window of the first suspicious signal".
    step_threshold: int = 5

    #: What counts as "sensitive data access" for R1. 0.30 sits just below the
    #: score a bare credential-path read produces, so reading ~/.ssh qualifies.
    sensitivity_threshold: float = 0.30

    #: R2: "two or more servers".
    min_servers: int = 2

    #: R3: see the module docstring. The NETWORK call carries the "high-stage"
    #: requirement; the READ defaults to any stage.
    r3_network_stage_min: int = 5
    r3_read_stage_min: int = 1

    #: What R3 does when the destination is ATTESTED -- named by the environment
    #: in a clean READ response before the session ever referenced it.
    #:
    #: ``"downgrade"`` is the operational default. Landing 2 made a copied
    #: destination observable whether it came from a clean bill or an injected
    #: one; provenance is the existing signal that separates those flows. On the
    #: archived AgentDojo sessions, downgrade restores benign CRITICAL sessions
    #: from 3/9 to 1/9 while leaving attack CRITICAL sessions at 16/33.
    #:
    #: Downgrade keeps the alert but stops the block, which is the point:
    #: every false positive measured in Phase 7 was a block, and a WARNING on a
    #: legitimate payment costs a human a glance rather than costing the business
    #: the payment. ``"ignore"`` preserves section IV-D's paper-literal behavior,
    #: which knows nothing about recipients; ``"suppress"`` drops the alert.
    r3_attested_action: str = "downgrade"

    #: R4: "a stage jump of two or more positions".
    r4_min_jump: int = 2

    #: R5: "late-stage configuration writes at Stage 4 or above".
    r5_stage_min: int = 4

    #: INFO: "suspicious stage assignments generate INFO alerts". Stage 3 is the
    #: first stage that implies compromise rather than ordinary activity.
    info_stage_min: int = 3


def rule_r1(window: Sequence[CallRecord], config: RuleConfig) -> Alert | None:
    """Reconnaissance directly followed by sensitive data access.

    "Directly" is taken at face value: the immediately preceding call, not merely
    a Stage 1 call somewhere in the window.
    """
    if len(window) < 2:
        return None
    current, previous = window[-1], window[-2]
    if previous.stage != 1:
        return None
    if current.sensitivity < config.sensitivity_threshold:
        return None
    return Alert(
        rule="R1",
        severity=Severity.WARNING,
        call_index=current.index,
        stage=current.stage,
        message=(
            f"reconnaissance ({previous.tool}) directly followed by sensitive "
            f"data access ({current.tool}, PS={current.sensitivity:.2f})"
        ),
    )


def rule_r2(window: Sequence[CallRecord], config: RuleConfig) -> Alert | None:
    """Two or more servers accessed with sensitive data flow flags active.

    Requires the shared session daemon to be meaningful -- a single proxy process
    only ever sees one server, so ``cross_server`` stays 0 and this never fires.
    Section VI singles out R2 as the likely false-positive source for "legitimate
    enterprise workflows spanning multiple services".
    """
    if not window:
        return None
    servers = {record.server for record in window}
    if len(servers) < config.min_servers:
        return None

    flagged = [r for r in window if r.chained or r.cross_server]
    if not flagged:
        return None

    current = window[-1]
    return Alert(
        rule="R2",
        severity=Severity.WARNING,
        call_index=current.index,
        stage=current.stage,
        message=(
            f"{len(servers)} servers accessed ({', '.join(sorted(servers))}) with "
            f"sensitive data flow on {len(flagged)} call(s)"
        ),
    )


def rule_r3(window: Sequence[CallRecord], config: RuleConfig) -> Alert | None:
    """Read-then-transmit exfiltration signature. CRITICAL, blocks the call."""
    if not window:
        return None
    current = window[-1]

    if current.category is not ToolCategory.NETWORK:
        return None
    if current.stage < config.r3_network_stage_min:
        return None
    if not current.chained:
        return None

    # Look back at most m steps for the READ whose data is being carried out.
    lookback = [r for r in window[-(config.step_threshold + 1) : -1]]
    source = next(
        (
            r
            for r in reversed(lookback)
            if r.category is ToolCategory.READ and r.stage >= config.r3_read_stage_min
        ),
        None,
    )
    if source is None:
        return None

    # Recipient provenance can only ever *lower* the severity, never raise one, so
    # enabling it can cost detection but can never invent an alert. An ATTESTED
    # destination is one the environment named in a clean READ before the session
    # touched it -- a colleague out of the address book, not a payee the agent
    # registered itself.
    severity = Severity.CRITICAL
    if current.provenance is Provenance.ATTESTED:
        if config.r3_attested_action == "suppress":
            return None
        if config.r3_attested_action == "downgrade":
            severity = Severity.WARNING

    return Alert(
        rule="R3",
        severity=severity,
        call_index=current.index,
        stage=current.stage,
        message=(
            f"exfiltration signature: {source.tool} (stage {source.stage}) read data "
            f"now leaving via {current.tool} (stage {current.stage}); "
            f"destination {current.provenance.name}"
        ),
    )


def rule_r4(window: Sequence[CallRecord], config: RuleConfig) -> Alert | None:
    """Rapid kill chain acceleration -- a stage jump of two or more positions."""
    if len(window) < 2:
        return None
    current, previous = window[-1], window[-2]
    jump = current.stage - previous.stage
    if jump < config.r4_min_jump:
        return None
    return Alert(
        rule="R4",
        severity=Severity.WARNING,
        call_index=current.index,
        stage=current.stage,
        message=f"kill chain accelerated {jump} stages ({previous.stage} -> {current.stage}) on {current.tool}",
    )


def rule_r5(window: Sequence[CallRecord], config: RuleConfig) -> Alert | None:
    """Late-stage configuration write. CRITICAL, blocks the call.

    This is the cross-agent escalation guard: an agent rewriting MCP wiring once a
    session already looks compromised (scenario S4, Rehberger ref [21]).
    """
    if not window:
        return None
    current = window[-1]
    if current.category is not ToolCategory.CONFIGURE:
        return None
    if current.stage < config.r5_stage_min:
        return None
    return Alert(
        rule="R5",
        severity=Severity.CRITICAL,
        call_index=current.index,
        stage=current.stage,
        message=f"configuration write ({current.tool}) at stage {current.stage}",
    )


def rule_info(window: Sequence[CallRecord], config: RuleConfig) -> Alert | None:
    """Suspicious stage assignment -- informational only, never blocks."""
    if not window:
        return None
    current = window[-1]
    if current.stage < config.info_stage_min:
        return None
    return Alert(
        rule="STAGE",
        severity=Severity.INFO,
        call_index=current.index,
        stage=current.stage,
        message=f"{current.tool} classified at stage {current.stage}",
    )


#: Evaluation order. R3 and R5 come first so a blocking verdict is reached even if
#: a later rule were to raise.
ALL_RULES = (rule_r3, rule_r5, rule_r1, rule_r2, rule_r4, rule_info)


def evaluate(window: Sequence[CallRecord], config: RuleConfig | None = None) -> list[Alert]:
    """Run every rule against the window and return the alerts that fired."""
    config = config or RuleConfig()
    alerts = [rule(window, config) for rule in ALL_RULES]
    return [alert for alert in alerts if alert is not None]
