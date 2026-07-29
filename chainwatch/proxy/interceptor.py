"""Wires MCP traffic into the Sequential Pattern Analyzer.

Owns the request/response correlation that the two-phase feature extraction needs:
a ``tools/call`` is analysed when it goes out, and the matching response -- located
by JSON-RPC ``id`` -- completes it on the way back.

Transport-agnostic on purpose. It is handed lines and returns decisions, so it can
be driven by the stdio proxy, by the replay harness, or by a test, without change.

Concurrency
-----------
The proxy pumps the two directions on separate threads, which creates a problem
the sequential model cannot tolerate: if request N+1 is inspected before the
response to call N has been folded in, the ``chained`` data-flow flag is still 0
and rule R3 cannot fire. An exfiltration would sail straight through purely
because of thread scheduling.

Two guards, therefore. A lock, because ``SessionAnalyzer`` is not thread-safe and
both directions mutate it. And a bounded wait for in-flight calls to settle before
a new ``tools/call`` is analysed -- MCP hosts await each result before sending the
next, so in practice this returns immediately; the timeout exists only so a server
that never answers cannot wedge the proxy.
"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..audit import AuditLog
from ..engine.alerts import Severity, Verdict
from ..engine.features import ObservedCall
from ..engine.session import SessionAnalyzer
from . import jsonrpc

#: ANSI colours, matching mcpwall's colour-coded stderr so the two layers read as
#: one system. Suppressed automatically when stderr is not a terminal.
_COLOURS = {
    Severity.INFO: "\033[36m",
    Severity.WARNING: "\033[33m",
    Severity.CRITICAL: "\033[31m",
}
_RESET = "\033[0m"


@dataclass
class Decision:
    """What the proxy should do with a message it just inspected."""

    forward: bool
    #: Set when the call is blocked: the JSON-RPC error to return upstream.
    reply: dict[str, Any] | None = None
    verdict: Verdict | None = None


@dataclass
class Interceptor:
    """Stateful inspector for one proxied MCP server."""

    server: str = "default"
    analyzer: SessionAnalyzer = field(default_factory=SessionAnalyzer)
    #: Where alerts are written. Injectable so tests can capture them.
    emit: Callable[[str], None] | None = None
    #: Set false to observe and log without ever blocking -- useful for a first
    #: deployment where false-positive tolerance is unknown.
    enforcing: bool = True

    #: Trace capture. ``None`` disables it entirely; the stderr alerts are unaffected.
    audit: AuditLog | None = None
    #: Groups a session's calls in the log. Shared across servers when the daemon is
    #: in use, because they share one window and the trace must match what the rules
    #: actually reasoned over.
    session: str = ""
    #: Operator's assertion about this traffic, not an inference. See ``audit``.
    label: str = ""
    #: Which population these lines belong to, so they stay separable downstream.
    source: str = ""

    #: How long to wait for outstanding responses before analysing a new call.
    #: Generous: it is a deadlock guard, not a latency budget.
    quiesce_timeout: float = 30.0

    #: Pending calls awaiting a response, keyed by JSON-RPC id.
    _in_flight: dict[Any, ObservedCall] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _idle: threading.Event = field(default_factory=threading.Event, repr=False)

    def __post_init__(self) -> None:
        if self.emit is None:
            self.emit = self._default_emit
        self._idle.set()

    # ------------------------------------------------------------------ inbound

    def on_request(self, message: dict[str, Any]) -> Decision:
        """Inspect a message heading toward the MCP server."""
        if not jsonrpc.is_tool_call(message):
            return Decision(forward=True)

        # Let outstanding responses land first, so this call is judged against a
        # complete picture of what the session has already learned.
        if not self._idle.wait(timeout=self.quiesce_timeout):
            self.emit(
                "[chainwatch] timed out waiting for in-flight responses; "
                "analysing with incomplete session state"
            )

        tool, arguments = jsonrpc.tool_call_details(message)
        call = ObservedCall(
            tool=tool,
            arguments=arguments,
            server=self.server,
            timestamp=time.time(),
        )
        with self._lock:
            # Observe-only forwards even a CRITICAL call, so the analyzer has to keep
            # it: its response must land on its own record, not the previous call's.
            verdict = self.analyzer.submit(call, commit_blocked=not self.enforcing)
            self._report(verdict)

            if verdict.blocked and self.enforcing:
                # No response will ever arrive, so this is the only chance to record it
                # -- and omitting it would erase R3 and R5 from the corpus, since
                # CRITICAL is exactly what blocks.
                self._record(call, verdict)
                reason = "; ".join(a.message for a in verdict.alerts if a.blocks)
                return Decision(
                    forward=False,
                    reply=jsonrpc.blocked_response(message.get("id"), reason, verdict.rules_fired),
                    verdict=verdict,
                )

            # Only remember calls that were actually forwarded; a response can
            # never arrive for one that was not.
            self._in_flight[message.get("id")] = call
            self._idle.clear()
            return Decision(forward=True, verdict=verdict)

    # ----------------------------------------------------------------- outbound

    def on_response(self, message: dict[str, Any]) -> Decision:
        """Inspect a message heading back toward the host."""
        message_id = message.get("id")

        with self._lock:
            # A tools/list result is where rug-pulls become visible.
            if "result" in message:
                tools = jsonrpc.extract_tools(message["result"])
                if tools:
                    changed = self.analyzer.register_tools(self.server, tools)
                    if changed:
                        self.emit(
                            f"{_colour(Severity.WARNING)}[WARNING] tool definition changed "
                            f"mid-session: {', '.join(sorted(changed))}{_reset()}"
                        )

            call = self._in_flight.pop(message_id, None)
            if not self._in_flight:
                self._idle.set()
            if call is None:
                return Decision(forward=True)

            verdict = self.analyzer.complete(call, jsonrpc.response_text(message))
            self._report(verdict, completed=True)
            # Recorded here, not pre-flight: this is the only verdict whose vector has
            # the Output Characteristics group filled in.
            self._record(call, verdict)
            return Decision(forward=True, verdict=verdict)

    def wait_for_quiescence(self, timeout: float) -> bool:
        """Block until every forwarded call has been answered, or ``timeout``."""
        return self._idle.wait(timeout=timeout)

    # ------------------------------------------------------------------ helpers

    def _record(self, call: ObservedCall, verdict: Verdict) -> None:
        """Append one trace line. Called under ``_lock``, exactly once per call."""
        if self.audit is None:
            return
        self.audit.record(
            server=call.server,
            tool=call.tool,
            arguments=call.arguments,
            verdict=verdict,
            vector=verdict.vector,
            session=self.session,
            label=self.label,
            source=self.source,
            # The analyzer's index, not a counter of our own. One Interceptor exists
            # per proxied server, so a local counter restarts at 1 for each of them --
            # and with the daemon they all share a session, so ``load_sessions`` would
            # be sorting several calls that all claim to be call 1. ``call_index``
            # comes from the shared analyzer and is unique across servers.
            #
            # A call blocked while enforcing never commits, so it keeps the index the
            # next call will take. That tie is the one case, and it resolves correctly:
            # the sort is stable and the blocked line is written first, which is also
            # the order it happened in.
            call=verdict.call_index + 1,
            # Whether the call was really stopped, not merely judged CRITICAL. In
            # observe-only it was forwarded, and the trace has to say so.
            blocked=verdict.blocked and self.enforcing,
        )

    def _report(self, verdict: Verdict, completed: bool = False) -> None:
        """Print alerts once each. Pre-flight and post-response both evaluate the
        same window, so without this every WARNING would appear twice."""
        if verdict.severity is Severity.NONE:
            return
        # Blocking alerts are reported pre-flight; everything else once completed.
        show_blocking = not completed
        for alert in verdict.alerts:
            if alert.blocks != show_blocking:
                continue
            self.emit(f"{_colour(alert.severity)}{alert}{_reset()}")

    @staticmethod
    def _default_emit(line: str) -> None:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()


def _colour(severity: Severity) -> str:
    return _COLOURS.get(severity, "") if sys.stderr.isatty() else ""


def _reset() -> str:
    return _RESET if sys.stderr.isatty() else ""
