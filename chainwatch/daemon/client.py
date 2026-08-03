"""Client side of the session daemon.

:class:`DaemonSession` presents the *same* interface as
:class:`~chainwatch.engine.session.SessionAnalyzer` -- ``register_tools``,
``submit``, ``complete`` -- so the interceptor is oblivious to which one it holds.

If the daemon is unreachable, :func:`build_session_backend` returns a plain local
analyzer and warns once on stderr. Detection keeps working; only the cross-server
parts (dim 9 and rule R2) go quiet. Degrading beats refusing to start and leaving
the user with no MCP server at all.
"""

from __future__ import annotations

import itertools
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any, Iterable

import numpy as np

from ..engine.alerts import Alert, Severity, Verdict
from ..engine.features import ObservedCall
from ..engine.rules import RuleConfig
from ..engine.session import SessionAnalyzer
from .server import DEFAULT_SOCKET_PATH


def verdict_from_dict(payload: dict[str, Any]) -> Verdict:
    """Rebuild a Verdict from its wire form."""
    vector = payload.get("vector")
    verdict = Verdict(
        call_index=payload["call_index"],
        stage=payload["stage"],
        # numpy, so a daemon-backed verdict is indistinguishable from a local one to
        # anything that slices it -- which the audit log does.
        vector=None if vector is None else np.asarray(vector, dtype=np.float64),
        # Kept as the bare name the daemon sent. Nothing downstream compares it to
        # a Provenance member -- the audit log formats it, and the rules run
        # daemon-side where the enum still exists.
        provenance=payload.get("provenance"),
    )
    verdict.alerts = [
        Alert(
            rule=a["rule"],
            severity=Severity[a["severity"]],
            call_index=a["call_index"],
            stage=a["stage"],
            message=a["message"],
        )
        for a in payload.get("alerts", [])
    ]
    return verdict


class DaemonSession:
    """Duck-type replacement for SessionAnalyzer, backed by the shared daemon."""

    def __init__(self, connection: socket.socket, session: str = "") -> None:
        self._socket = connection
        self._file = connection.makefile("rwb")
        # Unique per process, so two proxies cannot collide on a call key.
        self._keys = (f"{os.getpid()}-{n}" for n in itertools.count())
        # The daemon keys one analyzer per session. Several proxied servers sharing a
        # CHAINWATCH_SESSION therefore share a window -- which is the point, it is what
        # makes dim 9 and R2 observable -- while two capture recipes do not. Sending
        # nothing here pools every session a daemon ever sees into one timeline; a
        # two-recipe run measured that as a single 26-call session.
        self._session = session

    # ------------------------------------------------------------- SessionAnalyzer API

    def register_tools(self, server: str, tools: Iterable[dict[str, Any]]) -> set[str]:
        reply = self._call({"op": "register_tools", "server": server, "tools": list(tools)})
        return set(reply.get("changed", []))

    def submit(self, call: ObservedCall, *, commit_blocked: bool = False) -> Verdict:
        key = next(self._keys)
        reply = self._call(
            {
                "op": "submit",
                "key": key,
                "server": call.server,
                "tool": call.tool,
                "arguments": call.arguments,
                "timestamp": call.timestamp,
                "commit_blocked": commit_blocked,
            }
        )
        verdict = verdict_from_dict(reply["verdict"])
        if not verdict.blocked or commit_blocked:
            # Stash the key on the call so complete() can find it again.
            setattr(call, "_daemon_key", key)
        return verdict

    def complete(self, call: ObservedCall, response_text: str) -> Verdict:
        key = getattr(call, "_daemon_key", None)
        if key is None:
            raise RuntimeError("complete() called for a call that was never submitted")
        reply = self._call({"op": "complete", "key": key, "response": response_text})
        return verdict_from_dict(reply["verdict"])

    @property
    def stages(self) -> list[int]:
        return self._call({"op": "stages"}).get("stages", [])

    # ------------------------------------------------------------------ transport

    def _call(self, request: dict[str, Any]) -> dict[str, Any]:
        # Stamped here rather than at each call site, so a new op cannot be added that
        # silently reports into the wrong session's window.
        if self._session:
            request = {**request, "session": self._session}
        self._file.write((json.dumps(request, separators=(",", ":")) + "\n").encode())
        self._file.flush()
        line = self._file.readline()
        if not line:
            raise ConnectionError("chainwatch daemon closed the connection")
        reply = json.loads(line)
        if not reply.get("ok"):
            raise RuntimeError(f"daemon error: {reply.get('error')}")
        return reply

    def close(self) -> None:
        try:
            self._file.close()
            self._socket.close()
        except OSError:
            pass


def connect(
    socket_path: Path | str = DEFAULT_SOCKET_PATH,
    timeout: float = 2.0,
    session: str = "",
) -> DaemonSession:
    """Connect to a running daemon, or raise ``OSError``."""
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    connection.connect(str(socket_path))
    connection.settimeout(None)
    return DaemonSession(connection, session=session)


def build_session_backend(
    config: RuleConfig | None = None,
    use_daemon: bool = True,
    socket_path: Path | str = DEFAULT_SOCKET_PATH,
    session: str = "",
) -> Any:
    """Return a daemon-backed session if one is available, else a local analyzer.

    ``session`` is the caller's ``CHAINWATCH_SESSION``. It is passed in rather than
    read from the environment here so the proxy has one source of truth for the id it
    also writes into every trace line -- otherwise the analyzer could be grouping
    calls one way while the corpus records them another.
    """
    config = config or RuleConfig()

    if use_daemon:
        try:
            return connect(socket_path, session=session)
        except OSError:
            sys.stderr.write(
                f"[chainwatch] no daemon at {socket_path}; using local session state. "
                "Cross-server detection (rule R2, feature dim 9) is disabled. "
                "Start one with: python -m chainwatch daemon\n"
            )
            sys.stderr.flush()

    return SessionAnalyzer(config=config)
