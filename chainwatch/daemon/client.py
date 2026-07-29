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

    def __init__(self, connection: socket.socket) -> None:
        self._socket = connection
        self._file = connection.makefile("rwb")
        # Unique per process, so two proxies cannot collide on a call key.
        self._keys = (f"{os.getpid()}-{n}" for n in itertools.count())

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


def connect(socket_path: Path | str = DEFAULT_SOCKET_PATH, timeout: float = 2.0) -> DaemonSession:
    """Connect to a running daemon, or raise ``OSError``."""
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(timeout)
    connection.connect(str(socket_path))
    connection.settimeout(None)
    return DaemonSession(connection)


def build_session_backend(
    config: RuleConfig | None = None,
    use_daemon: bool = True,
    socket_path: Path | str = DEFAULT_SOCKET_PATH,
) -> Any:
    """Return a daemon-backed session if one is available, else a local analyzer."""
    config = config or RuleConfig()

    if use_daemon:
        try:
            return connect(socket_path)
        except OSError:
            sys.stderr.write(
                f"[chainwatch] no daemon at {socket_path}; using local session state. "
                "Cross-server detection (rule R2, feature dim 9) is disabled. "
                "Start one with: python -m chainwatch daemon\n"
            )
            sys.stderr.flush()

    return SessionAnalyzer(config=config)
