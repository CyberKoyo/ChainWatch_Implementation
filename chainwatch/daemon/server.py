"""Cross-server session daemon.

One proxy process runs per MCP server, so each on its own sees only its own
traffic. That makes two parts of the specification permanently dead:

* feature dim 9, ``cross-server`` -- never 1;
* rule R2, "two or more servers accessed with sensitive data flow flags active".

The daemon fixes both by holding a **single** :class:`SessionAnalyzer` -- one HMM,
one k=10 window -- that every proxy reports into. Calls from different servers
interleave in one timeline, exactly as the paper's session model assumes.

Protocol: newline-delimited JSON over a Unix socket. Deliberately trivial; the
socket is user-owned in the user's home directory and carries no authentication,
which is appropriate for a single-user local monitoring layer and nothing more.
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import threading
from pathlib import Path
from typing import Any

from ..engine.features import ObservedCall
from ..engine.rules import RuleConfig
from ..engine.session import SessionAnalyzer

DEFAULT_SOCKET_PATH = Path.home() / ".chainwatch" / "session.sock"

#: Guards the shared analyzer. Proxies are independent processes but the daemon
#: serves them on threads, and the analyzer is emphatically not thread-safe.
_LOCK = threading.Lock()


def verdict_to_dict(verdict: Any) -> dict[str, Any]:
    """Wire form of a Verdict.

    The feature vector crosses the socket because the proxy, not the daemon, owns the
    audit log -- and a daemon-backed proxy is the normal multi-server deployment, so
    dropping it here would leave every captured trace line carrying ``v: null``.
    """
    payload: dict[str, Any] = {
        "call_index": verdict.call_index,
        "stage": verdict.stage,
        "severity": verdict.severity.name,
        "blocked": verdict.blocked,
        "rules": verdict.rules_fired,
        "alerts": [
            {
                "rule": a.rule,
                "severity": a.severity.name,
                "call_index": a.call_index,
                "stage": a.stage,
                "message": a.message,
                "blocks": a.blocks,
            }
            for a in verdict.alerts
        ],
    }
    if verdict.vector is not None:
        payload["vector"] = [float(x) for x in verdict.vector]
    return payload


class SessionState:
    """The shared analyzer plus the calls currently awaiting responses."""

    def __init__(self, config: RuleConfig | None = None) -> None:
        self.analyzer = SessionAnalyzer(config=config or RuleConfig())
        self.pending: dict[str, ObservedCall] = {}

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        operation = request.get("op")

        if operation == "ping":
            return {"ok": True, "calls": len(self.analyzer.history)}

        if operation == "register_tools":
            changed = self.analyzer.register_tools(request["server"], request["tools"])
            return {"ok": True, "changed": sorted(changed)}

        if operation == "submit":
            call = ObservedCall(
                tool=request["tool"],
                arguments=request.get("arguments", {}),
                server=request.get("server", "default"),
                timestamp=request["timestamp"],
            )
            commit_blocked = bool(request.get("commit_blocked", False))
            verdict = self.analyzer.submit(call, commit_blocked=commit_blocked)
            # An observe-only proxy forwards a blocked call, so its response is still
            # coming and the call has to stay claimable by complete().
            if not verdict.blocked or commit_blocked:
                self.pending[request["key"]] = call
            return {"ok": True, "verdict": verdict_to_dict(verdict)}

        if operation == "complete":
            call = self.pending.pop(request["key"], None)
            if call is None:
                return {"ok": False, "error": "unknown call key"}
            verdict = self.analyzer.complete(call, request.get("response", ""))
            return {"ok": True, "verdict": verdict_to_dict(verdict)}

        if operation == "stages":
            return {"ok": True, "stages": self.analyzer.stages}

        if operation == "reset":
            self.analyzer = SessionAnalyzer(config=self.analyzer.config)
            self.pending.clear()
            return {"ok": True}

        return {"ok": False, "error": f"unknown op {operation!r}"}


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        for raw in self.rfile:
            try:
                request = json.loads(raw)
            except (ValueError, TypeError):
                self._reply({"ok": False, "error": "malformed request"})
                continue
            try:
                with _LOCK:
                    response = self.server.state.handle(request)  # type: ignore[attr-defined]
            except Exception as error:  # never let one proxy kill the daemon
                response = {"ok": False, "error": repr(error)}
            self._reply(response)

    def _reply(self, payload: dict[str, Any]) -> None:
        self.wfile.write((json.dumps(payload, separators=(",", ":")) + "\n").encode())
        self.wfile.flush()


class _Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, path: str, state: SessionState) -> None:
        self.state = state
        super().__init__(path, _Handler)


def serve(socket_path: Path | str = DEFAULT_SOCKET_PATH, config: RuleConfig | None = None) -> None:
    """Run the daemon until interrupted."""
    path = Path(socket_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    # A socket left behind by a crashed daemon would block bind(); only remove it
    # once we have confirmed nobody is listening on the other end.
    if path.exists():
        if _is_live(path):
            raise SystemExit(f"chainwatch daemon already running at {path}")
        path.unlink()

    server = _Server(str(path), SessionState(config))
    os.chmod(path, 0o600)  # single-user monitoring layer; keep it that way
    print(f"[chainwatch] daemon listening on {path}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        path.unlink(missing_ok=True)


def _is_live(path: Path) -> bool:
    """True if something is actually accepting connections on ``path``."""
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        probe.connect(str(path))
        return True
    except OSError:
        return False
    finally:
        probe.close()
