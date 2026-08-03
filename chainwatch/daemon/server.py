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
from collections import OrderedDict
from pathlib import Path
from typing import Any

from ..audit import state_home
from ..engine.features import ObservedCall
from ..engine.rules import RuleConfig
from ..engine.session import SessionAnalyzer

#: Shares ``state_home()`` with the trace writer on purpose. The capture scripts
#: relocate both together via CHAINWATCH_HOME and then wait for this socket to
#: appear; resolving the two independently is how that wait silently never ends.
DEFAULT_SOCKET_PATH = state_home() / "session.sock"

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
    # Sent as a bare name for the same reason as the vector: the proxy owns the
    # audit log, so anything the trace needs has to survive the socket. Route C is
    # daemon-backed, and this is the column it exists to produce.
    if verdict.provenance is not None:
        payload["provenance"] = verdict.provenance.name
    return payload


#: How many sessions one daemon keeps analyzers for. A capture run is a few dozen
#: recipes and a desktop is one operator, so this only bounds a daemon left running
#: for weeks; the oldest is evicted, which at worst restarts that session's window.
MAX_TRACKED_SESSIONS = 64

#: Used when a client sends no session id. Every proxy sends one, but the field is
#: optional on the wire so an older client still works -- and pooling those into one
#: named bucket is honest about what is happening, where inventing a fresh id per
#: request would silently disable the window entirely.
DEFAULT_SESSION = "default"


class SessionState:
    """One analyzer **per session**, plus the calls currently awaiting responses.

    Pooling is by session, not by daemon. Several proxied servers reporting under one
    ``CHAINWATCH_SESSION`` share a window on purpose -- that is what makes feature dim
    9 and rule R2 observable at all. Two *different* sessions must not, and until the
    id crossed the wire they did: a two-recipe capture run came back as one 26-call
    session, its call index running straight through the boundary. Sharing a window
    across recipes lets R2 pair servers from unrelated tasks and lets R3 find its
    "READ within m steps" in the previous recipe, which corrupts precisely the
    false-positive figure route C exists to measure.
    """

    def __init__(self, config: RuleConfig | None = None) -> None:
        self.config = config or RuleConfig()
        self._analyzers: OrderedDict[str, SessionAnalyzer] = OrderedDict()
        # Keyed by the client's call key, which is already pid-unique. The session is
        # carried alongside so complete() reaches the same analyzer submit() used,
        # even if the client's session id changed in between.
        self.pending: dict[str, tuple[str, ObservedCall]] = {}

    def analyzer_for(self, session: str) -> SessionAnalyzer:
        """The analyzer for ``session``, created on first sight."""
        existing = self._analyzers.get(session)
        if existing is not None:
            self._analyzers.move_to_end(session)
            return existing

        created = SessionAnalyzer(config=self.config)
        self._analyzers[session] = created
        while len(self._analyzers) > MAX_TRACKED_SESSIONS:
            self._analyzers.popitem(last=False)
        return created

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        operation = request.get("op")
        session = str(request.get("session") or DEFAULT_SESSION)

        if operation == "ping":
            return {"ok": True, "calls": len(self.analyzer_for(session).history)}

        if operation == "register_tools":
            changed = self.analyzer_for(session).register_tools(
                request["server"], request["tools"]
            )
            return {"ok": True, "changed": sorted(changed)}

        if operation == "submit":
            call = ObservedCall(
                tool=request["tool"],
                arguments=request.get("arguments", {}),
                server=request.get("server", "default"),
                timestamp=request["timestamp"],
            )
            commit_blocked = bool(request.get("commit_blocked", False))
            verdict = self.analyzer_for(session).submit(call, commit_blocked=commit_blocked)
            # An observe-only proxy forwards a blocked call, so its response is still
            # coming and the call has to stay claimable by complete().
            if not verdict.blocked or commit_blocked:
                self.pending[request["key"]] = (session, call)
            return {"ok": True, "verdict": verdict_to_dict(verdict)}

        if operation == "complete":
            claimed = self.pending.pop(request["key"], None)
            if claimed is None:
                return {"ok": False, "error": "unknown call key"}
            owning_session, call = claimed
            verdict = self.analyzer_for(owning_session).complete(
                call, request.get("response", "")
            )
            return {"ok": True, "verdict": verdict_to_dict(verdict)}

        if operation == "stages":
            return {"ok": True, "stages": self.analyzer_for(session).stages}

        if operation == "reset":
            # No session named means all of them; the op exists for tests and for an
            # operator clearing a daemon between runs.
            if request.get("session"):
                self._analyzers.pop(session, None)
                self.pending = {
                    key: value for key, value in self.pending.items() if value[0] != session
                }
            else:
                self._analyzers.clear()
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
