"""Transparent stdio proxy -- the process that sits in the MCP chain.

Spawns the real MCP server (everything after ``--``) and pumps JSON-RPC lines in
both directions, handing each to an :class:`Interceptor` on the way past.

    host -> mcpwall -> [ this process ] -> real MCP server

Design rules, both inherited from mcpwall so the two layers behave consistently:

* **Fail open.** Any line that cannot be parsed, or any error inside inspection,
  is forwarded unchanged. A monitoring layer must never be the reason legitimate
  traffic breaks.
* **Never buffer.** Every line is flushed immediately; MCP clients block waiting
  on responses, so a buffered proxy looks like a hung server.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, TextIO

from ..audit import DEFAULT_LOG_DIR, AuditLog
from ..engine.rules import RuleConfig
from . import jsonrpc
from .interceptor import Interceptor


class StdioProxy:
    """Bidirectional JSON-RPC pump around a child MCP server process."""

    #: How long to keep draining responses after stdin closes. A slow server --
    #: `npx` fetching a package on first run is the common case -- can still be
    #: starting up when the last request arrives. At 2 seconds the proxy tore down
    #: first and silently dropped every reply.
    drain_timeout: float = 30.0

    def __init__(self, command: list[str], interceptor: Interceptor) -> None:
        if not command:
            raise ValueError("no server command given; expected: chainwatch [opts] -- <command>")
        self.command = command
        self.interceptor = interceptor
        self.process: subprocess.Popen[str] | None = None

    def run(self) -> int:
        """Start the child and pump until either side closes. Returns its exit code."""
        self.process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # child stderr passes straight through to ours
            text=True,
            bufsize=1,
        )

        downstream = threading.Thread(target=self._pump_responses, daemon=True)
        downstream.start()

        try:
            self._pump_requests()
        except (BrokenPipeError, KeyboardInterrupt):
            pass
        finally:
            self._shutdown()

        downstream.join(timeout=self.drain_timeout)
        return self.process.returncode or 0

    # ------------------------------------------------------------------ pumps

    def _pump_requests(self) -> None:
        """host -> server. The direction where calls get blocked."""
        assert self.process is not None and self.process.stdin is not None
        child_stdin = self.process.stdin

        for line in sys.stdin:
            message = jsonrpc.parse(line)
            if message is None:
                self._write(child_stdin, line)
                continue

            try:
                decision = self.interceptor.on_request(message)
            except Exception as error:  # fail open, loudly
                self._warn(f"inspection error on request, forwarding anyway: {error!r}")
                self._write(child_stdin, line)
                continue

            if decision.forward:
                self._write(child_stdin, line)
            elif decision.reply is not None:
                # Blocked: answer the host ourselves, never touch the server.
                self._write(sys.stdout, jsonrpc.serialize(decision.reply))

    def _pump_responses(self) -> None:
        """server -> host. The direction that completes feature extraction."""
        assert self.process is not None and self.process.stdout is not None

        for line in self.process.stdout:
            message = jsonrpc.parse(line)
            if message is None:
                self._write(sys.stdout, line)
                continue

            try:
                self.interceptor.on_response(message)
            except Exception as error:  # fail open
                self._warn(f"inspection error on response, forwarding anyway: {error!r}")

            self._write(sys.stdout, line)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _write(stream: TextIO, line: str) -> None:
        try:
            stream.write(line if line.endswith("\n") else line + "\n")
            stream.flush()
        except (BrokenPipeError, ValueError):
            pass

    @staticmethod
    def _warn(text: str) -> None:
        sys.stderr.write(f"[chainwatch] {text}\n")
        sys.stderr.flush()

    def _shutdown(self) -> None:
        if self.process is None:
            return
        # Give outstanding calls a chance to come back before tearing the child
        # down; closing its stdin first would strand them.
        self.interceptor.wait_for_quiescence(self.drain_timeout)
        try:
            if self.process.stdin:
                self.process.stdin.close()
        except (BrokenPipeError, ValueError):
            pass
        try:
            self.process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self.process.kill()


def split_command(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split our own options from the child command at the ``--`` separator."""
    if "--" not in argv:
        return argv, []
    index = argv.index("--")
    return argv[:index], argv[index + 1 :]


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    own_args, command = split_command(argv)

    parser = argparse.ArgumentParser(
        prog="chainwatch",
        description="Sequential multi-step attack detection for MCP (arXiv:2607.19432v1)",
    )
    parser.add_argument("--server", default=None, help="name for this server in alerts and logs")
    parser.add_argument(
        "--server-map",
        default=None,
        help="JSON file mapping tool name -> server label; overrides --server per call",
    )
    parser.add_argument("--window", type=int, default=10, help="sliding window k (default 10)")
    parser.add_argument("--steps", type=int, default=5, help="step threshold m (default 5)")
    parser.add_argument(
        "--observe-only",
        action="store_true",
        help="report but never block; for calibrating false positives",
    )
    parser.add_argument("--no-daemon", action="store_true", help="skip the shared session daemon")
    parser.add_argument(
        "--label",
        choices=("benign", "attack"),
        help="what this traffic is, asserted by you. Required unless --no-log: an "
        "unlabelled session would train as benign, which is a claim, not a default",
    )
    parser.add_argument(
        "--source",
        default="live",
        help="population tag, so captured lines stay separable from other corpora",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="model id driving this capture, stamped on every trace line. Asserted, "
        "never inferred: a batch whose agent is unrecorded is not reproducible and "
        "cannot be compared with another batch (note 32)",
    )
    parser.add_argument("--log-dir", default=None, help=f"trace directory (default {DEFAULT_LOG_DIR})")
    parser.add_argument(
        "--log-args",
        action="store_true",
        help="also record call arguments. Off by default: training reads only the "
        "feature vector, and real arguments carry the contents of real files",
    )
    parser.add_argument("--no-log", action="store_true", help="do not write a trace at all")
    options = parser.parse_args(own_args)

    if not command:
        parser.error("no server command given; usage: chainwatch [options] -- <command> [args...]")

    if not options.no_log and not options.label:
        parser.error("--label benign|attack is required when logging; or pass --no-log")

    # Imported here so the engine stays importable without the daemon present.
    from ..daemon.client import build_session_backend

    server_name = options.server or command[-1].split("/")[-1]
    config = RuleConfig(window=options.window, step_threshold=options.steps)
    # One id per *session*, not per process: with the daemon on, several proxied servers
    # share one k=10 window, so their lines must group together or the trace will not
    # match what the rules actually reasoned over. Export CHAINWATCH_SESSION to tie them.
    #
    # Resolved *before* the backend, and handed to it, because the daemon keys one
    # analyzer per session. Built the other way round the daemon got no id at all and
    # pooled every session of its lifetime into one window -- so a capture run's
    # recipes were judged against each other's calls while the trace, using this same
    # id, correctly recorded them apart.
    session = os.environ.get("CHAINWATCH_SESSION") or uuid.uuid4().hex[:12]

    backend = build_session_backend(
        config=config, use_daemon=not options.no_daemon, session=session
    )

    audit = None
    if not options.no_log:
        audit = AuditLog(
            directory=options.log_dir or DEFAULT_LOG_DIR,
            include_arguments=options.log_args,
            model=options.model,
        )
        # Say so out loud. Silent capture is indistinguishable from a misconfiguration,
        # and the whole point is noticing later that the corpus is empty.
        sys.stderr.write(
            f"[chainwatch] recording {options.label}/{options.source} "
            f"session {session} to {audit.directory}\n"
        )
        sys.stderr.flush()

    # Validated here rather than trusted: a map that is not str -> str would silently
    # degrade back to one server per session, which is the false topology --server-map
    # exists to remove, and it would do so with no visible symptom in the corpus.
    server_map = None
    if options.server_map:
        server_map = json.loads(Path(options.server_map).read_text(encoding="utf-8"))
        if not isinstance(server_map, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in server_map.items()
        ):
            parser.error("--server-map must be a JSON object of string -> string")

    interceptor = Interceptor(
        server=server_name,
        server_map=server_map,
        analyzer=backend,
        enforcing=not options.observe_only,
        audit=audit,
        session=session,
        label=options.label or "",
        source=options.source,
    )
    return StdioProxy(command, interceptor).run()


if __name__ == "__main__":
    raise SystemExit(main())
