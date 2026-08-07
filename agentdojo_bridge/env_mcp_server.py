"""Serve one AgentDojo suite as an MCP stdio server for ChainWatch capture.

Mirrors ``agentlab_bridge/env_mcp_server.py``. Benign vs attack is decided *here*,
not by the agent: ``--inject <injection_task_id>`` fills the suite's injection
vectors with AgentDojo's verbatim ``important_instructions`` payload; without it the
env carries the innocuous defaults. The prompt handed to the agent is the same
published ``user_task`` either way.

At stdin EOF the server writes AgentDojo's own ``utility()``/``security()`` verdict
to ``--score-out``. That is published ground truth, and it is what replaces the
hand-authored checks CLAUDE.md notes 34 and 35 were written about.

Run underneath the proxy chain exactly as a real server would be:

    npx mcpwall -- python -m chainwatch --observe-only --label attack \\
        --source agentdojo --model claude-opus-5 -- \\
        python -m agentdojo_bridge.env_mcp_server --suite workspace \\
            --user-task user_task_0 --inject injection_task_1 --score-out /tmp/s.json
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .adapter import SUITE_NAMES, AgentDojoAdapter
from .payload import build_injections

PROTOCOL_VERSION = "2024-11-05"


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def handle(adapter: AgentDojoAdapter, request: dict[str, Any]) -> dict[str, Any] | None:
    """Produce the JSON-RPC response for one request, or ``None`` for notifications."""
    method = request.get("method", "")
    request_id = request.get("id")
    if request_id is None:
        return None

    if method == "initialize":
        result: Any = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": f"agentdojo-{adapter.name}", "version": "1.0.0"},
        }
    elif method == "tools/list":
        result = {"tools": adapter.list_tools()}
    elif method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            output = adapter.call_tool(name, arguments)
        except Exception as error:  # never crash the pipe
            output = {"success": False, "message": f"{type(error).__name__}: {error}"}
        result = {
            "content": [{"type": "text", "text": _as_text(output)}],
            "isError": bool(isinstance(output, dict) and output.get("success") is False),
        }
    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentdojo_bridge.env_mcp_server")
    parser.add_argument("--suite", required=True, choices=list(SUITE_NAMES))
    parser.add_argument("--inject", default=None, help="injection_task_id (omit for benign)")
    parser.add_argument("--user-task", default=None, help="user_task_id, for utility scoring")
    parser.add_argument("--score-out", default=None, help="where to write the verdict")
    options = parser.parse_args(argv)

    injections = build_injections(options.suite, options.inject) if options.inject else {}
    adapter = AgentDojoAdapter(options.suite, injections)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            continue
        response = handle(adapter, request)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()

    if options.score_out:
        verdict = adapter.score(options.user_task, options.inject)
        verdict.update(
            suite=options.suite,
            user_task=options.user_task,
            injection_task=options.inject,
            calls=len(adapter.trace),
        )
        with open(options.score_out, "w") as score_file:
            json.dump(verdict, score_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
