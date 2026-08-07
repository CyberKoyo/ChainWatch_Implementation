"""Serve one InjecAgent case as an MCP stdio server for ChainWatch capture.

Same wire shape as ``agentdojo_bridge/env_mcp_server.py``. Benign vs attack is again
a server-side data choice: ``--benign`` serves the case's ``Tool Response Template``
with the ``<Attacker Instruction>`` slot emptied, and without it the published
``Tool Response`` -- injection included -- is served verbatim.

At stdin EOF the server writes ``{"attacker_called", "attacker_tools_called",
"calls", ...}`` to ``--score-out``. That is InjecAgent's own success criterion.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .adapter import InjecAgentAdapter
from .loader import SPLITS, VARIANTS, dev_cases

PROTOCOL_VERSION = "2024-11-05"


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def handle(adapter: InjecAgentAdapter, request: dict[str, Any]) -> dict[str, Any] | None:
    """Produce the JSON-RPC response for one request, or ``None`` for notifications."""
    method = request.get("method", "")
    request_id = request.get("id")
    if request_id is None:
        return None

    if method == "initialize":
        result: Any = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "injecagent", "version": "1.0.0"},
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
    parser = argparse.ArgumentParser(prog="injecagent_bridge.env_mcp_server")
    parser.add_argument("--split", default="ds", choices=list(SPLITS))
    parser.add_argument("--variant", default="base", choices=list(VARIANTS))
    parser.add_argument("--case-index", type=int, required=True)
    parser.add_argument(
        "--benign",
        action="store_true",
        help="serve the injection-stripped response (the benign twin of this case)",
    )
    parser.add_argument("--score-out", default=None, help="where to write the verdict")
    options = parser.parse_args(argv)

    cases = dev_cases(options.split, options.variant)
    if not 0 <= options.case_index < len(cases):
        parser.error(
            f"--case-index {options.case_index} out of range: "
            f"{options.split}/{options.variant} has {len(cases)} dev cases"
        )
    adapter = InjecAgentAdapter(cases[options.case_index], benign=options.benign)

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
        verdict = adapter.score()
        verdict.update(
            split=options.split,
            variant=options.variant,
            case_index=options.case_index,
            benign=options.benign,
            user_tool=adapter.user_tool,
        )
        with open(options.score_out, "w") as score_file:
            json.dump(verdict, score_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
