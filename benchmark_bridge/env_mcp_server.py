"""Serve an AgentLAB environment as a real MCP stdio server.

This is what turns the benchmark from a list of *plans* into live JSON-RPC
traffic. Run underneath the proxy chain exactly as a real server would be:

    npx mcpwall -- python -m chainwatch -- \\
        python -m benchmark_bridge.env_mcp_server --env banking

Implements the subset of MCP the replay exercises: ``initialize``, ``tools/list``,
``tools/call``. That is deliberate -- this is an evaluation fixture, not a general
MCP server, and a smaller surface is easier to trust.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .base import AdapterError, EnvAdapter

PROTOCOL_VERSION = "2024-11-05"


def load_adapter(env: str, family: str = "auto") -> EnvAdapter:
    """Build the adapter for ``env``, choosing the family automatically if asked.

    SHADE_Arena is tried first because it carries the majority of the verified
    chains and its environment labels are the ones the chain metadata uses.
    """
    if family in ("auto", "shade"):
        try:
            from .shade_arena import ShadeArenaAdapter

            return ShadeArenaAdapter(env)
        except AdapterError:
            if family == "shade":
                raise
        except Exception:
            if family == "shade":
                raise

    from .safetybench import SafetyBenchAdapter

    return SafetyBenchAdapter(env)


def handle(adapter: EnvAdapter, request: dict[str, Any]) -> dict[str, Any] | None:
    """Produce the JSON-RPC response for one request, or ``None`` for notifications."""
    method = request.get("method", "")
    request_id = request.get("id")

    # Notifications carry no id and expect no reply.
    if request_id is None:
        return None

    if method == "initialize":
        result: Any = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": f"agentlab-{adapter.name}", "version": "1.0.0"},
        }
    elif method == "tools/list":
        result = {"tools": adapter.list_tools()}
    elif method == "tools/call":
        params = request.get("params") or {}
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            output = adapter.call_tool(name, arguments)
        except Exception as error:
            output = {"success": False, "message": f"{type(error).__name__}: {error}"}
        # MCP wraps tool output in content blocks; the text carries the payload
        # that ChainWatch's output-characteristic detectors read.
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


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmark_bridge.env_mcp_server")
    parser.add_argument("--env", required=True, help="environment name, e.g. banking")
    parser.add_argument("--family", default="auto", choices=["auto", "shade", "safetybench"])
    options = parser.parse_args(argv)

    adapter = load_adapter(options.env, options.family)

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
