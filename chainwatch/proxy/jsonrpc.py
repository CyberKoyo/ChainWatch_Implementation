"""Line-delimited JSON-RPC 2.0 helpers for the stdio proxy.

MCP speaks JSON-RPC 2.0 over stdio, one compact JSON object per line. Everything
here is deliberately tolerant: a proxy that raises on a message it does not
understand would break the very traffic it exists to protect. Parsing failures
return ``None`` and the caller forwards the raw line untouched -- mirroring
mcpwall's documented "fail open on outbound errors" stance.
"""

from __future__ import annotations

import json
from typing import Any

#: JSON-RPC error code returned when ChainWatch blocks a call. The -32000..-32099
#: block is reserved for implementation-defined server errors.
BLOCKED_ERROR_CODE = -32001


def parse(line: str) -> dict[str, Any] | None:
    """Parse one line into a JSON-RPC message, or ``None`` if it is not one."""
    line = line.strip()
    if not line:
        return None
    try:
        message = json.loads(line)
    except (ValueError, TypeError):
        return None
    return message if isinstance(message, dict) else None


def serialize(message: dict[str, Any]) -> str:
    """Render a message as a single line, compact, newline-terminated."""
    return json.dumps(message, separators=(",", ":"), ensure_ascii=False) + "\n"


def is_tool_call(message: dict[str, Any]) -> bool:
    return message.get("method") == "tools/call"


def is_tools_list(message: dict[str, Any]) -> bool:
    return message.get("method") == "tools/list"


def tool_call_details(message: dict[str, Any]) -> tuple[str, Any]:
    """Extract ``(tool_name, arguments)`` from a ``tools/call`` request."""
    params = message.get("params") or {}
    return params.get("name", ""), params.get("arguments", {})


def extract_tools(result: Any) -> list[dict[str, Any]]:
    """Pull the tool definition list out of a ``tools/list`` result."""
    if isinstance(result, dict):
        tools = result.get("tools")
        if isinstance(tools, list):
            return [t for t in tools if isinstance(t, dict)]
    return []


def response_text(message: dict[str, Any]) -> str:
    """Flatten a response to text for output-characteristic scanning.

    The whole ``result`` is serialized rather than only its ``content`` blocks:
    injected instructions have been documented in error messages and metadata as
    well as visible content (CyberArk, ref [22]).
    """
    if "result" in message:
        payload = message["result"]
    elif "error" in message:
        payload = message["error"]
    else:
        return ""
    if isinstance(payload, str):
        return payload
    return json.dumps(payload, ensure_ascii=False)


def blocked_response(request_id: Any, message: str, rules: list[str]) -> dict[str, Any]:
    """Build the JSON-RPC error returned in place of a blocked call.

    Sent upstream to mcpwall, which forwards it to the host. The agent sees a
    failed tool call and the reason, which is the intended feedback: the model
    should learn the action was refused, not silently receive nothing.
    """
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": BLOCKED_ERROR_CODE,
            "message": f"[BLOCKED BY CHAINWATCH] {message}",
            "data": {"rules": rules, "detector": "chainwatch"},
        },
    }
