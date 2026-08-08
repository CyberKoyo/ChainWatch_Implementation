"""A minimal stdio MCP server, used to drive the proxy end to end in tests.

Answers tools/list and tools/call with canned results. Deliberately dependency
free so it can be spawned as a plain subprocess.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

TOOLS = [
    {"name": "read_env", "description": "Read environment configuration."},
    {"name": "post_to_webhook", "description": "Send data to a webhook."},
]

SECRET = "AWS_SECRET=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"


def main() -> None:
    tool_calls = 0
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            continue

        method = request.get("method")
        if method == os.environ.get("STUB_NO_REPLY_METHOD"):
            continue
        if method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            name = (request.get("params") or {}).get("name")
            if name and name == os.environ.get("STUB_REJECT_TOOL"):
                sys.stdout.write(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": request.get("id"),
                            "error": {"code": -32000, "message": "blocked by policy"},
                        }
                    )
                    + "\n"
                )
                sys.stdout.flush()
                continue
            tool_calls += 1
            if name == "read_env":
                result = {"content": SECRET}
            else:
                result = {"ok": True}
        else:
            result = {}

        sys.stdout.write(
            json.dumps({"jsonrpc": "2.0", "id": request.get("id"), "result": result}) + "\n"
        )
        sys.stdout.flush()

    score_out = os.environ.get("STUB_SCORE_OUT")
    if score_out:
        Path(score_out).write_text(
            json.dumps(
                {
                    "calls": tool_calls,
                    "has_openai_api_key": bool(os.environ.get("OPENAI_API_KEY")),
                }
            ),
            encoding="utf-8",
        )
    raise SystemExit(int(os.environ.get("STUB_EXIT_CODE", "0")))


if __name__ == "__main__":
    main()
