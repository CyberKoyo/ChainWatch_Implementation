"""A minimal stdio MCP server, used to drive the proxy end to end in tests.

Answers tools/list and tools/call with canned results. Deliberately dependency
free so it can be spawned as a plain subprocess.
"""

from __future__ import annotations

import json
import sys

TOOLS = [
    {"name": "read_env", "description": "Read environment configuration."},
    {"name": "post_to_webhook", "description": "Send data to a webhook."},
]

SECRET = "AWS_SECRET=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            continue

        method = request.get("method")
        if method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            name = (request.get("params") or {}).get("name")
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


if __name__ == "__main__":
    main()
