#!/usr/bin/env bash
# Route A -- capture the work you were going to do anyway.
#
# Starts the cross-server session daemon, then launches Claude Code with every
# file operation routed through a proxied filesystem MCP server instead of the
# built-in tools. Nothing about the work changes; only the pipe it travels down.
#
#   scripts/capture.sh [extra claude args...]
#
# Everything is observe-only: Phase 7 measured 17.5% false positives on benign
# traffic and every one of them was a block, so an enforcing proxy would kill
# real tool calls in the middle of real work.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
STATE="${CHAINWATCH_HOME:-$HOME/.chainwatch}"

[ -x "$PYTHON" ] || { echo "no venv at $PYTHON -- see CLAUDE.md §10" >&2; exit 1; }

mkdir -p "$STATE/logs" "$STATE/notes"

# One id for the whole capture session. With the daemon on, the proxied servers
# share a single k=10 window, so their calls must share a session id too --
# otherwise the trace grouping would not match what the rules reasoned over.
export CHAINWATCH_SESSION="${CHAINWATCH_SESSION:-$(date +%Y%m%d-%H%M%S)}"

if [ ! -S "$STATE/session.sock" ]; then
    "$PYTHON" -m chainwatch daemon &
    DAEMON=$!
    trap 'kill "$DAEMON" 2>/dev/null || true' EXIT
    # The socket appears a beat after the process does; a proxy that starts first
    # falls back to per-process state and silently loses cross-server flags.
    for _ in $(seq 20); do [ -S "$STATE/session.sock" ] && break; sleep 0.1; done
fi

echo "chainwatch: session $CHAINWATCH_SESSION -> $STATE/logs/$(date -u +%F).jsonl" >&2

exec claude \
    --mcp-config "$ROOT/.mcp.capture.json" \
    --settings "$ROOT/.claude/capture.settings.json" \
    "$@"
