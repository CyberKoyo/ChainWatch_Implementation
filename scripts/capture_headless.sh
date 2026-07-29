#!/usr/bin/env bash
# Route B -- volume, over public data only.
#
#   scripts/capture_headless.sh [recipes.txt] [repeats]
#
# Drives `claude -p` once per recipe against proxied github / exa / playwright /
# notes servers. Each run is one session with its own id, so a recipe that fires
# R3 is inspectable on its own rather than smeared across a pooled window.
#
# Session *ordering* here is chosen by the task list. Arguments and responses are
# not: every repo, query and path is real. That distinction is the whole point --
# Phase 8 established the leak lives in argument content, so a generator that
# invents parameter values reproduces `benign_gen` exactly.
#
# Public repositories and public search only. Route A is where the operator's own
# files are captured, and there `--log-args` stays off.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
STATE="${CHAINWATCH_HOME:-$HOME/.chainwatch}"
RECIPES="${1:-$ROOT/docs/recipes.txt}"
REPEATS="${2:-1}"

[ -x "$PYTHON" ] || { echo "no venv at $PYTHON -- see CLAUDE.md §10" >&2; exit 1; }
[ -f "$RECIPES" ] || { echo "no recipe file at $RECIPES" >&2; exit 1; }

mkdir -p "$STATE/logs" "$STATE/notes"

# The github server reads GITHUB_PERSONAL_ACCESS_TOKEN. Borrow the gh CLI's token
# at runtime rather than writing one into .mcp.research.json, which is a file that
# wants to be committable.
if [ -z "${GITHUB_PERSONAL_ACCESS_TOKEN:-}" ] && command -v gh >/dev/null; then
    GITHUB_PERSONAL_ACCESS_TOKEN="$(gh auth token 2>/dev/null || true)"
    export GITHUB_PERSONAL_ACCESS_TOKEN
fi
[ -n "${GITHUB_PERSONAL_ACCESS_TOKEN:-}" ] || \
    echo "warning: no GitHub token; the github recipes will fail and be skipped" >&2

if [ ! -S "$STATE/session.sock" ]; then
    "$PYTHON" -m chainwatch daemon &
    DAEMON=$!
    trap 'kill "$DAEMON" 2>/dev/null || true' EXIT
    for _ in $(seq 20); do [ -S "$STATE/session.sock" ] && break; sleep 0.1; done
fi

run=0
for pass in $(seq "$REPEATS"); do
    # Blank lines and # comments are structure, not tasks.
    while IFS= read -r task; do
        case "$task" in ''|'#'*) continue ;; esac
        run=$((run + 1))

        # A fresh id per recipe. Reusing one across recipes would merge unrelated
        # work into a single k=10 window and invent adjacencies that never happened.
        export CHAINWATCH_SESSION="research-$(date +%Y%m%d)-$(printf '%03d' "$run")"
        echo "[$CHAINWATCH_SESSION] $task" >&2

        # Failures are logged and stepped over: one unreachable repo or rate limit
        # must not end a capture run that is otherwise producing usable traffic.
        claude -p "$task" \
            --mcp-config "$ROOT/.mcp.research.json" \
            --settings "$ROOT/.claude/capture.settings.json" \
            >/dev/null 2>>"$STATE/logs/headless.err" \
            || echo "  ... failed, continuing (see $STATE/logs/headless.err)" >&2
    done < "$RECIPES"
done

echo "chainwatch: $run session(s) -> $STATE/logs/$(date -u +%F).jsonl" >&2
