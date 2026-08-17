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
# invents parameter values reproduces `agentlab_benign_gen` exactly.
#
# Public repositories and public search only. Route A is where the operator's own
# files are captured, and there `--log-args` stays off.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
STATE="${CHAINWATCH_HOME:-$HOME/.chainwatch}"
RECIPES="${1:-$ROOT/docs/recipes.txt}"
REPEATS="${2:-1}"

[ -x "$PYTHON" ] || { echo "no venv at $PYTHON -- see README Quick start" >&2; exit 1; }
[ -f "$RECIPES" ] || { echo "no recipe file at $RECIPES" >&2; exit 1; }

mkdir -p "$STATE/logs" "$STATE/notes"

# One stamp per invocation. `research-YYYYMMDD-NNN` is identical for the Nth
# recipe of every run made on the same day, so two runs merge into one apparent
# session and the k=10 window reasons over calls that never sat next to each
# other. Same defect measured on route C.
RUN="$(date +%Y%m%d-%H%M%S)"

# The github server reads GITHUB_PERSONAL_ACCESS_TOKEN. Borrow the gh CLI's token
# at runtime rather than writing one into .mcp.research.json, which is a file that
# wants to be committable.
if [ -z "${GITHUB_PERSONAL_ACCESS_TOKEN:-}" ] && command -v gh >/dev/null; then
    GITHUB_PERSONAL_ACCESS_TOKEN="$(gh auth token 2>/dev/null || true)"
    export GITHUB_PERSONAL_ACCESS_TOKEN
fi
[ -n "${GITHUB_PERSONAL_ACCESS_TOKEN:-}" ] || \
    echo "warning: no GitHub token; the github recipes will fail and be skipped" >&2

# Probe by connecting, not by `[ -S ]`: a daemon killed without cleanup leaves the
# socket file behind, so the stat test passes, no daemon is started, and every
# proxy silently falls back to per-process state with dim 9 and R2 dead.
daemon_alive() {
    "$PYTHON" - "$STATE/session.sock" <<'PY'
import socket, sys
probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
probe.settimeout(1.0)
try:
    probe.connect(sys.argv[1])
except OSError:
    sys.exit(1)
PY
}

if ! daemon_alive; then
    rm -f "$STATE/session.sock"          # only ever a corpse; a live one answered above
    "$PYTHON" -m chainwatch daemon &
    DAEMON=$!
    trap 'kill "$DAEMON" 2>/dev/null || true' EXIT
    for _ in $(seq 40); do daemon_alive && break; sleep 0.1; done
fi

run=0
for pass in $(seq "$REPEATS"); do
    # Blank lines and # comments are structure, not tasks.
    while IFS= read -r task; do
        case "$task" in ''|'#'*) continue ;; esac
        run=$((run + 1))

        # A fresh id per recipe. Reusing one across recipes would merge unrelated
        # work into a single k=10 window and invent adjacencies that never happened.
        export CHAINWATCH_SESSION="research-$RUN-$(printf '%03d' "$run")"
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
