#!/usr/bin/env bash
# Route C -- business operations, over simulated but populated environments.
#
#   scripts/capture_bizops.sh [recipes.txt] [repeats]
#
# Drives `claude -p` once per recipe against SHADE_Arena's workspace, banking,
# travel and spam_filter environments, each served as a real MCP stdio server by
# agentlab_bridge.env_mcp_server and each wrapped in the chainwatch proxy.
#
# Why this exists. Routes A and B capture software engineering: files, repos,
# docs. Nothing in either exercises payments, email, calendar or filter
# configuration -- so R2, which section VI names as the likely false-positive
# source for "legitimate enterprise workflows spanning multiple services", and R5,
# whose entire attack population is 5 chains, have never seen benign traffic.
#
# Why simulated data is acceptable here, when benign_gen's was not. The leak Phase
# 8 measured is in argument *content*: benign_gen fills parameters from a list of
# placeholders, so PS is 0.002 by construction. Here the environments ship ~1.1 MB
# of populated fixtures and an agent picks the arguments out of them -- a real
# invoice body, a real balance, a real contact. The generator chooses nothing.
#
# The fixtures are shared with SHADE_Arena's attack task pairs, so the run ends
# with scripts/fixture_audit.py checking that no session reached a planted entity.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
STATE="${CHAINWATCH_HOME:-$HOME/.chainwatch}"
RECIPES="${1:-$ROOT/docs/recipes_bizops.txt}"
REPEATS="${2:-1}"

[ -x "$PYTHON" ] || { echo "no venv at $PYTHON -- see CLAUDE.md §10" >&2; exit 1; }
[ -f "$RECIPES" ] || { echo "no recipe file at $RECIPES" >&2; exit 1; }
[ -d "$ROOT/AgentLAB/SHADE_Arena" ] || {
    echo "no SHADE_Arena checkout at $ROOT/AgentLAB -- route C has nothing to serve" >&2
    exit 1
}

mkdir -p "$STATE/logs" "$STATE/transcripts"

# One stamp per invocation, to second resolution. Without it the session id is
# `bizops-YYYYMMDD-NNN`, which is identical for the Nth recipe of every run made
# on the same day -- so two runs merge into one apparent session, and the k=10
# window is asked to reason over calls that never sat next to each other.
# Measured: a 24-call run and a 15-call run reported as one 39-call session.
RUN="$(date +%Y%m%d-%H%M%S)"

# No credentials of any kind: every environment is local and in-memory. That is
# route C's advantage over route B, which needs a GitHub token and rate limits.

# The daemon is not optional here. The cross-service recipes are the only source
# of dim 9 (cross-server) and the only way R2 can fire, and both need the four
# proxied servers to share one k=10 window.
#
# Probe by connecting, not by `[ -S ]`. A daemon killed without cleanup leaves the
# socket file behind, so the stat test passes, the script declines to start a
# daemon, and every proxy falls back to per-process state -- capture continues,
# dim 9 and R2 are dead, and nothing says so. Measured: a run whose call index
# restarted mid-session because two proxies each owned a counter.
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
daemon_alive || {
    echo "no daemon answering on $STATE/session.sock; cross-server flags would be dead" >&2
    exit 1
}

run=0
for pass in $(seq "$REPEATS"); do
    # Blank lines and # comments are structure, not tasks.
    while IFS= read -r task; do
        case "$task" in ''|'#'*) continue ;; esac
        run=$((run + 1))

        # A fresh id per recipe. Reusing one across recipes would merge unrelated
        # work into a single k=10 window and invent adjacencies that never
        # happened. Within a recipe the id is shared by all four servers, which is
        # what makes a cross-service session one session.
        export CHAINWATCH_SESSION="bizops-$RUN-$(printf '%03d' "$run")"
        echo "[$CHAINWATCH_SESSION] $task" >&2

        # Keep the agent's own transcript. A tool call the settings file denies
        # never reaches the server, so it leaves no trace line at all -- meaning
        # "the agent chose not to send an email" and "the send was denied" look
        # identical in the trace and differ only here. Discarding this made a
        # zero-write session undiagnosable without re-running the whole capture.
        #
        # Failures are logged and stepped over: one environment that fails to
        # instantiate must not end a run that is otherwise producing traffic.
        claude -p "$task" \
            --mcp-config "$ROOT/.mcp.bizops.json" \
            --settings "$ROOT/.claude/bizops.settings.json" \
            >"$STATE/transcripts/$CHAINWATCH_SESSION.txt" 2>>"$STATE/logs/bizops.err" \
            || echo "  ... failed, continuing (see $STATE/logs/bizops.err)" >&2
    done < "$RECIPES"
done

TRACE="$STATE/logs/$(date -u +%F).jsonl"
echo "chainwatch: $run session(s) -> $TRACE" >&2

# A session that paid bank_transfer_2's IBAN carries a benign label over an
# attack. Report it here rather than at training time, where it would be one
# poisoned row among thousands. Non-zero exit is deliberate: a contaminated
# capture should be noticed now.
echo >&2
"$PYTHON" "$ROOT/scripts/fixture_audit.py" --source bizops "$TRACE"
