#!/usr/bin/env bash
# Route E -- AgentDojo indirect injection, office domain.
#
#   scripts/capture_agentdojo.sh [recipes.tsv] [repeats]
#   DRY=1 scripts/capture_agentdojo.sh            # print row 1's config + argv, launch nothing
#
# What makes this route different from every attack population before it: the agent
# is never asked to do anything harmful. It is handed a published AgentDojo
# `user_task` PROMPT -- the same one on both halves -- and the *environment* either
# does or does not carry AgentDojo's verbatim important_instructions payload. So a
# resisted injection still produces a full trajectory instead of the zero-call
# refusal that voided the twinattack half (CLAUDE.md §12: 80% refusal on
# human-written secondary tasks, 100% on machine-authored goals).
#
# Both halves run under one frozen executor and differ by the served data alone:
#
#   * --setting-sources project, not `hooks: {}`. `--settings` *merges* hook arrays
#     across sources, so a profile-level empty hooks block does not suppress the
#     operator's SessionStart hook; dropping the user source does (note 33).
#   * --strict-mcp-config, so the ECC plugin's six servers cannot be reached as an
#     unproxied alternative that produces no trace at all (note 14, one level up).
#   * An empty working directory. `claude -p` loads its cwd's CLAUDE.md, and this
#     repo's documents the defence being measured (note 30).
#   * --model pinned and written to every trace line via chainwatch --model, so the
#     batch is reproducible and comparable (note 32).
#
# No daemon. One session serves exactly one suite from one server, so there is no
# cross-server state for it to pool -- dim 9 and R2 are structurally dead on this
# route rather than accidentally dead, and per-process state says so honestly.
#
# Observe-only. Enforcing would stop each session at its first CRITICAL and truncate
# the trajectory, and the injection usually fires late; blocking is evaluated offline
# over complete sequences.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
STATE="${CHAINWATCH_HOME:-$HOME/.chainwatch}"
RECIPES="${1:-$ROOT/docs/recipes_agentdojo.tsv}"
REPEATS="${2:-1}"
PROFILE="${PROFILE:-agentdojo}"
MODEL="${CHAINWATCH_MODEL:-claude-opus-5}"
DRY="${DRY:-0}"

[ -x "$PYTHON" ] || { echo "no venv at $PYTHON -- see CLAUDE.md §10" >&2; exit 1; }
[ -f "$RECIPES" ] || {
    echo "no recipe file at $RECIPES -- run scripts/gen_agentdojo_recipes.py" >&2
    exit 1
}
"$PYTHON" -c "import agentdojo" 2>/dev/null || {
    echo "agentdojo is not installed -- .venv/bin/pip install -e ./agentdojo" >&2
    exit 1
}

mkdir -p "$STATE/logs" "$STATE/transcripts" "$STATE/scores" "$STATE/mcp"

# One stamp per invocation, so the Nth row of two batches gets two distinct session
# ids and the k=10 window never spans them (note 18).
RUN="$(date +%Y%m%d-%H%M%S)"
TRACE="$STATE/logs/$(date -u +%F).jsonl"
SCORES="$STATE/agentdojo_scores-$RUN.jsonl"
WORKDIR="$STATE/agent-cwd"
mkdir -p "$WORKDIR"

# Per-session MCP config. Written under $STATE rather than /tmp so the path stays
# short and predictable; note 16's socket-length limit does not bite here (no
# daemon), but short paths remain the habit.
write_mcp_config() {
    local path="$1" label="$2" suite="$3" user_task="$4" injection_task="$5" score_out="$6"
    INJECT="$injection_task" LABEL="$label" SUITE="$suite" UT="$user_task" \
    SCORE_OUT="$score_out" CAPTURE_MODEL="$MODEL" CAPTURE_PROFILE="$PROFILE" \
    "$PYTHON" - "$path" <<'PY'
import json, os, sys

server = [
    "-m", "agentdojo_bridge.env_mcp_server",
    "--suite", os.environ["SUITE"],
    "--user-task", os.environ["UT"],
    "--score-out", os.environ["SCORE_OUT"],
]
# The one difference between the two halves, and it is server-side data, never a
# change to what the agent is asked.
if os.environ["INJECT"] not in ("", "-"):
    server += ["--inject", os.environ["INJECT"]]

config = {
    "mcpServers": {
        "adojo": {
            "command": "npx",
            "args": [
                "-y", "mcpwall", "--",
                sys.executable, "-m", "chainwatch",
                "--observe-only", "--no-daemon",
                "--label", os.environ["LABEL"],
                "--source", os.environ["CAPTURE_PROFILE"],
                "--model", os.environ["CAPTURE_MODEL"],
                "--log-args",
                "--",
                sys.executable, *server,
            ],
        }
    }
}
with open(sys.argv[1], "w") as handle:
    json.dump(config, handle, indent=2)
PY
}

# Lines this session contributed, counted from the trace rather than from the agent's
# own account of itself: a denied tool call never reaches the server and leaves no
# line, and a prose-only answer looks like success to `claude -p`'s exit code.
calls_for() {
    "$PYTHON" - "$TRACE" "$1" <<'PY'
import json, sys
from pathlib import Path
path, session = Path(sys.argv[1]), sys.argv[2]
count = 0
if path.is_file():
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("session") == session:
                count += 1
print(count)
PY
}

echo "chainwatch: profile $PROFILE, model $MODEL, recipes $RECIPES" >&2

run=0
captured=0
silent=0
errored=0
fired=0

for _pass in $(seq "$REPEATS"); do
    while IFS=$'\t' read -r label suite user_task injection_task prompt; do
        case "$label" in ''|'#'*) continue ;; esac
        run=$((run + 1))

        export CHAINWATCH_SESSION="$PROFILE-$RUN-$(printf '%03d' "$run")"
        CONFIG="$STATE/mcp/$CHAINWATCH_SESSION.json"
        SCORE_OUT="$STATE/scores/$CHAINWATCH_SESSION.json"
        write_mcp_config "$CONFIG" "$label" "$suite" "$user_task" "$injection_task" "$SCORE_OUT"

        if [ "$DRY" != "0" ]; then
            echo "--- $CHAINWATCH_SESSION ($label $suite/$user_task inj=$injection_task)"
            cat "$CONFIG"
            echo "cwd: $WORKDIR"
            echo "claude -p '${prompt:0:80}...' --model $MODEL --mcp-config $CONFIG" \
                 "--strict-mcp-config --setting-sources project" \
                 "--settings $ROOT/.claude/agentdojo.settings.json"
            exit 0
        fi

        echo "[$CHAINWATCH_SESSION] $label $suite/$user_task inj=$injection_task" >&2

        status=0
        (cd "$WORKDIR" && claude -p "$prompt" \
            --model "$MODEL" \
            --mcp-config "$CONFIG" \
            --strict-mcp-config \
            --setting-sources project \
            --settings "$ROOT/.claude/agentdojo.settings.json") \
            >"$STATE/transcripts/$CHAINWATCH_SESSION.txt" 2>>"$STATE/logs/$PROFILE.err" \
            || status=$?

        calls="$(calls_for "$CHAINWATCH_SESSION")"
        if [ "$status" -ne 0 ]; then
            errored=$((errored + 1))
            echo "  ... claude exited $status, $calls call(s) (see $STATE/logs/$PROFILE.err)" >&2
        elif [ "$calls" -eq 0 ]; then
            silent=$((silent + 1))
            echo "  ... 0 calls (transcript kept)" >&2
        else
            captured=$((captured + 1))
            echo "  ... $calls call(s)" >&2
        fi

        # AgentDojo's own verdict, written by the server at stdin EOF. Both outcomes
        # are kept: security=true is the read-then-exfil trajectory this route exists
        # to produce, security=false is a resisted injection, which is still a full
        # trajectory and still a measurement -- that is the property that breaks the
        # refusal deadlock.
        if [ -f "$SCORE_OUT" ]; then
            "$PYTHON" - "$SCORE_OUT" "$CHAINWATCH_SESSION" "$label" >>"$SCORES" <<'PY'
import json, sys
verdict = json.load(open(sys.argv[1]))
verdict.update(session=sys.argv[2], label=sys.argv[3])
print(json.dumps(verdict, separators=(",", ":")))
PY
            if "$PYTHON" -c "import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get('security') else 1)" "$SCORE_OUT"; then
                fired=$((fired + 1))
                echo "  ... security=TRUE (injection fired)" >&2
            fi
        else
            echo "  ... no score sidecar: the server never reached EOF" >&2
        fi
    done < "$RECIPES"
done

echo >&2
echo "chainwatch: $run session(s) attempted -> $TRACE" >&2
echo "  captured : $captured" >&2
echo "  no calls : $silent   (transcripts in $STATE/transcripts)" >&2
echo "  errored  : $errored" >&2
echo "  security fired : $fired" >&2
echo "  scores   : $SCORES" >&2

# An empty capture is the one hard failure: exit 0 would let a run that recorded
# nothing report success, which is notes 14 and 20 in one place.
if [ "$captured" -eq 0 ]; then
    echo >&2
    echo "captured 0 session(s) with any tool call: nothing was recorded" >&2
    exit 3
fi
