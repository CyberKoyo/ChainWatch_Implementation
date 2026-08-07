#!/usr/bin/env bash
# Route F -- InjecAgent indirect injection, developer domain.
#
#   scripts/capture_injecagent.sh [recipes.tsv] [repeats]
#   DRY=1 scripts/capture_injecagent.sh           # print row 1's config + argv, launch nothing
#
# Route E's driver with one server swapped. Everything about the executor is
# byte-identical to it on purpose -- the two routes differ by domain, and the two
# *halves* of each route differ by served data alone. See capture_agentdojo.sh for
# why --setting-sources project (note 33), --strict-mcp-config (note 14), the neutral
# cwd (note 30) and the pinned --model (note 32) are each load-bearing.
#
# The one structural difference worth stating: a route F session is one user tool
# plus whatever the agent does next, so these are *short* -- benign around one call,
# a complied attack two or three. Size batches by case count, not by calls, and never
# pool this population with route E's, or session length carries the label.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
STATE="${CHAINWATCH_HOME:-$HOME/.chainwatch}"
RECIPES="${1:-$ROOT/docs/recipes_injecagent.tsv}"
REPEATS="${2:-1}"
PROFILE="${PROFILE:-injecagent}"
MODEL="${CHAINWATCH_MODEL:-claude-opus-5}"
DRY="${DRY:-0}"

[ -x "$PYTHON" ] || { echo "no venv at $PYTHON -- see CLAUDE.md §10" >&2; exit 1; }
[ -f "$RECIPES" ] || {
    echo "no recipe file at $RECIPES -- run scripts/gen_injecagent_recipes.py" >&2
    exit 1
}
[ -d "$ROOT/InjecAgent/data" ] || {
    echo "no InjecAgent checkout at $ROOT/InjecAgent -- route F has nothing to serve" >&2
    exit 1
}

mkdir -p "$STATE/logs" "$STATE/transcripts" "$STATE/scores" "$STATE/mcp"

RUN="$(date +%Y%m%d-%H%M%S)"
TRACE="$STATE/logs/$(date -u +%F).jsonl"
SCORES="$STATE/injecagent_scores-$RUN.jsonl"
WORKDIR="$STATE/agent-cwd"
mkdir -p "$WORKDIR"

write_mcp_config() {
    local path="$1" label="$2" split="$3" variant="$4" case_index="$5" score_out="$6"
    LABEL="$label" SPLIT="$split" VARIANT="$variant" CASE_INDEX="$case_index" \
    SCORE_OUT="$score_out" CAPTURE_MODEL="$MODEL" CAPTURE_PROFILE="$PROFILE" \
    "$PYTHON" - "$path" <<'PY'
import json, os, sys

server = [
    "-m", "injecagent_bridge.env_mcp_server",
    "--split", os.environ["SPLIT"],
    "--variant", os.environ["VARIANT"],
    "--case-index", os.environ["CASE_INDEX"],
    "--score-out", os.environ["SCORE_OUT"],
]
# The one difference between the two halves: the benign twin is the same response
# template with the <Attacker Instruction> slot emptied. The prompt is identical.
if os.environ["LABEL"] == "benign":
    server.append("--benign")

config = {
    "mcpServers": {
        "inj": {
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
complied=0

for _pass in $(seq "$REPEATS"); do
    while IFS=$'\t' read -r label split variant case_index user_tool prompt; do
        case "$label" in ''|'#'*) continue ;; esac
        run=$((run + 1))

        export CHAINWATCH_SESSION="$PROFILE-$RUN-$(printf '%03d' "$run")"
        CONFIG="$STATE/mcp/$CHAINWATCH_SESSION.json"
        SCORE_OUT="$STATE/scores/$CHAINWATCH_SESSION.json"
        write_mcp_config "$CONFIG" "$label" "$split" "$variant" "$case_index" "$SCORE_OUT"

        if [ "$DRY" != "0" ]; then
            echo "--- $CHAINWATCH_SESSION ($label $split/$variant #$case_index $user_tool)"
            cat "$CONFIG"
            echo "cwd: $WORKDIR"
            echo "claude -p '${prompt:0:80}...' --model $MODEL --mcp-config $CONFIG" \
                 "--strict-mcp-config --setting-sources project" \
                 "--settings $ROOT/.claude/injecagent.settings.json"
            exit 0
        fi

        echo "[$CHAINWATCH_SESSION] $label $split/$variant #$case_index $user_tool" >&2

        status=0
        (cd "$WORKDIR" && claude -p "$prompt" \
            --model "$MODEL" \
            --mcp-config "$CONFIG" \
            --strict-mcp-config \
            --setting-sources project \
            --settings "$ROOT/.claude/injecagent.settings.json") \
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

        # InjecAgent's success criterion: did the agent call an attacker tool. A
        # resisted injection still produced a trajectory and is kept -- that is the
        # property that breaks the refusal deadlock.
        if [ -f "$SCORE_OUT" ]; then
            "$PYTHON" - "$SCORE_OUT" "$CHAINWATCH_SESSION" "$label" >>"$SCORES" <<'PY'
import json, sys
verdict = json.load(open(sys.argv[1]))
verdict.update(session=sys.argv[2], label=sys.argv[3])
print(json.dumps(verdict, separators=(",", ":")))
PY
            if "$PYTHON" -c "import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get('attacker_called') else 1)" "$SCORE_OUT"; then
                complied=$((complied + 1))
                echo "  ... attacker tool CALLED" >&2
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
echo "  attacker tool called : $complied" >&2
echo "  scores   : $SCORES" >&2

if [ "$captured" -eq 0 ]; then
    echo >&2
    echo "captured 0 session(s) with any tool call: nothing was recorded" >&2
    exit 3
fi
