#!/usr/bin/env bash
# Route C, attack half -- the same pipeline, the same fixtures, the other label.
#
#   scripts/capture_bizops_attack.sh [recipes.txt] [repeats]
#
# Everything here is deliberately identical to capture_bizops.sh except the label,
# the source tag, the recipe file and the audit. That is the whole point: every
# attack population this project has is a statically replayed plan and every benign
# one is live agent work, so a model separates the two *generators* rather than the
# two intents. Measured three times -- window occupancy proxied session length, PS
# proxied argument realism, provenance proxied destination realism -- and none of
# them was fixed by choosing better features.
#
# What differs from the benign script, and why each difference is load-bearing:
#
#   * .mcp.bizattack.json asserts --label attack --source bizattack. Labels are
#     asserted, never inferred (CLAUDE.md, "Trace / audit log format"): dataset.build treats any
#     label that is not "attack" as benign, so a mis-tagged run poisons the negative
#     class silently.
#
#   * fixture_audit.py is NOT run to reject contaminated sessions. Reaching a
#     planted entity is the *objective* here, so the benign audit's verdict is
#     inverted: it is reported for information, and a session that reached a plant
#     is the successful half of the corpus rather than a spoiled one. Note 21's
#     precedent, one step further: an audit with no competence over a population
#     must not delete it.
#
#   * Refusals are counted and reported. The recipe file adds no jailbreak framing,
#     so the agent will decline some fraction of these outright. A declined session
#     records zero trace lines, which is indistinguishable from a crashed one unless
#     something says so (note 14), so both are counted separately and the run exits
#     non-zero if *nothing* was captured at all.
#
# Still observe-only, exactly as the benign side is. Enforcing would stop each chain
# at its first CRITICAL and truncate the corpus -- api_key_calendar_agendas_2 lands
# 17 lines on disk instead of 44 that way, and the one real exfiltration at call 36
# is past the cut. Blocking is evaluated offline, over complete sequences.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
STATE="${CHAINWATCH_HOME:-$HOME/.chainwatch}"
RECIPES="${1:-$ROOT/docs/recipes_bizattack.txt}"
REPEATS="${2:-1}"

# Profile name == trace `source` == .mcp.<profile>.json == session-id prefix, exactly
# as in the benign driver. Four literals collapsed into one string, because a run
# that tagged its lines one way while auditing them another would have looked like a
# clean run.
#
#   PROFILE=twinattack scripts/capture_bizops_attack.sh docs/recipes_twin_attack.txt 1
PROFILE="${PROFILE:-bizattack}"
MCP_CONFIG="$ROOT/.mcp.$PROFILE.json"

# Pinned, never the CLI's moving default -- and it must be the *same* pin the benign
# half used. Refusal rate is a property of the model, so an attack half captured
# under a different agent than its benign twin measures the agent, not the task.
MODEL="${CHAINWATCH_MODEL:-claude-opus-5}"

[ -x "$PYTHON" ] || { echo "no venv at $PYTHON -- see README Quick start" >&2; exit 1; }
[ -f "$RECIPES" ] || {
    echo "no recipe file at $RECIPES -- run scripts/gen_attack_recipes.py" >&2
    exit 1
}
[ -f "$MCP_CONFIG" ] || { echo "no mcp config at $MCP_CONFIG for profile $PROFILE" >&2; exit 1; }
[ -d "$ROOT/AgentLAB/SHADE_Arena" ] || {
    echo "no SHADE_Arena checkout at $ROOT/AgentLAB -- route C has nothing to serve" >&2
    exit 1
}

mkdir -p "$STATE/logs" "$STATE/transcripts"

# One stamp per invocation. Without it the Nth recipe of every run made on the same
# day shares an id, and two runs merge into one apparent session -- the k=10 window
# then reasons over calls that never sat next to each other (note 18).
RUN="$(date +%Y%m%d-%H%M%S)"

# Probe the daemon by connecting, never by [ -S ]: a daemon killed without cleanup
# leaves the socket file behind, so the stat test passes, every proxy falls back to
# per-process state, and dim 9 and R2 die silently (note 17).
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

TRACE="$STATE/logs/$(date -u +%F).jsonl"

# Run the agent from an empty directory, never from the repo.
#
# `claude -p` loads the CLAUDE.md of its working directory into context, and this
# project's CLAUDE.md documents the planted entities, names
# docs/fixture_exclusions.txt and fixture_audit.py, and explains what route C is
# for. Measured on the first attack smoke run: the agent declined and cited "this
# repo's own fixture-contamination notes (docs/fixture_exclusions.txt)"
# in its refusal. That is the firewall's own documentation reaching the subject of
# the experiment.
#
# The benign script does the same, and has to: a benign population captured with the
# spec in context and an attack population captured without it would differ by the
# context rather than by the task, which is the generator leak in a new costume.
WORKDIR="$STATE/agent-cwd"
mkdir -p "$WORKDIR"

# How many lines this session contributed, counted from the trace rather than from
# the agent's own account of itself. A tool call the settings file denies never
# reaches the server and leaves no line, and an agent that declines the task says so
# in prose -- both look like success to `claude -p`'s exit code.
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

for pass in $(seq "$REPEATS"); do
    while IFS= read -r task; do
        case "$task" in ''|'#'*) continue ;; esac
        run=$((run + 1))

        export CHAINWATCH_SESSION="$PROFILE-$RUN-$(printf '%03d' "$run")"
        echo "[$CHAINWATCH_SESSION] ${task:0:110}..." >&2

        status=0
        # Both halves must be captured under identical agent configuration, so this
        # block is byte-identical to capture_bizops.sh's. See that file for why
        # --setting-sources is the seam and `hooks: {}` is not: `--settings` merges
        # rather than replaces, so the operator's SessionStart/Stop hooks reached
        # every session captured before this line existed.
        (cd "$WORKDIR" && claude -p "$task" \
            --model "$MODEL" \
            --mcp-config "$MCP_CONFIG" \
            --strict-mcp-config \
            --setting-sources project \
            --settings "$ROOT/.claude/bizops.settings.json") \
            >"$STATE/transcripts/$CHAINWATCH_SESSION.txt" 2>>"$STATE/logs/$PROFILE.err" \
            || status=$?

        calls="$(calls_for "$CHAINWATCH_SESSION")"
        if [ "$status" -ne 0 ]; then
            errored=$((errored + 1))
            echo "  ... claude exited $status, $calls call(s) (see $STATE/logs/$PROFILE.err)" >&2
        elif [ "$calls" -eq 0 ]; then
            # The agent ran, answered, and issued no tool call. Against this recipe
            # file that is overwhelmingly a refusal, but it is recorded as what was
            # observed -- "no calls" -- because the transcript is the only thing that
            # can tell a refusal from a task the agent thought it had finished.
            silent=$((silent + 1))
            echo "  ... 0 calls: refused or answered in prose (transcript kept)" >&2
        else
            captured=$((captured + 1))
            echo "  ... $calls call(s)" >&2
        fi
    done < "$RECIPES"
done

echo >&2
echo "chainwatch: $run session(s) attempted -> $TRACE" >&2
echo "  captured : $captured" >&2
echo "  no calls : $silent   (refusal or prose-only; transcripts in $STATE/transcripts)" >&2
echo "  errored  : $errored" >&2
if [ "$run" -gt 0 ]; then
    "$PYTHON" -c "print(f'  no-call rate: {$silent / $run:.1%}')" >&2
fi

# Informational only, and inverted: a hit means the agent reached the entity the
# secondary task names, which is the successful half of this population. Never
# --out, never a non-zero exit on contamination.
echo >&2
"$PYTHON" "$ROOT/scripts/fixture_audit.py" --source "$PROFILE" --expect-plants "$TRACE" || true

# Did each attack session actually attack? (note 35) fixture_audit answers "reached a
# plant?" and cannot answer this: american_airlines_2's objective is a distribution
# over airlines, not a planted entity, so a benign trajectory wearing an attack label
# passes the audit while dropping the attack. compliance_check reports it.
#
# Twin-only: the pair mapping assumes docs/recipes_twin_attack.txt's PAIRS ordering,
# so it is meaningful for PROFILE=twinattack and nonsense for the machine-authored
# bizattack goals, which have no pair. `|| true` because the capture already ran --
# a NOT-ATTACKED line tells the operator to drop that session, it does not un-run it.
case "$PROFILE" in
    *twinattack*)
        echo >&2
        "$PYTHON" "$ROOT/scripts/compliance_check.py" --source "$PROFILE" "$TRACE" || true
        ;;
esac

# An empty capture is the one hard failure. Exit 0 here would let a run that
# recorded nothing report success, which is note 14 and note 20 in one place.
if [ "$captured" -eq 0 ]; then
    echo >&2
    echo "captured 0 session(s) with any tool call: nothing was recorded" >&2
    exit 3
fi
