# Capturing a benign corpus that means something

Companion to `scripts/capture.sh` and `scripts/capture_headless.sh`. CLAUDE.md §12 records
*why* this exists; this file records how to run it and what to check.

## The one rule

Session ordering may be synthetic. **Arguments and responses must not be.**

Phase 8 measured where the previous corpus went wrong: `benign_gen` fills arguments from
`PLACEHOLDERS` (`"report"`, `5`, `False`), giving synthesized benign a parameter-sensitivity
mean of 0.002 against the attack corpus's 0.092 — while *real* benign work scores 0.407. Every
model trained on it learned "PS > 0 → attack", which is a fact about the generator. Matching the
shape of benign traffic — length, tool mix, category balance — does not address this, because
the leak is in argument content, which every synthesized population shares.

So: no recipe fills a parameter from a list, and no recipe tells the agent which tools to call
in which order. If the sequence comes from the recipe author, the trace records the author's
idea of an attack shape rather than an agent's behaviour, which is the same failure one level up.

## Route A — your own work, re-routed

```bash
scripts/capture.sh
```

Starts the daemon, then launches Claude Code with `Read`/`Write`/`Edit`/`Glob`/`Grep` denied, so
the proxied `filesystem` server is the only path to a file. The work is whatever you were going
to do anyway; only the pipe changes. Tagged `source: devwork`.

**`Bash` stays allowed** — there is no MCP equivalent, and denying it would break the work being
captured. This is route A's honest limit: Bash was 291 of the 532 tool calls in the existing
transcripts, so roughly half of real activity stays invisible to the proxy no matter what.

`--log-args` is off, so only the 20-dim vector `v` is recorded — never the contents of your files.

## Route B — public data, for volume

```bash
scripts/capture_headless.sh                      # one pass over docs/recipes.txt
scripts/capture_headless.sh docs/recipes.txt 5   # five passes
```

Run this **after** route A, aimed at whatever route A leaves dead — the point is to target
measured gaps rather than guess. Tagged `source: research`, one session id per recipe, public
repositories and public search only.

| recipe group | servers | targets |
|---|---|---|
| read-then-network | github, notes | benign R3 shape with real arguments — the population R3's false-positive rate depends on |
| long browsing | playwright, notes | 20+ call sessions; OC 16 (volume anomaly), OC 19 (external URL) |
| search into a write | exa, notes | an external URL flowing into a local write |
| short lookups | context7 | low-sensitivity stage-2 negatives |

Two properties every recipe holds:

- **Length ≥ 4 calls.** The attack corpus averages 2.8 calls and 74/200 are ≤2, against a
  six-stage kill chain whose documented attacks span 4–7. A benign corpus with the same defect
  would prove nothing about a rule that needs a progression to fire.
- **Real targets.** Real repos, real queries, real paths.

`sequential-thinking` is deliberately absent: high call volume, prose arguments, no data flow.

## What to check afterwards

Traces are JSON Lines at `~/.chainwatch/logs/YYYY-MM-DD.jsonl`, format in CLAUDE.md §10.

1. **Did anything get captured at all?** If file operations do not appear as `tools/call`, the
   deny list is not taking effect and the built-in tools are still winning. That is route A's
   whole failure mode, and it looks exactly like "quiet session" from the outside.
2. **Was anything blocked?** Observe-only means `blocked` is false on every line even when
   `severity` is CRITICAL. A true `blocked` means the profile is wrong.
3. **Cross-server.** One `session` value spanning several `server` values, with dim 9 nonzero.
   If R2 never fires with three servers inside one k=10 window, the daemon is not being shared —
   a bug, not a property of the traffic. Both were structurally dead before this capture existed.
4. **Populations stay separable.** Filter on `source`; never pool `devwork`, `research` and the
   6396 existing synthetic vectors. Pooling lets the largest and weakest population set the
   headline number, which is how the 0.0% false-positive figure survived as long as it did.

Then the measurement this is all for: **the false-positive rate on captured benign traffic
alone**, against Phase 7's synthetic 17.5%. That number decides whether R3 is deployable.
