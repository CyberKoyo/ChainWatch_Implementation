# ChainWatch Agent Guide

This file is the agent-facing companion to `CLAUDE.md`. It exists so coding agents
that do not automatically load Claude-specific instructions still receive the
project's architectural and experimental constraints.

> If this file and `CLAUDE.md` disagree, `CLAUDE.md` wins. Update this file after
> updating `CLAUDE.md`. Before making a substantial ChainWatch change, read
> `CLAUDE.md` in its entirety; it is the authoritative living specification and
> contains the measurements and failed approaches behind these rules.

## Purpose and threat model

ChainWatch is an ML-based sequential firewall for Model Context Protocol traffic.
It detects multi-call attack trajectories that individual call allow/deny checks
miss: reconnaissance, credential access, collection, exfiltration, persistence, and
other kill-chain-shaped behavior.

The paper/specification target is arXiv:2607.19432v1. The implementation combines:

- a fixed feature extractor;
- a six-state HMM stage classifier;
- five sequential rules, R1-R5;
- observe-only JSONL capture for training and evaluation;
- an optional supervised XGBoost comparison layer.

## Runtime architecture

The production and capture chain is:

```text
MCP host / capture runner
  -> mcpwall
    -> chainwatch
      -> MCP server
```

ChainWatch must remain inside `mcpwall`, immediately in front of the real MCP
server. That placement lets ChainWatch inspect raw server output before `mcpwall`
redacts or transforms it. Capture drivers must launch the same chain. Traffic sent
directly from a benchmark runner to its MCP server is not valid ChainWatch capture
data.

For fixture-backed Route E/F capture, run ChainWatch with:

```text
--observe-only --no-daemon --label benign|attack --source <population>
--model <resolved-model> --log-args -- <server command>
```

Observe-only is required because enforcing at the first CRITICAL call truncates the
trajectory being measured. No daemon is correct for these one-server-per-session
routes; cross-server state is structurally absent.

## Fixed 20-dimensional feature contract

Do not add, remove, reorder, or reinterpret HMM feature dimensions. Existing models,
traces, tests, and paper claims depend on this exact shape:

| Indices | Group | Meaning |
|---|---|---|
| 0-4 | TC | Tool category one-hot: READ, WRITE, EXECUTE, NETWORK, CONFIGURE |
| 5 | PS | Parameter sensitivity |
| 6-9 | DF | Internal read, external write, chained flow, cross-server flow |
| 10-12 | TF | Inter-call interval, call rate over window k, session age |
| 13-19 | OC | Imperative, XML, mismatch, volume, hash change, encoded, external URL |

Destination provenance is sidecar state on call records and trace rows. It is not a
21st HMM feature. The supervised XGBoost dataset may one-hot provenance separately,
but the HMM vector remains 20-dimensional.

The six HMM stages are Reconnaissance, Trust Building, Injection, Escalation, Lateral
Movement, and Exfiltration. R1-R5 reason over ordered calls and the sliding window;
do not replace sequential semantics with isolated-call checks.

## Trace contract

The audit log is append-only JSON Lines and doubles as the training corpus. A normal
captured call contains:

```text
ts, session, label, source, call, server, tool, stage, severity,
rules, blocked, prov, v, model
```

`args` is omitted by default. It is enabled only for controlled fixture routes such
as AgentDojo and InjecAgent. `label` is an operator assertion and is required when
logging; any downstream default would silently turn missing labels into benign
training claims. `source` is the population boundary. `blocked` records operational
truth: in observe-only mode a CRITICAL call is forwarded and therefore has
`blocked=false`.

`model` must identify the model that actually produced the tool decision. A capture
runner using an API alias must compare the API response's resolved model with the
requested model before forwarding its tool calls. A mismatch invalidates the
session; do not write a requested id as though it were resolved.

## XGBoost population discipline

The supervised experiment asks whether a learned model can reduce false positives
at matched rule-engine detection. It does not ask whether a flexible classifier can
memorize corpus generators.

Known corpus leaks include parameter sensitivity, provenance extractability,
session length/window occupancy, prompt generator, and executor/model identity.
Synthetic benign data produced by a different generator is not a valid negative
class, even when aggregate metrics look excellent.

Population selection in `chainwatch/ml/evaluate.py` is a source whitelist. The
`model` trace field is metadata and is not used by the selector. Consequently:

- existing Claude AgentDojo rows remain `source=agentdojo`;
- existing Claude InjecAgent rows remain `source=injecagent`;
- GPT-4o-mini AgentDojo rows use `source=agentdojo-gpt4omini`;
- GPT-4o-mini InjecAgent rows use `source=injecagent-gpt4omini`;
- each source receives its own `Populations` entry;
- Route E and Route F are reported separately;
- rows from different executors or models are never pooled merely because they use
  the same benchmark.

Do not add session length as an XGBoost feature. Temporal dimensions 10-12 are
excluded from supervised rows because replay speed describes the harness, not the
attack. Window features remain bounded by the rule window.

## Route E: AgentDojo

Route E uses published AgentDojo office-domain tasks. Benign and attack sessions
receive the same published user-task prompt. The only class difference is server-side
environment data: attack sessions fill injection vectors with AgentDojo's verbatim
`important_instructions` payload; benign sessions serve innocuous defaults.

Attack success comes from AgentDojo's native `security()`/trace-aware scorer. Utility
comes from its native utility scorer. Unscorable injection tasks and tasks incapable
of exercising the target NETWORK/CONFIGURE categories are excluded by the generated
recipe pipeline described in `CLAUDE.md`.

Keep both fired and resisted injections. A resisted injection can still produce a
complete benign trajectory. Absence of a score sidecar does not mean resistance; it
means the server did not reach EOF and the session is invalid.

## Route F: InjecAgent

Route F uses published InjecAgent developer-domain cases. Benign and attack sessions
receive the same published `User Instruction`. The user tool serves either the
published injected response or the same template with the
`<Attacker Instruction>` slot emptied.

Attacker tools must remain visible to the model; otherwise refusal is
indistinguishable from missing capability. Native attack success is whether an
attacker tool was called. Route F sessions are short by construction and must never
be pooled with Route E.

## OpenAI capture rules

The planned OpenAI executor uses pinned `gpt-4o-mini-2024-07-18` through Chat
Completions tool calling. It is a distinct executor population from Claude Code.
Record the executor id, system-prompt hash, max-turn limit, requested model, resolved
model, prompt/completion token usage, cached tokens, and estimated cost in sidecars.

Malformed JSON function arguments are returned to the model as a tool error so the
session can recover. Do not truncate and label such a session as quiet. Closing the
MCP client must close stdin and wait for the server so its scorer can write the
sidecar.

Capture each session into its own staging log. Publish rows into the XGBoost corpus
only when the executor ends as `completed` or at the configured `max_turns`, the MCP
chain exits successfully, the native score sidecar parses, and staged row count,
session, source, and model all match the executor result. Rename rejected staged
files away from `*.jsonl` globs while preserving them for diagnosis. Publish each
accepted session as its own atomic corpus file; never append a session piecemeal to a
shared daily log.

`OPENAI_API_KEY` is read from the parent process environment by the SDK. Never print
or persist it. Pass `mcpwall`, ChainWatch, and benchmark subprocesses an allowlisted
environment with a neutral HOME/cache; do not expose unrelated parent credentials.
Live API use requires explicit operator confirmation; unit tests use fake clients and
dry runs launch neither OpenAI nor `npx`.

**Never construct a capture chain without `--server`.** `build_mcpwall_chain_argv`
requires `server_name` and every driver passes it, because the proxy otherwise names
the server after the last argv token. See the limitations below.

## Known limitations of the OpenAI executor

`CLAUDE.md` §14 is authoritative and wins on any conflict; these are the same points.

- **The system prompt is authored in this repo** (`chainwatch/capture/openai_mcp.py`,
  `DEFAULT_SYSTEM_PROMPT`). It is byte-identical across both halves and its sha256 is
  written to every usage row, so it cannot carry a label — but the Claude routes run
  under Claude Code's own system prompt, so GPT and Claude sessions differ by executor
  and prompt and can never be compared. Report them apart, always.
- **`server` is the environment**, asserted rather than derived: route E writes its
  suite, route F the constant `injecagent-dev`. The old argv fallback read the
  score-file path on one half and `--benign` on the other, making `ml/dataset.py`'s
  leave-one-environment-out grouping unique-per-session on E and label-correlated on F.
  Same species as `win_occupancy`, PS and provenance.
- **Route F has one environment.** All 558 recipe rows drive a GitHub user tool, so
  leave-one-environment-out is unavailable there; route F carries the dev-domain signal
  only.
- **A rejected tool call is not a failed session.** `mcpwall` sits above ChainWatch and
  refuses by returning a JSON-RPC error, which never reaches the bridge and never
  produces a trace row. Count those as `rejected_calls`, feed them back to the model as
  a tool error, and keep them out of `calls` so the native sidecar, the executor count
  and the published row count stay equal.
- **The observed-spend budget cuts the recipe file at a prefix.** The grids are
  round-robined across environments so a prefix stays representative, and `--suite` /
  `--split` exist for topping one environment up.

## Development and verification

Use the project virtual environment:

```bash
.venv/bin/pytest -q
.venv/bin/python -m chainwatch --help
```

For capture work, verify at minimum:

- an argv test proves `mcpwall` precedes ChainWatch and ChainWatch precedes the
  benchmark server;
- MCP initialization, tool listing, calls, EOF, and score-sidecar creation work;
- dry-run output contains the pinned model and isolated source;
- zero captured calls exits nonzero;
- missing scorer sidecars are reported as failures;
- partial or metadata-mismatched traces remain outside the final corpus;
- GPT population selectors are disjoint from Claude and from each other;
- changed files contain no API keys or other credentials.

Run AgentDojo and InjecAgent evaluations separately. Never report a pooled E/F or
Claude/GPT number as though it measured one population.

## Do not do these

- Do not bypass `mcpwall` for captured data.
- Do not put ChainWatch outside `mcpwall`.
- Do not change the 20-dimensional HMM vector without an explicit spec revision and
  model migration.
- Do not hand-author Route E/F prompts or add jailbreak framing.
- Do not pool synthetic, route, model, or executor populations.
- Do not infer resistance from zero calls or a missing score sidecar.
- Do not trust a requested model id without checking the API response model.
- Do not execute live API traffic without explicit operator confirmation.
