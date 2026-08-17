# ChainWatch — ML-based sequential MCP firewall

Implementation of **arXiv:2607.19432v1**, *"ChainWatch: A Kill Chain-Aligned Sequential Detection
Framework for Multi-Step Attacks in MCP-Based AI Agent Systems"* (Narayan, Jyoti, Singh — 20 Jul
2026), running underneath [`mcpwall`](https://mcpwall.dev) in the MCP stdio chain.

This file describes the implemented behaviour: the specification as read, the four ambiguities in it
and how each was resolved, the parameters the paper leaves unspecified, and what has been measured.
It is written so that `chainwatch/engine/` can be ported to another language from this document
alone.

The executable contract is `tests/test_scenarios.py`, which encodes the paper's five §V-B scenarios
verbatim and asserts exact stage labels and exact rule/call pairs. Prose can drift; that file cannot.

Per-decision debugging history — 42 numbered notes cited from code comments and test docstrings —
lives in **`docs/development-notes.md`**. Full measurement detail is in **`GPT_GRID_RESULTS.md`**.

The paper is at <https://arxiv.org/abs/2607.19432>; §IV and §V are the implemented sections. Its
full text is not redistributed here — the arXiv perpetual non-exclusive licence grants arXiv that
right, not this repository.

---

## 1. Why this exists

`mcpwall` is a **per-call** filter — it inspects each `tools/call` against YAML rules, first match
wins, zero AI. It cannot see an attack where *every individual call is permitted* but the
**sequence** is malicious. STAC (paper ref [5], arXiv:2509.25624) reports **>90% attack success**
against GPT-4.1 using exactly that technique: decompose a malicious goal into individually-innocent
tool calls.

ChainWatch adds the missing layer: it models a session as a progression through a **six-stage kill
chain**, infers the stage of each call with a **Hidden Markov Model**, and fires **five
session-level rules** when the stage sequence looks like an attack.

The paper is explicitly a **design specification**, not a released system:

- §IV-A: *"this section does not document a system that is currently in operation."*
- §IV-C: transition matrix `A` is *"pending Baum-Welch estimation from labelled trace data."*
- No trained parameters are published anywhere in the paper.

So this repo does three things: implement the spec exactly, supply the priors the paper leaves
unspecified, and close the paper's own evaluation gap (§V-A: *"data that no existing benchmark
provides"*) using published agent-security benchmarks.

---

## 2. Locked decisions

| Decision | Choice | Why |
|---|---|---|
| Language | Python, numpy only | Readability is the explicit priority. No `hmmlearn` — see below. |
| Chain position | **Inner**: host → mcpwall → chainwatch → server | ChainWatch must see *raw* server output before mcpwall redacts it |
| Benchmark depth | Full replay harness | Only way to get all 20 dims live instead of 10 |
| Benign negative class | From published benchmark tasks, never self-authored | See the standing rule below |
| Cross-server state | Session daemon over Unix socket | Otherwise R2 and `DF.cross-server` are permanently dead |
| Training | Design-spec priors + Baum-Welch + trace capture | Paper publishes no parameters |

**Why inner, not outer.** All 7 Output Characteristics features (injection markers, encoded data,
external URL, volume anomaly) depend on unredacted server output. Running outside mcpwall would mean
observing `[REDACTED BY MCPWALL]` instead of the real payload. Inner placement also matches the
paper's adversary model (§III-A): per-call defenses filter first, ChainWatch only ever observes calls
that were *individually permitted*.

**Why not `hmmlearn`.** The 20-dim vector is mixed-type: TC is one-hot categorical, DF+OC are 11
binary flags, PS+TF are 4 continuous. `GaussianHMM` would force all 20 into a single Gaussian —
statistically wrong, and it would hide the structure that makes the model readable. Factored
emissions are ~200 lines.

**The standing rule on prompts.** Every task prompt used to generate traffic comes from published
research, never from this repository. Machine authorship is fine; *self*-authorship is
disqualifying, because a false-positive rate measured over tasks the defender selected tells you
about the selection. No script can detect a violation of this — it is a property of provenance, not
of argument content.

**Portability.** `chainwatch/engine/` is pure functions — no I/O, no MCP knowledge. Python stays
connected to mcpwall permanently via the stdio chain (language-agnostic pipes; one interpreter start
per *server launch*, not per call). A port would only need to move `engine/`.

---

## 3. Spec ambiguities found, and how they are resolved

Tracing §V-B's scenarios against §IV-D's rule definitions surfaced two internal inconsistencies in
the paper, and implementing recipient provenance surfaced two more. Each is resolved here; each has
a config flag so the literal reading stays reachable.

### A1 — R3's "high-stage READ"

§IV-D defines R3 as *"a high-stage READ followed within `m` steps by a NETWORK call carrying that
data."* That holds for S2 (`read_file` @ Stage 4) and S5 (`read_env` @ Stage 4). It **fails for S1**,
where the only READs are `get_balance` @ Stage 1 and `list_payees` @ Stage 2 — yet §V-B states
*"R3 would fire at call 4."*

**Resolution:** "high-stage" qualifies the **NETWORK** call, not the READ. R3 fires when a NETWORK
call at stage ≥ `r3_network_stage_min` (default **5**) carries `DF.chained` data traceable to any
READ within `m` steps. This satisfies S1, S2, and S5 simultaneously. Config `r3_read_stage_min`
(default **1** = any) restores the strict literal reading.

### A2 — S3's severity

§IV-D assigns R4 → WARNING. But §V-B's S3 says *"R4 would fire on the three-stage jump. A CRITICAL
alert would be raised."* Under §IV-D, R4 alone cannot produce CRITICAL.

**Resolution:** `redirect_all_messages` is a chained NETWORK call at Stage 6, so **R3 also fires**,
which legitimately yields CRITICAL. Severities follow §IV-D's table (R4 = WARNING); S3 is asserted to
produce `{R4: WARNING, R3: CRITICAL}`.

### A3 — R3 does not bind the chained data to the READ

§IV-D says R3 fires on *"a high-stage READ followed within `m` steps by a NETWORK call carrying
**that** data."* "That data" binds the payload to the READ. `rules.py` does not bind them: it tests
`current.chained` and, separately, looks for any READ in the lookback.

**This cannot be tightened.** In S1 the exfiltrated IBAN comes from `add_payee`'s **WRITE** response
— neither `get_balance` nor `list_payees` ever produced it. Bind the two and R3 stops firing on S1,
contradicting §V-B's *"R3 would fire at call 4"*. The loose reading is forced by the paper's own
scenario, exactly as A1 was. No config flag, because the strict reading is not reachable at all.

**Measured, not argued.** Every remembered output token carries the `ToolCategory` that produced it
(`SessionState.output_tokens` is `(text, category)`), so the question is answerable:

| population | chained calls | READ-sourced | WRITE-sourced | NETWORK-sourced |
|---|---|---|---|---|
| attack / agentlab | 152 | 85.5% | 14.5% | 0% |
| attack / shade (real) | 10 | 10.0% | 0% | **90.0%** |
| benign / shade (real) | 10 | 10.0% | 0% | **90.0%** |

The synthetic corpus mostly matches the paper's premise. **Real agent trajectories do not**: 90% of
the data R3 sees leaving came from a prior *NETWORK* response — an agent quoting an earlier email
thread back into a reply. Consequence: since nearly every session has a READ within `m=5`, R3 in
practice reduces to **"NETWORK at stage ≥ 5 whose arguments echo any prior response."**

### A4 — §IV-D has no concept of a recipient

Not an inconsistency in the paper; an absence. R3 keys on the *shape* of an act — read something,
send something — and that shape is equally an assistant doing its job. Nothing in §IV-D asks **who
the data is going to**.

**Resolution:** a sidecar, never a feature dimension. `features.Provenance` classifies a NETWORK
call's destination by first sighting — `ATTESTED` (named by a clean READ response before the session
referenced it), `INTRODUCED` (the session put it there), `UNATTESTED` (never seen), `UNKNOWN` (no
destination extractable → fail closed). It rides on `CallRecord`, the HMM never sees it, and the
20-dim vector in §5 is untouched.

`RuleConfig.r3_attested_action` defaults operationally to **`"downgrade"`**: an R3 match to an
ATTESTED destination remains visible as WARNING but does not block. Explicit `"ignore"` preserves the
paper-literal §IV-D behaviour; `"suppress"` drops the alert. Provenance may only ever lower a
severity, so enabling it can cost blocking but can never invent an alert. The operational default is
measurement-driven: on archived AgentDojo GPT-4o-mini sessions, paper-literal `"ignore"` blocked 3/9
benign sessions while `"downgrade"` blocked 1/9, and both blocked 16/33 attack-labelled sessions.

`tests/test_scenarios.py::test_provenance_never_changes_a_paper_scenario` runs all five §V-B
scenarios under all three settings and asserts identical stages, rule/call pairs, severity and block
point — 15 cases. No scenario sends to a recipient the environment attested, so the setting is inert
there by construction, and that test is what makes "by construction" checked rather than argued.

---

## 4. The six-stage MCP kill chain (§III-C, Table I)

| # | Stage | Key observable features |
|---|---|---|
| 1 | Reconnaissance | `tools/list` calls, sparse params, rapid tool sampling |
| 2 | Trust Building | benign patterns, low sensitivity, no cross-server calls |
| 3 | Injection | instruction text in outputs, XML tags, description mismatch |
| 4 | Escalation | READ→WRITE transitions, rising sensitivity, chained data |
| 5 | Lateral Movement | cross-server calls, `.mcp.json` edits, agent spawning |
| 6 | Exfiltration | READ→NETWORK chain, communication tools carrying data |

Stages are numbered **1–6** in all code and logs (not 0-indexed) to match the paper.

---

## 5. The 20-dimensional feature vector (§IV-B, Table II)

`v = [TC, PS, DF, TF, OC] ∈ ℝ²⁰`. **Fixed index order — this is the contract between every module.**

| idx | group | dimension | type |
|---|---|---|---|
| 0 | TC | READ | one-hot |
| 1 | TC | WRITE | one-hot |
| 2 | TC | EXECUTE | one-hot |
| 3 | TC | NETWORK | one-hot |
| 4 | TC | CONFIGURE | one-hot |
| 5 | PS | parameter sensitivity (credentials, paths, URLs, encoded data) | continuous [0,1] |
| 6 | DF | internal-read | binary |
| 7 | DF | external-write | binary |
| 8 | DF | chained | binary |
| 9 | DF | cross-server | binary |
| 10 | TF | inter-call interval (log-scaled) | continuous |
| 11 | TF | call rate over window k | continuous |
| 12 | TF | session age (seconds) | continuous |
| 13 | OC | imperative text in output | binary |
| 14 | OC | XML tags in output | binary |
| 15 | OC | description–output mismatch | binary |
| 16 | OC | volume anomaly | binary |
| 17 | OC | tool definition hash change | binary |
| 18 | OC | encoded data in output | binary |
| 19 | OC | external URL in output | binary |

Invariants enforced by `tests/test_features.py`: length is exactly 20; `v[0:5]` sums to 1;
`v[6:10]` and `v[13:20]` ∈ {0,1}; `v[5]` ∈ [0,1].

Notes:

- **idx 8 `chained`** — set when a current argument value contains a span originating from an earlier
  *response*. Requires a rolling store of prior output substrings.
- **idx 9 `cross-server`** — requires the daemon, and requires that the deployment declare more than
  one server. Under a one-server-per-session topology this dim is permanently 0 and R2 is dead.
- **idx 17 `hash change`** — SHA-256 of each `tools/list` definition; flagged when a tool name's hash
  changes mid-session. This is the rug-pull detector S3 depends on.
- **Two-phase extraction.** Rules must block *before* a call runs, but OC describes its *response*.
  So `FeatureExtractor.extract()` runs pre-flight (OC zero except `hash change`, which is already
  known from `tools/list`), and `patch_output_characteristics()` rewrites dims 13–19 afterwards.
  The pre-flight vector's TC/PS/DF/TF stay authoritative — re-extracting wholesale would corrupt the
  temporal group, since `commit()` has by then advanced `last_timestamp` to the current call.
- **Blocked calls are never committed.** A call that did not execute must not enter the timeline that
  later calls are judged against (`tests/test_scenarios.py::test_s4_blocked_call_is_not_committed…`).
- **PS** reuses mcpwall's own secret regex corpus (13 patterns: AWS, GitHub, OpenAI, Anthropic,
  Stripe, JWT, Slack, private-key header, DB URLs) read from the installed `mcpwall` package's
  `rules/default.yml`, so the two layers agree on what "a secret" means.

---

## 6. HMM stage classifier (§IV-C)

`λ = (S, Σ, A, B, π)`, `|S| = 6`, observations in ℝ²⁰. Adapts Holgado et al. [13] by replacing
discrete IDS alert types with continuous 20-dim vectors.

**Factored emissions** (24 params per state):

```
log b_s(v) = log Cat₅(TC) + log N(PS) + Σ log Bern(DF) + Σ log N(TF) + Σ log Bern(OC)
```

**Prior `A`** is generated by rule from §IV-C's three stated constraints — forward transitions more
probable than backward; jumps of more than two stages unlikely (consistent with documented 4–7 call
spans); small backward probabilities retained because attackers repeat earlier behaviour:

```
self 0.35 | +1 0.35 | +2 0.15 | +3 or more 0.02 total | backward 0.05 spread | row-normalized
π = [0.60, 0.25, 0.05, 0.05, 0.03, 0.02]     # sessions start at Reconnaissance
```

Generating `A` from a rule rather than hardcoding 36 numbers keeps it auditable against the paper.
`chainwatch/models/prior.json` does not exist and never did: the priors are constructed in
`engine/model.py` rather than shipped as data, so there is nothing to keep in sync with this table.

**Decoding:** online Viterbi over the sliding window, entirely in log-space.

**Prior sensitivity.** Priors perturbed multiplicatively (TC/DF/OC probabilities and PS means, 40
trials each) to check the §V-B labels do not rest on knife-edge tuning:

| noise | scenario sets fully correct | first to break |
|---|---|---|
| ±2% | 40/40 | — |
| ±5% | 40/40 | — |
| ±10% | 30/40 | S5 |
| ±15% | 25/40 | S5, then S3 |
| ±20% | 17/40 | S5, S3 |

S5 is the fragile one, as expected: it is the only scenario requiring a **three-stage jump** (1→4),
the transition class §IV-C explicitly calls unlikely.

---

## 7. Sequential Pattern Analyzer (§IV-D)

Window `k = 10` (chosen to exceed the documented 4–7 call attack spans), step threshold `m = 5`.
Both configurable.

| Rule | Condition | Severity | Blocks |
|---|---|---|---|
| R1 | Stage 1 (Recon) directly followed by sensitive data access (PS ≥ τ) | WARNING | no |
| R2 | ≥2 distinct servers in window with sensitive DF flags active | WARNING | no |
| R3 | NETWORK call, stage ≥ 5, `DF.chained`, READ within `m` steps (see A1) | **CRITICAL** | **yes** |
| R4 | `stage(t) − stage(t−1) ≥ 2` | WARNING | no |
| R5 | TC = CONFIGURE at stage ≥ 4 | **CRITICAL** | **yes** |
| — | suspicious stage assignment (stage ≥ 3) | INFO | no |

CRITICAL blocks the pending call by returning a JSON-RPC error upstream to mcpwall, which forwards it
to the host.

**R2 is measured and fails its own pre-registered threshold** (§13). Under a per-app topology it
fires on **29.9% of benign sessions** against a threshold of 20% fixed before the capture. The rate
is conditional on how finely servers are declared: one server per suite puts it at 0.0%.

**R5 has no benign population anywhere in this project.** The published suites used for capture
expose no CONFIGURE tool, so R5 is structurally 0/0 there; the one legitimate population that did
exercise it is self-authored and therefore disqualified as evidence by §2's standing rule.
OpenAgentSafety was measured as a candidate source and rejected (§13).

---

## 8. Conformance gate — §V-B scenarios

`tests/test_scenarios.py` encodes all five scenarios from §V-B verbatim. **This test is the
operational definition of "follows the specification exactly."** It asserts exact stage labels *and*
exact rule/call pairs.

| Scenario | Class | Call sequence | Expected stages | Expected rules |
|---|---|---|---|---|
| S1 Financial Fraud | DSA | `get_balance` → `list_payees` → `add_payee` → `transfer_funds` | 1, 2, 4, 6 | R4 @ 3, R3 @ 4 → CRITICAL |
| S2 GitHub Data Heist | IIC | `list_repos` → `get_issue` → `read_file` → `create_PR` | 1, 3, 4, 6 | R3 @ 4 → CRITICAL |
| S3 WhatsApp Rug-Pull | HMSA | `send_message` → `get_fact` → `get_fact` → `redirect_all_messages` | 2, 2, 3, 6 | R4 (+R3, see A2) → CRITICAL |
| S4 Cross-Agent Escalation | HMSA | `read_workspace_config` → `execute_agent_task` → `write_mcp_config` | 1, 3, 5 | R5 immediate → CRITICAL + blocked |
| S5 Credential Harvest | DSA | `list_tools` → `read_env` → `read_ssh_config` → `post_to_webhook` | 1, 4, 4, 6 | R1 @ 2, R3 @ 4 → CRITICAL |

All five reproduce exactly from priors derived only from Table I, under all three settings of
`r3_attested_action`.

---

## 9. Architecture

```
MCP Host (Claude Code / Cursor)
   │ stdio JSON-RPC
   ▼
mcpwall            ← per-call rules (existing, unmodified)
   │ stdio JSON-RPC
   ▼
chainwatch proxy   ← observes, extracts features, blocks on CRITICAL
   │  unix socket  ──▶ chainwatch daemon (one HMM + one k=10 window, ALL servers)
   │ stdio JSON-RPC
   ▼
Real MCP server / benchmark env bridge
```

```
chainwatch/
  engine/           PURE — no I/O, no MCP knowledge, unit-testable alone
    taxonomy.py     tool name/schema → TC category; PS scoring weights
    features.py     → np.ndarray shape (20,)  [§5];  Provenance  [§3 A4]
    hmm.py          forward-backward, Viterbi, Baum-Welch, factored emissions
    model.py        builds prior A/B/π in code; save/load JSON
    rules.py        R1–R5 + RuleConfig (window k, step threshold m, r3_attested_action)
    session.py      sliding window k=10, step threshold m=5
    alerts.py       INFO / WARNING / CRITICAL, block decision
  proxy/            __main__.py (--server/--server-map/--observe-only/--label/--source/
                    --log-args/--model), interceptor.py (two-phase extraction; per-call
                    server resolution), jsonrpc.py (fail-open)
  daemon/           server.py (unix socket, one analyzer per session id), client.py
  capture/          openai_mcp.py — GPT-4o-mini executor: MCP JSON-RPC, tool loop, cost
  ml/               dataset.py, scorer.py (arms B–E), evaluate.py; optional [ml] extra
  models/           trained_full.json, trained_transitions.json
  audit.py          JSON Lines trace writer; pure build_trace_line
  cli.py            check / daemon / train / ml-train / ml-eval; bare argv falls through
                    to the proxy, which is what makes an MCP config entry work

benchmark_bridge/   AgentLAB replay, plus the SHADE_Arena and Agent_SafetyBench material
                    vendored inside that checkout. agentlab_replay.py and
                    agentlab_benign_gen.py are AgentLAB's; base.py, safetybench.py,
                    shade_arena.py, env_mcp_server.py and shade_solutions.py serve the rest.
agentdojo_bridge/   route E, OFFICE domain: adapter.py (published utility()/security(),
                    UNSCORABLE_INJECTION_TASKS, tool_functions()), payload.py (verbatim
                    important_instructions), env_mcp_server.py
                    (--suite/--inject/--user-task/--score-out),
                    topology.py (tool -> <suite>-<app>, from AgentDojo's own modules)
injecagent_bridge/  route F, DEV domain: loader.py (data/*.json only, src/ never imported),
                    adapter.py, env_mcp_server.py (--split/--variant/--case-index/--benign)

scripts/            capture drivers, recipe generators, and the offline measurement tools.
                    Every measurement quoted in this file or in GPT_GRID_RESULTS.md is
                    reproducible from one of these; each is unit-tested.
docs/               recipes (generated), fixture exclusions, traffic_recipes.md,
                    development-notes.md
tests/              461 collected; test_scenarios.py is the conformance gate
```

`engine/` deliberately knows nothing about MCP, sockets, or files. That keeps it unit-testable in
isolation and means a port to another language only has to move that directory.

---

## 10. Running it

```bash
python3 -m venv .venv && .venv/bin/pip install numpy pyyaml pytest   # one-time
.venv/bin/pytest tests/ -v                                          # test_scenarios.py is the gate

# dry-run a single call, mcpwall-style; exit 0 allow / 1 block / 2 error
.venv/bin/python -m chainwatch check --input '{"jsonrpc":"2.0","id":1,"method":"tools/call",...}'

.venv/bin/python -m chainwatch daemon      # cross-server state: needed for R2 and DF.cross-server

# capture real traffic as a labelled trace corpus (observe-only: never blocks)
export CHAINWATCH_SESSION=$(date +%s)      # one id shared by every proxied server
.venv/bin/python -m chainwatch --observe-only --label benign --source devwork \
    -- npx -y @modelcontextprotocol/server-filesystem ~/projects

.venv/bin/python -m benchmark_bridge.agentlab_replay --all     # legacy replay
.venv/bin/python -m chainwatch train --traces ~/.chainwatch/traces/*.jsonl --iters 50 \
    --out chainwatch/models/trained.json
```

### mcpwall integration (inner chain)

```json
{ "mcpServers": { "filesystem": { "command": "npx", "args": [
    "-y", "mcpwall", "--",
    "python", "-m", "chainwatch", "--",
    "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/projects"
]}}}
```

### Trace / audit log format

JSON Lines at `~/.chainwatch/logs/YYYY-MM-DD.jsonl`, mirroring mcpwall's convention so both layers
read with the same tooling. ISO-8601 UTC timestamps.

**One file, two readers.** A line carries the operational fields a human wants (`ts`, `severity`,
`blocked`) *and* the corpus fields the trainers need (`session`, `label`, `source`, `call`, `v`),
making it a superset consumable unchanged by `ml.dataset.load_sessions` and `cli._load_sequences` —
both group on `session`, sort on `call`, and skip any line whose `v` is not a list. A second writer
in a second format would only be a thing to keep in sync.
`tests/test_proxy.py::test_captured_file_is_readable_by_both_trace_consumers` asserts this rather
than trusting it.

```json
{"ts":"2026-07-29T21:29:48Z","session":"09adecbe2846","label":"benign","source":"devwork",
 "call":2,"server":"stub","tool":"post_to_webhook","stage":6,"severity":"CRITICAL",
 "rules":["R3","R4","STAGE"],"blocked":false,"prov":"ATTESTED",
 "v":[0,0,0,1,0,0.8,0,1,1,0,0.1164,0,0.1164,0,0,0,0,0,0,0]}
```

**Two writers, not one, and they must stay in step.** The live proxy writes through
`chainwatch/audit.py`; the replay harness has its own writer in
`benchmark_bridge/agentlab_replay.py` (`write_traces`), because a replayed chain has no wall-clock
timing and no server process to attribute. Both emit the schema above. That duplication is why a
field present in one corpus can be absent from the other — which is what happened with `prov`.

- **`label` is asserted, never inferred.** `dataset.build` treats any label that is not `"attack"` as
  benign, so an unlabelled session would quietly become a benign training example. The proxy
  therefore refuses to start logging without `--label benign|attack`; pass `--no-log` to opt out.
- **`source`** keeps populations separable. Live capture defaults to `live`; each capture route tags
  itself.
- **`prov`** is the destination's provenance (§3, A4). It is `UNKNOWN` on any call with no
  extractable destination — most of them — so its absence and its fail-closed value are deliberately
  the same column downstream.
- **`model`** is the executor model — an explicit `null` when unasserted, since an absent key is
  indistinguishable from a reader that never looked.
- **`args` is omitted by default.** Training reads only `v`, and real arguments carry the contents of
  real files. `--log-args` restores them, still redacted on block as mcpwall does. Only routes whose
  arguments are benchmark fixture data rather than anybody's files enable it.
- **`blocked` means the call was actually stopped**, which is not the same as a CRITICAL rule firing
  — an observe-only proxy forwards it anyway. The rule-level fact lives in `severity` and `rules`,
  leaving this field free to carry the operational truth. Conflating the two would have made an
  observe-only corpus report blocks that never happened.
- **Recording phase is forced by correctness.** Forwarded calls are recorded on the *response*, the
  only point where OC dims 13–19 are real; a call blocked while enforcing is recorded from the
  request side, since no response will ever come and omitting it would erase R3 and R5 from the
  corpus — CRITICAL being exactly what blocks.
- **Session scoping.** `CHAINWATCH_SESSION` groups several proxied servers into one session id, which
  matters because with the daemon they share one k=10 window. Without it each proxy process gets its
  own uuid4 prefix.

---

## 11. Environment facts, and what the deployment cannot see

- `mcpwall` ships a single bundled ESM CLI and has **no plugin or hook API** — stdio chaining is the
  only supported seam. Only `tools/call` is inspected; all other JSON-RPC methods pass through.
- **Transport determines proxyability.** stdio servers (`npx …`) can be wrapped. An HTTP-transport
  MCP server has no stdio pipe and needs `npx mcp-remote <url>` in front of it. Remote connectors
  that execute on a vendor's side — hosted Gmail, Calendar and Drive integrations — never reach this
  machine at all, so no local proxy can observe them. A hard limit, not a gap to close.
- **`WebSearch` and `WebFetch` are native agent tools, not MCP.** They produce no ChainWatch-visible
  traffic. Web search is only observable through an MCP search server bridged to stdio.
- **There is nothing to mine retroactively.** Across 14 local agent transcripts, 532 recorded tool
  calls were Bash/Edit/Read/Write and **0 were MCP**. Capture requires deliberately routing an agent
  through wrapped servers; merely running a proxy yields nothing.
- **`--mcp-config` is additive, not a replacement.** A capture session sees the host's other
  configured servers *alongside* the wrapped ones, so an agent can reach an unproxied server and
  produce no trace. `--strict-mcp-config` is the structural fix; denying tools by name in a settings
  file is the fallback, and `--settings` merges with the user's settings rather than replacing them.
- Developed against Python 3.12, numpy 2.5, pytest 9.1.

### Vendored benchmarks

None of these is redistributed here; all are gitignored. Clone them yourself to use the capture and
replay routes:

| directory | source | how it is used |
|---|---|---|
| `agentdojo/` | Debenedetti et al., NeurIPS 2024 D&B | editable install; imported only from `agentdojo_bridge/` |
| `InjecAgent/` | Zhan et al., ACL 2024 | **data only** — `data/*.json` read, `src/` never imported |
| `AgentLAB/` | TanqiuJiang/AgentLAB | 200 verified attack chains; contains SHADE_Arena and Agent_SafetyBench |
| `OpenAgentSafety/` | 357 tasks, MIT | gate input only; measured and rejected, no bridge built |

Without them, five modules fail or skip (`test_agentdojo_bridge`, `test_injecagent_bridge`,
`test_recipe_generators`, `test_capture_drivers`, `test_injection_payloads`); the other **379 tests
pass on numpy + pyyaml alone**. That is exactly what CI runs.

---

## 12. Status

| Phase | State | Tests |
|---|---|---|
| 1. Feature Extraction Layer | ✅ done | 104 |
| 2. HMM stage classifier | ✅ done | 22 |
| 3. Pattern Analyzer + S1–S5 gate | ✅ done | 40 |
| 4. Proxy + daemon | ✅ done | 43 |
| 5. Benchmark replay harness | ✅ done | — |
| 6. Train + evaluate | ✅ done | — |
| 7. Real benign corpus (SHADE task pairs) | ✅ done | — |
| 8. XGBoost five-arm comparison | ✅ done | 33 |
| 9–10. Live trace capture + capture profiles | ✅ done | (in phase 4) |
| 11. Business-ops capture | 🔧 exploratory only — self-authored prompts, disqualified as evidence | 13 |
| 13. Recipient provenance for R3 (§3, A4) | ✅ done — halves benign blocks; detection unchanged | 30 |
| 14. R3′ gate | ✅ measured; **void, not passed** — deferred | 22 |
| 15–16. Live attack half via the user-prompt channel | ❌ **unpurchasable** — 80–100% refusal | 6 |
| 17. Indirect injection: route E (AgentDojo) + route F (InjecAgent) | ✅ bridges gated | 25 |
| 18. Injection-stage observability audit | ✅ done | 12 |
| 19. Grid readiness: manifest, resume/dedupe, native join, task-grouped folds | ✅ done | 35 |
| 20. The v2 GPT-4o-mini grid | ✅ AgentDojo 452/452 | 7 |
| 21. Per-call server topology → **R2 measurable** | ✅ v3 grid 452/452; dim 9 non-zero at last | 11 |
| 22. OpenAgentSafety decidability gate (R5's missing population) | ✅ **measured and rejected** | 7 |

**461 tests collected**; the full suite passes **460 with 1 skipped** — the held-out payload family,
deselected by `tests/conftest.py` and run explicitly with `-m holdout` so rules cannot be iterated
against it. `tests/test_ml.py` skips itself without the `[ml]` extra.

---

## 13. What has been measured

Full detail in **`GPT_GRID_RESULTS.md`**. Two grids exist; **they are never pooled**, because each is
a fresh set of Bernoulli draws rather than a rescoring of the other.

### The v3 grid — the primary result

Model `gpt-4o-mini-2024-07-18`, pinned and verified per response. **452/452 coordinates, 0
duplicated, 0 quarantined, 1924 calls, $0.4417.** Both classes come off **one generator** — same
published task, same executor, same environment, same system prompt, differing only by whether the
injection payload is served. That is what makes the arms below something other than a leak.

Two denominators, both required:

| | native-valid — *attacks that worked* | all-attempts — *injected environments* |
|---|---|---|
| attack sessions | 76 (published `security()`) | 355 |
| **detected** | **74/76 = 97.4%** | 39.4% |
| benign false positives | 4/38 = 10.5% (completed task) | 7.2% |

Native attack success rate is **21.4%**. The gap between columns is sessions where the model refused;
reporting only the second understates detection, reporting only the first hides that most served
injections never became attacks. **Report both.**

Per suite, **every missed successful attack is `slack`** — 2 of them on v3, 8 on v2, the same
invariant across two independent draws. Both v3 misses are one injection task whose failing R3
conjunct is dim 8, because `URL_RE` requires a scheme and the phishing link in that payload has none.

### Per rule, under a per-app topology

| | attack (n=355) | benign (n=97) |
|---|---|---|
| **R2** | **41.1%** | **29.9%** |
| R1 / R3 / R4 | 12.7 / 41.1 / 58.9% | 11.3 / 17.5 / 25.8% |
| R5 | **0%** | **0%** |

R2's threshold was written before capture: *R2 on ≥20% of benign sessions makes it a false-positive
engine on legitimate multi-service work.* Measured **29.9%** — §VI of the paper predicts it. Cost
isolated inside the same sessions: 10.3% of benign sessions fire R2 *and nothing else*, against 4.5%
of attack sessions. **R2 buys 4.5 points of attack coverage for 10.3 points of benign noise.**

**The rate is conditional on the declared topology and any claim must say so.** One server per suite
puts R2 at 0.0% in both classes; a finer split raises it. Supportable: *"R2 fires on 29.9% of benign
sessions under a three-app workspace topology"* — never *"R2 has a 29.9% false-positive rate"*. Rate
is a property of rule **and** deployment shape.

R2 is WARNING, so it contributed nothing to any detection or blocking figure above.

### The supervised arms

B/C/D/E are one XGBoost (`max_depth=3, n_estimators=120, learning_rate=0.08`) over different feature
groups; **A is the rule engine itself**, a hard predicate. Pinned to arm A's detection, native-valid:

| arm | detection | FP | AUC | leave-one-environment-out FP |
|---|---|---|---|---|
| A rules | 91.8% | 17.6% | — | — |
| B current+window | 93.2% | **0.0%** | 0.997 | 5.9% |
| C hmm+rules | 91.8% | 23.5% | 0.928 | 29.4% |
| D everything | 91.8% | **0.0%** | 0.998 | 5.9% |
| E current only | 94.5% | **32.4%** | 0.876 | **70.6%** |
| permutation floor | | | **0.478** | |

1. **Arm E's collapse is the evidence against a leak.** A greedy depth-3 learner finds a per-call
   shortcut immediately when one exists. Here the per-call arm is the *worst*, and only the window
   features rescue it. The signal is sequential — ChainWatch's own thesis, supported by data.
2. **C is dominated by A** while holding strictly more information: same detection, more false
   positives. The HMM posteriors and rule firings compress worse than the window aggregates beneath
   them and add nothing on top of them.
3. **Inverting the pin changes the verdict.** Pinning detection and reading false positives cannot
   say whether a learned model detects *more*. Fixing the false-positive budget instead, at arm A's
   CRITICAL budget of 10.5%, **B and D detect 76/76 against the rule engine's 74/76** — arm A
   dominated on both axes. But B flags 91.0% of all-attempts sessions, of which only 76 succeeded, so
   **≥247 of its positives are refusals**: B recognises that *an injection was served*, not that the
   agent was subverted. Real signal, about the environment rather than the trajectory.
4. **A remains the deployable artifact** — no training data, no drift exposure. The arms are an upper
   bound on extractable signal, not a shipping recommendation.

### Per-call latency

**3.9 ms per call at p50, 50 ms at p99, 85 ms max**, over real transcript responses. The Viterbi
decode is the largest single stage (610 µs; `complete` re-decodes, so §IV-C costs 1.53 ms of the
5.20 ms mean), and a one-row XGBoost `predict_proba` is 1.1 ms of wrapper overhead — so swapping the
decoder for a booster is lateral, and arms C/D are strictly +23%. The largest component is neither:
**40% is provenance and output-token bookkeeping**. Cost grows **1.9×** from call 1–2 to call 6+,
since the window and the remembered-span store both only grow.

### Route F (InjecAgent): unavailable, not zero

117 sessions, **0/78 native attack success** (95% bound ≤3.8%), **1.00 calls on every session**, no
rule fired in either class. All 78 read the payload and reported it back as data with zero refusal
language — the model never declined because it never treated a tool response as an instruction. A
one-call session cannot satisfy R3 or R5, so its 0% benign rate is a floor over content the
deployment never sees. The published harness uses a ReAct text stream while this executor uses the
Chat Completions `tool` role, so the honest claim is **"0/78 under tool-role delivery"**, never
"gpt-4o-mini is immune to InjecAgent".

### Injection-stage detector floors

Regression floors. **These are floors, not results — do not weaken them.**

| corpus response family | injection signal |
|---|---:|
| AgentDojo `important_instructions` attack payloads | **27/27** |
| InjecAgent `base` attack responses | **0/186** |
| InjecAgent `enhanced` attack responses | **186/186** |
| InjecAgent benign twins, `base` / `enhanced` | **0/186 / 0/186** |

**One limit on the 27/27, recorded because it cannot be undone.** `tests/test_features.py` carries
AgentDojo's payload verbatim as dim 13's unit fixture, written as the failing test. The phrasing was
therefore in the development loop before the holdout was ever spent: 27/27 is real but is **not** a
clean generalisation measurement, and no write-up may claim the rules were developed against
InjecAgent alone.

### Legacy regression — reported separately, never pooled

The AgentLAB replay (200 static attack chains plus two synthesized benign populations) predates the
current primary populations, and its benign class was generated separately from its attack class —
precisely the defect §14 describes. Under the current operational default it produces attack
detection 47.5% / blocking 39.0%, and benign-realism detection/blocking 19.0% / 9.0%.

**An earlier revision of this project published 0.0% false positives for that benign class. That
number was an artifact and is retracted.** It was measured against a benign class that never chained
a read into an outbound call — R3's signature — so 0.0% was guaranteed before anything ran. See
`docs/development-notes.md`, "Phase 7".

---

## 14. Limits

- **One executor, one payload family, one benchmark.** Leave-one-environment-out holds all three
  constant. Nothing here supports a claim about other models or other injection styles.
- **Every grid cell is a single Bernoulli draw.** Read 89.0% (v2) and 97.4% (v3) as two draws from
  one rate at n≈75, not as an improvement. Detection and false positives rose *together* between the
  grids, which is the signature of resampling rather than of a change. Replication, not more
  coordinates, is the next cheap measurement.
- **The benign class under-completes.** 38 of 97 benign sessions achieved `utility`, so the
  false-positive rate is measured partly over sessions that did little.
- **The 27/27 injection-detector figure is partly in-sample**, as recorded above.
- **R2's rate is a property of rule and topology together**, not of the rule.
- **R5 has never been measured against legitimate traffic** from a source that passes §2's standing
  rule. The gap is open and labelled.
- **A signal can be sound as a rule and poisoned as a feature.** Provenance is load-bearing in the
  rule engine, where it is compared against a session's own history, and was 83.6% of one arm's
  importance while improving nothing — the signature of a leak.
  `tests/test_ml.py::test_no_feature_correlates_with_session_length` asserts correlation, not range,
  because asserting a feature's range proves nothing.

---

## 15. Out of scope

- Modifying mcpwall (no plugin API; chaining is the only seam).
- Running any benchmark's *attack generation* (needs vLLM + GPU + API keys). Only already-verified
  chains and published payloads are replayed.
- Jailbreak framing to obtain an attack population through the user-prompt channel. That is what §2's
  standing rule forbids, and it is why routes E and F attack the data channel instead.

---

## 16. Development notes

42 numbered notes record decisions that cost real debugging — each a wrong turn some test or
measurement caught. **Numbers are permanent**: code comments and test docstrings cite them, and a
retracted note keeps its index. The index, and the still-binding notes in full, are in
**`docs/development-notes.md`**.

Three constrain code directly and are repeated here so nothing violates them:

- **Note 28** — `ToolCategory.READ` and `Provenance.UNKNOWN` are both `IntEnum` 0, so every
  optional-enum comparison uses `is not None`, never truthiness.
- **Note 22** — PS's lexical arm scores a *search* for "IBAN" as high as a transfer to one.
  Unchanged, because it feeds the §V-B gate.
- **Note 34** — `fixture_audit.py` cannot tell a report about a planted entity from a payment to one.
  Unchanged, same reason.
