# ChainWatch

[![tests](https://github.com/CyberKoyo/ChainWatch_Implementation/actions/workflows/tests.yml/badge.svg)](https://github.com/CyberKoyo/ChainWatch_Implementation/actions/workflows/tests.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Sequential, ML-based detection for multi-step MCP attacks — layered underneath
[`mcpwall`](https://mcpwall.dev).**

> **This README is the documentation.** [`CLAUDE.md`](CLAUDE.md) is the agent- and contributor-facing
> contract — feature indices, priors, invariants, commands — written to be loaded by a coding agent
> rather than read for its findings. Everything a person needs is here; full measurement detail is in
> [`GPT_GRID_RESULTS.md`](GPT_GRID_RESULTS.md).

An implementation of [arXiv:2607.19432v1](https://arxiv.org/abs/2607.19432), *"ChainWatch: A Kill
Chain-Aligned Sequential Detection Framework for Multi-Step Attacks in MCP-Based AI Agent Systems"*
(Narayan, Jyoti & Singh, 2026).

`mcpwall` inspects each tool call in isolation. That is the right design for blocking `rm -rf` or a
read of `~/.ssh/id_rsa` — and it is structurally blind to an attack where *every individual call is
permitted* but the **sequence** is malicious. STAC (the paper's ref [5]) achieves **>90% success**
against GPT-4.1 exactly that way: decompose a malicious goal into individually innocent tool calls.

ChainWatch watches the sequence.

```
get_balance  →  list_payees  →  add_payee  →  transfer_funds
   Stage 1       Stage 2        Stage 4        Stage 6
                               R4 WARNING     R3 CRITICAL → blocked
```

Every one of those four calls passes per-call inspection. The *shape* of the sequence is the attack.

---

## Infrastructure

### Process topology

ChainWatch is a transparent stdio proxy. It does not replace `mcpwall`; it sits **inside** it, so it
observes raw server output before `mcpwall` redacts secrets, and only ever sees calls that already
passed per-call inspection — matching the paper's adversary model (§III-A).

```
┌──────────────────────────────────────────────────────────────────────────┐
│  MCP Host   (Claude Code, Cursor, Windsurf)                              │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ stdio JSON-RPC
┌───────────────────────────────▼──────────────────────────────────────────┐
│  mcpwall            per-call YAML rules, secret redaction  [unmodified]  │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ stdio JSON-RPC
┌───────────────────────────────▼──────────────────────────────────────────┐
│  chainwatch proxy                                                        │
│    • extracts a 20-dim feature vector per call                           │
│    • asks the daemon for a stage label + rule verdict                    │
│    • blocks the pending call on CRITICAL, else forwards                  │
└──────┬────────────────────────┬──────────────────────────────────────────┘
       │ unix socket            │ stdio JSON-RPC
┌──────▼──────────────────┐  ┌──▼───────────────────────────────────────────┐
│  chainwatch daemon      │  │  Real MCP server  /  benchmark env bridge    │
│   one HMM               │  └──────────────────────────────────────────────┘
│   one k=10 window       │
│   shared by ALL servers │   ← this is what makes cross-server detection
└─────────────────────────┘     (rule R2, feature dim 9) actually work
```

One proxy process runs per MCP server, exactly as `mcpwall` does. The daemon exists because rule R2
("two or more servers accessed with sensitive data flow") and the `cross-server` feature dimension
are meaningless if each proxy only sees its own server. Proxies send feature vectors over
`~/.chainwatch/session.sock` and receive verdicts; if the daemon is unreachable the proxy degrades to
local-only state and says so on stderr.

### Detection pipeline

```
  raw JSON-RPC              ┌─────────────────────┐
  tools/call          ─────▶│ Feature Extraction  │  §IV-B, Table II
  tools/list                │      Layer          │
  responses                 └──────────┬──────────┘
                                       │  v ∈ ℝ²⁰
                            ┌──────────▼──────────┐
                            │ Kill Chain Stage    │  §IV-C
                            │ Classifier (HMM)    │  6 states, Viterbi
                            └──────────┬──────────┘
                                       │  stage ∈ 1..6
                            ┌──────────▼──────────┐
                            │ Sequential Pattern  │  §IV-D
                            │ Analyzer  R1..R5    │  window k=10, m=5
                            └──────────┬──────────┘
                                       │
                     INFO / WARNING / CRITICAL(+block)
```

### The 20-dimensional feature vector (§IV-B, Table II)

| dims | group | contents |
|---|---|---|
| 0–4 | **TC** Tool Category | one-hot: READ, WRITE, EXECUTE, NETWORK, CONFIGURE |
| 5 | **PS** Parameter Sensitivity | weighted sum over credentials, financial identifiers, paths, URLs, encoded data |
| 6–9 | **DF** Data Flow | internal-read, external-write, chained, cross-server |
| 10–12 | **TF** Temporal | inter-call interval, call rate over *k*, session age |
| 13–19 | **OC** Output Characteristics | imperative text, XML tags, desc–output mismatch, volume anomaly, tool-hash change, encoded data, external URL |

Because rules must block a call *before* it runs, extraction is two-phase: a pre-flight pass (OC
mostly zero, but `hash change` already known from `tools/list`) and a post-response pass that fills OC
in and updates session state for subsequent calls.

### Six-stage kill chain (§III-C, Table I)

| # | Stage | Observable signature |
|---|---|---|
| 1 | Reconnaissance | `tools/list`, sparse params, rapid sampling |
| 2 | Trust Building | benign patterns, low sensitivity, no cross-server |
| 3 | Injection | instruction text in outputs, XML tags, description mismatch |
| 4 | Escalation | READ→WRITE, rising sensitivity, chained data |
| 5 | Lateral Movement | cross-server calls, `.mcp.json` edits, agent spawning |
| 6 | Exfiltration | READ→NETWORK chain, comms tools carrying data |

### Detection rules (§IV-D)

| Rule | Fires when | Severity | Blocks |
|---|---|---|---|
| R1 | Reconnaissance directly followed by sensitive data access | WARNING | no |
| R2 | ≥2 servers accessed with sensitive data-flow flags | WARNING | no |
| R3 | NETWORK call at high stage carrying chained READ data | **CRITICAL** | **yes** |
| R4 | stage jumps ≥2 positions in one step | WARNING | no |
| R5 | CONFIGURE call at stage ≥4 | **CRITICAL** | **yes** |

Two of these have measured problems, reported below rather than papered over: **R2 fails its own
pre-registered false-positive threshold**, and **R5 has never been measured against legitimate
traffic**, because no published benchmark used here exposes a CONFIGURE tool.

---

## Repository layout

```
chainwatch/
  engine/              pure functions — no I/O, no MCP knowledge, portable
    taxonomy.py        tool name → Tool Category; parameter sensitivity scoring
    features.py        the 20-dim vector; two-phase extraction; session state; Provenance
    hmm.py             factored emissions, log-space forward/backward, Viterbi, Baum-Welch
    model.py           design-spec priors for A, B, pi — generated from §IV-C's constraints
    rules.py           R1–R5 and RuleConfig
    session.py         sliding window k=10, step threshold m=5
    alerts.py          severity + block decision
  proxy/               stdio JSON-RPC proxy; spawns the child server after `--`
  daemon/              unix-socket session daemon (cross-server state)
  capture/             pinned-model executor used for benchmark capture
  ml/                  the supervised comparison arms; optional [ml] extra
  models/              trained_full.json, trained_transitions.json
  audit.py             JSON Lines trace writer
  cli.py               check | daemon | train | ml-train | ml-eval
                       (bare argv falls through to the proxy)

benchmark_bridge/      AgentLAB replay, plus SHADE_Arena and Agent_SafetyBench adapters
agentdojo_bridge/      AgentDojo (office domain): published utility()/security(), verbatim
                       injection payloads, per-app server topology
injecagent_bridge/     InjecAgent (developer domain): data/*.json only, src/ never imported

scripts/               capture drivers, recipe generators, offline measurement tools
docs/                  development-notes.md, generated recipe files
tests/                 464 tests; test_scenarios.py is the conformance gate

CLAUDE.md                    the specification: ambiguities, priors, rules, measurements
GPT_GRID_RESULTS.md          full measurement detail
docs/development-notes.md    42 numbered notes, cited by number from code comments
```

`engine/` deliberately knows nothing about MCP, sockets, or files. That keeps it unit-testable in
isolation and means a port to another language only has to move that directory.

---

## Why the priors exist

The paper is a **design specification**, not a released system. §IV-A: *"this section does not
document a system that is currently in operation."* §IV-C: the transition matrix is *"pending
Baum-Welch estimation from labelled trace data."* No parameters are published.

So `model.py` generates `A` from the three constraints the paper *does* state (forward > backward,
jumps >2 unlikely, backward mass retained) rather than hardcoding 36 opaque numbers, and derives `B`
from Table I's observable-features column. Every value is a prior meant to be replaced by
`chainwatch train` once real traces exist.

**These priors reproduce all five of the paper's §V-B scenarios exactly** — exact stage labels and
exact rule/call pairs — and the labels survive ±5% perturbation of every prior across 40/40 trials:

| Scenario | Call sequence | Expected stages | Expected rules |
|---|---|---|---|
| S1 Financial Fraud | `get_balance` → `list_payees` → `add_payee` → `transfer_funds` | 1, 2, 4, 6 | R4 @ 3, R3 @ 4 → CRITICAL |
| S2 GitHub Data Heist | `list_repos` → `get_issue` → `read_file` → `create_PR` | 1, 3, 4, 6 | R3 @ 4 → CRITICAL |
| S3 WhatsApp Rug-Pull | `send_message` → `get_fact` → `get_fact` → `redirect_all_messages` | 2, 2, 3, 6 | R4 + R3 → CRITICAL |
| S4 Cross-Agent Escalation | `read_workspace_config` → `execute_agent_task` → `write_mcp_config` | 1, 3, 5 | R5 immediate → CRITICAL + blocked |
| S5 Credential Harvest | `list_tools` → `read_env` → `read_ssh_config` → `post_to_webhook` | 1, 4, 4, 6 | R1 @ 2, R3 @ 4 → CRITICAL |

`tests/test_scenarios.py` encodes these verbatim and asserts exact stage labels *and* exact
rule/call pairs. It is the operational definition of "follows the specification", and it holds under
all three settings of the recipient-provenance policy described below.

Sensitivity is uneven and worth stating: at ±10% perturbation 30 of 40 trials still label every
scenario correctly, and **S5 is always the first to break** — it is the only scenario requiring a
three-stage jump, the transition class the paper itself calls unlikely.

---

## What the paper leaves ambiguous

Tracing the paper's own §V-B scenarios against its §IV-D rule definitions surfaced two internal
inconsistencies; implementing recipient provenance surfaced two more. Each resolution is forced by
the paper's own text rather than invented, and each is reachable in config so the literal reading
stays available.

**A1 — whose stage is "high"?** R3 is defined as *"a high-stage READ followed within m steps by a
NETWORK call carrying that data."* That reading holds for two of the paper's scenarios and fails for
a third, where the only READs sit at stages 1 and 2 — yet the paper states R3 fires there. So
"high-stage" must qualify the **NETWORK** call, not the READ. That satisfies all three at once.

**A2 — a severity the rule table cannot produce.** The paper assigns R4 a WARNING, then says its
rug-pull scenario raises a CRITICAL alert on an R4 firing. Resolved without touching the severity
table: the same call is a chained NETWORK call at stage 6, so R3 fires too, and R3 is CRITICAL.

**A3 — "that data" cannot be enforced.** R3's text binds the exfiltrated payload to the READ that
produced it. The implementation deliberately does not, because in the paper's own fraud scenario the
exfiltrated account number came from a *WRITE* response — bind them and R3 stops firing on a
scenario the paper says it fires on. The loose reading is forced. Measured consequence: on real
agent trajectories **90% of chained data came from a prior NETWORK response**, and since nearly every
session contains a READ within the window, R3 reduces in practice to *"an outbound call at high
stage whose arguments echo any earlier response."*

**A4 — the rules never ask who the data is going to.** Not an inconsistency, an absence. R3 keys on
the *shape* of an act — read something, send something — which is equally an assistant doing its
job. So destination provenance rides alongside as a sidecar, never as a feature: is this recipient
one that a clean response named, one the session introduced, or one never seen? It can only ever
lower a severity, never raise one, so it cannot invent an alert. It released 20 benign chains for
every 1 attack chain and changed detection not at all — **a precision mechanism, not a detection
one.**

The operative form of all four, with the config flags and the reasoning a reimplementation needs, is
in [`CLAUDE.md`](CLAUDE.md).

---

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install numpy pyyaml pytest

.venv/bin/pytest tests/ -v          # conformance gate lives in test_scenarios.py
```

Wrap a real server (ChainWatch inside mcpwall):

```json
{ "mcpServers": { "filesystem": { "command": "npx", "args": [
    "-y", "mcpwall", "--",
    "python", "-m", "chainwatch", "--",
    "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/projects"
]}}}
```

```bash
.venv/bin/python -m chainwatch daemon        # cross-server state; needed for R2 and dim 9
.venv/bin/python -m chainwatch check --input '{"jsonrpc":"2.0",...}'   # 0 allow / 1 block / 2 error
.venv/bin/python -m chainwatch train --traces ~/.chainwatch/traces/*.jsonl --iters 50
```

### Vendored benchmarks

The capture and replay routes read benchmark checkouts that are **not redistributed here** and are
gitignored. Clone them into the repo root yourself if you want those routes:

| directory | source | how it is used |
|---|---|---|
| `agentdojo/` | [AgentDojo](https://github.com/ethz-spylab/agentdojo) (Debenedetti et al., NeurIPS 2024) | editable install; imported only from `agentdojo_bridge/` |
| `InjecAgent/` | [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) (Zhan et al., ACL 2024) | **data only** — `data/*.json` read, `src/` never imported |
| `AgentLAB/` | [AgentLAB](https://github.com/TanqiuJiang/AgentLAB) | 200 verified attack chains; contains SHADE_Arena and Agent_SafetyBench |

Without them five test modules fail or skip; **the other 382 tests pass on numpy + pyyaml alone**,
which is exactly what CI runs.

All three are MIT licensed. This repo reproduces verbatim task text from each in `docs/recipes_*`;
their copyright and permission notices are in [`NOTICE`](NOTICE), as MIT requires.

### What ChainWatch cannot see

Decisive if you are considering deploying it, and none of it is fixable from inside this project:

- **Remote connectors execute on the vendor's side.** Hosted Gmail, Calendar and Drive integrations
  never reach your machine, so no local proxy can observe them. A hard limit, not a gap to close.
- **HTTP-transport MCP servers have no stdio pipe.** They need `npx mcp-remote <url>` in front of
  them before anything can wrap them.
- **`WebSearch` and `WebFetch` are native agent tools, not MCP.** They produce no ChainWatch-visible
  traffic at all; web search is only observable through an MCP search server bridged to stdio.
- **`--mcp-config` adds servers, it does not replace them.** An agent can reach an unproxied server
  and produce no trace, so a session can look clean because it was never watched.
  `--strict-mcp-config` is the structural fix.

There is also nothing to mine retroactively: across 14 local agent transcripts, 532 recorded tool
calls were Bash/Edit/Read/Write and **zero were MCP**. Observation requires deliberately routing an
agent through wrapped servers.

---

## Results

The paper admits it has no data (§V-A: *"data that no existing benchmark provides"*). The primary
evidence here comes from **AgentDojo**, whose tasks, environments, injection payloads and scoring
functions are all published, run against a pinned `gpt-4o-mini-2024-07-18` executor.

**Both classes come off one generator** — same published task, same executor, same environment, same
system prompt, differing only by whether the injection payload is served into the environment's data.
That design exists because an earlier synthetic corpus leaked its label through argument content; see
`docs/development-notes.md`, "Phase 8".

452 of 452 coordinates captured; 1924 tool calls; total spend $0.4417.

### Two denominators, both required

| | native-valid — *attacks that worked* | all-attempts — *injected environments* |
|---|---|---|
| attack sessions | 76 (published `security()`) | 355 |
| **detected** | **74/76 = 97.4%** | 39.4% |
| benign false positives | 4/38 = 10.5% | 7.2% |

Native attack success rate is **21.4%** — most served injections never became attacks, because the
model refused. Reporting only the right column understates detection; reporting only the left hides
that the firewall also fires on attempts that went nowhere. **Both, always.**

Every missed successful attack is `slack` — 2 on this grid, 8 on the previous one, the same invariant
across two independent draws. Both current misses are one injection task whose failing R3 conjunct is
the `chained` dimension, because the URL pattern requires a scheme and that payload's phishing link
has none.

### Per rule

| | attack (n=355) | benign (n=97) |
|---|---|---|
| **R2** | **41.1%** | **29.9%** |
| R1 / R3 / R4 | 12.7 / 41.1 / 58.9% | 11.3 / 17.5 / 25.8% |
| R5 | **0%** | **0%** |

**R2 fails a threshold written before the capture ran** — *fire on ≥20% of benign sessions and it is a
false-positive engine on legitimate multi-service work*. Measured 29.9%. Isolated inside the same
sessions, 10.3% of benign sessions fire R2 *and nothing else*, against 4.5% of attack sessions: **R2
buys 4.5 points of attack coverage for 10.3 points of benign noise.**

That rate is a property of the rule **and the declared topology**. One MCP server per suite puts R2
at 0.0% in both classes; splitting a workspace into its email, calendar and drive apps raises it.
Supportable: *"R2 fires on 29.9% of benign sessions under a three-app workspace topology."* Not
supportable: *"R2 has a 29.9% false-positive rate."*

**R5 is 0/0 because the published suites expose no CONFIGURE tool at all.** A candidate source for
that missing population (OpenAgentSafety) was measured against a pre-registered threshold, failed it,
and no bridge was built. The gap is open and labelled rather than filled with weaker evidence.

### Rules versus learned models

Arms B–E are one XGBoost (`max_depth=3, n_estimators=120, learning_rate=0.08`) over different feature
groups; **arm A is the rule engine itself.** Pinned to arm A's detection, on the native-valid split:

| arm | detection | FP | AUC | leave-one-environment-out FP |
|---|---|---|---|---|
| A rules | 91.8% | 17.6% | — | — |
| B current + window | 93.2% | **0.0%** | 0.997 | 5.9% |
| C hmm + rules | 91.8% | 23.5% | 0.928 | 29.4% |
| D everything | 91.8% | **0.0%** | 0.998 | 5.9% |
| E current call only | 94.5% | **32.4%** | 0.876 | **70.6%** |
| permutation floor | | | **0.478** | |

**Arm E's collapse is the evidence against another leak.** A greedy depth-3 learner finds a per-call
shortcut immediately when one exists — in the earlier synthetic corpus it found one at a 121× gap.
Here the per-call arm is the *worst*, and only the window features rescue it. The signal is
sequential, which is this project's own thesis supported by data rather than assumed.

Arm C is dominated by arm A while holding strictly more information: the HMM posteriors and rule
firings compress worse than the window aggregates beneath them, and add nothing on top of them.

Inverting the pin — fixing the false-positive budget instead of the detection rate — changes the
headline: at arm A's CRITICAL budget, B and D detect 76/76 against the rule engine's 74/76. But B
also flags 91.0% of all-attempts sessions, of which only 76 succeeded, so **most of its positives are
refusals**. B recognises that *an injection was served*, not that the agent was subverted. Real
signal, about the environment rather than the trajectory.

**Arm A remains the deployable artifact**: no training data, no drift exposure. The arms are an upper
bound on extractable signal, not a shipping recommendation.

### Cost

**3.9 ms per call at p50, 50 ms at p99, 85 ms max.** The Viterbi decode is the largest single stage
(610 µs), but 40% of the total is provenance and output-token bookkeeping, and per-call cost grows
1.9× from the first calls of a session to the sixth and beyond, since the window and the
remembered-span store only grow.

### Legacy regression, reported separately

The AgentLAB replay (200 static attack chains against two synthesized benign populations) predates
the current primary corpus, and its two classes come off different generators. It is kept as a
regression diagnostic and **never pooled** with the results above: attack detection 47.5% / blocking
39.0%, benign detection/blocking 19.0% / 9.0%.

**An earlier revision of this README reported 0.0% false positives for that benign class. That number
was an artifact and is retracted** — it was measured against a benign class that never chained a
read's output into an outbound call, which is R3's entire signature, so 0.0% was guaranteed before
anything ran. The full account is in `docs/development-notes.md`, "Phase 7".

---

## Limitations

- **One executor, one payload family, one benchmark.** Leave-one-environment-out holds all three
  constant. Nothing here supports a claim about other models or other injection styles.
- **Every grid cell is a single Bernoulli draw.** The previous grid measured 89.0% detection and this
  one 97.4%; read them as two draws from one rate at n≈75, not as an improvement. Detection and false
  positives rose *together* between them, which is the signature of resampling.
- **The benign class under-completes**: 38 of 97 benign sessions achieved the published utility
  check, so the false-positive rate is measured partly over sessions that did little.
- **The injection-stage detector figure is partly in-sample.** The AgentDojo payload is a unit-test
  fixture in this repo, so its 27/27 detection rate is real but is not a clean generalisation
  measurement.
- **R3 as specified cannot separate exfiltration from an assistant doing its job.** Search files,
  then email what you found, is both. Recipient provenance narrows this; it does not close it.
- **The developer-domain route returned no attack population**: 0/78 native attack success under
  tool-role delivery, on one-call sessions that cannot satisfy R3 or R5 at all. Unavailable, not zero.

---

## Status

| Component | State |
|---|---|
| Feature extraction layer | complete, 104 tests |
| HMM stage classifier | complete, 22 tests |
| Sequential pattern analyzer + §V-B gate | complete, 40 tests |
| Proxy + daemon | complete, 43 tests |
| Benchmark bridges and capture | complete |
| Supervised comparison arms | complete |

**464 tests collected; 463 pass with 1 skipped** — a held-out payload family, deselected by default
so detection rules cannot be iterated against it, and run explicitly with `-m holdout`.

### Where things live

| document | audience | contents |
|---|---|---|
| **`README.md`** — this file | people | what it is, what it detects, what was measured, what the limits are |
| [`CLAUDE.md`](CLAUDE.md) | coding agents, contributors | the contract: 20-dim index order, priors, rule definitions, invariants, commands |
| [`GPT_GRID_RESULTS.md`](GPT_GRID_RESULTS.md) | anyone checking the numbers | every measurement in full, and how to reproduce it |
| [`docs/development-notes.md`](docs/development-notes.md) | contributors | 42 numbered notes — the wrong turns, and why several defects are still open |

## License

Apache-2.0, matching `mcpwall`. Not affiliated with the paper's authors, `mcpwall`, or Anthropic.

Third-party material derived from the benchmarks is attributed in [`NOTICE`](NOTICE).
