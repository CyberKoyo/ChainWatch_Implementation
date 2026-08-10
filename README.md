# ChainWatch

**Sequential, ML-based detection for multi-step MCP attacks — layered underneath [`mcpwall`](https://mcpwall.dev).**

An implementation of [arXiv:2607.19432v1](https://arxiv.org/html/2607.19432v1), *"ChainWatch: A Kill
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
│  chainwatch daemon      │  │  Real MCP server  /  AgentLAB env bridge     │
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

---

## Repository layout

```
chainwatch/
  engine/              pure functions — no I/O, no MCP knowledge, portable
    taxonomy.py        tool name → Tool Category; parameter sensitivity scoring
    features.py        the 20-dim vector; two-phase extraction; session state
    hmm.py             factored emissions, log-space forward/backward, Viterbi, Baum-Welch
    model.py           design-spec priors for A, B, pi — generated from §IV-C's constraints
    rules.py           R1–R5
    session.py         sliding window k=10, step threshold m=5
    alerts.py          severity + block decision
  proxy/               stdio JSON-RPC proxy; spawns the child server after `--`
  daemon/              unix-socket session daemon (cross-server state)
  models/prior.json    serialized priors
  cli.py               proxy | daemon | check | train | replay | eval | capture

benchmark_bridge/      bridges the vendored AgentLAB, SHADE, and SafetyBench data
  safetybench.py       Agent_SafetyBench adapter (BaseEnv subclass + paired .json schema)
  shade_arena.py       SHADE_Arena adapter (167 of the 200 chains)
  env_mcp_server.py    exposes an environment as a real MCP stdio server
  agentlab_replay.py   drives 200 verified AgentLAB attack chains through the full stack
  agentlab_benign_gen.py synthesizes the legacy matched benign negative class

tests/
  test_scenarios.py    the paper's five §V-B scenarios — the conformance gate
  test_features.py     20-dim contract, categories, sensitivity, OC detectors
  test_hmm.py          Viterbi vs brute force, EM monotonicity, prior constraints
  test_rules.py  test_proxy.py

CLAUDE.md              the living spec — authoritative when it and the code disagree
docs/paper.txt         local copy of the paper
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

**These priors reproduce all five of the paper's §V-B scenarios exactly** — see the conformance gate.

---

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install numpy pytest pyyaml

.venv/bin/pytest tests/ -v          # conformance gate lives in test_scenarios.py
```

Wrap a real server (ChainWatch inside mcpwall):

```json
{ "mcpServers": { "filesystem": { "command": "npx", "args": [
    "-y", "mcpwall", "--",
    "python", "-m", "chainwatch", "--",
    "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/you/projects"
]}}}
```

```bash
.venv/bin/python -m chainwatch daemon        # cross-server state; needed for R2
.venv/bin/python -m benchmark_bridge.agentlab_replay --all
.venv/bin/python -m chainwatch train --traces ~/.chainwatch/traces/*.jsonl --iters 50
```



---

## Validation

The paper admits it has no data (§V-A: *"data that no existing benchmark provides"*). This repo uses
[AgentLAB](https://github.com/TanqiuJiang/AgentLAB), which ships `STAC_gen`/`STAC_eval` — STAC being
the paper's own ref [5] — plus 200 verified malicious tool chains and 700+ executable environment
simulators.

Those chains are *plans*, not MCP traces: no responses, no timestamps, no server attribution. Parsed
statically they yield only 10 of 20 dimensions. The replay harness executes them against real MCP
servers so TF and OC become extractable and the full vector is live.

### Results

200 verified attack chains + 200 synthesized benign chains, replayed through the real interceptor
against real environment simulators, using the design-spec priors:

| shape | n | detected | blocked |
|---|---|---|---|
| read-then-network (R3's target) | 90 | **74.4%** | **67.8%** |
| no outbound step at all | 98 | 10.2% | 0% |
| **benign (negative class)** | 200 | **0.0%** | **0.0%** |

The aggregate over all 200 attack chains is 38.5% detected / 30.5% blocked. It is lower than the
subset figure because much of the AgentLAB corpus is harmful *content* distribution — author a
payload, attach it, send it — which has no upstream data flow and no kill-chain progression for a
sequential detector to see. Chains also average 2.8 calls against a six-stage model.

Unsupervised Baum-Welch over these traces did **not** improve on the priors: transitions-only
training dropped the target subset to 58.9%, and full EM bought aggregate recall at the cost of
7.5% false positives. §IV-C anticipates estimation from *labelled* traces; 400 unlabelled sessions
of median length 3 are not that.

---

## Status

| Phase | State |
|---|---|
| Feature Extraction Layer | complete, 42 tests |
| HMM stage classifier | complete, 22 tests |
| Sequential Pattern Analyzer + §V-B gate | complete, 22 tests |
| Proxy + daemon | complete, 24 tests |
| AgentLAB replay harness | complete |
| Train + evaluate | complete |

**111 tests passing.** The conformance gate reproduces every stage label and rule firing the paper
states for S1–S5, and the labels survive ±5% perturbation of every prior (40/40 trials).

See `CLAUDE.md` for the full spec, the two paper ambiguities found and how they were resolved, and
per-phase verified-vs-assumed notes.

## License

Apache-2.0, matching `mcpwall`. Not affiliated with the paper's authors, `mcpwall`, or Anthropic.
