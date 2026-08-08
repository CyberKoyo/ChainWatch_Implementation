# GPT-4o-mini E/F Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate model-isolated AgentDojo and InjecAgent ChainWatch traces with pinned `gpt-4o-mini-2024-07-18` for the XGBoost comparison, while keeping `mcpwall` in the captured stdio path and accounting for every API token and dollar.

**Architecture:** A small Python capture package owns newline-delimited MCP JSON-RPC, OpenAI Chat Completions tool conversion, the tool-call loop, resolved-model verification, transcripts, and usage accounting. Two route-specific wrappers read the existing generated TSV recipes and launch the full `npx -y mcpwall -- python -m chainwatch -- benchmark_server` chain for every session. GPT rows receive new `source` values and new ML population selectors, so they can never pool with the existing Claude rows selected by `source` alone.

**Tech Stack:** Python 3.10+, OpenAI Python SDK, stdlib `subprocess`/JSON/CSV, pytest, existing AgentDojo/InjecAgent bridges, `mcpwall`, ChainWatch.

## Global Constraints

- `CLAUDE.md` is the authoritative living specification and has been read in full for this work.
- Create `AGENT.md` as an agent-facing companion. If it and `CLAUDE.md` disagree, `CLAUDE.md` wins.
- The captured process chain is always host runner → `mcpwall` → `chainwatch` → benchmark server.
- `chainwatch` runs with `--observe-only --no-daemon --log-args` for these fixture-only routes.
- The requested model is pinned to `gpt-4o-mini-2024-07-18`; aliases are not accepted.
- Before forwarding any model-generated tool call, verify the API response's `model` equals the requested pinned model. A mismatch ends the session before that tool call.
- Record requested model, resolved response model, executor id, system-prompt hash, max turns, token usage, and estimated cost in sidecars.
- Use `source=agentdojo-gpt4omini` and `source=injecagent-gpt4omini`; never pool GPT, Claude, route E, or route F populations.
- Route E and F prompts come verbatim from generated benchmark recipes. Do not hand-author attack prompts or jailbreak framing.
- Invalid function-argument JSON becomes an error tool result returned to the model; it does not truncate the session.
- Closing the MCP client must close stdin and drain the child process so native score sidecars are written.
- Missing score sidecar is an execution failure, never a resisted injection.
- Read `OPENAI_API_KEY` only through the OpenAI SDK/environment. Never print, persist, or include it in subprocess environments beyond normal inherited API-client use.
- No live OpenAI API request may be made without the user's explicit confirmation. Local tests use fake clients; command verification uses `--dry-run`.
- Existing modifications to `scripts/capture_agentdojo.sh` and `scripts/capture_injecagent.sh` are user work and must not be overwritten.

---

### Task 1: Agent-facing project contract

**Files:**
- Create: `AGENT.md`

- [ ] Write the project purpose, living-spec precedence, stdio architecture, fixed 20-dimensional feature contract, trace contract, XGBoost population rules, Route E/F rules, capture failure semantics, and verification commands.
- [ ] Include explicit prohibitions against bypassing `mcpwall`, pooling populations, hand-authoring route prompts, and interpreting missing sidecars as resistance.
- [ ] Review the document against `CLAUDE.md` for contradictions.

### Task 2: Capture package and chain builder

**Files:**
- Create: `chainwatch/capture/__init__.py`
- Create: `chainwatch/capture/openai_mcp.py`
- Modify: `pyproject.toml`
- Test: `tests/test_openai_mcp_capture.py`

**Interfaces:**
- `build_mcpwall_chain_argv(python, label, source, model, server_args, log_dir=None) -> list[str]`
- `openai_tool_from_mcp_tool(tool) -> dict`

- [ ] Write tests asserting exact process ordering, required ChainWatch flags, source/model values, optional log directory, and the final `--` boundary.
- [ ] Run the focused tests and confirm they fail because the package does not exist.
- [ ] Implement the package scaffold, argv builder, and MCP-to-OpenAI tool schema conversion.
- [ ] Run the focused tests and confirm they pass.

### Task 3: Newline MCP subprocess transport

**Files:**
- Modify: `chainwatch/capture/openai_mcp.py`
- Test: `tests/test_openai_mcp_capture.py`

**Interfaces:**
- `MCPProcess(argv, env=None, cwd=None, stderr_path=None)`
- `request(method, params=None) -> dict`
- `notify(method, params=None) -> None`
- `initialize() -> list[dict]`
- `call_tool(name, arguments) -> dict`
- `close() -> int`

- [ ] Write tests using `tests/stub_mcp_server.py` for initialize, list, call, request ids, and EOF shutdown.
- [ ] Confirm the tests fail for the missing transport.
- [ ] Implement line-oriented JSON-RPC with exact-id response matching and deterministic process cleanup.
- [ ] Confirm transport tests pass.

### Task 4: Tool loop, model identity, and usage accounting

**Files:**
- Modify: `chainwatch/capture/openai_mcp.py`
- Test: `tests/test_openai_mcp_capture.py`

**Interfaces:**
- `SessionSpec(session_id, label, source, requested_model, prompt, chain_argv, env, transcript_path, usage_path, max_turns=12, max_output_tokens=512, system_prompt=...)`
- `SessionResult(session_id, calls, status, requested_model, resolved_model, prompt_tokens, completion_tokens, estimated_cost_usd, error=None)`
- `CaptureBudget(limit_usd)`
- `run_session(spec, openai_client=None, budget=None) -> SessionResult`

- [ ] Write fake-client tests for a tool call followed by a final answer, multiple tool calls, invalid JSON recovery, max turns, API errors, budget exhaustion, and absence of API-key data in artifacts.
- [ ] Write a test proving a resolved-model mismatch prevents MCP tool execution.
- [ ] Confirm all new tests fail for missing behavior.
- [ ] Implement Chat Completions requests, message replay, model verification, exact usage accumulation, GPT-4o-mini pricing, JSONL usage output, and transcript output.
- [ ] Confirm focused tests pass.

### Task 5: AgentDojo wrapper

**Files:**
- Create: `scripts/capture_agentdojo_openai.py`
- Test: `tests/test_openai_capture_wrappers.py`

**Interfaces:**
- CLI defaults: `--model gpt-4o-mini-2024-07-18`, `--source agentdojo-gpt4omini`, `--max-cost-usd 3.00`, `--max-turns 12`, `--max-output-tokens 512`.
- Live execution requires `--confirm-api-usage`; `--dry-run` never constructs an OpenAI client.

- [ ] Write tests for TSV parsing, benign/attack server argv differences, source/model isolation, dry-run output, and refusal to run live without the confirmation flag.
- [ ] Confirm tests fail because the wrapper is absent.
- [ ] Implement per-session ids, neutral state directories, `PYTHONPATH`, score aggregation, usage aggregation, trace-call counting, and nonzero exit when no session records a tool call.
- [ ] Confirm wrapper tests pass.

### Task 6: InjecAgent wrapper

**Files:**
- Create: `scripts/capture_injecagent_openai.py`
- Test: `tests/test_openai_capture_wrappers.py`

**Interfaces:**
- CLI defaults: `--model gpt-4o-mini-2024-07-18`, `--source injecagent-gpt4omini`, `--max-cost-usd 3.00`, `--max-turns 12`, `--max-output-tokens 512`.
- Live execution requires `--confirm-api-usage`; `--dry-run` never constructs an OpenAI client.

- [ ] Write tests for recipe parsing, base/enhanced selection, benign-only `--benign`, full chain ordering, dry-run output, and live confirmation gating.
- [ ] Confirm tests fail because the wrapper is absent.
- [ ] Implement score/usage aggregation and the same empty-capture failure semantics as Route E.
- [ ] Confirm wrapper tests pass.

### Task 7: GPT-specific XGBoost populations

**Files:**
- Modify: `chainwatch/ml/evaluate.py`
- Modify: `tests/test_ml.py`

- [ ] Write failing tests requiring `agentdojo-gpt4omini` and `injecagent-gpt4omini` population keys that select only their exact same-named source.
- [ ] Assert both GPT populations are disjoint from each other and from the existing Claude-backed `agentdojo`/`injecagent` populations.
- [ ] Add the two `Populations` definitions and registry entries.
- [ ] Run the ML tests.

### Task 8: Runbook and dry smoke

**Files:**
- Modify: `docs/traffic_recipes.md`

- [ ] Document model availability/model-identity checks performed by the runner, API-key requirements, cost estimates, usage sidecars, and the observed-cost budget semantics.
- [ ] Document recipe generation and `--dry-run` commands for both routes.
- [ ] Document live smoke commands with `--confirm-api-usage`, clearly marked as requiring explicit user confirmation before execution.
- [ ] Document separate `chainwatch ml-eval --population agentdojo-gpt4omini` and `injecagent-gpt4omini` commands.

### Task 9: Local verification only

**Files:**
- Test: `tests/test_openai_mcp_capture.py`
- Test: `tests/test_openai_capture_wrappers.py`
- Test: existing bridge/proxy/ML tests

- [ ] Run `pytest tests/test_openai_mcp_capture.py tests/test_openai_capture_wrappers.py -v`.
- [ ] Run `pytest tests/test_agentdojo_bridge.py tests/test_injecagent_bridge.py tests/test_proxy.py tests/test_ml.py -v`.
- [ ] Run both wrappers with `--dry-run` and inspect that `mcpwall` precedes `chainwatch`, which precedes the benchmark server.
- [ ] Search changed files for accidental secrets or hard-coded API keys.
- [ ] Do not execute a live smoke until the user separately confirms API usage.

