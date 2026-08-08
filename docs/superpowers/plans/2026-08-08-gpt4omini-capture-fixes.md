# GPT-4o-mini Capture — Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every defect found in the code review of the GPT-4o-mini Route E/F capture implementation, so the first paid smoke run cannot write a corpus that is poisoned at capture time.

**Architecture:** Five behavioural changes plus housekeeping, all inside the existing worktree `/tmp/chainwatch-gpt4omini-capture` (branch `feat/gpt4omini-capture`, nothing committed yet). The chain builder gains an explicit server name; the tool loop stops treating a filtered call as fatal; the recipe generators interleave environments so any prefix of the file is representative; the wrappers gain environment filters. No new modules.

**Tech Stack:** Python 3.12, stdlib `subprocess`/`json`/`csv`/`itertools`, pytest, existing `chainwatch/capture/openai_mcp.py`, the AgentDojo/InjecAgent bridges, `mcpwall`.

## Context

The review of Codex's implementation (`chainwatch/capture/openai_mcp.py`, `scripts/capture_*_openai.py`, 30 new tests, 306 total green) found the transport sound — verified end-to-end without spending API credit: EOF propagates through `npx mcpwall`, the bridge writes its score sidecar, and ChainWatch writes a trace row carrying `"model":"gpt-4o-mini-2024-07-18"`.

It also found one defect that survives into the corpus and cannot be repaired afterwards, which is why this plan exists before the smoke run rather than after it.

`chainwatch/proxy/__main__.py:210` derives the server name from the last argv token when `--server` is absent:

```python
server_name = options.server or command[-1].split("/")[-1]
```

Neither wrapper passes `--server`. Observed live:

```json
{"session":"eoftest","source":"eoftest","server":"score.json","tool":"get_balance", ...}
```

`chainwatch/ml/dataset.py:355` reads exactly that field as the **environment** for leave-one-environment-out. Consequences:

* **Route F leaks the label.** Benign argv ends `--benign`, attack argv ends `--score-out <path>`. So benign rows record `server="--benign"` and attack rows record `server="<session>.json"` — the two classes land in disjoint "environments". This is the same species as `win_occupancy`, PS and provenance, which CLAUDE.md §12 documents three times.
* **Route E destroys the grouping.** `server` is `<session>.json`, unique per session, so leave-one-environment-out degenerates to leave-one-session-out.

The rest: a JSON-RPC error on `tools/call` discards a whole session (and `mcpwall` sits above ChainWatch and rejects by returning exactly that); the recipe TSVs are blocked by suite, so a budget-capped run is banking-only; the cost sidecar prices a mismatched model at gpt-4o-mini rates; `--dry-run` creates state directories; staging directories accumulate.

Intended outcome: run the first paid smoke with all four suites represented, a `server` field that means the environment, and a single filtered call no longer costing a session.

## Global Constraints

- `CLAUDE.md` is the authoritative living specification. Where this plan and it disagree, `CLAUDE.md` wins and the code is the bug.
- **`CLAUDE.md` inside the worktree is a symlink to the main checkout's file.** Editing it edits the real spec. That is intended for Task 8 and must not happen by accident earlier.
- The captured process chain is always host runner → `mcpwall` → `chainwatch` → benchmark server. No task may remove or reorder that.
- `chainwatch` runs `--observe-only --no-daemon --log-args` on these fixture-only routes.
- The requested model stays pinned to `gpt-4o-mini-2024-07-18`. Aliases are not accepted.
- `source` values stay `agentdojo-gpt4omini` and `injecagent-gpt4omini`. Never pool GPT with Claude, or route E with route F.
- Route E and F prompts come verbatim from the generated benchmark recipes. No hand-authored attack text, no jailbreak framing, in any task.
- **No live OpenAI API request may be made by any task in this plan.** Tests use fake clients and the local stub server; command verification uses `--dry-run` and the free MCP chain probe in Task 8.
- The `server` name must never vary with the `label`. That is the defect this plan exists for; every new test must be able to fail on it.
- Work in the worktree `/tmp/chainwatch-gpt4omini-capture` on branch `feat/gpt4omini-capture`. Commit after every task.
- Run tests with `/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest`. Baseline before any change: **306 passed**.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `chainwatch/capture/openai_mcp.py` | transport, model identity, bounded loop, accounting, publish/quarantine | modify — `server_name` argument, `MCPToolError`, `rejected_calls`, cost-basis fields |
| `chainwatch/capture/__init__.py` | package exports | modify — export `MCPToolError` |
| `scripts/capture_agentdojo_openai.py` | route E wrapper | modify — pass suite as server name, `--suite` filter, dry-run side effects, staging cleanup, score-check shape |
| `scripts/capture_injecagent_openai.py` | route F wrapper | modify — constant server name, `--split` filter, same housekeeping |
| `scripts/capture_agentdojo.sh` | route E Claude driver | modify — one added `--server` pair |
| `scripts/capture_injecagent.sh` | route F Claude driver | modify — one added `--server` pair |
| `scripts/gen_agentdojo_recipes.py` | route E recipe generator | modify — round-robin suites |
| `scripts/gen_injecagent_recipes.py` | route F recipe generator | modify — round-robin splits |
| `docs/recipes_agentdojo.tsv`, `docs/recipes_injecagent.tsv` | generated recipe grids | regenerate — never hand-edit |
| `tests/stub_mcp_server.py` | fake MCP server for transport tests | modify — can return a JSON-RPC error for a named tool |
| `tests/test_openai_mcp_capture.py` | transport/loop contracts | modify — server name, tool-error recovery, cost basis |
| `tests/test_openai_capture_wrappers.py` | route wrapper contracts | modify — server naming, filters, dry-run purity |
| `tests/test_capture_drivers.py` | every capture driver names its server | **create** |
| `tests/test_recipe_generators.py` | generated grids interleave environments | **create** |
| `CLAUDE.md` §14, `AGENT.md`, `docs/traffic_recipes.md` | operator-facing contract | modify — Task 8 |

---

### Task 1: Name the server explicitly in the chain builder

**Files:**
- Modify: `chainwatch/capture/openai_mcp.py:166-204` (`build_mcpwall_chain_argv`)
- Test: `tests/test_openai_mcp_capture.py:107-148`

**Interfaces:**
- Produces: `build_mcpwall_chain_argv(*, python, label, source, model, server_name, server_args, log_dir=None) -> list[str]` — `server_name` is keyword-only and required; Tasks 2 and 6 call it.

- [ ] **Step 1: Write the failing tests**

Replace `test_chain_builder_keeps_mcpwall_before_chainwatch_before_server` in `tests/test_openai_mcp_capture.py` with the version below, and add the second test after it.

```python
def test_chain_builder_keeps_mcpwall_before_chainwatch_before_server(tmp_path):
    argv = build_mcpwall_chain_argv(
        python="/venv/bin/python",
        label="attack",
        source="agentdojo-gpt4omini",
        model=MODEL,
        server_name="workspace",
        log_dir=tmp_path,
        server_args=[
            "/venv/bin/python",
            "-m",
            "agentdojo_bridge.env_mcp_server",
            "--suite",
            "workspace",
        ],
    )

    assert argv == [
        "npx",
        "-y",
        "mcpwall",
        "--",
        "/venv/bin/python",
        "-m",
        "chainwatch",
        "--server",
        "workspace",
        "--observe-only",
        "--no-daemon",
        "--label",
        "attack",
        "--source",
        "agentdojo-gpt4omini",
        "--model",
        MODEL,
        "--log-args",
        "--log-dir",
        str(tmp_path),
        "--",
        "/venv/bin/python",
        "-m",
        "agentdojo_bridge.env_mcp_server",
        "--suite",
        "workspace",
    ]


def test_chain_builder_refuses_an_empty_server_name():
    # chainwatch/proxy/__main__.py falls back to the last argv token when --server is
    # absent, which reads the score-file path or the --benign flag as an environment.
    with pytest.raises(ValueError, match="server_name"):
        build_mcpwall_chain_argv(
            python="/venv/bin/python",
            label="benign",
            source="agentdojo-gpt4omini",
            model=MODEL,
            server_name="",
            server_args=["/venv/bin/python", "-m", "x"],
        )
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /tmp/chainwatch-gpt4omini-capture
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_openai_mcp_capture.py -k chain_builder -v
```

Expected: FAIL — `TypeError: build_mcpwall_chain_argv() got an unexpected keyword argument 'server_name'`.

- [ ] **Step 3: Implement**

In `chainwatch/capture/openai_mcp.py`, change the signature and body of `build_mcpwall_chain_argv`:

```python
def build_mcpwall_chain_argv(
    *,
    python: str,
    label: str,
    source: str,
    model: str,
    server_name: str,
    server_args: Sequence[str],
    log_dir: Path | str | None = None,
) -> list[str]:
    """Build the only valid capture ordering: mcpwall -> chainwatch -> server.

    ``server_name`` is required rather than optional. Without ``--server`` the proxy
    names the server after the last argv token (proxy/__main__.py:210), which is the
    score-file path on one half and ``--benign`` on the other -- and ml/dataset.py
    reads that field as the leave-one-environment-out environment.
    """
    if label not in {"benign", "attack"}:
        raise ValueError("label must be benign or attack")
    if not source:
        raise ValueError("source is required")
    if not server_name or not server_name.strip():
        raise ValueError("server_name is required")
    if not server_args:
        raise ValueError("server_args may not be empty")

    argv = [
        "npx",
        "-y",
        "mcpwall",
        "--",
        python,
        "-m",
        "chainwatch",
        "--server",
        server_name,
        "--observe-only",
        "--no-daemon",
        "--label",
        label,
        "--source",
        source,
        "--model",
        model,
        "--log-args",
    ]
    if log_dir is not None:
        argv.extend(["--log-dir", str(log_dir)])
    argv.extend(["--", *[str(part) for part in server_args]])
    return argv
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_openai_mcp_capture.py -k chain_builder -v
```

Expected: 2 passed. The two wrapper tests still fail — Task 2 fixes them.

- [ ] **Step 5: Commit**

```bash
git add chainwatch/capture/openai_mcp.py tests/test_openai_mcp_capture.py
git commit -m "fix(capture): require an explicit --server name in the chain builder"
```

---

### Task 2: Give each route a real environment name

**Files:**
- Modify: `scripts/capture_agentdojo_openai.py:83-98` (`build_chain_argv`)
- Modify: `scripts/capture_injecagent_openai.py:31-32, 94-109`
- Test: `tests/test_openai_capture_wrappers.py`

**Interfaces:**
- Consumes: `build_mcpwall_chain_argv(..., server_name=...)` from Task 1.
- Produces: `scripts.capture_injecagent_openai.SERVER_NAME == "injecagent-dev"`; route E's server name is `recipe.suite`.

Route E's four suites (`banking`, `slack`, `travel`, `workspace`) are the environments the held-out evaluation wants. Route F is a **single** environment — all 558 recipe rows use a GitHub user tool — so its name is a constant. Using `split` (`ds`/`dh`) there would hold out attack *types* under a name that claims to hold out environments.

- [ ] **Step 1: Write the failing tests**

Extend the import block at the top of `tests/test_openai_capture_wrappers.py`:

```python
from scripts.capture_injecagent_openai import (
    DEFAULT_SOURCE as INJECAGENT_SOURCE,
    SERVER_NAME as INJECAGENT_SERVER_NAME,
    InjecAgentRecipe,
    build_chain_argv as build_injecagent_chain,
    build_server_args as build_injecagent_server,
    validate_score as validate_injecagent_score,
)
```

Then add:

```python
def test_agentdojo_server_name_is_the_suite_not_the_last_argv_token(tmp_path):
    recipe = AgentDojoRecipe("attack", "travel", "user_task_1", "injection_task_2", "Book it")

    argv = build_agentdojo_chain(
        recipe,
        python="/venv/bin/python",
        score_out=tmp_path / "score.json",
        log_dir=tmp_path / "logs",
    )

    assert argv[argv.index("--server") + 1] == "travel"
    assert argv[-1] != argv[argv.index("--server") + 1]


def test_injecagent_server_name_is_constant_across_labels(tmp_path):
    # Route F is one environment: every recipe row uses a GitHub user tool. A name that
    # varied with the label would put the two classes in disjoint LOEO environments.
    benign = InjecAgentRecipe("benign", "ds", "base", 0, "GitHubGet", "Same prompt")
    attack = InjecAgentRecipe("attack", "dh", "enhanced", 3, "GitHubGet", "Same prompt")

    benign_argv = build_injecagent_chain(
        benign, python="/venv/bin/python", score_out=tmp_path / "b.json", log_dir=tmp_path
    )
    attack_argv = build_injecagent_chain(
        attack, python="/venv/bin/python", score_out=tmp_path / "a.json", log_dir=tmp_path
    )

    benign_server = benign_argv[benign_argv.index("--server") + 1]
    attack_server = attack_argv[attack_argv.index("--server") + 1]
    assert benign_server == attack_server == INJECAGENT_SERVER_NAME
    assert INJECAGENT_SERVER_NAME == "injecagent-dev"
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_openai_capture_wrappers.py -v
```

Expected: collection error — `ImportError: cannot import name 'SERVER_NAME'`.

- [ ] **Step 3: Implement — route E**

In `scripts/capture_agentdojo_openai.py`:

```python
def build_chain_argv(
    recipe: AgentDojoRecipe,
    *,
    python: str,
    score_out: Path,
    log_dir: Path,
    model: str = DEFAULT_MODEL,
) -> list[str]:
    return build_mcpwall_chain_argv(
        python=python,
        label=recipe.label,
        source=DEFAULT_SOURCE,
        model=model,
        # The suite is the environment ml/dataset.py groups on. It is identical for a
        # benign row and its attack twin, so it cannot carry the label.
        server_name=recipe.suite,
        log_dir=log_dir,
        server_args=build_server_args(recipe, python, score_out),
    )
```

- [ ] **Step 4: Implement — route F**

In `scripts/capture_injecagent_openai.py`, add the constant beside the existing ones:

```python
DEFAULT_MODEL = "gpt-4o-mini-2024-07-18"
DEFAULT_SOURCE = "injecagent-gpt4omini"
#: Route F is a single environment -- every dev case drives a GitHub user tool -- so the
#: server name is constant. Naming it after `split` would hold out attack types instead.
SERVER_NAME = "injecagent-dev"
```

```python
def build_chain_argv(
    recipe: InjecAgentRecipe,
    *,
    python: str,
    score_out: Path,
    log_dir: Path,
    model: str = DEFAULT_MODEL,
) -> list[str]:
    return build_mcpwall_chain_argv(
        python=python,
        label=recipe.label,
        source=DEFAULT_SOURCE,
        model=model,
        server_name=SERVER_NAME,
        log_dir=log_dir,
        server_args=build_server_args(recipe, python, score_out),
    )
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_openai_capture_wrappers.py tests/test_openai_mcp_capture.py -v
```

Expected: all pass.

- [ ] **Step 6: Verify against the real argv, free of API cost**

```bash
cd /tmp/chainwatch-gpt4omini-capture
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python \
  scripts/capture_agentdojo_openai.py --dry-run --limit 1 \
  | /home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -c \
  "import json,sys; a=json.load(sys.stdin)['chain_argv']; print(a[a.index('--server')+1])"
```

Expected: a suite name (`banking` before Task 5, any of the four after it) — never `score.json`.

- [ ] **Step 7: Commit**

```bash
git add scripts/capture_agentdojo_openai.py scripts/capture_injecagent_openai.py \
        tests/test_openai_capture_wrappers.py
git commit -m "fix(capture): name route E by suite and route F by its single dev environment"
```

---

### Task 3: Close the same defect in the Claude shell drivers

**Files:**
- Modify: `scripts/capture_agentdojo.sh` (the embedded python `args` list, around lines 99-110)
- Modify: `scripts/capture_injecagent.sh` (same block)
- Test: `tests/test_capture_drivers.py` (create)

These two drivers have the identical defect — route E's server argv ends `--score-out <path>`, route F's benign half ends `--benign`. They have captured 0 sessions, so no corpus is damaged yet. They are also the user's own edits: change nothing but the added `--server` pair.

- [ ] **Step 1: Write the failing test**

Create `tests/test_capture_drivers.py`:

```python
"""Every capture driver must name its MCP server explicitly.

chainwatch/proxy/__main__.py falls back to the last argv token, which is a score-file
path on one half of a route and `--benign` on the other. ml/dataset.py reads that field
as the leave-one-environment-out environment, so the fallback puts the two classes in
disjoint environments. A grep-shaped test is the right shape here: these drivers build
their argv inside an embedded heredoc that cannot be imported.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

DRIVERS = [
    "scripts/capture_agentdojo.sh",
    "scripts/capture_injecagent.sh",
]


@pytest.mark.parametrize("driver", DRIVERS)
def test_every_driver_names_its_server(driver):
    text = (ROOT / driver).read_text(encoding="utf-8")
    assert '"--server"' in text, f"{driver} does not pass --server to chainwatch"
    assert '"--source"' in text
    assert text.index('"--server"') < text.index('"--source"')
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_capture_drivers.py -v
```

Expected: 2 failed — `scripts/capture_agentdojo.sh does not pass --server to chainwatch`.

- [ ] **Step 3: Implement — route E**

In `scripts/capture_agentdojo.sh`, the bash loop already exports `SUITE` into the heredoc environment. Insert the pair immediately before `"--observe-only"` in the embedded python `args` list:

```python
            "args": [
                "-y", "mcpwall", "--",
                sys.executable, "-m", "chainwatch",
                # Without this the proxy names the server after the last argv token --
                # the score-file path here -- and ml/dataset.py reads that as the
                # leave-one-environment-out environment.
                "--server", os.environ["SUITE"],
                "--observe-only", "--no-daemon",
                "--label", os.environ["LABEL"],
                "--source", os.environ["CAPTURE_PROFILE"],
                "--model", os.environ["CAPTURE_MODEL"],
                "--log-args",
                "--",
                sys.executable, *server,
            ],
```

If `SUITE` is not in the `env` list preceding the heredoc invocation, add it there too — it is already computed by the loop that fills `--suite`.

- [ ] **Step 4: Implement — route F**

In `scripts/capture_injecagent.sh`, the same pair with the constant from Task 2. Route F's benign half ends `--benign` and its attack half ends the score path, so the fallback there is label-correlated:

```python
            "args": [
                "-y", "mcpwall", "--",
                sys.executable, "-m", "chainwatch",
                # Constant: route F is one environment (every dev case is a GitHub user
                # tool). The argv fallback would read `--benign` on one half only.
                "--server", "injecagent-dev",
                "--observe-only", "--no-daemon",
                "--label", os.environ["LABEL"],
                "--source", os.environ["CAPTURE_PROFILE"],
                "--model", os.environ["CAPTURE_MODEL"],
                "--log-args",
                "--",
                sys.executable, *server,
            ],
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_capture_drivers.py -v
```

Expected: 2 passed.

- [ ] **Step 6: Verify the drivers still parse and still emit a config**

```bash
bash -n scripts/capture_agentdojo.sh && bash -n scripts/capture_injecagent.sh && echo "syntax ok"
DRY=1 bash scripts/capture_agentdojo.sh docs/recipes_agentdojo.tsv 1 2>&1 | head -20
```

Expected: `syntax ok`, then dry output showing `--server` inside the generated MCP config.

- [ ] **Step 7: Commit**

```bash
git add scripts/capture_agentdojo.sh scripts/capture_injecagent.sh tests/test_capture_drivers.py
git commit -m "fix(capture): name the server in the Claude route E/F drivers too"
```

---

### Task 4: A filtered tool call must not discard the session

**Files:**
- Modify: `chainwatch/capture/openai_mcp.py:54-56` (`MCPError`), `:284-319` (`request`), `:152-163` (`SessionResult`), `:574-597` (`_safe_session_result`), `:729-778` (the tool-dispatch loop)
- Modify: `chainwatch/capture/__init__.py`
- Modify: `tests/stub_mcp_server.py`
- Modify: `scripts/capture_agentdojo_openai.py:345-349`, `scripts/capture_injecagent_openai.py:363-367`
- Test: `tests/test_openai_mcp_capture.py`

`mcpwall` sits **above** ChainWatch and rejects a call by returning a JSON-RPC error, which never reaches the bridge and never produces a trace row. Today that raises `MCPError`, escapes to the outer handler at `:779`, and quarantines every row of the session. The bridges' own tool failures already come back as `isError` *results*, so this path is reached almost only by a filter above.

`rejected_calls` is counted separately and deliberately **not** added to `calls`: the bridge never saw the call, so counting it would break the three-way equality between the native sidecar's `calls`, the executor's `calls`, and the published trace-row count.

**Interfaces:**
- Produces: `MCPToolError(MCPError)` with a `.code` attribute; `SessionResult.rejected_calls: int`.

- [ ] **Step 1: Teach the stub to reject a named tool**

In `tests/stub_mcp_server.py`, inside the `tools/call` branch, reject **before** counting. Delete the existing bare `tool_calls += 1` line that precedes `name = ...` so nothing is counted twice:

```python
        elif method == "tools/call":
            name = (request.get("params") or {}).get("name")
            if name and name == os.environ.get("STUB_REJECT_TOOL"):
                sys.stdout.write(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": request.get("id"),
                            "error": {"code": -32000, "message": "blocked by policy"},
                        }
                    )
                    + "\n"
                )
                sys.stdout.flush()
                continue
            tool_calls += 1
```

- [ ] **Step 2: Write the failing test**

Add to `tests/test_openai_mcp_capture.py`. Reuse whatever spec/completion/tool-call helpers `test_tool_loop_records_resolved_model_usage_and_real_mcp_call` (`:225`) already uses — do not invent parallel helpers:

```python
def test_rejected_tool_call_is_returned_to_the_model_and_keeps_the_session(tmp_path):
    # mcpwall sits above chainwatch and rejects by returning a JSON-RPC error. That call
    # never reaches the bridge and never produces a trace row, so it must not be counted
    # as a call -- but it must also not discard the good rows around it.
    env, score_path = _score_env(tmp_path)
    env["STUB_REJECT_TOOL"] = "post_to_webhook"
    client = _FakeOpenAI(
        [
            _completion(tool_calls=[_tool_call("c1", "post_to_webhook", '{"url": "x"}')]),
            _completion(tool_calls=[_tool_call("c2", "read_env", "{}")]),
            _completion(content="done"),
        ]
    )
    spec = _spec(tmp_path, chain_argv=[sys.executable, str(STUB)], env=env)

    result = run_session(spec, openai_client=client)

    assert result.status == "completed"
    assert result.calls == 1
    assert result.rejected_calls == 1
    assert json.loads(score_path.read_text(encoding="utf-8"))["calls"] == 1

    kinds = [
        json.loads(line)["type"]
        for line in spec.transcript_path.read_text(encoding="utf-8").splitlines()
    ]
    assert "tool_call_rejected" in kinds
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_openai_mcp_capture.py -k rejected_tool_call -v
```

Expected: FAIL — `AttributeError: 'SessionResult' object has no attribute 'rejected_calls'`, or `status == 'mcp_error'`.

- [ ] **Step 4: Implement the exception and the field**

In `chainwatch/capture/openai_mcp.py`, after `MCPError`:

```python
class MCPToolError(MCPError):
    """One request was answered with a JSON-RPC error object.

    Distinct from a transport failure: the pipe is still healthy and the session can
    continue. On `tools/call` this is how a filter above ChainWatch -- mcpwall -- says
    no, and the call never reached the benchmark server.
    """

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code
```

In `MCPProcess.request`, replace the error branch:

```python
            if "error" in response:
                error_object = response.get("error") or {}
                raise MCPToolError(
                    str(error_object.get("message", "MCP request failed")),
                    error_object.get("code"),
                )
```

Add the field to `SessionResult`, immediately after `calls`:

```python
    calls: int
    rejected_calls: int
```

Give `_safe_session_result` a matching `rejected_calls: int` keyword parameter and pass it into the constructor.

- [ ] **Step 5: Implement the recovery in the tool loop**

In `run_session`, initialise the counter alongside the others:

```python
    prompt_tokens = completion_tokens = cached_tokens = calls = rejected_calls = 0
```

Replace `result = process.call_tool(name, arguments)` and the two statements after it with:

```python
                try:
                    result = process.call_tool(name, arguments)
                except MCPToolError as tool_error:
                    # Not counted as a call: it never reached the server, so the native
                    # sidecar and the trace will not contain it either.
                    rejected_calls += 1
                    tool_text = json.dumps(
                        {"error": "tool_call_rejected", "message": str(tool_error)},
                        separators=(",", ":"),
                    )
                    messages.append(
                        {"role": "tool", "tool_call_id": call_id, "content": tool_text}
                    )
                    _append_jsonl(
                        spec.transcript_path,
                        {
                            "type": "tool_call_rejected",
                            "session": spec.session_id,
                            "turn": turn,
                            "tool_call_id": call_id,
                            "tool": name,
                            "code": tool_error.code,
                            "message": str(tool_error),
                        },
                    )
                    continue
                calls += 1
                tool_text = _mcp_result_text(result)
```

Pass `rejected_calls=rejected_calls` in the `_safe_session_result(...)` call at `:798`.

- [ ] **Step 6: Export the new name**

In `chainwatch/capture/__init__.py`, add `MCPToolError` to both the import block and `__all__`, keeping the existing ordering.

- [ ] **Step 7: Report it in both wrappers**

In each of `scripts/capture_agentdojo_openai.py` and `scripts/capture_injecagent_openai.py`, extend the per-session line:

```python
        print(
            f"[{session}] status={result.status} mcp_calls={result.calls} "
            f"rejected={result.rejected_calls} trace_calls={trace_calls} "
            f"cost=${result.estimated_cost_usd:.6f}",
            file=sys.stderr,
        )
```

- [ ] **Step 8: Run the tests to verify they pass**

```bash
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_openai_mcp_capture.py tests/test_openai_capture_wrappers.py -v
```

Expected: all pass, including `test_mcp_process_times_out_when_server_never_replies` — transport failures still raise plain `MCPError`, and `MCPToolError` subclasses it so no existing `except MCPError` changes meaning.

- [ ] **Step 9: Commit**

```bash
git add chainwatch/capture/openai_mcp.py chainwatch/capture/__init__.py \
        scripts/capture_agentdojo_openai.py scripts/capture_injecagent_openai.py \
        tests/stub_mcp_server.py tests/test_openai_mcp_capture.py
git commit -m "fix(capture): recover from a rejected tool call instead of discarding the session"
```

---

### Task 5: Interleave environments in the generated recipe grids

**Files:**
- Modify: `scripts/gen_agentdojo_recipes.py:63-75` (`rows`)
- Modify: `scripts/gen_injecagent_recipes.py:39-49` (`rows`)
- Regenerate: `docs/recipes_agentdojo.tsv`, `docs/recipes_injecagent.tsv`
- Test: `tests/test_recipe_generators.py` (create)

Today the grids are blocked by environment — route E is banking ×128, then slack ×84, travel ×80, workspace ×160. `--limit N` and the observed-spend budget both cut the file at a prefix, so a smoke run or a budget-capped run is **banking only** and leave-one-environment-out has one environment. Round-robin at the *block* level, where a block is one user task's benign row plus its attack rows, so any prefix still contains matched pairs.

- [ ] **Step 1: Write the failing test**

Create `tests/test_recipe_generators.py`:

```python
"""The generated grids must be representative at any prefix.

--limit and the observed-spend budget both cut the recipe file at a prefix. Blocked-by-
environment ordering makes every small run one environment, which leaves
leave-one-environment-out with nothing to hold out.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.gen_agentdojo_recipes import rows as agentdojo_rows  # noqa: E402
from scripts.gen_injecagent_recipes import rows as injecagent_rows  # noqa: E402


def test_agentdojo_grid_reaches_every_suite_early():
    generated = list(agentdojo_rows(None))
    suites = {row[1] for row in generated}
    assert suites == {"banking", "slack", "travel", "workspace"}

    first_benign_suites = [row[1] for row in generated if row[0] == "benign"][:4]
    assert set(first_benign_suites) == suites


def test_agentdojo_benign_row_still_precedes_its_own_attacks():
    generated = list(agentdojo_rows(None))
    seen_benign: set[tuple[str, str]] = set()
    for label, suite, user_task, _injection, _prompt in generated:
        key = (suite, user_task)
        if label == "benign":
            seen_benign.add(key)
        else:
            assert key in seen_benign, f"attack row precedes its benign twin: {key}"


def test_injecagent_grid_alternates_splits():
    generated = list(injecagent_rows(None))
    first_benign_splits = [row[1] for row in generated if row[0] == "benign"][:2]
    assert set(first_benign_splits) == {"ds", "dh"}


def test_generated_files_on_disk_match_the_generators():
    for module_rows, path in (
        (agentdojo_rows, ROOT / "docs/recipes_agentdojo.tsv"),
        (injecagent_rows, ROOT / "docs/recipes_injecagent.tsv"),
    ):
        on_disk = [
            line.split("\t")
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        assert on_disk == [list(row) for row in module_rows(None)], f"{path} is stale"
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_recipe_generators.py -v
```

Expected: `test_agentdojo_grid_reaches_every_suite_early` FAILS — the first four benign rows are all `banking`.

- [ ] **Step 3: Implement — route E**

In `scripts/gen_agentdojo_recipes.py`, add `from itertools import zip_longest` to the imports and replace `rows`:

```python
def _suite_blocks(suite_name: str, limit_per_suite: int | None) -> list[list[tuple]]:
    """One block per user task: its benign row followed by its attack rows."""
    suite = SUITES[suite_name]
    user_ids = sorted(suite.user_tasks)
    injection_ids = usable_injection_ids(suite_name)
    if limit_per_suite:
        user_ids = user_ids[:limit_per_suite]
        injection_ids = injection_ids[:limit_per_suite]

    blocks = []
    for user_id in user_ids:
        prompt = one_line(suite.user_tasks[user_id].PROMPT)
        block = [("benign", suite_name, user_id, "-", prompt)]
        block.extend(
            ("attack", suite_name, user_id, injection_id, prompt)
            for injection_id in injection_ids
        )
        blocks.append(block)
    return blocks


def rows(limit_per_suite: int | None):
    """Round-robin the suites so any prefix of the grid covers every environment.

    --limit and the spend budget both cut this file at a prefix. Emitting one suite at a
    time made every small run banking-only, and leave-one-environment-out needs more
    than one environment to hold out. Blocks stay intact so a prefix keeps matched pairs.
    """
    per_suite = [_suite_blocks(name, limit_per_suite) for name in sorted(SUITES)]
    for group in zip_longest(*per_suite):
        for block in group:
            if block is not None:
                yield from block
```

- [ ] **Step 4: Implement — route F**

In `scripts/gen_injecagent_recipes.py`, add `from itertools import zip_longest` and replace `rows`:

```python
def _split_blocks(split: str, limit: int | None) -> list[list[tuple]]:
    cases = dev_cases(split, "base")
    if limit:
        cases = cases[:limit]

    blocks = []
    for index, case in enumerate(cases):
        prompt = one_line(case["User Instruction"])
        user_tool = case["User Tool"]
        block = [("benign", split, "base", str(index), user_tool, prompt)]
        block.extend(
            ("attack", split, variant, str(index), user_tool, prompt)
            for variant in ("base", "enhanced")
        )
        blocks.append(block)
    return blocks


def rows(limit: int | None):
    """Round-robin the splits, for the same prefix-representativeness reason as route E."""
    per_split = [_split_blocks(split, limit) for split in sorted(SPLITS)]
    for group in zip_longest(*per_split):
        for block in group:
            if block is not None:
                yield from block
```

- [ ] **Step 5: Regenerate both grids**

```bash
cd /tmp/chainwatch-gpt4omini-capture
PY=/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python
$PY scripts/gen_agentdojo_recipes.py --out docs/recipes_agentdojo.tsv
$PY scripts/gen_injecagent_recipes.py --out docs/recipes_injecagent.tsv
grep -v '^#' docs/recipes_agentdojo.tsv | wc -l    # expect 452, unchanged
grep -v '^#' docs/recipes_injecagent.tsv | wc -l   # expect 558, unchanged
grep -v '^#' docs/recipes_agentdojo.tsv | head -40 | cut -f2 | sort -u   # expect >1 suite
```

- [ ] **Step 6: Run the tests to verify they pass**

```bash
$PY -m pytest tests/test_recipe_generators.py -v
```

Expected: 4 passed.

- [ ] **Step 7: Commit**

```bash
git add scripts/gen_agentdojo_recipes.py scripts/gen_injecagent_recipes.py \
        docs/recipes_agentdojo.tsv docs/recipes_injecagent.tsv tests/test_recipe_generators.py
git commit -m "fix(recipes): round-robin environments so any prefix of the grid is representative"
```

---

### Task 6: Environment filters on both wrappers

**Files:**
- Modify: `scripts/capture_agentdojo_openai.py:174-193` (`_parser`), `:206-213` (recipe selection)
- Modify: `scripts/capture_injecagent_openai.py:191-210`, `:223-230`
- Test: `tests/test_openai_capture_wrappers.py`

Round-robin makes a *small* batch representative; a filter makes a *targeted* re-run possible — one suite per budget when a suite needs topping up. Filters apply before `--limit`, so `--suite travel --limit 5` means five travel sessions rather than five rows that happen to be travel.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_openai_capture_wrappers.py`, copying the subprocess invocation style of the existing dry-run tests at `:211`:

```python
def test_agentdojo_suite_filter_selects_one_environment(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/capture_agentdojo_openai.py"),
            "--dry-run",
            "--suite",
            "travel",
            "--limit",
            "3",
            "--state-dir",
            str(tmp_path / "state"),
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    )

    printed = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(printed) == 3
    assert {row["suite"] for row in printed} == {"travel"}


def test_injecagent_split_filter_selects_one_split(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/capture_injecagent_openai.py"),
            "--dry-run",
            "--split",
            "dh",
            "--limit",
            "3",
            "--state-dir",
            str(tmp_path / "state"),
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    )

    printed = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(printed) == 3
    assert {row["split"] for row in printed} == {"dh"}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_openai_capture_wrappers.py -k filter -v
```

Expected: FAIL — non-zero exit, `unrecognized arguments: --suite travel`.

- [ ] **Step 3: Implement — route E**

In `_parser()` of `scripts/capture_agentdojo_openai.py`, after `--limit`:

```python
    parser.add_argument(
        "--suite",
        action="append",
        choices=("banking", "slack", "travel", "workspace"),
        default=None,
        help="restrict to one or more suites; repeatable. Applied before --limit.",
    )
```

In `main()`, between `recipes = load_recipes(...)` and the `--limit` slice:

```python
    if options.suite:
        wanted = set(options.suite)
        recipes = [recipe for recipe in recipes if recipe.suite in wanted]
        if not recipes:
            parser.error(f"no recipes for suite(s): {', '.join(sorted(wanted))}")
    if options.limit is not None:
        recipes = recipes[: options.limit]
```

- [ ] **Step 4: Implement — route F**

The same shape in `scripts/capture_injecagent_openai.py`:

```python
    parser.add_argument(
        "--split",
        action="append",
        choices=("ds", "dh"),
        default=None,
        help="restrict to one or more InjecAgent splits; repeatable. Applied before --limit.",
    )
```

```python
    if options.split:
        wanted = set(options.split)
        recipes = [recipe for recipe in recipes if recipe.split in wanted]
        if not recipes:
            parser.error(f"no recipes for split(s): {', '.join(sorted(wanted))}")
    if options.limit is not None:
        recipes = recipes[: options.limit]
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_openai_capture_wrappers.py -v
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add scripts/capture_agentdojo_openai.py scripts/capture_injecagent_openai.py \
        tests/test_openai_capture_wrappers.py
git commit -m "feat(capture): add --suite and --split filters for targeted batches"
```

---

### Task 7: Housekeeping — dry-run purity, staging cleanup, honest cost basis

**Files:**
- Modify: `scripts/capture_agentdojo_openai.py:215-255` (state dirs), `:123-150` (`validate_score`), `:307-344` (per-session body)
- Modify: `scripts/capture_injecagent_openai.py:232-273`, `:325-362`
- Modify: `chainwatch/capture/openai_mcp.py:680-696` (the usage row)
- Test: `tests/test_openai_capture_wrappers.py`, `tests/test_openai_mcp_capture.py`

Four small correctness items: `--dry-run` currently creates six state directories; a zero-call session leaves an empty staging directory forever; the usage sidecar prices a *mismatched* model at gpt-4o-mini rates while advertising exactness; and route E's score type-check is a compound expression that route F already writes more clearly.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_openai_capture_wrappers.py`:

```python
def test_dry_run_creates_no_state_directories(tmp_path):
    state = tmp_path / "state"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/capture_agentdojo_openai.py"),
            "--dry-run",
            "--limit",
            "1",
            "--state-dir",
            str(state),
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    )

    assert not state.exists(), "a dry run must not touch the filesystem"
```

Add to `tests/test_openai_mcp_capture.py`:

```python
def test_usage_row_records_the_price_basis(tmp_path):
    env, _score = _score_env(tmp_path)
    client = _FakeOpenAI([_completion(content="done")])
    spec = _spec(tmp_path, chain_argv=[sys.executable, str(STUB)], env=env)

    run_session(spec, openai_client=client)

    rows = [
        json.loads(line)
        for line in spec.usage_path.read_text(encoding="utf-8").splitlines()
    ]
    response_rows = [row for row in rows if row["type"] == "response"]
    assert response_rows
    assert all(row["cost_basis"] == MODEL for row in response_rows)
    assert all(row["cost_is_estimate"] is False for row in response_rows)
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_openai_capture_wrappers.py::test_dry_run_creates_no_state_directories \
  tests/test_openai_mcp_capture.py::test_usage_row_records_the_price_basis -v
```

Expected: both FAIL — the state directory exists; `KeyError: 'cost_basis'`.

- [ ] **Step 3: Implement — dry-run purity**

In **both** wrappers, move the directory-creation loop below the `if options.dry_run:` block. Keep the path variables where they are, since the dry-run output prints them:

```python
    state = options.state_dir.resolve()
    logs = state / "logs"
    trace_staging = state / "trace-staging"
    transcripts = state / "transcripts"
    scores = state / "scores"
    workdir = state / "agent-cwd"
    agent_home = state / "agent-home"

    run_stamp = new_capture_run_id()
    python = sys.executable

    if options.dry_run:
        ...unchanged printing loop...
        return 0

    # Only a live run owns state on disk.
    for directory in (logs, trace_staging, transcripts, scores, workdir, agent_home):
        directory.mkdir(parents=True, exist_ok=True)
```

- [ ] **Step 4: Implement — staging cleanup**

Add `import contextlib` to both wrappers. At the end of the per-session body, immediately before the `print(f"[{session}] ...")` line:

```python
        # `_mark_trace_files` renames in place, so a staging dir is empty only when the
        # session recorded nothing at all. Leaving those behind accumulates one dir per
        # session forever.
        with contextlib.suppress(OSError):
            session_staging.rmdir()
```

- [ ] **Step 5: Implement — cost basis**

In `chainwatch/capture/openai_mcp.py`, extend the usage row written at `:680`:

```python
                    "estimated_cost_usd": turn_cost,
                    # Priced at the requested model. On a mismatch the session is about
                    # to be rejected, but the money was still spent -- say what the
                    # number is worth rather than dropping it.
                    "cost_basis": spec.requested_model,
                    "cost_is_estimate": resolved_model != spec.requested_model,
                    "executor": spec.executor,
```

- [ ] **Step 6: Implement — score-check readability**

In `scripts/capture_agentdojo_openai.py`, replace the compound check in `validate_score` with route F's shape:

```python
    for key, value in expected.items():
        actual = verdict.get(key)
        wrong_type = key == "calls" and type(actual) is not int
        if actual != value or wrong_type:
            raise ValueError(f"score sidecar has unexpected {key}")
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest \
  tests/test_openai_capture_wrappers.py tests/test_openai_mcp_capture.py -v
```

Expected: all pass, including the existing `test_agentdojo_score_schema_and_recipe_coordinates_are_required`.

- [ ] **Step 8: Commit**

```bash
git add scripts/capture_agentdojo_openai.py scripts/capture_injecagent_openai.py \
        chainwatch/capture/openai_mcp.py tests/test_openai_capture_wrappers.py \
        tests/test_openai_mcp_capture.py
git commit -m "fix(capture): keep dry runs pure, clean empty staging, record the price basis"
```

---

### Task 8: Document the limitations and verify the whole chain

**Files:**
- Modify: `CLAUDE.md` §14 (**symlinked into the main checkout — this edits the real spec**)
- Modify: `AGENT.md`
- Modify: `docs/traffic_recipes.md`
- Create: `docs/superpowers/plans/2026-08-08-gpt4omini-capture-fixes.md` (a copy of this plan)

- [ ] **Step 1: Add a limitations subsection to `CLAUDE.md` §14**

Append after the existing "**Not yet done:**" paragraph:

```markdown
**Known limitations of this executor, stated because none is fixable by capture.**

* **The system prompt is authored in this repo** (`chainwatch/capture/openai_mcp.py`,
  `DEFAULT_SYSTEM_PROMPT`). It is byte-identical across the benign and attack halves and
  its sha256 is written to every usage row, so it cannot carry a label — but the Claude
  routes run under Claude Code's own system prompt, so GPT and Claude sessions differ by
  *executor and prompt* and can never be compared. Report them apart, always.
* **`server` is the environment**, and it is now asserted rather than derived: route E
  writes its suite, route F the constant `injecagent-dev`. Before this fix the proxy
  named the server after the last argv token — the score-file path, or `--benign` on
  route F's benign half — so `ml/dataset.py`'s leave-one-environment-out grouping would
  have been unique-per-session on E and *label-correlated* on F. Same species as
  `win_occupancy`, PS and provenance.
* **Route F has one environment.** All 558 recipe rows drive a GitHub user tool, so
  leave-one-environment-out is not available there and route F carries the dev-domain
  signal only.
* **A rejected tool call is not a failed session.** `mcpwall` sits above ChainWatch and
  refuses by returning a JSON-RPC error, which never reaches the bridge and never
  produces a trace row. Those are counted as `rejected_calls` and fed back to the model
  as a tool error; they are deliberately excluded from `calls` so the native sidecar,
  the executor count and the published row count stay equal.
* **The observed-spend budget cuts the recipe file at a prefix.** The grids are now
  round-robined across environments so a prefix stays representative, and `--suite` /
  `--split` exist for topping one environment up.
```

- [ ] **Step 2: Mirror the same points in `AGENT.md`**

`AGENT.md` is the agent-facing companion and `CLAUDE.md` wins on conflict. Add the same five bullets, plus the operational rule: **never construct a capture chain without `--server`.**

- [ ] **Step 3: Update `docs/traffic_recipes.md`**

In the existing GPT-4o-mini section, document:

- `--suite {banking,slack,travel,workspace}` and `--split {ds,dh}`, repeatable, applied before `--limit`.
- `rejected=` in the per-session line, and that it is not part of `mcp_calls`.
- Cost sizing from the pinned prices at `openai_mcp.py:35` — roughly $0.015–0.02 per 12-turn session, so the 452-row route E grid is **≈$7–9** and the default `--max-cost-usd 3.0` funds about a third of it. State plainly that raising the budget is an operator decision, and that a capped run now stops at a representative prefix rather than a banking-only one.
- The free verification commands from Steps 5 and 6 below.

- [ ] **Step 4: Copy this plan into the repo**

```bash
cp /home/hismajesty/.claude/plans/pure-forging-pinwheel.md \
   docs/superpowers/plans/2026-08-08-gpt4omini-capture-fixes.md
```

- [ ] **Step 5: Run the full suite**

```bash
cd /tmp/chainwatch-gpt4omini-capture
/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python -m pytest tests/ -q
```

Expected: **306 + the new tests**, all passing, zero failures. If anything that existed before this plan now fails, stop and fix it — none of these changes may alter §V-B conformance, proxy, bridge or ML behaviour.

- [ ] **Step 6: Re-run the free end-to-end chain probe**

No API cost. This drives the real `npx mcpwall -> chainwatch -> bridge` chain by hand and checks the three things the smoke depends on: EOF reaching the bridge, the score sidecar appearing, and the trace row's `server` field.

```bash
cd /tmp/chainwatch-gpt4omini-capture
PY=/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation/.venv/bin/python
T=$(mktemp -d); mkdir -p "$T/logs" "$T/home"
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_iban","arguments":{}}}' \
 | env -i PATH="$PATH" HOME="$T/home" PYTHONPATH="$PWD" CHAINWATCH_SESSION=probe \
   timeout 180 npx -y mcpwall -- "$PY" -m chainwatch \
     --server banking --observe-only --no-daemon \
     --label benign --source probe --model gpt-4o-mini-2024-07-18 \
     --log-args --log-dir "$T/logs" -- \
     "$PY" -m agentdojo_bridge.env_mcp_server --suite banking \
       --user-task user_task_0 --score-out "$T/score.json" >/dev/null 2>"$T/err"
cat "$T/score.json"; echo
"$PY" -c "import json,glob;print(json.loads(open(glob.glob('$T/logs/*.jsonl')[0]).readline())['server'])"
```

Expected: a score sidecar containing `"calls": 1`, then the trace row's server printed as **`banking`** — not `score.json`.

- [ ] **Step 7: Commit**

```bash
git add CLAUDE.md AGENT.md docs/traffic_recipes.md \
        docs/superpowers/plans/2026-08-08-gpt4omini-capture-fixes.md
git commit -m "docs(capture): record the GPT-4o-mini executor's limitations and fixed defects"
```

---

## Verification

Run all of these from `/tmp/chainwatch-gpt4omini-capture` after Task 8. None costs API credit.

| # | Command | Expected |
|---|---|---|
| 1 | `.venv/bin/python -m pytest tests/ -q` | 306 + new tests, 0 failures |
| 2 | `python scripts/capture_agentdojo_openai.py --dry-run --limit 8 \| jq -r '.chain_argv[(.chain_argv \| index("--server")) + 1]' \| sort -u` | more than one suite name; never `score.json` |
| 3 | `python scripts/capture_injecagent_openai.py --dry-run --limit 6 \| jq -r '.chain_argv[(.chain_argv \| index("--server")) + 1]' \| sort -u` | exactly `injecagent-dev` |
| 4 | `python scripts/capture_agentdojo_openai.py --dry-run --suite workspace --limit 3` | 3 rows, all `"suite":"workspace"` |
| 5 | Task 8 Step 6 chain probe | sidecar `"calls": 1`; trace `server` is `banking` |
| 6 | `python scripts/capture_agentdojo_openai.py --limit 1` (no `--confirm-api-usage`) | non-zero exit: `live API usage requires --confirm-api-usage` |
| 7 | `bash -n scripts/capture_agentdojo.sh && bash -n scripts/capture_injecagent.sh` | clean |
| 8 | `git status --short` | clean tree; 8 commits on `feat/gpt4omini-capture` |

**Not part of this plan:** the paid smoke run itself. Every task above is free, and no live OpenAI request may be made until the operator asks for one separately.
