"""GPT-4o-mini capture runner contracts.

The OpenAI client is the only fake: network access is external and forbidden in the
test suite. MCP is a real subprocess speaking newline JSON-RPC through the same
transport used by captures.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from chainwatch.capture.openai_mcp import (
    DEFAULT_EXECUTOR,
    CaptureBudget,
    MCPError,
    MCPProcess,
    SessionSpec,
    build_capture_child_env,
    build_mcpwall_chain_argv,
    new_capture_run_id,
    openai_tool_from_mcp_tool,
    publish_session_traces,
    quarantine_session_traces,
    run_session,
)


MODEL = "gpt-4o-mini-2024-07-18"
STUB = Path(__file__).with_name("stub_mcp_server.py")


def _completion(
    *,
    model: str = MODEL,
    content: str | None = None,
    tool_calls: list[tuple[str, str, str]] | None = None,
    prompt_tokens: int = 10,
    completion_tokens: int = 2,
    cached_tokens: int = 0,
):
    calls = None
    if tool_calls is not None:
        calls = [
            SimpleNamespace(
                id=call_id,
                type="function",
                function=SimpleNamespace(name=name, arguments=arguments),
            )
            for call_id, name, arguments in tool_calls
        ]
    message = SimpleNamespace(role="assistant", content=content, tool_calls=calls)
    usage = SimpleNamespace(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        prompt_tokens_details=SimpleNamespace(cached_tokens=cached_tokens),
    )
    return SimpleNamespace(model=model, choices=[SimpleNamespace(message=message)], usage=usage)


class _FakeCompletions:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests: list[dict] = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class _FakeOpenAI:
    def __init__(self, responses):
        self.chat = SimpleNamespace(completions=_FakeCompletions(responses))


def _spec(tmp_path: Path, *, env: dict[str, str] | None = None, max_turns: int = 12):
    return SessionSpec(
        session_id="session-001",
        label="attack",
        source="agentdojo-gpt4omini",
        requested_model=MODEL,
        prompt="Read the environment and report the configured region.",
        chain_argv=[sys.executable, str(STUB)],
        env=env,
        transcript_path=tmp_path / "transcript.jsonl",
        usage_path=tmp_path / "usage.jsonl",
        max_turns=max_turns,
        max_output_tokens=512,
    )


def _score_env(tmp_path: Path) -> tuple[dict[str, str], Path]:
    score = tmp_path / "score.json"
    env = dict(os.environ)
    env["STUB_SCORE_OUT"] = str(score)
    return env, score


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


def test_capture_child_environment_is_allowlisted_and_uses_neutral_home(tmp_path):
    parent = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "SSL_CERT_FILE": "/etc/ssl/cert.pem",
        "PYTHONPATH": "/untrusted/parent/path",
        "OPENAI_API_KEY": "openai-secret",
        "ANTHROPIC_API_KEY": "anthropic-secret",
        "AWS_SECRET_ACCESS_KEY": "aws-secret",
        "GITHUB_TOKEN": "github-secret",
    }

    env = build_capture_child_env(
        parent,
        repo_root=tmp_path / "repo",
        neutral_home=tmp_path / "home",
        session_id="session-001",
    )

    assert env["PATH"] == "/usr/bin:/bin"
    assert env["LANG"] == "C.UTF-8"
    assert env["SSL_CERT_FILE"] == "/etc/ssl/cert.pem"
    assert env["PYTHONPATH"] == str(tmp_path / "repo")
    assert env["HOME"] == str(tmp_path / "home")
    assert env["CHAINWATCH_SESSION"] == "session-001"
    assert env["NPM_CONFIG_CACHE"] == str(tmp_path / "home" / ".npm-cache")
    assert not any("secret" in value for value in env.values())


def test_tool_conversion_preserves_schema_and_supplies_empty_description():
    schema = {
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    }

    converted = openai_tool_from_mcp_tool({"name": "fetch", "inputSchema": schema})

    assert converted == {
        "type": "function",
        "function": {"name": "fetch", "description": "", "parameters": schema},
    }


def test_mcp_process_initializes_calls_tool_and_drains_eof_sidecar(tmp_path):
    env, score_path = _score_env(tmp_path)
    process = MCPProcess([sys.executable, str(STUB)], env=env)

    tools = process.initialize()
    result = process.call_tool("read_env", {})
    exit_code = process.close()

    assert [tool["name"] for tool in tools] == ["read_env", "post_to_webhook"]
    assert result == {"content": "AWS_SECRET=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"}
    assert exit_code == 0
    assert json.loads(score_path.read_text(encoding="utf-8"))["calls"] == 1


def test_mcp_process_times_out_when_server_never_replies(tmp_path):
    env = dict(os.environ)
    env["STUB_NO_REPLY_METHOD"] = "tools/list"
    process = MCPProcess(
        [sys.executable, str(STUB)],
        env=env,
        request_timeout_seconds=2.0,
    )

    try:
        with pytest.raises(MCPError, match="timed out waiting for tools/list"):
            process.initialize()
    finally:
        process.close()


def test_tool_loop_records_resolved_model_usage_and_real_mcp_call(tmp_path):
    env, score_path = _score_env(tmp_path)
    client = _FakeOpenAI(
        [
            _completion(
                tool_calls=[("call-1", "read_env", "{}")],
                prompt_tokens=20,
                completion_tokens=4,
                cached_tokens=5,
            ),
            _completion(content="The region is configured.", prompt_tokens=30, completion_tokens=6),
        ]
    )

    result = run_session(_spec(tmp_path, env=env), openai_client=client)

    assert result.status == "completed"
    assert result.calls == 1
    assert result.requested_model == MODEL
    assert result.resolved_model == MODEL
    assert result.prompt_tokens == 50
    assert result.completion_tokens == 10
    assert result.cached_tokens == 5
    expected = ((45 * 0.15) + (5 * 0.075) + (10 * 0.60)) / 1_000_000
    assert result.estimated_cost_usd == pytest.approx(expected)
    assert json.loads(score_path.read_text(encoding="utf-8"))["calls"] == 1

    usage = [json.loads(line) for line in (tmp_path / "usage.jsonl").read_text().splitlines()]
    assert [entry["type"] for entry in usage] == ["response", "response", "session"]
    assert usage[0]["resolved_model"] == MODEL
    assert usage[-1]["executor"] == DEFAULT_EXECUTOR


def test_multiple_tool_calls_in_one_response_are_all_forwarded(tmp_path):
    env, score_path = _score_env(tmp_path)
    client = _FakeOpenAI(
        [
            _completion(
                tool_calls=[
                    ("call-1", "read_env", "{}"),
                    ("call-2", "post_to_webhook", '{"url":"https://example.test"}'),
                ]
            ),
            _completion(content="Done."),
        ]
    )

    result = run_session(_spec(tmp_path, env=env), openai_client=client)

    assert result.status == "completed"
    assert result.calls == 2
    assert json.loads(score_path.read_text(encoding="utf-8"))["calls"] == 2


def test_invalid_tool_json_returns_error_to_model_without_calling_mcp(tmp_path):
    env, score_path = _score_env(tmp_path)
    client = _FakeOpenAI(
        [
            _completion(tool_calls=[("call-bad", "read_env", "{not-json")]),
            _completion(content="I could not construct valid arguments."),
        ]
    )

    result = run_session(_spec(tmp_path, env=env), openai_client=client)

    assert result.status == "completed"
    assert result.calls == 0
    assert json.loads(score_path.read_text(encoding="utf-8"))["calls"] == 0
    transcript = [
        json.loads(line) for line in (tmp_path / "transcript.jsonl").read_text().splitlines()
    ]
    error = next(entry for entry in transcript if entry["type"] == "tool_argument_error")
    assert error["tool"] == "read_env"
    assert error["tool_call_id"] == "call-bad"


def test_model_mismatch_stops_before_forwarding_tool_call(tmp_path):
    env, score_path = _score_env(tmp_path)
    client = _FakeOpenAI(
        [
            _completion(
                model="gpt-4o-mini-remapped",
                tool_calls=[("call-1", "read_env", "{}")],
            )
        ]
    )

    result = run_session(_spec(tmp_path, env=env), openai_client=client)

    assert result.status == "model_mismatch"
    assert result.calls == 0
    assert result.resolved_model == "gpt-4o-mini-remapped"
    assert json.loads(score_path.read_text(encoding="utf-8"))["calls"] == 0


def test_turn_limit_ends_session_after_bounded_number_of_responses(tmp_path):
    env, score_path = _score_env(tmp_path)
    client = _FakeOpenAI([_completion(tool_calls=[("call-1", "read_env", "{}")])])

    result = run_session(_spec(tmp_path, env=env, max_turns=1), openai_client=client)

    assert result.status == "max_turns"
    assert result.calls == 1
    assert json.loads(score_path.read_text(encoding="utf-8"))["calls"] == 1


def test_exhausted_budget_makes_no_model_request_and_still_closes_server(tmp_path):
    env, score_path = _score_env(tmp_path)
    client = _FakeOpenAI([_completion(content="This response must remain unused.")])

    result = run_session(
        _spec(tmp_path, env=env),
        openai_client=client,
        budget=CaptureBudget(limit_usd=0.0),
    )

    assert result.status == "budget_exhausted"
    assert result.prompt_tokens == 0
    assert result.completion_tokens == 0
    assert json.loads(score_path.read_text(encoding="utf-8"))["calls"] == 0


def test_api_error_does_not_leak_key_and_key_is_removed_from_mcp_environment(tmp_path):
    env, score_path = _score_env(tmp_path)
    secret = "sk-test-this-must-never-be-written"
    env["OPENAI_API_KEY"] = secret
    client = _FakeOpenAI([RuntimeError(f"upstream failed while using {secret}")])

    result = run_session(_spec(tmp_path, env=env), openai_client=client)

    assert result.status == "api_error"
    assert result.error == "OpenAI request failed"
    score = json.loads(score_path.read_text(encoding="utf-8"))
    assert score == {"calls": 0, "has_openai_api_key": False}
    assert secret not in (tmp_path / "transcript.jsonl").read_text(encoding="utf-8")
    assert secret not in (tmp_path / "usage.jsonl").read_text(encoding="utf-8")


def test_run_session_cannot_construct_a_live_client_implicitly(tmp_path):
    with pytest.raises(TypeError, match="openai_client"):
        run_session(_spec(tmp_path))


def test_capture_run_ids_are_collision_resistant_and_sortable():
    first = new_capture_run_id()
    second = new_capture_run_id()

    assert first != second
    assert first[:8].isdigit()
    assert first.count("-") == 3


def test_nonzero_mcp_shutdown_rejects_otherwise_completed_session(tmp_path):
    env, score_path = _score_env(tmp_path)
    env["STUB_EXIT_CODE"] = "7"
    client = _FakeOpenAI([_completion(content="Done.")])

    result = run_session(_spec(tmp_path, env=env), openai_client=client)

    assert score_path.is_file()
    assert result.status == "mcp_error"
    assert result.error == "MCP session exited with status 7"


def _write_staged_trace(path, *, session="session-1", source="route-gpt", model=MODEL):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "session": session,
                "source": source,
                "model": model,
                "tool": "read_file",
            }
        )
        + "\n",
        encoding="utf-8",
    )


def test_publish_session_traces_validates_then_moves_rows_into_corpus(tmp_path):
    staging = tmp_path / "staging"
    staged_trace = staging / "2026-08-08.jsonl"
    final_logs = tmp_path / "logs"
    _write_staged_trace(staged_trace)

    calls = publish_session_traces(
        staging,
        final_logs,
        session_id="session-1",
        source="route-gpt",
        model=MODEL,
    )

    assert calls == 1
    assert json.loads((final_logs / "session-1.jsonl").read_text())[
        "session"
    ] == "session-1"
    assert not staged_trace.exists()
    assert staged_trace.with_suffix(".jsonl.published").is_file()


def test_publish_session_traces_refuses_to_duplicate_an_existing_session(tmp_path):
    staging = tmp_path / "staging"
    staged_trace = staging / "2026-08-08.jsonl"
    final_logs = tmp_path / "logs"
    _write_staged_trace(staged_trace)
    final_logs.mkdir()
    destination = final_logs / "session-1.jsonl"
    destination.write_text('{"existing":true}\n', encoding="utf-8")

    with pytest.raises(FileExistsError, match="already published"):
        publish_session_traces(
            staging,
            final_logs,
            session_id="session-1",
            source="route-gpt",
            model=MODEL,
        )

    assert destination.read_text(encoding="utf-8") == '{"existing":true}\n'
    assert staged_trace.is_file()


def test_publish_session_traces_rejects_false_model_metadata(tmp_path):
    staging = tmp_path / "staging"
    staged_trace = staging / "2026-08-08.jsonl"
    final_logs = tmp_path / "logs"
    _write_staged_trace(staged_trace, model="gpt-4o-mini")

    with pytest.raises(ValueError, match="unexpected model"):
        publish_session_traces(
            staging,
            final_logs,
            session_id="session-1",
            source="route-gpt",
            model=MODEL,
        )

    assert not final_logs.exists()
    assert staged_trace.is_file()


def test_publish_session_traces_rejects_missing_expected_calls(tmp_path):
    staging = tmp_path / "staging"
    staged_trace = staging / "2026-08-08.jsonl"
    final_logs = tmp_path / "logs"
    _write_staged_trace(staged_trace)

    with pytest.raises(ValueError, match="expected 2 trace rows, found 1"):
        publish_session_traces(
            staging,
            final_logs,
            session_id="session-1",
            source="route-gpt",
            model=MODEL,
            expected_calls=2,
        )

    assert not final_logs.exists()
    assert staged_trace.is_file()


def test_quarantine_session_traces_keeps_failed_capture_out_of_jsonl_globs(tmp_path):
    staging = tmp_path / "staging"
    staged_trace = staging / "2026-08-08.jsonl"
    _write_staged_trace(staged_trace)

    quarantine_session_traces(staging)

    assert list(staging.glob("*.jsonl")) == []
    assert staged_trace.with_suffix(".jsonl.rejected").is_file()
