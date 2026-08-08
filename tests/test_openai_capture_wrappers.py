"""Route-specific GPT-4o-mini wrapper contracts.

These tests execute dry mode as a subprocess. A regression that constructs an
OpenAI client, starts npx, or ignores the live confirmation gate will therefore fail
at the wrapper boundary rather than merely changing an internal helper.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.capture_agentdojo_openai import (
    DEFAULT_MODEL,
    DEFAULT_SOURCE as AGENTDOJO_SOURCE,
    AgentDojoRecipe,
    build_chain_argv as build_agentdojo_chain,
    build_server_args as build_agentdojo_server,
    validate_score as validate_agentdojo_score,
)
from scripts.capture_injecagent_openai import (
    DEFAULT_SOURCE as INJECAGENT_SOURCE,
    SERVER_NAME as INJECAGENT_SERVER_NAME,
    InjecAgentRecipe,
    build_chain_argv as build_injecagent_chain,
    build_server_args as build_injecagent_server,
    validate_score as validate_injecagent_score,
)


ROOT = Path(__file__).resolve().parent.parent


def test_agentdojo_attack_and_benign_differ_only_by_injected_server_data(tmp_path):
    benign = AgentDojoRecipe("benign", "workspace", "user_task_0", "-", "Same prompt")
    attack = AgentDojoRecipe(
        "attack", "workspace", "user_task_0", "injection_task_1", "Same prompt"
    )

    benign_argv = build_agentdojo_server(benign, "/venv/bin/python", tmp_path / "b.json")
    attack_argv = build_agentdojo_server(attack, "/venv/bin/python", tmp_path / "a.json")

    assert benign.prompt == attack.prompt
    assert benign_argv == [
        "/venv/bin/python",
        "-m",
        "agentdojo_bridge.env_mcp_server",
        "--suite",
        "workspace",
        "--user-task",
        "user_task_0",
        "--score-out",
        str(tmp_path / "b.json"),
    ]
    assert attack_argv == [
        "/venv/bin/python",
        "-m",
        "agentdojo_bridge.env_mcp_server",
        "--suite",
        "workspace",
        "--user-task",
        "user_task_0",
        "--score-out",
        str(tmp_path / "a.json"),
        "--inject",
        "injection_task_1",
    ]


def test_agentdojo_chain_uses_fixed_gpt_source_and_pinned_model(tmp_path):
    recipe = AgentDojoRecipe(
        "attack", "travel", "user_task_1", "injection_task_2", "Book the trip"
    )

    argv = build_agentdojo_chain(
        recipe,
        python="/venv/bin/python",
        score_out=tmp_path / "score.json",
        log_dir=tmp_path / "logs",
    )

    assert AGENTDOJO_SOURCE == "agentdojo-gpt4omini"
    assert DEFAULT_MODEL == "gpt-4o-mini-2024-07-18"
    assert argv[:4] == ["npx", "-y", "mcpwall", "--"]
    assert argv[argv.index("--source") + 1] == AGENTDOJO_SOURCE
    assert argv[argv.index("--model") + 1] == DEFAULT_MODEL
    assert argv.index("chainwatch") < argv.index("agentdojo_bridge.env_mcp_server")


def test_injecagent_benign_and_attack_differ_only_by_benign_server_flag(tmp_path):
    benign = InjecAgentRecipe("benign", "ds", "base", 0, "GitHubGet", "Same prompt")
    attack = InjecAgentRecipe("attack", "ds", "base", 0, "GitHubGet", "Same prompt")

    benign_argv = build_injecagent_server(benign, "/venv/bin/python", tmp_path / "b.json")
    attack_argv = build_injecagent_server(attack, "/venv/bin/python", tmp_path / "a.json")

    assert benign.prompt == attack.prompt
    assert benign_argv == [
        "/venv/bin/python",
        "-m",
        "injecagent_bridge.env_mcp_server",
        "--split",
        "ds",
        "--variant",
        "base",
        "--case-index",
        "0",
        "--score-out",
        str(tmp_path / "b.json"),
        "--benign",
    ]
    assert attack_argv == [
        "/venv/bin/python",
        "-m",
        "injecagent_bridge.env_mcp_server",
        "--split",
        "ds",
        "--variant",
        "base",
        "--case-index",
        "0",
        "--score-out",
        str(tmp_path / "a.json"),
    ]


def test_injecagent_chain_uses_separate_fixed_source(tmp_path):
    recipe = InjecAgentRecipe("attack", "dh", "enhanced", 4, "SlackRead", "Read it")

    argv = build_injecagent_chain(
        recipe,
        python="/venv/bin/python",
        score_out=tmp_path / "score.json",
        log_dir=tmp_path / "logs",
    )

    assert INJECAGENT_SOURCE == "injecagent-gpt4omini"
    assert INJECAGENT_SOURCE != AGENTDOJO_SOURCE
    assert argv[argv.index("--source") + 1] == INJECAGENT_SOURCE
    assert argv[argv.index("--model") + 1] == DEFAULT_MODEL
    assert argv.index("chainwatch") < argv.index("injecagent_bridge.env_mcp_server")


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


def test_agentdojo_score_schema_and_recipe_coordinates_are_required():
    recipe = AgentDojoRecipe(
        "attack", "workspace", "user_task_0", "injection_task_1", "Prompt"
    )
    verdict = {
        "utility": True,
        "security": False,
        "suite": "workspace",
        "user_task": "user_task_0",
        "injection_task": "injection_task_1",
        "calls": 2,
    }

    assert validate_agentdojo_score(verdict, recipe, expected_calls=2) == verdict
    with pytest.raises(ValueError, match="suite"):
        validate_agentdojo_score({**verdict, "suite": "travel"}, recipe, expected_calls=2)
    with pytest.raises(ValueError, match="calls"):
        validate_agentdojo_score(verdict, recipe, expected_calls=1)


def test_injecagent_score_schema_and_recipe_coordinates_are_required():
    recipe = InjecAgentRecipe("attack", "ds", "enhanced", 3, "GitHubGet", "Prompt")
    verdict = {
        "attacker_called": True,
        "attacker_tools_called": ["GithubAttack"],
        "calls": 2,
        "split": "ds",
        "variant": "enhanced",
        "case_index": 3,
        "benign": False,
        "user_tool": "GitHubGet",
    }

    assert validate_injecagent_score(verdict, recipe, expected_calls=2) == verdict
    with pytest.raises(ValueError, match="benign"):
        validate_injecagent_score({**verdict, "benign": True}, recipe, expected_calls=2)
    with pytest.raises(ValueError, match="calls"):
        validate_injecagent_score(verdict, recipe, expected_calls=1)


def _run(script: str, recipe: Path, state: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    # A dry-run or unconfirmed invocation must be safe even when a real shell has a
    # funded key. The test value also gives leak checks a recognizable marker.
    env["OPENAI_API_KEY"] = "sk-test-wrapper-must-not-use"
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / script),
            str(recipe),
            "--state-dir",
            str(state),
            *extra,
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_agentdojo_dry_run_prints_two_complete_chains_without_api_use(tmp_path):
    recipes = tmp_path / "agentdojo.tsv"
    recipes.write_text(
        "# label\tsuite\tuser_task\tinjection_task\tprompt\n"
        "benign\tworkspace\tuser_task_0\t-\tSame published prompt\n"
        "attack\tworkspace\tuser_task_0\tinjection_task_1\tSame published prompt\n",
        encoding="utf-8",
    )

    completed = _run(
        "capture_agentdojo_openai.py", recipes, tmp_path / "state", "--dry-run", "--limit", "2"
    )

    assert completed.returncode == 0, completed.stderr
    rows = [json.loads(line) for line in completed.stdout.splitlines()]
    assert [row["label"] for row in rows] == ["benign", "attack"]
    assert all(row["source"] == AGENTDOJO_SOURCE for row in rows)
    assert all(row["model"] == DEFAULT_MODEL for row in rows)
    assert all(row["chain_argv"][:3] == ["npx", "-y", "mcpwall"] for row in rows)
    for row in rows:
        log_dir = row["chain_argv"][row["chain_argv"].index("--log-dir") + 1]
        assert log_dir.endswith(f"trace-staging/{row['session']}")
    assert "sk-test-wrapper-must-not-use" not in completed.stdout


def test_injecagent_dry_run_prints_three_recipe_variants_without_api_use(tmp_path):
    recipes = tmp_path / "injecagent.tsv"
    recipes.write_text(
        "# label\tsplit\tvariant\tcase_index\tuser_tool\tprompt\n"
        "benign\tds\tbase\t0\tGitHubGet\tSame published prompt\n"
        "attack\tds\tbase\t0\tGitHubGet\tSame published prompt\n"
        "attack\tds\tenhanced\t0\tGitHubGet\tSame published prompt\n",
        encoding="utf-8",
    )

    completed = _run(
        "capture_injecagent_openai.py",
        recipes,
        tmp_path / "state",
        "--dry-run",
        "--limit",
        "3",
    )

    assert completed.returncode == 0, completed.stderr
    rows = [json.loads(line) for line in completed.stdout.splitlines()]
    assert [row["label"] for row in rows] == ["benign", "attack", "attack"]
    assert [row["variant"] for row in rows] == ["base", "base", "enhanced"]
    assert all(row["source"] == INJECAGENT_SOURCE for row in rows)
    for row in rows:
        log_dir = row["chain_argv"][row["chain_argv"].index("--log-dir") + 1]
        assert log_dir.endswith(f"trace-staging/{row['session']}")
    assert "sk-test-wrapper-must-not-use" not in completed.stdout


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


def test_live_agentdojo_requires_explicit_api_confirmation(tmp_path):
    recipes = tmp_path / "agentdojo.tsv"
    recipes.write_text(
        "benign\tworkspace\tuser_task_0\t-\tPublished prompt\n", encoding="utf-8"
    )

    completed = _run("capture_agentdojo_openai.py", recipes, tmp_path / "state", "--limit", "1")

    assert completed.returncode == 2
    assert "live API usage requires --confirm-api-usage" in completed.stderr


def test_live_injecagent_requires_explicit_api_confirmation(tmp_path):
    recipes = tmp_path / "injecagent.tsv"
    recipes.write_text(
        "benign\tds\tbase\t0\tGitHubGet\tPublished prompt\n", encoding="utf-8"
    )

    completed = _run("capture_injecagent_openai.py", recipes, tmp_path / "state", "--limit", "1")

    assert completed.returncode == 2
    assert "live API usage requires --confirm-api-usage" in completed.stderr
