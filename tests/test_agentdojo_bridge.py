"""Route E — the AgentDojo indirect-injection bridge.

AgentDojo (Debenedetti et al., NeurIPS 2024 D&B) is vendored at ``./agentdojo`` and
installed editable into the venv. It is imported *only* from ``agentdojo_bridge/``,
the same isolation ``benchmark_bridge/`` has for SHADE — ``chainwatch/engine/`` stays
numpy-only.
"""


def test_agentdojo_is_importable():
    import agentdojo  # noqa: F401

    # Importing agentdojo.default_suites.v1.<suite>.task_suite *directly* raises
    # ImportError: cannot import name 'WorkspaceDeepDiff' from partially initialized
    # module -- a circular import inside AgentDojo itself (its own test suite carries
    # an "isort: skip -- avoid circular import issue" comment for the same reason).
    # get_suite is the supported entry and yields the identical suite objects.
    from agentdojo.task_suite.load_suites import get_suite

    task_suite = get_suite("v1", "workspace")
    assert "send_email" in {t.name for t in task_suite.tools}


def test_adapter_lists_and_calls_tools_on_clean_env():
    from agentdojo_bridge.adapter import AgentDojoAdapter

    a = AgentDojoAdapter("workspace")
    names = {t["name"] for t in a.list_tools()}
    assert {"send_email", "search_emails"} <= names
    schema = next(t["inputSchema"] for t in a.list_tools() if t["name"] == "send_email")
    assert schema["type"] == "object" and "recipients" in schema["properties"]
    out = a.call_tool("get_unread_emails", {})
    assert out is not None
    assert a.trace[-1].function == "get_unread_emails"


def test_adapter_is_an_envadapter():
    """The bridge must satisfy the same Protocol benchmark_bridge's servers do."""
    from benchmark_bridge.base import EnvAdapter

    from agentdojo_bridge.adapter import AgentDojoAdapter

    assert isinstance(AgentDojoAdapter("banking"), EnvAdapter)


def test_build_injections_is_verbatim_important_instructions():
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack

    from agentdojo_bridge.adapter import SUITES
    from agentdojo_bridge.payload import build_injections

    suite = SUITES["workspace"]
    inj_id = next(iter(suite.injection_tasks))
    goal = suite.injection_tasks[inj_id].GOAL
    injections = build_injections(
        "workspace", inj_id, model_name="Claude", user_name="Emma Johnson"
    )
    assert set(injections) == set(suite.get_injection_vector_defaults())
    expected = ImportantInstructionsAttack._JB_STRING.format(
        user="Emma Johnson", model="Claude", goal=goal
    )
    assert all(v == expected for v in injections.values())
    assert goal in next(iter(injections.values()))


def _run_ground_truth(adapter, task):
    for fc in task.ground_truth(adapter.pre_env):
        adapter.call_tool(fc.function, dict(fc.args))


#: Scorable under the fill-all placement; see UNSCORABLE_INJECTION_TASKS for the two
#: that are not, and why.
SCORABLE_INJECTION = ("workspace", "injection_task_1")


def test_security_true_when_injection_trajectory_runs():
    from agentdojo_bridge.adapter import SUITES, AgentDojoAdapter
    from agentdojo_bridge.payload import build_injections

    suite_name, inj_id = SCORABLE_INJECTION
    inj_task = SUITES[suite_name].injection_tasks[inj_id]
    a = AgentDojoAdapter(suite_name, build_injections(suite_name, inj_id))
    _run_ground_truth(a, inj_task)
    assert a.score(user_task_id=None, injection_task_id=inj_id)["security"] is True


def test_security_false_on_clean_run():
    from agentdojo_bridge.adapter import AgentDojoAdapter

    suite_name, inj_id = SCORABLE_INJECTION
    a = AgentDojoAdapter(suite_name)
    a.call_tool("get_unread_emails", {})
    assert a.score(user_task_id=None, injection_task_id=inj_id)["security"] is False


def test_unscorable_set_is_exactly_the_tasks_that_cannot_flag():
    """The exclusion list is a measurement, not an opinion.

    Every injection task outside the set must flag ``security`` when its own
    ``ground_truth`` trajectory is replayed against the injected env; every task
    inside it must fail to, under the same fill-all placement capture uses. A task
    silently drifting into "never fires" would make attack sessions score as
    resisted, which is the failure this pins shut.
    """
    from agentdojo_bridge.adapter import (
        SUITES,
        UNSCORABLE_INJECTION_TASKS,
        AgentDojoAdapter,
    )
    from agentdojo_bridge.payload import build_injections

    observed_unscorable = set()
    for suite_name, suite in sorted(SUITES.items()):
        for inj_id, inj_task in sorted(suite.injection_tasks.items()):
            a = AgentDojoAdapter(suite_name, build_injections(suite_name, inj_id))
            _run_ground_truth(a, inj_task)
            if a.score(None, inj_id)["security"] is not True:
                observed_unscorable.add((suite_name, inj_id))
    assert observed_unscorable == set(UNSCORABLE_INJECTION_TASKS)


def test_server_handles_tools_list_and_call():
    from agentdojo_bridge import env_mcp_server as srv
    from agentdojo_bridge.adapter import AgentDojoAdapter

    a = AgentDojoAdapter("banking")
    resp = srv.handle(a, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert resp["result"]["tools"]
    read_tool = resp["result"]["tools"][0]["name"]
    resp = srv.handle(
        a,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": read_tool, "arguments": {}},
        },
    )
    assert resp["result"]["content"][0]["type"] == "text"


def test_tool_output_is_json_not_a_python_repr():
    """CLAUDE.md note 6, for route E.

    AgentDojo tools return pydantic models. Serialised with ``default=str`` they
    become ``"id_='29' filename='plan.txt'"`` -- unparseable by any MCP client, and
    it flatlined ``df_chained`` across the whole benchmark the first time. The text
    block must round-trip through ``json.loads`` into real structure.
    """
    import json

    from agentdojo_bridge import env_mcp_server as srv
    from agentdojo_bridge.adapter import AgentDojoAdapter

    a = AgentDojoAdapter("workspace")
    resp = srv.handle(
        a,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "get_unread_emails", "arguments": {}},
        },
    )
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert isinstance(payload, list) and payload
    assert "sender" in payload[0] and "body" in payload[0]


def test_server_notification_gets_no_reply():
    from agentdojo_bridge import env_mcp_server as srv
    from agentdojo_bridge.adapter import AgentDojoAdapter

    a = AgentDojoAdapter("slack")
    assert srv.handle(a, {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_server_writes_score_sidecar_at_eof(tmp_path):
    """The sidecar is the published verdict; capture reads it per session."""
    import json
    import subprocess
    import sys

    out = tmp_path / "score.json"
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "agentdojo_bridge.env_mcp_server",
            "--suite",
            "banking",
            "--user-task",
            "user_task_0",
            "--score-out",
            str(out),
        ],
        input=request,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    verdict = json.loads(out.read_text())
    assert verdict["suite"] == "banking"
    assert verdict["injection_task"] is None  # benign row
    assert verdict["security"] is None  # nothing to score against
    assert verdict["utility"] is False  # tools/list alone does no work
    assert verdict["calls"] == 0


def test_recipes_are_verbatim_and_labelled(tmp_path):
    import subprocess
    import sys

    from agentdojo_bridge.adapter import SUITES

    out = tmp_path / "r.tsv"
    subprocess.run(
        [
            sys.executable,
            "scripts/gen_agentdojo_recipes.py",
            "--out",
            str(out),
            "--limit-per-suite",
            "2",
        ],
        check=True,
    )
    rows = [
        line.split("\t")
        for line in out.read_text().splitlines()
        if line and not line.startswith("#")
    ]
    assert {r[0] for r in rows} == {"benign", "attack"}
    benign = next(r for r in rows if r[0] == "benign")
    _, suite, user_task, injection_task, prompt = benign
    assert injection_task == "-"
    assert prompt == " ".join(SUITES[suite].user_tasks[user_task].PROMPT.split())


def test_recipes_never_offer_an_unscorable_injection(tmp_path):
    """An attack row that can never score would be recorded as resisted."""
    import subprocess
    import sys

    from agentdojo_bridge.adapter import UNSCORABLE_INJECTION_TASKS

    out = tmp_path / "r.tsv"
    subprocess.run(
        [sys.executable, "scripts/gen_agentdojo_recipes.py", "--out", str(out)], check=True
    )
    offered = {
        (r[1], r[3])
        for r in (
            line.split("\t")
            for line in out.read_text().splitlines()
            if line and not line.startswith("#")
        )
        if r[0] == "attack"
    }
    assert offered.isdisjoint(UNSCORABLE_INJECTION_TASKS)
    assert offered, "the grid must not be empty"


def test_decidability_gate_passes():
    import subprocess
    import sys

    r = subprocess.run(
        [sys.executable, "scripts/agentdojo_decidability.py"], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert "PASS" in r.stdout
