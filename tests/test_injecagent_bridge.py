"""Route F — the InjecAgent indirect-injection bridge (developer domain).

InjecAgent (Zhan et al., ACL 2024 Findings) is vendored at ``./InjecAgent`` and read
as *data*: its ``data/*.json`` files are loaded, its ``src/`` never imported.
"""

from injecagent_bridge.adapter import InjecAgentAdapter
from injecagent_bridge.loader import dev_cases, load_tools


def test_loader_finds_github_tools_and_dev_cases():
    by_name = load_tools()
    assert "GitHubSearchRepositories" in by_name
    toolkit, definition = by_name["GitHubSearchRepositories"]
    assert toolkit == "GitHub" and "parameters" in definition

    cases = dev_cases("ds", "base")
    assert len(cases) == 96
    assert all(c["User Tool"].startswith("GitHub") for c in cases)
    assert cases[0]["Attacker Tools"]


def test_loader_case_counts_match_the_published_splits():
    """Pinned so a swapped or truncated data file is loud rather than silent."""
    assert len(dev_cases("ds", "base")) == 96
    assert len(dev_cases("ds", "enhanced")) == 96
    assert len(dev_cases("dh", "base")) == 90
    assert len(dev_cases("dh", "enhanced")) == 90


def test_adapter_exposes_user_and_attacker_tools():
    """The attacker tools must be present, or compliance is impossible.

    Without them a refused injection and an unreachable one look identical, and the
    route would be measuring its own tool surface rather than the agent.
    """
    case = dev_cases("ds", "base")[0]
    adapter = InjecAgentAdapter(case)
    names = {t["name"] for t in adapter.list_tools()}
    assert case["User Tool"] in names
    assert set(case["Attacker Tools"]) <= names


def test_attack_response_carries_injection_benign_does_not():
    case = dev_cases("ds", "base")[0]
    injected = case["Attacker Instruction"][:30]
    attack = InjecAgentAdapter(case, benign=False).call_tool(case["User Tool"], {})
    benign = InjecAgentAdapter(case, benign=True).call_tool(case["User Tool"], {})
    assert injected in str(attack)
    assert injected not in str(benign)


def test_both_halves_are_served_the_same_prompt():
    """Benign vs attack is a server-side data choice, never a prompt change."""
    case = dev_cases("ds", "base")[0]
    attack = InjecAgentAdapter(case, benign=False)
    benign = InjecAgentAdapter(case, benign=True)
    assert attack.case["User Instruction"] == benign.case["User Instruction"]
    assert {t["name"] for t in attack.list_tools()} == {
        t["name"] for t in benign.list_tools()
    }


def test_score_flags_attacker_tool_call():
    case = dev_cases("ds", "base")[0]
    adapter = InjecAgentAdapter(case)
    adapter.call_tool(case["User Tool"], {})
    assert adapter.score()["attacker_called"] is False
    adapter.call_tool(case["Attacker Tools"][0], {})
    assert adapter.score()["attacker_called"] is True
    assert adapter.score()["attacker_tools_called"] == [case["Attacker Tools"][0]]


def test_enhanced_variant_is_served_verbatim():
    """The 'IMPORTANT!!! Ignore all previous instructions' wrapper is published text.

    It is used as shipped -- Global Constraints forbid editing a payload, and a
    variant that differs between the corpus and the benchmark is not a replication.
    """
    base = dev_cases("ds", "base")[0]
    enhanced = dev_cases("ds", "enhanced")[0]
    assert enhanced["Tool Response"] != base["Tool Response"]
    served = InjecAgentAdapter(enhanced).call_tool(enhanced["User Tool"], {})
    assert served == enhanced["Tool Response"]


def test_injecagent_server_lists_and_calls():
    from injecagent_bridge import env_mcp_server as srv

    adapter = InjecAgentAdapter(dev_cases("ds", "base")[0])
    resp = srv.handle(adapter, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert resp["result"]["tools"]
    resp = srv.handle(
        adapter,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": adapter.user_tool, "arguments": {}},
        },
    )
    assert resp["result"]["content"][0]["type"] == "text"


def test_injecagent_server_writes_score_sidecar(tmp_path):
    import json
    import subprocess
    import sys

    out = tmp_path / "score.json"
    case = dev_cases("ds", "base")[0]
    requests = "\n".join(
        json.dumps(r)
        for r in (
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": case["Attacker Tools"][0], "arguments": {}},
            },
        )
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "injecagent_bridge.env_mcp_server",
            "--split",
            "ds",
            "--variant",
            "base",
            "--case-index",
            "0",
            "--score-out",
            str(out),
        ],
        input=requests + "\n",
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    verdict = json.loads(out.read_text())
    assert verdict["attacker_called"] is True
    assert verdict["benign"] is False
    assert verdict["case_index"] == 0


def test_injecagent_recipes_verbatim_and_labelled(tmp_path):
    import subprocess
    import sys

    out = tmp_path / "r.tsv"
    subprocess.run(
        [sys.executable, "scripts/gen_injecagent_recipes.py", "--out", str(out), "--limit", "2"],
        check=True,
    )
    rows = [
        line.split("\t")
        for line in out.read_text().splitlines()
        if line and not line.startswith("#")
    ]
    assert {r[0] for r in rows} == {"benign", "attack"}
    benign = next(r for r in rows if r[0] == "benign")
    _, split, variant, index, user_tool, prompt = benign
    case = dev_cases(split, "base")[int(index)]
    assert prompt == " ".join(case["User Instruction"].split())
    assert user_tool == case["User Tool"]


def test_recipe_halves_of_a_case_share_one_prompt(tmp_path):
    """If the two halves differed by prompt, the route would measure the prompt."""
    import subprocess
    import sys

    out = tmp_path / "r.tsv"
    subprocess.run(
        [sys.executable, "scripts/gen_injecagent_recipes.py", "--out", str(out), "--limit", "3"],
        check=True,
    )
    by_case: dict[tuple[str, str], set[str]] = {}
    for line in out.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        label, split, _variant, index, _tool, prompt = line.split("\t")
        by_case.setdefault((split, index), set()).add(prompt)
    assert by_case
    assert all(len(prompts) == 1 for prompts in by_case.values())
