"""Every capture driver must name its MCP server explicitly.

chainwatch/proxy/__main__.py falls back to the last argv token, which is a score-file
path on one half of a route and `--benign` on the other. ml/dataset.py reads that field
as the leave-one-environment-out environment, so the fallback puts the two classes in
disjoint environments. A grep-shaped test is the right shape here: these drivers build
their argv inside an embedded heredoc that cannot be imported.
"""

from __future__ import annotations

import json
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


def test_dry_run_reports_selection_without_touching_the_api(tmp_path, capsys):
    """A selection bug must be free to find. Dry run constructs no client and
    writes no state -- notes 14 and 20 are both 'a run that did nothing exited 0'."""
    import scripts.capture_agentdojo_openai as driver

    recipes = tmp_path / "r.tsv"
    recipes.write_text(
        "# GENERATED\n# cols\n"
        "benign\tbanking\tuser_task_0\t-\tdo the thing\n"
        "attack\tbanking\tuser_task_0\tinjection_task_0\tdo the thing\n",
        encoding="utf-8",
    )
    assert driver.main([str(recipes), "--dry-run", "--corpus-revision", "v2",
                        "--state-dir", str(tmp_path / "state")]) == 0
    lines = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith("{")]
    assert len(lines) == 2
    assert {line["selected"] for line in lines} == {True}
    assert not (tmp_path / "state").exists(), "a dry run owns no state on disk"


def test_a_recipe_coordinate_matches_the_score_row_it_will_produce():
    """A benign recipe spells its injection task '-' and its score sidecar spells
    it None. Compare the two raw and --resume silently re-buys the benign half."""
    import scripts.capture_agentdojo_openai as driver
    from chainwatch.capture import manifest

    recipe = driver.AgentDojoRecipe("benign", "banking", "user_task_0", "-", "do it")
    sidecar = {"label": "benign", "suite": "banking", "user_task": "user_task_0",
               "injection_task": None}
    assert driver.recipe_coordinate(recipe) == manifest.coordinate(sidecar)


def test_resume_skips_a_completed_coordinate_and_keeps_an_incomplete_one(tmp_path):
    """Resume skips only what is complete under this exact configuration."""
    import scripts.capture_agentdojo_openai as driver
    from chainwatch.capture import manifest

    path = tmp_path / "manifest.jsonl"
    done = {"label": "benign", "suite": "banking", "user_task": "user_task_0",
            "injection_task": None}
    manifest.append_entry(path, manifest.ManifestEntry(
        coordinate=manifest.coordinate(done), fold_group=manifest.fold_group(done),
        session="s1", source="agentdojo-gpt4omini", fingerprint="fp",
        corpus_revision="v2", git_commit="abc", native={}, calls=3,
        cost_usd=0.0007, status="completed"))

    skipped = driver.resolve_resume_skips(path, fingerprint="fp")
    assert manifest.coordinate(done) in skipped
    assert driver.resolve_resume_skips(path, fingerprint="other") == set()


def test_duplicate_completed_coordinates_are_a_hard_error(tmp_path):
    import scripts.capture_agentdojo_openai as driver
    from chainwatch.capture import manifest

    path = tmp_path / "manifest.jsonl"
    row = {"label": "benign", "suite": "banking", "user_task": "user_task_0",
           "injection_task": None}
    entry = manifest.ManifestEntry(
        coordinate=manifest.coordinate(row), fold_group=manifest.fold_group(row),
        session="s1", source="agentdojo-gpt4omini", fingerprint="fp",
        corpus_revision="v2", git_commit="abc", native={}, calls=3,
        cost_usd=0.0007, status="completed")
    manifest.append_entry(path, entry)
    manifest.append_entry(path, manifest.ManifestEntry(**{**entry.__dict__, "session": "s2"}))
    with pytest.raises(SystemExit):
        driver.assert_no_duplicates(path)


def test_group_selection_takes_whole_task_groups_never_a_row_prefix(tmp_path, capsys):
    """A row prefix leaves a fold group whose benign half is a different task
    from its attack half -- a group with one side missing."""
    import scripts.capture_agentdojo_openai as driver

    recipes = tmp_path / "r.tsv"
    recipes.write_text(
        "benign\tbanking\tuser_task_0\t-\ta\n"
        "attack\tbanking\tuser_task_0\tinjection_task_0\ta\n"
        "benign\tbanking\tuser_task_1\t-\tb\n"
        "attack\tbanking\tuser_task_1\tinjection_task_0\tb\n",
        encoding="utf-8",
    )
    assert driver.main([str(recipes), "--dry-run", "--corpus-revision", "v2",
                        "--groups-per-partition", "1",
                        "--state-dir", str(tmp_path / "state")]) == 0
    lines = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.startswith("{")]
    assert len(lines) == 2, "one whole group, both of its rows"
    assert {line["user_task"] for line in lines} == {"user_task_0"}


def test_both_drivers_expose_the_same_grid_options():
    """Note 33's rule: the two halves must differ by task alone."""
    import scripts.capture_agentdojo_openai as agentdojo
    import scripts.capture_injecagent_openai as injecagent

    wanted = {"corpus_revision", "groups_per_partition", "resume", "require_clean_git"}
    for module in (agentdojo, injecagent):
        options = {action.dest for action in module._parser()._actions}
        assert wanted <= options, f"{module.__name__} is missing {wanted - options}"
