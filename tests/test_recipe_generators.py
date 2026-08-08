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
