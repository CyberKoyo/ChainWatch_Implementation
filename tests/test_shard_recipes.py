"""Shards decide which coordinates each parallel process buys.

`--resume` computes its skip set once at startup, so two processes over
overlapping rows both buy the same coordinate and `assert_no_duplicates` then
refuses every later run. Disjointness has to be a property of the files, and
checked rather than intended.
"""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import shard_recipes


ADOJO = [
    "benign\tbanking\tuser_task_0\t-\tPay the bill.\n",
    "attack\tbanking\tuser_task_0\tinjection_task_0\tPay the bill.\n",
    "attack\tbanking\tuser_task_0\tinjection_task_1\tPay the bill.\n",
    "benign\tslack\tuser_task_2\t-\tSummarise the channel.\n",
    "attack\tslack\tuser_task_2\tinjection_task_0\tSummarise the channel.\n",
    "benign\ttravel\tuser_task_1\t-\tBook the hotel.\n",
]
INJEC = [
    "benign\tdh\tbase\t0\tGitHubGetRepositoryDetails\tSummarise the repo.\n",
    "attack\tdh\tbase\t0\tGitHubGetRepositoryDetails\tSummarise the repo.\n",
    "attack\tdh\tenhanced\t0\tGitHubGetRepositoryDetails\tSummarise the repo.\n",
    "benign\tds\tbase\t4\tGitHubGetUserDetails\tSummarise the user.\n",
]


def test_every_row_survives_exactly_once():
    buckets = shard_recipes.shard(ADOJO, 3)
    assert sorted(row for bucket in buckets for row in bucket) == sorted(ADOJO)


def test_a_fold_group_never_spans_two_shards():
    buckets = shard_recipes.shard(ADOJO, 3)
    homes = {}
    for index, bucket in enumerate(buckets):
        for row in bucket:
            homes.setdefault(shard_recipes.group_key(row.rstrip("\n").split("\t")), index)
    for index, bucket in enumerate(buckets):
        for row in bucket:
            assert homes[shard_recipes.group_key(row.rstrip("\n").split("\t"))] == index


def test_injecagent_groups_bind_base_to_enhanced():
    assert shard_recipes.group_key(INJEC[1].rstrip("\n").split("\t")) == \
           shard_recipes.group_key(INJEC[2].rstrip("\n").split("\t"))
    assert shard_recipes.group_key(INJEC[0].rstrip("\n").split("\t")) != \
           shard_recipes.group_key(INJEC[3].rstrip("\n").split("\t"))


def test_comment_and_blank_lines_are_not_data():
    buckets = shard_recipes.shard(["# GENERATED\n", "\n", *ADOJO], 2)
    assert all(not row.startswith("#") and row.strip() for bucket in buckets for row in bucket)
    assert sum(len(bucket) for bucket in buckets) == len(ADOJO)


def test_an_unrecognised_row_width_is_an_error_not_a_guess():
    with pytest.raises(ValueError, match="4 columns"):
        shard_recipes.group_key(["benign", "banking", "user_task_0", "-"])


def test_the_cli_writes_disjoint_files_that_reassemble_the_input(tmp_path):
    source = tmp_path / "recipes.tsv"
    source.write_text("# GENERATED\n" + "".join(ADOJO), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(Path(shard_recipes.__file__)), str(source),
         "--shards", "3", "--out-dir", str(tmp_path / "out")],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    written = sorted((tmp_path / "out").glob("recipes_shard*.tsv"))
    assert len(written) == 3
    rejoined = sorted(line for path in written
                      for line in path.read_text(encoding="utf-8").splitlines(keepends=True)
                      if not line.startswith("#"))
    assert rejoined == sorted(ADOJO)
