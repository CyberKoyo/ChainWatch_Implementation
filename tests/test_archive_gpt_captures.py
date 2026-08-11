"""The archive must be recoverable, never lossy.

Note 21's rule generalised: a tool with no competence over a population must not
delete it. Here the tool has competence and still must not delete -- the archived
sessions are the evidence section 15 rests on.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import archive_gpt_captures as archiver  # noqa: E402


def _seed(state: Path) -> Path:
    (state / "logs").mkdir(parents=True)
    trace = state / "logs" / "agentdojo-gpt4omini-x-001.jsonl"
    trace.write_text('{"session":"agentdojo-gpt4omini-x-001","v":[]}\n', encoding="utf-8")
    return trace


def test_dry_run_moves_nothing(tmp_path):
    state = tmp_path / "state"
    trace = _seed(state)

    plan = archiver.plan_archive(state, sources=("agentdojo-gpt4omini",), stamp="20260810")
    assert len(plan) == 1
    assert trace.exists(), "dry run must not move anything"


def test_apply_moves_and_records_a_verifiable_checksum(tmp_path):
    state = tmp_path / "state"
    trace = _seed(state)
    original = archiver.sha256_of(trace)

    plan = archiver.plan_archive(state, sources=("agentdojo-gpt4omini",), stamp="20260810")
    manifest_path = archiver.apply_archive(plan)

    assert not trace.exists()
    rows = [json.loads(l) for l in manifest_path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    assert rows[0]["sha256"] == original
    assert archiver.sha256_of(Path(rows[0]["archived"])) == original


def test_a_destination_collision_refuses(tmp_path):
    state = tmp_path / "state"
    _seed(state)
    archiver.apply_archive(
        archiver.plan_archive(state, sources=("agentdojo-gpt4omini",), stamp="20260810"))
    (state / "logs" / "agentdojo-gpt4omini-x-001.jsonl").write_text("{}\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        archiver.apply_archive(
            archiver.plan_archive(state, sources=("agentdojo-gpt4omini",), stamp="20260810"))


def test_an_empty_plan_is_an_error_not_a_quiet_success():
    """Note 20: a run that audited nothing must not report a clean run."""
    with pytest.raises(SystemExit):
        archiver.apply_archive([])


def test_the_archive_is_not_re_archived(tmp_path):
    """The destination lives under the state dir, so a second pass must not
    collect what the first pass moved there."""
    state = tmp_path / "state"
    _seed(state)
    archiver.apply_archive(
        archiver.plan_archive(state, sources=("agentdojo-gpt4omini",), stamp="20260810"))
    assert archiver.plan_archive(state, sources=("agentdojo-gpt4omini",),
                                 stamp="20260811") == []



def _seed_again(state: Path, name: str) -> Path:
    """Another capture generation's artifact, in the same state dir."""
    (state / "logs").mkdir(parents=True, exist_ok=True)
    trace = state / "logs" / f"agentdojo-gpt4omini-{name}-001.jsonl"
    trace.write_text('{"session":"x","v":[]}\n', encoding="utf-8")
    return trace


def test_two_generations_on_one_day_do_not_share_a_directory(tmp_path):
    """The defect this guard exists for: the destination used to vary only by date, so
    archiving v2 on the same day as pre-v2 merged both into one directory under a label
    asserting it was the first -- two corpora that must never pool, pooled by a format
    string. Per-file collision checks cannot catch it: the run ids differ, so every
    filename is free."""
    state = tmp_path / "state"
    _seed(state)

    first = archiver.plan_archive(state, sources=("agentdojo-gpt4omini",), stamp="20260810")
    second = archiver.plan_archive(
        state, sources=("agentdojo-gpt4omini",), stamp="20260810", generation="pre-v3"
    )

    assert {item["archived"] for item in first}.isdisjoint(
        item["archived"] for item in second
    )
    assert all("gpt-grid-pre-v3-20260810" in item["archived"] for item in second)


def test_apply_refuses_a_generation_directory_that_already_exists(tmp_path, capsys):
    """A second --apply into an existing generation has to say so out loud."""
    state = tmp_path / "state"
    _seed(state)
    argv = ["--state-dir", str(state), "--source", "agentdojo-gpt4omini",
            "--stamp", "20260810", "--apply"]
    assert archiver.main(argv) == 0

    _seed_again(state, "second")
    assert archiver.main(argv) == 3
    assert "generation directory already exists" in capsys.readouterr().err

    # still archivable under its own label ...
    assert archiver.main(argv[:-1] + ["--generation", "pre-v3", "--apply"]) == 0
    # ... and a second source may still join an existing generation, said explicitly
    _seed_again(state, "third")
    assert archiver.main(argv + ["--append-generation"]) == 0


def test_the_corpus_manifest_is_archived_with_its_generation(tmp_path):
    """It carries no run stamp, so the `_*-*` aggregate pattern missed it.

    Leaving it behind broke the archive in two directions: the archive lost the only
    record of which published coordinate each archived session occupied, and the live
    tree kept a manifest describing sessions that were gone -- enough for
    `assert_no_duplicates` to abort the next capture over a duplicate belonging to an
    archived generation.
    """
    state = tmp_path / "state"
    _seed(state)
    manifest = state / "agentdojo-gpt4omini_manifest.jsonl"
    manifest.write_text('{"session":"agentdojo-gpt4omini-x-001"}\n', encoding="utf-8")

    plan = archiver.plan_archive(state, sources=("agentdojo-gpt4omini",), stamp="20260810")
    assert any(item["original"] == str(manifest) for item in plan)

    archiver.apply_archive(plan)
    assert not manifest.exists(), "the live tree must not keep an archived generation's manifest"
