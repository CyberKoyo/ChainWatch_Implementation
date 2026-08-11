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
