"""The manifest is the authoritative corpus record, so its keys are load-bearing.

A coordinate that is not stable across runs makes --resume useless; a fold group
that is merely the session id lets a benign task and its injected twin land in
different folds, which is the leakage note 31 is the ancestor of.
"""

import pytest

from chainwatch.capture import manifest


ADOJO_BENIGN = {
    "label": "benign", "suite": "banking", "user_task": "user_task_0",
    "injection_task": None, "source": "agentdojo-gpt4omini", "session": "s1",
    "utility": True, "security": None, "calls": 3, "executor_status": "completed",
}
ADOJO_ATTACK = dict(ADOJO_BENIGN, label="attack", injection_task="injection_task_0",
                    session="s2", security=True, utility=False)
INJEC = {
    "label": "attack", "split": "dh", "variant": "base", "case_index": 0,
    "user_tool": "GitHubGetRepositoryDetails", "source": "injecagent-gpt4omini",
    "session": "s3", "attacker_called": False, "calls": 1, "executor_status": "completed",
}


def _entry(row, **overrides):
    fields = dict(
        coordinate=manifest.coordinate(row), fold_group=manifest.fold_group(row),
        session="s1", source="agentdojo-gpt4omini", fingerprint="fp-a",
        corpus_revision="v2", git_commit="abc", native={}, calls=3,
        cost_usd=0.0007, status="completed",
    )
    fields.update(overrides)
    return manifest.ManifestEntry(**fields)


def test_coordinate_separates_a_benign_task_from_its_injected_variant():
    assert manifest.coordinate(ADOJO_BENIGN) != manifest.coordinate(ADOJO_ATTACK)


def test_fold_group_keeps_a_benign_task_and_its_injected_variant_together():
    """Grouping on session lets related rows cross folds. Grouping on the
    published task is what actually prevents the leak."""
    assert manifest.fold_group(ADOJO_BENIGN) == manifest.fold_group(ADOJO_ATTACK)
    assert manifest.fold_group(ADOJO_BENIGN) == "agentdojo:banking:user_task_0"


def test_injecagent_fold_group_binds_base_to_enhanced():
    enhanced = dict(INJEC, variant="enhanced", session="s4")
    assert manifest.fold_group(INJEC) == manifest.fold_group(enhanced)


def test_coordinate_separates_base_from_enhanced():
    enhanced = dict(INJEC, variant="enhanced", session="s4")
    assert manifest.coordinate(INJEC) != manifest.coordinate(enhanced)


def test_an_unrecognised_score_row_is_an_error_not_a_guess():
    """`source` is an assertion the wrapper makes; the keys are the evidence."""
    with pytest.raises(ValueError):
        manifest.coordinate({"source": "agentdojo-gpt4omini", "session": "s1"})


def test_fingerprint_changes_with_every_input_that_changes_behaviour():
    base = dict(model="gpt-4o-mini-2024-07-18", system_prompt_sha256="a" * 64,
                max_turns=12, corpus_revision="v2")
    reference = manifest.config_fingerprint(**base)
    for field, value in (("model", "other"), ("system_prompt_sha256", "b" * 64),
                         ("max_turns", 8), ("corpus_revision", "v3")):
        assert manifest.config_fingerprint(**dict(base, **{field: value})) != reference


def test_completed_coordinates_ignores_entries_from_another_configuration():
    """Resume must not skip a coordinate captured under a different prompt or
    corpus revision -- those are different sessions wearing the same name."""
    entries = [_entry(ADOJO_BENIGN)]
    assert manifest.completed_coordinates(entries, fingerprint="fp-a")
    assert not manifest.completed_coordinates(entries, fingerprint="fp-b")


def test_a_zero_call_session_is_not_a_completed_coordinate():
    """A session that recorded nothing is the thing a resumed run must retry."""
    entries = [_entry(ADOJO_BENIGN, calls=0)]
    assert not manifest.completed_coordinates(entries, fingerprint="fp-a")


def test_a_round_trip_through_disk_preserves_the_coordinate_type(tmp_path):
    """JSON has no tuples. A coordinate read back as a list would never compare
    equal to a freshly computed one, and resume would silently do nothing."""
    path = tmp_path / "m.jsonl"
    manifest.append_entry(path, _entry(ADOJO_BENIGN))
    assert manifest.read_entries(path)[0].coordinate == manifest.coordinate(ADOJO_BENIGN)


def test_duplicate_coordinates_reports_the_two_already_on_disk(tmp_path):
    """The archive holds 42 AgentDojo rows over 40 coordinates. A manifest that
    cannot say so is not a manifest."""
    path = tmp_path / "m.jsonl"
    manifest.append_entry(path, _entry(ADOJO_BENIGN))
    manifest.append_entry(path, _entry(ADOJO_BENIGN, session="s9"))
    dupes = manifest.duplicate_coordinates(manifest.read_entries(path))
    assert list(dupes.values()) == [2]


def _append_burst(path, writer, count):
    """One shard's worth of appends, in its own process."""
    for index in range(count):
        manifest.append_entry(
            path,
            _entry(
                ADOJO_BENIGN,
                session=f"w{writer}-{index}",
                coordinate=("agentdojo", "benign", "banking", f"user_task_{writer}", f"n{index}"),
            ),
        )


def test_concurrent_writers_never_tear_a_row(tmp_path):
    """Six parallel shards append to one manifest, so a torn row is silent corruption.

    A row is ~700 bytes and `append_entry` opens O_APPEND, so each write should be
    atomic on Linux -- but nothing asserted it until the grid needed six writers,
    and an unasserted floor is the defect note 37 is about.
    """
    from multiprocessing import Process

    path = tmp_path / "manifest.jsonl"
    writers, per_writer = 6, 40
    procs = [Process(target=_append_burst, args=(path, w, per_writer)) for w in range(writers)]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(timeout=120)

    assert [proc.exitcode for proc in procs] == [0] * writers
    entries = manifest.read_entries(path)
    assert len(entries) == writers * per_writer
    assert len({entry.coordinate for entry in entries}) == writers * per_writer
