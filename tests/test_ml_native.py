"""Native-valid selection, and the one thing it must never do.

An attack the agent declined is not a benign session. Relabelling it would
manufacture the mislabeled row note 35 already caught by hand -- a benign
trajectory wearing an attack label, but in the other direction and at scale.
"""

from chainwatch.ml import native


OUTCOMES = {
    "a1": {"route": "agentdojo", "label": "attack", "security": True},
    "a2": {"route": "agentdojo", "label": "attack", "security": False},
    "b1": {"route": "agentdojo", "label": "benign", "utility": True},
    "b2": {"route": "agentdojo", "label": "benign", "utility": False},
    "i1": {"route": "injecagent", "label": "attack", "attacker_called": True},
    "i2": {"route": "injecagent", "label": "attack", "attacker_called": False},
}


def test_only_successful_attacks_are_native_valid():
    assert native.is_native_valid("a1", "attack", OUTCOMES)
    assert not native.is_native_valid("a2", "attack", OUTCOMES)
    assert native.is_native_valid("i1", "attack", OUTCOMES)
    assert not native.is_native_valid("i2", "attack", OUTCOMES)


def test_a_failed_attack_is_excluded_never_relabelled():
    valid, attempts = native.partition_sessions(
        ["a1", "a2"], {"a1": "attack", "a2": "attack"}, OUTCOMES)
    assert valid == ["a1"]
    assert attempts == ["a1", "a2"], "the sensitivity analysis keeps every attempt"
    assert "a2" not in valid


def test_benign_validity_reads_utility_not_security():
    assert native.is_native_valid("b1", "benign", OUTCOMES)
    assert not native.is_native_valid("b2", "benign", OUTCOMES)


def test_a_partition_with_no_valid_attacks_is_reported_unavailable_not_empty():
    valid, attempts = native.partition_sessions(["a2"], {"a2": "attack"}, OUTCOMES)
    assert valid == []
    assert attempts == ["a2"]


def test_a_session_with_no_manifest_entry_is_never_native_valid():
    """A legacy population has no published check. Fail closed -- the alternative
    is a primary analysis quietly counting sessions nothing verified."""
    assert not native.is_native_valid("unknown", "attack", OUTCOMES)
    valid, attempts = native.partition_sessions(["unknown"], {"unknown": "attack"}, OUTCOMES)
    assert valid == [] and attempts == []


def test_outcomes_are_read_off_the_manifest_on_disk(tmp_path):
    from chainwatch.capture import manifest

    row = {"label": "attack", "suite": "banking", "user_task": "user_task_0",
           "injection_task": "injection_task_0"}
    path = tmp_path / "agentdojo-gpt4omini_manifest.jsonl"
    manifest.append_entry(path, manifest.ManifestEntry(
        coordinate=manifest.coordinate(row), fold_group=manifest.fold_group(row),
        session="s1", source="agentdojo-gpt4omini", fingerprint="fp",
        corpus_revision="v2", git_commit="abc",
        native={"utility": False, "security": True}, calls=4,
        cost_usd=0.0007, status="completed"))

    outcomes = native.native_outcomes([path])
    assert outcomes["s1"]["route"] == "agentdojo"
    assert outcomes["s1"]["label"] == "attack"
    assert native.is_native_valid("s1", "attack", outcomes)
    # The whole coordinate survives the join: nothing else can answer "which
    # suite was this?" now that `server` names an app rather than a suite.
    assert outcomes["s1"]["coordinate"][0] == "agentdojo"


def _write_corpus(tmp_path):
    """Two sessions, one natively valid, in the trace schema both readers share."""
    import json

    rows = []
    for session, label, rules in (("s_ok", "attack", ["R3"]),
                                  ("s_refused", "attack", [])):
        for call in (1, 2):
            vector = [0.0] * 20
            vector[0] = 1.0
            rows.append({"session": session, "label": label,
                         "source": "agentdojo-gpt4omini", "call": call,
                         "v": vector, "rules": rules, "severity": "NONE",
                         "stage": 1, "server": "slack-slack"})
    path = tmp_path / "traces.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    return path


def test_the_session_allowlist_reaches_both_the_baseline_and_the_matrix(tmp_path):
    from chainwatch.ml.dataset import build
    from chainwatch.ml.evaluate import AGENTDOJO_GPT4OMINI, rule_baseline

    path = _write_corpus(tmp_path)

    everything = rule_baseline(path, AGENTDOJO_GPT4OMINI)
    primary = rule_baseline(path, AGENTDOJO_GPT4OMINI, sessions={"s_ok"})
    assert everything.n_attack == 2
    assert primary.n_attack == 1, "the refused attack is excluded, never relabelled"

    dataset = build(path, groups=("current",), sources=("agentdojo-gpt4omini",),
                    sessions={"s_ok"})
    assert set(dataset.sessions.tolist()) == {"s_ok"}


def test_an_empty_allowlist_is_not_the_same_as_no_allowlist(tmp_path):
    """None means 'every session'; an empty set means 'nothing survived selection'.

    Conflating them would silently turn a manifest that matched nothing into a run
    over the whole corpus, published under the native-valid heading.
    """
    from chainwatch.ml.evaluate import AGENTDOJO_GPT4OMINI, rule_baseline

    path = _write_corpus(tmp_path)
    assert rule_baseline(path, AGENTDOJO_GPT4OMINI, sessions=set()).n_attack == 0
    assert rule_baseline(path, AGENTDOJO_GPT4OMINI, sessions=None).n_attack == 2
