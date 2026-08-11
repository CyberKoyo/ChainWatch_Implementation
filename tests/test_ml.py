"""Tests for the supervised layer.

These guard the *protocol*, not the model's accuracy. A number produced by a leaky
split is worse than no number, so what is asserted here is that folds cannot leak,
that excluded features stay excluded, and that the numpy-only install path is
unchanged by any of this.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from chainwatch.engine.session import SessionAnalyzer
from chainwatch.ml import dataset as ds

xgboost = pytest.importorskip("xgboost", reason="requires the [ml] extra")

from chainwatch.ml.evaluate import (  # noqa: E402 -- must follow importorskip
    HELD_SOURCES,
    POPULATIONS,
    TRAIN_SOURCES,
    _auc,
    _folds,
    rule_baseline,
    shade_case_study,
    threshold_for_detection,
)
from chainwatch.ml.scorer import Scorer, session_scores  # noqa: E402


def write_traces(path, sessions):
    """Write a minimal JSONL trace file. ``sessions`` maps id -> list of call dicts."""
    with path.open("w", encoding="utf-8") as handle:
        for session, calls in sessions.items():
            for index, call in enumerate(calls, start=1):
                handle.write(
                    json.dumps(
                        {
                            "session": session,
                            "label": call.get("label", "benign"),
                            "source": call.get("source", "realism"),
                            "environment": call.get("environment", "banking"),
                            "call": index,
                            "tool": call.get("tool", "get_file"),
                            "server": call.get("server", "banking"),
                            "stage": call.get("stage", 1),
                            "rules": call.get("rules", []),
                            "v": call["v"],
                        }
                    )
                    + "\n"
                )
    return path


def vector(**overrides):
    """A 20-dim feature vector, READ by default."""
    v = [0.0] * 20
    v[0] = 1.0
    for index, value in overrides.items():
        v[int(index)] = value
    return v


@pytest.fixture
def traces(tmp_path):
    return write_traces(
        tmp_path / "t.jsonl",
        {
            "attack-1": [
                {"v": vector(), "label": "attack", "source": "agentlab"},
                {"v": vector(**{"3": 1.0, "0": 0.0, "8": 1.0}), "label": "attack",
                 "source": "agentlab", "stage": 6, "rules": ["R3"], "tool": "post_webhook"},
            ],
            "benign-1": [
                {"v": vector()},
                {"v": vector(**{"5": 0.2})},
            ],
        },
    )


# ------------------------------------------------------------------ feature groups


def test_temporal_dims_never_reach_the_model(traces):
    """TF dims 10-12 are replay artifacts: call_rate hit 1816/sec under batch replay.

    Pinned by *name* rather than by column count. A count alone passes just as well
    when a temporal dimension is added and an unrelated one dropped -- the same
    weakness that let ``win_occupancy`` sit in arm D unnoticed, and the reason the
    regression test below asserts correlation rather than range.
    """
    built = ds.build(traces, groups=("current",))
    assert built.names == [
        "tc_read", "tc_write", "tc_execute", "tc_network", "tc_configure",
        "ps",
        "df_internal_read", "df_external_write", "df_chained", "df_cross_server",
        "oc_imperative", "oc_xml", "oc_mismatch", "oc_volume", "oc_hash_change",
        "oc_encoded", "oc_external_url",
        "prov_unknown", "prov_attested", "prov_introduced", "prov_unattested",
    ]
    assert not any("tf_" in name or "interval" in name or "rate" in name for name in built.names)


def test_no_feature_correlates_with_session_length(tmp_path):
    """Benign realism averages 26.3 calls vs attacks' 2.8 -- length is a corpus artifact.

    Regression test for a real leak: a ``win_occupancy`` feature (``len(window)/size``)
    read as innocuous, correlated almost perfectly with session length, became arm D's
    single most important feature and pushed the false-positive rate to 0.0%.

    Asserting a feature's *range* proves nothing; this asserts its *correlation*.
    """
    path = write_traces(
        tmp_path / "len.jsonl",
        {
            "short": [{"v": vector()} for _ in range(2)],
            "long": [{"v": vector()} for _ in range(30)],
        },
    )
    built = ds.build(path, groups=("current", "window"))
    lengths = np.array(
        [(built.sessions == session).sum() for session in built.sessions], dtype=float
    )

    for index, name in enumerate(built.names):
        column = built.rows[:, index]
        if column.std() == 0:
            continue
        correlation = abs(float(np.corrcoef(column, lengths)[0, 1]))
        assert correlation < 0.9, f"{name} tracks session length (r={correlation:.2f})"


def test_arm_groups_are_nested_as_documented(traces):
    widths = {arm: ds.build(traces, groups=groups).rows.shape[1] for arm, groups in ds.ARMS.items()}
    assert widths["E"] < widths["B"] < widths["D"]
    assert widths["C"] < widths["D"]


def test_rule_features_read_the_fired_rules(traces):
    built = ds.build(traces, groups=("rules",))
    column = built.names.index("rule_r3")
    assert built.rows[:, column].max() == 1.0


def test_later_calls_carry_more_weight(traces):
    """Call 1 of an attack chain is indistinguishable from benign but shares its label."""
    built = ds.build(traces, groups=("current",))
    assert built.weights.max() > built.weights.min()


# ------------------------------------------------------------------- provenance


def test_provenance_defaults_to_unknown_on_traces_that_predate_it(traces):
    """Every trace written before Phase 13 lacks ``prov``; none may become ATTESTED.

    ``UNKNOWN`` is ``Provenance``'s fail-closed value, so an absent field and an
    unreadable destination land in the same column -- the honest place for both.
    """
    built = ds.build(traces, groups=("current",))
    assert (built.rows[:, built.names.index("prov_unknown")] == 1.0).all()
    for name in ("prov_attested", "prov_introduced", "prov_unattested"):
        assert built.rows[:, built.names.index(name)].max() == 0.0


def test_provenance_reads_the_recorded_destination(tmp_path):
    """A one-hot that is UNKNOWN on every row is a dead feature, not a working one."""
    path = tmp_path / "p.jsonl"
    with path.open("w", encoding="utf-8") as handle:
        for index, prov in enumerate(("ATTESTED", "INTRODUCED", "UNATTESTED"), start=1):
            handle.write(
                json.dumps(
                    {
                        "session": "s", "label": "benign", "source": "realism",
                        "environment": "workspace", "call": index, "server": "workspace",
                        "stage": 6, "rules": [], "prov": prov, "v": vector(),
                    }
                )
                + "\n"
            )

    built = ds.build(path, groups=("current",))
    for offset, name in enumerate(("prov_attested", "prov_introduced", "prov_unattested")):
        assert built.rows[offset, built.names.index(name)] == 1.0
    assert built.rows[:, built.names.index("prov_unknown")].max() == 0.0


def test_an_unrecognised_provenance_string_fails_closed(tmp_path):
    """A trace from a future version must not silently one-hot as something trusted."""
    path = tmp_path / "u.jsonl"
    path.write_text(
        json.dumps(
            {
                "session": "s", "label": "benign", "source": "realism",
                "environment": "workspace", "call": 1, "server": "workspace",
                "stage": 1, "rules": [], "prov": "SOMETHING_NEW", "v": vector(),
            }
        )
        + "\n",
        encoding="utf-8",
    )

    built = ds.build(path, groups=("current",))
    assert built.rows[0, built.names.index("prov_unknown")] == 1.0


# ------------------------------------------------------------------- populations


def test_shade_is_excluded_from_training_sources(tmp_path):
    path = write_traces(
        tmp_path / "s.jsonl",
        {
            "a": [{"v": vector(), "label": "attack", "source": "agentlab"}],
            "s": [{"v": vector(), "label": "attack", "source": "shade"}],
        },
    )
    built = ds.build(path, sources=("agentlab", "realism", "control"))
    assert "shade" not in set(built.sources.tolist())


def test_false_positive_source_is_realism_only(tmp_path):
    """Control is surface-matched to attacks; quoting it as an FP rate misreports it."""
    path = write_traces(
        tmp_path / "c.jsonl",
        {
            "a": [{"v": vector(), "label": "attack", "source": "agentlab", "rules": ["R3"]}],
            "r": [{"v": vector(), "source": "realism", "rules": ["R3"]}],
            "c": [{"v": vector(), "source": "control", "rules": ["R3"]}],
        },
    )
    baseline = rule_baseline(path)
    assert baseline.false_positives == 1.0
    assert baseline.control_rate == 1.0
    assert baseline.n_benign == 1  # control is not in the benign denominator


def test_several_trace_files_load_as_one_corpus(tmp_path):
    """bizops lives in ~/.chainwatch/logs/ while the replay corpus lives in traces/."""
    first = write_traces(tmp_path / "one.jsonl", {"a": [{"v": vector(), "source": "agentlab"}]})
    second = write_traces(tmp_path / "two.jsonl", {"b": [{"v": vector(), "source": "bizops"}]})

    sessions = ds.load_sessions([first, second])
    assert len(sessions) == 2
    assert {str(calls[0]["source"]) for calls in sessions} == {"agentlab", "bizops"}


def test_one_session_split_across_files_is_reunited(tmp_path):
    """The audit log rolls daily, so a long capture session spans files by design.

    Grouping on ``session`` across every file and then sorting on ``call`` is what
    puts it back together -- and is why ``call`` had to become unique session-wide.
    """
    first = tmp_path / "day1.jsonl"
    second = tmp_path / "day2.jsonl"
    for path, calls in ((first, (1, 2)), (second, (3, 4))):
        with path.open("w", encoding="utf-8") as handle:
            for index in calls:
                handle.write(
                    json.dumps(
                        {
                            "session": "long", "label": "benign", "source": "bizops",
                            "call": index, "server": "banking", "stage": 1,
                            "rules": [], "v": vector(),
                        }
                    )
                    + "\n"
                )

    sessions = ds.load_sessions([second, first])  # deliberately out of order
    assert len(sessions) == 1
    assert [entry["call"] for entry in sessions[0]] == [1, 2, 3, 4]


def test_environment_falls_back_to_the_server_name(tmp_path):
    """Live capture records ``server``; only replayed lines carry ``environment``.

    Without the fallback every captured session collapses into a single "None"
    stratum, so leave-one-environment-out holds out nothing.
    """
    path = tmp_path / "biz.jsonl"
    path.write_text(
        json.dumps(
            {
                "session": "s", "label": "benign", "source": "bizops",
                "call": 1, "server": "banking", "stage": 1, "rules": [], "v": vector(),
            }
        )
        + "\n",
        encoding="utf-8",
    )

    built = ds.build(path, groups=("current",), sources=("bizops",))
    assert built.environments.tolist() == ["banking"]


def test_held_out_sources_are_never_trained_on(tmp_path):
    """The held-out populations are the only real agent behaviour in the corpus.

    Scoring a chain with a model that was fitted on it says nothing, and the two
    lists are edited independently -- so the disjointness is pinned here rather than
    left as a property nothing observes.
    """
    assert not set(HELD_SOURCES) & set(TRAIN_SOURCES)


def test_every_population_holds_out_what_it_does_not_train_on(tmp_path):
    """Same invariant as above, for each named protocol rather than the globals.

    ``REAL`` trains on ``bizops``/``bizattack`` -- populations ``SYNTHETIC`` holds
    out -- so the disjointness cannot be asserted once over two module constants and
    has to hold per protocol. Getting this wrong is silent: the model would be
    scored on chains it was fitted on and the report would look better for it.
    """
    for name, populations in POPULATIONS.items():
        assert not set(populations.train) & set(populations.held), name
        assert populations.false_positive in populations.train, name
        if populations.control is not None:
            assert populations.control in populations.train, name


def test_case_study_refuses_to_score_a_population_it_trained_on(tmp_path):
    """The held-out study's only value is that the model never met these chains."""
    path = write_traces(
        tmp_path / "overlap.jsonl",
        {"a": [{"v": vector(), "label": "attack", "source": "bizattack"}]},
    )
    with pytest.raises(ValueError):
        shade_case_study(
            path, ("current",), train_sources=("bizops", "bizattack"), sources=("bizattack",)
        )


def test_rule_baseline_ignores_shade(tmp_path):
    path = write_traces(
        tmp_path / "b.jsonl",
        {
            "a": [{"v": vector(), "label": "attack", "source": "agentlab"}],
            "s": [{"v": vector(), "label": "attack", "source": "shade", "rules": ["R3"]}],
        },
    )
    assert rule_baseline(path).n_attack == 1


def test_rule_baseline_counts_only_what_the_population_trains_on(tmp_path):
    """A population's baseline may not borrow the other population's attack class.

    Selecting as "everything except ``held``" let any source named in neither set
    through. Under ``REAL`` that is ``agentlab``, so a run over route C's corpus
    reported a baseline of 200 synthesized attack chains against 9 real benign
    sessions -- a cross-population number, printed as the headline every arm is then
    pinned to, in the one mode whose whole purpose is keeping the two apart.

    It also disabled ``main``'s both-classes guard: ``n_attack`` was 200, so a
    population with no attack session at all printed nan tables and exited 0, which
    is CLAUDE.md note 20's defect wearing arm A's hat.
    """
    path = write_traces(
        tmp_path / "mixed.jsonl",
        {
            "syn": [{"v": vector(), "label": "attack", "source": "agentlab", "rules": ["R3"]}],
            "biz": [{"v": vector(), "label": "benign", "source": "bizops"}],
            "atk": [{"v": vector(), "label": "attack", "source": "bizattack", "rules": ["R3"]}],
        },
    )
    real = rule_baseline(path, POPULATIONS["real"])
    assert (real.n_attack, real.n_benign) == (1, 1)

    # ...and the synthetic side keeps the numbers CLAUDE.md's tables were measured
    # with, which is what makes this a fix rather than a re-baselining.
    synthetic = rule_baseline(path, POPULATIONS["synthetic"])
    assert (synthetic.n_attack, synthetic.n_benign) == (1, 0)


# ---------------------------------------------------------------------- protocol


def test_folds_never_split_a_session():
    sessions = np.array(["a", "a", "a", "b", "b", "c"], dtype=object)
    folds = _folds(sessions, k=3, seed=0)
    seen = [set(fold.tolist()) for fold in folds]
    for left in range(len(seen)):
        for right in range(left + 1, len(seen)):
            assert not seen[left] & seen[right]
    assert set().union(*seen) == {"a", "b", "c"}


def test_threshold_hits_the_requested_detection():
    scores = np.array([0.9, 0.8, 0.7, 0.2, 0.1])
    threshold = threshold_for_detection(scores, 0.6)
    assert (scores >= threshold).mean() >= 0.6


def test_auc_is_half_when_scores_are_tied():
    assert _auc(np.array([0.5, 0.5]), np.array([0.5, 0.5])) == 0.5


def test_session_score_takes_the_maximum(traces):
    """Rules count a chain as detected if any rule fired anywhere; match that."""
    built = ds.build(traces, groups=("current",))
    scores = np.linspace(0.1, 0.9, len(built))
    reduced = session_scores(built, scores)
    assert max(reduced.values()) == pytest.approx(0.9)


# ------------------------------------------------------------------------ scorer


def test_scorer_round_trips(traces, tmp_path):
    built = ds.build(traces, groups=("current", "window"))
    model = Scorer.train(built, seed=0)
    before = model.score(built.rows)

    model.save(tmp_path / "m")
    after = Scorer.load(tmp_path / "m").score(built.rows)
    assert np.allclose(before, after)


def test_unfitted_scorer_refuses_to_guess():
    with pytest.raises(RuntimeError):
        Scorer().score(np.zeros((1, 3)))


# ------------------------------------------------------------------ engine intact


def test_engine_has_no_scorer_by_default():
    """The numpy-only install path must behave exactly as before."""
    analyzer = SessionAnalyzer()
    assert getattr(analyzer, "scorer", None) is None


def test_injection_populations_select_only_their_own_source():
    """Route E and F are whitelists, and never each other's or anyone else's.

    Note 31: a population that selects by exclusion inherits every source nobody
    named -- ``real`` counted 200 synthesized attack chains that way and printed a
    measurement over a corpus holding no real attack session at all.
    """
    for name in ("agentdojo", "injecagent"):
        populations = POPULATIONS[name]
        assert set(populations.train) == {name}
        assert populations.false_positive == name
        for foreign in ("agentlab", "realism", "control", "shade", "bizops", "twin"):
            assert foreign not in populations.train


def test_injection_populations_do_not_pool_with_each_other():
    """Route F sessions are short by construction; route E's are multi-step.

    Pooled, session length would carry the label -- which is what win_occupancy did.
    """
    assert set(POPULATIONS["agentdojo"].train).isdisjoint(POPULATIONS["injecagent"].train)


def test_gpt4omini_injection_populations_select_only_their_exact_source():
    """Model identity is metadata; source is the enforced population boundary."""
    for name in ("agentdojo-gpt4omini", "injecagent-gpt4omini"):
        populations = POPULATIONS[name]
        assert populations.train == (name,)
        assert populations.false_positive == name
        assert populations.control is None
        assert populations.held == ()


def test_gpt4omini_populations_do_not_pool_routes_or_claude_executor_rows():
    sources = {
        name: set(POPULATIONS[name].train)
        for name in (
            "agentdojo",
            "injecagent",
            "agentdojo-gpt4omini",
            "injecagent-gpt4omini",
        )
    }

    for name, selected in sources.items():
        assert selected == {name}
        assert all(selected.isdisjoint(other) for key, other in sources.items() if key != name)


def test_adding_injection_populations_left_the_existing_ones_alone():
    """Every measured figure in CLAUDE.md §12 belongs to these three."""
    assert POPULATIONS["synthetic"].train == TRAIN_SOURCES
    assert POPULATIONS["real"].train == ("bizops", "bizattack")
    assert POPULATIONS["twins"].train == ("twin", "twinattack")


def test_a_benign_task_and_its_injected_variant_never_cross_a_fold():
    """Session-grouped CV looks equivalent to task-grouped and is not.

    AgentDojo's benign user_task_0 and its injected twin share the user task, the
    environment and most of the trajectory. Split across folds, the model is
    tested on a task it was trained on -- the same species as win_occupancy, one
    level up: a property of how the corpus was generated becoming a usable label.
    """
    from chainwatch.ml.evaluate import _folds

    groups = np.array([
        "agentdojo:banking:user_task_0", "agentdojo:banking:user_task_0",
        "agentdojo:banking:user_task_1", "agentdojo:banking:user_task_1",
        "agentdojo:slack:user_task_0", "agentdojo:slack:user_task_0",
    ], dtype=object)
    folds = _folds(groups, k=3, seed=0)
    for fold in folds:
        held = set(fold.tolist())
        rest = {group for group in groups.tolist() if group not in held}
        assert not (held & rest), f"group straddles a fold: {held & rest}"
    assert sorted(g for fold in folds for g in fold.tolist()) == sorted(set(groups.tolist()))


def test_a_session_with_no_manifest_entry_groups_on_its_own_id(tmp_path):
    """Legacy populations must fold exactly as they did, or every number in
    CLAUDE.md §12 stops being reproducible."""
    from chainwatch.ml.dataset import build

    trace = tmp_path / "legacy.jsonl"
    trace.write_text("\n".join(
        json.dumps({
            "session": "legacy-1", "source": "realism", "label": "benign",
            "call": index, "stage": 1, "severity": "NONE", "rules": [],
            "v": [0.0] * 20,
        })
        for index in range(1, 4)
    ) + "\n", encoding="utf-8")

    dataset = build(trace, groups=("current",), sources=["realism"])
    assert len(dataset) == 3
    assert set(dataset.groups.tolist()) == set(dataset.sessions.tolist())
