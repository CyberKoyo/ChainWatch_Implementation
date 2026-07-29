"""HMM correctness and prior-structure tests -- ChainWatch section IV-C.

Two jobs. First, verify the algorithms are actually right (Viterbi against brute
force, forward against enumeration, EM monotonicity) -- an HMM that is subtly wrong
still produces plausible-looking stage labels, so this cannot be eyeballed. Second,
verify the prior transition matrix genuinely satisfies the three constraints the
paper states, rather than merely looking reasonable.
"""

from __future__ import annotations

import itertools

import numpy as np
import pytest

from chainwatch.engine.features import FEATURE_DIM
from chainwatch.engine.hmm import (
    N_STAGES,
    STAGE_NAMES,
    KillChainHMM,
    log_sum_exp,
)
from chainwatch.engine.model import (
    BACKWARD_TOTAL,
    FORWARD_1,
    FORWARD_2,
    SELF_TRANSITION,
    build_prior_emissions,
    build_prior_model,
    build_transition_matrix,
)


@pytest.fixture
def model() -> KillChainHMM:
    return build_prior_model()


def _random_observations(n: int, seed: int = 0) -> np.ndarray:
    """Structurally valid observations: one-hot TC, binary DF/OC, bounded PS."""
    rng = np.random.default_rng(seed)
    out = np.zeros((n, FEATURE_DIM))
    for i in range(n):
        out[i, rng.integers(0, 5)] = 1.0
        out[i, 5] = rng.random()
        out[i, 6:10] = rng.integers(0, 2, size=4)
        out[i, 10:13] = rng.random(3) * 3
        out[i, 13:20] = (rng.random(7) < 0.2).astype(float)
    return out


# ----------------------------------------------------------------- numerics


def test_log_sum_exp_matches_naive():
    values = np.array([-1000.0, -1001.0, -1002.0])
    assert log_sum_exp(values, axis=0) == pytest.approx(
        -1000.0 + np.log(1 + np.exp(-1) + np.exp(-2))
    )


def test_log_sum_exp_survives_underflow():
    """Naive exp() of these underflows to zero; the shift-by-max trick must not."""
    assert np.isfinite(log_sum_exp(np.full(6, -50_000.0), axis=0))


# -------------------------------------------------------- transition structure


def test_transition_rows_are_distributions():
    matrix = build_transition_matrix()
    assert matrix.shape == (N_STAGES, N_STAGES)
    assert np.allclose(matrix.sum(axis=1), 1.0)
    assert np.all(matrix > 0), "no transition may be impossible"


def test_constraint_forward_beats_backward():
    """Section IV-C: 'forward transitions are more probable than backward ones'."""
    matrix = build_transition_matrix()
    for row in range(N_STAGES - 1):
        forward = matrix[row, row + 1]
        for column in range(row):
            assert forward > matrix[row, column]


def test_constraint_large_jumps_are_unlikely():
    """Section IV-C: 'large jumps of more than two stages are unlikely'."""
    matrix = build_transition_matrix()
    for row in range(N_STAGES):
        for column in range(row + 3, N_STAGES):
            assert matrix[row, column] < matrix[row, min(row + 2, N_STAGES - 1)]


def test_constraint_backward_mass_is_retained():
    """Section IV-C: 'small backward probabilities are retained'."""
    matrix = build_transition_matrix()
    for row in range(1, N_STAGES):
        assert matrix[row, :row].sum() > 0.0


def test_constraint_ordering_of_weights():
    """The generating weights themselves must encode the stated ordering."""
    assert SELF_TRANSITION > FORWARD_2 > BACKWARD_TOTAL
    assert FORWARD_1 > FORWARD_2


# ------------------------------------------------------------------ emissions


def test_emission_shapes_cover_all_twenty_dims():
    e = build_prior_emissions()
    assert e.tc_probs.shape == (N_STAGES, 5)
    assert e.ps_mean.shape == (N_STAGES, 1)
    assert e.df_probs.shape == (N_STAGES, 4)
    assert e.tf_mean.shape == (N_STAGES, 3)
    assert e.oc_probs.shape == (N_STAGES, 7)
    assert 5 + 1 + 4 + 3 + 7 == FEATURE_DIM


def test_tool_category_rows_are_distributions():
    assert np.allclose(build_prior_emissions().tc_probs.sum(axis=1), 1.0)


def test_bernoulli_parameters_are_probabilities():
    e = build_prior_emissions()
    for block in (e.df_probs, e.oc_probs):
        assert np.all(block > 0.0) and np.all(block < 1.0)


def test_emission_log_prob_shape(model):
    assert model.emissions.log_prob(_random_observations(1)[0]).shape == (N_STAGES,)
    assert model.emissions.log_prob_matrix(_random_observations(4)).shape == (4, N_STAGES)


def test_stage_names_match_paper_table_one():
    assert STAGE_NAMES == (
        "Reconnaissance",
        "Trust Building",
        "Injection",
        "Escalation",
        "Lateral Movement",
        "Exfiltration",
    )


# ------------------------------------------------------------------- decoding


def test_viterbi_matches_brute_force(model):
    """Exhaustively score every path over a short sequence and compare.

    6**4 = 1296 paths, cheap enough to enumerate, and the only way to be sure the
    backpointer bookkeeping is right.
    """
    observations = _random_observations(4, seed=7)
    log_emissions = model.emissions.log_prob_matrix(observations)
    log_a = np.log(model.transitions)
    log_pi = np.log(model.initial)

    best_score, best_path = -np.inf, None
    for path in itertools.product(range(N_STAGES), repeat=4):
        score = log_pi[path[0]] + log_emissions[0, path[0]]
        for t in range(1, 4):
            score += log_a[path[t - 1], path[t]] + log_emissions[t, path[t]]
        if score > best_score:
            best_score, best_path = score, path

    stages, score = model.viterbi(observations)
    assert list(stages) == list(best_path)
    assert score == pytest.approx(best_score)


def test_forward_equals_enumeration_of_all_paths(model):
    """Total likelihood must equal the sum over every path, not just the best one."""
    observations = _random_observations(3, seed=11)
    log_emissions = model.emissions.log_prob_matrix(observations)
    log_a = np.log(model.transitions)
    log_pi = np.log(model.initial)

    scores = []
    for path in itertools.product(range(N_STAGES), repeat=3):
        score = log_pi[path[0]] + log_emissions[0, path[0]]
        for t in range(1, 3):
            score += log_a[path[t - 1], path[t]] + log_emissions[t, path[t]]
        scores.append(score)

    assert model.log_likelihood(observations) == pytest.approx(
        float(log_sum_exp(np.array(scores), axis=0)), rel=1e-9
    )


def test_viterbi_handles_empty_and_single(model):
    stages, score = model.viterbi(np.empty((0, FEATURE_DIM)))
    assert len(stages) == 0 and score == 0.0
    stages, _ = model.viterbi(_random_observations(1))
    assert len(stages) == 1


def test_posterior_rows_sum_to_one(model):
    assert np.allclose(model.posterior(_random_observations(5)).sum(axis=1), 1.0)


# ------------------------------------------------------------------- training


def test_baum_welch_log_likelihood_is_monotonic(model):
    """EM guarantees non-decreasing likelihood; a drop means the M-step is wrong."""
    sequences = [_random_observations(6, seed=s) for s in range(4)]
    history = model.baum_welch(sequences, iterations=12)

    assert len(history) >= 2
    for earlier, later in zip(history, history[1:]):
        assert later >= earlier - 1e-6, f"likelihood decreased: {earlier} -> {later}"


def test_baum_welch_preserves_stochasticity(model):
    model.baum_welch([_random_observations(6, seed=s) for s in range(3)], iterations=5)
    assert np.allclose(model.transitions.sum(axis=1), 1.0)
    assert model.initial.sum() == pytest.approx(1.0)
    assert np.allclose(model.emissions.tc_probs.sum(axis=1), 1.0)


def test_baum_welch_can_hold_emissions_fixed(model):
    """Priors encode Table I domain knowledge a small trace set would wash out."""
    before = model.emissions.tc_probs.copy()
    model.baum_welch([_random_observations(6, seed=1)], iterations=3, update_emissions=False)
    assert np.allclose(model.emissions.tc_probs, before)
    assert np.allclose(model.transitions.sum(axis=1), 1.0)


def test_baum_welch_on_empty_input_is_noop(model):
    assert model.baum_welch([], iterations=5) == []


# -------------------------------------------------------------- serialisation


def test_model_round_trips_through_dict(model):
    restored = KillChainHMM.from_dict(model.to_dict())
    observations = _random_observations(5, seed=3)
    assert np.allclose(restored.transitions, model.transitions)
    assert np.allclose(restored.initial, model.initial)
    assert list(restored.viterbi(observations)[0]) == list(model.viterbi(observations)[0])


def test_constructor_rejects_wrong_shapes():
    e = build_prior_emissions()
    with pytest.raises(ValueError):
        KillChainHMM(np.eye(5), np.ones(6) / 6, e)
    with pytest.raises(ValueError):
        KillChainHMM(np.eye(6), np.ones(5) / 5, e)
