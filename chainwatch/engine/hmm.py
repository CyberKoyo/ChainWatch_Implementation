"""Kill Chain Stage Classifier -- ChainWatch section IV-C.

Assigns each tool call one of the six kill chain stages. Stage assignment is a
hidden state inference problem, so the paper models it as an HMM
``lambda = (S, Sigma, A, B, pi)`` with ``|S| = 6`` and observations in R^20,
adapting Holgado et al. by replacing discrete IDS alert types with
continuous feature vectors.

Factored emissions
------------------
The 20-dim vector is not homogeneous: TC is a one-hot categorical, DF and OC are
11 independent binary flags, PS and TF are 4 continuous quantities. Modelling all
20 with a single multivariate Gaussian -- what a standard ``GaussianHMM``
would do -- is both statistically wrong and unreadable. Instead each group keeps
its natural distribution and the log-densities add:

    log b_s(v) = log Cat5(TC) + log N(PS) + sum log Bern(DF)
                 + sum log N(TF) + sum log Bern(OC)

Everything runs in log-space; a session of 10 calls with 20 near-zero densities
each would underflow float64 otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .features import DF_SLICE, FEATURE_DIM, OC_SLICE, PS_INDEX, TC_SLICE, TF_SLICE

#: Number of kill chain stages (section III-C, Table I).
N_STAGES = 6

#: Stage names indexed 0-5 internally; presented to users as 1-6 to match the paper.
STAGE_NAMES: tuple[str, ...] = (
    "Reconnaissance",
    "Trust Building",
    "Injection",
    "Escalation",
    "Lateral Movement",
    "Exfiltration",
)

#: Floor for probabilities, so log() never sees a hard zero. A stage that has
#: never emitted a flag must remain merely improbable, not impossible -- otherwise
#: one unseen combination makes an entire Viterbi path -inf.
EPSILON = 1e-6

#: Minimum standard deviation for Gaussian components, guarding against a
#: degenerate fit when Baum-Welch sees a feature that never varies.
MIN_STD = 1e-3


def log_sum_exp(values: np.ndarray, axis: int | None = None) -> np.ndarray:
    """Numerically stable ``log(sum(exp(values)))``.

    Hand-rolled because scipy is not a dependency; the shift-by-max trick is all
    that is needed.
    """
    maximum = np.max(values, axis=axis, keepdims=True)
    maximum = np.where(np.isfinite(maximum), maximum, 0.0)
    shifted = np.exp(values - maximum)
    total = np.log(np.sum(shifted, axis=axis, keepdims=True)) + maximum
    return np.squeeze(total, axis=axis) if axis is not None else total.reshape(())


def _log_gaussian(x: np.ndarray, mean: np.ndarray, std: np.ndarray) -> np.ndarray:
    """Elementwise log N(x; mean, std)."""
    std = np.maximum(std, MIN_STD)
    z = (x - mean) / std
    return -0.5 * z * z - np.log(std) - 0.5 * np.log(2.0 * np.pi)


def _log_bernoulli(x: np.ndarray, p: np.ndarray) -> np.ndarray:
    """Elementwise log Bern(x; p), with x in {0, 1}."""
    p = np.clip(p, EPSILON, 1.0 - EPSILON)
    return x * np.log(p) + (1.0 - x) * np.log(1.0 - p)


@dataclass
class FactoredEmissions:
    """Per-stage emission parameters, one block per feature group.

    Shapes are all ``(N_STAGES, group_width)``, so every computation below stays a
    single broadcast against the observation.
    """

    tc_probs: np.ndarray  # (6, 5)  categorical over Tool Category
    ps_mean: np.ndarray  # (6, 1)
    ps_std: np.ndarray  # (6, 1)
    df_probs: np.ndarray  # (6, 4)  independent Bernoulli
    tf_mean: np.ndarray  # (6, 3)
    tf_std: np.ndarray  # (6, 3)
    oc_probs: np.ndarray  # (6, 7)  independent Bernoulli

    def log_prob(self, observation: np.ndarray) -> np.ndarray:
        """Log emission density of one 20-dim observation under each stage.

        Returns shape ``(N_STAGES,)``.
        """
        tc = observation[TC_SLICE]
        ps = observation[PS_INDEX]
        df = observation[DF_SLICE]
        tf = observation[TF_SLICE]
        oc = observation[OC_SLICE]

        # TC is one-hot, so the dot product selects the probability of the
        # category that actually fired.
        tc_term = np.log(np.clip(self.tc_probs @ tc, EPSILON, None))
        ps_term = _log_gaussian(ps, self.ps_mean[:, 0], self.ps_std[:, 0])
        df_term = _log_bernoulli(df, self.df_probs).sum(axis=1)
        tf_term = _log_gaussian(tf, self.tf_mean, self.tf_std).sum(axis=1)
        oc_term = _log_bernoulli(oc, self.oc_probs).sum(axis=1)

        return tc_term + ps_term + df_term + tf_term + oc_term

    def log_prob_matrix(self, observations: np.ndarray) -> np.ndarray:
        """Log emission densities for a whole sequence. Shape ``(T, N_STAGES)``."""
        return np.vstack([self.log_prob(o) for o in np.atleast_2d(observations)])

    def to_dict(self) -> dict[str, list]:
        return {
            "tc_probs": self.tc_probs.tolist(),
            "ps_mean": self.ps_mean.tolist(),
            "ps_std": self.ps_std.tolist(),
            "df_probs": self.df_probs.tolist(),
            "tf_mean": self.tf_mean.tolist(),
            "tf_std": self.tf_std.tolist(),
            "oc_probs": self.oc_probs.tolist(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, list]) -> "FactoredEmissions":
        return cls(**{key: np.asarray(value, dtype=np.float64) for key, value in payload.items()})


class KillChainHMM:
    """Six-state HMM over kill chain stages.

    ``transitions`` and ``initial`` are ordinary probabilities; they are converted
    to logs once at construction because every algorithm below needs them in log
    form.
    """

    def __init__(
        self,
        transitions: np.ndarray,
        initial: np.ndarray,
        emissions: FactoredEmissions,
    ) -> None:
        if transitions.shape != (N_STAGES, N_STAGES):
            raise ValueError(f"transitions must be {(N_STAGES, N_STAGES)}, got {transitions.shape}")
        if initial.shape != (N_STAGES,):
            raise ValueError(f"initial must be {(N_STAGES,)}, got {initial.shape}")

        self.transitions = np.asarray(transitions, dtype=np.float64)
        self.initial = np.asarray(initial, dtype=np.float64)
        self.emissions = emissions
        self._log_transitions = np.log(np.clip(self.transitions, EPSILON, None))
        self._log_initial = np.log(np.clip(self.initial, EPSILON, None))

    # ------------------------------------------------------------------ decoding

    def viterbi(self, observations: np.ndarray) -> tuple[np.ndarray, float]:
        """Most likely stage sequence for ``observations``.

        Returns ``(stages, log_probability)`` with stages **0-indexed**. Callers
        that display stages to a user add 1 to match the paper's 1-6 numbering.

        Section II-D cites Holgado et al.'s use of Viterbi decoding for kill chain
        stage prediction; this is the direct analogue. Decoding is global over the
        window, which is what lets a later, unambiguous call retroactively settle
        an earlier ambiguous one -- exactly the behaviour scenario S1 needs, where
        calls 1 and 2 are near-identical and only the jump to Escalation reveals
        that the second was Trust Building rather than more Reconnaissance.
        """
        observations = np.atleast_2d(observations)
        n_obs = observations.shape[0]
        if n_obs == 0:
            return np.empty(0, dtype=int), 0.0

        log_emissions = self.emissions.log_prob_matrix(observations)

        scores = self._log_initial + log_emissions[0]
        backpointers = np.zeros((n_obs, N_STAGES), dtype=int)

        for t in range(1, n_obs):
            candidates = scores[:, None] + self._log_transitions
            backpointers[t] = np.argmax(candidates, axis=0)
            scores = np.max(candidates, axis=0) + log_emissions[t]

        path = np.zeros(n_obs, dtype=int)
        path[-1] = int(np.argmax(scores))
        for t in range(n_obs - 1, 0, -1):
            path[t - 1] = backpointers[t, path[t]]
        return path, float(np.max(scores))

    # ------------------------------------------------------------- forward/backward

    def forward(self, log_emissions: np.ndarray) -> tuple[np.ndarray, float]:
        """Log forward variables and total log-likelihood."""
        n_obs = log_emissions.shape[0]
        alpha = np.zeros((n_obs, N_STAGES))
        alpha[0] = self._log_initial + log_emissions[0]
        for t in range(1, n_obs):
            alpha[t] = log_sum_exp(alpha[t - 1][:, None] + self._log_transitions, axis=0)
            alpha[t] += log_emissions[t]
        return alpha, float(log_sum_exp(alpha[-1], axis=0))

    def backward(self, log_emissions: np.ndarray) -> np.ndarray:
        """Log backward variables."""
        n_obs = log_emissions.shape[0]
        beta = np.zeros((n_obs, N_STAGES))
        for t in range(n_obs - 2, -1, -1):
            beta[t] = log_sum_exp(
                self._log_transitions + log_emissions[t + 1] + beta[t + 1], axis=1
            )
        return beta

    def log_likelihood(self, observations: np.ndarray) -> float:
        observations = np.atleast_2d(observations)
        if observations.shape[0] == 0:
            return 0.0
        return self.forward(self.emissions.log_prob_matrix(observations))[1]

    def posterior(self, observations: np.ndarray) -> np.ndarray:
        """Per-call stage posteriors, shape ``(T, N_STAGES)``.

        Used for the INFO-level "suspicious stage assignment" signal, where the
        confidence matters as much as the argmax.
        """
        observations = np.atleast_2d(observations)
        log_emissions = self.emissions.log_prob_matrix(observations)
        alpha, total = self.forward(log_emissions)
        beta = self.backward(log_emissions)
        return np.exp(alpha + beta - total)

    # ------------------------------------------------------------------ training

    def baum_welch(
        self,
        sequences: list[np.ndarray],
        iterations: int = 50,
        tolerance: float = 1e-4,
        update_emissions: bool = True,
    ) -> list[float]:
        """Fit the model to unlabelled sequences by Expectation-Maximisation.

        Section IV-C leaves the transition values as "design choices pending
        Baum-Welch estimation from labelled trace data" -- this is that estimator.

        Returns the log-likelihood after each iteration. It is monotonically
        non-decreasing by construction of EM, which the tests assert.

        ``update_emissions=False`` re-estimates only ``A`` and ``pi``, useful when
        the emission priors encode deliberate domain knowledge (the Table I
        observable features) that a small trace set would wash out.
        """
        sequences = [np.atleast_2d(s) for s in sequences if np.atleast_2d(s).shape[0] > 0]
        if not sequences:
            return []

        history: list[float] = []
        for _ in range(iterations):
            initial_acc = np.zeros(N_STAGES)
            transition_acc = np.zeros((N_STAGES, N_STAGES))
            gamma_sum = np.zeros(N_STAGES)
            total_ll = 0.0
            all_gammas: list[np.ndarray] = []
            all_obs: list[np.ndarray] = []

            for observations in sequences:
                log_emissions = self.emissions.log_prob_matrix(observations)
                alpha, sequence_ll = self.forward(log_emissions)
                beta = self.backward(log_emissions)
                total_ll += sequence_ll

                gamma = np.exp(alpha + beta - sequence_ll)
                initial_acc += gamma[0]
                gamma_sum += gamma.sum(axis=0)
                all_gammas.append(gamma)
                all_obs.append(observations)

                for t in range(observations.shape[0] - 1):
                    xi = (
                        alpha[t][:, None]
                        + self._log_transitions
                        + log_emissions[t + 1]
                        + beta[t + 1]
                        - sequence_ll
                    )
                    transition_acc += np.exp(xi)

            history.append(total_ll)

            self.initial = self._normalise(initial_acc)
            self.transitions = np.vstack([self._normalise(row) for row in transition_acc])
            self._log_transitions = np.log(np.clip(self.transitions, EPSILON, None))
            self._log_initial = np.log(np.clip(self.initial, EPSILON, None))

            if update_emissions:
                self._update_emissions(all_obs, all_gammas, gamma_sum)

            if len(history) >= 2 and abs(history[-1] - history[-2]) < tolerance:
                break

        return history

    def _update_emissions(
        self,
        sequences: list[np.ndarray],
        gammas: list[np.ndarray],
        gamma_sum: np.ndarray,
    ) -> None:
        """M-step for the emission parameters, group by group."""
        observations = np.vstack(sequences)
        weights = np.vstack(gammas)  # (T_total, N_STAGES)
        denominator = np.maximum(gamma_sum, EPSILON)[:, None]

        tc = observations[:, TC_SLICE]
        self.emissions.tc_probs = np.vstack(
            [self._normalise(weights[:, s] @ tc) for s in range(N_STAGES)]
        )

        df = observations[:, DF_SLICE]
        self.emissions.df_probs = np.clip((weights.T @ df) / denominator, EPSILON, 1 - EPSILON)

        oc = observations[:, OC_SLICE]
        self.emissions.oc_probs = np.clip((weights.T @ oc) / denominator, EPSILON, 1 - EPSILON)

        ps = observations[:, PS_INDEX : PS_INDEX + 1]
        self.emissions.ps_mean = (weights.T @ ps) / denominator
        ps_var = (weights.T @ (ps**2)) / denominator - self.emissions.ps_mean**2
        self.emissions.ps_std = np.sqrt(np.maximum(ps_var, MIN_STD**2))

        tf = observations[:, TF_SLICE]
        self.emissions.tf_mean = (weights.T @ tf) / denominator
        tf_var = (weights.T @ (tf**2)) / denominator - self.emissions.tf_mean**2
        self.emissions.tf_std = np.sqrt(np.maximum(tf_var, MIN_STD**2))

    @staticmethod
    def _normalise(vector: np.ndarray) -> np.ndarray:
        total = vector.sum()
        if total <= 0:
            return np.full(vector.shape, 1.0 / vector.shape[0])
        return vector / total

    # ------------------------------------------------------------ serialisation

    def to_dict(self) -> dict:
        return {
            "n_stages": N_STAGES,
            "feature_dim": FEATURE_DIM,
            "transitions": self.transitions.tolist(),
            "initial": self.initial.tolist(),
            "emissions": self.emissions.to_dict(),
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "KillChainHMM":
        return cls(
            transitions=np.asarray(payload["transitions"], dtype=np.float64),
            initial=np.asarray(payload["initial"], dtype=np.float64),
            emissions=FactoredEmissions.from_dict(payload["emissions"]),
        )
