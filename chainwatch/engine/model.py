"""Design-spec priors for the kill chain HMM -- ChainWatch section IV-C.

The paper publishes no trained parameters. Section IV-C states only that the
transition structure reflects three constraints, and that "specific transition
values are design choices pending Baum-Welch estimation from labelled trace data".

So this module supplies:

* :func:`build_transition_matrix` -- generates ``A`` from those three constraints
  rather than hardcoding 36 opaque numbers, so it stays auditable against the paper.
* :func:`build_prior_emissions` -- derives ``B`` from Table I's "Key Observable
  Features" column, which is the only description of stage behaviour the paper gives.
* :func:`build_prior_model` -- assembles both into a usable model.

Every value here is a prior to be replaced by ``chainwatch train`` once real traces
exist. They are chosen to be *defensible from the paper's text*, not tuned to be
correct in any absolute sense.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from .hmm import N_STAGES, FactoredEmissions, KillChainHMM

#: Section IV-C constraint weights, expressed as unnormalised transition mass.
#:
#: "forward transitions are more probable than backward ones"  -> FORWARD_1 >> BACKWARD
#: "large jumps of more than two stages are unlikely"           -> FAR_JUMP is small
#:
#: "Unlikely" is not "impossible". Section V-B's own scenarios contain two such
#: jumps -- S5 has read_env "jumping to Stage 4" from Reconnaissance, and S3 jumps
#: three stages to Exfiltration. At 0.02 the prior made those paths so costly that
#: Viterbi preferred to relabel the *earlier* calls to avoid them, which is how a
#: prior ends up contradicting the paper it came from. 0.06 keeps far jumps well
#: below FORWARD_2 (0.15) while leaving them reachable on real evidence.
#: "small backward probabilities are retained because attackers
#:  sometimes repeat earlier behaviour"                         -> BACKWARD > 0
SELF_TRANSITION = 0.35
FORWARD_1 = 0.35
FORWARD_2 = 0.15
FAR_JUMP_TOTAL = 0.06
BACKWARD_TOTAL = 0.05

#: Sessions overwhelmingly begin with Reconnaissance; an attacker probing what is
#: available is the documented entry point, and a benign session's first call is
#: equally unremarkable there.
#:
#: This carries real weight. Stage 1 and stage 2 emit similarly -- both are benign
#: -- so pi is much of what separates "first call of the session" from "ordinary
#: call mid-session". Too flat and scenario S5's opening list_tools gets relabelled
#: to Trust Building purely to make its jump to Escalation cheaper.
INITIAL_DISTRIBUTION = np.array([0.70, 0.15, 0.05, 0.05, 0.03, 0.02])


def build_transition_matrix() -> np.ndarray:
    """Construct ``A`` from section IV-C's three stated constraints.

    Mass that would fall off the end of the chain (a forward jump from stage 6)
    is left unallocated and removed by row normalisation, which naturally makes
    late stages stickier -- an attacker at Exfiltration has nowhere further to go.
    """
    matrix = np.zeros((N_STAGES, N_STAGES), dtype=np.float64)

    for row in range(N_STAGES):
        matrix[row, row] = SELF_TRANSITION

        if row + 1 < N_STAGES:
            matrix[row, row + 1] = FORWARD_1
        if row + 2 < N_STAGES:
            matrix[row, row + 2] = FORWARD_2

        far_targets = [c for c in range(row + 3, N_STAGES)]
        if far_targets:
            for column in far_targets:
                matrix[row, column] = FAR_JUMP_TOTAL / len(far_targets)

        backward_targets = [c for c in range(0, row)]
        if backward_targets:
            for column in backward_targets:
                matrix[row, column] = BACKWARD_TOTAL / len(backward_targets)

    return matrix / matrix.sum(axis=1, keepdims=True)


def build_prior_emissions() -> FactoredEmissions:
    """Derive ``B`` from Table I's observable features, stage by stage.

    Each row below is a direct reading of one Table I entry. The comments quote
    the paper so the mapping can be checked without leaving the file.
    """
    # --- Tool Category: READ, WRITE, EXECUTE, NETWORK, CONFIGURE
    tc_probs = np.array(
        [
            # 1 Reconnaissance: "tools/list calls, sparse params, rapid tool sampling"
            #   Overwhelmingly READ. Probing is by definition observational, so a
            #   WRITE or NETWORK call as the opening action is strong evidence the
            #   session did NOT start with reconnaissance. Held at 0.80 this was
            #   too soft: scenario S3 opens with send_message and the prior alone
            #   was enough to call it recon anyway.
            [0.90, 0.03, 0.02, 0.02, 0.03],
            # 2 Trust Building: "benign patterns" -- ordinary mixed work, including
            #   legitimate messaging, which is why NETWORK keeps real mass here.
            #   READ is high because benign sessions are read-dominated too. An
            #   earlier 0.45 made every plain read fit Reconnaissance better than
            #   Trust Building, so a benign lookup mid-session was labelled recon
            #   (scenario S3). Stages 1 and 2 are separated by pi and by Table I's
            #   "sparse params / rapid tool sampling", not by being read-heavy.
            [0.60, 0.18, 0.04, 0.14, 0.04],
            # 3 Injection: the call that ingests poisoned content, or a delegated
            #   task carrying it. Reads and executes dominate.
            [0.45, 0.10, 0.25, 0.15, 0.05],
            # 4 Escalation: "READ-to-WRITE transitions"
            [0.35, 0.45, 0.10, 0.05, 0.05],
            # 5 Lateral Movement: ".mcp.json edits, agent spawning"
            [0.05, 0.10, 0.25, 0.05, 0.55],
            # 6 Exfiltration: "communication tools with data"
            [0.05, 0.10, 0.05, 0.75, 0.05],
        ]
    )

    # --- Parameter Sensitivity: one Gaussian per stage.
    # The gradient from 0.03 to 0.55 is the "rising sensitivity" of stage 4.
    # Injection sits low: the call that *ingests* poisoned content is typically an
    # ordinary read of a public issue or ticket. Its signature is the output, not
    # the parameters. Keeping stage 3's PS low is what stops a high-sensitivity
    # credential read (scenario S5's read_env) from being mistaken for injection.
    ps_mean = np.array([[0.03], [0.05], [0.12], [0.55], [0.40], [0.50]])
    ps_std = np.array([[0.08], [0.08], [0.15], [0.25], [0.30], [0.30]])

    # --- Data Flow: internal-read, external-write, chained, cross-server
    df_probs = np.array(
        [
            [0.80, 0.05, 0.02, 0.05],  # 1 probing, nothing leaves
            [0.65, 0.35, 0.05, 0.02],  # 2 "no cross-server calls"
            [0.55, 0.25, 0.10, 0.05],  # 3 ingesting injected content
            [0.45, 0.50, 0.35, 0.05],  # 4 "chained data"
            [0.15, 0.70, 0.25, 0.60],  # 5 "cross-server calls"
            [0.05, 0.85, 0.70, 0.15],  # 6 "READ-to-NETWORK chain"
        ]
    )

    # --- Temporal: inter-call interval (log1p seconds), call rate, session age.
    # The paper says only that "rapid bursts are characteristic of automated attack
    # execution" and publishes no distributions.
    # Identical across all six stages, and deliberately so: the prior is
    # UNINFORMATIVE. An identical Gaussian contributes the same constant to every
    # state, so it cancels exactly in both argmax and Viterbi and cannot influence
    # a stage label.
    #
    # This is a correction, not laziness. An earlier version varied the means
    # slightly per stage -- "rapid bursts" for Reconnaissance, rising session age
    # thereafter -- which sounds reasonable but is pure invention: the paper gives
    # no temporal distributions whatsoever. Those invented values were shifting
    # decisions by a few tenths of a nat, which was enough to flip the stage
    # labels in scenarios S3 and S5 depending on nothing more than whether an
    # inter-call interval was measured before or after the call was committed.
    # Stage labels must rest on evidence the paper actually specifies. Baum-Welch
    # will learn the real temporal structure from traces; until then it stays mute.
    # On the log1p scale all three dims live in roughly [0, 10].
    tf_mean = np.tile(np.array([0.50, 1.00, 2.50]), (N_STAGES, 1))
    tf_std = np.tile(np.array([1.50, 1.50, 2.50]), (N_STAGES, 1))

    # --- Output Characteristics: imperative, xml, desc-mismatch, volume,
    #     hash-change, encoded, external-url.
    # Table II: "These flags map most directly to Stages 3 and 5 of the kill chain."
    # Stage 3 is a balancing act, and the flags are modelled as INDEPENDENT.
    # Push the markers too high and a single-signal injection stops fitting: a
    # pure rug-pull (scenario S3) raises hash-change and nothing else, so with
    # imperative/xml/mismatch all at 0.80 the absent markers outweighed the
    # present one and the call fell back to Reconnaissance. Push them too low and
    # an unrelated credential read drifts into Injection (scenario S5).
    # Hash-change therefore carries the most mass -- it is the one marker that is
    # unambiguous on its own and needs no corroboration.
    #
    # Its probability at the BENIGN stages matters just as much, and is set to
    # 0.005 rather than 0.02. A well-behaved MCP server does not rewrite a tool
    # definition the user already approved; section II-A calls that out as the
    # rug-pull vector precisely because the protocol permits it silently. At 0.02
    # the evidence was too cheap to explain away, and scenario S3's swapped
    # get_fact stayed in Reconnaissance -- the model shrugged at the one signal
    # the entire attack turns on.
    oc_probs = np.array(
        [
            [0.02, 0.02, 0.02, 0.03, 0.005, 0.03, 0.05],  # 1
            [0.02, 0.02, 0.02, 0.03, 0.005, 0.03, 0.05],  # 2
            [0.55, 0.40, 0.35, 0.15, 0.75, 0.15, 0.20],  # 3 injection markers
            [0.08, 0.05, 0.08, 0.12, 0.02, 0.10, 0.10],  # 4
            [0.10, 0.08, 0.10, 0.10, 0.15, 0.12, 0.15],  # 5 defs change here too
            [0.08, 0.05, 0.10, 0.20, 0.02, 0.20, 0.35],  # 6 data heading out
        ]
    )

    return FactoredEmissions(
        tc_probs=tc_probs,
        ps_mean=ps_mean,
        ps_std=ps_std,
        df_probs=df_probs,
        tf_mean=tf_mean,
        tf_std=tf_std,
        oc_probs=oc_probs,
    )


def build_prior_model() -> KillChainHMM:
    """The design-spec model used until real traces have been captured."""
    return KillChainHMM(
        transitions=build_transition_matrix(),
        initial=INITIAL_DISTRIBUTION.copy(),
        emissions=build_prior_emissions(),
    )


def save_model(model: KillChainHMM, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(model.to_dict(), indent=2), encoding="utf-8")


def load_model(path: str | Path) -> KillChainHMM:
    return KillChainHMM.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
