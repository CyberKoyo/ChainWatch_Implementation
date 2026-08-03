"""Sequential Pattern Analyzer -- ChainWatch section IV-D.

Holds the sliding window of k=10 calls, drives the HMM over it, and runs the five
rules. This is the component that turns per-call observations into a session-level
judgement.

Call lifecycle
--------------
Each call passes through two points, because a blocking decision has to be made
*before* the call executes while Output Characteristics only exist *after*:

    submit(call)              -> pre-flight Verdict. Blocks on CRITICAL.
    complete(call, response)  -> final Verdict; OC dims filled, stages re-decoded.

A blocked call is never committed to session state: it did not run, so it must not
contaminate the timeline that subsequent calls are judged against.

The one exception is ``submit(..., commit_blocked=True)``, for observe-only
deployments. There the *caller* overrides the block and forwards the call anyway, so
the call did run and its response does need somewhere to land -- without this the
following ``complete()`` would patch the previous call's record instead, silently
losing every CRITICAL call from a captured trace. Whether a blocked call is really
forwarded is the interceptor's decision, so the analyzer has to be told.

Stage labels are re-decoded over the whole window on every update rather than
frozen once assigned. Viterbi is a global optimum over the sequence, so a later
unambiguous call legitimately revises an earlier ambiguous one -- which is exactly
how scenario S1 resolves its near-identical opening pair.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Iterable

import numpy as np

from .alerts import Verdict
from .features import FeatureExtractor, ObservedCall, Provenance
from .hmm import KillChainHMM
from .model import build_prior_model
from .rules import CallRecord, RuleConfig, evaluate


@dataclass
class SessionAnalyzer:
    """One analysed session, potentially spanning several MCP servers.

    The daemon owns a single instance shared by every proxy, which is what makes
    the ``cross-server`` feature dimension and rule R2 meaningful.
    """

    model: KillChainHMM = field(default_factory=build_prior_model)
    extractor: FeatureExtractor = field(default_factory=FeatureExtractor)
    config: RuleConfig = field(default_factory=RuleConfig)

    #: Every completed call, oldest first. The window is the tail of this.
    history: list[CallRecord] = field(default_factory=list)
    _next_index: int = 0

    def __post_init__(self) -> None:
        # Keep the extractor's notion of "call rate over k" aligned with the
        # window the rules actually reason about.
        self.extractor.window = self.config.window

    # ------------------------------------------------------------------ tools/list

    def register_tools(self, server: str, tools: Iterable[dict[str, Any]]) -> set[str]:
        """Forward tool definitions to the extractor for rug-pull hashing."""
        return self.extractor.register_tool_definitions(server, tools)

    # ------------------------------------------------------------------ lifecycle

    def submit(self, call: ObservedCall, *, commit_blocked: bool = False) -> Verdict:
        """Evaluate a pending call. If the verdict blocks, do not forward it.

        ``commit_blocked`` is for observe-only callers that forward the call regardless
        of the verdict; see the module docstring.
        """
        vector = self.extractor.extract(call)
        # Classified before commit(), which is what records the argument side --
        # otherwise this call would introduce its own destination and could never
        # be anything but INTRODUCED.
        provenance = self.extractor.destination_provenance(call)
        window, stages = self._decode_with(vector, call, provenance)
        verdict = Verdict(
            call_index=self._next_index,
            stage=stages[-1],
            vector=vector,
            provenance=provenance,
        )
        verdict.alerts = evaluate(window, self.config)

        if verdict.blocked and not commit_blocked:
            # Blocked calls never happened: leave session state untouched.
            return verdict

        self.extractor.commit(call)
        self.history.append(window[-1])
        self._sync_stages(stages)
        self._next_index += 1
        return verdict

    def complete(self, call: ObservedCall, response_text: str) -> Verdict:
        """Fold a response into the session and re-evaluate the finished call."""
        if not self.history:
            raise RuntimeError("complete() called before any successful submit()")

        last = self.history[-1]
        patched = self.extractor.patch_output_characteristics(last.vector, call, response_text)
        self.history[-1] = replace(last, vector=patched)

        window = self.window
        stages, _ = self.model.viterbi(np.array([r.vector for r in window]))
        self._sync_stages([int(s) + 1 for s in stages])

        window = self.window
        # The *patched* vector, not the pre-flight one: dims 13-19 only exist once the
        # response is folded in, so a trace captured from the pre-flight vector would
        # have the whole Output Characteristics group stuck at zero.
        verdict = Verdict(
            call_index=window[-1].index,
            stage=window[-1].stage,
            vector=window[-1].vector,
            provenance=window[-1].provenance,
        )
        verdict.alerts = evaluate(window, self.config)
        return verdict

    def process(self, call: ObservedCall, response_text: str) -> tuple[Verdict, Verdict]:
        """Convenience for replay and tests: submit, then complete if allowed.

        Returns ``(preflight, final)``. When the call is blocked the response is
        never fetched, so both entries are the same pre-flight verdict.
        """
        preflight = self.submit(call)
        if preflight.blocked:
            return preflight, preflight
        return preflight, self.complete(call, response_text)

    # ------------------------------------------------------------------ internals

    @property
    def window(self) -> list[CallRecord]:
        """The trailing k calls the rules operate over."""
        return self.history[-self.config.window :]

    @property
    def stages(self) -> list[int]:
        """Stage label per completed call, 1-6, in order."""
        return [record.stage for record in self.history]

    def _decode_with(
        self,
        vector: np.ndarray,
        call: ObservedCall,
        provenance: Provenance = Provenance.UNKNOWN,
    ) -> tuple[list[CallRecord], list[int]]:
        """Decode the window with ``vector`` appended as the pending call."""
        window = self.window
        vectors = [record.vector for record in window] + [vector]
        raw_stages, _ = self.model.viterbi(np.array(vectors))
        stages = [int(s) + 1 for s in raw_stages]

        # replace() rather than field-by-field reconstruction. Three sites rebuild
        # these frozen records, and a field added later must not be silently
        # dropped by whichever one was missed -- which is exactly how a defaulted
        # field turns into a bug that no test sees.
        records = [replace(record, stage=stage) for record, stage in zip(window, stages)]
        records.append(
            CallRecord(
                index=self._next_index,
                tool=call.tool,
                server=call.server,
                vector=vector,
                stage=stages[-1],
                provenance=provenance,
            )
        )
        return records, stages

    def _sync_stages(self, stages: list[int]) -> None:
        """Write re-decoded stage labels back over the window."""
        window_size = min(len(stages), len(self.history))
        for offset, stage in enumerate(stages[-window_size:], start=len(self.history) - window_size):
            self.history[offset] = replace(self.history[offset], stage=stage)
