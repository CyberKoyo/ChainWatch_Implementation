"""Feature Extraction Layer -- ChainWatch section IV-B, Table II.

Converts each raw MCP tool call into the fixed 20-dimensional vector the HMM
consumes. The index layout is the contract every other module depends on:

    idx  0-4   TC  one-hot   READ, WRITE, EXECUTE, NETWORK, CONFIGURE
    idx  5     PS  float     parameter sensitivity in [0, 1]
    idx  6-9   DF  binary    internal-read, external-write, chained, cross-server
    idx 10-12  TF  float     inter-call interval, call rate over k, session age
    idx 13-19  OC  binary    imperative text, XML tags, desc-output mismatch,
                             volume anomaly, hash change, encoded data, external URL

Two-phase extraction
--------------------
Output Characteristics describe a call's *response*, but rules R3 and R5 must block
a call *before* it executes. So extraction runs twice per call:

* :meth:`FeatureExtractor.extract` -- pre-flight, before forwarding. OC dims that
  depend on the response are 0; ``hash change`` is still available because it comes
  from ``tools/list``, which was seen earlier.
* :meth:`FeatureExtractor.observe_response` -- after the response returns. Fills the
  OC dims in and updates session state so *subsequent* calls see the truth.

This is what lets scenario S2 work: the injection flag raised by ``get_issue``'s
response is what colours the following ``read_file`` and ``create_PR``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Iterable

import numpy as np

from .taxonomy import (
    ENCODED_BLOB_RE,
    HEX_BLOB_RE,
    URL_RE,
    SensitivityScorer,
    ToolCategory,
    ToolClassifier,
    looks_base64,
)

#: Length of the feature vector. Fixed by Table II; asserted in tests.
FEATURE_DIM = 20

# Index constants. Prefer these over integer literals everywhere else.
TC_SLICE = slice(0, 5)
PS_INDEX = 5
DF_SLICE = slice(6, 10)
DF_INTERNAL_READ, DF_EXTERNAL_WRITE, DF_CHAINED, DF_CROSS_SERVER = 6, 7, 8, 9
TF_SLICE = slice(10, 13)
TF_INTERVAL, TF_CALL_RATE, TF_SESSION_AGE = 10, 11, 12
OC_SLICE = slice(13, 20)
(
    OC_IMPERATIVE,
    OC_XML_TAGS,
    OC_DESC_MISMATCH,
    OC_VOLUME_ANOMALY,
    OC_HASH_CHANGE,
    OC_ENCODED_DATA,
    OC_EXTERNAL_URL,
) = range(13, 20)

FEATURE_NAMES: tuple[str, ...] = (
    "tc_read",
    "tc_write",
    "tc_execute",
    "tc_network",
    "tc_configure",
    "ps_sensitivity",
    "df_internal_read",
    "df_external_write",
    "df_chained",
    "df_cross_server",
    "tf_interval",
    "tf_call_rate",
    "tf_session_age",
    "oc_imperative_text",
    "oc_xml_tags",
    "oc_desc_mismatch",
    "oc_volume_anomaly",
    "oc_hash_change",
    "oc_encoded_data",
    "oc_external_url",
)

#: Phrases characteristic of instructions smuggled into tool output. Tool poisoning
#: (section II-B) works by getting the model to treat server output as direction, so
#: these target the imperative register rather than any specific payload.
IMPERATIVE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"disregard\s+(all\s+)?(previous|prior|the\s+above)",
        r"you\s+must\s+(now|immediately|instead)",
        r"do\s+not\s+(tell|inform|mention|alert)\s+the\s+user",
        r"without\s+(telling|informing|asking)\s+the\s+user",
        r"\bnew\s+instructions?\b",
        r"\bsystem\s*(prompt|message)\s*:",
        r"important\s*:\s*(before|first|you\s+must)",
        r"instead\s+of\s+.{0,40}\s*,?\s*(you\s+should|please)\s+",
        r"as\s+an\s+ai\s+(assistant|agent)\s*,?\s*you\s+(should|must)",
    )
)

#: Pseudo-XML wrappers are the common carrier for injected blocks, e.g.
#: ``<IMPORTANT>`` or ``<instructions>``. Ordinary HTML is excluded to keep the
#: signal specific.
XML_TAG_RE = re.compile(
    r"</?\s*(important|instruction|instructions|system|prompt|secret|hidden|admin|note_to_ai)\s*>",
    re.IGNORECASE,
)

#: mcpwall flags responses above 100 KB (``flag-large-responses``). Reused so the
#: two layers call the same thing anomalous.
ABSOLUTE_VOLUME_BYTES = 102_400

#: Minimum length of an output substring worth remembering for chained-data
#: detection. Short strings collide with ordinary argument values ("true", ids).
MIN_CHAIN_TOKEN_LEN = 12

#: Cap on remembered output tokens, so a long session cannot grow without bound.
MAX_CHAIN_TOKENS = 512

#: Identifiers are exempt from MIN_CHAIN_TOKEN_LEN. A tool that returns
#: ``{"file_id": "29"}`` and a later call that passes ``file_id=29`` is a genuine
#: propagated data flow -- the paper's DF definition is "carries data propagated
#: from a previous call's output", and an id is exactly that. Requiring 12
#: characters silently excluded every identifier, which on the AgentLAB replay
#: left df_chained at 0.0% across all 560 attack calls and stopped rule R3 from
#: ever firing. They are matched on word boundaries so a short id cannot collide
#: with an unrelated substring.
MIN_IDENTIFIER_LEN = 4

#: Chained-data matching is done on sliding windows, not whole values.
#:
#: An agent forwarding data copies a *portion* of what it read -- a paragraph out
#: of a file, a field out of a record. Requiring the entire prior response to
#: appear verbatim in a later argument is far too strict: on the AgentLAB replay
#: it left df_chained at 0 across all 560 attack calls, even though 80% of the
#: read-then-network chains demonstrably do forward read content. Windowing
#: recovers exactly that, and stays specific because a 24-character run of text
#: does not recur between unrelated calls by chance.
CHAIN_WINDOW = 24
CHAIN_WINDOW_STRIDE = 12
#: Bounds the work per remembered value, so one huge response cannot make
#: extraction quadratic in a long session.
MAX_WINDOWS_PER_TOKEN = 96

_ID_KEY_RE = re.compile(r"(^|_)ids?$|^id_?$", re.IGNORECASE)

_WORD_RE = re.compile(r"[a-z][a-z0-9_]{2,}")


@dataclass
class ObservedCall:
    """One MCP ``tools/call`` as ChainWatch sees it.

    ``response_text`` is ``None`` during the pre-flight pass and populated on the
    post-response pass.
    """

    tool: str
    arguments: Any
    server: str = "default"
    timestamp: float = field(default_factory=time.time)
    response_text: str | None = None
    response_bytes: int = 0
    tool_description: str | None = None


@dataclass
class SessionState:
    """Mutable per-session memory the extractor needs across calls.

    Held separately from the extractor so the daemon can own one instance shared
    by every proxied server -- which is what makes ``cross-server`` (dim 9) and
    rule R2 real rather than permanently zero.
    """

    first_timestamp: float | None = None
    last_timestamp: float | None = None
    last_server: str | None = None
    servers_seen: set[str] = field(default_factory=set)
    call_timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=64))
    output_tokens: Deque[str] = field(default_factory=lambda: deque(maxlen=MAX_CHAIN_TOKENS))
    #: Short identifier values seen in responses, matched on word boundaries.
    identifier_tokens: Deque[str] = field(default_factory=lambda: deque(maxlen=MAX_CHAIN_TOKENS))
    tool_definition_hashes: dict[str, str] = field(default_factory=dict)
    response_sizes: dict[str, list[int]] = field(default_factory=dict)
    #: Tool names whose definition hash changed mid-session -- the rug-pull signal.
    #: Sticky: once a server has swapped a definition it stays suspect.
    changed_tools: set[str] = field(default_factory=set)


class FeatureExtractor:
    """Builds 20-dim vectors from MCP traffic.

    Stateful by necessity: ``chained``, ``cross-server``, the temporal group and
    most of OC are all defined relative to what the session has already done.
    """

    def __init__(
        self,
        classifier: ToolClassifier | None = None,
        scorer: SensitivityScorer | None = None,
        state: SessionState | None = None,
        window: int = 10,
    ) -> None:
        self.classifier = classifier or ToolClassifier()
        self.scorer = scorer or SensitivityScorer()
        self.state = state if state is not None else SessionState()
        #: Matches the Sequential Pattern Analyzer's k, so "call rate over k"
        #: measures the same span the rules reason about.
        self.window = window

    # ------------------------------------------------------------------ tools/list

    def register_tool_definitions(self, server: str, tools: Iterable[dict[str, Any]]) -> set[str]:
        """Hash tool definitions from a ``tools/list`` response.

        Returns the names whose definition changed since last seen. The MCP spec
        permits a server to alter a tool after the user approved it and provides no
        way to notice (section II-A); this is where ChainWatch notices.
        """
        changed: set[str] = set()
        for tool in tools:
            name = tool.get("name")
            if not name:
                continue
            key = f"{server}:{name}"
            digest = hashlib.sha256(
                json.dumps(tool, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            previous = self.state.tool_definition_hashes.get(key)
            if previous is not None and previous != digest:
                changed.add(name)
                self.state.changed_tools.add(name)
            self.state.tool_definition_hashes[key] = digest
        return changed

    # ------------------------------------------------------------------ extraction

    def extract(self, call: ObservedCall) -> np.ndarray:
        """Build the feature vector for ``call``.

        Safe to invoke pre-flight: when ``call.response_text`` is ``None`` the
        response-derived OC dims stay 0 and only ``hash change`` -- knowable from
        an earlier ``tools/list`` -- can fire.
        """
        vector = np.zeros(FEATURE_DIM, dtype=np.float64)
        category = self.classifier.classify(call.tool, call.tool_description)

        vector[category.value] = 1.0
        vector[PS_INDEX] = self.scorer.score(call.arguments)

        self._fill_data_flow(vector, call, category)
        self._fill_temporal(vector, call)
        self._fill_output_characteristics(vector, call)
        return vector

    def commit(self, call: ObservedCall) -> None:
        """Fold ``call`` into session state. Call once per call, after extraction.

        Kept separate from :meth:`extract` so a blocked call can still be scored
        without polluting the timeline of calls that actually ran.
        """
        if self.state.first_timestamp is None:
            self.state.first_timestamp = call.timestamp
        self.state.last_timestamp = call.timestamp
        self.state.last_server = call.server
        self.state.servers_seen.add(call.server)
        self.state.call_timestamps.append(call.timestamp)

    def patch_output_characteristics(
        self, vector: np.ndarray, call: ObservedCall, response_text: str
    ) -> np.ndarray:
        """Fill the OC dims of an existing pre-flight vector from the response.

        The alternative -- re-running :meth:`extract` once the response arrives --
        would corrupt the temporal group, because :meth:`commit` has by then
        already advanced ``last_timestamp`` to this very call, making the
        inter-call interval 0. So the pre-flight vector's TC/PS/DF/TF dims are
        authoritative and only dims 13-19 are rewritten here.

        Returns a new array; the input is left untouched.
        """
        call.response_text = response_text
        call.response_bytes = len(response_text.encode("utf-8"))

        patched = vector.copy()
        patched[OC_SLICE] = 0.0
        self._fill_output_characteristics(patched, call)

        self.state.response_sizes.setdefault(call.tool, []).append(call.response_bytes)
        self._remember_output_tokens(response_text)
        return patched

    def observe_response(self, call: ObservedCall, response_text: str) -> np.ndarray:
        """Re-extract with the response attached, then remember its content.

        Returns the completed vector -- the one that should be recorded in the
        session history, since it is the only version with OC filled in.
        """
        call.response_text = response_text
        call.response_bytes = len(response_text.encode("utf-8"))
        vector = self.extract(call)

        sizes = self.state.response_sizes.setdefault(call.tool, [])
        sizes.append(call.response_bytes)
        self._remember_output_tokens(response_text)
        return vector

    # ------------------------------------------------------------------ groups

    def _fill_data_flow(self, vector: np.ndarray, call: ObservedCall, category: ToolCategory) -> None:
        """DF, dims 6-9.

        ``internal-read`` and ``external-write`` follow from the category.
        ``chained`` is the exfiltration tell: an argument carrying a span that came
        out of an earlier response. ``cross-server`` needs the shared session and is
        why the daemon exists.
        """
        if category is ToolCategory.READ:
            vector[DF_INTERNAL_READ] = 1.0
        if category in (ToolCategory.NETWORK, ToolCategory.WRITE, ToolCategory.CONFIGURE):
            vector[DF_EXTERNAL_WRITE] = 1.0

        argument_text = "\n".join(self.scorer._iter_strings(call.arguments))
        if self._carries_prior_output(argument_text):
            vector[DF_CHAINED] = 1.0

        if self.state.last_server is not None and call.server != self.state.last_server:
            vector[DF_CROSS_SERVER] = 1.0

    def _fill_temporal(self, vector: np.ndarray, call: ObservedCall) -> None:
        """TF, dims 10-12. Rapid bursts are characteristic of automated execution."""
        if self.state.last_timestamp is not None:
            delta = max(0.0, call.timestamp - self.state.last_timestamp)
            vector[TF_INTERVAL] = math.log1p(delta)

        # All three temporal dims are log-scaled. Rate and age are unbounded in
        # principle -- a replay harness firing calls back to back reached 1816
        # calls/second, which against a Gaussian prior is a z-score of 605 and a
        # log-density of -1.8e5 from one observation. That swamped the entire
        # model likelihood and would have had Baum-Welch fitting noise. log1p
        # keeps them compact without discarding the ordering that matters.
        timestamps = list(self.state.call_timestamps)[-self.window :]
        if len(timestamps) >= 2:
            span = max(1e-6, timestamps[-1] - timestamps[0])
            vector[TF_CALL_RATE] = math.log1p(len(timestamps) / span)

        if self.state.first_timestamp is not None:
            vector[TF_SESSION_AGE] = math.log1p(max(0.0, call.timestamp - self.state.first_timestamp))

    def _fill_output_characteristics(self, vector: np.ndarray, call: ObservedCall) -> None:
        """OC, dims 13-19 -- signals of a compromised server.

        ``hash change`` is sticky and available pre-flight; everything else needs
        the response and stays 0 until :meth:`observe_response`.
        """
        if call.tool in self.state.changed_tools:
            vector[OC_HASH_CHANGE] = 1.0

        text = call.response_text
        if not text:
            return

        if any(pattern.search(text) for pattern in IMPERATIVE_PATTERNS):
            vector[OC_IMPERATIVE] = 1.0
        if XML_TAG_RE.search(text):
            vector[OC_XML_TAGS] = 1.0
        if self._description_mismatch(call, text):
            vector[OC_DESC_MISMATCH] = 1.0
        if self._volume_anomaly(call):
            vector[OC_VOLUME_ANOMALY] = 1.0
        if HEX_BLOB_RE.search(text) or any(
            looks_base64(candidate) for candidate in ENCODED_BLOB_RE.findall(text)
        ):
            vector[OC_ENCODED_DATA] = 1.0
        if any(self.scorer._is_external(url) for url in URL_RE.findall(text)):
            vector[OC_EXTERNAL_URL] = 1.0

    # ------------------------------------------------------------------ helpers

    def _carries_prior_output(self, argument_text: str) -> bool:
        """True if an argument echoes a substantial span of an earlier response."""
        if not argument_text:
            return False
        for token in self.state.output_tokens:
            if len(token) <= CHAIN_WINDOW:
                if token in argument_text:
                    return True
                continue
            limit = min(len(token) - CHAIN_WINDOW, MAX_WINDOWS_PER_TOKEN * CHAIN_WINDOW_STRIDE)
            for start in range(0, limit + 1, CHAIN_WINDOW_STRIDE):
                if token[start : start + CHAIN_WINDOW] in argument_text:
                    return True
        # Identifiers need boundary matching: "29" must not match "1293".
        return any(
            re.search(rf"(?<![A-Za-z0-9]){re.escape(token)}(?![A-Za-z0-9])", argument_text)
            for token in self.state.identifier_tokens
        )

    def _remember_output_tokens(self, response_text: str) -> None:
        """Record distinctive spans of a response for later chained-data checks.

        MCP responses are JSON and usually arrive on a single line, so remembering
        raw lines would store ``{"content": "AKIA..."}`` -- which never reappears
        verbatim in a later argument. Parse first and remember the *string leaves*;
        those are what an exfiltration chain actually carries forward. Non-JSON
        payloads fall back to line granularity.

        Whole values are used rather than words: a word repeats by coincidence, a
        12-plus character value carried into a later argument does not.
        """
        candidates: list[str] = []
        try:
            payload = json.loads(response_text)
        except (ValueError, TypeError):
            candidates = [line.strip().strip('",') for line in response_text.splitlines()]
        else:
            candidates = list(self.scorer._iter_strings(payload))
            # Keep the raw text too, so a bare JSON string response still registers.
            candidates.extend(line.strip().strip('",') for line in response_text.splitlines())
            self._remember_identifiers(payload)

        for candidate in candidates:
            if len(candidate) >= MIN_CHAIN_TOKEN_LEN:
                self.state.output_tokens.append(candidate)

    def _remember_identifiers(self, payload: Any, key: str | None = None) -> None:
        """Record identifier values, which are chainable regardless of length."""
        if isinstance(payload, dict):
            for child_key, child in payload.items():
                self._remember_identifiers(child, child_key)
        elif isinstance(payload, (list, tuple)):
            for child in payload:
                self._remember_identifiers(child, key)
        elif key and _ID_KEY_RE.search(key) and isinstance(payload, (str, int)):
            text = str(payload)
            if MIN_IDENTIFIER_LEN <= len(text) <= 64:
                self.state.identifier_tokens.append(text)

    def _description_mismatch(self, call: ObservedCall, response_text: str) -> bool:
        """True if the response bears little relation to what the tool claims to do.

        A crude lexical overlap test, and deliberately conservative -- it only
        fires on substantial responses, so a terse ``{"success": true}`` is never
        flagged for failing to echo its description.
        """
        description = call.tool_description
        if not description or len(response_text) < 200:
            return False
        description_words = set(_WORD_RE.findall(description.lower()))
        response_words = set(_WORD_RE.findall(response_text.lower()))
        if not description_words or not response_words:
            return False
        overlap = len(description_words & response_words) / len(description_words)
        return overlap < 0.1

    def _volume_anomaly(self, call: ObservedCall) -> bool:
        """True if this response is far larger than this tool's norm.

        Absolute ceiling matches mcpwall's 100 KB threshold; the statistical arm
        catches a tool that quietly starts returning ten times its usual payload.
        """
        if call.response_bytes >= ABSOLUTE_VOLUME_BYTES:
            return True
        history = self.state.response_sizes.get(call.tool, [])
        if len(history) < 3:
            return False
        mean = statistics.mean(history)
        deviation = statistics.pstdev(history)
        if deviation == 0:
            return call.response_bytes > mean * 3
        return call.response_bytes > mean + 3 * deviation
