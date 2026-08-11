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
from enum import IntEnum
from functools import lru_cache
from typing import Any, Deque, Iterable

import numpy as np

from .taxonomy import (
    ENCODED_BLOB_RE,
    HEX_BLOB_RE,
    URL_RE,
    SensitivityScorer,
    ToolCategory,
    ToolClassifier,
    destination_tokens,
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

#: Cap on remembered destinations, in the spirit of MAX_CHAIN_TOKENS -- a long
#: session must not grow session state without bound.
MAX_DESTINATIONS = 512

#: An alias is a person- or account-shaped label: letters, spaces and the light
#: punctuation names carry. Bounded so a message body cannot become a recipient --
#: "Dave Smith" aliases, a paragraph does not.
_ALIAS_MIN_LEN = 3
_ALIAS_MAX_LEN = 64
_ALIAS_RE = re.compile(r"[a-z][a-z0-9 .,'\-_]*[a-z0-9]")


class Provenance(IntEnum):
    """Where a call's destination came from. See CLAUDE.md ambiguity A4.

    **Not a feature dimension.** The 20-dim vector is fixed by Table II and feeds
    the HMM; this rides beside it on ``CallRecord`` and is read only by rule R3.
    A 21st dimension would invalidate every trained model and every captured
    trace, and would let a signal the paper never specified move the section V-B
    stage labels.

    Rule R3 as specified fires on the *shape* of an act -- read something, send
    something -- and that shape is equally the assistant's job. What separates
    the exfiltration in ``api_key_calendar_agendas_2`` from its benign twin is
    the recipient: an attacker-controlled contact the agent itself registered 27
    calls earlier. This enum is the question no rule in section IV-D asks.
    """

    #: No destination token in the arguments. Fail closed -- treated as untrusted.
    UNKNOWN = 0
    #: First seen in a clean READ response: the environment named this recipient.
    ATTESTED = 1
    #: First seen in a request argument: the session put this recipient there.
    INTRODUCED = 2
    #: Never seen before this call: invented, or lifted from poisoned content.
    UNATTESTED = 3


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

#: Weak alone, diagnostic together. Each names one property of a payload that is
#: *addressing the agent* rather than describing data: a directive aimed at the
#: reader, or a reference to the surrounding interaction.
#:
#: The conjunction requirement is the whole design. A single directive is
#: ordinary correspondence -- "please review the attached invoice" -- and the
#: mailboxes route C and the twins read are full of them. What an injected block
#: has to do, and ordinary mail does not, is tell the reader to act *and* relate
#: that action to the task it is hijacking.
#:
#: Deliberately not covered: a bare polite request planted in a data field, which
#: is InjecAgent's ``base`` family. It is textually identical to a colleague
#: asking for the same thing, so catching it means flagging real correspondence.
#: What separates those two is the provenance of the destination, which is A4's
#: question and already has a mechanism -- not the prose.
DIRECTIVE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        # a directive aimed at the reader
        r"\bdo\s+the\s+following\b",
        r"\byou\s+(must|should|need\s+to|have\s+to|are\s+required\s+to)\b",
        r"\b(before|after)\s+you\s+(can\s+)?(solve|complete|answer|do|proceed|continue)\b",
        r"\bstrictly\s+adhere\b",
        r"\bonce\s+you\s+have\b",
        # a reference to the surrounding interaction
        r"\bthe\s+task\s+(that\s+)?(i|you)\s+(gave|assigned|were\s+given)\b",
        r"\b(my|the\s+following|these)\s+instructions?\b",
        r"\bin\s+the\s+beginning\b",
        r"\bthis\s+is\s+(an?\s+)?(important|urgent)\s+(message|instruction|notice)\b",
        r"\bto\s+you,\s*(claude|assistant|ai|agent|model|gpt)\b",
    )
)

#: One directive occurs in ordinary prose; two independent ones is the signal.
DIRECTIVE_SIGNAL_MINIMUM = 2

#: Tag names ordinary documents legitimately carry. Everything else in angle
#: brackets is a wrapper somebody added, and a data response is not entitled to
#: add wrappers.
#:
#: Inverting the test this way is what keeps the rule general. An allowlist of
#: *suspicious* names only ever catches payloads whose author happened to pick a
#: name already on the list -- which is how AgentDojo's ``<INFORMATION>`` passed
#: all 27 of its injection tasks untouched while InjecAgent's ``enhanced``
#: variant, which prepends the folk idiom, was caught 186 times out of 186.
_HTML_TAGS = frozenset(
    """
    a abbr address article aside b blockquote body br button caption cite code col
    colgroup dd del details dfn div dl dt em fieldset figcaption figure footer form
    h1 h2 h3 h4 h5 h6 head header hr html i iframe img input ins kbd label legend li
    link main mark meta nav ol optgroup option p pre q s samp script section select
    small source span strong style sub summary sup table tbody td textarea tfoot th
    thead time title tr u ul var video wbr
    """.split()
)

#: The serialisation vocabularies a *data* response is entitled to speak. This is
#: not a name allowlist creeping back in: the test is still "markup the document
#: formats do not define", and these formats define these. AgentDojo's
#: ``<INFORMATION>`` is a wrapper somebody put around prose; ``<rss>``, ``<entry>``
#: and ``<svg>`` are the document's own shape.
_SERIALISATION_TAGS = frozenset(
    """
    atom author channel content description entry feed guid item link rss updated
    circle defs ellipse g path polygon polyline rect svg tspan use
    envelope fault soap rdf xml
    """.split()
)

#: Tag names ordinary documents legitimately carry. Everything else in angle
#: brackets is a wrapper somebody added, and a data response is not entitled to
#: add wrappers.
KNOWN_MARKUP_TAGS = _HTML_TAGS | _SERIALISATION_TAGS

#: Matches a tag-shaped span; the name is then checked against the allowlist.
#: A regex cannot express "not in this set" readably, so the split is deliberate.
_TAG_SHAPE_RE = re.compile(r"(</?)\s*([A-Za-z][A-Za-z0-9_.:-]{0,40})\s*/?>")


class _UnknownTagMatcher:
    """Regex-compatible shim: ``.search(text)`` is truthy on an unknown *wrapper*.

    Presented as a matcher rather than a bare function so the existing call sites
    keep working unchanged -- both ``_fill_output_characteristics`` and
    ``_attest_destinations`` already call ``XML_TAG_RE.search``.

    **A wrapper wraps.** An unknown tag fires only when the same name appears as
    both an opening and a closing tag, because that is what distinguishes a block
    somebody wrapped around prose from the many other things angle brackets mean
    in ordinary data:

    * type parameters -- ``List<Integer>``, ``Vec<u8>``, ``Optional<str>``;
    * command-line placeholders -- ``<msg>``, ``<sha>``, ``<branch>``;
    * anything a shell or a README quotes.

    None of those ever closes. Both published payload families do: AgentDojo's
    ``<INFORMATION>...</INFORMATION>`` and section V-B's
    ``<IMPORTANT>...</IMPORTANT>``.

    The cost is stated rather than hidden: a *lone* unknown opening tag no longer
    raises dim 14. An injected block written that way has to be caught by dim 13's
    directive conjunction instead, which is the detector that does not depend on
    markup at all. Enumerating placeholder names instead would have been the name
    allowlist creeping back in through the other door -- and it was tried first:
    a four-character floor killed ``<msg>`` and ``<sha>`` and left ``<branch>``.
    """

    @staticmethod
    def search(text: str) -> re.Match[str] | None:
        matches = list(_TAG_SHAPE_RE.finditer(text))
        closing = {m.group(2).lower() for m in matches if m.group(1) == "</"}
        for match in matches:
            name = match.group(2).lower()
            if name in KNOWN_MARKUP_TAGS:
                continue
            # A closing tag is proof on its own -- nothing closes what was never
            # opened, and neither a type parameter nor a shell placeholder ever
            # produces one. Taking it alone also covers an opening tag carrying
            # attributes, which the shape pattern does not match:
            # `<INFORMATION type="x">...</INFORMATION>` is seen only by its close.
            if match.group(1) == "</" or name in closing:
                return match
        return None


XML_TAG_RE = _UnknownTagMatcher()

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

#: Separators an account number is written with and remembered without.
_SEPARATOR_RE = re.compile(r"[\s\-]")

#: Longest token worth building a separator-tolerant pattern for. An IBAN is at
#: most 34 characters and a card 19, so this is slack, not a constraint.
_SEPARATOR_TOLERANT_MAX = 64


@lru_cache(maxsize=4096)
def _destination_pattern(token: str) -> re.Pattern[str]:
    """Boundary-anchored, separator-tolerant matcher for one remembered entity.

    ``destination_tokens`` strips separators before remembering, so the stored
    form is compact while the argument may be grouped -- an account read as
    ``GB29NWBK60161331926819`` and written back as ``GB29 NWBK 6016 1331 9268
    19``. Stripping the *argument* instead would fix the value and break
    everything around it: arguments are flattened key-and-value text, so removing
    whitespace glues ``recipient`` onto ``GB29...`` and destroys the very word
    boundary the match depends on. Tolerating separators inside the pattern keeps
    both intact.

    Cached because this runs once per remembered destination per call, and the
    store holds up to ``MAX_CHAIN_TOKENS``. Rebuilding the pattern each time cost
    14 ms of a 16 ms ``extract()`` on a 200-entity session -- 89% of the call, in
    the live proxy's hot path. The tokens repeat across calls, so the cache hits.
    """
    if len(token) > _SEPARATOR_TOLERANT_MAX or _SEPARATOR_RE.search(token):
        body = re.escape(token)
    else:
        body = r"[\s-]*".join(re.escape(character) for character in token)
    return re.compile(rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])")

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
    #: ``(text, producing ToolCategory)``. The category is carried so the corpus
    #: can answer whether R3's chained data actually came from a READ -- which is
    #: what section IV-D's "carrying *that* data" claims and what ambiguity A3
    #: records the implementation cannot enforce.
    output_tokens: Deque[tuple[str, ToolCategory]] = field(
        default_factory=lambda: deque(maxlen=MAX_CHAIN_TOKENS)
    )
    #: Short identifier values seen in responses, matched on word boundaries.
    identifier_tokens: Deque[tuple[str, ToolCategory]] = field(
        default_factory=lambda: deque(maxlen=MAX_CHAIN_TOKENS)
    )
    #: Entities a response *named* -- contacts, IBANs, cards, URL hosts. Kept
    #: apart from ``output_tokens`` because they are matched differently: a host
    #: can be five characters, so the bare containment test that store uses fires
    #: on any word that happens to contain it. Boundary matching is what makes a
    #: short entity chainable without being promiscuous.
    destination_echoes: Deque[tuple[str, ToolCategory]] = field(
        default_factory=lambda: deque(maxlen=MAX_CHAIN_TOKENS)
    )
    tool_definition_hashes: dict[str, str] = field(default_factory=dict)
    response_sizes: dict[str, list[int]] = field(default_factory=dict)
    #: Tool names whose definition hash changed mid-session -- the rug-pull signal.
    #: Sticky: once a server has swapped a definition it stays suspect.
    changed_tools: set[str] = field(default_factory=set)
    #: Destinations the environment named in a clean READ response.
    attested_destinations: set[str] = field(default_factory=set)
    #: Destinations the session itself introduced through a request argument.
    #: Kept disjoint from ``attested_destinations`` by first-sighting-wins.
    introduced_destinations: set[str] = field(default_factory=set)
    #: Lowercased names that appeared *alongside* a destination the session
    #: introduced, so a later call addressing the recipient by name still resolves.
    #: Only the introduced direction is aliased -- see ``_remember_aliases``.
    destination_aliases: set[str] = field(default_factory=set)


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
        #: Category of the call whose response the last extracted arguments echoed,
        #: or None. Measurement only -- no rule reads it. See ambiguity A3.
        self.last_chain_source: ToolCategory | None = None

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

        # First sighting wins. A destination the environment already attested is
        # not reclassified merely because the session then referenced it -- an
        # assistant quoting a colleague's address back does not make that address
        # its own invention.
        tokens = destination_tokens(call.arguments, self.scorer)
        for token in tokens:
            if token not in self.state.attested_destinations:
                self._remember_destination(self.state.introduced_destinations, token)
        if tokens:
            self._remember_aliases(call.arguments, tokens)

    def destination_provenance(self, call: ObservedCall) -> Provenance:
        """Classify where ``call``'s destination came from.

        A pure read of session state, so it is safe to run pre-flight alongside
        :meth:`extract` -- and it *must* run before :meth:`commit`, or the call
        would introduce its own destination and never be anything but INTRODUCED.

        INTRODUCED is tested with ``any`` and ATTESTED with ``all``: one novel
        recipient among trusted ones makes the whole call untrusted, which is the
        fail-closed direction.
        """
        tokens = destination_tokens(call.arguments, self.scorer)
        if not tokens:
            # No address, but the call may still name a recipient the session
            # registered earlier. Measured on api_key_calendar_agendas_2: the fraud
            # registers {name, email} at call 9 and sends to the *name* at call 36,
            # so the address never appears in the exfiltrating call's arguments.
            if self._matches_alias(call.arguments):
                return Provenance.INTRODUCED
            return Provenance.UNKNOWN
        if any(token in self.state.introduced_destinations for token in tokens):
            return Provenance.INTRODUCED
        if all(token in self.state.attested_destinations for token in tokens):
            return Provenance.ATTESTED
        return Provenance.UNATTESTED

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
        category = self.classifier.classify(call.tool, call.tool_description)
        self._remember_output_tokens(response_text, category)
        self._attest_destinations(patched, call, response_text)
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
        self._remember_output_tokens(
            response_text, self.classifier.classify(call.tool, call.tool_description)
        )
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
        chain_source = self._carries_prior_output(argument_text)
        self.last_chain_source = chain_source
        if chain_source is not None:
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

        directive_hits = sum(1 for pattern in DIRECTIVE_PATTERNS if pattern.search(text))
        if (
            any(pattern.search(text) for pattern in IMPERATIVE_PATTERNS)
            or directive_hits >= DIRECTIVE_SIGNAL_MINIMUM
        ):
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

    def _remember_aliases(self, arguments: Any, tokens: set[str]) -> None:
        """Record names that appeared beside a destination this call introduced.

        Aliasing is deliberately **one-directional**. Only arguments alias, never
        responses: trusting a name because a response happened to mention it beside
        an address would let a poisoned -- or merely coincidental -- pairing
        downgrade a later send, which is the hole the injection gate exists to
        close. An unresolvable name therefore stays UNKNOWN, which never downgrades.

        The candidate filter is deliberately narrow: a short human-readable string
        that is not itself a destination. Anything longer is prose, and prose in an
        argument is a message body rather than a recipient.
        """
        for value in self.scorer._iter_strings(arguments):
            candidate = value.strip().lower()
            if not (_ALIAS_MIN_LEN <= len(candidate) <= _ALIAS_MAX_LEN):
                continue
            if candidate in tokens or not _ALIAS_RE.fullmatch(candidate):
                continue
            self._remember_destination(self.state.destination_aliases, candidate)

    def _matches_alias(self, arguments: Any) -> bool:
        """True if any argument value names a destination the session introduced."""
        if not self.state.destination_aliases:
            return False
        return any(
            value.strip().lower() in self.state.destination_aliases
            for value in self.scorer._iter_strings(arguments)
        )

    def _remember_destination(self, sink: set[str], token: str) -> None:
        """Record a destination, bounded so a long session cannot grow forever."""
        if len(sink) < MAX_DESTINATIONS:
            sink.add(token)

    def _attest_destinations(
        self, vector: np.ndarray, call: ObservedCall, response_text: str
    ) -> None:
        """Record destinations this response named, if it is entitled to name any.

        Three gates, each closing a distinct hole:

        * **READ only.** A WRITE echoing back the recipient you just handed it
          attests nothing. That is scenario S1's ``add_payee``, whose response
          repeats the attacker's IBAN -- treat that as attestation and R3 stops
          firing on the paper's own scenario.
        * **No injection markers.** Otherwise an address planted in a poisoned
          issue body launders itself into ATTESTED, which is precisely the tool
          poisoning threat model of section II-A.
        * **Not already introduced.** Otherwise a READ whose own arguments carried
          the destination attests it from its own echo, and
          ``search_contacts_by_email(email=X)`` returning X would trust X one call
          before the send.
        """
        if self.classifier.classify(call.tool, call.tool_description) is not ToolCategory.READ:
            return
        if vector[OC_IMPERATIVE] or vector[OC_XML_TAGS]:
            return
        for token in destination_tokens(response_text, self.scorer):
            if token not in self.state.introduced_destinations:
                self._remember_destination(self.state.attested_destinations, token)

    def _carries_prior_output(self, argument_text: str) -> ToolCategory | None:
        """The category of the call whose response this argument echoes, if any.

        Returns a category rather than a bool purely to record *where* the chained
        data came from. The matching itself is unchanged -- ``DF_CHAINED`` is still
        set for exactly the same arguments.
        """
        if not argument_text:
            return None
        for token, category in self.state.output_tokens:
            if len(token) <= CHAIN_WINDOW:
                if token in argument_text:
                    return category
                continue
            limit = min(len(token) - CHAIN_WINDOW, MAX_WINDOWS_PER_TOKEN * CHAIN_WINDOW_STRIDE)
            for start in range(0, limit + 1, CHAIN_WINDOW_STRIDE):
                if token[start : start + CHAIN_WINDOW] in argument_text:
                    return category
        # Identifiers need boundary matching: "29" must not match "1293".
        for token, category in self.state.identifier_tokens:
            if re.search(rf"(?<![A-Za-z0-9]){re.escape(token)}(?![A-Za-z0-9])", argument_text):
                return category
        # Destinations echo the identifier rule, not the output-token rule: match
        # the whole entity or nothing. A URL reduces to its host, so "x.com" is
        # five characters -- inside "box.combo" that is a coincidence, standing
        # alone it is the datum leaving.
        #
        # Both sides are normalised the same way, because ``destination_tokens``
        # normalises what it remembers: contacts are lowercased and account
        # numbers separator-stripped. Comparing that against raw argument text
        # only matches when the agent happens to copy in the extractor's own
        # spelling -- so a mailbox read as "Alice@Gmail.com" and sent to
        # "ALICE@GMAIL.COM" missed, and an account read compact and written out
        # in groups of four missed as well.
        folded = argument_text.casefold()
        for token, category in self.state.destination_echoes:
            if _destination_pattern(token.casefold()).search(folded):
                return category
        return None

    def _remember_output_tokens(self, response_text: str, category: ToolCategory) -> None:
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
            self._remember_identifiers(payload, category=category)

        for candidate in candidates:
            if len(candidate) >= MIN_CHAIN_TOKEN_LEN:
                self.state.output_tokens.append((candidate, category))

        # Entities the response *names* are chainable wherever they sit inside it.
        # Remembering only whole leaves misses the exfiltration shape entirely: a
        # short identifier lifted out of a long document. The leaf exceeds
        # CHAIN_WINDOW, so matching falls to the sliding window, and every window
        # carries a neighbouring source character the destination argument does
        # not have -- so a 23-character IBAN inside a bill could never match.
        #
        # destination_tokens already extracts exactly these entities -- contacts,
        # IBANs, cards, URL hosts -- and is what puts them in
        # attested_destinations, so it is reused rather than reimplemented.
        for token in destination_tokens(response_text, self.scorer):
            self.state.destination_echoes.append((token, category))

    def _remember_identifiers(
        self, payload: Any, key: str | None = None, *, category: ToolCategory = ToolCategory.READ
    ) -> None:
        """Record identifier values, which are chainable regardless of length."""
        if isinstance(payload, dict):
            for child_key, child in payload.items():
                self._remember_identifiers(child, child_key, category=category)
        elif isinstance(payload, (list, tuple)):
            for child in payload:
                self._remember_identifiers(child, key, category=category)
        elif key and _ID_KEY_RE.search(key) and isinstance(payload, (str, int)):
            text = str(payload)
            if MIN_IDENTIFIER_LEN <= len(text) <= 64:
                self.state.identifier_tokens.append((text, category))

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
