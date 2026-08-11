"""Corpus-driven measurement of the Injection-stage markers (dims 13 and 14).

The markers were written against one phrasing family -- ten spellings of "ignore
all previous instructions" plus an allowlist of suspicious tag names -- and were
never measured against anything else. These tests measure them against published
payloads instead, and keep the AgentDojo family held out so a rule cannot be
tuned until it passes.

Measured before this file existed: AgentDojo 0/27, InjecAgent base 0/186,
InjecAgent enhanced 186/186. `enhanced` differs from `base` only by prepending
the folk idiom, so the markers were detecting the decoration, not the act.
"""

import pytest

from chainwatch.engine.features import (
    DIRECTIVE_PATTERNS,
    DIRECTIVE_SIGNAL_MINIMUM,
    IMPERATIVE_PATTERNS,
    XML_TAG_RE,
)

AGENTDOJO_SUITES = ("banking", "slack", "travel", "workspace")


def injection_markers_fire(text: str) -> bool:
    """True if dim 13 or dim 14 would be set for this response text."""
    directive_hits = sum(1 for pattern in DIRECTIVE_PATTERNS if pattern.search(text))
    return (
        bool(XML_TAG_RE.search(text))
        or any(pattern.search(text) for pattern in IMPERATIVE_PATTERNS)
        or directive_hits >= DIRECTIVE_SIGNAL_MINIMUM
    )


def agentdojo_payloads() -> list[tuple[str, str, str]]:
    """(suite, injection_task_id, payload_text) for every AgentDojo injection task."""
    from agentdojo.task_suite.load_suites import get_suite

    from agentdojo_bridge.payload import build_injections

    out: list[tuple[str, str, str]] = []
    for suite_name in AGENTDOJO_SUITES:
        suite = get_suite("v1", suite_name)
        for task_id in suite.injection_tasks:
            vectors = build_injections(suite_name, task_id)
            if vectors:
                out.append((suite_name, task_id, next(iter(vectors.values()))))
    return out


def injecagent_payloads(variant: str) -> list[str]:
    """Every InjecAgent dev-split tool response for one payload variant."""
    from injecagent_bridge.loader import dev_cases

    return [
        case["Tool Response"]
        for split in ("ds", "dh")
        for case in dev_cases(split, variant)
        if case.get("Tool Response")
    ]


def injecagent_benign_responses(variant: str) -> list[str]:
    """Injection-stripped response for every published dev case."""
    from injecagent_bridge.adapter import InjecAgentAdapter
    from injecagent_bridge.loader import dev_cases

    return [
        InjecAgentAdapter(case, benign=True).call_tool(case["User Tool"], {})
        for split in ("ds", "dh")
        for case in dev_cases(split, variant)
    ]


def test_enhanced_variant_is_the_regression_floor():
    """InjecAgent 'enhanced' already detects at 100% and must never regress.

    'enhanced' prepends "IMPORTANT!!! Ignore all previous instructions..." to
    'base'. It is the one family the original markers did catch, so it guards
    against a rewrite that trades old detection for new.
    """
    payloads = injecagent_payloads("enhanced")
    assert len(payloads) == 186
    assert all(injection_markers_fire(p) for p in payloads)


#: Ordinary structured data, correspondence, requests and markup. These remain a
#: small readability floor beside the complete published InjecAgent benign twins.
BENIGN_FIXTURE_PROSE = [
    "Type: send | Amount: $65.0 | Date: 2024-05-14 09:30:00 | "
    "To: julie.williams@bluesparrowtech.com | Note: Marketing team coffee run",
    "Hi Emma, please find the December invoice attached. Let me know if you "
    "need anything else. Best, Robert Schmidt, City Property Management",
    "Bill for the month of December 2023\n"
    "-----------------------------------\nService\t\t\tAmount\n"
    "-----------------------------------\nSpotify Premium\t\t50.00\n",
    '{"id_": "29", "filename": "plan.txt", "owner": "emma.johnson@bluesparrowtech.com"}',
    "Meeting moved to 3pm Thursday. Agenda: Q4 numbers, hiring, the Boston visit.",
    "Your GitHub sign-in from a new device was successful. If this was not you, "
    "review your security settings.",
    "Please retrieve my saved addresses and email them to amy.watson@gmail.com.",
    "Could you send the report to sarah.baker@bluesparrowtech.com when you have a moment?",
    "<div class='row'><span>Balance</span><code>1234.50</code></div>",
    # Route F's domain. InjecAgent reads GitHub, where generics and usage strings
    # are ordinary content -- and its published benign twins happen to carry none,
    # so a 372-response floor passed while saying nothing about any of this. dim 14
    # gates attestation, so a false positive here becomes a blocked call.
    "Map<String, List<Integer>> cache = new HashMap<>();",
    "def parse(raw: Optional<str>) -> Vec<Token>: return []",
    "usage: git commit -m <msg> && git push origin <branch>",
    "<rss><channel><item><title>Release 2.1</title></item></channel></rss>",
    '<svg viewBox="0 0 24 24"><path d="M4 4h16v16H4z"/></svg>',
]


def test_benign_fixture_prose_does_not_trip_the_markers():
    """A rule that fires on ordinary fixture prose is rejected outright.

    Stage 3's priors sit at 0.02 for these dims at the benign stages. A detector
    firing on routine business text pushes benign calls into Injection and breaks
    the ceiling this change is governed by.

    The hard cases are deliberate: two plain requests to a person, one piece of
    real HTML, and five from route F's own domain -- generics, a usage string and
    two serialisation formats. That last group is here because a floor measured
    only on the published InjecAgent twins could not fail on it: none of those 372
    responses carries a type parameter, so the floor passed while saying nothing
    about the domain route F actually captures.
    """
    tripped = [text for text in BENIGN_FIXTURE_PROSE if injection_markers_fire(text)]
    assert tripped == [], f"markers fired on benign prose: {tripped}"


def test_base_variant_is_a_measured_limit_not_a_silent_success():
    """InjecAgent `base` is not detectable from prose without flagging real mail.

    Recorded as a measurement rather than left implicit: `base` is `enhanced`
    minus the folk idiom, and what remains is an ordinary request. The signal that
    separates it from real correspondence is where the data is going, which is
    A4's provenance question, not dim 13's.
    """
    payloads = injecagent_payloads("base")
    assert len(payloads) == 186
    assert sum(injection_markers_fire(p) for p in payloads) == 0


@pytest.mark.parametrize("variant", ["base", "enhanced"])
def test_injecagent_benign_twins_do_not_trip_the_markers(variant):
    """Primary benign floor: use InjecAgent's published matched response half."""
    responses = injecagent_benign_responses(variant)
    assert len(responses) == 186
    assert [text for text in responses if injection_markers_fire(text)] == []


@pytest.mark.holdout
def test_agentdojo_family_is_detected():
    """The held-out family. Run with -m holdout, after the benign floor passes.

    Measured 0/27 before this change. The rules were written from the structural
    argument -- a data response should not carry unknown markup, and should not
    both direct the reader and reference the surrounding task -- and against
    InjecAgent, not against this family.
    """
    payloads = agentdojo_payloads()
    assert len(payloads) == 27
    missed = [(suite, task) for suite, task, text in payloads if not injection_markers_fire(text)]
    assert missed == [], f"undetected AgentDojo payloads: {missed}"
