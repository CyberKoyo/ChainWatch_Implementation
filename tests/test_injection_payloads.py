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

from chainwatch.engine.features import IMPERATIVE_PATTERNS, XML_TAG_RE

AGENTDOJO_SUITES = ("banking", "slack", "travel", "workspace")


def injection_markers_fire(text: str) -> bool:
    """True if dim 13 or dim 14 would be set for this response text."""
    return bool(XML_TAG_RE.search(text)) or any(p.search(text) for p in IMPERATIVE_PATTERNS)


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


def test_enhanced_variant_is_the_regression_floor():
    """InjecAgent 'enhanced' already detects at 100% and must never regress.

    'enhanced' prepends "IMPORTANT!!! Ignore all previous instructions..." to
    'base'. It is the one family the original markers did catch, so it guards
    against a rewrite that trades old detection for new.
    """
    payloads = injecagent_payloads("enhanced")
    assert len(payloads) == 186
    assert all(injection_markers_fire(p) for p in payloads)
