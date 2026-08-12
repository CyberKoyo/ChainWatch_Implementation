"""Which sessions the audit picks, and the one it must not pick.

A missed attack is a session the benchmark says succeeded and the firewall did not
flag. A *refused* attack is neither -- excluding it is the whole point of the
native-valid partition, and including it here would restate 279 refusals as misses.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import miss_audit  # noqa: E402


OUTCOMES = {
    "hit": {"route": "agentdojo", "label": "attack", "security": True,
            "coordinate_suite": "slack"},
    "miss": {"route": "agentdojo", "label": "attack", "security": True,
             "coordinate_suite": "slack"},
    "refused": {"route": "agentdojo", "label": "attack", "security": False,
                "coordinate_suite": "slack"},
    "other": {"route": "agentdojo", "label": "attack", "security": True,
              "coordinate_suite": "banking"},
}


def _session(session_id, rules, severity="NONE", prov="UNKNOWN"):
    return [{"session": session_id, "label": "attack", "call": 1, "v": [0.0] * 20,
             "rules": rules, "severity": severity, "prov": prov,
             "tool": "post_webpage", "server": "slack-web", "stage": 4}]


def test_a_flagged_session_is_not_a_miss():
    sessions = [_session("hit", ["R3"], severity="CRITICAL", prov="UNATTESTED")]
    assert miss_audit.missed_sessions(sessions, OUTCOMES) == []


def test_an_unflagged_successful_attack_is_a_miss():
    sessions = [_session("miss", ["R4"], severity="WARNING")]
    picked = miss_audit.missed_sessions(sessions, OUTCOMES)
    assert [calls[0]["session"] for calls in picked] == ["miss"]


def test_a_refused_attack_is_not_a_miss():
    """It never succeeded, so there was nothing to catch. 279 of these exist."""
    sessions = [_session("refused", [])]
    assert miss_audit.missed_sessions(sessions, OUTCOMES) == []


def test_an_attested_r3_counts_as_unflagged_under_the_operational_default():
    """r3_attested_action='downgrade' keeps the alert and removes the block.

    A session whose only CRITICAL is an attested R3 does not block in deployment, so
    the audit must count it as missed -- otherwise the report describes the
    paper-literal configuration nobody runs.
    """
    sessions = [_session("miss", ["R3"], severity="CRITICAL", prov="ATTESTED")]
    picked = miss_audit.missed_sessions(sessions, OUTCOMES)
    assert [calls[0]["session"] for calls in picked] == ["miss"]


def test_the_suite_filter_selects_on_the_published_coordinate():
    sessions = [_session("miss", []), _session("other", [])]
    picked = miss_audit.missed_sessions(sessions, OUTCOMES, suite="slack")
    assert [calls[0]["session"] for calls in picked] == ["miss"]


def test_the_call_line_names_the_fields_a_diagnosis_turns_on():
    line = miss_audit.format_call(
        {"call": 5, "tool": "post_webpage", "server": "slack-web", "stage": 6,
         "rules": ["R4"], "severity": "WARNING", "prov": "UNATTESTED",
         "v": [0.0] * 20})
    for expected in ("post_webpage", "slack-web", "R4", "UNATTESTED"):
        assert expected in line
