"""Published benchmark outcomes, joined to captured sessions.

Both benchmarks ship their own success check -- AgentDojo `utility()`/`security()`,
InjecAgent "an attacker tool was called" -- and until now nothing in `ml/` read
either. An attack the model declined therefore entered the positive class as a
successful attack, which is the corpus telling the model that a refusal looks like
an exfiltration.

Two analyses, always reported together and never merged:

* **native-valid** -- the primary. Attacks that the benchmark's own check says
  succeeded, benign sessions the benchmark says completed their task.
* **all-attempts** -- the sensitivity. Every validated session under its asserted
  label.

A failed attack is *excluded from the primary*, never moved to the benign class.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from chainwatch.capture.manifest import read_entries


def native_outcomes(manifest_paths: Iterable[Path]) -> dict[str, dict]:
    """Every manifest entry's published outcome, keyed by session id.

    Route and label come off the coordinate rather than the source string, for the
    reason ``manifest._route`` gives: the keys are evidence, the source is an
    assertion the capture wrapper makes.
    """
    outcomes: dict[str, dict] = {}
    for path in manifest_paths:
        for entry in read_entries(Path(path)):
            outcomes[entry.session] = {
                "route": entry.coordinate[0],
                "label": entry.coordinate[1],
                # The whole coordinate, not only the two keys this module reads:
                # a caller asking "which suite was this?" has no other honest
                # source. ``server`` names an app since the per-app topology
                # landed, and the trace carries no suite field at all.
                "coordinate": tuple(entry.coordinate),
                **entry.native,
            }
    return outcomes


def is_native_valid(session_id: str, label: str, outcomes: Mapping[str, dict]) -> bool:
    """Did the benchmark's own check say this session did what its label claims?

    Fails closed on an unknown session. A legacy population carries no published
    check, and counting it as valid would put unverified sessions into the very
    analysis that exists to be verified.
    """
    outcome = outcomes.get(session_id)
    if outcome is None:
        return False
    route = outcome.get("route")
    if route == "agentdojo":
        if label == "benign":
            return outcome.get("utility") is True
        return outcome.get("security") is True
    if route == "injecagent":
        if label == "benign":
            # InjecAgent publishes no benign utility check; a validated session
            # that reached the manifest is the whole of what it asserts.
            return True
        return outcome.get("attacker_called") is True
    return False


def partition_sessions(
    sessions: Sequence[str],
    labels: Mapping[str, str],
    outcomes: Mapping[str, dict],
) -> tuple[list[str], list[str]]:
    """Split into (native-valid primary, all-attempts sensitivity).

    Both lists preserve the caller's order so a report can print them side by
    side. A session with no manifest entry appears in neither -- it is not an
    attempt at a published coordinate.
    """
    valid: list[str] = []
    attempts: list[str] = []
    for session in sessions:
        if session not in outcomes:
            continue
        attempts.append(session)
        if is_native_valid(session, labels[session], outcomes):
            valid.append(session)
    return valid, attempts
