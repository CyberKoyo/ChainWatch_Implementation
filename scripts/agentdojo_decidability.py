#!/usr/bin/env python3
"""Prove the AgentDojo bridge + scoring are wired, without spending quota.

For each suite and injection task: a clean run must NOT flag security; running the
injection task's own ``ground_truth()`` trajectory against the injected env MUST flag
it. If this fails, no live capture is worth launching -- the pipeline cannot tell an
attack from a benign run, and every attack session would be recorded as resisted.

Two tasks are known unscorable under the fill-all-vectors placement capture uses, and
they are *reported* here rather than excused: the gate re-derives the set and fails if
it has drifted, because the exclusion list is a measurement. See
``agentdojo_bridge.adapter.UNSCORABLE_INJECTION_TASKS``. Recipes drop them, so no
attack row is ever offered for one.

This is CLAUDE.md §12 item 5's decidability check, done before any quota is spent --
notes 23-25 measured three times over what skipping it costs.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentdojo_bridge.adapter import (  # noqa: E402
    SUITES,
    UNSCORABLE_INJECTION_TASKS,
    AgentDojoAdapter,
)
from agentdojo_bridge.payload import build_injections  # noqa: E402


def main() -> int:
    failures: list[str] = []
    observed_unscorable: set[tuple[str, str]] = set()
    checked = 0

    for suite_name in sorted(SUITES):
        suite = SUITES[suite_name]
        if not AgentDojoAdapter(suite_name).list_tools():
            failures.append(f"{suite_name}: empty tool surface")

        for injection_id, injection_task in sorted(suite.injection_tasks.items()):
            checked += 1

            clean = AgentDojoAdapter(suite_name)
            if clean.score(None, injection_id)["security"] is not False:
                failures.append(
                    f"{suite_name}/{injection_id}: clean run already flags security"
                )

            hit = AgentDojoAdapter(suite_name, build_injections(suite_name, injection_id))
            for call in injection_task.ground_truth(hit.pre_env):
                hit.call_tool(call.function, dict(call.args))
            if hit.score(None, injection_id)["security"] is not True:
                observed_unscorable.add((suite_name, injection_id))

    for suite_name, injection_id in sorted(observed_unscorable):
        print(f"UNSCORABLE {suite_name}/{injection_id} (excluded from the recipe grid)")

    drifted = observed_unscorable ^ set(UNSCORABLE_INJECTION_TASKS)
    for suite_name, injection_id in sorted(drifted):
        failures.append(
            f"{suite_name}/{injection_id}: scorability disagrees with "
            "UNSCORABLE_INJECTION_TASKS -- re-measure before capturing"
        )

    for failure in failures:
        print("FAIL", failure)
    scorable = checked - len(observed_unscorable)
    print(
        f"{'PASS' if not failures else 'FAILED'}: {checked} injection tasks checked, "
        f"{scorable} scorable, {len(observed_unscorable)} excluded"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
