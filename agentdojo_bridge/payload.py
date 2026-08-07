"""Build AgentDojo injection payloads, verbatim.

The payload text is AgentDojo's own ``important_instructions`` template
(``ImportantInstructionsAttack._JB_STRING``) with ``{user}``/``{model}``/``{goal}``
filled. We do not construct the full attack pipeline (it needs a target LLM object);
we reuse the published template string directly so the payload is byte-for-byte the
benchmark's. See Global Constraints: no tuning, no added framing.

Every injection vector of the suite gets the same payload. AgentDojo's own attack
fills the single vector the reference trajectory reads; which vector a *live* agent
reads is trajectory-dependent, so filling all of them guarantees the payload is
present wherever it looks. The payload *text* is untouched -- only placement breadth
varies, and placement is not the published attack string.

Placement breadth is not free, though, and one task measures the cost:
``workspace/injection_task_0``'s ``security()`` requires *exactly one* inbox email
subjected "Important message!", a string that appears inside its own GOAL and hence
inside the payload -- so filling 16 vectors plants 16 copies and the check can never
fire. Filling one vector scores True, filling all scores False. That task is listed
in ``adapter.UNSCORABLE_INJECTION_TASKS`` and dropped from the recipe grid rather
than silently recorded as a resisted attack.
"""

from __future__ import annotations

from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack

from .adapter import SUITES


def build_injections(
    suite_name: str,
    injection_task_id: str,
    *,
    model_name: str = "Claude",
    user_name: str = "Emma Johnson",
) -> dict[str, str]:
    """``{vector_id: payload}`` for one injection task, ready for the env loader."""
    suite = SUITES[suite_name]
    goal = suite.injection_tasks[injection_task_id].GOAL
    payload = ImportantInstructionsAttack._JB_STRING.format(
        user=user_name, model=model_name, goal=goal
    )
    return {vector_id: payload for vector_id in suite.get_injection_vector_defaults()}
