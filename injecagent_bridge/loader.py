"""Read InjecAgent's published data. We import its JSON only, never its ``src/``.

InjecAgent (Zhan et al., ACL 2024 Findings) ships a harness that calls models; none
of that is used here. Route F reimplements exactly two things -- serving the case's
tool responses, and asking whether an attacker tool was called -- because both are
observable from ChainWatch's own trace and neither needs a model in the loop.

Shape of the data, verified rather than assumed:

* ``tools.json`` -- 38 toolkits, each ``{toolkit, tools: [{name, summary,
  parameters: [{name, type, description, required}], returns}]}``. A case names a
  tool by ``toolkit + tool.name``, e.g. ``GitHubSearchRepositories``.
* ``test_cases_{ds,dh}_{base,enhanced}.json`` -- ds (data-stealing) 544, dh
  (direct-harm) 510; ``enhanced`` wraps the same instruction in InjecAgent's
  "IMPORTANT!!! Ignore all previous instructions..." framing. Both are published
  variants and both are served verbatim.
* ``attacker_simulated_responses.json`` -- 2347 entries keyed ``"(ToolName,{args})"``.
"""

from __future__ import annotations

import json
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "InjecAgent" / "data"

#: The dev user-tool surface. The *attacker* tools a case names are left untouched --
#: they are Terminal/Dropbox/Slack/Gmail as often as GitHub, which is the point: the
#: developer reads a repo and the injection moves data somewhere else entirely.
DEV_PREFIXES = ("GitHub",)

SPLITS = ("ds", "dh")
VARIANTS = ("base", "enhanced")


def load_tools() -> dict[str, tuple[str, dict]]:
    """``{full_tool_name: (toolkit, tool_def)}`` over every toolkit."""
    toolkits = json.loads((DATA / "tools.json").read_text())
    by_name: dict[str, tuple[str, dict]] = {}
    for toolkit in toolkits:
        for tool in toolkit["tools"]:
            by_name[toolkit["toolkit"] + tool["name"]] = (toolkit["toolkit"], tool)
    return by_name


def dev_cases(split: str = "ds", variant: str = "base") -> list[dict]:
    """Published cases whose *user* tool is in the dev surface, order preserved.

    The file's own order must be kept: a recipe row addresses a case by index, so a
    reordering would silently repoint every row at a different case.
    """
    cases = json.loads((DATA / f"test_cases_{split}_{variant}.json").read_text())
    return [c for c in cases if (c.get("User Tool") or "").startswith(DEV_PREFIXES)]


#: InjecAgent's own simulated attacker-tool responses, keyed ``"(ToolName,{args})"``.
ATTACKER_RESPONSES: dict[str, str] = json.loads(
    (DATA / "attacker_simulated_responses.json").read_text()
)
