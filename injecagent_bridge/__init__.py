"""Route F — InjecAgent served as a ChainWatch-observable MCP tool surface.

The developer domain, where route E is the office one: the user tool is GitHub, and
the attacker tools the published cases name are Terminal, Dropbox, Slack and Gmail.
Benign and attack sessions run the same published ``User Instruction``; the
difference is whether the tool response the agent reads carries the injection.

Data only -- ``InjecAgent/data/*.json`` is read, ``InjecAgent/src/`` is never
imported.
"""

from .adapter import InjecAgentAdapter
from .loader import (
    ATTACKER_RESPONSES,
    DEV_PREFIXES,
    SPLITS,
    VARIANTS,
    dev_cases,
    load_tools,
)

__all__ = [
    "InjecAgentAdapter",
    "load_tools",
    "dev_cases",
    "ATTACKER_RESPONSES",
    "DEV_PREFIXES",
    "SPLITS",
    "VARIANTS",
]
