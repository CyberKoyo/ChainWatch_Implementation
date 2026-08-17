"""Which MCP server each AgentDojo tool would live on in a real deployment.

``server`` is asserted, never derived (CLAUDE.md, "The capture executor"), so asserting one label
per session is a claim that a suite is one server -- false for ``workspace``, which is
email + calendar + cloud drive, and which AgentDojo itself keeps in three modules.
This module asserts the topology those modules already describe.

Derived, not hand-listed: a hand-written table rots the moment the vendored package
moves a tool, and a stale table is a false topology -- the defect this exists to remove.
"""

from __future__ import annotations

#: AgentDojo tool-module basename -> the MCP server that module would be.
#: A deployment-topology declaration, not a benchmark fact. Identical for a benign
#: row and its attack twin, so it cannot carry the label -- the property whose absence
#: made ``win_occupancy`` a leak (CLAUDE.md, Phase 8).
MODULE_SERVERS: dict[str, str] = {
    "email_client": "email",
    "calendar_client": "calendar",
    "cloud_drive_client": "cloud-drive",
    "banking_client": "banking",
    "file_reader": "files",
    "slack": "slack",
    "travel_booking_client": "travel-booking",
    "user_account": "user-account",
    "web": "web",
}


def server_map(suite: str) -> dict[str, str]:
    """Tool name -> ``<suite>-<app>`` label for every tool the suite publishes."""
    from .adapter import AgentDojoAdapter

    adapter = AgentDojoAdapter(suite, {})
    mapping: dict[str, str] = {}
    for name, function in adapter.tool_functions().items():
        module = getattr(function, "__module__", "").rsplit(".", 1)[-1]
        app = MODULE_SERVERS.get(module)
        if app is None:
            # Never fall back to the suite label: a silent fallback reintroduces the
            # false one-server topology this module exists to remove, and it would do
            # so invisibly on exactly the tool the vendored package just moved.
            raise KeyError(f"{suite}: tool {name!r} lives in unmapped module {module!r}")
        mapping[name] = f"{suite}-{app}"
    return mapping
