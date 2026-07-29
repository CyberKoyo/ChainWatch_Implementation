"""Common interface for turning an AgentLAB environment into an MCP tool surface.

AgentLAB ships two quite different environment families, and the replay harness
should not care which it is driving:

* **Agent_SafetyBench** -- a ``BaseEnv`` subclass with one method per tool and a
  paired ``.json`` file already in OpenAI tool-schema form. Uniform across all
  351 environments.
* **SHADE_Arena** -- pydantic environments whose tools are free functions taking
  injected dependencies via ``Annotated[..., Depends("inbox")]``. Covers 167 of
  the 200 verified attack chains, so it carries most of the benchmark.

Both are reduced to the same two operations: list the tools, call one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

#: Root of the vendored AgentLAB checkout.
AGENTLAB_ROOT = Path(__file__).resolve().parent.parent / "AgentLAB"


@runtime_checkable
class EnvAdapter(Protocol):
    """What ``env_mcp_server`` needs from an environment, and nothing more."""

    name: str

    def list_tools(self) -> list[dict[str, Any]]:
        """Tool definitions in MCP form: ``name``, ``description``, ``inputSchema``."""

    def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
        """Invoke a tool and return its raw result."""


#: Python annotation -> JSON Schema type. Anything unrecognised becomes a string,
#: which is the safe default: the value still round-trips, it is simply untyped.
JSON_TYPES: dict[Any, str] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
}


def json_type_of(annotation: Any) -> str:
    """Best-effort JSON Schema type for a Python annotation."""
    if annotation in JSON_TYPES:
        return JSON_TYPES[annotation]

    origin = getattr(annotation, "__origin__", None)
    if origin in JSON_TYPES:
        return JSON_TYPES[origin]

    # Optional[X] / X | None -- describe it by its non-None member.
    args = [a for a in getattr(annotation, "__args__", ()) if a is not type(None)]
    if len(args) == 1:
        return json_type_of(args[0])

    text = str(annotation).lower()
    for python_type, json_name in (
        (list, "array"), (dict, "object"), (bool, "boolean"),
        (int, "integer"), (float, "number"),
    ):
        if python_type.__name__ in text:
            return json_name
    return "string"


class AdapterError(RuntimeError):
    """Raised when an environment cannot be loaded or a tool cannot be invoked."""
