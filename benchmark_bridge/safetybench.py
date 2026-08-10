"""Agent_SafetyBench adapter.

Every environment in this family follows the same shape, verified across all 351
files: a ``class <Name>(BaseEnv)`` with ``__init__(*, parameters=None)``, one
keyword-only method per tool returning a dict, and a sibling ``<Name>.json``
holding the tool schemas in OpenAI form.

``BaseEnv`` already provides ``call_tool``, including required-parameter checking
and dropping of unexpected keys, so this adapter is mostly a schema translation.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from .base import AGENTLAB_ROOT, AdapterError

#: Both copies of the environment set ship in the checkout; the top-level one is
#: the complete list, so prefer it and fall back to the vendored Agent_SafetyBench.
ENV_DIRS = (
    AGENTLAB_ROOT / "environments",
    AGENTLAB_ROOT / "Agent_SafetyBench" / "environments",
)


def environment_dir() -> Path:
    for candidate in ENV_DIRS:
        if candidate.is_dir():
            return candidate
    raise AdapterError(f"no Agent_SafetyBench environments found under {AGENTLAB_ROOT}")


def available_environments() -> list[str]:
    """Names of every environment that has both a module and a schema."""
    directory = environment_dir()
    return sorted(
        path.stem
        for path in directory.glob("*.py")
        if path.stem not in {"BaseEnv", "EnvManager", "functions_runtime"}
        and (directory / f"{path.stem}.json").exists()
    )


class SafetyBenchAdapter:
    """Exposes one Agent_SafetyBench environment as an MCP tool surface."""

    def __init__(self, name: str, parameters: dict[str, Any] | None = None) -> None:
        self.name = name
        directory = environment_dir()
        schema_path = directory / f"{name}.json"
        module_path = directory / f"{name}.py"
        if not schema_path.exists() or not module_path.exists():
            raise AdapterError(f"unknown Agent_SafetyBench environment {name!r}")

        self._schema: list[dict[str, Any]] = json.loads(schema_path.read_text(encoding="utf-8"))

        # BaseEnv reads '<Class>.json' relative to its own module directory, so the
        # environment package must be importable by its real path, not copied.
        if str(directory) not in sys.path:
            sys.path.insert(0, str(directory))

        module = self._load_module(name, module_path)
        env_class = getattr(module, name, None)
        if env_class is None:
            raise AdapterError(f"{module_path} defines no class named {name!r}")
        self.env = env_class(parameters=parameters or {})

    @staticmethod
    def _load_module(name: str, path: Path) -> Any:
        spec = importlib.util.spec_from_file_location(f"agentlab_env_{name}", path)
        if spec is None or spec.loader is None:
            raise AdapterError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    # ------------------------------------------------------------------ EnvAdapter

    def list_tools(self) -> list[dict[str, Any]]:
        """Translate OpenAI-form schemas into MCP ``inputSchema`` form."""
        return [
            {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "inputSchema": tool.get(
                    "parameters", {"type": "object", "properties": {}, "required": []}
                ),
            }
            for tool in self._schema
            if tool.get("name")
        ]

    def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
        return self.env.call_tool(tool, dict(arguments or {}))
