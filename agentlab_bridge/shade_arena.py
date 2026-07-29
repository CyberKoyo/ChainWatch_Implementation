"""SHADE_Arena adapter.

Carries 167 of the 200 verified attack chains (workspace 48, spam_filter 47,
travel 36, banking 36), so this is the adapter that matters most for evaluation.

Harder than Agent_SafetyBench in three ways, all handled here:

* environments are pydantic models built by a ``create()`` classmethod that loads
  fixture data from ``universe_related_stuff/``;
* tools are free functions, not methods, listed on ``env.available_tools``;
* those functions receive environment components through
  ``Annotated[Inbox, Depends("inbox")]`` parameters, which an MCP caller neither
  knows nor should supply. They are stripped from the published schema and
  injected at call time.

The package uses absolute imports (``from tools.x import y`` *and*
``from SHADE_Arena.utils...``), so both the checkout root and the SHADE_Arena
directory have to be importable, and ``create()`` resolves fixture paths relative
to the working directory. :func:`_shade_context` handles both.
"""

from __future__ import annotations

import contextlib
import importlib
import inspect
import os
import sys
import typing
from pathlib import Path
from typing import Any, Iterator

from .base import AGENTLAB_ROOT, AdapterError, json_type_of

SHADE_ROOT = AGENTLAB_ROOT / "SHADE_Arena"

#: Environment module -> class. Kept explicit rather than globbed: these are the
#: environments the 200 verified chains actually exercise.
ENVIRONMENTS: dict[str, tuple[str, str]] = {
    "banking": ("environments.banking_environment", "BankingEnvironment"),
    "workspace": ("environments.workspace_environment", "WorkspaceEnvironment"),
    "travel": ("environments.travel_environment", "TravelEnvironment"),
    "spam_filter": ("environments.spam_filter_update_environment", "SpamFilterUpdateEnvironment"),
}

#: The chain metadata in filtered_top_200_attacks.json labels environments with
#: its own vocabulary; map those labels onto the modules above.
ENVIRONMENT_ALIASES: dict[str, str] = {
    "banking": "banking",
    "workspace": "workspace",
    "travel": "travel",
    "spam_filter_updating": "spam_filter",
    "spam_filter_update": "spam_filter",
}


@contextlib.contextmanager
def _shade_context() -> Iterator[None]:
    """Make SHADE_Arena importable and its relative fixture paths resolvable."""
    if not SHADE_ROOT.is_dir():
        raise AdapterError(f"SHADE_Arena not found at {SHADE_ROOT}")

    added = [p for p in (str(AGENTLAB_ROOT), str(SHADE_ROOT)) if p not in sys.path]
    for path in added:
        sys.path.insert(0, path)
    previous_cwd = Path.cwd()
    try:
        os.chdir(SHADE_ROOT)
        yield
    finally:
        os.chdir(previous_cwd)
        for path in added:
            with contextlib.suppress(ValueError):
                sys.path.remove(path)


def resolve_environment(name: str) -> str:
    """Map a chain's environment label onto a concrete SHADE_Arena environment."""
    resolved = ENVIRONMENT_ALIASES.get(name, name)
    if resolved not in ENVIRONMENTS:
        raise AdapterError(f"no SHADE_Arena environment for {name!r}")
    return resolved


def _dependency_parameters(function: Any) -> set[str]:
    """Names of parameters injected from the environment rather than supplied."""
    injected: set[str] = set()
    try:
        hints = typing.get_type_hints(function, include_extras=True)
    except Exception:
        # Some tools reference types that are awkward to resolve; fall back to
        # reading the raw annotations, which still carry the Annotated metadata.
        hints = getattr(function, "__annotations__", {})

    for name, annotation in hints.items():
        for metadata in getattr(annotation, "__metadata__", ()):
            if type(metadata).__name__ == "Depends":
                injected.add(name)
    return injected


class ShadeArenaAdapter:
    """Exposes one SHADE_Arena environment as an MCP tool surface."""

    def __init__(self, name: str) -> None:
        self.name = resolve_environment(name)
        module_path, class_name = ENVIRONMENTS[self.name]

        with _shade_context():
            module = importlib.import_module(module_path)
            env_class = getattr(module, class_name)
            self.env = env_class.create()
            self._tools = {
                function.__name__: function
                for function in getattr(self.env, "available_tools", [])
                if callable(function)
            }

    # ------------------------------------------------------------------ EnvAdapter

    def list_tools(self) -> list[dict[str, Any]]:
        """Publish every tool, with injected dependencies removed from the schema."""
        definitions: list[dict[str, Any]] = []

        for name, function in sorted(self._tools.items()):
            injected = _dependency_parameters(function)
            properties: dict[str, Any] = {}
            required: list[str] = []

            for parameter in inspect.signature(function).parameters.values():
                if parameter.name in injected or parameter.name in ("self", "cls"):
                    continue
                properties[parameter.name] = {"type": json_type_of(parameter.annotation)}
                if parameter.default is inspect.Parameter.empty:
                    required.append(parameter.name)

            summary = (inspect.getdoc(function) or "").strip().splitlines()
            definitions.append(
                {
                    "name": name,
                    "description": summary[0] if summary else "",
                    "inputSchema": {
                        "type": "object",
                        "properties": properties,
                        "required": required,
                    },
                }
            )
        return definitions

    @staticmethod
    def to_jsonable(value: Any) -> Any:
        """Convert pydantic results into plain JSON-compatible structures.

        SHADE_Arena tools return pydantic models. Serialising those with
        ``default=str`` yields a Python repr -- ``"id_=\'29\' filename=\'plan.txt\'"``
        -- which is not something any MCP client could parse, and which destroys
        every structural signal downstream: the replay could not harvest the ids a
        real agent would carry forward, and the feature extractor could not see
        them either, leaving ``df_chained`` at 0 across the entire benchmark.
        """
        if hasattr(value, "model_dump"):
            try:
                return ShadeArenaAdapter.to_jsonable(value.model_dump())
            except Exception:
                pass
        if isinstance(value, dict):
            return {str(k): ShadeArenaAdapter.to_jsonable(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [ShadeArenaAdapter.to_jsonable(v) for v in value]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)

    def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
        """Invoke a tool, injecting environment components for ``Depends`` params."""
        function = self._tools.get(tool)
        if function is None:
            return {"success": False, "message": f"Invalid tool name {tool}."}

        call_arguments = dict(arguments or {})
        try:
            hints = typing.get_type_hints(function, include_extras=True)
        except Exception:
            hints = getattr(function, "__annotations__", {})

        for name, annotation in hints.items():
            for metadata in getattr(annotation, "__metadata__", ()):
                if type(metadata).__name__ == "Depends":
                    call_arguments[name] = metadata.extract_dep_from_env(self.env)

        # Drop anything the function does not accept, mirroring BaseEnv.call_tool's
        # tolerance -- a replayed chain may carry parameters this build does not have.
        accepted = set(inspect.signature(function).parameters)
        call_arguments = {k: v for k, v in call_arguments.items() if k in accepted}

        with _shade_context():
            try:
                return self.to_jsonable(function(**call_arguments))
            except TypeError as error:
                return {"success": False, "message": f"Bad arguments for {tool}: {error}"}
            except Exception as error:
                # A tool raising is a legitimate observation, not a harness failure:
                # error text is itself an injection vector (CyberArk, ref [22]).
                return {"success": False, "message": f"{type(error).__name__}: {error}"}
