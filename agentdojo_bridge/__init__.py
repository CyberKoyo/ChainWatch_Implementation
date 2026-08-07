"""Route E — AgentDojo served as a ChainWatch-observable MCP tool surface.

Benign and attack sessions differ by *one server-side data choice*: whether the
suite's injection vectors carry AgentDojo's verbatim ``important_instructions``
payload. The agent's prompt is the same published ``user_task`` either way, so a
resisted injection still yields a full trajectory -- which is what breaks the
refusal deadlock recorded in CLAUDE.md §12.
"""

from .adapter import BENCHMARK_VERSION, SUITES, AgentDojoAdapter
from .payload import build_injections

__all__ = ["AgentDojoAdapter", "SUITES", "BENCHMARK_VERSION", "build_injections"]
