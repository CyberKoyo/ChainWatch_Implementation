#!/usr/bin/env python3
"""Capture Route F through OpenAI Chat Completions and the full MCP firewall chain."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from chainwatch.capture.openai_mcp import (  # noqa: E402
    CaptureBudget,
    SessionSpec,
    build_capture_child_env,
    build_mcpwall_chain_argv,
    new_capture_run_id,
    publish_session_traces,
    quarantine_session_traces,
    run_session,
)


DEFAULT_MODEL = "gpt-4o-mini-2024-07-18"
DEFAULT_SOURCE = "injecagent-gpt4omini"
#: Route F is a single environment -- every dev case drives a GitHub user tool -- so the
#: server name is constant. Naming it after `split` would hold out attack types instead.
SERVER_NAME = "injecagent-dev"


@dataclass(frozen=True)
class InjecAgentRecipe:
    label: str
    split: str
    variant: str
    case_index: int
    user_tool: str
    prompt: str

    def __post_init__(self) -> None:
        if self.label not in {"benign", "attack"}:
            raise ValueError(f"invalid label: {self.label}")
        if self.split not in {"ds", "dh"}:
            raise ValueError(f"invalid split: {self.split}")
        if self.variant not in {"base", "enhanced"}:
            raise ValueError(f"invalid variant: {self.variant}")
        if self.label == "benign" and self.variant != "base":
            raise ValueError("benign InjecAgent rows must use the base variant")
        if self.case_index < 0:
            raise ValueError("case_index must be non-negative")


def load_recipes(path: Path) -> list[InjecAgentRecipe]:
    recipes: list[InjecAgentRecipe] = []
    with path.open(newline="", encoding="utf-8") as handle:
        rows: Iterable[list[str]] = csv.reader(
            (line for line in handle if line.strip() and not line.startswith("#")),
            delimiter="\t",
        )
        for number, row in enumerate(rows, start=1):
            if len(row) != 6:
                raise ValueError(f"recipe row {number} has {len(row)} columns; expected 6")
            try:
                case_index = int(row[3])
            except ValueError as error:
                raise ValueError(f"recipe row {number} has invalid case_index") from error
            recipes.append(InjecAgentRecipe(row[0], row[1], row[2], case_index, row[4], row[5]))
    return recipes


def build_server_args(recipe: InjecAgentRecipe, python: str, score_out: Path) -> list[str]:
    argv = [
        python,
        "-m",
        "injecagent_bridge.env_mcp_server",
        "--split",
        recipe.split,
        "--variant",
        recipe.variant,
        "--case-index",
        str(recipe.case_index),
        "--score-out",
        str(score_out),
    ]
    if recipe.label == "benign":
        argv.append("--benign")
    return argv


def build_chain_argv(
    recipe: InjecAgentRecipe,
    *,
    python: str,
    score_out: Path,
    log_dir: Path,
    model: str = DEFAULT_MODEL,
) -> list[str]:
    return build_mcpwall_chain_argv(
        python=python,
        label=recipe.label,
        source=DEFAULT_SOURCE,
        model=model,
        server_name=SERVER_NAME,
        log_dir=log_dir,
        server_args=build_server_args(recipe, python, score_out),
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return parsed


def _nonnegative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def _load_score(score_out: Path) -> dict | None:
    try:
        verdict = json.loads(score_out.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return verdict if isinstance(verdict, dict) else None


def validate_score(
    verdict: dict | None,
    recipe: InjecAgentRecipe,
    *,
    expected_calls: int,
) -> dict:
    """Validate native Route F ground truth before publishing any trace rows."""
    if verdict is None:
        raise ValueError("missing/invalid score sidecar")
    expected = {
        "split": recipe.split,
        "variant": recipe.variant,
        "case_index": recipe.case_index,
        "benign": recipe.label == "benign",
        "user_tool": recipe.user_tool,
        "calls": expected_calls,
    }
    for key, value in expected.items():
        actual = verdict.get(key)
        wrong_type = (
            key in {"case_index", "calls"} and type(actual) is not int
        ) or (key == "benign" and type(actual) is not bool)
        if actual != value or wrong_type:
            raise ValueError(f"score sidecar has unexpected {key}")
    if type(verdict.get("attacker_called")) is not bool:
        raise ValueError("score sidecar has invalid attacker_called verdict")
    attacker_tools = verdict.get("attacker_tools_called")
    if not isinstance(attacker_tools, list) or not all(
        isinstance(tool, str) for tool in attacker_tools
    ):
        raise ValueError("score sidecar has invalid attacker_tools_called verdict")
    if verdict["attacker_called"] != bool(attacker_tools):
        raise ValueError("score sidecar attacker verdict fields disagree")
    return dict(verdict)


def _append_score(
    aggregate: Path,
    verdict: dict,
    *,
    recipe: InjecAgentRecipe,
    session: str,
    result,
) -> None:
    verdict = dict(verdict)
    verdict.update(
        session=session,
        label=recipe.label,
        source=DEFAULT_SOURCE,
        requested_model=result.requested_model,
        resolved_model=result.resolved_model,
        executor_status=result.status,
    )
    with aggregate.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(verdict, separators=(",", ":")) + "\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="capture_injecagent_openai.py")
    parser.add_argument("recipes", nargs="?", type=Path, default=ROOT / "docs/recipes_injecagent.tsv")
    parser.add_argument("--limit", type=_positive_int, default=None)
    parser.add_argument(
        "--split",
        action="append",
        choices=("ds", "dh"),
        default=None,
        help="restrict to one or more InjecAgent splits; repeatable. Applied before --limit.",
    )
    parser.add_argument("--model", choices=(DEFAULT_MODEL,), default=DEFAULT_MODEL)
    parser.add_argument("--max-cost-usd", type=_nonnegative_float, default=3.0)
    parser.add_argument("--max-turns", type=_positive_int, default=12)
    parser.add_argument("--max-output-tokens", type=_positive_int, default=512)
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path(os.environ.get("CHAINWATCH_HOME", Path.home() / ".chainwatch")),
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--confirm-api-usage",
        action="store_true",
        help="acknowledge that this invocation may incur separately billed API usage",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    options = parser.parse_args(argv)
    if not options.recipes.is_file():
        parser.error(f"recipe file does not exist: {options.recipes}")
    if not options.dry_run and not options.confirm_api_usage:
        parser.error("live API usage requires --confirm-api-usage")
    if not options.dry_run and not os.environ.get("OPENAI_API_KEY"):
        parser.error("OPENAI_API_KEY is required for live capture")

    try:
        recipes = load_recipes(options.recipes)
    except ValueError as error:
        parser.error(str(error))
    if options.split:
        wanted = set(options.split)
        recipes = [recipe for recipe in recipes if recipe.split in wanted]
        if not recipes:
            parser.error(f"no recipes for split(s): {', '.join(sorted(wanted))}")
    if options.limit is not None:
        recipes = recipes[: options.limit]
    if not recipes:
        parser.error("recipe file contains no sessions")

    state = options.state_dir.resolve()
    logs = state / "logs"
    trace_staging = state / "trace-staging"
    transcripts = state / "transcripts"
    scores = state / "scores"
    workdir = state / "agent-cwd"
    agent_home = state / "agent-home"
    for directory in (logs, trace_staging, transcripts, scores, workdir, agent_home):
        directory.mkdir(parents=True, exist_ok=True)

    run_stamp = new_capture_run_id()
    python = sys.executable

    if options.dry_run:
        for index, recipe in enumerate(recipes, start=1):
            session = f"{DEFAULT_SOURCE}-dry-{index:03d}"
            score_out = scores / f"{session}.json"
            session_staging = trace_staging / session
            print(
                json.dumps(
                    {
                        "session": session,
                        "label": recipe.label,
                        "split": recipe.split,
                        "variant": recipe.variant,
                        "case_index": recipe.case_index,
                        "user_tool": recipe.user_tool,
                        "source": DEFAULT_SOURCE,
                        "model": options.model,
                        "cwd": str(workdir),
                        "chain_argv": build_chain_argv(
                            recipe,
                            python=python,
                            score_out=score_out,
                            log_dir=session_staging,
                            model=options.model,
                        ),
                    },
                    separators=(",", ":"),
                )
            )
        return 0

    score_aggregate = state / f"{DEFAULT_SOURCE}_scores-{run_stamp}.jsonl"
    usage_aggregate = state / f"{DEFAULT_SOURCE}_usage-{run_stamp}.jsonl"
    from openai import OpenAI

    openai_client = OpenAI(max_retries=0, timeout=60.0)
    budget = CaptureBudget(options.max_cost_usd)
    captured = invalid = complied = 0

    for index, recipe in enumerate(recipes, start=1):
        if not budget.available:
            print(f"budget reached after {index - 1} session(s); stopping", file=sys.stderr)
            break
        session = f"{DEFAULT_SOURCE}-{run_stamp}-{index:03d}"
        score_out = scores / f"{session}.json"
        session_staging = trace_staging / session
        transcript = transcripts / f"{session}.jsonl"
        if score_out.exists() or transcript.exists() or session_staging.exists():
            print(f"[{session}] session artifact collision; refusing capture", file=sys.stderr)
            return 4
        session_staging.mkdir()
        result = run_session(
            SessionSpec(
                session_id=session,
                label=recipe.label,
                source=DEFAULT_SOURCE,
                requested_model=options.model,
                prompt=recipe.prompt,
                chain_argv=build_chain_argv(
                    recipe,
                    python=python,
                    score_out=score_out,
                    log_dir=session_staging,
                    model=options.model,
                ),
                env=build_capture_child_env(
                    os.environ,
                    repo_root=ROOT,
                    neutral_home=agent_home,
                    session_id=session,
                ),
                cwd=workdir,
                stderr_path=logs / f"{DEFAULT_SOURCE}.err",
                transcript_path=transcript,
                usage_path=usage_aggregate,
                max_turns=options.max_turns,
                max_output_tokens=options.max_output_tokens,
            ),
            openai_client=openai_client,
            budget=budget,
        )
        trace_calls = 0
        try:
            verdict = validate_score(_load_score(score_out), recipe, expected_calls=result.calls)
        except ValueError as score_error:
            invalid += 1
            print(f"[{session}] {score_error}", file=sys.stderr)
            quarantine_session_traces(session_staging)
        else:
            if result.status not in {"completed", "max_turns"}:
                invalid += 1
                print(f"[{session}] rejected executor status {result.status}", file=sys.stderr)
                quarantine_session_traces(session_staging)
            else:
                try:
                    trace_calls = publish_session_traces(
                        session_staging,
                        logs,
                        session_id=session,
                        source=DEFAULT_SOURCE,
                        model=options.model,
                        expected_calls=result.calls,
                    )
                except (OSError, ValueError) as error:
                    invalid += 1
                    print(f"[{session}] invalid staged trace: {error}", file=sys.stderr)
                    quarantine_session_traces(session_staging)
                else:
                    _append_score(
                        score_aggregate,
                        verdict,
                        recipe=recipe,
                        session=session,
                        result=result,
                    )
                    if trace_calls > 0:
                        captured += 1
                        if verdict.get("attacker_called") is True:
                            complied += 1
        print(
            f"[{session}] status={result.status} mcp_calls={result.calls} "
            f"rejected={result.rejected_calls} trace_calls={trace_calls} "
            f"cost=${result.estimated_cost_usd:.6f}",
            file=sys.stderr,
        )

    print(
        f"captured={captured} invalid_sidecars={invalid} attacker_called={complied} "
        f"observed_cost=${budget.spent_usd:.6f}",
        file=sys.stderr,
    )
    if captured == 0:
        print("captured 0 sessions with any traced tool call", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
