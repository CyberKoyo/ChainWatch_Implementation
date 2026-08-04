"""Command-line entry points.

    chainwatch [options] -- <server command>   proxy mode (the default)
    chainwatch daemon                          shared cross-server session state
    chainwatch check --input '<json-rpc>'      dry-run one call, no proxy
    chainwatch train --traces ... --out ...    Baum-Welch over captured traces

``check`` mirrors mcpwall's own dry-run subcommand, including its exit codes, so
the two can be used interchangeably in scripts and CI:
0 allowed, 1 blocked, 2 input or configuration error.
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
import time
from pathlib import Path

import numpy as np

from .engine.features import ObservedCall
from .engine.rules import RuleConfig
from .engine.session import SessionAnalyzer

EXIT_ALLOWED = 0
EXIT_BLOCKED = 1
EXIT_ERROR = 2


def command_check(argv: list[str]) -> int:
    """Evaluate one or more JSON-RPC messages without running the proxy."""
    parser = argparse.ArgumentParser(prog="chainwatch check")
    parser.add_argument("--input", help="a JSON-RPC message; omit to read stdin")
    parser.add_argument("--server", default="default")
    options = parser.parse_args(argv)

    raw = options.input if options.input else sys.stdin.read()
    if not raw.strip():
        sys.stderr.write("chainwatch check: no input\n")
        return EXIT_ERROR

    analyzer = SessionAnalyzer()
    worst = EXIT_ALLOWED

    # Accept either a single message or one per line, so a captured session can be
    # piped straight in and evaluated as a sequence.
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError as error:
            sys.stderr.write(f"chainwatch check: invalid JSON: {error}\n")
            return EXIT_ERROR

        params = message.get("params") or {}
        tool = params.get("name")
        if message.get("method") != "tools/call" or not tool:
            continue

        call = ObservedCall(
            tool=tool,
            arguments=params.get("arguments", {}),
            server=options.server,
            timestamp=time.time(),
        )
        verdict = analyzer.submit(call)

        mark = "x" if verdict.blocked else ("!" if verdict.rules_fired else "+")
        print(f"{mark} {verdict.severity.name:8s} stage {verdict.stage}  {tool}")
        for alert in verdict.alerts:
            print(f"    {alert}")
        if verdict.blocked:
            worst = EXIT_BLOCKED

    return worst


def command_daemon(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="chainwatch daemon")
    parser.add_argument("--socket", default=None, help="override the socket path")
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--steps", type=int, default=5)
    options = parser.parse_args(argv)

    from .daemon.server import DEFAULT_SOCKET_PATH, serve

    serve(
        socket_path=options.socket or DEFAULT_SOCKET_PATH,
        config=RuleConfig(window=options.window, step_threshold=options.steps),
    )
    return EXIT_ALLOWED


def command_train(argv: list[str]) -> int:
    """Re-estimate the model from captured traces (section IV-C)."""
    parser = argparse.ArgumentParser(prog="chainwatch train")
    parser.add_argument("--traces", nargs="+", required=True, help="JSONL trace files or globs")
    parser.add_argument("--iters", type=int, default=50)
    parser.add_argument("--out", default="chainwatch/models/trained.json")
    parser.add_argument(
        "--transitions-only",
        action="store_true",
        help="re-estimate A and pi but keep the Table I emission priors",
    )
    options = parser.parse_args(argv)

    from .engine.model import build_prior_model, save_model

    paths: list[str] = []
    for pattern in options.traces:
        paths.extend(sorted(glob.glob(pattern)))
    if not paths:
        sys.stderr.write("chainwatch train: no trace files matched\n")
        return EXIT_ERROR

    sequences = [seq for path in paths for seq in _load_sequences(Path(path))]
    if not sequences:
        sys.stderr.write("chainwatch train: trace files contained no feature vectors\n")
        return EXIT_ERROR

    model = build_prior_model()
    print(f"training on {len(sequences)} sessions ({sum(len(s) for s in sequences)} calls)")
    history = model.baum_welch(
        sequences,
        iterations=options.iters,
        update_emissions=not options.transitions_only,
    )
    print(f"log-likelihood {history[0]:.2f} -> {history[-1]:.2f} over {len(history)} iterations")

    save_model(model, options.out)
    print(f"wrote {options.out}")
    return EXIT_ALLOWED


def _load_sequences(path: Path) -> list[np.ndarray]:
    """Group a JSONL trace into per-session observation matrices.

    Lines carry a ``v`` feature vector and optionally a ``session`` id; without one
    the whole file is treated as a single session.
    """
    sessions: dict[str, list[list[float]]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        vector = entry.get("v")
        if not isinstance(vector, list):
            continue
        sessions.setdefault(str(entry.get("session", path.stem)), []).append(vector)
    return [np.array(rows, dtype=np.float64) for rows in sessions.values() if rows]


def command_ml_train(argv: list[str]) -> int:
    """Fit the supervised scorer over captured traces."""
    parser = argparse.ArgumentParser(prog="chainwatch ml-train")
    parser.add_argument(
        "--traces",
        nargs="+",
        default=["traces/agentlab.jsonl"],
        help="one or more JSONL trace files, read as a single corpus",
    )
    parser.add_argument("--out", default="chainwatch/models/scorer")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--arm", default="D", help="which feature groups to use (B, C, D or E)")
    options = parser.parse_args(argv)

    try:
        from .ml.dataset import ARMS, build  # noqa: PLC0415 -- optional dependency
        from .ml.evaluate import TRAIN_SOURCES
        from .ml.scorer import Scorer
    except ImportError as error:
        sys.stderr.write(f"chainwatch ml-train: {error}\ninstall with: pip install -e '.[ml]'\n")
        return EXIT_ERROR

    dataset = build(options.traces, groups=ARMS[options.arm], sources=TRAIN_SOURCES)
    if not len(dataset):
        sys.stderr.write("chainwatch ml-train: no rows built from traces\n")
        return EXIT_ERROR

    print(f"training arm {options.arm} on {len(dataset)} calls "
          f"({len(set(dataset.sessions.tolist()))} sessions, {len(dataset.names)} features)")
    Scorer.train(dataset, seed=options.seed).save(options.out)
    print(f"wrote {options.out}.ubj")
    return EXIT_ALLOWED


def command_ml_eval(argv: list[str]) -> int:
    """Run the five-arm comparison against the rule engine."""
    try:
        from .ml.evaluate import main as evaluate_main  # noqa: PLC0415
    except ImportError as error:
        sys.stderr.write(f"chainwatch ml-eval: {error}\ninstall with: pip install -e '.[ml]'\n")
        return EXIT_ERROR
    return evaluate_main(argv)


#: Subcommands. Anything not listed here is treated as proxy-mode options.
COMMANDS = {
    "check": command_check,
    "daemon": command_daemon,
    "train": command_train,
    "ml-train": command_ml_train,
    "ml-eval": command_ml_eval,
}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] in COMMANDS:
        return COMMANDS[argv[0]](argv[1:])

    # Default: proxy mode, so the MCP config line stays short.
    from .proxy.__main__ import main as proxy_main

    return proxy_main(argv)
