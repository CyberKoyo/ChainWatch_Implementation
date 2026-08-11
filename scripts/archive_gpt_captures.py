#!/usr/bin/env python
"""Move a GPT capture generation into a dated, checksummed, recoverable archive.

The sessions on disk are section 15's evidence, so this never deletes. It also
never leaves them where a resumed grid would count them as already captured --
they were produced by different detectors, and treating them as current would mix
two corpora exactly as note 30's pre-neutral-cwd batches did.

Dry run is the default. `--apply` moves, verifies each checksum after the move,
and refuses outright on any destination that already exists.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import shutil
import sys
from pathlib import Path

SUBDIRS = ("logs", "transcripts", "scores")
ARCHIVE_DIRNAME = "archive"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def plan_archive(state: Path, *, sources: tuple[str, ...], stamp: str) -> list[dict]:
    """Every artifact belonging to these sources, with its destination. Moves nothing."""
    state = Path(state)
    archive_root = state / ARCHIVE_DIRNAME
    destination_root = archive_root / f"gpt-grid-pre-v2-{stamp}"
    plan: list[dict] = []
    for source in sources:
        for subdir in SUBDIRS:
            for path in sorted((state / subdir).glob(f"{source}-*")):
                plan.append({
                    "original": str(path),
                    "archived": str(destination_root / subdir / path.name),
                    "source": source,
                    "session": path.stem,
                })
        # The aggregates sit at the top of the state dir, not in a subdir. The
        # `archive/` guard is what stops a second pass from re-archiving the
        # first pass's own output, since the destination lives under `state`.
        for path in sorted(state.glob(f"{source}_*-*.jsonl")):
            if archive_root in path.parents:
                continue
            plan.append({
                "original": str(path),
                "archived": str(destination_root / path.name),
                "source": source,
                "session": None,
            })
    return plan


def apply_archive(plan: list[dict]) -> Path:
    """Move every planned artifact, then verify. Returns the manifest path."""
    if not plan:
        print("nothing to archive", file=sys.stderr)
        raise SystemExit(2)

    for item in plan:
        if Path(item["archived"]).exists():
            print(f"destination exists, refusing: {item['archived']}", file=sys.stderr)
            raise SystemExit(1)

    root = Path(plan[0]["archived"]).parent
    while root.parent != root and not root.name.startswith("gpt-grid-pre-v2-"):
        root = root.parent
    manifest_path = root / "archive_manifest.jsonl"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    with open(manifest_path, "a", encoding="utf-8") as handle:
        for item in plan:
            source_path = Path(item["original"])
            checksum = sha256_of(source_path)
            size = source_path.stat().st_size
            destination = Path(item["archived"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source_path), str(destination))
            # Verify after the move, not before. A checksum taken only on the way
            # out proves the file was readable, not that it arrived.
            if sha256_of(destination) != checksum:
                print(f"checksum changed in transit: {destination}", file=sys.stderr)
                raise SystemExit(1)
            handle.write(json.dumps({**item, "bytes": size, "sha256": checksum},
                                    separators=(",", ":")) + "\n")
    return manifest_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", type=Path, default=Path.home() / ".chainwatch")
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument("--stamp", default=None, help="archive date stamp; defaults to today UTC")
    parser.add_argument("--apply", action="store_true", help="perform the move (default: dry run)")
    options = parser.parse_args(argv)

    stamp = options.stamp or datetime.datetime.now(datetime.UTC).strftime("%Y%m%d")
    plan = plan_archive(options.state_dir, sources=tuple(options.source), stamp=stamp)
    for item in plan:
        print(f"{'MOVE' if options.apply else 'PLAN'} {item['original']} -> {item['archived']}")
    print(f"{len(plan)} artifact(s)", file=sys.stderr)
    if not options.apply:
        print("dry run; nothing moved. Re-run with --apply", file=sys.stderr)
        return 0
    manifest_path = apply_archive(plan)
    print(f"archived, manifest at {manifest_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
