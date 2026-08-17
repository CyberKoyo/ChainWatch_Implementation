#!/usr/bin/env python3
"""Parameter Sensitivity by population -- the direct test of whether the leak closed.

    scripts/ps_by_population.py traces/agentlab.jsonl ~/.chainwatch/logs/*.jsonl

Phase 8 located the leak in argument *content*: ``agentlab_benign_gen`` fills parameters from
``PLACEHOLDERS`` (``"report"``, ``5``, ``False``), so synthesized benign carries
almost no parameter sensitivity by construction while attack chains carry real
argument strings. Measured at **0.6% nonzero against 72.7%** -- a 121x gap, and a
depth-3 tree splits on it once. The model learned "PS > 0 -> attack", which is a fact
about the generator rather than about attacks, and every held-out real trajectory
misfires accordingly.

Route C's attack half exists to close that gap by construction: both classes are
live agent sessions over the same four SHADE environments, lifting arguments out of
the same ~1.1 MB of populated fixtures. Whether it worked is this table and nothing
else. Two readings, both stated in the plan before the numbers existed:

* real benign and real attack land in the same neighbourhood -- the generator
  artifact is gone and any separation the model finds afterwards is behavioural;
* they still split cleanly -- the pipeline reintroduced a leak somewhere else and
  any model result over it is void.

A *low* PS on the attack side is not automatically good news either. The real
``bank_transfer_2`` twins already sit within 0.008 of each other, which says PS does
not separate them at all; that is the honest baseline this table is read against,
not zero.

``--nonzero-only`` restricts every statistic to calls that carry any sensitivity,
which is the comparison to make when one population has far more no-argument reads
than the other -- a mean over mostly-zero rows describes the mix of calls, not the
arguments.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

#: Parameter Sensitivity, dim 5 of the 20-dim vector (CLAUDE.md, "The 20-dimensional feature vector (§IV-B, Table II)").
PS_INDEX = 5


def load(paths: list[Path]) -> list[dict]:
    """Every line carrying a feature vector, from every file, in file order."""
    entries: list[dict] = []
    for path in paths:
        if not path.is_file():
            print(f"warning: no such trace file: {path}", file=sys.stderr)
            continue
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                # A line without a vector is not a call this can measure. Skipping
                # rather than defaulting keeps "absent" out of the arithmetic.
                if isinstance(entry, dict) and isinstance(entry.get("v"), list):
                    entries.append(entry)
    return entries


def population_of(entry: dict) -> tuple[str, str]:
    """``(label, source)`` -- the two fields that keep populations separable.

    Never merged into one key. ``label`` is asserted by the capturing proxy and
    ``source`` says which pipeline produced it; the whole point of the table is to
    compare the same label across two sources and the same source across two labels.
    """
    return str(entry.get("label", "?")), str(entry.get("source", "?"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ps_by_population.py", description=__doc__)
    parser.add_argument("traces", nargs="+", type=Path)
    parser.add_argument(
        "--nonzero-only",
        action="store_true",
        help="restrict every statistic to calls with PS > 0",
    )
    options = parser.parse_args(argv)

    entries = load(options.traces)
    if not entries:
        # Same failure as note 20: a script that measured nothing must not report a
        # clean pass, because "no data" and "no signal" are different findings.
        print("no trace lines with a feature vector: nothing was measured", file=sys.stderr)
        return 2

    by_population: dict[tuple[str, str], list[float]] = defaultdict(list)
    sessions: dict[tuple[str, str], set[str]] = defaultdict(set)
    for entry in entries:
        key = population_of(entry)
        vector = entry["v"]
        if len(vector) <= PS_INDEX:
            continue
        by_population[key].append(float(vector[PS_INDEX]))
        sessions[key].add(str(entry.get("session")))

    scope = "PS > 0 only" if options.nonzero_only else "all calls"
    print(f"Parameter Sensitivity by population   [{scope}]")
    print(f"{'label':8s} {'source':12s} {'sessions':>8s} {'calls':>7s} "
          f"{'mean':>7s} {'median':>7s} {'max':>6s} {'nonzero':>8s}")
    print("-" * 70)

    for key in sorted(by_population):
        label, source = key
        values = by_population[key]
        nonzero = [value for value in values if value > 0.0]
        shown = nonzero if options.nonzero_only else values
        if not shown:
            print(f"{label:8s} {source:12s} {len(sessions[key]):8d} {len(values):7d} "
                  f"{'-':>7s} {'-':>7s} {'-':>6s} {0.0:7.1f}%")
            continue
        print(
            f"{label:8s} {source:12s} {len(sessions[key]):8d} {len(shown):7d} "
            f"{statistics.fmean(shown):7.3f} {statistics.median(shown):7.3f} "
            f"{max(shown):6.2f} {len(nonzero) / len(values) * 100:7.1f}%"
        )

    # The comparison the plan actually asks for, spelled out rather than left to the
    # reader: the synthetic pair is the leak as measured, the real pair is whether it
    # closed, and the SHADE twins are the standing baseline for "PS separates
    # nothing". Printing all three together is what makes the second interpretable.
    def stats(label: str, source: str) -> tuple[float, float] | None:
        values = by_population.get((label, source))
        if not values:
            return None
        nonzero = [value for value in values if value > 0.0]
        return statistics.fmean(values), len(nonzero) / len(values)

    print()
    for title, attack, benign in (
        ("synthetic", ("attack", "agentlab"), ("benign", "realism")),
        # The matched twins are the row to read first. Both halves are live agent
        # work over the same fixtures *and* their task text differs by one clause of
        # the same author's prose, so a PS split here cannot be a generator artifact
        # the way the synthetic row's 121x is -- there is only one generator.
        ("live twins", ("attack", "twinattack"), ("benign", "twin")),
        # Kept, but `bizops`'s recipes were written by hand in this repo, so a split
        # on this row measures the recipe author as much as the pipeline.
        ("real (route C)", ("attack", "bizattack"), ("benign", "bizops")),
        ("real (SHADE twins)", ("attack", "shade"), ("benign", "shade")),
    ):
        left, right = stats(*attack), stats(*benign)
        if left is None or right is None:
            print(f"  {title:20s} not both populations present")
            continue
        ratio = (
            f"{left[1] / right[1]:.1f}x" if right[1] else "benign has no nonzero PS at all"
        )
        print(
            f"  {title:20s} attack PS {left[0]:.3f} ({left[1]:.1%} nonzero)   "
            f"benign PS {right[0]:.3f} ({right[1]:.1%} nonzero)   nonzero ratio {ratio}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
