# GPT Grid Smoke and Parallel Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Plan file location.** Plan mode restricts edits to this file. At execution time, copy it to
> `docs/superpowers/plans/2026-08-11-gpt-grid-smoke-and-parallel-capture.md` — the convention
> CLAUDE.md §14 uses — before starting Task 1.

**Goal:** Buy the 70-session paid smoke of the AgentDojo + InjecAgent GPT-4o-mini grid, verify the
captured corpus against the machinery Part B built, present the go/no-go, and — only if the grid is
approved — build the sharding needed to capture the remaining 940 coordinates in about an hour
instead of seven to twelve.

**Architecture:** Tasks 1–4 are source-plan Task 11 (the paid smoke) and Task 12 (the readiness
review); they add no code and buy 70 sessions at a $0.25 combined cap. Task 5 is contingent on the
go/no-go and adds exactly two things the grid needs and does not yet have: a test that concurrent
`append_entry` does not tear a row, and `scripts/shard_recipes.py`, which slices a GENERATED recipe
TSV into provably disjoint shards on whole fold groups. Everything else parallel capture needs —
per-invocation run stamps, exclusive session artifacts, per-run aggregates — already exists.

**Tech Stack:** Python 3.12 + numpy 2.5.1 (`.venv`), pytest 9.1.1, node v24.14.1 (`npx mcpwall@0.3.1`),
vendored `agentdojo/` (editable) and `InjecAgent/` (data only), OpenAI Python SDK against
`gpt-4o-mini-2024-07-18`.

## Global Constraints

- Working dir `/home/hismajesty/Documents/MCP_ML_Firewall/ChainWatch_Implementation`; interpreter is
  `.venv/bin/python` — never bare `python3`.
- **Stage or commit nothing without explicit confirmation.** Every commit step means: show the file
  list and the diff, ask, then commit. Standing user rule.
- **No commit trailers.** No `Co-Authored-By`, no `Claude-Session`.
- **Every paid command is run by the operator**, prefixed with `!`, with `OPENAI_API_KEY` inline. The
  key never enters this session's context, a file, or a script.
- **No API call without a fresh confirmation naming the exact command and cap.** Approval of this
  plan is not that confirmation. Tasks 2 and 3 each need their own.
- **Never pool populations.** `agentdojo-gpt4omini` and `injecagent-gpt4omini` are reported apart
  from each other and from every legacy population. Selection is on `source`.
- Recipe TSVs under `docs/` are **GENERATED** — read them, slice them, never hand-edit them.
- `r3_attested_action` stays `"downgrade"`. No policy change here.
- The 20-dim vector is fixed (CLAUDE.md §5). No 21st column. `chainwatch/engine/` stays pure numpy.
- Baseline before Task 5: `.venv/bin/pytest tests/ -q` → **379 passed, 1 skipped**, measured at HEAD
  `e7026f4`. Re-record the actual number at Task 5 Step 0; do not assert this one.

---

## Context

Part B is committed (`d24e768` … `e7026f4`). The manifest keys every session by published grid
**coordinate** (resume, duplicate detection) and published **task** (fold grouping); both wrappers
resume and refuse a dirty tree; `chainwatch/ml/native.py` joins the benchmarks' own success checks so
an attack the model *declined* never enters the positive class; `_folds` splits on task rather than
session; and the 45 pre-fix GPT sessions are archived recoverably at
`~/.chainwatch/archive/gpt-grid-pre-v2-20260811/`.

The primary corpus is therefore **empty**, `oc_landing_report.py` exits 2 with
`NOT CAPTURED (primary source)` — undecidable, not failing — and every stated reason not to buy
sessions has been removed. Verified read-only at HEAD `e7026f4`:

| check | result |
|---|---|
| `.venv/bin/pytest tests/ -q` | **379 passed, 1 skipped** (holdout skipped by default) |
| `scripts/grid_readiness.py` | `0 of 452` / `0 of 558` complete, **0 duplicated** |
| AgentDojo `--dry-run --groups-per-partition 2` | **selected=40**, whole task groups, no client constructed |
| InjecAgent `--dry-run --groups-per-partition 5` | **selected=30**, both splits including `ds` |
| chain argv | `npx mcpwall` outermost → chainwatch `--observe-only --no-daemon --log-args` → bridge |
| `assert_clean_worktree` | tracked-diff only; untracked `INJECTION_OBSERVABILITY.md` passes |

### Where the 42 s/session actually goes

Measured on this machine (8 cores, ~8 GB available) rather than estimated:

| component | cost |
|---|---|
| `import agentdojo.task_suite.load_suites` | **15.1 s** — AgentDojo's eager registry: importing it loads every suite of v1 and v1_1 |
| rest of the AgentDojo bridge boot (env build, deep copy) | ≈7 s |
| `npx -y mcpwall` | 2.3 s |
| the API turns themselves | the ≈17 s remainder |
| **InjecAgent bridge boot** | **0.26 s** — route F is API-latency bound, not CPU bound |
| bridge peak RSS | 189 MB; ≈330 MB per session with the node and numpy processes |

**Making the AgentDojo import lazy would save nothing, and that is measured rather than assumed.**
`agentdojo_bridge/adapter.py:34` builds all four suites eagerly, but
`from agentdojo.task_suite.load_suites import get_suite` alone costs **15.152 s** while building
`workspace` on top of it costs **15.147 s** — construction is free, the import is the whole bill. The
adapter's own docstring records that importing a suite module directly hits a circular import inside
AgentDojo, so `get_suite` is the only supported door. That lever is dead.

So the only lever on wall clock is sharding, and the load profile suits it: CPU-bound, 189 MB,
8 cores. Route E is floored at 452 × ~25 s CPU ÷ 8 cores ≈ 24 min; route F is latency-bound and
takes more workers than E. Projection on that basis: **≈1 hour for the whole grid** at six shards
per route with both routes running together, against 7–12 h serial. Money was never the constraint
and still is not — the full grid is ≈**$0.42**.

### Why sharding needs a script rather than an `awk` line

`--resume` computes its skip set once at startup, so two concurrent processes over overlapping rows
both buy the same coordinate; `assert_no_duplicates` then refuses every later run until the manifest
is repaired. Disjointness therefore has to be a property of the input files and has to be *checked*.
And what a shard file contains decides which coordinates were bought, which puts it under the same
rule as the recipe files themselves: generated and reproducible, never a shell-history artifact.

---

## File Structure

| file | responsibility | change |
|---|---|---|
| `tests/test_capture_manifest.py` | manifest invariants | Task 5 — add one concurrency test; reuse the existing `_entry` factory |
| `scripts/shard_recipes.py` | **new** — slice a GENERATED recipe TSV into disjoint shards on whole fold groups | Task 5 |
| `tests/test_shard_recipes.py` | **new** — every row survives exactly once; no group spans two shards | Task 5 |
| `CLAUDE.md` (parent dir, untracked) | living spec | Task 4/5 — note 38, §12 phase table, §15 primary gate |

No capture code changes. Tasks 1–4 add no files at all.

---

### Task 1: Pre-flight and the first approval prompt

No API usage. Deliverable: a re-verified tree and an approval prompt the operator can answer.

**Files:** none — read-only verification.

**Interfaces:**
- Consumes: `scripts/grid_readiness.py`, both capture wrappers' `--dry-run`.
- Produces: the confirmed selection counts and caps that Tasks 2 and 3 quote verbatim.

- [ ] **Step 1: Confirm the tree is where the plan assumes**

```bash
git rev-parse --short HEAD && git status --short
```

Expected: `e7026f4`, and no tracked modifications. Untracked `INJECTION_OBSERVABILITY.md` is fine —
`assert_clean_worktree` inspects `git diff --stat HEAD` only, and its docstring says untracked files
are allowed on purpose. If HEAD differs, stop and re-verify the Context table before spending.

- [ ] **Step 2: Confirm the corpus is empty and undeduplicated**

```bash
.venv/bin/python scripts/grid_readiness.py
```

Expected: `0 of 452 complete, 452 remaining, 0 duplicated` and `0 of 558 complete, 558 remaining,
0 duplicated`. A nonzero `duplicated` means a prior run half-landed; stop and repair the manifest
before buying anything.

- [ ] **Step 3: Confirm what each smoke will select, without constructing a client**

```bash
.venv/bin/python scripts/capture_agentdojo_openai.py --dry-run \
    --corpus-revision v2 --groups-per-partition 2 2>&1 >/dev/null | tail -1
.venv/bin/python scripts/capture_injecagent_openai.py --dry-run \
    --corpus-revision v2 --groups-per-partition 5 2>&1 >/dev/null | tail -1
```

Expected: `selected=40 skipped_by_resume=0 planned=40` and `selected=30 skipped_by_resume=0
planned=30`. **The approval prompt quotes these numbers, never an estimate.**

- [ ] **Step 4: Present the approval prompt**

One message, containing all of:

- commit: **`e7026f4`**, tracked tree clean; corpus revision label **`v2`**
- pinned model **`gpt-4o-mini-2024-07-18`** — a response resolving to any other snapshot is rejected
  before its tool calls reach MCP
- coordinates: **40** AgentDojo across all four suites, **30** InjecAgent across both splits
- caps **$0.20** and **$0.05**, against measured means of $0.000675 and $0.000190/session
- **overshoot:** the budget is enforced on *observed* spend, so a cap can be exceeded by at most the
  final in-flight response
- writes to `~/.chainwatch/{logs,scores,transcripts,trace-staging}` and appends to
  `~/.chainwatch/*_manifest.jsonl`; makes no commit and touches no tracked file
- the two commands from Tasks 2 and 3, verbatim
- that the two may run **concurrently** — different sources, different manifests, disjoint by
  construction, one CPU-heavy and one not — taking the smoke from ≈50 min to ≈30 min

Then stop and wait. Do not proceed to Task 2 without an explicit yes.

---

### Task 2: The AgentDojo smoke

**Spends money.** Requires the Task 1 Step 4 confirmation.

**Files:** none. Writes only under `~/.chainwatch/`.

**Interfaces:**
- Consumes: the confirmed count (40) and cap ($0.20) from Task 1.
- Produces: 40 rows in `~/.chainwatch/agentdojo-gpt4omini_manifest.jsonl`, each with a coordinate,
  a fold group, a native `{utility, security}` verdict, and three artifact paths.

- [ ] **Step 1: The operator runs it**

Ask the operator to paste this prefixed with `!`, from the repo root, with the key inline:

```bash
OPENAI_API_KEY=sk-... .venv/bin/python scripts/capture_agentdojo_openai.py \
    --corpus-revision v2 --groups-per-partition 2 --resume --require-clean-git \
    --max-cost-usd 0.20 --confirm-api-usage
```

- [ ] **Step 2: Read the summary line rather than assuming success**

Expected on stderr: `captured=40 invalid_sidecars=0 injection_fired=<n> observed_cost=$0.0…`.

Any `invalid_sidecars` above 0 means a session's native score, executor status or trace-row count
disagreed and its traces were quarantined rather than published — report the count and the per-session
`[session] …` lines, do not average over it. `budget reached after N session(s)` means the cap bound
before the recipes did; that is a finding about cost, not a failure.

- [ ] **Step 3: If it was interrupted, resume rather than restart**

Re-run the identical command. `--resume` skips coordinates already complete under the same config
fingerprint, so batches compose; `new_capture_run_id()` gives the second invocation its own run stamp
and aggregate files, so nothing collides.

---

### Task 3: The InjecAgent smoke

**Spends money.** Requires its own confirmation. May run concurrently with Task 2.

**Files:** none. Writes only under `~/.chainwatch/`.

**Interfaces:**
- Consumes: the confirmed count (30) and cap ($0.05) from Task 1.
- Produces: 30 rows in `~/.chainwatch/injecagent-gpt4omini_manifest.jsonl`, including the `ds` split
  the pre-v2 archive never covered.

- [ ] **Step 1: The operator runs it**

```bash
OPENAI_API_KEY=sk-... .venv/bin/python scripts/capture_injecagent_openai.py \
    --corpus-revision v2 --groups-per-partition 5 --resume --require-clean-git \
    --max-cost-usd 0.05 --confirm-api-usage
```

- [ ] **Step 2: Read the summary line**

Expected: `captured=30 invalid_sidecars=0 …`. Route F sessions are short by construction — one user
tool plus whatever follows — so a low mean call count is the population's shape, not a defect.

---

### Task 4: Verify the corpus before reading anything into it

No API usage.

**Files:** none — read-only verification.

**Interfaces:**
- Consumes: the manifests, traces, scores and transcripts Tasks 2 and 3 wrote.
- Produces: the verified numbers Task 5 reports.

- [ ] **Step 1: Completeness and duplicates**

```bash
.venv/bin/python scripts/grid_readiness.py
```

Expected: `40 of 452` and `30 of 558` complete, **0 duplicated** on both. A duplicate here means two
invocations overlapped, and it must be resolved before any further capture.

- [ ] **Step 2: The primary gate**

```bash
.venv/bin/python scripts/oc_landing_report.py; echo "exit=$?"
```

Expected: **exit 0**, no `NOT CAPTURED (primary source)`, and each source's benign CRITICAL-session
rate **at or under 19.0%**, capped separately with a combined primary summary. A short source cannot
dilute a breach in the other; that is the gate's whole design.

- [ ] **Step 3: The rescore must agree with the as-captured view**

```bash
.venv/bin/python scripts/rescore_transcripts.py \
    --source agentdojo-gpt4omini --source injecagent-gpt4omini --quiet
```

This check is newly meaningful. The archived sessions predate the Part A detectors, so a divergence
there was expected; these were captured by the engine that is rescoring them, so **a divergence now
is a defect** — report it, do not reconcile it by choosing the friendlier number.

- [ ] **Step 4: Every manifest entry has its three artifacts**

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
from chainwatch.capture.manifest import read_entries
for source in ("agentdojo-gpt4omini", "injecagent-gpt4omini"):
    path = Path.home() / ".chainwatch" / f"{source}_manifest.jsonl"
    entries = read_entries(path)
    missing = [(e.session, name) for e in entries
               for name, target in e.artifacts.items() if not Path(target).exists()]
    print(source, "entries:", len(entries), "missing artifacts:", len(missing))
    for row in missing[:10]:
        print("   ", row)
PY
```

Expected: 40 and 30 entries, **0 missing**. Publication already requires native call count ==
executor call count == trace-row count, so a missing artifact is a bug rather than noise.

---

### Task 5: The readiness review, and the go/no-go

No API usage. This is source-plan Task 12. It ends by asking a question, not by deciding.

**Files:** none, unless the operator approves the grid — then Task 6.

**Interfaces:**
- Consumes: Task 4's verified outputs.
- Produces: a per-partition decision from the operator.

- [ ] **Step 1: Present the readiness report**

From `scripts/grid_readiness.py` plus the manifests: native attack success per suite and per split,
from the benchmarks' own `security()` and attacker-tool-called checks; mean attack call depth against
the ≥4 quality signal; native-valid and all-attempts sample sizes per partition; observed cost; and
projected remaining at both the measured mean and the measured max.

**Name an unavailable partition as unavailable.** `0 of 0 attempts succeeded natively` is not 0%.

- [ ] **Step 2: Present the rule-level result**

Per-source benign CRITICAL-session rate against the 19.0% ceiling, broken out per rule, the two
sources reported apart. This is the deliverable that does not depend on the ML arms existing at all —
CLAUDE.md §12 already records in writing that if the arms do not clear the permutation floor, the
rule-level table *is* the result.

- [ ] **Step 3: Ask, per partition, whether to buy the remainder**

Do not assume a partition with poor native success should be dropped, and do not assume one with good
success should be topped up. Both are the operator's call, and the staged design exists to keep them
that way.

- [ ] **Step 4: If the answer is no, stop here**

Record the smoke in CLAUDE.md as note 38 — the grid as captured, native success rates, the rule-level
false-positive table per source — update §12's phase table, and show the diff for confirmation before
any commit. Tasks 6 and 7 do not run.

---

### Task 6: Prove concurrent capture is safe, and make shards reproducible

Only if Task 5 approved at least one partition. No API usage.

**Files:**
- Modify: `tests/test_capture_manifest.py` (append one test; reuse the existing `_entry` factory)
- Create: `scripts/shard_recipes.py`
- Test: `tests/test_shard_recipes.py`

**Interfaces:**
- Consumes: `chainwatch.capture.manifest.append_entry` / `read_entries`; the GENERATED TSVs
  `docs/recipes_agentdojo.tsv` (5 columns: label, suite, user_task, injection_task, prompt) and
  `docs/recipes_injecagent.tsv` (6 columns: label, split, variant, case_index, user_tool, prompt).
- Produces: `group_key(fields: list[str]) -> str`, `shard(lines: Iterable[str], count: int) ->
  list[list[str]]`, and a CLI writing `<stem>_shard<i>.tsv` files that Task 7 feeds to the wrappers
  as their positional `recipes` argument.

- [ ] **Step 0: Record the baseline**

Run: `.venv/bin/pytest tests/ -q`
Write down the printed count. Later steps compare against that number, not against 379.

- [ ] **Step 1: Write the failing concurrency test**

Append to `tests/test_capture_manifest.py`:

```python
def _append_burst(path, writer, count):
    """One shard's worth of appends, in its own process."""
    for index in range(count):
        manifest.append_entry(
            path,
            _entry(
                ADOJO_BENIGN,
                session=f"w{writer}-{index}",
                coordinate=("agentdojo", "benign", "banking", f"user_task_{writer}", f"n{index}"),
            ),
        )


def test_concurrent_writers_never_tear_a_row(tmp_path):
    """Six parallel shards append to one manifest, so a torn row is silent corruption.

    A row is ~700 bytes and `append_entry` opens O_APPEND, so each write should be
    atomic on Linux -- but nothing asserted it until the grid needed six writers,
    and an unasserted floor is the defect note 37 is about.
    """
    from multiprocessing import Process

    path = tmp_path / "manifest.jsonl"
    writers, per_writer = 6, 40
    procs = [Process(target=_append_burst, args=(path, w, per_writer)) for w in range(writers)]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(timeout=120)

    assert [proc.exitcode for proc in procs] == [0] * writers
    entries = manifest.read_entries(path)
    assert len(entries) == writers * per_writer
    assert len({entry.coordinate for entry in entries}) == writers * per_writer
```

- [ ] **Step 2: Run it**

Run: `.venv/bin/pytest tests/test_capture_manifest.py::test_concurrent_writers_never_tear_a_row -v`

Expected: **PASS**, because `append_entry` already opens in append mode. This test is a floor being
pinned, not a bug being fixed — if it *fails*, parallel capture is off the table until
`append_entry` takes a lock, and that is exactly what the test exists to find out before money is
spent rather than after.

- [ ] **Step 3: Write the failing shard tests**

Create `tests/test_shard_recipes.py`:

```python
"""Shards decide which coordinates each parallel process buys.

`--resume` computes its skip set once at startup, so two processes over
overlapping rows both buy the same coordinate and `assert_no_duplicates` then
refuses every later run. Disjointness has to be a property of the files, and
checked rather than intended.
"""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import shard_recipes


ADOJO = [
    "benign\tbanking\tuser_task_0\t-\tPay the bill.\n",
    "attack\tbanking\tuser_task_0\tinjection_task_0\tPay the bill.\n",
    "attack\tbanking\tuser_task_0\tinjection_task_1\tPay the bill.\n",
    "benign\tslack\tuser_task_2\t-\tSummarise the channel.\n",
    "attack\tslack\tuser_task_2\tinjection_task_0\tSummarise the channel.\n",
    "benign\ttravel\tuser_task_1\t-\tBook the hotel.\n",
]
INJEC = [
    "benign\tdh\tbase\t0\tGitHubGetRepositoryDetails\tSummarise the repo.\n",
    "attack\tdh\tbase\t0\tGitHubGetRepositoryDetails\tSummarise the repo.\n",
    "attack\tdh\tenhanced\t0\tGitHubGetRepositoryDetails\tSummarise the repo.\n",
    "benign\tds\tbase\t4\tGitHubGetUserDetails\tSummarise the user.\n",
]


def test_every_row_survives_exactly_once():
    buckets = shard_recipes.shard(ADOJO, 3)
    assert sorted(row for bucket in buckets for row in bucket) == sorted(ADOJO)


def test_a_fold_group_never_spans_two_shards():
    buckets = shard_recipes.shard(ADOJO, 3)
    homes = {}
    for index, bucket in enumerate(buckets):
        for row in bucket:
            homes.setdefault(shard_recipes.group_key(row.rstrip("\n").split("\t")), index)
    for index, bucket in enumerate(buckets):
        for row in bucket:
            assert homes[shard_recipes.group_key(row.rstrip("\n").split("\t"))] == index


def test_injecagent_groups_bind_base_to_enhanced():
    assert shard_recipes.group_key(INJEC[1].rstrip("\n").split("\t")) == \
           shard_recipes.group_key(INJEC[2].rstrip("\n").split("\t"))
    assert shard_recipes.group_key(INJEC[0].rstrip("\n").split("\t")) != \
           shard_recipes.group_key(INJEC[3].rstrip("\n").split("\t"))


def test_comment_and_blank_lines_are_not_data():
    buckets = shard_recipes.shard(["# GENERATED\n", "\n", *ADOJO], 2)
    assert all(not row.startswith("#") and row.strip() for bucket in buckets for row in bucket)
    assert sum(len(bucket) for bucket in buckets) == len(ADOJO)


def test_an_unrecognised_row_width_is_an_error_not_a_guess():
    with pytest.raises(ValueError, match="4 columns"):
        shard_recipes.group_key(["benign", "banking", "user_task_0", "-"])


def test_the_cli_writes_disjoint_files_that_reassemble_the_input(tmp_path):
    source = tmp_path / "recipes.tsv"
    source.write_text("# GENERATED\n" + "".join(ADOJO), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(Path(shard_recipes.__file__)), str(source),
         "--shards", "3", "--out-dir", str(tmp_path / "out")],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    written = sorted((tmp_path / "out").glob("recipes_shard*.tsv"))
    assert len(written) == 3
    rejoined = sorted(line for path in written
                      for line in path.read_text(encoding="utf-8").splitlines(keepends=True)
                      if not line.startswith("#"))
    assert rejoined == sorted(ADOJO)
```

- [ ] **Step 4: Run them to verify they fail**

Run: `.venv/bin/pytest tests/test_shard_recipes.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'shard_recipes'`.

- [ ] **Step 5: Write the slicer**

Create `scripts/shard_recipes.py`:

```python
#!/usr/bin/env python
"""Slice a GENERATED recipe TSV into disjoint shards, on whole fold groups.

Parallel capture is only safe if two processes never share a coordinate, and
`--resume` cannot supply that: it computes its skip set once at startup, so two
concurrent runs over overlapping rows both buy the same coordinate and
`assert_no_duplicates` then refuses every later run. Disjointness has to be a
property of the input files, and it has to be checked rather than intended --
which is also why this is a script rather than a shell one-liner: what a shard
file contains decides which coordinates were bought, so it belongs under the
same rule as the recipe files themselves.

Splitting on whole fold groups additionally keeps a benign task and its injected
twin inside one process, which is the grouping the task-level folds rely on.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

#: The columns naming the published task, per route, keyed by row width.
#: AgentDojo: suite, user_task. InjecAgent: split, case_index -- which binds
#: `base` to `enhanced`, since the variant is not part of the task's identity.
GROUP_COLUMNS: dict[int, tuple[int, ...]] = {5: (1, 2), 6: (1, 3)}


def group_key(fields: list[str]) -> str:
    """The published task a row belongs to. Rows sharing it share a shard."""
    try:
        columns = GROUP_COLUMNS[len(fields)]
    except KeyError:
        raise ValueError(
            f"unrecognised recipe row of {len(fields)} columns; "
            f"expected one of {sorted(GROUP_COLUMNS)}"
        ) from None
    return ":".join(fields[index] for index in columns)


def shard(lines: Iterable[str], count: int) -> list[list[str]]:
    """Assign whole groups round-robin in first-seen order.

    Round-robin rather than by suite: banking carries seven injection tasks per
    user task where the others carry three, so slicing by suite leaves one shard
    twice the size of its siblings.
    """
    if count < 1:
        raise ValueError("shard count must be at least 1")
    buckets: list[list[str]] = [[] for _ in range(count)]
    assigned: dict[str, int] = {}
    for line in lines:
        if not line.strip() or line.startswith("#"):
            continue
        key = group_key(line.rstrip("\n").split("\t"))
        if key not in assigned:
            assigned[key] = len(assigned) % count
        buckets[assigned[key]].append(line)
    return buckets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="shard_recipes.py")
    parser.add_argument("recipes", type=Path)
    parser.add_argument("--shards", type=int, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    options = parser.parse_args(argv)

    if not options.recipes.is_file():
        parser.error(f"recipe file does not exist: {options.recipes}")

    lines = options.recipes.read_text(encoding="utf-8").splitlines(keepends=True)
    data = [line for line in lines if line.strip() and not line.startswith("#")]
    try:
        buckets = shard(lines, options.shards)
    except ValueError as error:
        parser.error(str(error))

    # Checked, not intended: a slicer that silently dropped or duplicated a row
    # would buy the wrong corpus and say nothing.
    rejoined = sorted(row for bucket in buckets for row in bucket)
    if rejoined != sorted(data):
        print("shards do not reassemble the input; refusing to write", file=sys.stderr)
        return 2

    options.out_dir.mkdir(parents=True, exist_ok=True)
    header = f"# GENERATED by shard_recipes.py from {options.recipes.name} -- do not edit.\n"
    for index, bucket in enumerate(buckets):
        target = options.out_dir / f"{options.recipes.stem}_shard{index}.tsv"
        target.write_text(header + "".join(bucket), encoding="utf-8")
        groups = {group_key(row.rstrip("\n").split("\t")) for row in bucket}
        print(f"{target} rows={len(bucket)} groups={len(groups)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `.venv/bin/pytest tests/test_shard_recipes.py tests/test_capture_manifest.py -v`
Expected: all PASS.

- [ ] **Step 7: Run the whole suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: Step 0's count plus 7 (6 shard tests + 1 concurrency test), still 1 skipped.

- [ ] **Step 8: Commit**

Show the file list and the diff, ask, and only then:

```bash
git add scripts/shard_recipes.py tests/test_shard_recipes.py tests/test_capture_manifest.py
git commit -m "feat(scripts): disjoint recipe shards for parallel grid capture"
```

---

### Task 7: The full grid, in parallel — second API approval checkpoint

**Spends money.** Requires a fresh confirmation with caps recomputed from the smoke's own usage —
never the smoke's cap, never the 3.0 default.

**Files:** none. Shard files are written under the scratch dir, not into `docs/`.

**Interfaces:**
- Consumes: `scripts/shard_recipes.py` from Task 6; the approved partitions from Task 5.
- Produces: the remaining manifest entries for each approved partition.

- [ ] **Step 1: Cut the shards and prove they are disjoint**

```bash
SHARDS="$HOME/.chainwatch/shards"         # outside docs/: these are scratch, not GENERATED recipes
mkdir -p "$SHARDS"
.venv/bin/python scripts/shard_recipes.py docs/recipes_agentdojo.tsv --shards 6 --out-dir $SHARDS
.venv/bin/python scripts/shard_recipes.py docs/recipes_injecagent.tsv --shards 6 --out-dir $SHARDS
cat $SHARDS/recipes_agentdojo_shard*.tsv | grep -v '^#' | sort | md5sum
grep -v '^#' docs/recipes_agentdojo.tsv | sort | md5sum
```

The two digests must match, and the printed row counts must sum to 452 and 558. The script refuses to
write if they do not, but the digest is the check a reviewer can repeat.

- [ ] **Step 2: Recompute the caps from the smoke's observed usage**

Remaining coordinates per approved partition × the smoke's observed **max** cost per session × 1.25,
divided by the shard count, since **`--max-cost-usd` is per process and must be divided, not
replicated**. `grid_readiness.py` prints the same arithmetic for the serial case and names its basis
on every line; quote its numbers rather than recomputing them by hand.

- [ ] **Step 3: Present the second approval prompt**

Selected partitions, remaining counts, the shard files, every command verbatim, the per-shard caps and
their sum, and the same overshoot disclosure as Task 1.

- [ ] **Step 4: On confirmation, the operator runs the shards**

Six per route, all carrying `--resume` so an interrupted shard composes rather than collides:

```bash
for i in 0 1 2 3 4 5; do
  OPENAI_API_KEY=sk-... .venv/bin/python scripts/capture_agentdojo_openai.py \
      $SHARDS/recipes_agentdojo_shard$i.tsv \
      --corpus-revision v2 --resume --require-clean-git \
      --max-cost-usd <per-shard> --confirm-api-usage &
done; wait
```

Watch `uptime` and `free -m` on the first minute: six AgentDojo sessions is ≈2 GB and six busy cores
out of eight. If load makes the machine unusable, drop to four shards — the projection is CPU-floored,
so four costs about 35 min against six's 24.

- [ ] **Step 5: Verify exactly as in Task 4**

`grid_readiness.py` (**0 duplicated** is the one that matters after a parallel run),
`oc_landing_report.py`, `rescore_transcripts.py`, and the artifact check.

- [ ] **Step 6: Evaluate, both analyses, never pooled**

```bash
.venv/bin/python -m chainwatch ml-eval --population agentdojo-gpt4omini
.venv/bin/python -m chainwatch ml-eval --population injecagent-gpt4omini
```

Report the native-valid primary and the all-attempts sensitivity side by side, each against the
permutation floor. **If an arm does not clear the floor, that is the result** — §12 records three
approaches already abandoned because the measurement said so, and a fourth is not a failure.

- [ ] **Step 7: Record it in CLAUDE.md and commit**

Note 38: the grid as captured, native success rates per suite and split, the rule-level
false-positive table per source, and the arms' verdict. Update §12's phase table and test count. Show
the diff, ask, then commit.

---

## Verification

In the order a reviewer would check it:

1. `git rev-parse --short HEAD` — the capture ran from a commit, with tracked files clean.
2. `.venv/bin/python scripts/grid_readiness.py` — completeness matches what was bought, and
   **0 duplicated** on both sources.
3. `.venv/bin/python scripts/oc_landing_report.py; echo $?` — exit **0**, each primary source at or
   under 19.0% benign CRITICAL sessions, reported apart.
4. `.venv/bin/python scripts/rescore_transcripts.py --source agentdojo-gpt4omini --source
   injecagent-gpt4omini --quiet` — agrees with the as-captured view.
5. `.venv/bin/pytest tests/ -q` — Task 6 Step 0's count plus 7, 1 skipped.
6. `.venv/bin/pytest tests/test_scenarios.py -q` — the §V-B gate, **40**, untouched throughout.
7. Every manifest entry's three artifacts exist (Task 4 Step 4's snippet).
8. `cat $SHARDS/recipes_*_shard*.tsv | grep -v '^#' | sort | md5sum` equals the filtered original,
   per route.
9. `git log --oneline` — no commit carries a `Co-Authored-By` or `Claude-Session` trailer.

## What this plan deliberately does not do

- **No unapproved API call.** Tasks 2, 3 and 7 each need their own confirmation naming the exact
  command and cap.
- **No lazy-import optimisation of the AgentDojo bridge.** Measured at zero benefit; the cost is
  AgentDojo's own eager registry and the supported entry point is `get_suite`.
- **No hand-edit of a GENERATED recipe file.** Shards are produced by script into scratch, and the
  digest check proves they reassemble the original.
- **No R3 policy change**, no new feature dimension, no `oc_probs` change, no HMM training.
- **No pooling.** The two GPT sources stay apart from each other and from every legacy population.
- **No deletion of any captured session.** Quarantine and archive move and checksum; they never
  remove.
