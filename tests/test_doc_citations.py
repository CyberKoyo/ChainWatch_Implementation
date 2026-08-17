"""References to CLAUDE.md must be by name, and must resolve.

Section ordinals shift as a side effect of inserting a section. Renumbering
CLAUDE.md once invalidated two dozen references at once, silently, and no test
noticed. So the ordinal form is banned outright and this test is what enforces
it; cite `CLAUDE.md, "Running it"` or `CLAUDE.md, ambiguity A1` instead.

Note numbers are the deliberate exception: docs/development-notes.md declares
them permanent, so they are cited by number and merely checked to resolve.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: Only what ships. Enumerating the working tree instead would police vendored
#: benchmark clones, build output, and gitignored working documents -- files a
#: fresh clone does not have, so their references cannot rot for anyone else.
GIT_LS_FILES = ("git", "ls-files", "-z")

#: Fallback when git is unavailable (a tarball export, say). Then the working
#: tree is all there is, and these are the directories to stay out of.
SKIP_DIRS = {
    ".git", ".venv", "build", "dist", "__pycache__", ".pytest_cache",
    "agentdojo", "InjecAgent", "AgentLAB", "OpenAgentSafety",
    "Agent-SafetyBench", "regular_data", "superpowers",
}

SOURCE_SUFFIXES = {".py", ".sh", ".md", ".txt", ".tsv", ".yml", ".json"}

#: The banned form. Anchored on the filename, so the paper's own roman-numbered
#: sections can never match.
ORDINAL_RE = re.compile(r"CLAUDE\.md,?\s*(?:§|[Ss]ection\s+)\d+")

#: The permitted form: CLAUDE.md, "The capture executor"  /  ..., ambiguity A1
#: The comma is required, not optional: without it this matches Python source
#: such as (REPO / "CLAUDE.md").read_text(encoding="utf-8"), capturing the code
#: between the two quotes as if it were a heading.
NAMED_RE = re.compile(r'CLAUDE\.md,\s*(?:"([^"]{3,80})"|ambiguity (A[1-4]))')

#: "note 28", "Notes 36-37" -> 36. Bare, because notes are cited without a filename.
NOTE_RE = re.compile(r"\b[Nn]otes?\s+(\d+)\b")


def _sources() -> list[Path]:
    try:
        listed = subprocess.run(
            GIT_LS_FILES, cwd=REPO, capture_output=True, check=True, text=True
        ).stdout.split("\0")
        candidates = [REPO / name for name in listed if name]
    except (OSError, subprocess.CalledProcessError):
        candidates = [
            path
            for path in REPO.rglob("*")
            if not any(part in SKIP_DIRS for part in path.parts)
        ]
    return [p for p in candidates if p.suffix in SOURCE_SUFFIXES and p.is_file()]


def _claude_headings() -> set[str]:
    """Every heading in CLAUDE.md with any leading 'N. ' ordinal stripped, plus
    the four ambiguity labels. These are what a reference may name."""
    text = (REPO / "CLAUDE.md").read_text(encoding="utf-8")
    headings = set()
    for raw in re.findall(r"^#{2,4}\s+(.+?)\s*$", text, re.MULTILINE):
        headings.add(re.sub(r"^\d+\.\s*", "", raw))
    return headings | {"A1", "A2", "A3", "A4"}


def _note_numbers() -> set[int]:
    text = (REPO / "docs" / "development-notes.md").read_text(encoding="utf-8")
    return {int(n) for n in re.findall(r"^\| \*{0,2}(\d+)\*{0,2} \|", text, re.MULTILINE)}


def _hits(pattern: re.Pattern[str]) -> list[tuple[str, re.Match[str]]]:
    out = []
    for path in _sources():
        body = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(body.splitlines(), 1):
            for match in pattern.finditer(line):
                out.append((f"{path.relative_to(REPO)}:{lineno}", match))
    return out


def test_no_reference_cites_a_claude_md_section_number():
    """Ordinals shift when a section is inserted; names do not.

    This module is the one place the banned form could legitimately appear, so
    ORDINAL_RE is written with an escape sequence rather than the literal
    character and cannot match its own source.
    """
    bad = [f"{where}: {m.group(0)!r}" for where, m in _hits(ORDINAL_RE)]
    assert not bad, "cite CLAUDE.md by name, not by section number:\n" + "\n".join(bad)


def test_every_named_claude_md_reference_resolves():
    headings = _claude_headings()
    bad = [
        f"{where}: {(m.group(1) or m.group(2))!r}"
        for where, m in _hits(NAMED_RE)
        if (m.group(1) or m.group(2)) not in headings
    ]
    assert not bad, (
        "references name a CLAUDE.md heading that does not exist:\n" + "\n".join(bad)
    )


def test_every_note_reference_resolves():
    valid = _note_numbers()
    bad = [
        f"{where}: {m.group(0)!r}"
        for where, m in _hits(NOTE_RE)
        if int(m.group(1)) not in valid
    ]
    assert not bad, (
        "references name a note not in docs/development-notes.md:\n" + "\n".join(bad)
    )
