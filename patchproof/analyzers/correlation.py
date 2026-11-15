"""Part 3: git-diff parsing and change-region extraction.

This module is intentionally limited to parsing the patch contents into
structured, evidence-friendly change regions. It does not decide whether a
security issue is fixed or incomplete; that classification is implemented in
later Part 3 steps.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?: (?P<header>.*))?$"
)


@dataclass(frozen=True)
class DiffHunk:
    """One unified-diff hunk."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str = ""
    lines: tuple[str, ...] = ()

    @property
    def old_range(self) -> tuple[int, int]:
        if self.old_count == 0:
            return (self.old_start, self.old_start)
        return (self.old_start, self.old_start + self.old_count - 1)

    @property
    def new_range(self) -> tuple[int, int]:
        if self.new_count == 0:
            return (self.new_start, self.new_start)
        return (self.new_start, self.new_start + self.new_count - 1)


@dataclass(frozen=True)
class ChangedFile:
    """All hunks for one changed file."""

    path: str
    hunks: tuple[DiffHunk, ...] = ()

    @property
    def changed_ranges(self) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        for hunk in self.hunks:
            ranges.append(hunk.new_range)
        return ranges


def parse_diff(diff_text: str) -> list[ChangedFile]:
    """Parse a unified git diff into a list of changed files and hunks.

    The output deliberately stays generic: it exposes the file, hunk range, and
    the raw diff lines without assuming anything about the target program. This
    is the foundation for later stack-to-diff correlation.
    """

    diff_text = diff_text or ""
    if not diff_text.strip():
        return []

    files: list[ChangedFile] = []
    current_path: str | None = None
    current_hunks: list[DiffHunk] = []
    pending_hunk: DiffHunk | None = None
    pending_lines: list[str] = []

    def flush_hunk() -> None:
        nonlocal pending_hunk, pending_lines, current_hunks
        if pending_hunk is None:
            return
        hunk = DiffHunk(
            old_start=pending_hunk.old_start,
            old_count=pending_hunk.old_count,
            new_start=pending_hunk.new_start,
            new_count=pending_hunk.new_count,
            header=pending_hunk.header,
            lines=tuple(pending_lines),
        )
        current_hunks.append(hunk)
        pending_hunk = None
        pending_lines = []

    def flush_file() -> None:
        nonlocal files, current_path, current_hunks
        if current_path is not None:
            files.append(ChangedFile(path=current_path, hunks=tuple(current_hunks)))
        current_path = None
        current_hunks = []

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff --git "):
            flush_hunk()
            flush_file()
            match = re.search(r" b/(.+)$", raw_line)
            if match:
                current_path = _normalise_path(match.group(1))
            continue

        if raw_line.startswith("--- ") and current_path is None:
            # Some diffs may not begin with a diff --git header; handle the file header
            # when it appears directly.
            path = raw_line[4:]
            if path.startswith("a/") or path.startswith("b/"):
                current_path = _normalise_path(path[2:])
            continue

        if raw_line.startswith("+++ "):
            # If the file path is already known, keep the latest value for the current file.
            path = raw_line[4:]
            if path.startswith("a/") or path.startswith("b/"):
                current_path = _normalise_path(path[2:])
            continue

        match = _HUNK_RE.match(raw_line)
        if match:
            flush_hunk()
            pending_hunk = DiffHunk(
                old_start=int(match.group("old_start") or 0),
                old_count=int(match.group("old_count") or 0),
                new_start=int(match.group("new_start") or 0),
                new_count=int(match.group("new_count") or 0),
                header=match.group("header") or "",
            )
            continue

        if pending_hunk is not None:
            pending_lines.append(raw_line)
            continue

        # Ignore non-hunk metadata lines.

    flush_hunk()
    flush_file()

    return files


def _normalise_path(path: str) -> str:
    text = path.strip()
    if text.startswith("a/") or text.startswith("b/"):
        text = text[2:]
    return text
