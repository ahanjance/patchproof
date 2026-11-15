"""Part 3: diff parsing and execution-to-source frame normalization.

This module is intentionally limited to the evidence-collection phase of Part 3:
parsing git diffs into changed regions and extracting user frames from crash
reports. It does not decide whether a security issue is fixed or incomplete;
that classification is implemented in later Part 3 steps.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?: (?P<header>.*))?$"
)

_RUNTIME_FRAME_PREFIXES = (
    "__asan",
    "__interceptor",
    "___interceptor",
    "__sanitizer",
    "__ubsan",
    "__libc_start",
    "_start",
    "__GI_",
    "__pthread_kill",
    "raise",
    "abort",
    "__stack_chk_fail",
    "__fortify_fail",
    "__chk_fail",
)
_FRAME_RE = re.compile(
    r"^\s*#(?P<idx>\d+)\s+(?:0x[0-9A-Fa-f]+)?(?:\s+in\s+)?(?P<func>\S+)(?:\s+\((?P<object>[^)]+)\))?(?:\s+at\s+(?P<file>.+?):(?P<line>\d+))?\s*$"
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


@dataclass(frozen=True)
class NormalizedFrame:
    """A crash stack frame after runtime frames are filtered out."""

    function: str
    file: str | None = None
    line: int | None = None
    raw: str = ""


@dataclass(frozen=True)
class CorrelationMatch:
    """Evidence that a crash frame intersects a changed code region."""

    file: str
    function: str | None
    line: int | None
    range_start: int | None
    range_end: int | None
    confidence: str


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


def extract_user_frames(report: str) -> list[NormalizedFrame]:
    """Extract user stack frames from a crash report, ignoring runtime frames.

    This is deliberately generic and only normalizes execution evidence. It does
    not make any security classification decisions.
    """

    frames: list[NormalizedFrame] = []
    for line in (report or "").splitlines():
        match = _FRAME_RE.match(line)
        if not match:
            continue

        function = match.group("func")
        if function.startswith(_RUNTIME_FRAME_PREFIXES):
            continue

        file_value = match.group("file")
        if file_value and ("libasan" in file_value or "libubsan" in file_value):
            continue

        line_value = match.group("line")
        frames.append(
            NormalizedFrame(
                function=function,
                file=file_value.strip() if file_value else None,
                line=int(line_value) if line_value is not None else None,
                raw=line.rstrip(),
            )
        )
    return frames


def symbolize_frames(
    frames: list[NormalizedFrame],
    binary_path: str,
    *,
    symbolizer: str | None = None,
    runner=subprocess.run,
) -> list[NormalizedFrame]:
    """Resolve a frame's source file and line via addr2line/llvm-symbolizer.

    If a frame already has a file and line, it is left alone. If the tool cannot
    symbolise a frame, the original frame is preserved and the method returns the
    same function metadata without raising.
    """

    if not frames or not binary_path:
        return list(frames)

    chosen = symbolizer or _detect_symbolizer()
    if chosen is None:
        return list(frames)

    resolved: list[NormalizedFrame] = []
    for frame in frames:
        if frame.file is not None and frame.line is not None:
            resolved.append(frame)
            continue

        address = _extract_address(frame.raw)
        if not address:
            resolved.append(frame)
            continue

        command = _symbolizer_command(chosen, binary_path, address)
        if command is None:
            resolved.append(frame)
            continue

        try:
            completed = runner(command, capture_output=True, text=True, check=False)
        except OSError:
            resolved.append(frame)
            continue

        resolved_frame = _apply_symbolizer_result(frame, completed.stdout)
        resolved.append(resolved_frame)

    return resolved


def _detect_symbolizer() -> str | None:
    if shutil.which("addr2line"):
        return "addr2line"
    if shutil.which("llvm-symbolizer"):
        return "llvm-symbolizer"
    return None


def _symbolizer_command(symbolizer: str, binary_path: str, address: str) -> list[str] | None:
    if symbolizer == "addr2line":
        return ["addr2line", "-f", "-C", "-e", binary_path, address]
    if symbolizer == "llvm-symbolizer":
        return ["llvm-symbolizer", "-e", binary_path, address]
    return None


def _extract_address(raw: str) -> str | None:
    match = re.search(r"0x[0-9A-Fa-f]+", raw or "")
    if not match:
        return None
    return match.group(0)


def _apply_symbolizer_result(frame: NormalizedFrame, stdout: str) -> NormalizedFrame:
    output = (stdout or "").strip()
    if not output:
        return frame

    match = re.search(r"(?P<file>.+?):(?P<line>\d+)$", output)
    if match:
        file_value = match.group("file")
        line_value = int(match.group("line"))
        return NormalizedFrame(
            function=frame.function,
            file=file_value,
            line=line_value,
            raw=frame.raw,
        )

    # Some symbolizers return a function name on the first line and a file:line on
    # the second. Accept the first resolved file:line pair in that case.
    for candidate in output.splitlines():
        match = re.search(r"(?P<file>.+?):(?P<line>\d+)$", candidate.strip())
        if match:
            file_value = match.group("file")
            line_value = int(match.group("line"))
            return NormalizedFrame(
                function=frame.function,
                file=file_value,
                line=line_value,
                raw=frame.raw,
            )

    return frame


def correlate_frames_to_diff(
    frames: list[NormalizedFrame],
    changed_files: list[ChangedFile],
) -> list[CorrelationMatch]:
    """Match a normalized frame to a changed diff range using file and line info.

    The logic is intentionally conservative: a direct match requires either the
    same file and line range or the same function name and a changed hunk in that
    function. This is still a direct correlation step, not a final status
    decision.
    """

    matches: list[CorrelationMatch] = []
    for frame in frames:
        if not frame.file:
            continue

        for changed in changed_files:
            if changed.path != frame.file:
                continue
            for hunk in changed.hunks:
                if frame.line is not None and hunk.new_start <= frame.line <= hunk.new_start + max(hunk.new_count, 1) - 1:
                    matches.append(
                        CorrelationMatch(
                            file=changed.path,
                            function=frame.function,
                            line=frame.line,
                            range_start=hunk.new_start,
                            range_end=hunk.new_start + max(hunk.new_count, 1) - 1,
                            confidence="direct",
                        )
                    )
                    continue
                if frame.function and any(frame.function in line for line in hunk.lines if line.startswith(("+", "-", " "))):
                    matches.append(
                        CorrelationMatch(
                            file=changed.path,
                            function=frame.function,
                            line=frame.line,
                            range_start=hunk.new_start,
                            range_end=hunk.new_start + max(hunk.new_count, 1) - 1,
                            confidence="function-name",
                        )
                    )
    return matches


def correlate_caller_callee(
    changed_files: list[ChangedFile],
    frames: list[NormalizedFrame],
    *,
    caller_function: str | None = None,
    callee_function: str | None = None,
) -> list[CorrelationMatch]:
    """Handle indirect patch influence from a caller to a downstream callee.

    This function models the required project case where a validation or bounds
    check is changed in one function and a crash appears while the callee later
    acts on bad input. Only a clear caller-to-callee relationship is treated as
    evidence; ambiguous chains are ignored.
    """

    matches: list[CorrelationMatch] = []
    if not changed_files or not frames:
        return matches

    if caller_function is None and callee_function is None:
        return matches

    for changed in changed_files:
        for hunk in changed.hunks:
            if caller_function:
                hunk_text = "\n".join([hunk.header, *hunk.lines])
                context_tokens = [
                    candidate.strip().lstrip("+- ")
                    for candidate in hunk.lines
                    if candidate.startswith(("+", "-", " "))
                ]
                if caller_function not in hunk_text and not any(
                    caller_function in token for token in context_tokens
                ):
                    continue

                for frame in frames:
                    if callee_function and frame.function == callee_function:
                        matches.append(
                            CorrelationMatch(
                                file=changed.path,
                                function=caller_function,
                                line=None,
                                range_start=hunk.new_start,
                                range_end=hunk.new_start + max(hunk.new_count, 1) - 1,
                                confidence="caller-callee",
                            )
                        )
                    elif callee_function is None and frame.file == changed.path:
                        matches.append(
                            CorrelationMatch(
                                file=changed.path,
                                function=caller_function,
                                line=frame.line,
                                range_start=hunk.new_start,
                                range_end=hunk.new_start + max(hunk.new_count, 1) - 1,
                                confidence="caller-callee",
                            )
                        )
    return matches


def _normalise_path(path: str) -> str:
    text = path.strip()
    if text.startswith("a/") or text.startswith("b/"):
        text = text[2:]
    return text
