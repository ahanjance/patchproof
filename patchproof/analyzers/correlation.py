"""Part 3: diff parsing, execution evidence and status classification.

This module covers the evidence-collection and decisioning steps needed for
Part 3: parsing git diffs, extracting user frames from crash reports,
correlating those frames to changed code, and classifying the result as a
patch-related status.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

from ..analysis import AnalysisContext
from ..model import Finding, FindingStatus, TestObservation
from .crash import Classification, classify

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
    r"^\s*#(?P<idx>\d+)\s+(?:0x[0-9A-Fa-f]+)?(?:\s+in\s+)?(?P<func>\S+)(?:\s+\((?P<object>[^)]+)\))?(?:\s+(?:at\s+)?(?P<file>[^\s()]+?):(?P<line>\d+)(?::\d+)?)?\s*$"
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
    side: str = "new",
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
            # Frames carry the worktree's absolute path; the diff is repo-relative.
            if frame.file != changed.path and not frame.file.endswith("/" + changed.path):
                continue
            for hunk in changed.hunks:
                # A base crash has base line numbers, so it is compared to the old side.
                start, end = hunk.old_range if side == "old" else hunk.new_range
                if frame.line is not None and start <= frame.line <= end:
                    matches.append(
                        CorrelationMatch(
                            file=changed.path,
                            function=frame.function,
                            line=frame.line,
                            range_start=start,
                            range_end=end,
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


def classify_patch_status(
    *,
    base_reproduced: bool = False,
    patched_reproduced: bool = False,
    functional_regression: bool = False,
    has_match: bool = False,
    ambiguous: bool = False,
    classification: Classification | None = None,
) -> str:
    """Classify evidence into the five Part 3 status values.

    Part 2 already classifies the crash type, mechanism and confirmation state. When
    a confirmed crash object is supplied, its presence is treated as evidence that
    the underlying execution was a real vulnerability signal rather than a bare
    signal/timeout. Ambiguous or weak evidence still stays inconclusive.
    """

    if ambiguous:
        return "inconclusive"

    if classification is not None and not classification.confirmed:
        return "inconclusive"

    if functional_regression:
        return "functional_regression"

    if not has_match:
        return "inconclusive"

    if base_reproduced and patched_reproduced:
        return "incomplete"

    if base_reproduced and not patched_reproduced:
        return "fixed"

    if patched_reproduced and not base_reproduced:
        return "new"

    return "inconclusive"


def _observation_ref(obs: TestObservation | dict | tuple[str, str, str]) -> dict[str, str]:
    if isinstance(obs, TestObservation):
        return {"test_id": obs.test_id, "version": obs.version, "variant": obs.variant}
    if isinstance(obs, dict):
        return {
            "test_id": str(obs["test_id"]),
            "version": str(obs["version"]),
            "variant": str(obs["variant"]),
        }
    if isinstance(obs, (list, tuple)) and len(obs) == 3:
        test_id, version, variant = obs
        return {"test_id": str(test_id), "version": str(version), "variant": str(variant)}
    raise TypeError(f"Unsupported observation reference: {obs!r}")


def serialize_correlation_finding(
    *,
    finding_id: str,
    title: str,
    status: str | FindingStatus,
    summary: str = "",
    observations: list[TestObservation | dict | tuple[str, str, str]] | None = None,
    matches: list[CorrelationMatch] | None = None,
    frames: list[NormalizedFrame] | None = None,
    diff_hunks: list[dict] | None = None,
    kind: str = "security",
    confirmed: bool = True,
) -> Finding:
    """Build a Part 3 finding with exact references to the observations used.

    The verdict engine only trusts a finding when `evidence["observations"]` lists
    the exact `(test_id, version, variant)` tuples that were used as evidence. This
    helper centralizes that serialization contract and keeps the metadata stable
    across Part 3 findings.
    """

    obs_refs = [_observation_ref(obs) for obs in observations or []]
    evidence: dict[str, object] = {"observations": obs_refs}

    if matches:
        evidence["correlations"] = [
            {
                "file": match.file,
                "function": match.function,
                "line": match.line,
                "range_start": match.range_start,
                "range_end": match.range_end,
                "confidence": match.confidence,
            }
            for match in matches
        ]

    if frames:
        evidence["frames"] = [
            {
                "function": frame.function,
                "file": frame.file,
                "line": frame.line,
                "raw": frame.raw,
            }
            for frame in frames
        ]

    if diff_hunks:
        evidence["diff_hunks"] = diff_hunks

    normalized_status = FindingStatus(status) if not isinstance(status, FindingStatus) else status
    if not obs_refs:
        confirmed = False
        normalized_status = FindingStatus.INCONCLUSIVE

    return Finding(
        id=finding_id,
        title=title,
        status=normalized_status,
        kind=kind,
        confirmed=confirmed,
        summary=summary,
        evidence=evidence,
        analyzer="correlation",
    )


class CorrelationAnalyzer:
    """Part 3 serialization and correlation analyzer.

    This class is intentionally conservative: it serializes only evidence-backed
    findings and leaves status logic to the earlier Part 3 decision helpers.
    """

    name = "correlation"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        if not context.diff:
            return []

        relevant = [obs for obs in context.observations if obs.kind == "security"]
        if not relevant:
            return []

        findings: list[Finding] = []
        grouped: dict[str, list[TestObservation]] = {}
        for observation in relevant:
            grouped.setdefault(observation.test_id, []).append(observation)

        diff_files = parse_diff(context.diff)
        for test_id, observations in grouped.items():
            # Same notion of "reproduced" as Part 2, so UBSan exits without a signal count.
            hits = [obs for obs in observations if classify(obs, obs.stderr or "")]
            base_hit = any(obs.version == "base" for obs in hits)
            patched_hit = any(obs.version == "patched" for obs in hits)
            if not hits:
                continue

            frames = []
            matches = []
            for obs in hits:
                obs_frames = extract_user_frames(obs.stderr or "")
                frames.extend(obs_frames)
                side = "old" if obs.version == "base" else "new"
                matches.extend(correlate_frames_to_diff(obs_frames, diff_files, side=side))

            if base_hit and patched_hit:
                status = "incomplete"
            elif base_hit:
                status = "fixed"
            else:
                status = "new"
            # Statement 3.1: without enough evidence the *link* is unknown; the
            # reproduction status still comes from execution on both versions.
            link = "direct" if matches else "unknown"

            finding = serialize_correlation_finding(
                finding_id=f"CORR-{test_id}",
                title=f"diff correlation for {test_id}: link {link}",
                status=status,
                summary=(
                    f"reproduced on {'base' if base_hit else ''}"
                    f"{' and ' if base_hit and patched_hit else ''}{'patched' if patched_hit else ''}; "
                    + (f"{len(matches)} frame(s) fall in changed hunks" if matches
                       else "no crash frame falls in a changed hunk, link unknown")
                ),
                observations=observations,
                matches=matches,
                frames=frames,
                diff_hunks=[
                    {
                        "file": changed.path,
                        "ranges": [hunk.new_range for hunk in changed.hunks],
                    }
                    for changed in diff_files
                ],
                confirmed=True,
                kind="security",
            )
            finding.evidence["link"] = link
            findings.append(finding)

        return findings


def _normalise_path(path: str) -> str:
    text = path.strip()
    if text.startswith("a/") or text.startswith("b/"):
        text = text[2:]
    return text
