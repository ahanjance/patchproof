"""Part 2: crash classification from execution evidence.

Every observation's stderr is scanned (not only crashes: UBSan with
``halt_on_error`` exits with a plain non-zero code).  Each problem execution is
reduced to three separate facts, as the project statement requires:

* error type    - what went wrong (heap-buffer-overflow, null-dereference, ...)
* mechanism     - who noticed (asan, ubsan, stack-canary, fortify, glibc-malloc,
                  os-signal, timeout, resource-limit)
* termination   - exit code / signal / timeout plus stdout/stderr artifacts

Executions are grouped by a stable signature (error type + top user frames,
never the input name or addresses) and the group's presence on base/patched
decides the status: both -> INCOMPLETE, base only -> FIXED, patched only -> NEW.

Only sanitizer, canary, fortify or allocator reports count as confirmed
evidence.  A bare signal, a timeout or a resource limit is reported but left
INCONCLUSIVE: "not every stop is an exploitable vulnerability".
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..analysis import AnalysisContext
from ..model import Finding, FindingStatus, TestObservation

_ASAN = re.compile(r"ERROR: AddressSanitizer: (attempting double-free|[\w-]+)(?: on (?:unknown )?address (0x[0-9a-fA-F]+))?")
_ASAN_ACCESS = re.compile(r"^(READ|WRITE) of size (\d+)", re.M)
_ASAN_SEGV_ACCESS = re.compile(r"caused by a (READ|WRITE) memory access")
_UBSAN = re.compile(r"^(\S+?:\d+(?::\d+)?): runtime error: (.+)$", re.M)
_FRAME = re.compile(r"^\s*#(\d+) 0x[0-9a-fA-F]+ in (\S+)\s*(.*)$")

# glibc / binary-protection messages seen in release builds.
_RUNTIME_CHECKS = [
    (re.compile(r"\*\*\* stack smashing detected \*\*\*"), "stack-smashing", "stack-canary"),
    (re.compile(r"\*\*\* buffer overflow detected \*\*\*"), "buffer-overflow", "fortify"),
    (re.compile(r"double free detected|free\(\): double free"), "double-free", "glibc-malloc"),
    (re.compile(r"^(?:\w+\(\): (?:invalid|corrupted)|corrupted (?:size|double-linked))", re.M), "heap-corruption", "glibc-malloc"),
]

_ASAN_TYPES = {
    "attempting double-free": "double-free",
    "heap-use-after-free": "use-after-free",
    "FPE": "division-by-zero",
    "attempting": "invalid-free",
}

_UBSAN_TYPES = [
    ("division by zero", "division-by-zero"),
    ("null pointer", "null-dereference"),
    ("out of bounds", "out-of-bounds-index"),
    ("signed integer overflow", "integer-overflow"),
    ("shift", "invalid-shift"),
    ("misaligned address", "misaligned-access"),
    ("pointer overflow", "pointer-overflow"),
]

_SIGNAL_TYPES = {
    "SIGSEGV": "invalid-memory-access",
    "SIGBUS": "bus-error",
    "SIGFPE": "arithmetic-error",
    "SIGILL": "illegal-instruction",
    "SIGABRT": "abort",
}
_RESOURCE_SIGNALS = {"SIGXCPU", "SIGXFSZ"}

_RUNTIME_FRAME_PREFIXES = (
    "__asan", "__interceptor", "___interceptor", "__sanitizer", "__ubsan",
    "__libc_start", "_start", "__GI_", "__pthread_kill", "raise", "abort",
    "__stack_chk_fail", "__fortify_fail", "__chk_fail",
)
_TOP_FRAMES = 3


@dataclass
class Classification:
    error_type: str
    mechanism: str
    confirmed: bool
    frames: list[str] = field(default_factory=list)
    location: str = ""
    access: str = ""
    excerpt: str = ""

    @property
    def signature(self) -> str:
        return "|".join([self.error_type, *self.frames[:_TOP_FRAMES]])


def classify_stderr(stderr: str) -> Classification | None:
    """Classify the first sanitizer or runtime-check report in ``stderr``."""

    match = _ASAN.search(stderr)
    if match:
        raw, address = match.group(1), match.group(2)
        error_type = _ASAN_TYPES.get(raw, raw)
        if raw == "SEGV":
            near_zero = address is not None and int(address, 16) < 0x1000
            error_type = "null-dereference" if near_zero else "invalid-memory-access"
        report = stderr[match.start():]
        sized = _ASAN_ACCESS.search(report)
        segv = _ASAN_SEGV_ACCESS.search(report)
        access = f"{sized[1]} of size {sized[2]}" if sized else (segv[1] if segv else "")
        frames, location = _frames(report)
        return Classification(
            error_type=error_type,
            mechanism="asan",
            confirmed=True,
            frames=frames,
            location=location,
            access=access,
            excerpt=_excerpt(report),
        )

    match = _UBSAN.search(stderr)
    if match:
        message = match.group(2)
        error_type = next(
            (name for needle, name in _UBSAN_TYPES if needle in message),
            "undefined-behavior",
        )
        report = stderr[match.start():]
        frames, _ = _frames(report)
        return Classification(
            error_type=error_type,
            mechanism="ubsan",
            confirmed=True,
            frames=frames,
            location=match.group(1),
            excerpt=_excerpt(report),
        )
    return None


def classify_abort(stderr: str) -> Classification | None:
    """Classify a SIGABRT raised by a canary, FORTIFY or glibc malloc check."""

    for pattern, error_type, mechanism in _RUNTIME_CHECKS:
        match = pattern.search(stderr)
        if match:
            return Classification(
                error_type=error_type,
                mechanism=mechanism,
                confirmed=True,
                excerpt=_excerpt(stderr[match.start():]),
            )
    return None


def classify(observation: TestObservation, stderr: str) -> Classification | None:
    """Classify one execution, or ``None`` when nothing abnormal happened."""

    found = classify_stderr(stderr)
    if found:
        return found
    if observation.timed_out:
        return Classification("timeout", "timeout", confirmed=False)
    name = observation.signal_name
    if name is None:
        return None
    # Program output could mimic these messages; only trust them with the abort.
    if name == "SIGABRT" and (found := classify_abort(stderr)):
        return found
    if name in _RESOURCE_SIGNALS:
        return Classification("resource-limit", "resource-limit", confirmed=False)
    return Classification(
        _SIGNAL_TYPES.get(name, f"signal-{name}"), "os-signal", confirmed=False
    )


class CrashAnalyzer:
    name = "crash"

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        classified: dict[tuple[str, str, str], Classification] = {}
        for obs in context.observations:
            found = classify(obs, _full_stderr(obs))
            if found:
                classified[obs.key] = found

        # A release-build stop belongs to the sanitizer finding of the same
        # test and version: same input, corresponding build, richer evidence.
        groups: dict[str, list[tuple[TestObservation, Classification]]] = {}
        by_key = {obs.key: obs for obs in context.observations}
        for key, found in classified.items():
            obs = by_key[key]
            primary = found
            twin = classified.get((obs.test_id, obs.version, "sanitized"))
            if obs.variant == "release" and twin and twin.confirmed:
                primary = twin
            signature = primary.signature if primary.confirmed else f"{found.signature}|{obs.test_id}|{obs.version}"
            groups.setdefault(signature, []).append((obs, found))

        findings = [_finding(signature, members) for signature, members in groups.items()]
        findings.extend(_base_reproduction(context.observations, findings))
        return findings


def _finding(signature: str, members: list[tuple[TestObservation, Classification]]) -> Finding:
    confirmed_members = [found for _, found in members if found.confirmed]
    lead = confirmed_members[0] if confirmed_members else members[0][1]
    versions = {obs.version for obs, _ in members}
    if not confirmed_members:
        status = FindingStatus.INCONCLUSIVE
    elif versions == {"base", "patched"}:
        status = FindingStatus.INCOMPLETE
    elif versions == {"base"}:
        status = FindingStatus.FIXED
    else:
        status = FindingStatus.NEW

    where = lead.frames[0] if lead.frames else (lead.location or "unknown location")
    digest = hashlib.sha1(signature.encode()).hexdigest()[:10]
    return Finding(
        id=f"SEC-{digest}",
        title=f"{lead.error_type} in {where}",
        status=status,
        kind="security",
        confirmed=bool(confirmed_members),
        summary=(
            f"{lead.error_type} detected by {lead.mechanism}; seen on "
            f"{', '.join(sorted(versions))}"
            + ("" if confirmed_members else "; no sanitizer/canary evidence, so not confirmed")
        ),
        evidence={
            "observations": [
                {"test_id": obs.test_id, "version": obs.version, "variant": obs.variant}
                for obs, _ in members
            ],
            "signature": signature,
            "error_type": lead.error_type,
            "mechanisms": sorted({found.mechanism for _, found in members}),
            "access": lead.access,
            "frames": lead.frames,
            "location": lead.location,
            "report_excerpt": lead.excerpt,
            "executions": [_execution(obs, found) for obs, found in members],
        },
        analyzer=CrashAnalyzer.name,
    )


def _base_reproduction(observations: list[TestObservation], findings: list[Finding]) -> list[Finding]:
    """PASS needs the target bug reproduced on base (statement 3.5, code 40)."""

    if not any(obs.kind == "security" for obs in observations):
        return []
    security_tests = {obs.test_id for obs in observations if obs.kind == "security"}
    for finding in findings:
        if not finding.confirmed:
            continue
        for ref in finding.evidence["observations"]:
            if ref["version"] == "base" and ref["test_id"] in security_tests:
                return []
    return [
        Finding(
            id="SEC-base-not-reproduced",
            title="target bug was not reproduced on the base version",
            status=FindingStatus.INCONCLUSIVE,
            confirmed=False,
            summary="no security test produced a confirmed error on base",
            evidence={"observations": [], "security_tests": sorted(security_tests)},
            analyzer=CrashAnalyzer.name,
        )
    ]


def _execution(obs: TestObservation, found: Classification) -> dict:
    return {
        "test_id": obs.test_id,
        "kind": obs.kind,
        "version": obs.version,
        "variant": obs.variant,
        "error_type": found.error_type,
        "mechanism": found.mechanism,
        "confirmed": found.confirmed,
        "termination": {
            "exit_code": obs.exit_code,
            "signal": obs.signal_name,
            "timed_out": obs.timed_out,
            "stdout_path": obs.stdout_path,
            "stderr_path": obs.stderr_path,
        },
    }


def _frames(report: str) -> tuple[list[str], str]:
    """User frames of the first stack in ``report`` and the top frame's location."""

    frames: list[str] = []
    location = ""
    started = False
    for line in report.splitlines():
        match = _FRAME.match(line)
        if not match:
            if started:
                break  # end of the error stack; "freed by"/"allocated by" follow
            continue
        started = True
        function, where = match.group(2), match.group(3)
        if function.startswith(_RUNTIME_FRAME_PREFIXES) or "libasan" in where or "libubsan" in where:
            continue
        if not frames:
            location = where
        frames.append(function)
    return frames, location


def _excerpt(report: str, lines: int = 40) -> str:
    return "\n".join(report.splitlines()[:lines])


def _full_stderr(obs: TestObservation) -> str:
    # The observation keeps a 32 KiB preview; the artifact has the whole report.
    if obs.stderr_path:
        try:
            return Path(obs.stderr_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    return obs.stderr
