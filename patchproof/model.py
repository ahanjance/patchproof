"""Data model shared by the runner, analyzers and report writer.

The model deliberately contains no analysis logic.  Parts 2 and 3 attach
:class:`Finding` objects to the observations produced here; the verdict engine
turns those findings into the exit codes required by the project statement.
"""

from __future__ import annotations

import signal as _signal
from dataclasses import dataclass, field
from enum import Enum, IntEnum


class ExitCode(IntEnum):
    """Exit codes mandated by the project statement."""

    PASS = 0
    VULN_REMAINS_OR_NEW_ISSUE = 10
    FUNC_REGRESSION = 20
    BUILD_OR_CONFIG_ERROR = 30
    INCONCLUSIVE = 40


class FindingStatus(str, Enum):
    """Patch-to-finding correlation status."""

    FIXED = "fixed"
    INCOMPLETE = "incomplete"
    NEW = "new"
    FUNCTIONAL_REGRESSION = "functional_regression"
    INCONCLUSIVE = "inconclusive"


@dataclass
class ExecResult:
    """Raw result of one process execution."""

    argv: list[str]
    exit_code: int | None
    signal: int | None
    timed_out: bool
    duration_seconds: float
    stdout: str
    stderr: str
    stdout_path: str = ""
    stderr_path: str = ""

    @property
    def signal_name(self) -> str | None:
        if self.signal is None:
            return None
        try:
            return _signal.Signals(self.signal).name
        except ValueError:  # pragma: no cover - platform specific signal
            return f"SIG{self.signal}"

    @property
    def crashed(self) -> bool:
        return self.signal is not None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.crashed


@dataclass
class TestObservation:
    """One (test, target version, build variant) execution."""

    test_id: str
    kind: str
    version: str
    variant: str
    outcome: str  # pass | fail | crash | timeout | error
    expectation_met: bool
    exit_code: int | None
    signal: int | None
    timed_out: bool
    duration_seconds: float
    stdout: str = ""
    stderr: str = ""
    stdout_path: str = ""
    stderr_path: str = ""
    argv: list[str] = field(default_factory=list)
    failure_reasons: list[str] = field(default_factory=list)

    @property
    def signal_name(self) -> str | None:
        if self.signal is None:
            return None
        try:
            return _signal.Signals(self.signal).name
        except ValueError:  # pragma: no cover
            return f"SIG{self.signal}"

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.test_id, self.version, self.variant)

    @property
    def is_problem_execution(self) -> bool:
        return self.outcome in {"crash", "timeout", "error"}


@dataclass
class Finding:
    """A correlated finding produced by an analyzer or by the core pipeline."""

    id: str
    title: str
    status: FindingStatus
    kind: str = "security"  # security | functional
    confirmed: bool = True
    summary: str = ""
    evidence: dict = field(default_factory=dict)
    analyzer: str = "core"


@dataclass
class BuildResult:
    """Result of building one (version, variant) pair."""

    version: str
    variant: str
    ok: bool
    command: list[str]
    exit_code: int | None
    signal: int | None
    timed_out: bool
    duration_seconds: float
    log_path: str
    binary_path: str
    binary_sha256: str = ""
    error: str = ""

    @property
    def signal_name(self) -> str | None:
        if self.signal is None:
            return None
        try:
            return _signal.Signals(self.signal).name
        except ValueError:  # pragma: no cover
            return f"SIG{self.signal}"


@dataclass
class Verdict:
    """The single exit decision plus human-readable reasons."""

    exit_code: int
    status: str
    reasons: list[str] = field(default_factory=list)


@dataclass
class Report:
    """Everything persisted as ``report.json`` for one run."""

    schema_version: str
    tool: dict
    run: dict
    target: dict
    config_path: str
    config_sha256: str
    builds: list[BuildResult]
    observations: list[TestObservation]
    findings: list[Finding]
    verdict: Verdict
    hardening: dict | None = None
    error: str | None = None
