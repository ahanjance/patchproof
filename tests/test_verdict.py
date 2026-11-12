from __future__ import annotations

import signal
import unittest

from patchproof.model import (
    BuildResult,
    ExitCode,
    Finding,
    FindingStatus,
    TestObservation,
)
from patchproof.verdict import decide


def build(ok: bool = True, version: str = "base") -> BuildResult:
    return BuildResult(
        version=version,
        variant="release",
        ok=ok,
        command=["cc"],
        exit_code=0 if ok else 1,
        signal=None,
        timed_out=False,
        duration_seconds=0.01,
        log_path="build.log",
        binary_path="/bin/true",
        error="" if ok else "compile failed",
    )


def observation(
    test_id: str = "t",
    kind: str = "security",
    version: str = "base",
    variant: str = "release",
    outcome: str = "crash",
    met: bool = False,
    expectation_met: bool | None = None,
) -> TestObservation:
    if expectation_met is not None:
        met = expectation_met
    return TestObservation(
        test_id=test_id,
        kind=kind,
        version=version,
        variant=variant,
        outcome=outcome,
        expectation_met=met,
        exit_code=0 if outcome == "pass" else None,
        signal=signal.SIGSEGV if outcome == "crash" else None,
        timed_out=outcome == "timeout",
        duration_seconds=0.01,
    )


def finding(
    status: FindingStatus,
    *,
    finding_id: str = "F1",
    confirmed: bool = True,
    refs: list[dict[str, str]] | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        title="test finding",
        status=status,
        confirmed=confirmed,
        evidence={"observations": refs or []},
    )


class VerdictTests(unittest.TestCase):
    def test_pass(self) -> None:
        verdict = decide(
            [build()],
            [observation(outcome="pass", met=True)],
            [],
        )
        self.assertEqual(verdict.exit_code, ExitCode.PASS)
        self.assertEqual(verdict.status, "PASS")

    def test_no_builds_is_build_error(self) -> None:
        verdict = decide([], [], [])
        self.assertEqual(verdict.exit_code, ExitCode.BUILD_OR_CONFIG_ERROR)

    def test_build_failure_is_build_error(self) -> None:
        verdict = decide([build(ok=False)], [], [])
        self.assertEqual(verdict.exit_code, ExitCode.BUILD_OR_CONFIG_ERROR)
        self.assertIn("compile failed", verdict.reasons[0])

    def test_target_execution_error_is_build_error(self) -> None:
        verdict = decide([build()], [observation(outcome="error")], [])
        self.assertEqual(verdict.exit_code, ExitCode.BUILD_OR_CONFIG_ERROR)

    def test_unclassified_crash_is_inconclusive(self) -> None:
        verdict = decide([build()], [observation()], [])
        self.assertEqual(verdict.exit_code, ExitCode.INCONCLUSIVE)
        self.assertTrue(any("unclassified crash" in item for item in verdict.reasons))

    def test_covered_crash_can_be_a_security_finding(self) -> None:
        refs = [
            {"test_id": "t", "version": "base", "variant": "release"},
            {"test_id": "t", "version": "patched", "variant": "release"},
        ]
        observations = [
            observation(version="base"),
            observation(version="patched"),
        ]
        verdict = decide(
            [build(), build(version="patched")],
            observations,
            [finding(FindingStatus.INCOMPLETE, refs=refs)],
        )
        self.assertEqual(verdict.exit_code, ExitCode.VULN_REMAINS_OR_NEW_ISSUE)
        self.assertEqual(verdict.status, "VULN_REMAINS")

    def test_new_issue_status(self) -> None:
        refs = [{"test_id": "t", "version": "patched", "variant": "release"}]
        verdict = decide(
            [build(), build(version="patched")],
            [observation(version="patched")],
            [finding(FindingStatus.NEW, refs=refs)],
        )
        self.assertEqual(verdict.exit_code, ExitCode.VULN_REMAINS_OR_NEW_ISSUE)
        self.assertEqual(verdict.status, "NEW_ISSUE")

    def test_incomplete_and_new(self) -> None:
        refs = [{"test_id": "t", "version": "patched", "variant": "release"}]
        verdict = decide(
            [build(), build(version="patched")],
            [observation(version="patched")],
            [
                finding(FindingStatus.INCOMPLETE, finding_id="A", refs=refs),
                finding(FindingStatus.NEW, finding_id="B", refs=refs),
            ],
        )
        self.assertEqual(verdict.status, "VULN_REMAINS_OR_NEW_ISSUE")

    def test_functional_regression(self) -> None:
        verdict = decide(
            [build(), build(version="patched")],
            [],
            [finding(FindingStatus.FUNCTIONAL_REGRESSION)],
        )
        self.assertEqual(verdict.exit_code, ExitCode.FUNC_REGRESSION)

    def test_regression_beats_security_problem(self) -> None:
        refs = [{"test_id": "t", "version": "patched", "variant": "release"}]
        verdict = decide(
            [build(), build(version="patched")],
            [observation(version="patched")],
            [
                finding(FindingStatus.NEW, finding_id="SEC", refs=refs),
                finding(FindingStatus.FUNCTIONAL_REGRESSION, finding_id="REG"),
            ],
        )
        self.assertEqual(verdict.exit_code, ExitCode.FUNC_REGRESSION)

    def test_inconclusive_beats_regression(self) -> None:
        verdict = decide(
            [build()],
            [],
            [
                finding(FindingStatus.INCONCLUSIVE, finding_id="I"),
                finding(FindingStatus.FUNCTIONAL_REGRESSION, finding_id="REG"),
            ],
        )
        self.assertEqual(verdict.exit_code, ExitCode.INCONCLUSIVE)

    def test_unconfirmed_finding_is_inconclusive(self) -> None:
        verdict = decide(
            [build()],
            [],
            [finding(FindingStatus.INCOMPLETE, confirmed=False)],
        )
        self.assertEqual(verdict.exit_code, ExitCode.INCONCLUSIVE)

    def test_analysis_incomplete_is_inconclusive(self) -> None:
        verdict = decide([build()], [], [], analysis_complete=False)
        self.assertEqual(verdict.exit_code, ExitCode.INCONCLUSIVE)

    def test_fixed_finding_is_pass(self) -> None:
        verdict = decide([build()], [], [finding(FindingStatus.FIXED)])
        self.assertEqual(verdict.exit_code, ExitCode.PASS)

    def test_base_reference_failure_is_inconclusive(self) -> None:
        verdict = decide(
            [build()],
            [observation(kind="functional", outcome="fail", met=False)],
            [],
        )
        self.assertEqual(verdict.exit_code, ExitCode.INCONCLUSIVE)
        self.assertTrue(any("reference expectation" in item for item in verdict.reasons))

    def test_unclassified_crash_beats_regression(self) -> None:
        verdict = decide(
            [build()],
            [observation()],
            [finding(FindingStatus.FUNCTIONAL_REGRESSION)],
        )
        self.assertEqual(verdict.exit_code, ExitCode.INCONCLUSIVE)

    def test_build_error_beats_inconclusive(self) -> None:
        verdict = decide([build(ok=False)], [observation()], [], analysis_complete=False)
        self.assertEqual(verdict.exit_code, ExitCode.BUILD_OR_CONFIG_ERROR)

    def test_timeout_is_reported(self) -> None:
        verdict = decide([build()], [observation(outcome="timeout")], [])
        self.assertEqual(verdict.exit_code, ExitCode.INCONCLUSIVE)
        self.assertTrue(any("unclassified timeout" in item for item in verdict.reasons))


if __name__ == "__main__":
    unittest.main()
