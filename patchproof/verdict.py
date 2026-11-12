"""Exit-code aggregation.

The project statement fixes both the codes and their priority:

    40 (inconclusive) > 20 (functional regression) > 10 (security) >
    30 (build/config error) > 0 (pass)

Build/tool errors are returned before the priority chain because the run never
produced trustworthy evidence.
"""

from __future__ import annotations

from collections.abc import Sequence

from .model import (
    BuildResult,
    ExitCode,
    Finding,
    FindingStatus,
    TestObservation,
    Verdict,
)


def decide(
    builds: Sequence[BuildResult],
    observations: Sequence[TestObservation],
    findings: Sequence[Finding],
    *,
    analysis_complete: bool = True,
) -> Verdict:
    if not builds:
        return Verdict(
            ExitCode.BUILD_OR_CONFIG_ERROR,
            "BUILD_OR_CONFIG_ERROR",
            ["no build results were produced"],
        )

    failed_builds = [build for build in builds if not build.ok]
    if failed_builds:
        return Verdict(
            ExitCode.BUILD_OR_CONFIG_ERROR,
            "BUILD_OR_CONFIG_ERROR",
            [
                f"{build.version}/{build.variant}: {build.error or 'build failed'}"
                for build in failed_builds
            ],
        )

    errored = [obs for obs in observations if obs.outcome == "error"]
    if errored:
        return Verdict(
            ExitCode.BUILD_OR_CONFIG_ERROR,
            "BUILD_OR_CONFIG_ERROR",
            [
                f"{obs.test_id} ({obs.version}/{obs.variant}): "
                f"{'; '.join(obs.failure_reasons) or 'could not execute'}"
                for obs in errored
            ],
        )

    inconclusive_reasons: list[str] = []
    if not analysis_complete:
        inconclusive_reasons.append("mandatory analysis did not complete")

    for finding in findings:
        if finding.status == FindingStatus.INCONCLUSIVE or not finding.confirmed:
            inconclusive_reasons.append(
                f"finding {finding.id} is inconclusive: {finding.title}"
            )

    # The base version must satisfy valid/boundary expectations; otherwise the
    # reference test itself is wrong and no regression can be claimed.
    for obs in observations:
        if (
            obs.kind in {"functional", "boundary"}
            and obs.version == "base"
            and obs.variant == "release"
            and not obs.expectation_met
        ):
            inconclusive_reasons.append(
                f"reference expectation failed on base: {obs.test_id} "
                f"({'; '.join(obs.failure_reasons) or 'unmet'})"
            )

    covered = _covered_observations(findings)
    for obs in observations:
        if obs.outcome in {"crash", "timeout"} and obs.key not in covered:
            inconclusive_reasons.append(
                f"unclassified {obs.outcome} not linked to a finding: "
                f"{obs.test_id} ({obs.version}/{obs.variant})"
            )

    regressions = [
        finding
        for finding in findings
        if finding.confirmed
        and finding.status == FindingStatus.FUNCTIONAL_REGRESSION
    ]
    security_problems = [
        finding
        for finding in findings
        if finding.confirmed
        and finding.status in {FindingStatus.INCOMPLETE, FindingStatus.NEW}
    ]

    if inconclusive_reasons:
        return Verdict(
            ExitCode.INCONCLUSIVE,
            "INCONCLUSIVE",
            _dedupe(inconclusive_reasons),
        )

    if regressions:
        return Verdict(
            ExitCode.FUNC_REGRESSION,
            "FUNC_REGRESSION",
            [
                f"{finding.id}: {finding.title}"
                for finding in regressions
            ],
        )

    if security_problems:
        has_incomplete = any(
            finding.status == FindingStatus.INCOMPLETE
            for finding in security_problems
        )
        has_new = any(
            finding.status == FindingStatus.NEW for finding in security_problems
        )
        if has_incomplete and has_new:
            status = "VULN_REMAINS_OR_NEW_ISSUE"
        elif has_incomplete:
            status = "VULN_REMAINS"
        else:
            status = "NEW_ISSUE"
        return Verdict(
            ExitCode.VULN_REMAINS_OR_NEW_ISSUE,
            status,
            [f"{finding.id}: {finding.title}" for finding in security_problems],
        )

    return Verdict(
        ExitCode.PASS,
        "PASS",
        ["all builds succeeded", "all mandatory checks completed"],
    )


def _covered_observations(findings: Sequence[Finding]) -> set[tuple[str, str, str]]:
    covered: set[tuple[str, str, str]] = set()
    for finding in findings:
        refs = finding.evidence.get("observations", [])
        if not isinstance(refs, list):
            continue
        for ref in refs:
            if isinstance(ref, dict):
                test_id = ref.get("test_id")
                version = ref.get("version")
                variant = ref.get("variant")
            elif isinstance(ref, (list, tuple)) and len(ref) == 3:
                test_id, version, variant = ref
            else:
                continue
            if all(isinstance(item, str) for item in (test_id, version, variant)):
                covered.add((test_id, version, variant))
    return covered


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
