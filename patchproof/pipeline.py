"""End-to-end orchestration: git versions -> builds -> tests -> verdict."""

from __future__ import annotations

import platform
import secrets
import sys
import time
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from . import SCHEMA_VERSION, __version__
from .analysis import AnalysisContext, Analyzer
from .build import build
from .config import Config
from .errors import PatchProofError
from .model import (
    BuildResult,
    Finding,
    FindingStatus,
    Report,
    TestObservation,
    Verdict,
)
from .repo import Repo, sha256_file, sha256_text
from .testing import run_test
from .verdict import decide


def execute(
    config: Config,
    *,
    out_root: str | Path = "patchproof-out",
    keep_worktrees: bool = False,
    analyzers: Sequence[Analyzer] = (),
    verbose: bool = False,
) -> Report:
    """Run the full pipeline and always return a report (never exit here)."""

    run_id = _new_run_id()
    run_dir = Path(out_root).expanduser().resolve() / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    started_at = _utc_now()
    started = time.monotonic()

    base_commit = ""
    patched_commit = ""
    changed_files: list[str] = []
    diff = ""
    worktrees: dict[str, Path] = {}
    builds: list[BuildResult] = []
    observations: list[TestObservation] = []
    findings: list[Finding] = []
    analysis_complete = True
    error: str | None = None
    verdict: Verdict | None = None
    repo: Repo | None = None

    try:
        repo = Repo(config.target.repo)
        base_commit = repo.resolve(config.target.base_ref)
        patched_commit = repo.resolve(config.target.patched_ref)
        diff = repo.diff(base_commit, patched_commit)
        changed_files = repo.changed_files(base_commit, patched_commit)
        (run_dir / "patch.diff").write_text(diff, encoding="utf-8")

        for version, commit in (("base", base_commit), ("patched", patched_commit)):
            worktrees[version] = repo.add_worktree(
                commit, run_dir / "worktrees" / version
            )

        for version in ("base", "patched"):
            for variant in config.variants:
                _log(verbose, f"build {version}/{variant}")
                result = build(
                    worktree=worktrees[version],
                    version=version,
                    variant=variant,
                    build_config=config.build,
                    out_dir=run_dir,
                )
                builds.append(result)
                if not result.ok:
                    _log(verbose, f"  failed: {result.error}")

        if all(result.ok for result in builds):
            by_build = {(item.version, item.variant): item for item in builds}
            for test in config.tests:
                for version in ("base", "patched"):
                    for variant in config.variants:
                        build_result = by_build[(version, variant)]
                        variant_env = (
                            config.build.sanitized.env
                            if variant == "sanitized" and config.build.sanitized
                            else config.build.release.env
                        )
                        _log(
                            verbose,
                            f"test {test.id} {version}/{variant}",
                        )
                        observation = run_test(
                            test,
                            binary=build_result.binary_path,
                            worktree=worktrees[version],
                            version=version,
                            variant=variant,
                            limits=config.limits,
                            variant_env=variant_env,
                            out_dir=run_dir,
                        )
                        observations.append(observation)

            findings.extend(_core_findings(config, observations))

            if analyzers:
                context = AnalysisContext(
                    config=config,
                    base_worktree=worktrees["base"],
                    patched_worktree=worktrees["patched"],
                    diff=diff,
                    observations=observations,
                    out_dir=run_dir,
                )
                for analyzer in analyzers:
                    name = getattr(analyzer, "name", type(analyzer).__name__)
                    try:
                        findings.extend(analyzer.analyze(context))
                        _log(verbose, f"analyzer {name}: ok")
                    except Exception as exc:  # an analyzer bug must not fake a pass
                        analysis_complete = False
                        findings.append(
                            Finding(
                                id=f"ANALYZER-{name}",
                                title=f"analyzer {name} failed",
                                status=FindingStatus.INCONCLUSIVE,
                                confirmed=False,
                                summary=f"{type(exc).__name__}: {exc}",
                                analyzer=name,
                            )
                        )
                        _log(verbose, f"analyzer {name}: {type(exc).__name__}: {exc}")

            verdict = decide(
                builds,
                observations,
                findings,
                analysis_complete=analysis_complete,
            )
        else:
            verdict = decide(builds, [], [], analysis_complete=True)

    except (PatchProofError, OSError, ValueError) as exc:
        error = f"{type(exc).__name__}: {exc}"
        verdict = Verdict(
            exit_code=30,
            status="BUILD_OR_CONFIG_ERROR",
            reasons=[error],
        )
    except Exception as exc:  # pragma: no cover - defensive
        error = f"{type(exc).__name__}: {exc}"
        verdict = Verdict(
            exit_code=30,
            status="BUILD_OR_CONFIG_ERROR",
            reasons=[f"internal error: {error}"],
        )
    finally:
        if repo is not None and not keep_worktrees:
            for path in worktrees.values():
                try:
                    repo.remove_worktree(path)
                except PatchProofError:
                    pass

    if verdict is None:  # pragma: no cover - unreachable by construction
        verdict = decide(builds, observations, findings)

    finished_at = _utc_now()
    duration = round(time.monotonic() - started, 3)

    return Report(
        schema_version=SCHEMA_VERSION,
        tool={
            "name": "patchproof",
            "version": __version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        run={
            "id": run_id,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_seconds": duration,
            "out_dir": str(run_dir),
            "keep_worktrees": keep_worktrees,
            "worktrees": (
                {name: str(path) for name, path in worktrees.items()}
                if keep_worktrees
                else {}
            ),
        },
        target={
            "name": config.target.name,
            "repo": str(config.target.repo),
            "base_ref": config.target.base_ref,
            "patched_ref": config.target.patched_ref,
            "base_commit": base_commit,
            "patched_commit": patched_commit,
            "changed_files": changed_files,
            "diff_path": str(run_dir / "patch.diff"),
            "diff_sha256": sha256_text(diff),
        },
        config_path=str(config.path),
        config_sha256=sha256_file(config.path),
        builds=builds,
        observations=observations,
        findings=findings,
        hardening=None,
        verdict=verdict,
        error=error,
    )


def _core_findings(
    config: Config, observations: Sequence[TestObservation]
) -> list[Finding]:
    """Regression detection that does not need an analyzer.

    A valid/boundary test that met its reference expectation on the base
    release binary but fails on the patched release binary is objective
    evidence of a functional regression (exit code 20).
    """

    lookup = {(obs.test_id, obs.version, obs.variant): obs for obs in observations}
    findings: list[Finding] = []
    for test in config.tests:
        if test.kind not in {"functional", "boundary"}:
            continue
        base = lookup.get((test.id, "base", "release"))
        patched = lookup.get((test.id, "patched", "release"))
        if base is None or patched is None:
            continue
        if not base.expectation_met or patched.expectation_met:
            continue
        findings.append(
            Finding(
                id=f"REG-{test.id}",
                title=f"functional regression on {test.id}",
                status=FindingStatus.FUNCTIONAL_REGRESSION,
                kind="functional",
                confirmed=True,
                summary=(
                    "reference expectation passed on base and failed on patched: "
                    + "; ".join(patched.failure_reasons)
                ),
                evidence={
                    "observations": [_ref(base), _ref(patched)],
                    "reasons": patched.failure_reasons,
                },
                analyzer="core",
            )
        )
    return findings


def _ref(observation: TestObservation) -> dict[str, str]:
    return {
        "test_id": observation.test_id,
        "version": observation.version,
        "variant": observation.variant,
    }


def _new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _log(verbose: bool, message: str) -> None:
    if verbose:
        print(f"[patchproof] {message}", file=sys.stderr, flush=True)
