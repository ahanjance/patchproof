
"""Member 4 end-to-end delivery workflow for PatchProof."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from .analyzers.correlation import CorrelationAnalyzer
from .analyzers.crash import CrashAnalyzer
from .config import load_config
from .harden import compare_hardening
from .minimize import minimize_input
from .pipeline import execute
from .regression import register_and_verify_regression
from .repro import create_reproducer_bundle
from .repo import Repo, sha256_file
from .report import write_report


def _safe_name(value: str) -> str:
    result = "".join(
        char if char.isalnum() or char in "_.-" else "_"
        for char in value
    )
    return result.strip("_") or "unknown"


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )


def run_delivery(
    config_path: str | Path,
    *,
    out_root: str | Path = "patchproof-out",
    register_regressions: bool = True,
) -> int:
    config = load_config(config_path)

    report = execute(
        config,
        out_root=out_root,
        keep_worktrees=True,
        analyzers=[
            CrashAnalyzer(),
            CorrelationAnalyzer(),
        ],
        verbose=True,
    )

    run_dir = Path(report.run["out_dir"]).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)

    # Preserve the exact configuration used by this pipeline execution.
    config_snapshot = run_dir / "config-used.toml"
    shutil.copy2(config.path, config_snapshot)

    builds = {
        (item.version, item.variant): item
        for item in report.builds
    }

    worktrees = {
        name: Path(path).resolve()
        for name, path in report.run.get("worktrees", {}).items()
    }

    base_worktree = worktrees.get("base")
    patched_worktree = worktrees.get("patched")

    artifacts: dict[str, Any] = {
        "config_snapshot": str(config_snapshot),
        "reproducers": [],
        "minimizations": [],
        "regression_tests": [],
        "hardening": None,
        "errors": [],
    }

    repo = None

    try:
        # 1. Reproducer bundles and input minimization.
        repo = Repo(config.target.repo)

        problem_observations = [
            obs
            for obs in report.observations
            if obs.kind == "security"
            and obs.outcome in {"crash", "timeout", "error"}
            and obs.argv
        ]

        for obs in problem_observations:
            build_result = builds.get((obs.version, obs.variant))

            if build_result is None or not build_result.ok:
                continue

            worktree = worktrees.get(obs.version)

            if worktree is None or not worktree.is_dir():
                continue

            commit = report.target.get(
                f"{obs.version}_commit", ""
            )

            try:
                bundle = create_reproducer_bundle(
                    config,
                    obs,
                    build_result,
                    commit=commit,
                    worktree=worktree,
                    out_dir=run_dir,
                    replay_count=3,
                )

                artifacts["reproducers"].append({
                    "test_id": obs.test_id,
                    "version": obs.version,
                    "variant": obs.variant,
                    "path": str(bundle),
                })

            except Exception as exc:
                artifacts["errors"].append({
                    "stage": "reproducer",
                    "test_id": obs.test_id,
                    "version": obs.version,
                    "variant": obs.variant,
                    "error": f"{type(exc).__name__}: {exc}",
                })

        # Minimize Base security failures only. Prefer sanitized evidence.
        base_security = [
            obs
            for obs in problem_observations
            if obs.version == "base"
        ]

        selected: dict[str, Any] = {}

        for obs in base_security:
            current = selected.get(obs.test_id)

            if current is None or (
                obs.variant == "sanitized"
                and current.variant != "sanitized"
            ):
                selected[obs.test_id] = obs

        for test_id, obs in selected.items():
            build_result = builds.get(("base", obs.variant))

            if (
                build_result is None
                or not build_result.ok
                or base_worktree is None
            ):
                continue

            test = config.test_by_id(test_id)

            if test.input_mode == "none" or test.input_path is None:
                continue

            minimize_dir = (
                run_dir
                / "minimized"
                / _safe_name(test_id)
                / obs.variant
            )

            try:
                minimized = minimize_input(
                    config,
                    obs,
                    build_result,
                    worktree=base_worktree,
                    out_dir=minimize_dir,
                )

                artifacts["minimizations"].append({
                    "test_id": test_id,
                    "variant": obs.variant,
                    "path": str(minimized),
                })

                # Register only if the same test fails on Base
                # and passes its expected behavior on Patched.
                if not register_regressions:
                    continue

                patched_observation = next(
                    (
                        item
                        for item in report.observations
                        if item.test_id == test_id
                        and item.version == "patched"
                        and item.variant == obs.variant
                    ),
                    None,
                )

                patched_build = builds.get(("patched", obs.variant))

                if (
                    patched_observation is None
                    or patched_observation.outcome != "pass"
                    or not patched_observation.expectation_met
                    or patched_build is None
                    or not patched_build.ok
                    or patched_worktree is None
                ):
                    continue

                try:
                    registration = register_and_verify_regression(
                        config,
                        source_test_id=test_id,
                        minimized_input=minimized,
                        variant=obs.variant,
                        base_build=build_result,
                        patched_build=patched_build,
                        base_worktree=base_worktree,
                        patched_worktree=patched_worktree,
                        out_dir=run_dir / "regression-registration",
                    )

                    artifacts["regression_tests"].append(registration)

                except Exception as exc:
                    artifacts["errors"].append({
                        "stage": "regression-registration",
                        "test_id": test_id,
                        "error": f"{type(exc).__name__}: {exc}",
                    })

            except Exception as exc:
                artifacts["errors"].append({
                    "stage": "minimization",
                    "test_id": test_id,
                    "variant": obs.variant,
                    "error": f"{type(exc).__name__}: {exc}",
                })

        # 2. Compare hardening on release binaries.
        base_release = builds.get(("base", "release"))
        patched_release = builds.get(("patched", "release"))

        if (
            base_release is not None
            and patched_release is not None
            and base_release.ok
            and patched_release.ok
        ):
            try:
                hardening = compare_hardening(
                    base_release.binary_path,
                    patched_release.binary_path,
                    out_dir=run_dir / "hardening",
                )

                report.hardening = hardening
                artifacts["hardening"] = hardening

            except Exception as exc:
                artifacts["errors"].append({
                    "stage": "hardening",
                    "error": f"{type(exc).__name__}: {exc}",
                })

        # 3. Save Member 4 artifacts and final report.
        _save_json(run_dir / "member4-artifacts.json", artifacts)

        report_path, summary_path = write_report(
            report,
            run_dir,
        )

        print(f"\nReport: {report_path}")
        print(f"Summary: {summary_path}")
        print(f"Member 4 artifacts: {run_dir / 'member4-artifacts.json'}")
        print(f"Pipeline verdict: {report.verdict.status}")
        print(f"Exit code: {report.verdict.exit_code}")

        return int(report.verdict.exit_code)

    finally:
        # Worktrees are needed until all post-processing is complete.
        if repo is not None:
            for worktree in worktrees.values():
                try:
                    repo.remove_worktree(worktree)
                except Exception as exc:
                    print(
                        f"WARNING: could not remove worktree "
                        f"{worktree}: {exc}"
                    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the complete PatchProof Member 4 delivery workflow."
    )
    parser.add_argument(
        "config",
        help="Path to the target TOML configuration.",
    )
    parser.add_argument(
        "--out-root",
        default="patchproof-out",
        help="Directory for pipeline outputs.",
    )
    parser.add_argument(
        "--no-register",
        action="store_true",
        help="Do not modify the TOML regression suite.",
    )

    args = parser.parse_args()

    return run_delivery(
        args.config,
        out_root=args.out_root,
        register_regressions=not args.no_register,
    )


if __name__ == "__main__":
    raise SystemExit(main())
