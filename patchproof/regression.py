"""Register minimized inputs as regression tests and verify both versions."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from .config import TestCase
from .model import BuildResult, TestObservation
from .testing import run_test


def register_and_verify_regression(
    config,
    *,
    source_test_id: str,
    minimized_input: str | Path,
    variant: str,
    base_build: BuildResult,
    patched_build: BuildResult,
    base_worktree: str | Path,
    patched_worktree: str | Path,
    out_dir: str | Path,
) -> dict:
    """
    Verify a minimized input against base and patched builds.

    The input is added to the persistent TOML regression suite only if:
      - the base version fails the test;
      - the patched version passes the test.

    Returns a dictionary containing both observations and the new test.
    """

    source_test = config.test_by_id(source_test_id)

    if source_test.input_mode == "none":
        raise ValueError("Cannot create a regression test without an input file.")

    if variant not in config.variants:
        raise ValueError(f"Unknown build variant: {variant}")

    if not base_build.ok or not patched_build.ok:
        raise ValueError("Both base and patched builds must be successful.")

    if base_build.variant != variant or patched_build.variant != variant:
        raise ValueError("Build variants do not match the requested variant.")

    minimized_input = Path(minimized_input).resolve()

    if not minimized_input.is_file():
        raise FileNotFoundError(
            f"Minimized input not found: {minimized_input}"
        )

    if minimized_input.stat().st_size == 0:
        raise ValueError("Minimized input is empty.")

    config_path = Path(config.path).resolve()

    if not config_path.is_file():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    safe_source_id = re.sub(
        r"[^A-Za-z0-9_.-]+", "_", source_test_id
    ).strip("_")

    test_id = f"regression_{safe_source_id}"

    try:
        config.test_by_id(test_id)
    except KeyError:
        pass
    else:
        raise ValueError(f"Regression test already exists: {test_id}")

    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    temporary_input = out_dir / f"{test_id}.bin"
    shutil.copy2(minimized_input, temporary_input)

    regression_test = TestCase(
        id=test_id,
        kind="functional",
        input_mode=source_test.input_mode,
        input_path=temporary_input,
        argv=source_test.argv,
        expect_exit=0,
    )

    build_variant = (
        config.build.sanitized
        if variant == "sanitized"
        else config.build.release
    )

    base_observation = run_test(
        regression_test,
        binary=base_build.binary_path,
        worktree=base_worktree,
        version=base_build.version,
        variant=variant,
        limits=config.limits,
        variant_env=build_variant.env,
        out_dir=out_dir / "base",
    )

    patched_observation = run_test(
        regression_test,
        binary=patched_build.binary_path,
        worktree=patched_worktree,
        version=patched_build.version,
        variant=variant,
        limits=config.limits,
        variant_env=build_variant.env,
        out_dir=out_dir / "patched",
    )

    base_failed = base_observation.outcome in {"fail", "crash"}
    patched_passed = (
        patched_observation.outcome == "pass"
        and patched_observation.expectation_met
    )

    if not base_failed or not patched_passed:
        temporary_input.unlink(missing_ok=True)

        return {
            "registered": False,
            "test_id": test_id,
            "base_observation": base_observation,
            "patched_observation": patched_observation,
            "reason": (
                "Regression test conditions were not met. "
                "The base must fail and the patched version must pass."
            ),
        }

    regression_dir = config_path.parent / "regression_inputs"
    regression_dir.mkdir(parents=True, exist_ok=True)

    permanent_input = regression_dir / f"{test_id}.bin"

    if permanent_input.exists():
        raise FileExistsError(
            f"Regression input already exists: {permanent_input}"
        )

    shutil.copy2(temporary_input, permanent_input)

    test_block = [
        "",
        "[[tests]]",
        f"id = {json.dumps(test_id)}",
        'kind = "functional"',
        f"input_mode = {json.dumps(source_test.input_mode)}",
        f"input = {json.dumps(str(permanent_input))}",
        "expect_exit = 0",
    ]

    if source_test.argv:
        test_block.append(
            f"argv = {json.dumps(list(source_test.argv))}"
        )

    try:
        with config_path.open("a", encoding="utf-8", newline="\n") as file:
            file.write("\n".join(test_block) + "\n")
    except OSError:
        permanent_input.unlink(missing_ok=True)
        raise

    temporary_input.unlink(missing_ok=True)

    return {
        "registered": True,
        "test_id": test_id,
        "input_path": str(permanent_input),
        "base_observation": base_observation,
        "patched_observation": patched_observation,
        "reason": "Base failed and patched version passed.",
    }