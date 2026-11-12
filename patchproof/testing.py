"""Execute the declared test suite against both versions and build variants."""

from __future__ import annotations

import re
from pathlib import Path

from .config import RunLimits, TestCase
from .model import ExecResult, TestObservation
from .proc import run

_SAFE_ID = re.compile(r"[^A-Za-z0-9_.-]+")


def run_test(
    test: TestCase,
    *,
    binary: str | Path,
    worktree: str | Path,
    version: str,
    variant: str,
    limits: RunLimits,
    variant_env: dict[str, str] | None = None,
    out_dir: str | Path,
) -> TestObservation:
    """Run one test and convert the process result into an observation."""

    artifact_dir = (
        Path(out_dir).resolve()
        / "artifacts"
        / version
        / variant
        / _safe_id.sub("_", test.id)[:80]
    )
    timeout = (
        test.timeout_seconds
        if test.timeout_seconds is not None
        else limits.timeout_seconds
    )
    env = dict(variant_env or {})
    env.update(limits.env)
    if variant == "sanitized":
        env.setdefault("ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0:symbolize=1")
        env.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")

    argv, stdin_bytes, input_error = _build_invocation(
        test, binary=binary, worktree=worktree, artifact_dir=artifact_dir
    )
    if input_error:
        return TestObservation(
            test_id=test.id,
            kind=test.kind,
            version=version,
            variant=variant,
            outcome="error",
            expectation_met=False,
            exit_code=None,
            signal=None,
            timed_out=False,
            duration_seconds=0.0,
            argv=argv,
            failure_reasons=[input_error],
        )

    try:
        result = run(
            argv,
            cwd=worktree,
            stdin_bytes=stdin_bytes,
            timeout=timeout,
            # ASan reserves a huge virtual address range; RLIMIT_AS would kill it.
            memory_mb=None if variant == "sanitized" else limits.memory_mb,
            cpu_seconds=limits.cpu_seconds,
            file_size_mb=limits.file_size_mb,
            env=env,
            artifact_dir=artifact_dir,
        )
    except OSError as exc:
        return TestObservation(
            test_id=test.id,
            kind=test.kind,
            version=version,
            variant=variant,
            outcome="error",
            expectation_met=False,
            exit_code=None,
            signal=None,
            timed_out=False,
            duration_seconds=0.0,
            argv=argv,
            failure_reasons=[f"cannot execute target: {exc}"],
        )

    met, reasons = evaluate(result, test)
    if result.timed_out:
        outcome = "timeout"
    elif result.crashed:
        outcome = "crash"
    elif met:
        outcome = "pass"
    else:
        outcome = "fail"

    return TestObservation(
        test_id=test.id,
        kind=test.kind,
        version=version,
        variant=variant,
        outcome=outcome,
        expectation_met=met,
        exit_code=result.exit_code,
        signal=result.signal,
        timed_out=result.timed_out,
        duration_seconds=result.duration_seconds,
        stdout=result.stdout,
        stderr=result.stderr,
        stdout_path=result.stdout_path,
        stderr_path=result.stderr_path,
        argv=argv,
        failure_reasons=reasons,
    )


def evaluate(result: ExecResult, test: TestCase) -> tuple[bool, list[str]]:
    """Check one execution against the reference expectation in the test case."""

    reasons: list[str] = []
    if result.timed_out:
        reasons.append("execution timed out")
    if result.crashed:
        reasons.append(f"crashed with {result.signal_name}")
    if reasons:
        return False, reasons

    if test.expect_exit is not None and result.exit_code != test.expect_exit:
        reasons.append(f"exit code {result.exit_code}, expected {test.expect_exit}")
    if test.stdout_contains is not None and test.stdout_contains not in result.stdout:
        reasons.append(f"stdout does not contain {test.stdout_contains!r}")
    if test.stdout_regex is not None and not re.search(
        test.stdout_regex, result.stdout
    ):
        reasons.append(f"stdout does not match {test.stdout_regex!r}")
    if (
        test.stderr_contains is not None
        and test.stderr_contains not in result.stderr
    ):
        reasons.append(f"stderr does not contain {test.stderr_contains!r}")
    return not reasons, reasons


def _build_invocation(
    test: TestCase,
    *,
    binary: str | Path,
    worktree: str | Path,
    artifact_dir: Path,
) -> tuple[list[str], bytes | None, str | None]:
    input_text = str(test.input_path) if test.input_path is not None else ""
    substitutions = {
        "{input}": input_text,
        "{repo}": str(Path(worktree).resolve()),
        "{out}": str(artifact_dir.resolve()),
    }
    has_input_placeholder = any(
        "{input}" in arg for arg in test.argv
    )

    argv = [str(Path(binary).resolve())]
    for arg in test.argv:
        for key, value in substitutions.items():
            arg = arg.replace(key, value)
        argv.append(arg)

    stdin_bytes: bytes | None = None
    try:
        if test.input_mode == "stdin":
            assert test.input_path is not None
            stdin_bytes = test.input_path.read_bytes()
        elif test.input_mode in {"file", "argv"} and not has_input_placeholder:
            assert test.input_path is not None
            argv.append(str(test.input_path))
    except OSError as exc:
        return argv, None, f"cannot read test input: {exc}"

    return argv, stdin_bytes, None
