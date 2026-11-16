"""Minimize reproducer inputs while preserving the original failure signature."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

from .model import BuildResult, TestObservation
from .proc import run


def _failure_signature(
    exit_code: int | None,
    signal: int | None,
    timed_out: bool,
    stdout: str,
    stderr: str,
) -> tuple:
    """Extract a stable failure signature, ignoring memory addresses."""

    output = f"{stderr}\n{stdout}"

    sanitizer = re.search(
        r"(ERROR: AddressSanitizer:.*|runtime error:.*|"
        r"UndefinedBehaviorSanitizer:.*|SUMMARY: .*Sanitizer:.*)",
        output,
    )

    frames = re.findall(
        r"^\s*#\d+\s+.*?(?:in\s+.+?)?(?: at | )([^()\n]+:\d+)(?:\s|$)",
        output,
        re.MULTILINE,
    )

    if sanitizer:
        return (
            "sanitizer",
            sanitizer.group(1).strip(),
            frames[:3],
        )

    if signal is not None:
        return ("signal", signal)

    if timed_out:
        return ("timeout",)

    return ("exit", exit_code)


def _build_command(
    test,
    binary: Path,
    input_path: Path | None,
) -> tuple[list[str], bytes | None]:
    """Build the command using the same input conventions as the test runner."""

    argv = [str(binary), *test.argv]
    stdin_bytes = None

    if test.input_mode == "stdin":
        if input_path is not None:
            stdin_bytes = input_path.read_bytes()

    elif test.input_mode in {"file", "argv"}:
        if input_path is None:
            raise ValueError("This test requires an input file.")

        replaced = False
        for index, arg in enumerate(argv):
            if "{input}" in arg:
                argv[index] = arg.replace("{input}", str(input_path))
                replaced = True

        if not replaced:
            argv.append(str(input_path))

    elif test.input_mode != "none":
        raise ValueError(f"Unsupported input mode: {test.input_mode}")

    return argv, stdin_bytes


def minimize_input(
    config,
    observation: TestObservation,
    build_result: BuildResult,
    *,
    worktree: str | Path,
    out_dir: str | Path,
) -> Path:
    """
    Minimize a failing test input using byte-level ddmin.

    Returns the path to minimized-input.bin.
    The original input is preserved as original-input.bin.
    """

    worktree = Path(worktree).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not build_result.ok or not build_result.binary_path:
        raise ValueError("Cannot minimize input: build result is not successful.")

    if observation.exit_code == 0 and observation.signal is None and not observation.timed_out:
        raise ValueError("Cannot minimize input: observation does not indicate a failure.")

    test = config.test_by_id(observation.test_id)

    if test.input_mode == "none" or not test.input_path:
        raise ValueError("This test does not have a minimizable input file.")

    source_input = Path(test.input_path)
    if not source_input.is_absolute():
        source_input = worktree / source_input

    source_input = source_input.resolve()
    if not source_input.is_file():
        raise FileNotFoundError(f"Input file not found: {source_input}")

    original_data = source_input.read_bytes()
    if not original_data:
        raise ValueError("Input file is empty; nothing to minimize.")

    original_copy = out_dir / "original-input.bin"
    minimized_path = out_dir / "minimized-input.bin"
    candidate_path = out_dir / ".minimize-candidate.bin"
    replay_dir = out_dir / "minimize-replays"

    shutil.copy2(source_input, original_copy)

    binary = Path(build_result.binary_path).resolve()
    if not binary.is_file():
        raise FileNotFoundError(f"Binary not found: {binary}")

    variant = next(
        (item for item in config.build.variants if item.name == observation.variant),
        None,
    )
    if variant is None:
        raise ValueError(f"Build variant not found: {observation.variant}")

    env = dict(variant.env)
    env.update(config.limits.env)

    if observation.variant == "sanitized":
        env.setdefault("ASAN_OPTIONS", "detect_leaks=0:abort_on_error=1")
        env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1")

    timeout = test.timeout_seconds or config.limits.timeout_seconds

    expected_signature = _failure_signature(
        observation.exit_code,
        observation.signal,
        observation.timed_out,
        observation.stdout,
        observation.stderr,
    )

    replay_number = 0

    def reproduces(data: bytes) -> bool:
        nonlocal replay_number
        replay_number += 1

        candidate_path.write_bytes(data)

        argv, stdin_bytes = _build_command(
            test,
            binary,
            candidate_path,
        )

        result = run(
            argv,
            cwd=worktree,
            stdin_bytes=stdin_bytes,
            timeout=timeout,
            memory_mb=config.limits.memory_mb,
            cpu_seconds=config.limits.cpu_seconds,
            file_size_mb=config.limits.file_size_mb,
            env=env,
            artifact_dir=replay_dir / f"attempt-{replay_number:04d}",
        )

        actual_signature = _failure_signature(
            result.exit_code,
            result.signal,
            result.timed_out,
            result.stdout,
            result.stderr,
        )

        return actual_signature == expected_signature

    if not reproduces(original_data):
        candidate_path.unlink(missing_ok=True)
        raise RuntimeError(
            "The original input did not reproduce the same failure signature."
        )

    # Classic ddmin: repeatedly remove chunks while preserving the failure.
    current = original_data
    granularity = 2

    while len(current) >= 2:
        chunk_size = (len(current) + granularity - 1) // granularity
        reduced = False

        for start in range(0, len(current), chunk_size):
            candidate = current[:start] + current[start + chunk_size:]

            if not candidate:
                continue

            if reproduces(candidate):
                current = candidate
                granularity = max(granularity - 1, 2)
                reduced = True
                break

        if reduced:
            continue

        if granularity >= len(current):
            break

        granularity = min(granularity * 2, len(current))

    minimized_path.write_bytes(current)
    candidate_path.unlink(missing_ok=True)

    metadata = {
        "test_id": observation.test_id,
        "version": observation.version,
        "variant": observation.variant,
        "original_size": len(original_data),
        "minimized_size": len(current),
        "reduction_bytes": len(original_data) - len(current),
        "reduction_percent": round(
            (1 - len(current) / len(original_data)) * 100, 2
        ),
        "original_sha256": hashlib.sha256(original_data).hexdigest(),
        "minimized_sha256": hashlib.sha256(current).hexdigest(),
        "failure_signature": list(expected_signature),
        "replay_attempts": replay_number,
    }

    (out_dir / "minimize-metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    return minimized_path
