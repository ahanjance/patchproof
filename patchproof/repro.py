"""Create reproducible bundles for observed PatchProof executions."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from .config import Config
from .model import BuildResult, TestObservation
from .proc import run
from .repo import sha256_file


_ENV_ALLOWLIST = (
    "PATH",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LANG",
    "LC_ALL",
    "ASAN_OPTIONS",
    "UBSAN_OPTIONS",
)
_SECRET_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH")
_SANITIZER_ERROR = re.compile(
    r"(?:ERROR:\s*AddressSanitizer:\s*|runtime error:\s*)([^\n]+)"
)
_STACK_FRAME = re.compile(
    r"^\s*#\d+\s+(?:0x[0-9a-fA-F]+\s+in\s+)?(.+?)\s*$",
    re.MULTILINE,
)


def create_reproducer_bundle(
    config: Config,
    observation: TestObservation,
    build_result: BuildResult,
    *,
    commit: str,
    worktree: str | Path,
    out_dir: str | Path,
    replay_count: int = 3,
) -> Path:
    """Preserve an execution and replay it at least three times.

    The bundle contains the original input, the exact executable, hashes,
    commit, build/run settings, commands, relevant environment, and replay
    artifacts. The source worktree must remain available for the replay cwd.
    """
    if replay_count < 3:
        raise ValueError("replay_count must be at least 3")
    if not commit.strip():
        raise ValueError("commit must be a non-empty commit hash")
    if not build_result.ok or not build_result.binary_path:
        raise ValueError("a successful build with a binary is required")
    if not observation.argv:
        raise ValueError("observation has no execution command")

    worktree_path = Path(worktree).resolve()
    if not worktree_path.is_dir():
        raise NotADirectoryError(f"worktree not found: {worktree_path}")

    original_binary = Path(build_result.binary_path).resolve()
    if not original_binary.is_file():
        raise FileNotFoundError(f"binary not found: {original_binary}")

    test = config.test_by_id(observation.test_id)
    bundle = (
        Path(out_dir).resolve()
        / "reproducers"
        / observation.version
        / observation.variant
        / _safe_name(observation.test_id)
    )
    # Do not silently overwrite evidence from an earlier run.
    bundle.mkdir(parents=True, exist_ok=False)

    bundled_binary = bundle / "program"
    shutil.copy2(original_binary, bundled_binary)
    original_binary_hash = sha256_file(original_binary)
    bundled_binary_hash = sha256_file(bundled_binary)
    if original_binary_hash != bundled_binary_hash:
        raise RuntimeError("binary hash changed while creating reproducer bundle")

    original_input: Path | None = None
    bundled_input: Path | None = None
    stdin_bytes: bytes | None = None

    if test.input_path is not None:
        original_input = Path(test.input_path).resolve()
        if not original_input.is_file():
            raise FileNotFoundError(f"test input not found: {original_input}")
        bundled_input = bundle / f"input{original_input.suffix}"
        shutil.copy2(original_input, bundled_input)

    if test.input_mode == "stdin":
        if original_input is None:
            raise ValueError("stdin test has no input file")
        stdin_bytes = original_input.read_bytes()

    original_argv = list(observation.argv)
    replay_argv = _make_replay_argv(
        original_argv,
        original_binary=original_binary,
        bundled_binary=bundled_binary,
        test_input=test.input_path,
        original_input=original_input,
        bundled_input=bundled_input,
        input_mode=test.input_mode,
    )

    build_spec = (
        config.build.sanitized
        if observation.variant == "sanitized"
        else config.build.release
    )
    if build_spec is None:
        raise ValueError(f"no build specification for {observation.variant!r}")

    execution_env = dict(build_spec.env)
    execution_env.update(config.limits.env)
    if observation.variant == "sanitized":
        execution_env.setdefault(
            "ASAN_OPTIONS", "abort_on_error=1:detect_leaks=0:symbolize=1"
        )
        execution_env.setdefault(
            "UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"
        )

    timeout = (
        test.timeout_seconds
        if test.timeout_seconds is not None
        else config.limits.timeout_seconds
    )
    memory_mb = (
        None if observation.variant == "sanitized" else config.limits.memory_mb
    )

    _copy_if_exists(observation.stdout_path, bundle / "original_stdout.txt")
    _copy_if_exists(observation.stderr_path, bundle / "original_stderr.txt")

    original_signature = _execution_signature(
        exit_code=observation.exit_code,
        signal=observation.signal,
        timed_out=observation.timed_out,
        stderr=observation.stderr,
    )

    replay_results: list[dict[str, Any]] = []
    signatures = [original_signature]

    for index in range(1, replay_count + 1):
        replay_dir = bundle / "replays" / str(index)
        result = run(
            replay_argv,
            cwd=worktree_path,
            stdin_bytes=stdin_bytes,
            timeout=timeout,
            memory_mb=memory_mb,
            cpu_seconds=config.limits.cpu_seconds,
            file_size_mb=config.limits.file_size_mb,
            env=execution_env,
            artifact_dir=replay_dir,
        )
        signature = _execution_signature(
            exit_code=result.exit_code,
            signal=result.signal,
            timed_out=result.timed_out,
            stderr=result.stderr,
        )
        signatures.append(signature)
        replay_results.append(
            {
                "index": index,
                "exit_code": result.exit_code,
                "signal": result.signal,
                "timed_out": result.timed_out,
                "duration_seconds": result.duration_seconds,
                "stdout_path": result.stdout_path,
                "stderr_path": result.stderr_path,
                "signature": signature,
            }
        )

    # Compare the original execution and every replay. A differing sanitizer
    # diagnostic or stack location is treated as an unstable reproduction.
    unstable = len({_stable_json(item) for item in signatures}) != 1

    metadata = {
        "test_id": observation.test_id,
        "version": observation.version,
        "variant": observation.variant,
        "commit": commit,
        "worktree": str(worktree_path),
        "binary": {
            "original_path": str(original_binary),
            "bundled_path": str(bundled_binary),
            "sha256": bundled_binary_hash,
            "build_result_sha256": build_result.binary_sha256 or None,
            "build_result_hash_matches": (
                build_result.binary_sha256 == bundled_binary_hash
                if build_result.binary_sha256
                else None
            ),
        },
        "input": {
            "mode": test.input_mode,
            "original_path": str(original_input) if original_input else None,
            "bundled_path": str(bundled_input) if bundled_input else None,
            "sha256": (
                _sha256_file(bundled_input) if bundled_input is not None else None
            ),
        },
        "original_execution": {
            "command": original_argv,
            "cwd": str(worktree_path),
            "exit_code": observation.exit_code,
            "signal": observation.signal,
            "timed_out": observation.timed_out,
            "failure_reasons": observation.failure_reasons,
            "signature": original_signature,
        },
        "replay_command": replay_argv,
        "build": {
            "command": list(build_spec.command),
            "binary_setting": build_spec.binary,
            "environment": _redact_environment(build_spec.env),
            "timeout_seconds": config.build.timeout_seconds,
            "result_command": build_result.command,
            "result_exit_code": build_result.exit_code,
            "result_log_path": build_result.log_path,
        },
        "execution": {
            "timeout_seconds": timeout,
            "memory_mb": memory_mb,
            "cpu_seconds": config.limits.cpu_seconds,
            "file_size_mb": config.limits.file_size_mb,
            "environment": _redact_environment(execution_env),
            "inherited_environment": _relevant_inherited_environment(),
        },
        "replay_count": replay_count,
        "replays": replay_results,
        "signature_comparison": signatures,
        "unstable": unstable,
        "signature_note": (
            "Compares exit status, signal, timeout, sanitizer diagnostic, "
            "and available top stack frames. A generic crash without a "
            "diagnostic can only be compared by process outcome."
        ),
    }

    (bundle / "metadata.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (bundle / "README.md").write_text(
        "\n".join(
            [
                "# PatchProof reproducer bundle",
                "",
                f"- Test: `{observation.test_id}`",
                f"- Version / variant: `{observation.version}/{observation.variant}`",
                f"- Commit: `{commit}`",
                f"- Binary SHA-256: `{bundled_binary_hash}`",
                f"- Replays: {replay_count}",
                f"- Unstable: `{unstable}`",
                "",
                "See `metadata.json` for commands, build settings, execution",
                "limits, environment, input hash, and replay signatures.",
                "Replay artifacts are under `replays/`.",
                "",
                "The executable and input are bundled. The recorded working",
                "directory is the original source worktree and must remain",
                "available if the program depends on files relative to it.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return bundle


def _make_replay_argv(
    original_argv: list[str],
    *,
    original_binary: Path,
    bundled_binary: Path,
    test_input: Path | None,
    original_input: Path | None,
    bundled_input: Path | None,
    input_mode: str,
) -> list[str]:
    argv = list(original_argv)
    if not argv:
        raise ValueError("empty execution command")

    argv[0] = str(bundled_binary)

    if input_mode in {"file", "argv"}:
        if original_input is None or bundled_input is None:
            raise ValueError(f"{input_mode} test has no usable input file")

        old_values = {str(test_input), str(original_input)}
        replaced = False
        updated: list[str] = []
        for arg in argv[1:]:
            new_arg = arg
            for old in old_values:
                if old and old in new_arg:
                    new_arg = new_arg.replace(old, str(bundled_input))
                    replaced = True
            updated.append(new_arg)
        argv = [argv[0], *updated]

        # _build_invocation appends the input path when no {input}
        # placeholder appears in the configured argv.
        if not replaced:
            if argv[-1] == str(original_input):
                argv[-1] = str(bundled_input)
            else:
                raise ValueError(
                    "could not locate the original input path in observation.argv"
                )

    return argv


def _execution_signature(
    *,
    exit_code: int | None,
    signal: int | None,
    timed_out: bool,
    stderr: str,
) -> dict[str, Any]:
    sanitizer_match = _SANITIZER_ERROR.search(stderr)
    diagnostic = sanitizer_match.group(1).strip() if sanitizer_match else ""

    frames = []
    for frame in _STACK_FRAME.findall(stderr):
        # Remove unstable raw addresses while preserving function/location.
        frame = re.sub(r"0x[0-9a-fA-F]+", "<address>", frame)
        frames.append(frame.strip())
        if len(frames) == 3:
            break

    return {
        "exit_code": exit_code,
        "signal": signal,
        "timed_out": timed_out,
        "diagnostic": diagnostic,
        "stack_frames": frames,
    }


def _stable_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _safe_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return name[:80] or "test"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _copy_if_exists(source: str, destination: Path) -> None:
    if source:
        source_path = Path(source)
        if source_path.is_file():
            shutil.copy2(source_path, destination)


def _redact_environment(environment: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in environment.items():
        if any(marker in key.upper() for marker in _SECRET_MARKERS):
            result[key] = "<redacted>"
        else:
            result[key] = value
    return result


def _relevant_inherited_environment() -> dict[str, str]:
    return {
        key: value
        for key in _ENV_ALLOWLIST
        if (value := os.environ.get(key)) is not None
    }
