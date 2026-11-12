"""Build orchestration for the base and patched versions, release and ASan/UBSan."""

from __future__ import annotations

from pathlib import Path

from .config import BuildConfig, BuildVariant
from .model import BuildResult
from .proc import run
from .repo import sha256_file


def build(
    *,
    worktree: str | Path,
    version: str,
    variant: str,
    build_config: BuildConfig,
    out_dir: str | Path,
) -> BuildResult:
    spec: BuildVariant | None = (
        build_config.release if variant == "release" else build_config.sanitized
    )
    if spec is None:
        raise ValueError(f"no build spec for variant {variant!r}")

    worktree_path = Path(worktree).resolve()
    artifact_dir = Path(out_dir).resolve() / "builds" / f"{version}-{variant}"
    log_path = artifact_dir / "build.log"

    try:
        result = run(
            list(spec.command),
            cwd=worktree_path,
            timeout=build_config.timeout_seconds,
            memory_mb=None,  # compilers and sanitizers need virtual address space
            cpu_seconds=int(build_config.timeout_seconds),
            file_size_mb=2048,
            env=spec.env,
            artifact_dir=artifact_dir,
        )
    except OSError as exc:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        log_path.write_text(f"$ {' '.join(spec.command)}\ncannot start build: {exc}\n")
        return BuildResult(
            version=version,
            variant=variant,
            ok=False,
            command=list(spec.command),
            exit_code=None,
            signal=None,
            timed_out=False,
            duration_seconds=0.0,
            log_path=str(log_path),
            binary_path="",
            error=f"cannot start build: {exc}",
        )

    binary_path = _resolve_binary(worktree_path, spec.binary)
    error = ""
    if result.timed_out:
        error = f"build timed out after {build_config.timeout_seconds}s"
    elif result.crashed:
        error = f"build crashed with {result.signal_name}"
    elif result.exit_code != 0:
        error = f"build exited with code {result.exit_code}"
    elif not binary_path.is_file():
        error = f"built binary not found: {binary_path}"
    elif not binary_path.stat().st_mode & 0o111:
        error = f"built binary is not executable: {binary_path}"

    log_path.write_text(
        "\n".join(
            [
                f"$ {' '.join(spec.command)}",
                f"cwd: {worktree_path}",
                f"exit: {result.exit_code}  signal: {result.signal_name}  "
                f"timeout: {result.timed_out}  duration: {result.duration_seconds:.3f}s",
                f"stdout: {result.stdout_path}",
                f"stderr: {result.stderr_path}",
                "",
                "--- stdout ---",
                result.stdout,
                "--- stderr ---",
                result.stderr,
                "--- error ---",
                error or "(none)",
                "",
            ]
        ),
        encoding="utf-8",
    )

    return BuildResult(
        version=version,
        variant=variant,
        ok=not error,
        command=list(spec.command),
        exit_code=result.exit_code,
        signal=result.signal,
        timed_out=result.timed_out,
        duration_seconds=result.duration_seconds,
        log_path=str(log_path),
        binary_path=str(binary_path),
        binary_sha256=sha256_file(binary_path) if binary_path.is_file() else "",
        error=error,
    )


def _resolve_binary(worktree: Path, binary: str) -> Path:
    path = Path(binary).expanduser()
    if not path.is_absolute():
        path = worktree / path
    return path.resolve()
