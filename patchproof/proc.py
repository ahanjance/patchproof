"""Sandboxed process execution with timeout, rlimits and artifact capture."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

from .model import ExecResult

PREVIEW_BYTES = 32 * 1024


def run(
    argv: list[str] | tuple[str, ...],
    *,
    cwd: str | Path,
    stdin_bytes: bytes | None = None,
    timeout: float = 10.0,
    memory_mb: int | None = 512,
    cpu_seconds: int = 5,
    file_size_mb: int = 32,
    env: dict[str, str] | None = None,
    artifact_dir: str | Path | None = None,
) -> ExecResult:
    """Execute *argv* and never raise for target misbehaviour.

    ``memory_mb=None`` disables ``RLIMIT_AS``.  This is required for ASan
    builds: AddressSanitizer reserves terabytes of virtual address space and
    dies immediately under a 512 MiB address-space limit.
    """

    argv = [str(item) for item in argv]
    cwd_path = Path(cwd).resolve()
    if not cwd_path.is_dir():
        raise FileNotFoundError(f"working directory does not exist: {cwd_path}")

    artifact_path: Path | None = None
    if artifact_dir is not None:
        artifact_path = Path(artifact_dir).resolve()
        artifact_path.mkdir(parents=True, exist_ok=True)

    child_env = os.environ.copy()
    if env:
        child_env.update({str(key): str(value) for key, value in env.items()})
    child_env.setdefault("LC_ALL", "C")

    started = time.monotonic()
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd_path),
        stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_env,
        start_new_session=True,
        preexec_fn=_limit_setter(cpu_seconds, memory_mb, file_size_mb),
    )

    timed_out = False
    try:
        stdout_raw, stderr_raw = proc.communicate(stdin_bytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc.pid)
        stdout_raw, stderr_raw = proc.communicate()
    duration = time.monotonic() - started

    returncode = proc.returncode
    exit_code = returncode if returncode is not None and returncode >= 0 else None
    received_signal = -returncode if returncode is not None and returncode < 0 else None

    stdout_text = stdout_raw.decode("utf-8", errors="replace")
    stderr_text = stderr_raw.decode("utf-8", errors="replace")

    stdout_path = ""
    stderr_path = ""
    if artifact_path is not None:
        stdout_file = artifact_path / "stdout.txt"
        stderr_file = artifact_path / "stderr.txt"
        stdout_file.write_bytes(stdout_raw)
        stderr_file.write_bytes(stderr_raw)
        stdout_path = str(stdout_file)
        stderr_path = str(stderr_file)

    return ExecResult(
        argv=argv,
        exit_code=exit_code,
        signal=received_signal,
        timed_out=timed_out,
        duration_seconds=round(duration, 6),
        stdout=_preview(stdout_text),
        stderr=_preview(stderr_text),
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )


def _limit_setter(cpu_seconds: int, memory_mb: int | None, file_size_mb: int):
    try:
        import resource
    except ImportError:  # pragma: no cover - PatchProof targets Linux
        return None

    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(
            resource.RLIMIT_CPU, (int(cpu_seconds), int(cpu_seconds) + 1)
        )
        if memory_mb is not None:
            limit = int(memory_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        file_limit = int(file_size_mb) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))

    return apply


def _kill_group(pid: int) -> None:
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:  # pragma: no cover - defensive
        pass


def _preview(text: str, limit: int = PREVIEW_BYTES) -> str:
    if len(text) <= limit:
        return text
    half = limit // 2
    omitted = len(text) - limit
    return f"{text[:half]}\n... [{omitted} bytes truncated] ...\n{text[-half:]}"
