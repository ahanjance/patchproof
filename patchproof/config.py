"""TOML configuration loading and validation.

The configuration is the only target-specific input to PatchProof.  Adding a
new C/C++ program must not require code changes: build command, binary path,
input delivery and the test suite all live here (project requirement 2).
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigError

VALID_TEST_KINDS = {"functional", "boundary", "invalid", "security"}
VALID_INPUT_MODES = {"stdin", "file", "argv", "none"}

DEFAULT_TEST_TIMEOUT = 10.0
DEFAULT_MEMORY_MB = 512
DEFAULT_CPU_SECONDS = 5
DEFAULT_FILE_SIZE_MB = 32
DEFAULT_BUILD_TIMEOUT = 300.0


@dataclass(frozen=True)
class Target:
    name: str
    repo: Path
    base_ref: str
    patched_ref: str


@dataclass(frozen=True)
class BuildVariant:
    command: tuple[str, ...]
    binary: str
    env: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class BuildConfig:
    release: BuildVariant
    sanitized: BuildVariant | None = None
    timeout_seconds: float = DEFAULT_BUILD_TIMEOUT


@dataclass(frozen=True)
class RunLimits:
    timeout_seconds: float = DEFAULT_TEST_TIMEOUT
    memory_mb: int = DEFAULT_MEMORY_MB
    cpu_seconds: int = DEFAULT_CPU_SECONDS
    file_size_mb: int = DEFAULT_FILE_SIZE_MB
    env: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class TestCase:
    id: str
    kind: str
    input_mode: str
    input_path: Path | None = None
    argv: tuple[str, ...] = ()
    expect_exit: int | None = None
    stdout_contains: str | None = None
    stdout_regex: str | None = None
    stderr_contains: str | None = None
    timeout_seconds: float | None = None


@dataclass(frozen=True)
class Config:
    path: Path
    target: Target
    build: BuildConfig
    limits: RunLimits
    tests: tuple[TestCase, ...]
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def variants(self) -> tuple[str, ...]:
        return ("release", "sanitized") if self.build.sanitized else ("release",)

    def test_by_id(self, test_id: str) -> TestCase:
        for test in self.tests:
            if test.id == test_id:
                return test
        raise KeyError(test_id)


def load_config(path: str | Path) -> Config:
    """Load and fully validate *path*.  Raises :class:`ConfigError`."""

    config_path = Path(path).expanduser().resolve()
    if not config_path.is_file():
        raise ConfigError(f"config file not found: {config_path}")

    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{config_path}: invalid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"{config_path}: cannot read: {exc}") from exc

    _check_keys(data, {"target", "build", "run", "tests"}, "top level")
    base_dir = config_path.parent

    target = _parse_target(_table(data, "target"), base_dir)
    build = _parse_build(_table(data, "build"))
    limits = _parse_run(_table(data, "run", required=False))
    tests = _parse_tests(data.get("tests"), base_dir)

    return Config(
        path=config_path,
        target=target,
        build=build,
        limits=limits,
        tests=tests,
        raw=data,
    )


# ---------------------------------------------------------------------------
# helpers


def _check_keys(table: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s): {', '.join(unknown)}")


def _table(data: dict[str, Any], key: str, *, required: bool = True) -> dict[str, Any]:
    value = data.get(key)
    if value is None:
        if required:
            raise ConfigError(f"missing required section [{key}]")
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"[{key}] must be a table")
    return value


def _string(table: dict[str, Any], key: str, where: str, *, default: str | None = None) -> str:
    value = table.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}.{key} must be a non-empty string")
    return value.strip()


def _positive_int(table: dict[str, Any], key: str, where: str, default: int) -> int:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{where}.{key} must be a positive integer")
    return value


def _positive_float(
    table: dict[str, Any], key: str, where: str, default: float
) -> float:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ConfigError(f"{where}.{key} must be a positive number")
    return float(value)


def _string_list(table: dict[str, Any], key: str, where: str) -> tuple[str, ...]:
    value = table.get(key)
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{where}.{key} must be a non-empty array of strings")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise ConfigError(f"{where}.{key} must contain only non-empty strings")
        result.append(item)
    return tuple(result)


def _env(table: dict[str, Any], where: str) -> dict[str, str]:
    value = table.get("env", {})
    if not isinstance(value, dict):
        raise ConfigError(f"{where}.env must be a table")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ConfigError(f"{where}.env keys and values must be strings")
        result[key] = item
    return result


# ---------------------------------------------------------------------------
# sections


def _parse_target(table: dict[str, Any], base_dir: Path) -> Target:
    _check_keys(table, {"name", "repo", "base_ref", "patched_ref"}, "[target]")
    name = _string(table, "name", "[target]")
    repo_value = _string(table, "repo", "[target]")
    repo = Path(repo_value).expanduser()
    if not repo.is_absolute():
        repo = (base_dir / repo).resolve()
    else:
        repo = repo.resolve()
    if not repo.is_dir():
        raise ConfigError(f"[target].repo is not a directory: {repo}")
    return Target(
        name=name,
        repo=repo,
        base_ref=_string(table, "base_ref", "[target]"),
        patched_ref=_string(table, "patched_ref", "[target]"),
    )


def _parse_build(table: dict[str, Any]) -> BuildConfig:
    _check_keys(
        table,
        {"command", "binary", "env", "timeout_seconds", "sanitized"},
        "[build]",
    )
    release = _parse_build_variant(table, "[build]")
    sanitized = None
    raw_sanitized = table.get("sanitized")
    if raw_sanitized is not None:
        if not isinstance(raw_sanitized, dict):
            raise ConfigError("[build.sanitized] must be a table")
        _check_keys(raw_sanitized, {"command", "binary", "env"}, "[build.sanitized]")
        sanitized = _parse_build_variant(raw_sanitized, "[build.sanitized]")
    return BuildConfig(
        release=release,
        sanitized=sanitized,
        timeout_seconds=_positive_float(
            table, "timeout_seconds", "[build]", DEFAULT_BUILD_TIMEOUT
        ),
    )


def _parse_build_variant(table: dict[str, Any], where: str) -> BuildVariant:
    return BuildVariant(
        command=_string_list(table, "command", where),
        binary=_string(table, "binary", where),
        env=_env(table, where),
    )


def _parse_run(table: dict[str, Any]) -> RunLimits:
    _check_keys(
        table,
        {"timeout_seconds", "memory_mb", "cpu_seconds", "file_size_mb", "env"},
        "[run]",
    )
    return RunLimits(
        timeout_seconds=_positive_float(
            table, "timeout_seconds", "[run]", DEFAULT_TEST_TIMEOUT
        ),
        memory_mb=_positive_int(table, "memory_mb", "[run]", DEFAULT_MEMORY_MB),
        cpu_seconds=_positive_int(table, "cpu_seconds", "[run]", DEFAULT_CPU_SECONDS),
        file_size_mb=_positive_int(
            table, "file_size_mb", "[run]", DEFAULT_FILE_SIZE_MB
        ),
        env=_env(table, "[run]"),
    )


def _parse_tests(value: Any, base_dir: Path) -> tuple[TestCase, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError("at least one [[tests]] entry is required")
    tests: list[TestCase] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ConfigError(f"tests[{index}] must be a table")
        test = _parse_test(item, base_dir, index)
        if test.id in seen:
            raise ConfigError(f"duplicate test id: {test.id}")
        seen.add(test.id)
        tests.append(test)
    return tuple(tests)


def _parse_test(table: dict[str, Any], base_dir: Path, index: int) -> TestCase:
    where = f"tests[{index}]"
    _check_keys(
        table,
        {
            "id",
            "kind",
            "input_mode",
            "input",
            "argv",
            "expect_exit",
            "stdout_contains",
            "stdout_regex",
            "stderr_contains",
            "timeout_seconds",
        },
        where,
    )

    test_id = _string(table, "id", where)
    where = f"test {test_id!r}"
    kind = _string(table, "kind", where)
    if kind not in VALID_TEST_KINDS:
        raise ConfigError(
            f"{where}.kind must be one of: {', '.join(sorted(VALID_TEST_KINDS))}"
        )

    input_mode = table.get("input_mode")
    if input_mode is None:
        input_mode = "stdin" if "input" in table else "none"
    if input_mode not in VALID_INPUT_MODES:
        raise ConfigError(
            f"{where}.input_mode must be one of: "
            f"{', '.join(sorted(VALID_INPUT_MODES))}"
        )

    input_path: Path | None = None
    if input_mode != "none":
        raw_input = table.get("input")
        if not isinstance(raw_input, str) or not raw_input.strip():
            raise ConfigError(f"{where}.input is required for input_mode={input_mode}")
        input_path = Path(raw_input).expanduser()
        if not input_path.is_absolute():
            input_path = (base_dir / input_path).resolve()
        else:
            input_path = input_path.resolve()
        if not input_path.is_file():
            raise ConfigError(f"{where}.input is not a file: {input_path}")
    elif "input" in table:
        raise ConfigError(f"{where}.input cannot be used with input_mode='none'")

    argv: tuple[str, ...] = ()
    raw_argv = table.get("argv", [])
    if not isinstance(raw_argv, list) or any(
        not isinstance(arg, str) for arg in raw_argv
    ):
        raise ConfigError(f"{where}.argv must be an array of strings")
    argv = tuple(raw_argv)

    expect_exit = table.get("expect_exit")
    if expect_exit is not None:
        if isinstance(expect_exit, bool) or not isinstance(expect_exit, int):
            raise ConfigError(f"{where}.expect_exit must be an integer")
    elif kind in {"functional", "boundary"}:
        raise ConfigError(
            f"{where}.expect_exit is required for kind={kind} "
            "(reference behaviour must be explicit)"
        )

    stdout_regex = table.get("stdout_regex")
    if stdout_regex is not None:
        if not isinstance(stdout_regex, str) or not stdout_regex:
            raise ConfigError(f"{where}.stdout_regex must be a non-empty string")
        try:
            re.compile(stdout_regex)
        except re.error as exc:
            raise ConfigError(f"{where}.stdout_regex is invalid: {exc}") from exc

    timeout_seconds = None
    if "timeout_seconds" in table:
        timeout_seconds = _positive_float(
            table, "timeout_seconds", where, DEFAULT_TEST_TIMEOUT
        )

    def optional_text(key: str) -> str | None:
        value = table.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ConfigError(f"{where}.{key} must be a string")
        return value

    return TestCase(
        id=test_id,
        kind=kind,
        input_mode=input_mode,
        input_path=input_path,
        argv=argv,
        expect_exit=expect_exit,
        stdout_contains=optional_text("stdout_contains"),
        stdout_regex=stdout_regex,
        stderr_contains=optional_text("stderr_contains"),
        timeout_seconds=timeout_seconds,
    )
