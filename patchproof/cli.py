"""Command line interface.

Usage:
    patchproof run -c config.toml [-o patchproof-out]
    patchproof validate -c config.toml
    patchproof version
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import SCHEMA_VERSION, __version__
from .analyzers.correlation import CorrelationAnalyzer
from .analyzers.crash import CrashAnalyzer
from .config import load_config
from .errors import ConfigError, RepoError
from .pipeline import execute
from .report import render_summary, to_jsonable, write_report
from .repo import Repo


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(f"patchproof {__version__}")
        return 0

    if args.command == "validate":
        return _validate(Path(args.config))

    if args.command == "run":
        return _run(
            Path(args.config),
            out_root=Path(args.out),
            keep_worktrees=args.keep_worktrees,
            verbose=args.verbose,
        )

    parser.error("a command is required")  # pragma: no cover
    return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="patchproof",
        description=(
            "Validate a security patch against a base version: builds, dynamic "
            "tests, JSON evidence and CI/CD exit codes."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="build and validate one target configuration")
    run.add_argument("-c", "--config", required=True, help="path to patchproof.toml")
    run.add_argument(
        "-o",
        "--out",
        default="patchproof-out",
        help="output directory (default: patchproof-out)",
    )
    run.add_argument(
        "--keep-worktrees",
        action="store_true",
        help="do not delete the base/patched git worktrees after the run",
    )
    run.add_argument("-v", "--verbose", action="store_true", help="progress on stderr")

    validate = sub.add_parser("validate", help="validate config and git refs only")
    validate.add_argument("-c", "--config", required=True, help="path to patchproof.toml")

    sub.add_parser("version", help="print the version")
    return parser


def _validate(config_path: Path) -> int:
    try:
        config = load_config(config_path)
        repo = Repo(config.target.repo)
        base_commit = repo.resolve(config.target.base_ref)
        patched_commit = repo.resolve(config.target.patched_ref)
    except (ConfigError, RepoError) as exc:
        print(f"patchproof: configuration error: {exc}", file=sys.stderr)
        return 30

    print(
        f"config OK: {config.target.name} | {len(config.tests)} tests | "
        f"variants={','.join(config.variants)} | "
        f"base={config.target.base_ref} ({base_commit[:12]}) | "
        f"patched={config.target.patched_ref} ({patched_commit[:12]})"
    )
    return 0


def _run(
    config_path: Path,
    *,
    out_root: Path,
    keep_worktrees: bool,
    verbose: bool,
) -> int:
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        message = str(exc)
        print(f"patchproof: configuration error: {message}", file=sys.stderr)
        report_path = _write_error_report(out_root, message, config_path)
        print(f"report: {report_path}")
        return 30

    report = execute(
        config,
        out_root=out_root,
        keep_worktrees=keep_worktrees,
        analyzers=[CrashAnalyzer(), CorrelationAnalyzer()],
        verbose=verbose,
    )
    data = to_jsonable(report)
    summary = render_summary(data)
    write_report(report, report.run["out_dir"], summary=summary)
    print(summary, end="")
    return int(report.verdict.exit_code)


def _write_error_report(
    out_root: Path, message: str, config_path: Path | None = None
) -> Path:
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + secrets.token_hex(3)
    )
    run_dir = Path(out_root).expanduser().resolve() / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "patchproof", "version": __version__},
        "run": {
            "id": run_id,
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "out_dir": str(run_dir),
        },
        "target": {},
        "config_path": str(config_path) if config_path is not None else "",
        "config_sha256": "",
        "builds": [],
        "observations": [],
        "findings": [],
        "hardening": None,
        "verdict": {
            "exit_code": 30,
            "status": "BUILD_OR_CONFIG_ERROR",
            "reasons": [message],
        },
        "error": message,
    }
    path = run_dir / "report.json"
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (run_dir / "summary.txt").write_text(
        f"PatchProof {__version__}\nVerdict: BUILD_OR_CONFIG_ERROR (exit 30)\n"
        f"  - {message}\nReport: {path}\n",
        encoding="utf-8",
    )
    return path


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
