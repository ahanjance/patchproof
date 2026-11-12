"""JSON serialization and the developer-facing summary."""

from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .model import Report


def to_jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: to_jsonable(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    return value


def write_report(
    report: Report,
    destination: str | Path,
    *,
    summary: str | None = None,
) -> tuple[Path, Path]:
    destination = Path(destination).resolve()
    if destination.suffix != ".json":
        destination.mkdir(parents=True, exist_ok=True)
        destination = destination / "report.json"
    destination.parent.mkdir(parents=True, exist_ok=True)

    data = to_jsonable(report)
    destination.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    summary_path = destination.with_name("summary.txt")
    summary_path.write_text(
        summary if summary is not None else render_summary(data),
        encoding="utf-8",
    )
    return destination, summary_path


def render_summary(data: dict[str, Any]) -> str:
    target = data.get("target", {})
    run = data.get("run", {})
    tool = data.get("tool", {})
    verdict = data.get("verdict", {})
    builds = data.get("builds", [])
    observations = data.get("observations", [])
    findings = data.get("findings", [])

    lines: list[str] = []
    lines.append(
        f"PatchProof {tool.get('version', '?')} — {target.get('name', 'unknown target')}"
    )
    base_commit = (target.get("base_commit") or "")[:12]
    patched_commit = (target.get("patched_commit") or "")[:12]
    lines.append(
        f"Versions: {target.get('base_ref', '?')} ({base_commit or '?'}) -> "
        f"{target.get('patched_ref', '?')} ({patched_commit or '?'})"
    )
    lines.append(f"Run: {run.get('id', '?')}")

    if builds:
        build_bits = [
            f"{item['version']}/{item['variant']}={'OK' if item['ok'] else 'FAIL'}"
            for item in builds
        ]
        lines.append("Builds: " + ", ".join(build_bits))
    else:
        lines.append("Builds: none")

    if observations:
        counts: dict[str, int] = {}
        for item in observations:
            counts[item["outcome"]] = counts.get(item["outcome"], 0) + 1
        count_text = ", ".join(
            f"{name} {counts.get(name, 0)}"
            for name in ("pass", "fail", "crash", "timeout", "error")
        )
        lines.append(f"Observations: {len(observations)} ({count_text})")
    else:
        lines.append("Observations: none")

    if findings:
        lines.append(f"Findings: {len(findings)}")
        for finding in findings:
            lines.append(
                f"  - [{finding['status']}] {finding['id']}: {finding['title']}"
            )
    else:
        lines.append("Findings: none")

    lines.append(
        f"Verdict: {verdict.get('status', '?')} "
        f"(exit {verdict.get('exit_code', '?')})"
    )
    for reason in verdict.get("reasons", []):
        lines.append(f"  - {reason}")

    if data.get("error"):
        lines.append(f"Error: {data['error']}")

    report_path = Path(run.get("out_dir", ".")) / "report.json"
    lines.append(f"Report: {report_path}")
    return "\n".join(lines) + "\n"
