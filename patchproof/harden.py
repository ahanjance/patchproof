"""Inspect ELF binary hardening properties and compare two builds."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path


def _run_readelf(binary: Path, option: str) -> str:
    """Run readelf and return its output."""

    executable = shutil.which("readelf")
    if executable is None:
        raise RuntimeError("readelf was not found. Install binutils first.")

    result = subprocess.run(
        [executable, "-W", option, str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"readelf {option} failed for {binary}: "
            f"{result.stderr.strip()}"
        )

    return result.stdout


def inspect_binary(binary_path: str | Path) -> dict:
    """Inspect NX, PIE, RELRO and stack canary for one ELF binary."""

    binary = Path(binary_path).resolve()

    if not binary.is_file():
        raise FileNotFoundError(f"Binary not found: {binary}")

    header = _run_readelf(binary, "-h")
    program_headers = _run_readelf(binary, "-l")
    dynamic = _run_readelf(binary, "-d")
    symbols = _run_readelf(binary, "-s")

    # NX: a GNU_STACK segment without execute permission.
    stack_line = next(
        (
            line for line in program_headers.splitlines()
            if "GNU_STACK" in line
        ),
        None,
    )

    if stack_line is None:
        nx = None
    else:
        flags = re.split(r"\s+", stack_line.strip())
        nx = "E" not in flags[6]

    # PIE: executable ELF files built as position-independent executables
    # normally have ELF type DYN.
    elf_type_match = re.search(r"Type:\s+(\S+)", header)
    elf_type = elf_type_match.group(1) if elf_type_match else None
    pie = elf_type == "DYN" if elf_type else None

    # RELRO: GNU_RELRO segment plus immediate binding means full RELRO.
    has_relro_segment = "GNU_RELRO" in program_headers
    has_bind_now = bool(
        re.search(r"\bBIND_NOW\b", dynamic)
        or re.search(r"\bFLAGS\b.*\bNOW\b", dynamic)
        or re.search(r"\bFLAGS_1\b.*\bNOW\b", dynamic)
    )

    if not has_relro_segment:
        relro = "none"
    elif has_bind_now:
        relro = "full"
    else:
        relro = "partial"

    # Canary: look for the compiler's stack-check failure symbol.
    canary = bool(
        re.search(
            r"__stack_chk_fail(?:_local)?(?:@|$|\s)",
            symbols,
        )
    )

    return {
        "binary": str(binary),
        "nx": nx,
        "pie": pie,
        "relro": relro,
        "stack_canary": canary,
        "elf_type": elf_type,
        "evidence": {
            "header": header,
            "program_headers": program_headers,
            "dynamic": dynamic,
            "symbols": symbols,
        },
    }


def compare_hardening(
    base_binary: str | Path,
    patched_binary: str | Path,
    *,
    out_dir: str | Path,
) -> dict:
    """
    Compare hardening properties between base and patched binaries.

    Raw readelf output and a JSON report are saved in out_dir.
    """

    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    base = inspect_binary(base_binary)
    patched = inspect_binary(patched_binary)

    properties = ("nx", "pie", "relro", "stack_canary")

    warnings = []
    changes = {}

    relro_rank = {
        "none": 0,
        "partial": 1,
        "full": 2,
    }

    for property_name in properties:
        before = base[property_name]
        after = patched[property_name]

        changes[property_name] = {
            "base": before,
            "patched": after,
        }

        if before is None or after is None:
            warnings.append(
                f"Could not determine {property_name} for both binaries."
            )
            continue

        if property_name == "relro":
            weakened = relro_rank[after] < relro_rank[before]
        else:
            weakened = before is True and after is False

        if weakened:
            warnings.append(
                f"{property_name} protection was weakened: "
                f"{before} -> {after}"
            )

    # Save raw evidence separately for convenient inspection.
    for label, result in (("base", base), ("patched", patched)):
        evidence_dir = out_dir / label
        evidence_dir.mkdir(parents=True, exist_ok=True)

        for evidence_name, content in result["evidence"].items():
            (evidence_dir / f"readelf-{evidence_name}.txt").write_text(
                content,
                encoding="utf-8",
            )

    report = {
        "base_binary": base["binary"],
        "patched_binary": patched["binary"],
        "base": {
            key: base[key] for key in properties
        },
        "patched": {
            key: patched[key] for key in properties
        },
        "changes": changes,
        "warnings": warnings,
        "raw_evidence_directories": {
            "base": str(out_dir / "base"),
            "patched": str(out_dir / "patched"),
        },
    }

    report_path = out_dir / "hardening-report.json"
    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    report["report_path"] = str(report_path)

    return report
