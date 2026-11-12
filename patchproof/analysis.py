"""Analyzer extension point used by Parts 2 and 3.

Part 1 owns the pipeline contract.  A crash is *never* enough on its own to
confirm a vulnerability (project statement 3.2/3.5), so crashes that no
analyzer links to a :class:`Finding` force exit code 40.

An analyzer receives all observations and both worktrees, and returns findings
whose ``evidence["observations"]`` entries are dictionaries of the form
``{"test_id": ..., "version": "base"|"patched", "variant": "release"|"sanitized"}``.
Those references are how the verdict engine knows an observation was
classified.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .config import Config
from .model import Finding, TestObservation


@dataclass(frozen=True)
class AnalysisContext:
    config: Config
    base_worktree: Path
    patched_worktree: Path
    diff: str
    observations: list[TestObservation]
    out_dir: Path


@runtime_checkable
class Analyzer(Protocol):
    name: str

    def analyze(self, context: AnalysisContext) -> list[Finding]:
        """Return findings; never raise for target behaviour."""
        ...
