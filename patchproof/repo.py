"""Thin git wrapper: resolve refs, extract the diff, manage disposable worktrees."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

from .errors import RepoError


class Repo:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        probe = self._git("rev-parse", "--git-dir", check=False)
        if probe.returncode != 0:
            raise RepoError(f"not a git repository: {self.root}")

    def _git(
        self, *args: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        try:
            completed = subprocess.run(
                ["git", "-C", str(self.root), "--no-pager", *args],
                capture_output=True,
                text=True,
                errors="replace",
            )
        except OSError as exc:
            raise RepoError(f"cannot run git: {exc}") from exc
        if check and completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RepoError(
                f"git {' '.join(args)} failed ({completed.returncode}): {detail}"
            )
        return completed

    def resolve(self, ref: str) -> str:
        completed = self._git("rev-parse", "--verify", f"{ref}^{{commit}}", check=False)
        if completed.returncode != 0:
            raise RepoError(f"unknown git ref: {ref}")
        return completed.stdout.strip()

    def diff(self, base_ref: str, patched_ref: str) -> str:
        return self._git(
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--full-index",
            base_ref,
            patched_ref,
            "--",
        ).stdout

    def changed_files(self, base_ref: str, patched_ref: str) -> list[str]:
        output = self._git(
            "diff", "--name-only", "--no-ext-diff", base_ref, patched_ref, "--"
        ).stdout
        return [line for line in output.splitlines() if line.strip()]

    def add_worktree(self, commit: str, destination: str | Path) -> Path:
        destination = Path(destination).resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            self.remove_worktree(destination)
        self._git(
            "worktree",
            "add",
            "--detach",
            "--force",
            str(destination),
            commit,
        )
        return destination

    def remove_worktree(self, destination: str | Path) -> None:
        destination = Path(destination).resolve()
        if not destination.exists():
            self._git("worktree", "prune", check=False)
            return
        completed = self._git(
            "worktree", "remove", "--force", str(destination), check=False
        )
        if completed.returncode != 0:
            shutil.rmtree(destination, ignore_errors=True)
            self._git("worktree", "prune", check=False)

    def prune(self) -> None:
        self._git("worktree", "prune", check=False)


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
