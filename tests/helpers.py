"""Shared fixtures for the PatchProof test suite (stdlib unittest only)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "PatchProof Tests",
            "GIT_AUTHOR_EMAIL": "tests@patchproof.local",
            "GIT_COMMITTER_NAME": "PatchProof Tests",
            "GIT_COMMITTER_EMAIL": "tests@patchproof.local",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    return env


def git(cwd: str | Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        env=_git_env(),
    )
    if check and completed.returncode != 0:
        raise AssertionError(
            f"git {' '.join(args)} failed: {completed.stderr or completed.stdout}"
        )
    return completed


def write_files(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def init_repo(
    root: Path,
    files: dict[str, str],
    *,
    message: str = "initial",
    tag: str | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "PatchProof Tests")
    git(root, "config", "user.email", "tests@patchproof.local")
    write_files(root, files)
    git(root, "add", "-A")
    git(root, "commit", "-m", message)
    if tag:
        git(root, "tag", tag)
    return root


def commit(
    root: Path,
    files: dict[str, str] | None = None,
    *,
    message: str = "change",
    tag: str | None = None,
    allow_empty: bool = False,
) -> str:
    if files:
        write_files(root, files)
        git(root, "add", "-A")
    args = ["commit", "-m", message]
    if allow_empty:
        args.insert(1, "--allow-empty")
    git(root, *args)
    if tag:
        git(root, "tag", tag)
    return git(root, "rev-parse", "HEAD").stdout.strip()


BENIGN_APP = r"""
#include <stdio.h>

int main(void) {
    long n;
    if (scanf("%ld", &n) != 1) {
        fprintf(stderr, "invalid input\n");
        return 1;
    }
    printf("OK %ld\n", n);
    return 0;
}
"""

REGRESSION_APP = r"""
#include <stdio.h>

int main(void) {
    long n;
    if (scanf("%ld", &n) != 1) {
        fprintf(stderr, "invalid input\n");
        return 1;
    }
    if (n == 0) {
        fprintf(stderr, "zero rejected\n");
        return 2;
    }
    printf("OK %ld\n", n);
    return 0;
}
"""

CRASH_APP = r"""
#include <stdio.h>

int main(void) {
    long n;
    if (scanf("%ld", &n) != 1) {
        fprintf(stderr, "invalid input\n");
        return 1;
    }
    if (n < 0) {
        volatile int *p = 0;
        *p = 1;
    }
    printf("OK %ld\n", n);
    return 0;
}
"""
