from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from helpers import commit, init_repo

from patchproof.errors import RepoError
from patchproof.repo import Repo, sha256_file


class RepoTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo_path = init_repo(
            self.root / "repo",
            {"app.c": "int main(void){return 1;}\n"},
            tag="base",
        )
        commit(
            self.repo_path,
            {"app.c": "int main(void){return 0;}\n"},
            tag="patched",
        )
        self.repo = Repo(self.repo_path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_resolve_tags(self) -> None:
        base = self.repo.resolve("base")
        patched = self.repo.resolve("patched")
        self.assertNotEqual(base, patched)
        self.assertEqual(len(base), 40)
        with self.assertRaisesRegex(RepoError, "unknown git ref"):
            self.repo.resolve("does-not-exist")

    def test_diff_and_changed_files(self) -> None:
        diff = self.repo.diff("base", "patched")
        self.assertIn("-int main(void){return 1;}", diff)
        self.assertIn("+int main(void){return 0;}", diff)
        self.assertEqual(self.repo.changed_files("base", "patched"), ["app.c"])

    def test_worktree_checkout_and_cleanup(self) -> None:
        destination = self.root / "out" / "worktrees" / "base"
        self.repo.add_worktree(self.repo.resolve("base"), destination)
        self.assertTrue((destination / "app.c").is_file())
        self.assertIn("return 1", (destination / "app.c").read_text())

        self.repo.remove_worktree(destination)
        self.assertFalse(destination.exists())

    def test_not_a_repository(self) -> None:
        plain = self.root / "plain"
        plain.mkdir()
        with self.assertRaisesRegex(RepoError, "not a git repository"):
            Repo(plain)

    def test_sha256_file(self) -> None:
        path = self.root / "blob"
        path.write_text("abc", encoding="utf-8")
        self.assertEqual(
            sha256_file(path),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )


if __name__ == "__main__":
    unittest.main()
