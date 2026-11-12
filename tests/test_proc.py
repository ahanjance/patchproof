from __future__ import annotations

import signal
import tempfile
import unittest
from pathlib import Path

from patchproof.proc import run


class ProcTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_stdout_and_exit_zero(self) -> None:
        result = run(["sh", "-c", "printf hello"], cwd=self.root)
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout, "hello")
        self.assertEqual(result.exit_code, 0)
        self.assertIsNone(result.signal)
        self.assertFalse(result.timed_out)

    def test_nonzero_exit(self) -> None:
        result = run(["sh", "-c", "exit 3"], cwd=self.root)
        self.assertEqual(result.exit_code, 3)
        self.assertFalse(result.ok)

    def test_standard_input(self) -> None:
        result = run(["sh", "-c", "cat"], cwd=self.root, stdin_bytes=b"abc\n")
        self.assertEqual(result.stdout, "abc\n")
        self.assertTrue(result.ok)

    def test_crash_signal(self) -> None:
        result = run(["sh", "-c", "kill -SEGV $$"], cwd=self.root)
        self.assertEqual(result.signal, signal.SIGSEGV)
        self.assertTrue(result.crashed)
        self.assertFalse(result.ok)

    def test_timeout_kills_process_group(self) -> None:
        result = run(
            ["sh", "-c", "sleep 10"],
            cwd=self.root,
            timeout=0.2,
            cpu_seconds=1,
        )
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)
        self.assertLess(result.duration_seconds, 5)

    def test_artifacts_are_written(self) -> None:
        artifact = self.root / "artifacts" / "one"
        result = run(
            ["sh", "-c", "printf out; printf err >&2"],
            cwd=self.root,
            artifact_dir=artifact,
        )
        self.assertEqual(Path(result.stdout_path).read_text(), "out")
        self.assertEqual(Path(result.stderr_path).read_text(), "err")

    def test_missing_working_directory(self) -> None:
        with self.assertRaises(FileNotFoundError):
            run(["true"], cwd=self.root / "missing")

    def test_preview_truncates_but_artifacts_keep_everything(self) -> None:
        artifact = self.root / "artifacts" / "big"
        result = run(
            ["sh", "-c", "yes x | head -c 100000"],
            cwd=self.root,
            artifact_dir=artifact,
        )
        self.assertIn("truncated", result.stdout)
        self.assertEqual(Path(result.stdout_path).stat().st_size, 100000)


if __name__ == "__main__":
    unittest.main()
