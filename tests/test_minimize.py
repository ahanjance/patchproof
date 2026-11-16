import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from patchproof.minimize import minimize_input


class MinimizeTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        self.worktree = self.root / "worktree"
        self.worktree.mkdir()

        self.out_dir = self.root / "output"
        self.input_path = self.worktree / "input.bin"

        self.input_path.write_bytes(b"X" * 100 + b"BAD" + b"Y" * 100)

        self.binary = self.worktree / "target"

        self.test_case = SimpleNamespace(
            id="test-crash",
            input_mode="file",
            input_path=str(self.input_path),
            argv=(),
            timeout_seconds=5,
        )

        self.variant = SimpleNamespace(
            name="release",
            env={},
        )

        self.config = SimpleNamespace(
            test_by_id=lambda test_id: self.test_case,
            build=SimpleNamespace(
                variants=[self.variant],
            ),
            limits=SimpleNamespace(
                timeout_seconds=5,
                memory_mb=512,
                cpu_seconds=5,
                file_size_mb=32,
                env={},
            ),
        )

        self.observation = SimpleNamespace(
            test_id="test-crash",
            version="base",
            variant="release",
            exit_code=1,
            signal=None,
            timed_out=False,
            stdout="",
            stderr="ERROR: AddressSanitizer: heap-buffer-overflow",
        )

        self.build_result = SimpleNamespace(
            ok=True,
            binary_path=str(self.binary),
        )

    def tearDown(self):
        self.temp.cleanup()

    def create_target(self, input_mode="file"):
        if input_mode == "file":
            source = """#!/usr/bin/env python3
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()

if b"BAD" in data:
    print("ERROR: AddressSanitizer: heap-buffer-overflow", file=sys.stderr)
    sys.exit(1)

sys.exit(0)
"""
        else:
            source = """#!/usr/bin/env python3
import sys

data = sys.stdin.buffer.read()

if b"BAD" in data:
    print("ERROR: AddressSanitizer: heap-buffer-overflow", file=sys.stderr)
    sys.exit(1)

sys.exit(0)
"""

        self.binary.write_text(source, encoding="utf-8")
        self.binary.chmod(0o755)

    def test_file_input_is_minimized_and_original_is_preserved(self):
        self.create_target("file")

        original = self.input_path.read_bytes()

        result = minimize_input(
            self.config,
            self.observation,
            self.build_result,
            worktree=self.worktree,
            out_dir=self.out_dir,
        )

        self.assertTrue(result.is_file())
        self.assertLess(len(result.read_bytes()), len(original))
        self.assertEqual(self.input_path.read_bytes(), original)

        self.assertEqual(result.read_bytes(), b"BAD")

        metadata_path = self.out_dir / "minimize-metadata.json"
        self.assertTrue(metadata_path.is_file())

        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        self.assertLess(
            metadata["minimized_size"],
            metadata["original_size"],
        )

    def test_stdin_input_is_minimized(self):
        self.create_target("stdin")

        self.test_case.input_mode = "stdin"

        result = minimize_input(
            self.config,
            self.observation,
            self.build_result,
            worktree=self.worktree,
            out_dir=self.out_dir,
        )

        self.assertTrue(result.is_file())
        self.assertEqual(result.read_bytes(), b"BAD")

        original_copy = self.out_dir / "original-input.bin"
        self.assertTrue(original_copy.is_file())

    def test_non_reproducing_input_is_rejected(self):
        self.create_target("file")

        self.input_path.write_bytes(b"NO-ERROR")

        with self.assertRaises(RuntimeError):
            minimize_input(
                self.config,
                self.observation,
                self.build_result,
                worktree=self.worktree,
                out_dir=self.out_dir,
            )


if __name__ == "__main__":
    unittest.main()
