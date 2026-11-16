import tempfile
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace

from patchproof.config import RunLimits, TestCase
from patchproof.regression import register_and_verify_regression


class RegressionTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        self.base_worktree = self.root / "base"
        self.patched_worktree = self.root / "patched"
        self.base_worktree.mkdir()
        self.patched_worktree.mkdir()

        self.config_path = self.root / "config.toml"
        self.config_path.write_text(
            '[[tests]]\n'
            'id = "source_test"\n'
            'kind = "security"\n'
            'input_mode = "file"\n'
            'input = "original.bin"\n',
            encoding="utf-8",
        )

        self.original_input = self.root / "original.bin"
        self.original_input.write_bytes(b"BAD")

        self.minimized_input = self.root / "minimized.bin"
        self.minimized_input.write_bytes(b"BAD")

        self.source_test = TestCase(
            id="source_test",
            kind="security",
            input_mode="file",
            input_path=self.original_input,
        )

        self.variant_config = SimpleNamespace(env={})

        self.config = SimpleNamespace(
            path=self.config_path,
            variants=("release",),
            build=SimpleNamespace(
                release=self.variant_config,
                sanitized=None,
            ),
            limits=RunLimits(),
            test_by_id=lambda test_id: (
                self.source_test
                if test_id == "source_test"
                else (_ for _ in ()).throw(KeyError(test_id))
            ),
        )

        self.base_binary = self.base_worktree / "target"
        self.patched_binary = self.patched_worktree / "target"

        self.base_binary.write_text(
            """#!/usr/bin/env python3
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()

if b"BAD" in data:
    print("BASE_FAILURE", file=sys.stderr)
    sys.exit(1)

sys.exit(0)
""",
            encoding="utf-8",
        )

        self.patched_binary.write_text(
            """#!/usr/bin/env python3
import sys

sys.exit(0)
""",
            encoding="utf-8",
        )

        self.base_binary.chmod(0o755)
        self.patched_binary.chmod(0o755)

        self.base_build = SimpleNamespace(
            ok=True,
            version="base",
            variant="release",
            binary_path=str(self.base_binary),
        )

        self.patched_build = SimpleNamespace(
            ok=True,
            version="patched",
            variant="release",
            binary_path=str(self.patched_binary),
        )

        self.out_dir = self.root / "output"

    def tearDown(self):
        self.temp.cleanup()

    def test_registers_when_base_fails_and_patched_passes(self):
        result = register_and_verify_regression(
            self.config,
            source_test_id="source_test",
            minimized_input=self.minimized_input,
            variant="release",
            base_build=self.base_build,
            patched_build=self.patched_build,
            base_worktree=self.base_worktree,
            patched_worktree=self.patched_worktree,
            out_dir=self.out_dir,
        )

        self.assertTrue(result["registered"])
        self.assertEqual(
            result["base_observation"].outcome,
            "fail",
        )
        self.assertEqual(
            result["patched_observation"].outcome,
            "pass",
        )

        permanent_input = Path(result["input_path"])
        self.assertTrue(permanent_input.is_file())
        self.assertEqual(permanent_input.read_bytes(), b"BAD")

        with self.config_path.open("rb") as file:
            data = tomllib.load(file)

        self.assertEqual(len(data["tests"]), 2)
        self.assertEqual(
            data["tests"][1]["id"],
            "regression_source_test",
        )
        self.assertEqual(data["tests"][1]["expect_exit"], 0)

    def test_does_not_register_when_patched_version_fails(self):
        self.patched_binary.write_text(
            """#!/usr/bin/env python3
import sys

sys.exit(1)
""",
            encoding="utf-8",
        )
        self.patched_binary.chmod(0o755)

        result = register_and_verify_regression(
            self.config,
            source_test_id="source_test",
            minimized_input=self.minimized_input,
            variant="release",
            base_build=self.base_build,
            patched_build=self.patched_build,
            base_worktree=self.base_worktree,
            patched_worktree=self.patched_worktree,
            out_dir=self.out_dir,
        )

        self.assertFalse(result["registered"])

        with self.config_path.open("rb") as file:
            data = tomllib.load(file)

        self.assertEqual(len(data["tests"]), 1)

        permanent_input = (
            self.root / "regression_inputs" / "regression_source_test.bin"
        )
        self.assertFalse(permanent_input.exists())

    def test_rejects_missing_minimized_input(self):
        with self.assertRaises(FileNotFoundError):
            register_and_verify_regression(
                self.config,
                source_test_id="source_test",
                minimized_input=self.root / "missing.bin",
                variant="release",
                base_build=self.base_build,
                patched_build=self.patched_build,
                base_worktree=self.base_worktree,
                patched_worktree=self.patched_worktree,
                out_dir=self.out_dir,
            )


if __name__ == "__main__":
    unittest.main()
