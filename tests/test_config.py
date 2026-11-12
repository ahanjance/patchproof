from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from helpers import commit, init_repo, write_files

from patchproof.config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = init_repo(
            self.root / "repo",
            {"app.c": "int main(void){return 0;}\n"},
            tag="base",
        )
        commit(self.repo, message="patched", tag="patched", allow_empty=True)
        self.config_dir = self.root / "cfg"
        self.inputs = self.config_dir / "inputs"
        self.inputs.mkdir(parents=True)
        (self.inputs / "valid.txt").write_text("5\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, body: str) -> Path:
        path = self.config_dir / "patchproof.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def _valid_body(self, extra: str = "") -> str:
        return f"""
[target]
name = "demo"
repo = "{self.repo}"
base_ref = "base"
patched_ref = "patched"

[build]
command = ["cc", "-o", "app", "app.c"]
binary = "app"

[[tests]]
id = "valid"
kind = "functional"
input = "inputs/valid.txt"
input_mode = "stdin"
expect_exit = 0
{extra}
"""

    def test_minimal_config(self) -> None:
        config = load_config(self._write(self._valid_body()))
        self.assertEqual(config.target.name, "demo")
        self.assertEqual(config.target.repo, self.repo.resolve())
        self.assertEqual(config.variants, ("release",))
        self.assertEqual(len(config.tests), 1)
        self.assertEqual(config.tests[0].input_mode, "stdin")
        self.assertEqual(config.tests[0].input_path, (self.inputs / "valid.txt").resolve())
        self.assertEqual(config.limits.timeout_seconds, 10.0)
        self.assertEqual(config.limits.memory_mb, 512)

    def test_sanitized_variant_and_env(self) -> None:
        body = self._valid_body() + f"""
[build.sanitized]
command = ["cc", "-fsanitize=address", "-o", "app-asan", "app.c"]
binary = "app-asan"
env = {{ ASAN_OPTIONS = "abort_on_error=1" }}

[run]
timeout_seconds = 3.5
memory_mb = 128
cpu_seconds = 2
file_size_mb = 8
env = {{ FOO = "bar" }}
"""
        config = load_config(self._write(body))
        self.assertEqual(config.variants, ("release", "sanitized"))
        self.assertIsNotNone(config.build.sanitized)
        self.assertEqual(config.build.sanitized.env["ASAN_OPTIONS"], "abort_on_error=1")
        self.assertEqual(config.limits.timeout_seconds, 3.5)
        self.assertEqual(config.limits.memory_mb, 128)
        self.assertEqual(config.limits.env["FOO"], "bar")

    def test_unknown_key_rejected(self) -> None:
        body = self._valid_body() + "\n[oops]\nx = 1\n"
        with self.assertRaisesRegex(ConfigError, "unknown key"):
            load_config(self._write(body))

    def test_duplicate_test_id_rejected(self) -> None:
        body = self._valid_body() + """
[[tests]]
id = "valid"
kind = "functional"
input = "inputs/valid.txt"
input_mode = "stdin"
expect_exit = 0
"""
        with self.assertRaisesRegex(ConfigError, "duplicate test id"):
            load_config(self._write(body))

    def test_missing_input_rejected(self) -> None:
        body = self._valid_body().replace("inputs/valid.txt", "inputs/missing.txt")
        with self.assertRaisesRegex(ConfigError, "is not a file"):
            load_config(self._write(body))

    def test_functional_test_requires_expect_exit(self) -> None:
        body = self._valid_body().replace("expect_exit = 0", "")
        with self.assertRaisesRegex(ConfigError, "expect_exit is required"):
            load_config(self._write(body))

    def test_invalid_kind_rejected(self) -> None:
        body = self._valid_body().replace('kind = "functional"', 'kind = "smoke"')
        with self.assertRaisesRegex(ConfigError, "kind must be one of"):
            load_config(self._write(body))

    def test_bad_regex_rejected(self) -> None:
        body = self._valid_body() + 'stdout_regex = "("\n'
        with self.assertRaisesRegex(ConfigError, "stdout_regex is invalid"):
            load_config(self._write(body))

    def test_relative_repo_path(self) -> None:
        body = self._valid_body().replace(f'repo = "{self.repo}"', 'repo = "../repo"')
        config = load_config(self._write(body))
        self.assertEqual(config.target.repo, self.repo.resolve())

    def test_missing_config_file(self) -> None:
        with self.assertRaisesRegex(ConfigError, "config file not found"):
            load_config(self.root / "nope.toml")


if __name__ == "__main__":
    unittest.main()
