from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from helpers import BENIGN_APP, commit, init_repo

from patchproof.cli import main


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.repo = init_repo(
            self.root / "repo", {"app.c": BENIGN_APP}, tag="base"
        )
        commit(
            self.repo,
            {"app.c": BENIGN_APP},
            message="patched",
            tag="patched",
            allow_empty=True,
        )
        self.config_dir = self.root / "cfg"
        (self.config_dir / "inputs").mkdir(parents=True)
        (self.config_dir / "inputs" / "valid.txt").write_text("5\n")
        self.config = self.config_dir / "patchproof.toml"
        self.config.write_text(self._config_text())

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _config_text(self) -> str:
        return f"""
[target]
name = "cli-demo"
repo = "{self.repo}"
base_ref = "base"
patched_ref = "patched"

[build]
command = ["cc", "-O0", "-o", "app", "app.c"]
binary = "app"

[[tests]]
id = "valid"
kind = "functional"
input_mode = "stdin"
input = "inputs/valid.txt"
expect_exit = 0
"""

    def test_version(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["version"])
        self.assertEqual(code, 0)
        self.assertIn("patchproof", output.getvalue())

    def test_validate_ok(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["validate", "-c", str(self.config)])
        self.assertEqual(code, 0)
        self.assertIn("config OK", output.getvalue())

    def test_validate_reports_missing_ref(self) -> None:
        self.config.write_text(
            self._config_text().replace('base_ref = "base"', 'base_ref = "nope"')
        )
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            code = main(["validate", "-c", str(self.config)])
        self.assertEqual(code, 30)
        self.assertIn("unknown git ref", error.getvalue())

    def test_run_end_to_end(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(
                [
                    "run",
                    "-c",
                    str(self.config),
                    "-o",
                    str(self.root / "out"),
                ]
            )
        self.assertEqual(code, 0)
        self.assertIn("Verdict: PASS", output.getvalue())
        reports = list((self.root / "out").glob("*/report.json"))
        self.assertEqual(len(reports), 1)
        self.assertEqual(json.loads(reports[0].read_text())["verdict"]["exit_code"], 0)

    def test_config_error_writes_json_report(self) -> None:
        bad = self.root / "bad.toml"
        bad.write_text("[target]\nname = 'x'\n")
        output = io.StringIO()
        error = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            code = main(["run", "-c", str(bad), "-o", str(self.root / "out")])
        self.assertEqual(code, 30)
        reports = list((self.root / "out").glob("*/report.json"))
        self.assertEqual(len(reports), 1)
        data = json.loads(reports[0].read_text())
        self.assertEqual(data["verdict"]["status"], "BUILD_OR_CONFIG_ERROR")


if __name__ == "__main__":
    unittest.main()
