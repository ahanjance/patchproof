from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from helpers import BENIGN_APP, CRASH_APP, REGRESSION_APP, commit, init_repo

from patchproof.config import load_config
from patchproof.model import Finding, FindingStatus
from patchproof.pipeline import execute
from patchproof.report import render_summary, to_jsonable, write_report


class CrashAnalyzer:
    name = "fake-crash"

    def analyze(self, context):
        refs = [
            {
                "test_id": observation.test_id,
                "version": observation.version,
                "variant": observation.variant,
            }
            for observation in context.observations
            if observation.kind == "security" and observation.outcome == "crash"
        ]
        return [
            Finding(
                id="SEC-1",
                title="confirmed memory error",
                status=FindingStatus.INCOMPLETE,
                evidence={"observations": refs},
                analyzer=self.name,
            )
        ]


class BrokenAnalyzer:
    name = "broken"

    def analyze(self, context):
        raise RuntimeError("analyzer exploded")


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.out = self.root / "out"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _target(self, base_source: str, patched_source: str) -> Path:
        repo = init_repo(
            self.root / "repo", {"app.c": base_source}, tag="base"
        )
        commit(
            repo,
            {"app.c": patched_source},
            message="patched",
            tag="patched",
            allow_empty=True,
        )
        config_dir = self.root / "config"
        (config_dir / "inputs").mkdir(parents=True)
        (config_dir / "inputs" / "valid.txt").write_text("5\n", encoding="utf-8")
        (config_dir / "inputs" / "zero.txt").write_text("0\n", encoding="utf-8")
        (config_dir / "inputs" / "negative.txt").write_text("-1\n", encoding="utf-8")
        return repo

    def _config(
        self,
        repo: Path,
        test_blocks: str,
        *,
        build_command: str = '["cc", "-O0", "-g", "-o", "app", "app.c"]',
        sanitized: bool = False,
    ) -> Path:
        sanitized_block = ""
        if sanitized:
            sanitized_block = """
[build.sanitized]
command = ["cc", "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-o", "app-asan", "app.c"]
binary = "app-asan"
"""
        text = f"""
[target]
name = "pipeline-demo"
repo = "{repo}"
base_ref = "base"
patched_ref = "patched"

[build]
command = {build_command}
binary = "app"
{sanitized_block}
[run]
timeout_seconds = 10
memory_mb = 256
cpu_seconds = 5
file_size_mb = 16

{test_blocks}
"""
        path = self.root / "config" / "patchproof.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def _run(self, config_path: Path, analyzers=()):
        config = load_config(config_path)
        return execute(
            config,
            out_root=self.out,
            analyzers=analyzers,
        )

    def test_correct_patch_exits_zero_and_writes_report(self) -> None:
        repo = self._target(BENIGN_APP, BENIGN_APP)
        config_path = self._config(
            repo,
            """
[[tests]]
id = "valid"
kind = "functional"
input_mode = "stdin"
input = "inputs/valid.txt"
expect_exit = 0
stdout_contains = "OK 5"
""",
        )
        report = self._run(config_path)
        self.assertEqual(report.verdict.exit_code, 0)
        self.assertEqual(len(report.builds), 2)
        self.assertTrue(all(item.ok for item in report.builds))
        self.assertEqual(len(report.observations), 2)
        self.assertTrue(all(item.outcome == "pass" for item in report.observations))
        self.assertTrue((Path(report.run["out_dir"]) / "patch.diff").is_file())
        self.assertTrue(Path(report.target["diff_path"]).is_file())

        data = to_jsonable(report)
        report_path, summary_path = write_report(report, report.run["out_dir"])
        self.assertTrue(report_path.is_file())
        self.assertTrue(summary_path.is_file())
        persisted = json.loads(report_path.read_text())
        self.assertEqual(persisted["verdict"]["exit_code"], 0)
        self.assertIn("PASS", render_summary(persisted))

        # Worktrees are disposable by default.
        self.assertFalse((Path(report.run["out_dir"]) / "worktrees" / "base").exists())

    def test_regression_patch_exits_20(self) -> None:
        repo = self._target(BENIGN_APP, REGRESSION_APP)
        config_path = self._config(
            repo,
            """
[[tests]]
id = "valid-zero"
kind = "boundary"
input_mode = "stdin"
input = "inputs/zero.txt"
expect_exit = 0
stdout_contains = "OK 0"
""",
        )
        report = self._run(config_path)
        self.assertEqual(report.verdict.exit_code, 20)
        self.assertEqual(report.verdict.status, "FUNC_REGRESSION")
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].status, FindingStatus.FUNCTIONAL_REGRESSION)
        self.assertIn("valid-zero", report.findings[0].id)

    def test_build_failure_exits_30_without_running_tests(self) -> None:
        repo = self._target(BENIGN_APP, BENIGN_APP)
        config_path = self._config(
            repo,
            """
[[tests]]
id = "valid"
kind = "functional"
input_mode = "stdin"
input = "inputs/valid.txt"
expect_exit = 0
""",
            build_command='["false"]',
        )
        report = self._run(config_path)
        self.assertEqual(report.verdict.exit_code, 30)
        self.assertEqual(report.observations, [])
        self.assertEqual(len(report.builds), 2)
        self.assertTrue(all(not item.ok for item in report.builds))

    def test_unclassified_crash_exits_40(self) -> None:
        repo = self._target(CRASH_APP, CRASH_APP)
        config_path = self._config(
            repo,
            """
[[tests]]
id = "negative-input"
kind = "security"
input_mode = "stdin"
input = "inputs/negative.txt"
""",
        )
        report = self._run(config_path)
        self.assertEqual(report.verdict.exit_code, 40)
        self.assertEqual(report.findings, [])
        self.assertEqual(len(report.observations), 2)
        self.assertTrue(all(item.outcome == "crash" for item in report.observations))

    def test_analyzer_can_confirm_a_crash(self) -> None:
        repo = self._target(CRASH_APP, CRASH_APP)
        config_path = self._config(
            repo,
            """
[[tests]]
id = "negative-input"
kind = "security"
input_mode = "stdin"
input = "inputs/negative.txt"
""",
        )
        report = self._run(config_path, analyzers=[CrashAnalyzer()])
        self.assertEqual(report.verdict.exit_code, 10)
        self.assertEqual(report.verdict.status, "VULN_REMAINS")
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].evidence["observations"][0]["test_id"], "negative-input")

    def test_analyzer_failure_forces_inconclusive(self) -> None:
        repo = self._target(BENIGN_APP, BENIGN_APP)
        config_path = self._config(
            repo,
            """
[[tests]]
id = "valid"
kind = "functional"
input_mode = "stdin"
input = "inputs/valid.txt"
expect_exit = 0
""",
        )
        report = self._run(config_path, analyzers=[BrokenAnalyzer()])
        self.assertEqual(report.verdict.exit_code, 40)
        self.assertEqual(report.findings[0].status, FindingStatus.INCONCLUSIVE)

    def test_release_and_sanitized_builds_are_separate(self) -> None:
        repo = self._target(BENIGN_APP, BENIGN_APP)
        config_path = self._config(
            repo,
            """
[[tests]]
id = "valid"
kind = "functional"
input_mode = "stdin"
input = "inputs/valid.txt"
expect_exit = 0
stdout_contains = "OK 5"
""",
            sanitized=True,
        )
        report = self._run(config_path)
        self.assertEqual(report.verdict.exit_code, 0)
        variants = {(item.version, item.variant) for item in report.builds}
        self.assertEqual(
            variants,
            {
                ("base", "release"),
                ("base", "sanitized"),
                ("patched", "release"),
                ("patched", "sanitized"),
            },
        )
        self.assertEqual(len(report.observations), 4)
        self.assertTrue(all(item.outcome == "pass" for item in report.observations))


if __name__ == "__main__":
    unittest.main()
