"""Focused tests for Member 4 reproducer bundle generation."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from patchproof.config import (
    BuildConfig,
    BuildVariant,
    Config,
    RunLimits,
    Target,
    TestCase,
)
from patchproof.model import BuildResult, TestObservation
from patchproof.repro import create_reproducer_bundle
from patchproof.repo import sha256_file


class ReproducerBundleTests(unittest.TestCase):
    def _make_fixture(self, root: Path, input_mode: str):
        worktree = root / "worktree"
        worktree.mkdir()
        binary = worktree / "target.py"
        binary.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib, sys\n"
            "data = pathlib.Path(sys.argv[1]).read_text() if len(sys.argv) > 1 else sys.stdin.read()\n"
            "sys.stderr.write('reproducer-error\\n')\n"
            "sys.exit(7 if data.strip() == 'trigger' else 0)\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)

        input_file = root / "trigger.txt"
        input_file.write_text("trigger\n", encoding="utf-8")

        test = TestCase(
            id="repro-test",
            kind="security",
            input_mode=input_mode,
            input_path=input_file,
        )
        config_file = root / "config.toml"
        config_file.write_text("", encoding="utf-8")
        config = Config(
            path=config_file,
            target=Target("fixture", worktree, "base", "patched"),
            build=BuildConfig(
                release=BuildVariant(("python3", "build.py"), "target.py"),
            ),
            limits=RunLimits(),
            tests=(test,),
        )
        argv = [str(binary)]
        if input_mode == "file":
            argv.append(str(input_file))

        observation = TestObservation(
            test_id="repro-test",
            kind="security",
            version="base",
            variant="release",
            outcome="fail",
            expectation_met=False,
            exit_code=7,
            signal=None,
            timed_out=False,
            duration_seconds=0.01,
            stdout="",
            stderr="reproducer-error\n",
            argv=argv,
            failure_reasons=["exit code 7"],
        )
        build_result = BuildResult(
            version="base",
            variant="release",
            ok=True,
            command=["python3", "build.py"],
            exit_code=0,
            signal=None,
            timed_out=False,
            duration_seconds=0.01,
            log_path=str(root / "build.log"),
            binary_path=str(binary),
            binary_sha256=sha256_file(binary),
        )
        return config, observation, build_result, worktree

    def test_file_input_is_bundled_and_replayed_three_times(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config, observation, build, worktree = self._make_fixture(root, "file")
            bundle = create_reproducer_bundle(
                config,
                observation,
                build,
                commit="0123456789abcdef",
                worktree=worktree,
                out_dir=root / "output",
            )

            metadata = json.loads((bundle / "metadata.json").read_text())
            self.assertEqual(metadata["replay_count"], 3)
            self.assertFalse(metadata["unstable"])
            self.assertTrue((bundle / "program").is_file())
            self.assertTrue((bundle / "input.txt").is_file())
            self.assertTrue(
                all(item["exit_code"] == 7 for item in metadata["replays"])
            )
            self.assertIn(str(bundle / "input.txt"), metadata["replay_command"])

    def test_stdin_input_is_bundled_and_replayed_three_times(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config, observation, build, worktree = self._make_fixture(root, "stdin")
            observation = TestObservation(
                test_id=observation.test_id,
                kind=observation.kind,
                version=observation.version,
                variant=observation.variant,
                outcome=observation.outcome,
                expectation_met=observation.expectation_met,
                exit_code=7,
                signal=None,
                timed_out=False,
                duration_seconds=0.01,
                stdout="",
                stderr="reproducer-error\n",
                argv=[str(build.binary_path)],
                failure_reasons=["exit code 7"],
            )
            bundle = create_reproducer_bundle(
                config,
                observation,
                build,
                commit="0123456789abcdef",
                worktree=worktree,
                out_dir=root / "output",
            )
            metadata = json.loads((bundle / "metadata.json").read_text())
            self.assertEqual(len(metadata["replays"]), 3)
            self.assertTrue(all(item["exit_code"] == 7 for item in metadata["replays"]))

    def test_replay_count_below_three_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config, observation, build, worktree = self._make_fixture(root, "file")
            with self.assertRaises(ValueError):
                create_reproducer_bundle(
                    config,
                    observation,
                    build,
                    commit="0123456789abcdef",
                    worktree=worktree,
                    out_dir=root / "output",
                    replay_count=2,
                )


if __name__ == "__main__":
    unittest.main()
