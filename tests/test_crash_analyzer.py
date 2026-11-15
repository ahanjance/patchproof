from __future__ import annotations

import platform
import shutil
import signal
import tempfile
import unittest
from pathlib import Path

from helpers import commit, init_repo

from patchproof.analysis import AnalysisContext
from patchproof.analyzers.crash import CrashAnalyzer, classify, classify_stderr
from patchproof.config import load_config
from patchproof.model import FindingStatus, TestObservation
from patchproof.pipeline import execute

FIXTURES = Path(__file__).parent / "fixtures" / "crash"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def obs(test_id, version, variant, *, stderr="", sig=None, timed_out=False, kind="security"):
    return TestObservation(
        test_id=test_id,
        kind=kind,
        version=version,
        variant=variant,
        outcome="timeout" if timed_out else ("crash" if sig else "pass"),
        expectation_met=sig is None and not timed_out,
        exit_code=None if sig else 0,
        signal=sig,
        timed_out=timed_out,
        duration_seconds=0.1,
        stderr=stderr,
    )


def analyze(observations):
    context = AnalysisContext(
        config=None, base_worktree=Path("."), patched_worktree=Path("."),
        diff="", observations=observations, out_dir=Path("."),
    )
    return CrashAnalyzer().analyze(context)


class ClassifyFixtureTests(unittest.TestCase):
    """Real ASan/UBSan/glibc output captured by tests/fixtures/crash/gen.sh."""

    def check(self, name, error_type, mechanism, top_frame=None):
        found = classify_stderr(fixture(name))
        self.assertIsNotNone(found, name)
        self.assertEqual((found.error_type, found.mechanism), (error_type, mechanism), name)
        self.assertTrue(found.confirmed)
        if top_frame:
            self.assertEqual(found.frames[0], top_frame, name)

    def test_stack_buffer_overflow_skips_interceptor_frame(self):
        self.check("asan-stack.txt", "stack-buffer-overflow", "asan", "stack_overflow")

    def test_heap_buffer_overflow_records_access(self):
        self.check("asan-heap.txt", "heap-buffer-overflow", "asan", "main")
        self.assertEqual(classify_stderr(fixture("asan-heap.txt")).access, "WRITE of size 1")

    def test_global_overflow_caught_by_ubsan_bounds_first(self):
        # -fsanitize=undefined includes bounds checks, which fire before ASan.
        self.check("asan-global.txt", "out-of-bounds-index", "ubsan", "main")

    def test_use_after_free(self):
        self.check("asan-uaf.txt", "use-after-free", "asan", "main")

    def test_double_free(self):
        self.check("asan-double.txt", "double-free", "asan", "main")

    def test_null_dereference(self):
        found = classify_stderr(fixture("asan-null.txt"))
        self.assertEqual(found.error_type, "null-dereference")

    def test_division_by_zero(self):
        self.check("asan-div.txt", "division-by-zero", "ubsan")

    def test_release_canary_needs_the_abort(self):
        text = fixture("release-stack.txt")
        aborted = classify(obs("t", "base", "release", stderr=text, sig=signal.SIGABRT), text)
        self.assertEqual((aborted.error_type, aborted.mechanism), ("stack-smashing", "stack-canary"))
        self.assertIsNone(classify(obs("t", "base", "release", stderr=text), text))

    def test_release_glibc_double_free(self):
        text = fixture("release-double.txt")
        found = classify(obs("t", "base", "release", stderr=text, sig=signal.SIGABRT), text)
        self.assertEqual((found.error_type, found.mechanism), ("double-free", "glibc-malloc"))

    def test_clean_run_is_not_classified(self):
        self.assertIsNone(classify(obs("t", "base", "release", stderr="ok\n"), "ok\n"))


class AnalyzerStatusTests(unittest.TestCase):
    heap = fixture("asan-heap.txt")
    uaf = fixture("asan-uaf.txt")

    def test_same_signature_on_both_versions_is_incomplete(self):
        findings = analyze([
            obs("cve", "base", "sanitized", stderr=self.heap, sig=signal.SIGABRT),
            obs("bypass", "patched", "sanitized", stderr=self.heap, sig=signal.SIGABRT),
        ])
        self.assertEqual([f.status for f in findings], [FindingStatus.INCOMPLETE])
        self.assertEqual(len(findings[0].evidence["observations"]), 2)

    def test_base_only_is_fixed_and_patched_only_is_new(self):
        findings = analyze([
            obs("cve", "base", "sanitized", stderr=self.heap, sig=signal.SIGABRT),
            obs("other", "patched", "sanitized", stderr=self.uaf, sig=signal.SIGABRT),
        ])
        statuses = {f.evidence["error_type"]: f.status for f in findings}
        self.assertEqual(statuses, {
            "heap-buffer-overflow": FindingStatus.FIXED,
            "use-after-free": FindingStatus.NEW,
        })

    def test_release_signal_joins_its_sanitized_twin(self):
        findings = analyze([
            obs("cve", "base", "sanitized", stderr=self.heap, sig=signal.SIGABRT),
            obs("cve", "base", "release", sig=signal.SIGSEGV),
        ])
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].confirmed)
        self.assertEqual(findings[0].evidence["mechanisms"], ["asan", "os-signal"])

    def test_bare_signal_and_timeout_stay_inconclusive(self):
        findings = analyze([
            obs("cve", "base", "sanitized", stderr=self.heap, sig=signal.SIGABRT),
            obs("odd", "patched", "release", sig=signal.SIGSEGV, kind="invalid"),
            obs("slow", "patched", "release", timed_out=True, kind="invalid"),
        ])
        loose = [f for f in findings if f.evidence["error_type"] in {"invalid-memory-access", "timeout"}]
        self.assertEqual(len(loose), 2)
        for finding in loose:
            self.assertFalse(finding.confirmed)
            self.assertEqual(finding.status, FindingStatus.INCONCLUSIVE)

    def test_security_tests_without_base_reproduction_are_inconclusive(self):
        findings = analyze([obs("cve", "base", "sanitized"), obs("cve", "patched", "sanitized")])
        self.assertEqual([f.id for f in findings], ["SEC-base-not-reproduced"])

    def test_signature_ignores_test_name_and_addresses(self):
        renamed = self.heap.replace("0x", "0x7")
        a = classify_stderr(self.heap).signature
        b = classify_stderr(renamed).signature
        self.assertEqual(a, b)


VULN = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char line[256];
    if (!fgets(line, sizeof line, stdin)) return 1;
    size_t n = strcspn(line, "\n");
    char *buf = malloc(8);
    memcpy(buf, line, n);           /* heap overflow for n > 8 */
    printf("OK %zu\n", n);
    free(buf);
    return 0;
}
"""
INCOMPLETE = VULN.replace("memcpy(buf, line, n);", "if (n == 32) return 2;\n    memcpy(buf, line, n);")
CORRECT = VULN.replace("memcpy(buf, line, n);", "if (n > 8) return 2;\n    memcpy(buf, line, n);")


@unittest.skipUnless(platform.system() == "Linux" and shutil.which("cc"), "needs Linux + cc with ASan")
class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def run_patch(self, patched_source):
        repo = init_repo(self.root / "repo", {"app.c": VULN}, tag="base")
        commit(repo, {"app.c": patched_source}, tag="patched", allow_empty=True)
        inputs = {"ok.txt": "abc\n", "cve.txt": "A" * 32 + "\n", "bypass.txt": "B" * 20 + "\n"}
        for name, text in inputs.items():
            (self.root / name).write_text(text)
        config = self.root / "patchproof.toml"
        config.write_text(f"""
[target]
name = "e2e"
repo = "{repo}"
base_ref = "base"
patched_ref = "patched"
[build]
command = ["cc", "-O0", "-g", "-o", "app", "app.c"]
binary = "app"
[build.sanitized]
command = ["cc", "-O0", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-o", "app-asan", "app.c"]
binary = "app-asan"
[[tests]]
id = "valid"
kind = "functional"
input = "ok.txt"
expect_exit = 0
stdout_contains = "OK 3"
[[tests]]
id = "cve"
kind = "security"
input = "cve.txt"
[[tests]]
id = "bypass"
kind = "security"
input = "bypass.txt"
""")
        return execute(load_config(config), out_root=self.root / "out", analyzers=[CrashAnalyzer()])

    def test_incomplete_patch_exits_10(self):
        report = self.run_patch(INCOMPLETE)
        self.assertEqual(report.verdict.exit_code, 10, report.verdict.reasons)
        self.assertIn(FindingStatus.INCOMPLETE, [f.status for f in report.findings])

    def test_correct_patch_exits_0(self):
        report = self.run_patch(CORRECT)
        self.assertEqual(report.verdict.exit_code, 0, report.verdict.reasons)
        self.assertEqual({f.status for f in report.findings}, {FindingStatus.FIXED})


if __name__ == "__main__":
    unittest.main()
