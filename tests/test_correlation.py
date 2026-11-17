from __future__ import annotations

import unittest
from pathlib import Path

from patchproof.analysis import AnalysisContext
from patchproof.analyzers.correlation import (
    CorrelationAnalyzer,
    NormalizedFrame,
    classify_patch_status,
    correlate_caller_callee,
    correlate_frames_to_diff,
    extract_user_frames,
    parse_diff,
    serialize_correlation_finding,
    symbolize_frames,
)
from patchproof.analyzers.crash import classify_stderr
from patchproof.model import TestObservation


class DiffParsingTests(unittest.TestCase):
    def test_parse_single_hunk(self):
        diff = """diff --git a/src/parser.c b/src/parser.c
index 1111111..2222222 100644
--- a/src/parser.c
+++ b/src/parser.c
@@ -10,3 +10,5 @@ static int parse(void)
   if (len < 0) {
-    return 0;
+    return 1;
+  }
+  check_bounds(len);
"""
        files = parse_diff(diff)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].path, "src/parser.c")
        self.assertEqual(len(files[0].hunks), 1)
        hunk = files[0].hunks[0]
        self.assertEqual(hunk.old_start, 10)
        self.assertEqual(hunk.old_count, 3)
        self.assertEqual(hunk.new_start, 10)
        self.assertEqual(hunk.new_count, 5)
        self.assertEqual(hunk.lines[0], "   if (len < 0) {")
        self.assertEqual(hunk.lines[1], "-    return 0;")
        self.assertEqual(hunk.lines[2], "+    return 1;")
        self.assertEqual(hunk.new_range, (10, 14))

    def test_parse_multiple_files(self):
        diff = """diff --git a/src/parser.c b/src/parser.c
--- a/src/parser.c
+++ b/src/parser.c
@@ -1,2 +1,2 @@
-old
+new

diff --git a/src/util.c b/src/util.c
--- a/src/util.c
+++ b/src/util.c
@@ -20,2 +20,3 @@
   int x = 0;
+  x += 1;
"""
        files = parse_diff(diff)
        self.assertEqual([f.path for f in files], ["src/parser.c", "src/util.c"])
        self.assertEqual(len(files[0].hunks), 1)
        self.assertEqual(len(files[1].hunks), 1)

    def test_parse_diff_handles_zero_line_hunks(self):
        diff = """diff --git a/src/newfile.c b/src/newfile.c
new file mode 100644
--- /dev/null/null
+++ b/src/newfile.c
@@ -0,0 +1,3 @@
+int main(void) {
+    return 0;
+}
"""
        files = parse_diff(diff)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].path, "src/newfile.c")
        self.assertEqual(files[0].hunks[0].new_range, (1, 3))

    def test_extract_user_frames_skips_runtime_frames(self):
        report = """==123== ERROR: AddressSanitizer: heap-buffer-overflow in /tmp/test
#0 0x111111 in parse_header at src/parser.c:42
#1 0x222222 in main at src/main.c:10
#2 0x333333 in __libc_start_main in /usr/lib/libc.so.6
"""
        frames = extract_user_frames(report)
        self.assertEqual([f.function for f in frames], ["parse_header", "main"])
        self.assertEqual(frames[0].line, 42)
        self.assertEqual(frames[1].file, "src/main.c")

    def test_extract_user_frames_reads_real_asan_paths(self):
        # Real gcc ASan output: "in func /abs/path/file.c:line", no "at".
        report = (Path(__file__).parent / "fixtures" / "crash" / "asan-stack.txt").read_text()
        frames = extract_user_frames(report)
        self.assertEqual(frames[0].function, "stack_overflow")
        self.assertTrue(frames[0].file.endswith("zoo.c"))
        self.assertEqual(frames[0].line, 11)
        changed = parse_diff("--- a/tests/fixtures/crash/zoo.c\n+++ b/tests/fixtures/crash/zoo.c\n@@ -11 +11 @@\n-x\n+y\n")
        self.assertEqual(len(correlate_frames_to_diff(frames[:1], changed, side="old")), 1)

    def test_extract_user_frames_handles_blank_report(self):
        self.assertEqual(extract_user_frames(""), [])

    def test_symbolize_frames_uses_addr2line(self):
        def fake_runner(command, capture_output, text, check):
            self.assertEqual(command[:3], ["addr2line", "-f", "-C"])
            self.assertEqual(command[-1], "0x1234")
            return type(
                "Completed",
                (),
                {"stdout": "src/parser.c:42\n"},
            )()

        frames = [
            NormalizedFrame(
                function="parse_header",
                file=None,
                line=None,
                raw="#0 0x1234 in parse_header at src/parser.c:42",
            )
        ]
        mapped = symbolize_frames(frames, "/tmp/app", symbolizer="addr2line", runner=fake_runner)
        self.assertEqual(mapped[0].file, "src/parser.c")
        self.assertEqual(mapped[0].line, 42)

    def test_symbolize_frames_falls_back_gracefully(self):
        frames = [NormalizedFrame(function="main", raw="#0 0x9999 in main")]
        mapped = symbolize_frames(frames, "/tmp/app", symbolizer="addr2line", runner=lambda *args, **kwargs: (_ for _ in ()).throw(OSError("missing tool")))
        self.assertEqual(mapped, frames)

    def test_correlate_frames_to_diff(self):
        diff = """diff --git a/src/parser.c b/src/parser.c
--- a/src/parser.c
+++ b/src/parser.c
@@ -10,3 +10,5 @@
   if (len < 0) {
-    return 0;
+    return 1;
+  }
+  validate(len);
"""
        frames = [
            NormalizedFrame(function="parse_header", file="src/parser.c", line=12, raw="#0 0x1234 in parse_header at src/parser.c:12")
        ]
        matches = correlate_frames_to_diff(frames, parse_diff(diff))
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].file, "src/parser.c")
        self.assertEqual(matches[0].confidence, "direct")

    def test_correlate_caller_callee(self):
        diff = """diff --git a/src/validate.c b/src/validate.c
--- a/src/validate.c
+++ b/src/validate.c
@@ -5,2 +5,3 @@
 int validate(int len) {
-  if (len <= 0) return 0;
+  if (len <= 0) return 1;
+  return 0;
 }
"""
        frames = [
            NormalizedFrame(function="parse_header", file="src/parser.c", line=42, raw="#0 0x1234 in parse_header at src/parser.c:42")
        ]
        matches = correlate_caller_callee(parse_diff(diff), frames, caller_function="validate", callee_function="parse_header")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].confidence, "caller-callee")


class StatusClassificationTests(unittest.TestCase):
    def test_fixed_status(self):
        self.assertEqual(
            classify_patch_status(base_reproduced=True, patched_reproduced=False, has_match=True),
            "fixed",
        )

    def test_incomplete_status(self):
        self.assertEqual(
            classify_patch_status(base_reproduced=True, patched_reproduced=True, has_match=True),
            "incomplete",
        )

    def test_new_status(self):
        self.assertEqual(
            classify_patch_status(base_reproduced=False, patched_reproduced=True, has_match=True),
            "new",
        )

    def test_functional_regression_status(self):
        self.assertEqual(
            classify_patch_status(functional_regression=True, has_match=True),
            "functional_regression",
        )

    def test_inconclusive_status(self):
        self.assertEqual(
            classify_patch_status(base_reproduced=True, patched_reproduced=False, has_match=False),
            "inconclusive",
        )
        self.assertEqual(
            classify_patch_status(base_reproduced=True, patched_reproduced=False, has_match=True, ambiguous=True),
            "inconclusive",
        )

    def test_status_uses_part2_confirmed_classification(self):
        asan = classify_stderr(
            "==123== ERROR: AddressSanitizer: heap-buffer-overflow in src/parser.c:42\n"
            "#0 0x111111 in parse_header at src/parser.c:42\n"
        )
        self.assertIsNotNone(asan)
        self.assertEqual(
            classify_patch_status(
                base_reproduced=True,
                patched_reproduced=False,
                has_match=True,
                classification=asan,
            ),
            "fixed",
        )
        self.assertEqual(
            classify_patch_status(
                base_reproduced=True,
                patched_reproduced=False,
                has_match=True,
                classification=type("Weak", (), {"confirmed": False})(),
            ),
            "inconclusive",
        )


class SerializationTests(unittest.TestCase):
    def test_serialize_finding_uses_exact_observation_refs(self):
        base = TestObservation(
            test_id="cve-1",
            kind="security",
            version="base",
            variant="sanitized",
            outcome="crash",
            expectation_met=False,
            exit_code=None,
            signal=6,
            timed_out=False,
            duration_seconds=0.1,
            stderr="==123== ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x1111 in parse_header at src/parser.c:42\n",
        )
        patched = TestObservation(
            test_id="cve-1",
            kind="security",
            version="patched",
            variant="sanitized",
            outcome="pass",
            expectation_met=True,
            exit_code=0,
            signal=None,
            timed_out=False,
            duration_seconds=0.1,
        )

        finding = serialize_correlation_finding(
            finding_id="CORR-1",
            title="heap-buffer-overflow correlation",
            status="fixed",
            summary="base reproduced, patched did not",
            observations=[base, patched],
            matches=[],
            frames=[
                NormalizedFrame(function="parse_header", file="src/parser.c", line=42, raw="#0 ...")
            ],
            diff_hunks=[{"file": "src/parser.c", "ranges": [(10, 12)]}],
        )

        self.assertEqual(
            finding.evidence["observations"],
            [
                {"test_id": "cve-1", "version": "base", "variant": "sanitized"},
                {"test_id": "cve-1", "version": "patched", "variant": "sanitized"},
            ],
        )
        self.assertEqual(finding.evidence["diff_hunks"][0]["file"], "src/parser.c")
        self.assertEqual(finding.status.value, "fixed")

    def test_analyzer_serializes_multiple_findings_without_losing_metadata(self):
        context = AnalysisContext(
            config=None,
            base_worktree=None,
            patched_worktree=None,
            diff="""diff --git a/src/parser.c b/src/parser.c
--- a/src/parser.c
+++ b/src/parser.c
@@ -10,2 +10,3 @@
-  return 0;
+  return 1;
+  validate(len);
""",
            observations=[
                TestObservation(
                    test_id="bg-1",
                    kind="security",
                    version="base",
                    variant="sanitized",
                    outcome="crash",
                    expectation_met=False,
                    exit_code=None,
                    signal=11,
                    timed_out=False,
                    duration_seconds=0.1,
                    stderr="#0 0x1111 in parse_header at src/parser.c:11\n",
                ),
                TestObservation(
                    test_id="bg-1",
                    kind="security",
                    version="patched",
                    variant="sanitized",
                    outcome="pass",
                    expectation_met=True,
                    exit_code=0,
                    signal=None,
                    timed_out=False,
                    duration_seconds=0.1,
                    stderr="",
                ),
            ],
            out_dir=None,
        )
        findings = CorrelationAnalyzer().analyze(context)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["observations"][0]["test_id"], "bg-1")
        self.assertEqual(findings[0].evidence["diff_hunks"][0]["file"], "src/parser.c")

    def test_analyzer_ignores_non_security_observations(self):
        context = AnalysisContext(
            config=None,
            base_worktree=None,
            patched_worktree=None,
            diff="""diff --git a/src/parser.c b/src/parser.c
--- a/src/parser.c
+++ b/src/parser.c
@@ -5,2 +5,3 @@
-  if (len <= 0) return 0;
+  if (len <= 0) return 1;
+  return 0;
""",
            observations=[
                TestObservation(
                    test_id="valid",
                    kind="functional",
                    version="base",
                    variant="release",
                    outcome="pass",
                    expectation_met=True,
                    exit_code=0,
                    signal=None,
                    timed_out=False,
                    duration_seconds=0.1,
                ),
                TestObservation(
                    test_id="valid",
                    kind="functional",
                    version="patched",
                    variant="release",
                    outcome="pass",
                    expectation_met=True,
                    exit_code=0,
                    signal=None,
                    timed_out=False,
                    duration_seconds=0.1,
                ),
            ],
            out_dir=None,
        )
        self.assertEqual(CorrelationAnalyzer().analyze(context), [])

    def test_missing_observation_refs_keep_result_inconclusive(self):
        finding = serialize_correlation_finding(
            finding_id="CORR-2",
            title="incomplete evidence",
            status="fixed",
            summary="weak evidence",
            observations=[],
        )
        self.assertFalse(finding.confirmed)
        self.assertEqual(finding.status, type(finding.status)("inconclusive"))


if __name__ == "__main__":
    unittest.main()
