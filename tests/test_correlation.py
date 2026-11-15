from __future__ import annotations

import unittest

from patchproof.analyzers.correlation import (
    NormalizedFrame,
    correlate_caller_callee,
    correlate_frames_to_diff,
    extract_user_frames,
    parse_diff,
    symbolize_frames,
)


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


if __name__ == "__main__":
    unittest.main()
