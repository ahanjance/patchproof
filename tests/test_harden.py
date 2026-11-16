import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from patchproof.harden import inspect_binary, compare_hardening


HEADER_PIE = """
ELF Header:
  Type: DYN (Position-Independent Executable file)
"""

HEADER_EXEC = """
ELF Header:
  Type: EXEC (Executable file)
"""

PROGRAM_HEADERS_NX = """
Program Headers:
  GNU_STACK      0x000000 0x000000 0x000000 0x000000 0x000000 RW  0x10
  GNU_RELRO      0x000000 0x000000 0x000000 0x000000 0x000000 R   0x1
"""

PROGRAM_HEADERS_EXEC = """
Program Headers:
  GNU_STACK      0x000000 0x000000 0x000000 0x000000 0x000000 RWE 0x10
  GNU_RELRO      0x000000 0x000000 0x000000 0x000000 0x000000 R   0x1
"""

DYNAMIC_FULL_RELRO = """
Dynamic section:
 0x000000000000001e (FLAGS)              BIND_NOW
"""

DYNAMIC_PARTIAL_RELRO = """
Dynamic section:
 0x0000000000000004 (HASH)               0x400000
"""

SYMBOLS_WITH_CANARY = """
Symbol table '.dynsym':
  1: 0000000000000000     0 FUNC GLOBAL DEFAULT UND __stack_chk_fail
"""

SYMBOLS_WITHOUT_CANARY = """
Symbol table '.dynsym':
  1: 0000000000000000     0 FUNC GLOBAL DEFAULT UND puts
"""


class HardeningTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

        self.base = self.root / "base"
        self.patched = self.root / "patched"

        self.base.write_bytes(b"fake ELF")
        self.patched.write_bytes(b"fake ELF")

    def tearDown(self):
        self.temp.cleanup()

    def fake_readelf(self, command, **kwargs):
        binary = Path(command[-1])
        is_base = binary.name == "base"
        option = command[2]

        if option == "-h":
            output = HEADER_PIE if is_base else HEADER_EXEC
        elif option == "-l":
            output = PROGRAM_HEADERS_NX if is_base else PROGRAM_HEADERS_EXEC
        elif option == "-d":
            output = DYNAMIC_FULL_RELRO if is_base else DYNAMIC_PARTIAL_RELRO
        elif option == "-s":
            output = SYMBOLS_WITH_CANARY if is_base else SYMBOLS_WITHOUT_CANARY
        else:
            raise AssertionError(f"Unexpected readelf option: {option}")

        class Result:
            returncode = 0
            stdout = output
            stderr = ""

        return Result()

    @patch("patchproof.harden.shutil.which", return_value="/usr/bin/readelf")
    @patch("patchproof.harden.subprocess.run")
    def test_inspect_binary_detects_security_properties(
        self, mock_run, mock_which
    ):
        mock_run.side_effect = self.fake_readelf

        result = inspect_binary(self.base)

        self.assertTrue(result["nx"])
        self.assertTrue(result["pie"])
        self.assertEqual(result["relro"], "full")
        self.assertTrue(result["stack_canary"])

    @patch("patchproof.harden.shutil.which", return_value="/usr/bin/readelf")
    @patch("patchproof.harden.subprocess.run")
    def test_compare_detects_weakened_protections(
        self, mock_run, mock_which
    ):
        mock_run.side_effect = self.fake_readelf

        result = compare_hardening(
            self.base,
            self.patched,
            out_dir=self.root / "report",
        )

        self.assertFalse(result["patched"]["nx"])
        self.assertFalse(result["patched"]["pie"])
        self.assertEqual(result["patched"]["relro"], "partial")
        self.assertFalse(result["patched"]["stack_canary"])

        self.assertEqual(len(result["warnings"]), 4)
        self.assertTrue(Path(result["report_path"]).is_file())

        self.assertTrue(
            (self.root / "report" / "base" / "readelf-header.txt").is_file()
        )
        self.assertTrue(
            (self.root / "report" / "patched" / "readelf-symbols.txt").is_file()
        )

    def test_missing_binary_is_rejected(self):
        with self.assertRaises(FileNotFoundError):
            inspect_binary(self.root / "missing-binary")


if __name__ == "__main__":
    unittest.main()
