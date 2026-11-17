#!/usr/bin/env python3
"""Unit tests for .github/ci/local/steps.py's ::add-mask:: handling (the
local CI runner masks as GitHub does): the command line is never written,
every later occurrence of the value and its common encodings is ***, in
log() and in a step's output stream.

Run: python3 tests/test_local_steps.py (or python3 -m pytest -q tests/)
"""
import base64
import io
import os
import subprocess
import sys
import types
import unittest
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / ".github" / "ci" / "local"))
try:
    import yaml  # noqa: F401  (steps.py reads ci.yml with it; masking doesn't)
except ImportError:
    sys.modules["yaml"] = types.ModuleType("yaml")
import steps  # noqa: E402

SECRET = "s3cr3t/T0ken+with=chars&more"


class MaskerTest(unittest.TestCase):
    def setUp(self):
        self.m = steps.Masker()

    def test_command_line_is_never_written(self):
        self.assertIsNone(self.m.line(f"::add-mask::{SECRET}\n"))
        self.assertIsNone(self.m.line(f"  ::add-mask::{SECRET}"))

    def test_later_occurrences_and_encodings_are_masked(self):
        self.m.line(f"::add-mask::{SECRET}\n")
        for form in (SECRET, urllib.parse.quote(SECRET, safe=""), urllib.parse.quote_plus(SECRET),
                     base64.b64encode(SECRET.encode()).decode().rstrip("=")):
            out = self.m.line(f"before {form} after\n")
            self.assertEqual(out, "before *** after\n", form)

    def test_unmasked_text_is_unchanged(self):
        self.assertEqual(self.m.line("nothing secret here\n"), "nothing secret here\n")
        self.m.line("::add-mask::abcdef\n")
        self.assertEqual(self.m.line("nothing secret here\n"), "nothing secret here\n")

    def test_multiline_value_each_line(self):
        self.m.add("first-line-value\nsecond-line-value")
        self.assertEqual(self.m.line("x first-line-value y second-line-value\n"), "x *** y ***\n")

    def test_longest_value_first(self):
        self.m.add("abc")
        self.m.add("abcdef")
        self.assertEqual(self.m.line("abcdef abc\n"), "*** ***\n")

    def test_empty_mask_is_ignored(self):
        self.assertIsNone(self.m.line("::add-mask::\n"))
        self.assertEqual(self.m.line("text\n"), "text\n")


class StreamTest(unittest.TestCase):
    def test_a_steps_output_is_masked(self):
        """_pump: a child's ::add-mask:: line vanishes, its value is *** after."""
        m = steps.Masker()
        p = subprocess.Popen(["sh", "-c", 'echo "::add-mask::$V"; echo "token=$V"; echo "plain"'],
                             env=dict(os.environ, V=SECRET), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = io.StringIO()
        steps._pump(p.stdout, m, out)
        p.wait()
        self.assertEqual(out.getvalue(), "token=***\nplain\n")
        self.assertNotIn(SECRET, out.getvalue())

    def test_log_masks_and_drops_commands(self):
        buf = io.StringIO()
        old, steps.MASK = steps.MASK, steps.Masker()
        try:
            sys.stdout, real = buf, sys.stdout
            try:
                steps.log(f"::add-mask::{SECRET}")
                steps.log(f"summary: {SECRET}")
            finally:
                sys.stdout = real
        finally:
            steps.MASK = old
        self.assertEqual(buf.getvalue(), "summary: ***\n")


if __name__ == "__main__":
    unittest.main(verbosity=1)
