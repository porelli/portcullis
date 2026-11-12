#!/usr/bin/env python3
"""The branding copies in the Keycloak login theme (polish batch 1): the
favicon and the Raised-gate mark (dark variant) are byte copies of the
branding sources (sha256 pinned), and the theme's stylesheet puts the mark
above the login card. Stdlib only: `python3 tests/test_branding.py`."""

import hashlib
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LOGIN = os.path.join(HERE, "..", "keycloak", "themes", "portcullis", "login")

PINNED = {
    os.path.join("resources", "img", "favicon.ico"):
        "d709cb96a8d612fc471fa02914d674f03972146a1680db98f97f93e46bcea7a1",  # favicon.ico
    os.path.join("resources", "img", "portcullis-mark.svg"):
        "a63ddab1ce0eac394cdbc7547f9fcbc9bf6947060601dd5202527222cef97bfa",  # concept-1-mark-dark.svg
}


def read(rel, mode="r"):
    with open(os.path.join(LOGIN, rel), mode) as f:
        return f.read()


class ThemeBrandingTest(unittest.TestCase):
    def test_copies_pinned(self):
        for rel, want in PINNED.items():
            with self.subTest(file=rel):
                self.assertEqual(hashlib.sha256(read(rel, "rb")).hexdigest(), want)

    def test_theme_properties_styles(self):
        lines = read("theme.properties").splitlines()
        self.assertIn("styles=css/styles.css css/portcullis.css", lines)

    def test_stylesheet_places_mark(self):
        css = read(os.path.join("resources", "css", "portcullis.css"))
        self.assertIn("../img/portcullis-mark.svg", css)
        self.assertIn("#kc-header-wrapper::before", css)


if __name__ == "__main__":
    unittest.main(verbosity=2)
