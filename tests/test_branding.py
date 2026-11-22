#!/usr/bin/env python3
"""The branding copies in the Keycloak login theme (polish batch 1): the
favicon and the Raised-gate mark (dark variant) are byte copies of the
branding sources (sha256 pinned), and the theme's stylesheet puts the mark
above the login card. The gate (mockup gate-styles-v2 option A): the arch and
the portcullis art reuse the logo's shapes, the stylesheet draws them behind
the card with the drop / rise / still rules, and the theme's script is listed.
Stdlib only: `python3 tests/test_branding.py`."""

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


class GateTest(unittest.TestCase):
    def test_theme_properties_scripts(self):
        self.assertIn("scripts=js/portcullis-gate.js", read("theme.properties").splitlines())
        self.assertTrue(os.path.isfile(os.path.join(LOGIN, "resources", "js", "portcullis-gate.js")))

    def test_reload_replays_the_drop(self):
        js = read(os.path.join("resources", "js", "portcullis-gate.js"))
        self.assertIn('getEntriesByType("navigation")', js)
        self.assertIn('nav.type === "reload"', js)
        self.assertIn("if (!reload && now - last >= 0 && now - last < WINDOW_MS)", js)

    def test_art_reuses_the_logo(self):
        mark = read(os.path.join("resources", "img", "portcullis-mark.svg"))
        arch = read(os.path.join("resources", "img", "portcullis-arch.svg"))
        gate = read(os.path.join("resources", "img", "portcullis-gate.svg"))
        # The logo's colours: stone #e8edf5, brass #e3ac52 (the gate at 60%).
        self.assertIn('fill="#e8edf5"', mark)
        self.assertIn('fill="#e3ac52"', mark)
        self.assertIn('fill="#e8edf5"', arch)
        self.assertIn('fill="#e3ac52" opacity=".6"', gate)
        self.assertIn('viewBox="0 0 32 34"', arch)
        # The gate's bars in the top 34 units, 34 empty below: every offset
        # (-4 down, -38 up) stays within one image height (Chromium paints a
        # no-repeat SVG background past it as if it wrapped).
        self.assertIn('viewBox="0 0 32 68"', gate)
        for svg in (arch, gate):
            self.assertNotIn("<script", svg)
        # The logo's arch (a 14-radius outer, 12 inner here) run to the foot.
        self.assertIn("a14 14 0 0 1 28 0", arch)
        self.assertIn("a12 12 0 0 0-24 0", arch)

    def test_stylesheet_draws_the_gate(self):
        css = read(os.path.join("resources", "css", "portcullis.css"))
        for want in ('url("../img/portcullis-arch.svg")', 'url("../img/portcullis-gate.svg")',
                     "@keyframes pc-gate-drop", "@keyframes pc-gate-rise", "animation:pc-gate-drop 460ms",
                     'data-page-id="login-portcullis-let-through"', "animation:pc-gate-rise 560ms cubic-bezier(.2,.7,.3,1)",
                     ".pf-v5-c-alert.pf-m-danger",
                     "@media (prefers-reduced-motion:reduce)", "#keycloak-bg>.pf-v5-c-login{position:relative;z-index:1}"):
            with self.subTest(rule=want):
                self.assertIn(want, css)
        self.assertIn("background-size:calc(32 * var(--pc-u)) calc(68 * var(--pc-u))", css)
        # The Let through page rests UP (not only the animation's fill) and
        # the still / error rules never apply to it; reduced motion: down.
        self.assertIn('#keycloak-bg[data-page-id="login-portcullis-let-through"]::before{background-position-y:calc(-38 * var(--pc-u));animation:pc-gate-rise', css)
        self.assertIn('.pc-gate-still #keycloak-bg:not([data-page-id="login-portcullis-let-through"])::before', css)
        self.assertIn('#keycloak-bg:not([data-page-id="login-portcullis-let-through"]):has(', css)
        self.assertIn('#keycloak-bg[data-page-id="login-portcullis-let-through"]::before{animation:none;background-position-y:calc(-4 * var(--pc-u))}', css)
        # The drop's overshoot: 0.8 units past down (-4) at 82% of its progress.
        self.assertIn("96.09%{background-position-y:calc(-3.2 * var(--pc-u))", css)


if __name__ == "__main__":
    unittest.main(verbosity=2)
