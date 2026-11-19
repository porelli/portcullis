#!/usr/bin/env python3
"""Unit tests for tests/e2e/e2e_mailcheck.py (e2e_mail's pure helpers:
no stack, no network, no Playwright).

Run: python3 tests/test_e2e_mailcheck.py (or python3 -m pytest -q tests/)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "e2e"))
import e2e_mailcheck as mc  # noqa: E402

DAY = "2026-11-19"
CHANGED = f"the mail server changed on {DAY}: create a new mail password"


class PWError(Exception):
    """Stands in for playwright's Error (a plain Exception subclass)."""


ABORT = PWError("Page.goto: net::ERR_NETWORK_CHANGED at https://auth.ci.example.org/...")


class NetworkRetries(unittest.TestCase):
    def run_with(self, outcomes, tries=4):
        calls, notes, sleeps = [], [], []

        def attempt(n):
            calls.append(n)
            got = outcomes[n - 1]
            if isinstance(got, BaseException):
                raise got
            return got

        out = mc.network_retries(attempt, notes.append, "switch", tries=tries, wait=3, sleep=sleeps.append)
        return out, calls, notes, sleeps

    def test_first_attempt(self):
        out, calls, notes, sleeps = self.run_with(["ok"])
        self.assertEqual((out, calls, notes, sleeps), ("ok", [1], [], []))

    def test_goto_abort_then_ok(self):
        # Run 44449741582: page.goto itself raised ERR_NETWORK_CHANGED.
        out, calls, notes, sleeps = self.run_with([ABORT, ABORT, "ok"])
        self.assertEqual(out, "ok")
        self.assertEqual(calls, [1, 2, 3])
        self.assertEqual(len(notes), 2)
        self.assertIn("attempt 1", notes[0])
        self.assertEqual(sleeps, [3, 3])

    def test_chrome_error_page_then_ok(self):
        stuck = AssertionError("switch: no fresh-auth code (stuck at chrome-error://chromewebdata/)")
        out, calls, _, _ = self.run_with([stuck, "ok"])
        self.assertEqual((out, calls), ("ok", [1, 2]))

    def test_other_failure_not_retried(self):
        for e in (AssertionError("switch: no fresh-auth code (stuck at https://auth.ci.example.org/x)"),
                  PWError("Timeout 30000ms exceeded"), ValueError("bad")):
            with self.assertRaises(type(e)):
                self.run_with([e, "ok"])

    def test_bounded(self):
        with self.assertRaises(PWError):
            self.run_with([ABORT] * 4)
        with self.assertRaises(PWError):
            self.run_with([ABORT, ABORT], tries=2)


def row(label, status="voided", reason=CHANGED):
    r = {"id": "m" + label, "label": label, "status": status}
    if reason is not None:
        r["voided_reason"] = reason
    return r


class SwitchVoided(unittest.TestCase):
    def test_all_voided_by_the_switch(self):
        rows = [row("e2e switch"), row("e2e alice")]
        self.assertIsNone(mc.switch_voided_problem(rows, {DAY}, must=("e2e switch",)))

    def test_run_44449741582_rows(self):
        # The Hub's real answer then: status voided + the switch's reason.
        rows = [row(f"e2e extra {i}") for i in range(3)] + [row("e2e alice")]
        self.assertIsNone(mc.switch_voided_problem(rows, {DAY}))

    def test_refusals(self):
        cases = {
            "no rows": ([], ()),
            "status 'active'": ([row("a"), row("b", status="active", reason=None)], ()),
            "status 'provider_changed'": ([row("a", status="provider_changed")], ()),
            "reason 'reset by a restore'": ([row("a", reason="reset by a restore")], ()),
            "reason None": ([row("a", reason=None)], ()),
            "voided on 2026-11-18": ([row("a", reason=CHANGED.replace(DAY, "2026-11-18"))], ()),
            "no row for ['e2e switch']": ([row("a")], ("e2e switch",)),
        }
        for want, (rows, must) in cases.items():
            got = mc.switch_voided_problem(rows, {DAY}, must=must)
            self.assertIsNotNone(got, want)
            self.assertIn(want, got)

    def test_reason_must_match_whole(self):
        self.assertIsNotNone(mc.switch_voided_problem([row("a", reason=CHANGED + " (and more)")], {DAY}))


class ConfirmRemoval(unittest.TestCase):
    def test_phrase(self):
        self.assertEqual(mc.confirm_phrase('type "remove 2 mailboxes" to confirm'), "remove 2 mailboxes")
        # Inside a JSON error body (json.dumps of the Hub's answer).
        self.assertEqual(mc.confirm_phrase('{"error": "type \\"remove 2 mailboxes\\" to confirm"}'), "remove 2 mailboxes")
        for t in ("", "forbidden", 'type "" to confirm', None):
            self.assertIsNone(mc.confirm_phrase(t), t)

    def test_pending_uuids(self):
        v = {"accounts": [{"username": "bob", "uuid": "u2"}, {"username": "alice", "uuid": "u1"}], "confirmed": False}
        self.assertEqual(mc.pending_uuids(v), ["u1", "u2"])
        for bad in (None, {}, {"accounts": []}, {"accounts": [{"uuid": ""}]},
                    {"accounts": [{"uuid": "u1"}], "confirmed": True}):
            with self.assertRaises(AssertionError):
                mc.pending_uuids(bad)


if __name__ == "__main__":
    unittest.main()
