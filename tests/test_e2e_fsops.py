#!/usr/bin/env python3
"""Unit tests for tests/e2e/e2e_fsops.py: e2e_filesharing's run_op on a
fake Hub (no stack, no network, no Playwright).

Run: python3 tests/test_e2e_fsops.py (or python3 -m pytest -q tests/)

run_op waits for the Hub's own queued restart only when a 409's JSON
record is a running `restart`, then sends the operation exactly once
more; any other 409, or a second one, fails. Every failure is scrubbed.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "e2e"))
import e2e_fsops  # noqa: E402
import e2e_ops  # noqa: E402

INST = "samba"
OP_PATH = f"/api/instances/{INST}/backups"
RESTART_POLL = e2e_ops.op_url(INST, "r-1")
POLL = e2e_ops.op_url(INST, "b-1")
PASSWORD = "abcd-efgh-jkmn-pqrs-tuvw-xyz2"
NT_HASH = "0123456789ABCDEF0123456789ABCDEF"


def restart(running: bool, ok=None, **extra) -> dict:
    rec = {"op": "restart", "op_id": "r-1", "instance": INST, "running": running}
    if ok is not None:
        rec["ok"] = ok
    rec.update(extra)
    return rec


ACCEPTED = {"op": "backup", "op_id": "b-1", "instance": INST, "poll": POLL}
BACKUP_OK = {"op": "backup", "op_id": "b-1", "instance": INST, "running": False, "ok": True}


class FakeHub:
    """hub(method, path, body) → (status, body): the POST answers in order;
    GET of the restart's or the backup's record by op_id returns the next
    record of `restart` / `op`, repeating the last."""

    def __init__(self, posts, restart=(), op=(BACKUP_OK,)):
        self.posts = list(posts)
        self.records = {RESTART_POLL: list(restart), POLL: list(op)}
        self.sent, self.gets = [], 0

    def __call__(self, method, path, body=None, timeout=300):
        if method == "GET":
            assert path in self.records and self.records[path], f"GET {path}"
            self.gets += 1
            recs = self.records[path]
            return 200, recs.pop(0) if len(recs) > 1 else recs[0]
        self.sent.append((method, path, body))
        assert self.posts, f"unexpected {method} {path} (#{len(self.sent)})"
        return self.posts.pop(0)


class RunOpTest(unittest.TestCase):
    def setUp(self):
        e2e_fsops.PASSWORDS["alice/samba/0"] = PASSWORD
        e2e_fsops.HASHES.add(NT_HASH)
        self.saved = []
        p = mock.patch.object(e2e_ops.time, "sleep", lambda s: None)
        p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        e2e_fsops.PASSWORDS.clear()
        e2e_fsops.HASHES.clear()

    def run_op(self, hub):
        return e2e_fsops.run_op(hub, lambda name, rec: self.saved.append((name, rec)), "POST", OP_PATH, {}, 5)

    def assertScrubbed(self, msg: str):
        self.assertNotIn(PASSWORD, msg)
        self.assertNotIn(NT_HASH.lower(), msg.lower())
        self.assertIn("[password]", msg)

    def test_busy_restart_ok_then_resent_once(self):
        hub = FakeHub([(409, restart(True)), (202, ACCEPTED)], [restart(True), restart(False, ok=True)])
        rec = self.run_op(hub)
        self.assertEqual(rec, BACKUP_OK)
        self.assertEqual(len(hub.sent), 2, "the operation is sent exactly once more")
        self.assertEqual(hub.sent[0], hub.sent[1])
        self.assertEqual(self.saved, [("op-backup-b-1.json", BACKUP_OK)])

    def test_busy_restart_failed(self):
        failed = restart(False, ok=False, error=f"smbpasswd {PASSWORD} failed", output=f"hash {NT_HASH.lower()}")
        hub = FakeHub([(409, restart(True))], [restart(True), failed])
        with self.assertRaises(AssertionError) as cm:
            self.run_op(hub)
        msg = str(cm.exception)
        self.assertIn("restart", msg)
        self.assertIn("failed", msg)
        self.assertIn("smbpasswd [password] failed", msg, "the failed record is in the message")
        self.assertIn("[hash]", msg)
        self.assertScrubbed(msg)
        self.assertEqual(len(hub.sent), 1, "not resent after a failed restart")

    def test_409_other_op_fails_at_once(self):
        busy = {"op": "backup", "op_id": "x-1", "instance": INST, "running": True, "error": f"pw {PASSWORD}"}
        hub = FakeHub([(409, busy)])
        with self.assertRaises(AssertionError) as cm:
            self.run_op(hub)
        msg = str(cm.exception)
        self.assertIn("HTTP 409 (want 202)", msg)
        self.assertScrubbed(msg)
        self.assertEqual((len(hub.sent), hub.gets), (1, 0), "no wait, no resend")

    def test_409_restart_not_running_fails_at_once(self):
        hub = FakeHub([(409, restart(False, ok=True))])
        with self.assertRaises(AssertionError) as cm:
            self.run_op(hub)
        self.assertIn("HTTP 409 (want 202)", str(cm.exception))
        self.assertEqual((len(hub.sent), hub.gets), (1, 0))

    def test_second_409_after_resend_fails(self):
        hub = FakeHub([(409, restart(True)), (409, restart(True, op_id="r-2", error=f"pw {PASSWORD}"))],
                      [restart(False, ok=True)])
        with self.assertRaises(AssertionError) as cm:
            self.run_op(hub)
        msg = str(cm.exception)
        self.assertIn("HTTP 409 (want 202)", msg)
        self.assertScrubbed(msg)
        self.assertEqual(len(hub.sent), 2, "sent once more, never a third time")

    def test_409_plain_text_fails(self):
        hub = FakeHub([(409, f"busy: restart running ({PASSWORD})")])
        with self.assertRaises(AssertionError) as cm:
            self.run_op(hub)
        msg = str(cm.exception)
        self.assertIn("HTTP 409 (want 202)", msg)
        self.assertScrubbed(msg)
        self.assertEqual((len(hub.sent), hub.gets), (1, 0))

    def test_failed_operation_record_scrubbed(self):
        failed = dict(BACKUP_OK, ok=False, error=f"tar: {PASSWORD}")
        hub = FakeHub([(202, ACCEPTED)], op=[failed])
        with self.assertRaises(AssertionError) as cm:
            self.run_op(hub)
        self.assertScrubbed(str(cm.exception))

    def test_poll_by_op_id_answering_another_op_fails_at_once(self):
        other = dict(BACKUP_OK, op="restart", op_id="r-9", error=f"pw {PASSWORD}")
        hub = FakeHub([(202, ACCEPTED)], op=[dict(BACKUP_OK, running=True), other, BACKUP_OK])
        with self.assertRaises(AssertionError) as cm:
            self.run_op(hub)
        msg = str(cm.exception)
        self.assertIn("answered op r-9", msg)
        self.assertScrubbed(msg)
        self.assertEqual(hub.gets, 2)

    def test_202_poll_must_be_the_ops_own_record(self):
        hub = FakeHub([(202, dict(ACCEPTED, poll=f"/api/instances/{INST}/op"))])
        with self.assertRaises(AssertionError) as cm:
            self.run_op(hub)
        self.assertIn("202 poll", str(cm.exception))
        self.assertEqual(hub.gets, 0)


if __name__ == "__main__":
    unittest.main()
