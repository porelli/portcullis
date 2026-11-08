"""The Hub's background operations for the e2e scripts (contract §11.7).

Every lifecycle route (enable, disable, restart, create, an AI switch on an
enabled instance, backup, restore, delete) answers 202
{op_id, op, instance, poll}, with poll = /api/instances/<id>/op?op_id=<op_id>:
that op's own record, even after a newer op (the Hub's own queued restart)
replaced the instance's current one. The caller polls it until it is no
longer running and then reads `ok`. Folder and doctor ops poll their key's
record (no op_id, no history). One poll helper for all the e2e scripts: each
passes its own `get(path)` (the Hub's admin API as that script calls it),
which returns the decoded JSON body.

These helpers never retry: a failed record is the caller's failure unless
the test expects it. The one resend lives in e2e_fsops.run_op (a busy 409
from the Hub's own running restart: wait for it, then send once more).
"""

from __future__ import annotations

import json
import time
from typing import Callable

POLL_EVERY = 2  # seconds between two reads of the record


def describe(rec) -> str:
    """The failure as the record tells it: error / output / hint / status
    and each step (key, state, detail)."""
    if not isinstance(rec, dict):
        return str(rec)[:1500]
    head = {k: rec.get(k) for k in ("op", "op_id", "ok", "error", "hint", "status", "stopped_by", "warnings")
            if rec.get(k) not in (None, "", [])}
    steps = [" ".join(str(s.get(k)) for k in ("key", "state", "detail") if s.get(k) not in (None, ""))
             for s in rec.get("steps") or []]
    out = (rec.get("output") or "")[-1500:]
    return f"{json.dumps(head)[:1200]}\n      steps: {steps}" + (f"\n      output: {out}" if out else "")


def op_url(instance: str, op_id: str) -> str:
    """The record of one instance op (contract §11.7, op history)."""
    return f"/api/instances/{instance}/op?op_id={op_id}"


def accepted(body, op: str | None = None, instance: str | None = None) -> dict:
    """A 202 body: op_id and poll, the op and the instance when given; an
    instance op's poll is that op's own record (op_url)."""
    assert isinstance(body, dict) and body.get("op_id") and body.get("poll"), f"202 without op_id / poll: {str(body)[:400]}"
    if op is not None:
        assert body.get("op") == op, f"202 for op {body.get('op')!r}, want {op!r}: {body}"
    if instance is not None:
        assert body.get("instance") == instance and body["poll"] == op_url(instance, body["op_id"]), \
            f"202 for instance {body.get('instance')!r} (poll {body.get('poll')!r}), want {instance!r}"
    elif str(body["poll"]).startswith("/api/instances/"):
        assert body["poll"] == op_url(body.get("instance") or "", body["op_id"]), f"202 poll {body['poll']!r}: {body}"
    return body


def wait(get: Callable[[str], object], acc: dict, timeout: float, every: float = POLL_EVERY) -> dict:
    """The record of the operation `acc` (a 202 body) once it ended: polled
    every `every` s for up to `timeout` s. Not checked for ok. A poll by
    op_id that answers another op's record fails at once."""
    op_id, poll = acc["op_id"], acc["poll"]
    by_id = f"op_id={op_id}" in poll
    deadline, last = time.time() + timeout, None
    while True:
        try:
            last = get(poll)
        except Exception as e:  # noqa: BLE001  (a read that failed: read again)
            last = f"{type(e).__name__}: {e}"
        if isinstance(last, dict) and last.get("op_id") == op_id and not last.get("running"):
            return last
        if by_id and isinstance(last, dict) and last.get("op_id") and last.get("op_id") != op_id:
            raise AssertionError(f"{acc.get('op')} {op_id}: {poll} answered op {last.get('op_id')}: {describe(last)}")
        if time.time() > deadline:
            raise AssertionError(f"{acc.get('op')} {op_id}: still running after {timeout:.0f} s: {describe(last)}")
        time.sleep(every)


def check_ok(acc: dict, rec: dict) -> dict:
    """The ended record must be ok (else the error, output, hint and the
    steps)."""
    assert rec.get("ok") is True, f"{acc.get('op')} {acc.get('instance') or ''} failed: {describe(rec)}"
    return rec


def wait_ok(get: Callable[[str], object], acc: dict, timeout: float, every: float = POLL_EVERY) -> dict:
    """wait(), then check_ok()."""
    return check_ok(acc, wait(get, acc, timeout, every))
