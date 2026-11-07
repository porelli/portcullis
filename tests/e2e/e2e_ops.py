"""The Hub's background operations for the e2e scripts (contract §11.7).

Every lifecycle route (enable, disable, restart, create, an AI switch on an
enabled instance, backup, restore, delete) answers 202
{op_id, op, instance, poll}; the caller polls the op record at `poll` until
it is no longer running and then reads `ok`. One poll helper for all the
e2e scripts: each passes its own `get(path)` (the Hub's admin API as that
script calls it), which returns the decoded JSON body.

Never a retry: a busy 409 (the running record) or a failed record is the
caller's failure unless the test expects it.
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


def accepted(body, op: str | None = None, instance: str | None = None) -> dict:
    """A 202 body: op_id and poll, the op and the instance when given."""
    assert isinstance(body, dict) and body.get("op_id") and body.get("poll"), f"202 without op_id / poll: {str(body)[:400]}"
    if op is not None:
        assert body.get("op") == op, f"202 for op {body.get('op')!r}, want {op!r}: {body}"
    if instance is not None:
        assert body.get("instance") == instance and body["poll"] == f"/api/instances/{instance}/op", \
            f"202 for instance {body.get('instance')!r} (poll {body.get('poll')!r}), want {instance!r}"
    return body


def wait(get: Callable[[str], object], acc: dict, timeout: float, every: float = POLL_EVERY) -> dict:
    """The record of the operation `acc` (a 202 body) once it ended: polled
    every `every` s for up to `timeout` s. Not checked for ok."""
    op_id, poll = acc["op_id"], acc["poll"]
    deadline, last = time.time() + timeout, None
    while True:
        try:
            last = get(poll)
        except Exception as e:  # noqa: BLE001  (a read that failed: read again)
            last = f"{type(e).__name__}: {e}"
        if isinstance(last, dict) and last.get("op_id") == op_id and not last.get("running"):
            return last
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
