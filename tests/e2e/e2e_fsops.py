"""e2e_filesharing's operation runner and scrubber, importable without the
e2e environment (no Playwright, no env vars, no network at import) so
tests/test_e2e_fsops.py can drive run_op with a fake Hub.

e2e_filesharing.py imports these names and passes its own Hub helpers.
"""

from __future__ import annotations

import re
from typing import Callable

import e2e_ops  # the op record poll, contract §11.7

HASHES: set[str] = set()      # every NT hash seen on the secrets volume (upper case)
PASSWORDS: dict[str, str] = {}  # label → password (never printed)


def scrub(text: str) -> str:
    """Belt and braces: no password or hash in anything this test prints."""
    for v in list(PASSWORDS.values()):
        text = text.replace(v, "[password]")
    for h in list(HASHES):
        text = re.sub(re.escape(h), "[hash]", text, flags=re.I)
    # Playwright's errors list the request's headers (session cookies).
    return re.sub(r"(?im)^(\s*-\s*(?:cookie|authorization):).*$", r"\1 [redacted]", text)


def instance_of(path: str, body) -> str | None:
    """The instance a lifecycle route acts on."""
    parts = path.split("/")
    if path.startswith("/api/instances/") and len(parts) > 3 and parts[3] != "restore":
        return parts[3]
    if path.startswith("/api/templates/restart/") and len(parts) > 4:
        return parts[4]
    if path in ("/api/templates/enable", "/api/templates/disable") and isinstance(body, dict):
        return body.get("id")
    return None


def run_op(hub: Callable, save: Callable[[str, object], None], method: str, path: str, body,
           timeout: float) -> dict:
    """A 202 operation, polled at its `poll` (e2e_ops) until its record
    (same op_id) is no longer running; the record must be ok. `hub(method,
    path, body)` is the Hub's admin API: (HTTP status, decoded JSON body or
    the raw text); `save(name, record)` keeps the ended record.

    A busy 409 whose record is a running `restart` is the Hub's own queued
    restart (a membership or settings change restarts the app): that
    restart, polled by its op_id, must end ok, then the operation is sent
    once more. Any other 409 fails. Every failure message is scrubbed."""
    try:
        return _run_op(hub, save, method, path, body, timeout)
    except AssertionError as e:
        raise AssertionError(scrub(str(e))) from None


def _run_op(hub: Callable, save: Callable[[str, object], None], method: str, path: str, body,
            timeout: float) -> dict:
    def hub_get(p: str):
        return hub("GET", p)[1]

    code, out = hub(method, path, body)
    inst = instance_of(path, body)
    if code == 409 and inst and isinstance(out, dict) and out.get("op") == "restart" and out.get("running") \
            and out.get("op_id"):
        print(f"    {method} {path}: busy with the Hub's restart {out['op_id']}: waiting for it", flush=True)
        busy = {"op": "restart", "op_id": out["op_id"], "instance": inst, "poll": e2e_ops.op_url(inst, out["op_id"])}
        e2e_ops.wait_ok(hub_get, busy, timeout)
        code, out = hub(method, path, body)
    assert code == 202, f"{method} {path}: HTTP {code} (want 202): {scrub(str(out))[:800]}"
    acc = e2e_ops.accepted(out)
    rec = e2e_ops.wait(hub_get, acc, timeout)
    save(f"op-{acc.get('op')}-{acc['op_id']}.json", rec)
    return e2e_ops.check_ok(acc, rec)
