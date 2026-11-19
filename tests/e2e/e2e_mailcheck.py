"""e2e_mail's pure helpers (no stack, no network, no Playwright), unit
tested by tests/test_e2e_mailcheck.py.

- network_retries: a browser step retried only while Chromium aborts it
  because the runner's network changed (net::ERR_NETWORK_CHANGED, or the
  chrome-error:// page it leaves). A container start or a `docker
  network connect` adds an interface on the runner; Chromium then drops
  every navigation in flight. Each retry is noted (job summary), every
  other failure is raised at once.
- switch_voided_problem: the Hub's mail-password rows after a provider
  switch (GET /api/directory/users/<u>/mail). The Hub shows a row voided
  by a provider change as status "voided" with the reason "the mail
  server changed on <date>: create a new mail password" (a revoked row
  isn't listed); anything else is named.
- confirm_phrase / pending_uuids: the confirmation of a pending mass
  removal (R-SWITCH-BASE-3, R-CONFIRM-REMOVAL): the phrase the Hub's 400
  names, and the pending accounts' uuids; removal_phrase the phrase's
  format ("remove <n> mailboxes", "remove 1 mailbox").
- mail_status_view / sync_problem: `./portcullis mail status --json` read
  whatever its exit says about checks (1 = a Problem check), and the Hub's
  view judged: wired, reachable, no void, not held, applied = generation.
"""
from __future__ import annotations

import json
import re
import time

ABORT_MARKS = ("ERR_NETWORK_CHANGED", "chrome-error://")


def navigation_aborted(err: BaseException) -> bool:
    """Chromium dropped the navigation on a network change."""
    return any(m in str(err) for m in ABORT_MARKS)


def network_retries(attempt, note, what: str, tries: int = 4, wait: float = 3.0, sleep=time.sleep):
    """attempt(n) for n = 1..tries; a new attempt only after a network
    abort (noted with what), never after any other failure."""
    for n in range(1, tries + 1):
        try:
            return attempt(n)
        except Exception as e:  # noqa: BLE001
            if n == tries or not navigation_aborted(e):
                raise
            note(f"{what}: attempt {n} aborted by a network change on the runner "
                 f"(net::ERR_NETWORK_CHANGED / chrome-error://): a new attempt in {wait:.0f} s")
            sleep(wait)
    raise AssertionError(f"{what}: no attempt ran")  # tries < 1


SWITCH_REASON = re.compile(r"the mail server changed on (\d{4}-\d{2}-\d{2}): create a new mail password")


def switch_voided_problem(rows: list, days: set, must: tuple = ()) -> str | None:
    """None when there are rows, each one is voided by a provider change
    on one of days (UTC YYYY-MM-DD), and every label in must is among
    them; else what is wrong."""
    if not rows:
        return "no rows"
    for r in rows:
        label = r.get("label")
        if r.get("status") != "voided":
            return f"{label!r}: status {r.get('status')!r} (want voided)"
        m = SWITCH_REASON.fullmatch(r.get("voided_reason") or "")
        if not m:
            return f"{label!r}: reason {r.get('voided_reason')!r} (want the mail server changed)"
        if m.group(1) not in days:
            return f"{label!r}: voided on {m.group(1)} (want one of {sorted(days)})"
    labels = {r.get("label") for r in rows}
    missing = [x for x in must if x not in labels]
    if missing:
        return f"no row for {missing}"
    return None


# The Hub's refusal of an untyped confirmation: 'type "<phrase>" to confirm'
# (its statusErr form, also as a JSON-escaped string inside an error body).
CONFIRM_PHRASE = re.compile(r'type \\?"([^"\\]{1,200})\\?" to confirm')


def confirm_phrase(text: str) -> str | None:
    """The phrase the Hub asks to be typed, from its 400 answer (None:
    the answer names none)."""
    m = CONFIRM_PHRASE.search(text or "")
    return m.group(1) if m else None


def pending_uuids(view) -> list:
    """The pending removal's account uuids (GET /api/mail/settings
    pending_removal), sorted; an absent, confirmed or empty one fails."""
    if not isinstance(view, dict):
        raise AssertionError(f"no pending removal: {view!r}")
    if view.get("confirmed"):
        raise AssertionError(f"the pending removal is already confirmed: {view!r}")
    out = sorted(a.get("uuid") or "" for a in view.get("accounts") or [])
    if not out or "" in out:
        raise AssertionError(f"the pending removal names no (or a blank) account: {view!r}")
    return out


def removal_phrase(n: int) -> str:
    """The typed confirmation of a pending removal of n mailboxes (Hub
    R-CONFIRM-REMOVAL): "remove <n> mailboxes", "remove 1 mailbox"."""
    return "remove 1 mailbox" if n == 1 else f"remove {n} mailboxes"


def mail_status_view(rc: int, out: str) -> dict:
    """`./portcullis mail status --json`'s document. Exit 1 only says a
    check is a Problem (in CI the PTR one always is: no reverse DNS), so
    rc 0 and 1 are both read; rc 2, any other code, or output that isn't
    one status object (the slot closed: `fail` exits 1 with nothing on
    stdout) is a failed read."""
    if rc not in (0, 1):
        raise AssertionError(f"./portcullis mail status --json: rc {rc}")
    try:
        j = json.loads(out)
    except ValueError:
        raise AssertionError(f"./portcullis mail status --json: rc {rc}, not JSON: {out[:200]!r}") from None
    if not isinstance(j, dict) or "hub" not in j or "problem" not in j:
        raise AssertionError(f"./portcullis mail status --json: rc {rc}, not a status document: {out[:200]!r}")
    if (rc == 1) != (j.get("problem") is True):
        raise AssertionError(f"./portcullis mail status --json: rc {rc} but problem={j.get('problem')!r}")
    return j


def sync_problem(status: dict) -> str | None:
    """None when the Hub's view in a mail status document says the sync
    converged: wired, reachable, no void owed, not held, and the provider
    applied the Hub's generation; else what isn't."""
    h = status.get("hub")
    if not isinstance(h, dict):
        return "the Hub didn't answer hub mail status"
    for k, want in (("wired", True), ("reachable", True)):
        if h.get(k) is not want:
            return f"{k} is {h.get(k)!r}"
    for k in ("void_owed", "held"):
        if h.get(k) is not None:
            return f"{k}: {h.get(k)!r}"
    gen, applied = h.get("generation"), h.get("applied_generation")
    if not isinstance(gen, int) or gen < 1:
        return f"no generation sent ({gen!r})"
    if applied != gen:
        return f"applied generation {applied!r} of {gen}"
    return None
