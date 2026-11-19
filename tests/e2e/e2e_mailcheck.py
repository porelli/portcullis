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
"""
from __future__ import annotations

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
