#!/usr/bin/env python3
"""Setup-link check against any running Portcullis (CI or a live server).

  python3 tests/e2e/e2e_invite.py <setup-link> <landing-url> [--reinvite-cmd CMD [--replaced]]

Get the link on the server with `./portcullis invite <user> --to <hub|portal|URL>`
(use a throwaway user: the link registers a NEW passkey for it). With a
Playwright Chromium and a CDP virtual authenticator it proves, and exits 1
otherwise:

  1. the link page names the user; one click → passkey registration → the
     landing URL, with no password field anywhere and no second prompt;
  2. the token oauth2-proxy holds says acr=hwk, amr=[hwk];
  3. the link is single use;
  4. a second login in a fresh browser with the same key is ONE passkey
     assertion, no password, straight to the landing URL;
  5. the identity provider cannot be used without a redeemed link
     (/oauth2/start?kc_idp_hint=portcullis-invite ends on enroll's error page);
  6. with --reinvite-cmd (a command printing `portcullis invite <same user>
     --json`, run AFTER the first link was used, e.g.
     "ssh host ./portcullis/portcullis invite u --json"): the lost-key
     recovery — a second link registers a NEW authenticator for the same
     user and lands; then the new key signs in with one touch, and the first
     key still does too — or, with --replaced (the command used
     --replace-keys), no longer does.

Requirements: pip install -r tests/e2e/requirements.txt && playwright install chromium
Set E2E_IGNORE_HTTPS_ERRORS=1 for ACME staging / an untrusted CA.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
from urllib.parse import urlsplit

from playwright.sync_api import Page, sync_playwright

import shlex
import subprocess

LINK, LANDING = sys.argv[1], sys.argv[2]
_opts = sys.argv[3:]
REINVITE = shlex.split(_opts[_opts.index("--reinvite-cmd") + 1]) if "--reinvite-cmd" in _opts else None
REPLACED = "--replaced" in _opts
DOMAIN = urlsplit(LINK).hostname.split(".", 1)[1]
AUTH = f"https://auth.{DOMAIN}"
failures: list[str] = []


def expect(ok: bool, what: str) -> None:
    print(("PASS: " if ok else "FAIL: ") + what, flush=True)
    if not ok:
        failures.append(what)


def browser_page(pw, creds=None):
    b = pw.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])
    ctx = b.new_context(ignore_https_errors=os.environ.get("E2E_IGNORE_HTTPS_ERRORS") == "1")
    ctx.set_default_timeout(30_000)
    page = ctx.new_page()
    # Like a user pressing OK: keep the default (a stock Keycloak theme
    # asks for the passkey label; Portcullis' theme does not ask at all).
    page.on("dialog", lambda d: d.accept(d.default_value))
    cdp = ctx.new_cdp_session(page)
    cdp.send("WebAuthn.enable", {"enableUI": False})
    aid = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "usb", "hasResidentKey": True, "hasUserVerification": True,
        "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
    counts = {"registered": 0, "asserted": 0}
    cdp.on("WebAuthn.credentialAdded", lambda _e: counts.__setitem__("registered", counts["registered"] + 1))
    cdp.on("WebAuthn.credentialAsserted", lambda _e: counts.__setitem__("asserted", counts["asserted"] + 1))
    # A copied credential must never go back in its signature counter.
    for c in creds or []:
        cdp.send("WebAuthn.addCredential", {"authenticatorId": aid, "credential": dict(c, signCount=c.get("signCount", 0) + int(time.time()) - 1_700_000_000)})
    return b, page, cdp, aid, counts


def one_touch_login(pw, creds, label: str, expect_ok: bool = True) -> None:
    b, page, _cdp, _aid, counts = browser_page(pw, creds)
    page.goto(LANDING, wait_until="domcontentloaded")
    reached, prompts = drive(page)
    if expect_ok:
        expect(reached and prompts == 0 and counts == {"registered": 0, "asserted": 1},
               f"{label}: one passkey touch ({counts})")
    else:
        expect(not reached and prompts == 0, f"{label}: refused (reached={reached})")
    b.close()


def drive(page: Page) -> tuple[bool, int]:
    """Click through until LANDING; returns (reached, password prompts seen)."""
    deadline = time.time() + 90
    while time.time() < deadline:
        page.wait_for_load_state("networkidle")
        pw = page.locator("input[type=password]")
        if pw.count() and pw.first.is_visible():
            print(f"      password field at {page.url.split('?')[0]}")
            return False, 1
        if page.url.startswith(LANDING) and "Additional authentication" not in page.title():
            return True, 0
        for sel in ("#invite-continue", "#registerWebAuthn", "#authenticateWebAuthnButton"):
            if page.locator(sel).is_visible():
                page.click(sel)
                page.wait_for_timeout(1500)
                break
        else:
            if page.locator("#kc-try-again, .error").count():
                print(f"      error page at {page.url.split('?')[0]}: {page.locator('body').inner_text()[:200]!r}")
                return False, 0
            page.wait_for_timeout(500)
    return False, 0


def token_claims(page: Page) -> dict:
    r = page.request.get(f"{AUTH}/oauth2/auth")
    t = r.headers.get("x-auth-request-access-token", "")
    if not t:
        return {}
    p = t.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


with sync_playwright() as pw:
    b, page, cdp, aid, counts = browser_page(pw)
    page.goto(LINK, wait_until="domcontentloaded")
    expect("Set up your passkey" in page.content(), "the setup link shows the setup page")
    reached, prompts = drive(page)
    expect(reached and prompts == 0, f"setup link → passkey registration → {LANDING}, no password")
    expect(counts == {"registered": 1, "asserted": 0}, f"one registration, no extra touch ({counts})")
    c = token_claims(page)
    expect(c.get("acr") == "hwk" and "hwk" in (c.get("amr") or []), f"token acr/amr: {c.get('acr')} {c.get('amr')}")
    creds = cdp.send("WebAuthn.getCredentials", {"authenticatorId": aid})["credentials"]
    resp = page.goto(LINK, wait_until="domcontentloaded")
    expect(bool(resp) and resp.status == 404, "the link works once")
    b.close()

    one_touch_login(pw, creds, "second login in a fresh browser")

    b, page, cdp, aid, counts = browser_page(pw)
    page.goto(f"{AUTH}/oauth2/start?rd={LANDING}&kc_idp_hint=portcullis-invite&prompt=login", wait_until="domcontentloaded")
    page.wait_for_load_state("networkidle")
    expect(page.url.startswith(f"https://enroll.{DOMAIN}/invite/") and "invalid, expired or already used" in page.content(),
           "the invite identity provider refuses a browser without a redeemed link")
    b.close()

    if REINVITE:
        out = subprocess.run(REINVITE, check=True, capture_output=True, text=True).stdout
        link2 = json.loads(out.strip().splitlines()[-1])["url"]
        b, page, cdp, aid, counts = browser_page(pw)  # a NEW authenticator
        page.goto(link2, wait_until="domcontentloaded")
        reached, prompts = drive(page)
        expect(reached and prompts == 0 and counts == {"registered": 1, "asserted": 0},
               f"re-invite (recovery): a second key registers and lands ({counts})")
        creds2 = cdp.send("WebAuthn.getCredentials", {"authenticatorId": aid})["credentials"]
        b.close()
        one_touch_login(pw, creds2, "the new key")
        if REPLACED:
            one_touch_login(pw, creds, "the replaced first key", expect_ok=False)
        else:
            one_touch_login(pw, creds, "the first key still works (spare key)")

print(f"\n{'OK' if not failures else 'FAILED: ' + ', '.join(failures)}")
sys.exit(1 if failures else 0)
