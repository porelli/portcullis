#!/usr/bin/env python3
"""End-to-end: authenticator-app codes (totp) on a real stack (contract
§8.1 "Authenticator-app codes", §5, §5.1, §8.2, §9.4).

Runs in CI inside the `e2e-signin` job, after e2e_signin.py, on the same
stack (its users, the pat password file, the hr group). It sets up what it
needs itself, so it also runs alone after the job's setup steps:

  totp           switched on here (a setup link with the authenticator option
                 is refused while it is off), off again at the end
  password       switched on for the run, back as it was at the end
  e2e-otp        a template all[password, totp], created here
  echo-otp.<d>   an echo instance on e2e-otp (pat and alice members)
  people core    e2e-otp for fresh_one_code only (Strong before and after)

The authenticator-app secret is read from Keycloak's own manual-key element
(the setup page's QR and key are hidden by CSS injected into every page
before anything is shown, P23), masked, kept in memory only and never
printed or written; codes come from pyotp (RFC 6238, pinned with hashes in
tests/e2e/requirements-totp.txt). No screenshot or HTML is ever taken of a
page that holds a secret (the setup page), no Playwright trace is recorded.

Cases (in this order):
  setup_link_refused_while_off  invite {"authenticator": true} → 409 while totp is off
  setup                         totp on, password on, e2e-otp, echo-otp, members
  policy_read_back              the realm OTP policy and both actions' max_auth_age
  editor_refuses_code_only      any[totp, security_key]: save 400 (the text), preview 200 code_only
  no_code_only_way_in           a cold sign-in never asks for a code first, offers no
                                code; username + a code as the password: no session
  pat_cap_refused               pat's password-only session: no "+ Add" on the Sign-in
                                page, a hand-made kc_action=CONFIGURE_TOTP refused (cap)
  pat_setup_link_authenticator  the Hub's setup link with the authenticator option:
                                a passkey, then Keycloak's authenticator setup
  password_then_code            echo-otp: password, then the code (group-gate's step-up);
                                amr pwd + otp; LOGIN pc_methods password, then totp
                                (a step_up: one LOGIN per authentication)
  sso_stepup_only_code          a password session on echo-basic, then echo-otp:
                                step-up pc_method=totp, only the code asked
  wrong_code_failed             history "wrong authenticator code", brute force 1
  replay_refused                the same code twice in one step: the second refused
  window                        the previous step's code accepted, 90 s old refused
  fresh_one_code                people core e2e-otp: the Hub's fresh_auth asks
                                pc_method=totp; password, then code in one authentication
                                (LOGIN pc_methods password,totp) → pc_fresh=totp with pwd
                                in amr; the proof sets pat's password; a password-only
                                fresh proof → 403
  add_replace_rename_remove     the Sign-in page's popups: + Add, Replace
                                (CONFIGURE_TOTP:<id>: new code works, old refused),
                                rename (404 for a passkey id), Remove (delete_credential:
                                <id>, its re-authentication never code-only)
  fourth_refused                at 3 the page offers no "+ Add"; a 4th by hand refused
  history_method_entries        added / replaced / removed entries, one per change
  root_impersonating_pat        root signed in as pat: echo-otp's impersonation needs
                                page (no step-up), CONFIGURE_TOTP refused
  carol_removes_alice           alice's setup-link authenticator, removed by carol
                                (sign_in_help); a help entry
  admin_no_code_step            admin: no code step, CONFIGURE_TOTP refused (CI only)
  no_secret_anywhere            every secret (and its lowercase / unpadded forms)
                                absent from the logs, the audit, the history, artifacts
  finally                       instance, template, authenticators removed; totp off,
                                password and people core back
Environment: as e2e_signin.py.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.parse

import pyotp
from playwright.sync_api import Error as PWError
from playwright.sync_api import Page, sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_login as base  # noqa: E402
import e2e_ops  # noqa: E402
import e2e_signin as s  # noqa: E402  (the stack's helpers: check, hub, kc, people_json, …)
from e2e_signin import (AUTH, DOMAIN, ECHO_BASIC, PEOPLE, PORTAL, REALM, TIMEOUT_MS, body, check, goto,  # noqa: E402
                        hub, hub_ok, kc, kc_user_id, mask, needs, people_as, people_json, state, until)

ECHO_OTP = f"https://echo-otp.{DOMAIN}"
INSTANCE, TEMPLATE = "echo-otp", "e2e-otp"
CODE_ONLY_TEXT = "an authenticator code can't be the only way in: combine it with another method (all of)"
SHOTS = os.path.join(s.ART, "totp-screens")
os.makedirs(SHOTS, exist_ok=True)
# The setup page's QR code and manual key, hidden in every document of
# every context before it renders (P23: the key is revealed in manual mode
# only after this is in place).
HIDE_SECRET = """(() => {
  const css = '#kc-totp-secret-qr-code, #kc-totp-secret-qr-code *, #kc-totp-secret-key, #kc-totp-secret-key * '
    + '{ visibility: hidden !important; }';
  const add = () => { const s = document.createElement('style'); s.textContent = css;
    (document.head || document.documentElement).appendChild(s); };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', add); else add();
})();"""

# label → base32 secret, in memory only (masked as soon as it is read).
SECRETS: dict[str, str] = {}
# (secret, time step) of every code typed, accepted or not: a code is used
# once (otpPolicyCodeReusable false), so the next one waits for a new step.
USED: set = set()


# ── small helpers ──

def shot(page: Page, name: str) -> None:
    """A screenshot only (never the HTML), never of the setup page."""
    try:
        if page.locator("#totpSecret, #kc-totp-secret-key, #kc-totp-secret-qr-code").count():
            return
        page.screenshot(path=os.path.join(SHOTS, f"{name}.png"), full_page=True)
    except PWError:
        pass


def masked(secret: str) -> None:
    for form in variants(secret):
        mask(form)


def variants(secret: str) -> set:
    """A secret's forms that must never appear anywhere."""
    s_ = secret.replace(" ", "")
    return {s_, s_.lower(), s_.rstrip("="), s_.rstrip("=").lower()}


def step_of(t: float) -> int:
    return int(t // 30)


def code_now(secret: str, min_left: float = 12) -> str:
    """A code from secret for a time step no code was typed in, with at
    least min_left seconds of that step left."""
    while True:
        now = time.time()
        st = step_of(now)
        if (secret, st) not in USED and (st + 1) * 30 - now >= min_left:
            USED.add((secret, st))
            return pyotp.TOTP(secret).at(now)
        time.sleep(max(0.5, (st + 1) * 30 - now + 0.3))


def pat_password() -> str:
    with open(os.environ["E2E_PAT_PASSWORD_FILE"]) as f:
        return f.read().strip()


def run_op(method: str, path: str, body_, op: str, instance: str, timeout: float = 600) -> dict:
    code, out = hub(method, path, body_)
    assert code == 202, f"{method} {path}: HTTP {code} {str(out)[:400]}"
    acc = e2e_ops.accepted(out, op, instance)

    def get(poll):
        c, o = hub("GET", poll)
        assert c == 200, f"GET {poll}: HTTP {c}"
        return o
    return e2e_ops.wait_ok(get, acc, timeout)


def _ok(answer: tuple, codes: tuple) -> None:
    code, out = answer
    assert code in codes, f"HTTP {code} {str(out)[:200]}"


def otp_ids(user: str) -> list[dict]:
    uid = kc_user_id(user)
    return [c for c in kc(f"/users/{uid}/credentials") if c["type"] == "otp"] if uid else []


def my_authenticators(user: str) -> list[dict]:
    view = people_json(user, "GET", "/api/me/signin?refresh=1")
    row = next((m for m in view["methods"] if m["id"] == "totp"), {})
    return row.get("authenticators") or []


def kc_events(user: str, type_: str, n: int = 20) -> list[dict]:
    uid = kc_user_id(user)
    return kc(f"/events?" + urllib.parse.urlencode({"user": uid, "type": type_, "max": n})) or []


def history(user: str) -> list[dict]:
    return people_json(user, "GET", "/api/me/signin/history?limit=100")["entries"]


# ── Keycloak pages ──

def on_kc(page: Page) -> bool:
    return page.url.startswith(AUTH + "/realms/")


def visible(page: Page, sel: str) -> bool:
    loc = page.locator(sel)
    return loc.count() > 0 and loc.first.is_visible()


def offered(page: Page) -> list[str]:
    """The "Try another way" page's text (one string), opened and left
    open; [] when there is no such link."""
    if not visible(page, "#try-another-way"):
        return []
    page.click("#try-another-way")
    page.wait_for_load_state("domcontentloaded")
    return [body(page)]


def offers_code(ways: list[str]) -> bool:
    return any("authenticator app" in w.lower() or "authenticator code" in w.lower() or "one-time code" in w.lower()
               for w in ways)


def to_password(page: Page) -> None:
    """From Keycloak's first page to the password form (the passkey page's
    "Try another way" → Password); never through a code."""
    page.wait_for_load_state("domcontentloaded")
    assert not visible(page, "#otp"), f"a code asked before any other method at {page.url.split('?')[0]}"
    if visible(page, "#password"):
        return
    page.wait_for_selector("#authenticateWebAuthnButton, #try-another-way", state="visible")
    if visible(page, "#try-another-way"):
        page.click("#try-another-way")
        page.wait_for_load_state("domcontentloaded")
    page.get_by_text("Password", exact=True).first.click()
    page.wait_for_selector("#password", state="visible")


def type_password(page: Page, user: str, password: str) -> None:
    to_password(page)
    if visible(page, "#username") and page.locator("#username").is_editable():
        page.fill("#username", user)
    page.fill("#password", password)
    with page.expect_navigation(wait_until="domcontentloaded"):
        page.click("#kc-login")


def dismiss_notice(page: Page) -> bool:
    """The impersonation notice (an administrator signed in as this person
    earlier: shown once at the next sign-in), continued."""
    if visible(page, "#portcullis-impersonation-notice"):
        with page.expect_navigation(wait_until="domcontentloaded"):
            page.click("#portcullis-notice-continue")
        return True
    return False


def to_code(page: Page) -> None:
    """After the password on a forward-auth app: Keycloak's code step, or
    group-gate's step-up page (the password session reached the app, which
    asks pc_method=totp) clicked through to it."""
    try:
        page.wait_for_selector("#otp, #stepup-continue, #portcullis-impersonation-notice", state="visible")
        if dismiss_notice(page):
            page.wait_for_selector("#otp, #stepup-continue", state="visible")
    except PWError:
        shot(page, "no-code-step")
        raise AssertionError(f"no code step at {page.url.split('?')[0]}: {body(page)[:300]!r}") from None
    if visible(page, "#stepup-continue"):
        href = page.locator("#stepup-continue").get_attribute("href") or ""
        assert urllib.parse.parse_qs(urllib.parse.urlsplit(href).query).get("pc_method") == ["totp"], href
        page.click("#stepup-continue")


def type_code(page: Page, code: str, label: str | None = None) -> None:
    to_code(page)
    page.wait_for_selector("#otp", state="visible")
    assert not visible(page, "input[type=password]"), "a password field next to the code"
    if label and page.locator("[id^=kc-otp-credential-]").count() > 1:
        # Keycloak's own list of the person's apps (login-otp.ftl): a click
        # sets the hidden selectedCredentialId.
        cid = next(c["id"] for c in otp_ids("pat") if c.get("userLabel") == label)
        page.locator("[id^=kc-otp-credential-]", has_text=label).first.click()
        got = page.locator("#selectedCredentialId").input_value()
        assert got == cid, f"the code's app isn't selected: {got} != {cid}"
    page.fill("#otp", code)
    with page.expect_navigation(wait_until="domcontentloaded"):
        page.click("#kc-login")


def code_error(page: Page) -> bool:
    page.wait_for_load_state("domcontentloaded")
    return visible(page, "#otp") and ("Invalid authenticator code" in body(page) or visible(page, "#input-error-otp-code"))


def setup_page(page: Page) -> bool:
    return page.locator("#kc-totp-settings-form").count() > 0


def configure(page: Page) -> tuple[str, str]:
    """Keycloak's authenticator-app setup page (CONFIGURE_TOTP, the
    override): the secret from the manual-key element (hidden by
    HIDE_SECRET, masked at once), the prefilled label, then a code from it
    submitted. Returns (label, secret)."""
    page.wait_for_selector("#kc-totp-settings-form")
    page.wait_for_selector("#mode-manual")
    with page.expect_navigation(wait_until="domcontentloaded"):
        page.click("#mode-manual")
    key = page.locator("#kc-totp-secret-key")
    key.wait_for(state="attached")
    assert not key.is_visible(), "the manual key is visible (the hiding CSS didn't apply)"
    secret = (key.text_content() or "").replace(" ", "").strip()
    assert re.fullmatch(r"[A-Z2-7]{16,}=*", secret), "the manual key isn't base32"
    masked(secret)
    label = page.locator("#userLabel").input_value()
    assert re.fullmatch(r"Authenticator \d{4}-\d\d-\d\d \d\d:\d\d:\d\d", label), f"prefilled label {label!r}"
    page.fill("#totp", code_now(secret))
    SECRETS[label] = secret
    try:
        with page.expect_navigation(wait_until="domcontentloaded"):
            page.click("#saveTOTPBtn")
        again = setup_page(page)
    except PWError as e:  # the popup closes itself once the Hub's callback ran
        if not page.is_closed() and "closed" not in str(e):
            raise
        again = False
    assert not again, f"the setup page again: {body(page)[:200]!r}"
    return label, secret


def refusal(page: Page) -> str:
    """The override's refusal page text (no QR, no key, no setup form)."""
    page.wait_for_load_state("domcontentloaded")
    assert not setup_page(page) and page.locator("#kc-totp-secret-qr-code, #kc-totp-secret-key, #totpSecret").count() == 0, \
        "the setup page (a secret) instead of a refusal"
    return body(page)


def aia_url(action: str) -> str:
    """A hand-made application-initiated action on the fresh-auth client
    (as freshauth.js builds it): prompt=login, max_age=0."""
    verifier = secrets.token_urlsafe(48)
    challenge = s.base64.urlsafe_b64encode(s.hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return s.authorize_url("portcullis-fresh-auth", PEOPLE + "/signin", prompt="login", max_age="0",
                           kc_action=action, code_challenge=challenge, code_challenge_method="S256")


def finish(page: Page, until_: str, seconds: int = 60) -> None:
    """Follow redirects (oauth2-proxy, group-gate's step-up page clicked)
    until the page is on until_ and not on Keycloak."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            page.wait_for_load_state("domcontentloaded")
            if page.url.startswith(until_) and not on_kc(page):
                return
            if dismiss_notice(page):
                continue
            if page.locator("#needs-stronger").count():
                shot(page, "needs-stronger")
                raise AssertionError(f"needs-stronger at {page.url.split('?')[0]}: {body(page)[:300]!r}")
        except PWError as e:
            if "Execution context was destroyed" not in str(e):
                raise
        page.wait_for_timeout(500)
    raise AssertionError(f"not on {until_}: stuck at {page.url.split('?')[0]}: {body(page)[:200]!r}")


def amr(page: Page) -> list:
    return s.token_claims(page).get("amr") or []


START = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())  # the history's RFC 3339 times compare as text


def main() -> int:
    with sync_playwright() as pw_:
        browser = pw_.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])

        def new_context():
            ctx = browser.new_context()
            ctx.set_default_timeout(TIMEOUT_MS)
            ctx.add_init_script(HIDE_SECRET)
            ctx.on("page", lambda p: p.on("dialog", lambda d: d.accept(d.default_value)))
            return ctx

        def key_context(creds_key: str):
            """A context with a virtual key holding state[creds_key]'s credentials."""
            ctx = new_context()
            page = ctx.new_page()
            s.Key(page, credentials=state[creds_key])
            return ctx, page

        restore: dict = {}

        # ── setup ──
        def setup_link_refused_while_off():
            view = hub_ok("GET", "/api/signin")
            restore["methods"] = {m["id"]: m["on"] for m in view["methods"]}
            restore["people"] = view["core"].get("people", "")
            restore["add_stronger"] = view.get("add_stronger", False)
            assert restore["methods"].get("totp") is False, f"totp isn't off at the start: {restore['methods']}"
            code, out = hub("POST", "/api/directory/users/pat/invite", {"authenticator": True})
            assert code == 409 and "authenticator apps are off on this server" in str(out), f"HTTP {code} {str(out)[:200]}"
            code, out = hub("POST", "/api/directory/users/pat/invite", {"authenticator": True, "x": 1})
            assert code == 400, f"unknown key: HTTP {code}"
        check("setup_link_refused_while_off: a setup link with the authenticator option is refused (409) while "
              "totp is off", setup_link_refused_while_off)

        def setup():
            hub_ok("PUT", "/api/signin/methods/totp", {"on": True})
            hub_ok("PUT", "/api/signin/methods/password", {"on": True})
            if restore.get("add_stronger"):
                hub_ok("PUT", "/api/signin/add-stronger", {"on": False})
            until("totp and password on in signin-keycloak.json",
                  lambda: {"totp", "password"} <= set(s.published()["methods"]), 60)
            code, out = hub("POST", "/api/signin/templates", {"id": TEMPLATE, "name": "Password + code (e2e)",
                                                              "rule": {"op": "all", "items": ["password", "totp"]}})
            assert code in (200, 201), f"create {TEMPLATE}: HTTP {code} {str(out)[:300]}"
            state["template"] = True
            run_op("POST", "/api/instances", {"template": "echo", "id": INSTANCE, "label": "Echo OTP",
                                              "hosts": {"echo": f"{INSTANCE}.{DOMAIN}"}}, "create", INSTANCE)
            state["instance"] = True
            hub_ok("PUT", f"/api/instances/{INSTANCE}/settings", {"sign_in_template": TEMPLATE})
            for u in ("pat", "alice"):
                code, out = hub("POST", f"/api/directory/groups/users_{INSTANCE}/members", {"username": u})
                assert code in (200, 201, 409), f"add {u}: HTTP {code} {str(out)[:200]}"
            run_op("POST", "/api/templates/enable", {"id": INSTANCE}, "enable", INSTANCE)
            until(f"{INSTANCE} on {TEMPLATE} in the policy",
                  lambda: s.hub_json("group-gate-policy.json")["hosts"].get(f"{INSTANCE}.{DOMAIN}") == TEMPLATE, 60)
            until(f"{INSTANCE} routed", lambda: s.curl_tls(f"{INSTANCE}.{DOMAIN}")[1] in ("302", "401", "403"), 120)
            # pat: his password only (e2e_signin gave him a device-bound passkey).
            uid = kc_user_id("pat")
            for c in kc(f"/users/{uid}/credentials"):
                if c["type"] in s.PASSKEY_TYPES or c["type"] == "otp":
                    kc(f"/users/{uid}/credentials/{c['id']}", "DELETE")
            kc(f"/users/{uid}/logout", "POST")
            kc(f"/attack-detection/brute-force/users/{uid}", "DELETE")
            s.wait_people("pat", ["password"])
            state["setup"] = True
        check(f"setup: totp and password on, {TEMPLATE} = all[password, totp], {INSTANCE} on it (pat, alice)", setup)

        def policy_read_back():
            realm = kc("")
            got = {k: realm.get(k) for k in ("otpPolicyType", "otpPolicyAlgorithm", "otpPolicyDigits", "otpPolicyPeriod",
                                             "otpPolicyLookAheadWindow", "otpPolicyCodeReusable", "otpPolicyInitialCounter")}
            assert got == {"otpPolicyType": "totp", "otpPolicyAlgorithm": "HmacSHA1", "otpPolicyDigits": 6,
                           "otpPolicyPeriod": 30, "otpPolicyLookAheadWindow": 1, "otpPolicyCodeReusable": False,
                           "otpPolicyInitialCounter": 0}, got
            for ra in ("CONFIGURE_TOTP", "delete_credential"):
                a = kc(f"/authentication/required-actions/{ra}")
                assert a["enabled"] and not a["defaultAction"], a
                assert kc(f"/authentication/required-actions/{ra}/config")["config"].get("max_auth_age") == "300", ra
        check("policy_read_back: the realm OTP policy is HmacSHA1 / 6 / 30 s / look-ahead 1 / not reusable / 0; "
              "CONFIGURE_TOTP and delete_credential on with max_auth_age 300", policy_read_back)

        def editor_refuses_code_only():
            bad = {"op": "any", "items": ["totp", "security_key"]}
            code, out = hub("POST", "/api/signin/templates", {"id": "e2e-code-only", "name": "Code only", "rule": bad})
            assert code == 400 and CODE_ONLY_TEXT in str(out), f"save: HTTP {code} {str(out)[:300]}"
            code, out = hub("POST", "/api/signin/templates/preview", {"id": "e2e-code-only", "name": "Code only", "rule": bad})
            assert code == 200 and CODE_ONLY_TEXT in str(out.get("problem", "")) and out.get("code_only") == [[]], \
                f"preview: HTTP {code} {str(out)[:300]}"
            assert all(t["id"] != "e2e-code-only" for t in hub_ok("GET", "/api/signin")["templates"])
        check("editor_refuses_code_only: any[totp, security_key] — save 400 with the text, preview 200 with "
              "problem and code_only [[]]", editor_refuses_code_only)

        # ── pat: no authenticator yet ──
        def no_code_only_way_in():
            needs("setup")
            ctx = new_context()
            page = ctx.new_page()
            try:
                # A step-up asking for the code on a cold browser: no code
                # field, no code among the other ways, before a password.
                goto(page, f"{AUTH}/oauth2/start?" + urllib.parse.urlencode({"pc_method": "totp", "rd": ECHO_OTP + "/"}))
                s.kc_page(page)
                assert not visible(page, "#otp"), "a code field on a cold sign-in"
                ways = offered(page)
                if offers_code(ways):
                    shot(page, "cold-offers-code")
                    page.get_by_text("Authenticator app", exact=True).first.click()
                    page.wait_for_load_state("domcontentloaded")
                    shot(page, "cold-chose-code")
                    raise AssertionError(f"a cold sign-in offers a code ({ways}); chosen: otp field {visible(page, '#otp')}, "
                                         f"username field {visible(page, '#username')}, at {page.url.split('?')[0]}: "
                                         f"{body(page)[:200]!r}")
                shot(page, "cold-pc-method-totp")
                # pat's username with a code as the password: refused, no session.
                goto(page, ECHO_OTP + "/")
                s.kc_page(page)
                type_password(page, "pat", "123456")
                assert on_kc(page) and visible(page, "#password"), f"not refused: {page.url.split('?')[0]}"
                assert not s.kc_sessions("pat"), "a Keycloak session for pat"
            finally:
                ctx.close()
            uid = kc_user_id("pat")
            kc(f"/attack-detection/brute-force/users/{uid}", "DELETE")
        check("no_code_only_way_in: a cold sign-in (also with pc_method=totp) asks for no code and offers none; "
              "pat's username with a code as the password gets no session", no_code_only_way_in)

        def pat_cap_refused():
            needs("setup")
            ctx = new_context()
            page = ctx.new_page()
            try:
                goto(page, PEOPLE + "/signin")
                s.kc_page(page)
                type_password(page, "pat", pat_password())
                finish(page, PEOPLE + "/signin")
                page.wait_for_selector("[data-msi-askadmin], [data-msi-act=totp-add]")
                shot(page, "pat-signin-page-capped")
                assert page.locator("[data-msi-act=totp-add]").count() == 0, "+ Add offered to a password-only person"
                assert page.locator("[data-msi-askadmin]").count() >= 1, "no \"ask your admin\""
                # The account console's path and a hand-made URL both run the override.
                goto(page, aia_url("CONFIGURE_TOTP"))
                type_password(page, "pat", pat_password())
                text = refusal(page)
                shot(page, "pat-cap-refused")
                assert "stronger than the way you signed in" in text, text[:300]
            finally:
                ctx.close()
            assert otp_ids("pat") == [], "an authenticator was stored"
        check("pat_cap_refused: pat's password-only session — the Sign-in page says \"ask your admin\" (no + Add); "
              "a hand-made kc_action=CONFIGURE_TOTP is refused by the cap, nothing stored", pat_cap_refused)

        def setup_link(user: str, creds_key: str) -> tuple[str, str]:
            """The Hub's setup link with the authenticator option: the
            passkey (a virtual key), then Keycloak's authenticator setup,
            then the step-up with the new key; lands on the portal."""
            code, out = hub("POST", f"/api/directory/users/{user}/invite", {"authenticator": True})
            assert code == 200, f"invite {user}: HTTP {code} {s.redact(str(out))[:200]}"
            m = s.SETUP_LINK.search(json.dumps(out))
            assert m, "no setup link in the answer"
            link = m.group(0)
            mask(link)
            ctx = new_context()
            page = ctx.new_page()
            key = s.Key(page)
            got = None
            try:
                goto(page, link)
                deadline = time.time() + 120
                while time.time() < deadline:
                    page.wait_for_load_state("domcontentloaded")
                    if setup_page(page):
                        assert got is None, "a second authenticator setup page"
                        assert key.registered >= 1, "the authenticator setup before the passkey"
                        got = configure(page)
                        continue
                    if page.url.startswith(PORTAL) and not base.on_login_pages(page):
                        if visible(page, "#stepup-continue"):
                            page.click("#stepup-continue")
                            continue
                        if "Signed in as" in page.content():
                            break
                    if dismiss_notice(page):
                        continue
                    if visible(page, "#invite-continue"):
                        page.click("#invite-continue")
                        continue
                    if visible(page, "#registerWebAuthn"):
                        page.click("#registerWebAuthn")
                        page.wait_for_timeout(1500)
                        continue
                    if visible(page, "#authenticateWebAuthnButton"):
                        page.click("#authenticateWebAuthnButton")
                        page.wait_for_timeout(1500)
                        continue
                    assert not visible(page, "#kc-error-message"), body(page)[:300]
                    page.wait_for_timeout(500)
                else:
                    raise AssertionError(f"setup link: stuck at {page.url.split('?')[0]}")
                assert got, "no authenticator setup page after the passkey"
                state[creds_key] = key.credentials()
            finally:
                ctx.close()
            return got

        def pat_setup_link_authenticator():
            needs("setup")
            label, _ = setup_link("pat", "pat_creds")
            state["pat_first"] = label
            ids = otp_ids("pat")
            assert [c["userLabel"] for c in ids] == [label], ids
            assert not kc(f"/users/{kc_user_id('pat')}").get("requiredActions"), "a required action left on pat"
            # group-gate's people list (the Hub's inventory, at most 30 s
            # old) must know the code before the pages offer its step-up.
            s.wait_people_has("pat", "totp", True)
        check("pat_setup_link_authenticator: the Hub's setup link with the authenticator option — the passkey, "
              "then Keycloak's authenticator setup (secret read from the manual key, never shown); one otp credential",
              pat_setup_link_authenticator)

        def signin_password_code(page: Page, url: str, label: str | None = None, code: str | None = None) -> None:
            goto(page, url)
            s.kc_page(page)
            type_password(page, "pat", pat_password())
            type_code(page, code or code_now(SECRETS[label or state["pat_first"]]), label)

        def password_then_code():
            needs("pat_first")
            ctx = new_context()
            page = ctx.new_page()
            try:
                signin_password_code(page, ECHO_OTP + "/")
                finish(page, ECHO_OTP + "/")
                until("the echo page", lambda: "Hostname" in body(page), 20, every=1)
                assert s.headers_of(body(page)).get("x-forwarded-user") == ["pat"]
                a = amr(page)
                assert "pwd" in a and "otp" in a, a
                # A forward-auth app: the password sign-in, then group-gate's
                # step-up asking the code: two LOGIN events (pc_methods of each
                # authentication), the code's a step_up.
                until("LOGIN events: password, then the code's step_up",
                      lambda: [((e.get("details") or {}).get("pc_methods"), (e.get("details") or {}).get("pc_kind"))
                               for e in kc_events("pat", "LOGIN", 2)] == [("totp", "step_up"), ("password", "sign_in")],
                      30, every=2)
                state["pat_pwd_otp"] = True
            finally:
                ctx.close()
        check("password_then_code: echo-otp (all[password, totp]) — the password, then group-gate's step-up asks the "
              "code; amr pwd + otp; LOGIN pc_methods password (sign_in), then totp (step_up)", password_then_code)

        def sso_stepup_only_code():
            needs("pat_first")
            s.wait_people_has("pat", "totp", True)
            ctx = new_context()
            page = ctx.new_page()
            try:
                goto(page, ECHO_BASIC + "/")
                s.kc_page(page)
                type_password(page, "pat", pat_password())
                finish(page, ECHO_BASIC + "/")
                assert "otp" not in amr(page)
                resp = goto(page, ECHO_OTP + "/")
                assert resp and resp.status == 403 and visible(page, "#stepup-continue"), \
                    f"no step-up page: {resp and resp.status} {body(page)[:200]!r}"
                href = page.locator("#stepup-continue").get_attribute("href") or ""
                assert urllib.parse.parse_qs(urllib.parse.urlsplit(href).query).get("pc_method") == ["totp"], href
                shot(page, "pat-stepup-totp")
                page.click("#stepup-continue")
                s.kc_page(page)
                assert not visible(page, "input[type=password]") and not visible(page, "#authenticateWebAuthnButton"), \
                    "more than the code asked"
                type_code(page, code_now(SECRETS[state["pat_first"]]))
                finish(page, ECHO_OTP + "/")
                a = amr(page)
                assert "pwd" in a and "otp" in a, a
            finally:
                ctx.close()
        check("sso_stepup_only_code: pat's password session on echo-basic, then echo-otp: group-gate's step-up "
              "pc_method=totp, Keycloak asks only for the code", sso_stepup_only_code)

        def wrong_code_failed():
            needs("pat_first")
            uid = kc_user_id("pat")
            kc(f"/attack-detection/brute-force/users/{uid}", "DELETE")
            ctx = new_context()
            page = ctx.new_page()
            try:
                goto(page, ECHO_OTP + "/")
                s.kc_page(page)
                type_password(page, "pat", pat_password())
                right = code_now(SECRETS[state["pat_first"]])
                wrong = f"{(int(right) + 500000) % 1000000:06d}"
                type_code(page, wrong)
                assert code_error(page), f"a wrong code wasn't refused: {page.url.split('?')[0]}"
                shot(page, "pat-wrong-code")
                bf = kc(f"/attack-detection/brute-force/users/{uid}")
                assert bf.get("numFailures") == 1, bf
            finally:
                ctx.close()
            until("history: failed, wrong authenticator code",
                  lambda: any(e["kind"] == "failed" and e.get("reason") == "wrong authenticator code" and e.get("methods") == ["totp"]
                              for e in history("pat")), 60)
            kc(f"/attack-detection/brute-force/users/{uid}", "DELETE")
        check("wrong_code_failed: a wrong code is refused; pat's history has a failed \"wrong authenticator code\"; "
              "brute force counted 1", wrong_code_failed)

        def replay_refused():
            needs("pat_first")
            secret = SECRETS[state["pat_first"]]
            ctx1, ctx2 = new_context(), new_context()
            try:
                p1, p2 = ctx1.new_page(), ctx2.new_page()
                for p in (p1, p2):
                    goto(p, ECHO_OTP + "/")
                    s.kc_page(p)
                    type_password(p, "pat", pat_password())
                code = code_now(secret, min_left=12)
                type_code(p1, code)
                finish(p1, ECHO_OTP + "/")
                type_code(p2, code)
                assert code_error(p2), "the same code accepted twice"
            finally:
                ctx1.close()
                ctx2.close()
            kc(f"/attack-detection/brute-force/users/{kc_user_id('pat')}", "DELETE")
        check("replay_refused: one code, two sign-ins in the same time step — the second is refused", replay_refused)

        def window():
            needs("pat_first")
            secret = SECRETS[state["pat_first"]]
            totp = pyotp.TOTP(secret)
            ctx = new_context()
            page = ctx.new_page()
            goto(page, ECHO_OTP + "/")
            s.kc_page(page)
            type_password(page, "pat", pat_password())
            # Mid-step, with the previous step unused: its code (-30 s) is accepted, -90 s refused.
            while True:
                now = time.time()
                st = step_of(now)
                if (secret, st - 1) not in USED and (secret, st - 3) not in USED and (st + 1) * 30 - now >= 15:
                    break
                time.sleep((st + 1) * 30 - now + 0.5)
            old, previous = totp.at(now - 90), totp.at(now - 30)
            USED.update({(secret, st - 3), (secret, st - 1)})
            try:
                type_code(page, old)
                assert code_error(page), "a 90 s old code accepted"
                type_code(page, previous)
                finish(page, ECHO_OTP + "/")
            finally:
                ctx.close()
            kc(f"/attack-detection/brute-force/users/{kc_user_id('pat')}", "DELETE")
        check("window: the previous step's code (−30 s) is accepted, a −90 s one refused", window)

        def fresh_one_code():
            needs("pat_first")
            hub_ok("PUT", "/api/signin/core/people", {"template": TEMPLATE})
            try:
                view = people_json("pat", "GET", "/api/me/signin")
                assert (view.get("fresh_auth") or {}).get("pc_method") == "totp", view.get("fresh_auth")
                ctx = new_context()
                page = ctx.new_page()
                try:
                    goto(page, PEOPLE + "/signin")  # the Sign-in page's paths take any switched-on method
                    s.kc_page(page)
                    type_password(page, "pat", pat_password())
                    finish(page, PEOPLE + "/signin")
                    secret = SECRETS[state["pat_first"]]

                    def popup(label: str, with_code: bool) -> dict:
                        """The Hub's popup flow (prompt=login, max_age=0), pc_method=totp."""
                        rd = s.Redirect(page, PEOPLE + "/signin")
                        verifier, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(16)
                        challenge = s.base64.urlsafe_b64encode(s.hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                        extra = {"pc_method": "totp"} if with_code else {}
                        goto(page, s.authorize_url("portcullis-fresh-auth", PEOPLE + "/signin", prompt="login", max_age="0",
                                                   nonce=nonce, code_challenge=challenge, code_challenge_method="S256", **extra))
                        type_password(page, "pat", pat_password())
                        if with_code:
                            type_code(page, code_now(secret))
                        until(f"{label}: the code at the redirect URI (or a code asked)",
                              lambda: rd.code() is not None or visible(page, "#otp"), 30, every=0.5)
                        if rd.code() is None:
                            return None
                        return {"code": rd.code(), "code_verifier": verifier, "nonce": nonce}

                    # The proof's claims (exchanged here, a throwaway): pc_fresh totp, a primary in amr.
                    pr = popup("claims", True)
                    tok = s.exchange(page, "portcullis-fresh-auth", PEOPLE + "/signin", pr["code"], verifier=pr["code_verifier"])
                    claims = s.claims_of(tok["id_token"])
                    assert claims.get("pc_fresh") == "totp" and "pwd" in (claims.get("amr") or []), \
                        {k: claims.get(k) for k in ("pc_fresh", "amr")}
                    until("the fresh sign-in's LOGIN: pc_methods password,totp",
                          lambda: any((e.get("details") or {}).get("pc_methods") == "password,totp"
                                      and e.get("clientId") == "portcullis-fresh-auth" for e in kc_events("pat", "LOGIN", 5)),
                          30, every=2)
                    new_pw = "Ci-" + secrets.token_urlsafe(18)
                    mask(new_pw)
                    # A password alone isn't the governing template's fresh method.
                    pr = popup("password only", False)
                    if pr is None:
                        print("    password only: Keycloak itself asked for the code", flush=True)
                    else:
                        code, out = people_as("pat", "PUT", "/api/me/signin/password", dict(pr, password=new_pw))
                        assert code == 403, f"password-only fresh proof: HTTP {code} {out[:200]}"
                    pr = popup("password and code", True)
                    code, out = people_as("pat", "PUT", "/api/me/signin/password", dict(pr, password=new_pw))
                    assert code == 204, f"one code: HTTP {code} {out[:200]}"
                    fd = os.open(os.environ["E2E_PAT_PASSWORD_FILE"], os.O_WRONLY | os.O_TRUNC)
                    try:
                        os.write(fd, new_pw.encode())
                    finally:
                        os.close(fd)
                finally:
                    ctx.close()
            finally:
                hub_ok("PUT", "/api/signin/core/people", {"template": restore.get("people") or "strong"})
        check("fresh_one_code: people core e2e-otp — the Hub's fresh_auth asks pc_method=totp; Keycloak asks the "
              "password, then the code (pc_fresh totp, pwd in amr); that proof changes pat's password, a password-only "
              "proof gets 403", fresh_one_code)

        # ── the Sign-in page's popups ──
        def signin_page(page: Page) -> None:
            goto(page, PEOPLE + "/signin")
            if on_kc(page):
                page.click("#authenticateWebAuthnButton")
            finish(page, PEOPLE + "/signin")
            page.wait_for_selector("[data-msi-act=totp-add], [data-msi-act=totp-rename], [data-msi-askadmin]")

        def popup_action(page: Page, selector: str, kind: str):
            """Click a Sign-in page button that opens Keycloak in the popup;
            the popup re-authenticates with the virtual key; returns the
            popup (still open on the setup page, or closed when done)."""
            with page.context.expect_page() as info:
                page.click(selector)
            pop = info.value
            pop.wait_for_load_state("domcontentloaded")
            s.Key(pop, credentials=state["pat_creds"])
            deadline = time.time() + 60
            looked = [False]
            while time.time() < deadline and not pop.is_closed():
                try:
                    pop.wait_for_load_state("domcontentloaded")
                    if kind == "configure" and setup_page(pop):
                        return pop
                    if visible(pop, "#otp"):
                        raise AssertionError("the popup asked for a code")
                    if visible(pop, "#authenticateWebAuthnButton"):
                        if kind == "remove" and not looked[0]:
                            looked[0] = True
                            ways = offered(pop)
                            assert not offers_code(ways), f"a code offered on the removal's re-authentication: {ways}"
                            if ways:  # back to the passkey through the list itself
                                pop.get_by_text("Passkey", exact=True).first.click()
                                pop.wait_for_load_state("domcontentloaded")
                            continue
                        pop.click("#authenticateWebAuthnButton")
                        pop.wait_for_timeout(1500)
                        continue
                    if kind == "remove" and visible(pop, "#kc-accept, button[name=accept]"):
                        pop.click("#kc-accept, button[name=accept]")
                        continue
                    if visible(pop, "#kc-error-message") or "not added" in body(pop):
                        return pop
                except PWError as e:
                    if "closed" in str(e) or "Execution context was destroyed" in str(e):
                        break
                    raise
                pop.wait_for_timeout(500)
            return pop

        def wait_status(page: Page, text: str) -> None:
            until(f"the Sign-in page says {text!r}", lambda: text in body(page), 60, every=1)

        def add_replace_rename_remove():
            needs("pat_creds", "pat_first")
            ctx, page = key_context("pat_creds")
            try:
                signin_page(page)
                assert page.locator("[data-msi-act=totp-add]").count() == 1, "no + Add for pat (a security key set up)"
                pop = popup_action(page, "[data-msi-act=totp-add]", "configure")
                assert setup_page(pop), f"+ Add: no setup page ({body(pop)[:200]!r})"
                label2, _ = configure(pop)
                wait_status(page, "Authenticator app added.")
                labels = [a["label"] for a in my_authenticators("pat")]
                assert labels == [state["pat_first"], label2], labels
                c2 = new_context()
                p2 = c2.new_page()
                try:
                    signin_password_code(p2, ECHO_OTP + "/", label2, code_now(SECRETS[label2]))
                    finish(p2, ECHO_OTP + "/")
                finally:
                    c2.close()
                # Replace the second: a new secret, the old one refused.
                id2 = next(c["id"] for c in otp_ids("pat") if c["userLabel"] == label2)
                old_secret = SECRETS[label2]
                pop = popup_action(page, f"[data-msi-act=totp-replace][data-cred='{id2}']", "configure")
                assert setup_page(pop), f"Replace: no setup page ({body(pop)[:200]!r})"
                label3, new_secret = configure(pop)
                wait_status(page, "Authenticator app replaced.")
                ids = otp_ids("pat")
                assert id2 not in [c["id"] for c in ids] and label3 in [c["userLabel"] for c in ids], ids
                state["pat_third"] = label3
                c2 = new_context()
                p2 = c2.new_page()
                try:
                    signin_password_code(p2, ECHO_OTP + "/", label3, code_now(old_secret))
                    assert code_error(p2), "the replaced app's code still works"
                    type_code(p2, code_now(new_secret), label3)
                    finish(p2, ECHO_OTP + "/")
                finally:
                    c2.close()
                kc(f"/attack-detection/brute-force/users/{kc_user_id('pat')}", "DELETE")
                # Rename (its own route); a passkey's id is 404.
                id3 = next(c["id"] for c in otp_ids("pat") if c["userLabel"] == label3)
                code, out = people_as("pat", "PUT", f"/api/me/signin/authenticators/{id3}/label", {"label": "CI phone"})
                assert code == 204, f"rename: HTTP {code} {out[:200]}"
                pk = next(c["id"] for c in kc(f"/users/{kc_user_id('pat')}/credentials") if c["type"] in s.PASSKEY_TYPES)
                code, out = people_as("pat", "PUT", f"/api/me/signin/authenticators/{pk}/label", {"label": "x"})
                assert code == 404 and "no such authenticator app" in out, f"a passkey id: HTTP {code} {out[:200]}"
                SECRETS["CI phone"] = SECRETS.pop(label3)
                state["pat_third"] = "CI phone"
                state["pat_rows"] = True
            finally:
                ctx.close()
        check("add_replace_rename_remove (add, replace, rename): the Sign-in page's + Add and Replace open "
              "CONFIGURE_TOTP[:<id>] in the popup; the replaced app's code is refused, the new one works; rename 204, "
              "a passkey's id 404", add_replace_rename_remove)

        def fourth_refused():
            needs("pat_rows")
            ctx, page = key_context("pat_creds")
            try:
                signin_page(page)
                pop = popup_action(page, "[data-msi-act=totp-add]", "configure")
                configure(pop)
                wait_status(page, "Authenticator app added.")
                page.reload()
                page.wait_for_selector("[data-msi-act=totp-rename]")
                assert page.locator("[data-msi-act=totp-add]").count() == 0, "+ Add offered at 3"
                assert len(otp_ids("pat")) == 3
                # By hand, in a browser with a fresh copy of pat's key (a copy's
                # signature counter must be above every earlier copy's).
                c4, p4 = key_context("pat_creds")
                try:
                    goto(p4, aia_url("CONFIGURE_TOTP"))
                    p4.wait_for_selector("#authenticateWebAuthnButton", state="visible")
                    with p4.expect_navigation(wait_until="domcontentloaded"):
                        p4.click("#authenticateWebAuthnButton")
                    until("past the passkey page", lambda: not visible(p4, "#authenticateWebAuthnButton"), 30, every=1)
                    text = refusal(p4)
                    shot(p4, "pat-fourth-refused")
                finally:
                    c4.close()
                assert "you already have 3 authenticator apps: remove one first" in text, text[:300]
                assert len(otp_ids("pat")) == 3, "a fourth stored"
                # The removal (delete_credential:<id>, Keycloak's own confirmation), its re-authentication never code-only.
                signin_page(page)
                victim = next(a for a in my_authenticators("pat") if a["label"] == "CI phone")
                pop = popup_action(page, f"[data-msi-act=totp-remove][data-cred='{victim['id']}']", "remove")
                wait_status(page, "Authenticator app removed.")
                assert victim["id"] not in [c["id"] for c in otp_ids("pat")]
                state["pat_removed"] = True
            finally:
                ctx.close()
        check("fourth_refused / remove: at 3 the page offers no + Add, a hand-made 4th is refused (\"you already have "
              "3 …\"); Remove opens delete_credential:<id>, whose re-authentication offers no code", fourth_refused)

        def history_method_entries():
            needs("pat_removed")
            entries = [e for e in history("pat") if e.get("time", "") >= START]
            method = [e["detail"] for e in entries if e["kind"] == "method"]
            print(f"    pat's method entries: {method}", flush=True)
            assert sum(d.startswith("authenticator app added: ") for d in method) == 3, method
            assert sum(d.startswith("authenticator app replaced: ") for d in method) == 1, method
            assert sum(d.startswith("authenticator app removed: ") for d in method) == 1, method
            assert any(d == "authenticator app removed: CI phone" for d in method), method
            assert all(e["kind"] != "method" or e.get("methods") == ["totp"] for e in entries)
        check("history_method_entries: pat's history has exactly the 3 added, 1 replaced and 1 removed authenticator "
              "app entries (never from a LOGIN event)", history_method_entries)

        def cli_setup_link(page: Page, user: str, until_: str) -> None:
            """./portcullis invite <user> (the CLI path, never an authenticator
            step): the passkey registered by page's virtual key, then the
            step-up with it; lands on until_."""
            goto(page, base.mint_setup_link(user, "hub" if until_.startswith(s.HUB) else "portal"))
            deadline = time.time() + 120
            while time.time() < deadline:
                page.wait_for_load_state("domcontentloaded")
                assert not setup_page(page), f"an authenticator setup on {user}'s CLI setup link"
                if page.url.startswith(until_) and not base.on_login_pages(page):
                    if visible(page, "#stepup-continue"):
                        page.click("#stepup-continue")
                        continue
                    if not visible(page, "#needs-stronger"):
                        return
                for sel in ("#invite-continue", "#registerWebAuthn", "#authenticateWebAuthnButton"):
                    if visible(page, sel):
                        page.click(sel)
                        page.wait_for_timeout(1500)
                        break
                else:
                    page.wait_for_timeout(500)
            raise AssertionError(f"{user}'s setup link: stuck at {page.url.split('?')[0]}")

        def root_impersonating_pat():
            needs("pat_first")
            view = hub_ok("GET", "/api/impersonations")
            assert view.get("allowed") is True and not view.get("running"), view
            before = len(otp_ids("pat"))
            ctx = new_context()
            page = ctx.new_page()
            s.Key(page)
            started = False
            try:
                cli_setup_link(page, "root", s.HUB + "/")
                tok = s.access_token(page)
                assert tok, "no access token for root"
                proof = s.fresh_code(page, "root-imp-fresh", s.HUB + "/")
                code, out = s.hub_as("root", "POST", "/api/directory/users/pat/impersonation",
                                     dict(proof, reason="checking authenticator codes"),
                                     headers={"X-Forwarded-Access-Token": tok})
                assert code == 200, f"start root → pat: HTTP {code} {out[:300]}"
                started = True
                goto(page, json.loads(out)["next"])
                page.wait_for_url(re.compile("^" + re.escape(PORTAL)), timeout=TIMEOUT_MS)
                # echo-otp: the impersonation's needs page (root's sign-in has
                # no password and code of pat's), never a step-up asking pat's code.
                resp = goto(page, ECHO_OTP + "/")
                shot(page, "root-imp-echo-otp")
                assert resp and resp.status == 403, f"echo-otp while impersonating: HTTP {resp and resp.status}"
                assert page.locator("#needs-stronger[data-impersonated=true]").count() == 1, body(page)[:300]
                assert not visible(page, "#stepup-continue"), "a step-up while impersonating"
                # + Add (a hand-made CONFIGURE_TOTP): refused, nothing stored.
                goto(page, aia_url("CONFIGURE_TOTP"))
                deadline = time.time() + 30
                while time.time() < deadline and visible(page, "#authenticateWebAuthnButton"):
                    page.click("#authenticateWebAuthnButton")
                    page.wait_for_timeout(1500)
                assert not visible(page, "#otp"), "pat's code asked while impersonating"
                text = refusal(page)
                shot(page, "root-imp-add-refused")
                print(f"    the refusal: {text[:160]!r}", flush=True)
                assert len(otp_ids("pat")) == before, "an authenticator stored while impersonating"
            finally:
                ctx.close()
                if started:
                    hub("POST", "/api/directory/users/pat/impersonation/stop", {})
        check("root_impersonating_pat: root signed in as pat can't open echo-otp (the impersonation's needs page, no "
              "step-up) and gets a refusal on + Add (CONFIGURE_TOTP), nothing stored", root_impersonating_pat)

        def carol_removes_alice():
            needs("setup")
            code, out = hub("POST", "/api/directory/groups", {"name": "hr"})
            assert code in (200, 201, 409), f"hr: HTTP {code}"
            code, out = hub("POST", "/api/directory/groups/hr/members", {"username": "carol"})
            assert code in (200, 201, 409), f"carol in hr: HTTP {code}"
            hub_ok("PUT", "/api/directory/permissions/sign_in_help", {"group": "hr"})
            setup_link("alice", "alice_creds")
            assert len(otp_ids("alice")) == 1
            view = people_json("carol", "GET", "/api/directory/users/alice/signin")
            assert view["can"].get("remove_authenticators"), view["can"]
            code, out = people_as("carol", "POST", "/api/directory/users/alice/remove-authenticators", {"confirm": "alice"})
            assert code == 200, f"carol: HTTP {code} {out[:200]}"
            until("alice's authenticators gone", lambda: otp_ids("alice") == [], 30)
            code, out = people_as("carol", "POST", "/api/directory/users/root/remove-authenticators", {"confirm": "root"})
            assert code in (403, 409), f"carol on root: HTTP {code}"
            until("alice's history: help by carol",
                  lambda: any(e["kind"] == "help" and e.get("by") == "carol" and "authenticator" in (e.get("detail") or "")
                              for e in history("alice")), 60)
        check("carol_removes_alice: alice's setup-link authenticator, removed by carol (sign_in_help: 200, root "
              "refused); alice's history has the help entry", carol_removes_alice)

        def admin_no_code_step():
            needs("setup")
            ctx = new_context()
            page = ctx.new_page()
            key = s.Key(page)
            try:
                link = base.mint_setup_link("admin", "portal")
                goto(page, link)
                deadline = time.time() + 120
                while time.time() < deadline:
                    page.wait_for_load_state("domcontentloaded")
                    assert not setup_page(page), "an authenticator setup for admin"
                    assert not visible(page, "#otp"), "a code step for admin"
                    if page.url.startswith(PORTAL) and not base.on_login_pages(page):
                        if visible(page, "#stepup-continue"):
                            page.click("#stepup-continue")
                            continue
                        if "Signed in as" in page.content():
                            break
                    for sel in ("#invite-continue", "#registerWebAuthn", "#authenticateWebAuthnButton"):
                        if visible(page, sel):
                            page.click(sel)
                            page.wait_for_timeout(1500)
                            break
                    else:
                        page.wait_for_timeout(500)
                assert key.registered >= 1, "admin's key wasn't registered"
                goto(page, aia_url("CONFIGURE_TOTP"))
                page.wait_for_selector("#authenticateWebAuthnButton", state="visible")
                with page.expect_navigation(wait_until="domcontentloaded"):
                    page.click("#authenticateWebAuthnButton")
                until("past the passkey page", lambda: not visible(page, "#authenticateWebAuthnButton"), 30, every=1)
                text = refusal(page)
                assert "aren't available for this account" in text, text[:300]
                assert otp_ids("admin") == []
            finally:
                ctx.close()
        check("admin_no_code_step: admin's sign-in never asks for a code; a hand-made CONFIGURE_TOTP is refused "
              "(\"not available for this account\")", admin_no_code_step)

        # ── no secret anywhere, then put everything back ──
        def no_secret_anywhere():
            assert SECRETS, "no secret was read (nothing to check)"
            forms = set().union(*(variants(v) for v in SECRETS.values()))
            logs = subprocess.run(["docker", "compose", "logs", "--no-color"], capture_output=True, text=True).stdout
            places = {"docker compose logs": logs, "the Hub's audit file": s.hub_file("audit.jsonl"),
                      "the audit API": json.dumps(hub_ok("GET", "/api/directory/audit"))}
            for u in ("pat", "alice", "admin"):
                places[f"{u}'s history"] = json.dumps(history(u))
                places[f"{u}'s Sign-in view"] = json.dumps(people_json(u, "GET", "/api/me/signin"))
            for root_, _, files in os.walk(s.ART):
                for f in files:
                    with open(os.path.join(root_, f), "rb") as fh:
                        places[f"artifact {f}"] = fh.read().decode(errors="replace")
            leaks = [where for where, text in places.items() if any(f in text for f in forms)]
            assert not leaks, f"a secret found in: {leaks}"
        check("no_secret_anywhere: no authenticator secret (nor its lowercase / unpadded forms) in docker compose logs, "
              "the Hub's audit, the history, the Sign-in views or the artifacts", no_secret_anywhere)

        def finally_():
            problems = []

            def attempt(what, fn):
                try:
                    fn()
                except Exception as e:  # noqa: BLE001
                    problems.append(f"{what}: {e}")
            if state.get("instance"):
                attempt("delete echo-otp", lambda: run_op("DELETE", f"/api/instances/{INSTANCE}", {"confirm": INSTANCE},
                                                          "delete", INSTANCE))
            if state.get("template"):
                attempt("delete e2e-otp", lambda: _ok(hub("DELETE", f"/api/signin/templates/{TEMPLATE}"), (200, 204)))
            for u in ("pat", "alice", "admin"):
                for c in otp_ids(u):
                    attempt(f"{u}'s authenticator", lambda u=u, c=c: kc(f"/users/{kc_user_id(u)}/credentials/{c['id']}", "DELETE"))
            m = restore.get("methods") or {}
            attempt("totp off", lambda: hub_ok("PUT", "/api/signin/methods/totp", {"on": False}))
            if "password" in m:
                attempt("password back", lambda: hub_ok("PUT", "/api/signin/methods/password", {"on": m["password"]}))
            if restore.get("add_stronger"):
                attempt("add_stronger back", lambda: hub_ok("PUT", "/api/signin/add-stronger", {"on": True}))
            assert not problems, problems
            assert hub_ok("GET", "/api/signin")["core"].get("people") == (restore.get("people") or "strong")
        check("finally: echo-otp and e2e-otp removed, every authenticator removed, totp off, password and "
              "add_stronger back", finally_)
        browser.close()

    for n in range(1, s._kicks[0] + 1):
        hub("DELETE", f"/api/directory/groups/ci-kick-{n}", {"confirm": f"ci-kick-{n}"})
    results = s.results
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write("### Authenticator codes (e2e_totp)\n\n")
            for name, ok, _ in results:
                f.write(f"- {'✅' if ok else '❌'} {name.split(':')[0]}\n")
    for name, _, err in failed:
        print(f"  FAIL {name}: {err}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
