#!/usr/bin/env python3
"""End-to-end login test: Traefik -> oauth2-proxy -> Keycloak -> group-gate.

Runs in CI (job `e2e` in .github/workflows/ci.yml) against a full core stack
plus a whoami test app with three hosts:

  app.<domain>    users_e2e group; path_groups /admin -> admin_e2e; the
                  default template (the Hub's fresh-install Standard: any
                  passkey or a YubiKey certificate)
  hwk.<domain>    template any[security_key]
  mtls.<domain>   template any[yubikey_cert] (X.509 login through Keycloak +
                  mtls binding)

The workflow writes policy file v7 and signin-keycloak.json (no Hub in this
job); the latter's trust list holds the CI fixture
tests/e2e/fixtures/virtual-authenticators.json, so the virtual key registers
as a security key. Sign-in is passkey-only. Every user starts from a one-time
setup link (`portcullis invite`): open it, register the key, then group-gate's
step-up page (a setup-link session, amr inv, meets no template) asks for the
new key once more, and the browser lands on the app — the test fails on ANY
password field or a needs-stronger page. Then: the session reaches the apps, a second
login in a fresh browser is one passkey touch, the link is single use, the
session survives two refreshes with concurrent requests (refresh_rotation,
contract §8), a user
outside the group is denied, the bootstrap admin's link lands on the portal
with the Hub link, an unused link cannot sign in to another client through
the invite identity provider (post-broker deny, contract §8), X.509 login /
mtls binding, a cert-only session (no authenticator) opens a
default-template app (enroll's /self is gone: the renewal is the Sign-in
page's, e2e_signin.py), revocation / foreign CA; the login theme's brand on
the first sign-in page (login_theme_brand: css/portcullis.css linked, the
mark as #kc-header-wrapper::before, the favicon = the branding favicon.ico).

Browser: Playwright Chromium with a CDP virtual WebAuthn authenticator
(CTAP2, USB, resident keys, user verification). The CA must be trusted by
Chromium (NSS db) and by Playwright's client-certificate proxy
(NODE_EXTRA_CA_CERTS) — the workflow sets both up.

Environment (all required):
  E2E_DOMAIN          e.g. portcullis.local
  E2E_USER            member of users_e2e (not admin_e2e)
  E2E_INVITE          its setup link (portcullis invite <user> --to https://hwk.<domain>/)
  E2E_OTHER_INVITE    setup link of a user in no group (--to https://app.<domain>/)
  E2E_ADMIN_INVITE    setup link of the bootstrap admin (--to portal)
  E2E_BYPASS_INVITE   setup link of a user in no group (--to https://app.<domain>/)
  E2E_BYPASS_CLIENT   a public Keycloak client (redirect https://app.<domain>/bypass-cb)
                      without the portcullis-invite-client scope
  E2E_CERT / E2E_KEY                client cert for E2E_USER (Vault-issued)
  E2E_FOREIGN_CERT / E2E_FOREIGN_KEY  cert from an unrelated CA, CN=E2E_USER
  E2E_REVOKE_CMD      command (split like a shell would, no shell) that revokes E2E_CERT
  E2E_ARTIFACTS       directory for screenshots / traces (default ./e2e-artifacts)

Run: python3 tests/e2e/e2e_login.py   (not collected by pytest: needs a live stack)
Against a live server without certs: tests/e2e/e2e_invite.py.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
import traceback
import urllib.parse

from playwright.sync_api import Error as PWError
from playwright.sync_api import Page, sync_playwright

DOMAIN = os.environ["E2E_DOMAIN"]
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
TIMEOUT_MS = 30_000
AUTH = f"https://auth.{DOMAIN}"
# sha256 of the branding favicon.ico (keycloak/themes/portcullis/login/resources/img/; tests/test_branding.py).
FAVICON_ICO_SHA256 = "d709cb96a8d612fc471fa02914d674f03972146a1680db98f97f93e46bcea7a1"
APP = f"https://app.{DOMAIN}"
HWK = f"https://hwk.{DOMAIN}"
MTLS = f"https://mtls.{DOMAIN}"
ENROLL = f"https://enroll.{DOMAIN}"
PORTAL = f"https://{DOMAIN}/"

os.makedirs(ART, exist_ok=True)
_step = 0
results: list[tuple[str, bool, str]] = []


def shot(page: Page, name: str) -> None:
    global _step
    _step += 1
    try:
        page.screenshot(path=os.path.join(ART, f"{_step:02d}-{name}.png"), full_page=True)
        with open(os.path.join(ART, f"{_step:02d}-{name}.html"), "w") as f:
            f.write(page.content())
    except PWError:
        pass


class Authenticator:
    """Virtual FIDO2 security key on a page, answering every prompt
    automatically; counts registrations and assertions."""

    def __init__(self, page: Page, credentials: list | None = None):
        self.cdp = page.context.new_cdp_session(page)
        self.cdp.send("WebAuthn.enable", {"enableUI": False})
        self.id = self.cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2",
            "transport": "usb",
            "hasResidentKey": True,
            "hasUserVerification": True,
            "isUserVerified": True,
            "automaticPresenceSimulation": True,
        }})["authenticatorId"]
        self.registered = 0
        self.asserted = 0
        self.cdp.on("WebAuthn.credentialAdded", lambda _e: setattr(self, "registered", self.registered + 1))
        self.cdp.on("WebAuthn.credentialAsserted", lambda _e: setattr(self, "asserted", self.asserted + 1))
        for c in credentials or []:
            # A copied credential must not go back in its signature counter.
            self.cdp.send("WebAuthn.addCredential", {"authenticatorId": self.id,
                                                     "credential": dict(c, signCount=c.get("signCount", 0) + 1000)})

    def credentials(self) -> list:
        return self.cdp.send("WebAuthn.getCredentials", {"authenticatorId": self.id})["credentials"]


def on_login_pages(page: Page) -> bool:
    return page.url.startswith(AUTH + "/realms/") or page.url.startswith(f"https://enroll.{DOMAIN}/invite/")


def passkey_flow(page: Page, *, until: str, label: str, expect_stepups: int, stepups: list | None = None) -> None:
    """Drive the setup-link page, Keycloak and group-gate's step-up page
    until the browser lands on `until`. Handles: "Register my key" (setup
    link), the passkey registration required action, "Sign in with
    Passkey", and group-gate's step-up page (#stepup-continue, contract §5:
    a setup-link session meets no template, so the new passkey is touched
    once more; each step-up URL is appended to `stepups`). Exactly
    `expect_stepups` step-up pages must appear: one more fails at once (never
    a silent second click), fewer fails on arrival. Fails at once on a
    password field, a Keycloak error, or group-gate's needs-stronger /
    present-certificate page: there are no passwords any more."""
    seen: list = [] if stepups is None else stepups
    deadline = time.time() + 90
    while time.time() < deadline:
        page.wait_for_load_state("domcontentloaded")
        if not on_login_pages(page):
            if page.locator("#stepup-continue").count():
                shot(page, f"{label}-stepup")
                href = page.locator("#stepup-continue").get_attribute("href")
                if len(seen) >= expect_stepups:
                    raise AssertionError(f"step-up page #{len(seen) + 1} at {page.url} (want {expect_stepups}): "
                                         f"{href}; earlier: {seen}")
                seen.append(href)
                page.click("#stepup-continue")
                page.wait_for_timeout(1500)
                continue
            for marker in ("#needs-stronger", "#present-certificate"):
                if page.locator(marker).count():
                    shot(page, f"{label}-{marker[1:]}")
                    raise AssertionError(f"group-gate's {marker} page at {page.url}: {page.inner_text('body')[:300]!r}")
        if page.url.startswith(until) and not on_login_pages(page):
            if len(seen) != expect_stepups:
                raise AssertionError(f"reached {until} after {len(seen)} step-up page(s), want {expect_stepups}")
            return
        if not on_login_pages(page):
            page.wait_for_timeout(500)  # oauth2-proxy redirects on its own
            continue
        shot(page, f"{label}-login")
        pw = page.locator("input[type=password]")
        if pw.count() and pw.first.is_visible():
            raise AssertionError(f"password prompt at {page.url}")
        if page.locator("#invite-continue").is_visible():
            page.click("#invite-continue")
            continue
        if page.locator("#registerWebAuthn").is_visible():
            page.click("#registerWebAuthn")
            page.wait_for_timeout(1500)
            continue
        if page.locator("#authenticateWebAuthnButton").is_visible():
            page.click("#authenticateWebAuthnButton")
            page.wait_for_timeout(1500)
            continue
        err = page.locator("#kc-error-message, .pf-m-danger, .alert-error, #input-error, .kc-feedback-text, .error")
        if err.count() and err.first.is_visible():
            raise AssertionError(f"error page at {page.url.split('?')[0]}: {err.first.inner_text()!r}")
        page.wait_for_timeout(500)
    shot(page, f"{label}-timeout")
    raise AssertionError(f"login did not reach {until} (stuck at {page.url})")


def forged_token(user: str, amr: list) -> str:
    """An unsigned JWT a client could send: header.payload.signature, the
    payload claiming `amr` for `user`."""
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return b({"alg": "HS256", "typ": "JWT"}) + "." + b({"preferred_username": user, "amr": amr}) + ".Zm9yZ2Vk"


def goto_status(page: Page, url: str) -> int:
    resp = page.goto(url, wait_until="domcontentloaded")
    return resp.status if resp else 0


def check(name: str, fn) -> None:
    try:
        fn()
        results.append((name, True, ""))
        print(f"PASS: {name}", flush=True)
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"{type(e).__name__}: {e}"))
        print(f"FAIL: {name}: {e}", flush=True)
        traceback.print_exc()


def main() -> int:
    user = os.environ["E2E_USER"]
    invite, other_invite, admin_invite = (os.environ["E2E_INVITE"], os.environ["E2E_OTHER_INVITE"],
                                          os.environ["E2E_ADMIN_INVITE"])
    cert = {"certPath": os.environ["E2E_CERT"], "keyPath": os.environ["E2E_KEY"]}
    foreign = {"certPath": os.environ["E2E_FOREIGN_CERT"], "keyPath": os.environ["E2E_FOREIGN_KEY"]}

    with sync_playwright() as pw_:
        browser = pw_.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])

        def new_context(client_cert=None, storage_state=None, trace_name="ctx"):
            certs = []
            if client_cert:
                certs = [dict(client_cert, origin=o) for o in (AUTH, APP, HWK, MTLS, ENROLL)]
            ctx = browser.new_context(client_certificates=certs, storage_state=storage_state)
            ctx.set_default_timeout(TIMEOUT_MS)
            ctx.tracing.start(screenshots=True, snapshots=True, name=trace_name)
            # A user pressing OK on any dialog (the stock label prompt): keep the default.
            ctx.on("page", lambda p: p.on("dialog", lambda d: d.accept(d.default_value)))
            return ctx

        def close(ctx, name):
            try:
                ctx.tracing.stop(path=os.path.join(ART, f"trace-{name}.zip"))
            finally:
                ctx.close()

        # ── 1. setup link: passkey registration, signed in on a webauthn app ──
        ctx = new_context(trace_name="main")
        page = ctx.new_page()
        key = Authenticator(page)
        saved: dict = {}

        def unauthenticated_redirect():
            page.goto(APP + "/", wait_until="domcontentloaded")
            page.wait_for_url(re.compile(re.escape(AUTH) + r"/realms/portcullis/"), timeout=TIMEOUT_MS)
            shot(page, "redirected")
            assert "client_id=portcullis-forward-auth" in page.url or "login-actions" in page.url, page.url
            assert page.locator("#kc-error-message").count() == 0, \
                f"Keycloak's error page instead of the sign-in: {page.inner_text('body')[:200]!r}"
            assert page.locator("#authenticateWebAuthnButton").count() == 1, "the sign-in page offers no passkey"
            assert page.locator("input[type=password]").count() == 0, "the sign-in page has a password field"
        check("unauthenticated request is redirected to a passkey-only sign-in", unauthenticated_redirect)

        def login_theme_brand():
            # The portcullis login theme's branding (keycloak/themes/portcullis):
            # its stylesheet loaded after keycloak.v2's, the mark above the
            # card, and the favicon a byte copy of the branding source's.
            assert page.locator('link[href$="/css/portcullis.css"]').count() == 1, "portcullis.css is not linked"
            bg = page.evaluate("getComputedStyle(document.querySelector('#kc-header-wrapper'), '::before')"
                               ".backgroundImage")
            assert "portcullis-mark.svg" in bg, f"#kc-header-wrapper::before background-image: {bg!r}"
            href = page.eval_on_selector("link[rel=icon]", "e => e.href")
            got = page.evaluate("""async (u) => {
                const r = await fetch(u, {credentials: "omit"});
                return {status: r.status, bytes: Array.from(new Uint8Array(await r.arrayBuffer()))};
            }""", href)
            assert got["status"] == 200, f"favicon {href}: HTTP {got['status']}"
            digest = hashlib.sha256(bytes(got["bytes"])).hexdigest()
            assert digest == FAVICON_ICO_SHA256, f"favicon {href}: sha256 {digest}"
        check("login_theme_brand", login_theme_brand)

        def setup_link_signs_in():
            page.goto(invite, wait_until="domcontentloaded")
            shot(page, "setup-link")
            assert f"<strong>{user}</strong>" in page.content(), "setup page does not name the user"
            stepups: list = []
            passkey_flow(page, until=HWK, label="setup", expect_stepups=1, stepups=stepups)
            shot(page, "hwk-after-setup")
            assert key.registered == 1, f"{key.registered} passkeys registered"
            # A setup-link session (amr inv) meets no template: hwk's
            # (security key only) asks for exactly that, one more touch of
            # the new key — which only works when Keycloak classified the
            # virtual key as a security key (the CI trust-list fixture).
            assert len(stepups) == 1 and "pc_method=security_key&" in stepups[0], f"step-ups: {stepups}"
            assert key.asserted == 1, f"{key.asserted} passkey assertions after the registration (want the one step-up)"
            assert "Hostname" in page.inner_text("body"), page.url
            saved["creds"] = key.credentials()
        check("setup link: register the key, step up with it, land on a security-key app (no password)",
              setup_link_signs_in)

        def setup_link_single_use():
            p2 = ctx.new_page()
            try:
                resp = p2.goto(invite, wait_until="domcontentloaded")
                assert resp and resp.status == 404 and "invalid, expired or already used" in p2.content(), \
                    f"used link: HTTP {resp and resp.status}"
            finally:
                p2.close()
        check("a setup link works once", setup_link_single_use)

        def session_reaches_app():
            page.goto(APP + "/", wait_until="domcontentloaded")
            shot(page, "app-after-login")
            body = page.inner_text("body")
            assert "Hostname" in body, body[:500]
            assert re.search(r"X-Forwarded-User: \S+", body), "app did not get X-Forwarded-User"
        check("the session reaches the app", session_reaches_app)

        def identity_is_username():
            # Identity = LLDAP username; the (user-editable) email travels
            # separately. Client-supplied copies of these headers are dropped,
            # and so are forged attribute headers (CI writes city=Milan for
            # the user into user-attributes.json).
            # A forged, unsigned access token claiming every method (and the
            # user's own name) must never reach group-gate or the app: every
            # forwardAuth lists the token headers, so Traefik deletes them.
            forged = forged_token(user, ["hwk", "mtls"])
            spoof = {"X-Forwarded-User": "admin", "X-Forwarded-Email": "admin@" + DOMAIN,
                     "X-Auth-Request-User": "admin", "X-Auth-Request-Email": "admin@" + DOMAIN,
                     "X-Auth-Request-Preferred-Username": "admin",
                     "X-Forwarded-Attr-City": "Forged", "X-Forwarded-Attr-Forged": "x",
                     "X-Forwarded-Access-Token": forged, "Authorization": "Bearer " + forged}
            for extra in ({}, spoof):
                page.set_extra_http_headers(extra)
                try:
                    page.goto(APP + "/", wait_until="domcontentloaded")
                    body = page.inner_text("body")
                finally:
                    page.set_extra_http_headers({})
                seen = {}
                for line in body.splitlines():
                    name, _, value = line.partition(": ")
                    seen.setdefault(name.strip().lower(), []).append(value.strip())
                for name, want in (("x-forwarded-user", user), ("x-auth-request-user", user),
                                   ("x-forwarded-email", f"{user}@{DOMAIN}"), ("x-forwarded-attr-city", "Milan")):
                    assert seen.get(name) == [want], f"{name}: {seen.get(name)} (want [{want!r}], spoofed={bool(extra)})"
                assert "admin" not in seen.get("x-auth-request-preferred-username", [user]), body[:800]
                assert "x-forwarded-attr-forged" not in seen, body[:800]
                assert forged not in body, "the forged access token reached the app"
            # mtls.<d> (YubiKey certificate only): the real session has no
            # mtls, so group-gate steps up. Had the forged token (amr mtls)
            # reached it, the page would be present-certificate instead.
            page.set_extra_http_headers({"X-Forwarded-Access-Token": forged, "Authorization": "Bearer " + forged})
            try:
                resp = page.goto(MTLS + "/", wait_until="domcontentloaded")
                shot(page, "mtls-forged-token")
                assert resp and resp.status == 403, f"mtls.<d> with a forged token: HTTP {resp and resp.status}"
                assert page.locator("#stepup-continue").count() == 1, "no step-up page for a forged token"
                assert page.locator("#present-certificate").count() == 0, "group-gate saw the forged token's amr"
                assert "pc_method=yubikey_cert" in (page.locator("#stepup-continue").get_attribute("href") or "")
            finally:
                page.set_extra_http_headers({})
        check("apps get the username (not the email) as X-Forwarded-User and the user's attribute headers; "
              "spoofed identity / attribute / access-token headers are dropped (group-gate never sees a forged token)",
              identity_is_username)

        def refresh_rotation():
            # Refresh tokens and concurrency (contract §8 "Connection length
            # and rotation", G51). oauth2-proxy refreshes the forward-auth
            # session once it is older than a minute
            # (OAUTH2_PROXY_COOKIE_REFRESH=1m, cookie sessions, no lock): the
            # session must survive two refreshes, each with two requests on
            # the same old cookie at once (concurrent fetches, then two tabs),
            # without a new sign-in. Traefik's forwardAuth doesn't pass
            # oauth2-proxy's Set-Cookie on to the browser, so the cookie keeps
            # the first refresh token and every request after the first minute
            # refreshes with it again: realm-wide rotation (revokeRefreshToken)
            # fails this at once. The workflow checks oauth2-proxy's log for
            # the refreshes (and no refresh error) after this script.
            asserted = key.asserted
            page.goto(APP + "/", wait_until="domcontentloaded")
            for rnd in (1, 2):
                assert any(c["name"].startswith("_oauth2_proxy") for c in ctx.cookies([APP + "/"])), \
                    "no forward-auth session cookie"
                page.wait_for_timeout(65_000)
                if rnd == 1:
                    got = page.evaluate("""async (u) => {
                        const rs = await Promise.all([0, 1].map(() =>
                            fetch(u, {credentials: "include", redirect: "manual", cache: "no-store"})));
                        return Promise.all(rs.map(async r => [r.status, r.type, (await r.text()).includes("Hostname")]));
                    }""", APP + "/")
                    assert got == [[200, "basic", True], [200, "basic", True]], f"concurrent refresh: {got}"
                else:
                    tabs = [ctx.new_page(), ctx.new_page()]
                    try:
                        for t in tabs:
                            t.evaluate("u => setTimeout(() => location.assign(u), 0)", APP + "/")
                        for i, t in enumerate(tabs):
                            t.wait_for_url(APP + "/", wait_until="domcontentloaded", timeout=TIMEOUT_MS)
                            shot(t, f"refresh-tab{i}")
                            assert not on_login_pages(t) and "Hostname" in t.inner_text("body"), \
                                f"tab {i} after the refresh: {t.url}"
                    finally:
                        for t in tabs:
                            t.close()
                page.goto(APP + "/", wait_until="domcontentloaded")
                shot(page, f"refresh-{rnd}")
                assert not on_login_pages(page) and "Hostname" in page.inner_text("body"), \
                    f"after refresh {rnd}: {page.url}"
            assert key.asserted == asserted, f"{key.asserted - asserted} new passkey sign-ins during the refreshes"
        check("forward-auth session survives two refreshes with concurrent requests (no new sign-in)",
              refresh_rotation)

        if os.environ.get("E2E_METRICS"):
            def metrics_needs_admin():
                # Grafana (monitoring profile) is a core subdomain: lldap_admin only.
                code = goto_status(page, f"https://metrics.{DOMAIN}/")
                shot(page, "metrics-non-admin")
                assert code == 403, f"metrics.<domain> for a non-admin: HTTP {code}"
            check("metrics.<domain> (Grafana) is denied to non-admins", metrics_needs_admin)

        def path_groups_denied():
            for path in ("/admin", "/admin/x", "/%61dmin", "//admin", "/x/../admin", "/ADMIN"):
                code = goto_status(page, APP + path)
                shot(page, "path-" + re.sub(r"\W", "_", path))
                assert code == 403, f"{path}: HTTP {code}"
            assert goto_status(page, APP + "/administrator") == 200
            assert goto_status(page, APP + "/public") == 200
        check("path_groups: /admin needs admin_e2e (bypass variants denied)", path_groups_denied)

        close(ctx, "main")

        # ── 2. second login: a fresh browser, the same key, one touch ──
        ctx = new_context(trace_name="second")
        page = ctx.new_page()

        def second_login_one_touch():
            if "creds" not in saved:
                raise AssertionError("needs the registered passkey")
            key2 = Authenticator(page, saved["creds"])
            page.goto(HWK + "/", wait_until="domcontentloaded")
            passkey_flow(page, until=HWK, label="second", expect_stepups=0)
            shot(page, "hwk-second-login")
            assert "Hostname" in page.inner_text("body"), page.url
            assert (key2.asserted, key2.registered) == (1, 0), f"assertions={key2.asserted} registrations={key2.registered}"
        check("second login: one passkey touch reaches a webauthn app", second_login_one_touch)
        close(ctx, "second")

        # ── 3. a user outside the group, and the bootstrap admin ──
        ctx = new_context(trace_name="other")
        page = ctx.new_page()
        Authenticator(page)

        def group_denied():
            page.goto(other_invite, wait_until="domcontentloaded")
            passkey_flow(page, until=APP, label="other", expect_stepups=0)
            resp = page.reload(wait_until="domcontentloaded")
            shot(page, "other-denied")
            assert resp and resp.status == 403, f"HTTP {resp and resp.status}"
            assert "not authorized" in page.content()
        check("group denial for a user not in users_e2e", group_denied)
        close(ctx, "other")

        ctx = new_context(trace_name="admin")
        page = ctx.new_page()
        admin_key = Authenticator(page)

        def admin_bootstrap():
            page.goto(admin_invite, wait_until="domcontentloaded")
            stepups: list = []
            passkey_flow(page, until=PORTAL, label="admin", expect_stepups=1, stepups=stepups)
            shot(page, "portal-admin")
            body = page.content()
            assert "Signed in as <strong>admin</strong>" in body, body[:400]
            assert f'href="https://hub.{DOMAIN}/"' in body, "portal has no Hub link for lldap_admin"
            # The portal's template (Standard) after the setup link: one
            # step-up, any passkey (`people` is ignored for a setup-link session).
            assert len(stepups) == 1 and "pc_method=passkey&" in stepups[0], f"step-ups: {stepups}"
            assert (admin_key.registered, admin_key.asserted) == (1, 1), \
                f"registrations={admin_key.registered} assertions={admin_key.asserted}"
        check("bootstrap admin: setup link → key → step-up → portal with the Hub (no password)", admin_bootstrap)
        close(ctx, "admin")

        # An unused setup link, redeemed, then steered to ANOTHER client's
        # authorize endpoint with kc_idp_hint=portcullis-invite: Keycloak's
        # broker finishes through the invite IdP's post-broker flow (not the
        # client's browser flow), which must deny every client but
        # portcullis-forward-auth — no code for the client, no passkey.
        ctx = new_context(trace_name="bypass")
        page = ctx.new_page()
        bypass_key = Authenticator(page)

        def invite_broker_other_client_denied():
            client = os.environ["E2E_BYPASS_CLIENT"]
            # Redeem the link without following its redirect to /oauth2/start
            # (the browser would finish the forward-auth login and use the
            # redemption up): the context's request API shares the cookie jar,
            # so the redemption cookie lands in the browser.
            page.goto(os.environ["E2E_BYPASS_INVITE"], wait_until="domcontentloaded")
            r = page.request.post(os.environ["E2E_BYPASS_INVITE"], max_redirects=0)
            assert r.status == 303 and r.headers.get("location", "").startswith(AUTH + "/oauth2/start"), \
                f"redeem: HTTP {r.status} {r.headers.get('location')}"
            assert any(c["name"] == "portcullis_invite" for c in ctx.cookies([ENROLL + "/invite/"])), "no redemption cookie"
            codes = []
            page.on("request", lambda r: codes.append(r.url) if r.url.startswith(APP + "/bypass-cb") else None)
            q = urllib.parse.urlencode({"client_id": client, "response_type": "code", "scope": "openid",
                                        "redirect_uri": APP + "/bypass-cb", "state": "e2e", "nonce": "e2e",
                                        "kc_idp_hint": "portcullis-invite", "prompt": "login"})
            page.goto(f"{AUTH}/realms/portcullis/protocol/openid-connect/auth?{q}", wait_until="domcontentloaded")
            deadline = time.time() + 30
            while time.time() < deadline and "Setup links work only through" not in page.content():
                if page.locator("#registerWebAuthn").is_visible():
                    raise AssertionError("the invite login reached the passkey registration for another client")
                page.wait_for_timeout(500)
            shot(page, "bypass-denied")
            assert "Setup links work only through" in page.content(), f"not denied at {page.url}"
            assert not codes, f"the client got a redirect: {codes}"
            assert bypass_key.registered == 0, "a passkey was registered"
        check("an unused setup link cannot sign in to another client (invite post-broker deny)",
              invite_broker_other_client_denied)
        close(ctx, "bypass")

        # ── 4. X.509 login through Keycloak, mtls binding, revocation ──
        ctx = new_context(client_cert=cert, trace_name="mtls")
        page = ctx.new_page()
        state = {}

        def x509_login():
            page.goto(MTLS + "/", wait_until="domcontentloaded")
            passkey_flow(page, until=MTLS, label="x509", expect_stepups=0)
            shot(page, "mtls-app")
            body = page.inner_text("body")
            assert "Hostname" in body, body[:500]
            state["storage"] = ctx.storage_state()
        check("X.509 login via Keycloak satisfies a YubiKey-certificate template", x509_login)

        def binding_without_cert():
            if "storage" not in state:
                raise AssertionError("needs the X.509 session")
            c2 = new_context(storage_state=state["storage"], trace_name="nocert")
            p2 = c2.new_page()
            try:
                resp = p2.goto(MTLS + "/", wait_until="domcontentloaded")
                shot(p2, "mtls-session-without-cert")
                assert resp and resp.status == 403, f"HTTP {resp and resp.status}"
            finally:
                close(c2, "nocert")
        check("mtls session without the cert on the request is refused", binding_without_cert)

        # The same browser has a cert and NO authenticator: a cert-only
        # session (amr=[mtls]) under the Hub's default, Standard.
        def cert_only_default_app():
            resp = page.goto(APP + "/", wait_until="domcontentloaded")
            shot(page, "cert-only-app")
            assert resp and resp.status == 200 and "Hostname" in page.inner_text("body"), \
                f"default-template app for a cert-only session: HTTP {resp and resp.status}"
        check("cert-only session opens an app with the default template (Standard)", cert_only_default_app)

        # The cert-only renewal moved with the renewal page to the Sign-in
        # page (people.<d>, the Hub: D31): e2e_signin.py's yubikey_cert_renew
        # (this job runs no Hub). enroll.<d> keeps only /invite/*.
        def cert_only_self_gone():
            for path in ("/self", "/api/self/renew"):
                r = page.request.get(ENROLL + path, max_redirects=0)
                assert r.status == 404, f"enroll.<d>{path} for a cert-only session: HTTP {r.status}"
        check("cert-only session: enroll's /self and /api/self/renew are gone (404; the renewal is on the "
              "Sign-in page)", cert_only_self_gone)

        def revoked_cert():
            subprocess.run(shlex.split(os.environ["E2E_REVOKE_CMD"]), check=True)
            resp = page.goto(MTLS + "/", wait_until="domcontentloaded")
            shot(page, "mtls-revoked")
            assert resp and resp.status == 403, f"HTTP {resp and resp.status}"
            assert "revoked" in page.content()
        check("revoked client cert is rejected", revoked_cert)
        close(ctx, "mtls")

        ctx = new_context(client_cert=foreign, trace_name="foreign")
        page = ctx.new_page()

        def foreign_cert():
            try:
                resp = page.goto(MTLS + "/", wait_until="domcontentloaded")
            except PWError as e:
                print(f"    foreign cert: navigation failed as expected ({str(e).splitlines()[0]})")
                return
            # Playwright presents client certs through its own TLS proxy and
            # reports a failed server handshake as a synthetic 503 page.
            body = page.content()
            if resp is not None and resp.status == 503 and "client-certificate error" in body \
                    and "unknown ca" in body:
                print("    foreign cert: TLS handshake refused by the server (alert unknown ca)")
                return
            shot(page, "foreign")
            raise AssertionError(f"foreign-CA cert got HTTP {resp and resp.status}")
        check("client cert from a foreign CA is rejected in the TLS handshake", foreign_cert)
        close(ctx, "foreign")
        browser.close()

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    for name, _, err in failed:
        print(f"  FAIL {name}: {err}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
