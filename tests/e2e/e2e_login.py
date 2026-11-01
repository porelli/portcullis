#!/usr/bin/env python3
"""End-to-end login test: Traefik -> oauth2-proxy -> Keycloak -> group-gate.

Runs in CI (job `e2e` in .github/workflows/ci.yml) against a full core stack
plus a whoami test app with three hosts:

  app.<domain>    users_e2e group; path_groups /admin -> admin_e2e
  hwk.<domain>    policy: webauthn (the Hub's fresh-install default)
  mtls.<domain>   policy: mtls (X.509 login through Keycloak + mtls binding)

Sign-in is passkey-only. Every user starts from a one-time setup link
(`portcullis invite`): open it, register the key, land on the app — the test
fails on ANY password field. Then: the session reaches the apps, a second
login in a fresh browser is one passkey touch, the link is single use, a user
outside the group is denied, the bootstrap admin's link lands on the portal
with the Hub link, X.509 login / mtls binding / revocation / foreign CA.

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
  E2E_CERT / E2E_KEY                client cert for E2E_USER (Vault-issued)
  E2E_FOREIGN_CERT / E2E_FOREIGN_KEY  cert from an unrelated CA, CN=E2E_USER
  E2E_REVOKE_CMD      command (split like a shell would, no shell) that revokes E2E_CERT
  E2E_ARTIFACTS       directory for screenshots / traces (default ./e2e-artifacts)

Run: python3 tests/e2e/e2e_login.py   (not collected by pytest: needs a live stack)
Against a live server without certs: tests/e2e/e2e_invite.py.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import time
import traceback

from playwright.sync_api import Error as PWError
from playwright.sync_api import Page, sync_playwright

DOMAIN = os.environ["E2E_DOMAIN"]
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
TIMEOUT_MS = 30_000
AUTH = f"https://auth.{DOMAIN}"
APP = f"https://app.{DOMAIN}"
HWK = f"https://hwk.{DOMAIN}"
MTLS = f"https://mtls.{DOMAIN}"
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


def passkey_flow(page: Page, *, until: str, label: str) -> None:
    """Drive the setup-link page and Keycloak until the browser lands on
    `until`. Handles: "Register my key" (setup link), the passkey
    registration required action, "Sign in with Passkey". Fails at once on a
    password field or a Keycloak error: there are no passwords any more."""
    deadline = time.time() + 90
    while time.time() < deadline:
        page.wait_for_load_state("domcontentloaded")
        if page.url.startswith(until) and not on_login_pages(page):
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
        err = page.locator(".pf-m-danger, .alert-error, #input-error, .kc-feedback-text, .error")
        if err.count() and err.first.is_visible():
            raise AssertionError(f"error page: {err.first.inner_text()!r}")
        page.wait_for_timeout(500)
    shot(page, f"{label}-timeout")
    raise AssertionError(f"login did not reach {until} (stuck at {page.url})")


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
                certs = [dict(client_cert, origin=o) for o in (AUTH, APP, HWK, MTLS)]
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
            assert page.locator("input[type=password]").count() == 0, "the sign-in page has a password field"
        check("unauthenticated request is redirected to a passkey-only sign-in", unauthenticated_redirect)

        def setup_link_signs_in():
            page.goto(invite, wait_until="domcontentloaded")
            shot(page, "setup-link")
            assert f"<strong>{user}</strong>" in page.content(), "setup page does not name the user"
            passkey_flow(page, until=HWK, label="setup")
            shot(page, "hwk-after-setup")
            assert key.registered == 1, f"{key.registered} passkeys registered"
            assert key.asserted == 0, "a passkey login was needed right after the registration"
            assert "Hostname" in page.inner_text("body"), page.url
            saved["creds"] = key.credentials()
        check("setup link: register the key and land on a webauthn app (no password, no second prompt)",
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
            # separately. Client-supplied copies of these headers are dropped.
            spoof = {"X-Forwarded-User": "admin", "X-Forwarded-Email": "admin@" + DOMAIN,
                     "X-Auth-Request-User": "admin", "X-Auth-Request-Email": "admin@" + DOMAIN,
                     "X-Auth-Request-Preferred-Username": "admin"}
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
                                   ("x-forwarded-email", f"{user}@{DOMAIN}")):
                    assert seen.get(name) == [want], f"{name}: {seen.get(name)} (want [{want!r}], spoofed={bool(extra)})"
                assert "admin" not in seen.get("x-auth-request-preferred-username", [user]), body[:800]
        check("apps get the username (not the email) as X-Forwarded-User; spoofed identity headers are dropped",
              identity_is_username)

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
            passkey_flow(page, until=HWK, label="second")
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
            passkey_flow(page, until=APP, label="other")
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
            passkey_flow(page, until=PORTAL, label="admin")
            shot(page, "portal-admin")
            body = page.content()
            assert "Signed in as <strong>admin</strong>" in body, body[:400]
            assert f'href="https://hub.{DOMAIN}/"' in body, "portal has no Hub link for lldap_admin"
            assert admin_key.registered == 1 and admin_key.asserted == 0
        check("bootstrap admin: setup link → key → portal with the Hub (no password)", admin_bootstrap)
        close(ctx, "admin")

        # ── 4. X.509 login through Keycloak, mtls binding, revocation ──
        ctx = new_context(client_cert=cert, trace_name="mtls")
        page = ctx.new_page()
        state = {}

        def x509_login():
            page.goto(MTLS + "/", wait_until="domcontentloaded")
            passkey_flow(page, until=MTLS, label="x509")
            shot(page, "mtls-app")
            body = page.inner_text("body")
            assert "Hostname" in body, body[:500]
            state["storage"] = ctx.storage_state()
        check("X.509 login via Keycloak satisfies an mtls policy", x509_login)

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
