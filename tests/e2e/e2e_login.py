#!/usr/bin/env python3
"""End-to-end login test: Traefik -> oauth2-proxy -> Keycloak -> group-gate.

Runs in CI (job `e2e` in .github/workflows/ci.yml) against a full core stack
plus a whoami test app with four routers:

  app.<domain>    users_e2e group; path_groups /admin -> admin_e2e
  hwk.<domain>    policy: webauthn (step-up from a password session)
  mtls.<domain>   policy: mtls (X.509 login through Keycloak + mtls binding)

Browser: Playwright Chromium with a CDP virtual WebAuthn authenticator
(CTAP2, USB, resident keys, user verification). The CA must be trusted by
Chromium (NSS db) and by Playwright's client-certificate proxy
(NODE_EXTRA_CA_CERTS) — the workflow sets both up.

Environment (all required):
  E2E_DOMAIN          e.g. portcullis.local
  E2E_USER / E2E_PASSWORD           member of users_e2e (not admin_e2e)
  E2E_OTHER / E2E_OTHER_PASSWORD    member of nothing
  E2E_CERT / E2E_KEY                client cert for E2E_USER (Vault-issued)
  E2E_FOREIGN_CERT / E2E_FOREIGN_KEY  cert from an unrelated CA, CN=E2E_USER
  E2E_REVOKE_CMD      command (split like a shell would, no shell) that revokes E2E_CERT
  E2E_ARTIFACTS       directory for screenshots / traces (default ./e2e-artifacts)

Run: python3 tests/e2e/e2e_login.py   (not collected by pytest: needs a live stack)
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


def add_authenticator(page: Page) -> None:
    """Virtual FIDO2 security key, answering every prompt automatically."""
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable", {"enableUI": False})
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2",
        "transport": "usb",
        "hasResidentKey": True,
        "hasUserVerification": True,
        "isUserVerified": True,
        "automaticPresenceSimulation": True,
    }})


def on_keycloak(page: Page) -> bool:
    return page.url.startswith(AUTH + "/realms/")


def keycloak_login(page: Page, user: str | None, password: str | None, *, passkey: bool = False,
                   until: str, label: str) -> None:
    """Drive whatever Keycloak shows until the browser lands on `until`.

    Handles: username/password form, "Try another way" + authenticator
    selection, the passkey (WebAuthn) login button, and the passkey
    registration required action.
    """
    deadline = time.time() + 90
    clicked: set[str] = set()
    while time.time() < deadline:
        page.wait_for_load_state("domcontentloaded")
        if page.url.startswith(until) and not on_keycloak(page):
            return
        if not on_keycloak(page):
            # oauth2-proxy / group-gate step-up pages redirect on their own.
            page.wait_for_timeout(500)
            continue
        shot(page, f"{label}-kc")
        if page.locator("#registerWebAuthn").is_visible():
            page.click("#registerWebAuthn")
            page.wait_for_timeout(1500)
            continue
        if page.locator("#authenticateWebAuthnButton").is_visible():
            if passkey:
                page.click("#authenticateWebAuthnButton")
                page.wait_for_timeout(1500)
                continue
            if page.locator("#try-another-way").is_visible() and "tryanother" not in clicked:
                clicked.add("tryanother")
                page.click("#try-another-way")
                continue
        if page.locator("#kc-select-credential-form").count() and not passkey:
            page.locator("div[role=button]", has_text=re.compile("password", re.I)).first.click()
            continue
        if page.locator("#kc-select-credential-form").count() and passkey:
            page.locator("div[role=button]", has_text=re.compile("passkey|security key|webauthn", re.I)).first.click()
            continue
        if page.locator("#username").is_visible() and user is not None:
            page.fill("#username", user)
            if page.locator("#password").is_visible():
                page.fill("#password", password or "")
            page.locator("#kc-login, button[type=submit], input[type=submit]").first.click()
            continue
        if page.locator("#password").is_visible() and password is not None:
            page.fill("#password", password)
            page.locator("#kc-login, button[type=submit], input[type=submit]").first.click()
            continue
        err = page.locator(".pf-m-danger, .alert-error, #input-error, .kc-feedback-text")
        if err.count() and err.first.is_visible():
            raise AssertionError(f"Keycloak error page: {err.first.inner_text()!r}")
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
    user, pw = os.environ["E2E_USER"], os.environ["E2E_PASSWORD"]
    other, other_pw = os.environ["E2E_OTHER"], os.environ["E2E_OTHER_PASSWORD"]
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
            ctx.on("page", lambda p: p.on("dialog", lambda d: d.accept("e2e-key")))
            return ctx

        def close(ctx, name):
            try:
                ctx.tracing.stop(path=os.path.join(ART, f"trace-{name}.zip"))
            finally:
                ctx.close()

        # ── 1. password user registers a passkey, then step-up / groups / paths ──
        ctx = new_context(trace_name="main")
        page = ctx.new_page()
        add_authenticator(page)

        def unauthenticated_redirect():
            page.goto(APP + "/", wait_until="domcontentloaded")
            page.wait_for_url(re.compile(re.escape(AUTH) + r"/realms/portcullis/"), timeout=TIMEOUT_MS)
            shot(page, "redirected")
            assert "client_id=portcullis-forward-auth" in page.url or "login-actions" in page.url, page.url
        check("unauthenticated request is redirected to Keycloak", unauthenticated_redirect)

        def password_login_registers_passkey():
            keycloak_login(page, user, pw, until=APP, label="pwd-login")
            page.wait_for_load_state("domcontentloaded")
            shot(page, "app-after-login")
            body = page.inner_text("body")
            assert "Hostname" in body, body[:500]
            assert re.search(r"X-Forwarded-User: \S+", body), "app did not get X-Forwarded-User"
        check("password login (+ passkey registration) reaches the app", password_login_registers_passkey)

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

        def path_groups_denied():
            for path in ("/admin", "/admin/x", "/%61dmin", "//admin", "/x/../admin", "/ADMIN"):
                code = goto_status(page, APP + path)
                shot(page, "path-" + re.sub(r"\W", "_", path))
                assert code == 403, f"{path}: HTTP {code}"
            assert goto_status(page, APP + "/administrator") == 200
            assert goto_status(page, APP + "/public") == 200
        check("path_groups: /admin needs admin_e2e (bypass variants denied)", path_groups_denied)

        def stepup_to_webauthn():
            resp = page.goto(HWK + "/", wait_until="domcontentloaded")
            shot(page, "hwk-stepup")
            assert resp and resp.status == 403 and "Additional authentication required" in page.content(), \
                f"expected step-up page, got {resp and resp.status}"
            page.wait_for_url(re.compile(re.escape(AUTH)), timeout=TIMEOUT_MS)  # meta refresh
            keycloak_login(page, user, pw, passkey=True, until=HWK, label="hwk")
            shot(page, "hwk-after-stepup")
            assert "Hostname" in page.inner_text("body")
        check("step-up: webauthn policy after a password login", stepup_to_webauthn)
        close(ctx, "main")

        # ── 2. a user outside the group ──
        ctx = new_context(trace_name="other")
        page = ctx.new_page()

        def group_denied():
            page.goto(APP + "/", wait_until="domcontentloaded")
            keycloak_login(page, other, other_pw, until=APP, label="other")
            resp = page.reload(wait_until="domcontentloaded")
            shot(page, "other-denied")
            assert resp and resp.status == 403, f"HTTP {resp and resp.status}"
            assert "not authorized" in page.content()
        check("group denial for a user not in users_e2e", group_denied)
        close(ctx, "other")

        # ── 3. X.509 login through Keycloak, mtls binding, revocation ──
        ctx = new_context(client_cert=cert, trace_name="mtls")
        page = ctx.new_page()
        state = {}

        def x509_login():
            page.goto(MTLS + "/", wait_until="domcontentloaded")
            keycloak_login(page, None, None, until=MTLS, label="x509")
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
