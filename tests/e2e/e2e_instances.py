#!/usr/bin/env python3
"""End-to-end: app instances on the main and an enrolled extra domain.

Runs in CI (job `e2e-instances` in .github/workflows/ci.yml) against the
whole core stack, the Hub, the domains service (Pebble + fake DNS) with the
enrolled domain E2E_EXTRA, and three instances of the CI template
tests/e2e/apps/echo (traefik/whoami behind Portcullis sign-in) that the
workflow created through the Hub's API:

  echo-a.<extra>   users_echo-a (alice); default policy; extra domain
  echo-b.<domain>  users_echo-b (bob);   default policy; main domain;
                   its hold service makes a backup take > 60 s
  echo-c.<extra>   users_echo-c (alice); policy mtls (step-up from a
                   passkey session); extra domain

Scenarios (contract §5, §11):
  cross_domain_sso  alice signs in on the main domain (setup link, passkey);
                    echo-a on the extra domain opens with NO further
                    WebAuthn assertion through forward-auth-ext (host-only
                    __Host-portcullis_ext cookie, relative callback on the
                    host, PKCE S256); echo-c (policy mtls) steps up exactly
                    once and lands on the app; a stale ext cookie signs in
                    again without a redirect loop.
  two_instances     two instances, two groups: alice reaches echo-a only,
                    bob echo-b only (group-gate v5 keyed by hostname).
  long_backup       an admin's backup of echo-b through Traefik
                    (hub.<domain>, default timeouts) that takes longer than
                    60 s: accepted with 202, a concurrent one is 409 busy,
                    the op record ends ok with the archive.

Environment: E2E_DOMAIN, E2E_EXTRA, E2E_ALICE_INVITE, E2E_BOB_INVITE,
E2E_ADMIN_INVITE (setup links, --to portal), E2E_CERT / E2E_KEY (alice's
Vault client certificate), E2E_ARTIFACTS. Chromium must trust core's CA and
Pebble's root (NSS db), Node too (NODE_EXTRA_CA_CERTS) — the workflow sets
both up.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import traceback
import urllib.parse

from playwright.sync_api import Error as PWError
from playwright.sync_api import Page, sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_login as base  # noqa: E402  (Authenticator, passkey_flow, shot)

DOMAIN = os.environ["E2E_DOMAIN"]
EXTRA = os.environ["E2E_EXTRA"]
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
TIMEOUT_MS = 30_000
AUTH = f"https://auth.{DOMAIN}"
PORTAL = f"https://{DOMAIN}/"
HUB = f"https://hub.{DOMAIN}"
ECHO_A = f"https://echo-a.{EXTRA}"
ECHO_B = f"https://echo-b.{DOMAIN}"
ECHO_C = f"https://echo-c.{EXTRA}"
EXT_COOKIE = "__Host-portcullis_ext"

results: list[tuple[str, bool, str]] = []


def check(name: str, fn) -> None:
    try:
        fn()
        results.append((name, True, ""))
        print(f"PASS: {name}", flush=True)
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"{type(e).__name__}: {e}"))
        print(f"FAIL: {name}: {e}", flush=True)
        traceback.print_exc()


def headers_of(body: str) -> dict:
    seen: dict = {}
    for line in body.splitlines():
        name, _, value = line.partition(": ")
        seen.setdefault(name.strip().lower(), []).append(value.strip())
    return seen


def settle(page: Page, url: str, *, seconds: int = 45) -> int:
    """Open url and follow the sign-in redirects until the browser rests on
    url's host (not on a login page); returns the final HTTP status."""
    resp = page.goto(url, wait_until="domcontentloaded")
    deadline = time.time() + seconds
    while time.time() < deadline:
        page.wait_for_load_state("domcontentloaded")
        if page.url.startswith(url) and not base.on_login_pages(page):
            resp = page.reload(wait_until="domcontentloaded")
            return resp.status if resp else 0
        page.wait_for_timeout(500)
    raise AssertionError(f"{url}: never settled (at {page.url})")


class Traffic:
    """Requests a page makes, for redirect-loop and sign-in checks."""

    def __init__(self, page: Page):
        self.urls: list[str] = []
        page.on("request", lambda r: self.urls.append(r.url) if r.is_navigation_request() else None)

    def reset(self) -> None:
        self.urls.clear()

    def matching(self, rx: str) -> list[str]:
        return [u for u in self.urls if re.search(rx, u)]


def main() -> int:
    cert = {"certPath": os.environ["E2E_CERT"], "keyPath": os.environ["E2E_KEY"]}
    with sync_playwright() as pw_:
        browser = pw_.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])

        def new_context(trace_name: str, client_cert=None, origins=(), storage_state=None):
            certs = [dict(client_cert, origin=o) for o in origins] if client_cert else []
            ctx = browser.new_context(client_certificates=certs, storage_state=storage_state)
            ctx.set_default_timeout(TIMEOUT_MS)
            ctx.tracing.start(screenshots=True, snapshots=True, name=trace_name)
            ctx.on("page", lambda p: p.on("dialog", lambda d: d.accept(d.default_value)))
            return ctx

        def close(ctx, name):
            try:
                ctx.tracing.stop(path=os.path.join(ART, f"trace-inst-{name}.zip"))
            finally:
                ctx.close()

        # ── alice: main-domain sign-in, then the extra domain ──
        ctx = new_context("alice")
        page = ctx.new_page()
        key = base.Authenticator(page)
        traffic = Traffic(page)
        state: dict = {}

        def alice_signs_in():
            page.goto(os.environ["E2E_ALICE_INVITE"], wait_until="domcontentloaded")
            base.passkey_flow(page, until=PORTAL, label="inst-alice")
            base.shot(page, "inst-alice-portal")
            assert "Signed in as <strong>alice</strong>" in page.content(), page.content()[:400]
            assert key.registered == 1, f"{key.registered} passkeys registered"
            # The portal lists the instance on the extra domain (contract §10).
            assert ECHO_A in page.content(), "portal does not list echo-a on the extra domain"
        check("alice: setup link → passkey → portal (main domain), echo-a listed", alice_signs_in)

        def cross_domain_sso():
            before = (key.asserted, key.registered)
            traffic.reset()
            code = settle(page, ECHO_A + "/")
            base.shot(page, "inst-echo-a")
            body = page.inner_text("body")
            assert code == 200 and "Hostname" in body, f"echo-a: HTTP {code}: {body[:300]}"
            assert headers_of(body).get("x-forwarded-user") == ["alice"], body[:600]
            assert (key.asserted, key.registered) == before, \
                f"WebAuthn prompts on the extra domain: assertions {before[0]}→{key.asserted}"
            # Sign-in went through forward-auth-ext on the host itself:
            # Keycloak with the host's callback + PKCE, one callback on the
            # host, nothing through auth.<main domain>'s oauth2-proxy.
            cbs = traffic.matching(r"^" + re.escape(ECHO_A) + r"/oauth2/callback\?")
            assert len(cbs) == 1, f"callbacks on echo-a: {cbs}"
            assert not traffic.matching(re.escape(AUTH) + r"/oauth2/"), "sign-in went through auth.<main domain>"
            authz = traffic.matching(re.escape(AUTH) + r"/realms/portcullis/protocol/openid-connect/auth\?")
            assert authz, f"no Keycloak authorize request: {traffic.urls}"
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(authz[0]).query)
            assert q.get("client_id") == ["portcullis-forward-auth"], q
            assert q.get("redirect_uri") == [ECHO_A + "/oauth2/callback"], q.get("redirect_uri")
            assert q.get("code_challenge_method") == ["S256"] and q.get("code_challenge"), "no PKCE S256"
            # The session cookie: host-only __Host- cookie on echo-a only.
            cookies = ctx.cookies([ECHO_A])
            ext = [c for c in cookies if c["name"].startswith(EXT_COOKIE)]
            assert ext, f"no {EXT_COOKIE} cookie: {[c['name'] for c in cookies]}"
            for c in ext:
                assert c["domain"] == f"echo-a.{EXTRA}" and c["path"] == "/" and c["secure"], c
            assert not [c for c in ctx.cookies() if c["domain"].lstrip(".") == EXTRA], "a cookie for the whole extra domain"
            assert not [c for c in cookies if c["name"] == "_oauth2_proxy"], "main-domain cookie sent to the extra domain"
            # The setup link's session (post-broker flow portcullis-invite-session:
            # LoA 1 and 2 recorded): the mtls step-up below starts from it.
            state["storage"] = ctx.storage_state()
        check("cross_domain_sso: echo-a on the extra domain opens with no extra WebAuthn assertion "
              "(forward-auth-ext, host-only __Host-portcullis_ext, host callback, PKCE S256)", cross_domain_sso)

        def stale_cookie_no_loop():
            ctx.add_cookies([{"name": EXT_COOKIE, "value": "stale|1700000000|AAAA", "url": ECHO_A + "/",
                              "secure": True, "sameSite": "Lax"}])
            before = key.asserted
            traffic.reset()
            code = settle(page, ECHO_A + "/", seconds=30)
            base.shot(page, "inst-echo-a-stale")
            assert code == 200 and "Hostname" in page.inner_text("body"), f"HTTP {code}"
            rounds = traffic.matching(r"/oauth2/callback\?")
            assert len(rounds) <= 1, f"redirect loop: {len(rounds)} sign-in rounds: {rounds}"
            assert key.asserted == before, "a stale cookie cost a WebAuthn assertion"
            fresh = [c for c in ctx.cookies([ECHO_A]) if c["name"].startswith(EXT_COOKIE)]
            assert fresh and all(c["value"] != "stale|1700000000|AAAA" for c in fresh), "stale cookie kept"
        check("cross_domain_sso: a stale ext cookie signs in again without a loop", stale_cookie_no_loop)

        def alice_not_on_echo_b():
            code = settle(page, ECHO_B + "/")
            base.shot(page, "inst-alice-echo-b")
            assert code == 403, f"alice on echo-b: HTTP {code}"
        check("two_instances: alice (users_echo-a) is refused on echo-b", alice_not_on_echo_b)
        close(ctx, "alice")

        # ── alice with her client certificate: step-up on echo-c (mtls) ──
        def stepup_once():
            if "storage" not in state:
                raise AssertionError("needs alice's session")
            storage = state["storage"]
            c2 = new_context("alice-stepup", client_cert=cert, origins=(AUTH, ECHO_C), storage_state=storage)
            p2 = c2.new_page()
            key2 = base.Authenticator(p2)
            t2 = Traffic(p2)
            try:
                p2.goto(ECHO_C + "/", wait_until="domcontentloaded")
                stepups, deadline = 0, time.time() + 60
                while time.time() < deadline:
                    p2.wait_for_load_state("domcontentloaded")
                    if p2.locator("#stepup-continue").count():
                        stepups += 1
                        base.shot(p2, "inst-echo-c-stepup")
                        if stepups > 1:
                            break
                        p2.click("#stepup-continue")
                        p2.wait_for_timeout(1000)
                        continue
                    if p2.url.startswith(ECHO_C) and "Hostname" in p2.content():
                        break
                    if base.on_login_pages(p2) and p2.locator("#authenticateWebAuthnButton").is_visible():
                        base.shot(p2, "inst-echo-c-keycloak-asks-passkey")
                        raise AssertionError(f"the mtls step-up asked for a passkey (no certificate at Keycloak?) at {p2.url}")
                    p2.wait_for_timeout(500)
                base.shot(p2, "inst-echo-c")
                assert stepups == 1, f"{stepups} step-up pages (want exactly one)"
                assert p2.url.startswith(ECHO_C) and "Hostname" in p2.inner_text("body"), f"stuck at {p2.url}"
                assert key2.asserted == 0 and key2.registered == 0, "the mtls step-up asked for a passkey"
                ext_starts = t2.matching(r"^" + re.escape(ECHO_C) + r"/oauth2/start\?.*acr_values=mtls")
                assert ext_starts, f"step-up did not use the host's /oauth2/start: {t2.urls}"
                assert not t2.matching(re.escape(AUTH) + r"/oauth2/start"), "step-up went through auth.<domain>"
                assert headers_of(p2.inner_text("body")).get("x-forwarded-user") == ["alice"]
            finally:
                close(c2, "alice-stepup")
        check("cross_domain_sso: echo-c (policy mtls) on the extra domain steps up exactly once", stepup_once)

        # ── bob: his instance only ──
        ctx = new_context("bob")
        page = ctx.new_page()
        bkey = base.Authenticator(page)

        def bob_only_echo_b():
            page.goto(os.environ["E2E_BOB_INVITE"], wait_until="domcontentloaded")
            base.passkey_flow(page, until=PORTAL, label="inst-bob")
            code = settle(page, ECHO_B + "/")
            base.shot(page, "inst-bob-echo-b")
            assert code == 200 and headers_of(page.inner_text("body")).get("x-forwarded-user") == ["bob"], f"HTTP {code}"
            before = bkey.asserted
            code = settle(page, ECHO_A + "/")
            base.shot(page, "inst-bob-echo-a")
            assert code == 403, f"bob on echo-a: HTTP {code}"
            assert bkey.asserted == before, "bob needed a WebAuthn assertion on the extra domain"
        check("two_instances: bob (users_echo-b) reaches echo-b and is refused on echo-a", bob_only_echo_b)
        close(ctx, "bob")

        # ── admin: a backup longer than 60 s through Traefik ──
        ctx = new_context("admin")
        page = ctx.new_page()
        base.Authenticator(page)

        def long_backup_through_traefik():
            page.goto(os.environ["E2E_ADMIN_INVITE"], wait_until="domcontentloaded")
            base.passkey_flow(page, until=PORTAL, label="inst-admin")
            assert goto_ok(page, HUB + "/"), "admin cannot open the Hub"
            # The Hub accepts at once (202) and runs the backup in the
            # background; no request stays open (Traefik's default timeouts).
            t0 = time.time()
            r = page.request.post(HUB + "/api/instances/echo-b/backups", data="{}",
                                  headers={"Content-Type": "application/json"})
            assert r.status == 202, f"HTTP {r.status}: {r.text()[:300]}"
            acc = r.json()
            assert acc.get("op") == "backup" and acc.get("op_id") and acc.get("poll") == f"/api/instances/echo-b/op?op_id={acc['op_id']}", acc
            assert time.time() - t0 < 30, "the backup request was not answered at once"
            # A second operation on the instance meanwhile: busy.
            r2 = page.request.post(HUB + "/api/instances/echo-b/backups", data="{}",
                                   headers={"Content-Type": "application/json"})
            assert r2.status == 409, f"concurrent backup: HTTP {r2.status}"
            rec, deadline = {}, time.time() + 600
            while time.time() < deadline:
                p = page.request.get(HUB + acc["poll"])
                assert p.status == 200, f"poll: HTTP {p.status}"
                rec = p.json()
                assert rec.get("op_id") == acc["op_id"], f"poll by op_id answered another op: {json.dumps(rec)[:300]}"
                if not rec.get("running"):
                    break
                time.sleep(3)
            took = time.time() - t0
            print(f"    backup of echo-b through Traefik: {took:.0f} s, record {json.dumps(rec)[:300]}", flush=True)
            assert rec.get("ok") and rec.get("op") == "backup", rec
            archive = (rec.get("result") or {}).get("archive", "")
            assert archive.startswith("echo-b/"), rec
            assert took > 60, f"the backup took {took:.0f} s: not longer than Traefik's 60 s readTimeout (test is vacuous)"
            listed = page.request.get(HUB + "/api/instances/echo-b/backups")
            assert listed.status == 200 and any(b.get("archive") == archive for b in listed.json()), listed.text()[:300]
        check("long_backup: an admin's > 60 s backup through Traefik (202, polled) completes; a concurrent one is 409", long_backup_through_traefik)
        close(ctx, "admin")
        browser.close()

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    for name, _, err in failed:
        print(f"  FAIL {name}: {err}")
    return 1 if failed else 0


def goto_ok(page: Page, url: str) -> bool:
    try:
        resp = page.goto(url, wait_until="domcontentloaded")
    except PWError:
        return False
    return bool(resp and resp.status == 200)


if __name__ == "__main__":
    sys.exit(main())
