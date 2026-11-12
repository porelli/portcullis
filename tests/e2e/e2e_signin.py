#!/usr/bin/env python3
"""End-to-end: sign-in methods on a real stack (contract §5, §8, §8.1).

Runs in CI (job `e2e-signin` in .github/workflows/ci.yml) against the whole
core stack and the Hub (same-named Hub branch; HUB_DEV=1 with the CI trust
list fixture, mounted from a host directory this script rewrites), with one
local template source: the CI templates tests/e2e/apps/echo (forward-auth)
and tests/e2e/apps/oidc-echo (native OIDC). The workflow created, through
the Hub's API:

  echo-std.<d>     echo, the default template (Standard)
  echo-basic.<d>   echo, Basic (enabled for this job)            pat
  echo-cert.<d>    echo, e2e-cert = any[yubikey_cert]            alice
  oidc-strong.<d>  oidc-echo (client oidc-strong), Strong
  oidc-all.<d>     oidc-echo (client oidc-all), YubiKey + certificate
  oidc-cert.<d>    oidc-echo (client oidc-cert), e2e-cert (a switch to another
                   person's certificate would meet it)

and the people root, sam (both lldap_admin), alice, bob (a certificate
only), pat (a Hub-set password only), rita, plus LLDAP's admin. Certificates
from Vault: root's and bob's. Setup links come from `./portcullis invite`
here (never printed).

Virtual authenticators (CDP, CTAP2 USB, resident keys, UV): backup
eligibility 0 = Chromium's packed attestation the fixture lists → a
security key; backup eligibility 1 = synced (contract §8.1 "Passkey
kinds"). Every navigator.credentials.get call's allowCredentials is
recorded (an init script), so "only that kind's credentials" is checked on
what the browser was asked, not on Chromium's silent allowCredentials probe.

Cases (in this order; each later case needs only the state it names):
  password_off_not_offered  cold sign-in: passkey only, no "Try another way",
                            no password field, also with pc_method=password
  reclassify (part 1)       fixture without the key → rita's setup-link key
                            registers as webauthn-passwordless (passkey_synced);
                            pc_fresh absent for her setup-link session
                            (portcullis-fresh-auth, SSO reused); fixture back
  security_key_on_strong    root: setup link → pc_method=security_key step-up
                            → hub.<d> (Strong); type portcullis-security-key
  synced_passkey_refused_on_strong  sam (synced key) gets #needs-stronger on hub.<d>
  native_oidc_template_enforced     sam on oidc-strong: Keycloak's
                            portcullis-needs-stronger.ftl in the portcullis
                            theme, no code (screenshot artifact)
  pc_method_kind            sam's spare security key: the step-up asks
                            security_key and the browser is asked for the
                            security key only (the synced one never)
  pc_method_reaches_keycloak / amr_accumulates  sam's synced session on
                            hub.<d>: step-up pc_method=security_key, Keycloak
                            shows the passkey prompt only, the token's amr then
                            has spk and hwk
  cross_user_certificate    alice's passkey session presenting bob's
                            certificate: on echo-cert's yubikey_cert step-up and
                            on oidc-cert (template step: needs-stronger; a
                            pc_method=yubikey_cert step: refused by Keycloak's
                            X.509 user check or the extension's USER_CONFLICT):
                            never bob, no code
  all_met_step_by_step      root with his certificate on oidc-all
                            (all[yubikey_cert, security_key]): Keycloak asks
                            the security key itself, then issues (amr mtls+hwk)
  pc_fresh_present          root's fresh passkey sign-in: pc_fresh =
                            security_key; an SSO reuse right after: none
  fresh_follows_hub_template  sam's admin confirmation (delete_group through
                            the Hub's MCP listener, the gate secret): the hub
                            core template (Strong) governs it — his synced
                            passkey's fresh sign-in is refused (403), his
                            security key's approves; audited "template strong"
  password_on_basic_app     password on: pat signs in with his password on
                            echo-basic; people.<d> (Strong) → #needs-stronger
  admin_password_refused    admin + LLDAP's admin password, 11 times (above
                            failureFactor 10): refused, not counted by brute
                            force, admin's passkey still signs in
  password_off_not_offered  again after switching it off
  reclassify (part 2)       rita's credential becomes portcullis-security-key;
                            the PasskeyReclassified log line is at most 360 s
                            after the fixture's return
  part 2 (browser_cert on since the job's setup; echo-file on e2e-file =
  any[browser_cert], echo-anycert on e2e-anycert = any[yubikey_cert,
  browser_cert], both protected-any@file; carol, hr = sign_in_help):
  browser_cert_create_download  alice's fresh security-key sign-in → POST
                            people.<d>/api/me/signin/browser-certificates: 200
                            no-store, the .p12 (EC key, CN alice, browser CA,
                            ~30 d, chain browser CA + root), no secret audited
  browser_cert_fresh_refused_weak  sam's synced fresh sign-in → 403
  browser_cert_max_active   two more succeed, the fourth 409
  tls_protected_yubikey_ca_only / tls_mtls_refuses_browser_cert /
  tls_protected_any         CA names (YubiKey CA only on protected; root +
                            both on protected-any) and handshakes (curl with
                            the leaf + the .p12's whole chain, the .p12 in
                            Playwright)
  browser_cert_signin_file  the .p12 alone signs alice in: amr file, no mtls
  browser_cert_not_yubikey  that session on oidc-cert: needs-stronger, a
                            pc_method=yubikey_cert step no code
  browser_cert_cannot_renew the renewal with the browser certificate: 403
  yubikey_cert_still_mtls / yubikey_cert_renew  alice's Vault pki_int
                            certificate signs in (mtls) and renews on the
                            Sign-in page (moved from e2e_login)
  forged_cert_headers       client-sent X-Forwarded-Tls-Client-Cert(-Info)
                            deleted by Traefik (group-gate, the renewal)
  browser_cert_revoked      DELETE → 403 within 70 s, shown revoked
  signin_page_reachable_weak  pat (password only): /signin, /api/me/signin
                            200; /api/directory and raw ../ paths refused
  sign_in_help_actions      carol: setup link, passkeys, revoke; 403 / 409s
  browser_cert_none_left    people no longer lists browser_cert for alice
  history_entries           sign_in [browser_cert], step_up, opened, help,
                            certificate; pat's failed
  enroll_site_gone          enroll.<d> serves /invite/* only
  part 3, signing in as someone else (the job's .env sets
  IMPERSONATION_MAX_MINUTES=2; AI switched on for the CI AI client; each
  start: root's YubiKey-certificate session, then in a copy of that browser
  his fresh security-key sign-in and the start route on the Hub listener):
  imp_stock_endpoint_off    Keycloak's own impersonation endpoint non-2xx
  imp_setup                 AI on; alice's People MCP token before any start
  imp_start                 next → portal as alice: act root, pc_imp, amr =
                            root's + hwk; root no session, alice one
  imp_banner_everywhere     portal, people.<d>/ and /signin, group-gate's
                            needs page (echo-file), the extension's page
  imp_call5                 echo-cert with root's certificate (impersonation
                            headers; forged copies deleted), alice's own
                            certificate → needs page, no step-up; oidc-strong
                            with act / pc_act
  imp_people_read_only      PUT / POST / DELETE → 403, GET 200
  imp_ai_refused            the AI client's authorize → #impersonating, no
                            code; alice's pre-start token still works
  imp_refused_concurrent    second start / person taken → 409; next reused → 403
  imp_stop                  Stop page → sign_out; session gone, cookie dead,
                            refresh invalid_grant; audit and history
  imp_notice_next_signin    alice's next sign-in: the notice once
  imp_stop_elsewhere        sam's stop_impersonation → ended page within 5 s
  imp_refused_proofs        synced, no touch, bob's, browser certificate →
                            403; reason "ab" → 400
  imp_refused_targets       root, sam, portcullis-hub, admin → 409; carol
                            403; the switch off ends one and refuses starts
  imp_next_bound            next in bob's browser → 403, his session intact
  imp_expiry (+ late next)  last, in parallel: expiry after 2 min 10 s; sam's
                            start opened after 125 s → 403
  cert_and_password_kinds_identified  LOGIN pc_methods yubikey_cert /
                            browser_cert (alice), password (pat); /api/me/signin rows
  passkey_kinds_identified  (the job drifted the realm's passwordless policy
                            and `keycloak configure` restored it) a security
                            key (rita, invite --replace-keys), synced (bob),
                            device-bound (pat; fixture kind passkey_device):
                            type, log kind + AAGUID, /api/me/signin row, amr,
                            LOGIN pc_methods
  tls_follows_switch        echo-std / echo-basic / auth.<d> CA names;
                            Standard = any[family:passkey], hub / people →
                            standard, Strong (and the certificate templates)
                            disabled, yubikey_cert off → public@file, no CA
                            names; auth.<d> keeps them; everything restored

Environment: E2E_DOMAIN, HUB_IP, E2E_HUB_SECRET, KEYCLOAK_ADMIN,
KEYCLOAK_ADMIN_PASSWORD, LLDAP_ADMIN_PASSWORD, E2E_ROOT_CERT / _KEY,
E2E_BOB_CERT / _KEY, E2E_PAT_PASSWORD_FILE, E2E_FIXTURE (the host file the
Hub's HUB_SIGNIN_EXTRA_AUTHENTICATORS is), E2E_MCPCLIENT (tests/e2e/mcpclient,
built), ALPINE, E2E_ARTIFACTS. Secrets
come only from the environment or files and are never printed; no
Playwright traces (a DOM snapshot would carry a typed password).
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from playwright.sync_api import Error as PWError
from playwright.sync_api import Page, sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_login as base  # noqa: E402  (passkey_flow, shot, on_login_pages)

DOMAIN = os.environ["E2E_DOMAIN"]
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
SCREENS = os.path.join(ART, "signin-screens")
ALPINE = os.environ["ALPINE"]
TIMEOUT_MS = 30_000
AUTH = f"https://auth.{DOMAIN}"
PORTAL = f"https://{DOMAIN}/"
HUB = f"https://hub.{DOMAIN}"
PEOPLE = f"https://people.{DOMAIN}"
ECHO_STD = f"https://echo-std.{DOMAIN}"
ECHO_BASIC = f"https://echo-basic.{DOMAIN}"
ECHO_CERT = f"https://echo-cert.{DOMAIN}"
ECHO_FILE = f"https://echo-file.{DOMAIN}"
ECHO_ANYCERT = f"https://echo-anycert.{DOMAIN}"
ENROLL_HOST = f"enroll.{DOMAIN}"
OIDC_STRONG = f"https://oidc-strong.{DOMAIN}"
OIDC_ALL = f"https://oidc-all.{DOMAIN}"
OIDC_CERT = f"https://oidc-cert.{DOMAIN}"
REALM = f"{AUTH}/realms/portcullis"
HUB_API = f"http://{os.environ['HUB_IP']}:8888"
PEOPLE_API = f"http://{os.environ['HUB_IP']}:8889"  # the Hub's people listener
CA_CHAIN = "certs/ca-chain.crt"
KC_ADMIN = "http://127.0.0.1:8080"
AAGUID = "01020304-0506-0708-0102-030405060708"  # Chromium's virtual CTAP2 key
FIXTURE = os.environ["E2E_FIXTURE"]
RECLASSIFY_S = 360  # the extension's reclassify task runs every 5 min (D5), plus slack

os.makedirs(SCREENS, exist_ok=True)
results: list[tuple[str, bool, str]] = []
state: dict = {}

# Records every navigator.credentials.get's allowCredentials (standard
# base64 ids) through the context's __pcAllow binding.
ALLOW_RECORDER = """(() => {
  const c = navigator.credentials;
  if (!c || !c.get) return;
  const orig = c.get.bind(c);
  c.get = (o) => {
    try {
      const list = (o && o.publicKey && o.publicKey.allowCredentials) || [];
      window.__pcAllow(list.map((x) => {
        const v = x.id;
        const u = v instanceof ArrayBuffer ? new Uint8Array(v) : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
        let s = "";
        for (const b of u) s += String.fromCharCode(b);
        return btoa(s);
      }));
    } catch (e) {
      window.__pcAllow(["error:" + e]);
    }
    return orig(o);
  };
})();"""


SETUP_LINK = re.compile(r"(https://enroll\.[^/\s'\"]+/invite/)[A-Za-z0-9_-]+")


def redact(text: str) -> str:
    """Setup links out of failure messages (also masked in the log)."""
    return SETUP_LINK.sub(r"\1<redacted>", text)


def check(name: str, fn) -> None:
    try:
        fn()
        results.append((name, True, ""))
        print(f"PASS: {name}", flush=True)
    except Exception as e:  # noqa: BLE001
        results.append((name, False, redact(f"{type(e).__name__}: {e}")))
        print(redact(f"FAIL: {name}: {e}"), flush=True)
        print(redact(traceback.format_exc()), flush=True)


def needs(*keys: str) -> None:
    """A case that builds on an earlier one fails when that one did."""
    missing = [k for k in keys if k not in state]
    assert not missing, f"needs {', '.join(missing)} (an earlier case failed)"


def until(what: str, fn, seconds: float, every: float = 3):
    deadline, last = time.time() + seconds, None
    while True:
        try:
            got = fn()
            if got:
                return got
            last = got
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
        if time.time() > deadline:
            raise AssertionError(f"{what}: not within {seconds:.0f} s (last: {str(last)[:600]})")
        time.sleep(every)


def raw_id(b64: str) -> bytes:
    """A credential id in standard or URL-safe base64, padded or not."""
    s = b64.replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def claims_of(jwt: str) -> dict:
    p = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


# ── the Hub's admin API (as Traefik calls it), its files, Keycloak's admin API ──

def hub(method: str, path: str, body=None, timeout: float = 300):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(HUB_API + path, data=data, method=method, headers={
        "X-Portcullis-Proxy-Secret": os.environ["E2E_HUB_SECRET"], "X-Forwarded-User": "admin",
        "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code, raw = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read().decode()
    try:
        return code, json.loads(raw) if raw else ""
    except ValueError:
        return code, raw


def hub_ok(method: str, path: str, body=None):
    code, out = hub(method, path, body)
    assert code in (200, 201), f"{method} {path}: HTTP {code} {str(out)[:400]}"
    return out


def hub_file(name: str) -> str:
    return subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", "portcullis_hub_data:/d:ro", ALPINE,
                           "cat", f"/d/{name}"], check=True, capture_output=True, text=True).stdout


def hub_json(name: str) -> dict:
    return json.loads(hub_file(name))


_kicks = [0]


def kick() -> None:
    """A directory change through the Hub (a throwaway group): its directory
    sync writes the policy and signin-keycloak.json (re-reading the extra
    authenticators file) and refreshes the sign-in inventory."""
    _kicks[0] += 1
    hub_ok("POST", "/api/directory/groups", {"name": f"ci-kick-{_kicks[0]}"})


def wait_people(user: str, methods: list) -> None:
    """The policy file's `people` (the Hub's inventory, group-gate's page
    wording) lists exactly `methods` for user; kicked again every 35 s (the
    inventory refreshes at most once per 30 s)."""
    want = sorted(methods)
    last_kick = [0.0]

    def ok():
        if time.time() - last_kick[0] > 35:
            kick()
            last_kick[0] = time.time()
        return hub_json("group-gate-policy.json").get("people", {}).get(user) == want
    until(f"people[{user}] == {want}", ok, 150, every=3)


_kc = {"t": 0.0, "token": ""}


def kc(path: str, method: str = "GET"):
    """Keycloak's admin API (portcullis realm); a POST / PUT sends an empty body."""
    if time.time() - _kc["t"] > 30:
        body = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli",
                                       "username": os.environ["KEYCLOAK_ADMIN"],
                                       "password": os.environ["KEYCLOAK_ADMIN_PASSWORD"]}).encode()
        with urllib.request.urlopen(urllib.request.Request(
                f"{KC_ADMIN}/realms/master/protocol/openid-connect/token", data=body), timeout=30) as r:
            _kc["token"], _kc["t"] = json.loads(r.read())["access_token"], time.time()
    req = urllib.request.Request(f"{KC_ADMIN}/admin/realms/portcullis{path}", method=method,
                                 data=b"" if method in ("POST", "PUT") else None,
                                 headers={"Authorization": "Bearer " + _kc["token"]})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def kc_user_id(username: str) -> str | None:
    users = kc("/users?" + urllib.parse.urlencode({"username": username, "exact": "true"}))
    return users[0]["id"] if users else None


PASSKEY_TYPES = {"webauthn", "webauthn-passwordless", "portcullis-device-passkey", "portcullis-security-key"}


def kc_types(username: str) -> list:
    """The person's passkey credential types (Keycloak also lists the LDAP
    federation's `password`, which isn't a stored credential)."""
    uid = kc_user_id(username)
    assert uid, f"{username} isn't in Keycloak"
    return sorted(c["type"] for c in kc(f"/users/{uid}/credentials") if c["type"] in PASSKEY_TYPES)


def kc_sessions(username: str) -> list:
    uid = kc_user_id(username)
    return kc(f"/users/{uid}/sessions") if uid else []


def kc_log() -> str:
    out = subprocess.run(["docker", "compose", "logs", "--no-color", "keycloak"], capture_output=True, text=True)
    return out.stdout + out.stderr


def invite(user: str, to: str) -> str:
    out = subprocess.run(["./portcullis", "invite", user, "--to", to, "--json"], capture_output=True, text=True)
    assert out.returncode == 0, f"portcullis invite {user}: exit {out.returncode} {out.stderr[-300:]}"
    url = json.loads(out.stdout)["url"]
    assert re.fullmatch(rf"https://enroll\.{re.escape(DOMAIN)}/invite/[A-Za-z0-9_-]{{43}}", url), "malformed setup link"
    print(f"::add-mask::{url}", flush=True)  # GitHub Actions hides it from the log from here on
    return url


def oidc_secret(instance: str) -> str:
    cid = subprocess.run(["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project=portcullis-{instance}",
                          "--filter", "label=com.docker.compose.service=web"],
                         check=True, capture_output=True, text=True).stdout.split()
    assert len(cid) == 1, f"{instance}: containers {cid}"
    env = json.loads(subprocess.run(["docker", "inspect", "-f", "{{json .Config.Env}}", cid[0]],
                                    check=True, capture_output=True, text=True).stdout)
    for e in env:
        if e.startswith("OIDC_ECHO_SECRET="):
            return e.split("=", 1)[1]
    raise AssertionError(f"{instance}: no OIDC_ECHO_SECRET")


def write_fixture(data: bytes) -> None:
    """Atomically (a temp file renamed over it in the same directory, which
    the Hub reads through a read-only mount, so it never sees a partial
    file): a new mtime is a new generation of the development mds.serial."""
    tmp = os.path.join(os.path.dirname(FIXTURE), ".extra-authenticators.json.tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o644)  # the Hub (uid 10001) reads it
    os.replace(tmp, FIXTURE)


def published() -> dict:
    return hub_json("signin-keycloak.json")


# ── the browser ──

class Key:
    """A virtual CTAP2 authenticator on a page answering every prompt;
    backup eligibility 1 makes its passkeys synced. Copied credentials
    start each copy 1000 signatures further on, so no copy's counter ever
    goes back below what Keycloak stored from an earlier one."""

    copies = 0

    def __init__(self, page: Page, *, synced: bool = False, credentials: list | None = None, transport: str = "usb"):
        self.cdp = page.context.new_cdp_session(page)
        self.cdp.send("WebAuthn.enable", {"enableUI": False})
        opts = {"protocol": "ctap2", "transport": transport, "hasResidentKey": True, "hasUserVerification": True,
                "isUserVerified": True, "automaticPresenceSimulation": True}
        if synced:
            opts.update(defaultBackupEligibility=True, defaultBackupState=True)
        self.id = self.cdp.send("WebAuthn.addVirtualAuthenticator", {"options": opts})["authenticatorId"]
        self.registered = 0
        self.asserted = 0
        self.cdp.on("WebAuthn.credentialAdded", lambda _e: setattr(self, "registered", self.registered + 1))
        self.cdp.on("WebAuthn.credentialAsserted", lambda _e: setattr(self, "asserted", self.asserted + 1))
        if credentials:
            Key.copies += 1
        for c in credentials or []:
            self.cdp.send("WebAuthn.addCredential", {"authenticatorId": self.id, "credential": dict(
                c, signCount=c.get("signCount", 0) + 1000 * Key.copies)})

    def credentials(self) -> list:
        return self.cdp.send("WebAuthn.getCredentials", {"authenticatorId": self.id})["credentials"]


def token_claims(page: Page) -> dict:
    """The access token oauth2-proxy holds for this browser (auth.<d>)."""
    t = page.request.get(f"{AUTH}/oauth2/auth").headers.get("x-auth-request-access-token", "")
    return claims_of(t) if t else {}


def kc_page(page: Page, seconds: int = 30) -> None:
    page.wait_for_url(re.compile("^" + re.escape(REALM) + "/"), timeout=seconds * 1000)
    page.wait_for_load_state("domcontentloaded")


def goto(page: Page, url: str):
    """page.goto, retried on Chromium's net::ERR_NETWORK_CHANGED (a
    container start changes the runner's network)."""
    for i in range(3):
        try:
            return page.goto(url, wait_until="domcontentloaded")
        except PWError as e:
            if "ERR_NETWORK_CHANGED" not in str(e) or i == 2:
                raise
            page.wait_for_timeout(2000)


def body(page: Page) -> str:
    try:
        return page.inner_text("body")
    except PWError:
        return ""


def headers_of(text: str) -> dict:
    seen: dict = {}
    for line in text.splitlines():
        name, _, value = line.partition(": ")
        seen.setdefault(name.strip().lower(), []).append(value.strip())
    return seen


def drive_kc(page: Page, done, label: str, seconds: int = 60) -> str:
    """Follow Keycloak (and group-gate's step-up page, clicked) until done()
    → "done"; Keycloak's or group-gate's needs-stronger page →
    "needs-stronger"; Keycloak's error page → "error". Clicks the passkey
    button whenever it shows; fails on a password field."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            page.wait_for_load_state("domcontentloaded")
            if done():
                return "done"
            if page.locator("#needs-stronger").count():
                base.shot(page, f"{label}-needs-stronger")
                return "needs-stronger"
            if page.locator("#stepup-continue").count():
                base.shot(page, f"{label}-stepup")
                page.click("#stepup-continue")
                page.wait_for_timeout(1500)
                continue
            if page.url.startswith(AUTH + "/"):
                pw = page.locator("input[type=password]")
                if pw.count() and pw.first.is_visible():
                    raise AssertionError(f"password prompt at {page.url.split('?')[0]}")
                if page.locator("#kc-error-message").count():
                    base.shot(page, f"{label}-kc-error")
                    return "error"
                if page.locator("#authenticateWebAuthnButton").is_visible():
                    page.click("#authenticateWebAuthnButton")
                    page.wait_for_timeout(1500)
                    continue
        except PWError as e:
            if "ERR_NETWORK_CHANGED" not in str(e) and "Execution context was destroyed" not in str(e):
                raise
        page.wait_for_timeout(500)
    base.shot(page, f"{label}-timeout")
    raise AssertionError(f"{label}: stuck at {page.url.split('?')[0]}: {body(page)[:300]!r}")


class Redirect:
    """Keeps the URLs Keycloak sends the browser to at a client's redirect
    URI (a request event: a page route never saw Keycloak's redirect in
    CI). The code is redeemed here; what the app host then
    answers doesn't matter (oidc-all's host may refuse the TLS handshake,
    people.<d> shows its own page)."""

    def __init__(self, page: Page, redirect_uri: str):
        self.urls: list[str] = []
        prefix = redirect_uri + "?"
        page.on("request", lambda r: self.urls.append(r.url) if r.url.startswith(prefix) else None)

    def code(self) -> str | None:
        for u in self.urls:
            c = urllib.parse.parse_qs(urllib.parse.urlsplit(u).query).get("code")
            if c:
                return c[0]
        return None


def authorize_url(client: str, redirect_uri: str, **extra) -> str:
    q = {"client_id": client, "response_type": "code", "scope": "openid", "redirect_uri": redirect_uri,
         "state": secrets.token_urlsafe(12), "nonce": secrets.token_urlsafe(12)}
    q.update(extra)
    return f"{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(q)


def exchange(page: Page, client: str, redirect_uri: str, code: str, *, secret: str | None = None,
             verifier: str | None = None) -> dict:
    form = {"grant_type": "authorization_code", "client_id": client, "code": code, "redirect_uri": redirect_uri}
    if secret:
        form["client_secret"] = secret
    if verifier:
        form["code_verifier"] = verifier
    r = page.request.post(f"{REALM}/protocol/openid-connect/token", form=form)
    assert r.status == 200, f"token exchange for {client}: HTTP {r.status} {r.text()[:300]}"
    return r.json()


def fresh_auth(page: Page, label: str, **extra) -> dict:
    """An authorization through the Hub's fresh-auth client (public, PKCE
    S256, redirect https://people.<d>/signin, D24), as the Hub's popup does;
    the ID token's claims."""
    redirect_uri = PEOPLE + "/signin"
    rd = Redirect(page, redirect_uri)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    goto(page, authorize_url("portcullis-fresh-auth", redirect_uri, code_challenge=challenge,
                             code_challenge_method="S256", **extra))
    out = drive_kc(page, lambda: rd.code() is not None, label)
    assert out == "done", f"{label}: {out} at {page.url.split('?')[0]}"
    tok = exchange(page, "portcullis-fresh-auth", redirect_uri, rd.code(), verifier=verifier)
    return claims_of(tok["id_token"])


def fresh_code(page: Page, label: str, redirect_uri: str, fresh: bool = True) -> dict:
    """The Hub's popup flow on redirect_uri (prompt=login, max_age=0, PKCE
    S256): the proof the page posts — code, verifier and nonce — not
    exchanged here (the Hub does it). fresh=False: the same without
    prompt=login / max_age (the SSO cookie alone, no touch)."""
    rd = Redirect(page, redirect_uri)
    verifier, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(16)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    extra = {"prompt": "login", "max_age": "0"} if fresh else {}
    goto(page, authorize_url("portcullis-fresh-auth", redirect_uri, code_challenge=challenge, code_challenge_method="S256",
                             nonce=nonce, **extra))
    out = drive_kc(page, lambda: rd.code() is not None, label)
    assert out == "done", f"{label}: {out} at {page.url.split('?')[0]}"
    return {"code": rd.code(), "code_verifier": verifier, "nonce": nonce}


def hub_as(user: str, method: str, path: str, body=None, base_url: str = HUB_API, headers: dict | None = None):
    """The Hub listener (or base_url: the people listener) as Traefik calls
    it for user (proxy secret), plus headers."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base_url + path, data=data, method=method, headers={
        "X-Portcullis-Proxy-Secret": os.environ["E2E_HUB_SECRET"], "X-Forwarded-User": user,
        "Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def hub_mcp_admin(user: str, tool: str, args: dict) -> tuple[bool, str]:
    """tools/call on the Hub's Portcullis MCP (admin), as mcp-gate calls it
    (the gate secret from the host file, never printed): (isError, text)."""
    with open(os.environ.get("E2E_MCP_SECRET_FILE", "secrets/mcp-gate/hub-secret")) as f:
        mcp_secret = f.read().strip()
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": args}}).encode()
    req = urllib.request.Request(f"http://{os.environ['HUB_IP']}:8890/mcp/admin", data=data, method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
        "Mcp-Protocol-Version": "2025-11-25", "X-Portcullis-MCP-Secret": mcp_secret, "X-Forwarded-User": user,
        "X-Portcullis-AI-Client": "portcullis-ai-claude-code", "X-Portcullis-AI-Resource": f"https://hub.{DOMAIN}/mcp"})
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = r.read().decode()
    lines = [ln[6:] for ln in raw.splitlines() if ln.startswith("data: ")]
    doc = json.loads(lines[-1] if lines else raw)
    res = doc["result"]
    return bool(res.get("isError")), "\n".join(c.get("text", "") for c in res.get("content") or [])


def ca_names(host: str) -> bool:
    """Traefik asks for a client certificate on host (s_client prints the
    acceptable CA names of a CertificateRequest)."""
    out = subprocess.run(["openssl", "s_client", "-connect", "127.0.0.1:443", "-servername", host],
                         stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    text = out.stdout + out.stderr
    assert "BEGIN CERTIFICATE" in text or "Server certificate" in text, f"no TLS handshake with {host}: {text[-300:]}"
    return "Acceptable client certificate CA names" in text


def tls_option(instance: str) -> str:
    cid = subprocess.run(["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project=portcullis-{instance}",
                          "--filter", "label=com.docker.compose.service=web"],
                         check=True, capture_output=True, text=True).stdout.split()
    if len(cid) != 1:
        return f"containers {cid}"
    labels = json.loads(subprocess.run(["docker", "inspect", "-f", "{{json .Config.Labels}}", cid[0]],
                                       check=True, capture_output=True, text=True).stdout)
    return labels.get(f"traefik.http.routers.{instance}_echo.tls.options", "(none)")


# ── part 2: certificates, raw requests, the people listener ──

# Keys, certificates and the .p12's chain for openssl / curl / Playwright:
# a 0700 directory of 0600 files, never printed or uploaded.
SECRET_DIR = tempfile.mkdtemp(prefix="e2e-signin-")


def mask(value: str) -> None:
    print(f"::add-mask::{value}", flush=True)


def write_secret(name: str, data: bytes) -> str:
    path = os.path.join(SECRET_DIR, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def load_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def cn_of(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else ""


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def csr_for(key, user: str) -> str:
    return x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, user)])).sign(key, hashes.SHA256()).public_bytes(
        serialization.Encoding.PEM).decode()


def serial_int(serial: str) -> int:
    """Vault's serial (lowercase colon hex) as a number."""
    return int(serial.replace(":", "").replace("-", ""), 16)


def vault_issue(user: str) -> tuple[x509.Certificate, object]:
    """A pki_int (YubiKey) certificate for user, issued through Vault as CI
    issues root's and bob's (the root token from secrets/, in the
    environment of `docker compose exec -e VAULT_TOKEN`, never on argv)."""
    with open("secrets/vault-init.json") as f:
        token = json.load(f)["root_token"]
    mask(token)
    key = ec.generate_private_key(ec.SECP256R1())
    out = subprocess.run(["docker", "compose", "exec", "-T", "-e", "VAULT_TOKEN", "vault", "vault", "write",
                          "-format=json", "pki_int/sign/client-cert", f"csr={csr_for(key, user)}",
                          f"common_name={user}", "ttl=2h"],
                         env=dict(os.environ, VAULT_TOKEN=token), capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, f"vault write pki_int/sign/client-cert for {user}: exit {out.returncode} {out.stderr[-300:]}"
    return x509.load_pem_x509_certificate(json.loads(out.stdout)["data"]["certificate"].encode()), key


def ca_name_list(host: str) -> list[str]:
    """The CNs of the acceptable client certificate CA names Traefik sends
    on host (openssl s_client's list), in order."""
    out = subprocess.run(["openssl", "s_client", "-connect", "127.0.0.1:443", "-servername", host],
                         stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    lines = (out.stdout + out.stderr).splitlines()
    assert any("BEGIN CERTIFICATE" in ln or "Server certificate" in ln for ln in lines), \
        f"no TLS handshake with {host}: {lines[-5:]}"
    names, inside = [], False
    for ln in lines:
        if ln.strip() == "Acceptable client certificate CA names":
            inside = True
            continue
        if inside:
            if not re.match(r"^\s*[A-Za-z][A-Za-z0-9.]*\s*=", ln):
                break
            m = re.search(r"(?:^|,)\s*CN\s*=\s*([^,]+)", ln)
            names.append(m.group(1).strip() if m else ln.strip())
    return names


def curl_tls(host: str, cert_file: str | None = None, key_file: str | None = None) -> tuple[int, str]:
    """GET https://<host>/ with curl (core's CA trusted), presenting
    cert_file (a PEM leaf followed by its chain: curl sends them all) when
    given: (curl's exit code, the HTTP status; 000 = no answer)."""
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "20", "--cacert", CA_CHAIN]
    if cert_file:
        cmd += ["--cert", cert_file, "--key", key_file]
    out = subprocess.run(cmd + [f"https://{host}/"], capture_output=True, text=True, timeout=60)
    return out.returncode, out.stdout.strip()


def raw_request(host: str, path: str, cookie: str = "", method: str = "GET") -> tuple[int, str]:
    """One HTTPS request with the path written exactly as given
    (http.client never normalises it): (status, body)."""
    conn = http.client.HTTPSConnection(host, 443, context=ssl.create_default_context(cafile=CA_CHAIN), timeout=30)
    try:
        headers = {"Cookie": cookie} if cookie else {}
        conn.request(method, path, headers=headers)
        r = conn.getresponse()
        return r.status, r.read().decode(errors="replace")
    finally:
        conn.close()


def people_as(user: str, method: str, path: str, body=None, headers: dict | None = None) -> tuple[int, str]:
    """The Hub's people listener as Traefik calls it for user."""
    return hub_as(user, method, path, body, base_url=PEOPLE_API, headers=headers)


def people_json(user: str, method: str, path: str, body=None):
    code, out = people_as(user, method, path, body)
    assert code == 200, f"{user}: {method} {path}: HTTP {code} {out[:300]}"
    return json.loads(out)


def people_methods(user: str) -> list:
    return hub_json("group-gate-policy.json").get("people", {}).get(user) or []


def wait_people_has(user: str, method: str, present: bool, seconds: float = 150) -> None:
    """The policy file's `people` lists (or no longer lists) method for
    user; kicked every 35 s like wait_people."""
    last_kick = [0.0]

    def ok():
        if time.time() - last_kick[0] > 35:
            kick()
            last_kick[0] = time.time()
        return (method in people_methods(user)) == present
    until(f"people[{user}] {'has' if present else 'lacks'} {method}", ok, seconds, every=3)


def forged_cert_headers(cert: x509.Certificate) -> dict:
    """What Traefik's client-cert-pem@file would pass for cert (base64 DER,
    URL-escaped) and a matching -Info: sent by the client, Traefik must
    delete both."""
    b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    info = f'Subject="CN={cn_of(cert.subject)}";Issuer="CN={cn_of(cert.issuer)}";SerialNumber="{cert.serial_number}"'
    return {"X-Forwarded-Tls-Client-Cert": urllib.parse.quote(b64, safe=""),
            "X-Forwarded-Tls-Client-Cert-Info": urllib.parse.quote(info, safe="")}


# ── part 3: signing in as someone else ──

MAIN = f"https://{DOMAIN}"
IMP_REASON = "checking quota"
IMP_BANNER = f"You are signed in as alice (by root) · reason “{IMP_REASON}” ·"
READ_ONLY = "not while you are signed in as someone else: Stop first"
AI_CLIENT = "portcullis-ai-claude-code"
AI_CALLBACK = "http://127.0.0.1:33418/callback"
PEOPLE_MCP = PEOPLE + "/mcp"
PEOPLE_SCOPE = "mcp:portcullis.people"
MCPCLIENT = os.environ.get("E2E_MCPCLIENT", "")


def access_token(page: Page) -> str:
    """The raw access token oauth2-proxy holds for this browser (never printed)."""
    return page.request.get(f"{AUTH}/oauth2/auth").headers.get("x-auth-request-access-token", "")


def audit_entries(action: str) -> list:
    return [e for e in hub_ok("GET", "/api/directory/audit") if e.get("action") == action]


def kc_events(user: str, kind: str, **extra) -> list:
    uid = kc_user_id(user)
    return kc("/events?" + urllib.parse.urlencode(dict({"user": uid, "type": kind, "max": 100}, **extra))) if uid else []


def session_ids(user: str) -> set:
    return {x["id"] for x in kc_sessions(user)}


def mcp_login(page: Page, resource: str, scope: str, label: str) -> str:
    """tests/e2e/mcpclient login (as e2e_ai.py): the authorize URL it prints
    opened in page, the consent approved; the token file (0600, never
    printed)."""
    assert MCPCLIENT, "E2E_MCPCLIENT isn't set"
    tf = os.path.join(SECRET_DIR, f"{label}.token.json")
    p = subprocess.Popen([MCPCLIENT, "login", "--client-id", AI_CLIENT, "--callback-port", "33418", "--resource", resource,
                          "--scope", scope, "--token-file", tf, "--ca-file", CA_CHAIN, "--timeout", "3m"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        url = p.stdout.readline().strip()
        assert url.startswith(REALM + "/protocol/openid-connect/auth?"), \
            f"mcpclient login printed {url[:80]!r}: {p.stderr.read()[:400] if p.poll() is not None else ''}"
        goto(page, url)
        deadline = time.time() + 90
        while time.time() < deadline and not page.url.startswith(AI_CALLBACK):
            try:
                page.wait_for_load_state("domcontentloaded")
                if page.url.startswith(AUTH + "/"):
                    accept = page.locator("[name=accept]")
                    if accept.count() and accept.first.is_visible():
                        accept.first.click()
                        page.wait_for_timeout(1000)
                        continue
                    if page.locator("#authenticateWebAuthnButton").is_visible():
                        page.click("#authenticateWebAuthnButton")
                        page.wait_for_timeout(1500)
                        continue
                    if page.locator("#kc-error-message, #impersonating").count():
                        raise AssertionError(f"{label}: Keycloak refused: {body(page)[:300]!r}")
            except PWError as e:
                if "ERR_NETWORK_CHANGED" not in str(e) and "Execution context was destroyed" not in str(e):
                    raise
            page.wait_for_timeout(500)
        rc = p.wait(60)
        assert rc == 0, f"mcpclient login: rc {rc}: {p.stderr.read()[:600]}"
    finally:
        if p.poll() is None:
            p.kill()
    assert os.path.exists(tf), "mcpclient wrote no token file"
    return tf


def mcp_tools_list(url: str, tf: str) -> tuple[int, dict]:
    out = subprocess.run([MCPCLIENT, "call", "--url", url, "--token-file", tf, "--method", "tools/list",
                          "--ca-file", CA_CHAIN], capture_output=True, text=True, timeout=120)
    assert out.returncode in (0, 2), f"mcpclient call: rc {out.returncode}: {out.stderr.strip()[:400]}"
    return out.returncode, json.loads(out.stdout)


def main() -> int:
    root_cert = {"certPath": os.environ["E2E_ROOT_CERT"], "keyPath": os.environ["E2E_ROOT_KEY"]}
    bob_cert = {"certPath": os.environ["E2E_BOB_CERT"], "keyPath": os.environ["E2E_BOB_KEY"]}
    original_fixture = open(FIXTURE, "rb").read()

    with sync_playwright() as pw_:
        browser = pw_.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])

        def new_context(client_cert=None, origins=(), storage_state=None, recorder: list | None = None):
            certs = [dict(client_cert, origin=o) for o in origins] if client_cert else []
            ctx = browser.new_context(client_certificates=certs, storage_state=storage_state)
            ctx.set_default_timeout(TIMEOUT_MS)
            ctx.on("page", lambda p: p.on("dialog", lambda d: d.accept(d.default_value)))
            if recorder is not None:
                ctx.expose_binding("__pcAllow", lambda _src, ids: recorder.append(list(ids)))
                ctx.add_init_script(ALLOW_RECORDER)
            return ctx

        def cold_page_offers_passkey_only(label: str) -> None:
            ctx = new_context()
            page = ctx.new_page()
            try:
                goto(page, ECHO_STD + "/")
                kc_page(page)
                base.shot(page, f"{label}-cold")
                assert page.locator("#kc-error-message").count() == 0, body(page)[:300]
                assert page.locator("#authenticateWebAuthnButton").count() == 1, "no passkey sign-in"
                assert page.locator("input[type=password]").count() == 0, "a password field"
                assert page.locator("#try-another-way").count() == 0, "\"Try another way\" offered"
                # A step-up asking for the password, which is off: still no password form.
                authz: list = []
                page.on("request", lambda r: authz.append(r.url)
                        if r.url.startswith(f"{REALM}/protocol/openid-connect/auth?") else None)
                goto(page, f"{AUTH}/oauth2/start?" + urllib.parse.urlencode({"pc_method": "password",
                                                                             "rd": ECHO_STD + "/"}))
                kc_page(page)
                base.shot(page, f"{label}-pc-method-password")
                asked = [urllib.parse.parse_qs(urllib.parse.urlsplit(u).query).get("pc_method") for u in authz]
                assert ["password"] in asked, f"pc_method=password never reached Keycloak's authorize: {asked}"
                assert page.locator("input[type=password]").count() == 0, "pc_method=password showed a password field"
            finally:
                ctx.close()

        def methods_on() -> list:
            return sorted(m["id"] for m in hub_ok("GET", "/api/signin")["methods"] if m["on"])

        def password_off_not_offered():
            assert "password" not in methods_on(), methods_on()
            cold_page_offers_passkey_only("pw-off-1")
        check("password_off_not_offered: password off — passkey sign-in only, no \"Try another way\", "
              "no password field (also with pc_method=password)", password_off_not_offered)

        # ── reclassify, part 1: rita registers while the fixture lacks the key ──
        def reclassify_register():
            s0 = published()["mds"]["serial"]
            ctx = None
            try:
                write_fixture(b"{}\n")
                kick()
                # The FIDO MDS's own entries stay; only the fixture's goes.
                until("signin-keycloak.json without the virtual key's entry",
                      lambda: AAGUID not in published()["authenticators"] and published()["mds"]["serial"] > s0, 90)
                ctx = new_context()
                page = ctx.new_page()
                key = Key(page)
                goto(page, invite("rita", "portal"))
                deadline = time.time() + 90
                while time.time() < deadline:
                    page.wait_for_load_state("domcontentloaded")
                    if page.locator("#stepup-continue").count():
                        break
                    for marker in ("#needs-stronger", "#present-certificate", "#kc-error-message"):
                        assert page.locator(marker).count() == 0, f"{marker} at {page.url.split('?')[0]}"
                    if page.locator("#invite-continue").is_visible():
                        page.click("#invite-continue")
                    elif page.locator("#registerWebAuthn").is_visible():
                        page.click("#registerWebAuthn")
                        page.wait_for_timeout(1500)
                    page.wait_for_timeout(500)
                base.shot(page, "rita-stepup")
                assert page.locator("#stepup-continue").count() == 1, f"no step-up page (at {page.url})"
                assert (key.registered, key.asserted) == (1, 0), (key.registered, key.asserted)
            except Exception:
                if ctx:
                    ctx.close()
                raise
            finally:
                # The fixture back at once: no other registration sees it empty.
                write_fixture(original_fixture)
                kick()
                state["fixture_back"] = time.time()
                # Every later registration needs the key's entry published.
                until("signin-keycloak.json lists the key again",
                      lambda: AAGUID in published()["authenticators"], 90)
            try:
                assert kc_types("rita") == ["webauthn-passwordless"], kc_types("rita")
                assert f"passkey registered for rita: AAGUID {AAGUID}, kind passkey_synced" in kc_log(), \
                    "no registration line for rita as passkey_synced"
            except Exception:
                ctx.close()
                raise
            state["rita"] = True
            state["rita_page"] = (ctx, page, key)
        check("reclassify (1): with the key's entry gone from the fixture, a setup-link registration is "
              "webauthn-passwordless (passkey_synced)", reclassify_register)

        def pc_fresh_absent_after_setup_link():
            needs("rita_page")
            ctx, page, key = state.pop("rita_page")
            try:
                before = key.asserted
                c = fresh_auth(page, "rita-fresh")
                assert key.asserted == before, "the SSO reuse asked for the key"
                assert c.get("preferred_username") == "rita", c.get("preferred_username")
                assert "pc_fresh" not in c, f"pc_fresh after a setup link: {c.get('pc_fresh')}"
            finally:
                ctx.close()
        check("pc_fresh: absent for a setup-link session (portcullis-fresh-auth, SSO reused, no touch)",
              pc_fresh_absent_after_setup_link)

        # ── root: a security key, Strong on hub.<d> ──
        def security_key_on_strong():
            ctx = new_context()
            page = ctx.new_page()
            key = Key(page)
            try:
                goto(page, invite("root", HUB + "/"))
                stepups: list = []
                base.passkey_flow(page, until=HUB, label="root", expect_stepups=1, stepups=stepups)
                # A setup-link session asks the Hub's Strong for the one passkey kind it has.
                assert "pc_method=security_key&" in stepups[0], stepups
                resp = page.reload(wait_until="domcontentloaded")
                base.shot(page, "root-hub")
                assert resp and resp.status == 200, f"hub.<d>: HTTP {resp and resp.status}"
                amr = token_claims(page).get("amr") or []
                assert "hwk" in amr and "spk" not in amr, amr
                assert kc_types("root") == ["portcullis-security-key"], kc_types("root")
                assert f"passkey registered for root: AAGUID {AAGUID}, kind security_key" in kc_log()
                state["root_creds"] = key.credentials()
            finally:
                ctx.close()
        check("security_key_on_strong: a security-key session opens hub.<d> (Strong); stored as "
              "portcullis-security-key", security_key_on_strong)

        def admin_signs_up():
            ctx = new_context()
            page = ctx.new_page()
            key = Key(page)
            try:
                goto(page, invite("admin", "portal"))
                base.passkey_flow(page, until=PORTAL, label="admin", expect_stepups=1)
                assert "Signed in as <strong>admin</strong>" in page.content()
                state["admin_creds"] = key.credentials()
            finally:
                ctx.close()
        check("admin: setup link → passkey → portal", admin_signs_up)

        # ── sam: a synced passkey ──
        def synced_refused_on_strong():
            ctx = new_context()
            page = ctx.new_page()
            key = Key(page, synced=True)
            goto(page, invite("sam", "portal"))
            stepups: list = []
            base.passkey_flow(page, until=PORTAL, label="sam", expect_stepups=1, stepups=stepups)
            assert "pc_method=passkey&" in stepups[0], stepups
            assert kc_types("sam") == ["webauthn-passwordless"], kc_types("sam")
            assert f"passkey registered for sam: AAGUID {AAGUID}, kind passkey_synced" in kc_log()
            amr = token_claims(page).get("amr") or []
            assert "spk" in amr and "hwk" not in amr, amr
            synced_creds = key.credentials()
            ctx.close()
            # A setup-link session (amr inv) counts as not known in `people`
            # (contract §5): the needs-stronger page needs a later sign-in.
            wait_people("sam", ["passkey_synced"])
            ctx = new_context()
            page = ctx.new_page()
            key = Key(page, synced=True, credentials=synced_creds)
            try:
                goto(page, HUB + "/")
                deadline = time.time() + 60
                while time.time() < deadline and not (page.url.startswith(HUB + "/") and not base.on_login_pages(page)):
                    page.wait_for_load_state("domcontentloaded")
                    if base.on_login_pages(page) and page.locator("#authenticateWebAuthnButton").is_visible():
                        page.click("#authenticateWebAuthnButton")
                        page.wait_for_timeout(1500)
                        continue
                    page.wait_for_timeout(500)
                assert key.asserted == 1, f"{key.asserted} assertions for sam's sign-in"
                amr = token_claims(page).get("amr") or []
                assert "spk" in amr and "inv" not in amr and "hwk" not in amr, amr
                resp = page.reload(wait_until="domcontentloaded")
                base.shot(page, "sam-hub-needs-stronger")
                assert resp and resp.status == 403, f"hub.<d>: HTTP {resp and resp.status}"
                assert page.locator("#needs-stronger").count() == 1, body(page)[:300]
                assert page.locator("#stepup-continue").count() == 0, "a step-up the synced key can't complete"
            except Exception:
                ctx.close()
                raise
            state["sam_synced"] = synced_creds
            state["sam_ctx"], state["sam_page"] = ctx, page
        check("synced_passkey_refused_on_strong: a synced passkey (backup eligible) is webauthn-passwordless "
              "and gets #needs-stronger on hub.<d>", synced_refused_on_strong)

        def native_oidc_template_enforced():
            needs("sam_page")
            page = state["sam_page"]
            rd = Redirect(page, OIDC_STRONG + "/cb")
            goto(page, authorize_url("oidc-strong", OIDC_STRONG + "/cb"))
            out = drive_kc(page, lambda: rd.code() is not None, "sam-oidc-strong")
            page.screenshot(path=os.path.join(SCREENS, "keycloak-needs-stronger.png"), full_page=True)
            with open(os.path.join(SCREENS, "keycloak-needs-stronger.html"), "w") as f:
                f.write(page.content())
            assert out == "needs-stronger", f"{out}: {body(page)[:300]!r}"
            assert page.url.startswith(AUTH + "/"), page.url
            text = body(page)
            assert "OIDC Strong needs a stronger sign-in" in text, text[:400]
            assert "/login/portcullis/" in page.content(), "not core's portcullis login theme"
            assert rd.code() is None and not rd.urls, f"the client got a redirect: {rd.urls}"
            assert "sam doesn't meet the sign-in template of oidc-strong" in kc_log()
        check("native_oidc_template_enforced: a synced session on a Strong native-OIDC client gets Keycloak's "
              "needs-stronger page (portcullis theme), no code", native_oidc_template_enforced)

        def pc_method_kind():
            needs("sam_synced")
            rec: list = []
            ctx = new_context(recorder=rec)
            page = ctx.new_page()
            key = Key(page)
            try:
                goto(page, invite("sam", HUB + "/"))
                stepups: list = []
                base.passkey_flow(page, until=HUB, label="sam-spare", expect_stepups=1, stepups=stepups)
                assert "pc_method=security_key&" in stepups[0], stepups
                creds = key.credentials()
                assert key.registered == 1 and len(creds) == 1, (key.registered, creds)
                spare, synced = raw_id(creds[0]["credentialId"]), raw_id(state["sam_synced"][0]["credentialId"])
                asked = [[raw_id(i) for i in ids] for ids in rec]
                assert asked == [[spare]], f"allowCredentials asked: {rec}"
                assert all(synced not in ids for ids in asked)
                assert kc_types("sam") == ["portcullis-security-key", "webauthn-passwordless"], kc_types("sam")
                state["sam_spare"] = creds
            finally:
                ctx.close()
        check("pc_method=security_key for a person with a synced and a security-key passkey: the browser is "
              "asked for the security key only", pc_method_kind)

        def pc_method_reaches_keycloak():
            needs("sam_ctx", "sam_spare")
            wait_people("sam", ["passkey_synced", "security_key"])
            rec: list = []
            ctx = new_context(storage_state=state["sam_ctx"].storage_state(), recorder=rec)
            page = ctx.new_page()
            key = Key(page, credentials=state["sam_spare"])
            try:
                resp = goto(page, HUB + "/")
                base.shot(page, "sam-hub-stepup")
                assert resp and resp.status == 403, f"hub.<d>: HTTP {resp and resp.status}"
                href = page.locator("#stepup-continue").get_attribute("href") or ""
                assert "pc_method=security_key&" in href, href
                page.click("#stepup-continue")
                kc_page(page)
                page.wait_for_selector("#authenticateWebAuthnButton", state="visible")
                base.shot(page, "sam-kc-stepup")
                assert page.locator("input[type=password]").count() == 0, "a password field"
                assert page.locator("#try-another-way").count() == 0, "\"Try another way\" on a pc_method step-up"
                assert page.locator("#kc-error-message").count() == 0, body(page)[:300]
                page.click("#authenticateWebAuthnButton")
                page.wait_for_url(re.compile("^" + re.escape(HUB) + "/"), timeout=TIMEOUT_MS)
                resp = page.reload(wait_until="domcontentloaded")
                assert resp and resp.status == 200, f"hub.<d> after the step-up: HTTP {resp and resp.status}"
                spare, synced = raw_id(state["sam_spare"][0]["credentialId"]), raw_id(state["sam_synced"][0]["credentialId"])
                asked = [[raw_id(i) for i in ids] for ids in rec]
                assert asked == [[spare]], f"allowCredentials asked: {rec}"
                assert key.asserted >= 1
                amr = token_claims(page).get("amr") or []
                assert {"spk", "hwk"} <= set(amr), f"amr after the step-up: {amr}"
            finally:
                ctx.close()
                state.pop("sam_ctx").close()
        check("pc_method_reaches_keycloak + amr_accumulates: a synced session steps up on hub.<d> with "
              "pc_method=security_key, Keycloak shows the passkey prompt only (no other way, no password), "
              "the token's amr then has spk and hwk", pc_method_reaches_keycloak)

        # ── alice (passkey) presenting bob's certificate ──
        def alice_signs_up():
            ctx = new_context()
            page = ctx.new_page()
            key = Key(page)
            try:
                goto(page, invite("alice", "portal"))
                base.passkey_flow(page, until=PORTAL, label="alice", expect_stepups=1)
                state["alice_storage"] = ctx.storage_state()
                state["alice_creds"] = key.credentials()
            finally:
                ctx.close()
        check("alice: setup link → passkey → portal", alice_signs_up)

        def alice_session_is_one_ticket():
            """oauth2-proxy #3486: the step-up's session outgrew one cookie,
            the cookie store wrote _oauth2_proxy_0..n and kept loading the
            stale unsplit _oauth2_proxy (the step-up page looped). With the
            session store the browser holds one small ticket."""
            needs("alice_storage")
            names = sorted(c["name"] for c in state["alice_storage"]["cookies"]
                           if re.fullmatch(r"_oauth2_proxy(_\d+)?", c["name"]))
            assert names == ["_oauth2_proxy"], f"oauth2-proxy cookies after alice's step-up: {names}"
            (ticket,) = [c for c in state["alice_storage"]["cookies"] if c["name"] == "_oauth2_proxy"]
            assert len(ticket["value"]) < 512, f"_oauth2_proxy is {len(ticket['value'])} bytes, not a ticket"
        check("alice's session after the step-up is one small _oauth2_proxy ticket (no _oauth2_proxy_0…, "
              "oauth2-proxy #3486)", alice_session_is_one_ticket)

        def bob_refused_in(log: str, client: str) -> bool:
            """Keycloak's X.509 user check (it won't set another user than the
            step's: a LOGIN_ERROR for bob's certificate with no user) or the
            extension's USER_CONFLICT (its log line naming alice)."""
            return "a certificate of another account was presented while alice was signing in" in log or bool(
                re.search(r'type="LOGIN_ERROR".*clientId="' + re.escape(client) +
                          r'".*userId="null".*x509_cert_subject_distinguished_name="CN=bob"', log))

        def never_bob(page: Page) -> None:
            assert kc_sessions("bob") == [], f"bob has Keycloak sessions: {kc_sessions('bob')}"
            user = token_claims(page).get("preferred_username")
            assert user in (None, "alice"), f"forward-auth session of {user}"

        def cross_user_cert_forward_auth():
            needs("alice_storage")
            ctx = new_context(client_cert=bob_cert, origins=(AUTH, ECHO_CERT), storage_state=state["alice_storage"])
            page = ctx.new_page()
            Key(page, credentials=state["alice_creds"])
            callbacks: list = []
            page.on("request", lambda r: callbacks.append(r.url) if r.url.startswith(AUTH + "/oauth2/callback") else None)
            mark = len(kc_log())
            try:
                resp = goto(page, ECHO_CERT + "/")
                base.shot(page, "alice-bobcert-stepup")
                assert resp and resp.status == 403, f"echo-cert: HTTP {resp and resp.status}"
                assert page.locator("#present-certificate").count() == 0, "present-certificate for a session without mtls"
                href = page.locator("#stepup-continue").get_attribute("href") or ""
                assert "pc_method=yubikey_cert&" in href, href
                page.click("#stepup-continue")
                deadline = time.time() + 30
                while time.time() < deadline:
                    page.wait_for_load_state("domcontentloaded")
                    assert not (page.url.startswith(ECHO_CERT) and "Hostname" in body(page)), "echo-cert opened"
                    if page.url.startswith(AUTH + "/realms/") and page.locator("#kc-error-message").count():
                        break
                    page.wait_for_timeout(500)
                base.shot(page, "alice-bobcert-refused")
                assert page.locator("#kc-error-message").count() == 1, f"not refused at {page.url.split('?')[0]}"
                assert not callbacks, f"a code reached oauth2-proxy: {len(callbacks)}"
                assert bob_refused_in(kc_log()[mark:], "portcullis-forward-auth"), \
                    "no refusal of bob's certificate in Keycloak's log"
                never_bob(page)
            finally:
                ctx.close()
        check("cross_user_certificate (forward-auth): alice's step-up to yubikey_cert presenting bob's "
              "certificate is refused by Keycloak's X.509 user check or the extension's USER_CONFLICT, no code, "
              "never bob", cross_user_cert_forward_auth)

        def cross_user_cert_native():
            # oidc-cert's template is any[yubikey_cert]: a switch to bob's
            # account would meet it and issue a code.
            needs("alice_storage")
            ctx = new_context(client_cert=bob_cert, origins=(AUTH,), storage_state=state["alice_storage"])
            page = ctx.new_page()
            Key(page, credentials=state["alice_creds"])
            try:
                rd = Redirect(page, OIDC_CERT + "/cb")
                # The template step: bob's certificate isn't alice's, so it isn't asked for.
                mark = len(kc_log())
                goto(page, authorize_url("oidc-cert", OIDC_CERT + "/cb"))
                out = drive_kc(page, lambda: rd.code() is not None, "alice-bobcert-oidc-cert")
                assert out == "needs-stronger", f"{out}: {rd.urls}"
                assert "alice doesn't meet the sign-in template of oidc-cert" in kc_log()[mark:]
                # A step asking for the certificate itself (pc_method): refused.
                mark = len(kc_log())
                goto(page, authorize_url("oidc-cert", OIDC_CERT + "/cb", pc_method="yubikey_cert"))
                out = drive_kc(page, lambda: rd.code() is not None, "alice-bobcert-oidc-cert-pc-method")
                assert out == "error", f"{out}: {rd.urls}"
                assert bob_refused_in(kc_log()[mark:], "oidc-cert"), "no refusal of bob's certificate in Keycloak's log"
                assert rd.code() is None and not rd.urls, f"oidc-cert got a redirect: {rd.urls}"
                assert "bob" not in body(page).lower(), body(page)[:300]
                never_bob(page)
            finally:
                ctx.close()
        check("cross_user_certificate (native OIDC): alice on oidc-cert (YubiKey certificate only) presenting "
              "bob's certificate: the template step doesn't take it, a pc_method=yubikey_cert step is refused "
              "by Keycloak's X.509 user check or the extension's USER_CONFLICT; no code, never bob",
              cross_user_cert_native)

        # ── root: all[yubikey_cert, security_key] met step by step ──
        def all_met_step_by_step():
            needs("root_creds")
            rec: list = []
            ctx = new_context(client_cert=root_cert, origins=(AUTH,), recorder=rec)
            page = ctx.new_page()
            key = Key(page, credentials=state["root_creds"])
            try:
                rd = Redirect(page, OIDC_ALL + "/cb")
                goto(page, authorize_url("oidc-all", OIDC_ALL + "/cb"))
                out = drive_kc(page, lambda: rd.code() is not None, "root-oidc-all")
                assert out == "done", f"{out} at {page.url.split('?')[0]}: {body(page)[:300]!r}"
                assert key.asserted >= 1, "no passkey assertion"
                assert [[raw_id(i) for i in ids] for ids in rec] == [[raw_id(state["root_creds"][0]["credentialId"])]], \
                    f"allowCredentials asked: {rec}"
                tok = exchange(page, "oidc-all", OIDC_ALL + "/cb", rd.code(), secret=oidc_secret("oidc-all"))
                c = claims_of(tok["id_token"])
                assert c.get("preferred_username") == "root", c.get("preferred_username")
                assert {"mtls", "hwk"} <= set(c.get("amr") or []), f"amr {c.get('amr')}"
            finally:
                ctx.close()
        check("all_met_step_by_step: root's certificate signs in, Keycloak asks for his security key itself, "
              "then issues (amr mtls + hwk) — native OIDC, YubiKey + certificate", all_met_step_by_step)

        def pc_fresh_present():
            needs("root_creds")
            ctx = new_context()
            page = ctx.new_page()
            key = Key(page, credentials=state["root_creds"])
            try:
                c = fresh_auth(page, "root-fresh", prompt="login", max_age="0")
                assert key.asserted >= 1, "no passkey assertion"
                assert c.get("preferred_username") == "root", c.get("preferred_username")
                assert c.get("pc_fresh") == "security_key", f"pc_fresh {c.get('pc_fresh')!r}"
                before = key.asserted
                c = fresh_auth(page, "root-fresh-sso")
                assert key.asserted == before, "the SSO reuse asked for the key"
                assert "pc_fresh" not in c, f"pc_fresh on an SSO reuse: {c.get('pc_fresh')}"
            finally:
                ctx.close()
        check("pc_fresh: = security_key after a fresh passkey sign-in; absent when the SSO cookie alone signs in",
              pc_fresh_present)

        def fresh_follows_hub_template():
            # Contract §8 "Governing template": an admin tool's confirmation
            # (Hub listener) is governed by the hub core template, Strong
            # here: sam's synced passkey is refused, his security key approves.
            needs("sam_synced", "sam_spare")
            assert hub_ok("GET", "/api/signin")["core"]["hub"] == "strong", "hub.<d> isn't on Strong"
            group = "ci-fresh-hub"
            hub_ok("POST", "/api/directory/groups", {"name": group})
            try:
                err, text = hub_mcp_admin("sam", "delete_group", {"group": group})
                m = re.search(r"https://hub\.[a-z0-9.-]+/confirm/([A-Za-z0-9_-]+)", text)
                print(f"    delete_group: isError {err}: {text[:160]}", flush=True)
                assert err and m, text[:300]
                cid = m.group(1)

                def approve(creds: list, synced: bool, label: str):
                    ctx = new_context()
                    page = ctx.new_page()
                    key = Key(page, synced=synced, credentials=creds)
                    try:
                        proof = fresh_code(page, label, HUB + "/")
                        assert key.asserted >= 1, f"{label}: no passkey assertion"
                    finally:
                        ctx.close()
                    return hub_as("sam", "POST", f"/api/me/confirmations/{cid}",
                                  dict(proof, decision="approve", typed=group))

                code, out = approve(state["sam_synced"], True, "sam-fresh-synced")
                print(f"    synced passkey: HTTP {code} {out.strip()[:120]}", flush=True)
                assert code == 403 and "a fresh sign-in is required" in out, f"synced passkey on Strong: HTTP {code} {out[:200]}"
                code, out = approve(state["sam_spare"], False, "sam-fresh-key")
                print(f"    security key: HTTP {code} {out.strip()[:120]}", flush=True)
                assert code == 200 and json.loads(out) == {"state": "approved"}, f"security key on Strong: HTTP {code} {out[:200]}"
                audit = hub_ok("GET", "/api/directory/audit")
                mine = [e for e in audit if e.get("action") == "ai.confirm" and cid in (e.get("detail") or "")]
                details = [(e.get("result"), e.get("detail")) for e in mine]
                print(f"    audit: {details}", flush=True)
                assert any(r == "refused" and "doesn't accept" in d and "template strong" in d for r, d in details), details
                assert any(r == "ok" and d.startswith("approved ") and d.endswith("template strong") for r, d in details), details
            finally:
                dcode, dout = hub("DELETE", f"/api/directory/groups/{group}", {"confirm": group})
                print(f"    cleanup: DELETE {group}: HTTP {dcode}", flush=True)
                # Never hides the case's own failure (an exception in flight).
                assert dcode == 200 or sys.exc_info()[0] is not None, f"deleting {group}: HTTP {dcode} {str(dout)[:200]}"
        check("fresh_follows_hub_template: an admin confirmation (Hub listener, hub core template Strong): sam's "
              "synced passkey fresh sign-in → 403, his security key → approved; the audit names template strong",
              fresh_follows_hub_template)

        # ── passwords ──
        def password_switch(on: bool) -> None:
            hub_ok("PUT", "/api/signin/methods/password", {"on": on})
            until(f"password {'on' if on else 'off'} in signin-keycloak.json",
                  lambda: ("password" in published()["methods"]) == on, 60)

        def choose_password(page: Page) -> None:
            page.wait_for_selector("#authenticateWebAuthnButton", state="visible")
            assert page.locator("#try-another-way").count() == 1, "no \"Try another way\" with password on"
            page.click("#try-another-way")
            page.wait_for_load_state("domcontentloaded")
            page.get_by_text("Password", exact=True).first.click()
            page.wait_for_selector("#password", state="visible")

        def password_on_basic_app():
            password_switch(True)
            state["password_on"] = True
            ctx = new_context()
            page = ctx.new_page()
            try:
                goto(page, ECHO_BASIC + "/")
                kc_page(page)
                choose_password(page)
                page.fill("#username", "pat")
                with open(os.environ["E2E_PAT_PASSWORD_FILE"]) as f:
                    page.fill("#password", f.read().strip())
                page.click("#kc-login")
                page.wait_for_url(re.compile("^" + re.escape(ECHO_BASIC) + "/"), timeout=TIMEOUT_MS)
                for _ in range(20):  # oauth2-proxy's callback, then the app
                    page.wait_for_load_state("domcontentloaded")
                    if "Hostname" in body(page):
                        break
                    page.wait_for_timeout(1000)
                # No screenshot: whoami echoes the session cookie and bearer token.
                assert headers_of(body(page)).get("x-forwarded-user") == ["pat"], body(page)[:400]
                amr = token_claims(page).get("amr") or []
                assert "pwd" in amr, amr
                wait_people("pat", ["password"])
                resp = goto(page, PEOPLE + "/")
                base.shot(page, "pat-people-needs-stronger")
                assert resp and resp.status == 403, f"people.<d>: HTTP {resp and resp.status}"
                assert page.locator("#needs-stronger").count() == 1, body(page)[:300]
            finally:
                ctx.close()
        check("password_on_basic_app: password on — a password sign-in opens a Basic app; people.<d> (Strong) "
              "then shows #needs-stronger", password_on_basic_app)

        def admin_password_refused():
            needs("password_on", "admin_creds")
            ctx = new_context()
            page = ctx.new_page()
            try:
                goto(page, PORTAL)
                kc_page(page)
                choose_password(page)
                for i in range(11):  # above the realm's failureFactor (10)
                    page.fill("#username", "admin")
                    page.fill("#password", os.environ["LLDAP_ADMIN_PASSWORD"])
                    with page.expect_navigation(wait_until="domcontentloaded"):
                        page.click("#kc-login")
                    page.wait_for_selector("#password", state="visible")
                    text = body(page)
                    assert "Password sign-in isn't available for this account" in text, f"attempt {i + 1}: {text[:300]!r}"
                    assert not page.url.startswith(PORTAL), "signed in with admin's password"
                admin_id = kc_user_id("admin")
                assert admin_id is not None, "admin isn't in Keycloak"
                # Read a few times over 10 s: a failure Keycloak counted
                # asynchronously would show up meanwhile.
                for _ in range(5):
                    time.sleep(2)
                    bf = kc(f"/attack-detection/brute-force/users/{admin_id}")
                    assert bf.get("numFailures") == 0 and not bf.get("disabled"), f"brute force: {bf}"
            finally:
                ctx.close()
            ctx = new_context()
            page = ctx.new_page()
            key = Key(page, credentials=state["admin_creds"])
            try:
                goto(page, PORTAL)
                base.passkey_flow(page, until=PORTAL, label="admin-after", expect_stepups=0)
                assert "Signed in as <strong>admin</strong>" in page.content()
                assert key.asserted >= 1
            finally:
                ctx.close()
        check("admin_password_refused: admin + LLDAP's admin password, 11 times: \"Password sign-in isn't "
              "available for this account\", no brute-force failure counted, admin's passkey still signs in",
              admin_password_refused)

        def password_off_again():
            needs("password_on")
            password_switch(False)
            cold_page_offers_passkey_only("pw-off-2")
        check("password_off_not_offered: switched off again — no \"Try another way\", no password field",
              password_off_again)

        # ── reclassify, part 2 ──
        def reclassify_upgraded():
            needs("rita", "fixture_back")
            back = state["fixture_back"]
            # The extension's task runs every 5 min: 360 s with slack; polled a little longer.
            until("rita's passkey reclassified to portcullis-security-key",
                  lambda: kc_types("rita") == ["portcullis-security-key"], max(back + RECLASSIFY_S + 30 - time.time(), 30),
                  every=10)
            out = subprocess.run(["docker", "compose", "logs", "--no-color", "--timestamps", "keycloak"],
                                 capture_output=True, text=True).stdout
            m = re.search(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?Z .*PasskeyReclassified user rita AAGUID "
                          + re.escape(AAGUID) + " passkey_synced -> security_key", out)
            assert m, "no PasskeyReclassified line for rita"
            at = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp() \
                + float("0" + (m.group(2) or ""))
            took = at - back
            print(f"    reclassified {took:.0f} s after the fixture came back", flush=True)
            assert -5 <= took <= RECLASSIFY_S, f"PasskeyReclassified {took:.0f} s after the fixture's return (limit {RECLASSIFY_S})"
        check(f"reclassify (2): the fixture's entry back (a new mtime → a higher mds.serial): within {RECLASSIFY_S} s "
              "rita's credential is portcullis-security-key (PasskeyReclassified, its log time)", reclassify_upgraded)

        # ── part 2: browser certificates, the Sign-in page, help, history ──
        yubikey_ca, browser_ca, root_ca = (load_cert("certs/yubikey-ca.crt"), load_cert("certs/browser-ca.crt"),
                                           load_cert("certs/root-ca.crt"))
        names = {"root": cn_of(root_ca.subject), "yubikey": cn_of(yubikey_ca.subject),
                 "browser": cn_of(browser_ca.subject)}
        assert len(set(names.values())) == 3, f"CA CNs not distinct: {names}"

        def people_signin(page: Page, label: str) -> None:
            """A forward-auth session on people.<d>, landing on the Sign-in page."""
            goto(page, PEOPLE + "/signin")
            out = drive_kc(page, lambda: page.url.startswith(PEOPLE + "/signin"), label)
            assert out == "done", f"{label}: {out} at {page.url.split('?')[0]}"

        def people_req(page: Page, method: str, path: str, body=None, headers: dict | None = None):
            """A request through Traefik to people.<d> with the browser's
            session (and its client certificate, if any); no redirects."""
            return page.request.fetch(PEOPLE + path, method=method, max_redirects=0,
                                      data=json.dumps(body) if body is not None else None,
                                      headers={"Content-Type": "application/json", **(headers or {})})

        def create_browser_cert(page: Page, label: str, days: int = 30):
            """The Sign-in page's create: a fresh sign-in (popup flow on
            people.<d>/signin), then the POST; the answer (never printed)."""
            proof = fresh_code(page, label, PEOPLE + "/signin")
            r = people_req(page, "POST", "/api/me/signin/browser-certificates", dict(proof, days=days))
            if r.status == 200:
                mask(r.json()["password"])
            return r

        def browser_cert_on():
            assert "browser_cert" in methods_on(), methods_on()
            assert "browser_cert" in published()["methods"], published()["methods"]
            for inst in ("echo-file", "echo-anycert"):
                assert tls_option(inst) == "protected-any@file", f"{inst}: {tls_option(inst)}"
            assert tls_option("echo-cert") == "protected@file", f"echo-cert: {tls_option('echo-cert')}"
            state["bc_on"] = True
        check("browser_cert_on: browser_cert switched on (Hub API); e2e-file / e2e-anycert apps on "
              "protected-any@file, e2e-cert's on protected@file", browser_cert_on)

        def browser_cert_create_download():
            needs("bc_on", "alice_creds")
            ctx = new_context()
            page = ctx.new_page()
            key = Key(page, credentials=state["alice_creds"])
            try:
                people_signin(page, "alice-people")
                before = key.asserted
                r = create_browser_cert(page, "alice-fresh-bc1")
                assert key.asserted > before, "the fresh sign-in asked no security key"
                assert r.status == 200, f"create: HTTP {r.status} {r.text()[:300]}"
                h = r.headers
                assert "no-store" in h.get("cache-control", ""), f"Cache-Control: {h.get('cache-control')!r}"
                assert h.get("pragma") == "no-cache", f"Pragma: {h.get('pragma')!r}"
                doc = r.json()
                pw, b64 = doc["password"], doc["p12"]
                assert re.fullmatch(r"[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}", pw), "password not 4×5 Crockford"
                p12 = base64.b64decode(b64)
                bkey, leaf, extra = pkcs12.load_key_and_certificates(p12, pw.encode())
                assert isinstance(bkey, ec.EllipticCurvePrivateKey) and bkey.curve.name == "secp256r1", type(bkey)
                assert cn_of(leaf.subject) == "alice", leaf.subject.rfc4514_string()
                assert leaf.issuer == browser_ca.subject, f"issuer {leaf.issuer.rfc4514_string()}"
                leaf.verify_directly_issued_by(browser_ca)
                left = leaf.not_valid_after_utc - datetime.now(timezone.utc)
                assert abs(left - timedelta(days=30)) < timedelta(hours=2), f"not_after in {left}"
                subjects = [c.subject for c in extra or []]
                assert browser_ca.subject in subjects and root_ca.subject in subjects, \
                    f".p12 chain: {[s.rfc4514_string() for s in subjects]} (want the browser CA and the root)"
                assert yubikey_ca.subject not in subjects, ".p12 chain holds the YubiKey CA"
                assert re.fullmatch(r"alice-browser-certificate-\d{8}\.p12", doc["filename"]), doc["filename"]
                cert = doc["certificate"]
                assert cert["kind"] == "browser" and serial_int(cert["serial"]) == leaf.serial_number, cert
                # The audit names the certificate, never the file or its password.
                entries = [e for e in hub_ok("GET", "/api/directory/audit")
                           if e.get("action") == "cert.create" and "alice" in json.dumps(e)]
                assert entries, "no cert.create audit entry for alice"
                dump = json.dumps(entries)
                assert pw not in dump and pw.replace("-", "") not in dump, "the password in the audit"
                assert b64[:48] not in dump and not re.search(r"[A-Za-z0-9+/]{48,}", dump), "base64 in the audit"
                assert any(cert["serial"] in (e.get("detail") or "") for e in entries), entries[-3:]
                state["bc"] = [{"p12": p12, "pw": pw, "serial": cert["serial"], "leaf": leaf, "key": bkey,
                                "extra": extra}]
                state["alice_pk"] = (ctx, page, key)
            except Exception:
                ctx.close()
                raise
            wait_people_has("alice", "browser_cert", True)
        check("browser_cert_create_download: alice's fresh security-key sign-in, then POST /api/me/signin/"
              "browser-certificates {days: 30} → 200 no-store; the .p12 opens with the shown password: an EC P-256 "
              "key, CN alice, issued by the browser CA, ~30 days, chain = browser CA + root; the audit holds "
              "neither the password nor base64", browser_cert_create_download)

        def browser_cert_fresh_refused_weak():
            needs("bc_on", "sam_synced")
            ctx = new_context()
            page = ctx.new_page()
            Key(page, synced=True, credentials=state["sam_synced"])
            try:
                people_signin(page, "sam-people-synced")
                r = create_browser_cert(page, "sam-fresh-bc")
                print(f"    synced passkey: HTTP {r.status} {r.text().strip()[:100] if r.status != 200 else ''}", flush=True)
                assert r.status == 403 and "a fresh sign-in is required" in r.text(), \
                    f"synced fresh sign-in under Strong: HTTP {r.status} {r.text()[:200] if r.status != 200 else ''}"
                v = people_req(page, "GET", "/api/me/signin")
                assert v.status == 200 and v.json()["active_browser_certs"] == 0, f"HTTP {v.status} {v.text()[:200]}"
            finally:
                ctx.close()
        check("browser_cert_fresh_refused_weak: sam's synced-passkey fresh sign-in (people core template Strong) "
              "→ 403 \"a fresh sign-in is required\", nothing created", browser_cert_fresh_refused_weak)

        def browser_cert_max_active():
            needs("alice_pk", "bc")
            _, page, _ = state["alice_pk"]
            for n in (2, 3):
                r = create_browser_cert(page, f"alice-fresh-bc{n}")
                assert r.status == 200, f"create #{n}: HTTP {r.status} {r.text()[:300] if r.status != 200 else ''}"
                doc = r.json()
                p12 = base64.b64decode(doc["p12"])
                bkey, leaf, extra = pkcs12.load_key_and_certificates(p12, doc["password"].encode())
                assert cn_of(leaf.subject) == "alice" and leaf.issuer == browser_ca.subject
                state["bc"].append({"p12": p12, "pw": doc["password"], "serial": doc["certificate"]["serial"],
                                    "leaf": leaf, "key": bkey, "extra": extra})
            r = create_browser_cert(page, "alice-fresh-bc4")
            print(f"    fourth: HTTP {r.status} {r.text().strip()[:120] if r.status != 200 else ''}", flush=True)
            assert r.status == 409 and "browser certificates" in r.text(), \
                f"fourth create: HTTP {r.status} {r.text()[:200] if r.status != 200 else ''}"
            v = people_req(page, "GET", "/api/me/signin")
            assert v.status == 200 and v.json()["active_browser_certs"] == 3, f"HTTP {v.status} {v.text()[:200]}"
            assert len({c["serial"] for c in state["bc"]}) == 3
        check("browser_cert_max_active: two more creates succeed, the fourth gets 409 (at most 3 active)",
              browser_cert_max_active)

        def bc_files(i: int = 0) -> tuple[str, str]:
            """alice's browser certificate i as a browser sends it: the leaf
            followed by the .p12's chain (pki_file + root), and its key."""
            c = state["bc"][i]
            full = pem(c["leaf"]) + b"".join(pem(x) for x in c["extra"])
            return write_secret(f"bc{i}-full.pem", full), write_secret(f"bc{i}.key", key_pem(c["key"]))

        def tls_protected_yubikey_ca_only():
            got = ca_name_list(f"echo-cert.{DOMAIN}")
            print(f"    echo-cert CA names: {got}", flush=True)
            assert got == [names["yubikey"]], f"protected@file CA names {got} (want only {names['yubikey']!r})"
        check("tls_protected_yubikey_ca_only: echo-cert (protected@file) names only the YubiKey CA (no root, no "
              "browser CA)", tls_protected_yubikey_ca_only)

        def tls_mtls_refuses_browser_cert():
            needs("bc")
            full, key = bc_files(0)
            rc, code = curl_tls(f"echo-cert.{DOMAIN}", full, key)
            print(f"    browser certificate + chain on echo-cert: curl exit {rc}, HTTP {code}", flush=True)
            # 35 (CURLE_SSL_CONNECT_ERROR) / 56 (CURLE_RECV_ERROR: TLS 1.3's
            # alert after the client's Certificate) / 55 (CURLE_SEND_ERROR:
            # that alert while curl sends the request, run 43173240200): the handshake refused,
            # nothing else (a timeout, DNS, a bad file) counts.
            assert rc in (35, 55, 56) and code == "000", \
                f"echo-cert with a browser certificate: curl exit {rc}, HTTP {code} (want a handshake refusal, 35 / 56)"
            # The same files complete the handshake where browser
            # certificates are accepted: the refusal above is the option's.
            rc, code = curl_tls(f"echo-anycert.{DOMAIN}", full, key)
            print(f"    the same files on echo-anycert: curl exit {rc}, HTTP {code}", flush=True)
            assert rc == 0 and code != "000", f"the same files on echo-anycert: curl exit {rc}, HTTP {code}"
            # The .p12 itself, as a browser presents it.
            c = state["bc"][0]
            ctx = new_context(client_cert={"pfx": c["p12"], "passphrase": c["pw"]}, origins=(ECHO_CERT, ECHO_ANYCERT))
            page = ctx.new_page()
            try:
                try:
                    resp = page.goto(ECHO_CERT + "/", wait_until="domcontentloaded")
                except PWError as e:
                    # Chromium's own client-certificate refusal, or
                    # net::ERR_HTTP2_PROTOCOL_ERROR: Playwright presents the
                    # certificate through its own TLS proxy, and with TLS 1.3
                    # the server's refusal (alert "unknown ca") can arrive
                    # after the proxy's tls.connect already reported the
                    # handshake done; the proxy has then answered the browser
                    # with h2 (Traefik's ALPN) and tears that session down
                    # when the alert comes (playwright 1.64.1, coreBundle.js
                    # _establishTlsTunnel: the synthetic 503 below is the same
                    # refusal when the alert wins the race; run 43101286740).
                    # That h2 error only counts if the same .p12 in the same
                    # context gets a real answer from echo-anycert (whose
                    # protected-any@file accepts it): so it was echo-cert's
                    # handshake, not Playwright's proxy or h2 in general.
                    first = str(e).splitlines()[0]
                    if "net::ERR_BAD_SSL_CLIENT_AUTH_CERT" in str(e):
                        pass
                    elif "net::ERR_HTTP2_PROTOCOL_ERROR" in str(e):
                        # A new page: the failed one still navigates to its
                        # chrome-error page and would interrupt this goto.
                        ctl = ctx.new_page()
                        ok_resp = ctl.goto(ECHO_ANYCERT + "/", wait_until="domcontentloaded")
                        assert ok_resp is not None and ok_resp.status != 503 \
                            and "client-certificate error" not in ctl.content(), \
                            f"the .p12 on echo-anycert (control for {first}): HTTP {ok_resp and ok_resp.status}"
                        print(f"    the .p12 on echo-anycert (control): HTTP {ok_resp.status}", flush=True)
                    else:
                        raise
                    print(f"    the .p12 on echo-cert: handshake refused ({first})", flush=True)
                else:
                    # Playwright presents client certificates through its own
                    # TLS proxy and answers a refused server handshake with a
                    # synthetic 503 "client-certificate error" page.
                    text = body(page)
                    print(f"    the .p12 on echo-cert: HTTP {resp and resp.status}: {text.strip()[:160]!r}", flush=True)
                    assert resp is not None and resp.status == 503 and "client-certificate error" in page.content(), \
                        f"echo-cert with the .p12: HTTP {resp and resp.status} {text[:200]!r}"
            finally:
                ctx.close()
            # Control: root's YubiKey certificate completes the handshake.
            rc, code = curl_tls(f"echo-cert.{DOMAIN}", os.environ["E2E_ROOT_CERT"], os.environ["E2E_ROOT_KEY"])
            print(f"    root's YubiKey certificate on echo-cert: curl exit {rc}, HTTP {code}", flush=True)
            assert rc == 0 and code != "000", f"root's YubiKey certificate refused: exit {rc}, HTTP {code}"
        check("tls_mtls_refuses_browser_cert: a handshake with alice's browser certificate and its full chain "
              "(leaf + pki_file + root, and the .p12 itself) to echo-cert is refused (curl 35 / 56); the same files "
              "pass on echo-anycert; root's YubiKey certificate passes on echo-cert",
              tls_mtls_refuses_browser_cert)

        def tls_protected_any():
            needs("bc")
            got = ca_name_list(f"echo-anycert.{DOMAIN}")
            print(f"    echo-anycert CA names: {got}", flush=True)
            assert sorted(got) == sorted(names.values()), f"protected-any@file CA names {got} (want {names})"
            full, key = bc_files(0)
            rc, code = curl_tls(f"echo-anycert.{DOMAIN}", full, key)
            print(f"    browser certificate on echo-anycert: curl exit {rc}, HTTP {code}", flush=True)
            assert rc == 0 and code != "000", f"protected-any@file refused a browser certificate: exit {rc}, HTTP {code}"
            rc, code = curl_tls(f"echo-anycert.{DOMAIN}")
            print(f"    no certificate on echo-anycert: curl exit {rc}, HTTP {code}", flush=True)
            assert rc != 0 and code == "000", f"protected-any@file without a certificate: exit {rc}, HTTP {code}"
        check("tls_protected_any: echo-anycert (e2e-anycert = any[yubikey_cert, browser_cert]) names the root and "
              "both CAs; alice's browser certificate completes the handshake, none fails", tls_protected_any)

        def browser_cert_signin_file():
            needs("bc")
            c = state["bc"][0]
            ctx = new_context(client_cert={"pfx": c["p12"], "passphrase": c["pw"]}, origins=(AUTH, ECHO_FILE, PEOPLE))
            page = ctx.new_page()  # no authenticator: the certificate only
            uid = kc_user_id("alice")
            mark, t0 = len(kc_log()), int(time.time() * 1000) - 2000
            try:
                goto(page, ECHO_FILE + "/")
                base.passkey_flow(page, until=ECHO_FILE, label="alice-file", expect_stepups=0)
                for _ in range(20):
                    page.wait_for_load_state("domcontentloaded")
                    if "Hostname" in body(page):
                        break
                    page.wait_for_timeout(1000)
                # No screenshot: whoami echoes the session cookie and bearer token.
                assert headers_of(body(page)).get("x-forwarded-user") == ["alice"], "echo-file didn't open for alice"
                amr = token_claims(page).get("amr") or []
                assert "file" in amr and "mtls" not in amr, f"amr {amr}"
                log = kc_log()[mark:]
                bad = [ln for ln in log.splitlines() if "alice" in ln and ("mtls" in ln or "yubikey_cert" in ln)]
                assert not bad, f"Keycloak's log names mtls / yubikey_cert for alice: {bad[:3]}"
                events = [e for e in kc("/events?" + urllib.parse.urlencode({"user": uid, "type": "LOGIN", "max": 20}))
                          if e.get("time", 0) >= t0]
                methods = [(e.get("details") or {}).get("pc_methods", "") for e in events]
                print(f"    LOGIN events since: {[(e.get('clientId'), m) for e, m in zip(events, methods)]}", flush=True)
                assert "browser_cert" in methods and not any("yubikey_cert" in m for m in methods), methods
                rows = {m["id"]: m for m in people_json("alice", "GET", "/api/me/signin")["methods"]}
                assert rows["browser_cert"]["state"] == "set", rows["browser_cert"]
                state["alice_file"] = ctx.storage_state()
            finally:
                ctx.close()
        check("browser_cert_signin_file: alice (no other session) signs in with the .p12 only and echo-file "
              "(any[browser_cert]) opens: amr has file, never mtls; Keycloak's LOGIN pc_methods browser_cert, "
              "no mtls / yubikey_cert for her in its log", browser_cert_signin_file)

        def browser_cert_not_yubikey():
            needs("alice_file")
            c = state["bc"][0]
            ctx = new_context(client_cert={"pfx": c["p12"], "passphrase": c["pw"]}, origins=(AUTH,),
                              storage_state=state["alice_file"])
            page = ctx.new_page()
            try:
                rd = Redirect(page, OIDC_CERT + "/cb")
                mark = len(kc_log())
                goto(page, authorize_url("oidc-cert", OIDC_CERT + "/cb"))
                out = drive_kc(page, lambda: rd.code() is not None, "alice-file-oidc-cert")
                assert out == "needs-stronger", f"oidc-cert (any[yubikey_cert]) for a browser-certificate session: {out}"
                assert "alice doesn't meet the sign-in template of oidc-cert" in kc_log()[mark:]
                # A step asking for the YubiKey certificate itself: the
                # browser certificate never counts (the extension's
                # yubikey_cert execution steps aside for a pki_file leaf).
                goto(page, authorize_url("oidc-cert", OIDC_CERT + "/cb", pc_method="yubikey_cert"))
                outcome, deadline = None, time.time() + 30
                while time.time() < deadline and outcome is None:
                    page.wait_for_load_state("domcontentloaded")
                    if rd.code() is not None:
                        outcome = "code"
                    elif page.locator("#needs-stronger").count():
                        outcome = "needs-stronger"
                    elif page.locator("#kc-error-message").count():
                        outcome = "error"
                    elif page.url.startswith(REALM) and page.locator("#authenticateWebAuthnButton").count():
                        outcome = "passkey prompt"
                    else:
                        page.wait_for_timeout(500)
                base.shot(page, "alice-file-pc-method-yubikey")
                print(f"    pc_method=yubikey_cert with the browser certificate: {outcome}", flush=True)
                assert outcome in ("needs-stronger", "error", "passkey prompt"), f"outcome {outcome}"
                assert rd.code() is None and not rd.urls, f"oidc-cert got a redirect: {rd.urls}"
            finally:
                ctx.close()
        check("browser_cert_not_yubikey: alice's browser-certificate session on oidc-cert (any[yubikey_cert]) "
              "gets Keycloak's needs-stronger; a pc_method=yubikey_cert step with that certificate signs nobody in "
              "(no code). (A forward-auth any[yubikey_cert] host is protected@file: the TLS case refuses it)",
              browser_cert_not_yubikey)

        def browser_cert_cannot_renew():
            needs("alice_file")
            c = state["bc"][0]
            ctx = new_context(client_cert={"pfx": c["p12"], "passphrase": c["pw"]}, origins=(AUTH, PEOPLE),
                              storage_state=state["alice_file"])
            page = ctx.new_page()
            try:
                v0 = people_json("alice", "GET", "/api/me/signin")["certificates"]
                r = people_req(page, "POST", "/api/me/signin/yubikey-certificate/renew", {"csr": csr_for(c["key"], "alice")})
                print(f"    renewal with the browser certificate: HTTP {r.status} {r.text().strip()[:100]}", flush=True)
                assert r.status == 403 and "present your current YubiKey certificate" in r.text(), \
                    f"HTTP {r.status} {r.text()[:200]}"
                v1 = people_json("alice", "GET", "/api/me/signin")["certificates"]
                assert sorted(x["serial"] for x in v1) == sorted(x["serial"] for x in v0), "a certificate was issued"
            finally:
                ctx.close()
        check("browser_cert_cannot_renew: the browser certificate presented on POST /api/me/signin/yubikey-"
              "certificate/renew with a CSR for its key → 403 \"present your current YubiKey certificate\", nothing "
              "issued", browser_cert_cannot_renew)

        def browser_cert_off_counts_nothing():
            # A switched-off method is never accepted (global constraint):
            # browser_cert off, the same valid .p12 and the same file session
            # count for nothing; then everything back (in a finally). The
            # switch drops browser_cert from every compiled rule (the Hub's
            # signin.Compile), so e2e-anycert = any[yubikey_cert, browser_cert]
            # compiles to any[yubikey_cert] and echo-anycert moves to
            # protected@file (contract §5: every alternative has
            # yubikey_cert), where a browser certificate can't even finish
            # the handshake; echo-file, on the default template (Standard)
            # meanwhile, is authaware@file, so the .p12 reaches Keycloak and
            # the file session reaches group-gate there.
            needs("alice_file")
            c = state["bc"][0]
            errs: list = []
            try:
                hub_ok("PUT", "/api/instances/echo-file/settings", {"sign_in_template": ""})
                hub_ok("PUT", "/api/signin/templates/e2e-file/enabled", {"on": False})
                hub_ok("PUT", "/api/signin/methods/browser_cert", {"on": False})
                def switched_off():
                    got = {"signin-keycloak.json has browser_cert": "browser_cert" in published()["methods"],
                           "group-gate-policy.json has browser_cert":
                               "browser_cert" in hub_json("group-gate-policy.json").get("methods", []),
                           "echo-anycert": tls_option("echo-anycert"), "echo-file": tls_option("echo-file")}
                    ok = (not got["signin-keycloak.json has browser_cert"]
                          and not got["group-gate-policy.json has browser_cert"]
                          and got["echo-anycert"] == "protected@file" and got["echo-file"] == "authaware@file")
                    assert ok, got  # until() keeps the last state for the failure message
                    return True
                until("browser_cert off in both published files, echo-anycert on protected@file, echo-file "
                      "(Standard) on authaware@file", switched_off, 180, every=5)
                # Traefik: on protected@file the browser certificate no longer
                # finishes the handshake (tls_protected_any had the same files
                # pass there while the switch was on): 35 / 56 as in
                # tls_mtls_refuses_browser_cert, nothing else counts.
                full, key = bc_files(0)
                rc, code = curl_tls(f"echo-anycert.{DOMAIN}", full, key)
                print(f"    browser certificate + chain on echo-anycert with browser_cert off: curl exit {rc}, "
                      f"HTTP {code}", flush=True)
                assert rc in (35, 55, 56) and code == "000", \
                    f"echo-anycert with browser_cert off: curl exit {rc}, HTTP {code} (want a handshake refusal, 35 / 56)"
                # Keycloak: the .p12 alone signs nobody in.
                uid = kc_user_id("alice")
                t0 = int(time.time() * 1000) - 2000
                ctx = new_context(client_cert={"pfx": c["p12"], "passphrase": c["pw"]}, origins=(AUTH, ECHO_FILE))
                page = ctx.new_page()  # no authenticator
                try:
                    goto(page, ECHO_FILE + "/")
                    kc_page(page)
                    page.wait_for_selector("#authenticateWebAuthnButton", state="visible")
                    page.wait_for_timeout(5000)
                    base.shot(page, "alice-bc-off-kc")
                    assert page.url.startswith(REALM + "/"), f"left Keycloak: {page.url.split('?')[0]}"
                    assert "Hostname" not in body(page), "echo-file opened"
                finally:
                    ctx.close()
                events = [e for e in kc("/events?" + urllib.parse.urlencode({"user": uid, "type": "LOGIN", "max": 20}))
                          if e.get("time", 0) >= t0]
                assert not events, f"LOGIN events with browser_cert off: {[(e.get('clientId'), e.get('details')) for e in events]}"
                # group-gate: the earlier file session (amr file) meets nothing.
                ctx = new_context(client_cert={"pfx": c["p12"], "passphrase": c["pw"]}, origins=(AUTH, ECHO_FILE),
                                  storage_state=state["alice_file"])
                page = ctx.new_page()
                try:
                    resp = goto(page, ECHO_FILE + "/")
                    print(f"    alice's file session on echo-file (Standard) with browser_cert off: HTTP {resp and resp.status}",
                          flush=True)
                    assert resp is not None and resp.status == 403 and "Hostname" not in body(page), \
                        f"echo-file with browser_cert off: HTTP {resp and resp.status}"
                finally:
                    ctx.close()
            finally:
                for method, path, body_ in (("PUT", "/api/signin/methods/browser_cert", {"on": True}),
                                            ("PUT", "/api/signin/templates/e2e-file/enabled", {"on": True}),
                                            ("PUT", "/api/instances/echo-file/settings", {"sign_in_template": "e2e-file"})):
                    try:
                        hub_ok(method, path, body_)
                    except Exception as e:  # noqa: BLE001
                        errs.append(str(e))
                if not errs:
                    try:
                        until("browser_cert back: published, echo-file / echo-anycert on protected-any@file",
                              lambda: "browser_cert" in published()["methods"]
                              and tls_option("echo-file") == "protected-any@file"
                              and tls_option("echo-anycert") == "protected-any@file", 180, every=5)
                    except Exception as e:  # noqa: BLE001
                        errs.append(str(e))
            assert not errs, f"restore failed: {errs}"
        check("browser_cert_off_counts_nothing: browser_cert switched off — the valid .p12 alone signs nobody in "
              "(Keycloak keeps the passkey prompt, no LOGIN event) and alice's file session gets 403 on echo-file "
              "(Standard, authaware@file); echo-anycert moves to protected@file, where the browser certificate's "
              "handshake is refused (curl 35 / 56); "
              "switched back on in a finally (echo-file / echo-anycert back on protected-any@file)",
              browser_cert_off_counts_nothing)

        def yubikey_cert_still_mtls():
            cert, ykey = vault_issue("alice")
            assert cert.issuer == yubikey_ca.subject, cert.issuer.rfc4514_string()
            crt_path, key_path = write_secret("alice-yk.crt", pem(cert)), write_secret("alice-yk.key", key_pem(ykey))
            state["alice_yk"] = {"cert": cert, "key": ykey}
            ctx = new_context(client_cert={"certPath": crt_path, "keyPath": key_path}, origins=(AUTH, PEOPLE, ECHO_CERT))
            page = ctx.new_page()  # no authenticator: the YubiKey certificate only
            try:
                goto(page, ECHO_CERT + "/")
                base.passkey_flow(page, until=ECHO_CERT, label="alice-yk", expect_stepups=0)
                for _ in range(20):
                    page.wait_for_load_state("domcontentloaded")
                    if "Hostname" in body(page):
                        break
                    page.wait_for_timeout(1000)
                assert headers_of(body(page)).get("x-forwarded-user") == ["alice"], "echo-cert didn't open for alice"
                amr = token_claims(page).get("amr") or []
                assert "mtls" in amr and "file" not in amr, f"amr {amr}"
                state["alice_yk_storage"] = ctx.storage_state()
                state["alice_yk_ctx"] = (ctx, page)
            except Exception:
                ctx.close()
                raise
        check("yubikey_cert_still_mtls: a pki_int certificate CI issued through Vault signs alice in (no "
              "authenticator) with amr mtls, never file; echo-cert opens", yubikey_cert_still_mtls)

        def yubikey_cert_renew():
            # Moved from e2e_login (enroll's /self is gone, D31): the
            # Sign-in page's renewal with the presented certificate.
            needs("alice_yk_ctx")
            ctx, page = state.pop("alice_yk_ctx")
            try:
                goto(page, PEOPLE + "/signin")
                assert page.url.startswith(PEOPLE + "/signin"), f"at {page.url.split('?')[0]}"
                key = state["alice_yk"]["key"]
                r = people_req(page, "POST", "/api/me/signin/yubikey-certificate/renew", {"csr": csr_for(key, "alice")})
                assert r.status == 200, f"renewal: HTTP {r.status} {r.text()[:300]}"
                assert "no-store" in r.headers.get("cache-control", ""), r.headers.get("cache-control")
                doc = r.json()
                new = x509.load_pem_x509_certificate(doc["certificate"].encode())
                assert cn_of(new.subject) == "alice" and new.issuer == yubikey_ca.subject, new.subject.rfc4514_string()
                assert new.public_key().public_numbers() == key.public_key().public_numbers(), "another key"
                assert serial_int(doc["serial"]) == new.serial_number != state["alice_yk"]["cert"].serial_number
                state["alice_yk"]["renewed"] = new
            finally:
                ctx.close()
        check("yubikey_cert_renew: alice's YubiKey-certificate-only session renews it on the Sign-in page (POST "
              "people.<d>/api/me/signin/yubikey-certificate/renew, same key, CN alice, the YubiKey CA)",
              yubikey_cert_renew)

        def forged_cert_headers_dropped():
            needs("alice_yk", "alice_yk_storage", "alice_pk")
            yk = state["alice_yk"].get("renewed") or state["alice_yk"]["cert"]
            forged = forged_cert_headers(yk)
            # group-gate: alice's mtls-only session without the certificate,
            # the headers forged: Traefik deletes them, no certificate counts.
            ctx = new_context(storage_state=state["alice_yk_storage"])
            page = ctx.new_page()
            try:
                r = page.request.get(PEOPLE + "/", headers=forged, max_redirects=0)
                print(f"    forged headers on people.<d>/ (mtls session, no certificate): HTTP {r.status}", flush=True)
                assert r.status == 403 and 'id="present-certificate"' in r.text(), \
                    f"a forged certificate header counted: HTTP {r.status} {r.text()[:200]}"
            finally:
                ctx.close()
            # The Hub's renewal: alice's passkey session, no certificate, the
            # headers forged → 403 (with them kept it would renew).
            _, page, _ = state["alice_pk"]
            r = people_req(page, "POST", "/api/me/signin/yubikey-certificate/renew",
                           {"csr": csr_for(state["alice_yk"]["key"], "alice")}, headers=forged)
            print(f"    forged headers on the renewal: HTTP {r.status} {r.text().strip()[:100]}", flush=True)
            assert r.status == 403 and "present your current YubiKey certificate" in r.text(), \
                f"HTTP {r.status} {r.text()[:200]}"
            # Positive control: the same header straight to the Hub's people
            # listener (no Traefik in between) renews — so the 403 above is
            # Traefik deleting it, not the Hub refusing the header's form.
            code, out = people_as("alice", "POST", "/api/me/signin/yubikey-certificate/renew",
                                  {"csr": csr_for(state["alice_yk"]["key"], "alice")},
                                  headers={"X-Forwarded-Tls-Client-Cert": forged["X-Forwarded-Tls-Client-Cert"]})
            print(f"    the same header straight to the people listener: HTTP {code}", flush=True)
            assert code == 200, f"control (people listener, no Traefik): HTTP {code} {out[:200]}"
            ctl = x509.load_pem_x509_certificate(json.loads(out)["certificate"].encode())
            assert cn_of(ctl.subject) == "alice" and ctl.issuer == yubikey_ca.subject, ctl.subject.rfc4514_string()
        check("forged_cert_headers: Traefik deletes a client-sent X-Forwarded-Tls-Client-Cert / -Info — an mtls "
              "session without the certificate stays on #present-certificate; a renewal with them forged → 403 "
              "through Traefik, while the same header sent straight to the Hub's people listener renews (200)",
              forged_cert_headers_dropped)

        def browser_cert_revoked():
            needs("alice_file")
            c = state["bc"][0]
            ctx = new_context(client_cert={"pfx": c["p12"], "passphrase": c["pw"]}, origins=(AUTH, ECHO_FILE, PEOPLE),
                              storage_state=state["alice_file"])
            page = ctx.new_page()
            try:
                resp = goto(page, ECHO_FILE + "/")
                assert resp and resp.status == 200, f"echo-file before the revocation: HTTP {resp and resp.status}"
                r = people_req(page, "DELETE", "/api/me/signin/certificates/" + urllib.parse.quote(c["serial"], safe=""))
                assert r.status == 204, f"DELETE: HTTP {r.status} {r.text()[:200]}"
                t0 = time.time()

                def refused():
                    resp = goto(page, ECHO_FILE + "/")
                    return resp is not None and resp.status == 403 and "revoked" in page.content()
                until("echo-file refuses the revoked browser certificate", refused, 70, every=5)
                print(f"    refused {time.time() - t0:.0f} s after the revocation", flush=True)
                base.shot(page, "alice-file-revoked")
            finally:
                ctx.close()
            rows = {x["serial"]: x for x in people_json("alice", "GET", "/api/me/signin")["certificates"]}
            assert rows.get(c["serial"], {}).get("status") == "revoked", rows.get(c["serial"])
            # Own route: a YubiKey certificate's serial is 404; her third
            # browser certificate she revokes herself.
            needs("alice_yk")
            yk_serials = [s for s, x in rows.items() if x["kind"] == "yubikey"]
            assert yk_serials, rows
            code, out = people_as("alice", "DELETE", "/api/me/signin/certificates/" + urllib.parse.quote(yk_serials[0], safe=""))
            assert code == 404, f"own revoke of a YubiKey certificate: HTTP {code} {out[:200]}"
            third = state["bc"][2]["serial"]
            code, out = people_as("alice", "DELETE", "/api/me/signin/certificates/" + urllib.parse.quote(third, safe=""))
            assert code == 204, f"revoking the third: HTTP {code} {out[:200]}"
            state["bc_revoked"] = True
        check("browser_cert_revoked: DELETE /api/me/signin/certificates/<serial> → 204; within 70 s echo-file "
              "answers 403 (revoked) and /api/me/signin shows it revoked; a YubiKey serial on that route is 404",
              browser_cert_revoked)

        def signin_page_reachable_weak():
            # pat: a Hub-set password only (bob has a YubiKey certificate, so
            # people.<d> would offer him a step-up, not needs-stronger).
            password_switch(True)
            ctx = new_context()
            page = ctx.new_page()
            try:
                goto(page, PEOPLE + "/signin")
                kc_page(page)
                choose_password(page)
                # A wrong password first (pat's history shows it failed).
                page.fill("#username", "pat")
                page.fill("#password", "not-" + secrets.token_urlsafe(12))
                with page.expect_navigation(wait_until="domcontentloaded"):
                    page.click("#kc-login")
                page.wait_for_selector("#password", state="visible")
                assert not page.url.startswith(PEOPLE), "signed in with a wrong password"
                page.fill("#username", "pat")
                with open(os.environ["E2E_PAT_PASSWORD_FILE"]) as f:
                    page.fill("#password", f.read().strip())
                page.click("#kc-login")
                page.wait_for_url(re.compile("^" + re.escape(PEOPLE) + "/signin"), timeout=TIMEOUT_MS)
                assert "pwd" in (token_claims(page).get("amr") or []), token_claims(page).get("amr")
                for path in ("/signin", "/api/me/signin"):
                    r = people_req(page, "GET", path)
                    assert r.status == 200, f"{path}: HTTP {r.status}"
                assert people_req(page, "GET", "/api/me/signin").json()["user"] == "pat"
                r = people_req(page, "GET", "/api/directory")
                assert r.status == 403 and 'id="needs-stronger"' in r.text(), f"/api/directory: HTTP {r.status} {r.text()[:200]}"
                cookie = "; ".join(f"{c['name']}={c['value']}" for c in ctx.cookies(PEOPLE))
                host = f"people.{DOMAIN}"
                code, text = raw_request(host, "/api/me/signin", cookie)
                assert code == 200 and '"user":"pat"' in text.replace(" ", ""), f"raw /api/me/signin: HTTP {code}"
                for path in ("/signin/../api/directory", "/api/me/signin/../../directory", "/static/../api/directory",
                             "/signin/%2e%2e/api/directory", "/api/me/signin/%2E%2E/%2E%2E/directory",
                             "/signin%2F..%2Fapi%2Fdirectory", "/api/me/signin/..%2F..%2Fdirectory",
                             "/signin/..%5Capi%5Cdirectory"):
                    code, text = raw_request(host, path, cookie)
                    print(f"    raw {path}: HTTP {code}", flush=True)
                    assert code in (400, 403, 404), f"raw {path}: HTTP {code} {text[:200]}"
                    if code == 403:
                        assert 'id="needs-stronger"' in text, f"raw {path}: a 403 without needs-stronger: {text[:200]}"
                    if "%" not in path:
                        assert code == 403, f"raw {path}: HTTP {code} (want group-gate's needs-stronger)"
            finally:
                ctx.close()
                password_switch(False)
        check("signin_page_reachable_weak: password on, pat signed in with a password only: /signin and "
              "/api/me/signin 200; /api/directory and raw unnormalised paths (/signin/../api/directory, encoded "
              "dots and slashes) refused (#needs-stronger)", signin_page_reachable_weak)

        def sign_in_help_actions():
            needs("bc_revoked")
            hub_ok("POST", "/api/directory/groups", {"name": "hr"})
            hub_ok("POST", "/api/directory/groups/hr/members", {"username": "carol"})
            hub_ok("PUT", "/api/directory/permissions/sign_in_help", {"group": "hr"})
            view = people_json("carol", "GET", "/api/directory/users/alice/signin")
            assert view["can"]["setup_link"] and view["can"]["remove_passkeys"] and view["can"]["revoke"], view["can"]
            assert not view["can"]["password"] and not view["can"]["issue"], view["can"]

            def act(user, method, path, body=None) -> tuple[int, str]:
                code, out = people_as(user, method, path, body)
                for link in SETUP_LINK.finditer(out):
                    mask(link.group(0))
                return code, redact(out)
            code, out = act("carol", "POST", "/api/directory/users/alice/invite", {})
            assert code == 200, f"carol: setup link for alice: HTTP {code} {out[:200]}"
            code, out = act("carol", "POST", "/api/directory/users/alice/remove-passkeys", {"confirm": "alice"})
            assert code == 200, f"carol: remove alice's passkeys: HTTP {code} {out[:200]}"
            until("alice's passkeys gone from Keycloak", lambda: kc_types("alice") == [], 30)
            second = state["bc"][1]["serial"]
            code, out = act("carol", "DELETE", "/api/directory/users/alice/certificates/" + urllib.parse.quote(second, safe=""))
            assert code == 204, f"carol: revoke alice's certificate: HTTP {code} {out[:200]}"
            # Never a password, never an administrator, a protected account or herself.
            code, out = act("carol", "POST", "/api/directory/users/alice/password", {"generate": True})
            assert code == 403, f"carol: alice's password: HTTP {code}"
            refused = []
            for target in ("root", "portcullis-hub", "carol"):
                for method, path, body_ in (("POST", f"/api/directory/users/{target}/invite", {}),
                                            ("POST", f"/api/directory/users/{target}/remove-passkeys", {"confirm": target}),
                                            ("GET", f"/api/directory/users/{target}/signin", None)):
                    code, out = act("carol", method, path, body_)
                    if code != 403:
                        refused.append(f"{method} {path}: HTTP {code} {out[:120]}")
            assert not refused, f"carol acted beyond sign_in_help: {refused}"
            root_serial = next((x["serial"] for x in hub_ok("GET", "/api/directory/users/root/signin")["certificates"]
                                if x["kind"] == "yubikey"), None)
            assert root_serial, "root has no YubiKey certificate listed"
            code, out = act("carol", "DELETE", "/api/directory/users/root/certificates/" + urllib.parse.quote(root_serial, safe=""))
            assert code == 403, f"carol: revoke root's certificate: HTTP {code} {out[:200]}"
            # An administrator: the certificate routes refuse administrator
            # targets (409; the CLI recovers).
            code, out = hub("DELETE", "/api/directory/users/root/certificates/" + urllib.parse.quote(root_serial, safe=""), {})
            assert code == 409 and "managed from the server" in str(out), f"admin: revoke root's: HTTP {code} {str(out)[:200]}"
            k = ec.generate_private_key(ec.SECP256R1())
            code, out = hub("POST", "/api/directory/users/root/certificates",
                            {"csr": csr_for(k, "root"), "code": "x", "code_verifier": "x", "nonce": "x"})
            assert code == 409 and "managed from the server" in str(out), f"admin: issue for root: HTTP {code} {str(out)[:200]}"
            audit = [e for e in hub_ok("GET", "/api/directory/audit") if "sign_in_help" in (e.get("detail") or "")]
            assert {e.get("action") for e in audit} >= {"user.invite", "user.remove_passkeys", "cert.revoke"}, \
                [(e.get("action"), e.get("detail")) for e in audit]
            state["helped"] = True
        check("sign_in_help_actions: PUT …/permissions/sign_in_help {group: hr}; carol (hr) sends alice a setup "
              "link (200), removes her passkeys (200), revokes her certificate (204); 403 for alice's password, "
              "root, portcullis-hub and herself; an admin gets 409 issuing / revoking root's certificate",
              sign_in_help_actions)

        def browser_cert_none_left():
            needs("helped")
            v = people_json("alice", "GET", "/api/me/signin")
            assert v["active_browser_certs"] == 0, v["active_browser_certs"]
            statuses = {x["serial"]: x["status"] for x in v["certificates"] if x["kind"] == "browser"}
            assert all(statuses.get(c["serial"]) == "revoked" for c in state["bc"]), statuses
            wait_people_has("alice", "browser_cert", False)
        check("browser_cert_revoked (all): alice's three browser certificates revoked → published people no "
              "longer lists browser_cert for her", browser_cert_none_left)

        def history_entries():
            needs("helped")
            page_ = people_json("alice", "GET", "/api/me/signin/history?limit=100")
            entries = page_["entries"]
            kinds = sorted({e["kind"] for e in entries})
            print(f"    alice: {len(entries)} entries, kinds {kinds}, unknown {page_['unknown']}", flush=True)
            assert page_["unknown"] == [], page_["unknown"]
            assert any(e["kind"] == "sign_in" and e["methods"] == ["browser_cert"] and e["browser"] for e in entries), \
                [e for e in entries if e["kind"] == "sign_in"][:5]
            # Her first sign-in, through the setup link: no method did it.
            assert any(e["kind"] == "sign_in" and e["methods"] == [] and e["detail"] == "Setup link used"
                       for e in entries), [(e["methods"], e["detail"]) for e in entries if e["kind"] == "sign_in"]
            assert any(e["kind"] == "step_up" for e in entries), "no step_up"
            assert any(e["kind"] == "opened" and "browser_cert" in e["methods"] and "echo" in e["app"].lower()
                       and "file" in e["app"].lower() for e in entries), \
                [(e["app"], e["methods"]) for e in entries if e["kind"] == "opened"]
            helps = [e for e in entries if e["kind"] == "help" and e["by"] == "carol"]
            assert len(helps) >= 3, [(e["by"], e["detail"]) for e in entries if e["kind"] == "help"]
            assert sum(e["kind"] == "certificate" for e in entries) >= 3, "fewer than 3 certificate entries"
            dump = json.dumps(entries)
            assert not any(c["pw"] in dump for c in state.get("bc", [])), "a .p12 password in the history"
            pat = people_json("pat", "GET", "/api/me/signin/history?limit=100")
            assert any(e["kind"] == "failed" for e in pat["entries"]), sorted({e["kind"] for e in pat["entries"]})
            # carol (sign_in_help) may read alice's history too.
            assert people_json("carol", "GET", "/api/directory/users/alice/signin/history")["entries"]
        check("history_entries: alice's history has her setup-link sign_in (no methods, \"Setup link used\"), a "
              "sign_in [browser_cert] with a browser, a step_up, an opened "
              "echo-file, help by carol and certificate entries; pat's a failed sign-in (his wrong password)",
              history_entries)

        def cert_and_password_kinds_identified():
            # The LOGIN events' pc_methods of the sign-ins above (the amr was
            # asserted at each: mtls, file, pwd) and the Sign-in page's rows.
            got = {}
            for user in ("alice", "pat"):
                got[user] = {(e.get("details") or {}).get("pc_methods", "") for e in kc_events(user, "LOGIN")}
            print(f"    LOGIN pc_methods: alice {sorted(got['alice'])}, pat {sorted(got['pat'])}", flush=True)
            assert "yubikey_cert" in got["alice"] and "browser_cert" in got["alice"], got["alice"]
            assert "password" in got["pat"], got["pat"]
            rows = {m["id"]: m["state"] for m in people_json("alice", "GET", "/api/me/signin")["methods"]}
            assert rows["yubikey_cert"] == "set", rows
            rows = {m["id"]: m["state"] for m in people_json("pat", "GET", "/api/me/signin")["methods"]}
            assert rows["password"] == "set" and all(rows[k] != "set" for k in ("security_key", "passkey_device",
                                                                                 "passkey_synced", "yubikey_cert",
                                                                                 "browser_cert")), rows
        check("cert_and_password_kinds_identified: Keycloak's LOGIN pc_methods name yubikey_cert and browser_cert for "
              "alice's certificate sign-ins and password for pat's; /api/me/signin lists alice's yubikey_cert and pat's "
              "password (and nothing else for pat)", cert_and_password_kinds_identified)

        def enroll_site_gone():
            # Traefik's own 404 (no router): enroll never sees these paths.
            for path in ("/", "/self", "/api/self/renew", "/api/sign", "/api/users", "/users", "/certs"):
                code, text = raw_request(ENROLL_HOST, path)
                assert code == 404 and text.strip() == "404 page not found", \
                    f"enroll.<d>{path}: HTTP {code} {text[:120]!r} (want Traefik's 404)"
            # /invite/* reaches enroll: its invite page for an unusable link.
            code, text = raw_request(ENROLL_HOST, "/invite/" + secrets.token_urlsafe(32))
            print(f"    /invite/<bad token>: HTTP {code}", flush=True)
            assert code == 404 and "This setup link is invalid, expired or already used" in text, \
                f"/invite/<bad>: HTTP {code} {text[:200]}"
        check("enroll_site_gone: enroll.<d>/, /self and its old APIs get Traefik's 404; /invite/<bad token> "
              "reaches enroll's invite page (\"This setup link is invalid, expired or already used\")",
              enroll_site_gone)

        if "alice_pk" in state:
            state.pop("alice_pk")[0].close()

        # ── part 3: signing in as someone else (IMPERSONATION_MAX_MINUTES=2) ──
        # Every start: root signs in with his YubiKey certificate (amr mtls),
        # then, in a copy of that browser that presents the certificate only
        # to the apps, a fresh sign-in with his security key (the proof,
        # pc_fresh security_key, the same Keycloak session: F39) and the
        # start route on the Hub listener with his access token (its sid).
        imp_t0: dict = {}

        def landed(page: Page, origin: str) -> bool:
            return (page.url.startswith(origin + "/") and not page.url.startswith(AUTH + "/")
                    and page.locator("#stepup-continue, #needs-stronger, #present-certificate, #impersonation-ended").count() == 0)

        def cert_files(cert, key, name: str) -> dict:
            return {"certPath": write_secret(f"{name}.crt", pem(cert)), "keyPath": write_secret(f"{name}.key", key_pem(key))}

        def cert_goto(page: Page, url: str):
            """goto with a client certificate: Playwright's TLS proxy may
            answer net::ERR_HTTP2_PROTOCOL_ERROR when it loses the race with
            the server's handshake (see tls_mtls_refuses_browser_cert); the
            same URL again in a new page of the same context is the control
            (every certificate here completes the handshake). Returns (page,
            response)."""
            for i in range(3):
                try:
                    return page, goto(page, url)
                except PWError as e:
                    if "net::ERR_HTTP2_PROTOCOL_ERROR" not in str(e) or i == 2:
                        raise
                    print(f"    {url}: {str(e).splitlines()[0]} — again in a new page", flush=True)
                    page = page.context.new_page()

        def root_session(label: str, origins=None):
            """root signed in (YubiKey certificate, hub.<d>), then a context
            with that session presenting his certificate to `origins` (not
            auth.<d>) and his security key: (ctx, page, key)."""
            needs("root_creds")
            ctxa = new_context(client_cert=root_cert, origins=(AUTH, HUB))
            try:
                pa = ctxa.new_page()  # no authenticator: the certificate signs in (amr mtls)
                goto(pa, HUB + "/")
                out = drive_kc(pa, lambda: landed(pa, HUB), f"{label}-root")
                assert out == "done", f"{label}: root's sign-in: {out} at {pa.url.split('?')[0]}"
                storage = ctxa.storage_state()
            finally:
                ctxa.close()
            ctx = new_context(client_cert=root_cert, storage_state=storage,
                              origins=origins or (HUB, PEOPLE, MAIN, ECHO_STD, ECHO_CERT, ECHO_FILE))
            page = ctx.new_page()
            key = Key(page, credentials=state["root_creds"])
            return ctx, page, key

        def imp_post(caller: str, target: str, body_: dict, token: str = "") -> tuple[int, str]:
            """The start route on the Hub listener; a refusal's audited
            detail (the Hub's reason, never a proof value) is printed."""
            headers = {"X-Forwarded-Access-Token": token} if token else {}
            code, out = hub_as(caller, "POST", f"/api/directory/users/{target}/impersonation", body_, headers=headers)
            if code != 200:
                last = sorted((e for e in audit_entries("impersonation.start") if e.get("result") == "refused"
                               and e.get("actor") == caller and e.get("target") == target),
                              key=lambda e: str(e.get("time") or e.get("at") or ""))[-1:]
                print(f"    start {caller} → {target} refused (HTTP {code}); audit: {[e.get('detail') for e in last]}", flush=True)
            return code, out

        def imp_begin(page: Page, label: str, caller: str = "root", target: str = "alice") -> dict:
            """The fresh sign-in in page, then the start: {id, next, until}."""
            tok = access_token(page)
            assert tok, f"{label}: no access token for {caller}"
            proof = fresh_code(page, f"{label}-fresh", HUB + "/")
            code, out = imp_post(caller, target, dict(proof, reason=IMP_REASON), tok)
            assert code == 200, f"{label}: start {caller} → {target}: HTTP {code} {out[:300]}"
            doc = json.loads(out)
            assert re.fullmatch(r"[0-9a-f]{32}", doc["id"]), doc
            assert doc["next"] == f"{REALM}/portcullis-impersonate/start?id={doc['id']}", doc["next"]
            imp_t0[doc["id"]] = time.time()
            return doc

        def imp_open(page: Page, doc: dict, label: str) -> None:
            goto(page, doc["next"])
            page.wait_for_url(re.compile("^" + re.escape(PORTAL)), timeout=TIMEOUT_MS)
            page.wait_for_load_state("domcontentloaded")
            base.shot(page, f"{label}-portal")
            assert "alice" in body(page) and IMP_BANNER in body(page), f"{label}: portal: {body(page)[:300]!r}"

        def imp_stop_admin(target: str = "alice") -> int:
            code, _ = hub("POST", f"/api/directory/users/{target}/impersonation/stop", {})
            return code

        def imp_elapsed(imp_id: str) -> str:
            return f"{time.time() - imp_t0.get(imp_id, time.time()):.0f} s after the start"

        def ended_page(page: Page, url: str) -> bool:
            resp = goto(page, url)
            return resp is not None and resp.status == 403 and page.locator("#impersonation-ended").count() == 1

        def no_imp_session(user: str, sids: set) -> bool:
            return not (session_ids(user) & sids)

        def imp_stock_endpoint_off():
            uid = kc_user_id("alice")
            assert uid, "alice isn't in Keycloak"
            try:
                kc(f"/users/{uid}/impersonation", "POST")
                raise AssertionError("Keycloak's own impersonation endpoint answered 2xx")
            except urllib.error.HTTPError as e:
                print(f"    POST /admin/realms/portcullis/users/<alice>/impersonation: HTTP {e.code}", flush=True)
                assert e.code >= 300, e.code
        check("imp_stock_endpoint_off: Keycloak's own admin impersonation endpoint answers non-2xx "
              "(--features-disabled=impersonation)", imp_stock_endpoint_off)

        def imp_setup():
            # The CI AI client and People MCP (imp_ai_refused): AI on, Claude Code offered.
            v = hub_ok("PUT", "/api/ai/settings", {"enabled": True,
                                                    "clients": {"claude_code": {"offered": True, "admin": True}}})
            assert v.get("enabled") is True and v.get("gate_present") is True, f"AI settings: {json.dumps(v)[:400]}"
            state["ai_on"] = True
            view = hub_ok("GET", "/api/impersonations")
            print(f"    impersonations: allowed {view.get('allowed')} max_minutes {view.get('max_minutes')} "
                  f"running {len(view.get('running') or [])}", flush=True)
            assert view.get("allowed") is True and view.get("max_minutes") == 2 and not view.get("running"), view
            # A YubiKey certificate of alice's own (F16, below): her sign-ins
            # here, and imp_call5's "the person's certificate never counts".
            # carol's remove-passkeys (sign_in_help_actions) left alice the
            # passkey registration action: a start on her is refused (rule 6)
            # until she finishes it (below).
            uid = kc_user_id("alice")
            actions = kc(f"/users/{uid}").get("requiredActions") or []
            print(f"    alice's required actions: {actions}", flush=True)
            if actions:
                code, out = imp_post("root", "alice", {"reason": IMP_REASON, "code": "x", "code_verifier": "x", "nonce": "x"})
                print(f"    a start on alice with {actions}: HTTP {code} {out.strip()[:100]!r}", flush=True)
                assert code == 409 and "unfinished sign-in step" in out, f"HTTP {code} {out[:200]}"
            # alice signs in with her certificate and finishes the action (a
            # new security key: an AI token counts no certificate method).
            cert, key = vault_issue("alice")
            state["imp_alice_cert"] = cert_files(cert, key, "alice-imp-yk")
            ctx = new_context(client_cert=state["imp_alice_cert"], origins=(AUTH, ECHO_CERT))
            try:
                page = ctx.new_page()
                akey = Key(page)
                goto(page, ECHO_CERT + "/")
                base.passkey_flow(page, until=ECHO_CERT, label="alice-imp-register", expect_stepups=0)
                assert akey.registered == (1 if actions else 0), f"alice registered {akey.registered} passkeys"
                creds = akey.credentials()
            finally:
                ctx.close()
            assert not (kc(f"/users/{uid}").get("requiredActions") or []), "alice's required actions stay"
            assert creds, "alice has no passkey"
            state["alice_imp_creds"] = creds
            # A token for alice's People MCP, minted before any start.
            ctx = new_context()
            try:
                Key(ctx.new_page(), credentials=state["alice_imp_creds"])
                until(f"{PEOPLE_MCP}'s metadata served", lambda: ctx.request.get(
                    PEOPLE + "/.well-known/oauth-protected-resource/mcp").status == 200, 120)
                tf = mcp_login(ctx.pages[0], PEOPLE_MCP, PEOPLE_SCOPE, "alice-people-mcp")
            finally:
                ctx.close()
            rc, doc = mcp_tools_list(PEOPLE_MCP, tf)
            names = [t.get("name") for t in ((doc.get("result") or {}).get("tools") or [])]
            print(f"    alice's People MCP before the start: rc {rc}, {len(names)} tools", flush=True)
            assert rc == 0 and names, f"alice's People MCP token: {json.dumps(doc)[:300]}"
            state["alice_ai_tf"] = tf
        check("imp_setup: AI on (Claude Code offered); signing in as someone else allowed, max 2 minutes, none "
              "running; alice's People MCP token minted before any start answers tools/list", imp_setup)

        def imp_start():
            # root's earlier sessions out: then his one session ends at the start.
            kc(f"/users/{kc_user_id('root')}/logout", "POST")
            until("root has no Keycloak session", lambda: kc_sessions("root") == [], 20, every=2)
            ctx, page, key = root_session("imp1")
            try:
                before = token_claims(page)
                amr0 = before.get("amr") or []
                assert before.get("preferred_username") == "root" and "mtls" in amr0, f"root's session: {before.get('preferred_username')} {amr0}"
                root_sids = session_ids("root")
                assert len(root_sids) == 1, f"root's sessions: {root_sids}"
                (root_sid,) = root_sids
                alice0 = session_ids("alice")
                asserted = key.asserted
                proof = fresh_code(page, "imp1-fresh", HUB + "/")
                assert key.asserted > asserted, "the fresh sign-in asked no security key"
                # F39: the proof's session is still root's one session.
                assert session_ids("root") == {root_sid}, f"root's session changed across prompt=login: {session_ids('root')}"
                # Keycloak keeps only the fresh sign-in's methods in the
                # session after prompt=login (run 43174939742: mtls before,
                # the impersonation hwk alone; run 43183771383 read the
                # session's amr with one more fresh-auth authorize here,
                # ['hwk'] — which also replaced the proof's client session, so
                # its code then failed: no authorize between the proof and
                # the start any more), so root then steps up to his
                # YubiKey certificate (step-ups accumulate) so the session
                # has both for imp_call5.
                ctxc = new_context(client_cert=root_cert, storage_state=ctx.storage_state(),
                                   origins=(AUTH, HUB, PEOPLE, MAIN, ECHO_STD, ECHO_CERT, ECHO_FILE))
                ctx.close()
                ctx = ctxc
                page = ctx.new_page()
                key = Key(page, credentials=state["root_creds"])
                goto(page, f"{AUTH}/oauth2/start?" + urllib.parse.urlencode({"pc_method": "yubikey_cert", "rd": HUB + "/"}))
                out = drive_kc(page, lambda: landed(page, HUB), "imp1-stepup-cert")
                assert out == "done", f"root's step-up to yubikey_cert: {out} at {page.url.split('?')[0]}"
                amr0 = token_claims(page).get("amr") or []
                assert {"mtls", "hwk"} <= set(amr0), f"root's amr after the step-up: {amr0}"
                assert session_ids("root") == {root_sid}, f"root's session changed across the step-up: {session_ids('root')}"
                code, out = imp_post("root", "alice", dict(proof, reason=IMP_REASON), access_token(page))
                assert code == 200, f"start root → alice: HTTP {code} {out[:300]}"
                doc = json.loads(out)
                assert doc["next"] == f"{REALM}/portcullis-impersonate/start?id={doc['id']}", doc["next"]
                imp_t0[doc["id"]] = time.time()
                starts = [e for e in audit_entries("impersonation.start") if (e.get("detail") or "").startswith(doc["id"])]
                print(f"    start: {[(e.get('actor'), e.get('target'), e.get('result'), e.get('detail')) for e in starts]}", flush=True)
                assert len(starts) == 1 and starts[0].get("result") == "ok" and starts[0].get("actor") == "root" \
                    and starts[0].get("target") == "alice" and starts[0]["detail"] == f"{doc['id']} · security_key · {IMP_REASON}", starts
                imp_open(page, doc, "imp1")
                c = token_claims(page)
                amr = c.get("amr") or []
                print(f"    root's amr before {amr0}, as alice {amr}; act {c.get('act')}", flush=True)
                assert c.get("preferred_username") == "alice", c.get("preferred_username")
                assert c.get("act") == {"sub": "root"}, c.get("act")
                assert (c.get("pc_imp") or {}).get("id") == doc["id"], c.get("pc_imp")
                assert set(amr) == set(amr0) | {"hwk"}, f"amr {amr} (root's {amr0} + hwk)"
                assert IMP_REASON not in json.dumps(c), "the reason in the token"
                until("root's Keycloak session is gone", lambda: kc_sessions("root") == [], 10, every=1)
                new = session_ids("alice") - alice0
                assert len(new) == 1, f"alice's new sessions: {new}"
                ev = [e for e in kc_events("alice", "IMPERSONATE") if (e.get("details") or {}).get("pc_imp") == doc["id"]]
                assert len(ev) == 1 and ev[0]["details"].get("pc_act") == "root", f"IMPERSONATE events: {ev}"
                state["imp1"] = {"ctx": ctx, "page": page, "key": key, "doc": doc, "sids": new}
            except Exception:
                ctx.close()
                raise
        check("imp_start: root's fresh security-key sign-in + reason → the start (audited, security_key); next lands "
              "root's browser on the portal as alice: preferred_username alice, act.sub root, pc_imp.id, amr = root's + "
              "hwk; root has no Keycloak session, alice one more (IMPERSONATE pc_act root)", imp_start)

        def imp_banner_everywhere():
            needs("imp1")
            imp = state["imp1"]
            page = imp["page"]
            goto(page, PORTAL)
            html_ = page.content()
            assert IMP_BANNER in body(page) and "min left" in body(page), f"portal: {body(page)[:300]!r}"
            assert page.locator("#pc-imp-banner #pc-imp-stop").count() == 1, "no Stop on the portal's banner"
            assert "/impersonation/stop" in html_, "the portal's Stop doesn't lead to the Stop page"
            for path in ("/", "/signin"):
                goto(page, PEOPLE + path)
                page.wait_for_selector("#pc-imp-banner", timeout=15_000)
                text = page.inner_text("#pc-imp-banner")
                base.shot(page, f"imp1-people{path.replace('/', '-')}")
                assert IMP_BANNER in text and "min left" in text and "Stop" in text, f"people.<d>{path}: {text!r}"
                assert page.locator("#pc-imp-banner button, #pc-imp-banner a").count() >= 1, f"people.<d>{path}: no Stop"
            # group-gate's needs page: echo-file (any[browser_cert]), root's session can't meet it.
            page, resp = cert_goto(page, ECHO_FILE + "/")
            imp["page"] = page
            base.shot(page, "imp1-needs")
            assert resp and resp.status == 403, f"echo-file: HTTP {resp and resp.status}"
            assert page.locator("#needs-stronger[data-impersonated=true]").count() == 1, body(page)[:300]
            assert IMP_BANNER in body(page) and "min left" in body(page), body(page)[:300]
            assert page.locator("#pc-imp-stop").count() == 1 and page.locator("#stepup-continue").count() == 0
            assert "x-stepup-url" not in resp.headers, resp.headers.get("x-stepup-url")
            # The extension's page: a client not in the file's clients (the Hub's fresh-auth).
            rd = Redirect(page, HUB + "/")
            resp = goto(page, authorize_url("portcullis-fresh-auth", HUB + "/", code_challenge="x" * 43,
                                            code_challenge_method="S256"))
            base.shot(page, "imp1-kc-refused")
            assert resp and resp.status == 403 and page.locator("#impersonating[data-mode=refused]").count() == 1, \
                f"fresh-auth while impersonating: HTTP {resp and resp.status} {body(page)[:200]!r}"
            text = page.inner_text("#portcullis-impersonation-banner")
            assert IMP_BANNER in text and "min left" in text, text
            assert page.locator("#portcullis-impersonation-stop-banner, #portcullis-impersonation-stop").count() >= 1
            assert rd.code() is None, "fresh-auth issued a code while impersonating"
            print(f"    banners checked {imp_elapsed(imp['doc']['id'])}", flush=True)
        check("imp_banner_everywhere: \"You are signed in as alice (by root) · reason “checking quota” · … min left\" "
              "with Stop on the portal, people.<d>/ and /signin (impersonation.js), group-gate's needs page (echo-file; "
              "no step-up, no X-Stepup-URL) and the extension's page (fresh-auth refused, no code)", imp_banner_everywhere)

        def imp_call5():
            needs("imp1", "imp_alice_cert")
            imp = state["imp1"]
            imp_id = imp["doc"]["id"]
            page, resp = cert_goto(imp["page"], ECHO_CERT + "/")
            imp["page"] = page
            assert resp and resp.status == 200, f"echo-cert with root's certificate: HTTP {resp and resp.status}"
            seen = headers_of(body(page))
            assert seen.get("x-forwarded-user") == ["alice"], seen.get("x-forwarded-user")
            assert seen.get("x-forwarded-impersonator") == ["root"] and seen.get("x-forwarded-impersonation") == [imp_id], \
                (seen.get("x-forwarded-impersonator"), seen.get("x-forwarded-impersonation"))
            # Client-sent copies: Traefik deletes them, the app sees group-gate's only.
            r = page.request.get(ECHO_CERT + "/", headers={"X-Forwarded-Impersonator": "sam",
                                                           "X-Forwarded-Impersonation": "0" * 32})
            seen = headers_of(r.text())
            assert r.status == 200 and seen.get("x-forwarded-impersonator") == ["root"] \
                and seen.get("x-forwarded-impersonation") == [imp_id], \
                f"forged headers: HTTP {r.status} {seen.get('x-forwarded-impersonator')} {seen.get('x-forwarded-impersonation')}"
            # alice's own YubiKey certificate in the same session: never counts.
            ctx = new_context(client_cert=state["imp_alice_cert"], origins=(ECHO_CERT,),
                              storage_state=imp["ctx"].storage_state())
            try:
                pc, resp = cert_goto(ctx.new_page(), ECHO_CERT + "/")
                base.shot(pc, "imp1-alice-cert")
                assert resp and resp.status == 403, f"echo-cert with alice's certificate: HTTP {resp and resp.status}"
                assert pc.locator("#needs-stronger[data-impersonated=true]").count() == 1, body(pc)[:300]
                assert "x-stepup-url" not in resp.headers and pc.locator("#stepup-continue, #present-certificate").count() == 0
                assert "Hostname" not in body(pc), "echo-cert opened with alice's certificate"
            finally:
                ctx.close()
            # Strong: people.<d> (core, Strong) opened above; a native-OIDC app on Strong, with pc_act.
            print(f"    alice's own methods: {people_methods('alice')}", flush=True)
            rd = Redirect(page, OIDC_STRONG + "/cb")
            t0 = int(time.time() * 1000) - 2000
            goto(page, authorize_url("oidc-strong", OIDC_STRONG + "/cb"))
            out = drive_kc(page, lambda: rd.code() is not None, "imp1-oidc-strong", seconds=30)
            assert out == "done", f"oidc-strong: {out}"
            tok = exchange(page, "oidc-strong", OIDC_STRONG + "/cb", rd.code(), secret=oidc_secret("oidc-strong"))
            c = claims_of(tok["id_token"])
            assert c.get("preferred_username") == "alice" and c.get("act") == {"sub": "root"} \
                and (c.get("pc_imp") or {}).get("id") == imp_id, (c.get("preferred_username"), c.get("act"), c.get("pc_imp"))
            assert tok.get("refresh_token"), "oidc-strong got no refresh token"
            imp["refresh"] = tok["refresh_token"]
            logins = until("oidc-strong's LOGIN with pc_act root", lambda: [
                e for e in kc_events("alice", "LOGIN", client="oidc-strong")
                if e.get("time", 0) >= t0 and (e.get("details") or {}).get("pc_act") == "root"], 20, every=2)
            print(f"    oidc-strong LOGIN details: {logins[0].get('details')}; {imp_elapsed(imp_id)}", flush=True)
        check("imp_call5: echo-cert (any[yubikey_cert]) opens with root's YubiKey certificate (X-Forwarded-Impersonator "
              "root / -Impersonation id; forged copies deleted); with alice's own certificate the impersonation needs "
              "page, no step-up; oidc-strong (Strong) issues alice's tokens with act root, its LOGIN has pc_act root",
              imp_call5)

        def imp_people_read_only():
            needs("imp1")
            page = state["imp1"]["page"]
            for method, path, body_ in (("PUT", "/api/me/signin/password", {}),
                                        ("POST", "/api/me/signin/browser-certificates", {"days": 1}),
                                        ("DELETE", "/api/me/ai/connections/x", None)):
                r = people_req(page, method, path, body_)
                print(f"    {method} {path}: HTTP {r.status} {r.text().strip()[:80]!r}", flush=True)
                assert r.status == 403 and READ_ONLY in r.text(), f"{method} {path}: HTTP {r.status} {r.text()[:200]}"
                # Control: alice herself (no impersonation header) isn't refused that way.
                code, out = people_as("alice", method, path, body_)
                assert READ_ONLY not in out, f"control {method} {path} as alice: HTTP {code} {out[:200]}"
            r = people_req(page, "GET", "/api/me/apps")
            assert r.status == 200, f"GET /api/me/apps: HTTP {r.status}"
            r = people_req(page, "GET", "/api/me/impersonation")
            active = r.json().get("active") or {}
            assert active.get("person") == "alice" and active.get("admin") == "root" and active.get("reason") == IMP_REASON, active
        check("imp_people_read_only: while impersonated PUT /api/me/signin/password, POST /api/me/signin/browser-"
              "certificates, DELETE /api/me/ai/connections/x → 403 \"not while you are signed in as someone else: Stop "
              "first\" (alice herself: not that refusal); GET /api/me/apps 200", imp_people_read_only)

        def imp_ai_refused():
            needs("imp1", "alice_ai_tf")
            page = state["imp1"]["page"]
            rd = Redirect(page, AI_CALLBACK)
            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            resp = goto(page, authorize_url(AI_CLIENT, AI_CALLBACK, scope=f"openid {PEOPLE_SCOPE}", resource=PEOPLE_MCP,
                                            code_challenge=challenge, code_challenge_method="S256"))
            page.wait_for_timeout(1000)
            base.shot(page, "imp1-ai-authorize")
            assert page.locator("#impersonating").count() == 1, f"the AI client's authorize: {page.url.split('?')[0]} {body(page)[:200]!r}"
            assert resp and resp.status == 403, f"HTTP {resp and resp.status}"
            assert IMP_BANNER in body(page), body(page)[:300]
            assert rd.code() is None and not rd.urls, "a code for the AI client while impersonating"
            rc, doc = mcp_tools_list(PEOPLE_MCP, state["alice_ai_tf"])
            print(f"    alice's pre-start People MCP token during the impersonation: rc {rc}, "
                  f"{len((doc.get('result') or {}).get('tools') or [])} tools", flush=True)
            assert rc == 0 and (doc.get("result") or {}).get("tools"), f"alice's own token: {json.dumps(doc)[:300]}"
        check("imp_ai_refused: the CI AI client's authorize in the impersonating browser shows #impersonating (403, "
              "banner), no code; alice's People MCP token minted before the start still works", imp_ai_refused)

        def imp_refused_concurrent():
            needs("imp1")
            body_ = {"reason": IMP_REASON, "code": "x", "code_verifier": "x", "nonce": "x"}
            code, out = imp_post("root", "pat", body_)
            print(f"    root → pat while root runs one: HTTP {code} {out.strip()[:100]!r}", flush=True)
            assert code == 409 and "Stop it first" in out, f"HTTP {code} {out[:200]}"
            code, out = imp_post("sam", "alice", body_)
            print(f"    sam → alice while root runs one: HTTP {code} {out.strip()[:100]!r}", flush=True)
            assert code == 409 and "root is signed in as alice right now" in out, f"HTTP {code} {out[:200]}"
            # The used next once more in root's (now alice's) browser: refused, no new session.
            imp = state["imp1"]
            before = session_ids("alice")
            resp = goto(imp["page"], imp["doc"]["next"])
            base.shot(imp["page"], "imp1-next-again")
            assert resp and resp.status == 403 and imp["page"].locator("#impersonating[data-mode=refused]").count() == 1, \
                f"next again: HTTP {resp and resp.status} {body(imp['page'])[:200]!r}"
            assert session_ids("alice") == before, f"alice's sessions changed: {before} → {session_ids('alice')}"
            print(f"    {imp_elapsed(imp['doc']['id'])}", flush=True)
        check("imp_refused_concurrent + imp_next_bound (reuse): a second start by root → 409 \"Stop it first\", sam on "
              "alice → 409 \"root is signed in as alice right now\"; the used next again → 403 page, no session",
              imp_refused_concurrent)

        def imp_stop():
            needs("imp1")
            imp = state.pop("imp1")
            ctx, page, doc = imp["ctx"], imp["page"], imp["doc"]
            try:
                old = next(c["value"] for c in ctx.cookies(AUTH) if c["name"] == "_oauth2_proxy")
                code, _ = raw_request(f"echo-std.{DOMAIN}", "/", f"_oauth2_proxy={old}")
                assert code == 200, f"control: the session's cookie on echo-std before Stop: HTTP {code}"
                print(f"    Stop pressed {imp_elapsed(doc['id'])}", flush=True)
                seen: list = []
                page.on("request", lambda r: seen.append((r.method, r.url.split("?")[0])))
                goto(page, PORTAL)
                page.click("#pc-imp-stop")
                page.wait_for_url(re.compile("^" + re.escape(PEOPLE + "/impersonation/stop")), timeout=TIMEOUT_MS)
                btn = page.get_by_role("button", name="Stop signing in as alice")
                btn.wait_for(timeout=15_000)
                base.shot(page, "imp1-stop-page")
                btn.click()
                # (Playwright delivers the request events only inside its own
                # calls: hence the wait_for_timeout.)
                until("/oauth2/sign_out after Stop", lambda: page.wait_for_timeout(500) or
                      any(u == AUTH + "/oauth2/sign_out" for _, u in seen), 20, every=0.5)
                # Then the sign-in: this browser presents root's YubiKey
                # certificate to auth.<d> (imp_start's step-up), so Keycloak's
                # X.509 step signs root himself in again and the portal opens
                # as root (run 43234690407); without it, the sign-in page.

                def after_stop():
                    page.wait_for_load_state("domcontentloaded")
                    if page.url.startswith(REALM + "/"):
                        return page.locator("#authenticateWebAuthnButton").count() == 1 and "sign-in page"
                    if page.url.startswith(PORTAL) and "Signed in as" in body(page):
                        return "portal as root"
                    return None
                landing = until("the sign-in after Stop", after_stop, 30, every=1)
                base.shot(page, "imp1-after-stop")
                text = body(page)
                print(f"    after Stop: {landing}", flush=True)
                assert ("POST", PEOPLE + "/api/me/impersonation/stop") in seen, [u for _, u in seen][-10:]
                assert IMP_BANNER not in text and "Your session as alice" not in text, text[:200]
                if landing == "portal as root":
                    c = token_claims(page)
                    assert c.get("preferred_username") == "root" and "act" not in c and "pc_imp" not in c, \
                        f"after Stop: {c.get('preferred_username')} act {c.get('act')} pc_imp {c.get('pc_imp')}"
                    assert "Signed in as <strong>root</strong>" in page.content(), text[:200]
                until("alice's impersonated Keycloak session gone", lambda: no_imp_session("alice", imp["sids"]), 20, every=2)
                code, _ = raw_request(f"echo-std.{DOMAIN}", "/", f"_oauth2_proxy={old}")
                print(f"    the old _oauth2_proxy cookie on echo-std after Stop: HTTP {code}", flush=True)
                assert code in (302, 401, 403), f"the old cookie after Stop: HTTP {code}"
                r = page.request.post(f"{REALM}/protocol/openid-connect/token", form={
                    "grant_type": "refresh_token", "client_id": "oidc-strong", "client_secret": oidc_secret("oidc-strong"),
                    "refresh_token": imp["refresh"]})
                assert r.status == 400 and r.json().get("error") == "invalid_grant", f"refresh after Stop: HTTP {r.status} {r.text()[:200]}"
            finally:
                ctx.close()
            start = [e for e in audit_entries("impersonation.start") if (e.get("detail") or "").startswith(doc["id"])]
            assert start and IMP_REASON in start[0]["detail"], start

            def ended():
                e = [x for x in audit_entries("impersonation.end") if (x.get("detail") or "").startswith(doc["id"])]
                return e and e[0]
            end = until("impersonation.end in the audit", ended, 60, every=3)
            print(f"    end: {end.get('actor')} {end.get('detail')!r}", flush=True)
            assert end.get("actor") == "root" and re.fullmatch(
                re.escape(doc["id"]) + r" · stopped · \d+ min · apps opened: (?!none).+", end["detail"]), end

            def entry():
                h = people_json("alice", "GET", "/api/me/signin/history?limit=100")["entries"]
                got = [e for e in h if e["kind"] == "impersonation" and e.get("by") == "root" and e.get("reason") == IMP_REASON
                       and "stopped by root" in (e.get("detail") or "")]
                return got and got[0]
            e = until("alice's history has the impersonation entry", entry, 60, every=3)
            print(f"    history: {e.get('detail')!r}", flush=True)
            assert "apps opened:" in e["detail"] and "apps opened: none" not in e["detail"], e["detail"]
            state["imp1_done"] = doc
        check("imp_stop: Stop on the portal → the Stop page POSTs, /oauth2/sign_out, the sign-in page; within 20 s alice "
              "has no impersonated Keycloak session; the old _oauth2_proxy cookie (200 before) isn't 200; oidc-strong's "
              "refresh token invalid_grant; audit start (reason) and end \"stopped\" by root with the apps; alice's "
              "history has the impersonation entry by root with the reason and the apps", imp_stop)

        def imp_notice_next_signin():
            needs("imp1_done", "imp_alice_cert")
            uid = kc_user_id("alice")
            until("alice has the notice action", lambda: "portcullis-impersonation-notice" in
                  (kc(f"/users/{uid}").get("requiredActions") or []), 60, every=3)
            ctx = new_context(client_cert=state["imp_alice_cert"], origins=(AUTH, ECHO_CERT))
            try:
                page = ctx.new_page()
                goto(page, ECHO_CERT + "/")
                page.wait_for_selector("#portcullis-impersonation-notice", timeout=TIMEOUT_MS)
                base.shot(page, "alice-notice")
                lines = [x.strip() for x in page.locator(".portcullis-notice-line").all_inner_texts()]
                print(f"    notice: {lines}", flush=True)
                assert len(lines) == 1 and re.match(
                    r"root signed in as you on \d{1,2} [A-Z][a-z]{2} \d{4} \d\d:\d\d UTC for \d+ min: checking quota\. "
                    r"Apps opened: (?!none)", lines[0]), lines
                page.click("#portcullis-notice-continue")
                page.wait_for_url(re.compile("^" + re.escape(ECHO_CERT) + "/"), timeout=TIMEOUT_MS)
                until("echo-cert opened for alice", lambda: "Hostname" in body(page), 20, every=1)
                assert headers_of(body(page)).get("x-forwarded-user") == ["alice"]
                # Her own session: forged impersonation headers don't reach the app.
                r = page.request.get(ECHO_CERT + "/", headers={"X-Forwarded-Impersonator": "root",
                                                               "X-Forwarded-Impersonation": "0" * 32})
                seen = headers_of(r.text())
                assert r.status == 200 and "x-forwarded-impersonator" not in seen and "x-forwarded-impersonation" not in seen, \
                    f"forged headers on alice's own session: {seen.get('x-forwarded-impersonator')} {seen.get('x-forwarded-impersonation')}"
                c = token_claims(page)
                assert "act" not in c and "pc_imp" not in c, "alice's own token has act / pc_imp"
            finally:
                ctx.close()
            assert "portcullis-impersonation-notice" not in (kc(f"/users/{uid}").get("requiredActions") or [])
            ctx = new_context(client_cert=state["imp_alice_cert"], origins=(AUTH, ECHO_CERT))
            try:
                page = ctx.new_page()
                shown: list = []
                page.on("request", lambda r: shown.append(r.url) if "portcullis-impersonation-notice" in r.url else None)
                goto(page, ECHO_CERT + "/")
                page.wait_for_url(re.compile("^" + re.escape(ECHO_CERT) + "/"), timeout=TIMEOUT_MS)
                until("echo-cert opened for alice again", lambda: "Hostname" in body(page), 20, every=1)
                assert not shown and page.locator("#portcullis-impersonation-notice").count() == 0, "the notice again"
            finally:
                ctx.close()
        check("imp_notice_next_signin: alice's own next sign-in shows \"root signed in as you on … UTC for … min: "
              "checking quota. Apps opened: …\" once; Continue reaches echo-cert (forged impersonation headers deleted on "
              "her own session); her next sign-in shows no notice", imp_notice_next_signin)

        def imp_stop_elsewhere():
            ctx, page, _ = root_session("imp2")
            try:
                doc = imp_begin(page, "imp2")
                before = session_ids("alice")
                imp_open(page, doc, "imp2")
                sids = session_ids("alice") - before
                err, text = hub_mcp_admin("sam", "stop_impersonation", {"user": "alice"})
                print(f"    sam's stop_impersonation: isError {err}: {text[:120]!r}", flush=True)
                assert not err, text[:300]
                t0 = time.time()
                until("root's browser gets the ended page", lambda: ended_page(page, ECHO_STD + "/"), 5, every=1)
                print(f"    ended page {time.time() - t0:.1f} s after the stop", flush=True)
                base.shot(page, "imp2-ended")
                until("alice's impersonated Keycloak session gone", lambda: no_imp_session("alice", sids), 20, every=2)
                end = until("impersonation.end by sam", lambda: [x for x in audit_entries("impersonation.end")
                                                                 if (x.get("detail") or "").startswith(doc["id"] + " · stopped")], 30)
                assert end[0].get("actor") == "sam", end
            finally:
                ctx.close()
                imp_stop_admin()
        check("imp_stop_elsewhere: sam's stop_impersonation {user: alice} (Hub MCP) ends it; root's browser gets "
              "group-gate's ended page within 5 s; Keycloak's session gone; audited stopped by sam", imp_stop_elsewhere)

        def imp_switch_off():
            body_ = {"reason": IMP_REASON, "code": "x", "code_verifier": "x", "nonce": "x"}
            # The switch off ends a running one, and refuses a start.
            ctx, page, _ = root_session("imp3")
            switched = False
            try:
                doc = imp_begin(page, "imp3")
                before = session_ids("alice")
                imp_open(page, doc, "imp3")
                sids = session_ids("alice") - before
                v = hub_ok("PUT", "/api/signin/impersonation", {"allowed": False})
                switched = True
                assert v.get("allowed") is False, v
                until("root's browser gets the ended page", lambda: ended_page(page, ECHO_STD + "/"), 10, every=1)
                until("alice's impersonated Keycloak session gone", lambda: no_imp_session("alice", sids), 20, every=2)
                code, out = imp_post("root", "alice", body_)
                assert code == 409 and "switched off" in out, f"start while off: HTTP {code} {out[:200]}"
                recent = {x["id"]: x for x in hub_ok("GET", "/api/impersonations").get("recent") or []}
                assert recent.get(doc["id"], {}).get("how") == "switched_off", recent.get(doc["id"])
            finally:
                ctx.close()
                if switched:
                    hub_ok("PUT", "/api/signin/impersonation", {"allowed": True})
                imp_stop_admin()
        check("imp_refused_targets (switch): the switch off ends the running one (ended page, Keycloak's session "
              "gone, how switched_off) and a start → 409; switched back on", imp_switch_off)

        def imp_next_bound():
            needs("root_creds")
            bctx = new_context(client_cert=bob_cert, origins=(AUTH, MAIN))
            ctx, page, _ = root_session("imp4")
            try:
                bpage = bctx.new_page()
                goto(bpage, PORTAL)
                assert drive_kc(bpage, lambda: landed(bpage, MAIN), "imp4-bob") == "done"
                bob0 = session_ids("bob")
                assert bob0, "bob has no Keycloak session"
                doc = imp_begin(page, "imp4")
                alice0 = session_ids("alice")
                resp = goto(bpage, doc["next"])
                base.shot(bpage, "imp4-bob-next")
                assert resp and resp.status == 403 and bpage.locator("#impersonating[data-mode=refused]").count() == 1, \
                    f"next in bob's browser: HTTP {resp and resp.status} {body(bpage)[:200]!r}"
                assert session_ids("bob") == bob0, f"bob's sessions: {bob0} → {session_ids('bob')}"
                goto(bpage, PORTAL)
                assert landed(bpage, MAIN) and "bob" in body(bpage), f"bob's session after: {bpage.url.split('?')[0]}"
                assert session_ids("alice") == alice0, "alice got a session"
            finally:
                bctx.close()
                ctx.close()
                imp_stop_admin()
        check("imp_next_bound: next opened in bob's signed-in browser → 403 page, bob's session intact, alice none",
              imp_next_bound)

        # Last, in parallel: the expiry (root as alice, max 2 minutes) and a
        # start whose next is opened after 125 s (sam as pat: root runs the
        # other one, and alice is taken).
        def imp_expiry_and_late_next():
            needs("sam_spare")
            ctx, page, _ = root_session("imp5")
            sctx = new_context()
            try:
                doc = imp_begin(page, "imp5")
                before = session_ids("alice")
                imp_open(page, doc, "imp5")
                sids = session_ids("alice") - before
                spage = sctx.new_page()
                Key(spage, credentials=state["sam_spare"])
                goto(spage, HUB + "/")
                assert drive_kc(spage, lambda: landed(spage, HUB), "imp6-sam") == "done"
                late = imp_begin(spage, "imp6", caller="sam", target="pat")
                pat0 = session_ids("pat")
                t_exp, t_late = imp_t0[doc["id"]] + 130, imp_t0[late["id"]] + 125
                errors = []
                for at, what in sorted([(t_exp, "expiry"), (t_late, "late")]):
                    time.sleep(max(0, at - time.time()))
                    try:
                        if what == "late":
                            resp = goto(spage, late["next"])
                            base.shot(spage, "imp6-late-next")
                            print(f"    sam's next after {time.time() - imp_t0[late['id']]:.0f} s: HTTP {resp and resp.status}", flush=True)
                            assert resp and resp.status == 403 and spage.locator("#impersonating[data-mode=refused]").count() == 1, \
                                f"late next: HTTP {resp and resp.status} {body(spage)[:200]!r}"
                            assert session_ids("pat") == pat0, "pat got a session"
                        else:
                            resp = goto(page, ECHO_STD + "/")
                            base.shot(page, "imp5-expired")
                            text = body(page)
                            # Ruling: group-gate's ended page, or (oauth2-proxy
                            # re-authorizes: the token's exp is until) Keycloak's
                            # sign-in page; never anything as alice.
                            gg = page.locator("#impersonation-ended").count() == 1
                            kce = page.locator("#impersonating[data-mode=ended]").count() == 1
                            signin = page.url.startswith(REALM + "/") and page.locator("#authenticateWebAuthnButton").count() == 1
                            print(f"    {time.time() - imp_t0[doc['id']]:.0f} s after the start: HTTP {resp and resp.status} at "
                                  f"{page.url.split('?')[0]} (group-gate ended {gg}, Keycloak ended {kce}, sign-in page {signin})",
                                  flush=True)
                            assert "Hostname" not in text and "alice" not in text.replace("as alice has ended", ""), \
                                f"alice's data after the expiry: {text[:200]!r}"
                            assert gg or kce or signin, f"neither the ended page nor the sign-in page: {page.url.split('?')[0]} {text[:200]!r}"
                            until("alice's impersonated Keycloak session gone", lambda: no_imp_session("alice", sids), 20, every=2)
                    except Exception as e:  # noqa: BLE001
                        errors.append(f"{what}: {e}")
                end = until("impersonation.end expired", lambda: [x for x in audit_entries("impersonation.end")
                                                                  if (x.get("detail") or "").startswith(doc["id"] + " · expired")], 30)
                print(f"    end: {end[0].get('actor')} {end[0].get('detail')!r}", flush=True)
                assert end[0].get("actor") == "portcullis", end
                assert not errors, errors
            finally:
                ctx.close()
                sctx.close()
                imp_stop_admin()
                imp_stop_admin("pat")
        check("imp_expiry + imp_next_bound (late): after 2 min 10 s root's browser gets the ended page, within 20 s more "
              "Keycloak has no impersonated session, the audit has \"expired\" by portcullis; meanwhile sam's start "
              "opened after 125 s → 403 page, pat gets no session", imp_expiry_and_late_next)

        # The refusals last: every refused start counts toward the caller's
        # limit (10 a minute, then 429: run 43187789128), and root still
        # had starts to make before.
        def imp_refused_proofs():
            needs("sam_synced")
            # Reason first (rule 4, before the proof).
            code, out = imp_post("root", "alice", {"reason": "ab", "code": "x", "code_verifier": "x", "nonce": "x"})
            assert code == 400 and "type a reason" in out, f"reason ab: HTTP {code} {out[:200]}"

            def refused(caller: str, page: Page, proof: dict, what: str) -> None:
                code, out = imp_post(caller, "alice", dict(proof, reason=IMP_REASON), access_token(page))
                print(f"    {what}: HTTP {code} {out.strip()[:100]!r}", flush=True)
                assert code == 403 and "a fresh sign-in is required" in out, f"{what}: HTTP {code} {out[:200]}"
            alice0 = session_ids("alice")
            # sam's synced passkey.
            ctx = new_context()
            try:
                page = ctx.new_page()
                Key(page, synced=True, credentials=state["sam_synced"])
                goto(page, PORTAL)
                assert drive_kc(page, lambda: landed(page, MAIN), "imp-sam-synced") == "done"
                refused("sam", page, fresh_code(page, "imp-sam-synced-fresh", HUB + "/"), "sam's synced-passkey proof")
            finally:
                ctx.close()
            # root's browser certificate (created for this, revoked after).
            rctx, rpage, rkey = root_session("imp-rootbc")
            try:
                proof = fresh_code(rpage, "imp-root-bc-create", PEOPLE + "/signin")
                code, out = people_as("root", "POST", "/api/me/signin/browser-certificates", dict(proof, days=1))
                assert code == 200, f"root's browser certificate: HTTP {code} {out[:200]}"
                doc = json.loads(out)
                mask(doc["password"])
                state["imp_root_bc"] = doc["certificate"]["serial"]
                # No touch: the SSO cookie alone (no prompt=login) in root's own session.
                refused("root", rpage, fresh_code(rpage, "imp-root-sso", HUB + "/", fresh=False), "root's proof without a touch")
                # bob's proof (another person's) with root's session.
                bctx = new_context(client_cert=bob_cert, origins=(AUTH, MAIN))
                try:
                    bpage = bctx.new_page()
                    goto(bpage, PORTAL)
                    assert drive_kc(bpage, lambda: landed(bpage, MAIN), "imp-bob") == "done"
                    bob_proof = fresh_code(bpage, "imp-bob-fresh", HUB + "/")
                finally:
                    bctx.close()
                refused("root", rpage, bob_proof, "bob's proof with root's session")
            finally:
                rctx.close()
            pctx = new_context(client_cert={"pfx": base64.b64decode(doc["p12"]), "passphrase": doc["password"]},
                               origins=(AUTH, MAIN))
            try:
                ppage = pctx.new_page()
                goto(ppage, PORTAL)
                assert drive_kc(ppage, lambda: landed(ppage, MAIN), "imp-root-bc") == "done"
                assert "file" in (token_claims(ppage).get("amr") or []), token_claims(ppage).get("amr")
                refused("root", ppage, fresh_code(ppage, "imp-root-bc-fresh", HUB + "/"), "root's browser-certificate proof")
            finally:
                pctx.close()
            assert session_ids("alice") <= alice0, "alice got a session"
            assert not hub_ok("GET", "/api/impersonations").get("running"), "an impersonation runs"
            refusals = [e for e in audit_entries("impersonation.start") if e.get("result") == "refused"]
            assert len(refusals) >= 5, [(e.get("actor"), e.get("detail")) for e in refusals]
        check("imp_refused_proofs: sam's synced-passkey proof, root's proof without a touch (SSO), bob's proof with root's "
              "session and root's browser-certificate proof → 403 \"a fresh sign-in is required\"; reason \"ab\" → 400; "
              "nothing started, refusals audited", imp_refused_proofs)

        def imp_refused_targets():
            body_ = {"reason": IMP_REASON, "code": "x", "code_verifier": "x", "nonce": "x"}
            for target, want in (("root", "you can't sign in as yourself"), ("sam", "administrators can't be signed in as"),
                                 ("portcullis-hub", "this account can't be signed in as"),
                                 ("admin", "this account can't be signed in as")):
                code, out = imp_post("root", target, body_)
                print(f"    root → {target}: HTTP {code} {out.strip()[:80]!r}", flush=True)
                assert code == 409 and want in out, f"{target}: HTTP {code} {out[:200]}"
            needs("helped")  # carol holds sign_in_help (group hr)
            for listener in (HUB_API, PEOPLE_API):
                code, out = hub_as("carol", "POST", "/api/directory/users/alice/impersonation", body_, base_url=listener)
                assert code == 403, f"carol (sign_in_help) on {listener}: HTTP {code} {out[:200]}"
            view = people_json("carol", "GET", "/api/directory/users/alice/signin")
            assert view["can"].get("impersonate") is False and view.get("impersonation") is None, view["can"]

        check("imp_refused_targets: root on himself, on sam (an administrator), on portcullis-hub and admin → 409; carol "
              "(sign_in_help) → 403 on both listeners", imp_refused_targets)

        # Part 3's leftovers: root's browser certificate, AI off.
        if "imp_root_bc" in state:
            code, out = people_as("root", "DELETE", "/api/me/signin/certificates/" + urllib.parse.quote(state["imp_root_bc"], safe=""))
            print(f"    cleanup: root's browser certificate: HTTP {code}", flush=True)
        if state.get("ai_on"):
            code, out = hub("PUT", "/api/ai/settings", {"enabled": False})
            print(f"    cleanup: AI off: HTTP {code}", flush=True)

        # ── every passkey kind identified (test server 2026-11-12: a drifted
        # passwordless policy, conveyance none, registered a YubiKey as
        # synced; the job drifts it before any registration and expects
        # `keycloak configure` to restore direct). One credential of each
        # kind through a real setup link: rita with `./portcullis invite
        # --replace-keys` (security key), bob (synced) and pat (device-bound:
        # Chromium's virtual authenticators all share one AAGUID, so the
        # fixture names it passkey_device while pat registers) through the
        # Hub's setup link. ──
        KIND = {"security_key": ("portcullis-security-key", "hwk"), "passkey_device": ("portcullis-device-passkey", "dpk"),
                "passkey_synced": ("webauthn-passwordless", "spk")}

        def fixture_kind(kind: str) -> None:
            doc = json.loads(original_fixture)
            doc[AAGUID] = dict(doc[AAGUID], kind=kind)
            write_fixture(json.dumps(doc, indent=2).encode() + b"\n")
            kick()
            until(f"signin-keycloak.json lists the virtual key as {kind}",
                  lambda: (published()["authenticators"].get(AAGUID) or {}).get("kind") == kind, 90)

        def hub_setup_link(user: str) -> str:
            code, out = hub("POST", f"/api/directory/users/{user}/invite", {})
            m = SETUP_LINK.search(json.dumps(out) if not isinstance(out, str) else out)
            if m:
                mask(m.group(0))
            assert code == 200 and m, f"the Hub's setup link for {user}: HTTP {code} {redact(str(out))[:200]}"
            raw = (out.get("url") if isinstance(out, dict) else None) or m.group(0)
            mask(raw)
            return raw

        def kind_identified(user: str, kind: str, link: str, synced: bool = False, transport: str = "usb",
                            old: list | None = None) -> None:
            ctype, amr_code = KIND[kind]
            mark = len(kc_log())
            ctx = new_context()
            try:
                page = ctx.new_page()
                key = Key(page, synced=synced, transport=transport)
                goto(page, link)
                base.passkey_flow(page, until=PORTAL, label=f"{user}-{kind}", expect_stepups=1)
                creds = key.credentials()
                assert key.registered == 1 and len(creds) == 1, (key.registered, creds)
            finally:
                ctx.close()
            types = kc_types(user)
            print(f"    {user}: Keycloak types {types}", flush=True)
            assert types == [ctype], f"{user}: {types} (want [{ctype}])"
            line = re.search(rf"passkey registered for {re.escape(user)}: AAGUID ([0-9a-f-]{{36}}), kind (\w+)", kc_log()[mark:])
            assert line, f"no registration line for {user}"
            print(f"    {user}: {line.group(0)}", flush=True)
            assert line.group(2) == kind, f"{user} registered as {line.group(2)} (want {kind})"
            if kind != "passkey_synced":
                assert line.group(1) == AAGUID and set(line.group(1)) != {"0", "-"}, f"AAGUID {line.group(1)}"
            if old:
                ids = {raw_id(c["credentialId"]) for c in old}
                assert raw_id(creds[0]["credentialId"]) not in ids, "--replace-keys kept the old credential"
            # The Sign-in page: the passkey under its kind only.

            def listed():
                rows = {m["id"]: m for m in people_json(user, "GET", "/api/me/signin")["methods"]}
                others = [k for k in KIND if k != kind and (rows[k]["state"] == "set" or rows[k].get("passkeys"))]
                return rows[kind]["state"] == "set" and len(rows[kind].get("passkeys") or []) == 1 and not others and rows
            rows = until(f"{user}'s /api/me/signin lists one {kind}", listed, 60, every=3)
            print(f"    {user}: /api/me/signin {[(k, rows[k]['state']) for k in KIND]}", flush=True)
            # A sign-in with it: amr and the LOGIN event's pc_methods.
            t0 = int(time.time() * 1000) - 2000
            ctx = new_context()
            try:
                page = ctx.new_page()
                Key(page, synced=synced, transport=transport, credentials=creds)
                goto(page, PORTAL)
                assert drive_kc(page, lambda: page.url.startswith(PORTAL) and "Signed in as" in body(page),
                                f"{user}-{kind}-signin") == "done"
                amr = token_claims(page).get("amr") or []
            finally:
                ctx.close()
            others = {KIND[k][1] for k in KIND if k != kind}
            assert amr_code in amr and not (others & set(amr)), f"{user}: amr {amr} (want {amr_code}, none of {others})"

            def login():
                ev = [e for e in kc_events(user, "LOGIN") if e.get("time", 0) >= t0]
                return [(e.get("details") or {}).get("pc_methods", "") for e in ev]
            pcm = until(f"{user}'s LOGIN event", login, 20, every=2)
            print(f"    {user}: amr {amr}, LOGIN pc_methods {pcm}", flush=True)
            assert kind in pcm and not any(k in m for m in pcm for k in KIND if k != kind), pcm

        def passkey_kinds_identified():
            pol = kc("")
            policy = {k: pol.get(k) for k in ("webAuthnPolicyPasswordlessAttestationConveyancePreference",
                                              "webAuthnPolicyPasswordlessAuthenticatorAttachment",
                                              "webAuthnPolicyPasswordlessRequireResidentKey",
                                              "webAuthnPolicyPasswordlessUserVerificationRequirement")}
            assert list(policy.values()) == ["direct", "not specified", "Yes", "required"], policy
            errors = []
            # security_key: the operator's lost-key path.
            old = kc_types("rita")
            uid = kc_user_id("rita")
            old_creds = [c for c in kc(f"/users/{uid}/credentials") if c["type"] in PASSKEY_TYPES]
            out = subprocess.run(["./portcullis", "invite", "rita", "--replace-keys", "--to", "portal", "--json"],
                                 capture_output=True, text=True)
            assert out.returncode == 0, f"portcullis invite --replace-keys rita: exit {out.returncode} {out.stderr[-300:]}"
            link = json.loads(out.stdout)["url"]
            mask(link)
            print(f"    rita before --replace-keys: {old}", flush=True)
            assert kc_types("rita") == [], f"--replace-keys left {kc_types('rita')}"
            try:
                kind_identified("rita", "security_key", link)
                gone = {c["id"] for c in old_creds} & {c["id"] for c in kc(f"/users/{uid}/credentials")}
                assert not gone, "rita's old credential is still there"
            except Exception as e:  # noqa: BLE001
                errors.append(f"security_key: {redact(str(e))}")
            try:
                kind_identified("bob", "passkey_synced", hub_setup_link("bob"), synced=True)
            except Exception as e:  # noqa: BLE001
                errors.append(f"passkey_synced: {redact(str(e))}")
            try:
                fixture_kind("passkey_device")
                kind_identified("pat", "passkey_device", hub_setup_link("pat"), transport="internal")
            except Exception as e:  # noqa: BLE001
                errors.append(f"passkey_device: {redact(str(e))}")
            finally:
                write_fixture(original_fixture)
                kick()
                until("signin-keycloak.json lists the virtual key as security_key again",
                      lambda: (published()["authenticators"].get(AAGUID) or {}).get("kind") == "security_key", 90)
            assert not errors, errors
        check("passkey_kinds_identified: the realm's passwordless policy is direct / not specified / resident key / UV "
              "(after the job drifted it and configure restored it); a security key (rita, ./portcullis invite "
              "--replace-keys), a synced passkey (bob) and a device-bound passkey (pat; the fixture's kind "
              "passkey_device) through setup links: each stored under its Keycloak type, logged with its kind (a "
              "non-zero AAGUID), listed under its method only on /api/me/signin, signing in with amr hwk / spk / dpk and "
              "LOGIN pc_methods of its kind", passkey_kinds_identified)

        # ── TLS follows the switches (last: it restarts apps) ──
        def tls_follows_switch():
            snap0 = hub_ok("GET", "/api/signin")
            picks0 = {i: hub_ok("GET", f"/api/instances/{i}/signin").get("template", "")
                      for i in ("echo-cert", "echo-file", "echo-anycert", "oidc-strong", "oidc-all", "oidc-cert")}
            assert picks0 == {"echo-cert": "e2e-cert", "echo-file": "e2e-file", "echo-anycert": "e2e-anycert",
                              "oidc-strong": "strong", "oidc-all": "yubikey-and-certificate",
                              "oidc-cert": "e2e-cert"}, picks0
            # Both certificate methods are on (browser_cert since part 2):
            # Standard and Basic name family:certificate = both of them.
            assert {"yubikey_cert", "browser_cert"} <= set(methods_on()), methods_on()
            cert_templates = ("strong", "yubikey-and-certificate", "e2e-cert", "e2e-file", "e2e-anycert")
            std0 = next(t for t in snap0["templates"] if t["id"] == "standard")
            for inst in ("echo-std", "echo-basic"):
                assert tls_option(inst) == "authaware@file", f"{inst}: {tls_option(inst)}"
                assert ca_names(f"{inst}.{DOMAIN}"), f"{inst}: no CA names with yubikey_cert on"
            assert ca_names(f"auth.{DOMAIN}"), "auth.<d>: no CA names"

            def restore() -> list:
                """Everything back as it was, each step tried whatever failed before."""
                errs = []
                steps = [("PUT", "/api/signin/methods/yubikey_cert", {"on": True}),
                         ("PUT", "/api/signin/methods/browser_cert", {"on": True}),
                         ("PUT", "/api/signin/templates/standard", {"name": std0["name"], "rule": std0["rule"]})]
                steps += [("PUT", f"/api/signin/templates/{t}/enabled",
                           {"on": next(x for x in snap0["templates"] if x["id"] == t)["enabled"]})
                          for t in cert_templates]
                steps += [("PUT", f"/api/signin/core/{k}", {"template": snap0["core"][k]}) for k in ("hub", "people")]
                steps += [("PUT", f"/api/instances/{i}/settings", {"sign_in_template": t}) for i, t in picks0.items()]
                for method, path, body_ in steps:
                    try:
                        hub_ok(method, path, body_)
                    except Exception as e:  # noqa: BLE001
                        errs.append(str(e))
                return errs

            restored: list | None = None
            try:
                hub_ok("PUT", "/api/signin/templates/standard",
                       {"name": std0["name"], "rule": {"op": "any", "items": ["family:passkey"]}})
                for inst in picks0:
                    hub_ok("PUT", f"/api/instances/{inst}/settings", {"sign_in_template": ""})
                for page_key in ("hub", "people"):
                    hub_ok("PUT", f"/api/signin/core/{page_key}", {"template": "standard"})
                for t in cert_templates:
                    hub_ok("PUT", f"/api/signin/templates/{t}/enabled", {"on": False})
                until("echo-std on public@file without CA names (Standard has no certificate any more)",
                      lambda: tls_option("echo-std") == "public@file" and not ca_names(f"echo-std.{DOMAIN}"), 180, every=5)
                # Basic still names family:certificate: the method switches alone move it.
                assert tls_option("echo-basic") == "authaware@file" and ca_names(f"echo-basic.{DOMAIN}"), \
                    f"echo-basic before the switch: {tls_option('echo-basic')}"
                hub_ok("PUT", "/api/signin/methods/yubikey_cert", {"on": False})
                # browser_cert alone still counts as a certificate there: once
                # the Hub has applied the switch (both published files without
                # yubikey_cert, its own tier for echo-basic authaware, no
                # echo-basic op running), echo-basic stays authaware with CA
                # names over several samples.
                def applied():
                    pol, kc_ = hub_json("group-gate-policy.json"), published()
                    tier = hub_ok("GET", "/api/instances/echo-basic/settings").get("tier")
                    code, op = hub("GET", "/api/instances/echo-basic/op")
                    running = code == 200 and isinstance(op, dict) and op.get("running")
                    return ("yubikey_cert" not in pol.get("methods", []) and "yubikey_cert" not in kc_["methods"]
                            and tier == "authaware@file" and not running)
                until("the Hub applied yubikey_cert off (published, echo-basic's tier, no op running)", applied, 120)
                for i in range(6):
                    assert tls_option("echo-basic") == "authaware@file" and ca_names(f"echo-basic.{DOMAIN}"), \
                        f"echo-basic with browser_cert still on, sample {i + 1}: {tls_option('echo-basic')}"
                    time.sleep(5)
                hub_ok("PUT", "/api/signin/methods/browser_cert", {"on": False})
                until("echo-basic on public@file without CA names (yubikey_cert and browser_cert off)",
                      lambda: tls_option("echo-basic") == "public@file" and not ca_names(f"echo-basic.{DOMAIN}"), 180,
                      every=5)
                assert ca_names(f"auth.{DOMAIN}"), "auth.<d> lost its CA names (core routers stay on authaware)"
                assert ca_names(f"hub.{DOMAIN}"), "hub.<d> lost its CA names (core routers stay on authaware)"
            finally:
                restored = restore()
            assert not restored, f"restore steps failed: {restored}"
            for inst in ("echo-std", "echo-basic"):
                until(f"{inst} back on authaware@file with CA names",
                      lambda inst=inst: tls_option(inst) == "authaware@file" and ca_names(f"{inst}.{DOMAIN}"), 180, every=5)
            snap1 = hub_ok("GET", "/api/signin")
            shape = lambda v: ({m["id"]: m["on"] for m in v["methods"]}, v["default"], v["core"],  # noqa: E731
                               sorted((t["id"], t["enabled"], json.dumps(t["rule"], sort_keys=True)) for t in v["templates"]))
            assert shape(snap1) == shape(snap0), f"not restored: {shape(snap1)} != {shape(snap0)}"
            picks1 = {i: hub_ok("GET", f"/api/instances/{i}/signin").get("template", "") for i in picks0}
            assert picks1 == picks0, picks1
        check("tls_follows_switch: an app's client-certificate request follows the switches (authaware → "
              "public@file, CA names gone, once both certificate methods are off); auth.<d> / hub.<d> keep them; "
              "everything restored", tls_follows_switch)

        for k in ("sam_ctx",):
            if k in state:
                state.pop(k).close()
        browser.close()

    # The throwaway groups kick() made (best effort).
    for n in range(1, _kicks[0] + 1):
        code, out = hub("DELETE", f"/api/directory/groups/ci-kick-{n}", {"confirm": f"ci-kick-{n}"})
        if code not in (200, 204):
            print(f"    cleanup: ci-kick-{n}: HTTP {code} {str(out)[:200]}", flush=True)

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    for name, _, err in failed:
        print(f"  FAIL {name}: {err}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
