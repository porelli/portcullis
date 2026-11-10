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
  password_on_basic_app     password on: pat signs in with his password on
                            echo-basic; people.<d> (Strong) → #needs-stronger
  admin_password_refused    admin + LLDAP's admin password, 11 times (above
                            failureFactor 10): refused, not counted by brute
                            force, admin's passkey still signs in
  password_off_not_offered  again after switching it off
  reclassify (part 2)       rita's credential becomes portcullis-security-key;
                            the PasskeyReclassified log line is at most 360 s
                            after the fixture's return
  tls_follows_switch        echo-std / echo-basic / auth.<d> CA names;
                            Standard = any[family:passkey], hub / people →
                            standard, Strong (and the certificate templates)
                            disabled, yubikey_cert off → public@file, no CA
                            names; auth.<d> keeps them; everything restored

Environment: E2E_DOMAIN, HUB_IP, E2E_HUB_SECRET, KEYCLOAK_ADMIN,
KEYCLOAK_ADMIN_PASSWORD, LLDAP_ADMIN_PASSWORD, E2E_ROOT_CERT / _KEY,
E2E_BOB_CERT / _KEY, E2E_PAT_PASSWORD_FILE, E2E_FIXTURE (the host file the
Hub's HUB_SIGNIN_EXTRA_AUTHENTICATORS is), ALPINE, E2E_ARTIFACTS. Secrets
come only from the environment or files and are never printed; no
Playwright traces (a DOM snapshot would carry a typed password).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

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
OIDC_STRONG = f"https://oidc-strong.{DOMAIN}"
OIDC_ALL = f"https://oidc-all.{DOMAIN}"
OIDC_CERT = f"https://oidc-cert.{DOMAIN}"
REALM = f"{AUTH}/realms/portcullis"
HUB_API = f"http://{os.environ['HUB_IP']}:8888"
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
    if time.time() - _kc["t"] > 30:
        body = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli",
                                       "username": os.environ["KEYCLOAK_ADMIN"],
                                       "password": os.environ["KEYCLOAK_ADMIN_PASSWORD"]}).encode()
        with urllib.request.urlopen(urllib.request.Request(
                f"{KC_ADMIN}/realms/master/protocol/openid-connect/token", data=body), timeout=30) as r:
            _kc["token"], _kc["t"] = json.loads(r.read())["access_token"], time.time()
    req = urllib.request.Request(f"{KC_ADMIN}/admin/realms/portcullis{path}", method=method,
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

    def __init__(self, page: Page, *, synced: bool = False, credentials: list | None = None):
        self.cdp = page.context.new_cdp_session(page)
        self.cdp.send("WebAuthn.enable", {"enableUI": False})
        opts = {"protocol": "ctap2", "transport": "usb", "hasResidentKey": True, "hasUserVerification": True,
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
    S256, redirect https://people.<d>/), as the Hub's popup does; the ID
    token's claims."""
    redirect_uri = PEOPLE + "/"
    rd = Redirect(page, redirect_uri)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    goto(page, authorize_url("portcullis-fresh-auth", redirect_uri, code_challenge=challenge,
                             code_challenge_method="S256", **extra))
    out = drive_kc(page, lambda: rd.code() is not None, label)
    assert out == "done", f"{label}: {out} at {page.url.split('?')[0]}"
    tok = exchange(page, "portcullis-fresh-auth", redirect_uri, rd.code(), verifier=verifier)
    return claims_of(tok["id_token"])


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

        # ── TLS follows the switches (last: it restarts apps) ──
        def tls_follows_switch():
            snap0 = hub_ok("GET", "/api/signin")
            picks0 = {i: hub_ok("GET", f"/api/instances/{i}/signin").get("template", "")
                      for i in ("echo-cert", "oidc-strong", "oidc-all", "oidc-cert")}
            assert picks0 == {"echo-cert": "e2e-cert", "oidc-strong": "strong", "oidc-all": "yubikey-and-certificate",
                              "oidc-cert": "e2e-cert"}, picks0
            std0 = next(t for t in snap0["templates"] if t["id"] == "standard")
            for inst in ("echo-std", "echo-basic"):
                assert tls_option(inst) == "authaware@file", f"{inst}: {tls_option(inst)}"
                assert ca_names(f"{inst}.{DOMAIN}"), f"{inst}: no CA names with yubikey_cert on"
            assert ca_names(f"auth.{DOMAIN}"), "auth.<d>: no CA names"

            def restore() -> list:
                """Everything back as it was, each step tried whatever failed before."""
                errs = []
                steps = [("PUT", "/api/signin/methods/yubikey_cert", {"on": True}),
                         ("PUT", "/api/signin/templates/standard", {"name": std0["name"], "rule": std0["rule"]})]
                steps += [("PUT", f"/api/signin/templates/{t}/enabled",
                           {"on": next(x for x in snap0["templates"] if x["id"] == t)["enabled"]})
                          for t in ("strong", "yubikey-and-certificate", "e2e-cert")]
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
                for t in ("strong", "yubikey-and-certificate", "e2e-cert"):
                    hub_ok("PUT", f"/api/signin/templates/{t}/enabled", {"on": False})
                until("echo-std on public@file without CA names (Standard has no certificate any more)",
                      lambda: tls_option("echo-std") == "public@file" and not ca_names(f"echo-std.{DOMAIN}"), 180, every=5)
                # Basic still names family:certificate: the method switch alone moves it.
                assert tls_option("echo-basic") == "authaware@file" and ca_names(f"echo-basic.{DOMAIN}"), \
                    f"echo-basic before the switch: {tls_option('echo-basic')}"
                hub_ok("PUT", "/api/signin/methods/yubikey_cert", {"on": False})
                until("echo-basic on public@file without CA names (yubikey_cert off)",
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
              "public@file, CA names gone); auth.<d> / hub.<d> keep them; everything restored", tls_follows_switch)

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
