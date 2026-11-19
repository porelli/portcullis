#!/usr/bin/env python3
"""End-to-end: Portcullis mail on a real stack with a second mail server
(contract §19; mail plan Task 12).

Runs in CI (job `e2e-mail` in .github/workflows/ci.yml): the whole core
stack + the Hub (same-named Hub branch) + domains (Pebble, the fake
provider; ONE fake zone shared with the dns tool and mail-cert), mail on
for ci.example.org and the enrolled team-b.test, and a remote Stalwart
(e2e-mail-remote.sh: remote.test, account carla) on the wired stalwart
template's egress network. Nothing
leaves the runner: outbound 25 / 465 / 587 is rejected outside the
stack's networks, every name is the fake zone's.

  python3 tests/e2e/e2e_mail.py            scenarios 1–9
  python3 tests/e2e/e2e_mail.py restore    scenario 10 (after the job's
                                           backup / restore phase)

Scenarios:
  setup        alice, bob (mail_users), carol (not), root (lldap_admin,
               mail_users); mail on for ci.example.org (every mailbox)
               and team-b.test (mail_users); the list team (alice, bob,
               members-only); every account answers RCPT; DKIM ed25519 +
               rsa active for both domains (./portcullis mail rotate);
               alice, bob and root create their mail passwords on the
               Sign-in page (fresh-auth popup, shown once).
  1 exchange_both_ways      alice → carla@remote.test: the remote's
               Authentication-Results show dkim=pass for an ed25519-sha256
               and an rsa-sha256 signature, spf=pass, dmarc=pass; carla →
               alice arrives; the remote's DMARC aggregate report (forced
               through its report task) reaches dmarc-reports@ and shows
               in GET /api/mail/checks.
  2 enrolled_domain_alias   bob receives at bob@team-b.test and sends as it.
  3 gtube_rejected_at_data  550 5.7.1 at DATA; between_thresholds_to_junk:
               a message scoring 5–15 (all-caps subject, no Date /
               Message-ID / MIME-Version) lands in bob's Junk with X-Spam-*.
  4 mail_password_flow      alice's "e2e laptop" shown once and nowhere
               after the dialog; IMAP 993, SMTP 465 and 587 work; her LLDAP
               password fails IMAP and the mail password fails LLDAP;
               the management listener: 404 from a portcullis-mail
               address, and from mailctl's own address Basic auth gets a
               method-level forbidden; five passwords, the sixth 409.
  8 members_only_list       carla → team@: 550 5.7.1 at RCPT; alice
               (authenticated) → team@ reaches bob.
  9 postmaster_to_admins    carla → postmaster@ci.example.org reaches root.
  5 revoke_within_8s        a NOOP-polled IMAP session fails within 8 s
               of the revoke.
  6 leave_ends_idle_session bob's IDLE session fails within 8 s of his
               removal from mail_users; RCPT to bob@ci.example.org 550 5.1.1.
  7 recreated_username_fresh_mailbox  bob deleted and created again in
               LLDAP, back in mail_users: INBOX empty, his old passwords
               fail, former-<old uuid> listed in GET /api/mail/status.
  10 restore_voids_mail_passwords  (restore) the rows are voided
               (void_restore), the Sign-in page says "reset by a restore",
               the old password fails.

Environment: E2E_DOMAIN, E2E_EXTRA, E2E_HUB_SECRET (never printed), E2E_MAIL_CA,
LLDAP_ADMIN_PASSWORD, REMOTE_ADMIN, REMOTE_PASSWORD, REMOTE_USER,
E2E_ARTIFACTS. Every password is masked (::add-mask::) as soon as it is
known and never printed. No Playwright traces (the dialog shows a password).
"""
from __future__ import annotations

import base64
import imaplib
import json
import os
import re
import smtplib
import socket
import ssl
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
import uuid as uuidlib
from email.parser import BytesHeaderParser

from playwright.sync_api import Error as PWError
from playwright.sync_api import Page, sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_login as base  # noqa: E402  (Authenticator, passkey_flow, shot)
import e2e_mailcheck as mailcheck  # noqa: E402  (pure helpers, unit tested)
import e2e_mailremote as remote  # noqa: E402
import e2e_ops  # noqa: E402  (the Hub's 202 op records)
import scenarios  # noqa: E402  (E2E_SCENARIOS: single-scenario reruns)

DOMAIN = os.environ["E2E_DOMAIN"]
EXTRA = os.environ.get("E2E_EXTRA", "team-b.test")
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
SECRET = os.environ["E2E_HUB_SECRET"]
REMOTE_USER = os.environ.get("REMOTE_USER", "carla")
REMOTE_ADDR = f"{REMOTE_USER}@remote.test"
REMOTE_IP = "172.30.88.25"
STATE_FILE = "/tmp/e2e-mail-state.json"
TIMEOUT_MS = 30_000
PEOPLE = f"https://people.{DOMAIN}"
AUTH = f"https://auth.{DOMAIN}"
PORTAL = f"https://{DOMAIN}/"
LLDAP = "http://127.0.0.1:17170"
SLA_S = 8
# The chains are verified against E2E_MAIL_CA (Pebble's issuing root for
# mail's certificate, the remote's self-signed one); the name isn't, as
# every connection goes to an address of this runner's own stack.
TLS = ssl.create_default_context(cafile=os.environ["E2E_MAIL_CA"])
TLS.check_hostname = False

results: list[tuple[str, bool, str]] = []
state: dict = {}
SECRETS: list[str] = []
LATENCY: dict[str, float] = {}
POPUPS: dict[str, int] = {}


def scrub(s: str) -> str:
    for v in SECRETS + [SECRET, os.environ.get("REMOTE_PASSWORD", ""), os.environ.get("REMOTE_ADMIN", "")]:
        if v and len(v) >= 6:
            s = s.replace(v, "***")
    return s


def mask(value: str) -> None:
    if value:
        SECRETS.append(value)
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::add-mask::{value}", flush=True)


def check(name: str, fn) -> None:
    if scenarios.skip(name):  # E2E_SCENARIOS (tests/e2e/scenarios.py)
        return
    try:
        fn()
        results.append((name, True, ""))
        print(f"PASS: {name}", flush=True)
    except Exception as e:  # noqa: BLE001
        msg = scrub(f"{type(e).__name__}: {e}")
        results.append((name, False, msg))
        print(f"FAIL: {name}: {msg}", flush=True)
        print(scrub(traceback.format_exc()), flush=True)


def needs(*keys: str) -> None:
    missing = [k for k in keys if k not in state]
    assert not missing, f"needs {', '.join(missing)} (an earlier scenario failed)"


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
            raise AssertionError(f"{what}: not within {seconds:.0f} s (last: {scrub(str(last))[:600]})")
        time.sleep(every)


def save(name: str, data) -> None:
    os.makedirs(ART, exist_ok=True)
    with open(os.path.join(ART, name), "w") as f:
        f.write(scrub(data if isinstance(data, str) else json.dumps(data, indent=2, default=str)))


def summary(line: str) -> None:
    print(line, flush=True)
    p = os.environ.get("GITHUB_STEP_SUMMARY")
    if p:
        with open(p, "a") as f:
            f.write(line + "\n")


def run(*argv: str, timeout: float = 600, check_rc: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)
    if check_rc and p.returncode != 0:
        raise AssertionError(f"{' '.join(argv[:4])}: rc {p.returncode}: {scrub((p.stdout + p.stderr)[-1500:])}")
    return p


def docker(*args: str, check_rc: bool = True, timeout: float = 120) -> str:
    return run("docker", *args, timeout=timeout, check_rc=check_rc).stdout


def persist() -> None:
    """The passwords and ids scenario 10 needs, for the restore phase (0600,
    /tmp, never an artifact)."""
    keep = {k: state[k] for k in ("pw_alice", "pw_alice_ids") if k in state}
    fd = os.open(STATE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(keep, f)


# ── the Hub's admin API (as Traefik calls it: proxy secret + identity) ──

PROVIDER_PROJECT = "portcullis-stalwart"


def running(project: str) -> list[str]:
    """The running containers of a compose project (an unwire or a failed
    void is a compose down: its containers are gone, its volumes kept)."""
    return docker("ps", "-q", "--filter", f"label=com.docker.compose.project={project}").split()


def pcid(service: str, project: str = PROVIDER_PROJECT) -> str:
    """The wired provider instance's container of service (any state)."""
    out = docker("ps", "-aq", "--filter", f"label=com.docker.compose.project={project}",
                 "--filter", f"label=com.docker.compose.service={service}").split()
    return out[0] if out else ""


def hub_ip() -> str:
    cid = docker("compose", "ps", "-q", "hub").strip()
    return json.loads(docker("inspect", "-f", "{{json .NetworkSettings.Networks}}", cid))["portcullis"]["IPAddress"]


def hub(method: str, path: str, body=None, timeout: float = 120, actor: str = "admin"):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://{state.get('hub_ip') or hub_ip()}:8888" + path, data=data, method=method,
                                 headers={"X-Portcullis-Proxy-Secret": SECRET, "X-Forwarded-User": actor,
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


def hub_ok(method: str, path: str, body=None, want=(200,), timeout: float = 120):
    want = (want,) if isinstance(want, int) else want
    code, out = hub(method, path, body, timeout)
    assert code in want, f"{method} {path}: HTTP {code} (want {want}): {scrub(str(out))[:800]}"
    return out


def member(op: str, group: str, user: str) -> None:
    if op == "add":
        hub_ok("POST", f"/api/directory/groups/{group}/members", {"username": user}, want=(200, 201, 204))
    else:
        hub_ok("DELETE", f"/api/directory/groups/{group}/members/{user}", {}, want=(200, 204))


# ── LLDAP (GraphQL as its admin) ──

def lldap_login(user: str, password: str) -> int:
    body = json.dumps({"username": user, "password": password}).encode()
    req = urllib.request.Request(LLDAP + "/auth/simple/login", data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def lldap_token() -> str:
    body = json.dumps({"username": "admin", "password": os.environ["LLDAP_ADMIN_PASSWORD"]}).encode()
    req = urllib.request.Request(LLDAP + "/auth/simple/login", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        tok = json.loads(r.read())["token"]
    mask(tok)
    return tok


def gql(query: str, variables: dict | None = None) -> dict:
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(LLDAP + "/api/graphql", data=body, headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + (state.get("lldap") or lldap_token())})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read())
    assert not out.get("errors"), f"LLDAP: {out['errors']}"
    return out["data"]


def create_user(u: str) -> None:
    gql("mutation($u: CreateUserInput!) { createUser(user: $u) { id } }", {"u": {"id": u, "email": f"{u}@users.{DOMAIN}"}})


def uuid_of(u: str) -> str:
    return gql('query($id: String!) { user(userId: $id) { uuid } }', {"id": u})["user"]["uuid"]


# ── mail clients (the host's published ports; the remote's address) ──

def imap_login(user: str, pw: str, host: str = "127.0.0.1") -> imaplib.IMAP4_SSL:
    i = imaplib.IMAP4_SSL(host, 993, ssl_context=TLS, timeout=20)
    i.login(user, pw)
    return i


def imap_refused(user: str, pw: str, host: str = "127.0.0.1", wait: float = 120) -> bool:
    """True only when a connected IMAP server answers the login with a
    refusal (NO / BAD / AUTHENTICATIONFAILED); False when it logs in. A
    server that can't be reached (mail restarting: a revoke restarts it)
    is waited for, never counted as a refusal (final review M8); one that
    never answers fails the check."""
    deadline = time.monotonic() + wait
    last = ""
    while True:
        try:
            i = imaplib.IMAP4_SSL(host, 993, ssl_context=TLS, timeout=20)
        except (OSError, imaplib.IMAP4.abort) as e:
            last = f"{type(e).__name__}: {e}"
        else:
            try:
                i.login(user, pw)
            except imaplib.IMAP4.abort as e:  # dropped mid-login: not an answer
                last = f"abort: {e}"
            except imaplib.IMAP4.error:
                # imaplib raises IMAP4.error (not abort) only for the
                # server's tagged NO / BAD answer to LOGIN: a refusal.
                return True
            else:
                try:
                    i.logout()
                except (OSError, imaplib.IMAP4.error):
                    pass
                return False
            finally:
                try:
                    i.shutdown()
                except OSError:
                    pass
        if time.monotonic() > deadline:
            raise AssertionError(f"IMAP on {host}:993 never answered a login within {wait:.0f}s: {last}")
        time.sleep(2)


def submit(user: str, pw: str, frm: str, to: list[str], msg: bytes, port: int = 587, host: str = "127.0.0.1"):
    if port == 465:
        s = smtplib.SMTP_SSL(host, 465, context=TLS, timeout=30)
    else:
        s = smtplib.SMTP(host, port, timeout=30)
        s.ehlo("e2e.client")
        s.starttls(context=TLS)
    try:
        s.login(user, pw)
        return s.sendmail(frm, to, msg)
    finally:
        s.quit()


def message(frm: str, to: str, subject: str, body: str = "e2e-mail\r\n", extra: str = "", plain: bool = False) -> bytes:
    if plain:
        return f"From: {frm}\r\nTo: {to}\r\nSubject: {subject}\r\n{extra}\r\n{body}".encode()
    mid = f"<{uuidlib.uuid4().hex}@e2e.{DOMAIN}>"
    date = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    return (f"From: {frm}\r\nTo: {to}\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: {mid}\r\n"
            f"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n{extra}\r\n{body}").encode()


def find(i: imaplib.IMAP4_SSL, subject: str, folder: str = "INBOX") -> bytes | None:
    typ, _ = i.select(f'"{folder}"', readonly=True)
    assert typ == "OK", f"select {folder}"
    typ, d = i.search(None, "SUBJECT", f'"{subject}"')
    for n in (d[0] or b"").split():
        typ, m = i.fetch(n, "(BODY.PEEK[HEADER])")
        return m[0][1]
    return None


def spam_headers(raw: bytes) -> str:
    h = BytesHeaderParser().parsebytes(raw)
    return json.dumps({k: v for k, v in h.items() if k.lower().startswith("x-spam")})[:1500]


def wait_mail(login, subject: str, folder: str = "INBOX", seconds: float = 120) -> bytes:
    def got():
        i = login()
        try:
            return find(i, subject, folder)
        finally:
            try:
                i.logout()
            except (imaplib.IMAP4.error, OSError):
                pass
    try:
        return until(f"{subject!r} in {folder}", got, seconds, every=3)
    except AssertionError:
        if folder == "INBOX":
            # Filed as spam? Its scores say why.
            i = login()
            try:
                raw = find(i, subject, junk_folder(i))
            finally:
                i.logout()
            if raw:
                raise AssertionError(f"{subject!r} landed in Junk, not INBOX: {spam_headers(raw)}") from None
        raise


def junk_folder(i: imaplib.IMAP4_SSL) -> str:
    typ, boxes = i.list()
    for b in boxes or []:
        line = b.decode(errors="replace")
        if "\\Junk" in line:
            return line.rsplit(' "', 1)[-1].rstrip('"') if line.endswith('"') else line.split()[-1]
    raise AssertionError(f"no \\Junk mailbox: {boxes}")


def remote_imap():
    return imap_login(REMOTE_ADDR, os.environ["REMOTE_PASSWORD"], REMOTE_IP)


def remote_send(to: str, msg: bytes) -> None:
    submit(REMOTE_ADDR, os.environ["REMOTE_PASSWORD"], REMOTE_ADDR, [to], msg, host=REMOTE_IP)


def smtp25(frm: str, rcpt: str, data: bytes | None = None, host: str = "127.0.0.1", helo: str = "mx.remote.test"):
    """One unauthenticated port-25 transaction; returns (stage, code, text)
    at the first refusal, or ("data", 250, …)."""
    s = smtplib.SMTP(host, 25, timeout=30)
    try:
        s.ehlo(helo)
        c, m = s.mail(frm)
        if c >= 400:
            return "mail", c, m.decode(errors="replace")
        c, m = s.rcpt(rcpt)
        if c >= 400 or data is None:
            return "rcpt", c, m.decode(errors="replace")
        try:
            c, m = s.data(data)
        except smtplib.SMTPDataError as e:
            c, m = e.smtp_code, e.smtp_error
        return "data", c, (m.decode(errors="replace") if isinstance(m, bytes) else str(m))
    finally:
        try:
            s.quit()
        except (smtplib.SMTPException, OSError):
            pass


def mailstatus() -> dict:
    return hub_ok("GET", "/api/mail/status")


def remote_jmap() -> remote.Jmap:
    u, _, p = os.environ["REMOTE_ADMIN"].partition(":")
    return remote.Jmap(f"http://{REMOTE_IP}:8080", u, p)


# ── browser: the Sign-in page's mail passwords ──

def sign_in(browser, who: str):
    link = base.mint_setup_link(who, "portal")
    ctx = browser.new_context()
    ctx.set_default_timeout(TIMEOUT_MS)
    page = ctx.new_page()
    auth = base.Authenticator(page)
    base.setup_link_signin(page, link, who=who, mint=lambda: base.mint_setup_link(who, "portal"),
                           until=PORTAL, label=f"set-{who}", expect_stepups=1)
    return ctx, page, auth


def open_mail(page: Page):
    page.goto(PEOPLE + "/signin", wait_until="domcontentloaded")
    deadline = time.time() + 90
    while time.time() < deadline:
        if base.on_login_pages(page):
            base.passkey_flow(page, until=PEOPLE, label="people", expect_stepups=0)
            page.goto(PEOPLE + "/signin", wait_until="domcontentloaded")
        body = page.locator("[data-msi-mail-body]")
        if body.count() and body.first.is_visible():
            return body.first
        page.wait_for_timeout(500)
        if time.time() > deadline - 60 and int(deadline - time.time()) % 15 == 0:
            page.reload(wait_until="domcontentloaded")
    base.shot(page, "mail-section-missing")
    raise AssertionError(f"no Mail passwords section on the Sign-in page (at {page.url})")


def drive_popup(popup: Page, label: str) -> dict:
    seen = {"prompted": 0, "urls": []}
    deadline = time.time() + 120
    while time.time() < deadline:
        if popup.is_closed():
            return seen
        try:
            u = popup.url.split("?")[0]
            if not seen["urls"] or seen["urls"][-1] != u:
                seen["urls"].append(u)
            if popup.url.startswith(AUTH + "/realms/"):
                pw = popup.locator("input[type=password]")
                if pw.count() and pw.first.is_visible():
                    base.shot(popup, f"{label}-password-prompt")
                    raise AssertionError(f"password prompt in the popup at {u}")
                btn = popup.locator("#authenticateWebAuthnButton")
                if btn.count() and btn.first.is_visible():
                    seen["prompted"] += 1
                    btn.first.click()
                    popup.wait_for_timeout(1500)
                    continue
                err = popup.locator(".pf-m-danger, .alert-error, #input-error, .kc-feedback-text")
                if err.count() and err.first.is_visible():
                    base.shot(popup, f"{label}-kc-error")
                    raise AssertionError(f"Keycloak error in the popup: {err.first.inner_text()!r}")
            popup.wait_for_timeout(300)
        except PWError:
            if popup.is_closed():
                return seen
            time.sleep(0.3)
    base.shot(popup, f"{label}-popup-stuck")
    raise AssertionError(f"the popup didn't finish (visited {seen['urls']})")


def create_mail_password(page: Page, auth, who: str, label: str, strict: bool = False) -> str:
    """+ New mail password → label → Create → the fresh sign-in popup →
    the shown-once dialog. strict: the password is nowhere after Done."""
    open_mail(page)
    page.locator('[data-msi-act="mail-create"]').first.click()
    page.locator("[data-msi-maillabel]").fill(label)
    posts: list[tuple[str, str]] = []

    def on_request(req):
        if req.method == "POST" and req.url.endswith("/api/me/mail/passwords"):
            posts.append((req.url, req.post_data or ""))

    page.on("request", on_request)
    try:
        try:
            with page.context.expect_page(timeout=30_000) as pinfo:
                page.locator('[data-msi-act="mail-create-go"]').click()
            popup = pinfo.value
        except PWError:
            base.shot(page, f"{who}-mail-no-popup")
            panel = page.locator('[data-msi-panel="mail"]')
            msg = panel.first.inner_text() if panel.count() else "?"
            raise AssertionError(f"no fresh-auth popup for {who}'s mail password; the panel says: {msg[:300]!r}") from None
        n = POPUPS[who] = POPUPS.get(who, 0) + 1
        copies = [dict(c, signCount=c.get("signCount", 0) + 1000 * (n - 1)) for c in auth.credentials()]
        base.Authenticator(popup, credentials=copies)
        drive_popup(popup, f"{who}-mail")
        loc = page.locator("dialog[open] [data-msi-mailsecret]")
        try:
            loc.wait_for(state="visible", timeout=60_000)
        except PWError:
            base.shot(page, f"{who}-mail-no-dialog")
            raise AssertionError("no mail password dialog") from None
        pw = (loc.text_content() or "").strip()
        mask(pw)
    finally:
        page.remove_listener("request", on_request)
    assert len(pw) >= 16, f"the shown password is {len(pw)} characters"
    assert len(posts) == 1, f"{len(posts)} create POSTs (want 1)"
    page.locator('dialog[open] [data-msi-dlg="done"]').click()
    page.wait_for_timeout(500)
    assert page.locator("dialog[open]").count() == 0, "the dialog stayed open"
    if strict:
        assert pw not in page.content(), "the password is still in the page after Done"
        storage = page.evaluate("() => JSON.stringify([Object.assign({}, localStorage), Object.assign({}, sessionStorage)])")
        assert pw not in storage, "the password is in web storage"
        assert pw not in page.url, "the password is in the URL"
        me = page.request.get(PEOPLE + "/api/me/mail")
        assert me.status == 200 and pw not in me.text(), f"/api/me/mail: HTTP {me.status} or carries the password"
        url, body = posts[0]
        r = page.request.post(url, data=body, headers={"Content-Type": "application/json"})
        assert r.status in (403, 409) and pw not in r.text(), f"the same proof again: HTTP {r.status}"
        assert pw not in json.dumps(hub_ok("GET", f"/api/directory/users/{who}/mail")), "the admin view carries it"
    return pw


def my_mail(page: Page) -> dict:
    r = page.request.get(PEOPLE + "/api/me/mail")
    assert r.status == 200, f"/api/me/mail: HTTP {r.status}"
    return r.json()


def dns_diagnostics() -> None:
    """On a stuck DKIM activation: the Hub's domain rows, the domains
    service's plan of the added domain (its last error, the mail items),
    and what the fake zone holds there (artifacts, no secret)."""
    try:
        save("hub-domains.json", hub_ok("GET", "/api/domains"))
        save("mail-status.json", mailstatus())
        p = subprocess.run(["docker", "run", "--rm", "-i", "--network", "portcullis_portcullis-domains", "--entrypoint", "sh",
                            "docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93",
                            "-c", 'read -r t; printf "Authorization: Bearer %s\n" "$t" > /tmp/h; '
                                  'curl -s -H @/tmp/h "http://domains:8080/domains/$0"; echo; curl -s -H @/tmp/h "http://domains:8080/domains/$0/dns"', EXTRA],
                           input=open("secrets/domains/api-secret").read().strip() + "\n", capture_output=True, text=True, timeout=120)
        save("domains-extra.json", p.stdout)
        body = json.dumps({"op": "get", "zone": EXTRA + ".", "token": "ci-fake-token-0123456789", "records": []}).encode()
        with urllib.request.urlopen(urllib.request.Request("http://172.30.87.53:8054", data=body,
                                                           headers={"Content-Type": "application/json"}), timeout=30) as r:
            save("fakezone-extra.json", json.loads(r.read()))
        # mailctl's own view: the document's domains and the DKIM keys
        # (public data only), and what mail-resolver / the fake DNS answer.
        st = json.loads(docker("run", "--rm", "--network", "none", "-v", PROVIDER_PROJECT + "_adapter_data:/d:ro",
                               "docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a",
                               "cat", "/d/state.json"))
        save("mailctl-view.json", {"domains": [{k: d.get(k) for k in ("name", "mail", "dmarc_start")} for d in (st.get("doc") or {}).get("domains") or []],
                                   "generation": st.get("generation"), "applied_generation": st.get("applied_generation"),
                                   "errors": st.get("errors"), "dkim": json.loads(json.dumps((st.get("ext") or {}).get("dkim")))})
        for k in ((st.get("ext") or {}).get("dkim") or {}).get("keys") or []:
            if k.get("domain") != EXTRA:
                continue
            name = f"{k['selector']}._domainkey.{EXTRA}"
            # The template resolver (mailctl's only resolver here; the fake
            # zone itself is in fakezone-extra.json).
            out = docker("exec", pcid("resolver"), "drill", "-p", "5353", "@127.0.0.1", "TXT", name, check_rc=False)
            ans = [ln for ln in out.splitlines() if "\tTXT\t" in ln or "rcode" in ln]
            print(f"    drill the template resolver {name}: {ans[:3]}", flush=True)
            print(f"    mailctl wants: v=DKIM1; k={k['algorithm']}; p={k.get('public_key', '')[:24]}… (id {k.get('id') or '-'}, {k.get('stage')})", flush=True)
        print("    diagnostics saved: hub-domains.json, mail-status.json, domains-extra.json, fakezone-extra.json, mailctl-view.json", flush=True)
        for ln in p.stdout.splitlines()[:1]:
            print("    domains: " + scrub(ln)[:600], flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"    diagnostics failed: {type(e).__name__}: {e}", flush=True)


# ── scenarios ──

def setup(browser) -> None:
    state["lldap"] = lldap_token()
    for u in ("alice", "bob", "carol", "root"):
        create_user(u)
    gid = next(g["id"] for g in gql("{ groups { id displayName } }")["groups"] if g["displayName"] == "lldap_admin")
    gql("mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }", {"u": "root", "g": gid})
    hub_ok("PUT", f"/api/mail/domains/{DOMAIN}", {"enabled": True, "groups": []}, want=(200, 204))
    until("mail_users made by the Hub", lambda: any(g["displayName"] == "mail_users" for g in gql("{ groups { id displayName } }")["groups"]), 60)
    for u in ("alice", "bob", "root"):
        member("add", "mail_users", u)
    hub_ok("PUT", f"/api/mail/domains/{EXTRA}", {"enabled": True, "groups": ["mail_users"]}, want=(200, 204))
    # The remote on the spam allow list (the product's own path: DMARC must
    # pass, then TRUSTED_DOMAIN): CI's .test names score like spam otherwise.
    cur = hub_ok("GET", "/api/mail/settings")
    spam_s = dict(cur["spam"], allow=sorted(set((cur["spam"].get("allow") or []) + ["remote.test"])))
    hub_ok("PUT", "/api/mail/settings", {"primary_domain": cur["primary_domain"], "spam": spam_s,
                                          "limits": cur["limits"], "quotas": cur.get("quotas") or []})
    hub_ok("POST", "/api/directory/groups", {"name": "team"}, want=(200, 201))
    for u in ("alice", "bob"):
        member("add", "team", u)
    hub_ok("PUT", "/api/directory/groups/team/mail-list", {"enabled": True, "domain": DOMAIN, "posting": "members"}, want=(200, 204))
    # Additions are debounced 60 s: every address answers RCPT once applied.
    for a in (f"alice@{DOMAIN}", f"bob@{DOMAIN}", f"root@{DOMAIN}", f"bob@{EXTRA}"):
        until(f"{a} accepted at RCPT", lambda a=a: smtp25("probe@relay-test.example", a)[1] == 250, 240, every=5)
    # The members-only list exists once an outsider gets its 5.7.1 (not 5.1.1).
    until(f"team@{DOMAIN} a members-only list at RCPT",
          lambda: (lambda r: r[1] == 550 and r[2].startswith("5.7.1"))(smtp25("probe@relay-test.example", f"team@{DOMAIN}")), 240, every=5)
    # DKIM: the keys go active once both resolvers serve them (the main
    # domain's set is the CLI's: mail rotate; team-b.test's the Hub's).
    def dkim_active():
        run("./portcullis", "mail", "rotate", timeout=600)
        ks = (mailstatus().get("status") or {}).get("dkim") or []
        act = {(k["domain"], k["algorithm"]) for k in ks if k.get("stage") == "active"}
        want = {(d, a) for d in (DOMAIN, EXTRA) for a in ("ed25519", "rsa")}
        if want <= act:
            return True
        print("    DKIM keys: " + ", ".join(f"{k['domain']} {k['algorithm']} {k['selector']} {k['stage']}" for k in ks), flush=True)
        return False
    try:
        until("DKIM ed25519 + rsa active on both domains", dkim_active, 420, every=10)
    except AssertionError:
        dns_diagnostics()
        raise
    for who in ("alice", "bob", "root"):
        ctx, page, auth = sign_in(browser, who)
        state[f"ctx_{who}"], state[f"page_{who}"], state[f"auth_{who}"] = ctx, page, auth
        state[f"pw_{who}"] = create_mail_password(page, auth, who, f"e2e {who}")
    state["setup"] = True


def exchange_both_ways() -> None:
    needs("setup")
    subj = f"e2e out {uuidlib.uuid4().hex[:8]}"
    submit(f"alice@{DOMAIN}", state["pw_alice"], f"alice@{DOMAIN}", [REMOTE_ADDR],
           message(f"alice@{DOMAIN}", REMOTE_ADDR, subj))
    raw = wait_mail(remote_imap, subj)
    save("remote-received-headers.txt", raw.decode(errors="replace"))
    h = BytesHeaderParser().parsebytes(raw)
    ar = " ".join(h.get_all("Authentication-Results") or [])
    sigs = h.get_all("DKIM-Signature") or []
    algos = sorted(re.search(r"\ba=([a-z0-9-]+)", s).group(1) for s in sigs if re.search(r"\ba=", s))
    assert algos == ["ed25519-sha256", "rsa-sha256"], f"DKIM signatures: {algos}"
    passes = re.findall(r"dkim=pass[^;]*", ar)
    for s in sigs:
        sel = re.search(r"\bs=([^;\s]+)", s).group(1)
        assert any(f"header.s={sel}" in p for p in passes), f"no dkim=pass for selector {sel}: {ar[:600]}"
    assert re.search(r"\bspf=pass\b", ar), f"spf: {ar[:600]}"
    assert re.search(r"\bdmarc=pass\b", ar), f"dmarc: {ar[:600]}"
    print(f"    remote: {len(passes)} dkim=pass ({', '.join(algos)}), spf=pass, dmarc=pass", flush=True)
    subj2 = f"e2e in {uuidlib.uuid4().hex[:8]}"
    remote_send(f"alice@{DOMAIN}", message(REMOTE_ADDR, f"alice@{DOMAIN}", subj2))
    raw2 = wait_mail(lambda: imap_login(f"alice@{DOMAIN}", state["pw_alice"]), subj2)
    assert "TRUSTED_DOMAIN" in spam_headers(raw2), f"the allow-listed remote without TRUSTED_DOMAIN: {spam_headers(raw2)}"
    # A forged message from ci.example.org straight into the remote's 25
    # (the runner's address: neither SPF nor DKIM aligned), so its
    # aggregate report carries a failure.
    smtp25(f"forger@{DOMAIN}", REMOTE_ADDR, message(f"forger@{DOMAIN}", REMOTE_ADDR, "e2e forged"),
           host=REMOTE_IP, helo="forger.example")
    j = remote_jmap()

    def forced():
        # The aggregate data waits in the aggregation window
        # (DmarcReportWindow) until it closes; then an internal report and
        # its DmarcReport task exist. The tasks' due dates are pulled forward
        # (an internal report's deliverAt can't be set to the past).
        due = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 5))
        reps = [r for r in j.get_all("DmarcInternalReport") if r.get("domain") == DOMAIN]
        # The aggregation window (DmarcReportWindow) closes early: it then
        # makes the internal report and its DmarcReport task.
        tasks = [t for t in j.get_all("Task") if t.get("@type") in ("DmarcReport", "DmarcReportWindow")]
        for t in tasks:
            st = t.get("status") or {}
            if st.get("@type") in ("Pending", "Retry"):
                j.set("Task", update={t["id"]: {"status": {"@type": "Pending", "due": due}}})
        # Done once the DmarcReport task is due now (its internal report
        # then goes out).
        return [t for t in tasks if t.get("@type") == "DmarcReport"] if reps else []

    try:
        until("the remote's DMARC report (internal report or task)", forced, 180, every=5)
    except AssertionError:
        print("    remote tasks: " + json.dumps([{k: t.get(k) for k in ("@type", "status", "due")} for t in j.get_all("Task")])[:800], flush=True)
        print("    remote internal reports: " + json.dumps(j.get_all("DmarcInternalReport"))[:800], flush=True)
        raise

    def queued_now():
        # The report then waits in the remote's queue (Stalwart staggers
        # reports by up to hours): its next try a few seconds from now.
        soon = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3))
        for q in j.get_all("QueuedMessage"):
            if "dmarc-reports@" + DOMAIN in json.dumps(q.get("recipients")) and (q.get("nextRetry") or "") > soon:
                j.set("QueuedMessage", update={q["id"]: {"nextRetry": soon}})

    def in_checks():
        forced()
        queued_now()
        c = hub_ok("GET", "/api/mail/checks?refresh=1")
        dm = next((x for x in c.get("checks") or [] if x.get("id") == "dmarc_reports"), None)
        # The remote's report has the forged message's failure: shown
        # (display-only, contract §19.8), naming the remote as its source.
        return dm if dm and dm.get("severity") != "ok" and "remote.test" in (dm.get("detail") or "") else None
    dm = until("the remote's DMARC report in GET /api/mail/checks", in_checks, 600, every=65)
    save("checks-dmarc.json", dm)
    print(f"    dmarc_reports: {dm.get('severity')}: {dm.get('detail')}", flush=True)


def enrolled_domain_alias() -> None:
    needs("setup")
    subj = f"e2e alias in {uuidlib.uuid4().hex[:8]}"
    remote_send(f"bob@{EXTRA}", message(REMOTE_ADDR, f"bob@{EXTRA}", subj))
    wait_mail(lambda: imap_login(f"bob@{DOMAIN}", state["pw_bob"]), subj)
    subj2 = f"e2e alias out {uuidlib.uuid4().hex[:8]}"
    submit(f"bob@{DOMAIN}", state["pw_bob"], f"bob@{EXTRA}", [REMOTE_ADDR], message(f"bob@{EXTRA}", REMOTE_ADDR, subj2))
    raw = wait_mail(remote_imap, subj2)
    ar = " ".join(BytesHeaderParser().parsebytes(raw).get_all("Authentication-Results") or [])
    assert "dmarc=pass" in ar and f"header.d={EXTRA}" in ar, f"as bob@{EXTRA}: {ar[:600]}"


def spam() -> None:
    needs("setup")
    # The vendored rules are imported (mailctl's own copy, no network).
    def rules_in():
        c = hub_ok("GET", "/api/mail/checks?refresh=1")
        r = next((x for x in c.get("checks") or [] if x.get("id") == "x-spam_rules"), None)
        return r if r and r.get("severity") == "ok" else None
    until("the spam rules imported (check x-spam_rules ok)", rules_in, 300, every=65)
    gtube = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
    probe, helo = "probe@example.com", "client.example.com"
    # Stalwart v1.1.0 recognises GTUBE in the Subject (refused at DATA) and
    # not in the body (pinned: a bump that changes it is noticed).
    stage, code, text = smtp25(probe, f"bob@{DOMAIN}", message(probe, f"bob@{DOMAIN}", gtube), helo=helo)
    if not (stage == "data" and code == 550 and text.startswith("5.7.1")):
        i = imap_login(f"bob@{DOMAIN}", state["pw_bob"])
        try:
            raw = until("the GTUBE message somewhere", lambda: find(i, gtube[:20], junk_folder(i)) or find(i, gtube[:20]), 30)
        finally:
            i.logout()
        raise AssertionError(f"GTUBE in the Subject: {stage} {code} {text}; its spam headers: {spam_headers(raw)}")
    print(f"    gtube_rejected_at_data: {code} {text[:80]}", flush=True)
    stage, code, text = smtp25(probe, f"bob@{DOMAIN}", message(probe, f"bob@{DOMAIN}", "e2e gtube body", gtube + "\r\n"), helo=helo)
    assert stage == "data" and code == 250, f"GTUBE in the body (Stalwart doesn't recognise it there): {stage} {code} {text}"
    subj = f"URGENT OFFER {uuidlib.uuid4().hex[:6].upper()}"
    # A sender off the allow list, no Date / Message-ID / MIME-Version, an
    # all-caps subject: 5 < score < 15 (MISSING_DATE 1, MISSING_MID 2.5,
    # SUBJ_ALL_CAPS 3, plus AUTH_NA / DMARC_NA / RDNS for a direct client).
    stage, code, text = smtp25(probe, f"bob@{DOMAIN}", message(probe, f"bob@{DOMAIN}", subj, "buy now\r\n", plain=True), helo=helo)
    assert stage == "data" and code == 250, f"the 5–15 message: {stage} {code} {text}"

    def in_junk():
        i = imap_login(f"bob@{DOMAIN}", state["pw_bob"])
        try:
            return find(i, subj, junk_folder(i))
        finally:
            i.logout()
    raw = until("the 5–15 message in bob's Junk", in_junk, 120)
    h = BytesHeaderParser().parsebytes(raw)
    xs = {k: v for k, v in h.items() if k.lower().startswith("x-spam")}
    assert xs, "no X-Spam-* header on the junk message"
    m = re.search(r"score=([0-9.]+)", h.get("X-Spam-Score") or "")
    assert m and 5 <= float(m.group(1)) < 15, f"the junk message's score: {h.get('X-Spam-Score')}"
    save("junk-headers.txt", raw.decode(errors="replace"))
    print(f"    between_thresholds_to_junk: {h.get('X-Spam-Score')}", flush=True)


def mail_password_flow() -> None:
    needs("setup")
    page, auth = state["page_alice"], state["auth_alice"]
    pw = create_mail_password(page, auth, "alice", "e2e laptop", strict=True)
    state["pw_alice2"] = pw
    a = f"alice@{DOMAIN}"
    imap_login(a, pw).logout()
    for port in (465, 587):
        submit(a, pw, a, [a], message(a, a, f"e2e self {port}"), port=port)
    out = hub_ok("POST", "/api/directory/users/alice/password", {"generate": True}, want=(200, 201))
    lp = out["password"]
    mask(lp)
    assert imap_refused(a, lp), "alice's LLDAP password opened IMAP"
    assert lldap_login("alice", pw) == 401, "the mail password signed in to LLDAP"
    # The management listener: 404 from another address on the template's
    # internal network; from the adapter's own address Basic auth
    # authenticates but the method is forbidden (the adapter stopped
    # meanwhile: its address is pinned).
    curl = "docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93"
    body = json.dumps({"using": remote.USING, "methodCalls": [["x:Account/get", {"ids": None}, "0"]]})
    tok = base64.b64encode(f"{a}:{pw}".encode()).decode()

    def mgmt(ip: str) -> str:
        p = subprocess.run(["docker", "run", "--rm", "-i", "--network", PROVIDER_PROJECT + "_internal", "--ip", ip, "--entrypoint", "sh", curl,
                            "-c", 'read -r h; printf "Authorization: Basic %s\\n" "$h" > /tmp/h; '
                                  'curl -s -H @/tmp/h -H "Content-Type: application/json" -d "$0" -w "\\n%{http_code}" http://172.31.255.2:8080/jmap', body],
                           input=tok + "\n", capture_output=True, text=True, timeout=60)
        return p.stdout
    out = mgmt("172.31.255.9")
    assert out.strip().endswith("404"), f"from 172.31.255.9: {scrub(out)[-300:]}"
    adapter = pcid("adapter")
    docker("stop", adapter)
    try:
        out = mgmt("172.31.255.3")
    finally:
        docker("start", adapter)
    lines = out.strip().splitlines()
    assert lines and lines[-1] == "200" and "forbidden" in out, f"from the adapter's address: {scrub(out)[-400:]}"
    until("the adapter healthy again", lambda: docker("inspect", "-f", "{{.State.Health.Status}}", pcid("adapter")).strip() == "healthy", 120)
    # Up to five: three more, then the sixth is 409 (checked before any proof).
    for n in range(3):
        create_mail_password(page, auth, "alice", f"e2e extra {n}")
    rows = [p for p in my_mail(page)["passwords"] if p["status"] == "active"]
    assert len(rows) == 5, f"active mail passwords: {len(rows)}"
    open_mail(page)
    assert page.locator('[data-msi-act="mail-create"]').count() == 0, "+ New mail password still offered at 5"
    r = page.request.post(PEOPLE + "/api/me/mail/passwords", data=json.dumps(
        {"label": "e2e sixth", "expiry": "none", "code": "x", "code_verifier": "x", "nonce": "x"}),
        headers={"Content-Type": "application/json"})
    assert r.status == 409, f"the sixth: HTTP {r.status} {r.text()[:200]}"
    state["alice_rows"] = rows


def members_only_list() -> None:
    needs("setup")
    stage, code, text = smtp25(REMOTE_ADDR, f"team@{DOMAIN}")
    assert stage == "rcpt" and code == 550 and text.startswith("5.7.1"), f"carla → team@: {stage} {code} {text}"
    subj = f"e2e team {uuidlib.uuid4().hex[:8]}"
    a = f"alice@{DOMAIN}"
    submit(a, state["pw_alice"], a, [f"team@{DOMAIN}"], message(a, f"team@{DOMAIN}", subj))
    wait_mail(lambda: imap_login(f"bob@{DOMAIN}", state["pw_bob"]), subj)


def postmaster_to_admins() -> None:
    needs("setup")
    subj = f"e2e admins {uuidlib.uuid4().hex[:8]}"
    remote_send(f"postmaster@{DOMAIN}", message(REMOTE_ADDR, f"postmaster@{DOMAIN}", subj))
    wait_mail(lambda: imap_login(f"root@{DOMAIN}", state["pw_root"]), subj)


def revoke_within_8s() -> None:
    needs("alice_rows")
    page = state["page_alice"]
    a = f"alice@{DOMAIN}"
    pw = state["pw_alice2"]
    row = next(p for p in my_mail(page)["passwords"] if p["label"] == "e2e laptop" and p["status"] == "active")
    i = imap_login(a, pw)
    i.select("INBOX")
    r = page.request.delete(PEOPLE + f"/api/me/mail/passwords/{row['id']}", headers={"Content-Type": "application/json"})
    t0 = time.time()
    assert r.status == 204, f"revoke: HTTP {r.status}"
    while time.time() - t0 < SLA_S + 4:
        try:
            typ, _ = i.noop()
            if typ != "OK":
                break
        except (imaplib.IMAP4.error, imaplib.IMAP4.abort, OSError):
            break
        time.sleep(0.5)
    took = time.time() - t0
    LATENCY["revoke_within_8s"] = took
    print(f"LATENCY revoke → IMAP session gone: {took:.1f} s", flush=True)
    assert took <= SLA_S, f"the session lasted {took:.1f} s after the revoke (SLA {SLA_S} s)"
    assert imap_refused(a, pw), "the revoked password still logs in"


def mail_started_at() -> str:
    return docker("inspect", "-f", "{{.State.StartedAt}}", pcid("stalwart")).strip()


def leave_ends_idle_session() -> None:
    needs("setup")
    b = f"bob@{DOMAIN}"
    state["bob_old_uuid"] = uuid_of("bob")
    # The revoke before made the Hub restart mail (contract §19.6): IMAP
    # back first.
    i = until("IMAP accepting bob again", lambda: imap_login(b, state["pw_bob"]), 120, every=3)
    started = mail_started_at()
    i.select("INBOX")
    tag = i._new_tag().decode()
    i.send(f"{tag} IDLE\r\n".encode())
    assert i.readline().startswith(b"+"), "IDLE not accepted"
    i.sock.settimeout(0.5)
    member("remove", "mail_users", "bob")
    t0 = time.time()
    gone = False
    while time.time() - t0 < SLA_S + 4:
        try:
            line = i.sock.recv(4096)
            if not line or b"BYE" in line:
                gone = True
                break
        except socket.timeout:
            continue
        except OSError:
            gone = True
            break
    took = time.time() - t0
    LATENCY["leave_ends_idle_session"] = took
    print(f"LATENCY leave → IDLE session gone: {took:.1f} s", flush=True)
    assert gone and took <= SLA_S, f"bob's IDLE session lasted {took:.1f} s after leaving mail_users (SLA {SLA_S} s)"
    # The cut is the leave's: the Hub restarted mail (not a crash), and
    # audited the leave's revocation.
    until("mail running again after the Hub's restart", lambda: mail_started_at() != started
          and docker("inspect", "-f", "{{.State.Running}} {{.State.OOMKilled}}", pcid("stalwart")).strip() == "true false", 60)
    assert "mail_credential.revoke_leave" in json.dumps(hub_ok("GET", "/api/directory/audit")), "no mail_credential.revoke_leave in the audit"
    stage, code, text = until("RCPT bob@ refused 550 5.1.1", lambda: (lambda r: r if r[1] == 550 else None)(smtp25(REMOTE_ADDR, b)), 30, every=2)
    assert stage == "rcpt" and text.startswith("5.1.1"), f"RCPT {b}: {stage} {code} {text}"


def recreated_username_fresh_mailbox(browser) -> None:
    needs("bob_old_uuid")
    old = state["bob_old_uuid"]
    state["ctx_bob"].close()
    gql('mutation($u: String!) { deleteUser(userId: $u) { ok } }', {"u": "bob"})
    create_user("bob")
    new = uuid_of("bob")
    assert new != old, "the same uuid after re-creating bob"
    member("add", "mail_users", "bob")
    until("bob@ accepted at RCPT again", lambda: smtp25("probe@relay-test.example", f"bob@{DOMAIN}")[1] == 250, 240, every=5)
    ctx, page, auth = sign_in(browser, "bob")
    pw = create_mail_password(page, auth, "bob", "e2e bob again")
    i = imap_login(f"bob@{DOMAIN}", pw)
    typ, d = i.select("INBOX", readonly=True)
    n = int(d[0])
    i.logout()
    assert n == 0, f"the new bob's INBOX has {n} messages"
    assert imap_refused(f"bob@{DOMAIN}", state["pw_bob"]), "the old bob's password opens the new mailbox"
    former = (mailstatus().get("status") or {}).get("former") or []
    assert any(f.get("id") == f"former-{old}" or old in json.dumps(f) for f in former), f"former: {former}"
    ctx.close()


def restore_voids_mail_passwords(browser) -> None:
    with open(STATE_FILE) as f:
        st = json.load(f)
    pw = st["pw_alice"]
    mask(pw)
    a = f"alice@{DOMAIN}"
    # Stalwart first: the pre-restore password is refused by IMAP and SMTP.
    until("mail serving again after the restore", lambda: socket.create_connection(("127.0.0.1", 993), 5).close() is None, 180)
    assert imap_refused(a, pw), "a mail password from before the restore still logs in (IMAP)"
    try:
        submit(a, pw, a, [a], message(a, a, "e2e after restore"))
        raise AssertionError("a mail password from before the restore still authenticates (SMTP AUTH)")
    except smtplib.SMTPAuthenticationError:
        pass
    # Then the Hub's rows: reset by the restore.
    def voided():
        rows = hub_ok("GET", "/api/directory/users/alice/mail")["passwords"]
        live = [r for r in rows if r["status"] != "revoked"]
        return rows if live and all(r["status"] == "voided" for r in live) else None
    try:
        until("the Hub's rows voided after the restore", voided, 120, every=10)
    except AssertionError:
        raise AssertionError(f"Stalwart refuses the old password, but the Hub's rows aren't voided: "
                             f"{hub_ok('GET', '/api/directory/users/alice/mail')['passwords']}") from None
    audit = json.dumps(hub_ok("GET", "/api/directory/audit"))
    assert "mail_credential.void_restore" in audit, "no mail_credential.void_restore in the audit"
    ctx, page, _ = sign_in(browser, "alice")
    open_mail(page)
    assert "reset by a restore" in page.locator("[data-msi-mail-body]").first.inner_text(), "no 'reset by a restore' on the Sign-in page"
    ctx.close()


# ── the provider scenarios (mail provider plan Task 27) ──

FAKE = "mail-fake"
CONF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mail-conformance", "run.py")


def get_as(actor: str):
    return lambda path: hub_ok_as("GET", path, actor)


def hub_ok_as(method: str, path: str, actor: str, body=None, want=(200,)):
    code, ans = hub(method, path, body, actor=actor)
    assert code in want, f"{method} {path} as {actor}: HTTP {code} {scrub(json.dumps(ans))[:400]}"
    return ans


def run_op_as(actor: str, method: str, path: str, body=None, timeout: float = 900) -> dict:
    acc = e2e_ops.accepted(hub_ok_as(method, path, actor, body, want=(202,)))
    rec = e2e_ops.wait(get_as(actor), acc, timeout)
    return e2e_ops.check_ok(acc, rec)


def counter_ahead(page: Page) -> None:
    """The page's virtual authenticator ahead of every copy made so far:
    a popup's copy (mail passwords) raised Keycloak's stored signature
    counter past this page's, and Keycloak refuses a counter that goes
    back ("Malicious counter value is detected")."""
    auth = next((state.get("auth_" + k[5:]) for k in list(state) if k.startswith("page_") and state[k] is page), None)
    if auth is None:
        return
    state["sign_bump"] = state.get("sign_bump", 0) + 100000
    for c in auth.credentials():
        auth.cdp.send("WebAuthn.removeCredential", {"authenticatorId": auth.id, "credentialId": c["credentialId"]})
        auth.cdp.send("WebAuthn.addCredential", {"authenticatorId": auth.id,
                                                 "credential": dict(c, signCount=c.get("signCount", 0) + state["sign_bump"])})


def fresh_proof(page: Page, fa: dict, label: str) -> dict:
    """The Hub listener's fresh sign-in (prompt=login, max_age=0, PKCE
    S256), as the instance's Mail tab runs it: the wiring's proof. A
    container start or a network attach on the runner makes Chromium
    abort the navigation (net::ERR_NETWORK_CHANGED, raised by page.goto
    itself or left as chrome-error://): a new attempt with a new PKCE
    pair then, at most 4 in all, each noted in the job summary
    (e2e_mailcheck.network_retries; any other failure fails at once)."""
    return mailcheck.network_retries(lambda n: _fresh_proof(page, fa, label if n == 1 else f"{label}-retry{n - 1}"),
                                     base._note_retry, f"{label}: the fresh sign-in")


def _fresh_proof(page: Page, fa: dict, label: str) -> dict:
    counter_ahead(page)
    redirect = fa["redirect_uri"]
    seen: list[str] = []

    def on_request(r):
        if r.url.startswith(redirect + "?"):
            seen.append(r.url)

    page.on("request", on_request)
    try:
        return _fresh_proof_run(page, fa, label, seen)
    finally:
        page.remove_listener("request", on_request)


def _fresh_proof_run(page: Page, fa: dict, label: str, seen: list) -> dict:
    import hashlib
    import secrets as pysecrets
    import urllib.parse
    redirect = fa["redirect_uri"]
    verifier, nonce = pysecrets.token_urlsafe(48), pysecrets.token_urlsafe(16)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {"client_id": fa["client_id"], "response_type": "code", "scope": "openid", "redirect_uri": redirect,
         "state": pysecrets.token_urlsafe(12), "nonce": nonce, "code_challenge": challenge,
         "code_challenge_method": "S256", "prompt": "login", "max_age": "0"}
    if fa.get("pc_method"):
        q["pc_method"] = fa["pc_method"]
    page.goto(fa["authorize_url"] + "?" + urllib.parse.urlencode(q), wait_until="domcontentloaded")
    deadline = time.time() + 60
    while time.time() < deadline:
        for u in seen:
            code = urllib.parse.parse_qs(urllib.parse.urlsplit(u).query).get("code")
            if code:
                return {"code": code[0], "code_verifier": verifier, "nonce": nonce}
        if page.url.startswith("chrome-error://"):
            raise AssertionError(f"{label}: the fresh sign-in's page aborted (stuck at chrome-error://)")
        if page.url.startswith(AUTH) and page.locator("#authenticateWebAuthnButton").is_visible():
            page.click("#authenticateWebAuthnButton")
        page.wait_for_timeout(700)
    base.shot(page, f"{label}-fresh-timeout")
    raise AssertionError(f"{label}: no fresh-auth code (stuck at {page.url.split('?')[0]})")


def provider_view(inst: str, actor: str = "root") -> dict:
    return hub_ok_as("GET", f"/api/instances/{inst}/mail-provider", actor)


def ensure_fake_instance() -> None:
    """The CI-only mail-fake as an instance (created once, not wired)."""
    listed = hub_ok("GET", "/api/instances")
    if any((i.get("id") if isinstance(i, dict) else i) == FAKE for i in (listed if isinstance(listed, list) else listed.get("instances") or [])):
        return
    run_op_as("admin", "POST", "/api/instances", {"template": "mail-fake", "id": FAKE, "label": "Mail fake"}, 600)


def remote_off_egress() -> None:
    # The remote leaves stalwart's egress network (a stop / down removes it).
    docker("network", "disconnect", "portcullis-stalwart_egress", "e2e-remote", check_rc=False)


def remote_on_egress() -> None:
    docker("network", "connect", "--ip", REMOTE_IP, "portcullis-stalwart_egress", "e2e-remote", check_rc=False)


def rotate_when_set() -> None:
    """./portcullis mail rotate once the provider has its first set (a
    provider just wired answers "no set … yet" for a moment)."""
    last = ""
    for _ in range(36):
        p = run("./portcullis", "mail", "rotate", timeout=600, check_rc=False)
        if p.returncode == 0:
            return
        last = p.stdout + p.stderr
        if "no set for" not in last:
            break
        time.sleep(5)
    # What the Hub knows of the provider then (generation sent / applied,
    # reachable, void, hold): no secret in it.
    st = run("./portcullis", "mail", "status", "--json", timeout=120, check_rc=False).stdout
    save("rotate-failed-mail-status.json", st)
    try:
        h = json.loads(st).get("hub") or {}
        print("    hub view: " + json.dumps({k: h.get(k) for k in ("instance", "mode", "reachable", "generation", "applied_generation", "void_owed", "held")}), flush=True)
    except ValueError:
        print("    mail status --json unreadable", flush=True)
    raise AssertionError(f"./portcullis mail rotate: {scrub(last[-1500:])}")


def lan_only(on: bool, provider: str) -> None:
    """LAN-only is core's (MAIL_SUBMISSION_LAN_ONLY → core.env), set with
    mail enable --lan-only on the wired provider (no second install)."""
    # --provider none: the slot's settings only (the wired provider stays).
    run("./portcullis", "mail", "enable", "--lan-only", "true" if on else "false", "--provider", "none", "--yes", timeout=900)
    hub_answers()


def switch_to(inst: str) -> dict:
    """POST /api/mail/provider/switch as root: the typed id, the typed
    "<n> mailboxes start empty" (the Hub names n when it differs), a fresh
    proof each attempt."""
    if (hub_ok("GET", "/api/mail/status").get("provider") or {}).get("instance") == inst:
        return {}
    page = state["page_root"]
    phrase = state.get("empty_phrase", "0 mailboxes start empty")
    for _ in range(2):
        v = provider_view(inst)
        body = {"to": inst, "confirm": inst, "confirm_empty": phrase, **fresh_proof(page, v["fresh_auth"], f"switch-{inst}")}
        code, ans = hub("POST", "/api/mail/provider/switch", body, actor="root")
        txt = ans if isinstance(ans, str) else json.dumps(ans)
        m = re.search(r'(\d+) mailboxes start empty', txt)
        if code == 400 and m:
            phrase = state["empty_phrase"] = m.group(1) + " mailboxes start empty"
            continue
        assert code == 202, f"switch to {inst}: HTTP {code} {scrub(json.dumps(ans))[:400]}"
        acc = e2e_ops.accepted(ans)
        return e2e_ops.check_ok(acc, e2e_ops.wait(get_as("root"), acc, 1200))
    raise AssertionError(f"switch to {inst}: the typed phrase was refused twice")


def zone(name: str) -> list[dict]:
    body = json.dumps({"op": "get", "zone": name + ".", "token": "ci-fake-token-0123456789", "records": []}).encode()
    with urllib.request.urlopen(urllib.request.Request("http://172.30.87.53:8054", data=body,
                                                       headers={"Content-Type": "application/json"}), timeout=30) as r:
        return json.loads(r.read()).get("records") or []


def banner(port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as c:
        c.settimeout(5)
        try:
            return c.recv(64)
        except OSError:
            return b""


def switch_provider() -> None:
    """11: to mail-fake (honest): the sets replaced per domain (the old
    DKIM keys kept, retiring), every mail password row voided "the mail
    server changed on <date>" (a row made just before, under stalwart,
    included: this switch's own void), the ports reach the fake (no SMTP
    banner), stalwart stopped with its volumes, mail.provider_switched
    audited; then back (voids again)."""
    needs("setup")
    ensure_fake_instance()
    # Run 13 switched (and voided) before: this scenario's own row.
    until("stalwart wired before the switch", lambda: (hub_ok("GET", "/api/mail/status").get("provider") or {}).get("instance") == "stalwart", 300)
    pw_switch = create_mail_password(state["page_alice"], state["auth_alice"], "alice", "e2e switch")
    days = {time.strftime("%Y-%m-%d", time.gmtime())}
    old_dkim = {r["name"] for r in zone(DOMAIN) if r.get("type") == "TXT" and "._domainkey" in r.get("name", "")}
    remote_off_egress()
    try:
        switch_to(FAKE)
        until("the Hub says mail-fake is wired", lambda: (hub_ok("GET", "/api/mail/status").get("provider") or {}).get("instance") == FAKE, 120)
        rotate_when_set()
        names = {(r["name"], r["type"]) for r in zone(DOMAIN)}
        # The fake zone's names are relative to the zone (fake._domainkey).
        assert any(n == "fake._domainkey" or n.startswith("fake._domainkey.") for n, t in names if t == "TXT"), \
            f"the fake's DKIM key isn't published: {sorted(names)}"
        assert old_dkim and all((n, "TXT") in names or n.split(".", 1)[0] + "._domainkey" in {x.split(".", 1)[0] + "._domainkey" for x, _ in names}
                                for n in old_dkim), f"the old DKIM keys went at the switch: {sorted(old_dkim)} vs {sorted(names)}"
        rows = hub_ok("GET", "/api/directory/users/alice/mail").get("passwords") or []
        days.add(time.strftime("%Y-%m-%d", time.gmtime()))
        problem = mailcheck.switch_voided_problem(rows, days, must=("e2e switch",))
        assert problem is None, f"alice's rows after the switch: {problem}: {rows}"
        assert not banner(25).startswith(b"220"), "port 25 still answers like Stalwart"
        # The unwire is a compose down: nothing of stalwart runs, its
        # volumes stay.
        assert not running(PROVIDER_PROJECT), f"stalwart's containers still run after the switch: {running(PROVIDER_PROJECT)}"
        assert "stalwart_data" in docker("volume", "ls", "-q"), "stalwart's store volume went with the switch"
        assert "mail.provider_switched" in json.dumps(hub_ok("GET", "/api/directory/audit")), "no mail.provider_switched in the audit"
        state["switched"] = True
    finally:
        switch_to("stalwart")
        remote_on_egress()
    until("stalwart wired again", lambda: (hub_ok("GET", "/api/mail/status").get("provider") or {}).get("instance") == "stalwart", 120)
    st = hub_ok("GET", "/api/mail/status")
    assert not (st.get("provider") or {}).get("void"), f"a void still owed after the switch back: {(st.get('provider') or {}).get('void')}"
    assert imap_refused(f"alice@{DOMAIN}", state["pw_alice"]), "alice's old mail password survived two switches"
    assert imap_refused(f"alice@{DOMAIN}", pw_switch), "the mail password made before the switch survived it"


def hostile_provider_contained() -> None:
    """12: mail-fake in hostile mode while wired: none of its forbidden
    records reaches the zone (mail_records_wrong names them), no
    mass-removal document is sent, the wide allowed_ips row is revoked
    (mail_lan_only_unenforced), the failed void stops the instance
    (mail_void_pending)."""
    needs("setup")
    ensure_fake_instance()
    remote_off_egress()
    try:
        switch_to(FAKE)
        docker("exec", pcid("fake", "portcullis-" + FAKE), "mail-fake", "mode", "hostile")
        time.sleep(3)
        run("./portcullis", "mail", "rotate", timeout=600, check_rc=False)
        recs = zone(DOMAIN)
        bad = [r for r in recs if (r.get("type") == "A" and r.get("data") == "192.0.2.66") or "attacker" in json.dumps(r)
               or (r.get("name", "").startswith("_dmarc.") and "p=none" in r.get("data", ""))]
        assert not bad, f"forbidden records in the zone: {bad}"
        findings = json.dumps(hub_ok("GET", "/api/doctor"))
        assert "mail_records_wrong" in findings, "no mail_records_wrong finding"
        # LAN-only on: the provider answers 0.0.0.0/0 → the row is revoked.
        lan_only(True, FAKE)
        try:
            # A mail password made under LAN-only: the hostile provider
            # answers it 0.0.0.0/0, the Hub revokes it and names it (the
            # switch voided every earlier one, so this is the row judged).
            try:
                create_mail_password(state["page_alice"], state["auth_alice"], "alice", "e2e hostile lan")
            except AssertionError as e:
                print(f"    the hostile provider's password: {scrub(str(e))[:200]} (the Hub may refuse it at once)", flush=True)
            until("mail_lan_only_unenforced", lambda: "mail_lan_only_unenforced" in json.dumps(hub_ok("GET", "/api/doctor")), 180, every=10)
        finally:
            lan_only(False, FAKE)
        # A void that keeps a credential fails its verification: stopped.
        # A credential first (LAN-only off: the hostile provider keeps the
        # first one through any void), then a void owed: the slot's API
        # secret removed (only a void writes a fresh one; contract §19.11),
        # so the Mail tab's Retry runs one.
        create_mail_password(state["page_alice"], state["auth_alice"], "alice", "e2e hostile keep")
        docker("run", "--rm", "--network", "none", "-v", "portcullis_mail_provider_slot:/hs",
               "docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a",
               "rm", "-f", "/hs/api-secret")
        code, ans = hub("POST", "/api/mail/provider/retry-void", actor="root")
        assert code == 202, f"retry-void with the API secret gone: HTTP {code} {scrub(json.dumps(ans))[:300]} (want 202: a void owed)"
        try:
            e2e_ops.wait(get_as("root"), e2e_ops.accepted(ans), 600)
        except AssertionError as e:
            print(f"    the void op: {scrub(str(e))[:200]} (a failed verification is the expected end)", flush=True)
        until("mail_void_pending", lambda: "mail_void_pending" in json.dumps(hub_ok("GET", "/api/doctor")), 300, every=10)
        # A failed void stops it (compose down: no container left running).
        assert not running("portcullis-" + FAKE), f"the hostile provider still runs after a failed void: {running('portcullis-' + FAKE)}"
    finally:
        # Honest again for 16: the mode file in its data volume (the
        # failed void removed the container; a later start reads it).
        docker("run", "--rm", "--network", "none", "--user", "10011:10011", "-v", f"portcullis-{FAKE}_data:/d",
               "docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a",
               "sh", "-c", "echo honest > /d/mode", check_rc=False)
        switch_to("stalwart")
        remote_on_egress()


def wiring_guards() -> None:
    """13: wiring is refused without a fresh proof (403), with a wrong
    typed id (400), for an AI / MCP actor (403) and for a delegate (403);
    with all of them it succeeds (the CI-only source's template)."""
    needs("setup")
    ensure_fake_instance()
    page = state["page_root"]
    path = f"/api/instances/{FAKE}/mail-provider"
    code, _ = hub("PUT", path, {"wired": True, "confirm": FAKE}, actor="root")
    assert code == 403, f"no fresh proof: HTTP {code} (want 403)"
    v = provider_view(FAKE)
    code, _ = hub("PUT", path, {"wired": True, "confirm": "stalwart", **fresh_proof(page, v["fresh_auth"], "wire-typo")}, actor="root")
    assert code == 400, f"a wrong typed id: HTTP {code} (want 400)"
    # An AI / MCP actor: the Hub's Portcullis MCP has no tool that wires,
    # switches or unwires a provider (contract §19.9), and the listener
    # refuses outright when AI support is off.
    with open("secrets/mcp-gate/hub-secret") as f:
        mcp_secret = f.read().strip()
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode()
    req = urllib.request.Request(f"http://{state['hub_ip']}:8890/mcp/admin", data=data, method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2025-11-25",
        "X-Portcullis-MCP-Secret": mcp_secret, "X-Forwarded-User": "root",
        "X-Portcullis-AI-Client": "portcullis-ai-claude-code", "X-Portcullis-AI-Resource": f"https://hub.{DOMAIN}/mcp"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read().decode()
        tools = json.dumps(raw)
        assert not any(w in tools for w in ("mail_provider", "mail-provider", "switch_mail", "wire_mail", "unwire")), \
            "the Portcullis MCP lists a mail provider tool"
    except urllib.error.HTTPError as e:
        assert e.code in (403, 404, 503), f"the MCP listener: HTTP {e.code}"
    code, _ = hub("PUT", path, {"wired": True, "confirm": FAKE}, actor="alice")
    assert code == 403, f"a non-admin / delegate: HTTP {code} (want 403)"
    # Every guard met, but stalwart is wired: a second wiring is refused
    # (409, switch instead); the guarded switch then succeeds.
    v = provider_view(FAKE)
    code, ans = hub("PUT", path, {"wired": True, "confirm": FAKE, **fresh_proof(page, v["fresh_auth"], "wire-ok")}, actor="root")
    assert code == 409 and "switch" in json.dumps(ans), f"a second wiring: HTTP {code} {scrub(json.dumps(ans))[:300]} (want 409, switch instead)"
    remote_off_egress()
    try:
        switch_to(FAKE)
        assert (hub_ok("GET", "/api/mail/status").get("provider") or {}).get("instance") == FAKE, "the guarded switch didn't wire mail-fake"
    finally:
        switch_to("stalwart")
        remote_on_egress()


def template_change_holds() -> None:
    """14: the wired template's files change (a comment line), the Hub
    syncs: no container recreated, mail_provider_refused, the provider
    held (Ruling R-HH1: the running, confirmed containers keep taking the
    mail routes and documents); a re-wire clears the hold."""
    needs("setup")
    # Serving first (an earlier scenario's switch back may still be starting).
    until("stalwart serves before the change (GET /api/mail/checks 200)", lambda: hub("GET", "/api/mail/checks")[0] == 200, 300, every=5)
    before = {s: docker("inspect", "-f", "{{.Id}}", pcid(s)).strip() for s in ("stalwart", "adapter")}
    docker("run", "--rm", "--network", "none", "-v", "portcullis_hub_data:/d",
           "docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a",
           "sh", "-c", "echo '# e2e-mail 14' >> /d/repos/portcullis/stalwart/compose.yml")
    docker("kill", "-s", "HUP", docker("compose", "ps", "-q", "hub").strip())
    until("mail_provider_refused", lambda: "mail_provider_refused" in json.dumps(hub_ok("GET", "/api/doctor")), 180, every=5)
    after = {s: docker("inspect", "-f", "{{.Id}}", pcid(s)).strip() for s in ("stalwart", "adapter")}
    assert after == before, "a container was recreated on the template change"
    prov = (hub_ok("GET", "/api/mail/status").get("provider") or {})
    assert prov.get("held") is True, f"the provider isn't held: {scrub(json.dumps(prov))[:300]}"
    code, _ = hub("GET", "/api/mail/checks")
    assert code == 200, f"the mail routes answer {code} while held (R-HH1: the held provider still serves)"
    page = state["page_root"]
    v = provider_view("stalwart")
    remote_off_egress()
    try:
        run_op_as("root", "PUT", "/api/instances/stalwart/mail-provider",
                  {"wired": True, "confirm": "stalwart", "block_hash": v.get("block_hash", ""), **fresh_proof(page, v["fresh_auth"], "rewire")}, 900)
    finally:
        remote_on_egress()
    until("the hold cleared", lambda: "mail_provider_refused" not in json.dumps(hub_ok("GET", "/api/doctor")), 180, every=5)
    assert (hub_ok("GET", "/api/mail/status").get("provider") or {}).get("held") is False, "still held after the re-wire"
    code, _ = hub("GET", "/api/mail/checks")
    assert code == 200, f"the mail routes answer {code} after the re-wire"


def served_spki() -> str:
    """The sha256 of the mail certificate's key (core's mail_tls volume)."""
    pem = docker("run", "--rm", "--network", "none", "-v", "portcullis_mail_tls:/t:ro",
                 "docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a",
                 "cat", "/t/fullchain.pem")
    pub = subprocess.run(["openssl", "x509", "-pubkey", "-noout"], input=pem.encode(), capture_output=True, check=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "der"], input=pub, capture_output=True, check=True).stdout
    import hashlib
    return hashlib.sha256(der).hexdigest()


def conformance(level: str, inst: str, service: str) -> None:
    """The conformance suite against the wired provider, as the Hub (its
    pinned portcullis-mail-api address; the Hub stopped meanwhile), once
    the provider answers (a switch back just before may still be starting)."""
    until(f"{inst} answers the Hub (GET /api/mail/checks 200)", lambda: hub("GET", "/api/mail/checks")[0] == 200, 300, every=5)

    def serving():
        p = run("./portcullis", "mail", "status", "--json", timeout=120, check_rc=False)
        try:
            h = json.loads(p.stdout).get("hub") or {}
        except ValueError:
            return False
        return h.get("instance") == inst and h.get("reachable") is True and h.get("void_owed") is None and h.get("held") is None
    until(f"{inst} reachable, no void owed, not held (./portcullis mail status --json)", serving, 300, every=5)
    hub_cid = docker("compose", "ps", "-q", "hub").strip()
    docker("stop", hub_cid)
    try:
        args = ["--level", level, "--api-url", "http://172.31.255.19:8080", "--secret-file", "/hs/api-secret", "--spki", served_spki()]
        if level == "full":
            # The published ports through the runner's address (a container
            # can't reach the stack's 127.0.0.1).
            host = subprocess.run(["sh", "-c", "ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == \"src\") print $(i + 1)}'"],
                                  capture_output=True, text=True).stdout.strip()
            args += ["--smtp-host", host, "--imap-host", host]
        # The Hub's address on portcullis-mail-api (internal); the full
        # level also needs a route to the runner's published ports: the
        # default bridge as a second network.
        name = f"e2e-mail-conformance-{level}"
        docker("rm", "-f", name, check_rc=False)
        docker("create", "--name", name, "--user", "0:0", "--network", "portcullis-mail-api", "--ip", "172.31.255.18",
               "-v", "portcullis_mail_provider_slot:/hsv:ro", "-v", f"{os.path.dirname(CONF)}:/c:ro",
               "--entrypoint", "sh", "portcullis-group-gate", "-c",
               'mkdir -p /hs && cp /hsv/api-secret /hs/ && python3 /c/run.py "$@"', "x", *args)
        if level == "full":
            docker("network", "connect", "bridge", name)
        try:
            p = subprocess.run(["docker", "start", "-a", name], capture_output=True, text=True, timeout=600)
        finally:
            docker("rm", "-f", name, check_rc=False)
        save(f"conformance-{level}.txt", p.stdout + p.stderr)
        print(scrub(p.stdout), flush=True)
        assert p.returncode == 0, f"conformance {level} on {inst}: exit {p.returncode}: {scrub(p.stdout)[-600:]}"
    finally:
        docker("start", hub_cid)
        hub_answers()


def hub_answers() -> None:
    """The Hub's API answers again (after a stop / start; its address may
    have changed)."""
    def ok():
        state.pop("hub_ip", None)
        try:
            return hub("GET", "/api/mail/status")[0] == 200
        except OSError:
            return False
    until("the Hub's API answers", ok, 180, every=3)


def conformance_stalwart() -> None:
    """15: run.py --level full against the wired stalwart."""
    needs("setup")
    conformance("full", "stalwart", "adapter")


def conformance_fake_api() -> None:
    """16: run.py --level api against mail-fake, wired for the run."""
    needs("setup")
    ensure_fake_instance()
    remote_off_egress()
    try:
        switch_to(FAKE)
        conformance("api", FAKE, "fake")
    finally:
        switch_to("stalwart")
        remote_on_egress()


def report() -> int:
    failed = [r for r in results if not r[1]]
    for name, ok, msg in results:
        summary(f"- {'✅' if ok else '❌'} {name}" + (f": {msg[:300]}" if msg else ""))
    for k, v in LATENCY.items():
        summary(f"- LATENCY {k}: {v:.1f} s")
    return 1 if failed else 0


def main() -> int:
    os.makedirs(ART, exist_ok=True)
    state["hub_ip"] = hub_ip()
    phase = sys.argv[1] if len(sys.argv) > 1 else "main"
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            if phase == "restore":
                check("10 restore_voids_mail_passwords", lambda: restore_voids_mail_passwords(browser))
                return report()
            check("setup: people, mail domains, the team list, DKIM active, mail passwords", lambda: setup(browser))
            check("1 exchange_both_ways (dkim ed25519 + rsa, spf, dmarc; the DMARC report)", exchange_both_ways)
            check("2 enrolled_domain_alias", enrolled_domain_alias)
            check("3 gtube_rejected_at_data, between_thresholds_to_junk", spam)
            check("4 mail_password_flow", mail_password_flow)
            check("8 members_only_list", members_only_list)
            check("9 postmaster_to_admins", postmaster_to_admins)
            check("5 revoke_within_8s", revoke_within_8s)
            check("6 leave_ends_idle_session", leave_ends_idle_session)
            check("7 recreated_username_fresh_mailbox", lambda: recreated_username_fresh_mailbox(browser))
            check("13 wiring_guards", wiring_guards)
            check("11 switch_provider", switch_provider)
            check("12 hostile_provider_contained", hostile_provider_contained)
            check("14 template_change_holds", template_change_holds)
            check("15 conformance_stalwart", conformance_stalwart)
            check("16 conformance_fake_api", conformance_fake_api)
            if "pw_alice" in state:
                persist()
        finally:
            browser.close()
    return report()


if __name__ == "__main__":
    sys.exit(main())
