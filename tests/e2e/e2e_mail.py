#!/usr/bin/env python3
"""End-to-end: Portcullis mail on a real stack with a second mail server
(contract §19; mail plan Task 12).

Runs in CI (job `e2e-mail` in .github/workflows/ci.yml): the whole core
stack + the Hub (same-named Hub branch) + domains (Pebble, the fake
provider; ONE fake zone shared with the dns tool and mail-cert), mail on
for ci.example.org and the enrolled team-b.test, and a remote Stalwart
(e2e-mail-remote.sh: remote.test, account carla) on mail-egress. Nothing
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
import e2e_mailremote as remote  # noqa: E402

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


def imap_refused(user: str, pw: str, host: str = "127.0.0.1") -> bool:
    try:
        imap_login(user, pw, host).logout()
        return False
    except (imaplib.IMAP4.error, OSError):
        return True


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
    return until(f"{subject!r} in {folder}", got, seconds, every=3)


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
        st = json.loads(docker("run", "--rm", "--network", "none", "-v", "portcullis_mailctl_data:/d:ro",
                               "docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a",
                               "cat", "/d/state.json"))
        save("mailctl-view.json", {"domains": [{k: d.get(k) for k in ("name", "mail", "dmarc_start")} for d in (st.get("doc") or {}).get("domains") or []],
                                   "generation": st.get("generation"), "applied_generation": st.get("applied_generation"),
                                   "errors": st.get("errors"), "dkim": json.loads(json.dumps((st.get("ext") or {}).get("dkim")))})
        for k in ((st.get("ext") or {}).get("dkim") or {}).get("keys") or []:
            if k.get("domain") != EXTRA:
                continue
            name = f"{k['selector']}._domainkey.{EXTRA}"
            for srv in (["-p", "5353", "@127.0.0.1"], ["-p", "8053", "@172.30.87.53"]):
                out = docker("compose", "--profile", "mail", "exec", "-T", "mail-resolver", "drill", *srv, "TXT", name, check_rc=False)
                ans = [ln for ln in out.splitlines() if "\tTXT\t" in ln or "rcode" in ln]
                print(f"    drill {srv[-1]} {name}: {ans[:3]}", flush=True)
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
    # The address set again now that mailctl holds the Hub's document: the
    # dns tool gets mail_hostname only with the mail set, and MAIL_HOSTNAME's
    # own A (its HELO SPF / CAA hide the wildcard) is written then.
    run("./portcullis", "dns", "setup", "--yes", "--only", "address", timeout=900)
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
    wait_mail(lambda: imap_login(f"alice@{DOMAIN}", state["pw_alice"]), subj2)
    # A forged message from ci.example.org straight into the remote's 25
    # (the runner's address: neither SPF nor DKIM aligned), so its
    # aggregate report carries a failure.
    smtp25(f"forger@{DOMAIN}", REMOTE_ADDR, message(f"forger@{DOMAIN}", REMOTE_ADDR, "e2e forged"),
           host=REMOTE_IP, helo="forger.example")
    j = remote_jmap()

    def forced():
        due = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 5))
        tasks = [t for t in j.get_all("Task") if t.get("@type") in ("DmarcReport", "ReportWindow")]
        for t in tasks:
            st = t.get("status") or {}
            if st.get("@type") in ("Pending", "Retry"):
                j.set("Task", update={t["id"]: {"status": {"@type": "Pending", "due": due}}})
        return tasks

    until("the remote's DMARC report task", forced, 120, every=5)

    def in_checks():
        forced()
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
        r = next((x for x in c.get("checks") or [] if x.get("id") == "spam_rules"), None)
        return r if r and r.get("severity") == "ok" else None
    until("the spam rules imported (check spam_rules ok)", rules_in, 300, every=65)
    gtube = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
    stage, code, text = smtp25("probe@relay-test.example", f"bob@{DOMAIN}",
                               message("probe@relay-test.example", f"bob@{DOMAIN}", "e2e gtube", gtube + "\r\n"))
    assert stage == "data" and code == 550 and text.startswith("5.7.1"), f"GTUBE: {stage} {code} {text}"
    print(f"    gtube_rejected_at_data: {code} {text[:80]}", flush=True)
    subj = f"URGENT OFFER {uuidlib.uuid4().hex[:6].upper()}"
    # No Date / Message-ID / MIME-Version, all-caps subject: 5 < score < 15
    # (MISSING_DATE 1, MISSING_MID 2.5, MISSING_MIME_VERSION 2,
    # SUBJ_ALL_CAPS 3; SPF / DKIM / DMARC pass through the remote).
    remote_send(f"bob@{DOMAIN}", message(REMOTE_ADDR, f"bob@{DOMAIN}", subj, "buy now\r\n", plain=True))

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
    save("junk-headers.txt", raw.decode(errors="replace"))
    print(f"    between_thresholds_to_junk: {json.dumps(xs)[:300]}", flush=True)


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
    # The management listener: 404 from another portcullis-mail address;
    # from mailctl's own address Basic auth authenticates but the method
    # is forbidden (mailctl stopped meanwhile: its address is pinned).
    curl = "docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93"
    body = json.dumps({"using": remote.USING, "methodCalls": [["x:Account/get", {"ids": None}, "0"]]})
    tok = base64.b64encode(f"{a}:{pw}".encode()).decode()

    def mgmt(ip: str) -> str:
        p = subprocess.run(["docker", "run", "--rm", "-i", "--network", "portcullis-mail", "--ip", ip, "--entrypoint", "sh", curl,
                            "-c", 'read -r h; printf "Authorization: Basic %s\\n" "$h" > /tmp/h; '
                                  'curl -s -H @/tmp/h -H "Content-Type: application/json" -d "$0" -w "\\n%{http_code}" http://172.31.255.2:8080/jmap', body],
                           input=tok + "\n", capture_output=True, text=True, timeout=60)
        return p.stdout
    out = mgmt("172.31.255.9")
    assert out.strip().endswith("404"), f"from 172.31.255.9: {scrub(out)[-300:]}"
    docker("compose", "--profile", "mail", "stop", "mailctl")
    try:
        out = mgmt("172.31.255.3")
    finally:
        docker("compose", "--profile", "mail", "start", "mailctl")
    lines = out.strip().splitlines()
    assert lines and lines[-1] == "200" and "forbidden" in out, f"from mailctl's address: {scrub(out)[-400:]}"
    until("mailctl healthy again", lambda: docker("inspect", "-f", "{{.State.Health.Status}}",
                                                   docker("compose", "ps", "-q", "mailctl").strip()).strip() == "healthy", 120)
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
    subj = f"e2e postmaster {uuidlib.uuid4().hex[:8]}"
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
    return docker("inspect", "-f", "{{.State.StartedAt}}", docker("compose", "ps", "-q", "mail").strip()).strip()


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
          and docker("inspect", "-f", "{{.State.Running}} {{.State.OOMKilled}}", docker("compose", "ps", "-q", "mail").strip()).strip() == "true false", 60)
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
    rows = hub_ok("GET", "/api/directory/users/alice/mail")["passwords"]
    assert rows and all(r["status"] == "voided" for r in rows if r["status"] != "revoked"), f"after the restore: {rows}"
    audit = json.dumps(hub_ok("GET", "/api/directory/audit"))
    assert "mail_credential.void_restore" in audit, "no mail_credential.void_restore in the audit"
    assert imap_refused(a, pw), "a mail password from before the restore still logs in"
    ctx, page, _ = sign_in(browser, "alice")
    open_mail(page)
    assert "reset by a restore" in page.locator("[data-msi-mail-body]").first.inner_text(), "no 'reset by a restore' on the Sign-in page"
    ctx.close()


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
            if "pw_alice" in state:
                persist()
        finally:
            browser.close()
    return report()


if __name__ == "__main__":
    sys.exit(main())
