#!/usr/bin/env python3
"""End-to-end: Firefox Sync + own accounts (the templates repo's
firefox-sync-fxa) with real mail and the real Hub (plan
2026-11-24-firefox-sync-own-accounts, Task 18).

Runs in CI (job `e2e-fxa` in .github/workflows/ci.yml): e2e-mail's stack
(.github/ci/e2e-mail-start-stack.sh: the whole core stack, the Hub built
from the same-named Hub branch, the stalwart template wired for
ci.example.org, Pebble, the shared fake zone) plus the templates repo's
firefox-sync-fxa (same-named templates branch) as a local source, and
e2e-mail's remote Stalwart (remote.test): every person's mailbox is there,
so each code crosses the internet's path (Portcullis's submission listener
with the sender's password and STARTTLS, its outbound queue, the remote's
MX, which checks DKIM / SPF / DMARC). Nothing leaves the runner (outbound
25 / 465 / 587 is rejected outside the stack's networks).
Containers resolve the e2e hostnames to the runner (.github/ci/e2e-fxa-dns.sh):
fxa-auth and the Hub reach mail.<d>:587 as on a real server, and trust
Pebble's root through certs/ca-bundle.crt.

People: alice, bob (the access group users_firefox-sync-fxa), carol (not
in it), root (lldap_admin, both groups, the admin UI); alice and carol in
mail_users; every email at remote.test.

Scenarios (in this order):
  setup                        people, mail on with DKIM active, remote
                               mailboxes, the instance enabled and routed
  email_verify_by_code         alice asks for a code (her People page's
                               route on people.<d>): a message from
                               portcullis-hub-mail@<d> (dkim=pass) reaches
                               her INBOX; her code → email_verified
  unverified_not_listed        bob (group, unverified) is the one member
                               without a verified email on the instance
                               page; his sign-up is refused (errno 125), no
                               account
  signup_code_via_provider     alice's sign-up: within 120 s a message from
                               portcullis-app-firefox-sync-fxa@<d> with
                               dkim=pass reaches her INBOX; its code
                               verifies the account
  nonmember_refused            carol (admin-verified, not in the group):
                               refused, no account, no code sent
  leave_disables_via_hub       alice removed through the Hub: within 180 s
                               her session token answers 401
  rejoin_enables_via_hub       alice added again: within 180 s she signs in
  email_change_disables        alice's email changed in LLDAP: within the
                               periodic run (10 min) her account is
                               disabled and neither address is listed; the
                               new one shows as unverified
  email_changed_in_fxa_before_block  SKIPPED until porelli/firefox-sync
                               publishes ffs.disable_accounts_not_allowed
  admin_disable_survives_routine_run  bob admin-verified and signed up; the
                               admin UI (root: Portcullis sign-in, its OIDC
                               sign-in) disables him; the settings Retry
                               (POST /api/instances/<id>/settings/retry)
                               runs the access-sync hook; bob stays disabled
  bypass_badges                4 whole-host badges (public@file, their
                               hosts.reasons), the accounts host's 4 paths,
                               the sign-up and token routers (their host's
                               reason)
  mail_unwired_refuses         the provider unwired: mail_sender_unwired
                               listed, POST /api/me/email/verify 409, the
                               instance's restart stops at fxa-mail-check
                               (exit 1)

Environment: as e2e_mail.py (E2E_DOMAIN, E2E_HUB_SECRET, E2E_MAIL_CA,
LLDAP_ADMIN_PASSWORD, REMOTE_ADMIN, REMOTE_PASSWORD, REMOTE_USER,
E2E_ARTIFACTS) plus REQUESTS_CA_BUNDLE (core's CA chain, for PyFxA).
Every password, code and token is masked (::add-mask::) as soon as it is
known and never printed; PyFxA's session tokens stay in memory. No
Playwright traces.
"""
from __future__ import annotations

import email
import email.policy
import email.utils
import imaplib
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_login as base  # noqa: E402  (passkey_flow, shot)
import e2e_mail as m  # noqa: E402  (hub_ok, member, gql, imap_login, until, mask, sign_in)
import e2e_ops  # noqa: E402  (the Hub's 202 op records)
import scenarios  # noqa: E402  (E2E_SCENARIOS)

from fxa.core import Client  # noqa: E402  (PyFxA, tests/e2e/requirements-fxa.txt)
from fxa.errors import ClientError, ServerError  # noqa: E402
from playwright.sync_api import Error as PWError  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

DOMAIN = m.DOMAIN
INST = "firefox-sync-fxa"
PROJECT = "portcullis-" + INST
ACCESS = "users_" + INST
ADMIN_GROUP = "admin_" + INST
API = f"https://{INST}-api.{DOMAIN}"
ADMIN = f"https://{INST}-admin.{DOMAIN}"
HUB_SENDER = f"portcullis-hub-mail@{DOMAIN}"
APP_SENDER = f"portcullis-app-{INST}@{DOMAIN}"
REMOTE_IP = m.REMOTE_IP
MAILBOXES = ("alice", "bob", "carol", "alice2")
SWEEP_SKIP = ("waits for porelli/firefox-sync's ffs.disable_accounts_not_allowed(p_max) (an image with it isn't "
              "published yet): an account whose email was changed inside FxA before the gate refused it is "
              "disabled by the sweep only")

state: dict = m.state  # e2e_mail's helpers (hub_ip, lldap token) read the same dict
needs = m.needs
mask = m.mask
results: list[tuple[str, str, str]] = []
LATENCY: dict[str, float] = {}


class Skipped(Exception):
    """A scenario that can't run yet (its reason is the message)."""


def check(name: str, fn) -> None:
    if scenarios.skip(name):  # E2E_SCENARIOS (tests/e2e/scenarios.py)
        return
    try:
        fn()
        results.append((name, "pass", ""))
        print(f"PASS: {name}", flush=True)
    except Skipped as e:
        results.append((name, "skip", str(e)))
        print(f"SKIP: {name}: {e}", flush=True)
    except Exception as e:  # noqa: BLE001
        msg = m.scrub(f"{type(e).__name__}: {e}")
        results.append((name, "fail", msg))
        print(f"FAIL: {name}: {msg}", flush=True)
        print(m.scrub(traceback.format_exc()), flush=True)


def report() -> int:
    mark = {"pass": "✅", "fail": "❌", "skip": "⏭️"}
    for name, res, msg in results:
        m.summary(f"- {mark[res]} {name}" + (f": {msg[:300]}" if msg else ""))
    for k, v in LATENCY.items():
        m.summary(f"- LATENCY {k}: {v:.1f} s")
    return 1 if any(r == "fail" for _, r, _ in results) else 0


def latency(what: str, t0: float) -> None:
    LATENCY[what] = time.time() - t0
    print(f"    LATENCY {what}: {LATENCY[what]:.1f} s", flush=True)


# ── the Hub ──

def people_api(method: str, path: str, user: str, body=None):
    """The people listener (:8889) as Traefik calls it for user's browser
    (proxy secret + identity): the routes the People page uses."""
    data = json.dumps(body if body is not None else {}).encode()
    req = urllib.request.Request(f"http://{state['hub_ip']}:8889{path}", data=data, method=method, headers={
        "X-Portcullis-Proxy-Secret": m.SECRET, "X-Forwarded-User": user, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            code, raw = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read().decode()
    try:
        return code, json.loads(raw) if raw else ""
    except ValueError:
        return code, raw


def get(path: str):
    return m.hub_ok("GET", path)


def directory_user(u: str) -> dict:
    for x in get("/api/directory").get("users") or []:
        if x.get("username") == u:
            return x
    raise AssertionError(f"{u} isn't in GET /api/directory")


def panel() -> dict:
    return get(f"/api/instances/{INST}/settings")


def no_verified() -> list:
    return sorted((panel().get("population") or {}).get("no_verified_email") or [])


def admin_verify(u: str) -> None:
    m.hub_ok("POST", f"/api/directory/users/{u}/email/verified", {}, want=(200, 204))


def set_lldap_email(u: str, addr: str) -> None:
    m.gql("mutation($u: UpdateUserInput!) { updateUser(user: $u) { ok } }", {"u": {"id": u, "email": addr}})


# ── the instance's accounts database (read-only checks, as root inside
# fxa-db: the password stays in that container's environment) ──

def cid(service: str) -> str:
    out = m.docker("ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}",
                   "--filter", f"label=com.docker.compose.service={service}").split()
    return out[0] if out else ""


def sql(query: str) -> str:
    c = cid("fxa-db")
    assert c, "no fxa-db container"
    p = subprocess.run(["docker", "exec", "-i", c, "sh", "-c",
                        'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql --no-defaults -uroot -h127.0.0.1 --batch -N'],
                       input=query, capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, f"mysql: rc {p.returncode}: {m.scrub(p.stderr[-400:])}"
    return p.stdout.strip()


def allowlist() -> list[str]:
    return sorted(x for x in sql("SELECT entry FROM ffs.signup_allowlist ORDER BY entry;").splitlines() if x)


def account(addr: str) -> str:
    """<accounts>:<disabled 1/0, x = none>:<email verified 1/0, x = none>."""
    assert re.fullmatch(r"[a-z0-9.]+@[a-z0-9.]+", addr), addr
    return sql("SELECT CONCAT(COUNT(*), ':', IFNULL(MAX(disabledAt IS NOT NULL), 'x'), ':', IFNULL(MAX(emailVerified), 'x')) "
               f"FROM fxa.accounts WHERE normalizedEmail = '{addr}';")


# ── the remote mailboxes (remote.test, every person's) ──

def remote_login(user: str) -> imaplib.IMAP4_SSL:
    return m.imap_login(f"{user}@remote.test", state[f"mbox_{user}"], REMOTE_IP)


def inbox_uids(user: str) -> set[int]:
    i = remote_login(user)
    try:
        i.select("INBOX", readonly=True)
        typ, d = i.uid("search", None, "ALL")
        return {int(x) for x in (d[0] or b"").split()}
    finally:
        i.logout()


def new_messages(user: str, seen: set[int]) -> list[email.message.Message]:
    i = remote_login(user)
    try:
        i.select("INBOX", readonly=True)
        typ, d = i.uid("search", None, "ALL")
        out = []
        for uid in sorted({int(x) for x in (d[0] or b"").split()} - seen):
            typ, msg = i.uid("fetch", str(uid), "(BODY.PEEK[])")
            out.append(email.message_from_bytes(msg[0][1], policy=email.policy.compat32))
        return out
    finally:
        i.logout()


def from_addr(msg) -> str:
    return email.utils.parseaddr(msg.get("From", ""))[1].lower()


def wait_from(user: str, seen: set[int], sender: str, seconds: float):
    """The first new message in user's INBOX from sender."""
    def got():
        for msg in new_messages(user, seen):
            if from_addr(msg) == sender:
                return msg
        return None
    return m.until(f"a message from {sender} in {user}@remote.test's INBOX", got, seconds, every=3)


def dkim_pass(msg, domain: str) -> str:
    """The remote's Authentication-Results: dkim=pass for header.d=domain."""
    ar = " ".join(msg.get_all("Authentication-Results") or [])
    passes = [p for p in re.findall(r"dkim=pass[^;]*", ar) if f"header.d={domain}" in p]
    assert passes, f"no dkim=pass for {domain}: {ar[:600]}"
    return passes[0]


def no_message_from(user: str, seen: set[int], sender: str, seconds: float) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        got = [x for x in new_messages(user, seen) if from_addr(x) == sender]
        assert not got, f"{user} got a message from {sender}: {got[0].get('Subject')!r}"
        time.sleep(5)


# ── Firefox's side (PyFxA through Traefik and fxa-gate) ──

def fxa() -> Client:
    return Client(API)


def fxa_code(msg) -> tuple[str, str]:
    for h in ("X-Verify-Code", "X-Signin-Verify-Code", "X-Verify-Short-Code", "X-Signin-Verify-Short-Code"):
        v = (msg.get(h) or "").strip()
        if v:
            mask(v)
            return h, v
    raise AssertionError(f"the accounts mail carries no code header (template {msg.get('X-Template-Name')!r})")


def verify_session(session, msg) -> None:
    h, code = fxa_code(msg)
    if h in ("X-Verify-Code", "X-Signin-Verify-Code"):
        session.verify_email_code(code)
    else:
        session.apiclient.post("/session/verify_code", {"code": code}, auth=session._auth)


def refused_errno(fn) -> tuple[int, int]:
    try:
        fn()
    except (ClientError, ServerError) as e:
        return getattr(e, "code", 0), getattr(e, "errno", 0)
    raise AssertionError("the accounts server accepted it")


def session_status(session) -> int:
    try:
        session.check_session_status()
        return 200
    except ClientError as e:
        return getattr(e, "code", 0)


def signup(user: str, addr: str) -> None:
    """user creates their account at addr and verifies it with the mailed
    code (within 120 s): state[f"fxa_{user}"] the session."""
    pw = state.setdefault(f"fxapw_{user}", secrets.token_urlsafe(18))
    mask(pw)
    seen = inbox_uids(user)
    t0 = time.time()
    session = fxa().create_account(addr, pw)
    msg = wait_from(user, seen, APP_SENDER, 120)
    latency(f"{user}'s sign-up code at the remote", t0)
    d = dkim_pass(msg, DOMAIN)
    print(f"    {user}'s code: From {msg.get('From')!r}, {d}", flush=True)
    verify_session(session, msg)
    assert session.get_email_status().get("verified") is True, "the account isn't verified after its code"
    state[f"fxa_{user}"] = session


# ── setup ──

def remote_accounts() -> None:
    """A remote.test mailbox per person (the plan's role and domain)."""
    j = m.remote_jmap()
    dom = next(d["id"] for d in j.get_all("Domain") if d.get("name") == "remote.test")
    role = next(r["id"] for r in j.get_all("Role") if r.get("description") == "remote-user")
    have = {a.get("name") for a in j.get_all("Account")}
    create = {}
    for u in MAILBOXES:
        pw = state.setdefault(f"mbox_{u}", secrets.token_hex(16))
        mask(pw)
        if u not in have:
            create[u] = {"@type": "User", "name": u, "domainId": dom, "description": "e2e-fxa",
                         "credentials": {"0": {"@type": "Password", "secret": pw}},
                         "roles": {"@type": "Custom", "roleIds": {role: True}}}
    if create:
        j.set("Account", create=create)
    for u in MAILBOXES:
        m.until(f"{u}@remote.test's IMAP login", lambda u=u: inbox_uids(u) is not None, 60)


def dkim_active() -> bool:
    m.run("./portcullis", "mail", "rotate", timeout=600)
    ks = (m.mailstatus().get("status") or {}).get("dkim") or []
    act = {k["algorithm"] for k in ks if k.get("domain") == DOMAIN and k.get("stage") == "active"}
    if {"ed25519", "rsa"} <= act:
        return True
    print("    DKIM keys: " + ", ".join(f"{k['domain']} {k['algorithm']} {k['stage']}" for k in ks), flush=True)
    return False


def setup() -> None:
    state["lldap"] = m.lldap_token()
    for u in ("alice", "bob", "carol", "root"):
        m.gql("mutation($u: CreateUserInput!) { createUser(user: $u) { id } }", {"u": {"id": u, "email": f"{u}@remote.test"}})
    gid = next(g["id"] for g in m.gql("{ groups { id displayName } }")["groups"] if g["displayName"] == "lldap_admin")
    m.gql("mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }", {"u": "root", "g": gid})
    remote_accounts()
    m.hub_ok("PUT", f"/api/mail/domains/{DOMAIN}", {"enabled": True, "groups": []}, want=(200, 204))
    m.until("mail_users made by the Hub", lambda: any(g["displayName"] == "mail_users" for g in m.gql("{ groups { id displayName } }")["groups"]), 60)
    for u in ("alice", "carol"):
        m.member("add", "mail_users", u)
    # The Hub's and the app's senders sign with the main domain's keys: the
    # remote's dkim=pass needs them active (published, both resolvers).
    m.until(f"DKIM ed25519 + rsa active on {DOMAIN}", dkim_active, 420, every=10)
    # The template's sizes are a warning, never a refusal.
    t0 = time.time()
    code, acc = m.hub("POST", "/api/templates/enable", {"id": INST}, timeout=300)
    assert code == 202, f"enable {INST}: HTTP {code}: {m.scrub(str(acc))[:600]}"
    rec = e2e_ops.wait_ok(get, e2e_ops.accepted(acc, "enable", INST), 2400, every=5)
    latency(f"{INST} enabled", t0)
    print(f"    enable warnings: {json.dumps(rec.get('warnings'))[:400]}", flush=True)
    # The instance's groups: made by the enable (else as the Apps page's
    # banner would, by name).
    have = {g["displayName"] for g in m.gql("{ groups { id displayName } }")["groups"]}
    for g in (ACCESS, ADMIN_GROUP):
        if g not in have:
            print(f"    {g} not made by the enable: creating it", flush=True)
            m.hub_ok("POST", "/api/directory/groups", {"name": g}, want=(200, 201))
    for u in ("alice", "bob", "root"):
        m.member("add", ACCESS, u)
    m.member("add", ADMIN_GROUP, "root")
    # root's email verified by the admin (an admin can't verify their own):
    # bob is then the access group's one member without a verified email.
    admin_verify("root")
    # fxa-mail-check found the provider's sender (its one line: no secret).
    out = m.docker("logs", cid("fxa-mail-check"), check_rc=False, timeout=60).strip()
    print(f"    fxa-mail-check: {m.scrub(out)[:300]}", flush=True)
    assert "portcullis: mail: " in out and "mail." + DOMAIN + ":587, STARTTLS" in out, f"fxa-mail-check: {m.scrub(out)[:400]}"
    # Routed: the open API host answers through Traefik and fxa-gate.
    def heartbeat():
        req = urllib.request.Request(API + "/__heartbeat__")
        with urllib.request.urlopen(req, timeout=20, context=CA) as r:
            return r.status == 200
    m.until(f"{API}/__heartbeat__ through Traefik", heartbeat, 600, every=5)
    state["setup"] = True


# ── scenarios ──

def email_verify_by_code() -> None:
    needs("setup")
    assert directory_user("alice").get("email_verified") is False, "alice is verified before her code"
    seen = inbox_uids("alice")
    t0 = time.time()
    code, out = people_api("POST", "/api/me/email/verify", "alice")
    assert code == 202 and isinstance(out, dict) and out.get("expires_at"), f"POST /api/me/email/verify: HTTP {code} {m.scrub(str(out))[:300]}"
    msg = wait_from("alice", seen, HUB_SENDER, 120)
    latency("the Hub's code at the remote", t0)
    assert msg.get("Subject") == "Your Portcullis email code", f"subject {msg.get('Subject')!r}"
    print(f"    the Hub's code: From {msg.get('From')!r}, {dkim_pass(msg, DOMAIN)}", flush=True)
    body = " ".join(part.get_payload(decode=True).decode(errors="replace") for part in msg.walk()
                    if part.get_content_type() == "text/plain")
    got = re.search(r"Your code is (\d{8})\.", body)
    assert got, "no 8-digit code in the Hub's message"
    mask(got.group(1))
    code, out = people_api("POST", "/api/me/email/verify/confirm", "alice", {"code": got.group(1)})
    assert code == 200 and out == {"verified": True}, f"confirm: HTTP {code} {m.scrub(str(out))[:300]}"
    assert directory_user("alice").get("email_verified") is True, "alice isn't email_verified after her code"
    state["alice_verified"] = True


def unverified_not_listed() -> None:
    needs("setup")
    m.until("bob, the one member without a verified email, on the instance page",
            lambda: no_verified() == ["bob"] or (print(f"    no_verified_email: {no_verified()}", flush=True) and False), 180, every=5)
    st, errno = refused_errno(lambda: fxa().create_account("bob@remote.test", secrets.token_urlsafe(18)))
    assert (st, errno) == (400, 125), f"bob's sign-up: HTTP {st} errno {errno} (want 400 errno 125)"
    assert account("bob@remote.test").startswith("0:"), f"bob has an account: {account('bob@remote.test')}"
    assert "bob@remote.test" not in allowlist(), "bob is on the sign-up list"


def signup_code_via_provider() -> None:
    needs("alice_verified")
    t0 = time.time()
    m.until("alice@remote.test on the sign-up list (the access sync)", lambda: "alice@remote.test" in allowlist(), 660, every=10)
    latency("alice's verified email on the sign-up list", t0)
    signup("alice", "alice@remote.test")
    assert account("alice@remote.test") == "1:0:1", f"alice's account: {account('alice@remote.test')}"
    state["alice_signed_up"] = True


def nonmember_refused() -> None:
    needs("setup")
    admin_verify("carol")
    assert directory_user("carol").get("email_verified") is True, "carol isn't admin-verified"
    seen = inbox_uids("carol")
    st, errno = refused_errno(lambda: fxa().create_account("carol@remote.test", secrets.token_urlsafe(18)))
    assert (st, errno) == (400, 125), f"carol's sign-up: HTTP {st} errno {errno} (want 400 errno 125)"
    assert account("carol@remote.test").startswith("0:"), f"carol has an account: {account('carol@remote.test')}"
    assert "carol@remote.test" not in allowlist(), "carol (not in the group) is on the sign-up list"
    no_message_from("carol", seen, APP_SENDER, 45)


def leave_disables_via_hub() -> None:
    needs("alice_signed_up")
    s = state["fxa_alice"]
    assert session_status(s) == 200, "alice's session isn't live before she leaves"
    t0 = time.time()
    m.member("remove", ACCESS, "alice")
    m.until("alice's session token answers 401", lambda: session_status(s) == 401, 180, every=3)
    latency("leave → 401", t0)
    assert account("alice@remote.test") == "1:1:1", f"alice's account: {account('alice@remote.test')}"
    assert "alice@remote.test" not in allowlist(), "alice is still on the sign-up list"
    state["alice_left"] = True


def rejoin_enables_via_hub() -> None:
    needs("alice_left")
    t0 = time.time()
    m.member("add", ACCESS, "alice")
    m.until("alice's account enabled and listed again",
            lambda: account("alice@remote.test") == "1:0:1" and "alice@remote.test" in allowlist(), 180, every=3)

    def sign_in():
        seen = inbox_uids("alice")
        s = fxa().login("alice@remote.test", state["fxapw_alice"])
        assert session_status(s) == 200, "the new session isn't live"
        return s, seen
    s, seen = m.until("alice signs in", sign_in, max(30, 180 - (time.time() - t0)), every=15)
    latency("rejoin → signed in", t0)
    assert time.time() - t0 <= 180, f"signed in after {time.time() - t0:.0f} s (want ≤ 180)"
    if not s.verified:
        # A new session of a verified account: the sign-in code, if one came.
        for msg in new_messages("alice", seen):
            if from_addr(msg) == APP_SENDER and any(msg.get(h) for h in ("X-Signin-Verify-Code", "X-Signin-Verify-Short-Code")):
                verify_session(s, msg)
                break
    state["fxa_alice"] = s
    state["alice_back"] = True


def email_change_disables() -> None:
    needs("alice_back")
    s = state["fxa_alice"]
    assert session_status(s) == 200, "alice's session isn't live before the change"
    t0 = time.time()
    set_lldap_email("alice", "alice2@remote.test")
    # The Hub sees the LLDAP change, drops the verification and the
    # periodic membership run (10 min) delivers her absence.
    m.until("alice's session token answers 401", lambda: session_status(s) == 401, 660, every=10)
    latency("LLDAP email change → 401", t0)
    assert account("alice@remote.test").split(":")[1] == "1", f"alice's account: {account('alice@remote.test')}"
    lst = allowlist()
    assert "alice@remote.test" not in lst and "alice2@remote.test" not in lst, f"listed: {lst}"
    assert "alice" in no_verified(), f"alice's new email isn't shown as unverified: {no_verified()}"
    assert directory_user("alice").get("email_verified") is False, "alice's new email is verified"


def email_changed_in_fxa_before_block() -> None:
    raise Skipped(SWEEP_SKIP)


def admin_ui_overview(page) -> None:
    m.goto(page, ADMIN + "/auth/login", "the admin UI's sign-in")
    deadline = time.time() + 150
    while time.time() < deadline:
        if base.on_login_pages(page):
            base.passkey_flow(page, until=ADMIN, label="root-admin-ui", expect_stepups=0)
            continue
        try:
            if page.url.startswith(ADMIN) and "Access managed elsewhere" in page.content():
                return
        except PWError:
            pass
        page.wait_for_timeout(1000)
    base.shot(page, "admin-ui-overview")
    raise AssertionError(f"no admin UI overview (at {page.url.split('?')[0]})")


def admin_disable(browser, uid: str) -> None:
    ctx, page, _auth = m.sign_in(browser, "root")
    try:
        admin_ui_overview(page)
        got = re.search(r'name="csrf" value="([^"]+)"', page.content())
        assert got, "no CSRF token on the admin UI's overview"
        mask(got.group(1))
        # The admin UI's own Disable form, posted by the page (same origin,
        # its session cookie, the CSRF token).
        with page.expect_navigation(timeout=60_000):
            page.evaluate("""([url, csrf]) => {
                const f = document.createElement('form');
                f.method = 'POST'; f.action = url;
                for (const [k, v] of [['csrf', csrf], ['reason', 'e2e-fxa: admin_disable_survives_routine_run']]) {
                    const i = document.createElement('input'); i.type = 'hidden'; i.name = k; i.value = v; f.appendChild(i);
                }
                document.body.appendChild(f); f.submit();
            }""", [f"{ADMIN}/accounts/{uid}/disable", got.group(1)])
        text = page.inner_text("body")
        assert "Disabled" in text, f"the admin UI's answer: {m.scrub(text)[:300]!r}"
    except Exception:
        base.shot(page, "admin-ui-disable")
        raise
    finally:
        ctx.close()


def admin_disable_survives_routine_run(browser) -> None:
    needs("setup")
    admin_verify("bob")
    t0 = time.time()
    m.until("bob@remote.test on the sign-up list", lambda: "bob@remote.test" in allowlist(), 660, every=10)
    latency("bob's admin-verified email on the sign-up list", t0)
    signup("bob", "bob@remote.test")
    s = state["fxa_bob"]
    admin_disable(browser, s.uid)
    m.until("bob's session token answers 401 after the admin UI's disable", lambda: session_status(s) == 401, 60, every=3)
    assert account("bob@remote.test") == "1:1:1", f"bob's account: {account('bob@remote.test')}"
    rep = m.hub_ok("POST", f"/api/instances/{INST}/settings/retry", {}, timeout=300)
    units = {u.get("unit"): u for u in (rep.get("units") or [])}
    hook = units.get("hook:access-sync") or {}
    assert hook.get("ok") is True and not hook.get("skipped"), f"the retry's access-sync hook: {json.dumps(hook)[:400]} (units {sorted(units)})"
    print("    retry: " + ", ".join(f"{k} ok={v.get('ok')}" for k, v in sorted(units.items())), flush=True)
    assert "bob@remote.test" in allowlist(), "the retry took bob off the list"
    assert account("bob@remote.test") == "1:1:1", f"after the retry bob's account: {account('bob@remote.test')}"
    assert session_status(s) == 401, "bob's session is live again after the retry"
    st, errno = refused_errno(lambda: fxa().login("bob@remote.test", state["fxapw_bob"]))
    assert st in (400, 401, 403), f"bob's sign-in after the retry: HTTP {st} errno {errno}"


HOST_REASONS = {
    INST: "Firefox syncs in the background, without cookies; each request is signed with the account's own keys.",
    f"{INST}-api": "Firefox and the account pages call the accounts API in the background, without cookies; the sign-up list decides who may create an account.",
    f"{INST}-profile": "Firefox loads account profiles and avatars in the background, without cookies.",
    f"{INST}-pairing": "An encrypted relay for pairing a phone by QR code; it can't read what it relays.",
}
ACCOUNTS_REASON = ("Firefox reads the accounts configuration and opens the start and change-password pages without "
                   "cookies; everything else on this host is behind sign-in.")
ACCOUNTS_PATHS = {f"{INST}-accounts-root": "/", f"{INST}-accounts-change-password": "/.well-known/change-password",
                  f"{INST}-accounts-config": "/.well-known/fxa-client-configuration", f"{INST}-accounts-metrics": "/metrics-flow"}
PATH_ROUTERS = {f"{INST}-signup": (f"{INST}-api", "/v1/account/create", "exact"), f"{INST}-token": (INST, "/1.0/", "prefix")}


def bypass_badges() -> None:
    needs("setup")
    inst = next((i for i in get("/api/instances") if i.get("id") == INST), None)
    assert inst, f"{INST} isn't in GET /api/instances"
    bs = inst.get("bypass") or []
    m.save("bypass.json", bs)
    opened = {b["router"]: b for b in bs if b.get("kind") == "open_router"}
    want = set(HOST_REASONS) | set(ACCOUNTS_PATHS) | set(PATH_ROUTERS)
    assert set(opened) == want, f"open routers {sorted(opened)}, want {sorted(want)}"
    assert not [b for b in bs if b.get("kind") != "open_router"], f"other badges: {[b.get('kind') for b in bs]}"
    for r, reason in HOST_REASONS.items():
        b = opened[r]
        assert b["paths"] == [] and b["hosts"] == [f"{r}.{DOMAIN}"], f"{r}: {b}"
        assert b["tier"] == "public@file", f"{r}: tier {b['tier']}"
        assert b["note"] == reason, f"{r}: note {b['note']!r}"
    for r, path in ACCOUNTS_PATHS.items():
        b = opened[r]
        assert b["hosts"] == [f"{INST}-accounts.{DOMAIN}"] and b["paths"] == [{"path": path, "match": "exact"}], f"{r}: {b}"
        # A path router's note is its host's reason (contract §3).
        assert b["note"] == ACCOUNTS_REASON, f"{r}: note {b['note']!r}"
    for r, (host, path, match) in PATH_ROUTERS.items():
        b = opened[r]
        assert b["hosts"] == [f"{host}.{DOMAIN}"] and b["paths"] == [{"path": path, "match": match}], f"{r}: {b}"
        assert b["note"] == HOST_REASONS[host], f"{r}: note {b['note']!r}"
    print("    " + "; ".join(f"{r} {b['tier']} {len(b['paths'])} path(s)" for r, b in sorted(opened.items())), flush=True)


def mail_unwired_refuses() -> None:
    needs("setup")
    m.run("./portcullis", "mail", "disable", "--yes", "--force", timeout=900)
    # mail disable restarts the Hub (the slot closed): its new address.
    state["hub_ip"] = m.hub_ip()
    m.until("the Hub answers again", lambda: m.hub("GET", "/api/instances", timeout=20)[0] == 200, 180, every=3)

    def findings(x):
        if isinstance(x, dict):
            if "kind" in x and "fp" in x:
                yield x
            for v in x.values():
                yield from findings(v)
        elif isinstance(x, list):
            for v in x:
                yield from findings(v)

    def unwired():
        if any(f.get("kind") == "mail_sender_unwired" and str(f.get("title", "")).startswith(INST + " ")
               for f in findings(get("/api/doctor"))):
            return True
        m.hub("POST", "/api/doctor/scan", {})
        return False
    m.until(f"mail_sender_unwired for {INST} in the doctor", unwired, 300, every=15)
    code, out = people_api("POST", "/api/me/email/verify", "bob")
    assert code == 409, f"POST /api/me/email/verify with mail off: HTTP {code} {m.scrub(str(out))[:300]}"
    # The restart's fxa-mail-check, watched while it runs (a failed start
    # may be taken down with its containers).
    before = cid("fxa-mail-check")
    seen: dict[str, tuple[str, str]] = {}
    stop = threading.Event()

    def watch():
        while not stop.is_set():
            for c in m.docker("ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}",
                              "--filter", "label=com.docker.compose.service=fxa-mail-check", check_rc=False).split():
                if c == before or c in seen:
                    continue
                st = m.docker("inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", c, check_rc=False).split()
                if st and st[0] == "exited":
                    seen[c] = (st[1], m.docker("logs", c, check_rc=False, timeout=60).strip())
            stop.wait(0.5)
    w = threading.Thread(target=watch, daemon=True)
    w.start()
    try:
        code, acc = m.hub("POST", f"/api/templates/restart/{INST}", {}, timeout=300)
        assert code == 202, f"restart: HTTP {code}: {m.scrub(str(acc))[:400]}"
        rec = e2e_ops.wait(get, e2e_ops.accepted(acc), 1200, every=5)
    finally:
        stop.set()
        w.join(timeout=30)
    print(f"    the restart without mail: ok={rec.get('ok')} {m.scrub(str(rec.get('error') or ''))[:300]}", flush=True)
    assert seen, f"no fxa-mail-check ran in the restart (the earlier one: {before[:12] or 'none'})"
    rc, out = next(iter(seen.values()))
    assert rc == "1", f"fxa-mail-check exit {rc}: {m.scrub(out)[:300]}"
    assert "portcullis: no mail" in out, f"fxa-mail-check's line: {m.scrub(out)[:300]}"
    assert rec.get("ok") is not True, "the restart without mail succeeded"
    print(f"    fxa-mail-check: exit 1: {m.scrub(out.splitlines()[-1])[:200]}", flush=True)


CA = None


def main() -> int:
    global CA
    import ssl
    CA = ssl.create_default_context(cafile=os.environ["REQUESTS_CA_BUNDLE"])
    os.makedirs(m.ART, exist_ok=True)
    state["hub_ip"] = m.hub_ip()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        try:
            check("setup: people, mail on with DKIM, remote mailboxes, the instance enabled and routed", setup)
            check("email_verify_by_code", email_verify_by_code)
            check("unverified_not_listed", unverified_not_listed)
            check("signup_code_via_provider", signup_code_via_provider)
            check("nonmember_refused", nonmember_refused)
            check("leave_disables_via_hub", leave_disables_via_hub)
            check("rejoin_enables_via_hub", rejoin_enables_via_hub)
            check("email_change_disables", email_change_disables)
            check("email_changed_in_fxa_before_block", email_changed_in_fxa_before_block)
            check("admin_disable_survives_routine_run", lambda: admin_disable_survives_routine_run(browser))
            check("bypass_badges", bypass_badges)
            check("mail_unwired_refuses", mail_unwired_refuses)
        finally:
            browser.close()
    return report()


if __name__ == "__main__":
    sys.exit(main())
