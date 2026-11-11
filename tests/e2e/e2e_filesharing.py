#!/usr/bin/env python3
"""End-to-end: file sharing on a real stack (contract §5.1, §11.6, §13.16,
§13.17, §14).

Runs in CI (job `e2e-filesharing` in .github/workflows/ci.yml) against the
whole core stack and the Hub (built from the same-named Hub branch), with
one template source holding the templates repo's samba and timemachine
(same-named templates branch). smbclient is the runner's (apt, pinned);
it connects to each instance's container address on its compose network,
so Samba sees the bridge gateway (inside the default Local networks).

Scenarios:
  setup        LLDAP users alice, bob, carol (GraphQL); the groups
               users_timemachine, office_milan, users_samba and the
               memberships through the Hub (alice: users_timemachine +
               office_milan; bob: users_samba; carol: users_samba +
               office_milan); before enabling (F55): each instance's
               connect_address and SMB port (127.0.0.1; Time Machine on
               10445), Time Machine size_limit default 500GiB with
               office_milan 10GiB, Samba slot 1 = shared folder `family`
               (/srv/e2e-family, POST /api/folders, assign preview + apply)
               named Family, readers office_milan, writers users_samba;
               then both enabled through the Hub.
  fresh_auth   alice (signed in with her passkey) opens My apps and clicks
               Create password: the popup goes to Keycloak with
               prompt=login, max_age=0 (no ACR request: the pc_fresh claim), asks for the
               passkey again (exactly one more authenticator assertion),
               comes back to people.<domain>/ and hands the code to its
               opener (window.opener survives: Cross-Origin-Opener-Policy
               of every document recorded); the dialog shows the password
               (6 groups of 4 from the 54-character alphabet); a second
               POST with the same code is 403; once the dialog is closed
               the password is nowhere in the page, storage or the API.
  smb          smbclient -m SMB3 (encryption required) with alice's password
               lists //…/TimeMachine-alice; testparm in the container shows
               fruit:time machine max size = 10240M (office_milan); every
               person id is in 20000–59999. bob and carol create their
               Samba passwords the same way (one assertion each); Home and
               Family work for both, carol (writer) writes to Family.
  revoke_hub   alice holds an open session; she is removed from
               users_timemachine through the Hub: within 10 s her session
               is gone and a new login fails; audit credential.revoke_leave.
  demote       carol holds an open Family session; share1_writers is
               emptied through the Hub (carol stays a reader through
               office_milan): her session is ended, a new login lists
               Family, a write is refused.
  revoke_lldap bob holds an open session; he is removed from users_samba
               with LLDAP's GraphQL (not through the Hub): within 75 s his
               login fails and his session is gone.
  restore_inst back up and restore Samba through the Hub: carol's password
               no longer works, the admin view says voided (restore), her
               My apps card says "reset by a restore"; she creates a new
               one (works).
  password_only_template  dave (a Hub-set password only, users_samba),
               password on: his fresh sign-in through portcullis-fresh-auth
               with the password (prompt=login, max_age=0) and the proof
               posted to the people listener: refused (403) while the
               default (Samba's template: it takes no pick) is Standard,
               accepted once the default is a password-only template; the
               audit names the template; his share works. Default,
               template and password switch restored.
  secrets      the instance archives (hub_data /data/backups/samba/*.tar),
               the core backup (every file, nested archives opened) and
               the whole hub_data volume contain none of the hashes the
               test read from the secrets volume during the run.
  visible      docker inspect of both containers, the Hub's and the apps'
               logs contain no hash.
  restore_core ./portcullis backup → ./portcullis restore with both apps
               running: the restore takes them down first (volumes kept),
               reports them and leaves them down; every credential voided
               (epoch missing), the volume holds no hash file; Samba
               restarted from the Hub: carol's password fails.

Latencies (F60) are printed as `LATENCY …` lines and added to the step
summary.

Environment: E2E_DOMAIN, E2E_HUB_SECRET (the proxy secret; never printed,
never on argv), LLDAP_ADMIN_PASSWORD, ALPINE, E2E_FAMILY (/srv/e2e-family),
E2E_ARTIFACTS. Passwords and hashes are masked (::add-mask::) as soon as
they are known and never printed; smbclient gets them through PASSWD.
Chromium trusts core's CA (NSS db). No traces: a DOM snapshot would carry
the shown password.
"""
from __future__ import annotations

import base64
import glob
import gzip
import hashlib
import io
import json
import os
import re
import secrets
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

from playwright.sync_api import Error as PWError
from playwright.sync_api import Page, sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_login as base  # noqa: E402  (Authenticator, passkey_flow, shot)
import e2e_fsops  # noqa: E402  (run_op, scrub; unit-tested without the stack)
from e2e_fsops import HASHES, PASSWORDS, scrub  # noqa: E402

DOMAIN = os.environ["E2E_DOMAIN"]
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
SECRET = os.environ["E2E_HUB_SECRET"]
ALPINE = os.environ["ALPINE"]
FAMILY = os.environ.get("E2E_FAMILY", "/srv/e2e-family")
TIMEOUT_MS = 30_000
PORTAL = f"https://{DOMAIN}/"
PEOPLE = f"https://people.{DOMAIN}"
AUTH = f"https://auth.{DOMAIN}"
LLDAP = "http://127.0.0.1:17170"
SECRETS_VOLUME = "portcullis_hub_secrets"
TM, SMB = "timemachine", "samba"
KEY = "share_password"
FOLDER = "family"
PW_RE = re.compile(r"^(?:[2-9A-HJ-NP-Ya-hjkmnp-z]{4}-){5}[2-9A-HJ-NP-Ya-hjkmnp-z]{4}$")
SMB_OPTS = ["--use-kerberos=disabled", "-m", "SMB3", "--option=client min protocol=SMB3",
            "--option=client smb encrypt=required"]
HUB_SLA_S, LLDAP_SLA_S = 10, 75
OP_S = 900

results: list[tuple[str, bool, str]] = []
state: dict = {}
LATENCY: dict[str, float] = {}
OBS: list[str] = []           # observations for the report (popup, COOP, …)
POPUPS: dict[str, int] = {}   # fresh-auth popups per person (signature counter offsets)


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


def mask(value: str) -> None:
    """GitHub masks value in every later log line (the command line itself
    is not shown)."""
    if value and os.environ.get("GITHUB_ACTIONS"):
        print(f"::add-mask::{value}", flush=True)


def save(name: str, data) -> None:
    os.makedirs(ART, exist_ok=True)
    with open(os.path.join(ART, name), "w") as f:
        f.write(scrub(data if isinstance(data, str) else json.dumps(data, indent=2)))


def summary(line: str) -> None:
    print(line, flush=True)
    p = os.environ.get("GITHUB_STEP_SUMMARY")
    if p:
        with open(p, "a") as f:
            f.write(line + "\n")


# ── docker ──

def docker(*args: str, check_rc: bool = True, timeout: float = 120, binary: bool = False):
    p = subprocess.run(["docker", *args], capture_output=True, text=not binary, timeout=timeout)
    if check_rc and p.returncode != 0:
        err = p.stderr if not binary else p.stderr.decode(errors="replace")
        raise AssertionError(f"docker {' '.join(args[:3])}…: rc {p.returncode}: {scrub(err.strip())[:400]}")
    return p.stdout


def container(project: str, service: str) -> str:
    ids = docker("ps", "-q", "--filter", f"label=com.docker.compose.project={project}",
                 "--filter", f"label=com.docker.compose.service={service}").split()
    assert len(ids) == 1, f"{project}/{service}: running containers {ids}"
    return ids[0]


def app(instance: str) -> str:
    return container(f"portcullis-{instance}", instance)


def cid_project(cid: str) -> str:
    """The instance id of an app container (its compose project minus portcullis-)."""
    return docker("inspect", "-f", '{{index .Config.Labels "com.docker.compose.project"}}', cid).strip() \
        .removeprefix("portcullis-")


def ip_of(cid: str) -> str:
    nets = json.loads(docker("inspect", "-f", "{{json .NetworkSettings.Networks}}", cid))
    ips = [n.get("IPAddress") for n in nets.values() if n.get("IPAddress")]
    assert ips, f"{cid}: no address"
    return ips[0]


def hub_ip() -> str:
    cid = container("portcullis", "hub")
    return json.loads(docker("inspect", "-f", "{{json .NetworkSettings.Networks}}", cid))["portcullis"]["IPAddress"]


# ── the Hub's admin API (as Traefik calls it: proxy secret + identity) ──

def hub(method: str, path: str, body=None, timeout: float = 300):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://{state.get('hub_ip') or hub_ip()}:8888" + path, data=data, method=method,
                                 headers={"X-Portcullis-Proxy-Secret": SECRET, "X-Forwarded-User": "admin",
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


def hub_ok(method: str, path: str, body=None, want: int = 200, timeout: float = 300):
    code, out = hub(method, path, body, timeout)
    assert code == want, f"{method} {path}: HTTP {code} (want {want}): {scrub(str(out))[:800]}"
    return out


def hub_get(path: str):
    return hub("GET", path)[1]


def run_op(method: str, path: str, body, timeout: float = OP_S) -> dict:
    """e2e_fsops.run_op on this script's Hub API (tests/test_e2e_fsops.py)."""
    return e2e_fsops.run_op(hub, save, method, path, body, timeout)


def member(op: str, group: str, user: str) -> None:
    if op == "add":
        hub_ok("POST", f"/api/directory/groups/{group}/members", {"username": user})
    else:
        hub_ok("DELETE", f"/api/directory/groups/{group}/members/{user}", {})


def creds(instance: str) -> dict:
    """user → row of the admin credentials view (metadata only)."""
    views = hub_ok("GET", f"/api/instances/{instance}/credentials")
    view = next(v for v in views if v["key"] == KEY)
    return {r["user"]: r for r in view.get("rows") or []}


def uid_of(instance: str, user: str) -> int:
    ids = creds(instance)[user].get("ids") or {}
    assert "uid" in ids, f"{user} has no uid on {instance}: {ids}"
    return ids["uid"]


def audit() -> list[dict]:
    out = hub_ok("GET", "/api/directory/audit")
    return out if isinstance(out, list) else []


# ── LLDAP (GraphQL as its admin: the change the Hub doesn't make) ──

def lldap_token() -> str:
    body = json.dumps({"username": "admin", "password": os.environ["LLDAP_ADMIN_PASSWORD"]}).encode()
    req = urllib.request.Request(LLDAP + "/auth/simple/login", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        tok = json.loads(r.read())["token"]
    mask(tok)
    return tok


def gql(query: str) -> dict:
    tok = lldap_token()
    req = urllib.request.Request(LLDAP + "/api/graphql", data=json.dumps({"query": query}).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + tok})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read())
    assert not out.get("errors"), f"LLDAP GraphQL: {out['errors']}"
    return out["data"]


# ── secrets volume: the hashes this run must never find anywhere else ──

def record_hashes() -> int:
    """Reads every .nt file of the secrets volume into HASHES (masked, never
    printed); returns how many files there are now."""
    out = docker("run", "--rm", "--network", "none", "-v", f"{SECRETS_VOLUME}:/s:ro", ALPINE, "sh", "-c",
                 "find /s -type f -name '*.nt' -exec cat {} +")
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    for h in lines:
        assert re.fullmatch(r"[0-9A-F]{32}", h), "a hash file isn't 32 upper-case hex characters"
        if h not in HASHES:
            mask(h)
            mask(h.lower())
            HASHES.add(h)
    return len(lines)


def nt_files() -> list[str]:
    return docker("run", "--rm", "--network", "none", "-v", f"{SECRETS_VOLUME}:/s:ro", ALPINE,
                  "find", "/s", "-type", "f", "-name", "*.nt").split()


def hash_hits(data: bytes, where: str, depth: int = 0) -> list[str]:
    """Where in data (and in the archives it holds) a recorded hash occurs
    (hex text or raw 16 bytes): the places, never the hash."""
    hits = []
    low = data.lower()
    for i, h in enumerate(sorted(HASHES)):
        if h.lower().encode() in low:
            hits.append(f"{where} (hash #{i} as hex)")
        # Also search for the raw 16 bytes (Samba passdb.tdb stores it this way)
        raw = bytes.fromhex(h)
        if raw in data:
            hits.append(f"{where} (hash #{i} as raw bytes)")
    if depth >= 5:
        return hits
    if data[:2] == b"\x1f\x8b":
        try:
            return hits + hash_hits(gzip.decompress(data), where + "|gunzip", depth + 1)
        except (OSError, EOFError):
            return hits
    if len(data) > 262 and data[257:262] == b"ustar":
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                for m in t.getmembers():
                    if m.isfile():
                        f = t.extractfile(m)
                        if f:
                            hits += hash_hits(f.read(), f"{where}:{m.name}", depth + 1)
        except tarfile.TarError:
            pass
    return hits


# ── smbclient (password through PASSWD, never argv) ──

def smb(cip: str, share: str, user: str, pw: str, *cmds: str, timeout: float = 30) -> tuple[bool, str]:
    args = ["smbclient", f"//{cip}/{share}", "-U", user, *SMB_OPTS, "-c", "; ".join(cmds or ("ls",))]
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"), "PASSWD": pw}
    try:
        p = subprocess.run(args, env=env, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "timeout"
    out = scrub(p.stdout + p.stderr)
    return p.returncode == 0 and "NT_STATUS" not in out, out


def running(cid: str) -> bool:
    p = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", cid], capture_output=True, text=True, timeout=30)
    return p.returncode == 0 and p.stdout.strip() == "true"


def sessions_gone(cid: str, uid: int) -> bool:
    """No smbd serves uid any more (a stopped container serves nobody: the
    Hub's kill fallback)."""
    try:
        return not sessions_of(cid, uid)
    except AssertionError:
        return not running(cid)


def sessions_of(cid: str, uid: int) -> list[str]:
    """smbd PIDs serving uid (smbstatus -p -n: numeric, a removed account no
    longer resolves by name)."""
    p = subprocess.run(["docker", "exec", cid, "smbstatus", "-p", "-n"], capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, f"smbstatus: rc {p.returncode}: {p.stderr[:300]}"
    out = []
    for ln in p.stdout.splitlines():
        f = ln.split()
        if len(f) >= 2 and f[0].isdigit() and f[1] == str(uid):
            out.append(f[0])
    return out


class Session:
    """An smbclient that stays connected (an `ls` every second on stdin)."""

    def __init__(self, cip: str, share: str, user: str, pw: str):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"), "PASSWD": pw}
        self.p = subprocess.Popen(["smbclient", f"//{cip}/{share}", "-U", user, *SMB_OPTS], env=env,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.out: list[str] = []
        self.stop = False
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._feed, daemon=True).start()

    def _read(self):
        for ln in self.p.stdout:
            self.out.append(ln)

    def _feed(self):
        while not self.stop and self.p.poll() is None:
            try:
                self.p.stdin.write("ls\n")
                self.p.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                return
            time.sleep(1)

    def disconnected(self) -> bool:
        return self.p.poll() is not None or any("NT_STATUS" in ln for ln in self.out[-20:])

    def close(self):
        self.stop = True
        try:
            self.p.kill()
        except OSError:
            pass


def measure_revocation(label: str, cid: str, cip: str, share: str, user: str, pw: str, uid: int,
                       act, limit: float) -> float:
    """Opens a session, runs act(), then polls until the session is gone
    and a new login fails; returns the latency from act's start."""
    proj = cid_project(cid)
    ok, out = smb(cip, share, user, pw)
    assert ok, f"{label}: {user} can't log in before the removal: {out[-400:]}"
    s = Session(cip, share, user, pw)
    try:
        pids = until(f"{label}: {user}'s session open", lambda: sessions_of(cid, uid), 30, every=1)
        # F58 evidence: can the container's root signal the per-user smbd
        # with this cap set (no KILL)? kill -0 only checks, sends nothing.
        p = subprocess.run(["docker", "exec", cid, "kill", "-0", pids[0]], capture_output=True, text=True, timeout=30)
        ids = subprocess.run(["docker", "exec", cid, "sh", "-c", f"grep -E '^(Uid|Gid):' /proc/{pids[0]}/status"],
                             capture_output=True, text=True, timeout=30).stdout.split()
        OBS.append(f"{label}: root in the container → kill -0 of {user}'s smbd: rc {p.returncode} "
                   f"{p.stderr.strip()[:120]!r}; smbd ids {' '.join(ids)}")
        print("    " + OBS[-1], flush=True)
        t0 = time.time()
        act()
        t_session = t_login = None
        while time.time() - t0 < limit + 60:
            now = time.time()
            if t_session is None and sessions_gone(cid, uid):
                t_session = now - t0
            if t_login is None and not smb(cip, share, user, pw, timeout=15)[0]:
                t_login = time.time() - t0
            if t_session is not None and t_login is not None:
                break
            time.sleep(0.5)
        client = "the client saw the disconnect" if s.disconnected() else "the client process did not notice yet"
        try:
            now_cid = container(f"portcullis-{proj}", proj)
        except AssertionError:
            now_cid = "none"
        recreated = not now_cid.startswith(cid[:12]) and not cid.startswith(now_cid[:12])
        OBS.append(f"{label}: the container was {'stopped/recreated (the Hub kill fallback)' if recreated else 'kept (applied live by the hook)'}")
        print("    " + OBS[-1], flush=True)
        lat = max(t_session or 1e9, t_login or 1e9)
        print(f"    {label}: session gone after {t_session} s, new login refused after {t_login} s ({client})", flush=True)
        assert t_session is not None and t_login is not None, f"{label}: session gone {t_session}, login refused {t_login}"
        LATENCY[label] = lat
        summary(f"LATENCY {label}: {lat:.1f} s (session ended {t_session:.1f} s, new login refused {t_login:.1f} s)")
        assert lat <= limit, f"{label}: {lat:.1f} s > {limit} s"
        return lat
    finally:
        s.close()


# ── browser ──

def sign_in(browser, who: str):
    url = subprocess.run(["./portcullis", "invite", who, "--to", "portal", "--json"], capture_output=True,
                         text=True, timeout=120, check=True).stdout
    link = json.loads(url)["url"]
    mask(link)
    assert re.fullmatch(rf"https://enroll\.{re.escape(DOMAIN)}/invite/[A-Za-z0-9_-]{{43}}", link), "setup link shape"
    ctx = browser.new_context()
    ctx.set_default_timeout(TIMEOUT_MS)
    page = ctx.new_page()
    auth = base.Authenticator(page)
    page.goto(link, wait_until="domcontentloaded")
    base.passkey_flow(page, until=PORTAL, label=f"set-{who}", expect_stepups=1)
    assert f"Signed in as <strong>{who}</strong>" in page.content(), page.content()[:300]
    return ctx, page, auth


def open_myapps(page: Page, instance: str):
    # A fresh load: a goto to the URL the page is already on (only the
    # hash) wouldn't reload, and the cards would be the old ones.
    page.goto(PEOPLE + "/#myapps", wait_until="domcontentloaded")
    page.reload(wait_until="domcontentloaded")
    deadline = time.time() + 60
    while time.time() < deadline:
        if base.on_login_pages(page):
            base.passkey_flow(page, until=PEOPLE, label="people", expect_stepups=0)
            page.goto(PEOPLE + "/#myapps", wait_until="domcontentloaded")
        row = page.locator(f'[data-ma-cred][data-ma-app="{instance}"][data-ma-key="{KEY}"]')
        if row.count() and row.first.is_visible():
            return row.first
        page.wait_for_timeout(500)
    base.shot(page, f"myapps-{instance}-missing")
    raise AssertionError(f"My apps: no {instance} card (at {page.url})")


def path_only(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    return f"{u.scheme}://{u.netloc}{u.path}"


def drive_popup(popup: Page, label: str) -> dict:
    """Signs in inside the fresh-auth popup until it closes itself."""
    seen = {"prompted": 0, "urls": []}
    deadline = time.time() + 120
    while time.time() < deadline:
        if popup.is_closed():
            return seen
        try:
            u = path_only(popup.url)
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
    raise AssertionError(f"the popup didn't finish (at {path_only(popup.url)}; visited {seen['urls']})")


def create_password(page: Page, auth, instance: str, who: str, replay: bool = True) -> str:
    """My apps → Create password → the fresh sign-in popup → the shown-once
    dialog. Asserts exactly one more authenticator assertion and (replay)
    that the same code can't be used twice. Returns the password."""
    row = open_myapps(page, instance)
    kind = row.get_attribute("data-ma-status-kind")
    assert kind in ("none", "voided"), f"{who}'s {instance} card: status {kind}"
    posts: list[tuple[str, str]] = []
    docs: list[tuple[str, int, str, str]] = []

    def on_request(req):
        if req.method == "POST" and "/api/me/apps/" in req.url and "/credentials/" in req.url:
            posts.append((req.url, req.post_data or ""))

    def on_response(r):
        try:
            if r.request.resource_type == "document":
                h = r.headers
                docs.append((path_only(r.url), r.status, h.get("cross-origin-opener-policy") or "-",
                             h.get("cross-origin-embedder-policy") or "-"))
        except PWError:
            pass

    page.on("request", on_request)
    page.context.on("response", on_response)
    before = auth.asserted
    t0 = time.time()
    try:
        with page.context.expect_page(timeout=30_000) as pinfo:
            row.locator('[data-ma-act="cred-create"]').click()
        popup = pinfo.value
        # Each popup gets a copy of the opener's credential; its signature
        # counter must stay above every earlier copy's (Keycloak refuses a
        # counter that didn't grow), and the opener's own never moves.
        n = POPUPS[who] = POPUPS.get(who, 0) + 1
        copies = [dict(c, signCount=c.get("signCount", 0) + 1000 * (n - 1)) for c in auth.credentials()]
        pauth = base.Authenticator(popup, credentials=copies)
        seen = drive_popup(popup, f"{who}-{instance}")
        pw_loc = page.locator("dialog[open] [data-ma-pw]")
        try:
            pw_loc.wait_for(state="visible", timeout=60_000)
        except PWError:
            status = page.locator(f'[data-ma-cred][data-ma-app="{instance}"] [data-ma-cred-status]')
            msg = status.first.inner_text() if status.count() else "?"
            base.shot(page, f"{who}-{instance}-no-dialog")
            raise AssertionError(f"no password dialog; card status: {msg!r}; popup visited {seen['urls']}")
        pw = (pw_loc.text_content() or "").strip()
        PASSWORDS[f"{who}/{instance}/{len(PASSWORDS)}"] = pw
        mask(pw)
    finally:
        page.remove_listener("request", on_request)
        page.context.remove_listener("response", on_response)
    took = time.time() - t0
    assert PW_RE.fullmatch(pw), f"the shown password isn't 6 groups of 4 from the alphabet (length {len(pw)})"
    asserted = pauth.asserted + (auth.asserted - before)
    obs = (f"{who}/{instance}: popup {took:.1f} s, Keycloak passkey prompts {seen['prompted']}, "
           f"assertions popup {pauth.asserted} + opener {auth.asserted - before}; documents "
           + "; ".join(f"{u} {s} COOP={c} COEP={e}" for u, s, c, e in docs))
    OBS.append(obs)
    print("    " + obs, flush=True)
    assert asserted == 1, f"{who}: {asserted} authenticator assertions for the fresh sign-in (want exactly 1)"
    assert len(posts) == 1, f"{len(posts)} credential POSTs (want 1)"
    if replay:
        url, body = posts[0]
        r = page.request.post(url, data=body, headers={"Content-Type": "application/json"})
        text = r.text()
        assert r.status == 403, f"the same code again: HTTP {r.status} (want 403)"
        assert pw not in text, "the replay's answer carries the password"
        print(f"    {who}: the same code again → 403", flush=True)
    page.locator('dialog[open] [data-ma-pw-act="done"]').click()
    page.wait_for_timeout(500)
    assert page.locator("dialog[open]").count() == 0, "the dialog stayed open"
    assert pw not in page.content(), "the password is still in the page after the dialog closed"
    storage = page.evaluate("() => JSON.stringify([Object.assign({}, localStorage), Object.assign({}, sessionStorage)])")
    assert pw not in storage, "the password is in web storage"
    assert pw not in page.url, "the password is in the URL"
    me = page.request.get(PEOPLE + "/api/me/apps")
    assert me.status == 200 and pw not in me.text(), f"/api/me/apps: HTTP {me.status} or carries the password"
    cred = next(c for a in me.json()["apps"] if a["id"] == instance for c in a["credentials"] if c["key"] == KEY)
    assert cred["status"] == "active", f"{who}'s {instance} credential after create: {cred}"
    assert pw not in json.dumps(hub_ok("GET", f"/api/instances/{instance}/credentials")), "the admin view carries it"
    return pw


# ── scenarios ──

def setup() -> None:
    for u in ("alice", "bob", "carol"):
        gql(f'mutation {{ createUser(user: {{id: "{u}", email: "{u}@{DOMAIN}"}}) {{ id }} }}')
    for g in ("users_timemachine", "office_milan", "users_samba"):
        hub_ok("POST", "/api/directory/groups", {"name": g})
    for m in ("alice:users_timemachine", "alice:office_milan", "bob:users_samba",
              "carol:users_samba", "carol:office_milan"):
        member("add", m.split(":")[1], m.split(":")[0])
    # Before enabling (F55): addresses, ports, the Time Machine limits and
    # Samba's slot 1.
    out = hub_ok("PUT", f"/api/instances/{TM}/settings", {
        "values": {"connect_address": f"nas.{DOMAIN}"},
        "person": {"size_limit": {"default": "500GiB", "resolve": "max",
                                  "rows": [{"group": "office_milan", "value": "10GiB"}]}},
        "ports": {"TM_SMB": "10445", "TM_SMB_BIND": "127.0.0.1"}})
    print(f"    saved {TM}: {json.dumps({k: out.get(k) for k in ('effect', 'changed', 'warnings')})[:400]}", flush=True)
    out = hub_ok("PUT", f"/api/instances/{SMB}/settings", {
        "values": {"connect_address": f"nas.{DOMAIN}", "share1_name": "Family",
                   "share1_readers": ["office_milan"], "share1_writers": ["users_samba"]},
        "ports": {"SAMBA_SMB": "445", "SAMBA_SMB_BIND": "127.0.0.1"}})
    print(f"    saved {SMB}: {json.dumps({k: out.get(k) for k in ('effect', 'changed', 'warnings')})[:400]}", flush=True)
    out = hub_ok("POST", "/api/folders", {"id": FOLDER, "name": "Family", "path": FAMILY,
                                          "description": "e2e-filesharing", "create": False}, want=201)
    state["gid"] = out["folder"]["gid"]
    uses = [{"instance": SMB, "key": "share1_folder"}]
    plan = hub_ok("POST", f"/api/folders/{FOLDER}/assign/preview", {"uses": uses})
    save("assign-preview.json", plan)
    run_op("POST", f"/api/folders/{FOLDER}/assign/apply", {"plan_hash": plan["plan_hash"], "uses": uses})
    panel = json.dumps(hub_ok("GET", f"/api/instances/{SMB}/settings"))
    assert f'"folder:{FOLDER}"' in panel, "share1_folder isn't folder:family after the assignment"
    for inst in (TM, SMB):
        t0 = time.time()
        out = run_op("POST", "/api/templates/enable", {"id": inst}, timeout=1500)
        print(f"    enabled {inst} in {time.time() - t0:.0f} s: {json.dumps(out.get('warnings'))[:300]}", flush=True)
    for inst in (TM, SMB):
        cid = until(f"{inst} running", lambda i=inst: app(i), 120)
        until(f"{inst} healthy", lambda c=cid: docker("inspect", "-f", "{{.State.Health.Status}}", c).strip() == "healthy",
              180, every=5)
        state[f"{inst}_cid"], state[f"{inst}_ip"] = cid, ip_of(cid)
    tp = docker("exec", state[f"{SMB}_cid"], "testparm", "-s")
    assert "server smb encrypt = required" in tp and "hosts allow = 10.0.0.0/8 172.16.0.0/12" in tp, tp[:1500]
    state["setup"] = True


def main() -> int:
    os.makedirs(ART, exist_ok=True)
    state["hub_ip"] = hub_ip()
    check("setup: users, groups, settings, slot 1 = shared folder family (assigned), both enabled before any password",
          setup)
    if "setup" not in state:
        return report()

    with sync_playwright() as pw_:
        browser = pw_.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])
        ses: dict = {}

        def signs_in():
            for who in ("alice", "bob", "carol"):
                ses[who] = sign_in(browser, who)
        check("alice, bob and carol: setup link → passkey → portal", signs_in)
        if len(ses) != 3:
            return report()

        # ── 2. fresh auth, shown once ──
        def fresh_auth():
            _, page, auth = ses["alice"]
            state["alice_tm"] = create_password(page, auth, TM, "alice")
            state["n_hashes"] = record_hashes()
        check("fresh_auth: Create password → popup (prompt=login, max_age=0, pc_fresh) → exactly one more "
              "assertion → the password shown once; the same code again 403; gone after the dialog", fresh_auth)

        # ── 3. SMB ──
        def smb_tm():
            needs("alice_tm")
            cid, cip = state[f"{TM}_cid"], state[f"{TM}_ip"]
            ok, out = until("alice lists TimeMachine-alice",
                            lambda: (r := smb(cip, "TimeMachine-alice", "alice", state["alice_tm"]))[0] and r, 60, every=3)
            assert "blocks of size" in out or "blocks available" in out, out[-400:]
            tp = docker("exec", cid, "testparm", "-s")
            sect = tp.split("[TimeMachine-alice]", 1)
            assert len(sect) == 2, f"no [TimeMachine-alice] in testparm: {tp[:1500]}"
            body = sect[1].split("\n[", 1)[0]
            assert re.search(r"fruit:time machine max size\s*=\s*10240M\b", body), body
            uid = uid_of(TM, "alice")
            assert 20000 <= uid <= 59999, f"alice's uid {uid} outside 20000–59999"
            state["alice_uid"] = uid
            print(f"    alice: uid {uid}, max size 10240M", flush=True)
        check("smb: smbclient -m SMB3 (encrypted) lists //…/TimeMachine-alice; testparm: fruit:time machine max "
              "size = 10240M; uid in 20000–59999", smb_tm)

        def samba_passwords():
            for who in ("bob", "carol"):
                _, page, auth = ses[who]
                state[f"{who}_smb"] = create_password(page, auth, SMB, who, replay=False)
            record_hashes()
            cip = state[f"{SMB}_ip"]
            rows = creds(SMB)
            for who in ("bob", "carol"):
                uid = rows[who]["ids"]["uid"]
                assert 20000 <= uid <= 59999 and uid != state.get("alice_uid"), f"{who}'s uid {uid}"
                state[f"{who}_uid"] = uid
                until(f"{who} lists Home", lambda w=who: smb(cip, "Home", w, state[f"{w}_smb"])[0], 60, every=3)
                ok, out = smb(cip, "Family", who, state[f"{who}_smb"])
                assert ok, f"{who} can't list Family: {out[-400:]}"
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
                f.write("written by carol\n")
                state["local_file"] = f.name
            ok, out = smb(cip, "Family", "carol", state["carol_smb"], f"put {state['local_file']} carol-writer.txt")
            assert ok, f"carol (writer) can't write to Family: {out[-400:]}"
            st = subprocess.run(["sudo", "stat", "-c", "%u:%g %a", os.path.join(FAMILY, "carol-writer.txt")],
                                capture_output=True, text=True).stdout.strip()
            assert st.startswith(f"{state['carol_uid']}:{state['gid']} "), f"carol's file: {st}"
            print(f"    carol's file on the host: {st}", flush=True)
        check("smb: bob and carol create Samba passwords (one assertion each); Home and Family list; carol "
              "(writer) writes to Family as <her uid>:<folder gid>", samba_passwords)

        # ── 4. removal through the Hub ──
        def revoke_hub():
            needs("alice_uid")
            t_audit = time.time()
            measure_revocation("hub-made removal (alice, users_timemachine)", state[f"{TM}_cid"], state[f"{TM}_ip"],
                               "TimeMachine-alice", "alice", state["alice_tm"], state["alice_uid"],
                               lambda: member("remove", "users_timemachine", "alice"), HUB_SLA_S)
            ents = [e for e in audit() if e.get("action") == "credential.revoke_leave" and "alice" in json.dumps(e)
                    and TM in json.dumps(e)]
            assert ents, f"no credential.revoke_leave for alice: {[e.get('action') for e in audit()][:30]}"
            assert creds(TM)["alice"]["status"] == "revoked", creds(TM)["alice"]
            print(f"    audit: {json.dumps(ents[0])[:300]} ({time.time() - t_audit:.0f} s)", flush=True)
        check(f"revoke_hub: alice removed from users_timemachine through the Hub: session dropped and a new login "
              f"refused within {HUB_SLA_S} s; audit credential.revoke_leave", revoke_hub)

        def demote():
            needs("carol_uid")
            cid, cip = state[f"{SMB}_cid"], state[f"{SMB}_ip"]
            s = Session(cip, "Family", "carol", state["carol_smb"])
            try:
                until("carol's Family session open", lambda: sessions_of(cid, state["carol_uid"]), 30, every=1)
                t0 = time.time()
                saved = hub_ok("PUT", f"/api/instances/{SMB}/settings", {"values": {"share1_writers": []}})
                try:
                    until("carol's write session ended", lambda: sessions_gone(cid, state["carol_uid"]), 30, every=0.5)
                except AssertionError as e:
                    # Evidence: what the save delivered, and whether smb.conf changed.
                    units = {u.get("unit"): {k: u.get(k) for k in ("ok", "skipped", "message", "error")}
                             for u in ((saved.get("deliveries") or {}).get("units") or {}).values()} \
                        if isinstance((saved.get("deliveries") or {}).get("units"), dict) else saved.get("deliveries")
                    tp = docker("exec", cid, "testparm", "-s")
                    fam = tp.split("[Family]", 1)[1].split("\n[", 1)[0] if "[Family]" in tp else "(no [Family])"
                    raise AssertionError(f"{e}; the save's deliveries: {json.dumps(units)[:1200]}; "
                                         f"[Family] now: {' | '.join(ln.strip() for ln in fam.splitlines() if ln.strip())}")
                took = time.time() - t0
                summary(f"LATENCY writer demoted to reader (carol, Family): session ended after {took:.1f} s")
            finally:
                s.close()
            ok, out = until("carol lists Family as a reader",
                            lambda: (r := smb(cip, "Family", "carol", state["carol_smb"]))[0] and r, 30, every=2)
            ok, out = smb(cip, "Family", "carol", state["carol_smb"], f"put {state['local_file']} carol-reader.txt")
            assert not ok and re.search(r"NT_STATUS_(ACCESS_DENIED|MEDIA_WRITE_PROTECTED)", out), \
                f"carol (reader) could write to Family: {out[-400:]}"
            print(f"    carol as a reader: {re.search(r'NT_STATUS_[A-Z_]+', out).group(0)}", flush=True)
        check("demote: share1_writers emptied through the Hub (carol stays a reader): her session is ended; a new "
              "login lists Family; Samba refuses her write", demote)

        # ── 5. removal directly in LLDAP ──
        def revoke_lldap():
            needs("bob_uid")
            gid = next(g["id"] for g in gql("{ groups { id displayName } }")["groups"] if g["displayName"] == "users_samba")

            def remove():
                gql(f'mutation {{ removeUserFromGroup(userId: "bob", groupId: {gid}) {{ ok }} }}')
            measure_revocation("LLDAP-direct removal (bob, users_samba)", state[f"{SMB}_cid"], state[f"{SMB}_ip"],
                               "Home", "bob", state["bob_smb"], state["bob_uid"], remove, LLDAP_SLA_S)
            until("bob revoked in the admin view", lambda: creds(SMB)["bob"]["status"] == "revoked", 30, every=2)
            op = hub("GET", f"/api/instances/{SMB}/op")[1]
            if isinstance(op, dict):
                OBS.append("samba op record after the LLDAP-direct revocation: " + scrub(json.dumps(
                    {k: op.get(k) for k in ("op", "ok", "error", "output", "hint")}))[:1500])
                print("    " + OBS[-1], flush=True)
        check(f"revoke_lldap: bob removed from users_samba with LLDAP's GraphQL: his login fails within "
              f"{LLDAP_SLA_S} s and his session is gone", revoke_lldap)

        # ── 6. instance restore voids ──
        def restore_inst():
            needs("carol_smb")
            rec = run_op("POST", f"/api/instances/{SMB}/backups", {})
            archive = (rec.get("result") or {}).get("archive", "")
            assert archive.startswith(f"{SMB}/"), rec
            state["smb_archive"] = archive
            run_op("POST", f"/api/instances/{SMB}/restore", {"archive": archive})
            row = creds(SMB)["carol"]
            assert row["status"] == "voided" and row.get("reason") == "restore", f"carol after the restore: {row}"
            cid = until("samba running again", lambda: app(SMB), 120)
            # Running is not listening: wait for the healthcheck (smbd up) before
            # asserting a logon failure, else a refused connection is what we get.
            until("samba healthy again", lambda: docker("inspect", "-f", "{{.State.Health.Status}}", cid).strip() == "healthy",
                  180, every=5)
            state[f"{SMB}_cid"], state[f"{SMB}_ip"] = cid, ip_of(cid)
            ok, out = smb(state[f"{SMB}_ip"], "Home", "carol", state["carol_smb"])
            assert not ok, "carol's password still works after the restore"
            assert "NT_STATUS_LOGON_FAILURE" in out, f"NT_STATUS_LOGON_FAILURE not in output: {out[:500]}"
            _, page, _ = ses["carol"]
            me = page.request.get(PEOPLE + "/api/me/apps")
            cred = next(c for a in me.json()["apps"] if a["id"] == SMB for c in a["credentials"] if c["key"] == KEY)
            assert cred["status"] == "voided" and cred.get("reason") == "restore", f"carol's /api/me/apps credential: {cred}"
            card = open_myapps(page, SMB)
            assert card.get_attribute("data-ma-status-kind") == "voided", card.get_attribute("data-ma-status-kind")
            assert "reset by a restore" in card.inner_text(), card.inner_text()
            assert not [f for f in nt_files() if f"/{SMB}/" in f], "Samba hash files left after the restore"
            state["restored_inst"] = True
        check("restore_inst: Samba backed up and restored through the Hub: carol's password no longer works, "
              "voided (restore), her card says 'reset by a restore'", restore_inst)

        def carol_again():
            needs("restored_inst")
            _, page, auth = ses["carol"]
            state["carol_smb2"] = create_password(page, auth, SMB, "carol", replay=False)
            record_hashes()
            until("carol's new password lists Home",
                  lambda: smb(state[f"{SMB}_ip"], "Home", "carol", state["carol_smb2"])[0], 60, every=3)
        check("restore_inst: carol creates a new password after the void (one assertion); it works", carol_again)

        def password_only_template():
            # Contract §8 "Governing template": a file-share password's fresh
            # sign-in is governed by the instance's template — Samba takes no
            # pick, so the default. dave has a Hub-set password only; with
            # password on, Standard refuses his password sign-in, a
            # password-only default accepts it (typing the password again).
            needs("setup")
            gql(f'mutation {{ createUser(user: {{id: "dave", email: "dave@{DOMAIN}"}}) {{ id }} }}')
            member("add", "users_samba", "dave")
            pw = hub_ok("POST", "/api/directory/users/dave/password", {"generate": True})["password"]
            mask(pw)
            PASSWORDS["dave-signin"] = pw
            hub_ok("PUT", "/api/signin/methods/password", {"on": True})
            code, out = hub("POST", "/api/signin/templates", {"id": "e2e-pw", "name": "Password only",
                                                              "rule": {"op": "any", "items": ["password"]}})
            assert code in (200, 201), f"create e2e-pw: HTTP {code} {scrub(str(out))[:300]}"
            state["pw_template"] = True
            until("password on in signin-keycloak.json", lambda: "password" in json.loads(docker(
                "run", "--rm", "--network", "none", "-v", "portcullis_hub_data:/d:ro", ALPINE, "cat",
                "/d/signin-keycloak.json"))["methods"], 60)

            def create_with_password(label: str) -> tuple[int, str]:
                ctx = browser.new_context()
                ctx.set_default_timeout(TIMEOUT_MS)
                page = ctx.new_page()
                landed: list[str] = []
                page.on("request", lambda r: landed.append(r.url) if r.url.startswith(PEOPLE + "/?") else None)
                verifier, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(16)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                q = {"client_id": "portcullis-fresh-auth", "response_type": "code", "scope": "openid",
                     "redirect_uri": PEOPLE + "/", "state": secrets.token_urlsafe(12), "nonce": nonce,
                     "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "login", "max_age": "0"}
                try:
                    page.goto(f"{AUTH}/realms/portcullis/protocol/openid-connect/auth?" + urllib.parse.urlencode(q),
                              wait_until="domcontentloaded")
                    page.wait_for_selector("#authenticateWebAuthnButton", state="visible")
                    page.click("#try-another-way")
                    page.wait_for_load_state("domcontentloaded")
                    page.get_by_text("Password", exact=True).first.click()
                    page.wait_for_selector("#password", state="visible")
                    page.fill("#username", "dave")
                    page.fill("#password", pw)
                    page.click("#kc-login")
                    code = None
                    for _ in range(60):  # Playwright delivers request events only inside its calls
                        code = next((c for u in landed for c in urllib.parse.parse_qs(
                            urllib.parse.urlsplit(u).query).get("code", [])), None)
                        if code:
                            break
                        page.wait_for_timeout(500)
                    assert code, f"{label}: no code at {PEOPLE}/ (at {page.url.split('?')[0]})"
                finally:
                    ctx.close()
                body = json.dumps({"code": code, "code_verifier": verifier, "nonce": nonce}).encode()
                req = urllib.request.Request(f"http://{state['hub_ip']}:8889/api/me/apps/{SMB}/credentials/{KEY}",
                                             data=body, method="POST", headers={
                                                 "X-Portcullis-Proxy-Secret": SECRET, "X-Forwarded-User": "dave",
                                                 "Content-Type": "application/json"})
                try:
                    with urllib.request.urlopen(req, timeout=120) as r:
                        return r.status, r.read().decode()
                except urllib.error.HTTPError as e:
                    return e.code, e.read().decode()

            code, out = create_with_password("standard")
            print(f"    Standard (the default) + a password: HTTP {code} {out.strip()[:80]}", flush=True)
            assert code == 403 and "a fresh sign-in is required" in out, f"Standard + password: HTTP {code} {out[:200]}"
            hub_ok("PUT", "/api/signin/default", {"template": "e2e-pw"})
            code, out = create_with_password("password-only")
            doc = json.loads(out) if code == 200 else {}
            if doc.get("password"):
                mask(doc["password"])
                PASSWORDS["dave"] = doc["password"]
            print(f"    password-only default + a password: HTTP {code}", flush=True)
            assert code == 200 and PW_RE.fullmatch(doc.get("password", "")), f"password-only + password: HTTP {code} {scrub(out)[:200]}"
            record_hashes()
            hits = [e for e in audit() if e.get("action") == "credential.create" and "user=dave" in (e.get("detail") or "")]
            assert any("template=e2e-pw" in (e.get("detail") or "") and e.get("result") == "ok" for e in hits), hits
            assert any("template standard" in (e.get("detail") or "") and e.get("result") == "refused" for e in hits), hits
            until("dave's new password lists Home",
                  lambda: smb(state[f"{SMB}_ip"], "Home", "dave", PASSWORDS["dave"])[0], 60, every=3)
        try:
            check("password_only_template: Samba governed by the default — Standard refuses dave's password fresh "
                  "sign-in (403), a password-only default accepts it (the password typed again); audited with the "
                  "template; the share works", password_only_template)
        finally:
            if state.pop("pw_template", False):
                hub("PUT", "/api/signin/default", {"template": "standard"})
                hub("DELETE", "/api/signin/templates/e2e-pw", {})
            hub("PUT", "/api/signin/methods/password", {"on": False})

        for who, (ctx, _, _) in ses.items():
            ctx.close()
        browser.close()

    # ── 8. no hash in instance archives ──
    def secrets_inst():
        needs("smb_archive")
        assert HASHES, "no hash recorded (nothing to look for)"
        names = docker("run", "--rm", "--network", "none", "-v", "portcullis_hub_data:/d:ro", ALPINE,
                       "find", f"/d/backups/{SMB}", "-type", "f", "-name", "*.tar").split()
        assert names, "no Samba instance archive"
        hits = []
        for n in names:
            data = docker("run", "--rm", "--network", "none", "-v", "portcullis_hub_data:/d:ro", ALPINE, "cat", n,
                          binary=True)
            hits += hash_hits(data, n)
        assert not hits, f"hash found in: {hits}"
        print(f"    {len(names)} instance archives, {len(HASHES)} hashes: none found", flush=True)
    check("secrets: no recorded hash in any Samba instance archive (the backup and the pre-restore one)", secrets_inst)

    # ── 9. no hash visible ──
    def visible():
        assert HASHES, "no hash recorded"
        hits = []
        for inst in (TM, SMB):
            cid = app(inst)
            hits += hash_hits(docker("inspect", cid).encode(), f"docker inspect {inst}")
            p = subprocess.run(["docker", "logs", cid], capture_output=True, timeout=60)
            hits += hash_hits(p.stdout + p.stderr, f"docker logs {inst}")
        hcid = container("portcullis", "hub")
        p = subprocess.run(["docker", "logs", hcid], capture_output=True, timeout=60)
        hits += hash_hits(p.stdout + p.stderr, "hub logs")
        hits += hash_hits(docker("inspect", hcid).encode(), "docker inspect hub")
        data = docker("run", "--rm", "--network", "none", "-v", "portcullis_hub_data:/d:ro", ALPINE,
                      "tar", "cf", "-", "-C", "/d", ".", binary=True, timeout=300)
        hits += hash_hits(data, "hub_data")
        assert not hits, f"hash found in: {hits}"
    check("visible: docker inspect of both containers and the Hub, the Hub's and the apps' logs, the whole "
          "hub_data volume (state, audit, ops, archives): no hash", visible)

    # ── 7. core backup / restore voids every credential ──
    def restore_core():
        # carol's active password: the one made after the instance restore,
        # else (that restore refused) her first one.
        pw_key = "carol_smb2" if "carol_smb2" in state else "carol_smb"
        needs(pw_key)
        assert creds(SMB)["carol"]["status"] == "active", creds(SMB)["carol"]
        state["carol_active"] = state[pw_key]
        # The apps hold hub_secrets (read-only subpath mounts) and keep
        # running: ./portcullis restore must take them down itself.
        def holders():
            users = docker("ps", "--filter", f"volume={SECRETS_VOLUME}", "--format", "{{.Names}}").split()
            apps = [n for n in users if n.startswith(("portcullis-samba", "portcullis-timemachine"))]
            return len(apps) == 2 and users
        # Both running (a restart the Hub queued earlier may still be on its way).
        users = until(f"both apps running and mounting {SECRETS_VOLUME}", holders, 300, every=5)
        until("samba healthy", lambda: docker("inspect", "-f", "{{.State.Health.Status}}", app(SMB)).strip() == "healthy",
              180, every=5)
        OBS.append(f"containers mounting {SECRETS_VOLUME} before the core restore: {sorted(users)}")
        print(f"    {OBS[-1]}", flush=True)
        before = set(glob.glob("backups/2*"))
        subprocess.run(["./portcullis", "backup"], check=True, timeout=1800)
        new = sorted(set(glob.glob("backups/2*")) - before)
        assert len(new) == 1, f"backup dirs: {new}"
        state["core_backup"] = new[0]
        files = subprocess.run(["sudo", "find", new[0], "-type", "f"], capture_output=True, text=True,
                               check=True).stdout.split()
        assert any(f.endswith("hub_data.tar.gz") for f in files), files
        hits = []
        for f in files:
            data = subprocess.run(["sudo", "cat", f], capture_output=True, check=True).stdout
            hits += hash_hits(data, f)
        assert not hits, f"hash found in the core backup: {hits}"
        print(f"    core backup {new[0]}: {len(files)} files, no hash", flush=True)
        state["core_scanned"] = True
        p = subprocess.run(["./portcullis", "restore", "--yes", new[0]], capture_output=True, text=True, timeout=2400)
        out = scrub(p.stdout + p.stderr)
        print("\n".join("    restore: " + ln for ln in out.splitlines()[-25:]), flush=True)
        assert p.returncode == 0, f"./portcullis restore with the apps running: rc {p.returncode}"
        for proj in (f"portcullis-{SMB}", f"portcullis-{TM}"):
            assert re.search(rf"Taken down for the restore and NOT started again:.*\b{re.escape(proj)}\b", out), \
                f"the restore didn't report {proj} as taken down"
            left = docker("ps", "-aq", "--filter", f"label=com.docker.compose.project={proj}").split()
            assert not left, f"{proj} has containers after the restore (it must stay down): {left}"
        vols = docker("volume", "ls", "-q").split()
        assert "portcullis_samba-homes" in vols and "portcullis_timemachine-data" in vols, \
            f"the apps' volumes were not kept: {vols}"
        try:
            state["hub_ip"] = until("the Hub after the restore", lambda: hub_ip(), 180, every=5)
            until("the Hub answers", lambda: hub("GET", "/api/directory")[0] == 200, 300, every=5)
        except AssertionError as e:
            p = subprocess.run(["docker", "compose", "logs", "--no-color", "--tail=30", "hub"], capture_output=True,
                               text=True, timeout=60)
            raise AssertionError(f"{e}; hub logs: {scrub(p.stdout + p.stderr)[-2500:]}")
        row = until("carol voided after the core restore",
                    lambda: (r := creds(SMB).get("carol")) and r["status"] == "voided" and r, 300, every=5)
        assert row.get("reason") == "restore", row
        assert not nt_files(), f"hash files after the core restore: {len(nt_files())}"
        assert docker("run", "--rm", "--network", "none", "-v", f"{SECRETS_VOLUME}:/s:ro", ALPINE,
                      "stat", "-c", "%u:%g %a", "/s").strip() == "10001:10001 700"
        voids = [e for e in audit() if e.get("action") == "credential.void_restore"]
        assert voids, "no credential.void_restore in the audit"
        # Started again by the admin, as the restore's message says.
        run_op("POST", f"/api/templates/restart/{SMB}", {}, timeout=1500)
        cid = until("samba running", lambda: app(SMB), 120)
        until("samba healthy", lambda: docker("inspect", "-f", "{{.State.Health.Status}}", cid).strip() == "healthy",
              180, every=5)
        ok, out = smb(ip_of(cid), "Home", "carol", state["carol_active"])
        assert not ok, "carol's password still works after the core restore"
        assert "NT_STATUS_LOGON_FAILURE" in out, f"NT_STATUS_LOGON_FAILURE not in smbclient output: {out[:500]}"
        p = subprocess.run(["docker", "logs", container("portcullis", "hub")], capture_output=True, timeout=60)
        assert not hash_hits(p.stdout + p.stderr, "hub logs"), "a hash in the Hub's logs after the restore"
    check("restore_core: ./portcullis backup (no hash in it) → ./portcullis restore with both apps running: it takes "
          "them down (volumes kept, reported, not restarted), voids every credential (epoch missing), no hash file "
          "left; carol's password fails after Samba is restarted from the Hub", restore_core)

    for k, v in LATENCY.items():
        summary(f"F60 {k}: {v:.1f} s")
    for o in OBS:
        summary(f"OBSERVED {o}")
    return report()


def report() -> int:
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    for name, _, err in failed:
        print(f"  FAIL {name}: {err}")
    return 1 if failed or not results else 0


if __name__ == "__main__":
    sys.exit(main())
