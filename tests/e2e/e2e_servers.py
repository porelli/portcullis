#!/usr/bin/env python3
"""Multiple servers end to end (contract §17; ci.yml jobs e2e-servers and
e2e-servers-podman). The primary runs the whole stack with `link init`; the
workers are docker:dind containers (or a pinned quay.io/podman/stable
container running rootless Podman as its user `podman`), joined with `./portcullis worker join` and the code on stdin.

Cases, in this order (one function each):

  join_ok                         add w1 (fresh sign-in), the code on the worker's stdin, ready
  join_code_reused_refused        the same code on another worker never enrols
  join_code_expired_refused       a code past its 15 min (the Hub's clock, a CI-only hook) is refused
  echo_on_worker_signed_in        an instance placed on w1 answers through the primary, same tier as one on the primary
  echo_on_worker_denied_without_sign_in
  no_portcullis_cookie_reaches_app      the app sees no Portcullis cookie
  parent_domain_set_cookie_stripped     a Set-Cookie for the parent domain comes back host-only
  move_worker_primary_worker_keeps_data the volume's marker survives w1 → primary (move) → w1 (Undo move)
  move_back_onto_kept_copy_refused      a direct move onto a server holding a kept copy is 409
  wg_stopped_fails_closed         wg down: the app is unreachable, its containers still run on w1
  wg_back_routes_again
  rogue_worker                    .github/ci/e2e-servers-rogue.sh (dind job: two workers)
  revoke_drops_handshake_and_rotates    the peer gone, the instance's client secret new
  revoke_cuts_websocket           a long-lived stream through the relay ends at the revocation
  socket_rule_both_stacks         .github/ci/e2e-servers-asserts.sh

The join code is a secret: written only to a 0700 temp dir and piped to
the worker; never an argument, an artifact or a log line. No secret is ever
printed, not even in an ::add-mask:: line (run-job's log keeps every line):
every failure text and command output goes through redact() (the known
secrets, join codes, bearer tokens, setup-link and OAuth code paths become
"[redacted]"); credentials come from core's .env, the setup links from
e2e-servers-setup.sh's 0600 files ($E2E_SERVERS_SECRETS).
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
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from playwright.sync_api import Page, sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_login as base  # noqa: E402
import e2e_ops  # noqa: E402
import scenarios  # noqa: E402

DOMAIN = os.environ["E2E_DOMAIN"]
KIND = os.environ.get("E2E_WORKER_KIND", "dind")  # dind | podman
HUB_API = f"http://{os.environ['HUB_IP']}:8888"
AUTH = f"https://auth.{DOMAIN}"
HUB = f"https://hub.{DOMAIN}"
PORTAL = f"https://{DOMAIN}/"


def dotenv(key: str) -> str:
    """A value of core's .env (secrets never pass through the step env)."""
    for line in open(".env"):
        if line.startswith(key + "="):
            return line[len(key) + 1:].rstrip("\n")
    raise KeyError(key)


def secret_file(name: str) -> str:
    """A 0600 file of e2e-servers-setup.sh's 0700 dir (the setup links)."""
    return open(os.path.join(os.environ["E2E_SERVERS_SECRETS"], name)).read().strip()


SECRET = dotenv("HUB_PROXY_SECRET")
# Never in any output (CI's and run-job's logs keep everything): each known
# secret and every token-shaped value becomes a fixed placeholder.
SECRETS: list[str] = [SECRET, dotenv("LLDAP_ADMIN_PASSWORD"), dotenv("KEYCLOAK_ADMIN_PASSWORD")]
TOKEN_RES = [re.compile(r"pcj1\.[A-Za-z0-9_.-]+"), re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
             re.compile(r"::add-mask::.*"), re.compile(r"(/setup/|/invite/|[?&](?:token|code|key|code_verifier)=)[A-Za-z0-9._~%-]+")]


def redact(s: str) -> str:
    for v in SECRETS:
        if v and len(v) >= 6:
            s = s.replace(v, "[redacted]")
    for r in TOKEN_RES:
        s = r.sub(lambda m: (m.group(1) if m.re.groups else "") + "[redacted]", s)
    return s


def mint_link(user: str, to: str) -> str:
    """A new setup link, as e2e_login.mint_setup_link but printing nothing
    (no ::add-mask:: line: run-job's log keeps every line)."""
    out = subprocess.run(["./portcullis", "invite", user, "--to", to, "--json"], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, redact(f"portcullis invite {user}: exit {out.returncode} {out.stderr[-300:]}")
    url = json.loads(out.stdout)["url"]
    assert re.fullmatch(r"https://enroll\.[A-Za-z0-9.-]+/invite/[A-Za-z0-9_-]{43}", url), "malformed setup link"
    SECRETS.append(url)
    return url


# check is base.check with every failure's text redacted (its traceback too).
def check(name: str, fn) -> None:
    if scenarios.skip(name):  # E2E_SCENARIOS (tests/e2e/scenarios.py)
        return

    def run():
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            raise AssertionError(redact(f"{type(e).__name__}: {e}" if not isinstance(e, AssertionError) else str(e))) from None
    base.check(name=name, fn=run)


TMP = tempfile.mkdtemp(prefix="e2e-servers-")
os.chmod(TMP, 0o700)
WORKER_SH = ".github/ci/e2e-servers-worker.sh"
state: dict = {}


def hub(method: str, path: str, body=None, timeout: float = 60):
    """The Hub's admin API as Traefik calls it (proxy secret + the admin)."""
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(HUB_API + path, data=data, method=method, headers={
        "X-Portcullis-Proxy-Secret": SECRET, "X-Forwarded-User": "admin", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors="replace")[:400]


def hub_ok(method: str, path: str, body=None, want=(200, 201, 202, 204)):
    code, b = hub(method, path, body)
    assert code in want, f"{method} {path}: {code} {str(b)[:400]}"
    return b


def get(path: str):
    return hub_ok("GET", path)


def run_op(method: str, path: str, body=None, timeout: float = 600) -> dict:
    acc = e2e_ops.accepted(hub_ok(method, path, body, want=(202,)))
    rec = e2e_ops.wait(get, acc, timeout)
    return e2e_ops.check_ok(acc, rec)


def sh(*args, check=True, stdin=None, timeout=900) -> subprocess.CompletedProcess:
    p = subprocess.run(list(args), stdin=stdin, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise AssertionError(redact(f"{' '.join(args[:4])}: exit {p.returncode}: {p.stdout[-800:]} {p.stderr[-800:]}"))
    return p


def fresh_proof(page: Page, label: str) -> dict:
    """The Hub's fresh sign-in (prompt=login, max_age=0, PKCE S256) as the
    Servers page's popup runs it: the proof a † route takes."""
    fa = get("/api/servers")["fresh_auth"]
    redirect = fa["redirect_uri"]
    seen: list[str] = []
    page.on("request", lambda r: seen.append(r.url) if r.url.startswith(redirect + "?") else None)
    verifier, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(16)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {"client_id": fa["client_id"], "response_type": "code", "scope": "openid", "redirect_uri": redirect,
         "state": secrets.token_urlsafe(12), "nonce": nonce, "code_challenge": challenge,
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
        if page.url.startswith(AUTH) and page.locator("#authenticateWebAuthnButton").is_visible():
            page.click("#authenticateWebAuthnButton")
        page.wait_for_timeout(700)
    base.shot(page, f"{label}-fresh-timeout")
    raise AssertionError(f"{label}: no fresh-auth code (stuck at {page.url.split('?')[0]})")


def add_server(sid: str) -> dict:
    """POST /api/servers (fresh sign-in): the code goes to a 0700 file only."""
    body = dict(id=sid, name=sid.upper(), **fresh_proof(state["admin_page"], f"add-{sid}"))
    code, ans = hub("POST", "/api/servers", body)
    if code >= 500:  # the Hub's view of its data dir (no secret in a listing)
        print(redact(sh("docker", "compose", "exec", "-T", "hub", "sh", "-c",
                        "id; ls -lan /data /data/nodes; stat -c '%A %u:%g %n' /data/nodes/* 2>&1", check=False).stdout), flush=True)
    assert code == 201 and isinstance(ans, dict) and ans.get("code", "").startswith("pcj1."), f"add {sid}: {code} {str(ans)[:200]}"
    path = os.path.join(TMP, f"{sid}.code")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
        f.write(ans["code"])
    ans["code"] = None  # never kept in memory past the file
    ans["code_file"] = path
    return ans


def join(kind: str, name: str, code_file: str, wait: int = 240, check=True) -> subprocess.CompletedProcess:
    """The worker script with the code on stdin; its output goes to a
    0600 file (checked for the code, then printed), also on a timeout."""
    log = os.path.join(TMP, f"{name}.join.log")
    rc = None
    with open(code_file) as f, open(log, "w") as out:
        os.chmod(log, 0o600)
        try:
            rc = subprocess.run(["bash", WORKER_SH, kind, name], stdin=f, stdout=out, stderr=subprocess.STDOUT,
                                timeout=wait + 420, env=dict(os.environ, WORKER_JOIN_WAIT=str(wait))).returncode
        except subprocess.TimeoutExpired:
            rc = "timeout"
            diag(name)
    text = open(log, errors="replace").read()
    assert "pcj1." not in text, "the join code reached the worker script's output"
    text = redact(text)
    print(f"::group::worker {name} ({kind}): exit {rc}\n{text[-6000:]}\n::endgroup::", flush=True)
    if check and rc != 0:
        raise AssertionError(f"worker {name}: exit {rc}: {text[-800:]}")
    return subprocess.CompletedProcess([WORKER_SH, kind, name], rc if isinstance(rc, int) else 124, text, "")


def wexec(name: str, *cmd, check=True) -> subprocess.CompletedProcess:
    return sh("bash", WORKER_SH, "exec", name, *cmd, check=check)


def server_state(sid: str):
    code, s = hub("GET", f"/api/servers/{sid}")
    return s.get("state") if code == 200 and isinstance(s, dict) else code


def needs(*keys: str) -> None:
    """An earlier case's state (scenarios.py reads these calls: running one
    case runs the cases that set its keys)."""
    missing = [k for k in keys if k not in state]
    assert not missing, f"needs {', '.join(missing)} (an earlier case failed)"


def wait_for(what: str, fn, timeout: float, every: float = 3):
    deadline, last = time.time() + timeout, None
    while time.time() < deadline:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
        time.sleep(every)
    raise AssertionError(f"{what}: not within {timeout:.0f} s (last: {str(last)[:300]})")


def link_peers() -> list:
    st = json.loads(sh("docker", "compose", "exec", "-T", "wg", "/wg", "status").stdout)
    return (st.get("link") or {}).get("peers") or []


def lldap_member(user: str, group: str) -> None:
    tok = json.loads(urllib.request.urlopen(urllib.request.Request(
        "http://127.0.0.1:17170/auth/simple/login", method="POST", headers={"Content-Type": "application/json"},
        data=json.dumps({"username": "admin", "password": dotenv("LLDAP_ADMIN_PASSWORD")}).encode()), timeout=20).read())["token"]

    def gql(q: str) -> dict:
        return json.loads(urllib.request.urlopen(urllib.request.Request(
            "http://127.0.0.1:17170/api/graphql", method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok}"},
            data=json.dumps({"query": q}).encode()), timeout=20).read())
    gid = [g["id"] for g in gql("{ groups { id displayName } }")["data"]["groups"] if g["displayName"] == group][0]
    r = gql(f'mutation {{ addUserToGroup(userId: "{user}", groupId: {gid}) {{ ok }} }}')
    assert not r.get("errors"), r


def fresh_get(page: Page, url: str):
    """GET url with page's cookies on new connections (a throwaway context
    with its storage state): a kept-alive connection set up before a host
    had a router keeps answering 421 Misdirected Request, and Playwright's
    request client — unlike a browser — never retries on a new one."""
    ctx = state["browser"].new_context(storage_state=page.context.storage_state())
    try:
        r = ctx.request.get(url, max_redirects=0)
        return r.status, r.text(), [h["value"] for h in r.headers_array if h["name"].lower() == "set-cookie"], r.headers.get("location", "")
    finally:
        ctx.close()


def echo(page: Page, iid: str):
    """alice's GET of the instance's CGI through the primary: (status, body, set-cookies)."""
    st, body, cookies, _ = fresh_get(page, f"https://{iid}.{DOMAIN}/cgi-bin/echo")
    return st, body, cookies


def reach(page: Page, iid: str) -> bool:
    """The instance answers alice through the primary (the last answer is
    kept for the failure message: status, Location's path and whether the
    body names the host — never the body: it echoes her session cookie)."""
    try:
        st, body, _, loc = fresh_get(page, f"https://{iid}.{DOMAIN}/cgi-bin/echo")
        state[f"last_reach_{iid}"] = f"{st} {loc.split('?')[0]} host-line={'HOST=' in body} {len(body)} bytes"
        return st == 200 and f"HOST={iid}.{DOMAIN}" in body
    except Exception as e:  # noqa: BLE001
        state[f"last_reach_{iid}"] = f"{type(e).__name__}: {redact(str(e))[:200]}"
        return False


# ── the cases ──

def diag(name: str) -> None:
    """What a failed enrolment needs to be understood (no secret in any
    of it): link's peers, the agent's routes / addresses / log, its
    networks."""
    out = []
    for title, cmd in (
        ("link status", ["docker", "compose", "exec", "-T", "wg", "/wg", "status"]),
        ("wg log", ["docker", "compose", "logs", "--no-color", "--tail=40", "wg"]),
        (f"{name} agent routes", ["bash", WORKER_SH, "exec", name, "docker", "exec", "portcullis-worker-agent-1", "sh", "-c",
                                  "ip route; ip -4 addr; cat /etc/resolv.conf"]),
        (f"{name} networks", ["bash", WORKER_SH, "exec", name, "docker", "network", "ls"]),
        (f"{name} containers", ["bash", WORKER_SH, "exec", name, "docker", "ps", "-a", "--format", "{{.Names}} {{.Status}}"]),
        (f"{name} proxy health", ["bash", WORKER_SH, "exec", name, "docker", "inspect", "--format", "{{json .State.Health}}",
                                  "portcullis-worker-socket-proxy-agent-1"]),
        (f"{name} proxy log", ["bash", WORKER_SH, "compose", name, "logs", "--no-color", "--tail=30", "socket-proxy-agent"]),
        (f"{name} agent log", ["bash", WORKER_SH, "compose", name, "logs", "--no-color", "--tail=60", "agent"]),
    ):
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out.append(f"--- {title} (exit {p.returncode})\n{(p.stdout + p.stderr)[-3000:]}")
    text = "\n".join(out)
    assert "pcj1." not in text
    print(f"::group::diagnostics {name}\n{redact(text)}\n::endgroup::", flush=True)


def join_ok():
    ans = add_server("w1")
    state["w1_op"] = ans
    join(KIND, "w1", ans["code_file"])
    rec = e2e_ops.wait(get, {"op_id": ans["op_id"], "poll": ans["poll"], "op": "server_enrol"}, 300)
    if not rec.get("ok"):
        diag("w1")
    assert rec.get("ok"), f"server_enrol: {e2e_ops.describe(rec)}"
    assert "pcj1." not in json.dumps(rec), "the code is in the op record"
    wait_for("w1 ready", lambda: server_state("w1") == "ready", 120)
    assert any(p["id"] == "w1" and p.get("handshake") for p in link_peers()), f"no w1 handshake: {link_peers()}"
    assert "pcj1." not in sh("docker", "compose", "logs", "hub", "wg").stdout, "the code is in the Hub's or wg's log"
    state["w1"] = True


def join_code_reused_refused():
    needs("w1")  # join_ok
    p = join(KIND if KIND == "dind" else "dind", "w1b", state["w1_op"]["code_file"], wait=60, check=False)
    assert p.returncode != 0, "a used code enrolled a second worker"
    names = [s["id"] for s in get("/api/servers")["servers"]]
    assert "w1b" not in names and names.count("w1") == 1, f"servers after a reused code: {names}"
    assert server_state("w1") == "ready", "w1 isn't ready after the reused code"
    sh("docker", "rm", "-f", "e2e-w1b", check=False)


def set_clock(offset: str) -> None:
    sh("docker", "run", "--rm", "-v", "portcullis_hub_data:/data", "--user", "10001:10001", os.environ["ALPINE"],
       "sh", "-c", f"printf '%s' '{offset}' > /data/dev-clock-offset")


def join_code_expired_refused():
    ans = add_server("w2x")
    try:
        set_clock("16m")
        rec = e2e_ops.wait(get, {"op_id": ans["op_id"], "poll": ans["poll"], "op": "server_enrol"}, 120)
        assert not rec.get("ok"), f"an expired code's enrolment didn't fail: {e2e_ops.describe(rec)}"
        p = join("dind", "w2x", ans["code_file"], wait=45, check=False)
        assert p.returncode != 0, "an expired code enrolled a worker"
        wait_for("w2x gone", lambda: server_state("w2x") == 404, 60)
    finally:
        set_clock("")
        sh("docker", "rm", "-f", "e2e-w2x", check=False)
    # A Hub clock 16 min ahead reads link's status as stale: w1 goes offline
    # (fail closed) until the next status write after the reset.
    if state.get("w1"):
        wait_for("w1 ready again after the clock reset", lambda: server_state("w1") == "ready", 180)


def echo_on_worker_signed_in():
    needs("w1")  # join_ok
    for iid, srv in (("se0", ""), ("se1", "w1")):
        run_op("POST", "/api/instances", {"template": "servers-echo", "id": iid, "label": iid.upper(),
                                          "hosts": {"secho": f"{iid}.{DOMAIN}"}, "server": srv})
        lldap_member("alice", f"users_{iid}")
        run_op("POST", "/api/templates/enable", {"id": iid}, timeout=900)
    page = state["alice_page"]
    try:
        wait_for("se1 through the relay", lambda: reach(page, "se1"), 180)
    except AssertionError as e:
        reach(page, "se0")
        raise AssertionError(f"{e}; se1's last answer: {state.get('last_reach_se1')}; se0's: {state.get('last_reach_se0')}") from None
    assert reach(page, "se0"), "se0 (on the primary) isn't reachable"
    # The data file (0640 group 10001) is readable by the app through its
    # group_add, on the primary and on the worker alike (§13.7 parity).
    for iid in ("se0", "se1"):
        body = echo(page, iid)[1]
        assert "DATAFILE=readable" in body, f"{iid}: the app can't read its data file (DATAFILE=unreadable: {'DATAFILE=unreadable' in body})"
    a, b = get("/api/instances/se0/signin"), get("/api/instances/se1/signin")
    assert {k: a.get(k) for k in ("template", "tier")} == {k: b.get(k) for k in ("template", "tier")}, f"tiers differ: {a} / {b}"
    ps = wexec("w1", "docker", "ps", "--filter", "label=com.docker.compose.project=portcullis-se1", "--format", "{{.Names}}").stdout
    assert ps.strip(), "se1 has no container on w1"
    # On the primary, se1's project holds only its relays (the same compose
    # project and service labels as the app's — contract §5 relays), never
    # the app's image.
    imgs = sh("docker", "ps", "-a", "--filter", "label=com.docker.compose.project=portcullis-se1",
              "--format", "{{.Image}}").stdout.split()
    assert imgs and all(i == os.environ["RELAY_IMAGE"] for i in imgs), f"se1's project on the primary runs {imgs}, not only the relay"
    state["se1"] = True


def echo_on_worker_denied_without_sign_in():
    needs("se1")  # echo_on_worker_signed_in
    ctx = state["browser"].new_context(ignore_https_errors=True)
    try:
        r = ctx.request.get(f"https://se1.{DOMAIN}/cgi-bin/echo", max_redirects=0)
        assert r.status in (302, 303, 401, 403) and "HOST=" not in r.text(), f"unsigned request: {r.status} {r.text()[:200]}"
    finally:
        ctx.close()


def no_portcullis_cookie_reaches_app():
    needs("se1")  # echo_on_worker_signed_in
    st, body, _ = echo(state["alice_page"], "se1")
    line = [ln for ln in body.splitlines() if ln.startswith("COOKIE=")][0]
    for bad in ("_oauth2_proxy", "__Host-portcullis_ext", "_oauth2_proxy_csrf"):
        names = [c.split("=", 1)[0].strip() for c in line[len("COOKIE="):].split(";") if c.strip()]
        assert bad not in line, f"the app on w1 saw {bad} (cookie names: {names})"  # never the values


def parent_domain_set_cookie_stripped():
    needs("se1")  # echo_on_worker_signed_in
    _, _, cookies = echo(state["alice_page"], "se1")
    wide = [c for c in cookies if c.startswith("wide=")]
    assert wide and all("domain=" not in c.lower() for c in wide), f"Set-Cookie for the parent domain: {cookies}"
    assert any(c.startswith("own=") for c in cookies), f"the host-only cookie is gone: {cookies}"


def marker(where: str, write: str | None = None) -> str:
    vol = "portcullis_se1-marker"  # the Hub's name for se1's volume (portcullis_<id>-<volume>)
    # Never create it: a mistyped name would silently make an empty one.
    probe = (lambda *c: sh(*c, check=False)) if where == "primary" else (lambda *c: wexec("w1", *c, check=False))
    assert probe("docker", "volume", "inspect", vol).returncode == 0, f"no volume {vol} on {where}"
    cmd = f"printf %s {write} > /d/marker && chmod 644 /d/marker" if write else "cat /d/marker"
    if where == "primary":
        return sh("docker", "run", "--rm", "-v", f"{vol}:/d", os.environ["ALPINE"], "sh", "-c", cmd).stdout
    return wexec("w1", "docker", "run", "--rm", "-v", f"{vol}:/d", os.environ["ALPINE"], "sh", "-c", cmd).stdout


def move_worker_primary_worker_keeps_data():
    needs("se1")  # echo_on_worker_signed_in
    mark = secrets.token_hex(8)
    marker("w1", mark)
    page = state["alice_page"]
    run_op("POST", "/api/instances/se1/move", {"server": ""}, timeout=900)
    assert marker("primary").strip() == mark, "the marker after the move to the primary"
    wait_for("se1 on the primary", lambda: f"MARKER={mark}" in echo(page, "se1")[1], 180)
    # Back onto w1, which keeps the previous copy: Undo move (contract
    # §17.6 "Kept copies"; a direct move there is refused — next case).
    body = dict(confirm="se1", **fresh_proof(state["admin_page"], "undo-se1"))
    run_op("POST", "/api/instances/se1/move/undo", body, timeout=900)
    assert marker("w1").strip() == mark, "the marker after the undo back to w1"
    wait_for("se1 on w1 again", lambda: f"MARKER={mark}" in echo(page, "se1")[1], 180)
    state["se1_moved"] = True


def move_back_onto_kept_copy_refused():
    needs("se1_moved")  # move_worker_primary_worker_keeps_data
    # The undo left the primary's copy kept: a direct move there is refused
    # up front, nothing sent, se1 still on w1.
    code, ans = hub("POST", "/api/instances/se1/move", {"server": ""})
    assert code == 409 and "still holds a previous copy of se1" in str(ans), f"a move onto the kept copy: {code} {str(ans)[:300]}"
    lst = get("/api/instances")
    rows = lst if isinstance(lst, list) else lst.get("instances", [])
    se1 = [r for r in rows if r.get("id") == "se1"]
    assert se1 and se1[0].get("server") == "w1", f"se1 left w1: {se1}"


def wg_stopped_fails_closed():
    needs("se1")  # echo_on_worker_signed_in
    sh("docker", "compose", "stop", "wg")
    page = state["alice_page"]
    wait_for("se1 unreachable with wg down", lambda: not reach(page, "se1"), 60)
    ps = wexec("w1", "docker", "ps", "--filter", "label=com.docker.compose.project=portcullis-se1", "--format", "{{.Status}}").stdout
    assert "Up" in ps, f"se1's containers stopped on w1: {ps}"


def wg_back_routes_again():
    sh("docker", "compose", "start", "wg")  # always: later cases need wg
    needs("se1")  # echo_on_worker_signed_in
    # link back first (the Hub reads servers as off until wg's status is
    # fresh again), then w1 ready, then the app through it.
    wait_for("servers on again", lambda: hub("GET", "/api/servers")[0] == 200, 120)
    wait_for("w1 ready again", lambda: server_state("w1") == "ready", 180)
    wait_for("se1 routed again", lambda: reach(state["alice_page"], "se1"), 240)


def rogue_worker():
    needs("w1")  # join_ok
    if KIND == "dind":
        ans = add_server("w3")
        join("dind", "w3", ans["code_file"])
        wait_for("w3 ready", lambda: server_state("w3") == "ready", 120)
    sh("bash", ".github/ci/e2e-servers-rogue.sh", KIND, timeout=1800)


def keycloak_secret(client_like: str) -> str:
    tok = json.loads(urllib.request.urlopen(urllib.request.Request(
        "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token", method="POST",
        data=urllib.parse.urlencode({"client_id": "admin-cli", "grant_type": "password", "username": dotenv("KEYCLOAK_ADMIN"),
                                     "password": dotenv("KEYCLOAK_ADMIN_PASSWORD")}).encode()), timeout=20).read())["access_token"]

    def kc(path: str):
        return json.loads(urllib.request.urlopen(urllib.request.Request(
            "http://127.0.0.1:8080/admin/realms/portcullis" + path, headers={"Authorization": f"Bearer {tok}"}), timeout=20).read())
    cl = [c for c in kc("/clients?max=500") if client_like in c.get("clientId", "")]
    assert cl, f"no Keycloak client like {client_like}"
    v = kc(f"/clients/{cl[0]['id']}/client-secret")["value"]
    SECRETS.append(v)
    return v


def revoke_drops_handshake_and_rotates():
    needs("se1")  # echo_on_worker_signed_in
    run_op("POST", "/api/instances", {"template": "oidc-echo", "id": "oe1", "label": "OE1",
                                      "hosts": {"oidc": f"oe1.{DOMAIN}"}, "server": "w1"})
    run_op("POST", "/api/templates/enable", {"id": "oe1"}, timeout=900)
    before = keycloak_secret("oe1")
    # A long-lived stream through the relay, open across the revocation.
    stream = {"closed_after": None}

    def hold():
        st = state["alice_ctx"].cookies()
        hdr = "; ".join(f"{c['name']}={c['value']}" for c in st if DOMAIN in c["domain"])
        req = urllib.request.Request(f"https://se1.{DOMAIN}/cgi-bin/echo?stream", headers={"Cookie": hdr})
        try:
            with urllib.request.urlopen(req, timeout=300, context=_tls()) as r:
                while r.read(1):
                    pass
        except Exception:  # noqa: BLE001
            pass
        stream["closed_after"] = time.time()
    t = threading.Thread(target=hold, daemon=True)
    t.start()
    time.sleep(5)
    t0 = time.time()
    body = dict(confirm="w1", **fresh_proof(state["admin_page"], "revoke-w1"))
    hub_ok("POST", "/api/servers/w1/revoke", body)
    wait_for("w1 out of link", lambda: all(p["id"] != "w1" for p in link_peers()), 15, every=1)
    assert server_state("w1") == "revoked", f"w1 is {server_state('w1')}"
    wait_for("oe1's client secret rotated", lambda: keycloak_secret("oe1") != before, 120)
    t.join(timeout=60)
    state["stream"] = (t0, stream["closed_after"])


def _tls():
    import ssl
    c = ssl.create_default_context(cafile="certs/ca-chain.crt")
    return c


def revoke_cuts_websocket():
    needs("stream")  # revoke_drops_handshake_and_rotates
    t0, closed = state["stream"]
    assert closed is not None and closed - t0 < 30, f"the stream outlived the revocation ({None if closed is None else round(closed - t0)} s)"


def socket_rule_both_stacks():
    sh("bash", ".github/ci/e2e-servers-asserts.sh", KIND)


def main() -> int:
    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])
        state["browser"] = browser
        for who, until in (("admin", HUB), ("alice", PORTAL)):
            def signs_in(who=who, until=until):
                ctx = browser.new_context()
                ctx.set_default_timeout(30_000)
                page = ctx.new_page()
                key = base.Authenticator(page)
                base.setup_link_signin(page, secret_file(f"{who}.invite"), who=who,
                                       mint=lambda: mint_link(who, "hub" if who == "admin" else "portal"),
                                       until=until, label=f"servers-{who}", expect_stepups=1)
                state[f"{who}_ctx"], state[f"{who}_page"], state[f"{who}_key"] = ctx, page, key
            check(f"{who} signs in from a setup link", signs_in)
        # One check each, by a literal name (tests/e2e/scenarios.py reads them).
        check("join_ok", join_ok)
        check("join_code_reused_refused", join_code_reused_refused)
        check("join_code_expired_refused", join_code_expired_refused)
        check("echo_on_worker_signed_in", echo_on_worker_signed_in)
        check("echo_on_worker_denied_without_sign_in", echo_on_worker_denied_without_sign_in)
        check("no_portcullis_cookie_reaches_app", no_portcullis_cookie_reaches_app)
        check("parent_domain_set_cookie_stripped", parent_domain_set_cookie_stripped)
        check("move_worker_primary_worker_keeps_data", move_worker_primary_worker_keeps_data)
        check("move_back_onto_kept_copy_refused", move_back_onto_kept_copy_refused)
        check("wg_stopped_fails_closed", wg_stopped_fails_closed)
        check("wg_back_routes_again", wg_back_routes_again)
        check("rogue_worker", rogue_worker)
        check("revoke_drops_handshake_and_rotates", revoke_drops_handshake_and_rotates)
        check("revoke_cuts_websocket", revoke_cuts_websocket)
        check("socket_rule_both_stacks", socket_rule_both_stacks)
        browser.close()
    failed = [n for n, ok, _ in base.results if not ok]
    print(f"\n{len(base.results) - len(failed)} passed, {len(failed)} failed: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
