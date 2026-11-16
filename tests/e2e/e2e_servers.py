#!/usr/bin/env python3
"""Multiple servers end to end (contract §17; ci.yml jobs e2e-servers and
e2e-servers-podman). The primary runs the whole stack with `link init`; the
workers are docker:dind containers (or rootless Podman as the runner user
`worker`), joined with `./portcullis worker join` and the code on stdin.

Cases, in this order (one function each):

  join_ok                         add w1 (fresh sign-in), the code on the worker's stdin, ready
  join_code_reused_refused        the same code on another worker never enrols
  join_code_expired_refused       a code past its 15 min (the Hub's clock, a CI-only hook) is refused
  echo_on_worker_signed_in        an instance placed on w1 answers through the primary, same tier as one on the primary
  echo_on_worker_denied_without_sign_in
  no_portcullis_cookie_reaches_app      the app sees no Portcullis cookie
  parent_domain_set_cookie_stripped     a Set-Cookie for the parent domain comes back host-only
  move_worker_primary_worker_keeps_data the volume's marker survives w1 → primary → w1
  wg_stopped_fails_closed         wg down: the app is unreachable, its containers still run on w1
  wg_back_routes_again
  rogue_worker                    .github/ci/e2e-servers-rogue.sh (dind job: two workers)
  revoke_drops_handshake_and_rotates    the peer gone, the instance's client secret new
  revoke_cuts_websocket           a long-lived stream through the relay ends at the revocation
  socket_rule_both_stacks         .github/ci/e2e-servers-asserts.sh

The join code is a secret: it is masked, written only to a 0700 temp dir
and piped to the worker; never an argument, an artifact or a log line.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
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

DOMAIN = os.environ["E2E_DOMAIN"]
KIND = os.environ.get("E2E_WORKER_KIND", "dind")  # dind | podman
HUB_API = f"http://{os.environ['HUB_IP']}:8888"
AUTH = f"https://auth.{DOMAIN}"
HUB = f"https://hub.{DOMAIN}"
PORTAL = f"https://{DOMAIN}/"
SECRET = open(".env").read().split("HUB_PROXY_SECRET=", 1)[1].split("\n", 1)[0]
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
        raise AssertionError(f"{' '.join(args[:4])}: exit {p.returncode}: {p.stdout[-800:]} {p.stderr[-800:]}")
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
    assert code == 201 and isinstance(ans, dict) and ans.get("code", "").startswith("pcj1."), f"add {sid}: {code} {str(ans)[:200]}"
    print(f"::add-mask::{ans['code']}", flush=True)
    path = os.path.join(TMP, f"{sid}.code")
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
        f.write(ans["code"])
    ans["code"] = None  # never kept in memory past the file
    ans["code_file"] = path
    return ans


def join(kind: str, name: str, code_file: str, wait: int = 240, check=True) -> subprocess.CompletedProcess:
    with open(code_file) as f:
        p = subprocess.run(["bash", WORKER_SH, kind, name], stdin=f, capture_output=True, text=True, timeout=wait + 600,
                           env=dict(os.environ, WORKER_JOIN_WAIT=str(wait)))
    out = p.stdout + p.stderr
    assert "pcj1." not in out, "the join code reached the worker script's output"
    if check and p.returncode != 0:
        raise AssertionError(f"worker {name}: exit {p.returncode}: {out[-1500:]}")
    return p


def wexec(name: str, *cmd, check=True) -> subprocess.CompletedProcess:
    return sh("bash", WORKER_SH, "exec", name, *cmd, check=check)


def server_state(sid: str):
    code, s = hub("GET", f"/api/servers/{sid}")
    return s.get("state") if code == 200 and isinstance(s, dict) else code


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
        data=json.dumps({"username": "admin", "password": os.environ["LLDAP_ADMIN_PASSWORD"]}).encode()), timeout=20).read())["token"]

    def gql(q: str) -> dict:
        return json.loads(urllib.request.urlopen(urllib.request.Request(
            "http://127.0.0.1:17170/api/graphql", method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok}"},
            data=json.dumps({"query": q}).encode()), timeout=20).read())
    gid = [g["id"] for g in gql("{ groups { id displayName } }")["data"]["groups"] if g["displayName"] == group][0]
    r = gql(f'mutation {{ addUserToGroup(userId: "{user}", groupId: {gid}) {{ ok }} }}')
    assert not r.get("errors"), r


def echo(page: Page, iid: str):
    """alice's GET of the instance's CGI through the primary: (status, body, set-cookies)."""
    r = page.request.get(f"https://{iid}.{DOMAIN}/cgi-bin/echo", max_redirects=0)
    cookies = [h["value"] for h in r.headers_array if h["name"].lower() == "set-cookie"]
    return r.status, r.text(), cookies


def reach(page: Page, iid: str) -> bool:
    try:
        st, body, _ = echo(page, iid)
        return st == 200 and f"HOST={iid}.{DOMAIN}" in body
    except Exception:  # noqa: BLE001
        return False


# ── the cases ──

def join_ok():
    ans = add_server("w1")
    state["w1_op"] = ans
    join(KIND, "w1", ans["code_file"])
    rec = e2e_ops.wait(get, {"op_id": ans["op_id"], "poll": ans["poll"], "op": "server_enrol"}, 300)
    assert rec.get("ok"), f"server_enrol: {e2e_ops.describe(rec)}"
    assert "pcj1." not in json.dumps(rec), "the code is in the op record"
    wait_for("w1 ready", lambda: server_state("w1") == "ready", 120)
    assert any(p["id"] == "w1" and p.get("handshake") for p in link_peers()), f"no w1 handshake: {link_peers()}"
    assert "pcj1." not in sh("docker", "compose", "logs", "hub", "wg").stdout, "the code is in the Hub's or wg's log"
    state["w1"] = True


def join_code_reused_refused():
    assert state.get("w1"), "needs join_ok"
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


def echo_on_worker_signed_in():
    assert state.get("w1"), "needs join_ok"
    for iid, srv in (("se0", ""), ("se1", "w1")):
        run_op("POST", "/api/instances", {"template": "servers-echo", "id": iid, "label": iid.upper(),
                                          "hosts": {"echo": f"{iid}.{DOMAIN}"}, "server": srv})
        lldap_member("alice", f"users_{iid}")
        run_op("POST", "/api/templates/enable", {"id": iid}, timeout=900)
    page = state["alice_page"]
    wait_for("se1 through the relay", lambda: reach(page, "se1"), 180)
    assert reach(page, "se0"), "se0 (on the primary) isn't reachable"
    a, b = get("/api/instances/se0/signin"), get("/api/instances/se1/signin")
    assert {k: a.get(k) for k in ("template", "tier")} == {k: b.get(k) for k in ("template", "tier")}, f"tiers differ: {a} / {b}"
    ps = wexec("w1", "docker", "ps", "--filter", "label=com.docker.compose.project=portcullis-se1", "--format", "{{.Names}}").stdout
    assert ps.strip(), "se1 has no container on w1"
    assert not sh("docker", "ps", "-q", "--filter", "label=com.docker.compose.service=web",
                  "--filter", "label=com.docker.compose.project=portcullis-se1").stdout.strip(), "se1's app runs on the primary"
    state["se1"] = True


def echo_on_worker_denied_without_sign_in():
    assert state.get("se1"), "needs echo_on_worker_signed_in"
    ctx = state["browser"].new_context(ignore_https_errors=True)
    try:
        r = ctx.request.get(f"https://se1.{DOMAIN}/cgi-bin/echo", max_redirects=0)
        assert r.status in (302, 303, 401, 403) and "HOST=" not in r.text(), f"unsigned request: {r.status} {r.text()[:200]}"
    finally:
        ctx.close()


def no_portcullis_cookie_reaches_app():
    assert state.get("se1"), "needs echo_on_worker_signed_in"
    st, body, _ = echo(state["alice_page"], "se1")
    line = [ln for ln in body.splitlines() if ln.startswith("COOKIE=")][0]
    for bad in ("_oauth2_proxy", "__Host-portcullis_ext", "_oauth2_proxy_csrf"):
        assert bad not in line, f"the app on w1 saw {bad}: {line[:200]}"


def parent_domain_set_cookie_stripped():
    assert state.get("se1"), "needs echo_on_worker_signed_in"
    _, _, cookies = echo(state["alice_page"], "se1")
    wide = [c for c in cookies if c.startswith("wide=")]
    assert wide and all("domain=" not in c.lower() for c in wide), f"Set-Cookie for the parent domain: {cookies}"
    assert any(c.startswith("own=") for c in cookies), f"the host-only cookie is gone: {cookies}"


def marker(where: str, write: str | None = None) -> str:
    vol = "portcullis-se1_data"
    cmd = f"printf %s {write} > /d/marker && chmod 644 /d/marker" if write else "cat /d/marker"
    if where == "primary":
        return sh("docker", "run", "--rm", "-v", f"{vol}:/d", os.environ["ALPINE"], "sh", "-c", cmd).stdout
    return wexec("w1", "docker", "run", "--rm", "-v", f"{vol}:/d", os.environ["ALPINE"], "sh", "-c", cmd).stdout


def move_worker_primary_worker_keeps_data():
    assert state.get("se1"), "needs echo_on_worker_signed_in"
    mark = secrets.token_hex(8)
    marker("w1", mark)
    page = state["alice_page"]
    for to, where in (("", "primary"), ("w1", "w1")):
        run_op("POST", "/api/instances/se1/move", {"server": to}, timeout=900)
        assert marker(where).strip() == mark, f"the marker after the move to {where or 'primary'}"
        wait_for(f"se1 on {where}", lambda: f"MARKER={mark}" in echo(page, "se1")[1], 180)


def wg_stopped_fails_closed():
    assert state.get("se1"), "needs echo_on_worker_signed_in"
    sh("docker", "compose", "stop", "wg")
    page = state["alice_page"]
    wait_for("se1 unreachable with wg down", lambda: not reach(page, "se1"), 60)
    ps = wexec("w1", "docker", "ps", "--filter", "label=com.docker.compose.project=portcullis-se1", "--format", "{{.Status}}").stdout
    assert "Up" in ps, f"se1's containers stopped on w1: {ps}"


def wg_back_routes_again():
    sh("docker", "compose", "start", "wg")
    wait_for("se1 routed again", lambda: reach(state["alice_page"], "se1"), 240)


def rogue_worker():
    assert state.get("w1"), "needs join_ok"
    if KIND == "dind":
        ans = add_server("w3")
        join("dind", "w3", ans["code_file"])
        wait_for("w3 ready", lambda: server_state("w3") == "ready", 120)
    sh("bash", ".github/ci/e2e-servers-rogue.sh", KIND, timeout=1800)


def keycloak_secret(client_like: str) -> str:
    tok = json.loads(urllib.request.urlopen(urllib.request.Request(
        "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token", method="POST",
        data=urllib.parse.urlencode({"client_id": "admin-cli", "grant_type": "password", "username": os.environ["KEYCLOAK_ADMIN"],
                                     "password": os.environ["KEYCLOAK_ADMIN_PASSWORD"]}).encode()), timeout=20).read())["access_token"]

    def kc(path: str):
        return json.loads(urllib.request.urlopen(urllib.request.Request(
            "http://127.0.0.1:8080/admin/realms/portcullis" + path, headers={"Authorization": f"Bearer {tok}"}), timeout=20).read())
    cl = [c for c in kc("/clients?max=500") if client_like in c.get("clientId", "")]
    assert cl, f"no Keycloak client like {client_like}"
    return kc(f"/clients/{cl[0]['id']}/client-secret")["value"]


def revoke_drops_handshake_and_rotates():
    assert state.get("se1"), "needs echo_on_worker_signed_in"
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
    t0, closed = state.get("stream", (None, None))
    assert t0, "needs revoke_drops_handshake_and_rotates"
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
                base.setup_link_signin(page, os.environ[f"E2E_{who.upper()}_INVITE"], who=who,
                                       mint=lambda: base.mint_setup_link(who, "hub" if who == "admin" else "portal"),
                                       until=until, label=f"servers-{who}", expect_stepups=1)
                state[f"{who}_ctx"], state[f"{who}_page"], state[f"{who}_key"] = ctx, page, key
            base.check(f"{who} signs in from a setup link", signs_in)
        for fn in (join_ok, join_code_reused_refused, join_code_expired_refused,
                   echo_on_worker_signed_in, echo_on_worker_denied_without_sign_in,
                   no_portcullis_cookie_reaches_app, parent_domain_set_cookie_stripped,
                   move_worker_primary_worker_keeps_data, wg_stopped_fails_closed, wg_back_routes_again,
                   rogue_worker, revoke_drops_handshake_and_rotates, revoke_cuts_websocket, socket_rule_both_stacks):
            base.check(fn.__name__, fn)
        browser.close()
    failed = [n for n, ok, _ in base.results if not ok]
    print(f"\n{len(base.results) - len(failed)} passed, {len(failed)} failed: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
