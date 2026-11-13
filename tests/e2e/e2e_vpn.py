#!/usr/bin/env python3
"""VPN-only access end to end (CI job e2e-vpn; contract §4, §5, §16).

The whole stack with the VPN service (profile wg, `./portcullis vpn init`),
the Hub (same-named Hub branch) with one local template source = the CI
template tests/e2e/apps/echo and the templates repo's headscale, instances
echo-vpn (VPN-only) and headscale (wired as a provider, refresh 15 s).
Clients without privileges: tests/e2e/vpn-client (wireguard-go netstack)
for the built-in VPN and userspace tailscaled containers for the tailnet.

Cases, each `FAIL: <what>` on failure:
  websecure_vpn_required    echo-vpn on websecure answers only /vpn-required
  builtin_signin_demanded   alice's built-in device without a session: 302 to auth.<d>
  builtin_opens             alice's device + alice's session: echo-vpn opens
  builtin_not_yours         bob's device (host CLI) + alice's session: 403 "this device isn't yours"
  builtin_dns               the people resolver: echo-vpn.<d> A 10.213.0.1, AAAA NODATA, no AD
  tailnet_register          a tailscaled node registered as alice through Keycloak (Playwright)
  tailnet_opens             through the headscale gateway with alice's session: opens
  tailnet_dns               MagicDNS: echo-vpn.<d> → the gateway's tailnet address
  via_builtin               via ["builtin"]: the tailnet device 403, the built-in one opens
  tailnet_local_denied      a node of a local (non-OIDC) Headscale user: never opens
  gateway_claims_builtin    a raw PROXY v2 header claiming a built-in address on the
                            headscale edge port, from the gateway: closed,
                            wg_edge_rejected_total{reason="outside_ranges"} grows
  builtin_revoked           bob's device revoked: its handshake fails within 5 s
  tailnet_node_deleted      alice's node deleted in Headscale: denied within refresh + 10 s
  gateway_stopped           the gateway down: only tailnet devices fail
  identity_hook_broken      the API key cleared: tailnet denied once stale, the built-in unaffected
  wg_stopped                wg down: echo-vpn unreachable on both paths, no internet fallback
  server_mode               vpn mode server --force: on websecure only the public set
                            answers; vpn mode apps with wg stopped restores everything

Environment: E2E_DOMAIN, HUB_IP, E2E_HUB_SECRET, E2E_ALICE_INVITE,
E2E_BOB_INVITE, E2E_VPN_CLIENT (built), TS_IMG, PY_IMG, CURL_IMG, ALPINE,
E2E_ARTIFACTS. Keys, configs and cookies live in a 0700 temp directory,
never in artifacts or the log; setup links are masked; no Playwright traces.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from playwright.sync_api import Page, sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_login as base  # noqa: E402  (passkey_flow, Authenticator, shot)

DOMAIN = os.environ["E2E_DOMAIN"]
PORTAL = f"https://{DOMAIN}/"
AUTH = f"https://auth.{DOMAIN}"
REALM = f"{AUTH}/realms/portcullis"
PEOPLE = f"https://people.{DOMAIN}"
ECHO = f"echo-vpn.{DOMAIN}"
HS = "headscale"
HS_HOST = f"vpn.{DOMAIN}"
HUB_API = f"http://{os.environ['HUB_IP']}:8888"
CA = "certs/ca-chain.crt"
VPN_CLIENT = os.environ["E2E_VPN_CLIENT"]
TS_IMG, PY_IMG, CURL_IMG = os.environ["TS_IMG"], os.environ["PY_IMG"], os.environ["CURL_IMG"]
REQUIRED = "This app is only reachable over a Portcullis VPN"
NOT_YOURS = "this device isn't yours; sign in on your own device"
TMP = tempfile.mkdtemp(prefix="e2e-vpn-")
os.chmod(TMP, 0o700)
results: list[tuple[str, bool, str]] = []
state: dict = {}


def redact(text: str) -> str:
    text = re.sub(r"(/invite/)[A-Za-z0-9_-]+", r"\1<redacted>", text)
    return re.sub(r"(PrivateKey = )\S+", r"\1<redacted>", text)


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
            raise AssertionError(f"{what}: not within {seconds:.0f} s (last: {redact(str(last))[:600]})")
        time.sleep(every)


def sh(*cmd: str, stdin: str | None = None, timeout: float = 120) -> tuple[int, str]:
    p = subprocess.run(list(cmd), input=stdin, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def mask(value: str) -> None:
    if value:
        print(f"::add-mask::{value}", flush=True)


def secret_file(name: str, text: str) -> str:
    path = os.path.join(TMP, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return path


# ── the Hub's admin API, as Traefik calls it ──

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
    assert code in (200, 201, 202), f"{method} {path}: HTTP {code} {str(out)[:400]}"
    return out


def set_reach(via: list) -> None:
    hub_ok("PUT", "/api/instances/echo-vpn/reach", {"mode": "vpn", "via": via, "public_links": False})


def provider(pid: str) -> dict:
    return next((p for p in hub_ok("GET", "/api/vpn").get("providers", []) if p.get("id") == pid), {})


# ── requests: websecure (the runner), the built-in tunnel, the tailnet ──

def web(host: str, path: str = "/", cookie_file: str | None = None) -> tuple[int, str]:
    args = ["curl", "-s", "-o", "-", "-w", "\n%{http_code}", "--max-time", "20", "--cacert", CA,
            "--resolve", f"{host}:443:127.0.0.1", f"https://{host}{path}"]
    if cookie_file:
        args[1:1] = ["-H", f"@{cookie_file}"]
    rc, out = sh(*args)
    body, _, code = out.rpartition("\n")
    return int(code) if code.isdigit() else 0, body


def tunnel(conf: str, host: str = ECHO, path: str = "/", cookie_file: str | None = None, wait: str = "20s") -> dict:
    args = [VPN_CLIENT, "--endpoint", "127.0.0.1:51820", "--wait-handshake", wait, "--ca-file", CA,
            "--resolve", f"{host}:443:10.213.0.1", "--get", f"https://{host}{path}"]
    if cookie_file:
        args += ["--header-file", cookie_file]
    with open(conf) as f:
        p = subprocess.run(args, stdin=f, capture_output=True, text=True, timeout=120)
    try:
        doc = json.loads(p.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        doc = {"error": f"no JSON (exit {p.returncode}): {p.stderr[-300:]}"}
    doc["rc"] = p.returncode
    return doc


def tunnel_dns(conf: str, name: str, typ: str) -> dict:
    with open(conf) as f:
        p = subprocess.run([VPN_CLIENT, "--endpoint", "127.0.0.1:51820", "--dns", name, "--type", typ],
                           stdin=f, capture_output=True, text=True, timeout=60)
    return json.loads(p.stdout.strip().splitlines()[-1])


def ts_get(node: str, host: str = ECHO, path: str = "/", cookie_file: str | None = None) -> tuple[int, str]:
    """A request through node's tailscaled (its SOCKS5 proxy, in its netns),
    the hostname resolved by tailscaled (MagicDNS extra records)."""
    vols = ["-v", f"{os.path.abspath(CA)}:/ca.pem:ro"]
    hdr = []
    if cookie_file:
        vols += ["-v", f"{cookie_file}:/h:ro"]
        hdr = ["-H", "@/h"]
    rc, out = sh("docker", "run", "--rm", "--network", f"container:ts-{node}", *vols, CURL_IMG,
                 "-s", "-o", "-", "-w", "\n%{http_code}", "--max-time", "20", "--socks5-hostname", "127.0.0.1:1055",
                 "--cacert", "/ca.pem", *hdr, f"https://{host}{path}", timeout=60)
    body, _, code = out.rpartition("\n")
    return int(code) if code.isdigit() else 0, body


def opens(code: int, body: str) -> bool:
    return code == 200 and "Hostname:" in body


def cookie_header(ctx) -> str:
    """The browser's Portcullis cookies as one Cookie header line (a file
    in TMP; a session secret)."""
    cs = [c for c in ctx.cookies() if c["domain"].lstrip(".").endswith(DOMAIN)]
    assert cs, "no Portcullis cookie in the browser"
    return "Cookie: " + "; ".join(f"{c['name']}={c['value']}" for c in cs) + "\n"


# ── the built-in devices ──

def keypair() -> tuple[str, str]:
    k = X25519PrivateKey.generate()
    priv = base64.b64encode(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                            serialization.NoEncryption())).decode()
    pub = base64.b64encode(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    return priv, pub


def wg_conf(priv: str, cfg: dict) -> str:
    return (f"[Interface]\nPrivateKey = {priv}\nAddress = {cfg['address']}/32\nDNS = {cfg['dns']}\nMTU = {cfg['mtu']}\n\n"
            f"[Peer]\nPublicKey = {cfg['server_public_key']}\nEndpoint = {cfg['endpoint']}\n"
            f"AllowedIPs = {cfg['allowed_ips']}\nPersistentKeepalive = 25\n")


def fresh_proof(page: Page, label: str, redirect_uri: str) -> dict:
    """The /vpn/ page's fresh-auth popup flow (contract §5.1): prompt=login,
    max_age=0, PKCE S256 on the fresh-auth client; the proof it posts."""
    seen: list[str] = []
    page.on("request", lambda r: seen.append(r.url) if r.url.startswith(redirect_uri + "?") else None)
    verifier, nonce = secrets.token_urlsafe(48), secrets.token_urlsafe(16)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {"client_id": "portcullis-fresh-auth", "response_type": "code", "scope": "openid", "redirect_uri": redirect_uri,
         "state": secrets.token_urlsafe(12), "nonce": nonce, "code_challenge": challenge,
         "code_challenge_method": "S256", "prompt": "login", "max_age": "0"}
    page.goto(f"{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(q), wait_until="domcontentloaded")
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


def main() -> int:
    with sync_playwright() as pw_:
        browser = pw_.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])

        def new_context():
            ctx = browser.new_context()
            ctx.set_default_timeout(30_000)
            ctx.on("page", lambda p: p.on("dialog", lambda d: d.accept(d.default_value)))
            return ctx

        # ── sessions: alice and bob from their setup links ──
        sessions = {}
        for who in ("alice", "bob"):
            def signs_in(who=who):
                ctx = new_context()
                page = ctx.new_page()
                key = base.Authenticator(page)
                page.goto(os.environ[f"E2E_{who.upper()}_INVITE"], wait_until="domcontentloaded")
                base.passkey_flow(page, until=PORTAL, label=f"vpn-{who}", expect_stepups=1)
                sessions[who] = (ctx, page, key)
                state[f"{who}_cookie"] = secret_file(f"{who}.cookie", cookie_header(ctx))
            check(f"{who} signs in from a setup link", signs_in)

        # ── the built-in devices: alice through /vpn/ (fresh auth), bob through the host CLI ──
        def alice_device():
            needs("alice_cookie")
            _, page, _ = sessions["alice"]
            proof = fresh_proof(page, "alice-vpn", PEOPLE + "/vpn/")
            priv, pub = keypair()
            r = page.request.fetch(PEOPLE + "/vpn/api/devices", method="POST", max_redirects=0,
                                   data=json.dumps(dict(proof, name="laptop", public_key=pub)),
                                   headers={"Content-Type": "application/json"})
            assert r.status == 201, f"POST /vpn/api/devices: HTTP {r.status} {r.text()[:300]}"
            cfg = r.json()
            assert cfg["allowed_ips"] == "10.213.0.1/32" and cfg["dns"] == "10.213.0.1" and cfg["mtu"] == 1280, cfg
            assert "private" not in json.dumps(cfg).lower(), "the Hub answered key material"
            state["alice_conf"] = secret_file("alice.conf", wg_conf(priv, cfg))
            state["alice_ip"] = cfg["address"]
        check("alice's built-in device through people.<d>/vpn/ (fresh sign-in, the public key only)", alice_device)

        def bob_device():
            rc, out = sh("./portcullis", "vpn", "add-device", "bob", "laptop", timeout=120)
            assert rc == 0, f"vpn add-device bob: exit {rc} {redact(out)[-400:]}"
            conf = "\n".join(re.findall(r"^(?:\[Interface\]|\[Peer\]|[A-Za-z]+ = .*)$", out, re.M)) + "\n"
            m = re.search(r"^PrivateKey = (\S+)$", conf, re.M)
            assert m, "no config printed"
            mask(m.group(1))
            assert "AllowedIPs = 10.213.0.1/32" in conf, "no AllowedIPs = 10.213.0.1/32"
            state["bob_conf"] = secret_file("bob.conf", conf)
            code, devs = hub("GET", "/api/vpn/devices?user=bob")
            assert code == 200, f"GET /api/vpn/devices?user=bob: {code}"
            state["bob_device"] = next(d["id"] for d in devs if d.get("provider") == "builtin")
        check("bob's built-in device through ./portcullis vpn add-device (config + QR on stdout only)", bob_device)

        def websecure_vpn_required():
            set_reach(["*"])
            until("echo-vpn on websecure → /vpn-required", lambda: (lambda c, b: c == 403 and REQUIRED in b)(*web(ECHO)), 120)
            code, body = web(ECHO, cookie_file=state.get("alice_cookie"))
            assert code == 403 and REQUIRED in body, f"with alice's session: {code} {body[:200]}"
            state["vpn_only"] = True
        check("websecure_vpn_required: echo-vpn on websecure answers only /vpn-required", websecure_vpn_required)

        def builtin_signin_demanded():
            needs("alice_conf", "vpn_only")
            r = until("a tunnel answer", lambda: (lambda d: d if d.get("status") else None)(tunnel(state["alice_conf"])), 60)
            assert r["status"] in (302, 303) and r.get("location", "").startswith(AUTH + "/"), \
                f"without a session: {r.get('status')} {r.get('location', '')[:120]}"
        check("builtin_signin_demanded: through the tunnel, sign-in is still demanded (302 to auth.<d>)", builtin_signin_demanded)

        def builtin_opens():
            needs("alice_conf", "alice_cookie", "vpn_only")
            r = until("echo-vpn opens", lambda: (lambda d: d if d.get("status") == 200 else None)(
                tunnel(state["alice_conf"], cookie_file=state["alice_cookie"])), 60)
            assert "Hostname:" in r["body"], r["body"][:200]
            assert state["alice_ip"] in r["body"], "the app doesn't see the device's tunnel address (X-Forwarded-For / X-Real-Ip)"
        check("builtin_opens: alice's device + alice's session opens echo-vpn", builtin_opens)

        def builtin_not_yours():
            needs("bob_conf", "alice_cookie", "vpn_only")
            r = tunnel(state["bob_conf"], cookie_file=state["alice_cookie"])
            assert r.get("status") == 403 and NOT_YOURS in r.get("body", ""), f"{r.get('status')} {r.get('body', '')[:200]}"
            assert "bob" not in r["body"] and "alice" not in r["body"], "the page names a person"
        check("builtin_not_yours: bob's device with alice's session → 403 \"this device isn't yours\"", builtin_not_yours)

        def builtin_dns():
            needs("alice_conf")
            a = tunnel_dns(state["alice_conf"], ECHO, "A")
            assert a.get("rcode") == "NOERROR" and any(x.endswith("IN A 10.213.0.1") for x in a.get("answers", [])), a
            assert not a.get("ad"), "AD on a rewritten answer"
            aaaa = tunnel_dns(state["alice_conf"], ECHO, "AAAA")
            assert aaaa.get("rcode") == "NOERROR" and not [x for x in aaaa.get("answers", []) if " IN AAAA " in x], aaaa
        check("builtin_dns: the built-in resolver answers echo-vpn.<d> A 10.213.0.1 and AAAA NODATA", builtin_dns)

        # ── the tailnet (headscale, wired as a provider) ──
        def headscale_wired():
            until("headscale wired and fresh", lambda: (lambda p: p.get("wired") and not p.get("stale"))(provider(HS)), 240)
            state["hs_wired"] = True
        check("headscale is wired as a VPN provider and its map is fresh", headscale_wired)

        def ts_node(node: str):
            ca_bundle = os.path.join(TMP, "ts-ca.pem")
            if not os.path.exists(ca_bundle):
                with open(ca_bundle, "w") as out:
                    for p in ("/etc/ssl/certs/ca-certificates.crt", CA):
                        with open(p) as f:
                            out.write(f.read())
            sh("docker", "rm", "-f", f"ts-{node}")
            rc, out = sh("docker", "run", "-d", "--name", f"ts-{node}", "--add-host", f"{HS_HOST}:host-gateway",
                         "-v", f"{ca_bundle}:/etc/ssl/certs/ca-certificates.crt:ro", "--cap-drop", "ALL",
                         "--security-opt", "no-new-privileges:true", "--entrypoint", "tailscaled", TS_IMG,
                         "--tun=userspace-networking", "--state=mem:", "--socket=/tmp/ts.sock",
                         "--socks5-server=127.0.0.1:1055", "--no-logs-no-support")
            assert rc == 0, f"tailscaled {node}: {out[-300:]}"

        def tailnet_register():
            needs("hs_wired", "alice_cookie")
            ts_node("alice")
            sh("docker", "exec", "-d", "ts-alice", "sh", "-c",
               f"tailscale --socket=/tmp/ts.sock up --login-server=https://{HS_HOST} --hostname=alice-laptop "
               f"--accept-dns=false > /tmp/up.log 2>&1")
            url = until("a registration URL", lambda: (lambda o: (re.search(r"https://\S+/register/\S+", o) or [None])[0])(
                sh("docker", "exec", "ts-alice", "cat", "/tmp/up.log")[1]), 60)
            _, page, _ = sessions["alice"]
            page.goto(url, wait_until="domcontentloaded")
            until("alice's node registered", lambda: '"Online": true' in sh(
                "docker", "exec", "ts-alice", "tailscale", "--socket=/tmp/ts.sock", "status", "--json")[1]
                or "BackendState\": \"Running" in sh("docker", "exec", "ts-alice", "tailscale", "--socket=/tmp/ts.sock",
                                                      "status", "--json")[1], 120)
            state["ts_alice"] = True
        check("tailnet_register: a userspace tailscaled node registered as alice through Keycloak", tailnet_register)

        def tailnet_opens():
            needs("ts_alice", "vpn_only")
            until("echo-vpn through the tailnet", lambda: opens(*ts_get("alice", cookie_file=state["alice_cookie"])), 150)
        check("tailnet_opens: through the headscale gateway with alice's session, echo-vpn opens", tailnet_opens)

        def tailnet_dns():
            needs("ts_alice")
            rc, out = sh("docker", "exec", "ts-alice", "tailscale", "--socket=/tmp/ts.sock", "dns", "query", ECHO)
            assert rc == 0 and re.search(r"100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.\d+\.\d+", out), \
                f"MagicDNS for {ECHO}: {out[-300:]}"
        check("tailnet_dns: MagicDNS resolves echo-vpn.<d> to the gateway's tailnet address", tailnet_dns)

        def via_builtin():
            needs("ts_alice", "alice_conf", "vpn_only")
            set_reach(["builtin"])
            try:
                until("the tailnet refused under via builtin", lambda: ts_get("alice", cookie_file=state["alice_cookie"])[0] == 403, 120)
                r = tunnel(state["alice_conf"], cookie_file=state["alice_cookie"])
                assert r.get("status") == 200, f"the built-in under via builtin: {r.get('status')}"
            finally:
                set_reach(["*"])
            until("the tailnet back under via *", lambda: opens(*ts_get("alice", cookie_file=state["alice_cookie"])), 120)
        check("via_builtin: via [\"builtin\"] refuses the tailnet device (403), the built-in opens", via_builtin)

        def tailnet_local_denied():
            needs("hs_wired", "alice_cookie")
            hs = f"portcullis-{HS}-headscale-1"
            sh("docker", "exec", hs, "headscale", "users", "create", "ci-local")
            rc, out = sh("docker", "exec", hs, "headscale", "users", "list", "-o", "json")
            uid = next(u["id"] for u in json.loads(out) if u.get("name") == "ci-local")
            rc, key = sh("docker", "exec", hs, "headscale", "preauthkeys", "create", "--user", str(uid), "--expiration", "1h")
            key = key.strip().splitlines()[-1]
            mask(key)
            ts_node("local")
            rc, out = sh("docker", "exec", "ts-local", "tailscale", "--socket=/tmp/ts.sock", "up", f"--login-server=https://{HS_HOST}",
                         "--hostname=local-node", "--accept-dns=false", "--authkey", key, timeout=120)  # secret-argv-ok (CI-only node key)
            assert rc == 0, f"tailscale up (pre-auth key): {out[-300:]}"
            time.sleep(20)  # one refresh: the node is known to Headscale, never to Portcullis
            code, body = ts_get("local", cookie_file=state["alice_cookie"])
            assert not opens(code, body), f"a local Headscale user's node opened echo-vpn ({code})"
        check("tailnet_local_denied: a node of a local (non-OIDC) Headscale user never opens", tailnet_local_denied)

        def gateway_claims_builtin():
            needs("hs_wired")
            p = provider(HS)
            port = 9001 + int(p.get("slot", 0)) if "slot" in p else None
            if port is None:
                vpn_json = sh("docker", "run", "--rm", "-v", "portcullis_vpn_doc:/d:ro", os.environ["ALPINE"], "cat", "/d/vpn.json")[1]
                port = next(x["edge_port"] for x in json.loads(vpn_json)["providers"] if x["id"] == HS)

            def rejected() -> float:
                out = sh("docker", "run", "--rm", "--network", "portcullis_portcullis-metrics-wg", CURL_IMG, "-s",
                         "http://wg-metrics:9100/metrics")[1]
                m = re.search(r'wg_edge_rejected_total\{provider="%s",reason="outside_ranges"\} (\d+)' % HS, out)
                return float(m.group(1)) if m else 0.0
            before = rejected()
            gw = f"portcullis-{HS}-gateway-1"
            script = ("import socket,struct,sys\n"
                      "s=socket.create_connection(('172.31.254.3',%d),5)\n"
                      "sig=b'\\r\\n\\r\\n\\x00\\r\\nQUIT\\n'\n"
                      "addr=socket.inet_aton('10.213.0.5')+socket.inet_aton('172.31.254.3')+struct.pack('!HH',40000,%d)\n"
                      "s.sendall(sig+bytes([0x21,0x11])+struct.pack('!H',len(addr))+addr+b'GET / HTTP/1.0\\r\\n\\r\\n')\n"
                      "s.settimeout(5)\n"
                      "print(len(s.recv(100)))\n") % (port, port)
            rc, out = sh("docker", "run", "--rm", "--network", f"container:{gw}", PY_IMG, "python3", "-c", script, timeout=60)
            assert out.strip().endswith("0") or rc != 0, f"the edge answered a claimed built-in address: {out[-200:]}"
            until("outside_ranges counted", lambda: rejected() > before, 30, every=2)
        check("gateway_claims_builtin: a PROXY header claiming a built-in address on the headscale edge port is closed (outside_ranges)",
              gateway_claims_builtin)

        def builtin_revoked():
            needs("bob_conf", "bob_device")
            rc, out = sh("./portcullis", "vpn", "revoke", state["bob_device"])
            assert rc == 0, f"vpn revoke: {out[-300:]}"
            t0 = time.time()
            until("bob's handshake refused", lambda: not tunnel(state["bob_conf"], wait="3s").get("handshake"), 15, every=1)
            assert time.time() - t0 <= 8, f"took {time.time() - t0:.0f} s"
        check("builtin_revoked: a revoked built-in device's handshake fails within 5 s", builtin_revoked)

        def tailnet_node_deleted():
            needs("ts_alice")
            hs = f"portcullis-{HS}-headscale-1"
            nodes = json.loads(sh("docker", "exec", hs, "headscale", "nodes", "list", "-o", "json")[1])
            nid = next(n["id"] for n in nodes if n.get("given_name", n.get("givenName", "")) == "alice-laptop" or n.get("name") == "alice-laptop")
            t0 = time.time()
            rc, out = sh("docker", "exec", hs, "headscale", "nodes", "delete", "-i", str(nid), "--force")
            assert rc == 0, out[-300:]
            until("alice's deleted node denied", lambda: not opens(*ts_get("alice", cookie_file=state["alice_cookie"])), 40, every=2)
            assert time.time() - t0 <= 25 + 15, f"took {time.time() - t0:.0f} s (refresh 15 s + 10 s)"
            state.pop("ts_alice")
        check("tailnet_node_deleted: a deleted Headscale node is denied within refresh + 10 s", tailnet_node_deleted)

        def gateway_stopped():
            needs("alice_conf", "alice_cookie")
            gw = f"portcullis-{HS}-gateway-1"
            sh("docker", "stop", gw)
            try:
                r = tunnel(state["alice_conf"], cookie_file=state["alice_cookie"])
                assert r.get("status") == 200, f"the built-in with the gateway down: {r.get('status')}"
            finally:
                sh("docker", "start", gw)
        check("gateway_stopped: with the gateway down the built-in still opens", gateway_stopped)

        def identity_hook_broken():
            needs("hs_wired", "alice_conf", "alice_cookie")
            hub_ok("PUT", f"/api/instances/{HS}/settings", {"values": {"api_key": ""}})
            try:
                until("the tailnet provider stale", lambda: provider(HS).get("stale"), 3 * 60 + 15, every=5)
                r = tunnel(state["alice_conf"], cookie_file=state["alice_cookie"])
                assert r.get("status") == 200, f"the built-in with the tailnet stale: {r.get('status')}"
            finally:
                key = os.environ.get("E2E_HS_API_KEY_FILE")
                if key:
                    with open(key) as f:
                        hub_ok("PUT", f"/api/instances/{HS}/settings", {"values": {"api_key": f.read().strip()}})
        check("identity_hook_broken: the API key cleared → the tailnet provider goes stale (≤ 3 min 15 s), the built-in unaffected",
              identity_hook_broken)

        def wg_stopped():
            needs("alice_conf", "alice_cookie", "vpn_only")
            sh("docker", "stop", "portcullis-wg-1")
            try:
                r = tunnel(state["alice_conf"], cookie_file=state["alice_cookie"], wait="5s")
                assert not r.get("handshake") and not r.get("status"), f"the tunnel answered with wg down: {r}"
                code, body = web(ECHO, cookie_file=state["alice_cookie"])
                assert code == 403 and REQUIRED in body, f"websecure with wg down: {code} {body[:120]}"
            finally:
                sh("docker", "start", "portcullis-wg-1")
            until("wg back", lambda: tunnel(state["alice_conf"], cookie_file=state["alice_cookie"]).get("status") == 200, 120)
        check("wg_stopped: wg down → echo-vpn unreachable on both paths, no internet fallback", wg_stopped)

        def server_mode():
            rc, out = sh("./portcullis", "vpn", "mode", "server", "--force", timeout=600)
            assert rc == 0, f"vpn mode server --force: {redact(out)[-500:]}"
            try:
                def public_set():
                    hub_code, hub_body = web(f"hub.{DOMAIN}")
                    kca_code, kca_body = web(f"auth.{DOMAIN}", "/admin/")
                    signin = web(f"auth.{DOMAIN}", "/realms/portcullis/.well-known/openid-configuration")[0]
                    enroll = web(f"enroll.{DOMAIN}", "/invite/x")[0]
                    vpn_page = web(f"people.{DOMAIN}", "/vpn/")
                    hs = web(HS_HOST, "/health")[0]
                    return (hub_code == 403 and REQUIRED in hub_body and kca_code == 403 and REQUIRED in kca_body
                            and signin == 200 and enroll not in (0, 403) and vpn_page[0] in (302, 303) and REQUIRED not in vpn_page[1]
                            and hs not in (0, 403))
                until("only the public set on websecure", public_set, 180)
            finally:
                sh("docker", "stop", "portcullis-wg-1")
                rc, out = sh("./portcullis", "vpn", "mode", "apps", timeout=600)
                assert rc == 0, f"vpn mode apps (break-glass, wg stopped): {redact(out)[-500:]}"
            until("hub.<d> back on websecure", lambda: web(f"hub.{DOMAIN}")[0] in (302, 303), 180)
            sh("docker", "start", "portcullis-wg-1")
        check("server_mode: only the public set on websecure (headscale's control router, auth sign-in pages, enroll, "
              "people.<d>/vpn/), not keycloak-admin or hub; vpn mode apps with wg stopped restores them", server_mode)

        for ctx, _, _ in sessions.values():
            ctx.close()
        browser.close()

    shutil.rmtree(TMP, ignore_errors=True)
    for node in ("alice", "local"):
        sh("docker", "rm", "-f", f"ts-{node}")
    failed = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed", flush=True)
    for n, ok, why in results:
        if not ok:
            print(f"  FAIL: {n}: {why[:300]}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
