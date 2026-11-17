"""End-to-end SSH access (contract §18; ci.yml job e2e-ssh).

The core stack with the Hub under test, two SSH servers on portcullis-proxy
(tests/e2e/sshd: web-1 enrolled as a managed host with `--service none`,
web-2 set up by `host trust`), the Portcullis CLI from the Hub image on the
runner (`portcullis login --no-browser`: Playwright opens the printed
address with a virtual security key) and the runner's own ssh-agent / ssh.

Cases (each a check(name, fn)):
  setup                          SSH on, host group web, web-1 enrolled, web-2 trusted,
                                 grants ssh_web → {username}, ssh_deploy → deploy,
                                 ssh_admins → all with full sudo (privileged: the group
                                 name typed again and a fresh sign-in)
  alice_reaches_both_no_sudo     alice's certificate opens both hosts, no sudo
  alice_sudo_after_join          alice joins ssh_admins, logs in again: sudo on web-1
                                 within one long-poll
  bob_deploy_keyid               bob reaches deploy@web-1; sshd logs ID pc:bob:web:
  root_refused                   root@ with alice's certificate is refused (bare
                                 principals open nothing, review 2)
  replayed_code_refused          a sign-in code works once at POST ssh/certificates
  wrong_key_proof_refused        a key proof made by another key is refused (403)
  cli_client_shape               Keycloak's portcullis-cli: public, PKCE S256, the three
                                 loopback redirects only (127.0.0.1:40000 and
                                 localhost:38917 refused), no web origins
  leave_locks_and_revokes        alice leaves: web-1 refuses her within seconds, web-2
                                 after one revoked-keys pull
  hub_stopped_valid_certs_and_breakglass_work
                                 the Hub stopped: bob's certificate still works, the
                                 break-glass account's own key works, and
                                 ./portcullis ssh breakglass-cert signs one from Vault
  no_secret_anywhere             no sign-in code, PKCE verifier, enrolment code or private
                                 key in the logs, the Hub's audit, issued.jsonl or the
                                 CLI's output
  finally                        hosts removed, SSH off

Environment: E2E_DOMAIN, HUB_IP, E2E_HUB_SECRET, E2E_FIXTURE, ALPINE,
E2E_PORTCULLIS (the CLI binary), E2E_WEB_1_IP / E2E_WEB_2_IP.
Run: python3 tests/e2e/e2e_ssh.py (needs the live stack of the job).
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
import urllib.parse
import urllib.request

from playwright.sync_api import Page, sync_playwright

import e2e_login as base
import e2e_signin as S
import scenarios  # noqa: E402

DOMAIN = os.environ["E2E_DOMAIN"]
PC = os.environ["E2E_PORTCULLIS"]
PEOPLE = f"https://people.{DOMAIN}"
# The CI CA chain (root + intermediates): Traefik serves the Vault
# wildcard leaf alone, so the root by itself can't verify it.
CA = os.path.abspath("certs/ca-chain.crt")
WEB1, WEB2 = f"web-1.{DOMAIN}", f"web-2.{DOMAIN}"
HOME = os.path.expanduser("~")
results: list[tuple[str, bool, str]] = []
state: dict = {"secrets": [], "cli_out": []}


def check(name: str, fn) -> None:
    if scenarios.skip(name):
        return
    try:
        fn()
        results.append((name, True, ""))
        print(f"PASS: {name}", flush=True)
    except Exception as e:  # noqa: BLE001
        results.append((name, False, S.redact(f"{type(e).__name__}: {e}")))
        print(f"FAIL: {name}: {S.redact(str(e))}", flush=True)
        traceback.print_exc()


def secret(v: str, kind: str = "code") -> str:
    """A value no log, audit or output may hold (masked in the job log).
    kind: code (an OAuth authorization code), verifier, nonce, enrol."""
    print(f"::add-mask::{v}", flush=True)
    state["secrets"].append((kind, v))
    return v


def api(method: str, path: str, body=None):
    code, raw = S.hub_as("root", method, path, body)
    try:
        return code, json.loads(raw) if raw else None
    except ValueError:
        return code, raw


def api_ok(method: str, path: str, body=None):
    code, out = api(method, path, body)
    assert code in (200, 201, 204), f"{method} {path}: HTTP {code} {str(out)[:400]}"
    return out


def until(what: str, fn, seconds: float, every: float = 2):
    deadline = time.time() + seconds
    last = None
    while time.time() < deadline:
        try:
            v = fn()
            if v:
                return v
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(every)
    raise AssertionError(f"{what}: not within {seconds:.0f} s (last: {last})")


def pkce() -> tuple[str, str]:
    v = secret(secrets.token_urlsafe(48), "verifier")
    return v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()


def code_via(page: Page, authorize: str, client: str, redirect_uri: str, label: str, fresh: bool = True) -> dict:
    """A code from Keycloak for client at redirect_uri, the virtual key
    answering (prompt=login, max_age=0 for a fresh sign-in)."""
    seen: list[str] = []
    page.on("request", lambda r: seen.append(r.url) if r.url.startswith(redirect_uri + "?") else None)
    verifier, challenge = pkce()
    nonce = secret(secrets.token_urlsafe(16), "nonce")
    q = {"client_id": client, "response_type": "code", "scope": "openid", "redirect_uri": redirect_uri,
         "state": secrets.token_urlsafe(12), "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
    if fresh:
        q.update(prompt="login", max_age="0")
    try:
        page.goto(authorize + "?" + urllib.parse.urlencode(q), wait_until="domcontentloaded")
    except Exception:  # noqa: BLE001  (a loopback redirect nobody answers)
        pass

    def got():
        for u in seen:
            c = urllib.parse.parse_qs(urllib.parse.urlsplit(u).query).get("code")
            if c:
                return c[0]
        return None
    out = S.drive_kc(page, lambda: got() is not None, label)
    assert out == "done", f"{label}: {out}"
    return {"code": secret(got()), "code_verifier": verifier, "nonce": nonce}


def fresh_proof(page: Page, label: str) -> dict:
    """The Hub page's fresh sign-in (freshauth.js) for root."""
    fa = api_ok("GET", "/api/ssh/settings")["fresh_auth"]
    return code_via(page, fa["authorize_url"], fa["client_id"], fa["redirect_uri"], label)


def run(args: list, *, input_: str | None = None, timeout: float = 120, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=input_, capture_output=True, text=True, timeout=timeout, env=env)


def dexec(host: str, *cmd: str, input_: str | None = None, timeout: float = 120) -> subprocess.CompletedProcess:
    return run(["docker", "exec", "-i", f"e2e-{host}", *cmd], input_=input_, timeout=timeout)


def cli_env() -> dict:
    return dict(os.environ, SSH_AUTH_SOCK=state["agent"])


def cli_login(page: Page, label: str) -> str:
    """portcullis login --no-browser: the printed address opened in page
    (the person's virtual key), the CLI's loopback gets the code."""
    p = subprocess.Popen([PC, "login", DOMAIN, "--no-browser", "--ca-file", CA], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=cli_env())
    url = ""
    err_lines = []
    deadline = time.time() + 60
    while time.time() < deadline and not url:
        line = p.stderr.readline()
        if not line:
            break
        err_lines.append(line)
        m = re.search(r"(https://auth\.\S+)", line)
        if m:
            url = m.group(1)
    assert url, f"{label}: no sign-in address printed: {''.join(err_lines)[-400:]}"
    seen: list[str] = []
    page.on("request", lambda r: seen.append(r.url) if r.url.startswith("http://127.0.0.1:3891") else None)
    try:
        page.goto(url, wait_until="domcontentloaded")
    except Exception:  # noqa: BLE001
        pass
    S.drive_kc(page, lambda: bool(seen), label)
    for u in seen:
        for c in urllib.parse.parse_qs(urllib.parse.urlsplit(u).query).get("code", []):
            secret(c)
    out, err = p.communicate(timeout=120)
    text = "".join(err_lines) + err + out
    state["cli_out"].append(text)
    assert p.returncode == 0, f"{label}: portcullis login exit {p.returncode}: {text[-600:]}"
    return text


def ssh(user: str, host: str, cmd: str = "id -un", timeout: float = 30) -> subprocess.CompletedProcess:
    return run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
                f"{user}@{host}", cmd], timeout=timeout, env=cli_env())


def logout() -> None:
    run([PC, "logout", "--domain", DOMAIN], env=cli_env())


def members(group: str, user: str, add: bool) -> None:
    if add:
        api_ok("POST", f"/api/directory/groups/{group}/members", {"username": user})
    else:
        api_ok("DELETE", f"/api/directory/groups/{group}/members/{user}")


def signed_cert_request(page: Page, key: str, proof_key: str | None = None) -> dict:
    """A POST ssh/certificates body as the CLI makes it: a code for
    portcullis-cli at the first loopback redirect and an SSHSIG key proof
    (ssh-keygen -Y sign) by key (or proof_key)."""
    cfg = json.loads(urllib.request.urlopen(urllib.request.Request(PEOPLE + "/api/cli/v1/config", headers=cli_headers()),
                                            context=ctx()).read())
    redirect = "http://127.0.0.1:38917/callback"
    p = code_via(page, cfg["authorize_url"], cfg["client_id"], redirect, "cli-code")
    pub = open(key + ".pub").read().split()
    pub_line = f"{pub[0]} {pub[1]}"
    msg = json.dumps({"domain": DOMAIN, "nonce": p["nonce"], "code_sha256": hashlib.sha256(p["code"].encode()).hexdigest(),
                      "public_key": pub_line}, separators=(",", ":"))
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(msg)
    sig = run(["ssh-keygen", "-Y", "sign", "-n", "portcullis-ssh-certificate@v1", "-f", proof_key or key, "-O", "hashalg=sha512", f.name])
    assert sig.returncode == 0, sig.stderr
    proof = open(f.name + ".sig").read()
    os.unlink(f.name)
    os.unlink(f.name + ".sig")
    return {"code": p["code"], "code_verifier": p["code_verifier"], "nonce": p["nonce"], "redirect_uri": redirect,
            "public_key": pub_line, "key_proof": proof, "host_groups": []}


def ctx():
    import ssl
    return ssl.create_default_context(cafile=CA)


def cli_headers() -> dict:
    ver = run([PC, "version"]).stdout.split()
    v = ver[1] if len(ver) > 1 else "dev"
    return {"Portcullis-CLI": f"{v}; api=1", "Content-Type": "application/json"}


def post_certs(body: dict) -> tuple[int, str]:
    req = urllib.request.Request(PEOPLE + "/api/cli/v1/ssh/certificates", data=json.dumps(body).encode(),
                                 method="POST", headers=cli_headers())
    try:
        with urllib.request.urlopen(req, context=ctx(), timeout=60) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="e2e-ssh-")
    os.chmod(tmp, 0o700)
    agent = run(["ssh-agent", "-a", os.path.join(tmp, "agent.sock")])
    assert agent.returncode == 0, agent.stderr
    m = re.search(r"SSH_AGENT_PID=(\d+)", agent.stdout)
    assert m, agent.stdout
    state["agent_pid"] = int(m.group(1))
    state["agent"] = os.path.join(tmp, "agent.sock")
    os.makedirs(os.path.join(HOME, ".ssh"), mode=0o700, exist_ok=True)
    with open(os.path.join(HOME, ".ssh", "config"), "w") as f:
        f.write("Include ~/.ssh/portcullis/*/config\n")
    # The break-glass account's own key (its authorized_keys, never Portcullis's).
    bg = os.path.join(tmp, "breakglass")
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", bg])
    for h in ("web-1", "web-2"):
        r = dexec(h, "sh", "-c", "cat > /home/breakglass/.ssh/authorized_keys && chown breakglass: /home/breakglass/.ssh/authorized_keys && chmod 600 /home/breakglass/.ssh/authorized_keys",
                  input_=open(bg + ".pub").read())
        assert r.returncode == 0, r.stderr

    with sync_playwright() as pw_:
        browser = pw_.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])
        pages: dict = {}

        def person(user: str) -> Page:
            if user in pages:
                return pages[user]
            c = browser.new_context()
            c.set_default_timeout(30_000)
            page = c.new_page()
            page.__dict__["_key"] = base.Authenticator(page)
            link = S.invite(user, "portal")
            base.setup_link_signin(page, link, who=user, mint=lambda: S.invite(user, "portal"), until=f"https://{DOMAIN}/",
                                   label=user, expect_stepups=1)
            pages[user] = page
            return page

        def setup():
            root = person("root")
            p = fresh_proof(root, "ssh-on")
            api_ok("PUT", "/api/ssh/settings", dict(enabled=True, default_ttl_hours=8, **p))
            # The CA keys come with the next compile (enroll's GET /internal/ssh-ca).
            st = until("the CA keys", lambda: (lambda v: v if v["user_cas"] and v["host_cas"] else None)(api_ok("GET", "/api/ssh/settings")), 90)
            assert st["enabled"], st
            assert not st["problems"], st["problems"]
            state["user_ca"] = st["user_cas"][0]
            api_ok("POST", "/api/ssh/hostgroups", {"id": "web", "label": "Web", "patterns": [WEB2]})
            p = fresh_proof(root, "host-web-1")
            out = api_ok("POST", "/api/ssh/hosts", dict(id="web-1", names=[WEB1], host_groups=["web"], managed=True, **p))
            code = secret(out["code"], "enrol")
            r = dexec("web-1", "portcullis", "host", "enroll", "--service", "none", "--ca-file", "/ca.pem", input_=code + "\n")
            assert r.returncode == 0, f"enroll: {r.stdout[-300:]} {r.stderr[-600:]}"
            run(["docker", "exec", "-d", "e2e-web-1", "portcullis", "host", "sync"])
            api_ok("POST", "/api/ssh/grants", {"group": "ssh_web", "host_group": "web", "accounts": ["{username}"], "sudo": "none"})
            api_ok("POST", "/api/ssh/grants", {"group": "ssh_deploy", "host_group": "web", "accounts": ["deploy"], "sudo": "none"})
            # Privileged: without the typed name refused, with it and a fresh sign-in saved.
            code_, _ = api("POST", "/api/ssh/grants", {"group": "ssh_admins", "host_group": "all", "accounts": ["{username}"], "sudo": "full"})
            assert code_ == 400, code_
            p = fresh_proof(root, "grant-admins")
            api_ok("POST", "/api/ssh/grants", dict(group="ssh_admins", host_group="all", accounts=["{username}"], sudo="full",
                                                   confirm="ssh_admins", **p))
            r = dexec("web-2", "portcullis", "host", "trust", "--domain", DOMAIN, "--host-group", "web", "--ca-key", state["user_ca"],
                      "--person", "alice", "--account", "deploy", "--revoked-keys", "--service-none", "--ca-file", "/ca.pem")
            assert r.returncode == 0, f"trust: {r.stdout[-300:]} {r.stderr[-600:]}"
            hosts = until("web-1 synced", lambda: [h for h in api_ok("GET", "/api/ssh/hosts")["hosts"]
                                                  if h["id"] == "web-1" and h.get("last_sync") and h["applied"] == h["serial"]], 120)
            assert hosts[0]["state"] in ("ok", "synced"), hosts

        check("setup", setup)

        def alice_reaches_both_no_sudo():
            cli_login(person("alice"), "alice-login")
            for h in (WEB1, WEB2):
                r = until(f"alice@{h}", lambda h=h: (lambda r: r if r.returncode == 0 else None)(ssh("alice", h, "id -un; sudo -n true 2>/dev/null && echo SUDO")), 90)
                assert r.stdout.split()[0] == "alice" and "SUDO" not in r.stdout, r.stdout
        check("alice_reaches_both_no_sudo", alice_reaches_both_no_sudo)

        def alice_sudo_after_join():
            members("ssh_admins", "alice", True)
            cli_login(person("alice"), "alice-login-2")
            until("alice sudo on web-1 (one long-poll)", lambda: "SUDO" in ssh("alice", WEB1, "sudo -n true && echo SUDO").stdout, 90)
        check("alice_sudo_after_join", alice_sudo_after_join)

        def root_refused():
            r = ssh("root", WEB1)
            assert r.returncode != 0, r.stdout
            r = ssh("root", WEB2)
            assert r.returncode != 0, r.stdout
        check("root_refused", root_refused)

        def bob_deploy_keyid():
            logout()
            cli_login(person("bob"), "bob-login")
            r = until("deploy@web-1", lambda: (lambda r: r if r.returncode == 0 else None)(ssh("deploy", WEB1)), 90)
            assert r.stdout.strip() == "deploy", r.stdout
            assert ssh("bob", WEB1).returncode != 0, "bob has no account grant"
            logs = run(["docker", "logs", "e2e-web-1"]).stderr + run(["docker", "logs", "e2e-web-1"]).stdout
            assert re.search(r"ID pc:bob:web:[0-9a-f]{16}", logs), "no pc:bob:web: key id in sshd's log"
        check("bob_deploy_keyid", bob_deploy_keyid)

        def replayed_code_refused():
            k = os.path.join(tmp, "replay")
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", k])
            body = signed_cert_request(person("bob"), k)
            c1, out1 = post_certs(body)
            assert c1 == 200, f"first use: {c1} {out1[:300]}"
            c2, out2 = post_certs(body)
            assert c2 == 403 and "fresh sign-in" in out2, f"replay: {c2} {out2[:300]}"
        check("replayed_code_refused", replayed_code_refused)

        def wrong_key_proof_refused():
            k, other = os.path.join(tmp, "k1"), os.path.join(tmp, "k2")
            for f in (k, other):
                run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", f])
            code_, out = post_certs(signed_cert_request(person("bob"), k, proof_key=other))
            assert code_ == 403, f"{code_} {out[:300]}"
        check("wrong_key_proof_refused", wrong_key_proof_refused)

        def cli_client_shape():
            cs = S.kc("/clients?clientId=portcullis-cli")
            assert len(cs) == 1, cs
            c = cs[0]
            assert c["publicClient"] and not c.get("serviceAccountsEnabled") and not c.get("directAccessGrantsEnabled"), c
            assert sorted(c["redirectUris"]) == [f"http://127.0.0.1:{p}/callback" for p in (38917, 38918, 38919)], c["redirectUris"]
            assert c.get("webOrigins") == [], c.get("webOrigins")
            assert c.get("attributes", {}).get("pkce.code.challenge.method") == "S256", c.get("attributes")
            page = person("bob")
            for bad in ("http://127.0.0.1:40000/callback", "http://localhost:38917/callback"):
                page.goto(f"https://auth.{DOMAIN}/realms/portcullis/protocol/openid-connect/auth?" + urllib.parse.urlencode(
                    {"client_id": "portcullis-cli", "response_type": "code", "scope": "openid", "redirect_uri": bad,
                     "code_challenge": "x" * 43, "code_challenge_method": "S256"}), wait_until="domcontentloaded")
                assert "redirect_uri" in S.body(page).lower() or page.locator("#kc-error-message").count(), f"{bad}: {page.url}"
        check("cli_client_shape", cli_client_shape)

        def leave_locks_and_revokes():
            logout()
            cli_login(person("alice"), "alice-login-3")
            assert ssh("alice", WEB1).returncode == 0
            assert ssh("alice", WEB2).returncode == 0
            members("ssh_admins", "alice", False)
            members("ssh_web", "alice", False)
            until("web-1 refuses alice", lambda: ssh("alice", WEB1).returncode != 0, 90)
            r = dexec("web-2", "portcullis", "host", "revoked-keys")
            assert r.returncode == 0, r.stderr[-400:]
            until("web-2 refuses alice after one pull", lambda: ssh("alice", WEB2).returncode != 0, 30)
        check("leave_locks_and_revokes", leave_locks_and_revokes)

        def hub_stopped_valid_certs_and_breakglass_work():
            logout()
            cli_login(person("bob"), "bob-login-2")
            subprocess.run(["docker", "compose", "stop", "hub"], check=True, capture_output=True)
            try:
                assert ssh("deploy", WEB1).returncode == 0, "bob's certificate with the Hub down"
                r = run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "IdentitiesOnly=yes",
                         "-o", "IdentityAgent=none", "-i", bg, f"breakglass@{WEB1}", "id -un"])
                assert r.returncode == 0 and r.stdout.strip() == "breakglass", r.stderr[-300:]
                k = os.path.join(tmp, "bgcert")
                run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", k])
                r = run(["./portcullis", "ssh", "breakglass-cert", "--account", "deploy", "--host-group", "web", "--ttl", "10m",
                         "--key", k + ".pub", "--note", "e2e outage"])
                assert r.returncode == 0, r.stderr[-400:]
                with open(k + "-cert.pub", "w") as f:
                    f.write(r.stdout)
                r = run(["ssh", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", k,
                         "-o", f"CertificateFile={k}-cert.pub", f"deploy@{WEB1}", "id -un"], env=cli_env())
                assert r.returncode == 0 and r.stdout.strip() == "deploy", r.stderr[-300:]
                rec = open("secrets/ssh/breakglass.jsonl").read().strip().splitlines()[-1]
                assert json.loads(rec)["note"] == "e2e outage", rec
            finally:
                subprocess.run(["docker", "compose", "start", "hub"], capture_output=True)
                until("the Hub back", lambda: S.hub_as("root", "GET", "/api/ssh/settings")[0] == 200, 120)
            audit = until("ssh.certificate.breakglass audited", lambda: [e for e in S.audit_entries("ssh.certificate.breakglass")], 60)
            assert audit, audit
        check("hub_stopped_valid_certs_and_breakglass_work", hub_stopped_valid_certs_and_breakglass_work)

        def no_secret_anywhere():
            # Traefik's access log holds every request line, the browser's
            # redirects with an OAuth code included (core-wide, every OIDC
            # sign-in): codes and nonces are checked everywhere else; the
            # verifier, enrolment code and private keys everywhere.
            services = run(["docker", "compose", "config", "--services"]).stdout.split()
            sources = {svc: run(["docker", "compose", "logs", "--no-color", svc]).stdout for svc in services}
            for h in ("web-1", "web-2"):
                sources[f"sshd {h}"] = run(["docker", "logs", f"e2e-{h}"]).stdout + run(["docker", "logs", f"e2e-{h}"]).stderr
            sources["hub data (audit, issued.jsonl)"] = run(["docker", "run", "--rm", "-v", "portcullis_hub_data:/d:ro", os.environ["ALPINE"], "sh", "-c",
                                                             "cat /d/audit*.jsonl /d/audit/*.jsonl /d/ssh/issued.jsonl 2>/dev/null; true"]).stdout
            sources["CLI output"] = "\n".join(state["cli_out"])
            leaked = []
            for where, text in sources.items():
                for kind, v in state["secrets"]:
                    if len(v) < 12 or v not in text:
                        continue
                    if where == "traefik" and kind in ("code", "nonce"):
                        continue
                    leaked.append(f"{kind} {v[:4]}… in {where}")
                if "PRIVATE KEY" in text:
                    leaked.append(f"a private key in {where}")
            assert not leaked, f"secrets found: {leaked}"
        check("no_secret_anywhere", no_secret_anywhere)

        def finally_():
            for h in ("web-1",):
                p = fresh_proof(person("root"), f"remove-{h}")
                api_ok("DELETE", f"/api/ssh/hosts/{h}", p)
            api_ok("PUT", "/api/ssh/settings", {"enabled": False, "default_ttl_hours": 8})
            assert api_ok("GET", "/api/ssh/settings")["enabled"] is False
        check("finally", finally_)
        browser.close()
    try:
        os.kill(state["agent_pid"], 15)  # our own agent only
    except OSError:
        pass
    shutil.rmtree(tmp, ignore_errors=True)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write("### e2e-ssh\n\n| Case | Result |\n|---|---|\n")
            for n, ok, why in results:
                f.write(f"| {n} | {'✅' if ok else '❌ ' + why[:200]} |\n")
    failed = [n for n, ok, _ in results if not ok]
    print(f"{len(results) - len(failed)} passed, {len(failed)} failed", flush=True)
    return 1 if failed or not results else 0


if __name__ == "__main__":
    sys.exit(main())
