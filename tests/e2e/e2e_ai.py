#!/usr/bin/env python3
"""AI support end to end (CI job `e2e-ai`, plan 4 Task 30; contract §15).

The first real run of the whole chain: an MCP client (tests/e2e/mcpclient,
the official Go SDK, on the runner host) → Traefik → mcp-gate → the Gitea
companion (the official gitea-mcp, from the templates repo) → Gitea, with
Keycloak's OAuth (PKCE + `resource`, the Hub's `portcullis-ai-claude-code`
client and `mcp:*` scopes) and the Hub (AI settings, companion switch,
gate files, lazy mint / revoke hooks).

Setup through the Hub's admin API as the CI admin `root` (never LLDAP's
`admin`): instance `gitea-b` (the cross-app resource), both instances
enabled, memberships (alice: users_gitea + users_gitea-b; bob:
users_gitea), master switch on with Claude Code offered (admin flag on, so
hub.<d>/mcp exists), Gitea's companion on in read_write on both. alice and
bob sign in through their setup links, then once to Gitea (their accounts
are created by Gitea's OIDC sign-in, the only way: account linking is
off); each gets one private repository (Gitea's CLI + API inside the
container, the token on curl's stdin).

Scenarios (one function each; screenshots and traces kept on failure):
  1. gitea_as_alice             token for https://gitea.<d>/mcp, tools/list,
                                repo_read list_my_repos → only alice's repos
  2. leaver_refused_and_revoked alice out of users_gitea → 403, her Gitea
                                portcullis-ai-* token deleted
  3. audience_separation        her Gitea token at gitea-b, mcp.<d>, hub.<d>,
                                people.<d> → 401; one token for two
                                resources → refused at both
  4. no_token_crossing          the MCP token on Gitea's and people's pages
                                → sign-in redirect / 401, never a page;
                                browser cookies on /mcp → 401
Scenario 2 runs last (it removes alice). T30 proper adds 5–7.

Environment: E2E_DOMAIN, HUB_IP, E2E_HUB_SECRET, E2E_HUB_ACTOR (root),
E2E_ALICE_INVITE, E2E_BOB_INVITE, E2E_MCPCLIENT (binary), E2E_CA (PEM the
stack's certificates chain to), E2E_ARTIFACTS. Tokens live only in
E2E_TOKEN_DIR (default a fresh temp dir, never in the artifacts) and are
never printed: only their claims' aud / scope / azp.
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

from playwright.sync_api import Error as PWError
from playwright.sync_api import Page, sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_login as base  # noqa: E402  (Authenticator, passkey_flow, shot)

DOMAIN = os.environ["E2E_DOMAIN"]
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
HUB_API = f"http://{os.environ['HUB_IP']}:8888"
SECRET = os.environ["E2E_HUB_SECRET"]
ACTOR = os.environ.get("E2E_HUB_ACTOR", "root")
MCPCLIENT = os.environ["E2E_MCPCLIENT"]
CA = os.environ["E2E_CA"]
TOKENS = os.environ.get("E2E_TOKEN_DIR") or tempfile.mkdtemp(prefix="e2e-ai-tokens-")
TIMEOUT_MS = 30_000
PORTAL = f"https://{DOMAIN}/"
AUTH = f"https://auth.{DOMAIN}"
GITEA = f"https://gitea.{DOMAIN}"
GITEA_B = f"https://gitea-b.{DOMAIN}"
GITEA_MCP = GITEA + "/mcp"
GITEA_B_MCP = GITEA_B + "/mcp"
MCP_ALL = f"https://mcp.{DOMAIN}/mcp"
HUB_MCP = f"https://hub.{DOMAIN}/mcp"
PEOPLE = f"https://people.{DOMAIN}"
PEOPLE_MCP = PEOPLE + "/mcp"
CLIENT = "portcullis-ai-claude-code"
CALLBACK = "http://127.0.0.1:33418/callback"
SCOPE_GITEA = "mcp:gitea.gitea"
# Access tokens live 5 minutes (realm); a token older than this is renewed
# by signing in again (the consent is remembered, the SSO session is live).
TOKEN_FRESH_S = 180

results: list[tuple[str, bool, str]] = []
SSL = ssl.create_default_context(cafile=CA)


def check(name: str, fn) -> None:
    try:
        fn()
        results.append((name, True, ""))
        print(f"PASS: {name}", flush=True)
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"{type(e).__name__}: {e}"))
        print(f"FAIL: {name}: {e}", flush=True)
        traceback.print_exc()


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


# ── the Hub's admin API (as Traefik calls it: proxy secret + identity) ──

def hub(method: str, path: str, body=None, timeout: float = 600) -> tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(HUB_API + path, data=data, method=method, headers={
        "X-Portcullis-Proxy-Secret": SECRET, "X-Forwarded-User": ACTOR,
        "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def hub_ok(method: str, path: str, body=None, want=(200,), timeout: float = 600) -> dict:
    code, out = hub(method, path, body, timeout)
    assert code in want, f"{method} {path}: HTTP {code}: {out[:600]}"
    return json.loads(out) if out.strip() else {}


def member(op: str, group: str, user: str) -> None:
    if op == "add":
        hub_ok("POST", f"/api/directory/groups/{group}/members", {"username": user})
    else:
        hub_ok("DELETE", f"/api/directory/groups/{group}/members/{user}", {})


# ── docker / Gitea ──

def docker(*args: str, stdin: str | None = None, check_rc: bool = True) -> str:
    p = subprocess.run(["docker", *args], input=stdin, capture_output=True, text=True, timeout=180)
    if check_rc and p.returncode != 0:
        raise AssertionError(f"docker {' '.join(args[:3])}…: rc {p.returncode}: {p.stderr.strip()[:400]}")
    return p.stdout


def container(project: str, service: str) -> str:
    ids = docker("ps", "-q", "--filter", f"label=com.docker.compose.project=portcullis-{project}",
                 "--filter", f"label=com.docker.compose.service={service}").split()
    assert len(ids) == 1, f"{project}/{service}: running containers {ids}"
    return ids[0]


# Inside the gitea container, as git: a token of $1 minted by Gitea's CLI
# (never on an argv: command substitution, then printf, a builtin, into
# curl's --config on stdin) and one API call with it.
GITEA_AS = r'''set -eu
u="$1"; scopes="$2"; method="$3"; path="$4"; body="${5:-}"
t=$(gitea admin user generate-access-token --username "$u" --scopes "$scopes" --raw \
     --token-name "ci-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')")
if [ -n "$body" ]; then
  printf 'user = "%s:%s"\n' "$u" "$t" | curl -sS --config - -o /tmp/ci-api.out -w '%{http_code}' -X "$method" \
    -H 'Content-Type: application/json' --data-raw "$body" "http://127.0.0.1:3000/api/v1$path"
else
  printf 'user = "%s:%s"\n' "$u" "$t" | curl -sS --config - -o /tmp/ci-api.out -w '%{http_code}' -X "$method" \
    "http://127.0.0.1:3000/api/v1$path"
fi
printf '\n'; cat /tmp/ci-api.out; rm -f /tmp/ci-api.out
'''


def gitea_api(instance: str, user: str, scopes: str, method: str, path: str, body: str = "") -> tuple[int, str]:
    cid = container(instance, "gitea")
    out = docker("exec", "-u", "git", cid, "sh", "-c", GITEA_AS, "sh", user, scopes, method, path, body)
    code, _, rest = out.partition("\n")
    return int(code.strip() or 0), rest


def ai_tokens(instance: str, user: str) -> list[str]:
    """The names of user's portcullis-ai-* tokens in Gitea (its API)."""
    code, out = gitea_api(instance, user, "read:user", "GET", f"/users/{user}/tokens")
    assert code == 200, f"Gitea tokens of {user}: HTTP {code}: {out[:300]}"
    return sorted(t["name"] for t in json.loads(out) if t["name"].startswith("portcullis-ai-"))


# ── HTTPS on the runner host (no redirects followed) ──

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: ANN002, ANN003
        return None


_OPENER = urllib.request.build_opener(urllib.request.HTTPSHandler(context=SSL), _NoRedirect)


def https(method: str, url: str, headers: dict | None = None, body: bytes | None = None) -> tuple[int, dict, str]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with _OPENER.open(req, timeout=60) as r:
            return r.status, dict(r.headers), r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")


# ── the MCP client ──

class NetworkChanged(AssertionError):
    """Chromium aborted a navigation (net::ERR_NETWORK_CHANGED: a container
    started or stopped on the runner); the step is safe to repeat."""


def check_network(page: Page) -> None:
    if page.url.startswith("chrome-error://"):
        raise NetworkChanged(f"browser network error (at {page.url})")


def goto(page: Page, url: str) -> None:
    try:
        page.goto(url, wait_until="domcontentloaded")
    except PWError as e:
        if "ERR_NETWORK_CHANGED" in str(e):
            raise NetworkChanged(f"browser network error opening {url.split('?')[0]}") from e
        raise


def retry_network(fn, what: str, tries: int = 3):
    for i in range(tries):
        try:
            return fn()
        except NetworkChanged as e:
            print(f"    {what}: {e}; again ({i + 1}/{tries})", flush=True)
            time.sleep(5)
    return fn()


def claims(token_file: str) -> dict:
    tok = json.load(open(token_file))["access_token"]
    payload = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def token_of(token_file: str) -> str:
    return json.load(open(token_file))["access_token"]


def show(label: str, token_file: str) -> dict:
    c = claims(token_file)
    print(f"    {label}: azp {c.get('azp')} aud {c.get('aud')} scope {c.get('scope')!r} acr {c.get('acr')}", flush=True)
    return c


def consent(page: Page, label: str) -> None:
    """Drive Keycloak from the authorize URL to the loopback callback:
    a passkey prompt if the session asks, the consent screen (approved)."""
    deadline = time.time() + 90
    approved = False
    while time.time() < deadline:
        page.wait_for_load_state("domcontentloaded")
        if page.url.startswith(CALLBACK):
            return
        check_network(page)
        if base.on_login_pages(page):
            accept = page.locator("[name=accept]")
            if accept.count() and accept.first.is_visible():
                base.shot(page, f"{label}-consent")
                text = page.inner_text("body")
                print(f"    consent screen: {' | '.join(l.strip() for l in text.splitlines() if 'as you' in l)}", flush=True)
                accept.first.click()
                approved = True
                page.wait_for_timeout(1000)
                continue
            if page.locator("#authenticateWebAuthnButton").is_visible():
                page.click("#authenticateWebAuthnButton")
                page.wait_for_timeout(1500)
                continue
            err = page.locator(".pf-m-danger, .alert-error, #input-error, .kc-feedback-text")
            if err.count() and err.first.is_visible():
                base.shot(page, f"{label}-kc-error")
                raise AssertionError(f"Keycloak error: {err.first.inner_text()!r}")
        page.wait_for_timeout(500)
    base.shot(page, f"{label}-stuck")
    raise AssertionError(f"authorize did not reach the callback (approved={approved}, at {page.url[:160]})")


def mcp_login(page: Page, resource: str, label: str, scope: str | None = None) -> str:
    """mcpclient login for resource, the browser part in page (repeated
    when Chromium's network changed); returns the token file."""
    return retry_network(lambda: _mcp_login(page, resource, label, scope), f"{label} login")


def _mcp_login(page: Page, resource: str, label: str, scope: str | None = None) -> str:
    tf = os.path.join(TOKENS, f"{label}.json")
    if os.path.exists(tf):
        os.remove(tf)
    argv = [MCPCLIENT, "login", "--client-id", CLIENT, "--callback-port", "33418", "--resource", resource,
            "--token-file", tf, "--ca-file", CA, "--timeout", "3m"]
    if scope:
        argv += ["--scope", scope]
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        url = p.stdout.readline().strip()
        if not url:
            p.wait(30)
            raise AssertionError(f"mcpclient login printed no URL: rc {p.returncode}: {p.stderr.read()[:600]}")
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        assert url.startswith(AUTH + "/realms/portcullis/protocol/openid-connect/auth?"), url[:120]
        assert q.get("client_id") == [CLIENT] and q.get("code_challenge_method") == ["S256"] \
            and q.get("resource") == [resource] and q.get("redirect_uri") == [CALLBACK], \
            f"authorize parameters: { {k: v for k, v in q.items() if k not in ('state', 'code_challenge')} }"
        goto(page, url)
        consent(page, label)
        rc = p.wait(60)
        err = p.stderr.read()
        assert rc == 0, f"mcpclient login: rc {rc}: {err[:600]}"
    finally:
        if p.poll() is None:
            p.kill()
    assert os.path.exists(tf), "no token file"
    return tf


def mcp_call(url: str, tf: str, method: str = "tools/list", tool: str | None = None, args: dict | None = None):
    argv = [MCPCLIENT, "call", "--url", url, "--token-file", tf, "--method", method, "--ca-file", CA]
    if tool:
        argv += ["--tool", tool, "--args", json.dumps(args or {})]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=200)
    assert p.returncode in (0, 2), f"mcpclient call {method} {url}: rc {p.returncode}: {p.stderr.strip()[:600]}"
    return p.returncode, json.loads(p.stdout)


def text_of(result: dict) -> str:
    return "\n".join(c.get("text", "") for c in (result.get("content") or []) if isinstance(c, dict))


def list_my_repos(tf: str) -> str:
    """repo_read list_my_repos as the token's person, retried while the
    gate is still preparing the credential (lazy mint)."""
    def once():
        rc, doc = mcp_call(GITEA_MCP, tf, "tools/call", "repo_read", {"method": "list_my_repos"})
        assert rc == 0, f"HTTP refusal: {doc}"
        if "error" in doc:
            print(f"    JSON-RPC error: {doc['error']}", flush=True)
            return None
        res = doc["result"]
        if res.get("isError"):
            print(f"    tool error: {text_of(res)[:300]}", flush=True)
            return None
        return text_of(res) or json.dumps(res.get("structuredContent"))
    return until("repo_read list_my_repos answered", once, 90, every=10)


def refused(url: str, tf: str) -> int:
    rc, doc = mcp_call(url, tf)
    return doc.get("http_status", 0) if rc == 2 else 0


def gitea_routed() -> None:
    """Both Gitea instances answer through Traefik (routed once healthy):
    the login page redirects to Gitea's OAuth2 source."""
    for base_url in (GITEA, GITEA_B):
        until(f"{base_url} routed", lambda: https("GET", base_url + "/user/login")[0] in (302, 303, 307), 240, every=5)


def main() -> int:
    os.makedirs(ART, exist_ok=True)
    os.chmod(TOKENS, 0o700)
    state: dict = {}

    # ── setup through the Hub's API ──
    def setup_instances():
        until("the Hub loaded gitea", lambda: any(t.get("id") == "gitea" for t in json.loads(hub("GET", "/api/templates")[1])), 90)
        hub_ok("POST", "/api/instances", {"template": "gitea", "id": "gitea-b", "hosts": {"gitea": f"gitea-b.{DOMAIN}"}},
               want=(201,))
        # One host port per instance: gitea keeps 2222 (Git over SSH is off
        # anyway), gitea-b none (the port's description says so).
        hub_ok("PUT", "/api/instances/gitea-b/settings", {"ports": {"GITEA_SSH_PORT": ""}})
        for inst in ("gitea", "gitea-b"):
            t0 = time.time()
            out = hub_ok("POST", "/api/templates/enable", {"id": inst}, timeout=1500)
            print(f"    enabled {inst} in {time.time() - t0:.0f} s: {json.dumps({k: out.get(k) for k in ('groups_created', 'warnings')})}",
                  flush=True)
        for m in ("alice:users_gitea", "alice:users_gitea-b", "bob:users_gitea"):
            u, g = m.split(":")
            member("add", g, u)
        gitea_routed()


    with sync_playwright() as pw_:
        browser = pw_.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])
        ctxs: dict = {}

        def sign_in(who: str) -> Page:
            ctx = browser.new_context()
            ctx.set_default_timeout(TIMEOUT_MS)
            ctxs[who] = ctx
            page = ctx.new_page()
            # Failed requests (path only: queries carry codes and states).
            page.on("requestfailed", lambda r: print(
                f"    {who}: request failed: {r.method} {r.url.split('?')[0]}: {r.failure}", flush=True))
            base.Authenticator(page)
            page.goto(os.environ[f"E2E_{who.upper()}_INVITE"], wait_until="domcontentloaded")
            base.passkey_flow(page, until=PORTAL, label=f"ai-{who}")
            # Traced from here: the (consumed) setup link stays out of the trace.
            ctx.tracing.start(screenshots=True, snapshots=True, name=who)
            assert f"Signed in as <strong>{who}</strong>" in page.content(), page.content()[:300]
            return page

        def gitea_sign_in(page: Page, who: str) -> None:
            goto(page, GITEA + "/user/login")
            deadline = time.time() + 90
            while time.time() < deadline:
                page.wait_for_load_state("domcontentloaded")
                if page.url.startswith(GITEA) and "/user/login" not in page.url and "/user/oauth2/" not in page.url:
                    break
                check_network(page)
                if base.on_login_pages(page) and page.locator("#authenticateWebAuthnButton").is_visible():
                    page.click("#authenticateWebAuthnButton")
                page.wait_for_timeout(500)
            body = page.content()
            assert "Sign-in prohibited" not in body, f"Gitea refused {who}"
            got = page.evaluate("""() => fetch('/user/settings', {redirect: 'manual'})
                .then(r => r.ok ? r.text() : '')
                .then(t => { const e = new DOMParser().parseFromString(t, 'text/html').querySelector('input#username');
                             return e ? e.value : null; })""")
            base.shot(page, f"ai-gitea-{who}")
            assert got == who, f"Gitea session of {who}: {got!r} (at {page.url})"

        pages: dict[str, Page] = {}

        # The setup links first, while the network is quiet: every container
        # start or stop changes the runner's interfaces, and Chromium then
        # aborts in-flight requests (net::ERR_NETWORK_CHANGED) — a consumed
        # setup link can't be retried.
        def setup_links():
            for who in ("alice", "bob"):
                pages[who] = sign_in(who)
        check("alice and bob: setup link → passkey → portal", setup_links)
        if len(pages) != 2:
            return report()
        check("setup: gitea-b created, gitea + gitea-b enabled, alice in users_gitea + users_gitea-b, bob in users_gitea "
              "(Hub API as root)", setup_instances)

        def gitea_accounts():
            for who in ("alice", "bob"):
                retry_network(lambda: gitea_sign_in(pages[who], who), f"{who}'s Gitea sign-in")
        check("alice and bob: Gitea's OIDC sign-in (through their Keycloak session) creates their Gitea accounts",
              gitea_accounts)
        alice = pages["alice"]

        def seed():
            for who in ("alice", "bob"):
                code, out = gitea_api("gitea", who, "write:repository,write:user", "POST", "/user/repos",
                                      json.dumps({"name": f"{who}-private", "private": True}))
                assert code == 201, f"{who}-private: HTTP {code}: {out[:300]}"
        check("seed: alice-private and bob-private (private Gitea repositories)", seed)

        def ai_on():
            v = hub_ok("PUT", "/api/ai/settings", {"enabled": True,
                                                    "clients": {"claude_code": {"offered": True, "admin": True}}})
            assert v.get("enabled") is True and v.get("gate_present") is True, f"AI settings: {json.dumps(v)[:600]}"
            for inst in ("gitea", "gitea-b"):
                r = hub_ok("PUT", f"/api/instances/{inst}/ai",
                           {"companions": {"gitea": {"enabled": True, "mode": "read_write"}}}, timeout=900)
                print(f"    {inst}: {json.dumps({'restarts': r.get('restarts'), 'warnings': r.get('warnings')})}", flush=True)

                def companion_on():
                    c = hub_ok("GET", f"/api/instances/{inst}/ai")["companions"][0]
                    print(f"    {inst} companion: status {c.get('status')} mode {c.get('mode')} "
                          f"population {c.get('population')} last_error {c.get('last_error')!r}", flush=True)
                    return c.get("status") == "on" and c.get("mode") == "read_write" and c
                until(f"{inst}'s companion on", companion_on, 180, every=5)
                until(f"{inst}'s gitea-mcp running", lambda: container(inst, "gitea-mcp"), 120, every=5)
            gitea_routed()
            for url, scope in ((GITEA_MCP, SCOPE_GITEA), (GITEA_B_MCP, "mcp:gitea-b.gitea"), (MCP_ALL, "mcp:all"),
                               (HUB_MCP, "mcp:portcullis.admin"), (PEOPLE_MCP, "mcp:portcullis.people")):
                host = urllib.parse.urlsplit(url).netloc
                meta = f"https://{host}/.well-known/oauth-protected-resource/mcp"

                def served():
                    code, _, body = https("GET", meta)
                    return code == 200 and json.loads(body)
                doc = until(f"{meta} served", served, 120)
                assert doc["resource"] == url and doc["scopes_supported"] == [scope] \
                    and doc["authorization_servers"] == [AUTH + "/realms/portcullis"], doc
        check("ai_on: master switch on (Claude Code offered, admin flag), Gitea's companion on in read_write on gitea and "
              "gitea-b; every resource's RFC 9728 metadata served", ai_on)

        # ── 1 ──
        def gitea_as_alice():
            tf = mcp_login(alice, GITEA_MCP, "alice-gitea")
            state["alice_gitea"], state["alice_gitea_at"] = tf, time.time()
            c = show("alice's Gitea token", tf)
            assert c.get("azp") == CLIENT and c.get("preferred_username") == "alice", c
            aud = c["aud"] if isinstance(c.get("aud"), list) else [c.get("aud")]
            assert GITEA_MCP in aud and not any(a.startswith("http") and a != GITEA_MCP for a in aud), aud
            assert SCOPE_GITEA in c.get("scope", "").split(), c.get("scope")
            rc, doc = mcp_call(GITEA_MCP, tf)
            assert rc == 0 and "result" in doc, f"tools/list: {doc}"
            names = sorted(t["name"] for t in doc["result"]["tools"])
            print(f"    tools/list: {len(names)} tools, e.g. {names[:6]}", flush=True)
            assert "repo_read" in names and "repo_write" in names, names
            text = list_my_repos(tf)
            assert "alice-private" in text, f"alice's repos: {text[:400]}"
            assert "bob-private" not in text, f"bob's repository listed for alice: {text[:400]}"
            minted = ai_tokens("gitea", "alice")
            assert len(minted) == 1, f"alice's portcullis-ai-* tokens in Gitea: {minted}"
            assert ai_tokens("gitea", "bob") == [], "bob got an AI token"
            act = hub_ok("GET", "/api/ai/activity?n=50")
            mine = [x for x in act.get("lines") or [] if x.get("user") == "alice" and x.get("instance") == "gitea"]
            assert any(x.get("decision") == "allow" and x.get("tool") == "repo_read" for x in mine), \
                f"access log: {json.dumps(mine)[:600] or json.dumps(act)[:600]}"
        check("gitea_as_alice: OAuth (PKCE, resource) for https://gitea.<d>/mcp, tools/list, repo_read list_my_repos "
              "→ alice-private only; one minted portcullis-ai-* token; access log allow", gitea_as_alice)

        def fresh_gitea_token() -> str:
            if state.get("alice_gitea") and time.time() - state.get("alice_gitea_at", 0) < TOKEN_FRESH_S:
                return state["alice_gitea"]
            tf = mcp_login(alice, GITEA_MCP, "alice-gitea")
            state["alice_gitea"], state["alice_gitea_at"] = tf, time.time()
            return tf

        # ── 3 ──
        def audience_separation():
            tf = fresh_gitea_token()
            got = {url: refused(url, tf) for url in (GITEA_B_MCP, MCP_ALL, HUB_MCP, PEOPLE_MCP)}
            print(f"    alice's Gitea token elsewhere: {got}", flush=True)
            assert all(v == 401 for v in got.values()), got
            assert refused(GITEA_MCP, tf) == 0, "the token stopped working on its own resource"
            # One token for two resources (both scopes).
            try:
                both = mcp_login(alice, GITEA_MCP, "alice-both", scope=f"{SCOPE_GITEA} mcp:all")
            except AssertionError as e:
                print(f"    RESULT both-scopes: Keycloak did not mint one ({e}); the case is dropped", flush=True)
                return
            c = show("alice's two-resource token", both)
            aud = c["aud"] if isinstance(c.get("aud"), list) else [c.get("aud")]
            print(f"    RESULT both-scopes: Keycloak minted aud {aud}", flush=True)
            got = {url: refused(url, both) for url in (GITEA_MCP, MCP_ALL, GITEA_B_MCP)}
            print(f"    two-resource token: {got}", flush=True)
            assert all(v == 401 for v in got.values()), got
        check("audience_separation: alice's Gitea token at gitea-b, mcp.<d>, hub.<d>, people.<d> → 401; a token "
              "minted for gitea + mcp:all → 401 everywhere", audience_separation)

        # ── 4 ──
        def no_token_crossing():
            tf = fresh_gitea_token()
            bearer = {"Authorization": "Bearer " + token_of(tf)}
            # Pages that need a session: the sign-in redirect, never the page.
            for url, ok_loc in ((GITEA + "/user/settings", ("/user/login",)), (GITEA + "/alice/alice-private", ("/user/login",)),
                                (PEOPLE + "/", (AUTH, "/oauth2/"))):
                code, h, body = https("GET", url, bearer)
                loc = h.get("Location") or h.get("location") or ""
                print(f"    bearer on {url}: HTTP {code} → {loc[:100]}", flush=True)
                assert code in (302, 303, 307) and any(s in loc for s in ok_loc), f"{url}: HTTP {code} {loc!r} {body[:200]}"
            # Gitea's landing page is public: with the token it is exactly the
            # anonymous page (nobody signed in).
            code, _, body = https("GET", GITEA + "/", bearer)
            anon, _, _ = https("GET", GITEA + "/")
            print(f"    bearer on {GITEA}/: HTTP {code} (anonymous: {anon})", flush=True)
            assert code == anon and "alice" not in body, f"Gitea's home with the MCP token: HTTP {code}, 'alice' in page: {'alice' in body}"
            code, _, body = https("GET", GITEA + "/api/v1/user", bearer)
            print(f"    bearer on Gitea's API: HTTP {code}", flush=True)
            assert code == 401, f"Gitea's API with the MCP token: HTTP {code} {body[:200]}"
            init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "browser", "version": "1"}}})
            for url in (GITEA_MCP, PEOPLE_MCP, MCP_ALL):
                cookies = [c["name"] for c in alice.context.cookies(url)]
                r = alice.request.post(url, data=init, headers={"Content-Type": "application/json",
                                                                 "Accept": "application/json, text/event-stream"})
                print(f"    browser cookies {cookies} on {url}: HTTP {r.status}", flush=True)
                assert r.status == 401, f"{url} with alice's browser session: HTTP {r.status} {r.text()[:200]}"
                assert "set-cookie" not in {k.lower() for k in r.headers}, f"{url} set a cookie"
            assert any(alice.context.cookies(GITEA)) and any(alice.context.cookies(PEOPLE)), "no browser session to test"
        check("no_token_crossing: the MCP token on Gitea's and people.<d>'s pages → sign-in redirect (Gitea API 401), "
              "never a page; the browser session's cookies on /mcp → 401", no_token_crossing)

        # ── 2 (last: alice leaves) ──
        def leaver_refused_and_revoked():
            tf = mcp_login(alice, GITEA_MCP, "alice-gitea-leave")
            assert "alice-private" in list_my_repos(tf)
            assert len(ai_tokens("gitea", "alice")) == 1
            t0 = time.time()
            member("remove", "users_gitea", "alice")
            code = until("alice refused (403)", lambda: refused(GITEA_MCP, tf) == 403 and 403, 120, every=3)
            print(f"    403 after {time.time() - t0:.0f} s", flush=True)
            assert code == 403
            until("alice's portcullis-ai-* token deleted in Gitea", lambda: ai_tokens("gitea", "alice") == [], 240, every=5)
            print(f"    token gone after {time.time() - t0:.0f} s", flush=True)
            assert refused(GITEA_MCP, tf) == 403, "alice is allowed again"
        check("leaver_refused_and_revoked: alice removed from users_gitea (Hub API) → her next call 403; her Gitea "
              "portcullis-ai-* token deleted (Gitea API)", leaver_refused_and_revoked)

        failed = any(not ok for _, ok, _ in results)
        for who, ctx in ctxs.items():
            try:
                if failed:
                    ctx.tracing.stop(path=os.path.join(ART, f"trace-ai-{who}.zip"))
                else:
                    ctx.tracing.stop()
            finally:
                ctx.close()
        browser.close()
    return report()


def report() -> int:
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    for name, _, err in failed:
        print(f"  FAIL {name}: {err}")
    return 1 if failed or not results else 0


if __name__ == "__main__":
    sys.exit(main())
