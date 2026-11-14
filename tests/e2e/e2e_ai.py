#!/usr/bin/env python3
"""AI support end to end (CI job `e2e-ai`, plan 4 Task 30; contract §15).

The first real run of the whole chain: an MCP client (tests/e2e/mcpclient,
the official Go SDK, on the runner host) → Traefik → mcp-gate → the Gitea
companion (the official gitea-mcp, from the templates repo) → Gitea, with
Keycloak's OAuth (PKCE + `resource`, the Hub's `portcullis-ai-claude-code`
client and `mcp:*` scopes) and the Hub (AI settings, companion switch,
gate files, lazy mint / revoke hooks).

Setup through the Hub's admin API as the CI admin `root` (never LLDAP's
`admin`): instances `gitea-b` (the cross-app resource) and `echo-del` (a
throwaway, never enabled), gitea, gitea-b and grafana enabled, memberships
(alice: users_gitea + users_gitea-b; bob: users_gitea; carol: users_gitea +
users_grafana), master switch on with Claude Code offered (admin flag on,
so hub.<d>/mcp exists), Gitea's companion on in read_write on both,
Grafana's (identity_headers) in read_only. root, alice, bob and carol sign
in through their setup links before any app starts (container starts
change the runner's network and Chromium aborts in-flight requests), then
alice, bob and carol once to Gitea (accounts exist only through its OIDC
sign-in); alice and bob get one private repository each (Gitea's CLI + API
inside the container, the token on curl's stdin).

Scenarios (one function each; screenshots and traces kept on failure):
  1. gitea_as_alice             token for https://gitea.<d>/mcp, tools/list,
                                repo_read list_my_repos → only alice's repos
  3. audience_separation        her Gitea token at gitea-b, mcp.<d>, hub.<d>,
                                people.<d> → 401; one token for two
                                resources → refused at both
  4. no_token_crossing          the MCP token on Gitea's and people's pages
                                → sign-in redirect / 401, never a page;
                                browser cookies on /mcp → 401
  5. destructive_confirmation   root's delete_instance on hub.<d>/mcp → the
                                confirmation link; bob can't open it; root
                                types the id + fresh passkey → approved; the
                                retry is accepted, a second one needs a new
                                confirmation; audited via ai with the client
                                and the confirmation id
  6. aggregate_lists            mcp.<d>: carol gitea__* + grafana__* +
                                portcullis__my_apps, a Grafana call through
                                the gate; bob no grafana__*; root no admin tool
  8. companion_confirmation     alice's label_write delete_repo_label → a
                                people.<d> confirmation (typed check the
                                instance label); bob 404; approved → runs
                                once with the canonical args; changed args →
                                a new one; access log confirmation_id
  9. url_elicitation_2026       URL elicitation declared: 2026-07-28 →
                                input_required (Hub D tool and companion);
                                2025-11-25 → the gate's elicitation/create
                                mode url, the Hub's text
  2. leaver_refused_and_revoked alice out of users_gitea → 403, her Gitea
                                portcullis-ai-* token deleted
  10. gitea_isolation           gitea-internal / companion alias resolution,
                                no portcullis-hook-* token left, switch-on's
                                revoke_all ok (T25 carry)
  7. ai_off                     master switch off → every resource 503

Environment: E2E_DOMAIN, HUB_IP, E2E_HUB_SECRET, E2E_HUB_ACTOR (root),
E2E_{ROOT,ALICE,BOB,CAROL}_INVITE, E2E_MCPCLIENT (binary), E2E_CA (PEM the
stack's certificates chain to), E2E_ARTIFACTS. Tokens live only in
E2E_TOKEN_DIR (default a fresh temp dir, never in the artifacts) and are
never printed: only their claims' aud / scope / azp.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

from playwright.sync_api import Error as PWError  # noqa: F401 (also goto)
from playwright.sync_api import Page, sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_login as base  # noqa: E402  (Authenticator, passkey_flow, shot)
import e2e_ops  # noqa: E402  (the op record poll, contract §11.7)

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
GRAFANA = f"https://grafana.{DOMAIN}"
GRAFANA_MCP = GRAFANA + "/mcp"
SCOPE_GRAFANA = "mcp:grafana.grafana"
HUB = f"https://hub.{DOMAIN}"
# The throwaway instance root deletes through the admin MCP (scenario 5).
ECHO_DEL = "echo-del"
# Never deleted: the target of the elicitation-shape checks (scenario 9).
ECHO_ELICIT = "echo-elicit"
PEOPLE_CONFIRM_RE = re.compile(r"https://people\.[a-z0-9.-]+/confirm/[A-Za-z0-9_-]+")
ALPINE = os.environ.get("ALPINE", "")
CONFIRM_RE = re.compile(r"https://hub\.[a-z0-9.-]+/confirm/[A-Za-z0-9_-]+")
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


def hub_get(path: str):
    code, out = hub("GET", path)
    return json.loads(out) if code == 200 and out.strip() else out


def run_op(method: str, path: str, body, op: str, instance: str, timeout: float) -> dict:
    """A lifecycle route's 202 (e2e_ops): the record polled until it ended,
    which must be ok."""
    acc = e2e_ops.accepted(hub_ok(method, path, body, want=(202,)), op, instance)
    return e2e_ops.wait_ok(hub_get, acc, timeout)


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


def mcp_call(url: str, tf: str, method: str = "tools/list", tool: str | None = None, args: dict | None = None,
             protocol: str | None = None, elicitation: bool = False, elicit_answer: str = "accept"):
    argv = [MCPCLIENT, "call", "--url", url, "--token-file", tf, "--method", method, "--ca-file", CA]
    if tool:
        argv += ["--tool", tool, "--args", json.dumps(args or {})]
    if protocol:
        argv += ["--protocol", protocol]
    if elicitation:
        argv += ["--elicitation", "url", "--elicit-answer", elicit_answer]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=200)
    assert p.returncode in (0, 2), f"mcpclient call {method} {url}: rc {p.returncode}: {p.stderr.strip()[:600]}"
    return p.returncode, json.loads(p.stdout)


def canonical(args: dict) -> str:
    """RFC 8785 for these arguments (strings and small integers only):
    sorted keys, no whitespace, UTF-8 as is."""
    return json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


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


def tool_names(url: str, tf: str) -> list[str]:
    rc, doc = mcp_call(url, tf)
    assert rc == 0 and "result" in doc, f"tools/list at {url}: {doc}"
    return sorted(t["name"] for t in doc["result"]["tools"])


def call_text(url: str, tf: str, tool: str, args: dict) -> tuple[bool, str]:
    """(isError, text) of a tools/call answer; a JSON-RPC error or an HTTP
    refusal fails."""
    rc, doc = mcp_call(url, tf, "tools/call", tool, args)
    assert rc == 0 and "result" in doc, f"{tool} at {url}: {doc}"
    res = doc["result"]
    return bool(res.get("isError")), text_of(res) or json.dumps(res.get("structuredContent"))


def drive_popup(popup: Page, label: str) -> int:
    """Signs in inside the fresh-auth popup until it closes itself; returns
    the passkey prompts answered."""
    prompted, deadline = 0, time.time() + 120
    while time.time() < deadline:
        if popup.is_closed():
            return prompted
        try:
            if popup.url.startswith(AUTH + "/realms/"):
                pw = popup.locator("input[type=password]")
                if pw.count() and pw.first.is_visible():
                    base.shot(popup, f"{label}-password-prompt")
                    raise AssertionError("password prompt in the fresh-auth popup")
                btn = popup.locator("#authenticateWebAuthnButton")
                if btn.count() and btn.first.is_visible():
                    prompted += 1
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
                return prompted
            time.sleep(0.3)
    base.shot(popup, f"{label}-popup-stuck")
    raise AssertionError(f"the fresh-auth popup didn't finish (at {popup.url.split('?')[0]})")


def norm_id(s: str) -> str:
    return s.replace("-", "").lower()


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
        until("the Hub loaded gitea, grafana and echo",
              lambda: {"gitea", "grafana", "echo"} <= {t.get("id") for t in json.loads(hub("GET", "/api/templates")[1])}, 90)
        # Never enabled: only deleted again, through the admin MCP (scenario 5).
        for tmpl, inst, label in (("echo", ECHO_DEL, "Delete me"), ("echo", ECHO_ELICIT, "Elicit"), ("gitea", "gitea-b", "B")):
            run_op("POST", "/api/instances", {"template": tmpl, "id": inst, "label": label, "hosts": {tmpl: f"{inst}.{DOMAIN}"}},
                   "create", inst, 300)
        # One host port per instance: gitea keeps 2222 (Git over SSH is off
        # anyway), gitea-b none (the port's description says so).
        hub_ok("PUT", "/api/instances/gitea-b/settings", {"ports": {"GITEA_SSH_PORT": ""}})
        for inst in ("gitea", "gitea-b", "grafana"):
            t0 = time.time()
            out = run_op("POST", "/api/templates/enable", {"id": inst}, "enable", inst, 1500)
            print(f"    enabled {inst} in {time.time() - t0:.0f} s: "
                  f"{json.dumps({'groups_created': (out.get('result') or {}).get('groups_created'), 'warnings': out.get('warnings')})}",
                  flush=True)
        for m in ("alice:users_gitea", "alice:users_gitea-b", "bob:users_gitea", "carol:users_gitea", "carol:users_grafana"):
            u, g = m.split(":")
            member("add", g, u)
        gitea_routed()
        until("grafana routed (sign-in redirect)", lambda: https("GET", GRAFANA + "/")[0] in (302, 303, 307), 240, every=5)


    with sync_playwright() as pw_:
        browser = pw_.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])
        ctxs: dict = {}
        auths: dict = {}

        def sign_in(who: str) -> Page:
            ctx = browser.new_context()
            ctx.set_default_timeout(TIMEOUT_MS)
            ctxs[who] = ctx
            page = ctx.new_page()
            # Failed requests (path only: queries carry codes and states).
            page.on("requestfailed", lambda r: print(
                f"    {who}: request failed: {r.method} {r.url.split('?')[0]}: {r.failure}", flush=True))
            auths[who] = base.Authenticator(page)
            base.setup_link_signin(page, os.environ[f"E2E_{who.upper()}_INVITE"], who=who,
                                   mint=lambda: base.mint_setup_link(who, "portal"),
                                   until=PORTAL, label=f"ai-{who}", expect_stepups=1)
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
            for who in ("root", "alice", "bob", "carol"):
                pages[who] = sign_in(who)
        check("root, alice, bob and carol: setup link → passkey → portal", setup_links)
        if len(pages) != 4:
            return report()
        check("setup: gitea-b and echo-del created, gitea + gitea-b + grafana enabled, alice in users_gitea + users_gitea-b, "
              "bob in users_gitea, carol in users_gitea + users_grafana (Hub API as root)", setup_instances)

        def gitea_accounts():
            for who in ("alice", "bob", "carol"):
                retry_network(lambda: gitea_sign_in(pages[who], who), f"{who}'s Gitea sign-in")
        check("alice, bob and carol: Gitea's OIDC sign-in (through their Keycloak session) creates their Gitea accounts",
              gitea_accounts)
        alice, root, bob, carol = pages["alice"], pages["root"], pages["bob"], pages["carol"]

        def seed():
            for who in ("alice", "bob"):
                code, out = gitea_api("gitea", who, "write:repository,write:user", "POST", "/user/repos",
                                      json.dumps({"name": f"{who}-private", "private": True}))
                assert code == 201, f"{who}-private: HTTP {code}: {out[:300]}"
            # Two labels on alice-private: one the companion confirmation
            # deletes (scenario 8), one that must survive it.
            for name in ("ci-delete-me", "ci-keep"):
                code, out = gitea_api("gitea", "alice", "write:repository,write:issue,write:user", "POST",
                                      "/repos/alice/alice-private/labels", json.dumps({"name": name, "color": "#e11d21"}))
                assert code == 201, f"label {name}: HTTP {code}: {out[:300]}"
                state.setdefault("labels", {})[name] = json.loads(out)["id"]
        check("seed: alice-private and bob-private (private Gitea repositories), two labels on alice-private", seed)

        def ai_on():
            v = hub_ok("PUT", "/api/ai/settings", {"enabled": True,
                                                    "clients": {"claude_code": {"offered": True, "admin": True}}})
            assert v.get("enabled") is True and v.get("gate_present") is True, f"AI settings: {json.dumps(v)[:600]}"
            for inst, comp, mode in (("gitea", "gitea", "read_write"), ("gitea-b", "gitea", "read_write"),
                                     ("grafana", "grafana", "read_only")):
                # An enabled instance: the switch runs in the background (202).
                r = run_op("PUT", f"/api/instances/{inst}/ai",
                           {"companions": {comp: {"enabled": True, "mode": mode}}}, "ai", inst, 900)
                print(f"    {inst}: {json.dumps({'steps': [(x.get('key'), x.get('state')) for x in r.get('steps') or []], 'warnings': r.get('warnings')})}",
                      flush=True)

                def companion_on():
                    c = hub_ok("GET", f"/api/instances/{inst}/ai")["companions"][0]
                    print(f"    {inst} companion: status {c.get('status')} mode {c.get('mode')} "
                          f"population {c.get('population')} last_error {c.get('last_error')!r}", flush=True)
                    return c.get("status") == "on" and c.get("mode") == mode and c
                until(f"{inst}'s companion on", companion_on, 180, every=5)
                until(f"{inst}'s {comp}-mcp running", lambda: container(inst, f"{comp}-mcp"), 120, every=5)
                # The switch-on's own record (a later restart may have taken
                # the instance's current one).
                state.setdefault("ai_ops", {})[inst] = hub_ok("GET", e2e_ops.op_url(inst, r["op_id"]))
            gitea_routed()
            state["ai_audit"] = [e for e in json.loads(hub("GET", "/api/directory/audit")[1]) if e.get("action") == "ai.enable"]
            for url, scope in ((GITEA_MCP, SCOPE_GITEA), (GITEA_B_MCP, "mcp:gitea-b.gitea"), (GRAFANA_MCP, SCOPE_GRAFANA),
                               (MCP_ALL, "mcp:all"),
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
              "gitea-b, Grafana's (identity_headers) in read_only; every resource's RFC 9728 metadata served", ai_on)

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
                # Contract §8 states this case as verified here (final review
                # M7): a Keycloak that stops minting it fails the check.
                raise AssertionError(f"Keycloak did not mint a two-resource token: {e}") from e
            c = show("alice's two-resource token", both)
            aud = c["aud"] if isinstance(c.get("aud"), list) else [c.get("aud")]
            print(f"    RESULT both-scopes: Keycloak minted aud {aud}", flush=True)
            assert {GITEA_MCP, MCP_ALL} <= set(aud), f"not a two-resource token: aud {aud}"
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

        # ── 5 ──
        def destructive_confirmation():
            tf = mcp_login(root, HUB_MCP, "root-hub")
            state["root_hub"], state["root_hub_at"] = tf, time.time()
            c = show("root's admin token", tf)
            assert c.get("preferred_username") == "root" and "mcp:portcullis.admin" in c.get("scope", "").split(), c
            assert "delete_instance" in tool_names(HUB_MCP, tf)
            args = {"id": ECHO_DEL}
            err, text = call_text(HUB_MCP, tf, "delete_instance", args)
            m = CONFIRM_RE.search(text)
            print(f"    delete_instance: isError {err}: {text[:200]}", flush=True)
            assert err and m and text.startswith("This needs your confirmation in your browser: open "), text[:300]
            url = m.group(0)
            cid = url.rsplit("/", 1)[1]
            # Before the approval the retry is still waiting (no new confirmation).
            err2, text2 = call_text(HUB_MCP, tf, "delete_instance", args)
            print(f"    retry while pending: isError {err2}: {text2[:160]}", flush=True)
            assert err2 and "Still waiting" in text2 and (CONFIRM_RE.search(text2) is None
                                                          or CONFIRM_RE.search(text2).group(0) == url), text2[:300]
            # bob: not an administrator, so group-gate never lets him reach
            # hub.<d>; the Hub itself answers another person's id with 404.
            r = bob.request.get(url, max_redirects=0)
            print(f"    bob opens the page through Traefik: HTTP {r.status}", flush=True)
            assert r.status in (302, 403) and "echo-del" not in r.text(), f"bob got HTTP {r.status}: {r.text()[:200]}"
            req = urllib.request.Request(f"{HUB_API}/confirm/{cid}", headers={
                "X-Portcullis-Proxy-Secret": SECRET, "X-Forwarded-User": "bob"})
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    code = resp.status
            except urllib.error.HTTPError as e:
                code = e.code
            print(f"    bob's identity on the Hub's /confirm/<id>: HTTP {code}", flush=True)
            assert code == 404, f"the Hub showed root's confirmation to bob: HTTP {code}"
            # root approves: the typed id, then a fresh passkey sign-in.
            goto(root, url)
            box = root.locator("#confirm")
            assert box.get_attribute("data-state") == "pending", box.get_attribute("data-state")
            assert ECHO_DEL in root.inner_text("body"), "the page doesn't name the instance"
            base.shot(root, "ai-confirm-page")
            root.fill("#cf-typed", ECHO_DEL)
            before = auths["root"].asserted
            with root.context.expect_page(timeout=30_000) as pinfo:
                root.click("#cf-approve")
            popup = pinfo.value
            copies = [dict(c, signCount=c.get("signCount", 0) + 1000) for c in auths["root"].credentials()]
            pauth = base.Authenticator(popup, credentials=copies)
            prompted = drive_popup(popup, "root-confirm")
            root.wait_for_selector('#confirm[data-state="approved"]', timeout=60_000)
            base.shot(root, "ai-confirm-approved")
            print(f"    approved: passkey prompts {prompted}, assertions popup {pauth.asserted} + page "
                  f"{auths['root'].asserted - before}", flush=True)
            assert pauth.asserted + auths["root"].asserted - before >= 1, "no fresh authenticator touch"
            # The retry runs the tool (the Hub answers 202: an accepted op).
            rc3, doc3 = mcp_call(HUB_MCP, tf, "tools/call", "delete_instance", args)
            assert rc3 == 0 and "result" in doc3, doc3
            res3 = doc3["result"]
            text3 = text_of(res3)
            print(f"    retry after the approval: isError {res3.get('isError')}: {text3[:200]}", flush=True)
            assert not res3.get("isError"), text3[:300]
            op = res3.get("structuredContent") or json.loads(text3)
            assert op.get("op_id") and op.get("instance") == ECHO_DEL and op.get("poll") == e2e_ops.op_url(ECHO_DEL, op["op_id"]), op
            # The approval was single use: once more = a new confirmation.
            err4, text4 = call_text(HUB_MCP, tf, "delete_instance", args)
            m4 = CONFIRM_RE.search(text4)
            print(f"    a second retry: isError {err4}: {text4[:160]}", flush=True)
            assert err4 and m4 and m4.group(0) != url, text4[:300]
            until("echo-del deleted (op record)", lambda: (lambda d: d.get("op_id") == op["op_id"] and not d.get("running")
                                                           and d)(hub_ok("GET", op["poll"])), 300, every=5)
            rec = hub_ok("GET", op["poll"])
            assert rec.get("ok") is True, f"delete op: {json.dumps(rec)[:400]}"

            def audited():
                es = json.loads(hub("GET", "/api/directory/audit?via=ai")[1])
                hit = [e for e in es if e.get("action") == "instance.delete" and e.get("target") == ECHO_DEL]
                return hit and hit[0]
            e = until("instance.delete audited via ai", audited, 60)
            print(f"    audit: {json.dumps({k: e.get(k) for k in ('actor', 'action', 'target', 'result', 'via', 'client', 'detail')})}",
                  flush=True)
            assert e.get("via") == "ai" and e.get("client") == CLIENT and e.get("actor") == "root" \
                and e.get("result") == "ok", e
            assert norm_id(cid) in norm_id(e.get("detail") or ""), f"the confirmation id {cid} isn't in the detail: {e.get('detail')!r}"
        check("destructive_confirmation: root's delete_instance on hub.<d>/mcp → the confirmation link (text); pending "
              "retry waits; bob can't open it (group-gate / Hub 404); root types the id + fresh passkey → approved; the "
              "retry is accepted (202 op); a second retry → a new confirmation; audit instance.delete via ai, client "
              "portcullis-ai-claude-code, confirmation id", destructive_confirmation)

        # ── 6 ──
        def aggregate_lists():
            ctf = mcp_login(carol, MCP_ALL, "carol-all")
            show("carol's aggregate token", ctf)

            def carol_names():
                n = tool_names(MCP_ALL, ctf)
                ok = any(x.startswith("gitea__") for x in n) and any(x.startswith("grafana__") for x in n)
                if not ok:
                    print(f"    carol's aggregate so far: {n[:12]}…", flush=True)
                return ok and n
            names = until("carol sees gitea__* and grafana__*", carol_names, 120, every=10)
            print(f"    carol: {len(names)} tools, e.g. {[x for x in names if '__' in x][:8]}", flush=True)
            assert "portcullis__my_apps" in names, [x for x in names if x.startswith("portcullis__")]
            assert not any(x.startswith("gitea-b__") for x in names), "carol isn't in gitea-b"
            # Grafana through the gate as carol (identity_headers: Hub
            # override, trust network, caller secret, Grafana's auth proxy).
            err, text = call_text(MCP_ALL, ctf, "grafana__search_dashboards", {"query": ""})
            print(f"    grafana__search_dashboards as carol: isError {err}: {text[:200]}", flush=True)
            assert not err, text[:400]
            act = hub_ok("GET", "/api/ai/activity?n=200")
            lines = [x for x in act.get("lines") or [] if x.get("user") == "carol" and x.get("instance") == "grafana"
                     and x.get("tool") == "search_dashboards"]
            assert any(x.get("decision") == "allow" and x.get("via") == "aggregate" and x.get("upstream_status") == 200
                       for x in lines), f"access log: {json.dumps(lines)[:600]}"
            # bob: gitea only.
            btf = mcp_login(bob, MCP_ALL, "bob-all")
            bn = until("bob sees gitea__*", lambda: (n := tool_names(MCP_ALL, btf)) and any(x.startswith("gitea__") for x in n) and n,
                       120, every=10)
            assert not any(x.startswith("grafana__") for x in bn), [x for x in bn if x.startswith("grafana__")]
            # root: no admin tool on the aggregate.
            rtf = mcp_login(root, MCP_ALL, "root-all")
            rn = tool_names(MCP_ALL, rtf)
            hub_tf = state.get("root_hub")
            if not hub_tf or time.time() - state.get("root_hub_at", 0) > TOKEN_FRESH_S:
                hub_tf = mcp_login(root, HUB_MCP, "root-hub")
            admin = set(tool_names(HUB_MCP, hub_tf))
            people = {x.removeprefix("portcullis__") for x in names if x.startswith("portcullis__")}
            leaked = sorted(x for x in rn if x.startswith("portcullis__") and x.removeprefix("portcullis__") in admin - people)
            print(f"    root's aggregate: {len(rn)} tools; admin-only tools {len(admin - people)}; leaked {leaked}", flush=True)
            assert "delete_instance" in admin and not leaked, leaked
            assert "portcullis__delete_instance" not in rn and "portcullis__my_apps" in rn, rn
        check("aggregate_lists: carol (gitea + grafana) sees gitea__* + grafana__* + portcullis__my_apps and runs "
              "grafana__search_dashboards through the gate (identity_headers, access log allow 200); bob (gitea) sees no "
              "grafana__*; root's aggregate has no admin tool", aggregate_lists)

        popups: dict = {"root": 1}

        def approve(page: Page, who: str, url: str, typed: str) -> None:
            """who opens the confirmation page, types the check and signs in
            again in the fresh-auth popup (its own virtual authenticator with
            a copy of who's credential, counter above every earlier copy)."""
            goto(page, url)
            assert page.locator("#confirm").get_attribute("data-state") == "pending"
            page.fill("#cf-typed", typed)
            n = popups[who] = popups.get(who, 0) + 1
            with page.context.expect_page(timeout=30_000) as pinfo:
                page.click("#cf-approve")
            popup = pinfo.value
            base.Authenticator(popup, credentials=[dict(c, signCount=c.get("signCount", 0) + 1000 * n)
                                                   for c in auths[who].credentials()])
            drive_popup(popup, f"{who}-confirm-{n}")
            page.wait_for_selector('#confirm[data-state="approved"]', timeout=60_000)
            base.shot(page, f"ai-{who}-approved-{n}")

        def labels() -> dict:
            code, out = gitea_api("gitea", "alice", "read:issue,read:repository", "GET", "/repos/alice/alice-private/labels")
            assert code == 200, f"labels: HTTP {code}: {out[:300]}"
            return {x["name"]: x["id"] for x in json.loads(out)}

        # ── 8 ──
        def companion_confirmation():
            tf = mcp_login(alice, GITEA_MCP, "alice-gitea-confirm")
            state["alice_gitea"], state["alice_gitea_at"] = tf, time.time()
            rc, doc = mcp_call(GITEA_MCP, tf)
            schema = next(t for t in doc["result"]["tools"] if t["name"] == "label_write")["inputSchema"]
            props = schema.get("properties") or {}
            assert {"method", "owner", "repo", "id"} <= set(props), f"label_write's schema: {json.dumps(schema)[:600]}"
            lid, keep = state["labels"]["ci-delete-me"], state["labels"]["ci-keep"]
            args = {"method": "delete_repo_label", "owner": "alice", "repo": "alice-private", "id": lid}
            canon = canonical(args)
            err, text = call_text(GITEA_MCP, tf, "label_write", args)
            print(f"    label_write delete_repo_label: isError {err}: {text[:200]}", flush=True)
            m = PEOPLE_CONFIRM_RE.search(text)
            assert err and m and text.startswith("This needs your confirmation in your browser: open "), text[:300]
            url = m.group(0)
            cid = url.rsplit("/", 1)[1]
            assert "ci-delete-me" in labels(), "the label went before the confirmation"
            # bob: people.<d> is open to him; the Hub answers another
            # person's confirmation with 404.
            r = bob.request.get(url)
            print(f"    bob opens alice's confirmation: HTTP {r.status}", flush=True)
            assert r.status == 404 and "label_write" not in r.text(), f"bob: HTTP {r.status}: {r.text()[:200]}"
            # alice: the page shows exactly the canonical arguments; the typed
            # check is the instance label (G75).
            goto(alice, url)
            box = alice.locator("#confirm")
            typed = box.get_attribute("data-typed")
            shown = (alice.locator("#cf-args").text_content() or "").strip()
            print(f"    page: typed check {typed!r}, arguments {shown}", flush=True)
            base.shot(alice, "ai-alice-companion-confirm")
            assert typed == "Gitea", f"typed check {typed!r} (want the instance label Gitea)"
            assert json.loads(shown) == args, f"shown arguments {shown!r} (canonical {canon!r})"
            approve(alice, "alice", url, typed)
            err2, text2 = call_text(GITEA_MCP, tf, "label_write", args)
            print(f"    retry after the approval: isError {err2}: {text2[:200]}", flush=True)
            assert not err2, text2[:400]
            now = labels()
            assert "ci-delete-me" not in now and now.get("ci-keep") == keep, f"alice-private's labels after: {now}"
            # Single use: the same call again needs a new confirmation.
            err3, text3 = call_text(GITEA_MCP, tf, "label_write", args)
            m3 = PEOPLE_CONFIRM_RE.search(text3)
            assert err3 and m3 and m3.group(0) != url, text3[:300]
            # A changed argument: a new confirmation, nothing deleted.
            args2 = dict(args, id=keep)
            err4, text4 = call_text(GITEA_MCP, tf, "label_write", args2)
            m4 = PEOPLE_CONFIRM_RE.search(text4)
            print(f"    changed argument: isError {err4}: {text4[:160]}", flush=True)
            assert err4 and m4 and m4.group(0) not in (url, m3.group(0)), text4[:300]
            assert labels().get("ci-keep") == keep, "ci-keep went without a confirmation"
            # The access log: the confirmation and the consuming call.
            digest = hashlib.sha256(canon.encode()).hexdigest()
            lines = [x for x in hub_ok("GET", "/api/ai/activity?n=200").get("lines") or []
                     if x.get("user") == "alice" and x.get("tool") == "label_write"]
            ran = [x for x in lines if x.get("decision") == "allow" and norm_id(x.get("confirmation_id") or "") == norm_id(cid)]
            print(f"    access log: {[(x.get('decision'), x.get('confirmation_id'), x.get('args_sha256', '')[:12]) for x in lines]}",
                  flush=True)
            assert len(ran) == 1 and ran[0].get("args_sha256") == digest and ran[0].get("upstream_status") == 200, \
                f"no single allow line with confirmation_id {cid} and args_sha256 {digest}: {json.dumps(lines)[:800]}"
            assert any(norm_id(x.get("decision") or "") == norm_id(f"confirm:{cid}") for x in lines), "no confirm:<id> line"
        check("companion_confirmation: alice's label_write delete_repo_label on gitea.<d>/mcp → people.<d>/confirm/<id> "
              "(typed check the instance label, the canonical arguments shown); bob 404; alice approves with a fresh "
              "passkey → the retry runs once (the label gone, the other kept); the same call again and a changed argument "
              "→ new confirmations; access log allow with confirmation_id and the canonical args_sha256", companion_confirmation)

        # ── 9 ──
        def url_elicitation_2026():
            def one_url_request(doc: dict, host_re) -> tuple[str, dict]:
                res = doc.get("result") or {}
                reqs = res.get("inputRequests") or {}
                # requestState is optional: the stateless Hub sends none (its
                # retry is matched by the arguments' digest), the gate its own.
                assert res.get("resultType") == "input_required" and len(reqs) == 1 and not res.get("content") \
                    and not res.get("isError"), \
                    f"not an input_required result: {json.dumps(doc)[:600]}"
                key, req = next(iter(reqs.items()))
                p = req.get("params") or {}
                assert req.get("method") == "elicitation/create" and p.get("mode") == "url" and host_re.fullmatch(p.get("url", "")) \
                    and p.get("elicitationId") and not p.get("requestedSchema"), f"input request: {json.dumps(req)[:400]}"
                return key, res
            # The Hub's D tool on hub.<d>/mcp.
            rtf = mcp_login(root, HUB_MCP, "root-hub-2026")
            state["root_hub"], state["root_hub_at"] = rtf, time.time()
            rc, doc = mcp_call(HUB_MCP, rtf, "tools/call", "delete_instance", {"id": ECHO_ELICIT},
                               protocol="2026-07-28", elicitation=True)
            print(f"    hub delete_instance (2026-07-28, url): protocol {doc.get('protocol')!r}: {json.dumps(doc.get('result'))[:300]}",
                  flush=True)
            assert rc == 0, doc
            key, res = one_url_request(doc, CONFIRM_RE)
            assert key == "portcullis_confirmation" and doc.get("elicitations") == [], (key, doc.get("elicitations"))
            # A companion's D tool through the gate.
            atf = state["alice_gitea"] if time.time() - state.get("alice_gitea_at", 0) < TOKEN_FRESH_S \
                else mcp_login(alice, GITEA_MCP, "alice-gitea-2026")
            args = {"method": "delete_repo_label", "owner": "alice", "repo": "alice-private", "id": 900001}
            rc, doc = mcp_call(GITEA_MCP, atf, "tools/call", "label_write", args, protocol="2026-07-28", elicitation=True)
            print(f"    gate label_write (2026-07-28, url): protocol {doc.get('protocol')!r}: {json.dumps(doc.get('result'))[:300]}",
                  flush=True)
            assert rc == 0, doc
            key, res = one_url_request(doc, PEOPLE_CONFIRM_RE)
            assert key == "portcullis_confirmation" and (res.get("requestState") or "").startswith("portcullis-gate:"), \
                (key, (res.get("requestState") or "")[:20])
            # 2025-11-25 session with URL elicitation: the gate sends
            # elicitation/create (mode url), then the text.
            args = dict(args, id=900002)
            rc, doc = mcp_call(GITEA_MCP, atf, "tools/call", "label_write", args, protocol="2025-11-25", elicitation=True)
            el = doc.get("elicitations") or []
            print(f"    gate label_write (2025-11-25, url): protocol {doc.get('protocol')!r}, elicitations "
                  f"{[(e.get('mode'), e.get('url')) for e in el]}, result {text_of(doc.get('result') or {})[:160]}", flush=True)
            assert rc == 0 and doc.get("protocol") == "2025-11-25", doc
            assert len(el) == 1 and el[0].get("mode") == "url" and PEOPLE_CONFIRM_RE.fullmatch(el[0].get("url", "")) \
                and el[0].get("elicitationId"), el
            text = text_of(doc["result"])
            assert doc["result"].get("isError") and el[0]["url"] in text, text[:300]
            # The Hub's MCP is stateless: on 2025-11-25 the text, never an
            # elicitation/create.
            rc, doc = mcp_call(HUB_MCP, rtf, "tools/call", "delete_instance", {"id": ECHO_ELICIT},
                               protocol="2025-11-25", elicitation=True)
            print(f"    hub delete_instance (2025-11-25, url): elicitations {doc.get('elicitations')}, "
                  f"{text_of(doc.get('result') or {})[:160]}", flush=True)
            assert rc == 0 and doc.get("elicitations") == [] and (doc.get("result") or {}).get("isError"), doc
        check("url_elicitation_2026: with URL elicitation declared on 2026-07-28 the Hub's delete_instance and the gate's "
              "label_write answer input_required with one url elicitation (hub.<d> / people.<d> /confirm/<id>, no content); "
              "on 2025-11-25 the gate sends elicitation/create mode url then the text, the stateless Hub the text only",
              url_elicitation_2026)

        # ── 2 (alice leaves) ──
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

        # ── 10: T25 carry ──
        def gitea_isolation():
            def nets(cid: str) -> dict:
                return json.loads(docker("inspect", "-f", "{{json .NetworkSettings.Networks}}", cid))

            def resolve(network: str, name: str) -> str:
                p = subprocess.run(["docker", "run", "--rm", "--network", network, ALPINE, "getent", "hosts", name],
                                   capture_output=True, text=True, timeout=120)
                return p.stdout.split()[0] if p.returncode == 0 and p.stdout.strip() else ""
            assert ALPINE, "ALPINE (pinned image) not set"
            seen = {}
            for inst in ("gitea", "gitea-b"):
                g, mcp = container(inst, "gitea"), container(inst, "gitea-mcp")
                gn, mn = nets(g), nets(mcp)
                default = f"portcullis-{inst}_default"
                assert "gitea-internal" in (gn[default].get("Aliases") or []), gn[default]
                assert "gitea-internal" not in (gn["portcullis-proxy"].get("Aliases") or []) + (gn["portcullis-proxy"].get("DNSNames") or []), \
                    gn["portcullis-proxy"]
                alias = f"portcullis-mcp-{inst}--gitea"
                assert alias in (mn["portcullis-proxy"].get("Aliases") or []), mn.get("portcullis-proxy")
                # Resolution, as the peers see it.
                internal = resolve(default, "gitea-internal")
                assert internal == gn[default]["IPAddress"], f"{inst}: gitea-internal → {internal}, gitea is {gn[default]['IPAddress']}"
                comp = resolve("portcullis-proxy", alias)
                assert comp == mn["portcullis-proxy"]["IPAddress"], f"{alias} → {comp}, the companion is {mn['portcullis-proxy']['IPAddress']}"
                seen[inst] = (internal, comp)
            assert resolve("portcullis-proxy", "gitea-internal") == "", "gitea-internal resolves on portcullis-proxy"
            assert seen["gitea"][1] != seen["gitea-b"][1], seen
            print(f"    gitea-internal / companion alias per instance: {seen}", flush=True)
            # No hook-local token is ever left behind (every mint and revoke
            # deletes its own portcullis-hook-* token).
            for inst in ("gitea", "gitea-b"):
                n = docker("exec", container(inst, "gitea-db"), "psql", "-X", "-U", "gitea", "-d", "gitea", "-tAc",
                           "SELECT count(*) FROM access_token WHERE name LIKE 'portcullis-hook-%'").strip()
                assert n == "0", f"{inst}: {n} portcullis-hook-* tokens left"
            # Switch-on's revoke_all exited 0: the switch-on is committed only
            # after it (a failure is a 502 with nothing saved), so the ai op
            # record is ok and ai.enable audited ok.
            for inst in ("gitea", "gitea-b"):
                op = state["ai_ops"][inst]
                assert op.get("op") == "ai" and op.get("ok") is True, f"{inst}'s op record after the switch-on: {json.dumps(op)[:300]}"
                hits = [e for e in state["ai_audit"] if (e.get("target") or "").split("/")[0] == inst]
                assert any(e.get("result") == "ok" and "read_write" in (e.get("detail") or "") for e in hits), hits
            print(f"    switch-on: op records {[(i, o.get('op'), o.get('ok')) for i, o in state['ai_ops'].items()]}, "
                  f"ai.enable {[(e.get('target'), e.get('result'), e.get('detail')) for e in state['ai_audit']]}", flush=True)
        # ── final review I4: the DNS-shadow guard on AI companion names ──
        def companion_alias_guard():
            def shadows() -> list:
                p = subprocess.run(["./portcullis", "status", "--json"], capture_output=True, text=True, timeout=300)
                return json.loads(p.stdout)["dns_shadows"]
            got = shadows()
            assert got == [], f"the real companions are flagged: {got}"
            alias = "portcullis-mcp-gitea--gitea"
            rogue = docker("run", "-d", "--rm", "--network", "portcullis-proxy", "--network-alias", alias, ALPINE, "sleep", "300").strip()
            try:
                got = shadows()
            finally:
                docker("rm", "-f", rogue, check_rc=False)
            assert any(h.get("name", "").startswith(alias + " (AI companion name outside project portcullis-gitea)") for h in got), got
            assert any(h.get("name", "").startswith(alias + " (AI companion name answered by more than one container)") for h in got), got
            assert shadows() == [], "still flagged once the rogue container is gone"
            print(f"    rogue alias flagged: {got}", flush=True)
        check("companion_alias_guard (final review I4): status lists no shadow for the real companions; a container "
              "outside the instance's project answering to portcullis-mcp-gitea--gitea is flagged (and the real one as shared)",
              companion_alias_guard)

        check("gitea_isolation (T25 carry): gitea-internal only on each project's default network and resolving to its own "
              "Gitea; portcullis-mcp-<id>--gitea resolving to that instance's companion only; no portcullis-hook-* token "
              "left; switch-on's revoke_all succeeded (ai op ok, ai.enable ok)", gitea_isolation)

        # ── 7 (last) ──
        def ai_off():
            hub_ok("PUT", "/api/ai/settings", {"enabled": False})
            init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "ci", "version": "1"}}}).encode()
            urls = (GITEA_MCP, GITEA_B_MCP, GRAFANA_MCP, MCP_ALL, HUB_MCP, PEOPLE_MCP)

            def all_off():
                got = {u: https("POST", u, {"Content-Type": "application/json",
                                            "Accept": "application/json, text/event-stream"}, init)[:3:2] for u in urls}
                print(f"    {[(u, c) for u, (c, _) in got.items()]}", flush=True)
                return all(c == 503 and "AI support is off" in b for c, b in got.values()) and got
            until("every MCP resource 503", all_off, 120, every=5)
            tf = state.get("root_hub")
            if tf:
                rc, doc = mcp_call(HUB_MCP, tf)
                print(f"    root's admin token: {doc}", flush=True)
                assert rc == 2 and doc.get("http_status") in (401, 503), doc
        check("ai_off: master switch off → every MCP resource (gitea, gitea-b, grafana, mcp, hub, people) answers 503 "
              "\"AI support is off\"", ai_off)

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
