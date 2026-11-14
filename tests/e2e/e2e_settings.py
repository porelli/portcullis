#!/usr/bin/env python3
"""End-to-end: the app settings panel's deliveries on a real stack.

Runs in CI (job `e2e-settings` in .github/workflows/ci.yml) against the
whole core stack and the Hub (built from the same-named Hub branch), with
one template source holding the templates repo's immich, grafana,
nextcloud and firefox-sync (same-named templates branch) and the CI
fixtures tests/e2e/apps/settings-echo (header) and settings-file (data
file + hook). The workflow enabled every instance, created the users and
groups and saved the starting settings through the Hub's API:

  alice  users_immich office_milan users_grafana users_settings-echo
         users_firefox-sync
  bob    users_immich admin_immich users_grafana admin_grafana
         users_settings-echo users_firefox-sync
  carol  users_settings-file office_milan
  dave   (no group)

  immich         storage_quota default 100GiB, office_milan 10GiB
                 (claim immich_quota); role: admin_immich = admin
                 (claim immich_role, the template's {{ADMIN_GROUP}} row)
  grafana        role: admin_grafana = Admin (header
                 X-Forwarded-Attr-Grafana-Role, the template's row)
  settings-echo  tier default bronze, office_milan gold (header
                 X-Forwarded-Attr-Tier)
  settings-file  seats default 1, office_milan 5 (people.json, restart);
                 level default basic, office_milan plus (hook log)
  nextcloud      default_quota (template default 10GiB, start hook)
  firefox-sync   mozilla_uid person-entered (allowlist.json, restart)

Scenarios (contract §13):
  claims        Immich /api/users/me after an OIDC sign-in:
                quotaSizeInBytes 10 GiB for alice (office_milan), the UI
                shows 10 GiB; bob (admin_immich) isAdmin.
  headers       Grafana: bob's org role is Admin on his first and later
                requests, alice's Viewer once the Hub published her
                Viewer header (Viewer is also Grafana's auto-assign
                default, so the header is checked first); settings-echo echoes
                X-Forwarded-Attr-Tier (gold / bronze) and never another
                host's header.
  file_hook     settings-file's people.json lists only the population
                (carol, seats 5 from office_milan); the hook sees her
                level plus.
  people        carol's My apps lists only her app, no other username;
                /api/instances/immich/settings on people.<domain> is 404.
  entries       alice enters her Mozilla uid on people.<domain>; bob's
                same uid is 409 without alice's name; carol (no access)
                404; after the debounce allowlist.json in
                firefox-sync-init lists it, the init ran once and
                guard.sql (real Postgres) lets that uid in and refuses an
                outsider.
  membership    one batch through the Hub: alice leaves office_milan and
                joins admin_immich, bob leaves admin_grafana, alice, bob
                and dave join users_settings-file. Within the debounce
                plus slack: alice's next Immich sign-in has 100 GiB and
                isAdmin (role changed on an existing account), her tier is
                bronze, bob is a Grafana Viewer, people.json lists four
                people (carol, still in office_milan, seats 5; the rest
                1) and settings-file restarted exactly once, the hook
                got the full state with trigger membership_change (carol
                plus, the rest basic).
  entries_leave alice leaves users_firefox-sync: allowlist.json no longer
                lists her, the init ran once, her rows are gone and no
                account can sync (empty allowlist = nobody); she rejoins:
                listed again and syncs.
  fields        a custom field with '_' (cost_center; LLDAP attribute
                cost-center, LLDAP refuses '_') created and set on alice
                through the Hub: the overview shows it, rule group cc_42
                (cost_center = "CC-42") gets alice, settings-echo gets
                X-Forwarded-Attr-Cost-Center, Keycloak's example access
                token for alice on Immich's client has attr_cost_center.
  nextcloud     the first install applied default_quota through the
                start hook (occ: files default_quota = "10 GB").

Environment: E2E_DOMAIN, E2E_ALICE_INVITE, E2E_BOB_INVITE, E2E_CAROL_INVITE
(setup links, --to portal), HUB_IP, KEYCLOAK_ADMIN(_PASSWORD), E2E_HUB_SECRET (the proxy secret; for
the Hub's admin API, as Traefik calls it), E2E_ARTIFACTS. Chromium trusts
core's CA (NSS db), Node too (NODE_EXTRA_CA_CERTS).
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tarfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

from playwright.sync_api import Page, sync_playwright

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_login as base  # noqa: E402  (Authenticator, passkey_flow, shot)

DOMAIN = os.environ["E2E_DOMAIN"]
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
HUB_API = f"http://{os.environ['HUB_IP']}:8888"
SECRET = os.environ["E2E_HUB_SECRET"]
TIMEOUT_MS = 30_000
PORTAL = f"https://{DOMAIN}/"
PEOPLE = f"https://people.{DOMAIN}"
PHOTOS_HOST = f"photos.{DOMAIN}"
PHOTOS = f"https://{PHOTOS_HOST}"
GRAFANA = f"https://grafana.{DOMAIN}"
ECHO = f"https://settings-echo.{DOMAIN}"
SYNC_HOST = f"firefox-sync.{DOMAIN}"
KC_LOCAL = "http://127.0.0.1:8080"
GIB = 1 << 30
# Membership deliveries are debounced 60 s per instance (contract §13.13);
# the slack covers the directory sync, Keycloak and a restart.
DELIVERY_S = 60 + 120
# "Exactly one restart" is counted after one more debounce window plus
# slack, so a second delivery a window later would be seen.
RESTART_QUIET_S = 75
ALICE_UID = "0123456789abcdef0123456789abcdef"
OUTSIDER_UID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

results: list[tuple[str, bool, str]] = []
state: dict = {}


def check(name: str, fn) -> None:
    try:
        fn()
        results.append((name, True, ""))
        print(f"PASS: {name}", flush=True)
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"{type(e).__name__}: {e}"))
        print(f"FAIL: {name}: {e}", flush=True)
        traceback.print_exc()


def until(what: str, fn, seconds: float, every: float = 5):
    """Polls fn until it returns a truthy value (returned) or the deadline
    passes (AssertionError with fn's last value or error)."""
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

def hub(method: str, path: str, body=None, timeout: float = 120) -> tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(HUB_API + path, data=data, method=method, headers={
        "X-Portcullis-Proxy-Secret": SECRET, "X-Forwarded-User": "admin",
        "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def member(op: str, group: str, user: str) -> None:
    if op == "add":
        code, out = hub("POST", f"/api/directory/groups/{group}/members", {"username": user})
    else:
        code, out = hub("DELETE", f"/api/directory/groups/{group}/members/{user}", {})
    assert code == 200, f"{op} {user} {group}: HTTP {code}: {out[:300]}"


# ── docker ──

def docker(*args: str, check_rc: bool = True) -> str:
    p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=120)
    if check_rc and p.returncode != 0:
        raise AssertionError(f"docker {' '.join(args[:3])}…: rc {p.returncode}: {p.stderr.strip()[:400]}")
    return p.stdout


def container(project: str, service: str) -> str:
    ids = docker("ps", "-aq", "--filter", f"label=com.docker.compose.project=portcullis-{project}",
                 "--filter", f"label=com.docker.compose.service={service}").split()
    assert len(ids) == 1, f"{project}/{service}: containers {ids}"
    return ids[0]


class StartLog:
    """Every container start, recorded live from `docker events` (the
    daemon replays only a short in-memory buffer for --since: a project's
    down/up elsewhere pushes older starts out of it)."""

    def __init__(self):
        self.events: list[tuple[float, str, str]] = []
        self.lock = threading.Lock()
        fmt = ('{{.TimeNano}} {{index .Actor.Attributes "com.docker.compose.project"}} '
               '{{index .Actor.Attributes "com.docker.compose.service"}}')
        self.proc = subprocess.Popen(["docker", "events", "--filter", "type=container", "--filter", "event=start",
                                      "--format", fmt], stdout=subprocess.PIPE, text=True)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        for line in self.proc.stdout:
            parts = line.split()
            if len(parts) == 3:
                with self.lock:
                    self.events.append((int(parts[0]) / 1e9, parts[1], parts[2]))

    def count(self, project: str, service: str, since: float) -> int:
        assert self.proc.poll() is None, f"docker events exited ({self.proc.returncode})"
        with self.lock:
            return sum(1 for t, p, sv in self.events if t >= since and p == f"portcullis-{project}" and sv == service)


START_LOG: StartLog | None = None


def starts(project: str, service: str, since: float) -> int:
    """Container starts of project/service since the unix time `since`."""
    assert START_LOG is not None
    return START_LOG.count(project, service, since)


def cp_out(cid: str, path: str) -> str:
    """A file from a container (running or not: docker cp mounts its
    volumes and binds), as text."""
    p = subprocess.run(["docker", "cp", f"{cid}:{path}", "-"], capture_output=True, timeout=60)
    assert p.returncode == 0, f"docker cp {path}: {p.stderr.decode()[:300]}"
    with tarfile.open(fileobj=io.BytesIO(p.stdout)) as t:
        m = t.getmembers()[0]
        return t.extractfile(m).read().decode()


def people_json() -> dict:
    return json.loads(docker("exec", container("settings-file", "app"), "cat", "/portcullis/people.json"))


def hook_inputs() -> list[dict]:
    cid = container("settings-file", "app")
    names = docker("exec", cid, "sh", "-c", "ls /log | grep '^hook-[0-9]*\\.json$' || true").split()
    return [json.loads(docker("exec", cid, "cat", f"/log/{n}")) for n in sorted(names)]


def host_header(host: str, suffix: str, user: str):
    """The value the Hub published for user under host's header suffix in
    user-attributes.json (contract §4.1 v2 hosts), or None."""
    doc = json.loads(docker("run", "--rm", "-v", "portcullis_hub_data:/d:ro", os.environ["ALPINE"],
                            "cat", "/d/user-attributes.json"))
    return ((doc.get("hosts") or {}).get(host) or {}).get(suffix, {}).get(user)


def allowlist() -> dict:
    return json.loads(cp_out(container("firefox-sync", "firefox-sync-init"), "/portcullis/allowlist.json"))


def entry_users(doc: dict) -> dict:
    return {e["user"]: e["value"] for e in (doc.get("entries") or {}).get("mozilla_uid") or []}


def psql(role: str, sql: str) -> tuple[int, str]:
    p = subprocess.run(["docker", "exec", container("firefox-sync", "firefox-sync-db"), "psql", "-X",
                        "-U", role, "-d", "firefoxsync", "-tAc", sql], capture_output=True, text=True, timeout=60)
    return p.returncode, (p.stdout + p.stderr).strip()


def sync_insert(uid: str) -> tuple[int, str]:
    """A users row as the tokenserver's post_user writes it, as the public
    server's own role (firefoxsync_app): what a Firefox sign-in does."""
    return psql("firefoxsync_app",
                "INSERT INTO users (service, email, generation, client_state, created_at, nodeid) "
                f"SELECT s.id, '{uid}@api.accounts.firefox.com', 1, 'aaaa', 1, n.id FROM services s "
                f"JOIN nodes n ON n.service = s.id WHERE s.service = 'sync-1.5' AND n.node = 'https://{SYNC_HOST}' "
                "RETURNING uid")


def allowed_db() -> list[str]:
    rc, out = psql("firefoxsync", "SELECT uid FROM sync_allowed_accounts ORDER BY uid")
    assert rc == 0, out
    return out.split()


# ── browser ──

def headers_of(body: str) -> dict:
    seen: dict = {}
    for line in body.splitlines():
        name, _, value = line.partition(": ")
        seen.setdefault(name.strip().lower(), []).append(value.strip())
    return seen


def kc_prompt(page: Page) -> bool:
    """Keycloak (or the setup page) waits for the person: a sign-in prompt,
    not the silent SSO redirect of a live session."""
    if not base.on_login_pages(page):
        return False
    for sel in ("#authenticateWebAuthnButton", "#registerWebAuthn", "#invite-continue", "input[type=password]"):
        loc = page.locator(sel)
        if loc.count() and loc.first.is_visible():
            return True
    return False


def settle(page: Page, url: str, *, seconds: int = 60, allow_resign: bool = False) -> int:
    """Open url and follow the sign-in redirects until the browser rests on
    url's host (not on a login page); returns the final HTTP status. A
    Keycloak prompt (the session ended) fails, unless allow_resign: then the
    person signs in again with their key."""
    page.goto(url, wait_until="domcontentloaded")
    deadline = time.time() + seconds
    while time.time() < deadline:
        page.wait_for_load_state("domcontentloaded")
        if page.url.startswith(url) and not base.on_login_pages(page):
            resp = page.reload(wait_until="domcontentloaded")
            return resp.status if resp else 0
        if kc_prompt(page):
            if not allow_resign:
                base.shot(page, "unexpected-sign-in-prompt")
                raise AssertionError(f"{url}: Keycloak asked to sign in again (session ended) at {page.url[:200]}")
            base.passkey_flow(page, until=url, label="resign", expect_stepups=0)
            continue
        page.wait_for_timeout(500)
    raise AssertionError(f"{url}: never settled (at {page.url})")


def signed_out(page: Page, url: str) -> bool:
    """True when opening url ends on a Keycloak sign-in prompt (the
    person's session is gone); False when it lands on the app."""
    page.goto(url, wait_until="domcontentloaded")
    deadline = time.time() + 30
    while time.time() < deadline:
        page.wait_for_load_state("domcontentloaded")
        if kc_prompt(page):
            return True
        if page.url.startswith(url) and not base.on_login_pages(page):
            return False
        page.wait_for_timeout(500)
    raise AssertionError(f"{url}: neither the app nor a sign-in prompt (at {page.url})")


def echo_headers(page: Page, allow_resign: bool = False) -> dict:
    code = settle(page, ECHO + "/", allow_resign=allow_resign)
    body = page.inner_text("body")
    assert code == 200 and "Hostname" in body, f"settings-echo: HTTP {code}: {body[:300]}"
    return headers_of(body)


def immich_sign_in(page: Page, label: str, *, allow_resign: bool = False, prompted: list | None = None) -> dict:
    """A fresh Immich OIDC sign-in (Immich's cookies dropped; through the
    Keycloak session, so no prompt): returns /api/users/me. A Keycloak
    prompt fails unless allow_resign (then the passkey signs in, and True is
    appended to `prompted`)."""
    page.context.clear_cookies(domain=PHOTOS_HOST)
    page.goto(PHOTOS + "/auth/login", wait_until="domcontentloaded")
    deadline = time.time() + 90
    while time.time() < deadline:
        page.wait_for_timeout(1000)
        if kc_prompt(page):
            if not allow_resign:
                base.shot(page, f"immich-{label}-unexpected-prompt")
                raise AssertionError(f"Immich sign-in: Keycloak asked {label} to sign in again (session ended)")
            if prompted is not None:
                prompted.append(True)
            base.passkey_flow(page, until=PHOTOS, label=f"immich-{label}", expect_stepups=0)
            continue
        if base.on_login_pages(page):
            continue
        sso = page.locator("button:has-text('Login with SSO')")
        if page.url.startswith(PHOTOS + "/auth/login") and sso.count() and sso.first.is_visible():
            sso.first.click()
            continue
        r = page.request.get(PHOTOS + "/api/users/me")
        if r.status == 200:
            return r.json()
    base.shot(page, f"immich-{label}-stuck")
    raise AssertionError(f"Immich sign-in did not complete (at {page.url})")


def grafana_role(page: Page) -> str:
    r = page.request.get(GRAFANA + "/api/user/orgs")
    assert r.status == 200, f"/api/user/orgs: HTTP {r.status}: {r.text()[:200]}"
    orgs = r.json()
    assert len(orgs) == 1, orgs
    return orgs[0]["role"]


def kc_admin(path: str):
    """GET on Keycloak's admin API (127.0.0.1:8080, the core publish) as the
    master admin; the password goes in the request body, from the env."""
    form = urllib.parse.urlencode({"client_id": "admin-cli", "grant_type": "password",
                                   "username": os.environ.get("KEYCLOAK_ADMIN", "admin"),
                                   "password": os.environ["KEYCLOAK_ADMIN_PASSWORD"]}).encode()
    with urllib.request.urlopen(urllib.request.Request(
            KC_LOCAL + "/realms/master/protocol/openid-connect/token", data=form), timeout=30) as r:
        tok = json.loads(r.read())["access_token"]
    req = urllib.request.Request(KC_LOCAL + "/admin/realms/portcullis" + path, headers={"Authorization": "Bearer " + tok})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def overview_user(name: str) -> dict:
    code, out = hub("GET", "/api/directory")
    assert code == 200, f"GET /api/directory: HTTP {code}: {out[:300]}"
    return next(u for u in json.loads(out)["users"] if u["username"] == name)


def put_uid(page: Page, uid: str):
    return page.request.put(PEOPLE + "/api/me/apps/firefox-sync/values/mozilla_uid",
                            data=json.dumps({"value": uid}), headers={"Content-Type": "application/json"})


def main() -> int:
    global START_LOG
    START_LOG = StartLog()
    time.sleep(1)
    with sync_playwright() as pw_:
        browser = pw_.chromium.launch(args=["--disable-features=WebAuthenticationConditionalUI"])
        ctxs = {}

        def sign_in(who: str) -> Page:
            ctx = browser.new_context()
            ctx.set_default_timeout(TIMEOUT_MS)
            ctxs[who] = ctx
            page = ctx.new_page()
            base.Authenticator(page)
            base.setup_link_signin(page, os.environ[f"E2E_{who.upper()}_INVITE"], who=who,
                                   mint=lambda: base.mint_setup_link(who, "portal"),
                                   until=PORTAL, label=f"set-{who}", expect_stepups=1)
            # Traced from here: the (consumed) setup link stays out of the trace.
            ctx.tracing.start(screenshots=True, snapshots=True, name=who)
            assert f"Signed in as <strong>{who}</strong>" in page.content(), page.content()[:300]
            return page

        pages: dict[str, Page] = {}

        def signs_in():
            for who in ("alice", "bob", "carol"):
                pages[who] = sign_in(who)
        check("alice, bob and carol: setup link → passkey → portal", signs_in)
        if len(pages) != 3:
            return report()
        alice, bob, carol = pages["alice"], pages["bob"], pages["carol"]

        # ── claims (Immich) ──
        def claims_alice():
            me = until("alice's Immich quota 10 GiB",
                       lambda: (m := immich_sign_in(alice, "alice")).get("quotaSizeInBytes") == 10 * GIB and m,
                       DELIVERY_S, every=10)
            assert me.get("isAdmin") is False, f"alice isAdmin: {me}"
            print(f"    alice: quotaSizeInBytes {me['quotaSizeInBytes']}, isAdmin {me['isAdmin']}", flush=True)
        check("claims: alice (office_milan) signs in to Immich: quotaSizeInBytes == 10737418240, not admin", claims_alice)

        def claims_ui():
            alice.goto(PHOTOS + "/photos", wait_until="domcontentloaded")
            alice.get_by_text(re.compile(r"\b10 GiB\b")).first.wait_for(state="visible", timeout=30_000)
            base.shot(alice, "set-immich-alice-quota")
        check("claims: Immich's UI shows alice's 10 GiB quota", claims_ui)

        def claims_bob():
            me = until("bob's Immich isAdmin", lambda: (m := immich_sign_in(bob, "bob")).get("isAdmin") is True and m,
                       DELIVERY_S, every=10)
            assert me.get("quotaSizeInBytes") == 100 * GIB, f"bob's quota (default): {me}"
        check("claims: bob (admin_immich) is an Immich admin (immich_role admin), quota the 100 GiB default", claims_bob)

        # ── headers (Grafana, settings-echo) ──
        def grafana_bob():
            # The header delivery is debounced (60 s) after the workflow's
            # memberships: his FIRST Grafana request waits until the Hub has
            # published his Role header for Grafana's host (§4.1 hosts).
            until("bob's Grafana-Role header published",
                  lambda: host_header(f"grafana.{DOMAIN}", "Grafana-Role", "bob") == "Admin", DELIVERY_S)
            code = settle(bob, GRAFANA + "/")
            assert code == 200, f"grafana: HTTP {code}"
            first = grafana_role(bob)
            settle(bob, GRAFANA + "/")
            later = grafana_role(bob)
            assert (first, later) == ("Admin", "Admin"), f"bob's org role: first {first}, later {later}"
            u = bob.request.get(GRAFANA + "/api/user").json()
            assert u.get("login") == "bob", u
        check("headers: bob (admin_grafana) is a Grafana org Admin on his first and later requests", grafana_bob)

        def grafana_alice():
            # Viewer is also Grafana's auto-assign role: only a published
            # Viewer header makes her Viewer the delivery's.
            until("alice's Grafana-Role header published",
                  lambda: host_header(f"grafana.{DOMAIN}", "Grafana-Role", "alice") == "Viewer", DELIVERY_S)
            assert settle(alice, GRAFANA + "/") == 200
            assert grafana_role(alice) == "Viewer"
        check("headers: alice (users_grafana only) is a Grafana Viewer (the default, header published)", grafana_alice)

        def echo_tiers():
            ha = until("alice's tier gold", lambda: (h := echo_headers(alice)).get("x-forwarded-attr-tier") == ["gold"] and h,
                       DELIVERY_S, every=10)
            assert ha.get("x-forwarded-user") == ["alice"], ha
            assert "x-forwarded-attr-grafana-role" not in ha, f"grafana's header on another host: {ha}"
            hb = echo_headers(bob)
            assert hb.get("x-forwarded-attr-tier") == ["bronze"], hb
            assert "x-forwarded-attr-grafana-role" not in hb, f"grafana's header on another host: {hb}"
        check("headers: settings-echo gets X-Forwarded-Attr-Tier gold (alice, office_milan) / bronze (bob), "
              "never Grafana's header", echo_tiers)

        # ── data file (settings-file) ──
        def file_population():
            doc = until("people.json = carol only", lambda: (d := people_json()).get("people", {}).keys() == {"carol"} and d,
                        DELIVERY_S)
            assert doc.get("instance") == "settings-file" and doc.get("version") == 1, doc
            assert str(doc["people"]["carol"].get("seats")) == "5", doc
            hooks = until("a hook run with carol at level plus",
                          lambda: [h for h in hook_inputs() if (h.get("people") or {}).keys() == {"carol"}
                                   and h["people"]["carol"].get("level") == "plus"], DELIVERY_S)
            assert hooks[-1].get("instance") == "settings-file", hooks[-1]
        check("file_hook: people.json in the container lists only the population (carol, seats 5 from office_milan); "
              "the hook sees her level plus", file_population)

        # ── person-entered values (firefox-sync, people.<domain>) ──
        def entries_put():
            assert settle(alice, PEOPLE + "/") == 200
            t0 = time.time()
            r = put_uid(alice, ALICE_UID)
            assert r.status == 200, f"alice PUT: HTTP {r.status}: {r.text()[:300]}"
            state["entry_t0"] = t0
            assert settle(bob, PEOPLE + "/") == 200
            r = put_uid(bob, ALICE_UID)
            body = r.text()
            assert r.status == 409, f"bob PUT the same uid: HTTP {r.status}: {body[:300]}"
            assert "alice" not in body.lower(), f"the 409 names the holder: {body[:300]}"
            assert settle(carol, PEOPLE + "/") == 200
            r = put_uid(carol, "fedcba9876543210fedcba9876543210")
            assert r.status == 404, f"carol (no access) PUT: HTTP {r.status}: {r.text()[:300]}"
        check("entries: alice enters her uid on people.<domain> (200); bob's same uid 409 without alice's name; "
              "carol (not in users_firefox-sync) 404", entries_put)

        def entries_delivered():
            assert "entry_t0" in state, "needs alice's entry"
            doc = until("allowlist.json lists alice", lambda: entry_users(d := allowlist()) == {"alice": ALICE_UID} and d,
                        DELIVERY_S)
            assert doc.get("instance") == "firefox-sync", doc
            until("sync_allowed_accounts has alice's uid", lambda: allowed_db() == [ALICE_UID], 60)
            until("firefox-sync-init ran", lambda: starts("firefox-sync", "firefox-sync-init", state["entry_t0"]) >= 1, 120)
            time.sleep(RESTART_QUIET_S)
            n = starts("firefox-sync", "firefox-sync-init", state["entry_t0"])
            assert n == 1, f"firefox-sync-init started {n} times since the entry (want 1)"
            rc, out = sync_insert(ALICE_UID)
            assert rc == 0 and re.match(r"^\d+", out), f"alice's uid refused: {out}"
            rc, out = sync_insert(OUTSIDER_UID)
            assert rc != 0 and f"Firefox account {OUTSIDER_UID} is not on the allowlist" in out, \
                f"an unlisted uid got a tokenserver row: {out}"
        check("entries: after the debounce allowlist.json in firefox-sync-init lists alice's uid, the init ran once; "
              "guard.sql (Postgres) lets it sync and refuses an unlisted account", entries_delivered)

        # ── membership change: one batch through the Hub ──
        def membership_batch():
            state["batch_t0"] = time.time()
            member("remove", "office_milan", "alice")
            member("add", "admin_immich", "alice")
            member("remove", "admin_grafana", "bob")
            for u in ("alice", "bob", "dave"):
                member("add", "users_settings-file", u)
        check("membership: alice leaves office_milan and joins admin_immich, bob leaves admin_grafana, "
              "alice, bob and dave join users_settings-file (Hub API)", membership_batch)
        batched = "batch_t0" in state

        def after_batch_immich():
            assert batched, "needs the batch"
            # Removing alice from office_milan signed her out of Keycloak
            # (contract §9.6): her first sign-in after the batch must prompt
            # for her key; later ones go through the new session silently.
            prompted: list = []
            first = immich_sign_in(alice, "alice-2", allow_resign=True, prompted=prompted)
            assert prompted, "alice's Keycloak session survived her removal from office_milan (no sign-in prompt)"
            me = first if first.get("quotaSizeInBytes") == 100 * GIB else until(
                "alice's next sign-in: 100 GiB",
                lambda: (m := immich_sign_in(alice, "alice-3")).get("quotaSizeInBytes") == 100 * GIB and m,
                DELIVERY_S, every=15)
            took = time.time() - state["batch_t0"]
            print(f"    alice after the batch: {took:.0f} s", flush=True)
            # Debounce 60 s + the evaluator interval (60 s, cmd/hub) + slack.
            assert took <= 60 + 60 + 30, f"alice's 100 GiB took {took:.0f} s (want <= 150 s)"
            assert me.get("isAdmin") is True, f"alice's role did not change on her existing account: {me}"
        check("membership: alice's session ended (§9.6 logout); her next Immich sign-in has the 100 GiB default "
              "within 60 s + the evaluator interval + slack, and isAdmin (role changed on an existing account)",
              after_batch_immich)

        def after_batch_headers():
            assert batched, "needs the batch"
            until("alice's tier bronze", lambda: echo_headers(alice).get("x-forwarded-attr-tier") == ["bronze"],
                  DELIVERY_S, every=10)
            # Removing bob from admin_grafana signed him out (contract §9.6):
            # within oauth2-proxy's 1 min refresh his next request prompts.
            until("bob's session ended", lambda: signed_out(bob, GRAFANA + "/"), 150, every=10)
            base.shot(bob, "set-bob-signed-out")
            assert settle(bob, GRAFANA + "/", allow_resign=True) == 200
            until("bob a Grafana Viewer", lambda: settle(bob, GRAFANA + "/") == 200 and grafana_role(bob) == "Viewer",
                  DELIVERY_S, every=10)
        check("membership: alice's next request has tier bronze; bob's session ended (§9.6 logout), "
              "signed in again he is a Grafana Viewer",
              after_batch_headers)

        def after_batch_file():
            assert batched, "needs the batch"
            want = {"alice", "bob", "carol", "dave"}
            doc = until("people.json = 4 people", lambda: (d := people_json()).get("people", {}).keys() == want and d,
                        DELIVERY_S)
            seats = {u: str(p.get("seats")) for u, p in doc["people"].items()}
            assert seats == {"alice": "1", "bob": "1", "carol": "5", "dave": "1"}, doc
            hooks = until("a membership_change hook run with 4 people",
                          lambda: [h for h in hook_inputs() if h.get("trigger") == "membership_change"
                                   and (h.get("people") or {}).keys() == want], 60)
            h = hooks[-1]
            assert h.get("instance") == "settings-file" and h.get("version") == 1, h
            assert {u: p.get("level") for u, p in h["people"].items()} == \
                {"alice": "basic", "bob": "basic", "carol": "plus", "dave": "basic"}, h["people"]
            until("settings-file restarted", lambda: starts("settings-file", "app", state["batch_t0"]) >= 1, 120)
            time.sleep(RESTART_QUIET_S)
            n = starts("settings-file", "app", state["batch_t0"])
            assert n == 1, f"settings-file's app started {n} times after 3 joins in one window (want 1)"
        check("file_hook: after the joins people.json lists the 4 people (carol seats 5, alice left office_milan: 1), "
              "the hook got the full state (trigger membership_change; carol plus, the rest basic), "
              "one restart for 3 joins", after_batch_file)

        def my_apps_carol():
            r = carol.request.get(PEOPLE + "/api/me/apps")
            body = r.text()
            assert r.status == 200, f"/api/me/apps: HTTP {r.status}: {body[:300]}"
            apps = r.json()["apps"]
            assert [a["id"] for a in apps] == ["settings-file"], [a["id"] for a in apps]
            for other in ("alice", "bob", "dave"):
                assert other not in body.lower(), f"{other} in carol's /api/me/apps: {body[:600]}"
            vals = {v["key"]: v["value"] for v in apps[0]["values"]}
            assert set(vals) == {"seats", "level"}, apps[0]
            r = carol.request.get(PEOPLE + "/api/instances/immich/settings")
            assert r.status == 404, f"people /api/instances/immich/settings: HTTP {r.status}: {r.text()[:200]}"
        check("people: carol's /api/me/apps lists only settings-file, no other username; "
              "/api/instances/immich/settings on people.<domain> is 404", my_apps_carol)

        # ── person-entered: leaving and rejoining the access group ──
        def entries_leave():
            assert "entry_t0" in state, "needs alice's entry"
            t0 = time.time()
            member("remove", "users_firefox-sync", "alice")
            until("allowlist.json without alice", lambda: entry_users(allowlist()) == {}, DELIVERY_S)
            until("sync_allowed_accounts empty", lambda: allowed_db() == [], 60)
            until("firefox-sync-init ran", lambda: starts("firefox-sync", "firefox-sync-init", t0) >= 1, 120)
            time.sleep(RESTART_QUIET_S)
            n = starts("firefox-sync", "firefox-sync-init", t0)
            assert n == 1, f"firefox-sync-init started {n} times after alice left (want 1)"
            rc, out = psql("firefoxsync", f"SELECT count(*) FROM users WHERE email LIKE '{ALICE_UID}@%'")
            assert rc == 0 and out == "0", f"alice's tokenserver rows kept: {out}"
            for uid in (ALICE_UID, OUTSIDER_UID):
                rc, out = sync_insert(uid)
                assert rc != 0 and "is not on the allowlist" in out, f"empty allowlist let {uid} in: {out}"
        check("entries_leave: alice leaves users_firefox-sync: the file no longer lists her, the init ran once, "
              "her rows are gone, nobody can sync (empty allowlist)", entries_leave)

        def entries_rejoin():
            assert "entry_t0" in state, "needs alice's entry"
            member("add", "users_firefox-sync", "alice")
            until("allowlist.json lists alice again", lambda: entry_users(allowlist()) == {"alice": ALICE_UID}, DELIVERY_S)
            until("sync_allowed_accounts has alice's uid", lambda: allowed_db() == [ALICE_UID], 60)
            rc, out = sync_insert(ALICE_UID)
            assert rc == 0 and re.match(r"^\d+", out), f"alice's uid refused after rejoining: {out}"
        check("entries_leave: alice rejoins: listed again, her account syncs", entries_rejoin)

        # ── a custom field with '_' (LLDAP attribute cost-center) ──
        # Last: it changes alice's details and groups, which nothing after
        # it counts.
        def field_underscore():
            code, out = hub("POST", "/api/directory/fields", {"name": "cost_center", "label": "Cost center",
                                                               "kind": "text", "share_with_apps": True})
            assert code == 200, f"create field cost_center: HTTP {code}: {out[:300]}"
            code, out = hub("PUT", "/api/directory/users/alice/details", {"attrs": {"cost_center": ["CC-42"]}})
            assert code == 200, f"alice's cost_center: HTTP {code}: {out[:300]}"
            # (a) the overview reads it back from LLDAP under the field name
            attrs = overview_user("alice").get("attrs") or {}
            assert attrs.get("cost_center") == ["CC-42"], f"overview: alice's attrs {attrs}"
            # (b) a rule group on the field
            code, out = hub("POST", "/api/directory/groups", {"name": "cc_42"})
            assert code == 200, f"create cc_42: HTTP {code}: {out[:300]}"
            rule = 'cost_center = "CC-42"'
            code, out = hub("POST", "/api/directory/groups/cc_42/convert-preview", {"rule": rule})
            assert code == 200, f"convert-preview: HTTP {code}: {out[:300]}"
            code, out = hub("POST", "/api/directory/groups/cc_42/convert", {"rule": rule, "keep": [], "preview": json.loads(out)})
            assert code == 200, f"convert: HTTP {code}: {out[:300]}"
            until("alice in rule group cc_42", lambda: "cc_42" in overview_user("alice").get("groups", []), 150, every=10)
            assert "cc_42" not in overview_user("bob").get("groups", []), "bob (no cost_center) in cc_42"
            # (c) the shared field's header (group-gate, user-attributes.json)
            until("X-Forwarded-Attr-Cost-Center: CC-42 for alice",
                  lambda: echo_headers(alice, allow_resign=True).get("x-forwarded-attr-cost-center") == ["CC-42"],
                  DELIVERY_S, every=10)
            # (c') the attr_cost_center claim: Keycloak's example access token
            # for alice on Immich's client (a Hub client: default scope
            # portcullis-attributes), whose LDAP mapper reads cost-center.
            uid = kc_admin("/users?exact=true&username=alice")[0]["id"]
            cid = kc_admin("/clients?clientId=immich")[0]["id"]
            until("alice's attr_cost_center claim = CC-42",
                  lambda: (t := kc_admin(f"/clients/{cid}/evaluate-scopes/generate-example-access-token"
                                         f"?scope=openid&userId={uid}")).get("attr_cost_center") == "CC-42" or
                  print(f"    example token claims: {sorted(k for k in t if k.startswith('attr_'))}", flush=True),
                  DELIVERY_S, every=10)
        check("fields: a custom field with '_' (cost_center, LLDAP cost-center) is created, set on alice, read back "
              "in the overview, drives rule group cc_42, reaches settings-echo as X-Forwarded-Attr-Cost-Center and "
              "Immich's token as claim attr_cost_center", field_underscore)

        # ── Nextcloud: the first install's start hook ──
        def nextcloud_quota():
            cid = container("nextcloud", "nextcloud")
            until("Nextcloud files default_quota = 10 GB",
                  lambda: docker("exec", "-u", "www-data", cid, "php", "/var/www/html/occ",
                                 "config:app:get", "files", "default_quota", check_rc=False).strip() == "10 GB",
                  900, every=15)
        check("nextcloud: the first install applied default_quota (10 GiB) through the start hook "
              "(occ files default_quota = '10 GB')", nextcloud_quota)

        for who, ctx in ctxs.items():
            try:
                ctx.tracing.stop(path=os.path.join(ART, f"trace-settings-{who}.zip"))
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
