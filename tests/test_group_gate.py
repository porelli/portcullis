#!/usr/bin/env python3
"""Unit tests for group-gate/group-gate.py.

Run: python3 tests/test_group_gate.py
Starts group-gate in-process on an ephemeral port with temp map/policy files.
"""
import importlib.util
import html
import http.server
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
GATE_PATH = os.path.join(HERE, "..", "group-gate", "group-gate.py")
MAP_PATH = os.path.join(HERE, "..", "group-gate", "group-gate-map.conf")

TMP = tempfile.mkdtemp()
POLICY = os.path.join(TMP, "policy.json")
REVOKED = os.path.join(TMP, "revoked-serials.txt")
os.environ["GATE_MAP_FILE"] = MAP_PATH
os.environ["GATE_POLICY_FILE"] = POLICY
os.environ["GATE_REVOKED_FILE"] = REVOKED
os.environ.pop("GATE_CRL_URL", None)
os.environ.pop("GATE_DELTA_CRL_URL", None)
os.environ["PORTCULLIS_DOMAIN"] = "example.com"
os.environ.pop("GATE_MAP", None)

spec = importlib.util.spec_from_file_location("group_gate", GATE_PATH)
gg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gg)


# The v6 keys of a fresh install (contract §4's example on example.com):
# the four methods switched on at the start, Standard and Strong, core
# pages on their starting picks (hub and people on Strong).
STANDARD = {"op": "any", "items": [{"op": "any", "items": ["passkey_synced", "passkey_device", "security_key"]},
                                    {"op": "any", "items": ["yubikey_cert"]}]}
STRONG = {"op": "any", "items": ["security_key", "yubikey_cert"]}
BASE = {
    "version": 6,
    "methods": ["passkey_device", "passkey_synced", "security_key", "yubikey_cert"],
    "templates": {"standard": STANDARD, "strong": STRONG},
    "default": "standard",
    "hosts": {},
    "core": {"directory.example.com": "standard", "enroll.example.com": "standard",
             "hub.example.com": "strong", "metrics.example.com": "standard",
             "people.example.com": "strong", "example.com": "standard",
             "traefik.example.com": "standard"},
    "people": {},
    "add_stronger": False,
}


def write_policy(doc, raw=False, malformed=False):
    # Only version 6 is served: a dict gets the BASE keys it lacks (version
    # 6 included) unless the test is about the file's shape (raw=True).
    if isinstance(doc, dict) and not raw:
        doc = {**BASE, **doc}
    # A file-level malformed document denies every request, so a test
    # expecting a deny would pass for the wrong reason: every document must
    # be well-formed unless the test says it is about a broken file.
    if isinstance(doc, dict) and not raw and not malformed:
        err = gg.validate_policy_doc(doc)
        if err is None:
            try:
                gg.expiring_entries(doc)  # `expiring` is checked per request
            except gg.PolicyError as e:
                err = str(e)
        assert err is None, f"test policy is malformed ({err}); pass malformed=True if intended"
    if doc is None:
        if os.path.exists(POLICY):
            os.remove(POLICY)
        return
    # Like the Hub: temp file + rename (group-gate caches the parsed file on
    # inode/mtime/size; a rename always gives a new inode).
    tmp = POLICY + ".tmp"
    with open(tmp, "w") as f:
        f.write(doc if isinstance(doc, str) else json.dumps(doc))
    os.replace(tmp, POLICY)


class GateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = gg.ThreadingHTTPServer(("127.0.0.1", 0), gg.Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        write_policy({})

    def req(self, host, groups="users_x", extra=None, uri=None, gate_path="/", want_headers=False):
        # What portcullis-auth (oauth2-proxy) hands group-gate: User = the
        # token's sub (Keycloak user id), Preferred-Username = LLDAP username.
        # The session: a security-key sign-in (amr hwk) unless the test
        # sends its own token (or None for no token).
        h = {"X-Forwarded-Host": host, "X-Auth-Request-Email": "bob@example.com",
             "X-Auth-Request-User": "8d3c0d2e-5f4b-4bd1-9a51-1f2d3c4b5a69",
             "X-Auth-Request-Preferred-Username": "bob",
             "X-Forwarded-Access-Token": token(amr=["hwk"], preferred_username="bob")}
        if groups is not None:
            h["X-Auth-Request-Groups"] = groups
        if uri is not None:
            h["X-Forwarded-Uri"] = uri
        h.update(extra or {})
        h = {k: v for k, v in h.items() if v is not None}
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{gate_path}", headers=h)
        try:
            with urllib.request.urlopen(r) as resp:
                return (resp.status, dict(resp.headers)) if want_headers else resp.status
        except urllib.error.HTTPError as e:
            with e:
                return (e.code, dict(e.headers)) if want_headers else e.code

    def test_hub_case_and_port_variants_denied_for_non_admin(self):
        for host in ["hub.example.com", "HUB.example.com", "Hub.Example.Com",
                     "hub.example.com:443", "Hub.example.com:443",
                     "hub.example.com.", "HUB.EXAMPLE.COM.:443"]:
            with self.subTest(host=host):
                self.assertEqual(self.req(host, groups="users_grafana"), 403)

    def test_hub_allowed_for_admin(self):
        self.assertEqual(self.req("HUB.example.com:443", groups="users_grafana, lldap_admin"), 200)

    def test_foreign_or_nested_host_denied(self):
        for host in ["hub.evil.com", "a.hub.example.com", "", "hubexample.com", "a.b.example.com",
                     "*.example.com", "x_y.example.com", "[::1]", "[::1]:443", "127.0.0.1",
                     "hub.example.com:x", "bob@hub.example.com", "hub..example.com", "-a.example.com",
                     "a" * 64 + ".example.com", "localhost"]:
            with self.subTest(host=host):
                self.assertEqual(self.req(host, groups="lldap_admin"), 403)
        # The apex is a core host (the portal): map.conf only, lldap_admin by default.
        self.assertEqual(self.req("example.com", groups="lldap_admin"), 200)
        self.assertEqual(self.req("example.com", groups="users_grafana"), 403)

    def test_group_exact_match_comma_split(self):
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana_x"), 403)
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana_x users_grafana"), 403)
        self.assertEqual(self.req("grafana.example.com", groups="a, users_grafana ,b"), 200)

    def test_unmapped_allows_authenticated(self):
        self.assertEqual(self.req("random.example.com", groups=""), 200)

    def test_no_username_fails_closed_everywhere(self):
        # No portcullis-auth in front (or no preferred_username): deny, even
        # for unmapped apps, and never fall back to sub / email.
        for gate_path in ("/", "/authenticated"):
            for extra in ({"X-Auth-Request-Preferred-Username": None},
                          {"X-Auth-Request-Preferred-Username": "  "}):
                with self.subTest(gate_path=gate_path, extra=extra):
                    self.assertEqual(self.req("random.example.com", groups="", gate_path=gate_path, extra=extra), 403)
                    self.assertEqual(self.req("hub.example.com", groups="lldap_admin", gate_path=gate_path, extra=extra), 403)

    def test_policy_groups_merge_but_cannot_override_core(self):
        write_policy({"groups": {"newapp.example.com": "users_newapp", "hub.example.com": "users_anyone"}})
        self.assertEqual(self.req("newapp.example.com", groups="users_other"), 403)
        self.assertEqual(self.req("NewApp.example.com", groups="users_newapp"), 200)
        self.assertEqual(self.req("hub.example.com", groups="users_anyone"), 403)

    def test_metrics_subdomain_is_core_admin_only(self):
        # Grafana (monitoring profile): lldap_admin, never overridable by the Hub.
        write_policy({"groups": {"metrics.example.com": "users_anyone"}, "path_groups": {"metrics.example.com": [{"prefix": "/x", "group": "g"}]}})
        self.assertEqual(self.req("metrics.example.com", groups="users_anyone"), 403)
        self.assertEqual(self.req("metrics.example.com", groups="lldap_admin"), 200)
        self.assertEqual(self.req("metrics.example.com", groups="lldap_admin", uri="/x"), 200)

    def test_policy_file_without_groups_ok(self):
        write_policy({})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 200)

    def test_malformed_policy_fails_closed(self):
        for doc in [{"templates": {"standard": {"op": "any", "items": ["yubikey"]}, "strong": STRONG}},
                    {"templates": {"standard": {"op": "some", "items": ["security_key"]}, "strong": STRONG}},
                    {"templates": {"standard": "security_key", "strong": STRONG}},
                    {"hosts": {"grafana.example.com": "missing"}},
                    {"default": "missing"},
                    {"policies": {"grafana.example.com": {"factors": ["mtls"], "op": "any"}}},
                    "{not json"]:
            with self.subTest(doc=doc):
                write_policy(doc, malformed=True)
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)

    def test_hub_default_standard(self):
        # The fresh-install default (Standard): any passkey kind OR a bound
        # YubiKey certificate passes; a password or setup-link session doesn't.
        for amr, want in ((["hwk"], 200), (["spk"], 200), (["dpk"], 200), (["pwd"], 403),
                          (["inv"], 403), ([], 403), (["mtls"], 403)):
            with self.subTest(amr=amr):
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana",
                                          extra={"X-Forwarded-Access-Token": token(amr=amr, preferred_username="bob")}), want)
        # No token at all: nothing is met.
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana",
                                  extra={"X-Forwarded-Access-Token": None}), 403)

    def test_hub_service_account_is_denied(self):
        for gate_path in ("/", "/authenticated", "/portal"):
            for name in ("portcullis-hub", "Portcullis-Hub"):
                with self.subTest(gate_path=gate_path, name=name):
                    self.assertEqual(self.req("hub.example.com", groups="lldap_admin", gate_path=gate_path,
                                              extra={"X-Auth-Request-Preferred-Username": name}), 403)
        self.assertEqual(self.req("hub.example.com", groups="lldap_admin"), 200)

    def portal(self, groups, doc):
        path = os.path.join(TMP, "portal-apps.json")
        if doc is None:
            if os.path.exists(path):
                os.unlink(path)
        else:
            with open(path, "w") as f:
                f.write(doc if isinstance(doc, str) else json.dumps(doc))
        old = gg.PORTAL_FILE
        gg.PORTAL_FILE = path
        try:
            h = {"X-Auth-Request-Preferred-Username": "bob", "X-Auth-Request-Groups": groups,
                 "X-Forwarded-Access-Token": token(amr=["hwk"], preferred_username="bob")}
            r = urllib.request.Request(f"http://127.0.0.1:{self.port}/portal", headers=h)
            with urllib.request.urlopen(r) as resp:
                return resp.read().decode()
        finally:
            gg.PORTAL_FILE = old

    def test_portal_filters_and_escapes(self):
        doc = {"version": 1, "apps": [
            {"id": "wiki", "name": "Wiki <b>", "description": "<script>x</script>", "icon": "W",
             "urls": [{"label": "Open", "url": "https://wiki.example.com/"}], "access_group": "users_wiki"},
            {"id": "open", "name": "Open app", "urls": [{"label": "Go", "url": "https://open.example.com/"},
                                                         {"label": "bad", "url": "javascript:alert(1)"},
                                                         {"label": "foreign", "url": "https://evil.org/"}],
             "access_group": ""},
            {"id": "secret", "name": "Secret", "urls": [{"label": "S", "url": "https://secret.example.com/"}],
             "access_group": "users_secret"}]}
        body = self.portal("users_wiki", doc)
        self.assertIn("Wiki &lt;b&gt;", body)
        self.assertNotIn("<script>x", body)
        self.assertIn("https://open.example.com/", body)
        self.assertNotIn("javascript:", body)
        self.assertNotIn("evil.org", body)
        self.assertNotIn("Secret", body)
        self.assertNotIn("hub.example.com", body)
        self.assertIn("Signed in as <strong>bob</strong>", body)
        admin = self.portal("lldap_admin, users_secret", doc)
        self.assertIn("https://hub.example.com/", admin)
        self.assertIn("Secret", admin)
        self.assertIn('href="https://people.example.com/"', body)  # every signed-in user
        self.assertNotIn("directory.example.com", admin)
        # Expired temporary memberships don't list their apps.
        write_policy({"expiring": [{"user": "bob", "group": "users_secret", "at": "2020-01-01T00:00:00Z"}]})
        self.assertNotIn("Secret", self.portal("lldap_admin, users_secret", doc))
        # A broken or missing policy file: no template is known, the portal
        # (a core page) is denied.
        for bad in ({"version": 6}, None):
            with self.subTest(bad=bad):
                write_policy(bad, raw=True)
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    self.portal("users_secret", doc)
                cm.exception.close()
                self.assertEqual(cm.exception.code, 403)
        write_policy({})
        self.assertIn("not available", self.portal("users_wiki", {"version": 2, "apps": doc["apps"]}))
        self.assertIn("not available", self.portal("users_wiki", None))
        self.assertIn("not available", self.portal("users_wiki", "{broken"))

    def test_portal_entry_without_url(self):
        """A portal entry with urls: [] + note should render as a card with the note, no link, content escaped."""
        doc = {"version": 1, "apps": [
            {"id": "samba", "name": "File Sharing", "description": "Shared folders", "icon": "📁",
             "urls": [], "note": "No web page: file sharing over SMB", "access_group": "users_samba"},
            {"id": "wiki", "name": "Wiki", "urls": [{"label": "Open", "url": "https://wiki.example.com/"}],
             "access_group": "users_wiki"}]}
        body = self.portal("users_samba", doc)
        self.assertIn("File Sharing", body)
        self.assertIn("No web page: file sharing over SMB", body)
        self.assertNotIn("<a", body.split("</h3>")[1].split("</li>")[0])  # No link in the samba card
        self.assertNotIn("Wiki", body)
        # Check escaping of note
        doc_xss = {"version": 1, "apps": [
            {"id": "test", "name": "Test", "urls": [], "note": "<script>alert(1)</script>", "access_group": ""}]}
        body_xss = self.portal("", doc_xss)
        self.assertIn("&lt;script&gt;", body_xss)
        self.assertNotIn("<script>alert", body_xss)

    def test_portal_entry_without_url_or_note(self):
        """A portal entry with urls: [] and no note should render with the fallback text 'No web page.', escaped."""
        doc = {"version": 1, "apps": [
            {"id": "tm", "name": "Time Machine", "description": "Backups", "icon": "⏰",
             "urls": [], "access_group": "users_timemachine"}]}
        body = self.portal("users_timemachine", doc)
        self.assertIn("Time Machine", body)
        self.assertIn("No web page.", body)
        # No <a> tag in the card
        card_content = body.split("</h3>")[1].split("</li>")[0]
        self.assertNotIn("<a", card_content)

    def test_portal_strict_csp_allows_only_its_inline_style(self):
        import base64, hashlib, re as _re
        h = {"X-Auth-Request-Preferred-Username": "bob", "X-Auth-Request-Groups": "",
             "X-Forwarded-Access-Token": token(amr=["hwk"], preferred_username="bob")}
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}/portal", headers=h)
        with urllib.request.urlopen(r) as resp:
            csp = resp.headers.get("Content-Security-Policy", "")
            body = resp.read().decode()
        self.assertIn("default-src 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        styles = _re.findall(r"<style>(.*?)</style>", body, _re.S)
        self.assertEqual(len(styles), 1)
        digest = base64.b64encode(hashlib.sha256(styles[0].encode()).digest()).decode()
        self.assertIn(f"'sha256-{digest}'", csp)
        self.assertNotIn("<script", body)
        self.assertNotIn(' style="', body)  # no inline style attributes (blocked by the CSP)

    # ── identity headers: username, never the (user-editable) email ──

    def test_allow_forwards_username_not_email_or_sub(self):
        code, hdrs = self.req("grafana.example.com", groups="users_grafana", want_headers=True)
        self.assertEqual(code, 200)
        self.assertEqual(hdrs.get("X-Forwarded-User"), "bob")
        self.assertEqual(hdrs.get("X-Auth-Request-User"), "bob")
        self.assertEqual(hdrs.get("X-Auth-Request-Preferred-Username"), "bob")
        self.assertEqual(hdrs.get("X-Forwarded-Email"), "bob@example.com")
        self.assertEqual(hdrs.get("X-Auth-Request-Email"), "bob@example.com")
        self.assertEqual(hdrs.get("X-Auth-Request-Groups"), "users_grafana")

    def test_email_or_sub_alone_is_no_identity(self):
        # An admin's address in the email header, or oauth2-proxy's session
        # user (the token's sub), must not become the user: no username = 403.
        for extra in ({"X-Auth-Request-Preferred-Username": None, "X-Auth-Request-Email": "admin@example.com"},
                      {"X-Auth-Request-Preferred-Username": None, "X-Auth-Request-User": "admin"}):
            for gate_path in ("/", "/authenticated"):
                with self.subTest(extra=extra, gate_path=gate_path):
                    self.assertEqual(self.req("grafana.example.com", groups="users_grafana",
                                              gate_path=gate_path, extra=extra), 403)

    def test_identity_headers_mapping(self):
        self.assertEqual(gg.identity_headers({}), {})
        self.assertEqual(gg.identity_headers({"X-Auth-Request-User": "sub-uuid", "X-Auth-Request-Email": "a@x"}),
                         {"X-Forwarded-Email": "a@x", "X-Auth-Request-Email": "a@x"})
        self.assertEqual(gg.identity_headers({"X-Auth-Request-User": "sub-uuid", "X-Auth-Request-Email": "a@x",
                                              "X-Auth-Request-Preferred-Username": " alice "}),
                         {"X-Forwarded-User": "alice", "X-Auth-Request-User": "alice",
                          "X-Auth-Request-Preferred-Username": "alice",
                          "X-Forwarded-Email": "a@x", "X-Auth-Request-Email": "a@x"})

    # ── reserved deny group (contract §4) ──

    def test_deny_sentinel_group_denies_everyone(self):
        write_policy({"groups": {"ghost.example.com": gg.DENY_GROUP, "ok.example.com": "users_ok"}})
        for groups in ("", "users_ghost", "lldap_admin", "users_ghost,lldap_admin"):
            with self.subTest(groups=groups):
                self.assertEqual(self.req("ghost.example.com", groups=groups), 403)
        # Positive control: the same file allows another host (not a broken file).
        self.assertEqual(self.req("ok.example.com", groups="users_ok"), 200)

    def test_deny_sentinel_cannot_be_satisfied_by_membership(self):
        write_policy({"groups": {"ghost.example.com": gg.DENY_GROUP, "ok.example.com": "users_ok"}})
        self.assertEqual(self.req("ghost.example.com", groups=gg.DENY_GROUP), 403)
        self.assertEqual(self.req("ok.example.com", groups="users_ok"), 200)

    def test_user_claiming_deny_group_is_denied_everywhere(self):
        for host in ("random.example.com", "grafana.example.com", "hub.example.com"):
            with self.subTest(host=host):
                self.assertEqual(self.req(host, groups=f"users_grafana,lldap_admin, {gg.DENY_GROUP}"), 403)
        self.assertEqual(self.req("random.example.com", groups="users_x", gate_path="/authenticated"), 200)
        self.assertEqual(self.req("random.example.com", groups=gg.DENY_GROUP, gate_path="/authenticated"), 403)

    def test_deny_sentinel_in_path_groups(self):
        write_policy({"path_groups": {"grafana.example.com": [{"prefix": "/x", "group": gg.DENY_GROUP}]}})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana", uri="/x/1"), 403)
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana", uri="/y"), 200)

    # ── version ──

    def test_policy_version(self):
        # group-gate serves only version 6 (contract §4); a file without
        # `version`, and a missing file, deny too.
        for version, want in [(6, 200), (5, 403), (4, 403), (3, 403), (1, 403), (7, 403), ("6", 403),
                              (True, 403), (0, 403), (6.0, 403)]:
            with self.subTest(version=version):
                write_policy(dict(BASE, version=version), raw=True)
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), want)
        body = json.dumps({k: v for k, v in BASE.items() if k != "version"})
        for doc in (None, {}, {"groups": {}}, '{"version": 6.0, %s' % body[1:], '{"version": 6e0, %s' % body[1:],
                    {k: v for k, v in BASE.items() if k != "version"}):
            with self.subTest(doc=doc):
                write_policy(doc, raw=True)
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
                self.assertEqual(self.req("hub.example.com", groups="lldap_admin"), 403)

    # ── healthz / authenticated-only ──

    def test_healthz(self):
        self.assertEqual(self.req("", groups=None, gate_path="/healthz"), 200)

    def test_authenticated_only_skips_group_but_not_other_checks(self):
        self.assertEqual(self.req("enroll.example.com", groups="users_x"), 403)
        self.assertEqual(self.req("enroll.example.com", groups="users_x", gate_path="/authenticated"), 200)
        self.assertEqual(self.req("enroll.example.com", groups="", gate_path="/authenticated/self"), 200)
        # no user at all
        self.assertEqual(self.req("enroll.example.com", groups="", gate_path="/authenticated",
                                  extra={"X-Auth-Request-Email": None, "X-Auth-Request-User": None,
                                         "X-Auth-Request-Preferred-Username": None}), 403)
        # host check still applies
        self.assertEqual(self.req("enroll.evil.com", groups="", gate_path="/authenticated"), 403)
        # "/authenticatedX" is not the authenticated-only endpoint
        self.assertEqual(self.req("enroll.example.com", groups="users_x", gate_path="/authenticatedX"), 403)


EXTRA = "team-b.example.org"


class PolicyHostsTest(GateTest):
    """Policy file v6 host handling (contract §4, §5): full-hostname keys,
    extra_domains, core hosts from map.conf, step-up on extra-domain hosts."""

    def setUp(self):
        super().setUp()
        write_attrs(None)

    def tearDown(self):
        write_attrs(None)

    def test_policy_host_keys(self):
        write_policy({"extra_domains": [EXTRA],
                      "hosts": {"grafana-team-a.example.com": "standard", f"grafana.{EXTRA}": "cert"},
                      "templates": {**BASE["templates"], "cert": {"op": "any", "items": ["yubikey_cert"]}},
                      "groups": {"grafana-team-a.example.com": "users_grafana-team-a",
                                 f"grafana.{EXTRA}": "users_grafana-team-b",
                                 "passwords.example.com": "users_vaultwarden"},
                      "path_groups": {"passwords.example.com": [{"prefix": "/admin", "group": "admin_vaultwarden"}]}})
        hwk = {"X-Forwarded-Access-Token": token(amr=["hwk"])}
        # Each host gets exactly its own group.
        self.assertEqual(self.req("grafana-team-a.example.com", groups="users_grafana-team-a", extra=hwk), 200)
        self.assertEqual(self.req("grafana-team-a.example.com", groups="users_grafana-team-b", extra=hwk), 403)
        self.assertEqual(self.req(f"grafana.{EXTRA}", groups="users_grafana-team-a", extra=hwk), 403)
        # ... and its own template: team-b needs a cert, a passkey session steps up.
        code, hdrs = self.req(f"grafana.{EXTRA}", groups="users_grafana-team-b", extra=hwk, want_headers=True)
        self.assertEqual(code, 403)
        self.assertIn("pc_method=yubikey_cert", hdrs["X-Stepup-URL"])
        self.assertEqual(self.req("passwords.example.com", groups="users_vaultwarden", uri="/"), 200)
        self.assertEqual(self.req("passwords.example.com", groups="users_vaultwarden", uri="/admin"), 403)
        self.assertEqual(self.req("passwords.example.com", groups="users_vaultwarden,admin_vaultwarden",
                                  uri="/admin"), 200)
        # The main map.conf's `grafana` (grafana.example.com) is untouched by
        # the instances; a subdomain-only key matches nothing.
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana-team-a"), 403)
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 200)
        # The same label on the extra domain is a different host: no fallback
        # to grafana.example.com's group, nor to the parent domain.
        write_policy({"extra_domains": [EXTRA], "groups": {f"grafana.{EXTRA}": "users_b"}})
        self.assertEqual(self.req(f"grafana.{EXTRA}", groups="users_grafana"), 403)
        self.assertEqual(self.req(f"other.{EXTRA}", groups=""), 200)  # unlisted: default, no group
        self.assertEqual(self.req(EXTRA, groups=""), 200)  # the enrolled apex itself

    def test_host_normalisation(self):
        # Review Focus 2: case, trailing dots and a port are normalised, then
        # the host is looked up EXACTLY.
        write_policy({"extra_domains": ["team-a.com"], "groups": {"grafana-a.team-a.com": "users_a"},
                      "path_groups": {"grafana-a.team-a.com": [{"prefix": "/admin", "group": "admin_a"}]}})
        for raw in ("grafana-a.team-a.com", "Grafana-A.Team-A.com", "GRAFANA-A.TEAM-A.COM.",
                    "Grafana-A.team-a.com.:443", "grafana-a.team-a.com:8443", "grafana-a.team-a.com..",
                    "grafana-a.team-a.com, evil.example.com"):
            with self.subTest(raw=raw):
                self.assertEqual(self.req(raw, groups="users_x"), 403)
                self.assertEqual(self.req(raw, groups="users_a"), 200)
                self.assertEqual(self.req(raw, groups="users_a", uri="/admin"), 403)
                self.assertEqual(self.req(raw, groups="users_a,admin_a", uri="/ADMIN/../admin"), 200)
        self.assertEqual(gg.normalize_host("Grafana-A.Team-A.com.:443"), "grafana-a.team-a.com")
        # Never a subdomain-only or parent match, and malformed hosts deny.
        for raw in ("grafana-a.team-a.com:x", "grafana-a.team-a.com:", "grafana-a.team-a.com:443:443",
                    "user@grafana-a.team-a.com", "grafana-a..team-a.com", "[grafana-a.team-a.com]",
                    "grafana-a.team-a.com/x", "grafana-a.team-a.com\\x", "x.grafana-a.team-a.com"):
            with self.subTest(raw=raw):
                self.assertEqual(self.req(raw, groups="users_a,admin_a"), 403)
        # A host on a domain that isn't enrolled (nor the main one) is denied,
        # even if the file has an entry for it.
        write_policy({"groups": {"grafana-a.team-a.com": "users_a"}})
        self.assertEqual(self.req("grafana-a.team-a.com", groups="users_a"), 403)

    def test_core_hosts_from_map(self):
        # map.conf <sub> entries are <sub>.<domain>; core hosts ignore the file.
        gate = gg.build_group_map({})
        for sub in gg.CORE_SUBDOMAINS:
            self.assertIn(f"{sub}.example.com", gate)
        self.assertEqual(gate["people.example.com"], "*")
        # mcp.<domain> (AI support, contract §4/§5): a core host, map entry
        # `*`; its router has no forward-auth (mcp-gate authorizes).
        self.assertIn("mcp", gg.CORE_SUBDOMAINS)
        self.assertEqual(gate["mcp.example.com"], "*")
        self.assertEqual(gate["grafana.example.com"], "users_grafana")
        self.assertEqual(gate["example.com"], "lldap_admin")
        self.assertNotIn("grafana", gate)
        self.assertEqual(gg.core_hosts(), frozenset(["example.com"] + [f"{s}.example.com" for s in gg.CORE_SUBDOMAINS]))
        write_policy({"extra_domains": [EXTRA],
                      "groups": {"hub.example.com": "users_x", "example.com": "users_x", "grafana.example.com": "users_g2"},
                      "hosts": {"hub.example.com": "standard"},
                      "path_groups": {"hub.example.com": [{"prefix": "/", "group": "nobody"}]},
                      "public_paths": {"hub.example.com": {"paths": [{"path": "/s", "match": "prefix"}]}}})
        self.assertEqual(self.req("hub.example.com", groups="users_x"), 403)
        self.assertEqual(self.req("hub.example.com", groups="lldap_admin", uri="/x"), 200)
        self.assertEqual(self.req("example.com", groups="users_x"), 403)
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)  # app entries: file overrides
        self.assertEqual(self.req("grafana.example.com", groups="users_g2"), 200)
        self.assertEqual(self.req("hub.example.com", gate_path="/public-guard", uri="/s"), 403)
        # Core hosts exist on the main domain only: hub.<extra domain> is an
        # ordinary extra-domain host.
        self.assertEqual(self.req(f"hub.{EXTRA}", groups=""), 200)
        # A map entry that is not a label is ignored.
        old = os.environ.get("GATE_MAP")
        os.environ["GATE_MAP"] = f"x.y=users_x,grafana.{EXTRA}=nobody,Wiki=users_w2"
        try:
            gate = gg.build_group_map({})
            self.assertNotIn("x.y.example.com", gate)
            self.assertNotIn(f"grafana.{EXTRA}.example.com", gate)
            self.assertEqual(gate["wiki.example.com"], "users_w2")
        finally:
            os.environ.pop("GATE_MAP") if old is None else os.environ.__setitem__("GATE_MAP", old)

    def test_v4_refused(self):
        # A v4 file (subdomain keys) denies every request, core hosts included.
        write_policy({"version": 4, "groups": {"grafana": "users_grafana"}}, raw=True)
        # A v5 file (factor policies) likewise.
        for host, groups in (("grafana.example.com", "users_grafana"), ("hub.example.com", "lldap_admin")):
            write_policy({"version": 5, "default": {"factors": ["webauthn"], "op": ""}, "policies": {}}, raw=True)
            self.assertEqual(self.req(host, groups=groups), 403)
        write_policy({"version": 4, "groups": {"grafana": "users_grafana"}}, raw=True)
        for host, groups in (("grafana.example.com", "users_grafana"), ("hub.example.com", "lldap_admin"),
                             ("random.example.com", "")):
            with self.subTest(host=host):
                self.assertEqual(self.req(host, groups=groups), 403)
        self.assertEqual(self.req("cloud.example.com", gate_path="/public-guard", uri="/s/x"), 403)

    def test_extra_domains_malformed_denies(self):
        for extra in ("team-b.example.org", [""], ["Team-B.example.org"], ["*.example.org"], [1],
                      ["team-b.example.org."], ["example.com"], ["com"], ["hub.example.com"],
                      ["x.hub.example.com"], [None]):
            with self.subTest(extra=extra):
                write_policy({"extra_domains": extra}, malformed=True)
                self.assertEqual(self.req("random.example.com", groups=""), 403)
        # An enrolled subdomain of the main domain is fine, and its hosts are
        # extra-domain hosts (contract §5).
        write_policy({"extra_domains": ["team-a.example.com"], "default": "strong"})
        for host in ("team-a.example.com", "x.team-a.example.com"):
            with self.subTest(host=host):
                code, hdrs = self.req(host, groups="", want_headers=True,
                                      extra={"X-Forwarded-Access-Token": token(amr=["spk"])})
                self.assertEqual(code, 403)
                self.assertTrue(hdrs["X-Stepup-URL"].startswith(f"https://{host}/oauth2/start?"), hdrs["X-Stepup-URL"])
        self.assertEqual(self.req("y.x.team-a.example.com", groups=""), 403)

    def test_stepup_url_on_extra_domain(self):
        url = gg.stepup_url(f"grafana.{EXTRA}", "yubikey_cert", extra=True)
        parts = urllib.parse.urlsplit(url)
        self.assertEqual((parts.scheme, parts.netloc, parts.path), ("https", f"grafana.{EXTRA}", "/oauth2/start"))
        self.assertEqual(urllib.parse.parse_qs(parts.query), {"pc_method": ["yubikey_cert"], "rd": ["/"]})
        write_policy({"extra_domains": [EXTRA], "hosts": {f"grafana.{EXTRA}": "strong"}})
        spk = {"X-Forwarded-Access-Token": token(amr=["spk"])}
        code, hdrs = self.req(f"Grafana.{EXTRA}.:443", groups="", want_headers=True, extra=spk)
        self.assertEqual(code, 403)
        parts = urllib.parse.urlsplit(hdrs["X-Stepup-URL"])
        self.assertEqual((parts.netloc, parts.path), (f"grafana.{EXTRA}", "/oauth2/start"))
        self.assertEqual(urllib.parse.parse_qs(parts.query), {"pc_method": ["security_key"], "rd": ["/"]})
        body = self.stepup_page_for(f"grafana.{EXTRA}")
        self.assertIn(f'href="https://grafana.{EXTRA}/oauth2/start?', body)
        # Main-domain hosts keep the auth.<domain> step-up.
        write_policy({"extra_domains": [EXTRA], "default": "strong"})
        code, hdrs = self.req("grafana.example.com", groups="users_grafana", want_headers=True, extra=spk)
        self.assertEqual(code, 403)
        self.assertTrue(hdrs["X-Stepup-URL"].startswith("https://auth.example.com/oauth2/start?"))

    def stepup_page_for(self, host):
        h = {"X-Forwarded-Host": host, "X-Auth-Request-Preferred-Username": "bob",
             "X-Forwarded-Access-Token": token(amr=["spk"])}
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}/", headers=h)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r)
        with cm.exception as e:
            return e.read().decode()

    def test_attribute_headers_on_extra_domain_host(self):
        write_attrs({"version": 2, "fields": {"city": "City"}, "users": {"bob": {"city": ["Milan"]}}})
        write_policy({"extra_domains": [EXTRA], "groups": {f"grafana.{EXTRA}": "users_b"}})
        status, hdrs = self.req(f"grafana.{EXTRA}", groups="users_b", want_headers=True)
        self.assertEqual((status, hdrs.get("X-Forwarded-Attr-City"), hdrs.get("X-Forwarded-User")), (200, "Milan", "bob"))
        status, hdrs = self.req(f"grafana.{EXTRA}", groups="users_x", want_headers=True)
        self.assertEqual(status, 403)
        self.assertFalse([k for k in hdrs if k.lower().startswith("x-forwarded-attr-")])
        # Not enrolled any more: the host is no longer served.
        write_policy({"groups": {f"grafana.{EXTRA}": "users_b"}})
        self.assertEqual(self.req(f"grafana.{EXTRA}", groups="users_b"), 403)

    def test_public_guard_on_extra_domain_host(self):
        entry = PUBLIC_DOC["public_paths"]["cloud.example.com"]
        write_policy({"extra_domains": [EXTRA], "public_paths": {f"cloud.{EXTRA}": entry}})
        self.assertEqual(self.req(f"Cloud.{EXTRA}:443", gate_path="/public-guard", uri="/s/AbC123"), 200)
        self.assertEqual(self.req("cloud.example.com", gate_path="/public-guard", uri="/s/AbC123"), 403)
        write_policy({"public_paths": {f"cloud.{EXTRA}": entry}})
        self.assertEqual(self.req(f"cloud.{EXTRA}", gate_path="/public-guard", uri="/s/AbC123"), 403)

    def test_portal_lists_enrolled_domains_only(self):
        doc = {"version": 1, "domains": [EXTRA, "Bad..Domain", 3],
               "apps": [{"id": "g", "name": "G", "access_group": "",
                         "urls": [{"label": "b", "url": f"https://grafana.{EXTRA}/"},
                                  {"label": "c", "url": "https://grafana.other.org/"},
                                  {"label": "d", "url": f"https://grafana.{EXTRA}.evil.org/"},
                                  {"label": "a", "url": "https://grafana-a.example.com/"}]}]}
        body = GateTest.portal(self, "", doc)
        self.assertIn(f"https://grafana.{EXTRA}/", body)
        self.assertIn("https://grafana-a.example.com/", body)
        self.assertNotIn("other.org", body)
        self.assertNotIn("evil.org", body)
        body = GateTest.portal(self, "", dict(doc, domains=[]))
        self.assertNotIn(EXTRA, body)

    def test_domain_required(self):
        old = gg.DOMAIN, gg.DOMAIN_OK
        gg.DOMAIN, gg.DOMAIN_OK = "", False
        try:
            self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
            self.assertEqual(self.req("hub.example.com", groups="lldap_admin"), 403)
            self.assertEqual(gg.core_hosts(), frozenset())
            self.assertEqual(gg.build_group_map({}), {})
        finally:
            gg.DOMAIN, gg.DOMAIN_OK = old


VECTORS = os.path.join(HERE, "signin_vectors.json")
ALPHA = os.path.join(HERE, "..", "oauth2-proxy", "alpha.yaml")
ALL_METHODS = set(gg.METHOD_IDS)
# Basic with password off compiles like Standard (contract §8.1).
BASIC_COMPILED = {"op": "any", "items": [{"op": "any", "items": ["passkey_synced", "passkey_device", "security_key"]},
                                         {"op": "any", "items": ["yubikey_cert"]}]}


class SigninV6Test(GateTest):
    """Policy file v6 sign-in templates (contract §4 "How group-gate
    decides", §5 "Step-up and the needs-stronger page", §8.1)."""

    def page(self, host, amr, user="bob", groups="users_grafana", gate_path="/", cert=None):
        h = {"X-Forwarded-Host": host, "X-Auth-Request-Preferred-Username": user,
             "X-Auth-Request-Groups": groups,
             "X-Forwarded-Access-Token": token(amr=amr, preferred_username=user)}
        if cert is not None:
            h[gg.CERT_INFO_HEADER] = cert
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{gate_path}", headers=h)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, dict(resp.headers), resp.read().decode()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, dict(e.headers), e.read().decode()

    def test_v6_only(self):
        for doc in (dict(BASE, version=5), dict(BASE, version=7)):
            write_policy(doc, raw=True)
            self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
        for key in gg.POLICY_REQUIRED_KEYS:
            with self.subTest(missing=key):
                write_policy({k: v for k, v in BASE.items() if k != key}, raw=True)
                self.assertIn("missing keys", gg.validate_policy_doc({k: v for k, v in BASE.items() if k != key}))
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
        # An unknown key (a v5 leftover included) denies too.
        for extra in ({"policies": {}}, {"acr": 1}):
            with self.subTest(extra=extra):
                write_policy(extra, malformed=True)
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)

    def test_unknown_leaf_denies(self):
        write_policy({"templates": {"standard": {"op": "any", "items": ["webauthn", "security_key"]}, "strong": STRONG}},
                     malformed=True)
        before = gg.METRICS.get("group_gate_denials_total", reason="policy_error")
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
        self.assertEqual(gg.METRICS.get("group_gate_denials_total", reason="policy_error"), before + 1)

    def test_rule_shapes_fail_closed(self):
        ok = {"op": "any", "items": ["security_key"]}
        deep = ok
        for _ in range(4):
            deep = {"op": "all", "items": [deep]}
        for bad in ("security_key", [], {"op": "any"}, {"op": "any", "items": []},
                    {"op": "any", "items": ["security_key"], "x": 1}, {"op": "ANY", "items": ["security_key"]},
                    {"op": "any", "items": ["security_key"] * 9}, {"op": "any", "items": [True]},
                    {"op": "any", "items": ["family:passkey"]}, {"op": "any", "items": ["inv"]},
                    {"op": "any", "items": ["hwk"]}, deep,
                    {"op": "any", "items": [{"op": "any", "items": ["security_key"] * 8}] * 7}):
            with self.subTest(bad=bad):
                self.assertIsNotNone(gg.validate_rule(bad, ALL_METHODS))
                write_policy({"templates": {"standard": STANDARD, "strong": STRONG, "x": bad}}, malformed=True)
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
        self.assertIsNone(gg.validate_rule({"op": "all", "items": [{"op": "any", "items": [{"op": "all", "items": [ok]}]}]},
                                           ALL_METHODS))
        self.assertIsNone(gg.validate_rule({"op": "any", "items": [{"op": "any", "items": ["security_key"] * 8}] * 6},
                                           ALL_METHODS))  # 48 leaves
        # Bad ids and references.
        for doc in ({"templates": {**BASE["templates"], "Bad": STRONG}},
                    {"templates": {**BASE["templates"], "collision.0": STRONG}},
                    {"hosts": {"grafana.example.com": "nope"}}, {"core": dict(BASE["core"], **{"hub.example.com": "nope"})},
                    {"core": dict(BASE["core"], **{"auth.example.com": "standard"})},
                    {"core": dict(BASE["core"], **{"grafana.example.com": "standard"})},
                    {"default": "nope"}, {"default": None}, {"hosts": []},
                    {"methods": ["passkey_synced", "passkey_synced", "passkey_device", "security_key", "yubikey_cert"]},
                    {"methods": ["webauthn"]}, {"methods": "security_key"},
                    {"people": {"Bob": []}}, {"people": {"bob": ["password"]}}, {"people": {"bob": "security_key"}},
                    {"people": []}, {"add_stronger": 0}, {"add_stronger": None}):
            with self.subTest(doc=doc):
                write_policy(doc, malformed=True)
                self.assertIsNotNone(gg.validate_policy_doc({**BASE, **doc}))
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
        write_policy({"templates": {**BASE["templates"], "collision.1": STRONG, "my-own-2": STRONG}})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 200)

    def test_shared_vectors(self):
        with open(VECTORS) as f:
            doc = json.load(f)
        self.assertEqual(doc["version"], 1)
        evaluated = rejects = 0
        saw_inv = False
        for c in doc["cases"]:
            with self.subTest(case=c["name"]):
                if c.get("reject"):
                    rejects += 1
                    self.assertIsNotNone(gg.validate_rule(c["compiled"], ALL_METHODS))
                    continue
                if "error" in c:
                    continue  # compiling is the Hub's
                evaluated += 1
                rule = c["compiled"]
                self.assertIsNone(gg.validate_rule(rule, set(c["on"])))
                saw_inv |= "inv" in c["have"]
                have = gg.session_methods(c["have"], ALL_METHODS, cert_bound=True)
                self.assertEqual(gg.rule_satisfied(rule, have), c["satisfied"], have)
                got = gg.alternatives(rule)
                self.assertEqual(set(got), {frozenset(a) for a in c["alternatives"]})
                self.assertEqual(len(got), len(c["alternatives"]), "listed once each")
                self.assertEqual(any(a <= have for a in got), c["satisfied"])
        self.assertGreaterEqual(evaluated, 30)
        self.assertGreaterEqual(rejects, 5)
        self.assertTrue(saw_inv)

    def test_alternatives_order_is_the_rules(self):
        rule = {"op": "any", "items": ["yubikey_cert", {"op": "all", "items": ["security_key", "yubikey_cert"]},
                                       "passkey_synced", {"op": "all", "items": ["password", "passkey_device"]}]}
        self.assertEqual(gg.alternatives(rule), [frozenset({"yubikey_cert"}), frozenset({"passkey_synced"}),
                                                 frozenset({"password", "passkey_device"})])

    def test_switched_off_method_amr_ignored(self):
        # methods without password: amr pwd counts as nothing, whatever the token says.
        write_policy({})
        code, hdrs, body = self.page("grafana.example.com", ["pwd"])
        self.assertEqual(code, 403)
        self.assertTrue('id="stepup-continue"' in body or 'id="needs-stronger"' in body)
        self.assertIn("pc_method=passkey", hdrs.get("X-Stepup-URL", ""))  # person unknown: any passkey
        # The same session meets a rule over password once it is on.
        write_policy({"methods": sorted(BASE["methods"] + ["password"]),
                      "templates": {**BASE["templates"], "basic": {"op": "any", "items": ["password", "security_key"]}},
                      "default": "basic"})
        self.assertEqual(self.page("grafana.example.com", ["pwd"])[0], 200)

    def test_leaf_outside_methods_denies(self):
        write_policy({"templates": {**BASE["templates"], "basic": {"op": "any", "items": ["password", "security_key"]}},
                      "hosts": {"grafana.example.com": "basic"}}, malformed=True)
        self.assertIn("not switched on", gg.validate_policy_doc({**BASE, "templates": {
            **BASE["templates"], "basic": {"op": "any", "items": ["password"]}}}))
        before = gg.METRICS.get("group_gate_policy_load_errors_total")
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
        self.assertEqual(gg.METRICS.get("group_gate_policy_load_errors_total"), before + 1)

    def test_inv_session_meets_nothing(self):
        write_policy({"templates": {**BASE["templates"], "basic": BASIC_COMPILED}, "default": "basic"})
        code, hdrs, body = self.page("grafana.example.com", ["inv"])
        self.assertEqual(code, 403)
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(hdrs["X-Stepup-URL"]).query),
                         {"pc_method": ["passkey"], "rd": ["https://grafana.example.com/"]})
        self.assertIn("grafana.example.com needs a passkey", body)
        # A known person: the template's first passkey kind they have set up.
        write_policy({"templates": {**BASE["templates"], "basic": BASIC_COMPILED}, "default": "basic",
                      "people": {"bob": ["passkey_device", "security_key"]}})
        code, hdrs, body = self.page("grafana.example.com", ["inv"])
        self.assertIn("pc_method=passkey_device", hdrs["X-Stepup-URL"])

    def test_yubikey_cert_needs_bound_cert(self):
        write_policy({"hosts": {"grafana.example.com": "strong"}})
        code, hdrs, body = self.page("grafana.example.com", ["mtls"])
        self.assertEqual(code, 403)
        self.assertIn('id="present-certificate"', body)
        self.assertNotIn("X-Stepup-URL", hdrs)
        self.assertEqual(self.page("grafana.example.com", ["mtls"], cert=cert_info_for("bob", 7))[0], 200)
        # Another person's certificate doesn't count.
        self.assertEqual(self.page("grafana.example.com", ["mtls"], cert=cert_info_for("alice", 7))[0], 403)

    def test_core_host_uses_core_map(self):
        # hub.<d> on strong, the default on standard: strong applies.
        code, hdrs, body = self.page("hub.example.com", ["spk"], groups="lldap_admin")
        self.assertEqual(code, 403)
        self.assertIn("pc_method=security_key", hdrs["X-Stepup-URL"])
        self.assertTrue(hdrs["X-Stepup-URL"].startswith("https://auth.example.com/oauth2/start?"))
        self.assertEqual(self.page("hub.example.com", ["hwk"], groups="lldap_admin")[0], 200)
        # A hosts entry for a core host is ignored.
        write_policy({"hosts": {"hub.example.com": "standard"}})
        self.assertEqual(self.page("hub.example.com", ["spk"], groups="lldap_admin")[0], 403)
        # Core on standard: a synced passkey is enough.
        write_policy({"core": dict(BASE["core"], **{"hub.example.com": "standard"})})
        self.assertEqual(self.page("hub.example.com", ["spk"], groups="lldap_admin")[0], 200)
        # A gated core host missing from `core` is denied (the Hub leaves out
        # a page whose template it can't publish).
        core = {k: v for k, v in BASE["core"].items() if k != "people.example.com"}
        write_policy({"core": core})
        self.assertEqual(self.page("people.example.com", ["hwk"], groups="")[0], 403)
        self.assertEqual(self.page("hub.example.com", ["hwk"], groups="lldap_admin")[0], 200)
        # /authenticated (enroll.<d>/self) applies enroll's template too.
        write_policy({"core": dict(BASE["core"], **{"enroll.example.com": "strong"})})
        self.assertEqual(self.page("enroll.example.com", ["spk"], groups="", gate_path="/authenticated")[0], 403)
        self.assertEqual(self.page("enroll.example.com", ["hwk"], groups="", gate_path="/authenticated")[0], 200)
        # auth.<d> (the Keycloak console's router) takes the Hub's template
        # (core["hub.<d>"]: strong here), never the default.
        write_policy({"default": "standard"})
        code, hdrs, body = self.page("auth.example.com", ["spk"], groups="lldap_admin")
        self.assertEqual(code, 403)
        self.assertIn("pc_method=security_key", hdrs.get("X-Stepup-URL", ""))
        self.assertEqual(self.page("auth.example.com", ["hwk"], groups="lldap_admin")[0], 200)
        write_policy({"core": dict(BASE["core"], **{"hub.example.com": "standard"}), "default": "strong"})
        self.assertEqual(self.page("auth.example.com", ["spk"], groups="lldap_admin")[0], 200)
        # Without core["hub.<d>"] the console is denied.
        write_policy({"core": {k: v for k, v in BASE["core"].items() if k != "hub.example.com"}})
        self.assertEqual(self.page("auth.example.com", ["hwk"], groups="lldap_admin")[0], 403)

    def test_membership_checks_run_before_the_template(self):
        # Outside the app's group (or a path group) with an unmet template:
        # the plain group 403, never a page naming the app or its rule.
        write_policy({"hosts": {"grafana.example.com": "strong"},
                      "path_groups": {"grafana.example.com": [{"prefix": "/admin", "group": "admin_g"}]}})
        before = gg.METRICS.get("group_gate_denials_total", reason="group")
        for groups, uri, reason in (("users_x", "/", "group"), ("users_grafana", "/admin", "path_group")):
            with self.subTest(groups=groups, uri=uri):
                h = {"X-Forwarded-Host": "grafana.example.com", "X-Auth-Request-Preferred-Username": "bob",
                     "X-Auth-Request-Groups": groups, "X-Forwarded-Uri": uri,
                     "X-Forwarded-Access-Token": token(amr=["spk"], preferred_username="bob")}
                r = urllib.request.Request(f"http://127.0.0.1:{self.port}/", headers=h)
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(r)
                with cm.exception as e:
                    body, hdrs = e.read().decode(), dict(e.headers)
                self.assertEqual(cm.exception.code, 403)
                self.assertNotIn("X-Stepup-URL", hdrs)
                for marker in ('id="stepup-continue"', 'id="needs-stronger"', 'id="present-certificate"', "pc_method"):
                    self.assertNotIn(marker, body)
        self.assertEqual(gg.METRICS.get("group_gate_denials_total", reason="group"), before + 1)
        # A member gets the step-up.
        self.assertIn("X-Stepup-URL", self.page("grafana.example.com", ["spk"])[1])

    def test_request_metric_names_each_page(self):
        m = gg.METRICS
        write_policy({"hosts": {"grafana.example.com": "strong"}, "people": {"bob": ["passkey_synced"]}})
        n0 = m.get("group_gate_requests_total", endpoint="gate", result="needs_stronger")
        self.assertIn('id="needs-stronger"', self.page("grafana.example.com", ["spk"])[2])
        self.assertEqual(m.get("group_gate_requests_total", endpoint="gate", result="needs_stronger"), n0 + 1)
        write_policy({"hosts": {"grafana.example.com": "strong"}})
        s0 = m.get("group_gate_requests_total", endpoint="gate", result="stepup")
        self.page("grafana.example.com", ["spk"])
        self.assertEqual(m.get("group_gate_requests_total", endpoint="gate", result="stepup"), s0 + 1)
        p0 = m.get("group_gate_requests_total", endpoint="gate", result="present_certificate")
        self.assertIn('id="present-certificate"', self.page("grafana.example.com", ["mtls"])[2])
        self.assertEqual(m.get("group_gate_requests_total", endpoint="gate", result="present_certificate"), p0 + 1)

    def test_portal_uses_its_core_template(self):
        write_policy({"core": dict(BASE["core"], **{"example.com": "strong"})})
        code, hdrs, body = self.page("example.com", ["spk"], groups="", gate_path="/portal")
        self.assertEqual(code, 403)
        self.assertIn("pc_method=security_key", hdrs["X-Stepup-URL"])
        self.assertIn("rd=https%3A%2F%2Fexample.com%2F", hdrs["X-Stepup-URL"])
        self.assertEqual(self.page("example.com", ["hwk"], groups="", gate_path="/portal")[0], 200)

    def test_stepup_one_method(self):
        write_policy({"hosts": {"grafana.example.com": "strong"}, "people": {"bob": ["passkey_synced", "security_key"]}})
        code, hdrs, body = self.page("grafana.example.com", ["spk"])
        self.assertEqual(code, 403)
        url = hdrs["X-Stepup-URL"]
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query),
                         {"pc_method": ["security_key"], "rd": ["https://grafana.example.com/"]})
        self.assertIn('id="stepup-continue"', body)
        self.assertIn(f'href="{html.escape(url, quote=True)}"', body)
        self.assertIn("grafana.example.com needs a security key", body)
        self.assertNotIn("refresh", body.lower().split("<style>")[0] + body.split("</style>")[1])
        # Only methods the person has set up are candidates.
        self.assertEqual(gg.choose_stepup(STRONG, {"passkey_synced"}, {"security_key"}), "security_key")
        self.assertEqual(gg.choose_stepup(STRONG, {"passkey_synced"}, {"yubikey_cert"}), "yubikey_cert")
        self.assertIsNone(gg.choose_stepup(STRONG, {"passkey_synced"}, set()))
        # Unknown person: the first candidate; never yubikey_cert while amr has mtls.
        self.assertEqual(gg.choose_stepup(STRONG, set(), None), "security_key")
        self.assertEqual(gg.choose_stepup({"op": "any", "items": ["yubikey_cert", "security_key"]}, set(), None,
                                          amr_mtls=True), "security_key")
        self.assertEqual(gg.choose_stepup(STANDARD, set(), None), "passkey")
        self.assertEqual(gg.choose_stepup(STANDARD, set(), {"passkey_device", "security_key"}), "passkey_device")
        self.assertIsNone(gg.choose_stepup({"op": "all", "items": ["security_key", "yubikey_cert"]}, set(), None))
        for m in ("password", "passkey_synced", "browser_cert", "passkey_device", "security_key", "yubikey_cert", "passkey"):
            self.assertIn(f"pc_method={m}&", gg.stepup_url("x.example.com", m, extra=False))
        with self.assertRaises(ValueError):
            gg.stepup_url("x.example.com", "hwk", extra=False)

    def test_people_and_add_stronger_never_decide_access(self):
        for people in ({}, {"bob": []}, {"bob": ["security_key"]}):
            for add in (False, True):
                with self.subTest(people=people, add=add):
                    write_policy({"hosts": {"grafana.example.com": "strong"}, "people": people, "add_stronger": add})
                    self.assertEqual(self.page("grafana.example.com", ["spk"])[0], 403)
                    self.assertEqual(self.page("grafana.example.com", ["hwk"])[0], 200)

    def test_needs_page_escapes(self):
        portal = os.path.join(TMP, "portal-apps.json")
        with open(portal, "w") as f:
            json.dump({"version": 1, "apps": [{"id": "g", "name": "<b>", "access_group": "",
                                               "urls": [{"label": "x", "url": "https://grafana.example.com/"}]}]}, f)
        old = gg.PORTAL_FILE
        gg.PORTAL_FILE = portal
        try:
            write_policy({"hosts": {"grafana.example.com": "strong"}, "people": {"bob": ["passkey_synced"]}})
            code, hdrs, body = self.page("grafana.example.com", ["spk"])
        finally:
            gg.PORTAL_FILE = old
            os.unlink(portal)
        self.assertEqual(code, 403)
        self.assertNotIn("X-Stepup-URL", hdrs)
        self.assertIn('id="needs-stronger"', body)
        self.assertNotIn("<b>&lt;", body.replace("<b>passkey</b>", ""))
        self.assertIn("&lt;b&gt; needs a stronger sign-in", body)
        self.assertNotIn("<b> needs", body)
        self.assertNotIn("http-equiv", body)
        self.assertNotIn("<script", body)
        self.assertEqual(hdrs.get("Cache-Control"), "no-store")
        self.assertIn("default-src 'none'", hdrs.get("Content-Security-Policy", ""))
        # The app name is the host when portal-apps.json doesn't list it.
        self.assertIn("grafana.example.com needs a stronger sign-in", self.page("grafana.example.com", ["spk"])[2])

    def test_needs_page_matches_the_extension(self):
        # portcullis-needs-stronger.ftl / NeedsStronger.java with
        # messages_en.properties: the same words, one line per alternative.
        acct = "https://auth.example.com/realms/portcullis/account/account-security/signing-in"
        b = gg.render_needs_page("Grafana", {"password"}, STRONG, {"password"}, False, "example.com").decode()
        self.assertIn("<h1>Grafana needs a stronger sign-in</h1>", b)
        self.assertIn('<div id="needs-stronger"><p>You signed in with a <b>password</b>. Grafana accepts any one of:</p>', b)
        self.assertIn("<li>a security key <span class=\"portcullis-sub\">— you don&#x27;t have one yet</span></li>", b)
        self.assertIn("<li>a YubiKey certificate</li>", b)
        # add_stronger off, a password session (1.0): a security key (3.5)
        # is stronger → ask your admin; certificates always.
        self.assertNotIn("portcullis-set-up-security-key", b)
        self.assertIn(f'<a id="portcullis-sign-in-methods" href="{acct}">Sign-in methods</a>', b)
        self.assertIn('<span class="portcullis-sub">or ask your admin</span>', b)
        # add_stronger on: Set up a security key (certificate still ask your admin).
        b = gg.render_needs_page("Grafana", {"password"}, STRONG, {"password"}, True, "example.com").decode()
        self.assertIn(f'<a id="portcullis-set-up-security-key" class="btn" href="{acct}">Set up a security key</a>', b)
        self.assertIn("or ask your admin", b)
        # Nothing counted; device-bound / synced missing → Set up a passkey.
        rule = {"op": "all", "items": ["passkey_device", "security_key"]}
        b = gg.render_needs_page("App", set(), rule, set(), True, "example.com").decode()
        self.assertIn("Your sign-in doesn&#x27;t count for App yet. App accepts any one of:", b)
        self.assertIn("<li>a device-bound passkey and a security key <span", b)
        self.assertIn("Set up a passkey</a>", b)
        self.assertIn("Set up a security key</a>", b)
        self.assertNotIn("ask your admin", b)
        # Signed-in words bold, joined with "and", in the table's order.
        b = gg.render_needs_page("App", {"security_key", "passkey_synced"}, {"op": "all", "items": ["yubikey_cert", "security_key"]},
                                 {"security_key"}, False, "example.com").decode()
        self.assertIn("You signed in with a <b>passkey</b> and a <b>security key</b>.", b)
        self.assertIn("<li>a security key and a YubiKey certificate</li>", b)
        # A person `people` doesn't know: no "you don't have one yet".
        b = gg.render_needs_page("App", set(), rule, None, True, "example.com").decode()
        self.assertNotIn("have one yet", b)
        # Every phrase is the extension's message (portcullisMethod_<id>).
        self.assertEqual(gg.METHOD_WORDS, {"password": "password", "passkey_synced": "passkey",
                                           "browser_cert": "browser certificate", "passkey_device": "device-bound passkey",
                                           "security_key": "security key", "yubikey_cert": "YubiKey certificate",
                                           "passkey": "passkey"})

    def test_alpha_pc_method_allowlist(self):
        with open(ALPHA) as f:
            text = f.read()
        self.assertNotIn("acr_values", text.split("loginURLParameters:")[1].split("server:")[0].replace("# acr", ""))
        params = {}
        name = None
        for line in text.split("loginURLParameters:")[1].split("\nserver:")[0].splitlines():
            stripped = line.strip()
            if stripped.startswith("- name:"):
                name = stripped.split(":", 1)[1].strip()
                params[name] = []
            elif stripped.startswith("- value:") and name:
                params[name].append(stripped.split(":", 1)[1].strip())
            elif stripped.startswith("default:"):
                params.setdefault("__default__", []).append(name)
        self.assertEqual(sorted(params), ["kc_idp_hint", "pc_method", "prompt"])
        self.assertEqual(params["pc_method"], ["password", "passkey_synced", "browser_cert", "passkey_device",
                                               "security_key", "yubikey_cert", "passkey"])
        self.assertEqual(set(params["pc_method"]), gg.STEPUP_METHODS)
        self.assertEqual(params["kc_idp_hint"], ["portcullis-invite"])
        self.assertEqual(params["prompt"], ["login"])


def token(**claims):
    """A well-formed JWT with a dummy signature (group-gate never verifies it:
    oauth2-proxy did)."""
    import base64
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'RS256', 'typ': 'JWT'})}.{b64(claims)}.c2lnbmF0dXJl"


ADMIN_RULES = {"version": 6,
               "groups": {"vw.example.com": "users_vw"},
               "path_groups": {"vw.example.com": [{"prefix": "/admin", "group": "admin_vw"},
                                      {"prefix": "/admin/super", "group": "super_vw"},
                                      {"prefix": "/api/admin/", "group": "admin_vw"}]}}


class PathGroupsTest(GateTest):
    def r(self, uri, groups="users_vw"):
        write_policy(ADMIN_RULES)
        return self.req("vw.example.com", groups=groups, uri=uri)

    def test_normalisation(self):
        n = gg.normalize_path_candidates
        self.assertEqual(n("/a//b/./c/../d?x=/admin")[0], "/a/b/d")
        for bad in ("/a#frag", "/a?x=1#frag", "/a%23b"):
            with self.assertRaises(gg.PathError):
                n(bad)
        self.assertEqual(n("/%61dmin")[0], "/admin")
        self.assertEqual(n("")[0], "/")
        self.assertEqual(n("/x/..")[0], "/")
        self.assertEqual(n("/../../admin")[0], "/admin")
        self.assertEqual(n("http://h/admin?q")[0], "/admin")
        with self.assertRaises(gg.PathError):              # absolute-form keeps its "\n"
            n("http://h/admin\n")
        self.assertIn("/admin", n("/%2561dmin"))           # double-decoding backends
        self.assertIn("/admin/x", n("/admin;jsessionid=1/x"))
        self.assertIn("/admin", n("/x\\..\\admin"))
        # One decode turns %2f into a real "/" (matched as such, deny-biased);
        # what is still encoded after that, NULs and controls are rejected.
        self.assertEqual(n("/foo/..%2fadmin")[0], "/admin")
        for bad in ("/a%00", "/a%252fb", "/a%255Cb", "/a%2500", "/%0a", "/%ff", "/a\x00b"):
            with self.subTest(bad=bad):
                with self.assertRaises(gg.PathError):
                    n(bad)

    def test_prefix_segment_boundary_and_longest_wins(self):
        rules = [("/admin", "a"), ("/admin/super", "s")]
        self.assertEqual(gg.required_path_groups(rules, ["/admin"]), ["a"])
        self.assertEqual(gg.required_path_groups(rules, ["/admin/x"]), ["a"])
        self.assertEqual(gg.required_path_groups(rules, ["/administrator"]), [])
        self.assertEqual(gg.required_path_groups(rules, ["/admin/super/x"]), ["s"])
        self.assertEqual(gg.required_path_groups([("/", "root")], ["/anything"]), ["root"])

    def test_group_required_in_addition_to_subdomain_group(self):
        self.assertEqual(self.r("/", groups="users_vw"), 200)
        self.assertEqual(self.r("/administrator", groups="users_vw"), 200)
        self.assertEqual(self.r("/admin", groups="users_vw"), 403)
        self.assertEqual(self.r("/admin", groups="admin_vw"), 403)      # lacks users_vw
        self.assertEqual(self.r("/admin", groups="users_vw,admin_vw"), 200)
        self.assertEqual(self.r("/admin/super/x", groups="users_vw,admin_vw"), 403)
        self.assertEqual(self.r("/admin/super/x", groups="users_vw,super_vw"), 200)
        self.assertEqual(self.r("/api/admin/users", groups="users_vw"), 403)

    def test_bypass_attempts_denied(self):
        for uri in ("/admin/../admin", "//admin", "/./admin", "/x/../admin/", "/%61dmin",
                    "/%2561dmin", "/Admin", "/ADMIN/x", "/admin?", "/admin#x", "/admin;x=1",
                    "/foo/..%2fadmin", "/admin%2f", "/%2e%2e/admin", "/.%2e/admin",
                    "/x\\..\\admin", "/admin%00", "admin", "/api//admin/x"):
            with self.subTest(uri=uri):
                self.assertEqual(self.r(uri, groups="users_vw"), 403)

    def test_missing_uri_is_root(self):
        write_policy(ADMIN_RULES)
        self.assertEqual(self.req("vw.example.com", groups="users_vw"), 200)

    def test_malformed_rules_fail_closed(self):
        for pg in ([], {"vw.example.com": {"prefix": "/a"}}, {"vw.example.com": [{"prefix": "admin", "group": "g"}]},
                   {"vw.example.com": [{"prefix": "/a", "group": ""}]}, {"vw.example.com": ["x"]},
                   {"vw.example.com": [{"prefix": "/a/../b", "group": "g"}]}, {"vw.example.com": [{"prefix": "/%61", "group": "g"}]}):
            with self.subTest(pg=pg):
                write_policy({"groups": {"vw.example.com": "users_vw"}, "path_groups": pg}, malformed=not isinstance(pg, dict))
                self.assertEqual(self.req("vw.example.com", groups="users_vw", uri="/"), 403)

    def test_key_that_is_not_a_valid_hostname_denies(self):
        # Host keys are lowercase full hostnames; anything else (an uppercase
        # key, a bare v4-style subdomain, a port, a wildcard) denies.
        for key in ("VW.example.com", "vw", "vw.example.com:443", "*.example.com", "vw.example.com."):
            for m in ("path_groups", "groups", "hosts", "public_paths"):
                with self.subTest(key=key, map=m):
                    val = {"path_groups": [{"prefix": "/admin", "group": "admin_vw"}], "groups": "users_vw",
                           "hosts": "standard", "public_paths": {"paths": [{"path": "/s", "match": "prefix"}]}}[m]
                    write_policy({m: {key: val}}, malformed=True)
                    self.assertEqual(self.req("vw.example.com", groups="users_vw,admin_vw", uri="/"), 403)
                    self.assertEqual(self.req("random.example.com", groups=""), 403)

    def test_core_subdomains_ignore_hub_path_rules(self):
        write_policy({"path_groups": {"hub.example.com": [{"prefix": "/", "group": "nobody"}]}})
        self.assertEqual(self.req("hub.example.com", groups="lldap_admin", uri="/x"), 200)




# ── Revocation ────────────────────────────────────────────────────────

def cert_info(*serials, encode_times=1):
    """Build X-Forwarded-Tls-Client-Cert-Info the way Traefik does."""
    parts = [f'Subject="CN=alice";Issuer="CN=example.com Intermediate CA";'
             f'SerialNumber="{sn}";NB="1700000000";NA="1700086400"' for sn in serials]
    value = ",".join(parts)
    for _ in range(encode_times):
        value = urllib.parse.quote_plus(value)
    return value


def write_revoked(lines):
    if lines is None:
        if os.path.exists(REVOKED):
            os.remove(REVOKED)
        return
    with open(REVOKED, "w") as f:
        f.write("\n".join(lines) + "\n")


def _der(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + content


def _der_int(n):
    return _der(0x02, n.to_bytes(n.bit_length() // 8 + 1, "big", signed=True))


def build_crl(serials, with_next_update=True, with_version=True, next_update=None):
    """Structurally valid (unsigned) X.509 v2 CRL. next_update: DER time
    element (default: the UTCTime used for thisUpdate)."""
    alg = _der(0x30, _der(0x06, bytes.fromhex("2a8648ce3d040302")))  # ecdsa-with-SHA256
    issuer = _der(0x30, _der(0x31, _der(0x30, _der(0x06, b"\x55\x04\x03") + _der(0x0C, b"Test CA"))))
    t = _der(0x17, b"250101000000Z")
    nu = next_update or t
    tbs = (_der_int(1) if with_version else b"") + alg + issuer + t + (nu if with_next_update else b"")
    if serials:
        tbs += _der(0x30, b"".join(_der(0x30, _der_int(sn) + t) for sn in serials))
    tbs += _der(0xA0, _der(0x30, b""))  # crlExtensions
    return _der(0x30, _der(0x30, tbs) + alg + _der(0x03, b"\x00\x01\x02"))


PUBLIC_DOC = {
    "version": 6,
    "public_paths": {
        "cloud.example.com": {
            "paths": [
                {"path": "/s/{token}", "match": "prefix"},
                {"path": "/public.php/dav/files/{token}", "match": "prefix"},
                {"path": "/dist", "match": "static"},
                {"path": "/core/mimeicon", "match": "exact"},
                {"path": "/apps/text/public", "match": "prefix"},
            ],
            "token_pattern": "^[A-Za-z0-9-]{1,32}$",
            "static_extensions": ["css", "js", "svg"],
            "credential_headers": ["X-Api-Key"],
            "credential_cookies": ["nc_token", "nc_username"],
            "credential_query": ["auth_token", "apiKey"],
        }
    },
}


class PhpVarNameTest(unittest.TestCase):
    """php_register_variable_ex() (php-src main/php_variables.c)."""

    def test_mangling(self):
        for raw, want in [
            (b"nc_token", b"nc_token"), (b"nc.token", b"nc_token"), (b"nc token", b"nc_token"),
            (b" nc_token", b"nc_token"), (b"   nc.token", b"nc_token"), (b"nc[token", b"nc_token"),
            (b"nc[to.ken", b"nc_to_ken"), (b"nc[to[ken", b"nc_to_ken"), (b"nc_token[]", b"nc_token"),
            (b"nc_token[x]", b"nc_token"), (b"nc_token[ ]", b"nc_token"), (b"nc_token[x][y]", b"nc_token"),
            (b"nc_token\0junk", b"nc_token"), (b"nc+token", b"nc+token"), (b"", b""),
        ]:
            with self.subTest(raw=raw):
                self.assertEqual(gg.php_var_name(raw), want)


class PublicGuardTest(GateTest):
    def guard(self, uri, host="cloud.example.com", headers=()):
        """Raw request: repeated headers (several Cookie lines) allowed."""
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.putrequest("GET", "/public-guard", skip_accept_encoding=True)
        c.putheader("X-Forwarded-Host", host)
        c.putheader("X-Forwarded-Uri", uri)
        for k, v in headers:
            c.putheader(k, v)
        c.endheaders()
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def setUp(self):
        write_policy(PUBLIC_DOC)

    def test_allowed(self):
        for uri in ["/s/AbC123", "/s/AbC123/", "/s/AbC123/download?files=a.txt", "/public.php/dav/files/AbC123/x.txt",
                    "/dist/core-common.js", "/dist/x/y.min.css", "/core/mimeicon?mime=text", "/apps/text/public/session/1",
                    "/s/AbC123?x=1&nc_tokens=2", "/s/AbC123?nc=token"]:
            with self.subTest(uri=uri):
                self.assertEqual(self.guard(uri, headers=[("Cookie", "oc123=sess; nc_sameSiteCookielax=true")]), 200)

    def test_path_outside(self):
        for uri in ["/", "/s", "/sx/AbC", "/s/a.b", "/s/..", "/s/AbC/../../apps/files", "/s/%2e%2e/apps",
                    "/s/AbC%2Fx", "/dist", "/dist/", "/dist/a", "/dist/a.php", "/dist/a.php/b.js", "/dist/x.y/a.js",
                    "/core/mimeicon/x", "/apps/text", "/index.php/s/AbC", "/S/AbC", "/s/AbC%00", "/s/%C0%AE%C0%AE/x",
                    "/s/" + "a" * 40]:
            with self.subTest(uri=uri):
                self.assertEqual(self.guard(uri), 403)

    def test_credential_headers(self):
        for h in [("Authorization", "Basic YWRtaW46YWRtaW4="), ("authorization", "Bearer x"), ("Proxy-Authorization", "x"),
                  ("X-Api-Key", "k"), ("x_api_key", "k"), ("Authorization", "")]:
            with self.subTest(h=h):
                self.assertEqual(self.guard("/s/AbC123", headers=[h]), 403)

    def test_credential_cookies(self):
        for cookie in ["nc_token=x", "a=1; nc_token=x", "a=1;nc_token=x", " nc_token=x", "nc.token=x", "nc token=x",
                       "nc[token=x", "nc_token[]=x", "nc_token[x]=y", "NC_TOKEN=x", "Nc.ToKeN=x", "nc+token=x",
                       "nc%5Ftoken=x", "%6Ec_token=x", "nc%2Etoken=x", "nc_username=bob", "a=1, nc_token=x",
                       "\tnc_token=x", "nc_token"]:
            with self.subTest(cookie=cookie):
                self.assertEqual(self.guard("/s/AbC123", headers=[("Cookie", cookie)]), 403)
        # Split over several Cookie headers, and duplicates.
        self.assertEqual(self.guard("/s/AbC123", headers=[("Cookie", "a=1"), ("Cookie", "nc_token=x")]), 403)
        self.assertEqual(self.guard("/s/AbC123", headers=[("Cookie", "nc_token=x; nc_token=y")]), 403)
        # Overlong UTF-8 / control characters in a name: refused.
        self.assertEqual(self.guard("/s/AbC123", headers=[("Cookie", "nc%C0%AEtoken=x")]), 403)

    def test_credential_query(self):
        for q in ["auth_token=x", "auth.token=x", "auth+token=x", "auth%20token=x", "+auth_token=x", "%20auth_token=x",
                  "auth[token=x", "auth_token[]=x", "auth_token[x]=y", "AUTH_TOKEN=x", "%61uth_token=x",
                  "a=1&auth_token=x", "a=1;auth_token=x", "auth_token", "apiKey=k", "apikey=k", "auth_token%00x=1",
                  "auth%C0%AEtoken=1"]:
            with self.subTest(q=q):
                self.assertEqual(self.guard("/s/AbC123?" + q), 403)

    def test_fail_closed(self):
        pp = PUBLIC_DOC["public_paths"]
        for doc in [None, {}, {"version": 3, "public_paths": pp},
                    {"version": 4, "public_paths": pp},
                    {"version": 4, "public_paths": {"cloud": pp["cloud.example.com"]}},
                    {"version": 5, "public_paths": pp},
                    dict(BASE, public_paths=pp, version=6.0),
                    '{"version": 6.0, %s' % json.dumps(dict({k: v for k, v in BASE.items() if k != "version"}, public_paths=pp))[1:],
                    {"public_paths": pp}, dict(BASE),
                    dict(BASE, public_paths=[]),
                    dict(BASE, public_paths={"cloud.example.com": {"paths": [{"path": "/s", "match": "prefix"}], "extra": 1}}),
                    dict(BASE, public_paths={"cloud.example.com": {"paths": []}}),
                    dict(BASE, public_paths={"cloud.example.com": {"paths": [{"path": "/s/{token}", "match": "prefix"}]}}),
                    dict(BASE, public_paths={"cloud.example.com": {"paths": [{"path": "/s/../x", "match": "prefix"}]}}),
                    dict(BASE, public_paths={"cloud.example.com": {"paths": [{"path": "/s", "match": "regex"}]}}),
                    # A v6 file broken elsewhere (a rule) denies the guard too.
                    dict(BASE, public_paths=pp, templates={"standard": {"op": "any", "items": ["webauthn"]}, "strong": STRONG}),
                    "not json"]:
            with self.subTest(doc=doc):
                write_policy(doc, raw=True)
                self.assertEqual(self.guard("/s/AbC123"), 403)
        write_policy(PUBLIC_DOC)
        for host in ["other.example.com", "cloud.evil.com", "hub.example.com", ""]:
            with self.subTest(host=host):
                self.assertEqual(self.guard("/s/AbC123", host=host), 403)

    def test_fragment_and_encoded_hash(self):
        for uri in ["/s/AbC123#x", "/s/AbC123?a=1#nc_token=x", "/s/AbC123#?nc_token=x", "/s/Ab%23C", "/dist/a%23.js", "/s/AbC123/%23"]:
            with self.subTest(uri=uri):
                self.assertEqual(self.guard(uri), 403)
        # The query is everything after the first '?'.
        self.assertEqual(self.guard("/s/AbC123?x=1?auth_token=y"), 200)  # key "x", value "1?auth_token=y"
        self.assertEqual(self.guard("/s/AbC123?x=1&auth_token=y"), 403)

    def test_logs_hide_tokens_values_and_credentials(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.guard("/s/SeCrEtToKeN42/../../x?apiKey=S3cr3tValue&q=PlainValue",
                       headers=[("Cookie", "nc_token=CookieSecret"), ("Authorization", "Basic QmFzaWNTZWNyZXQ=")])
            self.guard("/s/SeCrEtToKeN42?apiKey=S3cr3tValue", headers=[("Cookie", "nc_token=CookieSecret")])
            self.guard("/s/SeCrEtToKeN42", headers=[("Authorization", "Basic QmFzaWNTZWNyZXQ=")])
            write_policy({"version": 6, "path_groups": {"cloud.example.com": [{"prefix": "/admin", "group": "admin_x"}]}})
            self.req("cloud.example.com", uri="/admin/SeCrEtToKeN42?apiKey=S3cr3tValue")
            self.req("cloud.example.com", uri="/admin/%2fSeCrEtToKeN42?apiKey=S3cr3tValue")
        out = buf.getvalue()
        self.assertIn("DENIED", out)
        for secret in ["SeCrEtToKeN42", "S3cr3tValue", "PlainValue", "CookieSecret", "QmFzaWNTZWNyZXQ="]:
            self.assertNotIn(secret, out)
        self.assertIn("apiKey", out)  # parameter names are logged

    def test_no_identity_headers_returned(self):
        status, hdrs = self.req("cloud.example.com", uri="/s/AbC123", gate_path="/public-guard", want_headers=True)
        self.assertEqual(status, 200)
        self.assertFalse([k for k in hdrs if k.lower().startswith(("x-forwarded-user", "x-auth-request"))])


ATTRS = os.path.join(TMP, "user-attributes.json")


def write_attrs(doc):
    if doc is None:
        if os.path.exists(ATTRS):
            os.remove(ATTRS)
        return
    tmp = ATTRS + ".tmp"
    with open(tmp, "w") as f:
        f.write(doc if isinstance(doc, str) else json.dumps(doc))
    os.replace(tmp, ATTRS)


PAST = "2020-01-01T00:00:00Z"
FUTURE = "2999-12-31T23:59:59Z"


class PolicyExpiringTest(GateTest):
    """Policy file `expiring` (contract §4); the `*` map value (§5.1)."""

    def setUp(self):
        super().setUp()
        write_attrs(None)

    def tearDown(self):
        write_attrs(None)

    def test_policy_v4_and_older_refused(self):
        for doc in ({"version": 4}, {"version": 4, "groups": {"grafana": "users_grafana"}},
                    {"version": 4, "groups": {"grafana.example.com": "users_grafana"}},
                    {"version": 3}, {"version": 3, "groups": {"grafana.example.com": "users_grafana"}}):
            with self.subTest(doc=doc):
                write_policy(doc, malformed=True)
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
                self.assertEqual(self.req("random.example.com", groups=""), 403)
        write_policy({"version": 6})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 200)

    def test_expired_membership_stripped(self):
        write_policy({"version": 6, "groups": {"app.example.com": "b"},
                      "expiring": [{"user": "bob", "group": "b", "at": PAST}]})
        self.assertEqual(self.req("app.example.com", groups="a,b"), 403)
        write_policy({"version": 6, "groups": {"app.example.com": "a"},
                      "expiring": [{"user": "bob", "group": "b", "at": PAST}]})
        status, hdrs = self.req("app.example.com", groups="a,b", want_headers=True)
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("X-Auth-Request-Groups"), "a")
        # Usernames in the file are lowercase; the session's case doesn't matter.
        status, hdrs = self.req("app.example.com", groups="a,b", want_headers=True,
                                extra={"X-Auth-Request-Preferred-Username": "Bob"})
        self.assertEqual(hdrs.get("X-Auth-Request-Groups"), "a")
        # Another user's expiry, or another group's, changes nothing.
        write_policy({"version": 6, "groups": {"app.example.com": "b"},
                      "expiring": [{"user": "alice", "group": "b", "at": PAST},
                                   {"user": "bob", "group": "c", "at": PAST}]})
        status, hdrs = self.req("app.example.com", groups="a,b", want_headers=True)
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("X-Auth-Request-Groups"), "a,b")
        # Path groups and the core map see the stripped set too.
        write_policy({"version": 6, "path_groups": {"app.example.com": [{"prefix": "/admin", "group": "admin_app"}]},
                      "expiring": [{"user": "bob", "group": "admin_app", "at": PAST},
                                   {"user": "bob", "group": "lldap_admin", "at": PAST}]})
        self.assertEqual(self.req("app.example.com", groups="admin_app", uri="/admin"), 403)
        self.assertEqual(self.req("hub.example.com", groups="lldap_admin"), 403)
        # Only every group expired: no X-Auth-Request-Groups at all.
        status, hdrs = self.req("enroll.example.com", groups="lldap_admin", gate_path="/authenticated",
                                want_headers=True)
        self.assertEqual(status, 200)
        self.assertNotIn("X-Auth-Request-Groups", hdrs)

    def test_token_headers_echoed_unless_membership_expired(self):
        jwt_ = token(amr=["hwk"], preferred_username="bob")
        tok = {"Authorization": f"Bearer {jwt_}", "X-Forwarded-Access-Token": jwt_}
        write_policy({"version": 6, "groups": {"app.example.com": "a"},
                      "expiring": [{"user": "bob", "group": "b", "at": FUTURE}]})
        status, hdrs = self.req("app.example.com", groups="a,b", extra=tok, want_headers=True)
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("Authorization"), f"Bearer {jwt_}")
        self.assertEqual(hdrs.get("X-Forwarded-Access-Token"), jwt_)
        # Keycloak console routes: the console's own bearer, echoed as-is
        # (the session's methods come from X-Forwarded-Access-Token only).
        status, hdrs = self.req("auth.example.com", groups="lldap_admin", want_headers=True,
                                extra={"Authorization": "Bearer console"})
        self.assertEqual((status, hdrs.get("Authorization")), (200, "Bearer console"))
        # A forged bearer on that route never stands in for the session.
        status = self.req("auth.example.com", groups="lldap_admin", extra={
            "Authorization": "Bearer " + token(amr=["hwk"], preferred_username="bob"),
            "X-Forwarded-Access-Token": None})
        self.assertEqual(status, 403)
        # An expired membership was stripped: the token still names it, so
        # neither token header is returned (Traefik deletes them).
        write_policy({"version": 6, "groups": {"app.example.com": "a"},
                      "expiring": [{"user": "bob", "group": "b", "at": PAST}]})
        status, hdrs = self.req("app.example.com", groups="a,b", extra=tok, want_headers=True)
        self.assertEqual(status, 200)
        self.assertNotIn("Authorization", hdrs)
        self.assertNotIn("X-Forwarded-Access-Token", hdrs)
        self.assertEqual(hdrs.get("X-Auth-Request-Groups"), "a")
        # An expiry for a group the token doesn't carry changes nothing.
        status, hdrs = self.req("app.example.com", groups="a", extra=tok, want_headers=True)
        self.assertEqual(hdrs.get("Authorization"), f"Bearer {jwt_}")

    def test_not_yet_expired_kept(self):
        write_policy({"version": 6, "groups": {"app.example.com": "b"},
                      "expiring": [{"user": "bob", "group": "b", "at": FUTURE}]})
        status, hdrs = self.req("app.example.com", groups="a,b", want_headers=True)
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("X-Auth-Request-Groups"), "a,b")
        # The boundary: absent once now >= at.
        doc = {"version": 6, "expiring": [{"user": "bob", "group": "b", "at": "2030-01-01T00:00:00Z"}]}
        at = 1893456000.0
        self.assertEqual(gg.expired_groups(doc, "bob", now=at - 1), set())
        self.assertEqual(gg.expired_groups(doc, "bob", now=at), {"b"})

    def test_malformed_expiring_fails_closed(self):
        for exp in ({}, ["x"], [{"user": "bob", "group": "b"}], [{"user": "bob", "group": "b", "at": "tomorrow"}],
                    [{"user": "bob", "group": "b", "at": "2030-01-01T00:00:00"}],  # no offset
                    [{"user": "bob", "group": "b", "at": 1}], [{"user": "", "group": "b", "at": FUTURE}],
                    [{"user": "bob", "group": "b", "at": FUTURE, "extra": 1}]):
            with self.subTest(expiring=exp):
                write_policy({"version": 6, "expiring": exp}, malformed=True)
                self.assertEqual(self.req("random.example.com", groups="a"), 403)
        # Positive control: a well-formed `expiring` allows the same request.
        write_policy({"version": 6, "expiring": [{"user": "bob", "group": "b", "at": FUTURE}]})
        self.assertEqual(self.req("random.example.com", groups="a"), 200)

    def test_star_any_signed_in(self):
        self.assertEqual(gg.load_static_map().get("people"), "*")
        self.assertEqual(self.req("people.example.com", groups=""), 200)
        self.assertEqual(self.req("people.example.com", groups=None), 200)
        self.assertEqual(self.req("people.example.com", groups="users_x"), 200)
        # No session (no portcullis-auth username): denied.
        self.assertEqual(self.req("people.example.com", groups="lldap_admin",
                                  extra={"X-Auth-Request-Preferred-Username": None}), 403)
        self.assertEqual(self.req("people.example.com", groups="",
                                  extra={"X-Auth-Request-Preferred-Username": "portcullis-hub"}), 403)
        # A core subdomain: the policy file can't restrict or reassign it.
        write_policy({"version": 6, "groups": {"people.example.com": "lldap_admin"},
                      "path_groups": {"people.example.com": [{"prefix": "/", "group": "lldap_admin"}]}})
        self.assertEqual(self.req("people.example.com", groups="users_x"), 200)

    def test_star_ignored_in_policy_file(self):
        write_policy({"version": 6, "groups": {"grafana.example.com": "*", "newapp.example.com": "*"}})
        # grafana keeps map.conf's group; newapp falls back to no mapping.
        self.assertEqual(self.req("grafana.example.com", groups="users_x"), 403)
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 200)
        self.assertEqual(gg.build_group_map(gg.load_policy_file()).get("newapp"), None)
        # Holding a group literally named "*" never satisfies anything.
        self.assertEqual(self.req("grafana.example.com", groups="*"), 403)
        # In path_groups it is a malformed rule: fail closed.
        write_policy({"version": 6, "path_groups": {"grafana.example.com": [{"prefix": "/x", "group": "*"}]}})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana,*", uri="/y"), 403)

    def test_attribute_headers(self):
        write_attrs({"version": 2,
                     "fields": {"city": "City", "cost_center": "Cost-Center", "bio": "Bio", "dept": "Dept"},
                     "users": {"bob": {"city": ["Milan"], "cost_center": ["CC-1", "CC-2"],
                                       "bio": ["evil\r\nX-Injected: 1\x00\x7f"],
                                       "dept": ["x" * 1025, "ok"]},
                               "alice": {"city": ["Berlin"]}}})
        status, hdrs = self.req("grafana.example.com", groups="users_grafana", want_headers=True)
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("X-Forwarded-Attr-City"), "Milan")
        self.assertEqual(hdrs.get("X-Forwarded-Attr-Cost-Center"), "CC-1, CC-2")
        self.assertEqual(hdrs.get("X-Forwarded-Attr-Bio"), "evilX-Injected: 1")
        self.assertNotIn("X-Injected", hdrs)
        self.assertEqual(hdrs.get("X-Forwarded-Attr-Dept"), "ok")  # > 1 KB value dropped
        # Core subdomains and /authenticated get them too.
        for host, groups, path in (("hub.example.com", "lldap_admin", "/"), ("people.example.com", "", "/"),
                                   ("enroll.example.com", "", "/authenticated")):
            with self.subTest(host=host):
                status, hdrs = self.req(host, groups=groups, gate_path=path, want_headers=True)
                self.assertEqual((status, hdrs.get("X-Forwarded-Attr-City")), (200, "Milan"))
        # Never on a deny, nor for users absent from the file.
        status, hdrs = self.req("grafana.example.com", groups="users_x", want_headers=True)
        self.assertEqual(status, 403)
        self.assertFalse([k for k in hdrs if k.lower().startswith("x-forwarded-attr-")])
        status, hdrs = self.req("grafana.example.com", groups="users_grafana", want_headers=True,
                                extra={"X-Auth-Request-Preferred-Username": "carol"})
        self.assertEqual(status, 200)
        self.assertFalse([k for k in hdrs if k.lower().startswith("x-forwarded-attr-")])
        # `%` and `,` are percent-encoded in every value (single ones too), so
        # the ", " separator is unambiguous.
        write_attrs({"version": 2, "fields": {"name": "Name", "quota": "Quota"},
                     "users": {"bob": {"name": ["Doe, Jane", "Roe,Rick"], "quota": ["100%,%2C"]}}})
        status, hdrs = self.req("grafana.example.com", groups="users_grafana", want_headers=True)
        self.assertEqual(hdrs.get("X-Forwarded-Attr-Name"), "Doe%2C Jane, Roe%2CRick")
        self.assertEqual(hdrs.get("X-Forwarded-Attr-Quota"), "100%25%2C%252C")
        self.assertEqual([urllib.parse.unquote(v) for v in hdrs["X-Forwarded-Attr-Name"].split(", ")],
                         ["Doe, Jane", "Roe,Rick"])
        # Non-ASCII values travel as UTF-8 bytes.
        write_attrs({"version": 2, "fields": {"city": "City"}, "users": {"bob": {"city": ["Zürich", "東京"]}}})
        status, hdrs = self.req("grafana.example.com", groups="users_grafana", want_headers=True)
        self.assertEqual(hdrs.get("X-Forwarded-Attr-City").encode("latin-1").decode("utf-8"), "Zürich, 東京")

    def test_invalid_attribute_field_skipped_not_file(self):
        # A field the Hub's rule now forbids (dept_ -> "Dept-", a__b ->
        # "A--B", an over-long name) is skipped; the other fields still
        # produce their headers.
        long_name = "a" * 32
        write_attrs({"version": 2,
                     "fields": {"city": "City", "dept_": "Dept-", "a__b": "A--B", long_name: "A" * 32,
                                "Bad": "Bad", "ok_1": "Ok-1"},
                     "users": {"bob": {"city": ["Milan"], "dept_": ["x"], "a__b": ["y"], long_name: ["z"],
                                       "Bad": ["w"], "ok_1": ["v"]}}})
        status, hdrs = self.req("grafana.example.com", groups="users_grafana", want_headers=True)
        self.assertEqual(status, 200)
        attrs = {k: v for k, v in hdrs.items() if k.lower().startswith("x-forwarded-attr-")}
        self.assertEqual(attrs, {"X-Forwarded-Attr-City": "Milan", "X-Forwarded-Attr-Ok-1": "v"})
        self.assertEqual(sorted(gg.parse_user_attributes(
            {"version": 2, "fields": {"city": "City", "dept_": "Dept-"},
             "users": {"bob": {"city": ["Milan"], "dept_": ["x"]}}})[0]["bob"]),
            [("X-Forwarded-Attr-City", "Milan")])

    def test_attribute_field_or_header_with_trailing_newline_skipped(self):
        # Python's "$" also matches before a trailing "\n": validation must
        # use fullmatch, so "city\n" / "City\n" are skipped like any other
        # invalid field, and no header is emitted for them.
        doc = {"version": 2, "fields": {"city\n": "City", "dept": "Dept\n", "ok": "Ok"},
               "users": {"bob": {"city\n": ["Milan"], "dept": ["x"], "ok": ["v"]}}}
        self.assertEqual(gg.parse_user_attributes(doc)[0]["bob"], [("X-Forwarded-Attr-Ok", "v")])
        write_attrs(doc)
        status, hdrs = self.req("grafana.example.com", groups="users_grafana", want_headers=True)
        self.assertEqual(status, 200)
        attrs = {k: v for k, v in hdrs.items() if k.lower().startswith("x-forwarded-attr-")}
        self.assertEqual(attrs, {"X-Forwarded-Attr-Ok": "v"})
        doc = {"version": 2, "fields": {"city": "City\n"}, "users": {"bob": {"city": ["Milan"]}}}
        self.assertEqual(gg.parse_user_attributes(doc), ({}, {}, {}))

    def test_rfc3339_rejects_trailing_newline(self):
        self.assertGreater(gg._parse_rfc3339("2030-01-01T00:00:00Z"), 0)
        for bad in ("2030-01-01T00:00:00Z\n", "2030-01-01T00:00:00+00:00\n"):
            with self.assertRaises(ValueError):
                gg._parse_rfc3339(bad)

    def test_attribute_headers_missing_or_corrupt_file_never_denies(self):
        for doc in (None, "{not json", [], {"version": 3, "fields": {"city": "City"}, "users": {"bob": {"city": ["Milan"]}}},
                    {"version": 2, "fields": {"city": "City\r\nX: y"}, "users": {"bob": {"city": ["Milan"]}}},
                    {"version": 2, "fields": {"city": "City"}, "users": {"bob": {"city": "Milan"}}},
                    {"version": 2, "fields": {"City!": "City"}, "users": {"bob": {"City!": ["Milan"]}}},
                    {"version": 2, "fields": [], "users": {}},
                    # two fields on one header (header names are case-insensitive)
                    {"version": 2, "fields": {"city": "City", "town": "CITY"},
                     "users": {"bob": {"city": ["Milan"], "town": ["Rome"]}}}):
            with self.subTest(doc=doc):
                write_attrs(doc)
                status, hdrs = self.req("grafana.example.com", groups="users_grafana", want_headers=True)
                self.assertEqual(status, 200)
                self.assertFalse([k for k in hdrs if k.lower().startswith("x-forwarded-attr-")])

    def test_no_attribute_headers_on_public_guard(self):
        write_attrs({"version": 2, "fields": {"city": "City"}, "users": {"bob": {"city": ["Milan"]}}})
        write_policy(PUBLIC_DOC)
        status, hdrs = self.req("cloud.example.com", uri="/s/AbC123", gate_path="/public-guard", want_headers=True)
        self.assertEqual(status, 200)
        self.assertFalse([k for k in hdrs if k.lower().startswith("x-forwarded-attr-")])
        write_policy(dict(PUBLIC_DOC, version=4), malformed=True)
        self.assertEqual(self.req("cloud.example.com", uri="/s/AbC123", gate_path="/public-guard"), 403)


    # ── user-attributes.json v2: per-host headers (contract §4.1) ──
    # (The test domain is example.com: hosts outside it are never served.)
    GRAFANA = "grafana.example.com"

    def attrs_for(self, user, host, groups="users_grafana,users_other"):
        status, hdrs = self.req(host, groups=groups, want_headers=True,
                                extra={"X-Auth-Request-Preferred-Username": user})
        self.assertEqual(status, 200)
        return {k: v for k, v in hdrs.items() if k.lower().startswith("x-forwarded-attr-")}

    def logged_parse(self, doc):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = gg.parse_user_attributes(doc)
        return result, buf.getvalue()

    def test_attributes_v2_host_headers(self):
        write_attrs({"version": 2, "fields": {"department": "Department"},
                     "users": {"alice": {"department": ["Engineering"]}},
                     "hosts": {self.GRAFANA: {"Grafana-Role": {"alice": "Admin", "bob": "Editor"}}}})
        self.assertEqual(self.attrs_for("alice", self.GRAFANA),
                         {"X-Forwarded-Attr-Grafana-Role": "Admin", "X-Forwarded-Attr-Department": "Engineering"})
        # Usernames match case-insensitively; the request host is normalised.
        self.assertEqual(self.attrs_for("Bob", "Grafana.Example.com.:443"), {"X-Forwarded-Attr-Grafana-Role": "Editor"})
        # Never on a deny.
        status, hdrs = self.req(self.GRAFANA, groups="users_x", want_headers=True,
                                extra={"X-Auth-Request-Preferred-Username": "alice"})
        self.assertEqual(status, 403)
        self.assertFalse([k for k in hdrs if k.lower().startswith("x-forwarded-attr-")])

    def test_host_header_only_on_its_host(self):
        write_attrs({"version": 2, "fields": {"department": "Department"},
                     "users": {"alice": {"department": ["Engineering"]}},
                     "hosts": {self.GRAFANA: {"Grafana-Role": {"alice": "Admin"}}}})
        self.assertEqual(self.attrs_for("alice", "other.example.com"), {"X-Forwarded-Attr-Department": "Engineering"})
        # A user absent from the host map gets only the field headers there.
        self.assertEqual(self.attrs_for("carol", self.GRAFANA), {})

    def test_attributes_v1_refused(self):
        for doc in ({"version": 1, "fields": {"department": "Department"},
                     "users": {"alice": {"department": ["Engineering"]}}},
                    {"version": 1, "fields": {"department": "Department"},
                     "users": {"alice": {"department": ["Engineering"]}},
                     "hosts": {self.GRAFANA: {"Grafana-Role": {"alice": "Admin"}}}},
                    {"version": "2", "fields": {}, "users": {}}):
            with self.subTest(doc=doc):
                write_attrs(doc)
                self.assertEqual(self.attrs_for("alice", self.GRAFANA), {})  # still allowed
                with self.assertRaises(gg.AttributesError):
                    gg.parse_user_attributes(doc)

    def test_host_header_replaces_field_header(self):
        write_attrs({"version": 2, "fields": {"role": "Role", "city": "City"},
                     "users": {"alice": {"role": ["Viewer"], "city": ["Milan"]}},
                     "hosts": {self.GRAFANA: {"Role": {"alice": "Admin"}}}})
        # One Role header on the wire (dict(headers) would hide a duplicate).
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}/", headers={
            "X-Forwarded-Host": self.GRAFANA, "X-Auth-Request-Groups": "users_grafana",
            "X-Auth-Request-Preferred-Username": "alice",
            "X-Forwarded-Access-Token": token(amr=["hwk"], preferred_username="alice")})
        with urllib.request.urlopen(r) as resp:
            self.assertEqual(resp.headers.get_all("X-Forwarded-Attr-Role"), ["Admin"])
            self.assertEqual(resp.headers.get_all("X-Forwarded-Attr-City"), ["Milan"])
        # Elsewhere the field header stays.
        self.assertEqual(self.attrs_for("alice", "other.example.com"),
                         {"X-Forwarded-Attr-Role": "Viewer", "X-Forwarded-Attr-City": "Milan"})
        # Header names are case-insensitive: "role" replaces "Role" too.
        write_attrs({"version": 2, "fields": {"role": "Role"}, "users": {"alice": {"role": ["Viewer"]}},
                     "hosts": {self.GRAFANA: {"role": {"alice": "Admin"}}}})
        self.assertEqual(gg.user_attribute_headers("alice", self.GRAFANA), [("X-Forwarded-Attr-role", "Admin")])

    def test_host_header_replaces_field_header_for_everybody_on_the_host(self):
        # The host declares Role: on that host no field Role header goes out,
        # whether the user's value was dropped, stripped to nothing, or the
        # user isn't in the host's map at all. Other hosts keep it.
        write_attrs({"version": 2, "fields": {"role": "Role", "city": "City"},
                     "users": {u: {"role": ["Viewer"], "city": ["Milan"]} for u in ("alice", "bob", "carol", "dave")},
                     "hosts": {self.GRAFANA: {"Role": {"alice": "x" * 1025, "bob": "\x00\x01\x7f", "dave": "Admin"}},
                               "empty.example.com": {"ROLE": {}}}})
        for user in ("alice", "bob", "carol"):
            with self.subTest(user=user):
                self.assertEqual(self.attrs_for(user, self.GRAFANA), {"X-Forwarded-Attr-City": "Milan"})
                self.assertEqual(self.attrs_for(user, "other.example.com"),
                                 {"X-Forwarded-Attr-Role": "Viewer", "X-Forwarded-Attr-City": "Milan"})
        self.assertEqual(self.attrs_for("dave", self.GRAFANA),
                         {"X-Forwarded-Attr-Role": "Admin", "X-Forwarded-Attr-City": "Milan"})
        # A declared header without any user still replaces it (case-insensitive).
        self.assertEqual(self.attrs_for("alice", "empty.example.com", groups="users_empty"),
                         {"X-Forwarded-Attr-City": "Milan"})
        self.assertEqual(gg.parse_user_attributes({"version": 2, "hosts": {"empty.example.com": {"ROLE": {}}}})[2],
                         {"empty.example.com": {"x-forwarded-attr-role"}})

    def test_host_header_invalid_name_skipped(self):
        doc = {"version": 2, "fields": {}, "users": {},
               "hosts": {self.GRAFANA: {"Grafana-Role": {"alice": "Admin"}, "Bad Name": {"alice": "x"},
                                        "Trail-": {"alice": "x"}, "Nl\n": {"alice": "x"},
                                        "X-Forwarded-Attr-": {"alice": "x"}, "Ok_1": {"alice": "x"},
                                        "Team": {"alice": "Blue"}}}}
        (users, hosts, _), out = self.logged_parse(doc)
        self.assertEqual(hosts, {self.GRAFANA: {"alice": [("X-Forwarded-Attr-Grafana-Role", "Admin"),
                                                          ("X-Forwarded-Attr-Team", "Blue")]}})
        for bad in ("Bad Name", "Trail-", "Nl\n", "Ok_1", "X-Forwarded-Attr-"):
            self.assertIn(f"skipping invalid attribute header {bad!r}", out)
        write_attrs(doc)
        self.assertEqual(self.attrs_for("alice", self.GRAFANA),
                         {"X-Forwarded-Attr-Grafana-Role": "Admin", "X-Forwarded-Attr-Team": "Blue"})

    def test_host_header_value_limits(self):
        doc = {"version": 2, "fields": {}, "users": {},
               "hosts": {self.GRAFANA: {"Bio": {"alice": "evil\r\nX-Injected: 1\x00\x7f"},
                                        "Big": {"alice": "x" * 1025, "bob": "y" * 1024},
                                        "Name": {"alice": "Doe, Jane 100%"},
                                        "City": {"alice": "Zürich"}}}}
        (_, hosts, _), out = self.logged_parse(doc)
        self.assertIn("dropping 1025-byte value of header 'Big'", out)
        write_attrs(doc)
        status, hdrs = self.req(self.GRAFANA, groups="users_grafana", want_headers=True,
                                extra={"X-Auth-Request-Preferred-Username": "alice"})
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("X-Forwarded-Attr-Bio"), "evilX-Injected: 1")
        self.assertNotIn("X-Injected", hdrs)
        self.assertNotIn("X-Forwarded-Attr-Big", hdrs)            # > 1 KB dropped, not truncated
        self.assertEqual(hdrs.get("X-Forwarded-Attr-Name"), "Doe, Jane 100%")  # verbatim, no encoding
        self.assertEqual(hdrs.get("X-Forwarded-Attr-City").encode("latin-1").decode("utf-8"), "Zürich")
        self.assertEqual(self.attrs_for("bob", self.GRAFANA), {"X-Forwarded-Attr-Big": "y" * 1024})

    def test_host_keys_normalised(self):
        doc = {"version": 2, "fields": {}, "users": {},
               "hosts": {"Grafana.Example.com": {"Role": {"alice": "Admin"}},
                         "grafana.example.com.": {"Role": {"alice": "Admin"}},
                         "grafana.example.com:443": {"Role": {"alice": "Admin"}},
                         "other.example.com": {"Role": {"alice": "Editor"}}}}
        (_, hosts, _), out = self.logged_parse(doc)
        self.assertEqual(hosts, {"other.example.com": {"alice": [("X-Forwarded-Attr-Role", "Editor")]}})
        for bad in ("Grafana.Example.com", "grafana.example.com.", "grafana.example.com:443"):
            self.assertIn(f"skipping attribute host {bad!r}", out)
        write_attrs(doc)
        self.assertEqual(self.attrs_for("alice", self.GRAFANA), {})
        self.assertEqual(self.attrs_for("alice", "other.example.com"), {"X-Forwarded-Attr-Role": "Editor"})

    def test_host_headers_malformed_file_means_none(self):
        base = {"version": 2, "fields": {"city": "City"}, "users": {"alice": {"city": ["Milan"]}}}
        for hosts in ([], {self.GRAFANA: []}, {self.GRAFANA: {"Role": "Admin"}},
                      {self.GRAFANA: {"Role": {"alice": ["Admin"]}}},
                      # two headers of one host (case-insensitive)
                      {self.GRAFANA: {"Role": {"alice": "a"}, "ROLE": {"bob": "b"}}},
                      # two spellings of one user under one header
                      {self.GRAFANA: {"Role": {"alice": "a", "Alice": "b"}}},
                      {self.GRAFANA: {"Role": {"alice": "a", " alice": "b"}}}):
            with self.subTest(hosts=hosts):
                write_attrs(dict(base, hosts=hosts))
                self.assertEqual(self.attrs_for("alice", self.GRAFANA), {})


class PathFragmentTest(GateTest):
    def test_hash_denied_on_path_rules(self):
        write_policy({"version": 6, "groups": {"cloud.example.com": "users_x"},
                      "path_groups": {"cloud.example.com": [{"prefix": "/admin", "group": "admin_x"}]}})
        for uri in ["/x#/admin", "/x%23/../admin", "/admin%23"]:
            with self.subTest(uri=uri):
                self.assertEqual(self.req("cloud.example.com", uri=uri), 403)
        self.assertEqual(self.req("cloud.example.com", uri="/x?a=1"), 200)


class RevocationUnitTest(unittest.TestCase):
    def test_parse_hex_serial(self):
        self.assertEqual(gg.parse_hex_serial("1a:2B:03"), 0x1A2B03)
        self.assertEqual(gg.parse_hex_serial("1A2B03"), 0x1A2B03)
        self.assertIsNone(gg.parse_hex_serial("# comment"))
        self.assertIsNone(gg.parse_hex_serial("   "))
        self.assertIsNone(gg.parse_hex_serial("zz:yy"))

    def test_format_serial_roundtrip(self):
        for n in (1, 0xABC, 0x1A2B3C4D5E6F708192A3B4C5D6E7F80910111213):
            self.assertEqual(gg.parse_hex_serial(gg.format_serial(n)), n)
        self.assertEqual(gg.format_serial(0xABC), "0a:bc")

    def test_cert_serials_from_info(self):
        self.assertEqual(gg.cert_serials_from_info(cert_info(123456789)), [123456789])
        self.assertEqual(gg.cert_serials_from_info(cert_info(5, 7)), [5, 7])
        self.assertEqual(gg.cert_serials_from_info(cert_info(42, encode_times=2)), [42])
        self.assertEqual(gg.cert_serials_from_info('Subject="CN=x"'), [])
        self.assertEqual(gg.cert_serials_from_info(""), [])

    def test_parse_crl_serials_variants(self):
        big = 0x7A3F00112233445566778899AABBCCDDEEFF0011
        for kwargs in ({}, {"with_next_update": False}, {"with_version": False}):
            with self.subTest(**kwargs):
                self.assertEqual(gg.parse_crl_serials(build_crl([1, 0x80, big], **kwargs)), {1, 0x80, big})
        self.assertEqual(gg.parse_crl_serials(build_crl([])), frozenset())
        import base64
        pem = b"-----BEGIN X509 CRL-----\n" + base64.encodebytes(build_crl([99])) + b"-----END X509 CRL-----\n"
        self.assertEqual(gg.parse_crl_serials(pem), {99})
        with self.assertRaises(ValueError):
            gg.parse_crl_serials(b"\x30\x05\x01")

    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_parse_real_openssl_crl(self):
        d = tempfile.mkdtemp()
        def run(*args):
            subprocess.run(args, cwd=d, check=True, capture_output=True)
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
            "-out", "ca.crt", "-subj", "/CN=Test CA", "-days", "1")
        # index.txt: one revoked (R) and one valid (V) entry, serials in hex
        with open(os.path.join(d, "index.txt"), "w") as f:
            f.write("R\t300101000000Z\t250101000000Z\t1A2B3C\tunknown\t/CN=revoked\n")
            f.write("V\t300101000000Z\t\t0F\tunknown\t/CN=valid\n")
        with open(os.path.join(d, "ca.cnf"), "w") as f:
            f.write("[ca]\ndefault_ca=t\n[t]\ndatabase=index.txt\ncrlnumber=crlnumber\n"
                    "default_md=sha256\ndefault_crl_days=1\ncertificate=ca.crt\nprivate_key=ca.key\n")
        with open(os.path.join(d, "crlnumber"), "w") as f:
            f.write("01\n")
        try:
            run("openssl", "ca", "-config", "ca.cnf", "-gencrl", "-out", "crl.pem")
            run("openssl", "crl", "-in", "crl.pem", "-outform", "DER", "-out", "crl.der")
        except subprocess.CalledProcessError as e:
            self.skipTest(f"openssl ca unavailable: {e.stderr!r}")
        with open(os.path.join(d, "crl.der"), "rb") as f:
            self.assertEqual(gg.parse_crl_serials(f.read()), {0x1A2B3C})
        with open(os.path.join(d, "crl.pem"), "rb") as f:
            self.assertEqual(gg.parse_crl_serials(f.read()), {0x1A2B3C})

    def test_revoked_file_missing_and_reload(self):
        write_revoked(None)
        self.assertEqual(gg.load_revoked_file(), frozenset())
        write_revoked(["# header", "0a:bc", "", "garbage!"])
        self.assertEqual(gg.load_revoked_file(), {0xABC})
        write_revoked(["0a:bc", "ff"])
        self.assertEqual(gg.load_revoked_file(), {0xABC, 0xFF})
        write_revoked(None)


class _CrlHandler(http.server.BaseHTTPRequestHandler):
    body = b""
    status = 200
    by_path: dict = {}  # path -> (status, body), overrides status/body
    fetched: list = []

    def do_GET(self):
        _CrlHandler.fetched.append(self.path)
        status, body = self.by_path.get(self.path, (self.status, self.body))
        self.send_response(status)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class MtlsBindingTest(GateTest):
    """A token with amr=mtls only counts with a matching, unrevoked cert NOW."""

    def setUp(self):
        super().setUp()
        write_revoked(None)
        gg.CRL_CACHE = None

    def tearDown(self):
        write_revoked(None)

    CERT = {"op": "any", "items": ["yubikey_cert"]}
    EITHER = {"op": "any", "items": ["yubikey_cert", "security_key"]}
    BOTH = {"op": "all", "items": ["yubikey_cert", "security_key"]}

    def r(self, rule, amr, cert=None, user="bob", host="grafana.example.com", token_user=None):
        write_policy({"templates": {**BASE["templates"], "t": rule}, "hosts": {"grafana.example.com": "t"}})
        extra = {"X-Forwarded-Access-Token": token(amr=amr, preferred_username=user if token_user is None else token_user),
                 "X-Auth-Request-Preferred-Username": user or None}
        if cert is not None:
            extra[gg.CERT_INFO_HEADER] = cert
        return self.req(host, groups="users_grafana", extra=extra, want_headers=True)

    def body(self, rule, amr, cert=None):
        write_policy({"templates": {**BASE["templates"], "t": rule}, "hosts": {"grafana.example.com": "t"}})
        h = {"X-Forwarded-Host": "grafana.example.com", "X-Auth-Request-Preferred-Username": "bob",
             "X-Auth-Request-Groups": "users_grafana",
             "X-Forwarded-Access-Token": token(amr=amr, preferred_username="bob")}
        if cert is not None:
            h[gg.CERT_INFO_HEADER] = cert
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}/", headers=h)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r)
        with cm.exception as e:
            return e.code, dict(e.headers), e.read().decode()

    def test_mtls_token_without_cert_asks_for_the_certificate(self):
        # amr mtls, the rule met with the certificate: the present-certificate
        # page, no step-up (signing in again can't help).
        code, hdrs, body = self.body(self.CERT, ["mtls"])
        self.assertEqual(code, 403)
        self.assertNotIn("X-Stepup-URL", hdrs)
        self.assertIn('id="present-certificate"', body)
        self.assertIn("grafana.example.com needs your YubiKey certificate", body)
        self.assertIn("Insert your YubiKey and reload this page.", body)
        self.assertNotIn("oauth2/start", body)

    def test_mtls_token_with_matching_cert(self):
        self.assertEqual(self.r(self.CERT, ["mtls"], cert_info_for("bob", 0x10))[0], 200)

    def test_mtls_token_with_foreign_user_cert(self):
        self.assertEqual(self.r(self.CERT, ["mtls"], cert_info_for("alice", 0x10))[0], 403)
        self.assertEqual(self.r(self.CERT, ["mtls"], cert_info_for("Bob", 0x10))[0], 403)
        self.assertEqual(self.r(self.CERT, ["mtls"], cert_info_for("bob", 0x10), user="")[0], 403)
        code, hdrs, body = self.body(self.CERT, ["mtls"], cert_info_for("alice", 0x10))
        self.assertIn('id="present-certificate"', body)

    def test_mtls_binding_uses_the_session_username(self):
        # CN compared with the username apps get; the token must agree.
        self.assertEqual(self.r(self.CERT, ["mtls"], cert_info_for("bob", 0x10), token_user="")[0], 403)
        self.assertEqual(self.r(self.CERT, ["mtls"], cert_info_for("bob", 0x10), token_user="alice")[0], 403)
        self.assertEqual(self.r(self.CERT, ["mtls"], cert_info_for("alice", 0x10), token_user="alice")[0], 403)

    def test_mtls_token_with_revoked_cert(self):
        write_revoked(["10"])
        self.assertEqual(self.r(self.CERT, ["mtls"], cert_info_for("bob", 0x10))[0], 403)

    def test_cert_info_without_serial_does_not_satisfy_binding(self):
        self.assertEqual(self.r(self.CERT, ["mtls"], urllib.parse.quote('Subject="CN=bob"'))[0], 403)

    def test_any_rule_met_by_another_method_needs_no_cert(self):
        self.assertEqual(self.r(self.EITHER, ["hwk"])[0], 200)
        self.assertEqual(self.r(self.EITHER, ["mtls", "hwk"])[0], 200)
        self.assertEqual(self.r(self.EITHER, ["mtls"])[0], 403)
        self.assertEqual(self.r(self.EITHER, ["mtls"], cert_info_for("bob", 1))[0], 200)

    def test_all_rule_with_the_certificate_always_needs_it(self):
        self.assertEqual(self.r(self.BOTH, ["mtls", "hwk"])[0], 403)
        self.assertEqual(self.r(self.BOTH, ["mtls", "hwk"], cert_info_for("bob", 1))[0], 200)
        # amr mtls without hwk and no cert: the certificate alone wouldn't
        # do and two methods are missing (contract §5: only an alternative
        # that lacks exactly one has a candidate) — needs-stronger.
        code, hdrs, body = self.body(self.BOTH, ["mtls"])
        self.assertNotIn("X-Stepup-URL", hdrs)
        self.assertIn('id="needs-stronger"', body)
        # Signed in without mtls: the certificate is the one step-up.
        code, hdrs, body = self.body(self.BOTH, ["hwk"])
        self.assertIn("pc_method=yubikey_cert", hdrs.get("X-Stepup-URL", ""))

    def test_rule_without_the_certificate_unaffected(self):
        self.assertEqual(self.r({"op": "any", "items": ["security_key"]}, ["hwk"])[0], 200)

    def test_yubikey_cert_switched_off_never_counts(self):
        write_policy({"methods": ["passkey_device", "passkey_synced", "security_key"],
                      "templates": {"standard": {"op": "any", "items": ["passkey_synced", "passkey_device", "security_key"]},
                                    "strong": {"op": "any", "items": ["security_key"]}}})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana", extra={
            "X-Forwarded-Access-Token": token(amr=["mtls"], preferred_username="bob"),
            gg.CERT_INFO_HEADER: cert_info_for("bob", 1)}), 403)

    def test_leaf_cert_cn(self):
        self.assertEqual(gg.leaf_cert_cn(cert_info_for("bob", 1)), "bob")
        self.assertEqual(gg.leaf_cert_cn(urllib.parse.quote_plus(
            'Subject="C=DE,O=x,CN=carol";SerialNumber="1",Subject="CN=Intermediate";SerialNumber="2"')), "carol")
        self.assertIsNone(gg.leaf_cert_cn(""))
        self.assertIsNone(gg.leaf_cert_cn('Issuer="CN=x"'))


def cert_info_for(cn, serial):
    return urllib.parse.quote_plus(f'Subject="CN={cn}";Issuer="CN=example.com Intermediate CA";'
                                   f'SerialNumber="{serial}";NB="1700000000";NA="1700086400"')


class RevocationGateTest(GateTest):
    def setUp(self):
        super().setUp()
        write_revoked(None)
        gg.CRL_CACHE = None

    def tearDown(self):
        write_revoked(None)
        gg.CRL_CACHE = None

    def test_no_cert_unaffected_by_revocations(self):
        write_revoked(["0a:bc"])
        self.assertEqual(self.req("random.example.com"), 200)

    def test_revoked_serial_from_file_denied(self):
        self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: cert_info(0xABC)}), 200)
        write_revoked(["0a:bc"])
        self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: cert_info(0xABC)}), 403)
        # Revocation beats group membership, also for core subdomains.
        self.assertEqual(self.req("hub.example.com", groups="lldap_admin",
                                  extra={gg.CERT_INFO_HEADER: cert_info(0xABC)}), 403)
        # Different serial still allowed; intermediate in the chain is checked too.
        self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: cert_info(0xABD)}), 200)
        self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: cert_info(0xABD, 0xABC)}), 403)

    def test_unreadable_revocation_file_fails_closed_for_cert_requests(self):
        os.mkdir(REVOKED)  # a directory: exists but cannot be read as a file
        try:
            self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: cert_info(1)}), 403)
            self.assertEqual(self.req("random.example.com"), 200)
        finally:
            os.rmdir(REVOKED)

    def test_cert_info_without_serial_is_not_blocked(self):
        write_revoked(["01"])
        self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: 'Subject%3D%22CN%3Dx%22'}), 200)

    def test_revoked_serial_from_crl_denied(self):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CrlHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            _CrlHandler.status, _CrlHandler.body = 200, build_crl([0x77])
            cache = gg.CrlCache(f"http://127.0.0.1:{srv.server_address[1]}/v1/pki_int/crl", 60)
            self.assertTrue(cache.refresh())
            gg.CRL_CACHE = cache
            self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: cert_info(0x77)}), 403)
            self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: cert_info(0x78)}), 200)
            # Vault down / garbage → keep the last good list.
            _CrlHandler.status, _CrlHandler.body = 503, b"sealed"
            self.assertFalse(cache.refresh())
            _CrlHandler.status, _CrlHandler.body = 200, b"not a crl"
            self.assertFalse(cache.refresh())
            self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: cert_info(0x77)}), 403)
        finally:
            srv.shutdown()


class DeltaCrlTest(GateTest):
    """Vault with auto_rebuild: new revocations are only in the delta CRL."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.crl_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CrlHandler)
        threading.Thread(target=cls.crl_srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.crl_srv.shutdown()
        cls.crl_srv.server_close()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        write_revoked(None)
        gg.CRL_CACHE = None
        base = f"http://127.0.0.1:{self.crl_srv.server_address[1]}/v1/pki_int"
        self.cache = gg.CrlCache(base + "/crl", 60, delta_url=base + "/crl/delta")

    def tearDown(self):
        _CrlHandler.by_path = {}
        _CrlHandler.fetched = []
        gg.CRL_CACHE = None

    def test_union_of_full_and_delta(self):
        _CrlHandler.by_path = {"/v1/pki_int/crl": (200, build_crl([0x10])),
                               "/v1/pki_int/crl/delta": (200, build_crl([0x20]))}
        _CrlHandler.fetched = []
        self.assertTrue(self.cache.refresh())
        # delta first: a full rebuild in between can only move serials into the full CRL
        self.assertEqual(_CrlHandler.fetched, ["/v1/pki_int/crl/delta", "/v1/pki_int/crl"])
        self.assertEqual(self.cache.serials, {0x10, 0x20})
        gg.CRL_CACHE = self.cache
        for sn in (0x10, 0x20):
            self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: cert_info(sn)}), 403)
        self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: cert_info(0x30)}), 200)
        # Revocation is checked before (and independently of) the user.
        self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: cert_info(0x20),
                                                                "X-Auth-Request-Preferred-Username": None}), 403)

    def test_delta_failure_keeps_last_good_delta_and_reports_staleness(self):
        _CrlHandler.by_path = {"/v1/pki_int/crl": (200, build_crl([0x10])),
                               "/v1/pki_int/crl/delta": (200, build_crl([0x20]))}
        self.assertTrue(self.cache.refresh())
        ok = self.cache.last_success
        _CrlHandler.by_path["/v1/pki_int/crl/delta"] = (404, b"no delta")
        self.assertFalse(self.cache.refresh())
        self.assertEqual(self.cache.serials, {0x10, 0x20})
        # Freshness = the oldest source: the delta's last good fetch.
        self.assertEqual(self.cache.last_success, ok)
        self.assertEqual(self.cache.next_update, 1735689600.0)

    def test_never_fetched_delta_means_never_fresh(self):
        _CrlHandler.by_path = {"/v1/pki_int/crl": (200, build_crl([0x10])),
                               "/v1/pki_int/crl/delta": (500, b"")}
        self.assertFalse(self.cache.refresh())
        self.assertEqual(self.cache.last_success, 0)
        self.assertEqual(self.cache.serials, {0x10})


class MetricsTest(GateTest):
    def setUp(self):
        super().setUp()
        write_revoked(None)
        gg.CRL_CACHE = None

    def tearDown(self):
        write_revoked(None)
        gg.CRL_CACHE = None

    def scrape(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/metrics") as r:
            self.assertTrue(r.headers["Content-Type"].startswith("text/plain"))
            return r.read().decode()

    def test_counters_by_result_and_reason(self):
        m = gg.METRICS
        allow0 = m.get("group_gate_requests_total", endpoint="gate", result="allow")
        group0 = m.get("group_gate_denials_total", reason="group")
        host0 = m.get("group_gate_denials_total", reason="host")
        step0 = m.get("group_gate_stepups_total", reason="stepup")
        pol0 = m.get("group_gate_policy_load_errors_total")
        auth0 = m.get("group_gate_requests_total", endpoint="authenticated", result="allow")
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 200)
        self.assertEqual(self.req("grafana.example.com", groups="users_x"), 403)
        self.assertEqual(self.req("grafana.evil.com"), 403)
        self.assertEqual(self.req("hub.example.com", gate_path="/authenticated", groups=""), 200)
        write_policy({"hosts": {"grafana.example.com": "strong"}})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana",
                                  extra={"X-Forwarded-Access-Token": token(amr=["spk"])}), 403)
        write_policy("{not json")
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
        self.assertEqual(m.get("group_gate_requests_total", endpoint="gate", result="allow"), allow0 + 1)
        self.assertEqual(m.get("group_gate_denials_total", reason="group"), group0 + 1)
        self.assertEqual(m.get("group_gate_denials_total", reason="host"), host0 + 1)
        self.assertEqual(m.get("group_gate_stepups_total", reason="stepup"), step0 + 1)
        self.assertEqual(m.get("group_gate_policy_load_errors_total"), pol0 + 1)
        self.assertEqual(m.get("group_gate_requests_total", endpoint="authenticated", result="allow"), auth0 + 1)
        text = self.scrape()
        self.assertIn('group_gate_denials_total{reason="group"}', text)
        self.assertIn("# TYPE group_gate_requests_total counter", text)
        self.assertIn("group_gate_crl_enabled 0", text)
        self.assertIn("group_gate_revoked_file_serials 0", text)

    def test_revoked_cert_reason_and_unreadable_file_gauge(self):
        before = gg.METRICS.get("group_gate_denials_total", reason="revoked_cert")
        write_revoked(["0a:bc"])
        self.assertEqual(self.req("random.example.com", extra={gg.CERT_INFO_HEADER: cert_info(0xABC)}), 403)
        self.assertEqual(gg.METRICS.get("group_gate_denials_total", reason="revoked_cert"), before + 1)
        self.assertIn("group_gate_revoked_file_serials 1", self.scrape())
        write_revoked(None)
        os.mkdir(REVOKED)
        try:
            self.assertIn("group_gate_revoked_file_serials -1", self.scrape())
        finally:
            os.rmdir(REVOKED)

    def test_metrics_endpoint_needs_no_auth_headers_and_is_not_a_decision(self):
        before = gg.METRICS.get("group_gate_denials_total", reason="host")
        self.scrape()
        self.assertEqual(gg.METRICS.get("group_gate_denials_total", reason="host"), before)

    def test_crl_freshness_gauges(self):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CrlHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            _CrlHandler.status, _CrlHandler.body = 200, build_crl([7])
            cache = gg.CrlCache(f"http://127.0.0.1:{srv.server_address[1]}/crl", 60)
            gg.CRL_CACHE = cache
            self.assertIn("group_gate_crl_last_success_timestamp_seconds 0\n", self.scrape())
            self.assertTrue(cache.refresh())
            text = self.scrape()
            self.assertIn("group_gate_crl_enabled 1", text)
            self.assertIn("group_gate_crl_revoked_serials 1", text)
            # build_crl uses 2025-01-01T00:00:00Z for thisUpdate/nextUpdate.
            self.assertIn("group_gate_crl_next_update_timestamp_seconds 1735689600", text)
            ok = cache.last_success
            self.assertGreater(ok, 0)
            failures = gg.METRICS.get("group_gate_crl_fetch_failures_total")
            _CrlHandler.status = 500
            self.assertFalse(cache.refresh())
            self.assertEqual(cache.last_success, ok)  # a failure keeps the old timestamp
            self.assertEqual(gg.METRICS.get("group_gate_crl_fetch_failures_total"), failures + 1)
        finally:
            _CrlHandler.status = 200
            srv.shutdown()

    def test_parse_crl_next_update(self):
        self.assertEqual(gg.parse_crl(build_crl([1]))[1], 1735689600.0)
        self.assertIsNone(gg.parse_crl(build_crl([1], with_next_update=False))[1])
        # GeneralizedTime (dates from 2050 on)
        gen = _der(0x18, b"20991231235959Z")
        self.assertEqual(gg.parse_crl(build_crl([1], next_update=gen))[1], 4102444799.0)


class JwtClaimsTest(unittest.TestCase):
    """decode_jwt_payload: claims only, no verification (oauth2-proxy did it)."""

    def test_claims_without_verification(self):
        # Dummy signature, expired, foreign audience: still decoded.
        self.assertEqual(gg.decode_jwt_payload(token(acr="hwk", amr=["hwk"], exp=1, aud="other")),
                         {"acr": "hwk", "amr": ["hwk"], "exp": 1, "aud": "other"})

    def test_malformed_gives_no_claims(self):
        import base64
        b64 = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
        hdr = b64(b'{"alg": "RS256"}')
        for bad in ("", "x", "a.b", "x.y.z", f"{hdr}.{b64(b'[1, 2]')}.c2ln", f"{hdr}.{b64(b'not json')}.c2ln",
                    f"{b64(b'[]')}.{b64(b'{}')}.c2ln"):
            with self.subTest(token=bad):
                self.assertEqual(gg.decode_jwt_payload(bad), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
