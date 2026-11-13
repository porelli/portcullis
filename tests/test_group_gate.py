#!/usr/bin/env python3
"""Unit tests for group-gate/group-gate.py.

Run: python3 tests/test_group_gate.py
Starts group-gate in-process on an ephemeral port with temp map/policy files.
"""
import datetime
import importlib.util
import html
import http.server
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
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
os.environ.pop("GATE_CRL_URLS", None)
os.environ.pop("GATE_DELTA_CRL_URLS", None)
YUBIKEY_CA = os.path.join(TMP, "yubikey-ca.crt")
BROWSER_CA = os.path.join(TMP, "browser-ca.crt")
YUBIKEY_CA_CN = "example.com Intermediate CA"        # pki_yubikey_ca_cn (scripts/lib/pki.sh)
BROWSER_CA_CN = "example.com Browser Certificate CA"  # pki_browser_ca_cn
os.environ["GATE_YUBIKEY_CA_FILE"] = YUBIKEY_CA
os.environ["GATE_BROWSER_CA_FILE"] = BROWSER_CA
OPENED_DIR = os.path.join(TMP, "opened")
os.environ["GATE_OPENED_DIR"] = OPENED_DIR
os.environ["GATE_OPENED_GID"] = str(os.getgid())
os.environ["PORTCULLIS_DOMAIN"] = "example.com"
VPN_FILE = os.path.join(TMP, "vpn.json")
os.environ["GATE_VPN_FILE"] = VPN_FILE
os.environ.pop("GATE_MAP", None)

_CAS: dict = {}  # (cn, ca) -> (certificate, key): one key per CA for the whole run


def ca_pair(cn, ca=True):
    """A self-signed certificate with subject CN `cn` (a CA unless
    ca=False) and its key, made once per (cn, ca)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    if (cn, ca) not in _CAS:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
        now = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        _CAS[(cn, ca)] = (cert, key)
    return _CAS[(cn, ca)]


def write_ca(path, cn, ca=True, pem=True):
    """Writes ca_pair(cn, ca)'s certificate to `path` (atomically)."""
    from cryptography.hazmat.primitives import serialization
    cert, _ = ca_pair(cn, ca)
    data = cert.public_bytes(serialization.Encoding.PEM if pem else serialization.Encoding.DER)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


_LEAVES: dict = {}


def issue_leaf(cn, serial, issuer_cn, days=(-1, 30)):
    """A client certificate with subject CN `cn` (any text), issued and
    signed by ca_pair(issuer_cn) — an unknown CA when nobody wrote it to a
    CA file — valid from now+days[0] to now+days[1]."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    k = (cn, serial, issuer_cn, days)
    if k not in _LEAVES:
        ca, ca_key = ca_pair(issuer_cn)
        now = datetime.datetime.now(datetime.timezone.utc)
        _LEAVES[k] = (x509.CertificateBuilder()
                      .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
                      .issuer_name(ca.subject).public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
                      .serial_number(serial).not_valid_before(now + datetime.timedelta(days=days[0]))
                      .not_valid_after(now + datetime.timedelta(days=days[1]))
                      .sign(ca_key, hashes.SHA256()))
    return _LEAVES[k]


def pem_header(*certs):
    """X-Forwarded-Tls-Client-Cert the way Traefik writes it: Go's
    url.QueryEscape of the base64 DER bodies joined with ","."""
    import base64
    from cryptography.hazmat.primitives import serialization
    return urllib.parse.quote_plus(",".join(base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
                                            for c in certs))


write_ca(YUBIKEY_CA, YUBIKEY_CA_CN)
write_ca(BROWSER_CA, BROWSER_CA_CN)

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
    "version": 7,
    "methods": ["passkey_device", "passkey_synced", "security_key", "yubikey_cert"],
    "templates": {"standard": STANDARD, "strong": STRONG},
    "default": "standard",
    "hosts": {},
    "core": {"directory.example.com": "standard",
             "hub.example.com": "strong", "metrics.example.com": "standard",
             "people.example.com": "strong", "example.com": "standard",
             "traefik.example.com": "standard"},
    "people": {},
    "add_stronger": False,
    # v7: no VPN-only host, apps mode (contract §4).
    "vpn": {"hosts": {}, "server_mode": False, "admin_only": False, "public_enrol": True, "devices_file": "vpn.json"},
}


def write_policy(doc, raw=False, malformed=False):
    # Only version 7 is served: a dict gets the BASE keys it lacks (version
    # 7 included) unless the test is about the file's shape (raw=True).
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


class ReadyCrl:
    """A CRL cache whose lists are all read and fresh, revoking nothing."""
    serials = frozenset()
    ready = True
    last_success = 1.0
    next_update = 4102444799.0


READY_CRL = ReadyCrl()


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
        gg.CRL_CACHE = READY_CRL

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
        for gate_path in ("/", "/anything"):
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
        for gate_path in ("/", "/portal"):
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
        for bad in ({"version": 7}, None):
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
            for gate_path in ("/",):
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
        self.assertEqual(self.req("random.example.com", groups="users_x"), 200)
        self.assertEqual(self.req("random.example.com", groups=gg.DENY_GROUP), 403)

    def test_deny_sentinel_in_path_groups(self):
        write_policy({"path_groups": {"grafana.example.com": [{"prefix": "/x", "group": gg.DENY_GROUP}]}})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana", uri="/x/1"), 403)
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana", uri="/y"), 200)

    # ── version ──

    def test_policy_version(self):
        # group-gate serves only version 7 (contract §4); a file without
        # `version`, and a missing file, deny too.
        for version, want in [(7, 200), (6, 403), (5, 403), (4, 403), (3, 403), (1, 403), (8, 403), ("7", 403),
                              (True, 403), (0, 403), (7.0, 403)]:
            with self.subTest(version=version):
                write_policy(dict(BASE, version=version), raw=True)
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), want)
        body = json.dumps({k: v for k, v in BASE.items() if k != "version"})
        for doc in (None, {}, {"groups": {}}, '{"version": 7.0, %s' % body[1:], '{"version": 7e0, %s' % body[1:],
                    {k: v for k, v in BASE.items() if k != "version"}):
            with self.subTest(doc=doc):
                write_policy(doc, raw=True)
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
                self.assertEqual(self.req("hub.example.com", groups="lldap_admin"), 403)

    # ── healthz / no /authenticated ──

    def test_healthz(self):
        self.assertEqual(self.req("", groups=None, gate_path="/healthz"), 200)

    def test_no_authenticated_endpoint(self):
        # /authenticated is gone (contract §5 "Core routers"): any other
        # gate path gets the full checks, the host's group included.
        for gate_path in ("/authenticated", "/authenticated/self", "/authenticatedX"):
            with self.subTest(gate_path=gate_path):
                self.assertEqual(self.req("grafana.example.com", groups="users_x", gate_path=gate_path), 403)
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana", gate_path=gate_path), 200)
        # enroll.<d> is reserved but no longer gated: no template, deny.
        for gate_path in ("/", "/authenticated"):
            self.assertEqual(self.req("enroll.example.com", groups="lldap_admin", gate_path=gate_path), 403)


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

    def page(self, host, amr, user="bob", groups="users_grafana", gate_path="/", cert=None, uri=None, extra=None):
        h = {"X-Forwarded-Host": host, "X-Auth-Request-Preferred-Username": user,
             "X-Auth-Request-Groups": groups,
             "X-Forwarded-Access-Token": token(amr=amr, preferred_username=user)}
        if cert is not None:
            h.update(cert) if isinstance(cert, dict) else h.__setitem__(gg.CERT_INFO_HEADER, cert)
        if uri is not None:
            h["X-Forwarded-Uri"] = uri
        h.update(extra or {})
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{gate_path}", headers=h)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, dict(resp.headers), resp.read().decode()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, dict(e.headers), e.read().decode()

    def test_v6_only(self):
        for doc in (dict(BASE, version=6), dict(BASE, version=8)):
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
                have = gg.session_methods(c["have"], ALL_METHODS, bound={"yubikey_cert", "browser_cert"})
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
        # Just after a setup link the page says the key is set up and asks
        # to sign in with it — never "needs a passkey" (user report
        # 2026-11-12: confusing right after registering one).
        self.assertIn('id="setup-done"', body)
        self.assertIn("You&#x27;re set up", body)
        self.assertNotIn("needs a", body)
        # A normal session that lacks the method still gets "needs a …".
        code, hdrs, body = self.page("grafana.example.com", ["pwd"])
        self.assertIn("grafana.example.com needs a passkey", body)
        self.assertNotIn('id="setup-done"', body)
        # A setup-link session asked for something that isn't a passkey
        # (here a password) gets the normal "needs a …" page.
        write_policy({"methods": sorted(BASE["methods"] + ["password"]),
                      "templates": {**BASE["templates"], "basic": {"op": "any", "items": ["password"]}},
                      "default": "basic"})
        code, hdrs, body = self.page("grafana.example.com", ["inv"])
        self.assertEqual(code, 403)
        self.assertIn("pc_method=password", hdrs.get("X-Stepup-URL", ""))
        self.assertIn("grafana.example.com needs a password", body)
        self.assertNotIn('id="setup-done"', body)
        write_policy({"templates": {**BASE["templates"], "basic": BASIC_COMPILED}, "default": "basic"})
        # A setup-link session counts as not known in `people` (contract
        # §5): its new passkey may not be in the inventory yet, so neither a
        # stale entry nor an empty one turns the step-up into needs-stronger.
        for people in ({"bob": ["passkey_device", "security_key"]}, {"bob": []}, {"bob": ["yubikey_cert"]}):
            with self.subTest(people=people):
                write_policy({"templates": {**BASE["templates"], "basic": BASIC_COMPILED}, "default": "basic",
                              "people": people})
                code, hdrs, body = self.page("grafana.example.com", ["inv"])
                self.assertEqual(code, 403)
                self.assertIn('id="stepup-continue"', body)
                self.assertNotIn('id="needs-stronger"', body)
                self.assertIn("pc_method=passkey&", hdrs["X-Stepup-URL"])
        # One passkey candidate: that one, whatever `people` says.
        write_policy({"hosts": {"grafana.example.com": "strong"}, "people": {"bob": []}})
        code, hdrs, body = self.page("grafana.example.com", ["inv"])
        self.assertIn("pc_method=security_key", hdrs["X-Stepup-URL"])
        # The same person without `inv` and an empty inventory: needs-stronger.
        code, hdrs, body = self.page("grafana.example.com", ["spk"])
        self.assertIn('id="needs-stronger"', body)
        # [inv, spk] (a setup-link session that touched its synced passkey):
        # `people` is still ignored for the wording — a step-up, never
        # needs-stronger —, and access is decided by the methods alone.
        code, hdrs, body = self.page("grafana.example.com", ["inv", "spk"])
        self.assertEqual(code, 403)
        self.assertIn('id="stepup-continue"', body)
        self.assertNotIn('id="needs-stronger"', body)
        self.assertIn("pc_method=security_key", hdrs["X-Stepup-URL"])
        write_policy({"people": {"bob": []}})  # Standard default
        self.assertEqual(self.page("grafana.example.com", ["inv", "spk"])[0], 200)
        self.assertEqual(self.page("grafana.example.com", ["inv"])[0], 403)

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
        # enroll.<d> is not a gated core host: `core` may not list it.
        self.assertIn("not gated core hosts", gg.validate_policy_doc(
            {**BASE, "core": dict(BASE["core"], **{"enroll.example.com": "strong"})}))
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

    def stepup_rd(self, host, uri, method="GET", groups="users_grafana"):
        """The step-up's `rd` for a request to `host` + `uri` (the
        X-Stepup-URL header's and the page's href, which must agree)."""
        extra = {} if method is None else {"X-Forwarded-Method": method}
        code, hdrs, body = self.page(host, ["spk"], groups=groups, uri=uri, extra=extra)
        self.assertEqual(code, 403)
        url = hdrs["X-Stepup-URL"]
        self.assertIn(f'href="{html.escape(url, quote=True)}"', body)
        return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["rd"]

    def test_stepup_returns_to_page(self):
        write_policy({"hosts": {"grafana.example.com": "strong"}, "people": {"bob": ["passkey_synced", "security_key"]}})
        uri = "/d/abc?orgId=1&x=%20y"
        self.assertEqual(self.stepup_rd("grafana.example.com", uri), [f"https://grafana.example.com{uri}"])
        # An extra-domain host: the same path, relative.
        write_policy({"extra_domains": [EXTRA], "hosts": {f"grafana.{EXTRA}": "strong"},
                      "people": {"bob": ["passkey_synced", "security_key"]}})
        self.assertEqual(self.stepup_rd(f"grafana.{EXTRA}", uri, groups=""), [uri])

    def test_stepup_return_rejects_offhost_paths(self):
        write_policy({"extra_domains": [EXTRA], "hosts": {"grafana.example.com": "strong", f"grafana.{EXTRA}": "strong"},
                      "people": {"bob": ["passkey_synced", "security_key"]}})
        cases = [("POST", "/d/abc"), ("HEAD", "/d/abc"), (None, "/d/abc")]
        cases += [("GET", u) for u in ("//evil.example/x", "/\\evil.example", "/%5Cevil", "/%5cevil", "/a\tb",
                                       "/a b", "/\u00e9", "/" + "a" * 2048, "", "x")]
        for method, uri in cases:
            with self.subTest(method=method, uri=uri):
                self.assertEqual(gg.return_path(uri, method or ""), "/")
                if any(c in uri for c in "\t\u00e9"):
                    continue  # not sendable as an HTTP header by urllib; return_path covers it
                self.assertEqual(self.stepup_rd("grafana.example.com", uri, method), ["https://grafana.example.com/"])
                self.assertEqual(self.stepup_rd(f"grafana.{EXTRA}", uri, method, groups=""), ["/"])
        # 2048 bytes is still kept.
        self.assertEqual(gg.return_path("/" + "a" * 2047, "GET"), "/" + "a" * 2047)
        self.assertEqual(gg.return_path("/d/abc?orgId=1&x=%20y", "GET"), "/d/abc?orgId=1&x=%20y")
        self.assertEqual(gg.stepup_url("grafana.example.com", "security_key", extra=False, path="/x?y=1"),
                         "https://auth.example.com/oauth2/start?pc_method=security_key&rd=https%3A%2F%2Fgrafana.example.com%2Fx%3Fy%3D1")

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
                                          held=frozenset({"yubikey_cert"})), "security_key")
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
        acct = "https://people.example.com/signin"
        b = gg.render_needs_page("Grafana", {"password"}, STRONG, {"password"}, False, "example.com").decode()
        self.assertIn("<h1>" + gg.MARK_HTML + "Grafana needs a stronger sign-in</h1>", b)
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


ADMIN_RULES = {"version": 7,
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


def build_crl(serials, with_next_update=True, with_version=True, next_update=None, issuer_cn="Test CA"):
    """Structurally valid (unsigned) X.509 v2 CRL. next_update: DER time
    element (default: the UTCTime used for thisUpdate); issuer: CN
    issuer_cn (UTF8String, as ca_pair's subjects)."""
    alg = _der(0x30, _der(0x06, bytes.fromhex("2a8648ce3d040302")))  # ecdsa-with-SHA256
    issuer = _der(0x30, _der(0x31, _der(0x30, _der(0x06, b"\x55\x04\x03") + _der(0x0C, issuer_cn.encode()))))
    t = _der(0x17, b"250101000000Z")
    nu = next_update or t
    tbs = (_der_int(1) if with_version else b"") + alg + issuer + t + (nu if with_next_update else b"")
    if serials:
        tbs += _der(0x30, b"".join(_der(0x30, _der_int(sn) + t) for sn in serials))
    tbs += _der(0xA0, _der(0x30, b""))  # crlExtensions
    return _der(0x30, _der(0x30, tbs) + alg + _der(0x03, b"\x00\x01\x02"))


PUBLIC_DOC = {
    "version": 7,
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
                    dict(BASE, public_paths=pp, version=7.0),
                    '{"version": 7.0, %s' % json.dumps(dict({k: v for k, v in BASE.items() if k != "version"}, public_paths=pp))[1:],
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
            write_policy({"version": 7, "path_groups": {"cloud.example.com": [{"prefix": "/admin", "group": "admin_x"}]}})
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
        write_policy({"version": 7})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 200)

    def test_expired_membership_stripped(self):
        write_policy({"version": 7, "groups": {"app.example.com": "b"},
                      "expiring": [{"user": "bob", "group": "b", "at": PAST}]})
        self.assertEqual(self.req("app.example.com", groups="a,b"), 403)
        write_policy({"version": 7, "groups": {"app.example.com": "a"},
                      "expiring": [{"user": "bob", "group": "b", "at": PAST}]})
        status, hdrs = self.req("app.example.com", groups="a,b", want_headers=True)
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("X-Auth-Request-Groups"), "a")
        # Usernames in the file are lowercase; the session's case doesn't matter.
        status, hdrs = self.req("app.example.com", groups="a,b", want_headers=True,
                                extra={"X-Auth-Request-Preferred-Username": "Bob"})
        self.assertEqual(hdrs.get("X-Auth-Request-Groups"), "a")
        # Another user's expiry, or another group's, changes nothing.
        write_policy({"version": 7, "groups": {"app.example.com": "b"},
                      "expiring": [{"user": "alice", "group": "b", "at": PAST},
                                   {"user": "bob", "group": "c", "at": PAST}]})
        status, hdrs = self.req("app.example.com", groups="a,b", want_headers=True)
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("X-Auth-Request-Groups"), "a,b")
        # Path groups and the core map see the stripped set too.
        write_policy({"version": 7, "path_groups": {"app.example.com": [{"prefix": "/admin", "group": "admin_app"}]},
                      "expiring": [{"user": "bob", "group": "admin_app", "at": PAST},
                                   {"user": "bob", "group": "lldap_admin", "at": PAST}]})
        self.assertEqual(self.req("app.example.com", groups="admin_app", uri="/admin"), 403)
        self.assertEqual(self.req("hub.example.com", groups="lldap_admin"), 403)
        # Only every group expired: no X-Auth-Request-Groups at all.
        status, hdrs = self.req("people.example.com", groups="lldap_admin", want_headers=True)
        self.assertEqual(status, 200)
        self.assertNotIn("X-Auth-Request-Groups", hdrs)

    def test_token_headers_echoed_unless_membership_expired(self):
        jwt_ = token(amr=["hwk"], preferred_username="bob")
        tok = {"Authorization": f"Bearer {jwt_}", "X-Forwarded-Access-Token": jwt_}
        write_policy({"version": 7, "groups": {"app.example.com": "a"},
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
        write_policy({"version": 7, "groups": {"app.example.com": "a"},
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
        write_policy({"version": 7, "groups": {"app.example.com": "b"},
                      "expiring": [{"user": "bob", "group": "b", "at": FUTURE}]})
        status, hdrs = self.req("app.example.com", groups="a,b", want_headers=True)
        self.assertEqual(status, 200)
        self.assertEqual(hdrs.get("X-Auth-Request-Groups"), "a,b")
        # The boundary: absent once now >= at.
        doc = {"version": 7, "expiring": [{"user": "bob", "group": "b", "at": "2030-01-01T00:00:00Z"}]}
        at = 1893456000.0
        self.assertEqual(gg.expired_groups(doc, "bob", now=at - 1), set())
        self.assertEqual(gg.expired_groups(doc, "bob", now=at), {"b"})

    def test_malformed_expiring_fails_closed(self):
        for exp in ({}, ["x"], [{"user": "bob", "group": "b"}], [{"user": "bob", "group": "b", "at": "tomorrow"}],
                    [{"user": "bob", "group": "b", "at": "2030-01-01T00:00:00"}],  # no offset
                    [{"user": "bob", "group": "b", "at": 1}], [{"user": "", "group": "b", "at": FUTURE}],
                    [{"user": "bob", "group": "b", "at": FUTURE, "extra": 1}]):
            with self.subTest(expiring=exp):
                write_policy({"version": 7, "expiring": exp}, malformed=True)
                self.assertEqual(self.req("random.example.com", groups="a"), 403)
        # Positive control: a well-formed `expiring` allows the same request.
        write_policy({"version": 7, "expiring": [{"user": "bob", "group": "b", "at": FUTURE}]})
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
        write_policy({"version": 7, "groups": {"people.example.com": "lldap_admin"},
                      "path_groups": {"people.example.com": [{"prefix": "/", "group": "lldap_admin"}]}})
        self.assertEqual(self.req("people.example.com", groups="users_x"), 200)

    def test_star_ignored_in_policy_file(self):
        write_policy({"version": 7, "groups": {"grafana.example.com": "*", "newapp.example.com": "*"}})
        # grafana keeps map.conf's group; newapp falls back to no mapping.
        self.assertEqual(self.req("grafana.example.com", groups="users_x"), 403)
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 200)
        self.assertEqual(gg.build_group_map(gg.load_policy_file()).get("newapp"), None)
        # Holding a group literally named "*" never satisfies anything.
        self.assertEqual(self.req("grafana.example.com", groups="*"), 403)
        # In path_groups it is a malformed rule: fail closed.
        write_policy({"version": 7, "path_groups": {"grafana.example.com": [{"prefix": "/x", "group": "*"}]}})
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
        # Core subdomains get them too.
        for host, groups, path in (("hub.example.com", "lldap_admin", "/"), ("people.example.com", "", "/")):
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
        write_policy({"version": 7, "groups": {"cloud.example.com": "users_x"},
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
        gg.CRL_CACHE = READY_CRL

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
            extra.update(cert) if isinstance(cert, dict) else extra.__setitem__(gg.CERT_INFO_HEADER, cert)
        return self.req(host, groups="users_grafana", extra=extra, want_headers=True)

    def body(self, rule, amr, cert=None):
        write_policy({"templates": {**BASE["templates"], "t": rule}, "hosts": {"grafana.example.com": "t"}})
        h = {"X-Forwarded-Host": "grafana.example.com", "X-Auth-Request-Preferred-Username": "bob",
             "X-Auth-Request-Groups": "users_grafana",
             "X-Forwarded-Access-Token": token(amr=amr, preferred_username="bob")}
        if cert is not None:
            h.update(cert) if isinstance(cert, dict) else h.__setitem__(gg.CERT_INFO_HEADER, cert)
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
            **cert_info_for("bob", 1)}), 403)

    def test_leaf_cert_cn(self):
        self.assertEqual(gg.leaf_cert_cn(cert_info_for("bob", 1)[gg.CERT_INFO_HEADER]), "bob")
        self.assertEqual(gg.leaf_cert_cn(urllib.parse.quote_plus(
            'Subject="C=DE,O=x,CN=carol";SerialNumber="1",Subject="CN=Intermediate";SerialNumber="2"')), "carol")
        self.assertIsNone(gg.leaf_cert_cn(""))
        self.assertIsNone(gg.leaf_cert_cn('Issuer="CN=x"'))


def cert_info_for(cn, serial, issuer=None, chain=False, days=(-1, 30)):
    """The two certificate headers Traefik (client-headers@file) sends for
    a leaf with CN `cn` issued by `issuer` (default: the YubiKey CA): the
    Info text and the certificate itself."""
    issuer = issuer or YUBIKEY_CA_CN
    parts = [f'Subject="CN={cn}";Issuer="CN={issuer}";SerialNumber="{serial}";NB="1700000000";NA="1700086400"']
    certs = [issue_leaf(cn, serial, issuer, days)]
    if chain:
        parts.append(f'Subject="CN={issuer}";Issuer="CN=example.com Root CA";SerialNumber="987654321";'
                     'NB="1700000000";NA="1800000000"')
        certs.append(ca_pair(issuer)[0])
    return {gg.CERT_INFO_HEADER: urllib.parse.quote_plus(",".join(parts)), gg.CERT_PEM_HEADER: pem_header(*certs)}


class RevocationGateTest(GateTest):
    def setUp(self):
        super().setUp()
        write_revoked(None)
        gg.CRL_CACHE = READY_CRL

    def tearDown(self):
        write_revoked(None)
        gg.CRL_CACHE = READY_CRL

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
            cache = gg.CrlCache([f"http://127.0.0.1:{srv.server_address[1]}/v1/pki_int/crl"], 60)
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
        gg.CRL_CACHE = READY_CRL
        base = f"http://127.0.0.1:{self.crl_srv.server_address[1]}/v1/pki_int"
        self.cache = gg.CrlCache([base + "/crl"], 60, delta_urls=[base + "/crl/delta"])

    def tearDown(self):
        _CrlHandler.by_path = {}
        _CrlHandler.fetched = []
        gg.CRL_CACHE = READY_CRL

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
        gg.CRL_CACHE = READY_CRL

    def tearDown(self):
        write_revoked(None)
        gg.CRL_CACHE = READY_CRL

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
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 200)
        self.assertEqual(self.req("grafana.example.com", groups="users_x"), 403)
        self.assertEqual(self.req("grafana.evil.com"), 403)
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
        text = self.scrape()
        self.assertIn('group_gate_denials_total{reason="group"}', text)
        self.assertIn("# TYPE group_gate_requests_total counter", text)
        self.assertIn("group_gate_crl_enabled 1", text)
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
            cache = gg.CrlCache([f"http://127.0.0.1:{srv.server_address[1]}/crl"], 60)
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


# Traefik's own X-Forwarded-Tls-Client-Cert-Info example (passTLSClientCert
# docs): Go's url.QueryEscape of Subject="…";Issuer="…";NB;NA;SAN, so a
# space is "+". The Info text never decides a certificate's kind or user:
# forwarded_leaf refuses it.
TRAEFIK_INFO_FIXTURE = (
    "Subject%3D%22C%3DFR%2CST%3DIle-de-France%2CL%3DParis%2CO%3DCheese%2CCN%3D%2A.cheese.org%22%3B"
    "Issuer%3D%22DC%3Dorg%2CDC%3Dcheese%2CC%3DFR%2CC%3DUS%2CST%3DSigning+State%2CST%3DSigning+State+2%2C"
    "L%3DTOULOUSE%2CL%3DLYON%2CO%3DCheese%2CO%3DCheese+2%2CCN%3DSimple+Signing+CA%22%3B"
    "NB%3D%221544094616%22%3BNA%3D%221607166616%22%3B"
    "SAN%3D%22%2A.cheese.org%2C%2A.cheese.net%2Ccheese.in%2Ctest%40cheese.org%2Ctest%40cheese.net%2C10.0.1.0%2C10.0.1.2%22")


def leaf_info(cn, serial, issuer=YUBIKEY_CA_CN, chain=True):
    """cert_info_for with the intermediate after the leaf."""
    return cert_info_for(cn, serial, issuer, chain=chain)


ALL_ON = sorted(gg.METHOD_IDS)
# A CRL nextUpdate far ahead (GeneralizedTime).
FRESH = _der(0x18, b"20991231235959Z")


class SigninPart2Test(GateTest):
    """Sign-in methods part 2 in group-gate: certificate kinds by issuer,
    both CAs' CRLs, the Sign-in paths, the opened log, the links (contract
    §4, §5, §10)."""

    def setUp(self):
        super().setUp()
        write_revoked(None)
        gg.CRL_CACHE = READY_CRL
        write_ca(YUBIKEY_CA, YUBIKEY_CA_CN)
        write_ca(BROWSER_CA, BROWSER_CA_CN)
        self._old = (gg.YUBIKEY_CA_FILE, gg.BROWSER_CA_FILE, gg.OPENED_LOG)
        self.log_dir = tempfile.mkdtemp(dir=TMP)
        gg.OPENED_LOG = gg.OpenedLog(os.path.join(self.log_dir, "opened"), gid=os.getgid())

    def tearDown(self):
        gg.YUBIKEY_CA_FILE, gg.BROWSER_CA_FILE, gg.OPENED_LOG = self._old
        gg.CRL_CACHE = READY_CRL
        _CrlHandler.by_path = {}
        _CrlHandler.fetched = []
        write_revoked(None)
        write_ca(YUBIKEY_CA, YUBIKEY_CA_CN)
        write_ca(BROWSER_CA, BROWSER_CA_CN)

    def rules(self, **rules):
        """Every method on; host grafana.example.com on template "t"."""
        write_policy({"methods": ALL_ON, "templates": {**BASE["templates"], **rules},
                      "hosts": {"grafana.example.com": "t"} if "t" in rules else {}})

    def page(self, host="grafana.example.com", amr=("hwk",), user="bob", groups="users_grafana", cert=None,
             uri=None, gate_path="/", claims=None, extra=None):
        h = {"X-Forwarded-Host": host, "X-Auth-Request-Preferred-Username": user,
             "X-Auth-Request-Groups": groups,
             "X-Forwarded-Access-Token": token(amr=list(amr), preferred_username=user, **(claims or {}))}
        if cert is not None:
            h.update(cert) if isinstance(cert, dict) else h.__setitem__(gg.CERT_INFO_HEADER, cert)
        if uri is not None:
            h["X-Forwarded-Uri"] = uri
        h.update(extra or {})
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{gate_path}", headers=h)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, dict(resp.headers), resp.read().decode()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, dict(e.headers), e.read().decode()

    # ── certificate kinds by issuer (contract §4 "Certificate binding") ──

    def test_forwarded_leaf_traefik_format(self):
        leaf = issue_leaf("bob", 11, YUBIKEY_CA_CN)
        ca = ca_pair(YUBIKEY_CA_CN)[0]
        for raw in (pem_header(leaf), pem_header(leaf, ca), urllib.parse.unquote(pem_header(leaf)),
                    "-----BEGIN CERTIFICATE-----" + urllib.parse.unquote(pem_header(leaf)) + "-----END CERTIFICATE-----"):
            with self.subTest(raw=raw[:40]):
                self.assertEqual(gg.forwarded_leaf(raw), leaf)
        # Only the leaf (the first entry) is read.
        self.assertEqual(gg.forwarded_leaf(pem_header(ca, leaf)), ca)
        for bad in ("", "x", "%%%", "QUJD", urllib.parse.quote_plus(pem_header(leaf)),  # escaped twice
                    "A" * (gg.CERT_PEM_MAX + 1), TRAEFIK_INFO_FIXTURE):
            with self.subTest(bad=bad[:40]):
                self.assertIsNone(gg.forwarded_leaf(bad))

    def test_ca_subject_cn(self):
        self.assertEqual(gg.ca_subject_cn(YUBIKEY_CA), YUBIKEY_CA_CN)
        der = os.path.join(TMP, "der-ca.crt")
        write_ca(der, "DER CA", pem=False)
        self.assertEqual(gg.ca_subject_cn(der), "DER CA")
        write_ca(der, "Not a CA", ca=False)
        self.assertIsNone(gg.ca_subject_cn(der))  # re-read: (inode, mtime, size) changed
        with open(der, "w") as f:
            f.write("garbage")
        self.assertIsNone(gg.ca_subject_cn(der))
        self.assertIsNone(gg.ca_subject_cn(os.path.join(TMP, "missing.crt")))
        self.assertIsNone(gg.ca_subject_cn(TMP))  # a directory
        os.unlink(der)

    def test_cert_method(self):
        pem = lambda cn, issuer: cert_info_for(cn, 1, issuer)[gg.CERT_PEM_HEADER]  # noqa: E731
        self.assertEqual(gg.cert_method(pem("bob", YUBIKEY_CA_CN)), "yubikey_cert")
        self.assertEqual(gg.cert_method(pem("bob", BROWSER_CA_CN)), "browser_cert")
        # A leaf signed by an unknown CA, the root, or nothing counts as nothing.
        self.assertIsNone(gg.cert_method(pem("bob", "example.com Root CA")))
        self.assertIsNone(gg.cert_method(pem("bob", "Someone Else CA")))
        self.assertIsNone(gg.cert_method(""))
        # An impostor CA with the YubiKey CA's very name: the issuer name
        # matches, the signature doesn't verify.
        from cryptography import x509 as cx
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        k = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        forged = (cx.CertificateBuilder().subject_name(cx.Name([cx.NameAttribute(cx.NameOID.COMMON_NAME, "bob")]))
                  .issuer_name(ca_pair(YUBIKEY_CA_CN)[0].subject).public_key(k.public_key()).serial_number(5)
                  .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
                  .sign(k, hashes.SHA256()))
        self.assertIsNone(gg.cert_method(pem_header(forged)))
        # The Info header alone never makes a certificate count.
        self.rules(t={"op": "any", "items": ["yubikey_cert"]})
        info_only = {gg.CERT_INFO_HEADER: cert_info_for("bob", 1)[gg.CERT_INFO_HEADER]}
        self.assertEqual(self.page(amr=["mtls"], cert=info_only)[0], 403)
        self.assertEqual(self.page(amr=["mtls"], cert=cert_info_for("bob", 1))[0], 200)

    def test_crafted_cn_never_fakes_the_issuer(self):
        # Traefik writes Subject="…" unescaped: this CN, signed by pki_file,
        # makes the Info text read Issuer="CN=<YubiKey CA>" first.
        crafted = f'alice";Issuer="CN={YUBIKEY_CA_CN}'
        headers = cert_info_for(crafted, 0x91, BROWSER_CA_CN)
        info = urllib.parse.unquote_plus(headers[gg.CERT_INFO_HEADER])
        self.assertTrue(info.startswith(f'Subject="CN=alice";Issuer="CN={YUBIKEY_CA_CN}"'), info)
        self.assertEqual(gg.cert_method(headers[gg.CERT_PEM_HEADER]), "browser_cert")
        self.assertIsNone(gg.leaf_user(gg.forwarded_leaf(headers[gg.CERT_PEM_HEADER])))
        for rule in ({"op": "any", "items": ["yubikey_cert"]}, {"op": "any", "items": ["browser_cert"]}):
            with self.subTest(rule=rule):
                self.rules(t=rule)
                for amr in (["mtls"], ["file"], ["mtls", "file"]):
                    self.assertEqual(self.page(amr=amr, user="alice", cert=headers)[0], 403)

    def test_cn_must_be_the_username_exactly(self):
        self.rules(t={"op": "any", "items": ["yubikey_cert"]})
        self.assertEqual(self.page(amr=["mtls"], user="alice", cert=cert_info_for("alice", 0x92))[0], 200)
        for cn in ("alice+", "alice ", " alice", "alic%65", "Alice", "alice\x00", "alice,CN=bob", "ali ce"):
            with self.subTest(cn=cn):
                headers = cert_info_for(cn, 0x93)
                self.assertIsNone(gg.bound_cert_method(gg.forwarded_leaf(headers[gg.CERT_PEM_HEADER]), "alice"))
                self.assertEqual(self.page(amr=["mtls"], user="alice", cert=headers)[0], 403)
        # Outside its validity: never bound.
        for days in ((-10, -1), (1, 10)):
            with self.subTest(days=days):
                self.assertEqual(self.page(amr=["mtls"], user="alice",
                                           cert=cert_info_for("alice", 0x94, days=days))[0], 403)

    def test_browser_leaf_never_binds_yubikey(self):
        # amr mtls, but the leaf is a browser certificate (pki_file).
        self.rules(t={"op": "any", "items": ["yubikey_cert"]})
        code, hdrs, body = self.page(amr=["mtls"], user="alice", cert=leaf_info("alice", 5, BROWSER_CA_CN))
        self.assertEqual(code, 403)
        self.assertIn('id="present-certificate"', body)
        self.assertIn("needs your YubiKey certificate", body)
        self.assertEqual(self.page(amr=["mtls"], user="alice", cert=leaf_info("alice", 5))[0], 200)

    def test_yubikey_leaf_binds_only_yubikey(self):
        cert = leaf_info("bob", 6)
        self.rules(t={"op": "any", "items": ["yubikey_cert"]})
        self.assertEqual(self.page(amr=["mtls", "file"], cert=cert)[0], 200)
        self.rules(t={"op": "any", "items": ["browser_cert"]})
        code, hdrs, body = self.page(amr=["mtls", "file"], cert=cert)
        self.assertEqual(code, 403)
        self.assertIn("needs your browser certificate", body)
        self.assertIn("Use the browser it is installed in and reload this page.", body)
        self.assertNotIn("X-Stepup-URL", hdrs)
        # Both needed: a YubiKey leaf can't be both.
        self.rules(t={"op": "all", "items": ["yubikey_cert", "browser_cert"]})
        self.assertEqual(self.page(amr=["mtls", "file"], cert=cert)[0], 403)
        self.assertEqual(gg.session_methods(["mtls", "file"], set(ALL_ON), {"yubikey_cert"}), {"yubikey_cert"})

    def test_browser_cert_binds_with_file(self):
        cert = leaf_info("alice", 7, BROWSER_CA_CN)
        self.rules(t={"op": "any", "items": ["browser_cert"]})
        self.assertEqual(self.page(amr=["file"], user="alice", cert=cert)[0], 200)
        # Without the leaf, another person's, or a YubiKey leaf: not bound.
        self.assertEqual(self.page(amr=["file"], user="alice")[0], 403)
        self.assertEqual(self.page(amr=["file"], user="alice", cert=leaf_info("bob", 7, BROWSER_CA_CN))[0], 403)
        self.assertEqual(self.page(amr=["file"], user="alice", cert=leaf_info("alice", 7))[0], 403)
        # The token's user must agree.
        code = self.page(amr=["file"], user="alice", cert=cert,
                         extra={"X-Forwarded-Access-Token": token(amr=["file"], preferred_username="bob")})[0]
        self.assertEqual(code, 403)
        self.assertEqual(gg.session_methods(["file"], set(ALL_ON), {"browser_cert"}), {"browser_cert"})
        # browser_cert off: never counts, bound or not.
        on = [m for m in ALL_ON if m != "browser_cert"]
        self.assertEqual(gg.session_methods(["file"], set(on), {"browser_cert"}), set())
        write_policy({"methods": on, "templates": {**BASE["templates"], "t": {"op": "any", "items": ["security_key"]}},
                      "hosts": {"grafana.example.com": "t"}})
        self.assertEqual(self.page(amr=["file"], user="alice", cert=cert)[0], 403)

    def test_equal_or_missing_ca_files_count_nothing(self):
        self.rules(t={"op": "any", "items": ["yubikey_cert", "browser_cert"]})
        yk, br = leaf_info("bob", 8), leaf_info("bob", 9, BROWSER_CA_CN)
        self.assertEqual(self.page(amr=["mtls"], cert=yk)[0], 200)
        self.assertEqual(self.page(amr=["file"], cert=br)[0], 200)
        # The same CN in both files: neither kind counts.
        write_ca(BROWSER_CA, YUBIKEY_CA_CN)
        self.assertIsNone(gg.cert_method(yk[gg.CERT_PEM_HEADER]))
        self.assertEqual(self.page(amr=["mtls"], cert=yk)[0], 403)
        self.assertEqual(self.page(amr=["file"], cert=br)[0], 403)
        write_ca(BROWSER_CA, BROWSER_CA_CN)
        # A missing (or unreadable) file: neither kind counts.
        for missing in ("yubikey", "browser"):
            with self.subTest(missing=missing):
                gg.YUBIKEY_CA_FILE = os.path.join(TMP, "nope.crt") if missing == "yubikey" else YUBIKEY_CA
                gg.BROWSER_CA_FILE = os.path.join(TMP, "nope.crt") if missing == "browser" else BROWSER_CA
                self.assertIsNone(gg.cert_method(yk[gg.CERT_PEM_HEADER]))
                self.assertIsNone(gg.cert_method(br[gg.CERT_PEM_HEADER]))
                self.assertEqual(self.page(amr=["mtls"], cert=yk)[0], 403)
                self.assertEqual(self.page(amr=["file"], cert=br)[0], 403)
        gg.YUBIKEY_CA_FILE, gg.BROWSER_CA_FILE = YUBIKEY_CA, BROWSER_CA
        with open(BROWSER_CA, "w") as f:
            f.write("not a certificate")
        self.assertIsNone(gg.cert_method(yk[gg.CERT_PEM_HEADER]))
        self.assertEqual(self.page(amr=["mtls"], cert=yk)[0], 403)

    def test_step_up_never_asks_held_cert_method(self):
        # amr file, no certificate presented: the present-certificate page
        # (browser), never a step-up to browser_cert.
        self.rules(t={"op": "any", "items": ["browser_cert"]})
        code, hdrs, body = self.page(amr=["file"])
        self.assertEqual(code, 403)
        self.assertNotIn("X-Stepup-URL", hdrs)
        self.assertIn('id="present-certificate"', body)
        self.assertIn("grafana.example.com needs your browser certificate", body)
        self.assertIsNone(gg.choose_stepup({"op": "any", "items": ["browser_cert"]}, set(), None,
                                           held=frozenset({"browser_cert"})))
        self.assertEqual(gg.choose_stepup({"op": "any", "items": ["browser_cert"]}, set(), None,
                                          held=frozenset({"yubikey_cert"})), "browser_cert")
        # Signed in with a passkey only: the browser certificate is the step-up.
        code, hdrs, body = self.page(amr=["spk"])
        self.assertIn("pc_method=browser_cert", hdrs.get("X-Stepup-URL", ""))

    # ── revocation lists (contract §4 "Revocation lists") ──

    def crl_cache(self, lists):
        """A CrlCache over a fake Vault: `lists` path -> serials, for the
        four lists core sets."""
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CrlHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_address[1]}/v1"
        _CrlHandler.by_path = {f"/v1/{p}": (200, build_crl(sns, next_update=FRESH)) for p, sns in lists.items()}
        return gg.CrlCache([f"{base}/pki_int/crl", f"{base}/pki_file/crl"], 60,
                           delta_urls=[f"{base}/pki_int/crl/delta", f"{base}/pki_file/crl/delta"])

    def test_revoked_browser_cert_denied_by_pki_file_crl(self):
        cache = self.crl_cache({"pki_int/crl": [], "pki_int/crl/delta": [], "pki_file/crl": [],
                                "pki_file/crl/delta": [0x51]})
        self.assertTrue(cache.refresh())
        gg.CRL_CACHE = cache
        self.rules(t={"op": "any", "items": ["browser_cert", "security_key"]})
        revoked, other = leaf_info("bob", 0x51, BROWSER_CA_CN), leaf_info("bob", 0x52, BROWSER_CA_CN)
        for host, groups in (("grafana.example.com", "users_grafana"), ("random.example.com", ""),
                             ("hub.example.com", "lldap_admin"), ("people.example.com", "")):
            with self.subTest(host=host):
                code, hdrs, body = self.page(host=host, amr=["hwk"], groups=groups, cert=revoked)
                self.assertEqual(code, 403)
                self.assertIn("revoked", body)
                self.assertEqual(self.page(host=host, amr=["hwk"], groups=groups, cert=other)[0], 200)
        self.assertEqual(self.page(amr=["file"], cert=other)[0], 200)

    def test_crl_lists_union(self):
        cache = self.crl_cache({"pki_int/crl": [0x61], "pki_int/crl/delta": [0x62], "pki_file/crl": [0x63],
                                "pki_file/crl/delta": [0x64]})
        _CrlHandler.fetched = []
        self.assertTrue(cache.refresh())
        # Every delta before every full CRL.
        self.assertEqual(_CrlHandler.fetched, ["/v1/pki_int/crl/delta", "/v1/pki_file/crl/delta",
                                               "/v1/pki_int/crl", "/v1/pki_file/crl"])
        gg.CRL_CACHE = cache
        write_revoked(["65"])
        self.assertEqual(gg.revoked_serials(), {0x61, 0x62, 0x63, 0x64, 0x65})
        for sn in (0x61, 0x62, 0x63, 0x64, 0x65):
            for issuer in (YUBIKEY_CA_CN, BROWSER_CA_CN):
                with self.subTest(sn=sn, issuer=issuer):
                    self.assertEqual(self.page(host="random.example.com", groups="",
                                               cert=leaf_info("bob", sn, issuer))[0], 403)
        self.assertEqual(self.page(host="random.example.com", groups="", cert=leaf_info("bob", 0x66))[0], 200)
        # A list that fails later keeps its last good serials.
        _CrlHandler.by_path["/v1/pki_file/crl/delta"] = (503, b"sealed")
        self.assertFalse(cache.refresh())
        self.assertIn(0x64, cache.serials)
        self.assertTrue(cache.ready)

    def test_crl_never_read_counts_no_certificate(self):
        # A list that has never been read: no certificate counts as a
        # method (an unreadable CRL list fails closed); other methods do.
        cache = self.crl_cache({"pki_int/crl": [], "pki_int/crl/delta": [], "pki_file/crl": []})
        _CrlHandler.by_path["/v1/pki_file/crl/delta"] = (500, b"")
        self.assertFalse(cache.refresh())
        self.assertFalse(cache.ready)
        gg.CRL_CACHE = cache
        self.rules(t={"op": "any", "items": ["yubikey_cert", "security_key"]})
        code, hdrs, body = self.page(amr=["mtls"], cert=leaf_info("bob", 0x70))
        self.assertEqual(code, 403)
        self.assertIn('id="present-certificate"', body)
        self.assertEqual(self.page(amr=["hwk"], cert=leaf_info("bob", 0x70))[0], 200)
        _CrlHandler.by_path["/v1/pki_file/crl/delta"] = (200, build_crl([], next_update=FRESH))
        self.assertTrue(cache.refresh())
        self.assertEqual(self.page(amr=["mtls"], cert=leaf_info("bob", 0x70))[0], 200)

    def test_no_crl_list_counts_no_certificate(self):
        gg.CRL_CACHE = None
        self.assertFalse(gg.crl_ready())
        self.rules(t={"op": "any", "items": ["yubikey_cert", "security_key"]})
        self.assertEqual(self.page(amr=["mtls"], cert=leaf_info("bob", 0x71))[0], 403)
        self.assertEqual(self.page(amr=["hwk"])[0], 200)

    def test_stale_crl_counts_no_certificate(self):
        # Past nextUpdate + 1 h (Keycloak's crl-abort-if-non-updated): not
        # ready until it is read again with a fresh nextUpdate.
        def utc(t):
            return _der(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(t)).encode())
        cache = self.crl_cache({"pki_int/crl": [], "pki_int/crl/delta": [], "pki_file/crl": [],
                                "pki_file/crl/delta": []})
        _CrlHandler.by_path["/v1/pki_int/crl"] = (200, build_crl([], next_update=utc(time.time() - 3700)))
        self.assertTrue(cache.refresh())
        self.assertFalse(cache.ready)
        gg.CRL_CACHE = cache
        self.rules(t={"op": "any", "items": ["yubikey_cert"]})
        self.assertEqual(self.page(amr=["mtls"], cert=leaf_info("bob", 0x72))[0], 403)
        # Within the grace: ready.
        _CrlHandler.by_path["/v1/pki_int/crl"] = (200, build_crl([], next_update=utc(time.time() - 3000)))
        self.assertTrue(cache.refresh())
        self.assertTrue(cache.ready)
        self.assertEqual(self.page(amr=["mtls"], cert=leaf_info("bob", 0x72))[0], 200)
        # No nextUpdate at all: never ready.
        _CrlHandler.by_path["/v1/pki_int/crl"] = (200, build_crl([], with_next_update=False))
        self.assertTrue(cache.refresh())
        self.assertFalse(cache.ready)

    def coverage_cache(self, lists):
        """A CrlCache over a fake Vault serving `lists` (path -> issuer CN;
        paths ending in /delta are GATE_DELTA_CRL_URLS), every list read."""
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CrlHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        base = f"http://127.0.0.1:{srv.server_address[1]}/v1"
        _CrlHandler.by_path = {f"/v1/{p}": (200, build_crl([], next_update=FRESH, issuer_cn=cn))
                               for p, cn in lists.items()}
        cache = gg.CrlCache([f"{base}/{p}" for p in lists if not p.endswith("/delta")], 60,
                            delta_urls=[f"{base}/{p}" for p in lists if p.endswith("/delta")])
        self.assertTrue(cache.refresh())
        return cache

    def test_crl_coverage_warning(self):
        # M9: crl_ready() needs every configured list, not one per CA; a
        # CA no configured list belongs to is a start-up warning.
        both = {"pki_int/crl": YUBIKEY_CA_CN, "pki_int/crl/delta": YUBIKEY_CA_CN,
                "pki_file/crl": BROWSER_CA_CN, "pki_file/crl/delta": BROWSER_CA_CN}
        self.assertEqual(gg.crl_coverage_problems(self.coverage_cache(both)), [])
        # Only pki_int's lists: the browser CA has neither.
        cache = self.coverage_cache({"pki_int/crl": YUBIKEY_CA_CN, "pki_int/crl/delta": YUBIKEY_CA_CN})
        self.assertTrue(cache.ready)  # certificates count: hence the warning
        got = gg.crl_coverage_problems(cache)
        self.assertEqual(len(got), 1, got)
        self.assertIn("GATE_CRL_URLS / GATE_DELTA_CRL_URLS", got[0])
        self.assertIn(f"browser CA {BROWSER_CA_CN!r}", got[0])
        self.assertIn("GATE_REVOKED_FILE alone", got[0])
        # pki_file's delta missing: only the delta list named.
        got = gg.crl_coverage_problems(self.coverage_cache(
            {k: v for k, v in both.items() if k != "pki_file/crl/delta"}))
        self.assertEqual(len(got), 1, got)
        self.assertIn("no list in GATE_DELTA_CRL_URLS is", got[0])
        self.assertIn("its full CRL", got[0])
        # pki_int's full CRL missing: the YubiKey CA, its delta still read.
        got = gg.crl_coverage_problems(self.coverage_cache({k: v for k, v in both.items() if k != "pki_int/crl"}))
        self.assertEqual(len(got), 1, got)
        self.assertIn("no list in GATE_CRL_URLS is", got[0])
        self.assertIn(f"YubiKey CA {YUBIKEY_CA_CN!r}", got[0])
        self.assertIn("its delta CRL", got[0])
        # A list issued by another CA (same URLs) matches nothing.
        got = gg.crl_coverage_problems(self.coverage_cache({k: "Test CA" for k in both}))
        self.assertEqual(len(got), 2, got)
        # A CA file that doesn't load is skipped (no certificate of it counts);
        # no lists at all are warned about separately.
        gg.BROWSER_CA_FILE = os.path.join(TMP, "nope.crt")
        self.assertEqual(gg.crl_coverage_problems(self.coverage_cache(
            {"pki_int/crl": YUBIKEY_CA_CN, "pki_int/crl/delta": YUBIKEY_CA_CN})), [])
        gg.CRL_CACHE = None
        self.assertEqual(gg.crl_coverage_problems(), [])

    def test_crl_coverage_checked_once_after_first_read(self):
        cache = self.coverage_cache({"pki_int/crl": YUBIKEY_CA_CN, "pki_int/crl/delta": YUBIKEY_CA_CN})
        calls, sleeps = [], []

        def sleep(_):
            sleeps.append(1)
            if len(sleeps) == 3:
                raise StopIteration

        old_sleep = gg.time.sleep
        gg.time.sleep = sleep
        try:
            with self.assertRaises(StopIteration):
                cache.run_forever(lambda: calls.append(1))
        finally:
            gg.time.sleep = old_sleep
        self.assertEqual(calls, [1])  # three passes, one check
        # Never read (nothing listens on port 1): no check yet.
        unread = gg.CrlCache(["http://127.0.0.1:1/v1/pki_int/crl"], 60)
        sleeps.clear()
        gg.time.sleep = sleep
        try:
            with self.assertRaises(StopIteration):
                unread.run_forever(lambda: calls.append(2))
        finally:
            gg.time.sleep = old_sleep
        self.assertEqual(calls, [1])

    def test_old_crl_variables_refuse_to_start(self):
        for var in ("GATE_CRL_URL", "GATE_DELTA_CRL_URL"):
            with self.subTest(var=var):
                env = dict(os.environ, **{var: "http://vault:8200/v1/pki_int/crl"})
                r = subprocess.run([sys.executable, GATE_PATH], env=env, capture_output=True, text=True, timeout=30)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(f"{var} no longer exist", r.stderr)
                self.assertIn("GATE_CRL_URLS", r.stderr)
                self.assertIn("refusing to start", r.stderr)
        self.assertIsNone(gg.startup_problem())

    def test_crl_env_lists(self):
        env = dict(os.environ, GATE_CRL_URLS="http://v/pki_int/crl  http://v/pki_file/crl",
                   GATE_DELTA_CRL_URLS="http://v/pki_int/crl/delta http://v/pki_file/crl/delta",
                   GATE_CRL_URL="http://old", GATE_DELTA_CRL_URL="http://old/delta")
        out = subprocess.run(
            [sys.executable, "-c", "import importlib.util,sys;"
             f"s=importlib.util.spec_from_file_location('g',{GATE_PATH!r});m=importlib.util.module_from_spec(s);"
             "s.loader.exec_module(m);print(m.CRL_URLS, m.DELTA_CRL_URLS, [x.url for x in m.CRL_CACHE.sources])"],
            env=env, capture_output=True, text=True, check=True).stdout
        self.assertEqual(out.strip(), "['http://v/pki_int/crl', 'http://v/pki_file/crl'] "
                         "['http://v/pki_int/crl/delta', 'http://v/pki_file/crl/delta'] "
                         "['http://v/pki_int/crl/delta', 'http://v/pki_file/crl/delta', "
                         "'http://v/pki_int/crl', 'http://v/pki_file/crl']")
        self.assertNotIn("http://old", out)

    # ── the Sign-in paths (contract §4 "Sign-in paths") ──

    def test_signin_paths_exact_after_normalising(self):
        ok = ("/signin", "/signin?x=1", "/api/me/signin", "/api/me/signin/history",
              "/api/me/signin/history?before=2026-11-11T00:00:00Z&limit=5",
              "/api/me/signin/certificates/1a:2b", "/static/a.js", "/static/css/x.css", "/%73ignin")
        bad = ("/signin/../api/directory", "/static/../api/directory", "/api/me/signinx", "/api/me/signin%2F..%2Fapps",
               "/Signin", "/", "", "/signin/", "/api/me/signin/", "/static/", "/static", "/api/me/signin/../../apps",
               "/api/me/signin/x/../../../directory", "/static/%2e%2e/api/directory", "/static/%252e%252e/api/x",
               "/static\\..\\api\\directory", "/static/a%5c..%5capi", "/api/me/signin/x%2Fy", "/api/me/signin;x/../../apps",
               "/signin;jsessionid=1", "/signin#x", "/signin%00", "/static/a%0a", "//signin/../hub", "/api/me/apps",
               "http://evil/signin/../api/x", "/static/./../api")
        for path in ok:
            with self.subTest(ok=path):
                self.assertTrue(gg.signin_path("people.example.com", path))
                for c in gg.normalize_path_candidates(path):
                    self.assertTrue(c in ("/signin", "/api/me/signin") or c.startswith(("/api/me/signin/", "/static/")), c)
        for path in bad:
            with self.subTest(bad=path):
                self.assertFalse(gg.signin_path("people.example.com", path))
        for host in ("hub.example.com", "grafana.example.com", "example.com", "people.example.org",
                     "people.team-b.example.org", "PEOPLE.example.com"):
            for path in ok:
                with self.subTest(host=host, path=path):
                    self.assertFalse(gg.signin_path(host, path))

    def test_signin_paths_any_switched_on_method(self):
        # people.<d> on Strong; a password-only session.
        on = sorted(BASE["methods"] + ["password"])
        write_policy({"methods": on, "people": {"bob": ["password"]}})
        for uri in ("/signin", "/api/me/signin/history?limit=5", "/static/mysignin.js"):
            with self.subTest(uri=uri):
                self.assertEqual(self.page(host="people.example.com", amr=["pwd"], groups="", uri=uri)[0], 200)
        # Everywhere else on people.<d> (and the same paths elsewhere), the
        # host's template applies.
        for host, uri, groups in (("people.example.com", "/", ""), ("people.example.com", "/api/directory", ""),
                                  ("people.example.com", "/signin/../api/directory", ""),
                                  ("people.example.com", "/api/me/signin%2F..%2Fapps", ""),
                                  ("people.example.com", "/static/%2e%2e/api/me", ""),
                                  ("people.example.com", "/static/..%5capi", ""),
                                  ("people.example.com", None, ""),
                                  ("hub.example.com", "/signin", "lldap_admin"),
                                  ("grafana.example.com", "/signin", "users_grafana")):
            with self.subTest(host=host, uri=uri):
                code, hdrs, body = self.page(host=host, amr=["pwd"], groups=groups, uri=uri)
                self.assertEqual(code, 403)
                self.assertIn('id="needs-stronger"', body)
        # Password off: the session counts nothing, even on /signin.
        write_policy({"people": {"bob": []}})
        code, hdrs, body = self.page(host="people.example.com", amr=["pwd"], groups="", uri="/signin")
        self.assertEqual(code, 403)
        self.assertIn('id="needs-stronger"', body)
        # A passkey session reaches /signin though people.<d> asks for more.
        self.assertEqual(self.page(host="people.example.com", amr=["spk"], groups="", uri="/signin")[0], 200)
        self.assertEqual(self.page(host="people.example.com", amr=["spk"], groups="", uri="/")[0], 403)
        # Membership checks still run first: a reserved group, a service
        # account and a missing user are denied on /signin too.
        self.assertEqual(self.page(host="people.example.com", amr=["spk"], groups=gg.DENY_GROUP, uri="/signin")[0], 403)
        self.assertEqual(self.page(host="people.example.com", amr=["spk"], groups="", uri="/signin",
                                   user="portcullis-hub")[0], 403)
        # A certificate method still needs its binding on /signin.
        self.assertEqual(self.page(host="people.example.com", amr=["mtls"], groups="", uri="/signin")[0], 403)
        self.assertEqual(self.page(host="people.example.com", amr=["mtls"], groups="", uri="/signin",
                                   cert=leaf_info("bob", 3))[0], 200)

    # ── core hosts ──

    def test_enroll_not_gated_but_reserved(self):
        self.assertNotIn("enroll", gg.GATED_CORE_SUBDOMAINS)
        self.assertIn("enroll", gg.CORE_SUBDOMAINS)
        self.assertEqual(gg.GATED_CORE_SUBDOMAINS, ("traefik", "hub", "directory", "people", "metrics"))
        self.assertNotIn("enroll.example.com", gg.gated_core_hosts())
        # Still a core host: no app (Hub entry) can take the name.
        self.assertIn("enroll.example.com", gg.core_hosts())
        write_policy({"groups": {"enroll.example.com": "users_x"}, "hosts": {"enroll.example.com": "standard"}})
        self.assertEqual(self.req("enroll.example.com", groups="users_x"), 403)
        self.assertIsNotNone(gg.validate_policy_doc({**BASE, "core": dict(BASE["core"], **{"enroll.example.com": "standard"})}))

    # ── the opened log (contract §4 "Opened log") ──

    def opened_lines(self, *logs):
        for log in logs or (gg.OPENED_LOG,):
            self.assertTrue(log.flush())
        out = []
        d = os.path.join(self.log_dir, "opened")
        for name in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            with open(os.path.join(d, name)) as f:
                out += [(name, json.loads(line)) for line in f if line.strip()]
        return out

    def test_opened_log_first_request_per_session_host(self):
        portal = os.path.join(TMP, "portal-apps.json")
        with open(portal, "w") as f:
            json.dump({"version": 1, "apps": [{"id": "g", "name": "Grafana", "access_group": "",
                                               "urls": [{"label": "x", "url": "https://grafana.example.com/"}]}]}, f)
        self.addCleanup(os.unlink, portal)
        old = gg.PORTAL_FILE
        gg.PORTAL_FILE = portal
        self.addCleanup(setattr, gg, "PORTAL_FILE", old)
        ua = "Mozilla/5.0 \x01" + "x" * 400
        extra = {"X-Real-Ip": "203.0.113.7", "User-Agent": ua}
        claims = {"sid": "sid-1", "auth_time": 1700000000}
        for _ in range(3):
            self.assertEqual(self.page(amr=["hwk", "spk"], claims=claims, extra=extra)[0], 200)
        lines = self.opened_lines()
        self.assertEqual(len(lines), 1)
        name, line = lines[0]
        self.assertRegex(name, r"^\d{4}-\d{2}-\d{2}\.jsonl$")
        self.assertEqual(set(line), {"time", "user", "session", "host", "app", "methods", "ip", "ua", "act"})
        self.assertRegex(line["time"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertEqual(name, line["time"][:10] + ".jsonl")
        self.assertEqual({k: v for k, v in line.items() if k not in ("time", "ua")},
                         {"user": "bob", "session": "sid-1", "host": "grafana.example.com", "app": "Grafana",
                          "methods": ["passkey_synced", "security_key"], "ip": "203.0.113.7", "act": ""})
        self.assertEqual(line["ua"], ("Mozilla/5.0 " + "x" * 400)[:256])
        self.assertEqual(len(line["ua"]), 256)
        # Another host: a second line (the app's name falls back to the host).
        self.assertEqual(self.page(host="random.example.com", groups="", amr=["hwk"], claims=claims, extra=extra)[0], 200)
        lines = self.opened_lines()
        self.assertEqual(len(lines), 2)
        self.assertEqual((lines[1][1]["host"], lines[1][1]["app"]), ("random.example.com", "random.example.com"))
        # No sid: <user>@<auth_time>; the portal logs too; a denied
        # request never does.
        self.assertEqual(self.page(host="example.com", groups="", gate_path="/portal",
                                   claims={"auth_time": 1700000001}, user="Bob")[0], 200)
        self.assertEqual(self.page(groups="users_x", claims={"sid": "sid-2"})[0], 403)
        lines = self.opened_lines()
        self.assertEqual(len(lines), 3)
        self.assertEqual((lines[2][1]["session"], lines[2][1]["host"], lines[2][1]["user"]),
                         ("bob@1700000001", "example.com", "bob"))
        # Never a token or any other header.
        with open(os.path.join(self.log_dir, "opened", name)) as f:
            text = f.read()
        self.assertNotIn("eyJ", text)
        # Modes the Hub expects: opened/ 2770 with its group, files 0640.
        st = os.stat(os.path.join(self.log_dir, "opened"))
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o2770)
        self.assertEqual(st.st_gid, os.getgid())
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.log_dir, "opened", name)).st_mode), 0o640)
        # An unwritable directory: the request is still allowed, the
        # failure counted.
        blocker = os.path.join(self.log_dir, "file")
        with open(blocker, "w") as f:
            f.write("x")
        gg.OPENED_LOG = gg.OpenedLog(os.path.join(blocker, "opened"), gid=os.getgid())
        before = gg.METRICS.get("group_gate_opened_log_failures_total")
        self.assertEqual(self.page(amr=["hwk"], claims={"sid": "sid-3"})[0], 200)
        self.assertTrue(gg.OPENED_LOG.flush())
        self.assertEqual(gg.METRICS.get("group_gate_opened_log_failures_total"), before + 1)
        # Not remembered: the next request tries again.
        self.assertEqual(self.page(amr=["hwk"], claims={"sid": "sid-3"})[0], 200)
        self.assertTrue(gg.OPENED_LOG.flush())
        self.assertEqual(gg.METRICS.get("group_gate_opened_log_failures_total"), before + 2)
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/metrics") as r:
            self.assertIn("group_gate_opened_log_failures_total", r.read().decode())

    def test_opened_log_lru_and_bounds(self):
        log = gg.OpenedLog(os.path.join(self.log_dir, "opened"), capacity=2, gid=os.getgid())
        for sid in ("a", "b", "a", "c", "a", "b"):
            log.record("bob", sid, "h.example.com", "H", ["security_key"], "", "")
            self.assertTrue(log.flush())
        # LRU of 2: the repeated "a" is remembered (and refreshed), so "c"
        # evicts "b", which then logs again.
        sessions = [ln["session"] for _, ln in self.opened_lines(log)]
        self.assertEqual(sessions, ["a", "b", "c", "b"])
        # Never raises, whatever it's given; a full day file stops growing.
        log.record(None, "x", None, None, None, None, None)
        log.record("bob", "\n\x00", "h", "H", ["nope", "password"], "1.2.3.4\n", "ua ")
        small = gg.OpenedLog(os.path.join(self.log_dir, "opened"), gid=os.getgid())
        small.DAY_FILE_MAX = 1
        before = gg.METRICS.get("group_gate_opened_log_failures_total")
        small.record("bob", "z", "h.example.com", "H", [], "", "")
        self.assertTrue(small.flush())
        self.assertEqual(gg.METRICS.get("group_gate_opened_log_failures_total"), before + 1)
        self.assertEqual(gg.OpenedLog.DAY_FILE_MAX, 8 << 20)  # the Hub's per-day read window
        for _, ln in self.opened_lines(log):
            self.assertNotIn("\n", ln["session"] + ln["ip"] + ln["ua"])
            self.assertEqual(ln["methods"], [m for m in gg.METHOD_IDS if m in ln["methods"]])
        # A symlinked day file is never written through.
        d = os.path.join(self.log_dir, "opened")
        target = os.path.join(self.log_dir, "target")
        open(target, "w").close()
        day = datetime.datetime(2030, 1, 2, tzinfo=datetime.timezone.utc)
        os.symlink(target, os.path.join(d, "2030-01-02.jsonl"))
        log.record("bob", "s", "h.example.com", "H", [], "", "", now=day)
        self.assertTrue(log.flush())
        self.assertEqual(os.path.getsize(target), 0)

    def test_opened_log_never_blocks_on_a_hung_volume(self):
        # The writer thread is stuck (a hung volume): record() still
        # returns at once, at most QUEUE_MAX lines wait, the rest are
        # dropped and counted, and no other thread is started.
        log = gg.OpenedLog(os.path.join(self.log_dir, "opened"), gid=os.getgid())
        log.QUEUE_MAX = 3
        log._queue = gg.queue.Queue(3)
        release = threading.Event()
        real = log._write
        log._write = lambda now, line: (release.wait(10), real(now, line))
        before = gg.METRICS.get("group_gate_opened_log_failures_total")
        threads = threading.active_count()
        t0 = time.monotonic()
        for i in range(10):
            log.record("bob", f"s{i}", "h.example.com", "H", [], "", "")
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertLessEqual(threading.active_count(), threads + 1)
        # One taken by the writer, three queued, six dropped.
        self.assertGreaterEqual(gg.METRICS.get("group_gate_opened_log_failures_total"), before + 6)
        release.set()
        self.assertTrue(log.flush())
        self.assertEqual(len(self.opened_lines(log)), 10 - (gg.METRICS.get("group_gate_opened_log_failures_total") - before))

    def test_opened_log_failure_logs_are_rate_limited(self):
        import contextlib
        import io
        blocker = os.path.join(self.log_dir, "file")
        open(blocker, "w").close()
        log = gg.OpenedLog(os.path.join(blocker, "opened"), gid=os.getgid())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            for i in range(20):
                log.record("bob", f"s{i}", "h.example.com", "H", [], "", "")
                self.assertTrue(log.flush())
        self.assertEqual(out.getvalue().count("opened log write failed"), 1)
        self.assertIn("NotADirectoryError", log._last_error)
        log._last_log -= log.LOG_EVERY + 1
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            log.record("bob", "late", "h.example.com", "H", [], "", "")
            self.assertTrue(log.flush())
        self.assertIn("20 failure(s) since the last report", out.getvalue())

    # ── links (contract §5, §10) ──

    def test_pages_link_to_signin_page(self):
        signin = "https://people.example.com/signin"
        b = gg.render_needs_page("App", set(), {"op": "all", "items": ["passkey_device", "security_key"]}, set(),
                                 True, "example.com").decode()
        hrefs = re.findall(r'<a id="([^"]+)"[^>]*href="([^"]*)"', b)
        self.assertEqual(dict(hrefs), {"portcullis-set-up-passkey": signin, "portcullis-set-up-security-key": signin,
                                       "portcullis-sign-in-methods": signin})
        self.assertNotIn("account-security", b)
        # Through the gate.
        write_policy({"hosts": {"grafana.example.com": "strong"}, "people": {"bob": ["passkey_synced"]}, "add_stronger": True})
        code, hdrs, body = self.page(amr=["spk"])
        self.assertIn(f'href="{signin}"', body)
        self.assertIn("Set up a security key", body)

    def test_no_enroll_links(self):
        for groups in (set(), {"lldap_admin"}):
            b = gg.render_portal("bob", groups, [], "example.com").decode()
            self.assertNotIn("enroll.", b)
            self.assertNotIn("/self", b)
            self.assertIn('href="https://people.example.com/"', b)
            self.assertIn('<a href="https://people.example.com/signin">Sign-in methods</a>', b)
        b = gg.render_portal("bob", {"lldap_admin"}, [], "example.com").decode()
        for href in ("https://hub.example.com/", "https://auth.example.com/admin/portcullis/console/",
                     "https://traefik.example.com/"):
            self.assertIn(f'href="{href}"', b)
        self.assertNotIn("traefik.example.com", gg.render_portal("bob", set(), [], "example.com").decode())


IMP_ID = "0f3c" + "a" * 28
IMP_REASON = "checking quota"


def rfc3339(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


class ImpersonationTest(GateTest):
    """Sign-in methods part 3 in group-gate: impersonated requests (contract
    §4 "Impersonated requests", §5 the headers and the banner, §8.1
    "Impersonation")."""

    page = SigninPart2Test.page
    rules = SigninPart2Test.rules
    opened_lines = SigninPart2Test.opened_lines
    coverage_cache = SigninPart2Test.coverage_cache

    def setUp(self):
        super().setUp()
        write_revoked(None)
        write_ca(YUBIKEY_CA, YUBIKEY_CA_CN)
        write_ca(BROWSER_CA, BROWSER_CA_CN)
        self._old = gg.OPENED_LOG
        self.log_dir = tempfile.mkdtemp(dir=TMP)
        gg.OPENED_LOG = gg.OpenedLog(os.path.join(self.log_dir, "opened"), gid=os.getgid())
        self.imp_file = os.path.join(self.log_dir, "impersonation.json")
        self._old_imp = gg.IMPERSONATION_FILE
        gg.IMPERSONATION_FILE = self.imp_file
        gg._IMP_CACHE.clear()
        # alice's grafana on Standard; every method on.
        self.rules(t=STANDARD)
        self.write_imp()

    def tearDown(self):
        gg.IMPERSONATION_FILE = self._old_imp
        gg._IMP_CACHE.clear()
        gg.OPENED_LOG = self._old
        gg.CRL_CACHE = READY_CRL
        _CrlHandler.by_path = {}
        write_revoked(None)

    def session(self, **kw):
        now = time.time()
        rec = {"id": IMP_ID, "admin": "root", "target": "alice", "reason": IMP_REASON,
               "started": rfc3339(now - 60), "until": rfc3339(now + 1500), "ended": None}
        rec.update(kw)
        return rec

    def write_imp(self, sessions=None, allowed=True, written=None, raw=None, **extra):
        doc = {"version": 1, "allowed": allowed, "written": rfc3339(time.time() if written is None else written),
               "clients": ["portcullis-forward-auth"], "pending": [],
               "sessions": [self.session()] if sessions is None else sessions, "notices": {}, **extra}
        tmp = self.imp_file + ".tmp"
        with open(tmp, "w") as f:
            f.write(raw if raw is not None else json.dumps(doc))
        os.replace(tmp, self.imp_file)

    def claims(self, admin="root", imp_id=IMP_ID, until=None):
        return {"act": {"sub": admin},
                "pc_imp": {"id": imp_id, "until": int(time.time() + 1500) if until is None else until}}

    def imp(self, host="grafana.example.com", amr=("hwk",), user="alice", groups="users_grafana", claims=None,
            **kw):
        return self.page(host=host, amr=amr, user=user, groups=groups,
                         claims=self.claims() if claims is None else claims, **kw)

    def assert_ended(self, result, person="alice"):
        code, hdrs, body = result
        self.assertEqual(code, 403, body)
        self.assertIn(f"Your session as {person} has ended.", body)
        self.assertIn('href="https://auth.example.com/oauth2/sign_out?rd=https%3A%2F%2Fexample.com%2F"', body)
        for h in gg.IMPERSONATION_HEADERS:
            self.assertNotIn(h, hdrs)
        self.assertNotIn("X-Forwarded-User", hdrs)

    def logged(self, fn):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = fn()
        return result, buf.getvalue()

    # ── the claims ──

    def test_imp_claims_parse(self):
        good = {"act": {"sub": "root"}, "pc_imp": {"id": IMP_ID, "until": 1800000000}}
        self.assertEqual(gg.impersonation_claims(good), (True, gg.Impersonation(IMP_ID, "root", 1800000000.0)))
        self.assertEqual(gg.impersonation_claims({**good, "pc_imp": {"id": IMP_ID, "until": 1.8e9}})[1].until, 1.8e9)
        self.assertEqual(gg.impersonation_claims({}), (False, None))
        self.assertEqual(gg.impersonation_claims({"amr": ["hwk"], "sub": "x"}), (False, None))
        bad = [
            {"act": good["act"]},                                    # act only
            {"pc_imp": good["pc_imp"]},                              # pc_imp only
            {**good, "act": "root"},                                 # act not an object
            {**good, "act": {"sub": "Root"}},                        # not a username
            {**good, "act": {"sub": ""}},
            {**good, "act": {"sub": "root", "x": 1}},                # not exactly the shape
            {**good, "act": {}},
            {**good, "act": None},
            {**good, "pc_imp": None},
            {**good, "pc_imp": {"id": "XYZ", "until": 1800000000}},
            {**good, "pc_imp": {"id": IMP_ID.upper(), "until": 1800000000}},
            {**good, "pc_imp": {"id": IMP_ID + "\n", "until": 1800000000}},
            {**good, "pc_imp": {"id": IMP_ID, "until": "x"}},
            {**good, "pc_imp": {"id": IMP_ID, "until": "1800000000"}},
            {**good, "pc_imp": {"id": IMP_ID, "until": True}},
            {**good, "pc_imp": {"id": IMP_ID, "until": float("nan")}},
            {**good, "pc_imp": {"id": IMP_ID, "until": float("inf")}},
            {**good, "pc_imp": {"id": IMP_ID}},
            {**good, "pc_imp": {"id": IMP_ID, "until": 1800000000, "reason": "x"}},
            {**good, "pc_imp": [IMP_ID, 1800000000]},
        ]
        for c in bad:
            with self.subTest(claims=c):
                self.assertEqual(gg.impersonation_claims(c), (True, None))

    def test_imp_malformed_claims_denied(self):
        # Task 2 review: pc_imp without act, act without pc_imp, act not a
        # username, until passed: the ended page, never the person's app.
        c = self.claims()
        for claims in ({"pc_imp": c["pc_imp"]}, {"act": c["act"]}, {**c, "act": {"sub": "Root!"}},
                       self.claims(until=int(time.time()) - 1), self.claims(until=int(time.time()))):
            with self.subTest(claims=claims):
                self.assert_ended(self.imp(claims=claims))

    # ── live, headers, ended ──

    def test_imp_live_allows_with_headers(self):
        code, hdrs, body = self.imp()
        self.assertEqual(code, 200, body)
        self.assertEqual(hdrs.get("X-Forwarded-Impersonator"), "root")
        self.assertEqual(hdrs.get("X-Forwarded-Impersonation"), IMP_ID)
        self.assertEqual(hdrs.get("X-Forwarded-User"), "alice")
        # Without the claims alice's own session is untouched.
        code, hdrs, _ = self.page(user="alice")
        self.assertEqual(code, 200)
        for h in gg.IMPERSONATION_HEADERS:
            self.assertNotIn(h, hdrs)

    def test_imp_ended_denied_at_once(self):
        self.assertEqual(self.imp()[0], 200)
        self.assertEqual(self.imp(host="people.example.com", groups="")[0], 200)
        self.assertEqual(self.imp(host="example.com", groups="", gate_path="/portal")[0], 200)
        self.write_imp(sessions=[self.session(ended=rfc3339(time.time() - 1))])
        (result, out) = self.logged(self.imp)
        self.assert_ended(result)
        self.assertIn("reason=impersonation_ended", out)
        self.assertIn("DENIED", out)
        self.assertNotIn(IMP_REASON, out)
        self.assert_ended(self.imp(host="people.example.com", groups=""))
        self.assert_ended(self.imp(host="people.example.com", groups="", uri="/impersonation/stop"))
        self.assert_ended(self.imp(host="example.com", groups="", gate_path="/portal"))
        # Dropped from the file, or switched off: the same.
        for kw in ({"sessions": []}, {"allowed": False}):
            with self.subTest(**kw):
                self.write_imp(**kw)
                self.assert_ended(self.imp())
                self.assert_ended(self.imp(host="example.com", groups="", gate_path="/portal"))

    def test_imp_portal_path(self):
        portal = os.path.join(self.log_dir, "portal-apps.json")
        with open(portal, "w") as f:
            json.dump({"version": 1, "apps": []}, f)
        old = gg.PORTAL_FILE
        gg.PORTAL_FILE = portal
        self.addCleanup(setattr, gg, "PORTAL_FILE", old)
        code, hdrs, body = self.imp(host="example.com", groups="", gate_path="/portal")
        self.assertEqual(code, 200, body)
        self.assertIn('id="pc-imp-banner"', body)
        self.assertIn("You are signed in as alice (by root)", body)
        self.assertIn('href="https://people.example.com/impersonation/stop"', body)
        self.assertIn("default-src 'none'", hdrs["Content-Security-Policy"])
        # The portal's own template binds root's certificate, never alice's.
        write_policy({"methods": ALL_ON, "templates": {**BASE["templates"], "c": {"op": "any", "items": ["yubikey_cert"]}},
                      "core": {**BASE["core"], "example.com": "c"}})
        p = dict(host="example.com", groups="", gate_path="/portal", amr=["mtls"])
        self.assertEqual(self.imp(cert=leaf_info("root", 0x51), **p)[0], 200)
        code, _, body = self.imp(cert=leaf_info("alice", 0x52), **p)
        self.assertEqual(code, 403)
        self.assertIn('id="needs-stronger"', body)
        self.assertIn('id="pc-imp-banner"', body)
        self.assertNotIn('id="present-certificate"', body)
        # Ended: the ended page.
        self.write_imp(sessions=[self.session(ended=rfc3339(time.time()))])
        self.assert_ended(self.imp(cert=leaf_info("root", 0x51), **p))
        # Without a file at all.
        os.unlink(self.imp_file)
        self.assert_ended(self.imp(cert=leaf_info("root", 0x51), **p))
        # alice's own portal (no claims) never reads it.
        self.assertEqual(self.page(user="alice", cert=leaf_info("alice", 0x52), **p)[0], 200)

    def test_imp_ended_field_validated(self):
        self.write_imp(sessions=[self.session(ended=None)])
        self.assertEqual(self.imp()[0], 200)
        self.write_imp(sessions=[self.session(ended=rfc3339(time.time() + 600))])
        self.assert_ended(self.imp())
        for bad in (5, "x", {}, [], True, "", rfc3339(time.time()) + "\n"):
            with self.subTest(ended=bad):
                self.write_imp(sessions=[self.session(ended=bad)])
                self.assert_ended(self.imp())
        # Missing `ended` is not null.
        rec = self.session()
        del rec["ended"]
        self.write_imp(sessions=[rec])
        self.assert_ended(self.imp())

    def test_imp_file_shape_validated(self):
        # Any field group-gate uses outside its rule: the file is invalid,
        # no impersonation counts; normal requests unaffected.
        cases = [
            {"raw": "not json"}, {"raw": "[]"}, {"raw": ""},
            {"version": 2}, {"version": "1"}, {"version": True},
            {"allowed": "true"}, {"allowed": 1},
            {"written": "yesterday"}, {"written": None},
            {"sessions": None}, {"sessions": {}}, {"sessions": ["x"]},
            {"sessions": [self.session(), self.session()]},
            {"sessions": [self.session(id="XYZ")]},
            {"sessions": [self.session(admin="Root")]}, {"sessions": [self.session(target="")]},
            {"sessions": [self.session(admin=None)]},
            {"sessions": [self.session(reason="no")]}, {"sessions": [self.session(reason="a\nb c")]},
            {"sessions": [self.session(reason="x" * 201)]}, {"sessions": [self.session(reason="ab\u202ecd")]},
            {"sessions": [self.session(reason=None)]},
            {"sessions": [self.session(until="soon")]}, {"sessions": [self.session(until=1800000000)]},
        ]
        for kw in cases:
            with self.subTest(**{k: repr(v)[:60] for k, v in kw.items()}):
                raw = kw.pop("raw", None)
                if raw is None:
                    doc = {"version": 1, "allowed": True, "written": rfc3339(time.time()),
                           "sessions": [self.session()]}
                    doc.update(kw)
                    raw = json.dumps(doc)
                self.write_imp(raw=raw)
                self.assertIsNone(gg.load_impersonation_file())
                self.assert_ended(self.imp())
                self.assertEqual(self.page(user="alice")[0], 200)
        # A minimal valid file (unused fields absent) is fine.
        self.write_imp(raw=json.dumps({"version": 1, "allowed": True, "written": rfc3339(time.time()),
                                       "sessions": [self.session()]}))
        self.assertEqual(self.imp()[0], 200)

    def test_imp_file_cached_and_failure_logged_once(self):
        self.write_imp(raw="{")
        (_, out) = self.logged(lambda: [gg.load_impersonation_file() for _ in range(3)])
        self.assertEqual(len(out.splitlines()), 1, out)
        self.assertNotIn(IMP_REASON, out)
        self.write_imp()
        self.assertIsNotNone(gg.load_impersonation_file())
        # Parsed once per (inode, mtime, size).
        calls = []
        real = gg.json.load
        gg.json.load = lambda f: calls.append(1) or real(f)
        try:
            for _ in range(3):
                gg.load_impersonation_file()
        finally:
            gg.json.load = real
        self.assertEqual(calls, [])

    def test_imp_file_too_deep_cached_and_logged_once(self):
        # json.load raises RecursionError (not a ValueError) on deep
        # nesting: still "invalid", cached, logged once, no crash.
        self.write_imp(raw="[" * 200000 + "]" * 200000)
        calls = []
        real = gg.json.load
        gg.json.load = lambda f: calls.append(1) or real(f)
        try:
            (results, out) = self.logged(lambda: [gg.load_impersonation_file() for _ in range(3)])
        finally:
            gg.json.load = real
        self.assertEqual(results, [None, None, None])
        self.assertEqual(calls, [1])
        self.assertEqual(len(out.splitlines()), 1, out)
        self.assertIn("is invalid", out)
        self.assert_ended(self.imp())
        self.assertEqual(self.page(user="alice")[0], 200)

    def test_imp_needs_page_without_missing_methods(self):
        # Nothing of the rule is missing from `have` (e.g. a switched-off
        # method): the fallback words, never "needs ." with nothing.
        now = time.time()
        rec = {"id": IMP_ID, "admin": "root", "target": "alice", "reason": IMP_REASON, "until": now + 600,
               "ended": None}
        b = gg.render_needs_page("App", {"security_key", "yubikey_cert"}, STRONG, None, False, "example.com",
                                 impersonated=rec).decode()
        self.assertIn("App needs a stronger sign-in. root&#x27;s sign-in didn&#x27;t meet it, and a session as alice", b)
        self.assertNotIn("needs .", b)

    def test_imp_claims_from_access_token_only(self):
        tok = token(amr=["hwk"], preferred_username="alice", **self.claims(until=int(time.time()) - 5))
        # In Authorization only (the Keycloak console's route): not read.
        code, hdrs, _ = self.page(user="alice", extra={"Authorization": f"Bearer {tok}"})
        self.assertEqual(code, 200)
        for h in gg.IMPERSONATION_HEADERS:
            self.assertNotIn(h, hdrs)
        # In X-Forwarded-Access-Token: read (and here ended).
        self.assert_ended(self.page(user="alice", extra={"X-Forwarded-Access-Token": tok}))

    def test_imp_until_claim_wins(self):
        now = time.time()
        # The file's until later, the claim's passed.
        self.write_imp(sessions=[self.session(until=rfc3339(now + 1500))])
        self.assert_ended(self.imp(claims=self.claims(until=int(now) - 1)))
        # The reverse: the claim later, the file's passed.
        self.write_imp(sessions=[self.session(until=rfc3339(now - 1))])
        self.assert_ended(self.imp(claims=self.claims(until=int(now) + 1500)))
        # Through live_impersonation: now at either until is not live.
        self.write_imp(sessions=[self.session(until=rfc3339(now + 100))])
        imp = gg.Impersonation(IMP_ID, "root", float(int(now) + 200))
        self.assertIsNotNone(gg.live_impersonation(imp, "alice", now))
        self.assertIsNone(gg.live_impersonation(imp, "alice", gg._parse_rfc3339(rfc3339(now + 100))))
        self.assertIsNone(gg.live_impersonation(gg.Impersonation(IMP_ID, "root", now + 50), "alice", now + 50))

    def test_imp_stale_file_denies(self):
        self.write_imp(written=time.time() - 301)
        (result, out) = self.logged(self.imp)
        self.assert_ended(result)
        self.assertIn("300", out)
        (_, out) = self.logged(self.imp)
        self.assertNotIn("impersonation.json", out)  # once per change
        self.assertEqual(self.page(user="alice")[0], 200)
        self.write_imp(written=time.time() - 200)
        self.assertEqual(self.imp()[0], 200)
        # Unreadable.
        os.chmod(self.imp_file, 0)
        self.addCleanup(lambda: os.path.exists(self.imp_file) and os.chmod(self.imp_file, 0o644))
        if os.geteuid() != 0:
            gg._IMP_CACHE.clear()
            self.assert_ended(self.imp())
        os.chmod(self.imp_file, 0o644)
        # A directory in its place, missing, switched off.
        os.unlink(self.imp_file)
        self.assert_ended(self.imp())
        os.mkdir(self.imp_file)
        self.assert_ended(self.imp())
        os.rmdir(self.imp_file)
        self.write_imp(allowed=False)
        self.assert_ended(self.imp())
        self.assertEqual(self.page(user="alice")[0], 200)
        self.assertEqual(self.page(user="bob")[0], 200)

    def test_imp_admin_or_person_mismatch(self):
        # act.sub bob, the file's admin root.
        self.assert_ended(self.imp(claims=self.claims(admin="bob")))
        # The file's target carol.
        self.write_imp(sessions=[self.session(target="carol")])
        self.assert_ended(self.imp())
        # The token's preferred_username isn't the forward-auth user.
        self.write_imp()
        h = {"X-Forwarded-Access-Token": token(amr=["hwk"], preferred_username="carol", **self.claims())}
        self.assert_ended(self.page(user="alice", extra=h))
        # Another id.
        self.assert_ended(self.imp(claims=self.claims(imp_id="b" * 32)))
        # A pending-only record never counts.
        self.write_imp(sessions=[], pending=[{"id": IMP_ID, "admin": "root", "target": "alice"}])
        self.assert_ended(self.imp())

    def test_imp_cert_binds_admin_only(self):
        self.rules(t={"op": "any", "items": ["yubikey_cert"]})
        code, hdrs, body = self.imp(amr=["mtls"], cert=leaf_info("root", 0x61))
        self.assertEqual(code, 200, body)
        self.assertEqual(hdrs.get("X-Forwarded-Impersonator"), "root")
        for cert in (leaf_info("alice", 0x62), None):
            with self.subTest(cert=cert is not None):
                code, hdrs, body = self.imp(amr=["mtls"], cert=cert)
                self.assertEqual(code, 403)
                self.assertIn('id="needs-stronger"', body)
                self.assertNotIn('id="present-certificate"', body)
                self.assertNotIn("X-Stepup-URL", hdrs)
        # root's browser certificate never binds yubikey_cert.
        code, _, body = self.imp(amr=["mtls", "file"], cert=leaf_info("root", 0x63, issuer=BROWSER_CA_CN))
        self.assertEqual(code, 403)
        # root's revoked leaf: denied at the start (revocation runs first,
        # on every host), never allowed.
        write_revoked(["61"])
        code, _, body = self.imp(amr=["mtls"], cert=leaf_info("root", 0x61))
        self.assertEqual(code, 403)
        self.assertIn("revoked", body)
        # A revoked leaf through the template alone (no revocation pass):
        # needs page.
        self.assertIsNone(gg.bound_cert_method(issue_leaf("root", 0x61, YUBIKEY_CA_CN), "root"))
        write_revoked(None)
        # alice's own session with her certificate is unaffected.
        self.assertEqual(self.page(user="alice", amr=["mtls"], cert=leaf_info("alice", 0x62))[0], 200)

    def test_imp_never_steps_up(self):
        # Strong on the host; root's session has a synced passkey only:
        # a step-up to a security key would be completable for alice.
        self.rules(t=STRONG)
        write_policy({"methods": ALL_ON, "templates": {**BASE["templates"], "t": STRONG},
                      "hosts": {"grafana.example.com": "t"}, "people": {"alice": ["security_key"]},
                      "add_stronger": True})
        self.assertIn("X-Stepup-URL", self.page(user="alice", amr=["spk"])[1])  # alice's own
        code, hdrs, body = self.imp(amr=["spk"])
        self.assertEqual(code, 403)
        self.assertNotIn("X-Stepup-URL", hdrs)
        self.assertNotIn('id="stepup-continue"', body)
        self.assertIn('id="needs-stronger"', body)
        self.assertIn("root&#x27;s sign-in didn&#x27;t use them, and a session as alice can&#x27;t add one: "
                      "Stop, sign in with them, and start again.", body)
        self.assertIn("grafana.example.com needs a security key or a YubiKey certificate.", body)
        self.assertNotIn("portcullis-set-up", body)
        self.assertNotIn("people.example.com/signin", body)
        self.assertIn('href="https://people.example.com/impersonation/stop"', body)
        self.assertIn('id="pc-imp-banner"', body)

    def test_imp_signin_paths(self):
        imp_paths = ("/impersonation/stop", "/api/me/impersonation", "/api/me/impersonation/stop")
        for p in imp_paths:
            with self.subTest(path=p):
                self.assertTrue(gg.signin_path("people.example.com", p, impersonated=True))
                # Only for a live impersonation (security review ruling).
                self.assertFalse(gg.signin_path("people.example.com", p))
                self.assertFalse(gg.signin_path("hub.example.com", p, impersonated=True))
        for p in ("/impersonation/stop/../api/directory", "/impersonation", "/impersonation/stop/x",
                  "/api/me/impersonation/", "/api/me/impersonation/stopx", "/impersonation%2Fstop"):
            with self.subTest(bad=p):
                self.assertFalse(gg.signin_path("people.example.com", p, impersonated=True))
        # Part 2's set is unchanged; the three are their own list.
        self.assertEqual(gg.SIGNIN_EXACT, ("/signin", "/api/me/signin"))
        self.assertEqual(gg.SIGNIN_IMPERSONATION_EXACT, imp_paths)
        self.assertTrue(gg.signin_path("people.example.com", "/signin"))
        # Stop reachable from an impersonated session people.<d>'s template
        # refuses; a weak normal session on the same paths gets the people
        # template's answer (step-up or needs page), like any other route.
        write_policy({"methods": ALL_ON, "people": {"alice": ["passkey_synced"], "bob": ["passkey_synced"]}})
        for p in imp_paths:
            with self.subTest(live=p):
                code, hdrs, body = self.imp(host="people.example.com", groups="", amr=["spk"], uri=p)
                self.assertEqual(code, 200, body)
                self.assertEqual(hdrs.get("X-Forwarded-Impersonation"), IMP_ID)
            for user in ("alice", "bob"):
                with self.subTest(normal=p, user=user):
                    code, hdrs, body = self.page(host="people.example.com", groups="", amr=["spk"], uri=p, user=user)
                    self.assertEqual(code, 403)
                    self.assertTrue('id="needs-stronger"' in body or "X-Stepup-URL" in hdrs, body)
            with self.subTest(normal_stepup=p):
                write_policy({"methods": ALL_ON, "people": {"bob": ["passkey_synced", "security_key"]}})
                code, hdrs, body = self.page(host="people.example.com", groups="", amr=["spk"], uri=p)
                self.assertEqual(code, 403)
                self.assertIn("X-Stepup-URL", hdrs)
                write_policy({"methods": ALL_ON, "people": {"alice": ["passkey_synced"], "bob": ["passkey_synced"]}})
        self.assertEqual(self.imp(host="people.example.com", groups="", amr=["spk"], uri="/")[0], 403)

    def test_banner_reason_escaped(self):
        now = 1800000000.0
        rec = {"id": IMP_ID, "admin": "root", "target": "alice", "reason": "<script>alert(1)</script> & “q”",
               "until": now + 25 * 60 + 30, "ended": None}
        b = gg.render_banner(rec, now, "example.com")
        self.assertIn("You are signed in as alice (by root) · reason “&lt;script&gt;alert(1)&lt;/script&gt; "
                      "&amp; “q”” · 26 min left", b)
        self.assertNotIn("<script", b)
        self.assertIn('href="https://people.example.com/impersonation/stop"', b)
        self.assertIn(">Stop</a>", b)
        self.assertIn("· 1 min left", gg.render_banner(dict(rec, until=now + 1), now, "example.com"))
        self.assertIn("· 1 min left", gg.render_banner(dict(rec, until=now - 5), now, "example.com"))
        self.assertIn("· 2 min left", gg.render_banner(dict(rec, until=now + 61), now, "example.com"))
        self.assertIn("· 30 min left", gg.render_banner(dict(rec, until=now + 1800), now, "example.com"))
        pages = {
            "portal": gg.render_portal("alice", set(), [], "example.com", banner=b),
            "needs": gg.render_needs_page("App", set(), STRONG, None, False, "example.com", impersonated=rec),
            "stepup": gg.render_stepup_page("App", "security_key", "https://auth.example.com/x", banner=b),
            "certificate": gg.render_certificate_page("App", "yubikey_cert", banner=b),
        }
        for name, page in pages.items():
            with self.subTest(page=name):
                page = page.decode()
                self.assertIn('id="pc-imp-banner"', page)
                self.assertIn("&lt;script&gt;", page)
                self.assertNotIn("<script", page)
        # Through the gate (the reason in the file).
        self.write_imp(sessions=[self.session(reason="<b>x</b> “y”")])
        self.rules(t={"op": "any", "items": ["yubikey_cert"]})
        body = self.imp()[2]
        self.assertIn("reason “&lt;b&gt;x&lt;/b&gt; “y”” ·", body)
        # Every deny page of a live impersonation carries it.
        write_policy({"methods": ALL_ON, "groups": {"grafana.example.com": "users_grafana"}})
        code, _, body = self.imp(groups="users_other")
        self.assertEqual(code, 403)
        self.assertIn('id="pc-imp-banner"', body)

    def test_banner_names_validated(self):
        now = 1800000000.0
        rec = {"id": IMP_ID, "admin": "root", "target": "alice", "reason": IMP_REASON, "until": now + 60, "ended": None}
        self.assertTrue(gg.render_banner(rec, now, "example.com"))
        for k, v in (("admin", "Root"), ("admin", "<b>"), ("target", "al ice"), ("target", ""), ("admin", None),
                     ("reason", "no"), ("reason", None)):
            with self.subTest(**{k: v}):
                self.assertEqual(gg.render_banner(dict(rec, **{k: v}), now, "example.com"), "")
        # In the file: invalid, so no banner and a deny.
        for kw in ({"admin": "Ro<ot"}, {"target": "Alice"}):
            with self.subTest(**kw):
                self.write_imp(sessions=[self.session(**kw)])
                result = self.imp()
                self.assert_ended(result)
                self.assertNotIn('id="pc-imp-banner"', result[2])

    def test_imp_opened_log_act(self):
        claims = dict(self.claims(), sid="sid-imp")
        self.assertEqual(self.imp(claims=claims)[0], 200)
        self.assertEqual(self.page(user="bob", claims={"sid": "sid-own"})[0], 200)
        lines = [line for _, line in self.opened_lines()]
        self.assertEqual([(l["user"], l["session"], l["act"]) for l in lines],
                         [("alice", "sid-imp", "root"), ("bob", "sid-own", "")])
        self.assertNotIn(IMP_REASON, json.dumps(lines))

    def test_client_sent_imp_headers_ignored(self):
        extra = {"X-Forwarded-Impersonator": "root", "X-Forwarded-Impersonation": IMP_ID}
        code, hdrs, _ = self.page(user="alice", extra=extra)
        self.assertEqual(code, 200)
        for h in gg.IMPERSONATION_HEADERS:
            self.assertNotIn(h, hdrs)
        self.assertNotIn("X-Forwarded-Impersonator", gg.identity_headers(extra))

    def test_crl_first_read_failure_logged(self):
        cache = self.coverage_cache({"pki_int/crl": YUBIKEY_CA_CN, "pki_int/crl/delta": YUBIKEY_CA_CN})
        calls, refreshes = [], []
        real_refresh = cache.refresh

        def refresh():
            refreshes.append(1)
            return real_refresh()

        def boom():
            calls.append(1)
            raise RuntimeError("coverage check exploded")

        def sleep(_):
            if len(refreshes) == 3:
                raise StopIteration

        cache.refresh = refresh
        old_sleep = gg.time.sleep
        gg.time.sleep = sleep
        try:
            (_, out) = self.logged(lambda: self.assertRaises(StopIteration, cache.run_forever, boom))
        finally:
            gg.time.sleep = old_sleep
        self.assertEqual(calls, [1])      # tried once, not again
        self.assertEqual(len(refreshes), 3)  # the loop went on
        self.assertIn("coverage check exploded", out)
        self.assertIn("RuntimeError", out)


class BrandingTest(GateTest):
    """The Raised-gate mark and favicon on every group-gate page (polish
    batch 1): inline only — a data: favicon (img-src data:) and the inline
    SVG mark —, never an external load."""

    MARK_SHA256 = "a63ddab1ce0eac394cdbc7547f9fcbc9bf6947060601dd5202527222cef97bfa"  # concept-1-mark-dark.svg
    FAVICON_SHA256 = "8c07f90ac5371f5742ca1837b45ff450f56674c8773ddbcd0b4b03fa17fd2352"  # favicon.svg

    def deny_body(self):
        """A live _deny answer: a non-admin on the Hub."""
        h = {"X-Forwarded-Host": "hub.example.com", "X-Auth-Request-Preferred-Username": "bob",
             "X-Auth-Request-Groups": "users_grafana",
             "X-Forwarded-Access-Token": token(amr=["hwk"], preferred_username="bob")}
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}/", headers=h)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r)
        with cm.exception as e:
            self.assertEqual(e.code, 403)
            return e.read().decode()

    def pages(self):
        now = time.time()
        rec = {"id": IMP_ID, "admin": "root", "target": "alice", "reason": IMP_REASON, "until": now + 600,
               "ended": None}
        return {
            "portal": gg.render_portal("alice", {"lldap_admin"}, [], "example.com").decode(),
            "stepup": gg.render_stepup_page("App", "security_key", "https://auth.example.com/x").decode(),
            "certificate": gg.render_certificate_page("App", "yubikey_cert").decode(),
            "needs": gg.render_needs_page("App", {"passkey_synced"}, STRONG, None, False, "example.com").decode(),
            "needs-impersonated": gg.render_needs_page("App", set(), STRONG, None, False, "example.com",
                                                       impersonated=rec).decode(),
            "ended": gg.render_ended_page("alice", "example.com").decode(),
            "deny": self.deny_body(),
        }

    def test_bytes_pinned(self):
        import hashlib
        self.assertEqual(hashlib.sha256(gg.MARK_SVG.encode()).hexdigest(), self.MARK_SHA256)
        self.assertEqual(hashlib.sha256(gg.FAVICON_SVG.encode()).hexdigest(), self.FAVICON_SHA256)
        import base64
        self.assertEqual(gg.FAVICON_LINK, '<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,'
                         + base64.b64encode(gg.FAVICON_SVG.encode()).decode() + '">')
        self.assertEqual(gg.MARK_HTML, '<span class="pc-mark" aria-hidden="true">' + gg.MARK_SVG.strip() + "</span>")

    def test_every_page_has_mark_and_favicon(self):
        for name, page in self.pages().items():
            with self.subTest(page=name):
                self.assertIn(gg.FAVICON_LINK, page)
                self.assertIn(gg.MARK_HTML, page)
                # The mark opens the page's heading.
                self.assertIn("<h1>" + gg.MARK_HTML, page)

    def test_csp_allows_data_images(self):
        for csp in (gg.PORTAL_CSP, gg.SIGNIN_CSP):
            self.assertIn("img-src data:", csp)
        self.assertIn(".pc-mark{", gg.PORTAL_CSS)
        self.assertTrue(gg.SIGNIN_CSS.startswith(gg.PORTAL_CSS))

    def test_no_external_loads(self):
        for name, page in self.pages().items():
            with self.subTest(page=name):
                self.assertNotIn('src="http', page)
                self.assertNotIn("url(", page)
                for tag in re.findall(r'<(\w+)[^>]*\shref="http', page):
                    self.assertEqual(tag, "a")


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


# ── VPN (policy v7, vpn.json v2, contract §4 / §16) ──

SERVER_KEY = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
PEER_BOB = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
PEER_ALICE = "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0="


def iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def vpn_doc(now=None, hs_stale=False, hs_age=60, bob_expires=None, extra_devices=(), valid_for=3600):
    """A valid vpn.json v2: the built-in (bob .5, alice .6) and a hook
    provider `hs` (bob 100.64.0.7), refreshed hs_age s before now, valid
    until valid_for s after now (the Hub writes now + 1 h)."""
    now = time.time() if now is None else now
    bob_exp = None if bob_expires is None else iso(bob_expires)
    return {
        "version": 2,
        "valid_until": iso(now + valid_for),
        "builtin": {"subnet": "10.213.0.0/22", "server_public_key": SERVER_KEY, "domains": ["example.com"],
                    "peers": [{"ip": "10.213.0.5", "public_key": PEER_BOB, "device_id": "b1", "expires": bob_exp},
                              {"ip": "10.213.0.6", "public_key": PEER_ALICE, "device_id": "a1", "expires": None}]},
        "providers": [
            {"id": "builtin", "source": "builtin", "ranges": ["10.213.0.0/22"], "edge_port": 0, "gateway_ip": "", "stale": False},
            {"id": "hs", "source": "hook", "label": "Tailnet", "ranges": ["100.64.0.0/10"], "edge_port": 9001,
             "gateway_ip": "172.31.254.16", "refreshed_at": iso(now - hs_age), "stale_after": iso(now - hs_age + 180),
             "stale": hs_stale}],
        "devices": [
            {"ip": "10.213.0.5", "provider": "builtin", "user": "bob", "device_id": "b1", "name": "laptop", "expires": bob_exp},
            {"ip": "10.213.0.6", "provider": "builtin", "user": "alice", "device_id": "a1", "name": "phone", "expires": None},
            {"ip": "100.64.0.7", "provider": "hs", "user": "bob", "device_id": "hs:12", "name": "tab", "expires": None},
            *extra_devices],
    }


def write_vpn(doc):
    if doc is None:
        if os.path.exists(VPN_FILE):
            os.remove(VPN_FILE)
        return
    tmp = VPN_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(doc if isinstance(doc, str) else json.dumps(doc))
    os.replace(tmp, VPN_FILE)


def vpn_policy(hosts=None, server_mode=False, admin_only=False, public_enrol=True):
    return {"vpn": {"hosts": hosts if hosts is not None else {}, "server_mode": server_mode,
                    "admin_only": admin_only, "public_enrol": public_enrol, "devices_file": "vpn.json"}}


REQUIRED_TEXT = "This app is only reachable over a Portcullis VPN. Connect your device and reload."
NOT_YOURS = "this device isn't yours; sign in on your own device"
OUT_OF_DATE = "your VPN's device list is out of date; try again in a minute"


class VpnTest(GateTest):
    def setUp(self):
        super().setUp()
        write_vpn(vpn_doc())
        self.addCleanup(write_vpn, None)

    def get(self, host, xff, user="bob", groups="users_app", uri="/", gate_path="/auth/vpn"):
        """(status, body, headers) of a forward-auth request from client
        address `xff` (the X-Forwarded-For Traefik sends), by default on the
        VPN path (portcullis-groups-vpn@docker, vpnsecure routers only)."""
        h = {"X-Forwarded-Host": host, "X-Forwarded-Uri": uri,
             "X-Auth-Request-Preferred-Username": user, "X-Auth-Request-User": "id-" + user,
             "X-Auth-Request-Groups": groups,
             "X-Forwarded-Access-Token": token(amr=["hwk"], preferred_username=user, sid="s-" + user)}
        if xff is not None:
            h["X-Forwarded-For"] = xff
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{gate_path}", headers=h)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, resp.read().decode(), dict(resp.headers)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.read().decode(), dict(e.headers)

    # ── the files ──

    def test_vectors_vpn_json(self):
        with open(os.path.join(HERE, "vpn_json_vectors.json")) as f:
            vectors = json.load(f)
        self.assertGreaterEqual(len(vectors), 8)
        for v in vectors:
            with self.subTest(name=v["name"]):
                raw = v["doc"] if isinstance(v["doc"], str) else json.dumps(v["doc"])
                if "raw" in v:
                    raw = v["raw"]
                now = gg._parse_rfc3339(v["now"])
                try:
                    doc = gg.parse_vpn_doc(json.loads(raw, object_pairs_hook=gg._vpn_pairs))
                except ValueError:
                    doc = None
                if v["want"] != "ok":
                    self.assertIsNone(doc, f"parsed; want a refusal ({v['want']})")
                    continue
                self.assertIsNotNone(doc)
                for d in v.get("deny", []):
                    self.assertIsNone(gg.vpn_device(doc, d["provider"], d["ip"], now), d)
                for a in v.get("allow", []):
                    dev = gg.vpn_device(doc, a["provider"], a["ip"], now)
                    self.assertIsNotNone(dev, a)
                    self.assertEqual(dev["user"], a["user"])

    def test_parse_refusals(self):
        good = vpn_doc()
        cases = {
            "duplicate key": '{"version": 2, "version": 2, "providers": [], "devices": []}',
            "unknown key": dict(good, extra=1),
            "version 1": dict(good, version=1),
            "version true": dict(good, version=True),
            "missing source": dict(good, providers=[good["providers"][0], {k: v for k, v in good["providers"][1].items() if k != "source"}]),
            "unknown source": dict(good, providers=[good["providers"][0], dict(good["providers"][1], source="mesh")]),
            "hook without stale_after": dict(good, providers=[good["providers"][0], {k: v for k, v in good["providers"][1].items() if k != "stale_after"}]),
            "hook stale_after > 30 min": dict(good, providers=[good["providers"][0], dict(good["providers"][1], stale_after="2099-01-01T00:00:00Z")]),
            "static with stale_after": dict(good, providers=[good["providers"][0], dict(good["providers"][1], source="static")]),
            "builtin with stale_after": dict(good, providers=[dict(good["providers"][0], stale_after=good["providers"][1]["stale_after"]), good["providers"][1]]),
            "overlapping ranges": dict(good, providers=[good["providers"][0], dict(good["providers"][1], ranges=["10.213.0.0/16"])]),
            "duplicate edge port": dict(good, providers=[good["providers"][0], good["providers"][1],
                                                         dict(good["providers"][1], id="nb", ranges=["100.200.0.0/16"])]),
            "device outside its ranges": dict(good, devices=[dict(good["devices"][2], ip="10.0.0.7")]),
            "device of an unknown provider": dict(good, devices=[dict(good["devices"][2], provider="x")]),
            "duplicate device ip": dict(good, devices=[good["devices"][2], dict(good["devices"][2], user="eve")]),
            "builtin without builtin section": {k: v for k, v in good.items() if k != "builtin"},
            "bad peer key": dict(good, builtin=dict(good["builtin"], peers=[dict(good["builtin"]["peers"][0], public_key="x")])),
        }
        for name, doc in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    raw = doc if isinstance(doc, str) else json.dumps(doc)
                    gg.parse_vpn_doc(json.loads(raw, object_pairs_hook=gg._vpn_pairs))
        self.assertIsNotNone(gg.parse_vpn_doc(json.loads(json.dumps(good), object_pairs_hook=gg._vpn_pairs)))

    def test_policy_v6_denies(self):
        write_policy(dict(BASE, version=6), raw=True)
        self.assertEqual(self.get("grafana.example.com", "203.0.113.9", groups="users_grafana")[0], 403)

    def test_vpn_unknown_key_denies(self):
        for vpn in ({**BASE["vpn"], "extra": 1}, {k: v for k, v in BASE["vpn"].items() if k != "public_enrol"},
                    dict(BASE["vpn"], hosts={"app.example.com": {"via": ["*"], "x": 1}}),
                    dict(BASE["vpn"], hosts={"app.example.com": {"via": "*"}}),
                    dict(BASE["vpn"], hosts={"app.example.com": {"via": None}}),
                    dict(BASE["vpn"], hosts={"App..example.com": {"via": ["*"]}}),
                    dict(BASE["vpn"], hosts={"app.example.com": {"via": ["a"] * 9}}),
                    dict(BASE["vpn"], hosts={"app.example.com": {"via": ["*", "builtin"]}}),
                    dict(BASE["vpn"], hosts={"app.example.com": {"via": ["Bad Id"]}}),
                    dict(BASE["vpn"], server_mode="yes"), [], None):
            with self.subTest(vpn=vpn):
                self.assertIsNotNone(gg.validate_vpn_section(vpn))
                write_policy(dict(BASE, vpn=vpn), raw=True)
                self.assertEqual(self.get("grafana.example.com", "203.0.113.9", groups="users_grafana")[0], 403)
        self.assertIsNone(gg.validate_vpn_section(BASE["vpn"]))

    def test_devices_file_other_denies(self):
        for name in ("other.json", "/vpn-doc/vpn.json", "", None):
            with self.subTest(name=name):
                write_policy(dict(BASE, vpn=dict(BASE["vpn"], devices_file=name)), raw=True)
                self.assertEqual(self.get("grafana.example.com", "203.0.113.9", groups="users_grafana")[0], 403)

    # ── the binding, one test each ──

    def vpn_only(self, via=("*",)):
        write_policy(vpn_policy({"app.example.com": {"via": list(via)}}))

    def assert_denied(self, xff, text, user="bob", host="app.example.com"):
        st, body, _ = self.get(host, xff, user=user)
        self.assertEqual(st, 403, body)
        self.assertIn(html.escape(text), body)
        return body

    def test_allowed(self):
        self.vpn_only()
        self.assertEqual(self.get("app.example.com", "10.213.0.5")[0], 200)
        self.assertEqual(self.get("app.example.com", "100.64.0.7")[0], 200)

    def test_outside_ranges(self):
        self.vpn_only()
        for xff in ("203.0.113.9", "192.168.1.5", "fd00::5", "garbage", ""):
            with self.subTest(xff=xff):
                self.assert_denied(xff, REQUIRED_TEXT)
        st, body, _ = self.get("app.example.com", None)
        self.assertEqual(st, 403)

    def test_stale_provider(self):
        self.vpn_only()
        write_vpn(vpn_doc(hs_stale=True))
        self.assert_denied("100.64.0.7", OUT_OF_DATE)
        write_vpn(vpn_doc(hs_age=200))  # past stale_after by this clock (180 s span)
        self.assert_denied("100.64.0.7", OUT_OF_DATE)
        self.assertEqual(self.get("app.example.com", "10.213.0.5")[0], 200)  # the built-in unaffected

    def test_via_mismatch(self):
        self.vpn_only(via=["builtin"])
        self.assert_denied("100.64.0.7", REQUIRED_TEXT)
        self.assertEqual(self.get("app.example.com", "10.213.0.5")[0], 200)
        self.vpn_only(via=["gone"])  # a provider no longer wired: denied
        self.assert_denied("10.213.0.5", REQUIRED_TEXT)

    def test_via_empty_means_no_provider(self):
        # Contract: via [] is valid and names no provider: every address is
        # denied, the built-in's and a hook provider's alike. Only an
        # explicit ["*"] means any provider.
        self.assertIsNone(gg.validate_vpn_section(dict(BASE["vpn"], hosts={"app.example.com": {"via": []}})))
        self.vpn_only(via=[])
        self.assert_denied("10.213.0.5", REQUIRED_TEXT)
        self.assert_denied("100.64.0.7", REQUIRED_TEXT)
        self.assertEqual(self.get("app.example.com", "203.0.113.9", gate_path="/auth")[0], 403)
        doc = gg.parse_vpn_doc(json.loads(json.dumps(vpn_doc()), object_pairs_hook=gg._vpn_pairs))
        pol = dict(BASE, **vpn_policy({"app.example.com": {"via": []}}))
        self.assertEqual(gg.vpn_check(pol, doc, "app.example.com", "main", "/", gg.ipaddress.IPv4Address("10.213.0.5"),
                                      "bob", time.time())[0], "vpn_via")

    def test_valid_until(self):
        # Past valid_until the whole file is invalid: every VPN request is
        # denied, although each device is otherwise fine.
        self.vpn_only()
        self.assertEqual(self.get("app.example.com", "10.213.0.5")[0], 200)
        write_vpn(vpn_doc(valid_for=-1))
        self.assert_denied("10.213.0.5", REQUIRED_TEXT)
        self.assert_denied("100.64.0.7", REQUIRED_TEXT)
        now = time.time()
        doc = gg.parse_vpn_doc(json.loads(json.dumps(vpn_doc(now=now, valid_for=30)), object_pairs_hook=gg._vpn_pairs))
        self.assertIsNotNone(gg.vpn_device(doc, "builtin", "10.213.0.5", now + 29))
        self.assertIsNone(gg.vpn_device(doc, "builtin", "10.213.0.5", now + 30))
        pol = dict(BASE, **vpn_policy({"app.example.com": {"via": ["*"]}}))
        self.assertEqual(gg.vpn_check(pol, doc, "app.example.com", "main", "/", gg.ipaddress.IPv4Address("10.213.0.5"),
                                      "bob", now + 30)[0], "vpn_doc_expired")
        for bad in ({k: v for k, v in vpn_doc().items() if k != "valid_until"},
                    dict(vpn_doc(), valid_until=None), dict(vpn_doc(), valid_until="in an hour"),
                    dict(vpn_doc(), valid_until=1700000000)):
            with self.subTest(valid_until=bad.get("valid_until", "<missing>")):
                with self.assertRaises(ValueError):
                    gg.parse_vpn_doc(json.loads(json.dumps(bad), object_pairs_hook=gg._vpn_pairs))

    def test_unknown_device(self):
        self.vpn_only()
        self.assert_denied("10.213.0.9", REQUIRED_TEXT)
        self.assert_denied("100.64.0.8", REQUIRED_TEXT)

    def test_expired(self):
        self.vpn_only()
        write_vpn(vpn_doc(bob_expires=time.time() - 5))
        self.assert_denied("10.213.0.5", REQUIRED_TEXT)

    def test_other_owner(self):
        self.vpn_only()
        self.assert_denied("10.213.0.6", NOT_YOURS)

    def test_disabled_owner(self):
        # The Hub drops a disabled person's devices: absent from the doc.
        self.vpn_only()
        doc = vpn_doc()
        doc["devices"] = [d for d in doc["devices"] if d["user"] != "bob"]
        doc["builtin"]["peers"] = [p for p in doc["builtin"]["peers"] if p["device_id"] != "b1"]
        write_vpn(doc)
        self.assert_denied("10.213.0.5", REQUIRED_TEXT)
        self.assert_denied("100.64.0.7", REQUIRED_TEXT)

    def test_no_doc_denies_every_vpn_request(self):
        self.vpn_only()
        for bad in (None, "{", json.dumps(dict(vpn_doc(), version=1)), json.dumps(dict(vpn_doc(), extra=1))):
            with self.subTest(doc=bad):
                write_vpn(bad)
                self.assert_denied("10.213.0.5", REQUIRED_TEXT)
        write_vpn(vpn_doc())
        self.assertEqual(self.get("app.example.com", "10.213.0.5")[0], 200)

    def test_another_providers_address_never_counts(self):
        # The address names the provider (ranges are disjoint); a device
        # listed under another provider is refused by the reader, so the
        # whole file denies.
        self.vpn_only()
        doc = vpn_doc()
        doc["devices"].append({"ip": "100.64.0.9", "provider": "builtin", "user": "bob", "device_id": "x",
                               "name": "x", "expires": None})
        write_vpn(doc)
        self.assert_denied("100.64.0.7", REQUIRED_TEXT)

    def test_expired_device_denied_by_clock(self):
        # Review Focus 4: the Hub is stopped, the file never changes.
        t = time.time()
        doc = gg.parse_vpn_doc(json.loads(json.dumps(vpn_doc(now=t, bob_expires=t + 60)), object_pairs_hook=gg._vpn_pairs))
        policy = dict(BASE, **vpn_policy({"app.example.com": {"via": ["*"]}}))
        ip = gg.ipaddress.IPv4Address("10.213.0.5")
        self.assertIsNone(gg.vpn_check(policy, doc, "app.example.com", "main", "/", ip, "bob", t + 59))
        self.assertEqual(gg.vpn_check(policy, doc, "app.example.com", "main", "/", ip, "bob", t + 60)[0], "vpn_expired")
        # A hook provider past stale_after by the reader's clock.
        hs = gg.ipaddress.IPv4Address("100.64.0.7")
        self.assertIsNone(gg.vpn_check(policy, doc, "app.example.com", "main", "/", hs, "bob", t + 100))
        self.assertEqual(gg.vpn_check(policy, doc, "app.example.com", "main", "/", hs, "bob", t + 121)[0], "vpn_stale")

    def test_reasons(self):
        t = time.time()
        doc = gg.parse_vpn_doc(json.loads(json.dumps(vpn_doc(now=t)), object_pairs_hook=gg._vpn_pairs))
        A = gg.ipaddress.IPv4Address
        pol = lambda via: dict(BASE, **vpn_policy({"app.example.com": {"via": via}}))
        check = lambda p, d, ip, user="bob": gg.vpn_check(p, d, "app.example.com", "main", "/", ip, user, t)
        self.assertEqual(check(pol(["*"]), None, A("10.213.0.5"))[0], "vpn_no_doc")
        self.assertEqual(check(pol(["*"]), doc, None)[0], "vpn_not_vpn")
        self.assertEqual(check(pol(["*"]), doc, A("8.8.8.8"))[0], "vpn_not_vpn")
        self.assertEqual(check(pol(["builtin"]), doc, A("100.64.0.7"))[0], "vpn_via")
        self.assertEqual(check(pol(["*"]), doc, A("10.213.0.9"))[0], "vpn_unknown_device")
        self.assertEqual(check(pol(["*"]), doc, A("10.213.0.6"))[0], "vpn_other_owner")
        self.assertEqual(check(pol(["*"]), doc, A("10.213.0.6"), user="Alice"), None)  # lowercased
        self.assertIsNone(check(pol(["*"]), doc, A("10.213.0.5")))

    def test_last_xff_wins(self):
        self.assertEqual(gg.client_address({"X-Forwarded-For": "10.213.0.5, 203.0.113.9"}), gg.ipaddress.IPv4Address("203.0.113.9"))
        self.assertEqual(gg.client_address({"X-Forwarded-For": "203.0.113.9 , 10.213.0.5 "}), gg.ipaddress.IPv4Address("10.213.0.5"))
        for bad in ("", "fd00::5", "10.213.0.5, x", "1.2.3", "010.213.0.5"):
            with self.subTest(xff=bad):
                self.assertIsNone(gg.client_address({"X-Forwarded-For": bad}))
        self.assertIsNone(gg.client_address({}))
        self.vpn_only()
        self.assert_denied("10.213.0.5, 203.0.113.9", REQUIRED_TEXT)

    def test_internet_app_via_vpn_needs_no_binding(self):
        # Q3: a host missing from vpn.hosts is reachable from the internet;
        # reached over a VPN it needs no binding (another person's device).
        self.vpn_only()
        for xff in ("10.213.0.6", "10.213.0.9", "203.0.113.9"):
            with self.subTest(xff=xff):
                self.assertEqual(self.get("other.example.com", xff, groups="")[0], 200)

    # ── core-host classes ──

    def test_admin_only(self):
        write_policy(vpn_policy(admin_only=True))
        self.assertEqual(self.get("hub.example.com", "203.0.113.9", groups="lldap_admin")[0], 403)
        self.assertEqual(self.get("hub.example.com", "10.213.0.5", groups="lldap_admin")[0], 200)
        # Another person's device: the binding fails for core hosts too.
        self.assertEqual(self.get("hub.example.com", "10.213.0.6", groups="lldap_admin")[0], 403)
        for host in ("traefik.example.com", "directory.example.com", "metrics.example.com", "auth.example.com"):
            with self.subTest(host=host):
                self.assertEqual(self.get(host, "203.0.113.9", groups="lldap_admin")[0], 403)
        # core and enrol classes stay open in admin mode.
        self.assertEqual(self.get("people.example.com", "203.0.113.9", groups="")[0], 200)

    def test_server_mode(self):
        write_policy(vpn_policy(server_mode=True, public_enrol=True))
        self.assertEqual(self.get("people.example.com", "203.0.113.9", groups="", uri="/vpn/")[0], 200)
        self.assertEqual(self.get("people.example.com", "203.0.113.9", groups="", uri="/vpn/api/devices")[0], 200)
        for uri in ("/signin", "/", "/vpn", "/vpn/../signin", "/vpn/%2e%2e/signin", "/vpnx/"):
            with self.subTest(uri=uri):
                self.assertEqual(self.get("people.example.com", "203.0.113.9", groups="", uri=uri)[0], 403)
        self.assertEqual(self.get("people.example.com", "10.213.0.5", groups="", uri="/signin")[0], 200)
        self.assertEqual(self.get("hub.example.com", "203.0.113.9", groups="lldap_admin")[0], 403)
        # V17: the portal (a group-gate backend) checks class core too.
        st, _, _ = self.get("example.com", "203.0.113.9", groups="lldap_admin", gate_path="/portal/vpn")
        self.assertEqual(st, 403)
        st, _, _ = self.get("example.com", "10.213.0.5", groups="lldap_admin", gate_path="/portal/vpn")
        self.assertEqual(st, 200)
        # The portal's normal path (the websecure router): denied even from a device's address.
        st, _, _ = self.get("example.com", "10.213.0.5", groups="lldap_admin", gate_path="/portal")
        self.assertEqual(st, 403)
        # public_enrol off: /vpn/ goes VPN-only too.
        write_policy(vpn_policy(server_mode=True, public_enrol=False))
        self.assertEqual(self.get("people.example.com", "203.0.113.9", groups="", uri="/vpn/")[0], 403)
        self.assertEqual(self.get("people.example.com", "10.213.0.5", groups="", uri="/vpn/")[0], 200)

    def test_normal_path_never_satisfies_a_binding(self):
        # Security ruling: X-Forwarded-For is whatever a websecure client
        # sends (or its LAN / CGNAT address): on group-gate's normal path
        # (portcullis-groups@docker) a VPN-only host is always denied with
        # the /vpn-required page, a device's address and owner included.
        self.vpn_only()
        for xff in ("10.213.0.5", "100.64.0.7", "203.0.113.9, 10.213.0.5"):
            with self.subTest(xff=xff):
                st, body, _ = self.get("app.example.com", xff, gate_path="/")
                self.assertEqual(st, 403)
                self.assertIn(html.escape(REQUIRED_TEXT), body)
                st, _, _ = self.get("app.example.com", xff, gate_path="/anything")
                self.assertEqual(st, 403)
        # The same address on the VPN path: satisfied.
        self.assertEqual(self.get("app.example.com", "10.213.0.5", gate_path="/auth/vpn")[0], 200)
        # Paths that merely look like it aren't it.
        for p in ("/auth/vpn/", "/auth/vpnx", "/AUTH/VPN", "/auth/vpn/../vpn"):
            with self.subTest(path=p):
                self.assertEqual(self.get("app.example.com", "10.213.0.5", gate_path=p)[0], 403)
        # Core classes too: admin_only, hub from a bound device on the normal path.
        write_policy(vpn_policy(admin_only=True))
        self.assertEqual(self.get("hub.example.com", "10.213.0.5", groups="lldap_admin", gate_path="/")[0], 403)
        self.assertEqual(self.get("hub.example.com", "10.213.0.5", groups="lldap_admin")[0], 200)
        # A host that isn't VPN-only: the normal path ignores the address.
        self.assertEqual(self.get("other.example.com", "10.213.0.6", groups="", gate_path="/")[0], 200)

    def test_reserved_ranges_refused(self):
        # Security ruling: a provider range overlapping a Docker or core
        # network refuses the whole file (the edge and group-gate deny).
        good = vpn_doc()
        for r in ("172.31.250.0/24", "172.31.254.0/26", "172.17.0.0/16", "172.16.0.0/12", "192.168.10.0/24", "192.168.0.0/16", "10.214.0.0/24", "10.214.0.128/25", "172.0.0.0/8"):
            with self.subTest(range=r):
                doc = dict(good, providers=[good["providers"][0], dict(good["providers"][1], ranges=[r])], devices=[])
                with self.assertRaises(ValueError):
                    gg.parse_vpn_doc(json.loads(json.dumps(doc), object_pairs_hook=gg._vpn_pairs))
        # Docker's default address pools (app-instance networks come from them).
        self.assertEqual([str(n) for n in gg.VPN_RESERVED[:3]], ["172.16.0.0/12", "192.168.0.0/16", "10.214.0.0/24"])

    def test_core_hosts_never_vpn_host_keys(self):
        self.assertIsNotNone(gg.validate_vpn_section(dict(BASE["vpn"], hosts={"hub.example.com": {"via": ["*"]}})))

    # ── the public guard (V17: steps 1 and 2 only) ──

    def test_public_guard_vpn_steps_1_2(self):
        write_policy(dict(PUBLIC_DOC, **vpn_policy({"cloud.example.com": {"via": ["*"]}})))
        import http.client

        def guard(xff, path="/public-guard/vpn"):
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            c.putrequest("GET", path, skip_accept_encoding=True)
            c.putheader("X-Forwarded-Host", "cloud.example.com")
            c.putheader("X-Forwarded-Uri", "/s/AbC123")
            if xff is not None:
                c.putheader("X-Forwarded-For", xff)
            c.endheaders()
            r = c.getresponse()
            r.read()
            c.close()
            return r.status
        self.assertEqual(guard("203.0.113.9"), 403)   # step 1
        self.assertEqual(guard(None), 403)
        self.assertEqual(guard("10.213.0.9"), 403)    # step 2: no device
        self.assertEqual(guard("10.213.0.5"), 200)    # a device: no person to bind
        self.assertEqual(guard("10.213.0.6"), 200)    # step 3 isn't enforced
        write_vpn(vpn_doc(hs_stale=True))
        self.assertEqual(guard("100.64.0.7"), 403)
        write_vpn(None)
        self.assertEqual(guard("10.213.0.5"), 403)

    def test_public_guard_websecure_public_paths_on_a_vpn_host(self):
        # Ruling (server mode with public links): the websecure guard
        # (portcullis-public-guard@docker) admits the host's published
        # public paths with no VPN check: public links are public by design.
        # Anything else on the host still needs the VPN (/auth/vpn).
        write_policy(dict(PUBLIC_DOC, **vpn_policy({"cloud.example.com": {"via": ["*"]}}, server_mode=True)))
        import http.client

        def guard(uri, xff="203.0.113.9", path="/public-guard"):
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            c.putrequest("GET", path, skip_accept_encoding=True)
            c.putheader("X-Forwarded-Host", "cloud.example.com")
            c.putheader("X-Forwarded-Uri", uri)
            if xff is not None:
                c.putheader("X-Forwarded-For", xff)
            c.endheaders()
            r = c.getresponse()
            r.read()
            c.close()
            return r.status
        for xff in ("203.0.113.9", None, "10.213.0.9"):
            with self.subTest(xff=xff):
                self.assertEqual(guard("/s/AbC123", xff=xff), 200)
                self.assertEqual(guard("/dist/app.js", xff=xff), 200)
        write_vpn(None)  # no vpn.json at all: public links don't depend on it
        self.assertEqual(guard("/s/AbC123"), 200)
        write_vpn(vpn_doc())
        for uri in ("/", "/index.php/apps/files", "/s/AbC123/../../index.php", "/s/bad%2Ftoken", "/dist/app.php"):
            with self.subTest(uri=uri):
                self.assertEqual(guard(uri), 403)
        # The rest of the host: the normal gate path denies, the VPN path binds.
        self.assertEqual(self.get("cloud.example.com", "203.0.113.9", uri="/index.php/apps/files", gate_path="/auth")[0], 403)
        self.assertEqual(self.get("cloud.example.com", "203.0.113.9", uri="/index.php/apps/files")[0], 403)
        # A VPN host without public_paths: the websecure guard still denies.
        write_policy(dict(BASE, **vpn_policy({"app.example.com": {"via": ["*"]}}, server_mode=True)))
        c_status = guard("/s/AbC123")
        self.assertEqual(c_status, 403)

    # ── pages ──

    def test_vpn_required_page(self):
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}/vpn-required")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r)
        with cm.exception as e:
            body = e.read().decode()
            self.assertEqual(e.code, 403)
            self.assertIn(REQUIRED_TEXT, body)
            self.assertNotIn("Set-Cookie", dict(e.headers))
            self.assertEqual(e.headers.get("Cache-Control"), "no-store")
            self.assertNotIn("<form", body)
            self.assertNotIn("oauth2", body)

    def test_reason_pages_hide_owner(self):
        self.vpn_only()
        body = self.assert_denied("10.213.0.6", NOT_YOURS)
        self.assertNotIn("alice", body.lower())
        self.assertNotIn("phone", body.lower())

    def test_metrics_reasons(self):
        self.vpn_only()
        self.get("app.example.com", "10.213.0.6")
        self.assertIn('reason="vpn_other_owner"', gg.METRICS.render())

    # ── the opened log ──

    def test_opened_log_via_fields(self):
        d = tempfile.mkdtemp()
        old = gg.OPENED_LOG
        gg.OPENED_LOG = gg.OpenedLog(os.path.join(d, "opened"), gid=os.getgid())
        self.addCleanup(setattr, gg, "OPENED_LOG", old)
        self.vpn_only()
        self.assertEqual(self.get("app.example.com", "10.213.0.5")[0], 200)
        self.assertEqual(self.get("other.example.com", "203.0.113.9", groups="")[0], 200)
        self.assertTrue(gg.OPENED_LOG.flush())
        lines = []
        for name in os.listdir(os.path.join(d, "opened")):
            with open(os.path.join(d, "opened", name)) as f:
                lines += [json.loads(x) for x in f if x.strip()]
        by_host = {x["host"]: x for x in lines}
        self.assertEqual({k: by_host["app.example.com"].get(k) for k in ("via", "provider", "device")},
                         {"via": "vpn", "provider": "builtin", "device": "b1"})
        self.assertNotIn("via", by_host["other.example.com"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
