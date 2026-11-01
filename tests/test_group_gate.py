#!/usr/bin/env python3
"""Unit tests for group-gate/group-gate.py.

Run: python3 tests/test_group_gate.py
Starts group-gate in-process on an ephemeral port with temp map/policy files.
"""
import importlib.util
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


def write_policy(doc):
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
        write_policy(None)

    def req(self, host, groups="users_x", extra=None, uri=None, gate_path="/", want_headers=False):
        # What portcullis-auth (oauth2-proxy) hands group-gate: User = the
        # token's sub (Keycloak user id), Preferred-Username = LLDAP username.
        h = {"X-Forwarded-Host": host, "X-Auth-Request-Email": "bob@example.com",
             "X-Auth-Request-User": "8d3c0d2e-5f4b-4bd1-9a51-1f2d3c4b5a69",
             "X-Auth-Request-Preferred-Username": "bob"}
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
        for host in ["hub.evil.com", "example.com", "a.hub.example.com", "", "hubexample.com"]:
            with self.subTest(host=host):
                self.assertEqual(self.req(host, groups="lldap_admin"), 403)

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
        write_policy({"groups": {"newapp": "users_newapp", "hub": "users_anyone", "HUB": "users_anyone"}})
        self.assertEqual(self.req("newapp.example.com", groups="users_other"), 403)
        self.assertEqual(self.req("NewApp.example.com", groups="users_newapp"), 200)
        self.assertEqual(self.req("hub.example.com", groups="users_anyone"), 403)

    def test_metrics_subdomain_is_core_admin_only(self):
        # Grafana (monitoring profile): lldap_admin, never overridable by the Hub.
        write_policy({"groups": {"metrics": "users_anyone"}, "path_groups": {"metrics": [{"prefix": "/x", "group": "g"}]}})
        self.assertEqual(self.req("metrics.example.com", groups="users_anyone"), 403)
        self.assertEqual(self.req("metrics.example.com", groups="lldap_admin"), 200)
        self.assertEqual(self.req("metrics.example.com", groups="lldap_admin", uri="/x"), 200)

    def test_policy_file_without_groups_ok(self):
        write_policy({"policies": {}, "default": {"factors": [], "op": ""}})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 200)

    def test_malformed_policy_fails_closed(self):
        for doc in [{"policies": {"grafana": {"factors": ["yubikey"], "op": "any"}}},
                    {"policies": {"grafana": {"factors": ["mtls"], "op": "some"}}},
                    {"default": {"factors": ["bogus"]}},
                    {"policies": {"grafana": "mtls"}},
                    "{not json"]:
            with self.subTest(doc=doc):
                write_policy(doc)
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)

    def test_valid_policy_stepup(self):
        write_policy({"policies": {"grafana": {"factors": ["webauthn"], "op": ""}}})
        code, hdrs = self.req("grafana.example.com", groups="users_grafana", want_headers=True)
        self.assertEqual(code, 403)
        self.assertIn("acr_values=hwk", hdrs.get("X-Stepup-URL", ""))
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana",
                                  extra={"X-Forwarded-Access-Token": token(amr=["pwd"])}), 403)
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana",
                                  extra={"X-Forwarded-Access-Token": token(amr=["hwk"])}), 200)

    def stepup_page(self, policy, amr=("pwd",)):
        write_policy({"policies": {"grafana": policy}})
        h = {"X-Forwarded-Host": "grafana.example.com", "X-Auth-Request-Email": "bob@example.com",
             "X-Auth-Request-Preferred-Username": "bob", "X-Auth-Request-Groups": "users_grafana",
             "X-Forwarded-Access-Token": token(amr=list(amr))}
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}/", headers=h)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r)
        with cm.exception as e:
            self.assertEqual(e.code, 403)
            return e.read().decode()

    def test_stepup_page_hardware_factor_waits_for_the_user(self):
        # A user without a passkey must be able to read / follow the
        # enrolment link: no auto-redirect, a Continue button instead.
        body = self.stepup_page({"factors": ["webauthn"], "op": ""})
        self.assertNotIn('http-equiv="refresh"', body)
        self.assertIn('id="stepup-continue"', body)
        self.assertIn('href="https://auth.example.com/oauth2/start?', body)
        self.assertIn("https://auth.example.com/realms/portcullis/account/account-security/signing-in", body)
        body = self.stepup_page({"factors": ["mtls"], "op": ""})
        self.assertNotIn('http-equiv="refresh"', body)
        self.assertIn('href="https://enroll.example.com/"', body)
        self.assertNotIn("account-security", body)

    def test_stepup_page_password_factor_redirects(self):
        body = self.stepup_page({"factors": ["password"], "op": ""}, amr=())
        self.assertIn('http-equiv="refresh" content="2;url=https://auth.example.com/oauth2/start?', body)
        self.assertNotIn("No hardware key", body)

    def test_stepup_url_is_on_the_auth_host(self):
        # A host-less /oauth2/ router gets 421 from Traefik on tiered hosts.
        url = gg.stepup_url("hwk.example.com", 2, ["webauthn"])
        parts = urllib.parse.urlsplit(url)
        self.assertEqual((parts.scheme, parts.netloc, parts.path), ("https", "auth.example.com", "/oauth2/start"))
        self.assertEqual(urllib.parse.parse_qs(parts.query),
                         {"acr_values": ["hwk"], "rd": ["https://hwk.example.com/"]})

    def test_hub_service_account_is_denied(self):
        for gate_path in ("/", "/authenticated", "/portal"):
            for name in ("portcullis-hub", "Portcullis-Hub"):
                with self.subTest(gate_path=gate_path, name=name):
                    self.assertEqual(self.req("hub.example.com", groups="lldap_admin", gate_path=gate_path,
                                              extra={"X-Auth-Request-Preferred-Username": name}), 403)
        self.assertEqual(self.req("hub.example.com", groups="lldap_admin"), 200)

    def test_password_factor_met_by_hardware_factors(self):
        # No password in the browser flow: hwk / mtls sessions satisfy it.
        for amr in (["hwk"], ["mtls"], ["pwd"]):
            self.assertTrue(gg.evaluate_policy({"factors": ["password"], "op": ""}, "", amr)[0], amr)
        self.assertFalse(gg.evaluate_policy({"factors": ["password"], "op": ""}, "", [])[0])
        self.assertTrue(gg.evaluate_policy({"factors": ["password", "webauthn"], "op": "all"}, "", ["hwk"])[0])
        self.assertFalse(gg.evaluate_policy({"factors": ["webauthn"], "op": ""}, "", ["mtls"])[0])

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
            h = {"X-Auth-Request-Preferred-Username": "bob", "X-Auth-Request-Groups": groups}
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
        self.assertIn("not available", self.portal("users_wiki", {"version": 2, "apps": doc["apps"]}))
        self.assertIn("not available", self.portal("users_wiki", None))
        self.assertIn("not available", self.portal("users_wiki", "{broken"))

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
        write_policy({"groups": {"ghost": gg.DENY_GROUP}})
        for groups in ("", "users_ghost", "lldap_admin", "users_ghost,lldap_admin"):
            with self.subTest(groups=groups):
                self.assertEqual(self.req("ghost.example.com", groups=groups), 403)

    def test_deny_sentinel_cannot_be_satisfied_by_membership(self):
        write_policy({"groups": {"ghost": gg.DENY_GROUP}})
        self.assertEqual(self.req("ghost.example.com", groups=gg.DENY_GROUP), 403)

    def test_user_claiming_deny_group_is_denied_everywhere(self):
        for host in ("random.example.com", "grafana.example.com", "hub.example.com"):
            with self.subTest(host=host):
                self.assertEqual(self.req(host, groups=f"users_grafana,lldap_admin, {gg.DENY_GROUP}"), 403)
        self.assertEqual(self.req("random.example.com", groups="users_x", gate_path="/authenticated"), 200)
        self.assertEqual(self.req("random.example.com", groups=gg.DENY_GROUP, gate_path="/authenticated"), 403)

    def test_deny_sentinel_in_path_groups(self):
        write_policy({"path_groups": {"grafana": [{"prefix": "/x", "group": gg.DENY_GROUP}]}})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana", uri="/x/1"), 403)
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana", uri="/y"), 200)

    # ── version ──

    def test_policy_version(self):
        for doc, want in [({"version": 3}, 200), ({"version": 2}, 200), ({"version": 1}, 200), ({}, 200),
                          ({"version": 4}, 403), ({"version": "2"}, 403), ({"version": True}, 403),
                          ({"version": 0}, 403)]:
            with self.subTest(doc=doc):
                write_policy(doc)
                self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), want)

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


def token(**claims):
    import base64
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"x.{payload}.y"


ADMIN_RULES = {"version": 2,
               "groups": {"vw": "users_vw"},
               "path_groups": {"vw": [{"prefix": "/admin", "group": "admin_vw"},
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
        for pg in ([], {"vw": {"prefix": "/a"}}, {"vw": [{"prefix": "admin", "group": "g"}]},
                   {"vw": [{"prefix": "/a", "group": ""}]}, {"vw": ["x"]},
                   {"vw": [{"prefix": "/a/../b", "group": "g"}]}, {"vw": [{"prefix": "/%61", "group": "g"}]}):
            with self.subTest(pg=pg):
                write_policy({"groups": {"vw": "users_vw"}, "path_groups": pg})
                self.assertEqual(self.req("vw.example.com", groups="users_vw", uri="/"), 403)

    def test_subdomain_key_case_insensitive(self):
        write_policy({"path_groups": {"VW": [{"prefix": "/admin", "group": "admin_vw"}]}})
        self.assertEqual(self.req("vw.example.com", groups="x", uri="/admin"), 403)

    def test_core_subdomains_ignore_hub_path_rules(self):
        write_policy({"path_groups": {"hub": [{"prefix": "/", "group": "nobody"}]}})
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


def build_crl(serials, with_next_update=True, with_version=True):
    """Structurally valid (unsigned) X.509 v2 CRL."""
    alg = _der(0x30, _der(0x06, bytes.fromhex("2a8648ce3d040302")))  # ecdsa-with-SHA256
    issuer = _der(0x30, _der(0x31, _der(0x30, _der(0x06, b"\x55\x04\x03") + _der(0x0C, b"Test CA"))))
    t = _der(0x17, b"250101000000Z")
    tbs = (_der_int(1) if with_version else b"") + alg + issuer + t + (t if with_next_update else b"")
    if serials:
        tbs += _der(0x30, b"".join(_der(0x30, _der_int(sn) + t) for sn in serials))
    tbs += _der(0xA0, _der(0x30, b""))  # crlExtensions
    return _der(0x30, _der(0x30, tbs) + alg + _der(0x03, b"\x00\x01\x02"))


PUBLIC_DOC = {
    "version": 3,
    "public_paths": {
        "cloud": {
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
        for doc in [None, {}, {"version": 2, "public_paths": PUBLIC_DOC["public_paths"]}, {"version": 3},
                    {"version": 3, "public_paths": []},
                    {"version": 3, "public_paths": {"cloud": {"paths": [{"path": "/s", "match": "prefix"}], "extra": 1}}},
                    {"version": 3, "public_paths": {"cloud": {"paths": []}}},
                    {"version": 3, "public_paths": {"cloud": {"paths": [{"path": "/s/{token}", "match": "prefix"}]}}},
                    {"version": 3, "public_paths": {"cloud": {"paths": [{"path": "/s/../x", "match": "prefix"}]}}},
                    {"version": 3, "public_paths": {"cloud": {"paths": [{"path": "/s", "match": "regex"}]}}},
                    "not json"]:
            with self.subTest(doc=doc):
                write_policy(doc)
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
            write_policy({"version": 2, "path_groups": {"cloud": [{"prefix": "/admin", "group": "admin_x"}]}})
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


class PathFragmentTest(GateTest):
    def test_hash_denied_on_path_rules(self):
        write_policy({"version": 3, "groups": {"cloud": "users_x"},
                      "path_groups": {"cloud": [{"prefix": "/admin", "group": "admin_x"}]}})
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

    def r(self, policy, amr, cert=None, user="bob", host="grafana.example.com", token_user=None):
        write_policy({"policies": {"grafana": policy}})
        extra = {"X-Forwarded-Access-Token": token(amr=amr, preferred_username=user if token_user is None else token_user),
                 "X-Auth-Request-Preferred-Username": user or None}
        if cert is not None:
            extra[gg.CERT_INFO_HEADER] = cert
        return self.req(host, groups="users_grafana", extra=extra, want_headers=True)

    def test_mtls_token_without_cert_steps_up(self):
        code, hdrs = self.r({"factors": ["mtls"]}, ["mtls"])
        self.assertEqual(code, 403)
        self.assertIn("acr_values=mtls", hdrs.get("X-Stepup-URL", ""))

    def test_mtls_token_with_matching_cert(self):
        self.assertEqual(self.r({"factors": ["mtls"]}, ["mtls"], cert_info_for("bob", 0x10))[0], 200)

    def test_mtls_token_with_foreign_user_cert(self):
        self.assertEqual(self.r({"factors": ["mtls"]}, ["mtls"], cert_info_for("alice", 0x10))[0], 403)
        self.assertEqual(self.r({"factors": ["mtls"]}, ["mtls"], cert_info_for("Bob", 0x10))[0], 403)
        self.assertEqual(self.r({"factors": ["mtls"]}, ["mtls"], cert_info_for("bob", 0x10), user="")[0], 403)

    def test_mtls_binding_uses_the_session_username(self):
        # CN compared with the username apps get; the token must agree.
        self.assertEqual(self.r({"factors": ["mtls"]}, ["mtls"], cert_info_for("bob", 0x10), token_user="")[0], 403)
        self.assertEqual(self.r({"factors": ["mtls"]}, ["mtls"], cert_info_for("bob", 0x10), token_user="alice")[0], 403)
        self.assertEqual(self.r({"factors": ["mtls"]}, ["mtls"], cert_info_for("alice", 0x10), token_user="alice")[0], 403)

    def test_mtls_token_with_revoked_cert(self):
        write_revoked(["10"])
        self.assertEqual(self.r({"factors": ["mtls"]}, ["mtls"], cert_info_for("bob", 0x10))[0], 403)

    def test_cert_info_without_serial_does_not_satisfy_binding(self):
        self.assertEqual(self.r({"factors": ["mtls"]}, ["mtls"], urllib.parse.quote('Subject="CN=bob"'))[0], 403)

    def test_any_policy_satisfied_by_other_factor_needs_no_cert(self):
        p = {"factors": ["mtls", "webauthn"], "op": "any"}
        self.assertEqual(self.r(p, ["hwk"])[0], 200)
        self.assertEqual(self.r(p, ["mtls", "hwk"])[0], 200)
        self.assertEqual(self.r(p, ["mtls"])[0], 403)
        self.assertEqual(self.r(p, ["mtls"], cert_info_for("bob", 1))[0], 200)

    def test_all_policy_with_mtls_always_needs_cert(self):
        p = {"factors": ["mtls", "webauthn"], "op": "all"}
        self.assertEqual(self.r(p, ["mtls", "hwk"])[0], 403)
        self.assertEqual(self.r(p, ["mtls", "hwk"], cert_info_for("bob", 1))[0], 200)

    def test_policy_without_mtls_unaffected(self):
        self.assertEqual(self.r({"factors": ["webauthn"]}, ["hwk"])[0], 200)

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
        step0 = m.get("group_gate_stepups_total", reason="policy")
        pol0 = m.get("group_gate_policy_load_errors_total")
        auth0 = m.get("group_gate_requests_total", endpoint="authenticated", result="allow")
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 200)
        self.assertEqual(self.req("grafana.example.com", groups="users_x"), 403)
        self.assertEqual(self.req("grafana.evil.com"), 403)
        self.assertEqual(self.req("hub.example.com", gate_path="/authenticated", groups=""), 200)
        write_policy({"policies": {"grafana": {"factors": ["webauthn"], "op": ""}}})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
        write_policy("{not json")
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
        self.assertEqual(m.get("group_gate_requests_total", endpoint="gate", result="allow"), allow0 + 1)
        self.assertEqual(m.get("group_gate_denials_total", reason="group"), group0 + 1)
        self.assertEqual(m.get("group_gate_denials_total", reason="host"), host0 + 1)
        self.assertEqual(m.get("group_gate_stepups_total", reason="policy"), step0 + 1)
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
        self.assertEqual(gg._der_time(b"20991231235959Z", 0x18, 0, 15), 4102444799.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
