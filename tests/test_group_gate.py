#!/usr/bin/env python3
"""Unit tests for scripts/group-gate.py.

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
GATE_PATH = os.path.join(HERE, "..", "scripts", "group-gate.py")
MAP_PATH = os.path.join(HERE, "..", "scripts", "group-gate-map.conf")

TMP = tempfile.mkdtemp()
POLICY = os.path.join(TMP, "policy.json")
REVOKED = os.path.join(TMP, "revoked-serials.txt")
os.environ["GATE_MAP_FILE"] = MAP_PATH
os.environ["GATE_POLICY_FILE"] = POLICY
os.environ["GATE_REVOKED_FILE"] = REVOKED
os.environ.pop("GATE_CRL_URL", None)
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
    with open(POLICY, "w") as f:
        f.write(doc if isinstance(doc, str) else json.dumps(doc))


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

    def req(self, host, groups="users_x", extra=None):
        h = {"X-Forwarded-Host": host, "X-Auth-Request-Email": "bob@example.com"}
        if groups is not None:
            h["X-Auth-Request-Groups"] = groups
        h.update(extra or {})
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}/", headers=h)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

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

    def test_policy_groups_merge_but_cannot_override_core(self):
        write_policy({"groups": {"newapp": "users_newapp", "hub": "users_anyone", "HUB": "users_anyone"}})
        self.assertEqual(self.req("newapp.example.com", groups="users_other"), 403)
        self.assertEqual(self.req("NewApp.example.com", groups="users_newapp"), 200)
        self.assertEqual(self.req("hub.example.com", groups="users_anyone"), 403)

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
        write_policy({"policies": {"grafana": {"factors": ["mtls"], "op": ""}}})
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana"), 403)
        import base64
        payload = base64.urlsafe_b64encode(json.dumps({"amr": ["mtls"]}).encode()).decode().rstrip("=")
        tok = f"x.{payload}.y"
        self.assertEqual(self.req("grafana.example.com", groups="users_grafana",
                                  extra={"X-Forwarded-Access-Token": tok}), 200)



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

    def do_GET(self):
        self.send_response(self.status)
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *a):
        pass


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
