#!/usr/bin/env python3
"""run.py against a recorded provider (an in-process opener answering as
the contract says), then against defective variants: each defect fails
exactly its check. Stdlib only; `python3 tests/mail-conformance/test_run.py`.
"""
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(__file__))
import run  # noqa: E402

SECRET = "conformance-test-secret-0123456789abcdef"
KEYS = ["version", "generation", "primary_domain", "mail_hostname", "client_ip", "submission_lan_only", "dkim_rotate",
        "former_retention", "relay", "tls", "confirm_mass_removal", "domains", "accounts", "aliases", "lists", "postmaster",
        "limits", "spam", "local_networks"]


class Resp(io.BytesIO):
    def __init__(self, status, body):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Recorded:
    """The answers a conforming provider gives; defects switch one off."""

    def __init__(self, defects=()):
        self.d = set(defects)
        self.doc = None
        self.creds = {}  # uuid -> [ {id, uuid, label, ...} ]
        self.n = 0

    def __call__(self, req, timeout=None):
        st, body = self.answer(req)
        b = json.dumps(body).encode() if body is not None else b""
        if st >= 400:
            raise urllib.error.HTTPError(req.full_url, st, "", {}, io.BytesIO(b))
        return Resp(st, b)

    def answer(self, req):
        path = req.full_url.split("://", 1)[1].split("/", 1)[1]
        path = "/" + path
        p, _, q = path.partition("?")
        if "outside" in req.full_url and "outside" not in self.d:
            return 403, None
        if req.get_header("Authorization") != "Bearer " + SECRET and "auth" not in self.d:
            return 403, None
        m = req.get_method()
        if p == "/v1/provider":
            return 200, {"name": "Rec", "version": "1", "api_version": 1, "checks": [], "actions": []}
        if p == "/v1/state" and m == "GET":
            return 200, {"generation": self.doc["generation"] if self.doc else 0, "applied_generation": 0, "bootstrap": True, "errors": []}
        if p == "/v1/state" and m == "PUT":
            raw = req.data
            try:
                d = json.loads(raw)
            except ValueError:
                return 400, {"error": "bad"}
            if "strict" not in self.d and (set(d) != set(KEYS)):
                return 400, {"error": "keys"}
            # As mailctl: MailState v2's spam block is complete (dnsbl too).
            if set((d.get("spam") or {}).keys()) != {"junk_score", "reject_score", "dnsbl", "allow", "block"}:
                return 400, {"error": 'document.spam: missing key "dnsbl"'}
            if self.doc and len(self.doc["accounts"]) > 0 and "mass" not in self.d:
                now = {a["uuid"] for a in d["accounts"]}
                gone = [a for a in self.doc["accounts"] if a["uuid"] not in now]
                if len(gone) * 2 > len(self.doc["accounts"]) and not d["confirm_mass_removal"]:
                    return 409, {"error": "mass", "error_kind": "mass_removal",
                                 "removed": [{"username": a["username"], "uuid": a["uuid"]} for a in gone]}
            self.doc = d
            return 202, {"generation": d["generation"]}
        if p == "/v1/credentials" and m == "POST":
            b = json.loads(req.data)
            acct = next((a for a in self.doc["accounts"] if a["username"] == b["username"]), None)
            if acct is None:
                return 404, {"error": "no account"}
            if acct["uuid"] != b["uuid"] and "mismatch" not in self.d:
                return 409, {"error": "uuid", "error_kind": "account_mismatch"}
            self.n += 1
            row = {"id": str(self.n), "uuid": b["uuid"], "label": b["label"], "created_at": "2026-11-17T10:00:00Z", "expires_at": None,
                   "last_used_at": None, "allowed_ips": []}
            self.creds.setdefault(b["uuid"], []).append(row)
            return 201, {"id": row["id"], "secret": "pw-%d" % self.n, "created_at": row["created_at"], "expires_at": None}
        if p == "/v1/credentials" and m == "GET":
            uuid = q.split("uuid=", 1)[1]
            out = []
            for r in self.creds.get(uuid, []):
                r = dict(r)
                if self.doc.get("submission_lan_only"):
                    r["allowed_ips"] = ["0.0.0.0/0"] if "lan" in self.d else list(self.doc["local_networks"])
                if "uuid" in self.d:
                    r["uuid"] = "00000000-0000-4000-8000-000000000000"
                out.append(r)
            return 200, out
        if p.startswith("/v1/credentials/") and m == "DELETE":
            if "uuid=" not in q:
                return (204, None) if "revoke" in self.d else (400, {"error": "uuid"})
            uuid, pid = q.split("uuid=", 1)[1], p.rsplit("/", 1)[1]
            self.creds[uuid] = [r for r in self.creds.get(uuid, []) if r["id"] != pid]
            return 204, None
        if p == "/v1/void":
            if "void" not in self.d:
                self.creds = {}
            return 200, {"voided": 0, "restored_at": "2026-11-17T10:00:00Z"}
        return 404, {"error": "not found"}


def runs(defects=()):
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(SECRET + "\n")
    out = io.StringIO()
    rc = run.main(["--level", "api", "--api-url", "http://provider.test", "--secret-file", f.name,
                   "--outside-url", "http://outside.test"], opener=Recorded(defects), out=out)
    os.unlink(f.name)
    return rc, out.getvalue()


class RunTest(unittest.TestCase):
    def test_conforming_provider_passes(self):
        rc, out = runs()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("FAIL", out)
        self.assertIn("8 checks, 0 failed", out)

    def test_each_defect_fails_its_check(self):
        for defect, check in [("auth", "auth_refusals"), ("outside", "auth_refusals"), ("strict", "strict_json"),
                              ("mismatch", "account_mismatch"), ("uuid", "uuid_echoed"), ("revoke", "revoke_by_uuid"),
                              ("mass", "mass_removal"), ("lan", "allowed_ips_lan_only"), ("void", "void_empties_every_list")]:
            rc, out = runs([defect])
            self.assertEqual(rc, 1, (defect, out))
            self.assertIn("FAIL " + check + ":", out, defect)

    def test_secret_file_too_short(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("short\n")
        out = io.StringIO()
        rc = run.main(["--level", "api", "--api-url", "http://p.test", "--secret-file", f.name], opener=Recorded(), out=out)
        os.unlink(f.name)
        self.assertEqual(rc, 1)
        self.assertIn("fewer than 32", out.getvalue())


if __name__ == "__main__":
    unittest.main()
