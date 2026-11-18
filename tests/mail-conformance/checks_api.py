"""The provider API v1 checks (contract §19.5; mail provider plan P11).

Every check takes a Ctx and returns None (pass) or a reason (fail). They
write documents: run them only against a provider set aside for it (CI).
"""
import json
import urllib.error
import urllib.request


class Ctx:
    """api_url: the provider API as the Hub reaches it; secret: the Hub ⇄
    provider bearer; outside_url: the same API through an address outside
    portcullis-mail-api (optional: the wrong-source check)."""

    def __init__(self, api_url, secret, outside_url=None, opener=None):
        self.api_url = api_url.rstrip("/")
        self.secret = secret
        self.outside_url = outside_url.rstrip("/") if outside_url else None
        self.open = opener or urllib.request.urlopen
        self.gen = None
        # The key the provider serves (MailState v2: tls.spki_sha256 holds
        # 1-2 keys); a placeholder when the caller can't name it.
        self.spki = "0" * 64
        self.created = []  # (uuid, id, secret) of passwords made here

    def call(self, method, path, body=None, bearer="default", base=None, raw=None):
        """(status, parsed JSON or None, raw bytes)."""
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request((base or self.api_url) + path, data=data, method=method)
        if bearer == "default":
            bearer = self.secret
        if bearer is not None:
            req.add_header("Authorization", "Bearer " + bearer)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self.open(req, timeout=20) as r:
                b = r.read()
                status = r.status
        except urllib.error.HTTPError as e:
            b, status = e.read(), e.code
        try:
            j = json.loads(b) if b.strip() else None
        except ValueError:
            j = None
        return status, j, b

    def next_gen(self):
        if self.gen is None:
            st, j, _ = self.call("GET", "/v1/state")
            self.gen = (j or {}).get("generation", 0) if st == 200 else 0
        self.gen += 1000
        return self.gen


UUIDS = ["c0f0a000-0000-4000-8000-0000000000%02d" % i for i in range(1, 9)]


def doc(ctx, accounts, lan_only=False, local=None, confirm=False):
    accts = [{"username": u, "uuid": UUIDS[i], "display_name": u, "addresses": [u + "@conformance.test"], "quota_bytes": 0}
             for i, u in enumerate(accounts)]
    return {"version": 2, "generation": ctx.next_gen(), "primary_domain": "conformance.test",
            "mail_hostname": "mail.conformance.test", "client_ip": "preserved", "submission_lan_only": lan_only,
            "dkim_rotate": "4380h", "former_retention": "720h", "relay": None, "tls": {"spki_sha256": [ctx.spki]},
            "confirm_mass_removal": confirm,
            "domains": [{"name": "conformance.test", "dmarc_start": "reject", "dmarc_floor": "reject", "mail": "on", "dnssec": "unsigned"}],
            "accounts": accts, "aliases": [], "lists": [], "postmaster": [], "limits": {"recipients_per_hour": 100, "recipients_per_day": 1000},
            "spam": {"junk_score": 5, "reject_score": 10, "dnsbl": {"spamhaus": False, "spamcop": False, "barracuda": False}, "allow": [], "block": []},
            "local_networks": local if local is not None else ["192.168.77.0/24"]}


def put(ctx, d):
    st, j, b = ctx.call("PUT", "/v1/state", d)
    return st, j, b


def cred(ctx, user, uuid, label="conformance"):
    st, j, _ = ctx.call("POST", "/v1/credentials", {"username": user, "uuid": uuid, "label": label, "expires_at": None})
    if st == 201 and j:
        ctx.created.append((uuid, j.get("id"), j.get("secret")))
    return st, j


def check_auth(ctx):
    for name, bearer in (("no bearer", None), ("a wrong bearer", "not-the-secret-" + "x" * 24)):
        st, _, _ = ctx.call("GET", "/v1/provider", bearer=bearer)
        if st != 403:
            return "%s: HTTP %d (want 403)" % (name, st)
    if ctx.outside_url:
        st, _, _ = ctx.call("GET", "/v1/provider", base=ctx.outside_url)
        if st != 403:
            return "the right bearer from outside portcullis-mail-api: HTTP %d (want 403)" % st
    st, j, _ = ctx.call("GET", "/v1/provider")
    if st != 200 or not isinstance(j, dict) or j.get("api_version") != 1:
        return "GET /v1/provider: HTTP %d %r" % (st, j)
    return None


def check_strict_json(ctx):
    d = doc(ctx, ["alice"])
    d["unknown_key"] = 1
    st, _, _ = put(ctx, d)
    if st != 400:
        return "an unknown key: HTTP %d (want 400)" % st
    d = doc(ctx, ["alice"])
    st, _, _ = ctx.call("PUT", "/v1/state", raw=json.dumps(d).encode() + b" {}")
    if st != 400:
        return "trailing data: HTTP %d (want 400)" % st
    d = doc(ctx, ["alice"])
    del d["aliases"]
    st, _, _ = put(ctx, d)
    if st != 400:
        return "a missing key: HTTP %d (want 400)" % st
    return None


def reset(ctx):
    """Setup: a document with no account, mass removal confirmed (the
    provider may hold accounts from before)."""
    st, _, b = put(ctx, doc(ctx, [], confirm=True))
    if st != 202:
        return "the empty document (confirm_mass_removal): HTTP %d %s" % (st, b[:200])
    return None


def check_stale_generation(ctx):
    """A document whose generation isn't above the last accepted one: 409
    with error_kind generation (the Hub matches on error_kind, never on the
    text; contract §19.5)."""
    d = doc(ctx, ["alice", "bob"])
    st, _, b = put(ctx, d)
    if st != 202:
        return "PUT a document: HTTP %d %s" % (st, b[:200])
    st, j, _ = put(ctx, dict(d))
    if st != 409 or (j or {}).get("error_kind") != "generation":
        return "the same generation again: HTTP %d %r (want 409 error_kind generation)" % (st, j)
    return None


def check_account_mismatch(ctx):
    st, j, b = put(ctx, doc(ctx, ["alice", "bob"]))
    if st != 202:
        return "PUT a document: HTTP %d %s" % (st, b[:200])
    st, j = cred(ctx, "alice", UUIDS[1])  # bob's uuid
    if st != 409 or (j or {}).get("error_kind") != "account_mismatch":
        return "a password for alice with bob's uuid: HTTP %d %r (want 409 account_mismatch)" % (st, j)
    return None


def check_uuid_echoed(ctx):
    st, j = cred(ctx, "alice", UUIDS[0])
    if st != 201 or not (j or {}).get("secret") or not (j or {}).get("id"):
        return "create: HTTP %d" % st
    st, rows, _ = ctx.call("GET", "/v1/credentials?uuid=" + UUIDS[0])
    if st != 200 or not isinstance(rows, list) or not rows:
        return "list: HTTP %d %r" % (st, rows)
    if any(r.get("uuid") != UUIDS[0] for r in rows):
        return "a row without the account's uuid: %r" % rows
    if any("secret" in r for r in rows):
        return "a listed row carries a secret"
    return None


def check_revoke_by_uuid(ctx):
    st, j = cred(ctx, "alice", UUIDS[0], "revoke")
    if st != 201:
        return "create: HTTP %d" % st
    pid = j["id"]
    st, _, _ = ctx.call("DELETE", "/v1/credentials/" + pid)
    if st != 400:
        return "DELETE without ?uuid: HTTP %d (want 400)" % st
    for n in (1, 2):
        st, _, _ = ctx.call("DELETE", "/v1/credentials/%s?uuid=%s" % (pid, UUIDS[0]))
        if st != 204:
            return "DELETE by uuid (time %d): HTTP %d (want 204, idempotent)" % (n, st)
    st, rows, _ = ctx.call("GET", "/v1/credentials?uuid=" + UUIDS[0])
    if any(r.get("id") == pid for r in rows or []):
        return "the revoked password is still listed"
    return None


def check_mass_removal(ctx):
    put(ctx, doc(ctx, ["alice", "bob", "carol"]))
    st, j, _ = put(ctx, doc(ctx, ["alice"]))
    if st != 409 or (j or {}).get("error_kind") != "mass_removal" or not isinstance((j or {}).get("removed"), list):
        return "removing 2 of 3 accounts: HTTP %d %r (want 409 mass_removal with removed)" % (st, j)
    names = sorted(x.get("username") for x in j["removed"])
    if names != ["bob", "carol"]:
        return "removed lists %r (want bob, carol)" % names
    st, _, _ = put(ctx, doc(ctx, ["alice"], confirm=True))
    if st != 202:
        return "the confirmed removal: HTTP %d (want 202)" % st
    return None


def check_allowed_ips(ctx):
    nets = ["192.168.77.0/24", "10.20.0.0/16"]
    st, _, b = put(ctx, doc(ctx, ["alice"], lan_only=True, local=nets))
    if st != 202:
        return "PUT a LAN-only document: HTTP %d %s" % (st, b[:200])
    cred(ctx, "alice", UUIDS[0], "lan")
    st, rows, _ = ctx.call("GET", "/v1/credentials?uuid=" + UUIDS[0])
    if st != 200 or not rows:
        return "list: HTTP %d" % st
    for r in rows:
        if sorted(r.get("allowed_ips") or []) != sorted(nets):
            return "allowed_ips %r under LAN-only (want exactly %r)" % (r.get("allowed_ips"), nets)
    put(ctx, doc(ctx, ["alice"]))
    return None


def check_void(ctx):
    put(ctx, doc(ctx, ["alice", "bob"]))
    cred(ctx, "alice", UUIDS[0], "void-a")
    cred(ctx, "bob", UUIDS[1], "void-b")
    st, j, _ = ctx.call("POST", "/v1/void", {"reason": "restore"})
    if st != 200:
        return "POST /v1/void: HTTP %d" % st
    for u in UUIDS[:2]:
        st, rows, _ = ctx.call("GET", "/v1/credentials?uuid=" + u)
        if st != 200 or rows:
            return "after the void %s lists %r (want [])" % (u, rows)
    return None


API_CHECKS = [
    ("auth_refusals", check_auth),
    ("strict_json", check_strict_json),
    ("stale_generation", check_stale_generation),
    ("account_mismatch", check_account_mismatch),
    ("uuid_echoed", check_uuid_echoed),
    ("revoke_by_uuid", check_revoke_by_uuid),
    ("mass_removal", check_mass_removal),
    ("allowed_ips_lan_only", check_allowed_ips),
    ("void_empties_every_list", check_void),
]
