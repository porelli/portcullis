"""The provider API v1 checks (contract §19.5; mail provider plan P11).

Every check takes a Ctx and returns None (pass) or a reason (fail). They
write documents: run them only against a provider set aside for it (CI).
"""
import json
import time
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
        # A provider applies an accepted document on its own time, and
        # judges the next one against what it applied (its live accounts:
        # mass removal, parking): put() waits for applied_generation.
        self.sleep = time.sleep
        self.apply_wait = 180
        self.unavailable_wait = 90
        self.created = []  # (uuid, id, secret) of passwords made here
        self.notes = []  # what the running check observed (run.py prints them)
        self.smtp_host = self.imap_host = self.jmap_url = None

    def call(self, method, path, body=None, bearer="default", base=None, raw=None):
        """(status, parsed JSON or None, raw bytes). A 503 (the provider's
        mail server restarting, e.g. after a LAN-only change it applied)
        is asked again for up to unavailable_wait seconds."""
        waited = 0
        while True:
            st, j, b = self._call(method, path, body, bearer, base, raw)
            if st != 503 or waited >= self.unavailable_wait:
                return st, j, b
            self.sleep(2)
            waited += 2

    def _call(self, method, path, body=None, bearer="default", base=None, raw=None):
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
# App mail senders (contract §19.14): portcullis-app-<instance>.
SENDER_UUIDS = ["c0f0b000-0000-4000-8000-0000000000%02d" % i for i in range(1, 5)]
SENDERS = ["portcullis-app-conformance", "portcullis-hub-mail", "portcullis-app-conformance-b", "portcullis-app-conformance-c"]


def sender(i):
    return {"username": SENDERS[i], "uuid": SENDER_UUIDS[i], "address": SENDERS[i] + "@conformance.test"}


def doc(ctx, accounts, lan_only=False, local=None, confirm=False, senders=None):
    """senders: None = the key left out (an older Hub); a list of SENDERS
    indexes = present (possibly empty)."""
    accts = [{"username": u, "uuid": UUIDS[i], "display_name": u, "addresses": [u + "@conformance.test"], "quota_bytes": 0}
             for i, u in enumerate(accounts)]
    return with_senders({"version": 2, "generation": ctx.next_gen(), "primary_domain": "conformance.test",
            "mail_hostname": "mail.conformance.test", "client_ip": "preserved", "submission_lan_only": lan_only,
            "dkim_rotate": "4380h", "former_retention": "720h", "relay": None, "tls": {"spki_sha256": [ctx.spki]},
            "confirm_mass_removal": confirm,
            "domains": [{"name": "conformance.test", "dmarc_start": "reject", "dmarc_floor": "reject", "mail": "on", "dnssec": "unsigned"}],
            "accounts": accts, "aliases": [], "lists": [], "postmaster": [], "limits": {"recipients_per_hour": 100, "recipients_per_day": 1000},
            "spam": {"junk_score": 5, "reject_score": 10, "dnsbl": {"spamhaus": False, "spamcop": False, "barracuda": False}, "allow": [], "block": []},
            "local_networks": local if local is not None else ["192.168.77.0/24"]}, senders)


def with_senders(d, senders):
    if senders is not None:
        d["senders"] = [sender(i) for i in senders]
    return d


def put(ctx, d):
    """PUT /v1/state; once accepted (202), waits until the provider says
    it applied that generation (a provider judges the next document
    against what it applied; contract §19.5)."""
    st, j, b = ctx.call("PUT", "/v1/state", d)
    if st != 202:
        return st, j, b
    gen = d.get("generation")
    waited = 0
    while waited < ctx.apply_wait:
        s2, sj, _ = ctx.call("GET", "/v1/state")
        if s2 == 200 and isinstance(sj, dict) and (sj.get("applied_generation") or 0) >= gen:
            return st, j, b
        ctx.sleep(1)
        waited += 1
    # Accepted but never applied: no check may judge it (status 0).
    return 0, j, b + (" (not applied within %d s)" % ctx.apply_wait).encode()


def cred(ctx, user, uuid, label="conformance", allowed_ips=None):
    body = {"username": user, "uuid": uuid, "label": label, "expires_at": None}
    if allowed_ips is not None:
        body["allowed_ips"] = allowed_ips
    st, j, _ = ctx.call("POST", "/v1/credentials", body)
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
    st, _, b = put(ctx, doc(ctx, [], confirm=True, senders=[]))
    if st != 202:
        return "the empty document (confirm_mass_removal, no senders): HTTP %d %s" % (st, b[:200])
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


def check_senders_optional(ctx):
    """senders is optional (§19.5): absent (an older Hub), present and
    empty are all accepted."""
    for name, s in (("absent", None), ("present", [0, 1]), ("absent again", None), ("empty", [])):
        st, j, b = put(ctx, doc(ctx, ["alice"], senders=s))
        if st != 202:
            return "senders %s: HTTP %d %s (want 202)" % (name, st, b[:200])
    return None


def check_senders_refused(ctx):
    """A malformed sender refuses the whole document (400)."""
    bad = {
        "a person's username": {"username": "alice", "uuid": SENDER_UUIDS[0], "address": "alice@conformance.test"},
        "another address": {"username": SENDERS[0], "uuid": SENDER_UUIDS[0], "address": "app@conformance.test"},
        "a uuid that isn't one": {"username": SENDERS[0], "uuid": "c0f0b000", "address": SENDERS[0] + "@conformance.test"},
        "an unknown key": dict(sender(0), label="x"),
    }
    for name, s in bad.items():
        d = doc(ctx, ["alice"])
        d["senders"] = [s]
        st, _, _ = put(ctx, d)
        if st != 400:
            return "a sender with %s: HTTP %d (want 400)" % (name, st)
    d = doc(ctx, ["alice"])
    d["senders"] = [sender(0), sender(0)]
    st, _, _ = put(ctx, d)
    if st != 400:
        return "a sender twice: HTTP %d (want 400)" % st
    d = doc(ctx, ["alice"])
    d["senders"] = None
    st, _, _ = put(ctx, d)
    if st != 400:
        return "senders null: HTTP %d (want 400)" % st
    return None


def check_sender_credential(ctx):
    """A sender's credential (§19.14): no allowed_ips (400); under LAN-only
    it is the Local networks, like a person's."""
    nets = ["192.168.77.0/24", "10.20.0.0/16"]
    st, _, b = put(ctx, doc(ctx, ["alice"], lan_only=True, local=nets, senders=[0]))
    if st != 202:
        return "PUT a LAN-only document with a sender: HTTP %d %s" % (st, b[:200])
    st, j = cred(ctx, SENDERS[0], SENDER_UUIDS[0], "sender")
    if st != 201 or not (j or {}).get("secret"):
        return "the sender's credential: HTTP %d %r" % (st, (j or {}).get("error"))
    st, rows, _ = ctx.call("GET", "/v1/credentials?uuid=" + SENDER_UUIDS[0])
    if st != 200 or not rows or any(sorted(r.get("allowed_ips") or []) != sorted(nets) for r in rows):
        return "the sender's credentials under LAN-only: HTTP %d %r (want allowed_ips %r)" % (st, rows, nets)
    st, _ = cred(ctx, SENDERS[0], SENDER_UUIDS[0], "sender", allowed_ips=["172.18.0.0/16"])
    if st != 400:
        return "a sender's credential with allowed_ips: HTTP %d (want 400)" % st
    st, j = cred(ctx, SENDERS[0], SENDER_UUIDS[1], "sender")
    if st != 409 or (j or {}).get("error_kind") != "account_mismatch":
        return "the sender with another uuid: HTTP %d %r (want 409 account_mismatch)" % (st, j)
    put(ctx, doc(ctx, ["alice"], senders=[]))
    return None


def check_senders_not_mass_removal(ctx):
    """Senders are excluded from the 50 % rule: removing every sender is
    accepted, and so is a list without one of them (its credentials go)."""
    st, _, b = put(ctx, doc(ctx, ["alice"], senders=[0, 2, 3]))
    if st != 202:
        return "PUT three senders: HTTP %d %s" % (st, b[:200])
    cred(ctx, SENDERS[2], SENDER_UUIDS[2], "gone")
    st, j, _ = put(ctx, doc(ctx, ["alice"], senders=[0]))
    if st != 202:
        return "removing two of three senders: HTTP %d %r (want 202)" % (st, j)
    st, rows, _ = ctx.call("GET", "/v1/credentials?uuid=" + SENDER_UUIDS[2])
    if st == 200 and rows:
        return "a removed sender's credentials are still listed: %r" % rows
    st, j, _ = put(ctx, doc(ctx, ["alice"], senders=[]))
    if st != 202:
        return "removing every sender: HTTP %d %r (want 202)" % (st, j)
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
    ("senders_optional", check_senders_optional),
    ("senders_refused", check_senders_refused),
    ("sender_credential", check_sender_credential),
    ("senders_not_mass_removal", check_senders_not_mass_removal),
    ("void_empties_every_list", check_void),
]
