#!/usr/bin/env python3
"""Group-gate: per-app authorization middleware for Traefik ForwardAuth.

Checks, run in order:
  0. Revocation — if the request carries a TLS client cert (Traefik's
     passTLSClientCert middleware `client-headers@file` must run BEFORE
     portcullis-groups; it sets X-Forwarded-Tls-Client-Cert-Info incl.
     SerialNumber="<decimal>"), deny when that serial is revoked. Traefik
     itself never checks CRLs, so this is where revocation is enforced.
     Revoked serials come from
       - GATE_REVOKED_FILE (one hex serial per line, colons optional, '#'
         comments; written by scripts/revoke-cert.sh), re-read whenever it
         changes. Missing file = none revoked; unreadable file = requests
         that present a cert are denied (fail closed).
       - GATE_CRL_URL (Vault's DER CRL, e.g. http://vault:8200/v1/pki_int/crl),
         re-fetched every GATE_CRL_REFRESH_SECONDS (default 60) in the
         background. Fetch errors keep the last good CRL (fail open on
         Vault outages — the serial file still applies).
  1. Auth policy — does the current session's ACR/AMR satisfy the app's
     required factor set (one of mtls/webauthn/password, with AND/OR
     semantics)? If not, 403 with a stepup URL so the user can re-auth
     at the needed Level of Authentication.
  2. Group — does the user belong to the subdomain's required LLDAP
     group (users_<app>)? If not, 403.

Config sources (both re-read on every request; they are tiny):
  - /etc/group-gate/map.conf — subdomain=required_group. Authoritative for
    core subdomains (auth, traefik, hub, directory, enroll): the Hub policy
    file can never override those.
  - /hub-data/group-gate-policy.json — written by the Hub:
      {"policies": {"<template-id-or-subdomain>": {"factors": [...], "op": "any|all|"}},
       "default":  {"factors": [...], "op": "..."},
       "groups":   {"<subdomain>": "<required LLDAP group>"}}
    Optional; no file means every app falls through to the group check
    only. A file that exists but cannot be parsed, or a policy with unknown
    factor names / op, fails CLOSED (403).

Host handling: X-Forwarded-Host is normalised (lowercased, port and
trailing dot stripped) because Traefik's Host() matcher is
case-insensitive. When PORTCULLIS_DOMAIN is set, the host must be exactly
<single-label>.<PORTCULLIS_DOMAIN>, otherwise the request is denied.

Access token is read from X-Forwarded-Access-Token (oauth2-proxy with
PASS_ACCESS_TOKEN=true). The JWT signature is NOT verified here — it was
already verified upstream by oauth2-proxy before the request reaches us.
We only decode the payload to read the acr/amr claims.
"""

from __future__ import annotations

import base64
import html
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import FrozenSet, List, Optional, Tuple

LISTEN_PORT = int(os.environ.get("GATE_PORT", "8080"))
POLICY_FILE = os.environ.get("GATE_POLICY_FILE", "/hub-data/group-gate-policy.json")
MAP_FILE = os.environ.get("GATE_MAP_FILE", "/etc/group-gate/map.conf")
DOMAIN = os.environ.get("PORTCULLIS_DOMAIN", "").strip().lower().rstrip(".")
REVOKED_FILE = os.environ.get("GATE_REVOKED_FILE", "/etc/group-gate/revocation/revoked-serials.txt")
CRL_URL = os.environ.get("GATE_CRL_URL", "").strip()
CRL_REFRESH_SECONDS = float(os.environ.get("GATE_CRL_REFRESH_SECONDS", "60"))
CERT_INFO_HEADER = "X-Forwarded-Tls-Client-Cert-Info"

# Core infrastructure subdomains. Their required group comes only from
# map.conf / GATE_MAP; Hub-written "groups" entries for them are ignored.
# If map.conf somehow lacks one, it defaults to lldap_admin (fail closed).
CORE_SUBDOMAINS = ("auth", "traefik", "hub", "directory", "enroll")
CORE_DEFAULT_GROUP = "lldap_admin"
VALID_OPS = ("", "any", "all")

# Factor string ↔ AMR value used in tokens (RFC 8176 where possible).
FACTOR_TO_AMR = {
    "mtls": "mtls",
    "webauthn": "hwk",
    "password": "pwd",
}

# Factor → LoA level (must match the realm acr.loa.map).
FACTOR_TO_LOA = {
    "password": 1,
    "webauthn": 2,
    "mtls": 3,
}

# acr string → LoA int (must match realm acr.loa.map).
ACR_TO_LOA = {"public": 0, "pwd": 1, "hwk": 2, "mtls": 3}


class PolicyError(Exception):
    """Policy file exists but is unreadable/malformed — callers must deny."""


def load_static_map() -> dict:
    """Parse map.conf plus the GATE_MAP env override (subdomain=group)."""
    mapping = {}
    if os.path.isfile(MAP_FILE):
        with open(MAP_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    sub, group = line.split("=", 1)
                    mapping[sub.strip().lower()] = group.strip()
    env_map = os.environ.get("GATE_MAP", "")
    for pair in env_map.split(","):
        pair = pair.strip()
        if "=" in pair:
            sub, group = pair.split("=", 1)
            mapping[sub.strip().lower()] = group.strip()
    return mapping


def build_group_map(policy_doc: dict) -> dict:
    """Merge map.conf with the Hub's "groups" key.

    Hub entries add/override non-core subdomains; core subdomains always
    keep the map.conf value (or lldap_admin if map.conf is missing it).
    """
    mapping = load_static_map()
    for sub in CORE_SUBDOMAINS:
        mapping.setdefault(sub, CORE_DEFAULT_GROUP)
    hub_groups = policy_doc.get("groups") if isinstance(policy_doc, dict) else None
    if isinstance(hub_groups, dict):
        for sub, group in hub_groups.items():
            if not isinstance(sub, str) or not isinstance(group, str):
                continue
            sub, group = sub.strip().lower(), group.strip()
            if not sub or not group:
                continue
            if sub in CORE_SUBDOMAINS:
                if group != mapping[sub]:
                    print(
                        f"group-gate: ignoring policy-file group {group!r} for core subdomain {sub!r}",
                        flush=True,
                    )
                continue
            mapping[sub] = group
    return mapping


def load_policy_file() -> dict:
    """Return the Hub policy doc, {} if the file is absent.

    Raises PolicyError if the file exists but is not a JSON object — a
    broken policy must not silently downgrade apps to "no policy".
    """
    try:
        with open(POLICY_FILE) as f:
            doc = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise PolicyError(f"cannot read policy file: {e}") from e
    if not isinstance(doc, dict):
        raise PolicyError("policy file is not a JSON object")
    return doc


# ── Client-certificate revocation ─────────────────────────────────────


class RevocationError(Exception):
    """Revocation list exists but cannot be read — deny cert-bearing requests."""


def parse_hex_serial(text: str) -> Optional[int]:
    """'1a:2b:3c' / '1A2B3C' → int. None for blank/comment/garbage lines."""
    text = text.split("#", 1)[0].strip().replace(":", "").replace("-", "")
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


_file_cache_lock = threading.Lock()
_file_cache: dict = {"key": None, "serials": frozenset()}


def load_revoked_file(path: Optional[str] = None) -> FrozenSet[int]:
    """Serials from the revoked-serials file, cached on (inode, mtime, size)."""
    path = path or REVOKED_FILE
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return frozenset()
    except OSError as e:
        raise RevocationError(f"cannot stat {path}: {e}") from e
    key = (path, st.st_ino, st.st_mtime_ns, st.st_size)
    with _file_cache_lock:
        if _file_cache["key"] == key:
            return _file_cache["serials"]
    try:
        with open(path) as f:
            serials = frozenset(s for s in (parse_hex_serial(line) for line in f) if s is not None)
    except (OSError, UnicodeDecodeError) as e:
        raise RevocationError(f"cannot read {path}: {e}") from e
    with _file_cache_lock:
        _file_cache["key"] = key
        _file_cache["serials"] = serials
    return serials


def _der_tlv(buf: bytes, pos: int) -> Tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the DER element at pos."""
    if pos + 2 > len(buf):
        raise ValueError("truncated DER")
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(buf):
            raise ValueError("bad DER length")
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    if pos + length > len(buf):
        raise ValueError("truncated DER")
    return tag, pos, pos + length


def _der_children(buf: bytes, start: int, end: int) -> List[Tuple[int, int, int]]:
    out = []
    pos = start
    while pos < end:
        tag, cs, ce = _der_tlv(buf, pos)
        out.append((tag, cs, ce))
        pos = ce
    return out


def parse_crl_serials(data: bytes) -> FrozenSet[int]:
    """Revoked serial numbers from an X.509 CRL (DER, or PEM).

    The CRL signature is not verified: it is fetched from Vault over the
    internal network, and it can only ever ADD denials.
    """
    if data.lstrip().startswith(b"-----BEGIN"):
        b64 = b"".join(l for l in data.splitlines() if l and not l.startswith(b"-----"))
        data = base64.b64decode(b64)
    tag, cs, ce = _der_tlv(data, 0)
    if tag != 0x30:
        raise ValueError("CRL is not a SEQUENCE")
    tbs_tag, ts, te = _der_tlv(data, cs)
    if tbs_tag != 0x30:
        raise ValueError("tbsCertList is not a SEQUENCE")
    fields = _der_children(data, ts, te)
    i = 0
    if i < len(fields) and fields[i][0] == 0x02:  # version
        i += 1
    i += 2  # signature AlgorithmIdentifier, issuer Name
    times = (0x17, 0x18)  # UTCTime, GeneralizedTime
    if i >= len(fields) or fields[i][0] not in times:
        raise ValueError("CRL thisUpdate missing")
    i += 1
    if i < len(fields) and fields[i][0] in times:  # nextUpdate
        i += 1
    serials = set()
    if i < len(fields) and fields[i][0] == 0x30:  # revokedCertificates
        _, rs, re_ = fields[i]
        for etag, es, ee in _der_children(data, rs, re_):
            if etag != 0x30:
                continue
            stag, ss, se = _der_tlv(data, es)
            if stag == 0x02:
                serials.add(int.from_bytes(data[ss:se], "big", signed=True))
    return frozenset(serials)


class CrlCache:
    """Background-refreshed set of serials from GATE_CRL_URL."""

    def __init__(self, url: str, interval: float):
        self.url = url
        self.interval = max(interval, 1.0)
        self.serials: FrozenSet[int] = frozenset()
        self.last_error: Optional[str] = None

    def refresh(self) -> bool:
        try:
            with urllib.request.urlopen(self.url, timeout=5) as resp:
                data = resp.read(16 * 1024 * 1024)
            serials = parse_crl_serials(data)
        except Exception as e:  # noqa: BLE001 — any failure keeps the last good CRL
            err = f"{type(e).__name__}: {e}"
            if err != self.last_error:
                print(f"group-gate: CRL fetch from {self.url} failed ({err}); keeping last good list "
                      f"({len(self.serials)} serials)", flush=True)
            self.last_error = err
            return False
        if serials != self.serials or self.last_error:
            print(f"group-gate: CRL loaded from {self.url}: {len(serials)} revoked serial(s)", flush=True)
        self.serials = serials
        self.last_error = None
        return True

    def run_forever(self):
        while True:
            self.refresh()
            time.sleep(self.interval)


CRL_CACHE: Optional[CrlCache] = CrlCache(CRL_URL, CRL_REFRESH_SECONDS) if CRL_URL else None


def revoked_serials() -> FrozenSet[int]:
    serials = load_revoked_file()
    if CRL_CACHE is not None:
        serials = serials | CRL_CACHE.serials
    return serials


_SERIAL_RE = re.compile(r'SerialNumber="(\d+)"')


def format_serial(n: int) -> str:
    """int → Vault-style colon-separated hex ('1a:2b:...')."""
    h = f"{n:x}"
    if len(h) % 2:
        h = "0" + h
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def cert_serials_from_info(raw: str) -> List[int]:
    """Decimal serials from Traefik's X-Forwarded-Tls-Client-Cert-Info.

    Traefik URL-escapes the value (some versions twice), and with several
    certs in the presented chain joins them with ','. Every serial found is
    returned (leaf first).
    """
    value = raw or ""
    for _ in range(3):
        decoded = urllib.parse.unquote(value)
        if decoded == value:
            break
        value = decoded
    return [int(m) for m in _SERIAL_RE.findall(value)]


def normalize_host(raw: str) -> str:
    """Lowercase, drop port and trailing dot(s)."""
    host = (raw or "").split(",")[0].strip().lower()
    if host.startswith("["):  # IPv6 literal — never a valid app host
        return host
    host = host.rsplit(":", 1)[0] if ":" in host else host
    return host.rstrip(".")


def subdomain_for(host: str) -> Optional[str]:
    """Return the app subdomain, or None if the host is not acceptable.

    With PORTCULLIS_DOMAIN set the host must be exactly <label>.<domain>.
    Without it (dev/test), fall back to the first label.
    """
    if not host:
        return None
    if DOMAIN:
        suffix = "." + DOMAIN
        if not host.endswith(suffix):
            return None
        sub = host[: -len(suffix)]
        if not sub or "." in sub:
            return None
        return sub
    return host.split(".")[0] or None


def decode_jwt_payload(token: str) -> dict:
    """Decode a JWT payload without verifying the signature.

    The token has already been verified by oauth2-proxy upstream — we're
    inside the trust boundary and only need the claims.
    """
    try:
        _header, payload, _sig = token.split(".", 2)
    except ValueError:
        return {}
    # JWT uses base64url without padding; re-pad and decode.
    padded = payload + "=" * (-len(payload) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded.encode()))
    except (ValueError, UnicodeDecodeError):
        return {}


def resolve_policy(policy_doc: dict, subdomain: str) -> Optional[dict]:
    """Return {factors, op} for this app, or None if no policy configured."""
    if not policy_doc:
        return None
    policies = policy_doc.get("policies") or {}
    if not isinstance(policies, dict):
        raise PolicyError("'policies' is not an object")
    if subdomain in policies:
        policy = policies[subdomain]
        if not isinstance(policy, dict):
            raise PolicyError(f"policy for {subdomain!r} is not an object")
        return policy
    default = policy_doc.get("default")
    if default is None:
        return None
    if not isinstance(default, dict):
        raise PolicyError("'default' is not an object")
    if default.get("factors") is not None:
        return default
    return None


def validate_policy(policy: dict) -> Optional[str]:
    """Return an error string if the policy is malformed, else None."""
    factors = policy.get("factors")
    if factors is None:
        factors = []
    if not isinstance(factors, list):
        return "'factors' is not a list"
    unknown = [f for f in factors if not isinstance(f, str) or f not in FACTOR_TO_AMR]
    if unknown:
        return f"unknown factor(s) {unknown!r}"
    op = policy.get("op")
    if op is None:
        op = ""
    if not isinstance(op, str) or op.lower() not in VALID_OPS:
        return f"unknown op {op!r}"
    return None


def evaluate_policy(policy: dict, acr: str, amr: list) -> Tuple[bool, str, int]:
    """Return (allowed, reason, required_loa).

    required_loa is the LoA the user needs to reach to satisfy the policy;
    callers can encode it in a stepup URL when allowed=False.
    """
    # Callers must run validate_policy() first; unknown names are not
    # silently dropped here any more.
    factors = list(policy.get("factors") or [])
    op = (policy.get("op") or "").lower() or ("any" if len(factors) > 1 else "")

    # No factors = public, allow.
    if not factors:
        return True, "public", 0

    amr_set = set(amr or [])
    needed_amrs = {FACTOR_TO_AMR[f] for f in factors}

    if op == "all":
        required_loa = max(FACTOR_TO_LOA[f] for f in factors)
        if needed_amrs.issubset(amr_set):
            return True, f"all factors present (amr={sorted(amr_set)})", required_loa
        missing = sorted(needed_amrs - amr_set)
        return False, f"need all of {sorted(needed_amrs)}, missing {missing}", required_loa

    # op == "any" (or len == 1)
    required_loa = min(FACTOR_TO_LOA[f] for f in factors)
    if amr_set & needed_amrs:
        return True, f"amr {sorted(amr_set & needed_amrs)} satisfies any-of {sorted(needed_amrs)}", required_loa
    return False, f"need any of {sorted(needed_amrs)}, have {sorted(amr_set)}", required_loa


def stepup_url(host: str, needed_loa: int, factors: list) -> str:
    """Build a step-up URL that asks oauth2-proxy for a fresh login at the
    required Level of Authentication.

    We pass `prompt=login` and `acr_values=<acr>` to /oauth2/start, which
    oauth2-proxy forwards to Keycloak's authorize endpoint. `prompt=login`
    tells Keycloak to bypass its SSO `auth-cookie` short-circuit and re-run
    the flow; `acr_values` routes the user into the matching LoA conditional
    subflow so the missing factor is actually prompted for.

    No sign_out in the chain: the browser still has oauth2-proxy's cookie
    but we want Keycloak to issue a *new* token reflecting the step-up, not
    to delete the old session.
    """
    loa_to_acr = {0: "public", 1: "pwd", 2: "hwk", 3: "mtls"}
    acr = loa_to_acr.get(needed_loa, "pwd")
    query = urllib.parse.urlencode({
        "acr_values": acr,
        "prompt": "login",
        "rd": f"https://{host}/",
    })
    return f"https://{host}/oauth2/start?{query}"


def safe_factor_name(amr: str) -> str:
    for factor, amr_value in FACTOR_TO_AMR.items():
        if amr_value == amr:
            return factor
    return amr


class Handler(BaseHTTPRequestHandler):
    def _deny(self, title: str, body_html: str, log: str, extra_headers: Optional[dict] = None):
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(f"<h1>{html.escape(title)}</h1>{body_html}".encode())
        print(f"group-gate: {log}", flush=True)

    def _allow(self):
        self.send_response(200)
        email = self.headers.get("X-Auth-Request-Email", "")
        if email:
            self.send_header("X-Forwarded-User", email)
        # Traefik's forwardAuth deletes every authResponseHeaders entry from
        # the upstream request and only re-adds those present in OUR
        # response. Echo the values oauth2-proxy set (portcullis-auth runs
        # first) so backends like enroll still see the user's groups.
        for name in ("X-Auth-Request-User", "X-Auth-Request-Groups"):
            value = self.headers.get(name, "")
            if value:
                self.send_header(name, value)
        self.end_headers()

    def do_GET(self):
        raw_host = self.headers.get("X-Forwarded-Host", "")
        host = normalize_host(raw_host)
        user = self.headers.get("X-Auth-Request-Email", "") or self.headers.get("X-Auth-Request-User", "unknown")
        e_user = html.escape(user)

        subdomain = subdomain_for(host)
        if subdomain is None:
            self._deny(
                "Access Denied",
                "<p>Unrecognised host.</p>",
                f"DENIED user={user} host={raw_host!r} reason=host not under PORTCULLIS_DOMAIN={DOMAIN!r}",
            )
            return
        e_sub = html.escape(subdomain)

        # --- Client-cert revocation (before anything else) ---
        cert_info = self.headers.get(CERT_INFO_HEADER, "")
        if cert_info:
            serials = cert_serials_from_info(cert_info)
            if not serials:
                print(f"group-gate: WARNING {CERT_INFO_HEADER} has no SerialNumber — revocation "
                      f"cannot be checked (enable info.serialNumber in client-headers@file)", flush=True)
            else:
                try:
                    revoked = revoked_serials()
                except RevocationError as e:
                    self._deny(
                        "Access Denied",
                        "<p>The certificate revocation list is unavailable, so client certificates "
                        "cannot be accepted right now.</p>",
                        f"DENIED user={user} host={host} reason=revocation list error: {e}",
                    )
                    return
                hit = [sn for sn in serials if sn in revoked]
                if hit:
                    self._deny(
                        "Access Denied",
                        "<p>Your client certificate has been <b>revoked</b>. "
                        "Ask an administrator to re-enroll your security key.</p>",
                        f"DENIED user={user} host={host} reason=revoked client cert serial={format_serial(hit[0])}",
                    )
                    return

        # Per-request reload — the Hub rewrites the policy file on each
        # change, and both files are tiny.
        try:
            policy_doc = load_policy_file()
            gate = build_group_map(policy_doc)
            policy = resolve_policy(policy_doc, subdomain)
            policy_err = validate_policy(policy) if policy else None
        except PolicyError as e:
            policy_err = str(e)
            policy = None
            gate = {}
        if policy_err:
            self._deny(
                "Access Denied",
                "<p>The access policy for this app is misconfigured, so access is denied. "
                "Ask an administrator to fix it in the Hub.</p>",
                f"DENIED user={user} host={host} reason=malformed policy: {policy_err}",
            )
            return

        # --- Auth policy check (optional, only when policy is set) ---
        if policy:
            access_token = self.headers.get("X-Forwarded-Access-Token", "")
            if not access_token:
                auth_header = self.headers.get("Authorization", "")
                if auth_header.lower().startswith("bearer "):
                    access_token = auth_header[7:]

            claims = decode_jwt_payload(access_token) if access_token else {}
            acr = claims.get("acr", "")
            amr = claims.get("amr") or []
            if not isinstance(amr, list):
                amr = []

            allowed, reason, required_loa = evaluate_policy(policy, acr, amr)
            if not allowed:
                url = stepup_url(host, required_loa, policy.get("factors") or [])
                e_url = html.escape(url, quote=True)
                self.send_response(403)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("X-Stepup-URL", url)
                self.end_headers()
                factors = policy.get("factors") or []
                op = policy.get("op") or "any"
                have = ", ".join(safe_factor_name(str(a)) for a in amr) or "none"
                need_desc = f"{op} of: {', '.join(factors)}" if len(factors) > 1 else factors[0] if factors else "authentication"
                # If a hardware factor is in play, surface a link to the
                # Keycloak account console so users who haven't enrolled yet
                # can register a WebAuthn key.
                needs_hardware = any(f in ("mtls", "webauthn") for f in factors)
                parent_domain = DOMAIN or (".".join(host.split(".")[1:]) if "." in host else "")
                account_url = (
                    f"https://auth.{parent_domain}/realms/portcullis/account/account-security/signing-in"
                    if parent_domain else ""
                )
                enrollment_block = ""
                if needs_hardware and account_url:
                    enrollment_block = (
                        f"<p style=\"background:#fff7ed;border:1px solid #fed7aa;padding:.75rem 1rem;border-radius:.5rem;margin-top:1rem\">"
                        f"<b>No hardware key yet?</b> "
                        f"<a href=\"{html.escape(account_url, quote=True)}\" target=\"_blank\" rel=\"noopener\">Open the account console</a> "
                        f"to register a security key, then return and retry.</p>"
                    )
                # Meta-refresh bumps the user through the fresh authorize
                # flow automatically after 2 seconds. The explicit link is
                # the accessible fallback.
                self.wfile.write(
                    (
                        "<!doctype html><html><head>"
                        f"<meta http-equiv=\"refresh\" content=\"2;url={e_url}\">"
                        "<title>Additional authentication required</title>"
                        "<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:32rem;"
                        "margin:4rem auto;padding:2rem;color:#1e293b;line-height:1.55}"
                        "h1{font-size:1.5rem;margin:0 0 1rem}"
                        "code{background:#f1f5f9;padding:.15rem .4rem;border-radius:.25rem;font-size:.95em}"
                        "a{color:#3b82f6}</style></head><body>"
                        "<h1>Additional authentication required</h1>"
                        f"<p><b>{e_sub}</b> requires {html.escape(need_desc)}. "
                        f"Your current session was authenticated with <code>{html.escape(have)}</code>, which does not satisfy the app's policy.</p>"
                        f"<p>You will be redirected to re-authenticate in a moment. "
                        f"If nothing happens, <a href=\"{e_url}\">click here</a>.</p>"
                        f"{enrollment_block}"
                        "</body></html>"
                    ).encode()
                )
                print(
                    f"group-gate: STEPUP user={user} host={host} policy={policy} "
                    f"acr={acr!r} amr={amr} reason={reason!r}",
                    flush=True,
                )
                return

        # --- Group check ---
        required_group = gate.get(subdomain)
        if not required_group:
            print(f"group-gate: ALLOW-UNMAPPED user={user} host={host} (no group mapping for {subdomain!r})", flush=True)
            self._allow()
            return

        groups_raw = self.headers.get("X-Auth-Request-Groups", "")
        groups = {g.strip() for g in groups_raw.split(",") if g.strip()}
        if required_group in groups:
            self._allow()
            return

        self._deny(
            "Access Denied",
            f"<p>User <b>{e_user}</b> is not authorized to access <b>{e_sub}</b>.</p>"
            f"<p>Required group: <code>{html.escape(required_group)}</code></p>",
            f"DENIED user={user} host={host} need={required_group} have={sorted(groups)}",
        )

    def log_message(self, fmt, *args):
        # Default per-request logs are noisy; explicit logging above.
        pass


if __name__ == "__main__":
    print(
        f"group-gate: listening on :{LISTEN_PORT}, policy_file={POLICY_FILE}, "
        f"map_file={MAP_FILE}, domain={DOMAIN or '(unset: first-label fallback)'}",
        flush=True,
    )
    print(f"group-gate: static group mappings: {load_static_map()}", flush=True)
    print(f"group-gate: revocation: file={REVOKED_FILE} crl={CRL_URL or '(disabled)'} "
          f"refresh={CRL_REFRESH_SECONDS:g}s", flush=True)
    if CRL_CACHE is not None:
        threading.Thread(target=CRL_CACHE.run_forever, daemon=True, name="crl-refresh").start()
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
