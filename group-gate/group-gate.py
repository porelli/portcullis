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
         comments; written by `portcullis cert revoke|sync`), re-read whenever it
         changes. Missing file = none revoked; unreadable file = requests
         that present a cert are denied (fail closed).
       - GATE_CRL_URL (Vault's full DER CRL, http://vault:8200/v1/pki_int/crl)
         and GATE_DELTA_CRL_URL (its delta CRL, .../pki_int/crl/delta: with
         auto_rebuild Vault puts new revocations only there until the next
         full rebuild), re-fetched every GATE_CRL_REFRESH_SECONDS (default
         60) in the background; the union is enforced. Fetch errors keep
         the last good CRL (fail open on Vault outages — the serial file
         still applies).
     Traefik's entrypoint deletes client-supplied X-Forwarded-Tls-Client-*
     headers, so the header only ever describes a cert Traefik verified.
  1. Auth policy — does the current session's ACR/AMR satisfy the app's
     required factor set (one of mtls/webauthn, with AND/OR
     semantics)? If not, 403 with a stepup URL so the user can re-auth
     at the needed Level of Authentication.
     mTLS binding: when the policy is satisfied only through the `mtls`
     factor (amr=mtls), the token alone is not enough — it may have been
     obtained with a cert that has since been revoked. The CURRENT request
     must present a client cert (checked for revocation in step 0) whose
     subject CN equals the session user (the LLDAP username from
     X-Auth-Request-Preferred-Username, which must also match the token's
     preferred_username); otherwise step-up / deny.
  2. Group — does the user belong to the host's required LLDAP group
     (users_<app>)? If not, 403. The reserved group
     __portcullis_deny__ (published by the Hub for apps whose config is
     unknown) always denies, and so does a user who claims to be in it.
     The map.conf value `*` (people.<domain>) means any signed-in user.
     Temporary memberships (`expiring`) are absent once now >= at, for
     this check, path groups and the returned X-Auth-Request-Groups.
  3. Path groups — for hosts with `path_groups` rules, the normalised
     X-Forwarded-Uri path is matched against the rule prefixes (segment
     boundaries, longest prefix wins) and that rule's group is required in
     addition to the host's group. See normalize_path_candidates().

Request paths on group-gate itself (the forwardAuth `address`):
  /                     full checks (portcullis-groups@docker)
  /authenticated[/...]  everything except the host group check (step 2):
                        any authenticated user. Used for self-service routes
                        such as enroll.<domain>/self (portcullis-self@docker).
  /public-guard         public exceptions (portcullis-public-guard@docker, on
                        the Hub's portcullis-public-<instance> routers, no
                        forward-auth): no user, no group, no policy. Allows
                        only if the host has a `public_paths` entry (policy
                        file version 5; never a core host), the normalised
                        path is inside one of its patterns, and the request
                        carries no credential (Authorization,
                        Proxy-Authorization, the app's credential headers,
                        cookies or query parameters, names normalised the way
                        PHP does). Otherwise 403. See public_guard_check().
  /portal               the landing page at https://<domain>/
  /healthz              liveness (no checks, for the container healthcheck)
  /metrics              Prometheus metrics (monitoring profile): decisions by
                        endpoint/result, denials and step-ups by reason,
                        policy load errors, CRL freshness (last good fetch,
                        the CRL's nextUpdate), revoked-serial counts. Only
                        reachable on the internal `portcullis` network —
                        Traefik's forwardAuth always calls / or /authenticated.

Config sources (both re-read on every request; they are tiny):
  - /etc/group-gate/map.conf — <sub>=required_group, expanded to
    <sub>.<PORTCULLIS_DOMAIN> (`*` = any signed-in user, valid only
    there). Authoritative for the core hosts (<domain> itself and
    auth, traefik, hub, directory, enroll, people, metrics . <domain>):
    the Hub policy file can never override those.
  - /hub-data/group-gate-policy.json — written by the Hub (contract §4):
      {"version": 5,
       "default":  {"factors": [...], "op": "..."},
       "extra_domains": ["<enrolled domain>", ...],
       "policies": {"<hostname>": {"factors": [...], "op": "any|all|"}},
       "groups":   {"<hostname>": "<required LLDAP group>"},
       "path_groups": {"<hostname>": [{"prefix": "/admin", "group": "<LLDAP group>"}]},
       "public_paths": {"<hostname>": {"paths": [{"path": "/s/{token}", "match": "prefix"}],
                        "token_pattern": "^...$", "static_extensions": [...],
                        "credential_headers": [...], "credential_cookies": [...],
                        "credential_query": [...]}},
       "expiring": [{"user": "<lowercase username>", "group": "<LLDAP group>",
                     "at": "<RFC 3339 UTC>"}]}
    Every map is keyed by the full lowercase hostname the request is for
    (a valid hostname, see HOSTNAME_RE) — never by template or instance
    id, never by subdomain. Optional; no file means every app falls
    through to the group check only. Missing keys (other than `version`)
    are treated as empty. A file that exists but cannot be parsed, has no
    `version` or any `version` other than 5, a key that is not a valid
    hostname, a malformed `extra_domains`, or a policy / expiry with
    unknown factor names / op / rule shape fails CLOSED (403).
  - /hub-data/user-attributes.json — written by the Hub (contract §4.1):
    {"version": 2, "fields": {"<field>": "<Header-Name>"},
     "users": {"<user>": {"<field>": ["value", ...]}},
     "hosts": {"<host>": {"<Header-Name>": {"<user>": "value"}}}}. Every
    allow on / and /authenticated returns X-Forwarded-Attr-<Header-Name>
    for the user's fields: control characters stripped, values over 1 KB
    dropped (logged), `%` -> `%25` and `,` -> `%2C` in each value, values
    joined with ", ". On the request's (normalised) host it also returns
    that host's headers for the user: one value, control characters
    stripped, over 1 KB dropped (logged), no `,` encoding. A header a host
    declares replaces the same-named field header on that host for every
    user (with or without a value); two spellings of one user = malformed. A field whose name or header name is
    invalid, a host key that isn't a lowercase valid hostname, or a host
    header with an invalid name is skipped (logged); version 1 or any
    other version, a missing / corrupt file (logged; also two fields on
    one header, case-insensitive, or two headers of one host) = no
    attribute headers, never a deny.
  - Token headers: Authorization / X-Forwarded-Access-Token are echoed on
    allow (portcullis-groups lists them in authResponseHeaders) unless an
    expired membership was stripped for the request — the token still
    names the group, so it is withheld and Traefik deletes it.

Host handling (contract §4 "Host matching"): the first X-Forwarded-Host
value is lowercased, a numeric :<port> and trailing dots are stripped,
and the result must be a valid hostname. It is then looked up EXACTLY
(no subdomain or parent-domain fallback). A host is served only if it is
  - a core host (<domain>, <core sub>.<domain>): map.conf only;
  - an extra-domain host: an `extra_domains` entry <d> itself or
    <label>.<d> (step-up on the host itself, forward-auth-ext);
  - a main-domain host: <label>.<domain>.
Anything else is denied. PORTCULLIS_DOMAIN is required (the gate refuses
to start without a valid one, and denies every request if it is unset).

Access token is read from X-Forwarded-Access-Token (oauth2-proxy with
PASS_ACCESS_TOKEN=true). The JWT signature is NOT verified here — it was
already verified upstream by oauth2-proxy before the request reaches us.
We only decode the payload to read the acr/amr/preferred_username claims.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
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

import jwt  # PyJWT
from cryptography import x509

LISTEN_PORT = int(os.environ.get("GATE_PORT", "8080"))
POLICY_FILE = os.environ.get("GATE_POLICY_FILE", "/hub-data/group-gate-policy.json")
MAP_FILE = os.environ.get("GATE_MAP_FILE", "/etc/group-gate/map.conf")
DOMAIN = os.environ.get("PORTCULLIS_DOMAIN", "").strip().lower().rstrip(".")
REVOKED_FILE = os.environ.get("GATE_REVOKED_FILE", "/etc/group-gate/revocation/revoked-serials.txt")
CRL_URL = os.environ.get("GATE_CRL_URL", "").strip()
DELTA_CRL_URL = os.environ.get("GATE_DELTA_CRL_URL", "").strip()
CRL_REFRESH_SECONDS = float(os.environ.get("GATE_CRL_REFRESH_SECONDS", "60"))
CERT_INFO_HEADER = "X-Forwarded-Tls-Client-Cert-Info"

# A valid hostname (contract §4): lowercase, at least two labels, no port,
# no trailing dot, no wildcard, at most 253 characters. Always fullmatch():
# "$" would also match before a trailing "\n".
HOSTNAME_RE = re.compile(r"(?=.{1,253}\Z)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


def valid_hostname(value) -> bool:
    return isinstance(value, str) and HOSTNAME_RE.fullmatch(value) is not None


# The main domain; required (contract §4). Unset or invalid = every request
# is denied (and __main__ refuses to start).
DOMAIN_OK = valid_hostname(DOMAIN)

# Core infrastructure subdomains. With <domain> itself they are the core
# hosts: their required group comes only from map.conf / GATE_MAP;
# Hub-written entries for them are ignored. If map.conf somehow lacks one,
# it defaults to lldap_admin (fail closed).
CORE_SUBDOMAINS = ("auth", "traefik", "hub", "directory", "enroll", "people", "metrics")
CORE_DEFAULT_GROUP = "lldap_admin"


def core_hosts() -> FrozenSet[str]:
    """<domain> (the portal) and <core sub>.<domain> (contract §4)."""
    if not DOMAIN_OK:
        return frozenset()
    return frozenset([DOMAIN] + [f"{sub}.{DOMAIN}" for sub in CORE_SUBDOMAINS])
# map.conf value meaning "any signed-in user" (people.<domain>, contract
# §5.1). Valid ONLY in map.conf / GATE_MAP: in the policy file's `groups`
# it is ignored and in `path_groups` it is malformed (fail closed).
ANY_SIGNED_IN = "*"
VALID_OPS = ("", "any", "all")
# The one policy-file schema version this gate serves (contract §4): any
# other `version` denies (an older file lacks `expiring`, so a temporary
# membership would never end; a newer one may carry restrictions we would
# drop). A file without `version` denies too; only a missing FILE means
# "nothing published" (empty policy).
POLICY_VERSION = 5
# /public-guard needs a file of exactly this version (no `version` = deny).
PUBLIC_GUARD_VERSION = 5
# The maps of the policy file keyed by hostname (contract §4).
HOST_MAPS = ("policies", "groups", "path_groups", "public_paths")
# Reserved group (contract §4): the Hub publishes it for routed apps whose
# config is unknown. It always denies; nobody may claim membership.
DENY_GROUP = "__portcullis_deny__"
# Service accounts that must never use the gateway (the Hub's LLDAP account
# is in lldap_admin; Keycloak's federation also filters it out).
DENY_USERS = frozenset(u.strip().lower() for u in os.environ.get("GATE_DENY_USERS", "portcullis-hub").split(",") if u.strip())

# Factor string ↔ AMR value used in tokens (RFC 8176 where possible).
FACTOR_TO_AMR = {
    "mtls": "mtls",
    "webauthn": "hwk",
}
# There is no "password" factor: the browser flow has no password sign-in,
# and a stored policy naming it is unknown → denied (fail closed). The Hub
# rewrites such policies on load before publishing.

# Factor → LoA level (must match the realm acr.loa.map).
FACTOR_TO_LOA = {
    "webauthn": 2,
    "mtls": 3,
}

# acr string → LoA int (must match realm acr.loa.map).
ACR_TO_LOA = {"public": 0, "pwd": 1, "hwk": 2, "mtls": 3}


class PolicyError(Exception):
    """Policy file exists but is unreadable/malformed — callers must deny."""


def load_static_map() -> dict:
    """Parse map.conf plus the GATE_MAP env override (<sub>=group), keyed
    by subdomain label. An entry that is not a single DNS label is skipped
    (logged): the file names subdomains of the main domain only."""
    pairs = []
    if os.path.isfile(MAP_FILE):
        with open(MAP_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    pairs.append(line.split("=", 1))
    for pair in os.environ.get("GATE_MAP", "").split(","):
        pair = pair.strip()
        if "=" in pair:
            pairs.append(pair.split("=", 1))
    mapping = {}
    for sub, group in pairs:
        sub, group = sub.strip().lower(), group.strip()
        if not LABEL_RE.fullmatch(sub):
            print(f"group-gate: ignoring map entry {sub!r} (not a subdomain label)", flush=True)
            continue
        mapping[sub] = group
    return mapping


def build_group_map(policy_doc: dict) -> dict:
    """Required group per full hostname: map.conf's <sub> entries expanded
    to <sub>.<domain>, then the Hub's "groups" key.

    Hub entries add/override non-core hosts; core hosts always keep the
    map.conf value (or lldap_admin if map.conf is missing it). Key shapes
    were validated by load_policy_file.
    """
    if not DOMAIN_OK:
        return {}
    mapping = {f"{sub}.{DOMAIN}": group for sub, group in load_static_map().items()}
    core = core_hosts()
    for host in core:
        mapping.setdefault(host, CORE_DEFAULT_GROUP)
    hub_groups = policy_doc.get("groups") if isinstance(policy_doc, dict) else None
    if isinstance(hub_groups, dict):
        for host, group in hub_groups.items():
            if not isinstance(group, str) or not group.strip():
                continue
            group = group.strip()
            if group == ANY_SIGNED_IN:
                print(f"group-gate: ignoring policy-file group {group!r} for {host!r} (valid only in map.conf)",
                      flush=True)
                continue
            if host in core:
                if group != mapping[host]:
                    print(f"group-gate: ignoring policy-file group {group!r} for core host {host!r}", flush=True)
                continue
            mapping[host] = group
    return mapping


_POLICY_CACHE: dict = {}
_POLICY_LOCK = threading.Lock()


def validate_policy_doc(doc) -> Optional[str]:
    """Why a parsed policy file must deny every request, or None.

    Checks what applies to the whole file (contract §4): a JSON object of
    exactly POLICY_VERSION, every host map an object keyed by valid
    hostnames, and `extra_domains` a list of valid hostnames none of which
    is the main domain, a parent of it, or at or under a core host (extra
    domains never route core services). Per-host entries are validated
    when a request needs them.
    """
    if not isinstance(doc, dict):
        return "policy file is not a JSON object"
    version = doc.get("version")
    # An int exactly: JSON 5.0 (a float) or true (a bool) is not version 5.
    if type(version) is not int or version != POLICY_VERSION:
        return f"policy file version {version!r} is not supported (only {POLICY_VERSION})"
    for name in HOST_MAPS:
        m = doc.get(name)
        if m is None:
            continue
        if not isinstance(m, dict):
            return f"{name!r} is not an object"
        bad = [k for k in m if not valid_hostname(k)]
        if bad:
            return f"{name!r} has keys that are not valid hostnames: {sorted(map(repr, bad))[:5]}"
    extra = doc.get("extra_domains")
    if extra is not None:
        if not isinstance(extra, list):
            return "'extra_domains' is not a list"
        core = core_hosts()
        for d in extra:
            if not valid_hostname(d):
                return f"'extra_domains' entry {d!r} is not a valid hostname"
            # d == a core host, a parent of the main domain, or under a core
            # subdomain (x.hub.<domain>). <label>.<domain> is fine.
            if d in core or DOMAIN.endswith("." + d) or any(d.endswith("." + c) for c in core if c != DOMAIN):
                return f"'extra_domains' entry {d!r} overlaps the main domain's core hosts"
    return None


def _read_policy_doc():
    """(parsed policy file, why it must deny or None), cached on (path,
    inode, mtime, size): the Hub replaces it atomically (rename), so any
    change gives a new key. (None, None) when the file does not exist."""
    try:
        st = os.stat(POLICY_FILE)
    except FileNotFoundError:
        return None, None
    except OSError as e:
        raise PolicyError(f"cannot read policy file: {e}") from e
    key = (POLICY_FILE, st.st_ino, st.st_mtime_ns, st.st_size)
    with _POLICY_LOCK:
        if _POLICY_CACHE.get("key") == key:
            return _POLICY_CACHE["doc"], _POLICY_CACHE["error"]
    try:
        with open(POLICY_FILE) as f:
            doc = json.load(f)
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError) as e:
        raise PolicyError(f"cannot read policy file: {e}") from e
    error = validate_policy_doc(doc)
    with _POLICY_LOCK:
        _POLICY_CACHE.clear()
        _POLICY_CACHE.update(key=key, doc=doc, error=error)
    return doc, error


PORTAL_FILE = os.environ.get("GATE_PORTAL_FILE", os.path.join(os.path.dirname(POLICY_FILE), "portal-apps.json"))


def load_portal_apps():
    """(apps, domains) of the Hub's portal-apps.json (contract §10); apps is
    None when the file is missing, unreadable or of an unknown version
    (show nothing). domains: its valid `domains` entries (enrolled domains
    with listed hosts); anything else in it is ignored."""
    try:
        with open(PORTAL_FILE) as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return None, []
    if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(doc.get("apps"), list):
        return None, []
    domains = doc.get("domains")
    domains = [d for d in domains if valid_hostname(d)] if isinstance(domains, list) else []
    return [a for a in doc["apps"] if isinstance(a, dict)], domains


def _safe_url(u, domains=()) -> str:
    """https URLs on the main domain or one of `domains` only (anything
    else is dropped)."""
    if not isinstance(u, str) or not DOMAIN_OK:
        return ""
    parts = urllib.parse.urlsplit(u)
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or parts.username or not host:
        return ""
    if not any(host == d or host.endswith("." + d) for d in (DOMAIN, *domains)):
        return ""
    return u


# Same dark look as enroll's pages (enroll/web/*.html). Inline only, no
# external assets; allowed by PORTAL_CSP through its hash.
PORTAL_CSS = (
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}"
    ".container{max-width:60rem;margin:0 auto;padding:2rem}"
    "header{display:flex;flex-wrap:wrap;gap:1rem;justify-content:space-between;align-items:center;margin-bottom:2rem;padding-bottom:1rem;border-bottom:1px solid #1e293b}"
    "h1{font-size:1.5rem;color:#f1f5f9}h2{font-size:1.15rem;color:#f1f5f9;margin:0 0 .75rem}h3{font-size:1rem;color:#f1f5f9;margin-bottom:.25rem}"
    "section{margin-bottom:2rem}.user-badge{background:#1e293b;padding:.5rem 1rem;border-radius:.5rem;font-size:.875rem}"
    ".user-badge strong{color:#60a5fa}.muted{color:#94a3b8}"
    ".grid{list-style:none;display:grid;grid-template-columns:repeat(auto-fill,minmax(16rem,1fr));gap:1rem}"
    ".card{background:#1e293b;border-radius:.75rem;padding:1.25rem}.card p{color:#94a3b8;font-size:.875rem;margin:.25rem 0}"
    ".card .links{margin-top:.5rem;font-size:.9rem}.panel{background:#1e293b;border-radius:.75rem;padding:1.25rem 1.5rem}"
    ".plain{list-style:none}.plain li{padding:.3rem 0;border-bottom:1px solid #0f172a}.plain li:last-child{border-bottom:none}"
    "a{color:#60a5fa;text-decoration:none}a:hover{text-decoration:underline}"
    "a:focus-visible{outline:3px solid #f59e0b;outline-offset:2px;border-radius:.2rem}"
)
PORTAL_CSP = ("default-src 'none'; style-src 'sha256-"
              + base64.b64encode(hashlib.sha256(PORTAL_CSS.encode()).digest()).decode()
              + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def render_portal(user: str, groups: set, apps, domain: str, domains=()) -> bytes:
    e = lambda v: html.escape(str(v), quote=True)  # noqa: E731
    cards = []
    for a in apps or []:
        need = a.get("access_group") or ""
        if not isinstance(need, str) or (need and need not in groups) or need == DENY_GROUP:
            continue
        links = []
        for u in a.get("urls") or []:
            if not isinstance(u, dict):
                continue
            href = _safe_url(u.get("url"), domains)
            if href:
                links.append(f'<a href="{e(href)}">{e(u.get("label") or href)}</a>')
        # An entry with urls: [] and a note renders as a card with the note, no link (contract §10).
        note = a.get("note")
        has_note = isinstance(note, str) and note
        urls_value = a.get("urls")
        is_empty_urls = isinstance(urls_value, list) and len(urls_value) == 0
        if not links and not (is_empty_urls and has_note):
            continue
        icon = a.get("icon") if isinstance(a.get("icon"), str) else ""
        if links:
            content = f'<p>{e(a.get("description") or "")}</p><p class="links">{" · ".join(links)}</p>'
        else:
            # No links: show the note instead
            content = f'<p>{e(a.get("description") or "")}</p><p class="note">{e(note)}</p>'
        cards.append(
            f'<li class="card"><h3><span aria-hidden="true">{e(icon[:4])}</span> {e(a.get("name") or a.get("id") or "")}</h3>'
            f'{content}</li>')
    if apps is None:
        app_html = "<p class=\"muted\">The app list is not available yet.</p>"
    elif cards:
        app_html = "<ul class=\"grid\">" + "".join(cards) + "</ul>"
    else:
        app_html = "<p class=\"muted\">No apps are available to you yet.</p>"
    own = [("People (directory)", f"https://people.{domain}/"),
           ("My passkeys", f"https://auth.{domain}/realms/portcullis/account/account-security/signing-in"),
           ("My client certificate", f"https://enroll.{domain}/self")]
    admin = []
    if "lldap_admin" in groups:
        admin = [("Hub (apps, users &amp; marketplace)", f"https://hub.{domain}/"),
                 ("Keycloak (realm console)", f"https://auth.{domain}/admin/portcullis/console/"),
                 ("Certificates", f"https://enroll.{domain}/"),
                 ("Traefik", f"https://traefik.{domain}/")]
    def ul(items):
        return "<ul class=\"plain\">" + "".join(f'<li><a href="{e(u)}">{t}</a></li>' for t, u in items) + "</ul>"
    page = (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<meta name=\"color-scheme\" content=\"dark\">"
        f"<title>{e(domain)}</title><style>{PORTAL_CSS}</style></head><body><main class=\"container\">"
        f"<header><h1>{e(domain)}</h1><span class=\"user-badge\">Signed in as <strong>{e(user)}</strong></span></header>"
        f"<section><h2>Apps</h2>{app_html}</section>"
        + (f"<section class=\"panel\"><h2>Administration</h2>{ul(admin)}</section>" if admin else "")
        + f"<section class=\"panel\"><h2>Your account</h2>{ul(own)}</section></main></body></html>")
    return page.encode()


def load_policy_file() -> dict:
    """Return the Hub policy doc, {} if the file is absent (nothing
    published yet).

    Raises PolicyError if the file exists but fails validate_policy_doc()
    (not a JSON object, a `version` other than POLICY_VERSION — a missing
    one included —, a key that is not a valid hostname, a malformed
    `extra_domains`): a broken or foreign policy must not silently
    downgrade apps to "no policy". Callers must not modify the returned
    (cached) document.
    """
    doc, error = _read_policy_doc()
    if doc is None:
        return {}
    if error:
        raise PolicyError(error)
    return doc


def extra_domains(policy_doc: dict) -> List[str]:
    """The validated `extra_domains` of a loaded policy document."""
    return list(policy_doc.get("extra_domains") or []) if isinstance(policy_doc, dict) else []


def host_kind(host: str, extra: List[str]) -> Optional[str]:
    """"core", "extra" (extra-domain host), "main" (main-domain host), or
    None for a host Portcullis does not serve (contract §4 / §5).

    Core hosts first (they never move to an enrolled domain); then an
    enrolled domain <d> itself or <label>.<d> — which includes enrolled
    subdomains of the main domain; then <label>.<domain>.
    """
    if not DOMAIN_OK or not valid_hostname(host):
        return None
    if host in core_hosts():
        return "core"
    for d in extra:
        if host == d or (host.endswith("." + d) and LABEL_RE.fullmatch(host[: -len(d) - 1])):
            return "extra"
    if host.endswith("." + DOMAIN) and LABEL_RE.fullmatch(host[: -len(DOMAIN) - 1]):
        return "main"
    return None


# ── Temporary memberships (expiring, policy file v4) ─────────────────

_RFC3339_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})")
_EXPIRING_CACHE: dict = {"doc": None, "entries": None}
_EXPIRING_LOCK = threading.Lock()


def _parse_rfc3339(value) -> float:
    if not isinstance(value, str) or not _RFC3339_RE.fullmatch(value):
        raise ValueError("not an RFC 3339 timestamp with an offset")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    frac = re.search(r"\.(\d+)", text)
    if frac and len(frac.group(1)) > 6:  # datetime has microseconds only
        text = text.replace(frac.group(0), "." + frac.group(1)[:6])
    return datetime.datetime.fromisoformat(text).timestamp()


def expiring_entries(policy_doc: dict) -> List[Tuple[str, str, float]]:
    """[(lowercase user, group, at as epoch seconds)] of the `expiring`
    array; raises PolicyError if it is malformed (deny). Cached per parsed
    policy document."""
    with _EXPIRING_LOCK:
        if _EXPIRING_CACHE["doc"] is policy_doc and _EXPIRING_CACHE["entries"] is not None:
            return _EXPIRING_CACHE["entries"]
    raw = policy_doc.get("expiring") if isinstance(policy_doc, dict) else None
    entries = []
    if raw is not None:
        if not isinstance(raw, list):
            raise PolicyError("'expiring' is not a list")
        for e in raw:
            if not isinstance(e, dict) or set(e) != {"user", "group", "at"}:
                raise PolicyError("'expiring' entry is not {user, group, at}")
            user, group = e["user"], e["group"]
            if not isinstance(user, str) or not user.strip() or not isinstance(group, str) or not group.strip():
                raise PolicyError("'expiring' entry has an invalid user or group")
            try:
                at = _parse_rfc3339(e["at"])
            except ValueError as err:
                raise PolicyError(f"'expiring' entry has an invalid 'at' {e['at']!r}: {err}") from err
            entries.append((user.strip().lower(), group.strip(), at))
    with _EXPIRING_LOCK:
        _EXPIRING_CACHE.update(doc=policy_doc, entries=entries)
    return entries


def expired_groups(policy_doc: dict, username: str, now: Optional[float] = None) -> set:
    """Groups of `username` whose temporary membership has ended: absent
    once now >= at, whatever the token says (contract §4)."""
    now = time.time() if now is None else now
    user = username.strip().lower()
    return {g for u, g, at in expiring_entries(policy_doc) if u == user and now >= at}


# ── User attributes (user-attributes.json, contract §4.1 / §5) ───────

ATTRIBUTES_FILE = os.environ.get("GATE_ATTRIBUTES_FILE",
                                 os.path.join(os.path.dirname(POLICY_FILE), "user-attributes.json"))
ATTR_HEADER_PREFIX = "X-Forwarded-Attr-"
ATTR_VALUE_MAX = 1024  # bytes (UTF-8) per value; longer values are dropped
# Field names (contract §4.1): '_' only between letters/digits, <= 31 chars,
# so the header mapping is injective and always a valid header name.
# Always fullmatch(): "$" also matches before a trailing "\n".
_ATTR_FIELD_RE = re.compile(r"(?=.{1,31}\Z)[a-z][a-z0-9]*(_[a-z0-9]+)*")
_ATTR_HEADER_RE = re.compile(r"[A-Za-z0-9]+(-[A-Za-z0-9]+){0,30}")
_ATTR_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_ATTR_CACHE: dict = {"key": None, "users": {}, "hosts": {}, "declared": {}}
_ATTR_LOCK = threading.Lock()


class AttributesError(Exception):
    pass


def attr_encode(value: str) -> str:
    """Percent-encode the two characters that would make a joined header
    value ambiguous: `%` (first) and the `,` separator."""
    return value.replace("%", "%25").replace(",", "%2C")


def _attr_clean(value: str, what: str) -> str:
    """Control characters stripped; "" (logged) if the result is longer
    than ATTR_VALUE_MAX bytes (dropped, never truncated)."""
    value = _ATTR_CTRL_RE.sub("", value)
    n = len(value.encode("utf-8"))
    if n > ATTR_VALUE_MAX:
        print(f"group-gate: dropping {n}-byte value of {what} (limit {ATTR_VALUE_MAX})", flush=True)
        return ""
    return value


def parse_user_attributes(doc) -> Tuple[dict, dict, dict]:
    """(users, hosts, declared) from a version 2 user-attributes.json
    document: users = {lowercase user: [(header, value)]} (the field
    headers), hosts = {host: {lowercase user: [(header, value)]}} (per-host
    headers), declared = {host: {lowercase full header name}} (every valid
    header a host declares, with or without values: on that host it
    replaces the same-named field header for everybody).
    Raises AttributesError if the document is malformed or not version 2.

    Field values: control characters stripped, values longer than
    ATTR_VALUE_MAX bytes dropped (logged, never truncated), `%` -> `%25`
    and `,` -> `%2C` in every value (so "Doe, Jane" stays one value), then
    joined with ", ". Host values: one value each, control characters
    stripped, over ATTR_VALUE_MAX dropped (logged), sent verbatim (no `,`
    encoding)."""
    if not isinstance(doc, dict) or doc.get("version") != 2:
        raise AttributesError("not a version 2 document")
    fields, users, hosts = doc.get("fields", {}), doc.get("users", {}), doc.get("hosts", {})
    if not isinstance(fields, dict) or not isinstance(users, dict) or not isinstance(hosts, dict):
        raise AttributesError("'fields' / 'users' / 'hosts' is not an object")
    seen_headers = {}
    valid = {}
    for name, header in fields.items():
        if not _ATTR_FIELD_RE.fullmatch(name) or not isinstance(header, str) or not _ATTR_HEADER_RE.fullmatch(header):
            # One bad field doesn't cost every other field its header: it is
            # skipped (logged once per file version: the result is cached).
            print(f"group-gate: skipping invalid attribute field {name!r} -> {header!r} in {ATTRIBUTES_FILE}", flush=True)
            continue
        # Header names are case-insensitive: two fields on one header would
        # merge their values.
        other = seen_headers.setdefault(header.lower(), name)
        if other != name:
            raise AttributesError(f"fields {other!r} and {name!r} map to the same header {header!r}")
        valid[name] = header
    fields = valid
    out = {}
    for user, values in users.items():
        if not isinstance(values, dict):
            raise AttributesError(f"values of user {user!r} are not an object")
        headers = []
        for name, vals in values.items():
            if not isinstance(vals, list) or not all(isinstance(v, str) for v in vals):
                raise AttributesError(f"field {name!r} of user {user!r} is not a list of strings")
            if name not in fields:
                continue
            kept = []
            for v in vals:
                v = _attr_clean(v, f"field {name!r} for user {user!r}")
                if v:
                    kept.append(attr_encode(v))
            if kept:
                headers.append((ATTR_HEADER_PREFIX + fields[name], ", ".join(kept)))
        if headers:
            out[user.strip().lower()] = headers
    out_hosts, declared = {}, {}
    for host, by_header in hosts.items():
        if not isinstance(by_header, dict):
            raise AttributesError(f"headers of host {host!r} are not an object")
        # Keys are full lowercase hostnames, matched exactly against the
        # normalised request host: anything else could never match (or
        # could match the wrong host after normalising), so it is skipped.
        if not valid_hostname(host):
            print(f"group-gate: skipping attribute host {host!r} in {ATTRIBUTES_FILE} "
                  "(not a lowercase valid hostname)", flush=True)
            continue
        seen = {}
        per_user = {}
        for header, by_user in by_header.items():
            if not isinstance(by_user, dict) or not all(isinstance(v, str) for v in by_user.values()):
                raise AttributesError(f"header {header!r} of host {host!r} is not an object of strings")
            if not isinstance(header, str) or not _ATTR_HEADER_RE.fullmatch(header):
                print(f"group-gate: skipping invalid attribute header {header!r} of host {host!r} "
                      f"in {ATTRIBUTES_FILE}", flush=True)
                continue
            other = seen.setdefault(header.lower(), header)
            if other != header:
                raise AttributesError(f"host {host!r} has headers {other!r} and {header!r}")
            declared.setdefault(host, set()).add((ATTR_HEADER_PREFIX + header).lower())
            users_seen = set()
            for user, v in by_user.items():
                folded = user.strip().lower()
                # Two spellings of one user would give two values.
                if folded in users_seen:
                    raise AttributesError(f"header {header!r} of host {host!r} lists user {folded!r} twice")
                users_seen.add(folded)
                v = _attr_clean(v, f"header {header!r} of host {host!r} for user {user!r}")
                if v:
                    per_user.setdefault(folded, []).append((ATTR_HEADER_PREFIX + header, v))
        if per_user:
            out_hosts[host] = per_user
    return out, out_hosts, declared


def user_attribute_headers(username: str, host: str) -> List[Tuple[str, str]]:
    """Attribute headers for the user on the (normalised) host: the field
    headers, then the host's headers. A header the host declares replaces
    the same-named field header on that host for every user, also users
    without a (kept) value for it. A missing file means none; an unreadable or malformed one is
    logged (once per file version) and means none too — never a deny.
    Cached on (path, inode, mtime, size)."""
    try:
        st = os.stat(ATTRIBUTES_FILE)
    except FileNotFoundError:
        return []
    except OSError as e:
        print(f"group-gate: cannot read {ATTRIBUTES_FILE}: {e} (no attribute headers)", flush=True)
        return []
    key = (ATTRIBUTES_FILE, st.st_ino, st.st_mtime_ns, st.st_size)
    with _ATTR_LOCK:
        if _ATTR_CACHE["key"] != key:
            try:
                with open(ATTRIBUTES_FILE, encoding="utf-8") as f:
                    users, hosts, declared = parse_user_attributes(json.load(f))
            except FileNotFoundError:
                return []
            except (OSError, ValueError, AttributesError) as e:
                print(f"group-gate: ignoring corrupt {ATTRIBUTES_FILE}: {e} (no attribute headers)", flush=True)
                users, hosts, declared = {}, {}, {}
            _ATTR_CACHE.update(key=key, users=users, hosts=hosts, declared=declared)
        user = username.strip().lower()
        fields = _ATTR_CACHE["users"].get(user, [])
        on_host = _ATTR_CACHE["hosts"].get(host, {}).get(user, [])
        replaced = _ATTR_CACHE["declared"].get(host, set())
    return [h for h in fields if h[0].lower() not in replaced] + on_host


# ── Path rules (path_groups) ──────────────────────────────────────────


def _normalize_prefix(prefix: str) -> str:
    prefix = "/" + prefix.strip().lstrip("/")
    return prefix.rstrip("/") or "/"


def path_rules_for(policy_doc: dict, host: str) -> List[Tuple[str, str]]:
    """[(prefix, group)] for the host (exact key); raises PolicyError if
    malformed.

    Core hosts never take rules from the Hub file.
    """
    pg = policy_doc.get("path_groups") if isinstance(policy_doc, dict) else None
    if pg is None:
        return []
    if not isinstance(pg, dict):
        raise PolicyError("'path_groups' is not an object")
    rules_raw = pg.get(host)
    if rules_raw is None:
        return []
    if host in core_hosts():
        print(f"group-gate: ignoring policy-file path_groups for core host {host!r}", flush=True)
        return []
    if not isinstance(rules_raw, list):
        raise PolicyError(f"path_groups for {host!r} is not a list")
    rules = []
    for rule in rules_raw:
        if not isinstance(rule, dict):
            raise PolicyError(f"path_groups rule for {host!r} is not an object")
        prefix, group = rule.get("prefix"), rule.get("group")
        if not isinstance(prefix, str) or not prefix.strip().startswith("/"):
            raise PolicyError(f"path_groups rule for {host!r} has an invalid prefix {prefix!r}")
        if not isinstance(group, str) or not group.strip() or group.strip() == ANY_SIGNED_IN:
            raise PolicyError(f"path_groups rule for {host!r} has an invalid group {group!r}")
        if any(c in prefix for c in "%?#\\\x00") or "/./" in prefix + "/" or "/../" in prefix + "/":
            raise PolicyError(f"path_groups prefix {prefix!r} for {host!r} is not a normalised path")
        rules.append((_normalize_prefix(prefix), group.strip()))
    return rules


class PathError(Exception):
    """The request path is ambiguous (encoded slash / NUL) — deny."""


_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _resolve_dot_segments(path: str) -> str:
    """RFC 3986 remove_dot_segments on an absolute path, plus // collapsing."""
    out: List[str] = []
    segments = path.split("/")
    for seg in segments[1:]:
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    trailing = path.endswith("/") or segments[-1] in (".", "..")
    result = "/" + "/".join(out)
    if trailing and result != "/":
        result += "/"
    return result


def normalize_path_candidates(raw_uri: str) -> List[str]:
    """Normalised forms of X-Forwarded-Uri's path, for deny-biased matching.

    The primary form (contract §4): query stripped, percent-decoded ONCE, '//' collapsed, dot-segments resolved. Raises PathError if
    the decoded path still contains an encoded slash/backslash/NUL, or a NUL
    / control character — such paths mean different things to different
    backends, so they are denied outright. So is a '#' in the URI or an
    encoded one in the path (browsers never send fragments).

    Extra candidates cover how some backends read the same bytes
    differently: fully percent-decoded (double-decoding backends),
    backslash as separator, and ';' path parameters stripped (servlet
    containers). A rule applies if it matches ANY candidate.
    """
    uri = raw_uri or "/"
    if "#" in uri:
        # Browsers never send a fragment: a raw '#' means different things
        # to different parsers (some read what follows as query or path).
        raise PathError("'#' in the request URI")
    path = uri.split("?", 1)[0]
    if not path.startswith("/"):
        # Absolute-form ("http://h/p") or garbage: keep only the path part.
        m = re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*://[^/]*(/.*)?", path)
        path = (m.group(1) or "/") if m else "/" + path
    try:
        once = urllib.parse.unquote(path, errors="strict") if "%" in path else path
    except UnicodeDecodeError as e:
        raise PathError("path is not valid UTF-8 after decoding") from e
    if re.search(r"%(2[fF]|5[cC]|00)", once):
        raise PathError("encoded slash/backslash/NUL after decoding")
    if "#" in once:
        raise PathError("encoded '#' in the path")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in once):
        raise PathError("control character in path")
    forms = [once]
    full = once
    for _ in range(3):
        if not _PCT_RE.search(full):
            break
        full = urllib.parse.unquote(full)
    if any(ord(c) < 0x20 for c in full):
        raise PathError("control character after repeated decoding")
    forms.append(full)
    forms += [f.replace("\\", "/") for f in list(forms)]
    forms += [re.sub(r";[^/]*", "", f) for f in list(forms)]
    out: List[str] = []
    for f in forms:
        n = _resolve_dot_segments(f if f.startswith("/") else "/" + f)
        if n not in out:
            out.append(n)
    return out


def _prefix_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


def required_path_groups(rules: List[Tuple[str, str]], candidates: List[str]) -> List[str]:
    """Groups required by path rules: for every candidate path, matched both
    case-sensitively and case-insensitively, the group of the longest
    matching prefix. Several distinct groups → all are required."""
    needed: List[str] = []
    for path in candidates:
        for fold in (False, True):
            p = path.lower() if fold else path
            best = None
            for prefix, group in rules:
                pf = prefix.lower() if fold else prefix
                if _prefix_matches(p, pf) and (best is None or len(pf) > len(best[0])):
                    best = (pf, group)
            if best and best[1] not in needed:
                needed.append(best[1])
    return needed


# ── Public guard (public exceptions, /public-guard) ───────────────────
#
# The Hub's public router (portcullis-public-<app>, no forward-auth) runs
# portcullis-public-guard@docker first. The guard re-checks what Traefik's
# rule already restricts (defence in depth) and refuses any request that
# carries a credential the app would log a user in with: on these paths a
# stolen password, API key or session cookie must not get past the
# gateway's hardware-key requirement.

PUBLIC_MATCHES = ("prefix", "exact", "static")
PUBLIC_KEYS = {"paths", "token_pattern", "static_extensions", "credential_headers",
               "credential_cookies", "credential_query"}
ALWAYS_CREDENTIAL_HEADERS = ("authorization", "proxy-authorization")
_PUBLIC_TOKEN = "{token}"
_TOKEN_CHARS_RE = re.compile(r"[A-Za-z0-9._~-]{1,128}")
_PUBLIC_PATH_RE = re.compile(r"(/([A-Za-z0-9._~-]+|\{token\}))+")
_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_HEADER_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
_EXT_RE = re.compile(r"[a-z0-9]{1,8}")


class PublicConfig:
    def __init__(self, paths, token_re, exts, headers, cookies, query):
        self.paths = paths            # [(path, match)]
        self.token_re = token_re      # compiled or None
        self.exts = exts              # tuple of extensions
        self.headers = headers        # normalised header names (lower, '-')
        self.cookies = cookies        # php_var_name(...).lower() of each name
        self.query = query


def _str_list(entry: dict, key: str, rx, sub: str) -> List[str]:
    v = entry.get(key, [])
    if not isinstance(v, list) or not all(isinstance(x, str) and rx.fullmatch(x) for x in v):
        raise PolicyError(f"public_paths[{sub!r}].{key} is not a list of valid names")
    return v


def public_config_for(policy_doc: dict, host: str) -> Optional[PublicConfig]:
    """The host's public_paths entry, validated (None if absent; always
    None for a core host).

    Raises PolicyError for a file version other than PUBLIC_GUARD_VERSION or
    any malformed / unknown field: the guard then denies (fail closed).
    """
    version = policy_doc.get("version")
    if type(version) is not int or version != PUBLIC_GUARD_VERSION:
        raise PolicyError(f"public guard needs policy file version {PUBLIC_GUARD_VERSION}, got {version!r}")
    pp = policy_doc.get("public_paths")
    if pp is None:
        return None
    if not isinstance(pp, dict):
        raise PolicyError("'public_paths' is not an object")
    if host in core_hosts():
        return None
    entry = pp.get(host)
    if entry is None:
        return None
    if not isinstance(entry, dict):
        raise PolicyError(f"public_paths[{host!r}] is not an object")
    unknown = set(entry) - PUBLIC_KEYS
    if unknown:
        raise PolicyError(f"public_paths[{host!r}] has unknown keys {sorted(unknown)}")
    raw_paths = entry.get("paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        raise PolicyError(f"public_paths[{host!r}].paths is empty")
    paths = []
    has_token = False
    for p in raw_paths:
        if not isinstance(p, dict) or set(p) != {"path", "match"}:
            raise PolicyError(f"public_paths[{host!r}] has a malformed path entry {p!r}")
        path, match = p["path"], p["match"]
        if not isinstance(path, str) or not _PUBLIC_PATH_RE.fullmatch(path) or match not in PUBLIC_MATCHES:
            raise PolicyError(f"public_paths[{host!r}] has an invalid path {path!r} / match {match!r}")
        segs = path.split("/")[1:]
        if any(seg in (".", "..") or (".." in seg) for seg in segs) or segs.count(_PUBLIC_TOKEN) > 1 \
                or (match != "prefix" and _PUBLIC_TOKEN in segs):
            raise PolicyError(f"public_paths[{host!r}] has an invalid path {path!r}")
        has_token = has_token or _PUBLIC_TOKEN in segs
        paths.append((path, match))
    token_re = None
    pat = entry.get("token_pattern", "")
    if not isinstance(pat, str):
        raise PolicyError(f"public_paths[{host!r}].token_pattern is not a string")
    if has_token:
        if not (pat.startswith("^") and pat.endswith("$")):
            raise PolicyError(f"public_paths[{host!r}].token_pattern must be anchored")
        try:
            token_re = re.compile(pat)
        except re.error as e:
            raise PolicyError(f"public_paths[{host!r}].token_pattern: {e}") from e
    exts = tuple(_str_list(entry, "static_extensions", _EXT_RE, host))
    headers = {h.lower().replace("_", "-") for h in _str_list(entry, "credential_headers", _HEADER_NAME_RE, host)}
    headers.update(ALWAYS_CREDENTIAL_HEADERS)
    cookies = {php_var_name(n.encode()).lower() for n in _str_list(entry, "credential_cookies", _NAME_RE, host)}
    query = {php_var_name(n.encode()).lower() for n in _str_list(entry, "credential_query", _NAME_RE, host)}
    return PublicConfig(paths, token_re, exts, headers, cookies, query)


def php_var_name(name: bytes) -> bytes:
    """The variable name PHP stores a request field under.

    Port of php_register_variable_ex() (php-src main/php_variables.c,
    PHP-8.4): C-string (stops at NUL), leading spaces dropped, ' ' and '.'
    become '_' up to the first '['; a '[' with a matching ']' later starts
    an array, so the variable is the part before it (nc_token[] and
    nc_token[x] are $_COOKIE['nc_token']); a '[' without one becomes '_'
    and ' ', '.', '[' after it become '_' too.
    """
    name = name.split(b"\0", 1)[0].lstrip(b" ")
    out = bytearray()
    for i, c in enumerate(name):
        if c in (0x20, 0x2E):
            out.append(0x5F)
        elif c == 0x5B:
            rest = name[i + 1:]
            after = rest[1:] if rest[:1].isspace() else rest
            if b"]" in after:
                return bytes(out)
            out.append(0x5F)
            out.extend(0x5F if ch in (0x20, 0x2E, 0x5B) else ch for ch in rest)
            return bytes(out)
        else:
            out.append(c)
    return bytes(out)


class CredentialError(Exception):
    """The request carries something that may log a user in."""


def _name_candidates(raw: str, url_decoded: bool) -> List[bytes]:
    """Names an app may read a cookie / query key as: raw, and percent- /
    '+'-decoded (PHP url-decodes query keys, not cookie names; other
    stacks differ, so both are checked). Non-UTF-8 (incl. overlong forms)
    or control characters after decoding are refused outright."""
    forms = [raw.encode("utf-8", "surrogateescape")]
    forms.append(urllib.parse.unquote_to_bytes(raw.replace("+", " ")))
    out = []
    for f in forms:
        try:
            f.decode("utf-8", "strict")
        except UnicodeDecodeError as e:
            raise CredentialError(f"name {raw!r} is not valid UTF-8") from e
        if any(b < 0x20 or b == 0x7F for b in f):
            raise CredentialError(f"name {raw!r} contains control characters")
        out.append(php_var_name(f).lower())
        out.append(f.strip().lower())
    return out


def credential_problem(cfg: PublicConfig, headers, raw_uri: str) -> Optional[str]:
    """Why the request carries a credential, or None."""
    for name in headers.keys():
        if name.strip().lower().replace("_", "-") in cfg.headers:
            return f"credential header {name}"
    try:
        for cookie_header in headers.get_all("Cookie") or []:
            # PHP splits on ';' only; ',' too, for other parsers.
            for part in re.split(r"[;,]", cookie_header):
                name = part.split("=", 1)[0].lstrip(" \t\r\n\v\f")
                if not name:
                    continue
                if cfg.cookies & set(_name_candidates(name, False)):
                    return f"credential cookie {name!r}"
        query = raw_uri.split("?", 1)[1] if "?" in raw_uri else ""
        for part in re.split(r"[&;]", query):
            name = part.split("=", 1)[0]
            if not name:
                continue
            if cfg.query & set(_name_candidates(name, True)):
                return f"credential query parameter {name!r}"
    except CredentialError as e:
        return str(e)
    return None


def _static_ok(path: str, prefix: str, exts) -> bool:
    if not exts or not path.startswith(prefix + "/"):
        return False
    rest = path[len(prefix) + 1:].split("/")
    dirs, file = rest[:-1], rest[-1]
    if any(not re.fullmatch(r"[A-Za-z0-9_~@+-]+", d) for d in dirs):
        return False
    m = re.fullmatch(r"[A-Za-z0-9_~@+-][A-Za-z0-9._~@+-]*\.([A-Za-z0-9]+)", file)
    return bool(m) and m.group(1) in exts


def public_path_allowed(cfg: PublicConfig, path: str) -> bool:
    """Is a normalised path inside one of the published patterns? Same
    semantics as the Hub's router: prefix = segment boundary, exact = the
    path itself, static = files with a static extension below the prefix;
    {token} matches one segment the token_pattern accepts."""
    segs = path.split("/")[1:]
    for pattern, match in cfg.paths:
        if match == "static":
            if _static_ok(path, pattern, cfg.exts):
                return True
            continue
        psegs = pattern.split("/")[1:]
        if len(segs) < len(psegs) or (match == "exact" and len(segs) != len(psegs)):
            continue
        ok = True
        for ps, s in zip(psegs, segs):
            if ps == _PUBLIC_TOKEN:
                ok = bool(cfg.token_re and _TOKEN_CHARS_RE.fullmatch(s) and s not in (".", "..")
                          and cfg.token_re.fullmatch(s))
            else:
                ok = ps == s
            if not ok:
                break
        if ok:
            return True
    return False


def public_guard_check(policy_doc: dict, host: str, headers, raw_uri: str) -> Optional[str]:
    """None to allow the public request, else the reason to deny."""
    try:
        cfg = public_config_for(policy_doc, host)
    except PolicyError as e:
        return f"policy: {e}"
    if cfg is None:
        return "no public exception for this host"
    if "#" in (raw_uri or ""):
        return "path: '#' in the request URI"
    raw_path = (raw_uri or "").split("?", 1)[0]
    if re.search(r"%(2[fF]|5[cC]|00|23)", raw_path):
        # An encoded / \ NUL or # means different paths to Traefik and the app.
        return "path: encoded slash, backslash, NUL or '#'"
    try:
        candidates = normalize_path_candidates(raw_uri)
    except PathError as e:
        return f"path: {e}"
    outside = [c for c in candidates if not public_path_allowed(cfg, c)]
    if outside:
        return "path is not public"
    return credential_problem(cfg, headers, raw_uri)


_LOG_SEG_RE = re.compile(r"[A-Za-z0-9._~-]{1,40}")


def log_uri(raw_uri: str, cfg: Optional[PublicConfig] = None) -> str:
    """A request URI for logs: never share tokens, query values, cookies or
    credentials. The path is reduced to its segments, each masked as
    <token> when it sits where a published {token} does, matches the
    token_pattern, or looks like an opaque value (digits, or longer than 16
    characters); query parameters are logged by name only."""
    raw = raw_uri or ""
    path, _, query = raw.partition("?")
    try:
        path = urllib.parse.unquote(path.split("#", 1)[0])
    except Exception:  # noqa: BLE001 - logging must never fail
        path = "<undecodable>"
    token_slots = set()
    if cfg is not None:
        segs = path.split("/")[1:]
        for pattern, _match in cfg.paths:
            psegs = pattern.split("/")[1:]
            if "{token}" in psegs and len(segs) > psegs.index("{token}") \
                    and segs[:psegs.index("{token}")] == psegs[:psegs.index("{token}")]:
                token_slots.add(psegs.index("{token}"))
    out = []
    for i, seg in enumerate(path.split("/")[1:]):
        opaque = (i in token_slots or not _LOG_SEG_RE.fullmatch(seg) or len(seg) > 16
                  or re.search(r"\d", seg) is not None
                  or (cfg is not None and cfg.token_re is not None and cfg.token_re.fullmatch(seg) is not None and len(seg) >= 6))
        out.append("<token>" if opaque and seg else seg)
    logged = "/" + "/".join(out)
    if query:
        names = []
        for part in re.split(r"[&;]", query):
            name = part.split("=", 1)[0]
            if name:
                names.append(name if _LOG_SEG_RE.fullmatch(name) else "<name>")
        logged += "?" + "&".join(names[:20]) + ("&…" if len(names) > 20 else "")
    return logged


# ── Metrics (GET /metrics, Prometheus text format) ────────────────────


class Metrics:
    """Tiny thread-safe counter registry (no client library in the image)."""

    HELP = {
        "group_gate_requests_total": ("counter", "Forward-auth decisions by endpoint (gate|authenticated|public_guard) and result (allow|deny|stepup)."),
        "group_gate_denials_total": ("counter", "Denied requests by reason."),
        "group_gate_stepups_total": ("counter", "Step-up (re-authentication) answers by reason."),
        "group_gate_policy_load_errors_total": ("counter", "Requests denied because the Hub policy file or a policy in it is invalid."),
        "group_gate_crl_fetch_failures_total": ("counter", "Failed CRL fetches (the last good CRL is kept)."),
    }

    def __init__(self):
        self._lock = threading.Lock()
        self._values: dict = {}

    def inc(self, name: str, **labels):
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._values[key] = self._values.get(key, 0) + 1

    def get(self, name: str, **labels) -> float:
        with self._lock:
            return self._values.get((name, tuple(sorted(labels.items()))), 0)

    @staticmethod
    def _fmt(name: str, labels, value) -> str:
        if labels:
            inner = ",".join(f'{k}="{str(v).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'
                             for k, v in labels)
            name = f"{name}{{{inner}}}"
        value = float(value)
        return f"{name} {int(value) if value.is_integer() else repr(value)}"

    def render(self) -> str:
        lines: List[str] = []
        with self._lock:
            values = dict(self._values)
        for name, (mtype, help_text) in self.HELP.items():
            lines += [f"# HELP {name} {help_text}", f"# TYPE {name} {mtype}"]
            series = sorted((k[1], v) for k, v in values.items() if k[0] == name)
            if not series and mtype == "counter" and name in ("group_gate_policy_load_errors_total",
                                                               "group_gate_crl_fetch_failures_total"):
                series = [((), 0)]
            lines += [self._fmt(name, labels, v) for labels, v in series]
        crl = CRL_CACHE
        gauges = [
            ("group_gate_crl_enabled", "1 if revocation is also checked against Vault's CRL.", 1 if crl else 0),
        ]
        if crl is not None:
            gauges += [
                ("group_gate_crl_last_success_timestamp_seconds", "Unix time of the last successful CRL fetch, oldest of full and delta CRL (0 = never).", crl.last_success),
                ("group_gate_crl_next_update_timestamp_seconds", "Earliest nextUpdate of the cached full / delta CRL (0 = unknown).", crl.next_update or 0),
                ("group_gate_crl_revoked_serials", "Revoked serials in the cached CRLs (full + delta, deduplicated).", len(crl.serials)),
            ]
        try:
            file_serials = float(len(load_revoked_file()))
        except RevocationError:
            file_serials = -1.0
        gauges.append(("group_gate_revoked_file_serials", "Serials in the revoked-serials file (-1 = unreadable: cert requests are denied).", file_serials))
        for name, help_text, value in gauges:
            lines += [f"# HELP {name} {help_text}", f"# TYPE {name} gauge", self._fmt(name, (), value)]
        return "\n".join(lines) + "\n"


METRICS = Metrics()


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


def parse_crl_serials(data: bytes) -> FrozenSet[int]:
    """Revoked serial numbers from an X.509 CRL (DER, or PEM)."""
    return parse_crl(data)[0]


def parse_crl(data: bytes) -> Tuple[FrozenSet[int], Optional[float]]:
    """(revoked serial numbers, nextUpdate epoch or None) from an X.509 CRL
    (DER, or PEM). Malformed input raises ValueError.

    The CRL signature is not verified: it is fetched from Vault over the
    internal network, and it can only ever ADD denials.
    """
    stripped = data.lstrip()
    if stripped.startswith(b"-----BEGIN"):
        crl = x509.load_pem_x509_crl(stripped)
    else:
        crl = x509.load_der_x509_crl(data)
    next_update = crl.next_update_utc
    return (frozenset(entry.serial_number for entry in crl),
            next_update.timestamp() if next_update else None)


class CrlSource:
    """One CRL URL: last good serials / nextUpdate, kept across fetch errors."""

    def __init__(self, url: str):
        self.url = url
        self.serials: FrozenSet[int] = frozenset()
        self.last_error: Optional[str] = None
        self.last_success: float = 0.0      # epoch of the last good fetch (0 = never)
        self.next_update: Optional[float] = None  # the CRL's own nextUpdate

    def refresh(self) -> bool:
        try:
            with urllib.request.urlopen(self.url, timeout=5) as resp:
                data = resp.read(16 * 1024 * 1024)
            serials, next_update = parse_crl(data)
        except Exception as e:  # noqa: BLE001 — any failure keeps the last good CRL
            METRICS.inc("group_gate_crl_fetch_failures_total")
            err = f"{type(e).__name__}: {e}"
            if err != self.last_error:
                print(f"group-gate: CRL fetch from {self.url} failed ({err}); keeping last good list "
                      f"({len(self.serials)} serials)", flush=True)
            self.last_error = err
            return False
        if serials != self.serials or self.last_error:
            print(f"group-gate: CRL loaded from {self.url}: {len(serials)} revoked serial(s)", flush=True)
        self.serials = serials
        self.next_update = next_update
        self.last_success = time.time()
        self.last_error = None
        return True


class CrlCache:
    """Background-refreshed revoked serials from Vault's CRLs.

    Vault (pki_int/config/crl auto_rebuild=true) does NOT rebuild the full
    CRL on revoke: new revocations appear in the delta CRL (enable_delta,
    rebuilt about once a minute) until the next full rebuild, which then
    clears the delta. So both are fetched and the union is enforced.

    Order: delta first, then full. A full rebuild between the two fetches
    can then only move a serial from the (already fetched) delta into the
    (about to be fetched) full CRL — never out of both.

    Freshness for /metrics is the WORST of the sources: oldest successful
    fetch, earliest nextUpdate.
    """

    def __init__(self, url: str, interval: float, delta_url: str = ""):
        self.sources = ([CrlSource(delta_url)] if delta_url else []) + [CrlSource(url)]
        self.url = url
        self.interval = max(interval, 1.0)

    @property
    def serials(self) -> FrozenSet[int]:
        out: FrozenSet[int] = frozenset()
        for src in self.sources:
            out = out | src.serials
        return out

    @property
    def last_success(self) -> float:
        return min(src.last_success for src in self.sources)

    @property
    def next_update(self) -> Optional[float]:
        known = [src.next_update for src in self.sources if src.next_update]
        return min(known) if known else None

    def refresh(self) -> bool:
        results = [src.refresh() for src in self.sources]
        return all(results)

    def run_forever(self):
        while True:
            self.refresh()
            time.sleep(self.interval)


CRL_CACHE: Optional[CrlCache] = (CrlCache(CRL_URL, CRL_REFRESH_SECONDS, DELTA_CRL_URL)
                                 if CRL_URL else None)


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
    return [int(m) for m in _SERIAL_RE.findall(_decode_cert_info(raw))]


_SUBJECT_RE = re.compile(r'Subject="([^"]*)"')


def _decode_cert_info(raw: str) -> str:
    value = raw or ""
    for _ in range(3):
        decoded = urllib.parse.unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def leaf_cert_cn(raw: str) -> Optional[str]:
    """Subject CN of the leaf (first) cert in X-Forwarded-Tls-Client-Cert-Info.

    This header is Traefik's own text format (Subject="C=..,O=..,CN=..",
    values unescaped — not RFC 4514), not a certificate: client-headers@file
    sends no PEM, so there is nothing for an X.509 parser to load here.
    """
    value = _decode_cert_info(raw)
    m = _SUBJECT_RE.search(value)
    if not m:
        return None
    for attr in m.group(1).split(","):
        attr = attr.strip()
        if attr.startswith("CN="):
            return attr[3:]
    return None


_PORT_RE = re.compile(r":[0-9]{1,5}\Z")


def normalize_host(raw: str) -> str:
    """First X-Forwarded-Host value, lowercased, a numeric :<port> and
    trailing dots stripped (contract §4: `Grafana-A.Team-A.com.:443` ->
    `grafana-a.team-a.com`). The result still has to pass valid_hostname():
    an IPv6 literal, a non-numeric port, userinfo, a wildcard... do not."""
    host = (raw or "").split(",")[0].strip().lower()
    host = _PORT_RE.sub("", host)
    return host.rstrip(".")


def decode_jwt_payload(token: str) -> dict:
    """Claims of a JWT, WITHOUT verifying its signature (or exp/aud/iss).

    The token has already been verified by oauth2-proxy upstream — we're
    inside the trust boundary and only need the claims. Anything that is not
    a well-formed JWT with a JSON-object payload gives {} (no claims: the
    auth policy then fails closed).
    """
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return {}
    return claims if isinstance(claims, dict) else {}


def resolve_policy(policy_doc: dict, host: str) -> Optional[dict]:
    """Return {factors, op} for this host (exact key; a core host never
    takes one from the file), or the default, or None if no policy is
    configured."""
    if not policy_doc:
        return None
    policies = policy_doc.get("policies") or {}
    if not isinstance(policies, dict):
        raise PolicyError("'policies' is not an object")
    if host in policies and host not in core_hosts():
        policy = policies[host]
        if not isinstance(policy, dict):
            raise PolicyError(f"policy for {host!r} is not an object")
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


def policy_relies_on_mtls(policy: dict, amr: list) -> bool:
    """True if the (already satisfied) policy is satisfied only through the
    mtls factor: `all` with mtls in it, or `any` where mtls is the only
    required factor present in amr."""
    factors = list(policy.get("factors") or [])
    if "mtls" not in factors:
        return False
    op = (policy.get("op") or "").lower() or ("any" if len(factors) > 1 else "")
    if op == "all" or len(factors) == 1:
        return True
    amr_set = set(amr or [])
    others = {FACTOR_TO_AMR[f] for f in factors if f != "mtls"}
    return not (amr_set & others)


def stepup_url(host: str, needed_loa: int, factors: list, extra: bool = False) -> str:
    """Build a step-up URL that asks oauth2-proxy for a fresh login at the
    required Level of Authentication (contract §5 "Step-up URL").

    We pass `acr_values=<acr>` to /oauth2/start, which oauth2-proxy forwards
    to Keycloak's authorize endpoint. No `prompt=login`: Keycloak's cookie
    authenticator already runs the flow when the requested LoA is above the
    session's (LoA step-up), and then asks only for the levels not reached
    yet — a full re-authentication would ask again for factors the session
    already has.

    Main-domain and core hosts: on auth.<domain> (router oauth2-callback,
    forward-auth), never on the app's own host — a host-less
    PathPrefix(`/oauth2/`) router cannot carry the tiers' TLS options, so
    Traefik would serve it with the default options and answer 421
    Misdirected Request. oauth2-proxy's cookie is set for .<domain> and
    `rd` is in its whitelist, so the user lands back on the app.

    Extra-domain hosts (`extra`): on the host itself, served by
    forward-auth-ext through the Hub's Host-scoped sign-in router
    (portcullis-oauth2-<instance>_<router>); `rd=/` is relative, so it
    needs no whitelist and can only land on the same host.

    No sign_out in the chain: the browser still has oauth2-proxy's cookie
    but we want Keycloak to issue a *new* token reflecting the step-up, not
    to delete the old session.
    """
    loa_to_acr = {0: "public", 1: "pwd", 2: "hwk", 3: "mtls"}
    acr = loa_to_acr.get(needed_loa, "pwd")
    if extra:
        return f"https://{host}/oauth2/start?" + urllib.parse.urlencode({"acr_values": acr, "rd": "/"})
    query = urllib.parse.urlencode({"acr_values": acr, "rd": f"https://{host}/"})
    return f"https://auth.{DOMAIN}/oauth2/start?{query}"


def safe_factor_name(amr: str) -> str:
    for factor, amr_value in FACTOR_TO_AMR.items():
        if amr_value == amr:
            return factor
    return amr


# The one header the signed-in username is read from: set by oauth2-proxy
# (portcullis-auth, injectResponseHeaders in alpha.yaml) from the ID token's
# preferred_username = the LLDAP username. oauth2-proxy's own session "user"
# is the token's `sub` (Keycloak's internal user UUID) and can't be
# configured (alpha `userIDClaim` is a deprecated alias of `emailClaim`),
# so neither it nor the email is ever used as the identity.
USERNAME_HEADER = "X-Auth-Request-Preferred-Username"


def session_username(req_headers) -> str:
    """The signed-in LLDAP username, or '' if portcullis-auth did not set one."""
    return (req_headers.get(USERNAME_HEADER, "") or "").strip()


# Token headers portcullis-auth sets and portcullis-groups lists in its
# authResponseHeaders: echoed unchanged on allow (apps keep the token, the
# Keycloak console keeps its own bearer: portcullis-auth-console leaves
# Authorization alone), OMITTED when an expired membership was stripped —
# the token still carries the expired group, so Traefik must drop it.
TOKEN_HEADERS = ("Authorization", "X-Forwarded-Access-Token")


def identity_headers(req_headers, groups: Optional[str] = None, omit_tokens: bool = False) -> dict:
    """Identity headers group-gate returns on ALLOW (Traefik copies them onto
    the upstream request: they are this middleware's authResponseHeaders, so
    Traefik first deletes any client-supplied copies).

    X-Forwarded-User / X-Auth-Request-User are the LLDAP username (see
    USERNAME_HEADER) and NEVER the email or Keycloak's user id: LLDAP lets
    users edit their own mail, so an email-keyed identity could be taken
    over. The email travels separately in X-Forwarded-Email for display /
    notifications only.
    """
    out = {}
    user = session_username(req_headers)
    email = (req_headers.get("X-Auth-Request-Email", "") or "").strip()
    if groups is None:
        groups = req_headers.get("X-Auth-Request-Groups", "") or ""
    if user:
        out["X-Forwarded-User"] = user
        out["X-Auth-Request-User"] = user
        out[USERNAME_HEADER] = user
    if email:
        out["X-Forwarded-Email"] = email
        out["X-Auth-Request-Email"] = email
    # Traefik's forwardAuth deletes every authResponseHeaders entry from the
    # upstream request and only re-adds those present in OUR response: echo
    # the groups oauth2-proxy set (portcullis-auth runs first) so backends
    # like enroll still see them — minus expired temporary memberships
    # (the caller passes the filtered list).
    if groups:
        out["X-Auth-Request-Groups"] = groups
    if not omit_tokens:
        for name in TOKEN_HEADERS:
            value = req_headers.get(name)
            if value:
                out[name] = value
    return out


class Handler(BaseHTTPRequestHandler):
    def _deny(self, title: str, body_html: str, log: str, reason: str,
              extra_headers: Optional[dict] = None):
        METRICS.inc("group_gate_requests_total", endpoint=self._endpoint, result="deny")
        METRICS.inc("group_gate_denials_total", reason=reason)
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(f"<h1>{html.escape(title)}</h1>{body_html}".encode())
        print(f"group-gate: {log}", flush=True)

    def _allow(self, groups_header: Optional[str] = None, username: str = "", host: str = ""):
        METRICS.inc("group_gate_requests_total", endpoint=self._endpoint, result="allow")
        self.send_response(200)
        # groups_header is set only when expired memberships were stripped.
        for name, value in identity_headers(self.headers, groups_header,
                                            omit_tokens=groups_header is not None).items():
            self.send_header(name, value)
        # Attribute headers (contract §5): only on allow; Traefik forwards
        # them through authResponseHeadersRegex ^X-Forwarded-Attr- (which
        # also deletes client-sent copies). Values go out as UTF-8 bytes.
        # `host` is the normalised request host (per-host headers, §4.1).
        for name, value in user_attribute_headers(username, host) if username else []:
            self.send_header(name, value.encode("utf-8").decode("latin-1"))
        self.end_headers()

    def _deny_policy(self, user: str, host: str, reason: str):
        METRICS.inc("group_gate_policy_load_errors_total")
        self._deny(
            "Access Denied",
            "<p>The access policy for this app is misconfigured, so access is denied. "
            "Ask an administrator to fix it in the Hub.</p>",
            f"DENIED user={user} host={host} reason=malformed policy: {reason}",
            "policy_error",
        )

    def _stepup(self, host: str, kind: str, user: str, policy: dict, required_loa: int,
                acr: str, amr: list, reason: str, detail_html: str = "", metric_reason: str = "policy"):
        METRICS.inc("group_gate_requests_total", endpoint=self._endpoint, result="stepup")
        METRICS.inc("group_gate_stepups_total", reason=metric_reason)
        url = stepup_url(host, required_loa, policy.get("factors") or [], extra=kind == "extra")
        e_url = html.escape(url, quote=True)
        e_host = html.escape(host)
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Stepup-URL", url)
        self.end_headers()
        factors = policy.get("factors") or []
        op = policy.get("op") or "any"
        have = ", ".join(safe_factor_name(str(a)) for a in amr) or "none"
        need_desc = f"{op} of: {', '.join(factors)}" if len(factors) > 1 else factors[0] if factors else "authentication"
        # A hardware factor (passkey / client cert) may be one the user
        # does not have yet: no auto-redirect then (it would bounce them
        # straight back into a sign-in they cannot complete), but a
        # Continue button and, right next to it, how to enrol. Users who
        # have no passkey yet finish the step-up at LoA 1, so they land
        # here again until they register one.
        needs_hardware = any(f in ("mtls", "webauthn") for f in factors)
        parent = DOMAIN  # passkeys and certificates are managed on the main domain only
        enrol = []
        if parent and "webauthn" in factors:
            account_url = f"https://auth.{parent}/realms/portcullis/account/account-security/signing-in"
            enrol.append(
                f"<a href=\"{html.escape(account_url, quote=True)}\" target=\"_blank\" rel=\"noopener\">"
                "Register a passkey in the account console</a> (Signing in &rarr; Passkey &rarr; Set up)")
        if parent and "mtls" in factors:
            enrol.append(
                f"<a href=\"{html.escape(f'https://enroll.{parent}/', quote=True)}\" target=\"_blank\" rel=\"noopener\">"
                "Enrol a client certificate</a>")
        enrollment_block = ""
        if needs_hardware and enrol:
            enrollment_block = (
                "<section aria-labelledby=\"enrol-h\" style=\"background:#fff7ed;border:1px solid #fed7aa;"
                "padding:.75rem 1rem;border-radius:.5rem;margin-top:1.5rem\">"
                "<h2 id=\"enrol-h\" style=\"font-size:1.05rem;margin:0 0 .4rem\">No hardware key registered yet?</h2>"
                f"<p style=\"margin:0\">{' or '.join(enrol)}, then come back and press <b>Continue</b>.</p>"
                "</section>"
            )
        if not detail_html:
            detail_html = (f"<p><b>{e_host}</b> requires {html.escape(need_desc)}. "
                           f"Your current session was authenticated with <code>{html.escape(have)}</code>, "
                           "which does not satisfy the app's policy.</p>")
        if needs_hardware:
            refresh = ""
            action = (f"<p><a id=\"stepup-continue\" class=\"btn\" href=\"{e_url}\" autofocus>Continue</a> "
                      "to sign in again with the required factor.</p>")
        else:
            # Nothing to enrol: bump the user through the fresh authorize
            # flow after 2 seconds; the link is the accessible fallback.
            refresh = f"<meta http-equiv=\"refresh\" content=\"2;url={e_url}\">"
            action = (f"<p>You will be redirected to re-authenticate in a moment. "
                      f"If nothing happens, <a id=\"stepup-continue\" href=\"{e_url}\">click here</a>.</p>")
        self.wfile.write(
            (
                "<!doctype html><html lang=\"en\"><head>"
                f"{refresh}"
                "<title>Additional authentication required</title>"
                "<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:32rem;"
                "margin:4rem auto;padding:2rem;color:#1e293b;line-height:1.55}"
                "h1{font-size:1.5rem;margin:0 0 1rem}"
                "code{background:#f1f5f9;padding:.15rem .4rem;border-radius:.25rem;font-size:.95em}"
                "a{color:#1d4ed8}"
                ".btn{display:inline-block;background:#1d4ed8;color:#fff;padding:.55rem 1.25rem;"
                "border-radius:.4rem;text-decoration:none;font-weight:600}"
                ".btn:focus-visible{outline:3px solid #f59e0b;outline-offset:2px}</style></head><body>"
                "<main><h1>Additional authentication required</h1>"
                f"{detail_html}"
                f"{action}"
                f"{enrollment_block}"
                "</main></body></html>"
            ).encode()
        )
        print(
            f"group-gate: STEPUP user={user} host={host} policy={policy} "
            f"acr={acr!r} amr={amr} reason={reason!r}",
            flush=True,
        )

    _endpoint = "gate"

    def _portal(self):
        """Landing page at https://<domain>/ (router `portal`: portcullis-auth,
        then replacePath /portal). Lists the apps of portal-apps.json the
        user's groups allow (contract §10) and, for lldap_admin, the core
        consoles. Identity headers come from forward-auth's authResponseHeaders."""
        user = session_username(self.headers)
        groups = {g.strip() for g in self.headers.get("X-Auth-Request-Groups", "").split(",") if g.strip()}
        if not user:
            self._deny("Access Denied", "<p>Not signed in.</p>", "DENIED portal reason=no username", "no_user")
            return
        try:
            groups -= expired_groups(load_policy_file(), user)
        except PolicyError as e:
            # Only a listing (every app enforces access itself): show the
            # signed-in user nothing group-based rather than deny the page.
            print(f"group-gate: portal user={user} lists no apps: malformed policy: {e}", flush=True)
            groups = set()
        if user.lower() in DENY_USERS:
            self._deny("Access Denied", "<p>This account is a service account and cannot sign in.</p>",
                       f"DENIED portal user={user} reason=service account", "service_account")
            return
        METRICS.inc("group_gate_requests_total", endpoint="portal", result="allow")
        apps, domains = load_portal_apps()
        body = render_portal(user, groups, apps, DOMAIN, domains)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", PORTAL_CSP)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _public_guard(self):
        raw_host = self.headers.get("X-Forwarded-Host", "")
        host = normalize_host(raw_host)
        raw_uri = self.headers.get("X-Forwarded-Uri", "")
        cfg = None
        try:
            doc = load_policy_file()
        except PolicyError as e:
            doc = None
            reason = f"policy: {e}"
        if doc is not None:
            kind = host_kind(host, extra_domains(doc))
            if kind in ("main", "extra"):
                reason = public_guard_check(doc, host, self.headers, raw_uri)
                try:
                    cfg = public_config_for(doc, host)
                except PolicyError:
                    cfg = None
            else:
                reason = "core host" if kind == "core" else "host not served by Portcullis"
        if reason:
            self._deny(
                "Access Denied",
                "<p>This public link can't be opened with these request details. If you are "
                "signed in to the app in this browser, open the link in a private window.</p>",
                f"DENIED public host={raw_host!r} uri={log_uri(raw_uri, cfg)!r} reason={reason}",
                "public_guard",
            )
            return
        METRICS.inc("group_gate_requests_total", endpoint=self._endpoint, result="allow")
        # No identity headers: nobody is signed in on a public path.
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        gate_path = urllib.parse.urlsplit(self.path).path
        if gate_path == "/metrics":
            body = METRICS.render().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if gate_path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        if gate_path == "/portal":
            self._endpoint = "portal"
            self._portal()
            return
        if gate_path == "/public-guard":
            self._endpoint = "public_guard"
            self._public_guard()
            return
        # /authenticated: any authenticated user, no host group check.
        authenticated_only = gate_path == "/authenticated" or gate_path.startswith("/authenticated/")
        self._endpoint = "authenticated" if authenticated_only else "gate"

        raw_host = self.headers.get("X-Forwarded-Host", "")
        host = normalize_host(raw_host)
        username = session_username(self.headers)
        user = username or "unknown"  # for logs / pages only
        e_user = html.escape(user)

        if not valid_hostname(host) or not DOMAIN_OK:
            self._deny(
                "Access Denied",
                "<p>Unrecognised host.</p>",
                f"DENIED user={user} host={raw_host!r} reason=not a valid hostname"
                + ("" if DOMAIN_OK else f" (PORTCULLIS_DOMAIN={DOMAIN!r} is not a valid hostname)"),
                "host",
            )
            return
        e_host = html.escape(host)

        groups_raw = self.headers.get("X-Auth-Request-Groups", "")
        groups = {g.strip() for g in groups_raw.split(",") if g.strip()}
        if DENY_GROUP in groups:
            self._deny(
                "Access Denied",
                "<p>Your account carries a reserved group name. Ask an administrator to remove it.</p>",
                f"DENIED user={user} host={host} reason=user claims reserved group {DENY_GROUP!r}",
                "reserved_group",
            )
            return

        # --- Client-cert revocation (before anything else) ---
        cert_info = self.headers.get(CERT_INFO_HEADER, "")
        cert_serials: List[int] = []
        if cert_info:
            cert_serials = cert_serials_from_info(cert_info)
            if not cert_serials:
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
                        "revocation_unavailable",
                    )
                    return
                hit = [sn for sn in cert_serials if sn in revoked]
                if hit:
                    self._deny(
                        "Access Denied",
                        "<p>Your client certificate has been <b>revoked</b>. "
                        "Ask an administrator to re-enroll your security key.</p>",
                        f"DENIED user={user} host={host} reason=revoked client cert serial={format_serial(hit[0])}",
                        "revoked_cert",
                    )
                    return

        # --- Identity: every route needs the username portcullis-auth sets.
        # Missing = the router lacks portcullis-auth@docker (or oauth2-proxy
        # did not get preferred_username): deny instead of falling back to
        # the email / Keycloak user id or letting the request through
        # anonymously. Runs after the revocation check, which never depends
        # on who the user is.
        if not username:
            self._deny("Access Denied", "<p>Not signed in.</p>",
                       f"DENIED host={host} reason=no {USERNAME_HEADER} "
                       f"(router without portcullis-auth@docker?)",
                       "unauthenticated")
            return
        if username.lower() in DENY_USERS:
            self._deny("Access Denied", "<p>This account is a service account and cannot sign in.</p>",
                       f"DENIED user={user} host={host} reason=service account", "service_account")
            return

        # Per-request reload — the Hub rewrites the policy file on each
        # change, and both files are tiny.
        try:
            policy_doc = load_policy_file()
            kind = host_kind(host, extra_domains(policy_doc))
            gate = build_group_map(policy_doc)
            policy = resolve_policy(policy_doc, host)
            policy_err = validate_policy(policy) if policy else None
            path_rules = path_rules_for(policy_doc, host)
            expired = expired_groups(policy_doc, username)
        except PolicyError as e:
            self._deny_policy(user, host, str(e))
            return
        if policy_err:
            self._deny_policy(user, host, policy_err)
            return
        if kind is None:
            # Neither a core host, nor <label>.<domain>, nor on an enrolled
            # domain: not served by Portcullis (contract §4, §11.3).
            self._deny(
                "Access Denied",
                "<p>Unrecognised host.</p>",
                f"DENIED user={user} host={raw_host!r} reason=host not served by Portcullis "
                f"(domain={DOMAIN!r}, extra_domains={extra_domains(policy_doc)})",
                "host",
            )
            return

        # --- Temporary memberships: an expired one is absent, whatever the
        # token says, for every check below and in X-Auth-Request-Groups.
        groups_header = None
        if expired & groups:
            groups -= expired
            groups_header = ",".join(g for g in (x.strip() for x in groups_raw.split(",")) if g and g in groups)
            print(f"group-gate: user={user} expired memberships ignored: {sorted(expired)} "
                  f"(token headers withheld)", flush=True)

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
                self._stepup(host, kind, user, policy, required_loa, acr, amr, reason)
                return

            # --- mTLS binding: amr=mtls is only as good as the cert used NOW ---
            if policy_relies_on_mtls(policy, amr):
                # The cert must belong to the same user apps are told about
                # (X-Forwarded-User = username); the token, from the same
                # session, must agree.
                token_user = claims.get("preferred_username")
                cert_cn = leaf_cert_cn(cert_info) if cert_info else None
                problem = None
                if not cert_info or not cert_serials:
                    problem = "no client certificate on this request"
                elif token_user != username:
                    problem = f"token preferred_username {token_user!r} != session user {username!r}"
                elif cert_cn is None or cert_cn != username:
                    problem = f"client cert CN {cert_cn!r} != session user {username!r}"
                if problem:
                    self._stepup(
                        host, kind, user, policy, FACTOR_TO_LOA["mtls"], acr, amr,
                        f"mtls binding: {problem}",
                        "<p><b>" + e_host + "</b> requires your client certificate (security key) on "
                        "every request, and it must belong to the signed-in user. Insert your "
                        "security key, select its certificate when the browser asks, and sign in again.</p>",
                        metric_reason="mtls_binding",
                    )
                    return

        # --- Group check ---
        if not authenticated_only:
            required_group = gate.get(host)
            if required_group == DENY_GROUP:
                self._deny(
                    "Access Denied",
                    f"<p>The configuration of <b>{e_host}</b> is unavailable, so access is denied. "
                    "Ask an administrator to check the app in the Hub.</p>",
                    f"DENIED user={user} host={host} reason=app configuration unavailable ({DENY_GROUP})",
                    "app_unavailable",
                )
                return
            if required_group == ANY_SIGNED_IN:
                pass  # map.conf only (people.<domain>): any signed-in user
            elif not required_group:
                print(f"group-gate: ALLOW-UNMAPPED user={user} host={host} (no group mapping for {host!r})", flush=True)
            elif required_group not in groups:
                self._deny(
                    "Access Denied",
                    f"<p>User <b>{e_user}</b> is not authorized to access <b>{e_host}</b>.</p>"
                    f"<p>Required group: <code>{html.escape(required_group)}</code></p>",
                    f"DENIED user={user} host={host} need={required_group} have={sorted(groups)}",
                    "group",
                )
                return

        # --- Path groups (in addition to the host's group) ---
        if path_rules:
            raw_uri = self.headers.get("X-Forwarded-Uri", "")
            try:
                candidates = normalize_path_candidates(raw_uri)
            except PathError as e:
                self._deny(
                    "Access Denied",
                    "<p>The request path is not acceptable.</p>",
                    f"DENIED user={user} host={host} uri={log_uri(raw_uri)!r} reason=path: {e}",
                    "path_invalid",
                )
                return
            for need in required_path_groups(path_rules, candidates):
                if need == DENY_GROUP or need not in groups:
                    self._deny(
                        "Access Denied",
                        f"<p>User <b>{e_user}</b> is not authorized to access this part of <b>{e_host}</b>.</p>"
                        f"<p>Required group: <code>{html.escape(need)}</code></p>",
                        f"DENIED user={user} host={host} path={log_uri(candidates[0])!r} need={need} have={sorted(groups)}",
                        "path_group",
                    )
                    return

        self._allow(groups_header, username, host)

    def log_message(self, fmt, *args):
        # Default per-request logs are noisy; explicit logging above.
        pass


if __name__ == "__main__":
    if not DOMAIN_OK:
        # Required (contract §4): without it no host can be classified.
        raise SystemExit(f"group-gate: PORTCULLIS_DOMAIN={DOMAIN!r} is not a valid hostname — refusing to start")
    print(
        f"group-gate: listening on :{LISTEN_PORT}, policy_file={POLICY_FILE}, "
        f"map_file={MAP_FILE}, domain={DOMAIN}",
        flush=True,
    )
    print(f"group-gate: static group mappings: {load_static_map()}", flush=True)
    print(f"group-gate: revocation: file={REVOKED_FILE} crl={CRL_URL or '(disabled)'} "
          f"delta={DELTA_CRL_URL or '(none)'} refresh={CRL_REFRESH_SECONDS:g}s", flush=True)
    if CRL_CACHE is not None:
        threading.Thread(target=CRL_CACHE.run_forever, daemon=True, name="crl-refresh").start()
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
