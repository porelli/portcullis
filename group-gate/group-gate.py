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
     required factor set (one of mtls/webauthn/password, with AND/OR
     semantics)? If not, 403 with a stepup URL so the user can re-auth
     at the needed Level of Authentication.
     mTLS binding: when the policy is satisfied only through the `mtls`
     factor (amr=mtls), the token alone is not enough — it may have been
     obtained with a cert that has since been revoked. The CURRENT request
     must present a client cert (checked for revocation in step 0) whose
     subject CN equals the session user (the LLDAP username from
     X-Auth-Request-Preferred-Username, which must also match the token's
     preferred_username); otherwise step-up / deny.
  2. Group — does the user belong to the subdomain's required LLDAP
     group (users_<app>)? If not, 403. The reserved group
     __portcullis_deny__ (published by the Hub for apps whose config is
     unknown) always denies, and so does a user who claims to be in it.
  3. Path groups — for subdomains with `path_groups` rules, the normalised
     X-Forwarded-Uri path is matched against the rule prefixes (segment
     boundaries, longest prefix wins) and that rule's group is required in
     addition to the subdomain group. See normalize_path_candidates().

Request paths on group-gate itself (the forwardAuth `address`):
  /                     full checks (portcullis-groups@docker)
  /authenticated[/...]  everything except the subdomain group check (step 2):
                        any authenticated user. Used for self-service routes
                        such as enroll.<domain>/self (portcullis-self@docker).
  /public-guard         public exceptions (portcullis-public-guard@docker, on
                        the Hub's portcullis-public-<app> routers, no forward-
                        auth): no user, no group, no policy. Allows only if the
                        subdomain has a `public_paths` entry (policy file
                        version 3), the normalised path is inside one of its
                        patterns, and the request carries no credential
                        (Authorization, Proxy-Authorization, the app's
                        credential headers, cookies or query parameters,
                        names normalised the way PHP does). Otherwise 403.
                        See public_guard_check().
  /healthz              liveness (no checks, for the container healthcheck)
  /metrics              Prometheus metrics (monitoring profile): decisions by
                        endpoint/result, denials and step-ups by reason,
                        policy load errors, CRL freshness (last good fetch,
                        the CRL's nextUpdate), revoked-serial counts. Only
                        reachable on the internal `portcullis` network —
                        Traefik's forwardAuth always calls / or /authenticated.

Config sources (both re-read on every request; they are tiny):
  - /etc/group-gate/map.conf — subdomain=required_group. Authoritative for
    core subdomains (auth, traefik, hub, directory, enroll, metrics): the Hub policy
    file can never override those.
  - /hub-data/group-gate-policy.json — written by the Hub (contract §4):
      {"version": 3,
       "policies": {"<subdomain>": {"factors": [...], "op": "any|all|"}},
       "default":  {"factors": [...], "op": "..."},
       "groups":   {"<subdomain>": "<required LLDAP group>"},
       "path_groups": {"<subdomain>": [{"prefix": "/admin", "group": "<LLDAP group>"}]},
       "public_paths": {"<subdomain>": {"paths": [{"path": "/s/{token}", "match": "prefix"}],
                        "token_pattern": "^...$", "static_extensions": [...],
                        "credential_headers": [...], "credential_cookies": [...],
                        "credential_query": [...]}}}
    Every map is keyed by the lowercase subdomain the request is for —
    never by template ID. Optional; no file means every app falls through to the group check
    only. Missing keys (incl. `version`) are treated as empty. A file that
    exists but cannot be parsed, a newer `version` than this gate knows, or
    a policy with unknown factor names / op / rule shape fails CLOSED (403).

Host handling: X-Forwarded-Host is normalised (lowercased, port and
trailing dot stripped) because Traefik's Host() matcher is
case-insensitive. When PORTCULLIS_DOMAIN is set, the host must be exactly
<single-label>.<PORTCULLIS_DOMAIN>, otherwise the request is denied.

Access token is read from X-Forwarded-Access-Token (oauth2-proxy with
PASS_ACCESS_TOKEN=true). The JWT signature is NOT verified here — it was
already verified upstream by oauth2-proxy before the request reaches us.
We only decode the payload to read the acr/amr/preferred_username claims.
"""

from __future__ import annotations

import base64
import calendar
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
DELTA_CRL_URL = os.environ.get("GATE_DELTA_CRL_URL", "").strip()
CRL_REFRESH_SECONDS = float(os.environ.get("GATE_CRL_REFRESH_SECONDS", "60"))
CERT_INFO_HEADER = "X-Forwarded-Tls-Client-Cert-Info"

# Core infrastructure subdomains. Their required group comes only from
# map.conf / GATE_MAP; Hub-written "groups" entries for them are ignored.
# If map.conf somehow lacks one, it defaults to lldap_admin (fail closed).
CORE_SUBDOMAINS = ("auth", "traefik", "hub", "directory", "enroll", "metrics")
CORE_DEFAULT_GROUP = "lldap_admin"
VALID_OPS = ("", "any", "all")
# Highest policy-file schema version this gate understands (contract §4).
POLICY_VERSION = 3
# /public-guard needs a file of exactly this version: an older file has no
# (or another) public_paths shape, so the guard denies.
PUBLIC_GUARD_VERSION = 3
# Reserved group (contract §4): the Hub publishes it for routed apps whose
# config is unknown. It always denies; nobody may claim membership.
DENY_GROUP = "__portcullis_deny__"

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


_POLICY_CACHE: dict = {}
_POLICY_LOCK = threading.Lock()


def _read_policy_doc():
    """Parsed policy file, cached on (path, inode, mtime, size): the Hub
    replaces it atomically (rename), so any change gives a new key."""
    try:
        st = os.stat(POLICY_FILE)
    except FileNotFoundError:
        return {}
    except OSError as e:
        raise PolicyError(f"cannot read policy file: {e}") from e
    key = (POLICY_FILE, st.st_ino, st.st_mtime_ns, st.st_size)
    with _POLICY_LOCK:
        if _POLICY_CACHE.get("key") == key:
            return _POLICY_CACHE["doc"]
    try:
        with open(POLICY_FILE) as f:
            doc = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise PolicyError(f"cannot read policy file: {e}") from e
    with _POLICY_LOCK:
        _POLICY_CACHE.clear()
        _POLICY_CACHE.update(key=key, doc=doc)
    return doc


def load_policy_file() -> dict:
    """Return the Hub policy doc, {} if the file is absent.

    Raises PolicyError if the file exists but is not a JSON object — a
    broken policy must not silently downgrade apps to "no policy". Callers
    must not modify the returned (cached) document.
    """
    doc = _read_policy_doc()
    if not isinstance(doc, dict):
        raise PolicyError("policy file is not a JSON object")
    version = doc.get("version")
    if version is not None:
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise PolicyError(f"invalid policy file version {version!r}")
        if version > POLICY_VERSION:
            # A newer schema may carry restrictions we would silently drop.
            raise PolicyError(f"policy file version {version} is newer than supported ({POLICY_VERSION})")
    return doc


# ── Path rules (path_groups) ──────────────────────────────────────────


def _normalize_prefix(prefix: str) -> str:
    prefix = "/" + prefix.strip().lstrip("/")
    return prefix.rstrip("/") or "/"


def path_rules_for(policy_doc: dict, subdomain: str) -> List[Tuple[str, str]]:
    """[(prefix, group)] for the subdomain; raises PolicyError if malformed.

    Core subdomains never take rules from the Hub file.
    """
    pg = policy_doc.get("path_groups") if isinstance(policy_doc, dict) else None
    if pg is None:
        return []
    if not isinstance(pg, dict):
        raise PolicyError("'path_groups' is not an object")
    rules_raw = None
    for key, value in pg.items():
        if isinstance(key, str) and key.strip().lower() == subdomain:
            rules_raw = value
            break
    if rules_raw is None:
        return []
    if subdomain in CORE_SUBDOMAINS:
        print(f"group-gate: ignoring policy-file path_groups for core subdomain {subdomain!r}", flush=True)
        return []
    if not isinstance(rules_raw, list):
        raise PolicyError(f"path_groups for {subdomain!r} is not a list")
    rules = []
    for rule in rules_raw:
        if not isinstance(rule, dict):
            raise PolicyError(f"path_groups rule for {subdomain!r} is not an object")
        prefix, group = rule.get("prefix"), rule.get("group")
        if not isinstance(prefix, str) or not prefix.strip().startswith("/"):
            raise PolicyError(f"path_groups rule for {subdomain!r} has an invalid prefix {prefix!r}")
        if not isinstance(group, str) or not group.strip():
            raise PolicyError(f"path_groups rule for {subdomain!r} has an invalid group {group!r}")
        if any(c in prefix for c in "%?#\\\x00") or "/./" in prefix + "/" or "/../" in prefix + "/":
            raise PolicyError(f"path_groups prefix {prefix!r} for {subdomain!r} is not a normalised path")
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
        m = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/]*(/.*)?$", path)
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


def public_config_for(policy_doc: dict, subdomain: str) -> Optional[PublicConfig]:
    """The subdomain's public_paths entry, validated (None if absent).

    Raises PolicyError for a file version other than PUBLIC_GUARD_VERSION or
    any malformed / unknown field: the guard then denies (fail closed).
    """
    version = policy_doc.get("version")
    if version != PUBLIC_GUARD_VERSION:
        raise PolicyError(f"public guard needs policy file version {PUBLIC_GUARD_VERSION}, got {version!r}")
    pp = policy_doc.get("public_paths")
    if pp is None:
        return None
    if not isinstance(pp, dict):
        raise PolicyError("'public_paths' is not an object")
    if subdomain in CORE_SUBDOMAINS:
        return None
    entry = pp.get(subdomain)
    if entry is None:
        return None
    if not isinstance(entry, dict):
        raise PolicyError(f"public_paths[{subdomain!r}] is not an object")
    unknown = set(entry) - PUBLIC_KEYS
    if unknown:
        raise PolicyError(f"public_paths[{subdomain!r}] has unknown keys {sorted(unknown)}")
    raw_paths = entry.get("paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        raise PolicyError(f"public_paths[{subdomain!r}].paths is empty")
    paths = []
    has_token = False
    for p in raw_paths:
        if not isinstance(p, dict) or set(p) != {"path", "match"}:
            raise PolicyError(f"public_paths[{subdomain!r}] has a malformed path entry {p!r}")
        path, match = p["path"], p["match"]
        if not isinstance(path, str) or not _PUBLIC_PATH_RE.fullmatch(path) or match not in PUBLIC_MATCHES:
            raise PolicyError(f"public_paths[{subdomain!r}] has an invalid path {path!r} / match {match!r}")
        segs = path.split("/")[1:]
        if any(seg in (".", "..") or (".." in seg) for seg in segs) or segs.count(_PUBLIC_TOKEN) > 1 \
                or (match != "prefix" and _PUBLIC_TOKEN in segs):
            raise PolicyError(f"public_paths[{subdomain!r}] has an invalid path {path!r}")
        has_token = has_token or _PUBLIC_TOKEN in segs
        paths.append((path, match))
    token_re = None
    pat = entry.get("token_pattern", "")
    if not isinstance(pat, str):
        raise PolicyError(f"public_paths[{subdomain!r}].token_pattern is not a string")
    if has_token:
        if not (pat.startswith("^") and pat.endswith("$")):
            raise PolicyError(f"public_paths[{subdomain!r}].token_pattern must be anchored")
        try:
            token_re = re.compile(pat)
        except re.error as e:
            raise PolicyError(f"public_paths[{subdomain!r}].token_pattern: {e}") from e
    exts = tuple(_str_list(entry, "static_extensions", _EXT_RE, subdomain))
    headers = {h.lower().replace("_", "-") for h in _str_list(entry, "credential_headers", _HEADER_NAME_RE, subdomain)}
    headers.update(ALWAYS_CREDENTIAL_HEADERS)
    cookies = {php_var_name(n.encode()).lower() for n in _str_list(entry, "credential_cookies", _NAME_RE, subdomain)}
    query = {php_var_name(n.encode()).lower() for n in _str_list(entry, "credential_query", _NAME_RE, subdomain)}
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


def public_guard_check(policy_doc: dict, subdomain: str, headers, raw_uri: str) -> Optional[str]:
    """None to allow the public request, else the reason to deny."""
    try:
        cfg = public_config_for(policy_doc, subdomain)
    except PolicyError as e:
        return f"policy: {e}"
    if cfg is None:
        return "no public exception for this subdomain"
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


def _der_time(buf: bytes, tag: int, start: int, end: int) -> Optional[float]:
    """UTCTime (0x17) / GeneralizedTime (0x18) → epoch seconds (UTC), or None."""
    text = buf[start:end].decode("ascii", "replace").rstrip("Z")
    try:
        if tag == 0x17:
            yy = int(text[:2])
            text = ("19" if yy >= 50 else "20") + text
        st = time.strptime(text[:14], "%Y%m%d%H%M%S")
    except ValueError:
        return None
    return float(calendar.timegm(st))


def parse_crl_serials(data: bytes) -> FrozenSet[int]:
    """Revoked serial numbers from an X.509 CRL (DER, or PEM)."""
    return parse_crl(data)[0]


def parse_crl(data: bytes) -> Tuple[FrozenSet[int], Optional[float]]:
    """(revoked serial numbers, nextUpdate epoch or None) from an X.509 CRL
    (DER, or PEM).

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
    next_update = None
    if i < len(fields) and fields[i][0] in times:  # nextUpdate
        next_update = _der_time(data, *fields[i])
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
    return frozenset(serials), next_update


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
    """Subject CN of the leaf (first) cert in X-Forwarded-Tls-Client-Cert-Info."""
    value = _decode_cert_info(raw)
    m = _SUBJECT_RE.search(value)
    if not m:
        return None
    for attr in m.group(1).split(","):
        attr = attr.strip()
        if attr.startswith("CN="):
            return attr[3:]
    return None


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


def parent_domain(host: str) -> str:
    """PORTCULLIS_DOMAIN, or (dev/test without it) the host minus its first label."""
    return DOMAIN or (host.split(".", 1)[1] if "." in host else "")


def stepup_url(host: str, needed_loa: int, factors: list) -> str:
    """Build a step-up URL that asks oauth2-proxy for a fresh login at the
    required Level of Authentication.

    We pass `prompt=login` and `acr_values=<acr>` to /oauth2/start, which
    oauth2-proxy forwards to Keycloak's authorize endpoint. `prompt=login`
    tells Keycloak to bypass its SSO `auth-cookie` short-circuit and re-run
    the flow; `acr_values` routes the user into the matching LoA conditional
    subflow so the missing factor is actually prompted for.

    The URL is on auth.<domain> (router oauth2-callback), never on the app's
    own host: a host-less PathPrefix(`/oauth2/`) router cannot carry the
    tiers' TLS options, so Traefik serves it with the default options and
    answers 421 Misdirected Request on every app host (they all use
    authaware/protected/public). oauth2-proxy's cookie is set for
    .<domain> and `rd` is in its whitelist, so the user lands back on the app.

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
    parent = parent_domain(host)
    return f"https://auth.{parent}/oauth2/start?{query}" if parent else f"https://{host}/oauth2/start?{query}"


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


def identity_headers(req_headers) -> dict:
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
    # like enroll still see them.
    if groups:
        out["X-Auth-Request-Groups"] = groups
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

    def _allow(self):
        METRICS.inc("group_gate_requests_total", endpoint=self._endpoint, result="allow")
        self.send_response(200)
        for name, value in identity_headers(self.headers).items():
            self.send_header(name, value)
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

    def _stepup(self, host: str, subdomain: str, user: str, policy: dict, required_loa: int,
                acr: str, amr: list, reason: str, detail_html: str = "", metric_reason: str = "policy"):
        METRICS.inc("group_gate_requests_total", endpoint=self._endpoint, result="stepup")
        METRICS.inc("group_gate_stepups_total", reason=metric_reason)
        url = stepup_url(host, required_loa, policy.get("factors") or [])
        e_url = html.escape(url, quote=True)
        e_sub = html.escape(subdomain)
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
        parent = parent_domain(host)
        account_url = (
            f"https://auth.{parent}/realms/portcullis/account/account-security/signing-in"
            if parent else ""
        )
        enrollment_block = ""
        if needs_hardware and account_url:
            enrollment_block = (
                f"<p style=\"background:#fff7ed;border:1px solid #fed7aa;padding:.75rem 1rem;border-radius:.5rem;margin-top:1rem\">"
                f"<b>No hardware key yet?</b> "
                f"<a href=\"{html.escape(account_url, quote=True)}\" target=\"_blank\" rel=\"noopener\">Open the account console</a> "
                f"to register a security key, then return and retry.</p>"
            )
        if not detail_html:
            detail_html = (f"<p><b>{e_sub}</b> requires {html.escape(need_desc)}. "
                           f"Your current session was authenticated with <code>{html.escape(have)}</code>, "
                           "which does not satisfy the app's policy.</p>")
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
                f"{detail_html}"
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

    _endpoint = "gate"

    def _public_guard(self):
        raw_host = self.headers.get("X-Forwarded-Host", "")
        host = normalize_host(raw_host)
        subdomain = subdomain_for(host)
        raw_uri = self.headers.get("X-Forwarded-Uri", "")
        reason = "host not under PORTCULLIS_DOMAIN"
        cfg = None
        if subdomain is not None:
            try:
                doc = load_policy_file()
            except PolicyError as e:
                doc = None
                reason = f"policy: {e}"
            if doc is not None:
                reason = public_guard_check(doc, subdomain, self.headers, raw_uri)
                try:
                    cfg = public_config_for(doc, subdomain)
                except PolicyError:
                    cfg = None
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
        if gate_path == "/public-guard":
            self._endpoint = "public_guard"
            self._public_guard()
            return
        # /authenticated: any authenticated user, no subdomain group check.
        authenticated_only = gate_path == "/authenticated" or gate_path.startswith("/authenticated/")
        self._endpoint = "authenticated" if authenticated_only else "gate"

        raw_host = self.headers.get("X-Forwarded-Host", "")
        host = normalize_host(raw_host)
        username = session_username(self.headers)
        user = username or "unknown"  # for logs / pages only
        e_user = html.escape(user)

        subdomain = subdomain_for(host)
        if subdomain is None:
            self._deny(
                "Access Denied",
                "<p>Unrecognised host.</p>",
                f"DENIED user={user} host={raw_host!r} reason=host not under PORTCULLIS_DOMAIN={DOMAIN!r}",
                "host",
            )
            return
        e_sub = html.escape(subdomain)

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

        # Per-request reload — the Hub rewrites the policy file on each
        # change, and both files are tiny.
        try:
            policy_doc = load_policy_file()
            gate = build_group_map(policy_doc)
            policy = resolve_policy(policy_doc, subdomain)
            policy_err = validate_policy(policy) if policy else None
            path_rules = path_rules_for(policy_doc, subdomain)
        except PolicyError as e:
            self._deny_policy(user, host, str(e))
            return
        if policy_err:
            self._deny_policy(user, host, policy_err)
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
                self._stepup(host, subdomain, user, policy, required_loa, acr, amr, reason)
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
                        host, subdomain, user, policy, FACTOR_TO_LOA["mtls"], acr, amr,
                        f"mtls binding: {problem}",
                        "<p><b>" + e_sub + "</b> requires your client certificate (security key) on "
                        "every request, and it must belong to the signed-in user. Insert your "
                        "security key, select its certificate when the browser asks, and sign in again.</p>",
                        metric_reason="mtls_binding",
                    )
                    return

        # --- Group check ---
        if not authenticated_only:
            required_group = gate.get(subdomain)
            if required_group == DENY_GROUP:
                self._deny(
                    "Access Denied",
                    f"<p>The configuration of <b>{e_sub}</b> is unavailable, so access is denied. "
                    "Ask an administrator to check the app in the Hub.</p>",
                    f"DENIED user={user} host={host} reason=app configuration unavailable ({DENY_GROUP})",
                    "app_unavailable",
                )
                return
            if not required_group:
                print(f"group-gate: ALLOW-UNMAPPED user={user} host={host} (no group mapping for {subdomain!r})", flush=True)
            elif required_group not in groups:
                self._deny(
                    "Access Denied",
                    f"<p>User <b>{e_user}</b> is not authorized to access <b>{e_sub}</b>.</p>"
                    f"<p>Required group: <code>{html.escape(required_group)}</code></p>",
                    f"DENIED user={user} host={host} need={required_group} have={sorted(groups)}",
                    "group",
                )
                return

        # --- Path groups (in addition to the subdomain group) ---
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
                        f"<p>User <b>{e_user}</b> is not authorized to access this part of <b>{e_sub}</b>.</p>"
                        f"<p>Required group: <code>{html.escape(need)}</code></p>",
                        f"DENIED user={user} host={host} path={log_uri(candidates[0])!r} need={need} have={sorted(groups)}",
                        "path_group",
                    )
                    return

        self._allow()

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
          f"delta={DELTA_CRL_URL or '(none)'} refresh={CRL_REFRESH_SECONDS:g}s", flush=True)
    if CRL_CACHE is not None:
        threading.Thread(target=CRL_CACHE.run_forever, daemon=True, name="crl-refresh").start()
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
