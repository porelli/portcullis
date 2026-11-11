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
       - GATE_CRL_URLS (space-separated: Vault's full DER CRLs of both
         intermediates, http://vault:8200/v1/pki_int/crl and .../pki_file/crl)
         and GATE_DELTA_CRL_URLS (their delta CRLs, .../crl/delta: with
         auto_rebuild Vault puts new revocations only there until the next
         full rebuild), re-fetched every GATE_CRL_REFRESH_SECONDS (default
         60) in the background; the union of all of them and the file is
         enforced. Until every list has been read once no certificate counts
         as a sign-in method; after that, fetch errors keep the last good
         CRL (the serial file still applies).
     Traefik's entrypoint deletes client-supplied X-Forwarded-Tls-Client-*
     headers, so the header only ever describes a cert Traefik verified.
  1. Sign-in template (policy file v6; checked LAST, after 2. and 3., so a
     non-member gets the plain 403) — the host's compiled rule over
     sign-in methods (core[host] for a gated core host, else hosts[host],
     else default) must be met by the session's methods: the token's amr
     values mapped through the method table (AMR_TO_METHOD), kept only
     while the method is switched on (`methods`). If not, 403 with one of
     three pages (contract §5), never an automatic redirect:
       - present-certificate (#present-certificate): amr holds mtls (file)
         and the rule would be met if the YubiKey (browser) certificate
         counted, but this request carries no bound certificate of that kind;
       - step-up (#stepup-continue, X-Stepup-URL): one missing method can
         be completed — /oauth2/start?pc_method=<method> (a setup-link
         session, amr `inv`, counts as not known in `people`);
       - needs-stronger (#needs-stronger): nothing can be completed here.
     Certificate binding: `yubikey_cert` (amr mtls) counts only when the
     CURRENT request presents a YubiKey certificate, and `browser_cert`
     (amr file) only with a browser certificate: the leaf's issuer CN must
     be the subject CN of GATE_YUBIKEY_CA_FILE (pki_int) or
     GATE_BROWSER_CA_FILE (pki_file) — equal CNs or an unreadable file: no
     certificate counts —, it passed the revocation check in step 0, and
     its subject CN equals the session user (the LLDAP username from
     X-Auth-Request-Preferred-Username, which must also match the token's
     preferred_username) — the token alone may have been obtained with a
     certificate that has since been revoked.
     Sign-in paths: on people.<domain> the Sign-in page's own paths
     (/signin, /api/me/signin, /api/me/signin/*, /static/*: every
     normalised reading of the path inside that set) take "any switched-on
     method" instead of the people template (contract §4).
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
  /public-guard         public exceptions (portcullis-public-guard@docker, on
                        the Hub's portcullis-public-<instance> routers, no
                        forward-auth): no user, no group, no policy. Allows
                        only if the host has a `public_paths` entry (policy
                        file version 6; never a core host), the normalised
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
                        Traefik's forwardAuth always calls /.

The opened log: every allowed request on / and /portal whose (session,
host) this process hasn't logged yet appends a line to
GATE_OPENED_DIR/<YYYY-MM-DD>.jsonl (OpenedLog; the Hub's sign-in history
reads it). A failed write is counted, never a deny.

Config sources (both re-read on every request; they are tiny):
  - /etc/group-gate/map.conf — <sub>=required_group, expanded to
    <sub>.<PORTCULLIS_DOMAIN> (`*` = any signed-in user, valid only
    there). Authoritative for the core hosts (<domain> itself and
    auth, traefik, hub, directory, enroll, people, metrics, mcp . <domain>;
    enroll is reserved but not gated):
    the Hub policy file can never override those.
  - /hub-data/group-gate-policy.json — written by the Hub (contract §4):
      {"version": 6,
       "methods": ["<switched-on method id>", ...],
       "templates": {"<template id>": {"op": "any|all", "items": ["<method id>" | {group}, ...]}},
       "default": "<template id>",
       "hosts": {"<app hostname>": "<template id>"},
       "core": {"<gated core hostname>": "<template id>"},
       "people": {"<lowercase username>": ["<method id they have set up>", ...]},
       "add_stronger": false,
       "extra_domains": ["<enrolled domain>", ...],
       "groups":   {"<hostname>": "<required LLDAP group>"},
       "path_groups": {"<hostname>": [{"prefix": "/admin", "group": "<LLDAP group>"}]},
       "public_paths": {"<hostname>": {"paths": [{"path": "/s/{token}", "match": "prefix"}],
                        "token_pattern": "^...$", "static_extensions": [...],
                        "credential_headers": [...], "credential_cookies": [...],
                        "credential_query": [...]}},
       "expiring": [{"user": "<lowercase username>", "group": "<LLDAP group>",
                     "at": "<RFC 3339 UTC>"}]}
    Every host map is keyed by the full lowercase hostname the request is
    for (a valid hostname, see HOSTNAME_RE) — never by template or instance
    id, never by subdomain. The seven v6 keys `methods` … `add_stronger`
    are required; the others may be missing (= empty). A MISSING file, a
    file that cannot be parsed, any `version` but 6 (a missing one
    included), an unknown key, a key that is not a valid hostname, a
    malformed `extra_domains`, a compiled rule of another shape (unknown op,
    0 or > 8 items, a leaf that isn't a switched-on method id, > 4 levels,
    > 48 leaves), a template id `default` / `hosts` / `core` names that
    `templates` lacks, or a gated core host missing from `core` fails
    CLOSED (403). `people` and `add_stronger` only word the pages, never
    an access decision.
  - /hub-data/user-attributes.json — written by the Hub (contract §4.1):
    {"version": 2, "fields": {"<field>": "<Header-Name>"},
     "users": {"<user>": {"<field>": ["value", ...]}},
     "hosts": {"<host>": {"<Header-Name>": {"<user>": "value"}}}}. Every
    allow on / returns X-Forwarded-Attr-<Header-Name>
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
We only decode the payload to read the amr/preferred_username claims.
"""

from __future__ import annotations

import base64
import collections
import datetime
import hashlib
import html
import json
import os
import re
import stat
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
# Space-separated (contract §4 "Revocation lists"): the pki_int and pki_file
# full CRLs, and their delta CRLs.
CRL_URLS: List[str] = os.environ.get("GATE_CRL_URLS", "").split()
DELTA_CRL_URLS: List[str] = os.environ.get("GATE_DELTA_CRL_URLS", "").split()
# The two intermediates' certificates (contract §4 "Certificate binding"):
# a leaf's issuer CN says which kind it is.
YUBIKEY_CA_FILE = os.environ.get("GATE_YUBIKEY_CA_FILE", "/etc/group-gate/ca/yubikey-ca.crt")
BROWSER_CA_FILE = os.environ.get("GATE_BROWSER_CA_FILE", "/etc/group-gate/ca/browser-ca.crt")
# The opened log (contract §4 "Opened log"): <dir>/<YYYY-MM-DD>.jsonl.
OPENED_DIR = os.environ.get("GATE_OPENED_DIR", "/data/opened")
# The Hub's gid: opened/ is 2770 with this group, its files 0640.
OPENED_GID = int(os.environ.get("GATE_OPENED_GID", "10001"))
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
# `mcp` (AI support, contract §4/§5) is the "all my apps" MCP endpoint: its
# router has no forward-auth (mcp-gate authorizes), so group-gate never sees
# its requests; listing it keeps every Hub entry for mcp.<domain> out.
CORE_SUBDOMAINS = ("auth", "traefik", "hub", "directory", "enroll", "people", "metrics", "mcp")
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
# The one policy-file schema version this gate serves (contract §4): any
# other `version` denies (an older file has no sign-in templates, so it
# can't say which methods an app accepts; a newer one may carry
# restrictions we would drop). A file without `version` denies too, and so
# does a missing file (no method is on, no template is known).
POLICY_VERSION = 6
# /public-guard needs a file of exactly this version (no `version` = deny).
PUBLIC_GUARD_VERSION = 6
# The maps of the policy file keyed by hostname (contract §4).
HOST_MAPS = ("hosts", "groups", "path_groups", "public_paths")
# The v6 keys the Hub always writes; a file without one of them denies.
POLICY_REQUIRED_KEYS = ("methods", "templates", "default", "hosts", "core", "people", "add_stronger")
# Keys that may be missing (= empty, as before v6). Any other key denies.
POLICY_OPTIONAL_KEYS = ("extra_domains", "groups", "path_groups", "public_paths", "expiring")
# Reserved group (contract §4): the Hub publishes it for routed apps whose
# config is unknown. It always denies; nobody may claim membership.
DENY_GROUP = "__portcullis_deny__"
# Service accounts that must never use the gateway (the Hub's LLDAP account
# is in lldap_admin; Keycloak's federation also filters it out).
DENY_USERS = frozenset(u.strip().lower() for u in os.environ.get("GATE_DENY_USERS", "portcullis-hub").split(",") if u.strip())

# ── Sign-in methods (contract §8.1 "Methods"; the same table in the Hub's
# internal/signin, the Keycloak extension and mcp-gate) ──

# The six method ids in canonical order (weakest first).
METHOD_IDS = ("password", "passkey_synced", "browser_cert", "passkey_device", "security_key", "yubikey_cert")
# amr value → method id. Anything else (`inv`, a setup-link session,
# included) stands for nothing.
AMR_TO_METHOD = {"pwd": "password", "spk": "passkey_synced", "file": "browser_cert",
                 "dpk": "passkey_device", "hwk": "security_key", "mtls": "yubikey_cert"}
# Strengths in tenths (contract §8.1): only the pages' "Set up …" vs "ask
# your admin" use them, never an access decision.
METHOD_TENTHS = {"password": 10, "passkey_synced": 25, "browser_cert": 25,
                 "passkey_device": 30, "security_key": 35, "yubikey_cert": 40}
PASSKEY_KINDS = ("passkey_synced", "passkey_device", "security_key")
# What a step-up may ask for (`pc_method`, oauth2-proxy's allowlist in
# oauth2-proxy/alpha.yaml): one method id, or `passkey` = any passkey kind.
STEPUP_METHODS = frozenset(METHOD_IDS) | {"passkey"}
# Compiled-rule limits (contract §4 / §8.1 "Rules"), the same in every reader.
RULE_MAX_DEPTH = 4
RULE_MAX_ITEMS = 8
RULE_MAX_LEAVES = 48
TEMPLATE_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,31}|collision\.[1-9][0-9]*")
# Core subdomains group-gate gates with a template from `core` (with the
# apex, the portal). `auth` (the Keycloak admin console's router) takes the
# Hub's template (`core["hub.<domain>"]`); `mcp` never reaches group-gate
# (mcp-gate authorizes).
# `enroll` is a core subdomain (reserved against apps) but not gated: its
# one router (setup links, /invite/*) has no forward-auth (contract §4).
GATED_CORE_SUBDOMAINS = ("traefik", "hub", "directory", "people", "metrics")


def gated_core_hosts() -> FrozenSet[str]:
    """The core hosts `core` must list (contract §4): <domain> and
    <gated core sub>.<domain>."""
    if not DOMAIN_OK:
        return frozenset()
    return frozenset([DOMAIN] + [f"{sub}.{DOMAIN}" for sub in GATED_CORE_SUBDOMAINS])


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


# ── Compiled sign-in rules (contract §8.1 "Rules") ──────────────────

def _rule_leaves(node) -> int:
    return sum(1 if isinstance(it, str) else _rule_leaves(it) for it in node["items"])


def validate_rule(node, methods: set, depth: int = 1) -> Optional[str]:
    """Why `node` is not a compiled rule over `methods`, or None.

    A compiled rule is a group {"op": "all"|"any", "items": [...]} with
    exactly those two keys and 1–8 items, each a method id listed in
    `methods` (switched on) or a nested group of the same shape; groups nest
    at most 4 levels (the top group is level 1), with at most 48 leaves.
    A family, an amr value, `inv` or any other leaf is refused, as is a
    leaf at the top."""
    if not isinstance(node, dict):
        return "a compiled rule must be a group"
    if depth > RULE_MAX_DEPTH:
        return f"groups nest at most {RULE_MAX_DEPTH} levels"
    if set(node) != {"op", "items"}:
        return 'a group has exactly "op" and "items"'
    op, items = node["op"], node["items"]
    if not isinstance(op, str) or op not in ("all", "any"):
        return f'"op" must be "all" or "any", not {op!r}'
    if not isinstance(items, list) or not 1 <= len(items) <= RULE_MAX_ITEMS:
        return f"a group holds 1–{RULE_MAX_ITEMS} items"
    for it in items:
        if isinstance(it, str):
            if it not in METHOD_IDS:
                return f"{it!r} is not a sign-in method id"
            if it not in methods:
                return f"{it!r} is not switched on"
        elif isinstance(it, dict):
            err = validate_rule(it, methods, depth + 1)
            if err:
                return err
        else:
            return f"an item must be a method id or a group, not {it!r}"
    if depth == 1 and _rule_leaves(node) > RULE_MAX_LEAVES:
        return f"more than {RULE_MAX_LEAVES} methods in one rule"
    return None


def rule_satisfied(node, have: set) -> bool:
    """An `all` group is met when every item is, an `any` group when one
    is; a method when it is among the session's methods. (Validated rules
    only.)"""
    met = (it in have if isinstance(it, str) else rule_satisfied(it, have) for it in node["items"])
    return all(met) if node["op"] == "all" else any(met)


_RANK = {m: i for i, m in enumerate(METHOD_IDS)}


def _minimal(sets: List[int]) -> List[int]:
    """Drops duplicates and supersets of another set, keeping the first
    copy (the Hub's signin.Alternatives / the extension's Rule.minimal)."""
    out = []
    for i, s in enumerate(sets):
        if not any(i != j and o & s == o and (o != s or j < i) for j, o in enumerate(sets)):
            out.append(s)
    return out


def _alternative_masks(node) -> List[int]:
    if isinstance(node, str):
        return [1 << _RANK[node]]
    if node["op"] == "any":
        out: List[int] = []
        for it in node["items"]:
            out = _minimal(out + _alternative_masks(it))
        return out
    out = [0]
    for it in node["items"]:
        alts = _alternative_masks(it)
        out = _minimal([x | y for x in out for y in alts])
    return out


def alternatives(node) -> List[FrozenSet[str]]:
    """The rule's ways to be met: its minimal any-of-all-of form, in the
    rule's order (no alternative twice, none containing another)."""
    return [frozenset(m for m in METHOD_IDS if mask >> _RANK[m] & 1) for mask in _alternative_masks(node)]


# The certificate methods, strongest first, and the amr each one's
# sign-in leaves in the token (contract §4 "Certificate binding").
CERT_METHODS = ("yubikey_cert", "browser_cert")
CERT_AMR = {"yubikey_cert": "mtls", "browser_cert": "file"}


def session_methods(amr: list, enabled: set, bound: set) -> set:
    """The session's methods (contract §8.1 "Session methods"): each amr
    value through AMR_TO_METHOD (`inv` and unknown values count as
    nothing), kept only while switched on; a certificate method only when
    this request binds it (`bound`: the certificate methods the presented
    leaf binds, cert_method() — at most one)."""
    out = set()
    for value in amr if isinstance(amr, list) else []:
        m = AMR_TO_METHOD.get(value) if isinstance(value, str) else None
        if m and m in enabled and (m not in CERT_METHODS or m in bound):
            out.add(m)
    return out


def held_cert_methods(amr: list) -> FrozenSet[str]:
    """The certificate methods whose amr the session's token holds."""
    values = amr if isinstance(amr, list) else []
    return frozenset(m for m in CERT_METHODS if CERT_AMR[m] in values)


def choose_stepup(node, have: set, set_up: Optional[set], held: FrozenSet[str] = frozenset()) -> Optional[str]:
    """The method a step-up asks for (contract §5), or None (the
    needs-stronger page).

    Candidates: for each alternative, in the rule's order, that lacks
    exactly one method, that method — only ones the person has set up when
    `people` knows them (`set_up` not None), any when it doesn't — never a
    certificate method whose amr the session already holds (`held`:
    `yubikey_cert` with mtls, `browser_cert` with file; that is the
    present-certificate page). Choice: the first candidate; with the person
    unknown and two or more passkey-kind candidates, `passkey`."""
    candidates: List[str] = []
    for alt in alternatives(node):
        missing = alt - have
        if len(missing) != 1:
            continue
        (m,) = missing
        if m in held or (set_up is not None and m not in set_up):
            continue
        if m not in candidates:
            candidates.append(m)
    if not candidates:
        return None
    if set_up is None and sum(m in PASSKEY_KINDS for m in candidates) >= 2:
        return "passkey"
    return candidates[0]


_POLICY_CACHE: dict = {}
_POLICY_LOCK = threading.Lock()


def validate_policy_doc(doc) -> Optional[str]:
    """Why a parsed policy file must deny every request, or None.

    Checks the whole file (contract §4): a JSON object of exactly
    POLICY_VERSION with only known keys and every v6 key; `methods` a list
    of distinct method ids; every template id well-formed and its rule a
    compiled rule over `methods`; `default`, every `hosts` and `core` value
    a key of `templates`; `core` keyed by gated core hosts; `people` lists
    of switched-on method ids; `add_stronger` a boolean; every host map an
    object keyed by valid hostnames; `extra_domains` a list of valid
    hostnames none of which is the main domain, a parent of it, or at or
    under a core host (extra domains never route core services). Other
    per-host entries are validated when a request needs them.
    """
    if not isinstance(doc, dict):
        return "policy file is not a JSON object"
    version = doc.get("version")
    # An int exactly: JSON 6.0 (a float) or true (a bool) is not version 6.
    if type(version) is not int or version != POLICY_VERSION:
        return f"policy file version {version!r} is not supported (only {POLICY_VERSION})"
    unknown = sorted(k for k in doc if k != "version" and k not in POLICY_REQUIRED_KEYS + POLICY_OPTIONAL_KEYS)
    if unknown:
        return f"unknown keys {unknown[:5]}"
    missing = [k for k in POLICY_REQUIRED_KEYS if k not in doc]
    if missing:
        return f"missing keys {missing}"
    methods = doc["methods"]
    if (not isinstance(methods, list) or not all(isinstance(m, str) and m in METHOD_IDS for m in methods)
            or len(set(methods)) != len(methods)):
        return "'methods' is not a list of distinct sign-in method ids"
    methods = set(methods)
    templates = doc["templates"]
    if not isinstance(templates, dict):
        return "'templates' is not an object"
    for tid, rule in templates.items():
        if not TEMPLATE_ID_RE.fullmatch(tid):
            return f"template id {tid!r} is not valid"
        err = validate_rule(rule, methods)
        if err:
            return f"template {tid!r}: {err}"
    if not isinstance(doc["default"], str) or doc["default"] not in templates:
        return f"'default' {doc['default']!r} is not a published template"
    for name in ("hosts", "core"):
        m = doc[name]
        if not isinstance(m, dict):
            return f"{name!r} is not an object"
        bad = sorted(repr(h) for h, tid in m.items() if not isinstance(tid, str) or tid not in templates)
        if bad:
            return f"{name!r} names templates that aren't published for {bad[:5]}"
    gated = gated_core_hosts()
    bad = sorted(repr(h) for h in doc["core"] if h not in gated)
    if bad:
        return f"'core' has keys that are not gated core hosts: {bad[:5]}"
    people = doc["people"]
    if not isinstance(people, dict):
        return "'people' is not an object"
    for user, ms in people.items():
        if (not user or user != user.lower() or not isinstance(ms, list)
                or not all(isinstance(m, str) and m in methods for m in ms)):
            return f"'people' entry {user!r} is not a lowercase user with a list of switched-on methods"
    if type(doc["add_stronger"]) is not bool:
        return "'add_stronger' is not a boolean"
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
        # An entry with urls: [] renders as a card even without a note (contract §10).
        note = a.get("note")
        has_note = isinstance(note, str) and note
        urls_value = a.get("urls")
        is_empty_urls = isinstance(urls_value, list) and len(urls_value) == 0
        if not links and not is_empty_urls:
            continue
        icon = a.get("icon") if isinstance(a.get("icon"), str) else ""
        if links:
            content = f'<p>{e(a.get("description") or "")}</p><p class="links">{" · ".join(links)}</p>'
        else:
            # No links: show the note (or "No web page." if empty)
            content = f'<p>{e(a.get("description") or "")}</p><p class="note">{e(note or "No web page.")}</p>'
        cards.append(
            f'<li class="card"><h3><span aria-hidden="true">{e(icon[:4])}</span> {e(a.get("name") or a.get("id") or "")}</h3>'
            f'{content}</li>')
    if apps is None:
        app_html = "<p class=\"muted\">The app list is not available yet.</p>"
    elif cards:
        app_html = "<ul class=\"grid\">" + "".join(cards) + "</ul>"
    else:
        app_html = "<p class=\"muted\">No apps are available to you yet.</p>"
    # Contract §10: People and Sign-in methods for everyone; the Hub, the
    # Keycloak realm console and Traefik for admins. No enrollment link.
    own = [("People", f"https://people.{domain}/"),
           ("Sign-in methods", f"https://people.{domain}/signin")]
    admin = []
    if "lldap_admin" in groups:
        admin = [("Hub (apps, users &amp; marketplace)", f"https://hub.{domain}/"),
                 ("Keycloak (realm console)", f"https://auth.{domain}/admin/portcullis/console/"),
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
    """Return the validated Hub policy doc.

    Raises PolicyError if the file is missing (the Hub has never written
    one, or the volume is gone: no method is on and no template is known,
    contract §4) or fails validate_policy_doc() (not a JSON object, a
    `version` other than POLICY_VERSION — a missing one included —, an
    unknown or missing key, a malformed rule, …): a broken, foreign or
    absent policy must not silently downgrade apps to "no policy". Callers
    must not modify the returned (cached) document.
    """
    doc, error = _read_policy_doc()
    if doc is None:
        raise PolicyError(f"no policy file ({POLICY_FILE}): the Hub has not published one")
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


# ── Temporary memberships (expiring, policy file) ────────────────────

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


# The Sign-in page's paths on people.<domain> (contract §4 "Sign-in
# paths"): exactly these, or under these prefixes.
SIGNIN_EXACT = ("/signin", "/api/me/signin")
SIGNIN_PREFIXES = ("/api/me/signin/", "/static/")
_ENCODED_SEPARATOR_RE = re.compile(r"%(2[fF]|5[cC])")


def signin_path(host: str, raw_path: str) -> bool:
    """True when the request is for the Sign-in page on people.<main
    domain> (the one host it lives on): normalize_path_candidates(raw_path)
    doesn't raise and EVERY candidate it returns is exactly /signin or
    /api/me/signin, or under /api/me/signin/ or /static/. Anything else —
    another host, a path with an encoded '/' or '\\' or a literal '\\',
    a '..' leaving the set in any reading — is not (the host's template
    applies)."""
    if not DOMAIN_OK or host != f"people.{DOMAIN}":
        return False
    path = (raw_path or "").split("?", 1)[0]
    if "\\" in path or _ENCODED_SEPARATOR_RE.search(path):
        return False
    try:
        candidates = normalize_path_candidates(raw_path)
    except PathError:
        return False
    return bool(candidates) and all(
        c in SIGNIN_EXACT or any(c.startswith(p) and len(c) > len(p) for p in SIGNIN_PREFIXES)
        for c in candidates)


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
        "group_gate_requests_total": ("counter", "Forward-auth decisions by endpoint (gate|public_guard|portal) and result (allow|deny|stepup|needs_stronger|present_certificate)."),
        "group_gate_denials_total": ("counter", "Denied requests by reason."),
        "group_gate_stepups_total": ("counter", "Sign-in pages (403) by reason: stepup, present_certificate, needs_stronger."),
        "group_gate_policy_load_errors_total": ("counter", "Requests denied because the Hub policy file or a policy in it is invalid."),
        "group_gate_crl_fetch_failures_total": ("counter", "Failed CRL fetches (the last good CRL is kept)."),
        "group_gate_opened_log_failures_total": ("counter", "Opened-log lines that couldn't be written (the request is still answered)."),
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
                                                               "group_gate_crl_fetch_failures_total",
                                                               "group_gate_opened_log_failures_total"):
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


# ── The opened log (contract §4 "Opened log", §8.2) ───────────────────

_LOG_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def _log_field(value, limit: int) -> str:
    """A string field of a log line: control characters removed, at most
    `limit` characters."""
    return _LOG_CTRL_RE.sub("", value if isinstance(value, str) else "")[:limit]


class OpenedLog:
    """group-gate's "app opened" log: the first allowed request per
    (session, host) this process sees appends one JSON line to
    <directory>/<YYYY-MM-DD>.jsonl (UTC day), which the Hub reads
    (internal/signinhistory/opened.go) and prunes.

    - Remembered (session, host) pairs sit in an LRU of `capacity`; a pair
      is remembered only once its line is written, so a failed write is
      tried again on the next request.
    - Append-only: each line is one write(2) on an O_APPEND descriptor
      opened per line (O_NOFOLLOW: a symlink is never written through) —
      nothing is buffered across requests and a line is never torn by
      another writer.
    - Bounded: every field is cut (ua ≤ 256 characters) and a day file
      stops growing at DAY_FILE_MAX bytes (later lines count as failures).
    - Modes: the directory is 2770 with group `gid` (the Hub's), each file
      0640. The directory's parent must exist (the group_gate_data volume).
    - Never raises: a failure is logged (once per distinct error) and
      counted (group_gate_opened_log_failures_total), never a deny.
    - Holds no secret: no token, cookie or header but the User-Agent.
    """

    DAY_FILE_MAX = 32 << 20
    FIELD_MAX = 256

    def __init__(self, directory: str, capacity: int = 10000, gid: Optional[int] = None):
        self.directory = directory
        self.capacity = max(int(capacity), 1)
        self.gid = OPENED_GID if gid is None else gid
        self._seen: "collections.OrderedDict[Tuple[str, str], None]" = collections.OrderedDict()
        self._lock = threading.Lock()
        self._dir_ok = False
        self._last_error: Optional[str] = None

    def seen(self, session: str, host: str) -> bool:
        """The pair already has its line (the LRU's view)."""
        with self._lock:
            return (session, host) in self._seen

    def _ensure_dir(self):
        if self._dir_ok:
            return
        try:
            os.mkdir(self.directory, 0o2770)
        except FileExistsError:
            pass
        st = os.lstat(self.directory)
        if not stat.S_ISDIR(st.st_mode):
            raise OSError(f"{self.directory} is not a directory")
        if st.st_gid != self.gid:
            os.chown(self.directory, -1, self.gid, follow_symlinks=False)
        if stat.S_IMODE(st.st_mode) != 0o2770:
            # mkdir's mode is cut by the umask and may drop the setgid bit.
            # (lstat said it's a real directory, not a symlink.)
            os.chmod(self.directory, 0o2770)
        self._dir_ok = True

    def _write(self, now: datetime.datetime, line: bytes):
        self._ensure_dir()
        path = os.path.join(self.directory, now.strftime("%Y-%m-%d") + ".jsonl")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags, 0o640)
        except OSError:
            self._dir_ok = False  # re-check the directory next time
            raise
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError(f"{path} is not a regular file")
            if st.st_size + len(line) > self.DAY_FILE_MAX:
                raise OSError(f"{path} reached {self.DAY_FILE_MAX} bytes")
            if stat.S_IMODE(st.st_mode) != 0o640:
                os.fchmod(fd, 0o640)
            if st.st_gid != self.gid:
                os.fchown(fd, -1, self.gid)
            if os.write(fd, line) != len(line):
                raise OSError(f"short write to {path}")
        finally:
            os.close(fd)

    def record(self, user, session, host, app, methods, ip, ua, act="", now: Optional[datetime.datetime] = None) -> None:
        """Append the line for (session, host) unless this process already
        wrote it. Never raises."""
        try:
            session = _log_field(session, self.FIELD_MAX)
            host = _log_field(host, 253).lower()
            if not session or not host:
                return
            key = (session, host)
            with self._lock:
                if key in self._seen:
                    self._seen.move_to_end(key)
                    return
                now = (now or datetime.datetime.now(datetime.timezone.utc)).astimezone(datetime.timezone.utc)
                doc = {"time": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "user": _log_field(user, self.FIELD_MAX).lower(),
                       "session": session, "host": host,
                       "app": _log_field(app, self.FIELD_MAX),
                       "methods": [m for m in METHOD_IDS if m in set(methods or ())],
                       "ip": _log_field(ip, 64), "ua": _log_field(ua, self.FIELD_MAX),
                       "act": _log_field(act, self.FIELD_MAX)}
                line = (json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
                self._write(now, line)
                self._seen[key] = None
                while len(self._seen) > self.capacity:
                    self._seen.popitem(last=False)
                self._last_error = None
        except Exception as e:  # noqa: BLE001 — logging never denies a request
            METRICS.inc("group_gate_opened_log_failures_total")
            err = f"{type(e).__name__}: {e}"
            if err != self._last_error:
                print(f"group-gate: opened log write failed ({err})", flush=True)
            self._last_error = err


OPENED_LOG = OpenedLog(OPENED_DIR)


def log_session_id(claims: dict, user: str) -> str:
    """The opened log's `session`: the token's `sid`, else
    <user>@<auth_time>; "" when the token has neither."""
    sid = claims.get("sid")
    if isinstance(sid, str) and sid.strip():
        return sid.strip()
    auth_time = claims.get("auth_time")
    if type(auth_time) is int and user:
        return f"{user.lower()}@{auth_time}"
    return ""


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
    """Background-refreshed revoked serials from Vault's CRLs: both
    intermediates' (pki_int, the YubiKey certificates; pki_file, the browser
    certificates), each a full and a delta CRL (contract §4 "Revocation
    lists").

    Vault (config/crl auto_rebuild=true) does NOT rebuild the full CRL on
    revoke: new revocations appear in the delta CRL (enable_delta, rebuilt
    about once a minute) until the next full rebuild, which then clears the
    delta. So every list is fetched and the union is enforced.

    Order: every delta first, then every full CRL. A full rebuild between
    the two fetches can then only move a serial from the (already fetched)
    delta into the (about to be fetched) full CRL — never out of both.

    Freshness for /metrics is the WORST of the sources: oldest successful
    fetch, earliest nextUpdate. `ready`: every list has been read at least
    once — until then no certificate counts as a sign-in method (an
    unreadable CRL list fails closed); afterwards a failed fetch keeps the
    last good list.
    """

    def __init__(self, urls: List[str], interval: float, delta_urls: List[str] = ()):
        self.sources = [CrlSource(u) for u in delta_urls] + [CrlSource(u) for u in urls]
        self.urls = list(urls)
        self.interval = max(interval, 1.0)

    @property
    def ready(self) -> bool:
        return all(src.last_success > 0 for src in self.sources)

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


CRL_CACHE: Optional[CrlCache] = (CrlCache(CRL_URLS, CRL_REFRESH_SECONDS, DELTA_CRL_URLS)
                                 if CRL_URLS or DELTA_CRL_URLS else None)


def revoked_serials() -> FrozenSet[int]:
    """The union of the serial file and every CRL. Raises RevocationError
    when the serial file can't be read."""
    serials = load_revoked_file()
    if CRL_CACHE is not None:
        serials = serials | CRL_CACHE.serials
    return serials


def crl_ready() -> bool:
    """Every configured CRL list has been read (no lists configured: only
    the serial file applies)."""
    return CRL_CACHE is None or CRL_CACHE.ready


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
    """Traefik's header value decoded: it is Go's url.QueryEscape of the
    text (a space is "+", a literal "+" is %2B), some versions twice."""
    value = raw or ""
    for _ in range(3):
        decoded = urllib.parse.unquote_plus(value)
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


# The leaf's own fields at the start of the header: Traefik writes each
# certificate's Subject, then its Issuer (client-headers@file asks for the
# issuer's commonName only), the leaf first.
_LEAF_ISSUER_RE = re.compile(r'Subject="[^"]*";Issuer="([^"]*)"')


def _dn_cn(dn: str) -> Optional[str]:
    """The one CN of a Traefik DN text ("C=..,O=..,CN=.."); None when there
    is none or more than one."""
    cns = [a.strip()[3:] for a in dn.split(",") if a.strip().startswith("CN=")]
    return cns[0] if len(cns) == 1 and cns[0] else None


def leaf_cert_issuer_cn(raw: str) -> Optional[str]:
    """Issuer CN of the leaf (first) cert in X-Forwarded-Tls-Client-Cert-Info,
    or None. Only the leaf's own Issuer counts: the header must start with
    its Subject="…";Issuer="…" (Traefik's order), so an intermediate's
    fields later in the chain are never read as the leaf's."""
    m = _LEAF_ISSUER_RE.match(_decode_cert_info(raw))
    return _dn_cn(m.group(1)) if m else None


_CA_CACHE_LOCK = threading.Lock()
_CA_CACHE: dict = {}  # path -> ((inode, mtime, size), CN or None)


def ca_subject_cn(path: str) -> Optional[str]:
    """Subject CN of the CA certificate in `path` (PEM, the first block, or
    DER), read with `cryptography` and cached by (inode, mtime, size).
    None — no certificate counts — when the file is missing or unreadable,
    isn't a certificate, isn't a CA (basicConstraints ca) or has no single
    CN."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (st.st_ino, st.st_mtime_ns, st.st_size)
    with _CA_CACHE_LOCK:
        hit = _CA_CACHE.get(path)
        if hit and hit[0] == key:
            return hit[1]
    cn: Optional[str] = None
    try:
        with open(path, "rb") as f:
            data = f.read(1 << 20)
        if data.lstrip().startswith(b"-----BEGIN"):
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if len(names) == 1 and isinstance(names[0].value, str) and names[0].value:
                cn = names[0].value
    except Exception as e:  # noqa: BLE001 — any failure: the file doesn't count
        print(f"group-gate: CA file {path} can't be used ({type(e).__name__}: {e}): "
              f"no certificate of its kind counts", flush=True)
        cn = None
    with _CA_CACHE_LOCK:
        _CA_CACHE[path] = (key, cn)
    return cn


def cert_method(cert_info: str) -> Optional[str]:
    """The method the presented leaf is a certificate for (contract §4
    "Certificate binding"): "yubikey_cert" when its issuer CN is the
    YubiKey CA's (pki_int), "browser_cert" when it is the browser CA's
    (pki_file), else None. Both CA files must be readable and their CNs
    different; otherwise no certificate counts (fail closed)."""
    if not cert_info:
        return None
    yubikey, browser = ca_subject_cn(YUBIKEY_CA_FILE), ca_subject_cn(BROWSER_CA_FILE)
    if yubikey is None or browser is None or yubikey == browser:
        return None
    issuer = leaf_cert_issuer_cn(cert_info)
    if issuer is None:
        return None
    if issuer == yubikey:
        return "yubikey_cert"
    if issuer == browser:
        return "browser_cert"
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


def rule_for_host(doc: dict, host: str) -> Optional[dict]:
    """The compiled rule of the normalised host's template (contract §4
    "How group-gate decides"): `core[host]` for a gated core host (missing
    = None: deny), the Hub's (`core["hub.<domain>"]`, missing = deny) for
    `auth.<domain>` (the Keycloak admin console's router: as powerful as
    the Hub; `core` never lists it), None for `mcp.<domain>`
    (never gated here); else `hosts[host]`, else `default`. A validated
    document only (every named template exists)."""
    templates = doc["templates"]
    if host in core_hosts():
        if host in gated_core_hosts():
            tid = doc["core"].get(host)
        elif host == f"auth.{DOMAIN}":
            tid = doc["core"].get(f"hub.{DOMAIN}")
        else:
            tid = None
    else:
        tid = doc["hosts"].get(host, doc["default"])
    return templates.get(tid) if tid is not None else None


def stepup_url(host: str, method: str, extra: bool) -> str:
    """The step-up URL (contract §5 "Step-up URL"): oauth2-proxy's
    /oauth2/start with `pc_method=<method>` (one of the six method ids or
    `passkey`; oauth2-proxy's loginURLParameters allow exactly those and
    Keycloak hands it to the extension as a client note), which asks for
    that one method on top of the Keycloak session's.

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

    No sign_out and no prompt=login in the chain: the browser keeps
    oauth2-proxy's cookie and Keycloak's session, so Keycloak asks only
    for the one method and issues a new token whose amr has both.
    """
    if method not in STEPUP_METHODS:
        raise ValueError(f"not a step-up method: {method!r}")
    if extra:
        return f"https://{host}/oauth2/start?" + urllib.parse.urlencode({"pc_method": method, "rd": "/"})
    query = urllib.parse.urlencode({"pc_method": method, "rd": f"https://{host}/"})
    return f"https://auth.{DOMAIN}/oauth2/start?{query}"


# ── Step-up, present-certificate and needs-stronger pages (contract §5) ──
# The needs-stronger copy is the Keycloak extension's
# (portcullis-keycloak: messages_en.properties `portcullis*`,
# portcullis-needs-stronger.ftl, NeedsStronger.java): same words, same
# lines, same element ids, so both pages read alike.

# portcullisMethod_<id> (every portcullisArticle_<id> is "a"); "passkey"
# is the step-up's any-passkey-kind ask.
METHOD_WORDS = {"password": "password", "passkey_synced": "passkey", "browser_cert": "browser certificate",
                "passkey_device": "device-bound passkey", "security_key": "security key",
                "yubikey_cert": "YubiKey certificate", "passkey": "passkey"}

SIGNIN_CSS = PORTAL_CSS + (
    "h1{margin-bottom:1rem}p{margin:.75rem 0}ul{margin:.5rem 0 .75rem 1.5rem}"
    ".btn{display:inline-block;background:#2563eb;color:#fff;padding:.5rem 1.1rem;border-radius:.4rem;"
    "font-weight:600;margin-right:.5rem}.btn:hover{text-decoration:none;background:#1d4ed8}"
    ".portcullis-sub{color:#94a3b8}"
)
SIGNIN_CSP = ("default-src 'none'; style-src 'sha256-"
              + base64.b64encode(hashlib.sha256(SIGNIN_CSS.encode()).digest()).decode()
              + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def _canonical(methods) -> List[str]:
    return [m for m in METHOD_IDS if m in methods]


def _methods_html(methods, bold: bool = False) -> str:
    """"a <b>password</b> and a <b>security key</b>" (the ftl's `methods`
    macro: only the method words bold, where asked)."""
    words = (html.escape(METHOD_WORDS[m]) for m in methods)
    return " and ".join(f"a <b>{w}</b>" if bold else f"a {w}" for w in words)


def signin_page_url(domain: str) -> str:
    """The Sign-in page on people.<domain> (contract §5.1): every person's
    one place for their sign-in methods."""
    return f"https://people.{domain}/signin"


def app_name(host: str) -> str:
    """The app's name from portal-apps.json (the first app with a URL on
    `host`), else the host."""
    apps, _ = load_portal_apps()
    for a in apps or []:
        for u in a.get("urls") or []:
            url = u.get("url") if isinstance(u, dict) else None
            if not isinstance(url, str):
                continue
            try:
                h = (urllib.parse.urlsplit(url).hostname or "").lower()
            except ValueError:
                continue
            name = a.get("name")
            if h == host and isinstance(name, str) and name.strip():
                return name
    return host


def _signin_page(title: str, body: str) -> bytes:
    """A 403 page: no refresh, no script, every value escaped by the caller."""
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<meta name=\"color-scheme\" content=\"dark\">"
            f"<title>{html.escape(title)}</title><style>{SIGNIN_CSS}</style></head><body>"
            f"<main class=\"container\"><h1>{html.escape(title)}</h1>{body}</main></body></html>").encode()


def render_stepup_page(app: str, method: str, url: str) -> bytes:
    """"<App> needs <method>" with a Continue button (#stepup-continue) to
    the step-up URL."""
    title = f"{app} needs a {METHOD_WORDS[method]}"
    e_url = html.escape(url, quote=True)
    return _signin_page(title, f"<p><a id=\"stepup-continue\" class=\"btn\" href=\"{e_url}\" autofocus>Continue</a></p>")


# The present-certificate page's words per certificate method.
CERTIFICATE_PAGE = {
    "yubikey_cert": ("YubiKey", "Insert your YubiKey and reload this page."),
    "browser_cert": ("browser", "Use the browser it is installed in and reload this page."),
}


def render_certificate_page(app: str, method: str) -> bytes:
    """The present-certificate page (#present-certificate) for `method`
    (yubikey_cert or browser_cert): signing in again can't help, this
    request must carry the person's own certificate of that kind."""
    kind, ask = CERTIFICATE_PAGE[method]
    return _signin_page(
        f"{app} needs your {kind} certificate",
        f"<div id=\"present-certificate\"><p>{html.escape(ask)}</p>"
        "<p class=\"portcullis-sub\">A revoked certificate, or another person&#x27;s, doesn&#x27;t count.</p></div>")


def render_needs_page(app: str, have: set, node, set_up: Optional[set], add_stronger: bool, domain: str) -> bytes:
    """The needs-stronger page (#needs-stronger), NeedsStronger.of's rules:
    one line per alternative of the rule; "— you don't have one yet" on a
    line that needs a passkey kind the person hasn't set up (only when
    `people` knows them: `set_up` None words nothing about it); "Set up a
    passkey" / "Set up a security key" for a missing passkey kind not set
    up while `add_stronger` is on or it is no stronger than the session's
    strongest method, otherwise — and always for passwords and
    certificates — "or ask your admin"; "Sign-in methods" always."""
    e = html.escape
    strongest = max((METHOD_TENTHS[m] for m in have), default=0)
    known = set_up if set_up is not None else set()
    lines, missing_all = [], []
    for alt in alternatives(node):
        not_set_up = False
        for m in _canonical(alt):
            if m in have:
                continue
            if m not in missing_all:
                missing_all.append(m)
            if m in PASSKEY_KINDS and set_up is not None and m not in known:
                not_set_up = True
        sub = " <span class=\"portcullis-sub\">— you don&#x27;t have one yet</span>" if not_set_up else ""
        lines.append(f"<li>{_methods_html(_canonical(alt))}{sub}</li>")
    passkey = security_key = ask_admin = False
    for m in missing_all:
        if m not in PASSKEY_KINDS:
            ask_admin = True  # passwords and certificates: only an admin sets them up
        elif m in known:
            continue
        elif add_stronger or METHOD_TENTHS[m] <= strongest:
            if m == "security_key":
                security_key = True
            else:
                passkey = True
        else:
            ask_admin = True
    e_app = e(app)
    if have:
        signed_in = f"You signed in with {_methods_html(_canonical(have), bold=True)}."
    else:
        signed_in = f"Your sign-in doesn&#x27;t count for {e_app} yet."
    acct = e(signin_page_url(domain), quote=True)
    links = []
    if passkey:
        links.append(f"<a id=\"portcullis-set-up-passkey\" class=\"btn\" href=\"{acct}\">Set up a passkey</a>")
    if security_key:
        links.append(f"<a id=\"portcullis-set-up-security-key\" class=\"btn\" href=\"{acct}\">Set up a security key</a>")
    links.append(f"<a id=\"portcullis-sign-in-methods\" href=\"{acct}\">Sign-in methods</a>")
    if ask_admin:
        links.append("<span class=\"portcullis-sub\">or ask your admin</span>")
    return _signin_page(
        f"{app} needs a stronger sign-in",
        f"<div id=\"needs-stronger\"><p>{signed_in} {e_app} accepts any one of:</p>"
        f"<ul>{''.join(lines)}</ul><p>{' '.join(links)}</p></div>")


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

    def _signin_answer(self, body: bytes, reason: str, log: str, stepup_url_value: str = ""):
        """403 with a sign-in page (contract §5): never a redirect."""
        METRICS.inc("group_gate_requests_total", endpoint=self._endpoint, result=reason)
        METRICS.inc("group_gate_stepups_total", reason=reason)
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", SIGNIN_CSP)
        self.send_header("Content-Length", str(len(body)))
        if stepup_url_value:
            self.send_header("X-Stepup-URL", stepup_url_value)
        self.end_headers()
        self.wfile.write(body)
        print(f"group-gate: {log}", flush=True)

    def _signin_check(self, doc: dict, host: str, kind: str, username: str,
                      cert_info: str, cert_ok: bool, raw_uri: str = "") -> bool:
        """The host's sign-in template (contract §4 "How group-gate
        decides"). True when the request was answered (denied, or one of
        the step-up / present-certificate / needs-stronger pages); False
        when the session meets the template (self._have / self._claims then
        hold what the opened log records).

        `cert_ok`: the request's client certificate (if any) passed the
        revocation check. A certificate method counts only when it did,
        every CRL list has been read, the leaf's issuer is that method's CA
        (cert_method), its CN is the session user and the token's
        preferred_username agrees (contract §4 "Certificate binding").

        On people.<domain>, the Sign-in page's paths (signin_path(): every
        normalised reading of `raw_uri` inside the set) take "any
        switched-on method" instead of the people template; no method on
        = deny."""
        if signin_path(host, raw_uri):
            on = _canonical(doc["methods"])
            rule = {"op": "any", "items": on} if on else None
            if rule is None:
                self._deny_policy(username, host, "no sign-in method is switched on")
                return True
        else:
            rule = rule_for_host(doc, host)
        if rule is None:
            self._deny_policy(username, host, "no sign-in template for this host")
            return True
        # Only X-Forwarded-Access-Token: oauth2-proxy sets it on every
        # forward-auth route and Traefik deletes client copies (it is in
        # every forwardAuth middleware's authResponseHeaders). Not the
        # Authorization header: on the Keycloak console's route
        # (portcullis-auth-console) that one is the client's own, and the
        # token's signature is not checked here.
        claims = decode_jwt_payload(self.headers.get("X-Forwarded-Access-Token", "") or "")
        amr = claims.get("amr")
        amr = amr if isinstance(amr, list) else []
        cert_cn = leaf_cert_cn(cert_info) if cert_info else None
        kind_of_cert = cert_method(cert_info) if cert_info else None
        bound = set()
        if (kind_of_cert and cert_ok and crl_ready() and claims.get("preferred_username") == username
                and cert_cn == username):
            bound = {kind_of_cert}
        enabled = set(doc["methods"])
        have = session_methods(amr, enabled, bound)
        if rule_satisfied(rule, have):
            self._have, self._claims = have, claims
            return False
        app = app_name(host)
        what = f"user={username} host={host} amr={amr} have={_canonical(have)}"
        held = held_cert_methods(amr)
        # Present-certificate page: a certificate method the token holds,
        # switched on, not bound on this request, that would meet the rule
        # (alone, else together with the other held one).
        unbound = [m for m in CERT_METHODS if m in held and m in enabled and m not in bound]
        ask = next((m for m in unbound if rule_satisfied(rule, have | {m})), None)
        if ask is None and unbound and rule_satisfied(rule, have | set(unbound)):
            ask = unbound[0]
        if ask is not None:
            self._signin_answer(render_certificate_page(app, ask), "present_certificate",
                                f"PRESENT-CERTIFICATE {what} method={ask} cert_kind={kind_of_cert} "
                                f"cert_cn={cert_cn!r} token_user={claims.get('preferred_username')!r} "
                                f"cert_ok={cert_ok} crl_ready={crl_ready()}")
            return True
        # A setup-link session (amr `inv`) is treated as not known in
        # `people` (contract §5): it has just registered a passkey the
        # Hub's inventory may not show yet, so a stale entry must never
        # turn the step-up into the needs-stronger page.
        set_up = None if "inv" in amr else doc["people"].get(username.lower())
        set_up = set(set_up) if set_up is not None else None
        method = choose_stepup(rule, have, set_up, held=held)
        if method is not None:
            url = stepup_url(host, method, extra=kind == "extra")
            self._signin_answer(render_stepup_page(app, method, url), "stepup",
                                f"STEPUP {what} pc_method={method}", url)
            return True
        self._signin_answer(render_needs_page(app, have, rule, set_up, doc["add_stronger"], DOMAIN),
                            "needs_stronger", f"NEEDS-STRONGER {what} set_up={set_up}")
        return True

    def _record_opened(self, username: str, host: str):
        """The opened log's line for this allowed request (first per
        (session, host)); never fails the request."""
        try:
            claims = getattr(self, "_claims", None) or {}
            session = log_session_id(claims, username)
            if not session or OPENED_LOG.seen(session, host):
                return
            OPENED_LOG.record(username.lower(), session, host, app_name(host), getattr(self, "_have", set()),
                              self.headers.get("X-Real-Ip", "") or "", self.headers.get("User-Agent", "") or "")
        except Exception as e:  # noqa: BLE001
            METRICS.inc("group_gate_opened_log_failures_total")
            print(f"group-gate: opened log failed ({type(e).__name__}: {e})", flush=True)

    def _cert_ok(self, cert_serials: List[int]) -> bool:
        """The presented certificate is not revoked (False when the
        revocation list can't be read)."""
        try:
            revoked = revoked_serials()
        except RevocationError:
            return False
        return bool(cert_serials) and not any(sn in revoked for sn in cert_serials)

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
        if user.lower() in DENY_USERS:
            self._deny("Access Denied", "<p>This account is a service account and cannot sign in.</p>",
                       f"DENIED portal user={user} reason=service account", "service_account")
            return
        # The portal is a core page (`core[<domain>]`): its router has no
        # portcullis-groups, so its template is checked here. A missing or
        # broken policy file denies (no template is known).
        cert_info = self.headers.get(CERT_INFO_HEADER, "")
        try:
            if not DOMAIN_OK:
                raise PolicyError(f"PORTCULLIS_DOMAIN={DOMAIN!r} is not a valid hostname")
            doc = load_policy_file()
            if self._signin_check(doc, DOMAIN, "core", user, cert_info,
                                  self._cert_ok(cert_serials_from_info(cert_info)) if cert_info else False):
                return
            groups -= expired_groups(doc, user)
        except PolicyError as e:
            self._deny_policy(user, DOMAIN, str(e))
            return
        METRICS.inc("group_gate_requests_total", endpoint="portal", result="allow")
        self._record_opened(user, DOMAIN)
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
        # Per request (a kept-alive connection reuses the handler).
        self._have, self._claims = set(), {}
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
        # Every other path: the full checks (there is no /authenticated).
        self._endpoint = "gate"

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
                        "<p>The certificate revocation list is unavailable, so certificates "
                        "cannot be accepted right now.</p>",
                        f"DENIED user={user} host={host} reason=revocation list error: {e}",
                        "revocation_unavailable",
                    )
                    return
                hit = [sn for sn in cert_serials if sn in revoked]
                if hit:
                    self._deny(
                        "Access Denied",
                        "<p>Your certificate has been <b>revoked</b>. Remove it from this browser "
                        "(or use another YubiKey) and sign in another way.</p>",
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
            path_rules = path_rules_for(policy_doc, host)
            expired = expired_groups(policy_doc, username)
        except PolicyError as e:
            self._deny_policy(user, host, str(e))
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

        # --- Group check ---
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
        raw_uri = self.headers.get("X-Forwarded-Uri", "")
        if path_rules:
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

        # --- Sign-in template, only after the membership checks: someone
        # outside the app's groups gets the plain 403 above, never a page
        # naming the app's rule. A revoked certificate was denied at the
        # start, so one still here passed the revocation check.
        if self._signin_check(policy_doc, host, kind, username, cert_info, bool(cert_serials), raw_uri):
            return

        self._allow(groups_header, username, host)
        self._record_opened(username, host)

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
    print(f"group-gate: revocation: file={REVOKED_FILE} crls={' '.join(CRL_URLS) or '(none)'} "
          f"deltas={' '.join(DELTA_CRL_URLS) or '(none)'} refresh={CRL_REFRESH_SECONDS:g}s", flush=True)
    if not CRL_URLS or not DELTA_CRL_URLS:
        print("group-gate: WARNING GATE_CRL_URLS / GATE_DELTA_CRL_URLS unset: only the serial file "
              "revokes certificates", flush=True)
    print(f"group-gate: certificate kinds: yubikey CA={YUBIKEY_CA_FILE} ({ca_subject_cn(YUBIKEY_CA_FILE)!r}), "
          f"browser CA={BROWSER_CA_FILE} ({ca_subject_cn(BROWSER_CA_FILE)!r}); opened log={OPENED_DIR}", flush=True)
    if CRL_CACHE is not None:
        threading.Thread(target=CRL_CACHE.run_forever, daemon=True, name="crl-refresh").start()
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
