#!/usr/bin/env python3
"""Group-gate: per-app authorization middleware for Traefik ForwardAuth.

Two checks, run in order:
  1. Auth policy — does the current session's ACR/AMR satisfy the app's
     required factor set (one of mtls/webauthn/password, with AND/OR
     semantics)? If not, 403 with a stepup URL so the user can re-auth
     at the needed Level of Authentication.
  2. Group — does the user belong to the subdomain's required LLDAP
     group (users_<app>)? If not, 403.

Config sources:
  - /etc/group-gate/map.conf — subdomain=required_group (existing)
  - /hub-data/group-gate-policy.json — written by the Hub with per-app
    {factors, op} policies plus a global default. Optional; no file
    means every app falls through to the group check only.

Access token is read from X-Forwarded-Access-Token (oauth2-proxy with
PASS_ACCESS_TOKEN=true). The JWT signature is NOT verified here — it was
already verified upstream by oauth2-proxy before the request reaches us.
We only decode the payload to read the acr/amr claims.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional, Tuple

LISTEN_PORT = int(os.environ.get("GATE_PORT", "8080"))
POLICY_FILE = os.environ.get("GATE_POLICY_FILE", "/hub-data/group-gate-policy.json")

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


def load_group_map():
    mapping = {}
    conf = os.environ.get("GATE_MAP_FILE", "/etc/group-gate/map.conf")
    if os.path.isfile(conf):
        with open(conf) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    sub, group = line.split("=", 1)
                    mapping[sub.strip()] = group.strip()
    env_map = os.environ.get("GATE_MAP", "")
    for pair in env_map.split(","):
        pair = pair.strip()
        if "=" in pair:
            sub, group = pair.split("=", 1)
            mapping[sub.strip()] = group.strip()
    return mapping


def load_policy_file():
    """Return {policies: {app_id: {factors: [...], op: str}}, default: {...}} or empty dict."""
    try:
        with open(POLICY_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


GATE = load_group_map()
print(f"group-gate: loaded {len(GATE)} group mappings: {GATE}", flush=True)


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
    if subdomain in policies:
        return policies[subdomain]
    default = policy_doc.get("default")
    if default and default.get("factors") is not None:
        return default
    return None


def evaluate_policy(policy: dict, acr: str, amr: list) -> Tuple[bool, str, int]:
    """Return (allowed, reason, required_loa).

    required_loa is the LoA the user needs to reach to satisfy the policy;
    callers can encode it in a stepup URL when allowed=False.
    """
    factors = [f for f in (policy.get("factors") or []) if f in FACTOR_TO_AMR]
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

    The flow is: sign out of oauth2-proxy (so it doesn't short-circuit back
    to the existing too-weak session), then /oauth2/start?acr_values=<acr>&rd=...
    which oauth2-proxy forwards to Keycloak (per-request acr_values enabled
    via loginURLParameters in alpha config). Keycloak triggers the matching
    LoA conditional subflow and prompts the user for the missing factor.
    """
    loa_to_acr = {0: "public", 1: "pwd", 2: "hwk", 3: "mtls"}
    acr = loa_to_acr.get(needed_loa, "pwd")
    start_q = urllib.parse.urlencode({"acr_values": acr, "rd": f"https://{host}/"})
    start_url = f"https://{host}/oauth2/start?{start_q}"
    sign_out_q = urllib.parse.urlencode({"rd": start_url})
    return f"https://{host}/oauth2/sign_out?{sign_out_q}"


def safe_factor_name(amr: str) -> str:
    for factor, amr_value in FACTOR_TO_AMR.items():
        if amr_value == amr:
            return factor
    return amr


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get("X-Forwarded-Host", "")
        subdomain = host.split(".")[0] if host else ""
        user = self.headers.get("X-Auth-Request-Email", "") or self.headers.get("X-Auth-Request-User", "unknown")

        # Per-request policy reload — the Hub rewrites this file on each
        # policy change. Cheap (<1kb JSON, rare reads).
        policy_doc = load_policy_file()
        policy = resolve_policy(policy_doc, subdomain)

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

            allowed, reason, required_loa = evaluate_policy(policy, acr, amr)
            if not allowed:
                url = stepup_url(host or "localhost", required_loa, policy.get("factors") or [])
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.send_header("X-Stepup-URL", url)
                self.end_headers()
                factors = policy.get("factors") or []
                op = policy.get("op") or "any"
                have = ", ".join(safe_factor_name(a) for a in amr) or "none"
                need_desc = f"{op} of: {', '.join(factors)}" if len(factors) > 1 else factors[0] if factors else "authentication"
                # If a hardware factor is in play, surface a link to the
                # Keycloak account console so users who haven't enrolled yet
                # can register a WebAuthn key. Parent domain comes from
                # X-Forwarded-Host so the page works regardless of which app
                # served the 403.
                needs_hardware = any(f in ("mtls", "webauthn") for f in factors)
                parent_domain = ".".join(host.split(".")[1:]) if host and "." in host else ""
                account_url = (
                    f"https://auth.{parent_domain}/realms/portcullis/account/account-security/signing-in"
                    if parent_domain else ""
                )
                enrollment_block = ""
                if needs_hardware and account_url:
                    enrollment_block = (
                        f"<p style=\"background:#fff7ed;border:1px solid #fed7aa;padding:.75rem 1rem;border-radius:.5rem;margin-top:1rem\">"
                        f"<b>No hardware key yet?</b> "
                        f"<a href=\"{account_url}\" target=\"_blank\" rel=\"noopener\">Open the account console</a> "
                        f"to register a security key, then return and retry.</p>"
                    )
                # Meta-refresh bumps the user through the sign-out + fresh
                # authorize flow automatically after 2 seconds. The explicit
                # link is the accessible fallback.
                self.wfile.write(
                    (
                        "<!doctype html><html><head>"
                        f"<meta http-equiv=\"refresh\" content=\"2;url={url}\">"
                        "<title>Additional authentication required</title>"
                        "<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:32rem;"
                        "margin:4rem auto;padding:2rem;color:#1e293b;line-height:1.55}"
                        "h1{font-size:1.5rem;margin:0 0 1rem}"
                        "code{background:#f1f5f9;padding:.15rem .4rem;border-radius:.25rem;font-size:.95em}"
                        "a{color:#3b82f6}</style></head><body>"
                        "<h1>Additional authentication required</h1>"
                        f"<p><b>{subdomain}</b> requires {need_desc}. "
                        f"Your current session was authenticated with <code>{have}</code>, which does not satisfy the app's policy.</p>"
                        f"<p>You will be redirected to re-authenticate in a moment. "
                        f"If nothing happens, <a href=\"{url}\">click here</a>.</p>"
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

        # --- Group check (existing behavior) ---
        groups_raw = self.headers.get("X-Auth-Request-Groups", "")
        required_group = GATE.get(subdomain)
        if not required_group:
            self.send_response(200)
            email = self.headers.get("X-Auth-Request-Email", "")
            if email:
                self.send_header("X-Forwarded-User", email)
            self.end_headers()
            return

        groups = {g.strip().strip('"') for g in groups_raw.replace(",", " ").split() if g.strip()}
        if required_group in groups:
            self.send_response(200)
            email = self.headers.get("X-Auth-Request-Email", "")
            if email:
                self.send_header("X-Forwarded-User", email)
            self.end_headers()
            return

        self.send_response(403)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            f"<h1>Access Denied</h1><p>User <b>{user}</b> is not authorized to access <b>{subdomain}</b>.</p>"
            f"<p>Required group: <code>{required_group}</code></p>".encode()
        )
        print(
            f"group-gate: DENIED user={user} host={host} need={required_group} have={groups}",
            flush=True,
        )

    def log_message(self, fmt, *args):
        # Default per-request logs are noisy; explicit logging above.
        pass


if __name__ == "__main__":
    print(f"group-gate: listening on :{LISTEN_PORT}, policy_file={POLICY_FILE}", flush=True)
    HTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
