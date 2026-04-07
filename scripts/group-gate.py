#!/usr/bin/env python3
"""Group-gate: per-app group authorization middleware for Traefik ForwardAuth.

Reads X-Forwarded-Host to determine which app is being accessed,
then checks X-Auth-Request-Groups (set by oauth2-proxy) for the
required users_<app> group. Returns 200 (allow) or 403 (deny).

Config: GATE_MAP env var or /etc/group-gate/map.conf file.
Format: one "subdomain=required_group" per line.
"""

import os
from http.server import HTTPServer, BaseHTTPRequestHandler

LISTEN_PORT = int(os.environ.get("GATE_PORT", "8080"))

def load_map():
    """Load subdomain→group mapping from env or file."""
    mapping = {}
    # From file
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
    # From env (overrides file)
    env_map = os.environ.get("GATE_MAP", "")
    for pair in env_map.split(","):
        pair = pair.strip()
        if "=" in pair:
            sub, group = pair.split("=", 1)
            mapping[sub.strip()] = group.strip()
    return mapping

GATE = load_map()
print(f"group-gate: loaded {len(GATE)} mappings: {GATE}")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get("X-Forwarded-Host", "")
        groups_raw = self.headers.get("X-Auth-Request-Groups", "")
        user = self.headers.get("X-Auth-Request-Email", "") or self.headers.get("X-Auth-Request-User", "unknown")

        # Extract subdomain (first component of host)
        subdomain = host.split(".")[0] if host else ""

        # Debug: log first few requests
        if not hasattr(Handler, '_debug_count'):
            Handler._debug_count = 0
        if Handler._debug_count < 3:
            Handler._debug_count += 1
            print(f"group-gate: req#{Handler._debug_count} host={host} sub={subdomain} user={user} groups_raw='{groups_raw}' required={GATE.get(subdomain, 'NONE')}")

        # Look up required group
        required = GATE.get(subdomain)
        if not required:
            # No mapping = no group restriction, allow through
            self.send_response(200)
            email = self.headers.get("X-Auth-Request-Email", "")
            if email:
                self.send_header("X-Forwarded-User", email)
            self.end_headers()
            return

        # Parse groups (comma or space separated)
        groups = {g.strip().strip('"') for g in groups_raw.replace(",", " ").split() if g.strip()}

        if required in groups:
            self.send_response(200)
            # Pass user identity as X-Forwarded-User for header-auth apps
            email = self.headers.get("X-Auth-Request-Email", "")
            if email:
                self.send_header("X-Forwarded-User", email)
            self.end_headers()
        else:
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                f"<h1>Access Denied</h1><p>User <b>{user}</b> is not authorized to access <b>{subdomain}</b>.</p>"
                f"<p>Required group: <code>{required}</code></p>".encode()
            )
            print(f"group-gate: DENIED user={user} host={host} need={required} have={groups}")

    def log_message(self, fmt, *args):
        # Suppress default per-request logs (denials logged above)
        pass

    def do_first_debug(self):
        """Log first request details for verification, then stop."""
        host = self.headers.get("X-Forwarded-Host", "")
        groups = self.headers.get("X-Auth-Request-Groups", "NONE")
        user = self.headers.get("X-Auth-Request-Email", "")
        print(f"group-gate: DEBUG host={host} user={user} groups={groups}")


if __name__ == "__main__":
    print(f"group-gate: listening on :{LISTEN_PORT}")
    HTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
