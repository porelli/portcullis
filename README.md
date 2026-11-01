# Portcullis

Self-hosted, hardware-backed authentication gateway. YubiKey tap to access everything.

Inspired by Amazon's Midway — phishing-resistant authentication with YubiKeys,
a user directory, and SAML/OIDC identity provider for downstream applications.

## Quick Start

```bash
git clone git@github.com:porelli/portcullis.git && cd portcullis
./portcullis init
```

`portcullis init` asks for your domain and DNS provider, writes `.env` (0600) with
every secret randomly generated, initialises Vault and the CA, starts all
services, configures the identity provider, and prints the URLs.

Everything else goes through the same command — `./portcullis help`:

```
init | up | down | upgrade | status [--json|--textfile] | version
backup [--offsite] | backup verify [--local] | backup schedule --systemd | restore [--from-offsite]
config apply [--bundle-only] | config init | dns setup [--check]
vault init | vault unseal | vault rotate-enroll-secret | pki setup [--force] [--with-server-cert]
keycloak configure | oidc register
cert enroll | cert renew | cert revoke | cert list | cert sync
```

`./portcullis <command> --help` documents each one.

## Two Ways to Authenticate

| Method | How it works | Enrollment | Best for |
|--------|-------------|------------|----------|
| **WebAuthn** | Tap YubiKey in browser → Keycloak login | Visit enrollment page, tap key. Done. | Most users, browser apps |
| **mTLS** | Client certificate on YubiKey → TLS handshake | CLI script or paste CSR in web UI | APIs, CLI tools, service-to-service |

Both methods are phishing-resistant and hardware-backed. Users can have both.

**WebAuthn enrollment** requires zero local software — just a browser and a YubiKey.
**mTLS enrollment** requires `ykman` CLI to write certificates to the YubiKey's PIV slot.

## Architecture

```
                      *.<your-domain> :443
                    (single wildcard cert, ACME)
                              │
                              ▼
                    ┌───────────────────┐
                    │     Traefik       │
                    │  mTLS + forward   │
                    │  auth to Keycloak │
                    └────────┬──────────┘
                             │
         ┌───────────┬───────┼───────┬────────────┐
         ▼           ▼       ▼       ▼            ▼
    ┌─────────┐ ┌────────┐ ┌─────┐ ┌──────┐ ┌─────────┐
    │ Enroll  │ │Keycloak│ │LLDAP│ │ Vault│ │ Your    │
    │   UI    │ │WebAuthn│ │user │ │ PKI  │ │ apps    │
    │         │ │SAML/   │ │dir  │ │  CA  │ │         │
    │         │ │OIDC IdP│ │     │ │      │ │         │
    └─────────┘ └────────┘ └─────┘ └──────┘ └─────────┘
```

| Component | Role | URL |
|-----------|------|-----|
| **Traefik** | Reverse proxy, wildcard TLS, mTLS, forward auth, dashboard | `traefik.<domain>` |
| **Enrollment UI** | YubiKey enrollment hub (WebAuthn + mTLS) | `enroll.<domain>` |
| **Hub** | App catalog — enable/disable templates, manage sources | `hub.<domain>` |
| **Keycloak** | WebAuthn, SAML/OIDC IdP, X.509 auth | `auth.<domain>` |
| **LLDAP** | Lightweight user/group directory with web UI | `directory.<domain>` |
| **Vault PKI** | Private CA, issues client certificates (30 days, self-service renewal) | `localhost:8200` |
| **Forward Auth** | OIDC bridge — redirects unauthenticated browser users to Keycloak | (internal) |

## Access Tiers

| Tier | How | Use case |
|------|-----|----------|
| **mTLS only** | `tls.options=protected` | Requires PIV client cert. High-security admin tools, APIs. |
| **WebAuthn** | `tls.options=public` + `portcullis-auth@docker` | Redirects to Keycloak → tap YubiKey. Browser apps. |
| **Both** | `tls.options=authaware` + `portcullis-auth@docker` | mTLS if cert present, WebAuthn fallback. Best UX. |
| **Public** | `tls.options=public` | No auth. Public pages. |

## Workflow

### 1. First sign-in (bootstrap admin)

`./portcullis init` ends with a **one-time setup link** for the LLDAP
`admin`. Open it, click "Register my key", touch the YubiKey (set / enter
its PIN): you are signed in and land in the Hub. There is no password
anywhere in the browser sign-in; a new link any time (lost key, expired
link): `./portcullis invite admin --to hub` on the server.

### 2. Users and their keys

Create users and groups in the Hub (**Users & Groups**, or LLDAP at
`https://directory.<domain>`, which keeps its own login). Each new user gets
a setup link (Hub, or `./portcullis invite <user>`): open it, register the
key, signed in — every later sign-in is one touch ("Sign in with Passkey").
The link works once, expires after 72 h and replaces earlier links.
A second link adds another key (a spare); for a lost or stolen key use
`./portcullis invite <user> --replace-keys`, which removes the old keys first.
`https://<domain>/` lists the apps a user may open (and the Hub for admins).

**mTLS (CLI — for advanced users):**
```bash
./portcullis cert enroll <username> <email>
```

Or use the web UI at `https://enroll.<domain>` → "mTLS Certificate" for a guided flow.
Certificates last 30 days (`CLIENT_CERT_TTL`); users renew their own at
`https://enroll.<domain>/self` (same key, cert still valid). With the cert
selected in the browser, users can also log in to Keycloak by X.509.

### 3. Add services

**WebAuthn-protected app** (most common):
```yaml
labels:
  traefik.enable: "true"
  traefik.http.routers.myapp.rule: Host(`myapp.${PORTCULLIS_DOMAIN}`)
  traefik.http.routers.myapp.entrypoints: websecure
  traefik.http.routers.myapp.tls.options: public
  traefik.http.routers.myapp.middlewares: portcullis-auth@docker,security-headers@file
  traefik.http.services.myapp.loadbalancer.server.port: "8080"
```

**mTLS-protected app** (high security):
```yaml
labels:
  traefik.enable: "true"
  traefik.http.routers.myapp.rule: Host(`myapp.${PORTCULLIS_DOMAIN}`)
  traefik.http.routers.myapp.entrypoints: websecure
  traefik.http.routers.myapp.tls.options: protected
  traefik.http.routers.myapp.middlewares: client-headers@file,security-headers@file
  traefik.http.services.myapp.loadbalancer.server.port: "8080"
```

**Both (mTLS if available, WebAuthn fallback):**
```yaml
labels:
  traefik.http.routers.myapp.tls.options: authaware
  traefik.http.routers.myapp.middlewares: client-headers@file,portcullis-auth@docker,security-headers@file
```

See `docker-compose.apps.yml` for complete examples.

**Non-Docker services** — edit `traefik/dynamic/external-services.yml`.

**SAML/OIDC apps** — register in Keycloak at `https://auth.<domain>/admin/`.

## Guides

| Guide | Description |
|-------|-------------|
| [Adding a Domain](docs/adding-a-domain.md) | DNS setup, Cloudflare config, wildcard certs, one domain per installation, local dev |
| [SAML App: Nextcloud](docs/saml-app-nextcloud.md) | Full walkthrough — deploy Nextcloud, register in Keycloak, configure SAML SSO |
| [Non-SAML App: Kanboard](docs/non-saml-app-kanboard.md) | Header-based auth — deploy Kanboard, extract CN from mTLS, reverse proxy auth pattern |
| [Backups](docs/backups.md) | Consistent backups, off-host with restic, verify, schedule, restore (also on a new host) |
| [Monitoring](docs/monitoring.md) | Opt-in profile: Prometheus, Alertmanager, Grafana at `metrics.<domain>`, alerts |
| [Hardening](docs/hardening.md) | Socket proxies, per-service hardening, secrets ownership, header trust, identity |

The Kanboard guide includes a **general pattern table** for configuring header-based
auth in common apps (Gitea, Grafana, Wiki.js, pgAdmin, etc.).

## File Structure

```
├── docker-compose.yml              # All core services
├── docker-compose.override.example.yml  # Override template (copy to config/)
├── docker-compose.apps.yml         # Example apps (all tiers + VPN)
├── config/                         # YOUR config (separate git repo, gitignored)
├── headscale/
│   └── config.yaml                # Headscale config (OIDC → Keycloak)
├── docs/
│   ├── adding-a-domain.md          # DNS, certs, single-domain scope
│   ├── certificates.md             # TLS, mTLS, client certs, revocation, Vault
│   ├── hardening.md                # Socket proxies, container hardening, exceptions
│   ├── backups.md                  # Consistent + off-host (restic) backups, verify, restore
│   ├── monitoring.md               # Monitoring profile: Prometheus, alerts, Grafana
│   ├── saml-app-nextcloud.md       # SAML app integration guide
│   └── non-saml-app-kanboard.md    # Header-based auth guide
├── portcullis                     # The admin CLI (./portcullis help)
├── monitoring/                     # Prometheus config + alert rules (+ tests), blackbox, Grafana provisioning/dashboard
├── CHANGELOG.md                    # Keep a Changelog; releases are vX.Y.Z tags (release.yml)
├── scripts/lib/                    # CLI libraries, one per area (vault, pki, certs, keycloak, ...)
├── group-gate/
│   ├── group-gate.py               # Per-subdomain group / path / policy / revocation gate
│   ├── Dockerfile                  # Image portcullis-group-gate (pinned python base)
│   ├── requirements.txt            # cryptography, PyJWT (pinned with hashes)
│   └── group-gate-map.conf         # Core subdomain → required LLDAP group
├── templates/                      # Hub-generated copies of enabled app templates (gitignored)
├── vault/                          # Vault server config (raft), auto-unseal entrypoint, enroll policy
├── secrets/                        # Vault root token, unseal key, enroll AppRole creds (gitignored, 0700)
├── tests/                          # Unit tests (CLI, shell libs, group-gate); e2e/ browser login test (CI)
├── enroll/                         # Enrollment web UI (Go)
│   ├── main.go
│   ├── Dockerfile
│   └── web/                        # HTML templates
├── traefik/                        # Static config: env vars in docker-compose.yml
│   └── dynamic/
│       ├── tls.yml                 # TLS options (protected/authaware/public)
│       ├── middlewares.yml         # Client cert headers, rate limits, security headers
│       ├── external-services.yml   # Non-Docker services
│       └── local/                  # Your custom routers/middlewares (gitignored)
└── keycloak/
    └── realm-export.json           # Portcullis realm + LLDAP + WebAuthn + X.509
```

## Customization & Versioning

All user config lives in `config/` — a **separate git repo** inside the project.
Portcullis ignores it, so `git pull` never conflicts with your settings.

```
portcullis/              ← git pull updates this (upstream)
  config/                ← your own git repo (private)
    .env                 ← secrets, domain, DNS provider
    docker-compose.override.yml  ← compose customizations
    traefik/*.yml        ← custom Traefik routes
```

### Setup

```bash
# `portcullis init` creates config/ automatically, or run it yourself:
./portcullis config init

# Point it at your private repo (.env holds every secret):
./portcullis config init --remote git@github.com:you/my-portcullis-config.git

# Or restore an existing config on a new machine:
./portcullis config init --from git@github.com:you/my-portcullis-config.git
```

### Day-to-day workflow

```bash
# Change settings
vi config/.env
vi config/docker-compose.override.yml

# Version your changes
cd config && git add -A && git commit -m "update passwords" && git push

# Update Portcullis (no conflicts)
cd .. && git pull && ./portcullis upgrade
```

| What to customize | File in `config/` | Mechanism |
|-------------------|--------------------|-----------|
| Secrets, domain, DNS provider | `.env` | Symlinked to project root |
| Compose overrides (ports, volumes, limits) | `docker-compose.override.yml` | Docker Compose auto-merges |
| Custom Traefik routers/middlewares | `traefik/*.yml` | Symlinked into `traefik/dynamic/local/`, hot-reloaded |

Enabled apps and template sources are Hub state (in the `hub_data` volume), managed in the Hub UI.

## Integration

Portcullis is an auth layer that works with existing platforms:

| Platform | How to integrate |
|----------|-----------------|
| **YunoHost** | LLDAP as LDAP provider, Keycloak as SAML IdP |
| **Headscale** | OIDC → Keycloak for node registration, Headplane admin UI behind Traefik |
| **NetBird** | OIDC → Keycloak for peer auth, dashboard + management behind Traefik |
| **Coolify** | Traefik mTLS/forward-auth in front, Coolify handles deploys |
| **Kubernetes** | Traefik as Ingress Controller, cert-manager for ACME, Keycloak as OIDC provider |
| **Any Docker app** | Add Traefik labels to join the network |

## Production Considerations

- **Vault**: runs in server mode (raft storage) and auto-unseals from `secrets/` on the host — back up `secrets/vault-init.json` (root token + unseal key) **offline**
- **Secrets**: `portcullis init` generates every password and secret into `.env` (0600); docker compose refuses to start if one is missing — there are no default passwords
- **Revocation**: `./portcullis cert revoke <serial>` — enforced by group-gate on every request (Traefik itself doesn't check CRLs), by Keycloak's X.509 login (CRL) and by the mTLS binding (an `amr=mtls` session needs the unrevoked cert on every request); see [docs/certificates.md](docs/certificates.md)
- **Renewal**: client certs live `CLIENT_CERT_TTL` (default 30 days); users renew their own at `https://enroll.<domain>/self` with the cert still valid, `portcullis status` warns 7 days ahead
- **Backups**: `./portcullis backup` (also run by `upgrade`) makes a consistent backup without stopping anything (Vault raft snapshot, `pg_dump`, SQLite online backup, `.env`, `certs/`, `secrets/`); `--offsite` uploads it to a restic repository, encrypted with `BACKUP_PASSWORD` — **store that password offline**, the backups contain the Vault root token and unseal key. `backup verify` restores and checks it, `backup schedule --systemd` runs it daily, `restore [--from-offsite]` puts it back; see [docs/backups.md](docs/backups.md)
- **Monitoring**: `COMPOSE_PROFILES=monitoring` adds Prometheus, Alertmanager and Grafana (`https://metrics.<domain>`, `lldap_admin`) with alerts for a sealed Vault, expiring certificates, a stale CRL, deny spikes, down services and old backups; see [docs/monitoring.md](docs/monitoring.md)
- **Identity**: apps receive the LLDAP **username** as `X-Forwarded-User` and the email separately as `X-Forwarded-Email` — users can edit their own email in LLDAP, so never key accounts on it; see [docs/hardening.md](docs/hardening.md#header-trust)
- **Network**: `portcullis-proxy` uses a fixed subnet (`PORTCULLIS_PROXY_SUBNET`, default `172.31.250.0/24`) with Traefik pinned at `PORTCULLIS_TRAEFIK_IP` — change in `.env` only if it collides with a host network (before `init`; later the network has to be recreated, `./portcullis up` explains how)
- **Docker socket**: only the two socket proxies mount it — Traefik gets read-only containers/networks/events, the Hub what `docker compose` needs (no swarm/system/plugins/secrets/build); see [docs/hardening.md](docs/hardening.md)
- **Containers**: every core image is pinned by digest; services run with `no-new-privileges`, `cap_drop: ALL`, read-only root filesystems, non-root users and memory/pid limits where the image allows — exceptions in [docs/hardening.md](docs/hardening.md)
- **Hub image**: `HUB_IMAGE` (default `ghcr.io/porelli/portcullis-hub:edge` on `main`; a core release pins a released Hub tag by digest); `./portcullis version` shows the core version and the Hub image in use. The Hub gets a generated env subset (`secrets/hub/core.env`), never the core `.env`, and no LLDAP credentials
- **Releases**: `vX.Y.Z` tags; `release.yml` runs the full CI, requires a released, digest-pinned `HUB_IMAGE` default and a `CHANGELOG.md` section, and publishes notes plus a tarball with its sha256. Dependabot proposes weekly image/action/module updates; CI fails on any unpinned image or action
- **PIV PIN**: enforce PIN changes from default (123456) for mTLS users
