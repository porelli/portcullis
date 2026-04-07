# Portcullis

Self-hosted, hardware-backed authentication gateway. YubiKey tap to access everything.

Inspired by Amazon's Midway — phishing-resistant authentication with YubiKeys,
a user directory, and SAML/OIDC identity provider for downstream applications.

## Quick Start

```bash
git clone git@github.com:porelli/portcullis.git && cd portcullis
./scripts/bootstrap.sh
```

The bootstrap script generates passwords, starts all services, initializes the CA,
configures the identity provider, and prints URLs and credentials.

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
| **Vault PKI** | Private CA, issues short-lived client certificates | `localhost:8200` |
| **Forward Auth** | OIDC bridge — redirects unauthenticated browser users to Keycloak | (internal) |

## Access Tiers

| Tier | How | Use case |
|------|-----|----------|
| **mTLS only** | `tls.options=protected` | Requires PIV client cert. High-security admin tools, APIs. |
| **WebAuthn** | `tls.options=public` + `portcullis-auth@docker` | Redirects to Keycloak → tap YubiKey. Browser apps. |
| **Both** | `tls.options=authaware` + `portcullis-auth@docker` | mTLS if cert present, WebAuthn fallback. Best UX. |
| **Public** | `tls.options=public` | No auth. Public pages. |

## Workflow

### 1. Manage users

Open `https://directory.<domain>` — add users and groups in LLDAP.
Keycloak syncs from LLDAP automatically.

### 2. Enroll YubiKeys

**WebAuthn (browser — zero install):**
1. Visit `https://enroll.<domain>`
2. Click "WebAuthn (Browser)"
3. Log into Keycloak (first time: username + temporary password from LLDAP)
4. Browser prompts "Touch your security key" → tap YubiKey
5. Done. Future logins just require a tap.

**mTLS (CLI — for advanced users):**
```bash
./scripts/enroll-yubikey.sh <username> <email>
```

Or use the web UI at `https://enroll.<domain>` → "mTLS Certificate" for a guided flow.

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
| [Adding a Domain](docs/adding-a-domain.md) | DNS setup, Cloudflare config, wildcard certs, multiple domains, local dev |
| [SAML App: Nextcloud](docs/saml-app-nextcloud.md) | Full walkthrough — deploy Nextcloud, register in Keycloak, configure SAML SSO |
| [Non-SAML App: Kanboard](docs/non-saml-app-kanboard.md) | Header-based auth — deploy Kanboard, extract CN from mTLS, reverse proxy auth pattern |

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
│   ├── adding-a-domain.md          # DNS, certs, multiple domains
│   ├── saml-app-nextcloud.md       # SAML app integration guide
│   └── non-saml-app-kanboard.md    # Header-based auth guide
├── scripts/
│   ├── bootstrap.sh                # One-command setup
│   ├── setup-vault-pki.sh          # Initialize CA hierarchy
│   ├── configure-keycloak.sh       # Import realm config
│   ├── init-config.sh              # Initialize config/ directory
│   ├── upgrade.sh                  # Safe upgrade for existing deployments
│   ├── restore.sh                  # Restore from backup
│   ├── status.sh                   # Health dashboard
│   ├── revoke-cert.sh              # Revoke client certificate + update CRL
│   ├── register-oidc-clients.sh    # Register OIDC clients in Keycloak
│   ├── enroll-yubikey.sh           # CLI mTLS enrollment
│   └── renew-yubikey.sh            # CLI mTLS renewal
├── hub/                            # App catalog web UI (Go)
│   ├── main.go
│   ├── Dockerfile
│   └── web/                        # HTML templates
├── templates/                      # App templates (local catalog)
│   ├── headscale/                  # VPN — Headscale + Headplane
│   ├── netbird/                    # VPN — NetBird + COTURN
│   ├── grafana/                    # Monitoring
│   ├── wiki/                       # Wiki.js
│   ├── vault-ui/                   # Vault web UI
│   └── docs/                       # Public docs site
├── enroll/                         # Enrollment web UI (Go)
│   ├── main.go
│   ├── Dockerfile
│   └── web/                        # HTML templates
├── traefik/
│   ├── traefik.yml                 # Static config
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
    hub/state.yaml       ← enabled apps & sources
```

### Setup

```bash
# Bootstrap creates config/ automatically, or init manually:
./scripts/init-config.sh

# Point it at your private repo:
./scripts/init-config.sh --remote git@github.com:you/my-portcullis-config.git

# Or restore an existing config on a new machine:
./scripts/init-config.sh --from git@github.com:you/my-portcullis-config.git
```

### Day-to-day workflow

```bash
# Change settings
vi config/.env
vi config/docker-compose.override.yml

# Version your changes
cd config && git add -A && git commit -m "update passwords" && git push

# Update Portcullis (no conflicts)
cd .. && git pull && docker compose up -d
```

| What to customize | File in `config/` | Mechanism |
|-------------------|--------------------|-----------|
| Secrets, domain, DNS provider | `.env` | Symlinked to project root |
| Compose overrides (ports, volumes, limits) | `docker-compose.override.yml` | Docker Compose auto-merges |
| Custom Traefik routers/middlewares | `traefik/*.yml` | Symlinked into `traefik/dynamic/local/`, hot-reloaded |
| Enabled apps + template sources | `hub/state.yaml` | Managed by Hub UI |

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

- **Vault**: switch from dev mode to proper storage + auto-unseal
- **Passwords**: the bootstrap script generates random values — keep them safe
- **Forward Auth secret**: generate a strong `FORWARD_AUTH_SECRET` and `FORWARD_AUTH_CLIENT_SECRET`
- **OCSP/CRL**: enable in Keycloak's X.509 config for cert revocation checking
- **Renewal**: automate `renew-yubikey.sh` via cron/launchd (mTLS users only)
- **Backups**: Vault (CA keys), PostgreSQL (Keycloak), LLDAP data volume
- **Docker socket**: consider a socket proxy for Traefik for hardening
- **PIV PIN**: enforce PIN changes from default (123456) for mTLS users
