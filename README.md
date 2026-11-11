# Portcullis

Self-hosted, hardware-backed authentication gateway. YubiKey tap to access everything.

Inspired by Amazon's Midway — phishing-resistant authentication with YubiKeys,
a user directory, and SAML/OIDC identity provider for downstream applications.

**Documentation: <https://porelli.github.io/portcullis-docs/>** — setup, CLI reference, operations, security and app
guides all live there; this README is only an overview.

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
keycloak configure | oidc register | invite | signin reset-core
cert enroll | cert renew | cert revoke | cert list | cert sync
```

`./portcullis <command> --help` documents each one.

## Ways to Sign In

| Method | How it works | Setting it up | Best for |
|--------|-------------|------------|----------|
| **Passkey / security key** | Tap YubiKey (or use a passkey) in the browser → Keycloak sign-in | Open the setup link, tap key. Done. | Most users, browser apps |
| **YubiKey certificate** | Certificate in the YubiKey's PIV slot → TLS handshake | `./portcullis cert enroll` (or the admin on the person's Sign-in tab); renewed on the Sign-in page | APIs, CLI tools, service-to-service |
| **Browser certificate** | A certificate file installed in the browser (off by default) | Made on the Sign-in page (`https://people.<domain>/signin`) | Devices without a security key |

The admin switches each method on or off (Hub → Settings → Sign-in methods);
each app's sign-in template says which ones it accepts.

**Passkeys** need zero local software — just a browser and a YubiKey.
**YubiKey certificates** need the `ykman` CLI to write the certificate to the YubiKey's PIV slot.

## Architecture

```
                      *.<your-domain> :443
                    (single wildcard cert, ACME)
                              │
                              ▼
                    ┌───────────────────┐
                    │     Traefik       │
                    │ certs + forward   │
                    │  auth to Keycloak │
                    └────────┬──────────┘
                             │
         ┌───────────┬───────┼───────┬────────────┐
         ▼           ▼       ▼       ▼            ▼
    ┌─────────┐ ┌────────┐ ┌─────┐ ┌──────┐ ┌─────────┐
    │ People /│ │Keycloak│ │LLDAP│ │ Vault│ │ Your    │
    │ Sign-in │ │WebAuthn│ │user │ │ PKI  │ │ apps    │
    │         │ │SAML/   │ │dir  │ │  CA  │ │         │
    │         │ │OIDC IdP│ │     │ │      │ │         │
    └─────────┘ └────────┘ └─────┘ └──────┘ └─────────┘
```

| Component | Role | URL |
|-----------|------|-----|
| **Traefik** | Reverse proxy, wildcard TLS, certificates at the TLS handshake, forward auth, dashboard | `traefik.<domain>` |
| **enroll** | Setup links (`/invite/*`, the only route on `enroll.<domain>`) and certificate issuing for the Hub (internal) | `enroll.<domain>/invite/…` |
| **Hub** | App catalog — enable/disable templates, manage sources (admins) | `hub.<domain>` |
| **People** | The Hub's directory — users, groups, org chart, for every signed-in user (permissions checked per request) — and the Sign-in page (your passkeys, certificates, password, sign-in history) | `people.<domain>`, `people.<domain>/signin` |
| **Keycloak** | WebAuthn, SAML/OIDC IdP, X.509 auth | `auth.<domain>` |
| **LLDAP** | Lightweight user/group directory (its own UI is break-glass only: `./portcullis lldap-ui`; `directory.<domain>` redirects to `people.<domain>`) | (internal) |
| **Vault PKI** | Internal certificate authority: YubiKey certificates (`pki_int`) and browser certificates (`pki_file`), 30 days, renewed on the Sign-in page | `localhost:8200` |
| **Forward Auth** | OIDC bridge — redirects unauthenticated browser users to Keycloak | (internal) |

## Access Tiers

| Tier | How | Use case |
|------|-----|----------|
| **YubiKey certificate only** | `tls.options=protected` | Requires a YubiKey certificate at the TLS handshake. High-security admin tools, APIs. |
| **Any certificate** | `tls.options=protected-any` | Requires a YubiKey or browser certificate at the TLS handshake. |
| **WebAuthn** | `tls.options=public` + `portcullis-auth@docker` | Redirects to Keycloak → tap YubiKey. Browser apps. |
| **Both** | `tls.options=authaware` + `portcullis-auth@docker` | Certificate if present, WebAuthn fallback. Best UX. |
| **Public** | `tls.options=public` | No auth. Public pages. |

## Workflow

### 1. First sign-in (bootstrap admin)

`./portcullis init` ends with a **one-time setup link** for the LLDAP
`admin`. Open it, click "Register my key", touch the YubiKey (set / enter
its PIN): you are signed in and land in the Hub. There is no password
anywhere in the browser sign-in; a new link any time (lost key, expired
link): `./portcullis invite admin --to hub` on the server.

### 2. Users and their keys

Create users and groups in the directory at `https://people.<domain>`
(the Hub's directory; `directory.<domain>` redirects there, and LLDAP's own
UI is break-glass only: `./portcullis lldap-ui`). Each new user gets
a setup link (Hub, or `./portcullis invite <user>`): open it, register the
key, signed in — every later sign-in is one touch ("Sign in with Passkey").
The link works once, expires after 72 h and replaces earlier links.
A second link adds another key (a spare); for a lost or stolen key use
`./portcullis invite <user> --replace-keys`, which removes the old keys first.
`https://<domain>/` lists the apps a user may open (and the Hub for admins).

**YubiKey certificate (CLI — for advanced users):**
```bash
./portcullis cert enroll <username> <email>
```

Or, as an admin, issue one from the person's Sign-in tab on `https://people.<domain>`.
Certificates last 30 days (`CLIENT_CERT_TTL`); people renew their own on the
Sign-in page, `https://people.<domain>/signin` (same key, certificate still
valid), where they can also make a browser certificate when that method is
on. With the certificate selected in the browser, people can also sign in
to Keycloak with it.

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

**YubiKey-certificate-protected app** (high security):
```yaml
labels:
  traefik.enable: "true"
  traefik.http.routers.myapp.rule: Host(`myapp.${PORTCULLIS_DOMAIN}`)
  traefik.http.routers.myapp.entrypoints: websecure
  traefik.http.routers.myapp.tls.options: protected
  traefik.http.routers.myapp.middlewares: client-headers@file,security-headers@file
  traefik.http.services.myapp.loadbalancer.server.port: "8080"
```

**Both (a certificate if available, WebAuthn fallback):**
```yaml
labels:
  traefik.http.routers.myapp.tls.options: authaware
  traefik.http.routers.myapp.middlewares: client-headers@file,portcullis-auth@docker,security-headers@file
```

See `docker-compose.apps.yml` for complete examples.

**Non-Docker services** — edit `traefik/dynamic/external-services.yml`.

**SAML/OIDC apps** — register in Keycloak at `https://auth.<domain>/admin/`.

## Guides

All guides are on the [documentation site](https://porelli.github.io/portcullis-docs/):

| Guide | Description |
|-------|-------------|
| [DNS Configuration](https://porelli.github.io/portcullis-docs/setup/dns/) | DNS setup, Cloudflare config, wildcard certs, one domain per installation, local dev |
| [Certificates](https://porelli.github.io/portcullis-docs/setup/certificates/) | Website certificates (HTTPS, ACME staging/production), YubiKey and browser certificates, revocation, the internal certificate authority and auto-unseal |
| [SAML Integration](https://porelli.github.io/portcullis-docs/guides/saml-app/) | Nextcloud walkthrough — register in Keycloak, configure SAML SSO |
| [Header Auth Pattern](https://porelli.github.io/portcullis-docs/guides/header-auth-app/) | Trusted-header login (`X-Forwarded-User`, Traefik-only trust) for Kanboard, Grafana, Gitea, Wiki.js, pgAdmin, … |
| [CLI Reference](https://porelli.github.io/portcullis-docs/operations/cli/) | Every `./portcullis` command and option |
| [Backups](https://porelli.github.io/portcullis-docs/operations/backups/) | Consistent backups, off-host with restic, verify, schedule, restore (also on a new host) |
| [Monitoring](https://porelli.github.io/portcullis-docs/operations/monitoring/) | Opt-in profile: Prometheus, Alertmanager, Grafana at `metrics.<domain>`, alerts |
| [Security & Hardening](https://porelli.github.io/portcullis-docs/operations/hardening/) | Socket proxies, per-service hardening, secrets ownership, header trust, identity |

## File Structure

```
├── docker-compose.yml              # All core services
├── docker-compose.override.example.yml  # Override template (copy to config/)
├── docker-compose.apps.yml         # Example apps (all tiers + VPN)
├── config/                         # YOUR config (separate git repo, gitignored)
├── headscale/
│   └── config.yaml                # Headscale config (OIDC → Keycloak)
├── docs/                           # Pointers to https://porelli.github.io/portcullis-docs/
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
├── enroll/                         # Setup links + certificate issuing for the Hub (Go)
│   ├── main.go
│   ├── Dockerfile
│   └── web/                        # The setup-link page
├── traefik/                        # Static config: env vars in docker-compose.yml
│   └── dynamic/
│       ├── tls.yml                 # TLS options (protected/protected-any/authaware/public)
│       ├── middlewares.yml         # Certificate headers, rate limits, security headers
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
| Custom Traefik routers/middlewares | `traefik/*.yml` | Symlinked into `traefik/dynamic/local/`; loaded when Traefik (re)builds its file configuration — Traefik watches only `traefik/dynamic/` itself, not subdirectories, so apply a change with `docker compose restart traefik` |

Enabled apps and template sources are Hub state (in the `hub_data` volume), managed in the Hub UI.

## Integration

Portcullis is an auth layer that works with existing platforms:

| Platform | How to integrate |
|----------|-----------------|
| **YunoHost** | LLDAP as LDAP provider, Keycloak as SAML IdP |
| **Headscale** | OIDC → Keycloak for node registration, Headplane admin UI behind Traefik |
| **NetBird** | OIDC → Keycloak for peer auth, dashboard + management behind Traefik |
| **Coolify** | Traefik (certificates, forward-auth) in front, Coolify handles deploys |
| **Kubernetes** | Traefik as Ingress Controller, cert-manager for ACME, Keycloak as OIDC provider |
| **Any Docker app** | Add Traefik labels to join the network |

## Production Considerations

- **Vault**: runs in server mode (raft storage) and auto-unseals from `secrets/` on the host — back up `secrets/vault-init.json` (root token + unseal key) **offline**
- **Secrets**: `portcullis init` generates every password and secret into `.env` (0600); docker compose refuses to start if one is missing — there are no default passwords
- **Revocation**: `./portcullis cert revoke <serial>` — enforced by group-gate on every request (Traefik itself doesn't check CRLs), by Keycloak's certificate sign-in (each CA's CRLs) and by the certificate binding (a session signed in with a YubiKey or browser certificate needs that unrevoked certificate on every request); see [Certificates](https://porelli.github.io/portcullis-docs/setup/certificates/#revocation)
- **Renewal**: YubiKey and browser certificates live at most `CLIENT_CERT_TTL` (default 30 days); people renew their YubiKey certificate (with it still valid) or make a new browser certificate on the Sign-in page, `https://people.<domain>/signin`; `portcullis status` warns 7 days ahead
- **Backups**: `./portcullis backup` (also run by `upgrade`) makes a consistent backup without stopping anything (Vault raft snapshot, `pg_dump`, SQLite online backup, `.env`, `certs/`, `secrets/`); `--offsite` uploads it to a restic repository, encrypted with `BACKUP_PASSWORD` — **store that password offline**, the backups contain the Vault root token and unseal key. `backup verify` restores and checks it, `backup schedule --systemd` runs it daily, `restore [--from-offsite]` puts it back; see [Backups](https://porelli.github.io/portcullis-docs/operations/backups/)
- **Monitoring**: `COMPOSE_PROFILES=monitoring` adds Prometheus, Alertmanager and Grafana (`https://metrics.<domain>`, `lldap_admin`) with alerts for a sealed Vault, expiring certificates, a stale CRL, deny spikes, down services and old backups; see [Monitoring](https://porelli.github.io/portcullis-docs/operations/monitoring/)
- **Identity**: apps receive the LLDAP **username** as `X-Forwarded-User` and the email separately as `X-Forwarded-Email` — users can edit their own email in LLDAP, so never key accounts on it; see [Security & Hardening](https://porelli.github.io/portcullis-docs/operations/hardening/#header-spoofing-protections)
- **Network**: `portcullis-proxy` uses a fixed subnet (`PORTCULLIS_PROXY_SUBNET`, default `172.31.250.0/24`) with Traefik pinned at `PORTCULLIS_TRAEFIK_IP` — change in `.env` only if it collides with a host network (before `init`; later the network has to be recreated, `./portcullis up` explains how)
- **Docker socket**: only the two socket proxies mount it — Traefik gets read-only containers/networks/events, the Hub what `docker compose` needs (no swarm/system/plugins/secrets/build); see [Security & Hardening](https://porelli.github.io/portcullis-docs/operations/hardening/)
- **Containers**: every core image is pinned by digest (except our own `edge` Hub and Keycloak images on `main`); services run with `no-new-privileges`, `cap_drop: ALL`, read-only root filesystems, non-root users and memory/pid limits where the image allows — exceptions in [Security & Hardening](https://porelli.github.io/portcullis-docs/operations/hardening/)
- **Hub image**: `HUB_IMAGE` (default `ghcr.io/porelli/portcullis-hub:edge` on `main`; a core release pins a released Hub tag by digest); `./portcullis version` shows the core version and the Hub and Keycloak images in use. The Hub gets a generated env subset (`secrets/hub/core.env`), never the core `.env`, and no LLDAP credentials
- **Keycloak image**: `KEYCLOAK_IMAGE` (default `ghcr.io/porelli/portcullis-keycloak:edge` on `main`: the official Keycloak, pinned by digest, plus Portcullis's sign-in extension; a core release pins a released tag by digest)
- **Releases**: `vX.Y.Z` tags; `release.yml` runs the full CI, requires released, digest-pinned `HUB_IMAGE` and `KEYCLOAK_IMAGE` defaults and a `CHANGELOG.md` section, and publishes notes plus a tarball with its sha256. Dependabot proposes weekly image/action/module updates; CI fails on any unpinned image or action
- **PIV PIN**: enforce PIN changes from default (123456) for YubiKey certificate users
