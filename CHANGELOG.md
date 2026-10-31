# Changelog

All notable changes to the Portcullis core stack. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [semantic versioning](https://semver.org/) with `vMAJOR.MINOR.PATCH`
tags (integration contract §1). `release.yml` publishes the section of a
tag's version as its release notes.

## [Unreleased]

First release of the modernised core stack. There are no earlier installs:
nothing here migrates old data.

### Added

- **One admin CLI**, `./portcullis` (`help`, `<command> --help`), replacing
  every script: `init`, `up`, `down`, `upgrade`, `status [--json|--textfile]`,
  `version`, `backup`, `restore`, `config`, `dns setup`, `vault`, `pki setup`,
  `keycloak configure`, `oidc register`, `cert enroll|renew|revoke|list|sync`.
  `init` generates every secret; compose refuses to start without them.
- **Backups**: consistent online backups (Vault raft snapshot, `pg_dump`,
  SQLite online backup of the LLDAP / Hub / ACME volumes, `.env`, `certs/`,
  `secrets/`, config, checksummed `MANIFEST.json`); `--offsite` to a restic
  repository (pinned image, encrypted with the generated `BACKUP_PASSWORD`,
  retention `BACKUP_KEEP_DAILY/WEEKLY/MONTHLY`); `backup verify` (restic check,
  restore, Vault snapshot / `pg_restore` / LLDAP database checks);
  `restore --from-offsite`, also onto a new host; `backup schedule --systemd`.
- **Monitoring** (compose profile `monitoring`): Prometheus, Alertmanager,
  Grafana at `metrics.<domain>` (`lldap_admin`), blackbox and textfile
  exporters. Scrapes Traefik (internal metrics entrypoint), Vault (scoped
  `portcullis-metrics` token), Keycloak, group-gate (`/metrics`: decisions,
  denials and step-ups by reason, policy errors, CRL freshness). Alerts for a
  sealed Vault, public certificate < 14 days, stale CRL, deny spikes, down
  services, backups older than 36 h, expiring client certificates and CAs.
  Receivers (webhook, ntfy, SMTP) from `.env`. Provisioned dashboard.
- **Vault** in server mode (raft) with auto-unseal from `secrets/`, a
  least-privilege AppRole for enroll, no default/dev tokens.
- **Client certificates**: `CLIENT_CERT_TTL` (30 days), self-service renewal
  at `enroll.<domain>/self`, revocation enforced by group-gate on every
  request (serial file + Vault CRL) and by Keycloak's X.509 login (CRL, fails
  closed when stale), mTLS binding for `amr=mtls` sessions.
- **X.509 login** through Traefik (Keycloak `traefik` lookup provider); proxy
  headers are trusted only from Traefik's fixed address on `portcullis-auth`.
- **group-gate**: `path_groups`, policy file v2, reserved deny group,
  `/authenticated` (self-service routes), `/healthz`, `/metrics`.
- `portcullis version` (core version and the Hub image in use).
- **Releases**: `release.yml` for `vX.Y.Z` tags (full CI, released + pinned
  Hub image required, notes, tarball + sha256). This changelog.
- **Supply chain**: Dependabot (compose, enroll Dockerfile and Go modules,
  actions, e2e pip); CI fails on any image not pinned `tag@sha256` or any
  action not pinned by commit SHA.
- **Tests**: CLI and shell-library tests, group-gate unit tests, enroll Go
  tests, Playwright e2e login (passwords, passkeys, step-up, X.509, mTLS
  binding, revocation), backup → off-host → restore into a fresh stack,
  monitoring checks, promtool rule tests.

### Changed

- **Identity is the LLDAP username, never the email** (users can edit their
  own email in LLDAP): `X-Forwarded-User` / `X-Auth-Request-User` /
  `X-Auth-Request-Preferred-Username` carry the username (oauth2-proxy
  injects the `preferred_username` claim; its session user is Keycloak's
  `sub`), the email moves to `X-Forwarded-Email`; Keycloak does not mark
  LLDAP email as verified. group-gate takes the user only from
  `X-Auth-Request-Preferred-Username` and denies requests without it.
  Header-auth apps must log users in by username.
  `keycloak configure` maintains an `email-unverified` client scope (`email`
  claim, no `email_verified`) for apps that refuse `email_verified=false`
  (Hub templates opt in with `email_verified_claim: false`).
- **Docker socket**: only two socket proxies mount it (Traefik read-only, the
  Hub what `docker compose` needs), each on its own internal network.
- **Hardening**: every core image pinned by digest; `no-new-privileges`,
  `cap_drop: ALL`, memory/pid limits on every service; read-only root
  filesystems and non-root users wherever the image allows (exceptions in
  `docs/hardening.md`). Keycloak runs `start` (production mode).
- The Hub gets a generated env subset (`secrets/hub/core.env`), the proxy
  secret via a Traefik middleware, and no LLDAP credentials.
- `portcullis-proxy` has fixed IPAM with Traefik at `PORTCULLIS_TRAEFIK_IP`,
  the only peer header-auth apps trust.
- One base domain per installation (`PORTCULLIS_DOMAIN`), enforced by
  group-gate and the Hub.

### Removed

- `scripts/*.sh` (replaced by `./portcullis`), Vault dev mode and its static
  token, public default secrets, the unused Traefik static configuration
  files (Traefik is configured through environment variables).
