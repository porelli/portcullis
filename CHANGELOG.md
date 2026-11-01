# Changelog

All notable changes to the Portcullis core stack. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [semantic versioning](https://semver.org/) with `vMAJOR.MINOR.PATCH`
tags (integration contract §1). `release.yml` publishes the section of a
tag's version as its release notes.

## [Unreleased]

### Changed

- **Sign-in is passkey-only, one touch.** The browser flow (`portcullis-universal`) has no password: LoA 1 is a client cert (automatic when presented) or a passkey, LoA 2 (`hwk`) is reached by the same touch (no second prompt), LoA 3 still needs the cert. oauth2-proxy asks for `acr_values=hwk` by default, so webauthn-policy apps (the Hub's fresh-install default) need no step-up, and group-gate's step-up no longer sends `prompt=login` (Keycloak's LoA step-up asks only for the missing level). The policy factor `password` is met by any hardware factor.
- **`keycloak configure` applies flow changes to existing realms**: each top-level flow of `realm-export.json` (`portcullis-universal`, `portcullis-invite-link`, `portcullis-invite-session`) is rebuilt when its tree changed (hash kept in the flow description), bindings moved, the old tree deleted. No `--wipe-realm` needed for flow changes.
- The `portcullis` realm uses `sslRequired=external` (browsers reach Keycloak only through Traefik over HTTPS; `all` refused the invite identity provider's back-channel URLs on the private network). The identity provider is not in `realm-export.json` but `keycloak/invite-idp.json`, created by `keycloak configure`: Keycloak accepts its http URLs only when `enroll` resolves to a private address, which is not guaranteed during the first start's realm import ("The url [token_url] requires secure connections" aborted it).
- **Fresh-install lockout fixed**: the Hub's `webauthn` default stepped every user up to LoA 2, which a user without a passkey (every user of a new install, the bootstrap `admin` included) could not pass: "Invalid username or password". Keycloak 26.8 cannot enrol a passkey from inside that flow (`WebAuthnPasswordlessAuthenticatorFactory.isUserSetupAllowed()` is false: a REQUIRED passkey step fails with "credential setup required"), so first passkeys now come from setup links. group-gate's step-up page no longer auto-redirects when a hardware factor is missing: a Continue button and links to register a passkey / enrol a certificate.

### Added

- **One-time setup links** (`./portcullis invite <user> [--ttl] [--to hub|portal|URL]`; `init` prints the bootstrap admin's link): open it, register the security key, signed in (acr `hwk`, amr `hwk`) and on the landing page — no password, no LLDAP / Keycloak login. enroll serves `https://enroll.<domain>/invite/<token>` (public router), acts as the hidden OIDC identity provider `portcullis-invite` for Keycloak (first login links to the existing LLDAP user only; ES256 id_token, PKCE, client secret, back-channel on the unrouted port 8445) and adds the `webauthn-register-passwordless` required action through the service account `portcullis-enroll` (manage-users) when the link is redeemed. Tokens: 256 bit, stored hashed, single use, 72 h (max 7 days), a new link revokes older ones, viewing does not consume, same-origin redeem only, rate limited, audited (`INVITE ...` log lines without tokens).
- **Hub invite API** (integration contract §9.4): `POST http://enroll:8444/internal/invites` with the bearer secret in `secrets/enroll/invite-api-secret` (Hub copy: `/run/portcullis/invite/secret`); refuses `admin`, `portcullis-hub` and every member of `lldap_admin`, `lldap_password_manager` and the core-console groups (409; 503 when LLDAP can't be asked), re-checked when an API invite is redeemed, at the authorization code and at the token exchange (a user promoted after the invite was made is refused, their pending API invites cancelled): administrators are invited only from the server.
- **The Hub's LLDAP service account** (contract §9.1): `init` / `up` / `upgrade` keep LLDAP user `portcullis-hub` in `lldap_admin` with the password in `secrets/hub/lldap/password`, mounted read-only at `/run/portcullis/lldap/{username,password}` (group 10001, 0640); Hub env `LLDAP_HTTP_URL`, `LLDAP_LDAP_URL`, `LLDAP_BASE_DN`. It can't sign in: the Keycloak federation filters it out and group-gate denies it.
- `tests/test_cli.sh` fails on secrets on the CLI's command lines (`--arg x "$(cat ...)"`, secret variables in `--arg`, `--password $...`); the LLDAP / SMTP passwords now reach jq via `--rawfile` / its environment.
- **Landing portal** at `https://<domain>/` (group-gate `/portal`, behind forward-auth): the apps of the Hub's `portal-apps.json` (contract §10) the user's groups allow, the Hub and consoles for `lldap_admin`, the user's passkeys and certificate.
- `lldap_admin` members get `realm-admin` on the `portcullis` realm: `https://auth.<domain>/admin/portcullis/console/` works with the normal passkey session.
- **Lost-key recovery / spare keys**: login theme `portcullis` (`keycloak/themes/portcullis`, keycloak.v2 + one changed `webauthnRegister.js`) labels each new passkey "Security key <date time>" without asking. Stock Keycloak prompted for a label with a fixed default, and a second key of the same user then failed with "Device already exists with the same name" — re-inviting a user who already had a key (incl. `./portcullis invite admin`) could not work. `./portcullis invite <user> --replace-keys` first deletes the user's keys and signs them out (lost / stolen key); without it the new key is added next to the old ones.
- The Hub's fresh-install default policy is now `{factors: [mtls, webauthn], op: any}` (a passkey OR a client cert; `webauthn` alone sent cert-only sessions, e.g. a renewal at `enroll.<domain>/self`, to a step-up they could not pass). CI asserts it; the e2e default-policy app and `/self` renewal run with a cert-only session (no authenticator). group-gate steps sessions with neither factor up to `hwk` (passkey), with links to register a passkey or enrol a certificate.
- The portal at `https://<domain>/` has the enroll pages' dark look; inline CSS only, allowed by a strict `Content-Security-Policy` (`default-src 'none'`, the style's sha256).
- `tests/e2e/e2e_invite.py`: setup-link check (registration, no password, acr/amr, single use, one-touch second login, IdP closed without a link) for CI or a live server.

### Fixed

- group-gate no longer accepts the obsolete `password` policy factor; a policy naming it is denied as malformed (fail closed). The Hub already rewrites such policies.

- Keycloak admin consoles behind forward-auth answered "You do not have permission to access this resource": `portcullis-auth` replaced the console's own `Authorization: Bearer` header with the forward-auth session's token. The `/admin` router uses `portcullis-auth-console` (same, minus `Authorization`). The console's ~40 JS chunks also hit the login rate limit (HTTP 429, "Failed to fetch dynamically imported module"): `/resources/` has its own router with the general limit.
- `init`, `up` and `upgrade` now run `config apply`, so `ACME_STAGING` and `MTLS_ENABLED` reach Traefik. Previously only the CA bundle was rebuilt, and Traefik always used the production ACME CA. A first flip to staging also clears ACME storage that the compose default (production) had already filled.

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
- **group-gate public guard** (`/public-guard`, middleware
  `portcullis-public-guard@docker`) for the Hub's public exceptions: allows
  only the paths a subdomain publishes in the policy file's `public_paths`
  and refuses requests carrying `Authorization`, `Proxy-Authorization` or
  the app's credential headers, cookies or query parameters (names
  normalised the way PHP's `php_register_variable_ex` does). Policy file
  version 3; the guard requires exactly 3, and the Hub and core must be
  upgraded together.
- **group-gate**: `path_groups`, policy file v3 (v1–v3 accepted, parsed file
  cached on inode/mtime/size), reserved deny group,
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
- **Step-up** goes to `https://auth.<domain>/oauth2/start?acr_values=…&rd=<app>`;
  oauth2-proxy is routed on `auth.<domain>` only (a host-less `/oauth2/`
  router gets Traefik's 421 on tiered hosts).
- **Delta CRLs** on pki_int (`enable_delta`, rebuilt every minute):
  `auto_rebuild` defers full CRL rebuilds, so revocations made in Vault
  directly are only in the delta CRL until then; group-gate
  (`GATE_DELTA_CRL_URL`) and Keycloak's X.509 login read both.
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
