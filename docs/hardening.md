# Container hardening

What the core stack (`docker-compose.yml`) does to limit the damage a
compromised component can do, and where it can't.

## Docker API access (integration contract §6)

No service mounts `/var/run/docker.sock` except two
[linuxserver/socket-proxy](https://github.com/linuxserver/docker-socket-proxy)
containers (HAProxy, pinned by digest), each on its own `internal` network
shared with exactly one client:

| Proxy | Client | Network | Allowed (`1`) | Methods |
|-------|--------|---------|---------------|---------|
| `socket-proxy-traefik` | Traefik (`TRAEFIK_PROVIDERS_DOCKER_ENDPOINT=tcp://socket-proxy-traefik:2375`) | `socket-proxy-traefik` | `CONTAINERS`, `NETWORKS`, `EVENTS`, `VERSION`, `PING` | `GET`/`HEAD` only (`POST=0`) |
| `socket-proxy-hub` | Hub (`DOCKER_HOST=tcp://socket-proxy-hub:2375`) | `socket-proxy-hub` | `CONTAINERS`, `IMAGES`, `NETWORKS`, `VOLUMES`, `EXEC`, `EVENTS`, `INFO`, `VERSION`, `PING`, `ALLOW_LOGS` | all (`POST=1` also allows `PUT`/`DELETE` on the allowed sections) |

That is what `docker compose up/down/ps/logs/restart` and the Hub's Engine
API calls (status, logs, exec, events) need: container create / start /
stop / kill / rm / inspect / list / wait / logs / exec, image pull
(`/images/create`) and inspect, network and volume create / inspect / rm,
`/events`, `/info`, `/version`, `/_ping`. Denied: `BUILD`, `COMMIT`,
`SWARM`, `NODES`, `SERVICES`, `TASKS`, `SECRETS`, `CONFIGS`, `PLUGINS`,
`SYSTEM` (df / prune), `AUTH`, `DISTRIBUTION`, `SESSION`, container
`archive` / `export`. CI runs a real `docker compose` project through
`socket-proxy-hub` and checks the denials.

**Limits of a socket proxy.** The Hub can still create containers with any
`HostConfig` (privileged, host bind mounts) — that is inherent to "runs
compose for arbitrary templates". The proxy removes the rest of the API
surface (swarm, plugins, image builds, system prune, secrets); treat the Hub
as host-root-equivalent and keep it behind `lldap_admin` + the proxy secret.

## Per-service settings

Every service: `security_opt: [no-new-privileges:true]`, `cap_drop: [ALL]`,
`mem_limit`, `pids_limit`, image pinned `tag@sha256:digest` (the Hub via
`HUB_IMAGE`; enroll and group-gate are built from `enroll/Dockerfile` /
`group-gate/Dockerfile`, whose bases are pinned; group-gate's Python
dependencies are exact pins with hashes in `group-gate/requirements.txt`,
installed wheels-only with `pip install --require-hashes`).

| Service | User | Root FS | `cap_add` | Healthcheck | Notes |
|---------|------|---------|-----------|-------------|-------|
| socket-proxy-traefik / -hub | root | read-only (`tmpfs /run`) | `SYS_CHROOT` | `/_ping` | Exception: HAProxy needs root to open the root-owned socket and `chroot`s to `/` |
| traefik | root | read-only (`tmpfs /tmp`) | `NET_BIND_SERVICE` | `traefik healthcheck --ping` | Exception: root for ports 80/443 and the root-owned ACME volume; without `CAP_DAC_OVERRIDE` it reads files by mode only (`certs/server.key` is group 0, `0640`) |
| postgres | 70:70 | read-only (`tmpfs /var/run/postgresql`, `/tmp`) | — | `pg_isready` | `/var/lib/postgresql` is postgres-owned in the image, so the entrypoint needs no `chown` |
| vault | 100:1000 | read-only (`tmpfs /tmp`) | — | `vault status` | `disable_mlock` (raft), so no `IPC_LOCK`; reads `secrets/vault-unseal/` via group 1000 |
| lldap | 1000 (`-rootless` image) | read-only (`tmpfs /tmp`) | — | `lldap healthcheck` | |
| keycloak | 1000 (image) | **writable** (`tmpfs /tmp`) | — | `/health/ready` | Exception: `start` re-augments the server into `/opt/keycloak/lib` because the x509 lookup provider is a build option. A custom pre-built (`--optimized`) image would allow read-only |
| forward-auth | 65532 (distroless) | read-only | — | **none** | Exception: the image has no shell or HTTP client |
| group-gate | 10003:10003 (`USER` in Dockerfile) | read-only (`tmpfs /tmp`) | — | `/healthz` | Image `portcullis-group-gate`: pinned `python` alpine base + `cryptography` (CRL parsing) and `PyJWT` (token claims) + the script. Only world-readable mounts |
| hub | 10001:10001 (image) | read-only (`tmpfs /tmp`, `/home/hub`) | — | image `HEALTHCHECK` (`/healthz`) | Writes `/data` (volume), `/project/templates` (chowned to 10001 by `./portcullis up`) |
| enroll | 10002:10002 (`USER` in Dockerfile) | read-only | — | `/healthz` | Reads `secrets/enroll/` via group 10002 |
| prometheus, alertmanager, blackbox, textfile-exporter (profile `monitoring`) | 65534:65534 | read-only | — | `/-/ready`, `/-/healthy`, `/metrics` | `monitoring` network is `internal`; nothing published. Alertmanager's only egress is the `alerting` network |
| grafana (profile `monitoring`) | 472:472 | read-only (`tmpfs /tmp`) | — | `/api/health` | Header auth only from `PORTCULLIS_TRAEFIK_IP`; login form and basic auth off |

Throwaway containers the CLI starts: the chown helper (pinned `alpine`,
`--network none`, only `CAP_CHOWN`); for backups the volume snapshot and
LLDAP check (the `portcullis-group-gate` image, built first if missing; the volume owner's uid,
`--network none`, read-only, no capabilities), `restic` (pinned, the
operator's uid, read-only, no capabilities; `--network none` for a local
repository) and, for `backup verify`, a `postgres` without network.

## Secrets the containers read

The CLI keeps these **operator-owned** with the container's group, so the
operator can still rewrite them and nobody else can read them
(`secrets_fix_perms`, run by `init`, `up`, `upgrade`, `vault init`,
`restore`):

| Path | Group | Mode | Read by |
|------|-------|------|---------|
| `secrets/vault-unseal/unseal-key` | 1000 | 0640 (dir 0750) | vault (auto-unseal) |
| `secrets/enroll/{role-id,secret-id}` | 10002 | 0640 (dir 0750) | enroll |
| `secrets/enroll/{invite-client-secret,keycloak-client-secret,invite-api-secret}` | 10002 | 0640 | enroll (invite IdP client, Keycloak service account `portcullis-enroll`, Hub invite API) |
| `secrets/hub/core.env` | 10001 | 0640 (dir 0750) | Hub (as `/project/.env`) |
| `secrets/hub/lldap/{username,password}` | 10001 | 0640 (dir 0750) | Hub (`/run/portcullis/lldap`, LLDAP account `portcullis-hub`, `lldap_admin`) |
| `secrets/hub/invite/secret` | 10001 | 0640 (dir 0750) | Hub (`/run/portcullis/invite/secret`, same value as enroll's `invite-api-secret`) |
| `secrets/monitoring/prometheus/{vault-token,tls-targets.json}` | 65534 | 0640 (dir 0750) | Prometheus (Vault metrics token: policy `portcullis-metrics`) |
| `secrets/monitoring/alertmanager/alertmanager.yml` | 65534 | 0640 (dir 0750) | Alertmanager (receivers incl. SMTP password / webhook URLs) |
| `secrets/monitoring/grafana/admin-password` | 472 | 0640 (dir 0750) | Grafana |
| `certs/server.key` (dev/CI only) | 0 | 0640 | Traefik |
| `templates/` | owner 10001 | 0755 | Hub (writes) |

Without root, the CLI changes owner/group through a throwaway container
(pinned `alpine`, `--network none`, `--cap-drop ALL --cap-add CHOWN`).
Anyone who can run docker is root-equivalent anyway.

**The Hub never sees the core `.env`.** `secrets/hub/core.env` holds only
what templates may reference: `PORTCULLIS_DOMAIN`, `PORTCULLIS_TRAEFIK_IP`,
the proxy subnet, `PORTAL_DISPLAY_NAME`, `HEADSCALE_*`, `HEADPLANE_*`,
`NETBIRD_*`, `COTURN_*`, plus the names in `HUB_SHARED_ENV` (core secrets
are refused). It is rewritten in place on every `./portcullis up`.

## Header trust

**Identity is the LLDAP username, never the email.** LLDAP lets every user
edit their own `mail`, so an email can be set to someone else's address.
Therefore:

- Keycloak's LDAP federation has `trustEmail=false`: tokens carry
  `email_verified=false` for LLDAP users.
- Keycloak's LDAP federation has `cachePolicy=NO_CACHE` (realm export +
  `keycloak configure`): group memberships and attributes are read from
  LLDAP on every lookup, so a removal or attribute change in LLDAP is in
  the next token (oauth2-proxy refreshes every minute) instead of a cached
  copy surviving until eviction or the daily sync.
- oauth2-proxy's session user is always the token's `sub` (Keycloak's user
  UUID); its alpha `userIDClaim` is only a deprecated alias of
  `emailClaim`, so it is not used (CI rejects it). Instead
  `oauth2-proxy/alpha.yaml` builds `X-Auth-Request-User`,
  `X-Forwarded-User` and `X-Auth-Request-Preferred-Username` from the
  `preferred_username` claim, keeps `emailClaim: email`, and accepts the
  unverified email (`insecureAllowUnverifiedEmail`) because nothing
  authorises by it.
- group-gate reads the username ONLY from
  `X-Auth-Request-Preferred-Username` (set by `portcullis-auth`, which must
  run first) and denies the request when it is missing — it never falls
  back to the email or `sub`.
- Apps behind `portcullis-auth@docker,portcullis-groups@docker` receive
  `X-Forwarded-User` / `X-Auth-Request-User` /
  `X-Auth-Request-Preferred-Username` = username and
  `X-Forwarded-Email` / `X-Auth-Request-Email` = email (display only), plus
  `X-Auth-Request-Groups`. All of them are `authResponseHeaders` of the
  forward-auth middlewares, so Traefik deletes client-supplied copies
  (the e2e test sends spoofed ones). Header-auth apps must log users in by
  `X-Forwarded-User` as a username and take the email from
  `X-Forwarded-Email`.
- Attribute headers: on every request group-gate allows (`/` and
  `/authenticated`, app and core subdomains alike) it also returns
  `X-Forwarded-Attr-<Header-Name>` for the signed-in user's shared custom
  fields, read from the Hub's `user-attributes.json` in `hub_data`
  (contract §4.1/§5): control characters (0x00–0x1F, 0x7F) stripped,
  values over 1 KB dropped and logged, then `%` → `%25` and `,` → `%2C` in
  every value (so `Doe, Jane` stays one value; apps percent-decode each
  item) and the values joined with `, `; non-ASCII as UTF-8 bytes. A
  missing or corrupt file (logged) means no attribute headers, never a
  deny; header names must match `^[A-Za-z0-9]+(-[A-Za-z0-9]+)*$` and be
  unique case-insensitively (two fields on one header = corrupt). `portcullis-groups` forwards them with
  `authResponseHeadersRegex: ^X-Forwarded-Attr-`. A headers middleware can
  only delete headers by exact name (and the field names are the Hub's), so
  client-sent `X-Forwarded-Attr-*` are deleted by the same regex on every
  forwardAuth middleware (`portcullis-auth`, `-auth-console`, `-groups`,
  `-self`, `-public-guard`): Traefik removes all request headers matching it
  before copying the auth server's. Public routers therefore get none, and
  `_` aliases are dropped by the entrypoints (`aliasHeadersStrategy`). CI
  sends forged ones through the gated and public test routers.
  Routers with **no** forwardAuth middleware (`keycloak`,
  `keycloak-resources`, `lldap` (redirect only), `vault-ui`,
  `enroll-invite`, and in the app overlays `headscale`, `netbird-*`,
  `docs`) do not strip client-sent `X-Forwarded-Attr-*`: their backends
  must never trust those headers (none of them reads them today).
- Temporary memberships: the policy file (version 4, the only version
  group-gate serves) lists `expiring` `{user, group, at}` entries; group-gate
  treats a membership as absent once `now >= at` — for the subdomain and
  path-group checks and in the `X-Auth-Request-Groups` it returns —
  whatever the token says, so expiry holds even while the Hub is down.
  A malformed entry denies (fail closed). The access token still names the
  expired group, so when group-gate strips a membership it withholds
  `Authorization` and `X-Forwarded-Access-Token` (both are
  `portcullis-groups` `authResponseHeaders`, so Traefik deletes them);
  otherwise it echoes them unchanged (apps keep the token, the Keycloak
  console behind `portcullis-auth-console` keeps its own bearer).
  Only version 4 is served: a file without `version` denies as well; only
  a missing file means "nothing published".
- `people.<domain>` (the Hub's directory listener `:8889`, contract §5.1)
  is open to any signed-in user: `people=*` in `group-gate-map.conf` (`*` is
  valid only there; in the policy file's `groups` it is ignored, in
  `path_groups` it is malformed). It has the admin Hub's chain
  (`client-headers`, `portcullis-auth`, `portcullis-groups`,
  `hub-proxy-secret`, `security-headers`), and the Hub checks permissions
  per request and registers no app / policy / Docker endpoint there.
- Forward-auth sessions are re-validated every minute
  (`OAUTH2_PROXY_COOKIE_REFRESH=1m`, a legacy option that still applies
  with `--alpha-config`): once the session cookie is a minute old,
  oauth2-proxy redeems the refresh token with Keycloak. A Keycloak logout or
  a session the Hub revokes (membership removal) then fails the refresh and
  ends access, and changed groups reach group-gate, within about a minute;
  without it the 168 h cookie (`cookie_expire`, unchanged) kept the groups
  of the sign-in. The refresh also ends forward-auth sessions at Keycloak's
  SSO session limits (8 h idle, 12 h max).
- enroll identifies the signed-in user by `X-Forwarded-User` as-is (no
  email → username lookup); group-gate's mTLS binding compares the cert CN
  with that same username (and requires the token's `preferred_username`
  to match it).
- oauth2-proxy's endpoints (`/oauth2/start`, `/oauth2/callback`,
  `/oauth2/sign_out`) are routed only on `auth.<domain>`: a host-less
  `PathPrefix(/oauth2/)` router cannot carry the tiers' TLS options and
  Traefik answers 421 on it. group-gate's step-up page therefore sends the
  browser to `https://auth.<domain>/oauth2/start?acr_values=…&rd=<app>`.
  CI rejects router rules without `Host(`.
- Keycloak's `/admin` and `/realms/master` router uses
  `portcullis-auth-console`: the same forward-auth, minus `Authorization`
  in `authResponseHeaders`. The admin console sends its own bearer token to
  the admin API; `portcullis-auth` replaced it with the forward-auth
  session's token ("You do not have permission to access this resource").
- Setup links: `enroll-invite` (`enroll.<domain>/invite/*`) is the only
  enroll router without forward-auth. The token is 256 bit, stored as
  SHA-256, single use, bound to one LLDAP user, 72 h (max 7 days), revoked
  by a newer link; `GET` only shows it (link previews must not burn it), the
  same-origin `POST` redeems it. enroll then acts as the hidden identity
  provider `portcullis-invite` (Keycloak shows it only for
  `kc_idp_hint=portcullis-invite`; its first-login flow links the existing
  LLDAP user and never creates one): a 10-minute HttpOnly redemption cookie
  scoped to `/invite/`, a 60 s single-use code bound to the broker redirect
  URI and the PKCE challenge, an ES256 id_token. Its token / JWKS port
  (8445) and the Hub's invite API (8444, bearer secret, refuses `admin` and
  `portcullis-hub`) are not routed by Traefik; `enroll invite` (the CLI,
  through `docker exec`) uses a loopback-only listener (8446), the only way
  to invite an administrator: the Hub API refuses `admin`, `portcullis-hub`
  and every member of `lldap_admin`, `lldap_password_manager` and the
  core-console groups of `group-gate-map.conf` (LLDAP group lookup, fails
  closed), so a leaked API secret cannot take over an admin account. The
  check is repeated for API-made invites at redeem, at the authorization
  code and at the token exchange (a user promoted to lldap_admin after the
  invite was made is refused, and their pending API invites are cancelled). The invite session is LoA 2 / amr `hwk`:
  it cannot finish without the passkey registration (`webauthn-register-passwordless`,
  added by enroll's service account `portcullis-enroll`, realm-management
  view-users + manage-users, when the link is redeemed). enroll already held
  the LLDAP admin bind and Vault signing rights, so this adds no new class
  of power to it. A re-invite of a user who already has keys adds one more
  (spare); `./portcullis invite <user> --replace-keys` (lost / stolen key)
  deletes the user's WebAuthn credentials and sessions first.
- The Hub logs in to LLDAP as `portcullis-hub` (`lldap_admin`; LLDAP
  0.6.3's `lldap_password_manager` cannot create users or groups): it could
  already start arbitrary containers through its socket proxy, so this is
  no new trust (integration contract §9.1). The account cannot sign in:
  Keycloak's federation filters it out (`(!(uid=portcullis-hub))`) and
  group-gate denies it (`GATE_DENY_USERS`).
- Public exceptions (the Hub's `portcullis-public-<app>` routers) have no
  forward-auth: nothing is signed in and no identity header is passed (the
  Hub's strip middleware deletes client copies). Their first middleware,
  `portcullis-public-guard@docker` (group-gate `/public-guard`), returns
  403 unless the policy file (version 4) publishes the subdomain in
  `public_paths`, the normalised path is inside one of its patterns
  (prefix / exact / static files; encoded `/`, `\`, NUL or `#` denied, and
  so is any `#` in `X-Forwarded-Uri`: browsers never send fragments), and the
  request carries none of `Authorization`, `Proxy-Authorization`, the
  app's `credential_headers` (also in `_` form), `credential_cookies` or
  `credential_query`. Cookie and query names are compared case-insensitively
  after PHP's mangling (`main/php_variables.c` `php_register_variable_ex`:
  leading spaces dropped, ` `/`.` → `_`, `name[...]` is `name`, an unclosed
  `[` → `_`, NUL ends the name), both raw and percent-/`+`-decoded; names
  that are not valid UTF-8 (overlong forms) are refused. It never returns
  identity headers. Its logs (like group-gate's path denials) show the path
  with token-like segments masked as `<token>` and query parameter names
  only — never share tokens, query values, cookies or credentials.
- group-gate's `path_groups` checks also deny a `#` in the URI or an
  encoded one in the path.
- Native OIDC apps must key accounts on `sub` / `preferred_username`, not
  on the email, and must not link existing accounts by email (e.g.
  Vaultwarden `SSO_SIGNUPS_MATCH_EMAIL`); apps that insist on
  `email_verified=true` need their "allow unverified email" option.
- Apps that refuse `email_verified=false` but accept the claim being absent
  (Vaultwarden SSO signups) use the `email-unverified` client scope instead
  of `email`: `portcullis keycloak configure` maintains it with a single
  `email` mapper and no `email_verified` mapper, and the Hub attaches it to
  clients whose template sets `keycloak_clients[].email_verified_claim:
  false`. The email is just as unverified; such apps must still never link
  accounts by it.

- The `websecure` entrypoint has no `forwardedHeaders.trustedIPs`, so
  Traefik deletes client-supplied `X-Forwarded-*` and
  `X-Forwarded-Tls-Client-Cert(-Info)` headers, and
  `aliasHeadersStrategy=delete` drops `X_Forwarded_…`-style aliases.
  The cert headers seen by group-gate, enroll and Keycloak therefore always
  describe a certificate Traefik verified (CI checks this).
- Keycloak accepts proxy headers (incl. the client cert for X.509 login)
  only from Traefik's fixed IP on `portcullis-auth`
  (`--proxy-trusted-addresses=${PORTCULLIS_AUTH_TRAEFIK_IP}`); the check
  uses the TCP peer address and cannot be set by a client header. The
  `127.0.0.1:8080` publish stays for the CLI's admin API calls — requests
  from there are untrusted, so they can't use a cert header. CI sends a
  forged header from every reachable place (see `docs/certificates.md`).
- The Hub only answers requests carrying `X-Portcullis-Proxy-Secret`,
  which the `hub-proxy-secret` middleware adds **after** the forward-auth
  middlewares (so the secret is never sent to oauth2-proxy / group-gate).
- Traefik's default path handling stays on (`sanitizePath`, decoding of
  unreserved `%XX`); encoded `/`, `\`, `;`, `%00` are allowed by default
  because apps such as GitLab and Nextcloud use them. group-gate's
  `path_groups` matching therefore normalises the path itself and denies
  encoded slashes / NULs that survive one decode.
