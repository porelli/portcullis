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
`HUB_IMAGE`, enroll is built from `enroll/Dockerfile` whose bases are pinned).

| Service | User | Root FS | `cap_add` | Healthcheck | Notes |
|---------|------|---------|-----------|-------------|-------|
| socket-proxy-traefik / -hub | root | read-only (`tmpfs /run`) | `SYS_CHROOT` | `/_ping` | Exception: HAProxy needs root to open the root-owned socket and `chroot`s to `/` |
| traefik | root | read-only (`tmpfs /tmp`) | `NET_BIND_SERVICE` | `traefik healthcheck --ping` | Exception: root for ports 80/443 and the root-owned ACME volume; without `CAP_DAC_OVERRIDE` it reads files by mode only (`certs/server.key` is group 0, `0640`) |
| postgres | 70:70 | read-only (`tmpfs /var/run/postgresql`, `/tmp`) | — | `pg_isready` | `/var/lib/postgresql` is postgres-owned in the image, so the entrypoint needs no `chown` |
| vault | 100:1000 | read-only (`tmpfs /tmp`) | — | `vault status` | `disable_mlock` (raft), so no `IPC_LOCK`; reads `secrets/vault-unseal/` via group 1000 |
| lldap | 1000 (`-rootless` image) | read-only (`tmpfs /tmp`) | — | `lldap healthcheck` | |
| keycloak | 1000 (image) | **writable** (`tmpfs /tmp`) | — | `/health/ready` | Exception: `start` re-augments the server into `/opt/keycloak/lib` because the x509 lookup provider is a build option. A custom pre-built (`--optimized`) image would allow read-only |
| forward-auth | 65532 (distroless) | read-only | — | **none** | Exception: the image has no shell or HTTP client |
| group-gate | 10003:10003 | read-only (`tmpfs /tmp`) | — | `/healthz` | Only world-readable mounts |
| hub | 10001:10001 (image) | read-only (`tmpfs /tmp`, `/home/hub`) | — | image `HEALTHCHECK` (`/healthz`) | Writes `/data` (volume), `/project/templates` (chowned to 10001 by `./portcullis up`) |
| enroll | 10002:10002 (`USER` in Dockerfile) | read-only | — | `/healthz` | Reads `secrets/enroll/` via group 10002 |

## Secrets the containers read

The CLI keeps these **operator-owned** with the container's group, so the
operator can still rewrite them and nobody else can read them
(`secrets_fix_perms`, run by `init`, `up`, `upgrade`, `vault init`,
`restore`):

| Path | Group | Mode | Read by |
|------|-------|------|---------|
| `secrets/vault-unseal/unseal-key` | 1000 | 0640 (dir 0750) | vault (auto-unseal) |
| `secrets/enroll/{role-id,secret-id}` | 10002 | 0640 (dir 0750) | enroll |
| `secrets/hub/core.env` | 10001 | 0640 (dir 0750) | Hub (as `/project/.env`) |
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
