# Monitoring

An opt-in compose profile, `monitoring`, adds Prometheus, Alertmanager,
Grafana and two small exporters to the core stack. Grafana is at
`https://metrics.<domain>` for `lldap_admin` only; nothing else is
published. `./portcullis status` works the same with or without it.

## Enable

```bash
# .env
COMPOSE_PROFILES=monitoring
# Optional: where alerts go (default: nowhere — visible in Grafana only)
ALERT_NTFY_URL=https://ntfy.sh/<your-topic>
```

```bash
./portcullis up
```

`./portcullis up` (also `init`, `upgrade`, `restore`, `vault init`)
generates the files the containers read into `secrets/monitoring/` and
`vault init` creates the Vault metrics token, so always go through the CLI.
Add a DNS record for `metrics.<domain>` if you do not use a wildcard. To
get the backup and certificate metrics, schedule the backup
(`./portcullis backup schedule --systemd`, see [backups.md](backups.md)).

## Components

| Service | Image | Networks | Purpose |
|---------|-------|----------|---------|
| prometheus | `prom/prometheus` | `monitoring`, `portcullis` | scrapes everything below, evaluates `monitoring/prometheus/alerts.yml`; retention `PROMETHEUS_RETENTION` (30d) |
| alertmanager | `prom/alertmanager` | `monitoring`, `alerting` | routes alerts to the receivers configured in `.env` (`alerting` is its only network with egress) |
| grafana | `grafana/grafana` | `monitoring`, `portcullis-proxy` | dashboard "Portcullis" (provisioned, read-only), datasources Prometheus + Alertmanager |
| blackbox | `prom/blackbox-exporter` | `monitoring`, `portcullis` | HTTP/TCP liveness probes, Vault seal probe, TLS probe of the public certificate |
| textfile-exporter | `prom/node-exporter` (textfile collector only, no host metrics or mounts) | `monitoring` | serves `monitoring/textfile/*.prom` written by `./portcullis` |

All images are pinned `tag@sha256`, run as non-root (65534; Grafana 472)
with read-only root filesystems, `no-new-privileges`, no capabilities and
memory/pid limits. `monitoring` is an `internal` network.

## What is scraped

| Job | Target | Notes |
|-----|--------|-------|
| `traefik` | `traefik:8082/metrics` | internal `metrics` entrypoint, not published, no routers |
| `vault` | `vault:8200/v1/sys/metrics?format=prometheus` | token with policy `portcullis-metrics` (`vault/policies/metrics.hcl`: read `sys/metrics` only), orphan, no default policy, 10-year TTL, in `secrets/monitoring/prometheus/vault-token`; `vault init` recreates it when less than a year is left (it raises the `token/` mount's max TTL to allow this) |
| `group-gate` | `group-gate:8080/metrics` | decisions by endpoint/result, denials and step-ups by reason, policy load errors, CRL last fetch + the CRL's `nextUpdate`, revoked-serial counts |
| `keycloak` | `keycloak:9000/metrics` | management port (`--metrics-enabled`), not routed |
| `prometheus`, `alertmanager`, `grafana` | self | |
| `portcullis` | `textfile-exporter:9100` | `backup_local.prom` / `backup_offsite.prom` (written by `portcullis backup`), `status.prom` (`portcullis status --textfile`: service health, Vault active, CA expiry, newest client cert per user) |
| `vault_health` | blackbox → `http://vault:8200/v1/sys/health` | 200 only when initialised, unsealed and active |
| `services`, `services_tcp` | blackbox → enroll, forward-auth, Hub, LLDAP (HTTP); Postgres, LLDAP LDAP (TCP) | services without a metrics endpoint |
| `tls` | blackbox → `auth.<domain>:443` | through the host's published port, i.e. the certificate browsers see; verified against the system roots |

## Alerts

| Alert | Fires when | Severity |
|-------|-----------|----------|
| `VaultSealedOrDown` | `/v1/sys/health` ≠ 200 for 2 min | critical |
| `TargetDown` | a scrape target is down for 5 min | warning |
| `ServiceProbeFailed` | a liveness probe fails for 5 min | warning |
| `PublicCertExpiringSoon` | the public (ACME) certificate expires in < 14 days | critical |
| `PublicCertProbeFailed` | TLS to `auth.<domain>` fails for 30 min | warning |
| `CrlStale` | group-gate has no CRL newer than 10 min, or it is past `nextUpdate` | critical |
| `RevocationListUnreadable` | group-gate cannot read `revoked-serials.txt` (it then denies every client cert) | critical |
| `GroupGateDenySpike` | > 0.5 denials/s for 10 min | warning |
| `GroupGatePolicyErrors` | the Hub policy file is invalid (group-gate fails closed) | warning |
| `BackupTooOld` | last successful local / off-host backup > 36 h ago | warning |
| `BackupNeverRan` | no backup metric at all for 6 h | warning |
| `ClientCertExpiring` | a user's newest client certificate expires in < 7 days | info |
| `CaExpiring` | the root or intermediate CA expires in < 90 days | critical |
| `PortcullisStatusStale` / `PortcullisStatusProblems` | `status --textfile` did not run for 36 h / reported problems for 1 h | warning |

`promtool test rules monitoring/prometheus/tests/alerts_test.yml` (run in CI)
covers the main rules.

## Receivers

Set in `.env`; `./portcullis up` writes `secrets/monitoring/alertmanager/alertmanager.yml`
(values are JSON-encoded, so any character is safe). Several can be set at once.

| Variables | Receiver |
|-----------|----------|
| `ALERT_WEBHOOK_URL` | generic webhook (Alertmanager JSON payload) |
| `ALERT_NTFY_URL` | ntfy topic URL; sent with `?template=alertmanager` (ntfy formats the alert) |
| `ALERT_SMTP_SMARTHOST` (`host:port`), `ALERT_SMTP_TO`, optional `ALERT_SMTP_FROM` (default `portcullis@<domain>`), `ALERT_SMTP_USERNAME`, `ALERT_SMTP_PASSWORD`, `ALERT_SMTP_REQUIRE_TLS` (`true`) | email |

After changing them run `./portcullis up`: it regenerates the file and a
running Alertmanager reloads it.

## Access and trust

- `metrics.<domain>` is a **core subdomain** in group-gate (like `hub`,
  `traefik`, …): it always requires `lldap_admin` and the Hub's policy file
  cannot change that. The router uses
  `client-headers@file,portcullis-auth@docker,portcullis-groups@docker`.
- Grafana logs users in from `X-Forwarded-User` (the LLDAP **username**) and
  `X-Forwarded-Email`, accepted only from Traefik's fixed IP
  (`GF_AUTH_PROXY_WHITELIST=${PORTCULLIS_TRAEFIK_IP}`); its login form and
  basic auth are off. Everyone who gets through is an admin, so they are
  Grafana Admins.
- Prometheus, Alertmanager and the exporters have no route. To look at
  Prometheus directly: `docker compose exec prometheus wget -qO- 'http://127.0.0.1:9090/api/v1/alerts'`,
  or Grafana's Explore view.
- The Vault metrics token can only read `sys/metrics`. Metrics endpoints on
  the internal `portcullis` network (Traefik `:8082`, group-gate
  `/metrics`, Keycloak `:9000`) are unauthenticated; only core services
  are on that network.
