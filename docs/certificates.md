# TLS Certificates & mTLS

Portcullis uses two independent TLS features that can be toggled independently:

| Setting | `.env` variable | Default | What it controls |
|---------|----------------|---------|------------------|
| **Certificate source** | `ACME_STAGING` | `true` | Staging (test) vs production (trusted) Let's Encrypt certs |
| **Client certificates** | `MTLS_ENABLED` | `true` | Whether Traefik requests mTLS client certs (PIV/YubiKey) |

After changing either toggle, run:

```bash
./scripts/apply-config.sh
docker compose up -d --force-recreate traefik
```

---

## ACME Staging vs Production

### Staging (`ACME_STAGING=true`)

- Uses Let's Encrypt **staging** CA — no rate limits, but **browsers won't trust the certificate**.
- Great for initial setup, testing, and development.
- App containers that talk to Keycloak over HTTPS mount `certs/ca-bundle.crt`, which `apply-config.sh` builds from: system CAs + the internal Portcullis PKI chain + the Let's Encrypt staging root (only when `ACME_STAGING=true`). This is handled automatically.

**Browser workarounds:**

Chrome (macOS):
```bash
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --ignore-certificate-errors
```

Chrome (Linux):
```bash
google-chrome --ignore-certificate-errors
```

Firefox:
- Navigate to the site → click "Advanced" → "Accept the Risk and Continue"
- Or set `security.tls.insecure_fallback_hosts` in `about:config`

curl:
```bash
curl -k https://app.portcullis.example.com
```

### Production (`ACME_STAGING=false`)

- Uses Let's Encrypt **production** CA — trusted by all browsers.
- Rate limits apply: 50 certificates per registered domain per week.
- **Only switch to production once everything works with staging.**

**To switch:**

1. Edit `.env`:
   ```
   ACME_STAGING=false
   ```

2. Apply and restart:
   ```bash
   ./scripts/apply-config.sh
   # Delete the old staging cert so Traefik requests a new one
   docker compose exec traefik rm -f /acme/acme.json
   docker compose up -d --force-recreate traefik
   ```

3. Wait ~2 minutes for DNS-01 challenge to complete. Check logs:
   ```bash
   docker compose logs -f traefik 2>&1 | grep -i acme
   ```

---

## mTLS (Client Certificates)

### Enabled (`MTLS_ENABLED=true`)

Traefik uses three TLS tiers:

| Tier | Traefik option | Behavior |
|------|---------------|----------|
| **protected** | `RequireAndVerifyClientCert` | Client cert **required** — no cert = TLS handshake fails |
| **authaware** | `VerifyClientCertIfGiven` | Client cert **optional** — verified if present, WebAuthn fallback if not |
| **public** | `NoClientCert` | No client cert requested |

The tier is no longer hard-coded per template. The Hub derives it from each app's **access policy** (see `docs/operations/auth-policies.md` in the docs site) and writes the chosen tier into a per-app compose override. You change tiers by editing the app's policy in the Hub UI, not by editing `compose.yml`.

Most apps end up on `authaware` with a default policy of "any of mTLS / WebAuthn" — users with a PIV certificate are authenticated automatically via X.509, users without fall through to WebAuthn. Apps with "mTLS only" or "all of … mTLS" get `protected`; public apps get `public`.

**Issuing client certificates:**

1. Users enroll their YubiKey PIV slot via the Enrollment UI (`enroll.<domain>`)
2. The Enrollment UI signs a CSR using Vault's PKI engine (with a least-privilege AppRole, see below)
3. Certificates are short-lived (24 hours) and automatically renewable

### Revoking client certificates

```bash
./scripts/revoke-cert.sh --list          # find the serial
./scripts/revoke-cert.sh <serial>        # revoke (add --yes to skip the prompt)
./scripts/revoke-cert.sh --sync          # rewrite the serial list from Vault
```

**Traefik does not check CRLs** — a TLS handshake with a revoked-but-unexpired cert still succeeds. Revocation is enforced by **group-gate** (`portcullis-groups@docker`): `client-headers@file` (Traefik `passTLSClientCert`, with `serialNumber: true`) passes `X-Forwarded-Tls-Client-Cert-Info` to the backend *and* to every later forward-auth middleware, and group-gate returns 403 when the cert's serial is revoked. Sources:

- `certs/revocation/revoked-serials.txt` — rewritten atomically by `revoke-cert.sh` from Vault's list of revoked serials; checked on the next request. If Vault can't be queried (sealed, bad token, unreachable) the file is left unchanged and the script fails — it never "un-revokes" by writing an empty list.
- Vault's CRL (`http://vault:8200/v1/pki_int/crl`), re-fetched every 60 s — also covers revocations made directly through the Vault API/UI. If Vault is unreachable the last good CRL is kept.

Coverage: every router whose middleware chain has `client-headers@file` **before** `portcullis-groups@docker` (all core routers and the default app templates). **Not covered:** routers that rely on the TLS client cert alone (e.g. a `protected`-tier router without `portcullis-groups@docker`) — the 24 h cert lifetime bounds the exposure there — and Keycloak sessions that were already opened with the cert (sign the user out in the Keycloak admin console, or enable CRL checking in the realm's X.509 authenticator).

## Vault storage, unsealing & tokens

Vault runs in **server mode** with integrated (raft) storage on the `vault_data` volume (`vault/vault.hcl`), so the CA survives restarts. The listener is plain HTTP on the internal `portcullis` network and `127.0.0.1:8200` on the host only.

`./scripts/vault-init.sh` (run by `bootstrap.sh`, `upgrade.sh` and `restore.sh`; idempotent) does:

1. **Init** (first run only) with **one key share, threshold 1**, writing to `secrets/` (dir `0700`, files `0600`, gitignored):
   - `secrets/vault-init.json` — root token + unseal key (`vault operator init` output)
   - `secrets/vault-unseal/unseal-key` — mounted read-only into the vault container
2. **Unseal**. Afterwards `vault/entrypoint.sh` unseals automatically on every container start (`docker compose up`, restart, host reboot).
3. **Least privilege for enroll**: AppRole `portcullis-enroll` with policy `vault/policies/enroll.hcl` (only `pki_int/sign/client-cert`, list `pki_int/certs`, read `pki_int/cert/*`). Credentials in `secrets/enroll/` are mounted read-only into enroll, which logs in for 1 h tokens and logs in again before expiry or on 403 — there is no static or root token in `.env` any more. Rotate with `./scripts/vault-init.sh --rotate-enroll-secret`.

Admin scripts (`setup-vault-pki.sh`, `enroll-yubikey.sh`, `renew-yubikey.sh`, `revoke-cert.sh`, `status.sh`) use the root token from `secrets/vault-init.json`, or `VAULT_TOKEN` if exported. They use the host `vault` CLI if installed, otherwise the CLI inside the vault container (token passed by environment-variable name, never on the command line). `secrets/` and `backups/` are masked from the Hub container with empty tmpfs mounts.

`setup-vault-pki.sh` is idempotent: it does nothing when the root issuer, intermediate issuer and `client-cert` role all exist; if it finds an incomplete PKI (an earlier run aborted) it wipes and recreates it; any Vault error aborts instead of being mistaken for "no PKI". `certs/server.key` is written `0600`.

**Trade-off.** The unseal key lives on the same host as the encrypted data, so root on the host (or anyone who can read `secrets/`) can unseal Vault. What it does protect: a copy of the `vault_data` volume alone is useless. Multiple Shamir shares on the same disk would add nothing, hence one share. For stronger guarantees remove the `secrets/vault-unseal` mount and unseal manually (`docker compose exec vault vault operator unseal`) after each restart, or use a cloud KMS auto-unseal. **Keep an offline copy of `secrets/vault-init.json`** — backups made by `upgrade.sh` include `secrets/`, so protect them like the keys themselves.

### Upgrading from dev-mode Vault

Older releases ran Vault in dev mode (in-memory, root token `myroot`). The CA keys were generated `internal` (non-exportable) inside that in-memory Vault, so they **cannot be migrated**. `./scripts/upgrade.sh` detects dev mode and stops unless you pass `--migrate-vault` (or confirm interactively). Migrating creates a new root + intermediate CA, rewrites `certs/root-ca.crt`, `certs/intermediate-ca.crt`, `certs/ca-chain.crt` (and `server.crt`/`server.key` if present; the old files are copied to `backups/certs-before-vault-migration-*`), and **every YubiKey client certificate must be re-enrolled**. WebAuthn logins are unaffected. `VAULT_DEV_TOKEN` in `.env` is no longer used and can be deleted.

### Disabled (`MTLS_ENABLED=false`)

All three TLS tiers become equivalent — no client certificates are requested. Authentication is purely WebAuthn (YubiKey FIDO2) via Keycloak.

This is simpler to set up and doesn't require `ykman` CLI or PIV slot configuration. Recommended if you only want YubiKey tap-to-authenticate (WebAuthn) without client certificate management.

**To disable:**

1. Edit `.env`:
   ```
   MTLS_ENABLED=false
   ```

2. Apply and restart:
   ```bash
   ./scripts/apply-config.sh
   docker compose up -d --force-recreate traefik
   ```

---

## Common Scenarios

### Fresh setup (testing)
```
ACME_STAGING=true
MTLS_ENABLED=false
```
Simplest setup — untrusted certs (use Chrome `--ignore-certificate-errors`), no client certs, WebAuthn only.

### Production with WebAuthn only
```
ACME_STAGING=false
MTLS_ENABLED=false
```
Trusted certs, YubiKey tap-to-authenticate, no certificate management needed.

### Production with full mTLS
```
ACME_STAGING=false
MTLS_ENABLED=true
```
Trusted certs, dual auth (PIV certificates for CLI/API, WebAuthn for browser), highest security.

### Development / CI
```
ACME_STAGING=true
MTLS_ENABLED=true
```
Test everything including mTLS flows, with staging certs.

---

## Troubleshooting

### "Your connection is not private" in browser
You're using staging certificates. Either:
- Switch to production: `ACME_STAGING=false`
- Or launch Chrome with `--ignore-certificate-errors`

### "NET::ERR_CERT_AUTHORITY_INVALID"
Same as above — staging CA is not trusted by browsers.

### App shows "unable to get local issuer certificate"
The app container can't verify Keycloak's staging TLS cert. Make sure:
- `certs/ca-bundle.crt` exists (run `./scripts/apply-config.sh`)
- The container mounts it (check compose.yml for `ca-bundle.crt` volume mount)
- For Node.js apps: set `NODE_EXTRA_CA_CERTS=/path/to/ca-bundle.crt`
- For Go apps: set `SSL_CERT_FILE=/path/to/ca-bundle.crt`

### mTLS: "ERR_BAD_SSL_CLIENT_AUTH_CERT"
Your client certificate is invalid, expired, or not signed by the Portcullis CA. Re-enroll your YubiKey via the Enrollment UI.

### mTLS: "ERR_SSL_CLIENT_AUTH_CERT_NEEDED" on Vault UI
The Vault UI uses the `protected` tier and requires a client cert. If you haven't enrolled a PIV cert, you can't access it. Either:
- Enroll a PIV cert first
- Or disable mTLS (`MTLS_ENABLED=false`) to access Vault via WebAuthn
