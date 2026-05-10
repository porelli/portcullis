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

Most apps use `authaware` — users with a PIV certificate (YubiKey) are authenticated automatically via X.509, while users without a cert fall through to WebAuthn.

Vault UI uses `protected` — it requires a valid client certificate (highest security tier).

**Issuing client certificates:**

1. Users enroll their YubiKey PIV slot via the Enrollment UI (`enroll.<domain>`)
2. The Enrollment UI signs a CSR using Vault's PKI engine
3. Certificates are short-lived (24 hours) and automatically renewable

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
