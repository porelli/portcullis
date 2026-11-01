# TLS Certificates & mTLS

Portcullis uses two independent TLS features that can be toggled independently:

| Setting | `.env` variable | Default | What it controls |
|---------|----------------|---------|------------------|
| **Certificate source** | `ACME_STAGING` | `false` | Staging (test) vs production (trusted) Let's Encrypt certs |
| **Client certificates** | `MTLS_ENABLED` | `true` | Whether Traefik requests mTLS client certs (PIV/YubiKey) |

After changing either toggle, run:

```bash
./portcullis config apply
./portcullis up
```

`config apply` rewrites `traefik/dynamic/tls.yml` (hot-reloaded by Traefik) and `ACME_CA_SERVER` in `.env`; `up` recreates Traefik when its environment changed.

---

## ACME Staging vs Production

### Staging (`ACME_STAGING=true`)

- Uses Let's Encrypt **staging** CA — no rate limits, but **browsers won't trust the certificate**.
- Great for initial setup, testing, and development.
- App containers that talk to Keycloak over HTTPS mount `certs/ca-bundle.crt`, which `portcullis config apply` (and `init`, `up`, `upgrade`) builds from: system CAs + the internal Portcullis PKI chain + the Let's Encrypt staging root (only when `ACME_STAGING=true`). This is handled automatically.

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

2. Apply and restart (`config apply` notices the staging→production flip
   and clears Traefik's `acme.json`, so a new certificate is requested):
   ```bash
   ./portcullis config apply
   ./portcullis up
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

1. An admin enrolls a user's YubiKey PIV slot via the Enrollment UI (`enroll.<domain>`) or `./portcullis cert enroll`
2. The Enrollment UI signs a CSR using Vault's PKI engine (with a least-privilege AppRole, see below)
3. Certificates live `CLIENT_CERT_TTL` (default `720h` = 30 days). Users renew their own certificate at `https://enroll.<domain>/self` while it is still valid (see below)

### Lifetime and renewal

Certificates used to live 24 h, which meant a manual `cert renew` with the YubiKey every day: in practice certs expired and users fell back to other factors. The short lifetime was standing in for revocation. Revocation is now enforced everywhere a cert is accepted (group-gate on every request, Keycloak's X.509 login against the CRL, and the mTLS binding below), so the lifetime only sets how often people renew:

- **`CLIENT_CERT_TTL`** in `.env`, default `720h` (30 days); `portcullis pki setup` / `upgrade` rewrites the Vault `client-cert` role with it (new certs only). 90 days (`2160h`) is reasonable if you revoke lost keys promptly.
- **Self-service renewal** at `https://enroll.<domain>/self` (any signed-in user, router `enroll-self` with `portcullis-self@docker`): the browser must present the user's **current, valid, unrevoked** cert (Traefik passes it to enroll via `client-cert-pem@file`), its CN must be the signed-in user, Vault must have issued exactly that cert, and the pasted CSR must be for **the same public key** (`ykman piv keys export 9a` + `ykman piv certificates request`). The key never leaves the YubiKey; an expired or revoked cert cannot be renewed this way (an admin re-enrolls).
- **CLI**: `./portcullis cert renew <user>` on the Portcullis host (with the YubiKey attached).
- **Warnings**: `portcullis status` (and `--json` → `vault.certs_expiring`) lists users whose newest cert has less than `CERT_EXPIRY_WARN_DAYS` (default 7) days left; `cert list` marks them `expiring`; the enrollment UI flags them.

### mTLS login through Keycloak

`auth.<domain>` uses the **authaware** tier, so the browser can present the YubiKey cert to Keycloak. Traefik verifies it against `certs/ca-chain.crt` and forwards it PEM-encoded in `X-Forwarded-Tls-Client-Cert` (`client-cert-pem@file`); Keycloak reads it with its built-in **`traefik` x509 lookup provider** (`--spi-x509cert-lookup--provider=traefik`, made for Traefik's `passTLSClientCert` `pem: true` format: comma-separated PEM bodies). The realm's X.509 authenticator (`x509-config`) then:

- maps the Subject CN to the LLDAP username,
- **re-validates** the chain against `certs/truststore/` (written by `pki setup`, mounted as Keycloak's truststore) and checks the validity period and the `clientAuth` EKU,
- **checks the CRLs** at `http://vault:8200/v1/pki_int/crl` and `.../crl/delta` (`##`-separated in `crl-relative-path`; Keycloak caches each for at most 60 s). pki_int has `auto_rebuild=true` (keeps the full CRL from going stale) and therefore `enable_delta=true`: Vault does **not** rebuild the full CRL on revoke, new revocations land in the delta CRL (rebuilt every minute) until the next full rebuild. `portcullis cert revoke` also rotates the full CRL immediately.

- **fails closed on the CRL**: if the CRL cannot be fetched the X.509 login fails, and `x509-cert-auth-crl-abort-if-non-updated=true` (that is Keycloak's actual key, with a dash) also rejects a CRL past its `nextUpdate`. Vault never lets it get there: `pki setup` sets `pki_int/config/crl` to `expiry=72h auto_rebuild=true auto_rebuild_grace_period=12h`, and every revoke rebuilds it.

**Header spoofing.** A cert header carries only the public certificate, so whoever can put it in front of Keycloak could log in as that user. What prevents it:

- Keycloak's header-based lookup providers (`traefik` included) return no certificate unless `HttpRequest.isProxyTrusted()`. With `--proxy-trusted-addresses` set, Quarkus decides that **from the TCP peer address of every request** and overwrites any `X-Forwarded-Trusted-Proxy` header the client sent (`ForwardedParser`, run before routing). The only trusted address is Traefik's fixed IP on the internal `portcullis-auth` network (`PORTCULLIS_AUTH_TRAEFIK_IP`, outside the dynamic range, so no other container can get it). Requests via `127.0.0.1:8080` (the CLI's admin API access; it arrives from the Docker gateway), the `portcullis` network or another container attached to `portcullis-auth` are untrusted: the cert header is ignored (Keycloak logs `HTTP header "X-Forwarded-Tls-Client-Cert" is not trusted`), and so are their `X-Forwarded-*`.
- Traefik deletes client-supplied `X-Forwarded-Tls-Client-Cert*` headers on the entrypoint (also for requests without a TLS client cert, where `passTLSClientCert` itself would leave them alone), plus their `_`/`.` aliases (`aliasHeadersStrategy=delete`).
- CI (`build-and-test`) logs in through Traefik with a real cert (must succeed), then sends the same enrolled cert as a forged header straight to Keycloak from the `portcullis` and `portcullis-auth` networks and from `127.0.0.1:8080`, with the realm's HTTPS requirement temporarily off so only the proxy gate can stop it. None may get an authorization code.

`portcullis keycloak configure` pushes the `x509-config` settings from `keycloak/realm-export.json` to an existing realm.

### Sign-in levels (Keycloak browser flow)

`portcullis-universal` (kept equal to `keycloak/realm-export.json` by `portcullis keycloak configure`) has **no password**:

| acr (LoA) | Satisfied by | amr |
|-----------|--------------|-----|
| `pwd` (1) | the client cert (automatic when the browser presents one) or a passkey | `mtls` / `hwk` |
| `hwk` (2) | reaching LoA 1 — every LoA 1 factor is hardware-backed, so no second touch | (same) |
| `mtls` (3) | the client cert | `mtls` |

oauth2-proxy asks for `hwk` by default; group-gate asks for `mtls` when a policy needs the cert. Keycloak's step-up on an existing session asks only for the levels it has not reached (no `prompt=login`). A user's first passkey comes from a one-time setup link (`./portcullis invite <user>`, or the Hub): Keycloak 26.8 cannot enrol a passkey from inside the flow (`WebAuthnPasswordlessAuthenticatorFactory.isUserSetupAllowed()` is false). The setup link signs the user in through the hidden identity provider `portcullis-invite` (enroll) with LoA 2 / amr `hwk`, after the passkey registration it requires. Details: [hardening](hardening.md#header-trust).

### mTLS binding (group-gate)

A token with `amr=mtls` proves a cert was used **at login**. When an app's policy is satisfied **only** through the `mtls` factor (`mtls` alone, `all` including `mtls`, or `any` where `mtls` is the only factor in the token), group-gate also requires the **current request** to carry a client cert that is not revoked and whose CN equals the session's `preferred_username`. Otherwise the user gets the step-up page (`acr_values=mtls`). So a session opened with a cert that is revoked later, or replayed from another browser without the key, stops working immediately.

### Revoking client certificates

```bash
./portcullis cert list                # find the serial (--all includes revoked)
./portcullis cert revoke <serial>     # revoke (add --yes to skip the prompt)
./portcullis cert sync                # rewrite the serial list from Vault
```

**Traefik does not check CRLs** — a TLS handshake with a revoked-but-unexpired cert still succeeds. Revocation is enforced by **group-gate** (`portcullis-groups@docker`): `client-headers@file` (Traefik `passTLSClientCert`, with `serialNumber: true`) passes `X-Forwarded-Tls-Client-Cert-Info` to the backend *and* to every later forward-auth middleware, and group-gate returns 403 when the cert's serial is revoked. Sources:

- `certs/revocation/revoked-serials.txt` — rewritten atomically by `portcullis cert revoke` / `cert sync` from Vault's list of revoked serials; checked on the next request. If Vault can't be queried (sealed, bad token, unreachable) the file is left unchanged and the command fails — it never "un-revokes" by writing an empty list.
- Vault's full and delta CRL (`GATE_CRL_URL` = `http://vault:8200/v1/pki_int/crl`, `GATE_DELTA_CRL_URL` = `.../crl/delta`), re-fetched every 60 s (`GATE_CRL_REFRESH_SECONDS`); the union is enforced — also covers revocations made directly through the Vault API/UI, which reach the delta CRL within about 2 minutes (Vault's periodic rebuild runs once a minute) and are denied at group-gate's next refresh. If Vault is unreachable the last good copy of each CRL is kept.

Coverage: every router whose middleware chain has `client-headers@file` **before** `portcullis-groups@docker` (all core routers and the default app templates), new Keycloak X.509 logins (CRL), and sessions on mtls-only policies (mTLS binding above). **Not covered:** routers that rely on the TLS client cert alone (e.g. a `protected`-tier router without `portcullis-groups@docker`) — Traefik never checks CRLs, so there the cert works until it expires — and password/WebAuthn sessions of the same user (sign them out in the Keycloak admin console if needed).

## Vault storage, unsealing & tokens

Vault runs in **server mode** with integrated (raft) storage on the `vault_data` volume (`vault/vault.hcl`), so the CA survives restarts. The listener is plain HTTP on the internal `portcullis` network and `127.0.0.1:8200` on the host only.

`./portcullis vault init` (run by `portcullis init`, `upgrade` and `restore`; idempotent) does:

1. **Init** (first run only) with **one key share, threshold 1**, writing to `secrets/` (dir `0700`, gitignored):
   - `secrets/vault-init.json` — root token + unseal key (`vault operator init` output), `0600`
   - `secrets/vault-unseal/unseal-key` — mounted read-only into the vault container, which runs as the image's non-root `vault` user (100:1000): the file is owned by you, group 1000, `0640` (dir `0750`)
2. **Unseal**. Afterwards `vault/entrypoint.sh` unseals automatically on every container start (`docker compose up`, restart, host reboot).
3. **Least privilege for enroll**: AppRole `portcullis-enroll` with policy `vault/policies/enroll.hcl` (only `pki_int/sign/client-cert`, list `pki_int/certs`, read `pki_int/cert/*`). Credentials in `secrets/enroll/` (group 10002 = the enroll user, `0640`) are mounted read-only into enroll, which logs in for 1 h tokens and logs in again before expiry or on 403 — there is no static or root token in `.env`. Rotate with `./portcullis vault rotate-enroll-secret`.

The admin commands (`portcullis pki setup`, `cert enroll|renew|revoke|list|sync`, `status`) use the root token from `secrets/vault-init.json`, or `VAULT_TOKEN` if exported. They use the host `vault` CLI if installed, otherwise the CLI inside the vault container (token passed by environment-variable name, never on the command line). `secrets/` and `backups/` are masked from the Hub container with empty tmpfs mounts.

`portcullis pki setup` is idempotent: it never replaces an existing CA (only missing pieces such as the `client-cert` role or the exported CA files are recreated); if it finds an incomplete PKI (an earlier run aborted before the intermediate was signed) it wipes and recreates it; any Vault error aborts instead of being mistaken for "no PKI". If Vault has no CA but `certs/ca-chain.crt` exists (Vault data lost), it refuses to create a new CA — restore a backup, or pass `--force` to create a new one (every client cert must then be re-enrolled). `certs/server.key` is written `0640` with group 0 (Traefik runs as root but without `CAP_DAC_OVERRIDE`). The CLI changes group ownership through a throwaway root container (`alpine`, only `CAP_CHOWN`, no network) when it is not run as root.

**Trade-off.** The unseal key lives on the same host as the encrypted data, so root on the host (or anyone who can read `secrets/`) can unseal Vault. What it does protect: a copy of the `vault_data` volume alone is useless. Multiple Shamir shares on the same disk would add nothing, hence one share. For stronger guarantees remove the `secrets/vault-unseal` mount and unseal manually (`docker compose exec vault vault operator unseal`) after each restart, or use a cloud KMS auto-unseal. **Keep an offline copy of `secrets/vault-init.json`** — backups made by `portcullis backup` / `upgrade` include `secrets/` (and a raft snapshot of Vault), so protect them like the keys themselves; off-host copies are encrypted with `BACKUP_PASSWORD` ([backups.md](backups.md)).

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
   ./portcullis config apply
   ./portcullis up
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
- `certs/ca-bundle.crt` exists (run `./portcullis config apply --bundle-only`)
- The container mounts it (check compose.yml for `ca-bundle.crt` volume mount)
- For Node.js apps: set `NODE_EXTRA_CA_CERTS=/path/to/ca-bundle.crt`
- For Go apps: set `SSL_CERT_FILE=/path/to/ca-bundle.crt`

### mTLS: "ERR_BAD_SSL_CLIENT_AUTH_CERT"
Your client certificate is invalid, expired, or not signed by the Portcullis CA. Re-enroll your YubiKey via the Enrollment UI.

### mTLS: "ERR_SSL_CLIENT_AUTH_CERT_NEEDED" on Vault UI
The Vault UI uses the `protected` tier and requires a client cert. If you haven't enrolled a PIV cert, you can't access it. Either:
- Enroll a PIV cert first
- Or disable mTLS (`MTLS_ENABLED=false`) to access Vault via WebAuthn
