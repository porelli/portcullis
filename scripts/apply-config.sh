#!/usr/bin/env bash
#
# apply-config.sh — Reads ACME_STAGING and MTLS_ENABLED from .env
# and applies the corresponding configuration changes.
#
# Run after editing .env toggles:
#   ./scripts/apply-config.sh
#   docker compose up -d --force-recreate traefik
#
set -euo pipefail
cd "$(dirname "$0")/.."

ENV_FILE=".env"
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: .env file not found. Run ./scripts/bootstrap.sh first."
  exit 1
fi

# Read values
ACME_STAGING=$(grep '^ACME_STAGING=' "$ENV_FILE" | cut -d= -f2 | tr -d ' "' || echo "true")
MTLS_ENABLED=$(grep '^MTLS_ENABLED=' "$ENV_FILE" | cut -d= -f2 | tr -d ' "' || echo "true")

echo "Configuration:"
echo "  ACME_STAGING=$ACME_STAGING"
echo "  MTLS_ENABLED=$MTLS_ENABLED"
echo ""

# ── ACME Staging / Production ──────────────────────────────
if [ "$ACME_STAGING" = "true" ]; then
  CA_SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"
  echo "TLS: Using Let's Encrypt STAGING (untrusted certs)"
  echo "     Browsers will show certificate warnings."
  echo "     Chrome: /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --ignore-certificate-errors"

  # Create CA bundle with staging CA for app containers
  if [ -f certs/ca-chain.crt ]; then
    # Fetch Let's Encrypt staging root if not cached
    STAGING_CA="certs/letsencrypt-stg-root-x1.pem"
    if [ ! -f "$STAGING_CA" ]; then
      curl -sf -o "$STAGING_CA" "https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem" 2>/dev/null || true
    fi
    # Combine system CAs + staging root + our PKI chain
    cat /etc/ssl/certs/ca-certificates.crt "$STAGING_CA" certs/ca-chain.crt > certs/ca-bundle-with-staging.crt 2>/dev/null || \
    cat certs/ca-chain.crt "$STAGING_CA" > certs/ca-bundle-with-staging.crt 2>/dev/null || true
    echo "     Created certs/ca-bundle-with-staging.crt"
  fi
else
  CA_SERVER="https://acme-v02.api.letsencrypt.org/directory"
  echo "TLS: Using Let's Encrypt PRODUCTION (trusted certs)"

  # Production certs don't need a custom CA bundle
  # Create a symlink so containers that mount ca-bundle-with-staging.crt still work
  if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    cp /etc/ssl/certs/ca-certificates.crt certs/ca-bundle-with-staging.crt
  fi
  echo "     certs/ca-bundle-with-staging.crt → system CA bundle"
fi

# Update ACME_CA_SERVER in .env
if grep -q '^ACME_CA_SERVER=' "$ENV_FILE"; then
  sed -i "s|^ACME_CA_SERVER=.*|ACME_CA_SERVER=$CA_SERVER|" "$ENV_FILE"
else
  echo "ACME_CA_SERVER=$CA_SERVER" >> "$ENV_FILE"
fi
echo "     ACME_CA_SERVER=$CA_SERVER"
echo ""

# ── mTLS Toggle ──────────────────────────────────────────
TLS_CONFIG="traefik/dynamic/tls.yml"

if [ "$MTLS_ENABLED" = "true" ]; then
  echo "mTLS: ENABLED — client certificates requested (PIV/YubiKey)"
  cat > "$TLS_CONFIG" << 'EOF'
# TLS options for the three access tiers.
# mTLS ENABLED — client certificates are requested.
tls:
  options:
    protected:
      clientAuth:
        caFiles:
          - /certs/ca-chain.crt
        clientAuthType: RequireAndVerifyClientCert
      minVersion: VersionTLS12
      sniStrict: false

    authaware:
      clientAuth:
        caFiles:
          - /certs/ca-chain.crt
        clientAuthType: VerifyClientCertIfGiven
      minVersion: VersionTLS12
      sniStrict: false

    public:
      minVersion: VersionTLS12
      sniStrict: false
EOF
else
  echo "mTLS: DISABLED — no client certificates (WebAuthn-only)"
  cat > "$TLS_CONFIG" << 'EOF'
# TLS options — mTLS DISABLED.
# All tiers use public TLS (no client certificates).
# Authentication is WebAuthn-only via Keycloak.
tls:
  options:
    protected:
      minVersion: VersionTLS12
      sniStrict: false

    authaware:
      minVersion: VersionTLS12
      sniStrict: false

    public:
      minVersion: VersionTLS12
      sniStrict: false
EOF
fi
echo "     Updated $TLS_CONFIG"
echo ""

echo "Done. Restart Traefik to apply:"
echo "  docker compose up -d --force-recreate traefik"
