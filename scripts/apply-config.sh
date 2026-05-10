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
# Detect a flip vs the last-applied value. The ACME account and issued
# certs in acme.json are bound to the CA directory URL, so switching
# directions without wiping the file leaves Traefik trying to reuse a
# staging account against production (or vice versa) — it often keeps
# serving the old cert until the file is cleared.
SENTINEL="certs/.acme-staging-last"
LAST_STAGING=""
[ -f "$SENTINEL" ] && LAST_STAGING=$(cat "$SENTINEL")

if [ -n "$LAST_STAGING" ] && [ "$LAST_STAGING" != "$ACME_STAGING" ]; then
  echo "ACME_STAGING flipped: $LAST_STAGING → $ACME_STAGING"
  echo "  Clearing Traefik ACME storage so it re-registers against the new CA."
  # Stop Traefik if running (best-effort) and wipe acme.json
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^portcullis-traefik-1$'; then
    docker compose stop traefik >/dev/null 2>&1 || true
  fi
  docker volume inspect portcullis_traefik_acme >/dev/null 2>&1 && \
    docker run --rm -v portcullis_traefik_acme:/acme alpine sh -c 'rm -f /acme/acme.json' >/dev/null 2>&1 || true
  echo "  ACME storage cleared. Traefik will re-register on next start."
fi

if [ "$ACME_STAGING" = "true" ]; then
  CA_SERVER="https://acme-staging-v02.api.letsencrypt.org/directory"
  echo "TLS: Using Let's Encrypt STAGING (untrusted certs)"
  echo "     Browsers will show certificate warnings."
else
  CA_SERVER="https://acme-v02.api.letsencrypt.org/directory"
  echo "TLS: Using Let's Encrypt PRODUCTION (trusted certs)"
fi

# Build the CA bundle for app containers.
# Always includes:
#   - System CAs (so public issuers like Let's Encrypt production are trusted)
#   - Internal Portcullis PKI chain (so apps can verify internal-only certs)
# Adds staging root only when ACME_STAGING=true.
BUNDLE="certs/ca-bundle.crt"
mkdir -p certs

: > "$BUNDLE"
if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
  cat /etc/ssl/certs/ca-certificates.crt >> "$BUNDLE"
elif [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then
  cat /etc/pki/tls/certs/ca-bundle.crt >> "$BUNDLE"
fi
if [ -f certs/ca-chain.crt ]; then
  cat certs/ca-chain.crt >> "$BUNDLE"
fi
if [ "$ACME_STAGING" = "true" ]; then
  STAGING_CA="certs/letsencrypt-stg-root-x1.pem"
  if [ ! -f "$STAGING_CA" ]; then
    curl -sf -o "$STAGING_CA" "https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem" 2>/dev/null || true
  fi
  [ -f "$STAGING_CA" ] && cat "$STAGING_CA" >> "$BUNDLE"
fi
echo "     Wrote $BUNDLE (system + internal PKI$([ "$ACME_STAGING" = "true" ] && echo " + staging root"))"

# Record what we applied so we can detect the next flip.
echo "$ACME_STAGING" > "$SENTINEL"

# Update ACME_CA_SERVER in .env
if grep -q '^ACME_CA_SERVER=' "$ENV_FILE"; then
  sed -i.bak "s|^ACME_CA_SERVER=.*|ACME_CA_SERVER=$CA_SERVER|" "$ENV_FILE" && rm -f "${ENV_FILE}.bak"
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
