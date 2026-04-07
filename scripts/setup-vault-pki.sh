#!/usr/bin/env bash
#
# Initializes Vault PKI with a Root CA and an Intermediate CA
# for issuing short-lived client certificates.
#
# In production with ACME, server certs come from Let's Encrypt.
# Vault PKI is used ONLY for the client certificate CA chain.
# Pass --with-server-cert to also generate a self-signed server cert (for local dev).
#
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-myroot}"
CERT_DIR="${CERT_DIR:-./certs}"
DOMAIN="${DOMAIN:-portcullis.local}"
TTL_ROOT="87600h"          # 10 years
TTL_INTERMEDIATE="43800h"  # 5 years
TTL_CLIENT="24h"           # short-lived client certs
GEN_SERVER_CERT=false

for arg in "$@"; do
  case "$arg" in
    --with-server-cert) GEN_SERVER_CERT=true ;;
  esac
done

export VAULT_ADDR VAULT_TOKEN

mkdir -p "$CERT_DIR"

echo "==> Enabling PKI secrets engine (root)..."
vault secrets enable -path=pki pki 2>/dev/null || true
vault secrets tune -max-lease-ttl="$TTL_ROOT" pki

echo "==> Generating Root CA..."
vault write -format=json pki/root/generate/internal \
  common_name="$DOMAIN Root CA" \
  ttl="$TTL_ROOT" \
  | jq -r '.data.certificate' > "$CERT_DIR/root-ca.crt"

vault write pki/config/urls \
  issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
  crl_distribution_points="$VAULT_ADDR/v1/pki/crl"

echo "==> Enabling PKI secrets engine (intermediate)..."
vault secrets enable -path=pki_int pki 2>/dev/null || true
vault secrets tune -max-lease-ttl="$TTL_INTERMEDIATE" pki_int

echo "==> Generating Intermediate CA CSR..."
vault write -format=json pki_int/intermediate/generate/internal \
  common_name="$DOMAIN Intermediate CA" \
  | jq -r '.data.csr' > "$CERT_DIR/intermediate.csr"

echo "==> Signing Intermediate CA with Root..."
vault write -format=json pki/root/sign-intermediate \
  csr=@"$CERT_DIR/intermediate.csr" \
  format=pem_bundle \
  ttl="$TTL_INTERMEDIATE" \
  | jq -r '.data.certificate' > "$CERT_DIR/intermediate-ca.crt"

echo "==> Setting signed intermediate certificate..."
vault write pki_int/intermediate/set-signed \
  certificate=@"$CERT_DIR/intermediate-ca.crt"

vault write pki_int/config/urls \
  issuing_certificates="$VAULT_ADDR/v1/pki_int/ca" \
  crl_distribution_points="$VAULT_ADDR/v1/pki_int/crl"

echo "==> Creating client certificate role..."
vault write pki_int/roles/client-cert \
  allowed_domains="$DOMAIN" \
  allow_any_name=true \
  enforce_hostnames=false \
  client_flag=true \
  server_flag=false \
  key_type=ec \
  key_bits=256 \
  max_ttl="$TTL_CLIENT" \
  ttl="$TTL_CLIENT" \
  no_store=false

echo "==> Building CA chain (for mTLS client cert validation)..."
cat "$CERT_DIR/root-ca.crt" "$CERT_DIR/intermediate-ca.crt" > "$CERT_DIR/ca-chain.crt"

if [ "$GEN_SERVER_CERT" = true ]; then
  echo "==> Generating self-signed server certificate (local dev)..."

  # Need a server-cert role that allows server flag
  vault write pki_int/roles/server-cert \
    allowed_domains="$DOMAIN" \
    allow_subdomains=true \
    allow_bare_domains=true \
    allow_glob_domains=true \
    client_flag=false \
    server_flag=true \
    key_type=ec \
    key_bits=256 \
    max_ttl="8760h" \
    ttl="8760h" \
    no_store=false

  vault write -format=json pki_int/issue/server-cert \
    common_name="*.$DOMAIN" \
    alt_names="$DOMAIN,localhost" \
    ip_sans="127.0.0.1" \
    ttl="8760h" \
    | tee >(jq -r '.data.certificate' > "$CERT_DIR/server.crt") \
    | jq -r '.data.private_key' > "$CERT_DIR/server.key"

  echo "    Server cert:     $CERT_DIR/server.crt (wildcard: *.$DOMAIN)"
fi

echo ""
echo "==> Vault PKI setup complete."
echo "    Root CA:         $CERT_DIR/root-ca.crt"
echo "    Intermediate CA: $CERT_DIR/intermediate-ca.crt"
echo "    CA chain:        $CERT_DIR/ca-chain.crt"
echo ""
echo "    The CA chain is used by Traefik to validate client certificates."
echo "    Server TLS certificates are managed by ACME (Let's Encrypt)."
echo "    For local dev without ACME, re-run with: $0 --with-server-cert"
