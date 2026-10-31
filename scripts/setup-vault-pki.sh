#!/usr/bin/env bash
#
# Initializes Vault PKI with a Root CA and an Intermediate CA
# for issuing short-lived client certificates.
#
# In production with ACME, server certs come from Let's Encrypt.
# Vault PKI is used ONLY for the client certificate CA chain.
# Pass --with-server-cert to also generate a self-signed server cert (for local dev).
#
# Root and intermediate keys are generated `internal` — they never leave
# Vault and are persisted (encrypted) in Vault's raft storage.
#
# Idempotent: if pki_int already has a CA the script exits without touching
# anything (re-generating would invalidate every enrolled client cert).
# Pass --force to wipe both PKI mounts and create a brand-new CA.
#
# Admin token: VAULT_TOKEN if set, else the root token from
# secrets/vault-init.json (see scripts/vault-init.sh). Uses the host
# `vault` CLI if installed, otherwise the CLI inside the vault container.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/vault-common.sh
source "$SCRIPT_DIR/lib/vault-common.sh"

CERT_DIR="${CERT_DIR:-./certs}"
DOMAIN="${DOMAIN:-portcullis.local}"
TTL_ROOT="87600h"          # 10 years
TTL_INTERMEDIATE="43800h"  # 5 years
TTL_CLIENT="24h"           # short-lived client certs
GEN_SERVER_CERT=false
FORCE=false

for arg in "$@"; do
  case "$arg" in
    --with-server-cert) GEN_SERVER_CERT=true ;;
    --force) FORCE=true ;;
  esac
done

vault_admin_env || exit 1

# Host vault CLI if installed, else the CLI inside the vault container.
vault_use_container_cli || exit 1

mkdir -p "$CERT_DIR" "$CERT_DIR/revocation"

# vault_probe <vault args...> — 0 = present, 2 = absent ("No value found",
# vault CLI exit 2), anything else aborts: a sealed Vault or a bad token
# must never be mistaken for "no PKI yet" (that would create a 2nd CA).
vault_probe() {
  local rc=0 out
  out="$(vault "$@" 2>&1)" || rc=$?
  case "$rc" in
    0) [ -n "$out" ] && return 0 || return 2 ;;
    2) return 2 ;;
    *) echo "ERROR: 'vault $*' failed (exit $rc):" >&2
       printf '%s\n' "$out" | sed 's/^/    /' >&2
       exit 1 ;;
  esac
}

issue_server_cert() {
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
    no_store=false >/dev/null

  local issued
  issued="$(vault write -format=json pki_int/issue/server-cert \
    common_name="*.$DOMAIN" \
    alt_names="$DOMAIN,localhost" \
    ip_sans="127.0.0.1" \
    ttl="8760h")"
  printf '%s\n' "$issued" | jq -r '.data.certificate' > "$CERT_DIR/server.crt"
  # Private key: owner-only (Traefik runs as root and can still read it).
  (umask 077 && printf '%s\n' "$issued" | jq -r '.data.private_key' > "$CERT_DIR/server.key")
  chmod 600 "$CERT_DIR/server.key"

  echo "    Server cert:     $CERT_DIR/server.crt (wildcard: *.$DOMAIN)"
}

write_client_role() {
  echo "==> Creating client certificate role..."
  # Client-auth only. The CN is always taken from the explicit common_name
  # parameter (enroll / enroll-yubikey.sh pass the LLDAP username), never from
  # the CSR, and CSR SANs are ignored — so a crafted CSR cannot smuggle in a
  # different identity. allow_any_name is needed because usernames are not
  # hostnames.
  vault write pki_int/roles/client-cert \
    allowed_domains="$DOMAIN" \
    allow_any_name=true \
    enforce_hostnames=false \
    use_csr_common_name=false \
    use_csr_sans=false \
    client_flag=true \
    server_flag=false \
    code_signing_flag=false \
    email_protection_flag=false \
    key_type=ec \
    key_bits=256 \
    max_ttl="$TTL_CLIENT" \
    ttl="$TTL_CLIENT" \
    no_store=false >/dev/null
}

MOUNTS="$(vault secrets list -format=json)" || { echo "ERROR: cannot list Vault secrets engines (sealed? bad token?)" >&2; exit 1; }
HAVE_PKI=false; HAVE_PKI_INT=false
printf '%s' "$MOUNTS" | jq -e 'has("pki/")' >/dev/null && HAVE_PKI=true
printf '%s' "$MOUNTS" | jq -e 'has("pki_int/")' >/dev/null && HAVE_PKI_INT=true

# The intermediate issuer is what signs client certs: once it exists, certs
# may depend on it and only --force may destroy it. Without it nothing can
# have been issued, so a partial earlier run (mounts / root issuer but no
# signed intermediate) is safe to wipe and redo.
INT_ISSUER=false
if [ "$HAVE_PKI_INT" = true ] && vault_probe list -format=json pki_int/issuers; then
  INT_ISSUER=true
fi

if [ "$INT_ISSUER" = true ] && [ "$FORCE" != true ]; then
  echo "==> Vault PKI already initialised — not touching the CA."
  echo "    Re-run with --force to DESTROY it and create a new CA (all client certs must then be re-enrolled)."
  if ! vault_probe read -format=json pki_int/roles/client-cert; then
    echo "==> client-cert role missing — recreating it."
    write_client_role
  fi
  # Re-export the public CA files if they are missing (e.g. fresh checkout).
  [ -s "$CERT_DIR/root-ca.crt" ] || vault read -field=certificate pki/cert/ca > "$CERT_DIR/root-ca.crt"
  [ -s "$CERT_DIR/intermediate-ca.crt" ] || vault read -field=certificate pki_int/cert/ca > "$CERT_DIR/intermediate-ca.crt"
  [ -s "$CERT_DIR/ca-chain.crt" ] || cat "$CERT_DIR/root-ca.crt" "$CERT_DIR/intermediate-ca.crt" > "$CERT_DIR/ca-chain.crt"
  [ -f "$CERT_DIR/revocation/revoked-serials.txt" ] || : > "$CERT_DIR/revocation/revoked-serials.txt"
  if [ "$GEN_SERVER_CERT" = true ] && [ ! -s "$CERT_DIR/server.crt" ]; then
    issue_server_cert
  fi
  exit 0
fi
if [ "$FORCE" = true ] || [ "$HAVE_PKI" = true ] || [ "$HAVE_PKI_INT" = true ]; then
  if [ "$FORCE" = true ]; then
    echo "==> --force: disabling existing PKI mounts (old CA and issued-cert records are destroyed)..."
  else
    echo "==> Found an INCOMPLETE PKI (earlier run aborted?) — wiping it and starting over."
    echo "    (An incomplete PKI has no usable intermediate CA, so no client certs depend on it.)"
  fi
  if [ "$HAVE_PKI_INT" = true ]; then vault secrets disable pki_int >/dev/null; fi
  if [ "$HAVE_PKI" = true ]; then vault secrets disable pki >/dev/null; fi
fi

echo "==> Enabling PKI secrets engine (root)..."
vault secrets enable -path=pki pki >/dev/null
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
vault secrets enable -path=pki_int pki >/dev/null
vault secrets tune -max-lease-ttl="$TTL_INTERMEDIATE" pki_int

echo "==> Generating Intermediate CA CSR..."
vault write -format=json pki_int/intermediate/generate/internal \
  common_name="$DOMAIN Intermediate CA" \
  | jq -r '.data.csr' > "$CERT_DIR/intermediate.csr"

echo "==> Signing Intermediate CA with Root..."
vault write -format=json pki/root/sign-intermediate \
  csr="$(cat "$CERT_DIR/intermediate.csr")" \
  format=pem_bundle \
  ttl="$TTL_INTERMEDIATE" \
  | jq -r '.data.certificate' > "$CERT_DIR/intermediate-ca.crt"

echo "==> Setting signed intermediate certificate..."
vault write pki_int/intermediate/set-signed \
  certificate="$(cat "$CERT_DIR/intermediate-ca.crt")"

vault write pki_int/config/urls \
  issuing_certificates="$VAULT_ADDR/v1/pki_int/ca" \
  crl_distribution_points="$VAULT_ADDR/v1/pki_int/crl"

write_client_role

echo "==> Building CA chain (for mTLS client cert validation)..."
cat "$CERT_DIR/root-ca.crt" "$CERT_DIR/intermediate-ca.crt" > "$CERT_DIR/ca-chain.crt"

# New CA → old revocations are meaningless; start an empty serial list
# (read by group-gate, maintained by revoke-cert.sh).
: > "$CERT_DIR/revocation/revoked-serials.txt"

if [ "$GEN_SERVER_CERT" = true ]; then
  issue_server_cert
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
