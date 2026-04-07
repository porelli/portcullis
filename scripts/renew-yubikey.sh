#!/usr/bin/env bash
#
# Renews the certificate on a YubiKey without regenerating the key pair.
# Use this for daily re-enrollment (the key stays, only the cert rotates).
#
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-myroot}"
PIV_SLOT="${PIV_SLOT:-9a}"
PIV_PIN="${PIV_PIN:-123456}"
TTL="${TTL:-24h}"

export VAULT_ADDR VAULT_TOKEN

usage() {
  echo "Usage: $0 <username> [email]"
  echo "Renews the certificate on an already-enrolled YubiKey."
  exit 1
}

[ $# -lt 1 ] && usage

USERNAME="$1"
EMAIL="${2:-${USERNAME}@portcullis.local}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "==> Checking for YubiKey..."
ykman info > /dev/null 2>&1 || { echo "ERROR: No YubiKey detected."; exit 1; }

echo "==> Exporting public key from existing slot $PIV_SLOT..."
ykman piv keys export "$PIV_SLOT" "$TMPDIR/pubkey.pem" 2>/dev/null || {
  echo "ERROR: No key found in slot $PIV_SLOT. Run enroll-yubikey.sh first."
  exit 1
}

echo "==> Generating CSR..."
ykman piv certificates request \
  --subject "CN=${USERNAME},emailAddress=${EMAIL}" \
  --hash-algorithm SHA256 \
  "$PIV_SLOT" \
  "$TMPDIR/pubkey.pem" \
  "$TMPDIR/request.csr" \
  --pin "$PIV_PIN"

echo "==> Requesting new certificate from Vault..."
CSR_CONTENT=$(cat "$TMPDIR/request.csr")

vault write -format=json pki_int/sign/client-cert \
  csr="$CSR_CONTENT" \
  common_name="$USERNAME" \
  ttl="$TTL" \
  | jq -r '.data.certificate' > "$TMPDIR/client.crt"

echo "==> Writing certificate to YubiKey..."
ykman piv certificates import \
  "$PIV_SLOT" \
  "$TMPDIR/client.crt" \
  --pin "$PIV_PIN" \
  --verify

echo "==> Renewal complete for $USERNAME (TTL: $TTL)"
