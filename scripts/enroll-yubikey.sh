#!/usr/bin/env bash
#
# Enrolls a YubiKey by:
#   1. Generating a key pair on the YubiKey's PIV slot 9a (Authentication)
#   2. Creating a CSR from that key
#   3. Requesting a signed certificate from Vault
#   4. Writing the certificate back to the YubiKey
#
# Prerequisites:
#   - ykman (YubiKey Manager CLI)
#   - vault CLI (optional on the Portcullis host: falls back to the vault container)
#   - openssl
#   - A YubiKey 5 series inserted
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/vault-common.sh
source "$SCRIPT_DIR/lib/vault-common.sh"
# Admin token: VAULT_TOKEN if exported, else the root token from
# secrets/vault-init.json (only readable on the Portcullis host).
vault_admin_env || exit 1
vault_use_container_cli || exit 1
CERT_DIR="${CERT_DIR:-./certs}"
PIV_SLOT="${PIV_SLOT:-9a}"
PIV_PIN="${PIV_PIN:-123456}"
TTL="${TTL:-24h}"


usage() {
  cat <<EOF
Usage: $0 <username> [email]

Enrolls a YubiKey with a short-lived client certificate.

Arguments:
  username   The user's identity (used as CN in the certificate)
  email      Optional email address (used as SAN)

Environment variables:
  VAULT_ADDR    Vault server address (default: http://127.0.0.1:8200)
  VAULT_TOKEN   Vault admin token (default: root token from secrets/vault-init.json)
  PIV_SLOT      YubiKey PIV slot (default: 9a - Authentication)
  PIV_PIN       YubiKey PIV PIN (default: 123456)
  TTL           Certificate TTL (default: 24h)

EOF
  exit 1
}

[ $# -lt 1 ] && usage

USERNAME="$1"
EMAIL="${2:-${USERNAME}@portcullis.local}"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "==> Checking for YubiKey..."
if ! ykman info > /dev/null 2>&1; then
  echo "ERROR: No YubiKey detected. Insert your YubiKey and try again."
  exit 1
fi

SERIAL=$(ykman info 2>/dev/null | grep "Serial" | awk '{print $NF}')
echo "    Found YubiKey serial: $SERIAL"

echo "==> Generating key pair on YubiKey PIV slot $PIV_SLOT..."
ykman piv keys generate \
  --algorithm ECCP256 \
  --pin-policy DEFAULT \
  --touch-policy CACHED \
  "$PIV_SLOT" \
  "$TMPDIR/pubkey.pem" \
  --pin "$PIV_PIN" 2>/dev/null || {
    echo "WARNING: Slot $PIV_SLOT already has a key. Overwriting..."
    ykman piv keys generate \
      --algorithm ECCP256 \
      --pin-policy DEFAULT \
      --touch-policy CACHED \
      --force \
      "$PIV_SLOT" \
      "$TMPDIR/pubkey.pem" \
      --pin "$PIV_PIN"
  }

echo "==> Generating CSR on YubiKey..."
ykman piv certificates request \
  --subject "CN=${USERNAME},emailAddress=${EMAIL}" \
  --hash-algorithm SHA256 \
  "$PIV_SLOT" \
  "$TMPDIR/pubkey.pem" \
  "$TMPDIR/request.csr" \
  --pin "$PIV_PIN"

echo "==> Requesting signed certificate from Vault..."
CSR_CONTENT=$(cat "$TMPDIR/request.csr")

# common_name is mandatory: the client-cert role ignores the CSR subject.
vault write -format=json pki_int/sign/client-cert \
  csr="$CSR_CONTENT" \
  common_name="$USERNAME" \
  ttl="$TTL" \
  | jq -r '.data.certificate' > "$TMPDIR/client.crt"

echo "==> Writing certificate to YubiKey PIV slot $PIV_SLOT..."
ykman piv certificates import \
  "$PIV_SLOT" \
  "$TMPDIR/client.crt" \
  --pin "$PIV_PIN" \
  --verify

echo ""
echo "==> Enrollment complete!"
echo "    User:        $USERNAME"
echo "    Email:       $EMAIL"
echo "    YubiKey:     $SERIAL"
echo "    PIV Slot:    $PIV_SLOT"
echo "    Cert TTL:    $TTL"
echo "    Touch:       CACHED (touch once, then cached for 15s)"
echo ""
echo "    To verify:   ykman piv certificates export $PIV_SLOT - | openssl x509 -text -noout"
echo "    To re-enroll (daily): $0 $USERNAME $EMAIL"
