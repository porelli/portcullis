#!/usr/bin/env bash
#
# Portcullis cert revocation — revoke a client certificate and update CRL.
#
# Usage:
#   ./scripts/revoke-cert.sh <serial>           # revoke by serial number
#   ./scripts/revoke-cert.sh --list             # list all certs (find serial)
#   ./scripts/revoke-cert.sh --list-revoked     # list revoked certs
#
# The serial number is shown in the enrollment UI (/certs) or by --list.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
DIM='\033[2m'
NC='\033[0m'

info()  { echo -e "${BLUE}==>${NC} $*"; }
ok()    { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}==>${NC} $*"; }
fail()  { echo -e "${RED}ERROR:${NC} $*"; exit 1; }

[ -f .env ] || fail ".env not found."
set -a; source .env; set +a

export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_TOKEN="${VAULT_DEV_TOKEN:-}"

command -v vault >/dev/null || fail "vault CLI is required"

# ── List mode ──────────────────────────────────────────────

list_certs() {
  local show_revoked="${1:-false}"
  info "Fetching certificates from Vault..."

  SERIALS=$(vault list -format=json pki_int/certs 2>/dev/null) || fail "Cannot list certs. Is Vault running?"

  echo ""
  printf "  %-20s %-30s %-12s %s\n" "SERIAL" "COMMON NAME" "STATUS" "EXPIRES"
  printf "  %-20s %-30s %-12s %s\n" "------" "-----------" "------" "-------"

  NOW=$(date +%s)

  echo "$SERIALS" | jq -r '.[]' | while read -r serial; do
    CERT_DATA=$(vault read -format=json "pki_int/cert/$serial" 2>/dev/null) || continue
    CERT_PEM=$(echo "$CERT_DATA" | jq -r '.data.certificate')
    REVOCATION_TIME=$(echo "$CERT_DATA" | jq -r '.data.revocation_time // "0"')

    CN=$(echo "$CERT_PEM" | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
    END_DATE=$(echo "$CERT_PEM" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    END_EPOCH=$(date -j -f "%b %d %T %Y %Z" "$END_DATE" +%s 2>/dev/null || date -d "$END_DATE" +%s 2>/dev/null || echo "0")

    if [ "$REVOCATION_TIME" != "0" ] && [ "$REVOCATION_TIME" != "null" ]; then
      STATUS="${RED}revoked${NC}"
      [ "$show_revoked" = false ] && continue
    elif [ "$END_EPOCH" -lt "$NOW" ]; then
      STATUS="${RED}expired${NC}"
    elif [ $((END_EPOCH - NOW)) -lt 604800 ]; then
      STATUS="${YELLOW}expiring${NC}"
    else
      STATUS="${GREEN}valid${NC}"
    fi

    SHORT_SERIAL="${serial:0:18}.."
    printf "  %-20s %-30s " "$SHORT_SERIAL" "$CN"
    echo -e "$STATUS"
    printf "  %54s%s\n" "" "$END_DATE"
  done

  echo ""
}

if [ "${1:-}" = "--list" ]; then
  list_certs false
  exit 0
fi

if [ "${1:-}" = "--list-revoked" ]; then
  list_certs true
  exit 0
fi

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  echo "Usage: $0 <serial>           Revoke cert by serial number"
  echo "       $0 --list             List all active certificates"
  echo "       $0 --list-revoked     List all certificates including revoked"
  echo ""
  echo "Find serial numbers with --list or in the enrollment UI (/certs)."
  exit 0
fi

# ── Revoke mode ────────────────────────────────────────────

SERIAL="${1:-}"
[ -z "$SERIAL" ] && fail "Usage: $0 <serial-number>  (use --list to find serials)"

# Fetch the cert first to show what we're revoking
info "Looking up certificate $SERIAL..."
CERT_DATA=$(vault read -format=json "pki_int/cert/$SERIAL" 2>/dev/null) || fail "Certificate not found: $SERIAL"
CERT_PEM=$(echo "$CERT_DATA" | jq -r '.data.certificate')
CN=$(echo "$CERT_PEM" | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
END_DATE=$(echo "$CERT_PEM" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
REVOCATION_TIME=$(echo "$CERT_DATA" | jq -r '.data.revocation_time // "0"')

if [ "$REVOCATION_TIME" != "0" ] && [ "$REVOCATION_TIME" != "null" ]; then
  warn "Certificate is already revoked."
  exit 0
fi

echo ""
echo "  Certificate to revoke:"
echo "    Subject:  $CN"
echo "    Serial:   $SERIAL"
echo "    Expires:  $END_DATE"
echo ""

read -rp "Revoke this certificate? [y/N] " CONFIRM
case "$CONFIRM" in
  y|Y|yes|YES) ;;
  *) echo "Cancelled."; exit 0 ;;
esac

# Revoke
info "Revoking certificate..."
vault write pki_int/revoke serial_number="$SERIAL" || fail "Revocation failed"
ok "Certificate revoked."

# Rotate CRL
info "Rotating CRL..."
vault read -format=json pki_int/crl/rotate >/dev/null 2>&1
ok "CRL updated."

# Update CA chain + CRL bundle for Traefik
info "Updating CRL for Traefik..."
CRL_PEM=$(vault read -format=json pki_int/cert/crl 2>/dev/null | jq -r '.data.certificate // empty')
if [ -n "$CRL_PEM" ]; then
  CERTS_DIR="certs"
  mkdir -p "$CERTS_DIR"
  echo "$CRL_PEM" > "$CERTS_DIR/crl.pem"

  # Append CRL to ca-chain if not already there
  if [ -f "$CERTS_DIR/ca-chain.crt" ] && ! grep -q "X509 CRL" "$CERTS_DIR/ca-chain.crt" 2>/dev/null; then
    cat "$CERTS_DIR/crl.pem" >> "$CERTS_DIR/ca-chain.crt"
    ok "CRL appended to ca-chain.crt"
  fi

  ok "CRL saved to $CERTS_DIR/crl.pem"
fi

# Hint about reloading
echo ""
warn "Traefik will pick up the updated CRL automatically (file provider watches for changes)."
warn "For Keycloak X.509 CRL checking, configure the CRL URL in the realm's X.509 auth flow."
echo ""
echo "  To verify revocation:"
echo "    vault read pki_int/cert/$SERIAL | grep revocation_time"
echo ""
