#!/usr/bin/env bash
#
# Portcullis cert revocation — revoke a client certificate and enforce it.
#
# Usage:
#   ./scripts/revoke-cert.sh <serial>           # revoke by serial number (asks to confirm)
#   ./scripts/revoke-cert.sh --yes <serial>     # revoke without prompting
#   ./scripts/revoke-cert.sh --list             # list all certs (find serial)
#   ./scripts/revoke-cert.sh --list-revoked     # list revoked certs
#   ./scripts/revoke-cert.sh --sync             # rewrite the revoked-serials file from Vault
#
# The serial number is shown in the enrollment UI (/certs) or by --list.
#
# How revocation is enforced: Traefik does NOT check CRLs. group-gate
# (portcullis-groups@docker) denies any request whose TLS client cert has a
# revoked serial. It learns revoked serials from
#   - certs/revocation/revoked-serials.txt (rewritten by this script from
#     Vault's authoritative list — takes effect on the next request), and
#   - Vault's CRL (http://vault:8200/v1/pki_int/crl, re-fetched every 60s),
#     which also covers revocations done via the Vault API/UI directly.
# Only routers whose middleware chain contains client-headers@file BEFORE
# portcullis-groups@docker are covered.
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

# shellcheck source=lib/vault-common.sh
source "$SCRIPT_DIR/lib/vault-common.sh"
vault_admin_env || exit 1
# Host vault CLI if installed, else the CLI inside the vault container.
vault_use_container_cli || exit 1

REVOKED_FILE="certs/revocation/revoked-serials.txt"

# sync_revoked_file — rewrite $REVOKED_FILE from Vault's list of revoked
# serials. Aborts (file untouched) if Vault can't be queried.
sync_revoked_file() {
  write_revoked_serials "$REVOKED_FILE" || fail "Could not refresh $REVOKED_FILE (left unchanged)."
  ok "Revoked-serial list updated: $REVOKED_FILE ($(grep -vc '^#' "$REVOKED_FILE" || true) serial(s))"
}

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

if [ "${1:-}" = "--sync" ]; then
  sync_revoked_file
  exit 0
fi

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  echo "Usage: $0 [--yes] <serial>   Revoke cert by serial number"
  echo "       $0 --list             List all active certificates"
  echo "       $0 --list-revoked     List all certificates including revoked"
  echo "       $0 --sync             Rewrite $REVOKED_FILE from Vault"
  echo ""
  echo "Find serial numbers with --list or in the enrollment UI (/certs)."
  exit 0
fi

# ── Revoke mode ────────────────────────────────────────────

ASSUME_YES=false
if [ "${1:-}" = "--yes" ] || [ "${1:-}" = "-y" ]; then
  ASSUME_YES=true
  shift
fi

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
  sync_revoked_file
  exit 0
fi

echo ""
echo "  Certificate to revoke:"
echo "    Subject:  $CN"
echo "    Serial:   $SERIAL"
echo "    Expires:  $END_DATE"
echo ""

if [ "$ASSUME_YES" != true ]; then
  read -rp "Revoke this certificate? [y/N] " CONFIRM
  case "$CONFIRM" in
    y|Y|yes|YES) ;;
    *) echo "Cancelled."; exit 0 ;;
  esac
fi

# Revoke
info "Revoking certificate..."
vault write pki_int/revoke serial_number="$SERIAL" || fail "Revocation failed"
ok "Certificate revoked."

# Rotate CRL (Vault rebuilds it on revoke; this is belt and braces)
info "Rotating CRL..."
vault read -format=json pki_int/crl/rotate >/dev/null 2>&1 || warn "CRL rotate failed (group-gate still uses the serial file)"

# Enforce: group-gate reads this file on every request.
sync_revoked_file

# Keep a PEM copy of the CRL for tools that want one (e.g. Keycloak X.509
# CRL checking with a file URL). NOT used by Traefik.
CRL_PEM=$(curl -sf "$VAULT_ADDR/v1/pki_int/crl/pem" 2>/dev/null || true)
if [ -n "$CRL_PEM" ]; then
  printf '%s\n' "$CRL_PEM" > certs/crl.pem
fi

echo ""
ok "Requests presenting this certificate are now denied by group-gate on every"
ok "router using client-headers@file + portcullis-groups@docker (all core routers"
ok "and the default app templates)."
warn "NOT covered: routers that rely on the TLS client cert alone (protected tier"
warn "without portcullis-groups@docker) — Traefik does not check CRLs. Client certs"
warn "are short-lived (24h), so such routers stop accepting it when it expires."
warn "A Keycloak session that was opened with this cert stays valid until it ends;"
warn "to cut it now, sign the user out in the Keycloak admin console."
echo ""
echo "  To verify revocation:"
echo "    vault read pki_int/cert/$SERIAL | grep revocation_time"
echo "    grep -i '$SERIAL' $REVOKED_FILE"
echo ""
