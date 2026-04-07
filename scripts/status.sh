#!/usr/bin/env bash
#
# Portcullis status — quick health overview of all services.
#
# Usage:
#   ./scripts/status.sh
#   ./scripts/status.sh --json    # machine-readable output
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
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

JSON_MODE=false
[ "${1:-}" = "--json" ] && JSON_MODE=true

[ -f .env ] || { echo "ERROR: .env not found. Is this a Portcullis deployment?"; exit 1; }
set -a; source .env; set +a

DOMAIN="${PORTCULLIS_DOMAIN:-portcullis.local}"
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"

# ── Helpers ────────────────────────────────────────────────

check_status() { echo -e "  ${GREEN}✓${NC} $*"; }
check_warn()   { echo -e "  ${YELLOW}!${NC} $*"; }
check_fail()   { echo -e "  ${RED}✗${NC} $*"; }
section()      { echo -e "\n${CYAN}$*${NC}"; }

# ── Docker Services ────────────────────────────────────────

if [ "$JSON_MODE" = true ]; then
  # JSON output
  SERVICES_JSON="["
  first=true
  while IFS= read -r line; do
    name=$(echo "$line" | jq -r '.Service // .Name')
    state=$(echo "$line" | jq -r '.State')
    health=$(echo "$line" | jq -r '.Health // "n/a"')
    [ "$first" = true ] && first=false || SERVICES_JSON+=","
    SERVICES_JSON+="{\"name\":\"$name\",\"state\":\"$state\",\"health\":\"$health\"}"
  done < <(docker compose ps --format json 2>/dev/null)
  SERVICES_JSON+="]"
else
  section "Services"
  while IFS= read -r line; do
    name=$(echo "$line" | jq -r '.Service // .Name')
    state=$(echo "$line" | jq -r '.State')
    health=$(echo "$line" | jq -r '.Health // "n/a"')
    status=$(echo "$line" | jq -r '.Status')

    if [ "$state" = "running" ] && [ "$health" = "healthy" ]; then
      check_status "$name ${DIM}($status)${NC}"
    elif [ "$state" = "running" ]; then
      check_warn "$name ${DIM}($status)${NC}"
    else
      check_fail "$name ${DIM}($status)${NC}"
    fi
  done < <(docker compose ps --format json 2>/dev/null)
fi

# ── Vault PKI ──────────────────────────────────────────────

if [ "$JSON_MODE" = false ]; then
  section "Vault PKI"
fi

VAULT_OK=false
VAULT_CERTS_JSON="[]"
if curl -sf "$VAULT_ADDR/v1/sys/health" >/dev/null 2>&1; then
  VAULT_OK=true
  export VAULT_TOKEN="${VAULT_DEV_TOKEN:-}"

  # Root CA expiry
  ROOT_EXPIRY=""
  if ROOT_CA=$(vault read -format=json pki/cert/ca 2>/dev/null); then
    ROOT_EXPIRY=$(echo "$ROOT_CA" | jq -r '.data.certificate' | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  fi

  # Intermediate CA expiry
  INT_EXPIRY=""
  if INT_CA=$(vault read -format=json pki_int/cert/ca 2>/dev/null); then
    INT_EXPIRY=$(echo "$INT_CA" | jq -r '.data.certificate' | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  fi

  # Issued certificates
  CERT_SERIALS=()
  if CERT_LIST=$(vault list -format=json pki_int/certs 2>/dev/null); then
    mapfile -t CERT_SERIALS < <(echo "$CERT_LIST" | jq -r '.[]')
  fi

  if [ "$JSON_MODE" = false ]; then
    check_status "Vault reachable"
    [ -n "$ROOT_EXPIRY" ] && check_status "Root CA expires: $ROOT_EXPIRY" || check_warn "Root CA: not found"
    [ -n "$INT_EXPIRY" ] && check_status "Intermediate CA expires: $INT_EXPIRY" || check_warn "Intermediate CA: not found"
    check_status "Issued certificates: ${#CERT_SERIALS[@]}"

    # Show certs expiring soon (within 7 days)
    NOW=$(date +%s)
    for serial in "${CERT_SERIALS[@]}"; do
      CERT_DATA=$(vault read -format=json "pki_int/cert/$serial" 2>/dev/null) || continue
      CERT_PEM=$(echo "$CERT_DATA" | jq -r '.data.certificate')
      CN=$(echo "$CERT_PEM" | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
      END_DATE=$(echo "$CERT_PEM" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
      END_EPOCH=$(date -j -f "%b %d %T %Y %Z" "$END_DATE" +%s 2>/dev/null || date -d "$END_DATE" +%s 2>/dev/null || echo "0")
      DAYS_LEFT=$(( (END_EPOCH - NOW) / 86400 ))

      if [ "$DAYS_LEFT" -lt 0 ]; then
        check_fail "  $CN — expired $((-DAYS_LEFT))d ago"
      elif [ "$DAYS_LEFT" -lt 7 ]; then
        check_warn "  $CN — expires in ${DAYS_LEFT}d"
      fi
    done
  fi
else
  if [ "$JSON_MODE" = false ]; then
    check_fail "Vault not reachable at $VAULT_ADDR"
  fi
fi

# ── Keycloak ───────────────────────────────────────────────

if [ "$JSON_MODE" = false ]; then
  section "Keycloak"
fi

KC_OK=false
KC_CLIENTS_JSON="[]"
if curl -sf "$KEYCLOAK_URL/health/ready" >/dev/null 2>&1; then
  KC_OK=true

  # Get admin token
  KC_TOKEN=$(curl -sk "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -d "client_id=admin-cli" \
    -d "username=${KEYCLOAK_ADMIN:-admin}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD:-admin}" \
    -d "grant_type=password" 2>/dev/null \
    | jq -r '.access_token')

  if [ "$KC_TOKEN" != "null" ] && [ -n "$KC_TOKEN" ]; then
    # Realm check
    REALM_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
      "$KEYCLOAK_URL/admin/realms/portcullis" \
      -H "Authorization: Bearer $KC_TOKEN")

    # OIDC clients
    CLIENTS_RAW=$(curl -sk "$KEYCLOAK_URL/admin/realms/portcullis/clients?max=100" \
      -H "Authorization: Bearer $KC_TOKEN" 2>/dev/null)
    CLIENT_IDS=$(echo "$CLIENTS_RAW" | jq -r '.[].clientId' 2>/dev/null | sort)

    # User count
    USER_COUNT=$(curl -sk "$KEYCLOAK_URL/admin/realms/portcullis/users/count" \
      -H "Authorization: Bearer $KC_TOKEN" 2>/dev/null || echo "?")

    if [ "$JSON_MODE" = false ]; then
      check_status "Keycloak reachable"
      [ "$REALM_STATUS" = "200" ] && check_status "Portcullis realm exists" || check_fail "Portcullis realm missing"
      check_status "Users: $USER_COUNT"

      # Check expected clients
      for expected in portcullis-forward-auth headscale headplane netbird-dashboard; do
        if echo "$CLIENT_IDS" | grep -qx "$expected"; then
          check_status "OIDC client: $expected"
        else
          check_warn "OIDC client missing: $expected"
        fi
      done
    fi
  else
    [ "$JSON_MODE" = false ] && check_warn "Keycloak reachable but admin auth failed"
  fi
else
  [ "$JSON_MODE" = false ] && check_fail "Keycloak not reachable at $KEYCLOAK_URL"
fi

# ── LLDAP ──────────────────────────────────────────────────

if [ "$JSON_MODE" = false ]; then
  section "LLDAP"
fi

LLDAP_OK=false
LLDAP_URL="http://localhost:17170"
if curl -sf "$LLDAP_URL" >/dev/null 2>&1; then
  LLDAP_OK=true

  # Get LLDAP user count via GraphQL
  LLDAP_TOKEN=$(curl -s "$LLDAP_URL/auth/simple/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"${LLDAP_ADMIN_PASSWORD:-admin}\"}" 2>/dev/null \
    | jq -r '.token // empty')

  if [ -n "$LLDAP_TOKEN" ]; then
    LLDAP_USERS=$(curl -s "$LLDAP_URL/api/graphql" \
      -H "Authorization: Bearer $LLDAP_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"query":"{ users { id } }"}' 2>/dev/null \
      | jq '.data.users | length' 2>/dev/null || echo "?")

    LLDAP_GROUPS=$(curl -s "$LLDAP_URL/api/graphql" \
      -H "Authorization: Bearer $LLDAP_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"query":"{ groups { id } }"}' 2>/dev/null \
      | jq '.data.groups | length' 2>/dev/null || echo "?")

    [ "$JSON_MODE" = false ] && check_status "LLDAP reachable — $LLDAP_USERS users, $LLDAP_GROUPS groups"
  else
    [ "$JSON_MODE" = false ] && check_warn "LLDAP reachable but auth failed"
  fi
else
  [ "$JSON_MODE" = false ] && check_fail "LLDAP not reachable at $LLDAP_URL"
fi

# ── Traefik ────────────────────────────────────────────────

if [ "$JSON_MODE" = false ]; then
  section "Traefik"
fi

TRAEFIK_API="http://localhost:8080/api"
TRAEFIK_OK=false
if ROUTERS=$(curl -sf "$TRAEFIK_API/http/routers" 2>/dev/null); then
  TRAEFIK_OK=true
  ROUTER_COUNT=$(echo "$ROUTERS" | jq 'length')
  TLS_COUNT=$(echo "$ROUTERS" | jq '[.[] | select(.tls)] | length')

  if [ "$JSON_MODE" = false ]; then
    check_status "Traefik reachable — $ROUTER_COUNT routers ($TLS_COUNT with TLS)"

    # Show routers by TLS tier
    for tier in protected authaware public; do
      TIER_ROUTERS=$(echo "$ROUTERS" | jq -r "[.[] | select(.tls.options == \"${tier}@file\")] | .[].name" 2>/dev/null)
      if [ -n "$TIER_ROUTERS" ]; then
        echo -e "    ${DIM}$tier:${NC} $(echo "$TIER_ROUTERS" | tr '\n' ', ' | sed 's/,$//')"
      fi
    done
  fi
else
  [ "$JSON_MODE" = false ] && check_fail "Traefik API not reachable"
fi

# ── JSON output ────────────────────────────────────────────

if [ "$JSON_MODE" = true ]; then
  cat <<ENDJSON
{
  "domain": "$DOMAIN",
  "services": $SERVICES_JSON,
  "vault": {"reachable": $VAULT_OK, "certs_issued": ${#CERT_SERIALS[@]}},
  "keycloak": {"reachable": $KC_OK, "users": ${USER_COUNT:-0}},
  "lldap": {"reachable": $LLDAP_OK, "users": ${LLDAP_USERS:-0}, "groups": ${LLDAP_GROUPS:-0}},
  "traefik": {"reachable": $TRAEFIK_OK, "routers": ${ROUTER_COUNT:-0}}
}
ENDJSON
  exit 0
fi

# ── Summary ────────────────────────────────────────────────

echo ""
echo -e "${DIM}Domain: $DOMAIN${NC}"
echo -e "${DIM}Run with --json for machine-readable output.${NC}"
echo ""
