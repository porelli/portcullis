#!/usr/bin/env bash
#
# Register all Portcullis OIDC clients in Keycloak.
# Called by both bootstrap.sh and upgrade.sh.
#
# Requires: KEYCLOAK_URL, KEYCLOAK_ADMIN, KEYCLOAK_ADMIN_PASSWORD,
#           PORTCULLIS_DOMAIN, and client secret env vars.
#
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "  $*"; }

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
DOMAIN="${PORTCULLIS_DOMAIN:-portcullis.local}"

# Get admin token
KC_TOKEN=$(curl -sk "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli" \
  -d "username=${KEYCLOAK_ADMIN:-admin}" \
  -d "password=${KEYCLOAK_ADMIN_PASSWORD:-admin}" \
  -d "grant_type=password" \
  | jq -r '.access_token')

if [ "$KC_TOKEN" = "null" ] || [ -z "$KC_TOKEN" ]; then
  echo -e "${RED}ERROR:${NC} Failed to authenticate with Keycloak at $KEYCLOAK_URL"
  exit 1
fi

register_client() {
  local client_id="$1"
  local client_secret="$2"
  local redirect_uri="$3"
  local description="${4:-$client_id}"

  local HTTP_CODE
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    "$KEYCLOAK_URL/admin/realms/portcullis/clients" \
    -H "Authorization: Bearer $KC_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"clientId\": \"$client_id\",
      \"name\": \"$description\",
      \"enabled\": true,
      \"protocol\": \"openid-connect\",
      \"publicClient\": false,
      \"secret\": \"$client_secret\",
      \"redirectUris\": [\"$redirect_uri\"],
      \"standardFlowEnabled\": true,
      \"directAccessGrantsEnabled\": false,
      \"attributes\": {
        \"post.logout.redirect.uris\": \"$redirect_uri\"
      }
    }")

  case "$HTTP_CODE" in
    201) echo -e "  ${GREEN}Created${NC} $client_id" ;;
    409) echo -e "  ${YELLOW}Exists${NC}  $client_id" ;;
    *)   echo -e "  ${RED}Failed${NC}  $client_id (HTTP $HTTP_CODE)" ;;
  esac
}

# Core clients
register_client \
  "portcullis-forward-auth" \
  "${FORWARD_AUTH_CLIENT_SECRET:-portcullis-forward-auth-secret}" \
  "https://auth.${DOMAIN}/_oauth" \
  "Portcullis Forward Auth"

# The realm export (auto-imported on first Keycloak start) ships the public
# default secret, so "Exists" above usually means Keycloak still holds that
# default. Push the .env value so oauth2-proxy and Keycloak always agree and
# a non-default secret actually takes effect. Idempotent.
sync_client_secret() {
  local client_id="$1" secret="$2" uuid client updated code
  uuid=$(curl -sk "$KEYCLOAK_URL/admin/realms/portcullis/clients?clientId=$client_id" \
    -H "Authorization: Bearer $KC_TOKEN" | jq -r '.[0].id // empty')
  if [ -z "$uuid" ]; then
    echo -e "  ${RED}Failed${NC}  $client_id secret sync (client not found)"
    return 0
  fi
  client=$(curl -sk "$KEYCLOAK_URL/admin/realms/portcullis/clients/$uuid" \
    -H "Authorization: Bearer $KC_TOKEN")
  updated=$(echo "$client" | jq --arg s "$secret" '.secret = $s')
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X PUT \
    "$KEYCLOAK_URL/admin/realms/portcullis/clients/$uuid" \
    -H "Authorization: Bearer $KC_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$updated")
  if [ "$code" = "204" ]; then
    echo -e "  ${GREEN}Synced${NC}  $client_id client secret from .env"
  else
    echo -e "  ${RED}Failed${NC}  $client_id secret sync (HTTP $code)"
  fi
}

FWD_SECRET="${FORWARD_AUTH_CLIENT_SECRET:-portcullis-forward-auth-secret}"
sync_client_secret "portcullis-forward-auth" "$FWD_SECRET"
if [ "$FWD_SECRET" = "portcullis-forward-auth-secret" ]; then
  echo -e "  ${YELLOW}WARNING${NC} FORWARD_AUTH_CLIENT_SECRET is the public default — set a random value in .env, re-run this script, then: docker compose up -d forward-auth"
fi

# VPN clients (optional — only register if secrets are set)
if [ -n "${HEADSCALE_OIDC_CLIENT_SECRET:-}" ]; then
  register_client \
    "headscale" \
    "$HEADSCALE_OIDC_CLIENT_SECRET" \
    "https://vpn.${DOMAIN}/oidc/callback" \
    "Headscale VPN"
fi

if [ -n "${HEADPLANE_OIDC_CLIENT_SECRET:-}" ]; then
  register_client \
    "headplane" \
    "$HEADPLANE_OIDC_CLIENT_SECRET" \
    "https://vpn-admin.${DOMAIN}/*" \
    "Headplane Admin UI"
fi

if [ -n "${NETBIRD_OIDC_CLIENT_SECRET:-}" ]; then
  register_client \
    "netbird-dashboard" \
    "$NETBIRD_OIDC_CLIENT_SECRET" \
    "https://netbird.${DOMAIN}/*" \
    "NetBird Dashboard"
fi
