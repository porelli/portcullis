#!/usr/bin/env bash
# Test: Immich (native OIDC + auto-register)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="immich"
section "Immich"

APP_ID=immich
SUBDOMAIN=photos
SERVICE=immich-server

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:2283" 90 "$APP_ID"

# OIDC discovery reachable from container
assert_container_can_reach "portcullis-${SERVICE}-1" \
  "http://keycloak:8080/realms/portcullis/.well-known/openid-configuration"

# Server config should advertise SSO button
BODY=$(curl -sf "http://${IP}:2283/api/server/config" 2>/dev/null || echo "{}")
if echo "$BODY" | grep -qi "SSO"; then
  pass "/api/server/config → oauthButtonText contains 'SSO'"
else
  fail "/api/server/config → 'SSO' not found in response"
fi

compose_down "$APP_ID"
