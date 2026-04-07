#!/usr/bin/env bash
# Test: Vaultwarden (native OIDC SSO)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="vaultwarden"
section "Vaultwarden"

APP_ID=vaultwarden
SUBDOMAIN=passwords

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:80" 60 "$APP_ID"

# OIDC discovery reachable from container
assert_container_can_reach "portcullis-${APP_ID}-1" \
  "http://keycloak:8080/realms/portcullis/.well-known/openid-configuration"

# Homepage should mention single sign-on
BODY=$(curl -sf "http://${IP}:80/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "single sign-on"; then
  pass "/ → body contains 'single sign-on'"
else
  fail "/ → 'single sign-on' not found in body"
fi

compose_down "$APP_ID"
