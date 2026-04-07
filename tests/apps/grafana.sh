#!/usr/bin/env bash
# Test: Grafana (header-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="grafana"
section "Grafana"

APP_ID=grafana
SUBDOMAIN=grafana

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:3000" 60 "$APP_ID"

assert_redirect_to_keycloak "https://${SUBDOMAIN}.${DOMAIN}/"

# Verify proxy auth is enabled in the container environment
GF_PROXY=$(docker exec "portcullis-${APP_ID}-1" printenv GF_AUTH_PROXY_ENABLED 2>/dev/null || echo "")
if [ "$GF_PROXY" = "true" ]; then
  pass "GF_AUTH_PROXY_ENABLED=true"
else
  fail "GF_AUTH_PROXY_ENABLED expected 'true', got '$GF_PROXY'"
fi

compose_down "$APP_ID"
