#!/usr/bin/env bash
# Test: Firefly III (header-auth + remote_user_guard)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="firefly-iii"
section "Firefly III"

APP_ID=firefly-iii
SUBDOMAIN=finance

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:8080" 60 "$APP_ID"

assert_redirect_to_keycloak "https://${SUBDOMAIN}.${DOMAIN}/"

# Verify AUTHENTICATION_GUARD is set to remote_user_guard
AUTH_GUARD=$(docker exec "portcullis-${APP_ID}-1" printenv AUTHENTICATION_GUARD 2>/dev/null || echo "")
if [ "$AUTH_GUARD" = "remote_user_guard" ]; then
  pass "AUTHENTICATION_GUARD=remote_user_guard"
else
  fail "AUTHENTICATION_GUARD expected 'remote_user_guard', got '$AUTH_GUARD'"
fi

compose_down "$APP_ID"
