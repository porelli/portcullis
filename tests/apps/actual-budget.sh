#!/usr/bin/env bash
# Test: Actual Budget (native OIDC)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="actual-budget"
section "Actual Budget"

APP_ID=actual-budget
SUBDOMAIN=budget

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:5006" 60 "$APP_ID"

# Container should be able to reach Keycloak (uses NODE_EXTRA_CA_CERTS)
assert_container_can_reach "portcullis-${APP_ID}-1" \
  "http://keycloak:8080/realms/portcullis/.well-known/openid-configuration"

compose_down "$APP_ID"
