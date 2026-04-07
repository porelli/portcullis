#!/usr/bin/env bash
# Test: Wiki.js (forward-auth + group-gate)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="wiki"
section "Wiki.js"

APP_ID=wiki
SUBDOMAIN=wiki

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID" "wiki")
wait_for_url "http://${IP}:3000" 60 "$APP_ID"

assert_redirect_to_keycloak "https://${SUBDOMAIN}.${DOMAIN}/"

compose_down "$APP_ID"
