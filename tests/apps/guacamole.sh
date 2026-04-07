#!/usr/bin/env bash
# Test: Apache Guacamole (native OIDC + HTTP header auth)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="guacamole"
section "Guacamole"

APP_ID=guacamole
SUBDOMAIN=remote

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:8080/guacamole/" 90 "$APP_ID"

# Homepage should return the Guacamole login page
BODY=$(curl -sf "http://${IP}:8080/guacamole/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "guacamole"; then
  pass "/ → Guacamole login page returned"
else
  fail "/ → Guacamole login page not found"
fi

compose_down "$APP_ID"
