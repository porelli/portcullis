#!/usr/bin/env bash
# Test: Headscale (native OIDC)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="headscale"
section "Headscale"

APP_ID=headscale
SUBDOMAIN=vpn

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:8080/health" 60 "$APP_ID"

# Health endpoint should return OK
BODY=$(curl -sf "http://${IP}:8080/health" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "ok"; then
  pass "/health → OK"
else
  fail "/health → expected OK, got: $BODY"
fi

compose_down "$APP_ID"
