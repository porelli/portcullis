#!/usr/bin/env bash
# Test: NetBird (native OIDC dashboard)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="netbird"
section "NetBird"

APP_ID=netbird
SUBDOMAIN=netbird
SERVICE=netbird-dashboard

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID" "$SERVICE")
wait_for_url "http://${IP}:80" 60 "$APP_ID"

# Dashboard should return HTML
BODY=$(curl -sf "http://${IP}:80/" 2>/dev/null || echo "")
if echo "$BODY" | grep -qi "<html"; then
  pass "/ → dashboard returns HTML"
else
  fail "/ → dashboard did not return HTML"
fi

compose_down "$APP_ID"
