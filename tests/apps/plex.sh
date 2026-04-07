#!/usr/bin/env bash
# Test: Plex (public, no auth)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="plex"
section "Plex"

APP_ID=plex
SUBDOMAIN=plex

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:32400/web/index.html" 60 "$APP_ID"

# Web UI should be accessible without auth
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "http://${IP}:32400/web/index.html" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  pass "/web/index.html → HTTP 200"
else
  fail "/web/index.html → expected HTTP 200, got $HTTP_CODE"
fi

compose_down "$APP_ID"
