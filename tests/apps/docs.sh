#!/usr/bin/env bash
# Test: Docs (public, no auth)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="docs"
section "Docs"

APP_ID=docs
SUBDOMAIN=docs

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:8000" 60 "$APP_ID"

# Should be publicly accessible
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "http://${IP}:8000/" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  pass "/ → HTTP 200"
else
  fail "/ → expected HTTP 200, got $HTTP_CODE"
fi

compose_down "$APP_ID"
