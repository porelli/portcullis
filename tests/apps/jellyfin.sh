#!/usr/bin/env bash
# Test: Jellyfin (native OIDC + SSO plugin + group enforcement)
set -euo pipefail
cd "$(dirname "$0")/../.."
source tests/lib.sh
TEST_NAME="jellyfin"
section "Jellyfin"

APP_ID=jellyfin
SUBDOMAIN=media

compose_up "$APP_ID"

IP=$(app_container_ip "$APP_ID")
wait_for_url "http://${IP}:8096" 90 "$APP_ID"

# Wait for setup sidecar to finish
info "Waiting for setup sidecar to complete..."
docker wait "portcullis-jellyfin-setup-1" 2>/dev/null || true

# OIDC discovery reachable from container
assert_container_can_reach "portcullis-${APP_ID}-1" \
  "http://keycloak:8080/realms/portcullis/.well-known/openid-configuration"

# Startup wizard should be completed
BODY=$(curl -sf "http://${IP}:8096/System/Info/Public" 2>/dev/null || echo "{}")
if echo "$BODY" | grep -q '"StartupWizardCompleted"\s*:\s*true'; then
  pass "/System/Info/Public → StartupWizardCompleted=true"
else
  fail "/System/Info/Public → StartupWizardCompleted not true"
fi

# SSO redirect endpoint should point to Keycloak
SSO_LOCATION=$(curl -sf -o /dev/null -w "%{redirect_url}" "http://${IP}:8096/sso/OID/start/keycloak" 2>/dev/null || echo "")
if echo "$SSO_LOCATION" | grep -qi "keycloak\|auth\.${DOMAIN}"; then
  pass "/sso/OID/start/keycloak → redirects to Keycloak"
else
  fail "/sso/OID/start/keycloak → expected Keycloak redirect, got: $SSO_LOCATION"
fi

compose_down "$APP_ID"
