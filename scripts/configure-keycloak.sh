#!/usr/bin/env bash
#
# Configures Keycloak after first boot:
#   - Imports the portcullis realm (if not using auto-import)
#   - Sets the browser flow to X.509
#   - Creates a test user
#
set -euo pipefail

KEYCLOAK_URL="${KEYCLOAK_URL:-https://auth.portcullis.local}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
REALM="portcullis"

echo "==> Authenticating with Keycloak admin..."
# Get admin token
TOKEN=$(curl -sk "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli" \
  -d "username=$KEYCLOAK_ADMIN" \
  -d "password=$KEYCLOAK_ADMIN_PASSWORD" \
  -d "grant_type=password" \
  | jq -r '.access_token')

if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
  echo "ERROR: Failed to authenticate with Keycloak. Is it running?"
  exit 1
fi

echo "==> Importing portcullis realm..."
# Delete-then-import is the only reliable way to apply nested auth-flow
# changes on an existing realm — Keycloak's partial-import and
# POST /authentication/flows both fail to propagate subflows + executions
# defined in a single JSON document. Acceptable because Portcullis state
# that matters (LLDAP users, their WebAuthn registrations) lives in LLDAP,
# not in the Keycloak realm, and the bootstrap scripts always re-register
# clients + test users.
if [ "${PORTCULLIS_WIPE_REALM:-}" = "true" ]; then
  echo "    PORTCULLIS_WIPE_REALM=true — deleting existing realm before import"
  curl -sk -o /dev/null -X DELETE \
    "$KEYCLOAK_URL/admin/realms/$REALM" \
    -H "Authorization: Bearer $TOKEN"
fi

HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
  "$KEYCLOAK_URL/admin/realms" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @keycloak/realm-export.json)

if [ "$HTTP_CODE" = "201" ]; then
  echo "    Realm created successfully."
elif [ "$HTTP_CODE" = "409" ]; then
  echo "    Realm already exists (set PORTCULLIS_WIPE_REALM=true to rebuild it)."
else
  echo "    WARNING: Unexpected response code $HTTP_CODE"
fi

echo "==> Updating realm ACR→LoA map and browserFlow binding..."
REALM_DATA=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM" -H "Authorization: Bearer $TOKEN")
CURRENT_BROWSER_FLOW=$(echo "$REALM_DATA" | jq -r '.browserFlow // ""')
# Realm-level acr.loa.map attribute + browserFlow. Only change browserFlow if
# it's still the legacy value or unset; preserve custom operator overrides.
UPDATE_PAYLOAD=$(jq -n \
  --arg current "$CURRENT_BROWSER_FLOW" \
  --argjson attrs '{"acr.loa.map":"{\"public\":\"0\",\"pwd\":\"1\",\"hwk\":\"2\",\"mtls\":\"3\"}"}' \
  '
  {attributes: $attrs} +
  ( if ($current == "" or $current == "portcullis-browser-flow")
    then {browserFlow: "portcullis-universal"}
    else {} end )
  ')
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -X PUT \
  "$KEYCLOAK_URL/admin/realms/$REALM" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$UPDATE_PAYLOAD")
if [ "$HTTP_CODE" != "204" ]; then
  echo "    WARNING: realm attribute/browserFlow update returned $HTTP_CODE"
else
  echo "    acr.loa.map set; browserFlow=$(echo "$UPDATE_PAYLOAD" | jq -r '.browserFlow // "preserved"')"
fi

echo "==> Ensuring forward-auth client has acr scope + default.acr.values..."
FWD_CLIENT_UUID=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM/clients?clientId=portcullis-forward-auth" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id // ""')
if [ -n "$FWD_CLIENT_UUID" ]; then
  FWD_CLIENT=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM/clients/$FWD_CLIENT_UUID" \
    -H "Authorization: Bearer $TOKEN")
  UPDATED_FWD=$(echo "$FWD_CLIENT" | jq '
    .attributes = ((.attributes // {}) + {"default.acr.values":"pwd"}) |
    .defaultClientScopes = ((.defaultClientScopes // []) + ["acr"] | unique)
  ')
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -X PUT \
    "$KEYCLOAK_URL/admin/realms/$REALM/clients/$FWD_CLIENT_UUID" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$UPDATED_FWD")
  if [ "$HTTP_CODE" != "204" ]; then
    echo "    WARNING: forward-auth client update returned $HTTP_CODE"
  fi
fi

echo "==> Creating test user..."
USER_PAYLOAD=$(cat <<'USERJSON'
{
  "username": "testuser",
  "email": "testuser@portcullis.local",
  "enabled": true,
  "firstName": "Test",
  "lastName": "User",
  "realmRoles": ["user"]
}
USERJSON
)

HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
  "$KEYCLOAK_URL/admin/realms/$REALM/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$USER_PAYLOAD")

if [ "$HTTP_CODE" = "201" ]; then
  echo "    Test user 'testuser' created."
elif [ "$HTTP_CODE" = "409" ]; then
  echo "    Test user already exists."
else
  echo "    WARNING: User creation returned $HTTP_CODE"
fi

# Apply branding
PORTAL_NAME="${PORTAL_DISPLAY_NAME:-Portcullis}"
echo "==> Applying branding: $PORTAL_NAME"
BRAND_HTML=$(echo "$PORTAL_NAME" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read().strip()))" 2>/dev/null || echo "\"$PORTAL_NAME\"")
curl -sk -o /dev/null -w "" -X PUT \
  "$KEYCLOAK_URL/admin/realms/$REALM" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"displayName\":$BRAND_HTML,\"displayNameHtml\":\"<span style=\\\"font-size:2rem;font-weight:700;letter-spacing:-0.02em\\\">$(echo "$PORTAL_NAME" | sed 's/"/\\"/g')</span>\"}"
echo "    Login page header set to: $PORTAL_NAME"

echo ""
echo "==> Keycloak configuration complete."
echo "    Admin console:    $KEYCLOAK_URL/admin/master/console/"
echo "    Portcullis realm:     $KEYCLOAK_URL/realms/$REALM"
echo "    SAML metadata:    $KEYCLOAK_URL/realms/$REALM/protocol/saml/descriptor"
echo "    SAML SSO URL:     $KEYCLOAK_URL/realms/$REALM/protocol/saml"
echo ""
echo "    To add a SAML SP, create a new SAML client in the portcullis realm"
echo "    with your app's ACS URL and entity ID."
