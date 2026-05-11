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

# Realm-export references LLDAP_*_PLACEHOLDER — substitute before posting so
# the LDAP federation binds on first import. DOMAIN isn't templated in the
# export (the forward-auth redirectUri uses a placeholder host that's PUT
# onto the real domain after import — see below).
LLDAP_BASE_DN="${LLDAP_BASE_DN:-dc=portcullis,dc=local}"
LLDAP_PASS="${LLDAP_ADMIN_PASSWORD:-}"
REALM_EXPANDED=$(sed \
  -e "s|LLDAP_BASE_DN_PLACEHOLDER|$LLDAP_BASE_DN|g" \
  -e "s|LLDAP_PASSWORD_PLACEHOLDER|$LLDAP_PASS|g" \
  keycloak/realm-export.json)
HTTP_CODE=$(echo "$REALM_EXPANDED" | curl -sk -o /dev/null -w "%{http_code}" \
  "$KEYCLOAK_URL/admin/realms" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @-)

if [ "$HTTP_CODE" = "201" ]; then
  echo "    Realm created successfully."
elif [ "$HTTP_CODE" = "409" ]; then
  echo "    Realm already exists (set PORTCULLIS_WIPE_REALM=true to rebuild it)."
else
  echo "    WARNING: Unexpected response code $HTTP_CODE"
fi

echo "==> Substituting LLDAP placeholders in federation config..."
# Keycloak auto-imports realm-export.json verbatim, so LLDAP_BASE_DN_PLACEHOLDER
# and LLDAP_PASSWORD_PLACEHOLDER land as literal strings in the LDAP federation
# component. Patch them via the admin API after import so the realm actually
# binds to LLDAP.
LLDAP_BASE_DN="${LLDAP_BASE_DN:-dc=portcullis,dc=local}"
LLDAP_PASS="${LLDAP_ADMIN_PASSWORD:-}"
LDAP_COMP=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM/components" -H "Authorization: Bearer $TOKEN" | jq '.[] | select(.providerId == "ldap")')
if [ -n "$LDAP_COMP" ] && [ "$LDAP_COMP" != "null" ]; then
  LDAP_ID=$(echo "$LDAP_COMP" | jq -r .id)
  PATCHED=$(echo "$LDAP_COMP" | jq \
    --arg b "$LLDAP_BASE_DN" --arg p "$LLDAP_PASS" '
    .config.usersDn = ["ou=people," + $b] |
    .config.bindDn = ["uid=admin,ou=people," + $b] |
    .config.bindCredential = [$p]
  ')
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -X PUT \
    "$KEYCLOAK_URL/admin/realms/$REALM/components/$LDAP_ID" \
    -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
    -d "$PATCHED")
  [ "$HTTP_CODE" = "204" ] && echo "    LDAP base DN + bind credential set" || echo "    WARNING: LDAP patch returned $HTTP_CODE"

  # Also patch the nested group-ldap-mapper's groups.dn
  MAPPER=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM/components?parent=$LDAP_ID" -H "Authorization: Bearer $TOKEN" | jq '.[] | select(.providerId == "group-ldap-mapper")')
  if [ -n "$MAPPER" ] && [ "$MAPPER" != "null" ]; then
    MID=$(echo "$MAPPER" | jq -r .id)
    MFIX=$(echo "$MAPPER" | jq --arg b "$LLDAP_BASE_DN" '.config["groups.dn"] = ["ou=groups," + $b]')
    curl -sk -o /dev/null -w "    group-ldap-mapper.groups.dn: HTTP %{http_code}\n" -X PUT \
      "$KEYCLOAK_URL/admin/realms/$REALM/components/$MID" \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d "$MFIX"
  fi
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

echo "==> Attaching AMR reference values to factor executors..."
# Keycloak's AMR mapper emits `amr` values read from each execution's
# `default.reference.value`. Without this config, `amr` is always an empty
# list. Walk the LoA-factor subflows and give each executor a reference
# (pwd / hwk / mtls) with a long max_age so the value survives the session.
attach_amr_ref() {
  # $1 = parent flow alias, $2 = authenticator provider id, $3 = reference value
  local parent="$1" provider="$2" ref="$3"
  local exec_id
  exec_id=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM/authentication/flows/$parent/executions" \
    -H "Authorization: Bearer $TOKEN" | jq -r --arg p "$provider" \
    '.[] | select(.providerId == $p) | .id' | head -1)
  if [ -z "$exec_id" ]; then return; fi
  # Only create if not already configured
  local existing
  existing=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM/authentication/executions/$exec_id" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.authenticationConfig // ""')
  if [ -n "$existing" ]; then return; fi
  local payload
  payload=$(jq -n --arg a "amr-$parent-$provider" --arg r "$ref" '{
    alias: $a,
    config: {
      "default.reference.value": $r,
      "default.reference.maxAge": "36000"
    }
  }')
  curl -sk -o /dev/null -w "    amr-ref $provider in $parent: %{http_code}\n" -X POST \
    "$KEYCLOAK_URL/admin/realms/$REALM/authentication/executions/$exec_id/config" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$payload"
}

attach_amr_ref portcullis-loa-1-factors auth-username-password-form pwd
attach_amr_ref portcullis-loa-1-factors webauthn-authenticator-passwordless hwk
attach_amr_ref portcullis-loa-1-factors auth-x509-client-username-form mtls
attach_amr_ref portcullis-loa-2-factors webauthn-authenticator-passwordless hwk
attach_amr_ref portcullis-loa-2-factors auth-x509-client-username-form mtls
attach_amr_ref portcullis-loa-3 auth-x509-client-username-form mtls

echo "==> Attaching AMR mapper to acr client scope..."
ACR_SCOPE_ID=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[] | select(.name == "acr") | .id // empty')
if [ -n "$ACR_SCOPE_ID" ]; then
  HAS_AMR=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes/$ACR_SCOPE_ID/protocol-mappers/models" \
    -H "Authorization: Bearer $TOKEN" | jq -r '[.[] | select(.protocolMapper == "oidc-amr-mapper")] | length')
  if [ "$HAS_AMR" = "0" ]; then
    curl -sk -o /dev/null -w "    amr-mapper create: %{http_code}\n" -X POST \
      "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes/$ACR_SCOPE_ID/protocol-mappers/models" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "name": "amr",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-amr-mapper",
        "config": {
          "id.token.claim": "true",
          "access.token.claim": "true",
          "introspection.token.claim": "true",
          "userinfo.token.claim": "true",
          "claim.name": "amr"
        }
      }'
  else
    echo "    AMR mapper already present on acr scope"
  fi
fi

echo "==> Ensuring 'groups' client scope exists..."
HAS_GROUPS=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes" \
  -H "Authorization: Bearer $TOKEN" | jq -r '[.[] | select(.name == "groups")] | length')
if [ "$HAS_GROUPS" = "0" ]; then
  curl -sk -o /dev/null -w "    groups scope create: %{http_code}\n" -X POST \
    "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "groups",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true",
        "display.on.consent.screen": "true"
      },
      "protocolMappers": [
        {
          "name": "groups",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-group-membership-mapper",
          "config": {
            "id.token.claim": "true",
            "access.token.claim": "true",
            "introspection.token.claim": "true",
            "userinfo.token.claim": "true",
            "claim.name": "groups",
            "full.path": "false"
          }
        }
      ]
    }'
else
  echo "    groups scope already present"
fi

echo "==> Ensuring forward-auth client has acr scope + default.acr.values + concrete redirectUri..."
# Substitute {{DOMAIN}} in redirectUris, attach acr scope, set default.acr.values.
# Also attach the groups scope if present (created below during first import).
DOMAIN_VAL="${PORTCULLIS_DOMAIN:-portcullis.local}"
FWD_CLIENT_UUID=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM/clients?clientId=portcullis-forward-auth" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id // ""')
if [ -n "$FWD_CLIENT_UUID" ]; then
  FWD_CLIENT=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM/clients/$FWD_CLIENT_UUID" \
    -H "Authorization: Bearer $TOKEN")
  # Force redirectUris onto the real domain. The realm export ships a
  # placeholder (auth.portcullis.local) so Keycloak's strict URL parser
  # accepts it at import; we overwrite with the configured domain here.
  UPDATED_FWD=$(echo "$FWD_CLIENT" | jq --arg d "$DOMAIN_VAL" '
    .attributes = ((.attributes // {}) + {"default.acr.values":"pwd"}) |
    .defaultClientScopes = ((.defaultClientScopes // []) + ["acr"] | unique) |
    .redirectUris = ["https://auth." + $d + "/oauth2/callback"]
  ')
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -X PUT \
    "$KEYCLOAK_URL/admin/realms/$REALM/clients/$FWD_CLIENT_UUID" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$UPDATED_FWD")
  if [ "$HTTP_CODE" != "204" ]; then
    echo "    WARNING: forward-auth client update returned $HTTP_CODE"
  fi

  # Attach the groups client scope to the forward-auth client so oauth2-proxy
  # can request scope=groups successfully. Idempotent — 204 whether new or
  # already attached.
  GROUPS_SCOPE_ID=$(curl -sk "$KEYCLOAK_URL/admin/realms/$REALM/client-scopes" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.[] | select(.name == "groups") | .id // empty')
  if [ -n "$GROUPS_SCOPE_ID" ]; then
    curl -sk -o /dev/null -w "    attach groups scope: %{http_code}\n" -X PUT \
      "$KEYCLOAK_URL/admin/realms/$REALM/clients/$FWD_CLIENT_UUID/default-client-scopes/$GROUPS_SCOPE_ID" \
      -H "Authorization: Bearer $TOKEN"
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
