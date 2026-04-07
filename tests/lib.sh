#!/usr/bin/env bash
# Shared test library for Portcullis app auth tests.
# Source this from each test script: source "$(dirname "$0")/../lib.sh"
set -euo pipefail

# ── Config ─────────────────────────────────────────────────
DOMAIN="${PORTCULLIS_DOMAIN:-portcullis.local}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
LLDAP_URL="${LLDAP_URL:-http://localhost:17170}"
LLDAP_PASS="${LLDAP_ADMIN_PASSWORD:-ci-lldap-pass}"
KC_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KC_PASS="${KEYCLOAK_ADMIN_PASSWORD:-ci-admin-pass}"
PROJECT_DIR="${PROJECT_DIR:-.}"
RESOLVE_OPTS="--resolve *.${DOMAIN}:443:127.0.0.1 --cacert certs/ca-chain.crt"

PASS_COUNT=0
FAIL_COUNT=0
TEST_NAME="${TEST_NAME:-unknown}"

# ── Output ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { ((PASS_COUNT++)); echo -e "  ${GREEN}PASS${NC} $*"; }
fail() { ((FAIL_COUNT++)); echo -e "  ${RED}FAIL${NC} $*"; }
info() { echo -e "  ${YELLOW}INFO${NC} $*"; }
section() { echo -e "\n=== $* ==="; }

report() {
  echo ""
  if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${RED}$TEST_NAME: $FAIL_COUNT FAILED, $PASS_COUNT passed${NC}"
    exit 1
  else
    echo -e "${GREEN}$TEST_NAME: All $PASS_COUNT tests passed${NC}"
  fi
}
trap report EXIT

# ── Wait helpers ───────────────────────────────────────────
wait_for_url() {
  local url="$1" timeout="${2:-60}" label="${3:-$1}"
  info "Waiting for $label..."
  for i in $(seq 1 "$timeout"); do
    if curl -sf -o /dev/null "$url" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  fail "Timeout waiting for $label ($url)"
  return 1
}

wait_for_container() {
  local name="$1" timeout="${2:-60}"
  info "Waiting for container $name..."
  for i in $(seq 1 "$timeout"); do
    if docker inspect "$name" --format '{{.State.Running}}' 2>/dev/null | grep -q true; then
      return 0
    fi
    sleep 1
  done
  fail "Container $name not running after ${timeout}s"
  return 1
}

# ── Keycloak helpers ───────────────────────────────────────
keycloak_admin_token() {
  curl -sf "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -d "client_id=admin-cli" \
    -d "username=$KC_ADMIN" \
    -d "password=$KC_PASS" \
    -d "grant_type=password" | jq -r '.access_token'
}

keycloak_user_token() {
  local user="$1" password="$2" client_id="${3:-portcullis-forward-auth}" client_secret="${4:-${FORWARD_AUTH_CLIENT_SECRET:-ci-forward-auth-secret}}"
  curl -sf "$KEYCLOAK_URL/realms/portcullis/protocol/openid-connect/token" \
    -d "client_id=$client_id" \
    -d "client_secret=$client_secret" \
    -d "username=$user" \
    -d "password=$password" \
    -d "grant_type=password" \
    -d "scope=openid email profile groups" | jq -r '.access_token'
}

keycloak_enable_direct_grant() {
  local client_id="$1"
  local token
  token=$(keycloak_admin_token)
  local uuid
  uuid=$(curl -sf "$KEYCLOAK_URL/admin/realms/portcullis/clients?clientId=$client_id" \
    -H "Authorization: Bearer $token" | jq -r '.[0].id')
  curl -sf -o /dev/null -X PUT "$KEYCLOAK_URL/admin/realms/portcullis/clients/$uuid" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "{\"clientId\":\"$client_id\",\"directAccessGrantsEnabled\":true}"
}

keycloak_register_client() {
  local client_id="$1" secret="$2" redirect_uri="$3"
  local token
  token=$(keycloak_admin_token)
  curl -sf -o /dev/null -w "%{http_code}" \
    "$KEYCLOAK_URL/admin/realms/portcullis/clients" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "{
      \"clientId\":\"$client_id\",
      \"enabled\":true,
      \"protocol\":\"openid-connect\",
      \"publicClient\":false,
      \"secret\":\"$secret\",
      \"redirectUris\":[\"$redirect_uri\"],
      \"standardFlowEnabled\":true,
      \"directAccessGrantsEnabled\":true
    }"
}

# ── LLDAP helpers ──────────────────────────────────────────
lldap_token() {
  curl -sf "$LLDAP_URL/auth/simple/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"$LLDAP_PASS\"}" | jq -r '.token'
}

lldap_graphql() {
  local query="$1"
  local token
  token=$(lldap_token)
  curl -sf "$LLDAP_URL/api/graphql" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"$query\"}"
}

lldap_create_user() {
  local username="$1" email="$2" password="${3:-}"
  lldap_graphql "mutation { createUser(user: {id: \\\"$username\\\", email: \\\"$email\\\"}) { id } }" > /dev/null 2>&1 || true
  if [ -n "$password" ]; then
    # Set password via LLDAP admin API (GraphQL doesn't support this directly)
    local token
    token=$(lldap_token)
    curl -sf -o /dev/null "$LLDAP_URL/api/graphql" \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/json" \
      -d "{\"query\":\"mutation { updateUser(user: {id: \\\"$username\\\"}) { ok } }\"}" 2>/dev/null || true
  fi
}

lldap_create_group() {
  local name="$1"
  local result
  result=$(lldap_graphql "mutation { createGroup(name: \\\"$name\\\") { id } }" 2>/dev/null || true)
  echo "$result" | jq -r '.data.createGroup.id // empty' 2>/dev/null
}

lldap_add_to_group() {
  local user="$1" group_id="$2"
  lldap_graphql "mutation { addUserToGroup(userId: \\\"$user\\\", groupId: $group_id) { ok } }" > /dev/null 2>&1 || true
}

lldap_sync_keycloak() {
  local token
  token=$(keycloak_admin_token)
  # Find LDAP provider ID
  local ldap_id
  ldap_id=$(curl -sf "$KEYCLOAK_URL/admin/realms/portcullis/components" \
    -H "Authorization: Bearer $token" | jq -r '.[] | select(.providerId=="ldap") | .id')
  if [ -n "$ldap_id" ]; then
    # Sync groups
    local mapper_id
    mapper_id=$(curl -sf "$KEYCLOAK_URL/admin/realms/portcullis/components?parent=$ldap_id" \
      -H "Authorization: Bearer $token" | jq -r '.[] | select(.providerId=="group-ldap-mapper") | .id')
    if [ -n "$mapper_id" ]; then
      curl -sf -o /dev/null -X POST \
        "$KEYCLOAK_URL/admin/realms/portcullis/user-storage/$ldap_id/mappers/$mapper_id/sync?direction=fedToKeycloak" \
        -H "Authorization: Bearer $token"
    fi
    # Full user sync
    curl -sf -o /dev/null -X POST \
      "$KEYCLOAK_URL/admin/realms/portcullis/user-storage/$ldap_id/sync?action=triggerFullSync" \
      -H "Authorization: Bearer $token"
  fi
}

# ── Assertions ─────────────────────────────────────────────
assert_http_code() {
  local url="$1" expected="$2"
  shift 2
  local actual
  actual=$(curl -sf -o /dev/null -w "%{http_code}" $RESOLVE_OPTS "$@" "$url" 2>/dev/null || echo "000")
  if [ "$actual" = "$expected" ]; then
    pass "$url → HTTP $actual"
  else
    fail "$url → expected HTTP $expected, got $actual"
  fi
}

assert_redirect_to_keycloak() {
  local url="$1"
  shift
  local location
  location=$(curl -sf -o /dev/null -w "%{redirect_url}" -L --max-redirs 0 $RESOLVE_OPTS "$@" "$url" 2>/dev/null || true)
  if echo "$location" | grep -q "auth\.$DOMAIN"; then
    pass "$url → redirects to Keycloak"
  else
    # oauth2-proxy may redirect to /oauth2/sign_in first
    local location2
    location2=$(curl -sf -o /dev/null -w "%{redirect_url}" -L --max-redirs 2 $RESOLVE_OPTS "$@" "$url" 2>/dev/null || true)
    if echo "$location2" | grep -q "auth\.$DOMAIN"; then
      pass "$url → redirects to Keycloak (via oauth2-proxy)"
    else
      fail "$url → expected redirect to Keycloak, got: $location"
    fi
  fi
}

assert_redirect_contains() {
  local url="$1" expected="$2"
  shift 2
  local location
  location=$(curl -sf -o /dev/null -w "%{redirect_url}" --max-redirs 5 -L $RESOLVE_OPTS "$@" "$url" 2>/dev/null || true)
  if echo "$location" | grep -q "$expected"; then
    pass "$url → redirect contains '$expected'"
  else
    fail "$url → redirect does not contain '$expected', got: $location"
  fi
}

assert_body_contains() {
  local url="$1" expected="$2"
  shift 2
  local body
  body=$(curl -sf $RESOLVE_OPTS "$@" "$url" 2>/dev/null || echo "")
  if echo "$body" | grep -q "$expected"; then
    pass "$url → body contains '$expected'"
  else
    fail "$url → body does not contain '$expected'"
  fi
}

assert_container_can_reach() {
  local container="$1" url="$2"
  if docker exec "$container" curl -sf "$url" > /dev/null 2>&1; then
    pass "$container can reach $url"
  else
    # Try wget (some containers don't have curl)
    if docker exec "$container" wget -qO- "$url" > /dev/null 2>&1; then
      pass "$container can reach $url"
    else
      fail "$container cannot reach $url"
    fi
  fi
}

# ── Compose helpers ────────────────────────────────────────
compose_up() {
  local app_id="$1"
  local compose_path="templates/$app_id/compose.yml"
  if [ ! -f "$compose_path" ]; then
    fail "compose.yml not found for $app_id"
    return 1
  fi
  info "Starting $app_id..."
  COMPOSE_IGNORE_ORPHANS=true docker compose \
    -p portcullis \
    -f "$compose_path" \
    --project-directory "$PROJECT_DIR" \
    --env-file "$PROJECT_DIR/.env" \
    up -d --no-deps 2>&1 | tail -5
}

compose_down() {
  local app_id="$1"
  local compose_path="templates/$app_id/compose.yml"
  [ -f "$compose_path" ] || return 0
  COMPOSE_IGNORE_ORPHANS=true docker compose \
    -p portcullis \
    -f "$compose_path" \
    --project-directory "$PROJECT_DIR" \
    --env-file "$PROJECT_DIR/.env" \
    down 2>&1 | tail -3
}

app_container_ip() {
  local app_id="$1" service="${2:-$1}"
  docker inspect "portcullis-${service}-1" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo ""
}

app_logs() {
  local app_id="$1" lines="${2:-20}"
  local compose_path="templates/$app_id/compose.yml"
  COMPOSE_IGNORE_ORPHANS=true docker compose \
    -p portcullis \
    -f "$compose_path" \
    --project-directory "$PROJECT_DIR" \
    --env-file "$PROJECT_DIR/.env" \
    logs --tail "$lines" --no-color 2>&1
}
