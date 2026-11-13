#!/usr/bin/env bash
# ci.yml job e2e, step "Users, groups, setup links, policy, test app, certs".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
set -o pipefail
gql() {
  jq -n --arg q "$1" '{query: $q}' | curl -sf http://127.0.0.1:17170/api/graphql \
    -H @<(printf 'Authorization: Bearer %s\n' "$LLDAP_TOKEN") -H 'Content-Type: application/json' -d @- \
    | tee /dev/stderr | jq -e '.errors == null' >/dev/null
}
LLDAP_TOKEN=$(jq -n '{username: "admin", password: env.LLDAP_ADMIN_PASSWORD}' \
  | curl -sf http://127.0.0.1:17170/auth/simple/login -H 'Content-Type: application/json' -d @- | jq -r .token)
[ -z "$LLDAP_TOKEN" ] || [ "$LLDAP_TOKEN" = null ] || echo "::add-mask::$LLDAP_TOKEN"
gql 'mutation { createUser(user: {id: "e2e", email: "e2e@portcullis.local"}) { id } }'
gql 'mutation { createUser(user: {id: "e2e-other", email: "e2e-other@portcullis.local"}) { id } }'
gql 'mutation { createUser(user: {id: "e2e-bypass", email: "e2e-bypass@portcullis.local"}) { id } }'
for g in users_e2e admin_e2e; do
  gql "mutation { createGroup(name: \"$g\") { id } }"
done
GID=$(jq -n '{query: "{ groups { id displayName } }"}' | curl -sf http://127.0.0.1:17170/api/graphql \
  -H @<(printf 'Authorization: Bearer %s\n' "$LLDAP_TOKEN") -H 'Content-Type: application/json' -d @- \
  | jq -r '.data.groups[] | select(.displayName == "users_e2e") | .id')
gql "mutation { addUserToGroup(userId: \"e2e\", groupId: $GID) { ok } }"
# No passwords at all: every user (incl. the bootstrap admin) gets
# a one-time setup link, like `portcullis init` prints for admin.
# Nothing is pre-assigned in Keycloak: redeeming the link adds the
# passkey registration itself.
for spec in "E2E_INVITE e2e https://hwk.portcullis.local/" "E2E_OTHER_INVITE e2e-other https://app.portcullis.local/" \
            "E2E_ADMIN_INVITE admin portal" "E2E_BYPASS_INVITE e2e-bypass https://app.portcullis.local/"; do
  read -r var who to <<<"$spec"
  url="$(./portcullis invite "$who" --to "$to" --json | jq -r .url)"
  # Masked before anything can print it: a malformed link may still carry a token.
  [ -z "$url" ] || [ "$url" = null ] || echo "::add-mask::$url"
  [[ "$url" =~ ^https://enroll\.portcullis\.local/invite/[A-Za-z0-9_-]{43}$ ]] || { echo "FAIL: setup link for $who: $url"; exit 1; }
  echo "$var=$url" >> "$GITHUB_ENV"
done

# Keycloak imports the users from LDAP when the links are redeemed.
KC_TOKEN=$(printf '%s' "$KEYCLOAK_ADMIN_PASSWORD" | curl -sf http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  --data-urlencode client_id=admin-cli --data-urlencode "username=$KEYCLOAK_ADMIN" \
  --data-urlencode grant_type=password --data-urlencode password@- | jq -r .access_token)
[ -z "$KC_TOKEN" ] || [ "$KC_TOKEN" = null ] || echo "::add-mask::$KC_TOKEN"
kc() { curl -sf -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") -H 'Content-Type: application/json' "$@"; }
KC_UID=$(kc "http://127.0.0.1:8080/admin/realms/portcullis/users?username=e2e&exact=true" | jq -r '.[0].id')
[ -n "$KC_UID" ] && [ "$KC_UID" != null ] || { echo "FAIL: e2e not visible in Keycloak (LDAP federation)"; exit 1; }
kc "http://127.0.0.1:8080/admin/realms/portcullis/users/$KC_UID" | jq -e '(.requiredActions // []) == []' >/dev/null \
  || { echo "FAIL: e2e has required actions before redeeming its link"; exit 1; }
# Another client (like a Hub-created app client): no marker scope, so
# the invite IdP's post-broker flow must refuse it (e2e_login.py).
jq -n '{clientId: "e2e-invite-bypass", enabled: true, protocol: "openid-connect", publicClient: true,
        standardFlowEnabled: true, directAccessGrantsEnabled: false,
        redirectUris: ["https://app.portcullis.local/bypass-cb"]}' \
  | kc -X POST --data-binary @- http://127.0.0.1:8080/admin/realms/portcullis/clients >/dev/null
echo "E2E_BYPASS_CLIENT=e2e-invite-bypass" >> "$GITHUB_ENV"
SCOPE_ID=$(kc http://127.0.0.1:8080/admin/realms/portcullis/client-scopes | jq -r '.[] | select(.name == "portcullis-invite-client") | .id')
[ -n "$SCOPE_ID" ] || { echo "FAIL: keycloak configure did not create the portcullis-invite-client scope"; exit 1; }
for c in portcullis-forward-auth e2e-invite-bypass; do
  CID=$(kc "http://127.0.0.1:8080/admin/realms/portcullis/clients?clientId=$c" | jq -r '.[0].id')
  HAS=$(kc "http://127.0.0.1:8080/admin/realms/portcullis/clients/$CID/default-client-scopes" | jq --arg s "$SCOPE_ID" 'any(.[]; .id == $s)')
  WANT=false; [ "$c" = portcullis-forward-auth ] && WANT=true
  [ "$HAS" = "$WANT" ] || { echo "FAIL: $c has the portcullis-invite-client scope: $HAS (want $WANT)"; exit 1; }
done

# group-gate policy file v7 (normally written by the Hub), with the
# Hub's fresh-install methods and Standard default (any passkey or
# a YubiKey certificate). "app" has no template of its own
# (passkey and cert-only sessions must both pass); every core
# page on Standard.
printf '%s' '{"version": 7,
  "methods": ["passkey_device", "passkey_synced", "security_key", "yubikey_cert"],
  "templates": {"standard": {"op": "any", "items": [{"op": "any", "items": ["passkey_synced", "passkey_device", "security_key"]}, {"op": "any", "items": ["yubikey_cert"]}]},
                "e2e-hwk": {"op": "any", "items": ["security_key"]}, "e2e-mtls": {"op": "any", "items": ["yubikey_cert"]}},
  "default": "standard",
  "hosts": {"hwk.portcullis.local": "e2e-hwk", "mtls.portcullis.local": "e2e-mtls"},
  "core": {"portcullis.local": "standard", "directory.portcullis.local": "standard",
           "hub.portcullis.local": "standard", "metrics.portcullis.local": "standard", "people.portcullis.local": "standard",
           "traefik.portcullis.local": "standard"},
  "people": {}, "add_stronger": false, "extra_domains": [],
  "groups": {"app.portcullis.local": "users_e2e", "hwk.portcullis.local": "users_e2e", "mtls.portcullis.local": "users_e2e"},
  "path_groups": {"app.portcullis.local": [{"prefix": "/admin", "group": "admin_e2e"}]},
  "vpn": {"hosts": {}, "server_mode": false, "admin_only": false, "public_enrol": true, "devices_file": "vpn.json"}}' \
  | docker run --rm -i -v portcullis_hub_data:/d "$ALPINE" sh -c 'cat > /d/group-gate-policy.json && chmod 644 /d/group-gate-policy.json'
# The extension's signin-keycloak.json (normally written by the Hub;
# without it nobody signs in, contract §8.1): the same methods and
# templates, no native-OIDC clients, the CI trust list (Chromium's
# virtual authenticator = a security key) and no FIDO list yet.
docker run --rm -v portcullis_hub_data:/d:ro "$ALPINE" cat /d/group-gate-policy.json \
  | jq -c --slurpfile auth tests/e2e/fixtures/virtual-authenticators.json \
      '{version: 1, methods, add_stronger, templates, clients: {}, authenticators: $auth[0],
        mds: {serial: 0, next_update: "0001-01-01T00:00:00Z"}}' \
  | docker run --rm -i -v portcullis_hub_data:/d "$ALPINE" \
      sh -c 'cat > /d/signin-keycloak.json.tmp && chmod 644 /d/signin-keycloak.json.tmp && mv /d/signin-keycloak.json.tmp /d/signin-keycloak.json'
# Shared custom fields (normally written by the Hub): e2e_login.py
# checks the attribute header reaches the app and forged ones don't.
printf '%s' '{"version": 2, "fields": {"city": "City"}, "users": {"e2e": {"city": ["Milan"]}}}' \
  | docker run --rm -i -v portcullis_hub_data:/d "$ALPINE" sh -c 'cat > /d/user-attributes.json && chmod 644 /d/user-attributes.json'

# Test app behind the standard forward-auth chain.
cat > /tmp/e2e-app.yml <<'YML'
services:
  whoami:
    image: docker.io/traefik/whoami:v1.12.0@sha256:c4717a8d1f0134a7444e24f881160e033991f23027c6c5a9a3f8fd22e70d1d44
    networks: [portcullis-proxy]
    labels:
      traefik.enable: "true"
      traefik.http.services.e2e.loadbalancer.server.port: "80"
      traefik.http.routers.e2e.rule: Host(`app.portcullis.local`) || Host(`hwk.portcullis.local`) || Host(`mtls.portcullis.local`)
      traefik.http.routers.e2e.entrypoints: websecure
      traefik.http.routers.e2e.tls.options: authaware@file
      traefik.http.routers.e2e.middlewares: client-headers@file,portcullis-auth@docker,portcullis-groups@docker,security-headers@file
      traefik.http.routers.e2e.service: e2e
networks:
  portcullis-proxy:
    external: true
YML
sed -i 's/^          //' /tmp/e2e-app.yml
docker compose -p e2e-app -f /tmp/e2e-app.yml up -d
echo "127.0.0.1 portcullis.local auth.portcullis.local enroll.portcullis.local app.portcullis.local hwk.portcullis.local mtls.portcullis.local metrics.portcullis.local" | sudo tee -a /etc/hosts

# Client certs: one for e2e from Vault, one from a foreign CA.
VAULT_TOKEN=$(jq -r .root_token secrets/vault-init.json); export VAULT_TOKEN
echo "::add-mask::$VAULT_TOKEN"
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/e2e.key
openssl req -new -key /tmp/e2e.key -subj "/CN=e2e" -out /tmp/e2e.csr
docker compose exec -T -e VAULT_TOKEN vault vault write -format=json pki_int/sign/client-cert \
  csr="$(cat /tmp/e2e.csr)" common_name=e2e ttl=2h > /tmp/e2e.json
jq -r .data.certificate /tmp/e2e.json > /tmp/e2e.crt
echo "E2E_REVOKE_CMD=./portcullis cert revoke --yes $(jq -r .data.serial_number /tmp/e2e.json)" >> "$GITHUB_ENV"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout /tmp/foreign.key -out /tmp/foreign.crt -subj "/CN=e2e" -days 1

# Wait until the app is routed (unauthenticated → redirect to sign-in).
for i in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --cacert certs/ca-chain.crt https://app.portcullis.local/ || true)
  case "$code" in 302|401|403) echo "app routed (HTTP $code)"; break ;; esac
  [ "$i" -eq 40 ] && { echo "FAIL: app not routed ($code)"; docker compose logs --tail=40 traefik forward-auth; exit 1; }
  sleep 3
done
