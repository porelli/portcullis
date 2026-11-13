#!/usr/bin/env bash
# ci.yml job e2e-instances, step "Extra domain, instances, users, setup links (through the Hub's API)".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
set -o pipefail
SECRET="$(grep '^HUB_PROXY_SECRET=' .env | cut -d= -f2-)"; echo "::add-mask::$SECRET"
# The Hub's API as Traefik calls it: proxy secret + the admin's identity.
hub() { local m="$1" p="$2"; shift 2
        curl -s -X "$m" -H @<(printf 'X-Portcullis-Proxy-Secret: %s\nX-Forwarded-User: admin\n' "$SECRET") \
          -H 'Content-Type: application/json' "$@" "http://$HUB_IP:8888$p"; }
hubc() { hub "$@" -o /tmp/hub.out -w '%{http_code}'; }
# hubop: a lifecycle route's 202, then its op record until done.
source tests/e2e/hubop.sh
for i in $(seq 1 30); do
  hub GET /api/templates | jq -e 'any(.[]; .id == "echo")' >/dev/null 2>&1 && break
  [ "$i" -eq 30 ] && { echo "FAIL: the Hub did not load the CI template: $(hub GET /api/templates | head -c 400)"; docker compose logs --tail=40 hub; exit 1; }
  sleep 2
done

# Enrolled domain team-b.test: the Hub accepts only real providers,
# so CI enrolls it on the domains service's API with the fake one;
# the Hub picks the service's list up (RefreshDomains).
code=$(hubc POST /api/domains -d '{"name":"team-b.test","provider":"fake","credentials":{"api_token":"ci-fake-token-0123456789"}}')
[ "$code" = 400 ] || { echo "FAIL: the Hub forwarded an unknown provider ($code)"; exit 1; }
DSECRET="$(cat secrets/domains/api-secret)"; echo "::add-mask::$DSECRET"
dapi() { printf 'Authorization: Bearer %s\n' "$DSECRET" \
         | docker run --rm -i --network portcullis_portcullis-domains "$CURL_IMG" -s -H @- -H 'Content-Type: application/json' "$@"; }
code=$(dapi -o /dev/null -w '%{http_code}' -X PUT -d '{"provider":"fake","credentials":{"api_token":"ci-fake-token-0123456789"}}' "http://domains:8080/domains/$E2E_EXTRA")
[ "$code" = 202 ] || { echo "FAIL: enroll $E2E_EXTRA got $code"; exit 1; }
for i in $(seq 1 60); do
  st="$(hub GET /api/domains | jq -r --arg d "$E2E_EXTRA" '.[]? | select(.name == $d) | .state')"
  [ "$st" = ready ] && break
  [ "$i" -eq 60 ] && { echo "FAIL: $E2E_EXTRA in the Hub: $(hub GET /api/domains)"; docker compose logs --tail=60 domains pebble; exit 1; }
  sleep 3
done
echo "PASS: $E2E_EXTRA enrolled (Pebble, DNS-01 with the fake provider) and ready in the Hub"

# Instances: echo-a and echo-c on the extra domain, echo-b on the main one.
for spec in "echo-a echo-a.$E2E_EXTRA Team A" "echo-b echo-b.$E2E_DOMAIN Team B" "echo-c echo-c.$E2E_EXTRA Team C"; do
  read -r id host label <<<"$spec"
  hubop POST /api/instances -d "$(jq -cn --arg id "$id" --arg l "$label" --arg h "$host" '{template: "echo", id: $id, label: $l, hosts: {echo: $h}}')" \
    || { echo "FAIL: create $id"; exit 1; }
done
# A host on a domain that isn't enrolled is refused.
code=$(hubc POST /api/instances -d '{"template":"echo","id":"echo-x","label":"X","hosts":{"echo":"echo-x.not-enrolled.test"}}')
case "$code" in 400|409) ;; *) echo "FAIL: a host on an unknown domain got $code"; exit 1 ;; esac
# Every create names its label (contracts §11.9).
code=$(hubc POST /api/instances -d "$(jq -cn --arg h "echo-y.$E2E_DOMAIN" '{template: "echo", id: "echo-y", hosts: {echo: $h}}')")
[ "$code" = 400 ] || { echo "FAIL: a create without a label got $code $(cat /tmp/hub.out)"; exit 1; }
# echo-c: a template of the YubiKey certificate only (a passkey
# session steps up, contract §8.1); echo-b: a slow stop (its backup
# takes > 60 s, e2e_instances.py long_backup).
code=$(hubc POST /api/signin/templates -d '{"id":"e2e-cert","name":"YubiKey certificate only","rule":{"op":"any","items":["yubikey_cert"]}}')
[ "$code" = 201 ] || { echo "FAIL: create the e2e-cert template: $code $(cat /tmp/hub.out)"; exit 1; }
code=$(hubc PUT /api/instances/echo-c/settings -d '{"sign_in_template":"e2e-cert"}')
[ "$code" = 200 ] || { echo "FAIL: echo-c sign-in template: $code $(cat /tmp/hub.out)"; exit 1; }
hub GET /api/instances/echo-c/signin | jq -e '.template == "e2e-cert" and (.inherits | not)' >/dev/null \
  || { echo "FAIL: echo-c's pick: $(hub GET /api/instances/echo-c/signin | head -c 400)"; exit 1; }
code=$(hubc PUT /api/instances/echo-b/settings -d '{"values":{"echo_stop_grace":"75s"}}')
[ "$code" = 200 ] || { echo "FAIL: echo-b settings: $code $(cat /tmp/hub.out)"; exit 1; }
# Env overrides (contracts §11.9): a variable of the admin's own is
# stored and reset; a Hub variable and a setting's (echo_stop_grace)
# are refused; the whole-file Expert route is gone.
code=$(hubc PUT /api/instances/echo-b/env/CI_MARKER -d '{"value":"on"}')
if [ "$code" != 200 ] || ! jq -e '.row.name == "CI_MARKER" and .row.source == "custom" and .row.value == "on" and .row.overridden' /tmp/hub.out >/dev/null; then
  echo "FAIL: env override CI_MARKER: $code $(cat /tmp/hub.out)"; exit 1
fi
hub GET /api/instances/echo-b/env | jq -e 'any(.rows[]; .name == "CI_MARKER" and .value == "on" and .overridden)' >/dev/null \
  || { echo "FAIL: env rows of echo-b: $(hub GET /api/instances/echo-b/env)"; exit 1; }
for n in PORTCULLIS_INSTANCE ECHO_STOP_GRACE; do
  code=$(hubc PUT "/api/instances/echo-b/env/$n" -d '{"value":"x"}')
  [ "$code" = 400 ] || { echo "FAIL: env override $n got $code $(cat /tmp/hub.out)"; exit 1; }
done
code=$(hubc DELETE /api/instances/echo-b/env/CI_MARKER)
if [ "$code" != 200 ] || ! jq -e '.row == null' /tmp/hub.out >/dev/null; then
  echo "FAIL: env reset CI_MARKER: $code $(cat /tmp/hub.out)"; exit 1
fi
code=$(hubc GET /api/templates/env/echo-b)
case "$code" in 404|405) ;; *) echo "FAIL: the removed /api/templates/env/ route answered $code"; exit 1 ;; esac
echo "PASS: env overrides: custom variable stored and reset, Hub and setting variables refused, whole-file route gone"

# Users and the instances' groups (created by the Hub as the admin).
LLDAP_TOKEN=$(jq -n '{username: "admin", password: env.LLDAP_ADMIN_PASSWORD}' \
  | curl -sf http://127.0.0.1:17170/auth/simple/login -H 'Content-Type: application/json' -d @- | jq -r .token)
[ -z "$LLDAP_TOKEN" ] || [ "$LLDAP_TOKEN" = null ] || echo "::add-mask::$LLDAP_TOKEN"
gql() { jq -n --arg q "$1" '{query: $q}' | curl -sf http://127.0.0.1:17170/api/graphql \
          -H @<(printf 'Authorization: Bearer %s\n' "$LLDAP_TOKEN") -H 'Content-Type: application/json' -d @-; }
for u in alice bob; do
  gql "mutation { createUser(user: {id: \"$u\", email: \"$u@portcullis.local\"}) { id } }" | jq -e '.errors == null' >/dev/null
done
GROUPS_JSON="$(gql '{ groups { id displayName } }')"
for g in users_echo-a admin_echo-a users_echo-b users_echo-c; do
  echo "$GROUPS_JSON" | jq -e --arg g "$g" 'any(.data.groups[]; .displayName == $g)' >/dev/null || { echo "FAIL: the Hub did not create $g"; exit 1; }
done
for m in alice:users_echo-a alice:users_echo-c bob:users_echo-b; do
  gid=$(echo "$GROUPS_JSON" | jq -r --arg g "${m#*:}" '.data.groups[] | select(.displayName == $g) | .id')
  gql "mutation { addUserToGroup(userId: \"${m%%:*}\", groupId: $gid) { ok } }" | jq -e '.errors == null' >/dev/null
done

for id in echo-a echo-b echo-c; do
  hubop POST /api/templates/enable -d "{\"id\":\"$id\"}" || { echo "FAIL: enable $id"; exit 1; }
done

# What the Hub published: policy v7 keyed by hostname, the extra domain.
policy_file() { docker run --rm -v portcullis_hub_data:/d:ro "$ALPINE" cat /d/group-gate-policy.json; }
for i in $(seq 1 30); do
  policy_file | jq -e --arg x "$E2E_EXTRA" '.version == 7 and .extra_domains == [$x]
      and .groups["echo-a.\($x)"] == "users_echo-a" and .groups["echo-c.\($x)"] == "users_echo-c"
      and .groups["echo-b.portcullis.local"] == "users_echo-b"
      and .hosts["echo-c.\($x)"] == "e2e-cert" and .templates["e2e-cert"] == {op: "any", items: ["yubikey_cert"]}
      and (.hosts | has("echo-a.\($x)") | not) and .default == "standard"' >/dev/null 2>&1 && break
  [ "$i" -eq 30 ] && { echo "FAIL: policy file: $(policy_file)"; exit 1; }
  sleep 2
done
echo "PASS: policy v7: instances keyed by hostname, groups per instance, echo-c on e2e-cert, extra_domains = [$E2E_EXTRA]"

# The rendered sign-in: forward-auth-ext on extra-domain hosts only.
labels() { docker inspect -f '{{json .Config.Labels}}' "$(docker ps -q --filter "label=com.docker.compose.project=portcullis-$1" --filter label=com.docker.compose.service=web)"; }
labels echo-a | jq -e --arg h "echo-a.$E2E_EXTRA" '
    (.["traefik.http.routers.echo-a_echo.middlewares"] | split(",") | index("portcullis-auth-ext@docker") != null and index("portcullis-auth@docker") == null)
    and .["traefik.http.routers.portcullis-oauth2-echo-a_echo.service"] == "forward-auth-ext@docker"
    and .["traefik.http.routers.portcullis-oauth2-echo-a_echo.rule"] == "Host(`\($h)`) && PathPrefix(`/oauth2/`)"' >/dev/null \
  || { echo "FAIL: echo-a labels: $(labels echo-a)"; exit 1; }
labels echo-b | jq -e '(.["traefik.http.routers.echo-b_echo.middlewares"] | split(",") | index("portcullis-auth@docker") != null)
    and ([keys[] | select(startswith("traefik.http.routers.portcullis-oauth2-"))] == [])' >/dev/null \
  || { echo "FAIL: echo-b labels: $(labels echo-b)"; exit 1; }
KC_TOKEN=$(printf '%s' "$KEYCLOAK_ADMIN_PASSWORD" | curl -sf http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  --data-urlencode client_id=admin-cli --data-urlencode "username=$KEYCLOAK_ADMIN" \
  --data-urlencode grant_type=password --data-urlencode password@- | jq -r .access_token)
[ -z "$KC_TOKEN" ] || [ "$KC_TOKEN" = null ] || echo "::add-mask::$KC_TOKEN"
curl -sf -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") "http://127.0.0.1:8080/admin/realms/portcullis/clients?clientId=portcullis-forward-auth" \
  | jq -e --arg x "$E2E_EXTRA" '.[0].redirectUris as $u | ($u | index("https://echo-a.\($x)/oauth2/callback") != null)
      and ($u | index("https://echo-c.\($x)/oauth2/callback") != null) and ($u | index("https://echo-b.portcullis.local/oauth2/callback") == null)' >/dev/null \
  || { echo "FAIL: forward-auth callbacks"; exit 1; }
echo "PASS: extra-domain routers use portcullis-auth-ext + a Host-scoped /oauth2/ router to forward-auth-ext; callbacks registered"

# Traefik serves the enrolled domain's certificate by SNI; core hosts keep the main one.
sni_sans() { openssl s_client -connect 127.0.0.1:443 -servername "$1" </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' '; }
for i in $(seq 1 30); do
  sni_sans "echo-a.$E2E_EXTRA" | grep -q "DNS:\*\.$E2E_EXTRA" && break
  [ "$i" -eq 30 ] && { echo "FAIL: no $E2E_EXTRA certificate for echo-a: $(sni_sans "echo-a.$E2E_EXTRA")"; exit 1; }
  sleep 1
done
sni_sans "auth.$E2E_DOMAIN" | grep -q 'DNS:\*\.portcullis\.local' || { echo "FAIL: auth.<main> lost the main certificate"; exit 1; }
docker run --rm --network portcullis_domains-egress "$CURL_IMG" -sfk https://pebble:15000/roots/0 > /tmp/pebble-root.pem
openssl x509 -noout -in /tmp/pebble-root.pem
cat certs/ca-chain.crt /tmp/pebble-root.pem > /tmp/e2e-ca-bundle.pem
echo "PASS: echo-a.$E2E_EXTRA is served with the enrolled domain's certificate (Pebble); auth.<main> keeps the main one"

echo "127.0.0.1 portcullis.local auth.portcullis.local enroll.portcullis.local hub.portcullis.local echo-b.portcullis.local echo-a.$E2E_EXTRA echo-c.$E2E_EXTRA" | sudo tee -a /etc/hosts
for i in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --cacert /tmp/e2e-ca-bundle.pem "https://echo-a.$E2E_EXTRA/" || true)
  case "$code" in 302|401|403) echo "echo-a routed (HTTP $code)"; break ;; esac
  [ "$i" -eq 40 ] && { echo "FAIL: echo-a not routed ($code)"; docker compose logs --tail=40 traefik forward-auth-ext; exit 1; }
  sleep 3
done

for spec in "E2E_ALICE_INVITE alice" "E2E_BOB_INVITE bob" "E2E_ADMIN_INVITE admin"; do
  read -r var who <<<"$spec"
  url="$(./portcullis invite "$who" --to portal --json | jq -r .url)"
  # Masked before anything can print it: a malformed link may still carry a token.
  [ -z "$url" ] || [ "$url" = null ] || echo "::add-mask::$url"
  [[ "$url" =~ ^https://enroll\.portcullis\.local/invite/[A-Za-z0-9_-]{43}$ ]] || { echo "FAIL: setup link for $who: $url"; exit 1; }
  echo "$var=$url" >> "$GITHUB_ENV"
done
# alice's client certificate (echo-c's mtls step-up).
VAULT_TOKEN=$(jq -r .root_token secrets/vault-init.json); export VAULT_TOKEN
echo "::add-mask::$VAULT_TOKEN"
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/alice.key
openssl req -new -key /tmp/alice.key -subj "/CN=alice" -out /tmp/alice.csr
docker compose exec -T -e VAULT_TOKEN vault vault write -format=json pki_int/sign/client-cert \
  csr="$(cat /tmp/alice.csr)" common_name=alice ttl=2h | jq -r .data.certificate > /tmp/alice.crt
