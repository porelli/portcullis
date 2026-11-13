#!/usr/bin/env bash
# ci.yml job e2e-signin, step "Users, groups, templates, instances, certificates, a password (through the Hub's API)".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
set -o pipefail
SECRET="$(grep '^HUB_PROXY_SECRET=' .env | cut -d= -f2-)"; echo "::add-mask::$SECRET"
hub() { local m="$1" p="$2"; shift 2
        curl -s -X "$m" -H @<(printf 'X-Portcullis-Proxy-Secret: %s\nX-Forwarded-User: admin\n' "$SECRET") \
          -H 'Content-Type: application/json' "$@" "http://$HUB_IP:8888$p"; }
hubc() { hub "$@" -o /tmp/hub.out -w '%{http_code}'; }
want() { local code="$1" what="$2"
         case "$code" in 200|201) ;; *) echo "FAIL: $what: HTTP $code $(head -c 600 /tmp/hub.out)"; docker compose logs --tail=40 hub; exit 1 ;; esac; }
# hubop: a lifecycle route's 202, then its op record until done.
source tests/e2e/hubop.sh
for i in $(seq 1 30); do
  hub GET /api/templates | jq -e '[.[].id] as $ids | ["echo", "oidc-echo"] - $ids == []' >/dev/null 2>&1 && break
  [ "$i" -eq 30 ] && { echo "FAIL: the Hub did not load the CI templates: $(hub GET /api/templates | jq -c '[.[].id]')"; docker compose logs --tail=60 hub; exit 1; }
  sleep 2
done

# People, created with the Hub's own LLDAP service account; root and
# sam in lldap_admin (only the CLI invites administrators).
LLDAP_TOKEN=$(jq -n --rawfile u secrets/hub/lldap/username --rawfile p secrets/hub/lldap/password \
    '{username: ($u | rtrimstr("\n")), password: ($p | rtrimstr("\n"))}' \
  | curl -sf http://127.0.0.1:17170/auth/simple/login -H 'Content-Type: application/json' -d @- | jq -r .token)
[ -z "$LLDAP_TOKEN" ] || [ "$LLDAP_TOKEN" = null ] || echo "::add-mask::$LLDAP_TOKEN"
[ -n "$LLDAP_TOKEN" ] && [ "$LLDAP_TOKEN" != null ] || { echo "FAIL: LLDAP login as the Hub's service account"; exit 1; }
gql() { jq -n --arg q "$1" '{query: $q}' | curl -sf http://127.0.0.1:17170/api/graphql \
          -H @<(printf 'Authorization: Bearer %s\n' "$LLDAP_TOKEN") -H 'Content-Type: application/json' -d @-; }
for u in root sam alice bob pat rita carol; do
  gql "mutation { createUser(user: {id: \"$u\", email: \"$u@portcullis.local\"}) { id } }" | jq -e '.errors == null' >/dev/null
done
gid=$(gql '{ groups { id displayName } }' | jq -r '.data.groups[] | select(.displayName == "lldap_admin") | .id')
for u in root sam; do
  gql "mutation { addUserToGroup(userId: \"$u\", groupId: $gid) { ok } }" | jq -e '.errors == null' >/dev/null
done

# Templates: Basic and YubiKey + certificate on (they start
# disabled), e2e-cert = YubiKey certificate only.
for t in basic yubikey-and-certificate; do
  code=$(hubc PUT "/api/signin/templates/$t/enabled" -d '{"on":true}'); want "$code" "enable template $t"
done
code=$(hubc POST /api/signin/templates -d '{"id":"e2e-cert","name":"YubiKey certificate only","rule":{"op":"any","items":["yubikey_cert"]}}')
want "$code" "create the e2e-cert template"
# Browser certificates (part 2): browser_cert on (off by default),
# e2e-file = any[browser_cert] and e2e-anycert = any[yubikey_cert,
# browser_cert] — both protected-any@file.
# Off by default (a fresh Hub, part 2 ruling): asserted before the switch.
hub GET /api/signin | jq -e '[.methods[] | select(.id == "browser_cert")] | length == 1 and .[0].on == false' >/dev/null \
  || { echo "FAIL: browser_cert isn't off by default: $(hub GET /api/signin | jq -c '[.methods[] | select(.id == "browser_cert")]')"; exit 1; }
echo "PASS: browser_cert is off by default"
code=$(hubc PUT /api/signin/methods/browser_cert -d '{"on":true}'); want "$code" "switch browser_cert on"
code=$(hubc POST /api/signin/templates -d '{"id":"e2e-file","name":"Browser certificate only","rule":{"op":"any","items":["browser_cert"]}}')
want "$code" "create the e2e-file template"
code=$(hubc POST /api/signin/templates -d '{"id":"e2e-anycert","name":"Any certificate","rule":{"op":"any","items":["yubikey_cert","browser_cert"]}}')
want "$code" "create the e2e-anycert template"

# Instances (all on the main domain) and their picks, then enable.
for spec in "echo echo-std Echo-Std" "echo echo-basic Echo-Basic" "echo echo-cert Echo-Cert" \
            "echo echo-file Echo-File" "echo echo-anycert Echo-Anycert" \
            "oidc-echo oidc-strong OIDC-Strong" "oidc-echo oidc-all OIDC-All" "oidc-echo oidc-cert OIDC-Cert"; do
  read -r tpl id label <<<"$spec"
  router="echo"; [ "$tpl" = oidc-echo ] && router="oidc"
  label="${label//-/ }"
  hubop POST /api/instances -d "$(jq -cn --arg t "$tpl" --arg id "$id" --arg l "$label" --arg r "$router" --arg h "$id.$E2E_DOMAIN" \
      '{template: $t, id: $id, label: $l, hosts: {($r): $h}}')" || { echo "FAIL: create $id"; exit 1; }
done
for pick in echo-basic:basic echo-cert:e2e-cert echo-file:e2e-file echo-anycert:e2e-anycert \
            oidc-strong:strong oidc-all:yubikey-and-certificate oidc-cert:e2e-cert; do
  code=$(hubc PUT "/api/instances/${pick%%:*}/settings" -d "$(jq -cn --arg t "${pick#*:}" '{sign_in_template: $t}')")
  want "$code" "sign-in template of ${pick%%:*}"
done
for m in alice:users_echo-std alice:users_echo-cert alice:users_echo-file alice:users_echo-anycert pat:users_echo-basic; do
  code=$(hubc POST "/api/directory/groups/${m#*:}/members" -d "$(jq -cn --arg u "${m%%:*}" '{username: $u}')")
  want "$code" "add $m"
done
for id in echo-std echo-basic echo-cert echo-file echo-anycert oidc-strong oidc-all oidc-cert; do
  hubop POST /api/templates/enable -d "{\"id\":\"$id\"}" || { echo "FAIL: enable $id"; exit 1; }
done

# What the Hub published: the picks in the policy file, the
# native-OIDC clients with their templates in signin-keycloak.json.
hub_file() { docker run --rm --network none -v portcullis_hub_data:/d:ro "$ALPINE" cat "/d/$1"; }
for i in $(seq 1 30); do
  hub_file group-gate-policy.json | jq -e --arg d "$E2E_DOMAIN" '.version == 7
      and .hosts["echo-basic.\($d)"] == "basic" and .hosts["echo-cert.\($d)"] == "e2e-cert"
      and .hosts["echo-file.\($d)"] == "e2e-file" and .hosts["echo-anycert.\($d)"] == "e2e-anycert"
      and (.methods | index("browser_cert") != null)
      and (.hosts | has("echo-std.\($d)") | not) and .default == "standard"
      and .core["hub.\($d)"] == "strong" and .core["people.\($d)"] == "strong"' >/dev/null 2>&1 \
    && hub_file signin-keycloak.json | jq -e '.clients["oidc-strong"] == {template: "strong", name: "OIDC echo · OIDC Strong"}
      and .clients["oidc-all"] == {template: "yubikey-and-certificate", name: "OIDC echo · OIDC All"}
      and .clients["oidc-cert"] == {template: "e2e-cert", name: "OIDC echo · OIDC Cert"}
      and (.authenticators | has("01020304-0506-0708-0102-030405060708"))
      and (.methods | index("password") == null) and (.methods | index("browser_cert") != null)' >/dev/null 2>&1 && break
  [ "$i" -eq 30 ] && { echo "FAIL: published: $(hub_file group-gate-policy.json | jq -c '{hosts, core, default}') $(hub_file signin-keycloak.json | jq -c '{clients, methods, mds}')"; exit 1; }
  sleep 2
done
echo "PASS: policy v7 picks (Basic, e2e-cert, e2e-file, e2e-anycert, Strong core pages; browser_cert on) and signin-keycloak.json clients (oidc-strong Strong, oidc-all YubiKey + certificate, oidc-cert e2e-cert)"

# pat: a Hub-set password only (allowed while the method is off),
# kept in a 0600 file, never printed.
mkdir -m 700 /tmp/e2e-secrets
code=$(hubc POST /api/directory/users/pat/password -d '{"generate":true}')
want "$code" "set pat's password"
( umask 077; jq -er .password /tmp/hub.out > /tmp/e2e-secrets/pat.password ) || { echo "FAIL: no generated password"; rm -f /tmp/hub.out; exit 1; }
rm -f /tmp/hub.out
echo "::add-mask::$(cat /tmp/e2e-secrets/pat.password)"

# Certificates: root's (all[yubikey_cert, security_key]) and bob's
# (the cross-user certificate).
VAULT_TOKEN=$(jq -r .root_token secrets/vault-init.json); export VAULT_TOKEN
echo "::add-mask::$VAULT_TOKEN"
for u in root bob; do
  openssl ecparam -name prime256v1 -genkey -noout -out "/tmp/e2e-secrets/$u.key"
  openssl req -new -key "/tmp/e2e-secrets/$u.key" -subj "/CN=$u" -out "/tmp/e2e-secrets/$u.csr"
  docker compose exec -T -e VAULT_TOKEN vault vault write -format=json pki_int/sign/client-cert \
    csr="$(cat "/tmp/e2e-secrets/$u.csr")" common_name="$u" ttl=2h | jq -r .data.certificate > "/tmp/e2e-secrets/$u.crt"
  openssl x509 -noout -subject -in "/tmp/e2e-secrets/$u.crt"
done

# shellcheck disable=SC2086
echo "127.0.0.1 portcullis.local auth.portcullis.local enroll.portcullis.local hub.portcullis.local people.portcullis.local $(printf '%s.portcullis.local ' $APP_HOSTS)" | sudo tee -a /etc/hosts
for id in echo-std echo-basic; do
  for i in $(seq 1 40); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --cacert certs/ca-chain.crt "https://$id.$E2E_DOMAIN/" || true)
    case "$code" in 302|401|403) echo "$id routed (HTTP $code)"; break ;; esac
    [ "$i" -eq 40 ] && { echo "FAIL: $id not routed ($code)"; docker compose logs --tail=40 traefik; exit 1; }
    sleep 3
  done
done
