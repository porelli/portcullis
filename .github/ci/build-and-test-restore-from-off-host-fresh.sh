#!/usr/bin/env bash
# ci.yml job build-and-test, step "Restore from off-host into a fresh stack (new host)".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
VAULT_TOKEN=$(jq -r .root_token secrets/vault-init.json); export VAULT_TOKEN
echo "::add-mask::$VAULT_TOKEN"
ROOT_CA=$(vault read -field=certificate pki/cert/ca | sha256sum)
N_CERTS=$(vault list -format=json pki_int/certs | jq length)
REVOKED=$(cat /tmp/test-client.serial)
BACKUP_REPOSITORY="$(grep '^BACKUP_REPOSITORY=' .env | cut -d= -f2-)"
BACKUP_PASSWORD="$(grep '^BACKUP_PASSWORD=' .env | cut -d= -f2-)"
echo "::add-mask::$BACKUP_PASSWORD"
export BACKUP_REPOSITORY BACKUP_PASSWORD
cp secrets/mcp-gate/age.pub /tmp/gate-age.pub
# The built-in VPN's server key (secrets/wg/people.key) must survive: a
# new key would break every built-in device's config.
WG_PUB="$(docker compose exec -T wg /wg status | jq -r '.people.public_key // empty')"
[ -n "$WG_PUB" ] || { echo "FAIL: no built-in VPN public key before the backup"; exit 1; }
# LLDAP's admin: its Keycloak id and LLDAP uuid (the link, entryUUID) must survive.
KC_TOKEN=$(printf '%s' "$KEYCLOAK_ADMIN_PASSWORD" | curl -sf http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  --data-urlencode client_id=admin-cli --data-urlencode "username=$KEYCLOAK_ADMIN" \
  --data-urlencode grant_type=password --data-urlencode password@- | jq -r .access_token)
[ -z "$KC_TOKEN" ] || [ "$KC_TOKEN" = null ] || echo "::add-mask::$KC_TOKEN"
ADMIN_KC=$(curl -sf -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") "http://127.0.0.1:8080/admin/realms/portcullis/users?username=admin&exact=true" \
  | jq -c '.[0] | {id, link: .attributes.LDAP_ID}')
jq -e '.id != null and (.link | length) == 1' <<<"$ADMIN_KC" >/dev/null || { echo "FAIL: admin's Keycloak copy before the backup: $ADMIN_KC"; exit 1; }
# Everything local is gone: containers, volumes, .env, secrets/, certs/, local backups.
docker compose -p ci-mtls -f /tmp/ci-mtls.yml down 2>/dev/null || true
docker compose -p ci-hubproxy down -v 2>/dev/null || true
docker compose down -v
rm -rf .env secrets/* certs backups/2* backups/.verify-* monitoring/textfile/*.prom
unset VAULT_TOKEN
./portcullis restore --yes --from-offsite 2>&1 | tee /tmp/restore.out
[ "${PIPESTATUS[0]}" = 0 ] || { echo "FAIL: restore --from-offsite"; exit 1; }
# Its last line (T24, both restore paths): authenticator apps and passkeys
# removed since the backup work again.
tail -n1 /tmp/restore.out | sed 's/\x1b\[[0-9;]*m//g' \
  | grep -qxF "==> Authenticator apps and passkeys removed after this backup's date work again: remove the ones reported lost since then (People → person → Sign-in)." \
  || { echo "FAIL: restore's last line isn't the lost-devices note: $(tail -n1 /tmp/restore.out)"; exit 1; }
VAULT_TOKEN=$(jq -r .root_token secrets/vault-init.json); export VAULT_TOKEN
echo "::add-mask::$VAULT_TOKEN"
test "$ROOT_CA" = "$(vault read -field=certificate pki/cert/ca | sha256sum)" || { echo "FAIL: CA differs after restore"; exit 1; }
# domains_data (age-encrypted) + secrets/domains/age.key came back: the store decrypts.
for _ in $(seq 1 40); do [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q domains)" 2>/dev/null)" = healthy ] && break; sleep 3; done
printf 'Authorization: Bearer %s\n' "$(cat secrets/domains/api-secret)" \
  | docker run --rm -i --network portcullis_portcullis-domains docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93 -sf -H @- http://domains:8080/domains \
  | jq -e 'any(.[]; .name == "keep.ci-domains.test")' >/dev/null || { echo "FAIL: enrolled domain lost by backup/restore"; docker compose logs --tail=20 domains; exit 1; }
test "$N_CERTS" = "$(vault list -format=json pki_int/certs | jq length)" || { echo "FAIL: issued-cert records lost"; exit 1; }
vault read -format=json "pki_int/cert/$REVOKED" | jq -e '.data.revocation_time > 0' >/dev/null || { echo "FAIL: revocation lost"; exit 1; }
# Keycloak realm, client secret and the LLDAP user survived.
for _ in $(seq 1 60); do curl -sf http://localhost:9000/health/ready >/dev/null && break; sleep 3; done
KC_TOKEN=$(printf '%s' "$KEYCLOAK_ADMIN_PASSWORD" | curl -sf http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  --data-urlencode client_id=admin-cli --data-urlencode "username=$KEYCLOAK_ADMIN" \
  --data-urlencode grant_type=password --data-urlencode password@- | jq -r .access_token)
[ -z "$KC_TOKEN" ] || [ "$KC_TOKEN" = null ] || echo "::add-mask::$KC_TOKEN"
kc() { curl -sf -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") "http://127.0.0.1:8080/admin/realms/portcullis$1"; }
UUID=$(kc "/clients?clientId=portcullis-forward-auth" | jq -r '.[0].id')
test "$(kc "/clients/$UUID/client-secret" | jq -r .value)" = "$FORWARD_AUTH_CLIENT_SECRET" || { echo "FAIL: Keycloak client secret after restore"; exit 1; }
LLDAP_TOKEN=$(jq -n '{username: "admin", password: env.LLDAP_ADMIN_PASSWORD}' \
  | curl -sf http://localhost:17170/auth/simple/login -H 'Content-Type: application/json' -d @- | jq -r .token)
[ -z "$LLDAP_TOKEN" ] || [ "$LLDAP_TOKEN" = null ] || echo "::add-mask::$LLDAP_TOKEN"
jq -n '{query: "{ user(userId: \"testuser\") { id } }"}' | curl -sf http://localhost:17170/api/graphql \
  -H @<(printf 'Authorization: Bearer %s\n' "$LLDAP_TOKEN") -H 'Content-Type: application/json' -d @- \
  | jq -e '.data.user.id == "testuser"' >/dev/null || { echo "FAIL: LLDAP user lost"; exit 1; }
# Same Keycloak id after the restore and a full sync, still linked to the same LLDAP uuid.
LDAPC=$(kc "/components?type=org.keycloak.storage.UserStorageProvider" | jq -r '[.[] | select(.providerId == "ldap")][0].id')
curl -sf -X POST -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") "http://127.0.0.1:8080/admin/realms/portcullis/user-storage/$LDAPC/sync?action=triggerFullSync" >/dev/null \
  || { echo "FAIL: full sync after restore"; exit 1; }
jq -n '{query: "{ user(userId: \"admin\") { uuid } }"}' | curl -sf http://localhost:17170/api/graphql \
  -H @<(printf 'Authorization: Bearer %s\n' "$LLDAP_TOKEN") -H 'Content-Type: application/json' -d @- \
  | jq -e --argjson b "$ADMIN_KC" '[.data.user.uuid] == $b.link' >/dev/null || { echo "FAIL: LLDAP admin's uuid changed by backup/restore"; exit 1; }
[ "$(kc "/users?username=admin&exact=true" | jq -c '.[0] | {id, link: .attributes.LDAP_ID}')" = "$ADMIN_KC" ] \
  || { echo "FAIL: admin's Keycloak identity changed by backup/restore: $ADMIN_KC → $(kc "/users?username=admin&exact=true" | jq -c '.[0] | {id, link: .attributes.LDAP_ID}')"; exit 1; }
./portcullis status --json | jq -e '.vault.active and .keycloak.realm and .keycloak.forward_auth_client' >/dev/null \
  || { echo "FAIL: status after restore"; ./portcullis status || true; exit 1; }
# The gate's key / recipient / secret and its access log came back (G29 modes kept).
for _ in $(seq 1 40); do [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q mcp-gate)" 2>/dev/null)" = healthy ] && break; sleep 3; done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q mcp-gate)")" = healthy ] || { echo "FAIL: mcp-gate after restore"; docker compose logs --tail=30 mcp-gate; exit 1; }
cmp -s /tmp/gate-age.pub secrets/mcp-gate/age.pub || { echo "FAIL: the gate's recipient changed by backup/restore"; exit 1; }
for _ in $(seq 1 30); do
  GOT="$(docker compose exec -T wg /wg status 2>/dev/null | jq -r '.people.public_key // empty' || true)"
  [ -n "$GOT" ] && break
  sleep 2
done
[ "$GOT" = "$WG_PUB" ] || { echo "FAIL: the built-in VPN's server key changed by backup/restore ($WG_PUB → ${GOT:-none})"; exit 1; }
docker run --rm -v portcullis_mcp_gate_data:/d:ro docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a \
  sh -c 'stat -c "%a %u %g" /d /d/access.jsonl && grep -c "deny:off" /d/access.jsonl' > /tmp/gate-restored
[ "$(sed -n 1,2p /tmp/gate-restored | paste -sd' ')" = "750 10005 10001 640 10005 10001" ] && [ "$(sed -n 3p /tmp/gate-restored)" -ge 3 ] \
  || { echo "FAIL: restored access log: $(cat /tmp/gate-restored)"; exit 1; }
echo "PASS: restored from restic into a fresh stack: CA, cert records, revocations, Keycloak (admin's id and entryUUID link kept), LLDAP, the MCP gate's key and access log, the built-in VPN's server key"
# The restore's LLDAP guard read the real volume and database: LLDAP
# users counted, Keycloak's federated users counted, so it passed.
GUARD=$(bash -c 'source scripts/lib/common.sh; env_load; source scripts/lib/status.sh; source scripts/lib/backup.sh; _backup_load_cfg
  printf "%s %s" "$(_restore_lldap_count)" "$(_restore_kc_federated_count)"')
echo "restore guard sees: LLDAP $GUARD Keycloak"
[[ "$GUARD" =~ ^[1-9][0-9]*\ [1-9][0-9]*$ ]] || { echo "FAIL: restore guard counts: $GUARD"; exit 1; }
# An empty LLDAP volume is "missing" (refused while Keycloak has users).
docker volume create ci-empty-lldap >/dev/null
EMPTY=$(bash -c 'source scripts/lib/common.sh; env_load; source scripts/lib/status.sh; source scripts/lib/backup.sh; _backup_load_cfg
  _volume_name() { echo ci-empty-lldap; }; _restore_lldap_count')
docker volume rm ci-empty-lldap >/dev/null
[ "$EMPTY" = missing ] || { echo "FAIL: empty LLDAP volume counted as $EMPTY"; exit 1; }
echo "PASS: restore's LLDAP guard counts the real LLDAP and Keycloak users; an empty volume is missing"
