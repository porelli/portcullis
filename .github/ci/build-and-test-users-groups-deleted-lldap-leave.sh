#!/usr/bin/env bash
# ci.yml job build-and-test, step "Test users and groups deleted in LLDAP leave Keycloak".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
set -o pipefail
tok() { printf '%s' "$KEYCLOAK_ADMIN_PASSWORD" | curl -sf http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  --data-urlencode client_id=admin-cli --data-urlencode "username=${KEYCLOAK_ADMIN:-admin}" \
  --data-urlencode grant_type=password --data-urlencode password@- | jq -r .access_token; }
KC_TOKEN=$(tok)
[ -z "$KC_TOKEN" ] || [ "$KC_TOKEN" = null ] || echo "::add-mask::$KC_TOKEN"
kc() { curl -sf -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") "http://127.0.0.1:8080/admin/realms/portcullis$1"; }
kcpost() { curl -sf -X POST -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") "http://127.0.0.1:8080/admin/realms/portcullis$1"; }
kcstatus() { curl -s -o /dev/null -w '%{http_code}' -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") "http://127.0.0.1:8080/admin/realms/portcullis$1"; }
LT=$(jq -n '{username: "admin", password: env.LLDAP_ADMIN_PASSWORD}' \
  | curl -sf http://127.0.0.1:17170/auth/simple/login -H 'Content-Type: application/json' -d @- | jq -r .token)
[ -z "$LT" ] || [ "$LT" = null ] || echo "::add-mask::$LT"
lq() { jq -n --arg q "$1" '{query: $q}' | curl -sf http://127.0.0.1:17170/api/graphql \
  -H @<(printf 'Authorization: Bearer %s\n' "$LT") -H 'Content-Type: application/json' -d @-; }
lg() { lq "$1" | jq -e '.errors == null' >/dev/null || { echo "FAIL: LLDAP: $1"; exit 1; }; }
kcgroup() { kc "/groups?search=$1&exact=true&briefRepresentation=true" | jq -e --arg g "$1" 'any(.[]?; .name == $g)' >/dev/null; }

# configure (run above, idempotent) set the federation up for it.
LDAP_ID=$(kc "/components?type=org.keycloak.storage.UserStorageProvider" | jq -r '[.[] | select(.providerId == "ldap")][0].id')
kc "/components/$LDAP_ID" | jq -e '.config.removeInvalidUsersEnabled == ["true"] and .config.fullSyncPeriod == ["3600"]
    and .config.editMode == ["READ_ONLY"] and .config.customUserSearchFilter == ["(!(uid=portcullis-hub))"]
    and .config.uuidLDAPAttribute == ["entryUUID"] and .config.usernameLDAPAttribute == ["uid"]' >/dev/null \
  || { echo "FAIL: LDAP federation: $(kc "/components/$LDAP_ID" | jq -c '.config | del(.bindCredential)')"; exit 1; }
MAP=$(kc "/components?parent=$LDAP_ID&type=org.keycloak.storage.ldap.mappers.LDAPStorageMapper" | jq -r '[.[] | select(.providerId == "group-ldap-mapper")][0].id')
kc "/components/$MAP" | jq -e '.config["drop.non.existing.groups.during.sync"] == ["true"] and .config.mode == ["READ_ONLY"]' >/dev/null \
  || { echo "FAIL: group mapper: $(kc "/components/$MAP" | jq -c .config)"; exit 1; }

# A user and a group in LLDAP reach Keycloak with a full sync.
lg 'mutation { createUser(user: {id: "gone-user", email: "gone-user@portcullis.local"}) { id } }'
GID=$(lq 'mutation { createGroup(name: "gone-group") { id } }' | jq -r '.data.createGroup.id')
lg "mutation { addUserToGroup(userId: \"gone-user\", groupId: $GID) { ok } }"
kcpost "/user-storage/$LDAP_ID/sync?action=triggerFullSync" | jq -e '.status' >/dev/null || { echo "FAIL: full sync"; exit 1; }
UID_GONE=$(kc "/users?username=gone-user&exact=true" | jq -r '.[0].id // empty')
[ -n "$UID_GONE" ] || { echo "FAIL: gone-user not imported"; exit 1; }
kcgroup gone-group || { echo "FAIL: gone-group not imported"; exit 1; }
# The Hub's service account exists in LLDAP from `up` on (later in this job).
HUB_SA=$(lq '{ user(userId: "portcullis-hub") { id } }' | jq -r '.data.user.id // empty')
# Keycloak ids: a removed-and-reimported user would get a new one.
ADMIN_ID=$(kc "/users?username=admin&exact=true" | jq -r '.[0].id // empty')
TEST_ID=$(kc "/users?username=testuser&exact=true" | jq -r '.[0].id // empty')
[ -n "$ADMIN_ID" ] && [ -n "$TEST_ID" ] || { echo "FAIL: admin / testuser not in Keycloak before the check"; exit 1; }

# LLDAP unreachable: a listing keeps every user (Keycloak can't
# tell gone from unreachable), a sync drops no group.
docker compose stop lldap >/dev/null
kc "/users?briefRepresentation=true&max=1000" >/dev/null || true
kcpost "/user-storage/$LDAP_ID/sync?action=triggerFullSync" >/dev/null || true
docker compose start lldap >/dev/null
for i in $(seq 1 60); do
  [ "$(docker inspect --format '{{.State.Health.Status}}' "$(docker compose ps -q lldap)")" = healthy ] && break
  [ "$i" -eq 60 ] && { echo "FAIL: lldap not healthy again"; docker compose logs --tail=40 lldap; exit 1; }
  sleep 2
done
KC_TOKEN=$(tok)
[ -z "$KC_TOKEN" ] || [ "$KC_TOKEN" = null ] || echo "::add-mask::$KC_TOKEN"
LT=$(jq -n '{username: "admin", password: env.LLDAP_ADMIN_PASSWORD}' \
  | curl -sf http://127.0.0.1:17170/auth/simple/login -H 'Content-Type: application/json' -d @- | jq -r .token)
[ -z "$LT" ] || [ "$LT" = null ] || echo "::add-mask::$LT"
kc "/users?username=testuser&exact=true" | jq -e --arg id "$TEST_ID" '.[0].id == $id' >/dev/null || { echo "FAIL: testuser removed while LLDAP was down"; exit 1; }
kcgroup lldap_admin || { echo "FAIL: lldap_admin dropped while LLDAP was down"; exit 1; }
# Keycloak reaches LLDAP again (its JVM caches the failed DNS lookup
# for a while; a sync that can't reach LDAP answers 0 updated users).
for i in $(seq 1 30); do
  kcpost "/user-storage/$LDAP_ID/sync?action=triggerFullSync" | jq -e '.updated > 0' >/dev/null 2>&1 && break
  [ "$i" -eq 30 ] && { echo "FAIL: Keycloak doesn't reach LLDAP again"; exit 1; }
  sleep 3
done

# Deleted straight in LLDAP: the next sync drops the group; the
# user goes at its next lookup (the Hub lists all users every 15 min).
lg 'mutation { deleteUser(userId: "gone-user") { ok } }'
lg "mutation { deleteGroup(groupId: $GID) { ok } }"
lq '{ groups { displayName } }' | jq -e 'all(.data.groups[]; .displayName != "gone-group")' >/dev/null || { echo "FAIL: gone-group still in LLDAP"; exit 1; }
SYNC=$(kcpost "/user-storage/$LDAP_ID/sync?action=triggerFullSync") || { echo "FAIL: full sync"; exit 1; }
echo "full sync: $SYNC"
if kcgroup gone-group; then
  echo "FAIL: gone-group still in Keycloak after the sync"
  echo "mapper sync: $(kcpost "/user-storage/$LDAP_ID/mappers/$MAP/sync?direction=fedToKeycloak")"
  kcgroup gone-group && echo "(still there after a mapper sync too)"
  docker compose logs --tail=80 keycloak | grep -iE 'ldap|group|sync' | tail -40
  exit 1
fi
kc "/users?briefRepresentation=true&max=1000" | jq -e 'all(.[]; .username != "gone-user")' >/dev/null \
  || { echo "FAIL: gone-user still listed"; exit 1; }
[ "$(kcstatus "/users/$UID_GONE")" = 404 ] || { echo "FAIL: Keycloak kept its copy of gone-user"; exit 1; }

# Linked by LLDAP's immutable entryUUID, never the username: an
# account deleted and re-created under the same name straight in
# LLDAP (no Keycloak lookup in between) is a new identity — a new
# Keycloak id (every token's sub), the old copy (sessions, consents,
# passkeys, role grants) removed, not inherited; a full sync first
# doesn't re-link it either. LLDAP's admin (read only here) is
# linked by its LLDAP uuid.
KC_TOKEN=$(tok)
[ -z "$KC_TOKEN" ] || [ "$KC_TOKEN" = null ] || echo "::add-mask::$KC_TOKEN"
luuid() { lq "{ user(userId: \"$1\") { uuid } }" | jq -r '.data.user.uuid // empty'; }
kc "/users/$ADMIN_ID" | jq -e --arg u "$(luuid admin)" --arg l "$LDAP_ID" '$u != "" and .attributes.LDAP_ID == [$u] and .federationLink == $l' >/dev/null \
  || { echo "FAIL: admin not linked by its LLDAP uuid: $(kc "/users/$ADMIN_ID" | jq -c '[.federationLink, .attributes.LDAP_ID]')"; exit 1; }
lg 'mutation { createUser(user: {id: "same-name", email: "same-name@portcullis.local"}) { id } }'
U1=$(luuid same-name)
K1=$(kc "/users?username=same-name&exact=true" | jq -r '.[0].id // empty')
[ -n "$U1" ] && [ -n "$K1" ] || { echo "FAIL: same-name not imported"; exit 1; }
kc "/users/$K1" | jq -e --arg u "$U1" '.attributes.LDAP_ID == [$u]' >/dev/null || { echo "FAIL: same-name not linked by its LLDAP uuid"; exit 1; }
# A Keycloak-side grant on the old copy stands for its local state.
kcjson() { curl -sf -X POST -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") -H 'Content-Type: application/json' -d @- "http://127.0.0.1:8080/admin/realms/portcullis$1"; }
echo '{"name": "ci-same-name-marker"}' | kcjson /roles >/dev/null || { echo "FAIL: create the marker role"; exit 1; }
kc /roles/ci-same-name-marker | jq -c '[.]' | kcjson "/users/$K1/role-mappings/realm" >/dev/null || { echo "FAIL: grant the marker role"; exit 1; }
lg 'mutation { deleteUser(userId: "same-name") { ok } }'
lg 'mutation { createUser(user: {id: "same-name", email: "same-name@portcullis.local"}) { id } }'
U2=$(luuid same-name)
[ -n "$U2" ] && [ "$U2" != "$U1" ] || { echo "FAIL: LLDAP gave the re-created account the same uuid ($U1 / $U2)"; exit 1; }
kcpost "/user-storage/$LDAP_ID/sync?action=triggerFullSync" >/dev/null || { echo "FAIL: full sync"; exit 1; }
K2=$(kc "/users?username=same-name&exact=true" | jq -r '.[0].id // empty')
[ -n "$K2" ] && [ "$K2" != "$K1" ] || { echo "FAIL: the re-created same-name kept Keycloak id $K1 (got '$K2')"; exit 1; }
[ "$(kcstatus "/users/$K1")" = 404 ] || { echo "FAIL: Keycloak kept the old same-name copy $K1"; exit 1; }
kc "/users/$K2" | jq -e --arg u "$U2" '.attributes.LDAP_ID == [$u]' >/dev/null || { echo "FAIL: re-created same-name not linked by its new uuid"; exit 1; }
[ "$(kc "/users?briefRepresentation=true&max=1000" | jq '[.[] | select(.username == "same-name")] | length')" = 1 ] \
  || { echo "FAIL: same-name duplicated in Keycloak"; exit 1; }
kc "/users/$K2/role-mappings/realm" | jq -e 'all(.[]?; .name != "ci-same-name-marker")' >/dev/null \
  || { echo "FAIL: the re-created same-name inherited the old copy's grant"; exit 1; }
curl -sf -X DELETE -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") http://127.0.0.1:8080/admin/realms/portcullis/roles/ci-same-name-marker \
  || { echo "FAIL: delete the marker role"; exit 1; }
lg 'mutation { deleteUser(userId: "same-name") { ok } }'
[ "$(kcstatus "/users/$K2")" = 404 ] || { echo "FAIL: Keycloak kept same-name after its deletion"; exit 1; }

# Core's own accounts are untouched: LLDAP's admin + testuser and
# their groups in Keycloak, the Hub's service account in LLDAP (and
# never in Keycloak), the master realm's admin.
for id in "$ADMIN_ID" "$TEST_ID"; do
  [ "$(kcstatus "/users/$id")" = 200 ] || { echo "FAIL: Keycloak user $id (admin / testuser) removed"; exit 1; }
done
kcgroup lldap_admin || { echo "FAIL: lldap_admin dropped"; exit 1; }
[ "$(lq '{ user(userId: "portcullis-hub") { id } }' | jq -r '.data.user.id // empty')" = "$HUB_SA" ] || { echo "FAIL: the Hub's service account changed in LLDAP"; exit 1; }
lq '{ user(userId: "admin") { id } }' | jq -e '.data.user.id == "admin"' >/dev/null || { echo "FAIL: LLDAP admin gone"; exit 1; }
[ "$(kc "/users?username=portcullis-hub&exact=true" | jq length)" = 0 ] || { echo "FAIL: the Hub's service account is in Keycloak"; exit 1; }
[ -n "$(tok)" ] && [ "$(tok)" != null ] || { echo "FAIL: master admin can't sign in"; exit 1; }
echo "PASS: users and groups deleted in LLDAP leave Keycloak (group at sync, user at lookup); a re-created name is a new Keycloak identity (entryUUID); LLDAP outage removes nothing; core's accounts kept"
