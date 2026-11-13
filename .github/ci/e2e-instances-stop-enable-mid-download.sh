#!/usr/bin/env bash
# ci.yml job e2e-instances, step "Stop an enable mid-download (stop_enable_mid_pull)".
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
source tests/e2e/hubop.sh
ID=slowpull PROJECT=portcullis-slowpull
IMG="$(sed -n 's/^ *image: //p' tests/e2e/apps/slowpull/compose.yml)"
KC_TOKEN=$(printf '%s' "$KEYCLOAK_ADMIN_PASSWORD" | curl -sf http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  --data-urlencode client_id=admin-cli --data-urlencode "username=$KEYCLOAK_ADMIN" \
  --data-urlencode grant_type=password --data-urlencode password@- | jq -r .access_token)
[ -z "$KC_TOKEN" ] || [ "$KC_TOKEN" = null ] || echo "::add-mask::$KC_TOKEN"
kc_clients() { curl -sf -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") \
                 "http://127.0.0.1:8080/admin/realms/portcullis/clients?clientId=$1" | jq length; }
LLDAP_TOKEN=$(jq -n '{username: "admin", password: env.LLDAP_ADMIN_PASSWORD}' \
  | curl -sf http://127.0.0.1:17170/auth/simple/login -H 'Content-Type: application/json' -d @- | jq -r .token)
[ -z "$LLDAP_TOKEN" ] || [ "$LLDAP_TOKEN" = null ] || echo "::add-mask::$LLDAP_TOKEN"
lldap_groups() { jq -n '{query: "{ groups { displayName } }"}' | curl -sf http://127.0.0.1:17170/api/graphql \
                   -H @<(printf 'Authorization: Bearer %s\n' "$LLDAP_TOKEN") -H 'Content-Type: application/json' -d @- \
                   | jq -c '[.data.groups[].displayName]'; }

# Before: the template is loaded, its default instance never ran
# (not listed: no record, not enabled), the image absent (else the
# pull is instant and the test vacuous).
hub GET /api/templates | jq -e --arg id "$ID" 'any(.[]; .id == $id)' >/dev/null \
  || { echo "FAIL: the Hub did not load the CI template $ID: $(hub GET /api/templates | jq -c '[.[].id]')"; exit 1; }
hub GET /api/instances | jq -e --arg id "$ID" 'all(.[]; .id != $id)' >/dev/null \
  || { echo "FAIL: $ID before the enable: $(hub GET /api/instances | jq -c --arg id "$ID" '.[] | select(.id == $id)')"; exit 1; }
if docker image inspect "$IMG" >/dev/null 2>&1; then echo "FAIL: $IMG is already on the runner"; exit 1; fi
[ "$(kc_clients "$ID")" = 0 ] || { echo "FAIL: a Keycloak client $ID exists before the enable"; exit 1; }

# The enable, until its images step runs; then Stop.
hubop_start POST /api/templates/enable -d "{\"id\":\"$ID\"}"
jq -e --arg id "$ID" '.op == "enable" and .instance == $id' /tmp/hub.out >/dev/null || { echo "FAIL: 202 body $(cat /tmp/hub.out)"; exit 1; }
t0=$SECONDS
for i in $(seq 1 600); do
  hub GET "$HUBOP_POLL" --max-time 30 > /tmp/op.json || true
  jq -e --arg o "$HUBOP_ID" '.op_id == $o and any(.steps[]?; .key == "images" and .state == "running")' /tmp/op.json >/dev/null 2>&1 && break
  if jq -e --arg o "$HUBOP_ID" '.op_id == $o and (.running | not)' /tmp/op.json >/dev/null 2>&1; then
    echo "FAIL: the enable ended before its images step ran:"; hubop_explain; exit 1
  fi
  [ "$i" = 600 ] && { echo "FAIL: images not running after 300 s:"; hubop_explain; exit 1; }
  sleep 0.5
done
echo "images running after $((SECONDS - t0)) s: $(jq -c '{stoppable, created, images: [.steps[] | select(.key == "images")][0]}' /tmp/op.json)"
code=$(hubc POST "/api/instances/$ID/op/stop" -d "{\"op_id\":\"$HUBOP_ID\"}")
[ "$code" = 202 ] || { echo "FAIL: Stop: HTTP $code $(head -c 1500 /tmp/hub.out)"; exit 1; }
jq -e --arg o "$HUBOP_ID" '.op_id == $o and .stopping == true' /tmp/hub.out >/dev/null \
  || { echo "FAIL: the Stop's answer is not the stopping record: $(head -c 1500 /tmp/hub.out)"; exit 1; }
echo "Stop accepted $((SECONDS - t0)) s after the enable"
# Still downloading when the Stop was accepted (not a vacuous Stop).
if docker image inspect "$IMG" >/dev/null 2>&1; then echo "FAIL: $IMG finished downloading before the Stop"; exit 1; fi

# The record ends stopped: not running, not ok, no error, stopped_by.
hubop_end "$HUBOP_POLL" "$HUBOP_ID" 300 || exit 1
cp /tmp/op.json /tmp/op-stopped.json
# Booleans are left out when false: a missing one reads as false.
jq -e '.op == "enable" and .ok == false and (.error // "") == "" and .stopped_by == "admin" and .stopped_at != null
    and (.stopping // false) == false and (.stoppable // false) == false' /tmp/op.json >/dev/null \
  || { echo "FAIL: the record didn't end stopped:"; hubop_explain; exit 1; }
echo "stopped after $((SECONDS - t0)) s: $(jq -c '{created, steps: [.steps[] | {key, state}]}' /tmp/op.json)"

# Nothing the enable made is left.
left="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")"
[ -z "$left" ] || { echo "FAIL: containers of $PROJECT left: $(docker ps -a --filter "label=com.docker.compose.project=$PROJECT")"; exit 1; }
for v in $(jq -r '.created.volumes[]?' /tmp/op.json); do
  if docker volume inspect "$v" >/dev/null 2>&1; then echo "FAIL: volume $v (created by the enable) left"; exit 1; fi
done
vols="$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT")"
[ -z "$vols" ] || { echo "FAIL: volumes of $PROJECT left: $vols"; exit 1; }
jq -e --arg id "$ID" '.created.keycloak_clients | index($id) != null' /tmp/op.json >/dev/null \
  || { echo "FAIL: the enable's ledger has no Keycloak client $ID (stopped too early?): $(jq -c .created /tmp/op.json)"; exit 1; }
for c in $(jq -r '.created.keycloak_clients[]?' /tmp/op.json); do
  [ "$(kc_clients "$c")" = 0 ] || { echo "FAIL: Keycloak client $c (created by the enable) left"; exit 1; }
done
jq -e '.created.groups | length > 0' /tmp/op.json >/dev/null \
  || { echo "FAIL: the enable's ledger has no groups: $(jq -c .created /tmp/op.json)"; exit 1; }
GROUPS_NOW="$(lldap_groups)"
[ -n "$GROUPS_NOW" ] || { echo "FAIL: LLDAP groups unreadable"; exit 1; }
for g in $(jq -r '.created.groups[]?' /tmp/op.json); do
  echo "$GROUPS_NOW" | jq -e --arg g "$g" 'index($g) == null' >/dev/null || { echo "FAIL: group $g (created by the enable) left in LLDAP"; exit 1; }
done
hub GET /api/instances | jq -e --arg id "$ID" 'any(.[]; .id == $id and .state == "disabled")' >/dev/null \
  || { echo "FAIL: $ID after the Stop: $(hub GET /api/instances | jq -c --arg id "$ID" '.[] | select(.id == $id)')"; exit 1; }
# The Stop's audit names the step it stopped (images).
hub GET /api/directory/audit | jq -e --arg id "$ID" 'any(.[]; .action == "enable.stop" and .result == "ok" and .actor == "admin"
    and ((.target // "") | split("/")[0]) == $id and .detail == "images")' >/dev/null \
  || { echo "FAIL: no enable.stop in the audit: $(hub GET /api/directory/audit | jq -c --arg id "$ID" '[.[] | select((.target // "") | startswith($id))]')"; exit 1; }
echo "PASS: stop_enable_mid_pull: the enable stopped during images; no containers, volumes, Keycloak client $(jq -c .created.keycloak_clients /tmp/op.json) or groups $(jq -c .created.groups /tmp/op.json) left; $ID disabled; enable.stop audited"

# Cleanup: no half-pulled image (a later run must pull it again).
docker image rm -f "$IMG" "${IMG%@*}" >/dev/null 2>&1 || true
