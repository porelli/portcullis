#!/usr/bin/env bash
# ci.yml job e2e-vpn, step "Instances, users, the headscale provider (through the Hub's API), setup links".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
set -o pipefail
SECRET="$(grep '^HUB_PROXY_SECRET=' .env | cut -d= -f2-)"; echo "::add-mask::$SECRET"
echo "E2E_HUB_SECRET=$SECRET" >> "$GITHUB_ENV"
hub() { local m="$1" p="$2"; shift 2
        curl -s -X "$m" -H @<(printf 'X-Portcullis-Proxy-Secret: %s\nX-Forwarded-User: admin\n' "$SECRET") \
          -H 'Content-Type: application/json' "$@" "http://$HUB_IP:8888$p"; }
hubc() { hub "$@" -o /tmp/hub.out -w '%{http_code}'; }
source tests/e2e/hubop.sh
for i in $(seq 1 30); do
  hub GET /api/templates | jq -e '[.[].id] as $ids | ["echo", "headscale"] - $ids == []' >/dev/null 2>&1 && break
  [ "$i" -eq 30 ] && { echo "FAIL: the Hub did not load echo and headscale: $(hub GET /api/templates | head -c 400)"; docker compose logs --tail=60 hub; exit 1; }
  sleep 2
done
hubop POST /api/instances -d '{"template":"echo","id":"echo-vpn","label":"VPN echo","hosts":{"echo":"echo-vpn.portcullis.local"}}' \
  || { echo "FAIL: create echo-vpn"; exit 1; }
hubop POST /api/instances -d '{"template":"headscale","id":"headscale","label":"Tailnet","hosts":{"headscale":"vpn.portcullis.local","headplane":"vpn-admin.portcullis.local"}}' \
  || { echo "FAIL: create headscale"; exit 1; }
LLDAP_TOKEN=$(jq -n '{username: "admin", password: env.LLDAP_ADMIN_PASSWORD}' \
  | curl -sf http://127.0.0.1:17170/auth/simple/login -H 'Content-Type: application/json' -d @- | jq -r .token)
echo "::add-mask::$LLDAP_TOKEN"
gql() { jq -n --arg q "$1" '{query: $q}' | curl -sf http://127.0.0.1:17170/api/graphql \
          -H @<(printf 'Authorization: Bearer %s\n' "$LLDAP_TOKEN") -H 'Content-Type: application/json' -d @-; }
# carol: an LLDAP administrator, for the break-glass case (an admin
# surface on websecure after vpn mode apps with the Hub down).
for u in alice bob carol; do
  gql "mutation { createUser(user: {id: \"$u\", email: \"$u@portcullis.local\"}) { id } }" | jq -e '.errors == null' >/dev/null
done
GROUPS_JSON="$(gql '{ groups { id displayName } }')"
for m in alice:users_echo-vpn bob:users_echo-vpn alice:users_headscale carol:lldap_admin; do
  gid=$(echo "$GROUPS_JSON" | jq -r --arg g "${m#*:}" '.data.groups[] | select(.displayName == $g) | .id')
  [ -n "$gid" ] || { echo "FAIL: the Hub did not create ${m#*:}"; exit 1; }
  gql "mutation { addUserToGroup(userId: \"${m%%:*}\", groupId: $gid) { ok } }" | jq -e '.errors == null' >/dev/null
done
for id in echo-vpn headscale; do
  hubop POST /api/templates/enable -d "{\"id\":\"$id\"}" || { echo "FAIL: enable $id"; exit 1; }
done
# Headscale's API key (the identity and DNS hooks, the gateway's
# pre-auth key): created in the container, never printed, kept in a
# 0600 file for the test's restore.
umask 077
for i in $(seq 1 30); do
  docker exec portcullis-headscale-headscale-1 headscale apikeys create --expiration 1d > "$RUNNER_TEMP/hs-api-key" 2>/dev/null && break
  [ "$i" -eq 30 ] && { echo "FAIL: headscale apikeys create"; docker logs --tail=40 portcullis-headscale-headscale-1; exit 1; }
  sleep 3
done
KEY="$(tail -n1 "$RUNNER_TEMP/hs-api-key")"; echo "::add-mask::$KEY"
printf '%s\n' "$KEY" > "$RUNNER_TEMP/hs-api-key"
echo "E2E_HS_API_KEY_FILE=$RUNNER_TEMP/hs-api-key" >> "$GITHUB_ENV"
# A secret setting: the Hub's secrets form (contract §13.12), on stdin only.
T_PUT="$(date -u +%s)"
KEY="$KEY" jq -n '{secrets: {api_key: {value: env.KEY}}}' | hubc PUT /api/instances/headscale/settings -d @- > /tmp/code
case "$(cat /tmp/code)" in 200|202) ;; *) echo "FAIL: headscale api_key: $(cat /tmp/code) $(cat /tmp/hub.out)"; exit 1 ;; esac
code=$(hubc PUT /api/instances/headscale/vpn-provider -d '{"wired": true, "refresh": "15s"}')
case "$code" in 200|202) ;; *) echo "FAIL: wire headscale: $code $(cat /tmp/hub.out)"; exit 1 ;; esac
# Settle before the setup links are spent (the browser runs next): the
# Hub restarts headscale for the new API key (applies: restart) and
# attaches the gateway in the background, and a container start or
# network attach on the runner makes Chromium abort in-flight requests
# (net::ERR_NETWORK_CHANGED; a setup link can't be retried).
for i in $(seq 1 60); do
  read -r started running < <(docker inspect -f '{{.State.StartedAt}} {{.State.Running}}' portcullis-headscale-headscale-1)
  [ "$running" = true ] && [ "$(date -u -d "$started" +%s)" -ge "$T_PUT" ] && break
  [ "$i" -eq 60 ] && { echo "FAIL: headscale wasn't restarted for its API key"; docker logs --tail=30 portcullis-headscale-headscale-1; exit 1; }
  sleep 3
done
for i in $(seq 1 80); do
  hub GET /api/vpn | jq -e 'any(.providers[]; .id == "headscale" and .wired and (.stale | not))' >/dev/null && break
  [ "$i" -eq 80 ] && { echo "FAIL: headscale's map isn't fresh: $(hub GET /api/vpn | jq -c .providers)"; exit 1; }
  sleep 3
done
# 60 s, not 20: on main run 43527815385 headscale's gateway exited and
# restarted on its own ~40 s after a 20 s quiet window (during bob's
# sign-in). setup_link_signin retries once with a new link if one is hit.
for i in $(seq 1 100); do
  n="$(docker events --since 60s --until "$(date +%s)" --filter event=start --filter event=connect --format '{{.Type}} {{.Action}} {{.Actor.Attributes.name}}' | wc -l)"
  [ "$n" -eq 0 ] && break
  [ "$i" -eq 100 ] && { echo "FAIL: the engine never went 60 s without a container start or network attach"; exit 1; }
  sleep 3
done
hub GET /api/vpn | jq -c '{mode, wg, providers: [.providers[] | {id, wired, stale, devices}]}'
for spec in "E2E_ALICE_INVITE alice" "E2E_BOB_INVITE bob" "E2E_CAROL_INVITE carol"; do
  read -r var who <<<"$spec"
  url="$(./portcullis invite "$who" --to portal --json | jq -r .url)"
  [ -z "$url" ] || [ "$url" = null ] || echo "::add-mask::$url"
  [[ "$url" =~ ^https://enroll\.portcullis\.local/invite/[A-Za-z0-9_-]{43}$ ]] || { echo "FAIL: setup link for $who"; exit 1; }
  echo "$var=$url" >> "$GITHUB_ENV"
done
