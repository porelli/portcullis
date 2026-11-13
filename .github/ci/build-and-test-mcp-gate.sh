#!/usr/bin/env bash
# ci.yml job build-and-test, step "Test the MCP gate (non-root, pinned address, secrets, access log, MCP routes without forward-auth)".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
set -o pipefail
ALPINE=docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
# The CLI of the image: usage on a bad command (exit 2), keygen
# prints one identity with its recipient (never kept here).
rc=0; docker run --rm --network none --read-only --cap-drop ALL portcullis-mcp-gate --help 2>/tmp/gate-help >/dev/null || rc=$?
if [ "$rc" != 2 ] || ! grep -q 'usage: mcp-gate \[serve|keygen|healthcheck\]' /tmp/gate-help; then
  echo "FAIL: mcp-gate --help (rc=$rc): $(cat /tmp/gate-help)"; exit 1
fi
docker run --rm --network none --read-only --cap-drop ALL portcullis-mcp-gate keygen \
  | awk '/^# public key: age1[0-9a-z]+$/ {p++} /^AGE-SECRET-KEY-1[0-9A-Z]+$/ {k++} END {exit !(p == 1 && k == 1)}' \
  || { echo "FAIL: mcp-gate keygen"; exit 1; }
rc=0; docker run --rm --network none --read-only --cap-drop ALL portcullis-mcp-gate healthcheck || rc=$?
[ "$rc" = 1 ] || { echo "FAIL: healthcheck without a running gate exited $rc"; exit 1; }
# Secrets made by ./portcullis (mcpgate_ensure_secrets): modes, groups, recipient = the key's.
test "$(stat -c '%a' secrets/mcp-gate)" = 700 || { echo "FAIL: secrets/mcp-gate is not 0700"; exit 1; }
for f in age.key:10005 age.pub:10001 hub-secret:10001; do
  test "$(stat -c '%a %g' "secrets/mcp-gate/${f%%:*}")" = "640 ${f#*:}" || { echo "FAIL: secrets/mcp-gate/${f%%:*}: $(stat -c '%a %g' "secrets/mcp-gate/${f%%:*}")"; exit 1; }
done
grep -qx "# public key: $(cat secrets/mcp-gate/age.pub)" secrets/mcp-gate/age.key || { echo "FAIL: age.pub is not age.key's recipient"; exit 1; }
[ "$(tr -d '\n' < secrets/mcp-gate/hub-secret | wc -c)" = 48 ] || { echo "FAIL: hub-secret is not 48 characters"; exit 1; }
if ! grep -qx 'PORTCULLIS_MCP_GATE_IP=172.31.250.3' secrets/hub/core.env || grep -q 'MCP.*SECRET' secrets/hub/core.env; then
  echo "FAIL: core.env lacks PORTCULLIS_MCP_GATE_IP (or carries a gate secret)"; exit 1
fi

docker compose up -d mcp-gate
for i in $(seq 1 40); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q mcp-gate)")" = healthy ] && break
  [ "$i" -eq 40 ] && { echo "FAIL: mcp-gate not healthy"; docker compose logs --tail=40 mcp-gate; exit 1; }
  sleep 3
done
CID="$(docker compose ps -q mcp-gate)"
docker inspect "$CID" | jq -e '.[0] as $c
    | $c.Config.User == "10005:10005" and $c.HostConfig.GroupAdd == ["10001"]
    and $c.HostConfig.ReadonlyRootfs == true and $c.HostConfig.CapDrop == ["ALL"]
    and ($c.HostConfig.SecurityOpt | index("no-new-privileges:true")) != null
    and ($c.HostConfig.Privileged | not)
    and ([$c.Mounts[] | select(.Source | test("docker\\.sock"))] == [])
    and ($c.NetworkSettings.Networks | keys | sort) == ["portcullis-mcp", "portcullis-proxy"]
    and $c.NetworkSettings.Networks["portcullis-proxy"].IPAddress == "172.31.250.3"
    and ($c.HostConfig.PortBindings // {} | length) == 0' >/dev/null \
  || { echo "FAIL: mcp-gate container (user, group 10001 only, read-only, caps, socket, networks, address)"; exit 1; }
[ "$(docker exec "$CID" id -G)" = "10005 10001" ] || { echo "FAIL: mcp-gate groups: $(docker exec "$CID" id -G)"; exit 1; }
# portcullis-mcp: exactly the gate, Keycloak and the Hub; the gate
# reaches Keycloak's JWKS (and resolves hub) there, and no other core service.
docker network inspect portcullis-mcp | jq -e '.[0].Internal == true and .[0].IPAM.Config[0].Subnet == "172.31.253.0/28"' >/dev/null \
  || { echo "FAIL: portcullis-mcp network (internal, subnet)"; exit 1; }
# keycloak / hub come from /etc/hosts (extra_hosts), pinned to their
# portcullis-mcp addresses, which really are theirs.
docker exec "$CID" cat /etc/hosts > /tmp/gate-hosts
if ! grep -qE '^172\.31\.253\.2[[:space:]]+keycloak$' /tmp/gate-hosts || ! grep -qE '^172\.31\.253\.3[[:space:]]+hub$' /tmp/gate-hosts; then
  echo "FAIL: the gate's /etc/hosts lacks the pinned keycloak / hub:"; cat /tmp/gate-hosts; exit 1
fi
for s in keycloak:172.31.253.2 hub:172.31.253.3; do
  got="$(docker inspect -f '{{(index .NetworkSettings.Networks "portcullis-mcp").IPAddress}}' "$(docker compose ps -q "${s%%:*}")")"
  [ "$got" = "${s#*:}" ] || { echo "FAIL: ${s%%:*} is $got on portcullis-mcp (pinned ${s#*:})"; exit 1; }
done
docker exec "$CID" wget -q -T 5 -O /dev/null http://keycloak:8080/realms/portcullis/protocol/openid-connect/certs \
  || { echo "FAIL: the gate can't read Keycloak's JWKS over portcullis-mcp"; exit 1; }
# No other core service is reachable by name from the gate.
for other in lldap vault postgres group-gate enroll domains forward-auth socket-proxy-hub; do
  if out="$(docker exec "$CID" nslookup "$other" 2>&1)"; then
    echo "FAIL: the gate resolves $other (it must reach only Keycloak and the Hub): $out"; exit 1
  fi
done
if docker exec "$CID" sh -c 'touch /x' 2>/dev/null; then echo "FAIL: mcp-gate rootfs is writable"; exit 1; fi
docker exec "$CID" mcp-gate healthcheck || { echo "FAIL: mcp-gate healthcheck in the container"; exit 1; }
# G29: the access log and its directory (gate-owned, group 10001: the Hub's read-only mount).
docker run --rm -v portcullis_mcp_gate_data:/d:ro "$ALPINE" stat -c '%n %a %u %g' /d /d/access.jsonl > /tmp/gate-log-mode
[ "$(cat /tmp/gate-log-mode)" = "$(printf '/d 750 10005 10001\n/d/access.jsonl 640 10005 10001')" ] \
  || { echo "FAIL: access log modes: $(cat /tmp/gate-log-mode)"; exit 1; }

# Through Traefik: no MCP route runs forward-auth (no sign-in
# redirect, no cookie), the gate answers (no mcp-gate.json yet: AI
# support off), hub.<d>/mcp and people.<d>/mcp outrank the Hub's
# forward-auth routers, every other path of those hosts doesn't
# reach the gate.
mcp_req() { curl -s -o /tmp/mcp-body -D /tmp/mcp-hdr -w '%{http_code}' --cacert certs/ca-chain.crt \
              --resolve "$1:443:127.0.0.1" "${@:3}" "https://$1$2" || true; }
for t in mcp.portcullis.local/mcp mcp.portcullis.local/.well-known/oauth-protected-resource/mcp \
         hub.portcullis.local/mcp hub.portcullis.local/.well-known/oauth-protected-resource/mcp \
         people.portcullis.local/mcp people.portcullis.local/.well-known/oauth-protected-resource/mcp; do
  code="$(mcp_req "${t%%/*}" "/${t#*/}" -X POST -H 'Content-Type: application/json' -H 'Cookie: _oauth2_proxy=x' --data '{}')"
  [ "${t#*/}" = mcp ] || code="$(mcp_req "${t%%/*}" "/${t#*/}")"
  if [ "$code" != 503 ] || ! grep -q 'AI support is off' /tmp/mcp-body; then
    echo "FAIL: https://$t → $code (want the gate's 503 'AI support is off'): $(head -c 300 /tmp/mcp-body)"; cat /tmp/mcp-hdr; exit 1
  fi
  if grep -qi '^set-cookie:' /tmp/mcp-hdr; then echo "FAIL: https://$t set a cookie"; exit 1; fi
done
for t in hub.portcullis.local/ hub.portcullis.local/mcp/x people.portcullis.local/ people.portcullis.local/.well-known/oauth-protected-resource; do
  code="$(mcp_req "${t%%/*}" "/${t#*/}")"
  if [ "$code" = 503 ] && grep -q 'AI support is off' /tmp/mcp-body; then echo "FAIL: https://$t reached the gate"; exit 1; fi
done
# To a file first: under pipefail, `logs | grep -q` fails when grep
# exits early and compose gets SIGPIPE.
docker compose logs mcp-gate > /tmp/mcp-gate.log 2>&1
grep -q 'mcp-gate: listening on :8080' /tmp/mcp-gate.log || { echo "FAIL: no listening line"; tail -20 /tmp/mcp-gate.log; exit 1; }
if grep -qE 'eyJ|AGE-SECRET-KEY|_oauth2_proxy' /tmp/mcp-gate.log; then echo "FAIL: a token, key or cookie in the gate's log"; exit 1; fi
# Refusals reach the access log (one line per request, decision deny:off).
docker run --rm -v portcullis_mcp_gate_data:/d:ro "$ALPINE" cat /d/access.jsonl > /tmp/gate-access.jsonl
jq -se 'length >= 3 and all(.decision == "deny:off" and .user == "" and .client == "")' /tmp/gate-access.jsonl >/dev/null \
  || { echo "FAIL: access log after the refused requests:"; cat /tmp/gate-access.jsonl; exit 1; }
if [ -n "$(docker compose ps -q hub)" ]; then
  docker compose exec -T hub sh -c 'test -r /run/portcullis/mcp-gate/hub-secret && test -r /run/portcullis/mcp-gate/age.pub && test -r /mcp-gate-data/access.jsonl && ! touch /mcp-gate-data/x 2>/dev/null' \
    || { echo "FAIL: the Hub's gate files (secret, recipient, read-only access log)"; exit 1; }
fi
echo "PASS: mcp-gate healthy as 10005 (+10001 only) at 172.31.250.3, read-only, secrets 0640 by group, access log 0640/0750 group 10001 read-only in the Hub, MCP routes reach the gate without forward-auth or cookies"
