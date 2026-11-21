#!/usr/bin/env bash
# ci.yml job e2e-ssh, step "Start the whole stack, the people and the two SSH servers".
# The core stack + the Hub under test (same-named Hub branch), the CI
# template echo as the Hub's only source (never pulled), the people root
# (lldap_admin), alice, bob and carol, the groups ssh_web / ssh_deploy /
# ssh_admins (alice in ssh_web, bob in ssh_deploy), and two SSH servers on
# portcullis-proxy built from tests/e2e/sshd: web-1 (to be enrolled) and
# web-2 (to trust the CA by hand). Each gets the Hub image's own
# `portcullis` binary (root-owned 0755) and the CI CA as /ca.pem; the runner
# resolves web-1 / web-2.<domain> to them (/etc/hosts). Writes HUB_IP and
# the hosts' addresses to $GITHUB_ENV.
set -euo pipefail
: "${E2E_DOMAIN:?}" "${ALPINE:?}"

./portcullis vault init  # first: its stack_prepare gives LLDAP its key seed
docker compose up -d postgres lldap
./portcullis pki setup --with-server-cert
./portcullis config apply --bundle-only
printf 'tls:\n  certificates:\n    - certFile: /certs/server.crt\n      keyFile: /certs/server.key\n' > traefik/dynamic/ci-certs.yml
docker volume create --label com.docker.compose.project=portcullis --label com.docker.compose.volume=hub_data portcullis_hub_data >/dev/null
docker run --rm -v portcullis_hub_data:/data -v "$PWD/tests/e2e/apps:/src:ro" "$ALPINE" sh -c '
  mkdir -p /data/repos/ci && cp -r /src/echo /data/repos/ci/ &&
  printf "sources:\n  - name: ci\n    url: \"\"\n    path: /data/repos/ci\n" > /data/state.yaml &&
  chown -R 10001:10001 /data && chmod 600 /data/state.yaml'
# shellcheck disable=SC2046
docker compose up -d $(docker compose config --services | grep -vx hub)
for i in $(seq 1 100); do
  curl -sf http://127.0.0.1:9000/health/ready >/dev/null && break
  [ "$i" -eq 100 ] && { echo "FAIL: Keycloak not ready"; docker compose logs --tail=80 keycloak; exit 1; }
  sleep 3
done
./portcullis keycloak configure
./portcullis oidc register
./portcullis up
docker compose restart forward-auth forward-auth-ext
HUB_IP=$(docker inspect -f '{{(index .NetworkSettings.Networks "portcullis").IPAddress}}' "$(docker compose ps -q hub)")
echo "HUB_IP=$HUB_IP" >> "$GITHUB_ENV"
for i in $(seq 1 40); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://$HUB_IP:8888/healthz")" = 200 ] && break
  [ "$i" -eq 40 ] && { echo "FAIL: hub /healthz"; docker compose logs --tail=40 hub; exit 1; }
  sleep 2
done

# People and groups, with the Hub's own LLDAP service account.
LLDAP_TOKEN=$(jq -n --rawfile u secrets/hub/lldap/username --rawfile p secrets/hub/lldap/password \
    '{username: ($u | rtrimstr("\n")), password: ($p | rtrimstr("\n"))}' \
  | curl -sf http://127.0.0.1:17170/auth/simple/login -H 'Content-Type: application/json' -d @- | jq -r .token)
[ -n "$LLDAP_TOKEN" ] && [ "$LLDAP_TOKEN" != null ] || { echo "FAIL: LLDAP login as the Hub's service account"; exit 1; }
echo "::add-mask::$LLDAP_TOKEN"
gql() { jq -n --arg q "$1" '{query: $q}' | curl -sf http://127.0.0.1:17170/api/graphql \
          -H @<(printf 'Authorization: Bearer %s\n' "$LLDAP_TOKEN") -H 'Content-Type: application/json' -d @-; }
for u in root alice bob carol; do
  gql "mutation { createUser(user: {id: \"$u\", email: \"$u@$E2E_DOMAIN\"}) { id } }" | jq -e '.errors == null' >/dev/null
done
for g in ssh_web ssh_deploy ssh_admins; do
  gql "mutation { createGroup(name: \"$g\") { id } }" | jq -e '.errors == null' >/dev/null
done
gid() { gql '{ groups { id displayName } }' | jq -r --arg n "$1" '.data.groups[] | select(.displayName == $n) | .id'; }
for m in root:lldap_admin alice:ssh_web bob:ssh_deploy; do
  gql "mutation { addUserToGroup(userId: \"${m%%:*}\", groupId: $(gid "${m#*:}")) { ok } }" | jq -e '.errors == null' >/dev/null
done
unset LLDAP_TOKEN

# The two SSH servers.
docker build -q -t portcullis-e2e-sshd tests/e2e/sshd >/dev/null
cid="$(docker create "$(docker compose config --format json | jq -r .services.hub.image)")"
docker cp "$cid:/usr/local/bin/portcullis" "$RUNNER_TEMP/portcullis"
docker rm "$cid" >/dev/null
"$RUNNER_TEMP/portcullis" version
for h in web-1 web-2; do
  docker rm -f "e2e-$h" >/dev/null 2>&1 || true
  docker run -d --name "e2e-$h" --hostname "$h.$E2E_DOMAIN" --network portcullis-proxy portcullis-e2e-sshd >/dev/null
  docker cp "$RUNNER_TEMP/portcullis" "e2e-$h:/usr/local/bin/portcullis"
  docker cp certs/ca-chain.crt "e2e-$h:/ca.pem"
  docker exec "e2e-$h" sh -c 'chown root:root /usr/local/bin/portcullis /ca.pem && chmod 0755 /usr/local/bin/portcullis && chmod 0644 /ca.pem'
  ip="$(docker inspect -f '{{(index .NetworkSettings.Networks "portcullis-proxy").IPAddress}}' "e2e-$h")"
  [ -n "$ip" ] || { echo "FAIL: e2e-$h has no portcullis-proxy address"; exit 1; }
  echo "$ip $h.$E2E_DOMAIN" | sudo tee -a /etc/hosts >/dev/null
  echo "E2E_$(printf %s "${h//-/_}" | tr "[:lower:]" "[:upper:]")_IP=$ip" >> "$GITHUB_ENV"
done
# web-2 is unmanaged: its person account is the operator's (alice), made
# by hand, as on any host that only trusts the CA.
docker exec e2e-web-2 useradd -m -s /bin/bash alice
echo "PASS: the stack, the people and the two SSH servers are up"
