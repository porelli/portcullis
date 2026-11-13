#!/usr/bin/env bash
# ci.yml job e2e-vpn, step "Start the whole stack (Hub with the echo / headscale template source), vpn init".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
set -o pipefail
docker compose up -d postgres lldap
./portcullis vault init
./portcullis pki setup --with-server-cert
./portcullis config apply --bundle-only
printf 'tls:\n  certificates:\n    - certFile: /certs/server.crt\n      keyFile: /certs/server.key\n' > traefik/dynamic/ci-certs.yml
docker volume create --label com.docker.compose.project=portcullis --label com.docker.compose.volume=hub_data portcullis_hub_data >/dev/null
docker run --rm -v portcullis_hub_data:/data -v "$PWD/tests/e2e/apps:/src:ro" -v "$RUNNER_TEMP/templates:/tpl:ro" "$ALPINE" sh -c '
  mkdir -p /data/repos/ci && cp -r /src/echo /tpl/headscale /data/repos/ci/ &&
  printf "sources:\n  - name: ci\n    url: \"\"\n    path: /data/repos/ci\n" > /data/state.yaml &&
  chown -R 10001:10001 /data && chmod 600 /data/state.yaml'
# shellcheck disable=SC2046
docker compose up -d $(docker compose config --services | grep -vxE 'hub|wg')
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
./portcullis vpn init
docker compose exec -T wg /wg status | jq -c '{edge, people: (.people | {ok, port, subnet})}'
echo "127.0.0.1 portcullis.local auth.portcullis.local enroll.portcullis.local hub.portcullis.local people.portcullis.local echo-vpn.portcullis.local vpn.portcullis.local vpn-admin.portcullis.local" | sudo tee -a /etc/hosts
