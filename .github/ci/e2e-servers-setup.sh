#!/usr/bin/env bash
# ci.yml jobs e2e-servers / e2e-servers-podman, step "Primary: the whole
# stack + Hub + link init" (multiple servers, contract §17). The primary on
# Docker: .env, the CI override (the Hub's dev hooks, its API on the
# runner, the virtual authenticator), the CI template source (echo), the
# stack, `./portcullis link init`, the admin's and alice's setup links.
# Run from the workspace root (bash -e). Writes HUB_IP, the setup links
# (masked) and the runner's address to $GITHUB_ENV.
set -euo pipefail
: "${E2E_DOMAIN:?}" "${ALPINE:?}" "${GITHUB_ENV:?}"

./portcullis init --env-only --runtime docker --non-interactive --domain "$E2E_DOMAIN" \
  --email "ci@$E2E_DOMAIN" --dns-provider none
for v in KEYCLOAK_ADMIN KEYCLOAK_ADMIN_PASSWORD LLDAP_ADMIN_PASSWORD; do
  val="$(grep "^$v=" .env | cut -d= -f2-)"
  [ "$v" = KEYCLOAK_ADMIN ] || echo "::add-mask::$val"
  echo "$v=$val" >> "$GITHUB_ENV"
done
# CI only: the Hub's dev hooks (an e2etest build: the clock offset for the
# expired join code, a file re-read live), Chromium's virtual authenticator as a security key,
# Keycloak's health port.
cat > docker-compose.ci.yml <<'YML'
services:
  hub:
    environment:
      HUB_DEV: "1"
      HUB_DEV_CLOCK_OFFSET_FILE: /data/dev-clock-offset
      HUB_SIGNIN_EXTRA_AUTHENTICATORS: /run/portcullis/signin/extra-authenticators.json
    volumes:
      - ./tests/e2e/fixtures/virtual-authenticators.json:/run/portcullis/signin/extra-authenticators.json:ro
  keycloak:
    ports:
      - "127.0.0.1:9000:9000"
  lldap:
    ports:
      - "127.0.0.1:17170:17170"
YML
docker compose config -q

docker compose up -d postgres lldap
./portcullis vault init
./portcullis pki setup --with-server-cert
./portcullis config apply --bundle-only
printf 'tls:\n  certificates:\n    - certFile: /certs/server.crt\n      keyFile: /certs/server.key\n' > traefik/dynamic/ci-certs.yml
# The Hub's only template source: the CI template echo (a local source).
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

# The link role (contract §17.2): wg with the tunnel the workers dial.
./portcullis link init
./portcullis link status --json | jq -e '.up and .port == 51821' >/dev/null \
  || { echo "FAIL: link status after link init: $(./portcullis link status --json)"; exit 1; }
# The address workers reach the primary's link port at (the runner's, not
# loopback: a dind or rootless worker has its own).
RUNNER_IP="$(ip -4 -o route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
[[ "$RUNNER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "FAIL: no runner address"; exit 1; }
echo "RUNNER_IP=$RUNNER_IP" >> "$GITHUB_ENV"

# People: the admin (the Hub API's actor, its fresh sign-ins) and alice
# (an echo user), each from a setup link; alice in users_<instance>.
SECRET="$(grep '^HUB_PROXY_SECRET=' .env | cut -d= -f2-)"; echo "::add-mask::$SECRET"
LLDAP_TOKEN=$(jq -n '{username: "admin", password: env.LLDAP_ADMIN_PASSWORD}' \
  | curl -sf http://127.0.0.1:17170/auth/simple/login -H 'Content-Type: application/json' -d @- | jq -r .token)
echo "::add-mask::$LLDAP_TOKEN"
jq -n --arg q 'mutation { createUser(user: {id: "alice", email: "alice@portcullis.local"}) { id } }' '{query: $q}' \
  | curl -sf http://127.0.0.1:17170/api/graphql -H @<(printf 'Authorization: Bearer %s\n' "$LLDAP_TOKEN") \
      -H 'Content-Type: application/json' -d @- | jq -e '.errors == null' >/dev/null
for who in admin:hub alice:portal; do
  url="$(./portcullis invite "${who%%:*}" --to "${who#*:}" --json | jq -r .url)"
  echo "::add-mask::$url"
  echo "E2E_$(printf '%s' "${who%%:*}" | tr '[:lower:]' '[:upper:]')_INVITE=$url" >> "$GITHUB_ENV"
done
echo "PASS: primary up (Hub at $HUB_IP, link on UDP 51821 at $RUNNER_IP), setup links for admin and alice"
