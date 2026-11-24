#!/usr/bin/env bash
# ci.yml job e2e-mail, step "Start the whole stack, team-b.test, mail on".
# Runs from the workspace root with GitHub's default shell behaviour (bash -e).
#
# Nothing leaves the runner (user rule, P40, P41): outbound TCP 25 / 465 /
# 587 is rejected first (containers and the runner itself, except to the
# stack's own 172.16.0.0/12 networks); every DNS name the mail side asks
# for is answered by the one fake zone (the domains service's, shared with
# the dns tool and mail-cert through DOMAINS_FAKEDNS_REMOTE); the remote
# mail server (e2e-mail-remote.sh) is a container on the template's egress
# network (portcullis-stalwart_egress, pinned by the CI copy).
set -euo pipefail
CURL_IMG=docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93
EXTRA=team-b.test

PROJ=portcullis-stalwart
ALPINE=docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
cid() { docker ps -aq --filter "label=com.docker.compose.project=$PROJ" --filter "label=com.docker.compose.service=$1" | head -n1; }
fail() {
  echo "FAIL: $*"
  for s in bootstrap stalwart adapter resolver; do c="$(cid "$s")"; [ -z "$c" ] || { echo "--- $s"; docker logs --tail=40 "$c" 2>&1 | tail -n 40; }; done
  docker compose logs --tail=60 domains hub 2>/dev/null || true
  exit 1
}

# 1. Outbound SMTP never leaves (containers and the runner).
sudo iptables -I DOCKER-USER -p tcp -m multiport --dports 25,465,587 ! -d 172.16.0.0/12 -j REJECT --reject-with tcp-reset
# The runner itself: only to loopback (the published ports) and the
# stack's networks (the remote's 25 / 587); REJECT first, the two
# exceptions inserted above it.
sudo iptables -I OUTPUT -p tcp -m multiport --dports 25,465,587 -j REJECT --reject-with tcp-reset
sudo iptables -I OUTPUT -p tcp -m multiport --dports 25,465,587 -d 127.0.0.0/8 -j ACCEPT
sudo iptables -I OUTPUT -p tcp -m multiport --dports 25,465,587 -d 172.16.0.0/12 -j ACCEPT
sudo ip6tables -I FORWARD -p tcp -m multiport --dports 25,465,587 -j REJECT --reject-with tcp-reset
sudo ip6tables -I OUTPUT -p tcp -m multiport --dports 25,465,587 ! -d ::1/128 -j REJECT --reject-with tcp-reset
set +e
docker run --rm "$CURL_IMG" -s --connect-timeout 5 telnet://192.0.2.1:25 </dev/null; rc=$?
set -e
[ "$rc" = 7 ] || fail "outbound 25 from a container isn't refused (curl exit $rc)"
# Refused (rc 1: the REJECT's reset), never a timeout (124) or a connect.
set +e
timeout 5 bash -c 'exec 3<>/dev/tcp/192.0.2.1/25' 2>/dev/null; rc=$?
set -e
[ "$rc" = 1 ] || fail "outbound 25 from the runner: rc $rc (want 1: refused at once)"
echo "PASS: outbound TCP 25/465/587 rejected (containers and runner)"

# 2. The stack (as e2e-filesharing), Pebble's root for the domains service
# and mail-cert.
PEBBLE_IMG=$(docker compose config --format json | jq -r .services.pebble.image)
cid="$(docker create "$PEBBLE_IMG")"; docker cp "$cid:/test/certs/pebble.minica.pem" /tmp/pebble.minica.pem; docker rm "$cid" >/dev/null
chmod 644 /tmp/pebble.minica.pem
# The Hub's "portcullis" source before its first start: the templates
# checkout (stalwart: the adapter built here, the resolver on the fake DNS
# through the runner's :8053, egress pinned at 172.30.88.0/24 with stalwart
# at .2) plus the CI-only mail-fake, a local source (never pulled).
MAIL_CI_DNS_PROBE="$EXTRA" MAIL_CI_EGRESS="172.30.88.0/24 172.30.88.128/25 172.30.88.2" \
  bash .github/ci/mail-templates-checkout.sh "$RUNNER_TEMP/templates" "$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')"
docker volume create --label com.docker.compose.project=portcullis --label com.docker.compose.volume=hub_data portcullis_hub_data >/dev/null
docker run --rm --network none -v portcullis_hub_data:/data -v "$RUNNER_TEMP/templates:/tpl:ro" -v "$PWD/tests/e2e/apps:/src:ro" "$ALPINE" sh -c '
  mkdir -p /data/repos/portcullis &&
  cp -r /tpl/stalwart /src/mail-fake /data/repos/portcullis/ &&
  printf "sources:\n  - name: portcullis\n    url: \"\"\n    path: /data/repos/portcullis\n" > /data/state.yaml &&
  chown -R 10001:10001 /data && chmod 600 /data/state.yaml'
./portcullis vault init  # first: its stack_prepare gives LLDAP its key seed
docker compose up -d postgres lldap
./portcullis pki setup --with-server-cert
./portcullis config apply --bundle-only
printf 'tls:\n  certificates:\n    - certFile: /certs/server.crt\n      keyFile: /certs/server.key\n' > traefik/dynamic/ci-certs.yml
# shellcheck disable=SC2046
docker compose up -d $(docker compose config --services | grep -vx hub)
for i in $(seq 1 100); do
  curl -sf http://127.0.0.1:9000/health/ready >/dev/null && break
  [ "$i" -eq 100 ] && { docker compose logs --tail=80 keycloak; fail "Keycloak not ready"; }
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
  [ "$i" -eq 40 ] && { docker compose logs --tail=40 hub; fail "hub /healthz"; }
  sleep 2
done
# mail.<d> (no HTTPS router: Traefik's default TLS options) and the
# read-only admin view, for e2e_mail's admin_view_end_to_end.
echo "127.0.0.1 $E2E_DOMAIN auth.$E2E_DOMAIN enroll.$E2E_DOMAIN hub.$E2E_DOMAIN people.$E2E_DOMAIN mail.$E2E_DOMAIN mail-admin.$E2E_DOMAIN" | sudo tee -a /etc/hosts >/dev/null
SECRET="$(grep '^HUB_PROXY_SECRET=' .env | cut -d= -f2-)"; echo "::add-mask::$SECRET"
hub() { local m="$1" p="$2"; shift 2
        curl -s -X "$m" -H @<(printf 'X-Portcullis-Proxy-Secret: %s\nX-Forwarded-User: admin\n' "$SECRET") \
          -H 'Content-Type: application/json' "$@" "http://$HUB_IP:8888$p"; }

# 3. team-b.test on the domains service's API with the fake provider (the
# Hub refuses unknown providers); its records land in the shared zone.
DSECRET="$(cat secrets/domains/api-secret)"; echo "::add-mask::$DSECRET"
code=$(printf 'Authorization: Bearer %s\n' "$DSECRET" | docker run --rm -i --network portcullis_portcullis-domains "$CURL_IMG" -s -H @- \
  -H 'Content-Type: application/json' -o /dev/null -w '%{http_code}' -X PUT \
  -d '{"provider":"fake","credentials":{"api_token":"ci-fake-token-0123456789"}}' "http://domains:8080/domains/$EXTRA")
[ "$code" = 202 ] || fail "enroll $EXTRA got $code"
for i in $(seq 1 60); do
  st="$(hub GET /api/domains | jq -r --arg d "$EXTRA" '.[]? | select(.name == $d) | .state')"
  [ "$st" = ready ] && break
  [ "$i" -eq 60 ] && { docker compose logs --tail=60 domains pebble; fail "$EXTRA in the Hub: $(hub GET /api/domains)"; }
  sleep 3
done
echo "PASS: $EXTRA enrolled and ready in the Hub"

# 4. Mail on: mail-cert through the shared zone against Pebble (DNS-01),
# the resolver forwarding every name to the fake zone. The main domain's
# address / caa records too (dns-tool, the fake provider).
bash .github/ci/mail-enable-logged.sh stalwart /tmp/mail-enable.out || fail "mail enable"
# Pebble's issuing root (its management API): e2e_mail.py verifies mail's
# certificate chain against it (E2E_MAIL_CA, with the remote's).
docker run --rm --network portcullis_domains-egress -v /tmp/pebble.minica.pem:/ca.pem:ro "$CURL_IMG" \
  -sf --cacert /ca.pem https://pebble:15000/roots/0 > /tmp/e2e-pebble-root.pem
grep -q 'BEGIN CERTIFICATE' /tmp/e2e-pebble-root.pem || fail "Pebble's issuing root"
./portcullis dns setup --yes --only address
./portcullis dns setup --yes --only caa
for s in resolver stalwart adapter; do
  for i in $(seq 1 100); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$(cid "$s")" 2>/dev/null)" = healthy ] && break
    [ "$i" -eq 100 ] && fail "$s not healthy"
    sleep 3
  done
done
set +e
docker run --rm --network "${PROJ}_egress" "$CURL_IMG" -s --connect-timeout 5 telnet://192.0.2.1:25 </dev/null; rc=$?
set -e
[ "$rc" = 7 ] || fail "outbound 25 from the template's egress network isn't refused (curl exit $rc)"
echo "PASS: mail on: the stalwart template wired (resolver, stalwart, adapter healthy; its egress refuses outbound 25)"
