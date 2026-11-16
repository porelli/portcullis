#!/usr/bin/env bash
# ci.yml job e2e-podman, step "Mail on rootless Podman" (mail plan Task 12).
# Runs from the workspace root with GitHub's default shell behaviour (bash -e),
# after the Docker → Podman round trip (the stack is up, rt-person exists).
#
#   ip_unprivileged_port_start=25, then ./portcullis mail enable;
#   MAILCTL_CLIENT_IP=rewritten; the Hub's doctor names
#   mail_client_ip_rewritten; a message from a CI container to the host's
#   port 25 is delivered, and no BlockedIp appears (Review Focus 1: every
#   client is the gateway under rootless Podman, so a ban would lock
#   everyone out; Stalwart's ban events in its log).
#
# Nothing leaves the runner: outbound 25 / 465 / 587 is rejected for the
# runner and pasta (rootless Podman's egress is the user's own sockets);
# mail-cert's CA is a CI Pebble (always valid: the one-shot's fake zone is
# its own); mail-resolver forwards every name to the domains fake DNS.
set -euo pipefail
# shellcheck source=/dev/null
source "$RUNNER_TEMP/podlib.sh"
CURL_IMG=docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93
PEBBLE_IMG=ghcr.io/letsencrypt/pebble:2.10.1@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199
D="${E2E_DOMAIN:-portcullis.local}"
fail() { echo "FAIL: $*"; docker compose --profile mail logs --tail=60 mail mailctl mail-resolver 2>/dev/null || true; exit 1; }

# 1. No outbound SMTP (the runner, and pasta's sockets for the containers).
# Only to the host's own addresses (pasta turns a container's connection to
# host.containers.internal into a host socket to one of them).
for t in iptables ip6tables; do
  sudo "$t" -I OUTPUT -p tcp -m multiport --dports 25,465,587 -j REJECT --reject-with tcp-reset
  sudo "$t" -I OUTPUT -p tcp -m multiport --dports 25,465,587 -m addrtype --dst-type LOCAL -j ACCEPT
done
podman pull -q "$CURL_IMG" >/dev/null
set +e
podman run --rm "$CURL_IMG" -s --connect-timeout 5 telnet://192.0.2.1:25 </dev/null; rc=$?
set -e
[ "$rc" = 7 ] || fail "outbound 25 from a rootless container isn't refused (curl exit $rc)"
echo "PASS: outbound TCP 25/465/587 rejected (runner and rootless containers)"

# 2. Port 25 for the rootless user.
sudo sysctl -qw net.ipv4.ip_unprivileged_port_start=25

# 3. The CI pieces: the domains test build (provider fake), a Pebble for
# mail-cert (its TLS certificate from a throwaway CI CA), the CI resolver.
rm -rf /tmp/pebble-mail && mkdir -p /tmp/pebble-mail && (
  cd /tmp/pebble-mail
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=ci-pebble-mail-ca -keyout ca.key -out ca.pem 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=e2e-pebble-mail -keyout key.pem -out req.csr 2>/dev/null
  printf 'subjectAltName=DNS:e2e-pebble-mail\n' > ext.cnf
  openssl x509 -req -in req.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out cert.pem 2>/dev/null
  jq -n '{pebble: {listenAddress: "0.0.0.0:14000", managementListenAddress: "0.0.0.0:15000", certificate: "/ci/cert.pem",
    privateKey: "/ci/key.pem", httpPort: 5002, tlsPort: 5001, ocspResponderURL: "", externalAccountBindingRequired: false}}' > pebble.json
  rm -f ca.key req.csr ext.cnf ca.srl; chmod 644 ./*
)
cat > docker-compose.ci-mail.yml <<'YML'
services:
  domains:
    build:
      args:
        GO_TAGS: testprovider
    environment:
      DOMAINS_FAKEDNS_API_ADDR: ":8054"
  mail-cert:
    environment:
      LEGO_CA_CERTIFICATES: /run/ci/pebble-mail-ca.pem
      DOMAINS_RESOLVERS: 127.0.0.1:8053
    volumes:
      - /tmp/pebble-mail/ca.pem:/run/ci/pebble-mail-ca.pem:ro
  mail-resolver:
    volumes:
      - /tmp/unbound-ci.conf:/etc/unbound/custom.conf:ro
    networks:
      domains-egress: {}
    healthcheck:
      test: ["CMD", "drill-hc", "-p", "5353", "@127.0.0.1", "ci-probe.portcullis.test"]
  mailctl:
    environment:
      MAILCTL_RESOLVERS: 172.31.255.4:5353
      MAILCTL_PUBLIC_IPV4: 203.0.113.25
YML
# This file LAST: runtime_export only adds the Podman overlays when
# missing, and the SELinux overlay re-declares mail-resolver's config bind
# (the later file wins: the production resolver would ask the root servers).
cf="$COMPOSE_FILE:docker-compose.podman.yml"
[ "$(getenforce 2>/dev/null)" != Enforcing ] || cf="$cf:docker-compose.podman-selinux.yml"
export COMPOSE_FILE="$cf:docker-compose.ci-mail.yml"
export PORTCULLIS_TESTPROVIDER=1 DNS_PROVIDER=fake FAKE_API_TOKEN=ci-podman-fake-token-0123 \
  MAIL_ACME_CA_SERVER=https://e2e-pebble-mail:14000/dir MAIL_CAA_ISSUER=pebble.test
# The domains test build first (its fake DNS answers mail-resolver).
./portcullis up
DOM_CID="$(docker compose ps -q domains)"
FAKEDNS="$(podman inspect -f '{{(index .NetworkSettings.Networks "portcullis_domains-egress").IPAddress}}' "$DOM_CID")"
[ -n "$FAKEDNS" ] || fail "no domains address on domains-egress"
# The recreated container's banner (it may still be starting).
for i in $(seq 1 30); do
  out="$(docker compose logs domains 2>&1 || true)"
  grep -q 'provider "fake" enabled' <<<"$out" && break
  [ "$i" -eq 30 ] && fail "the domains service isn't the test build: $(docker compose logs --tail=5 domains 2>&1)"
  sleep 2
done
DOM_CID="$(docker compose ps -q domains)"
# One name for mail-resolver's health check in the fake zone.
jq -n '{op: "append", zone: "portcullis.test.", token: "ci-podman-fake-token-0123",
        records: [{name: "ci-probe", type: "A", ttl: 300, data: "192.0.2.10"}]}' \
  | podman run --rm -i --network portcullis_domains-egress "$CURL_IMG" -sf -H 'Content-Type: application/json' --data-binary @- "http://$FAKEDNS:8054" \
  | jq -e '.error == null' >/dev/null || fail "the probe name into the fake zone"
sed "s/__FAKEDNS__/$FAKEDNS/" tests/e2e/mail/unbound-ci.conf > /tmp/unbound-ci.conf
chmod 644 /tmp/unbound-ci.conf
podman pull -q "$PEBBLE_IMG" >/dev/null
podman rm -f e2e-pebble-mail >/dev/null 2>&1 || true
podman run -d --name e2e-pebble-mail --network portcullis_domains-egress -v /tmp/pebble-mail:/ci:ro \
  -e PEBBLE_VA_ALWAYS_VALID=1 -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
  "$PEBBLE_IMG" -config /ci/pebble.json -dnsserver 127.0.0.1:53 >/dev/null

# 4. mail enable: rewritten client addresses under rootless Podman.
./portcullis mail enable --yes 2>&1 | tee /tmp/mail-enable.out
[ "${PIPESTATUS[0]}" = 0 ] || fail "mail enable on rootless Podman"
grep -qx 'MAILCTL_CLIENT_IP=rewritten' .env || fail "MAILCTL_CLIENT_IP is $(grep '^MAILCTL_CLIENT_IP=' .env)"
# The CI resolver is in use (iterator only: no DNSSEC validator, no root servers).
out="$(docker compose --profile mail logs mail-resolver 2>&1 || true)"
grep -q 'init module 0: iterator' <<<"$out" \
  || fail "mail-resolver doesn't run the CI config: $(docker compose --profile mail logs mail-resolver 2>&1 | grep 'init module' | head -2)"
for s in mail mailctl mail-resolver; do
  for i in $(seq 1 60); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q "$s")")" = healthy ] && break
    [ "$i" -eq 60 ] && fail "$s not healthy"
    sleep 3
  done
done
echo "PASS: mail enable on rootless Podman (port start 25, MAILCTL_CLIENT_IP=rewritten, healthy)"

# 5. The Hub: mail on for the main domain, rt-person in mail_users; the
# doctor names the rewritten client addresses.
SECRET="$(grep '^HUB_PROXY_SECRET=' .env | cut -d= -f2-)"; echo "::add-mask::$SECRET"
hub() { local m="$1" p="$2"; shift 2
        curl -s -X "$m" -H @<(printf 'X-Portcullis-Proxy-Secret: %s\nX-Forwarded-User: admin\n' "$SECRET") \
          -H 'Content-Type: application/json' "$@" "http://127.0.0.1:18888$p"; }
hub PUT "/api/mail/domains/$D" -d '{"enabled":true,"groups":[]}' | jq -e '.mail' >/dev/null || fail "mail on for $D"
for i in $(seq 1 30); do
  code=$(hub POST /api/directory/groups/mail_users/members -d '{"username":"rt-person"}' -o /dev/null -w '%{http_code}')
  case "$code" in 200|201|204) break ;; esac
  [ "$i" -eq 30 ] && fail "rt-person into mail_users: $code"
  sleep 2
done
smtp_to() {  # smtp_to <rcpt> — one message from a CI container to the host's port 25
  printf 'From: probe@relay-test.example\r\nTo: %s\r\nSubject: e2e-podman mail\r\n\r\npodman\r\n' "$1" \
    | podman run --rm -i "$CURL_IMG" -sS --max-time 30 "smtp://host.containers.internal:25/relay-test.example" \
        --mail-from probe@relay-test.example --mail-rcpt "$1" -T -
}
for i in $(seq 1 60); do
  smtp_to "rt-person@$D" && break
  [ "$i" -eq 60 ] && fail "a message to rt-person@$D wasn't accepted on the host's port 25"
  sleep 5
done
for i in $(seq 1 30); do
  out="$(docker compose logs mail 2>&1 || true)"
  grep -E 'message-ingest' <<<"$out" | grep -qF "rt-person@$D" && break
  [ "$i" -eq 30 ] && fail "the message to rt-person@$D wasn't delivered"
  sleep 2
done
echo "PASS: a message from a CI container to the host's port 25 is delivered to rt-person@$D"
op="$(hub POST /api/doctor/scan -d '{}')"
for i in $(seq 1 60); do
  rep="$(hub GET /api/doctor)"
  jq -e 'any(.findings[]?; .kind == "mail_client_ip_rewritten")' <<<"$rep" >/dev/null && break
  [ "$i" -eq 60 ] && fail "no mail_client_ip_rewritten finding (scan: $op): $(jq -c '[.findings[]?.kind]' <<<"$rep")"
  sleep 5
done
echo "PASS: the doctor names mail_client_ip_rewritten"

# 6. No ban (final review L12): past Stalwart's default auth ban rate
# (100 failed logins a day) from one container, then a delivery from
# another still works: every client is the gateway under rootless Podman,
# so a ban would lock everyone out (DegradedSecurity turns the rates off).
# mailctl's role can't read BlockedIp, so Stalwart's own ban events in its
# log are the second signal.
podman run --rm --entrypoint sh "$CURL_IMG" -c '
  n=0; i=0
  while [ "$i" -lt 110 ]; do
    i=$((i + 1))
    curl -s --max-time 10 --ssl-reqd -k -u "nobody@'"$D"':wrong-$i" "smtp://host.containers.internal:587/relay-test.example" \
      --mail-from "nobody@'"$D"'" --mail-rcpt "x@'"$D"'" -T /dev/null >/dev/null 2>&1 && n=$((n + 1))
  done
  echo "accepted=$n"' > /tmp/mail-badauth.out
grep -qx 'accepted=0' /tmp/mail-badauth.out || fail "a wrong password was accepted: $(cat /tmp/mail-badauth.out)"
for i in $(seq 1 12); do
  smtp_to "rt-person@$D" && break
  [ "$i" -eq 12 ] && fail "after 110 failed logins a delivery from another container is refused (a ban on the gateway?)"
  sleep 5
done
out="$(docker compose --profile mail logs mail 2>&1 || true)"
bans="$(grep -iE 'security\.[a-z-]*ban|ip-blocked|blocked-ip|banned' <<<"$out" || true)"
[ -z "$bans" ] || fail "Stalwart banned an address: $(head -3 <<<"$bans")"
echo "PASS: no ban after 110 failed logins (rewritten client addresses never ban the gateway): another container still delivers"

# 7. The container's start gate, for real on rootless Podman (final
# review M2 / M3 / M4: refusals, recovery only with this boot's session
# file, no port published meanwhile).
bash .github/ci/mail-gate-entrypoint.sh podman
podman rm -f e2e-pebble-mail >/dev/null 2>&1 || true
