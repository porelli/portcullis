#!/usr/bin/env bash
# ci.yml job e2e-podman, step "Mail on rootless Podman" (mail provider plan
# Task 25; spec §12). Runs from the workspace root with GitHub's default
# shell behaviour (bash -e), after the Docker → Podman round trip (the
# stack is up, rt-person exists).
#
#   mail enable refused while ip_unprivileged_port_start > 25; then 25 and
#   `mail enable --provider stalwart` (the templates checkout as the Hub's
#   "portcullis" source, the adapter built here); client addresses
#   rewritten; the Hub's doctor names it; a message from a CI container to
#   the host's port 25 is delivered; no ban after 110 failed logins (every
#   client is the gateway under rootless Podman); the gate (P3) refuses a
#   raw start without the slot sentinel.
#
# Nothing leaves the runner: outbound 25 / 465 / 587 is rejected for the
# runner and pasta (rootless Podman's egress is the user's own sockets);
# mail-cert's CA is a CI Pebble (always valid: the one-shot's fake zone is
# its own); the template's resolver forwards every name to the domains
# fake DNS (rootless Podman's networks aren't isolated from each other).
set -euo pipefail
# shellcheck source=/dev/null
source "$RUNNER_TEMP/podlib.sh"
CURL_IMG=docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93
PEBBLE_IMG=ghcr.io/letsencrypt/pebble:2.10.1@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199
ALPINE_IMG=docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
D="${E2E_DOMAIN:-portcullis.local}"
INST=stalwart
PROJ="portcullis-$INST"
cid() { podman ps -aq --filter "label=com.docker.compose.project=$PROJ" --filter "label=com.docker.compose.service=$1" | head -n1; }
health() { podman inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$(cid "$1")" 2>/dev/null || echo missing; }
fail() {
  echo "FAIL: $*"
  for s in bootstrap stalwart adapter resolver; do c="$(cid "$s" 2>/dev/null || true)"; [ -z "$c" ] || { echo "--- $s"; podman logs --tail=40 "$c" 2>&1 | tail -n 40; }; done
  docker compose logs --tail=40 hub 2>/dev/null || true
  exit 1
}
wait_healthy() { for _ in $(seq 1 100); do [ "$(health "$1")" = healthy ] && return 0; sleep 3; done; fail "$1 not healthy ($(health "$1"))"; }
hub_mail() { docker compose exec -T hub hub mail "$@"; }

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

# 2. The CI pieces: the domains test build (provider fake), a Pebble for
# mail-cert (its TLS certificate from a throwaway CI CA).
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
YML
cf="$COMPOSE_FILE:docker-compose.podman.yml"
[ "$(getenforce 2>/dev/null)" != Enforcing ] || cf="$cf:docker-compose.podman-selinux.yml"
export COMPOSE_FILE="$cf:docker-compose.ci-mail.yml"
export PORTCULLIS_TESTPROVIDER=1 DNS_PROVIDER=fake FAKE_API_TOKEN=ci-podman-fake-token-0123 \
  MAIL_ACME_CA_SERVER=https://e2e-pebble-mail:14000/dir MAIL_CAA_ISSUER=pebble.test
./portcullis up
DOM_CID="$(docker compose ps -q domains)"
for i in $(seq 1 30); do
  out="$(docker compose logs domains 2>&1 || true)"
  grep -q 'provider "fake" enabled' <<<"$out" && break
  [ "$i" -eq 30 ] && fail "the domains service isn't the test build: $(docker compose logs --tail=5 domains 2>&1)"
  sleep 2
done
DOM_CID="$(docker compose ps -q domains)"
FAKEDNS="$(podman inspect -f '{{(index .NetworkSettings.Networks "portcullis_domains-egress").IPAddress}}' "$DOM_CID")"
[ -n "$FAKEDNS" ] || fail "no domains address on domains-egress"
# One name for the template resolver's health check in the fake zone.
jq -n '{op: "append", zone: "portcullis.test.", token: "ci-podman-fake-token-0123",
        records: [{name: "ci-probe", type: "A", ttl: 300, data: "192.0.2.10"}]}' \
  | podman run --rm -i --network portcullis_domains-egress "$CURL_IMG" -sf -H 'Content-Type: application/json' --data-binary @- "http://$FAKEDNS:8054" \
  | jq -e '.error == null' >/dev/null || fail "the probe name into the fake zone"
podman pull -q "$PEBBLE_IMG" >/dev/null
podman rm -f e2e-pebble-mail >/dev/null 2>&1 || true
podman run -d --name e2e-pebble-mail --network portcullis_domains-egress -v /tmp/pebble-mail:/ci:ro \
  -e PEBBLE_VA_ALWAYS_VALID=1 -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
  "$PEBBLE_IMG" -config /ci/pebble.json -dnsserver 127.0.0.1:53 >/dev/null

# 3. The adapter from the checkout (P2) and the template for this runner.
podman build -q -t portcullis-mailctl:ci mailctl >/dev/null
MAIL_CI_DNS_PROBE=ci-probe.portcullis.test bash .github/ci/mail-templates-checkout.sh "$RUNNER_TEMP/templates" "$FAKEDNS"
# The checkout as the Hub's "portcullis" source (the restore brought back
# the Docker phase's clone of main, which has no mail template).
docker compose stop hub >/dev/null
podman run --rm --network none -v portcullis_hub_data:/d -v "$RUNNER_TEMP/templates:/tpl:ro" "$ALPINE_IMG" sh -ec '
  p=$(awk "/- name: portcullis\$/ {f=1; next} f && /path:/ {print \$2; exit}" /d/state.yaml)
  case "$p" in /data/repos/*) ;; *) echo "no portcullis source path in state.yaml: $p" >&2; exit 1 ;; esac
  d="/d/${p#/data/}"
  rm -rf "$d" && mkdir -p "$d" && cp -r /tpl/. "$d/" && rm -rf "$d/.git"
  sed -i "s#^\( *\)url: https://github.com/porelli/portcullis-templates.git\$#\1url: \"\"#" /d/state.yaml
  grep -q "url: \"\"" /d/state.yaml
  chown -R 10001:10001 "$d" /d/state.yaml'
docker compose start hub >/dev/null
for _ in $(seq 1 40); do hub_mail provider >/dev/null 2>&1 && break; sleep 3; done

# 4. The port start: mail enable refused while unprivileged ports start
# above 25 (before anything is written), then accepted at 25.
sudo sysctl -qw net.ipv4.ip_unprivileged_port_start=80
set +e
./portcullis mail enable --provider stalwart --yes > /tmp/mail-enable-refused.out 2>&1; rc=$?
set -e
[ "$rc" != 0 ] && grep -q 'ip_unprivileged_port_start' /tmp/mail-enable-refused.out \
  || fail "mail enable with ports starting at 80: rc $rc: $(tail -3 /tmp/mail-enable-refused.out)"
! grep -q '^PORTCULLIS_MAIL=on$' .env || fail "the refused mail enable opened the slot"
echo "PASS: mail enable refused while ip_unprivileged_port_start > 25, nothing written"
sudo sysctl -qw net.ipv4.ip_unprivileged_port_start=25
bash .github/ci/mail-enable-logged.sh stalwart /tmp/mail-enable.out | redact || fail "mail enable on rootless Podman"
for s in resolver stalwart adapter; do wait_healthy "$s"; done
[ "$(podman inspect -f '{{.State.ExitCode}}' "$(cid bootstrap)")" = 0 ] || fail "the bootstrap job failed"
podman logs "$(cid bootstrap)" 2>&1 | grep -qE 'bootstrap: done \(the base plan, the recovery login refused\)|its API key is in place; nothing to do' \
  || fail "the bootstrap job's last run: $(podman logs --tail=20 "$(cid bootstrap)" 2>&1)"
podman run --rm --network none -v "${PROJ}_data:/v:ro" "$ALPINE_IMG" cat /v/.portcullis-base-plan | jq -e '.version == 1' >/dev/null \
  || fail "the store has no base-plan marker (the plan never ran on the fresh store)"
./portcullis mail status --json > /tmp/mail-status.json || true
jq -e --arg i "$INST" '.hub.wired == true and .hub.instance == $i and .client_ip == "rewritten"' /tmp/mail-status.json >/dev/null \
  || fail "mail status --json: $(cat /tmp/mail-status.json)"
echo "PASS: mail enable on rootless Podman (port start 25, wired, healthy, client addresses rewritten)"

# 5. A cold start (the Podman 4.9 recreate quirk: every up recreates):
# the marked store's key is kept, no plan.
podman stop "$(cid adapter)" "$(cid stalwart)" >/dev/null
podman start -a "$(cid bootstrap)" > /tmp/mail-bootstrap2.out 2>&1 || { cat /tmp/mail-bootstrap2.out; fail "the bootstrap job's cold start"; }
grep -q 'its API key is in place; nothing to do' /tmp/mail-bootstrap2.out || fail "cold start: $(tail -4 /tmp/mail-bootstrap2.out)"
podman start "$(cid stalwart)" "$(cid adapter)" >/dev/null
for s in stalwart adapter; do wait_healthy "$s"; done
echo "PASS: a cold start keeps the store's key (no plan, no new key)"

# 6. The Hub: mail on for the main domain, rt-person in mail_users; the
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
  out="$(podman logs "$(cid stalwart)" 2>&1 || true)"
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

# 7. No ban: past Stalwart's default auth ban rate (100 failed logins a
# day) from one container, then a delivery from another still works
# (every client is the gateway under rootless Podman, so a ban would lock
# everyone out); Stalwart's own ban events in its log are the second signal.
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
out="$(podman logs "$(cid stalwart)" 2>&1 || true)"
bans="$(grep -iE 'security\.[a-z-]*ban|ip-blocked|blocked-ip|banned' <<<"$out" || true)"
[ -z "$bans" ] || fail "Stalwart banned an address: $(head -3 <<<"$bans")"
echo "PASS: no ban after 110 failed logins: another container still delivers"

# 8. The gate (P3) on rootless Podman: without the slot sentinel a raw
# start of the server fails before it serves; with it, healthy again.
podman run --rm --network none -v portcullis_mail_provider_slot:/hs "$ALPINE_IMG" rm /hs/.present
podman stop "$(cid stalwart)" >/dev/null
set +e
podman start -a "$(cid stalwart)" > /tmp/mail-gate.out 2>&1; rc=$?
set -e
podman run --rm --network none -v portcullis_mail_provider_slot:/hs "$ALPINE_IMG" sh -c 'printf "portcullis-mail-gate\n" > /hs/.present && chown 10001:2000 /hs/.present && chmod 0640 /hs/.present'
[ "$rc" != 0 ] || fail "stalwart started without the gate sentinel"
podman start "$(cid stalwart)" >/dev/null
wait_healthy stalwart
echo "PASS: the gate wrapper refuses a raw start without .present (exit $rc), healthy with it"
podman rm -f e2e-pebble-mail >/dev/null 2>&1 || true
