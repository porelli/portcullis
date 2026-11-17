#!/usr/bin/env bash
# ci.yml job e2e-mail, step "The remote mail server (remote.test)".
# Runs from the workspace root with GitHub's default shell behaviour (bash -e).
#
# A second Stalwart (the stalwart template's pin and plain config) as
# remote.test's MX: on the wired template's egress network
# (portcullis-stalwart_egress, pinned 172.30.88.0/24 by the CI checkout)
# at 172.30.88.25 (it reaches Portcullis's mail at 172.30.88.2) and on
# domains-egress at 172.30.87.25 (its resolver: the fake zone at
# 172.30.87.53:8053). It reaches nothing else (DOCKER-USER), downloads
# nothing (plan.json), and its records go into the shared fake zone.
# Writes REMOTE_* (the recovery admin and the account's password, masked)
# to GITHUB_ENV for e2e_mail.py.
set -euo pipefail
S="$(awk '/^  stalwart:$/ {f = 1} f && /^    image: / {print $2; exit}' "$RUNNER_TEMP/templates/stalwart/compose.yml")"
[[ "$S" =~ ^docker\.io/stalwartlabs/stalwart:[^@]+@sha256:[0-9a-f]{64}$ ]] || { echo "FAIL: the template's Stalwart image: $S"; exit 1; }
R=/tmp/e2e-remote
FAKE_API=http://172.30.87.53:8054
fail() { echo "FAIL: $*"; docker logs --tail 60 e2e-remote 2>&1 || true; exit 1; }

sudo rm -rf "$R"; mkdir -p "$R/tls" "$R/etc"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=mx.remote.test \
  -addext subjectAltName=DNS:mx.remote.test -keyout "$R/tls/privkey.pem" -out "$R/tls/fullchain.pem" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$R/dkim.pem" 2>/dev/null
cp "$RUNNER_TEMP/templates/stalwart/config/config.json" "$R/etc/config.json"
chmod -R a+rX "$R/tls" "$R/etc"
ADMIN_PW="$(openssl rand -hex 24)"; echo "::add-mask::$ADMIN_PW"
REMOTE_PASSWORD="$(openssl rand -hex 16)"; echo "::add-mask::$REMOTE_PASSWORD"
{ echo "REMOTE_ADMIN=portcullis-recovery:$ADMIN_PW"; echo "REMOTE_PASSWORD=$REMOTE_PASSWORD"; echo "REMOTE_USER=carla"; } >> "$GITHUB_ENV"

# The remote reaches the stack's own networks only (and never port 25
# outside them: the job's first rule).
for ip in 172.30.88.25 172.30.87.25; do
  sudo iptables -I DOCKER-USER -s "$ip" ! -d 172.16.0.0/12 -j REJECT
done

run_remote() {
  docker rm -f e2e-remote >/dev/null 2>&1 || true
  docker create --name e2e-remote --network portcullis-stalwart_egress --ip 172.30.88.25 \
    -v e2e-remote-data:/var/lib/stalwart -v "$R/etc:/etc/stalwart:ro" -v "$R/tls:/run/remote/tls:ro" \
    --env-file <(echo "STALWART_RECOVERY_ADMIN=portcullis-recovery:$ADMIN_PW") "$@" "$S" --config /etc/stalwart/config.json >/dev/null
  docker network connect --ip 172.30.87.25 portcullis_domains-egress e2e-remote
  docker start e2e-remote >/dev/null
  for _ in $(seq 1 60); do docker exec e2e-remote curl -fsS -o /dev/null http://127.0.0.1:8080/healthz/live 2>/dev/null && return 0; sleep 2; done
  fail "the remote didn't start"
}
docker volume rm e2e-remote-data >/dev/null 2>&1 || true
run_remote -e STALWART_RECOVERY_MODE=1
REMOTE_ADMIN="portcullis-recovery:$ADMIN_PW" REMOTE_PASSWORD="$REMOTE_PASSWORD" REMOTE_USER=carla \
  PORTCULLIS_MX=172.30.88.2 RESOLVER_IP=172.30.87.53 RESOLVER_PORT=8053 REMOTE_DKIM_PEM="$(cat "$R/dkim.pem")" \
  python3 tests/e2e/e2e_mailremote.py apply http://172.30.88.25:8080 || fail "the remote's plan"
rm -f "$R/dkim.pem"
run_remote

# remote.test in the shared zone: MX, the MX host's address, SPF, the
# DKIM key Stalwart derived (its Domain's zone file), DMARC with reports.
dkim="$(REMOTE_ADMIN="portcullis-recovery:$ADMIN_PW" python3 -c '
import os, sys; sys.path.insert(0, "tests/e2e"); import e2e_mailremote as m
u, _, p = os.environ["REMOTE_ADMIN"].partition(":")
d = m.Jmap("http://172.30.88.25:8080", u, p).get_all("Domain")[0]
for ln in d["dnsZoneFile"].splitlines():
    if ln.startswith("rem1._domainkey.remote.test. IN TXT "):
        print(ln.split(" IN TXT ", 1)[1].strip().strip("\""))')"
[[ "$dkim" == "v=DKIM1; k=ed25519; "* ]] || fail "no DKIM record from the remote: $dkim"
jq -n --arg dkim "$dkim" '{op: "append", zone: "remote.test.", token: "ci-fake-token-0123456789", records: [
  {name: "@", type: "MX", ttl: 300, data: "10 mx.remote.test."},
  {name: "mx", type: "A", ttl: 300, data: "172.30.88.25"},
  {name: "@", type: "TXT", ttl: 300, data: "v=spf1 ip4:172.30.88.25 -all"},
  {name: "mx", type: "TXT", ttl: 300, data: "v=spf1 a -all"},
  {name: "rem1._domainkey", type: "TXT", ttl: 300, data: $dkim},
  {name: "_dmarc", type: "TXT", ttl: 300, data: "v=DMARC1; p=reject; rua=mailto:postmaster@remote.test"}]}' \
  | curl -sf -H 'Content-Type: application/json' --data-binary @- "$FAKE_API" | jq -e '.error == null' >/dev/null \
  || fail "remote.test's records into the fake zone"
# Its reverse name (a real MX has one: RDNS_NONE otherwise).
jq -n '{op: "append", zone: "88.30.172.in-addr.arpa.", token: "ci-fake-token-0123456789",
        records: [{name: "25", type: "PTR", ttl: 300, data: "mx.remote.test."}]}' \
  | curl -sf -H 'Content-Type: application/json' --data-binary @- "$FAKE_API" | jq -e '.error == null' >/dev/null \
  || fail "the remote's PTR into the fake zone"
jq -n '{op: "get", zone: "remote.test.", token: "ci-fake-token-0123456789", records: []}' \
  | curl -sf -H 'Content-Type: application/json' --data-binary @- "$FAKE_API" \
  | jq -e 'any(.records[]; .type == "MX" and .data == "10 mx.remote.test.")' >/dev/null || fail "remote.test's MX isn't in the fake zone"
cat /tmp/e2e-pebble-root.pem "$R/tls/fullchain.pem" > /tmp/e2e-mail-ca.pem
echo "E2E_MAIL_CA=/tmp/e2e-mail-ca.pem" >> "$GITHUB_ENV"
echo "PASS: the remote mail server (remote.test) is up, its records are in the fake zone"
