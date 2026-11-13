#!/usr/bin/env bash
# ci.yml job e2e-podman, step "The VPN service on rootless Podman (vpn init, wg as 10006 without capabilities, a built-in device through the tunnel)".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
set -o pipefail
# shellcheck source=/dev/null
source "$RUNNER_TEMP/podlib.sh"
# vpn init needs the Hub (hub vpn host-info): show its state first.
docker inspect --format 'Hub: {{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$(docker compose ps -q hub)" \
  || { echo "FAIL: no Hub container before vpn init"; docker compose ps -a; exit 1; }
./portcullis vpn init 2>&1 | redact
WG_CID="$(docker compose ps -q wg)"
docker inspect "$WG_CID" | jq -e '.[0] | .Config.User == "10006:10006" and (.HostConfig.CapAdd // [] | length) == 0
    and (.HostConfig.Privileged | not) and (.HostConfig.Devices // [] | length) == 0' >/dev/null \
  || { echo "FAIL: wg on Podman: $(docker inspect "$WG_CID" | jq -c '.[0] | {User: .Config.User, CapAdd: .HostConfig.CapAdd, Privileged: .HostConfig.Privileged}')"; exit 1; }
[ "$(docker compose exec -T wg id -u)" = 10006 ] || { echo "FAIL: wg's uid in its container"; exit 1; }
for i in $(seq 1 40); do
  docker compose exec -T wg /wg status | jq -e '.people.ok and .edge.ok' >/dev/null 2>&1 && break
  [ "$i" -eq 40 ] && { echo "FAIL: wg status: $(docker compose exec -T wg /wg status)"; docker compose logs --tail=40 wg hub; exit 1; }
  sleep 3
done
# A person for the device (LLDAP; the Hub's VPN users group is everyone by default).
LLDAP_ADMIN_PASSWORD="$(grep '^LLDAP_ADMIN_PASSWORD=' .env | cut -d= -f2-)"; echo "::add-mask::$LLDAP_ADMIN_PASSWORD"
LT=$(LLDAP_ADMIN_PASSWORD="$LLDAP_ADMIN_PASSWORD" jq -n '{username: "admin", password: env.LLDAP_ADMIN_PASSWORD}' \
  | curl -sf http://127.0.0.1:17170/auth/simple/login -H 'Content-Type: application/json' -d @- | jq -r .token)
echo "::add-mask::$LT"
jq -n '{query: "mutation { createUser(user: {id: \"vpn-ci\", email: \"vpn-ci@portcullis.local\"}) { id } }"}' \
  | curl -sf http://127.0.0.1:17170/api/graphql -H @<(printf 'Authorization: Bearer %s\n' "$LT") -H 'Content-Type: application/json' -d @- \
  | jq -e '.errors == null' >/dev/null || { echo "FAIL: LLDAP user vpn-ci"; exit 1; }
# The device: the host CLI prints the config once (the private key
# goes to a 0600 file in RUNNER_TEMP for the client, never an artifact).
umask 077
for i in $(seq 1 20); do
  ./portcullis vpn add-device vpn-ci laptop > "$RUNNER_TEMP/vpn-ci.out" 2>&1 && break
  [ "$i" -eq 20 ] && { echo "FAIL: vpn add-device: $(grep -v PrivateKey "$RUNNER_TEMP/vpn-ci.out")"; exit 1; }
  sleep 6
done
sed -n '/^\[Interface\]/,/^PersistentKeepalive/p' "$RUNNER_TEMP/vpn-ci.out" > "$RUNNER_TEMP/vpn-ci.conf"
grep -qx 'AllowedIPs = 10.213.0.1/32' "$RUNNER_TEMP/vpn-ci.conf" || { echo "FAIL: the config has no AllowedIPs = 10.213.0.1/32"; exit 1; }
# The tunnel: handshake over the published UDP port, then people.<d>
# through the edge and vpnsecure: forward-auth still asks to sign in.
for i in $(seq 1 10); do
  "$RUNNER_TEMP/vpn-client" --endpoint 127.0.0.1:51820 --ca-file certs/ca-chain.crt \
    --resolve "people.$E2E_DOMAIN:443:10.213.0.1" --get "https://people.$E2E_DOMAIN/" < "$RUNNER_TEMP/vpn-ci.conf" > /tmp/vpn-get.json || true
  jq -e --arg d "$E2E_DOMAIN" '.handshake and (.status == 302 or .status == 401) and ((.location // "") | startswith("https://auth.\($d)/") or . == "")' /tmp/vpn-get.json >/dev/null && break
  [ "$i" -eq 10 ] && { echo "FAIL: through the tunnel: $(jq -c 'del(.body)' /tmp/vpn-get.json)"; docker compose logs --tail=40 wg traefik; exit 1; }
  sleep 5
done
"$RUNNER_TEMP/vpn-client" --endpoint 127.0.0.1:51820 --dns "people.$E2E_DOMAIN" < "$RUNNER_TEMP/vpn-ci.conf" > /tmp/vpn-dns.json || true
jq -e '.handshake' /tmp/vpn-dns.json >/dev/null || { echo "FAIL: DNS through the tunnel: $(cat /tmp/vpn-dns.json)"; exit 1; }
rm -f "$RUNNER_TEMP/vpn-ci.conf" "$RUNNER_TEMP/vpn-ci.out"
jq -c '{status, location, handshake}' /tmp/vpn-get.json | tee -a "$GITHUB_STEP_SUMMARY"
status_wait 120
echo "PASS: wg on rootless Podman: 10006, no capability, a built-in device's handshake and a request through the edge and vpnsecure"
