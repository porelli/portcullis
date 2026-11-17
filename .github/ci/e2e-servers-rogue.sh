#!/usr/bin/env bash
# ci.yml jobs e2e-servers / e2e-servers-podman, e2e_servers.py rogue_worker
# (contract §17.2, §17.4): a worker is untrusted.
#   1. From the tunnel, with w1's own key, every TCP port of link
#      (10.214.0.1) is closed: link's netstack has no listener.
#   2. (dind) w3's agent certificate on w1 is refused: the Hub pins each
#      server's SPKI and serial (server_identity_mismatch → offline), and
#      w1 is ready again with its own identity back.
#   3. A data CONNECT on portcullis-link-data without a valid relay token,
#      or naming an instance that isn't the token's, is refused (403).
#   4. (an e2etest agent) an oversized /v1/info is cut off: w1 goes offline,
#      and is ready again without the flag.
# Secrets (w1's WireGuard key, the relay token) stay in a 0700 temp dir.
set -euo pipefail
kind="${1:?dind|podman}"
: "${RUNNER_IP:?}" "${HUB_IP:?}" "${ALPINE:?}" "${CURL_IMG:?}"
W=".github/ci/e2e-servers-worker.sh"
T="$(mktemp -d)"; chmod 700 "$T"; trap 'rm -rf "$T"' EXIT
SECRET="$(grep '^HUB_PROXY_SECRET=' .env | cut -d= -f2-)"  # never printed, not even masked
hub() { curl -s -H @<(printf 'X-Portcullis-Proxy-Secret: %s\nX-Forwarded-User: admin\n' "$SECRET") "http://$HUB_IP:8888$1"; }
srv_state() { hub "/api/servers/$1" | jq -r '.state // empty'; }
wait_state() {  # <server> <state> <seconds>
  local i
  for ((i = 0; i < $3; i += 3)); do [ "$(srv_state "$1")" = "$2" ] && return 0; sleep 3; done
  echo "FAIL: $1 is $(srv_state "$1"), not $2 after $3 s"; return 1
}
data_dir() { bash "$W" exec w1 sh -c 'grep "^PORTCULLIS_WORKER_DATA=" .env | cut -d= -f2-'; }
# A file of the worker's identity, read as the worker's root (dind) or
# through podman unshare (rootless), never printed.
wfile() {
  if [ "$kind" = dind ]; then bash "$W" exec w1 cat "$(data_dir)/identity/$1"
  else bash "$W" exec w1 podman unshare cat "$(data_dir)/identity/$1"; fi
}

# 1. Every port on 10.214.0.1 closed, through w1's own tunnel (its agent
# stopped meanwhile: one key, one endpoint).
LINK_PUB="$(docker compose exec -T wg /wg status | jq -r .link.public_key)"
W1_IP="$(hub /api/servers/w1 | jq -r .tunnel_ip)"
bash "$W" compose w1 stop agent >/dev/null
(umask 077; { printf '[Interface]\nPrivateKey = '; wfile wg.key | tr -d '\n'; printf '\nAddress = %s/32\nMTU = 1380\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:51821\nAllowedIPs = 10.214.0.1/32\nPersistentKeepalive = 25\n' "$W1_IP" "$LINK_PUB" "$RUNNER_IP"; } > "$T/w1.conf")
PORTS="22,80,443,3128,3129,7000,7443,8080,$(shuf -i 1-65535 -n 2000 | paste -sd, -)"
OUT="$("$E2E_VPN_CLIENT" --wait-handshake 30s --probe 10.214.0.1 --ports "$PORTS" < "$T/w1.conf")" \
  || { echo "FAIL: the probe through w1's tunnel: $OUT"; bash "$W" compose w1 start agent; exit 1; }
bash "$W" compose w1 start agent >/dev/null
echo "$OUT" | jq -e '.handshake and .open == null and .probed > 2000' >/dev/null \
  || { echo "FAIL: ports open on link's netstack: $(echo "$OUT" | jq -c '{handshake, open, probed}')"; exit 1; }
wait_state w1 ready 180
echo "PASS: rogue 1: $(echo "$OUT" | jq -r .probed) TCP ports on 10.214.0.1 closed from w1's tunnel"

# 2. Another server's agent certificate on w1 → refused (dind: w3 exists).
if [ "$kind" = dind ]; then
  D="$(data_dir)"
  bash "$W" exec w1 sh -c "cp -a '$D/identity' /opt/identity.saved"
  for f in tls.key tls.crt; do
    docker exec e2e-w3 sh -c "cat \"\$(grep '^PORTCULLIS_WORKER_DATA=' /opt/portcullis/.env | cut -d= -f2-)/identity/$f\"" \
      | docker exec -i e2e-w1 sh -c "cat > '$D/identity/$f'"
  done
  bash "$W" compose w1 restart agent >/dev/null
  wait_state w1 offline 240
  hub /api/servers/w1 | jq -e 'tostring | test("server_identity_mismatch|identity")' >/dev/null \
    || echo "note: w1's view doesn't name the mismatch: $(hub /api/servers/w1 | jq -c '{state}')"
  bash "$W" exec w1 sh -c "rm -rf '$D/identity' && cp -a /opt/identity.saved '$D/identity' && rm -rf /opt/identity.saved"
  bash "$W" compose w1 restart agent >/dev/null
  wait_state w1 ready 240
  echo "PASS: rogue 2: w3's certificate on w1 refused (w1 offline), w1 ready again with its own"
fi

# 3. Data CONNECTs: no token, a bogus token, se1's token for another instance.
docker run --rm -v portcullis_hub_data:/d:ro --user 10001:10001 "$ALPINE" cat /d/env/se1.relay.env \
  | sed -n 's/^PORTCULLIS_RELAY_TOKEN=//p' > "$T/token"
[ -s "$T/token" ] || { echo "FAIL: no relay token for se1"; exit 1; }
printf 'Proxy-Authorization: Bearer %s\n' "$(cat "$T/token")" > "$T/good.hdr"
printf 'Proxy-Authorization: Bearer %s\n' "$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')" > "$T/bogus.hdr"
: > "$T/none.hdr"
connect() {  # <header file> <target> → the CONNECT's HTTP status
  # As the runner's uid: $T is 0700 (the token), curl's own user can't read it.
  docker run --rm --network portcullis-link-data --user "$(id -u):$(id -g)" -v "$T:/t:ro" "$CURL_IMG" -s -o /dev/null -w '%{http_code}' --max-time 15 \
    --proxytunnel -x http://172.31.254.130:3129 --proxy-header "@/t/$1" "http://$2/" 2>/dev/null || true
}
for c in "none.hdr se1.web.relay:8080" "bogus.hdr se1.web.relay:8080" "good.hdr se0.web.relay:8080" "good.hdr gitea.web.relay:3000"; do
  read -r hdr target <<<"$c"
  code="$(connect "$hdr" "$target")"
  case "$code" in 403|000) ;; *) echo "FAIL: data CONNECT ${hdr%.hdr} → $target answered $code (want 403)"; exit 1 ;; esac
done
echo "PASS: rogue 3: data CONNECTs without a token, with a bogus one, or for another instance than the token's are refused"

# 4. An oversized /v1/info (an e2etest agent, AGENT_TEST_OVERSIZE_INFO=1).
if [ "${AGENT_IMAGE:-}" = localhost/portcullis-agent:ci ]; then
  bash "$W" exec w1 sh -c 'cp docker-compose.worker.override.yml override.saved && printf "    environment:\n      AGENT_TEST_OVERSIZE_INFO: \"1\"\n" >> docker-compose.worker.override.yml'
  bash "$W" compose w1 up -d agent >/dev/null
  wait_state w1 offline 240
  bash "$W" exec w1 sh -c 'mv override.saved docker-compose.worker.override.yml'
  bash "$W" compose w1 up -d agent >/dev/null
  wait_state w1 ready 240
  echo "PASS: rogue 4: an oversized /v1/info is cut off (w1 offline), ready again without it"
else
  echo "::warning::rogue 4 skipped: the agent image isn't an e2etest build (no same-named Hub branch)"
fi
