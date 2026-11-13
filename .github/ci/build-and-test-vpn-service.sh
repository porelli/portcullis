#!/usr/bin/env bash
# ci.yml job build-and-test, step "Test the VPN service (wg userspace, least privilege; vpnsecure trusts only wg's PROXY)".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
set -o pipefail
CURL_IMG=docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93
./portcullis vpn init
grep -qx 'COMPOSE_PROFILES=wg' .env || { echo "FAIL: vpn init did not add wg to COMPOSE_PROFILES"; grep '^COMPOSE_PROFILES' .env; exit 1; }
WG_CID="$(docker compose ps -q wg)"
[ -n "$WG_CID" ] || { echo "FAIL: no wg container"; exit 1; }
docker inspect "$WG_CID" | jq -e '.[0] | .Config.User == "10006:10006"
    and (.HostConfig.CapAdd // [] | length) == 0 and .HostConfig.CapDrop == ["ALL"]
    and (.HostConfig.Privileged | not) and (.HostConfig.Devices // [] | length) == 0
    and .HostConfig.GroupAdd == ["10007"] and .HostConfig.ReadonlyRootfs
    and ([.Mounts[] | select(.Source | test("docker\\.sock|podman\\.sock"))] == [])
    and (.State.Health.Status == "healthy")' >/dev/null \
  || { echo "FAIL: wg container: $(docker inspect "$WG_CID" | jq -c '.[0] | {User: .Config.User, CapAdd: .HostConfig.CapAdd, GroupAdd: .HostConfig.GroupAdd, Health: .State.Health.Status}')"; docker compose logs --tail=40 wg; exit 1; }
docker compose exec -T wg sh -c 'id -u; id -G; stat -c "%a %u %g" /data /data/status.json' > /tmp/wg-ids.txt
[ "$(cat /tmp/wg-ids.txt | tr '\n' '|')" = "10006|10006 10007|2750 10006 10001|640 10006 10001|" ] \
  || { echo "FAIL: wg's ids / wg_data modes: $(cat /tmp/wg-ids.txt | tr '\n' '|')"; exit 1; }
for i in $(seq 1 40); do
  docker compose exec -T wg /wg status | jq -e '.version == 1 and .people.ok and .edge.ok and (.people.public_key | length) == 44
      and .people.port == 51820 and .people.subnet == "10.213.0.0/22" and .people.mtu == 1280' >/dev/null 2>&1 && break
  [ "$i" -eq 40 ] && { echo "FAIL: wg status: $(docker compose exec -T wg /wg status)"; docker compose logs --tail=40 wg hub; exit 1; }
  sleep 3
done
# The Hub reads status.json read-only through group 10001, never the engine.
docker compose exec -T hub sh -c 'test -r /wg-data/status.json && ! test -w /wg-data/status.json && test -w /vpn-doc' \
  || { echo "FAIL: the Hub's wg_data / vpn_doc access"; exit 1; }
# The people key: 0640 group 10006, never printed (a 44-character base64 key).
[ "$(stat -c '%a %g %s' secrets/wg/people.key)" = "640 10006 45" ] || { echo "FAIL: people.key $(stat -c '%a %g %s' secrets/wg/people.key)"; exit 1; }
echo "PASS: vpn init: wg healthy as 10006 (group 10007 only), no capability / device / privilege, wg_data 2750 10006:10001, status.json 0640 group 10001, the people role on"

# A whoami on both entrypoints (no middleware): it echoes what a backend gets.
cat > /tmp/ci-vpnecho.yml <<'YML'
services:
  whoami:
    image: docker.io/traefik/whoami:v1.12.0@sha256:c4717a8d1f0134a7444e24f881160e033991f23027c6c5a9a3f8fd22e70d1d44
    networks: [portcullis-proxy]
    labels:
      traefik.enable: "true"
      traefik.http.services.ci-vpnecho.loadbalancer.server.port: "80"
      traefik.http.routers.ci-vpnecho.rule: Host(`vpnecho.portcullis.local`)
      traefik.http.routers.ci-vpnecho.entrypoints: websecure,vpnsecure
      traefik.http.routers.ci-vpnecho.tls.options: authaware@file
      traefik.http.routers.ci-vpnecho.service: ci-vpnecho
networks:
  portcullis-proxy:
    external: true
YML
sed -i 's/^          //' /tmp/ci-vpnecho.yml
docker compose -p ci-vpnecho -f /tmp/ci-vpnecho.yml up -d
echo_web() { curl -s --cacert certs/ca-chain.crt --resolve "vpnecho.portcullis.local:443:127.0.0.1" "$@" https://vpnecho.portcullis.local/ || true; }
for i in $(seq 1 30); do echo_web | grep -q '^Hostname:' && break; [ "$i" -eq 30 ] && { echo "FAIL: vpnecho not routed"; exit 1; }; sleep 2; done
# Spoofed client addresses on websecure: Traefik drops them (no
# forwarded-header trust), the backend sees the real peer only.
OUT="$(echo_web -H 'X-Forwarded-For: 10.213.0.5' -H 'X-Real-Ip: 10.213.0.5' -H 'X_Forwarded_For: 10.213.0.5')"
if printf '%s' "$OUT" | grep -qi '10\.213\.0\.5'; then echo "FAIL: a spoofed address reached the backend on websecure:"; printf '%s\n' "$OUT"; exit 1; fi
printf '%s' "$OUT" | grep -qiE '^X-Forwarded-For: [0-9.]+$' || { echo "FAIL: no single X-Forwarded-For: $OUT"; exit 1; }
# group-gate's normal path never binds: the spoofed headers on a
# gated route are logged with the real address, never 10.213.0.5.
curl -s -o /dev/null --cacert certs/ca-chain.crt --resolve "gated.portcullis.local:443:127.0.0.1" \
  -H 'X-Forwarded-For: 10.213.0.5' -H 'X-Real-Ip: 10.213.0.5' https://gated.portcullis.local/ || true
if docker compose logs --since 2m group-gate | grep -q 'addr=10\.213\.0\.5'; then echo "FAIL: group-gate saw a spoofed address"; exit 1; fi
echo "PASS: spoofed X-Forwarded-For / X-Real-Ip on websecure never reach a backend or group-gate"

# A PROXY header to vpnsecure from anything but wg: from a gateway's
# network (portcullis-vpn) Traefik isn't reachable at all; from the
# edge network (only wg and Traefik belong there: a throwaway
# container stands in for an intruder) the header isn't honoured.
EDGE_TRAEFIK=172.31.254.66
if docker run --rm --network portcullis-vpn --ip 172.31.254.20 "$CURL_IMG" -s --max-time 8 -k -o /dev/null \
     --haproxy-protocol --haproxy-clientip 10.213.0.5 --resolve "vpnecho.portcullis.local:8443:$EDGE_TRAEFIK" \
     https://vpnecho.portcullis.local:8443/; then
  echo "FAIL: a container on portcullis-vpn reached vpnsecure"; exit 1
fi
OUT="$(docker run --rm --network portcullis-vpn-edge --ip 172.31.254.70 "$CURL_IMG" -s --max-time 8 -k \
         --haproxy-protocol --haproxy-clientip 10.213.0.5 --resolve "vpnecho.portcullis.local:8443:$EDGE_TRAEFIK" \
         https://vpnecho.portcullis.local:8443/ || true)"
if printf '%s' "$OUT" | grep -q '10\.213\.0\.5'; then echo "FAIL: vpnsecure honoured a PROXY header from 172.31.254.70:"; printf '%s\n' "$OUT"; exit 1; fi
printf '%s' "$OUT" | grep -qE '^X-Forwarded-For: 172\.31\.254\.70$' || [ -z "$OUT" ] \
  || { echo "FAIL: unexpected answer on vpnsecure: $OUT"; exit 1; }
echo "PASS: vpnsecure honours PROXY only from wg (portcullis-vpn can't reach it; another edge address is ignored)"
# Nothing listens on the edge's provider ports without a wired provider.
if docker run --rm --network portcullis-vpn --ip 172.31.254.21 "$CURL_IMG" -s --max-time 5 -o /dev/null telnet://172.31.254.3:9001 </dev/null; then
  echo "FAIL: an edge port answers with no provider wired"; exit 1
fi
docker compose -p ci-vpnecho -f /tmp/ci-vpnecho.yml down
# wg stays on (profile wg) for the rest of the job: up, upgrade,
# backup and restore run with it (secrets/wg is backed up).
echo "PASS: the VPN service"
