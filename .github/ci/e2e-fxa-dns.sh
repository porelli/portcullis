#!/usr/bin/env bash
# ci.yml job e2e-fxa, step "Containers resolve the e2e hostnames to the
# runner". Runs first, before any other container (Docker restarts).
#
# On a real server every app reaches the server's public names through
# public DNS: fxa-auth and the Hub submit their mail to MAIL_HOSTNAME:587
# (contract §19.14), the admin UI reads Keycloak's issuer at auth.<d>. CI
# has no public DNS for $E2E_DOMAIN, so the runner answers it itself: a
# CoreDNS container (the pin e2e-vpn uses) published on the runner's
# address :53 answers every name under $E2E_DOMAIN with that address
# (where Traefik's 443 and the provider's mail ports are published) and
# forwards every other name to the runner's own upstream; it is Docker's
# DNS server (daemon.json "dns": the embedded resolver forwards each name
# it doesn't own there). The runner itself uses /etc/hosts (the start
# script's line, E2E_HOSTS_IP = the same address).
# Writes RUNNER_IP to GITHUB_ENV.
set -euo pipefail
ALPINE=docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
COREDNS=docker.io/coredns/coredns:1.15.0@sha256:0a9d8c8ddf34347eb59aad9a8784f0710de88d6d112726d11d271f9bc6daca26
d="${E2E_DOMAIN:?}"
[[ "$d" =~ ^[a-z0-9.-]+$ ]] || { echo "FAIL: E2E_DOMAIN '$d'"; exit 1; }
ip="$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')"
[[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "FAIL: the runner's address: '$ip'"; exit 1; }
up="$(awk '$1 == "nameserver" && $2 !~ /^127\./ {print $2; exit}' /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null || true)"
[[ "$up" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "FAIL: no upstream resolver ('$up')"; exit 1; }
cur="$(sudo cat /etc/docker/daemon.json 2>/dev/null || true)"
jq --arg ip "$ip" '. + {dns: [$ip]}' <<<"${cur:-{\}}" | sudo tee /etc/docker/daemon.json.new >/dev/null
sudo mv /etc/docker/daemon.json.new /etc/docker/daemon.json
sudo systemctl restart docker
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 2; done
docker info >/dev/null || { echo "FAIL: Docker didn't come back"; exit 1; }
conf=/tmp/e2e-fxa-coredns
rm -rf "$conf"; mkdir -p "$conf"
cat > "$conf/Corefile" <<COREFILE
$d {
  template IN A {
    answer "{{ .Name }} 60 IN A $ip"
  }
  template ANY ANY {
    rcode NOERROR
  }
}
. {
  forward . $up
}
COREFILE
chmod -R a+rX "$conf"
docker run -d --name e2e-fxa-dns --restart always -p "$ip:53:53/udp" -p "$ip:53:53/tcp" \
  -v "$conf:/etc/coredns:ro" "$COREDNS" -conf /etc/coredns/Corefile >/dev/null
docker network create e2e-fxa-dnsprobe >/dev/null
trap 'docker network rm e2e-fxa-dnsprobe >/dev/null 2>&1 || true' EXIT
ok=""
for _ in $(seq 1 20); do
  got="$(docker run --rm --network e2e-fxa-dnsprobe "$ALPINE" nslookup "mail.$d" 2>&1 || true)"
  grep -qF "Address: $ip" <<<"$got" && { ok=1; break; }
  sleep 2
done
if [ -z "$ok" ]; then
  echo "FAIL: a container doesn't resolve mail.$d to $ip: $got"
  echo "--- straight at $ip:"; docker run --rm "$ALPINE" nslookup "mail.$d" "$ip" 2>&1 || true
  echo "--- daemon.json:"; sudo cat /etc/docker/daemon.json; docker logs e2e-fxa-dns 2>&1 | tail -20
  exit 1
fi
got="$(docker run --rm "$ALPINE" nslookup "auth.$d" 2>&1 || true)"
grep -qF "Address: $ip" <<<"$got" || { echo "FAIL: on the default bridge auth.$d: $got"; exit 1; }
docker run --rm --network e2e-fxa-dnsprobe "$ALPINE" nslookup github.com >/dev/null 2>&1 \
  || echo "::warning::a container couldn't resolve github.com through the runner's resolver"
echo "RUNNER_IP=$ip" >> "$GITHUB_ENV"
echo "PASS: containers resolve *.$d to $ip (CoreDNS on $ip:53 as Docker's DNS; other names → $up)"
