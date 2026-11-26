#!/usr/bin/env bash
# ci.yml job e2e-fxa, step "Containers resolve the e2e hostnames to the
# runner". Runs first, before any container (Docker restarts).
#
# On a real server every app reaches the server's public names through
# public DNS: fxa-auth and the Hub submit their mail to MAIL_HOSTNAME:587
# (contract §19.14), the admin UI reads Keycloak's issuer at auth.<d>. CI
# has no public DNS for ci.example.org, so the runner answers them itself:
# systemd-resolved gets an extra stub listener on the runner's address and
# becomes Docker's DNS server (daemon.json "dns"; the embedded resolver
# forwards every name it doesn't own there). resolved answers the names
# /etc/hosts holds (the start script's line, E2E_HOSTS_IP = this address,
# where Traefik's 443 and the provider's 587 are published) and forwards
# every other name upstream as before. Nothing leaves the runner that
# didn't before (the job's port 25 / 465 / 587 rules come later).
# Writes RUNNER_IP to GITHUB_ENV.
set -euo pipefail
ALPINE=docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
ip="$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')"
[[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "FAIL: the runner's address: '$ip'"; exit 1; }
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListenerExtra=%s\n' "$ip" | sudo tee /etc/systemd/resolved.conf.d/e2e-fxa.conf >/dev/null
sudo systemctl restart systemd-resolved
cur="$(sudo cat /etc/docker/daemon.json 2>/dev/null || true)"
jq --arg ip "$ip" '. + {dns: [$ip]}' <<<"${cur:-{\}}" | sudo tee /etc/docker/daemon.json.new >/dev/null
sudo mv /etc/docker/daemon.json.new /etc/docker/daemon.json
sudo systemctl restart docker
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 2; done
docker info >/dev/null || { echo "FAIL: Docker didn't come back"; exit 1; }
# A probe name from /etc/hosts, on a user-defined network (the embedded
# resolver) and on the default bridge.
echo "$ip e2e-fxa-dns-probe.test" | sudo tee -a /etc/hosts >/dev/null
docker network create e2e-fxa-dnsprobe >/dev/null
trap 'docker network rm e2e-fxa-dnsprobe >/dev/null 2>&1 || true; sudo sed -i "/ e2e-fxa-dns-probe\.test$/d" /etc/hosts' EXIT
for net in e2e-fxa-dnsprobe bridge; do
  got="$(docker run --rm --network "$net" "$ALPINE" nslookup e2e-fxa-dns-probe.test 2>&1 || true)"
  grep -qF "Address: $ip" <<<"$got" || { echo "FAIL: a container on $net doesn't resolve /etc/hosts names to $ip: $got"; exit 1; }
done
docker run --rm --network e2e-fxa-dnsprobe "$ALPINE" nslookup github.com >/dev/null 2>&1 \
  || echo "::warning::a container couldn't resolve github.com through the runner's resolver"
echo "RUNNER_IP=$ip" >> "$GITHUB_ENV"
echo "PASS: containers resolve the runner's /etc/hosts names to $ip (systemd-resolved on $ip:53, Docker's DNS)"
