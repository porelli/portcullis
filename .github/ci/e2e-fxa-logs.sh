#!/usr/bin/env bash
# ci.yml job e2e-fxa, step "Collect logs" (on a failure only).
#   e2e-fxa-logs.sh <dir>
# The core services e2e-mail collects, the provider's containers, the
# remote, and of firefox-sync-fxa: every container's state, the one-shots
# and the gate in full (they log counts and settings, never an address's
# code, a password or a token), the long-running services' last 200 lines
# without any line that names a code, token, password, secret, key or
# authorization (fxa-auth logs its mailer's headers, where the codes are).
set -uo pipefail
out="${1:?usage: e2e-fxa-logs.sh <dir>}"
mkdir -p "$out"
docker compose ps -a > "$out/compose-ps.txt" 2>&1
for svc in domains hub traefik keycloak group-gate; do
  docker compose logs --no-color "$svc" > "$out/$svc.log" 2>&1
done
for p in portcullis-stalwart portcullis-firefox-sync-fxa; do
  docker ps -a --filter "label=com.docker.compose.project=$p" --format '{{.Names}}\t{{.Status}}\t{{.Image}}' > "$out/$p-ps.txt" 2>&1
done
for c in $(docker ps -aq --filter label=com.docker.compose.project=portcullis-stalwart); do
  docker logs "$c" > "$out/$(docker inspect -f '{{.Name}}' "$c" | tr -d /).log" 2>&1
done
full='fxa-mail-check|fxa-db-users|fxa-db-guard|fxa-policy|fxa-keys-owner|fxa-migrations|firefox-sync-fxa-migrate|firefox-sync-fxa-db-init|firefox-sync-fxa-init|fxa-gate'
for c in $(docker ps -aq --filter label=com.docker.compose.project=portcullis-firefox-sync-fxa); do
  svc="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$c")"
  if [[ "$svc" =~ ^($full)$ ]]; then
    docker logs "$c" > "$out/fxa-$svc.log" 2>&1
  else
    docker logs --tail 200 "$c" 2>&1 | grep -viE 'code|token|passw|secret|key|authoriz|cookie|session' > "$out/fxa-$svc.log"
  fi
done
docker logs e2e-remote > "$out/remote.log" 2>&1
exit 0
