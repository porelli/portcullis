#!/usr/bin/env bash
# ci.yml job e2e-ssh, step "Collect logs (secret-scanned)": the stack's and
# the SSH servers' logs into e2e-artifacts/, then a scan that empties the
# directory if anything looks like a secret (an enrolment code, a private
# key, a JWT): logs only, never a key, code or token.
set -uo pipefail
mkdir -p e2e-artifacts
docker compose ps -a > e2e-artifacts/compose-ps.txt 2>&1 || true
for svc in traefik keycloak forward-auth group-gate hub enroll vault; do
  docker compose logs --no-color "$svc" > "e2e-artifacts/$svc.log" 2>&1 || true
done
for h in web-1 web-2; do
  docker logs "e2e-$h" > "e2e-artifacts/sshd-$h.log" 2>&1 || true
done
# web-1's Portcullis state as sshd sees it (names and principals only).
# shellcheck disable=SC2016  # expanded in the container
docker exec e2e-web-1 sh -c 'ls -la /etc/ssh/portcullis /etc/ssh/portcullis/principals
  for f in /etc/ssh/portcullis/principals/*; do echo "$f: $(cat "$f")"; done
  getent passwd alice bob deploy; passwd -S alice deploy; chage -l alice
  sshd -T -C user=alice,host=x,addr=127.0.0.1 | grep -iE "principals|trusted|revoked|pubkeyauth|usepam|authorizedkeysfile"
  wc -l /etc/ssh/portcullis/revoked_keys' > e2e-artifacts/host-web-1.txt 2>&1 || true
if grep -rlE 'pcenrol1\.|PRIVATE KEY|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.' e2e-artifacts/; then
  echo "::error::a secret-looking value in the logs: artifacts withheld"
  rm -rf e2e-artifacts/*
  echo "withheld: a secret-looking value was found" > e2e-artifacts/WITHHELD.txt
fi
exit 0
