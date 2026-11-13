#!/usr/bin/env bash
# ci.yml job build-and-test, step "Test the Hub (non-root, socket proxy, proxy secret)".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
if [ -z "${HUB_LOCAL:-}" ] && ! docker compose pull --quiet hub; then
  echo "::warning::Hub image $(docker compose config --format json | jq -r .services.hub.image) cannot be pulled — skipping the Hub test"
  exit 0
fi
# The Hub's admin routes (GET /api/signin here, the sign-in API in
# reset-core's step) check the actor in LLDAP with the Hub's service
# account, which `portcullis up` reconciles later in this job: set
# it up now with the same function.
# shellcheck disable=SC1090
PORTCULLIS_LIB="$PWD/scripts/lib" bash -c 'set -euo pipefail
  for l in common network vault pki certs keycloak users domains mcpgate dns config status monitoring backup signin stack; do
    source "$PORTCULLIS_LIB/$l.sh"
  done
  lldap_service_account' | tee /tmp/hub-sa.out
grep -qE 'portcullis-hub: password (matches|set from) secrets/hub/lldap/password' /tmp/hub-sa.out \
  || { echo "FAIL: the Hub's LLDAP service account"; exit 1; }
docker compose up -d hub
HUB_CID="$(docker compose ps -q hub)"
test "$(docker inspect -f '{{json .HostConfig.Binds}}' "$HUB_CID" | grep -c docker.sock)" = 0 || { echo "FAIL: hub mounts docker.sock"; exit 1; }
HUB_IP=$(docker inspect -f '{{(index .NetworkSettings.Networks "portcullis").IPAddress}}' "$HUB_CID")
for i in $(seq 1 30); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://$HUB_IP:8888/healthz")" = 200 ] && break
  [ "$i" -eq 30 ] && { echo "FAIL: hub /healthz"; docker compose logs --tail=40 hub; exit 1; }
  sleep 2
done
code=$(curl -s -o /dev/null -w '%{http_code}' "http://$HUB_IP:8888/")
case "$code" in 401|403) ;; *) echo "FAIL: hub without proxy secret got $code"; exit 1 ;; esac
SECRET="$(grep '^HUB_PROXY_SECRET=' .env | cut -d= -f2-)"
code=$(curl -s -o /dev/null -w '%{http_code}' -H @<(printf 'X-Portcullis-Proxy-Secret: %s\n' "$SECRET") "http://$HUB_IP:8888/")
case "$code" in 401|403|000) echo "FAIL: hub WITH proxy secret got $code"; docker compose logs --tail=20 hub; exit 1 ;; esac
docker compose exec -T hub sh -c 'test "$(id -u)" = 10001 && test -w /project/templates && test -w /project/appfiles && ! grep -q POSTGRES_PASSWORD /project/.env && docker version >/dev/null' \
  || { echo "FAIL: hub runtime (uid / templates / env subset / DOCKER_HOST)"; docker compose logs --tail=20 hub; exit 1; }
echo "PASS: Hub runs as 10001 without the socket, sees only the env subset, enforces the proxy secret"

# Template sources: the Hub synced them at start (status file) and
# syncs again on SIGHUP — what `./portcullis upgrade` does (hub_sources_sync).
OUT="$(bash -c 'source scripts/lib/common.sh; source scripts/lib/status.sh; hub_sources_sync 40' 2>&1)"
echo "$OUT"
echo "$OUT" | grep -q 'template source portcullis: \(updated to\|up to date\)' \
  || { echo "FAIL: upgrade's template sync"; docker compose logs --tail=30 hub; exit 1; }
docker compose exec -T hub cat /data/source-sync.json | jq -e '.trigger == "signal" and .ok and (.running | not)' >/dev/null \
  || { echo "FAIL: source-sync.json: $(docker compose exec -T hub cat /data/source-sync.json)"; exit 1; }
[ "$(docker inspect -f '{{.State.Running}} {{.RestartCount}}' "$HUB_CID")" = "true 0" ] || { echo "FAIL: the Hub did not survive SIGHUP"; exit 1; }
docker compose logs hub | grep -q 'sync on SIGHUP finished (ok=true)' || { echo "FAIL: no SIGHUP sync in the Hub log"; exit 1; }
echo "PASS: the Hub syncs its template sources at start and on SIGHUP; upgrade prints the result"

# Product default (contract §4, §8.1): on a fresh install the Hub
# publishes policy file v7 with the four starting methods, Standard
# (any passkey or a YubiKey certificate) the default and Strong
# (security key or certificate) on hub / people, and group-gate
# applies the default to every app host without its own pick — here
# the ci-gated test app.
hubapi() { curl -s -H @<(printf 'X-Portcullis-Proxy-Secret: %s\nX-Forwarded-User: admin\n' "$SECRET") "$@"; }
policy_file() { docker run --rm -v portcullis_hub_data:/d:ro docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a cat /d/group-gate-policy.json 2>/dev/null; }
gated() { curl -s -o /dev/null -w '%{http_code}' --cacert certs/ca-chain.crt \
            --resolve "gated.portcullis.local:443:127.0.0.1" -H 'X-Auth-Request-Preferred-Username: testuser' \
            --cert /tmp/test-client.crt --key /tmp/test-client.key "$@" https://gated.portcullis.local/ || true; }
STANDARD='{"op":"any","items":[{"op":"any","items":["passkey_synced","passkey_device","security_key"]},{"op":"any","items":["yubikey_cert"]}]}'
for i in $(seq 1 30); do
  policy_file | jq -e --argjson std "$STANDARD" '.version == 7 and .methods == ["passkey_device", "passkey_synced", "security_key", "yubikey_cert"]
      and .default == "standard" and .templates.standard == $std
      and .templates.strong == {op: "any", items: ["security_key", "yubikey_cert"]}
      and .core["hub.portcullis.local"] == "strong" and .core["people.portcullis.local"] == "strong"
      and .core["portcullis.local"] == "standard" and (.extra_domains | type) == "array" and .add_stronger == false' >/dev/null 2>&1 && break
  [ "$i" -eq 30 ] && { echo "FAIL: the Hub did not publish the fresh-install v7 policy: $(policy_file)"; docker compose logs --tail=20 hub; exit 1; }
  sleep 2
done
hubapi "http://$HUB_IP:8888/api/signin" | jq -e '.default == "standard" and ([.methods[] | select(.on) | .id] | sort) == ["passkey_device", "passkey_synced", "security_key", "yubikey_cert"]' >/dev/null \
  || { echo "FAIL: GET /api/signin on a fresh Hub: $(hubapi "http://$HUB_IP:8888/api/signin" | head -c 600)"; exit 1; }
# Log lines are counted before and after each request: the mTLS
# step already logged the same kind of line for this host.
gg_count() { docker compose logs group-gate > /tmp/gg.log 2>&1; grep -cE "$1" /tmp/gg.log || true; }
gg_grew() { local i; for i in $(seq 1 10); do [ "$(gg_count "$1")" -gt "$2" ] && return 0; sleep 1; done; return 1; }
STEP_RE='STEPUP user=testuser host=gated\.portcullis\.local amr=\[\] have=\[\] pc_method=(passkey|passkey_synced|passkey_device|security_key|yubikey_cert)$'
n0=$(gg_count "$STEP_RE")
code=$(gated)
[ "$code" = 403 ] || { echo "FAIL: gated app under the Standard default without a session got $code"; exit 1; }
gg_grew "$STEP_RE" "$n0" \
  || { echo "FAIL: group-gate did not step up under the Standard default"; docker compose logs --tail=10 group-gate; exit 1; }
for t in "$CI_TOKEN_SPK" "$CI_TOKEN_HWK" "$CI_TOKEN_MTLS"; do
  [ "$(gated -H "X-Forwarded-Access-Token: $t")" = 200 ] || { echo "FAIL: a session meeting Standard denied: $(gated -H "X-Forwarded-Access-Token: $t")"; exit 1; }
done
echo "PASS: fresh Hub publishes policy v7 (Standard the default, Strong on hub / people); group-gate steps up apps without their own pick"

# An admin change through the sign-in API reaches group-gate: Strong
# as the default refuses the synced passkey (the step-up asks for a
# security key or the certificate, or needs-stronger when the Hub's
# inventory knows testuser has neither) and keeps the YubiKey
# certificate; then back to Standard.
setdef() { printf '{"template":"%s"}' "$1" | hubapi -o /tmp/setdef.json -w '%{http_code}' -X PUT -H 'Content-Type: application/json' \
             --data-binary @- "http://$HUB_IP:8888/api/signin/default"; }
STRONG_RE="(STEPUP|NEEDS-STRONGER) user=testuser host=gated\\.portcullis\\.local amr=\\['spk'\\] have=\\['passkey_synced'\\] (pc_method=(security_key|yubikey_cert)|set_up=.*)$"
n0=$(gg_count "$STRONG_RE")
[ "$(setdef strong)" = 200 ] || { echo "FAIL: PUT /api/signin/default strong: $(head -c 400 /tmp/setdef.json)"; exit 1; }
for i in $(seq 1 30); do
  policy_file | jq -e '.default == "strong"' >/dev/null 2>&1 && [ "$(gated -H "X-Forwarded-Access-Token: $CI_TOKEN_SPK")" = 403 ] && break
  [ "$i" -eq 30 ] && { echo "FAIL: group-gate does not enforce the Strong default: $(policy_file)"; docker compose logs --tail=10 group-gate; exit 1; }
  sleep 2
done
gg_grew "$STRONG_RE" "$n0" \
  || { echo "FAIL: no step-up / needs-stronger page for a synced session under Strong"; docker compose logs --tail=10 group-gate; exit 1; }
[ "$(gated -H "X-Forwarded-Access-Token: $CI_TOKEN_MTLS")" = 200 ] || { echo "FAIL: a bound mtls session denied under Strong"; exit 1; }
[ "$(gated -H "X-Forwarded-Access-Token: $CI_TOKEN_HWK")" = 200 ] || { echo "FAIL: a security-key session denied under Strong"; exit 1; }
[ "$(setdef standard)" = 200 ] || { echo "FAIL: PUT /api/signin/default standard: $(head -c 400 /tmp/setdef.json)"; exit 1; }
for i in $(seq 1 30); do
  policy_file | jq -e '.default == "standard"' >/dev/null 2>&1 && [ "$(gated -H "X-Forwarded-Access-Token: $CI_TOKEN_SPK")" = 200 ] && break
  [ "$i" -eq 30 ] && { echo "FAIL: group-gate still enforces Strong: $(policy_file)"; exit 1; }
  sleep 2
done
echo "PASS: an admin's default change (PUT /api/signin/default) is published and enforced by group-gate"
