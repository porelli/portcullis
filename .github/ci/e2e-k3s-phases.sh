#!/usr/bin/env bash
# e2e-k3s phases (ci.yml job e2e-k3s; each step runs one):
#   docker   the Docker phase of the cross-runtime round trip (rootless P11):
#            init on Docker, one LLDAP person, a backup copied to
#            $RUNNER_TEMP/rt-backup (0700, never an artifact), the CA
#            chain's sha256; then down and wiped
#   init     .env for kubernetes (context ci, K1 local images), the CI TLS
#            certificate, ./portcullis init --runtime kubernetes
#   seed     the Hub's template source (tests/e2e/apps echo, folder-writer,
#            alias-echo, mcp-echo) into hub-data, the
#            fixer's /srv/e2e-k3s, an issued YubiKey certificate's serial
#   hub      tests/e2e/e2e_k3s.py through a port-forward to the Hub
#   vpn      vpn init (built-in on), a device handshake through wg-people
#            from netns ext, vpn mode admin, then the break-glass vpn mode
#            apps with the Hub at 0: the core routers' entrypoints move
#   restore  the Docker phase's backup restored onto k3s: the host's
#            kubernetes keys kept, the CA chain and rt-person the Docker
#            phase's, status clean
# Output goes through redact (setup links); no secret is printed.
set -euo pipefail
cd "$(dirname "$0")/../.."
K() { kubectl --context ci "$@"; }
redact() { sed -E 's#(https?://[^ ]*/invite/)[A-Za-z0-9_-]+#\1<redacted>#g'; }
fail() { echo "FAIL: $*"; exit 1; }
ALPINE="docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a"

status_wait() { # status_wait <seconds> — status --json clean (DNS problems allowed: portcullis.local has no records)
  local i
  for ((i = 0; i < $1; i += 10)); do
    ./portcullis status --json > /tmp/status.json 2>/dev/null || true
    if jq -e '.runtime.name == "kubernetes" and ([.runtime.checks[] | select(.status == "fail")] == [])
        and (.services | length > 0) and ([.services[] | select(.state != "running" or (.health != "healthy" and .health != "n/a"))] == [])
        and .vault.active and .netpol == "proven" and .admission == "ok"' /tmp/status.json >/dev/null 2>&1; then
      return 0
    fi
    sleep 10
  done
  jq -c '{runtime: .runtime.name, checks: [.runtime.checks[] | select(.status != "ok")], services: [.services[] | select(.health != "healthy" and .health != "n/a")], netpol, admission}' /tmp/status.json || true
  fail "status not clean after $1 s"
}

lldap_token() { # lldap_token <base> — admin's token (retried; the HTTP status on failure, never the token)
  local pw code tok out
  pw="$(grep '^LLDAP_ADMIN_PASSWORD=' .env | cut -d= -f2-)"; echo "::add-mask::$pw" >&2
  out="$(mktemp)"
  for _ in $(seq 1 30); do
    code="$(PW="$pw" jq -n '{username: "admin", password: env.PW}' \
      | curl -s -o "$out" -w '%{http_code}' --max-time 10 "$1/auth/simple/login" -H 'Content-Type: application/json' -d @- || true)"
    tok="$(jq -r '.token // empty' "$out" 2>/dev/null || true)"
    [ "$code" = 200 ] && [ -n "$tok" ] && { rm -f "$out"; printf '%s' "$tok"; return 0; }
    sleep 2
  done
  rm -f "$out"; echo "FAIL: LLDAP login as admin: HTTP ${code:-none}" >&2; return 1
}

# E2E_K3S_SKIP_DOCKER=1 (local iteration, .github/ci/e2e-k3s-local.sh):
# the Docker phase and the Docker → Kubernetes restore are skipped; CI runs
# both.
if [ "${E2E_K3S_SKIP_DOCKER:-}" = 1 ]; then
  case "${1:-}" in docker|restore) echo "SKIPPED: $1 (E2E_K3S_SKIP_DOCKER=1)"; exit 0 ;; esac
fi

case "${1:-}" in
docker)
  ./portcullis init --env-only --runtime docker --non-interactive --domain "$E2E_DOMAIN" --email "ci@$E2E_DOMAIN" --dns-provider none
  printf 'services:\n  lldap:\n    ports:\n      - "127.0.0.1:17170:17170"\n' > docker-compose.ci.yml
  printf 'tls:\n  certificates:\n    - certFile: /certs/server.crt\n      keyFile: /certs/server.key\n' > traefik/dynamic/ci-certs.yml
  COMPOSE_FILE=docker-compose.yml:docker-compose.ci.yml ./portcullis init --runtime docker --non-interactive --domain "$E2E_DOMAIN" \
    --email "ci@$E2E_DOMAIN" --dns-provider none --no-config-repo 2>&1 | redact
  bash .github/ci/lldap-create-person.sh rt-person
  COMPOSE_FILE=docker-compose.yml:docker-compose.ci.yml ./portcullis backup
  B="$(find backups -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | tail -n1)"
  jq -e '.runtime.name == "docker"' "$B/MANIFEST.json" >/dev/null || fail "the Docker backup's MANIFEST.json"
  (umask 077 && cp -r --preserve=mode,timestamps "$B" "$RUNNER_TEMP/rt-backup")
  chmod 700 "$RUNNER_TEMP/rt-backup"
  sha256sum certs/ca-chain.crt | cut -d' ' -f1 > "$RUNNER_TEMP/rt-ca.sha256"
  COMPOSE_FILE=docker-compose.yml:docker-compose.ci.yml ./portcullis down
  docker volume ls -q --filter label=com.docker.compose.project=portcullis | xargs -r docker volume rm
  sudo rm -rf .env secrets certs templates appfiles backups/2* docker-compose.ci.yml
  git checkout -- secrets/.gitkeep backups/.gitkeep
  echo "PASS: Docker phase: init, rt-person, backup (copied to \$RUNNER_TEMP/rt-backup, 0700), wiped"
  ;;
init)
  ./portcullis init --env-only --runtime kubernetes --kube-context ci --non-interactive --domain "$E2E_DOMAIN" \
    --email "ci@$E2E_DOMAIN" --dns-provider none
  for k in CONTAINER_RUNTIME=kubernetes PORTCULLIS_KUBE_CONTEXT=ci PORTCULLIS_POD_CIDR= PORTCULLIS_SERVICE_CIDR= PORTCULLIS_KUBE_INSTALL_ID=; do
    grep -q "^$k" .env || fail ".env lacks $k"
  done
  bash -c 'source scripts/lib/common.sh; env_set PORTCULLIS_KUBE_IMAGES local; env_set PORTCULLIS_PUBLIC_IPV4 198.51.100.1; env_set COMPOSE_PROFILES monitoring'
  printf 'tls:\n  certificates:\n    - certFile: /certs/server.crt\n      keyFile: /certs/server.key\n' > traefik/dynamic/ci-certs.yml
  ./portcullis init --runtime kubernetes --kube-context ci --non-interactive --no-config-repo 2>&1 | redact
  status_wait 600
  jq -c '.runtime | {name, version, context}' /tmp/status.json | tee -a "$GITHUB_STEP_SUMMARY"
  echo "PASS: init --runtime kubernetes; status clean"
  ;;
seed)
  pod="seed-$RANDOM"
  N="$pod" IMG="$ALPINE" jq -n '{apiVersion: "v1", kind: "Pod", metadata: {name: env.N, namespace: "portcullis", labels: {"portcullis.io/component": "volume-helper"}},
    spec: {restartPolicy: "Never", automountServiceAccountToken: false,
      securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: "RuntimeDefault"}},
      containers: [{name: "c", image: env.IMG, command: ["sleep", "600"], resources: {limits: {memory: "64Mi"}, requests: {memory: "64Mi"}},
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}},
        volumeMounts: [{name: "d", mountPath: "/data"}]}], volumes: [{name: "d", persistentVolumeClaim: {claimName: "hub-data"}}]}}' | K create -f - >/dev/null
  K -n portcullis wait --for=condition=Ready "pod/$pod" --timeout=180s >/dev/null
  # The CI templates (mcp-echo: an AI companion with numeric users).
  tar -cf - -C tests/e2e/apps echo folder-writer alias-echo mcp-echo | K -n portcullis exec -i "$pod" -- sh -c 'mkdir -p /data/repos/ci && tar -C /data/repos/ci -xf - &&
    printf "sources:\n  - name: ci\n    url: \"\"\n    path: /data/repos/ci\n" > /data/state.yaml && chmod 600 /data/state.yaml'
  K -n portcullis delete pod "$pod" --wait=false >/dev/null
  K -n portcullis rollout restart deploy/hub >/dev/null
  K -n portcullis rollout status deploy/hub --timeout=300s
  sudo rm -rf "$E2E_FOLDER"; sudo install -d -o 1000 -g 1000 -m 0750 "$E2E_FOLDER"
  for f in 1 2 3; do echo "k3s $f" | sudo tee "$E2E_FOLDER/file-$f.txt" >/dev/null; done
  # A YubiKey-CA certificate to revoke (the root token on the vault pod's
  # stdin, never argv); its serial for the revocation SLA.
  root="$(jq -r .root_token secrets/vault-init.json)"; echo "::add-mask::$root"
  # shellcheck disable=SC2016  # expanded by the pod's sh
  serial="$(printf '%s\n' "$root" | K -n portcullis exec -i deploy/vault -c vault -- sh -c 'IFS= read -r t; VAULT_TOKEN="$t" VAULT_ADDR=http://127.0.0.1:8200 exec vault write -format=json pki_int/issue/client-cert common_name=rt-revoke ttl=1h' | jq -r '.data.serial_number')"
  [[ "$serial" =~ ^[0-9a-f:]+$ ]] || fail "could not issue a certificate to revoke"
  echo "E2E_REVOKE_SERIAL=$serial" >> "$GITHUB_ENV"
  echo "PASS: the Hub's template source (echo, folder-writer) seeded; $E2E_FOLDER ready; certificate $serial issued"
  ;;
hub)
  # The forward binds one pod when it starts: wait until the Hub's rollout
  # (the assertions' `./portcullis up`) is done, or it may be a terminating one.
  K -n portcullis rollout status deploy/hub --timeout=300s >/dev/null || fail "the Hub's rollout didn't finish"
  K -n portcullis wait --for=condition=Available deploy/hub --timeout=300s >/dev/null || fail "the Hub isn't available"
  pf_log="$(mktemp)"
  K -n portcullis port-forward --address 127.0.0.1 svc/hub :8888 > "$pf_log" 2>&1 &
  for i in $(seq 1 50); do grep -q 'Forwarding from' "$pf_log" && break; sleep 0.2; done
  port="$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) .*/\1/p' "$pf_log" | head -n1)"
  [ -n "$port" ] || fail "no port-forward to the Hub"
  sec="$(grep '^HUB_PROXY_SECRET=' .env | cut -d= -f2-)"; echo "::add-mask::$sec"
  HUB_API="http://127.0.0.1:$port" E2E_HUB_SECRET="$sec" python3 tests/e2e/e2e_k3s.py
  ;;
vpn)
  ./portcullis vpn init --builtin on --port 51820 2>&1 | redact
  K -n portcullis get svc wg-people -o json | jq -e '.spec.type == "LoadBalancer" and .spec.externalTrafficPolicy == "Local" and ([.spec.ports[].protocol] == ["UDP"])' >/dev/null \
    || fail "wg-people isn't a UDP-only LoadBalancer with externalTrafficPolicy Local"
  K -n portcullis get svc traefik -o json | jq -e '[.spec.ports[].port] == [80, 443]' >/dev/null || fail "the traefik LoadBalancer has ports beyond 80 / 443"
  ep() { K -n portcullis-edge get ingressroute "$1" -o jsonpath='{.spec.entryPoints}'; }
  [ "$(ep hub)" = '["websecure"]' ] || fail "apps mode: the hub router's entrypoints are $(ep hub)"
  ./portcullis vpn mode admin --force 2>&1 | redact
  [ "$(ep hub)" = '["parked"]' ] && [ "$(ep hub-vpn)" = '["vpnsecure"]' ] || fail "admin mode: hub $(ep hub), hub-vpn $(ep hub-vpn)"
  K -n portcullis scale deploy/hub --replicas=0 >/dev/null
  ./portcullis vpn mode apps 2>&1 | redact
  [ "$(ep hub)" = '["websecure"]' ] || fail "break-glass vpn mode apps with the Hub at 0: hub $(ep hub)"
  K -n portcullis get deploy group-gate -o json | jq -e '.spec.template.spec.containers[0].env[] | select(.name == "GATE_VPN_MODE") | .value == "apps"' >/dev/null \
    || fail "group-gate's GATE_VPN_MODE isn't apps after the break-glass"
  K -n portcullis scale deploy/hub --replicas=1 >/dev/null
  echo "PASS: vpn init (wg-people UDP LB, ETP Local), vpn mode admin parks the hub router, break-glass vpn mode apps with the Hub at 0"
  ;;
restore)
  ./portcullis restore --yes "$RUNNER_TEMP/rt-backup" 2>&1 | redact
  grep -qx 'CONTAINER_RUNTIME=kubernetes' .env && grep -qx 'PORTCULLIS_KUBE_CONTEXT=ci' .env || fail "restore didn't keep this host's kubernetes keys"
  status_wait 600
  [ "$(sha256sum certs/ca-chain.crt | cut -d' ' -f1)" = "$(cat "$RUNNER_TEMP/rt-ca.sha256")" ] || fail "the CA chain isn't the Docker phase's"
  pf_log="$(mktemp)"
  K -n portcullis port-forward --address 127.0.0.1 svc/lldap :17170 > "$pf_log" 2>&1 &
  for i in $(seq 1 50); do grep -q 'Forwarding from' "$pf_log" && break; sleep 0.2; done
  port="$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) .*/\1/p' "$pf_log" | head -n1)"
  tok="$(lldap_token "http://127.0.0.1:$port")" || exit 1; echo "::add-mask::$tok"
  jq -n '{query: "{ user(userId: \"rt-person\") { id } }"}' | curl -sf "http://127.0.0.1:$port/api/graphql" -H @<(printf 'Authorization: Bearer %s\n' "$tok") \
    -H 'Content-Type: application/json' -d @- | jq -e '.data.user.id == "rt-person"' >/dev/null || fail "rt-person isn't in the restored LLDAP"
  echo "PASS: Docker → Kubernetes restore: host keys kept, status clean, the CA chain and rt-person are the Docker phase's"
  ;;
*) echo "usage: $0 docker|init|seed|hub|vpn|restore" >&2; exit 2 ;;
esac
