#!/usr/bin/env bash
# e2e-ha-k3d phases (ci.yml job e2e-ha-k3d; each step runs one):
#   images    the nodeagent image from the Hub checkout (HUB_SRC; CI: the
#             hub-image action's clone, else the Hub's main) and nodeadm's
#             image from this checkout with its binaries (`--build-context
#             nodeagent=…`, ruling P20) and GO_TAGS=testprovider (the
#             documentation ranges as public addresses, as the front door's
#             testprovider build)
#   init      on the k3d cluster `ha` (e2e-ha-k3d-install.sh main): .env for
#             kubernetes (K1 local images, the fake DNS provider of the
#             testprovider domains build, nodeadm on: the k3s version and
#             nodeadm's image by its digest in every node's containerd, the
#             k3s server token read from a server node into the path the
#             CLI reads it from), ./portcullis init --runtime kubernetes
#   ha        the HA switch the way `ha enable` makes it, minus its installs
#             (Longhorn, fencing: not in k3d; the replicated tier is the
#             harness's local-path class): a certificate of <d> and *.<d>
#             issued by core's own CA and named in traefik/dynamic (the
#             switch's served pair), then ha.sh's own steps volumes →
#             switch (PORTCULLIS_HA=on, up) → postgres → vault → sessions;
#             ha status after it
#   scenarios tests/e2e/e2e_ha.py (the HA scenarios; E2E_SCENARIOS)
#   sites     tests/e2e/e2e_ha.py sites (ha_dns_failover_sites, on the
#             5-server cluster `sites`)
#   collect   failure artifacts: pods, events, logs (never Secrets, .env)
# Output goes through redact (setup links); no secret is printed.
set -euo pipefail
cd "$(dirname "$0")/../.."
ctx="${E2E_HA_CONTEXT:-ha}"
K() { kubectl --context "$ctx" "$@"; }
redact() { sed -E 's#(https?://[^ ]*/invite/)[A-Za-z0-9_-]+#\1<redacted>#g'; }
fail() { echo "FAIL: $*"; exit 1; }
# shellcheck disable=SC2016  # expanded by the inner bash
CLI_LIBS='for _lib in $(sed -n "s/^for _lib in \(.*\); do\$/\1/p" portcullis); do source "scripts/lib/$_lib.sh"; done'
lib() { bash -c "$CLI_LIBS"'; need_env >/dev/null; '"$1"; }
E2E_DOMAIN="${E2E_DOMAIN:-portcullis.local}"
K3S_VERSION="v1.37.2+k3s1"

case "${1:-}" in
images)
  hub="${HUB_SRC:-$RUNNER_TEMP/portcullis-hub}"
  if [ ! -f "$hub/Dockerfile.nodeagent" ]; then
    git clone --quiet --depth=1 https://github.com/porelli/portcullis-hub "$hub"
  fi
  echo "nodeagent: built from $hub ($(git -C "$hub" rev-parse --short HEAD 2>/dev/null || echo archive))" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
  for i in 1 2 3; do
    docker buildx build --load --provenance=false -f "$hub/Dockerfile.nodeagent" -t portcullis-nodeagent:ci "$hub" && break
    [ "$i" = 3 ] && fail "the nodeagent image didn't build"
    sleep 20
  done
  docker buildx build --load --provenance=false --build-arg GO_TAGS=testprovider \
    --build-context nodeagent=docker-image://portcullis-nodeagent:ci -t portcullis-nodeadm:ci nodeadm
  echo "PASS: portcullis-nodeagent:ci, portcullis-nodeadm:ci (testprovider)"
  ;;
init)
  # nodeadm's image in every node's containerd by its digest (the CLI's own
  # import: _kube_local_import through the k3s ctr shim).
  ref="$(bash -c 'source scripts/lib/common.sh; _kube_local_import portcullis-nodeadm:ci nodeadm')"
  [[ "$ref" =~ ^localhost/portcullis-nodeadm@sha256:[0-9a-f]{64}$ ]] || fail "nodeadm's image didn't import ($ref)"
  # The k3s server token where the CLI reads it on a server (root's 0600
  # file); read from a server node over docker exec, never argv.
  srv="$(K get nodes -l node-role.kubernetes.io/control-plane=true -o jsonpath='{.items[0].metadata.name}')"
  sudo install -d -m 0700 /var/lib/rancher/k3s/server
  docker exec "$srv" cat /var/lib/rancher/k3s/server/token | sudo tee /var/lib/rancher/k3s/server/token >/dev/null
  sudo chmod 600 /var/lib/rancher/k3s/server/token
  sudo test -s /var/lib/rancher/k3s/server/token || fail "no k3s server token from $srv"
  export PORTCULLIS_TESTPROVIDER=1
  ./portcullis init --env-only --runtime kubernetes --kube-context "$ctx" --non-interactive --domain "$E2E_DOMAIN" \
    --email "ci@$E2E_DOMAIN" --dns-provider none
  # The fake provider's token: a CI test value (the testprovider build's
  # in-memory zone), in .env as any provider's credentials are.
  bash -c 'source scripts/lib/common.sh; env_set PORTCULLIS_KUBE_IMAGES local; env_set PORTCULLIS_PUBLIC_IPV4 203.0.113.11
    env_set DNS_PROVIDER fake; env_set FAKE_API_TOKEN ci-ha-fake-token-0123456789; env_set DNS_CAA false
    env_set PORTCULLIS_K3S_VERSION "$1"; env_set PORTCULLIS_NODEADM_IMAGE "$2"; env_set PORTCULLIS_TESTPROVIDER 1' _ "$K3S_VERSION" "$ref"
  printf 'tls:\n  certificates:\n    - certFile: /certs/server.crt\n      keyFile: /certs/server.key\n' > traefik/dynamic/ci-certs.yml
  ./portcullis init --runtime kubernetes --kube-context "$ctx" --non-interactive --no-config-repo 2>&1 | redact
  ./portcullis status --json > /tmp/status.json 2>/dev/null || true
  jq -c '{runtime: .runtime.name, vault: .vault.active, netpol, admission}' /tmp/status.json || true
  echo "PASS: init --runtime kubernetes on k3d (nodeadm $ref)"
  ;;
ha)
  # The switch's served pair: <d> and *.<d> exactly (_ha_cert_ok), from
  # core's CA (the root token on the vault pod's stdin; the key into a
  # 0600 file under certs/, never printed).
  root="$(jq -r .root_token secrets/vault-init.json)"; echo "::add-mask::$root"
  # shellcheck disable=SC2016  # expanded by the pod's sh
  printf '%s\n' "$root" | K -n portcullis exec -i pod/vault-0 -c vault -- sh -c 'IFS= read -r t; VAULT_TOKEN="$t" VAULT_ADDR=http://127.0.0.1:8200 exec vault write -format=json pki_int/issue/server-cert common_name="$1" alt_names="*.$1" ttl=2160h' _ "$E2E_DOMAIN" \
    > "$RUNNER_TEMP/ha-main.json"
  chmod 600 "$RUNNER_TEMP/ha-main.json"
  (umask 077 && jq -r .data.certificate "$RUNNER_TEMP/ha-main.json" > certs/ha-main.crt && jq -r .data.private_key "$RUNNER_TEMP/ha-main.json" > certs/ha-main.key)
  rm -f "$RUNNER_TEMP/ha-main.json"
  printf 'tls:\n  certificates:\n    - certFile: /certs/ha-main.crt\n      keyFile: /certs/ha-main.key\n' > traefik/dynamic/ci-ha-main.yml
  t0=$(date +%s)
  # ha enable's own steps (scripts/lib/ha.sh), its installs left out.
  lib 'ha_enable_step_volumes && ha_enable_step_switch && ha_enable_step_postgres && ha_enable_step_vault && ha_enable_step_sessions' 2>&1 | redact
  echo "HA switch: $(( $(date +%s) - t0 )) s" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
  # The CI template echo as the Hub's source (as e2e-k3s seeds it, here
  # on the replicated hub-state-r): ha_n_minus_1 makes an instance of it.
  ALPINE="docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a"
  K -n portcullis scale deploy/hub --replicas=0 >/dev/null
  K -n portcullis wait --for=delete pod -l portcullis.io/component=hub --timeout=180s >/dev/null 2>&1 || true
  pod="seed-$RANDOM"
  N="$pod" IMG="$ALPINE" jq -n '{apiVersion: "v1", kind: "Pod", metadata: {name: env.N, namespace: "portcullis", labels: {"portcullis.io/component": "volume-helper"}},
    spec: {restartPolicy: "Never", automountServiceAccountToken: false, priorityClassName: "portcullis-core",
      securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: "RuntimeDefault"}},
      containers: [{name: "c", image: env.IMG, command: ["sleep", "600"], resources: {limits: {memory: "64Mi"}, requests: {memory: "64Mi"}},
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}},
        volumeMounts: [{name: "d", mountPath: "/data"}]}], volumes: [{name: "d", persistentVolumeClaim: {claimName: "hub-state-r"}}]}}' | K create -f - >/dev/null
  K -n portcullis wait --for=condition=Ready "pod/$pod" --timeout=180s >/dev/null
  tar -cf - -C tests/e2e/apps echo | K -n portcullis exec -i "$pod" -- sh -c 'mkdir -p /data/repos/ci && tar -C /data/repos/ci -xf - &&
    { grep -q "^sources:" /data/state.yaml 2>/dev/null || printf "sources:\n  - name: ci\n    url: \"\"\n    path: /data/repos/ci\n" >> /data/state.yaml; } && chmod 600 /data/state.yaml'
  K -n portcullis delete pod "$pod" --wait=false >/dev/null
  K -n portcullis scale deploy/hub --replicas=1 >/dev/null
  K -n portcullis rollout status deploy/hub --timeout=300s
  ./portcullis ha status 2>&1 | redact || true
  K -n portcullis get pods -o wide
  echo "PASS: HA on (volumes, switch, postgres, vault, sessions)"
  ;;
scenarios)
  NODE_EXTRA_CA_CERTS="$PWD/certs/ca-chain.crt" "${E2E_PY:-/tmp/e2e-venv/bin/python}" tests/e2e/e2e_ha.py main
  ;;
sites)
  # The sites cluster (install.sh sites) is a fresh install: this
  # checkout's main install is wiped (its cluster is gone), then init and
  # the HA switch again on context sites.
  sudo rm -rf .env secrets certs templates appfiles traefik/dynamic/ci-certs.yml traefik/dynamic/ci-ha-main.yml
  git checkout -- secrets/.gitkeep 2>/dev/null || true
  E2E_HA_CONTEXT=sites bash "$0" init
  E2E_HA_CONTEXT=sites bash "$0" ha
  E2E_HA_CONTEXT=sites "${E2E_PY:-/tmp/e2e-venv/bin/python}" tests/e2e/e2e_ha.py sites
  ;;
collect)
  a="${E2E_ARTIFACTS:-e2e-artifacts}"; mkdir -p "$a"
  for c in ha sites; do
    kubectl --context "$c" get nodes -o wide > "$a/$c-nodes.txt" 2>&1 || continue
    kubectl --context "$c" get pods -A -o wide > "$a/$c-pods.txt" 2>&1 || true
    kubectl --context "$c" get events -A --sort-by=.lastTimestamp > "$a/$c-events.txt" 2>&1 || true
    for ns in portcullis portcullis-ingress portcullis-nodeadm cnpg-system portcullis-e2e; do
      for p in $(kubectl --context "$c" -n "$ns" get pods -o name 2>/dev/null); do
        kubectl --context "$c" -n "$ns" logs "$p" --all-containers --tail=300 > "$a/$c-$ns-${p#pod/}.log" 2>&1 || true
      done
    done
  done
  ./portcullis ha status --json > "$a/ha-status.json" 2>&1 || true
  # Never a setup link in an artifact.
  grep -rlE '/invite/[A-Za-z0-9_-]{16,}' "$a" 2>/dev/null | xargs -r rm -f
  ;;
*) echo "usage: $0 images|init|ha|scenarios|sites|collect" >&2; exit 2 ;;
esac
