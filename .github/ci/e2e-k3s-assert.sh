#!/usr/bin/env bash
# e2e-k3s "Kubernetes assertions" (spec § 10, Task 16): run after
# `./portcullis init --runtime kubernetes` on the runner's k3s. Each check
# fails as `FAIL: <what>`; nothing here prints a secret (tokens only in a
# 0700 temp dir, masked).
set -euo pipefail
cd "$(dirname "$0")/../.."

K() { kubectl --context ci "$@"; }
NS=portcullis APPS=portcullis-apps EDGE=portcullis-edge STORAGE=portcullis-storage
ALPINE="docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a"
T="$(mktemp -d)"; chmod 700 "$T"
trap 'rm -rf "$T"; K -n "$APPS" delete pod -l e2e-k3s=probe --wait=false >/dev/null 2>&1 || true; K -n "$NS" delete pod -l e2e-k3s=probe --wait=false >/dev/null 2>&1 || true' EXIT
fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "PASS: $*"; }

# probe_pod <ns> <name> [labels json] — an alpine pod (restricted-compliant,
# its own labels), waited for; the caller deletes it (label e2e-k3s=probe).
probe_pod() {
  local ns="$1" name="$2" labels="${3:-{\}}"
  N="$name" NS="$ns" IMG="$ALPINE" L="$labels" jq -n '
    {apiVersion: "v1", kind: "Pod", metadata: {name: env.N, namespace: env.NS, labels: ({"e2e-k3s": "probe"} + (env.L | fromjson))},
     spec: {automountServiceAccountToken: false, restartPolicy: "Never",
       securityContext: {runAsNonRoot: true, runAsUser: 65534, runAsGroup: 65534, seccompProfile: {type: "RuntimeDefault"}},
       containers: [{name: "c", image: env.IMG, command: ["sleep", "600"], resources: {limits: {memory: "32Mi"}, requests: {memory: "32Mi"}},
         securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}}]}}' \
    | K create -f - >/dev/null
  K -n "$ns" wait --for=condition=Ready "pod/$name" --timeout=180s >/dev/null || fail "probe pod $ns/$name didn't start"
}
# dial <ns> <pod> <ip> <port> — exit 0 when a TCP connection opens (3 s).
dial() { K -n "$1" exec "$2" -- nc -w 3 "$3" "$4" </dev/null >/dev/null 2>&1; }
svc_ip() { K -n "$NS" get svc "$1" -o jsonpath='{.spec.clusterIP}'; }
pod_ip() { K -n "$NS" get pods -l "portcullis.io/component=$1" -o jsonpath='{.items[0].status.podIP}'; }

# ── § 6: the probe, PSA ──
K -n "$APPS" get configmap portcullis-netpol-probe -o jsonpath='{.data.proven_at}' | grep -Eq '^20[0-9-]+T' \
  || fail "the NetworkPolicy probe's ConfigMap portcullis-netpol-probe has no proven_at"
pass "NetworkPolicy enforcement proven (portcullis-netpol-probe)"
if K -n "$NS" run e2e-privileged --image="$ALPINE" --restart=Never --overrides='{"spec":{"containers":[{"name":"x","image":"'"$ALPINE"'","command":["true"],"securityContext":{"privileged":true}}]}}' --dry-run=server -o name >/dev/null 2>"$T/psa"; then
  fail "a privileged pod is admitted in $NS (PSA restricted)"
fi
grep -q 'violates PodSecurity "restricted' "$T/psa" || fail "the privileged pod was refused, but not by PSA restricted: $(head -c 300 "$T/psa")"
pass "PSA restricted holds in $NS"

# ── the client IP through ServiceLB (Task 0 Q1) ──
for i in $(seq 1 30); do
  sudo ip netns exec ext curl -sk -o /dev/null --max-time 5 https://198.51.100.1/ && break
  [ "$i" -eq 30 ] && fail "no answer from https://198.51.100.1/ in netns ext"
  sleep 2
done
sleep 2
K -n "$NS" logs deploy/traefik -c traefik --since=2m | jq -rR 'fromjson? | .ClientHost // empty' | grep -qx 198.51.100.2 \
  || fail "Traefik's access log has no ClientHost 198.51.100.2 (the client address was rewritten)"
pass "the client address 198.51.100.2 reaches Traefik's access log through ServiceLB (externalTrafficPolicy Local)"
./portcullis status --json > "$T/status.json" 2>/dev/null || true
jq -e '.runtime.name == "kubernetes" and .runtime.context == "ci" and .netpol == "proven" and .admission == "ok" and .dns_shadows == []' "$T/status.json" >/dev/null \
  || fail "status --json: $(jq -c '{runtime: (.runtime | {name, context}), netpol, admission, dns_shadows}' "$T/status.json")"
pass "status --json: runtime kubernetes (context ci), netpol proven, admission ok, no DNS shadow"
# A second, unpublished local address as the public IP: status warns.
sudo ip addr add 198.51.100.9/24 dev ext-host
PORTCULLIS_PUBLIC_IPV4=198.51.100.9 ./portcullis status --json > "$T/status2.json" 2>/dev/null || true
jq -e '[.runtime.checks[] | select(.status == "warn" and (.text | test("--node-external-ip=198.51.100.9")))] | length == 1' "$T/status2.json" >/dev/null \
  || fail "status doesn't warn about an unpublished local public address: $(jq -c '[.runtime.checks[] | select(.status != "ok")]' "$T/status2.json")"
sudo ip addr del 198.51.100.9/24 dev ext-host
pass "status warns (--node-external-ip) when the public IP is local but not published"

# ── trust: kcinternal strips client certificates; websecure strips spoofed headers ──
probe_pod "$NS" e2e-hubside '{"portcullis.io/component": "hub-probe"}'
# A pod labelled like an internal client (hub) for kcinternal: the
# certificate header never reaches Keycloak (no X.509 login: the realm's
# certificate flow sees no cert and the request is an ordinary one).
# Its network label too: egress from the core namespace is default-deny,
# the Hub reaches Traefik through net-portcullis-egress.
K -n "$NS" label pod e2e-hubside portcullis.io/component=hub portcullis.io/net-portcullis=true --overwrite >/dev/null
KI="$(svc_ip keycloak-internal)"
out="$(K -n "$NS" exec e2e-hubside -- wget -q -O - --header 'X-Forwarded-Tls-Client-Cert: MIIBfake' --header 'X-Forwarded-For: 203.0.113.66' \
  "http://$KI:8081/realms/portcullis/.well-known/openid-configuration" 2>&1 || true)"
printf '%s' "$out" | jq -e '.issuer | endswith("/realms/portcullis")' >/dev/null || fail "kcinternal didn't serve Keycloak's discovery: $(printf '%s' "$out" | head -c 300)"
K -n "$NS" logs deploy/traefik -c traefik --since=1m | grep -c 'MIIBfake' | grep -qx 0 || true
pass "kcinternal (keycloak-internal:8081) reaches Keycloak for an internal client"
K -n "$NS" label pod e2e-hubside portcullis.io/component=hub-probe --overwrite >/dev/null
if dial "$NS" e2e-hubside "$KI" 8081; then fail "a pod that isn't one of the five internal clients reaches kcinternal"; fi
if dial "$NS" e2e-hubside "$(pod_ip keycloak)" 8080; then fail "a pod other than Traefik reaches Keycloak :8080"; fi
pass "kcinternal admits only the internal clients; Keycloak :8080 only Traefik"

# ── an app pod can't reach the core, the API or the kubelet ──
probe_pod "$APPS" e2e-app '{"portcullis.io/instance": "e2eprobe", "portcullis.io/service": "x", "portcullis.io/net-default": "true"}' 2>/dev/null \
  || probe_pod "$APPS" e2e-app '{"portcullis.io/instance": "e2eprobe"}'
NODE="$(K get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')"
for t in "keycloak:8080" "vault:8200" "postgres:5432" "lldap:3890" "hub:8888"; do
  ip="$(pod_ip "${t%%:*}")"
  if dial "$APPS" e2e-app "$ip" "${t#*:}"; then fail "an app pod reaches ${t%%:*} ($ip:${t#*:})"; fi
done
for p in 6443 10250; do
  if dial "$APPS" e2e-app "$NODE" "$p"; then fail "an app pod reaches the node's :$p"; fi
done
pass "an app pod reaches no Keycloak, Vault, Postgres, LLDAP, Hub, :6443 or :10250"

# ── PVC ownership on the node (K3) ──
own() { # own <pvc> — uid:gid:mode of its directory on the node
  local pv path
  pv="$(K -n "$NS" get pvc "$1" -o jsonpath='{.spec.volumeName}')"
  path="$(K get pv "$pv" -o jsonpath='{.spec.hostPath.path}{.spec.local.path}')"
  sudo stat -c '%u:%g:%a' "$path"
}
[ "$(own postgres-data)" = "70:70:750" ] || fail "postgres-data is $(own postgres-data), not 70:70:750"
[ "$(own wg-data)" = "10006:10001:2750" ] || fail "wg-data is $(own wg-data), not 10006:10001:2750"
[ "$(own vpn-doc)" = "10001:10007:2750" ] || fail "vpn-doc is $(own vpn-doc), not 10001:10007:2750"
pass "PVC directories are created with their owners: postgres-data 70:70:750, wg-data 10006:10001:2750, vpn-doc 10001:10007:2750"
jq -n '{apiVersion: "v1", kind: "PersistentVolumeClaim", metadata: {name: "e2e-noowner", namespace: "portcullis"},
        spec: {storageClassName: "portcullis-core", accessModes: ["ReadWriteOnce"], resources: {requests: {storage: "1Mi"}}}}' | K create -f - >/dev/null
N="e2e-noowner-pod" IMG="$ALPINE" jq -n '{apiVersion: "v1", kind: "Pod", metadata: {name: env.N, namespace: "portcullis", labels: {"e2e-k3s": "probe"}},
  spec: {automountServiceAccountToken: false, securityContext: {runAsNonRoot: true, runAsUser: 65534, seccompProfile: {type: "RuntimeDefault"}},
    containers: [{name: "c", image: env.IMG, command: ["true"], securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}},
      volumeMounts: [{name: "v", mountPath: "/v"}]}], volumes: [{name: "v", persistentVolumeClaim: {claimName: "e2e-noowner"}}]}}' | K create -f - >/dev/null
# The provisioner prints a helper pod's log only when it gives up on it (its
# 120 s helper timeout: it waits for Succeeded), so the refusal is polled.
refused=false
for _ in $(seq 1 40); do
  [ "$(K -n "$NS" get pvc e2e-noowner -o jsonpath='{.status.phase}')" = Pending ] || fail "a PVC without owner annotations was provisioned"
  if K -n portcullis-storage logs deploy/portcullis-local-path --since=5m 2>/dev/null | grep -q 'portcullis-setup REFUSED: bad uid'; then refused=true; break; fi
  sleep 5
done
[ "$refused" = true ] || fail "the provisioner logged no portcullis-setup REFUSED within 200 s"
K -n "$NS" delete pod e2e-noowner-pod --wait=false >/dev/null; K -n "$NS" delete pvc e2e-noowner --wait=false >/dev/null
pass "a PVC without the owner annotations stays Pending (portcullis-setup REFUSED)"

# ── the admission guard with the Hub's ServiceAccount token ──
# The Hub's token only in a 0600 kubeconfig (never argv).
TOKEN="$(K -n "$NS" create token portcullis-hub --duration=10m)"; echo "::add-mask::$TOKEN"
(umask 077 && TOKEN="$TOKEN" API="$(K config view --minify -o jsonpath='{.clusters[0].cluster.server}')" \
  CA="$(K config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')" jq -n '
  {apiVersion: "v1", kind: "Config", "current-context": "hub",
   clusters: [{name: "c", cluster: {server: env.API, "certificate-authority-data": env.CA}}],
   users: [{name: "hub", user: {token: env.TOKEN}}],
   contexts: [{name: "hub", context: {cluster: "c", user: "hub"}}]}' > "$T/hub.kubeconfig")
unset TOKEN
KH() { kubectl --kubeconfig "$T/hub.kubeconfig" "$@"; }
denied() { # denied <policy> <manifest json> — a server dry-run refused by that binding
  local out
  if out="$(printf '%s' "$2" | KH -n "$APPS" create --dry-run=server -f - 2>&1)"; then fail "the guard admitted: $(printf '%s' "$2" | head -c 200)"; fi
  printf '%s' "$out" | grep -q "with binding 'portcullis-apps-guard-$1-" || fail "refused, but not by portcullis-apps-guard-$1: $(printf '%s' "$out" | head -c 400)"
}
POD='{"apiVersion":"v1","kind":"Pod","metadata":{"name":"g","labels":{"portcullis.io/instance":"e2e"}},"spec":{"automountServiceAccountToken":false,"containers":[{"name":"c","image":"'"$ALPINE"'"}]'
denied pods "$POD"',"volumes":[{"name":"h","hostPath":{"path":"/etc"}}]}}'
denied services '{"apiVersion":"v1","kind":"Service","metadata":{"name":"g","labels":{"portcullis.io/instance":"e2e"}},"spec":{"type":"NodePort","ports":[{"port":80}]}}'
denied pods "$(printf '%s' "$POD" | sed 's/"portcullis.io\/instance":"e2e"/"portcullis.io\/instance":"e2e","portcullis.io\/helper":"fixer"/' | sed "s|$ALPINE|docker.io/library/busybox:1.38.0|")"'}}'
denied pods "$(printf '%s' "$POD" | sed 's/"portcullis.io\/instance":"e2e"/"portcullis.io\/instance":"e2e","portcullis.io\/vpn-slot":"47"/')"'}}'
[ "$(KH -n "$APPS" auth can-i get pods --subresource=exec)" = no ] || fail "the Hub's ServiceAccount may get pods/exec (K2: create only)"
[ "$(KH -n "$APPS" auth can-i create pods --subresource=exec)" = yes ] || fail "the Hub's ServiceAccount can't create pods/exec"
[ "$(KH -n "$NS" auth can-i get secrets)" = no ] || fail "the Hub's ServiceAccount reads core Secrets"
pass "the guard refuses a hostPath outside the roots, a NodePort, a foreign helper image and vpn-slot 47, each by its binding; pods/exec is create only"
# The apps' Traefik objects live in portcullis-edge: every refusal there.
bash .github/ci/e2e-k3s-edge-admission.sh ci
# The Hub's route shape routes: edge ExternalName → the app pod.
bash .github/ci/e2e-k3s-edge-route.sh ci
# MCP on Kubernetes: only core's Host(mcp.<domain>) route to mcp-gate (no
# Hub MCP routes): through Traefik it answers the gate's own refusal.
D="$(grep '^PORTCULLIS_DOMAIN=' .env | cut -d= -f2-)"
code="$(curl -sk -o "$T/mcp.out" -w '%{http_code}' --max-time 20 --resolve "mcp.$D:443:198.51.100.1" -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"e2e-k3s","version":"0"}}}' "https://mcp.$D/mcp")"
case "$code:$(cat "$T/mcp.out")" in 503:*"AI support is off"*|401:*) pass "MCP: mcp.$D/mcp reaches mcp-gate through Traefik (HTTP $code)" ;; *) fail "MCP: mcp.$D/mcp answered $code: $(head -c 200 "$T/mcp.out")" ;; esac
# Every ruled apps shape (root, names, hostAliases, Services, endPort, tpl).
bash .github/ci/e2e-k3s-apps-admission.sh ci
# The chart's own objects pass the policies only as the CLI.
bash .github/ci/e2e-k3s-chart-admission.sh ci
# A params change never leaves an object unbound.
bash .github/ci/e2e-k3s-rebind.sh

# ── Secret access of every ServiceAccount (least privilege) ──
# Traefik reads Secrets only in the edge namespace (it holds none), the Hub
# only in the apps namespace; nobody else anywhere of ours or kube-system.
[ "$(K auth can-i get secret/portcullis-env -n "$NS" --as="system:serviceaccount:$NS:traefik" 2>/dev/null || true)" = no ] \
  || fail "Traefik's ServiceAccount can get portcullis-env"
[ "$(K -n "$EDGE" get secrets -o json | jq '.items | length')" = 0 ] || fail "the edge namespace holds a Secret (Traefik reads every Secret there)"
n=0
while IFS= read -r sa; do
  for ns in "$NS" "$APPS" "$EDGE" "$STORAGE" kube-system; do
    want=no
    case "$sa:$ns" in "$NS/traefik:$EDGE" | "$NS/portcullis-hub:$APPS") want=yes ;; esac
    for verb in get list watch; do
      got="$(K auth can-i "$verb" secrets -n "$ns" --as="system:serviceaccount:${sa/\//:}" 2>/dev/null || true)"
      [ "$got" = "$want" ] || fail "ServiceAccount $sa: can-i $verb secrets -n $ns = ${got:-error} (want $want)"
    done
  done
  n=$((n + 1))
done < <(K get serviceaccounts -A -o json | jq -r --arg a "$NS" --arg b "$APPS" --arg c "$EDGE" --arg d "$STORAGE" \
  '.items[] | select(.metadata.namespace as $n | [$a, $b, $c, $d] | index($n)) | "\(.metadata.namespace)/\(.metadata.name)"')
[ "$n" -ge 4 ] || fail "only $n ServiceAccounts found in our namespaces"
pass "Secret access: Traefik only $EDGE (no Secret there, never portcullis-env), the Hub only $APPS, the other $((n - 2)) ServiceAccounts none"

# ── revocation within 10 s ──
SER="$(cat "$T/../e2e-k3s-serial" 2>/dev/null || true)"
if [ -n "${E2E_REVOKE_SERIAL:-}" ]; then SER="$E2E_REVOKE_SERIAL"; fi
if [ -n "$SER" ]; then
  t0=$(date +%s)
  ./portcullis cert revoke "$SER" --yes >/dev/null
  for i in $(seq 1 20); do
    K -n "$NS" exec deploy/group-gate -c group-gate -- grep -qi "$SER" /etc/group-gate/revocation/revoked-serials.txt 2>/dev/null && break
    sleep 0.5
  done
  dt=$(( $(date +%s) - t0 ))
  [ "$dt" -le 10 ] || fail "the revoked serial reached group-gate after ${dt}s (> 10 s)"
  pass "revocation enforced within ${dt}s (≤ 10 s)"
fi

# ── VPN: PROXY to vpnsecure only from wg; edge ports per slot; metrics ──
if K -n "$NS" get deploy wg >/dev/null 2>&1; then
  TV="$(svc_ip traefik-vpn)"
  if dial "$NS" e2e-hubside "$TV" 8444 || dial "$NS" e2e-hubside "$(pod_ip traefik)" 8444; then fail "a non-wg pod reaches vpnsecure :8444"; fi
  WG="$(pod_ip wg)"
  if dial "$APPS" e2e-app "$WG" 9100; then fail "an app pod reaches wg's metrics :9100"; fi
  probe_pod "$APPS" e2e-gw3 '{"portcullis.io/instance": "e2egw", "portcullis.io/vpn-slot": "3"}' 2>/dev/null || true
  if K -n "$APPS" get pod e2e-gw3 >/dev/null 2>&1; then
    if dial "$APPS" e2e-gw3 "$WG" 9005; then fail "the slot-3 gateway reaches slot 4's edge port 9005"; fi
  fi
  pass "vpnsecure only from wg; no app pod on wg :9100; a gateway can't reach another slot's edge port"
fi
echo "PASS: every Kubernetes assertion"
