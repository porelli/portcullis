#!/usr/bin/env bash
# e2e-k3s "Traefik's default certificate" (Task 31 fix round 2, M3; found
# live: a starting HA Traefik served its own self-signed default until the
# domains document arrived, and hostPort sends traffic to a pod that isn't
# Ready). The HA Traefik's default TLS store is the chart's own document
# (traefik-dynamic's 00-default-cert.yml) naming the ingress namespace's
# kubernetes.io/tls Secret traefik-default-cert, projected into the watched
# directory as default-cert/tls.crt|tls.key (security review: the pair's
# writers never write configuration). This runs the HA chart's own
# Traefik shape — the image, the pod and container security contexts,
# that projection and that document exactly as rendered (the live objects
# when the cluster runs HA, else `helm template` with ha.enabled) — in a
# scratch namespace, with the pair written by the CLI's own
# ha_default_cert_sync from a frontdoor-cert holding a test pair of the
# main domain, and no domains provider at all (the worst case: its first
# answer never comes). A test router (Host(e2e-router.<d>), the stand-in
# for the core routes) makes websecure a TLS entrypoint. Asserted, through
# a port-forward polled in a tight loop from the moment the pod runs:
#   - the first handshake that completes, with no SNI and with an unknown
#     SNI, serves the main domain's test certificate, and no handshake
#     ever serves Traefik's self-signed default;
#   - the same after a restart (the pod deleted and created again);
#   - a renewed pair (frontdoor-cert changed, ha_default_cert_sync again)
#     is served without a restart (the projection's swap fires the watch);
#   - the control: the same pod without the document and the pair serves
#     Traefik's self-signed default (so the check can tell them apart).
#   bash .github/ci/e2e-k3s-default-cert.sh [<context>]   (default ci)
set -euo pipefail
CTX="${1:-ci}"
SNS=e2e-default-cert
K() { kubectl --context "$CTX" "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "PASS: $*"; }
T="$(mktemp -d)"
PF=""
cleanup() {
  [ -z "$PF" ] || kill "$PF" 2>/dev/null || true
  K delete namespace "$SNS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  rm -rf "$T"
}
trap cleanup EXIT
D="$(grep '^PORTCULLIS_DOMAIN=' .env | cut -d= -f2-)"
[ -n "$D" ] || fail "no PORTCULLIS_DOMAIN in .env"

# Two test pairs of the main domain (exactly <d> and *.<d>, as servableHA
# wants), from a throwaway CA; test keys, never secrets of the install.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=e2e default-cert CA" \
  -keyout "$T/ca.key" -out "$T/ca.crt" >/dev/null 2>&1
for n in 1 2; do
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$D" -keyout "$T/p$n.key" -out "$T/p$n.csr" >/dev/null 2>&1
  printf 'subjectAltName=DNS:%s,DNS:*.%s\n' "$D" "$D" > "$T/ext"
  openssl x509 -req -in "$T/p$n.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -CAcreateserial -days 2 -extfile "$T/ext" -out "$T/p$n.crt" >/dev/null 2>&1
done
serial() { openssl x509 -noout -serial -in "$1" | cut -d= -f2; }
S1="$(serial "$T/p1.crt")" S2="$(serial "$T/p2.crt")"

# The chart's HA Traefik pod template and traefik-dynamic: the live
# objects, else rendered.
if K -n portcullis-ingress get daemonset traefik -o json > "$T/ds.json" 2>/dev/null; then
  K -n portcullis-ingress get configmap traefik-dynamic -o json > "$T/td.json"
  src="the live HA DaemonSet and traefik-dynamic"
else
  [ -s secrets/kube/values.yaml ] || fail "no secrets/kube/values.yaml to render the chart with"
  helm template portcullis charts/portcullis -n portcullis -f secrets/kube/values.yaml --set ha.enabled=true \
    --show-only templates/traefik.yaml --show-only templates/traefik-file-middlewares.yaml | K create --dry-run=client -o json -f - > "$T/r.json"
  jq '(.items // [.])[] | select(.kind == "DaemonSet")' "$T/r.json" > "$T/ds.json"
  jq '(.items // [.])[] | select(.kind == "ConfigMap" and .metadata.name == "traefik-dynamic")' "$T/r.json" > "$T/td.json"
  src="the HA chart (helm template, ha.enabled)"
fi
jq -e '.spec.template.spec.volumes[] | select(.name == "dynamic") | .projected.sources[] | select(.secret.name == "traefik-default-cert")' "$T/ds.json" > "$T/proj.json" \
  || fail "the HA Traefik ($src) doesn't project traefik-default-cert"
jq -e '.secret.items == [{key: "tls.crt", path: "default-cert/tls.crt", mode: 288}, {key: "tls.key", path: "default-cert/tls.key", mode: 288}] and (.secret.optional | not)' "$T/proj.json" >/dev/null \
  || fail "the HA Traefik ($src) projects traefik-default-cert as $(jq -c . "$T/proj.json"), not exactly its pair as default-cert/*"
jq -r '.data["00-default-cert.yml"] // empty' "$T/td.json" > "$T/doc.yml"
grep -q 'certFile: /etc/traefik/dynamic/default-cert/tls.crt' "$T/doc.yml" || fail "traefik-dynamic ($src) has no default store document"
pass "the HA Traefik's shape from $src: $(jq -c . "$T/proj.json") + the chart's 00-default-cert.yml"

K create namespace "$SNS" >/dev/null
# The CLI writes the document from frontdoor-cert (its own function, the
# key on pipes): here both namespaces are the scratch one.
put_pair() {
  K -n "$SNS" create secret generic frontdoor-cert --from-file=tls.crt="$T/p$1.crt" --from-file=tls.key="$T/p$1.key" --dry-run=client -o json \
    | K apply -f - >/dev/null
  PORTCULLIS_KUBE_CONTEXT="$CTX" SNS="$SNS" bash -c 'for _lib in $(sed -n "s/^for _lib in \(.*\); do\$/\1/p" portcullis); do source "scripts/lib/$_lib.sh"; done
    env_load >/dev/null 2>&1 || true; kube_ns() { echo "$SNS"; }; KUBE_INGRESS_NS="$SNS"; PORTCULLIS_HOME="$PWD"; ha_default_cert_sync' \
    || fail "ha_default_cert_sync refused pair $1"
}
put_pair 1
K -n "$SNS" get secret traefik-default-cert -o json | jq -e --rawfile c "$T/p1.crt" '.type == "kubernetes.io/tls" and (.data | keys) == ["tls.crt", "tls.key"] and (.data["tls.crt"] | @base64d) == $c' >/dev/null \
  || fail "traefik-default-cert isn't a kubernetes.io/tls Secret of exactly the pair"
pass "ha_default_cert_sync wrote traefik-default-cert: kubernetes.io/tls, exactly tls.crt and tls.key"
K -n "$SNS" create configmap e2e-default-cert-doc --from-file=00-default-cert.yml="$T/doc.yml" >/dev/null
K -n "$SNS" create configmap e2e-routes --from-literal=routes.yml="http:
  routers:
    e2e-router:
      entryPoints: [websecure]
      rule: Host(\`e2e-router.$D\`)
      service: ping@internal
      tls: {}
" >/dev/null

# The pod: the chart's image, security contexts and projection; Traefik's
# entrypoints, ping and file provider (watched) from its environment; no
# HTTP provider (nothing else ever loads a certificate).
pod() { # pod <with projection: true|false>
  jq --arg ns "$SNS" --argjson with "$1" --slurpfile proj "$T/proj.json" '.spec.template.spec as $s | ($s.containers[0]) as $c |
    {apiVersion: "v1", kind: "Pod", metadata: {name: "e2e-traefik", namespace: $ns, labels: {"e2e-k3s": "default-cert"}},
     spec: {restartPolicy: "Never", automountServiceAccountToken: false, enableServiceLinks: false, securityContext: $s.securityContext,
       containers: [{name: "traefik", image: $c.image, securityContext: $c.securityContext,
         env: ([$c.env[] | select(.name | test("^TRAEFIK_(ENTRYPOINTS_(WEBSECURE|TRAEFIK)_ADDRESS|PING|LOG_LEVEL|PROVIDERS_FILE_(DIRECTORY|WATCH))$"))]),
         ports: [{containerPort: 8443}], resources: {limits: {memory: "256Mi"}, requests: {memory: "128Mi"}},
         volumeMounts: [{name: "dynamic", mountPath: "/etc/traefik/dynamic", readOnly: true}, {name: "tmp", mountPath: "/tmp"}]}],
       volumes: [{name: "dynamic", projected: {sources: ([{configMap: {name: "e2e-routes"}}] + (if $with then [{configMap: {name: "e2e-default-cert-doc"}}] + $proj else [] end))}},
         {name: "tmp", emptyDir: {medium: "Memory"}}]}}' "$T/ds.json"
}
# watch <label> <with: true|false> <want CN / serial> — create the pod,
# port-forward as soon as it runs, handshake in a tight loop (no SNI and
# an unknown SNI) until both have completed 5 times; every completed
# handshake is recorded and must be the wanted certificate.
watch() {
  local label="$1" with="$2" want="$3" port=18443 ok=0 seen=0 line
  K -n "$SNS" delete pod e2e-traefik --ignore-not-found --wait=true >/dev/null
  pod "$with" | K create -f - >/dev/null
  for _ in $(seq 1 120); do [ "$(K -n "$SNS" get pod e2e-traefik -o jsonpath='{.status.phase}' 2>/dev/null)" = Running ] && break; sleep 0.5; done
  [ "$(K -n "$SNS" get pod e2e-traefik -o jsonpath='{.status.phase}')" = Running ] || fail "$label: the Traefik pod didn't run ($(K -n "$SNS" get pod e2e-traefik -o jsonpath='{.status.containerStatuses[0].state}'))"
  kubectl --context "$CTX" -n "$SNS" port-forward pod/e2e-traefik "$port:8443" >/dev/null 2>&1 9>&- & PF=$!
  : > "$T/$label.log"
  for _ in $(seq 1 600); do
    for sni in -noservername "-servername unknown.invalid"; do
      # shellcheck disable=SC2086  # the SNI flag and its value
      line="$(timeout 2 openssl s_client -connect "127.0.0.1:$port" $sni </dev/null 2>/dev/null | openssl x509 -noout -serial -subject 2>/dev/null | tr '\n' ' ')" || line=""
      [ -n "$line" ] || continue
      seen=$((seen + 1)); printf '%s %s %s\n' "$(date -u +%T.%N | cut -c1-12)" "$sni" "$line" >> "$T/$label.log"
      case "$line" in *"$want"*) ok=$((ok + 1)) ;; esac
    done
    [ "$seen" -lt 10 ] || break
  done
  kill "$PF" 2>/dev/null || true; wait "$PF" 2>/dev/null || true; PF=""
  [ "$seen" -ge 10 ] || { cat "$T/$label.log"; fail "$label: only $seen handshakes completed"; }
  [ "$ok" = "$seen" ] || { cat "$T/$label.log"; fail "$label: $((seen - ok)) of $seen handshakes didn't serve $want (first: $(head -1 "$T/$label.log"))"; }
  pass "$label: every one of $seen handshakes from the first ($(head -1 "$T/$label.log" | cut -d' ' -f1), no SNI and an unknown SNI) served $want"
}
watch "control (no document, no pair)" false "TRAEFIK DEFAULT CERT"
watch "first start" true "serial=$S1"
watch "restart" true "serial=$S1"
# A renewed pair: written by the CLI's function; the running Traefik serves
# it without a restart once the kubelet updates the projection (≤ ~2 min).
put_pair 2
kubectl --context "$CTX" -n "$SNS" port-forward pod/e2e-traefik 18443:8443 >/dev/null 2>&1 9>&- & PF=$!
got=""
for _ in $(seq 1 90); do
  got="$(timeout 2 openssl s_client -connect 127.0.0.1:18443 -noservername </dev/null 2>/dev/null | openssl x509 -noout -serial 2>/dev/null | cut -d= -f2)" || got=""
  [ "$got" != "$S2" ] || break; sleep 2
done
kill "$PF" 2>/dev/null || true; wait "$PF" 2>/dev/null || true; PF=""
[ "$got" = "$S2" ] || fail "renewal: the running Traefik still serves $got, not the renewed $S2"
pass "renewal: the running Traefik serves the renewed pair without a restart (the projection's swap fires the file provider's watch)"
