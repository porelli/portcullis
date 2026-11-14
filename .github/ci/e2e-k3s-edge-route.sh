#!/usr/bin/env bash
# e2e-k3s "edge routing": the shape the Hub emits for an app's route works
# end to end. Traefik watches only portcullis-edge and can't read the apps
# namespace, so an app's backend is the Hub's ExternalName Service in the
# edge namespace pinned to <i>--<svc>.<apps ns>.svc.cluster.local. Here, as
# the CLI: a whoami pod + its ClusterIP Service + the Hub-style ingress
# NetworkPolicy (Traefik only) in the apps namespace; as the Hub's
# ServiceAccount (system:masters only so RBAC is out of the way: the policy
# alone judges): the ExternalName Service and the IngressRoute in the edge
# namespace. Then a request through Traefik reaches whoami, and the same
# route pointed at an ExternalName to a core Service can't be created.
#   bash .github/ci/e2e-k3s-edge-route.sh [<context>]   (default ci)
set -euo pipefail
CTX="${1:-ci}"
NS=portcullis APPS=portcullis-apps EDGE=portcullis-edge I=e2e-route
HUB="system:serviceaccount:$NS:portcullis-hub"
K() { kubectl --context "$CTX" "$@"; }
KH() { K --as="$HUB" --as-group=system:masters "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
WHOAMI="docker.io/traefik/whoami:v1.12.0@sha256:c4717a8d1f0134a7444e24f881160e033991f23027c6c5a9a3f8fd22e70d1d44"
cleanup() {
  K -n "$EDGE" delete ingressroute "$I--r" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  K -n "$EDGE" delete service "$I--web" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  K -n "$APPS" delete pod "$I--web" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  K -n "$APPS" delete service "$I--web" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  K -n "$APPS" delete networkpolicy "$I--routed-web" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT
D="$(grep '^PORTCULLIS_DOMAIN=' .env | cut -d= -f2-)"
H="$I.$D"
# The backend (the CLI's own objects: exempt from the apps policies).
I="$I" IMG="$WHOAMI" jq -n '{apiVersion: "v1", kind: "Pod", metadata: {name: (env.I + "--web"), labels: {"portcullis.io/instance": env.I, "portcullis.io/service": "web"}},
  spec: {automountServiceAccountToken: false, securityContext: {runAsNonRoot: true, runAsUser: 65534, runAsGroup: 65534, seccompProfile: {type: "RuntimeDefault"}},
    containers: [{name: "web", image: env.IMG, args: ["--port", "8080"], ports: [{containerPort: 8080}],
      resources: {limits: {memory: "32Mi"}, requests: {memory: "32Mi"}},
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}}]}}' | K -n "$APPS" create -f - >/dev/null
I="$I" jq -n '{apiVersion: "v1", kind: "Service", metadata: {name: (env.I + "--web"), labels: {"portcullis.io/instance": env.I}},
  spec: {selector: {"portcullis.io/instance": env.I, "portcullis.io/service": "web"}, ports: [{name: "p80", port: 80, targetPort: 8080}]}}' | K -n "$APPS" create -f - >/dev/null
I="$I" NS="$NS" jq -n '{apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: {name: (env.I + "--routed-web"), labels: {"portcullis.io/instance": env.I}},
  spec: {podSelector: {matchLabels: {"portcullis.io/instance": env.I, "portcullis.io/service": "web"}}, policyTypes: ["Ingress"],
    ingress: [{from: [{namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": env.NS}}, podSelector: {matchLabels: {"portcullis.io/component": "traefik"}}}],
      ports: [{port: 8080, protocol: "TCP"}]}]}}' | K -n "$APPS" create -f - >/dev/null
K -n "$APPS" wait --for=condition=Ready "pod/$I--web" --timeout=180s >/dev/null || fail "the whoami backend didn't start"
# The Hub's shape (relayed to the Hub stream word for word).
esvc() { I="$I" APPS="$APPS" X="$1" jq -n '{apiVersion: "v1", kind: "Service",
  metadata: {name: (env.I + "--web"), labels: {"portcullis.io/owner": "hub", "portcullis.io/instance": env.I}},
  spec: {type: "ExternalName", externalName: (if env.X == "" then env.I + "--web." + env.APPS + ".svc.cluster.local" else env.X end),
    ports: [{name: "tcp-80", port: 80, protocol: "TCP"}]}}'; }
out="$(esvc "keycloak.$NS.svc.cluster.local" | KH -n "$EDGE" create -f - 2>&1)" && fail "an ExternalName to a core Service was admitted"
printf '%s' "$out" | grep -q "with binding 'portcullis-edge-guard-routes-" || fail "the core-name ExternalName wasn't refused by the edge binding: ${out:0:300}"
esvc "" | KH -n "$EDGE" create -f - >/dev/null || fail "the Hub's ExternalName shape was refused"
I="$I" H="$H" jq -n '{apiVersion: "traefik.io/v1alpha1", kind: "IngressRoute",
  metadata: {name: (env.I + "--r"), labels: {"app.kubernetes.io/managed-by": "portcullis", "portcullis.io/owner": "hub", "portcullis.io/instance": env.I}},
  spec: {entryPoints: ["websecure"], routes: [{match: ("Host(`" + env.H + "`)"), kind: "Rule", services: [{kind: "Service", name: (env.I + "--web"), port: 80}]}],
    tls: {options: {name: "authaware@file"}}}}' | KH -n "$EDGE" create -f - >/dev/null || fail "the Hub's IngressRoute to its edge Service was refused"
# Through Traefik (ServiceLB on the node address), whoami answers with its
# own hostname: the edge Service resolved to the apps Service.
for _ in $(seq 1 30); do
  body="$(curl -sk --max-time 10 --resolve "$H:443:198.51.100.1" "https://$H/" 2>/dev/null || true)"
  printf '%s' "$body" | grep -q "^Hostname: $I--web" && break
  sleep 2
done
printf '%s' "$body" | grep -q "^Hostname: $I--web" || fail "https://$H/ through Traefik didn't reach the whoami behind the edge ExternalName: ${body:0:200}"
echo "PASS: edge routing: IngressRoute → ExternalName $EDGE/$I--web → $I--web.$APPS.svc.cluster.local → the app pod through Traefik; an ExternalName to a core Service refused"
