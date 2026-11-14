#!/usr/bin/env bash
# e2e-k3s "portcullis-edge admission" (controller ruling, option (a)): the
# Hub writes the apps' IngressRoutes / Middlewares and their backends
# (ExternalName Services pinned to <name>.<apps ns>.svc.cluster.local) into
# portcullis-edge, held by RBAC (its edge Role: IngressRoute, Middleware,
# Service) and the
# portcullis-edge-routes policy (kube/admission/policies.yaml). Every case
# runs as the Hub's ServiceAccount (`kubectl --as`, server dry-run unless it
# needs a live object); each refusal must come from a binding
# portcullis-edge-guard-routes-<params generation>, each control must be
# admitted.
#   bash .github/ci/e2e-k3s-edge-admission.sh [<context>]   (default ci)
# Needs: the namespaces, the policies + bindings + params, the Hub's Roles
# (./portcullis init does all of it).
set -euo pipefail
CTX="${1:-ci}"
NS=portcullis APPS=portcullis-apps EDGE=portcullis-edge
HUB="system:serviceaccount:$NS:portcullis-hub"
K() { kubectl --context "$CTX" "$@"; }
KH() { kubectl --context "$CTX" --as="$HUB" "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
# Cases run at the end of pipelines (subshells): count in files.
CNT="$(mktemp -d)"; trap 'rm -rf "$CNT"' EXIT
count() { echo . >> "$CNT/$1"; }

# admitted <what> <verb args…> — stdin is the manifest for create / apply.
admitted() {
  local what="$1" out; shift
  out="$(KH -n "$EDGE" "$@" 2>&1)" || fail "refused, want admitted: $what: $(printf '%s' "$out" | head -c 400)"
  count ok
}
# refused <what> <verb args…> — refused by the edge binding.
refused() {
  local what="$1" out; shift
  if out="$(KH -n "$EDGE" "$@" 2>&1)"; then fail "admitted, want refused: $what"; fi
  printf '%s' "$out" | grep -q "with binding 'portcullis-edge-guard-routes-" \
    || fail "refused, but not by portcullis-edge-guard-routes: $what: $(printf '%s' "$out" | head -c 400)"
  count ref
}
# rejected <what> <verb args…> — refused by the edge binding or, for a shape
# the API server's own validation already forbids (nodePort / loadBalancer
# fields on an ExternalName), by that validation: both keep it out.
rejected() {
  local what="$1" out; shift
  if out="$(KH -n "$EDGE" "$@" 2>&1)"; then fail "admitted, want refused: $what"; fi
  printf '%s' "$out" | grep -q "with binding 'portcullis-edge-guard-routes-\|is invalid:" \
    || fail "refused, but neither by portcullis-edge-guard-routes nor by API validation: $what: $(printf '%s' "$out" | head -c 400)"
  count ref
}
# forbidden <what> <verb args…> — refused by RBAC (the Hub's edge Role).
forbidden() {
  local what="$1" out; shift
  if out="$(KH -n "$EDGE" "$@" 2>&1)"; then fail "admitted, want forbidden: $what"; fi
  printf '%s' "$out" | grep -qi 'forbidden' || fail "refused, but not by RBAC: $what: $(printf '%s' "$out" | head -c 400)"
  count ref
}

# ir <jq patch> — an IngressRoute the Hub renders, patched.
ir() {
  jq -n '{apiVersion: "traefik.io/v1alpha1", kind: "IngressRoute",
    metadata: {name: "e2e-app", labels: {"portcullis.io/owner": "hub", "portcullis.io/instance": "e2e"}},
    spec: {entryPoints: ["websecure"],
      routes: [{match: "Host(`e2e.example.org`)", kind: "Rule",
        middlewares: [{name: "client-headers@file"}, {name: "portcullis-auth@file"}, {name: "portcullis-groups@file"}, {name: "e2e--strip"}],
        services: [{name: "e2e--web", port: 80}]}],
      tls: {certResolver: "letsencrypt", options: {name: "authaware@file"}}}}' | jq "$1"
}
# mw <spec json> [labels json] — a Middleware.
HUB_LABELS='{"portcullis.io/owner": "hub", "portcullis.io/instance": "e2e"}'
mw() {
  jq -n --argjson s "$1" --argjson l "${2:-$HUB_LABELS}" \
    '{apiVersion: "traefik.io/v1alpha1", kind: "Middleware", metadata: {name: "e2e--strip", labels: $l}, spec: $s}'
}
C=(create --dry-run=server -f -)

# ── controls: the Hub's shapes are admitted ──
ir . | admitted "an app IngressRoute (its own edge Service, @file + own middlewares, authaware)" "${C[@]}"
ir '.spec.routes[0].services[0].kind = "Service"' | admitted "its own edge Service, kind Service (the Hub's ref)" "${C[@]}"
ir '.spec.entryPoints = ["websecure", "vpnsecure"]' | admitted "entryPoints websecure, vpnsecure" "${C[@]}"
ir '.spec.routes[0].match = "Host(`a.example.org`) || Host(`b.example.org`) && (PathPrefix(`/x`) || Path(`/y`))" | .spec.routes[0].priority = 1000' \
  | admitted "two hosts, paths, priority at maxAppPriority" "${C[@]}"
ir '.spec.routes[0].services = [{name: "group-gate@file", kind: "TraefikService"}]' | admitted "a K15 core service (group-gate@file)" "${C[@]}"
ir '.spec.routes[0].middlewares += [{name: "e2e--chain", namespace: "portcullis-edge"}]' | admitted "a middleware named with the edge namespace" "${C[@]}"
mw '{"stripPrefix": {"prefixes": ["/x"]}}' | admitted "a stripPrefix Middleware" "${C[@]}"
mw '{"headers": {"customRequestHeaders": {"X-Forwarded-Attr-Tier": ""}}}' | admitted "a headers Middleware" "${C[@]}"
mw '{"redirectRegex": {"regex": "^https://a/(.*)", "replacement": "https://b/${1}"}}' | admitted "a redirectRegex Middleware" "${C[@]}"
mw '{"ipAllowList": {"sourceRange": ["10.213.0.0/22"]}}' | admitted "an ipAllowList Middleware" "${C[@]}"
mw '{"chain": {"middlewares": [{"name": "e2e--strip"}, {"name": "portcullis-groups-vpn@file"}]}}' | admitted "a chain of own + @file middlewares" "${C[@]}"

# ── ownership ──
ir 'del(.metadata.labels)' | refused "an IngressRoute without portcullis.io/owner" "${C[@]}"
ir '.metadata.labels["portcullis.io/owner"] = "core"' | refused "an IngressRoute claiming owner=core" "${C[@]}"
mw '{"stripPrefix": {"prefixes": ["/x"]}}' '{}' | refused "a Middleware without portcullis.io/owner" "${C[@]}"
core="$(K -n "$EDGE" get ingressroutes -l portcullis.io/owner=core -o jsonpath='{.items[0].metadata.name}')"
[ -n "$core" ] || fail "no owner=core IngressRoute in $EDGE"
refused "relabelling the core IngressRoute $core" label --dry-run=server ingressroute "$core" portcullis.io/owner=hub --overwrite
refused "patching the core IngressRoute $core" patch --dry-run=server ingressroute "$core" --type=merge -p '{"spec":{"entryPoints":["websecure"]}}'
refused "deleting the core IngressRoute $core" delete --dry-run=server ingressroute "$core"
refused "taking over the core IngressRoute $core (relabel owner=hub + instance, new spec)" patch --dry-run=server ingressroute "$core" --type=merge \
  -p "$(ir '.' | jq -c '{metadata: {labels: .metadata.labels}, spec: .spec}')"
refused "deleting the core Middleware hub-proxy-secret" delete --dry-run=server middleware hub-proxy-secret
refused "patching the core Middleware portcullis-auth-console" patch --dry-run=server middleware portcullis-auth-console --type=merge -p '{"metadata":{"labels":{"x":"y"}}}'
# A live Hub object: update and delete admitted.
ir . | KH -n "$EDGE" create -f - >/dev/null || fail "the Hub can't create its IngressRoute"
admitted "the Hub patching its own IngressRoute" patch ingressroute e2e-app --type=merge -p '{"spec":{"entryPoints":["websecure","vpnsecure"]}}'
refused "the Hub moving its route to another instance" label ingressroute e2e-app portcullis.io/instance=other --overwrite
refused "the Hub dropping its owner label" label ingressroute e2e-app portcullis.io/owner-
admitted "the Hub deleting its own IngressRoute" delete ingressroute e2e-app

# ── IngressRoute shapes ──
ir 'del(.spec.entryPoints)' | refused "no entryPoints (= every entrypoint)" "${C[@]}"
ir '.spec.entryPoints = []' | refused "empty entryPoints" "${C[@]}"
ir '.spec.entryPoints = ["kcinternal"]' | refused "entrypoint kcinternal" "${C[@]}"
ir '.spec.entryPoints = ["web"]' | refused "entrypoint web" "${C[@]}"
ir 'del(.metadata.labels["portcullis.io/instance"])' | refused "an IngressRoute without portcullis.io/instance" "${C[@]}"
ir 'del(.spec.tls)' | refused "a route without TLS" "${C[@]}"
ir '.spec.routes[0].priority = 1001' | refused "a priority above maxAppPriority" "${C[@]}"
for m in 'HostRegexp(`.+`)' 'PathPrefix(`/`)' 'Host(`e2e.example.org`) || PathPrefix(`/`)' 'Host(`e2e.example.org`) && Header(`X`, `y`)' 'ClientIP(`10.0.0.0/8`)'; do
  ir ".spec.routes[0].match = \"$m\"" | refused "the match $m" "${C[@]}"
done
# The params the live edge binding names (older generations may linger).
PREF="$(K get validatingadmissionpolicybinding -l portcullis.io/binding=portcullis-edge-guard-routes -o jsonpath='{.items[0].spec.paramRef.namespace}/{.items[0].spec.paramRef.name}')"
RES="$(K -n "${PREF%%/*}" get configmap "${PREF#*/}" -o jsonpath='{.data.reservedHosts}')"
APEX="${RES%% *}" HUBH="hub.${RES%% *}"
ir ".spec.routes[0].match = \"Host(\`app1.$APEX\`)\"" | admitted "an app host under the apex (app1.$APEX)" "${C[@]}"
for h in "$HUBH." "HUB.$APEX" "Hub.$APEX" "hub..$APEX" "-x.example.org" "x-.example.org" "x.$HUBH" "a.b.$HUBH" "$HUBH.." ".$HUBH"; do
  ir ".spec.routes[0].match = \"Host(\`$h\`)\"" | refused "the host $h (trailing dot, case, empty label, hyphen, a core subdomain)" "${C[@]}"
done
for h in $RES; do
  ir ".spec.routes[0].match = \"Host(\`$h\`) && PathPrefix(\`/x\`)\"" | refused "a route on the reserved host $h" "${C[@]}"
done
ir '.spec.entryPoints = ["websecure", "parked"]' | refused "entrypoint parked" "${C[@]}"
for sns in "$EDGE" "$APPS" "$NS" portcullis-storage kube-system; do
  ir ".spec.routes[0].services[0].namespace = \"$sns\"" | refused "a Service in $sns" "${C[@]}"
done
for sname in other--web e2e-app e2e--b--web e2e-- keycloak; do
  ir ".spec.routes[0].services[0].name = \"$sname\"" | refused "a route to the edge Service $sname (not instance e2e's own)" "${C[@]}"
done
ir '.spec.routes[0].services = [{name: "core-hub-8888@file", kind: "TraefikService"}]' | refused "a core router backend (core-hub-8888@file)" "${C[@]}"
ir '.spec.routes[0].services = [{name: "api@internal", kind: "TraefikService"}]' | refused "api@internal" "${C[@]}"
ir '.spec.routes[0].match = "Host(`e2e.example.org`) && Path(`/mcp`)" | .spec.routes[0].services = [{name: "mcp-gate@file", kind: "TraefikService"}]' \
  | admitted "a companion MCP route to mcp-gate@file on the app's host" "${C[@]}"
ir '.spec.routes[0].middlewares += [{name: "other--strip"}]' | refused "another instance's middleware" "${C[@]}"
ir '.metadata.labels["portcullis.io/reach"] = "vpn"' | refused "a VPN-only instance's route on websecure" "${C[@]}"
ir '.metadata.labels["portcullis.io/reach"] = "vpn" | .spec.entryPoints = ["vpnsecure"]' | admitted "a VPN-only instance's route on vpnsecure" "${C[@]}"
ir '.metadata.labels["portcullis.io/reach"] = "vpn" | .spec.routes[0].middlewares = [{name: "vpn-required-path@file"}] | .spec.routes[0].services = [{name: "group-gate@file", kind: "TraefikService"}]' \
  | admitted "a VPN-only instance's websecure VPN-required page" "${C[@]}"
mw '{"headers": {"customRequestHeaders": {"X_Portcullis_Proxy_Secret": "x"}}}' | refused "an X_Portcullis_* header" "${C[@]}"
# Only the Hub's ServiceAccount (and the CLI) may write here.
out="$(ir . | K -n "$EDGE" --as=system:serviceaccount:portcullis-apps:default --as-group=system:masters create --dry-run=server -f - 2>&1)" \
  && fail "another ServiceAccount (with RBAC) may write the apps' routes"
printf '%s' "$out" | grep -q "with binding 'portcullis-edge-guard-routes-" || fail "another ServiceAccount's route refused, but not by the edge binding: ${out:0:300}"
count ref
ir '.spec.routes[0].services = [{name: "e2e-wrr", kind: "TraefikService"}]' | refused "an own TraefikService" "${C[@]}"
ir '.spec.routes[0].services = [{name: "group-gate@file", kind: "TraefikService", namespace: "portcullis"}]' | refused "a K15 service with a namespace" "${C[@]}"
ir '.spec.routes[0].middlewares += [{name: "hub-proxy-secret"}]' | refused "the core middleware hub-proxy-secret" "${C[@]}"
ir '.spec.routes[0].middlewares += [{name: "portcullis-auth-console"}]' | refused "the core middleware portcullis-auth-console" "${C[@]}"
ir '.spec.routes[0].middlewares += [{name: "x", namespace: "portcullis-apps"}]' | refused "a middleware in the apps namespace" "${C[@]}"
ir '.spec.routes[0].middlewares += [{name: "strip-forwarded@file"}]' | refused "a chart-only @file middleware (strip-forwarded)" "${C[@]}"
ir '.spec.routes[0].middlewares += [{name: "x@kubernetescrd"}]' | refused "a provider-qualified middleware" "${C[@]}"
ir '.spec.tls.secretName = "secrets-certs"' | refused "a TLS secretName" "${C[@]}"
ir '.spec.tls.options = {name: "default"}' | refused "tls.options outside the tiers" "${C[@]}"
ir '.spec.tls.certResolver = "other"' | refused "another cert resolver" "${C[@]}"

# ── Middleware shapes ──
mw '{"forwardAuth": {"address": "http://group-gate.portcullis.svc.cluster.local:8080"}}' | refused "a forwardAuth Middleware" "${C[@]}"
mw '{"errors": {"status": ["500"], "service": {"name": "api@internal", "kind": "TraefikService"}, "query": "/"}}' | refused "an errors Middleware" "${C[@]}"
mw '{"plugin": {"x": {}}}' | refused "a plugin Middleware" "${C[@]}"
mw '{"basicAuth": {"secret": "portcullis-env"}}' | refused "a basicAuth Middleware" "${C[@]}"
mw '{"passTLSClientCert": {"pem": true}}' | refused "a passTLSClientCert Middleware" "${C[@]}"
mw '{"stripPrefix": {"prefixes": ["/x"]}, "compress": {}}' | refused "two types in one Middleware" "${C[@]}"
mw '{"rateLimit": {"average": 10, "redis": {"endpoints": ["sessions.portcullis:6379"]}}}' | refused "a rateLimit with redis" "${C[@]}"
mw '{"headers": {"customRequestHeaders": {"X-Portcullis-Proxy-Secret": "x"}}}' | refused "an X-Portcullis-* header" "${C[@]}"
mw '{"chain": {"middlewares": [{"name": "hub-proxy-secret"}]}}' | refused "a chain with a core middleware" "${C[@]}"
mw '{"chain": {"middlewares": [{"name": "x", "namespace": "portcullis-apps"}]}}' | refused "a chain into the apps namespace" "${C[@]}"
mw '{"chain": {"middlewares": [{"name": "nope@file"}]}}' | refused "a chain with an unlisted @file" "${C[@]}"

# ── the apps' backends: the Hub's ExternalName Services, pinned ──
# As the Hub with system:masters (RBAC out of the way): the policy alone.
# esvc <jq patch> — the shape the Hub emits for instance e2e's service web.
esvc() {
  jq -n --arg apps "$APPS" '{apiVersion: "v1", kind: "Service",
    metadata: {name: "e2e--web", labels: {"portcullis.io/owner": "hub", "portcullis.io/instance": "e2e"}},
    spec: {type: "ExternalName", externalName: ("e2e--web." + $apps + ".svc.cluster.local"),
      ports: [{name: "tcp-80", port: 80, protocol: "TCP"}]}}' | jq "$1"
}
KM=(--as-group=system:masters create --dry-run=server -f -)
esvc . | admitted "the pinned ExternalName Service (e2e--web → e2e--web.$APPS.svc.cluster.local)" "${KM[@]}"
esvc '.spec.ports += [{name: "tcp-8443", port: 8443, protocol: "TCP"}]' | admitted "two route ports" "${KM[@]}"
esvc 'del(.spec.ports)' | refused "no ports" "${KM[@]}"
esvc '.spec.ports[0].name = "http"' | refused "a port not named tcp-<port>" "${KM[@]}"
esvc '.spec.ports[0].name = "tcp-81"' | refused "a port named for another port" "${KM[@]}"
esvc ".metadata.name = \"other--web\" | .spec.externalName = \"other--web.$APPS.svc.cluster.local\"" | refused "another instance's name" "${KM[@]}"
esvc '.spec.externalName = "keycloak.portcullis.svc.cluster.local"' | refused "a core service's name" "${KM[@]}"
esvc ".spec.externalName = \"e2e--other.$APPS.svc.cluster.local\"" | refused "another of its own names than the Service's" "${KM[@]}"
esvc '.spec.externalName = "example.org"' | refused "an external FQDN" "${KM[@]}"
esvc '.spec.externalName = "10.43.0.20"' | refused "an IP address" "${KM[@]}"
esvc ".spec.externalName = \"e2e--web.$APPS.svc.cluster.local.\"" | refused "the name with a trailing dot" "${KM[@]}"
esvc ".spec.externalName = \"e2e--web.$APPS\"" | refused "a short name (search-domain dependent)" "${KM[@]}"
esvc '.metadata.labels["portcullis.io/instance"] = "e2f"' | refused "a label / name mismatch (instance e2f, name e2e--web)" "${KM[@]}"
esvc ".metadata.labels[\"portcullis.io/instance\"] = \"e2e--b\" | .metadata.name = \"e2e--b--web\" | .spec.externalName = \"e2e--b--web.$APPS.svc.cluster.local\"" \
  | admitted "instance e2e--b's own e2e--b--web" "${KM[@]}"
esvc ".metadata.name = \"e2e--b--web\" | .spec.externalName = \"e2e--b--web.$APPS.svc.cluster.local\"" | refused "instance e2e naming e2e--b--web (instance e2e--b's)" "${KM[@]}"
esvc 'del(.metadata.labels["portcullis.io/instance"])' | refused "no instance label" "${KM[@]}"
esvc '.metadata.labels["portcullis.io/owner"] = "core"' | refused "owner=core" "${KM[@]}"
esvc 'del(.spec.externalName) | .spec.type = "ClusterIP" | .spec.selector = {"portcullis.io/instance": "e2e"}' | refused "a ClusterIP Service with a selector" "${KM[@]}"
esvc 'del(.spec.externalName) | .spec.type = "ClusterIP" | .spec.clusterIP = "None"' | refused "a headless Service" "${KM[@]}"
esvc '.spec.selector = {"portcullis.io/instance": "e2e"}' | refused "an ExternalName with a selector" "${KM[@]}"
esvc '.spec.externalIPs = ["198.51.100.1"]' | refused "externalIPs" "${KM[@]}"
esvc '.spec.ports[0].targetPort = 8080' | refused "a targetPort other than its port" "${KM[@]}"
esvc '.spec.ports[0].appProtocol = "https"' | refused "an appProtocol" "${KM[@]}"
esvc '.spec.ports[0].protocol = "UDP"' | refused "a UDP port" "${KM[@]}"
esvc '.spec.ports[0].nodePort = 30080' | rejected "a nodePort" "${KM[@]}"
esvc '.spec.loadBalancerSourceRanges = ["0.0.0.0/0"]' | rejected "a loadBalancer field" "${KM[@]}"
# Live objects: an owner=core Service here (the CLI's, exempt; never
# ExternalName) the Hub may neither change nor delete, and the Hub's own one
# it may delete but never relabel.
jq -n '{apiVersion: "v1", kind: "Service", metadata: {name: "e2e-core", labels: {"portcullis.io/owner": "core"}},
  spec: {type: "ClusterIP", ports: [{name: "tcp-80", port: 80}]}}' | K -n "$EDGE" create -f - >/dev/null
esvc . | KH -n "$EDGE" --as-group=system:masters create -f - >/dev/null || fail "the Hub's ExternalName Service couldn't be created"
trap 'rm -rf "$CNT"; K -n "$EDGE" delete service e2e-core e2e--web --ignore-not-found --wait=false >/dev/null 2>&1 || true' EXIT
refused "deleting an owner=core Service" --as-group=system:masters delete service e2e-core --dry-run=server
refused "relabelling an owner=core Service to owner=hub" --as-group=system:masters label service e2e-core portcullis.io/owner=hub portcullis.io/instance=e2e --overwrite --dry-run=server
refused "relabelling its Service to another instance" --as-group=system:masters label service e2e--web portcullis.io/instance=e2f --overwrite --dry-run=server
refused "relabelling its Service owner=core" --as-group=system:masters label service e2e--web portcullis.io/owner=core --overwrite --dry-run=server
refused "repointing its Service at a core name" --as-group=system:masters patch service e2e--web --type=merge -p '{"spec":{"externalName":"keycloak.portcullis.svc.cluster.local"}}' --dry-run=server
refused "adding a selector to its Service" --as-group=system:masters patch service e2e--web --type=merge -p '{"spec":{"selector":{"portcullis.io/instance":"e2e"}}}' --dry-run=server
admitted "deleting its own Service" --as-group=system:masters delete service e2e--web --dry-run=server

# ── RBAC: only IngressRoute + Middleware + Service ──
jq -n '{apiVersion: "traefik.io/v1alpha1", kind: "TLSOption", metadata: {name: "e2e", labels: {"portcullis.io/owner": "hub"}}, spec: {minVersion: "VersionTLS10"}}' \
  | forbidden "a TLSOption" "${C[@]}"
jq -n '{apiVersion: "traefik.io/v1alpha1", kind: "TraefikService", metadata: {name: "e2e", labels: {"portcullis.io/owner": "hub"}}, spec: {weighted: {services: [{name: "api@internal"}]}}}' \
  | forbidden "a TraefikService" "${C[@]}"
for what in "get secrets" "list secrets" "create secrets" "get configmaps" "create configmaps" "create endpointslices.discovery.k8s.io"; do
  # shellcheck disable=SC2086  # verb + resource
  [ "$(KH -n "$EDGE" auth can-i $what 2>/dev/null || true)" = no ] || fail "the Hub can $what in $EDGE"
  count ref
done
[ "$(KH -n "$APPS" auth can-i create ingressroutes.traefik.io 2>/dev/null || true)" = no ] || fail "the Hub can still create IngressRoutes in $APPS"
[ "$(KH -n "$EDGE" auth can-i create services 2>/dev/null || true)" = yes ] || fail "the Hub can't create its ExternalName Services in $EDGE (its edge Role: services)"
echo "PASS: portcullis-edge admission: $(wc -l < "$CNT/ok" | tr -d " ") Hub shapes admitted, $(wc -l < "$CNT/ref" | tr -d " ") refusals (each by portcullis-edge-guard-routes or RBAC)"
