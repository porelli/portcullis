#!/usr/bin/env bash
# e2e-k3s "apps admission vectors": the ruled shapes of the portcullis-apps
# policies (kube/admission/policies.yaml), each sent as the Hub's
# ServiceAccount (system:masters too, so RBAC lets every shape reach
# admission; server dry-run), each admitted, or refused by a binding
# portcullis-apps-guard-*-<params generation>:
#   root      helpers, a Job's one-shot pods, root-shape init containers
#             (no hostPath at all, groups ≠ 0, own volumes only)
#   names     hostname / subdomain <instance>--pods / its search domain
#   hostAliases, Service names, NetworkPolicy endPort
#   template files: only the instance's own <instance>--tpl-*
# Then a real one-shot Job, whose pod the job controller creates, runs as uid 0.
#   bash .github/ci/e2e-k3s-apps-admission.sh [<context>]   (default ci)
set -euo pipefail
CTX="${1:-ci}"
NS=portcullis APPS=portcullis-apps
HUB="system:serviceaccount:$NS:portcullis-hub"
K() { kubectl --context "$CTX" "$@"; }
KH() { K -n "$APPS" --as="$HUB" --as-group=system:masters "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
CNT="$(mktemp -d)"
trap 'rm -rf "$CNT"; K -n "$APPS" delete job e2e-apps-oneshot --ignore-not-found --wait=false >/dev/null 2>&1 || true' EXIT
# want <admit|refuse> <what> — stdin is the object (cases run at pipeline ends: count in files).
want() {
  local out
  if out="$(KH create --dry-run=server -f - 2>&1)"; then
    [ "$1" = admit ] || fail "admitted, want refused: $2"
  else
    [ "$1" = refuse ] || fail "refused, want admitted: $2: $(printf '%s' "$out" | sed -n 1p | cut -c1-400)"
    printf '%s' "$out" | grep -q "with binding 'portcullis-apps-guard-" \
      || fail "refused, but not by an apps binding: $2: $(printf '%s' "$out" | sed -n 1p | cut -c1-400)"
  fi
  echo . >> "$CNT/$1"
}
A="docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a"
RS='{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"],"add":["CHOWN"]},"runAsUser":0,"runAsGroup":1000}'
# The addresses come from the params the pods binding reads.
PREF="$(K get validatingadmissionpolicybinding -l portcullis.io/binding=portcullis-apps-guard-pods \
  -o jsonpath='{.items[0].spec.paramRef.namespace}/{.items[0].spec.paramRef.name}')"
PARAMS="$(K -n "${PREF%%/*}" get configmap "${PREF#*/}" -o json)"
SVC_CIDR="$(printf '%s' "$PARAMS" | jq -r .data.serviceCIDR)"
NODE="$(printf '%s' "$PARAMS" | jq -r '.data.nodeAddresses | split(" ")[0] | split("/")[0]')"
# An address past the static band (the band is the CIDR's first /20…/24) and one inside it.
read -r IN_DYN IN_STATIC < <(python3 -I -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1]); print(n[n.num_addresses*3//4], n[20])' "$SVC_CIDR")
[ -n "$NODE" ] && [ -n "$IN_DYN" ] || fail "no serviceCIDR / nodeAddresses in $PREF"

pod() { jq -n --arg a "$A" --argjson x "$1" '{apiVersion: "v1", kind: "Pod",
  metadata: {name: "p", labels: {"portcullis.io/instance": "a", "portcullis.io/service": "web"}},
  spec: {automountServiceAccountToken: false, containers: [{name: "c", image: $a, command: ["true"]}]}} * $x'; }
# rc [<jq object merged in>] — a root-shape container.
rc() { jq -nc --arg a "$A" --argjson s "$RS" --argjson x "${1:-"{}"}" '{name: "c", image: $a, command: ["true"], securityContext: $s} * $x'; }
job() { jq -n --arg a "$A" --argjson s "$RS" --argjson x "$1" '{apiVersion: "batch/v1", kind: "Job",
  metadata: {name: "j", labels: {"portcullis.io/instance": "a"}},
  spec: {template: {metadata: {labels: {"portcullis.io/instance": "a", "portcullis.io/one-shot": "true"}},
    spec: {restartPolicy: "Never", automountServiceAccountToken: false,
      containers: [{name: "c", image: $a, command: ["true"], securityContext: $s}]}}}} * $x'; }
# jvol <volume json> <mount json> — a root Job with one volume mounted by its container.
jvol() { job "{\"spec\":{\"template\":{\"spec\":{\"volumes\":[$1],\"containers\":[$(rc "{\"volumeMounts\":[$2]}")]}}}}"; }
svc() { jq -n --arg n "$1" --argjson l "$2" --argjson x "${3:-"{}"}" '{apiVersion: "v1", kind: "Service",
  metadata: {name: $n, labels: $l}, spec: {selector: {"portcullis.io/instance": "a"}, ports: [{port: 80}]}} * $x'; }
np() { jq -n --argjson e "$1" '{apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy",
  metadata: {name: "np", labels: {"portcullis.io/instance": "a"}},
  spec: {podSelector: {matchLabels: {"portcullis.io/instance": "a", "portcullis.io/egress": "true"}}, policyTypes: ["Egress"], egress: [$e]}}'; }
IA='{"portcullis.io/instance":"a"}'
DNS='{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}},"podSelector":{"matchLabels":{"k8s-app":"kube-dns"}}}'
HP='{"name":"h","hostPath":{"path":"/srv/share"}}'

# ── root ──
pod "{\"spec\":{\"containers\":[$(rc)]}}" | want refuse "a root app container"
pod "{\"metadata\":{\"labels\":{\"portcullis.io/one-shot\":\"true\"},\"ownerReferences\":[{\"apiVersion\":\"batch/v1\",\"kind\":\"Job\",\"name\":\"j\",\"uid\":\"00000000-0000-0000-0000-000000000001\",\"controller\":true}]},\"spec\":{\"containers\":[$(rc)]}}" \
  | want refuse "a one-shot pod the Hub forged (ownerReference to a Job)"
pod "{\"spec\":{\"initContainers\":[$(rc '{"name":"i"}')]}}" | want admit "a root-shape init container"
pod "{\"spec\":{\"initContainers\":[$(rc '{"name":"i","ports":[{"containerPort":80}]}')]}}" | want refuse "a root init container with a port"
pod "{\"spec\":{\"volumes\":[$HP],\"initContainers\":[$(rc '{"name":"i","volumeMounts":[{"name":"h","mountPath":"/h","readOnly":true}]}')]}}" \
  | want refuse "a root init container mounting a read-only hostPath"
pod "{\"spec\":{\"initContainers\":[$(rc '{"name":"i","securityContext":{"capabilities":{"add":["NET_ADMIN"]}}}')]}}" \
  | want refuse "a root init container adding NET_ADMIN"
job '{}' | want admit "a root one-shot Job"
jvol "$HP" '{"name":"h","mountPath":"/h"}' | want refuse "a root Job on a hostPath"
jvol "$HP" '{"name":"h","mountPath":"/h","readOnly":true}' | want refuse "a root Job on a read-only hostPath"
jvol '{"name":"d","persistentVolumeClaim":{"claimName":"a--data"}}' '{"name":"d","mountPath":"/d"}' | want admit "a root Job on its own PVC"
jvol '{"name":"d","persistentVolumeClaim":{"claimName":"b--data"}}' '{"name":"d","mountPath":"/d"}' | want refuse "a root Job on another instance's PVC"
jvol '{"name":"t","configMap":{"name":"a--tpl-conf"}}' '{"name":"t","mountPath":"/t","readOnly":true}' | want admit "a root Job on its own template files"
jvol '{"name":"t","configMap":{"name":"b--tpl-conf"}}' '{"name":"t","mountPath":"/t","readOnly":true}' | want refuse "a root Job on another instance's template files"
jvol '{"name":"t","configMap":{"name":"tpl-conf"}}' '{"name":"t","mountPath":"/t","readOnly":true}' | want refuse "a root Job on a bare tpl-* ConfigMap"
job '{"spec":{"template":{"spec":{"securityContext":{"fsGroup":0}}}}}' | want refuse "a root Job with fsGroup 0"
job "{\"spec\":{\"template\":{\"spec\":{\"containers\":[$(rc | jq -c 'del(.securityContext.runAsGroup)')]}}}}" | want refuse "a root Job without a group"
# ── template files: the instance's own <instance>--tpl-* only ──
pod '{"spec":{"volumes":[{"name":"t","configMap":{"name":"a--tpl-conf"}}]}}' | want admit "its own template files"
pod '{"spec":{"volumes":[{"name":"t","configMap":{"name":"b--tpl-conf"}}]}}' | want refuse "another instance's template files"
pod '{"spec":{"volumes":[{"name":"t","configMap":{"name":"tpl-conf"}}]}}' | want refuse "a bare tpl-* ConfigMap"
pod '{"spec":{"volumes":[{"name":"t","secret":{"secretName":"tpl-conf"}}]}}' | want refuse "a bare tpl-* Secret"
pod '{"spec":{"volumes":[{"name":"t","projected":{"sources":[{"configMap":{"name":"tpl-conf"}}]}}]}}' | want refuse "a projected bare tpl-* ConfigMap"
pod "{\"spec\":{\"containers\":[{\"name\":\"c\",\"image\":\"$A\",\"envFrom\":[{\"configMapRef\":{\"name\":\"tpl-conf\"}}]}]}}" | want refuse "envFrom a bare tpl-* ConfigMap"
# ── compose names ──
pod '{"spec":{"hostname":"web","subdomain":"a--pods","dnsConfig":{"searches":["a--pods.portcullis-apps.svc.cluster.local"]}}}' \
  | want admit "its service's hostname, subdomain <instance>--pods and its search domain"
pod '{"spec":{"subdomain":"a"}}' | want refuse "subdomain = the instance"
pod '{"spec":{"dnsConfig":{"searches":["a.portcullis-apps.svc.cluster.local"]}}}' | want refuse "the search domain <instance>.<apps ns>"
pod '{"spec":{"dnsConfig":{"searches":["portcullis.svc.cluster.local"]}}}' | want refuse "core's search domain"
pod '{"spec":{"hostname":"other"}}' | want refuse "a hostname other than its service"
pod '{"spec":{"dnsConfig":{"nameservers":["1.1.1.1"]}}}' | want refuse "a nameserver"
# ── hostAliases ──
ha() { pod "$(jq -nc --arg ip "$1" --arg h "$2" '{spec: {hostAliases: [{ip: $ip, hostnames: [$h]}]}}')"; }
ha "$IN_DYN" web-internal | want admit "a hostAliases entry in the service CIDR"
ha "$NODE" web-internal | want refuse "a hostAliases node address"
ha 192.0.2.5 web-internal | want refuse "a hostAliases address outside the service CIDR"
ha "$IN_STATIC" web-internal | want refuse "a hostAliases address in the static band"
ha "${SVC_CIDR%/*}" web-internal | want refuse "a hostAliases network address"
ha "$IN_DYN" web.internal | want refuse "a hostAliases FQDN"
pod "$(jq -nc --arg ip "$IN_DYN" '{spec: {hostAliases: [range(17) | {ip: $ip, hostnames: ["a\(.)"]}]}}')" | want refuse "17 hostAliases entries"
# ── Services ──
svc a--web "$IA" | want admit "Service a--web"
svc a--pods "$IA" '{"spec":{"clusterIP":"None"}}' | want admit "the headless Service a--pods"
svc portcullis-mcp-a--gitea "$IA" | want admit "the MCP companion Service portcullis-mcp-a--gitea"
svc db "$IA" | want refuse "a Service named db"
svc b--web "$IA" | want refuse "another instance's Service name"
svc a--web '{}' | want refuse "a Service without its instance label"
# ── NetworkPolicy endPort ──
np "{\"to\":[$DNS],\"ports\":[{\"port\":53,\"protocol\":\"UDP\"}]}" | want admit "kube-dns :53"
np "{\"to\":[$DNS],\"ports\":[{\"port\":53,\"endPort\":65535,\"protocol\":\"TCP\"}]}" | want refuse "kube-dns 53-65535 (endPort)"
np "{\"to\":[$DNS],\"ports\":[]}" | want refuse "kube-dns without ports"
np "{\"to\":[{\"ipBlock\":{\"cidr\":\"$NODE/32\"}}],\"ports\":[{\"port\":443,\"endPort\":6443,\"protocol\":\"TCP\"}]}" | want refuse "a node 443-6443 (endPort)"
np '{"to":[{"podSelector":{"matchLabels":{"portcullis.io/instance":"a"}}}],"ports":[{"port":80,"endPort":90}]}' | want refuse "its own pods 80-90 (endPort)"

# ── a real one-shot Job: the job controller's pod is admitted and runs as root ──
jq -n --arg a "$A" --argjson s "$RS" '{apiVersion: "batch/v1", kind: "Job",
  metadata: {name: "e2e-apps-oneshot", labels: {"portcullis.io/instance": "a"}},
  spec: {backoffLimit: 0, template: {metadata: {labels: {"portcullis.io/instance": "a", "portcullis.io/one-shot": "true"}},
    spec: {restartPolicy: "Never", automountServiceAccountToken: false,
      containers: [{name: "c", image: $a, command: ["id", "-u"], securityContext: $s}]}}}}' \
  | KH create -f - >/dev/null || fail "the one-shot Job was refused"
if ! K -n "$APPS" wait --for=condition=Complete job/e2e-apps-oneshot --timeout=180s >/dev/null; then
  K -n "$APPS" get events --field-selector involvedObject.kind=Pod -o custom-columns=R:.reason,M:.message --no-headers | tail -5
  fail "the one-shot Job's pod didn't complete"
fi
[ "$(K -n "$APPS" logs job/e2e-apps-oneshot)" = 0 ] || fail "the one-shot pod didn't run as uid 0"
echo "PASS: apps admission: $(wc -l < "$CNT/admit" | tr -d ' ') shapes admitted, $(wc -l < "$CNT/refuse" | tr -d ' ') refused by their bindings; a one-shot Job ran as uid 0"
