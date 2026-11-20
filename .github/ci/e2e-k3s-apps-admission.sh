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
#   hostPath  every container non-root (runAsNonRoot / a uid > 0), no
#             escalation, an explicit group > 0, no fsGroup / supplemental 0,
#             supplementalGroupsPolicy Strict
#   claims    the portcullis-apps class, no volumeName / dataSource, own name, 3-digit mode
#   old objects  UPDATE / DELETE of NetworkPolicies (default-deny included),
#             Services, Secrets and claims only when the old object is owner=hub
#   template files: only the instance's own <instance>--tpl-*
# Then a real one-shot Job, whose pod the job controller creates, runs as uid 0,
# and (HA) every "ha" case of tests/admission_vectors.json
# (.github/ci/e2e-k3s-ha-admission.py: placement, core exec, nodeadm tokens
# and params ConfigMaps, portcullis-ingress).
#   bash .github/ci/e2e-k3s-apps-admission.sh [<context>]   (default ci)
set -euo pipefail
CTX="${1:-ci}"
NS=portcullis APPS=portcullis-apps
HUB="system:serviceaccount:$NS:portcullis-hub"
K() { kubectl --context "$CTX" "$@"; }
KH() { K -n "$APPS" --as="$HUB" --as-group=system:masters "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
CNT="$(mktemp -d)"
cleanup() {
  rm -rf "$CNT"
  K -n "$APPS" delete job e2e-apps-oneshot --ignore-not-found --wait=false >/dev/null 2>&1 || true
  K -n "$APPS" delete networkpolicy e2e-old-np e2e-old-np-cli --ignore-not-found --wait=false >/dev/null 2>&1 || true
  K -n "$APPS" delete service a--e2e-old a--e2e-old-cli --ignore-not-found --wait=false >/dev/null 2>&1 || true
  K -n "$APPS" delete secret a--e2e-old a--e2e-old-cli --ignore-not-found --wait=false >/dev/null 2>&1 || true
  K -n "$APPS" delete pod a--e2e-bind --ignore-not-found --wait=false >/dev/null 2>&1 || true
  K -n "$APPS" delete pvc a--e2e-old a--e2e-old-cli b--e2e-old-cli a--e2e-bind --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT
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
# A host path under the params' first shared-folder root (a rebind may move them).
ROOT1="$(printf '%s' "$PARAMS" | jq -r '.data.bindRoots | split(" ") | map(select(. != ""))[0] // empty')"
[ -n "$ROOT1" ] || fail "no bindRoots in $PREF"
HP="$(jq -nc --arg p "$ROOT1/share" '{name: "h", hostPath: {path: $p}}')"

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

# ── a pod with a hostPath volume: provably non-root, no escalation, never group 0 (final review I1) ──
NR='{"allowPrivilegeEscalation":false,"runAsUser":1000,"runAsGroup":1000}'
# hpod <container securityContext> [<pod securityContext>] [<init container securityContext>] — the hostPath mounted by the app container;
# the pod's supplementalGroupsPolicy is Strict unless <pod securityContext> sets it (null = unset).
hpod() {
  jq -n --arg a "$A" --argjson hp "$HP" --argjson s "$1" --argjson ps "${2:-"{}"}" --argjson is "${3:-null}" '{apiVersion: "v1", kind: "Pod",
    metadata: {name: "p", labels: {"portcullis.io/instance": "a", "portcullis.io/service": "web"}},
    spec: ({automountServiceAccountToken: false, volumes: [$hp],
      securityContext: ({supplementalGroupsPolicy: "Strict"} + $ps | with_entries(select(.value != null))),
      containers: [{name: "c", image: $a, command: ["true"], securityContext: $s, volumeMounts: [{name: "h", mountPath: "/h"}]}]}
      + (if $is == null then {} else {initContainers: [{name: "i", image: $a, command: ["true"], securityContext: $is}]} end))}'
}
hpod "$NR" | want admit "a hostPath pod: uid 1000, gid 1000, no escalation"
hpod '{"allowPrivilegeEscalation":false,"runAsNonRoot":true,"runAsGroup":1000}' | want admit "a hostPath pod: runAsNonRoot, gid 1000, no escalation"
hpod '{"allowPrivilegeEscalation":false}' '{"runAsUser":1000,"runAsGroup":1000}' | want admit "a hostPath pod: uid / gid from the pod, no escalation"
hpod '{"allowPrivilegeEscalation":false,"runAsGroup":1000}' | want refuse "a hostPath pod without a uid (the image's USER, maybe root)"
hpod '{"runAsUser":1000,"runAsGroup":1000}' | want refuse "a hostPath pod: uid 1000 but escalation not off (a setuid binary)"
hpod '{"allowPrivilegeEscalation":true,"runAsUser":1000,"runAsGroup":1000}' | want refuse "a hostPath pod: uid 1000 with escalation on"
hpod '{"allowPrivilegeEscalation":false,"runAsNonRoot":false,"runAsGroup":1000}' | want refuse "a hostPath pod: runAsNonRoot false, no uid"
hpod "$NR" '{}' '{}' | want refuse "a hostPath pod whose init container has no securityContext"
hpod "$NR" '{}' '{"allowPrivilegeEscalation":false,"runAsGroup":1000}' | want refuse "a hostPath pod whose init container has no uid"
hpod "$NR" '{}' "$NR" | want admit "a hostPath pod whose init container is non-root too"
hpod '{"allowPrivilegeEscalation":false,"runAsUser":1000}' | want refuse "a hostPath pod without a runAsGroup"
hpod '{"allowPrivilegeEscalation":false,"runAsUser":1000,"runAsGroup":0}' | want refuse "a hostPath pod: container runAsGroup 0"
hpod "$NR" '{"runAsGroup":0}' | want refuse "a hostPath pod: pod runAsGroup 0 (the containers' own groups set)"
hpod '{"allowPrivilegeEscalation":false,"runAsUser":1000}' '{"runAsGroup":0}' | want refuse "a hostPath pod: the effective group 0 from the pod"
hpod "$NR" '{"fsGroup":0}' | want refuse "a hostPath pod: fsGroup 0"
hpod "$NR" '{"supplementalGroups":[1000,0]}' | want refuse "a hostPath pod: supplemental group 0"
hpod "$NR" '{}' '{"allowPrivilegeEscalation":false,"runAsUser":1000}' | want refuse "a hostPath pod whose init container has no runAsGroup"
hpod "$NR" '{"supplementalGroupsPolicy":null}' | want refuse "a hostPath pod without supplementalGroupsPolicy (the image's /etc/group may add group 0)"
hpod "$NR" '{"supplementalGroupsPolicy":"Merge"}' | want refuse "a hostPath pod with supplementalGroupsPolicy Merge"
pod '{"spec":{"securityContext":{"supplementalGroupsPolicy":"Merge"}}}' | want admit "a pod without hostPath may keep supplementalGroupsPolicy Merge"
dep() { jq -n --argjson p "$(hpod "$1" | jq -c .spec)" '{apiVersion: "apps/v1", kind: "Deployment",
  metadata: {name: "d", labels: {"portcullis.io/instance": "a"}},
  spec: {replicas: 1, selector: {matchLabels: {"portcullis.io/instance": "a", "portcullis.io/service": "web"}},
    template: {metadata: {labels: {"portcullis.io/instance": "a", "portcullis.io/service": "web"}}, spec: $p}}}'; }
dep "$NR" | want admit "a hostPath Deployment: uid / gid 1000, no escalation"
dep '{"allowPrivilegeEscalation":false,"runAsGroup":1000}' | want refuse "a hostPath Deployment without a uid"
dep '{"allowPrivilegeEscalation":false,"runAsUser":1000}' | want refuse "a hostPath Deployment without a runAsGroup"
dep "$NR" | jq 'del(.spec.template.spec.securityContext.supplementalGroupsPolicy)' | want refuse "a hostPath Deployment without supplementalGroupsPolicy Strict"
jvol "$HP" '{"name":"h","mountPath":"/h","readOnly":true}' | jq '.spec.template.spec.containers[0].securityContext = {"allowPrivilegeEscalation":false,"runAsUser":1000,"runAsGroup":1000} | .spec.template.metadata.labels |= del(.["portcullis.io/one-shot"])' \
  | want refuse "a hostPath Job (non-root) without supplementalGroupsPolicy Strict"
jvol "$HP" '{"name":"h","mountPath":"/h","readOnly":true}' | jq '.spec.template.spec.containers[0].securityContext = {"allowPrivilegeEscalation":false,"runAsUser":1000,"runAsGroup":1000} | .spec.template.metadata.labels |= del(.["portcullis.io/one-shot"]) | .spec.template.spec.securityContext.supplementalGroupsPolicy = "Strict"' \
  | want admit "a hostPath Job (non-root, Strict)"
# ── PersistentVolumeClaims (final review M6) ──
pvc() { jq -n --argjson x "${1:-"{}"}" '{apiVersion: "v1", kind: "PersistentVolumeClaim",
  metadata: {name: "a--data", labels: {"portcullis.io/instance": "a"}, annotations: {"portcullis.io/uid": "1000", "portcullis.io/gid": "1000", "portcullis.io/mode": "0750"}},
  spec: {accessModes: ["ReadWriteOnce"], storageClassName: "portcullis-apps", resources: {requests: {storage: "1Gi"}}}} * $x'; }
pvc | want admit "a claim: portcullis-apps, <instance>--…, mode 0750"
pvc '{"metadata":{"annotations":{"portcullis.io/mode":"750"}}}' | want admit "a claim: mode 750"
pvc '{"spec":{"storageClassName":"portcullis-core"}}' | want refuse "a claim on portcullis-core (Retain)"
pvc '{"spec":{"storageClassName":"local-path"}}' | want refuse "a claim on k3s local-path"
pvc '{"spec":{"volumeName":"pvc-x"}}' | want refuse "a claim pre-bound to a volume"
pvc '{"spec":{"dataSource":{"kind":"PersistentVolumeClaim","name":"b--data"}}}' | want refuse "a claim cloned from another instance's"
pvc '{"spec":{"dataSourceRef":{"kind":"PersistentVolumeClaim","name":"b--data"}}}' | want refuse "a claim with a dataSourceRef"
pvc '{"metadata":{"name":"b--data"}}' | want refuse "a claim named after another instance"
pvc '{"metadata":{"annotations":{"portcullis.io/mode":"2750"}}}' | want refuse "a claim with mode 2750 (setgid)"
pvc '{"metadata":{"annotations":{"portcullis.io/mode":"4755"}}}' | want refuse "a claim with mode 4755 (setuid)"
pvc | jq 'del(.metadata.annotations["portcullis.io/mode"])' | want refuse "a claim without a mode"
# ── UPDATE / DELETE judged by the old object (final review I2) ──
# wantk <admit|refuse> <what> <kubectl args…> — as the Hub in the apps namespace; stdin as given.
wantk() {
  local w="$1" what="$2" out; shift 2
  if out="$(KH "$@" 2>&1)"; then
    [ "$w" = admit ] || fail "admitted, want refused: $what"
  else
    [ "$w" = refuse ] || fail "refused, want admitted: $what: $(printf '%s' "$out" | sed -n 1p | cut -c1-400)"
    printf '%s' "$out" | grep -q "with binding 'portcullis-apps-guard-" \
      || fail "refused, but not by an apps binding: $what: $(printf '%s' "$out" | sed -n 1p | cut -c1-400)"
  fi
  echo . >> "$CNT/$w"
}
OWN='{"portcullis.io/owner":"hub","portcullis.io/instance":"a"}'
# The chart's default-deny (owner=core): the Hub can neither delete nor rewrite it.
K -n "$APPS" get networkpolicy default-deny >/dev/null || fail "no default-deny NetworkPolicy in $APPS"
wantk refuse "the Hub deletes the apps default-deny" delete --dry-run=server networkpolicy default-deny
K -n "$APPS" get networkpolicy default-deny -o json \
  | jq '.metadata.labels["portcullis.io/owner"] = "hub" | .metadata.labels["portcullis.io/instance"] = "a" | .spec.podSelector = {matchLabels: {"portcullis.io/instance": "a"}}' \
  | wantk refuse "the Hub rewrites default-deny into an instance-shaped owner=hub policy" replace --dry-run=server -f -
wantk refuse "the Hub patches default-deny's selector" patch --dry-run=server networkpolicy default-deny --type=merge \
  -p '{"spec":{"podSelector":{"matchLabels":{"portcullis.io/instance":"a"}}}}'
# The Hub's own objects (created as the Hub, owner=hub): changed and deleted, but never moved to another instance or owner.
np "{\"to\":[$DNS],\"ports\":[{\"port\":53,\"protocol\":\"UDP\"}]}" | jq --argjson l "$OWN" '.metadata.name = "e2e-old-np" | .metadata.labels = $l' \
  | KH create -f - >/dev/null || fail "the Hub can't create its own NetworkPolicy"
K -n "$APPS" get networkpolicy e2e-old-np -o json | jq '.metadata.labels.x = "y"' | wantk admit "the Hub updates its own NetworkPolicy" replace --dry-run=server -f -
K -n "$APPS" get networkpolicy e2e-old-np -o json | jq '.spec.podSelector.matchLabels["portcullis.io/instance"] = "b"' \
  | wantk refuse "the Hub moves its NetworkPolicy to another instance's pods" replace --dry-run=server -f -
K -n "$APPS" get networkpolicy e2e-old-np -o json | jq '.metadata.labels["portcullis.io/owner"] = "core"' \
  | wantk refuse "the Hub relabels its NetworkPolicy owner=core" replace --dry-run=server -f -
wantk admit "the Hub deletes its own NetworkPolicy" delete --dry-run=server networkpolicy e2e-old-np
# Objects not owner=hub (made here by the CLI identity): the Hub can't change or delete them.
np "{\"to\":[$DNS],\"ports\":[{\"port\":53,\"protocol\":\"UDP\"}]}" | jq '.metadata.name = "e2e-old-np-cli"' | K -n "$APPS" create -f - >/dev/null
wantk refuse "the Hub deletes a NetworkPolicy without owner=hub" delete --dry-run=server networkpolicy e2e-old-np-cli
svc a--e2e-old "$OWN" | KH create -f - >/dev/null || fail "the Hub can't create its own Service"
K -n "$APPS" get service a--e2e-old -o json | jq '.metadata.labels.x = "y"' | wantk admit "the Hub updates its own Service" replace --dry-run=server -f -
K -n "$APPS" get service a--e2e-old -o json | jq '.metadata.labels["portcullis.io/owner"] = "core"' | wantk refuse "the Hub relabels its Service owner=core" replace --dry-run=server -f -
wantk admit "the Hub deletes its own Service" delete --dry-run=server service a--e2e-old
svc a--e2e-old-cli "$IA" | K -n "$APPS" create -f - >/dev/null
wantk refuse "the Hub deletes a Service without owner=hub" delete --dry-run=server service a--e2e-old-cli
sec() { jq -n --arg n "$1" --argjson l "$2" '{apiVersion: "v1", kind: "Secret", type: "Opaque", metadata: {name: $n, labels: $l}, data: {k: "dg=="}}'; }
sec a--e2e-old "$OWN" | KH create -f - >/dev/null || fail "the Hub can't create its own Secret"
K -n "$APPS" get secret a--e2e-old -o json | jq '.data.k = "dw=="' | wantk admit "the Hub updates its own Secret" replace --dry-run=server -f -
K -n "$APPS" get secret a--e2e-old -o json | jq '.metadata.labels["portcullis.io/instance"] = "b"' | wantk refuse "the Hub moves its Secret to another instance" replace --dry-run=server -f -
wantk admit "the Hub deletes its own Secret" delete --dry-run=server secret a--e2e-old
sec a--e2e-old-cli "$IA" | K -n "$APPS" create -f - >/dev/null
wantk refuse "the Hub deletes a Secret without owner=hub" delete --dry-run=server secret a--e2e-old-cli
wantk refuse "the Hub empties a Secret without owner=hub" patch --dry-run=server secret a--e2e-old-cli --type=merge -p '{"data":{"k":"eA=="}}'
pvc "{\"metadata\":{\"name\":\"a--e2e-old\",\"labels\":$OWN}}" | KH create -f - >/dev/null || fail "the Hub can't create its own claim"
K -n "$APPS" get pvc a--e2e-old -o json | jq '.metadata.labels.x = "y"' | wantk admit "the Hub updates its own claim" replace --dry-run=server -f -
K -n "$APPS" get pvc a--e2e-old -o json | jq '.metadata.labels["portcullis.io/instance"] = "b"' | wantk refuse "the Hub moves its claim to another instance" replace --dry-run=server -f -
K -n "$APPS" get pvc a--e2e-old -o json | jq '.metadata.labels["portcullis.io/owner"] = "core"' | wantk refuse "the Hub relabels its claim owner=core" replace --dry-run=server -f -
K -n "$APPS" get pvc a--e2e-old -o json | jq '.spec.volumeName = "pvc-e2e-other"' | wantk refuse "the Hub binds its claim to a volume of its choosing (only the volume binder sets volumeName)" replace --dry-run=server -f -
wantk admit "the Hub deletes its own claim" delete --dry-run=server pvc a--e2e-old
pvc '{"metadata":{"name":"a--e2e-old-cli"}}' | K -n "$APPS" create -f - >/dev/null
wantk refuse "the Hub deletes a claim without owner=hub" delete --dry-run=server pvc a--e2e-old-cli
wantk refuse "the Hub strips the pvc-protection finalizer of a claim without owner=hub" patch --dry-run=server pvc a--e2e-old-cli --type=merge -p '{"metadata":{"finalizers":null}}'
K -n "$APPS" get pvc a--e2e-old -o json | jq '.metadata.finalizers = []' | wantk admit "the Hub strips the finalizer of its own claim (owner=hub: judged as an update of its own)" replace --dry-run=server -f -
pvc "{\"metadata\":{\"name\":\"b--e2e-old-cli\",\"labels\":$OWN}}" | K -n "$APPS" create -f - >/dev/null
wantk refuse "the Hub deletes an owner=hub claim named after another instance" delete --dry-run=server pvc b--e2e-old-cli
# The PVC protection controller still removes its finalizer from claims the Hub can't touch: deletion completes.
K -n "$APPS" delete pvc a--e2e-old-cli b--e2e-old-cli --timeout=60s >/dev/null \
  || fail "claims without owner=hub never finished deleting (the pvc-protection controller refused?)"

# A real claim the Hub makes binds (the volume binder sets volumeName) once a pod uses it.
pvc '{"metadata":{"name":"a--e2e-bind","labels":{"portcullis.io/owner":"hub"}}}' | KH create -f - >/dev/null || fail "the Hub can't create a claim to bind"
jq -n --arg a "$A" '{apiVersion: "v1", kind: "Pod", metadata: {name: "a--e2e-bind", labels: {"portcullis.io/instance": "a", "portcullis.io/service": "web"}},
  spec: {automountServiceAccountToken: false, restartPolicy: "Never", volumes: [{name: "d", persistentVolumeClaim: {claimName: "a--e2e-bind"}}],
    securityContext: {runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, seccompProfile: {type: "RuntimeDefault"}},
    containers: [{name: "c", image: $a, command: ["true"], volumeMounts: [{name: "d", mountPath: "/d"}],
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}}}]}}' | KH create -f - >/dev/null || fail "the Hub can't create the binding pod"
K -n "$APPS" wait --for=jsonpath='{.status.phase}'=Bound pvc/a--e2e-bind --timeout=120s >/dev/null \
  || fail "the Hub's claim a--e2e-bind never bound (the volume binder refused?): $(K -n "$APPS" get pvc a--e2e-bind -o jsonpath='{.status.phase}')"
K -n "$APPS" delete pod a--e2e-bind --wait=false >/dev/null 2>&1 || true

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
# The HA vectors (Task 18): placement, core exec, nodeadm, portcullis-ingress.
python3 -I "$(dirname "$0")/e2e-k3s-ha-admission.py" "$CTX" || fail "the HA admission vectors (see above)"
echo "PASS: apps admission: $(wc -l < "$CNT/admit" | tr -d ' ') shapes admitted, $(wc -l < "$CNT/refuse" | tr -d ' ') refused by their bindings; a one-shot Job ran as uid 0"
