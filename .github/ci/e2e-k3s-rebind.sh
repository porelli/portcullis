#!/usr/bin/env bash
# e2e-k3s "admission params re-bind" (controller ruling: no unbound window):
# while the Hub's ServiceAccount creates a route on a reserved host in a loop
# (real creates, `kubectl --as`), the params change twice through
# `./portcullis up` (HUB_OVERRIDE_BIND_ROOTS → bindRoots → a new params
# generation, then back). Not one create may be admitted; every refusal comes
# from an edge binding; afterwards exactly one generation's swapped bindings
# and the fixed portcullis-nodes-guard-removed once.
set -euo pipefail
cd "$(dirname "$0")/../.."
K() { kubectl --context ci "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
HUB="system:serviceaccount:portcullis:portcullis-hub"
D="$(grep '^PORTCULLIS_DOMAIN=' .env | cut -d= -f2-)"
T="$(mktemp -d)"; trap 'touch "$T/stop"; wait 2>/dev/null || true; K -n portcullis-edge delete ingressroute -l portcullis.io/instance=e2e-rebind --wait=false >/dev/null 2>&1 || true; rm -rf "$T"' EXIT
mk() {
  N="$1" H="hub.$D" jq -n '{apiVersion: "traefik.io/v1alpha1", kind: "IngressRoute",
    metadata: {name: env.N, labels: {"portcullis.io/owner": "hub", "portcullis.io/instance": "e2e-rebind"}},
    spec: {entryPoints: ["websecure"], routes: [{match: ("Host(`" + env.H + "`)"), kind: "Rule",
      services: [{name: "e2e-rebind", namespace: "portcullis-apps", port: 80}]}], tls: {}}}'
}
( i=0; while [ ! -e "$T/stop" ]; do i=$((i + 1))
    if out="$(mk "e2e-rebind-$i" | K --as="$HUB" -n portcullis-edge create -f - 2>&1)"; then echo "ADMITTED $i" >> "$T/log"
    else case "$out" in *"binding 'portcullis-edge-guard-routes-"*"reserved core hostname"*) echo "refused" >> "$T/log" ;; *) echo "OTHER $i ${out:0:200}" >> "$T/log" ;; esac; fi
  done ) &
sleep 5
old="$(grep '^HUB_OVERRIDE_BIND_ROOTS=' .env || true)"
bash -c 'source scripts/lib/common.sh; env_set HUB_OVERRIDE_BIND_ROOTS /srv:/mnt:/media:/opt/e2e-rebind'
./portcullis up >/dev/null
if [ -n "$old" ]; then bash -c "source scripts/lib/common.sh; env_set HUB_OVERRIDE_BIND_ROOTS '${old#*=}'"; else sed -i '/^HUB_OVERRIDE_BIND_ROOTS=/d' .env; fi
./portcullis up >/dev/null
sleep 5; touch "$T/stop"; wait
r="$(grep -c '^refused' "$T/log" || true)" a="$(grep -c '^ADMITTED' "$T/log" || true)" o="$(grep -c '^OTHER' "$T/log" || true)"
[ "$a" = 0 ] || fail "a reserved-host route was admitted during a params change ($a times)"
[ "$r" -gt 10 ] || fail "only $r refusals recorded (the loop didn't run through the changes)"
[ "$o" = 0 ] || { grep -m3 '^OTHER' "$T/log"; fail "$o creates failed for another reason than the edge binding"; }
b="$(K get validatingadmissionpolicybinding -l portcullis.io/binding -o json)"
# The generation-swapped bindings: exactly one generation, every one of them
# labelled; portcullis-nodes-guard-removed (Task 30 fix round 2) is no
# generation's: its fixed name on its own params, exactly once.
n="$(printf '%s' "$b" | jq '[.items[] | select(.metadata.name != "portcullis-nodes-guard-removed") | .metadata.labels["portcullis.io/params-generation"]] | unique | length')"
[ "$n" = 1 ] || fail "$n params generations bound after the changes (want 1)"
printf '%s' "$b" | jq -e '[.items[] | select(.metadata.name != "portcullis-nodes-guard-removed") | .metadata.labels["portcullis.io/params-generation"] | select(. == null)] | length == 0' >/dev/null \
  || fail "a swapped binding has no params generation"
rb="$(printf '%s' "$b" | jq -c '[.items[] | select(.metadata.labels["portcullis.io/binding"] == "portcullis-nodes-guard-removed")] | map([.metadata.name, .spec.paramRef.name, (.metadata.labels["portcullis.io/params-generation"] // "-")] | join(" "))')"
[ "$rb" = '["portcullis-nodes-guard-removed portcullis-removed-nodes -"]' ] || fail "the removed-nodes binding isn't exactly once, fixed, on portcullis-removed-nodes: $rb"
echo "PASS: two params changes under a looped Hub create of hub.$D: $r refused, 0 admitted; one generation bound; portcullis-nodes-guard-removed once on its own params"
