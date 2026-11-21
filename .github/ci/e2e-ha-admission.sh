#!/usr/bin/env bash
# e2e-ha-admission.sh <kube context> — the HA pod policies against a live
# API server (plan Task 24 fix round 1, security review): applies
# portcullis-fencing-pods (ha_render fencing's policy + binding) and the
# host probes' namespace with portcullis-ha-probe-pods and its params
# (ha.sh _ha_probe_setup), then server-dry-runs every vector of
# tests/ha_admission_vectors.json: an allowed one must be admitted, a
# refused one refused BY ITS POLICY (the message names it); an
# "ephemeral" vector adds an ephemeral container to its (admitted, real)
# pod through pods/ephemeralcontainers; a "node" vector patches the first
# Node as a node identity or SNR's manager under portcullis-node-labels
# (round 3 I1: the storm guard's inputs). Run by
# e2e-ha-vm (Task 33) after the HA installs; locally against k3d / k3s.
# With HUB_DEV=1 + PORTCULLIS_DEV_SNR_IMAGE the vectors' SNR image is that
# one (as ha_render's).
set -euo pipefail
cd "$(dirname "$0")/../.."
ctx="${1:?usage: e2e-ha-admission.sh <kube context>}"
export PORTCULLIS_KUBE_CONTEXT="$ctx" PORTCULLIS_KUBE_INSTALL_ID="${PORTCULLIS_KUBE_INSTALL_ID:-0e2e0000-0000-4000-8000-0000000000aa}"
lib() { bash -c 'source scripts/lib/common.sh; '"$1"; }
lib '_ha_probe_setup; psa="$(kube_psa fencing)"; kube_namespace_apply portcullis-fencing $psa'
# The policies, the class the shapes name and the ServiceAccounts they run
# as (the admission chain looks them up before any policy judges).
kubectl --context "$ctx" apply --server-side --force-conflicts --field-manager=portcullis-cli -f kube/priorityclasses.yaml >/dev/null
for ns in portcullis-fencing portcullis-ha-probe; do
  kubectl --context "$ctx" -n "$ns" create serviceaccount vector-sa --dry-run=client -o json | kubectl --context "$ctx" apply -f - >/dev/null
done
lib 'ha_render fencing' | python3 -c 'import sys, yaml, json
keep = ("ServiceAccount", "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding")
print(json.dumps({"apiVersion": "v1", "kind": "List", "items": [d for d in yaml.safe_load_all(sys.stdin) if d and (d["kind"].startswith("ValidatingAdmissionPolicy") or d["kind"] in keep)]}))' \
  | kubectl --context "$ctx" apply --server-side --force-conflicts --field-manager=portcullis-cli -f - >/dev/null
# portcullis-node-labels (round 3 I1) with its binding and a params
# ConfigMap of a test generation; SNR's RBAC above lets the manager patch.
kubectl --context "$ctx" create namespace portcullis --dry-run=client -o json | kubectl --context "$ctx" apply -f - >/dev/null
kubectl --context "$ctx" -n portcullis create configmap portcullis-admission-params --from-literal=generation=e2e0ha0000000000 --dry-run=client -o json \
  | kubectl --context "$ctx" apply -f - >/dev/null
python3 -c 'import sys, yaml, json
docs = [d for f in sys.argv[1:] for d in yaml.safe_load_all(open(f)) if d]
print(json.dumps({"apiVersion": "v1", "kind": "List", "items": [d for d in docs if d["metadata"]["name"] in ("portcullis-node-labels", "portcullis-nodes-guard-labels")]}))' \
  kube/admission/policies.yaml kube/admission/bindings.yaml \
  | kubectl --context "$ctx" apply --server-side --force-conflicts --field-manager=portcullis-cli -f - >/dev/null
node="$(kubectl --context "$ctx" get nodes -o jsonpath='{.items[0].metadata.name}')"
pinned="$(lib 'printf %s "$HA_SNR_IMAGE"')" img="$(lib ha_snr_image)"
sleep 3   # the bindings see their params
fail=0 n=0
while IFS= read -r v; do
  n=$((n + 1))
  name="$(jq -r .name <<<"$v")" allowed="$(jq -r .allowed <<<"$v")" policy="$(jq -r .policy <<<"$v")"
  if [ "$(jq -r '.node // false' <<<"$v")" = true ]; then
    # A Node patch as a node identity / SNR's manager (impersonated).
    as=(--as "$(jq -r .as.user <<<"$v" | sed "s|@NODE@|$node|")")
    while IFS= read -r g; do as+=(--as-group "$g"); done < <(jq -r '.as.groups[]' <<<"$v")
    if jq -e '.taints_add' <<<"$v" >/dev/null; then
      p="$(kubectl --context "$ctx" get node "$node" -o json | jq -c --argjson a "$(jq -c .taints_add <<<"$v")" '{spec: {taints: ((.spec.taints // []) + $a)}}')"
    else p="$(jq -c .patch <<<"$v")"; fi
    out="$(kubectl --context "$ctx" "${as[@]}" patch node "$node" --type=merge -p "$p" --dry-run=server 2>&1)" && got=true || got=false
  elif [ "$(jq -r '.ephemeral // false' <<<"$v")" = true ]; then
    # pods/ephemeralcontainers: an admitted pod made for real, then the
    # subresource update (server dry-run), then the pod removed.
    ns="$(jq -r .pod.metadata.namespace <<<"$v")" pn="$(jq -r .pod.metadata.name <<<"$v")"
    jq -c .pod <<<"$v" | sed "s|$pinned|$img|g" | kubectl --context "$ctx" create -f - >/dev/null
    out="$(kubectl --context "$ctx" -n "$ns" get pod "$pn" -o json | jq --argjson e "$(jq -c .ephemeralContainers <<<"$v")" '.spec.ephemeralContainers = $e' \
      | kubectl --context "$ctx" replace --subresource=ephemeralcontainers --dry-run=server -f - 2>&1)" && got=true || got=false
    kubectl --context "$ctx" -n "$ns" delete pod "$pn" --wait=false >/dev/null 2>&1 || true
  else
    out="$(jq -c .pod <<<"$v" | sed "s|$pinned|$img|g" | kubectl --context "$ctx" create --dry-run=server -f - 2>&1)" && got=true || got=false
  fi
  if [ "$allowed" = true ] && [ "$got" = true ]; then echo "ok   - $name: admitted"
  elif [ "$allowed" = false ] && [ "$got" = false ] && grep -q "$policy" <<<"$out"; then echo "ok   - $name: refused by $policy"
  else echo "FAIL - $name: allowed=$allowed got=$got: $(head -c 300 <<<"$out")"; fail=1; fi
done < <(jq -c '.[]' tests/ha_admission_vectors.json)
echo "$n vectors"
exit "$fail"
