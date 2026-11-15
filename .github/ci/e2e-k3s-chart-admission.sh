#!/usr/bin/env bash
# e2e-k3s "chart objects through the admission policies": the chart rendered
# with this install's values (secrets/kube/values.yaml), and every object in
# the apps and edge namespaces server-dry-run applied
#   - as the CLI's identity (this context; helm's server-side apply runs as
#     it): each admitted;
#   - as the Hub's ServiceAccount (system:masters only so RBAC lets it reach
#     admission): each object the policies judge refused (the shape rules
#     are never loosened for anyone but the CLI).
#   bash .github/ci/e2e-k3s-chart-admission.sh [<context>]   (default ci)
set -euo pipefail
cd "$(dirname "$0")/../.."
CTX="${1:-ci}" VALUES="${VALUES:-secrets/kube/values.yaml}"
HUB="system:serviceaccount:portcullis:portcullis-hub"
fail() { echo "FAIL: $*"; exit 1; }
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
helm template portcullis charts/portcullis -n portcullis --kube-context "$CTX" -f "$VALUES" ${EXTRA_VALUES:+-f "$EXTRA_VALUES"} > "$T/all.yaml" \
  || fail "helm template"
python3 - "$T" <<'PY'
import json, sys, yaml, pathlib
t = pathlib.Path(sys.argv[1]); n = 0
for d in yaml.safe_load_all((t / "all.yaml").read_text()):
    if d and d.get("metadata", {}).get("namespace") in ("portcullis-apps", "portcullis-edge"):
        n += 1; (t / f"obj-{n:03d}.json").write_text(json.dumps(d))
print(f"{n} chart objects in the apps and edge namespaces")
PY
judged='^(NetworkPolicy|Service|Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|Secret|IngressRoute|Middleware|IngressRouteTCP|IngressRouteUDP|TLSOption|TLSStore|ServersTransport|TraefikService|MiddlewareTCP)$'
ok=0 refused=0
for f in "$T"/obj-*.json; do
  [ -e "$f" ] || continue
  kind="$(jq -r .kind "$f")" what="$(jq -r '.kind + " " + .metadata.namespace + "/" + .metadata.name' "$f")"
  out="$(kubectl --context "$CTX" apply --server-side --force-conflicts --field-manager=portcullis-chart-check --dry-run=server -f "$f" 2>&1)" \
    || fail "the CLI's own identity was refused $what: ${out:0:400}"
  ok=$((ok + 1))
  if [[ "$kind" =~ $judged ]]; then
    if out="$(kubectl --context "$CTX" --as="$HUB" --as-group=system:masters apply --server-side --force-conflicts \
        --field-manager=portcullis-chart-check --dry-run=server -f "$f" 2>&1)"; then
      fail "the Hub's ServiceAccount may write the chart's $what"
    fi
    printf '%s' "$out" | grep -q 'ValidatingAdmissionPolicy' || fail "the Hub writing $what refused, but not by a policy: ${out:0:300}"
    refused=$((refused + 1))
  fi
done
[ "$ok" -gt 0 ] || fail "no chart object in the apps / edge namespaces"
echo "PASS: $ok chart objects in the apps and edge namespaces admitted for the CLI; the $refused the policies judge refused for the Hub"
