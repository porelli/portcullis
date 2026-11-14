#!/usr/bin/env bash
# CI unit-tests, "Kubernetes chart: static checks" (Task 13): helm lint,
# helm template → kubeconform -strict (pinned Kubernetes schemas + the
# pinned Traefik CRDs), tests/k8s_parity.py, tests/k8s_netpol_matrix.py,
# tests/k8s_hardening.py, and the byte copies of the Hub's Role (K13) on
# the same-named Hub branch, else main. Locally: HELM / KUBECONFORM point at
# the binaries, PY at a python3 with PyYAML (tests/k8s-requirements.txt).
set -euo pipefail
cd "$(dirname "$0")/../.."

# Pinned tools (sha256 of the linux-amd64 release archives).
HELM_VERSION=v4.3.1
HELM_SHA256=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b
KUBECONFORM_VERSION=v0.8.0
KUBECONFORM_SHA256=9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883
# yannh/kubernetes-json-schema at a fixed commit, the API floor's schemas.
K8S_SCHEMA_COMMIT=2bfaff3898a7a4fa4e4760da3d2656211c9b4c71
K8S_VERSION=1.32.0

TOOLS="${RUNNER_TEMP:-/tmp}/k8s-tools"
mkdir -p "$TOOLS"
fetch() { # fetch <url> <sha256> <out>
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet - || { echo "FAIL: $1 doesn't match its pinned sha256"; exit 1; }
}
if [ -z "${HELM:-}" ]; then
  fetch "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz" "$HELM_SHA256" "$TOOLS/helm.tgz"
  tar -xzf "$TOOLS/helm.tgz" -C "$TOOLS" --strip-components=1 linux-amd64/helm
  HELM="$TOOLS/helm"
fi
if [ -z "${KUBECONFORM:-}" ]; then
  fetch "https://github.com/yannh/kubeconform/releases/download/$KUBECONFORM_VERSION/kubeconform-linux-amd64.tar.gz" "$KUBECONFORM_SHA256" "$TOOLS/kubeconform.tgz"
  tar -xzf "$TOOLS/kubeconform.tgz" -C "$TOOLS" kubeconform
  KUBECONFORM="$TOOLS/kubeconform"
fi
if [ -z "${PY:-}" ]; then
  if [ ! -x /tmp/k8s-venv/bin/python ]; then
    python3 -m venv /tmp/k8s-venv
    /tmp/k8s-venv/bin/pip install --quiet --disable-pip-version-check --require-hashes --only-binary=:all: -r tests/k8s-requirements.txt
  fi
  PY=/tmp/k8s-venv/bin/python
fi
export HELM

echo "::group::helm lint"
"$HELM" lint charts/portcullis -f tests/k8s-ci-values.yaml -f <("$PY" -c 'import sys; sys.path.insert(0, "tests"); import k8s_lib, yaml; print(yaml.safe_dump(k8s_lib.images_values()))')
echo "::endgroup::"

# The Traefik CRDs as JSON schemas (strict: unknown fields refused).
SCHEMAS="$TOOLS/crd-schemas"
rm -rf "$SCHEMAS" && mkdir -p "$SCHEMAS"
"$PY" - charts/portcullis/crds/*.yaml "$SCHEMAS" <<'PY'
import json, pathlib, sys, yaml
*files, out = sys.argv[1:]
def strict(s):
    if isinstance(s, dict):
        if s.get("type") == "object" and "properties" in s and "additionalProperties" not in s \
           and not s.get("x-kubernetes-preserve-unknown-fields"):
            s["additionalProperties"] = False
        for v in s.values():
            strict(v)
    elif isinstance(s, list):
        for v in s:
            strict(v)
n = 0
for f in files:
    for d in yaml.safe_load_all(open(f)):
        if not d or d.get("kind") != "CustomResourceDefinition":
            continue
        g, kind = d["spec"]["group"], d["spec"]["names"]["kind"].lower()
        for v in d["spec"]["versions"]:
            sch = v["schema"]["openAPIV3Schema"]
            strict(sch)
            p = pathlib.Path(out, g)
            p.mkdir(parents=True, exist_ok=True)
            (p / f"{kind}_{v['name']}.json").write_text(json.dumps(sch))
            n += 1
print(f"{n} CRD schemas")
PY

echo "::group::helm template → kubeconform (every profile on, every profile off, VPN modes)"
IMGV="$TOOLS/images-values.yaml"
"$PY" -c 'import sys; sys.path.insert(0, "tests"); import k8s_lib, yaml; print(yaml.safe_dump(k8s_lib.images_values()))' > "$IMGV"
for combo in "--set renderNamespaces=true" \
             "--set renderNamespaces=true --set wg.enabled=false --set monitoring.enabled=false" \
             "--set entrypoints.web.admin=parked --set entrypoints.ep.admin=vpnsecure"; do
  # shellcheck disable=SC2086  # the combo's flags
  "$HELM" template portcullis charts/portcullis -n portcullis -f tests/k8s-ci-values.yaml -f "$IMGV" $combo > "$TOOLS/rendered.yaml"
  "$KUBECONFORM" -strict -summary -kubernetes-version "$K8S_VERSION" \
    -schema-location "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/$K8S_SCHEMA_COMMIT/{{ .NormalizedKubernetesVersion }}-standalone{{ .StrictSuffix }}/{{ .ResourceKind }}{{ .KindSuffix }}.json" \
    -schema-location "$SCHEMAS/{{ .Group }}/{{ .ResourceKind }}_{{ .ResourceAPIVersion }}.json" \
    "$TOOLS/rendered.yaml"
done
for os in dns-tool hub; do
  "$HELM" template portcullis charts/portcullis -n portcullis -f tests/k8s-ci-values.yaml -f "$IMGV" --set-string "oneshot=$os" --show-only templates/oneshot.yaml > "$TOOLS/oneshot.yaml"
  "$KUBECONFORM" -strict -summary -kubernetes-version "$K8S_VERSION" \
    -schema-location "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/$K8S_SCHEMA_COMMIT/{{ .NormalizedKubernetesVersion }}-standalone{{ .StrictSuffix }}/{{ .ResourceKind }}{{ .KindSuffix }}.json" \
    "$TOOLS/oneshot.yaml"
done
# The CLI-applied manifests (probe, storage, admission; not the template of
# the params' keys).
KUBE_FILES=()
while IFS= read -r f; do KUBE_FILES+=("$f"); done < <(ls kube/probe/*.yaml kube/storage/*.yaml; find kube/admission -name '*.yaml' ! -name '*.tmpl.yaml' | sort)
"$KUBECONFORM" -strict -summary -kubernetes-version "$K8S_VERSION" \
  -schema-location "https://raw.githubusercontent.com/yannh/kubernetes-json-schema/$K8S_SCHEMA_COMMIT/{{ .NormalizedKubernetesVersion }}-standalone{{ .StrictSuffix }}/{{ .ResourceKind }}{{ .KindSuffix }}.json" \
  "${KUBE_FILES[@]}"
echo "::endgroup::"

# A missing required value is refused at render time (compose's ${VAR:?}).
if "$HELM" template portcullis charts/portcullis -n portcullis -f tests/k8s-ci-values.yaml -f "$IMGV" --set domain= >/dev/null 2>&1; then
  echo "FAIL: the chart renders without domain (required)"; exit 1
fi
if "$HELM" template portcullis charts/portcullis -n portcullis -f tests/k8s-ci-values.yaml -f "$IMGV" --set images.vault=docker.io/hashicorp/vault:2.2.1 >/dev/null 2>&1; then
  echo "FAIL: the chart renders an image without a digest"; exit 1
fi
# The egress policy fails closed without the node / API addresses, and
# excludes every API endpoint even off the nodes.
for empty in nodeAddresses apiEndpoints; do
  if "$HELM" template portcullis charts/portcullis -n portcullis -f tests/k8s-ci-values.yaml -f "$IMGV" --set "$empty=null" >/dev/null 2>&1 \
     || "$HELM" template portcullis charts/portcullis -n portcullis -f tests/k8s-ci-values.yaml -f "$IMGV" --set-json "$empty=[]" >/dev/null 2>&1; then
    echo "FAIL: the chart renders the egress policy with an empty $empty"; exit 1
  fi
done
"$HELM" template portcullis charts/portcullis -n portcullis -f tests/k8s-ci-values.yaml -f "$IMGV" --set-json 'apiEndpoints=["10.1.0.4:6443","10.9.8.7:6443"]' --show-only templates/netpol-networks.yaml \
  | "$PY" -c 'import sys, yaml
p = [d for d in yaml.safe_load_all(sys.stdin) if d and d["metadata"]["name"] == "egress-internet"][0]
ex = p["spec"]["egress"][0]["to"][0]["ipBlock"]["except"]
want = {"10.42.0.0/24", "10.43.0.0/16", "169.254.0.0/16", "10.1.0.4/32", "198.51.100.1/32", "10.9.8.7/32"}
sys.exit(0 if set(ex) == want else "FAIL: egress-internet except %s != %s" % (sorted(ex), sorted(want)))'
echo "PASS: the egress policy refuses an empty nodeAddresses / apiEndpoints and excludes every API endpoint"

"$PY" tests/k8s_parity.py
"$PY" tests/k8s_netpol_matrix.py
"$PY" tests/k8s_hardening.py

# K13: the Hub authors its Role (and the admission YAML, kube/admission/);
# core keeps byte copies, compared on the same-named Hub branch, else main.
REF="${REF:-${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-}}}"
url="https://github.com/porelli/portcullis-hub"
heads=$(git ls-remote --heads "$url") || { echo "::error::git ls-remote $url failed"; exit 1; }
ref=main
if [[ "$REF" =~ ^[A-Za-z0-9._/-]+$ ]] && [ "$REF" != main ] \
  && awk -v r="refs/heads/$REF" '$2 == r { f = 1 } END { exit !f }' <<<"$heads"; then
  ref="$REF"
fi
sha=$(awk -v r="refs/heads/$ref" '$2 == r { print $1 }' <<<"$heads")
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "::error::portcullis-hub has no single commit for refs/heads/$ref"; exit 1; }
copies="charts/portcullis/files/hub-role.yaml=internal/runtime/kube/testdata/role.yaml"
if [ -d kube/admission ]; then
  for f in kube/admission/policies.yaml kube/admission/bindings.yaml kube/admission/params.yaml; do
    copies="$copies $f=internal/runtime/kube/testdata/admission/${f##*/}"
  done
fi
fail=0
for pair in $copies; do
  own="${pair%%=*}" theirs="${pair#*=}"
  if ! curl -fsSL --retry 3 -o "$TOOLS/theirs" "https://raw.githubusercontent.com/porelli/portcullis-hub/$sha/$theirs"; then
    echo "::error::portcullis-hub $ref ($sha) has no $theirs: core's $own is a byte copy of it (K13)"; fail=1; continue
  fi
  cmp -s "$own" "$TOOLS/theirs" || { echo "::error::$own differs from portcullis-hub $ref:$theirs ($sha)"; diff "$own" "$TOOLS/theirs" | head -40; fail=1; }
done
[ "$fail" = 0 ] || exit 1
echo "PASS: the chart lints, validates and matches compose; the Hub's copies are equal ($ref $sha)"
