#!/usr/bin/env bash
# CI unit-tests, "Our SNR build" (plan Task 24 fix round 2, review M7): the
# patch in kube/ha/fencing/snr-patch applies to the pinned tag, the patched
# code vets, SNR's own certificates tests pass (envtest), the binary
# cross-compiles for arm64 (no emulation), and the image builds (amd64, no
# push). The push / sign is .github/workflows/snr.yml on main.
set -euo pipefail
cd "$(dirname "$0")/../.."
D=kube/ha/fencing/snr-patch
tag="$(sed -n 's/^ARG SNR_TAG=//p' "$D/Dockerfile" | head -n1)"
commit="$(sed -n 's/^ARG SNR_COMMIT=//p' "$D/Dockerfile" | head -n1)"
want="$(sed -n 's/^ARG PATCH_SHA256=//p' "$D/Dockerfile" | head -n1)"
got="$(sha256sum "$D/0001-secret-cache-own-namespace.patch" | cut -d' ' -f1)"
[ "$got" = "$want" ] || { echo "FAIL: the patch's sha256 is $got, the Dockerfile pins $want"; exit 1; }
W="${RUNNER_TEMP:-/tmp}/snr-src"
rm -rf "$W"
git clone -q --depth 1 --branch "$tag" https://github.com/medik8s/self-node-remediation.git "$W"
[ "$(git -C "$W" rev-parse HEAD)" = "$commit" ] || { echo "FAIL: $tag isn't $commit"; exit 1; }
git -C "$W" apply --check "$PWD/$D/0001-secret-cache-own-namespace.patch"
git -C "$W" apply "$PWD/$D/0001-secret-cache-own-namespace.patch"
# envtest (SNR's Makefile: 1.34), the tool pinned by its module version.
assets="$(cd "${RUNNER_TEMP:-/tmp}" && go run sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.2 use 1.34.x --bin-dir "${RUNNER_TEMP:-/tmp}/snr-envtest" -p path)"
( cd "$W"
  export GOTOOLCHAIN=local GOFLAGS=-mod=vendor
  test -z "$(gofmt -l cmd internal/certificates)"
  go vet ./cmd/... ./internal/certificates/...
  KUBEBUILDER_ASSETS="$assets" go test -count=1 ./internal/certificates/...
  CGO_ENABLED=0 GOARCH=arm64 go build -o /dev/null ./cmd )
docker build -q -t portcullis-snr:ci "$D" >/dev/null
docker run --rm --entrypoint /usr/bin/nsenter portcullis-snr:ci --version >/dev/null
echo "PASS: our SNR build ($tag + the patch $got): applies, vets, certificates tests, arm64 cross-compile, image"
