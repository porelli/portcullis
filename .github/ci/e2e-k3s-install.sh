#!/usr/bin/env bash
# e2e-k3s "Install k3s" (also used by portcullis-templates' Test Apps,
# Task 10): k3s and kubectl at the pinned versions (sha256-checked), k3s
# through the CLI's own kube_install_mesh + kube_install_k3s
# (scripts/lib/kube_install.sh: the node mesh pcmesh 10.215.0.1, embedded
# etcd, the server flags of tests/fixtures/k3s-server-flags.txt — the network
# policy controller and ServiceLB on), the kubeconfig context `ci` in
# ~/.kube/config (0600).
#
#   e2e-k3s-install.sh [--netns-client]
#
# --netns-client (Task 0 Q1): a network namespace `ext` (198.51.100.2) joined
# by a veth to the node (198.51.100.1), and k3s with
# --node-external-ip=198.51.100.1, so a curl from `ext` to 198.51.100.1 is
# an outside client ServiceLB publishes (its address must reach Traefik).
set -euo pipefail

K3S_VERSION="v1.37.2+k3s1"
KUBECTL_VERSION="v1.37.2"
HELM_VERSION=v4.3.1
# Per architecture (CI: amd64; a local arm64 runner, .github/ci/e2e-k3s-local.sh).
case "$(uname -m)" in
  x86_64)
    ARCH=amd64
    K3S_SHA256=265b3ee6a3198ef14033c63ef46cbb32370d83795199fb6d1b01f21575eddbda
    KUBECTL_SHA256=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4
    HELM_SHA256=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b ;;
  aarch64|arm64)
    ARCH=arm64
    K3S_SHA256=a779ccf1e5e2e33a62f5a29c2f1c0bbf99431e100579d4c10f0aa0742a6aa84b
    KUBECTL_SHA256=fcc16f63186659d9722014b7e02d5fdd2d4e669cb8c0ab66365d7d3b8ba03509
    HELM_SHA256=8cf8f66ecbc252ac8f7f06cca68aba88508ddfde3a6a34feb1678ad1694b4f88 ;;
  *) echo "FAIL: no pinned k3s / kubectl / helm for $(uname -m)"; exit 1 ;;
esac
# K3S_LINE=1.33: the oldest supported minor (the floor: supplementalGroupsPolicy
# Strict, CEL without flatten() etc.); CI runs the default, 1.37.
case "${K3S_LINE:-1.37}" in
  1.37) ;;
  1.33)
    K3S_VERSION="v1.33.13+k3s2" KUBECTL_VERSION="v1.33.13"
    case "$ARCH" in
      amd64) K3S_SHA256=1572f0f23bd5a844bd405b71875877aacacc7ab79e279d3d73735654c37c7735
             KUBECTL_SHA256=316d712726d857c20744c57cb36aa47cfc79bc0af7e82cebf3780244b654c073 ;;
      arm64) K3S_SHA256=cf6afb3944f9ecf120fa2837b542479018c08f9ea1d1d181d4a68445e7717a8d
             KUBECTL_SHA256=9fe8aadd5aab9421978c7ac95de6fad304a3c4c0ce9dbf4127579779e0699080 ;;
    esac ;;
  *) echo "FAIL: K3S_LINE is 1.37 (default) or 1.33"; exit 2 ;;
esac

netns=false
case "${1:-}" in
  --netns-client) netns=true ;;
  "") ;;
  *) echo "usage: $0 [--netns-client]" >&2; exit 2 ;;
esac

tmp="$(mktemp -d)"
fetch() { # fetch <url> <sha256> <out>
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet - || { echo "FAIL: $1 doesn't match its pinned sha256"; exit 1; }
}
fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/$ARCH/kubectl" "$KUBECTL_SHA256" "$tmp/kubectl"
fetch "https://get.helm.sh/helm-$HELM_VERSION-linux-$ARCH.tar.gz" "$HELM_SHA256" "$tmp/helm.tgz"
tar -xzf "$tmp/helm.tgz" -C "$tmp" --strip-components=1 "linux-$ARCH/helm"
sudo install -m 0755 "$tmp/kubectl" /usr/local/bin/kubectl
sudo install -m 0755 "$tmp/helm" /usr/local/bin/helm
rm -rf "$tmp"

extra=()
if [ "$netns" = true ]; then
  sudo ip netns add ext
  sudo ip link add ext-host type veth peer name ext-ns
  sudo ip link set ext-ns netns ext
  sudo ip addr add 198.51.100.1/24 dev ext-host
  sudo ip link set ext-host up
  sudo ip netns exec ext ip addr add 198.51.100.2/24 dev ext-ns
  sudo ip netns exec ext ip link set ext-ns up
  sudo ip netns exec ext ip link set lo up
  extra+=(--node-external-ip=198.51.100.1)
fi

# CI runner only (never the product: ./portcullis refuses such a host and
# names the options): Ubuntu 26.04's
# kernel.apparmor_restrict_unprivileged_unconfined=1 stacks containerd's
# AppArmor profile, whose signal rules then deny signals inside containers
# (Postgres never finishes starting; containerd#14485, k3s#13625).
aa=/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined
if [ -r "$aa" ] && [ "$(cat "$aa")" = 1 ]; then
  sudo sysctl -qw kernel.apparmor_restrict_unprivileged_unconfined=0
  echo "CI runner: kernel.apparmor_restrict_unprivileged_unconfined 1 → $(cat "$aa") (containerd#14485)"
fi

# k3s the way `init --runtime kubernetes` installs it (the pins overridden
# only for K3S_LINE): the mesh, then the server with the shared flags.
here="$(cd "$(dirname "$0")/../.." && pwd)"
command -v wg-quick >/dev/null 2>&1 || { sudo apt-get update -q && sudo apt-get install -y -q --no-install-recommends wireguard-tools; }
(
  # shellcheck source=../../scripts/lib/common.sh
  . "$here/scripts/lib/common.sh"
  # shellcheck disable=SC2034  # the pins kube_install_k3s reads (K3S_LINE)
  KUBE_K3S_VERSION="$K3S_VERSION"
  # shellcheck disable=SC2034
  case "$ARCH" in amd64) KUBE_K3S_SHA256_AMD64="$K3S_SHA256" ;; arm64) KUBE_K3S_SHA256_ARM64="$K3S_SHA256" ;; esac
  export KUBE_INSTALL_KUBECONFIG="$HOME/.kube/config" KUBE_INSTALL_CONTEXT=ci
  kube_install_mesh
  kube_install_k3s ${extra[@]+"${extra[@]}"}
)
kubectl config get-contexts -o name | grep -qx ci || { echo "FAIL: no context ci"; exit 1; }
kubectl --context ci wait --for=condition=Ready node --all --timeout=180s
# Spike run 1: the coredns Deployment appears a moment after the node.
for i in $(seq 1 60); do
  kubectl --context ci -n kube-system get deploy coredns >/dev/null 2>&1 && break
  [ "$i" -eq 60 ] && { echo "FAIL: no coredns Deployment"; exit 1; }
  sleep 2
done
kubectl --context ci -n kube-system rollout status deploy/coredns --timeout=180s
kubectl --context ci version
echo "PASS: k3s $K3S_VERSION (kube_install_k3s on pcmesh${extra[*]:+, ${extra[*]}}), kubectl $KUBECTL_VERSION, helm $HELM_VERSION; context ci"
