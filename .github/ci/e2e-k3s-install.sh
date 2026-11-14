#!/usr/bin/env bash
# e2e-k3s "Install k3s" (also used by portcullis-templates' Test Apps,
# Task 10): k3s and kubectl at the pinned versions (sha256-checked), the
# spec § 6 flags (--disable=traefik, --secrets-encryption,
# --kubelet-arg=pod-max-pids=1024; the network policy controller and
# ServiceLB on), the kubeconfig context `ci` in ~/.kube/config (0600).
#
#   e2e-k3s-install.sh [--netns-client]
#
# --netns-client (Task 0 Q1): a network namespace `ext` (198.51.100.2) joined
# by a veth to the node (198.51.100.1), and k3s with
# --node-external-ip=198.51.100.1, so a curl from `ext` to 198.51.100.1 is
# an outside client ServiceLB publishes (its address must reach Traefik).
set -euo pipefail

K3S_VERSION="v1.37.2+k3s1"
K3S_SHA256=265b3ee6a3198ef14033c63ef46cbb32370d83795199fb6d1b01f21575eddbda
KUBECTL_VERSION="v1.37.2"
KUBECTL_SHA256=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4
HELM_VERSION=v4.3.1
HELM_SHA256=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b

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
fetch "https://github.com/k3s-io/k3s/releases/download/${K3S_VERSION//+/%2B}/k3s" "$K3S_SHA256" "$tmp/k3s"
fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" "$KUBECTL_SHA256" "$tmp/kubectl"
fetch "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz" "$HELM_SHA256" "$tmp/helm.tgz"
tar -xzf "$tmp/helm.tgz" -C "$tmp" --strip-components=1 linux-amd64/helm
sudo install -m 0755 "$tmp/k3s" /usr/local/bin/k3s
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

# k3s as a systemd unit (the install script isn't pinned: the binary is).
sudo tee /etc/systemd/system/k3s.service >/dev/null <<UNIT
[Unit]
Description=k3s (Portcullis CI)
After=network-online.target
[Service]
Type=notify
ExecStart=/usr/local/bin/k3s server --disable=traefik --secrets-encryption --kubelet-arg=pod-max-pids=1024 --write-kubeconfig-mode=0600 ${extra[*]}
KillMode=process
Delegate=yes
LimitNOFILE=1048576
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable --now k3s.service

for i in $(seq 1 90); do
  sudo test -s /etc/rancher/k3s/k3s.yaml && sudo k3s kubectl get nodes >/dev/null 2>&1 && break
  [ "$i" -eq 90 ] && { echo "FAIL: k3s didn't start"; sudo journalctl -u k3s --no-pager | tail -50; exit 1; }
  sleep 2
done
mkdir -p "$HOME/.kube"
sudo cat /etc/rancher/k3s/k3s.yaml | sed 's/: default$/: ci/' > "$HOME/.kube/config"
chmod 600 "$HOME/.kube/config"
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
echo "PASS: k3s $K3S_VERSION (§ 6 flags${extra[*]:+, ${extra[*]}}), kubectl $KUBECTL_VERSION, helm $HELM_VERSION; context ci"
