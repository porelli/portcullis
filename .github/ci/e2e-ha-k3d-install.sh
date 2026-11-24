#!/usr/bin/env bash
# e2e-ha-k3d "Install k3d" (ci.yml job e2e-ha-k3d; plan Task 33, spec
# §19.2): kubectl, helm and k3d at their pins (sha256-checked), the k3s node
# image by digest, and one k3d cluster:
#
#   e2e-ha-k3d-install.sh [main|sites]
#
#   main   pk-ha: 3 servers (embedded etcd, the HA etcd timing, every server
#          site main, class cloud, ingress) + 1 agent (class small, tainted
#          portcullis.io/small=true:NoSchedule, site main), context `ha`
#   sites  pk-sites (ruling P48): 5 servers — main ×2, edge ×2, tb ×1
#          (class small, tainted) — context `sites`; one cluster at a time,
#          so pk-ha is deleted first
#
# The k3s flags are init's (kube_k3s_server_flags) minus the mesh: the
# secrets encryption, no bundled Traefik, the kubelet's pod pids limit and
# sync-frequency=10s (D2: the published documents' p99 ~14 s), the etcd
# heartbeat / election timing. No Longhorn in k3d (it needs the host's
# iSCSI): the harness's portcullis-core-replicated StorageClass is the
# Portcullis local-path provisioner (portcullis.io/local-path, the same
# owner patterns as portcullis-core), so the HA chart's <name>-r volumes
# bind; replication itself is e2e-ha-vm's (part B).
#
# The k3d network is 10.215.0.0/24, the node mesh's fixed range (§20.11):
# each node's InternalIP is a mesh address there, as on a real cluster
# where k3s runs --node-ip on pcmesh (nodeadm reads the mesh address from
# the InternalIP inside it; the WireGuard tunnel itself isn't in k3d).
#
# Every node has a TEST-NET-3 "public" address (203.0.113.1x/32 on its
# eth0, a route to it on every other node and on the runner), written as
# the node's portcullis.io/addresses annotation (nodeadm's shape): the
# testprovider front door publishes documentation ranges only in that
# build, and the nodeagent probes reach Traefik's hostPort there.
#
# The CLI imports the K1 local images with `sudo k3s ctr -n k8s.io images
# import`: on a k3d runner /usr/local/bin/k3s is a CI-only shim (written
# here) that runs that ctr command in every node container (the image
# store of each node; never the product). A node container restarted by a
# chaos scenario keeps its store.
set -euo pipefail
cd "$(dirname "$0")/../.."
mode="${1:-main}"
case "$mode" in main|sites) ;; *) echo "usage: $0 [main|sites]" >&2; exit 2 ;; esac

K3D_VERSION=v5.9.0
KUBECTL_VERSION=v1.37.2
HELM_VERSION=v4.3.1
# k3s v1.37.2+k3s1, the version init pins (KUBE_K3S_VERSION).
K3S_IMAGE="docker.io/rancher/k3s:v1.37.2-k3s1@sha256:21ea6e0fac4e3930c2ce8aa40ddd41a8b18cb3e9a0222c030dc005e7e88c4332"
# k3d's helper (image import, host entries); no load balancer (--no-lb).
export K3D_IMAGE_TOOLS="ghcr.io/k3d-io/k3d-tools:5.9.0@sha256:c57abce697e66feeb826922718738fe186b47779312d49d4e51e6fb9b8a6f34d"
export K3D_IMAGE_LOADBALANCER="ghcr.io/k3d-io/k3d-proxy:5.9.0@sha256:7be40abfeb6ac9a81d0d4157a7cbf3aacc68a64a1780ca2efb160f1aea915177"
case "$(uname -m)" in
  x86_64)
    ARCH=amd64
    K3D_SHA256=06d8f25bc3a971c4eb29e0ff08429b180402db0f4dec838c9eac427e296800a0
    KUBECTL_SHA256=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4
    HELM_SHA256=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b ;;
  aarch64|arm64)
    ARCH=arm64
    K3D_SHA256=03cde5cf23e6e8e67de5a039ecf26e5b85aca82fba3e5d13dadf904cd218a250
    KUBECTL_SHA256=fcc16f63186659d9722014b7e02d5fdd2d4e669cb8c0ab66365d7d3b8ba03509
    HELM_SHA256=8cf8f66ecbc252ac8f7f06cca68aba88508ddfde3a6a34feb1678ad1694b4f88 ;;
  *) echo "FAIL: no pinned k3d / kubectl / helm for $(uname -m)"; exit 1 ;;
esac

fetch() { # fetch <url> <sha256> <out>
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet - || { echo "FAIL: $1 doesn't match its pinned sha256"; exit 1; }
}
have() { # have <bin> <version text> — already installed at that version
  command -v "$1" >/dev/null 2>&1 && "$1" version 2>/dev/null | grep -q -- "$2"
}
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if ! have kubectl "$KUBECTL_VERSION"; then
  fetch "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/$ARCH/kubectl" "$KUBECTL_SHA256" "$tmp/kubectl"
  sudo install -m 0755 "$tmp/kubectl" /usr/local/bin/kubectl
fi
if ! have helm "$HELM_VERSION"; then
  fetch "https://get.helm.sh/helm-$HELM_VERSION-linux-$ARCH.tar.gz" "$HELM_SHA256" "$tmp/helm.tgz"
  tar -xzf "$tmp/helm.tgz" -C "$tmp" --strip-components=1 "linux-$ARCH/helm"
  sudo install -m 0755 "$tmp/helm" /usr/local/bin/helm
fi
if ! have k3d "$K3D_VERSION"; then
  fetch "https://github.com/k3d-io/k3d/releases/download/$K3D_VERSION/k3d-linux-$ARCH" "$K3D_SHA256" "$tmp/k3d"
  sudo install -m 0755 "$tmp/k3d" /usr/local/bin/k3d
fi

# CI runner only (as e2e-k3s-install.sh): Ubuntu 26.04's AppArmor stacking
# denies signals in containers (containerd#14485); and five kubelets +
# containerds on one kernel exhaust the default 128 inotify instances
# (spike-components: "too many open files").
aa=/proc/sys/kernel/apparmor_restrict_unprivileged_unconfined
if [ -r "$aa" ] && [ "$(cat "$aa")" = 1 ]; then
  sudo sysctl -qw kernel.apparmor_restrict_unprivileged_unconfined=0
fi
[ "$(sysctl -n fs.inotify.max_user_instances)" -ge 1024 ] || sudo sysctl -qw fs.inotify.max_user_instances=1024
[ "$(sysctl -n fs.inotify.max_user_watches)" -ge 524288 ] || sudo sysctl -qw fs.inotify.max_user_watches=524288

# The CI-only ctr shim (see the header): `k3s ctr -n k8s.io images import -`
# reads the archive once and imports it on every node; any other ctr call
# (ls, tag) runs on every node, the first node's output printed.
sudo tee /usr/local/bin/k3s >/dev/null <<'SHIM'
#!/usr/bin/env bash
# CI-only (.github/ci/e2e-ha-k3d-install.sh): k3s ctr on every k3d node.
set -euo pipefail
[ "${1:-}" = ctr ] || { echo "k3s shim: only 'k3s ctr …' (k3d runner)" >&2; exit 2; }
shift
nodes="$(docker ps --filter label=app=k3d --filter label=k3d.role --format '{{.Names}}' | grep -E -- '-(server|agent)-[0-9]+$' | sort)"
[ -n "$nodes" ] || { echo "k3s shim: no running k3d node" >&2; exit 1; }
case " $* " in
  *" import "*)
    f="$(mktemp)"; trap 'rm -f "$f"' EXIT
    cat > "$f"
    for n in $nodes; do docker exec -i "$n" ctr "$@" < "$f" >/dev/null; done ;;
  *)
    first=1
    for n in $nodes; do
      if [ "$first" = 1 ]; then docker exec "$n" ctr "$@"; first=0; else docker exec "$n" ctr "$@" >/dev/null; fi
    done ;;
esac
SHIM
sudo chmod 0755 /usr/local/bin/k3s

# One cluster at a time.
for c in pk-ha pk-sites; do
  if k3d cluster list -o json 2>/dev/null | jq -e --arg c "$c" 'any(.[]; .name == $c)' >/dev/null; then
    k3d cluster delete "$c" >/dev/null
  fi
done

if [ "$mode" = main ]; then name=pk-ha ctx=ha servers=3 agents=1; else name=pk-sites ctx=sites servers=5 agents=0; fi
net="$name-mesh"
docker network rm "$net" >/dev/null 2>&1 || true
docker network create --subnet 10.215.0.0/24 --gateway 10.215.0.254 "$net" >/dev/null
cat > "$tmp/k3d.yaml" <<EOF
apiVersion: k3d.io/v1alpha5
kind: Simple
metadata:
  name: $name
network: $net
servers: $servers
agents: $agents
image: $K3S_IMAGE
options:
  k3d:
    wait: true
    timeout: 360s
    disableLoadbalancer: true
  kubeconfig:
    updateDefaultKubeconfig: false
    switchCurrentContext: false
  k3s:
    extraArgs:
      - {arg: --secrets-encryption, nodeFilters: [server:*]}
      - {arg: --disable=traefik, nodeFilters: [server:*]}
      - {arg: --etcd-arg=heartbeat-interval=200, nodeFilters: [server:*]}
      - {arg: --etcd-arg=election-timeout=2000, nodeFilters: [server:*]}
      - {arg: --kube-controller-manager-arg=disable-force-detach-on-timeout=true, nodeFilters: [server:*]}
      - {arg: --kubelet-arg=pod-max-pids=1024, nodeFilters: [all]}
      - {arg: --kubelet-arg=sync-frequency=10s, nodeFilters: [all]}
EOF
k3d cluster create --config "$tmp/k3d.yaml"
mkdir -p "$HOME/.kube"; touch "$HOME/.kube/config"; chmod 600 "$HOME/.kube/config"
k3d kubeconfig get "$name" > "$tmp/kc"
KUBECONFIG="$tmp/kc" kubectl config rename-context "k3d-$name" "$ctx" >/dev/null
KUBECONFIG="$HOME/.kube/config:$tmp/kc" kubectl config view --flatten > "$tmp/merged"
install -m 0600 "$tmp/merged" "$HOME/.kube/config"
K() { kubectl --context "$ctx" "$@"; }
K wait --for=condition=Ready node --all --timeout=300s >/dev/null

# Placement labels (as nodeadm sets them, §20.1), taints, public addresses.
node_c() { echo "$1"; }  # the k3d node name is its container's name
mapfile -t nodes < <(K get nodes -o json | jq -r '.items[].metadata.name' | sort)
i=0
declare -A pub=()
for n in "${nodes[@]}"; do
  i=$((i + 1))
  class=cloud site=main ingress=true storage=true
  if [ "$mode" = main ]; then
    case "$n" in *-agent-*) class=small ingress=false storage=false ;; esac
  else
    case "$i" in 1|2) site=main ;; 3|4) site=edge ;; 5) site=tb class=small ingress=false storage=false ;; esac
  fi
  labels=("portcullis.io/class=$class" "portcullis.io/site=$site" "topology.kubernetes.io/zone=$site")
  if [ "$ingress" = true ]; then labels+=("portcullis.io/ingress=true" "svccontroller.k3s.cattle.io/enablelb=true"); fi
  [ "$storage" = false ] || labels+=("portcullis.io/storage=true")
  K label node "$n" --overwrite "${labels[@]}" >/dev/null
  [ "$class" != small ] || K taint node "$n" --overwrite portcullis.io/small=true:NoSchedule >/dev/null
  pub[$n]="203.0.113.$((10 + i))"
done
# The addresses on the node containers and the routes to them (the k3d
# network's own addresses as next hops).
declare -A lan=()
for n in "${nodes[@]}"; do
  lan[$n]="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(node_c "$n")")"
done
for n in "${nodes[@]}"; do
  docker exec "$(node_c "$n")" ip addr add "${pub[$n]}/32" dev eth0 2>/dev/null || true
  for m in "${nodes[@]}"; do
    [ "$m" = "$n" ] || docker exec "$(node_c "$n")" ip route replace "${pub[$m]}/32" via "${lan[$m]}"
  done
  sudo ip route replace "${pub[$n]}/32" via "${lan[$n]}"
  # nodeadm's annotation (its LAN and public addresses; the mesh address is
  # the InternalIP).
  A="$(PUB="${pub[$n]}" jq -cn '{lan: [], public: [env.PUB]}')"
  K annotate node "$n" --overwrite "portcullis.io/addresses=$A" >/dev/null
done

# The replicated tier on k3d (see the header): applied as the CLI's
# objects are, by name; the provisioner itself comes with init.
K apply -f - >/dev/null <<'EOF'
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: portcullis-core-replicated
  labels:
    app.kubernetes.io/managed-by: portcullis
    portcullis.io/e2e: k3d-harness
provisioner: portcullis.io/local-path
reclaimPolicy: Retain
volumeBindingMode: WaitForFirstConsumer
parameters:
  userPattern: '{{ index .PVC.Annotations "portcullis.io/uid" }}'
  groupPattern: '{{ index .PVC.Annotations "portcullis.io/gid" }}'
  permPattern: '{{ index .PVC.Annotations "portcullis.io/mode" }}'
EOF

for i in $(seq 1 90); do
  K -n kube-system get deploy coredns >/dev/null 2>&1 && break
  [ "$i" -eq 90 ] && { echo "FAIL: no coredns Deployment"; exit 1; }
  sleep 2
done
K -n kube-system rollout status deploy/coredns --timeout=300s >/dev/null
K get nodes -L portcullis.io/site,portcullis.io/class,portcullis.io/ingress
echo "PASS: k3d $K3D_VERSION cluster $name ($servers servers, $agents agent), k3s $(K version -o json | jq -r .serverVersion.gitVersion); context $ctx"
