# shellcheck shell=bash
#
# `init --runtime kubernetes` without --kube-context: this host becomes the
# cluster's first node (contract §20.11, plan R3). First the node mesh
# pcmesh (kernel WireGuard, 10.215.0.1/24, UDP 51830), then k3s at the
# pinned version with embedded etcd (--cluster-init) on it: etcd, the
# kubelet and the API server listen only on the mesh address (and etcd on
# loopback for its local clients), flannel wireguard-native runs inside
# pcmesh on UDP 51840 (never the people VPN's 51820). The kubeconfig goes to
# secrets/kube/kubeconfig, context `portcullis`. Sourced by runtime.sh after
# kube.sh (plan R8: the new kube CLI code lives here; kube.sh doesn't grow).
# Bash 3.2 compatible.
#
# Secrets: the k3s token is generated into a 0600 file and reaches k3s as
# --token-file; the mesh private key is generated on this host into a 0600
# file that wg-quick's PostUp loads. Neither is ever on argv, printed or
# logged.
#
# Overridable for tests: KUBE_INSTALL_PREFIX (a root for every host path;
# set = no sudo), KUBE_INSTALL_OS, KUBE_INSTALL_ARCH; CI's K3S_LINE sets
# the KUBE_K3S_* pins after sourcing (.github/ci/e2e-k3s-install.sh).

# The pins (plan Amendment 1). get.k3s.io is unversioned: the script is
# taken from the release tag, and the binary is checked on its own. The
# script stays at this tag when CI's K3S_LINE swaps the binary: with
# INSTALL_K3S_SKIP_DOWNLOAD it only writes the unit and the helper scripts.
KUBE_K3S_VERSION="v1.37.2+k3s1"
KUBE_K3S_SHA256_AMD64=265b3ee6a3198ef14033c63ef46cbb32370d83795199fb6d1b01f21575eddbda
KUBE_K3S_SHA256_ARM64=a779ccf1e5e2e33a62f5a29c2f1c0bbf99431e100579d4c10f0aa0742a6aa84b
KUBE_K3S_SCRIPT_URL="https://raw.githubusercontent.com/k3s-io/k3s/v1.37.2%2Bk3s1/install.sh"
KUBE_K3S_SCRIPT_SHA256=ed01f89fd977bf20ac1516bbebf8370bf3ddbaa55dac8aba610956a4c78cc00b
# The mesh and the cluster network (contract §20.9, §20.11).
KUBE_MESH_IF=pcmesh
KUBE_MESH_CIDR=10.215.0.0/24
KUBE_MESH_IP=10.215.0.1
KUBE_MESH_PORT=51830
KUBE_MESH_MTU=1420
KUBE_FLANNEL_PORT=51840
KUBE_CLUSTER_CIDR=10.42.0.0/16
# Host paths (KUBE_INSTALL_PREFIX in front when written; the flags name them bare).
KUBE_K3S_TOKEN_FILE=/etc/rancher/k3s/token
# The agents' own token (--agent-token-file): agents never hold the server
# token (nodeadm gives a joining agent a bootstrap token, a rotation gives
# agents this one).
KUBE_K3S_AGENT_TOKEN_FILE=/etc/rancher/k3s/agent-token
KUBE_FLANNEL_CONF=/etc/rancher/k3s/flannel-net-conf.json
KUBE_K3S_YAML=/etc/rancher/k3s/k3s.yaml
# The key lives under /etc/wireguard: Ubuntu's AppArmor profile for wg
# (26.04) lets it read nothing else, so a PostUp `wg set … private-key`
# from another directory fails.
KUBE_MESH_KEY=/etc/wireguard/pcmesh.key
KUBE_MESH_CONF=/etc/wireguard/pcmesh.conf
# The packages a node needs (wireguard-tools for wg-quick; Longhorn's
# open-iscsi and nfs-common, spike S2).
KUBE_NODE_PACKAGES="wireguard-tools open-iscsi nfs-common"

_ki_p() { printf '%s%s\n' "${KUBE_INSTALL_PREFIX:-}" "$1"; }
_ki_os() { echo "${KUBE_INSTALL_OS:-$(uname -s)}"; }

# _ki_sudo <cmd…> — as root (sudo unless already root, or a test prefix).
_ki_sudo() {
  if [ -n "${KUBE_INSTALL_PREFIX:-}" ] || [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi
}

# _ki_write <path> <mode> — stdin into a root-owned file (umask 077, then
# the mode), replaced atomically. Missing directories get the default 0755
# (k3s's kubectl symlink reads /etc/rancher/k3s as the operator).
_ki_write() {
  _ki_sudo sh -c 'mkdir -p "$(dirname "$1")" && umask 077 && cat > "$1.tmp" && chmod "$2" "$1.tmp" && mv -f "$1.tmp" "$1"' _ "$1" "$2"
}

# kube_install_kubeconfig / kube_install_context — where init's cluster is
# reached (contract §20.11: secrets/kube/kubeconfig, context portcullis).
kube_install_kubeconfig() { echo "${KUBE_INSTALL_KUBECONFIG:-$PORTCULLIS_ROOT/secrets/kube/kubeconfig}"; }
kube_install_context() { echo "${KUBE_INSTALL_CONTEXT:-portcullis}"; }

# _ki_kubeconfig_env — init's kubeconfig first in KUBECONFIG (the operator's
# own after it), so kube_ctl / kube_helm find the context.
_ki_kubeconfig_env() {
  local f
  f="$(kube_install_kubeconfig)"
  [ -s "$f" ] || return 0
  case ":${KUBECONFIG:-}:" in *":$f:"*) return 0 ;; esac
  export KUBECONFIG="$f:${KUBECONFIG:-$HOME/.kube/config}"
}
_ki_kubeconfig_env

# _ki_cluster_answers — init's context has a cluster that answers.
_ki_cluster_answers() {
  [ -s "$(kube_install_kubeconfig)" ] || return 1
  KUBECONFIG="$(kube_install_kubeconfig)" kubectl --context "$(kube_install_context)" --request-timeout=5s version -o json >/dev/null 2>&1
}

_ki_arch() {
  case "${KUBE_INSTALL_ARCH:-$(uname -m)}" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo "${KUBE_INSTALL_ARCH:-$(uname -m)}" ;;
  esac
}

# _ki_node_class — the class suggestion (contract §20.1): small below
# 3.5 GiB of RAM or on a Raspberry Pi, cloud when the public address is on this host, else
# home. PORTCULLIS_NODE_CLASS overrides it.
_ki_node_class() {
  local kb model pub
  if [ -n "${PORTCULLIS_NODE_CLASS:-}" ]; then
    case "$PORTCULLIS_NODE_CLASS" in small|home|cloud) echo "$PORTCULLIS_NODE_CLASS"; return 0 ;; esac
    fail "PORTCULLIS_NODE_CLASS must be small, home or cloud"
  fi
  kb="$(awk '/^MemTotal:/ { print $2 }' "$(_ki_p /proc/meminfo)" 2>/dev/null || true)"
  model="$(tr -d '\0' 2>/dev/null < "$(_ki_p /proc/device-tree/model)" || true)"
  # Below 3.5 GiB = 3 670 016 KiB (contract §20.1, nodeagent's class.Suggest).
  if { [ -n "$kb" ] && [ "$kb" -lt 3670016 ]; } || case "$model" in *"Raspberry Pi"*) true ;; *) false ;; esac; then
    echo small; return 0
  fi
  pub="$(_kube_public_ipv4)"
  if [ -n "$pub" ]; then
    case " $(_kube_local_addrs) " in *" $pub "*) echo cloud; return 0 ;; esac
  fi
  echo home
}

# The first node's Kubernetes name: its server id (contract §20.1, §17.3;
# Task 17 ruling: default node-1, later nodes get theirs from the join code).
KUBE_FIRST_NODE_NAME="${PORTCULLIS_NODE_NAME:-node-1}"
# The registration taint of every node (ruling R-NODELABELS; nodeadm's
# unlabelledTaint): off once the node is labelled.
KUBE_UNLABELLED_TAINT="nodeadm.portcullis/unlabelled=true:NoSchedule"

# kube_k3s_server_flags — the first server's flags, one per line (the
# kube-controller-manager never force-detaches a volume from an unready
# node by timeout, plan Task 24: fencing unconfirmed → no stateful
# failover; only SNR's out-of-service taint moves it;
# shared fixture tests/fixtures/k3s-server-flags.txt; nodeadm's join
# answer follows it, contract §20.2 / §20.11). No placement label: the
# kubelet may not set portcullis.io/, topology.kubernetes.io/,
# node.longhorn.io/ or svccontroller.k3s.cattle.io/ labels on its own Node
# (ruling R-NODELABELS); it registers with the unlabelled taint (the only
# registration portcullis-node-labels admits, as a joining node's) and the
# CLI labels it and removes the taint once it registers (_ki_label_node,
# kube_k3s_node_labels).
kube_k3s_server_flags() {
  local ip="$KUBE_MESH_IP"
  [[ "$KUBE_FIRST_NODE_NAME" =~ ^[a-z][a-z0-9-]{0,30}$ ]] || fail "PORTCULLIS_NODE_NAME must match ^[a-z][a-z0-9-]{0,30}$ (a server id)"
  cat <<EOF
--cluster-init
--node-name=$KUBE_FIRST_NODE_NAME
--secrets-encryption
--disable=traefik
--write-kubeconfig-mode=0600
--token-file=$KUBE_K3S_TOKEN_FILE
--agent-token-file=$KUBE_K3S_AGENT_TOKEN_FILE
--kubelet-arg=pod-max-pids=1024
--kubelet-arg=sync-frequency=10s
--kubelet-arg=address=$ip
--flannel-backend=wireguard-native
--flannel-conf=$KUBE_FLANNEL_CONF
--flannel-iface=$KUBE_MESH_IF
--node-ip=$ip
--advertise-address=$ip
--bind-address=$ip
--cluster-cidr=$KUBE_CLUSTER_CIDR
--etcd-arg=listen-client-urls=https://$ip:2379,https://127.0.0.1:2379
--etcd-arg=heartbeat-interval=200
--etcd-arg=election-timeout=2000
--kube-controller-manager-arg=disable-force-detach-on-timeout=true
--node-taint=$KUBE_UNLABELLED_TAINT
EOF
}

# kube_k3s_node_labels — the first node's placement labels (key=value, one
# per line; contract §20.1), set by the CLI's identity after it registers.
kube_k3s_node_labels() {
  local class
  class="$(_ki_node_class)" || return 1
  cat <<EOF
portcullis.io/class=$class
portcullis.io/site=main
topology.kubernetes.io/zone=main
portcullis.io/ingress=true
svccontroller.k3s.cattle.io/enablelb=true
EOF
  # Storage is off by default on small nodes. The first node is at the
  # primary site, so a storage node gets Longhorn's default-disk label too
  # (contract §20.11: only storage nodes at main; nodeadm labels later nodes
  # the same way).
  [ "$class" = small ] || printf '%s\n' "portcullis.io/storage=true" "node.longhorn.io/create-default-disk=true"
}

# _ki_label_node — the labels on the registered first node, then its
# unlabelled taint removed, as the CLI (k3s's admin kubeconfig, never the
# kubelet's identity); before anything is scheduled on it (until then only
# what tolerates the taint runs there). The taint already gone is fine.
_ki_label_node() {
  local labels=() l n="$KUBE_FIRST_NODE_NAME" out
  while IFS= read -r l; do labels+=("$l"); done < <(kube_k3s_node_labels)
  [ "${#labels[@]}" -gt 0 ] || fail "could not compute the first node's labels"
  _ki_sudo k3s kubectl label node "$n" --overwrite "${labels[@]}" >/dev/null \
    || fail "could not label the node $n (re-run ./portcullis init)"
  if ! out="$(_ki_sudo k3s kubectl taint node "$n" "${KUBE_UNLABELLED_TAINT%%=*}:NoSchedule-" 2>&1)"; then
    case "$out" in *"not found"*) ;; *) fail "could not remove the taint ${KUBE_UNLABELLED_TAINT%%=*} from the node $n (re-run ./portcullis init)" ;; esac
  fi
}

# kube_flannel_conf — flannel's net-conf, used verbatim by k3s (so it
# carries the cluster network too); the backend keys as the spike pinned
# them (fixture tests/fixtures/k3s-flannel-net-conf.json).
kube_flannel_conf() {
  printf '{"Network":"%s","EnableIPv4":true,"EnableIPv6":false,"Backend":{"Type":"wireguard","ListenPort":%s,"PersistentKeepaliveInterval":25,"Mode":"separate"}}\n' \
    "$KUBE_CLUSTER_CIDR" "$KUBE_FLANNEL_PORT"
}

# ── host checks before the install ──

# _ki_pkg_installed <package> — dpkg says installed, else its command is there.
_ki_pkg_installed() {
  if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; return
  fi
  case "$1" in
    wireguard-tools) command -v wg-quick >/dev/null 2>&1 ;;
    open-iscsi) command -v iscsiadm >/dev/null 2>&1 ;;
    nfs-common) command -v mount.nfs >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

# _ki_missing_packages — the node packages not installed yet.
_ki_missing_packages() {
  local p out=""
  for p in $KUBE_NODE_PACKAGES; do _ki_pkg_installed "$p" || out="$out $p"; done
  echo "${out# }"
}

# _ki_fs_type <dir> — the filesystem holding the directory.
_ki_fs_type() {
  findmnt -no FSTYPE -T "$1" 2>/dev/null || stat -f -c %T "$1" 2>/dev/null || echo unknown
}

# _ki_node_checks — the node's Longhorn and fencing prerequisites, reported
# only (ok|warn lines): open-iscsi, nfs-common, the watchdog device, ZFS /
# btrfs under /var/lib. Also in kube_host_checks on an init-installed node.
_ki_node_checks() {
  local p fs
  for p in open-iscsi nfs-common; do
    if _ki_pkg_installed "$p"; then _rt_chk ok "$p installed"; else _rt_chk warn "$p is not installed (storage replicas need it; init installs it)"; fi
  done
  if [ -e "$(_ki_p /dev/watchdog)" ]; then
    _rt_chk ok "watchdog device /dev/watchdog"
  else
    _rt_chk warn "no watchdog device (/dev/watchdog): high availability's fencing needs one (modprobe softdog provides it)"
  fi
  fs="$(_ki_fs_type "$(_ki_p /var/lib)")"
  case "$fs" in
    zfs) _rt_chk warn "/var/lib is on ZFS: storage replicas can't use a ZFS dataset (use a zvol or a separate disk)" ;;
    btrfs) _rt_chk ok "/var/lib is on btrfs (snapshots available)" ;;
    *) _rt_chk ok "/var/lib is on $fs" ;;
  esac
}

# _ki_port_busy <port> <tcp|udp> — something listens there (ss checked
# present by kube_install_host_checks: without it nothing would look busy).
_ki_port_busy() {
  local f=-Hlnt
  [ "$2" = tcp ] || f=-Hlnu
  [ -n "$(ss "$f" "sport = :$1" 2>/dev/null)" ]
}

# _ki_mesh_taken — an address or route of 10.215.0.0/24 that isn't pcmesh's.
_ki_mesh_taken() {
  { ip -4 -o addr show 2>/dev/null | awk -v m="$KUBE_MESH_IF" '$2 != m { sub("/.*", "", $4); print $4 }' \
      | while read -r a; do cidr_contains "$KUBE_MESH_CIDR" "$a" && echo "$a"; done
    ip -4 route show "$KUBE_MESH_CIDR" 2>/dev/null | grep -v "dev $KUBE_MESH_IF" | awk '{ print $1 }'
  } | head -n1
}

_ki_have() { command -v "$1" >/dev/null 2>&1; }

# _ki_link_up — the pcmesh interface exists and is up (wg-quick sets it up;
# Task 17 re-review N2).
_ki_link_up() { ip link show "$KUBE_MESH_IF" 2>/dev/null | grep -q ',UP'; }

# _ki_mesh_ours — pcmesh is a half-finished init's: the interface is up
# with our config (its header) and our key.
_ki_mesh_ours() {
  _ki_link_up && _ki_sudo test -s "$(_ki_p "$KUBE_MESH_KEY")" \
    && _ki_sudo grep -q '^# pcmesh: the Portcullis node mesh' "$(_ki_p "$KUBE_MESH_CONF")" 2>/dev/null
}

# _ki_k3s_ours — k3s is a half-finished init's: our token file, our
# flannel net-conf (exactly kube_flannel_conf) and the k3s unit.
_ki_k3s_ours() {
  _ki_sudo test -s "$(_ki_p "$KUBE_K3S_TOKEN_FILE")" && _ki_sudo test -f "$(_ki_p /etc/systemd/system/k3s.service)" \
    && [ "$(_ki_sudo cat "$(_ki_p "$KUBE_FLANNEL_CONF")" 2>/dev/null)" = "$(kube_flannel_conf)" ]
}

# The teardown of a half-finished install that isn't recognised as ours.
KUBE_INSTALL_TEARDOWN="if it is a half-finished Portcullis install, remove it first: sudo /usr/local/bin/k3s-uninstall.sh; sudo systemctl disable --now wg-quick@pcmesh; sudo rm -f /etc/wireguard/pcmesh.conf /etc/wireguard/pcmesh.key /etc/systemd/system/k3s.service.d/10-pcmesh.conf; sudo systemctl daemon-reload — otherwise name the existing cluster with --kube-context"

# kube_install_host_checks — "ok|warn|fail<TAB>text" lines before anything
# is installed (fail = refuse). A half-finished init of our own (pcmesh up
# with our config and key; k3s with our token, net-conf and unit) holds its
# own ports: the run resumes (_KI_RESUME names what).
kube_install_host_checks() {
  local p taken mine=" " k3sports="6443/tcp 2379/tcp 2380/tcp 10250/tcp $KUBE_FLANNEL_PORT/udp"
  if [ "$(_ki_os)" != Linux ]; then
    _rt_chk fail "init installs k3s on Linux only: on this host, name an existing cluster with --kube-context"; return 0
  fi
  if command -v systemctl >/dev/null 2>&1; then _rt_chk ok "systemd"; else _rt_chk fail "no systemd (systemctl): k3s and the mesh run as systemd services"; fi
  if [ "$(id -u)" = 0 ] || [ -n "${KUBE_INSTALL_PREFIX:-}" ] || command -v sudo >/dev/null 2>&1; then _rt_chk ok "root through sudo"; else _rt_chk fail "neither root nor sudo: installing k3s needs root"; fi
  case "$(_ki_arch)" in amd64|arm64) _rt_chk ok "architecture $(_ki_arch)" ;; *) _rt_chk fail "no pinned k3s for $(_ki_arch) (amd64 and arm64 only)" ;; esac
  if [ -d "$(_ki_p /sys/module/wireguard)" ] || modprobe -n wireguard >/dev/null 2>&1; then
    _rt_chk ok "kernel WireGuard"
  else
    _rt_chk fail "the kernel has no WireGuard module: the node mesh pcmesh needs it"
  fi
  if command -v helm >/dev/null 2>&1; then _rt_chk ok "helm present"; else _rt_chk fail "helm is missing (init deploys core with it): install helm first"; fi
  if ! _ki_have ss; then
    _rt_chk fail "ss (iproute2) is missing: the ports can't be checked free"
  else
    if _ki_mesh_ours; then mine="$mine$KUBE_MESH_PORT/udp "; _rt_chk ok "$KUBE_MESH_IF is a half-finished init's: resuming"; fi
    if _ki_k3s_ours; then mine="$mine$k3sports "; _rt_chk ok "k3s is a half-finished init's: resuming"; fi
    for p in $k3sports $KUBE_MESH_PORT/udp; do
      case "$mine" in *" $p "*) continue ;; esac
      if _ki_port_busy "${p%/*}" "${p#*/}"; then
        _rt_chk fail "port $p is in use: another Kubernetes or WireGuard runs here ($KUBE_INSTALL_TEARDOWN)"
      fi
    done
  fi
  # cidr_contains is network.sh's: without it nothing would look taken.
  if ! declare -F cidr_contains >/dev/null; then
    _rt_chk fail "the mesh subnet $KUBE_MESH_CIDR can't be checked free (network.sh isn't loaded)"
  elif taken="$(_ki_mesh_taken)" && [ -n "$taken" ]; then
    _rt_chk fail "the mesh subnet $KUBE_MESH_CIDR is already in use on this host ($taken)"
  else
    _rt_chk ok "the mesh subnet $KUBE_MESH_CIDR is free"
  fi
  for p in $KUBE_NODE_PACKAGES; do
    _ki_pkg_installed "$p" || command -v apt-get >/dev/null 2>&1 || _rt_chk fail "$p is missing and there is no apt-get: install it first"
  done
  _ki_node_checks
}

# _ki_confirm <text> — the one confirmation; --non-interactive goes ahead.
_ki_confirm() {
  if [ "${INIT_INTERACTIVE:-true}" = false ]; then info "$1 (--non-interactive: going ahead)"; return 0; fi
  confirm "$1 Continue?"
}

# kube_install_preflight — the host checks (refused while one fails), then
# one confirmation naming everything to install, then the packages.
kube_install_preflight() {
  local lines fails pkgs what
  lines="$(kube_install_host_checks)"
  printf '%s\n' "$lines" | awk -F'\t' '$1 == "warn" { print "  ! " $2 } $1 == "ok" && $2 ~ /resuming$/ { print "  > " $2 }' >&2
  fails="$(printf '%s\n' "$lines" | awk -F'\t' '$1 == "fail" { print "  - " $2 }')"
  [ -z "$fails" ] || fail "this host can't become the cluster's first node yet:"$'\n'"$fails"
  pkgs="$(_ki_missing_packages)"
  what="init installs on this host: k3s $KUBE_K3S_VERSION (systemd service k3s, embedded etcd) and the node mesh $KUBE_MESH_IF ($KUBE_MESH_IP, UDP $KUBE_MESH_PORT)"
  [ -z "$pkgs" ] || what="$what, and the packages: $pkgs"
  _ki_confirm "$what." || fail "nothing was installed"
  [ -n "$pkgs" ] || return 0
  # shellcheck disable=SC2086  # one word per package
  { _ki_sudo env DEBIAN_FRONTEND=noninteractive apt-get update -q && _ki_sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $pkgs; } >&2 \
    || fail "apt-get could not install $pkgs"
  case " $pkgs " in *" open-iscsi "*) _ki_sudo systemctl enable --now iscsid >/dev/null 2>&1 || warn "iscsid didn't start (storage replicas need it)" ;; esac
}

# ── the mesh ──

# kube_install_mesh — /etc/wireguard/pcmesh.conf (0600) for the first node,
# its private key generated here into /etc/wireguard/pcmesh.key (0600; never
# printed, never in the config: PostUp loads it), wg-quick@pcmesh enabled.
# An existing config is kept (nodeagent manages the peers).
kube_install_mesh() {
  local conf key
  conf="$(_ki_p "$KUBE_MESH_CONF")" key="$(_ki_p "$KUBE_MESH_KEY")"
  _ki_sudo sh -c 'umask 077; mkdir -p "$(dirname "$1")" && chmod 700 "$(dirname "$1")" && { [ -s "$1" ] || { wg genkey > "$1.tmp" && mv -f "$1.tmp" "$1"; }; } && chmod 600 "$1"' _ "$key" \
    || fail "could not generate the mesh key"
  if ! _ki_sudo test -s "$conf"; then
    _ki_write "$conf" 600 <<EOF || fail "could not write $KUBE_MESH_CONF"
# pcmesh: the Portcullis node mesh (written by ./portcullis init; the
# nodeagent manages the peers). The private key stays in $KUBE_MESH_KEY.
[Interface]
Address = $KUBE_MESH_IP/24
ListenPort = $KUBE_MESH_PORT
MTU = $KUBE_MESH_MTU
PostUp = wg set %i private-key $KUBE_MESH_KEY
EOF
  fi
  # `enable --now` can answer 0 although the start failed (systemd 255):
  # is-active decides.
  _ki_sudo systemctl enable --now "wg-quick@$KUBE_MESH_IF" >/dev/null 2>&1 || true
  if ! _ki_sudo systemctl is-active --quiet "wg-quick@$KUBE_MESH_IF"; then
    _ki_journal_tail "wg-quick@$KUBE_MESH_IF" 20
    fail "wg-quick@$KUBE_MESH_IF didn't start (its last journal lines are above)"
  fi
  info "Node mesh $KUBE_MESH_IF up: $KUBE_MESH_IP/24, UDP $KUBE_MESH_PORT."
}

# _ki_journal_tail <unit> <lines> — the unit's last journal lines on stderr
# (bounded: lines × 300 characters), any line holding the k3s token or the
# mesh key dropped (neither is logged by wg-quick or k3s; belt and braces).
_ki_journal_tail() {
  echo "    last $2 journal lines of $1:" >&2
  _ki_sudo sh -c 'p=""; for f in "$3" "$4"; do [ -s "$f" ] && p="$p -f $f"; done
    journalctl -u "$1" -n "$2" --no-pager -o cat 2>&1 | if [ -n "$p" ]; then grep -vF $p; else cat; fi' \
    _ "$1" "$2" "$(_ki_p "$KUBE_K3S_TOKEN_FILE")" "$(_ki_p "$KUBE_MESH_KEY")" | cut -c1-300 | sed 's/^/    | /' >&2 || true
}

# ── k3s ──

# _ki_fetch <url> <sha256> <tmpdir/out> — download, refused unless the
# sha256 matches (a refusal removes the whole download directory).
_ki_fetch() {
  local got
  curl -fsSL --retry 3 -o "$3" "$1" || { rm -rf "$(dirname "$3")"; fail "could not download $1"; }
  got="$(_kube_sha "$3")"
  [ "$got" = "$2" ] || { rm -rf "$(dirname "$3")"; fail "$1 doesn't match its pinned sha256 (want $2, got $got): nothing was installed"; }
}

# _ki_token_file [path] — a k3s token (the server's, else the agents'
# --agent-token-file): 32 random bytes as hex, generated once into a 0600
# file (k3s reads it through the file; it never reaches argv).
_ki_token_file() {
  local f="${1:-$KUBE_K3S_TOKEN_FILE}"
  _ki_sudo sh -c 'mkdir -p "$(dirname "$1")" && umask 077 && { [ -s "$1" ] || { head -c 32 /dev/urandom | od -An -tx1 | tr -d " \n" > "$1.tmp" && mv -f "$1.tmp" "$1"; }; } && chmod 600 "$1"' _ "$(_ki_p "$f")" \
    || fail "could not write the k3s token file $f"
}

# _ki_wait_ready — k3s wrote its kubeconfig and the node is Ready (5 min).
_ki_wait_ready() {
  for _ in $(seq 1 150); do
    _ki_sudo k3s kubectl get nodes --no-headers 2>/dev/null | awk '$2 == "Ready" { f = 1 } END { exit !f }' && return 0
    sleep 2
  done
  _ki_journal_tail k3s 30
  fail "k3s didn't become Ready within 5 minutes (its last journal lines are above)"
}

# _ki_write_kubeconfig — k3s.yaml as $(kube_install_kubeconfig) (0600, the
# operator's): the context, cluster and user named $(kube_install_context),
# the server the mesh address.
_ki_write_kubeconfig() {
  local f ctx
  f="$(kube_install_kubeconfig)" ctx="$(kube_install_context)"
  mkdir -p "$(dirname "$f")" && chmod 700 "$(dirname "$f")"
  (umask 077 && _ki_sudo cat "$(_ki_p "$KUBE_K3S_YAML")" \
    | sed -e "s/: default\$/: $ctx/" -e "s#server: https://.*#server: https://$KUBE_MESH_IP:6443#" > "$f.tmp") \
    || { rm -f "$f.tmp"; fail "could not read k3s's kubeconfig ($KUBE_K3S_YAML)"; }
  chmod 600 "$f.tmp" && mv -f "$f.tmp" "$f"
}

# kube_install_k3s [extra server flags…] — the pinned script and binary
# (both sha256-checked before anything runs), the token file, flannel's
# net-conf, then the k3s server with kube_k3s_server_flags (CI adds its
# --node-external-ip). Only when init's context has no cluster answering.
# shellcheck disable=SC2120  # CI passes extra flags
kube_install_k3s() {
  local tmp asset sha flags=() f
  if _ki_cluster_answers; then
    info "k3s already answers on the context $(kube_install_context): not installed again."
    return 0
  fi
  case "$(_ki_arch)" in
    amd64) asset=k3s sha="$KUBE_K3S_SHA256_AMD64" ;;
    arm64) asset=k3s-arm64 sha="$KUBE_K3S_SHA256_ARM64" ;;
    *) fail "no pinned k3s for $(_ki_arch)" ;;
  esac
  while IFS= read -r f; do flags+=("$f"); done < <(kube_k3s_server_flags)
  [ "${#flags[@]}" -gt 0 ] || fail "could not compute the k3s flags"
  tmp="$(mktemp -d)"
  info "Downloading k3s $KUBE_K3S_VERSION..."
  _ki_fetch "$KUBE_K3S_SCRIPT_URL" "$KUBE_K3S_SCRIPT_SHA256" "$tmp/install.sh"
  _ki_fetch "https://github.com/k3s-io/k3s/releases/download/$(printf '%s' "$KUBE_K3S_VERSION" | sed 's/+/%2B/')/$asset" "$sha" "$tmp/k3s"
  _ki_token_file
  _ki_token_file "$KUBE_K3S_AGENT_TOKEN_FILE"
  kube_flannel_conf | _ki_write "$(_ki_p "$KUBE_FLANNEL_CONF")" 644 || fail "could not write $KUBE_FLANNEL_CONF"
  _ki_sudo mkdir -p "$(_ki_p /usr/local/bin)"
  _ki_sudo install -m 0755 "$tmp/k3s" "$(_ki_p /usr/local/bin/k3s)" || { rm -rf "$tmp"; fail "could not install the k3s binary"; }
  # k3s binds the mesh address: start it after pcmesh (install.sh reloads systemd).
  printf '[Unit]\nAfter=wg-quick@%s.service\nRequires=wg-quick@%s.service\n' "$KUBE_MESH_IF" "$KUBE_MESH_IF" \
    | _ki_write "$(_ki_p /etc/systemd/system/k3s.service.d/10-pcmesh.conf)" 644 || { rm -rf "$tmp"; fail "could not write k3s's pcmesh ordering"; }
  info "Installing k3s $KUBE_K3S_VERSION (embedded etcd on $KUBE_MESH_IF $KUBE_MESH_IP)..."
  _ki_sudo env INSTALL_K3S_SKIP_DOWNLOAD=true INSTALL_K3S_VERSION="$KUBE_K3S_VERSION" \
    sh "$tmp/install.sh" server "${flags[@]}" ${1+"$@"} >&2 || { rm -rf "$tmp"; _ki_journal_tail k3s 30; fail "the k3s install script failed (k3s's last journal lines are above)"; }
  rm -rf "$tmp"
  _ki_wait_ready
  _ki_label_node
  _ki_write_kubeconfig
  _ki_kubeconfig_env
  ok "k3s $KUBE_K3S_VERSION runs: context $(kube_install_context) in $(kube_install_kubeconfig)."
}

# kube_install_run — init_run without --kube-context: unless init's context
# already answers (a re-run), the host checks and the one confirmation,
# the mesh, then k3s. Sets PORTCULLIS_KUBE_CONTEXT and _KI_INSTALLED.
kube_install_run() {
  if ! _ki_cluster_answers; then
    kube_install_preflight
    kube_install_mesh
    kube_install_k3s
  fi
  _ki_kubeconfig_env
  export PORTCULLIS_KUBE_CONTEXT
  PORTCULLIS_KUBE_CONTEXT="$(kube_install_context)"
  _KI_INSTALLED=1
}

# kube_env_keys <ctx> — the .env lines of a new kubernetes install (after
# kube_detect_cidrs): context, namespaces, networks, install id, images,
# the three fixed ClusterIPs; PORTCULLIS_K3S_VERSION when init installed k3s.
kube_env_keys() {
  local ctx="$1" id
  id="$(uuidgen 2>/dev/null | tr 'A-Z' 'a-z')" || true
  [ -n "$id" ] || id="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
  [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || fail "could not generate PORTCULLIS_KUBE_INSTALL_ID (uuidgen)"
  cat <<EOF
PORTCULLIS_KUBE_CONTEXT=$ctx
PORTCULLIS_NAMESPACE=portcullis
PORTCULLIS_APPS_NAMESPACE=portcullis-apps
PORTCULLIS_POD_CIDR=$_K_POD_CIDR
PORTCULLIS_SERVICE_CIDR=$_K_SVC_CIDR
PORTCULLIS_KUBE_API_ENDPOINTS=$_K_API_EP
PORTCULLIS_KUBE_INSTALL_ID=$id
PORTCULLIS_KUBE_IMAGES=registry
PORTCULLIS_TRAEFIK_SERVICE_IP=$(kube_svc_ip "$KUBE_TRAEFIK_SVC_OFFSET" "$_K_SVC_CIDR")
PORTCULLIS_TRAEFIK_VPN_SERVICE_IP=$(kube_svc_ip "$KUBE_TRAEFIK_VPN_SVC_OFFSET" "$_K_SVC_CIDR")
PORTCULLIS_WG_EDGE_SERVICE_IP=$(kube_svc_ip "$KUBE_WG_EDGE_SVC_OFFSET" "$_K_SVC_CIDR")
EOF
  [ "${_KI_INSTALLED:-}" != 1 ] || echo "PORTCULLIS_K3S_VERSION=$KUBE_K3S_VERSION"
}

# ── the cluster addresses document (contract §20.9) ──

# kube_cluster_addresses — after kube_detect_cidrs: once nodeadm has written
# the ConfigMap portcullis-cluster-addresses, it must agree with the fixed
# mesh and with the cluster itself, before anything else reads it:
# mesh_cidr = 10.215.0.0/24, every api / nodes[].mesh entry an IPv4 address
# in it, api (as ip:6443) = the default/kubernetes EndpointSlice, and
# cluster_cidr / service_cidr = the detected networks. Absent: return 0.
# Anything else: return 1, _K_ERR says why (fail closed: no params rewrite).
# It overrides nothing (.env is compared with the cluster as before).
kube_cluster_addresses() {
  local out doc vals pod svc mesh api nodes a ep
  if ! out="$(kube_ctl -n "$(kube_ns)" get configmap portcullis-cluster-addresses -o json 2>&1)"; then
    case "$out" in *NotFound*) return 0 ;; esac
    _K_ERR="the cluster addresses (ConfigMap portcullis-cluster-addresses) can't be read"; return 1
  fi
  doc="$(printf '%s' "$out" | jq -r '.data["addresses.json"] // empty' 2>/dev/null)"
  vals="$(printf '%s' "$doc" | jq -r 'def ip4: type == "string" and test("^[0-9]{1,3}([.][0-9]{1,3}){3}$");
    select(.v == 1 and (.mesh_cidr | type == "string") and (.cluster_cidr | type == "string") and (.service_cidr | type == "string")
      and (.api | type == "array" and length > 0 and all(ip4)) and (.nodes | type == "object" and length > 0)
      and ([.nodes[] | .mesh | ip4] | all))
    | [.cluster_cidr, .service_cidr, .mesh_cidr, (.api | join(" ")), ([.nodes[].mesh] | join(" "))] | @tsv' 2>/dev/null)"
  _K_ERR="the cluster addresses (ConfigMap portcullis-cluster-addresses) don't parse: nothing is changed"
  [ -n "$vals" ] || return 1
  IFS=$'\t' read -r pod svc mesh api nodes <<< "$vals"
  if [ "$mesh" != "$KUBE_MESH_CIDR" ]; then
    _K_ERR="the cluster addresses give the mesh as $mesh, not $KUBE_MESH_CIDR: nothing is changed"; return 1
  fi
  for a in $api $nodes; do
    cidr_contains "$KUBE_MESH_CIDR" "$a" || { _K_ERR="the cluster addresses list $a, which isn't an address in $KUBE_MESH_CIDR: nothing is changed"; return 1; }
  done
  ep="$(for a in $api; do echo "$a:6443"; done | LC_ALL=C sort | tr '\n' ' ')"
  ep="${ep% }"
  if [ "$ep" != "$_K_API_EP" ]; then
    _K_ERR="the cluster addresses list the API servers $ep, but the cluster has $_K_API_EP: nothing is changed"; return 1
  fi
  if [ "$pod" != "$_K_POD_CIDR" ] || [ "$svc" != "$_K_SVC_CIDR" ]; then
    _K_ERR="the cluster addresses give pods $pod and services $svc, but the cluster has $_K_POD_CIDR and $_K_SVC_CIDR: nothing is changed"; return 1
  fi
  _K_ERR=""
}

# ── HA admission (plan Task 18; contract §6): the four HA bindings' objects ──

# The admission policy files (kube/admission): policies.yaml and nodeadm's.
# shellcheck disable=SC2034  # read by kube.sh (kube_cluster_setup)
KUBE_POLICY_FILES="policies.yaml nodeadm-tokens.yaml"
# NEW (HA): Traefik's own namespace (PSA privileged for hostPort 80/443;
# portcullis-ingress-pods admits only its DaemonSet's pod shape there), and
# nodeadm's ServiceAccount (params nodeadmServiceAccount, contract §20.2).
KUBE_INGRESS_NS="portcullis-ingress"
KUBE_NODEADM_SA="system:serviceaccount:portcullis-nodeadm:nodeadm"

# kube_traefik_image — Traefik's image by digest for params traefikImage:
# the resolved one (_K_IMAGES), else images.json's pin (name:tag@sha256:…).
kube_traefik_image() {
  local t
  t="$(printf '%s' "${_K_IMAGES:-}" | jq -r '.traefik // empty' 2>/dev/null || true)"
  [ -n "$t" ] || t="$(jq -r '.images.traefik | if type == "object" then .tag_ref else . end | capture("^(?<n>.+):[^/:@]+@(?<d>sha256:[0-9a-f]{64})$") | .n + "@" + .d' \
    "$PORTCULLIS_HOME/charts/portcullis/images.json" 2>/dev/null || true)"
  [[ "$t" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]] \
    || fail "Traefik's image isn't resolved to a digest (images.traefik=${t:-unset}): refusing to write admission params for portcullis-ingress"
  printf '%s\n' "$t"
}

# _kube_probe_ha <binding> <gen> — the HA bindings' probes (contract §6
# "The probe"), each otherwise admissible by every generation's policy:
#   exec      the Hub's exec of `hub rev /hub-data probe-<gen>` in the
#             reader pod name group-gate-portcullis-admission-probe (no pod
#             needed: admission answers before the pod is looked up);
#   tokens    as nodeadm, a canonical bootstrap token Secret (expiring in
#             10 min) in kube-system;
#   ingress   a pod of portcullis-ingress (another generation's binding lets
#             a dry run annotated with its generation by);
#   nodes     as a node identity (system:node:portcullis-admission-probe,
#             group system:nodes), its own Node without placement labels,
#             with the unlabelled taint a registration must carry.
_kube_probe_ha() {
  local b="$1" g="$2" cns m
  cns="$(kube_ns)"
  m="$(G="$g" jq -nc '{name: "portcullis-admission-probe", annotations: {"portcullis.io/params-generation": env.G}}')"
  case "$b" in
    portcullis-core-guard-exec)
      kube_ctl --as="$(_kube_hub_sa)" --as-group=system:masters create --raw \
        "/api/v1/namespaces/$cns/pods/group-gate-portcullis-admission-probe/exec?command=/portcullis-bin/hub&command=rev&command=/hub-data&command=probe-$g&stdout=true&stderr=true" \
        -f - < /dev/null ;;
    portcullis-nodeadm-guard-tokens)
      M="$m" jq -n '{apiVersion: "v1", kind: "Secret", metadata: (env.M | fromjson | .name = "bootstrap-token-pcprob"),
          type: "bootstrap.kubernetes.io/token",
          stringData: {"token-id": "pcprob", "token-secret": "portcullisprobe0", "expiration": (now + 600 | floor | strftime("%Y-%m-%dT%H:%M:%SZ")),
            "usage-bootstrap-authentication": "true", "auth-extra-groups": "system:bootstrappers:k3s:default-node-token"}}' \
        | kube_ctl -n kube-system --as="$KUBE_NODEADM_SA" --as-group=system:masters create --dry-run=server -f - ;;
    portcullis-nodes-guard-labels)
      # Otherwise admissible: a node registers with exactly the unlabelled
      # taint (R-NODELABELS round 2), else an older generation's binding
      # refuses it first with its own message and the probe never sees ours.
      M="$m" jq -n '{apiVersion: "v1", kind: "Node", metadata: (env.M | fromjson),
          spec: {taints: [{key: "nodeadm.portcullis/unlabelled", value: "true", effect: "NoSchedule"}]}}' \
        | kube_ctl --as=system:node:portcullis-admission-probe --as-group=system:nodes --as-group=system:authenticated create --dry-run=server -f - ;;
    portcullis-ingress-guard-pods)
      M="$m" IMG="${KUBE_HUB_IMAGE:-$PORTCULLIS_HELPER_IMAGE}" jq -n '{apiVersion: "v1", kind: "Pod", metadata: (env.M | fromjson),
          spec: {automountServiceAccountToken: false, containers: [{name: "c", image: env.IMG, command: ["true"]}]}}' \
        | kube_ctl -n "$KUBE_INGRESS_NS" --as="$(_kube_hub_sa)" --as-group=system:masters create --dry-run=server -f - ;;
  esac
}
