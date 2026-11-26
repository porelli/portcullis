#!/usr/bin/env bash
# e2e-ha-vm setup (ci.yml job e2e-ha-vm: workflow_dispatch with
# -f runner=builder only; plan Task 33 part B, D9). The four test VMs are
# reused: reset, prepared and installed from this checkout every run. The
# builder host is never a node and nothing here touches it (the runner is a
# container on it; every VM operation goes over SSH).
#
#   access   the VMs' inventory, SSH key and host keys from the job's secrets
#            (E2E_HA_VM_INVENTORY, E2E_HA_VM_SSH_KEY, E2E_HA_VM_KNOWN_HOSTS)
#            into $E2E_HA_VM_DIR (0700; the key 0600), every address masked;
#            each VM answers over SSH with its host key pinned
#   reset    every VM in parallel: k3s and Portcullis uninstalled, the
#            harness's state wiped (the test disk, faults, fixtures, trust,
#            hosts lines), then rebooted and back
#   prep     packages, modules, the harness's host side
#            (tests/e2e/ha/vm-host.sh: faults, the Longhorn test disk on the
#            servers), vm1's fixtures (Docker, host network: Pebble on vm1's
#            private address with its own TLS CA, an S3 server for the backup
#            destination; never a published port: Docker's DNAT would hide
#            the address the pods' egress policies name), vm1's key for its
#            peers (the local images)
#   images   the nodeagent, nodeadm and Self Node Remediation images built
#            here (the Hub's from the hub-image action), loaded into vm1's
#            Docker (a checked tarball)
#   install  this checkout on vm1 (git archive, three harness-only patches,
#            below), init on vm1 (it becomes the first node), the backup
#            destination, vm2 and vm3 joined as servers and vm4 as an agent
#            at site edge (codes in 0600 files, on the nodes' stdin), then
#            ha enable --yes and its last step's N−1 result recorded
#   status   ha status (and --json into the artifacts)
#
# Harness-only patches of the copy on vm1 (never of this checkout, never
# shipped): config.sh takes E2E_HA_VM_ACME_CA as the ACME CA (Pebble; the
# product knows only Let's Encrypt); node.sh gives the fake DNS provider a
# probe egress host (github.com: real providers have their API host there,
# and without one nodeadm pushes no probe targets); the front door's
# template gets Pebble's TLS CA (LEGO_CA_CERTIFICATES) and the fake zone on
# vm1 (DOMAINS_FAKEDNS_REMOTE: its records outlive a front-door restart).
# Each patch is checked to have matched (fail closed).
#
# Secrets never reach argv or the log: the join codes, the S3 credentials
# and the Pebble key go through 0600 files and stdin.
set -euo pipefail
cd "$(dirname "$0")/../.."
D="${E2E_HA_VM_DIR:-${RUNNER_TEMP:-/tmp}/ha-vm}"
ART="${E2E_ARTIFACTS:-e2e-artifacts}"
PEBBLE_IMG="${PEBBLE_IMG:-ghcr.io/letsencrypt/pebble:2.10.1@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199}"
RCLONE_IMG="docker.io/rclone/rclone:1.71.2@sha256:3103526c506266a9ecdf064efe99bf3677d92ef6407af124d8c56b4f49cbaa51"
# Pebble's certificates: 30 days (the front door's RenewBefore) + 12 min,
# so the front door renews each one about 12 minutes after it was issued
# (the renewal-across-a-leader-move check waits for that).
PEBBLE_VALIDITY=$(( 30 * 86400 + 720 ))
fail() { echo "FAIL: $*" >&2; exit 1; }
redact() { sed -E 's#(https?://[^ ]*/invite/)[A-Za-z0-9_-]+#\1<redacted>#g; s#pcj[0-9]\.[A-Za-z0-9_-]{16,}#<join code>#g'; }
inv() { jq -er "$1" "$D/inventory.json"; }
vms() { inv '.vms[].vm'; }
field() { inv ".vms[] | select(.vm == \"$1\") | .$2"; }
role_vms() { inv ".vms[] | select(.role == \"$1\") | .vm"; }
domain() { inv .domain; }
# vm <vm> <command> — a command on a VM (its stdin passed through).
vm() { local h="$1"; shift; ssh -F "$D/ssh_config" "$h" "$@"; }
# vmq — the same without the connection multiplexer (a node that rebooted).
vmq() { local h="$1"; shift; ssh -F "$D/ssh_config" -o ControlMaster=no -o ControlPath=none "$h" "$@"; }
# shellcheck disable=SC2088  # the remote shell expands ~
pc() { vm vm1 "~/e2e-ha/pc $*"; }
K() { vm vm1 "sudo k3s kubectl $*"; }
each() { # each <fn> <vm>…: fn on every VM in parallel, every failure named
  local fn="$1" pids=() names=() rc=0 i; shift
  for h in "$@"; do "$fn" "$h" > "$D/log-$fn-$h" 2>&1 & pids+=($!); names+=("$h"); done
  for i in "${!pids[@]}"; do
    if ! wait "${pids[$i]}"; then rc=1; echo "::group::$fn ${names[$i]}: failed"; redact < "$D/log-$fn-${names[$i]}" | tail -40; echo "::endgroup::"; fi
  done
  return $rc
}

# tools — what the runner needs (the builder's job image has no SSH
# client): openssh-client and jq from apt, kubectl at e2e-ha-k3d's pin
# (sha256-checked; the drills reach the API through an SSH tunnel).
KUBECTL_VERSION=v1.37.2
KUBECTL_SHA256_AMD64=c04487523e7aa7d1493f7808174c899db93d7a9cf57531420cd76b9bd415f8f4
tools() {
  local missing="" t
  for t in ssh:openssh-client jq:jq openssl:openssl curl:curl; do command -v "${t%%:*}" >/dev/null 2>&1 || missing="$missing ${t#*:}"; done
  if [ -n "$missing" ]; then
    sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $missing >/dev/null || fail "couldn't install$missing"
  fi
  if ! { command -v kubectl >/dev/null 2>&1 && kubectl version --client 2>/dev/null | grep -q -- "$KUBECTL_VERSION"; }; then
    [ "$(uname -m)" = x86_64 ] || fail "no pinned kubectl for $(uname -m)"
    local tmp; tmp="$(mktemp -d)"
    curl -fsSL --retry 3 -o "$tmp/kubectl" "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl"
    echo "$KUBECTL_SHA256_AMD64  $tmp/kubectl" | sha256sum -c --quiet - || fail "kubectl doesn't match its pinned sha256"
    sudo /usr/bin/install -m 0755 "$tmp/kubectl" /usr/local/bin/kubectl
    rm -rf "$tmp"
  fi
  for t in ssh ssh-keygen jq openssl curl kubectl docker git python3; do command -v "$t" >/dev/null 2>&1 || fail "$t is missing on the runner"; done
  echo "PASS: the runner's tools (ssh, jq, openssl, curl, kubectl $KUBECTL_VERSION, docker, git, python3)"
}

access() {
  : "${E2E_HA_VM_INVENTORY:?the VM inventory (secret E2E_HA_VM_INVENTORY)}" "${E2E_HA_VM_SSH_KEY:?the VM SSH key (secret E2E_HA_VM_SSH_KEY)}" \
    "${E2E_HA_VM_KNOWN_HOSTS:?the VM host keys (secret E2E_HA_VM_KNOWN_HOSTS)}"
  (umask 077 && mkdir -p "$D" && printf '%s\n' "$E2E_HA_VM_INVENTORY" > "$D/inventory.json" \
    && printf '%s\n' "$E2E_HA_VM_SSH_KEY" > "$D/id" && printf '%s\n' "$E2E_HA_VM_KNOWN_HOSTS" > "$D/known_hosts")
  chmod 700 "$D"
  jq -e '(.vms | length) == 4 and ([.vms[].vm] | sort) == ["vm1","vm2","vm3","vm4"] and (.domain | test("^[a-z0-9.-]+$"))
    and ([.vms[] | select(.role == "first")] | length) == 1 and ([.vms[] | select(.role == "agent")] | length) == 1
    and (.lan_cidr | test("^[0-9.]+/[0-9]+$"))' "$D/inventory.json" >/dev/null || fail "the inventory isn't the four D9 VMs (vm1 first, vm2/vm3 servers, vm4 the agent)"
  local ip
  for ip in $(inv '.vms[] | .public, .private'); do
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "an inventory address isn't IPv4"
    echo "::add-mask::$ip"
  done
  {
    printf 'Host vm1 vm2 vm3 vm4\n  User %s\n  IdentityFile %s/id\n  IdentitiesOnly yes\n  UserKnownHostsFile %s/known_hosts\n' "$(inv .user)" "$D" "$D"
    printf '  StrictHostKeyChecking yes\n  ConnectTimeout 15\n  ServerAliveInterval 5\n  ServerAliveCountMax 3\n  BatchMode yes\n  LogLevel ERROR\n'
    printf '  ControlMaster auto\n  ControlPath %s/cm-%%h\n  ControlPersist 20m\n' "$D"
    for h in $(vms); do printf 'Host %s\n  HostName %s\n' "$h" "$(field "$h" public)"; done
  } > "$D/ssh_config"
  for h in $(vms); do
    vm "$h" true || fail "$h doesn't answer over SSH (its host key pinned)"
  done
  echo "PASS: the four VMs answer over SSH"
}

# reboot_vm <vm> — a reboot, and the node back over SSH with a new boot id.
reboot_vm() {
  local b0 b="" i
  b0="$(vmq "$1" cat /proc/sys/kernel/random/boot_id)"
  vmq "$1" 'sudo systemd-run --on-active=2 systemctl reboot >/dev/null' || true
  ssh -F "$D/ssh_config" -O exit "$1" >/dev/null 2>&1 || true
  sleep 20
  for i in $(seq 1 60); do
    b="$(vmq "$1" cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
    [ -n "$b" ] && [ "$b" != "$b0" ] && return 0
    sleep 5
  done
  fail "$1 didn't come back from its reboot"
}

reset_one() {
  # First a boot with nothing started that arms the watchdog: Self Node
  # Remediation pets softdog, and killing k3s under it reboots the node
  # in the middle of the uninstall (seen). k3s, its agent and the
  # nodeagent are disabled, then the node reboots; only then the uninstall.
  vmq "$1" 'sudo systemctl disable k3s.service k3s-agent.service portcullis-nodeagent.service >/dev/null 2>&1; true'
  if vmq "$1" 'systemctl list-unit-files k3s.service k3s-agent.service 2>/dev/null | grep -q -E "^k3s"'; then reboot_vm "$1"; fi
  vmq "$1" 'sudo bash -s' <<'EOF'
set -u
systemctl disable --now portcullis-kube-check.timer portcullis-kube-params.timer portcullis-nodeagent.service >/dev/null 2>&1
[ -x /usr/local/bin/k3s-uninstall.sh ] && /usr/local/bin/k3s-uninstall.sh >/dev/null 2>&1
[ -x /usr/local/bin/k3s-agent-uninstall.sh ] && /usr/local/bin/k3s-agent-uninstall.sh >/dev/null 2>&1
systemctl disable --now wg-quick@pcmesh >/dev/null 2>&1
ip link del pcmesh 2>/dev/null; ip link del flannel-wg 2>/dev/null
rm -f /etc/systemd/system/portcullis-* /etc/wireguard/pcmesh.conf /etc/wireguard/pcmesh.key
rm -rf /etc/systemd/system/k3s.service.d /etc/systemd/system/k3s-agent.service.d /etc/systemd/system/k3s*.env \
  /usr/local/lib/portcullis /var/lib/portcullis /etc/rancher /var/lib/rancher /var/lib/kubelet
# The harness's own state (the test disk, its faults, a dark flag).
systemctl disable --now e2e-ha-disk.service e2e-ha-net.service >/dev/null 2>&1
umount -l /var/lib/longhorn 2>/dev/null; dmsetup remove -f e2e-lh 2>/dev/null
for l in $(losetup -j /var/lib/e2e-ha/longhorn.img 2>/dev/null | cut -d: -f1); do losetup -d "$l"; done
rm -rf /var/lib/e2e-ha /var/lib/longhorn /etc/e2e-ha /usr/local/sbin/e2e-ha-host /usr/local/sbin/k3s \
  /etc/systemd/system/e2e-ha-*.service /etc/systemd/system/*.service.d/90-e2e-ha-dark.conf
iptables -w -t raw -S 2>/dev/null | grep -q E2EHA && { iptables -w -t raw -D PREROUTING -j E2EHA; iptables -w -t raw -D OUTPUT -j E2EHA; iptables -w -t raw -F E2EHA; iptables -w -t raw -X E2EHA; } 2>/dev/null
# vm1's fixtures and checkout; the earlier hand-built harness (vmr*).
if command -v docker >/dev/null 2>&1; then docker rm -f e2e-pebble e2e-s3 e2e-fakezone >/dev/null 2>&1; fi
home=$(getent passwd "${SUDO_USER:-ubuntu}" | cut -d: -f6)
for p in "$home"/vmr-*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null; done
rm -rf "$home/portcullis" "$home/e2e-ha" "$home"/vmr* /var/tmp/e2e-imp.*
sed -i '/# e2e-ha-vm$/d; /ha\.portcullis\.test/d' /etc/hosts
rm -f /usr/local/share/ca-certificates/e2e-ha-*.crt /usr/local/share/ca-certificates/vmr-*.crt /etc/modules-load.d/vmr-ha.conf
update-ca-certificates --fresh >/dev/null 2>&1
systemctl daemon-reload
EOF
  reboot_vm "$1"
  vmq "$1" 'test ! -e /usr/local/bin/k3s && ! ip link show pcmesh >/dev/null 2>&1 && ! systemctl list-unit-files | grep -q -E "^(k3s|portcullis)"' \
    || fail "$1: k3s or Portcullis is still there after the reset"
  echo "$1: reset (boot $(vmq "$1" cat /proc/sys/kernel/random/boot_id))"
}

# shellcheck disable=SC2046  # one VM name per word
reset() { each reset_one $(vms); echo "PASS: the four VMs reset and rebooted"; }

prep_one() {
  local h="$1" pk="jq git wireguard-tools open-iscsi nfs-common curl iptables dmsetup e2fsprogs"
  [ "$h" != vm1 ] || pk="$pk docker.io docker-buildx python3"
  # shellcheck disable=SC2029  # the package list and $h are expanded here
  vm "$h" "sudo bash -s $h $pk" <<'EOF'
set -euo pipefail
h="$1"; shift
export DEBIAN_FRONTEND=noninteractive
missing=""
for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 || missing="$missing $p"; done
if [ -n "$missing" ]; then apt-get update -qq; apt-get install -y -qq $missing >/dev/null; fi
[ "$h" != vm1 ] || usermod -aG docker "${SUDO_USER:-ubuntu}"
printf 'softdog\niscsi_tcp\ndm_mod\n' > /etc/modules-load.d/e2e-ha.conf
modprobe softdog; modprobe iscsi_tcp; modprobe dm_mod
systemctl enable --now iscsid >/dev/null 2>&1 || true
if [ -e /etc/multipath.conf ] && ! grep -q '^blacklist' /etc/multipath.conf; then
  printf 'blacklist {\n    devnode "^sd[a-z0-9]+"\n}\n' >> /etc/multipath.conf; systemctl restart multipathd 2>/dev/null || true
fi
EOF
  vm "$h" 'cat > /tmp/e2e-ha-host' < tests/e2e/ha/vm-host.sh
  local disk=""
  [ "$(field "$h" role)" = agent ] || disk=disk
  # shellcheck disable=SC2029
  vm "$h" "sudo bash /tmp/e2e-ha-host install $disk && rm -f /tmp/e2e-ha-host && sudo e2e-ha-host state"
  # The domain's names at vm1 (its private address in the region, its public
  # one from the other region).
  local to
  to="$(field vm1 private)"; [ "$(field "$h" site)" = main ] || to="$(field vm1 public)"
  local d; d="$(domain)"
  for n in "" auth. hub. people. portal. enroll. status. vpn.; do printf '%s %s%s # e2e-ha-vm\n' "$to" "$n" "$d"; done | vm "$h" 'sudo tee -a /etc/hosts >/dev/null'
}

fixtures() {
  # Pebble's TLS CA and its certificate for vm1's private address (made
  # here; the key only into vm1's 0700 dir), the S3 server's credentials
  # (random, a 0600 file read by docker --env-file, never argv).
  local p priv w
  p="$(field vm1 private)"; priv="$p"
  w="$(mktemp -d)"; chmod 700 "$w"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=e2e-ha-vm Pebble TLS CA" \
    -keyout "$w/ca.key" -out "$w/ca.crt" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$p" -keyout "$w/key.pem" -out "$w/csr.pem" 2>/dev/null
  printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\n' "$p" > "$w/ext"
  openssl x509 -req -in "$w/csr.pem" -CA "$w/ca.crt" -CAkey "$w/ca.key" -CAcreateserial -days 30 -extfile "$w/ext" -out "$w/cert.pem" 2>/dev/null
  jq -n --argjson v "$PEBBLE_VALIDITY" --arg l "$p:14443" '{pebble: {listenAddress: $l, managementListenAddress: "127.0.0.1:15443",
    certificate: "/p/cert.pem", privateKey: "/p/key.pem", httpPort: 5002, tlsPort: 5001, ocspResponderURL: "",
    externalAccountBindingRequired: false, retryAfter: {authz: 3, order: 5}, keyAlgorithm: "ecdsa",
    profiles: {default: {description: "e2e-ha-vm: renewed 12 min after issue", validityPeriod: $v}}}}' > "$w/pebble.json"
  { printf 'RCLONE_AUTH_KEY=%s,%s\n' "e2e$(openssl rand -hex 8)" "$(openssl rand -hex 24)"; } > "$w/s3.env"
  chmod 600 "$w"/*
  cp "$w/ca.crt" "$D/pebble-tls-ca.crt"
  tar -C "$w" -cf - ca.crt cert.pem key.pem pebble.json s3.env | vm vm1 'umask 077; mkdir -p ~/e2e-ha/pebble ~/e2e-ha/s3/data/e2e-bucket && tar -C ~/e2e-ha/pebble -xf - && mv ~/e2e-ha/pebble/s3.env ~/e2e-ha/s3.env && chmod 755 ~/e2e-ha ~/e2e-ha/pebble && chmod 644 ~/e2e-ha/pebble/*.pem ~/e2e-ha/pebble/*.json ~/e2e-ha/pebble/ca.crt'
  rm -rf "$w"
  # shellcheck disable=SC2029  # the images and addresses are expanded here
  vm vm1 "set -e; docker pull -q '$PEBBLE_IMG' >/dev/null; docker pull -q '$RCLONE_IMG' >/dev/null
    docker rm -f e2e-pebble e2e-s3 >/dev/null 2>&1 || true
    docker run -d --name e2e-pebble --restart no --network host \
      -e PEBBLE_VA_ALWAYS_VALID=1 -e PEBBLE_VA_NOSLEEP=1 -v ~/e2e-ha/pebble:/p:ro '$PEBBLE_IMG' -config /p/pebble.json >/dev/null
    docker run -d --name e2e-s3 --restart no --network host --env-file ~/e2e-ha/s3.env -v ~/e2e-ha/s3/data:/data \
      --user \"\$(id -u):\$(id -g)\" '$RCLONE_IMG' serve s3 --addr '$priv:9100' /data >/dev/null
    for i in \$(seq 1 30); do curl -fsk https://127.0.0.1:15443/roots/0 -o ~/e2e-ha/pebble-root.crt 2>/dev/null && break; sleep 1; done
    test -s ~/e2e-ha/pebble-root.crt"
  vm vm1 'cat ~/e2e-ha/pebble-root.crt' > "$D/pebble-root.crt"
  openssl x509 -noout -in "$D/pebble-root.crt" || fail "Pebble's root didn't come"
  # Pebble's issuing root on the main hosts' trust (the CA bundle the CLI
  # builds for forward-auth from the host's store: the served certificate
  # is Pebble's after ha enable's step 9).
  for h in $(vms); do
    [ "$(field "$h" site)" = main ] || continue
    vm "$h" 'sudo install -m 0644 /dev/stdin /usr/local/share/ca-certificates/e2e-ha-pebble-root.crt && sudo update-ca-certificates >/dev/null 2>&1' < "$D/pebble-root.crt"
  done
  echo "PASS: Pebble (validity $PEBBLE_VALIDITY s) and the S3 server on vm1"
}

peers_key() {
  # vm1's key for the image copies to its peers (the harness's k3s wrapper
  # there), its known_hosts the pinned host keys under the addresses vm1
  # uses (private in the region, the mesh address for vm4 once it joined).
  local w; w="$(mktemp -d)"; chmod 700 "$w"
  ssh-keygen -q -t ed25519 -N '' -C e2e-ha-vm-peers -f "$w/peer"
  for h in vm2 vm3 vm4; do vm "$h" 'umask 077; mkdir -p ~/.ssh; sed -i "/e2e-ha-vm-peers$/d" ~/.ssh/authorized_keys 2>/dev/null; cat >> ~/.ssh/authorized_keys' < "$w/peer.pub"; done
  : > "$w/known_hosts"; : > "$w/ssh_config"
  for h in vm2 vm3 vm4; do
    local pub addr
    pub="$(field "$h" public)"
    addr="$(field "$h" private)"; [ "$(field "$h" site)" = main ] || addr="10.215.0.4"
    awk -v p="$pub" -v a="$addr" '$1 == p { $1 = a; print }' "$D/known_hosts" >> "$w/known_hosts"
    printf 'Host %s\n  HostName %s\n  User %s\n  IdentityFile /etc/e2e-ha/peer\n  IdentitiesOnly yes\n  UserKnownHostsFile /etc/e2e-ha/known_hosts\n  StrictHostKeyChecking yes\n  BatchMode yes\n  ConnectTimeout 10\n' \
      "$h" "$addr" "$(inv .user)" >> "$w/ssh_config"
  done
  # The k3s wrapper (sudo's secure_path finds /usr/local/sbin first): the
  # CLI's `k3s ctr -n k8s.io images import -` and `images tag` also on every
  # peer in /etc/e2e-ha/peers (the K1 local images on every node; a peer's
  # failure fails the CLI's import, fail closed). Anything else is k3s.
  cat > "$w/k3s" <<'EOF'
#!/bin/bash
# e2e-ha-vm harness (vm1, a test VM only): see .github/ci/e2e-ha-vm-setup.sh peers_key.
set -euo pipefail
real=/usr/local/bin/k3s
if [ "${1:-}" = ctr ] && [ "${2:-}" = -n ] && [ "${3:-}" = k8s.io ] && [ "${4:-}" = images ] && { [ "${5:-}" = import ] || [ "${5:-}" = tag ]; }; then
  tmp=""
  if [ "$5" = import ] && [ "${6:-}" = - ]; then
    tmp="$(mktemp /var/tmp/e2e-imp.XXXXXX)"; trap 'rm -f "$tmp"' EXIT
    cat > "$tmp"; "$real" "$@" < "$tmp"
  else
    "$real" "$@"
  fi
  [ -s /etc/e2e-ha/peers ] || exit 0
  while read -r peer; do
    [ -n "$peer" ] || continue
    if [ -n "$tmp" ]; then
      ssh -F /etc/e2e-ha/ssh_config "$peer" sudo k3s "$(printf '%q ' "$@")" < "$tmp"
    else
      ssh -F /etc/e2e-ha/ssh_config "$peer" sudo k3s "$(printf '%q ' "$@")" < /dev/null
    fi
  done < /etc/e2e-ha/peers
  exit 0
fi
exec "$real" "$@"
EOF
  tar -C "$w" -cf - peer known_hosts ssh_config k3s | vm vm1 'sudo bash -c "umask 077; mkdir -p /etc/e2e-ha && tar -C /etc/e2e-ha -xf - && install -m 0755 /etc/e2e-ha/k3s /usr/local/sbin/k3s && rm /etc/e2e-ha/k3s && : > /etc/e2e-ha/peers"'
  rm -rf "$w"
}

prep() {
  # shellcheck disable=SC2046  # one VM name per word
  each prep_one $(vms)
  fixtures
  peers_key
  echo "PASS: the VMs prepared (packages, faults, the Longhorn test disk on the servers, vm1's fixtures)"
}

images() {
  local hub="${HUB_SRC:-${RUNNER_TEMP:-/tmp}/portcullis-hub}" i
  if [ ! -f "$hub/Dockerfile.nodeagent" ]; then git clone --quiet --depth=1 https://github.com/porelli/portcullis-hub "$hub"; fi
  echo "nodeagent: built from $hub ($(git -C "$hub" rev-parse --short HEAD 2>/dev/null || echo archive))" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
  for i in 1 2 3; do
    docker buildx build --load --provenance=false -f "$hub/Dockerfile.nodeagent" -t portcullis-nodeagent:ci "$hub" && break
    [ "$i" = 3 ] && fail "the nodeagent image didn't build"; sleep 20
  done
  docker buildx build --load --provenance=false --build-context nodeagent=docker-image://portcullis-nodeagent:ci -t portcullis-nodeadm:ci nodeadm
  docker buildx build --load --provenance=false -t portcullis-snr:ci kube/ha/fencing/snr-patch
  local imgs=(portcullis-nodeagent:ci portcullis-nodeadm:ci portcullis-snr:ci)
  [ -z "${HUB_LOCAL:-}" ] || imgs+=("${HUB_IMAGE:?}")
  [ -z "${KEYCLOAK_LOCAL:-}" ] || imgs+=("${KEYCLOAK_IMAGE:?}")
  docker save "${imgs[@]}" | gzip -1 > "$D/images.tgz"
  local sum; sum="$(sha256sum "$D/images.tgz" | cut -d' ' -f1)"
  # shellcheck disable=SC2029
  vm vm1 "cat > /tmp/e2e-images.tgz && [ \"\$(sha256sum /tmp/e2e-images.tgz | cut -d' ' -f1)\" = $sum ] && gunzip -c /tmp/e2e-images.tgz | docker load -q && rm /tmp/e2e-images.tgz" < "$D/images.tgz"
  rm -f "$D/images.tgz"
  echo "PASS: ${imgs[*]} in vm1's Docker"
}

# patch <file> <python> — a harness-only edit of the copy on vm1, which
# must change the file (fail closed).
patch_copy() {
  # shellcheck disable=SC2029
  vm vm1 "cd ~/portcullis && python3 - '$1'" <<<"import sys
p = sys.argv[1]; s = open(p).read(); o = s
$2
assert s != o, 'the harness patch of ' + p + ' matched nothing'
open(p, 'w').write(s)"
}

# hub_ready — the Hub and nodeadm rolled out and Ready (an `up` restarts
# the Hub; node add needs it answering).
hub_ready() {
  K -n portcullis rollout status deploy/hub --timeout=600s >/dev/null || fail "the Hub didn't become Ready"
  K -n portcullis-nodeadm rollout status deploy/nodeadm --timeout=600s >/dev/null || fail "nodeadm didn't become Ready"
}

join_node() { # join_node <vm> <node add arguments…>
  local h="$1"; shift
  local id; id="$(field "$h" node)"
  if [ "$(K get node "$id" --no-headers 2>/dev/null | awk '{print $2}')" = Ready ]; then
    echo "$id ($h): already joined and Ready"
  else
  # The code on stdout into a 0600 file here, then onto the node's root
  # 0600 file through stdin (join.sh --code-file); never argv, never logged.
  # A Hub that is still starting answers "isn't running": waited for and
  # tried again (3 times), anything else fails at once.
  local ok=""
  for _ in 1 2 3; do
    hub_ready
    if (umask 077 && pc node add "$id" "$*" > "$D/code-$h" 2> "$D/add-$h.log"); then ok=1; break; fi
    grep -q "isn't running\|not ready\|starting" "$D/add-$h.log" || break
    sleep 20
  done
  [ -n "$ok" ] || { redact < "$D/add-$h.log"; fail "node add $id"; }
  grep -q '^pcj[0-9]\.' "$D/code-$h" || fail "node add $id printed no join code"
  vm "$h" 'sudo install -m 0600 -o root -g root /dev/stdin /root/e2e-join-code' < "$D/code-$h"
  rm -f "$D/code-$h"
  local d; d="$(domain)"
  # shellcheck disable=SC2029
  vm "$h" "curl -fsSL https://$d/node/join.sh -o /tmp/join.sh && sudo sh /tmp/join.sh --code-file /root/e2e-join-code; rc=\$?; sudo rm -f /root/e2e-join-code /tmp/join.sh; exit \$rc" 2>&1 | redact | tail -20
  local i
  for i in $(seq 1 90); do
    # (No jsonpath: its quotes don't survive the remote shell.)
    [ "$(K get node "$id" --no-headers 2>/dev/null | awk '{print $2}')" = Ready ] && break
    [ "$i" = 90 ] && fail "$id isn't Ready 7.5 min after its join"
    sleep 5
  done
  fi
  # Every local image (localhost/portcullis-*) onto the new node, then the
  # wrapper keeps it in step (the peer list).
  vm vm1 "sudo bash -c 'refs=\$(k3s ctr -n k8s.io images ls -q | grep -E \"^localhost/portcullis-\" | sort -u); [ -z \"\$refs\" ] || /usr/local/bin/k3s ctr -n k8s.io images export --platform linux/amd64 - \$refs | ssh -F /etc/e2e-ha/ssh_config $h sudo k3s ctr -n k8s.io images import - >/dev/null; grep -qx $h /etc/e2e-ha/peers || echo $h >> /etc/e2e-ha/peers'"
  # The node's public address (contract gap, see the job's comment): a
  # joined node behind a 1:1 NAT (Lightsail, EC2) reports none, so nodeadm
  # would publish only the first node's; the harness names it, as an admin
  # would.
  local ann
  ann="$(jq -cn --arg l "$(field "$h" private)" --arg p "$(field "$h" public)" '{lan: [$l], public: [$p]}')"
  K annotate node "$id" --overwrite "portcullis.io/addresses='$ann'" >/dev/null
  echo "$id ($h) joined and Ready"
}

# core_trust — core's CA chain (the root and its intermediates, one file
# each: Traefik serves its leaf without the intermediate, so curl on a
# joining node must hold the intermediate too) in every host's trust.
core_trust() {
  vm vm1 'cat ~/portcullis/certs/ca-chain.crt' > "$D/core-root.crt"
  local w; w="$(mktemp -d)"
  awk -v d="$w" '/-----BEGIN CERTIFICATE-----/ { n++ } n { print > (d "/e2e-ha-core-" n ".crt") }' "$D/core-root.crt"
  [ -s "$w/e2e-ha-core-1.crt" ] || fail "core's CA chain is empty"
  for h in $(vms); do
    tar -C "$w" -cf - . | vm "$h" 'sudo rm -f /usr/local/share/ca-certificates/e2e-ha-core-*.crt && sudo tar -C /usr/local/share/ca-certificates -xf - --no-same-owner && sudo update-ca-certificates >/dev/null 2>&1'
  done
  rm -rf "$w"
}

install() {
  local d pub priv; d="$(domain)"; pub="$(field vm1 public)"; priv="$(field vm1 private)"
  git archive --format=tar HEAD | vm vm1 'rm -rf ~/portcullis && mkdir ~/portcullis && tar -C ~/portcullis -xf -'
  # The CLI's environment on vm1 (0600; no secret in it).
  {
    printf 'HUB_DEV=1\nPORTCULLIS_TESTPROVIDER=1\nPORTCULLIS_NODE_CLASS=cloud\nPORTCULLIS_KUBE_IMAGES=local\n'
    printf 'PORTCULLIS_PUBLIC_IPV4=%s\nPORTCULLIS_DOMAIN=%s\nACME_EMAIL=admin@%s\nE2E_HA_VM_ACME_CA=https://%s:14443/dir\n' "$pub" "$d" "$d" "$priv"
    [ -z "${HUB_LOCAL:-}" ] || printf 'HUB_IMAGE=%s\n' "$HUB_IMAGE"
    [ -z "${KEYCLOAK_LOCAL:-}" ] || printf 'KEYCLOAK_IMAGE=%s\n' "$KEYCLOAK_IMAGE"
  } | vm vm1 'umask 077; mkdir -p ~/e2e-ha && cat > ~/e2e-ha/env && printf "%s\n" "#!/bin/bash" "set -a; . ~/e2e-ha/env; set +a" "cd ~/portcullis && exec ./portcullis \"\$@\"" > ~/e2e-ha/pc && chmod 700 ~/e2e-ha/pc'
  # The three harness-only patches (see the header).
  patch_copy scripts/lib/config.sh "s = s.replace('''  # Traefik's DNS-01 provider (lego): hetzner-cloud''', '''  [ -z \"\${E2E_HA_VM_ACME_CA:-}\" ] || ca_server=\"\$E2E_HA_VM_ACME_CA\"  # e2e-ha-vm harness
  # Traefik's DNS-01 provider (lego): hetzner-cloud''', 1)"
  patch_copy scripts/lib/node.sh "s = s.replace('hetzner-cloud=api.hetzner.cloud\"', 'hetzner-cloud=api.hetzner.cloud fake=github.com\"', 1)"
  patch_copy charts/portcullis/templates/frontdoor.yaml "s = s.replace('''    (dict \"name\" \"ACME_CA_SERVER\" \"value\" .Values.acme.caServer)''', '''    (dict \"name\" \"ACME_CA_SERVER\" \"value\" .Values.acme.caServer)
    (dict \"name\" \"LEGO_CA_CERTIFICATES\" \"value\" \"/run/e2e-ha/ca.crt\")
    (dict \"name\" \"DOMAINS_FAKEDNS_REMOTE\" \"value\" \"http://$priv:8054\")''', 1)
s = s.replace('''    (dict \"name\" \"control-tls\" \"mountPath\" \"/run/portcullis/frontdoor-tls\" \"readOnly\" true))''', '''    (dict \"name\" \"control-tls\" \"mountPath\" \"/run/portcullis/frontdoor-tls\" \"readOnly\" true)
    (dict \"name\" \"e2e-ha-pebble\" \"mountPath\" \"/run/e2e-ha\" \"readOnly\" true))''', 1)
s = s.replace('''\"defaultMode\" 288 \"optional\" true)))''', '''\"defaultMode\" 288 \"optional\" true))
    (dict \"name\" \"e2e-ha-pebble\" \"configMap\" (dict \"name\" \"e2e-ha-pebble-ca\")))''', 1)"
  vm vm1 'cd ~/portcullis && grep -c "e2e-ha" charts/portcullis/templates/frontdoor.yaml scripts/lib/config.sh scripts/lib/node.sh'
  # init: k3s and pcmesh first (--env-only), then nodeadm's and SNR's
  # images by digest, then the whole init.
  pc init --env-only --runtime kubernetes --non-interactive --domain "$d" --email "admin@$d" --dns-provider none --no-config-repo 2>&1 | redact | tail -20
  vm vm1 'cd ~/portcullis && bash -c "source scripts/lib/common.sh
    env_set DNS_PROVIDER fake; env_set FAKE_API_TOKEN e2e-ha-vm-fake-token-0123456789; env_set DNS_CAA false; env_set DNS_CAA_ISSUER pebble.letsencrypt.org
    env_set PORTCULLIS_KUBE_IMAGES local; env_set PORTCULLIS_TESTPROVIDER 1
    n=\$(_kube_local_import portcullis-nodeadm:ci nodeadm) && s=\$(_kube_local_import portcullis-snr:ci snr) || exit 1
    [[ \$n =~ ^localhost/portcullis-nodeadm@sha256:[0-9a-f]{64}\$ && \$s =~ ^localhost/portcullis-snr@sha256:[0-9a-f]{64}\$ ]] || exit 1
    env_set PORTCULLIS_NODEADM_IMAGE \$n; env_set PORTCULLIS_DEV_SNR_IMAGE \$s"
    printf "tls:\n  certificates:\n    - certFile: /certs/server.crt\n      keyFile: /certs/server.key\n" > traefik/dynamic/ci-certs.yml'
  local t0; t0=$(date +%s)
  pc init --runtime kubernetes --non-interactive --no-config-repo 2>&1 | redact | tail -30
  echo "init: $(( $(date +%s) - t0 )) s" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
  # Core's root on every host (join.sh fetches from https://<d>), the
  # front door's Pebble CA, its egress to vm1's Pebble and fake zone.
  core_trust

  # shellcheck disable=SC2029
  vm vm1 "docker rm -f e2e-fakezone >/dev/null 2>&1; docker run -d --name e2e-fakezone --restart no --read-only --cap-drop ALL --security-opt no-new-privileges \
    --network host -e DOMAINS_FAKEDNS_API_ADDR='$priv:8054' --entrypoint domains portcullis-domains:kube-local fakezone >/dev/null"
  K -n portcullis create configmap e2e-ha-pebble-ca --from-file=ca.crt=/dev/stdin < "$D/pebble-tls-ca.crt" >/dev/null
  jq -n --arg ip "$priv/32" '{apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: {name: "e2e-ha-frontdoor-fixtures", namespace: "portcullis"},
    spec: {podSelector: {matchLabels: {"portcullis.io/component": "frontdoor"}}, policyTypes: ["Egress"],
      egress: [{to: [{ipBlock: {cidr: $ip}}], ports: [{protocol: "TCP", port: 14443}, {protocol: "TCP", port: 8054}]}]}}' | K apply -f - >/dev/null
  vm vm1 'cat ~/e2e-ha/s3.env' | sed -E 's/^RCLONE_AUTH_KEY=([^,]*),(.*)$/AWS_ACCESS_KEY_ID=\1\nAWS_SECRET_ACCESS_KEY=\2/' \
    | pc backup destination set "http://$priv:9100/e2e-bucket/portcullis" > "$D/dest.log" 2>&1 || { tail -5 "$D/dest.log"; fail "backup destination set"; }
  tail -3 "$D/dest.log"
  echo "PASS: init on vm1"
}

cluster() {
  local d priv; d="$(domain)"; priv="$(field vm1 private)"
  : "$d" "$priv"
  core_trust
  # The joins.
  local t0; t0=$(date +%s)
  for h in $(role_vms server); do join_node "$h" --role server --class cloud --site main; done
  join_node vm4 --role agent --class cloud --site "$(field vm4 site)" --public-endpoint "$(field vm4 public):51830"
  echo "joins: $(( $(date +%s) - t0 )) s" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
  # The switch's served pair (_ha_cert_ok: <d> and *.<d>), from core's CA,
  # named in traefik/dynamic (as e2e-ha-k3d; the root token on the vault
  # pod's stdin, the key into a 0600 file on vm1).
  vm vm1 'cd ~/portcullis && set -e; jq -r .root_token secrets/vault-init.json | sudo k3s kubectl -n portcullis exec -i pod/vault-0 -c vault -- sh -c "IFS= read -r t; VAULT_TOKEN=\"\$t\" VAULT_ADDR=http://127.0.0.1:8200 exec vault write -format=json pki_int/issue/server-cert common_name=\"\$1\" alt_names=\"*.\$1\" ttl=2160h" _ "$(. ~/e2e-ha/env; echo "$PORTCULLIS_DOMAIN")" > /tmp/e2e-main.json
    (umask 077 && jq -r ".data.certificate, .data.issuing_ca" /tmp/e2e-main.json > certs/ha-main.crt && jq -r .data.private_key /tmp/e2e-main.json > certs/ha-main.key); rm -f /tmp/e2e-main.json
    printf "tls:\n  certificates:\n    - certFile: /certs/ha-main.crt\n      keyFile: /certs/ha-main.key\n" > traefik/dynamic/ci-ha-main.yml'
  # The backup destination reaches the Hub (HUB_BACKUP_DESTINATION, the
  # checklist's backup_destination) only through an up; then the Hub Ready.
  pc up 2>&1 | redact | tail -5
  hub_ready
  t0=$(date +%s)
  local rc=0
  pc ha enable --yes 2>&1 | redact | tee "$D/ha-enable.log" | tail -60 || rc=$?
  echo "ha enable: $(( $(date +%s) - t0 )) s (exit $rc)" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
  mkdir -p "$ART"; cp "$D/ha-enable.log" "$ART/ha-enable.log"
  # The real-install carry (d1f38b3: a pod on a node-bound volume is
  # unplaceable off its node): step 10's N−1 as ha status reports it.
  pc ha status 2>&1 | redact | tee "$ART/ha-status-after-enable.txt" | grep -i -E "n.1|yellow|red|green|ha enable" | head -20 || true
  pc ha status --json > "$ART/ha-status-after-enable.json" 2>/dev/null || true
  [ "$rc" = 0 ] || fail "ha enable failed (exit $rc): its last lines above, the N−1 result in $ART/ha-status-after-enable.txt"
  echo "PASS: installed: init on vm1, $(role_vms server | xargs) servers, vm4 at $(field vm4 site), HA on"
}

# cleanup — the credentials from the job's secrets and everything derived
# from them (the key, host keys, inventory, kubeconfig, SSH sockets) gone.
cleanup() {
  [ -d "$D" ] || return 0
  local h
  for h in vm1 vm2 vm3 vm4; do ssh -F "$D/ssh_config" -O exit "$h" >/dev/null 2>&1 || true; done
  rm -rf "$D"
  echo "PASS: the VM credentials removed"
}

status() {
  mkdir -p "$ART"
  pc ha status 2>&1 | redact | tee "$ART/ha-status.txt"
  pc ha status --json > "$ART/ha-status.json" 2>/dev/null || true
}

case "${1:-}" in
  tools) tools ;;
  access) access ;;
  reset) reset ;;
  prep) prep ;;
  images) images ;;
  install) install; cluster ;;
  init) install ;;
  cluster) cluster ;;
  status) status ;;
  cleanup) cleanup ;;
  *) echo "usage: $0 tools|access|reset|prep|images|install|init|cluster|status|cleanup" >&2; exit 2 ;;
esac
