#!/usr/bin/env bash
# e2e-ha-vm: the harness's host side on a test VM (never the builder host),
# installed by .github/ci/e2e-ha-vm-setup.sh prep as /usr/local/sbin/e2e-ha-host
# (root 0755). The failures the drills inject, each undone by the harness
# or by a boot:
#
#   install [disk]      itself, its units, the drop-ins; `disk`: the
#                       Longhorn test disk (storage nodes)
#   disk up|kill|state  the test disk: a sparse file → loop → device-mapper
#                       e2e-lh (linear) → ext4 at /var/lib/longhorn (Longhorn's
#                       default disk). kill: the table swapped for `error`
#                       (every I/O fails, as a dead disk); a boot sets it up
#                       again (fsck first)
#   fill | unfill       the test disk filled (fallocate up to 1 MiB free) / freed
#   net set <spec>...   network faults in the raw table's own chain E2EHA
#                       (kube-router rewrites the filter table, never raw),
#                       kept in /etc/e2e-ha/net and applied again at boot:
#                         partition  every packet but loopback, SSH (port
#                                    22), the cloud metadata / link-local
#                                    range and DHCP dropped both ways
#                         drop443    inbound TCP 443 not from pcmesh (the
#                                    public ingress; the mesh stays)
#                         natmesh:<cidr>  a real NAT in front of the mesh
#                                    port: NEW inbound UDP 51830 from outside
#                                    <cidr> dropped, replies to the node's
#                                    own dials kept (conntrack; the mangle
#                                    table's chain E2EHAM: raw runs before
#                                    conntrack)
#                         dropmesh:<cidr>  inbound UDP 51830 from outside
#                                    <cidr> (the site's LAN) dropped: the
#                                    node's mesh port closed to the other
#                                    sites (a NAT), its LAN peers kept
#   net clear           the faults gone (live and at boot)
#   net apply           (boot) the saved faults
#   dark                a power-off: /etc/e2e-ha/dark + partition written and
#                       synced, then an immediate reboot without sync
#                       (sysrq b). While the flag is there, k3s, the k3s
#                       agent and the nodeagent don't start at boot
#                       (ConditionPathExists drop-ins) and the node is cut
#   light               powered on again: the flag and the faults gone, the
#                       services started
#   state               boot id, faults, dark flag, disk state (one JSON line)
set -euo pipefail
umask 022
CHAIN=E2EHA
MCHAIN=E2EHAM
ETC=/etc/e2e-ha
IMG=/var/lib/e2e-ha/longhorn.img
DM=e2e-lh
MNT=/var/lib/longhorn
SIZE_G="${E2E_HA_DISK_GB:-60}"
UNITS="k3s.service k3s-agent.service portcullis-nodeagent.service"

[ "$(id -u)" = 0 ] || { echo "e2e-ha-host: run as root" >&2; exit 2; }

ipt() { iptables -w -t raw "$@"; }

net_flush() {
  for c in PREROUTING OUTPUT; do
    while ipt -D "$c" -j "$CHAIN" 2>/dev/null; do :; done
  done
  ipt -F "$CHAIN" 2>/dev/null || true
  ipt -X "$CHAIN" 2>/dev/null || true
  while iptables -w -t mangle -D PREROUTING -j "$MCHAIN" 2>/dev/null; do :; done
  iptables -w -t mangle -F "$MCHAIN" 2>/dev/null || true
  iptables -w -t mangle -X "$MCHAIN" 2>/dev/null || true
}

net_rules() {
  local spec
  ipt -N "$CHAIN"
  ipt -A "$CHAIN" -i lo -j RETURN
  ipt -A "$CHAIN" -o lo -j RETURN
  for spec in "$@"; do
    case "$spec" in
      partition)
        ipt -A "$CHAIN" -p tcp --dport 22 -j RETURN
        ipt -A "$CHAIN" -p tcp --sport 22 -j RETURN
        # The machine's own platform stays (a cut node still has its cloud
        # metadata, link-local DNS and DHCP): with the metadata service
        # dropped at boot, cloud-init fell back to DataSourceNone, took the
        # boot for a new instance and regenerated the SSH host keys (seen
        # on vm1 and vm3, run 45892504006).
        ipt -A "$CHAIN" -d 169.254.0.0/16 -j RETURN
        ipt -A "$CHAIN" -s 169.254.0.0/16 -j RETURN
        ipt -A "$CHAIN" -p udp --sport 67:68 --dport 67:68 -j RETURN
        ipt -A "$CHAIN" -j DROP ;;
      drop443) ipt -A "$CHAIN" ! -i pcmesh -p tcp --dport 443 -m addrtype --dst-type LOCAL -j DROP ;;
      dropmesh:*) ipt -A "$CHAIN" ! -i pcmesh ! -s "${spec#dropmesh:}" -p udp --dport 51830 -j DROP ;;
      natmesh:*)
        iptables -w -t mangle -N "$MCHAIN" 2>/dev/null || true
        iptables -w -t mangle -A "$MCHAIN" ! -i pcmesh ! -s "${spec#natmesh:}" -p udp --dport 51830 -m conntrack --ctstate NEW -j DROP
        iptables -w -t mangle -C PREROUTING -j "$MCHAIN" 2>/dev/null || iptables -w -t mangle -I PREROUTING 1 -j "$MCHAIN" ;;
      *) echo "e2e-ha-host: unknown fault $spec" >&2; exit 2 ;;
    esac
  done
  ipt -I PREROUTING 1 -j "$CHAIN"
  ipt -I OUTPUT 1 -j "$CHAIN"
}

net_apply() {
  net_flush
  [ -s "$ETC/net" ] || return 0
  # shellcheck disable=SC2046  # one fault per word
  net_rules $(cat "$ETC/net")
}

disk_up() {
  mkdir -p "$(dirname "$IMG")" "$MNT"
  local fresh="" loop n
  if [ ! -f "$IMG" ]; then truncate -s "${SIZE_G}G" "$IMG"; fresh=1; fi
  if ! dmsetup info "$DM" >/dev/null 2>&1; then
    loop="$(losetup -j "$IMG" | cut -d: -f1 | head -1)"
    [ -n "$loop" ] || loop="$(losetup -f --show "$IMG")"
    n="$(blockdev --getsz "$loop")"
    dmsetup create "$DM" --table "0 $n linear $loop 0"
  fi
  if [ -n "$fresh" ]; then mkfs.ext4 -q -F -L e2e-lh "/dev/mapper/$DM"; else e2fsck -p "/dev/mapper/$DM" >/dev/null 2>&1 || e2fsck -y "/dev/mapper/$DM" >/dev/null 2>&1 || true; fi
  mountpoint -q "$MNT" || mount -o errors=remount-ro "/dev/mapper/$DM" "$MNT"
}

disk_kill() {
  local n
  n="$(dmsetup table "$DM" | awk '{print $2}')"
  dmsetup suspend --noflush "$DM"
  dmsetup load "$DM" --table "0 $n error"
  dmsetup resume "$DM"
}

disk_state() {
  if ! dmsetup info "$DM" >/dev/null 2>&1; then echo none; return; fi
  dmsetup table "$DM" | awk '{print $3}'
}

state() {
  local boot dark=false net="" disk
  boot="$(cat /proc/sys/kernel/random/boot_id)"
  [ ! -e "$ETC/dark" ] || dark=true
  [ ! -s "$ETC/net" ] || net="$(tr '\n' ' ' < "$ETC/net" | sed 's/ $//')"
  disk="$(disk_state)"
  printf '{"boot_id":"%s","dark":%s,"net":"%s","disk":"%s","live_rules":%s}\n' "$boot" "$dark" "$net" "$disk" \
    "$(( $(ipt -S "$CHAIN" 2>/dev/null | grep -c -- '-A ' || true) + $(iptables -w -t mangle -S "$MCHAIN" 2>/dev/null | grep -c -- '-A ' || true) ))"
}

install_self() {
  install -m 0755 "$0" /usr/local/sbin/e2e-ha-host
  mkdir -p "$ETC"
  cat > /etc/systemd/system/e2e-ha-net.service <<'EOF'
[Unit]
Description=e2e-ha-vm harness: the saved network faults (test VMs only)
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target k3s.service k3s-agent.service portcullis-nodeagent.service wg-quick@pcmesh.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/e2e-ha-host net apply

[Install]
WantedBy=multi-user.target
EOF
  local u
  for u in $UNITS; do
    mkdir -p "/etc/systemd/system/$u.d"
    printf '[Unit]\n# e2e-ha-vm harness: a powered-off node runs nothing\nConditionPathExists=!%s/dark\n' "$ETC" > "/etc/systemd/system/$u.d/90-e2e-ha-dark.conf"
  done
  if [ "${1:-}" = disk ]; then
    cat > /etc/systemd/system/e2e-ha-disk.service <<'EOF'
[Unit]
Description=e2e-ha-vm harness: the Longhorn test disk (test VMs only)
After=local-fs.target
Before=k3s.service k3s-agent.service iscsid.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/e2e-ha-host disk up

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now e2e-ha-disk.service >/dev/null 2>&1
  fi
  systemctl daemon-reload
  systemctl enable e2e-ha-net.service >/dev/null 2>&1
}

case "${1:-}" in
  install) install_self "${2:-}" ;;
  disk)
    case "${2:-}" in
      up) disk_up ;;
      kill) disk_kill ;;
      state) disk_state ;;
      *) echo "usage: disk up|kill|state" >&2; exit 2 ;;
    esac ;;
  fill)
    free=$(( $(stat -f -c '%a * %S' "$MNT") - 1048576 ))
    [ "$free" -gt 0 ] && fallocate -l "$free" "$MNT/e2e-fill" ;;
  unfill) rm -f "$MNT/e2e-fill" ;;
  net)
    case "${2:-}" in
      set) shift 2; mkdir -p "$ETC"; printf '%s\n' "$@" > "$ETC/net"; sync; net_apply ;;
      clear) rm -f "$ETC/net"; sync; net_flush ;;
      apply) net_apply ;;
      *) echo "usage: net set <fault>...|clear|apply" >&2; exit 2 ;;
    esac ;;
  dark)
    mkdir -p "$ETC"; : > "$ETC/dark"; printf 'partition\n' > "$ETC/net"; sync
    echo b > /proc/sysrq-trigger ;;
  light)
    rm -f "$ETC/dark" "$ETC/net"; sync; net_flush
    for u in $UNITS; do
      if systemctl cat "$u" >/dev/null 2>&1 && systemctl is-enabled "$u" >/dev/null 2>&1; then systemctl start --no-block "$u"; fi
    done ;;
  state) state ;;
  *) sed -n '2,40p' "$0"; exit 2 ;;
esac
