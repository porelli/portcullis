#!/usr/bin/env bash
# e2e-k3s "Collect logs and events" (on failure): pods, events, every
# Deployment's logs (and the previous container's), describe of every pod
# not Ready, and the node's state — disks (where Docker and k3s keep their
# data), memory / swap, pressure (PSI), processes stuck in I/O (D state) and
# the k3s journal without the kubelet's cgroup-read noise. Never env values
# or Secrets: describe shows a Secret's name only.
set -u
A=e2e-artifacts
mkdir -p "$A"
K() { kubectl --context ci "$@"; }
for ns in portcullis portcullis-apps portcullis-storage portcullis-edge; do
  K -n "$ns" get pods -o wide > "$A/$ns-pods.txt" 2>&1 || true
  K -n "$ns" get events --sort-by=.lastTimestamp > "$A/$ns-events.txt" 2>&1 || true
  K -n "$ns" get pvc -o wide > "$A/$ns-pvc.txt" 2>&1 || true
  for d in $(K -n "$ns" get deploy -o name 2>/dev/null); do
    K -n "$ns" logs "$d" --all-containers --tail=500 > "$A/$ns-${d#*/}.log" 2>&1 || true
    K -n "$ns" logs "$d" --all-containers --previous --tail=500 > "$A/$ns-${d#*/}.previous.log" 2>/dev/null || rm -f "$A/$ns-${d#*/}.previous.log"
  done
  for p in $(K -n "$ns" get pods -o json 2>/dev/null | jq -r '.items[] | select([.status.conditions[]? | select(.type == "Ready" and .status == "True")] | length == 0) | .metadata.name'); do
    K -n "$ns" describe pod "$p" > "$A/$ns-$p.describe.txt" 2>&1 || true
  done
done
{
  echo "## df"; df -hT 2>&1
  echo "## where the data lives"; findmnt -T /var/lib/docker 2>&1; findmnt -T /var/lib/rancher 2>&1; findmnt -T /var/lib/portcullis-storage 2>&1
  docker info --format 'docker root: {{.DockerRootDir}} driver: {{.Driver}}' 2>&1
  echo "## memory"; free -m 2>&1; swapon --show 2>&1
  for r in cpu io memory; do echo "## pressure $r"; cat "/proc/pressure/$r" 2>&1; done
  echo "## D state"; ps -eo pid,stat,wchan:32,etime,args | awk 'NR == 1 || $2 ~ /^D/' 2>&1
  echo "## top memory"; ps -eo pid,rss,args --sort=-rss | head -n 25
  echo "## node"; K describe node 2>&1 | sed -n '/Conditions:/,/Events:/p'
} > "$A/node.txt" 2>&1
sudo journalctl -u k3s --no-pager 2>/dev/null | grep -v 'failed to read memory cgroup\|failed to read memory.max\|failed to read cpu.max' | tail -n 3000 > "$A/k3s.log" || true
exit 0
