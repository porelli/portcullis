#!/usr/bin/env bash
# e2e-ha-vm chaos (ci.yml job e2e-ha-vm): Playwright and tests/e2e/e2e_ha_vm.py
# (the physical drills) against the VMs installed by e2e-ha-vm-setup.sh. Runs
# on the CI runner (a container on the builder); kubectl reaches the cluster
# over an SSH tunnel the runner opens.
#
#   scenarios   tests/e2e/e2e_ha_vm.py (E2E_SCENARIOS picks a subset)
#   collect     failure artifacts (over SSH to vm1): nodes, pods, events,
#               the front-door status, the e2e results; never .env or secrets
set -euo pipefail
cd "$(dirname "$0")/../.."
D="${E2E_HA_VM_DIR:?}"
ART="${E2E_ARTIFACTS:-e2e-artifacts}"
redact() { sed -u -E 's#(https?://[^ ]*/invite/)[A-Za-z0-9_-]+#\1<redacted>#g; s#pcj[0-9]\.[A-Za-z0-9_-]{16,}#<join code>#g'; }
kv() { ssh -F "$D/ssh_config" vm1 "$@"; }

case "${1:-}" in
scenarios)
  # Unbuffered and line-by-line through the redaction: the log's own times
  # are the drills' (run 3's lines all carried the step's end time).
  NODE_EXTRA_CA_CERTS="$D/core-root.crt" PYTHONUNBUFFERED=1 "${E2E_PY:-/tmp/e2e-venv/bin/python}" -u tests/e2e/e2e_ha_vm.py 2>&1 | redact
  ;;
collect)
  mkdir -p "$ART"
  kv 'sudo k3s kubectl get nodes -o wide' > "$ART/vm-nodes.txt" 2>&1 || true
  kv 'sudo k3s kubectl get pods -A -o wide' > "$ART/vm-pods.txt" 2>&1 || true
  kv 'sudo k3s kubectl get events -A --sort-by=.lastTimestamp' > "$ART/vm-events.txt" 2>&1 || true
  kv 'sudo k3s kubectl -n portcullis get cm frontdoor-status -o jsonpath="{.data.status\.json}"' > "$ART/vm-frontdoor-status.json" 2>&1 || true
  kv 'sudo k3s kubectl get volumes.longhorn.io -A -o wide 2>/dev/null' > "$ART/vm-longhorn.txt" 2>&1 || true
  kv 'sudo k3s kubectl get pods -A -o json 2>/dev/null' | jq -r '.items[]? | select(.status.phase != "Running" and .status.phase != "Succeeded") | "\(.metadata.namespace) \(.metadata.name)"' 2>/dev/null \
    | while read -r ns p; do kv "sudo k3s kubectl -n $ns describe pod $p" >> "$ART/vm-pending.txt" 2>&1 || true; done
  # The components' own logs (run 3's triage lacked them): the last 400
  # lines of each pod (every container), never .env or a Secret.
  for spec in portcullis:hub portcullis:frontdoor portcullis:keycloak portcullis:group-gate portcullis:forward-auth \
              portcullis-nodeadm:nodeadm portcullis-ingress:traefik longhorn-system:longhorn-manager portcullis-fencing:self-node-remediation; do
    ns="${spec%%:*}" app="${spec#*:}"
    for p in $(kv "sudo k3s kubectl -n $ns get pods -o name 2>/dev/null" | grep -- "/$app" || true); do
      kv "sudo k3s kubectl -n $ns logs $p --all-containers --tail=400" > "$ART/vm-log-$ns-${p#pod/}.log" 2>&1 || true
    done
  done
  for h in vm1 vm2 vm3 vm4; do ssh -F "$D/ssh_config" -o ConnectTimeout=10 "$h" 'sudo e2e-ha-host state 2>/dev/null; sudo journalctl -u k3s -u k3s-agent --no-pager --since "30 min ago" 2>/dev/null | grep -E "fatal|newer than datastore|different token" | tail -20' > "$ART/vm-host-$h.txt" 2>&1 || true; done
  # Never a setup link or join code in an artifact.
  { grep -rlE '/invite/[A-Za-z0-9_-]{16,}|pcj[0-9]\.[A-Za-z0-9_-]{16,}' "$ART" 2>/dev/null || true; } | xargs -r sed -i -E 's#(/invite/)[A-Za-z0-9_-]+#\1<redacted>#g; s#pcj[0-9]\.[A-Za-z0-9_-]{16,}#<join code>#g'
  ;;
*) echo "usage: $0 scenarios|collect" >&2; exit 2 ;;
esac
