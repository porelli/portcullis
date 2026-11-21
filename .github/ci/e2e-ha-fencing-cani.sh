#!/usr/bin/env bash
# e2e-ha-fencing-cani.sh <kube context> — the fencing identities' rights,
# live (plan Task 24 security ruling; e2e-ha-vm, Task 33, runs it after
# ha_install_fencing): SNR's agent (every node) reads no Secret but its
# peers' certificate by name and writes no Node but through
# portcullis-node-labels; SNR's manager writes no Secret outside
# portcullis-fencing; NHC creates no ClusterRole; Longhorn reads no Secret
# outside longhorn-system; cert-manager none outside cnpg-system /
# cert-manager. `kubectl auth can-i --as` (impersonation: no token).
set -euo pipefail
ctx="${1:?usage: e2e-ha-fencing-cani.sh <kube context>}"
fail=0
want() { # want yes|no <as> <can-i args…>
  local w="$1" as="$2" got
  shift 2
  got="$(kubectl --context "$ctx" auth can-i --as="system:serviceaccount:$as" "$@" 2>/dev/null || true)"
  if [ "$got" = "$w" ]; then echo "ok   - $as $* → $w"; else echo "FAIL - $as $* → $got (want $w)"; fail=1; fi
}
A=portcullis-fencing:self-node-remediation-agent
want no "$A" list secrets -A
want no "$A" get secrets -n portcullis
want no "$A" get secrets/fencing-webhook-cert -n portcullis-fencing
want yes "$A" get secrets/self-node-remediation-certificates -n portcullis-fencing
want no "$A" create nodes
want no "$A" delete nodes
want no "$A" patch nodes
M=portcullis-fencing:self-node-remediation-controller-manager
want no "$M" create secrets -n portcullis
want no "$M" delete nodes
want no "$M" delete pods -n portcullis
N=portcullis-fencing:node-healthcheck-controller-manager
want no "$N" create clusterroles
want no "$N" create namespaces
want no "$N" get secrets -n portcullis
L=longhorn-system:longhorn-service-account
want no "$L" get secrets -n portcullis
want no "$L" list secrets -A
want no "$L" create clusterroles
want no "$L" patch nodes
C=cert-manager:cert-manager
want no "$C" get secrets -n portcullis
want yes "$C" create secrets -n cnpg-system
exit "$fail"
