#!/bin/sh
# vault/serving.sh — the HA Vault voter's readiness and liveness (Task 31
# fix round 2; charts/portcullis/templates/vault.yaml): exit 0 only when
# this voter serves requests — it is the active node itself, or a standby
# whose advertised active node (one of our voters, <pod>.vault-internal)
# confirms on its own sys/leader that it is active (is_self). Anything
# else is "no active Vault behind this voter" and exits 1: sealed or not
# answering, no leader advertised, a leader advertised that isn't active
# (found live: an advertisement left by a dead active node while the
# Raft leader failed its post-unseal with `cannot mount under existing
# mount "sys/"`, Vault v2.2.1, ~50 min with no active node).
#
# sys/leader is unauthenticated and answered locally by every voter
# (Vault v2.2.1 http/handler.go: never forwarded), so the probe needs no
# token, writes nothing and never seals or steps anything down. The
# active node answers is_self from its own state, so it always passes:
# the liveness restart (kubelet, after its grace) only ever hits a voter
# that can't serve, and a restart is what clears that state (the
# entrypoint unseals again). Each call waits 1 s at most (two fit the
# probe's 3 s timeout). VAULT_SERVING_ADDR is the local API (tests).
a="${VAULT_SERVING_ADDR:-http://127.0.0.1:8200}"
l="$(wget -q -T 1 -O - "$a/v1/sys/leader" 2>/dev/null)" || exit 1
case "$l" in *'"is_self":true'*) exit 0 ;; esac
u="$(printf '%s' "$l" | sed -n 's/.*"leader_address":"\([^"]*\)".*/\1/p')"
case "$u" in
  http://vault-[0-9]*.vault-internal:8200) ;;
  *) exit 1 ;;
esac
r="$(wget -q -T 1 -O - "$u/v1/sys/leader" 2>/dev/null)" || exit 1
case "$r" in *'"is_self":true'*) exit 0 ;; esac
exit 1
