#!/bin/sh
#
# Portcullis Vault entrypoint (mounted read-only at /vault/portcullis/).
#
# Starts Vault in server mode with vault/vault.hcl and then unseals it
# automatically, on EVERY container start (docker compose up, restart,
# host reboot), using the unseal key that scripts/vault-init.sh wrote to
# ./secrets/vault-unseal/unseal-key (mounted read-only at /vault/unseal/).
#
# The unseal loop only acts while Vault reports "sealed"; once unsealed it
# exits, so a deliberate `vault operator seal` stays sealed until the next
# container restart. If the key file is absent (Vault not initialised yet)
# it just waits — scripts/vault-init.sh unseals directly after `init`.
#
# Trade-off (documented in docs/certificates.md): keeping the unseal key on
# the same host as the encrypted data means anyone with root on the host
# (or read access to ./secrets/) can unseal Vault. It protects against
# stolen volume backups without secrets/, not against host compromise.
# Remove the mount and unseal manually if you need that stronger property.

KEY_FILE="${PORTCULLIS_UNSEAL_KEY_FILE:-/vault/unseal/unseal-key}"
CONFIG_FILE="${PORTCULLIS_VAULT_CONFIG:-/vault/portcullis/vault.hcl}"
DATA_DIR="${PORTCULLIS_VAULT_DATA:-/vault/data}"
export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"

log() { echo "portcullis-vault: $*" >&2; }

# Raft needs a data dir owned by the vault user. Named volumes start out
# root-owned, and restore.sh untars as root, so fix ownership every start.
if [ "$(id -u)" = 0 ] && id vault >/dev/null 2>&1; then
  mkdir -p "$DATA_DIR"
  chown -R vault:vault "$DATA_DIR" 2>/dev/null || log "warning: could not chown $DATA_DIR"
fi

auto_unseal() {
  waiting_logged=false
  while :; do
    vault status >/dev/null 2>&1
    rc=$?
    case "$rc" in
      0)
        log "Vault is unsealed."
        return 0
        ;;
      2)
        # Sealed (or not yet initialised).
        if [ -s "$KEY_FILE" ]; then
          if vault write -format=json sys/unseal key=- <"$KEY_FILE" >/dev/null 2>&1; then
            continue
          fi
          log "unseal with $KEY_FILE failed (not initialised yet, or key does not match this data) - retrying in 10s"
          sleep 10
        else
          if [ "$waiting_logged" = false ]; then
            log "sealed and no unseal key at $KEY_FILE - waiting for scripts/vault-init.sh"
            waiting_logged=true
          fi
          sleep 5
        fi
        ;;
      *)
        # Server still starting.
        sleep 2
        ;;
    esac
  done
}

if command -v docker-entrypoint.sh >/dev/null 2>&1; then
  # Official image entrypoint: drops privileges to the vault user.
  # SKIP_SETCAP (set in compose) skips the mlock capability dance.
  docker-entrypoint.sh server -config="$CONFIG_FILE" &
else
  vault server -config="$CONFIG_FILE" &
fi
server_pid=$!

trap 'kill -TERM "$server_pid" 2>/dev/null' TERM INT

auto_unseal &

status=0
wait "$server_pid" || status=$?
# `wait` returns early when the trap fires; keep waiting for the real exit.
while kill -0 "$server_pid" 2>/dev/null; do
  wait "$server_pid" || status=$?
done
exit "$status"
