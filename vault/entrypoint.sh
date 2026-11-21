#!/bin/sh
#
# Portcullis Vault entrypoint (mounted read-only at /vault/portcullis/).
#
# Starts Vault in server mode with vault/vault.hcl.tmpl (rendered into
# /tmp/vault.hcl; `entrypoint.sh render` prints it and exits) and then unseals it
# automatically, on EVERY container start (docker compose up, restart,
# host reboot), using the unseal key that ./portcullis vault init wrote to
# ./secrets/vault-unseal/unseal-key (mounted read-only at /vault/unseal/).
#
# The unseal loop only acts while Vault reports "sealed"; once unsealed it
# exits, so a deliberate `vault operator seal` stays sealed until the next
# container restart. If the key file is absent (Vault not initialised yet)
# it just waits — ./portcullis vault init unseals directly after `init`.
#
# Trade-off (documented in docs/certificates.md): keeping the unseal key on
# the same host as the encrypted data means anyone with root on the host
# (or read access to ./secrets/) can unseal Vault. It protects against
# stolen volume backups without secrets/, not against host compromise.
# Remove the mount and unseal manually if you need that stronger property.

KEY_FILE="${PORTCULLIS_UNSEAL_KEY_FILE:-/vault/unseal/unseal-key}"
TEMPLATE="${PORTCULLIS_VAULT_TEMPLATE:-/vault/portcullis/vault.hcl.tmpl}"
CONFIG_FILE="${PORTCULLIS_VAULT_CONFIG:-/tmp/vault.hcl}"
DATA_DIR="${PORTCULLIS_VAULT_DATA:-/vault/file}"
export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"

log() { echo "portcullis-vault: $*" >&2; }

# render — vault.hcl.tmpl with its placeholders filled (see the template's
# header) on stdout. Every value is checked first, so nothing a variable
# holds can add HCL: a bad one exits 1.
#   VAULT_RAFT_NODE_ID  raft node id (default portcullis-vault-1: compose's
#                       single node; on Kubernetes the pod name)
#   VAULT_API_ADDR / VAULT_CLUSTER_ADDR  http://<host>:<port> (default
#                       http://vault:8200 / :8201)
#   VAULT_RAFT_PEERS    the voters' host names, space separated; this node
#                       (its node id, alone or as the first label) left out;
#                       joined over https only, so it needs VAULT_JOIN_TLS_DIR
#   VAULT_JOIN_TLS_DIR  ca.crt / tls.crt / tls.key: the join listener (:8202)
#                       and the CA retry_join trusts
render() {
  node_id="${VAULT_RAFT_NODE_ID:-portcullis-vault-1}"
  api_addr="${VAULT_API_ADDR:-http://vault:8200}"
  cluster_addr="${VAULT_CLUSTER_ADDR:-http://vault:8201}"
  printf '%s\n' "$node_id" | grep -Eqx '[a-z0-9][a-z0-9-]{0,62}' || { log "VAULT_RAFT_NODE_ID $node_id: [a-z0-9-] only"; return 1; }
  for a in "$api_addr" "$cluster_addr"; do
    printf '%s\n' "$a" | grep -Eqx 'http://[a-z0-9][a-z0-9.-]{0,252}:[0-9]{1,5}' || { log "address $a: http://<host>:<port> only"; return 1; }
  done
  tls="${VAULT_JOIN_TLS_DIR:-}" jl=""
  if [ -n "$tls" ]; then
    printf '%s\n' "$tls" | grep -Eqx '/[a-z0-9/_-]{1,100}' || { log "VAULT_JOIN_TLS_DIR $tls: an absolute path only"; return 1; }
    for f in ca.crt tls.crt tls.key; do [ -r "$tls/$f" ] || { log "no $tls/$f: the join listener needs it"; return 1; }; done
    jl="
# The peers' retry_join (https only): the CLI's private join CA.
listener \"tcp\" {
  address       = \"0.0.0.0:8202\"
  tls_cert_file = \"$tls/tls.crt\"
  tls_key_file  = \"$tls/tls.key\"
  tls_min_version = \"tls12\"
}
"
  fi
  joins=""
  for p in ${VAULT_RAFT_PEERS:-}; do
    printf '%s\n' "$p" | grep -Eqx '[a-z0-9][a-z0-9.-]{0,252}' || { log "VAULT_RAFT_PEERS entry $p: a host name only"; return 1; }
    case "$p" in "$node_id" | "$node_id".*) continue ;; esac
    [ -n "$jl" ] || { log "VAULT_RAFT_PEERS without VAULT_JOIN_TLS_DIR: retry_join runs over https only"; return 1; }
    joins="$joins  retry_join {
    leader_api_addr     = \"https://$p:8202\"
    leader_ca_cert_file = \"$tls/ca.crt\"
  }
"
  done
  [ -r "$TEMPLATE" ] || { log "no template at $TEMPLATE"; return 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      @RETRY_JOIN@) printf '%s' "$joins" ;;
      @JOIN_LISTENER@) printf '%s' "$jl" ;;
      *) printf '%s\n' "$line" | sed -e "s|@NODE_ID@|$node_id|g" -e "s|@API_ADDR@|$api_addr|g" -e "s|@CLUSTER_ADDR@|$cluster_addr|g" ;;
    esac
  done < "$TEMPLATE"
}

if [ "${1:-}" = render ]; then
  render
  exit
fi
render > "$CONFIG_FILE.tmp" && mv -f "$CONFIG_FILE.tmp" "$CONFIG_FILE" || { log "could not render $CONFIG_FILE"; exit 1; }

# Raft needs a data dir owned by the vault user. The image runs as that
# user (non-root) and the vault_data volume is mounted at /vault/file, which
# the image creates vault-owned, so nothing to do. Only when the container is
# started as root (e.g. a compose override with user: root) fix ownership.
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
            log "sealed and no unseal key at $KEY_FILE - waiting for ./portcullis vault init"
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
