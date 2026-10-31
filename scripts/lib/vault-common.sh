# shellcheck shell=bash
#
# Shared Vault helpers for Portcullis scripts. Source, don't execute:
#   source "$SCRIPT_DIR/lib/vault-common.sh"
#
# Vault runs in server mode (raft storage). scripts/vault-init.sh writes the
# init material to secrets/ on the host (outside git, dir 0700, files 0600):
#   secrets/vault-init.json         root token + unseal key (vault operator init output)
#   secrets/vault-unseal/unseal-key unseal key only (mounted read-only into vault)
#   secrets/enroll/role-id          AppRole credentials for the enrollment UI
#   secrets/enroll/secret-id        (mounted read-only into enroll)

_PORTCULLIS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORTCULLIS_PROJECT_DIR="${PORTCULLIS_PROJECT_DIR:-$(cd "$_PORTCULLIS_LIB_DIR/../.." && pwd)}"
PORTCULLIS_SECRETS_DIR="${PORTCULLIS_SECRETS_DIR:-$PORTCULLIS_PROJECT_DIR/secrets}"
VAULT_INIT_FILE="${VAULT_INIT_FILE:-$PORTCULLIS_SECRETS_DIR/vault-init.json}"

# vault_admin_env — export VAULT_ADDR and an admin VAULT_TOKEN.
# An explicit VAULT_TOKEN in the environment always wins; otherwise the root
# token is read from secrets/vault-init.json. Returns 1 (with a message on
# stderr) if no token can be found. There is deliberately no default token.
vault_admin_env() {
  export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
  if [ -n "${VAULT_TOKEN:-}" ]; then
    export VAULT_TOKEN
    return 0
  fi
  if [ ! -r "$VAULT_INIT_FILE" ]; then
    echo "ERROR: no VAULT_TOKEN set and $VAULT_INIT_FILE is not readable." >&2
    echo "       Run ./scripts/vault-init.sh on the Portcullis host, or export VAULT_TOKEN." >&2
    return 1
  fi
  command -v jq >/dev/null 2>&1 || { echo "ERROR: jq is required" >&2; return 1; }
  VAULT_TOKEN="$(jq -r '.root_token // empty' "$VAULT_INIT_FILE" 2>/dev/null || true)"
  if [ -z "$VAULT_TOKEN" ]; then
    echo "ERROR: $VAULT_INIT_FILE has no root_token." >&2
    return 1
  fi
  export VAULT_TOKEN
}

# vault_container_is_dev — succeed if the running vault container of the
# core project is the old dev-mode server (in-memory storage). Checks the
# container env (VAULT_DEV_ROOT_TOKEN_ID) and Vault's own storage_type.
vault_container_is_dev() {
  local cid
  cid="$(docker compose ps -q vault 2>/dev/null | head -n1)"
  [ -n "$cid" ] || return 1
  if docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$cid" 2>/dev/null \
      | grep -q '^VAULT_DEV_ROOT_TOKEN_ID='; then
    return 0
  fi
  local st
  st="$(curl -s --max-time 5 "${VAULT_ADDR:-http://127.0.0.1:8200}/v1/sys/seal-status" 2>/dev/null || true)"
  [ -n "$st" ] && [ "$(printf '%s' "$st" | jq -r '.storage_type // empty' 2>/dev/null)" = "inmem" ]
}

# vault_use_container_cli — if there is no host `vault` CLI, define a
# `vault` shell function that runs the CLI inside the core vault container.
# VAULT_TOKEN is forwarded by NAME (-e VAULT_TOKEN), so the token never
# appears in a process list; stdin is passed through (-T), so `key=-` /
# `policy write x -` style secret input keeps working. Other arguments
# (CSRs, serials, paths) are visible in `ps` exactly as with a host CLI.
vault_use_container_cli() {
  command -v vault >/dev/null 2>&1 && return 0
  command -v docker >/dev/null 2>&1 || {
    echo "ERROR: neither a host vault CLI nor docker is available" >&2
    return 1
  }
  vault() { docker compose --project-directory "$PORTCULLIS_PROJECT_DIR" exec -T -e VAULT_TOKEN vault vault "$@"; }
}

# vault_health_code — HTTP status of /v1/sys/health:
#   200 active, 429 standby, 472/473 DR/perf standby, 501 not initialised,
#   503 sealed, 000 unreachable.
vault_health_code() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    "${VAULT_ADDR:-http://127.0.0.1:8200}/v1/sys/health" 2>/dev/null || true
}

# vault_wait_active [timeout_seconds] — wait until Vault is initialised,
# unsealed AND the active node (raft leader elected). `vault status` exit 0
# alone is not enough: right after unseal the raft node can still be
# standby/leaderless and writes return 500.
vault_wait_active() {
  local timeout="${1:-60}" i code=""
  for ((i = 0; i < timeout; i++)); do
    code="$(vault_health_code)"
    [ "$code" = 200 ] && return 0
    sleep 1
  done
  echo "ERROR: Vault not active after ${timeout}s (last /v1/sys/health status: ${code:-none};" \
       "429=standby 501=uninitialised 503=sealed 000=unreachable)" >&2
  return 1
}

# write_revoked_serials <file> — atomically rewrite the revoked-serial list
# read by group-gate from Vault's authoritative list (pki_int/certs/revoked).
# Needs an admin VAULT_TOKEN and a `vault` command (host CLI or
# vault_use_container_cli). Fails — leaving <file> untouched — on ANY error
# other than Vault's "nothing to list" (exit 2): an empty list caused by a
# sealed Vault / bad token / network error must never un-revoke certs.
write_revoked_serials() {
  local file="$1" dir out rc=0 serials tmp
  dir="$(dirname "$file")"
  out="$(vault list -format=json pki_int/certs/revoked 2>&1)" || rc=$?
  case "$rc" in
    0)
      serials="$(printf '%s' "$out" | jq -r 'if type == "array" then .[] else error("not an array") end' 2>/dev/null)" || {
        echo "ERROR: unexpected output from 'vault list pki_int/certs/revoked' — $file left unchanged" >&2
        return 1
      }
      ;;
    2)
      # vault CLI: exit 2 = no values at that path (no revoked certs).
      serials=""
      ;;
    *)
      echo "ERROR: 'vault list pki_int/certs/revoked' failed (exit $rc) — $file left unchanged:" >&2
      printf '%s\n' "$out" | sed 's/^/    /' >&2
      return 1
      ;;
  esac
  mkdir -p "$dir" || return 1
  [ -w "$dir" ] || { echo "ERROR: $dir is not writable (fix: sudo chown \"$(id -un)\" \"$dir\")" >&2; return 1; }
  tmp="$(mktemp "$dir/.revoked.XXXXXX")" || return 1
  {
    echo "# Revoked client-cert serials (Vault pki_int). Generated by scripts/revoke-cert.sh"
    echo "# on $(date -u +%Y-%m-%dT%H:%M:%SZ) — do not edit; run: ./scripts/revoke-cert.sh --sync"
    if [ -n "$serials" ]; then printf '%s\n' "$serials"; fi
  } > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$file" || { rm -f "$tmp"; return 1; }
}
