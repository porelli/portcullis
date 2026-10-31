# shellcheck shell=bash
#
# Vault helpers and `portcullis vault init|unseal|rotate-enroll-secret`.
#
# Vault runs in server mode (raft storage). `portcullis vault init` writes
# the init material to secrets/ on the host (outside git, dir 0700, files 0600):
#   secrets/vault-init.json         root token + unseal key (vault operator init output)
#   secrets/vault-unseal/unseal-key unseal key only (mounted read-only into vault)
#   secrets/enroll/role-id          AppRole credentials for the enrollment UI
#   secrets/enroll/secret-id        (mounted read-only into enroll)
#
# Single key share trade-off: Shamir splitting only helps if the shares are
# held by different people/places. Portcullis auto-unseals from a key file
# on the same host, so multiple shares on one disk would add complexity
# without adding security. What it protects: a copy of the vault_data volume
# alone (e.g. a leaked volume backup) is useless without secrets/. Keep an
# OFFLINE copy of secrets/vault-init.json.

PORTCULLIS_SECRETS_DIR="${PORTCULLIS_SECRETS_DIR:-$PORTCULLIS_ROOT/secrets}"
VAULT_INIT_FILE="${VAULT_INIT_FILE:-$PORTCULLIS_SECRETS_DIR/vault-init.json}"
VAULT_UNSEAL_FILE="$PORTCULLIS_SECRETS_DIR/vault-unseal/unseal-key"
VAULT_ENROLL_DIR="$PORTCULLIS_SECRETS_DIR/enroll"
VAULT_ENROLL_ROLE="portcullis-enroll"
VAULT_ENROLL_POLICY_FILE="$PORTCULLIS_ROOT/vault/policies/enroll.hcl"

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
    echo "       Run ./portcullis vault init on the Portcullis host, or export VAULT_TOKEN." >&2
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
  vault() { dc exec -T -e VAULT_TOKEN vault vault "$@"; }
}

# vault_admin — admin token + a `vault` command, or fail.
vault_admin() {
  vault_admin_env || exit 1
  vault_use_container_cli || exit 1
}

# vexec — the vault CLI inside the container (talks to its own listener; no
# host CLI needed). VAULT_TOKEN is forwarded by name only.
vexec() { dc exec -T -e VAULT_TOKEN vault vault "$@"; }

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

# _write_secret <file> <value> — atomic, 0600, no trailing newline.
_write_secret() {
  local file="$1" value="$2" tmp
  tmp="$(mktemp "${file}.XXXXXX")"
  printf '%s' "$value" > "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$file"
}

# _vault_start_and_status — start the container if needed and wait for its
# API; sets VAULT_INITIALIZED / VAULT_SEALED.
_vault_start_and_status() {
  local i rc status=""
  if [ -z "$(dc ps -q --status running vault 2>/dev/null)" ]; then
    info "Starting vault container..."
    dc up -d --no-deps vault
  fi
  info "Waiting for the Vault API..."
  for ((i = 1; i <= 60; i++)); do
    rc=0
    status="$(vexec status -format=json 2>/dev/null)" || rc=$?
    # vault status: 0 = unsealed, 2 = sealed (incl. uninitialised), 1 = error
    if { [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; } && printf '%s' "$status" | jq -e 'has("initialized")' >/dev/null 2>&1; then
      break
    fi
    if [ "$i" -eq 60 ]; then
      dc logs --tail=30 vault >&2 || true
      fail "Vault API did not come up. See the logs above."
    fi
    sleep 2
  done
  VAULT_INITIALIZED="$(printf '%s' "$status" | jq -r '.initialized')"
  VAULT_SEALED="$(printf '%s' "$status" | jq -r '.sealed')"
}

# _vault_unseal_if_sealed — then wait for the raft node to become active.
_vault_unseal_if_sealed() {
  if [ "$VAULT_SEALED" = "true" ]; then
    [ -s "$VAULT_UNSEAL_FILE" ] || fail "Vault is sealed and $VAULT_UNSEAL_FILE is missing."
    info "Unsealing Vault..."
    vexec write -format=json sys/unseal key=- < "$VAULT_UNSEAL_FILE" >/dev/null \
      || fail "Unseal failed — does $VAULT_UNSEAL_FILE belong to this Vault's data?"
  fi
  vault_wait_active 60 || fail "Vault is unsealed but did not become active. Check: docker compose logs vault"
  ok "Vault is unsealed and active."
}

# vault_init [rotate=false] — idempotent: init (1 share) if needed, unseal,
# AppRole + policy for enroll, enroll role-id/secret-id in secrets/enroll/.
vault_init() {
  local rotate="${1:-false}" stale role_id need_secret old_accessors secret_id acc old_umask
  require_cmd docker jq curl
  stack_prepare
  # Owner-only for everything written below; restored at the end so later
  # steps (e.g. the CA bundle containers must read) get normal modes.
  old_umask="$(umask)"
  umask 077
  _vault_start_and_status

  if [ "$VAULT_INITIALIZED" != "true" ]; then
    if [ -e "$VAULT_INIT_FILE" ]; then
      stale="$VAULT_INIT_FILE.stale-$(date +%Y%m%d-%H%M%S)"
      warn "Vault is uninitialised but $VAULT_INIT_FILE exists (from a wiped Vault)."
      warn "Moving it to $stale — it cannot unseal the new Vault."
      mv "$VAULT_INIT_FILE" "$stale"
    fi
    info "Initialising Vault (1 key share, threshold 1)..."
    # Redirect target is created BEFORE init runs: if secrets/ were not
    # writable we would fail here, not lose the only copy of the keys.
    vexec operator init -key-shares=1 -key-threshold=1 -format=json > "$VAULT_INIT_FILE.tmp"
    chmod 600 "$VAULT_INIT_FILE.tmp"
    jq -e '.root_token and (.unseal_keys_b64 | length == 1)' "$VAULT_INIT_FILE.tmp" >/dev/null 2>&1 \
      || fail "Unexpected 'vault operator init' output kept in $VAULT_INIT_FILE.tmp — inspect it manually, it may hold the only copy of the keys."
    mv -f "$VAULT_INIT_FILE.tmp" "$VAULT_INIT_FILE"
    _write_secret "$VAULT_UNSEAL_FILE" "$(jq -r '.unseal_keys_b64[0]' "$VAULT_INIT_FILE")"
    VAULT_SEALED=true
    ok "Vault initialised. Root token + unseal key saved to $VAULT_INIT_FILE"
    warn "BACK UP $VAULT_INIT_FILE OFFLINE (password manager / safe)."
    warn "Without it the CA in Vault cannot be unsealed after the host is lost."
  else
    [ -s "$VAULT_INIT_FILE" ] || [ -n "${VAULT_TOKEN:-}" ] || \
      fail "Vault is initialised but $VAULT_INIT_FILE is missing. Restore secrets/ from a backup (or export VAULT_TOKEN and put the unseal key in $VAULT_UNSEAL_FILE)."
    if [ ! -s "$VAULT_UNSEAL_FILE" ] && [ -s "$VAULT_INIT_FILE" ]; then
      info "Recreating $VAULT_UNSEAL_FILE from $VAULT_INIT_FILE..."
      _write_secret "$VAULT_UNSEAL_FILE" "$(jq -r '.unseal_keys_b64[0]' "$VAULT_INIT_FILE")"
    fi
  fi

  _vault_unseal_if_sealed
  vault_admin_env >/dev/null || fail "no admin token available"

  # ── least-privilege AppRole for enroll ──
  vexec auth list -format=json | jq -e 'has("approle/")' >/dev/null 2>&1 || {
    info "Enabling AppRole auth..."
    vexec auth enable approle >/dev/null
  }
  vexec policy write "$VAULT_ENROLL_ROLE" - < "$VAULT_ENROLL_POLICY_FILE" >/dev/null
  # Short-lived tokens; enroll logs in again (AppRole) before they expire.
  # The secret-id itself does not expire.
  vexec write "auth/approle/role/$VAULT_ENROLL_ROLE" \
    token_policies="$VAULT_ENROLL_ROLE" token_ttl=1h token_max_ttl=4h \
    secret_id_ttl=0 secret_id_num_uses=0 >/dev/null

  role_id="$(vexec read -field=role_id "auth/approle/role/$VAULT_ENROLL_ROLE/role-id")"
  _write_secret "$VAULT_ENROLL_DIR/role-id" "$role_id"

  need_secret="$rotate"
  if [ ! -s "$VAULT_ENROLL_DIR/secret-id" ]; then
    need_secret=true
  elif ! vexec write -format=json "auth/approle/role/$VAULT_ENROLL_ROLE/secret-id/lookup" secret_id=- \
      < "$VAULT_ENROLL_DIR/secret-id" 2>/dev/null | jq -e '.data.secret_id_accessor' >/dev/null 2>&1; then
    warn "Stored enroll secret-id is not valid for this Vault — issuing a new one."
    need_secret=true
  fi
  if [ "$need_secret" = true ]; then
    old_accessors="$(vexec list -format=json "auth/approle/role/$VAULT_ENROLL_ROLE/secret-id" 2>/dev/null | jq -r '.[]' 2>/dev/null || true)"
    secret_id="$(vexec write -f -field=secret_id "auth/approle/role/$VAULT_ENROLL_ROLE/secret-id")"
    _write_secret "$VAULT_ENROLL_DIR/secret-id" "$secret_id"
    # Revoke previous secret-ids so a leaked old one stops working.
    for acc in $old_accessors; do
      vexec write "auth/approle/role/$VAULT_ENROLL_ROLE/secret-id-accessor/destroy" secret_id_accessor="$acc" >/dev/null 2>&1 || true
    done
    ok "Issued enroll AppRole secret-id ($VAULT_ENROLL_DIR/secret-id). enroll picks it up on its next login."
  else
    ok "Enroll AppRole credentials are valid."
  fi
  umask "$old_umask"
  ok "Vault ready (server mode, raft storage, auto-unseal on container start)."
}

help_vault() {
  cat <<'EOF'
Usage: portcullis vault <subcommand>

  init                    Initialise (1 key share), unseal, and set up the enroll AppRole
  unseal                  Unseal Vault if sealed and wait until it is active
  rotate-enroll-secret    Issue a new enroll AppRole secret-id, revoke the old ones

Run 'portcullis vault <subcommand> --help' for details.
EOF
}

help_vault_init() {
  cat <<'EOF'
Usage: portcullis vault init

Idempotent; run by `portcullis init`, `upgrade` and `restore`.
  1. Starts the vault container if it is not running.
  2. If Vault is uninitialised: `vault operator init` with ONE key share,
     saving the output to secrets/vault-init.json (0600) and the unseal key
     to secrets/vault-unseal/unseal-key (mounted read-only into vault, which
     auto-unseals on every start).
  3. Unseals Vault if it is sealed and waits until the raft node is active.
  4. Enables AppRole, writes the portcullis-enroll policy
     (vault/policies/enroll.hcl) and role, and stores the enroll role-id /
     secret-id in secrets/enroll/ (mounted read-only into enroll).

Keep an OFFLINE copy of secrets/vault-init.json: losing it together with
the host means losing the CA.
EOF
}

help_vault_unseal() {
  cat <<'EOF'
Usage: portcullis vault unseal

Unseal Vault with secrets/vault-unseal/unseal-key if it is sealed (Vault
normally does this itself on every container start), then wait until it is
the active raft node. Exits non-zero if Vault does not become active.
EOF
}

help_vault_rotate_enroll_secret() {
  cat <<'EOF'
Usage: portcullis vault rotate-enroll-secret

Same as `portcullis vault init`, but always issues a new enroll AppRole
secret-id (secrets/enroll/secret-id) and destroys every previous one.
The enroll service picks it up on its next login.
EOF
}

cmd_vault() {
  local sub="${1:-}"
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_vault; [ -n "$sub" ] || exit 2; return 0 ;;
    init|unseal|rotate-enroll-secret) ;;
    *) usage_error vault "unknown subcommand: $sub" ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) "help_vault_${sub//-/_}"; return 0 ;;
      *) usage_error "vault $sub" "unknown argument: $1" ;;
    esac
  done
  need_env
  case "$sub" in
    init) vault_init false ;;
    rotate-enroll-secret) vault_init true ;;
    unseal)
      require_cmd docker jq curl
      _vault_start_and_status
      [ "$VAULT_INITIALIZED" = true ] || fail "Vault is not initialised. Run ./portcullis vault init"
      _vault_unseal_if_sealed
      ;;
  esac
}
