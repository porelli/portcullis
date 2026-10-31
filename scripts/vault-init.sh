#!/usr/bin/env bash
#
# Portcullis Vault initialisation / unseal / least-privilege setup.
# Idempotent — bootstrap.sh and upgrade.sh run it on every invocation.
#
#   1. Starts the vault container if it is not running.
#   2. If Vault is uninitialised: `vault operator init` with ONE key share
#      and threshold 1, saving the output to secrets/vault-init.json (0600)
#      and the unseal key to secrets/vault-unseal/unseal-key (0600, mounted
#      read-only into the vault container for auto-unseal on every start).
#   3. Unseals Vault if it is sealed.
#   4. Enables AppRole, writes the `portcullis-enroll` policy
#      (vault/policies/enroll.hcl) and role, and stores the enroll
#      role-id / secret-id in secrets/enroll/ (mounted read-only into enroll).
#
# Usage:
#   ./scripts/vault-init.sh
#   ./scripts/vault-init.sh --rotate-enroll-secret   # issue a new enroll secret-id
#
# Single key share trade-off: Shamir splitting only helps if the shares are
# held by different people/places. Portcullis auto-unseals from a key file
# on the same host, so multiple shares on one disk would add complexity
# without adding security. The protection you get: a copy of the vault_data
# volume alone (e.g. a leaked volume backup) is useless without secrets/.
# Keep an OFFLINE copy of secrets/vault-init.json — losing it together with
# the host means losing the CA.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"
# shellcheck source=lib/vault-common.sh
source "$SCRIPT_DIR/lib/vault-common.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'
info()  { echo -e "${BLUE}==>${NC} $*"; }
ok()    { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}==>${NC} $*"; }
fail()  { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }

ROTATE_ENROLL_SECRET=false
for arg in "$@"; do
  case "$arg" in
    --rotate-enroll-secret) ROTATE_ENROLL_SECRET=true ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) fail "unknown argument: $arg" ;;
  esac
done

command -v docker >/dev/null || fail "docker is required"
command -v jq >/dev/null || fail "jq is required"
command -v curl >/dev/null || fail "curl is required"

# These paths are bind-mounted by docker-compose.yml — keep them in sync.
SECRETS_DIR="$PROJECT_DIR/secrets"
INIT_FILE="$SECRETS_DIR/vault-init.json"
UNSEAL_DIR="$SECRETS_DIR/vault-unseal"
UNSEAL_FILE="$UNSEAL_DIR/unseal-key"
ENROLL_DIR="$SECRETS_DIR/enroll"
POLICY_FILE="$PROJECT_DIR/vault/policies/enroll.hcl"
ENROLL_ROLE="portcullis-enroll"
ENROLL_POLICY="portcullis-enroll"

# Run the vault CLI inside the container (no host CLI needed). VAULT_TOKEN
# is forwarded by name only, so the token never appears in a process list.
vexec() { docker compose exec -T -e VAULT_TOKEN vault vault "$@"; }

# write_secret <file> <value> — atomic, 0600, no trailing newline.
write_secret() {
  local file="$1" value="$2" tmp
  tmp="$(mktemp "${file}.XXXXXX")"
  printf '%s' "$value" > "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$file"
}

# ── 1. secrets/ layout ─────────────────────────────────────

umask 077
for d in "$SECRETS_DIR" "$UNSEAL_DIR" "$ENROLL_DIR"; do
  mkdir -p "$d"
  chmod 700 "$d" 2>/dev/null || true
  [ -w "$d" ] || fail "$d is not writable (created by Docker as root?). Fix with: sudo chown -R \"$(id -un)\" \"$SECRETS_DIR\""
done

# ── 2. vault container + API ───────────────────────────────

if [ -z "$(docker compose ps -q --status running vault 2>/dev/null)" ]; then
  info "Starting vault container..."
  docker compose up -d --no-deps vault
fi

info "Waiting for the Vault API..."
STATUS_JSON=""
for i in $(seq 1 60); do
  rc=0
  STATUS_JSON="$(vexec status -format=json 2>/dev/null)" || rc=$?
  # vault status: 0 = unsealed, 2 = sealed (incl. uninitialised), 1 = error
  if { [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; } && printf '%s' "$STATUS_JSON" | jq -e 'has("initialized")' >/dev/null 2>&1; then
    break
  fi
  if [ "$i" -eq 60 ]; then
    docker compose logs --tail=30 vault >&2 || true
    fail "Vault API did not come up. See the logs above."
  fi
  sleep 2
done

STORAGE="$(printf '%s' "$STATUS_JSON" | jq -r '.storage_type // empty')"
if [ "$STORAGE" = "inmem" ]; then
  fail "Vault is running in DEV mode (in-memory storage). This compose file no longer uses dev mode — run ./scripts/upgrade.sh --migrate-vault (see its help)."
fi
INITIALIZED="$(printf '%s' "$STATUS_JSON" | jq -r '.initialized')"
SEALED="$(printf '%s' "$STATUS_JSON" | jq -r '.sealed')"

# ── 3. init ────────────────────────────────────────────────

if [ "$INITIALIZED" != "true" ]; then
  if [ -e "$INIT_FILE" ]; then
    STALE="$INIT_FILE.stale-$(date +%Y%m%d-%H%M%S)"
    warn "Vault is uninitialised but $INIT_FILE exists (from an older/wiped Vault)."
    warn "Moving it to $STALE — it cannot unseal the new Vault."
    mv "$INIT_FILE" "$STALE"
  fi
  info "Initialising Vault (1 key share, threshold 1)..."
  # Redirect target is created BEFORE init runs: if secrets/ were not
  # writable we would fail here, not lose the only copy of the keys.
  vexec operator init -key-shares=1 -key-threshold=1 -format=json > "$INIT_FILE.tmp"
  chmod 600 "$INIT_FILE.tmp"
  if ! jq -e '.root_token and (.unseal_keys_b64 | length == 1)' "$INIT_FILE.tmp" >/dev/null 2>&1; then
    fail "Unexpected 'vault operator init' output kept in $INIT_FILE.tmp — inspect it manually, it may hold the only copy of the keys."
  fi
  mv -f "$INIT_FILE.tmp" "$INIT_FILE"
  write_secret "$UNSEAL_FILE" "$(jq -r '.unseal_keys_b64[0]' "$INIT_FILE")"
  SEALED=true
  ok "Vault initialised. Root token + unseal key saved to $INIT_FILE"
  echo ""
  warn "BACK UP $INIT_FILE OFFLINE (password manager / safe)."
  warn "Without it the CA in Vault cannot be unsealed after the host is lost."
  echo ""
else
  [ -s "$INIT_FILE" ] || [ -n "${VAULT_TOKEN:-}" ] || \
    fail "Vault is initialised but $INIT_FILE is missing. Restore secrets/ from a backup (or export VAULT_TOKEN and put the unseal key in $UNSEAL_FILE)."
  if [ ! -s "$UNSEAL_FILE" ] && [ -s "$INIT_FILE" ]; then
    info "Recreating $UNSEAL_FILE from $INIT_FILE..."
    write_secret "$UNSEAL_FILE" "$(jq -r '.unseal_keys_b64[0]' "$INIT_FILE")"
  fi
fi

# ── 4. unseal ──────────────────────────────────────────────

if [ "$SEALED" = "true" ]; then
  [ -s "$UNSEAL_FILE" ] || fail "Vault is sealed and $UNSEAL_FILE is missing."
  info "Unsealing Vault..."
  vexec write -format=json sys/unseal key=- < "$UNSEAL_FILE" >/dev/null \
    || fail "Unseal failed — does $UNSEAL_FILE belong to this Vault's data?"
fi
# Unsealed is not enough: wait for the raft node to become the active
# leader, otherwise the writes below can fail with 500.
vault_wait_active 60 || fail "Vault is unsealed but did not become active. Check: docker compose logs vault"
ok "Vault is unsealed and active."

# ── 5. least-privilege AppRole for enroll ──────────────────

vault_admin_env >/dev/null || fail "no admin token available"

AUTH_LIST="$(vexec auth list -format=json)" || fail "could not list Vault auth methods"
if ! printf '%s' "$AUTH_LIST" | jq -e 'has("approle/")' >/dev/null; then
  info "Enabling AppRole auth..."
  vexec auth enable approle >/dev/null
fi

info "Writing policy $ENROLL_POLICY..."
vexec policy write "$ENROLL_POLICY" - < "$POLICY_FILE" >/dev/null

# Short-lived tokens; enroll logs in again (AppRole) before they expire, so
# nothing can "silently expire". The secret-id itself does not expire.
vexec write "auth/approle/role/$ENROLL_ROLE" \
  token_policies="$ENROLL_POLICY" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=0 \
  secret_id_num_uses=0 >/dev/null

ROLE_ID="$(vexec read -field=role_id "auth/approle/role/$ENROLL_ROLE/role-id")"
write_secret "$ENROLL_DIR/role-id" "$ROLE_ID"

NEED_SECRET=$ROTATE_ENROLL_SECRET
if [ ! -s "$ENROLL_DIR/secret-id" ]; then
  NEED_SECRET=true
elif ! vexec write -format=json "auth/approle/role/$ENROLL_ROLE/secret-id/lookup" secret_id=- \
      < "$ENROLL_DIR/secret-id" 2>/dev/null | jq -e '.data.secret_id_accessor' >/dev/null 2>&1; then
  warn "Stored enroll secret-id is not valid for this Vault — issuing a new one."
  NEED_SECRET=true
fi
if [ "$NEED_SECRET" = true ]; then
  OLD_ACCESSORS="$(vexec list -format=json "auth/approle/role/$ENROLL_ROLE/secret-id" 2>/dev/null | jq -r '.[]' 2>/dev/null || true)"
  SECRET_ID="$(vexec write -f -field=secret_id "auth/approle/role/$ENROLL_ROLE/secret-id")"
  write_secret "$ENROLL_DIR/secret-id" "$SECRET_ID"
  # Revoke previous secret-ids so a leaked old one stops working.
  for acc in $OLD_ACCESSORS; do
    vexec write "auth/approle/role/$ENROLL_ROLE/secret-id-accessor/destroy" secret_id_accessor="$acc" >/dev/null 2>&1 || true
  done
  ok "Issued enroll AppRole secret-id ($ENROLL_DIR/secret-id). enroll picks it up on its next login."
else
  ok "Enroll AppRole credentials are valid."
fi

ok "Vault ready (server mode, raft storage, auto-unseal on container start)."
