# shellcheck shell=bash
#
# `portcullis backup` / `portcullis restore` — local backups in backups/.
#
# A backup directory (backups/<YYYYmmdd-HHMMSS>/, 0700) contains:
#   .env, realm-export.json, headscale-config.yaml (if present)
#   certs/      CA chain Traefik trusts, server cert/key, revoked-serial list
#   secrets/    Vault root token + UNSEAL KEY + enroll AppRole creds
#   <volume>.tar.gz for each of BACKUP_VOLUMES
# vault_data.tar.gz is only usable with the secrets/ taken at the same time —
# and together they can decrypt the CA: store backups like the keys.
#
# Seam for off-host backups: backup_create leaves the path of the new
# directory in BACKUP_LAST_DIR; a later step can ship it elsewhere.

BACKUP_ROOT="${BACKUP_ROOT:-$PORTCULLIS_ROOT/backups}"
BACKUP_VOLUMES="${BACKUP_VOLUMES:-postgres_data lldap_data vault_data}"
# shellcheck disable=SC2034  # read by callers (upgrade)
BACKUP_LAST_DIR=""

# _volume_name <compose-volume-key> — actual Docker volume name.
_volume_name() {
  dc config --format json 2>/dev/null | jq -r --arg v "$1" '.volumes[$v].name // empty' 2>/dev/null
}

backup_create() {
  local dir vol full vault_stopped=false old_umask
  require_cmd docker jq
  dir="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
  info "Creating backup in $dir..."
  old_umask="$(umask)"
  umask 077
  mkdir -p "$dir"
  chmod 700 "$BACKUP_ROOT" "$dir"
  cp "$(env_file)" "$dir/.env"
  [ -f "$PORTCULLIS_ROOT/keycloak/realm-export.json" ] && cp "$PORTCULLIS_ROOT/keycloak/realm-export.json" "$dir/realm-export.json"
  [ -f "$PORTCULLIS_ROOT/headscale/config.yaml" ] && cp "$PORTCULLIS_ROOT/headscale/config.yaml" "$dir/headscale-config.yaml"
  [ -d "$PORTCULLIS_ROOT/certs" ] && cp -a "$PORTCULLIS_ROOT/certs" "$dir/certs"
  [ -d "$PORTCULLIS_ROOT/secrets" ] && cp -a "$PORTCULLIS_ROOT/secrets" "$dir/secrets"

  # Raft files must not be copied while Vault writes them: stop Vault for
  # the copy (it auto-unseals on start).
  if [ -n "$(dc ps -q --status running vault 2>/dev/null)" ]; then
    dc stop vault >/dev/null 2>&1 && vault_stopped=true
  fi
  for vol in $BACKUP_VOLUMES; do
    full="$(_volume_name "$vol")"
    if [ -n "$full" ] && docker volume inspect "$full" >/dev/null 2>&1; then
      printf '  %s...' "$vol"
      if docker run --rm -v "$full:/data:ro" -v "$dir:/backup" alpine \
          tar czf "/backup/$vol.tar.gz" -C /data . 2>/dev/null; then
        printf ' %sdone%s\n' "$C_GREEN" "$C_NC"
      else
        printf ' %sFAILED%s\n' "$C_RED" "$C_NC"
        [ "$vault_stopped" = false ] || dc start vault >/dev/null 2>&1 || true
        umask "$old_umask"
        fail "could not back up volume $vol"
      fi
    fi
  done
  if [ "$vault_stopped" = true ]; then
    dc start vault >/dev/null 2>&1 || warn "could not restart vault"
    vault_wait_active 60 >/dev/null 2>&1 || warn "Vault did not become active again after the backup — check ./portcullis status"
  fi
  umask "$old_umask"
  # shellcheck disable=SC2034
  BACKUP_LAST_DIR="$dir"
  ok "Backup saved to $dir (contains secrets/ — protect it like the Vault keys)."
}

backup_list() {
  local d any=false
  for d in "$BACKUP_ROOT"/*/; do
    [ -f "$d/.env" ] || continue
    any=true
    printf '  %-28s %6s  %s\n' "$(basename "$d")" "$(du -sh "$d" 2>/dev/null | cut -f1)" \
      "$(cd "$d" && ls -A | paste -sd' ' -)"
  done
  [ "$any" = true ] || echo "No backups in $BACKUP_ROOT"
}

# backup_restore <dir> <assume-yes>
backup_restore() {
  local dir="$1" yes="$2" pre vol full archive vault_image
  require_cmd docker jq
  [ -d "$dir" ] || fail "Backup directory not found: $dir"
  dir="$(cd "$dir" && pwd)"
  [ -f "$dir/.env" ] || fail "No .env in $dir — not a Portcullis backup."
  [ ! -f "$dir/vault_data.tar.gz" ] || [ -d "$dir/secrets" ] \
    || fail "$dir has vault_data.tar.gz but no secrets/ — Vault could not be unsealed. Incomplete backup."

  echo "This will stop Portcullis and replace .env$( [ -d "$dir/certs" ] && echo ", certs/")$( [ -d "$dir/secrets" ] && echo ", secrets/")"
  for archive in "$dir"/*.tar.gz; do
    [ -f "$archive" ] && echo "  and the volume $(basename "$archive" .tar.gz)"
  done
  if [ "$yes" != true ]; then
    confirm "Continue with restore?" || { echo "Cancelled."; return 0; }
  fi

  pre="$BACKUP_ROOT/pre-restore-$(date +%Y%m%d-%H%M%S)"
  info "Saving the current .env, secrets/ and certs/ to $pre..."
  (umask 077 && mkdir -p "$pre" && cp "$(env_file)" "$pre/.env" \
    && { [ ! -d "$PORTCULLIS_ROOT/secrets" ] || cp -a "$PORTCULLIS_ROOT/secrets" "$pre/secrets"; } \
    && { [ ! -d "$PORTCULLIS_ROOT/certs" ] || cp -a "$PORTCULLIS_ROOT/certs" "$pre/certs"; })

  vault_image="$(dc config --format json 2>/dev/null | jq -r '.services.vault.image // empty')"
  info "Stopping services..."
  dc down

  # .env in place (keeps a symlink into config/ and the Hub's bind mount).
  (umask 077 && cat "$dir/.env" > "$(env_file)")
  [ ! -f "$dir/realm-export.json" ] || cp "$dir/realm-export.json" "$PORTCULLIS_ROOT/keycloak/realm-export.json"
  if [ -f "$dir/headscale-config.yaml" ]; then
    mkdir -p "$PORTCULLIS_ROOT/headscale"
    cp "$dir/headscale-config.yaml" "$PORTCULLIS_ROOT/headscale/config.yaml"
  fi
  if [ -d "$dir/certs" ]; then
    rm -rf "$PORTCULLIS_ROOT/certs.restore-tmp" && cp -a "$dir/certs" "$PORTCULLIS_ROOT/certs.restore-tmp"
    rm -rf "$PORTCULLIS_ROOT/certs" && mv "$PORTCULLIS_ROOT/certs.restore-tmp" "$PORTCULLIS_ROOT/certs"
  fi
  if [ -d "$dir/secrets" ]; then
    (umask 077 && rm -rf "$PORTCULLIS_ROOT/secrets.restore-tmp" && cp -a "$dir/secrets" "$PORTCULLIS_ROOT/secrets.restore-tmp")
    rm -rf "$PORTCULLIS_ROOT/secrets" && mv "$PORTCULLIS_ROOT/secrets.restore-tmp" "$PORTCULLIS_ROOT/secrets"
    chmod 700 "$PORTCULLIS_ROOT/secrets"
  fi

  for archive in "$dir"/*.tar.gz; do
    [ -f "$archive" ] || continue
    vol="$(basename "$archive" .tar.gz)"
    full="$(_volume_name "$vol")"
    [ -n "$full" ] || { warn "Volume $vol is not in the compose config — skipped."; continue; }
    info "Restoring volume $vol..."
    docker volume create "$full" >/dev/null
    # tar as root keeps the archived ownership (vault_data must stay owned
    # by the image's non-root vault user).
    docker run --rm -v "$full:/data" -v "$dir:/backup:ro" alpine \
      sh -c "find /data -mindepth 1 -delete && tar xzf '/backup/$vol.tar.gz' -C /data" \
      || fail "could not restore volume $vol"
    if [ "$vol" = vault_data ] && [ -n "$vault_image" ]; then
      docker run --rm --user 0 --entrypoint chown -v "$full:/vault/file" "$vault_image" -R vault:vault /vault/file \
        || warn "could not chown the restored vault_data to the vault user"
    fi
  done

  env_reload
  stack_prepare
  config_build_ca_bundle
  # Vault first: it auto-unseals from secrets/vault-unseal/; vault init
  # verifies that (fails if secrets/ do not match vault_data) and refreshes
  # the enroll AppRole creds.
  vault_init false
  dc up -d
  wait_healthy 180 vault postgres lldap keycloak
  ok "Restore complete. Previous state: $pre — verify with ./portcullis status"
}

help_backup() {
  cat <<'EOF'
Usage: portcullis backup [--list]

Create a local backup in backups/<timestamp>/ (0700): .env, certs/,
secrets/ (Vault root token + unseal key), keycloak/realm-export.json,
headscale/config.yaml and the postgres_data, lldap_data and vault_data
volumes. Vault is stopped for the few seconds the raft copy takes.
The backup can decrypt the CA — protect it like the keys.

Options:
  --list   list existing backups
EOF
}

help_restore() {
  cat <<'EOF'
Usage: portcullis restore [--yes] <backup-dir>
       portcullis restore --list

Stop Portcullis, restore .env, certs/, secrets/, config files and volumes
from a backup made by `portcullis backup` / `portcullis upgrade`, then
start everything again. The current .env, secrets/ and certs/ are saved to
backups/pre-restore-<timestamp>/ first.

Options:
  -y, --yes   do not ask for confirmation
  --list      list available backups
EOF
}

cmd_backup() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --list) backup_list; return 0 ;;
      -h|--help) help_backup; return 0 ;;
      *) usage_error backup "unknown argument: $1" ;;
    esac
  done
  need_env
  backup_create
}

cmd_restore() {
  local yes=false dir=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --list) backup_list; return 0 ;;
      -y|--yes) yes=true ;;
      -h|--help) help_restore; return 0 ;;
      -*) usage_error restore "unknown option: $1" ;;
      *) [ -z "$dir" ] || usage_error restore "unexpected argument: $1"; dir="$1" ;;
    esac
    shift
  done
  [ -n "$dir" ] || usage_error restore "expected <backup-dir> (see --list)"
  # Relative paths: from where the command was run, else from the checkout.
  case "$dir" in
    /*) ;;
    *) if [ -d "$PORTCULLIS_CALLER_PWD/$dir" ]; then dir="$PORTCULLIS_CALLER_PWD/$dir"; else dir="$PORTCULLIS_ROOT/$dir"; fi ;;
  esac
  need_env
  backup_restore "$dir" "$yes"
}
