# shellcheck shell=bash
#
# `portcullis backup [--offsite] | backup verify | backup schedule` and
# `portcullis restore` — consistent backups, kept locally and (optionally)
# off-host in a restic repository. docs/backups.md.
#
# A backup (backups/<YYYYmmdd-HHMMSS>/, 0700; built in <dir>.partial and
# renamed when complete) contains:
#   MANIFEST.json        format, creation time, versions, sha256 of every file
#   .env, realm-export.json, headscale-config.yaml, docker-compose.override.yml,
#   config/              whichever exist
#   certs/               CA chain, server cert/key, revoked-serial list
#   secrets/             Vault ROOT TOKEN + UNSEAL KEY, enroll AppRole, ...
#   vault.snap           Vault raft snapshot (sys/storage/raft/snapshot)
#   postgres.dump        pg_dump -Fc of the Keycloak database
#   <volume>.tar.gz      lldap_data, hub_data, traefik_acme, domains_data (age-encrypted),
#                        mcp_gate_data (the MCP gate's access log): files, with every
#                        SQLite database copied through SQLite's online backup
#                        API (consistent while the service keeps running);
#                        hub_data includes the Hub's app instance backups
#                        (/data/backups/<instance>/<UTC>.tar, contract §11.5:
#                        0600 files of uid 10001, generated app secrets in
#                        clear), so --offsite ships them too
# Nothing is stopped for a backup. secrets/ + vault.snap can decrypt the CA
# and every secret: a backup is as sensitive as the host. Off-host copies
# are encrypted by restic with BACKUP_PASSWORD — keep that password offline.

BACKUP_ROOT="${BACKUP_ROOT:-$PORTCULLIS_ROOT/backups}"
BACKUP_FORMAT=1
BACKUP_RESTIC_IMAGE="restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510"
# Volumes archived as files: <compose volume>:<uid>:<gid> of the service
# that owns them (the snapshot container runs as that user so SQLite can
# open WAL databases; restore chowns the volume root back).
# domains_data holds only the age-encrypted store (contract §12.4).
# mcp_gate_data: the gate's access log (contract §15.8; 0640 group 10001,
# so the volume root goes back as 10005:10001).
# hub_secrets is NEVER backed up (offsite would carry password hashes) and
# is emptied by restore (contract §11.6: a restored hash could revive a
# leaked password). It is handled separately in cmd_restore.
BACKUP_FILE_VOLUMES="lldap_data:$CT_UID_LLDAP:$CT_UID_LLDAP hub_data:$CT_UID_HUB:$CT_UID_HUB traefik_acme:0:0 domains_data:$CT_UID_DOMAINS:$CT_UID_DOMAINS mcp_gate_data:$CT_UID_MCP_GATE:$CT_UID_HUB"
# restic: fixed host + path, so snapshots of every run form one series.
BACKUP_RESTIC_HOST="portcullis"
BACKUP_SNAPSHOT_PATH="/portcullis-backup"
# Provider credentials passed to restic (by name, never on argv). For each,
# BACKUP_<NAME> wins over <NAME> — e.g. BACKUP_AWS_ACCESS_KEY_ID when the
# AWS_* variables already hold Route53 credentials for ACME.
RESTIC_PROVIDER_VARS="AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION
  B2_ACCOUNT_ID B2_ACCOUNT_KEY AZURE_ACCOUNT_NAME AZURE_ACCOUNT_KEY AZURE_ACCOUNT_SAS AZURE_ENDPOINT_SUFFIX
  GOOGLE_PROJECT_ID RESTIC_REST_USERNAME RESTIC_REST_PASSWORD RESTIC_COMPRESSION"
# shellcheck disable=SC2034  # read by callers (upgrade)
BACKUP_LAST_DIR=""
_BACKUP_CFG=""
_RESTIC_MOUNTS=()

# Runs inside group-gate's (locally built) python image, as the volume owner:
# /data → gzipped tar on stdout; SQLite files via the online backup API.
read -r -d '' _BACKUP_PY_SNAPSHOT <<'PY' || true
import os, sqlite3, sys, tarfile, tempfile
SRC = "/data"
def is_sqlite(p):
    try:
        with open(p, "rb") as f:
            return f.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False
paths, dbs = [], {}
for root, dirs, files in os.walk(SRC):
    dirs.sort()
    paths.append(root)
    for fn in sorted(files):
        paths.append(os.path.join(root, fn))
skip = set()
tmp = tempfile.mkdtemp(dir="/tmp")
for p in paths:
    if os.path.isfile(p) and not os.path.islink(p) and is_sqlite(p):
        out = os.path.join(tmp, str(len(dbs)))
        src, dst = sqlite3.connect(p), sqlite3.connect(out)
        with dst:
            src.backup(dst)
        ok = dst.execute("PRAGMA quick_check").fetchone()[0]
        src.close(); dst.close()
        if ok != "ok":
            sys.exit(f"{p}: copy failed quick_check: {ok}")
        dbs[p] = out
        skip.update(p + s for s in ("-wal", "-shm", "-journal"))
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|gz") as tf:
    for p in paths:
        if p in skip:
            continue
        arc = "." if p == SRC else "./" + os.path.relpath(p, SRC)
        if p in dbs:
            ti = tf.gettarinfo(p, arcname=arc)
            ti.size = os.path.getsize(dbs[p])
            with open(dbs[p], "rb") as f:
                tf.addfile(ti, f)
        else:
            tf.add(p, arcname=arc, recursive=False)
print(f"{len(paths)} entries, {len(dbs)} sqlite database(s)", file=sys.stderr)
PY

# Runs inside the python image: lldap_data.tar.gz on stdin → the user
# database must open, pass integrity_check and contain users and groups.
read -r -d '' _BACKUP_PY_CHECK_LLDAP <<'PY' || true
import os, sqlite3, sys, tarfile
db, names = None, set()
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|gz") as tf:
    for m in tf:
        name = os.path.normpath(m.name)
        names.add(name)
        if name == "users.db" and m.isfile():
            db = "/tmp/users.db"
            with open(db, "wb") as out:
                out.write(tf.extractfile(m).read())
if db is None:
    sys.exit("users.db not in the archive")
c = sqlite3.connect(db)
ok = c.execute("PRAGMA integrity_check").fetchone()[0]
if ok != "ok":
    sys.exit(f"users.db integrity_check: {ok}")
users = c.execute("SELECT count(*) FROM users").fetchone()[0]
groups = c.execute("SELECT count(*) FROM groups").fetchone()[0]
if users < 1:
    sys.exit("users.db has no users")
print(f"users.db ok: {users} user(s), {groups} group(s)"
      + ("" if "private_key" in names else " (no private_key file: LLDAP_KEY_SEED must be set)"))
PY

# Runs inside the python image with lldap_data mounted at /data (read-only):
# prints the number of LLDAP users other than admin and the Hub's service
# account, or "missing" when there is no readable user database.
read -r -d '' _BACKUP_PY_COUNT_LLDAP <<'PY' || true
import sqlite3, sys
try:
    c = sqlite3.connect("file:/data/users.db?mode=ro&immutable=1", uri=True)
    n = c.execute("SELECT count(*) FROM users WHERE user_id NOT IN ('admin', 'portcullis-hub')").fetchone()[0]
except Exception as e:
    print("missing")
    sys.exit(0)
print(n)
PY

# ── helpers ────────────────────────────────────────────────

_backup_load_cfg() {
  [ -n "$_BACKUP_CFG" ] || _BACKUP_CFG="$(dc config --format json 2>/dev/null)" \
    || fail "docker compose config failed (is .env complete?)"
  [ -n "$_BACKUP_CFG" ] || fail "docker compose config returned nothing"
}
_volume_name() { printf '%s' "$_BACKUP_CFG" | jq -r --arg v "$1" '.volumes[$v].name // empty'; }
_svc_image() { printf '%s' "$_BACKUP_CFG" | jq -r --arg s "$1" '.services[$s].image // empty'; }
# _py_image — group-gate's image (python3 for the SQLite helpers), built
# first if this host does not have it yet (e.g. verify before the first `up`).
_py_image() {
  local img
  img="$(_svc_image group-gate)"
  [ -n "$img" ] || fail "group-gate has no image name in the compose config"
  docker image inspect "$img" >/dev/null 2>&1 || dc build --quiet group-gate >&2 \
    || fail "cannot build the group-gate image ($img)"
  printf '%s' "$img"
}
_project_name() { printf '%s' "$_BACKUP_CFG" | jq -r '.name // "portcullis"'; }

# _sha256_c <listfile> — verify "<hash>  <path>" lines (cwd-relative).
_sha256_c() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum --quiet -c "$1"; else shasum -a 256 --quiet -c "$1"; fi
}
_sha256_files() {
  if command -v sha256sum >/dev/null 2>&1; then xargs -0 sha256sum; else xargs -0 shasum -a 256; fi
}

# _backup_manifest <dir> — MANIFEST.json with the sha256 of every file.
_backup_manifest() {
  local dir="$1" files
  files="$(cd "$dir" && find . -type f ! -name MANIFEST.json -print0 | LC_ALL=C sort -z | _sha256_files \
    | jq -Rn '[inputs | capture("^(?<h>[0-9a-f]{64}) [ *](?<p>.*)$") | {key: (.p | ltrimstr("./")), value: .h}] | from_entries')" \
    || fail "could not checksum $dir"
  jq -n --argjson format "$BACKUP_FORMAT" --arg created "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg version "$(portcullis_version)" --arg domain "${PORTCULLIS_DOMAIN:-}" \
    --arg hub "$(_svc_image hub)" --argjson files "$files" \
    '{format: $format, created: $created, portcullis_version: $version, domain: $domain,
      hub_image: $hub, files: $files}' > "$dir/MANIFEST.json"
}

# _backup_check_manifest <dir> — every file listed has its checksum.
_backup_check_manifest() {
  local dir="$1" list rc=0
  list="$(mktemp)"
  jq -r '.files | to_entries[] | "\(.value)  \(.key)"' "$dir/MANIFEST.json" > "$list" || { rm -f "$list"; return 1; }
  (cd "$dir" && _sha256_c "$list") || rc=$?
  rm -f "$list"
  return "$rc"
}

# _backup_check_layout <dir> — the pieces a restore cannot do without.
_backup_check_layout() {
  local dir="$1" f
  [ -f "$dir/MANIFEST.json" ] || fail "$dir has no MANIFEST.json — not a Portcullis backup."
  [ "$(jq -r .format "$dir/MANIFEST.json" 2>/dev/null)" = "$BACKUP_FORMAT" ] \
    || fail "$dir: unsupported backup format (want $BACKUP_FORMAT)."
  for f in .env vault.snap postgres.dump secrets/vault-init.json secrets/vault-unseal/unseal-key; do
    [ -s "$dir/$f" ] || fail "$dir lacks $f — incomplete backup."
  done
  jq -e '.root_token and (.unseal_keys_b64 | length == 1)' "$dir/secrets/vault-init.json" >/dev/null 2>&1 \
    || fail "$dir/secrets/vault-init.json has no root token / unseal key."
}

_backup_vault_snapshot() {
  local out="$1" code
  code="$(curl -s --max-time 300 -o "$out" -w '%{http_code}' \
    -H @<(printf 'X-Vault-Token: %s\n' "$VAULT_TOKEN") \
    "${VAULT_ADDR:-http://127.0.0.1:8200}/v1/sys/storage/raft/snapshot" || true)"
  [ "$code" = 200 ] || fail "Vault raft snapshot failed (HTTP ${code:-none})"
  # List into a variable first: `tar -t | grep -q` under pipefail fails
  # whenever grep exits on the first entry (meta.json) and tar, still
  # listing state.bin / SHA256SUMS, dies of SIGPIPE.
  local list=""
  if ! gzip -t "$out" 2>/dev/null || ! list="$(tar -tzf "$out" 2>/dev/null)" \
     || ! grep -qxE '(\./)?meta\.json' <<< "$list" || ! grep -qxE '(\./)?state\.bin' <<< "$list"; then
    echo "  snapshot: $(wc -c < "$out") bytes, $(file -b "$out" 2>/dev/null || echo '?'), entries: $(tr '\n' ' ' <<< "$list")" >&2
    fail "Vault returned something that is not a raft snapshot"
  fi
}

_backup_pg_dump() {
  local out="$1"
  dc exec -T postgres pg_dump -U keycloak -d keycloak -Fc > "$out" || fail "pg_dump failed"
  [ "$(head -c 5 "$out")" = PGDMP ] || fail "pg_dump output is not a custom-format dump"
}

# _backup_volume_files <volume> <uid> <gid> — tar.gz of the volume on stdout.
_backup_volume_files() {
  local img
  img="$(_py_image)" || return 1
  docker run --rm --network none --user "$2:$3" --cap-drop ALL --security-opt no-new-privileges:true \
    --read-only --tmpfs /tmp -e PYTHONDONTWRITEBYTECODE=1 -v "$1:/data" \
    "$img" python3 -c "$_BACKUP_PY_SNAPSHOT"
}

# _backup_dirs — names of the timestamped backups in BACKUP_ROOT, oldest first.
_backup_dirs() {
  local d
  for d in "$BACKUP_ROOT"/[0-9]*-[0-9]*; do
    d="${d##*/}"
    [[ "$d" =~ ^[0-9]{8}-[0-9]{6}$ ]] && [ -d "$BACKUP_ROOT/$d" ] && printf '%s\n' "$d"
  done
  return 0
}

_backup_size_bytes() { echo $(( $(du -sk "$1" | cut -f1) * 1024 )); }

# _backup_metrics <kind> <duration> <size> — textfile metrics (monitoring).
_backup_metrics() {
  metrics_textfile_write "backup_$1" <<EOF
# HELP portcullis_backup_last_success_timestamp_seconds Unix time of the last successful backup.
# TYPE portcullis_backup_last_success_timestamp_seconds gauge
portcullis_backup_last_success_timestamp_seconds{kind="$1"} $(date +%s)
# HELP portcullis_backup_duration_seconds Duration of the last successful backup.
# TYPE portcullis_backup_duration_seconds gauge
portcullis_backup_duration_seconds{kind="$1"} $2
# HELP portcullis_backup_size_bytes Size of the last successful local backup.
# TYPE portcullis_backup_size_bytes gauge
portcullis_backup_size_bytes{kind="$1"} $3
EOF
}

# _backup_prune_local — keep the newest BACKUP_KEEP_LOCAL (default 7)
# timestamped backups; pre-restore-* and offsite-* dirs are left alone.
_backup_prune_local() {
  local keep="${BACKUP_KEEP_LOCAL:-7}" d n=0
  [[ "$keep" =~ ^[0-9]+$ ]] || { warn "BACKUP_KEEP_LOCAL=$keep is not a number — not pruning"; return 0; }
  [ "$keep" -gt 0 ] || return 0
  while IFS= read -r d; do
    n=$((n + 1))
    [ "$n" -le "$keep" ] && continue
    rm -rf "${BACKUP_ROOT:?}/$d" && echo "  removed old backup $d"
  done < <(_backup_dirs | sort -r)
}

# ── backup ─────────────────────────────────────────────────

backup_create() {
  local dir work started="" svc t0 old_umask spec key uid gid full f
  require_cmd docker jq curl gzip tar
  t0="$(date +%s)"
  _backup_load_cfg
  dir="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
  work="$dir.partial"
  [ ! -e "$dir" ] && [ ! -e "$work" ] || fail "$dir already exists"

  # The dumps talk to the running Vault and Postgres; start them if needed
  # (and stop them again afterwards).
  for svc in postgres vault; do
    [ -n "$(dc ps -q --status running "$svc" 2>/dev/null)" ] || started="$started $svc"
  done
  if [ -n "$started" ]; then
    info "Starting$started for the backup..."
    # shellcheck disable=SC2086
    dc up -d --no-deps $started
  fi
  wait_healthy 120 postgres
  vault_wait_active 90 || fail "Vault is not active — ./portcullis vault unseal"
  vault_admin_env >/dev/null || fail "no Vault admin token (secrets/vault-init.json or VAULT_TOKEN)"

  info "Creating backup in $dir..."
  old_umask="$(umask)"
  umask 077
  mkdir -p "$work"
  chmod 700 "$BACKUP_ROOT" "$work"
  cp "$(env_file)" "$work/.env"
  [ ! -f "$PORTCULLIS_ROOT/keycloak/realm-export.json" ] || cp "$PORTCULLIS_ROOT/keycloak/realm-export.json" "$work/realm-export.json"
  [ ! -f "$PORTCULLIS_ROOT/headscale/config.yaml" ] || cp "$PORTCULLIS_ROOT/headscale/config.yaml" "$work/headscale-config.yaml"
  [ ! -f "$PORTCULLIS_ROOT/docker-compose.override.yml" ] || cp -L "$PORTCULLIS_ROOT/docker-compose.override.yml" "$work/docker-compose.override.yml"
  [ ! -d "$PORTCULLIS_ROOT/config" ] || cp -a "$PORTCULLIS_ROOT/config" "$work/config"
  [ ! -d "$PORTCULLIS_ROOT/certs" ] || cp -a "$PORTCULLIS_ROOT/certs" "$work/certs"
  [ ! -d "$PORTCULLIS_ROOT/secrets" ] || cp -a "$PORTCULLIS_ROOT/secrets" "$work/secrets"

  printf '  %-26s' "vault (raft snapshot)"; _backup_vault_snapshot "$work/vault.snap"; printf ' %sdone%s\n' "$C_GREEN" "$C_NC"
  printf '  %-26s' "postgres (pg_dump)"; _backup_pg_dump "$work/postgres.dump"; printf ' %sdone%s\n' "$C_GREEN" "$C_NC"
  for spec in $BACKUP_FILE_VOLUMES; do
    IFS=: read -r key uid gid <<< "$spec"
    full="$(_volume_name "$key")"
    [ -n "$full" ] && docker volume inspect "$full" >/dev/null 2>&1 || continue
    printf '  %-26s' "$key"
    _backup_volume_files "$full" "$uid" "$gid" > "$work/$key.tar.gz" 2>"$work/.err" \
      || { cat "$work/.err" >&2; fail "could not back up volume $key"; }
    printf ' %sdone%s %s\n' "$C_GREEN" "$C_NC" "$(cat "$work/.err")"
    rm -f "$work/.err"
  done
  for f in "$work"/*.tar.gz; do
    [ -f "$f" ] && { gzip -t "$f" || fail "$f is corrupt"; }
  done
  _backup_manifest "$work"
  mv "$work" "$dir"
  umask "$old_umask"

  if [ -n "$started" ]; then
    # shellcheck disable=SC2086
    dc stop $started >/dev/null 2>&1 || true
  fi
  # shellcheck disable=SC2034
  BACKUP_LAST_DIR="$dir"
  _backup_metrics local $(( $(date +%s) - t0 )) "$(_backup_size_bytes "$dir")"
  _backup_prune_local
  ok "Backup saved to $dir"
  warn "It contains secrets/ (Vault root token + unseal key): protect it like the keys themselves."
}

backup_list() {
  local d any=false
  for d in "$BACKUP_ROOT"/*/; do
    [ -f "$d/MANIFEST.json" ] || [ -f "$d/.env" ] || continue
    any=true
    printf '  %-28s %6s  %s\n' "$(basename "$d")" "$(du -sh "$d" 2>/dev/null | cut -f1)" \
      "$(jq -r '"\(.created // "?")  \(.portcullis_version // "")"' "$d/MANIFEST.json" 2>/dev/null || echo "(pre-restore copy)")"
  done
  [ "$any" = true ] || echo "No backups in $BACKUP_ROOT"
}

# ── restic (off-host) ──────────────────────────────────────

# _backup_cred <NAME> — BACKUP_<NAME> if set, else <NAME>.
_backup_cred() { local o="BACKUP_$1"; printf '%s' "${!o:-${!1:-}}"; }

_restic_require() {
  [ -n "${BACKUP_REPOSITORY:-}" ] || fail "BACKUP_REPOSITORY is not set in .env (see docs/backups.md)"
  [ -n "${BACKUP_PASSWORD:-}" ] || fail "BACKUP_PASSWORD is not set in .env (./portcullis init generates it)"
  case "$BACKUP_REPOSITORY" in
    sftp:*|rclone:*) fail "BACKUP_REPOSITORY: sftp:/rclone: need tools the restic container does not have — use rest:, s3:, b2:, azure:, gs: or a local path" ;;
  esac
}

# _restic <restic args...> — restic in its pinned image, as the operator
# (files stay operator-owned), read-only root FS, no capabilities. Repo
# password and provider credentials are passed by NAME (-e VAR), in a
# subshell, so they never reach argv or this shell's later commands.
# Extra mounts: _RESTIC_MOUNTS=(-v src:dst ...).
_restic() {
  local repo="$BACKUP_REPOSITORY" path v
  local -a args=(run --rm -i --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges:true
    --read-only --tmpfs /tmp -e HOME=/tmp -e RESTIC_CACHE_DIR=/cache -v "$BACKUP_ROOT/.restic-cache:/cache"
    -e RESTIC_REPOSITORY -e RESTIC_PASSWORD -e RESTIC_PROGRESS_FPS=0.2)
  (umask 077 && mkdir -p "$BACKUP_ROOT/.restic-cache")
  case "$repo" in
    /*|local:/*)
      path="${repo#local:}"
      (umask 077 && mkdir -p "$path") || fail "cannot create $path"
      args+=(-v "$path:$path" --network none) ;;
  esac
  for v in $RESTIC_PROVIDER_VARS; do
    [ -n "$(_backup_cred "$v")" ] && args+=(-e "$v")
  done
  [ "${#_RESTIC_MOUNTS[@]}" -eq 0 ] || args+=("${_RESTIC_MOUNTS[@]}")
  (
    for v in $RESTIC_PROVIDER_VARS; do
      val="$(_backup_cred "$v")"
      [ -z "$val" ] || export "$v=$val"
    done
    export RESTIC_REPOSITORY="$repo" RESTIC_PASSWORD="$BACKUP_PASSWORD"
    docker "${args[@]}" --entrypoint restic "$BACKUP_RESTIC_IMAGE" "$@"
  )
}

# _restic_ensure_repo — open the repository, creating it on first use.
_restic_ensure_repo() {
  local rc=0
  _restic cat config >/dev/null 2>&1 || rc=$?
  case "$rc" in
    0) ;;
    10) info "Initialising the restic repository $BACKUP_REPOSITORY..."
        _restic init >/dev/null || fail "restic init failed" ;;
    12) fail "wrong BACKUP_PASSWORD for $BACKUP_REPOSITORY" ;;
    *)  _restic cat config >/dev/null || true
        fail "cannot open the restic repository $BACKUP_REPOSITORY (restic exit $rc)" ;;
  esac
}

# backup_offsite <dir> — upload a local backup, then apply the retention.
backup_offsite() {
  local dir="$1" t0 d w m
  t0="$(date +%s)"
  _restic_require
  _restic_ensure_repo
  info "Uploading $dir to $BACKUP_REPOSITORY (restic, encrypted)..."
  _RESTIC_MOUNTS=(-v "$dir:$BACKUP_SNAPSHOT_PATH:ro")
  _restic backup --host "$BACKUP_RESTIC_HOST" --tag portcullis --tag "domain=${PORTCULLIS_DOMAIN:-}" \
    "$BACKUP_SNAPSHOT_PATH" || { _RESTIC_MOUNTS=(); fail "restic backup failed"; }
  _RESTIC_MOUNTS=()
  d="${BACKUP_KEEP_DAILY:-7}" w="${BACKUP_KEEP_WEEKLY:-4}" m="${BACKUP_KEEP_MONTHLY:-6}"
  info "Retention: $d daily, $w weekly, $m monthly..."
  _restic forget --host "$BACKUP_RESTIC_HOST" --tag portcullis \
    --keep-daily "$d" --keep-weekly "$w" --keep-monthly "$m" --prune >/dev/null \
    || warn "restic forget/prune failed (the new snapshot is safe)"
  _backup_metrics offsite $(( $(date +%s) - t0 )) "$(_backup_size_bytes "$dir")"
  ok "Off-host backup done ($BACKUP_REPOSITORY)."
}

# backup_snapshots [--json]
backup_snapshots() {
  _restic_require
  _restic snapshots --host "$BACKUP_RESTIC_HOST" --tag portcullis "$@"
}

# _restic_restore_to <snapshot> <dir> — restore a snapshot; prints the
# backup directory inside <dir>.
_restic_restore_to() {
  local snap="$1" target="$2"
  local -a filter=()
  [ "$snap" != latest ] || filter=(--host "$BACKUP_RESTIC_HOST" --tag portcullis)
  (umask 077 && mkdir -p "$target")
  chmod 700 "$target"
  _RESTIC_MOUNTS=(-v "$target:/restore")
  _restic restore "$snap" ${filter[@]+"${filter[@]}"} --target /restore >&2 || { _RESTIC_MOUNTS=(); fail "restic restore of $snap failed"; }
  _RESTIC_MOUNTS=()
  [ -f "$target$BACKUP_SNAPSHOT_PATH/MANIFEST.json" ] || fail "snapshot $snap has no $BACKUP_SNAPSHOT_PATH/MANIFEST.json"
  printf '%s' "$target$BACKUP_SNAPSHOT_PATH"
}

# ── verify ─────────────────────────────────────────────────

# backup_verify_dir <dir> — checksums + every piece is usable.
backup_verify_dir() {
  local dir="$1" t n rc=0 realms users kc pg_img py_img f
  _backup_check_layout "$dir"
  _backup_check_manifest "$dir" || fail "checksum mismatch in $dir"
  ok "checksums match MANIFEST.json ($(jq '.files | length' "$dir/MANIFEST.json") files)"

  # Vault: a raft snapshot is a tar.gz of meta.json, state.bin, SHA256SUMS.
  t="$(mktemp -d)"
  if tar -xzf "$dir/vault.snap" -C "$t" 2>/dev/null && [ -s "$t/state.bin" ] && [ -s "$t/SHA256SUMS" ] \
     && (cd "$t" && grep -E ' (meta\.json|state\.bin)$' SHA256SUMS > sums && _sha256_c sums) \
     && jq -e '.Index > 0' "$t/meta.json" >/dev/null 2>&1; then
    ok "vault.snap parses (raft index $(jq -r .Index "$t/meta.json"), checksums ok)"
  else
    rc=1; warn "vault.snap is not a valid raft snapshot"
  fi
  rm -rf "$t"

  _backup_load_cfg
  pg_img="$(_svc_image postgres)" py_img="$(_py_image)"
  # Postgres: restore the dump into a throwaway server.
  n="portcullis-verify-pg-$$"
  docker run -d --rm --name "$n" --network none --tmpfs /var/lib/postgresql \
    -e POSTGRES_PASSWORD=verify "$pg_img" >/dev/null || fail "cannot start a throwaway postgres"
  if _verify_pg "$n" "$dir/postgres.dump"; then
    realms="$(docker exec "$n" psql -U postgres -d keycloak -tAc 'select count(*) from realm' 2>/dev/null)"
    users="$(docker exec "$n" psql -U postgres -d keycloak -tAc 'select count(*) from user_entity' 2>/dev/null)"
    kc="$(docker exec "$n" psql -U postgres -d keycloak -tAc "select count(*) from realm where name = 'portcullis'" 2>/dev/null)"
    if [[ "$realms" =~ ^[0-9]+$ ]] && [ "$realms" -ge 1 ]; then
      ok "postgres.dump restores into a fresh postgres ($realms realm(s), $users Keycloak user(s))"
      [ "$kc" = 1 ] || warn "the dump has no 'portcullis' realm"
    else
      rc=1; warn "postgres.dump restored, but has no Keycloak realms"
    fi
  else
    rc=1; warn "postgres.dump does not restore"
  fi
  docker rm -f "$n" >/dev/null 2>&1 || true

  # LLDAP: the user database opens and has users.
  if [ -f "$dir/lldap_data.tar.gz" ]; then
    if f="$(docker run -i --rm --network none --read-only --tmpfs /tmp --user 65534:65534 --cap-drop ALL \
          --security-opt no-new-privileges:true -e PYTHONDONTWRITEBYTECODE=1 "$py_img" \
          python3 -c "$_BACKUP_PY_CHECK_LLDAP" < "$dir/lldap_data.tar.gz")"; then
      ok "lldap: $f"
    else
      rc=1; warn "lldap_data.tar.gz: the LLDAP database is unusable"
    fi
  else
    rc=1; warn "no lldap_data.tar.gz"
  fi
  for f in "$dir"/*.tar.gz; do
    [ -f "$f" ] || continue
    tar -tzf "$f" >/dev/null 2>&1 && ok "$(basename "$f") is a readable archive" || { rc=1; warn "$(basename "$f") is corrupt"; }
  done
  return "$rc"
}

_verify_pg() {
  local n="$1" dump="$2" i
  for ((i = 0; i < 60; i++)); do
    docker exec "$n" pg_isready -U postgres -h 127.0.0.1 -q 2>/dev/null && break
    sleep 2
  done
  docker exec "$n" createdb -U postgres keycloak >/dev/null 2>&1 \
    && docker exec -i "$n" pg_restore -U postgres -d keycloak --no-owner --no-privileges --exit-on-error < "$dump" >/dev/null
}

# backup_verify <snapshot|""> <local-dir|""> <local:true|false>
backup_verify() {
  local snap="$1" ldir="$2" local_only="$3" tmp dir rc=0
  require_cmd docker jq tar gzip
  if [ "$local_only" = true ]; then
    if [ -z "$ldir" ]; then
      ldir="$(_backup_dirs | tail -n1)"
      [ -n "$ldir" ] || fail "no local backups in $BACKUP_ROOT"
      ldir="$BACKUP_ROOT/$ldir"
    fi
    info "Verifying $ldir..."
    backup_verify_dir "$ldir" || fail "backup $ldir FAILED verification"
    ok "Backup $ldir verified."
    return 0
  fi
  _restic_require
  _restic_ensure_repo
  info "Checking the repository (restic check, reading ${BACKUP_VERIFY_READ_DATA:-10%} of the data)..."
  _restic check --read-data-subset="${BACKUP_VERIFY_READ_DATA:-10%}" || fail "restic check failed"
  tmp="$BACKUP_ROOT/.verify-$(date +%Y%m%d-%H%M%S)"
  info "Restoring ${snap:-latest} into $tmp..."
  dir="$(_restic_restore_to "${snap:-latest}" "$tmp")"
  backup_verify_dir "$dir" || rc=$?
  rm -rf "$tmp"
  [ "$rc" = 0 ] || fail "off-host backup ${snap:-latest} FAILED verification"
  ok "Off-host backup ${snap:-latest} verified (restic check + restore + sanity checks)."
}

# ── restore ────────────────────────────────────────────────

_restore_pg() {
  local dir="$1" i
  info "Restoring the Keycloak database (pg_restore)..."
  # TCP readiness = the final server (the image's init server only listens
  # on the socket).
  for ((i = 0; i < 90; i++)); do
    dc exec -T postgres pg_isready -U keycloak -h 127.0.0.1 -q >/dev/null 2>&1 && break
    sleep 2
  done
  dc exec -T postgres pg_restore -U keycloak -d keycloak --no-owner --exit-on-error --single-transaction \
    < "$dir/postgres.dump" || fail "pg_restore failed"
}

# _restore_vault <dir> — the fresh Vault is initialised with throwaway
# keys, the snapshot is force-restored (it brings the ORIGINAL keyring),
# then Vault is recreated with the restored secrets/ and auto-unseals with
# the original key.
_restore_vault() {
  local dir="$1" init tmp_key tmp_root code
  info "Restoring Vault (raft snapshot)..."
  unset VAULT_TOKEN
  _vault_start_and_status
  [ "$VAULT_INITIALIZED" = false ] || fail "the vault_data volume was not empty"
  init="$(vexec operator init -key-shares=1 -key-threshold=1 -format=json)" || fail "temporary vault init failed"
  tmp_key="$(printf '%s' "$init" | jq -r '.unseal_keys_b64[0]')"
  tmp_root="$(printf '%s' "$init" | jq -r '.root_token')"
  printf '%s' "$tmp_key" | vexec write -format=json sys/unseal key=- >/dev/null || fail "temporary unseal failed"
  vault_wait_active 60 || fail "temporary Vault did not become active"
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 300 -X POST \
    -H @<(printf 'X-Vault-Token: %s\n' "$tmp_root") --data-binary @"$dir/vault.snap" \
    "${VAULT_ADDR:-http://127.0.0.1:8200}/v1/sys/storage/raft/snapshot-force" || true)"
  [ "$code" = 204 ] || [ "$code" = 200 ] || fail "Vault snapshot restore failed (HTTP ${code:-none})"
  _restore_secrets "$dir"
  dc up -d --no-deps --force-recreate vault >/dev/null
  vault_wait_active 120 || fail "Vault did not unseal with the restored key (secrets/ and vault.snap from different installs?)"
  ok "Vault restored and unsealed with the original key."
}

_restore_secrets() {
  local dir="$1"
  (umask 077 && rm -rf "$PORTCULLIS_ROOT/secrets.restore-tmp" && cp -a "$dir/secrets" "$PORTCULLIS_ROOT/secrets.restore-tmp")
  rm -rf "$PORTCULLIS_ROOT/secrets" && mv "$PORTCULLIS_ROOT/secrets.restore-tmp" "$PORTCULLIS_ROOT/secrets"
  chmod 700 "$PORTCULLIS_ROOT/secrets"
  secrets_fix_perms
}

# backup_restore <dir> <assume-yes>
# _restore_lldap_count — LLDAP users besides admin / portcullis-hub in the
# (stopped) lldap_data volume, or "missing".
_restore_lldap_count() {
  local vol
  vol="$(_volume_name lldap_data)"
  docker volume inspect "$vol" >/dev/null 2>&1 || { echo missing; return 0; }
  docker run --rm --network none --read-only --tmpfs /tmp --user "$CT_UID_LLDAP:$CT_UID_LLDAP" --cap-drop ALL \
    --security-opt no-new-privileges:true -e PYTHONDONTWRITEBYTECODE=1 -v "$vol:/data:ro" "$(_py_image)" \
    python3 -c "$_BACKUP_PY_COUNT_LLDAP" 2>/dev/null || echo missing
}

# _restore_kc_federated_count — Keycloak users of the portcullis realm
# linked to the LDAP federation (the restored database; Postgres is up),
# besides admin; "" if unknown.
_restore_kc_federated_count() {
  dc exec -T postgres psql -U keycloak -d keycloak -tAc \
    "select count(*) from user_entity u join realm r on r.id = u.realm_id where r.name = 'portcullis' and u.federation_link is not null and u.username <> 'admin'" \
    2>/dev/null | tr -d '[:space:]'
}

# _restore_lldap_guard <allow> — refuse (return 1, nothing more started)
# when LLDAP has no users but Keycloak's restored database has federated
# ones; <allow> = true (--allow-empty-lldap) only warns.
_restore_lldap_guard() {
  local allow="$1" ll kcn
  ll="$(_restore_lldap_count)"
  kcn="$(_restore_kc_federated_count)"
  case "$kcn" in ''|*[!0-9]*) kcn=0 ;; esac
  if { [ "$ll" = missing ] || [ "$ll" = 0 ]; } && [ "$kcn" -gt 0 ]; then
    if [ "$allow" = true ]; then
      warn "LLDAP has no users (${ll}) but the restored Keycloak database has $kcn — starting anyway (--allow-empty-lldap): Keycloak will delete those users' copies, passkeys included, at their next lookup."
      return 0
    fi
    warn "LLDAP has no users (${ll}) but the restored Keycloak database has $kcn federated users."
    warn "Starting Keycloak now would delete their Keycloak copies — passkeys included — at the next sign-in attempt or Hub sweep."
    warn "Nothing else was started (Postgres and Vault are up). Restore a backup that includes lldap_data.tar.gz, or re-run with --allow-empty-lldap if the users are really gone."
    return 1
  fi
  [ "$ll" != missing ] || warn "LLDAP has no user database yet (the restored Keycloak database has no federated users either)."
  return 0
}

# _restore_stop_secret_apps <volume> <core project> [hub_stopped] — takes down
# (compose down, volumes kept) every app project with a container mounting the
# hub_secrets volume (the file-sharing apps' read-only subpath mounts):
# the restore removes that volume, and Docker refuses to remove a volume
# any container — running or stopped — still references. Run before
# anything changes: a failed down or a container left aborts the restore
# with nothing changed. The projects taken down are left in
# RESTORE_STOPPED_APPS (space-separated) for the closing message; they are
# never started again here (the restore voids their credentials).
# If hub_stopped=true, returns error codes instead of calling fail (so the
# caller can restart the Hub).
RESTORE_STOPPED_APPS=""
_RESTORE_ERROR_MSG=""
_restore_stop_secret_apps() {
  local vol="$1" core="$2" hub_stopped="${3:-false}" ids id p left empty
  _RESTORE_ERROR_MSG=""
  if ! ids="$(docker ps -aq --filter "volume=$vol")"; then
    _RESTORE_ERROR_MSG="can't list the containers using $vol (docker ps failed): nothing was restored"
    [ "$hub_stopped" = true ] && return 1
    fail "$_RESTORE_ERROR_MSG"
  fi
  local projects=""
  for id in $ids; do
    if ! p="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id")"; then
      _RESTORE_ERROR_MSG="can't inspect container $id (it mounts $vol): nothing was restored"
      [ "$hub_stopped" = true ] && return 1
      fail "$_RESTORE_ERROR_MSG"
    fi
    [ "$p" = "$core" ] && continue
    if [ -z "$p" ]; then
      _RESTORE_ERROR_MSG="container $id mounts $vol but isn't part of a compose project: remove it (docker rm -f $id), then restore again. Nothing was restored"
      [ "$hub_stopped" = true ] && return 1
      fail "$_RESTORE_ERROR_MSG"
    fi
    case " $projects " in *" $p "*) ;; *) projects="${projects:+$projects }$p" ;; esac
  done
  [ -n "$projects" ] || return 0
  info "Taking down the apps that mount $vol (volumes kept): $projects"
  # By project name alone, from an empty directory: the Hub wrote these
  # projects' compose files, which aren't readable here.
  empty="$(mktemp -d)"
  for p in $projects; do
    if ! (cd "$empty" && env -u COMPOSE_FILE -u COMPOSE_PROJECT_NAME docker compose -p "$p" down); then
      rmdir "$empty" 2>/dev/null || true
      _RESTORE_ERROR_MSG="could not take down $p (docker compose -p $p down failed): nothing was restored${RESTORE_STOPPED_APPS:+ (already taken down: $RESTORE_STOPPED_APPS)}"
      [ "$hub_stopped" = true ] && return 1
      fail "$_RESTORE_ERROR_MSG"
    fi
    RESTORE_STOPPED_APPS="${RESTORE_STOPPED_APPS:+$RESTORE_STOPPED_APPS }$p"
  done
  rmdir "$empty" 2>/dev/null || true
  left=""
  for id in $(docker ps -aq --filter "volume=$vol"); do
    p="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id" 2>/dev/null || true)"
    [ "$p" = "$core" ] || left="${left:+$left }$id${p:+ ($p)}"
  done
  if [ -n "$left" ]; then
    _RESTORE_ERROR_MSG="containers still mount $vol after the down: $left — remove them, then restore again. Nothing was restored (taken down: $RESTORE_STOPPED_APPS)"
    [ "$hub_stopped" = true ] && return 1
    fail "$_RESTORE_ERROR_MSG"
  fi
}

backup_restore() {
  local dir="$1" yes="$2" allow_empty_lldap="${3:-false}" pre had_env=false key uid gid full spec proj helper
  require_cmd docker jq curl tar gzip
  [ -d "$dir" ] || fail "Backup directory not found: $dir"
  dir="$(cd "$dir" && pwd)"
  _backup_check_layout "$dir"
  _backup_check_manifest "$dir" || fail "checksum mismatch in $dir — refusing to restore a damaged backup"

  echo "This replaces .env, certs/, secrets/, the Vault data (raft snapshot), the Keycloak"
  echo "database (pg_dump) and$(for spec in $BACKUP_FILE_VOLUMES; do key="${spec%%:*}"; [ ! -f "$dir/$key.tar.gz" ] || printf ' %s' "$key"; done)"
  echo "with the backup from $(jq -r .created "$dir/MANIFEST.json") ($(jq -r '.domain' "$dir/MANIFEST.json"))."
  if [ "$yes" != true ]; then
    confirm "Continue with restore?" || { echo "Cancelled."; return 0; }
  fi

  [ -f "$(env_file)" ] && had_env=true
  # Stop the Hub so it can't restart secret apps, then take down the
  # file-sharing apps holding hub_secrets: all before anything changes
  # (contract §11.6; a failure here leaves everything as it was).
  hub_stopped=false
  if [ "$had_env" = true ]; then
    _backup_load_cfg
    info "Stopping Hub..."
    dc stop hub || fail "could not stop the Hub: nothing was restored"
    hub_stopped=true
    full="$(_volume_name hub_secrets)"
    if ! _restore_stop_secret_apps "${full:-portcullis_hub_secrets}" "$(_project_name)" true; then
      info "Restarting Hub..."
      if dc start hub 2>/dev/null; then
        fail "$_RESTORE_ERROR_MSG, Hub running again"
      else
        fail "$_RESTORE_ERROR_MSG, Hub was stopped but could not be restarted"
      fi
    fi
  else
    _restore_stop_secret_apps portcullis_hub_secrets portcullis false
  fi
  pre="$BACKUP_ROOT/pre-restore-$(date +%Y%m%d-%H%M%S)"
  if [ "$had_env" = true ]; then
    info "Saving the current .env, secrets/ and certs/ to $pre..."
    if ! (umask 077 && mkdir -p "$pre" && cp "$(env_file)" "$pre/.env" \
      && { [ ! -d "$PORTCULLIS_ROOT/secrets" ] || cp -a "$PORTCULLIS_ROOT/secrets" "$pre/secrets"; } \
      && { [ ! -d "$PORTCULLIS_ROOT/certs" ] || cp -a "$PORTCULLIS_ROOT/certs" "$pre/certs"; }); then
      if [ "$hub_stopped" = true ]; then
        info "Restarting Hub..."
        if dc start hub 2>/dev/null; then
          fail "could not save pre-restore copy: nothing was restored, Hub running again"
        else
          fail "could not save pre-restore copy: nothing was restored, Hub was stopped but could not be restarted"
        fi
      else
        fail "could not save pre-restore copy: nothing was restored"
      fi
    fi
    _backup_load_cfg
    info "Stopping services..."
    dc down
    hub_stopped=false  # dc down includes the Hub, so it's not independently stopped anymore
  fi

  # .env in place (keeps a symlink into config/ and the Hub's bind mount).
  if [ "$had_env" = true ]; then
    (umask 077 && cat "$dir/.env" > "$(env_file)")
  else
    (umask 077 && cp "$dir/.env" "$(env_file)")
  fi
  chmod 600 "$(env_file)" 2>/dev/null || true
  [ ! -f "$dir/realm-export.json" ] || cp "$dir/realm-export.json" "$PORTCULLIS_ROOT/keycloak/realm-export.json"
  if [ -f "$dir/headscale-config.yaml" ]; then
    mkdir -p "$PORTCULLIS_ROOT/headscale"
    cp "$dir/headscale-config.yaml" "$PORTCULLIS_ROOT/headscale/config.yaml"
  fi
  if [ -d "$dir/config" ]; then
    if [ -e "$PORTCULLIS_ROOT/config" ]; then
      warn "config/ exists — kept as is (the backup's copy: $dir/config)"
    else
      cp -a "$dir/config" "$PORTCULLIS_ROOT/config"
    fi
  fi
  if [ -f "$dir/docker-compose.override.yml" ] && [ ! -e "$PORTCULLIS_ROOT/docker-compose.override.yml" ]; then
    cp "$dir/docker-compose.override.yml" "$PORTCULLIS_ROOT/docker-compose.override.yml"
  fi
  if [ -d "$dir/certs" ]; then
    rm -rf "$PORTCULLIS_ROOT/certs.restore-tmp" && cp -a "$dir/certs" "$PORTCULLIS_ROOT/certs.restore-tmp"
    rm -rf "$PORTCULLIS_ROOT/certs" && mv "$PORTCULLIS_ROOT/certs.restore-tmp" "$PORTCULLIS_ROOT/certs"
  fi
  env_reload
  _BACKUP_CFG=""
  _backup_load_cfg
  proj="$(_project_name)"
  helper="$PORTCULLIS_HELPER_IMAGE"
  network_check

  # Fresh Postgres + Vault volumes for the logical restores. secrets/ is
  # restored only after the snapshot (Vault must start without an unseal key).
  for key in postgres_data vault_data; do
    full="$(_volume_name "$key")"
    docker volume rm -f "$full" >/dev/null 2>&1 || true
    ! docker volume inspect "$full" >/dev/null 2>&1 || fail "cannot remove volume $full (still in use? docker ps -a --filter volume=$full)"
  done
  rm -rf "$PORTCULLIS_ROOT/secrets"
  stack_prepare
  dc up -d --no-deps postgres vault
  _restore_pg "$dir"
  _restore_vault "$dir"

  for spec in $BACKUP_FILE_VOLUMES; do
    IFS=: read -r key uid gid <<< "$spec"
    [ -f "$dir/$key.tar.gz" ] || continue
    full="$(_volume_name "$key")"
    [ -n "$full" ] || { warn "Volume $key is not in the compose config — skipped."; continue; }
    info "Restoring volume $key..."
    docker volume rm -f "$full" >/dev/null 2>&1 || true
    docker volume create --label "com.docker.compose.project=$proj" --label "com.docker.compose.volume=$key" "$full" >/dev/null
    # tar as root keeps the archived ownership; the volume root belongs to the service user.
    docker run --rm --network none -v "$full:/data" -v "$dir:/backup:ro" "$helper" \
      sh -c "tar xzf '/backup/$key.tar.gz' -C /data && chown $uid:$gid /data" \
      || fail "could not restore volume $key"
  done

  # Empty hub_secrets (contract §11.6, file sharing): never backed up, and
  # a restore voids every credential. Remove and recreate with proper ownership.
  # Fail closed: a removal failure would leave old hashes in place.
  info "Emptying hub_secrets volume..."
  full="$(_volume_name hub_secrets)"
  [ -n "$full" ] || full="portcullis_hub_secrets"
  docker volume rm -f "$full" >/dev/null 2>&1 || true
  ! docker volume inspect "$full" >/dev/null 2>&1 || fail "cannot remove volume $full (still in use? docker ps -a --filter volume=$full)"
  docker volume create --label "com.docker.compose.project=$proj" --label "com.docker.compose.volume=hub_secrets" "$full" >/dev/null \
    || fail "could not create volume $full"
  # Ensure CT_UID_HUB:CT_UID_HUB 0700 (the Hub checks this at start).
  docker run --rm --network none -v "$full:/data" "$helper" \
    sh -c "chown $CT_UID_HUB:$CT_UID_HUB /data && chmod 0700 /data" \
    || fail "could not prepare hub_secrets volume"

  # Keycloak deletes its copy of a federated user — passkeys included —
  # as soon as a lookup (a sign-in attempt, the Hub's sweep) finds the user
  # missing in LDAP: never start it on an empty LLDAP over a Keycloak
  # database that has users.
  _restore_lldap_guard "$allow_empty_lldap" || return 1

  stack_prepare
  config_build_ca_bundle
  # Refreshes the enroll AppRole creds and the metrics token, verifies the
  # restored root token works.
  vault_init false
  # The core must come up; a non-core service (e.g. a Hub image that cannot
  # be pulled right now) must not abort a restore.
  dc up -d || warn "some services did not start — check ./portcullis status"
  wait_healthy 300 vault postgres lldap keycloak
  ok "Restore complete.${pre:+ Previous .env/secrets/certs: $pre.} Verify with ./portcullis status"
  if [ -n "$RESTORE_STOPPED_APPS" ]; then
    warn "Taken down for the restore and NOT started again: $RESTORE_STOPPED_APPS. Their file-share passwords were voided by the restore (people create new ones on My apps). Start each one again from the Hub: its drift shows it as not running (resolve the drift there, or restart the app)."
  fi
}

# ── schedule ───────────────────────────────────────────────

# backup_schedule_systemd <on-calendar> <output-dir|"">
backup_schedule_systemd() {
  local cal="$1" out="$2" user offsite="" svc timer env_line=""
  user="$(id -un)"
  [ -z "${BACKUP_REPOSITORY:-}" ] || offsite=" --offsite"
  [ "$PORTCULLIS_ROOT" = "$PORTCULLIS_HOME" ] || env_line="Environment=PORTCULLIS_ROOT=$PORTCULLIS_ROOT"
  svc="$(cat <<EOF
# portcullis-backup.service — generated by ./portcullis backup schedule --systemd
[Unit]
Description=Portcullis backup$( [ -n "$offsite" ] && echo " (local + off-host, restic)" || echo " (local only: BACKUP_REPOSITORY is not set)")
Wants=network-online.target
After=network-online.target docker.service
Requires=docker.service

[Service]
Type=oneshot
User=$user
WorkingDirectory=$PORTCULLIS_ROOT
Environment=NO_COLOR=1
${env_line}
ExecStart=$PORTCULLIS_HOME/portcullis backup$offsite
# Client-cert / CA expiry and service health for the monitoring profile
# (runs even when the backup failed).
ExecStopPost=-$PORTCULLIS_HOME/portcullis status --textfile
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=2h
EOF
)"
  timer="$(cat <<EOF
# portcullis-backup.timer — generated by ./portcullis backup schedule --systemd
[Unit]
Description=Daily Portcullis backup

[Timer]
OnCalendar=$cal
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
EOF
)"
  if [ -n "$out" ]; then
    mkdir -p "$out"
    printf '%s\n' "$svc" > "$out/portcullis-backup.service"
    printf '%s\n' "$timer" > "$out/portcullis-backup.timer"
    ok "Wrote $out/portcullis-backup.service and portcullis-backup.timer"
    cat <<EOF
Install (as root):
  install -m 0644 $out/portcullis-backup.service $out/portcullis-backup.timer /etc/systemd/system/
  systemctl daemon-reload && systemctl enable --now portcullis-backup.timer
  systemctl start portcullis-backup.service   # run once now; journalctl -u portcullis-backup
EOF
  else
    printf '%s\n\n%s\n' "$svc" "$timer"
  fi
}

# ── help / commands ────────────────────────────────────────

help_backup() {
  cat <<'EOF'
Usage: portcullis backup [--offsite] [--list [--json]]
       portcullis backup verify [--local [DIR] | --snapshot ID]
       portcullis backup schedule --systemd [--on-calendar SPEC] [--output DIR]

Create a consistent backup in backups/<timestamp>/ (0700) while everything
keeps running: Vault raft snapshot, pg_dump of the Keycloak database,
LLDAP / Hub / ACME / domains (age-encrypted) volumes (SQLite via its online backup API), .env,
certs/, secrets/, config/ and config files, plus MANIFEST.json with the
sha256 of every file. Keeps the newest BACKUP_KEEP_LOCAL (7) local backups.

The backup contains secrets/ — the Vault ROOT TOKEN and UNSEAL KEY — so it
can decrypt the CA and every secret. Protect it like the keys.

Options:
  --offsite   also upload it to the restic repository BACKUP_REPOSITORY,
              encrypted with BACKUP_PASSWORD (keep that password OFFLINE:
              without it the off-host copies are useless, with it they
              are the keys to everything), then apply the retention
              BACKUP_KEEP_DAILY/WEEKLY/MONTHLY (7/4/6)
  --list      list local backups (with --offsite: the restic snapshots;
              --json for restic's JSON)

Subcommands: verify, schedule (see 'portcullis backup <sub> --help').
See docs/backups.md.
EOF
}

help_backup_verify() {
  cat <<'EOF'
Usage: portcullis backup verify [--snapshot ID]
       portcullis backup verify --local [DIR]

Off-host (default): `restic check` (reading BACKUP_VERIFY_READ_DATA = 10%
of the pack data), restore the latest snapshot (or ID) into a temporary
directory, then check it. --local checks a local backup instead (DIR,
default the newest in backups/). The checks:
  - every file matches MANIFEST.json, .env / secrets/ are complete
  - vault.snap is a raft snapshot (meta.json, state.bin, SHA256SUMS ok)
  - postgres.dump restores into a throwaway postgres container (no
    network) and contains the Keycloak realms
  - the LLDAP database opens, passes integrity_check and has users
  - every volume archive is readable
Exits non-zero if anything fails.
EOF
}

help_backup_schedule() {
  cat <<'EOF'
Usage: portcullis backup schedule --systemd [--on-calendar SPEC] [--output DIR]

Print (or write to DIR) a systemd service + timer that run
`portcullis backup --offsite` (just `backup` while BACKUP_REPOSITORY is
unset) as the current user, followed by `portcullis status --textfile`
(metrics for the monitoring profile). The user must be able to run docker.

Options:
  --systemd           generate systemd units (the only scheduler supported)
  --on-calendar SPEC  systemd OnCalendar (default: *-*-* 03:15:00, plus up
                      to 30 minutes random delay)
  --output DIR        write portcullis-backup.service/.timer into DIR and
                      print the install commands
EOF
}

help_restore() {
  cat <<'EOF'
Usage: portcullis restore [--yes] [--allow-empty-lldap] <backup-dir>
       portcullis restore [--yes] [--allow-empty-lldap] --from-offsite [SNAPSHOT]
       portcullis restore --list [--offsite]

Stop Portcullis and restore a backup made by `portcullis backup` /
`upgrade`: .env, certs/, secrets/, config files, the Vault data (the raft
snapshot is restored into a fresh Vault, which then unseals with the
backed-up key), the Keycloak database (pg_restore into a fresh Postgres),
the LLDAP / Hub / ACME / domains volumes. Then everything is started again. The
backup's checksums are verified first. The current .env, secrets/ and
certs/ are saved to backups/pre-restore-<timestamp>/.

App projects with a container mounting hub_secrets (file sharing: Samba,
Time Machine) are taken down first (volumes kept) — a failure there
changes nothing — and are NOT started again: the restore voids every
file-share password. Start them again from the Hub.

--from-offsite restores SNAPSHOT (default: latest) from BACKUP_REPOSITORY.
On a new host without .env, export BACKUP_REPOSITORY, BACKUP_PASSWORD and
the provider credentials first (the .env comes from the backup).

Before starting Keycloak, restore checks LLDAP: if it has no users (the
backup had no lldap_data.tar.gz and the volume is empty) while the restored
Keycloak database has users, it stops with Postgres and Vault up and
nothing else started — Keycloak would delete those users' copies, passkeys
included, at their next lookup.

Options:
  -y, --yes          do not ask for confirmation
  --allow-empty-lldap  start even if LLDAP has no users (their Keycloak
                     copies and passkeys are then removed)
  --from-offsite     restore from the restic repository
  --list             list local backups (--offsite: restic snapshots)
EOF
}

cmd_backup() {
  local offsite=false list=false json=false sub="" snap="" ldir="" local_only=false systemd=false cal="*-*-* 03:15:00" out=""
  case "${1:-}" in
    verify|schedule) sub="$1"; shift ;;
  esac
  while [ $# -gt 0 ]; do
    case "$sub:$1" in
      *:-h|*:--help) if [ -n "$sub" ]; then "help_backup_$sub"; else help_backup; fi; return 0 ;;
      :--offsite) offsite=true ;;
      :--list) list=true ;;
      :--json) json=true ;;
      verify:--snapshot) need_value "backup verify" "$1" "${2:-}"; snap="$2"; shift ;;
      verify:--local)
        local_only=true
        if [ -n "${2:-}" ] && [ "${2#-}" = "$2" ]; then ldir="$2"; shift; fi ;;
      schedule:--systemd) systemd=true ;;
      schedule:--on-calendar) need_value "backup schedule" "$1" "${2:-}"; cal="$2"; shift ;;
      schedule:--output) need_value "backup schedule" "$1" "${2:-}"; out="$2"; shift ;;
      *) usage_error "backup${sub:+ $sub}" "unknown argument: $1" ;;
    esac
    shift
  done
  case "$sub" in
    verify)
      [ "$local_only" = false ] || [ -z "$snap" ] || usage_error "backup verify" "--local and --snapshot are exclusive"
      if [ -n "$ldir" ]; then
        case "$ldir" in /*) ;; *) if [ -d "$PORTCULLIS_CALLER_PWD/$ldir" ]; then ldir="$PORTCULLIS_CALLER_PWD/$ldir"; else ldir="$PORTCULLIS_ROOT/$ldir"; fi ;; esac
      fi
      need_env
      backup_verify "$snap" "$ldir" "$local_only"
      return ;;
    schedule)
      [ "$systemd" = true ] || usage_error "backup schedule" "--systemd is required (the only scheduler supported)"
      [ ! -f "$(env_file)" ] || env_load
      backup_schedule_systemd "$cal" "$out"
      return ;;
  esac
  [ "$json" = false ] || { [ "$list" = true ] && [ "$offsite" = true ]; } || usage_error backup "--json only goes with --list --offsite"
  if [ "$list" = true ]; then
    if [ "$offsite" = true ]; then
      need_env
      if [ "$json" = true ]; then backup_snapshots --json; else backup_snapshots; fi
    else
      backup_list
    fi
    return 0
  fi
  need_env
  backup_create
  [ "$offsite" = false ] || backup_offsite "$BACKUP_LAST_DIR"
}

cmd_restore() {
  local yes=false dir="" offsite=false list=false snap="" tmp allow=false
  while [ $# -gt 0 ]; do
    case "$1" in
      --list) list=true ;;
      --offsite) offsite=true ;;
      --from-offsite) offsite=true ;;
      -y|--yes) yes=true ;;
      --allow-empty-lldap) allow=true ;;
      -h|--help) help_restore; return 0 ;;
      -*) usage_error restore "unknown option: $1" ;;
      *) [ -z "$dir" ] || usage_error restore "unexpected argument: $1"; dir="$1" ;;
    esac
    shift
  done
  if [ "$list" = true ]; then
    if [ "$offsite" = true ]; then need_env; backup_snapshots; else backup_list; fi
    return 0
  fi
  if [ "$offsite" = true ]; then
    snap="${dir:-latest}"
    # A new host has no .env yet: BACKUP_* come from the environment.
    [ ! -f "$(env_file)" ] || env_load
    require_cmd docker jq
    tmp="$BACKUP_ROOT/offsite-$(date +%Y%m%d-%H%M%S)"
    _restic_require
    info "Restoring snapshot $snap from $BACKUP_REPOSITORY into $tmp..."
    dir="$(_restic_restore_to "$snap" "$tmp")"
    backup_restore "$dir" "$yes" "$allow"
    return
  fi
  [ -n "$dir" ] || usage_error restore "expected <backup-dir> or --from-offsite (see --list)"
  # Relative paths: from where the command was run, else from the checkout.
  case "$dir" in
    /*) ;;
    *) if [ -d "$PORTCULLIS_CALLER_PWD/$dir" ]; then dir="$PORTCULLIS_CALLER_PWD/$dir"; else dir="$PORTCULLIS_ROOT/$dir"; fi ;;
  esac
  need_env
  backup_restore "$dir" "$yes" "$allow"
}
