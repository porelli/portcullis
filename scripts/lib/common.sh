# shellcheck shell=bash
#
# Shared helpers for the `portcullis` CLI: output, .env handling, secret
# generation, docker compose wrappers, health waits. Sourced by ./portcullis
# (and by tests); never executed directly. Bash 3.2 compatible (macOS).
#
# Globals (set by ./portcullis before sourcing, overridable for tests):
#   PORTCULLIS_ROOT   installation root: .env, certs/, secrets/, compose files
#   PORTCULLIS_HOME   the checkout itself (defaults to this lib's ../..)
#   PORTCULLIS_LIB    this directory

PORTCULLIS_LIB="${PORTCULLIS_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
PORTCULLIS_ROOT="${PORTCULLIS_ROOT:-$(cd "$PORTCULLIS_LIB/../.." && pwd)}"
# The checkout (CLI, compose file, VERSION); set by ./portcullis.
PORTCULLIS_HOME="${PORTCULLIS_HOME:-$(cd "$PORTCULLIS_LIB/../.." && pwd)}"

# ── Output ─────────────────────────────────────────────────

# shellcheck disable=SC2034  # colours are used across the libs
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RED=$'\033[0;31m' C_GREEN=$'\033[0;32m' C_BLUE=$'\033[0;34m'
  C_YELLOW=$'\033[1;33m' C_CYAN=$'\033[0;36m' C_DIM=$'\033[2m' C_NC=$'\033[0m'
else
  C_RED='' C_GREEN='' C_BLUE='' C_YELLOW='' C_CYAN='' C_DIM='' C_NC=''
fi

info() { printf '%s==>%s %s\n' "$C_BLUE" "$C_NC" "$*"; }
ok()   { printf '%s==>%s %s\n' "$C_GREEN" "$C_NC" "$*"; }
warn() { printf '%s==>%s %s\n' "$C_YELLOW" "$C_NC" "$*" >&2; }
fail() { printf '%sERROR:%s %s\n' "$C_RED" "$C_NC" "$*" >&2; exit 1; }

# usage_error <command> <message> — bad invocation: exit 2 with a hint.
usage_error() {
  printf 'portcullis %s: %s\n' "$1" "$2" >&2
  printf "Run 'portcullis %s --help' for usage.\n" "$1" >&2
  exit 2
}

# need_value <command> <option> <next-arg> — for "--opt VALUE" parsing.
need_value() {
  [ -n "${3:-}" ] && [ "${3#-}" = "$3" ] || usage_error "$1" "$2 needs a value"
}

require_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || fail "$c is required but not installed"
  done
}

# confirm <prompt> — y/N question; false when stdin is not a terminal.
confirm() {
  local reply
  [ -t 0 ] || return 1
  read -rp "$1 [y/N] " reply
  case "$reply" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ── .env ───────────────────────────────────────────────────
#
# .env is PARSED, never sourced: the Hub container can write to it, so
# sourcing it would let the Hub run code as the operator. Semantics follow
# docker compose: KEY=VALUE, optional `export `, single/double quotes are
# stripped, ` #...` after an unquoted value is a comment. Variables that are
# already set in the environment win (the same precedence compose uses).

env_file() { echo "$PORTCULLIS_ROOT/.env"; }

# _env_parse_line <line> — on success sets _ENV_KEY / _ENV_VAL.
_env_parse_line() {
  local line="$1" val
  [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]] || return 1
  _ENV_KEY="${BASH_REMATCH[2]}"
  val="${BASH_REMATCH[3]}"
  val="${val%$'\r'}"
  if [[ "$val" =~ ^\"(.*)\"[[:space:]]*(#.*)?$ ]] || [[ "$val" =~ ^\'(.*)\'[[:space:]]*(#.*)?$ ]]; then
    val="${BASH_REMATCH[1]}"
  else
    val="$(printf '%s' "$val" | sed -E 's/[[:space:]]+#.*$//; s/[[:space:]]+$//')"
  fi
  _ENV_VAL="$val"
}

# env_load [file] — export every KEY=VALUE from .env that is not already set.
env_load() {
  local file="${1:-$(env_file)}" line
  [ -f "$file" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    _env_parse_line "$line" || continue
    [ -n "${!_ENV_KEY+x}" ] && continue
    export "$_ENV_KEY=$_ENV_VAL"
  done < "$file"
}

# env_reload [file] — like env_load, but values from the file replace
# whatever is in the environment (after the file itself was replaced).
env_reload() {
  local file="${1:-$(env_file)}" line
  [ -f "$file" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    _env_parse_line "$line" && unset "$_ENV_KEY"
  done < "$file"
  env_load "$file"
}

# env_get <key> [file] — value of key in the file (not the environment).
env_get() {
  local file="${2:-$(env_file)}" line out=""
  [ -f "$file" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    _env_parse_line "$line" || continue
    [ "$_ENV_KEY" = "$1" ] && out="$_ENV_VAL"
  done < "$file"
  printf '%s' "$out"
}

# env_set <key> <value> [file] — replace or append KEY=VALUE.
# Rewrites the file IN PLACE (same inode): .env is bind-mounted into the
# Hub and may be a symlink into config/; a rename would break both.
env_set() {
  local key="$1" value="$2" file="${3:-$(env_file)}" tmp
  [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || fail "env_set: bad key '$key'"
  case "$value" in *$'\n'*) fail "env_set: value for $key contains a newline" ;; esac
  tmp="$(mktemp)"
  if [ -f "$file" ] && grep -Eq "^[[:space:]]*(export[[:space:]]+)?${key}=" "$file"; then
    KEY="$key" VALUE="$value" awk '
      BEGIN { k = ENVIRON["KEY"]; v = ENVIRON["VALUE"] }
      $0 ~ "^[[:space:]]*(export[[:space:]]+)?" k "=" { if (!done) print k "=" v; done = 1; next }
      { print }' "$file" > "$tmp"
  else
    if [ -s "$file" ]; then
      cat "$file" > "$tmp"
      [ -z "$(tail -c1 "$file")" ] || echo >> "$tmp"
    fi
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
  fi
  cat "$tmp" > "$file"
  rm -f "$tmp"
}

# env_unset <key> [file] — remove every KEY= line, in place (like env_set).
env_unset() {
  local key="$1" file="${2:-$(env_file)}" tmp
  [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || fail "env_unset: bad key '$key'"
  [ -f "$file" ] || return 0
  grep -Eq "^[[:space:]]*(export[[:space:]]+)?${key}=" "$file" || return 0
  tmp="$(mktemp)"
  KEY="$key" awk 'BEGIN { k = ENVIRON["KEY"] } $0 !~ "^[[:space:]]*(export[[:space:]]+)?" k "=" { print }' "$file" > "$tmp"
  cat "$tmp" > "$file"
  rm -f "$tmp"
}

# need_env — load .env (fail if missing), then check the container runtime
# (CONTAINER_RUNTIME, the engine behind it: scripts/lib/runtime.sh).
need_env() {
  [ -f "$(env_file)" ] || fail "$(env_file) not found. Run ./portcullis init first."
  env_load
  runtime_check
}

# env_require <var>... — fail listing every unset/empty variable.
env_require() {
  local v missing=""
  for v in "$@"; do
    [ -n "${!v:-}" ] || missing="$missing $v"
  done
  [ -z "$missing" ] || fail "missing in .env:$missing (./portcullis init generates them)"
}

# Secrets every core service needs (docker-compose.yml uses ${VAR:?}).
# shellcheck disable=SC2034  # used by stack.sh
CORE_SECRETS="POSTGRES_PASSWORD KEYCLOAK_ADMIN_PASSWORD LLDAP_ADMIN_PASSWORD LLDAP_JWT_SECRET FORWARD_AUTH_CLIENT_SECRET FORWARD_AUTH_COOKIE_SECRET FORWARD_AUTH_REDIS_PASSWORD FORWARD_AUTH_EXT_REDIS_PASSWORD HUB_PROXY_SECRET"
# Subset that can be (re)generated on an existing install without losing
# data: nothing on disk is encrypted with them, `portcullis oidc register`
# pushes FORWARD_AUTH_CLIENT_SECRET to Keycloak, and the session store's
# config (secrets/sessions/valkey.conf) is rewritten from the two
# *_REDIS_PASSWORDs on every run (a new one only ends that proxy's sessions).
# shellcheck disable=SC2034
ROTATABLE_SECRETS="LLDAP_JWT_SECRET FORWARD_AUTH_CLIENT_SECRET FORWARD_AUTH_COOKIE_SECRET FORWARD_AUTH_REDIS_PASSWORD FORWARD_AUTH_EXT_REDIS_PASSWORD HUB_PROXY_SECRET"

# Encrypts the off-host (restic) backups. Generated by init/upgrade when
# missing (no repository can depend on a password that does not exist yet);
# NEVER rotate it by emptying it: the repository keeps the old one.
# shellcheck disable=SC2034  # used by stack.sh
BACKUP_SECRETS="BACKUP_PASSWORD"

# ── Secret generation ──────────────────────────────────────

# gen_alnum <len> — random [A-Za-z0-9]{len}. No pipe into `head` (SIGPIPE
# under pipefail); openssl output is long enough for len <= 64.
gen_alnum() {
  local n="${1:-32}" s
  s="$(openssl rand -base64 96 | LC_ALL=C tr -dc 'A-Za-z0-9')"
  [ "${#s}" -ge "$n" ] || fail "random generation failed"
  printf '%s' "${s:0:$n}"
}

# gen_cookie_secret — oauth2-proxy needs 16/24/32 bytes: base64url of 32
# random bytes (44 chars incl. padding).
gen_cookie_secret() { openssl rand -base64 32 | tr -- '+/' '-_'; }

# gen_secret_for <VAR> — the right kind of value for each core secret.
gen_secret_for() {
  case "$1" in
    FORWARD_AUTH_COOKIE_SECRET) gen_cookie_secret ;;
    HUB_PROXY_SECRET) openssl rand -hex 32 ;;
    FORWARD_AUTH_CLIENT_SECRET|FORWARD_AUTH_REDIS_PASSWORD|FORWARD_AUTH_EXT_REDIS_PASSWORD) gen_alnum 40 ;;
    LLDAP_JWT_SECRET|BACKUP_PASSWORD) gen_alnum 48 ;;
    *) gen_alnum 24 ;;
  esac
}

# env_generate_missing <var>... — generate + persist every empty/unset var
# (reads the FILE, so a value only exported in the shell does not count).
env_generate_missing() {
  local v
  for v in "$@"; do
    if [ -z "$(env_get "$v")" ]; then
      env_set "$v" "$(gen_secret_for "$v")"
      unset "$v"
      info "Generated $v in .env"
    fi
  done
  env_load
}

# ── docker compose ─────────────────────────────────────────

# dc <args> — docker compose for the core project. COMPOSE_FILE (e.g. CI
# overrides) is honoured because we run from the project root.
dc() { docker compose --project-directory "$PORTCULLIS_ROOT" "$@"; }

# container_health <service> — healthy|unhealthy|starting|running|exited|missing
container_health() {
  local cid st
  cid="$(dc ps -q "$1" 2>/dev/null | head -n1)"
  [ -n "$cid" ] || { echo missing; return 0; }
  st="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null)"
  echo "${st:-missing}"
}

# wait_healthy <timeout-seconds> <service>... — fail on timeout.
wait_healthy() {
  local timeout="$1" svc i st
  shift
  for svc in "$@"; do
    printf '  waiting for %s...' "$svc"
    st=""
    for ((i = 0; i < timeout; i += 3)); do
      st="$(container_health "$svc")"
      [ "$st" = healthy ] && break
      sleep 3
    done
    if [ "$st" = healthy ]; then
      printf ' %sready%s\n' "$C_GREEN" "$C_NC"
    else
      printf ' %stimeout (%s)%s\n' "$C_RED" "$st" "$C_NC"
      fail "$svc did not become healthy in ${timeout}s. Check: docker compose logs $svc"
    fi
  done
}

# ── Container identities and host file ownership ──────────
#
# Every core container runs as a fixed non-root uid/gid (docker-compose.yml
# `user:` or the image's USER). Host files they read through bind mounts
# are owned by the operator, with the container's GID as group and mode
# 0640 (dirs 0750), so the operator keeps full control and nobody else
# can read them.
# shellcheck disable=SC2034  # some are only used by other libs
CT_GID_VAULT=1000     # hashicorp/vault: vault = 100:1000
CT_UID_HUB=10001      # ghcr.io/porelli/portcullis-hub (USER 10001:10001)
CT_UID_ENROLL=10002   # enroll/Dockerfile (USER 10002:10002)
# shellcheck disable=SC2034  # used by backup.sh
CT_UID_GROUP_GATE=10003 # group-gate/Dockerfile (USER 10003:10003, + group 10001)
# shellcheck disable=SC2034  # used by domains.sh / backup.sh
CT_UID_DOMAINS=10004  # domains/Dockerfile (USER 10004:10004)
# shellcheck disable=SC2034  # used by mcpgate.sh / backup.sh
CT_UID_MCP_GATE=10005 # mcp-gate/Dockerfile (USER 10005:10005, + group 10001)
CT_GID_TRAEFIK=0      # Traefik runs as root, but without CAP_DAC_OVERRIDE
# shellcheck disable=SC2034  # used by sessions.sh
CT_UID_SESSIONS=999   # valkey/valkey alpine: valkey = 999:1000 (compose user: "999:1000")
# shellcheck disable=SC2034  # used by sessions.sh
CT_GID_SESSIONS=1000
# shellcheck disable=SC2034  # used by backup.sh
CT_UID_LLDAP=1000     # lldap/lldap:*-rootless (lldap_data is 1000-owned)
# Throwaway container used to chown/chgrp when not running as root (the
# operator can run docker, i.e. is root-equivalent anyway).
PORTCULLIS_HELPER_IMAGE="alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a"

# _owner_of <path> — "uid:gid" on the host (GNU or BSD stat).
_owner_of() { stat -c '%u:%g' "$1" 2>/dev/null || stat -f '%u:%g' "$1"; }

# Container ids vs host ids. Docker (rootful): the same. Rootless Podman:
# every container shares the operator's default user namespace, so
# container id 0 is the operator and 1 ≤ c < 65536 is subuid_start + c − 1
# (scripts/lib/runtime.sh runtime_id_maps, from the live map — never a
# guess). Container root is the OPERATOR there: files the operator must
# keep are chowned to "$(ct_operator_id):<gid>", never "$(id -u):…" (that
# would hand them to a subordinate id).

# ct_operator_id — the container uid that is the operator on the host.
ct_operator_id() {
  if _rt_is_podman; then echo 0; else id -u; fi
}

# _ct_maps — the rootless id map (cached); an unreadable or unexpected map refuses.
_ct_maps() {
  [ -z "${_RT_UID_START:-}" ] || return 0
  runtime_id_maps || fail "can't read the rootless id map (podman unshare cat /proc/self/uid_map and gid_map): 0 must map to the operator and 1… to one range of at least $RT_MIN_IDS subordinate ids (/etc/subuid, /etc/subgid)"
}

# _ct_to_host <op> <start> <count> <container id> — the host id, or exit 1.
_ct_to_host() {
  case "$4" in ''|*[!0-9]*) return 1 ;; esac
  if [ "$4" -eq 0 ]; then echo "$1"
  elif [ "$4" -le "$3" ] && [ "$4" -lt 65536 ]; then echo $(($2 + $4 - 1))
  else return 1; fi
}

# ct_host_id <c> / ct_host_gid <c> — the host uid / gid of container id c
# (docker: c itself); an id outside the map exits 1.
ct_host_id() {
  if ! _rt_is_podman; then echo "$1"; return 0; fi
  _ct_maps
  _ct_to_host "$_RT_UID_OP" "$_RT_UID_START" "$_RT_UID_N" "$1" || { echo "container uid $1 is outside the rootless id map" >&2; return 1; }
}
ct_host_gid() {
  if ! _rt_is_podman; then echo "$1"; return 0; fi
  _ct_maps
  _ct_to_host "$_RT_GID_OP" "$_RT_GID_START" "$_RT_GID_N" "$1" || { echo "container gid $1 is outside the rootless id map" >&2; return 1; }
}

# _ct_from_host <op> <start> <count> <host id> — the container id, or exit 1.
_ct_from_host() {
  if [ "$4" = "$1" ]; then echo 0
  elif [ "$4" -ge "$2" ] && [ "$4" -lt $(($2 + $3)) ] && [ $(($4 - $2 + 1)) -lt 65536 ]; then echo $(($4 - $2 + 1))
  else return 1; fi
}

# _owner_of_ct <path> — "uid:gid" in container ids (docker: the host ids);
# "unmapped" when either side is outside the rootless map (host root,
# another account: shown as 65534 inside).
_owner_of_ct() {
  local own u g cu cg
  own="$(_owner_of "$1")" || return 1
  _rt_is_podman || { echo "$own"; return 0; }
  _ct_maps
  u="${own%%:*}" g="${own#*:}"
  if cu="$(_ct_from_host "$_RT_UID_OP" "$_RT_UID_START" "$_RT_UID_N" "$u")" \
     && cg="$(_ct_from_host "$_RT_GID_OP" "$_RT_GID_START" "$_RT_GID_N" "$g")"; then
    echo "$cu:$cg"
  else
    echo unmapped
  fi
}

# _sq <string> — the string single-quoted for a POSIX shell (each embedded
# ' as '\''), so a pasted hint never runs anything but the command.
_sq() { printf "'%s'" "${1//\'/\'\\\'\'}"; }

# ct_hint_chown <uid:gid> <path>... — the command that fixes an owner by
# hand, every path single-quoted.
ct_hint_chown() {
  local spec="$1" p out=""
  shift
  for p in "$@"; do out+=" $(_sq "$p")"; done
  if _rt_is_podman; then echo "podman unshare chown $spec$out"; else echo "sudo chown $spec$out"; fi
}

# ct_run <docker run args...> — `docker run` for the CLI's own short-lived
# helper containers that bind-mount host files (restores, restic). Under
# rootless Podman they run with `--security-opt label=disable`: on an
# SELinux-enforcing host a confined helper can't touch checkout files, and
# relabelling backups/ or secrets/ (z / Z) is forbidden. These are our own
# pinned images, run on the operator's command for seconds; long-running
# compose services never get label=disable (only the two socket proxies,
# docker-compose.podman-selinux.yml, CI-linted). Docker: unchanged.
ct_run() {
  if _rt_is_podman; then
    docker run --security-opt label=disable "$@"
  else
    docker run "$@"
  fi
}

# ct_own <uid:gid> <path>... — chown the paths to these CONTAINER ids (no-op
# for those already right). Docker: as root directly, otherwise via a
# throwaway root container with only CAP_CHOWN and no network. Rootless
# Podman: `podman unshare chown` (the same user namespace as every
# container, so 10001 writes the host's subuid+10000; no container, no bind
# mount, nothing relabelled), never chown directly.
ct_own() {
  local spec="$1" p i=0 podman=false todo=() mounts=() targets=()
  shift
  if _rt_is_podman; then podman=true; _ct_maps; fi
  for p in "$@"; do
    [ -e "$p" ] || continue
    if [ "$podman" = true ]; then
      [ "$(_owner_of_ct "$p")" = "$spec" ] || todo+=("$p")
    else
      [ "$(_owner_of "$p")" = "$spec" ] || todo+=("$p")
    fi
  done
  [ "${#todo[@]}" -gt 0 ] || return 0
  if [ "$podman" = true ]; then
    podman unshare chown -- "$spec" "${todo[@]}" >/dev/null \
      || fail "could not chown ${todo[*]} to $spec (try: $(ct_hint_chown "$spec" "${todo[@]}"))"
    return
  fi
  if [ "$(id -u)" = 0 ]; then
    chown "$spec" "${todo[@]}"
    return
  fi
  for p in "${todo[@]}"; do
    p="$(cd "$(dirname "$p")" && pwd)/$(basename "$p")"
    mounts+=(--mount "type=bind,src=$p,dst=/t/$i")
    targets+=("/t/$i")
    i=$((i + 1))
  done
  docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN \
    --security-opt no-new-privileges:true "${mounts[@]}" "$PORTCULLIS_HELPER_IMAGE" \
    chown "$spec" "${targets[@]}" >/dev/null \
    || fail "could not chown ${todo[*]} to $spec (try: $(ct_hint_chown "$spec" "${todo[@]}"))"
}

# volume_own <volume> <uid:gid> — make sure the compose named volume exists
# and its top directory belongs to <uid:gid>. Needed for volumes shared by
# several services: whichever container starts first creates the volume, and
# if its image lacks the mountpoint (e.g. group-gate mounting hub_data
# read-only) the volume starts root-owned and Docker never copies the owning
# image's ownership in. Created with compose's labels so compose adopts it.
volume_own() {
  local vol="$1" spec="$2" project="${COMPOSE_PROJECT_NAME:-portcullis}" name
  name="${project}_$vol"
  if ! docker volume inspect "$name" >/dev/null 2>&1; then
    docker volume create --label "com.docker.compose.project=$project" \
      --label "com.docker.compose.volume=$vol" "$name" >/dev/null \
      || fail "could not create the Docker volume $name"
  fi
  # shellcheck disable=SC2016  # $1 is expanded by the container's sh
  docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN \
    --security-opt no-new-privileges:true --mount "type=volume,src=$name,dst=/v" \
    "$PORTCULLIS_HELPER_IMAGE" sh -c '[ "$(stat -c %u:%g /v)" = "$1" ] || chown "$1" /v' _ "$spec" >/dev/null \
    || fail "could not set the owner of volume $name to $spec"
}

# ct_group_read <gid> <path>... — operator-owned, group <gid>: dirs 0750,
# files 0640. For secrets a non-root container must read.
ct_group_read() {
  local gid="$1" p
  shift
  for p in "$@"; do
    [ -e "$p" ] || continue
    if [ -d "$p" ]; then chmod 750 "$p"; else chmod 640 "$p"; fi
  done
  ct_own "$(ct_operator_id):$gid" "$@"
}

# secrets_fix_perms — ownership/modes of everything under secrets/ that a
# container reads. Idempotent (also repairs a restored backup).
secrets_fix_perms() {
  local s="$PORTCULLIS_ROOT/secrets"
  chmod 700 "$s" 2>/dev/null || true
  [ ! -e "$s/vault-init.json" ] || chmod 600 "$s/vault-init.json"
  ct_group_read "$CT_GID_VAULT" "$s/vault-unseal" "$s/vault-unseal/unseal-key"
  ct_group_read "$CT_UID_ENROLL" "$s/enroll" "$s/enroll/role-id" "$s/enroll/secret-id" \
    "$s/enroll/invite-client-secret" "$s/enroll/keycloak-client-secret" "$s/enroll/invite-api-secret"
  ct_group_read "$CT_UID_HUB" "$s/hub" "$s/hub/core.env" \
    "$s/hub/lldap" "$s/hub/lldap/username" "$s/hub/lldap/password" "$s/hub/invite" "$s/hub/invite/secret"
  # secrets/monitoring/ (scripts/lib/monitoring.sh)
  if declare -F monitoring_fix_perms >/dev/null; then monitoring_fix_perms; fi
  # secrets/domains/ (scripts/lib/domains.sh)
  if declare -F domains_fix_perms >/dev/null; then domains_fix_perms; fi
  # secrets/mcp-gate/ (scripts/lib/mcpgate.sh)
  if declare -F mcpgate_fix_perms >/dev/null; then mcpgate_fix_perms; fi
  # secrets/sessions/ (scripts/lib/sessions.sh)
  if declare -F sessions_fix_perms >/dev/null; then sessions_fix_perms; fi
}

# Core variables the Hub may copy into app .env files (templates reference
# them as ${VAR}); everything else in .env is a core secret the Hub never
# sees. Operators can add names via HUB_SHARED_ENV="VAR1 VAR2".
HUB_ENV_VARS="PORTCULLIS_DOMAIN PORTCULLIS_TRAEFIK_IP PORTCULLIS_MCP_GATE_IP PORTCULLIS_PROXY_SUBNET PORTCULLIS_PROXY_IP_RANGE PORTAL_DISPLAY_NAME"
HUB_ENV_PREFIXES="HEADSCALE_ HEADPLANE_ NETBIRD_ COTURN_"

# hub_env_write — secrets/hub/core.env, mounted read-only as the Hub's
# /project/.env. Values as compose sees them (environment over .env, compose
# defaults). Rewritten IN PLACE (same inode) so the running Hub's
# single-file bind mount sees the update. Call after env_load.
hub_env_write() {
  local f="$PORTCULLIS_ROOT/secrets/hub/core.env" v pre val content=""
  local -a names=()
  # shellcheck disable=SC2206  # word splitting intended
  names=($HUB_ENV_VARS ${HUB_SHARED_ENV:-})
  for pre in $HUB_ENV_PREFIXES; do
    while IFS= read -r v; do names+=("$v"); done < <(compgen -e | grep "^$pre" || true)
  done
  for v in "${names[@]}"; do
    [[ "$v" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    case " $CORE_SECRETS " in *" $v "*) warn "HUB_SHARED_ENV: refusing to share core secret $v with the Hub"; continue ;; esac
    case "$content" in "$v="*|*$'\n'"$v="*) continue ;; esac
    # Written below from the host (podman only), never shared by name.
    [ "$v" != PORTCULLIS_UNPRIVILEGED_PORT_START ] || continue
    case "$v" in
      PORTCULLIS_DOMAIN) val="${PORTCULLIS_DOMAIN:-portcullis.local}" ;;
      PORTCULLIS_TRAEFIK_IP) val="$(proxy_traefik_ip)" ;;
      PORTCULLIS_MCP_GATE_IP) val="$(mcp_gate_ip)" ;;
      PORTCULLIS_PROXY_SUBNET) val="$(proxy_subnet)" ;;
      PORTCULLIS_PROXY_IP_RANGE) val="$(proxy_ip_range)" ;;
      PORTAL_DISPLAY_NAME) val="${PORTAL_DISPLAY_NAME:-Portcullis}" ;;
      *) val="${!v:-}" ;;
    esac
    content+="$v=$val"$'\n'
  done
  # Rootless Podman: the host's ip_unprivileged_port_start (a per-netns
  # sysctl the Hub can't read from inside its container; RootlessCompat).
  if _rt_is_podman; then
    content+="PORTCULLIS_UNPRIVILEGED_PORT_START=$(runtime_port_start)"$'\n'
  fi
  (umask 077 && mkdir -p "$(dirname "$f")")
  [ -e "$f" ] || (umask 077 && : > "$f")
  {
    echo "# Generated by ./portcullis from .env: the subset the Hub may use. Do not edit."
    printf '%s' "$content"
  } > "$f"
}

# _ensure_secrets_volume — ensure hub_secrets volume exists with CT_UID_HUB:CT_UID_HUB 0700.
# Called by init/upgrade/restore (through stack_prepare) per contract §6.
_ensure_secrets_volume() {
  local name="${HUB_SECRETS_VOLUME:-portcullis_hub_secrets}"
  local project="${COMPOSE_PROJECT_NAME:-portcullis}"
  if ! docker volume inspect "$name" >/dev/null 2>&1; then
    docker volume create --label "com.docker.compose.project=$project" \
      --label "com.docker.compose.volume=hub_secrets" "$name" >/dev/null \
      || fail "could not create the Docker volume $name"
  fi
  # Ensure CT_UID_HUB:CT_UID_HUB mode 0700 (the Hub checks this at start).
  docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges:true --mount "type=volume,src=$name,dst=/v" \
    "$PORTCULLIS_HELPER_IMAGE" sh -c "chown $CT_UID_HUB:$CT_UID_HUB /v && chmod 0700 /v" >/dev/null \
    || fail "could not set hub_secrets volume to $CT_UID_HUB:$CT_UID_HUB mode 0700"
}

# stack_prepare — bind-mount sources must exist before compose runs, or
# Docker creates them root-owned (as directories) and nothing can write
# them afterwards. Also sets the ownership/modes the non-root containers
# need.
stack_prepare() {
  local d
  (umask 077 && mkdir -p "$PORTCULLIS_ROOT/secrets/vault-unseal" "$PORTCULLIS_ROOT/secrets/enroll" "$PORTCULLIS_ROOT/secrets/hub" "$PORTCULLIS_ROOT/secrets/domains" "$PORTCULLIS_ROOT/secrets/mcp-gate")
  for d in secrets secrets/vault-unseal secrets/enroll secrets/hub secrets/domains secrets/mcp-gate; do
    if [ ! -w "$PORTCULLIS_ROOT/$d" ]; then
      if _rt_is_podman; then
        fail "$PORTCULLIS_ROOT/$d is not writable (owned by a subordinate id?). Fix: podman unshare chown -R 0:0 \"$PORTCULLIS_ROOT/secrets\""
      fi
      fail "$PORTCULLIS_ROOT/$d is not writable (created by Docker as root?). Fix: sudo chown -R \"$(id -un)\" \"$PORTCULLIS_ROOT/secrets\""
    fi
  done
  # templates/: the Hub (uid 10001) copies app template dirs here.
  # appfiles/: the Hub writes settings data files here (contract §13.7);
  # 0750, 10001-owned (some hold secrets).
  # backups/: mountpoint of the Hub's tmpfs mask (must exist inside the
  # read-only /project bind). certs/truststore: Keycloak's CA truststore.
  mkdir -p "$PORTCULLIS_ROOT/certs/revocation" "$PORTCULLIS_ROOT/certs/truststore" "$PORTCULLIS_ROOT/templates"
  (umask 077 && mkdir -p "$PORTCULLIS_ROOT/backups")
  (umask 027 && mkdir -p "$PORTCULLIS_ROOT/appfiles")
  [ -f "$PORTCULLIS_ROOT/certs/revocation/revoked-serials.txt" ] || : > "$PORTCULLIS_ROOT/certs/revocation/revoked-serials.txt"
  # group-gate bind-mounts the two CA files (contract §4 "Certificate
  # binding"): they must be files before the first `up` (Docker would make
  # directories), empty until ./portcullis pki setup writes them — an empty
  # or unreadable file means no certificate counts (fail closed).
  # forward-auth(-ext) bind-mount certs/ca-bundle.crt: a file before the
  # first `up` (rootless Podman + SELinux: the overlay's long-syntax binds
  # never create a missing source), empty — trusting nothing — until
  # config apply builds it.
  [ ! -d "$PORTCULLIS_ROOT/certs/ca-bundle.crt" ] || fail "$PORTCULLIS_ROOT/certs/ca-bundle.crt is a directory (made by Docker before config apply): remove it (rmdir) and run again"
  [ -f "$PORTCULLIS_ROOT/certs/ca-bundle.crt" ] || { : > "$PORTCULLIS_ROOT/certs/ca-bundle.crt"; chmod 644 "$PORTCULLIS_ROOT/certs/ca-bundle.crt"; }
  local ca
  for ca in yubikey-ca.crt browser-ca.crt; do
    [ ! -d "$PORTCULLIS_ROOT/certs/$ca" ] || fail "$PORTCULLIS_ROOT/certs/$ca is a directory (made by Docker before pki setup): remove it (rmdir) and run again"
    [ -f "$PORTCULLIS_ROOT/certs/$ca" ] || { : > "$PORTCULLIS_ROOT/certs/$ca"; chmod 644 "$PORTCULLIS_ROOT/certs/$ca"; }
  done
  # Public material, read by Traefik (root w/o DAC_OVERRIDE), group-gate,
  # Keycloak and forward-auth (non-root).
  chmod 755 "$PORTCULLIS_ROOT/certs" "$PORTCULLIS_ROOT/certs/revocation" "$PORTCULLIS_ROOT/certs/truststore"
  chmod 644 "$PORTCULLIS_ROOT/certs/revocation/revoked-serials.txt"
  [ ! -f "$PORTCULLIS_ROOT/certs/server.key" ] || ct_group_read "$CT_GID_TRAEFIK" "$PORTCULLIS_ROOT/certs/server.key"
  [ "$(_owner_of "$PORTCULLIS_ROOT/templates")" != "$(id -u):$(id -g)" ] || chmod 755 "$PORTCULLIS_ROOT/templates"
  ct_own "$CT_UID_HUB:$CT_UID_HUB" "$PORTCULLIS_ROOT/templates"
  [ "$(_owner_of "$PORTCULLIS_ROOT/appfiles")" != "$(id -u):$(id -g)" ] || chmod 750 "$PORTCULLIS_ROOT/appfiles"
  ct_own "$CT_UID_HUB:$CT_UID_HUB" "$PORTCULLIS_ROOT/appfiles"
  # hub_data is also mounted (read-only) by group-gate, mcp-gate and Keycloak,
  # any of which may create it.
  volume_own hub_data "$CT_UID_HUB:$CT_UID_HUB"
  # mcp_gate_data: the gate writes it (access log), the Hub mounts it
  # read-only and reads it through group 10001 (contract §15.8). The gate
  # sets the directory's mode / group itself at start, so the group here is
  # already the Hub's (never flipped back while the gate runs).
  volume_own mcp_gate_data "$CT_UID_MCP_GATE:$CT_UID_HUB"
  # group_gate_data: group-gate writes the opened log (opened/ 2770 and
  # 0640 day files, group 10001, set by group-gate itself); the Hub reads
  # and prunes it through group 10001 (contract §4 "Opened log", §8.2).
  volume_own group_gate_data "$CT_UID_GROUP_GATE:$CT_UID_HUB"
  # hub_secrets: per-person password hashes (contract §6, file sharing). The
  # Hub checks ownership and mode at start; ensure it here.
  _ensure_secrets_volume
  hub_env_write
  # Invite / service-account secrets (scripts/lib/users.sh).
  if declare -F users_secret_files >/dev/null; then users_secret_files; fi
  # Files of the opt-in monitoring profile (scripts/lib/monitoring.sh).
  if declare -F monitoring_prepare >/dev/null; then monitoring_prepare; fi
  # The domains service's secrets and endpoint certificates (scripts/lib/domains.sh).
  if declare -F domains_prepare >/dev/null; then domains_prepare; fi
  # The MCP gate's age key, recipient and Hub secret (scripts/lib/mcpgate.sh).
  if declare -F mcpgate_ensure_secrets >/dev/null; then mcpgate_ensure_secrets; fi
  # The session store's config with the oauth2-proxies' users (scripts/lib/sessions.sh).
  if declare -F sessions_prepare >/dev/null; then sessions_prepare; fi
  secrets_fix_perms
}

# to_epoch <openssl date> — "Jan  2 03:04:05 2030 GMT" → seconds (GNU or BSD date).
to_epoch() {
  date -d "$1" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$1" +%s 2>/dev/null || echo 0
}

# The container runtime (CONTAINER_RUNTIME, runtime_check, ...): every
# caller of common.sh gets it.
# shellcheck source=runtime.sh
source "$PORTCULLIS_LIB/runtime.sh"
