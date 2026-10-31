# shellcheck shell=bash
#
# Shared helpers for the `portcullis` CLI: output, .env handling, secret
# generation, docker compose wrappers, health waits. Sourced by ./portcullis
# (and by tests); never executed directly. Bash 3.2 compatible (macOS).
#
# Globals (set by ./portcullis before sourcing, overridable for tests):
#   PORTCULLIS_ROOT   checkout root: .env, certs/, secrets/, compose files
#   PORTCULLIS_LIB    this directory

PORTCULLIS_LIB="${PORTCULLIS_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
PORTCULLIS_ROOT="${PORTCULLIS_ROOT:-$(cd "$PORTCULLIS_LIB/../.." && pwd)}"

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

# need_env — load .env (fail if missing).
need_env() {
  [ -f "$(env_file)" ] || fail "$(env_file) not found. Run ./portcullis init first."
  env_load
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
CORE_SECRETS="POSTGRES_PASSWORD KEYCLOAK_ADMIN_PASSWORD LLDAP_ADMIN_PASSWORD LLDAP_JWT_SECRET FORWARD_AUTH_CLIENT_SECRET FORWARD_AUTH_COOKIE_SECRET HUB_PROXY_SECRET"
# Subset that can be (re)generated on an existing install without losing
# data: nothing on disk is encrypted with them, and `portcullis oidc
# register` pushes FORWARD_AUTH_CLIENT_SECRET to Keycloak.
# shellcheck disable=SC2034
ROTATABLE_SECRETS="LLDAP_JWT_SECRET FORWARD_AUTH_CLIENT_SECRET FORWARD_AUTH_COOKIE_SECRET HUB_PROXY_SECRET"

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
    FORWARD_AUTH_CLIENT_SECRET) gen_alnum 40 ;;
    LLDAP_JWT_SECRET) gen_alnum 48 ;;
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
CT_GID_TRAEFIK=0      # Traefik runs as root, but without CAP_DAC_OVERRIDE
# Throwaway container used to chown/chgrp when not running as root (the
# operator can run docker, i.e. is root-equivalent anyway).
PORTCULLIS_HELPER_IMAGE="alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a"

# _owner_of <path> — "uid:gid" (GNU or BSD stat).
_owner_of() { stat -c '%u:%g' "$1" 2>/dev/null || stat -f '%u:%g' "$1"; }

# ct_own <uid:gid> <path>... — chown the paths (no-op for those already
# right). As root directly, otherwise via a throwaway root container with
# only CAP_CHOWN and no network.
ct_own() {
  local spec="$1" p i=0 todo=() mounts=() targets=()
  shift
  for p in "$@"; do
    [ -e "$p" ] || continue
    [ "$(_owner_of "$p")" = "$spec" ] || todo+=("$p")
  done
  [ "${#todo[@]}" -gt 0 ] || return 0
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
    || fail "could not chown ${todo[*]} to $spec (try: sudo chown $spec ${todo[*]})"
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
  ct_own "$(id -u):$gid" "$@"
}

# secrets_fix_perms — ownership/modes of everything under secrets/ that a
# container reads. Idempotent (also repairs a restored backup).
secrets_fix_perms() {
  local s="$PORTCULLIS_ROOT/secrets"
  chmod 700 "$s" 2>/dev/null || true
  [ ! -e "$s/vault-init.json" ] || chmod 600 "$s/vault-init.json"
  ct_group_read "$CT_GID_VAULT" "$s/vault-unseal" "$s/vault-unseal/unseal-key"
  ct_group_read "$CT_UID_ENROLL" "$s/enroll" "$s/enroll/role-id" "$s/enroll/secret-id"
  ct_group_read "$CT_UID_HUB" "$s/hub" "$s/hub/core.env"
}

# Core variables the Hub may copy into app .env files (templates reference
# them as ${VAR}); everything else in .env is a core secret the Hub never
# sees. Operators can add names via HUB_SHARED_ENV="VAR1 VAR2".
HUB_ENV_VARS="PORTCULLIS_DOMAIN PORTCULLIS_TRAEFIK_IP PORTCULLIS_PROXY_SUBNET PORTCULLIS_PROXY_IP_RANGE PORTAL_DISPLAY_NAME"
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
    case "$v" in
      PORTCULLIS_DOMAIN) val="${PORTCULLIS_DOMAIN:-portcullis.local}" ;;
      PORTCULLIS_TRAEFIK_IP) val="$(proxy_traefik_ip)" ;;
      PORTCULLIS_PROXY_SUBNET) val="$(proxy_subnet)" ;;
      PORTCULLIS_PROXY_IP_RANGE) val="$(proxy_ip_range)" ;;
      PORTAL_DISPLAY_NAME) val="${PORTAL_DISPLAY_NAME:-Portcullis}" ;;
      *) val="${!v:-}" ;;
    esac
    content+="$v=$val"$'\n'
  done
  (umask 077 && mkdir -p "$(dirname "$f")")
  [ -e "$f" ] || (umask 077 && : > "$f")
  {
    echo "# Generated by ./portcullis from .env: the subset the Hub may use. Do not edit."
    printf '%s' "$content"
  } > "$f"
}

# stack_prepare — bind-mount sources must exist before compose runs, or
# Docker creates them root-owned (as directories) and nothing can write
# them afterwards. Also sets the ownership/modes the non-root containers
# need.
stack_prepare() {
  local d
  (umask 077 && mkdir -p "$PORTCULLIS_ROOT/secrets/vault-unseal" "$PORTCULLIS_ROOT/secrets/enroll" "$PORTCULLIS_ROOT/secrets/hub")
  for d in secrets secrets/vault-unseal secrets/enroll secrets/hub; do
    [ -w "$PORTCULLIS_ROOT/$d" ] || fail "$PORTCULLIS_ROOT/$d is not writable (created by Docker as root?). Fix: sudo chown -R \"$(id -un)\" \"$PORTCULLIS_ROOT/secrets\""
  done
  # templates/: the Hub (uid 10001) copies app template dirs here.
  # backups/: mountpoint of the Hub's tmpfs mask (must exist inside the
  # read-only /project bind). certs/truststore: Keycloak's CA truststore.
  mkdir -p "$PORTCULLIS_ROOT/certs/revocation" "$PORTCULLIS_ROOT/certs/truststore" "$PORTCULLIS_ROOT/templates"
  (umask 077 && mkdir -p "$PORTCULLIS_ROOT/backups")
  [ -f "$PORTCULLIS_ROOT/certs/revocation/revoked-serials.txt" ] || : > "$PORTCULLIS_ROOT/certs/revocation/revoked-serials.txt"
  # Public material, read by Traefik (root w/o DAC_OVERRIDE), group-gate,
  # Keycloak and forward-auth (non-root).
  chmod 755 "$PORTCULLIS_ROOT/certs" "$PORTCULLIS_ROOT/certs/revocation" "$PORTCULLIS_ROOT/certs/truststore"
  chmod 644 "$PORTCULLIS_ROOT/certs/revocation/revoked-serials.txt"
  [ ! -f "$PORTCULLIS_ROOT/certs/server.key" ] || ct_group_read "$CT_GID_TRAEFIK" "$PORTCULLIS_ROOT/certs/server.key"
  [ "$(_owner_of "$PORTCULLIS_ROOT/templates")" != "$(id -u):$(id -g)" ] || chmod 755 "$PORTCULLIS_ROOT/templates"
  ct_own "$CT_UID_HUB:$CT_UID_HUB" "$PORTCULLIS_ROOT/templates"
  hub_env_write
  secrets_fix_perms
}

# to_epoch <openssl date> — "Jan  2 03:04:05 2030 GMT" → seconds (GNU or BSD date).
to_epoch() {
  date -d "$1" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$1" +%s 2>/dev/null || echo 0
}
