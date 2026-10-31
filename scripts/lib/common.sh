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

# stack_prepare — bind-mount sources must exist before compose runs, or
# Docker creates them root-owned (as directories) and nothing can write
# them afterwards.
stack_prepare() {
  local d
  (umask 077 && mkdir -p "$PORTCULLIS_ROOT/secrets/vault-unseal" "$PORTCULLIS_ROOT/secrets/enroll")
  for d in secrets secrets/vault-unseal secrets/enroll; do
    chmod 700 "$PORTCULLIS_ROOT/$d" 2>/dev/null || true
    [ -w "$PORTCULLIS_ROOT/$d" ] || fail "$PORTCULLIS_ROOT/$d is not writable (created by Docker as root?). Fix: sudo chown -R \"$(id -un)\" \"$PORTCULLIS_ROOT/secrets\""
  done
  # templates/: the Hub copies app template dirs here. backups/: mountpoint
  # of the Hub's tmpfs mask (must exist inside the read-only /project bind).
  mkdir -p "$PORTCULLIS_ROOT/certs/revocation" "$PORTCULLIS_ROOT/templates"
  (umask 077 && mkdir -p "$PORTCULLIS_ROOT/backups")
  [ -f "$PORTCULLIS_ROOT/certs/revocation/revoked-serials.txt" ] || : > "$PORTCULLIS_ROOT/certs/revocation/revoked-serials.txt"
}

# to_epoch <openssl date> — "Jan  2 03:04:05 2030 GMT" → seconds (GNU or BSD date).
to_epoch() {
  date -d "$1" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$1" +%s 2>/dev/null || echo 0
}
