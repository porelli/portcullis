# shellcheck shell=bash
#
# Users: one-time invite links (`portcullis invite`, enroll/invite.go), the
# Hub's LLDAP service account (integration contract §9.1) and the secret
# files of both.
#
# No secret on a host command line: LLDAP calls run inside the lldap
# container (`docker compose exec -T lldap ...`) with the password / token on
# stdin; curl expands the bearer token from its environment
# (--variable/--expand-header) instead of argv.

HUB_LLDAP_USER="portcullis-hub"

# users_secret_files — create the files nothing else generates (idempotent;
# modes and groups: secrets_fix_perms):
#   secrets/enroll/invite-client-secret   Keycloak ⇄ enroll invite OIDC client
#   secrets/enroll/keycloak-client-secret Keycloak client portcullis-enroll
#   secrets/enroll/invite-api-secret      Hub → enroll invite API bearer secret
#   secrets/hub/invite/secret             the same value, readable by the Hub
#   secrets/hub/lldap/{username,password} the Hub's LLDAP service account
users_secret_files() {
  local s="$PORTCULLIS_ROOT/secrets" f
  (umask 077 && mkdir -p "$s/enroll" "$s/hub/invite" "$s/hub/lldap")
  for f in enroll/invite-client-secret enroll/keycloak-client-secret enroll/invite-api-secret hub/lldap/password; do
    [ -s "$s/$f" ] || (umask 077 && gen_alnum 48 > "$s/$f")
  done
  [ "$(cat "$s/hub/lldap/username" 2>/dev/null)" = "$HUB_LLDAP_USER" ] || (umask 077 && echo "$HUB_LLDAP_USER" > "$s/hub/lldap/username")
  # One value, two owners (a file has one group): enroll 10002, Hub 10001.
  cmp -s "$s/enroll/invite-api-secret" "$s/hub/invite/secret" 2>/dev/null \
    || (umask 077 && cat "$s/enroll/invite-api-secret" > "$s/hub/invite/secret")
}

# _lldap_login — prints an LLDAP JWT for the LLDAP admin (LLDAP_ADMIN_PASSWORD).
_lldap_login() {
  env_require LLDAP_ADMIN_PASSWORD
  # The password reaches jq through its environment, never argv.
  LLDAP_ADMIN_PASSWORD="$LLDAP_ADMIN_PASSWORD" jq -nc '{username: "admin", password: env.LLDAP_ADMIN_PASSWORD}' \
    | dc exec -T lldap curl -sf --max-time 20 http://localhost:17170/auth/simple/login \
        -H 'Content-Type: application/json' -d @- | jq -r '.token // empty'
}

# _lldap_gql <token> <query> [variables-json] — GraphQL as the LLDAP admin.
_lldap_gql() {
  local vars="${3:-}"
  [ -n "$vars" ] || vars='{}'
  # shellcheck disable=SC2016  # expanded by the container's sh / curl
  { printf '%s\n' "$1"; jq -nc --arg q "$2" --argjson v "$vars" '{query: $q, variables: $v}'; } \
    | dc exec -T lldap sh -c 'read -r T; export T; exec curl -sf --max-time 20 --variable %T \
        --expand-header "Authorization: Bearer {{T}}" -H "Content-Type: application/json" \
        -d @- http://localhost:17170/api/graphql'
}

# lldap_service_account — the Hub's LLDAP account (contract §9.1): user
# portcullis-hub in lldap_admin with the password in
# secrets/hub/lldap/password. Created if missing, re-added to the group,
# password reset when it no longer logs in. Needs a running LLDAP.
lldap_service_account() {
  local tok out gid pw="$PORTCULLIS_ROOT/secrets/hub/lldap/password"
  info "Ensuring the Hub's LLDAP service account ($HUB_LLDAP_USER)..."
  [ -s "$pw" ] || users_secret_files
  tok="$(_lldap_login)" || true
  [ -n "$tok" ] || { warn "    cannot log in to LLDAP as admin — service account not checked"; return 0; }
  out="$(_lldap_gql "$tok" 'query($id: String!) { user(userId: $id) { id groups { displayName } } }' \
    "$(jq -nc --arg id "$HUB_LLDAP_USER" '{id: $id}')" || true)"
  if ! printf '%s' "$out" | jq -e '.data.user.id' >/dev/null 2>&1; then
    out="$(_lldap_gql "$tok" 'mutation($u: CreateUserInput!) { createUser(user: $u) { id } }' \
      "$(jq -nc --arg id "$HUB_LLDAP_USER" --arg d "${PORTCULLIS_DOMAIN:-portcullis.local}" \
        '{u: {id: $id, email: ($id + "@" + $d), displayName: "Portcullis Hub (service account)"}}')" || true)"
    printf '%s' "$out" | jq -e '.data.createUser.id' >/dev/null 2>&1 \
      || { warn "    could not create $HUB_LLDAP_USER: $(printf '%s' "$out" | jq -c '.errors // .' 2>/dev/null)"; return 0; }
    echo "    created $HUB_LLDAP_USER"
    out='{"data":{"user":{"groups":[]}}}'
  fi
  if ! printf '%s' "$out" | jq -e 'any(.data.user.groups[]?; .displayName == "lldap_admin")' >/dev/null; then
    gid="$(_lldap_gql "$tok" '{ groups { id displayName } }' | jq -r '.data.groups[]? | select(.displayName == "lldap_admin") | .id')"
    out="$(_lldap_gql "$tok" 'mutation($u: String!, $g: Int!) { addUserToGroup(userId: $u, groupId: $g) { ok } }' \
      "$(jq -nc --arg u "$HUB_LLDAP_USER" --argjson g "${gid:-0}" '{u: $u, g: $g}')" || true)"
    printf '%s' "$out" | jq -e '.data.addUserToGroup.ok' >/dev/null 2>&1 \
      && echo "    $HUB_LLDAP_USER: added to lldap_admin" || warn "    could not add $HUB_LLDAP_USER to lldap_admin"
  fi
  # Password: try it; reset it when LLDAP and the file disagree.
  if jq -nc --arg u "$HUB_LLDAP_USER" --rawfile p "$pw" '{username: $u, password: ($p | rtrimstr("\n"))}' \
      | dc exec -T lldap curl -sf -o /dev/null --max-time 20 http://localhost:17170/auth/simple/login \
          -H 'Content-Type: application/json' -d @-; then
    echo "    $HUB_LLDAP_USER: password matches secrets/hub/lldap/password"
    return 0
  fi
  # lldap_set_password takes the user's password from LLDAP_USER_PASSWORD;
  # it has no env / file option for the admin credential, so the short-lived
  # admin JWT is its one secret argument — inside the lldap container only,
  # never on the host's command lines. (secret-argv-ok)
  # shellcheck disable=SC2016
  if { printf '%s\n' "$tok"; cat "$pw"; echo; } | dc exec -T lldap sh -c 'read -r T; read -r P; export LLDAP_USER_PASSWORD="$P";
      exec /app/lldap_set_password --base-url http://localhost:17170 --token "$T" --username "$1"' _ "$HUB_LLDAP_USER" >/dev/null; then # secret-argv-ok: inside the lldap container
    echo "    $HUB_LLDAP_USER: password set from secrets/hub/lldap/password"
  else
    warn "    could not set the password of $HUB_LLDAP_USER"
  fi
}

# invite_create <user> [ttl] [landing] — prints the one-time setup link
# (JSON from `enroll invite`, see enroll/invite.go).
invite_create() {
  local user="$1" ttl="${2:-}" landing="${3:-}" out
  local -a args=("$user")
  [ -z "$ttl" ] || args+=(-ttl "$ttl")
  [ -z "$landing" ] || args+=(-landing "$landing")
  out="$(dc exec -T enroll enroll invite "${args[@]}")" || fail "enroll refused the invite for $user (see above; is the stack up?)"
  printf '%s' "$out" | jq -e '.url' >/dev/null 2>&1 || fail "unexpected answer from enroll: $out"
  printf '%s' "$out"
}

help_invite() {
  cat <<'EOF'
Usage: portcullis invite <user> [--ttl DURATION] [--to hub|portal|URL] [--json]

Prints a one-time setup link for an LLDAP user. Opening it lets the user
register a passkey / security key (YubiKey) and signs them in: no password,
no other step. The link is single use, expires after --ttl (default 72h,
max 168h) and replaces the user's previous links. Pending links do not
survive a restart of the enroll container.

This is also how the bootstrap `admin` gets (or recovers) its key: the Hub
refuses invites for `admin`; only the server can issue them.

  --ttl DURATION   Go duration, e.g. 30m, 24h
  --to             where to land afterwards: hub (https://hub.<domain>/),
                   portal (https://<domain>/, default) or an https URL on
                   the domain
  --json           print enroll's JSON ({"url","expires_at"})
EOF
}

cmd_invite() {
  local user="" ttl="" to="portal" json=false landing out
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) help_invite; return 0 ;;
      --ttl) [ $# -ge 2 ] || usage_error invite "--ttl needs a value"; ttl="$2"; shift ;;
      --to) [ $# -ge 2 ] || usage_error invite "--to needs a value"; to="$2"; shift ;;
      --json) json=true ;;
      -*) usage_error invite "unknown option: $1" ;;
      *) [ -z "$user" ] || usage_error invite "one user only"; user="$1" ;;
    esac
    shift
  done
  [ -n "$user" ] || usage_error invite "missing <user>"
  [[ "$user" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$ ]] || usage_error invite "invalid user name: $user"
  case "$to" in
    hub|portal|https://*) ;;
    *) usage_error invite "--to must be hub, portal or an https URL" ;;
  esac
  require_cmd docker jq
  need_env
  case "$to" in
    hub) landing="https://hub.${PORTCULLIS_DOMAIN:-portcullis.local}/" ;;
    portal) landing="" ;;
    *) landing="$to" ;;
  esac
  out="$(invite_create "$user" "$ttl" "$landing")"
  if [ "$json" = true ]; then
    printf '%s\n' "$out"
  else
    ok "One-time setup link for $user (expires $(printf '%s' "$out" | jq -r .expires_at)):"
    printf '\n  %s\n\n' "$(printf '%s' "$out" | jq -r .url)"
    echo "    Send it to $user over a channel you trust. It works once."
  fi
}
