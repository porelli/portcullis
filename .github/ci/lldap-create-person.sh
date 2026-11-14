#!/usr/bin/env bash
# lldap-create-person.sh <user> [<base url>] — create one LLDAP person as
# LLDAP's admin through its published port (default http://127.0.0.1:17170;
# the job's CI override publishes it), the gql-helper pattern of the other
# jobs: the password from .env (masked), the token only in a variable and
# on curl's header process substitution, never printed. Login and the
# mutation are retried (LLDAP answers its login before GraphQL is ready);
# a failure prints the HTTP status and the response's errors, never the
# token. Used by e2e-podman's and e2e-k3s's Docker phases.
set -euo pipefail
user="${1:?usage: lldap-create-person.sh <user> [<base url>]}" base="${2:-http://127.0.0.1:17170}"
[[ "$user" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || { echo "FAIL: bad LLDAP user name '$user'"; exit 1; }
pw="$(grep '^LLDAP_ADMIN_PASSWORD=' .env | cut -d= -f2-)"; echo "::add-mask::$pw"
[ -n "$pw" ] || { echo "FAIL: no LLDAP_ADMIN_PASSWORD in .env"; exit 1; }
out="$(mktemp)"; trap 'rm -f "$out"' EXIT
tok="" code=""
for _ in $(seq 1 30); do
  code="$(PW="$pw" jq -n '{username: "admin", password: env.PW}' \
    | curl -s -o "$out" -w '%{http_code}' --max-time 10 "$base/auth/simple/login" -H 'Content-Type: application/json' -d @- || true)"
  tok="$(jq -r '.token // empty' "$out" 2>/dev/null || true)"
  [ "$code" = 200 ] && [ -n "$tok" ] && break
  tok=""; sleep 2
done
[ -n "$tok" ] || { echo "FAIL: LLDAP login as admin: HTTP ${code:-none} after 30 tries"; exit 1; }
echo "::add-mask::$tok"
q="mutation { createUser(user: {id: \"$user\", email: \"$user@portcullis.local\"}) { id } }"
for _ in $(seq 1 10); do
  code="$(jq -n --arg q "$q" '{query: $q}' | curl -s -o "$out" -w '%{http_code}' --max-time 10 "$base/api/graphql" \
    -H @<(printf 'Authorization: Bearer %s\n' "$tok") -H 'Content-Type: application/json' -d @- || true)"
  if [ "$code" = 200 ] && jq -e --arg u "$user" '.errors == null and .data.createUser.id == $u' "$out" >/dev/null 2>&1; then
    echo "LLDAP: created $user"; exit 0
  fi
  # Already there (a retry after a lost answer): fine.
  if [ "$code" = 200 ] && jq -e '[.errors[]?.message] | any(test("UNIQUE|already exists"; "i"))' "$out" >/dev/null 2>&1; then
    echo "LLDAP: $user already exists"; exit 0
  fi
  sleep 3
done
echo "FAIL: create the LLDAP person $user: HTTP ${code:-none}, errors $(jq -c '[.errors[]?.message]' "$out" 2>/dev/null || head -c 300 "$out")"
exit 1
