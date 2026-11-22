#!/usr/bin/env bash
# ci.yml job e2e-k3s, step "Sign out on Kubernetes" (contract §5 "Sign out"),
# after the Hub phase: a YubiKey-certificate sign-in through forward-auth
# (curl's cookie jar = the browser), then the site bar's POST. The sign-out
# lands on the Signed out page, the ticket is dead, this sign-in's Keycloak
# session is gone, and Traefik's access log gained no id_token_hint: the
# backend logout goes to keycloak-internal:8081 (kcinternal), whose logout
# path is the access-log-free router kcinternal-logout. Nothing secret is
# printed (tokens and keys only in a 0700 temp dir, masked).
set -euo pipefail
cd "$(dirname "$0")/../.."

K() { kubectl --context ci "$@"; }
NS=portcullis
T="$(mktemp -d)"; chmod 700 "$T"
PF=""
trap 'rm -rf "$T"; [ -z "$PF" ] || kill "$PF" 2>/dev/null || true' EXIT
fail() { echo "FAIL: $*"; exit 1; }
pass() { echo "PASS: $*"; }

D="$(grep '^PORTCULLIS_DOMAIN=' .env | cut -d= -f2-)"
IP=198.51.100.1
C=(curl -s --max-time 20 --cacert certs/ca-chain.crt --cert "$T/c.crt" --key "$T/c.key"
   --resolve "auth.$D:443:$IP" --resolve "$D:443:$IP" -c "$T/jar" -b "$T/jar")

# testuser's YubiKey-CA certificate (the root token on the vault pod's stdin).
root="$(jq -r .root_token secrets/vault-init.json)"; echo "::add-mask::$root"
# shellcheck disable=SC2016  # expanded by the pod's sh
printf '%s\n' "$root" | K -n "$NS" exec -i deploy/vault -c vault -- sh -c 'IFS= read -r t; VAULT_TOKEN="$t" VAULT_ADDR=http://127.0.0.1:8200 exec vault write -format=json pki_int/issue/client-cert common_name=testuser ttl=1h' > "$T/issue.json"
jq -r .data.certificate "$T/issue.json" > "$T/c.crt"
(umask 077; jq -r .data.private_key "$T/issue.json" > "$T/c.key")
rm -f "$T/issue.json"
grep -q 'BEGIN CERTIFICATE' "$T/c.crt" || fail "could not issue testuser's certificate"

# The sign-in, as build-and-test's session-store step: the Let through form
# posted as its script would, then on to /oauth2/auth (202).
"${C[@]}" -L --max-redirs 10 -o "$T/page" "https://auth.$D/oauth2/start?pc_method=yubikey_cert&rd=https%3A%2F%2Fauth.$D%2Foauth2%2Fauth" || true
ACTION="$(grep -o '<form id="portcullis-let-through-form" action="[^"]*"' "$T/page" | sed 's/.*action="//; s/"$//; s/&amp;/\&/g' || true)"
case "$ACTION" in "https://auth.$D/realms/portcullis/login-actions/required-action?"*) ;; *) fail "the certificate sign-in didn't reach the Let through page" ;; esac
END="$("${C[@]}" -L --max-redirs 10 -o /dev/null -w '%{http_code}' --data-binary '' "$ACTION")"
[ "$END" = 202 ] || fail "the sign-in through forward-auth ended with HTTP $END"
pass "a YubiKey-certificate sign-in through forward-auth on Kubernetes"
cp "$T/jar" "$T/jar.before"

# Keycloak's admin API through a port-forward (the password on stdin).
K -n "$NS" port-forward deploy/keycloak 18180:8080 >/dev/null 2>&1 & PF=$!
for _ in $(seq 1 30); do curl -sf -o /dev/null http://127.0.0.1:18180/realms/master && break; sleep 1; done
KC_PW="$(grep '^KEYCLOAK_ADMIN_PASSWORD=' .env | cut -d= -f2-)"; echo "::add-mask::$KC_PW"
KC_USER="$(grep '^KEYCLOAK_ADMIN=' .env | cut -d= -f2-)"
TOK="$(printf '%s' "$KC_PW" | curl -sf http://127.0.0.1:18180/realms/master/protocol/openid-connect/token \
  --data-urlencode client_id=admin-cli --data-urlencode "username=${KC_USER:-admin}" \
  --data-urlencode grant_type=password --data-urlencode password@- | jq -r .access_token)"
[ -n "$TOK" ] && [ "$TOK" != null ] || fail "no Keycloak admin token"
echo "::add-mask::$TOK"
kc() { curl -sf -H @<(printf 'Authorization: Bearer %s\n' "$TOK") "http://127.0.0.1:18180/admin/realms/portcullis$1"; }
TU="$(kc '/users?username=testuser&exact=true' | jq -r '.[0].id // empty')"
[ -n "$TU" ] || fail "testuser not found in Keycloak"
SID="$(kc "/users/$TU/sessions" | jq -r 'max_by(.start) | .id // empty')"
[ -n "$SID" ] || fail "testuser has no Keycloak session after the sign-in"

hints() { K -n "$NS" logs deploy/traefik -c traefik 2>/dev/null | grep -c 'id_token_hint' || true; }
BEFORE="$(hints)"
# The site bar's POST (the portal's form: its origin, same-site, text/plain).
HDRS="$("${C[@]}" -o /dev/null -D - -X POST -H 'Sec-Fetch-Site: same-site' -H "Origin: https://$D" \
  -H 'Content-Type: text/plain' --data-binary '' "https://auth.$D/oauth2/sign_out" | tr -d '\r')"
printf '%s\n' "$HDRS" | head -1 | grep -q ' 302' || fail "the sign-out POST: $(printf '%s\n' "$HDRS" | head -1)"
LOC="$(printf '%s\n' "$HDRS" | sed -n 's/^[Ll]ocation: //p')"
[ "$LOC" = "https://$D/signed-out" ] || fail "the sign-out landed on '$LOC'"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 --cacert certs/ca-chain.crt --resolve "auth.$D:443:$IP" -b "$T/jar.before" "https://auth.$D/oauth2/auth")"
[ "$code" = 401 ] || fail "the signed-out ticket still answers $code"
for i in $(seq 1 10); do
  [ "$(kc "/users/$TU/sessions" | jq --arg s "$SID" '[.[] | select(.id == $s)] | length')" = 0 ] && break
  [ "$i" = 10 ] && { K -n "$NS" logs deploy/forward-auth --since=2m 2>/dev/null | grep 'backend logout' | sed -E 's/id_token_hint=[^ "&]*/id_token_hint=…/g' | tail -3; fail "testuser's Keycloak session $SID survived the sign-out"; }
  sleep 1
done
sleep 2
AFTER="$(hints)"
[ "$AFTER" = "$BEFORE" ] || fail "the sign-out put an id_token_hint into Traefik's access log ($BEFORE → $AFTER lines)"
if K -n "$NS" logs deploy/forward-auth --since=2m 2>/dev/null | grep -q 'backend logout'; then
  fail "oauth2-proxy's backend logout reported an error"
fi
pass "sign-out on Kubernetes: 302 to https://$D/signed-out, the ticket gets 401, testuser's Keycloak session is gone, no id_token_hint in Traefik's access log (kcinternal-logout)"
