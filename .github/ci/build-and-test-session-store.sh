#!/usr/bin/env bash
# ci.yml job build-and-test, step "Test the session store (oauth2-proxy sessions in Valkey, a ticket cookie, the ACL)".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
# oauth2-proxy #3486: a session in cookies outgrew one cookie and the
# stale unsplit one kept winning. With the store the browser holds one
# small ticket and the session lives in `sessions` (Valkey).
docker compose up -d sessions forward-auth forward-auth-ext
SID="$(docker compose ps -q sessions)"
for i in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$SID")" = healthy ] && break
  [ "$i" = 30 ] && { echo "FAIL: sessions not healthy"; docker compose logs --tail=40 sessions; exit 1; }
  sleep 2
done
test "$(docker inspect -f '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}}' "$SID")" = "999:1000 true [ALL]" \
  || { echo "FAIL: sessions user / read-only / caps: $(docker inspect -f '{{.Config.User}} {{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}}' "$SID")"; exit 1; }
test "$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$SID")" = "portcullis_portcullis-sessions " \
  || { echo "FAIL: sessions networks: $(docker inspect -f '{{json .NetworkSettings.Networks}}' "$SID" | jq -c keys)"; exit 1; }
test "$(stat -c '%a' secrets/sessions) $(stat -c '%a %g' secrets/sessions/valkey.conf)" = "700 640 1000" \
  || { echo "FAIL: secrets/sessions modes / group"; exit 1; }
FA_PW="$(grep '^FORWARD_AUTH_REDIS_PASSWORD=' .env | cut -d= -f2-)"; echo "::add-mask::$FA_PW"
FX_PW="$(grep '^FORWARD_AUTH_EXT_REDIS_PASSWORD=' .env | cut -d= -f2-)"; echo "::add-mask::$FX_PW"
if grep -qF -e "$FA_PW" -e "$FX_PW" secrets/sessions/valkey.conf; then echo "FAIL: a store password in clear in valkey.conf"; exit 1; fi
# No password reaches argv / the container's environment: valkey-cli reads it from VALKEYCLI_AUTH, passed by name.
vk() { local pw="$1" user="$2"; shift 2; VALKEYCLI_AUTH="$pw" docker compose exec -T -e VALKEYCLI_AUTH sessions valkey-cli --no-auth-warning --user "$user" "$@" 2>&1; }
# shellcheck disable=SC2254  # $want is a glob on purpose
expect() { local want="$1" what="$2"; shift 2; local got; got="$("$@")" || true; case "$got" in $want) echo "PASS: $what" ;; *) echo "FAIL: $what: $got"; exit 1 ;; esac; }
expect '*NOAUTH*' "the default user is off (unauthenticated PING refused)" docker compose exec -T sessions valkey-cli ping
expect '*WRONGPASS*' "a wrong password is refused" vk wrong forward-auth ping
expect PONG "forward-auth signs in" vk "$FA_PW" forward-auth ping
expect PONG "forward-auth-ext signs in" vk "$FX_PW" forward-auth-ext ping
expect OK "forward-auth writes its own keys" vk "$FA_PW" forward-auth set _oauth2_proxy-ci0 x PX 60000
expect '*NOPERM*' "forward-auth-ext can't read forward-auth's keys" vk "$FX_PW" forward-auth-ext get _oauth2_proxy-ci0
expect '*NOPERM*' "forward-auth can't write forward-auth-ext's keys" vk "$FA_PW" forward-auth set __Host-portcullis_ext-ci0 x
expect OK "forward-auth-ext writes its own keys" vk "$FX_PW" forward-auth-ext set __Host-portcullis_ext-ci0 x PX 60000
expect '*NOPERM*' "forward-auth can't read forward-auth-ext's keys" vk "$FA_PW" forward-auth get __Host-portcullis_ext-ci0
for cmd in "keys x" "scan 0" "flushall" "config get maxmemory" "config set maxmemory 0" "acl list" "client list" "info" "shutdown" "script flush"; do
  # shellcheck disable=SC2086  # the command's words (no glob characters in them)
  expect '*NOPERM*' "forward-auth may not run '$cmd'" vk "$FA_PW" forward-auth $cmd
done
expect x "a script reads its own key" vk "$FA_PW" forward-auth eval "return redis.call('get', KEYS[1])" 1 _oauth2_proxy-ci0
expect '*NOPERM*' "a script can't read another proxy's key" vk "$FA_PW" forward-auth eval "return redis.call('get', KEYS[1])" 1 __Host-portcullis_ext-ci0
# (Valkey words a refused call inside a script "ACL failure in script: ... no permissions to run")
expect "*ACL failure in script*forward-auth has no permissions to run the 'flushall' command*" "a script can't run what the user can't" vk "$FA_PW" forward-auth eval "return redis.call('flushall')" 0
expect 1 "forward-auth deletes its own key" vk "$FA_PW" forward-auth del _oauth2_proxy-ci0
expect 1 "forward-auth-ext deletes its own key" vk "$FX_PW" forward-auth-ext del __Host-portcullis_ext-ci0

# A real sign-in through forward-auth (YubiKey certificate, curl's cookie jar = the browser).
VAULT_TOKEN=$(jq -r .root_token secrets/vault-init.json); export VAULT_TOKEN
echo "::add-mask::$VAULT_TOKEN"
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/sess.key
openssl req -new -key /tmp/sess.key -subj "/CN=testuser" -out /tmp/sess.csr
vault write -format=json pki_int/sign/client-cert csr=@/tmp/sess.csr common_name=testuser ttl=1h | jq -r .data.certificate > /tmp/sess.crt
J=/tmp/sess.jar; rm -f "$J"
C=(curl -s --cacert certs/ca-chain.crt --cert /tmp/sess.crt --key /tmp/sess.key --resolve "auth.portcullis.local:443:127.0.0.1" -c "$J" -b "$J")
for i in $(seq 1 30); do
  [ "$("${C[@]}" -o /dev/null -w '%{http_code}' https://auth.portcullis.local/oauth2/auth)" = 401 ] && break
  [ "$i" = 30 ] && { echo "FAIL: forward-auth does not answer"; docker compose logs --tail=40 forward-auth; exit 1; }
  sleep 2
done
# rd = oauth2-proxy's own /oauth2/auth: 202 once the session loads from the store.
# The certificate is an interactive sign-in, so Keycloak stops on its "Let
# through" page (contract §8.1): its form is posted as the page's script
# would (empty body, the same cookies and certificate), then the redirects
# go on to the callback and rd.
END="$("${C[@]}" -L --max-redirs 10 -o /tmp/sess.page -w '%{http_code} %{url_effective}' \
  "https://auth.portcullis.local/oauth2/start?pc_method=yubikey_cert&rd=https%3A%2F%2Fauth.portcullis.local%2Foauth2%2Fauth")"
grep -q 'id="portcullis-let-through-form"' /tmp/sess.page \
  || { echo "FAIL: the YubiKey-certificate sign-in didn't show the Let through page (at ${END%%\?*})"; exit 1; }
# rd is auth.<domain>'s own /oauth2/auth: not a host the Hub publishes in
# app_hosts, so the page names no host (contract §8.1 "Let through").
grep -q 'Let through — opening your app…' /tmp/sess.page \
  || { echo "FAIL: the Let through page names a host for rd=auth.<domain>: $(grep -o 'Let through[^<]*' /tmp/sess.page)"; exit 1; }
ACTION=$(grep -o '<form id="portcullis-let-through-form" action="[^"]*"' /tmp/sess.page | sed 's/.*action="//; s/"$//; s/&amp;/\&/g')
case "$ACTION" in
  https://auth.portcullis.local/realms/portcullis/login-actions/required-action\?*) ;;
  *) echo "FAIL: the Let through form posts to '$ACTION'"; exit 1 ;;
esac
END="$("${C[@]}" -L --max-redirs 10 -o /dev/null -w '%{http_code} %{url_effective}' --data-binary '' "$ACTION")"
rm -f /tmp/sess.page
[ "${END%% *}" = 202 ] || { echo "FAIL: sign-in through forward-auth ended at ${END%%\?*}"; docker compose logs --tail=40 forward-auth; exit 1; }
echo "PASS: a YubiKey-certificate sign-in through forward-auth; /oauth2/auth answers 202"
NAMES="$(awk -F'\t' '!/^#/ || /^#HttpOnly_/ { if (NF >= 7) print $6 }' "$J" | grep -E '^_oauth2_proxy(_[0-9]+)?$' | sort | paste -sd' ')"
[ "$NAMES" = _oauth2_proxy ] || { echo "FAIL: oauth2-proxy cookies after the sign-in: '$NAMES' (want exactly _oauth2_proxy, no _oauth2_proxy_0…)"; exit 1; }
VAL="$(awk -F'\t' '$6 == "_oauth2_proxy" { print $7 }' "$J")"
[ "${#VAL}" -lt 512 ] || { echo "FAIL: the session cookie is ${#VAL} bytes (a ticket is ~200)"; exit 1; }
# Value = base64url(v2.<base64url(ticket id)>.<base64url(secret)>)|<time>|<signature>.
KEY="$(VAL="$VAL" python3 -c 'import base64, os
def d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
t = d(os.environ["VAL"].split("|")[0]).decode().split(".")
assert t[0] == "v2" and len(t) == 3, "not a ticket"
print(d(t[1]).decode())')" || { echo "FAIL: the session cookie is not an oauth2-proxy ticket"; exit 1; }
[[ "$KEY" =~ ^_oauth2_proxy-[0-9a-f]{32}$ ]] || { echo "FAIL: ticket id '$KEY'"; exit 1; }
[ "$(vk "$FA_PW" forward-auth get "$KEY" | wc -c)" -gt 100 ] || { echo "FAIL: the store holds no session for $KEY"; exit 1; }
expect '*NOPERM*' "forward-auth-ext can't read the session" vk "$FX_PW" forward-auth-ext get "$KEY"
echo "PASS: one small ticket cookie (${#VAL} bytes), the session under $KEY in the store"
# Sign-in part 3 (contract §5): a client-sent X-Forwarded-Impersonation /
# -Impersonator never reaches the Hub through portcullis-auth +
# portcullis-groups. If it did, the Hub's read-only rule would answer
# every POST but Stop with its "Stop first" text (GET
# /api/me/impersonation first: the chain reaches the Hub at all).
P=(--resolve "people.portcullis.local:443:127.0.0.1")
FORGED=(-H 'X-Forwarded-Impersonator: root' -H "X-Forwarded-Impersonation: 0f3c$(printf 'a%.0s' $(seq 28))")
# Retried: `portcullis up` may have just restarted the Hub, and Traefik
# routes to it only once it is healthy (Traefik's own 404 until then).
for i in $(seq 1 30); do
  code="$("${C[@]}" "${P[@]}" -o /tmp/imp-get.json -w '%{http_code}' "${FORGED[@]}" https://people.portcullis.local/api/me/impersonation)"
  [ "$code" = 404 ] || break
  sleep 2
done
if [ "$code" != 200 ] || ! jq -e '.active == null' /tmp/imp-get.json >/dev/null; then
  echo "FAIL: GET people.<d>/api/me/impersonation with forged headers: $code $(head -c 300 /tmp/imp-get.json)"; docker compose logs --tail=20 group-gate; exit 1
fi
"${C[@]}" "${P[@]}" -o /tmp/imp-post.txt -X POST -H 'Content-Type: application/json' -d '{}' "${FORGED[@]}" \
  https://people.portcullis.local/api/me/signin/browser-certificates || true
if grep -q 'signed in as someone else' /tmp/imp-post.txt; then echo "FAIL: a client-sent X-Forwarded-Impersonation reached the Hub"; exit 1; fi
echo "PASS: client-sent impersonation headers never reach the Hub (people.<d> through forward-auth + group-gate)"
# Sign out (contract §5 "Sign out"): /oauth2/sign_out only as the site
# bar's same-site POST, through portcullis-signout-guard.
A=(--resolve "portcullis.local:443:127.0.0.1")
KC_TOKEN=$(printf '%s' "$KEYCLOAK_ADMIN_PASSWORD" | curl -sf http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  --data-urlencode client_id=admin-cli --data-urlencode "username=$KEYCLOAK_ADMIN" \
  --data-urlencode grant_type=password --data-urlencode password@- | jq -r .access_token)
[ -n "$KC_TOKEN" ] && [ "$KC_TOKEN" != null ] || { echo "FAIL: no Keycloak admin token"; exit 1; }
echo "::add-mask::$KC_TOKEN"
kc() { curl -sf -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") "http://127.0.0.1:8080/admin/realms/portcullis$1"; }
TU="$(kc '/users?username=testuser&exact=true' | jq -r '.[0].id // empty')"
[ -n "$TU" ] || { echo "FAIL: testuser not found in Keycloak"; exit 1; }
# This sign-in's Keycloak session = testuser's newest (earlier steps may
# have left others of his, which this sign-out must not need to end).
SID_KC="$(kc "/users/$TU/sessions" | jq -r 'max_by(.start) | .id // empty')"
[ -n "$SID_KC" ] || { echo "FAIL: testuser has no Keycloak session after the sign-in"; exit 1; }
kc_sessions() { kc "/users/$TU/sessions" | jq --arg s "$SID_KC" '[.[] | select(.id == $s)] | length'; }
alive() {  # the ticket in the store, /oauth2/auth 202 with the cookie, Keycloak's session
  [ "$(vk "$FA_PW" forward-auth get "$KEY" | wc -c)" -gt 100 ] \
    && [ "$("${C[@]}" -o /dev/null -w '%{http_code}' https://auth.portcullis.local/oauth2/auth)" = 202 ] \
    && [ "$(kc_sessions)" -ge 1 ]
}
# 1. A cross-site link / top-level navigation (GET, the Lax cookie sent):
#    the confirmation page (405), nothing ends — also an old ?rd= link.
for u in /oauth2/sign_out "/oauth2/sign_out?rd=https%3A%2F%2Fportcullis.local%2F" /oauth2/sign_out/x; do
  code="$("${C[@]}" -o /tmp/so-page.html -w '%{http_code}' -H 'Sec-Fetch-Site: cross-site' -H 'Sec-Fetch-Mode: navigate' \
    -H 'Sec-Fetch-Dest: document' "https://auth.portcullis.local$u")"
  [ "$code" = 405 ] || { echo "FAIL: a cross-site GET of $u answered $code (want the 405 confirmation)"; exit 1; }
  grep -q 'id="pc-sign-out-confirm"' /tmp/so-page.html || { echo "FAIL: GET $u: no confirmation page"; exit 1; }
  alive || { echo "FAIL: a cross-site GET of $u signed the browser out"; exit 1; }
done
echo "PASS: a cross-site GET of /oauth2/sign_out (also ?rd= and a longer path) shows the confirmation and ends nothing"
# 2. POSTs the guard refuses: cross-site, a foreign Origin, an rd in the
#    query or a form body that could carry one.
refused() {
  local what="$1"; shift
  code="$("${C[@]}" -o /dev/null -w '%{http_code}' -X POST "$@")"
  [ "$code" = 403 ] || { echo "FAIL: $what answered $code (want 403)"; exit 1; }
  alive || { echo "FAIL: $what signed the browser out"; exit 1; }
}
refused "a cross-site POST" -H 'Sec-Fetch-Site: cross-site' -H 'Origin: https://evil.example' -H 'Content-Type: text/plain' \
  https://auth.portcullis.local/oauth2/sign_out
refused "a POST with a foreign Origin" -H 'Origin: https://evil.example' -H 'Content-Type: text/plain' https://auth.portcullis.local/oauth2/sign_out
# An app under the domain is same-site: never proof (its own origin, or none).
refused "a POST from an app (same-site, Origin app.<d>)" -H 'Sec-Fetch-Site: same-site' -H 'Origin: https://app.portcullis.local' \
  -H 'Content-Type: text/plain' https://auth.portcullis.local/oauth2/sign_out
refused "a same-site POST with Origin null" -H 'Sec-Fetch-Site: same-site' -H 'Origin: null' -H 'Content-Type: text/plain' \
  https://auth.portcullis.local/oauth2/sign_out
refused "a same-site POST with ?rd=" -H 'Sec-Fetch-Site: same-site' -H 'Origin: https://portcullis.local' -H 'Content-Type: text/plain' \
  "https://auth.portcullis.local/oauth2/sign_out?rd=https%3A%2F%2Fhub.portcullis.local%2F"
refused "a same-site form-encoded POST" -H 'Sec-Fetch-Site: same-site' -H 'Origin: https://portcullis.local' \
  --data 'rd=https%3A%2F%2Fhub.portcullis.local%2F' https://auth.portcullis.local/oauth2/sign_out
echo "PASS: cross-site / foreign-origin / app-origin / Origin-null / rd-carrying sign-out POSTs are refused (403) and end nothing"
# 3. The site bar's POST (Sign out on hub.<d>, whose page switches to
#    strict-origin before the submit, so its Origin is sent): 302 to the
#    fixed Signed out page; the ticket is gone
#    from the store, the old cookie gets 401, Keycloak's session is gone and
#    the next request to a forward-auth page goes to sign-in.
cp "$J" /tmp/sess-before.jar
HDRS="$("${C[@]}" -o /dev/null -D - -X POST -H 'Sec-Fetch-Site: same-site' -H 'Sec-Fetch-Mode: navigate' -H 'Origin: https://hub.portcullis.local' \
  -H 'Content-Type: text/plain' --data-binary '' https://auth.portcullis.local/oauth2/sign_out | tr -d '\r')"
printf '%s\n' "$HDRS" | head -1 | grep -q ' 302' || { echo "FAIL: the sign-out POST: $(printf '%s\n' "$HDRS" | head -1)"; docker compose logs --tail=20 group-gate forward-auth; exit 1; }
LOC="$(printf '%s\n' "$HDRS" | sed -n 's/^[Ll]ocation: //p')"
[ "$LOC" = https://portcullis.local/signed-out ] || { echo "FAIL: the sign-out landed on '$LOC'"; exit 1; }
[ "$(vk "$FA_PW" forward-auth get "$KEY" | wc -c)" -le 1 ] || { echo "FAIL: the session survived the sign-out"; exit 1; }
code="$(curl -s -o /dev/null -w '%{http_code}' --cacert certs/ca-chain.crt --resolve "auth.portcullis.local:443:127.0.0.1" -b /tmp/sess-before.jar https://auth.portcullis.local/oauth2/auth)"
[ "$code" = 401 ] || { echo "FAIL: the signed-out ticket still answers $code"; exit 1; }
for i in $(seq 1 10); do [ "$(kc_sessions)" = 0 ] && break; [ "$i" = 10 ] && { echo "FAIL: testuser's Keycloak session $SID_KC survived the sign-out"; docker compose logs --tail=20 forward-auth; exit 1; }; sleep 1; done
PORTAL="$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' --cacert certs/ca-chain.crt "${A[@]}" --resolve "auth.portcullis.local:443:127.0.0.1" \
  -b /tmp/sess-before.jar https://portcullis.local/)"
case "$PORTAL" in "302 https://auth.portcullis.local/"*) ;; *) echo "FAIL: the portal after the sign-out: $PORTAL (want a redirect to sign-in)"; exit 1 ;; esac
code="$(curl -s -o /tmp/so-page.html -w '%{http_code}' --cacert certs/ca-chain.crt "${A[@]}" https://portcullis.local/signed-out)"
[ "$code" = 200 ] && grep -q 'id="pc-sign-in-again" href="https://portcullis.local/"' /tmp/so-page.html \
  || { echo "FAIL: the Signed out page without a session: $code"; exit 1; }
rm -f /tmp/so-page.html
echo "PASS: the site bar's sign-out POST lands on https://portcullis.local/signed-out (no session needed); the ticket is gone from the store, the old ticket gets 401, testuser's Keycloak session is gone and the portal redirects to sign-in"
