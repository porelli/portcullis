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
END="$("${C[@]}" -L --max-redirs 10 -o /dev/null -w '%{http_code} %{url_effective}' \
  "https://auth.portcullis.local/oauth2/start?pc_method=yubikey_cert&rd=https%3A%2F%2Fauth.portcullis.local%2Foauth2%2Fauth")"
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
# Signing out deletes it from the store: the same cookie no longer opens anything.
cp "$J" /tmp/sess-before.jar
"${C[@]}" -o /dev/null https://auth.portcullis.local/oauth2/sign_out
[ "$(vk "$FA_PW" forward-auth get "$KEY" | wc -c)" -le 1 ] || { echo "FAIL: the session survived the sign-out"; exit 1; }
code="$(curl -s -o /dev/null -w '%{http_code}' --cacert certs/ca-chain.crt --resolve "auth.portcullis.local:443:127.0.0.1" -b /tmp/sess-before.jar https://auth.portcullis.local/oauth2/auth)"
[ "$code" = 401 ] || { echo "FAIL: the signed-out ticket still answers $code"; exit 1; }
echo "PASS: sign-out removes the session from the store; the old ticket gets 401"
