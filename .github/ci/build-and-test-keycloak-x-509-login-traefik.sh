#!/usr/bin/env bash
# ci.yml job build-and-test, step "Test Keycloak X.509 login - via Traefik works, a forged cert header does not".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
# The Hub isn't running yet: write a minimal signin-keycloak.json
# (contract §8.1, the starting methods) into hub_data, or the sign-in
# extension denies everything (DENY_ALL). The Hub's start replaces it.
printf '%s' '{"version":1,"methods":["passkey_device","passkey_synced","security_key","yubikey_cert"],"add_stronger":false,"templates":{"standard":{"op":"any","items":[{"op":"any","items":["passkey_synced","passkey_device","security_key"]},{"op":"any","items":["yubikey_cert"]}]}},"clients":{},"authenticators":{},"mds":{"serial":0,"next_update":"0001-01-01T00:00:00Z"}}' \
  | docker run --rm -i -v portcullis_hub_data:/d docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a \
      sh -c 'cat > /d/signin-keycloak.json.tmp && chmod 644 /d/signin-keycloak.json.tmp && mv /d/signin-keycloak.json.tmp /d/signin-keycloak.json'
# pc_method=yubikey_cert = the YubiKey certificate only (the other
# methods step aside); with confirmation disabled a successful cert
# login answers 302 → redirect_uri?code=...
# portcullis-forward-auth requires PKCE S256 (like oauth2-proxy sends):
# S256 of the verifier ci-pkce-verifier-0123456789abcdefghijklmnopqrstuvwxyz.
NOPKCE='/realms/portcullis/protocol/openid-connect/auth?client_id=portcullis-forward-auth&response_type=code&scope=openid&pc_method=yubikey_cert&prompt=login&state=ci&nonce=ci&redirect_uri=https%3A%2F%2Fauth.portcullis.local%2Foauth2%2Fcallback'
AUTHQ="$NOPKCE&code_challenge=83JUujMAYgRhPwEoyXqFBcdcLnEjuT8NyjHlOlacyZo&code_challenge_method=S256"
got_code() { grep -qiE '^location: .*[?&]code=' "$1"; }

# 0) Without PKCE the forward-auth client issues no code (a stolen
#    code for an extra-domain callback is useless without the verifier).
curl -s -o /dev/null -D /tmp/kc-nopkce.h --cacert certs/ca-chain.crt \
  --cert /tmp/test-client.crt --key /tmp/test-client.key \
  --resolve "auth.portcullis.local:443:127.0.0.1" "https://auth.portcullis.local$NOPKCE" || true
if got_code /tmp/kc-nopkce.h; then echo "FAIL: portcullis-forward-auth issued a code without PKCE"; cat /tmp/kc-nopkce.h; exit 1; fi
echo "PASS: portcullis-forward-auth refuses authorization requests without PKCE"

# 1) Positive control: a real TLS client cert through Traefik (also
#    proves the CRL check + truststore re-validation pass).
curl -s -o /dev/null -D /tmp/kc-ok.h --cacert certs/ca-chain.crt \
  --cert /tmp/test-client.crt --key /tmp/test-client.key \
  --resolve "auth.portcullis.local:443:127.0.0.1" "https://auth.portcullis.local$AUTHQ" || true
got_code /tmp/kc-ok.h || { echo "FAIL: X.509 login through Traefik did not authenticate"; cat /tmp/kc-ok.h; docker compose logs --tail=60 keycloak; exit 1; }
echo "PASS: X.509 login through Traefik (CRL checked, chain re-validated) issues a code"

# 2) Forged header with that same valid, enrolled cert, sent straight
#    to Keycloak from everywhere except Traefik's address. Turn off
#    the realm's HTTPS requirement meanwhile, so plain-HTTP requests
#    reach the X.509 authenticator and only the proxy-trust gate can
#    stop them.
KC_TOKEN=$(printf '%s' "$KEYCLOAK_ADMIN_PASSWORD" | curl -sf http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  --data-urlencode client_id=admin-cli --data-urlencode "username=$KEYCLOAK_ADMIN" \
  --data-urlencode grant_type=password --data-urlencode password@- | jq -r .access_token)
[ -z "$KC_TOKEN" ] || [ "$KC_TOKEN" = null ] || echo "::add-mask::$KC_TOKEN"
realm_ssl() { printf '{"sslRequired":"%s"}' "$1" | curl -sf -X PUT -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") \
  -H 'Content-Type: application/json' -d @- http://127.0.0.1:8080/admin/realms/portcullis; }
realm_ssl none
trap 'realm_ssl all' EXIT
CERT_HDR="$(grep -v -- ----- /tmp/test-client.crt | tr -d '\n')"
FORGE=(-H "X-Forwarded-Tls-Client-Cert: $CERT_HDR" -H "X-Forwarded-For: 172.31.251.2"
       -H "X-Forwarded-Proto: https" -H "X-Forwarded-Trusted-Proxy: true")
CURL_IMG=docker.io/curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93
BEFORE=$(docker compose logs keycloak 2>&1 | grep -c 'X-Forwarded-Tls-Client-Cert" is not trusted' || true)
for net in portcullis portcullis-auth; do
  docker run --rm --network "$net" "$CURL_IMG" -s -o /dev/null -D - "${FORGE[@]}" "http://keycloak:8080$AUTHQ" > "/tmp/kc-forged-$net.h" || true
  grep -q '^HTTP/' "/tmp/kc-forged-$net.h" || { echo "FAIL: no answer from Keycloak on $net"; exit 1; }
  if got_code "/tmp/kc-forged-$net.h"; then echo "FAIL: forged cert header authenticated from the $net network"; exit 1; fi
done
curl -s -o /dev/null -D /tmp/kc-forged-host.h "${FORGE[@]}" "http://127.0.0.1:8080$AUTHQ" || true
if got_code /tmp/kc-forged-host.h; then echo "FAIL: forged cert header authenticated via 127.0.0.1:8080"; exit 1; fi
sleep 2
AFTER=$(docker compose logs keycloak 2>&1 | grep -c 'X-Forwarded-Tls-Client-Cert" is not trusted' || true)
[ "$AFTER" -ge $((BEFORE + 3)) ] || { echo "FAIL: Keycloak did not log the untrusted cert header 3x ($BEFORE → $AFTER)"; docker compose logs --tail=40 keycloak; exit 1; }
echo "PASS: forged X-Forwarded-Tls-Client-Cert ignored from portcullis, portcullis-auth and 127.0.0.1:8080 (proxy-trust gate)"

# 3) Vault keeps the CRL fresh, so crl-abort-if-non-updated=true never locks people out.
VAULT_TOKEN=$(jq -r .root_token secrets/vault-init.json); export VAULT_TOKEN
echo "::add-mask::$VAULT_TOKEN"
vault read -format=json pki_int/config/crl | jq -e '.data.auto_rebuild == true and .data.enable_delta == true' >/dev/null \
  || { echo "FAIL: CRL auto_rebuild / enable_delta off: $(vault read -format=json pki_int/config/crl | jq -c .data)"; exit 1; }
for crl in crl crl/delta; do
  NEXT=$(curl -sf "http://127.0.0.1:8200/v1/pki_int/$crl/pem" | openssl crl -noout -nextupdate | cut -d= -f2)
  [ -n "$NEXT" ] && [ "$(date -d "$NEXT" +%s)" -gt "$(date +%s)" ] || { echo "FAIL: Vault $crl is missing/stale (nextUpdate '$NEXT')"; exit 1; }
  echo "PASS: pki_int/$crl nextUpdate $NEXT"
done
echo "PASS: CRL auto-rebuild + delta CRL on (group-gate and Keycloak read both)"
