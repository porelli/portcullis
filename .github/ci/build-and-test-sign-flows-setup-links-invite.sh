#!/usr/bin/env bash
# ci.yml job build-and-test, step "Test the sign-in flows, setup links and the invite APIs".
# Moved out of ci.yml (GitHub refuses a workflow file over 500 KB);
# the step runs it from the workspace root with GitHub's default shell
# behaviour (bash -e).
set -e
set -o pipefail
# The invite IdP is created by configure once enroll runs (Keycloak
# resolves http://enroll:8445 to accept it; it is not in the realm
# import). Idempotent: the flows were synced by the first run.
# Regression (test server 2026-11-12): a realm whose passwordless
# passkey policy drifted (conveyance none, attachment cross-platform)
# must be put back by configure — the checks below expect direct.
PRE_TOKEN=$(printf '%s' "$KEYCLOAK_ADMIN_PASSWORD" | curl -sf http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  --data-urlencode client_id=admin-cli --data-urlencode "username=${KEYCLOAK_ADMIN:-admin}" \
  --data-urlencode grant_type=password --data-urlencode password@- | jq -r .access_token)
[ -n "$PRE_TOKEN" ] && [ "$PRE_TOKEN" != null ] || { echo "FAIL: admin token for the passkey-policy drift check"; exit 1; }
echo "::add-mask::$PRE_TOKEN"
echo '{"webAuthnPolicyPasswordlessRpEntityName": "Portcullis", "webAuthnPolicyPasswordlessAttestationConveyancePreference": "none", "webAuthnPolicyPasswordlessAuthenticatorAttachment": "cross-platform"}' \
  | curl -sf -X PUT -H @<(printf 'Authorization: Bearer %s\n' "$PRE_TOKEN") -H 'Content-Type: application/json' --data-binary @- \
    http://127.0.0.1:8080/admin/realms/portcullis \
  || { echo "FAIL: drifting the passkey policy"; exit 1; }
curl -sf -H @<(printf 'Authorization: Bearer %s\n' "$PRE_TOKEN") http://127.0.0.1:8080/admin/realms/portcullis \
  | jq -e '.webAuthnPolicyPasswordlessAttestationConveyancePreference == "none"' >/dev/null \
  || { echo "FAIL: the drift didn't take (the check would prove nothing)"; exit 1; }
unset PRE_TOKEN
OUT=$(./portcullis keycloak configure)
echo "$OUT" | grep -c "up to date" | grep -qx 3 || { echo "FAIL: flows rebuilt on a second configure"; echo "$OUT"; exit 1; }
echo "$OUT" | grep -q "invite identity provider (URLs, client secret): ok" || { echo "FAIL: invite IdP not configured"; echo "$OUT"; exit 1; }
KC_TOKEN=$(printf '%s' "$KEYCLOAK_ADMIN_PASSWORD" | curl -sf http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  --data-urlencode client_id=admin-cli --data-urlencode "username=${KEYCLOAK_ADMIN:-admin}" \
  --data-urlencode grant_type=password --data-urlencode password@- | jq -r .access_token)
[ -z "$KC_TOKEN" ] || [ "$KC_TOKEN" = null ] || echo "::add-mask::$KC_TOKEN"
kc() { curl -sf -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") "http://127.0.0.1:8080/admin/realms/portcullis$1"; }
# The browser flow (contract §8.1): only the sign-in extension's
# methods (no stock password, passkey or X.509 authenticator, no LoA
# condition), ending with the template check; the invite IdP is
# reachable only with kc_idp_hint (hidden), linking to existing users only.
EX=$(kc /authentication/flows/portcullis-universal/executions)
echo "$EX" | jq -e '[.[] | [.level, (if .authenticationFlow then .displayName else .providerId end), .requirement]]
    == [[0, "portcullis-authenticate", "REQUIRED"], [1, "auth-cookie", "ALTERNATIVE"], [1, "identity-provider-redirector", "ALTERNATIVE"],
        [1, "portcullis-signin", "ALTERNATIVE"], [2, "portcullis-x509", "ALTERNATIVE"], [2, "portcullis-x509", "ALTERNATIVE"],
        [2, "portcullis-signin-passkey", "ALTERNATIVE"],
        [3, "portcullis-passkey", "REQUIRED"],
        [3, "portcullis-passkey-security-key", "CONDITIONAL"], [4, "portcullis-condition-passkey-kind", "REQUIRED"], [4, "portcullis-method", "REQUIRED"],
        [3, "portcullis-passkey-device", "CONDITIONAL"], [4, "portcullis-condition-passkey-kind", "REQUIRED"], [4, "portcullis-method", "REQUIRED"],
        [3, "portcullis-passkey-synced", "CONDITIONAL"], [4, "portcullis-condition-passkey-kind", "REQUIRED"], [4, "portcullis-method", "REQUIRED"],
        [2, "portcullis-password-form", "ALTERNATIVE"], [0, "portcullis-template", "REQUIRED"]]' >/dev/null \
  || { echo "FAIL: browser flow: $(echo "$EX" | jq -c '[.[] | [.level, (if .authenticationFlow then .displayName else .providerId end), .requirement]]')"; exit 1; }
# Every reference execution keeps its method 10 h in the amr.
for c in $(echo "$EX" | jq -r '.[] | select(.providerId // "" | IN("portcullis-x509", "portcullis-password-form", "portcullis-method")) | .authenticationConfig // "none"'); do
  kc "/authentication/config/$c" | jq -e '(.config["default.reference.value"] | IN("mtls", "file", "pwd", "hwk", "dpk", "spk")) and .config["default.reference.maxAge"] == "36000"' >/dev/null \
    || { echo "FAIL: reference config $c: $(kc "/authentication/config/$c" | jq -c .config)"; exit 1; }
done
# The two x509 executions (contract §8.1, sign-in part 2), in order:
# x509-config (YubiKey: pki_int's CA and CRLs, amr mtls), then
# x509-browser-config (browser: pki_file's, amr file), as configure pushed them.
X509=$(for c in $(echo "$EX" | jq -r '.[] | select(.providerId == "portcullis-x509") | .authenticationConfig'); do
         kc "/authentication/config/$c" | jq -c '{alias, m: .config["portcullis.method"], ref: .config["default.reference.value"], ca: .config["portcullis.ca"],
             crl: .config["x509-cert-auth.crl-relative-path"], abort: .config["x509-cert-auth-crl-abort-if-non-updated"]}'
       done | jq -sc .)
T=/opt/keycloak/conf/truststores/portcullis
[ "$X509" = "$(jq -nc --arg t "$T" '[{alias: "x509-config", m: "yubikey_cert", ref: "mtls", ca: "\($t)/portcullis-yubikey-ca.pem",
      crl: "http://vault:8200/v1/pki_int/crl##http://vault:8200/v1/pki_int/crl/delta", abort: "true"},
    {alias: "x509-browser-config", m: "browser_cert", ref: "file", ca: "\($t)/portcullis-browser-ca.pem",
      crl: "http://vault:8200/v1/pki_file/crl##http://vault:8200/v1/pki_file/crl/delta", abort: "true"}]')" ] \
  || { echo "FAIL: the x509 configs: $X509"; exit 1; }
kc /events/config | jq -e '.eventsEnabled and ((.enabledEventTypes | sort) == ["IMPERSONATE", "LOGIN", "LOGIN_ERROR"]) and .eventsExpiration > 0' >/dev/null \
  || { echo "FAIL: realm events config: $(kc /events/config | jq -c '{eventsEnabled, enabledEventTypes, eventsExpiration}')"; exit 1; }
kc /authentication/required-actions | jq -e '[.[] | select(.alias | startswith("webauthn-register")) | [.alias, .enabled]] | sort
    == [["webauthn-register", false], ["webauthn-register-passwordless", true]]' >/dev/null \
  || { echo "FAIL: required actions: webauthn-register-passwordless on, the two-factor webauthn-register off"; exit 1; }
kc "" | jq -e '.attributes["acr.loa.map"] == "{}" and .bruteForceProtected and .failureFactor == 10 and .waitIncrementSeconds == 60
    and .maxFailureWaitSeconds == 900 and (.permanentLockout | not) and .webAuthnPolicyPasswordlessAttestationConveyancePreference == "direct"
    and .webAuthnPolicyPasswordlessAuthenticatorAttachment == "not specified" and .webAuthnPolicyPasswordlessRequireResidentKey == "Yes"
    and .webAuthnPolicyPasswordlessUserVerificationRequirement == "required"' >/dev/null \
  || { echo "FAIL: realm sign-in settings: $(kc "" | jq -c '{loa: .attributes["acr.loa.map"], bruteForceProtected, failureFactor, waitIncrementSeconds, maxFailureWaitSeconds, permanentLockout, att: .webAuthnPolicyPasswordlessAttestationConveyancePreference, attachment: .webAuthnPolicyPasswordlessAuthenticatorAttachment, rk: .webAuthnPolicyPasswordlessRequireResidentKey, uv: .webAuthnPolicyPasswordlessUserVerificationRequirement}')"; exit 1; }
kc /authentication/flows | jq -e 'any(.[]; .alias == "portcullis-universal" and (.description | test("\\[sync [0-9a-f]{10}\\]$")))' >/dev/null \
  || { echo "FAIL: browser flow not synced from realm-export.json"; exit 1; }
kc /identity-provider/instances/portcullis-invite | jq -e '.enabled and .hideOnLogin and (.trustEmail | not)
    and .firstBrokerLoginFlowAlias == "portcullis-invite-link" and .postBrokerLoginFlowAlias == "portcullis-invite-session"
    and .config.tokenUrl == "http://enroll:8445/oidc/token" and .config.pkceEnabled == "true"' >/dev/null \
  || { echo "FAIL: invite identity provider: $(kc /identity-provider/instances/portcullis-invite | jq -c 'del(.config.clientSecret)')"; exit 1; }
kc /authentication/flows/portcullis-invite-link/executions | jq -e '[.[].providerId] == ["idp-detect-existing-broker-user", "idp-auto-link"]' >/dev/null \
  || { echo "FAIL: invite first-login flow must only link existing users"; exit 1; }
# Post-broker flow: only portcullis-forward-auth (marker scope), a
# positive check then deny-unless-admitted, then amr inv and the
# template check (contract §8 "Invite links").
INV=$(kc /authentication/flows/portcullis-invite-session/executions)
echo "$INV" | jq -e '[.[] | select(.level == 0) | [(if .authenticationFlow then .displayName else .providerId end), .requirement]]
    == [["portcullis-invite-client", "CONDITIONAL"], ["portcullis-invite-deny", "CONDITIONAL"], ["allow-access-authenticator", "REQUIRED"], ["portcullis-template", "REQUIRED"]]
    and ([.[] | select(.level == 1) | .providerId] == ["conditional-client-scope", "allow-access-authenticator",
           "conditional-sub-flow-executed", "deny-access-authenticator"])' >/dev/null \
  || { echo "FAIL: invite post-broker flow: $(echo "$INV" | jq -c '[.[] | {displayName, providerId, requirement, level}]')"; exit 1; }
kc "/authentication/config/$(echo "$INV" | jq -r '.[] | select(.level == 0 and .providerId == "allow-access-authenticator") | .authenticationConfig')" \
  | jq -e '.config["default.reference.value"] == "inv" and .config["default.reference.maxAge"] == "36000"' >/dev/null \
  || { echo "FAIL: the invite flow's amr is not inv"; exit 1; }
FWD=$(kc "/clients?clientId=portcullis-forward-auth" | jq -r '.[0].id')
SCOPE_ID=$(kc /client-scopes | jq -r '.[] | select(.name == "portcullis-invite-client") | .id')
kc "/clients/$FWD" | jq -e '.attributes["pkce.code.challenge.method"] == "S256"' >/dev/null \
  || { echo "FAIL: portcullis-forward-auth does not require PKCE S256"; exit 1; }
# No LoA request on the forward-auth client (contract §8.1: the Hub
# pushes no default.acr.values; configure clears it).
kc "/clients/$FWD" | jq -e '(.attributes["default.acr.values"] // "") == ""' >/dev/null \
  || { echo "FAIL: portcullis-forward-auth has default.acr.values: $(kc "/clients/$FWD" | jq -c '.attributes["default.acr.values"]')"; exit 1; }
kc "/clients/$FWD/default-client-scopes" | jq -e --arg s "$SCOPE_ID" '[.[] | select(.id == $s)] | length == 1' >/dev/null \
  || { echo "FAIL: portcullis-forward-auth lacks the portcullis-invite-client scope"; exit 1; }
kc /default-default-client-scopes | jq -e --arg s "$SCOPE_ID" 'all(.[]; .id != $s)' >/dev/null \
  || { echo "FAIL: portcullis-invite-client is a realm default scope"; exit 1; }
# configure keeps the Hub's extra-domain callbacks on the forward-auth client (contract §5).
kc "/clients/$FWD" | jq '.redirectUris += ["https://grafana.team-b.example.org/oauth2/callback", "https://evil.example.org/*"]' \
  | curl -sf -X PUT -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") -H 'Content-Type: application/json' --data-binary @- \
      "http://127.0.0.1:8080/admin/realms/portcullis/clients/$FWD"
./portcullis keycloak configure >/dev/null
KC_TOKEN=$(printf '%s' "$KEYCLOAK_ADMIN_PASSWORD" | curl -sf http://127.0.0.1:8080/realms/master/protocol/openid-connect/token \
  --data-urlencode client_id=admin-cli --data-urlencode "username=${KEYCLOAK_ADMIN:-admin}" \
  --data-urlencode grant_type=password --data-urlencode password@- | jq -r .access_token)
[ -z "$KC_TOKEN" ] || [ "$KC_TOKEN" = null ] || echo "::add-mask::$KC_TOKEN"
kc "/clients/$FWD" | jq -e '.redirectUris | sort == ["https://auth.portcullis.local/oauth2/callback", "https://grafana.team-b.example.org/oauth2/callback"]' >/dev/null \
  || { echo "FAIL: configure did not keep (only) the extra-domain callbacks: $(kc "/clients/$FWD" | jq -c .redirectUris)"; exit 1; }
kc "/clients/$FWD" | jq '.redirectUris = ["https://auth.portcullis.local/oauth2/callback"]' \
  | curl -sf -X PUT -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") -H 'Content-Type: application/json' --data-binary @- \
      "http://127.0.0.1:8080/admin/realms/portcullis/clients/$FWD"
echo "PASS: invite post-broker flow limited to portcullis-forward-auth; configure keeps extra-domain callbacks"
# No LDAP user cache: group/attribute changes in LLDAP reach tokens at once.
kc "/components?type=org.keycloak.storage.UserStorageProvider" | jq -e '[.[] | select(.providerId == "ldap")][0].config.cachePolicy == ["NO_CACHE"]' >/dev/null \
  || { echo "FAIL: LDAP federation cachePolicy is not NO_CACHE"; exit 1; }
ENR=$(kc "/clients?clientId=portcullis-enroll" | jq -r '.[0].id')
SA=$(kc "/clients/$ENR/service-account-user" | jq -r .id)
RM=$(kc "/clients?clientId=realm-management" | jq -r '.[0].id')
kc "/users/$SA/role-mappings/clients/$RM" | jq -e '[.[].name] | sort == ["manage-users", "view-users"]' >/dev/null \
  || { echo "FAIL: portcullis-enroll service account roles"; exit 1; }
echo "PASS: passkey-only browser flow, hidden invite IdP (link-only), enroll service account; configure idempotent"

# Setup links (CLI → enroll over docker exec; enroll needs no secret on argv).
L1=$(./portcullis invite testuser --json | jq -r .url)
L2=$(./portcullis invite testuser --ttl 30m --to hub --json | jq -r .url)
for l in "$L1" "$L2"; do [ -z "$l" ] || [ "$l" = null ] || echo "::add-mask::$l"; done
for l in "$L1" "$L2"; do [[ "$l" =~ ^https://enroll\.portcullis\.local/invite/[A-Za-z0-9_-]{43}$ ]] || { echo "FAIL: link $l"; exit 1; }; done
page() { curl -s -o /dev/null -w '%{http_code}' "http://$ENROLL_IP:8443/invite/${1##*/}"; }
[ "$(page "$L1")" = 404 ] || { echo "FAIL: a new link must revoke the older one"; exit 1; }
[ "$(page "$L2")" = 200 ] || { echo "FAIL: setup page"; exit 1; }
[ "$(page "$L2")" = 200 ] || { echo "FAIL: viewing the setup page must not consume the link"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Sec-Fetch-Site: cross-site' "http://$ENROLL_IP:8443/invite/${L2##*/}")
[ "$code" = 403 ] || { echo "FAIL: cross-site redeem got $code"; exit 1; }
if ./portcullis invite portcullis-hub >/dev/null 2>&1; then echo "FAIL: invite for the Hub's service account"; exit 1; fi
./portcullis invite admin --json | jq -e .url >/dev/null || { echo "FAIL: the server must be able to invite the bootstrap admin"; exit 1; }
# The Hub's API (contract §9.4): bearer secret from the shared file; admin / portcullis-hub refused.
api() { jq -n --arg u "$1" '{username: $u}' | curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
    -H @<(printf 'Authorization: Bearer %s%s\n' "$(cat secrets/enroll/invite-api-secret)" "${2:-}") \
    -d @- "http://$ENROLL_IP:8444/internal/invites"; }
[ "$(api testuser)" = 201 ] || { echo "FAIL: Hub invite API for testuser"; exit 1; }
# Any lldap_admin member (not just `admin`) is refused: an invite hands over the account.
LT=$(jq -n '{username: "admin", password: env.LLDAP_ADMIN_PASSWORD}' \
  | curl -sf http://127.0.0.1:17170/auth/simple/login -H 'Content-Type: application/json' -d @- | jq -r .token)
[ -z "$LT" ] || [ "$LT" = null ] || echo "::add-mask::$LT"
lg() { jq -n --arg q "$1" '{query: $q}' | curl -sf http://127.0.0.1:17170/api/graphql \
  -H @<(printf 'Authorization: Bearer %s\n' "$LT") -H 'Content-Type: application/json' -d @- | jq -e '.errors == null' >/dev/null; }
lg 'mutation { createUser(user: {id: "ciadmin2", email: "ciadmin2@portcullis.local"}) { id } }'
lg 'mutation { addUserToGroup(userId: "ciadmin2", groupId: 1) { ok } }'
[ "$(api ciadmin2)" = 409 ] || { echo "FAIL: Hub invite API must refuse lldap_admin members"; exit 1; }
./portcullis invite ciadmin2 --json | jq -e .url >/dev/null || { echo "FAIL: the server must be able to invite an administrator"; exit 1; }
lg 'mutation { deleteUser(userId: "ciadmin2") { ok } }'
for u in admin portcullis-hub; do [ "$(api "$u")" = 409 ] || { echo "FAIL: Hub invite API must refuse $u"; exit 1; }; done
[ "$(api nosuchuser)" = 404 ] || { echo "FAIL: Hub invite API for an unknown user"; exit 1; }
[ "$(api testuser x)" = 401 ] || { echo "FAIL: Hub invite API with a wrong secret"; exit 1; }
cmp -s secrets/enroll/invite-api-secret secrets/hub/invite/secret || { echo "FAIL: the Hub's invite secret differs"; exit 1; }
docker compose exec -T enroll wget -q -O - http://127.0.0.1:8445/oidc/jwks | jq -e '.keys[0].alg == "ES256"' >/dev/null \
  || { echo "FAIL: invite JWKS"; exit 1; }
echo "PASS: setup links (single owner, revocation, no consumption on view, same-origin redeem), Hub invite API (§9.4)"
