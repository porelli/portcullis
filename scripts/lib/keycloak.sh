# shellcheck shell=bash
#
# `portcullis keycloak configure` and `portcullis oidc register`.
#
# Keycloak's admin API is reached on the loopback publish
# (127.0.0.1:8080), bypassing Traefik. Passwords, client secrets and the
# admin bearer token never appear on a command line: request bodies go to
# curl on stdin (-d @-) and the Authorization header through a
# process-substitution file (-H @/dev/fd/N).

KC_REALM="portcullis"

kc_url() { echo "${KEYCLOAK_URL:-http://127.0.0.1:8080}"; }

# kc_login — sets KC_TOKEN (admin-cli password grant on the master realm).
kc_login() {
  env_require KEYCLOAK_ADMIN_PASSWORD
  KC_TOKEN="$(printf '%s' "$KEYCLOAK_ADMIN_PASSWORD" | curl -sk --max-time 20 \
    "$(kc_url)/realms/master/protocol/openid-connect/token" \
    --data-urlencode "client_id=admin-cli" \
    --data-urlencode "username=${KEYCLOAK_ADMIN:-admin}" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "password@-" | jq -r '.access_token // empty' 2>/dev/null || true)"
  [ -n "$KC_TOKEN" ] || fail "Could not authenticate to Keycloak at $(kc_url) as ${KEYCLOAK_ADMIN:-admin}. Is it running (portcullis status)?"
  KC_TOKEN_AT=$SECONDS
}

# _kc_fresh — admin-cli tokens live 60 s: log in again before they expire
# (in a $(...) subshell the new token only lives for that call).
_kc_fresh() {
  if [ -n "${KC_TOKEN_AT:-}" ] && [ $(( SECONDS - KC_TOKEN_AT )) -gt 40 ]; then kc_login; fi
}

# kc_get <path> — GET JSON from the admin API (path relative to /admin/realms).
kc_get() {
  _kc_fresh
  curl -sk --max-time 20 -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") \
    "$(kc_url)/admin/realms$1"
}

# kc_send <METHOD> <path> — body on stdin (empty for none); prints HTTP code.
kc_send() {
  _kc_fresh
  curl -sk --max-time 20 -o /dev/null -w '%{http_code}' -X "$1" \
    -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") \
    -H 'Content-Type: application/json' --data-binary @- \
    "$(kc_url)/admin/realms$2"
}

# _kc_report <label> <code> <ok-codes...>
_kc_report() {
  local label="$1" code="$2" c
  shift 2
  for c in "$@"; do
    [ "$code" = "$c" ] && { echo "    $label: ok (HTTP $code)"; return 0; }
  done
  warn "    $label: unexpected HTTP $code"
  return 1
}

# _kc_ldap_patch <base-dn>: the LDAP federation component (JSON on stdin)
# with what `keycloak configure` enforces on every run (idempotent): DN +
# bind credential (env LLDAP_PASS), trustEmail off, the Hub's service
# account filtered out, and cachePolicy NO_CACHE — Keycloak's default user
# cache would keep a user's LDAP groups and attributes (attr_* claims)
# stale until eviction or the daily changed-users sync; with NO_CACHE a
# group or attribute change in LLDAP is visible at the next token refresh.
_kc_ldap_patch() {
  jq --arg b "$1" '
    .config.usersDn = ["ou=people," + $b] |
    .config.bindDn = ["uid=admin,ou=people," + $b] |
    .config.bindCredential = [env.LLDAP_PASS] |
    .config.trustEmail = ["false"] |
    .config.customUserSearchFilter = ["(!(uid=portcullis-hub))"] |
    .config.cachePolicy = ["NO_CACHE"]'
}

keycloak_configure() {
  local wipe="$1" realm code comp ldap_id mapper fwd_uuid scope_id execs flow
  require_cmd curl jq
  kc_login
  local base_dn="${LLDAP_BASE_DN:-dc=portcullis,dc=local}" domain="${PORTCULLIS_DOMAIN:-portcullis.local}"

  # Last resort: flow changes are applied by _kc_sync_flow below. Wiping
  # deletes Keycloak's copy of every user incl. their passkeys (LLDAP keeps
  # the accounts); clients are re-registered by `portcullis oidc register`.
  if [ "$wipe" = true ]; then
    warn "--wipe-realm: deleting realm $KC_REALM before import"
    code="$(kc_send DELETE "/$KC_REALM" < /dev/null)"
    _kc_report "delete realm" "$code" 204 404 || true
  fi

  info "Importing realm $KC_REALM..."
  # realm-export.json keeps LLDAP_*_PLACEHOLDER values (it is git-tracked);
  # substitute in memory only, no secret is ever written to the repo.
  # (Keycloak's own --import-realm at first start loads the file verbatim;
  # the LDAP component is patched below and the client secret is pushed by
  # `portcullis oidc register`.)
  realm="$(LLDAP_PASS="${LLDAP_ADMIN_PASSWORD:-}" FWD_SECRET="${FORWARD_AUTH_CLIENT_SECRET:-}" jq --arg b "$base_dn" '
      walk(if type == "string" then
             gsub("LLDAP_BASE_DN_PLACEHOLDER"; $b) | gsub("LLDAP_PASSWORD_PLACEHOLDER"; env.LLDAP_PASS)
             | gsub("FORWARD_AUTH_CLIENT_SECRET_PLACEHOLDER"; env.FWD_SECRET)
           else . end)' "$PORTCULLIS_ROOT/keycloak/realm-export.json")" || fail "cannot read keycloak/realm-export.json"
  code="$(printf '%s' "$realm" | kc_send POST "")"
  case "$code" in
    201) echo "    realm created" ;;
    409) echo "    realm already exists (auto-imported at first start; --wipe-realm rebuilds it)" ;;
    *) warn "    realm import: unexpected HTTP $code" ;;
  esac

  info "Pointing the LDAP federation at LLDAP..."
  # Keycloak's own --import-realm loads the file verbatim, placeholders
  # included; patch DN + bind credential onto the component (plus the user
  # filter that keeps the Hub's service account out). trustEmail
  # stays off: LLDAP lets users edit their own mail, so it is never
  # asserted as verified (identity is the username, see oauth2-proxy/alpha.yaml).
  comp="$(kc_get "/$KC_REALM/components" | jq '[.[] | select(.providerId == "ldap")][0] // empty')"
  if [ -n "$comp" ]; then
    ldap_id="$(printf '%s' "$comp" | jq -r .id)"
    code="$(printf '%s' "$comp" | LLDAP_PASS="${LLDAP_ADMIN_PASSWORD:-}" _kc_ldap_patch "$base_dn" | kc_send PUT "/$KC_REALM/components/$ldap_id")"
    _kc_report "LDAP base DN + bind credential, portcullis-hub excluded, no cache" "$code" 204 || true
    # The Hub's LLDAP service account (lldap_admin) must never sign in
    # through the gateway: the user filter above keeps it out of the
    # federation; drop a copy imported before the filter existed.
    local hub_kc
    hub_kc="$(kc_get "/$KC_REALM/users?username=portcullis-hub&exact=true" | jq -r '.[0].id // empty' 2>/dev/null || true)"
    if [ -n "$hub_kc" ]; then
      code="$(kc_send DELETE "/$KC_REALM/users/$hub_kc" < /dev/null)"
      _kc_report "remove Keycloak's copy of portcullis-hub" "$code" 204 404 || true
    fi
    mapper="$(kc_get "/$KC_REALM/components?parent=$ldap_id" | jq '[.[] | select(.providerId == "group-ldap-mapper")][0] // empty')"
    if [ -n "$mapper" ]; then
      code="$(printf '%s' "$mapper" | jq --arg b "$base_dn" '.config["groups.dn"] = ["ou=groups," + $b]' \
        | kc_send PUT "/$KC_REALM/components/$(printf '%s' "$mapper" | jq -r .id)")"
      _kc_report "group mapper groups.dn" "$code" 204 || true
    fi
  else
    warn "    no LDAP federation component found in realm $KC_REALM"
  fi

  info "Setting ACR→LoA map and the browser flow..."
  # Only switch browserFlow if it is unset or the realm's built-in value;
  # an operator's custom flow is preserved.
  # sslRequired=external: browsers only reach Keycloak through Traefik
  # (HTTPS; proxy headers trusted from Traefik only), and "all" would also
  # refuse the invite identity provider's back-channel URLs on the private
  # network (http://enroll:8445, Keycloak's URL check resolves the host).
  code="$(kc_get "/$KC_REALM" | jq '
      {sslRequired: "external", attributes: {"acr.loa.map": "{\"public\":\"0\",\"pwd\":\"1\",\"hwk\":\"2\",\"mtls\":\"3\"}"}} +
      (if ((.browserFlow // "") == "" or .browserFlow == "portcullis-browser-flow")
       then {browserFlow: "portcullis-universal"} else {} end) +
      # Login theme: unique passkey labels, so a second key (recovery) can be
      # registered; an operator-chosen theme other than the defaults is kept.
      (if ((.loginTheme // "") | IN("", "keycloak", "keycloak.v2")) then {loginTheme: "portcullis"} else {} end)' | kc_send PUT "/$KC_REALM")"
  _kc_report "realm attributes" "$code" 204 || true

  info "Syncing the authentication flows from realm-export.json..."
  for flow in $KC_EXPORT_FLOWS; do _kc_sync_flow "$flow" || true; done
  _kc_invite_idp
  _kc_enroll_client
  local ra
  ra="$(kc_get "/$KC_REALM/authentication/required-actions/webauthn-register-passwordless")"
  if printf '%s' "$ra" | jq -e '.enabled != true or .defaultAction != false' >/dev/null 2>&1; then
    code="$(printf '%s' "$ra" | jq -c '.enabled = true | .defaultAction = false' \
      | kc_send PUT "/$KC_REALM/authentication/required-actions/webauthn-register-passwordless")"
    _kc_report "webauthn-register-passwordless required action enabled" "$code" 204 || true
  fi

  info "Checking factor executors carry AMR reference values..."
  # Each authenticator in portcullis-loa-1-factors / portcullis-loa-3 /
  # portcullis-invite-loa needs an authenticatorConfig with
  # default.reference.value, or the amr claim is empty and AND-mode policies
  # cannot tell factors apart.
  for flow in portcullis-loa-1-factors portcullis-loa-3 portcullis-invite-loa; do
    execs="$(kc_get "/$KC_REALM/authentication/flows/$flow/executions")"
    printf '%s' "$execs" | jq -e 'type == "array"' >/dev/null 2>&1 || continue
    while read -r provider cfg; do
      if [ "$cfg" = none ]; then
        warn "    $flow/$provider has no authenticator config → empty amr for this factor"
      elif [ -z "$(kc_get "/$KC_REALM/authentication/config/$cfg" | jq -r '.config["default.reference.value"] // empty')" ]; then
        warn "    $flow/$provider config has no default.reference.value → empty amr for this factor"
      fi
    done < <(printf '%s' "$execs" | jq -r '.[] | select(.providerId and (.providerId | startswith("conditional-") | not)) | .providerId + " " + (.authenticationConfig // "none")')
  done

  info "Applying the X.509 authenticator config (CRL check, trust re-validation)..."
  # realm-export.json is only imported into a NEW realm; push the x509-config
  # authenticator settings onto every existing x509 execution's config.
  local x509_cfg cfg_ids cid
  x509_cfg="$(jq -c '.authenticatorConfig[] | select(.alias == "x509-config") | .config' "$PORTCULLIS_ROOT/keycloak/realm-export.json")"
  cfg_ids="$(for flow in portcullis-loa-1-factors portcullis-loa-3; do
      kc_get "/$KC_REALM/authentication/flows/$flow/executions" \
        | jq -r '.[]? | select(.providerId == "auth-x509-client-username-form") | .authenticationConfig // empty' 2>/dev/null
    done | sort -u)"
  for cid in $cfg_ids; do
    code="$(kc_get "/$KC_REALM/authentication/config/$cid" | jq --argjson c "$x509_cfg" '.config = ((.config // {}) + $c)' \
      | kc_send PUT "/$KC_REALM/authentication/config/$cid")"
    _kc_report "x509 config $cid" "$code" 204 || true
  done
  [ -n "$cfg_ids" ] || warn "    no X.509 executions found (custom flows?) — CRL checking not configured"

  info "Ensuring the amr mapper on the acr client scope..."
  scope_id="$(kc_get "/$KC_REALM/client-scopes" | jq -r '.[] | select(.name == "acr") | .id' | head -n1)"
  if [ -n "$scope_id" ]; then
    if [ "$(kc_get "/$KC_REALM/client-scopes/$scope_id/protocol-mappers/models" | jq '[.[] | select(.protocolMapper == "oidc-amr-mapper")] | length')" = 0 ]; then
      code="$(jq -n '{name: "amr", protocol: "openid-connect", protocolMapper: "oidc-amr-mapper",
          config: {"id.token.claim": "true", "access.token.claim": "true", "introspection.token.claim": "true",
                   "userinfo.token.claim": "true", "claim.name": "amr"}}' \
        | kc_send POST "/$KC_REALM/client-scopes/$scope_id/protocol-mappers/models")"
      _kc_report "amr mapper" "$code" 201 || true
    else
      echo "    amr mapper present"
    fi
  fi

  info "Ensuring the groups client scope..."
  if [ "$(kc_get "/$KC_REALM/client-scopes" | jq '[.[] | select(.name == "groups")] | length')" = 0 ]; then
    code="$(jq -n '{name: "groups", protocol: "openid-connect",
        attributes: {"include.in.token.scope": "true", "display.on.consent.screen": "true"},
        protocolMappers: [{name: "groups", protocol: "openid-connect", protocolMapper: "oidc-group-membership-mapper",
          config: {"id.token.claim": "true", "access.token.claim": "true", "introspection.token.claim": "true",
                   "userinfo.token.claim": "true", "claim.name": "groups", "full.path": "false"}}]}' \
      | kc_send POST "/$KC_REALM/client-scopes")"
    _kc_report "groups scope" "$code" 201 || true
  else
    echo "    groups scope present"
  fi

  _kc_email_unverified_scope
  info "Granting lldap_admin the $KC_REALM realm console..."
  _kc_admin_roles

  info "Configuring the forward-auth client (acr, groups, redirect URI)..."
  fwd_uuid="$(kc_get "/$KC_REALM/clients?clientId=portcullis-forward-auth" | jq -r '.[0].id // empty')"
  if [ -n "$fwd_uuid" ]; then
    # The realm export ships a placeholder host so Keycloak's URL parser
    # accepts it at import; put the real domain on.
    code="$(kc_get "/$KC_REALM/clients/$fwd_uuid" | jq --arg d "$domain" '
        .attributes = ((.attributes // {}) + {"default.acr.values": "pwd"}) |
        .defaultClientScopes = ((.defaultClientScopes // []) + ["acr"] | unique) |
        .redirectUris = ["https://auth." + $d + "/oauth2/callback"]' \
      | kc_send PUT "/$KC_REALM/clients/$fwd_uuid")"
    _kc_report "forward-auth client" "$code" 204 || true
    scope_id="$(kc_get "/$KC_REALM/client-scopes" | jq -r '.[] | select(.name == "groups") | .id' | head -n1)"
    if [ -n "$scope_id" ]; then
      code="$(kc_send PUT "/$KC_REALM/clients/$fwd_uuid/default-client-scopes/$scope_id" < /dev/null)"
      _kc_report "attach groups scope" "$code" 204 || true
    fi
  else
    warn "    client portcullis-forward-auth not found (run: ./portcullis oidc register)"
  fi

  info "Ensuring test user..."
  code="$(jq -n '{username: "testuser", email: "testuser@portcullis.local", enabled: true,
      firstName: "Test", lastName: "User"}' | kc_send POST "/$KC_REALM/users")"
  _kc_report "testuser" "$code" 201 409 || true

  local name="${PORTAL_DISPLAY_NAME:-Portcullis}"
  info "Applying branding: $name"
  code="$(jq -n --arg n "$name" '{displayName: $n,
      displayNameHtml: ("<span style=\"font-size:2rem;font-weight:700;letter-spacing:-0.02em\">" + $n + "</span>")}' \
    | kc_send PUT "/$KC_REALM")"
  _kc_report "branding" "$code" 204 || true

  ok "Keycloak configured. Admin console: https://auth.$domain/admin/master/console/"
  echo "    SAML metadata: https://auth.$domain/realms/$KC_REALM/protocol/saml/descriptor"
}

# Client scope that carries `email` but never `email_verified`. LLDAP lets
# users edit their own mail, so the built-in `email` scope always says
# email_verified=false; apps that refuse that value but accept the claim
# being absent (Vaultwarden SSO signups) get this scope instead of `email`
# (Hub: keycloak_clients[].email_verified_claim: false). Identity stays the
# sub / username; the email is still unverified, just not labelled.
KC_EMAIL_UNVERIFIED_SCOPE="email-unverified"

# _kc_email_unverified_scope — create the scope, or reconcile an existing one
# to exactly one `email` mapper (any other mapper, e.g. an added
# "email verified", is deleted).
_kc_email_unverified_scope() {
  local scope_id rep mappers mid code
  local mapper='{name: "email", protocol: "openid-connect", protocolMapper: "oidc-usermodel-property-mapper",
      config: {"user.attribute": "email", "claim.name": "email", "jsonType.label": "String",
               "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true",
               "introspection.token.claim": "true"}}'
  local attrs='{"include.in.token.scope": "true", "display.on.consent.screen": "true"}'

  info "Ensuring the $KC_EMAIL_UNVERIFIED_SCOPE client scope (email, no email_verified)..."
  scope_id="$(kc_get "/$KC_REALM/client-scopes" | jq -r --arg n "$KC_EMAIL_UNVERIFIED_SCOPE" '.[] | select(.name == $n) | .id' | head -n1)"
  if [ -z "$scope_id" ]; then
    code="$(jq -n --arg n "$KC_EMAIL_UNVERIFIED_SCOPE" "{name: \$n, protocol: \"openid-connect\",
        description: \"email claim without email_verified (LLDAP email is user-editable)\",
        attributes: $attrs, protocolMappers: [$mapper]}" | kc_send POST "/$KC_REALM/client-scopes")"
    _kc_report "$KC_EMAIL_UNVERIFIED_SCOPE scope" "$code" 201 || true
    return 0
  fi

  rep="$(kc_get "/$KC_REALM/client-scopes/$scope_id")"
  code="$(printf '%s' "$rep" | jq "del(.protocolMappers) | .protocol = \"openid-connect\" |
      .attributes = ((.attributes // {}) + $attrs)" | kc_send PUT "/$KC_REALM/client-scopes/$scope_id")"
  _kc_report "$KC_EMAIL_UNVERIFIED_SCOPE scope attributes" "$code" 204 || true

  mappers="$(kc_get "/$KC_REALM/client-scopes/$scope_id/protocol-mappers/models")"
  printf '%s' "$mappers" | jq -e 'type == "array"' >/dev/null 2>&1 \
    || { warn "    cannot list $KC_EMAIL_UNVERIFIED_SCOPE mappers"; return 0; }
  for mid in $(printf '%s' "$mappers" | jq -r '.[] | select(.name != "email") | .id'); do
    code="$(kc_send DELETE "/$KC_REALM/client-scopes/$scope_id/protocol-mappers/models/$mid" < /dev/null)"
    _kc_report "remove extra mapper $mid" "$code" 204 || true
  done
  mid="$(printf '%s' "$mappers" | jq -r '[.[] | select(.name == "email")][0].id // empty')"
  if [ -z "$mid" ]; then
    code="$(jq -n "$mapper" | kc_send POST "/$KC_REALM/client-scopes/$scope_id/protocol-mappers/models")"
    _kc_report "email mapper" "$code" 201 || true
  else
    code="$(jq -n --arg id "$mid" "$mapper + {id: \$id}" \
      | kc_send PUT "/$KC_REALM/client-scopes/$scope_id/protocol-mappers/models/$mid")"
    _kc_report "email mapper" "$code" 204 || true
  fi
}

KC_EXPORT_FLOWS="portcullis-universal portcullis-invite-link portcullis-invite-session"

# _kc_export — realm-export.json (path) for jq.
_kc_export() { echo "$PORTCULLIS_ROOT/keycloak/realm-export.json"; }

# _kc_flow_tree <top-alias> — the export's flows reachable from <top-alias>
# plus the authenticator configs they use, as compact sorted JSON.
_kc_flow_tree() {
  jq -cS --arg top "$1" '
    .authenticationFlows as $f | .authenticatorConfig as $c
    | def reach($a): [$a] + ([$f[] | select(.alias == $a) | .authenticationExecutions[] | select(.flowAlias) | .flowAlias]
                            | map(reach(.)) | add // []);
      (reach($top) | unique) as $names
    | {flows: [$f[] | select(.alias as $a | $names | index($a))],
       configs: [$c[] | select(.alias as $a | [$f[] | select(.alias as $x | $names | index($x)) | .authenticationExecutions[].authenticatorConfig] | index($a))]}' \
    "$(_kc_export)"
}

# _kc_flow_id <alias> — id of the realm flow with that alias, or empty.
_kc_flow_id() {
  kc_get "/$KC_REALM/authentication/flows" | jq -r --arg a "$1" '[.[]? | select(.alias == $a)][0].id // empty'
}

# _kc_build_execs <tree-json> <export-flow> <realm-flow> <suffix> — add the
# export flow's executions (recursively) to an existing, empty realm flow.
# Sub-flows get "<alias>.<suffix>", configs "<alias>.<suffix>.<seq>" (aliases
# are realm-unique and the export shares x509-config between executions);
# _kc_sync_flow renames them once the old tree is gone.
_kc_build_execs() {
  local tree="$1" src="$2" dst="$3" sfx="$4" ex prio req sub prov cfg id code n
  while read -r ex; do
    prio="$(jq -r .priority <<<"$ex")"; req="$(jq -r .requirement <<<"$ex")"
    if [ "$(jq -r .authenticatorFlow <<<"$ex")" = true ]; then
      sub="$(jq -r .flowAlias <<<"$ex")"
      code="$(jq -nc --arg a "$sub.$sfx" --argjson p "$prio" \
          --arg d "$(jq -r --arg a "$sub" '[.flows[] | select(.alias == $a)][0].description // ""' <<<"$tree")" \
          '{alias: $a, type: "basic-flow", priority: $p, description: $d}' \
        | kc_send POST "/$KC_REALM/authentication/flows/$dst/executions/flow")"
      [ "$code" = 201 ] || { warn "    $dst: add sub-flow $sub: HTTP $code"; return 1; }
    else
      prov="$(jq -r .authenticator <<<"$ex")"
      code="$(jq -nc --arg p "$prov" --argjson n "$prio" '{provider: $p, priority: $n}' \
        | kc_send POST "/$KC_REALM/authentication/flows/$dst/executions/execution")"
      [ "$code" = 201 ] || { warn "    $dst: add $prov: HTTP $code"; return 1; }
    fi
    id="$(kc_get "/$KC_REALM/authentication/flows/$dst/executions" \
      | jq -c --argjson p "$prio" '[.[] | select(.level == 0 and .priority == $p)][0]')"
    code="$(jq -c --arg r "$req" '.requirement = $r' <<<"$id" | kc_send PUT "/$KC_REALM/authentication/flows/$dst/executions")"
    case "$code" in 202|204) ;; *) warn "    $dst: requirement $req (priority $prio): HTTP $code"; return 1 ;; esac
    cfg="$(jq -r '.authenticatorConfig // empty' <<<"$ex")"
    if [ -n "$cfg" ]; then
      _KC_CFG_SEQ=$(( _KC_CFG_SEQ + 1 ))
      code="$(jq -c --arg a "$cfg" --arg n "$cfg.$sfx.$_KC_CFG_SEQ" '[.configs[] | select(.alias == $a)][0] | .alias = $n' <<<"$tree" \
        | kc_send POST "/$KC_REALM/authentication/executions/$(jq -r .id <<<"$id")/config")"
      [ "$code" = 201 ] || { warn "    $dst: config $cfg: HTTP $code"; return 1; }
    fi
    if [ "$(jq -r .authenticatorFlow <<<"$ex")" = true ]; then
      _kc_build_execs "$tree" "$sub" "$sub.$sfx" "$sfx" || return 1
    fi
  done < <(jq -c --arg a "$src" '[.flows[] | select(.alias == $a)][0].authenticationExecutions | sort_by(.priority)[]' <<<"$tree")
}

# _kc_sync_flow <top-alias> — make the realm's flow tree equal to the
# export's. Nested flow changes cannot be applied in place reliably, so a
# changed tree is rebuilt next to the old one ("<alias>.<hash>"), bindings
# (realm browser flow, identity providers) are moved over, the old tree is
# deleted (with its configs) and the new one renamed. The tree's hash is
# kept in the top flow's description: unchanged trees are left alone.
_kc_sync_flow() {
  local top="$1" tree hash marker cur old_id new_id code idp desc f sfx
  tree="$(_kc_flow_tree "$top")"
  hash="$(printf '%s' "$tree" | sha256sum | cut -c1-10)"
  marker="[sync $hash]"
  cur="$(kc_get "/$KC_REALM/authentication/flows" | jq -r --arg a "$top" '[.[]? | select(.alias == $a)][0].description // empty')"
  if [ "${cur% "$marker"}" != "$cur" ]; then
    echo "    $top: up to date"
    return 0
  fi
  # Leftovers of an interrupted run.
  for f in $(kc_get "/$KC_REALM/authentication/flows" | jq -r --arg a "$top." '.[]? | select(.alias | startswith($a)) | .id'); do
    kc_send DELETE "/$KC_REALM/authentication/flows/$f" < /dev/null >/dev/null
  done
  # Build suffix: unique per run, so a half-renamed earlier build never clashes.
  sfx="b$(date +%s)$$"
  desc="$(jq -r --arg a "$top" '[.flows[] | select(.alias == $a)][0].description' <<<"$tree") $marker"
  code="$(jq -nc --arg a "$top.$sfx" --arg d "$desc" \
      '{alias: $a, description: $d, providerId: "basic-flow", topLevel: true, builtIn: false}' \
    | kc_send POST "/$KC_REALM/authentication/flows")"
  [ "$code" = 201 ] || { warn "    $top: create: HTTP $code"; return 1; }
  _KC_CFG_SEQ=0
  _kc_build_execs "$tree" "$top" "$top.$sfx" "$sfx" || { warn "    $top: rebuild failed, the realm keeps the old flow"; return 1; }

  # Move the bindings, then drop the old tree.
  if [ "$(kc_get "/$KC_REALM" | jq -r --arg a "$top" '(.browserFlow // "") as $b | ($b == $a or ($a == "portcullis-universal" and ($b == "" or $b == "browser" or $b == "portcullis-browser-flow")))')" = true ]; then
    code="$(jq -nc --arg a "$top.$sfx" '{browserFlow: $a}' | kc_send PUT "/$KC_REALM")"
    _kc_report "$top: browser flow binding" "$code" 204 || return 1
  fi
  while read -r idp; do
    [ -n "$idp" ] || continue
    code="$(kc_get "/$KC_REALM/identity-provider/instances/$idp" | jq -c --arg o "$top" --arg n "$top.$sfx" '
        (if .firstBrokerLoginFlowAlias == $o then .firstBrokerLoginFlowAlias = $n else . end)
        | (if .postBrokerLoginFlowAlias == $o then .postBrokerLoginFlowAlias = $n else . end)' \
      | kc_send PUT "/$KC_REALM/identity-provider/instances/$idp")"
    _kc_report "$top: identity provider $idp binding" "$code" 204 || return 1
  done < <(kc_get "/$KC_REALM/identity-provider/instances" | jq -r --arg a "$top" '.[]? | select(.firstBrokerLoginFlowAlias == $a or .postBrokerLoginFlowAlias == $a) | .alias')
  old_id="$(_kc_flow_id "$top")"
  if [ -n "$old_id" ]; then
    code="$(kc_send DELETE "/$KC_REALM/authentication/flows/$old_id" < /dev/null)"
    _kc_report "$top: remove the previous flow" "$code" 204 || return 1
  fi
  # Canonical names (GET /flows lists top-level flows only: sub-flows come
  # from the executions).
  new_id="$(_kc_flow_id "$top.$sfx")"
  code="$(kc_get "/$KC_REALM/authentication/flows/$new_id" | jq -c --arg a "$top" '.alias = $a | del(.authenticationExecutions)' \
    | kc_send PUT "/$KC_REALM/authentication/flows/$new_id")"
  _kc_report "$top: rename" "$code" 204 || return 1
  while read -r f; do
    [ -n "$f" ] || continue
    code="$(kc_get "/$KC_REALM/authentication/flows/${f%% *}" | jq -c --arg a "${f#* }" '.alias = ($a | sub("\\.[^.]+$"; "")) | del(.authenticationExecutions)' \
      | kc_send PUT "/$KC_REALM/authentication/flows/${f%% *}")"
    [ "$code" = 204 ] || warn "    rename ${f#* }: HTTP $code"
  done < <(kc_get "/$KC_REALM/authentication/flows/$top/executions" \
    | jq -r --arg h ".$sfx" '.[] | select(.authenticationFlow == true and (.displayName | endswith($h))) | .flowId + " " + .displayName')
  # Configs: the first use of an export alias gets the alias, later ones "-2", "-3"...
  local seen=" " cfgs base n
  cfgs="$(for f in $(kc_get "/$KC_REALM/authentication/flows/$top/executions" | jq -r '.[] | .authenticationConfig // empty'); do
      kc_get "/$KC_REALM/authentication/config/$f" | jq -c '{id, alias}'
    done | jq -sc --arg h "$sfx" '[.[] | select(.alias | test("\\." + $h + "\\.[0-9]+$"))
      | . + (.alias | capture("^(?<base>.*)\\.[^.]+\\.(?<seq>[0-9]+)$") | {base, seq: (.seq | tonumber)})] | sort_by(.seq)[]')"
  while read -r f; do
    [ -n "$f" ] || continue
    base="$(jq -r .base <<<"$f")"
    n="$(printf '%s' "$seen" | tr ' ' '\n' | grep -cxF "$base" || true)"
    seen="$seen$base "
    [ "$n" = 0 ] && n="" || n="-$((n + 1))"
    code="$(kc_get "/$KC_REALM/authentication/config/$(jq -r .id <<<"$f")" | jq -c --arg a "$base$n" '.alias = $a' \
      | kc_send PUT "/$KC_REALM/authentication/config/$(jq -r .id <<<"$f")")"
    [ "$code" = 204 ] || warn "    rename config $base$n: HTTP $code"
  done <<<"$cfgs"
  echo "    $top: rebuilt from realm-export.json"
}

# Not in realm-export.json: Keycloak validates the http token / JWKS URLs
# against sslRequired=external by RESOLVING the host (SslRequired.isLocal:
# loopback / site-local only), and at the first start's --import-realm
# enroll may not run yet → "The url [token_url] requires secure
# connections" aborts the import. keycloak/invite-idp.json is created here.
# _kc_invite_idp — the `portcullis-invite` identity provider (enroll's
# one-time invite login, enroll/invite.go): created from realm-export.json
# if missing, URLs (domain) and the client secret
# (secrets/enroll/invite-client-secret) pushed every run.
_kc_invite_idp() {
  info "Ensuring the invite identity provider (one-time setup links)..."
  local domain="${PORTCULLIS_DOMAIN:-portcullis.local}" secret_file="$PORTCULLIS_ROOT/secrets/enroll/invite-client-secret" rep code
  [ -r "$secret_file" ] || { warn "    $secret_file missing (./portcullis up creates it) — invite login not configured"; return 0; }
  rep="$(kc_get "/$KC_REALM/identity-provider/instances/portcullis-invite")"
  if ! printf '%s' "$rep" | jq -e '.alias' >/dev/null 2>&1; then
    rep="$(jq -c . "$PORTCULLIS_ROOT/keycloak/invite-idp.json")"
    code="$(printf '%s' "$rep" | kc_send POST "/$KC_REALM/identity-provider/instances")"
    _kc_report "invite identity provider" "$code" 201 || {
      warn "    Keycloak accepts the http back-channel (http://enroll:8445) only while the name enroll resolves to"
      warn "    a private address (sslRequired=external): start enroll, then re-run ./portcullis keycloak configure"
      return 0; }
    rep="$(kc_get "/$KC_REALM/identity-provider/instances/portcullis-invite")"
  fi
  code="$(printf '%s' "$rep" | jq -c --arg d "$domain" --rawfile secret "$secret_file" \
      --argjson want "$(jq -c . "$PORTCULLIS_ROOT/keycloak/invite-idp.json")" '
      . + ($want | {enabled, hideOnLogin, trustEmail, storeToken, linkOnly, firstBrokerLoginFlowAlias, postBrokerLoginFlowAlias})
      | .config = ((.config // {}) + $want.config + {
          clientSecret: ($secret | rtrimstr("\n")),
          authorizationUrl: ("https://enroll." + $d + "/invite/authorize"),
          issuer: ("https://enroll." + $d + "/invite")})' \
    | kc_send PUT "/$KC_REALM/identity-provider/instances/portcullis-invite")"
  _kc_report "invite identity provider (URLs, client secret)" "$code" 204 || true
}

# _kc_enroll_client — confidential client portcullis-enroll (service
# account only, secret = secrets/enroll/keycloak-client-secret) with
# realm-management view-users + manage-users: enroll adds the passkey
# registration required action to a user redeeming an invite.
_kc_enroll_client() {
  local f="$PORTCULLIS_ROOT/secrets/enroll/keycloak-client-secret" uuid code sa rm roles
  [ -r "$f" ] || { warn "    $f missing (./portcullis up creates it)"; return 0; }
  code="$(jq -nc --rawfile s "$f" '{clientId: "portcullis-enroll", name: "Portcullis enroll (invites)",
      enabled: true, protocol: "openid-connect", publicClient: false, secret: ($s | rtrimstr("\n")),
      serviceAccountsEnabled: true, standardFlowEnabled: false, implicitFlowEnabled: false,
      directAccessGrantsEnabled: false, frontchannelLogout: false}' | kc_send POST "/$KC_REALM/clients")"
  case "$code" in 201|409) ;; *) warn "    client portcullis-enroll: HTTP $code"; return 0 ;; esac
  uuid="$(kc_get "/$KC_REALM/clients?clientId=portcullis-enroll" | jq -r '.[0].id // empty')"
  [ -n "$uuid" ] || { warn "    client portcullis-enroll not found"; return 0; }
  code="$(kc_get "/$KC_REALM/clients/$uuid" | jq -c --rawfile s "$f" '.secret = ($s | rtrimstr("\n")) | .serviceAccountsEnabled = true
      | .standardFlowEnabled = false | .directAccessGrantsEnabled = false | .publicClient = false' \
    | kc_send PUT "/$KC_REALM/clients/$uuid")"
  _kc_report "client portcullis-enroll (service account, secret)" "$code" 204 || return 0
  sa="$(kc_get "/$KC_REALM/clients/$uuid/service-account-user" | jq -r '.id // empty')"
  rm="$(kc_get "/$KC_REALM/clients?clientId=realm-management" | jq -r '.[0].id // empty')"
  [ -n "$sa" ] && [ -n "$rm" ] || { warn "    portcullis-enroll: service account or realm-management missing"; return 0; }
  roles="$(kc_get "/$KC_REALM/clients/$rm/roles" | jq -c '[.[] | select(.name == "view-users" or .name == "manage-users")]')"
  code="$(printf '%s' "$roles" | kc_send POST "/$KC_REALM/users/$sa/role-mappings/clients/$rm")"
  _kc_report "portcullis-enroll: view-users, manage-users" "$code" 204 || true
}

# _kc_admin_roles — members of the LLDAP group lldap_admin administer the
# portcullis realm (realm-management realm-admin) with their normal
# passkey session at https://auth.<domain>/admin/portcullis/console/. The
# group appears in Keycloak through the LDAP group mapper; sync it first.
_kc_admin_roles() {
  local comp mapper gid client role code
  comp="$(kc_get "/$KC_REALM/components?type=org.keycloak.storage.UserStorageProvider" | jq -r '[.[]? | select(.providerId == "ldap")][0].id // empty')"
  mapper="$(kc_get "/$KC_REALM/components?parent=$comp" | jq -r '[.[]? | select(.providerId == "group-ldap-mapper")][0].id // empty')"
  if [ -n "$comp" ] && [ -n "$mapper" ]; then
    code="$(kc_send POST "/$KC_REALM/user-storage/$comp/mappers/$mapper/sync?direction=fedToKeycloak" < /dev/null)"
    _kc_report "sync LLDAP groups" "$code" 200 204 || true
  fi
  gid="$(kc_get "/$KC_REALM/groups?search=lldap_admin&exact=true" | jq -r '[.[]? | select(.name == "lldap_admin")][0].id // empty')"
  client="$(kc_get "/$KC_REALM/clients?clientId=realm-management" | jq -r '.[0].id // empty')"
  [ -n "$gid" ] && [ -n "$client" ] || { warn "    group lldap_admin or client realm-management not found — realm console access not granted"; return 0; }
  if kc_get "/$KC_REALM/groups/$gid/role-mappings/clients/$client" | jq -e 'any(.[]?; .name == "realm-admin")' >/dev/null; then
    echo "    lldap_admin: realm-admin"
    return 0
  fi
  role="$(kc_get "/$KC_REALM/clients/$client/roles/realm-admin")"
  code="$(printf '[%s]' "$role" | kc_send POST "/$KC_REALM/groups/$gid/role-mappings/clients/$client")"
  _kc_report "lldap_admin: realm-admin of $KC_REALM" "$code" 204 || true
}

# _oidc_client <client-id> <secret-var> <redirect-uri> <name> — create the
# client if missing, then push the secret from .env (the realm export,
# auto-imported at Keycloak's first start, carries a placeholder secret).
_oidc_client() {
  local id="$1" var="$2" redirect="$3" name="$4" code uuid
  code="$(SECRET="${!var}" jq -n --arg id "$id" --arg r "$redirect" --arg n "$name" '{
      clientId: $id, name: $n, enabled: true, protocol: "openid-connect", publicClient: false,
      secret: env.SECRET, redirectUris: [$r], standardFlowEnabled: true,
      directAccessGrantsEnabled: false, attributes: {"post.logout.redirect.uris": $r}}' \
    | kc_send POST "/$KC_REALM/clients")"
  case "$code" in
    201) printf '  %sCreated%s %s\n' "$C_GREEN" "$C_NC" "$id" ;;
    409) printf '  %sExists%s  %s\n' "$C_YELLOW" "$C_NC" "$id" ;;
    *)   printf '  %sFailed%s  %s (HTTP %s)\n' "$C_RED" "$C_NC" "$id" "$code"; return 1 ;;
  esac
  uuid="$(kc_get "/$KC_REALM/clients?clientId=$id" | jq -r '.[0].id // empty')"
  [ -n "$uuid" ] || { printf '  %sFailed%s  %s: client not found after create\n' "$C_RED" "$C_NC" "$id"; return 1; }
  code="$(kc_get "/$KC_REALM/clients/$uuid" | SECRET="${!var}" jq '.secret = env.SECRET' \
    | kc_send PUT "/$KC_REALM/clients/$uuid")"
  if [ "$code" = 204 ]; then
    printf '  %sSynced%s  %s secret from %s\n' "$C_GREEN" "$C_NC" "$id" "$var"
  else
    printf '  %sFailed%s  %s secret sync (HTTP %s)\n' "$C_RED" "$C_NC" "$id" "$code"
    return 1
  fi
}

oidc_register() {
  local domain="${PORTCULLIS_DOMAIN:-portcullis.local}" failed=0
  require_cmd curl jq
  env_require FORWARD_AUTH_CLIENT_SECRET
  kc_login
  info "Registering OIDC clients..."
  _oidc_client portcullis-forward-auth FORWARD_AUTH_CLIENT_SECRET \
    "https://auth.$domain/oauth2/callback" "Portcullis Forward Auth" || failed=1
  # Optional VPN clients — only when their secret is set in .env.
  if [ -n "${HEADSCALE_OIDC_CLIENT_SECRET:-}" ]; then
    _oidc_client headscale HEADSCALE_OIDC_CLIENT_SECRET "https://vpn.$domain/oidc/callback" "Headscale VPN" || failed=1
  fi
  if [ -n "${HEADPLANE_OIDC_CLIENT_SECRET:-}" ]; then
    _oidc_client headplane HEADPLANE_OIDC_CLIENT_SECRET "https://vpn-admin.$domain/*" "Headplane Admin UI" || failed=1
  fi
  if [ -n "${NETBIRD_OIDC_CLIENT_SECRET:-}" ]; then
    _oidc_client netbird-dashboard NETBIRD_OIDC_CLIENT_SECRET "https://netbird.$domain/*" "NetBird Dashboard" || failed=1
  fi
  [ "$failed" = 0 ] || fail "some OIDC clients could not be registered (see above)"
  ok "OIDC clients registered."
}

help_keycloak() {
  cat <<'EOF'
Usage: portcullis keycloak configure [--wipe-realm]

  configure   Import/patch the portcullis realm (LDAP, LoA, scopes, branding)
EOF
}

help_keycloak_configure() {
  cat <<'EOF'
Usage: portcullis keycloak configure [--wipe-realm]

Idempotent post-start configuration of the portcullis realm via the admin
API on 127.0.0.1:8080 (override with KEYCLOAK_URL):
  - imports keycloak/realm-export.json if the realm does not exist
  - points the LDAP federation at LLDAP (LLDAP_BASE_DN, LLDAP_ADMIN_PASSWORD)
  - sets the ACR→LoA map, sslRequired=external and browserFlow=portcullis-universal
  - rebuilds every top-level flow of the file whose tree changed (passkey-only
    browser flow, the invite identity provider's first-login / post-login flows)
  - the invite identity provider portcullis-invite (enroll; URLs + client
    secret from secrets/enroll/invite-client-secret) and the service-account
    client portcullis-enroll (view-users, manage-users)
  - lldap_admin = realm-admin of the portcullis realm (realm console)
  - pushes the X.509 authenticator settings from the file (CRL check against
    Vault's pki_int CRL, trust re-validation, clientAuth EKU) to the realm
  - checks AMR reference values, ensures the amr mapper and groups scope
  - ensures the email-unverified scope (email claim, no email_verified) that
    Hub templates opt into with keycloak_clients[].email_verified_claim: false
  - sets acr/groups scopes and the redirect URI on portcullis-forward-auth
  - creates a credential-less `testuser`, applies PORTAL_DISPLAY_NAME branding

Options:
  --wipe-realm   delete the realm first and re-import it from the file
                 (users' passkeys are lost; clients must then be
                 re-registered with `portcullis oidc register`)
EOF
}

help_oidc() {
  cat <<'EOF'
Usage: portcullis oidc register

  register    Create the core OIDC clients and push their secrets from .env
EOF
}

help_oidc_register() {
  cat <<'EOF'
Usage: portcullis oidc register

Create the portcullis-forward-auth client (and headscale / headplane /
netbird-dashboard when their *_OIDC_CLIENT_SECRET is set in .env) and set
each client's secret in Keycloak to the value in .env, so oauth2-proxy and
Keycloak always agree. Idempotent. After changing FORWARD_AUTH_CLIENT_SECRET
run this, then `portcullis up`.
EOF
}

cmd_keycloak() {
  local sub="${1:-}" wipe=false
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_keycloak; [ -n "$sub" ] || exit 2; return 0 ;;
    configure) ;;
    *) usage_error keycloak "unknown subcommand: $sub" ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --wipe-realm) wipe=true ;;
      -h|--help) help_keycloak_configure; return 0 ;;
      *) usage_error "keycloak configure" "unknown argument: $1" ;;
    esac
    shift
  done
  need_env
  keycloak_configure "$wipe"
}

cmd_oidc() {
  local sub="${1:-}"
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_oidc; [ -n "$sub" ] || exit 2; return 0 ;;
    register) ;;
    *) usage_error oidc "unknown subcommand: $sub" ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) help_oidc_register; return 0 ;;
      *) usage_error "oidc register" "unknown argument: $1" ;;
    esac
  done
  need_env
  oidc_register
}
