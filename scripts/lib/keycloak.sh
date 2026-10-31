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
}

# kc_get <path> — GET JSON from the admin API (path relative to /admin/realms).
kc_get() {
  curl -sk --max-time 20 -H @<(printf 'Authorization: Bearer %s\n' "$KC_TOKEN") \
    "$(kc_url)/admin/realms$1"
}

# kc_send <METHOD> <path> — body on stdin (empty for none); prints HTTP code.
kc_send() {
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

keycloak_configure() {
  local wipe="$1" realm code comp ldap_id mapper fwd_uuid scope_id execs flow
  require_cmd curl jq
  kc_login
  local base_dn="${LLDAP_BASE_DN:-dc=portcullis,dc=local}" domain="${PORTCULLIS_DOMAIN:-portcullis.local}"

  # Delete-then-import is the only reliable way to apply nested auth-flow
  # changes on an existing realm. Users and their WebAuthn keys live in
  # LLDAP, and clients are re-registered by `portcullis oidc register`.
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
  # included; patch DN + bind credential onto the component. trustEmail
  # stays off: LLDAP lets users edit their own mail, so it is never
  # asserted as verified (identity is the username, see oauth2-proxy/alpha.yaml).
  comp="$(kc_get "/$KC_REALM/components" | jq '[.[] | select(.providerId == "ldap")][0] // empty')"
  if [ -n "$comp" ]; then
    ldap_id="$(printf '%s' "$comp" | jq -r .id)"
    code="$(printf '%s' "$comp" | LLDAP_PASS="${LLDAP_ADMIN_PASSWORD:-}" jq --arg b "$base_dn" '
        .config.usersDn = ["ou=people," + $b] |
        .config.bindDn = ["uid=admin,ou=people," + $b] |
        .config.bindCredential = [env.LLDAP_PASS] |
        .config.trustEmail = ["false"]' | kc_send PUT "/$KC_REALM/components/$ldap_id")"
    _kc_report "LDAP base DN + bind credential" "$code" 204 || true
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
  code="$(kc_get "/$KC_REALM" | jq '
      {attributes: {"acr.loa.map": "{\"public\":\"0\",\"pwd\":\"1\",\"hwk\":\"2\",\"mtls\":\"3\"}"}} +
      (if ((.browserFlow // "") == "" or .browserFlow == "portcullis-browser-flow")
       then {browserFlow: "portcullis-universal"} else {} end)' | kc_send PUT "/$KC_REALM")"
  _kc_report "realm attributes" "$code" 204 || true

  info "Checking factor executors carry AMR reference values..."
  # Each authenticator in portcullis-loa-*-factors / portcullis-loa-3 needs
  # an authenticatorConfig with default.reference.value, or the amr claim is
  # empty and AND-mode policies cannot tell factors apart.
  for flow in portcullis-loa-1-factors portcullis-loa-2-factors portcullis-loa-3; do
    execs="$(kc_get "/$KC_REALM/authentication/flows/$flow/executions")"
    printf '%s' "$execs" | jq -e 'type == "array"' >/dev/null 2>&1 || continue
    while read -r provider cfg; do
      if [ "$cfg" = none ]; then
        warn "    $flow/$provider has no authenticator config → empty amr for this factor"
      elif [ -z "$(kc_get "/$KC_REALM/authentication/config/$cfg" | jq -r '.config["default.reference.value"] // empty')" ]; then
        warn "    $flow/$provider config has no default.reference.value → empty amr for this factor"
      fi
    done < <(printf '%s' "$execs" | jq -r '.[] | select(.providerId and .providerId != "conditional-level-of-authentication") | .providerId + " " + (.authenticationConfig // "none")')
  done

  info "Applying the X.509 authenticator config (CRL check, trust re-validation)..."
  # realm-export.json is only imported into a NEW realm; push the x509-config
  # authenticator settings onto every existing x509 execution's config.
  local x509_cfg cfg_ids cid
  x509_cfg="$(jq -c '.authenticatorConfig[] | select(.alias == "x509-config") | .config' "$PORTCULLIS_ROOT/keycloak/realm-export.json")"
  cfg_ids="$(for flow in portcullis-loa-1-factors portcullis-loa-2-factors portcullis-loa-3; do
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
  - sets the ACR→LoA map and browserFlow=portcullis-universal
  - pushes the X.509 authenticator settings from the file (CRL check against
    Vault's pki_int CRL, trust re-validation, clientAuth EKU) to the realm
  - checks AMR reference values, ensures the amr mapper and groups scope
  - sets acr/groups scopes and the redirect URI on portcullis-forward-auth
  - creates a credential-less `testuser`, applies PORTAL_DISPLAY_NAME branding

Options:
  --wipe-realm   delete the realm first and re-import it from the file
                 (needed to apply auth-flow changes; clients must then be
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
