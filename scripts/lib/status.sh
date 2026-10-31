# shellcheck shell=bash
#
# `portcullis status [--json]` — health overview. Exit status 1 if any
# core service is not running/healthy or Vault is not active.

_st_line() {  # _st_line ok|warn|fail <text>
  case "$1" in
    ok)   printf '  %s✓%s %s\n' "$C_GREEN" "$C_NC" "$2" ;;
    warn) printf '  %s!%s %s\n' "$C_YELLOW" "$C_NC" "$2" ;;
    *)    printf '  %s✗%s %s\n' "$C_RED" "$C_NC" "$2" ;;
  esac
}

status_run() {
  local json="$1" problems=0 out
  local services="[]" svc_raw vault_code vault_json='{}' kc='{}' lldap='{}' traefik
  require_cmd docker jq curl
  export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"

  # ── services ──
  svc_raw="$(dc ps -a --format json 2>/dev/null || true)"
  # compose prints one object per line (or one array on older versions).
  services="$(printf '%s\n' "$svc_raw" | jq -cs '
      (if length == 1 and (.[0] | type) == "array" then .[0] else . end)
      | map({name: .Service, state: .State, health: (if (.Health // "") == "" then "n/a" else .Health end), status: .Status})' 2>/dev/null || echo '[]')"
  if [ "$(printf '%s' "$services" | jq '[.[] | select(.state != "running" or (.health != "healthy" and .health != "n/a"))] | length')" != 0 ] \
     || [ "$(printf '%s' "$services" | jq 'length')" = 0 ]; then
    problems=1
  fi

  # ── vault ──
  vault_code="$(vault_health_code)"
  vault_json="$(jq -n --arg c "$vault_code" '{http_status: $c,
      initialized: ($c != "501" and $c != "000"), sealed: ($c == "503"), active: ($c == "200")}')"
  [ "$vault_code" = 200 ] || problems=1
  local root_exp="" int_exp="" certs_issued=null expiring="[]"
  if [ "$vault_code" = 200 ] && vault_admin_env 2>/dev/null && vault_use_container_cli 2>/dev/null; then
    root_exp="$(vault read -field=certificate pki/cert/ca 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
    int_exp="$(vault read -field=certificate pki_int/cert/ca 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
    local serials s info cn end revoked now epoch
    if serials="$(vault list -format=json pki_int/certs 2>/dev/null)"; then
      certs_issued="$(printf '%s' "$serials" | jq 'length')"
      now="$(date +%s)"
      for s in $(printf '%s' "$serials" | jq -r '.[]'); do
        info="$(_cert_info "$s")" || continue
        IFS='|' read -r cn end revoked <<< "$info"
        [ "$revoked" = false ] || continue
        epoch="$(to_epoch "$end")"
        # valid but expiring within 6h (client certs live 24h)
        if [ "$epoch" -ge "$now" ] && [ $((epoch - now)) -lt 21600 ]; then
          expiring="$(printf '%s' "$expiring" | jq -c --arg cn "$cn" --arg e "$end" '. + [{cn: $cn, expires: $e}]')"
        fi
      done
    fi
    vault_json="$(printf '%s' "$vault_json" | jq --arg r "$root_exp" --arg i "$int_exp" --argjson n "$certs_issued" --argjson x "$expiring" \
      '. + {root_ca_expires: $r, intermediate_ca_expires: $i, certs_issued: $n, certs_expiring: $x}')"
  fi

  # ── keycloak (health on the unpublished management port → docker health) ──
  local kc_health users=null realm=false fwd=false
  kc_health="$(container_health keycloak)"
  [ "$kc_health" = healthy ] || problems=1
  if [ "$kc_health" = healthy ] && [ -n "${KEYCLOAK_ADMIN_PASSWORD:-}" ] && (kc_login >/dev/null 2>&1); then
    kc_login >/dev/null 2>&1
    [ "$(kc_get "/$KC_REALM" | jq -r '.realm // empty' 2>/dev/null)" = "$KC_REALM" ] && realm=true
    users="$(kc_get "/$KC_REALM/users/count" 2>/dev/null)"
    [[ "$users" =~ ^[0-9]+$ ]] || users=null
    [ -n "$(kc_get "/$KC_REALM/clients?clientId=portcullis-forward-auth" | jq -r '.[0].id // empty' 2>/dev/null)" ] && fwd=true
  fi
  kc="$(jq -n --arg h "$kc_health" --argjson r "$realm" --argjson u "$users" --argjson f "$fwd" \
    '{health: $h, realm: $r, users: $u, forward_auth_client: $f}')"

  # ── lldap / traefik ──
  lldap="$(jq -n --arg h "$(container_health lldap)" '{health: $h}')"
  traefik="$(container_health traefik)"
  case "$traefik" in healthy|running) ;; *) problems=1 ;; esac

  if [ "$json" = true ]; then
    jq -n --arg d "${PORTCULLIS_DOMAIN:-}" --argjson s "$services" --argjson v "$vault_json" \
      --argjson k "$kc" --argjson l "$lldap" --arg t "$traefik" --argjson p "$problems" \
      '{domain: $d, ok: ($p == 0), services: $s, vault: $v, keycloak: $k, lldap: $l, traefik: {state: $t}}'
    return "$problems"
  fi

  printf '\n%sServices%s\n' "$C_CYAN" "$C_NC"
  if [ "$(printf '%s' "$services" | jq 'length')" = 0 ]; then
    _st_line fail "no containers (start with: ./portcullis up)"
  fi
  while IFS=$'\t' read -r n st h stat; do
    if [ "$st" = running ] && { [ "$h" = healthy ] || [ "$h" = n/a ]; }; then
      _st_line ok "$n ${C_DIM}($stat)${C_NC}"
    elif [ "$st" = running ]; then
      _st_line warn "$n ${C_DIM}($stat)${C_NC}"
    else
      _st_line fail "$n ${C_DIM}($stat)${C_NC}"
    fi
  done < <(printf '%s' "$services" | jq -r '.[] | [.name, .state, .health, .status] | @tsv')

  printf '\n%sVault%s\n' "$C_CYAN" "$C_NC"
  case "$vault_code" in
    200) _st_line ok "active, unsealed" ;;
    503) _st_line fail "SEALED (auto-unseal failed?) — ./portcullis vault unseal; docker compose logs vault" ;;
    501) _st_line fail "NOT INITIALISED — ./portcullis vault init" ;;
    000) _st_line fail "not reachable at $VAULT_ADDR" ;;
    *)   _st_line warn "health status $vault_code (429 = standby)" ;;
  esac
  if [ "$vault_code" = 200 ]; then
    if [ -z "${VAULT_TOKEN:-}" ]; then
      _st_line warn "no admin token (secrets/vault-init.json unreadable, VAULT_TOKEN unset) — PKI details unavailable"
    else
      [ -n "$root_exp" ] && _st_line ok "root CA expires $root_exp" || _st_line warn "root CA not found (./portcullis pki setup)"
      [ -n "$int_exp" ] && _st_line ok "intermediate CA expires $int_exp" || _st_line warn "intermediate CA not found"
      [ "$certs_issued" = null ] || _st_line ok "issued certificates: $certs_issued"
      while IFS=$'\t' read -r cn end; do
        [ -n "$cn" ] && _st_line warn "  $cn expires $end"
      done < <(printf '%s' "$expiring" | jq -r '.[] | [.cn, .expires] | @tsv')
    fi
  fi

  printf '\n%sKeycloak%s\n' "$C_CYAN" "$C_NC"
  if [ "$kc_health" = healthy ]; then
    _st_line ok "healthy"
    if [ "$users" = null ] && [ "$realm" = false ]; then
      _st_line warn "admin login failed — realm details unavailable"
    else
      [ "$realm" = true ] && _st_line ok "realm $KC_REALM exists, $users user(s)" || _st_line fail "realm $KC_REALM missing (./portcullis keycloak configure)"
      [ "$fwd" = true ] && _st_line ok "OIDC client portcullis-forward-auth" || _st_line fail "OIDC client portcullis-forward-auth missing (./portcullis oidc register)"
    fi
  else
    _st_line fail "$kc_health"
  fi

  printf '\n%sLLDAP / Traefik%s\n' "$C_CYAN" "$C_NC"
  out="$(printf '%s' "$lldap" | jq -r .health)"
  [ "$out" = healthy ] && _st_line ok "lldap healthy" || _st_line fail "lldap $out"
  case "$traefik" in healthy|running) _st_line ok "traefik $traefik" ;; *) _st_line fail "traefik $traefik" ;; esac

  printf '\n%sDomain: %s — run with --json for machine-readable output%s\n\n' "$C_DIM" "${PORTCULLIS_DOMAIN:-?}" "$C_NC"
  return "$problems"
}

help_status() {
  cat <<'EOF'
Usage: portcullis status [--json]

Health overview: compose services, Vault (sealed/active, CA expiry, issued
and soon-expiring certs), Keycloak (realm, users, forward-auth client),
LLDAP and Traefik. Exits 1 if a core service is down/unhealthy or Vault is
not active, 0 otherwise.

Options:
  --json   machine-readable output (same exit status)
EOF
}

cmd_status() {
  local json=false
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json=true ;;
      -h|--help) help_status; return 0 ;;
      *) usage_error status "unknown argument: $1" ;;
    esac
    shift
  done
  need_env
  status_run "$json"
}
