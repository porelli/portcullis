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
  local root_exp="" int_exp="" certs_issued=null expiring="[]" newest="[]"
  if [ "$vault_code" = 200 ] && vault_admin_env 2>/dev/null && vault_use_container_cli 2>/dev/null; then
    root_exp="$(vault read -field=certificate pki/cert/ca 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
    int_exp="$(vault read -field=certificate pki_int/cert/ca 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
    local serials s info cn end revoked now epoch warn_s valid="" server_cn="*.${PORTCULLIS_DOMAIN:-}"
    warn_s="$(cert_warn_seconds)"
    if serials="$(vault list -format=json pki_int/certs 2>/dev/null)"; then
      certs_issued="$(printf '%s' "$serials" | jq 'length')"
      now="$(date +%s)"
      for s in $(printf '%s' "$serials" | jq -r '.[]'); do
        info="$(_cert_info "$s")" || continue
        IFS='|' read -r cn end revoked <<< "$info"
        [ "$revoked" = false ] && [ -n "$cn" ] && [ "$cn" != "$server_cn" ] || continue
        epoch="$(to_epoch "$end")"
        [ "$epoch" -ge "$now" ] || continue
        valid+="$(jq -cn --arg cn "$cn" --arg e "$end" --arg s "$s" --argjson t "$epoch" \
          '{cn: $cn, serial: $s, expires: $e, epoch: $t}')"$'\n'
      done
      # Per user, only the cert that lasts longest counts: once renewed, the
      # old (still valid) cert is no reason to warn.
      newest="$(printf '%s' "$valid" | jq -cs 'group_by(.cn) | map(max_by(.epoch)) | map({cn, serial, expires, epoch})')"
      expiring="$(printf '%s' "$newest" | jq -c --argjson now "$now" --argjson w "$warn_s" '
          map(select(.epoch - $now < $w))
          | map({cn, serial, expires, days_left: ((.epoch - $now) / 86400 | floor)})')"
    fi
    local root_epoch=0 int_epoch=0
    [ -z "$root_exp" ] || root_epoch="$(to_epoch "$root_exp")"
    [ -z "$int_exp" ] || int_epoch="$(to_epoch "$int_exp")"
    vault_json="$(printf '%s' "$vault_json" | jq --arg r "$root_exp" --arg i "$int_exp" --argjson n "$certs_issued" --argjson x "$expiring" \
      --argjson c "$newest" --argjson re "$root_epoch" --argjson ie "$int_epoch" \
      '. + {root_ca_expires: $r, intermediate_ca_expires: $i, root_ca_expires_epoch: $re,
            intermediate_ca_expires_epoch: $ie, certs_issued: $n, certs_expiring: $x, client_certs: $c}')"
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
      if [ "$(printf '%s' "$expiring" | jq length)" != 0 ]; then
        _st_line warn "client certificates expiring within ${CERT_EXPIRY_WARN_DAYS:-7} days (renew at https://enroll.${PORTCULLIS_DOMAIN:-<domain>}/self):"
      fi
      while IFS=$'\t' read -r cn end days; do
        [ -n "$cn" ] && _st_line warn "  $cn expires $end ($days day(s) left)"
      done < <(printf '%s' "$expiring" | jq -r '.[] | [.cn, .expires, .days_left] | @tsv')
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

# status_textfile — status as Prometheus textfile metrics
# (monitoring/textfile/status.prom; monitoring profile). Same exit status.
status_textfile() {
  local out rc=0
  out="$(status_run true)" || rc=$?
  printf '%s' "$out" | jq -r --argjson now "$(date +%s)" '
    def esc: tostring | gsub("\\\\"; "\\\\") | gsub("\""; "\\\"") | gsub("\n"; " ");
    def up: if .state == "running" and (.health == "healthy" or .health == "n/a") then 1 else 0 end;
    def g(n; h): "# HELP \(n) \(h)", "# TYPE \(n) gauge";
    g("portcullis_status_last_run_timestamp_seconds"; "Unix time of the last portcullis status --textfile."),
    "portcullis_status_last_run_timestamp_seconds \($now)",
    g("portcullis_status_ok"; "1 if portcullis status found no problem."),
    "portcullis_status_ok \(if .ok then 1 else 0 end)",
    g("portcullis_service_up"; "1 if the compose service is running and healthy (or has no healthcheck)."),
    (.services[] | "portcullis_service_up{service=\"\(.name | esc)\"} \(up)"),
    g("portcullis_vault_active"; "1 if Vault is initialised, unsealed and active."),
    "portcullis_vault_active \(if .vault.active then 1 else 0 end)",
    g("portcullis_ca_expiry_timestamp_seconds"; "Expiry of the client-certificate CAs in Vault."),
    (if (.vault.root_ca_expires_epoch // 0) > 0 then "portcullis_ca_expiry_timestamp_seconds{ca=\"root\"} \(.vault.root_ca_expires_epoch)" else empty end),
    (if (.vault.intermediate_ca_expires_epoch // 0) > 0 then "portcullis_ca_expiry_timestamp_seconds{ca=\"intermediate\"} \(.vault.intermediate_ca_expires_epoch)" else empty end),
    g("portcullis_client_cert_expiry_timestamp_seconds"; "Expiry of the newest valid, unrevoked client certificate of each user."),
    ((.vault.client_certs // [])[] | "portcullis_client_cert_expiry_timestamp_seconds{cn=\"\(.cn | esc)\"} \(.epoch)")
  ' | metrics_textfile_write status
  return "$rc"
}

# portcullis_version — core version: VERSION (release tarballs), else
# `git describe` of the checkout, else "unknown".
portcullis_version() {
  if [ -s "$PORTCULLIS_HOME/VERSION" ]; then
    tr -d '[:space:]' < "$PORTCULLIS_HOME/VERSION"
  elif git -C "$PORTCULLIS_HOME" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "$PORTCULLIS_HOME" describe --tags --always --dirty 2>/dev/null || echo unknown
  else
    echo unknown
  fi
}

# hub_image_default — the HUB_IMAGE default in docker-compose.yml.
hub_image_default() {
  sed -n 's/.*\${HUB_IMAGE:-\([^}]*\)}.*/\1/p' "$PORTCULLIS_HOME/docker-compose.yml" | head -n1
}

version_run() {
  local json="$1" ver hub src running="" cid=""
  ver="$(portcullis_version)"
  [ ! -f "$(env_file)" ] || env_load
  if [ -n "${HUB_IMAGE:-}" ]; then hub="$HUB_IMAGE" src="HUB_IMAGE"; else hub="$(hub_image_default)" src="default"; fi
  # The running Hub, if this is an installation and Docker answers.
  if [ -f "$(env_file)" ] && command -v docker >/dev/null 2>&1; then
    cid="$(dc ps -q hub 2>/dev/null | head -n1 || true)"
    [ -z "$cid" ] || running="$(docker inspect --format '{{.Config.Image}} ({{.Image}})' "$cid" 2>/dev/null || true)"
  fi
  if [ "$json" = true ]; then
    jq -n --arg v "$ver" --arg h "$hub" --arg s "$src" --arg r "$running" \
      '{version: $v, hub_image: $h, hub_image_source: $s, hub_running: (if $r == "" then null else $r end)}'
    return 0
  fi
  printf 'portcullis  %s\n' "$ver"
  printf 'hub image   %s (%s)\n' "$hub" "$src"
  [ -z "$running" ] || printf 'hub running %s\n' "$running"
}

help_version() {
  cat <<'EOF'
Usage: portcullis version [--json]

Print the core version (VERSION in a release tarball, else `git describe`
of the checkout) and the Hub image in use: HUB_IMAGE from .env or the
environment, else the default pinned in docker-compose.yml, plus the image
of the running Hub container if there is one.

Options:
  --json   machine-readable output
EOF
}

cmd_version() {
  local json=false
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json=true ;;
      -h|--help) help_version; return 0 ;;
      *) usage_error version "unknown argument: $1" ;;
    esac
    shift
  done
  version_run "$json"
}

help_status() {
  cat <<'EOF'
Usage: portcullis status [--json | --textfile]

Health overview: compose services, Vault (sealed/active, CA expiry, issued
certs, client certs expiring within CERT_EXPIRY_WARN_DAYS = 7 days),
Keycloak (realm, users, forward-auth client),
LLDAP and Traefik. Exits 1 if a core service is down/unhealthy or Vault is
not active, 0 otherwise.

Options:
  --json       machine-readable output (same exit status)
  --textfile   write the same as Prometheus metrics to
               monitoring/textfile/status.prom for the monitoring profile
               (service health, Vault active, CA and per-user client-cert
               expiry); run after every scheduled backup
EOF
}

cmd_status() {
  local json=false textfile=false
  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json=true ;;
      --textfile) textfile=true ;;
      -h|--help) help_status; return 0 ;;
      *) usage_error status "unknown argument: $1" ;;
    esac
    shift
  done
  need_env
  if [ "$textfile" = true ]; then status_textfile; return; fi
  status_run "$json"
}
