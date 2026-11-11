# shellcheck shell=bash
#
# `portcullis status [--json]` — health overview. Exit status 1 if any
# core service is not running/healthy or Vault is not active.

# _st_mcp_refusing — the reason mcp-gate refuses every AI request (503),
# from the last line of its Docker health log (mcp-gate healthcheck prints
# /healthz's "refusing every AI request (503): …" line: the Hub's files
# were refused, e.g. credentials not encrypted to secrets/mcp-gate/age.key);
# nothing when it serves, is off, or isn't running.
_st_mcp_refusing() {
  local cid
  cid="$(dc ps -q mcp-gate 2>/dev/null | head -n1)"
  [ -n "$cid" ] || return 0
  docker inspect --format '{{json .State.Health}}' "$cid" 2>/dev/null \
    | jq -r '((.Log // []) | last | .Output // "") | split("\n")[] | select(startswith("refusing every AI request (503): "))' 2>/dev/null \
    | head -n1 || true
}

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
  local root_exp="" int_exp="" file_exp="" certs_issued=null expiring="[]" newest="[]"
  if [ "$vault_code" = 200 ] && vault_admin_env 2>/dev/null && vault_use_container_cli 2>/dev/null; then
    root_exp="$(vault read -field=certificate pki/cert/ca 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
    int_exp="$(vault read -field=certificate pki_int/cert/ca 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
    file_exp="$(vault read -field=certificate pki_file/cert/ca 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
    local serials s info cn end revoked now epoch warn_s valid="" server_cn="*.${PORTCULLIS_DOMAIN:-}" mount kind issued=0 listed=true
    warn_s="$(cert_warn_seconds)"
    now="$(date +%s)"
    # Both kinds (contract §8.1 "Internal certificate authority"): YubiKey
    # certificates (pki_int) and browser certificates (pki_file).
    for mount in $CERT_MOUNTS; do
      serials="$(vault list -format=json "$mount/certs" 2>/dev/null)" || { listed=false; continue; }
      issued=$((issued + $(printf '%s' "$serials" | jq 'length')))
      kind="$(cert_kind "$mount" | tr '[:upper:]' '[:lower:]')"
      for s in $(printf '%s' "$serials" | jq -r '.[]'); do
        info="$(_cert_info "$mount" "$s")" || continue
        IFS='|' read -r cn end revoked <<< "$info"
        [ "$revoked" = false ] && [ -n "$cn" ] && [ "$cn" != "$server_cn" ] || continue
        epoch="$(to_epoch "$end")"
        [ "$epoch" -ge "$now" ] || continue
        valid+="$(jq -cn --arg cn "$cn" --arg k "$kind" --arg e "$end" --arg s "$s" --argjson t "$epoch" \
          '{cn: $cn, kind: $k, serial: $s, expires: $e, epoch: $t}')"$'\n'
      done
    done
    [ "$listed" != true ] || certs_issued="$issued"
    # Per user and kind, only the certificate that lasts longest counts: once
    # renewed (or a new browser certificate made), the old one is no reason
    # to warn.
    newest="$(printf '%s' "$valid" | jq -cs 'group_by([.cn, .kind]) | map(max_by(.epoch)) | map({cn, kind, serial, expires, epoch})')"
    expiring="$(printf '%s' "$newest" | jq -c --argjson now "$now" --argjson w "$warn_s" '
        map(select(.epoch - $now < $w))
        | map({cn, kind, serial, expires, days_left: ((.epoch - $now) / 86400 | floor)})')"
    local root_epoch=0 int_epoch=0 file_epoch=0
    [ -z "$root_exp" ] || root_epoch="$(to_epoch "$root_exp")"
    [ -z "$int_exp" ] || int_epoch="$(to_epoch "$int_exp")"
    [ -z "$file_exp" ] || file_epoch="$(to_epoch "$file_exp")"
    vault_json="$(printf '%s' "$vault_json" | jq --arg r "$root_exp" --arg i "$int_exp" --arg f "$file_exp" --argjson n "$certs_issued" --argjson x "$expiring" \
      --argjson c "$newest" --argjson re "$root_epoch" --argjson ie "$int_epoch" --argjson fe "$file_epoch" \
      '. + {root_ca_expires: $r, intermediate_ca_expires: $i, browser_ca_expires: $f, root_ca_expires_epoch: $re,
            intermediate_ca_expires_epoch: $ie, browser_ca_expires_epoch: $fe, certs_issued: $n, certs_expiring: $x, client_certs: $c}')"
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
  # A non-core container answering to a core service name on portcullis-proxy
  # (network.sh proxy_dns_shadows; up / upgrade refuse to run while it lasts).
  local shadows
  # A docker error is a problem too (fail closed), shown as one line.
  shadows="$(proxy_dns_shadows)" || shadows="(docker) the containers on portcullis-proxy can't be inspected"
  [ -z "$shadows" ] || problems=1
  local mcp_refusing
  mcp_refusing="$(_st_mcp_refusing)"
  [ -z "$mcp_refusing" ] || problems=1

  if [ "$json" = true ]; then
    jq -n --arg d "${PORTCULLIS_DOMAIN:-}" --argjson s "$services" --argjson v "$vault_json" \
      --argjson k "$kc" --argjson l "$lldap" --arg t "$traefik" --argjson p "$problems" --arg sh "$shadows" --arg mr "$mcp_refusing" \
      '{domain: $d, ok: ($p == 0), services: $s, vault: $v, keycloak: $k, lldap: $l, traefik: {state: $t},
        dns_shadows: [$sh | split("\n")[] | select(. != "") | capture("^(?<container>[^ ]+) (?<name>.+)$")],
        mcp_gate: {refusing: (if $mr == "" then null else $mr end)}}'
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
      [ -n "$int_exp" ] && _st_line ok "YubiKey certificate CA expires $int_exp" || _st_line warn "YubiKey certificate CA (pki_int) not found"
      [ -n "$file_exp" ] && _st_line ok "browser certificate CA expires $file_exp" || _st_line warn "browser certificate CA (pki_file) not found (./portcullis pki setup)"
      [ "$certs_issued" = null ] || _st_line ok "issued certificates: $certs_issued"
      if [ "$(printf '%s' "$expiring" | jq length)" != 0 ]; then
        _st_line warn "certificates expiring within ${CERT_EXPIRY_WARN_DAYS:-7} days (renew a YubiKey certificate or make a new browser certificate on the Sign-in page, https://people.${PORTCULLIS_DOMAIN:-<domain>}/signin):"
      fi
      while IFS=$'\t' read -r cn kind end days; do
        [ -n "$cn" ] && _st_line warn "  $cn: $kind certificate expires $end ($days day(s) left)"
      done < <(printf '%s' "$expiring" | jq -r '.[] | [.cn, (if .kind == "browser" then "browser" else "YubiKey" end), .expires, .days_left] | @tsv')
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
  domains_status_lines
  local shadow
  while read -r shadow; do
    [ -n "$shadow" ] || continue
    case "$shadow" in
      "(docker) "*) _st_line fail "portcullis-proxy: ${shadow#(docker) } (core-name check failed closed)" ;;
      *" (AI companion name"*) _st_line fail "portcullis-proxy: container ${shadow%% *} answers to the AI companion name ${shadow#* }" ;;
      *) _st_line fail "portcullis-proxy: container ${shadow%% *} answers to the core name ${shadow#* }" ;;
    esac
  done <<< "$shadows"
  [ -z "$mcp_refusing" ] || _st_line fail "mcp-gate: $mcp_refusing"

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
    g("portcullis_ca_expiry_timestamp_seconds"; "Expiry of the CAs of the internal certificate authority (Vault)."),
    (if (.vault.root_ca_expires_epoch // 0) > 0 then "portcullis_ca_expiry_timestamp_seconds{ca=\"root\"} \(.vault.root_ca_expires_epoch)" else empty end),
    (if (.vault.intermediate_ca_expires_epoch // 0) > 0 then "portcullis_ca_expiry_timestamp_seconds{ca=\"intermediate\"} \(.vault.intermediate_ca_expires_epoch)" else empty end),
    (if (.vault.browser_ca_expires_epoch // 0) > 0 then "portcullis_ca_expiry_timestamp_seconds{ca=\"browser\"} \(.vault.browser_ca_expires_epoch)" else empty end),
    g("portcullis_client_cert_expiry_timestamp_seconds"; "Expiry of the newest valid, unrevoked YubiKey and browser certificate of each user."),
    ((.vault.client_certs // [])[] | "portcullis_client_cert_expiry_timestamp_seconds{cn=\"\(.cn | esc)\",kind=\"\(.kind | esc)\"} \(.epoch)")
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

# keycloak_image_default — the KEYCLOAK_IMAGE default in docker-compose.yml.
keycloak_image_default() {
  sed -n 's/.*\${KEYCLOAK_IMAGE:-\([^}]*\)}.*/\1/p' "$PORTCULLIS_HOME/docker-compose.yml" | head -n1
}

# hub_pinned_warn — before an upgrade: a HUB_IMAGE or KEYCLOAK_IMAGE pinned
# in .env is not upgraded with core (`upgrade` pulls every image of the
# compose file; a pinned one stays what .env names).
hub_pinned_warn() {
  [ -z "${HUB_IMAGE:-}" ] || warn "HUB_IMAGE=$HUB_IMAGE is pinned in .env: the Hub is NOT upgraded with core. If this core's group-gate needs a newer policy file, every app host is denied until the Hub matches (checked after the start)."
  [ -z "${KEYCLOAK_IMAGE:-}" ] || warn "KEYCLOAK_IMAGE=$KEYCLOAK_IMAGE is pinned in .env: Keycloak is NOT upgraded with core. This core's realm needs the sign-in extension's providers of a matching portcullis-keycloak image."
  return 0
}

# hub_policy_check [tries] — after a start: the policy file the Hub wrote
# must be the version this core's group-gate serves (contract §4), and
# group-gate must not be denying for an unsupported version. Prints the
# fix; never fails the run.
hub_policy_check() {
  local tries="${1:-20}" want got="" i denied fix
  want="$(sed -n 's/^POLICY_VERSION = \([0-9][0-9]*\).*/\1/p' "$PORTCULLIS_HOME/group-gate/group-gate.py" | head -n1)"
  [ -n "$want" ] || return 0
  for i in $(seq 1 "$tries"); do
    got="$(dc exec -T group-gate python3 -c 'import json
try:
    print(json.load(open("/hub-data/group-gate-policy.json")).get("version"))
except FileNotFoundError:
    print("missing")
except Exception:
    print("unreadable")' 2>/dev/null | tr -d '[:space:]')" || got=""
    [ -z "$got" ] || [ "$got" = missing ] || break
    [ "$i" -eq "$tries" ] || sleep 3
  done
  denied="$(dc logs --no-color --since 10m group-gate 2>/dev/null | grep -c 'is not supported (only' || true)"
  if { [ -n "$got" ] && [ "$got" != missing ] && [ "$got" != "$want" ]; } || [ "${denied:-0}" -gt 0 ]; then
    fix="run ./portcullis up (it pulls the Hub image this core expects)"
    [ -z "${HUB_IMAGE:-}" ] || fix="remove HUB_IMAGE=$HUB_IMAGE from .env (or set a Hub release that matches this core), then $fix"
    warn "group-gate is denying every app host: the Hub's policy file is version ${got:-unknown}, this core's group-gate serves only version $want. Fix: $fix."
    return 0
  fi
  [ "$got" = "$want" ] && echo "    policy file version $got (matches group-gate)"
  return 0
}

# hub_started_unix — the running Hub container's start time (epoch
# seconds; 0: unknown).
hub_started_unix() {
  local cid at
  cid="$(dc ps -q hub 2>/dev/null | head -n1)"
  [ -n "$cid" ] || { echo 0; return 0; }
  at="$(docker inspect --format '{{.State.StartedAt}}' "$cid" 2>/dev/null || true)"
  jq -nr --arg s "$at" '($s | sub("\\.[0-9]+"; "") | fromdateiso8601? // 0)' 2>/dev/null || echo 0
}

# hub_sync_status — the Hub's last template sync (<data>/source-sync.json,
# JSON; empty: none).
hub_sync_status() { dc exec -T hub cat /data/source-sync.json 2>/dev/null || true; }

# hub_sources_sync [tries] — after a start: the Hub fast-forwards its
# template sources (git) and reports the outcome. A Hub newer than its
# template checkout rejects the templates it no longer accepts and denies
# their apps (fail closed) until the sources are synced. The Hub syncs at
# every start; here it is asked again with SIGHUP (the image may not have
# changed, so the container wasn't restarted) and the result is printed.
# A failed pull keeps the previous checkout. Never fails the run.
hub_sources_sync() {
  local tries="${1:-100}" i st="" since t0 fix
  fix="open Hub → Template Sources → Sync All Sources"
  # Only a Hub that writes the status file (this release on) gets SIGHUP:
  # the file must be newer than the running container (its start-up sync).
  since="$(hub_started_unix)"
  for i in $(seq 1 "$tries"); do
    st="$(hub_sync_status)"
    if [ -n "$st" ] && printf '%s' "$st" | jq -e --argjson t "$since" '.started_unix >= ($t - 5) and (.running | not)' >/dev/null 2>&1; then
      break
    fi
    st=""
    [ "$i" -eq "$tries" ] || sleep 3
  done
  if [ -z "$st" ]; then
    warn "The Hub reported no template sync since it started (an older Hub image, or it is still starting): $fix — until then apps whose templates it rejects stay denied."
    return 0
  fi
  t0="$(date +%s)"
  if ! dc kill -s HUP hub >/dev/null 2>&1; then
    warn "Could not signal the Hub to sync its template sources: $fix."
    return 0
  fi
  st=""
  for i in $(seq 1 "$tries"); do
    st="$(hub_sync_status)"
    if [ -n "$st" ] && printf '%s' "$st" | jq -e --argjson t "$t0" '.started_unix >= $t and (.running | not)' >/dev/null 2>&1; then
      break
    fi
    st=""
    [ "$i" -eq "$tries" ] || sleep 3
  done
  if [ -z "$st" ]; then
    warn "The Hub's template sync did not finish in time: check Hub → Template Sources (the previous templates keep serving meanwhile)."
    return 0
  fi
  printf '%s' "$st" | jq -r '.sources[]? | "    template source \(.name): " +
      (if .ok then (if .updated then "updated to \(.after[0:12])" else "up to date" end)
       else "NOT updated — \(.error // "failed")" end)'
  [ "$(printf '%s' "$st" | jq '.sources | length')" != 0 ] || echo "    no git template sources to sync"
  if ! printf '%s' "$st" | jq -e '.ok' >/dev/null 2>&1; then
    warn "Template sync incomplete (the previous versions are kept, see above and the Hub log): $fix after fixing the cause."
  fi
  local missing
  missing="$(printf '%s' "$st" | jq -r '(.missing_templates // []) | join(", ")')"
  if [ -n "$missing" ]; then
    warn "Enabled apps without a valid template, denied until fixed: $missing (see the Hub log; a newer Hub or template version may be needed)."
  fi
  return 0
}

version_run() {
  local json="$1" ver hub src running="" cid="" kc kcsrc kcrunning=""
  ver="$(portcullis_version)"
  [ ! -f "$(env_file)" ] || env_load
  if [ -n "${HUB_IMAGE:-}" ]; then hub="$HUB_IMAGE" src="HUB_IMAGE"; else hub="$(hub_image_default)" src="default"; fi
  if [ -n "${KEYCLOAK_IMAGE:-}" ]; then kc="$KEYCLOAK_IMAGE" kcsrc="KEYCLOAK_IMAGE"; else kc="$(keycloak_image_default)" kcsrc="default"; fi
  # The running Hub and Keycloak, if this is an installation and Docker answers.
  if [ -f "$(env_file)" ] && command -v docker >/dev/null 2>&1; then
    cid="$(dc ps -q hub 2>/dev/null | head -n1 || true)"
    [ -z "$cid" ] || running="$(docker inspect --format '{{.Config.Image}} ({{.Image}})' "$cid" 2>/dev/null || true)"
    cid="$(dc ps -q keycloak 2>/dev/null | head -n1 || true)"
    [ -z "$cid" ] || kcrunning="$(docker inspect --format '{{.Config.Image}} ({{.Image}})' "$cid" 2>/dev/null || true)"
  fi
  if [ "$json" = true ]; then
    jq -n --arg v "$ver" --arg h "$hub" --arg s "$src" --arg r "$running" --arg k "$kc" --arg ks "$kcsrc" --arg kr "$kcrunning" \
      '{version: $v, hub_image: $h, hub_image_source: $s, hub_running: (if $r == "" then null else $r end),
        keycloak_image: $k, keycloak_image_source: $ks, keycloak_running: (if $kr == "" then null else $kr end)}'
    return 0
  fi
  printf 'portcullis       %s\n' "$ver"
  printf 'hub image        %s (%s)\n' "$hub" "$src"
  [ -z "$running" ] || printf 'hub running      %s\n' "$running"
  printf 'keycloak image   %s (%s)\n' "$kc" "$kcsrc"
  [ -z "$kcrunning" ] || printf 'keycloak running %s\n' "$kcrunning"
}

help_version() {
  cat <<'EOF'
Usage: portcullis version [--json]

Print the core version (VERSION in a release tarball, else `git describe`
of the checkout) and the Hub and Keycloak images in use: HUB_IMAGE /
KEYCLOAK_IMAGE from .env or the environment, else the defaults in
docker-compose.yml, plus the images of the running Hub and Keycloak
containers if there are any.

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
certs, YubiKey and browser certificates expiring within
CERT_EXPIRY_WARN_DAYS = 7 days),
Keycloak (realm, users, forward-auth client),
LLDAP and Traefik. Exits 1 if a core service is down/unhealthy or Vault is
not active, 0 otherwise.

Options:
  --json       machine-readable output (same exit status)
  --textfile   write the same as Prometheus metrics to
               monitoring/textfile/status.prom for the monitoring profile
               (service health, Vault active, CA and per-user YubiKey /
               browser certificate expiry); run after every scheduled backup
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
