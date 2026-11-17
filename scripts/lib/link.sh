# shellcheck shell=bash
#
# `portcullis link …` — the link role of the wg service (multiple servers,
# contract §17): the WireGuard server worker servers dial out to, on its
# own UDP port and the fixed tunnel subnet 10.214.0.0/24 (VPN_LINK_SUBNET,
# network.sh; ruling P3: not configurable in v1).
#
#   link init [--port N]
#   link status [--json]
#
# Key material, all generated in place inside throwaway wg containers
# (the compose binds of single files pin their inodes) and never printed:
# secrets/wg/link.key (WireGuard, `wg genkey`), secrets/wg/link-tls.key
# (P-256, `wg genkey-tls`). The link.control certificate
# (secrets/wg/link-tls.crt) is signed by Vault pki_node/sign/node-link
# directly: the CSR goes on stdin, the root token through -H @<(...), never
# a command line. `up` / `upgrade` renew it at ⅓ of its life left.

LINK_DEFAULT_PORT=51821
LINK_CN="link.control"
LINK_CERT_TTL="2160h"
# Up to this long, `link init` and the renewal wait for Vault to answer.
LINK_VAULT_WAIT="${LINK_VAULT_WAIT:-60}"

# link_on — the link role is configured (.env PORTCULLIS_LINK=on).
link_on() { [ "${PORTCULLIS_LINK:-off}" = on ]; }

# _link_secret <name> — secrets/wg/<name>.
_link_secret() { printf '%s/secrets/wg/%s' "$PORTCULLIS_ROOT" "$1"; }

# _link_wg_run <file> <ro|rw> <wg args...> — `/wg <args>` in a throwaway
# container of the wg image with <file> at /k (no network, no capability,
# read-only root), as the file's owner (rootful Docker's root has no
# CAP_DAC_OVERRIDE here). WG_LINK_TLS_KEY=/k for link-csr.
_link_wg_run() {
  local f="$1" mode="$2" ro=""
  shift 2
  [ "$mode" = rw ] || ro=",readonly"
  ct_run --rm --network none --user "$(ct_operator_id):$CT_UID_WG" --cap-drop ALL \
    --security-opt no-new-privileges:true --read-only -e WG_LINK_TLS_KEY=/k \
    --mount "type=bind,src=$f,dst=/k$ro" --entrypoint /wg portcullis-wg "$@"
}

# link_genkeys — the WireGuard key and the TLS key, each once (an existing
# non-empty file is kept: workers pin the public key).
link_genkeys() {
  local key tls
  key="$(_link_secret link.key)"; tls="$(_link_secret link-tls.key)"
  [ -f "$key" ] && [ -f "$tls" ] || fail "the link key placeholders are missing (./portcullis up creates them)"
  if [ ! -s "$key" ] || [ ! -s "$tls" ]; then
    runtime_build_service wg || fail "could not build the wg image"
  fi
  if [ ! -s "$key" ]; then
    info "Generating the link role's WireGuard key..."
    _link_wg_run "$key" rw genkey /k >/dev/null || fail "could not generate the link key (wg genkey)"
    [ -s "$key" ] || fail "wg genkey wrote no key into $key"
  fi
  if [ ! -s "$tls" ]; then
    info "Generating the link role's TLS key..."
    _link_wg_run "$tls" rw genkey-tls /k >/dev/null || fail "could not generate the link TLS key (wg genkey-tls)"
    [ -s "$tls" ] || fail "wg genkey-tls wrote no key into $tls"
  fi
  ct_group_read "$CT_UID_WG" "$PORTCULLIS_ROOT/secrets/wg" "$key" "$tls" "$(_link_secret link-tls.crt)"
}

# _link_vault_ready — wait (LINK_VAULT_WAIT s) for an unsealed, active Vault.
_link_vault_ready() {
  local start=$SECONDS
  while [ "$(vault_health_code)" != 200 ]; do
    [ $((SECONDS - start)) -lt "$LINK_VAULT_WAIT" ] || return 1
    sleep 2
  done
}

# link_cert_sign — a link.control certificate for link-tls.key: the CSR
# from `wg link-csr`, signed by Vault pki_node/sign/node-link (CSR on
# stdin, token through -H @<(...)), checked (CN, chains to
# certs/node-ca.crt, the CSR's public key — i.e. link-tls.key's, which the
# CLI may not read) and written in place.
link_cert_sign() {
  local tls crt ca csr resp code cert tmp want
  tls="$(_link_secret link-tls.key)"; crt="$(_link_secret link-tls.crt)"; ca="$PORTCULLIS_ROOT/certs/node-ca.crt"
  [ -s "$tls" ] || fail "$tls is empty: run ./portcullis link init"
  [ -s "$ca" ] || fail "$ca is empty: the node CA isn't exported yet (./portcullis pki setup, or ./portcullis upgrade)"
  vault_admin_env || exit 1
  _link_vault_ready || fail "Vault isn't active (unsealed) at ${VAULT_ADDR:-http://127.0.0.1:8200}: ./portcullis vault unseal"
  runtime_build_service wg || fail "could not build the wg image"
  csr="$(_link_wg_run "$tls" ro link-csr)" || fail "could not make the link CSR (wg link-csr)"
  case "$csr" in *"-----BEGIN CERTIFICATE REQUEST-----"*) ;; *) fail "wg link-csr printed no CSR" ;; esac
  want="$(printf '%s\n' "$csr" | openssl req -noout -pubkey 2>/dev/null)"
  [ -n "$want" ] || fail "wg link-csr's CSR has no readable public key"
  tmp="$(mktemp -d)" || fail "no temporary directory"
  chmod 700 "$tmp"
  code="$(printf '%s' "$csr" | jq -Rs --arg cn "$LINK_CN" --arg ttl "$LINK_CERT_TTL" '{csr: ., common_name: $cn, ttl: $ttl, format: "pem"}' \
    | curl -s --max-time 30 -o "$tmp/resp" -w '%{http_code}' -X POST \
        -H @<(printf 'X-Vault-Token: %s\n' "$VAULT_TOKEN") -H 'Content-Type: application/json' --data-binary @- \
        "${VAULT_ADDR:-http://127.0.0.1:8200}/v1/pki_node/sign/node-link" || true)"
  unset csr
  if [ "$code" != 200 ]; then
    resp="$(jq -r '(.errors // []) | join("; ")' "$tmp/resp" 2>/dev/null | cut -c1-200)"
    rm -rf "$tmp"
    fail "Vault refused to sign the link certificate (pki_node/sign/node-link, HTTP ${code:-none})${resp:+: $resp}"
  fi
  cert="$(jq -r '.data.certificate // empty' "$tmp/resp" 2>/dev/null)"
  printf '%s\n' "$cert" > "$tmp/crt"
  if [ "$(openssl x509 -in "$tmp/crt" -noout -subject -nameopt RFC2253 2>/dev/null)" != "subject=CN=$LINK_CN" ] \
     || ! openssl verify -CAfile "$ca" -purpose sslclient "$tmp/crt" >/dev/null 2>&1 \
     || [ "$(openssl x509 -in "$tmp/crt" -noout -pubkey 2>/dev/null)" != "$want" ]; then
    rm -rf "$tmp"
    fail "Vault's link certificate isn't a $LINK_CN certificate (client auth) for link-tls.key under certs/node-ca.crt: nothing written"
  fi
  rm -rf "$tmp"
  # In place: the single-file bind pins the inode.
  printf '%s\n' "$cert" > "$crt"
  unset cert
  ct_group_read "$CT_UID_WG" "$crt"
}

# link_cert_due <crt> [now] — the certificate is missing, unreadable or
# has at most ⅓ of its life left (LINK_NOW: tests' clock).
link_cert_due() {
  local crt="$1" now="${2:-${LINK_NOW:-$(date +%s)}}" nb na
  [ -s "$crt" ] || return 0
  nb="$(to_epoch "$(openssl x509 -in "$crt" -noout -startdate 2>/dev/null | cut -d= -f2)")"
  na="$(to_epoch "$(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2)")"
  { [ "${nb:-0}" -gt 0 ] && [ "${na:-0}" -gt "$nb" ]; } || return 0
  [ $((na - now)) -le $(((na - nb) / 3)) ]
}

# link_cert_renew — `up` / `upgrade` (contract §17.5): with the role on,
# re-sign link.control at ⅓ of its life left. wg reads the files at every
# agent scrape: no restart. A failure warns (the old certificate stays).
link_cert_renew() {
  link_on || return 0
  _rt_is_kube && return 0
  link_cert_due "$(_link_secret link-tls.crt)" || return 0
  info "Renewing the link.control certificate..."
  (link_cert_sign) || warn "could not renew the link.control certificate: agents' metrics stop when it expires (run ./portcullis link init)"
}

# link_overlaps <docker subnets> <host-info json> — one line "<cidr>
# (<what>)" per range the link subnet overlaps: the built-in VPN's subnet,
# the reserved ranges (but itself and Docker's default pools, which don't
# reach 10.214.0.0/24), a Docker network, a Local network an admin entered
# or a wired provider's range.
link_overlaps() {
  local sub="$VPN_LINK_SUBNET" c
  if [ -n "${PORTCULLIS_VPN_SUBNET:-}" ] && _overlaps "$sub" "$PORTCULLIS_VPN_SUBNET"; then
    echo "$PORTCULLIS_VPN_SUBNET (the built-in VPN's subnet)"
  fi
  for c in $(vpn_reserved_ranges); do
    case "$c" in "$VPN_LINK_SUBNET") continue ;; esac
    ! _overlaps "$sub" "$c" || echo "$c (a reserved range)"
  done
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    ! _overlaps "$sub" "$c" || echo "$c (a Docker network)"
  done <<< "$1"
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    case " $VPN_DEFAULT_LOCAL_NETWORKS " in *" $c "*) continue ;; esac
    ! _overlaps "$sub" "$c" || echo "$c (a Local network, Hub Settings)"
  done < <(printf '%s' "$2" | jq -r '(.local_networks // [])[]' 2>/dev/null)
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    ! _overlaps "$sub" "$c" || echo "$c (a wired VPN provider's range)"
  done < <(printf '%s' "$2" | jq -r '(.provider_ranges // [])[]' 2>/dev/null)
}

link_init() {
  local port="$1" info subnets conflicts
  _rt_is_kube && fail "servers need a Docker or Podman primary: link init isn't available on Kubernetes"
  if _vpn_profiles_has_wg && [ "$port" = "${PORTCULLIS_VPN_PORT:-$VPN_DEFAULT_PORT}" ]; then
    fail "--port $port is the built-in VPN's port (PORTCULLIS_VPN_PORT): pick another one"
  fi
  info "Checking the Hub and the link subnet..."
  info="$(_vpn_hub_wait)" || exit 1  # _vpn_hub_wait printed why
  subnets="$(_vpn_docker_subnets)" || fail "could not list the Docker networks' subnets"
  conflicts="$(link_overlaps "$subnets" "$info")"
  if [ -n "$conflicts" ]; then
    printf 'portcullis link init: the link subnet %s (fixed) overlaps:\n%s\n' "$VPN_LINK_SUBNET" "$(printf '%s\n' "$conflicts" | sed 's/^/  /')" >&2
    printf 'Move the overlapping network or setting off %s, then run this again.\n' "$VPN_LINK_SUBNET" >&2
    exit 1
  fi
  _vpn_set COMPOSE_PROFILES "$(_vpn_profiles_with_wg)"
  _vpn_set PORTCULLIS_LINK_PORT "$port"
  link_genkeys
  if link_cert_due "$(_link_secret link-tls.crt)"; then
    info "Signing the link.control certificate (Vault pki_node)..."
    link_cert_sign
  fi
  _vpn_set PORTCULLIS_LINK on
  hub_env_write
  vpn_prom_targets
  if declare -F monitoring_fix_perms >/dev/null; then monitoring_fix_perms; fi
  info "Starting wg, Traefik and the Hub..."
  rt_up wg traefik hub || fail "could not start wg, Traefik and the Hub"
  wait_healthy 120 wg
  # link answers once the Hub has written link.json (it does when it sees
  # the role in wg's status): up to LINK_UP_WAIT (90 s).
  info "Waiting for the Hub to publish link.json..."
  local start=$SECONDS
  until [ "$(link_status_json | jq -r .up)" = true ]; do
    if [ $((SECONDS - start)) -ge "${LINK_UP_WAIT:-90}" ]; then
      warn "link isn't up yet ($(link_status_json | jq -r '.error // "no status"')): check ./portcullis link status, and the Hub's log"
      break
    fi
    sleep 3
  done
  ok "The link role is up (UDP port $port, subnet $VPN_LINK_SUBNET). Open UDP $port in your firewall, then add servers in the Hub (Settings → Servers)."
}

# ── status ──

# link_status_json — {enabled, port, up, error, public_key, peers[{id, ip,
# handshake, age, stale}], problem}. A problem: the role on but wg's link
# down, or a peer whose last handshake is more than 3 min old (offline,
# contract §17.3). A peer that never shook hands (still enrolling) isn't.
link_status_json() {
  local st="" enabled=false
  if link_on; then
    enabled=true
    st="$(rt_exec wg -- /wg status 2>/dev/null)" || st=""
  fi
  jq -n --argjson en "$enabled" --arg port "${PORTCULLIS_LINK_PORT:-$LINK_DEFAULT_PORT}" --arg st "$st" '
    ($st | try fromjson catch null) as $s
    | (if $s != null and ($s | type) == "object" and $s.version == 1
          and ((now - ($s.written | try fromdateiso8601 catch 0)) | . <= 30 and . >= -30)
       then $s.link else null end) as $l
    | {enabled: $en, port: ($port | tonumber? // null),
       up: ($l != null and $l.ok == true),
       error: (if $l == null then null else ($l.error // "") end),
       public_key: (if $l == null then null else $l.public_key end),
       peers: [($l.peers // [])[] | (if .handshake == null then null else (now - (.handshake | try fromdateiso8601 catch 0)) | floor end) as $age
               | {id, ip, handshake, age: $age, stale: ($age != null and $age > 180)}]}
    | .problem = (.enabled and ((.up | not) or any(.peers[]; .stale)))'
}

# link_status_lines <servers json> — the Servers block of `portcullis status`.
link_status_lines() {
  local j="$1" st text
  printf '\n%sServers%s\n' "$C_CYAN" "$C_NC"
  while IFS=$'\t' read -r st text; do
    [ -n "$st" ] && _st_line "$st" "$text"
  done < <(printf '%s' "$j" | jq -r '
    (if (.enabled | not) then ["note", "link not set up (./portcullis link init): no worker servers"]
     elif .up then ["ok", "link up on UDP \(.port), \(.peers | length) server(s)"]
     else ["fail", "link down or not answering" + (if (.error // "") != "" then " (\(.error))" else "" end)] end),
    (.peers[] | [(if .stale then "fail" elif .age == null then "warn" else "ok" end),
       "server \(.id) (\(.ip)): " + (if .age == null then "no handshake yet"
         else "last handshake \(.age) s ago" + (if .stale then " — offline: nothing routes to its apps" else "" end) end)])
    | @tsv')
}

# ── commands ──

help_link() {
  cat <<'EOF'
Usage: portcullis link <subcommand>

  init          Set up the link role: the tunnel worker servers dial out to
  status        The link role and each worker server's last handshake

Run 'portcullis link <subcommand> --help' for details.
EOF
}

help_link_init() {
  cat <<'EOF'
Usage: portcullis link init [--port N]

Set up the link role of the VPN service (compose profile wg; contract §17):
the WireGuard server worker servers connect out to, on its own UDP port and
the fixed tunnel subnet 10.214.0.0/24. Adds wg to COMPOSE_PROFILES, writes
PORTCULLIS_LINK=on and PORTCULLIS_LINK_PORT, generates the link's WireGuard
key and TLS key (once; secrets/wg/link.key and link-tls.key, never printed),
has Vault sign its link.control certificate (pki_node; renewed by up and
upgrade at a third of its life left) and starts wg, Traefik and the Hub.
Then add servers in the Hub (Settings → Servers) and run
./portcullis worker join on each.

The Hub must be running (./portcullis up first): link init refuses when
10.214.0.0/24 overlaps the built-in VPN's subnet, a Portcullis core
network, a Docker network, a Local network you entered in the Hub or a
wired provider's range. Not available on Kubernetes (servers need a Docker
or Podman primary).

Options:
  --port N   its UDP port (default 51821; open it in your firewall)
EOF
}

help_link_status() {
  cat <<'EOF'
Usage: portcullis link status [--json]

The link role (up, port) and each worker server's tunnel address and last
handshake; a server silent for more than 3 minutes is offline (exit 1).
EOF
}

link_status() {
  local j
  j="$(link_status_json)"
  if [ "$1" = true ]; then printf '%s\n' "$j"; else link_status_lines "$j"; fi
  [ "$(printf '%s' "$j" | jq -r .problem)" != true ]
}

cmd_link() {
  local sub="${1:-}"
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_link; [ -n "$sub" ] || exit 2; return 0 ;;
    init|status) ;;
    *) usage_error link "unknown subcommand: $sub" ;;
  esac
  local fn="help_link_${sub}" port="" json=false
  while [ $# -gt 0 ]; do
    case "$sub:$1" in
      *:-h|*:--help) "$fn"; return 0 ;;
      init:--port) need_value "link init" "$1" "${2:-}"; port="$2"; shift ;;
      status:--json) json=true ;;
      *:-*) usage_error "link $sub" "unknown option: $1" ;;
      *) usage_error "link $sub" "unexpected argument: $1" ;;
    esac
    shift
  done
  if [ -n "$port" ]; then
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || usage_error "link init" "--port must be a UDP port number"
  fi
  need_env
  case "$sub" in
    init) link_init "${port:-${PORTCULLIS_LINK_PORT:-$LINK_DEFAULT_PORT}}" ;;
    status) link_status "$json" ;;
  esac
}
