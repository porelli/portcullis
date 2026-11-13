# shellcheck shell=bash
#
# `portcullis vpn …` — the Portcullis VPN (contract §16): the wg service
# (compose profile wg; the edge and the built-in people role), the core
# routers' entrypoint classes per mode, and the host side of built-in
# devices through the Hub's control socket (`hub vpn …` inside the Hub).
#
#   vpn init [--builtin on|off] [--port N] [--subnet CIDR]
#   vpn mode apps|admin|server [--force] [--public-enrol true|false]
#   vpn builtin on|off
#   vpn add-device <user> <name>
#   vpn devices [--user U] [--json]
#   vpn revoke <device-id>
#
# Key material: `vpn init` writes the people key inside a throwaway wg
# container into secrets/wg/people.key, in place (the compose bind of a
# single file pins its inode). `vpn add-device` keeps the client's private
# key in shell variables and on stdin only: never on a command line, never
# in a file; only the public key reaches the Hub.

VPN_DEFAULT_PORT=51820
VPN_DEFAULT_SUBNET="10.213.0.0/22"
# VPN_LINK_SUBNET (the multi-server link role's 10.214.0.0/24) is in
# network.sh: it is one of vpn_reserved_ranges.
# The Hub's default Local networks (contract §14.7): broad private ranges
# that contain any built-in subnet a site would pick. An overlap with them
# is only a warning; a Local network an admin entered refuses.
VPN_DEFAULT_LOCAL_NETWORKS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10"

# vpn_entrypoints <mode> <public_enrol> — the core routers' entrypoint
# classes (contract §5, security ruling): PORTCULLIS_EP_* for the routers
# without group-gate (websecure,vpnsecure, or vpnsecure when VPN-only) and
# PORTCULLIS_WEB_* for the websecure twins of the routers through group-gate
# (websecure, or parked when VPN-only; their -vpn twins are always on
# vpnsecure with portcullis-groups-vpn@docker). apps → everything open;
# admin → the admin surfaces VPN-only; server → core and admin VPN-only,
# enrolment open only with public enrolment on.
vpn_entrypoints() {
  local both="websecure,vpnsecure" core=open admin=open enrol=open c
  case "$1" in
    apps) ;;
    admin) admin=vpn ;;
    server) core=vpn admin=vpn; [ "$2" = true ] || enrol=vpn ;;
    *) return 1 ;;
  esac
  for c in CORE ADMIN ENROL; do
    case "$c" in CORE) v="$core" ;; ADMIN) v="$admin" ;; ENROL) v="$enrol" ;; esac
    if [ "$v" = open ]; then printf 'PORTCULLIS_EP_%s=%s
' "$c" "$both"; else printf 'PORTCULLIS_EP_%s=vpnsecure
' "$c"; fi
  done
  for c in CORE ADMIN ENROL; do
    case "$c" in CORE) v="$core" ;; ADMIN) v="$admin" ;; ENROL) v="$enrol" ;; esac
    if [ "$v" = open ]; then printf 'PORTCULLIS_WEB_%s=websecure
' "$c"; else printf 'PORTCULLIS_WEB_%s=parked
' "$c"; fi
  done
}

# _vpn_profiles_has_wg — COMPOSE_PROFILES (as compose sees it) names wg.
_vpn_profiles_has_wg() {
  case ",${COMPOSE_PROFILES:-}," in *,wg,*) return 0 ;; esac
  return 1
}

# _vpn_profiles_with_wg — COMPOSE_PROFILES with wg added once.
_vpn_profiles_with_wg() {
  if _vpn_profiles_has_wg; then printf '%s' "${COMPOSE_PROFILES:-}"; return 0; fi
  if [ -z "${COMPOSE_PROFILES:-}" ]; then printf 'wg'; else printf '%s,wg' "$COMPOSE_PROFILES"; fi
}

# _vpn_set <key> <value> — .env (in place) and this shell: compose prefers
# the shell's value, which need_env loaded from the old .env.
_vpn_set() {
  env_set "$1" "$2"
  export "$1=$2"
}

# _vpn_docker_subnets — every IPv4 subnet of every Docker network, one per
# line. Fails on a docker error (fail closed: init refuses to go on).
_vpn_docker_subnets() {
  local ids
  ids="$(docker network ls -q)" || return 1
  [ -n "$ids" ] || return 0
  # shellcheck disable=SC2086  # network ids
  docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' $ids | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' || true
}

# _vpn_hub <args> — `hub vpn <args>` in the Hub container as its user 10001:
# the Hub's control socket /tmp/hub-host.sock (0600) answers that uid only.
# Arguments are names and ids; the public key goes on stdin.
_vpn_hub() {
  dc exec -T -u "$CT_UID_HUB:$CT_UID_HUB" hub hub vpn "$@"
}

# _vpn_hub_wait — the Hub's host-info JSON object, waiting up to
# VPN_HUB_WAIT seconds (default 120) for the Hub to answer: right after
# ./portcullis up restarts it, it answers before its health turns healthy
# (or, where the runtime applies no image HEALTHCHECK, it stays running).
# A Hub that is missing, stopped or unhealthy is refused at once; one that
# never answers is refused after the wait (fail closed: no subnet check,
# nothing written, without the Hub's Local networks and provider ranges).
_vpn_hub_wait() {
  local limit="${VPN_HUB_WAIT:-120}" st info start=$SECONDS
  while :; do
    st="$(container_health hub)"
    case "$st" in
      healthy|running|starting|restarting) ;;
      *) fail "the Hub isn't running (state: $st): ./portcullis up first" ;;
    esac
    if info="$(_vpn_host_info)" && printf '%s' "$info" | jq -e 'type == "object"' >/dev/null 2>&1; then
      printf '%s' "$info"
      return 0
    fi
    if [ $((SECONDS - start)) -ge "$limit" ]; then
      fail "the Hub didn't answer hub vpn host-info within $limit s (state: $st): docker compose logs hub"
    fi
    sleep 2
  done
}

# _vpn_hub_ready — wait for the Hub as _vpn_hub_wait does, for a call
# that doesn't need host-info's answer (add-device, devices, revoke).
_vpn_hub_ready() {
  _vpn_hub_wait >/dev/null
}

# _vpn_host_info — the Hub's `hub vpn host-info` JSON (Local networks,
# provider ranges, admin_device_seen), or exit 1 when the Hub doesn't answer.
_vpn_host_info() {
  _vpn_hub host-info 2>/dev/null
}

# vpn_overlaps <subnet> <docker subnets> <host-info json> — one line
# "<cidr> (<what>)" per conflict that refuses the subnet.
vpn_overlaps() {
  local sub="$1" docker_subnets="$2" info="$3" c
  for c in "$(vpn_net)" "$(vpn_edge_subnet)"; do
    ! _overlaps "$sub" "$c" || echo "$c (a Portcullis VPN network)"
  done
  ! _overlaps "$sub" "$VPN_LINK_SUBNET" || echo "$VPN_LINK_SUBNET (reserved for server links)"
  # What wg and group-gate refuse in vpn.json (vpn_reserved_ranges): the
  # VPN networks and the link subnet are reported above.
  for c in $(vpn_reserved_ranges); do
    case "$c" in
      172.16.0.0/12|192.168.0.0/16) ! _overlaps "$sub" "$c" || echo "$c (Docker's default address pool)" ;;
      "$(vpn_net)"|"$(vpn_edge_subnet)"|"$VPN_LINK_SUBNET") ;;
      *) ! _overlaps "$sub" "$c" || echo "$c (a Portcullis core network)" ;;
    esac
  done
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    ! _overlaps "$sub" "$c" || echo "$c (a Docker network)"
  done <<< "$docker_subnets"
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    case " $VPN_DEFAULT_LOCAL_NETWORKS " in *" $c "*) continue ;; esac
    ! _overlaps "$sub" "$c" || echo "$c (a Local network, Hub Settings)"
  done < <(printf '%s' "$info" | jq -r '(.local_networks // [])[]' 2>/dev/null)
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    # The built-in's own subnet, already published (a re-run of vpn init).
    [ "$c" != "${PORTCULLIS_VPN_SUBNET:-}" ] || continue
    ! _overlaps "$sub" "$c" || echo "$c (a wired VPN provider's range)"
  done < <(printf '%s' "$info" | jq -r '(.provider_ranges // [])[]' 2>/dev/null)
}

# vpn_default_local_overlaps <subnet> <host-info json> — the default Local
# networks the subnet lies in (a warning: those ranges never count for
# VPN-only access, contract §14.7).
vpn_default_local_overlaps() {
  local c
  while IFS= read -r c; do
    case " $VPN_DEFAULT_LOCAL_NETWORKS " in *" $c "*) ! _overlaps "$1" "$c" || echo "$c" ;; esac
  done < <(printf '%s' "$2" | jq -r '(.local_networks // [])[]' 2>/dev/null)
}

# vpn_suggest_subnet <docker subnets> <host-info json> — the first /22 of
# 10.213.0.0/16 (64 of them) with no conflict, or nothing.
vpn_suggest_subnet() {
  local base i cand
  base="$(ip_to_int 10.213.0.0)"
  for ((i = 0; i < 64; i++)); do
    cand="$(int_to_ip $((base + i * 1024)))/22"
    if [ -z "$(vpn_overlaps "$cand" "$1" "$2")" ]; then echo "$cand"; return 0; fi
  done
  return 1
}

# _vpn_valid_subnet <cidr> — an IPv4 network /8–/30 without host bits.
_vpn_valid_subnet() {
  local f _l bits="${1##*/}"
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || return 1
  [ "$bits" -ge 8 ] && [ "$bits" -le 30 ] || return 1
  read -r f _l <<< "$(cidr_bounds "$1" 2>/dev/null)" || return 1
  [ -n "${f:-}" ] && [ "$(int_to_ip "$f")/$bits" = "$1" ]
}

# vpn_genkey — a new people key, written into secrets/wg/people.key in
# place by `wg genkey` in a throwaway container of the wg image (built
# first: the profile may only just have been switched on). The container
# runs as the file's owner (the operator's container id: rootful Docker's
# root has no CAP_DAC_OVERRIDE here and couldn't write an operator-owned
# 0640 file), no network, no capability, read-only; the key is never
# printed. Then wg's group may read it (0640 group 10006).
vpn_genkey() {
  local key="$PORTCULLIS_ROOT/secrets/wg/people.key"
  [ -f "$key" ] || fail "$key is missing (./portcullis up creates the placeholder)"
  runtime_build_service wg || fail "could not build the wg image"
  ct_run --rm --network none --user "$(ct_operator_id):$CT_UID_WG" --cap-drop ALL \
    --security-opt no-new-privileges:true --read-only \
    --mount "type=bind,src=$key,dst=/k" --entrypoint /wg portcullis-wg genkey /k >/dev/null \
    || fail "could not generate the people key (wg genkey)"
  [ -s "$key" ] || fail "wg genkey wrote no key into $key"
  ct_group_read "$CT_UID_WG" "$PORTCULLIS_ROOT/secrets/wg" "$key"
}

# vpn_prom_targets — Prometheus' file_sd for job wg (V13): wg's metrics
# address when the profile is on, else nothing (no target, no TargetDown).
vpn_prom_targets() {
  local d="${MONITORING_SECRETS:-$PORTCULLIS_ROOT/secrets/monitoring}/prometheus"
  [ -d "$d" ] || return 0
  if _vpn_profiles_has_wg; then
    jq -n '[{targets: ["wg-metrics:9100"], labels: {}}]' > "$d/wg-targets.json"
  else
    echo '[]' > "$d/wg-targets.json"
  fi
}

# ── status ──

# vpn_status_json — {enabled, mode, public_enrol, builtin, port, subnet,
# up, status, providers, problem}. problem: a mode other than apps while
# wg is down (the VPN-only surfaces are then unreachable).
vpn_status_json() {
  local st="" prov="" enabled=false
  if _vpn_profiles_has_wg; then
    enabled=true
    st="$(dc exec -T wg /wg status 2>/dev/null)" || st=""
    prov="$(dc exec -T wg /wg providers 2>/dev/null)" || prov=""
  fi
  jq -n --argjson en "$enabled" --arg mode "${PORTCULLIS_VPN_MODE:-apps}" --arg pe "${PORTCULLIS_VPN_PUBLIC_ENROL:-true}" \
    --arg bi "${PORTCULLIS_VPN_BUILTIN:-off}" --arg port "${PORTCULLIS_VPN_PORT:-$VPN_DEFAULT_PORT}" \
    --arg sub "${PORTCULLIS_VPN_SUBNET:-$VPN_DEFAULT_SUBNET}" --arg st "$st" --arg prov "$prov" '
    ($st | try fromjson catch null) as $s
    | (if $s != null and ($s | type) == "object" and $s.version == 1
          and ((now - ($s.written | try fromdateiso8601 catch 0)) | . <= 30 and . >= -30)
       then true else false end) as $fresh
    | {enabled: $en, mode: $mode, public_enrol: ($pe == "true"), builtin: $bi, port: ($port | tonumber? // null), subnet: $sub,
       up: ($fresh and ($s.edge.ok == true)),
       status: (if $fresh then $s else null end),
       providers: (($prov | try fromjson catch null) // {} | .providers // [])}
    | .problem = (.mode != "apps" and (.up | not))'
}

# vpn_status_lines <vpn json> — the VPN block of `portcullis status`.
vpn_status_lines() {
  local j="$1" line st text
  printf '\n%sVPN%s\n' "$C_CYAN" "$C_NC"
  while IFS=$'\t' read -r st text; do
    [ -n "$st" ] && _st_line "$st" "$text"
  done < <(printf '%s' "$j" | jq -r --arg now "$(date +%s)" '
    def age($t): if $t == null then "never" else ((($now | tonumber) - ($t | fromdateiso8601)) | floor | tostring) + " s" end;
    (if .mode == "apps" then "ok" else "warn" end) as $ms
    | [$ms, "mode \(.mode)" + (if .mode == "server" then " (public enrolment \(if .public_enrol then "on" else "off" end))" else "" end)
             + (if .mode == "apps" then "" else ": VPN-only core surfaces; break-glass: ./portcullis vpn mode apps" end)],
      (if (.enabled | not) then
         [(if .problem then "fail" else "ok" end), "wg not set up (./portcullis vpn init)"]
       elif .up then
         ["ok", "wg up: edge ok" + (if .status.people == null then ", built-in VPN off"
            elif .status.people.ok then ", built-in VPN on port \(.status.people.port), subnet \(.status.people.subnet), \(.status.people.peers | length) peer(s)"
            else "" end)],
         (if .status.people != null and (.status.people.ok | not) then ["fail", "built-in VPN: \(.status.people.error)"] else empty end)
       else
         [(if .problem then "fail" else "warn" end), "wg down or not answering" + (if .status != null and (.status.edge.ok | not) then " (edge: \(.status.edge.error))" else "" end)
            + (if .problem then ": VPN-only surfaces are unreachable" else "" end)]
       end),
      (.providers[] | [(if .fresh then "ok" else "fail" end),
         "provider \(if .label != "" then .label else .id end) (\(.id)): \(.ranges | join(", ")), \(.devices) device(s), map age \(age(.refreshed_at))"
         + (if .fresh then "" else " — stale: its devices are denied" end)])
    | @tsv')
}

# ── commands ──

help_vpn() {
  cat <<'EOF'
Usage: portcullis vpn <subcommand>

  init          Set up the VPN service (wg) and the built-in VPN
  mode          Which core surfaces are VPN-only: apps, admin or server
  builtin       Switch the built-in VPN on or off (the edge keeps running)
  add-device    Make a built-in VPN device for a person (config + QR here)
  devices       List VPN devices (every provider)
  revoke        Remove a built-in VPN device

Run 'portcullis vpn <subcommand> --help' for details.
EOF
}

help_vpn_init() {
  cat <<'EOF'
Usage: portcullis vpn init [--builtin on|off] [--port N] [--subnet CIDR]

Set up the VPN service (compose profile wg): the edge that wired VPN
providers reach Traefik through, and the built-in WireGuard VPN for people
(userspace WireGuard: no capability, no TUN device). Adds wg to
COMPOSE_PROFILES, writes PORTCULLIS_VPN_BUILTIN / _PORT / _SUBNET, generates
the built-in VPN's key (once; secrets/wg/people.key, never printed) and
starts wg, Traefik and the Hub. The Hub must be running (./portcullis up
first): it answers which Local networks and provider ranges the subnet must
not overlap. vpn init waits up to 120 s for that answer (a Hub that just
restarted), and refuses, writing nothing, when it doesn't come.

The subnet must not overlap a Docker network, Docker's default address pools
172.16.0.0/12 and 192.168.0.0/16 (Docker allocates networks, app instances'
too, from them), Portcullis' core and VPN networks, the reserved link subnet
10.214.0.0/24, a Local network you entered in the Hub or a wired provider's
range; a free /22 in 10.213.0.0/16 is suggested.

Options:
  --builtin on|off  the built-in VPN (default on)
  --port N          its UDP port (default 51820; open it in your firewall)
  --subnet CIDR     its tunnel network (default 10.213.0.0/22)
EOF
}

help_vpn_mode() {
  cat <<'EOF'
Usage: portcullis vpn mode apps|admin|server [--force] [--public-enrol true|false]

Which core surfaces answer only over the VPN (Traefik's vpnsecure):
  apps    none (the default; apps choose per instance in the Hub)
  admin   the Hub, Keycloak's console, LLDAP, the Traefik dashboard, Grafana
          and the MCP endpoints
  server  everything but the enrolment surfaces (sign-in pages, setup links,
          people.<domain>/vpn/), and those too with --public-enrol false

Writes PORTCULLIS_VPN_MODE, PORTCULLIS_VPN_PUBLIC_ENROL and the routers'
entrypoint classes (PORTCULLIS_EP_* and PORTCULLIS_WEB_*), then recreates
core. A VPN-only core page answers /vpn-required on the internet. admin and server refuse unless an
administrator's VPN device was online in the last 10 minutes (the Hub
checks); --force skips that check.

`vpn mode apps` is the break-glass: it works with wg, every VPN provider and
the Hub down.
EOF
}

help_vpn_builtin() {
  cat <<'EOF'
Usage: portcullis vpn builtin on|off

Switch the built-in VPN on (a key is generated if there is none) or off
(the key file is emptied: its devices stop working). The edge, and every
wired VPN provider, keeps running. Recreates and restarts wg.
EOF
}

help_vpn_add_device() {
  cat <<'EOF'
Usage: portcullis vpn add-device <user> <name>

Make a built-in VPN device for <user> named <name>: the key pair is
generated in the wg container, only the public key goes to the Hub (which
assigns the address), and the WireGuard config and a QR code are printed
here, once. The private key is never stored and never on a command line.
EOF
}

help_vpn_devices() {
  cat <<'EOF'
Usage: portcullis vpn devices [--user U] [--json]

List VPN devices of every provider (or one person's), with no key material.
EOF
}

help_vpn_revoke() {
  cat <<'EOF'
Usage: portcullis vpn revoke <device-id>

Remove a built-in VPN device; wg drops its peer at once.
EOF
}

vpn_init() {
  local builtin="$1" port="$2" subnet="$3" info subnets conflicts suggestion warns
  info "Checking the Hub and the VPN subnet..."
  info="$(_vpn_hub_wait)" || exit 1  # _vpn_hub_wait printed why
  subnets="$(_vpn_docker_subnets)" || fail "could not list the Docker networks' subnets"
  if [ "$builtin" = on ]; then
    conflicts="$(vpn_overlaps "$subnet" "$subnets" "$info")"
    if [ -n "$conflicts" ]; then
      suggestion="$(vpn_suggest_subnet "$subnets" "$info" || true)"
      printf 'portcullis vpn init: %s overlaps:\n%s\n' "$subnet" "$(printf '%s\n' "$conflicts" | sed 's/^/  /')" >&2
      case "$conflicts" in
        *"(Docker's default address pool)"*)
          printf "172.16.0.0/12 and 192.168.0.0/16 are reserved: Docker allocates networks (app instances' too) from these ranges, so an address there could be a container's, not a VPN device's.\n" >&2 ;;
      esac
      if [ -n "$suggestion" ]; then
        printf 'Try: ./portcullis vpn init --subnet %s\n' "$suggestion" >&2
      fi
      exit 1
    fi
    warns="$(vpn_default_local_overlaps "$subnet" "$info")"
    [ -z "$warns" ] || warn "$subnet lies in the Local network(s) $(printf '%s' "$warns" | paste -sd' ' -): those never count for VPN-only access"
  fi
  _vpn_set COMPOSE_PROFILES "$(_vpn_profiles_with_wg)"
  _vpn_set PORTCULLIS_VPN_PORT "$port"
  _vpn_set PORTCULLIS_VPN_SUBNET "$subnet"
  if [ "$builtin" = on ] && [ ! -s "$PORTCULLIS_ROOT/secrets/wg/people.key" ]; then
    info "Generating the built-in VPN's key..."
    vpn_genkey
  fi
  _vpn_set PORTCULLIS_VPN_BUILTIN "$builtin"
  hub_env_write
  vpn_prom_targets
  if declare -F monitoring_fix_perms >/dev/null; then monitoring_fix_perms; fi
  info "Starting wg, Traefik and the Hub..."
  stack_compose_up wg traefik hub || fail "could not start wg, Traefik and the Hub"
  wait_healthy 120 wg
  ok "The VPN service is up (built-in VPN $builtin$([ "$builtin" = on ] && echo ", UDP port $port, subnet $subnet")). Wire marketplace VPNs in the Hub; add devices on the Sign-in page or with ./portcullis vpn add-device."
}

vpn_mode() {
  local mode="$1" pe="$2" force="$3" info line
  if [ "$mode" != apps ] && [ "$force" != true ]; then
    info="$(_vpn_hub_wait)" || fail "can't check for an administrator's VPN device without the Hub: start it (./portcullis up), or pass --force"
    if [ "$(printf '%s' "$info" | jq -r '.admin_device_seen == true' 2>/dev/null)" != true ]; then
      fail "no administrator's VPN device was online in the last 10 minutes: in $mode mode the admin surfaces answer only over the VPN, so you could lock yourself out. Connect a device (./portcullis vpn add-device <you> <name>) and run this again, or pass --force (break-glass: ./portcullis vpn mode apps)"
    fi
  fi
  _vpn_set PORTCULLIS_VPN_MODE "$mode"
  _vpn_set PORTCULLIS_VPN_PUBLIC_ENROL "$pe"
  while IFS= read -r line; do
    _vpn_set "${line%%=*}" "${line#*=}"
  done < <(vpn_entrypoints "$mode" "$pe")
  hub_env_write
  info "Recreating core with VPN mode $mode..."
  stack_compose_up || fail "could not recreate core (the .env is written: run ./portcullis up)"
  ok "VPN mode $mode."
}

vpn_builtin() {
  local key="$PORTCULLIS_ROOT/secrets/wg/people.key"
  case "$1" in
    on)
      [ -s "$key" ] || { info "Generating the built-in VPN's key..."; vpn_genkey; } ;;
    off)
      [ -f "$key" ] || fail "$key is missing (./portcullis up creates the placeholder)"
      : > "$key" ;;
  esac
  _vpn_set PORTCULLIS_VPN_BUILTIN "$1"
  hub_env_write
  runtime_build_service wg || fail "could not build the wg image"
  # up applies a changed WG_PEOPLE; the restart makes wg read the key file
  # again (it reads it at start) when only the key changed.
  # shellcheck disable=SC2046  # runtime_no_build prints one flag or nothing
  dc up -d --no-deps $(runtime_no_build) wg || fail "could not recreate wg"
  dc restart wg >/dev/null || fail "could not restart wg"
  ok "The built-in VPN is $1."
}

vpn_add_device() {
  local user="$1" name="$2" kp pub cfg conf
  [ -n "$(dc ps -q --status running wg 2>/dev/null)" ] || fail "wg isn't running: ./portcullis vpn init first"
  _vpn_hub_ready || exit 1  # before the key pair: _vpn_hub_wait printed why
  kp="$(dc exec -T wg /wg keypair)" || fail "wg keypair failed"
  pub="$(KP="$kp" jq -rn 'env.KP | fromjson | .public_key')" || { unset kp; fail "wg keypair: unexpected output"; }
  cfg="$(printf '%s\n' "$pub" | _vpn_hub add-device --user "$user" --name "$name")" \
    || { unset kp; fail "the Hub refused the device (see above)"; }
  conf="$(KP="$kp" CFG="$cfg" jq -rn '
    (env.KP | fromjson) as $k | (env.CFG | fromjson) as $c
    | "[Interface]\nPrivateKey = \($k.private_key)\nAddress = \($c.address)/32\nDNS = \($c.dns)\nMTU = \($c.mtu)\n\n[Peer]\nPublicKey = \($c.server_public_key)\nEndpoint = \($c.endpoint)\nAllowedIPs = \($c.allowed_ips)\nPersistentKeepalive = 25"')" \
    || { unset kp; fail "the Hub's answer isn't a device config"; }
  unset kp
  printf '# WireGuard config for %s (%s): import it, or scan the QR code below. Shown once.\n%s\n\n' "$user" "$name" "$conf"
  printf '%s\n' "$conf" | dc exec -T wg /wg qr || warn "could not draw the QR code"
  unset conf
}

vpn_devices() {
  local user="$1" json="$2" out
  local -a args=()
  [ -z "$user" ] || args=(--user "$user")
  _vpn_hub_ready || exit 1
  out="$(_vpn_hub devices "${args[@]}")" || fail "the Hub didn't list the devices (is it running?)"
  if [ "$json" = true ]; then printf '%s\n' "$out"; return 0; fi
  printf '%s' "$out" | jq -r '
    (if type == "array" then . else (.devices // []) end) as $d
    | if ($d | length) == 0 then "no VPN devices"
      else (["ID", "USER", "NAME", "PROVIDER", "ADDRESS", "LAST SEEN", "EXPIRES"] | @tsv),
           ($d[] | [.id, (.user // .owner // "-"), .name, (.provider_label // .provider), .address, (.last_seen // "never"), (.expires // "never")] | @tsv)
      end' | column -t -s $'\t'
}

vpn_revoke() {
  _vpn_hub_ready || exit 1
  _vpn_hub revoke "$1" || fail "the Hub didn't remove device $1"
  ok "Removed VPN device $1."
}

cmd_vpn() {
  local sub="${1:-}"
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_vpn; [ -n "$sub" ] || exit 2; return 0 ;;
    init|mode|builtin|add-device|devices|revoke) ;;
    *) usage_error vpn "unknown subcommand: $sub" ;;
  esac
  local fn="help_vpn_${sub//-/_}" builtin=on port="" subnet="" force=false pe="" user="" json=false
  local -a pos=()
  while [ $# -gt 0 ]; do
    case "$sub:$1" in
      *:-h|*:--help) "$fn"; return 0 ;;
      init:--builtin) need_value "vpn init" "$1" "${2:-}"; builtin="$2"; shift ;;
      init:--port) need_value "vpn init" "$1" "${2:-}"; port="$2"; shift ;;
      init:--subnet) need_value "vpn init" "$1" "${2:-}"; subnet="$2"; shift ;;
      mode:--force) force=true ;;
      mode:--public-enrol) need_value "vpn mode" "$1" "${2:-}"; pe="$2"; shift ;;
      devices:--user) need_value "vpn devices" "$1" "${2:-}"; user="$2"; shift ;;
      devices:--json) json=true ;;
      *:-*) usage_error "vpn $sub" "unknown option: $1" ;;
      *) pos+=("$1") ;;
    esac
    shift
  done
  local npos=${#pos[@]}
  case "$sub" in
    init)
      [ "$npos" -eq 0 ] || usage_error "vpn init" "unexpected argument: ${pos[0]}"
      case "$builtin" in on|off) ;; *) usage_error "vpn init" "--builtin must be on or off" ;; esac
      if [ -n "$port" ]; then
        [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || usage_error "vpn init" "--port must be a UDP port number"
      fi
      if [ -n "$subnet" ]; then
        _vpn_valid_subnet "$subnet" || usage_error "vpn init" "--subnet must be an IPv4 network /8–/30 without host bits (e.g. 10.213.0.0/22)"
      fi ;;
    mode)
      [ "$npos" -eq 1 ] || usage_error "vpn mode" "expected apps, admin or server"
      case "${pos[0]}" in apps|admin|server) ;; *) usage_error "vpn mode" "expected apps, admin or server" ;; esac
      case "$pe" in ""|true|false) ;; *) usage_error "vpn mode" "--public-enrol must be true or false" ;; esac ;;
    builtin)
      [ "$npos" -eq 1 ] || usage_error "vpn builtin" "expected on or off"
      case "${pos[0]}" in on|off) ;; *) usage_error "vpn builtin" "expected on or off" ;; esac ;;
    add-device)
      [ "$npos" -eq 2 ] || usage_error "vpn add-device" "expected <user> <name>"
      [[ "${pos[0]}" =~ ^[a-z0-9][a-z0-9._@-]*$ ]] || usage_error "vpn add-device" "invalid user name: ${pos[0]}"
      [[ "${pos[1]}" =~ ^[^[:cntrl:]]{1,64}$ ]] || usage_error "vpn add-device" "<name> must be one line of 1–64 characters" ;;
    devices)
      [ "$npos" -eq 0 ] || usage_error "vpn devices" "unexpected argument: ${pos[0]}"
      [ -z "$user" ] || [[ "$user" =~ ^[a-z0-9][a-z0-9._@-]*$ ]] || usage_error "vpn devices" "invalid user name: $user" ;;
    revoke)
      [ "$npos" -eq 1 ] || usage_error "vpn revoke" "expected exactly one <device-id>"
      [[ "${pos[0]}" =~ ^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$ ]] || usage_error "vpn revoke" "invalid device id: ${pos[0]}" ;;
  esac
  need_env
  case "$sub" in
    init) vpn_init "$builtin" "${port:-${PORTCULLIS_VPN_PORT:-$VPN_DEFAULT_PORT}}" "${subnet:-${PORTCULLIS_VPN_SUBNET:-$VPN_DEFAULT_SUBNET}}" ;;
    mode) vpn_mode "${pos[0]}" "${pe:-${PORTCULLIS_VPN_PUBLIC_ENROL:-true}}" "$force" ;;
    builtin) vpn_builtin "${pos[0]}" ;;
    add-device) vpn_add_device "${pos[0]}" "${pos[1]}" ;;
    devices) vpn_devices "$user" "$json" ;;
    revoke) vpn_revoke "${pos[0]}" ;;
  esac
}
