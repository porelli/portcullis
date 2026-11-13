# shellcheck shell=bash
#
# Helpers for the Docker networks with fixed IPAM and a static Traefik IP:
#   portcullis-proxy  shared routing plane (Traefik + apps); header-auth
#                     apps trust only Traefik's IP
#   portcullis-auth   Traefik <-> Keycloak only; Keycloak trusts proxy
#                     headers (incl. the forwarded client cert) only from
#                     Traefik's IP there
# Validation of the .env settings and a guard against an existing network
# with a different IPAM config. Sourced by ./portcullis; unit-tested by
# tests/test_shell_libs.sh with a stub `docker` on PATH.
#
# Inputs (env, with the same defaults as docker-compose.yml):
#   PORTCULLIS_PROXY_SUBNET    default 172.31.250.0/24
#   PORTCULLIS_PROXY_IP_RANGE  default 172.31.250.128/25
#   PORTCULLIS_TRAEFIK_IP      default 172.31.250.2
#   PORTCULLIS_MCP_GATE_IP     default 172.31.250.3 (mcp-gate on portcullis-proxy)
#   PORTCULLIS_AUTH_SUBNET     default 172.31.251.0/28
#   PORTCULLIS_AUTH_IP_RANGE   default 172.31.251.8/29
#   PORTCULLIS_AUTH_TRAEFIK_IP default 172.31.251.2
#   PORTCULLIS_DOMAINS_SUBNET  default 172.31.252.0/28 (portcullis-domains)
#   PORTCULLIS_MCP_SUBNET      default 172.31.253.0/28 (portcullis-mcp: mcp-gate,
#                              Keycloak, the Hub)
#   PORTCULLIS_MCP_IP_RANGE    default 172.31.253.8/29 (the gate's dynamic address)
#   PORTCULLIS_MCP_KEYCLOAK_IP default 172.31.253.2 (pinned; the gate's /etc/hosts)
#   PORTCULLIS_MCP_HUB_IP      default 172.31.253.3 (pinned; the gate's /etc/hosts)
#   PORTCULLIS_VPN_NET         default 172.31.254.0/26 (portcullis-vpn: wg's edge
#                              ports, wired providers' gateways .16–.62; no Traefik)
#   PORTCULLIS_VPN_IP_RANGE    default 172.31.254.8/29 (dynamic; none of the pinned)
#   PORTCULLIS_VPN_WG_IP       default 172.31.254.3 (wg, where gateways connect)
#   PORTCULLIS_VPN_EDGE_SUBNET default 172.31.254.64/28 (portcullis-vpn-edge:
#                              exactly wg and Traefik's vpnsecure)
#   PORTCULLIS_VPN_EDGE_IP_RANGE    default 172.31.254.72/29
#   PORTCULLIS_VPN_EDGE_TRAEFIK_IP  default 172.31.254.66 (vpnsecure)
#   PORTCULLIS_VPN_EDGE_WG_IP       default 172.31.254.67 (the only PROXY-trusted address)

PROXY_NETWORK="${PROXY_NETWORK:-portcullis-proxy}"
AUTH_NETWORK="${AUTH_NETWORK:-portcullis-auth}"
# Compose names it <project>_portcullis-domains (no explicit name).
DOMAINS_NETWORK="${DOMAINS_NETWORK:-portcullis_portcullis-domains}"
MCP_NETWORK="${MCP_NETWORK:-portcullis-mcp}"
VPN_NETWORK="${VPN_NETWORK:-portcullis-vpn}"
VPN_EDGE_NETWORK="${VPN_EDGE_NETWORK:-portcullis-vpn-edge}"

proxy_subnet()   { echo "${PORTCULLIS_PROXY_SUBNET:-172.31.250.0/24}"; }
proxy_ip_range() { echo "${PORTCULLIS_PROXY_IP_RANGE:-172.31.250.128/25}"; }
proxy_traefik_ip() { echo "${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}"; }
mcp_gate_ip()    { echo "${PORTCULLIS_MCP_GATE_IP:-172.31.250.3}"; }
auth_subnet()    { echo "${PORTCULLIS_AUTH_SUBNET:-172.31.251.0/28}"; }
auth_ip_range()  { echo "${PORTCULLIS_AUTH_IP_RANGE:-172.31.251.8/29}"; }
auth_traefik_ip() { echo "${PORTCULLIS_AUTH_TRAEFIK_IP:-172.31.251.2}"; }
domains_subnet() { echo "${PORTCULLIS_DOMAINS_SUBNET:-172.31.252.0/28}"; }
mcp_subnet()     { echo "${PORTCULLIS_MCP_SUBNET:-172.31.253.0/28}"; }
mcp_ip_range()   { echo "${PORTCULLIS_MCP_IP_RANGE:-172.31.253.8/29}"; }
mcp_keycloak_ip() { echo "${PORTCULLIS_MCP_KEYCLOAK_IP:-172.31.253.2}"; }
mcp_hub_ip()     { echo "${PORTCULLIS_MCP_HUB_IP:-172.31.253.3}"; }
vpn_net()        { echo "${PORTCULLIS_VPN_NET:-172.31.254.0/26}"; }
vpn_ip_range()   { echo "${PORTCULLIS_VPN_IP_RANGE:-172.31.254.8/29}"; }
vpn_wg_ip()      { echo "${PORTCULLIS_VPN_WG_IP:-172.31.254.3}"; }
vpn_edge_subnet()     { echo "${PORTCULLIS_VPN_EDGE_SUBNET:-172.31.254.64/28}"; }
vpn_edge_ip_range()   { echo "${PORTCULLIS_VPN_EDGE_IP_RANGE:-172.31.254.72/29}"; }
vpn_edge_traefik_ip() { echo "${PORTCULLIS_VPN_EDGE_TRAEFIK_IP:-172.31.254.66}"; }
vpn_edge_wg_ip()      { echo "${PORTCULLIS_VPN_EDGE_WG_IP:-172.31.254.67}"; }

# ip_to_int <a.b.c.d> — prints the address as an integer; fails if invalid.
ip_to_int() {
  local ip="$1" a b c d rest
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r a b c d rest <<< "$ip"
  for o in "$a" "$b" "$c" "$d"; do
    [ "$((10#$o))" -le 255 ] || return 1
  done
  echo $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
}

# cidr_bounds <a.b.c.d/n> — prints "<first> <last>" as integers.
cidr_bounds() {
  local cidr="$1" ip len base mask
  [[ "$cidr" == */* ]] || return 1
  ip="${cidr%/*}"; len="${cidr#*/}"
  [[ "$len" =~ ^[0-9]+$ ]] && [ "$len" -le 32 ] || return 1
  base="$(ip_to_int "$ip")" || return 1
  mask=$(( len == 0 ? 0 : (0xFFFFFFFF << (32 - len)) & 0xFFFFFFFF ))
  echo "$(( base & mask )) $(( (base & mask) | (~mask & 0xFFFFFFFF) ))"
}

# int_to_ip <n> — the dotted address of an integer.
int_to_ip() {
  echo "$(( ($1 >> 24) & 255 )).$(( ($1 >> 16) & 255 )).$(( ($1 >> 8) & 255 )).$(( $1 & 255 ))"
}

# cidr_contains <cidr> <ip> — succeed if ip is inside cidr.
cidr_contains() {
  local first last n
  read -r first last <<< "$(cidr_bounds "$1")" || return 1
  [ -n "$first" ] || return 1
  n="$(ip_to_int "$2")" || return 1
  [ "$n" -ge "$first" ] && [ "$n" -le "$last" ]
}

# _validate_net <VAR-prefix> <subnet> <range> <traefik-ip> <ip-var> — check
# one network's three settings are coherent. Prints a reason, returns 1.
_validate_net() {
  local pfx="$1" subnet="$2" range="$3" ip="$4" ipvar="$5" sf sl rf rl
  read -r sf sl <<< "$(cidr_bounds "$subnet" 2>/dev/null)" || true
  [ -n "${sf:-}" ] || { echo "${pfx}_SUBNET=$subnet is not a valid IPv4 CIDR"; return 1; }
  read -r rf rl <<< "$(cidr_bounds "$range" 2>/dev/null)" || true
  [ -n "${rf:-}" ] || { echo "${pfx}_IP_RANGE=$range is not a valid IPv4 CIDR"; return 1; }
  ip_to_int "$ip" >/dev/null || { echo "$ipvar=$ip is not a valid IPv4 address"; return 1; }
  { [ "$rf" -ge "$sf" ] && [ "$rl" -le "$sl" ]; } || { echo "${pfx}_IP_RANGE=$range is not inside ${pfx}_SUBNET=$subnet"; return 1; }
  cidr_contains "$subnet" "$ip" || { echo "$ipvar=$ip is not inside ${pfx}_SUBNET=$subnet"; return 1; }
  if cidr_contains "$range" "$ip"; then
    echo "$ipvar=$ip is inside the dynamic range ${pfx}_IP_RANGE=$range (another container could take it)"
    return 1
  fi
  # The first address is the bridge gateway, network/broadcast are unusable.
  local n; n="$(ip_to_int "$ip")"
  { [ "$n" -gt $((sf + 1)) ] && [ "$n" -lt "$sl" ]; } || { echo "$ipvar=$ip collides with the network/gateway/broadcast address"; return 1; }
  return 0
}

# validate_proxy_network_config — portcullis-proxy settings.
validate_proxy_network_config() {
  _validate_net PORTCULLIS_PROXY "$(proxy_subnet)" "$(proxy_ip_range)" "$(proxy_traefik_ip)" PORTCULLIS_TRAEFIK_IP
}

# validate_mcp_gate_ip — PORTCULLIS_MCP_GATE_IP (contract §2): a static
# address inside PORTCULLIS_PROXY_SUBNET, outside the dynamic range (no app
# container can be handed it: companions trust only the gate's caller
# secret, but the address is the gate's), never Traefik's, never the
# network / gateway / broadcast address.
validate_mcp_gate_ip() {
  local ip
  ip="$(mcp_gate_ip)"
  _validate_net PORTCULLIS_PROXY "$(proxy_subnet)" "$(proxy_ip_range)" "$ip" PORTCULLIS_MCP_GATE_IP || return 1
  if [ "$ip" = "$(proxy_traefik_ip)" ] || [ "$(ip_to_int "$ip")" = "$(ip_to_int "$(proxy_traefik_ip)" 2>/dev/null)" ]; then
    echo "PORTCULLIS_MCP_GATE_IP=$ip is PORTCULLIS_TRAEFIK_IP (each needs its own address)"
    return 1
  fi
}

# validate_auth_network_config — portcullis-auth settings, and no overlap
# with portcullis-proxy.
validate_auth_network_config() {
  local af al pf pl
  _validate_net PORTCULLIS_AUTH "$(auth_subnet)" "$(auth_ip_range)" "$(auth_traefik_ip)" PORTCULLIS_AUTH_TRAEFIK_IP || return 1
  read -r af al <<< "$(cidr_bounds "$(auth_subnet)")"
  read -r pf pl <<< "$(cidr_bounds "$(proxy_subnet)" 2>/dev/null)" || true
  if [ -n "${pf:-}" ] && [ "$af" -le "$pl" ] && [ "$pf" -le "$al" ]; then
    echo "PORTCULLIS_AUTH_SUBNET=$(auth_subnet) overlaps PORTCULLIS_PROXY_SUBNET=$(proxy_subnet)"
    return 1
  fi
}

# _overlaps <cidr> <cidr> — succeed if the two ranges share an address.
_overlaps() {
  local af al bf bl
  read -r af al <<< "$(cidr_bounds "$1" 2>/dev/null)" || true
  read -r bf bl <<< "$(cidr_bounds "$2" 2>/dev/null)" || true
  [ -n "${af:-}" ] && [ -n "${bf:-}" ] && [ "$af" -le "$bl" ] && [ "$bf" -le "$al" ]
}

# validate_domains_network_config — PORTCULLIS_DOMAINS_SUBNET (the domains
# API answers only connections addressed to it there, contract §12): a
# valid IPv4 CIDR with room for the gateway and two containers, overlapping
# neither portcullis-proxy nor portcullis-auth.
validate_domains_network_config() {
  local sub sf sl
  sub="$(domains_subnet)"
  read -r sf sl <<< "$(cidr_bounds "$sub" 2>/dev/null)" || true
  [ -n "${sf:-}" ] || { echo "PORTCULLIS_DOMAINS_SUBNET=$sub is not a valid IPv4 CIDR"; return 1; }
  [ $((sl - sf)) -ge 4 ] || { echo "PORTCULLIS_DOMAINS_SUBNET=$sub is too small (at least a /29)"; return 1; }
  if _overlaps "$sub" "$(proxy_subnet)"; then
    echo "PORTCULLIS_DOMAINS_SUBNET=$sub overlaps PORTCULLIS_PROXY_SUBNET=$(proxy_subnet)"; return 1
  fi
  if _overlaps "$sub" "$(auth_subnet)"; then
    echo "PORTCULLIS_DOMAINS_SUBNET=$sub overlaps PORTCULLIS_AUTH_SUBNET=$(auth_subnet)"; return 1
  fi
}

# validate_mcp_network_config — portcullis-mcp (mcp-gate ⇄ Keycloak's JWKS
# and the Hub's :8890, contract §15): the gate never resolves those two
# names through DNS — compose maps them (extra_hosts) to the pinned
# PORTCULLIS_MCP_KEYCLOAK_IP / _HUB_IP, which must lie in the subnet,
# outside the dynamic range (the gate's own address comes from it), apart
# from each other; the subnet overlaps no other fixed core network.
validate_mcp_network_config() {
  local sub other
  sub="$(mcp_subnet)"
  _validate_net PORTCULLIS_MCP "$sub" "$(mcp_ip_range)" "$(mcp_keycloak_ip)" PORTCULLIS_MCP_KEYCLOAK_IP || return 1
  _validate_net PORTCULLIS_MCP "$sub" "$(mcp_ip_range)" "$(mcp_hub_ip)" PORTCULLIS_MCP_HUB_IP || return 1
  if [ "$(ip_to_int "$(mcp_keycloak_ip)")" = "$(ip_to_int "$(mcp_hub_ip)")" ]; then
    echo "PORTCULLIS_MCP_KEYCLOAK_IP and PORTCULLIS_MCP_HUB_IP are the same address ($(mcp_hub_ip))"; return 1
  fi
  for other in "PORTCULLIS_PROXY_SUBNET=$(proxy_subnet)" "PORTCULLIS_AUTH_SUBNET=$(auth_subnet)" "PORTCULLIS_DOMAINS_SUBNET=$(domains_subnet)"; do
    if _overlaps "$sub" "${other#*=}"; then echo "PORTCULLIS_MCP_SUBNET=$sub overlaps $other"; return 1; fi
  done
}

# validate_vpn_network_config — portcullis-vpn (contract §16): wg's
# address (its edge ports) pinned inside the subnet, outside the dynamic
# range; the Hub pins wired providers' gateways at .16–.62 (Config.VPNNet),
# so the subnet is a /26 at least and neither the range nor wg reach that
# window; no overlap with the other fixed core networks. Traefik is never
# on it (gateways share it): vpnsecure lives on portcullis-vpn-edge.
validate_vpn_network_config() {
  local sub range sf sl rf rl n other
  sub="$(vpn_net)"; range="$(vpn_ip_range)"
  _validate_net PORTCULLIS_VPN "$sub" "$range" "$(vpn_wg_ip)" PORTCULLIS_VPN_WG_IP || return 1
  read -r sf sl <<< "$(cidr_bounds "$sub")"
  [ $((sl - sf + 1)) -ge 64 ] || { echo "PORTCULLIS_VPN_NET=$sub is too small (at least a /26: gateways take .16–.62)"; return 1; }
  read -r rf rl <<< "$(cidr_bounds "$range")"
  if [ "$rl" -ge $((sf + 16)) ] && [ "$rf" -le $((sf + 62)) ]; then
    echo "PORTCULLIS_VPN_IP_RANGE=$range reaches the gateway addresses .16–.62 of PORTCULLIS_VPN_NET"; return 1
  fi
  n="$(ip_to_int "$(vpn_wg_ip)")"
  if [ "$n" -ge $((sf + 16)) ] && [ "$n" -le $((sf + 62)) ]; then
    echo "PORTCULLIS_VPN_WG_IP=$(vpn_wg_ip) is one of the gateway addresses .16–.62 of PORTCULLIS_VPN_NET"; return 1
  fi
  for other in "PORTCULLIS_PROXY_SUBNET=$(proxy_subnet)" "PORTCULLIS_AUTH_SUBNET=$(auth_subnet)" \
               "PORTCULLIS_DOMAINS_SUBNET=$(domains_subnet)" "PORTCULLIS_MCP_SUBNET=$(mcp_subnet)" \
               "PORTCULLIS_VPN_EDGE_SUBNET=$(vpn_edge_subnet)"; do
    if _overlaps "$sub" "${other#*=}"; then echo "PORTCULLIS_VPN_NET=$sub overlaps $other"; return 1; fi
  done
}

# validate_vpn_edge_network_config — portcullis-vpn-edge (contract §16):
# exactly wg and Traefik's vpnsecure; Traefik trusts PROXY headers from
# wg's address here only, and no gateway can reach this network. Both
# pinned inside the subnet, outside the dynamic range, apart; no overlap
# with any other fixed core network.
validate_vpn_edge_network_config() {
  local sub range other
  sub="$(vpn_edge_subnet)"; range="$(vpn_edge_ip_range)"
  _validate_net PORTCULLIS_VPN_EDGE "$sub" "$range" "$(vpn_edge_traefik_ip)" PORTCULLIS_VPN_EDGE_TRAEFIK_IP || return 1
  _validate_net PORTCULLIS_VPN_EDGE "$sub" "$range" "$(vpn_edge_wg_ip)" PORTCULLIS_VPN_EDGE_WG_IP || return 1
  if [ "$(ip_to_int "$(vpn_edge_traefik_ip)")" = "$(ip_to_int "$(vpn_edge_wg_ip)")" ]; then
    echo "PORTCULLIS_VPN_EDGE_TRAEFIK_IP and PORTCULLIS_VPN_EDGE_WG_IP are the same address ($(vpn_edge_wg_ip))"; return 1
  fi
  for other in "PORTCULLIS_PROXY_SUBNET=$(proxy_subnet)" "PORTCULLIS_AUTH_SUBNET=$(auth_subnet)" \
               "PORTCULLIS_DOMAINS_SUBNET=$(domains_subnet)" "PORTCULLIS_MCP_SUBNET=$(mcp_subnet)" \
               "PORTCULLIS_VPN_NET=$(vpn_net)"; do
    if _overlaps "$sub" "${other#*=}"; then echo "PORTCULLIS_VPN_EDGE_SUBNET=$sub overlaps $other"; return 1; fi
  done
}

# Every core compose service (all profiles; CI checks the list against
# docker-compose.yml), and the ones that are portcullis-proxy members.
CORE_SERVICE_NAMES="socket-proxy-traefik socket-proxy-hub traefik postgres vault lldap keycloak sessions forward-auth forward-auth-ext group-gate hub enroll domains dns-tool mcp-gate prometheus alertmanager blackbox textfile-exporter grafana wg"
CORE_PROXY_SERVICES="traefik mcp-gate grafana"

# proxy_dns_shadows — one "<container> <name>" line per container on
# portcullis-proxy that could take core traffic by name. Core containers
# are ONLY the ids `docker compose -p <core project> -f docker-compose.yml
# ps -aq` lists (never labels or names a container gives itself); each may
# answer only to its own service, which must be in CORE_PROXY_SERVICES. Any
# other container is flagged for every core name it answers to (container
# name, hostname, network alias, DNS name; folded, a trailing dot ignored)
# and for claiming a core service label or a core container name.
#
# AI companion names (final review I4): mcp-gate sends app tokens and
# caller secrets to `portcullis-mcp-<instance>--<companion>` through Docker
# DNS on portcullis-proxy, so those names (`portcullis-mcp-` with a `--`;
# core's own portcullis-mcp-gate-1 has none) are guarded too. Such a name is
# allowed only as a portcullis-proxy network alias of a container that
# `docker compose -p portcullis-<instance> ps -aq` lists (the Hub's
# project for that instance), and only ONE container may answer to it (a
# second one would join Docker's round-robin). A core container, a
# container name or hostname with that prefix, a malformed name, a
# container outside that project, and every container sharing a name
# with another are flagged. Exit 2 on any docker error (fail closed);
# nothing when the network doesn't exist.
proxy_dns_shadows() {
  local ids id core info project="${COMPOSE_PROJECT_NAME:-portcullis}" exempt out line
  local mcp=""
  if ! ids="$(docker network inspect "$PROXY_NETWORK" --format '{{range $k, $v := .Containers}}{{$k}} {{end}}' 2>/dev/null)"; then
    local listed
    listed="$(docker network ls --format '{{.Name}}' 2>/dev/null)" || return 2
    ! printf '%s\n' "$listed" | grep -qx "$PROXY_NETWORK" || return 2
    return 0
  fi
  [ -n "${ids// /}" ] || return 0
  core="$(docker compose --project-directory "$PORTCULLIS_ROOT" -p "$project" -f "$PORTCULLIS_HOME/docker-compose.yml" --profile "*" ps -aq 2>/dev/null)" || return 2
  for id in $ids; do
    info="$(docker inspect --format '{{json .}}' "$id" 2>/dev/null)" || return 2
    exempt=false
    ! printf '%s\n' "$core" | grep -qxF -- "$id" || exempt=true
    # "F <container> <name...>": flagged; "M <container> <alias> <instance>":
    # an AI companion alias whose project membership is checked below.
    out="$(printf '%s' "$info" | jq -r --arg net "$PROXY_NETWORK" --arg proj "$project" --arg core " $CORE_SERVICE_NAMES " \
        --arg proxy " $CORE_PROXY_SERVICES " --argjson exempt "$exempt" '
        ((.Name // "") | ltrimstr("/")) as $n
        | ((.Config.Labels // {})["com.docker.compose.service"] // "") as $svc
        | ((.Config.Labels // {})["com.docker.compose.project"] // "") as $p
        | (.NetworkSettings.Networks[$net] // {}) as $nw
        | ([$n, (.Config.Hostname // ""), ($nw | (.Aliases // [])[], (.DNSNames // [])[])]
           | map(ascii_downcase | rtrimstr(".")) | unique) as $all
        | ($all | map(select(. as $x | $x != "" and ($core | contains(" " + $x + " "))))) as $hits
        | ([$n, (.Config.Hostname // "")] | map(ascii_downcase | rtrimstr("."))) as $own
        | ($all | map(select(startswith("portcullis-mcp-") and contains("--")))) as $ai
        | (if $exempt then
            (if ($proxy | contains(" " + $svc + " ")) and $svc != "" then empty
             else "\($n) \($svc) (core service not on portcullis-proxy)" end),
            ($hits[] | select(. != $svc) | "\($n) \(.)")
          else
            ($hits[] | "\($n) \(.)"),
            (if $p == $proj and $svc != "" and ($core | contains(" " + $svc + " ")) then "\($n) \($svc) (core service label)" else empty end),
            ($n | capture("^" + $proj + "-(?<s>.+)-[0-9]+$")? | .s | select(. as $s | $core | contains(" " + $s + " "))
              | select(. != $svc or $p != $proj) | "\($n) \(.) (core container name)")
          end | "F " + .),
          ($ai[] as $a
           | ([$a | capture("^portcullis-mcp-(?<i>[a-z0-9]+(-[a-z0-9]+)*)--[a-z0-9]+(-[a-z0-9]+)*$")?] | .[0]) as $m
           | if $exempt then "F \($n) \($a) (AI companion name on a core container)"
             elif ($own | index($a)) != null then "F \($n) \($a) (AI companion name as container name or hostname)"
             elif $m == null then "F \($n) \($a) (malformed AI companion name)"
             else "M \($n) \($a) \($m.i) \(if $svc == "" then "-" else $svc end) \((.Config.Labels // {})["com.docker.compose.project.config_files"] // "-")" end)' )" || return 2
    while IFS= read -r line; do
      case "$line" in
        "F "*) printf '%s\n' "${line#F }" ;;
        "M "*) mcp="$mcp$id ${line#M }"$'\n' ;;
      esac
    done <<< "$out"
  done
  [ -n "$mcp" ] || return 0
  _proxy_ai_alias_check "$mcp"
}

# _proxy_ai_alias_check <lines> — the AI companion part of
# proxy_dns_shadows, one "<id> <container> <alias> <instance> <service>
# <config_files>" line per candidate. A candidate passes only if ALL hold:
#   - `docker compose -p portcullis-<instance> ps -aq` (run from /, outside
#     any compose file) lists it;
#   - compose created it from the Hub's override for that instance: its
#     com.docker.compose.project.config_files names
#     /data/overrides/<instance>.override.yml (HUB_DATA_DIR in the Hub);
#   - its compose service is the one that override gives the alias to on
#     portcullis-proxy (the manifest's `service` of that companion, read
#     from hub_data by a throwaway read-only helper; no override, or no
#     service with that alias = flagged);
#   - no other container answers to the same alias.
# Residual (outside the threat model): all of this reads labels and
# membership Docker reports, and anyone with Docker access can create a
# container with forged compose labels (and could do far worse). The Hub
# refuses `com.docker.compose.*` labels in templates and custom overrides
# and names the projects itself, so without Docker access no app can
# claim another instance's project, override or service.
_proxy_ai_alias_check() {
  local mcp="$1" cache rc=0 cid cname alias inst svc files want
  cache="$(mktemp -d)" || return 2
  while read -r cid cname alias inst svc files; do
    [ -n "$cid" ] || continue
    if [ ! -e "$cache/$inst.members" ]; then
      (cd / && env -u COMPOSE_FILE docker compose -p "portcullis-$inst" ps -aq) > "$cache/$inst.members" 2>/dev/null || { rc=2; break; }
      local st=0 vol="${COMPOSE_PROJECT_NAME:-portcullis}_hub_data"
      # Never create the volume (compose would then refuse to own it):
      # no hub_data = no override.
      if ! docker volume inspect "$vol" >/dev/null 2>&1; then
        docker volume ls -q > "$cache/volumes" 2>/dev/null || { rc=2; break; }
        ! grep -qxF -- "$vol" "$cache/volumes" || { rc=2; break; }
        st=3
      else docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
        --user "$CT_UID_HUB:$CT_UID_HUB" -v "$vol:/d:ro" "$PORTCULLIS_HELPER_IMAGE" \
        sh -c '[ -f "$1" ] || exit 3; cat "$1"' _ "/d/overrides/$inst.override.yml" > "$cache/$inst.override" 2>/dev/null || st=$?
      fi
      case "$st" in 0) ;; 3) : > "$cache/$inst.override"; touch "$cache/$inst.nooverride" ;; *) rc=2; break ;; esac
    fi
    if ! grep -qxF -- "$cid" "$cache/$inst.members"; then
      printf '%s %s (AI companion name outside project portcullis-%s)\n' "$cname" "$alias" "$inst"
    elif ! printf '%s\n' "$files" | tr ',' '\n' | grep -qxF -- "/data/overrides/$inst.override.yml"; then
      printf '%s %s (AI companion name on a container the Hub did not create)\n' "$cname" "$alias"
    elif [ -e "$cache/$inst.nooverride" ]; then
      printf '%s %s (AI companion name with no Hub override for instance %s)\n' "$cname" "$alias" "$inst"
    else
      want="$(_override_alias_services "$alias" < "$cache/$inst.override")"
      if [ "$(printf '%s\n' "$want" | grep -c .)" != 1 ] || [ "$want" != "$svc" ]; then
        printf '%s %s (AI companion name on service %s, not the companion'"'"'s service)\n' "$cname" "$alias" "$svc"
      elif [ "$(printf '%s' "$mcp" | awk -v a="$alias" '$3 == a' | wc -l)" -gt 1 ]; then
        printf '%s %s (AI companion name answered by more than one container)\n' "$cname" "$alias"
      fi
    fi
  done <<< "$mcp"
  rm -rf "$cache"
  return "$rc"
}

# _override_alias_services <alias> — reads a Hub override (stdin): every
# service whose portcullis-proxy aliases list <alias> (the Hub writes
# services at 2 spaces, networks at 6, `aliases:` at 8 and the JSON-quoted
# items at 10).
_override_alias_services() {
  awk -v a="$1" '
    { match($0, /[^ ]/); ind = RSTART - 1; line = substr($0, ind + 1) }
    /^[^ ]/ { ins = ($0 == "services:"); svc = ""; net = ""; al = 0; next }
    !ins || line == "" { next }
    ind == 2 { svc = line; sub(/:$/, "", svc); gsub(/^"|"$/, "", svc); net = ""; al = 0; next }
    ind == 6 { net = line; sub(/:.*$/, "", net); gsub(/^"|"$/, "", net); al = 0; next }
    ind == 8 { al = (net == "portcullis-proxy" && line == "aliases:"); next }
    ind < 10 { al = 0; next }
    ind == 10 && al && substr(line, 1, 2) == "- " {
      v = substr(line, 3); gsub(/^"|"$/, "", v); if (v == a) print svc
    }'
}

# network_state <name> <subnet> <range> — prints one of: missing | ok |
# mismatch | unknown ("mismatch" = network exists without the expected IPAM
# subnet/ip_range, e.g. after editing the settings in .env; Docker can't
# change IPAM in place; "unknown" = the range can't be read: refused too).
# Docker: the compat inspect's Subnet and IPRange. Rootless Podman: its
# Docker-compatible inspect never reports IPRange (it keeps the range as a
# lease range: compat create maps ip_range <cidr> to first+1 .. last), so
# the subnet comes from that inspect and the range from the host's
# `podman network inspect` (libpod: subnets[].lease_range), which must be
# exactly the expected one (and absent when none is expected).
network_state() {
  local config cur_subnet cur_range
  if ! config="$(docker network inspect "$1" --format '{{json .IPAM.Config}}' 2>/dev/null)"; then
    echo missing
    return 0
  fi
  cur_subnet="$(printf '%s' "$config" | jq -r '.[0].Subnet // ""')"
  if _rt_is_podman; then
    [ "$cur_subnet" = "$2" ] || { echo mismatch; return 0; }
    _podman_lease_state "$1" "$2" "$3"
    return 0
  fi
  # IPRange is optional; treat unset, empty, or "invalid Prefix" (Docker 29+) as no range.
  cur_range="$(printf '%s' "$config" | jq -r '.[0].IPRange // "" | if . == "invalid Prefix" or . == "" then "" else . end')"
  if [ "$cur_subnet" = "$2" ] && [ "$cur_range" = "$3" ]; then
    echo ok
  else
    echo mismatch
  fi
}

# _podman_lease_state <name> <subnet> <range> — ok | mismatch | unknown:
# the libpod lease range of <subnet> against <range> (Podman's compat
# create: start = the range's first address + 1 (itself for a /32), end =
# its last address).
_podman_lease_state() {
  local j got want="" first last start
  if ! j="$(podman network inspect "$1" --format json 2>/dev/null)"; then echo unknown; return 0; fi
  got="$(printf '%s' "$j" | jq -r --arg s "$2" '
      [.[0].subnets[]? | select(.subnet == $s)]
      | if length != 1 then "no-such-subnet"
        else (.[0].lease_range // null) | if . == null then "" else "\(.start_ip // "")-\(.end_ip // "")" end end' 2>/dev/null)" \
    || { echo unknown; return 0; }
  if [ -n "$3" ]; then
    read -r first last <<< "$(cidr_bounds "$3")" || { echo unknown; return 0; }
    [ -n "$last" ] || { echo unknown; return 0; }
    start=$(( first == last ? first : first + 1 ))
    want="$(int_to_ip "$start")-$(int_to_ip "$last")"
  fi
  if [ "$got" = "$want" ]; then echo ok; else echo mismatch; fi
}

proxy_network_state() { network_state "$PROXY_NETWORK" "$(proxy_subnet)" "$(proxy_ip_range)"; }
auth_network_state()  { network_state "$AUTH_NETWORK" "$(auth_subnet)" "$(auth_ip_range)"; }
domains_network_state() { network_state "$DOMAINS_NETWORK" "$(domains_subnet)" ""; }
mcp_network_state()   { network_state "$MCP_NETWORK" "$(mcp_subnet)" "$(mcp_ip_range)"; }
vpn_network_state()   { network_state "$VPN_NETWORK" "$(vpn_net)" "$(vpn_ip_range)"; }
vpn_edge_network_state() { network_state "$VPN_EDGE_NETWORK" "$(vpn_edge_subnet)" "$(vpn_edge_ip_range)"; }

# network_check — validate the .env settings and refuse to continue if the
# existing network does not match them (compose would silently keep the old
# one and Traefik would not get its static IP).
network_check() {
  local err st
  err="$(validate_proxy_network_config)" || fail "Invalid portcullis-proxy settings in .env: $err"
  err="$(validate_mcp_gate_ip)" || fail "Invalid mcp-gate address in .env: $err"
  err="$(validate_auth_network_config)" || fail "Invalid portcullis-auth settings in .env: $err"
  err="$(validate_domains_network_config)" || fail "Invalid portcullis-domains settings in .env: $err"
  err="$(validate_mcp_network_config)" || fail "Invalid portcullis-mcp settings in .env: $err"
  err="$(validate_vpn_network_config)" || fail "Invalid portcullis-vpn settings in .env: $err"
  err="$(validate_vpn_edge_network_config)" || fail "Invalid portcullis-vpn-edge settings in .env: $err"
  st="$(proxy_network_state)"
  [ "$st" != unknown ] || fail "can't read the IP range of $PROXY_NETWORK (podman network inspect failed): refusing to go on unverified"
  if [ "$st" = mismatch ]; then
    fail "Docker network $PROXY_NETWORK exists with a different IPAM config than .env
       ($(proxy_subnet), range $(proxy_ip_range)). Docker cannot change it in place:
       disable the apps in the Hub, run ./portcullis down, then
       docker network rm $PROXY_NETWORK && ./portcullis up"
  fi
  st="$(auth_network_state)"
  [ "$st" != unknown ] || fail "can't read the IP range of $AUTH_NETWORK (podman network inspect failed): refusing to go on unverified"
  if [ "$st" = mismatch ]; then
    fail "Docker network $AUTH_NETWORK exists with a different IPAM config than .env
       ($(auth_subnet), range $(auth_ip_range)). Only core services use it:
       ./portcullis down && ./portcullis up recreates it."
  fi
  st="$(domains_network_state)"
  [ "$st" != unknown ] || fail "can't read the IP range of $DOMAINS_NETWORK (podman network inspect failed): refusing to go on unverified"
  if [ "$st" = mismatch ]; then
    fail "Docker network $DOMAINS_NETWORK exists with a different subnet than
       PORTCULLIS_DOMAINS_SUBNET=$(domains_subnet) (the domains API would refuse the Hub).
       Only the Hub and domains use it: ./portcullis down && ./portcullis up recreates it."
  fi
  st="$(mcp_network_state)"
  [ "$st" != unknown ] || fail "can't read the IP range of $MCP_NETWORK (podman network inspect failed): refusing to go on unverified"
  if [ "$st" = mismatch ]; then
    fail "Docker network $MCP_NETWORK exists with a different IPAM config than .env
       ($(mcp_subnet), range $(mcp_ip_range)). Only mcp-gate, Keycloak and the Hub use it:
       ./portcullis down && ./portcullis up recreates it."
  fi
  st="$(vpn_network_state)"
  [ "$st" != unknown ] || fail "can't read the IP range of $VPN_NETWORK (podman network inspect failed): refusing to go on unverified"
  if [ "$st" = mismatch ]; then
    fail "Docker network $VPN_NETWORK exists with a different IPAM config than .env
       ($(vpn_net), range $(vpn_ip_range)). Wired VPN gateways join it: unwire the
       VPN providers in the Hub, run ./portcullis down, then
       docker network rm $VPN_NETWORK && ./portcullis up"
  fi
  st="$(vpn_edge_network_state)"
  [ "$st" != unknown ] || fail "can't read the IP range of $VPN_EDGE_NETWORK (podman network inspect failed): refusing to go on unverified"
  if [ "$st" = mismatch ]; then
    fail "Docker network $VPN_EDGE_NETWORK exists with a different IPAM config than .env
       ($(vpn_edge_subnet), range $(vpn_edge_ip_range)). Only wg and Traefik use it:
       ./portcullis down && ./portcullis up recreates it."
  fi
  local shadows
  shadows="$(proxy_dns_shadows)" || fail "could not inspect the containers on $PROXY_NETWORK (docker error): refusing to go on without the core-name check"
  if [ -n "$shadows" ]; then
    fail "containers on $PROXY_NETWORK answer to core service or AI companion names
       (a core service or mcp-gate resolving that name could reach them instead):
$(printf '%s\n' "$shadows" | sed 's/^\([^ ]*\) \(.*\)$/         \1 answers to "\2"/')
       Disable those apps in the Hub (or remove the containers), then run this again."
  fi
}

# ── Public address detection (dns setup, the domains service's records) ──
#
# The detected address becomes A/AAAA records, so detection fails closed:
# HTTPS only (TLS ≥ 1.2, no redirects to http), at least two independent
# services must answer and all answers must agree, and the address must be
# global unicast. Anything else prints nothing (and the caller publishes no
# record). An explicit PORTCULLIS_PUBLIC_IPV4 / _IPV6 always wins (callers).
PUBLIC_IP_SERVICES_4="https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip"
PUBLIC_IP_SERVICES_6="https://api6.ipify.org https://ipv6.icanhazip.com https://ifconfig.me/ip"

# ipv4_is_global <a.b.c.d> — not private, shared, loopback, link-local,
# documentation, benchmark, multicast or reserved.
ipv4_is_global() {
  local n c
  n="$(ip_to_int "$1")" || return 1
  for c in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 \
           192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
    ! cidr_contains "$c" "$1" || return 1
  done
}

# ipv6_is_global <addr> — inside 2000::/3 (global unicast), outside the
# IANA special-purpose 2001::/23 (Teredo, benchmarking, ORCHID, ...) and
# documentation 2001:db8::/32.
ipv6_is_global() {
  local ip h1 rest h2 v
  ip="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  [[ "$ip" =~ ^[0-9a-f:]+$ ]] && [[ "$ip" == *:* ]] && [ "${#ip}" -le 39 ] || return 1
  [[ "$ip" != *:::* ]] || return 1
  case "$ip" in *::*::*) return 1 ;; esac
  h1="${ip%%:*}"; rest="${ip#*:}"; h2="${rest%%:*}"
  [ -n "$h1" ] && [ "${#h1}" -le 4 ] || return 1
  v=$(( 16#$h1 ))
  [ $(( v & 0xE000 )) -eq $(( 0x2000 )) ] || return 1
  # 3fff::/20 documentation (RFC 9637).
  [ "$v" -ne $(( 0x3fff )) ] || return 1
  if [ "$v" -eq $(( 0x2001 )) ]; then
    [ -n "$h2" ] || return 1
    [ $(( 16#$h2 )) -ge $(( 0x200 )) ] || return 1
    [ $(( 16#$h2 )) -ne $(( 0xdb8 )) ] || return 1
  fi
}

# public_ip_detect <4|6> — the host's public address, or nothing.
public_ip_detect() {
  local fam="$1" svc out got="" n=0 services
  if [ "$fam" = 4 ]; then services="$PUBLIC_IP_SERVICES_4"; else services="$PUBLIC_IP_SERVICES_6"; fi
  for svc in $services; do
    out="$(curl "-$fam" --proto '=https' --tlsv1.2 -sf --max-time 5 "$svc" 2>/dev/null | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" || continue
    [ -n "$out" ] || continue
    if [ "$fam" = 4 ]; then ipv4_is_global "$out" || return 0; else ipv6_is_global "$out" || return 0; fi
    if [ -z "$got" ]; then got="$out"; elif [ "$got" != "$out" ]; then return 0; fi
    n=$((n + 1))
  done
  [ "$n" -ge 2 ] || return 0
  printf '%s' "$got"
}
