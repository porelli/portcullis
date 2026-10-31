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
#   PORTCULLIS_AUTH_SUBNET     default 172.31.251.0/28
#   PORTCULLIS_AUTH_IP_RANGE   default 172.31.251.8/29
#   PORTCULLIS_AUTH_TRAEFIK_IP default 172.31.251.2

PROXY_NETWORK="${PROXY_NETWORK:-portcullis-proxy}"
AUTH_NETWORK="${AUTH_NETWORK:-portcullis-auth}"

proxy_subnet()   { echo "${PORTCULLIS_PROXY_SUBNET:-172.31.250.0/24}"; }
proxy_ip_range() { echo "${PORTCULLIS_PROXY_IP_RANGE:-172.31.250.128/25}"; }
proxy_traefik_ip() { echo "${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}"; }
auth_subnet()    { echo "${PORTCULLIS_AUTH_SUBNET:-172.31.251.0/28}"; }
auth_ip_range()  { echo "${PORTCULLIS_AUTH_IP_RANGE:-172.31.251.8/29}"; }
auth_traefik_ip() { echo "${PORTCULLIS_AUTH_TRAEFIK_IP:-172.31.251.2}"; }

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

# network_state <name> <subnet> <range> — prints one of: missing | ok | mismatch
# ("mismatch" = network exists without the expected IPAM subnet/ip_range,
# e.g. after editing the settings in .env; Docker can't change IPAM in place).
network_state() {
  local cur
  if ! cur="$(docker network inspect "$1" --format '{{range .IPAM.Config}}{{.Subnet}}|{{.IPRange}};{{end}}' 2>/dev/null)"; then
    echo missing
    return 0
  fi
  if [ "$cur" = "$2|$3;" ]; then
    echo ok
  else
    echo mismatch
  fi
}

proxy_network_state() { network_state "$PROXY_NETWORK" "$(proxy_subnet)" "$(proxy_ip_range)"; }
auth_network_state()  { network_state "$AUTH_NETWORK" "$(auth_subnet)" "$(auth_ip_range)"; }

# network_check — validate the .env settings and refuse to continue if the
# existing network does not match them (compose would silently keep the old
# one and Traefik would not get its static IP).
network_check() {
  local err
  err="$(validate_proxy_network_config)" || fail "Invalid portcullis-proxy settings in .env: $err"
  err="$(validate_auth_network_config)" || fail "Invalid portcullis-auth settings in .env: $err"
  if [ "$(proxy_network_state)" = mismatch ]; then
    fail "Docker network $PROXY_NETWORK exists with a different IPAM config than .env
       ($(proxy_subnet), range $(proxy_ip_range)). Docker cannot change it in place:
       disable the apps in the Hub, run ./portcullis down, then
       docker network rm $PROXY_NETWORK && ./portcullis up"
  fi
  if [ "$(auth_network_state)" = mismatch ]; then
    fail "Docker network $AUTH_NETWORK exists with a different IPAM config than .env
       ($(auth_subnet), range $(auth_ip_range)). Only core services use it:
       ./portcullis down && ./portcullis up recreates it."
  fi
}
