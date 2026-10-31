# shellcheck shell=bash
#
# Helpers for the shared `portcullis-proxy` Docker network (fixed IPAM,
# static Traefik IP): validation of the .env settings and a guard against an
# existing network with a different IPAM config. Sourced by ./portcullis;
# unit-tested by tests/test_shell_libs.sh with a stub `docker` on PATH.
#
# Inputs (env, with the same defaults as docker-compose.yml):
#   PORTCULLIS_PROXY_SUBNET    default 172.31.250.0/24
#   PORTCULLIS_PROXY_IP_RANGE  default 172.31.250.128/25
#   PORTCULLIS_TRAEFIK_IP      default 172.31.250.2

PROXY_NETWORK="${PROXY_NETWORK:-portcullis-proxy}"

proxy_subnet()   { echo "${PORTCULLIS_PROXY_SUBNET:-172.31.250.0/24}"; }
proxy_ip_range() { echo "${PORTCULLIS_PROXY_IP_RANGE:-172.31.250.128/25}"; }
proxy_traefik_ip() { echo "${PORTCULLIS_TRAEFIK_IP:-172.31.250.2}"; }

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

# validate_proxy_network_config — check the three settings are coherent.
# Prints a reason and returns 1 on error.
validate_proxy_network_config() {
  local subnet range ip sf sl rf rl
  subnet="$(proxy_subnet)"; range="$(proxy_ip_range)"; ip="$(proxy_traefik_ip)"
  read -r sf sl <<< "$(cidr_bounds "$subnet" 2>/dev/null)" || true
  [ -n "${sf:-}" ] || { echo "PORTCULLIS_PROXY_SUBNET=$subnet is not a valid IPv4 CIDR"; return 1; }
  read -r rf rl <<< "$(cidr_bounds "$range" 2>/dev/null)" || true
  [ -n "${rf:-}" ] || { echo "PORTCULLIS_PROXY_IP_RANGE=$range is not a valid IPv4 CIDR"; return 1; }
  ip_to_int "$ip" >/dev/null || { echo "PORTCULLIS_TRAEFIK_IP=$ip is not a valid IPv4 address"; return 1; }
  { [ "$rf" -ge "$sf" ] && [ "$rl" -le "$sl" ]; } || { echo "PORTCULLIS_PROXY_IP_RANGE=$range is not inside PORTCULLIS_PROXY_SUBNET=$subnet"; return 1; }
  cidr_contains "$subnet" "$ip" || { echo "PORTCULLIS_TRAEFIK_IP=$ip is not inside PORTCULLIS_PROXY_SUBNET=$subnet"; return 1; }
  if cidr_contains "$range" "$ip"; then
    echo "PORTCULLIS_TRAEFIK_IP=$ip is inside the dynamic range PORTCULLIS_PROXY_IP_RANGE=$range (another container could take it)"
    return 1
  fi
  # The first address is the bridge gateway, network/broadcast are unusable.
  local n; n="$(ip_to_int "$ip")"
  { [ "$n" -gt $((sf + 1)) ] && [ "$n" -lt "$sl" ]; } || { echo "PORTCULLIS_TRAEFIK_IP=$ip collides with the network/gateway/broadcast address"; return 1; }
  return 0
}

# proxy_network_state — prints one of: missing | ok | mismatch
# ("mismatch" = network exists without the expected IPAM subnet/ip_range,
# e.g. after editing the settings in .env; Docker can't change IPAM in place).
proxy_network_state() {
  local cur
  if ! cur="$(docker network inspect "$PROXY_NETWORK" --format '{{range .IPAM.Config}}{{.Subnet}}|{{.IPRange}};{{end}}' 2>/dev/null)"; then
    echo missing
    return 0
  fi
  if [ "$cur" = "$(proxy_subnet)|$(proxy_ip_range);" ]; then
    echo ok
  else
    echo mismatch
  fi
}

# network_check — validate the .env settings and refuse to continue if the
# existing network does not match them (compose would silently keep the old
# one and Traefik would not get its static IP).
network_check() {
  local err
  err="$(validate_proxy_network_config)" || fail "Invalid portcullis-proxy settings in .env: $err"
  if [ "$(proxy_network_state)" = mismatch ]; then
    fail "Docker network $PROXY_NETWORK exists with a different IPAM config than .env
       ($(proxy_subnet), range $(proxy_ip_range)). Docker cannot change it in place:
       disable the apps in the Hub, run ./portcullis down, then
       docker network rm $PROXY_NETWORK && ./portcullis up"
  fi
}
