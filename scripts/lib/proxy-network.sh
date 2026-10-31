# shellcheck shell=bash
#
# Helpers for the shared `portcullis-proxy` Docker network (fixed IPAM,
# static Traefik IP). Source, don't execute. Used by upgrade.sh and
# bootstrap.sh; unit-tested by tests/test_shell_libs.sh with a stub
# `docker` on PATH.
#
# Inputs (env, with the same defaults as docker-compose.yml):
#   PORTCULLIS_PROXY_SUBNET    default 172.31.250.0/24
#   PORTCULLIS_PROXY_IP_RANGE  default 172.31.250.128/25
#   PORTCULLIS_TRAEFIK_IP      default 172.31.250.2

PROXY_NETWORK="${PROXY_NETWORK:-portcullis-proxy}"
CORE_PROJECT="${CORE_PROJECT:-portcullis}"

_pn_log()  { if declare -F info >/dev/null; then info "$@"; else echo "==> $*"; fi; }
_pn_warn() { if declare -F warn >/dev/null; then warn "$@"; else echo "WARNING: $*" >&2; fi; }

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
# e.g. created by an older Portcullis; Docker can't change IPAM in place).
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

# _pn_aliases <container> — network aliases to restore on reconnect: the
# existing aliases minus Docker's automatic short container ID, plus the
# compose service name.
_pn_aliases() {
  local cid="$1" short svc
  short="$(docker inspect --format '{{.Id}}' "$cid" 2>/dev/null | cut -c1-12)"
  svc="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$cid" 2>/dev/null || true)"
  {
    docker inspect --format "{{with index .NetworkSettings.Networks \"$PROXY_NETWORK\"}}{{range .Aliases}}{{println .}}{{end}}{{end}}" "$cid" 2>/dev/null || true
    [ -n "$svc" ] && echo "$svc"
  } | awk -v s="$short" 'NF && $0 != s && !seen[$0]++'
}

# _pn_is_core_traefik <project> <service> — Traefik of the core project is
# recreated by compose (static IP); every other member is reconnected,
# including core-project containers from docker-compose.apps.yml.
_pn_is_core_traefik() { [ "$1" = "$CORE_PROJECT" ] && [ "$2" = traefik ]; }

# proxy_network_reconnect <state-file> — (re)attach every recorded member
# except core Traefik to $PROXY_NETWORK, restoring aliases. Idempotent:
# already-connected containers are skipped. Returns 1 if any failed.
proxy_network_reconnect() {
  local state_file="$1" cid name project service aliases failed=0 a
  local -a args al
  while IFS=$'\t' read -r cid name project service aliases; do
    [ -n "$cid" ] || continue
    _pn_is_core_traefik "$project" "$service" && continue
    if docker inspect --format "{{with index .NetworkSettings.Networks \"$PROXY_NETWORK\"}}yes{{end}}" "$cid" 2>/dev/null | grep -q yes; then
      continue
    fi
    args=()
    if [ -n "$aliases" ]; then
      IFS=, read -ra al <<< "$aliases"
      for a in "${al[@]}"; do args+=(--alias "$a"); done
    fi
    if docker network connect ${args[@]+"${args[@]}"} "$PROXY_NETWORK" "$cid" >/dev/null 2>&1; then
      _pn_log "  reconnected $name"
    else
      _pn_warn "  could not reconnect $name (docker network connect $PROXY_NETWORK $name)"
      failed=1
    fi
  done < "$state_file"
  return "$failed"
}

# proxy_network_recovery_help <state-file> — exact manual recovery steps.
proxy_network_recovery_help() {
  local state_file="$1"
  cat >&2 <<EOF

  ── Manual recovery for $PROXY_NETWORK ─────────────────────────────
  Member list (container, name, project, service, aliases): $state_file
  1. Fix the error above, then (re)create the network + Traefik:
       docker compose up -d --no-deps --force-recreate traefik
  2. Reconnect the app containers:
       bash -c 'source scripts/lib/proxy-network.sh && proxy_network_reconnect "$state_file"'
     (or re-enable each app in the Hub)
  3. Re-run ./scripts/upgrade.sh
  ───────────────────────────────────────────────────────────────────
EOF
}

# proxy_network_migrate <state-file> [dry-run]
#
# Recreate portcullis-proxy with the fixed IPAM config:
#   1. record every container attached to it (running or stopped) with its
#      compose project/service and aliases into <state-file>
#   2. disconnect them all (app containers keep running; they only lose the
#      routing plane for a few seconds)
#   3. remove the network and let compose recreate it by force-recreating
#      Traefik (which also gets its static IP)
#   4. reconnect every member except core Traefik
# Failure handling — members are reconnected on every path:
#   - `network rm` fails  → reconnect to the OLD network, return 1
#   - `compose up` fails  → if compose still created the network, reconnect
#                           to it; return 1 either way (+ recovery help)
# Returns 0 only if everything succeeded.
proxy_network_migrate() {
  local state_file="$1" dry_run="${2:-false}" cid name project service aliases
  _pn_log "Recreating Docker network $PROXY_NETWORK with subnet $(proxy_subnet), dynamic range $(proxy_ip_range), Traefik at $(proxy_traefik_ip)."

  : > "$state_file"
  while read -r cid; do
    [ -n "$cid" ] || continue
    name="$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's#^/##')"
    project="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$cid" 2>/dev/null || true)"
    service="$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$cid" 2>/dev/null || true)"
    aliases="$(_pn_aliases "$cid" | paste -sd, -)"
    printf '%s\t%s\t%s\t%s\t%s\n' "$cid" "$name" "$project" "$service" "$aliases" >> "$state_file"
  done < <(docker ps -aq --no-trunc --filter "network=$PROXY_NETWORK")

  if [ -s "$state_file" ]; then
    _pn_log "Containers attached to $PROXY_NETWORK (saved to $state_file):"
    awk -F'\t' '{printf "      %s (project %s)\n", $2, ($3 == "" ? "-" : $3)}' "$state_file"
  fi

  if [ "$dry_run" = true ]; then
    echo "  Would disconnect the containers above, run: docker network rm $PROXY_NETWORK"
    echo "  Would run: docker compose up -d --no-deps --force-recreate traefik   (recreates the network + Traefik static IP)"
    echo "  Would reconnect all containers above except core Traefik, with their aliases"
    return 0
  fi

  while IFS=$'\t' read -r cid name project service aliases; do
    docker network disconnect -f "$PROXY_NETWORK" "$cid" >/dev/null 2>&1 \
      || _pn_warn "could not disconnect $name (continuing)"
  done < "$state_file"

  if ! docker network rm "$PROXY_NETWORK" >/dev/null; then
    _pn_warn "docker network rm $PROXY_NETWORK failed — reconnecting containers to the OLD network."
    proxy_network_reconnect "$state_file" || true
    # Core Traefik was disconnected too; give it back its old attachment.
    while IFS=$'\t' read -r cid name project service aliases; do
      _pn_is_core_traefik "$project" "$service" && docker network connect "$PROXY_NETWORK" "$cid" >/dev/null 2>&1 || true
    done < "$state_file"
    proxy_network_recovery_help "$state_file"
    return 1
  fi

  if ! docker compose up -d --no-deps --force-recreate traefik; then
    if docker network inspect "$PROXY_NETWORK" >/dev/null 2>&1; then
      _pn_warn "Traefik failed to start, but $PROXY_NETWORK exists — reconnecting app containers."
      proxy_network_reconnect "$state_file" || true
    else
      _pn_warn "Traefik failed to start and $PROXY_NETWORK was not recreated — app containers are DISCONNECTED."
    fi
    proxy_network_recovery_help "$state_file"
    return 1
  fi

  if ! proxy_network_reconnect "$state_file"; then
    proxy_network_recovery_help "$state_file"
    return 1
  fi
  return 0
}
