# shellcheck shell=bash
#
# The container runtime behind every docker / docker compose call:
# CONTAINER_RUNTIME=docker (rootful Docker) or podman (rootless Podman, its
# Docker-compatible API on the operator's user socket). Chosen by `init`,
# written to .env and never switched (backup → fresh init → restore). There
# is no default: a missing or unknown value is refused.
#
# Sourced at the end of common.sh (so every caller of common.sh has it).
#
# Overridable for tests:
#   RT_DOCKER_SOCK       the rootful Docker socket (default /var/run/docker.sock)
#   RT_PROC_PORT_START   the ip_unprivileged_port_start sysctl file
#   RT_CGROUP_ROOT       the cgroup v2 mount (default /sys/fs/cgroup)

RT_PODMAN_MIN="5.4"
RT_PORT_START_MAX=80
RT_MIN_IDS=65536

# runtime_name — docker|podman from CONTAINER_RUNTIME; anything else fails.
runtime_name() {
  case "${CONTAINER_RUNTIME:-}" in
    docker|podman) printf '%s\n' "$CONTAINER_RUNTIME" ;;
    "") fail "CONTAINER_RUNTIME is not set in .env (docker or podman): ./portcullis init writes it; an install from before rootless support adds CONTAINER_RUNTIME=docker by hand" ;;
    *) fail "CONTAINER_RUNTIME=$CONTAINER_RUNTIME is neither docker nor podman (.env)" ;;
  esac
}

# runtime_podman_socket — the operator's rootless Podman API socket. Without
# XDG_RUNTIME_DIR (sudo -u, cron, a systemd unit) it is derived from the uid.
runtime_podman_socket() {
  printf '%s/podman/podman.sock\n' "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
}

# _rt_is_podman — true under CONTAINER_RUNTIME=podman (fails on a bad value).
_rt_is_podman() {
  local rt
  rt="$(runtime_name)" || exit 1
  [ "$rt" = podman ]
}

# _rt_engine_probe [docker-host] — ask the engine's /version. Sets
# _RT_ENGINE (docker|podman|unknown) and _RT_ENGINE_VERSION; returns 1 when
# nothing answers.
_rt_engine_probe() {
  local comps out
  _RT_ENGINE="" _RT_ENGINE_VERSION=""
  if [ -n "${1:-}" ]; then
    comps="$(DOCKER_HOST="$1" docker version --format '{{json .Server.Components}}' 2>/dev/null)" || return 1
  else
    comps="$(docker version --format '{{json .Server.Components}}' 2>/dev/null)" || return 1
  fi
  out="$(printf '%s' "$comps" | jq -r '
      if type != "array" then error("no components")
      elif any(.[]; .Name == "Podman Engine") then "podman\t" + ([.[] | select(.Name == "Podman Engine") | .Version][0] // "")
      elif any(.[]; .Name == "Engine") then "docker\t" + ([.[] | select(.Name == "Engine") | .Version][0] // "")
      else "unknown\t" end' 2>/dev/null)" || return 1
  [ -n "$out" ] || return 1
  IFS=$'\t' read -r _RT_ENGINE _RT_ENGINE_VERSION <<< "$out"
}

# _rt_engine_label <docker|podman|unknown> — the engine as /version names it.
_rt_engine_label() {
  case "$1" in
    podman) echo "Podman Engine" ;;
    docker) echo "Docker Engine" ;;
    *) echo "an unknown engine" ;;
  esac
}

_rt_prep_hints() {
  cat <<EOF
no container engine answers: pass --runtime docker|podman, or prepare the host first:
  Docker: Docker Engine with the compose plugin, the operator in the docker group
  rootless Podman >= $RT_PODMAN_MIN (as the dedicated unprivileged operator): podman, passt,
    uidmap and the Docker CLI with the compose plugin; >= $RT_MIN_IDS ids in /etc/subuid and
    /etc/subgid; sudo loginctl enable-linger <user>;
    systemctl --user enable --now podman.socket podman-restart.service;
    sysctl net.ipv4.ip_unprivileged_port_start=$RT_PORT_START_MAX (sysctl.d)
  (docs: operations/rootless-podman)
EOF
}

# runtime_detect [docker|podman] — the runtime for a new install: the flag
# or CONTAINER_RUNTIME, else a Docker engine on the rootful socket (or
# DOCKER_HOST) without a Podman component, else rootless Podman answering
# on the user socket. Docker wins when both answer. Root with podman is
# refused (rootless only). Prints docker|podman; exit 1 with the host-prep
# hints otherwise.
runtime_detect() {
  local want="${1:-${CONTAINER_RUNTIME:-}}" sock
  case "$want" in
    docker) echo docker; return 0 ;;
    podman)
      if [ "$(id -u)" = 0 ]; then
        echo "podman as root is not supported: Portcullis runs rootless Podman only (as a dedicated unprivileged user)" >&2
        return 1
      fi
      echo podman; return 0 ;;
    "") ;;
    *) echo "the container runtime must be docker or podman (got '$want')" >&2; return 1 ;;
  esac
  if [ -n "${DOCKER_HOST:-}" ]; then
    if _rt_engine_probe && [ "$_RT_ENGINE" = docker ]; then echo docker; return 0; fi
  elif [ -S "${RT_DOCKER_SOCK:-/var/run/docker.sock}" ]; then
    if _rt_engine_probe "unix://${RT_DOCKER_SOCK:-/var/run/docker.sock}" && [ "$_RT_ENGINE" = docker ]; then echo docker; return 0; fi
  fi
  if command -v podman >/dev/null 2>&1; then
    if [ "$(id -u)" = 0 ]; then
      echo "podman as root is not supported: Portcullis runs rootless Podman only (as a dedicated unprivileged user)" >&2
      return 1
    fi
    sock="$(runtime_podman_socket)"
    if [ -S "$sock" ] && _rt_engine_probe "unix://$sock" && [ "$_RT_ENGINE" = podman ]; then
      echo podman; return 0
    fi
  fi
  _rt_prep_hints >&2
  return 1
}

# _rt_selinux_enforcing — SELinux is present and enforcing.
_rt_selinux_enforcing() {
  command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = Enforcing ]
}

# runtime_export — under podman: DOCKER_HOST=unix://<user socket> for every
# docker / docker compose call (a different DOCKER_HOST is refused), and the
# podman overlays added to COMPOSE_FILE: docker-compose.podman.yml always
# (restart: always, the policy podman-restart.service starts at boot), and
# on an SELinux-enforcing host docker-compose.podman-selinux.yml. The list is
# the current COMPOSE_FILE, or docker-compose.yml plus
# docker-compose.override.yml when it exists (compose stops auto-loading
# the override once COMPOSE_FILE is set), without duplicates; the entries
# added here are absolute (compose resolves COMPOSE_FILE against the
# working directory, not --project-directory). Docker: no-op.
runtime_export() {
  local sock files f
  local -a add
  # Podman's address pools (10.88.0.0/16, its default network, and the
  # pinned 10.89.0.0/16): reserved against VPN provider ranges by wg and
  # group-gate (compose appends them to WG_CORE_SUBNETS / GATE_CORE_SUBNETS)
  # and by the Hub (vpn_reserved_ranges). Never taken from outside.
  export PORTCULLIS_VPN_RUNTIME_POOLS=""
  _rt_is_podman || return 0
  export PORTCULLIS_VPN_RUNTIME_POOLS="$RT_PODMAN_POOLS"
  sock="$(runtime_podman_socket)"
  if [ -n "${DOCKER_HOST:-}" ] && [ "$DOCKER_HOST" != "unix://$sock" ]; then
    fail "DOCKER_HOST=$DOCKER_HOST, but CONTAINER_RUNTIME=podman talks to unix://$sock: unset DOCKER_HOST"
  fi
  export DOCKER_HOST="unix://$sock"
  add=("$PORTCULLIS_HOME/docker-compose.podman.yml")
  if _rt_selinux_enforcing; then add+=("$PORTCULLIS_HOME/docker-compose.podman-selinux.yml"); fi
  files="${COMPOSE_FILE:-}"
  if [ -z "$files" ]; then
    files="$PORTCULLIS_ROOT/docker-compose.yml"
    [ ! -f "$PORTCULLIS_ROOT/docker-compose.override.yml" ] || files="$files:$PORTCULLIS_ROOT/docker-compose.override.yml"
  fi
  for f in "${add[@]}"; do
    case ":$files:" in *":$f:"*|*":${f##*/}:"*) ;; *) files="$files:$f" ;; esac
  done
  export COMPOSE_FILE="$files"
}

# runtime_check — once per run: CONTAINER_RUNTIME is valid, runtime_export,
# the engine answers and is the one CONTAINER_RUNTIME names; under podman
# PORTCULLIS_ENGINE_SOCKET is the user socket (a socket); under docker a set
# PORTCULLIS_ENGINE_SOCKET must be a socket.
runtime_check() {
  [ -z "${_RT_CHECKED:-}" ] || return 0
  local rt sock
  rt="$(runtime_name)" || exit 1
  runtime_export
  _rt_engine_probe || fail "the container engine doesn't answer (CONTAINER_RUNTIME=$rt, DOCKER_HOST=${DOCKER_HOST:-unset}): start it, or check the socket"
  [ "$_RT_ENGINE" = "$rt" ] || fail "CONTAINER_RUNTIME=$rt but the engine is $(_rt_engine_label "$_RT_ENGINE")${DOCKER_HOST:+ (DOCKER_HOST=$DOCKER_HOST)}"
  if [ "$rt" = podman ]; then
    sock="$(runtime_podman_socket)"
    [ -n "${PORTCULLIS_ENGINE_SOCKET:-}" ] || fail "PORTCULLIS_ENGINE_SOCKET is not set in .env (./portcullis init writes $sock)"
    [ "$PORTCULLIS_ENGINE_SOCKET" = "$sock" ] || fail "PORTCULLIS_ENGINE_SOCKET=$PORTCULLIS_ENGINE_SOCKET, but the rootless Podman socket is $sock"
    [ -S "$PORTCULLIS_ENGINE_SOCKET" ] || fail "PORTCULLIS_ENGINE_SOCKET=$PORTCULLIS_ENGINE_SOCKET is not a socket (systemctl --user enable --now podman.socket)"
  elif [ -n "${PORTCULLIS_ENGINE_SOCKET:-}" ]; then
    # Docker with a set socket: the proxies mount it, so it must be the
    # same kind of engine the CLI verified (never, e.g., a Podman socket).
    [ -S "$PORTCULLIS_ENGINE_SOCKET" ] || fail "PORTCULLIS_ENGINE_SOCKET=$PORTCULLIS_ENGINE_SOCKET is not a socket"
    _rt_engine_probe "unix://$PORTCULLIS_ENGINE_SOCKET" || fail "PORTCULLIS_ENGINE_SOCKET=$PORTCULLIS_ENGINE_SOCKET doesn't answer"
    [ "$_RT_ENGINE" = docker ] || fail "CONTAINER_RUNTIME=docker but PORTCULLIS_ENGINE_SOCKET=$PORTCULLIS_ENGINE_SOCKET is $(_rt_engine_label "$_RT_ENGINE")"
  fi
  _RT_CHECKED=1
}

# runtime_version — the engine's version (best effort, "" when it doesn't answer).
runtime_version() {
  _rt_engine_probe || return 0
  printf '%s\n' "$_RT_ENGINE_VERSION"
}

# _rt_map_norm — a uid_map / gid_map with its whitespace normalised.
_rt_map_norm() { awk 'NF { print $1 " " $2 " " $3 }'; }

# _rt_map_shape <map> <operator id> — "start count" for the one consistent
# shape (0 → the operator, 1… → one subordinate range of ≥ 65536 ids).
_rt_map_shape() {
  printf '%s\n' "$1" | awk -v op="$2" -v min="$RT_MIN_IDS" '
    NR == 1 { if ($1 != 0 || $2 != op || $3 != 1) bad = 1 }
    NR == 2 { if ($1 != 1 || $3 < min) bad = 1; s = $2; n = $3 }
    END { if (NR != 2 || bad) exit 1; print s " " n }'
}

# runtime_id_maps — the user namespace from `podman unshare`: sets _RT_UID_OP
# _RT_UID_START _RT_UID_N _RT_GID_OP _RT_GID_START _RT_GID_N. Returns 1 for
# an unreadable map, another shape, or fewer than 65536 subordinate ids.
runtime_id_maps() {
  local um gm u g
  um="$(podman unshare cat /proc/self/uid_map 2>/dev/null | _rt_map_norm)" || return 1
  gm="$(podman unshare cat /proc/self/gid_map 2>/dev/null | _rt_map_norm)" || return 1
  [ -n "$um" ] && [ -n "$gm" ] || return 1
  u="$(_rt_map_shape "$um" "$(id -u)")" || return 1
  g="$(_rt_map_shape "$gm" "$(id -g)")" || return 1
  _RT_UID_OP="$(id -u)" _RT_GID_OP="$(id -g)"
  read -r _RT_UID_START _RT_UID_N <<< "$u"
  read -r _RT_GID_START _RT_GID_N <<< "$g"
}

# runtime_port_start — net.ipv4.ip_unprivileged_port_start (missing or not a
# number: 1024, the kernel default).
runtime_port_start() {
  local v
  v="$(tr -d '[:space:]' < "${RT_PROC_PORT_START:-/proc/sys/net/ipv4/ip_unprivileged_port_start}" 2>/dev/null || true)"
  case "$v" in ''|*[!0-9]*) v=1024 ;; esac
  printf '%s\n' "$v"
}

# _ver_ge <a> <b> — version a >= b (dotted numbers; suffixes after the
# numbers ignored; an empty or non-numeric a is never >=).
_ver_ge() {
  local a="${1%%[!0-9.]*}" b="${2%%[!0-9.]*}" i x y
  [ -n "$a" ] || return 1
  local -a av bv
  IFS=. read -ra av <<< "$a"
  IFS=. read -ra bv <<< "$b"
  for ((i = 0; i < ${#bv[@]} || i < ${#av[@]}; i++)); do
    x="${av[i]:-0}" y="${bv[i]:-0}"
    x=$((10#${x:-0})) y=$((10#${y:-0}))
    [ "$x" -gt "$y" ] && return 0
    [ "$x" -lt "$y" ] && return 1
  done
  return 0
}

_rt_chk() { printf '%s\t%s\n' "$1" "$2"; }

# Podman's address pools, pinned (I3 ruling): every network Podman creates
# lies in its default network 10.88.0.0/16 or in 10.89.0.0/16 (/24s), both
# reserved against VPN provider ranges (vpn_reserved_ranges). Its stock
# pools reach 10.89–10.255.
RT_POOL_LINE='default_subnet_pools = [{"base" = "10.89.0.0/16", "size" = 24}]'
RT_PODMAN_POOLS="10.88.0.0/16 10.89.0.0/16"

# _rt_pool_check — one host-check line: where Podman really allocates
# networks (M5 ruling). A probe network is created, its subnet read and
# the network removed, so every config source counts ($CONTAINERS_CONF,
# $CONTAINERS_CONF_OVERRIDE, /etc/containers/containers.conf, the
# operator's file and drop-ins). Inside 10.89.0.0/16: ok. Outside (or no
# probe possible): fail with the wg profile on (VPN wiring relies on the
# reserved pools), warn with it off; the line to add is named either way.
_rt_pool_check() {
  local net="portcullis-pool-probe-$$" subnet="" why sev=warn
  case ",${COMPOSE_PROFILES:-}," in *,wg,*) sev=fail ;; esac
  if docker network create --label com.portcullis.pool-probe=1 "$net" >/dev/null 2>&1; then
    subnet="$(docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$net" 2>/dev/null | awk '{print $1}')"
    docker network rm "$net" >/dev/null 2>&1 || true
  fi
  # Inside 10.89.0.0/16: a 10.89.x.y network of /16 or longer.
  if [[ "$subnet" =~ ^10\.89\.[0-9]{1,3}\.[0-9]{1,3}/(1[6-9]|2[0-9]|3[0-2])$ ]]; then
    _rt_chk ok "Podman networks come from 10.89.0.0/16 (a probe network got $subnet)"
    return 0
  fi
  if [ -n "$subnet" ]; then why="a probe network got $subnet, outside 10.89.0.0/16"; else why="no probe network could be created"; fi
  _rt_chk "$sev" "Podman's network pool isn't pinned ($why; VPN provider ranges are kept out of 10.88.0.0/16 and 10.89.0.0/16 only): add under [network] in ${CONTAINERS_CONF_OVERRIDE:-${XDG_CONFIG_HOME:-$HOME/.config}/containers/containers.conf}: $RT_POOL_LINE"
}

# runtime_host_checks — the host preparation for rootless Podman, one
# "ok|warn|fail<TAB>text" line per item (fail = a † item: init, up,
# upgrade and restore refuse). Prints nothing under docker.
runtime_host_checks() {
  local uid user f ctl id lim lin u st pstart v um cm
  _rt_is_podman || return 0
  uid="$(id -u)" user="$(id -un)"
  if [ "$uid" = 0 ]; then
    _rt_chk fail "running as root: rootless Podman needs a dedicated unprivileged user"
  else
    _rt_chk ok "unprivileged operator $user (uid $uid)"
  fi
  if runtime_id_maps; then
    _rt_chk ok "user namespace: uid 0 = $user, subuid $_RT_UID_START+$_RT_UID_N, subgid $_RT_GID_START+$_RT_GID_N"
  else
    _rt_chk fail "subuid/subgid: podman unshare must map 0 to $user and 1… to one range of at least $RT_MIN_IDS ids in /etc/subuid and /etc/subgid (sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $(_sq "$user"), then podman system migrate)"
  fi
  um="$(podman unshare cat /proc/self/uid_map 2>/dev/null | _rt_map_norm || true)"
  cm="$(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    "$PORTCULLIS_HELPER_IMAGE" cat /proc/self/uid_map 2>/dev/null | _rt_map_norm || true)"
  if [ -n "$um" ] && [ "$um" = "$cm" ]; then
    _rt_chk ok "containers run in the user's default user namespace"
  else
    _rt_chk fail "containers don't run in the user's default user namespace (containers.conf userns must be empty or host: no auto, no keep-id)"
  fi
  f="${RT_CGROUP_ROOT:-/sys/fs/cgroup}/user.slice/user-$uid.slice/user@$uid.service/cgroup.controllers"
  ctl=" $(tr '\n' ' ' < "$f" 2>/dev/null || true) "
  case "$ctl" in *" memory "*) case "$ctl" in *" pids "*) ctl=delegated ;; esac ;; esac
  case "$ctl" in
    delegated)
      lim=""
      if id="$(docker create --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
          --memory 16m --pids-limit 8 "$PORTCULLIS_HELPER_IMAGE" true 2>/dev/null)" && [ -n "$id" ]; then
        lim="$(docker inspect --format '{{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}' "$id" 2>/dev/null || true)"
        docker rm -f "$id" >/dev/null 2>&1 || true
      fi
      if [ "$lim" = "16777216 8" ]; then
        _rt_chk ok "cgroup v2: memory and pids delegated, container limits enforced"
      else
        _rt_chk fail "cgroup v2: a probe container created with --memory 16m --pids-limit 8 doesn't keep its limits (mem/pids limits can't be enforced)"
      fi ;;
    *) _rt_chk fail "cgroup v2: memory and pids aren't both delegated in $f (mem/pids limits can't be enforced; cgroups v2 with systemd's default delegation)" ;;
  esac
  lin="$(loginctl show-user "$user" -p Linger --value 2>/dev/null || true)"
  if [ "$lin" = yes ]; then
    _rt_chk ok "linger enabled for $user"
  else
    _rt_chk fail "linger is off for $user: healthchecks and the start at boot need it (sudo loginctl enable-linger $(_sq "$user"))"
  fi
  for u in podman.socket podman-restart.service; do
    st="$(systemctl --user is-enabled "$u" 2>/dev/null || true)"
    if [ "$st" = enabled ]; then
      _rt_chk ok "user unit $u enabled"
    else
      _rt_chk fail "user unit $u is not enabled (systemctl --user enable --now $u)"
    fi
  done
  pstart="$(runtime_port_start)"
  if [ "$pstart" -le "$RT_PORT_START_MAX" ]; then
    _rt_chk ok "net.ipv4.ip_unprivileged_port_start = $pstart (ports >= $pstart)"
  else
    _rt_chk fail "net.ipv4.ip_unprivileged_port_start = $pstart: Traefik publishes 80 and 443 (sysctl -w net.ipv4.ip_unprivileged_port_start=$RT_PORT_START_MAX, and keep it in /etc/sysctl.d/)"
  fi
  if command -v nft >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1; then
    _rt_chk ok "nft or iptables present (rootlessport keeps remote TCP client addresses)"
  else
    _rt_chk warn "neither nft nor iptables: remote clients' addresses are rewritten (rate limits, access logs)"
  fi
  v="$(podman version --format '{{.Client.Version}}' 2>/dev/null || true)"
  if _ver_ge "$v" "$RT_PODMAN_MIN"; then
    _rt_chk ok "podman $v"
  else
    _rt_chk fail "podman ${v:-not found}: rootless Portcullis needs podman >= $RT_PODMAN_MIN"
  fi
  if command -v passt >/dev/null 2>&1; then
    _rt_chk ok "passt present"
  else
    _rt_chk fail "passt is missing (rootless networking): install passt"
  fi
  _rt_apparmor_pasta_check
  _rt_pool_check
  if v="$(docker compose version --short 2>/dev/null)" && [ -n "$v" ]; then
    _rt_chk ok "docker compose $v"
  else
    _rt_chk fail "the Docker CLI with the compose plugin is missing (no Docker daemon needed)"
  fi
  if command -v getenforce >/dev/null 2>&1; then
    _rt_chk ok "SELinux $(getenforce 2>/dev/null || echo unknown)"
  else
    _rt_chk ok "SELinux not present"
  fi
}

# _rt_apparmor_pasta_check — one host-check line. Ubuntu's AppArmor (26.04:
# Launchpad #2154379, unfixed) runs podman under its stub profile "podman"
# while pasta's profile only accepts signals from unconfined processes, so
# podman's SIGTERM to the rootless-netns pasta is denied: removing the last
# container of a network fails ("rootless netns: kill network process:
# permission denied"), e.g. ./portcullis down / restore after a boot.
# Overridable for tests: RT_APPARMOR_ENABLED, RT_APPARMOR_DIR.
_rt_apparmor_pasta_check() {
  local d="${RT_APPARMOR_DIR:-/etc/apparmor.d}" en files policy newest f
  en="$(cat "${RT_APPARMOR_ENABLED:-/sys/module/apparmor/parameters/enabled}" 2>/dev/null || true)"
  if [ "$en" != Y ] || [ ! -f "$d/podman" ] || [ ! -f "$d/usr.bin.pasta" ]; then
    _rt_chk ok "AppArmor: no podman / pasta profile pair to reconcile"
    return 0
  fi
  # The local file counts only when the profile includes it.
  files=("$d/usr.bin.pasta")
  if sed 's/#.*//' "$d/usr.bin.pasta" | grep -Eq 'include[[:space:]]+(if[[:space:]]+exists[[:space:]]+)?<local/usr\.bin\.pasta>'; then
    files+=("$d/local/usr.bin.pasta")
  fi
  if { for f in "${files[@]}"; do cat "$f" 2>/dev/null; done; true; } | sed 's/#.*//' \
       | grep -Eq 'signal[^,]*receive[^,]*peer="?podman"?[[:space:]]*,'; then
    # Best effort: a profile file newer than the loaded policy wasn't reloaded
    # (the policy tree is readable only by root on most hosts: then unchecked).
    policy="${RT_APPARMOR_POLICY:-/sys/kernel/security/apparmor/policy}"
    newest=""
    for f in "${files[@]}"; do
      [ -f "$f" ] || continue
      if [ -z "$newest" ] || [ "$f" -nt "$newest" ]; then newest="$f"; fi
    done
    if [ -r "$policy" ] && [ -n "$newest" ] && [ "$newest" -nt "$policy" ]; then
      _rt_chk warn "AppArmor: $newest looks newer than the loaded policy: if it wasn't reloaded, run sudo apparmor_parser -r $d/usr.bin.pasta"
    else
      _rt_chk ok "AppArmor: pasta accepts podman's SIGTERM (in the profile files; reload them with apparmor_parser -r after an edit)"
    fi
  else
    _rt_chk fail "AppArmor: pasta's profile refuses podman's SIGTERM (Ubuntu bug 2154379), so removing the last container of a network fails: add 'signal (receive) set=(term) peer=podman,' to $d/local/usr.bin.pasta (when $d/usr.bin.pasta includes <local/usr.bin.pasta>; else to $d/usr.bin.pasta itself), then sudo apparmor_parser -r $d/usr.bin.pasta"
  fi
}

# runtime_require_host — under podman: refuse (listing every failed item)
# while a † host-prep item fails. Docker: no-op.
runtime_require_host() {
  local lines fails
  _rt_is_podman || return 0
  [ -z "${_RT_HOST_OK:-}" ] || return 0
  lines="$(runtime_host_checks)" || exit 1
  fails="$(printf '%s\n' "$lines" | awk -F'\t' '$1 == "fail" { print "  - " $2 }')"
  [ -z "$fails" ] || fail "this host isn't prepared for rootless Podman (docs: operations/rootless-podman):"$'\n'"$fails"
  _RT_HOST_OK=1
}

# runtime_build_local [service...] — podman: build the services that have a
# `build` section (all of them, or the named ones) with `podman build`, each
# tagged with its `image:` (else <project>-<service>), build args and target
# from the merged compose config (so overrides' args survive). Never the
# compat API's /build.
runtime_build_local() {
  local cfg svc img ctx df args target a n=0
  local -a cmd
  cfg="$(dc config --format json)" || fail "docker compose config failed (is .env complete?)"
  while IFS=$'\t' read -r svc img ctx df args target; do
    [ -n "$svc" ] || continue
    case "$df" in /*) ;; *) df="$ctx/$df" ;; esac
    # --format docker: the OCI format drops the Dockerfile's HEALTHCHECK
    # ("not supported for OCI image format and will be ignored").
    cmd=(podman build --format docker -t "$img" -f "$df")
    while IFS= read -r a; do
      [ -n "$a" ] && cmd+=(--build-arg "$a")
    done < <(printf '%s' "$args" | jq -r 'to_entries[] | if .value == null then .key else "\(.key)=\(.value)" end')
    [ -z "$target" ] || cmd+=(--target "$target")
    cmd+=("$ctx")
    info "Building $img (podman build)..."
    "${cmd[@]}" >&2 || fail "podman build of $svc ($img) failed"
    n=$((n + 1))
  done < <(printf '%s' "$cfg" | jq -r '
      $ARGS.positional as $want | (.name // "portcullis") as $p
      | .services | to_entries[]
      | select(.value.build != null)
      | select(($want | length) == 0 or (.key as $k | $want | index($k)))
      | [.key, (.value.image // ($p + "-" + .key)), .value.build.context,
         (.value.build.dockerfile // "Dockerfile"), ((.value.build.args // {}) | tojson),
         (.value.build.target // "")] | @tsv' --args "$@")
  [ "$#" -eq 0 ] || [ "$n" -eq "$#" ] || fail "runtime_build_local: no build section for some of: $*"
}

# runtime_build_service <service> — build one local image: docker →
# `docker compose build --quiet`, podman → runtime_build_local.
runtime_build_service() {
  if _rt_is_podman; then runtime_build_local "$1"; else dc build --quiet "$1"; fi
}

# runtime_no_build — "--no-build" for a `dc up` outside stack_compose_up
# unless CONTAINER_RUNTIME is docker: under podman compose must never reach
# the compat /build (a missing image then fails instead).
runtime_no_build() {
  [ "${CONTAINER_RUNTIME:-}" = docker ] || echo --no-build
}

# stack_compose_up [service...] — `dc up -d` with the local images built:
# docker → --build, podman → runtime_build_local, then --no-build. Never
# --no-recreate / --force-recreate: compose recreates exactly the containers
# whose config or image changed. It compares the image's runnable content
# (its com.docker.compose.image label: under Docker's containerd store the
# platform manifest digest, not the image ID — that index digest also covers
# the provenance attestation and changes on every build, so a container's
# .Image differing from its tag's .Id is NOT a stale container; under
# Podman the image ID, which a fully cached `podman build` keeps). CI
# (build-and-test after an upgrade, e2e-podman after an up) checks that a
# changed image reaches its container and an unchanged one isn't recreated.
stack_compose_up() {
  local rc=0
  if _rt_is_podman; then
    runtime_build_local
    dc up -d --no-build "$@" || rc=$?
  else
    dc up -d --build "$@" || rc=$?
  fi
  [ "$rc" -eq 0 ] || { compose_health_report; return "$rc"; }
}

# runtime_proxies_refresh — rootless Podman: the socket proxies bind-mount
# the user socket FILE, so a restarted podman.socket (a new inode) leaves
# them talking to a dead one while they keep running (their /_ping health
# check fails). Restart each unhealthy proxy: a restart mounts the current
# socket. Docker: no-op (dockerd recreates its socket only with them).
runtime_proxies_refresh() {
  local svc
  _rt_is_podman || return 0
  for svc in socket-proxy-traefik socket-proxy-hub; do
    if [ "$(container_health "$svc")" = unhealthy ]; then
      warn "$svc is unhealthy (podman.socket restarted?): restarting it on the current socket"
      dc restart "$svc" >/dev/null || fail "could not restart $svc"
    fi
  done
}

# compose_health_report — after a failed `up`: each core container whose
# health is not healthy, with the exit code and output of its last three
# health checks (on stderr; outputs flattened and clipped to 300
# characters). Health checks print probe answers (HTTP status lines,
# `vault status`, PING replies), never a secret. Best effort, never fails.
compose_health_report() {
  local cid name st
  for cid in $(dc ps -aq 2>/dev/null); do
    read -r name st < <(docker inspect --format '{{.Name}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null) || continue
    case "$st" in
      unhealthy|starting)
        warn "${name#/} is $st; its last health checks:"
        docker inspect --format '{{json .State.Health.Log}}' "$cid" 2>/dev/null \
          | jq -r '(. // [])[-3:][] | "    exit \(.ExitCode): \((.Output // "") | gsub("\\s+"; " ") | .[0:300])"' >&2 2>/dev/null || true ;;
    esac
  done
  return 0
}

# runtime_status_json — {name, version, rootless, uid, subuid_start,
# subuid_count, subgid_start, subgid_count, port_start, checks: [{status, text}]}.
runtime_status_json() {
  local rt ver checks
  rt="$(runtime_name)" || exit 1
  ver="$(runtime_version)"
  if [ "$rt" = docker ]; then
    jq -nc --arg v "$ver" --argjson u "$(id -u)" \
      '{name: "docker", version: (if $v == "" then null else $v end), rootless: false, uid: $u,
        subuid_start: null, subuid_count: null, subgid_start: null, subgid_count: null, port_start: null, checks: []}'
    return 0
  fi
  checks="$(runtime_host_checks | jq -Rsc 'split("\n") | map(select(. != "") | split("\t") | {status: .[0], text: (.[1:] | join("\t"))})')"
  _RT_UID_START="" _RT_UID_N="" _RT_GID_START="" _RT_GID_N=""
  runtime_id_maps || true
  jq -nc --arg v "$ver" --argjson u "$(id -u)" --arg us "$_RT_UID_START" --arg un "$_RT_UID_N" \
    --arg gs "$_RT_GID_START" --arg gn "$_RT_GID_N" --argjson p "$(runtime_port_start)" --argjson c "$checks" \
    'def num: if . == "" then null else tonumber end;
     {name: "podman", version: (if $v == "" then null else $v end), rootless: true, uid: $u,
      subuid_start: ($us | num), subuid_count: ($un | num), subgid_start: ($gs | num), subgid_count: ($gn | num),
      port_start: $p, checks: $c}'
}
