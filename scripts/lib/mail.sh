# shellcheck shell=bash
#
# `portcullis mail …` — the mail server (contract §19): the compose profile
# mail (Stalwart, mailctl, mail-resolver), its recovery bootstrap, the mail
# certificate (the domains image's one-shot mail-cert) and the daily timer.
#
#   mail enable [--hostname H] [--lan-only true|false] [--yes]
#   mail disable [--yes] [--force]
#   mail status | test | dkim rotate <domain> | export <former-id>
#   mail cert | rotate | schedule --systemd [--out DIR]
#
# Docker and rootless Podman only: every function that runs a container
# starts with _rt_docker_only (Kubernetes is refused first).
#
# Secrets: the recovery admin's password lives in a shell variable and
# reaches the containers only through secrets/mail/recovery.env (0600,
# removed by a trap) and stdin; the API key goes from mailctl's stdout
# straight into secrets/mail/api-key (jq -r, never a variable that is
# echoed). jq reads secrets through env.X only.

MAIL_KUBE_REFUSED="mail isn't available on Kubernetes yet (Docker or rootless Podman only)"
MAIL_LAN_PODMAN_REFUSED="LAN-only needs the real client address; rootless Podman rewrites it"
MAIL_RECOVERY_USER=portcullis-recovery
MAIL_CERT_RENEW_DAYS=30
MAIL_HEALTH_WAIT="${MAIL_HEALTH_WAIT:-180}"

_mail_dir() { printf '%s/secrets/mail' "$PORTCULLIS_ROOT"; }

# _mail_set <key> <value> — .env (in place) and this shell (compose prefers
# the shell's value).
_mail_set() {
  env_set "$1" "$2"
  export "$1=$2"
}

# mail_hostname — MAIL_HOSTNAME, else mail.<main domain>.
mail_hostname() { printf '%s' "${MAIL_HOSTNAME:-mail.${PORTCULLIS_DOMAIN:-portcullis.local}}"; }

# _mail_profiles_with_mail — COMPOSE_PROFILES with mail added once.
_mail_profiles_with_mail() {
  if mail_profile_on; then printf '%s' "${COMPOSE_PROFILES:-}"; return 0; fi
  if [ -z "${COMPOSE_PROFILES:-}" ]; then printf 'mail'; else printf '%s,mail' "$COMPOSE_PROFILES"; fi
}

# _mail_profiles_without_mail — COMPOSE_PROFILES without mail.
_mail_profiles_without_mail() {
  printf '%s' "${COMPOSE_PROFILES:-}" | tr ',' '\n' | grep -vx mail | paste -sd, -
}

# mail_client_ip_mode — preserved (Docker: IPv4 DNAT keeps the client
# address) or rewritten (rootless Podman's rootlessport, M9).
mail_client_ip_mode() {
  if _rt_is_podman; then echo rewritten; else echo preserved; fi
}

# mail_lan_only_ok <true|false> — LAN-only (MAIL_SUBMISSION_LAN_ONLY) is
# refused under rootless Podman (fail closed): every client seems to come
# from the rootlessport gateway, so the Local networks can't be told apart.
mail_lan_only_ok() {
  [ "$1" = true ] || return 0
  ! _rt_is_podman || fail "$MAIL_LAN_PODMAN_REFUSED"
}

# mail_refuse_kube — the Kubernetes refusal (contract §19.12).
mail_refuse_kube() {
  ! _rt_is_kube || fail "$MAIL_KUBE_REFUSED"
}

# mail_port_start_ok — rootless Podman can publish 25 (Docker always can).
mail_port_start_ok() {
  local p
  _rt_is_podman || return 0
  p="$(runtime_port_start)"
  [ "$p" -le "$RT_PORT_START_MAX_MAIL" ]
}

mail_port_start_text() {
  printf 'net.ipv4.ip_unprivileged_port_start = %s: mail publishes ports 25, 465 and 587 (sysctl -w net.ipv4.ip_unprivileged_port_start=%s, and keep it in /etc/sysctl.d/; unprivileged users may then bind 25-79)' \
    "$(runtime_port_start)" "$RT_PORT_START_MAX_MAIL"
}

# _mail_volume <name> — the compose volume's Docker name.
_mail_volume() { printf '%s_%s' "${COMPOSE_PROJECT_NAME:-portcullis}" "$1"; }

# _mail_helper <volume> <dst> <ro|rw> <uid:gid> <cmd…> — a throwaway helper
# (no network, no capability) on one mail volume.
_mail_helper() {
  local vol="$1" dst="$2" mode="$3" user="$4" ro=""
  _rt_docker_only
  shift 4
  [ "$mode" = ro ] && ro=",readonly"
  ct_run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --user "$user" \
    --mount "type=volume,src=$(_mail_volume "$vol"),dst=$dst$ro" "$PORTCULLIS_HELPER_IMAGE" "$@"
}

# mail_config_present — mail_etc/config.json exists (P49: without it
# Stalwart starts in bootstrap mode and logs a generated admin password).
mail_config_present() {
  _rt_docker_only
  docker volume inspect "$(_mail_volume mail_etc)" >/dev/null 2>&1 || return 1
  _mail_helper mail_etc /v ro "$CT_UID_MAIL:$CT_UID_MAIL" test -s /v/config.json
}

# mail_config_install — mail/config.json (the store only) into mail_etc,
# as Stalwart's user.
mail_config_install() {
  _rt_docker_only
  volume_own mail_etc "$CT_UID_MAIL:$CT_UID_MAIL"
  ct_run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --user "$CT_UID_MAIL:$CT_UID_MAIL" \
    --mount "type=volume,src=$(_mail_volume mail_etc),dst=/v" "$PORTCULLIS_HELPER_IMAGE" \
    sh -c 'cat > /v/config.json.new && mv /v/config.json.new /v/config.json' < "$PORTCULLIS_HOME/mail/config.json" \
    || fail "could not write config.json into the mail_etc volume"
}

# mail_tls_present — mail_tls holds a chain (fullchain.pem).
mail_tls_present() {
  _rt_docker_only
  docker volume inspect "$(_mail_volume mail_tls)" >/dev/null 2>&1 || return 1
  _mail_helper mail_tls /v ro "$CT_UID_DOMAINS:$CT_UID_MAIL" test -s /v/fullchain.pem
}

# _mail_cert_input — mail-cert's stdin (contract §19.3): the main domain's
# DNS provider and credentials (jq env[$var], never argv), the CA, the CAA
# pin. A lego-only provider can't run mail-cert.
_mail_cert_input() {
  local provider="${DNS_PROVIDER:-none}" line var key map="[]" caa
  _dns_automated "$provider" || fail "mail needs a DNS provider Portcullis can write (see setup/mail.md): DNS_PROVIDER=$provider"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    var="${line%%:*}" key="${line#*:}"
    if [ -z "${!var:-}" ]; then
      [ "$var" = AWS_HOSTED_ZONE_ID ] && continue
      fail "$var is not set in .env (needed for DNS_PROVIDER=$provider)"
    fi
    export "${var?}"
    map="$(jq -c --arg v "$var" --arg k "$key" '. + [{var: $v, key: $k}]' <<<"$map")"
  done < <(_dns_cred_keys "$provider")
  caa="$(_dns_flag DNS_CAA true)" || return 1
  jq -n --arg host "$(mail_hostname)" --arg ca "$(_dns_ca_server)" --arg email "${ACME_EMAIL:-admin@${PORTCULLIS_DOMAIN}}" \
    --arg provider "$provider" --argjson map "$map" --argjson caa "$caa" --arg issuer "${DNS_CAA_ISSUER:-}" \
    --arg iodef "${DNS_CAA_IODEF:-}" --argjson days "$MAIL_CERT_RENEW_DAYS" '
    {hostname: $host, ca_server: $ca, email: $email, provider: $provider,
     credentials: ($map | map({key: .key, value: env[.var]}) | from_entries),
     caa: {enabled: $caa, issuer: $issuer, iodef: $iodef}, renew_below_days: $days}'
}

# mail_cert_ensure [--switch-key] — run mail-cert (issue / renew below 30
# days; --switch-key: issue with the next key, the TLSA rollover's last
# step); sets MAIL_CERT_RENEWED=true|false and MAIL_CERT_SPKI (the key's
# sha256 SPKI, hex). Its output line has no secret.
mail_cert_ensure() {
  local input out
  _rt_docker_only
  input="$(_mail_cert_input)" || exit 1
  domains_image_ensure "for the mail certificate"
  volume_own mail_tls "$CT_UID_DOMAINS:$CT_UID_MAIL" 2750
  volume_own mail_acme "$CT_UID_DOMAINS:$CT_UID_DOMAINS" 0700
  info "Mail certificate for $(mail_hostname)..."
  # shellcheck disable=SC2034  # read by the callers
  out="$(printf '%s' "$input" | rt_run mail-cert -i -- "$@")" || fail "the mail certificate could not be issued (see above)"
  MAIL_CERT_RENEWED="$(printf '%s' "$out" | tail -n1 | jq -r '.renewed // false' 2>/dev/null || echo false)"
  # shellcheck disable=SC2034  # read by mail_rotate
  MAIL_CERT_SPKI="$(printf '%s' "$out" | tail -n1 | jq -r '.spki_sha256 // ""' 2>/dev/null || true)"
  printf '%s' "$out" | tail -n1 | jq -r '"    not after \(.not_after // "?"), renewed: \(.renewed)"' 2>/dev/null || true
}

# mail_prom_targets — Prometheus' file_sd for jobs mail and mailctl
# (mail-targets.json: both targets while the profile is on, else []) and
# the copy of Stalwart's metrics password the mail job sends (empty while
# off); monitoring_fix_perms gives both Prometheus' group.
mail_prom_targets() {
  local d="${MONITORING_SECRETS:-$PORTCULLIS_ROOT/secrets/monitoring}/prometheus" src="$PORTCULLIS_ROOT/secrets/mail/metrics-secret"
  [ -d "$d" ] || return 0
  [ -f "$d/mail-metrics-secret" ] || (umask 077 && : > "$d/mail-metrics-secret")
  if mail_profile_on && [ -s "$src" ]; then
    jq -n '[{targets: ["mail-metrics:9180"], labels: {service: "mail"}}, {targets: ["mailctl-metrics:9100"], labels: {service: "mailctl"}}]' > "$d/mail-targets.json"
    cmp -s "$src" "$d/mail-metrics-secret" || cat "$src" > "$d/mail-metrics-secret"
  else
    echo '[]' > "$d/mail-targets.json"
    : > "$d/mail-metrics-secret"
  fi
}

# _mail_wait_healthy [timeout] — mail's health check passes.
_mail_wait_healthy() {
  local limit="${1:-$MAIL_HEALTH_WAIT}" start=$SECONDS st
  while :; do
    st="$(rt_health mail)"
    [ "$st" != healthy ] || return 0
    case "$st" in exited|missing) return 1 ;; esac
    [ $((SECONDS - start)) -lt "$limit" ] || return 1
    sleep 2
  done
}

# _mail_recreate — mail with the current env files (recovery or not):
# compose recreates it whenever its environment changed (no --force-recreate).
_mail_recreate() {
  _rt_docker_only
  # shellcheck disable=SC2046  # "--no-build" or nothing
  dc up -d --no-deps $(runtime_no_build) mail >/dev/null
}

# _mail_recovery_start — mail in recovery mode with no egress: created,
# detached from every network but portcullis-mail, then started. A first
# start (any start of a store without one) creates Stalwart's WebUI
# Application, which fetches webui.zip from GitHub; without a route it
# fails and Stalwart carries on. The bootstrap needs only mailctl on
# portcullis-mail. The normal recreate after the session reattaches all.
_mail_recovery_start() {
  local cid net
  _rt_docker_only
  # shellcheck disable=SC2046  # "--no-build" or nothing
  dc create $(runtime_no_build) mail >/dev/null || return 1
  cid="$(dc ps -aq mail)"
  [ -n "$cid" ] || return 1
  for net in $(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$cid"); do
    [ "$net" = "$MAIL_NETWORK" ] || docker network disconnect "$net" "$cid" >/dev/null || return 1
  done
  [ "$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$cid")" = "$MAIL_NETWORK " ] || return 1
  dc start mail >/dev/null
}

# _mail_recovery_end — the session's trap: the recovery admin goes away
# whatever happened (the env file, then a recreate without it).
_mail_recovery_end() {
  _rt_docker_only
  rm -f "$(_mail_dir)/recovery.env"
  # Restored passwords not voided (the void failed): mail stays stopped,
  # never back in normal mode with them.
  if mail_void_pending; then
    dc stop mail >/dev/null 2>&1 || warn "could not stop mail: stop it by hand (docker compose stop mail)"
    return 0
  fi
  # shellcheck disable=SC2046  # "--no-build" or nothing
  dc up -d --no-deps $(runtime_no_build) mail >/dev/null 2>&1 || warn "could not recreate mail without the recovery admin: ./portcullis up"
}

# mail_recovery_session <fn> — Stalwart in recovery mode for one step
# (contract §19.4): mailctl stopped (the one-shot takes its pinned
# address), recovery.env written (0600, a fresh 32-byte password), mail
# recreated and healthy, <fn> run with the password on fd 3; then always
# recovery.env removed and mail recreated; the recovery login must be
# refused (401) before mailctl starts again.
mail_recovery_session() {
  local fn="$1" pw rc=0 f
  _rt_docker_only
  f="$(_mail_dir)/recovery.env"
  runtime_build_service mailctl >/dev/null || fail "could not build the mailctl image"
  pw="$(openssl rand -base64 32 | tr -d '\n')"
  [ -n "$pw" ] || fail "could not generate the recovery password"
  dc stop mailctl >/dev/null 2>&1 || true
  (umask 077 && printf 'STALWART_RECOVERY_MODE=1\nSTALWART_RECOVERY_ADMIN=%s:%s\n' "$MAIL_RECOVERY_USER" "$pw" > "$f")
  trap '_mail_recovery_end' EXIT
  trap '_mail_recovery_end; exit 130' INT TERM
  info "Starting mail in recovery mode..."
  if ! _mail_recovery_start || ! _mail_wait_healthy; then
    rc=1
    warn "mail didn't become healthy in recovery mode: docker compose logs mail"
  else
    "$fn" 3<<<"$pw" || rc=$?
  fi
  _mail_recovery_end
  trap - EXIT INT TERM
  [ "$rc" = 0 ] || { pw=""; fail "the mail bootstrap failed (the recovery admin was removed; mail runs without it)"; }
  _mail_wait_healthy || { pw=""; fail "mail didn't become healthy after the recovery session: docker compose logs mail"; }
  _mail_verify_gone 3<<<"$pw" || { pw=""; fail "the recovery admin still works: stop mail and inspect"; }
  pw=""
  # shellcheck disable=SC2046  # "--no-build" or nothing
  dc up -d --no-deps $(runtime_no_build) mailctl >/dev/null 2>&1 || warn "could not start mailctl: ./portcullis up"
}

# mail_void_marker — secrets/mail/void-pending (0600): written by restore
# before the mail store comes back, removed only once its passwords are
# voided. While it exists mail never starts normally (M7, security review).
mail_void_marker() { printf '%s/void-pending' "$(_mail_dir)"; }
mail_void_pending() { [ -e "$(mail_void_marker)" ]; }

# mail_void_restore (fd 3: the password) — `mailctl void --reason restore`:
# every mail password destroyed, restored_at recorded (M7), then the
# marker removed. Credentials on stdin only.
mail_void_restore() {
  local pw
  _rt_docker_only
  IFS= read -r pw <&3
  MAIL_PW="$pw" jq -n --arg u "$MAIL_RECOVERY_USER" '{recovery_user: $u, recovery_password: env.MAIL_PW}' \
    | dc run --rm --no-deps -T mailctl void --reason restore || return 1
  rm -f "$(mail_void_marker)"
}

# mail_void_if_pending — with the marker: the void in a recovery session
# (no egress) first; 0 when nothing is pending or the void succeeded.
mail_void_if_pending() {
  mail_void_pending || return 0
  info "Mail passwords from a restore aren't voided yet: voiding them first (recovery session)..."
  (mail_recovery_session mail_void_restore) && ! mail_void_pending
}

# _mail_verify_gone (fd 3: the password) — mailctl's one-shot checks that
# the recovery login now gets 401.
_mail_verify_gone() {
  local pw
  _rt_docker_only
  IFS= read -r pw <&3
  MAIL_PW="$pw" jq -n --arg u "$MAIL_RECOVERY_USER" '{recovery_user: $u, recovery_password: env.MAIL_PW}' \
    | dc run --rm --no-deps -T mailctl bootstrap --verify-gone
}

# _mail_relay_json — {"host","port","username"} or null.
_mail_relay_json() {
  if [ -z "${MAIL_RELAY_HOST:-}" ]; then echo null; return 0; fi
  jq -nc --arg h "$MAIL_RELAY_HOST" --arg p "${MAIL_RELAY_PORT:-465}" --arg u "${MAIL_RELAY_USERNAME:-}" \
    '{host: $h, port: ($p | tonumber), username: $u}'
}

# mail_bootstrap_apply (fd 3: the recovery password) — the base plan, then
# the API key (printed once) straight into secrets/mail/api-key.
mail_bootstrap_apply() {
  local pw key out relay rotate=() tmp
  _rt_docker_only
  IFS= read -r pw <&3
  relay="$(_mail_relay_json)"
  [ "${MAIL_ROTATE_KEY:-false}" != true ] || rotate=(--rotate-key)
  key="$(_mail_dir)/api-key"
  tmp="$(_mail_dir)/.api-key.new"
  # shellcheck disable=SC2086  # VPN_DEFAULT_LOCAL_NETWORKS is a word list
  out="$(MAIL_PW="$pw" jq -nc --arg u "$MAIL_RECOVERY_USER" --arg h "$(mail_hostname)" --arg d "$PORTCULLIS_DOMAIN" \
      --arg ip "${MAILCTL_CLIENT_IP:-$(mail_client_ip_mode)}" --argjson lan "$([ "${MAIL_SUBMISSION_LAN_ONLY:-false}" = true ] && echo true || echo false)" \
      --argjson relay "$relay" --arg nets "$VPN_DEFAULT_LOCAL_NETWORKS" '
      {recovery_user: $u, recovery_password: env.MAIL_PW, hostname: $h, primary_domain: $d, client_ip: $ip,
       lan_only: $lan, local_networks: ($nets | split(" ")), relay: $relay, metrics_user: "prometheus"}' \
    | dc run --rm --no-deps -T mailctl bootstrap ${rotate[@]+"${rotate[@]}"})" || return 1
  pw=""
  # The key goes from mailctl's answer into the file, never echoed.
  if printf '%s' "$out" | jq -e '.api_key | type == "string"' >/dev/null 2>&1; then
    (umask 077 && printf '%s' "$out" | jq -r '.api_key' > "$tmp")
    # In place: the single-file bind pins the inode.
    cat "$tmp" > "$key"
    rm -f "$tmp"
    ct_group_read "$CT_UID_MAILCTL" "$key"
    ok "mailctl's Stalwart API key written (secrets/mail/api-key)"
  elif ! printf '%s' "$out" | jq -e '.api_key == null' >/dev/null 2>&1; then
    warn "mailctl bootstrap printed no api_key line"
    return 1
  fi
  out=""
  [ -s "$key" ] || { warn "secrets/mail/api-key is empty and Stalwart already has a key: run ./portcullis mail enable --rotate-key"; return 1; }
}

# _mail_image — the mail service's image reference as compose renders it.
_mail_image() {
  _rt_docker_only
  dc --profile mail config --format json | jq -r '.services.mail.image // ""'
}

# mail_image_update — after a change of the Stalwart image, one recreate
# with STALWART_UPDATE_ROLE_PERMISSIONS=true (a 0600 env file, removed once
# mail is healthy), then the image is remembered.
mail_image_update() {
  local cur prev f u
  _rt_docker_only
  f="$(_mail_dir)/.stalwart-image"
  u="$(_mail_dir)/update.env"
  cur="$(_mail_image)"
  prev="$(cat "$f" 2>/dev/null || true)"
  [ -n "$cur" ] || return 0
  if [ -n "$prev" ] && [ "$prev" != "$cur" ]; then
    info "Stalwart's image changed: updating its role permissions once..."
    (umask 077 && printf 'STALWART_UPDATE_ROLE_PERMISSIONS=true\n' > "$u")
    _mail_recreate && _mail_wait_healthy || { rm -f "$u"; fail "mail didn't become healthy after the image update: docker compose logs mail"; }
    rm -f "$u"
    _mail_recreate && _mail_wait_healthy || fail "mail didn't become healthy: docker compose logs mail"
  fi
  printf '%s\n' "$cur" > "$f"
}

# mail_up_steps <up|upgrade> — called by `up` and `upgrade` (before the
# stack starts) when mail is in COMPOSE_PROFILES.
mail_up_steps() {
  local mode="$1"
  mail_profile_on || return 0
  mail_refuse_kube
  _rt_docker_only
  mail_port_start_ok || fail "$(mail_port_start_text)"
  mail_lan_only_ok "${MAIL_SUBMISSION_LAN_ONLY:-false}"
  [ "${MAILCTL_CLIENT_IP:-}" = "$(mail_client_ip_mode)" ] || _mail_set MAILCTL_CLIENT_IP "$(mail_client_ip_mode)"
  mail_ipv6_refuse
  mail_config_present || fail "mail is in COMPOSE_PROFILES but mail_etc/config.json is missing (Stalwart would start in bootstrap mode): run ./portcullis mail enable"
  # A restore's passwords are voided before mail starts; if that fails
  # mail and mailctl stay stopped and the rest starts without the profile.
  if ! mail_void_if_pending; then
    _rt_docker_only
    dc --profile mail stop mail mailctl >/dev/null 2>&1 || true
    COMPOSE_PROFILES="$(_mail_profiles_without_mail)"; export COMPOSE_PROFILES
    warn "mail passwords from a restore are not voided yet: mail stays stopped (./portcullis mail enable to retry)"
    return 0
  fi
  mail_tls_present || mail_cert_ensure
  if [ "$mode" = upgrade ] || [ ! -s "$(_mail_dir)/api-key" ]; then
    mail_recovery_session mail_bootstrap_apply
  fi
}

# mail_ipv6_refuse — IPv6 for mail isn't supported yet: [::] ports onto an
# IPv4-only network go through docker-proxy, which rewrites the client
# address (LAN-only, SPF and the blocklists would judge the proxy). A set
# MAIL_IPV6 is refused, never ignored.
mail_ipv6_refuse() {
  [ -z "${MAIL_IPV6:-}" ] || fail "MAIL_IPV6 isn't supported yet: remove it from .env"
}

# mail_after_up — after the stack is up: the image-change recreate.
mail_after_up() {
  mail_profile_on || return 0
  ! mail_void_pending || return 0
  _rt_docker_only
  mail_image_update
}

# mail_enable <hostname> <lan_only> <yes> <rotate>
mail_enable() {
  local host="$1" lan="$2" yes="$3"
  mail_refuse_kube
  _rt_docker_only
  mail_port_start_ok || fail "$(mail_port_start_text)"
  require_cmd docker jq openssl
  _dns_automated "${DNS_PROVIDER:-none}" || fail "mail needs a DNS provider Portcullis can write (see setup/mail.md): DNS_PROVIDER=${DNS_PROVIDER:-none}"
  mail_lan_only_ok "${lan:-${MAIL_SUBMISSION_LAN_ONLY:-false}}"
  mail_ipv6_refuse
  [ -z "$host" ] || _mail_set MAIL_HOSTNAME "$host"
  [ -z "$lan" ] || _mail_set MAIL_SUBMISSION_LAN_ONLY "$lan"
  _mail_set MAILCTL_CLIENT_IP "$(mail_client_ip_mode)"
  mail_profile_on || _mail_set COMPOSE_PROFILES "$(_mail_profiles_with_mail)"
  runtime_check
  rt_network_check
  stack_prepare
  info "Mail for $(mail_hostname) (client addresses: $MAILCTL_CLIENT_IP)"
  mail_config_present || mail_config_install
  mail_cert_ensure
  mail_void_if_pending || fail "mail passwords could not be voided: mail stays stopped (./portcullis mail enable to retry)"
  mail_recovery_session mail_bootstrap_apply
  hub_env_write
  mail_prom_targets
  if declare -F monitoring_fix_perms >/dev/null; then monitoring_fix_perms; fi
  stack_compose_up mail mail-resolver mailctl traefik hub
  mail_image_update
  ok "Mail is on. DNS: ./portcullis dns setup --only mail; status: ./portcullis mail status"
  if [ "$yes" = true ] || confirm "Install the daily mail timer (certificate, DKIM, records) now?"; then
    mail_schedule_systemd ""
  fi
}

# _mail_hub <args> — `hub mail <args>` in the Hub (its control socket).
_mail_hub() {
  rt_exec -i hub -- hub mail "$@"
}

# mail_disable <yes> <force>
mail_disable() {
  local yes="$1" force="$2" doms off
  mail_refuse_kube
  mail_profile_on || { ok "Mail is already off."; return 0; }
  if [ "$yes" != true ] && ! confirm "Turn mail off for every domain (the MX goes after the MTA-STS max_age)?"; then
    fail "Aborted."
  fi
  if [ "$force" != true ]; then
    _mail_hub drain >/dev/null || fail "the Hub didn't drain the mail domains (is it running?): ./portcullis mail disable --force removes mail now"
    doms="$(_mail_hub domains)" || fail "the Hub didn't answer hub mail domains"
    off="$(printf '%s' "$doms" | jq -r 'if type == "array" and all(.[]; .state == "off") then "yes" else "no" end' 2>/dev/null || echo no)"
    if [ "$off" != yes ]; then
      ok "Every mail domain is draining: senders get MTA-STS mode none for its max_age (up to 7 days), then the MX goes."
      echo "    Run ./portcullis mail disable again once ./portcullis mail status says every domain is off."
      return 0
    fi
  else
    warn "--force: mail goes now; senders with a cached MTA-STS policy may bounce mail until its max_age."
  fi
  if _dns_automated "${DNS_PROVIDER:-none}"; then
    DNS_SETS=mail DNS_MAIL_RECORDS='[]' _dns_tool apply >/dev/null \
      || warn "the main domain's mail records could not be removed: run ./portcullis dns setup"
  fi
  _mail_set COMPOSE_PROFILES "$(_mail_profiles_without_mail)"
  _mail_stop_services
  mail_prom_targets
  hub_env_write
  ok "Mail is off (its volumes are kept)."
}

_mail_stop_services() {
  _rt_docker_only
  dc --profile mail stop mailctl mail mail-resolver >/dev/null 2>&1 || true
}

# _mail_main_dnssec — the main zone's DNSSEC state from the domains
# service's main plan (`domains report --main`), "unknown" when it can't
# be read (mailctl then withholds TLSA: fail closed).
_mail_main_dnssec() {
  local st
  st="$(rt_exec domains -- domains report --main --json 2>/dev/null | jq -r '.dnssec.state // empty' 2>/dev/null)" || st=""
  printf '%s' "${st:-unknown}"
}

# _mail_rotate_once <next spki> — `mailctl rotate --json` (stdin: the
# DNSSEC state and the SPKIs; contract §19.7), then the main domain's mail
# set through the dns tool; sets MAIL_SWITCH_KEY=true|false.
_mail_rotate_once() {
  local out in
  in="$(jq -cn --arg st "$(_mail_main_dnssec)" --arg cur "${MAIL_CERT_SPKI:-}" --arg next "$1" \
    '{dnssec_state: $st, spki: {current: $cur, next: $next}}')"
  out="$(printf '%s' "$in" | rt_exec -i mailctl -- mailctl rotate --json)" || fail "mailctl rotate failed"
  MAIL_SWITCH_KEY="$(printf '%s' "$out" | jq -r '.switch_key == true')"
  printf '%s' "$out" | jq -r '"    TLSA: \(.tlsa)"' 2>/dev/null || true
  if ! _dns_automated "${DNS_PROVIDER:-none}"; then
    warn "No automatic DNS for provider '${DNS_PROVIDER:-none}': ./portcullis dns plan shows the mail records to create by hand."
    return 0
  fi
  DNS_SETS=mail DNS_MAIL_RECORDS="$(printf '%s' "$out" | jq -c '.records // []')" _dns_tool apply >/dev/null \
    || fail "the main domain's mail records could not be written"
}

# mail_rotate [--next-key] — the daily timer's step (contract §19.3):
# renewal, a TLS reload after a change, the state machines and the main
# domain's set; the TLSA rollover's switch when mailctl says it's due.
# --next-key starts a rollover (mail-cert --next-key: both SPKIs published).
mail_rotate() {
  local next="" out
  mail_refuse_kube
  mail_profile_on || fail "mail is off: ./portcullis mail enable"
  _rt_docker_only
  mail_cert_ensure
  if [ "${MAIL_CERT_RENEWED:-false}" = true ]; then
    rt_exec mailctl -- mailctl reload-tls || fail "mailctl reload-tls failed"
  fi
  if [ "${1:-}" = --next-key ]; then
    out="$(rt_run mail-cert -- --next-key </dev/null)" || fail "mail-cert --next-key failed"
    next="$(printf '%s' "$out" | tail -n1 | jq -r '.spki_sha256 // ""')"
    [ -n "$next" ] || fail "mail-cert --next-key printed no key"
    info "Next mail key $next: published next to the current one; the switch follows in about a day."
  fi
  _mail_rotate_once "$next"
  if [ "${MAIL_SWITCH_KEY:-false}" = true ]; then
    info "Switching the mail certificate to the next key (TLSA rollover)..."
    mail_cert_ensure --switch-key
    rt_exec mailctl -- mailctl reload-tls || fail "mailctl reload-tls failed"
    _mail_rotate_once ""
  fi
  ok "Mail rotation done."
}

# mail_schedule_systemd <out dir> — portcullis-mail.service + .timer
# (daily; user units under rootless Podman), like backup schedule.
mail_schedule_systemd() {
  local out="$1" user svc timer after requires user_line wanted env_line=""
  user="$(id -un)"
  if _rt_is_podman; then
    after="network-online.target podman.socket" requires="podman.socket" user_line="" wanted="default.target"
  else
    after="network-online.target docker.service" requires="docker.service" user_line="User=$user" wanted="timers.target"
  fi
  [ "$PORTCULLIS_ROOT" = "$PORTCULLIS_HOME" ] || env_line="Environment=PORTCULLIS_ROOT=$PORTCULLIS_ROOT"
  svc="$(cat <<EOF
# portcullis-mail.service — generated by ./portcullis mail schedule --systemd
[Unit]
Description=Portcullis mail rotation (certificate, DKIM, MTA-STS, records)
Wants=network-online.target
After=$after
Requires=$requires

[Service]
Type=oneshot
${user_line:+$user_line
}WorkingDirectory=$PORTCULLIS_ROOT
Environment=NO_COLOR=1
${env_line}
ExecStart=$PORTCULLIS_HOME/portcullis mail rotate
TimeoutStartSec=1h
EOF
)"
  timer="$(cat <<EOF
# portcullis-mail.timer — generated by ./portcullis mail schedule --systemd
[Unit]
Description=Daily Portcullis mail rotation

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=$wanted
EOF
)"
  if [ -z "$out" ]; then
    out="$PORTCULLIS_ROOT/backups/systemd"
  fi
  mkdir -p "$out"
  printf '%s\n' "$svc" > "$out/portcullis-mail.service"
  printf '%s\n' "$timer" > "$out/portcullis-mail.timer"
  ok "Wrote $out/portcullis-mail.service and portcullis-mail.timer"
  if _rt_is_podman; then
    cat <<EOF
Install (as $user, user units; linger must be on):
  mkdir -p ~/.config/systemd/user
  install -m 0644 $(_sq "$out/portcullis-mail.service") $(_sq "$out/portcullis-mail.timer") ~/.config/systemd/user/
  systemctl --user daemon-reload && systemctl --user enable --now portcullis-mail.timer
EOF
  else
    cat <<EOF
Install (as root):
  install -m 0644 $(_sq "$out/portcullis-mail.service") $(_sq "$out/portcullis-mail.timer") /etc/systemd/system/
  systemctl daemon-reload && systemctl enable --now portcullis-mail.timer
EOF
  fi
}

# ── help / commands ────────────────────────────────────────

# ── status (contract §19.10) ──

# _mail_timer_state — portcullis-mail.timer: active | inactive | unknown
# (no systemd here). Podman installs it as the operator's user unit.
_mail_timer_state() {
  local scope=()
  command -v systemctl >/dev/null 2>&1 || { echo unknown; return 0; }
  ! _rt_is_podman || scope=(--user)
  if systemctl "${scope[@]}" is-active --quiet portcullis-mail.timer 2>/dev/null; then echo active; else echo inactive; fi
}

# mail_status_json — the mail block of status (absent with the profile
# off: nothing printed): the services' health, mailctl's status and checks
# (`mailctl status --json` on its control socket), the timer, the client
# address mode and `problem` (a service not healthy, mailctl unreachable,
# a Problem check).
mail_status_json() {
  local svc h hs="{}" ms=""
  mail_profile_on || return 0
  for svc in mail mailctl mail-resolver; do
    h="$(rt_health "$svc" 2>/dev/null)" || h=missing
    hs="$(jq -c --arg s "$svc" --arg h "$h" '. + {($s): $h}' <<<"$hs")"
  done
  ms="$(rt_exec mailctl -- mailctl status --json 2>/dev/null)" || ms=""
  printf '%s' "$ms" | jq -e 'type == "object"' >/dev/null 2>&1 || ms=""
  jq -cn --argjson hs "$hs" --arg ms "$ms" --arg timer "$(_mail_timer_state)" --argjson vp "$(mail_void_pending && echo true || echo false)" \
    --arg cip "${MAILCTL_CLIENT_IP:-$(mail_client_ip_mode)}" --arg host "$(mail_hostname)" '
    ($ms | if . == "" then null else fromjson end) as $m
    | {enabled: true, hostname: $host, services: $hs, timer: $timer, client_ip: $cip,
       mailctl: ($m.status // null), checks: ($m.checks // null), void_pending: $vp}
    | .problem = (.void_pending or ([.services[] | select(. != "healthy")] | length) > 0 or .mailctl == null
                  or ([(.checks.checks // [])[] | select(.severity == "problem")] | length) > 0)'
}

# mail_status_lines <json> — the "Mail" block in status's vocabulary.
mail_status_lines() {
  local j="$1" st text
  [ -n "$j" ] || return 0
  printf '\n%sMail%s\n' "$C_CYAN" "$C_NC"
  while IFS=$'\t' read -r st text; do
    [ -n "$st" ] && _st_line "$st" "$text"
  done < <(printf '%s' "$j" | jq -r '
    def sev: if . == "problem" then "fail" elif . == "warning" then "warn" elif . == "info" then "note" else "ok" end;
    (if .void_pending then ["fail", "mail passwords from a restore are not voided yet: mail stays stopped (./portcullis mail enable)"] else empty end),
    (.services | to_entries[] | [(if .value == "healthy" then "ok" else "fail" end), "\(.key): \(.value)"]),
    (if .mailctl == null then ["fail", "mailctl didn'"'"'t answer (its status and checks are unknown)"] else
      (.mailctl as $s
       | (if $s.cert == null then ["fail", "no mail certificate for \(.hostname): ./portcullis mail cert"]
          else ["ok", "certificate \($s.cert.sans | join(", ")) valid until \($s.cert.not_after)"] end),
         ($s.dkim | group_by(.domain)[] | ["ok", "DKIM \(.[0].domain): " + (map("\(.selector) \(.stage)") | join(", "))]),
         ($s.mtasts[] | [(if .mode == "testing" and .enforce_ready then "note" else "ok" end),
            "MTA-STS \(.domain): \(.mode)" + (if .enforce_ready then " (ready to enforce: the doctor fix)" else "" end)]),
         ($s.dmarc[] | [(if .proposed != null then "note" else "ok" end),
            "DMARC \(.domain): p=\(.policy)" + (if .proposed != null then " (\(.proposed) proposed: the doctor fix)" else "" end)]),
         ["ok", "queue: \($s.queue.messages) message(s), \($s.queue.deferred) deferred"],
         (if ($s.former | length) > 0 then ["note", "former accounts: " + ($s.former | map("\(.username) (\(.id))") | join(", "))] else empty end))
     end),
    ((.checks.checks // [])[] | select(.severity != "ok") | [(.severity | sev), "check \(.id): \(.detail)"]),
    (if .timer == "active" then ["ok", "daily timer portcullis-mail.timer active"]
     elif .timer == "inactive" then ["warn", "daily timer portcullis-mail.timer missing or inactive: ./portcullis mail schedule --systemd (certificate renewal, DKIM, TLSA)"]
     else ["note", "daily timer: unknown (no systemd here)"] end),
    (if .client_ip == "rewritten" then ["warn", "client addresses rewritten (rootless Podman): SPF, iprev and the IP blocklists are off"] else ["ok", "client addresses preserved"] end)
    | @tsv')
}

# mail_status <json> — `mail status [--json]`; exit 1 on a problem.
mail_status() {
  local j
  mail_profile_on || fail "mail is off: ./portcullis mail enable"
  j="$(mail_status_json)"
  if [ "$1" = true ]; then printf '%s\n' "$j"; else mail_status_lines "$j"; echo; fi
  [ "$(printf '%s' "$j" | jq -r .problem)" != true ]
}

# mail_test <to> — `mailctl test --to`: a message from the first postmaster
# account, signed by the primary domain's DKIM keys (contract §19.10).
mail_test() {
  local to="$1" out
  mail_profile_on || fail "mail is off: ./portcullis mail enable"
  out="$(rt_exec mailctl -- mailctl test --to "$to")" || fail "the test message could not be sent (see above)"
  printf '%s' "$out" | jq -r '"Sent from \(.from) to \(.to): \(.queued)", "Message-ID: <\(.message_id)>"'
  echo "    Open the message's headers (\"Show original\" / \"View source\") and check Authentication-Results:"
  echo "    dkim=pass, spf=pass and dmarc=pass mean receivers can verify mail from this server."
}

# mail_dkim_rotate <domain> — a new DKIM key pair now (mailctl's
# dkim-rotate action on its control socket).
mail_dkim_rotate() {
  local d="$1" out
  mail_profile_on || fail "mail is off: ./portcullis mail enable"
  out="$(rt_exec mailctl -- mailctl dkim rotate "$d" --json)" || fail "DKIM rotation of $d refused (see above)"
  ok "$(printf '%s' "$out" | jq -r '"\(.domain): \(.result)"')"
  if [ "$d" = "${PORTCULLIS_DOMAIN:-}" ]; then
    echo "    The main domain's records follow at the next ./portcullis mail rotate (or ./portcullis dns setup --only mail)."
  else
    echo "    The Hub publishes the new TXT records for $d."
  fi
}

# mail_export <former-id> <out> — a former account's mailbox as mbox
# (0600) under backups/mail-export/ (or <out>), streamed from `mailctl
# export`; nothing is left behind when it fails.
mail_export() {
  local id="$1" out="$2" dir tmp
  mail_profile_on || fail "mail is off: ./portcullis mail enable"
  if [ -z "$out" ]; then
    dir="$PORTCULLIS_ROOT/backups/mail-export"
    (umask 077 && mkdir -p "$dir")
    chmod 700 "$dir"
    out="$dir/$id-$(date -u +%Y%m%dT%H%M%SZ).mbox"
  fi
  [ ! -e "$out" ] || fail "$out exists: choose another --out"
  tmp="$out.part"
  if ! (umask 077 && rt_exec mailctl -- mailctl export --former "$id" > "$tmp"); then
    rm -f "$tmp"
    fail "the export of $id failed (see above); the account stays disabled"
  fi
  chmod 600 "$tmp"
  mv "$tmp" "$out"
  ok "Exported $id to $out ($(grep -c '^From ' "$out" 2>/dev/null || echo 0) messages, mode 0600)."
}

help_mail() {
  cat <<'EOF'
Usage: portcullis mail <subcommand>

  enable        Turn the mail server on (profile mail, certificate, bootstrap)
  disable       Turn mail off for every domain (drains first)
  status        Mail status: certificate, DKIM, MTA-STS, DMARC, queue, checks
  test          Send a signed test message from the postmaster account
  dkim          dkim rotate <domain>: a new DKIM key now
  cert          Issue or renew the mail certificate (below 30 days)
  rotate        The daily step: certificate, DKIM / MTA-STS / TLSA, the main domain's records
  schedule      schedule --systemd: install the daily timer
  export        Export a former account's mailbox as mbox

Run 'portcullis mail <subcommand> --help' for details.
EOF
}

help_mail_enable() {
  cat <<'EOF'
Usage: portcullis mail enable [--hostname H] [--lan-only true|false] [--rotate-key] [--yes]

Turn the mail server on (contract §19): adds mail to COMPOSE_PROFILES,
writes MAIL_HOSTNAME (default mail.<domain>) and MAILCTL_CLIENT_IP, issues
the mail certificate through your DNS provider (mail-cert), bootstraps
Stalwart in recovery mode (the recovery admin exists only during it and is
checked gone after), and starts mail, mail-resolver and mailctl. Idempotent.
--lan-only true: mail passwords work only from the Hub's Local networks.
--rotate-key: replace mailctl's Stalwart API key.
Docker or rootless Podman only; rootless Podman needs
net.ipv4.ip_unprivileged_port_start=25. Needs a DNS provider Portcullis can
write.
EOF
}

help_mail_disable() {
  cat <<'EOF'
Usage: portcullis mail disable [--yes] [--force]

Drain every mail domain (MTA-STS mode none for its max_age, then the MX
goes) through the Hub, and remove mail from COMPOSE_PROFILES once the Hub
reports every domain off. --force removes it now (senders may bounce).
EOF
}

help_mail_status() { echo "Usage: portcullis mail status [--json]"; echo; echo "Mail status (certificate, DKIM, MTA-STS, DMARC, queue, checks)."; }
help_mail_test() { echo "Usage: portcullis mail test --to <address>"; echo; echo "Send a DKIM-signed test message from the first postmaster account (<user>@<primary domain>) and print its queue id."; }
help_mail_dkim() { echo "Usage: portcullis mail dkim rotate <domain>"; echo; echo "Make a new DKIM key pair for the domain now."; }
help_mail_cert() { echo "Usage: portcullis mail cert"; echo; echo "Issue or renew the mail certificate (renewal below 30 days); reloads Stalwart on a change."; }
help_mail_rotate() { echo "Usage: portcullis mail rotate [--next-key]"; echo; echo "The daily timer's step: certificate, DKIM / MTA-STS / TLSA state, the main domain's mail records."; echo "--next-key starts a mail key rollover (both TLSA records published; the timer switches after 2×TTL + 1 day)."; }
help_mail_schedule() { echo "Usage: portcullis mail schedule --systemd [--out DIR]"; echo; echo "Write portcullis-mail.service and .timer (daily) and print how to install them."; }
help_mail_export() { echo "Usage: portcullis mail export <former-id> [--out FILE]"; echo; echo "Export a former account's mailbox as mbox (0600) under backups/mail-export/."; }

cmd_mail() {
  local sub="${1:-}"
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_mail; [ -n "$sub" ] || exit 2; return 0 ;;
    enable|disable|status|test|dkim|cert|rotate|schedule|export) ;;
    *) usage_error mail "unknown subcommand: $sub" ;;
  esac
  local fn="help_mail_$sub" host="" lan="" yes=false force=false rotkey=false systemd=false out="" to="" json=false nextkey=""
  local -a pos=()
  while [ $# -gt 0 ]; do
    case "$sub:$1" in
      *:-h|*:--help) "$fn"; return 0 ;;
      enable:--hostname) need_value "mail enable" "$1" "${2:-}"; host="$2"; shift ;;
      enable:--lan-only) need_value "mail enable" "$1" "${2:-}"; lan="$2"; shift ;;
      enable:--rotate-key) rotkey=true ;;
      enable:--yes|disable:--yes) yes=true ;;
      disable:--force) force=true ;;
      rotate:--next-key) nextkey=--next-key ;;
      schedule:--systemd) systemd=true ;;
      schedule:--out|export:--out) need_value "mail $sub" "$1" "${2:-}"; out="$2"; shift ;;
      test:--to) need_value "mail test" "$1" "${2:-}"; to="$2"; shift ;;
      status:--json) json=true ;;
      *:-*) usage_error "mail $sub" "unknown option: $1" ;;
      *) pos+=("$1") ;;
    esac
    shift
  done
  local npos=${#pos[@]}
  case "$sub" in
    enable)
      [ "$npos" -eq 0 ] || usage_error "mail enable" "unexpected argument: ${pos[0]}"
      [ -z "$host" ] || [[ "$host" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || usage_error "mail enable" "--hostname must be a lowercase host name (e.g. mail.example.com)"
      case "$lan" in ""|true|false) ;; *) usage_error "mail enable" "--lan-only must be true or false" ;; esac ;;
    disable|cert|rotate)
      [ "$npos" -eq 0 ] || usage_error "mail $sub" "unexpected argument: ${pos[0]}" ;;
    status)
      [ "$npos" -eq 0 ] || usage_error "mail status" "unexpected argument: ${pos[0]}" ;;
    schedule)
      [ "$npos" -eq 0 ] || usage_error "mail schedule" "unexpected argument: ${pos[0]}"
      [ "$systemd" = true ] || usage_error "mail schedule" "--systemd is required (the only scheduler)" ;;
    test)
      [ "$npos" -eq 0 ] || usage_error "mail test" "unexpected argument: ${pos[0]}"
      [[ "$to" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || usage_error "mail test" "--to <address> is required" ;;
    dkim)
      [ "$npos" -eq 2 ] && [ "${pos[0]}" = rotate ] || usage_error "mail dkim" "expected: dkim rotate <domain>" ;;
    export)
      [ "$npos" -eq 1 ] || usage_error "mail export" "expected exactly one <former-id>"
      [[ "${pos[0]}" =~ ^former-[0-9a-f-]{36}$ ]] || usage_error "mail export" "invalid former id: ${pos[0]} (former-<uuid>)" ;;
  esac
  [ -f "$(env_file)" ] || fail "$(env_file) not found. Run ./portcullis init first."
  env_load
  # Refused before anything touches the runtime (contract §19.12, M9).
  mail_refuse_kube
  if [ "$sub" = enable ]; then
    mail_port_start_ok || fail "$(mail_port_start_text)"
    mail_lan_only_ok "${lan:-${MAIL_SUBMISSION_LAN_ONLY:-false}}"
  fi
  runtime_check
  case "$sub" in
    enable) MAIL_ROTATE_KEY="$rotkey" mail_enable "$host" "$lan" "$yes" ;;
    disable) mail_disable "$yes" "$force" ;;
    cert)
      mail_refuse_kube
      mail_profile_on || fail "mail is off: ./portcullis mail enable"
      mail_cert_ensure
      if [ "${MAIL_CERT_RENEWED:-false}" = true ] && rt_running mailctl; then rt_exec mailctl -- mailctl reload-tls || fail "mailctl reload-tls failed"; fi ;;
    rotate) mail_rotate "$nextkey" ;;
    schedule) mail_schedule_systemd "$out" ;;
    status) mail_status "$json" ;;
    test) mail_test "$to" ;;
    dkim) mail_dkim_rotate "${pos[1]}" ;;
    export) mail_export "${pos[0]}" "$out" ;;
  esac
}
