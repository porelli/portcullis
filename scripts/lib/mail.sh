# shellcheck shell=bash
#
# `portcullis mail …` — the mail slot (contract §19): core keeps the mail
# certificate (the domains image's one-shot mail-cert), TLSA and the HELO
# SPF (dns-tool, mail_acme/tlsa.json), LAN-only and the timer; the mail
# server is the wired provider, a Marketplace template instance the Hub
# drives. Every provider operation goes through the Hub's host control
# socket (`hub mail <command>` in the Hub container, its body on stdin);
# the CLI execs into no mail container except for `mail export`.
#
#   mail enable [--hostname H] [--lan-only true|false] [--provider stalwart|none] [--yes]
#   mail disable [--yes] [--force]
#   mail status [--json] | test --to A | dkim rotate <domain> | export <former-id> [--out F]
#   mail cert | rotate [--next-key] | schedule --systemd [--out DIR]
#
# Docker and rootless Podman only (Kubernetes is refused first). No secret
# goes through here: mail-cert's DNS credentials go on its stdin (jq
# env.X), the Hub keeps the provider's secrets.

MAIL_KUBE_REFUSED="mail isn't available on Kubernetes yet (Docker or rootless Podman only)"
MAIL_LAN_PODMAN_REFUSED="LAN-only needs the real client address; rootless Podman rewrites it"
MAIL_CERT_RENEW_DAYS=30
MAIL_HUB_WAIT="${MAIL_HUB_WAIT:-120}"
# The default provider (contract §19.10): the stalwart template from the
# default source; its instance id is the template id.
MAIL_DEFAULT_PROVIDER=stalwart
MAIL_DEFAULT_SOURCE=portcullis
MAIL_OFF_TEXT="mail is off: ./portcullis mail enable"

_mail_dir() { printf '%s/secrets/mail' "$PORTCULLIS_ROOT"; }

# _mail_set <key> <value> — .env (in place) and this shell (compose prefers
# the shell's value).
_mail_set() {
  env_set "$1" "$2"
  export "$1=$2"
}

# mail_hostname — MAIL_HOSTNAME, else mail.<main domain>.
mail_hostname() { printf '%s' "${MAIL_HOSTNAME:-mail.${PORTCULLIS_DOMAIN:-portcullis.local}}"; }

# mail_hostname_track — records MAIL_HOSTNAME changes (final review L7):
# secrets/mail/hostname is the one last used; when it differs from today's
# (mail enable --hostname, or .env edited by hand) the old one goes into
# secrets/mail/former-hostnames, the only hosts the dns tool may adopt as
# a former MAIL_HOSTNAME (its HELO SPF and TLSA then removed).
mail_hostname_track() {
  local d cur last
  d="$(_mail_dir)"
  cur="$(mail_hostname | tr '[:upper:]' '[:lower:]')"
  (umask 077 && mkdir -p "$d")
  last="$(cat "$d/hostname" 2>/dev/null || true)"
  if [ -n "$last" ] && [ "$last" != "$cur" ] && ! grep -qxF "$last" "$d/former-hostnames" 2>/dev/null; then
    (umask 077 && printf '%s\n' "$last" >> "$d/former-hostnames")
  fi
  [ "$last" = "$cur" ] || (umask 077 && printf '%s\n' "$cur" > "$d/hostname")
}

# mail_former_hosts_json — secrets/mail/former-hostnames as a JSON array.
mail_former_hosts_json() {
  jq -Rnc '[inputs | select(length > 0)]' 2>/dev/null < "$(_mail_dir)/former-hostnames" || echo '[]'
}

# mail_dkim_written_json — secrets/mail/dkim-written (the main domain's
# <selector>._domainkey names the mail set wrote) as a JSON array: the dns
# tool removes a stale DKIM record only when it is listed (a foreign one
# stays).
mail_dkim_written_json() {
  jq -Rnc '[inputs | select(length > 0)]' 2>/dev/null < "$(_mail_dir)/dkim-written" || echo '[]'
}

# mail_dkim_record <records JSON> — after a successful write of the main
# set: its <selector>._domainkey.<domain> TXT names added to
# secrets/mail/dkim-written.
mail_dkim_record() {
  local d f n
  d="$(printf '%s' "${PORTCULLIS_DOMAIN:-}" | tr '[:upper:]' '[:lower:]')"
  f="$(_mail_dir)/dkim-written"
  (umask 077 && mkdir -p "$(_mail_dir)" && touch "$f")
  while IFS= read -r n; do
    [ -n "$n" ] && ! grep -qxF "$n" "$f" && (umask 077 && printf '%s\n' "$n" >> "$f")
  done < <(printf '%s' "$1" | jq -r --arg d "$d" '.[]? | select((.type | ascii_upcase) == "TXT")
      | .name | ascii_downcase | rtrimstr(".") | select(endswith("._domainkey." + $d))
      | select(rtrimstr("._domainkey." + $d) | test("^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$"))' 2>/dev/null)
  return 0
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

# mail_tls_present — mail_tls holds a chain (fullchain.pem).
mail_tls_present() {
  _rt_docker_only
  docker volume inspect "$(_mail_volume mail_tls)" >/dev/null 2>&1 || return 1
  _mail_helper mail_tls /v ro "$CT_UID_DOMAINS:$CT_GID_MAIL_PROVIDER" test -s /v/fullchain.pem
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
  # MAIL_ACME_CA_SERVER: another CA for the mail certificate than Traefik's
  # (a testing knob; https only). Its CAA issuer domain is MAIL_CAA_ISSUER
  # (never DNS_CAA_ISSUER, which is Traefik's CA's): mail-cert pins it at
  # the hostname, and refuses with CAA on when it isn't known.
  local ca issuer
  if [ -n "${MAIL_ACME_CA_SERVER:-}" ]; then
    case "$MAIL_ACME_CA_SERVER" in
      https://?*) ;;
      *) fail "MAIL_ACME_CA_SERVER must be an https:// ACME directory URL" ;;
    esac
    ca="$MAIL_ACME_CA_SERVER" issuer="${MAIL_CAA_ISSUER:-}"
  else
    ca="$(_dns_ca_server)" issuer="${MAIL_CAA_ISSUER:-${DNS_CAA_ISSUER:-}}"
  fi
  jq -n --arg host "$(mail_hostname)" --arg ca "$ca" --arg email "${ACME_EMAIL:-admin@${PORTCULLIS_DOMAIN}}" \
    --arg provider "$provider" --argjson map "$map" --argjson caa "$caa" --arg issuer "$issuer" \
    --arg iodef "${DNS_CAA_IODEF:-}" --argjson days "$MAIL_CERT_RENEW_DAYS" '
    {hostname: $host, ca_server: $ca, email: $email, provider: $provider,
     credentials: ($map | map({key: .key, value: env[.var]}) | from_entries),
     caa: {enabled: $caa, issuer: $issuer, iodef: $iodef}, renew_below_days: $days}'
}

# mail_cert_ensure [--switch-key] — run mail-cert (issue / renew below 30
# days; --switch-key: issue with the next key, the TLSA rollover's switch);
# sets MAIL_CERT_RENEWED=true|false, MAIL_CERT_SPKI (the key's sha256 SPKI,
# hex) and MAIL_CERT_NOT_AFTER. Its output line has no secret.
mail_cert_ensure() {
  local input out
  _rt_docker_only
  input="$(_mail_cert_input)" || exit 1
  domains_image_ensure "for the mail certificate"
  volume_own mail_tls "$CT_UID_DOMAINS:$CT_GID_MAIL_PROVIDER" 2750
  volume_own mail_acme "$CT_UID_DOMAINS:$CT_UID_DOMAINS" 0700
  info "Mail certificate for $(mail_hostname)..."
  out="$(printf '%s' "$input" | rt_run mail-cert -i -- "$@")" || fail "the mail certificate could not be issued (see above)"
  out="$(printf '%s' "$out" | tail -n1)"
  # shellcheck disable=SC2034  # read by the callers
  MAIL_CERT_RENEWED="$(printf '%s' "$out" | jq -r '.renewed // false' 2>/dev/null || echo false)"
  # shellcheck disable=SC2034
  MAIL_CERT_SPKI="$(printf '%s' "$out" | jq -r '.spki_sha256 // ""' 2>/dev/null || true)"
  MAIL_CERT_NOT_AFTER="$(printf '%s' "$out" | jq -r '.not_after // ""' 2>/dev/null || true)"
  printf '%s' "$out" | jq -r '"    not after \(.not_after // "?"), renewed: \(.renewed)"' 2>/dev/null || true
}

# _mail_tlsa <status|next|switch|drop> — `domains mail-tlsa` in the
# mail-cert one-shot (mail_acme's tlsa.json and keys, no credentials): its
# JSON on stdout (contract §19.3). --hostname: the switch checks the next
# key's TLSA at <hostname>'s authoritative servers (Ruling R-H4).
_mail_tlsa() {
  rt_run mail-cert --entrypoint domains -- mail-tlsa "$1" --hostname "$(mail_hostname)" </dev/null
}

# _mail_cert_metric <not_after> — portcullis_mail_cert_expiry_seconds
# through the textfile exporter (contract §19.8; MailCertExpiring; 0 =
# unknown, which the alert catches).
_mail_cert_metric() {
  local na="$1" ts d="$PORTCULLIS_ROOT/monitoring/textfile"
  ts="$(jq -rn --arg t "$na" '$t | fromdateiso8601' 2>/dev/null)" || ts=0
  [ -n "$ts" ] || ts=0
  mkdir -p "$d"
  {
    echo "# HELP portcullis_mail_cert_expiry_seconds Unix time the mail certificate expires (0 = unknown)."
    echo "# TYPE portcullis_mail_cert_expiry_seconds gauge"
    echo "portcullis_mail_cert_expiry_seconds $ts"
  } > "$d/mail_cert.prom.tmp"
  mv "$d/mail_cert.prom.tmp" "$d/mail_cert.prom"
}

# ── the Hub (contract §19.10) ──

# _mail_hub <command> [body] — `hub mail <command>` in the Hub container
# (its host control socket), the JSON body (if any) on stdin; the answer
# on stdout, exit 0 / 1 (a refusal, its text on stderr) / 2.
_mail_hub() {
  local cmd="$1" body="${2:-}"
  if [ -n "$body" ]; then
    printf '%s' "$body" | rt_exec -i hub -- hub mail "$cmd"
  else
    rt_exec -i hub -- hub mail "$cmd" </dev/null
  fi
}

# _mail_not_wired <rc> <stderr> — exactly the Hub's 409 "no mail provider
# is wired" (exit 1, the whole trimmed text): nothing is wired. Any other
# refusal or error is not this.
_mail_not_wired() {
  [ "$1" = 1 ] && [ "$(printf '%s' "$2" | tr -d '\r' | sed -e 's/^[[:space:]]*//;s/[[:space:]]*$//')" = "no mail provider is wired" ]
}

# _mail_hub_op <command> <body> — `hub mail <command>` that starts a Hub
# op (install, unwire, restore: the answer {op_id, op, instance, poll}),
# then `hub mail op` {instance, op_id} every MAIL_OP_POLL s until the
# op's record is no longer running (Ruling R-H6), at most MAIL_OP_WAIT s.
# Returns 0 only when the record says ok; 1 on a refusal (its text on
# stderr unless MAIL_HUB_QUIET=1; MAIL_HUB_ERR / MAIL_HUB_RC), a failed or another op's record,
# or the wait running out. The start's answer goes to stdout.
_mail_hub_op() {
  local cmd="$1" body="$2" out errf rc=0 id inst rec t0=$SECONDS
  MAIL_HUB_ERR="" MAIL_HUB_RC=0
  errf="$(mktemp)"
  out="$(_mail_hub "$cmd" "$body" 2>"$errf")" || rc=$?
  MAIL_HUB_ERR="$(cat "$errf")"; MAIL_HUB_RC=$rc
  rm -f "$errf"
  if [ "$rc" != 0 ]; then
    [ "${MAIL_HUB_QUIET:-}" = 1 ] || [ -z "$MAIL_HUB_ERR" ] || printf '%s\n' "$MAIL_HUB_ERR" >&2
    return 1
  fi
  id="$(printf '%s' "$out" | jq -r '.op_id | strings' 2>/dev/null)"
  inst="$(printf '%s' "$out" | jq -r '.instance | strings' 2>/dev/null)"
  if [ -z "$id" ] || [ -z "$inst" ]; then
    warn "hub mail $cmd started no op (no op_id / instance in its answer)"
    return 1
  fi
  printf '%s\n' "$out"
  while :; do
    rec="$(_mail_hub op "$(jq -cn --arg i "$inst" --arg o "$id" '{instance: $i, op_id: $o}')" 2>/dev/null)" || rec=""
    if printf '%s' "$rec" | jq -e --arg o "$id" '.op_id == $o and .running == false' >/dev/null 2>&1; then
      printf '%s' "$rec" | jq -e '.ok == true' >/dev/null 2>&1 && return 0
      warn "the Hub's $cmd op $id failed: $(printf '%s' "$rec" | jq -r '.error // "no error given"' 2>/dev/null)"
      return 1
    fi
    if printf '%s' "$rec" | jq -e --arg o "$id" '(.op_id | strings) != $o' >/dev/null 2>&1; then
      warn "hub mail op answered another op than $id"
      return 1
    fi
    if [ $((SECONDS - t0)) -ge "${MAIL_OP_WAIT:-1800}" ]; then
      warn "the Hub's $cmd op $id still runs after ${MAIL_OP_WAIT:-1800} s: ./portcullis mail status"
      return 1
    fi
    sleep "${MAIL_OP_POLL:-2}"
  done
}

# _mail_hub_wait — `hub mail provider`'s answer, waiting up to
# MAIL_HUB_WAIT seconds for the Hub to answer (it answers while its health
# is still starting right after an up). A Hub missing or stopped is
# refused at once; one that never answers after the wait.
_mail_hub_wait() {
  local st out start=$SECONDS
  while :; do
    st="$(rt_health hub)"
    case "$st" in
      healthy|running|starting|restarting) ;;
      *) fail "the Hub isn't running (state: $st): ./portcullis up first" ;;
    esac
    if out="$(_mail_hub provider 2>/dev/null)" && printf '%s' "$out" | jq -e 'type == "object"' >/dev/null 2>&1; then
      printf '%s' "$out"
      return 0
    fi
    [ $((SECONDS - start)) -lt "$MAIL_HUB_WAIT" ] || fail "the Hub didn't answer hub mail provider within $MAIL_HUB_WAIT s (state: $st): docker compose logs hub"
    sleep 2
  done
}

# _mail_tls_post <tlsa status JSON> — the SPKIs the TLSA publishes and
# the certificate's not_after to the Hub (`hub mail tls`, contract §19.3):
# it records them and the timer's visit, and reloads a wired provider; it
# exits 0 only when the key the provider serves is one of them (M3).
_mail_tls_post() {
  local body
  body="$(printf '%s' "$1" | jq -ce --arg na "${MAIL_CERT_NOT_AFTER:-}" '{spki_sha256: .publish, not_after: $na}')" || fail "domains mail-tlsa status printed no keys"
  _mail_hub tls "$body" >/dev/null || fail "the Hub refused the mail certificate's keys (hub mail tls)"
}

# _mail_dns_main — `hub mail dns-main` (contract §19.7): MAIL_MAIN_RECS
# (the provider's validated records) and MAIL_MAIN_RULES ({relay_include,
# dmarc_floor, draining}: the shared rules' inputs, re-checked by the dns
# tool). 0 = read; 3 = exactly the Hub's "no mail provider is wired"; 1 =
# any other failure (its text on stderr).
_mail_dns_main() {
  local out errf rc=0 err
  MAIL_MAIN_RECS="" MAIL_MAIN_RULES=""
  errf="$(mktemp)"
  out="$(_mail_hub dns-main 2>"$errf")" || rc=$?
  err="$(cat "$errf")"; rm -f "$errf"
  if [ "$rc" != 0 ]; then
    _mail_not_wired "$rc" "$err" && return 3
    [ -z "$err" ] || printf '%s\n' "$err" >&2
    return 1
  fi
  MAIL_MAIN_RECS="$(printf '%s' "$out" | jq -ce '.records | arrays' 2>/dev/null)" || { warn "hub mail dns-main answered no records"; return 1; }
  MAIL_MAIN_RULES="$(printf '%s' "$out" | jq -ce '.rules | select(type == "object" and (.relay_include | type) == "string"
      and (.dmarc_floor | IN("none", "quarantine", "reject")) and (.draining | type) == "boolean")
    | {relay_include, dmarc_floor, draining}' 2>/dev/null)" || { MAIL_MAIN_RECS=""; warn "hub mail dns-main answered no rules {relay_include, dmarc_floor, draining}"; return 1; }
  return 0
}

# _mail_withdraw_main — the main domain's mail set removed (with
# DNS_NOMAIL=true the null-mail records come back in the same run: never
# a window without SPF -all, DMARC and the null MX). 1 when it fails.
_mail_withdraw_main() {
  local sets=mail
  _dns_automated "${DNS_PROVIDER:-none}" || { warn "No automatic DNS for provider '${DNS_PROVIDER:-none}': remove the main domain's mail records by hand (./portcullis dns plan)."; return 0; }
  [ "$(_dns_flag DNS_NOMAIL false)" != true ] || sets="nomail mail"
  DNS_SETS="$sets" DNS_MAIL_RECORDS='[]' DNS_MAIL_TLSA='' DNS_MAIL_RULES='' _dns_tool apply >/dev/null
}

# _mail_main_set <tlsa status JSON> — the main domain's mail set through
# the dns tool: the provider's records and rules (`hub mail dns-main`,
# validated by the Hub, re-checked by the tool) plus core's HELO SPF and,
# while secure, the TLSA. Exactly nothing wired: the set is withdrawn
# (spec §5.3: the timer's next pass after an unwire). Any other Hub
# failure fails (the published records stay; H5).
_mail_main_set() {
  local rc=0
  _mail_dns_main || rc=$?
  case "$rc" in
    0) ;;
    3)
      _mail_withdraw_main || fail "no mail provider is wired, and the main domain's mail records could not be withdrawn"
      info "No mail provider is wired: the main domain's mail records are withdrawn."
      return 0 ;;
    *) fail "the Hub didn't give the main domain's mail set (hub mail dns-main, see above): the published records are left as they are" ;;
  esac
  if ! _dns_automated "${DNS_PROVIDER:-none}"; then
    warn "No automatic DNS for provider '${DNS_PROVIDER:-none}': ./portcullis dns plan shows the mail records to create by hand."
    return 0
  fi
  DNS_SETS=mail DNS_MAIL_RECORDS="$MAIL_MAIN_RECS" DNS_MAIL_RULES="$MAIL_MAIN_RULES" DNS_MAIL_TLSA="$(printf '%s' "$1" | jq -c '.publish // []')" _dns_tool apply >/dev/null \
    || fail "the main domain's mail records could not be written"
  mail_dkim_record "$MAIL_MAIN_RECS"
}

# mail_ipv6_refuse — IPv6 for mail isn't supported yet: [::] ports onto an
# IPv4-only network go through docker-proxy, which rewrites the client
# address (LAN-only, SPF and the blocklists would judge the proxy). A set
# MAIL_IPV6 is refused, never ignored.
mail_ipv6_refuse() {
  [ -z "${MAIL_IPV6:-}" ] || fail "MAIL_IPV6 isn't supported yet: remove it from .env"
}

# mail_up_steps <up|upgrade> — called by `up` and `upgrade` (before the
# stack starts) with the slot open: the refusals, the hostname record, the
# certificate when mail_tls has none.
mail_up_steps() {
  mail_slot_open || return 0
  mail_refuse_kube
  _rt_docker_only
  mail_port_start_ok || fail "$(mail_port_start_text)"
  mail_lan_only_ok "${MAIL_SUBMISSION_LAN_ONLY:-false}"
  mail_ipv6_refuse
  mail_hostname_track
  mail_tls_present || mail_cert_ensure
}

# mail_enable <hostname> <lan_only> <provider> <yes> — open the slot
# (contract §19.1) and, unless provider is none, install and wire the
# provider after the operator typed its instance id (--yes: accepted).
mail_enable() {
  local host="$1" lan="$2" provider="$3" yes="$4" pinfo st id typed
  mail_refuse_kube
  _rt_docker_only
  mail_port_start_ok || fail "$(mail_port_start_text)"
  require_cmd docker jq
  _dns_automated "${DNS_PROVIDER:-none}" || fail "mail needs a DNS provider Portcullis can write (see setup/mail.md): DNS_PROVIDER=${DNS_PROVIDER:-none}"
  mail_lan_only_ok "${lan:-${MAIL_SUBMISSION_LAN_ONLY:-false}}"
  mail_ipv6_refuse
  [ -z "$host" ] || _mail_set MAIL_HOSTNAME "$host"
  mail_hostname_track
  [ -z "$lan" ] || _mail_set MAIL_SUBMISSION_LAN_ONLY "$lan"
  _mail_set PORTCULLIS_MAIL on
  runtime_check
  rt_network_check
  stack_prepare
  info "Mail slot for $(mail_hostname) (client addresses: $(_rt_is_podman && echo rewritten || echo preserved))"
  mail_cert_ensure
  st="$(_mail_tlsa status)" || fail "the mail certificate's TLSA state couldn't be read (domains mail-tlsa status)"
  _mail_cert_metric "${MAIL_CERT_NOT_AFTER:-}"
  hub_env_write
  # The Hub (core.env: the slot open) and domains (its env file: the main
  # plan owns MAIL_HOSTNAME's address).
  stack_compose_up hub domains
  pinfo="$(_mail_hub_wait)"
  _mail_tls_post "$st"
  if [ "$provider" = none ]; then
    ok "The mail slot is open; no provider wired (--provider none): wire one in the Hub (the instance's Mail tab or Settings → Mail)."
  elif [ "$(printf '%s' "$pinfo" | jq -r --arg t "$provider" '.wired == true and .template == $t')" = true ]; then
    ok "$(printf '%s' "$pinfo" | jq -r '.instance') is already this server's mail provider."
  else
    id="$provider"
    printf '\n%s\n\n' "$(printf '%s' "$pinfo" | jq -r '.warning')"
    if [ "$yes" = true ]; then
      typed="$id"
    else
      [ -t 0 ] || fail "type the instance id to confirm: run this on a terminal, or pass --yes"
      printf 'Type the instance id (%s) to make it the mail server: ' "$id"
      IFS= read -r typed || typed=""
    fi
    [ "$typed" = "$id" ] || fail "type the instance id to confirm"
    _mail_hub_op install "$(jq -cn --arg t "$provider" --arg s "$MAIL_DEFAULT_SOURCE" --arg c "$typed" '{template: $t, source: $s, confirm: $c}')" >/dev/null \
      || fail "the Hub didn't wire $provider (see above): ./portcullis mail status"
    ok "$id is this server's mail provider."
  fi
  ok "Mail is on. DNS: ./portcullis dns setup ($(mail_hostname)'s address now; the mail records once the provider has its first document, then the daily timer keeps them); status: ./portcullis mail status"
  if [ "$yes" = true ] || confirm "Install the daily mail timer (certificate, TLSA, the main domain's records) now?"; then
    mail_schedule_systemd ""
  fi
}

# mail_disable <yes> <force> — unwire through the Hub (drain unless
# --force), and close the slot once the Hub reports every domain off.
mail_disable() {
  local yes="$1" force="$2" doms off drain=true
  mail_refuse_kube
  mail_slot_open || { ok "Mail is already off."; return 0; }
  if [ "$yes" != true ] && ! confirm "Turn mail off for every domain and unwire the mail provider?"; then
    fail "Aborted."
  fi
  [ "$force" != true ] || drain=false
  _mail_hub_wait >/dev/null
  # Nothing wired is exactly the Hub's 409 "no mail provider is wired":
  # already unwired (any other refusal or error fails).
  # The unwire op is waited for to its end (Ruling R-H6): the slot never
  # closes while it runs, and a failed op keeps it open.
  if ! MAIL_HUB_QUIET=1 _mail_hub_op unwire "$(jq -cn --argjson d "$drain" '{drain: $d}')" >/dev/null; then
    if [ "$MAIL_HUB_RC" != 0 ] && _mail_not_wired "$MAIL_HUB_RC" "$MAIL_HUB_ERR"; then
      info "No mail provider is wired (already unwired)."
    else
      [ -z "$MAIL_HUB_ERR" ] || printf '%s\n' "$MAIL_HUB_ERR" >&2
      fail "the Hub didn't unwire the mail provider (see above): the slot stays open"
    fi
  fi
  if [ "$force" != true ]; then
    doms="$(_mail_hub domains)" || fail "the Hub didn't answer hub mail domains"
    off="$(printf '%s' "$doms" | jq -r 'if type == "array" and all(.[]; .state == "off") then "yes" else "no" end' 2>/dev/null || echo no)"
    if [ "$off" != yes ]; then
      ok "Every mail domain is draining: senders get MTA-STS mode none for its max_age (up to 7 days), then the MX goes and the Hub unwires the provider."
      echo "    Run ./portcullis mail disable again once ./portcullis mail status says every domain is off."
      return 0
    fi
  else
    warn "--force: mail goes now; senders with a cached MTA-STS policy may bounce mail until its max_age."
  fi
  # The main domain's mail set goes, and with DNS_NOMAIL=true the null-mail
  # records come back in the same run (never a window without SPF -all,
  # DMARC and the null MX).
  _mail_withdraw_main || warn "the main domain's mail records could not be removed: run ./portcullis dns setup"
  _mail_set PORTCULLIS_MAIL off
  # The certificate metric goes with the slot (MailCertExpiring must not
  # fire for a closed slot; L11).
  rm -f "$PORTCULLIS_ROOT/monitoring/textfile/mail_cert.prom"
  hub_env_write
  _mail_domains_flag_off
  if rt_running hub; then rt_up_service hub >/dev/null 2>&1 || warn "could not restart the Hub with the slot closed: ./portcullis up"; fi
  ok "Mail is off (the provider instance and its data are kept; the slot's networks and mail_slot stay)."
  # Left in DNS on purpose (harmless: the A still names this server, the
  # CAA only restricts issuance); the admin may delete them by hand.
  info "Kept in DNS: $(mail_hostname)'s A / AAAA record and its CAA pin (mail-cert's); delete them by hand if no mail will come back."
  if [ "$(_mail_timer_state)" = active ]; then
    info "The daily mail timer is still installed: systemctl$(_rt_is_podman && echo " --user") disable --now portcullis-mail.timer (it fails every day while mail is off)."
  fi
}

# mail_rotate [--next-key] — the daily timer's step (contract §19.3):
# mail-cert (renewal below 30 days), the TLSA rollover step that is due
# (--next-key starts one: both SPKIs published), the keys to the Hub (it
# reloads the provider), the certificate metric, then the main domain's
# set through the dns tool.
mail_rotate() {
  local st out due
  mail_refuse_kube
  mail_slot_open || fail "$MAIL_OFF_TEXT"
  _rt_docker_only
  mail_cert_ensure
  if [ "${1:-}" = --next-key ]; then
    out="$(rt_run mail-cert -- --next-key </dev/null)" || fail "mail-cert --next-key failed"
    _mail_tlsa next >/dev/null || fail "the next key couldn't be recorded (domains mail-tlsa next)"
    info "Next mail key $(printf '%s' "$out" | tail -n1 | jq -r '.spki_sha256 // "?"'): published next to the current one; the switch follows after 2×TTL + 1 day."
  fi
  st="$(_mail_tlsa status)" || fail "the mail certificate's TLSA state couldn't be read (domains mail-tlsa status)"
  due="$(printf '%s' "$st" | jq -r '.due // ""')"
  if [ "$due" = switch ]; then
    info "Switching the mail certificate to the next key (TLSA rollover)..."
    _mail_tlsa switch >/dev/null || fail "domains mail-tlsa switch refused"
    mail_cert_ensure --switch-key
    st="$(_mail_tlsa status)" || fail "domains mail-tlsa status failed after the switch"
  elif [ "$due" = drop ]; then
    # The drop is committed only after the Hub confirmed the provider
    # serves the key that stays (hub mail tls exits 0 only then; M3).
    _mail_hub_wait >/dev/null
    _mail_tls_post "$(printf '%s' "$st" | jq -c '{publish: [.current | strings]}')"
    st="$(_mail_tlsa drop)" || fail "domains mail-tlsa drop failed"
  fi
  printf '%s' "$st" | jq -r '"    TLSA: \(.phase), publishing \(.publish | length) key(s)"' 2>/dev/null || true
  _mail_cert_metric "${MAIL_CERT_NOT_AFTER:-}"
  _mail_hub_wait >/dev/null
  _mail_tls_post "$st"
  _mail_main_set "$st"
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
Description=Portcullis mail rotation (certificate, TLSA, the main domain mail records)
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

# ── status, test, actions, export (contract §19.10) ──

# _mail_timer_state — portcullis-mail.timer: active | inactive | unknown
# (no systemd here). Podman installs it as the operator's user unit.
_mail_timer_state() {
  local scope=()
  command -v systemctl >/dev/null 2>&1 || { echo unknown; return 0; }
  ! _rt_is_podman || scope=(--user)
  if systemctl "${scope[@]}" is-active --quiet portcullis-mail.timer 2>/dev/null; then echo active; else echo inactive; fi
}

# mail_status_json — the mail block of status (nothing with the slot
# closed): the Hub's view (`hub mail status`: the provider, the document,
# its checks, the void and the hold) plus core's own rows: the
# certificate's expiry (the textfile metric mail rotate writes), the
# timer, the TLSA state, the client-address mode. `problem` when the Hub
# doesn't answer, nothing is wired, a void is owed, the provider is held
# or unreachable, the expiry is unknown, or a check is a Problem.
mail_status_json() {
  local hub="" tlsa="" exp="" f
  mail_slot_open || return 0
  hub="$(_mail_hub status 2>/dev/null)" || hub=""
  printf '%s' "$hub" | jq -e 'type == "object"' >/dev/null 2>&1 || hub=""
  tlsa="$(_mail_tlsa status 2>/dev/null)" || tlsa=""
  printf '%s' "$tlsa" | jq -e 'type == "object"' >/dev/null 2>&1 || tlsa=""
  f="$PORTCULLIS_ROOT/monitoring/textfile/mail_cert.prom"
  [ ! -f "$f" ] || exp="$(awk '$1 == "portcullis_mail_cert_expiry_seconds" {print $2}' "$f")"
  jq -cn --arg hub "$hub" --arg tlsa "$tlsa" --arg exp "${exp:-0}" --arg timer "$(_mail_timer_state)" \
    --arg cip "$(_rt_is_podman && echo rewritten || echo preserved)" --arg host "$(mail_hostname)" \
    --argjson lan "$([ "${MAIL_SUBMISSION_LAN_ONLY:-false}" = true ] && echo true || echo false)" '
    # void_owed / held: null or an object (the interface); false = none,
    # any other non-object value = owed / held with no detail (M7).
    def owed: if type == "object" then . elif . == null or . == false then null else {} end;
    ($hub | if . == "" then null else (fromjson | .void_owed |= owed | .held |= owed) end) as $h
    | ($exp | tonumber? // 0) as $e
    | {enabled: true, hostname: $host, hub: $h, timer: $timer, client_ip: $cip, lan_only: $lan,
       cert: {not_after: (if $e > 0 then ($e | todate) else null end)},
       tlsa: ($tlsa | if . == "" then null else (fromjson | {phase, due, publish}) end)}
    | .problem = (.hub == null or (.hub.wired != true) or (.hub.reachable == false)
                  or (.hub.void_owed != null) or (.hub.held != null) or .cert.not_after == null
                  or ([(.hub.checks.checks // [])[] | select(.severity == "problem")] | length) > 0)'
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
    (if .hub == null then ["fail", "the Hub didn'"'"'t answer hub mail status (./portcullis up)"]
     elif .hub.wired != true then ["fail", "no mail provider is wired: wire one in the Hub (Settings → Mail)"]
     else ["ok", "provider \(.hub.instance // "?") (\(.hub.label // .hub.template // "?")\(if .hub.version then " " + .hub.version else "" end))"] end),
    (if .hub.void_owed != null then ["fail", "a void of every mail password is owed (\(.hub.void_owed.reason // "?" | tostring)): the provider stays in void mode until it succeeds"] else empty end),
    (if .hub.held != null then ["fail", "the mail provider'"'"'s template changed: review and confirm on its Mail tab"] else empty end),
    (if .hub != null and .hub.wired == true and .hub.reachable == false then ["fail", "the mail provider isn'"'"'t reachable"] else empty end),
    (if .hub.generation != null then ["ok", "the Hub'"'"'s document: generation \(.hub.generation), applied \(.hub.applied_generation // "?")"] else empty end),
    ((.hub.checks.checks // [])[] | select(.severity != "ok") | [(.severity | sev), "check \(.id): \(.detail)"]),
    (if .cert.not_after == null then ["fail", "the mail certificate'"'"'s expiry is unknown: ./portcullis mail rotate"]
     else ["ok", "certificate \(.hostname) valid until \(.cert.not_after)"] end),
    (if .tlsa == null then ["warn", "the TLSA state couldn'"'"'t be read (domains mail-tlsa status)"]
     else [(if .tlsa.due != null then "note" else "ok" end), "TLSA: \(.tlsa.phase), \(.tlsa.publish | length) key(s)" + (if .tlsa.due != null then " (\(.tlsa.due) due at the next mail rotate)" else "" end)] end),
    (if .timer == "active" then ["ok", "daily timer portcullis-mail.timer active"]
     elif .timer == "inactive" then ["warn", "daily timer portcullis-mail.timer missing or inactive: ./portcullis mail schedule --systemd (certificate renewal, TLSA)"]
     else ["note", "daily timer: unknown (no systemd here)"] end),
    (if .client_ip == "rewritten" then ["warn", "client addresses rewritten (rootless Podman): SPF, iprev and the IP blocklists are off"] else ["ok", "client addresses preserved"] end),
    (if .lan_only then ["ok", "submission and IMAPS: Local networks only (LAN-only)"] else empty end)
    | @tsv')
}

# mail_status <json> — `mail status [--json]`; exit 1 on a problem.
mail_status() {
  local j
  mail_slot_open || fail "$MAIL_OFF_TEXT"
  j="$(mail_status_json)"
  if [ "$1" = true ]; then printf '%s\n' "$j"; else mail_status_lines "$j"; echo; fi
  [ "$(printf '%s' "$j" | jq -r .problem)" != true ]
}

# mail_test <to> — the provider's test action (`hub mail test`): a message
# from the first postmaster account, signed by the primary domain's DKIM.
mail_test() {
  local to="$1" out
  mail_slot_open || fail "$MAIL_OFF_TEXT"
  out="$(_mail_hub test "$(jq -cn --arg t "$to" '{to: $t}')")" || fail "the test message could not be sent (see above)"
  ok "Queued for $to: $(printf '%s' "$out" | jq -r '.queue_id // "?"')"
  echo "    Open the message's headers (\"Show original\" / \"View source\") and check Authentication-Results:"
  echo "    dkim=pass, spf=pass and dmarc=pass mean receivers can verify mail from this server."
}

# mail_dkim_rotate <domain> — the provider's dkim-rotate action now.
mail_dkim_rotate() {
  local d="$1"
  mail_slot_open || fail "$MAIL_OFF_TEXT"
  _mail_hub action "$(jq -cn --arg d "$d" '{name: "dkim-rotate", domain: $d}')" >/dev/null || fail "DKIM rotation of $d refused (see above)"
  ok "$d: a new DKIM key is being made"
  if [ "$d" = "${PORTCULLIS_DOMAIN:-}" ]; then
    echo "    The main domain's records follow at the next ./portcullis mail rotate (or ./portcullis dns setup --only mail)."
  else
    echo "    The Hub publishes the new TXT records for $d."
  fi
}

# _mail_instance_exec <instance> <service> <argv…> — exec argv (an array,
# never through a shell) in the running container of the instance's
# service, its stdout through.
_mail_instance_exec() {
  local inst="$1" svc="$2" cid
  shift 2
  _rt_docker_only
  cid="$(docker ps -q --filter "label=com.docker.compose.project=portcullis-$inst" --filter "label=com.docker.compose.service=$svc" --filter status=running | head -n1)"
  [ -n "$cid" ] || fail "the mail provider's $svc isn't running ($inst)"
  docker exec -i "$cid" "$@"
}

# mail_export <former-id> <out> — a former account's mailbox as mbox
# (0600) under backups/mail-export/ (or <out>): the wired block's
# export.argv ({former_id} replaced as one argv element, never a shell) in
# export.service; message content never passes through the Hub.
mail_export() {
  local id="$1" out="$2" dir tmp pinfo inst svc n i a
  local -a argv=()
  mail_slot_open || fail "$MAIL_OFF_TEXT"
  pinfo="$(_mail_hub provider)" || fail "the Hub didn't answer hub mail provider"
  [ "$(printf '%s' "$pinfo" | jq -r '.wired == true')" = true ] || fail "no mail provider is wired"
  [ "$(printf '%s' "$pinfo" | jq -r '.export != null')" = true ] || fail "the mail provider has no export"
  inst="$(printf '%s' "$pinfo" | jq -r '.instance')"
  svc="$(printf '%s' "$pinfo" | jq -r '.export.service')"
  [[ "$inst" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] && [[ "$svc" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$ ]] || fail "the Hub's export answer is malformed"
  n="$(printf '%s' "$pinfo" | jq -r '.export.argv | if type == "array" and all(.[]; type == "string") then length else -1 end')"
  [ "$n" -ge 1 ] || fail "the Hub's export argv is malformed"
  for ((i = 0; i < n; i++)); do
    a="$(printf '%s' "$pinfo" | jq -r --argjson i "$i" '.export.argv[$i]')"
    [ "$a" != "{former_id}" ] || a="$id"
    argv+=("$a")
  done
  if [ -z "$out" ]; then
    dir="$PORTCULLIS_ROOT/backups/mail-export"
    (umask 077 && mkdir -p "$dir")
    chmod 700 "$dir"
    out="$dir/$id-$(date -u +%Y%m%dT%H%M%SZ).mbox"
  fi
  [ ! -e "$out" ] || fail "$out exists: choose another --out"
  tmp="$out.part"
  if ! (umask 077 && _mail_instance_exec "$inst" "$svc" "${argv[@]}" > "$tmp"); then
    rm -f "$tmp"
    fail "the export of $id failed (see above)"
  fi
  chmod 600 "$tmp"
  mv "$tmp" "$out"
  ok "Exported $id to $out ($(grep -c '^From ' "$out" 2>/dev/null || true) messages, mode 0600)."
}

# _mail_domains_flag_off — the domains service's env file says mail is
# off at once (final review L6: not only at the next up), and a running
# domains service is recreated with it (its main plan stops owning
# MAIL_HOSTNAME's address).
_mail_domains_flag_off() {
  local f
  f="$(_domains_dir)/public-ips.env"
  [ -f "$f" ] && grep -qx 'DOMAINS_MAIL=on' "$f" || return 0
  (umask 077 && sed 's/^DOMAINS_MAIL=on$/DOMAINS_MAIL=off/' "$f" > "$f.tmp" && cat "$f.tmp" > "$f"); rm -f "$f.tmp"
  if rt_running domains; then
    rt_up_service domains >/dev/null 2>&1 || warn "could not recreate the domains service with mail off: ./portcullis up"
  fi
}

help_mail() {
  cat <<'EOF'
Usage: portcullis mail <subcommand>

  enable        Open the mail slot (certificate) and wire the mail provider
  disable       Unwire the provider (drains every domain first) and close the slot
  status        Mail status: the provider, its checks, the certificate, TLSA, the timer
  test          Send a signed test message from the postmaster account
  dkim          dkim rotate <domain>: a new DKIM key now
  cert          Issue or renew the mail certificate (below 30 days)
  rotate        The daily step: certificate, TLSA, the main domain's records
  schedule      schedule --systemd: install the daily timer
  export        Export a former account's mailbox as mbox

Run 'portcullis mail <subcommand> --help' for details.
EOF
}

help_mail_enable() {
  cat <<'EOF'
Usage: portcullis mail enable [--hostname H] [--lan-only true|false] [--provider stalwart|none] [--yes]

Open the mail slot (contract §19.1): writes PORTCULLIS_MAIL=on,
MAIL_HOSTNAME (default mail.<domain>) and MAIL_SUBMISSION_LAN_ONLY, issues
the mail certificate through your DNS provider (mail-cert), restarts the
Hub with the slot open, then, unless --provider none, prints what the
provider may do and installs and wires it (default stalwart) once you type
its instance id (--yes accepts it). Idempotent.
--lan-only true: mail passwords work only from the Hub's Local networks.
Docker or rootless Podman only; rootless Podman needs
net.ipv4.ip_unprivileged_port_start=25. Needs a DNS provider Portcullis can
write.
EOF
}

help_mail_disable() {
  cat <<'EOF'
Usage: portcullis mail disable [--yes] [--force]

Unwire the mail provider through the Hub: every mail domain drains first
(MTA-STS mode none for its max_age, then the MX goes); once the Hub
reports every domain off, the slot is closed (PORTCULLIS_MAIL=off).
--force unwires now (senders may bounce). The provider instance and its
data are kept.
EOF
}

help_mail_status() { echo "Usage: portcullis mail status [--json]"; echo; echo "Mail status: the provider and its checks (the Hub), the certificate, TLSA, the timer, the client-address mode."; }
help_mail_test() { echo "Usage: portcullis mail test --to <address>"; echo; echo "Send a DKIM-signed test message from the first postmaster account and print its queue id."; }
help_mail_dkim() { echo "Usage: portcullis mail dkim rotate <domain>"; echo; echo "Make a new DKIM key pair for the domain now (the provider's dkim-rotate action)."; }
help_mail_cert() { echo "Usage: portcullis mail cert"; echo; echo "Issue or renew the mail certificate (renewal below 30 days); the Hub reloads the provider on a change."; }
help_mail_rotate() { echo "Usage: portcullis mail rotate [--next-key]"; echo; echo "The daily timer's step: certificate, the TLSA rollover, the main domain's mail records."; echo "--next-key starts a mail key rollover (both TLSA records published; the timer switches after 2×TTL + 1 day)."; }
help_mail_schedule() { echo "Usage: portcullis mail schedule --systemd [--out DIR]"; echo; echo "Write portcullis-mail.service and .timer (daily) and print how to install them."; }
help_mail_export() { echo "Usage: portcullis mail export <former-id> [--out FILE]"; echo; echo "Export a former account's mailbox as mbox (0600) under backups/mail-export/ (the provider's export command)."; }

cmd_mail() {
  local sub="${1:-}"
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_mail; [ -n "$sub" ] || exit 2; return 0 ;;
    enable|disable|status|test|dkim|cert|rotate|schedule|export) ;;
    *) usage_error mail "unknown subcommand: $sub" ;;
  esac
  local fn="help_mail_$sub" host="" lan="" provider="$MAIL_DEFAULT_PROVIDER" yes=false force=false systemd=false out="" to="" json=false nextkey=""
  local -a pos=()
  while [ $# -gt 0 ]; do
    case "$sub:$1" in
      *:-h|*:--help) "$fn"; return 0 ;;
      enable:--hostname) need_value "mail enable" "$1" "${2:-}"; host="$2"; shift ;;
      enable:--lan-only) need_value "mail enable" "$1" "${2:-}"; lan="$2"; shift ;;
      enable:--provider) need_value "mail enable" "$1" "${2:-}"; provider="$2"; shift ;;
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
      case "$lan" in ""|true|false) ;; *) usage_error "mail enable" "--lan-only must be true or false" ;; esac
      case "$provider" in stalwart|none) ;; *) usage_error "mail enable" "--provider must be stalwart or none" ;; esac ;;
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
    enable) mail_enable "$host" "$lan" "$provider" "$yes" ;;
    disable) mail_disable "$yes" "$force" ;;
    cert) mail_cert_cmd ;;
    rotate) mail_rotate "$nextkey" ;;
    schedule) mail_schedule_systemd "$out" ;;
    status) mail_status "$json" ;;
    test) mail_test "$to" ;;
    dkim) mail_dkim_rotate "${pos[1]}" ;;
    export) mail_export "${pos[0]}" "$out" ;;
  esac
}

# mail_cert_cmd — `mail cert`: issue / renew; after a renewal the Hub gets
# the keys and reloads the provider.
mail_cert_cmd() {
  local st
  mail_slot_open || fail "$MAIL_OFF_TEXT"
  mail_cert_ensure
  _mail_cert_metric "${MAIL_CERT_NOT_AFTER:-}"
  [ "${MAIL_CERT_RENEWED:-false}" = true ] || return 0
  st="$(_mail_tlsa status)" || fail "domains mail-tlsa status failed"
  _mail_hub_wait >/dev/null
  _mail_tls_post "$st"
}
