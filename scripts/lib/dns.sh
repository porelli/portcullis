# shellcheck shell=bash
#
# `portcullis dns plan | setup | check` — the main domain's DNS plan
# (contract §12): the record sets Portcullis wants at PORTCULLIS_DOMAIN
# (address: A/AAAA for <d> and *.<d>; caa: issue + issuewild pinned to
# Traefik's ACME account; nomail when DNS_NOMAIL=true), what is live, the
# CAA judgement and the DNSSEC state. Everything runs in the domains
# image's one-shot `dns` tool (compose service dns-tool: egress only, no
# volumes, no env): the provider credentials go in as JSON on its stdin,
# built with jq from the exported .env variables (env[$var]), never on a
# command line or in a container's environment.

# _dns_flag <var> <default> — a true/false .env toggle (anything else
# fails: a typo must not switch CAA off).
_dns_flag() {
  local v="${!1:-}"
  case "${v:-$2}" in
    true|false) printf '%s' "${v:-$2}" ;;
    *) fail "$1=$v must be true or false" ;;
  esac
}

# _dns_ca_server — ACME_CA_SERVER, else (a fresh init runs before
# config apply writes it) the one ACME_STAGING selects, as config_apply.
_dns_ca_server() {
  if [ -n "${ACME_CA_SERVER:-}" ]; then
    printf '%s' "$ACME_CA_SERVER"
  elif [ "$(_bool "${ACME_STAGING:-}" false)" = true ]; then
    printf '%s' "https://acme-staging-v02.api.letsencrypt.org/directory"
  else
    printf '%s' "https://acme-v02.api.letsencrypt.org/directory"
  fi
}

# _dns_ips — DNS_IPV4 / DNS_IPV6: an explicit PORTCULLIS_PUBLIC_IPV4 /
# _IPV6 wins; else HTTPS detection where two services must agree on a
# global address (public_ip_detect). Once per run.
_dns_ips() {
  [ -z "${DNS_IPS_DONE:-}" ] || return 0
  DNS_IPV4="${PORTCULLIS_PUBLIC_IPV4:-$(public_ip_detect 4)}"
  if [ -n "${PORTCULLIS_PUBLIC_IPV6+x}" ]; then DNS_IPV6="$PORTCULLIS_PUBLIC_IPV6"; else DNS_IPV6="$(public_ip_detect 6)"; fi
  [ -n "$DNS_IPV4" ] || warn "Could not detect the public IPv4 address reliably (two HTTPS services must agree on a global address); set PORTCULLIS_PUBLIC_IPV4 in .env"
  DNS_IPS_DONE=1
}

# _dns_tool_input <write|read> — the tool's stdin JSON. write: the
# provider and its credentials (a required variable left empty fails,
# naming it, never its value); read: neither (public checks only).
_dns_tool_input() {
  local mode="$1" provider="${DNS_PROVIDER:-none}" line var key map="[]" caa nomail
  if [ "$mode" = write ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      var="${line%%:*}" key="${line#*:}"
      if [ -z "${!var:-}" ]; then
        [ "$var" = AWS_HOSTED_ZONE_ID ] && continue
        fail "$var is not set in .env (needed for DNS_PROVIDER=$provider)"
      fi
      # jq reads the value from its environment (env[$var]), not argv.
      export "${var?}"
      map="$(jq -c --arg v "$var" --arg k "$key" '. + [{var: $v, key: $k}]' <<<"$map")"
    done < <(_dns_cred_keys "$provider")
  fi
  caa="$(_dns_flag DNS_CAA true)" || return 1
  nomail="$(_dns_flag DNS_NOMAIL false)" || return 1
  jq -n --arg mode "$mode" --arg name "$PORTCULLIS_DOMAIN" --arg provider "$provider" --argjson map "$map" \
    --arg ipv4 "${DNS_IPV4:-}" --arg ipv6 "${DNS_IPV6:-}" --arg ca "$(_dns_ca_server)" \
    --argjson caa "$caa" --arg issuer "${DNS_CAA_ISSUER:-}" --arg uri "${DNS_ACCOUNT_URI:-}" --arg iodef "${DNS_CAA_IODEF:-}" \
    --argjson nomail "$nomail" --arg sets "${DNS_SETS:-}" --arg mail "${ALERT_SMTP_FROM:-}" '
    {name: $name, ipv4: $ipv4, ipv6: $ipv6, ca_server: $ca,
     caa: {enabled: $caa, issuer: $issuer, account_uri: $uri, iodef: $iodef},
     nomail: $nomail, sets: ($sets | split(" ") | map(select(. != ""))), mail_from: $mail}
    + (if $mode == "write"
       then {provider: $provider, credentials: ($map | map({key: .key, value: env[.var]}) | from_entries)}
       else {provider: ""} end)'
}

# _dns_tool <plan|apply|ttl|check|dnssec-enable> [args] — run the one-shot
# tool (compose service dns-tool) with the input on stdin. plan, apply, ttl
# and dnssec-enable take the credentials (plan only for an automated
# provider); check never does.
_dns_tool() {
  local sub="$1" mode="read" input
  case "$sub" in
    apply|dnssec-enable|ttl) mode="write" ;;
    plan) ! _dns_automated "${DNS_PROVIDER:-none}" || mode="write" ;;
  esac
  input="$(_dns_tool_input "$mode")" || exit 1
  domains_image_ensure "for the dns tool"
  printf '%s' "$input" | rt_run dns-tool -i -- "$@"
}

# _dns_dur <seconds> — "45 s", "10 min", "5 min 24 s".
_dns_dur() {
  local s="${1:-0}"
  if [ "$s" -lt 60 ]; then printf '%d s' "$s"
  elif [ $((s % 60)) -eq 0 ]; then printf '%d min' $((s / 60))
  else printf '%d min %d s' $((s / 60)) $((s % 60)); fi
}

# _dns_wait_text <apply output> <what> [old] — the sentence after `apply
# --wait` ended early (exit 1: the records were written), from the tool's
# wait report (contract §12.1). A resolver is a pool of caches, so the
# tool waits until the records are stable there (clean rounds over 30 s,
# every old CAA answer's TTL run out): "<what> written; not yet stable at
# <resolvers>: it may serve <old> for up to <t> more (until HH:MM UTC)",
# or, stable but not settled, "<what> written; every resolver checked
# shows it, but the CA's resolvers may cache <old> for up to <t>". Never
# that anything failed.
_dns_wait_text() {
  local w vis pend n clears at what="$2" old="${3:-the old records}" it=it its=its
  w="$(printf '%s' "$1" | jq -c '.wait // empty' 2>/dev/null)" || w=""
  if [ -z "$w" ]; then printf '%s written; not yet stable at the public resolvers' "$what"; return 0; fi
  vis="$(jq -r '.visible' <<<"$w")"
  pend="$(jq -r '.pending // [] | map(sub(":53$"; "")) | join(", ")' <<<"$w")"
  n="$(jq -r '.pending // [] | length' <<<"$w")"
  [ "$n" -le 1 ] || { it=they; its=their; }
  clears="$(jq -r '.clears_in // 0' <<<"$w")"
  at="$(_dns_wait_at "$1")"
  if [ "$vis" = true ]; then
    printf "%s written; every resolver checked shows it, but the CA's resolvers may cache %s for up to %s%s" "$what" "$old" "$(_dns_dur "$clears")" "${at:+ (until $at)}"
  elif [ "$clears" -gt 0 ]; then
    printf '%s written; not yet stable at %s: %s may serve %s for up to %s more%s' "$what" "$pend" "$it" "$old" "$(_dns_dur "$clears")" "${at:+ (until $at)}"
  else
    printf '%s written; not yet stable at %s (%s caches of %s should have expired by now: TTL %s s)' "$what" "$pend" "$its" "$old" "$(jq -r '.ttl' <<<"$w")"
  fi
}

# _dns_clock <unix> — a settle time as printed everywhere: "YYYY-MM-DD
# HH:MM UTC", rounded up to the minute, so "after <it>" is never early and
# never ambiguous (a 24 h point is tomorrow's HH:MM).
_dns_clock() {
  jq -rn --argjson t "$1" '(($t + 59) / 60 | floor) * 60 | strftime("%Y-%m-%d %H:%M UTC")'
}

# _dns_wait_at <apply output> — the report's settle point (_dns_clock);
# nothing without one.
_dns_wait_at() {
  local t
  t="$(printf '%s' "$1" | jq -r '.wait.settle_at // 0' 2>/dev/null)" || t=0
  [[ "$t" =~ ^[0-9]+$ ]] && [ "$t" -gt 0 ] || return 0
  _dns_clock "$t"
}

# _dns_uri_ok <uri> — an ACME account URI fit for a CAA value and an env
# file: https, a host, no spaces, quotes or ';' (the CAA parameter
# separator). The Go side's dnsplan.ValidAccountURI is the same rule.
_dns_uri_ok() {
  [[ "$1" =~ ^https://[A-Za-z0-9._~-]+(:[0-9]+)?(/[A-Za-z0-9._~:/?#@!\$\&\(\)*+,=%-]*)?$ ]]
}

# dns_traefik_account_uri — the URI of Traefik's ACME account, read from
# acme.json (.letsencrypt.Account.Registration.uri) by the domains image
# in a throwaway container: root (the file is 0600 root), no network, the
# volume read-only. Only that string leaves (the file holds private
# keys). Nothing when there is no account yet (fail closed: CA-only CAA).
# Exit 1 (nothing printed) when the volume exists but couldn't be read.
dns_traefik_account_uri() {
  local uri rc=0
  _rt_docker_only
  docker volume inspect portcullis_traefik_acme >/dev/null 2>&1 || return 0
  if ! docker image inspect "$DOMAINS_IMAGE_NAME" >/dev/null 2>&1; then
    (domains_image_ensure "to read Traefik's ACME account") >&2 || return 1
  fi
  uri="$(docker run --rm --network none --read-only --user 0:0 --cap-drop ALL --security-opt no-new-privileges:true \
    -v portcullis_traefik_acme:/acme:ro "$DOMAINS_IMAGE_NAME" traefik-account-uri /acme/acme.json 2>/dev/null | head -n1)" || rc=$?
  # traefik-account-uri exits 3 for "no account in the file".
  case "$rc" in 0) ;; 3) return 0 ;; *) return 1 ;; esac
  if _dns_uri_ok "$uri"; then printf '%s\n' "$uri"; return 0; fi
  return 1
}

# _dns_prepare — what plan / setup / check need: the domain, the
# addresses, and the CAA pin (Traefik's account, unless the caller set
# DNS_ACCOUNT_URI; empty = CA-only).
_dns_prepare() {
  env_require PORTCULLIS_DOMAIN
  require_cmd docker jq
  _dns_ips
  DNS_TRAEFIK_UNREADABLE=""
  if [ -z "${DNS_ACCOUNT_URI+x}" ]; then
    if ! DNS_ACCOUNT_URI="$(dns_traefik_account_uri)"; then
      DNS_ACCOUNT_URI=""
      DNS_TRAEFIK_UNREADABLE=1
      warn "Traefik's ACME account couldn't be read (its volume exists): the plan shows the CA-only pin, and dns setup leaves the live CAA alone"
    fi
    # Record what was read (Traefik may have registered after the last
    # up): the service's main plan and status judge against it. Stdout
    # stays the plan's (--json).
    [ -z "$DNS_ACCOUNT_URI" ] || dns_main_env_write "$DNS_ACCOUNT_URI" if-running >&2 || true
  fi
  export DNS_ACCOUNT_URI
}

# _dns_default_sets — the sets `dns setup` applies: address and caa (with
# DNS_CAA=false the caa step removes the entries Portcullis wrote), plus
# nomail when DNS_NOMAIL=true.
_dns_default_sets() {
  local s="address caa"
  [ "$(_dns_flag DNS_NOMAIL false)" != true ] || s="$s nomail"
  printf '%s' "$s"
}

# _dns_render — the plan JSON (stdin) as a table, then the CAA and DNSSEC
# lines and every step left.
_dns_render() {
  local plan set name type want live st sev
  plan="$(cat)"
  printf '  %-7s %-34s %-5s %-28s %-28s %s\n' SET NAME TYPE WANT LIVE STATUS
  while IFS=$'\t' read -r set name type want live st sev; do
    [ "$sev" = ok ] || st="$st ($sev)"
    printf '  %-7s %-34s %-5s %-28s %-28s %s\n' "$set" "$name" "${type:--}" "${want:--}" "${live:--}" "$st"
  done < <(printf '%s' "$plan" | jq -r '.items[] | [.set, .name, .type, ((.want // []) | join(", ")), ((.live // []) | join(", ")), .status, .severity] | @tsv')
  printf '%s' "$plan" | jq -r '.items[] | select((.steps // []) | length > 0) | .steps[] | "    → " + .'
  printf '%s' "$plan" | jq -r '
    "  CAA: issuer \(if .caa.issuer == "" then "unknown (set DNS_CAA_ISSUER)" else .caa.issuer end), account \(if .caa.account_uri == "" then "CA-only (no Traefik account yet)" else .caa.account_uri end), would issue: \(if .caa.would_issue then "yes" else "NO" end)",
    "  DNSSEC: \(.dnssec.state)\(if (.dnssec.zone // "") != "" then " (zone \(.dnssec.zone | rtrimstr(".")))" else "" end)\(if .dnssec.provider_can_sign then ", the provider can sign (./portcullis dns setup --dnssec)" else "" end)",
    ((.dnssec.ds // [])[] | "    DS: key tag \(.key_tag), algorithm \(.algorithm), digest type \(.digest_type), digest \(.digest)"),
    ((.dnssec.steps // [])[] | "    → " + .)'
}

# dns_plan <json> — print the plan; changes nothing.
dns_plan() {
  local json="$1" out rc=0
  _dns_prepare
  out="$(_dns_tool plan)" || rc=$?
  [ -n "$out" ] || fail "the dns tool failed (exit $rc)"
  if [ "$json" = true ]; then printf '%s\n' "$out"; else printf '%s' "$out" | _dns_render; fi
  return 0
}

# dns_check <json> — public checks only (no credentials); exit 1 when an
# item or the DNSSEC state is a Problem.
dns_check() {
  local json="$1" out rc=0
  _dns_prepare
  out="$(_dns_tool check)" || rc=$?
  [ -n "$out" ] || fail "the dns tool failed (exit $rc)"
  if [ "$json" = true ]; then printf '%s\n' "$out"; else printf '%s' "$out" | _dns_render; fi
  case "$rc" in
    0) [ "$json" = true ] || ok "DNS checks passed." ;;
    1) [ "$json" = true ] || warn "DNS checks found problems (see above)." ;;
    *) fail "the dns tool failed (exit $rc)" ;;
  esac
  return "$rc"
}

# _dns_plan_replaces_pin <plan> — the plan's caa item would change a live
# Portcullis pin (an entry of the issuer with an accounturi): replace it,
# or remove it with DNS_CAA=false.
_dns_plan_replaces_pin() {
  printf '%s' "$1" | jq -e '.caa.issuer as $iss | $iss != "" and
    ([.items[]? | select(.set == "caa" and .status == "wrong") | (.live // [])[]
      | select(contains("\"" + $iss) and contains("accounturi="))] | length > 0)' >/dev/null 2>&1
}

# dns_setup <yes> <dnssec> <only> — show the plan, confirm (unless yes),
# apply the sets (all, or only <only>) and wait for them, then check.
# --dnssec turns signing on where the provider can (cloudflare). A
# provider without automation: the records to create by hand, exit 0.
dns_setup() {
  local yes="$1" dnssec="$2" only="$3" provider="${DNS_PROVIDER:-none}" out rc=0 reply
  _dns_prepare
  DNS_SETS="${only:-$(_dns_default_sets)}"
  # Never replace a live pin with CA-only because the account read failed.
  if [ -n "${DNS_TRAEFIK_UNREADABLE:-}" ]; then
    DNS_SETS="$(printf '%s' "$DNS_SETS" | tr ' ' '\n' | grep -vx caa | paste -sd' ' -)"
    [ -n "$DNS_SETS" ] || { warn "Nothing to apply: the caa set needs Traefik's ACME account."; return 1; }
  fi
  export DNS_SETS
  if ! _dns_automated "$provider"; then
    warn "No automatic DNS for provider '$provider': create these records by hand."
    out="$(_dns_tool plan)" || rc=$?
    [ -n "$out" ] || fail "the dns tool failed (exit $rc)"
    printf '%s' "$out" | _dns_render
    return 0
  fi
  info "DNS plan for $PORTCULLIS_DOMAIN (provider: $provider):"
  out="$(_dns_tool plan)" || rc=$?
  [ -n "$out" ] || fail "the dns tool failed (exit $rc)"
  printf '%s' "$out" | _dns_render
  if [ "$yes" != true ]; then
    [ -t 0 ] || fail "non-interactive: pass --yes"
    local q="Apply these changes?"
    [ "$dnssec" != true ] || q="Apply these changes and turn on DNSSEC signing for the whole zone ($provider)?"
    read -rp "$q [y/N] " reply
    case "$reply" in y|Y|yes|YES) ;; *) info "Nothing changed."; return 0 ;; esac
  fi
  # Writing the caa set over a live Portcullis pin (removing it with
  # DNS_CAA=false, or replacing it) leaves caches holding that pin for its
  # TTL: save a settle point every later flip honours (N2), from the
  # tool's progress line the moment the write is accepted. Only then is
  # the caa set's TTL read first (I1: never the other sets, whose TTL says
  # nothing about a pin); when it can't be read (a hand-made pin with an
  # "auto" / zone-default TTL, or the read failed), the 24 h rule the relax
  # uses is saved before the write (M24): the progress line's settle point
  # is then only a guess.
  local settle_hook=""
  if [[ " $DNS_SETS " == *" caa "* ]] && _dns_plan_replaces_pin "$out"; then
    local pre prc=0
    pre="$(DNS_SETS=caa _dns_tool ttl)" || prc=$?
    if [ "$prc" -ne 0 ]; then
      _dns_relax_note "$(( $(date +%s) + 86400 ))" \
        || fail "couldn't save the ACME flip's settle point ($(_dns_relax_file)): nothing written"
      warn "How long caches hold the CAA pin of $PORTCULLIS_DOMAIN this replaces can't be read before the write (the message is above): an ACME_STAGING flip waits 24 h after it ($(_dns_relax_file))."
      settle_hook=_dns_relax_note
    elif [ "$(printf '%s' "$pre" | jq -r '.caa_relaxed // false' 2>/dev/null)" != true ]; then
      settle_hook=_dns_relax_note
    fi
  fi
  info "Applying the record sets: $DNS_SETS (then waiting for the public resolvers: the TTL the provider stored + 1 min, at most 15 min)..."
  rc=0
  out="$(DNS_ON_SETTLE="$settle_hook" _dns_apply_quiet --wait auto)" || rc=$?
  [ "$rc" -ne 4 ] || { dns_main_refresh; fail "the records were written, but the flip's settle point couldn't be saved ($(_dns_relax_file)): don't flip ACME_STAGING before the old CAA pin's TTL has passed"; }
  # A pin written again while a flip's settle point is saved (ACME_STAGING
  # reverted mid-flip) only moves the point later (I10).
  if { [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ]; } && [ -n "${DNS_ACCOUNT_URI:-}" ] && [[ " $DNS_SETS " == *" caa "* ]] && [ "$(_dns_flag DNS_CAA true)" = true ]; then
    _dns_relax_repin
  fi
  # Written but not yet stable (the bound was hit): no trailing check — it
  # would hit a stale cache and report problems for records that are fine.
  local stable=true at
  case "$rc" in
    0) ok "Applied: $DNS_SETS" ;;
    1) stable=false; at="$(_dns_wait_at "$out")"
       warn "$(_dns_wait_text "$out" "DNS records ($DNS_SETS)"). Run ./portcullis dns check${at:+ after $at} to see them." ;;
    2) dns_main_refresh; fail "the dns tool refused the arguments: the domains image is older than this CLI (docker compose build domains, then run it again)" ;;
    *) dns_main_refresh; fail "applying the DNS records failed (exit $rc; the message is above)" ;;
  esac
  if [ "$dnssec" = true ]; then
    if [ "$provider" = cloudflare ]; then
      info "Turning on DNSSEC signing (the whole zone)..."
      _dns_tool dnssec-enable >/dev/null || fail "turning on DNSSEC signing failed (the message is above)"
      ok "DNSSEC signing requested: add the DS the plan shows at your registrar."
    else
      warn "$provider can't turn on DNSSEC signing through its API:"
      printf '%s' "$out" | jq -r '(.dnssec.steps // [])[] | "    → " + .'
    fi
  fi
  dns_main_refresh
  [ "$stable" = true ] || return 0
  dns_check false
}

# ── lifecycle: the main domain's CAA pin follows Traefik's account ──

# dns_main_env_write <uri> [if-running] — secrets/domains/main-domain.env
# (0600, DOMAINS_MAIN_ACME_ACCOUNT_URI): the pin the domains service's
# read-only main-domain plan judges against. A change recreates domains
# (if-running: only when it runs — dns plan / check never start the stack).
dns_main_env_write() {
  local uri="$1" when="${2:-always}" f d new
  _dns_uri_ok "$uri" || { warn "not writing main-domain.env: '$uri' is not an ACME account URI"; return 1; }
  d="$(_domains_dir)"
  f="$d/main-domain.env"
  new="DOMAINS_MAIN_ACME_ACCOUNT_URI=$uri"
  [ "$(cat "$f" 2>/dev/null)" != "$new" ] || return 0
  mkdir -p "$d"
  (umask 077; printf '%s\n' "$new" > "$f.tmp") && mv -f "$f.tmp" "$f" && chmod 600 "$f" \
    || { rm -f "$f.tmp"; warn "could not write $f"; return 1; }
  info "Traefik's ACME account: $uri (secrets/domains/main-domain.env)"
  if [ "$when" = if-running ] && ! rt_running domains; then
    return 0
  fi
  rt_up_service --deps domains >/dev/null 2>&1 || warn "could not restart the domains service to read main-domain.env"
  return 0
}

# dns_main_env_uri — the URI main-domain.env holds (nothing without it;
# always exit 0: callers assign it under set -euo pipefail).
dns_main_env_uri() {
  local f
  f="$(_domains_dir)/main-domain.env"
  [ -r "$f" ] || return 0
  sed -n 's/^DOMAINS_MAIN_ACME_ACCOUNT_URI=//p' "$f" 2>/dev/null | head -n1 || true
}

# _dns_caa_live_ok <uri> — the live CAA at the main domain is already
# pinned to <uri> (public check; any failure = not ok).
_dns_caa_live_ok() {
  local out
  out="$(DNS_ACCOUNT_URI="$1" DNS_SETS=caa DNS_IPS_DONE=1 DNS_IPV4="${PORTCULLIS_PUBLIC_IPV4:-}" DNS_IPV6="${PORTCULLIS_PUBLIC_IPV6:-}" \
    _dns_tool check 2>/dev/null)" || true
  [ -n "$out" ] && printf '%s' "$out" | jq -e '.caa.would_issue and ([.items[] | select(.set == "caa" and .status != "ok" and .status != "foreign")] | length == 0)' >/dev/null 2>&1
}

# dns_tighten_main — after `up` / `upgrade` / `init` (Traefik running):
# read Traefik's ACME account URI (a first registration may take a while:
# polled up to 3 min, only when DNS_CAA=true and the provider is
# automated; otherwise one read), record it in main-domain.env, and pin
# the main domain's CAA to it when the live pin differs. Only warns:
# `up` never fails because of it.
dns_tighten_main() {
  local caa poll=false uri="" deadline every
  caa="$(_dns_flag DNS_CAA true 2>/dev/null)" || { warn "DNS_CAA must be true or false: the CAA pin is left alone"; return 0; }
  [ "$caa" != true ] || ! _dns_automated "${DNS_PROVIDER:-none}" || poll=true
  if [ "$poll" = true ]; then
    deadline=$((SECONDS + ${DNS_TIGHTEN_TIMEOUT:-180}))
    every="${DNS_TIGHTEN_POLL:-5}"
    while :; do
      uri="$(dns_traefik_account_uri)" || uri=""
      [ -z "$uri" ] || break
      [ "$SECONDS" -lt "$deadline" ] || break
      sleep "$every"
    done
  else
    uri="$(dns_traefik_account_uri)" || uri=""
  fi
  if [ -z "$uri" ]; then
    [ "$poll" != true ] || warn "Traefik has no ACME account yet: the CAA of $PORTCULLIS_DOMAIN stays CA-only (the next ./portcullis up pins it)."
    return 0
  fi
  dns_main_env_write "$uri" || return 0
  [ "$poll" = true ] || return 0
  _dns_caa_live_ok "$uri" && return 0
  info "Pinning the CAA of $PORTCULLIS_DOMAIN to Traefik's ACME account..."
  # Not a safety step: `up` / `upgrade` / `init` are never held long by it.
  # The stability wait is capped at 3 min; reaching it is success (status
  # may show the CAA not yet as planned until the plan's next rebuild).
  local out rc=0
  out="$(_dns_caa_apply "$uri" --wait-max 3m)" || rc=$?
  case "$rc" in
    0) ok "CAA of $PORTCULLIS_DOMAIN pinned to $uri"; _dns_relax_repin ;;
    1) warn "$(_dns_wait_text "$out" "The CAA pin of $PORTCULLIS_DOMAIN"). Nothing to do: ./portcullis status shows it as planned once those caches have cleared."; _dns_relax_repin ;;
    2) warn "could not pin the CAA of $PORTCULLIS_DOMAIN: the dns tool refused the arguments, the domains image is older than this CLI (docker compose build domains, then ./portcullis dns setup)" ;;
    *) warn "could not pin the CAA of $PORTCULLIS_DOMAIN to Traefik's account: the write failed (the message is above; fix: ./portcullis dns setup)" ;;
  esac
  dns_main_refresh
  return 0
}

# _dns_apply_quiet [args] — `_dns_tool apply [args]`, its stderr shown as
# it comes (the progress line after the write, a failure's message) except
# its own timeout line ("the records were written, but …"): the callers
# word that from the wait report. The tool's exit status.
# With DNS_ON_SETTLE=<function> set, the progress line's settle point
# (printed right after the write, before the wait: "… settle_at=<unix>")
# is handed to it at once (I8); a failing handler makes the whole call
# return 4 once the tool is done.
_dns_apply_quiet() {
  local rc mark
  mark="$(mktemp)"
  { _dns_tool apply "$@" 2>&1 1>&3 3>&- | _dns_apply_filter "$mark" >&2; rc="${PIPESTATUS[0]}"; } 3>&1
  if [ -s "$mark" ]; then rc=4; fi
  rm -f "$mark"
  return "$rc"
}

# _dns_apply_filter <mark> — the tool's stderr, line by line (see above).
_dns_apply_filter() {
  local line at
  while IFS= read -r line; do
    case "$line" in
      "domains dns apply: written; waiting"*) ;;
      "domains dns apply: written;"*) continue ;;
    esac
    printf '%s\n' "$line"
    if [ -n "${DNS_ON_SETTLE:-}" ] && [[ "$line" =~ settle_at=([0-9]+) ]]; then
      at="${BASH_REMATCH[1]}"
      "$DNS_ON_SETTLE" "$at" || echo failed > "$1"
    fi
  done
}

# _dns_caa_apply <uri> [args] — write the main domain's caa set pinned to
# <uri> ("" = CA-only) and wait for it (apply --wait auto [args]: the
# stored / served TTL bounds the wait, contract §12.1). Prints the tool's
# output; its exit: 0 visible (settled), 1 written but not yet, 2 the tool
# refused the arguments (an older domains image), 3 the write failed.
_dns_caa_apply() {
  (DNS_ACCOUNT_URI="$1" DNS_SETS=caa DNS_IPS_DONE=1 DNS_IPV4="${PORTCULLIS_PUBLIC_IPV4:-}" DNS_IPV6="${PORTCULLIS_PUBLIC_IPV6:-}" \
    _dns_apply_quiet --wait auto "${@:2}")
}

# _dns_relax_file — the pending flip's settle point (0600): when the relax
# was first written, the old pin's TTL, and the time before which no cache
# can be trusted to have dropped the old pin. It describes live DNS caches, not the host: never backed
# up; a restore keeps the live one (backup.sh _restore_secrets).
_dns_relax_file() { printf '%s/acme-relax.env' "$(_domains_dir)"; }

# _dns_relax_get <KEY> — a value of the settle point (nothing without one).
_dns_relax_get() {
  sed -n "s/^RELAX_$1=//p" "$(_dns_relax_file)" 2>/dev/null | head -n1 || true
}

# _dns_relax_put <written_at> <old_ttl> <not_before> — (re)write it, 0600.
_dns_relax_put() {
  local f d
  f="$(_dns_relax_file)"; d="$(dirname "$f")"
  mkdir -p "$d"
  (umask 077; printf 'RELAX_WRITTEN_AT=%s\nRELAX_OLD_TTL=%s\nRELAX_NOT_BEFORE=%s\n' "$1" "$2" "$3" > "$f.tmp") && mv -f "$f.tmp" "$f" && chmod 600 "$f"
}

# _dns_relax_point — the saved settle point, never earlier than any field
# says: max(NOT_BEFORE, WRITTEN_AT + OLD_TTL + 60). Nothing when the file
# is missing or a field isn't a number (unreadable: I6).
_dns_relax_point() {
  local nb w t
  nb="$(_dns_relax_get NOT_BEFORE)" w="$(_dns_relax_get WRITTEN_AT)" t="$(_dns_relax_get OLD_TTL)"
  [[ "$nb" =~ ^[0-9]+$ && "$w" =~ ^[0-9]+$ && "$t" =~ ^[0-9]+$ ]] || return 0
  [ $((w + t + 60)) -le "$nb" ] || nb=$((w + t + 60))
  printf '%s' "$nb"
}

# _dns_relax_raise <unix> — move the saved settle point later (never
# earlier); a failed write fails.
_dns_relax_raise() {
  local nb
  nb="$(_dns_relax_point)"
  [ -n "$nb" ] || return 1
  [ "$1" -gt "$nb" ] || return 0
  _dns_relax_put "$(_dns_relax_get WRITTEN_AT)" "$(_dns_relax_get OLD_TTL)" "$1"
}

# _dns_relax_repin — a pin was written again (the tighten, dns setup)
# while a flip's settle point is saved: it is never deleted here — caches
# may still hold the original, longer-TTL pin, and a later relax would
# only see this pin's TTL — and only ever moves later: max(saved, now +
# OLD_TTL + 60) (I10). An unreadable file is left as it is (the next relax
# then waits 24 h). A failed write only warns: the saved point is still
# the original one.
_dns_relax_repin() {
  local nb t
  [ -e "$(_dns_relax_file)" ] || return 0
  nb="$(_dns_relax_point)"
  [ -n "$nb" ] || return 0
  t="$(_dns_relax_get OLD_TTL)"
  _dns_relax_raise "$(( $(date +%s) + t + 60 ))" || warn "could not update the pending flip's settle point ($(_dns_relax_file))"
  return 0
}

# _dns_relax_note <unix> — a caa write over a live pin (dns setup): save
# <unix> as the settle point, or raise the saved one to it. An unreadable
# file is left as it is (a flip then waits 24 h). Fails when it can't be
# written.
_dns_relax_note() {
  local now
  if [ -e "$(_dns_relax_file)" ]; then
    [ -n "$(_dns_relax_point)" ] || return 0
    _dns_relax_raise "$1"
    return
  fi
  now="$(date +%s)"
  _dns_relax_put "$now" "$(( $1 > now + 60 ? $1 - now - 60 : 0 ))" "$1"
}

# dns_flip_guard <ca_server> [relaxed] — before any flip stops Traefik, managed CAA
# or not (N2): a saved settle point still in the future refuses (with its
# time), and so does a public CAA the CA wouldn't let a NEW account order
# under at every resolver — a live (or still cached) pin. A failed lookup
# refuses too (fail closed). Nothing has changed when it refuses.
dns_flip_guard() {
  local ca="$1" relaxed="${2:-}" d="${PORTCULLIS_DOMAIN:-the domain}" nb now out live why
  now="$(date +%s)"
  # (relaxed: dns_relax_main just settled past the saved point itself)
  if [ -z "$relaxed" ] && [ -e "$(_dns_relax_file)" ]; then
    nb="$(_dns_relax_point)"
    if [ -z "$nb" ]; then
      nb=$((now + 86400))
      _dns_relax_put "$now" 86400 "$nb" || { warn "could not save the settle point ($(_dns_relax_file))"; return 1; }
      warn "The saved settle point ($(_dns_relax_file)) is unreadable: how long caches may still hold an old CAA pin of $d can't be known, so the flip waits 24 h. Run it again after $(_dns_clock "$nb")."
      return 1
    fi
    if [ "$nb" -gt "$now" ]; then
      warn "An old CAA pin of $d may still be cached until $(_dns_clock "$nb") (saved when it was replaced or removed: $(_dns_relax_file)): run it again after $(_dns_clock "$nb")."
      return 1
    fi
  fi
  out="$(ACME_CA_SERVER="$ca" DNS_CAA=true DNS_ACCOUNT_URI="" DNS_SETS=caa DNS_IPS_DONE=1 DNS_IPV4="${PORTCULLIS_PUBLIC_IPV4:-}" DNS_IPV6="${PORTCULLIS_PUBLIC_IPV6:-}" \
    _dns_tool check 2>/dev/null)" || true
  if [ -z "$out" ] || ! printf '%s' "$out" | jq -e 'type == "object" and (.caa | type == "object")' >/dev/null 2>&1; then
    warn "couldn't check the public CAA of $d (would $ca let Traefik's new ACME account order?): nothing changed. Run it again when the public resolvers answer."
    return 1
  fi
  [ "$(printf '%s' "$out" | jq -r '.caa.would_issue')" = true ] && return 0
  # The check ran, but its CAA lookups failed (M22): that says nothing
  # about the CAA, so it is "couldn't check" — refused all the same.
  # (a pin live at another resolver is named instead, below: m4)
  if printf '%s' "$out" | jq -e '([.items[]? | select(.set == "caa" and .status == "unknown" and .severity != "info")] | length > 0)
      and ([.items[]? | select(.set == "caa") | (.live // [])[]] | length == 0)' >/dev/null 2>&1; then
    warn "couldn't check the public CAA of $d (DNS lookups failed): nothing changed. Run it again when the public resolvers answer."
    return 1
  fi
  live="$(printf '%s' "$out" | jq -r '[.items[] | select(.set == "caa") | (.live // [])[]] | unique | join("; ")' 2>/dev/null || true)"
  # How long caches may hold that CAA (M23): a pin removed by hand must be
  # waited out for its TTL — Portcullis can't see when that happened, and
  # the CA's resolvers may keep it after the public ones dropped it.
  local cttl its_ttl="its TTL"
  cttl="$(printf '%s' "$out" | jq -r '.caa_ttl // empty' 2>/dev/null || true)"
  [[ "$cttl" =~ ^[0-9]+$ ]] || cttl=""
  [ -z "$cttl" ] || its_ttl="its TTL ($cttl s, $(_dns_dur "$cttl"))"
  if [ "$(_dns_flag DNS_CAA true 2>/dev/null)" != true ]; then why="DNS_CAA=false"
  elif ! _dns_automated "${DNS_PROVIDER:-none}"; then why="DNS_PROVIDER=${DNS_PROVIDER:-none} has no automation"
  elif ! _dns_creds_present "${DNS_PROVIDER:-none}"; then why="the ${DNS_PROVIDER} credentials aren't set in .env"
  else why=""; fi
  if [ -n "$why" ]; then
    warn "The public CAA of $d wouldn't let Traefik's new ACME account order (${live:-the CAA at $d or a parent}), and Portcullis can't relax it ($why): remove that pin at ${DNS_PROVIDER:-your DNS provider} (or run ./portcullis dns setup with DNS_CAA=false and the credentials), then wait $its_ttl after removing it before running it again. Nothing changed."
  else
    warn "The public CAA of $d still wouldn't let Traefik's new ACME account order (${live:-the CAA at $d or a parent}${cttl:+; TTL $cttl s}): nothing changed; run it again once the resolvers show the CA-only form (./portcullis dns check)."
  fi
  return 1
}

# dns_relax_done — the flip finished (acme.json cleared, Traefik on the
# new CA, sentinel written): the settle point goes. Nothing else ever
# deletes it (I10).
dns_relax_done() { rm -f "$(_dns_relax_file)"; }

# dns_relax_main — on an ACME_STAGING flip, before `config apply` stops
# Traefik and clears acme.json: the main domain's CAA back to CA-only, so
# the new account Traefik registers can order, then wait until no cache
# anywhere (the CA's resolvers too) can still hold the old pin. Traefik
# keeps running meanwhile: CA-only allows its current account too.
# The settle point survives the run (C1): the first relax reads the old
# pin's TTL (`dns-tool ttl`, before anything is written) and saves
# written-at + TTL + 1 min (_dns_relax_file); every run passes it
# (--settle-after) and only ever moves it later, so a rerun — which sees
# only the CA-only records the first run wrote — can't settle early.
# Exit 0 only when settled; 1 written but not settled yet; 2 the dns tool
# refused the arguments (an older domains image); 3 a failure.
dns_relax_main() {
  local d="${PORTCULLIS_DOMAIN:-the domain}" out rc=0 ttl now nb relaxed at
  local -a env=(DNS_ACCOUNT_URI="" DNS_SETS=caa DNS_IPS_DONE=1 DNS_IPV4="${PORTCULLIS_PUBLIC_IPV4:-}" DNS_IPV6="${PORTCULLIS_PUBLIC_IPV6:-}")
  nb="$(_dns_relax_point)"
  if [ -z "$nb" ] && [ -e "$(_dns_relax_file)" ]; then
    # A file that can't be read means a relax happened once and its point
    # is lost: how long caches may still hold that pin can't be known,
    # also if the CAA was pinned again since. A day, the longest resolvers
    # commonly cache (I6).
    now="$(date +%s)"
    nb=$((now + 86400))
    _dns_relax_put "$now" 86400 "$nb" || { warn "could not save the relax's settle point ($(_dns_relax_file))"; return 3; }
    warn "The saved settle point of a relax of the CAA of $d ($(_dns_relax_file)) is unreadable: how long caches may still hold the old pin can't be known, so the flip waits 24 h, until $(_dns_clock "$nb"). Run it again after that time."
  fi
  if [ -z "$nb" ]; then
    # No usable saved point: read the CAA's TTL (and whether it is already
    # CA-only) before anything is written. Fail closed (I7): a TTL that
    # can't be read is never guessed.
    now="$(date +%s)"
    # (a subshell: the exports stay in it)
    out="$(export "${env[@]}"; _dns_tool ttl)" || rc=$?
    case "$rc" in
      0) ;;
      2) warn "could not relax the CAA of $d: the dns tool refused the arguments, the domains image is older than this CLI (docker compose build domains)."; return 2 ;;
      *) warn "could not read how long caches hold the CAA of $d (the message is above): nothing changed. If ${DNS_PROVIDER:-the provider} reports no TTL for it, set an explicit TTL there; then run it again."; return 3 ;;
    esac
    ttl="$(printf '%s' "$out" | jq -r '.ttl // empty' 2>/dev/null || true)"
    relaxed="$(printf '%s' "$out" | jq -r '.caa_relaxed // false' 2>/dev/null || echo false)"
    if ! [[ "$ttl" =~ ^[0-9]+$ ]]; then
      warn "could not read how long caches hold the CAA of $d (no TTL in the dns tool's answer): nothing changed. Set an explicit TTL at ${DNS_PROVIDER:-the provider}, then run it again."
      return 3
    fi
    # M19: main-domain.env never held an account URI = Portcullis never
    # pinned: no old pin to wait out (the flip's public check guards a
    # foreign one).
    if [ "$relaxed" = true ] && [ -n "$(dns_main_env_uri)" ]; then
      # Already CA-only and no valid settle point (lost, corrupt, edited):
      # the old pin's TTL can't be known any more. Assume a day, the
      # longest resolvers commonly cache (I6).
      nb=$((now + 86400))
      _dns_relax_put "$now" 86400 "$nb" || { warn "could not save the relax's settle point ($(_dns_relax_file))"; return 3; }
      warn "No Portcullis pin of $d is live (the CAA is CA-only or has none of its entries, e.g. Traefik never registered, so it was never pinned) and no settle record exists ($(_dns_relax_file)), so the old pin's lifetime is unknown: the flip waits 24 h and can go ahead after $(_dns_clock "$nb") (run it again then)."
    else
      nb=$((now + ttl + 60))
      _dns_relax_put "$now" "$ttl" "$nb" || { warn "could not save the relax's settle point ($(_dns_relax_file))"; return 3; }
    fi
  fi
  info "Relaxing the CAA of $d to CA-only (Traefik registers a new ACME account), then waiting until no cache can hold the old pin (the TTL caches got + 1 min, at most 15 min; Traefik keeps running meanwhile)..."
  rc=0
  # The tool's settle point is saved the moment it prints it, right after
  # the write (I8); a failed save fails.
  out="$(DNS_ON_SETTLE=_dns_relax_raise _dns_caa_apply "" --settle --settle-after "$nb")" || rc=$?
  at="$(printf '%s' "$out" | jq -r '.wait.settle_at // 0' 2>/dev/null || echo 0)"
  if [[ "$at" =~ ^[0-9]+$ ]] && [ "$at" -gt 0 ] && ! _dns_relax_raise "$at"; then rc=4; fi
  dns_main_refresh
  if [ "$rc" -eq 4 ]; then
    warn "could not save the relax's settle point ($(_dns_relax_file)): the flip can't go on safely."
    return 3
  fi
  # Exit 0 counts only with the report saying settled (defence in depth).
  if [ "$rc" -eq 0 ] && [ "$(printf '%s' "$out" | jq -r '.wait.settled // false' 2>/dev/null)" != true ]; then rc=1; fi
  at="$(_dns_wait_at "$out")"
  case "$rc" in
    0) ok "The CAA of $d is CA-only, and every cache of the old pin has expired."; return 0 ;;
    1)
      # Past what one run waits: each cause on its own (F), with the time
      # after which a rerun goes ahead.
      local rerun="./portcullis config apply (or the up / upgrade you ran)"
      if [ "$(printf '%s' "$out" | jq -r '.wait.beyond_cap // false' 2>/dev/null)" = true ]; then
        case "$(printf '%s' "$out" | jq -r '.wait.settle_cause // "ttl"' 2>/dev/null)" in
          resolver)
            local who left
            who="$(printf '%s' "$out" | jq -r '.wait.held_by // [] | map(sub(":53$"; "")) | if length == 0 then "a public resolver" else join(", ") end')"
            left="$(printf '%s' "$out" | jq -r '.wait.held_for // 0')"
            if [ "$left" -gt 0 ] 2>/dev/null; then
              warn "The CAA of $d was relaxed to CA-only, but $who still serves the old pin ($left s left), so caches (the CA's too) may hold it until $at. A rerun of $rerun goes ahead after $at."
            else
              warn "The CAA of $d was relaxed to CA-only, but a public resolver served the old pin late, so caches (the CA's too) may hold it until $at. A rerun of $rerun goes ahead after $at."
            fi ;;
          saved)
            at="$(_dns_wait_at "$out")"
            warn "The CAA of $d was relaxed to CA-only, but the settle point saved earlier ($(_dns_relax_file)) is past what one run waits (15 min): a rerun of $rerun goes ahead after $at." ;;
          *)
            ttl="$(printf '%s' "$out" | jq -r '.wait.ttl')"
            warn "The CAA of $d was relaxed to CA-only, but the old pin's stored TTL ($ttl s, $(_dns_dur "$ttl")) is above what one run waits (15 min): caches (the CA's too) may hold it until $at. A rerun of $rerun goes ahead after $at; lowering the CAA TTL at ${DNS_PROVIDER:-the provider} first shortens it." ;;
        esac
      else
        warn "$(_dns_wait_text "$out" "The CA-only CAA of $d" "the old pin"). Run ./portcullis config apply (or the up / upgrade you ran) again${at:+ after $at}."
      fi
      return 1 ;;
    2) warn "could not relax the CAA of $d: the dns tool refused the arguments, the domains image is older than this CLI (docker compose build domains)."; return 2 ;;
    3) warn "could not relax the CAA of $d to CA-only: the write failed (the message is above; check the provider access: ./portcullis dns plan)."; return 3 ;;
    *) warn "the relax of the CAA of $d was interrupted (exit $rc): its settle point is saved; run it again."; return 3 ;;
  esac
}

# dns_main_refresh — after the dns tool wrote the main domain's records
# (out of process: the service can't see it), have the domains service
# drop its cached main plan and rebuild it; otherwise status and the Hub
# show the plan from before the write for up to an hour. Best effort:
# nothing when the service isn't running.
dns_main_refresh() {
  rt_exec domains -- domains report --main --refresh >/dev/null 2>&1 || true
}

# dns_status_json — the domains service's DNS report (main + enrolled
# plans, loopback API), or nothing when it isn't running. --fresh: the
# main plan rebuilt for it (public lookups; the service rebuilds at most
# once per 30 s, and the report waits at most 20 s for it), so a CAA
# changed outside Portcullis shows at once; otherwise the cached plan
# with "main_fresh": false.
# An older running image refuses --fresh (usage, exit 2): its cached
# report then, marked image_old (status names it; M10).
dns_status_json() {
  local out rc=0
  out="$(rt_exec domains -- domains report --main --json --fresh 2>/dev/null)" || rc=$?
  if [ "$rc" -eq 2 ]; then
    out="$(rt_exec domains -- domains report --main --json 2>/dev/null)" || return 0
    printf '%s' "$out" | jq -c '. + {main_fresh: false, image_old: true}' 2>/dev/null || true
    return 0
  fi
  [ "$rc" -eq 0 ] || return 0
  printf '%s\n' "$out"
}

help_dns() {
  cat <<'EOF'
Usage: portcullis dns plan|setup|check [options]

  plan      Show the main domain's DNS plan: wanted vs live records, CAA, DNSSEC
  setup     Show the plan, confirm, write the records through the provider API
  check     Public checks only (no credentials); exit 1 on any problem
EOF
}

help_dns_plan() {
  cat <<'EOF'
Usage: portcullis dns plan [--json]

The DNS plan of PORTCULLIS_DOMAIN: every record Portcullis wants (address:
A/AAAA for <domain> and *.<domain>; caa: issue + issuewild for the ACME CA,
pinned to Traefik's ACME account, DNS-01 only; nomail with DNS_NOMAIL=true),
what the provider holds and the public resolvers (1.1.1.1, 8.8.8.8) answer,
records under the domain that aren't Portcullis', whether the CA would
issue, and the DNSSEC state with the steps left. Changes nothing.

Options:
  --json    the plan object (contract §12.2)
EOF
}

help_dns_setup() {
  cat <<'EOF'
Usage: portcullis dns setup [--yes] [--dnssec] [--only address|caa|nomail]

Show the plan, ask to apply it (--yes: don't ask; required without a
terminal), write the record sets through DNS_PROVIDER's API with its
credentials from .env, wait for the public resolvers, then check:
  cloudflare     CLOUDFLARE_API_TOKEN
  porkbun        PORKBUN_API_KEY, PORKBUN_SECRET_API_KEY
  route53        AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_HOSTED_ZONE_ID (optional)
  digitalocean   DO_AUTH_TOKEN
  hetzner        HETZNER_API_KEY (the legacy dns.hetzner.com API)
  hetzner-cloud  HETZNER_API_TOKEN (DNS in the Hetzner Cloud API)
Other providers (or none): prints the records to create by hand.
The credentials reach the domains image's dns tool on its stdin only.

Options:
  --yes       apply without asking
  --dnssec    also turn on DNSSEC signing (the whole zone; cloudflare only;
              others print the steps). Signing is never turned off.
  --only SET  apply one record set: address, caa or nomail
EOF
}

help_dns_check() {
  cat <<'EOF'
Usage: portcullis dns check [--json]

The plan from the public resolvers only (no credentials needed): A/AAAA,
the CAA pin (would the CA issue for Traefik's account?) and DNSSEC. Exits
1 when an item or the DNSSEC state is a problem.

Options:
  --json    the plan object (contract §12.2)
EOF
}

cmd_dns() {
  local sub="${1:-}" json=false yes=false dnssec=false only=""
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_dns; [ -n "$sub" ] || exit 2; return 0 ;;
    plan|setup|check) ;;
    *) usage_error dns "unknown subcommand: $sub" ;;
  esac
  while [ $# -gt 0 ]; do
    case "$sub:$1" in
      *:-h|*:--help) "help_dns_$sub"; return 0 ;;
      plan:--json|check:--json) json=true ;;
      setup:--yes) yes=true ;;
      setup:--dnssec) dnssec=true ;;
      setup:--only)
        need_value "dns setup" --only "${2:-}"
        case "$2" in address|caa|nomail) only="$2" ;; *) usage_error "dns setup" "--only must be address, caa or nomail" ;; esac
        shift ;;
      setup:--check) usage_error "dns setup" "unknown argument --check (use: ./portcullis dns check)" ;;
      *) usage_error "dns $sub" "unknown argument: $1" ;;
    esac
    shift
  done
  need_env
  case "$sub" in
    plan) dns_plan "$json" ;;
    check) dns_check "$json" ;;
    setup) dns_setup "$yes" "$dnssec" "$only" ;;
  esac
}
