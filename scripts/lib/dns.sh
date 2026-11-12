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

# _dns_tool <plan|apply|check|dnssec-enable> [args] — run the one-shot
# tool (compose service dns-tool) with the input on stdin. plan, apply and
# dnssec-enable take the credentials (plan only for an automated
# provider); check never does.
_dns_tool() {
  local sub="$1" mode="read" input
  case "$sub" in
    apply|dnssec-enable) mode="write" ;;
    plan) ! _dns_automated "${DNS_PROVIDER:-none}" || mode="write" ;;
  esac
  input="$(_dns_tool_input "$mode")" || exit 1
  domains_image_ensure "for the dns tool"
  printf '%s' "$input" | dc run --rm --no-deps -T dns-tool "$@"
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
    read -rp "Apply these changes? [y/N] " reply
    case "$reply" in y|Y|yes|YES) ;; *) info "Nothing changed."; return 0 ;; esac
  fi
  info "Applying the record sets: $DNS_SETS (waiting up to 5 minutes for the public resolvers)..."
  rc=0
  out="$(_dns_tool apply --wait 5m)" || rc=$?
  case "$rc" in
    0) ok "Applied: $DNS_SETS" ;;
    1) warn "Applied, but not everything is visible at the public resolvers yet (normal, can take longer)." ;;
    *) fail "applying the DNS records failed (exit $rc; the message is above)" ;;
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
  dns_check false
}

# ── lifecycle: the main domain's CAA pin follows Traefik's account ──

# dns_main_env_write <uri> — secrets/domains/main-domain.env (0600,
# DOMAINS_MAIN_ACME_ACCOUNT_URI): the pin the domains service's read-only
# main-domain plan judges against. A change recreates domains.
dns_main_env_write() {
  local uri="$1" f d new
  _dns_uri_ok "$uri" || { warn "not writing main-domain.env: '$uri' is not an ACME account URI"; return 1; }
  d="$(_domains_dir)"
  f="$d/main-domain.env"
  new="DOMAINS_MAIN_ACME_ACCOUNT_URI=$uri"
  [ "$(cat "$f" 2>/dev/null)" != "$new" ] || return 0
  mkdir -p "$d"
  (umask 077; printf '%s\n' "$new" > "$f.tmp") && mv -f "$f.tmp" "$f" && chmod 600 "$f" \
    || { rm -f "$f.tmp"; warn "could not write $f"; return 1; }
  info "Traefik's ACME account: $uri (secrets/domains/main-domain.env)"
  dc up -d domains >/dev/null 2>&1 || warn "could not restart the domains service to read main-domain.env"
  return 0
}

# dns_main_env_uri — the URI main-domain.env holds (nothing without it).
dns_main_env_uri() {
  sed -n 's/^DOMAINS_MAIN_ACME_ACCOUNT_URI=//p' "$(_domains_dir)/main-domain.env" 2>/dev/null | head -n1
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
  if (DNS_ACCOUNT_URI="$uri" DNS_SETS=caa DNS_IPS_DONE=1 DNS_IPV4="${PORTCULLIS_PUBLIC_IPV4:-}" DNS_IPV6="${PORTCULLIS_PUBLIC_IPV6:-}" \
      _dns_tool apply --wait 5m >/dev/null); then
    ok "CAA of $PORTCULLIS_DOMAIN pinned to $uri"
  else
    warn "could not pin the CAA of $PORTCULLIS_DOMAIN to Traefik's account (fix: ./portcullis dns setup)"
  fi
  return 0
}

# dns_relax_main — before `config apply` clears acme.json (an
# ACME_STAGING flip): the main domain's CAA back to CA-only, so the new
# account Traefik registers can order. Only warns.
dns_relax_main() {
  info "Relaxing the CAA of ${PORTCULLIS_DOMAIN:-the domain} to CA-only (Traefik registers a new ACME account)..."
  if ! (DNS_ACCOUNT_URI="" DNS_SETS=caa DNS_IPS_DONE=1 DNS_IPV4="${PORTCULLIS_PUBLIC_IPV4:-}" DNS_IPV6="${PORTCULLIS_PUBLIC_IPV6:-}" \
      _dns_tool apply >/dev/null); then
    warn "could not relax the CAA: issuance will fail on CAA until ./portcullis dns setup"
  fi
  return 0
}

# dns_status_json — the domains service's DNS report (main + enrolled
# plans, loopback API), or nothing when it isn't running.
dns_status_json() {
  dc exec -T domains domains report --main --json 2>/dev/null || true
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
