# shellcheck shell=bash
#
# `portcullis dns setup [--check]` — A/AAAA records for <domain> and
# *.<domain> pointing at this host's public IP. Providers: cloudflare,
# porkbun, digitalocean, hetzner, route53. API credentials come from .env
# and are passed to curl via stdin / process-substitution files, never as
# command-line arguments.

# _auth_curl <header-line> <curl args...> — curl with one secret header.
_auth_curl() {
  local h="$1"
  shift
  curl -sf --max-time 30 -H @<(printf '%s\n' "$h") "$@"
}

_dns_resolve() {
  local name="$1" rtype="${2:-A}"
  if command -v dig >/dev/null 2>&1; then
    dig +short "$name" @1.1.1.1 "$rtype" 2>/dev/null | head -n1
  else
    curl -sf --max-time 10 "https://cloudflare-dns.com/dns-query?name=$name&type=$rtype" \
      -H "Accept: application/dns-json" 2>/dev/null | jq -r '.Answer[0].data // empty' 2>/dev/null
  fi
}

# _dns_split <domain> — sets DNS_ROOT ("example.com") and DNS_PREFIX
# ("portcullis" for portcullis.example.com, "" for the apex).
_dns_split() {
  local d="$1" n
  n="$(printf '%s' "$d" | awk -F. '{print NF}')"
  if [ "$n" -le 2 ]; then
    DNS_ROOT="$d"; DNS_PREFIX=""
  else
    DNS_ROOT="$(printf '%s' "$d" | awk -F. '{print $(NF-1) "." $NF}')"
    DNS_PREFIX="${d%."$DNS_ROOT"}"
  fi
}

_dns_porkbun() {
  local name="$1" rtype="$2" ip="$3" api="https://api.porkbun.com/api/json/v3" endpoint id result body
  : "${PORKBUN_API_KEY:?PORKBUN_API_KEY not set}" "${PORKBUN_SECRET_API_KEY:?PORKBUN_SECRET_API_KEY not set}"
  body="$(jq -n --arg name "$name" --arg ip "$ip" --arg t "$rtype" \
    '{apikey: env.PORKBUN_API_KEY, secretapikey: env.PORKBUN_SECRET_API_KEY, name: $name, type: $t, content: $ip, ttl: "300"}')"
  endpoint="$api/dns/retrieveByNameType/$DNS_ROOT/$rtype${name:+/$name}"
  id="$(jq -n '{apikey: env.PORKBUN_API_KEY, secretapikey: env.PORKBUN_SECRET_API_KEY}' \
    | curl -sf --max-time 30 -X POST -H 'Content-Type: application/json' --data-binary @- "$endpoint" \
    | jq -r '.records[0].id // empty' 2>/dev/null || true)"
  if [ -n "$id" ]; then endpoint="$api/dns/edit/$DNS_ROOT/$id"; else endpoint="$api/dns/create/$DNS_ROOT"; fi
  result="$(printf '%s' "$body" | curl -sf --max-time 30 -X POST -H 'Content-Type: application/json' --data-binary @- "$endpoint" || true)"
  printf '%s' "$result" | jq -e '.status == "SUCCESS"' >/dev/null 2>&1 \
    || { warn "porkbun: $rtype ${name:-@}.$DNS_ROOT failed: $(printf '%s' "$result" | jq -r '.message // "no response"' 2>/dev/null)"; return 1; }
}

_dns_cloudflare() {
  local fqdn="$1" rtype="$2" ip="$3" api="https://api.cloudflare.com/client/v4" auth id
  auth="Authorization: Bearer ${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN not set}"
  [ -n "${CF_ZONE_ID:-}" ] || CF_ZONE_ID="$(_auth_curl "$auth" "$api/zones?name=$DNS_ROOT" | jq -r '.result[0].id // empty')"
  [ -n "$CF_ZONE_ID" ] || fail "Could not find the Cloudflare zone for $DNS_ROOT"
  id="$(_auth_curl "$auth" "$api/zones/$CF_ZONE_ID/dns_records?type=$rtype&name=$fqdn" | jq -r '.result[0].id // empty')"
  if [ -n "$id" ]; then
    jq -n --arg ip "$ip" '{content: $ip, ttl: 300, proxied: false}' \
      | _auth_curl "$auth" -X PATCH -H 'Content-Type: application/json' --data-binary @- "$api/zones/$CF_ZONE_ID/dns_records/$id" >/dev/null
  else
    jq -n --arg t "$rtype" --arg n "$fqdn" --arg ip "$ip" '{type: $t, name: $n, content: $ip, ttl: 300, proxied: false}' \
      | _auth_curl "$auth" -X POST -H 'Content-Type: application/json' --data-binary @- "$api/zones/$CF_ZONE_ID/dns_records" >/dev/null
  fi
}

_dns_digitalocean() {
  local name="${1:-@}" rtype="$2" ip="$3" api="https://api.digitalocean.com/v2" auth id
  auth="Authorization: Bearer ${DO_AUTH_TOKEN:?DO_AUTH_TOKEN not set}"
  id="$(_auth_curl "$auth" "$api/domains/$DNS_ROOT/records?type=$rtype&per_page=200" \
    | jq -r --arg n "$name" '.domain_records[] | select(.name == $n) | .id' | head -n1)"
  if [ -n "$id" ]; then
    jq -n --arg ip "$ip" '{data: $ip, ttl: 300}' \
      | _auth_curl "$auth" -X PUT -H 'Content-Type: application/json' --data-binary @- "$api/domains/$DNS_ROOT/records/$id" >/dev/null
  else
    jq -n --arg t "$rtype" --arg n "$name" --arg ip "$ip" '{type: $t, name: $n, data: $ip, ttl: 300}' \
      | _auth_curl "$auth" -X POST -H 'Content-Type: application/json' --data-binary @- "$api/domains/$DNS_ROOT/records" >/dev/null
  fi
}

_dns_hetzner() {
  local name="${1:-@}" rtype="$2" ip="$3" api="https://dns.hetzner.com/api/v1" auth id body
  auth="Auth-API-Token: ${HETZNER_API_KEY:?HETZNER_API_KEY not set}"
  [ -n "${HZ_ZONE_ID:-}" ] || HZ_ZONE_ID="$(_auth_curl "$auth" "$api/zones?name=$DNS_ROOT" | jq -r '.zones[0].id // empty')"
  [ -n "$HZ_ZONE_ID" ] || fail "Could not find the Hetzner zone for $DNS_ROOT"
  id="$(_auth_curl "$auth" "$api/records?zone_id=$HZ_ZONE_ID" \
    | jq -r --arg t "$rtype" --arg n "$name" '.records[] | select(.type == $t and .name == $n) | .id' | head -n1)"
  body="$(jq -n --arg z "$HZ_ZONE_ID" --arg t "$rtype" --arg n "$name" --arg ip "$ip" '{zone_id: $z, type: $t, name: $n, value: $ip, ttl: 300}')"
  if [ -n "$id" ]; then
    printf '%s' "$body" | _auth_curl "$auth" -X PUT -H 'Content-Type: application/json' --data-binary @- "$api/records/$id" >/dev/null
  else
    printf '%s' "$body" | _auth_curl "$auth" -X POST -H 'Content-Type: application/json' --data-binary @- "$api/records" >/dev/null
  fi
}

_dns_route53() {
  local domain="$1" ip4="$2" ip6="$3" changes
  : "${AWS_HOSTED_ZONE_ID:?AWS_HOSTED_ZONE_ID not set}" "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID not set}" "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY not set}"
  require_cmd aws
  # The AWS CLI reads the credentials from the environment.
  changes="$(jq -n --arg d "$domain" --arg v4 "$ip4" --arg v6 "$ip6" '
      [ ($d, "*." + $d) as $n
        | ({t: "A", v: $v4}, (if $v6 != "" then {t: "AAAA", v: $v6} else empty end))
        | {Action: "UPSERT", ResourceRecordSet: {Name: $n, Type: .t, TTL: 300, ResourceRecords: [{Value: .v}]}} ]
      | {Changes: .}')"
  aws route53 change-resource-record-sets --hosted-zone-id "$AWS_HOSTED_ZONE_ID" --change-batch "$changes" >/dev/null
}

dns_setup() {
  local check_only="$1" domain provider ip4 ip6 r r6 all_ok=true i rtype ip base wild
  require_cmd curl jq
  env_require PORTCULLIS_DOMAIN
  domain="$PORTCULLIS_DOMAIN"
  provider="${DNS_PROVIDER:-none}"

  info "Detecting public IP..."
  ip4="$(curl -4 -sf --max-time 10 ifconfig.me || curl -4 -sf --max-time 10 icanhazip.com || curl -4 -sf --max-time 10 api.ipify.org || true)"
  [ -n "$ip4" ] || fail "Could not detect the public IPv4 address"
  ip6="$(curl -6 -sf --max-time 10 ifconfig.me || curl -6 -sf --max-time 10 icanhazip.com || true)"
  ok "Public IPv4: $ip4${ip6:+, IPv6: $ip6}"

  if [ "$check_only" = true ]; then
    r="$(_dns_resolve "$domain" A)"; r6="$(_dns_resolve "test.$domain" A)"
    printf '  %-30s A    → %s\n  %-30s A    → %s\n' "$domain" "${r:-<unset>}" "*.$domain" "${r6:-<unset>}"
    { [ "$r" = "$ip4" ] && [ "$r6" = "$ip4" ]; } || { all_ok=false; warn "A records do not point to $ip4 yet."; }
    if [ -n "$ip6" ]; then
      r="$(_dns_resolve "$domain" AAAA)"; r6="$(_dns_resolve "test.$domain" AAAA)"
      printf '  %-30s AAAA → %s\n  %-30s AAAA → %s\n' "$domain" "${r:-<unset>}" "*.$domain" "${r6:-<unset>}"
      { [ "$r" = "$ip6" ] && [ "$r6" = "$ip6" ]; } || { all_ok=false; warn "AAAA records do not point to $ip6 yet."; }
    fi
    [ "$all_ok" = true ] || return 1
    ok "DNS records are correct."
    return 0
  fi

  _dns_split "$domain"
  if [ -n "$DNS_PREFIX" ]; then base="$DNS_PREFIX"; wild="*.$DNS_PREFIX"; else base=""; wild="*"; fi
  info "Setting DNS records for $domain and *.$domain (provider: $provider)..."
  case "$provider" in
    route53) _dns_route53 "$domain" "$ip4" "$ip6" ;;
    cloudflare|porkbun|digitalocean|hetzner)
      for rtype in A AAAA; do
        ip="$ip4"; [ "$rtype" = A ] || ip="$ip6"
        [ -n "$ip" ] || continue
        case "$provider" in
          cloudflare) _dns_cloudflare "$domain" "$rtype" "$ip" && _dns_cloudflare "*.$domain" "$rtype" "$ip" ;;
          porkbun) _dns_porkbun "$base" "$rtype" "$ip" && _dns_porkbun "$wild" "$rtype" "$ip" ;;
          digitalocean) _dns_digitalocean "$base" "$rtype" "$ip" && _dns_digitalocean "$wild" "$rtype" "$ip" ;;
          hetzner) _dns_hetzner "$base" "$rtype" "$ip" && _dns_hetzner "$wild" "$rtype" "$ip" ;;
        esac || fail "$provider: could not set the $rtype records"
        ok "$rtype records: $domain, *.$domain → $ip"
      done
      ;;
    *)
      warn "No automatic DNS for provider '$provider'."
      warn "Create A/AAAA records manually: $domain + *.$domain → $ip4${ip6:+ / $ip6}"
      return 0
      ;;
  esac

  info "Waiting for DNS propagation (TTL 300s, checking every 10s)..."
  for ((i = 1; i <= 30; i++)); do
    r="$(_dns_resolve "$domain" A)"
    if [ "$r" = "$ip4" ]; then
      ok "DNS verified: $domain A → $ip4"
      return 0
    fi
    printf '  attempt %d/30 — got %s\n' "$i" "${r:-<empty>}"
    sleep 10
  done
  warn "DNS not propagated after 5 minutes (normal, can take longer). Check later: ./portcullis dns setup --check"
}

help_dns() {
  cat <<'EOF'
Usage: portcullis dns setup [--check]

  setup     Create/update A/AAAA records for <domain> and *.<domain>
EOF
}

help_dns_setup() {
  cat <<'EOF'
Usage: portcullis dns setup [--check]

Create or update A (and AAAA, if the host has public IPv6) records for
PORTCULLIS_DOMAIN and *.PORTCULLIS_DOMAIN pointing at this host's public
IP, using DNS_PROVIDER and its credentials from .env:
  cloudflare    CLOUDFLARE_API_TOKEN
  porkbun       PORKBUN_API_KEY, PORKBUN_SECRET_API_KEY
  digitalocean  DO_AUTH_TOKEN
  hetzner       HETZNER_API_KEY
  route53       AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_HOSTED_ZONE_ID (needs the aws CLI)
Other providers (or none): prints the records to create by hand.

Options:
  --check   only compare what resolves (via 1.1.1.1) with the public IP;
            exits non-zero if the records are not correct yet
EOF
}

cmd_dns() {
  local sub="${1:-}" check=false
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_dns; [ -n "$sub" ] || exit 2; return 0 ;;
    setup) ;;
    *) usage_error dns "unknown subcommand: $sub" ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --check) check=true ;;
      -h|--help) help_dns_setup; return 0 ;;
      *) usage_error "dns setup" "unknown argument: $1" ;;
    esac
    shift
  done
  need_env
  dns_setup "$check"
}
