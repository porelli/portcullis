#!/usr/bin/env bash
#
# Portcullis DNS setup — creates A/AAAA + wildcard records pointing to this server.
#
# Supports: porkbun, cloudflare, digitalocean, hetzner, route53
#
# Usage:
#   ./scripts/setup-dns.sh              # auto-detect from .env
#   ./scripts/setup-dns.sh --check      # verify records only
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${BLUE}==>${NC} $*"; }
ok()    { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}==>${NC} $*"; }
fail()  { echo -e "${RED}ERROR:${NC} $*"; exit 1; }

# Load .env
[ -f .env ] || fail "No .env file found. Run bootstrap first."
set -a; source .env; set +a

DOMAIN="${PORTCULLIS_DOMAIN:?PORTCULLIS_DOMAIN not set}"
PROVIDER="${DNS_PROVIDER:?DNS_PROVIDER not set}"
CHECK_ONLY="${1:-}"

# Detect public IPs
info "Detecting public IP..."
PUBLIC_IP=$(curl -4 -sf ifconfig.me || curl -4 -sf icanhazip.com || curl -4 -sf api.ipify.org) \
  || fail "Could not detect public IPv4"
ok "Public IPv4: $PUBLIC_IP"

PUBLIC_IP6=$(curl -6 -sf ifconfig.me || curl -6 -sf icanhazip.com || true)
if [ -n "$PUBLIC_IP6" ]; then
  ok "Public IPv6: $PUBLIC_IP6"
else
  warn "No IPv6 detected — skipping AAAA records"
fi

# ── Helper: extract root domain and subdomain prefix ──────
# e.g. "portcullis.example.org" → root="example.org", prefix="portcullis"
# e.g. "example.com" → root="example.com", prefix=""
parse_domain() {
  local d="$1"
  local parts
  IFS='.' read -ra parts <<< "$d"
  local n=${#parts[@]}
  if [ "$n" -le 2 ]; then
    ROOT_DOMAIN="$d"
    SUBDOMAIN_PREFIX=""
  else
    ROOT_DOMAIN="${parts[$((n-2))]}.${parts[$((n-1))]}"
    SUBDOMAIN_PREFIX="${d%."$ROOT_DOMAIN"}"
  fi
}

parse_domain "$DOMAIN"
info "Root domain: $ROOT_DOMAIN"
[ -n "$SUBDOMAIN_PREFIX" ] && info "Subdomain prefix: $SUBDOMAIN_PREFIX"

# Records to create:
#   DOMAIN        → A record → PUBLIC_IP   (e.g. portcullis.example.org)
#   *.DOMAIN      → A record → PUBLIC_IP   (e.g. *.portcullis.example.org)
# In API terms (relative to root domain):
#   name=SUBDOMAIN_PREFIX  type=A  content=PUBLIC_IP
#   name=*.SUBDOMAIN_PREFIX  type=A  content=PUBLIC_IP
# If DOMAIN is the root itself:
#   name=""  type=A
#   name="*" type=A

if [ -n "$SUBDOMAIN_PREFIX" ]; then
  RECORD_BASE="$SUBDOMAIN_PREFIX"
  RECORD_WILDCARD="*.$SUBDOMAIN_PREFIX"
else
  RECORD_BASE=""
  RECORD_WILDCARD="*"
fi

# ── Check mode ────────────────────────────────────────────
resolve() {
  local name="$1" rtype="${2:-A}"
  if command -v dig >/dev/null 2>&1; then
    dig +short "$name" @1.1.1.1 "$rtype" 2>/dev/null | head -1
  else
    curl -sf "https://cloudflare-dns.com/dns-query?name=$name&type=$rtype" \
      -H "Accept: application/dns-json" 2>/dev/null \
      | jq -r '.Answer[0].data // empty' 2>/dev/null
  fi
}

if [ "$CHECK_ONLY" = "--check" ]; then
  info "Checking DNS resolution..."
  RESOLVED=$(resolve "$DOMAIN" A)
  RESOLVED_WC=$(resolve "test.$DOMAIN" A)
  echo "  $DOMAIN      A    → ${RESOLVED:-<unset>}"
  echo "  *.$DOMAIN    A    → ${RESOLVED_WC:-<unset>}"
  ALL_OK=true
  if [ "$RESOLVED" != "$PUBLIC_IP" ] || [ "$RESOLVED_WC" != "$PUBLIC_IP" ]; then
    ALL_OK=false
    warn "A records do not point to $PUBLIC_IP yet."
  fi
  if [ -n "$PUBLIC_IP6" ]; then
    RESOLVED6=$(resolve "$DOMAIN" AAAA)
    RESOLVED_WC6=$(resolve "test.$DOMAIN" AAAA)
    echo "  $DOMAIN      AAAA → ${RESOLVED6:-<unset>}"
    echo "  *.$DOMAIN    AAAA → ${RESOLVED_WC6:-<unset>}"
    if [ "$RESOLVED6" != "$PUBLIC_IP6" ] || [ "$RESOLVED_WC6" != "$PUBLIC_IP6" ]; then
      ALL_OK=false
      warn "AAAA records do not point to $PUBLIC_IP6 yet."
    fi
  fi
  $ALL_OK && ok "DNS records are correct."
  exit 0
fi

# ── Provider: Porkbun ─────────────────────────────────────
setup_porkbun() {
  local api_key="${PORKBUN_API_KEY:?PORKBUN_API_KEY not set}"
  local secret_key="${PORKBUN_SECRET_API_KEY:?PORKBUN_SECRET_API_KEY not set}"
  local api="https://api.porkbun.com/api/json/v3"
  local auth="{\"apikey\":\"$api_key\",\"secretapikey\":\"$secret_key\"}"

  create_or_update_porkbun() {
    local name="$1"
    local rtype="$2"
    local ip="$3"
    local display_name="${name:-@}"

    info "Setting $rtype record: ${display_name}.${ROOT_DOMAIN} → $ip"

    # Check if record exists
    local endpoint="$api/dns/retrieveByNameType/$ROOT_DOMAIN/$rtype"
    [ -n "$name" ] && endpoint="$endpoint/$name"

    local existing
    existing=$(curl -sf -X POST "$endpoint" \
      -H "Content-Type: application/json" \
      -d "$auth" 2>/dev/null) || existing="{}"

    local record_id
    record_id=$(echo "$existing" | jq -r '.records[0].id // empty' 2>/dev/null)

    if [ -n "$record_id" ]; then
      local result
      result=$(curl -sf -X POST "$api/dns/edit/$ROOT_DOMAIN/$record_id" \
        -H "Content-Type: application/json" \
        -d "$(jq -n --arg key "$api_key" --arg secret "$secret_key" \
               --arg name "$name" --arg ip "$ip" --arg rtype "$rtype" \
               '{apikey:$key, secretapikey:$secret, name:$name, type:$rtype, content:$ip, ttl:"300"}')")
      if echo "$result" | jq -e '.status == "SUCCESS"' >/dev/null 2>&1; then
        ok "Updated $rtype record: ${display_name}.${ROOT_DOMAIN} → $ip"
      else
        warn "Failed to update record: $(echo "$result" | jq -r '.message // "unknown error"')"
      fi
    else
      local result
      result=$(curl -sf -X POST "$api/dns/create/$ROOT_DOMAIN" \
        -H "Content-Type: application/json" \
        -d "$(jq -n --arg key "$api_key" --arg secret "$secret_key" \
               --arg name "$name" --arg ip "$ip" --arg rtype "$rtype" \
               '{apikey:$key, secretapikey:$secret, name:$name, type:$rtype, content:$ip, ttl:"300"}')")
      if echo "$result" | jq -e '.status == "SUCCESS"' >/dev/null 2>&1; then
        ok "Created $rtype record: ${display_name}.${ROOT_DOMAIN} → $ip"
      else
        warn "Failed to create record: $(echo "$result" | jq -r '.message // "unknown error"')"
      fi
    fi
  }

  create_or_update_porkbun "$RECORD_BASE" "A" "$PUBLIC_IP"
  create_or_update_porkbun "$RECORD_WILDCARD" "A" "$PUBLIC_IP"
  if [ -n "$PUBLIC_IP6" ]; then
    create_or_update_porkbun "$RECORD_BASE" "AAAA" "$PUBLIC_IP6"
    create_or_update_porkbun "$RECORD_WILDCARD" "AAAA" "$PUBLIC_IP6"
  fi
}

# ── Provider: Cloudflare ──────────────────────────────────
setup_cloudflare() {
  local token="${CLOUDFLARE_API_TOKEN:?CLOUDFLARE_API_TOKEN not set}"
  local api="https://api.cloudflare.com/client/v4"
  local auth_header="Authorization: Bearer $token"

  # Get zone ID for root domain
  local zone_resp
  zone_resp=$(curl -sf "$api/zones?name=$ROOT_DOMAIN" -H "$auth_header")
  local zone_id
  zone_id=$(echo "$zone_resp" | jq -r '.result[0].id // empty')
  [ -n "$zone_id" ] || fail "Could not find Cloudflare zone for $ROOT_DOMAIN"

  create_or_update_cf() {
    local fqdn="$1"
    local rtype="$2"
    local ip="$3"

    info "Setting $rtype record: $fqdn → $ip"

    local existing
    existing=$(curl -sf "$api/zones/$zone_id/dns_records?type=$rtype&name=$fqdn" -H "$auth_header")
    local record_id
    record_id=$(echo "$existing" | jq -r '.result[0].id // empty')

    if [ -n "$record_id" ]; then
      curl -sf -X PATCH "$api/zones/$zone_id/dns_records/$record_id" \
        -H "$auth_header" -H "Content-Type: application/json" \
        -d "{\"content\":\"$ip\",\"ttl\":300,\"proxied\":false}" >/dev/null
      ok "Updated $rtype record: $fqdn → $ip"
    else
      curl -sf -X POST "$api/zones/$zone_id/dns_records" \
        -H "$auth_header" -H "Content-Type: application/json" \
        -d "{\"type\":\"$rtype\",\"name\":\"$fqdn\",\"content\":\"$ip\",\"ttl\":300,\"proxied\":false}" >/dev/null
      ok "Created $rtype record: $fqdn → $ip"
    fi
  }

  create_or_update_cf "$DOMAIN" "A" "$PUBLIC_IP"
  create_or_update_cf "*.$DOMAIN" "A" "$PUBLIC_IP"
  if [ -n "$PUBLIC_IP6" ]; then
    create_or_update_cf "$DOMAIN" "AAAA" "$PUBLIC_IP6"
    create_or_update_cf "*.$DOMAIN" "AAAA" "$PUBLIC_IP6"
  fi
}

# ── Provider: DigitalOcean ────────────────────────────────
setup_digitalocean() {
  local token="${DO_AUTH_TOKEN:?DO_AUTH_TOKEN not set}"
  local api="https://api.digitalocean.com/v2"
  local auth_header="Authorization: Bearer $token"

  create_or_update_do() {
    local name="$1"
    local rtype="$2"
    local ip="$3"
    local display="${name:-@}"

    info "Setting $rtype record: ${display}.${ROOT_DOMAIN} → $ip"

    local existing
    existing=$(curl -sf "$api/domains/$ROOT_DOMAIN/records?type=$rtype&name=$name" \
      -H "$auth_header")
    local record_id
    record_id=$(echo "$existing" | jq -r ".domain_records[] | select(.name == \"$name\") | .id" 2>/dev/null | head -1)

    if [ -n "$record_id" ]; then
      curl -sf -X PUT "$api/domains/$ROOT_DOMAIN/records/$record_id" \
        -H "$auth_header" -H "Content-Type: application/json" \
        -d "{\"data\":\"$ip\",\"ttl\":300}" >/dev/null
      ok "Updated $rtype record: ${display}.${ROOT_DOMAIN} → $ip"
    else
      curl -sf -X POST "$api/domains/$ROOT_DOMAIN/records" \
        -H "$auth_header" -H "Content-Type: application/json" \
        -d "{\"type\":\"$rtype\",\"name\":\"$name\",\"data\":\"$ip\",\"ttl\":300}" >/dev/null
      ok "Created $rtype record: ${display}.${ROOT_DOMAIN} → $ip"
    fi
  }

  create_or_update_do "$RECORD_BASE" "A" "$PUBLIC_IP"
  create_or_update_do "$RECORD_WILDCARD" "A" "$PUBLIC_IP"
  if [ -n "$PUBLIC_IP6" ]; then
    create_or_update_do "$RECORD_BASE" "AAAA" "$PUBLIC_IP6"
    create_or_update_do "$RECORD_WILDCARD" "AAAA" "$PUBLIC_IP6"
  fi
}

# ── Provider: Hetzner ─────────────────────────────────────
setup_hetzner() {
  local token="${HETZNER_API_KEY:?HETZNER_API_KEY not set}"
  local api="https://dns.hetzner.com/api/v1"
  local auth_header="Auth-API-Token: $token"

  # Get zone ID
  local zones
  zones=$(curl -sf "$api/zones?name=$ROOT_DOMAIN" -H "$auth_header")
  local zone_id
  zone_id=$(echo "$zones" | jq -r '.zones[0].id // empty')
  [ -n "$zone_id" ] || fail "Could not find Hetzner zone for $ROOT_DOMAIN"

  create_or_update_hz() {
    local name="$1"
    local rtype="$2"
    local ip="$3"
    local display="${name:-@}"

    info "Setting $rtype record: ${display}.${ROOT_DOMAIN} → $ip"

    local existing
    existing=$(curl -sf "$api/records?zone_id=$zone_id" -H "$auth_header")
    local record_id
    record_id=$(echo "$existing" | jq -r ".records[] | select(.type == \"$rtype\" and .name == \"$name\") | .id" 2>/dev/null | head -1)

    if [ -n "$record_id" ]; then
      curl -sf -X PUT "$api/records/$record_id" \
        -H "$auth_header" -H "Content-Type: application/json" \
        -d "{\"zone_id\":\"$zone_id\",\"type\":\"$rtype\",\"name\":\"$name\",\"value\":\"$ip\",\"ttl\":300}" >/dev/null
      ok "Updated $rtype record: ${display}.${ROOT_DOMAIN} → $ip"
    else
      curl -sf -X POST "$api/records" \
        -H "$auth_header" -H "Content-Type: application/json" \
        -d "{\"zone_id\":\"$zone_id\",\"type\":\"$rtype\",\"name\":\"$name\",\"value\":\"$ip\",\"ttl\":300}" >/dev/null
      ok "Created $rtype record: ${display}.${ROOT_DOMAIN} → $ip"
    fi
  }

  create_or_update_hz "$RECORD_BASE" "A" "$PUBLIC_IP"
  create_or_update_hz "$RECORD_WILDCARD" "A" "$PUBLIC_IP"
  if [ -n "$PUBLIC_IP6" ]; then
    create_or_update_hz "$RECORD_BASE" "AAAA" "$PUBLIC_IP6"
    create_or_update_hz "$RECORD_WILDCARD" "AAAA" "$PUBLIC_IP6"
  fi
}

# ── Provider: Route53 ─────────────────────────────────────
setup_route53() {
  local zone_id="${AWS_HOSTED_ZONE_ID:?AWS_HOSTED_ZONE_ID not set}"
  : "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID not set}"
  : "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY not set}"

  command -v aws >/dev/null || fail "AWS CLI is required for Route53 DNS setup"

  info "Setting A records via Route53..."

  local changes
  changes=$(cat <<EOFJSON
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$DOMAIN",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{"Value": "$PUBLIC_IP"}]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "*.$DOMAIN",
        "Type": "A",
        "TTL": 300,
        "ResourceRecords": [{"Value": "$PUBLIC_IP"}]
      }
    }
EOFJSON
)

  if [ -n "$PUBLIC_IP6" ]; then
    changes="$changes,"
    changes="$changes $(cat <<EOFJSON
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$DOMAIN",
        "Type": "AAAA",
        "TTL": 300,
        "ResourceRecords": [{"Value": "$PUBLIC_IP6"}]
      }
    },
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "*.$DOMAIN",
        "Type": "AAAA",
        "TTL": 300,
        "ResourceRecords": [{"Value": "$PUBLIC_IP6"}]
      }
    }
EOFJSON
)"
  fi

  aws route53 change-resource-record-sets \
    --hosted-zone-id "$zone_id" \
    --change-batch "{\"Changes\": [$changes]}" >/dev/null

  ok "Created/updated A records: $DOMAIN + *.$DOMAIN → $PUBLIC_IP"
  [ -n "$PUBLIC_IP6" ] && ok "Created/updated AAAA records: $DOMAIN + *.$DOMAIN → $PUBLIC_IP6"
}

# ── Dispatch ──────────────────────────────────────────────

info "Setting up DNS records for $DOMAIN (provider: $PROVIDER)..."

case "$PROVIDER" in
  porkbun)       setup_porkbun ;;
  cloudflare)    setup_cloudflare ;;
  digitalocean)  setup_digitalocean ;;
  hetzner)       setup_hetzner ;;
  route53)       setup_route53 ;;
  none)
    warn "DNS provider is 'none' — skipping automatic DNS setup."
    warn "Manually create A/AAAA records: $DOMAIN + *.$DOMAIN → $PUBLIC_IP${PUBLIC_IP6:+ / $PUBLIC_IP6}"
    exit 0
    ;;
  *)
    warn "Unsupported DNS provider '$PROVIDER' for automatic record creation."
    warn "Manually create A/AAAA records: $DOMAIN + *.$DOMAIN → $PUBLIC_IP${PUBLIC_IP6:+ / $PUBLIC_IP6}"
    exit 0
    ;;
esac

# ── Verify ────────────────────────────────────────────────

info "Waiting for DNS propagation (TTL 300s, checking every 10s)..."
for i in $(seq 1 30); do
  RESOLVED=$(resolve "$DOMAIN" A)
  if [ "$RESOLVED" = "$PUBLIC_IP" ]; then
    ok "DNS verified: $DOMAIN A → $PUBLIC_IP"
    if [ -n "$PUBLIC_IP6" ]; then
      RESOLVED6=$(resolve "$DOMAIN" AAAA)
      [ "$RESOLVED6" = "$PUBLIC_IP6" ] && ok "DNS verified: $DOMAIN AAAA → $PUBLIC_IP6"
    fi
    exit 0
  fi
  printf "  attempt %d/30 — got '%s', waiting...\n" "$i" "${RESOLVED:-<empty>}"
  sleep 10
done

warn "DNS not yet propagated after 5 minutes. This is normal — it may take up to 10 minutes."
warn "Verify with: ./scripts/setup-dns.sh --check"
