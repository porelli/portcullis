#!/usr/bin/env bash
#
# Portcullis bootstrap — one-command setup.
#
# Usage:
#   ./scripts/bootstrap.sh
#   PORTCULLIS_DOMAIN=example.com ./scripts/bootstrap.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${BLUE}==>${NC} $*"; }
ok()    { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}==>${NC} $*"; }
fail()  { echo -e "${RED}ERROR:${NC} $*"; exit 1; }

# ── Prerequisites ──────────────────────────────────────────

info "Checking prerequisites..."

command -v docker >/dev/null || fail "docker is required"
command -v docker compose version >/dev/null 2>&1 || command -v docker-compose >/dev/null || fail "docker compose is required"
command -v jq >/dev/null || fail "jq is required"

ok "All prerequisites met."

# ── Environment ────────────────────────────────────────────

# Check for .env in config/ (symlinked) or project root
if [ ! -f .env ]; then
  info "Creating .env from template..."
  # .env holds every secret — create it owner-only.
  OLD_UMASK=$(umask)
  umask 077
  cp .env.example .env

  # Generate random passwords
  GENERATED_PG_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
  GENERATED_KC_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
  GENERATED_LLDAP_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
  GENERATED_JWT=$(openssl rand -base64 32)
  GENERATED_FWD_CLIENT_SECRET=$(openssl rand -base64 48 | tr -dc 'a-zA-Z0-9' | head -c 40)
  # oauth2-proxy cookie secret must decode to exactly 16, 24 or 32 bytes:
  # base64url-encode 32 random bytes (44 chars incl. padding).
  GENERATED_FWD_COOKIE_SECRET=$(openssl rand -base64 32 | tr -- '+/' '-_')

  # Prompt for domain
  DOMAIN="${PORTCULLIS_DOMAIN:-}"
  if [ -z "$DOMAIN" ]; then
    echo ""
    read -rp "Enter your domain (e.g., portcullis.example.com): " DOMAIN
    DOMAIN="${DOMAIN:-portcullis.local}"
  fi

  # Prompt for ACME email
  read -rp "Enter email for Let's Encrypt notifications [$DOMAIN admin]: " ACME_EMAIL
  ACME_EMAIL="${ACME_EMAIL:-admin@$DOMAIN}"

  # Prompt for DNS provider
  echo ""
  info "Supported DNS providers for wildcard certs (ACME DNS-01):"
  echo "  1) cloudflare    (default)"
  echo "  2) porkbun"
  echo "  3) route53       (AWS)"
  echo "  4) digitalocean"
  echo "  5) hetzner"
  echo "  6) none           (local dev — self-signed certs)"
  echo ""
  read -rp "DNS provider [cloudflare]: " DNS_PROVIDER_INPUT
  DNS_PROVIDER="${DNS_PROVIDER_INPUT:-cloudflare}"

  DNS_ENV_LINES=""
  case "$DNS_PROVIDER" in
    cloudflare|1)
      DNS_PROVIDER="cloudflare"
      read -rp "Cloudflare API token: " CF_TOKEN
      DNS_ENV_LINES="CLOUDFLARE_API_TOKEN=${CF_TOKEN:-}"
      ;;
    porkbun|2)
      DNS_PROVIDER="porkbun"
      read -rp "Porkbun API key: " PB_KEY
      read -rp "Porkbun secret API key: " PB_SECRET
      DNS_ENV_LINES="PORKBUN_API_KEY=${PB_KEY:-}
PORKBUN_SECRET_API_KEY=${PB_SECRET:-}"
      ;;
    route53|3)
      DNS_PROVIDER="route53"
      read -rp "AWS Access Key ID: " AWS_KEY
      read -rp "AWS Secret Access Key: " AWS_SECRET
      read -rp "AWS Hosted Zone ID: " AWS_ZONE
      DNS_ENV_LINES="AWS_ACCESS_KEY_ID=${AWS_KEY:-}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET:-}
AWS_HOSTED_ZONE_ID=${AWS_ZONE:-}"
      ;;
    digitalocean|4)
      DNS_PROVIDER="digitalocean"
      read -rp "DigitalOcean auth token: " DO_TOKEN
      DNS_ENV_LINES="DO_AUTH_TOKEN=${DO_TOKEN:-}"
      ;;
    hetzner|5)
      DNS_PROVIDER="hetzner"
      read -rp "Hetzner API key: " HZ_KEY
      DNS_ENV_LINES="HETZNER_API_KEY=${HZ_KEY:-}"
      ;;
    none|6)
      DNS_PROVIDER="none"
      warn "No DNS provider — will use self-signed certs via Vault PKI."
      DNS_ENV_LINES=""
      ;;
    *)
      # Custom provider — user knows the lego provider name
      DNS_PROVIDER="$DNS_PROVIDER_INPUT"
      warn "Using custom provider '$DNS_PROVIDER'. Set its env vars in .env after bootstrap."
      DNS_ENV_LINES=""
      ;;
  esac

  # Write .env
  cat > .env <<EOF
PORTCULLIS_DOMAIN=$DOMAIN
ACME_EMAIL=$ACME_EMAIL
DNS_PROVIDER=$DNS_PROVIDER
$DNS_ENV_LINES

KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=$GENERATED_KC_PASS
POSTGRES_PASSWORD=$GENERATED_PG_PASS
LLDAP_ADMIN_PASSWORD=$GENERATED_LLDAP_PASS
LLDAP_JWT_SECRET=$GENERATED_JWT
LLDAP_BASE_DN=dc=$(echo "$DOMAIN" | sed 's/\./,dc=/g')

FORWARD_AUTH_CLIENT_SECRET=$GENERATED_FWD_CLIENT_SECRET
FORWARD_AUTH_COOKIE_SECRET=$GENERATED_FWD_COOKIE_SECRET

# Fixed IPAM for portcullis-proxy; header-auth apps trust only Traefik's IP.
# Change only if it collides with a host network (see .env.example).
PORTCULLIS_PROXY_SUBNET=172.31.250.0/24
PORTCULLIS_PROXY_IP_RANGE=172.31.250.128/25
PORTCULLIS_TRAEFIK_IP=172.31.250.2
EOF
  chmod 600 .env
  umask "$OLD_UMASK"

  ok "Generated .env with random passwords."
  echo ""
  warn "IMPORTANT: Save these credentials somewhere safe!"
  echo "  Keycloak admin:    admin / $GENERATED_KC_PASS"
  echo "  LLDAP admin:       admin / $GENERATED_LLDAP_PASS"
  echo "  Vault:             root token + unseal key will be in secrets/vault-init.json"
  echo "  PostgreSQL:        keycloak / $GENERATED_PG_PASS"
  echo ""
else
  info "Using existing .env file."
fi

# Existing .env from an older release: add the proxy network settings the
# Hub copies into app envs (header-auth apps need PORTCULLIS_TRAEFIK_IP).
for kv in PORTCULLIS_PROXY_SUBNET=172.31.250.0/24 \
          PORTCULLIS_PROXY_IP_RANGE=172.31.250.128/25 \
          PORTCULLIS_TRAEFIK_IP=172.31.250.2; do
  grep -q "^${kv%%=*}=" .env || { echo "$kv" >> .env; info "Added ${kv} to .env"; }
done

# Source the env
set -a
source .env
set +a

# shellcheck source=lib/proxy-network.sh
source "$SCRIPT_DIR/lib/proxy-network.sh"
NET_ERR="$(validate_proxy_network_config)" || fail "Invalid portcullis-proxy settings in .env: $NET_ERR"
if [ "$(proxy_network_state)" = mismatch ]; then
  fail "Docker network portcullis-proxy exists with a different IPAM config. Run ./scripts/upgrade.sh (it recreates the network)."
fi

# ── DNS records ───────────────────────────────────────────

info "Setting up DNS records..."
./scripts/setup-dns.sh

# ── Start services ─────────────────────────────────────────

# Bind-mount sources must exist before compose runs, or Docker creates
# them root-owned and the scripts below can't write into them.
(umask 077 && mkdir -p secrets/vault-unseal secrets/enroll)
mkdir -p certs/revocation
# Hub copies app template dirs here (bind-mounted rw into the hub).
mkdir -p templates
# Mountpoints for the Hub's tmpfs masks (must exist inside the ro /project bind).
mkdir -p secrets backups
[ -f certs/revocation/revoked-serials.txt ] || : > certs/revocation/revoked-serials.txt

info "Starting and initialising Vault..."
./scripts/vault-init.sh

# forward-auth bind-mounts certs/ca-bundle.crt: it must be a file before
# `up` (rebuilt below once the internal CA exists).
./scripts/apply-config.sh --bundle-only

info "Starting services..."
docker compose up -d --build

info "Waiting for services to be healthy..."
for svc in vault postgres lldap keycloak; do
  printf "  Waiting for %s..." "$svc"
  for i in $(seq 1 60); do
    if docker compose ps --format json "$svc" 2>/dev/null | jq -e '.Health == "healthy"' >/dev/null 2>&1; then
      echo -e " ${GREEN}ready${NC}"
      break
    fi
    if [ "$i" -eq 60 ]; then
      echo -e " ${RED}timeout${NC}"
      fail "$svc did not become healthy in time. Check: docker compose logs $svc"
    fi
    sleep 3
  done
done

# ── Initialize Vault PKI ──────────────────────────────────

info "Initializing Vault PKI..."
export VAULT_ADDR=http://127.0.0.1:8200
export DOMAIN="$PORTCULLIS_DOMAIN"

# Token comes from secrets/vault-init.json. Skips (no-op) if the PKI exists.
./scripts/setup-vault-pki.sh --with-server-cert

# ── Restart Traefik (pick up certs) ───────────────────────

info "Rebuilding CA bundle with the internal CA chain..."
./scripts/apply-config.sh --bundle-only

info "Restarting Traefik and forward-auth to pick up the CA chain..."
docker compose restart traefik forward-auth

# ── Configure Keycloak ────────────────────────────────────

info "Configuring Keycloak..."

# keycloak/realm-export.json is git-tracked and keeps its
# LLDAP_*_PLACEHOLDER values. configure-keycloak.sh substitutes them in
# memory for its API import and PUTs the real bind DN / password onto the
# LDAP federation component, so no secret is ever written to the repo.

# Run configure-keycloak inside the network so it can reach keycloak:8080
export KEYCLOAK_URL="http://localhost:8080"
./scripts/configure-keycloak.sh

# ── Register OIDC Clients ─────────────────────────────────

info "Registering OIDC clients..."
./scripts/register-oidc-clients.sh
ok "OIDC clients registered."

# ── Initialize config directory ───────────────────────────

info "Initializing config directory..."
./scripts/init-config.sh
ok "Config directory ready — version your settings with: cd config && git push"

# ── Done ──────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "Portcullis is running!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Services:"
echo "    Enrollment UI:   https://enroll.${PORTCULLIS_DOMAIN}"
echo "    Directory (LLDAP): https://directory.${PORTCULLIS_DOMAIN}"
echo "    Identity (Keycloak): https://auth.${PORTCULLIS_DOMAIN}"
echo "    Gateway (Traefik): https://traefik.${PORTCULLIS_DOMAIN}"
echo "    Vault:           http://localhost:8200  (root token: secrets/vault-init.json)"
echo ""
echo "  Next steps:"
echo "    1. Log into LLDAP and create users: https://directory.${PORTCULLIS_DOMAIN}"
echo "       (admin / check .env for password)"
echo "    2. Enroll a YubiKey:"
echo "       ./scripts/enroll-yubikey.sh <username> <email>"
echo "       Or use the web UI: https://enroll.${PORTCULLIS_DOMAIN}"
echo ""
warn "Back up secrets/vault-init.json OFFLINE (Vault root token + unseal key)."
echo ""
