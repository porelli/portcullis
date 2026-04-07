#!/usr/bin/env bash
#
# Portcullis upgrade — safely update an existing deployment.
#
# What it does:
#   1. Backs up .env, volumes, and realm config
#   2. Merges new env vars from .env.example (without overwriting)
#   3. Pulls new images
#   4. Registers any missing OIDC clients in Keycloak
#   5. Restarts services with health checks
#
# Usage:
#   ./scripts/upgrade.sh
#   ./scripts/upgrade.sh --skip-backup
#   ./scripts/upgrade.sh --dry-run
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

SKIP_BACKUP=false
DRY_RUN=false

for arg in "$@"; do
  case "$arg" in
    --skip-backup) SKIP_BACKUP=true ;;
    --dry-run)     DRY_RUN=true ;;
    -h|--help)
      echo "Usage: $0 [--skip-backup] [--dry-run]"
      echo ""
      echo "  --skip-backup   Skip volume and config backup"
      echo "  --dry-run       Show what would happen without making changes"
      exit 0
      ;;
  esac
done

# ── Prerequisites ──────────────────────────────────────────

[ -f .env ] || fail ".env not found. Is this an existing Portcullis deployment? Run bootstrap.sh for first-time setup."

command -v docker >/dev/null || fail "docker is required"
command -v jq >/dev/null || fail "jq is required"

set -a
source .env
set +a

DOMAIN="${PORTCULLIS_DOMAIN:-portcullis.local}"

# ── Backup ─────────────────────────────────────────────────

BACKUP_DIR="backups/$(date +%Y%m%d-%H%M%S)"

if [ "$SKIP_BACKUP" = false ]; then
  info "Creating backup in $BACKUP_DIR..."

  if [ "$DRY_RUN" = true ]; then
    echo "  Would create: $BACKUP_DIR/"
    echo "  Would backup: .env, keycloak/realm-export.json, headscale/config.yaml"
    echo "  Would backup: docker volumes (portcullis postgres, lldap, vault, keycloak)"
  else
    mkdir -p "$BACKUP_DIR"

    # Config files
    cp .env "$BACKUP_DIR/.env"
    [ -f keycloak/realm-export.json ] && cp keycloak/realm-export.json "$BACKUP_DIR/realm-export.json"
    [ -f headscale/config.yaml ] && cp headscale/config.yaml "$BACKUP_DIR/headscale-config.yaml"

    # Volume data (compressed)
    info "Backing up volumes (this may take a moment)..."
    for vol in postgres_data lldap_data vault_data; do
      full_vol="$(docker compose config --format json 2>/dev/null | jq -r ".volumes.\"${vol}\".name // empty" 2>/dev/null || echo "")"
      if [ -n "$full_vol" ] && docker volume inspect "$full_vol" >/dev/null 2>&1; then
        printf "  Backing up %s..." "$vol"
        docker run --rm -v "${full_vol}:/data" -v "$(pwd)/$BACKUP_DIR:/backup" \
          alpine tar czf "/backup/${vol}.tar.gz" -C /data . 2>/dev/null \
          && echo -e " ${GREEN}done${NC}" \
          || echo -e " ${YELLOW}skipped${NC}"
      fi
    done

    ok "Backup saved to $BACKUP_DIR/"
  fi
else
  warn "Skipping backup (--skip-backup)."
fi

# ── Merge new env vars ─────────────────────────────────────

info "Checking for new environment variables..."

NEW_VARS=0
while IFS= read -r line; do
  # Skip comments, blank lines
  [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue

  KEY="${line%%=*}"

  # Check if this key exists in the current .env
  if ! grep -q "^${KEY}=" .env 2>/dev/null; then
    DEFAULT_VALUE="${line#*=}"
    NEW_VARS=$((NEW_VARS + 1))

    if [ "$DRY_RUN" = true ]; then
      echo "  Would add: ${KEY}=${DEFAULT_VALUE}"
    else
      # Generate a random value for secrets, use default for others
      case "$KEY" in
        *_SECRET|*_PASSWORD)
          GENERATED=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
          echo "${KEY}=${GENERATED}" >> .env
          echo "  Added ${KEY} (generated random value)"
          ;;
        *)
          echo "${KEY}=${DEFAULT_VALUE}" >> .env
          echo "  Added ${KEY}=${DEFAULT_VALUE}"
          ;;
      esac
    fi
  fi
done < .env.example

if [ "$NEW_VARS" -eq 0 ]; then
  ok "No new environment variables."
else
  ok "Added $NEW_VARS new variable(s) to .env"
  # Re-source after additions
  set -a
  source .env
  set +a
fi

# ── Pull new images ────────────────────────────────────────

info "Pulling latest images..."
if [ "$DRY_RUN" = true ]; then
  echo "  Would run: docker compose pull"
else
  docker compose pull --quiet 2>/dev/null || docker compose pull
  ok "Images updated."
fi

# ── Register OIDC clients in Keycloak ──────────────────────

info "Checking Keycloak OIDC clients..."

if [ "$DRY_RUN" = true ]; then
  echo "  Would check/register: portcullis-forward-auth, headscale, headplane, netbird-dashboard"
else
  export KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"

  printf "  Waiting for Keycloak..."
  KC_READY=false
  for i in $(seq 1 30); do
    if curl -sf "$KEYCLOAK_URL/health/ready" >/dev/null 2>&1; then
      KC_READY=true
      echo -e " ${GREEN}ready${NC}"
      break
    fi
    sleep 2
  done

  if [ "$KC_READY" = false ]; then
    warn "Keycloak not reachable at $KEYCLOAK_URL — skipping OIDC client registration."
    warn "You may need to register clients manually after Keycloak is up."
  else
    ./scripts/register-oidc-clients.sh || warn "Some OIDC clients may not have been registered."
    ok "OIDC clients checked."
  fi
fi

# ── Restart services ───────────────────────────────────────

info "Restarting services..."

if [ "$DRY_RUN" = true ]; then
  echo "  Would run: docker compose up -d --build --remove-orphans"
else
  docker compose up -d --build --remove-orphans

  # Health checks
  info "Waiting for services to be healthy..."
  SERVICES_TO_CHECK=(vault postgres lldap)

  for svc in "${SERVICES_TO_CHECK[@]}"; do
    printf "  Waiting for %s..." "$svc"
    for i in $(seq 1 30); do
      if docker compose ps --format json "$svc" 2>/dev/null | jq -e '.Health == "healthy"' >/dev/null 2>&1; then
        echo -e " ${GREEN}ready${NC}"
        break
      fi
      if [ "$i" -eq 30 ]; then
        echo -e " ${YELLOW}timeout (may still be starting)${NC}"
      fi
      sleep 2
    done
  done

  # Keycloak takes longer
  printf "  Waiting for Keycloak..."
  for i in $(seq 1 60); do
    if curl -sf http://localhost:8080/health/ready >/dev/null 2>&1; then
      echo -e " ${GREEN}ready${NC}"
      break
    fi
    if [ "$i" -eq 60 ]; then
      echo -e " ${YELLOW}may still be starting${NC}"
    fi
    sleep 3
  done

  ok "Services restarted."
fi

# ── Summary ────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$DRY_RUN" = true ]; then
  info "Dry run complete — no changes were made."
else
  ok "Upgrade complete!"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
if [ "$SKIP_BACKUP" = false ] && [ "$DRY_RUN" = false ]; then
  echo "  Backup:    $BACKUP_DIR/"
  echo "  Restore:   cp $BACKUP_DIR/.env .env"
  echo ""
fi
echo "  Verify:"
echo "    docker compose ps"
echo "    curl -k https://enroll.${DOMAIN}"
echo ""
