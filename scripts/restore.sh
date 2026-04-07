#!/usr/bin/env bash
#
# Portcullis restore — restore from a backup created by upgrade.sh.
#
# Usage:
#   ./scripts/restore.sh <backup-dir>
#   ./scripts/restore.sh backups/20240115-143022
#   ./scripts/restore.sh --list                    # list available backups
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
DIM='\033[2m'
NC='\033[0m'

info()  { echo -e "${BLUE}==>${NC} $*"; }
ok()    { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}==>${NC} $*"; }
fail()  { echo -e "${RED}ERROR:${NC} $*"; exit 1; }

# ── List backups ───────────────────────────────────────────

if [ "${1:-}" = "--list" ] || [ "${1:-}" = "-l" ]; then
  if [ ! -d backups ] || [ -z "$(ls -A backups 2>/dev/null)" ]; then
    echo "No backups found in backups/"
    exit 0
  fi

  echo "Available backups:"
  echo ""
  for dir in backups/*/; do
    [ -d "$dir" ] || continue
    dirname=$(basename "$dir")
    files=$(ls -1 "$dir" 2>/dev/null | tr '\n' ', ' | sed 's/,$//')
    size=$(du -sh "$dir" 2>/dev/null | cut -f1)
    echo "  $dirname  ($size)  [$files]"
  done
  echo ""
  echo "Restore with: $0 backups/<dirname>"
  exit 0
fi

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  echo "Usage: $0 <backup-dir>    Restore from backup"
  echo "       $0 --list          List available backups"
  exit 0
fi

# ── Validate ───────────────────────────────────────────────

BACKUP_DIR="${1:-}"
[ -z "$BACKUP_DIR" ] && fail "Usage: $0 <backup-dir>  (use --list to see available backups)"
[ -d "$BACKUP_DIR" ] || fail "Backup directory not found: $BACKUP_DIR"
[ -f "$BACKUP_DIR/.env" ] || fail "No .env found in backup — is this a valid Portcullis backup?"

echo ""
echo "Backup contents:"
ls -lh "$BACKUP_DIR/" | tail -n +2 | sed 's/^/  /'
echo ""

# ── Confirm ────────────────────────────────────────────────

warn "This will:"
echo "  1. Stop all Portcullis services"
echo "  2. Replace .env with the backed-up version"
if [ -f "$BACKUP_DIR/realm-export.json" ]; then
  echo "  3. Replace keycloak/realm-export.json"
fi
if [ -f "$BACKUP_DIR/headscale-config.yaml" ]; then
  echo "  4. Replace headscale/config.yaml"
fi
for vol_archive in "$BACKUP_DIR"/*.tar.gz; do
  [ -f "$vol_archive" ] || continue
  vol_name=$(basename "$vol_archive" .tar.gz)
  echo "  *  Restore volume: $vol_name"
done
echo ""

read -rp "Continue with restore? [y/N] " CONFIRM
case "$CONFIRM" in
  y|Y|yes|YES) ;;
  *) echo "Cancelled."; exit 0 ;;
esac

# ── Pre-restore backup of current state ────────────────────

PRE_RESTORE_DIR="backups/pre-restore-$(date +%Y%m%d-%H%M%S)"
info "Saving current .env to $PRE_RESTORE_DIR/ (just in case)..."
mkdir -p "$PRE_RESTORE_DIR"
cp .env "$PRE_RESTORE_DIR/.env"
ok "Current .env saved."

# ── Stop services ──────────────────────────────────────────

info "Stopping services..."
docker compose down
ok "Services stopped."

# ── Restore .env ───────────────────────────────────────────

info "Restoring .env..."
cp "$BACKUP_DIR/.env" .env
ok ".env restored."

# ── Restore config files ──────────────────────────────────

if [ -f "$BACKUP_DIR/realm-export.json" ]; then
  info "Restoring keycloak/realm-export.json..."
  cp "$BACKUP_DIR/realm-export.json" keycloak/realm-export.json
  ok "Realm config restored."
fi

if [ -f "$BACKUP_DIR/headscale-config.yaml" ]; then
  info "Restoring headscale/config.yaml..."
  mkdir -p headscale
  cp "$BACKUP_DIR/headscale-config.yaml" headscale/config.yaml
  ok "Headscale config restored."
fi

# ── Restore volumes ───────────────────────────────────────

set -a; source .env; set +a

for vol_archive in "$BACKUP_DIR"/*.tar.gz; do
  [ -f "$vol_archive" ] || continue
  vol_name=$(basename "$vol_archive" .tar.gz)

  # Find the actual Docker volume name
  full_vol=$(docker compose config --format json 2>/dev/null | jq -r ".volumes.\"${vol_name}\".name // empty" 2>/dev/null || echo "")

  if [ -z "$full_vol" ]; then
    warn "Volume $vol_name not found in compose config — skipping."
    continue
  fi

  info "Restoring volume $vol_name..."

  # Ensure volume exists
  docker volume create "$full_vol" >/dev/null 2>&1 || true

  # Restore data
  docker run --rm \
    -v "${full_vol}:/data" \
    -v "$(cd "$BACKUP_DIR" && pwd):/backup:ro" \
    alpine sh -c "rm -rf /data/* && tar xzf /backup/${vol_name}.tar.gz -C /data"

  ok "Volume $vol_name restored."
done

# ── Restart ────────────────────────────────────────────────

info "Starting services..."
docker compose up -d

info "Waiting for services to be healthy..."
for svc in vault postgres lldap; do
  printf "  Waiting for %s..." "$svc"
  for i in $(seq 1 30); do
    if docker compose ps --format json "$svc" 2>/dev/null | jq -e '.Health == "healthy"' >/dev/null 2>&1; then
      echo -e " ${GREEN}ready${NC}"
      break
    fi
    if [ "$i" -eq 30 ]; then
      echo -e " ${YELLOW}timeout${NC}"
    fi
    sleep 2
  done
done

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

# ── Done ───────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "Restore complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Pre-restore backup: $PRE_RESTORE_DIR/"
echo "  Verify: ./scripts/status.sh"
echo ""
