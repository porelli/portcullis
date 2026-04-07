#!/usr/bin/env bash
#
# Initialize the config/ directory for user-specific configuration.
#
# config/ is a separate git repo where users version their own settings.
# The main Portcullis repo ignores it, so `git pull` never conflicts.
#
# What goes in config/:
#   .env                           — secrets, domain, DNS provider
#   docker-compose.override.yml    — compose customizations
#   traefik/                       — custom Traefik routers/middlewares
#   hub/                           — hub state (enabled apps, sources)
#   headscale/                     — headscale config overrides
#
# Symlinks are created from the project root so Docker Compose, Traefik,
# and other tools find files in their expected locations.
#
# Usage:
#   ./scripts/init-config.sh                    # initialize
#   ./scripts/init-config.sh --remote <url>     # init + set git remote
#   ./scripts/init-config.sh --from <url>       # clone existing config
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

REMOTE=""
CLONE_URL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote)  REMOTE="$2"; shift 2 ;;
    --from)    CLONE_URL="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [options]"
      echo ""
      echo "  --remote <url>   Set git remote for config/ (push your config here)"
      echo "  --from <url>     Clone an existing config repo into config/"
      echo ""
      echo "Examples:"
      echo "  $0                                              # fresh init"
      echo "  $0 --remote git@github.com:me/my-portcullis.git  # init + remote"
      echo "  $0 --from git@github.com:me/my-portcullis.git    # restore from backup"
      exit 0
      ;;
    *) fail "Unknown option: $1" ;;
  esac
done

CONFIG_DIR="$PROJECT_DIR/config"

# ── Clone or create ───────────────────────────────────────

if [ -n "$CLONE_URL" ]; then
  if [ -d "$CONFIG_DIR" ]; then
    fail "config/ already exists. Remove it first to clone fresh."
  fi
  info "Cloning config from $CLONE_URL..."
  git clone "$CLONE_URL" "$CONFIG_DIR"
  ok "Config cloned."
else
  if [ -d "$CONFIG_DIR/.git" ]; then
    info "config/ already initialized — updating symlinks."
  else
    info "Creating config/ directory..."
    mkdir -p "$CONFIG_DIR"

    # Create subdirectories
    mkdir -p "$CONFIG_DIR/traefik"
    mkdir -p "$CONFIG_DIR/hub"
    mkdir -p "$CONFIG_DIR/headscale"

    # Move existing user files into config/ if they exist
    if [ -f "$PROJECT_DIR/.env" ] && [ ! -L "$PROJECT_DIR/.env" ]; then
      mv "$PROJECT_DIR/.env" "$CONFIG_DIR/.env"
      info "Moved .env → config/.env"
    fi

    if [ -f "$PROJECT_DIR/docker-compose.override.yml" ] && [ ! -L "$PROJECT_DIR/docker-compose.override.yml" ]; then
      mv "$PROJECT_DIR/docker-compose.override.yml" "$CONFIG_DIR/docker-compose.override.yml"
      info "Moved docker-compose.override.yml → config/"
    fi

    # Move local traefik configs
    if [ -d "$PROJECT_DIR/traefik/dynamic/local" ]; then
      for f in "$PROJECT_DIR/traefik/dynamic/local"/*.yml; do
        [ -f "$f" ] || continue
        mv "$f" "$CONFIG_DIR/traefik/"
        info "Moved $(basename "$f") → config/traefik/"
      done
    fi

    # Move hub state
    if [ -d "$PROJECT_DIR/.hub" ]; then
      cp -r "$PROJECT_DIR/.hub/"* "$CONFIG_DIR/hub/" 2>/dev/null || true
      info "Copied hub state → config/hub/"
    fi

    # Move headscale config if user-modified
    if [ -f "$PROJECT_DIR/headscale/config.local.yaml" ]; then
      mv "$PROJECT_DIR/headscale/config.local.yaml" "$CONFIG_DIR/headscale/config.yaml"
      info "Moved headscale config → config/headscale/"
    fi

    # Initialize git repo
    info "Initializing git repo in config/..."
    cd "$CONFIG_DIR"
    git init -q

    # Create .gitignore for config repo
    cat > .gitignore <<'GITIGNORE'
# Sensitive files you might NOT want in git
# Uncomment to exclude secrets (but then you need another way to back them up)
# .env
GITIGNORE

    # Create README
    cat > README.md <<'README'
# Portcullis Config

This directory contains your Portcullis instance configuration.
It is a separate git repo from the main Portcullis project.

## Files

| File | Purpose |
|------|---------|
| `.env` | Secrets, domain, DNS provider |
| `docker-compose.override.yml` | Compose customizations (ports, volumes, limits) |
| `traefik/*.yml` | Custom Traefik routers and middlewares |
| `hub/state.yaml` | Enabled apps and template sources |
| `headscale/config.yaml` | Headscale overrides |

## Usage

```bash
# Save your changes
cd config && git add -A && git commit -m "update config"

# Push to your private repo
git push

# On another machine: restore
./scripts/init-config.sh --from git@github.com:you/my-portcullis-config.git
```

## Updating Portcullis

```bash
cd ..              # back to portcullis root
git pull           # update portcullis — no conflicts
docker compose up -d
```
README

    git add -A
    git commit -q -m "Initial Portcullis config"
    ok "Config repo initialized."
    cd "$PROJECT_DIR"
  fi
fi

# ── Set remote if requested ───────────────────────────────

if [ -n "$REMOTE" ]; then
  cd "$CONFIG_DIR"
  if git remote get-url origin >/dev/null 2>&1; then
    git remote set-url origin "$REMOTE"
  else
    git remote add origin "$REMOTE"
  fi
  ok "Remote set to $REMOTE"
  cd "$PROJECT_DIR"
fi

# ── Create symlinks ──────────────────────────────────────

info "Setting up symlinks..."

create_symlink() {
  local target="$1"  # file in config/
  local link="$2"    # symlink location in project

  # Don't overwrite real files
  if [ -f "$link" ] && [ ! -L "$link" ]; then
    warn "Skipping $link — real file exists (move it to config/ first)"
    return
  fi

  if [ -e "$target" ]; then
    ln -sf "$target" "$link"
    echo "  $(basename "$link") → config/$(basename "$target")"
  fi
}

# .env
create_symlink "$CONFIG_DIR/.env" "$PROJECT_DIR/.env"

# docker-compose.override.yml
if [ -f "$CONFIG_DIR/docker-compose.override.yml" ]; then
  create_symlink "$CONFIG_DIR/docker-compose.override.yml" "$PROJECT_DIR/docker-compose.override.yml"
fi

# Traefik local configs — symlink the directory
mkdir -p "$PROJECT_DIR/traefik/dynamic/local"
for f in "$CONFIG_DIR/traefik"/*.yml; do
  [ -f "$f" ] || continue
  create_symlink "$f" "$PROJECT_DIR/traefik/dynamic/local/$(basename "$f")"
done

# Hub state
mkdir -p "$PROJECT_DIR/.hub"
if [ -f "$CONFIG_DIR/hub/state.yaml" ]; then
  create_symlink "$CONFIG_DIR/hub/state.yaml" "$PROJECT_DIR/.hub/state.yaml"
fi

ok "Symlinks created."

# ── Summary ───────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ok "Config directory ready!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Your config lives in: config/"
echo ""
echo "  Files:"
[ -f "$CONFIG_DIR/.env" ]                          && echo "    config/.env"
[ -f "$CONFIG_DIR/docker-compose.override.yml" ]   && echo "    config/docker-compose.override.yml"
ls "$CONFIG_DIR/traefik"/*.yml >/dev/null 2>&1     && echo "    config/traefik/*.yml"
[ -f "$CONFIG_DIR/hub/state.yaml" ]                && echo "    config/hub/state.yaml"
echo ""
echo "  Version your config:"
echo "    cd config"
echo "    git add -A && git commit -m 'update config'"
CURRENT_REMOTE=$(cd "$CONFIG_DIR" && git remote get-url origin 2>/dev/null || echo "")
if [ -n "$CURRENT_REMOTE" ]; then
  echo "    git push    # → $CURRENT_REMOTE"
else
  echo "    git remote add origin <your-private-repo-url>"
  echo "    git push -u origin main"
fi
echo ""
echo "  Update Portcullis without conflicts:"
echo "    git pull && docker compose up -d"
echo ""
