#!/usr/bin/env bash
#
# Portcullis upgrade — safely update an existing deployment.
#
# What it does:
#   1. Refuses to continue if Vault still runs in the old DEV mode, unless
#      --migrate-vault is given (or confirmed interactively) — see below
#   2. Backs up .env, certs/, secrets/, volumes, and realm config
#   3. Merges new env vars from .env.example (without overwriting)
#   4. Pulls new images
#   5. Registers any missing OIDC clients in Keycloak
#   6. Recreates the portcullis-proxy network if it lacks the fixed IPAM
#      config (static Traefik IP); app containers are reconnected
#   7. Ensures Vault is initialised + unsealed (scripts/vault-init.sh) and
#      the PKI exists
#   8. Restarts services with health checks
#
# Vault dev-mode migration: dev mode kept the PKI in memory and the CA keys
# were generated `internal` (non-exportable), so the current CA CANNOT be
# carried over. Migrating creates a NEW root + intermediate CA, rewrites
# certs/root-ca.crt, intermediate-ca.crt, ca-chain.crt (and server.crt/key
# if present) and EVERY enrolled YubiKey client cert stops working until
# it is re-enrolled. Hence opt-in.
#
# Usage:
#   ./scripts/upgrade.sh
#   ./scripts/upgrade.sh --migrate-vault   # allow the one-time Vault dev→server migration
#   ./scripts/upgrade.sh --skip-backup
#   ./scripts/upgrade.sh --dry-run
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Keycloak 26 serves /health/ready on the management port (9000), which is
# not published — so ask Docker for the compose healthcheck status instead.
keycloak_healthy() {
  local cid
  cid=$(docker compose ps -q keycloak 2>/dev/null | head -n1)
  [ -n "$cid" ] || return 1
  [ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$cid" 2>/dev/null)" = "healthy" ]
}

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
MIGRATE_VAULT=false

for arg in "$@"; do
  case "$arg" in
    --skip-backup)   SKIP_BACKUP=true ;;
    --dry-run)       DRY_RUN=true ;;
    --migrate-vault) MIGRATE_VAULT=true ;;
    -h|--help)
      echo "Usage: $0 [--migrate-vault] [--skip-backup] [--dry-run]"
      echo ""
      echo "  --migrate-vault Allow replacing a dev-mode Vault with the persistent server-mode"
      echo "                  Vault. Creates a NEW CA: every YubiKey must be re-enrolled."
      echo "  --skip-backup   Skip volume and config backup"
      echo "  --dry-run       Show what would happen without making changes"
      exit 0
      ;;
    *) fail "unknown argument: $arg (see --help)" ;;
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

# shellcheck source=lib/vault-common.sh
source "$SCRIPT_DIR/lib/vault-common.sh"
# shellcheck source=lib/proxy-network.sh
source "$SCRIPT_DIR/lib/proxy-network.sh"

# ── Preflight: Vault dev mode ──────────────────────────────
#
# PKI_REGEN_ALLOWED gates the only step of this upgrade that invalidates
# user credentials. Needed when Vault is still the dev-mode server, or when
# there is no server-mode Vault yet but certs/ca-chain.crt (an old CA that
# Traefik still trusts) exists.

PKI_REGEN_ALLOWED=false
PKI_REGEN_REASON=""
VAULT_IS_DEV=false
vault_container_is_dev && VAULT_IS_DEV=true
if [ "$VAULT_IS_DEV" = true ]; then
  PKI_REGEN_REASON="Vault is running in DEV mode (in-memory storage)."
elif [ ! -s "$VAULT_INIT_FILE" ] && [ -f certs/ca-chain.crt ]; then
  PKI_REGEN_REASON="There is no server-mode Vault yet (no $VAULT_INIT_FILE) but certs/ca-chain.crt exists."
fi

if [ -n "$PKI_REGEN_REASON" ]; then
  echo ""
  echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  warn "VAULT MIGRATION REQUIRED: $PKI_REGEN_REASON"
  echo "  This release runs Vault in server mode with persistent raft storage."
  echo "  The current CA cannot be carried over: its keys were generated as"
  echo "  'internal' (non-exportable) inside an in-memory Vault."
  echo ""
  echo "  Migrating will:"
  echo "    - initialise a new Vault (root token + unseal key -> secrets/vault-init.json)"
  echo "    - create a NEW root + intermediate CA and rewrite certs/root-ca.crt,"
  echo "      certs/intermediate-ca.crt, certs/ca-chain.crt (+ server.crt/key if present)"
  echo -e "    - ${RED}invalidate EVERY enrolled YubiKey client certificate${NC} — users must"
  echo "      re-enroll (https://enroll.${DOMAIN} or ./scripts/enroll-yubikey.sh)."
  echo "      WebAuthn logins are NOT affected."
  echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  if [ "$DRY_RUN" = true ]; then
    echo "  Dry run: a real run needs --migrate-vault (or interactive confirmation)."
  elif [ "$MIGRATE_VAULT" = true ]; then
    PKI_REGEN_ALLOWED=true
    warn "--migrate-vault given — proceeding with the Vault migration."
  elif [ -t 0 ]; then
    read -rp "Type 'migrate' to continue, anything else aborts: " CONFIRM
    [ "$CONFIRM" = "migrate" ] || { echo "Aborted — nothing was changed."; exit 1; }
    PKI_REGEN_ALLOWED=true
  else
    fail "Refusing to migrate Vault unattended (it invalidates all client certs). Nothing was changed. Re-run with --migrate-vault."
  fi
fi

# ── Backup ─────────────────────────────────────────────────

BACKUP_DIR="backups/$(date +%Y%m%d-%H%M%S)"

if [ "$SKIP_BACKUP" = false ]; then
  info "Creating backup in $BACKUP_DIR..."

  if [ "$DRY_RUN" = true ]; then
    echo "  Would create: $BACKUP_DIR/"
    echo "  Would backup: .env, keycloak/realm-export.json, headscale/config.yaml, certs/, secrets/"
    echo "  Would backup: docker volumes (portcullis postgres, lldap, vault)"
  else
    # Backups contain .env and volume dumps (secrets) — owner-only.
    OLD_UMASK=$(umask)
    umask 077
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"

    # Config files
    cp .env "$BACKUP_DIR/.env"
    [ -f keycloak/realm-export.json ] && cp keycloak/realm-export.json "$BACKUP_DIR/realm-export.json"
    [ -f headscale/config.yaml ] && cp headscale/config.yaml "$BACKUP_DIR/headscale-config.yaml"
    # certs/: CA chain Traefik trusts, server cert/key, revoked-serial list.
    [ -d certs ] && cp -a certs "$BACKUP_DIR/certs"
    # secrets/: Vault root token + UNSEAL KEY + enroll AppRole creds. Needed
    # to unseal a restored vault_data volume — and enough to decrypt it.
    if [ -d secrets ]; then
      cp -a secrets "$BACKUP_DIR/secrets"
      warn "Backup includes secrets/ (Vault root token + unseal key): together with"
      warn "vault_data.tar.gz it can decrypt the CA. Store $BACKUP_DIR like the keys."
    fi

    # Volume data (compressed)
    info "Backing up volumes (this may take a moment)..."
    # Raft files must not be copied while Vault writes them: stop a
    # server-mode Vault for the copy (it auto-unseals on start). A dev-mode
    # Vault keeps nothing on disk, and stopping it would destroy its PKI.
    VAULT_STOPPED=false
    if [ -n "$(docker compose ps -q --status running vault 2>/dev/null)" ] && [ "$VAULT_IS_DEV" = false ]; then
      docker compose stop vault >/dev/null 2>&1 && VAULT_STOPPED=true
    fi
    for vol in postgres_data lldap_data vault_data; do
      if [ "$vol" = vault_data ] && [ "$VAULT_IS_DEV" = true ]; then
        echo "  Skipping vault_data (dev mode: data is in memory only; certs/ is backed up)"
        continue
      fi
      full_vol="$(docker compose config --format json 2>/dev/null | jq -r ".volumes.\"${vol}\".name // empty" 2>/dev/null || echo "")"
      if [ -n "$full_vol" ] && docker volume inspect "$full_vol" >/dev/null 2>&1; then
        printf "  Backing up %s..." "$vol"
        docker run --rm -v "${full_vol}:/data" -v "$(pwd)/$BACKUP_DIR:/backup" \
          alpine tar czf "/backup/${vol}.tar.gz" -C /data . 2>/dev/null \
          && echo -e " ${GREEN}done${NC}" \
          || echo -e " ${YELLOW}skipped${NC}"
      fi
    done
    [ "$VAULT_STOPPED" = true ] && docker compose start vault >/dev/null 2>&1

    umask "$OLD_UMASK"
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
        FORWARD_AUTH_COOKIE_SECRET)
          # oauth2-proxy needs exactly 16/24/32 bytes; base64url of 32 random bytes.
          GENERATED=$(openssl rand -base64 32 | tr -- '+/' '-_')
          echo "${KEY}=${GENERATED}" >> .env
          echo "  Added ${KEY} (generated random value)"
          ;;
        FORWARD_AUTH_CLIENT_SECRET)
          # Keep the value Keycloak already has (the historical default) so
          # an upgrade never desyncs oauth2-proxy from the Keycloak client.
          # Rotate by editing .env; register-oidc-clients.sh (run below)
          # pushes the .env value to Keycloak.
          echo "${KEY}=portcullis-forward-auth-secret" >> .env
          echo "  Added ${KEY} (historical default — rotate it, see .env.example)"
          ;;
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

if grep -q '^VAULT_DEV_TOKEN=' .env 2>/dev/null; then
  warn "VAULT_DEV_TOKEN in .env is no longer used (Vault tokens live in secrets/). You can delete that line."
fi

if ! NET_ERR="$(validate_proxy_network_config)"; then
  fail "Invalid portcullis-proxy settings in .env: $NET_ERR"
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
    if keycloak_healthy; then
      KC_READY=true
      echo -e " ${GREEN}ready${NC}"
      break
    fi
    sleep 2
  done

  if [ "$KC_READY" = false ]; then
    warn "Keycloak container not healthy — skipping OIDC client registration."
    warn "You may need to register clients manually after Keycloak is up."
  else
    ./scripts/register-oidc-clients.sh || warn "Some OIDC clients may not have been registered."
    ok "OIDC clients checked."
  fi
fi

# ── portcullis-proxy network (fixed IPAM, static Traefik IP) ──

NET_STATE="$(proxy_network_state)"
case "$NET_STATE" in
  ok)      ok "Network $PROXY_NETWORK already has the fixed IPAM config." ;;
  missing) info "Network $PROXY_NETWORK does not exist yet — compose will create it." ;;
  mismatch)
    warn "Network $PROXY_NETWORK exists without the expected IPAM config"
    warn "(subnet $(proxy_subnet), range $(proxy_ip_range)). Docker cannot change that in"
    warn "place, so it is recreated now. App containers keep running and are reconnected;"
    warn "routing to apps is interrupted for a few seconds."
    if [ "$DRY_RUN" = true ]; then
      NET_STATE_FILE="$(mktemp)"
    else
      (umask 077 && mkdir -p backups)
      NET_STATE_FILE="backups/proxy-network-members-$(date +%Y%m%d-%H%M%S).tsv"
    fi
    if proxy_network_migrate "$NET_STATE_FILE" "$DRY_RUN"; then
      [ "$DRY_RUN" = true ] || ok "Network $PROXY_NETWORK recreated; Traefik is at $(proxy_traefik_ip)."
    else
      fail "Network migration of $PROXY_NETWORK FAILED — upgrade stopped. Follow the recovery steps above (member list: $NET_STATE_FILE)."
    fi
    if [ "$DRY_RUN" != true ]; then
      warn "Header-auth apps (grafana, firefly-iii, kanboard, guacamole, cloudbeaver) only"
      warn "pick up PORTCULLIS_TRAEFIK_IP after the Hub regenerates their env: open the Hub"
      warn "and disable/enable them (or use 'Restart' if your Hub version regenerates env)."
    fi
    ;;
esac

# ── Vault (server mode, unsealed, PKI present) ─────────────

PKI_REGENERATED=false
info "Checking Vault..."
if [ "$DRY_RUN" = true ]; then
  echo "  Would run: docker compose up -d --no-deps vault && ./scripts/vault-init.sh"
  echo "  Would run: ./scripts/setup-vault-pki.sh if pki_int has no CA"
else
  # Pre-create bind-mount sources so Docker doesn't create them root-owned.
  (umask 077 && mkdir -p secrets/vault-unseal secrets/enroll)
  mkdir -p certs/revocation
  # Hub copies app template dirs here (bind-mounted rw into the hub).
  mkdir -p templates
  # Mountpoints for the Hub's tmpfs masks (must exist inside the ro /project bind).
  mkdir -p secrets backups
  [ -f certs/revocation/revoked-serials.txt ] || : > certs/revocation/revoked-serials.txt

  if [ "$PKI_REGEN_ALLOWED" = true ]; then
    warn "Replacing the dev-mode Vault with the server-mode Vault (old in-memory PKI is discarded)..."
  fi
  docker compose up -d --no-deps vault
  ./scripts/vault-init.sh
  vault_admin_env
  vault_use_container_cli

  # pki_int issuers: exit 0 = CA present, 2 = none, anything else = error
  # (sealed / bad token) — never treat an error as "no PKI".
  PKI_RC=0
  vault list -format=json pki_int/issuers >/dev/null 2>&1 || PKI_RC=$?
  if [ "$PKI_RC" -ne 0 ] && [ "$PKI_RC" -ne 2 ]; then
    # Mount missing entirely is also reported as an error; tell them apart.
    if vault secrets list -format=json 2>/dev/null | jq -e 'has("pki_int/")' >/dev/null; then
      fail "Could not query Vault PKI (exit $PKI_RC). Check ./scripts/status.sh and docker compose logs vault."
    fi
    vault secrets list -format=json >/dev/null 2>&1 || fail "Could not query Vault (sealed? bad token?)."
    PKI_RC=2
  fi
  if [ "$PKI_RC" -eq 0 ]; then
    # Complete-but-partial runs are repaired (or left alone) by the script.
    DOMAIN="$DOMAIN" ./scripts/setup-vault-pki.sh >/dev/null || fail "setup-vault-pki.sh failed"
  else
    if [ -f certs/ca-chain.crt ] && [ "$PKI_REGEN_ALLOWED" != true ]; then
      fail "Vault has no PKI but certs/ca-chain.crt exists (Vault data lost?). Creating a new CA invalidates all client certs: restore vault_data + secrets/ from a backup (./scripts/restore.sh), or re-run with --migrate-vault to create a new CA."
    fi
    PKI_ARGS=()
    [ -f certs/server.crt ] && PKI_ARGS+=(--with-server-cert)
    if [ -d certs ] && [ -f certs/ca-chain.crt ]; then
      OLD_CERTS="backups/certs-before-vault-migration-$(date +%Y%m%d-%H%M%S)"
      (umask 077 && mkdir -p backups && cp -a certs "$OLD_CERTS")
      info "Old certs/ copied to $OLD_CERTS"
    fi
    info "Creating a new PKI (root + intermediate CA)..."
    DOMAIN="$DOMAIN" ./scripts/setup-vault-pki.sh ${PKI_ARGS[@]+"${PKI_ARGS[@]}"}
    PKI_REGENERATED=true
  fi
  ok "Vault ready."
fi

# ── Restart services ───────────────────────────────────────

info "Restarting services..."

# --remove-orphans would also delete containers the current compose files
# don't define, e.g. the examples from docker-compose.apps.yml (same
# project `portcullis`) when COMPOSE_FILE doesn't include that file. Only
# remove orphans when there are none we didn't create ourselves.
UP_ARGS=(-d --build)
DEFINED_SERVICES="$(docker compose config --services 2>/dev/null || true)"
ORPHANS="$(docker ps -a --filter "label=com.docker.compose.project=$CORE_PROJECT" \
  --format '{{.Label "com.docker.compose.service"}}' 2>/dev/null | sort -u \
  | grep -vxF -f <(printf '%s\n' "$DEFINED_SERVICES") || true)"
if [ -n "$ORPHANS" ]; then
  warn "Project $CORE_PROJECT has containers for services not in the current compose files:"
  printf '      %s\n' $ORPHANS
  warn "Leaving them in place (no --remove-orphans). If they come from docker-compose.apps.yml,"
  warn "run upgrades with COMPOSE_FILE=docker-compose.yml:docker-compose.apps.yml; if they are"
  warn "really obsolete, remove them with: docker compose up -d --remove-orphans"
else
  UP_ARGS+=(--remove-orphans)
fi

if [ "$DRY_RUN" = true ]; then
  echo "  Would run: ./scripts/apply-config.sh --bundle-only"
  echo "  Would run: docker compose up ${UP_ARGS[*]}"
else
  # Rebuild certs/ca-bundle.crt (bind-mounted by forward-auth; must be a
  # file before `up`) — also picks up a newly created CA chain.
  ./scripts/apply-config.sh --bundle-only
  docker compose up "${UP_ARGS[@]}"
  if [ "$PKI_REGENERATED" = true ]; then
    # Traefik reads ca-chain.crt / server cert only at start-up.
    docker compose restart traefik forward-auth >/dev/null
  fi

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
    if keycloak_healthy; then
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
echo "    ./scripts/status.sh"
echo "    curl -k https://enroll.${DOMAIN}"
echo ""
if [ "$PKI_REGENERATED" = true ]; then
  echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  warn "A NEW CERTIFICATE AUTHORITY WAS CREATED."
  echo "  Every YubiKey / PIV client certificate issued before this upgrade is now"
  echo "  rejected. Each user must re-enroll:"
  echo "    https://enroll.${DOMAIN}    or    ./scripts/enroll-yubikey.sh <user> <email>"
  echo "  If clients imported the old certs/root-ca.crt (e.g. local dev with a"
  echo "  self-signed server cert), replace it with the new certs/root-ca.crt."
  echo ""
  echo "  Back up secrets/vault-init.json OFFLINE now (root token + unseal key)."
  echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
fi
