# shellcheck shell=bash
#
# `portcullis config apply [--bundle-only]` and `portcullis config init`.

# _bool <value> <default> — normalise true/false toggles from .env.
_bool() {
  case "${1:-$2}" in true|TRUE|True|1|yes) echo true ;; *) echo false ;; esac
}

# config_build_ca_bundle — certs/ca-bundle.crt for containers that talk to
# Keycloak over HTTPS (forward-auth bind-mounts it as its system bundle):
# system CAs + the internal PKI chain (if it exists yet) + the Let's
# Encrypt staging root when ACME_STAGING=true. Must exist as a FILE before
# the first `docker compose up`, or Docker creates a directory there.
config_build_ca_bundle() {
  local certs="$PORTCULLIS_ROOT/certs" bundle staging stg_ca extra=""
  bundle="$certs/ca-bundle.crt"
  staging="$(_bool "${ACME_STAGING:-}" false)"
  mkdir -p "$certs"
  # A failed earlier `docker compose up` leaves a directory here.
  if [ -d "$bundle" ]; then
    rmdir "$bundle" 2>/dev/null || fail "$bundle is a non-empty directory — remove it manually"
  fi
  # Truncate in place (same inode) so a running container's bind mount
  # sees the new content.
  : > "$bundle"
  if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
    cat /etc/ssl/certs/ca-certificates.crt >> "$bundle"
  elif [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then
    cat /etc/pki/tls/certs/ca-bundle.crt >> "$bundle"
  elif [ -f /etc/ssl/cert.pem ]; then
    cat /etc/ssl/cert.pem >> "$bundle"
  fi
  if [ -f "$certs/ca-chain.crt" ]; then
    cat "$certs/ca-chain.crt" >> "$bundle"
    extra=" + internal PKI"
  fi
  if [ "$staging" = true ]; then
    stg_ca="$certs/letsencrypt-stg-root-x1.pem"
    [ -s "$stg_ca" ] || curl -sf --max-time 20 -o "$stg_ca" "https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem" || true
    if [ -s "$stg_ca" ]; then
      cat "$stg_ca" >> "$bundle"
      extra="$extra + LE staging root"
    else
      warn "could not download the Let's Encrypt staging root"
    fi
  fi
  chmod 644 "$bundle"
  ok "Wrote $bundle (system CAs$extra)"
}

config_apply() {
  local staging mtls sentinel last ca_server tls="$PORTCULLIS_ROOT/traefik/dynamic/tls.yml"
  staging="$(_bool "$(env_get ACME_STAGING)" false)"
  mtls="$(_bool "$(env_get MTLS_ENABLED)" true)"
  echo "  ACME_STAGING=$staging"
  echo "  MTLS_ENABLED=$mtls"

  # The ACME account + certs in acme.json are bound to the CA directory URL:
  # on a staging↔production flip clear them, or Traefik keeps reusing the
  # old account/cert.
  sentinel="$PORTCULLIS_ROOT/certs/.acme-staging-last"
  last="$(cat "$sentinel" 2>/dev/null || true)"
  # No sentinel but ACME storage exists: it was filled by compose's default
  # CA (production) — treat it as such so a first flip to staging clears it.
  if [ -z "$last" ] && docker volume inspect portcullis_traefik_acme >/dev/null 2>&1; then
    last=false
  fi
  if [ -n "$last" ] && [ "$last" != "$staging" ]; then
    warn "ACME_STAGING flipped ($last → $staging): clearing Traefik's ACME storage."
    dc stop traefik >/dev/null 2>&1 || true
    if docker volume inspect portcullis_traefik_acme >/dev/null 2>&1; then
      docker run --rm --network none -v portcullis_traefik_acme:/acme "$PORTCULLIS_HELPER_IMAGE" rm -f /acme/acme.json >/dev/null 2>&1 \
        || warn "could not clear acme.json"
    fi
  fi
  if [ "$staging" = true ]; then
    ca_server="https://acme-staging-v02.api.letsencrypt.org/directory"
    warn "TLS: Let's Encrypt STAGING — browsers will show certificate warnings."
  else
    ca_server="https://acme-v02.api.letsencrypt.org/directory"
    info "TLS: Let's Encrypt production."
  fi
  ACME_STAGING="$staging" config_build_ca_bundle
  mkdir -p "$(dirname "$sentinel")"
  echo "$staging" > "$sentinel"
  env_set ACME_CA_SERVER "$ca_server"

  if [ "$mtls" = true ]; then
    info "mTLS: ENABLED — client certificates requested (PIV/YubiKey)"
    cat > "$tls" <<'EOF'
# TLS options for the three access tiers (written by `portcullis config apply`).
# mTLS ENABLED — client certificates are requested.
tls:
  options:
    protected:
      clientAuth:
        caFiles:
          - /certs/ca-chain.crt
        clientAuthType: RequireAndVerifyClientCert
      minVersion: VersionTLS12
      sniStrict: false

    authaware:
      clientAuth:
        caFiles:
          - /certs/ca-chain.crt
        clientAuthType: VerifyClientCertIfGiven
      minVersion: VersionTLS12
      sniStrict: false

    public:
      minVersion: VersionTLS12
      sniStrict: false
EOF
  else
    warn "mTLS: DISABLED — no client certificates (WebAuthn only)"
    cat > "$tls" <<'EOF'
# TLS options (written by `portcullis config apply`) — mTLS DISABLED.
# All tiers use public TLS (no client certificates); authentication is
# WebAuthn-only via Keycloak.
tls:
  options:
    protected:
      minVersion: VersionTLS12
      sniStrict: false

    authaware:
      minVersion: VersionTLS12
      sniStrict: false

    public:
      minVersion: VersionTLS12
      sniStrict: false
EOF
  fi
  ok "Updated $tls and ACME_CA_SERVER. Apply with: ./portcullis up"
}

# config_init <remote> <clone-url> — config/ as a separate git repo holding
# the instance's settings, symlinked into the checkout so `git pull` of
# Portcullis never conflicts with them.
config_init() {
  local remote="$1" from="$2" cfg="$PORTCULLIS_ROOT/config" f
  require_cmd git
  if [ -n "$from" ]; then
    [ ! -e "$cfg" ] || fail "config/ already exists. Remove it first to clone fresh."
    git clone "$from" "$cfg"
    ok "Config cloned from $from"
  elif [ ! -d "$cfg/.git" ]; then
    info "Creating config/ (a separate git repo for your settings)..."
    (umask 077 && mkdir -p "$cfg/traefik")
    if [ -f "$PORTCULLIS_ROOT/.env" ] && [ ! -L "$PORTCULLIS_ROOT/.env" ]; then
      mv "$PORTCULLIS_ROOT/.env" "$cfg/.env"
    fi
    if [ -f "$PORTCULLIS_ROOT/docker-compose.override.yml" ] && [ ! -L "$PORTCULLIS_ROOT/docker-compose.override.yml" ]; then
      mv "$PORTCULLIS_ROOT/docker-compose.override.yml" "$cfg/docker-compose.override.yml"
    fi
    for f in "$PORTCULLIS_ROOT"/traefik/dynamic/local/*.yml; do
      [ -f "$f" ] && [ ! -L "$f" ] && mv "$f" "$cfg/traefik/"
    done
    cat > "$cfg/README.md" <<'EOF'
# Portcullis config

Settings of one Portcullis instance, kept out of the Portcullis checkout
(symlinked into it by `./portcullis config init`).

| File | Purpose |
|------|---------|
| `.env` | Secrets, domain, DNS provider |
| `docker-compose.override.yml` | Compose customizations |
| `traefik/*.yml` | Custom Traefik routers and middlewares |

`.env` holds every secret: push this repo only to a private remote, or
add `.env` to `.gitignore` and back it up some other way.
EOF
    (cd "$cfg" && git init -q && git add -A && git commit -q -m "initial portcullis config")
    ok "config/ initialised."
  else
    info "config/ already initialised — refreshing symlinks."
  fi

  if [ -n "$remote" ]; then
    if git -C "$cfg" remote get-url origin >/dev/null 2>&1; then
      git -C "$cfg" remote set-url origin "$remote"
    else
      git -C "$cfg" remote add origin "$remote"
    fi
    ok "config/ remote: $remote"
  fi

  # _link <target-in-config> <link-in-checkout> — never replaces a real file.
  _link() {
    [ -e "$1" ] || return 0
    if [ -e "$2" ] && [ ! -L "$2" ]; then
      warn "Skipping $2 — a real file exists (move it into config/ first)"
      return 0
    fi
    ln -sfn "$1" "$2"
    echo "  ${2#"$PORTCULLIS_ROOT"/} → ${1#"$PORTCULLIS_ROOT"/}"
  }
  _link "$cfg/.env" "$PORTCULLIS_ROOT/.env"
  _link "$cfg/docker-compose.override.yml" "$PORTCULLIS_ROOT/docker-compose.override.yml"
  mkdir -p "$PORTCULLIS_ROOT/traefik/dynamic/local"
  for f in "$cfg"/traefik/*.yml; do
    [ -f "$f" ] && _link "$f" "$PORTCULLIS_ROOT/traefik/dynamic/local/$(basename "$f")"
  done
  ok "Config directory ready. Version it with: cd config && git add -A && git commit && git push"
}

help_config() {
  cat <<'EOF'
Usage: portcullis config <subcommand>

  apply     Apply ACME_STAGING / MTLS_ENABLED from .env (CA bundle, tls.yml)
  init      Move your settings into config/, a separate git repo, and symlink them

Run 'portcullis config <subcommand> --help' for details.
EOF
}

help_config_apply() {
  cat <<'EOF'
Usage: portcullis config apply [--bundle-only]

Apply the toggles in .env:
  ACME_STAGING=true|false   (default false) Let's Encrypt staging vs production:
                            sets ACME_CA_SERVER in .env; on a flip clears
                            Traefik's acme.json so it re-registers
  MTLS_ENABLED=true|false   (default true) rewrites traefik/dynamic/tls.yml
                            (false: no client certs on any tier — routers that
                            rely only on the protected tier become unauthenticated)
and rebuild certs/ca-bundle.crt. Then run `portcullis up` to restart Traefik.

Options:
  --bundle-only   only rebuild certs/ca-bundle.crt (system CAs + internal
                  PKI chain + LE staging root if ACME_STAGING=true)
EOF
}

help_config_init() {
  cat <<'EOF'
Usage: portcullis config init [--remote URL | --from URL]

Create config/, a separate git repo for this instance's settings, move
.env, docker-compose.override.yml and traefik/dynamic/local/*.yml into it
and symlink them back, so `git pull` of Portcullis never conflicts with
your settings. Re-running only refreshes the symlinks.

Options:
  --remote URL   set config/'s git remote (push it to a PRIVATE repo: .env has secrets)
  --from URL     clone an existing config repo into config/ (new machine)
EOF
}

cmd_config() {
  local sub="${1:-}" bundle_only=false remote="" from=""
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_config; [ -n "$sub" ] || exit 2; return 0 ;;
    apply|init) ;;
    *) usage_error config "unknown subcommand: $sub" ;;
  esac
  while [ $# -gt 0 ]; do
    case "$sub:$1" in
      *:-h|*:--help) "help_config_$sub"; return 0 ;;
      apply:--bundle-only) bundle_only=true ;;
      init:--remote) need_value "config init" "$1" "${2:-}"; remote="$2"; shift ;;
      init:--from) need_value "config init" "$1" "${2:-}"; from="$2"; shift ;;
      *) usage_error "config $sub" "unknown argument: $1" ;;
    esac
    shift
  done
  case "$sub" in
    apply)
      need_env
      if [ "$bundle_only" = true ]; then config_build_ca_bundle; else config_apply; fi
      ;;
    init)
      [ -z "$remote" ] || [ -z "$from" ] || usage_error "config init" "--remote and --from are mutually exclusive"
      config_init "$remote" "$from"
      ;;
  esac
}
