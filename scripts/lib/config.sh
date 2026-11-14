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

# _cfg_flip_traefik_back — the flip stopped Traefik and didn't finish (an
# interrupt, a failure): start it again when it was running, once. The
# sentinel isn't written, so the flip stays pending.
# _cfg_acme_exists — Traefik's ACME storage exists.
_cfg_acme_exists() {
  _rt_docker_only
  docker volume inspect portcullis_traefik_acme >/dev/null 2>&1
}

# _cfg_acme_clear — remove acme.json from Traefik's ACME storage.
_cfg_acme_clear() {
  _rt_docker_only
  docker run --rm --network none -v portcullis_traefik_acme:/acme "$PORTCULLIS_HELPER_IMAGE" rm -f /acme/acme.json >/dev/null 2>&1
}

# _cfg_traefik_exists — a Traefik container exists (or docker can't tell).
_cfg_traefik_exists() {
  _rt_docker_only
  [ -n "$(dc ps -aq traefik 2>/dev/null || echo unknown)" ]
}

_cfg_flip_traefik_back() {
  [ -n "${CFG_FLIP_WINDOW:-}" ] || return 0
  CFG_FLIP_WINDOW=""
  trap - EXIT INT TERM HUP
  [ -n "${CFG_FLIP_TRAEFIK_WAS:-}" ] || return 0
  info "Starting Traefik again..."
  # No container to start (a recreate removed it): create it (M16).
  rt_start traefik >/dev/null 2>&1 || rt_up_service traefik >/dev/null 2>&1 || warn "could not start Traefik again (./portcullis up)"
}

config_apply() {
  local staging sentinel last ca_server flipping=false
  # lego's hetzner provider prefers HETZNER_API_TOKEN (the Cloud API) over
  # HETZNER_API_KEY (the legacy DNS API): both set = the wrong API.
  if [ "${DNS_PROVIDER:-}" = hetzner ] && [ -n "${HETZNER_API_TOKEN:-}" ]; then
    fail "DNS_PROVIDER=hetzner (the legacy DNS API, HETZNER_API_KEY) but HETZNER_API_TOKEN is set: Traefik's lego would use the Cloud API. Remove HETZNER_API_TOKEN, or set DNS_PROVIDER=hetzner-cloud"
  fi
  if [ "${DNS_PROVIDER:-}" = hetzner-cloud ] && [ -n "${HETZNER_API_KEY:-}" ]; then
    fail "DNS_PROVIDER=hetzner-cloud uses HETZNER_API_TOKEN, but HETZNER_API_KEY (the legacy DNS API) is set too: remove it"
  fi
  # Strict DNS_CAA (a typo must not switch CAA off), checked before
  # anything changes: the flip below stops Traefik.
  local caa
  caa="$(_dns_flag DNS_CAA true)" || exit 1
  staging="$(_bool "$(env_get ACME_STAGING)" false)"
  echo "  ACME_STAGING=$staging"
  if [ "$staging" = true ]; then
    ca_server="https://acme-staging-v02.api.letsencrypt.org/directory"
    warn "TLS: Let's Encrypt STAGING — browsers will show certificate warnings."
  else
    ca_server="https://acme-v02.api.letsencrypt.org/directory"
    info "TLS: Let's Encrypt production."
  fi
  # Traefik's DNS-01 provider (lego): hetzner-cloud is lego's hetzner with
  # HETZNER_API_TOKEN (lego v5's hetznerv1, Traefik v3.7.17).
  local acme_dns="${DNS_PROVIDER:-}"
  [ "$acme_dns" != hetzner-cloud ] || acme_dns=hetzner
  # The CA bundle (it may download) before anything stops (I9).
  ACME_STAGING="$staging" config_build_ca_bundle

  # The ACME account + certs in acme.json are bound to the CA directory URL:
  # on a staging↔production flip clear them, or Traefik keeps reusing the
  # old account/cert.
  sentinel="$PORTCULLIS_ROOT/certs/.acme-staging-last"
  last="$(cat "$sentinel" 2>/dev/null || true)"
  # No sentinel but ACME storage exists: it was filled by compose's default
  # CA (production) — treat it as such so a first flip to staging clears it.
  if [ -z "$last" ] && _cfg_acme_exists; then
    last=false
  fi
  if [ -n "$last" ] && [ "$last" != "$staging" ]; then
    warn "ACME_STAGING flipped ($last → $staging): Traefik needs a new ACME account and new certificates."
    flipping=true
    # The new account Traefik registers can't order while the CAA is
    # pinned to the old one: back to CA-only first, and the storage is
    # cleared only once no cache (the CA's either) can hold the old pin
    # (dns_tighten_main pins the new account after `up`). Traefik keeps
    # running through the relax and its wait: CA-only lets its current
    # account renew. Anything short of settled stops here, fail safe:
    # acme.json, the sentinel and the saved settle point stay, so nothing
    # orders against the old pin and the next run redoes the flip.
    # Only where Portcullis manages the CAA (DNS_CAA=true, an automated
    # provider with its credentials): anywhere else there is no pin of
    # ours to relax, so no relax, no settle point and no wait.
    local relaxed=""
    if [ "$caa" = true ] && _dns_automated "${DNS_PROVIDER:-none}" && _dns_creds_present "${DNS_PROVIDER:-none}"; then
      relaxed=1
      # The dns tool must understand this CLI's arguments (an `up` after a
      # `git pull` runs this before its own rebuild).
      domains_image_build "for the CAA relax"
      dns_relax_main || fail "The ACME_STAGING flip is not finished (see above): Traefik runs on with its current ACME account and storage, so nothing is ordered against the old CAA pin, and the settle point is saved: running it again early just waits or stops again."
    fi
    # Every flip, managed or not: a saved settle point in the future, or a
    # public CAA a NEW account couldn't order under, stops it here (N2).
    dns_flip_guard "$ca_server" "$relaxed" || fail "The ACME_STAGING flip is not finished (see above): nothing changed, Traefik runs on with its current ACME account."
    CFG_FLIP_TRAEFIK_WAS=""
    if rt_running traefik; then CFG_FLIP_TRAEFIK_WAS=1; fi
    # From the stop until Traefik runs on the new CA, any way out — an
    # interrupt (INT / TERM / HUP: an SSH drop), a `fail`, set -e — starts
    # it again on its old container; the sentinel is written only at the
    # end, so the flip stays pending (I9).
    CFG_FLIP_WINDOW=1
    trap '_cfg_flip_traefik_back' EXIT
    trap '_cfg_flip_traefik_back; exit 130' INT TERM HUP
    info "Stopping Traefik..."
    # acme.json is never cleared under a running Traefik (M15).
    # No container at all (after `down`) is nothing to stop (M20).
    if ! rt_stop traefik >/dev/null 2>&1 && _cfg_traefik_exists; then
      fail "could not stop Traefik: the ACME_STAGING flip is not finished; run the same command again"
    fi
    if _cfg_acme_exists; then
      info "Clearing Traefik's ACME storage (acme.json)..."
      _cfg_acme_clear || fail "could not clear Traefik's ACME storage (acme.json): the ACME_STAGING flip is not finished; run the same command again"
    fi
  fi
  # Written to .env AND exported: compose prefers the shell's value (which
  # env_load exported from the old .env) over the file (N1).
  env_set ACME_CA_SERVER "$ca_server"
  export ACME_CA_SERVER="$ca_server"
  env_set ACME_DNS_PROVIDER "$acme_dns"
  export ACME_DNS_PROVIDER="$acme_dns"
  if [ "$flipping" = true ] && [ -n "${CFG_FLIP_TRAEFIK_WAS:-}" ]; then
    info "Starting Traefik again (it registers a new ACME account with $ca_server)..."
    rt_up_service traefik >/dev/null 2>&1 || fail "could not start Traefik on $ca_server: the ACME_STAGING flip is not finished; run the same command again"
  fi
  # Only now (Traefik runs on the new CA, or isn't running: its next start
  # reads the new value) is the flip done.
  mkdir -p "$(dirname "$sentinel")"
  echo "$staging" > "$sentinel"
  if [ "$flipping" = true ]; then
    CFG_FLIP_WINDOW=""
    trap - EXIT INT TERM HUP
    dns_relax_done
  fi
  # A pending relax's settle point (ACME_STAGING reverted mid-flip) stays
  # until a flip finishes or a pin is written again (dns_tighten_main,
  # dns setup): the old pin may still be cached.
  # TLS options are static (traefik/dynamic/tls.yml, tracked): the Hub
  # picks one per app router, core routers use authaware.
  ok "Updated ACME_CA_SERVER. Apply with: ./portcullis up"
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
  elif [ ! -d "$cfg/.git" ] || ! git -C "$cfg" rev-parse -q --verify HEAD >/dev/null 2>&1; then
    # (also finishes a run that stopped before the first commit)
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
    # A fresh server often has no git identity: commit as "portcullis"
    # then (only for this commit; the operator's own commits are theirs).
    local -a ident=()
    git config user.email >/dev/null 2>&1 || ident=(-c user.name=portcullis -c "user.email=portcullis@${PORTCULLIS_DOMAIN:-localhost}")
    (cd "$cfg" && git init -q && git add -A && git ${ident[@]+"${ident[@]}"} commit -q -m "initial portcullis config")
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

  apply     Apply ACME_STAGING from .env (ACME CA server, CA bundle)
  init      Move your settings into config/, a separate git repo, and symlink them

Run 'portcullis config <subcommand> --help' for details.
EOF
}

help_config_apply() {
  cat <<'EOF'
Usage: portcullis config apply [--bundle-only]

Apply the toggle in .env:
  ACME_STAGING=true|false   (default false) Let's Encrypt staging vs production:
                            sets ACME_CA_SERVER in .env; on a flip clears
                            Traefik's acme.json so it re-registers
and rebuild certs/ca-bundle.crt. The TLS options in traefik/dynamic/tls.yml
are static (protected / authaware / public): the Hub picks one per app from
its sign-in template and the certificate methods switched on. Then run `portcullis up`: it restarts Traefik and,
when the bundle changed, the two forward-auth services (they read it only
at start-up).

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
