# shellcheck shell=bash
#
# Files of the domains service (integration contract §12.1, §12.4), kept in
# place by stack_prepare on every init / up / upgrade / restore:
#
#   secrets/domains/api-secret        Hub ⇄ domains bearer secret (group 10001
#                                     = the Hub; domains reads it through
#                                     group_add), 0640
#   secrets/domains/age.key           age X25519 identity encrypting
#                                     domains_data (group 10004), 0640
#   secrets/domains/certs-endpoint/   private CA + server cert (domains,
#                                     SAN DNS:domains) + client cert
#                                     (Traefik) of the certificate endpoint;
#                                     ca.key stays operator-only (0600)
#
# The endpoint certificates are ECDSA P-256: CA 10 years, server/client
# until the CA expires (a private CA on internal networks: nothing renews
# them between ups). A certificate with < 30 days left is renewed (the CA
# with < 1 year left: all three); after a renewal of existing certificates
# DOMAINS_CERTS_RENEWED=true and the caller restarts traefik and domains
# (neither re-reads the files while running).

DOMAINS_IMAGE_NAME="portcullis-domains"  # built locally from domains/ (compose image name)
DOMAINS_CERTS_RENEWED=false

_domains_dir() { echo "$PORTCULLIS_ROOT/secrets/domains"; }

# _domains_openssl_cnf — extensions for the endpoint certificates.
_domains_openssl_cnf() {
  cat <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = Portcullis domains certificate endpoint
[ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:domains
[client]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
EOF
}

# _domains_expiring <cert> <seconds> — true if missing or expiring within.
_domains_expiring() {
  [ -s "$1" ] || return 0
  ! openssl x509 -checkend "$2" -noout -in "$1" >/dev/null 2>&1
}

# _domains_leaf <name> <ext> <cn> — key + certificate signed by the CA.
_domains_leaf() {
  local d name="$1" ext="$2" cn="$3" cnf
  d="$(_domains_dir)/certs-endpoint"
  # Valid until the CA expires (whole days left on it, at least 1).
  local days end
  end="$(to_epoch "$(openssl x509 -noout -enddate -in "$d/ca.crt" 2>/dev/null | cut -d= -f2)")"
  days=$(( (end - $(date +%s)) / 86400 ))
  [ "$days" -ge 1 ] || days=1
  cnf="$(mktemp)"
  _domains_openssl_cnf > "$cnf"
  (umask 077 \
    && openssl ecparam -name prime256v1 -genkey -noout -out "$d/$name.key.new" 2>/dev/null \
    && openssl req -new -key "$d/$name.key.new" -subj "/CN=$cn" -out "$d/$name.csr" 2>/dev/null \
    && openssl x509 -req -in "$d/$name.csr" -CA "$d/ca.crt" -CAkey "$d/ca.key" -set_serial "0x$(openssl rand -hex 16)" \
         -days "$days" -sha256 -extfile "$cnf" -extensions "$ext" -out "$d/$name.crt.new" 2>/dev/null) \
    || { rm -f "$cnf" "$d/$name.csr" "$d/$name.key.new" "$d/$name.crt.new"; fail "could not create the certificate endpoint's $name certificate (openssl)"; }
  rm -f "$cnf" "$d/$name.csr"
  mv -f "$d/$name.key.new" "$d/$name.key"
  mv -f "$d/$name.crt.new" "$d/$name.crt"
}

# domains_endpoint_certs — create / renew the endpoint CA and certificates.
domains_endpoint_certs() {
  local d cnf existed=false all=false
  d="$(_domains_dir)/certs-endpoint"
  (umask 077 && mkdir -p "$d")
  [ ! -s "$d/server.crt" ] || existed=true
  if [ ! -s "$d/ca.key" ] || _domains_expiring "$d/ca.crt" $((365 * 86400)); then
    cnf="$(mktemp)"
    _domains_openssl_cnf > "$cnf"
    (umask 077 \
      && openssl ecparam -name prime256v1 -genkey -noout -out "$d/ca.key.new" 2>/dev/null \
      && openssl req -x509 -new -key "$d/ca.key.new" -days 3650 -sha256 -config "$cnf" -extensions ca \
           -out "$d/ca.crt.new" 2>/dev/null) \
      || { rm -f "$cnf" "$d/ca.key.new" "$d/ca.crt.new"; fail "could not create the certificate endpoint CA (openssl)"; }
    rm -f "$cnf"
    mv -f "$d/ca.key.new" "$d/ca.key"
    mv -f "$d/ca.crt.new" "$d/ca.crt"
    all=true
  fi
  local name ext cn
  for spec in "server:server:domains" "client:client:traefik"; do
    IFS=: read -r name ext cn <<<"$spec"
    if [ "$all" = true ] || _domains_expiring "$d/$name.crt" $((30 * 86400)) \
      || ! openssl verify -CAfile "$d/ca.crt" "$d/$name.crt" >/dev/null 2>&1; then
      _domains_leaf "$name" "$ext" "$cn"
      [ "$existed" = false ] || DOMAINS_CERTS_RENEWED=true
    fi
  done
  if [ "$DOMAINS_CERTS_RENEWED" = true ]; then
    info "Renewed the domains certificate-endpoint certificates (traefik and domains restart to load them)."
  fi
  return 0
}

# domains_image_ensure [why] — build the domains image if it is missing
# (its age key, the one-shot dns tool and the Traefik account reader all
# run from it, possibly before the first `up`).
domains_image_ensure() {
  docker image inspect "$DOMAINS_IMAGE_NAME" >/dev/null 2>&1 && return 0
  info "Building the domains service image${1:+ (needed $1)}..."
  runtime_build_service domains >/dev/null || fail "could not build the domains image"
}

# domains_age_keygen <file> — a new age X25519 identity, generated by the
# domains image itself (filippo.io/age), offline.
domains_age_keygen() {
  local f="$1" tmp
  domains_image_ensure "to generate its age key"
  tmp="$(mktemp "$f.XXXXXX")"
  chmod 600 "$tmp"
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --user "$CT_UID_DOMAINS:$CT_UID_DOMAINS" "$DOMAINS_IMAGE_NAME" keygen > "$tmp" \
    && grep -q '^AGE-SECRET-KEY-1' "$tmp" \
    || { rm -f "$tmp"; fail "could not generate secrets/domains/age.key"; }
  mv -f "$tmp" "$f"
  ok "Generated secrets/domains/age.key (encrypts the domains service's DNS credentials; backed up with secrets/)."
}

# domains_enrolled — false only when the running domains service reports
# no enrolled domain (unknown — not running, an old image — counts as
# enrolled: the lookups run).
domains_enrolled() {
  local n
  n="$(dc exec -T domains domains enrolled 2>/dev/null | tr -d '[:space:]')" || return 0
  [ "$n" != 0 ]
}

# _domains_last <4|6> [<address>] — the last detected address (stored, or
# read back: a valid global one only).
_domains_last() {
  local f
  f="$(_domains_dir)/last-public-ipv$1"
  if [ $# -gt 1 ]; then
    (umask 077 && printf '%s\n' "$2" > "$f")
    return 0
  fi
  [ -s "$f" ] || return 0
  local a
  a="$(head -n1 "$f")"
  if [ "$1" = 4 ]; then ipv4_is_global "$a" || a=""; else ipv6_is_global "$a" || a=""; fi
  printf '%s' "$a"
}

# domains_public_ips — the server's public IPv4 / IPv6 for the domains
# service's A/AAAA records (contract §12.1). An explicit
# PORTCULLIS_PUBLIC_IPV4 / _IPV6 (environment or .env; an empty _IPV6 =
# no IPv6) always wins; otherwise public_ip_detect (HTTPS, two services
# must agree, global unicast only) — skipped while no domain is enrolled
# (domains_enrolled): then no address unless .env sets one. A lookup that
# ran and failed keeps the last detected address. No address = the service
# keeps the records it set and renews certificates, but sets no new
# records (fail closed). The result is
# written to secrets/domains/public-ips.env, the domains service's
# env_file (a manual `docker compose up` gets it too).
domains_public_ips() {
  local v4="${PORTCULLIS_PUBLIC_IPV4:-}" v6="${PORTCULLIS_PUBLIC_IPV6:-}" lookup=true
  if [ -z "$v4" ] || [ -z "${PORTCULLIS_PUBLIC_IPV6+x}" ]; then
    domains_enrolled || lookup=false
  fi
  if [ -z "$v4" ]; then
    [ "$lookup" = false ] || v4="$(public_ip_detect 4)"
    if [ -n "$v4" ]; then
      _domains_last 4 "$v4"
    elif [ "$lookup" = true ]; then
      # Only a lookup that ran and failed falls back to the last address
      # (a skipped one publishes none: secrets/ restored on a new server
      # must not hand the old server's address to the first enrollment).
      v4="$(_domains_last 4)"
      if [ -n "$v4" ]; then
        warn "IPv4 detection failed: keeping the last detected address $v4 (set PORTCULLIS_PUBLIC_IPV4 in .env if it changed)."
      else
        warn "Could not detect the public IPv4 reliably (two HTTPS services must agree on a global address): added domains keep their records but get no new ones until it is known — set PORTCULLIS_PUBLIC_IPV4 in .env."
      fi
    fi
  fi
  if [ -z "${PORTCULLIS_PUBLIC_IPV6+x}" ]; then
    # No IPv6 means "remove the AAAA records": a transient detection
    # failure keeps the last detected address instead.
    v6=""
    [ "$lookup" = false ] || v6="$(public_ip_detect 6)"
    if [ -n "$v6" ]; then
      _domains_last 6 "$v6"
    elif [ "$lookup" = true ]; then
      v6="$(_domains_last 6)"
      [ -z "$v6" ] || warn "IPv6 detection failed: keeping the last detected address $v6 (set PORTCULLIS_PUBLIC_IPV6= in .env if the server has no IPv6 any more)."
    fi
  fi
  [ "$lookup" = true ] || info "No added domain: public address lookups skipped (run ./portcullis up again after adding the first domain)."
  export PORTCULLIS_PUBLIC_IPV4="$v4" PORTCULLIS_PUBLIC_IPV6="$v6"
  (umask 077 && printf 'DOMAINS_PUBLIC_IPV4=%s\nDOMAINS_PUBLIC_IPV6=%s\n' "$v4" "$v6" > "$(_domains_dir)/public-ips.env")
}

# domains_prepare — every file the domains service, the Hub and Traefik
# mount for it (called by stack_prepare, before compose runs).
domains_prepare() {
  local d
  d="$(_domains_dir)"
  (umask 077 && mkdir -p "$d/certs-endpoint")
  [ -s "$d/api-secret" ] || (umask 077 && gen_alnum 48 > "$d/api-secret")
  [ -s "$d/age.key" ] || domains_age_keygen "$d/age.key"
  domains_endpoint_certs
  domains_public_ips
}

# domains_fix_perms — called by secrets_fix_perms.
domains_fix_perms() {
  local d
  d="$(_domains_dir)"
  [ -d "$d" ] || return 0
  # Nothing traverses the directories (single-file bind mounts).
  chmod 700 "$d"
  [ ! -d "$d/certs-endpoint" ] || chmod 700 "$d/certs-endpoint"
  [ ! -e "$d/certs-endpoint/ca.key" ] || chmod 600 "$d/certs-endpoint/ca.key"
  [ ! -e "$d/certs-endpoint/ca.crt" ] || chmod 644 "$d/certs-endpoint/ca.crt"
  # Traefik's ACME account URI (dns_main_env_write): compose reads it.
  [ ! -e "$d/main-domain.env" ] || chmod 600 "$d/main-domain.env"
  local f
  [ ! -e "$d/api-secret" ] || { chmod 640 "$d/api-secret"; ct_own "$(id -u):$CT_UID_HUB" "$d/api-secret"; }
  for f in "$d/age.key" "$d/certs-endpoint/server.crt" "$d/certs-endpoint/server.key"; do
    [ ! -e "$f" ] || { chmod 640 "$f"; ct_own "$(id -u):$CT_UID_DOMAINS" "$f"; }
  done
  for f in "$d/certs-endpoint/client.crt" "$d/certs-endpoint/client.key"; do
    [ ! -e "$f" ] || { chmod 640 "$f"; ct_own "$(id -u):$CT_GID_TRAEFIK" "$f"; }
  done
}

# domains_restart_if_renewed — after `compose up`: restart domains, then
# traefik, when the endpoint certificates were renewed.
domains_restart_if_renewed() {
  [ "$DOMAINS_CERTS_RENEWED" = true ] || return 0
  # domains first (it serves the new server certificate), healthy, then
  # traefik (its client certificate): never traefik against the old one.
  if dc restart domains >/dev/null && wait_healthy 120 domains; then
    dc restart traefik >/dev/null || warn "could not restart traefik after renewing the endpoint certificates (run: docker compose restart traefik)"
  else
    warn "could not restart domains after renewing the endpoint certificates (run: docker compose restart domains, then docker compose restart traefik)"
  fi
  DOMAINS_CERTS_RENEWED=false
}

# domains_status_lines — `status` warnings for the endpoint certificates.
domains_status_lines() {
  local d f end
  d="$(_domains_dir)/certs-endpoint"
  for f in ca server client; do
    if [ ! -s "$d/$f.crt" ]; then
      _st_line warn "domains certificate endpoint: $f.crt missing (./portcullis up creates it)"
    elif _domains_expiring "$d/$f.crt" $((30 * 86400)); then
      end="$(openssl x509 -noout -enddate -in "$d/$f.crt" 2>/dev/null | cut -d= -f2)"
      _st_line warn "domains certificate endpoint: $f.crt expires $end (./portcullis up renews it)"
    else
      _st_line ok "domains certificate endpoint: $f.crt valid"
    fi
  done
}
