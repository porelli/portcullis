# shellcheck shell=bash
#
# `portcullis pki setup` — Vault PKI: root CA + intermediate CA for
# client certificates (and optionally a self-signed wildcard server cert
# for local dev / CI).
#
# Root and intermediate keys are generated `internal`: they never leave
# Vault and are persisted (encrypted) in Vault's raft storage.
#
# Idempotent: if pki_int already has an issuer nothing is regenerated
# (that would invalidate every enrolled client cert); only missing pieces
# (client-cert role, exported CA files, server cert) are recreated. A
# partial earlier run (mounts / root but no signed intermediate) is wiped
# and redone — no client cert can depend on it. --force destroys the CA.

PKI_TTL_ROOT="87600h"          # 10 years
PKI_TTL_INTERMEDIATE="43800h"  # 5 years
PKI_CREATED=false              # set to true when a new CA was created

# Client-cert lifetime: CLIENT_CERT_TTL (.env), default 30 days. Revocation
# is enforced on every request (group-gate) and at login (Keycloak CRL
# check), so the lifetime no longer has to stand in for revocation; users
# renew from the enrollment UI (/self) or `portcullis cert renew`.
pki_client_ttl() { echo "${CLIENT_CERT_TTL:-720h}"; }

# _vault_probe <vault args...> — 0 = present, 2 = absent ("No value found",
# vault CLI exit 2); anything else aborts: a sealed Vault or a bad token
# must never be mistaken for "no PKI yet" (that would create a 2nd CA).
_vault_probe() {
  local rc=0 out
  out="$(vault "$@" 2>&1)" || rc=$?
  case "$rc" in
    0) [ -n "$out" ] && return 0 || return 2 ;;
    2) return 2 ;;
    *) printf 'ERROR: %s failed (exit %s):\n' "'vault $*'" "$rc" >&2
       printf '%s\n' "$out" | sed 's/^/    /' >&2
       exit 1 ;;
  esac
}

_pki_issue_server_cert() {
  local domain="$1" certs="$2" issued
  info "Generating self-signed wildcard server certificate for *.$domain (local dev)..."
  vault write pki_int/roles/server-cert \
    allowed_domains="$domain" allow_subdomains=true allow_bare_domains=true \
    allow_glob_domains=true client_flag=false server_flag=true \
    key_type=ec key_bits=256 max_ttl="8760h" ttl="8760h" no_store=false >/dev/null
  issued="$(vault write -format=json pki_int/issue/server-cert \
    common_name="*.$domain" alt_names="$domain,localhost" ip_sans="127.0.0.1" ttl="8760h")" \
    || fail "server certificate issuance failed"
  printf '%s\n' "$issued" | jq -r '.data.certificate' > "$certs/server.crt"
  # Private key: operator + group 0 (Traefik runs as root but without
  # CAP_DAC_OVERRIDE, so it reads by mode like everyone else).
  (umask 077 && printf '%s\n' "$issued" | jq -r '.data.private_key' > "$certs/server.key")
  ct_group_read "$CT_GID_TRAEFIK" "$certs/server.key"
  ok "Server cert: $certs/server.crt"
}

_pki_write_client_role() {
  local domain="$1" ttl
  ttl="$(pki_client_ttl)"
  [[ "$ttl" =~ ^[0-9]+[smhd]?$ ]] || fail "CLIENT_CERT_TTL=$ttl is not a Vault duration (e.g. 720h)"
  info "Writing client-cert role (TTL $ttl)..."
  # Client-auth only. The CN is always the explicit common_name parameter
  # (enroll / `portcullis cert enroll` pass the LLDAP username), never the
  # CSR's, and CSR SANs are ignored — a crafted CSR cannot smuggle in a
  # different identity. allow_any_name: usernames are not hostnames.
  vault write pki_int/roles/client-cert \
    allowed_domains="$domain" allow_any_name=true enforce_hostnames=false \
    use_csr_common_name=false use_csr_sans=false \
    client_flag=true server_flag=false code_signing_flag=false email_protection_flag=false \
    key_type=ec key_bits=256 max_ttl="$ttl" ttl="$ttl" no_store=false >/dev/null
}

# _pki_configure_crl — keep pki_int's CRLs fresh. auto_rebuild re-signs the
# full CRL before its nextUpdate (72h) passes, so Keycloak's CRL check
# (crl-abort-if-non-updated) never sees a stale list. With auto_rebuild,
# Vault no longer rebuilds the full CRL on revoke: new revocations go into
# the delta CRL (enable_delta), rebuilt every delta_rebuild_interval
# (Vault's periodic function runs once a minute, so 1m is the floor) and
# folded into the full CRL at its next rebuild. group-gate and Keycloak
# read both (/v1/pki_int/crl + /v1/pki_int/crl/delta); `cert revoke` also
# rotates the full CRL immediately.
_pki_configure_crl() {
  vault write pki_int/config/crl expiry=72h auto_rebuild=true auto_rebuild_grace_period=12h \
    enable_delta=true delta_rebuild_interval=1m >/dev/null \
    || warn "could not configure CRL auto-rebuild / delta CRLs on pki_int"
}

# _pki_export_truststore — CA chain for Keycloak's X.509 authenticator
# (certs/truststore/, mounted into Keycloak; read at start-up).
_pki_export_truststore() {
  local certs="$1"
  mkdir -p "$certs/truststore"
  chmod 755 "$certs/truststore"
  if ! cmp -s "$certs/ca-chain.crt" "$certs/truststore/portcullis-ca-chain.pem" 2>/dev/null; then
    cp "$certs/ca-chain.crt" "$certs/truststore/portcullis-ca-chain.pem"
    chmod 644 "$certs/truststore/portcullis-ca-chain.pem"
    # shellcheck disable=SC2034  # read by stack.sh
    PKI_TRUSTSTORE_CHANGED=true
  fi
}

# pki_setup <force> <with_server_cert>
pki_setup() {
  local force="$1" server_cert="$2"
  local domain="${PORTCULLIS_DOMAIN:-portcullis.local}" certs="$PORTCULLIS_ROOT/certs"
  local mounts have_pki=false have_int=false int_issuer=false
  require_cmd jq
  vault_admin
  mkdir -p "$certs/revocation"

  mounts="$(vault secrets list -format=json)" || fail "cannot list Vault secrets engines (sealed? bad token?)"
  printf '%s' "$mounts" | jq -e 'has("pki/")' >/dev/null && have_pki=true
  printf '%s' "$mounts" | jq -e 'has("pki_int/")' >/dev/null && have_int=true
  if [ "$have_int" = true ] && _vault_probe list -format=json pki_int/issuers; then
    int_issuer=true
  fi

  if [ "$int_issuer" = true ] && [ "$force" != true ]; then
    ok "Vault PKI already initialised — not touching the CA (--force destroys it)."
    if ! _vault_probe read -format=json pki_int/roles/client-cert; then
      warn "client-cert role missing — recreating it."
    fi
    # Always rewritten: picks up a changed CLIENT_CERT_TTL.
    _pki_write_client_role "$domain"
    _pki_configure_crl
    # Re-export the public CA files if they are missing (e.g. fresh checkout).
    [ -s "$certs/root-ca.crt" ] || vault read -field=certificate pki/cert/ca > "$certs/root-ca.crt"
    [ -s "$certs/intermediate-ca.crt" ] || vault read -field=certificate pki_int/cert/ca > "$certs/intermediate-ca.crt"
    [ -s "$certs/ca-chain.crt" ] || cat "$certs/root-ca.crt" "$certs/intermediate-ca.crt" > "$certs/ca-chain.crt"
    [ -f "$certs/revocation/revoked-serials.txt" ] || : > "$certs/revocation/revoked-serials.txt"
    _pki_export_truststore "$certs"
    if [ "$server_cert" = true ] && [ ! -s "$certs/server.crt" ]; then
      _pki_issue_server_cert "$domain" "$certs"
    fi
    return 0
  fi

  # No CA in Vault, but a complete CA chain on disk: Vault data was lost
  # (or secrets/ belong to another Vault). A new CA silently invalidates
  # every enrolled cert, so that needs an explicit --force.
  if [ "$force" != true ] && [ -s "$certs/ca-chain.crt" ]; then
    fail "Vault has no CA but $certs/ca-chain.crt exists (Vault data lost?).
       Restore vault_data + secrets/ (./portcullis restore), or create a NEW CA
       with ./portcullis pki setup --force (every client cert must be re-enrolled)."
  fi

  if [ "$force" = true ] || [ "$have_pki" = true ] || [ "$have_int" = true ]; then
    if [ "$force" = true ]; then
      warn "--force: disabling existing PKI mounts (old CA and issued-cert records are destroyed)..."
    else
      warn "Found an INCOMPLETE PKI (earlier run aborted?) — wiping it and starting over."
    fi
    if [ "$have_int" = true ]; then vault secrets disable pki_int >/dev/null; fi
    if [ "$have_pki" = true ]; then vault secrets disable pki >/dev/null; fi
  fi

  info "Creating root CA..."
  vault secrets enable -path=pki pki >/dev/null
  vault secrets tune -max-lease-ttl="$PKI_TTL_ROOT" pki >/dev/null
  vault write -format=json pki/root/generate/internal \
    common_name="$domain Root CA" ttl="$PKI_TTL_ROOT" \
    | jq -r '.data.certificate' > "$certs/root-ca.crt"
  vault write pki/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki/crl" >/dev/null

  info "Creating intermediate CA..."
  vault secrets enable -path=pki_int pki >/dev/null
  vault secrets tune -max-lease-ttl="$PKI_TTL_INTERMEDIATE" pki_int >/dev/null
  vault write -format=json pki_int/intermediate/generate/internal \
    common_name="$domain Intermediate CA" \
    | jq -r '.data.csr' > "$certs/intermediate.csr"
  vault write -format=json pki/root/sign-intermediate \
    csr="$(cat "$certs/intermediate.csr")" format=pem_bundle ttl="$PKI_TTL_INTERMEDIATE" \
    | jq -r '.data.certificate' > "$certs/intermediate-ca.crt"
  vault write pki_int/intermediate/set-signed certificate="$(cat "$certs/intermediate-ca.crt")" >/dev/null
  vault write pki_int/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki_int/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki_int/crl" >/dev/null

  _pki_write_client_role "$domain"
  _pki_configure_crl

  # CA chain last: its presence marks a complete setup (see the guard above).
  cat "$certs/root-ca.crt" "$certs/intermediate-ca.crt" > "$certs/ca-chain.crt"
  _pki_export_truststore "$certs"
  # New CA → old revocations are meaningless; start an empty serial list.
  : > "$certs/revocation/revoked-serials.txt"

  if [ "$server_cert" = true ]; then
    _pki_issue_server_cert "$domain" "$certs"
  fi
  # shellcheck disable=SC2034  # read by stack.sh
  PKI_CREATED=true
  ok "Vault PKI ready: $certs/root-ca.crt, intermediate-ca.crt, ca-chain.crt"
}

help_pki() {
  cat <<'EOF'
Usage: portcullis pki setup [--force] [--with-server-cert]

  setup     Create the Vault PKI (root + intermediate CA, client-cert role)
EOF
}

help_pki_setup() {
  cat <<'EOF'
Usage: portcullis pki setup [--force] [--with-server-cert]

Create the client-certificate CA in Vault: root CA (10y), intermediate CA
(5y) and the client-cert role (lifetime CLIENT_CERT_TTL, default 720h = 30
days; CN taken from the caller, never from the CSR). Writes
certs/root-ca.crt, intermediate-ca.crt, ca-chain.crt and Keycloak's
truststore (certs/truststore/portcullis-ca-chain.pem); enables CRL
auto-rebuild + delta CRLs (rebuilt every minute) on pki_int.

Idempotent: an existing CA is never replaced; the client-cert role is
rewritten (so a new CLIENT_CERT_TTL applies to certs issued from now on),
missing pieces (CA files, truststore, server cert) are recreated, and a
partial earlier run is redone.
Refuses to create a new CA when Vault has none but certs/ca-chain.crt
exists (Vault data lost) — restore a backup or use --force.

Options:
  --force              DESTROY the existing CA and create a new one
                       (every enrolled client certificate stops working)
  --with-server-cert   Also issue a self-signed *.<domain> server cert
                       (certs/server.crt, server.key 0640 group 0) for local dev/CI

Admin token: VAULT_TOKEN if set, else the root token in secrets/vault-init.json.
EOF
}

cmd_pki() {
  local sub="${1:-}" force=false server_cert=false
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_pki; [ -n "$sub" ] || exit 2; return 0 ;;
    setup) ;;
    *) usage_error pki "unknown subcommand: $sub" ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      --force) force=true ;;
      --with-server-cert) server_cert=true ;;
      -h|--help) help_pki_setup; return 0 ;;
      *) usage_error "pki setup" "unknown argument: $1" ;;
    esac
    shift
  done
  need_env
  pki_setup "$force" "$server_cert"
}
