# shellcheck shell=bash
#
# `portcullis pki setup` — the internal certificate authority in Vault: a
# root CA (`pki`) and two intermediates signed by it, `pki_int` (YubiKey
# certificates, role client-cert) and `pki_file` (browser certificates,
# role browser-cert), and optionally a self-signed wildcard server cert for
# local dev / CI.
#
# Root and intermediate keys are generated `internal`: they never leave
# Vault and are persisted (encrypted) in Vault's raft storage.
#
# Idempotent: if pki_int already has an issuer the CA is not regenerated
# (that would invalidate every issued certificate); only missing pieces
# (pki_file, the roles, exported CA files, the truststore, the server
# cert) are recreated. A partial earlier run (mounts / root but no signed
# intermediate) is wiped and redone — no certificate can depend on it.
# --force destroys both CAs.

PKI_TTL_ROOT="87600h"          # 10 years
PKI_TTL_INTERMEDIATE="43800h"  # 5 years
PKI_CREATED=false              # set to true when a new CA was created

# Client-cert lifetime: CLIENT_CERT_TTL (.env), default 30 days. Revocation
# is enforced on every request (group-gate) and at login (Keycloak CRL
# check), so the lifetime no longer has to stand in for revocation; users
# renew on the Sign-in page (https://people.<domain>/signin) or with
# `portcullis cert renew`. Browser certificates get at most the same.
pki_client_ttl() { echo "${CLIENT_CERT_TTL:-720h}"; }

# _vault_probe <vault args...> — 0 = present, 2 = absent (Vault said "No
# value found": vault_no_value, or an empty JSON answer); anything else
# aborts. The vault CLI exits 2 for every API error too, so a sealed Vault,
# a 403 or an unreachable Vault must never be mistaken for "no PKI yet"
# (that would create a 2nd CA or wipe one).
_vault_probe() {
  local rc=0 out
  out="$(vault "$@" 2>&1)" || rc=$?
  if [ "$rc" = 0 ]; then
    case "$(printf '%s' "$out" | tr -d '[:space:]')" in
      "") ;;                 # exit 0 with no answer at all: not trusted
      "{}"|"[]") return 2 ;;
      *) return 0 ;;
    esac
  elif [ "$rc" = 2 ] && vault_no_value "$out"; then
    return 2
  fi
  printf 'ERROR: %s failed (exit %s):\n' "'vault $*'" "$rc" >&2
  printf '%s\n' "$out" | sed 's/^/    /' >&2
  exit 1
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

_pki_write_client_role() { _pki_write_role pki_int client-cert "$1"; }
_pki_write_browser_role() { _pki_write_role pki_file browser-cert "$1"; }

# _pki_write_role <mount> <role> <domain> — the YubiKey (pki_int/client-cert)
# and browser (pki_file/browser-cert) certificate roles share every setting.
_pki_write_role() {
  local mount="$1" role="$2" domain="$3" ttl
  ttl="$(pki_client_ttl)"
  [[ "$ttl" =~ ^[0-9]+[smhd]?$ ]] || fail "CLIENT_CERT_TTL=$ttl is not a Vault duration (e.g. 720h)"
  info "Writing the $role role on $mount (TTL $ttl)..."
  # Client-auth only. The CN is always the explicit common_name parameter
  # (enroll / `portcullis cert enroll` pass the LLDAP username), never the
  # CSR's, and CSR SANs are ignored — a crafted CSR cannot smuggle in a
  # different identity. allow_any_name: usernames are not hostnames.
  # No SANs of any kind: no IP SANs (allow_ip_sans=false), no URI / other
  # SANs (allowed_uri_sans / allowed_other_sans empty); alt_names, ip_sans,
  # uri_sans and other_sans are also denied to enroll by its Vault policy
  # (vault/policies/enroll.hcl denied_parameters).
  vault write "$mount/roles/$role" \
    allowed_domains="$domain" allow_any_name=true enforce_hostnames=false \
    use_csr_common_name=false use_csr_sans=false \
    allow_ip_sans=false allowed_uri_sans="" allowed_other_sans="" \
    client_flag=true server_flag=false code_signing_flag=false email_protection_flag=false \
    key_type=ec key_bits=256 max_ttl="$ttl" ttl="$ttl" no_store=false >/dev/null
}

# _pki_configure_crl <mount> — keep a CA's CRLs fresh. auto_rebuild
# re-signs the full CRL before its nextUpdate (72h) passes, so Keycloak's
# CRL check (crl-abort-if-non-updated) never sees a stale list. With
# auto_rebuild, Vault no longer rebuilds the full CRL on revoke: new
# revocations go into the delta CRL (enable_delta), rebuilt every
# delta_rebuild_interval (Vault's periodic function runs once a minute, so
# 1m is the floor) and folded into the full CRL at its next rebuild.
# group-gate and Keycloak read both (/v1/<mount>/crl + /v1/<mount>/crl/delta,
# for pki_int and pki_file); `cert revoke` also rotates the full CRL at once.
_pki_configure_crl() {
  vault write "$1/config/crl" expiry=72h auto_rebuild=true auto_rebuild_grace_period=12h \
    enable_delta=true delta_rebuild_interval=1m >/dev/null \
    || warn "could not configure CRL auto-rebuild / delta CRLs on $1"
}

# _pki_create_browser_ca <domain> — the second intermediate, pki_file
# (browser certificates), signed by the root. Its key never leaves Vault.
_pki_create_browser_ca() {
  local domain="$1" csr signed
  info "Creating the browser certificate CA (pki_file)..."
  vault secrets enable -path=pki_file pki >/dev/null
  vault secrets tune -max-lease-ttl="$PKI_TTL_INTERMEDIATE" pki_file >/dev/null
  csr="$(vault write -format=json pki_file/intermediate/generate/internal \
    common_name="$(pki_browser_ca_cn "$domain")" | jq -r '.data.csr')"
  [ -n "$csr" ] && [ "$csr" != null ] || fail "pki_file: Vault returned no CSR"
  signed="$(vault write -format=json pki/root/sign-intermediate \
    csr="$csr" format=pem_bundle ttl="$PKI_TTL_INTERMEDIATE" | jq -r '.data.certificate')"
  [ -n "$signed" ] && [ "$signed" != null ] || fail "pki_file: the root returned no certificate"
  vault write pki_file/intermediate/set-signed certificate="$signed" >/dev/null
  vault write pki_file/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki_file/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki_file/crl" >/dev/null
}

pki_yubikey_ca_cn() { echo "$1 Intermediate CA"; }
pki_browser_ca_cn() { echo "$1 Browser Certificate CA"; }

# _pki_ca_pem <mount> — the mount's CA certificate (PEM), read from Vault.
# Fails on any error: a chain file is never written from a guess.
_pki_ca_pem() {
  local pem
  pem="$(vault read -field=certificate "$1/cert/ca")" || fail "cannot read $1's CA certificate from Vault"
  case "$pem" in
    *"-----BEGIN CERTIFICATE-----"*) printf '%s\n' "$pem" ;;
    *) fail "$1's CA certificate from Vault is not a PEM certificate" ;;
  esac
}

# _pki_cn <pem> — the subject CN of a certificate ("" when unreadable).
_pki_cn() {
  printf '%s\n' "$1" | openssl x509 -noout -subject 2>/dev/null | sed -n '/CN *=/{s/.*CN *= *//;s/[,/].*//;p;}'
}

# _pki_same <file> <content> — the file holds exactly <content> + newline.
_pki_same() { [ -f "$1" ] && printf '%s\n' "$2" | cmp -s - "$1"; }

# _pki_put <file> <content> — atomic write, 0644 (public CA material).
_pki_put() {
  local tmp
  tmp="$(mktemp "$(dirname "$1")/.pki.XXXXXX")" || fail "cannot write $1"
  { printf '%s\n' "$2" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$1"; } \
    || { rm -f "$tmp"; fail "cannot write $1"; }
}

# _pki_export <certs> <rewrite:true|false> — the public CA files, from
# Vault's own copies of the three CA certificates:
#   yubikey-ca.crt (pki_int), browser-ca.crt (pki_file);
#   ca-chain.crt = root + pki_int + pki_file (Traefik's protected-any and
#     authaware options: both kinds);
#   ca-chain-yubikey.crt = root + pki_int only (Traefik's protected option:
#     a browser certificate never passes that handshake);
#   truststore/ (Keycloak): portcullis-ca-chain.pem, portcullis-yubikey-ca.pem,
#     portcullis-browser-ca.pem.
# Refuses when the two intermediates' CNs are equal (every reader tells the
# kinds apart by issuer). When <rewrite> is true (pki_file was just
# created) or any chain / truststore file differs from what it should be,
# all of them are rewritten and PKI_TRUSTSTORE_CHANGED=true (stack.sh then
# restarts Traefik, Keycloak and group-gate, which read them only at
# start-up or through a single-file bind mount); a rewritten
# yubikey-ca.crt / browser-ca.crt sets it too.
_pki_export() {
  local certs="$1" rewrite="$2" root int file cn_int cn_file chain chain_yk ts
  root="$(_pki_ca_pem pki)" || exit 1
  int="$(_pki_ca_pem pki_int)" || exit 1
  file="$(_pki_ca_pem pki_file)" || exit 1
  cn_int="$(_pki_cn "$int")"
  cn_file="$(_pki_cn "$file")"
  [ -n "$cn_int" ] && [ -n "$cn_file" ] || fail "cannot read the CNs of the pki_int / pki_file CA certificates"
  [ "$cn_int" != "$cn_file" ] || fail "pki_int and pki_file have the same CN ($cn_int): YubiKey and browser
       certificates could not be told apart. Nothing was exported."
  [ -s "$certs/root-ca.crt" ] || _pki_put "$certs/root-ca.crt" "$root"
  [ -s "$certs/intermediate-ca.crt" ] || _pki_put "$certs/intermediate-ca.crt" "$int"
  # group-gate bind-mounts these two files: a running container keeps the
  # old inode after an atomic replace, so a change restarts it too.
  # shellcheck disable=SC2034  # read by stack.sh
  _pki_same "$certs/yubikey-ca.crt" "$int" || { _pki_put "$certs/yubikey-ca.crt" "$int"; PKI_TRUSTSTORE_CHANGED=true; }
  # shellcheck disable=SC2034  # read by stack.sh
  _pki_same "$certs/browser-ca.crt" "$file" || { _pki_put "$certs/browser-ca.crt" "$file"; PKI_TRUSTSTORE_CHANGED=true; }

  chain="$root"$'\n'"$int"$'\n'"$file"
  chain_yk="$root"$'\n'"$int"
  ts="$certs/truststore"
  mkdir -p "$ts"
  chmod 755 "$ts"
  if [ "$rewrite" != true ] \
     && _pki_same "$certs/ca-chain.crt" "$chain" \
     && _pki_same "$certs/ca-chain-yubikey.crt" "$chain_yk" \
     && _pki_same "$ts/portcullis-ca-chain.pem" "$chain" \
     && _pki_same "$ts/portcullis-yubikey-ca.pem" "$int" \
     && _pki_same "$ts/portcullis-browser-ca.pem" "$file"; then
    return 0
  fi
  info "Writing the CA chains and Keycloak's truststore..."
  _pki_put "$certs/ca-chain-yubikey.crt" "$chain_yk"
  _pki_put "$ts/portcullis-yubikey-ca.pem" "$int"
  _pki_put "$ts/portcullis-browser-ca.pem" "$file"
  _pki_put "$ts/portcullis-ca-chain.pem" "$chain"
  # ca-chain.crt last: its presence marks a complete setup (see pki_setup).
  _pki_put "$certs/ca-chain.crt" "$chain"
  # shellcheck disable=SC2034  # read by stack.sh
  PKI_TRUSTSTORE_CHANGED=true
}

# pki_setup <force> <with_server_cert>
pki_setup() {
  local force="$1" server_cert="$2"
  local domain="${PORTCULLIS_DOMAIN:-portcullis.local}" certs="$PORTCULLIS_ROOT/certs"
  local mounts have_pki=false have_int=false have_file=false int_issuer=false file_issuer=false
  local file_created=false int_pem
  require_cmd jq openssl
  vault_admin
  mkdir -p "$certs/revocation"
  [ "$(pki_yubikey_ca_cn "$domain")" != "$(pki_browser_ca_cn "$domain")" ] \
    || fail "the YubiKey and browser certificate CAs would have the same CN"

  mounts="$(vault secrets list -format=json)" || fail "cannot list Vault secrets engines (sealed? bad token?)"
  printf '%s' "$mounts" | jq -e 'has("pki/")' >/dev/null && have_pki=true
  printf '%s' "$mounts" | jq -e 'has("pki_int/")' >/dev/null && have_int=true
  printf '%s' "$mounts" | jq -e 'has("pki_file/")' >/dev/null && have_file=true
  if [ "$have_int" = true ] && _vault_probe list -format=json pki_int/issuers; then
    int_issuer=true
  fi
  if [ "$have_file" = true ] && _vault_probe list -format=json pki_file/issuers; then
    file_issuer=true
  fi

  if [ "$int_issuer" = true ] && [ "$force" != true ]; then
    ok "Vault PKI already initialised — not touching the YubiKey CA (--force destroys it)."
    if ! _vault_probe read -format=json pki_int/roles/client-cert; then
      warn "client-cert role missing — recreating it."
    fi
    # Always rewritten: picks up a changed CLIENT_CERT_TTL.
    _pki_write_client_role "$domain"
    _pki_configure_crl pki_int
    # A missing pki_file is a missing piece: created next to the existing
    # pki_int (no YubiKey certificate depends on it). A mount without an
    # issuer is a partial earlier run: wiped and redone.
    if [ "$file_issuer" != true ]; then
      # browser-ca.crt on disk = a browser CA existed: never wipe or replace
      # it on a guess (people's browser certificates depend on it).
      if [ -s "$certs/browser-ca.crt" ]; then
        fail "Vault has no browser certificate CA (pki_file) but $certs/browser-ca.crt exists
       (Vault data lost?). Restore vault_data + secrets/ (./portcullis restore), or create
       NEW CAs with ./portcullis pki setup --force (destroys both CAs: every YubiKey and
       browser certificate must be issued again)."
      fi
      if [ "$have_file" = true ]; then
        warn "Found an INCOMPLETE browser certificate CA (pki_file) — wiping it and starting over."
        vault secrets disable pki_file >/dev/null
      else
        warn "Browser certificate CA (pki_file) missing — creating it."
      fi
      int_pem="$(_pki_ca_pem pki_int)" || exit 1
      [ "$(_pki_cn "$int_pem")" != "$(pki_browser_ca_cn "$domain")" ] \
        || fail "pki_int's CN is already '$(pki_browser_ca_cn "$domain")': the two CAs could not be told apart"
      _pki_create_browser_ca "$domain"
      file_created=true
    fi
    _pki_write_browser_role "$domain"
    _pki_configure_crl pki_file
    [ -f "$certs/revocation/revoked-serials.txt" ] || : > "$certs/revocation/revoked-serials.txt"
    _pki_export "$certs" "$file_created"
    if [ "$server_cert" = true ] && [ ! -s "$certs/server.crt" ]; then
      _pki_issue_server_cert "$domain" "$certs"
    fi
    return 0
  fi

  # No CA in Vault, but a complete CA chain on disk: Vault data was lost
  # (or secrets/ belong to another Vault). A new CA silently invalidates
  # every enrolled cert, so that needs an explicit --force.
  if [ "$force" != true ] && { [ -s "$certs/ca-chain.crt" ] || [ -s "$certs/browser-ca.crt" ]; }; then
    fail "Vault has no CA but $certs/ca-chain.crt or browser-ca.crt exists (Vault data lost?).
       Restore vault_data + secrets/ (./portcullis restore), or create a NEW CA
       with ./portcullis pki setup --force (every YubiKey and browser certificate must be issued again)."
  fi

  if [ "$force" = true ] || [ "$have_pki" = true ] || [ "$have_int" = true ] || [ "$have_file" = true ]; then
    if [ "$force" = true ]; then
      warn "--force: disabling existing PKI mounts (both CAs and their issued-cert records are destroyed)..."
    else
      warn "Found an INCOMPLETE PKI (earlier run aborted?) — wiping it and starting over."
    fi
    if [ "$have_file" = true ]; then vault secrets disable pki_file >/dev/null; fi
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

  info "Creating the YubiKey certificate CA (pki_int)..."
  vault secrets enable -path=pki_int pki >/dev/null
  vault secrets tune -max-lease-ttl="$PKI_TTL_INTERMEDIATE" pki_int >/dev/null
  vault write -format=json pki_int/intermediate/generate/internal \
    common_name="$(pki_yubikey_ca_cn "$domain")" \
    | jq -r '.data.csr' > "$certs/intermediate.csr"
  vault write -format=json pki/root/sign-intermediate \
    csr="$(cat "$certs/intermediate.csr")" format=pem_bundle ttl="$PKI_TTL_INTERMEDIATE" \
    | jq -r '.data.certificate' > "$certs/intermediate-ca.crt"
  vault write pki_int/intermediate/set-signed certificate="$(cat "$certs/intermediate-ca.crt")" >/dev/null
  vault write pki_int/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki_int/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki_int/crl" >/dev/null

  _pki_write_client_role "$domain"
  _pki_configure_crl pki_int
  _pki_create_browser_ca "$domain"
  _pki_write_browser_role "$domain"
  _pki_configure_crl pki_file

  # New CA → old revocations are meaningless; start an empty serial list.
  : > "$certs/revocation/revoked-serials.txt"
  # Chains + truststore last (ca-chain.crt marks a complete setup).
  _pki_export "$certs" true

  if [ "$server_cert" = true ]; then
    _pki_issue_server_cert "$domain" "$certs"
  fi
  # shellcheck disable=SC2034  # read by stack.sh
  PKI_CREATED=true
  ok "Vault PKI ready: $certs/ca-chain.crt (both CAs), ca-chain-yubikey.crt, yubikey-ca.crt, browser-ca.crt"
}

help_pki() {
  cat <<'EOF'
Usage: portcullis pki setup [--force] [--with-server-cert]

  setup     Create the internal certificate authority (YubiKey and browser certificate CAs)
EOF
}

help_pki_setup() {
  cat <<'EOF'
Usage: portcullis pki setup [--force] [--with-server-cert]

Create the internal certificate authority in Vault: a root CA (pki, 10y)
and two intermediates signed by it (5y each): the YubiKey certificate CA
(pki_int, role client-cert) and the browser certificate CA (pki_file, CN
"<domain> Browser Certificate CA", role browser-cert). Both roles: lifetime
CLIENT_CERT_TTL (default 720h = 30 days), CN taken from the caller, never
from the CSR. Enables CRL auto-rebuild + delta CRLs (rebuilt every minute)
on both intermediates.

Writes certs/root-ca.crt, intermediate-ca.crt, yubikey-ca.crt,
browser-ca.crt, ca-chain.crt (root + both intermediates: Traefik's
protected-any and authaware options), ca-chain-yubikey.crt (root + the
YubiKey CA only: Traefik's protected option) and Keycloak's truststore
(certs/truststore/portcullis-ca-chain.pem, portcullis-yubikey-ca.pem,
portcullis-browser-ca.pem).

Idempotent: an existing CA is never replaced; both roles are rewritten (so
a new CLIENT_CERT_TTL applies to certificates issued from now on); missing
pieces (the browser certificate CA, CA files, truststore, server cert) are
recreated; a partial earlier run is redone. When the browser certificate
CA is created or a chain file is out of date, both chain files and the
truststore are rewritten and the next `up` restarts Traefik and Keycloak.
Refuses when the two intermediates have the same CN, and refuses to create
a new CA when Vault has none but certs/ca-chain.crt exists (Vault data
lost) — restore a backup or use --force.

Options:
  --force              DESTROY both CAs and create new ones (every YubiKey
                       and browser certificate stops working)
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
