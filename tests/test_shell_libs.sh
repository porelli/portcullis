#!/usr/bin/env bash
#
# Unit tests for the shell libraries behind ./portcullis (scripts/lib/*.sh):
# .env parsing/editing, secret generation, portcullis-proxy validation,
# revoked-serial sync and `pki setup` idempotency. No Docker/Vault needed:
# stub `docker` / `vault` executables on PATH answer from canned data.
#
# Run: bash tests/test_shell_libs.sh
#
set -uo pipefail

# The shell environment wins over .env (like docker compose): make sure
# the caller's (e.g. CI's workflow-level) settings cannot leak in.
unset PORTCULLIS_DOMAIN VAULT_ADDR VAULT_TOKEN COMPOSE_FILE KEYCLOAK_URL

HERE="$(cd "$(dirname "$0")" && pwd)"
CLI="$HERE/../portcullis"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
# t_pass/t_fail, not ok/bad: the libraries define their own ok().
t_pass() { PASS=$((PASS + 1)); echo "ok   - $*"; }
t_fail() { FAIL=$((FAIL + 1)); echo "FAIL - $*"; }
expect_ok()   { local d="$1"; shift; if "$@" >/dev/null 2>&1; then t_pass "$d"; else t_fail "$d"; fi; }
expect_fail() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then t_fail "$d"; else t_pass "$d"; fi; }
expect_eq()   { if [ "$2" = "$3" ]; then t_pass "$1"; else t_fail "$1 (got '$2', want '$3')"; fi; }
file_mode()   { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
file_inode()  { stat -c %i "$1" 2>/dev/null || stat -f %i "$1"; }

# ── stubs ──────────────────────────────────────────────────
mkdir -p "$WORK/bin" "$WORK/stub"
export STUB_DIR="$WORK/stub"
# docker: only `network inspect` matters here ($STUB_DIR/ipam = current IPAM).
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_DIR/calls"
if [ "$1 $2" = "network inspect" ]; then
  [ -f "$STUB_DIR/ipam" ] || exit 1
  cat "$STUB_DIR/ipam"
fi
exit 0
STUB
# vault: STUB_VAULT_RC / STUB_VAULT_OUT control `vault list` behaviour.
cat > "$WORK/bin/vault" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_DIR/vault-calls"
printf '%s\n' "${STUB_VAULT_OUT:-}"
exit "${STUB_VAULT_RC:-0}"
STUB
chmod +x "$WORK/bin/docker" "$WORK/bin/vault"
export PATH="$WORK/bin:$PATH"

export PORTCULLIS_ROOT="$WORK/root"
mkdir -p "$PORTCULLIS_ROOT"
# shellcheck source=../scripts/lib/common.sh
source "$HERE/../scripts/lib/common.sh"
# shellcheck source=../scripts/lib/network.sh
source "$HERE/../scripts/lib/network.sh"
# shellcheck source=../scripts/lib/vault.sh
source "$HERE/../scripts/lib/vault.sh"
# shellcheck source=../scripts/lib/certs.sh
source "$HERE/../scripts/lib/certs.sh"

# ══ common: .env parsing ═══════════════════════════════════
ENVF="$WORK/test.env"
cat > "$ENVF" <<'EOF'
# comment
PLAIN=abc
export EXPORTED=yes
DQ="with spaces # not a comment"
SQ='single $HOME'
TRAIL=value # trailing comment
HASHED=a#b
EMPTY=
CMD=$(touch /tmp/portcullis-test-pwned)
ALREADY=from-file
  INDENT=x
not a line
EOF
rm -f /tmp/portcullis-test-pwned
(
  ALREADY=from-shell
  export ALREADY
  env_load "$ENVF"
  expect_eq "env: plain value" "$PLAIN" abc
  expect_eq "env: export prefix" "$EXPORTED" yes
  expect_eq "env: double quotes stripped, # kept" "$DQ" "with spaces # not a comment"
  # shellcheck disable=SC2016
  expect_eq "env: single quotes, no expansion" "$SQ" 'single $HOME'
  expect_eq "env: trailing comment stripped" "$TRAIL" value
  expect_eq "env: # inside a value kept" "$HASHED" 'a#b'
  expect_eq "env: empty value" "${EMPTY-unset}" ""
  expect_eq "env: leading whitespace" "$INDENT" x
  expect_eq "env: shell environment wins" "$ALREADY" from-shell
  # shellcheck disable=SC2016
  expect_eq "env: \$(...) not executed" "$CMD" '$(touch /tmp/portcullis-test-pwned)'
  expect_fail "env: no code execution" test -e /tmp/portcullis-test-pwned
  echo "$PASS $FAIL" > "$WORK/counts"
)
read -r PASS FAIL < "$WORK/counts"
expect_eq "env_get reads the file" "$(env_get TRAIL "$ENVF")" value
expect_eq "env_get missing key → empty" "$(env_get NOPE "$ENVF")" ""

# ── env_set: in place, replace / append ──
printf 'A=1\nB=2' > "$ENVF"   # no trailing newline
chmod 600 "$ENVF"
ino="$(file_inode "$ENVF")"
env_set B 'new&value|with/slashes' "$ENVF"
env_set C 3 "$ENVF"
expect_eq "env_set replaces + appends" "$(cat "$ENVF")" "$(printf 'A=1\nB=new&value|with/slashes\nC=3')"
expect_eq "env_set keeps the inode (bind mount)" "$(file_inode "$ENVF")" "$ino"
expect_eq "env_set keeps the mode" "$(file_mode "$ENVF")" 600
ln -s "$ENVF" "$WORK/link.env"
env_set A 9 "$WORK/link.env"
expect_ok "env_set through a symlink keeps the symlink" test -L "$WORK/link.env"
expect_eq "env_set through a symlink edits the target" "$(env_get A "$ENVF")" 9
expect_fail "env_set rejects newlines" bash -c "source '$HERE/../scripts/lib/common.sh'; env_set X \$'a\nb' '$ENVF'"

# ── secrets ──
s="$(gen_alnum 40)"
expect_eq "gen_alnum length" "${#s}" 40
expect_ok "gen_alnum charset" grep -Eqx '[A-Za-z0-9]{40}' <<< "$s"
expect_eq "cookie secret decodes to 32 bytes" "$(gen_cookie_secret | tr -- '-_' '+/' | openssl base64 -d -A | wc -c | tr -d ' ')" 32
expect_ok "hub proxy secret is 64 hex chars" grep -Eqx '[0-9a-f]{64}' <<< "$(gen_secret_for HUB_PROXY_SECRET)"
expect_fail "two secrets differ" test "$(gen_secret_for POSTGRES_PASSWORD)" = "$(gen_secret_for POSTGRES_PASSWORD)"

printf 'PORTCULLIS_DOMAIN=x\nHUB_PROXY_SECRET=\nLLDAP_JWT_SECRET=keep\n' > "$PORTCULLIS_ROOT/.env"
( unset HUB_PROXY_SECRET LLDAP_JWT_SECRET FORWARD_AUTH_CLIENT_SECRET
  env_generate_missing HUB_PROXY_SECRET LLDAP_JWT_SECRET FORWARD_AUTH_CLIENT_SECRET >/dev/null )
expect_ok "generate_missing fills an empty value" grep -Eq '^HUB_PROXY_SECRET=[0-9a-f]{64}$' "$PORTCULLIS_ROOT/.env"
expect_ok "generate_missing appends a missing key" grep -Eq '^FORWARD_AUTH_CLIENT_SECRET=[A-Za-z0-9]{40}$' "$PORTCULLIS_ROOT/.env"
expect_eq "generate_missing keeps existing values" "$(env_get LLDAP_JWT_SECRET)" keep
expect_eq "generate_missing writes each key once" "$(grep -c '^HUB_PROXY_SECRET=' "$PORTCULLIS_ROOT/.env")" 1

# ══ common: Hub env subset, container file ownership ═══════
HR="$WORK/hubroot"
mkdir -p "$HR"
cat > "$HR/.env" <<'ENVEOF'
PORTCULLIS_DOMAIN=hub.test
POSTGRES_PASSWORD=pg-secret
HUB_PROXY_SECRET=hub-secret
KEYCLOAK_ADMIN_PASSWORD=kc-secret
HEADSCALE_OIDC_CLIENT_SECRET=hs-secret
NETBIRD_OIDC_CLIENT_SECRET=nb-secret
MY_APP_VAR=shared
HUB_SHARED_ENV=MY_APP_VAR POSTGRES_PASSWORD
ENVEOF
hub_env_run() (
  PORTCULLIS_ROOT="$HR"
  unset PORTCULLIS_DOMAIN HEADSCALE_OIDC_CLIENT_SECRET NETBIRD_OIDC_CLIENT_SECRET MY_APP_VAR HUB_SHARED_ENV POSTGRES_PASSWORD HUB_PROXY_SECRET KEYCLOAK_ADMIN_PASSWORD
  env_load
  hub_env_write 2>/dev/null
)
hub_env_run
HE="$HR/secrets/hub/core.env"
expect_ok   "hub env: domain" grep -qx 'PORTCULLIS_DOMAIN=hub.test' "$HE"
expect_ok   "hub env: Traefik IP (compose default)" grep -qx 'PORTCULLIS_TRAEFIK_IP=172.31.250.2' "$HE"
expect_ok   "hub env: VPN client secret by prefix" grep -qx 'HEADSCALE_OIDC_CLIENT_SECRET=hs-secret' "$HE"
expect_ok   "hub env: HUB_SHARED_ENV" grep -qx 'MY_APP_VAR=shared' "$HE"
expect_fail "hub env: never a core secret" grep -Eq 'pg-secret|hub-secret|kc-secret' "$HE"
INODE_BEFORE="$(file_inode "$HE")"
hub_env_run
expect_eq "hub env: rewritten in place" "$(file_inode "$HE")" "$INODE_BEFORE"

rm -f "$STUB_DIR/calls"
mkdir -p "$HR/secrets/enroll" && echo r > "$HR/secrets/enroll/role-id" && chmod 600 "$HR/secrets/enroll/role-id"
ct_group_read 10002 "$HR/secrets/enroll" "$HR/secrets/enroll/role-id"
expect_eq "ct_group_read: file 0640" "$(file_mode "$HR/secrets/enroll/role-id")" 640
expect_eq "ct_group_read: dir 0750" "$(file_mode "$HR/secrets/enroll")" 750
expect_ok "ct_group_read: chgrp through a helper container" grep -q "run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN.*chown $(id -u):10002 /t/0 /t/1" "$STUB_DIR/calls"
rm -f "$STUB_DIR/calls"
ct_own "$(id -u):$(id -g)" "$HR/secrets/enroll/role-id"
expect_fail "ct_own: no-op when already right" test -s "$STUB_DIR/calls"

# ══ network: IP math / validation ══════════════════════════
expect_eq "ip_to_int" "$(ip_to_int 172.31.250.2)" "$(( (172<<24) | (31<<16) | (250<<8) | 2 ))"
expect_eq "ip_to_int leading zeros are decimal" "$(ip_to_int 010.0.0.8)" "$(( (10<<24) | 8 ))"
expect_fail "ip_to_int rejects 256" ip_to_int 1.2.3.256
expect_fail "ip_to_int rejects garbage" ip_to_int 1.2.3
expect_ok   "cidr_contains inside" cidr_contains 172.31.250.0/24 172.31.250.200
expect_fail "cidr_contains outside" cidr_contains 172.31.250.128/25 172.31.250.2
expect_ok   "cidr_contains /0" cidr_contains 0.0.0.0/0 8.8.8.8

unset PORTCULLIS_PROXY_SUBNET PORTCULLIS_PROXY_IP_RANGE PORTCULLIS_TRAEFIK_IP
expect_ok "defaults are valid" validate_proxy_network_config
check_cfg() { PORTCULLIS_PROXY_SUBNET="$1" PORTCULLIS_PROXY_IP_RANGE="$2" PORTCULLIS_TRAEFIK_IP="$3" validate_proxy_network_config; }
expect_ok   "custom valid config"             check_cfg 10.99.0.0/16 10.99.128.0/17 10.99.0.10
expect_fail "traefik IP in dynamic range"     check_cfg 172.31.250.0/24 172.31.250.0/25 172.31.250.2
expect_fail "range outside subnet"            check_cfg 172.31.250.0/24 172.31.251.0/25 172.31.250.2
expect_fail "traefik IP outside subnet"       check_cfg 172.31.250.0/24 172.31.250.128/25 172.31.251.2
expect_fail "traefik IP = gateway"            check_cfg 172.31.250.0/24 172.31.250.128/25 172.31.250.1
expect_fail "invalid subnet"                  check_cfg 172.31.250.0/33 172.31.250.128/25 172.31.250.2
unset PORTCULLIS_AUTH_SUBNET PORTCULLIS_AUTH_IP_RANGE PORTCULLIS_AUTH_TRAEFIK_IP
expect_ok "auth: defaults are valid" validate_auth_network_config
check_auth() { PORTCULLIS_AUTH_SUBNET="$1" PORTCULLIS_AUTH_IP_RANGE="$2" PORTCULLIS_AUTH_TRAEFIK_IP="$3" validate_auth_network_config; }
expect_ok   "auth: custom valid config"       check_auth 10.98.0.0/28 10.98.0.8/29 10.98.0.2
expect_fail "auth: traefik IP in range"       check_auth 172.31.251.0/28 172.31.251.0/29 172.31.251.2
expect_fail "auth: overlaps portcullis-proxy" check_auth 172.31.250.0/28 172.31.250.8/29 172.31.250.2
expect_fail "auth: traefik IP = gateway"      check_auth 172.31.251.0/28 172.31.251.8/29 172.31.251.1

# ══ network: state + guard ═════════════════════════════════
rm -f "$STUB_DIR/ipam"
expect_eq "state missing" "$(proxy_network_state)" missing
expect_ok "guard: missing network is fine" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
printf '%s' '172.31.250.0/24|172.31.250.128/25;' > "$STUB_DIR/ipam"
expect_eq "state ok" "$(proxy_network_state)" ok
printf '%s' '172.18.0.0/16|;' > "$STUB_DIR/ipam"
expect_eq "state mismatch (docker-assigned subnet)" "$(proxy_network_state)" mismatch
printf '%s' '172.31.250.0/24|;' > "$STUB_DIR/ipam"
expect_eq "state mismatch (no ip_range)" "$(proxy_network_state)" mismatch
expect_fail "guard: mismatch aborts" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
expect_fail "guard: invalid auth config aborts" bash -c "rm -f '$STUB_DIR/ipam'; PORTCULLIS_AUTH_TRAEFIK_IP=172.31.251.9; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
expect_fail "guard: invalid config aborts" bash -c "PORTCULLIS_TRAEFIK_IP=1.2.3.4; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
expect_fail "network lib has no migration code" grep -Eq 'proxy_network_(migrate|reconnect)|docker network (connect|disconnect)' "$HERE/../scripts/lib/network.sh"

# ══ certs: write_revoked_serials ═══════════════════════════
REV="$WORK/revocation/revoked-serials.txt"
mkdir -p "$WORK/revocation"
printf '# old\naa:bb\n' > "$REV"
serials_in() { grep -v '^#' "$REV" | paste -sd' ' -; }

STUB_VAULT_RC=0 STUB_VAULT_OUT='["0a:bc","de:ad:be:ef"]' write_revoked_serials "$REV" >/dev/null 2>&1
expect_eq "sync writes Vault's revoked serials" "$(serials_in)" "0a:bc de:ad:be:ef"
expect_ok "sync file keeps a header" grep -q '^# Revoked client-cert serials' "$REV"

STUB_VAULT_RC=2 STUB_VAULT_OUT='No value found at pki_int/certs/revoked' write_revoked_serials "$REV" >/dev/null 2>&1
rc=$?
expect_eq "exit 2 (nothing revoked) succeeds" "$rc" 0
expect_eq "exit 2 → empty list" "$(serials_in)" ""

printf '# prev\n0a:bc\n' > "$REV"
before="$(cat "$REV")"
for case in "1|Error listing pki_int/certs/revoked: Vault is sealed" \
            "1|Error making API request. Code: 403. permission denied" \
            "1|dial tcp 127.0.0.1:8200: connect: connection refused" \
            "0|not json at all" \
            '0|{"keys":["0a:bc"]}'; do
  rc=0
  STUB_VAULT_RC="${case%%|*}" STUB_VAULT_OUT="${case#*|}" write_revoked_serials "$REV" >/dev/null 2>&1 || rc=$?
  expect_eq "error '${case#*|}' → non-zero" "$([ "$rc" -ne 0 ] && echo fail || echo ok)" fail
  expect_eq "error '${case#*|}' → file untouched" "$(cat "$REV")" "$before"
done
expect_eq "no temp files left behind" "$(find "$WORK/revocation" -name '.revoked.*' | wc -l | tr -d ' ')" 0

# ══ portcullis pki setup: idempotency / partial runs / guard ═══
# A scripted vault stub: $PKI_STATE selects which PKI pieces "exist".
mkdir -p "$WORK/pki-bin"
cat > "$WORK/pki-bin/vault" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_DIR/pki-calls"
case "$PKI_STATE:$*" in
  sealed:secrets\ list*) echo "Error: Vault is sealed" >&2; exit 2 ;;
  *:secrets\ list*)
    case "$PKI_STATE" in
      none) echo '{"secret/":{}}' ;;
      *) echo '{"pki/":{},"pki_int/":{}}' ;;
    esac ;;
  complete:list*pki_int/issuers*|norole:list*pki_int/issuers*) echo '["abc"]' ;;
  intbroken:list*pki_int/issuers*) echo "Error: permission denied" >&2; exit 1 ;;
  *:list*issuers*) echo "No value found" >&2; exit 2 ;;
  complete:read*pki_int/roles/client-cert*) echo '{"data":{}}' ;;
  *:read*pki_int/roles/client-cert*) echo "No value found" >&2; exit 2 ;;
  *:read\ -field=certificate*) echo "-----BEGIN CERTIFICATE-----" ;;
  *:write\ -format=json\ pki/root/generate*) echo '{"data":{"certificate":"ROOT"}}' ;;
  *:write\ -format=json\ pki_int/intermediate/generate*) echo '{"data":{"csr":"CSR"}}' ;;
  *:write\ -format=json\ pki/root/sign-intermediate*) echo '{"data":{"certificate":"INT"}}' ;;
  *:write\ -format=json\ pki_int/issue/server-cert*) echo '{"data":{"certificate":"SRV","private_key":"KEY"}}' ;;
esac
exit 0
STUB
chmod +x "$WORK/pki-bin/vault"
PKI_ROOT="$WORK/pki-root"
mkdir -p "$PKI_ROOT"
echo "PORTCULLIS_DOMAIN=example.test" > "$PKI_ROOT/.env"
# run_pki <state> [--keep] [args] — prints the CLI's exit code. Without
# --keep, certs/ starts empty.
run_pki() {
  local rc=0 state="$1"
  shift
  if [ "${1:-}" = --keep ]; then shift; else rm -rf "$PKI_ROOT/certs"; fi
  rm -f "$STUB_DIR/pki-calls"; touch "$STUB_DIR/pki-calls"
  PATH="$WORK/pki-bin:$PATH" PKI_STATE="$state" VAULT_TOKEN=t PORTCULLIS_ROOT="$PKI_ROOT" \
    "$CLI" pki setup "$@" >"$WORK/pki-out" 2>&1 || rc=$?
  echo "$rc"
}
expect_eq "pki: fresh install succeeds" "$(run_pki none --with-server-cert)" 0
expect_ok "pki: fresh install generates a root" grep -q 'root/generate/internal' "$STUB_DIR/pki-calls"
expect_ok "pki: root CN uses PORTCULLIS_DOMAIN" grep -q 'common_name=example.test Root CA' "$STUB_DIR/pki-calls"
expect_eq "pki: server.key is 0640 (group 0 for Traefik)" "$(file_mode "$PKI_ROOT/certs/server.key")" 640
expect_ok "pki: server.key chgrp via a helper container" grep -q "chown $(id -u):0 /t/0" "$STUB_DIR/calls"
expect_ok "pki: ca-chain written" grep -q INT "$PKI_ROOT/certs/ca-chain.crt"
expect_ok "pki: Keycloak truststore written" cmp -s "$PKI_ROOT/certs/ca-chain.crt" "$PKI_ROOT/certs/truststore/portcullis-ca-chain.pem"
expect_ok "pki: client role defaults to 30 days" grep -q 'roles/client-cert .*max_ttl=720h ttl=720h' "$STUB_DIR/pki-calls"
expect_ok "pki: CRL auto-rebuild configured" grep -q 'pki_int/config/crl .*auto_rebuild=true' "$STUB_DIR/pki-calls"
# auto_rebuild defers full-CRL rebuilds on revoke: new revocations must go to a delta CRL.
expect_ok "pki: delta CRLs enabled, rebuilt every minute" grep -q 'pki_int/config/crl .*enable_delta=true delta_rebuild_interval=1m' "$STUB_DIR/pki-calls"
expect_eq "pki: complete PKI is a no-op" "$(run_pki complete)" 0
expect_fail "pki: complete PKI → no generate / disable" grep -Eq 'generate|secrets disable' "$STUB_DIR/pki-calls"
expect_ok "pki: complete PKI re-exports missing CA files" test -s "$PKI_ROOT/certs/ca-chain.crt"
expect_ok "pki: complete PKI rewrites the role (TTL changes apply)" grep -q 'write pki_int/roles/client-cert' "$STUB_DIR/pki-calls"
expect_ok "pki: complete PKI (re)applies the CRL config incl. delta" grep -q 'pki_int/config/crl .*enable_delta=true' "$STUB_DIR/pki-calls"
rm -f "$PKI_ROOT/certs/truststore/portcullis-ca-chain.pem"
expect_eq "pki: CLIENT_CERT_TTL=2160h" "$(CLIENT_CERT_TTL=2160h run_pki complete)" 0
expect_ok "pki: role uses CLIENT_CERT_TTL" grep -q 'max_ttl=2160h ttl=2160h' "$STUB_DIR/pki-calls"
expect_ok "pki: complete PKI re-exports the truststore" test -s "$PKI_ROOT/certs/truststore/portcullis-ca-chain.pem"
expect_eq "pki: invalid CLIENT_CERT_TTL fails" "$(CLIENT_CERT_TTL='30 days' run_pki complete)" 1
expect_eq "pki: missing role only" "$(run_pki norole)" 0
expect_ok "pki: missing role is recreated" grep -q 'write pki_int/roles/client-cert' "$STUB_DIR/pki-calls"
expect_fail "pki: missing role does NOT wipe the CA" grep -Eq 'generate|secrets disable' "$STUB_DIR/pki-calls"
expect_eq "pki: partial run (no intermediate) is redone" "$(run_pki partial)" 0
expect_ok "pki: partial run wipes pki_int + pki first" grep -q 'secrets disable pki_int' "$STUB_DIR/pki-calls"
expect_eq "pki: sealed Vault fails" "$(run_pki sealed)" 1
expect_fail "pki: sealed Vault → nothing generated" grep -q generate "$STUB_DIR/pki-calls"
expect_eq "pki: read error on issuers fails" "$(run_pki intbroken)" 1
expect_fail "pki: read error → nothing wiped/generated" grep -Eq 'generate|secrets disable' "$STUB_DIR/pki-calls"
# Vault lost its data but certs/ca-chain.crt from the old CA is still there.
mkdir -p "$PKI_ROOT/certs" && echo OLD > "$PKI_ROOT/certs/ca-chain.crt"
expect_eq "pki: no CA in Vault + old ca-chain → refuses" "$(run_pki none --keep)" 1
expect_fail "pki: refusal creates nothing" grep -q generate "$STUB_DIR/pki-calls"
expect_ok "pki: refusal explains --force" grep -q -- '--force' "$WORK/pki-out"
expect_eq "pki: --force creates a new CA anyway" "$(run_pki none --keep --force)" 0
expect_ok "pki: --force generated a root" grep -q 'root/generate/internal' "$STUB_DIR/pki-calls"

# ══ portcullis cert sync (dispatch through the CLI) ════════
mkdir -p "$PKI_ROOT/certs/revocation"
rc=0; STUB_VAULT_RC=0 STUB_VAULT_OUT='["11:22"]' VAULT_TOKEN=t PORTCULLIS_ROOT="$PKI_ROOT" "$CLI" cert sync >/dev/null 2>&1 || rc=$?
expect_eq "cli cert sync succeeds" "$rc" 0
expect_ok "cli cert sync wrote the serial" grep -qx '11:22' "$PKI_ROOT/certs/revocation/revoked-serials.txt"
rc=0; STUB_VAULT_RC=1 STUB_VAULT_OUT='sealed' VAULT_TOKEN=t PORTCULLIS_ROOT="$PKI_ROOT" "$CLI" cert sync >/dev/null 2>&1 || rc=$?
expect_eq "cli cert sync fails on Vault error" "$rc" 1
expect_ok "cli cert sync error keeps the list" grep -qx '11:22' "$PKI_ROOT/certs/revocation/revoked-serials.txt"

# ══ monitoring: alertmanager config, textfile metrics ═════
# shellcheck source=../scripts/lib/monitoring.sh
source "$HERE/../scripts/lib/monitoring.sh"
am() { env -u ALERT_WEBHOOK_URL -u ALERT_NTFY_URL -u ALERT_SMTP_SMARTHOST -u ALERT_SMTP_TO "$@" bash -c \
  "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/monitoring.sh'; alertmanager_config"; }
OUT="$(am)"
expect_eq "alertmanager: default receiver has no integrations" "$(printf '%s' "$OUT" | jq -c '.receivers')" '[{"name":"portcullis"}]'
expect_eq "alertmanager: route to it" "$(printf '%s' "$OUT" | jq -r '.route.receiver')" portcullis
OUT="$(am ALERT_WEBHOOK_URL='https://hooks.example/x?a="b"' ALERT_NTFY_URL=https://ntfy.sh/topic)"
expect_eq "alertmanager: webhook + ntfy (JSON-escaped)" "$(printf '%s' "$OUT" | jq -r '[.receivers[0].webhook_configs[].url] | join(" ")')" \
  'https://hooks.example/x?a="b" https://ntfy.sh/topic?template=alertmanager'
OUT="$(am ALERT_SMTP_SMARTHOST=smtp.example:587 ALERT_SMTP_TO=ops@example ALERT_SMTP_USERNAME=u ALERT_SMTP_PASSWORD="p'w\"d" PORTCULLIS_DOMAIN=d.example)"
expect_eq "alertmanager: smtp receiver" "$(printf '%s' "$OUT" | jq -c '.receivers[0].email_configs[0] | [.to, .from, .smarthost, .auth_password, .require_tls]')" \
  '["ops@example","portcullis@d.example","smtp.example:587","p'"'"'w\"d",true]'
expect_eq "alertmanager: smtp needs a recipient" "$(am ALERT_SMTP_SMARTHOST=smtp.example:587 | jq '.receivers[0] | has("email_configs")')" false

# shellcheck disable=SC2034  # read by metrics_textfile_write
MONITORING_TEXTFILE_DIR="$WORK/textfile"
printf 'x 1\n' | metrics_textfile_write test
expect_eq "textfile: written as <name>.prom" "$(cat "$WORK/textfile/test.prom")" "x 1"
expect_eq "textfile: world-readable" "$(file_mode "$WORK/textfile/test.prom")" 644
expect_eq "textfile: no temp file left" "$(find "$WORK/textfile" -name '.*' -type f | wc -l | tr -d ' ')" 0
expect_eq "metrics_label escapes" "$(metrics_label 'a"b\c')" 'a\"b\\c'

# ══ backup: manifest, layout, pruning (no Docker) ═════════
# shellcheck source=../scripts/lib/status.sh
source "$HERE/../scripts/lib/status.sh"
# shellcheck source=../scripts/lib/backup.sh
source "$HERE/../scripts/lib/backup.sh"
B="$WORK/backup"
mkdir -p "$B/secrets/vault-unseal" "$B/certs"
echo 'PORTCULLIS_DOMAIN=x' > "$B/.env"
echo '{"root_token":"r","unseal_keys_b64":["k"]}' > "$B/secrets/vault-init.json"
printf k > "$B/secrets/vault-unseal/unseal-key"
echo snap > "$B/vault.snap"; echo PGDMP > "$B/postgres.dump"; echo 'with space' > "$B/certs/a b.crt"
_BACKUP_CFG='{"services":{"hub":{"image":"hub:1"}}}'
_backup_manifest "$B"
expect_eq "manifest: format + every file" "$(jq -c '[.format, (.files | keys)]' "$B/MANIFEST.json")" \
  '[1,[".env","certs/a b.crt","postgres.dump","secrets/vault-init.json","secrets/vault-unseal/unseal-key","vault.snap"]]'
expect_eq "manifest: hub image recorded" "$(jq -r .hub_image "$B/MANIFEST.json")" hub:1
expect_ok "manifest: checksums verify" _backup_check_manifest "$B"
echo tampered >> "$B/postgres.dump"
expect_fail "manifest: a modified file fails" _backup_check_manifest "$B"
expect_ok "layout: complete backup accepted" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/monitoring.sh'; source '$HERE/../scripts/lib/backup.sh'; _backup_check_layout '$B'"
rm "$B/secrets/vault-unseal/unseal-key"
expect_fail "layout: missing unseal key rejected" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/monitoring.sh'; source '$HERE/../scripts/lib/backup.sh'; _backup_check_layout '$B'"

BACKUP_ROOT="$WORK/backups"
mkdir -p "$BACKUP_ROOT"/{20260101-000000,20260102-000000,20260103-000000,pre-restore-20260101-000000,offsite-20260101-000000,20260104-000000.partial}
BACKUP_KEEP_LOCAL=2 _backup_prune_local >/dev/null
expect_eq "prune: keeps the newest BACKUP_KEEP_LOCAL, leaves other dirs" "$(cd "$BACKUP_ROOT" && ls -1 | tr '\n' ' ')" \
  "20260102-000000 20260103-000000 20260104-000000.partial offsite-20260101-000000 pre-restore-20260101-000000 "
expect_eq "backup dirs: only timestamped ones" "$(_backup_dirs | tr '\n' ' ')" "20260102-000000 20260103-000000 "
expect_eq "restic creds: BACKUP_<NAME> wins" "$(AWS_ACCESS_KEY_ID=dns BACKUP_AWS_ACCESS_KEY_ID=bak _backup_cred AWS_ACCESS_KEY_ID)" bak
expect_eq "restic creds: falls back to <NAME>" "$(B2_ACCOUNT_ID=b2 _backup_cred B2_ACCOUNT_ID)" b2

# Vault snapshot check: a real-sized snapshot (meta.json first, then a large
# state.bin) under pipefail. `tar -t | grep -q` used to die of SIGPIPE here.
SNAPD="$WORK/snapsrc"; mkdir -p "$SNAPD" "$WORK/curlstub"
echo '{"Index":5}' > "$SNAPD/meta.json"
head -c 3000000 /dev/urandom > "$SNAPD/state.bin"
(cd "$SNAPD" && { sha256sum meta.json state.bin 2>/dev/null || shasum -a 256 meta.json state.bin; } > SHA256SUMS \
  && tar -czf "$WORK/good.snap" meta.json state.bin SHA256SUMS)
printf '<html>not a snapshot</html>' > "$WORK/bad.snap"
cat > "$WORK/curlstub/curl" <<'SH'
#!/bin/sh
# -o <file> → copy $SNAP_SRC there, print the status for -w.
while [ $# -gt 0 ]; do [ "$1" = -o ] && { cp "$SNAP_SRC" "$2"; shift; }; shift; done
printf 200
SH
chmod +x "$WORK/curlstub/curl"
snap_check() { (set -euo pipefail; PATH="$WORK/curlstub:$PATH" SNAP_SRC="$1" VAULT_TOKEN=t _backup_vault_snapshot "$WORK/out.snap"); }
for _ in 1 2 3; do expect_ok "backup: large raft snapshot accepted under pipefail" snap_check "$WORK/good.snap"; done
expect_fail "backup: non-snapshot body rejected" snap_check "$WORK/bad.snap"

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
