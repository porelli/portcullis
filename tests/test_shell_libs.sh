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
unset PORTCULLIS_DOMAIN VAULT_ADDR VAULT_TOKEN COMPOSE_FILE KEYCLOAK_URL DOCKER_HOST XDG_RUNTIME_DIR PORTCULLIS_ENGINE_SOCKET
# Every fixture is a Docker install (scripts/lib/runtime.sh: no default);
# the runtime tests below set their own.
export CONTAINER_RUNTIME=docker

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
file_mode()   { stat -c %a "$1" 2>/dev/null || { m="$(stat -f %Mp%Lp "$1")" && echo "${m#0}"; }; }
file_inode()  { stat -c %i "$1" 2>/dev/null || stat -f %i "$1"; }

# ── stubs ──────────────────────────────────────────────────
mkdir -p "$WORK/bin" "$WORK/stub"
# The engine's /version components (runtime_check): a Docker Engine.
cat > "$WORK/stub-version" <<'STUBV'
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
STUBV
export STUB_DIR="$WORK/stub"
# docker: only `network inspect` matters here ($STUB_DIR/ipam-json[-<network>] = IPAM).
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
# The engine's components (runtime_check): Docker Engine unless the test
# says otherwise. Not logged in calls.
if [ "$1" = version ] && [ "$3" = "{{json .Server.Components}}" ]; then
  echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0
fi
echo "$*" >> "$STUB_DIR/calls"
if [ "$1 $2" = "network inspect" ] && [ "$4" = "--format" ]; then
  if [ "$5" = "{{json .IPAM.Config}}" ]; then
    net="$3"
    if [ -f "$STUB_DIR/ipam-json-$net" ]; then cat "$STUB_DIR/ipam-json-$net"; exit 0; fi
    if [ -f "$STUB_DIR/ipam-json" ]; then cat "$STUB_DIR/ipam-json"; exit 0; fi
    exit 1
  fi
fi
exit 0
STUB
# vault: STUB_VAULT_RC / STUB_VAULT_OUT control `vault list` behaviour;
# calls on pki_file use STUB_VAULT_FILE_RC / STUB_VAULT_FILE_OUT when set.
cat > "$WORK/bin/vault" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_DIR/vault-calls"
case "$*" in
  *pki_file/*)
    if [ -n "${STUB_VAULT_FILE_RC:-}" ]; then
      printf '%s\n' "${STUB_VAULT_FILE_OUT:-}"
      exit "$STUB_VAULT_FILE_RC"
    fi ;;
esac
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
expect_ok   "hub env: an app variable by prefix (NETBIRD_)" grep -qx 'NETBIRD_OIDC_CLIENT_SECRET=nb-secret' "$HE"
expect_fail "hub env: no HEADSCALE_ / HEADPLANE_ prefix any more (core carries no Headscale)" grep -q '^HEADSCALE_\|^HEADPLANE_' "$HE"
expect_ok   "hub env: wg's portcullis-vpn address (compose default; the Hub's PORTCULLIS_VPN_EDGE for gateways)" \
  grep -qx 'PORTCULLIS_VPN_WG_IP=172.31.254.3' "$HE"
expect_ok   "hub env: the VPN reserved ranges (what wg / group-gate refuse) for the Hub" \
  grep -qx 'PORTCULLIS_VPN_RESERVED_RANGES=172.16.0.0/12 192.168.0.0/16 10.214.0.0/24 172.31.250.0/24 172.31.251.0/28 172.31.252.0/28 172.31.253.0/28 172.31.254.0/26 172.31.254.64/28 172.31.255.16/28 172.31.254.80/29 172.31.254.128/26' "$HE"
expect_ok   "hub env: HUB_SHARED_ENV" grep -qx 'MY_APP_VAR=shared' "$HE"
expect_ok   "hub env: mcp-gate IP (compose default, G42)" grep -qx 'PORTCULLIS_MCP_GATE_IP=172.31.250.3' "$HE"
expect_fail "hub env: never a core secret" grep -Eq 'pg-secret|hub-secret|kc-secret' "$HE"
expect_eq "hub env: the slot closed, the derived mail keys" \
  "$(grep -E '^PORTCULLIS_MAIL' "$HE" | tr '\n' ' ')" \
  "PORTCULLIS_MAIL=off PORTCULLIS_MAIL_HOSTNAME=mail.hub.test PORTCULLIS_MAIL_SUBMISSION_LAN_ONLY=false PORTCULLIS_MAIL_CLIENT_IP=preserved PORTCULLIS_MAIL_API_SUBNET=172.31.255.16/28 PORTCULLIS_MAIL_API_HUB_IP=172.31.255.18 PORTCULLIS_MAIL_API_PROVIDER_IP=172.31.255.19 PORTCULLIS_MAIL_PUBLIC_IPV4= PORTCULLIS_MAIL_PUBLIC_IPV6= "
# M2 (final cross review): the server's detected public addresses
# (domains' public-ips.env) reach the Hub for the provider's PTR /
# blocklist checks.
mkdir -p "$HR/secrets/domains" && printf 'DOMAINS_PUBLIC_IPV4=203.0.113.7\nDOMAINS_PUBLIC_IPV6=2001:db8::7\nDOMAINS_MAIL=\n' > "$HR/secrets/domains/public-ips.env"
( PORTCULLIS_ROOT="$HR"; export PORTCULLIS_MAIL=on MAIL_HOSTNAME=mx.hub.test MAIL_SUBMISSION_LAN_ONLY=true PORTCULLIS_MAIL_API_SUBNET=10.87.0.0/28 PORTCULLIS_MAIL_API_HUB_IP=10.87.0.2 PORTCULLIS_MAIL_API_PROVIDER_IP=10.87.0.3
  unset PORTCULLIS_DOMAIN; env_load; hub_env_write 2>/dev/null )
expect_eq "hub env: the slot open (exactly on), hostname, LAN-only, the API network's addresses, the public addresses" \
  "$(grep -E '^PORTCULLIS_MAIL' "$HE" | tr '\n' ' ')" \
  "PORTCULLIS_MAIL=on PORTCULLIS_MAIL_HOSTNAME=mx.hub.test PORTCULLIS_MAIL_SUBMISSION_LAN_ONLY=true PORTCULLIS_MAIL_CLIENT_IP=preserved PORTCULLIS_MAIL_API_SUBNET=10.87.0.0/28 PORTCULLIS_MAIL_API_HUB_IP=10.87.0.2 PORTCULLIS_MAIL_API_PROVIDER_IP=10.87.0.3 PORTCULLIS_MAIL_PUBLIC_IPV4=203.0.113.7 PORTCULLIS_MAIL_PUBLIC_IPV6=2001:db8::7 "
rm -f "$HR/secrets/domains/public-ips.env"
( PORTCULLIS_ROOT="$HR"; export PORTCULLIS_MAIL=yes; unset PORTCULLIS_DOMAIN; env_load; hub_env_write 2>/dev/null )
expect_ok "hub env: PORTCULLIS_MAIL other than on is off" grep -qx 'PORTCULLIS_MAIL=off' "$HE"
rm -rf "$HR/secrets/mail"; hub_env_run
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

# ── stack_prepare: appfiles/ (the Hub's settings data files, contract §13.7) ──
SP_ROOT="$WORK/sp-root"
mkdir -p "$SP_ROOT"
rm -f "$STUB_DIR/calls"
( PORTCULLIS_ROOT="$SP_ROOT"
  volume_own() { :; }; hub_env_write() { :; }; secrets_fix_perms() { :; }
  unset -f users_secret_files monitoring_prepare domains_prepare
  stack_prepare ) >/dev/null 2>&1
expect_ok "stack_prepare: creates appfiles/" test -d "$SP_ROOT/appfiles"
expect_eq "stack_prepare: appfiles/ is 0750" "$(file_mode "$SP_ROOT/appfiles")" 750
expect_ok "stack_prepare: appfiles/ chowned to the Hub (10001)" \
  grep -q "src=$SP_ROOT/appfiles,dst=/t/0 .* chown 10001:10001 /t/0\$" "$STUB_DIR/calls"
# A Hub-owned (or already chowned) appfiles/ is left alone: no chmod as us.
chmod 700 "$SP_ROOT/appfiles"
( PORTCULLIS_ROOT="$SP_ROOT"; _owner_of() { echo 10001:10001; }
  volume_own() { :; }; hub_env_write() { :; }; secrets_fix_perms() { :; }
  unset -f users_secret_files monitoring_prepare domains_prepare
  stack_prepare ) >/dev/null 2>&1
expect_eq "stack_prepare: a 10001-owned appfiles/ keeps its mode" "$(file_mode "$SP_ROOT/appfiles")" 700
# mcp_gate_data: the gate (10005) writes it, the Hub reads it (group 10001);
# whichever container starts first creates the volume, so it is created and
# owned before compose runs. The gate's secrets come with every prepare.
( PORTCULLIS_ROOT="$SP_ROOT"
  volume_own() { echo "volume_own $*" >> "$STUB_DIR/sp-vol"; }; hub_env_write() { :; }; secrets_fix_perms() { :; }
  mcpgate_ensure_secrets() { echo "mcpgate_ensure_secrets" >> "$STUB_DIR/sp-vol"; }
  unset -f users_secret_files monitoring_prepare domains_prepare
  stack_prepare ) >/dev/null 2>&1
expect_ok "stack_prepare: mcp_gate_data owned 10005:10001" grep -qx 'volume_own mcp_gate_data 10005:10001' "$STUB_DIR/sp-vol"
expect_ok "stack_prepare: mcp-gate secrets ensured" grep -qx 'mcpgate_ensure_secrets' "$STUB_DIR/sp-vol"
# wg_data (VPN, V5): wg (10006) writes status.json, the Hub reads it
# through group 10001; setgid 2750 so new files carry 10001.
expect_ok "stack_prepare: wg_data owned 10006:10001, mode 2750" grep -qx 'volume_own wg_data 10006:10001 2750' "$STUB_DIR/sp-vol"
# vpn_doc (security ruling): the Hub writes vpn.json there, wg and
# group-gate read it through group 10007 only (not the Hub's 10001).
expect_ok "stack_prepare: vpn_doc owned 10001:10007, mode 2750" grep -qx 'volume_own vpn_doc 10001:10007 2750' "$STUB_DIR/sp-vol"
# secrets/wg/people.key: an empty placeholder (people role off) so the
# bind never makes a directory and the SELinux overlay's source exists.
expect_ok "stack_prepare: secrets/wg/people.key is an empty file" bash -c "[ -f '$SP_ROOT/secrets/wg/people.key' ] && [ ! -s '$SP_ROOT/secrets/wg/people.key' ]"
expect_eq "stack_prepare: people.key placeholder 0640" "$(file_mode "$SP_ROOT/secrets/wg/people.key")" 640
printf 'KEY\n' > "$SP_ROOT/secrets/wg/people.key"
( PORTCULLIS_ROOT="$SP_ROOT"
  volume_own() { :; }; hub_env_write() { :; }; secrets_fix_perms() { :; }
  unset -f users_secret_files monitoring_prepare domains_prepare
  stack_prepare ) >/dev/null 2>&1
expect_eq "stack_prepare: an existing people.key is kept" "$(cat "$SP_ROOT/secrets/wg/people.key")" KEY
( PORTCULLIS_ROOT="$SP_ROOT"
  ct_group_read() { echo "ct_group_read $*" >> "$STUB_DIR/sfp-wg"; }
  unset -f monitoring_fix_perms domains_fix_perms mcpgate_fix_perms sessions_fix_perms
  secrets_fix_perms ) >/dev/null 2>&1
expect_ok "secrets_fix_perms: secrets/wg and people.key group 10006" \
  grep -qx "ct_group_read 10006 $SP_ROOT/secrets/wg $SP_ROOT/secrets/wg/people.key $SP_ROOT/secrets/wg/link.key $SP_ROOT/secrets/wg/link-tls.key $SP_ROOT/secrets/wg/link-tls.crt" "$STUB_DIR/sfp-wg"
# test_mail_slot_prepared_setgid (contract §19.1, P6): mail_slot always,
# 10001:65534 2750 (setgid: the Hub's files carry Prometheus' group);
# mail_tls 10004:2000 2750 and mail_acme 10004:10004 0700 only with the slot
# open (PORTCULLIS_MAIL exactly on). secrets/mail/ 0700, no secret in it.
expect_ok "stack_prepare: mail_slot owned 10001:65534, mode 2750 (setgid)" grep -qx 'volume_own mail_slot 10001:65534 2750' "$STUB_DIR/sp-vol"
expect_ok "stack_prepare: mail_provider_slot owned 10001:2000, mode 2750, also with the slot closed (R-POD2)" grep -qx 'volume_own mail_provider_slot 10001:2000 2750' "$STUB_DIR/sp-vol"
expect_fail "stack_prepare: no mail_tls / mail_acme with the slot closed" grep -qE '^volume_own mail_(tls|acme) ' "$STUB_DIR/sp-vol"
expect_eq "stack_prepare: secrets/mail is 0700 and holds no secret" "$(file_mode "$SP_ROOT/secrets/mail"):$(find "$SP_ROOT/secrets/mail" -type f | wc -l | tr -d ' ')" 700:0
for v in yes On 1; do
  rm -f "$STUB_DIR/sp-vol"
  ( PORTCULLIS_ROOT="$SP_ROOT"; export PORTCULLIS_MAIL="$v"
    volume_own() { echo "volume_own $*" >> "$STUB_DIR/sp-vol"; }; hub_env_write() { :; }; secrets_fix_perms() { :; }
    unset -f users_secret_files monitoring_prepare domains_prepare mcpgate_ensure_secrets
    stack_prepare ) >/dev/null 2>&1
  expect_fail "stack_prepare: PORTCULLIS_MAIL=$v doesn't open the slot (exactly on)" grep -qE '^volume_own mail_(tls|acme) ' "$STUB_DIR/sp-vol"
done
rm -f "$STUB_DIR/sp-vol"
( PORTCULLIS_ROOT="$SP_ROOT"; export PORTCULLIS_MAIL=on
  volume_own() { echo "volume_own $*" >> "$STUB_DIR/sp-vol"; }; hub_env_write() { :; }; secrets_fix_perms() { :; }
  docker() { echo "docker $*" >> "$STUB_DIR/sp-net"; [ "$1 $2" != "network inspect" ]; }
  unset -f users_secret_files monitoring_prepare domains_prepare mcpgate_ensure_secrets
  stack_prepare ) >/dev/null 2>&1
expect_eq "stack_prepare: with the slot open, the slot and mail-cert's volumes (owners, modes)" "$(grep '^volume_own mail' "$STUB_DIR/sp-vol" | sort | tr '\n' '|')" \
  "volume_own mail_acme 10004:10004 0700|volume_own mail_provider_slot 10001:2000 2750|volume_own mail_slot 10001:65534 2750|volume_own mail_tls 10004:2000 2750|"
expect_eq "stack_prepare with the slot open: portcullis-metrics-mail made (internal, compose's labels) when missing" \
  "$(grep -c '^docker network create --internal --label com.docker.compose.project=portcullis --label com.docker.compose.network=portcullis-metrics-mail portcullis-metrics-mail$' "$STUB_DIR/sp-net" 2>/dev/null)" 1
expect_eq "CT_GID_MAIL_PROVIDER is 2000" "$CT_GID_MAIL_PROVIDER" 2000
# group_gate_data (sign-in part 2, contract §4 "Opened log"): group-gate
# (10003) writes the opened log, the Hub (group 10001) reads and prunes it.
expect_ok "the stack's volume setup owns group_gate_data 10003:10001" grep -qx 'volume_own group_gate_data 10003:10001' "$STUB_DIR/sp-vol"
# group-gate bind-mounts both CA files: files (empty until pki setup), never
# directories Docker would make; a directory is refused.
expect_eq "stack_prepare: the two CA files exist as empty 0644 files before pki setup" \
  "$(for f in yubikey-ca.crt browser-ca.crt; do [ -f "$SP_ROOT/certs/$f" ] && [ ! -s "$SP_ROOT/certs/$f" ] && file_mode "$SP_ROOT/certs/$f"; done | tr '\n' ' ')" "644 644 "
printf 'pem\n' > "$SP_ROOT/certs/yubikey-ca.crt"
( PORTCULLIS_ROOT="$SP_ROOT"
  volume_own() { :; }; hub_env_write() { :; }; secrets_fix_perms() { :; }
  unset -f users_secret_files monitoring_prepare domains_prepare
  stack_prepare ) >/dev/null 2>&1
expect_eq "stack_prepare: an existing CA file is kept" "$(cat "$SP_ROOT/certs/yubikey-ca.crt")" pem
rm -f "$SP_ROOT/certs/browser-ca.crt"; mkdir "$SP_ROOT/certs/browser-ca.crt"
rc=0; ( PORTCULLIS_ROOT="$SP_ROOT"
  volume_own() { :; }; hub_env_write() { :; }; secrets_fix_perms() { :; }
  unset -f users_secret_files monitoring_prepare domains_prepare
  stack_prepare ) >/dev/null 2>&1 || rc=$?
expect_eq "stack_prepare: a CA file Docker made a directory is refused" "$rc" 1
rmdir "$SP_ROOT/certs/browser-ca.crt"
rm -f "$STUB_DIR/sp-vol"
rm -f "$STUB_DIR/calls"

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
rm -f "$STUB_DIR/ipam-json"
expect_eq "state missing" "$(proxy_network_state)" missing
expect_ok "guard: missing network is fine" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
printf '%s' '[{"Subnet":"172.31.250.0/24","IPRange":"172.31.250.128/25"}]' > "$STUB_DIR/ipam-json"
expect_eq "state ok" "$(proxy_network_state)" ok
printf '%s' '[{"Subnet":"172.18.0.0/16"}]' > "$STUB_DIR/ipam-json"
expect_eq "state mismatch (docker-assigned subnet)" "$(proxy_network_state)" mismatch
printf '%s' '[{"Subnet":"172.31.250.0/24"}]' > "$STUB_DIR/ipam-json"
expect_eq "state mismatch (no ip_range)" "$(proxy_network_state)" mismatch
expect_fail "guard: mismatch aborts" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
expect_fail "guard: invalid auth config aborts" bash -c "rm -f '$STUB_DIR/ipam-json'; PORTCULLIS_AUTH_TRAEFIK_IP=172.31.251.9; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
expect_fail "guard: invalid config aborts" bash -c "PORTCULLIS_TRAEFIK_IP=1.2.3.4; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
# Docker 29.9.2: "invalid Prefix" for unset IPRange should be treated as no range.
printf '%s' '[{"Subnet":"172.31.250.0/24","IPRange":"invalid Prefix"}]' > "$STUB_DIR/ipam-json"
expect_eq "state mismatch (Docker 29 invalid Prefix)" "$(proxy_network_state)" mismatch
# portcullis-domains (final review M2): valid, no overlap, existing IPAM.
# Clean up proxy/auth network stubs so network_check passes with just domains.
rm -f "$STUB_DIR/ipam-json"
unset PORTCULLIS_DOMAINS_SUBNET
expect_ok "domains net: default valid" validate_domains_network_config
check_dom() { PORTCULLIS_DOMAINS_SUBNET="$1" validate_domains_network_config; }
expect_ok   "domains net: custom valid"            check_dom 10.97.0.0/28
expect_fail "domains net: invalid CIDR"            check_dom 10.97.0.0/40
expect_fail "domains net: overlaps portcullis-proxy" check_dom 172.31.250.16/28
expect_fail "domains net: overlaps portcullis-auth"  check_dom 172.31.251.0/29
expect_fail "domains net: too small"               check_dom 10.97.0.0/31
rm -f "$STUB_DIR/ipam-json-portcullis_portcullis-domains"
printf '%s' '[{"Subnet":"172.31.252.0/28"}]' > "$STUB_DIR/ipam-json-portcullis_portcullis-domains"
expect_eq "domains net: state ok" "$(domains_network_state)" ok
expect_ok "guard: domains network matching" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
# Docker 29.9.2: "invalid Prefix" for unset IPRange should match empty range.
printf '%s' '[{"Subnet":"172.31.252.0/28","IPRange":"invalid Prefix"}]' > "$STUB_DIR/ipam-json-portcullis_portcullis-domains"
expect_eq "domains net: state ok (Docker 29 invalid Prefix)" "$(domains_network_state)" ok
printf '%s' '[{"Subnet":"172.18.5.0/28"}]' > "$STUB_DIR/ipam-json-portcullis_portcullis-domains"
expect_fail "guard: domains network mismatch aborts" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
expect_fail "guard: invalid domains subnet aborts" bash -c "rm -f '$STUB_DIR/ipam-json-portcullis_portcullis-domains'; PORTCULLIS_DOMAINS_SUBNET=172.31.250.0/28; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
rm -f "$STUB_DIR/ipam-json-portcullis_portcullis-domains"
# mcp-gate's pinned address on portcullis-proxy (contract §2 PORTCULLIS_MCP_GATE_IP).
unset PORTCULLIS_MCP_GATE_IP
expect_eq "mcp-gate IP: default" "$(mcp_gate_ip)" 172.31.250.3
expect_ok "mcp-gate IP: default valid" validate_mcp_gate_ip
check_gate() { PORTCULLIS_MCP_GATE_IP="$1" validate_mcp_gate_ip; }
expect_ok   "mcp-gate IP: another static address"           check_gate 172.31.250.40
expect_fail "mcp-gate IP: inside the dynamic range"         check_gate 172.31.250.200
expect_fail "mcp-gate IP: outside the subnet"               check_gate 172.31.251.3
expect_fail "mcp-gate IP: equal to Traefik's"               check_gate 172.31.250.2
expect_fail "mcp-gate IP: the gateway"                      check_gate 172.31.250.1
expect_fail "mcp-gate IP: the broadcast address"            check_gate 172.31.250.255
expect_fail "mcp-gate IP: not an address"                   check_gate 172.31.250
expect_fail "mcp-gate IP: equal to a custom Traefik IP" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; PORTCULLIS_TRAEFIK_IP=172.31.250.9 PORTCULLIS_MCP_GATE_IP=172.31.250.9 validate_mcp_gate_ip"
expect_fail "guard: mcp-gate IP in the dynamic range aborts" bash -c "PORTCULLIS_MCP_GATE_IP=172.31.250.130; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
expect_fail "guard: mcp-gate IP = Traefik's aborts" bash -c "PORTCULLIS_MCP_GATE_IP=172.31.250.2; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
expect_fail "guard: mcp-gate IP outside the subnet aborts" bash -c "PORTCULLIS_MCP_GATE_IP=10.0.0.3; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
expect_ok "guard: default mcp-gate IP passes" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
# portcullis-mcp (fix round 1): mcp-gate ⇄ Keycloak / the Hub only, fixed
# IPAM with Keycloak and the Hub pinned (the gate maps both names to them).
unset PORTCULLIS_MCP_SUBNET PORTCULLIS_MCP_IP_RANGE PORTCULLIS_MCP_KEYCLOAK_IP PORTCULLIS_MCP_HUB_IP
expect_eq "mcp net: defaults" "$(mcp_subnet) $(mcp_ip_range) $(mcp_keycloak_ip) $(mcp_hub_ip)" "172.31.253.0/28 172.31.253.8/29 172.31.253.2 172.31.253.3"
expect_ok "mcp net: default valid" validate_mcp_network_config
check_mnet() { PORTCULLIS_MCP_SUBNET="$1" PORTCULLIS_MCP_IP_RANGE="$2" PORTCULLIS_MCP_KEYCLOAK_IP="$3" PORTCULLIS_MCP_HUB_IP="$4" validate_mcp_network_config; }
expect_ok   "mcp net: custom valid"                  check_mnet 10.96.0.0/28 10.96.0.8/29 10.96.0.2 10.96.0.3
expect_fail "mcp net: invalid CIDR"                  check_mnet 10.96.0.0/33 10.96.0.8/29 10.96.0.2 10.96.0.3
expect_fail "mcp net: range outside the subnet"      check_mnet 10.96.0.0/28 10.96.1.8/29 10.96.0.2 10.96.0.3
expect_fail "mcp net: Keycloak IP in the range"      check_mnet 10.96.0.0/28 10.96.0.8/29 10.96.0.9 10.96.0.3
expect_fail "mcp net: Hub IP outside the subnet"     check_mnet 10.96.0.0/28 10.96.0.8/29 10.96.0.2 10.96.1.3
expect_fail "mcp net: Hub IP = the gateway"          check_mnet 10.96.0.0/28 10.96.0.8/29 10.96.0.2 10.96.0.1
expect_fail "mcp net: Keycloak and the Hub share an IP" check_mnet 10.96.0.0/28 10.96.0.8/29 10.96.0.2 10.96.0.2
expect_fail "mcp net: overlaps portcullis-proxy"     check_mnet 172.31.250.32/28 172.31.250.40/29 172.31.250.34 172.31.250.35
expect_fail "mcp net: overlaps portcullis-auth"      check_mnet 172.31.251.0/28 172.31.251.8/29 172.31.251.3 172.31.251.4
expect_fail "mcp net: overlaps portcullis-domains"   check_mnet 172.31.252.0/28 172.31.252.8/29 172.31.252.2 172.31.252.3
printf '%s' '[{"Subnet":"172.31.253.0/28","IPRange":"172.31.253.8/29"}]' > "$STUB_DIR/ipam-json-portcullis-mcp"
expect_eq "mcp net: state ok" "$(mcp_network_state)" ok
expect_ok "guard: mcp network matching" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
printf '%s' '[{"Subnet":"172.31.253.0/28"}]' > "$STUB_DIR/ipam-json-portcullis-mcp"
expect_fail "guard: mcp network without its range aborts" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
rm -f "$STUB_DIR/ipam-json-portcullis-mcp"
expect_fail "guard: invalid mcp settings abort" bash -c "PORTCULLIS_MCP_HUB_IP=172.31.253.9; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
# portcullis-vpn (contract §16): wg's edge ports, pinned outside the
# dynamic range; the Hub's gateway window .16–.62 outside both; a /26 at
# least; no overlap with the other fixed core networks. Traefik isn't on it.
unset PORTCULLIS_VPN_NET PORTCULLIS_VPN_IP_RANGE PORTCULLIS_VPN_WG_IP
expect_eq "vpn net: defaults" "$(vpn_net) $(vpn_ip_range) $(vpn_wg_ip)" "172.31.254.0/26 172.31.254.8/29 172.31.254.3"
expect_ok "vpn net: default valid" validate_vpn_network_config
check_vnet() { PORTCULLIS_VPN_NET="$1" PORTCULLIS_VPN_IP_RANGE="$2" PORTCULLIS_VPN_WG_IP="$3" validate_vpn_network_config; }
expect_ok   "vpn net: custom valid"                         check_vnet 10.97.0.0/26 10.97.0.8/29 10.97.0.3
expect_ok   "vpn net: a /24 is fine"                        check_vnet 10.97.0.0/24 10.97.0.8/29 10.97.0.3
expect_fail "validate_vpn_network_config: wg ip outside the subnet → fail" check_vnet 10.97.0.0/26 10.97.0.8/29 10.97.1.3
expect_fail "validate_vpn_network_config: wg ip inside the ip_range → fail" check_vnet 10.97.0.0/26 10.97.0.8/29 10.97.0.9
expect_fail "validate_vpn_network_config: overlap with the proxy subnet → fail" check_vnet 172.31.250.0/26 172.31.250.8/29 172.31.250.3
expect_fail "vpn net: overlaps portcullis-auth"             check_vnet 172.31.251.0/26 172.31.251.8/29 172.31.251.5
expect_fail "vpn net: overlaps portcullis-domains"          check_vnet 172.31.252.0/26 172.31.252.8/29 172.31.252.5
expect_fail "vpn net: overlaps portcullis-mcp"              check_vnet 172.31.253.0/26 172.31.253.8/29 172.31.253.5
expect_fail "vpn net: overlaps portcullis-vpn-edge"         check_vnet 172.31.254.64/26 172.31.254.72/29 172.31.254.67
expect_fail "vpn net: smaller than a /26"                   check_vnet 10.97.0.0/27 10.97.0.8/29 10.97.0.3
expect_fail "vpn net: wg = the gateway"                     check_vnet 10.97.0.0/26 10.97.0.8/29 10.97.0.1
expect_fail "vpn net: the range reaches the gateway window" check_vnet 10.97.0.0/26 10.97.0.16/29 10.97.0.3
expect_fail "vpn net: wg inside the gateway window"         check_vnet 10.97.0.0/26 10.97.0.8/29 10.97.0.20
expect_fail "vpn net: invalid CIDR"                         check_vnet 10.97.0.0/33 10.97.0.8/29 10.97.0.3
# portcullis-vpn-edge (security ruling): exactly wg and Traefik, internal,
# pinned outside the dynamic range, apart; vpnsecure trusts PROXY from wg's
# address here only. No overlap with any other fixed core network.
unset PORTCULLIS_VPN_EDGE_SUBNET PORTCULLIS_VPN_EDGE_IP_RANGE PORTCULLIS_VPN_EDGE_TRAEFIK_IP PORTCULLIS_VPN_EDGE_WG_IP
expect_eq "vpn edge net: defaults" "$(vpn_edge_subnet) $(vpn_edge_ip_range) $(vpn_edge_traefik_ip) $(vpn_edge_wg_ip)" "172.31.254.64/28 172.31.254.72/29 172.31.254.66 172.31.254.67"
expect_ok "vpn edge net: default valid" validate_vpn_edge_network_config
check_enet() { PORTCULLIS_VPN_EDGE_SUBNET="$1" PORTCULLIS_VPN_EDGE_IP_RANGE="$2" PORTCULLIS_VPN_EDGE_TRAEFIK_IP="$3" PORTCULLIS_VPN_EDGE_WG_IP="$4" validate_vpn_edge_network_config; }
expect_ok   "vpn edge net: custom valid"                   check_enet 10.98.0.0/28 10.98.0.8/29 10.98.0.2 10.98.0.3
expect_fail "vpn edge net: wg outside the subnet"          check_enet 10.98.0.0/28 10.98.0.8/29 10.98.0.2 10.98.1.3
expect_fail "vpn edge net: Traefik in the dynamic range"   check_enet 10.98.0.0/28 10.98.0.8/29 10.98.0.9 10.98.0.3
expect_fail "vpn edge net: Traefik and wg share an address" check_enet 10.98.0.0/28 10.98.0.8/29 10.98.0.2 10.98.0.2
expect_fail "vpn edge net: overlaps portcullis-vpn"        check_enet 172.31.254.0/28 172.31.254.8/29 172.31.254.2 172.31.254.3
expect_fail "vpn edge net: overlaps portcullis-proxy"      check_enet 172.31.250.0/28 172.31.250.8/29 172.31.250.4 172.31.250.5
expect_fail "vpn edge net: overlaps portcullis-mcp"        check_enet 172.31.253.0/28 172.31.253.8/29 172.31.253.4 172.31.253.5
expect_fail "vpn edge net: invalid CIDR"                   check_enet 10.98.0.0/33 10.98.0.8/29 10.98.0.2 10.98.0.3
printf '%s' '[{"Subnet":"172.31.254.0/26","IPRange":"172.31.254.8/29"}]' > "$STUB_DIR/ipam-json-portcullis-vpn"
printf '%s' '[{"Subnet":"172.31.254.64/28","IPRange":"172.31.254.72/29"}]' > "$STUB_DIR/ipam-json-portcullis-vpn-edge"
expect_eq "vpn net: state ok" "$(vpn_network_state)" ok
expect_eq "vpn edge net: state ok" "$(vpn_edge_network_state)" ok
expect_ok "guard: vpn networks matching" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
printf '%s' '[{"Subnet":"172.31.254.0/24","IPRange":"172.31.254.8/29"}]' > "$STUB_DIR/ipam-json-portcullis-vpn"
expect_fail "guard: vpn network mismatch aborts" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
printf '%s' '[{"Subnet":"172.31.254.0/26","IPRange":"172.31.254.8/29"}]' > "$STUB_DIR/ipam-json-portcullis-vpn"
printf '%s' '[{"Subnet":"172.31.254.64/28"}]' > "$STUB_DIR/ipam-json-portcullis-vpn-edge"
expect_fail "guard: vpn edge network mismatch aborts" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
rm -f "$STUB_DIR/ipam-json-portcullis-vpn" "$STUB_DIR/ipam-json-portcullis-vpn-edge"
expect_fail "guard: invalid vpn settings abort" bash -c "PORTCULLIS_VPN_WG_IP=172.31.254.9; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
expect_fail "guard: invalid vpn edge settings abort" bash -c "PORTCULLIS_VPN_EDGE_WG_IP=172.31.254.66; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
expect_ok "CORE_SERVICE_NAMES has wg" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; case \" \$CORE_SERVICE_NAMES \" in *' wg '*) exit 0;; esac; exit 1"
# ── the mail slot's API network (contract §19.1): portcullis-mail-api, the
# Hub and the provider pinned. Validated always (the Hub joins it with or
# without a provider).
unset PORTCULLIS_MAIL_API_SUBNET PORTCULLIS_MAIL_API_IP_RANGE PORTCULLIS_MAIL_API_HUB_IP PORTCULLIS_MAIL_API_PROVIDER_IP
expect_eq "mail-api net: defaults" "$(mail_api_subnet) $(mail_api_ip_range) $(mail_api_hub_ip) $(mail_api_provider_ip)" \
  "172.31.255.16/28 172.31.255.24/29 172.31.255.18 172.31.255.19"
expect_ok "mail-api net: default valid" validate_mail_network_config
check_mailnet() { (for a in "$@"; do export "${a?}"; done; validate_mail_network_config); }
expect_ok   "mail-api net: moved, valid" check_mailnet PORTCULLIS_MAIL_API_SUBNET=10.87.0.0/28 PORTCULLIS_MAIL_API_IP_RANGE=10.87.0.8/29 PORTCULLIS_MAIL_API_HUB_IP=10.87.0.2 PORTCULLIS_MAIL_API_PROVIDER_IP=10.87.0.3
expect_fail "validate_mail_network_config refuses a subnet that doesn't parse" check_mailnet PORTCULLIS_MAIL_API_SUBNET=172.31.255.16/33
expect_fail "validate_mail_network_config refuses a range outside the subnet" check_mailnet PORTCULLIS_MAIL_API_IP_RANGE=172.31.254.24/29
expect_fail "validate_mail_network_config refuses a pinned address outside the subnet" check_mailnet PORTCULLIS_MAIL_API_PROVIDER_IP=172.31.255.40
expect_fail "validate_mail_network_config refuses a pinned address in the range" check_mailnet PORTCULLIS_MAIL_API_HUB_IP=172.31.255.25
expect_fail "validate_mail_network_config refuses the gateway address" check_mailnet PORTCULLIS_MAIL_API_PROVIDER_IP=172.31.255.17
expect_fail "validate_mail_network_config refuses the broadcast address" check_mailnet PORTCULLIS_MAIL_API_HUB_IP=172.31.255.31
expect_fail "validate_mail_network_config refuses the Hub and the provider on one address" check_mailnet PORTCULLIS_MAIL_API_PROVIDER_IP=172.31.255.18
expect_fail "validate_mail_network_config refuses an overlap with portcullis-mcp" check_mailnet PORTCULLIS_MAIL_API_SUBNET=172.31.253.0/28 PORTCULLIS_MAIL_API_IP_RANGE=172.31.253.8/29 PORTCULLIS_MAIL_API_HUB_IP=172.31.253.4 PORTCULLIS_MAIL_API_PROVIDER_IP=172.31.253.5
expect_eq "vpn_reserved_ranges includes the mail-api subnet once" "$(vpn_reserved_ranges | tr ' ' '\n' | grep -c '^172\.31\.255\.')" 1
printf '%s' '[{"Subnet":"172.31.255.16/28","IPRange":"172.31.255.24/29"}]' > "$STUB_DIR/ipam-json-portcullis-mail-api"
expect_eq "mail-api net: state ok" "$(mail_api_network_state)" ok
expect_ok "guard: the mail-api network matching" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
printf '%s' '[{"Subnet":"172.31.255.16/27","IPRange":"172.31.255.24/29"}]' > "$STUB_DIR/ipam-json-portcullis-mail-api"
expect_fail "guard: a portcullis-mail-api mismatch aborts" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
rm -f "$STUB_DIR/ipam-json-portcullis-mail-api"
expect_fail "guard: invalid mail-api settings abort" bash -c "PORTCULLIS_MAIL_API_HUB_IP=172.31.250.2; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
expect_ok "no mail server in CORE_SERVICE_NAMES / CORE_PROXY_SERVICES (mail-cert stays)" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; for s in mail mailctl mail-resolver; do case \" \$CORE_SERVICE_NAMES \$CORE_PROXY_SERVICES \" in *\" \$s \"*) exit 1;; esac; done; case \" \$CORE_SERVICE_NAMES \" in *' mail-cert '*) ;; *) exit 1;; esac"

# The gate never resolves keycloak / hub through DNS: compose maps both
# names to the pinned addresses (extra_hosts) where they are pinned.
CF="$HERE/../docker-compose.yml"
expect_ok "compose: the gate maps keycloak and hub to their pinned portcullis-mcp addresses" \
  bash -c "grep -qF -- '- \"keycloak:\${PORTCULLIS_MCP_KEYCLOAK_IP:-172.31.253.2}\"' '$CF' && grep -qF -- '- \"hub:\${PORTCULLIS_MCP_HUB_IP:-172.31.253.3}\"' '$CF'"
expect_eq "compose: keycloak and the hub pinned on portcullis-mcp with the same variables" \
  "$(grep -cE 'ipv4_address: \$\{PORTCULLIS_MCP_(KEYCLOAK|HUB)_IP:-172\.31\.253\.[23]\}' "$CF")" 2

# DNS shadowing on portcullis-proxy (fix round 1, re-ruled): only the
# containers `docker compose ps` lists for the core project are core, and
# each may answer only to its own service, which must be a portcullis-proxy
# member (CORE_PROXY_SERVICES). Anything else answering to a core name — or
# claiming a core service label or container name — is flagged; any
# inspection error fails closed. network_check (init / up / upgrade /
# restore) refuses, status fails.
mkdir -p "$WORK/dnsbin" "$STUB_DIR/dns"
cat > "$WORK/dnsbin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
if [ "$1 $2" = "network inspect" ]; then
  case "$5" in
    "{{range"*) [ -f "$STUB_DIR/dns/net-fail" ] && exit 1; [ -f "$STUB_DIR/dns/ids" ] && cat "$STUB_DIR/dns/ids"; exit 0 ;;
    *) exit 1 ;;
  esac
fi
if [ "$1 $2" = "network ls" ]; then [ -f "$STUB_DIR/dns/net-listed" ] && echo portcullis-proxy; exit 0; fi
if [ "$1" = compose ]; then
  echo "$*" >> "$STUB_DIR/dns/compose-calls"
  [ -f "$STUB_DIR/dns/compose-fail" ] && exit 1
  # An instance project (the AI companion check): its own id list.
  if [ "$2" = -p ] && [ "$3" != portcullis ]; then
    [ "$*" = "compose -p $3 ps -aq" ] || exit 1
    [ "$PWD" = / ] || exit 1   # run outside any compose file
    [ -f "$STUB_DIR/dns/proj-fail" ] && exit 1
    cat "$STUB_DIR/dns/proj-$3" 2>/dev/null; exit 0
  fi
  case "$*" in *" ps -aq") cat "$STUB_DIR/dns/core-ids" 2>/dev/null; exit 0 ;; esac
  exit 1
fi
if [ "$1" = run ]; then   # the hub_data reader: its last argument is the override path
  echo "$*" >> "$STUB_DIR/dns/run-calls"
  [ -f "$STUB_DIR/dns/run-fail" ] && exit 1
  f="$STUB_DIR/dns/override-$(basename "${*: -1}" .override.yml)"
  [ -f "$f" ] || exit 3
  cat "$f"; exit 0
fi
if [ "$1" = inspect ] && [ "$2" = --format ]; then
  [ -f "$STUB_DIR/dns/$4.json" ] || exit 1
  cat "$STUB_DIR/dns/$4.json"; exit 0
fi
exit 0
STUB
chmod +x "$WORK/dnsbin/docker"
ctr() { # ctr <id> <name> <project> <service> <hostname> <aliases-json> [dnsnames-json] [config_files]
  jq -n --arg n "/$2" --arg p "$3" --arg s "$4" --arg h "$5" --argjson a "$6" --argjson d "${7:-[]}" --arg cf "${8:-}" \
    '{Name: $n, Config: {Hostname: $h, Labels: ({"com.docker.compose.project": $p, "com.docker.compose.service": $s, "com.docker.compose.project.config_files": $cf} | with_entries(select(.value != "")))},
      NetworkSettings: {Networks: {"portcullis-proxy": {Aliases: $a, DNSNames: $d}}}}' > "$STUB_DIR/dns/$1.json"
}
ctr c1 portcullis-traefik-1 portcullis traefik abc '["traefik","portcullis-traefik-1"]' '["portcullis-traefik-1","traefik","abc"]'
ctr c2 portcullis-mcp-gate-1 portcullis mcp-gate def '["mcp-gate"]'
GITEA_FILES=/project/templates/gitea/compose.yml,/data/overrides/gitea.override.yml,/data/overrides/gitea.user.yml
ctr c3 portcullis-gitea-web-1 portcullis-gitea web web1 '["web","portcullis-mcp-gitea--gitea"]' '["portcullis-gitea-web-1","web"]' "$GITEA_FILES"
# The Hub's override for instance gitea, as override.go writes it: the alias
# on the companion's service (web), another alias on another service.
cat > "$STUB_DIR/dns/override-gitea" <<'YML'
# Auto-generated by Portcullis Hub -- do not edit
services:
  db:
    environment:
      - "X=1"
  web:
    volumes:
      - ./templates/gitea/x:/x
    networks:
      default: {}
      portcullis-proxy:
        aliases:
          - "portcullis-mcp-gitea--gitea"
    labels: !override
      "traefik.http.routers.web.tls.options": "authaware@file"
  other:
    networks:
      portcullis-proxy:
        aliases:
          - "portcullis-mcp-gitea--other"
networks:
  portcullis-proxy:
    external: true
YML
echo "c1 c2 c3" > "$STUB_DIR/dns/ids"; printf 'c1\nc2\n' > "$STUB_DIR/dns/core-ids"; echo c3 > "$STUB_DIR/dns/proj-portcullis-gitea"
dns() { (PATH="$WORK/dnsbin:$PATH"; "$@"); }
expect_eq "dns guard: core containers and a well-behaved app pass" "$(dns proxy_dns_shadows)" ""
expect_ok "dns guard: core ids come from docker compose ps of the core project and file" \
  grep -qF -- "-p portcullis -f $(cd "$HERE/.." && pwd)/docker-compose.yml --profile * ps -aq" "$STUB_DIR/dns/compose-calls"
ctr c4 portcullis-evil-web-1 portcullis-evil web web '["web","Keycloak."]'
ctr c5 hub portcullis-evil2 api x '[]'
ctr c6 portcullis-evil3-app-1 portcullis-evil3 app LLDAP '[]'
ctr c7 portcullis-evil4-app-1 portcullis-evil4 app x '[]' '["vault"]'
# Forged core labels / names, not listed by compose: flagged even with no core alias.
ctr c8 portcullis-postgres-2 portcullis postgres x '[]'
ctr c9 portcullis-fake-1 portcullis keycloak x '[]'
# A real core container answering to ANOTHER core name, and a core service
# that is not a portcullis-proxy member at all.
ctr c1 portcullis-traefik-1 portcullis traefik abc '["traefik","hub"]'
ctr c10 portcullis-lldap-1 portcullis lldap x '["lldap"]'
echo "c1 c2 c3 c4 c5 c6 c7 c8 c9 c10" > "$STUB_DIR/dns/ids"; printf 'c1\nc2\nc10\n' > "$STUB_DIR/dns/core-ids"
expect_eq "dns guard: alias, name, hostname, DNS name, forged labels / names, a core container's foreign name, a core service off its networks" \
  "$(dns proxy_dns_shadows | sort | paste -sd'|' -)" \
  "hub hub|portcullis-evil-web-1 keycloak|portcullis-evil3-app-1 lldap|portcullis-evil4-app-1 vault|portcullis-fake-1 keycloak (core service label)|portcullis-lldap-1 lldap (core service not on portcullis-proxy)|portcullis-postgres-2 postgres (core service label)|portcullis-traefik-1 hub"
# Final review I4: AI companion names (mcp-gate sends credentials there).
# Only a portcullis-proxy alias of a container compose lists for that
# instance's project, and only one container per name.
ctr m1 portcullis-evil-web-1 portcullis-evil web web '["web","portcullis-mcp-gitea--gitea"]' '[]' "$GITEA_FILES"
ctr m2 portcullis-mcp-gitea--gitea other web web '[]'
ctr m3 portcullis-other-app-1 portcullis-other app portcullis-mcp-other--app '[]'
ctr m4 portcullis-other-x-1 portcullis-other x x '["portcullis-mcp-Other--x-"]'
ctr m5 portcullis-mcp-gate-1 portcullis mcp-gate def '["mcp-gate","portcullis-mcp-a--b"]'
echo c2 > "$STUB_DIR/dns/core-ids"
echo "c2 c3 m1" > "$STUB_DIR/dns/ids"
expect_eq "dns guard: an AI companion alias outside the instance's project" \
  "$(dns proxy_dns_shadows | sort | paste -sd'|' -)" \
  "portcullis-evil-web-1 portcullis-mcp-gitea--gitea (AI companion name outside project portcullis-gitea)|portcullis-gitea-web-1 portcullis-mcp-gitea--gitea (AI companion name answered by more than one container)"
# A forged project label: compose lists it, but two containers answer.
printf 'c3\nm1\n' > "$STUB_DIR/dns/proj-portcullis-gitea"
expect_eq "dns guard: two containers of the project answering to one AI companion name" \
  "$(dns proxy_dns_shadows | sort | paste -sd'|' -)" \
  "portcullis-evil-web-1 portcullis-mcp-gitea--gitea (AI companion name answered by more than one container)|portcullis-gitea-web-1 portcullis-mcp-gitea--gitea (AI companion name answered by more than one container)"
echo c3 > "$STUB_DIR/dns/proj-portcullis-gitea"
expect_ok "dns guard: the override is read from hub_data by a read-only, offline helper" \
  grep -qE -- "run --rm --network none --read-only --cap-drop ALL .*-v portcullis_hub_data:/d:ro .* /d/overrides/gitea.override.yml\$" "$STUB_DIR/dns/run-calls"
# Coordinator tightening: in the project, but not from the Hub's override;
# from it, but on another service than the one it gives the alias to; an
# instance with no override at all; the override unreadable (fail closed).
ctr m6 portcullis-gitea-web-2 portcullis-gitea web web '["portcullis-mcp-gitea--gitea"]' '[]' "/tmp/compose.yml"
ctr m7 portcullis-gitea-db-1 portcullis-gitea db db '["portcullis-mcp-gitea--other"]' '[]' "$GITEA_FILES"
ctr m8 portcullis-nohub-app-1 portcullis-nohub app app '["portcullis-mcp-nohub--app"]' '[]' "/data/overrides/nohub.override.yml"
printf 'm6\nm7\n' > "$STUB_DIR/dns/proj-portcullis-gitea"; echo m8 > "$STUB_DIR/dns/proj-portcullis-nohub"
echo "c2 m6 m7 m8" > "$STUB_DIR/dns/ids"
expect_eq "dns guard: AI companion name not from the Hub's override, on the wrong service, without an override" \
  "$(dns proxy_dns_shadows | sort | paste -sd'|' -)" \
  "portcullis-gitea-db-1 portcullis-mcp-gitea--other (AI companion name on service db, not the companion's service)|portcullis-gitea-web-2 portcullis-mcp-gitea--gitea (AI companion name on a container the Hub did not create)|portcullis-nohub-app-1 portcullis-mcp-nohub--app (AI companion name with no Hub override for instance nohub)"
touch "$STUB_DIR/dns/run-fail"
expect_fail "dns guard: hub_data unreadable fails closed" dns proxy_dns_shadows
rm -f "$STUB_DIR/dns/run-fail"
echo c3 > "$STUB_DIR/dns/proj-portcullis-gitea"
echo "c2 m2 m3 m4" > "$STUB_DIR/dns/ids"; echo m4 > "$STUB_DIR/dns/proj-portcullis-other"
expect_eq "dns guard: AI companion names as container name / hostname, malformed after folding" \
  "$(dns proxy_dns_shadows | sort | paste -sd'|' -)" \
  "portcullis-mcp-gitea--gitea portcullis-mcp-gitea--gitea (AI companion name as container name or hostname)|portcullis-other-app-1 portcullis-mcp-other--app (AI companion name as container name or hostname)|portcullis-other-x-1 portcullis-mcp-other--x- (malformed AI companion name)"
printf 'c2\nm5\n' > "$STUB_DIR/dns/core-ids"; echo "m5" > "$STUB_DIR/dns/ids"
expect_eq "dns guard: a core container never answers to an AI companion name" \
  "$(dns proxy_dns_shadows)" "portcullis-mcp-gate-1 portcullis-mcp-a--b (AI companion name on a core container)"
echo c2 > "$STUB_DIR/dns/core-ids"; echo "c2 c3" > "$STUB_DIR/dns/ids"; touch "$STUB_DIR/dns/proj-fail"
expect_fail "dns guard: an instance project that can't be listed fails closed" dns proxy_dns_shadows
rm -f "$STUB_DIR/dns/proj-fail"
printf 'c1\nc2\nc10\n' > "$STUB_DIR/dns/core-ids"
echo "c1 c2 c3 c4 c5 c6 c7 c8 c9 c10" > "$STUB_DIR/dns/ids"
expect_fail "guard: a container shadowing a core name aborts network_check" \
  bash -c "PATH='$WORK/dnsbin:$PATH'; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
OUT="$(PATH="$WORK/dnsbin:$PATH" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check" 2>&1)"
case "$OUT" in *'portcullis-evil-web-1 answers to "keycloak"'*) t_pass "guard: names the container and the core name" ;; *) t_fail "guard message: $OUT" ;; esac
ctr c1 portcullis-traefik-1 portcullis traefik abc '["traefik","portcullis-traefik-1"]'
echo "c1 c2 c3" > "$STUB_DIR/dns/ids"
expect_ok "guard: passes again once the apps are gone" \
  bash -c "PATH='$WORK/dnsbin:$PATH'; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
# Fail closed: every docker inspection error aborts.
for f in compose-fail net-fail; do
  touch "$STUB_DIR/dns/$f"; touch "$STUB_DIR/dns/net-listed"
  expect_fail "guard: inspection error ($f) aborts network_check" \
    bash -c "PATH='$WORK/dnsbin:$PATH'; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
  rm -f "$STUB_DIR/dns/$f" "$STUB_DIR/dns/net-listed"
done
echo "c1 c2 c3 gone" > "$STUB_DIR/dns/ids"
expect_fail "guard: a container that can't be inspected aborts network_check" \
  bash -c "PATH='$WORK/dnsbin:$PATH'; source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; network_check"
rm -f "$STUB_DIR/dns/ids"
expect_eq "dns guard: no network = nothing" "$(dns proxy_dns_shadows)" ""
expect_fail "network lib has no migration code" grep -Eq 'proxy_network_(migrate|reconnect)|docker network (connect|disconnect)' "$HERE/../scripts/lib/network.sh"

# ══ certs: write_revoked_serials ═══════════════════════════
REV="$WORK/revocation/revoked-serials.txt"
mkdir -p "$WORK/revocation"
printf '# old\naa:bb\n' > "$REV"
serials_in() { grep -v '^#' "$REV" | paste -sd' ' -; }

STUB_VAULT_RC=0 STUB_VAULT_OUT='["0a:bc","de:ad:be:ef"]' write_revoked_serials "$REV" >/dev/null 2>&1
expect_eq "sync writes Vault's revoked serials" "$(serials_in)" "0a:bc de:ad:be:ef"
expect_ok "sync file keeps a header" grep -q '^# Revoked YubiKey and browser certificate serials' "$REV"

STUB_VAULT_RC=2 STUB_VAULT_OUT='No value found at pki_int/certs/revoked' write_revoked_serials "$REV" >/dev/null 2>&1
rc=$?
expect_eq "exit 2 (nothing revoked) succeeds" "$rc" 0
expect_eq "exit 2 → empty list" "$(serials_in)" ""

printf '# prev\n0a:bc\n' > "$REV"
before="$(cat "$REV")"
# The vault CLI exits 2 for every API error (Vault 1.17): sealed, 403,
# unmounted, unreachable. Only "No value found at <path>" is "nothing".
for case in "2|$(printf 'Error listing pki_int/certs/revoked/: Error making API request.\n\nCode: 503. Errors:\n\n* Vault is sealed')" \
            "2|$(printf 'Error listing pki_int/certs/revoked/: Error making API request.\n\nCode: 403. Errors:\n\n* permission denied')" \
            "2|$(printf 'Error listing pki_int/certs/revoked/: Error making API request.\n\nCode: 404. Errors:\n\n* no handler for route \"pki_int/certs/revoked\". route entry not found.')" \
            "2|Error listing pki_int/certs/revoked/: Get \"http://127.0.0.1:8200/v1/pki_int/certs/revoked?list=true\": dial tcp 127.0.0.1:8200: connect: connection refused" \
            "2|" \
            "2|No value found at pki_int/certs/revoked plus something else" \
            "1|Error listing pki_int/certs/revoked: Vault is sealed" \
            "1|dial tcp 127.0.0.1:8200: connect: connection refused" \
            "0|not json at all" \
            '0|{"keys":["0a:bc"]}'; do
  rc=0
  STUB_VAULT_RC="${case%%|*}" STUB_VAULT_OUT="${case#*|}" write_revoked_serials "$REV" >/dev/null 2>&1 || rc=$?
  expect_eq "error '${case#*|}' → non-zero" "$([ "$rc" -ne 0 ] && echo fail || echo ok)" fail
  expect_eq "error '${case#*|}' → file untouched" "$(cat "$REV")" "$before"
done
expect_eq "no temp files left behind" "$(find "$WORK/revocation" -name '.revoked.*' | wc -l | tr -d ' ')" 0

# Both CAs: the union of pki_int/certs/revoked and pki_file/certs/revoked.
rm -f "$STUB_DIR/vault-calls"
STUB_VAULT_RC=0 STUB_VAULT_OUT='["0a:bc","11:11"]' STUB_VAULT_FILE_RC=0 STUB_VAULT_FILE_OUT='["ff:01","11:11"]' \
  write_revoked_serials "$REV" >/dev/null 2>&1
expect_eq "write_revoked_serials writes the union of both mounts" "$(serials_in)" "0a:bc 11:11 ff:01"
expect_ok "sync lists pki_int's revoked serials" grep -qx 'list -format=json pki_int/certs/revoked' "$STUB_DIR/vault-calls"
expect_ok "sync lists pki_file's revoked serials" grep -qx 'list -format=json pki_file/certs/revoked' "$STUB_DIR/vault-calls"
STUB_VAULT_RC=2 STUB_VAULT_OUT='No value found at pki_int/certs/revoked' STUB_VAULT_FILE_RC=0 STUB_VAULT_FILE_OUT='["ff:02"]' \
  write_revoked_serials "$REV" >/dev/null 2>&1
expect_eq "nothing revoked on pki_int + one on pki_file" "$(serials_in)" "ff:02"
before="$(cat "$REV")"
for case in "2|$(printf 'Error listing pki_file/certs/revoked/: Error making API request.\n\nCode: 503. Errors:\n\n* Vault is sealed')" \
            "2|$(printf 'Error listing pki_file/certs/revoked/: Error making API request.\n\nCode: 403. Errors:\n\n* permission denied')" \
            "1|Error listing pki_file/certs/revoked: Vault is sealed" "0|not json" '0|{"keys":["ff:03"]}'; do
  rc=0
  STUB_VAULT_RC=0 STUB_VAULT_OUT='["0a:bc"]' STUB_VAULT_FILE_RC="${case%%|*}" STUB_VAULT_FILE_OUT="${case#*|}" \
    write_revoked_serials "$REV" >/dev/null 2>&1 || rc=$?
  expect_eq "a failing pki_file list ('${case#*|}') → non-zero" "$([ "$rc" -ne 0 ] && echo fail || echo ok)" fail
  expect_eq "a failing pki_file list ('${case#*|}') leaves the file unchanged" "$(cat "$REV")" "$before"
done
rc=0
STUB_VAULT_RC=2 STUB_VAULT_OUT="$(printf 'Error listing pki_int/certs/revoked/: Error making API request.\n\nCode: 503. Errors:\n\n* Vault is sealed')" STUB_VAULT_FILE_RC=0 STUB_VAULT_FILE_OUT='["ff:04"]' \
  write_revoked_serials "$REV" >/dev/null 2>&1 || rc=$?
expect_eq "a failing pki_int list with a good pki_file one → non-zero" "$([ "$rc" -ne 0 ] && echo fail || echo ok)" fail
expect_eq "a failing pki_int list leaves the file unchanged" "$(cat "$REV")" "$before"
STUB_VAULT_RC=2 STUB_VAULT_OUT='No value found at pki_int/certs/revoked' STUB_VAULT_FILE_RC=2 STUB_VAULT_FILE_OUT='{}' \
  write_revoked_serials "$REV" >/dev/null 2>&1
expect_eq "'No value found' + '{}' (both CAs empty) → an empty list" "$(serials_in)" ""

# vault_no_value: only Vault's own "nothing there" answer.
expect_ok "vault_no_value: 'No value found at <path>'" vault_no_value 'No value found at pki_int/certs/revoked'
expect_ok "vault_no_value: '{}'" vault_no_value '{}'
expect_fail "vault_no_value: sealed" vault_no_value "$(printf 'Error reading x: Error making API request.\n\nCode: 503. Errors:\n\n* Vault is sealed')"
expect_fail "vault_no_value: 403" vault_no_value "$(printf 'Code: 403. Errors:\n\n* permission denied')"
expect_fail "vault_no_value: command not found" vault_no_value 'vault: command not found'
expect_fail "vault_no_value: empty" vault_no_value ''

# ══ portcullis pki setup: idempotency / partial runs / guard ═══
# Real (self-signed) CA certificates, so CNs and the chain order can be checked.
mkdir -p "$STUB_DIR/pem"
# mkpem <name> <CN> [<issuer name>] — a CA certificate: self-signed, or
# signed by <issuer> (a real hierarchy: the handshake check below builds
# paths through it); mkleaf <name> <CN> <issuer> — a client-auth leaf.
printf '[req]\ndistinguished_name=dn\n[dn]\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$STUB_DIR/pem/req.cnf"
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$STUB_DIR/pem/ca.ext"
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > "$STUB_DIR/pem/leaf.ext"
_mksigned() {  # <name> <CN> <issuer> <ext>
  openssl ecparam -genkey -name prime256v1 -out "$STUB_DIR/pem/$1.key" 2>/dev/null
  openssl req -new -key "$STUB_DIR/pem/$1.key" -subj "/CN=$2" -out "$STUB_DIR/pem/$1.csr" 2>/dev/null
  openssl x509 -req -in "$STUB_DIR/pem/$1.csr" -CA "$STUB_DIR/pem/$3" -CAkey "$STUB_DIR/pem/$3.key" \
    -set_serial "0x$(openssl rand -hex 8)" -days 2 -extfile "$STUB_DIR/pem/$4" -out "$STUB_DIR/pem/$1" 2>/dev/null
}
mkpem() {
  if [ -n "${3:-}" ]; then _mksigned "$1" "$2" "$3" ca.ext; return; fi
  openssl ecparam -genkey -name prime256v1 -out "$STUB_DIR/pem/$1.key" 2>/dev/null
  openssl req -new -x509 -key "$STUB_DIR/pem/$1.key" -subj "/CN=$2" -days 2 \
    -config "$STUB_DIR/pem/req.cnf" -extensions ca -out "$STUB_DIR/pem/$1" 2>/dev/null
}
mkleaf() { _mksigned "$1" "$2" "$3" leaf.ext; }
mkpem root "example.test Root CA"
mkpem int "example.test Intermediate CA" root
mkpem file "example.test Browser Certificate CA" root
mkpem file-samecn "example.test Intermediate CA" root
mkleaf leaf-yk alice int
mkleaf leaf-br alice file
# pki_node: its own root (ruling P1); node-root = the flaw (under pki).
mkpem node "example.test Node CA"
mkpem node-root "example.test Node CA" root
mkleaf leaf-node w1.node.portcullis.internal node
mkleaf leaf-node-root w1.node.portcullis.internal node-root
# A scripted vault stub: $PKI_STATE selects which PKI pieces "exist":
#   none (fresh Vault), complete (pki, pki_int, pki_file), nofile (pki_file
#   missing), norole (client-cert role missing), samecn (pki_file has
#   pki_int's CN), partial (mounts but no issuers), sealed, intbroken
#   (exit 1), int403 (403 on pki_int/issuers, exit 2 like the real CLI),
#   fileerr (sealed answer on pki_file/issuers, exit 2), roleerr (403 on the role),
#   nonode (pki_node missing), nodepartial (pki_node without an issuer),
#   nodeunderroot (pki_node's CA signed by the root: refused).
mkdir -p "$WORK/pki-bin"
cat > "$WORK/pki-bin/vault" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_DIR/pki-calls"
case "$PKI_STATE:$*" in
  sealed:secrets\ list*) echo "Error: Vault is sealed" >&2; exit 2 ;;
  *:secrets\ list*)
    case "$PKI_STATE" in
      none) echo '{"secret/":{}}' ;;
      nofile) echo '{"pki/":{},"pki_int/":{}}' ;;
      nonode) echo '{"pki/":{},"pki_int/":{},"pki_file/":{},"ssh_user/":{"type":"ssh","config":{"max_lease_ttl":43200}},"ssh_host/":{"type":"ssh","config":{"max_lease_ttl":7776000}}}' ;;
      *) echo '{"pki/":{},"pki_int/":{},"pki_file/":{},"pki_node/":{},"ssh_user/":{"type":"ssh","config":{"max_lease_ttl":43200}},"ssh_host/":{"type":"ssh","config":{"max_lease_ttl":7776000}}}' ;;
    esac ;;
  nodepartial:list*pki_node/issuers*) echo "No value found at $3" >&2; exit 2 ;;
  nonode:list*pki_*/issuers*|nodepartial:list*pki_*/issuers*|nodeunderroot:list*pki_*/issuers*) echo '["abc"]' ;;
  nodeunderroot:read\ -field=certificate\ pki_node/cert/ca) cat "$STUB_DIR/pem/node-root" ;;
  *:read\ -field=certificate\ pki_node/cert/ca) cat "$STUB_DIR/pem/node" ;;
  complete:list*pki_*/issuers*|norole:list*pki_*/issuers*|samecn:list*pki_*/issuers*) echo '["abc"]' ;;
  nofile:list*pki_int/issuers*) echo '["abc"]' ;;
  intbroken:list*pki_int/issuers*) echo "Error: permission denied" >&2; exit 1 ;;
  int403:list*pki_int/issuers*)
    printf 'Error listing pki_int/issuers/: Error making API request.\n\nCode: 403. Errors:\n\n* permission denied\n' >&2; exit 2 ;;
  fileerr:list*pki_int/issuers*) echo '["abc"]' ;;
  roleerr:list*pki_*/issuers*) echo '["abc"]' ;;
  fileerr:list*pki_file/issuers*)
    printf 'Error listing pki_file/issuers/: Error making API request.\n\nCode: 503. Errors:\n\n* Vault is sealed\n' >&2; exit 2 ;;
  *:list*issuers*) echo "No value found at $3" >&2; exit 2 ;;
  norole:read*pki_int/roles/client-cert*) echo "No value found at $3" >&2; exit 2 ;;
  roleerr:read*pki_int/roles/client-cert*)
    printf 'Error reading pki_int/roles/client-cert: Error making API request.\n\nCode: 403. Errors:\n\n* permission denied\n' >&2; exit 2 ;;
  *:read*/roles/*) echo '{"data":{}}' ;;
  *:read\ -field=certificate\ pki/cert/ca) cat "$STUB_DIR/pem/root" ;;
  *:read\ -field=certificate\ pki_int/cert/ca) cat "$STUB_DIR/pem/int" ;;
  samecn:read\ -field=certificate\ pki_file/cert/ca) cat "$STUB_DIR/pem/file-samecn" ;;
  *:read\ -field=certificate\ pki_file/cert/ca) cat "$STUB_DIR/pem/file" ;;
  *:write\ -format=json\ pki/root/generate*) echo '{"data":{"certificate":"ROOT"}}' ;;
  *:write\ -format=json\ pki_*/intermediate/generate*) echo '{"data":{"csr":"CSR"}}' ;;
  *:write\ -format=json\ pki/root/sign-intermediate*) echo '{"data":{"certificate":"INT"}}' ;;
  *:write\ -format=json\ pki_int/issue/server-cert*) echo '{"data":{"certificate":"SRV","private_key":"KEY"}}' ;;
  # ssh_setup (contract §18.7): the SSH CAs exist (tests/test_cli.sh has its own cases).
  *:read\ -field=public_key\ ssh_*/config/ca) echo "ssh-ed25519 AAAAstub" ;;
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
expect_ok "pki: ca-chain written" grep -q 'BEGIN CERTIFICATE' "$PKI_ROOT/certs/ca-chain.crt"
expect_ok "pki: Keycloak truststore written" cmp -s "$PKI_ROOT/certs/ca-chain.crt" "$PKI_ROOT/certs/truststore/portcullis-ca-chain.pem"
expect_ok "pki: client role defaults to 30 days" grep -q 'roles/client-cert .*max_ttl=720h ttl=720h' "$STUB_DIR/pki-calls"
expect_ok "pki: CRL auto-rebuild configured" grep -q 'pki_int/config/crl .*auto_rebuild=true' "$STUB_DIR/pki-calls"
# auto_rebuild defers full-CRL rebuilds on revoke: new revocations must go to a delta CRL.
expect_ok "pki: delta CRLs enabled, rebuilt every minute" grep -q 'pki_int/config/crl .*enable_delta=true delta_rebuild_interval=1m' "$STUB_DIR/pki-calls"
# The three CA files, as pki_setup must export them.
CHAIN3="$(cat "$STUB_DIR/pem/root" "$STUB_DIR/pem/int" "$STUB_DIR/pem/file")"
# ca-chain-yubikey.crt: pki_int ALONE (review C1: Go trusts every caFiles
# certificate as an anchor, so a root there would admit browser leaves).
CHAIN2="$(cat "$STUB_DIR/pem/int")"
nbegin() { grep -c 'BEGIN CERTIFICATE' "$1"; }
expect_ok "pki_setup on a fresh Vault enables pki" grep -qx 'secrets enable -path=pki pki' "$STUB_DIR/pki-calls"
expect_ok "pki_setup on a fresh Vault enables pki_int" grep -qx 'secrets enable -path=pki_int pki' "$STUB_DIR/pki-calls"
expect_ok "pki_setup on a fresh Vault enables pki_file" grep -qx 'secrets enable -path=pki_file pki' "$STUB_DIR/pki-calls"
expect_ok "pki_file CN is '<domain> Browser Certificate CA'" grep -q 'pki_file/intermediate/generate/internal common_name=example.test Browser Certificate CA' "$STUB_DIR/pki-calls"
expect_ok "pki_file is signed by the root (43800h)" grep -q 'pki/root/sign-intermediate csr=CSR format=pem_bundle ttl=43800h' "$STUB_DIR/pki-calls"
expect_ok "pki_file gets its signed certificate" grep -q 'write pki_file/intermediate/set-signed certificate=INT' "$STUB_DIR/pki-calls"
expect_ok "pki_file URLs point at pki_file" grep -q 'pki_file/config/urls issuing_certificates=.*/v1/pki_file/ca crl_distribution_points=.*/v1/pki_file/crl' "$STUB_DIR/pki-calls"
expect_eq "pki: ca-chain.crt has 3 certificates" "$(nbegin "$PKI_ROOT/certs/ca-chain.crt")" 3
expect_eq "pki: ca-chain.crt is root, pki_int, pki_file in order" "$(cat "$PKI_ROOT/certs/ca-chain.crt")" "$CHAIN3"
expect_eq "pki: ca-chain-yubikey.crt is pki_int's certificate alone (no root)" "$(cat "$PKI_ROOT/certs/ca-chain-yubikey.crt")" "$CHAIN2"
expect_eq "pki: ca-chain-yubikey.crt holds exactly 1 certificate" "$(nbegin "$PKI_ROOT/certs/ca-chain-yubikey.crt")" 1
# The handshake rule (review C1), with Go's semantics: every caFiles
# certificate is a trust anchor (-partial_chain) and the client's own
# chain is untrusted input. A browser .p12 sends leaf + pki_file + root.
BR_SENT="$STUB_DIR/pem/browser-sent"; cat "$STUB_DIR/pem/file" "$STUB_DIR/pem/root" > "$BR_SENT"
YK_SENT="$STUB_DIR/pem/yubikey-sent"; cat "$STUB_DIR/pem/int" > "$YK_SENT"
# OpenSSL >= 1.1 (CI's) has -partial_chain; LibreSSL (macOS /usr/bin) doesn't,
# and an unusable binary must never look like a refusal.
OSSL=""
for o in openssl /opt/homebrew/bin/openssl /usr/local/bin/openssl; do
  if command -v "$o" >/dev/null 2>&1 && "$o" verify -help 2>&1 | grep -q -- -partial_chain; then OSSL="$o"; break; fi
done
# hs <caFiles> <chain the client sends, "" for none> <leaf> — "accepted", "refused" or "error".
hs() {
  local out
  [ -n "$OSSL" ] || { echo error; return; }
  local sent=()
  [ -z "$2" ] || sent=(-untrusted "$2")
  if out="$("$OSSL" verify -partial_chain -purpose sslclient -CAfile "$1" "${sent[@]}" "$3" 2>&1)"; then echo accepted
  elif printf '%s' "$out" | grep -q 'error [0-9]* at [0-9]* depth lookup'; then echo refused
  else echo error; fi
}
expect_eq "handshake check: an OpenSSL with -partial_chain is available" "${OSSL:+yes}" yes
expect_eq "protected (ca-chain-yubikey.crt) refuses a browser leaf sending pki_file + root" \
  "$(hs "$PKI_ROOT/certs/ca-chain-yubikey.crt" "$BR_SENT" "$STUB_DIR/pem/leaf-br")" refused
expect_eq "protected (ca-chain-yubikey.crt) refuses a browser leaf sent alone" \
  "$(hs "$PKI_ROOT/certs/ca-chain-yubikey.crt" "" "$STUB_DIR/pem/leaf-br")" refused
expect_eq "protected (ca-chain-yubikey.crt) accepts a YubiKey leaf" \
  "$(hs "$PKI_ROOT/certs/ca-chain-yubikey.crt" "$YK_SENT" "$STUB_DIR/pem/leaf-yk")" accepted
expect_eq "protected (ca-chain-yubikey.crt) accepts a YubiKey leaf sent alone" \
  "$(hs "$PKI_ROOT/certs/ca-chain-yubikey.crt" "" "$STUB_DIR/pem/leaf-yk")" accepted
expect_eq "protected-any / authaware (ca-chain.crt) accept a browser leaf" \
  "$(hs "$PKI_ROOT/certs/ca-chain.crt" "$BR_SENT" "$STUB_DIR/pem/leaf-br")" accepted
expect_eq "protected-any / authaware (ca-chain.crt) accept a YubiKey leaf" \
  "$(hs "$PKI_ROOT/certs/ca-chain.crt" "$YK_SENT" "$STUB_DIR/pem/leaf-yk")" accepted
# The check catches the flaw: with the root in the file, the browser leaf passes.
cat "$STUB_DIR/pem/root" "$STUB_DIR/pem/int" > "$STUB_DIR/pem/old-yk-chain"
expect_eq "the handshake check detects a root in the YubiKey chain (root + pki_int admits a browser leaf)" \
  "$(hs "$STUB_DIR/pem/old-yk-chain" "$BR_SENT" "$STUB_DIR/pem/leaf-br")" accepted
expect_ok "pki: yubikey-ca.crt is pki_int's certificate" cmp -s "$PKI_ROOT/certs/yubikey-ca.crt" "$STUB_DIR/pem/int"
expect_ok "pki: browser-ca.crt is pki_file's certificate" cmp -s "$PKI_ROOT/certs/browser-ca.crt" "$STUB_DIR/pem/file"
expect_ok "truststore has portcullis-yubikey-ca.pem" cmp -s "$PKI_ROOT/certs/truststore/portcullis-yubikey-ca.pem" "$STUB_DIR/pem/int"
expect_ok "truststore has portcullis-browser-ca.pem" cmp -s "$PKI_ROOT/certs/truststore/portcullis-browser-ca.pem" "$STUB_DIR/pem/file"
expect_ok "browser-cert role written with client_flag=true server_flag=false" \
  grep -q 'write pki_file/roles/browser-cert .*client_flag=true server_flag=false' "$STUB_DIR/pki-calls"
expect_ok "browser-cert role: use_csr_common_name=false use_csr_sans=false, any name" \
  grep -q 'write pki_file/roles/browser-cert .*allow_any_name=true enforce_hostnames=false use_csr_common_name=false use_csr_sans=false' "$STUB_DIR/pki-calls"
expect_ok "browser-cert role: ec 256, max_ttl=\$CLIENT_CERT_TTL, stored" \
  grep -q 'write pki_file/roles/browser-cert .*key_type=ec key_bits=256 max_ttl=720h ttl=720h no_store=false' "$STUB_DIR/pki-calls"
expect_ok "browser-cert role: no IP / URI / other SANs" \
  grep -q 'write pki_file/roles/browser-cert .*allow_ip_sans=false allowed_uri_sans= allowed_other_sans= ' "$STUB_DIR/pki-calls"
expect_ok "client-cert role: no IP / URI / other SANs either" \
  grep -q 'write pki_int/roles/client-cert .*allow_ip_sans=false allowed_uri_sans= allowed_other_sans= ' "$STUB_DIR/pki-calls"
expect_ok "pki_file CRL configured auto_rebuild=true enable_delta=true delta_rebuild_interval=1m" \
  grep -q 'write pki_file/config/crl expiry=72h auto_rebuild=true auto_rebuild_grace_period=12h enable_delta=true delta_rebuild_interval=1m' "$STUB_DIR/pki-calls"
expect_eq "pki: complete PKI is a no-op" "$(run_pki complete)" 0
expect_fail "pki: complete PKI → no generate / disable" grep -Eq 'generate|secrets disable' "$STUB_DIR/pki-calls"
expect_ok "pki: complete PKI re-exports missing CA files" test -s "$PKI_ROOT/certs/ca-chain.crt"
expect_ok "pki: complete PKI rewrites the role (TTL changes apply)" grep -q 'write pki_int/roles/client-cert' "$STUB_DIR/pki-calls"
expect_ok "pki: complete PKI (re)applies the CRL config incl. delta" grep -q 'pki_int/config/crl .*enable_delta=true' "$STUB_DIR/pki-calls"
rm -f "$PKI_ROOT/certs/truststore/portcullis-ca-chain.pem"
expect_eq "pki: CLIENT_CERT_TTL=2160h" "$(CLIENT_CERT_TTL=2160h run_pki complete)" 0
expect_ok "pki: role uses CLIENT_CERT_TTL" grep -q 'max_ttl=2160h ttl=2160h' "$STUB_DIR/pki-calls"
expect_ok "pki: browser-cert role uses CLIENT_CERT_TTL" grep -q 'write pki_file/roles/browser-cert .*max_ttl=2160h' "$STUB_DIR/pki-calls"
expect_ok "pki: complete PKI re-exports the truststore" test -s "$PKI_ROOT/certs/truststore/portcullis-ca-chain.pem"
expect_eq "pki: invalid CLIENT_CERT_TTL fails" "$(CLIENT_CERT_TTL='30 days' run_pki complete)" 1
expect_eq "pki: missing role only" "$(run_pki norole)" 0
expect_ok "pki: missing role is recreated" grep -q 'write pki_int/roles/client-cert' "$STUB_DIR/pki-calls"
expect_fail "pki: missing role does NOT wipe the CA" grep -Eq 'generate|secrets disable' "$STUB_DIR/pki-calls"
expect_eq "pki: partial run (no intermediate) is redone" "$(run_pki partial)" 0
expect_ok "pki: partial run wipes pki_int + pki first" grep -q 'secrets disable pki_int' "$STUB_DIR/pki-calls"
expect_ok "pki: partial run wipes pki_file too" grep -qx 'secrets disable pki_file' "$STUB_DIR/pki-calls"
expect_eq "pki: sealed Vault fails" "$(run_pki sealed)" 1
expect_fail "pki: sealed Vault → nothing generated" grep -q generate "$STUB_DIR/pki-calls"
expect_eq "pki: read error on issuers fails" "$(run_pki intbroken)" 1
expect_fail "pki: read error → nothing wiped/generated" grep -Eq 'generate|secrets disable' "$STUB_DIR/pki-calls"
expect_eq "pki: a 403 on pki_int/issuers (exit 2) fails" "$(run_pki int403)" 1
expect_fail "pki: a 403 on pki_int/issuers → nothing wiped/generated" grep -Eq 'generate|secrets (enable|disable)' "$STUB_DIR/pki-calls"
expect_eq "pki: an error on pki_file/issuers (exit 2) fails" "$(run_pki fileerr)" 1
expect_fail "pki: an error on pki_file/issuers never wipes or re-creates pki_file" grep -Eq 'generate|secrets (enable|disable)' "$STUB_DIR/pki-calls"
expect_eq "pki: a 403 on the client-cert role (exit 2) fails" "$(run_pki roleerr)" 1
# Vault lost its data but certs/ca-chain.crt from the old CA is still there.
mkdir -p "$PKI_ROOT/certs" && echo OLD > "$PKI_ROOT/certs/ca-chain.crt"
expect_eq "pki: no CA in Vault + old ca-chain → refuses" "$(run_pki none --keep)" 1
expect_fail "pki: refusal creates nothing" grep -q generate "$STUB_DIR/pki-calls"
expect_ok "pki: refusal explains --force" grep -q -- '--force' "$WORK/pki-out"
expect_eq "pki: --force creates a new CA anyway" "$(run_pki none --keep --force)" 0
expect_ok "pki: --force generated a root" grep -q 'root/generate/internal' "$STUB_DIR/pki-calls"
expect_eq "pki: --force over a complete PKI" "$(run_pki complete --force)" 0
expect_ok "pki: --force destroys pki_file" grep -qx 'secrets disable pki_file' "$STUB_DIR/pki-calls"
expect_ok "pki: --force destroys pki_int" grep -qx 'secrets disable pki_int' "$STUB_DIR/pki-calls"

# PKI_TRUSTSTORE_CHANGED (read by stack.sh) needs pki_setup in this shell.
# pki_fn <state> — runs pki_setup on the current certs/, prints "<rc> <flag>".
pki_fn() {
  rm -f "$STUB_DIR/pki-calls"; touch "$STUB_DIR/pki-calls"
  PATH="$WORK/pki-bin:$PATH" PKI_STATE="$1" VAULT_TOKEN=t PORTCULLIS_ROOT="$PKI_ROOT" PORTCULLIS_DOMAIN=example.test \
    bash -c 'set -euo pipefail
      for l in common vault pki; do source "$1/scripts/lib/$l.sh"; done
      rc=0; ( pki_setup false false >/dev/null; echo "${PKI_TRUSTSTORE_CHANGED:-unset}" > "$2" ) || rc=$?
      [ "$rc" = 0 ] || echo error > "$2"
      echo "$rc $(cat "$2")"' _ "$HERE/.." "$WORK/pki-flag" 2>"$WORK/pki-out"
}
CERTS="$PKI_ROOT/certs"
# pki_int present, no pki_file: the install pki_file is added to.
rm -rf "$CERTS"; mkdir -p "$CERTS/truststore"
cp "$STUB_DIR/pem/root" "$CERTS/root-ca.crt"; cp "$STUB_DIR/pem/int" "$CERTS/intermediate-ca.crt"
printf '%s\n' "$CHAIN2" > "$CERTS/ca-chain.crt"; cp "$CERTS/ca-chain.crt" "$CERTS/truststore/portcullis-ca-chain.pem"
expect_eq "pki_setup with pki_int present but no pki_file sets PKI_TRUSTSTORE_CHANGED=true" "$(pki_fn nofile)" "0 true"
expect_ok "pki_setup with pki_int present creates pki_file" grep -qx 'secrets enable -path=pki_file pki' "$STUB_DIR/pki-calls"
expect_ok "pki_setup with pki_int present: pki_file signed by the root" grep -q 'write pki_file/intermediate/set-signed' "$STUB_DIR/pki-calls"
expect_fail "pki_setup with pki_int present keeps pki_int (no disable / generate on it)" \
  grep -Eq 'secrets disable|pki_int/intermediate/generate|pki/root/generate' "$STUB_DIR/pki-calls"
expect_eq "pki_setup with pki_int present rewrites ca-chain.crt to 3 certificates" "$(cat "$CERTS/ca-chain.crt")" "$CHAIN3"
expect_eq "pki_setup with pki_int present writes ca-chain-yubikey.crt (pki_int alone)" "$(cat "$CERTS/ca-chain-yubikey.crt")" "$CHAIN2"
expect_eq "pki_setup with pki_int present rewrites the truststore chain" "$(cat "$CERTS/truststore/portcullis-ca-chain.pem")" "$CHAIN3"
expect_ok "pki_setup with pki_int present writes the truststore's browser CA" cmp -s "$CERTS/truststore/portcullis-browser-ca.pem" "$STUB_DIR/pem/file"
expect_ok "pki_setup with pki_int present writes the browser-cert role" grep -q 'write pki_file/roles/browser-cert' "$STUB_DIR/pki-calls"
expect_ok "pki_setup with pki_int present configures pki_file's CRLs" grep -q 'write pki_file/config/crl .*enable_delta=true' "$STUB_DIR/pki-calls"
# pki_file missing in Vault but browser-ca.crt on disk: never re-created on a guess.
cp -p "$CERTS/ca-chain.crt" "$WORK/chain-before"
expect_eq "pki_setup refuses to re-create pki_file when certs/browser-ca.crt exists" "$(pki_fn nofile)" "1 error"
expect_fail "pki_setup's browser-ca.crt refusal enables / disables nothing" grep -Eq 'secrets (enable|disable)|generate' "$STUB_DIR/pki-calls"
expect_ok "pki_setup's browser-ca.crt refusal explains --force" grep -q -- '--force' "$WORK/pki-out"
expect_ok "pki_setup's browser-ca.crt refusal leaves the chain alone" cmp -s "$CERTS/ca-chain.crt" "$WORK/chain-before"
# All three present, both chains current.
expect_eq "pki_setup with all three present and both chains current leaves PKI_TRUSTSTORE_CHANGED unset" "$(pki_fn complete)" "0 unset"
expect_fail "pki_setup with all three present creates nothing" grep -Eq 'secrets (enable|disable)|generate' "$STUB_DIR/pki-calls"
# All three present, chain current but ca-chain-yubikey.crt missing / holding pki_file.
rm -f "$CERTS/ca-chain-yubikey.crt"
expect_eq "pki_setup with ca-chain-yubikey.crt missing sets PKI_TRUSTSTORE_CHANGED=true" "$(pki_fn complete)" "0 true"
expect_eq "pki_setup with ca-chain-yubikey.crt missing rewrites it" "$(cat "$CERTS/ca-chain-yubikey.crt")" "$CHAIN2"
printf '%s\n' "$CHAIN3" > "$CERTS/ca-chain-yubikey.crt"
expect_eq "pki_setup with ca-chain-yubikey.crt holding pki_file sets PKI_TRUSTSTORE_CHANGED=true" "$(pki_fn complete)" "0 true"
expect_eq "pki_setup with ca-chain-yubikey.crt holding pki_file rewrites it" "$(cat "$CERTS/ca-chain-yubikey.crt")" "$CHAIN2"
printf '%s\n' "$CHAIN2" > "$CERTS/ca-chain.crt"
expect_eq "pki_setup with a 2-certificate ca-chain.crt sets PKI_TRUSTSTORE_CHANGED=true" "$(pki_fn complete)" "0 true"
expect_eq "pki_setup with a 2-certificate ca-chain.crt rewrites it" "$(cat "$CERTS/ca-chain.crt")" "$CHAIN3"
# group-gate bind-mounts the CA files: an empty placeholder (stack_prepare)
# rewritten while the chains are current still restarts it.
: > "$CERTS/browser-ca.crt"
expect_eq "pki_setup with an empty browser-ca.crt (chains current) sets PKI_TRUSTSTORE_CHANGED=true" "$(pki_fn complete)" "0 true"
expect_ok "pki_setup rewrites an empty browser-ca.crt with pki_file's certificate" cmp -s "$CERTS/browser-ca.crt" "$STUB_DIR/pem/file"
expect_eq "pki_setup with every file current leaves PKI_TRUSTSTORE_CHANGED unset again" "$(pki_fn complete)" "0 unset"
# Equal CNs: refused, nothing exported.
cp -p "$CERTS/ca-chain.crt" "$WORK/chain-before"
rm -f "$CERTS/ca-chain-yubikey.crt"
expect_eq "pki_setup refuses when the two intermediates' CNs are equal" "$(pki_fn samecn)" "1 error"
expect_ok "pki_setup's refusal names the same CN" grep -q 'same CN' "$WORK/pki-out"
expect_ok "pki_setup's refusal leaves ca-chain.crt alone" cmp -s "$CERTS/ca-chain.crt" "$WORK/chain-before"
expect_fail "pki_setup's refusal writes no ca-chain-yubikey.crt" test -e "$CERTS/ca-chain-yubikey.crt"
expect_eq "pki setup (CLI) exits 1 on equal CNs" "$(run_pki samecn --keep)" 1

# ── test_pki_node_ca_not_trusted: pki_node is its own root, in no trust list (ruling P1) ──
expect_eq "pki_node: fresh install succeeds" "$(run_pki none)" 0
expect_ok "pki_node: fresh install enables pki_node" grep -qx 'secrets enable -path=pki_node pki' "$STUB_DIR/pki-calls"
expect_ok "pki_node: its own self-signed root (root/generate on pki_node, 10 y, EC P-256)" \
  grep -q 'write -format=json pki_node/root/generate/internal common_name=example.test Node CA ttl=87600h key_type=ec key_bits=256' "$STUB_DIR/pki-calls"
expect_fail "pki_node: never an intermediate, never signed by pki" \
  grep -Eq 'pki_node/intermediate|pki_node/.*set-signed' "$STUB_DIR/pki-calls"
expect_eq "pki_node: exactly one root/sign-intermediate per non-node CA (pki_int, pki_file)" \
  "$(grep -c 'pki/root/sign-intermediate' "$STUB_DIR/pki-calls")" 2
expect_ok "pki_node: node-worker role (client + server, 30 d, subdomains of node.portcullis.internal)" \
  grep -q 'write pki_node/roles/node-worker allowed_domains=node.portcullis.internal allow_subdomains=true allow_bare_domains=false .* client_flag=true server_flag=true .* key_type=ec key_bits=256 ttl=720h max_ttl=720h no_store=false not_before_duration=30s' "$STUB_DIR/pki-calls"
expect_ok "pki_node: node-control role (hub.control, client only, 30 d)" \
  grep -q 'write pki_node/roles/node-control allowed_domains=hub.control allow_subdomains=false allow_bare_domains=true .* client_flag=true server_flag=false .* ttl=720h max_ttl=720h no_store=false not_before_duration=30s' "$STUB_DIR/pki-calls"
expect_ok "pki_node: node-link role (link.control, client only, 90 d)" \
  grep -q 'write pki_node/roles/node-link allowed_domains=link.control allow_subdomains=false allow_bare_domains=true .* client_flag=true server_flag=false .* ttl=2160h max_ttl=2160h no_store=false not_before_duration=30s' "$STUB_DIR/pki-calls"
# HA (contract §17.5): nodeadm's three roles.
expect_ok "pki_node: node-cluster role (client + server, 30 d, subdomains of cluster.portcullis.internal)" \
  grep -q 'write pki_node/roles/node-cluster allowed_domains=cluster.portcullis.internal allow_subdomains=true allow_bare_domains=false .* client_flag=true server_flag=true .* ttl=720h max_ttl=720h' "$STUB_DIR/pki-calls"
expect_ok "pki_node: node-frontdoor role (frontdoor.control, client only, 30 d)" \
  grep -q 'write pki_node/roles/node-frontdoor allowed_domains=frontdoor.control allow_subdomains=false allow_bare_domains=true .* client_flag=true server_flag=false .* ttl=720h max_ttl=720h' "$STUB_DIR/pki-calls"
expect_ok "pki_node: node-nodeadm role (nodeadm.control + its serving name, client + server, 30 d)" \
  grep -q 'write pki_node/roles/node-nodeadm allowed_domains=nodeadm.control,nodeadm.portcullis-nodeadm.svc allow_subdomains=false allow_bare_domains=true .* client_flag=true server_flag=true .* ttl=720h max_ttl=720h' "$STUB_DIR/pki-calls"
expect_eq "pki_node: every node role refuses IP / URI / other SANs and the CSR's names" \
  "$(grep 'write pki_node/roles/' "$STUB_DIR/pki-calls" | grep -c 'allow_any_name=false allow_localhost=false allow_wildcard_certificates=false enforce_hostnames=true use_csr_common_name=false use_csr_sans=false allow_ip_sans=false allowed_uri_sans= allowed_other_sans=')" 6
expect_ok "pki_node: CRL auto-rebuild + delta" grep -q 'write pki_node/config/crl .*enable_delta=true' "$STUB_DIR/pki-calls"
NODE_C="$PKI_ROOT/certs"
expect_ok "pki_node: certs/node-ca.crt is pki_node's CA" cmp -s "$NODE_C/node-ca.crt" "$STUB_DIR/pem/node"
NODE_BODY="$(sed -n '2p' "$STUB_DIR/pem/node")"
for f in ca-chain.crt ca-chain-yubikey.crt yubikey-ca.crt browser-ca.crt root-ca.crt intermediate-ca.crt \
         truststore/portcullis-ca-chain.pem truststore/portcullis-yubikey-ca.pem truststore/portcullis-browser-ca.pem; do
  expect_fail "pki_node: node-ca.crt is not in $f" grep -qF "$NODE_BODY" "$NODE_C/$f"
done
expect_eq "pki_node: no chain / truststore / group-gate file holds the node CA (whole certs/ tree but node-ca.crt)" \
  "$(grep -rlF "$NODE_BODY" "$NODE_C" | grep -v '/node-ca.crt$' || true)" ""
# The handshakes themselves, with Go's semantics (every caFiles certificate
# an anchor, the client's chain untrusted input): a node-worker leaf sending
# the node CA fails Traefik's protected, protected-any and authaware
# options and Keycloak's truststore.
NODE_SENT="$STUB_DIR/pem/node-sent"; cat "$STUB_DIR/pem/node" > "$NODE_SENT"
for ca in ca-chain-yubikey.crt ca-chain.crt truststore/portcullis-ca-chain.pem truststore/portcullis-yubikey-ca.pem \
          truststore/portcullis-browser-ca.pem yubikey-ca.crt browser-ca.crt; do
  expect_eq "pki_node: a node-worker leaf sending its CA is refused by $ca" \
    "$(hs "$NODE_C/$ca" "$NODE_SENT" "$STUB_DIR/pem/leaf-node")" refused
  expect_eq "pki_node: a node-worker leaf sent alone is refused by $ca" \
    "$(hs "$NODE_C/$ca" "" "$STUB_DIR/pem/leaf-node")" refused
done
expect_eq "pki_node: the node leaf is valid under node-ca.crt (control)" \
  "$(hs "$NODE_C/node-ca.crt" "" "$STUB_DIR/pem/leaf-node")" accepted
# The check catches the flaw ruling P1 removed: a node CA under the root
# would pass Traefik's protected-any / authaware.
cat "$STUB_DIR/pem/node-root" "$STUB_DIR/pem/root" > "$STUB_DIR/pem/node-root-sent"
expect_eq "pki_node: the handshake check detects a node CA under the root (ca-chain.crt would accept it)" \
  "$(hs "$NODE_C/ca-chain.crt" "$STUB_DIR/pem/node-root-sent" "$STUB_DIR/pem/leaf-node-root")" accepted
# pki setup refuses such a pki_node and exports nothing of it.
rm -f "$NODE_C/node-ca.crt"
expect_eq "pki_node: pki setup refuses a pki_node signed by the root" "$(run_pki nodeunderroot --keep)" 1
expect_ok "pki_node: the refusal says why" grep -q 'not its own self-signed root' "$WORK/pki-out"
expect_fail "pki_node: the refusal writes no node-ca.crt" test -e "$NODE_C/node-ca.crt"
# Re-runs: present = roles only; missing = created; partial = wiped + redone.
expect_eq "pki_node: complete PKI" "$(run_pki complete --keep)" 0
expect_fail "pki_node: complete PKI creates no node CA" grep -Eq 'pki_node/root/generate|secrets (enable|disable) .*pki_node' "$STUB_DIR/pki-calls"
expect_ok "pki_node: complete PKI rewrites the node roles" grep -q 'write pki_node/roles/node-worker' "$STUB_DIR/pki-calls"
rm -f "$NODE_C/node-ca.crt"
expect_eq "pki_node: missing pki_node next to the other CAs" "$(run_pki nonode --keep)" 0
expect_ok "pki_node: missing pki_node is created" grep -qx 'secrets enable -path=pki_node pki' "$STUB_DIR/pki-calls"
expect_fail "pki_node: creating pki_node touches no other CA" grep -Eq 'secrets disable|pki(_int|_file)?/(root|intermediate)/generate' "$STUB_DIR/pki-calls"
expect_eq "pki_node: missing pki_node but node-ca.crt on disk is refused" "$(run_pki nonode --keep)" 1
expect_ok "pki_node: that refusal names node-ca.crt" grep -q 'node-ca.crt exists' "$WORK/pki-out"
expect_fail "pki_node: that refusal creates nothing" grep -Eq 'secrets enable|generate' "$STUB_DIR/pki-calls"
rm -f "$NODE_C/node-ca.crt"
expect_eq "pki_node: a partial pki_node (no issuer)" "$(run_pki nodepartial --keep)" 0
expect_ok "pki_node: a partial pki_node is wiped first" grep -qx 'secrets disable pki_node' "$STUB_DIR/pki-calls"
expect_ok "pki_node: then created" grep -q 'pki_node/root/generate/internal' "$STUB_DIR/pki-calls"
expect_eq "pki_node: --force over a complete PKI" "$(run_pki complete --keep --force)" 0
expect_ok "pki_node: --force destroys pki_node" grep -qx 'secrets disable pki_node' "$STUB_DIR/pki-calls"
expect_ok "pki_node: --force makes a new node root" grep -q 'pki_node/root/generate/internal' "$STUB_DIR/pki-calls"

# ── test_enroll_policy_node_paths: enroll may sign node-worker / node-control only ──
NODE_POLICY="$(awk '
  function flush() { if (p != "") print p " " c (d != "" ? " deny=" d : ""); p = ""; c = ""; d = "" }
  /^[[:space:]]*path[[:space:]]+"/ { flush(); p = $2; gsub(/"/, "", p); ind = 0; next }
  /capabilities/ { c = $0; sub(/.*\[/, "", c); sub(/\].*/, "", c); gsub(/[" ]/, "", c); next }
  /denied_parameters/ { ind = 1; next }
  ind && /=[[:space:]]*\[\]/ { k = $1; gsub(/"/, "", k); d = (d == "" ? k : d "," k); next }
  ind && /^[[:space:]]*}/ { ind = 0; next }
  END { flush() }
' "$HERE/../vault/policies/enroll.hcl" | grep '^pki_node/' | sort)"
NODE_POLICY_WANT="$(printf '%s\n' \
  'pki_node/sign/node-worker update deny=alt_names,ip_sans,uri_sans,other_sans' \
  'pki_node/sign/node-control update deny=alt_names,ip_sans,uri_sans,other_sans' \
  'pki_node/sign/node-cluster update deny=alt_names,ip_sans,uri_sans,other_sans' \
  'pki_node/sign/node-frontdoor update deny=alt_names,ip_sans,uri_sans,other_sans' \
  'pki_node/sign/node-nodeadm update' \
  'pki_node/cert/* read' 'pki_node/revoke update' 'pki_node/crl/rotate read' | sort)"
expect_eq "enroll.hcl: the pki_node paths are exactly sign node-worker / node-control / node-cluster / node-frontdoor (no SANs), node-nodeadm, cert read, revoke, crl/rotate" \
  "$NODE_POLICY" "$NODE_POLICY_WANT"
# node-nodeadm takes exactly its one SAN and the CN out of the SANs.
expect_eq "enroll.hcl: node-nodeadm's allowed_parameters pin the CN, its one alt_names value and exclude_cn_from_sans" \
  "$(sed -n '/path "pki_node\/sign\/node-nodeadm"/,/^}/p' "$HERE/../vault/policies/enroll.hcl" | grep -cE '"(common_name" += \["nodeadm.control"\]|alt_names" += \["nodeadm.portcullis-nodeadm.svc"\]|exclude_cn_from_sans" = \["true"\]|csr" += \[\]|ttl" += \[\])')" 5
expect_fail "enroll.hcl: never node-link, issue, roles, root or a pki_node wildcard" \
  grep -Eq 'path "pki_node/(sign/node-link|issue|roles|root|sign-verbatim|intermediate|config|\*|sign/\*)' "$HERE/../vault/policies/enroll.hcl"

# ══ portcullis cert sync (dispatch through the CLI) ════════
mkdir -p "$PKI_ROOT/certs/revocation"
rc=0; STUB_VAULT_RC=0 STUB_VAULT_OUT='["11:22"]' VAULT_TOKEN=t PORTCULLIS_ROOT="$PKI_ROOT" "$CLI" cert sync >/dev/null 2>&1 || rc=$?
expect_eq "cli cert sync succeeds" "$rc" 0
expect_ok "cli cert sync wrote the serial" grep -qx '11:22' "$PKI_ROOT/certs/revocation/revoked-serials.txt"
rc=0; STUB_VAULT_RC=1 STUB_VAULT_OUT='sealed' VAULT_TOKEN=t PORTCULLIS_ROOT="$PKI_ROOT" "$CLI" cert sync >/dev/null 2>&1 || rc=$?
expect_eq "cli cert sync fails on Vault error" "$rc" 1
rc=0; STUB_VAULT_RC=2 STUB_VAULT_OUT="$(printf 'Error listing pki_int/certs/revoked/: Error making API request.\n\nCode: 503. Errors:\n\n* Vault is sealed')" \
  VAULT_TOKEN=t PORTCULLIS_ROOT="$PKI_ROOT" "$CLI" cert sync >/dev/null 2>&1 || rc=$?
expect_eq "cli cert sync fails on a sealed Vault (exit 2)" "$rc" 1
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

# ── status: mcp-gate refusing every AI request (docs review M4) ──
# dc ps -q mcp-gate → an id; docker inspect → its health JSON.
mst() { (dc() { [ "$*" = "ps -q mcp-gate" ] && cat "$STUB_DIR/mst-id" 2>/dev/null; }
         docker() { [ "$1" = inspect ] && cat "$STUB_DIR/mst-health"; }; _st_mcp_refusing); }
echo cid1 > "$STUB_DIR/mst-id"
jq -n '{Status: "healthy", Log: [{Output: "ok\nrefusing every AI request (503): old"}, {Output: "ok\nrefusing every AI request (503): mcp-credentials.json: credentials[0]: no identity matched\n"}]}' > "$STUB_DIR/mst-health"
expect_eq "status: mcp-gate refusing = the last health log's reason" "$(mst)" "refusing every AI request (503): mcp-credentials.json: credentials[0]: no identity matched"
jq -n '{Status: "healthy", Log: [{Output: "ok\nrefusing every AI request (503): old"}, {Output: "ok\n"}]}' > "$STUB_DIR/mst-health"
expect_eq "status: mcp-gate serving = nothing" "$(mst)" ""
rm -f "$STUB_DIR/mst-id"
expect_eq "status: mcp-gate not running = nothing" "$(mst)" ""

# ── status --textfile: certificates per person and kind, the browser CA (review M2) ──
stf() { (status_run() { cat "$STUB_DIR/stf.json"; }; metrics_textfile_write() { cat; }; status_textfile); }
jq -n '{ok: true, services: [], vault: {active: true, root_ca_expires_epoch: 300, intermediate_ca_expires_epoch: 200, browser_ca_expires_epoch: 100,
        client_certs: [{cn: "alice", kind: "yubikey", epoch: 10}, {cn: "alice", kind: "browser", epoch: 20}, {cn: "b\"o", kind: "browser", epoch: 30}]}}' > "$STUB_DIR/stf.json"
STF="$(stf)"
expect_eq "status --textfile: one certificate series per person and kind (label kind)" \
  "$(printf '%s\n' "$STF" | grep '^portcullis_client_cert_expiry_timestamp_seconds{')" \
  'portcullis_client_cert_expiry_timestamp_seconds{cn="alice",kind="yubikey"} 10
portcullis_client_cert_expiry_timestamp_seconds{cn="alice",kind="browser"} 20
portcullis_client_cert_expiry_timestamp_seconds{cn="b\"o",kind="browser"} 30'
expect_eq "status --textfile: root, intermediate (YubiKey) and browser CA series" \
  "$(printf '%s\n' "$STF" | grep '^portcullis_ca_expiry_timestamp_seconds{')" \
  'portcullis_ca_expiry_timestamp_seconds{ca="root"} 300
portcullis_ca_expiry_timestamp_seconds{ca="intermediate"} 200
portcullis_ca_expiry_timestamp_seconds{ca="browser"} 100'
jq '.vault.browser_ca_expires_epoch = 0' "$STUB_DIR/stf.json" > "$STUB_DIR/stf2.json" && mv "$STUB_DIR/stf2.json" "$STUB_DIR/stf.json"
expect_eq "status --textfile: no browser CA series while its expiry is unknown" "$(stf | grep -c 'ca="browser"' || true)" 0
# status --json over both mounts: nothing issued on pki_file yet ("No value
# found", exit 2) is an empty list, not an unknown count (CI run 43051184972).
sjson() { (require_cmd() { :; }; dc() { :; }; rt_health() { echo healthy; }; kc_login() { return 1; }
           proxy_dns_shadows() { :; }; _st_mcp_refusing() { :; }; vault_health_code() { echo 200; }
           vault_admin_env() { export VAULT_TOKEN=x; }; vault_use_container_cli() { :; }
           _cert_info() { echo "testuser|Dec 11 15:51:10 2099 GMT|false"; }
           vault() { case "$*" in
                       "list -format=json pki_int/certs") echo '["aa:bb"]' ;;
                       "list -format=json pki_file/certs") echo "No value found at ${STATUS_FILE_LIST:-pki_file/certs}" >&2; return "${STATUS_FILE_RC:-2}" ;;
                       *) return 1 ;;
                     esac; }
           status_run true 2>/dev/null) || true; }
expect_eq "status --json: pki_file with nothing issued counts 0 (certs_issued 1, the YubiKey one listed)" \
  "$(sjson | jq -c '[.vault.certs_issued, [.vault.client_certs[] | .kind]]')" '[1,["yubikey"]]'
expect_eq "status --json: a failing pki_file list leaves certs_issued unknown" \
  "$(STATUS_FILE_RC=1 sjson | jq -c '.vault.certs_issued')" null

# ── upgrade: pinned Hub image, policy file version (final review M1) ──
# dc stub: exec prints $STUB_DIR/pv (the policy version), logs $STUB_DIR/gglog.
pv() { (dc() { case "$1" in exec) cat "$STUB_DIR/pv" 2>/dev/null ;; logs) cat "$STUB_DIR/gglog" 2>/dev/null ;; esac; }; sleep() { :; }; "$@"; hub_policy_check 2 2>&1); }
echo 7 > "$STUB_DIR/pv"; : > "$STUB_DIR/gglog"
expect_ok "upgrade: matching policy version is fine" sh -c "printf '%s' \"\$1\" | grep -q 'matches group-gate'" _ "$(pv unset HUB_IMAGE)"
echo 6 > "$STUB_DIR/pv"
OUT="$(pv export HUB_IMAGE=ghcr.io/porelli/portcullis-hub:v0.1)"
expect_ok "upgrade: old policy version names the pinned image and the fix" sh -c "printf '%s' \"\$1\" | grep -q 'version 6, this core' && printf '%s' \"\$1\" | grep -q 'remove HUB_IMAGE=ghcr.io/porelli/portcullis-hub:v0.1'" _ "$OUT"
echo 7 > "$STUB_DIR/pv"; echo "group-gate: deny host=x: policy file version 8 is not supported (only 7)" > "$STUB_DIR/gglog"
expect_ok "upgrade: group-gate deny log is reported" sh -c "printf '%s' \"\$1\" | grep -q 'denying every app host'" _ "$(pv unset HUB_IMAGE)"
rm -f "$STUB_DIR/pv" "$STUB_DIR/gglog"
# ── upgrade: the Hub syncs its template sources (SIGHUP, status file) ──
# dc stub: exec cat prints $STUB_DIR/sync (or, after a kill, $STUB_DIR/sync2);
# kill is logged in $STUB_DIR/kills. The container started at epoch 1000.
hs() { (hub_started_unix() { echo 1000; }
  dc() { case "$1" in
    exec) if [ -f "$STUB_DIR/killed" ] && [ -f "$STUB_DIR/sync2" ]; then cat "$STUB_DIR/sync2"; else cat "$STUB_DIR/sync" 2>/dev/null; fi ;;
    kill) echo "$*" >> "$STUB_DIR/kills"; [ -f "$STUB_DIR/killfail" ] && return 1; touch "$STUB_DIR/killed" ;;
  esac; }; sleep() { :; }; hub_sources_sync 2 2>&1); }
# A status started after the signal (an hour ahead: the test may cross a second).
NOW="$(( $(date +%s) + 3600 ))"
rm -f "$STUB_DIR/kills" "$STUB_DIR/killed"
OUT="$(hs)"
expect_ok "upgrade sync: no status file (older Hub) = warning, no signal" sh -c "printf '%s' \"\$1\" | grep -q 'reported no template sync' && [ ! -f \"\$2\" ]" _ "$OUT" "$STUB_DIR/kills"
echo '{"started_unix": 500, "running": false, "ok": true, "sources": []}' > "$STUB_DIR/sync"
OUT="$(hs)"
expect_ok "upgrade sync: a status older than the running Hub = not signalled" sh -c "printf '%s' \"\$1\" | grep -q 'reported no template sync' && [ ! -f \"\$2\" ]" _ "$OUT" "$STUB_DIR/kills"
echo '{"started_unix": 1001, "running": false, "ok": true, "sources": []}' > "$STUB_DIR/sync"
printf '{"started_unix": %s, "running": false, "ok": true, "sources": [{"name": "portcullis", "ok": true, "updated": true, "after": "0123456789abcdef"}]}' "$NOW" > "$STUB_DIR/sync2"
OUT="$(hs)"
expect_ok "upgrade sync: SIGHUP sent to the hub" grep -q 'kill -s HUP hub' "$STUB_DIR/kills"
expect_ok "upgrade sync: updated source printed" sh -c "printf '%s' \"\$1\" | grep -q 'template source portcullis: updated to 0123456789ab'" _ "$OUT"
expect_fail "upgrade sync: no warning when ok" sh -c "printf '%s' \"\$1\" | grep -qi 'warn\|incomplete\|denied'" _ "$OUT"
rm -f "$STUB_DIR/killed"
printf '{"started_unix": %s, "running": false, "ok": false, "missing_templates": ["headscale"], "sources": [{"name": "portcullis", "ok": false, "updated": false, "error": "git pull --ff-only failed — the previous version is kept"}]}' "$NOW" > "$STUB_DIR/sync2"
OUT="$(hs)"
expect_ok "upgrade sync: failed source and kept version reported" sh -c "printf '%s' \"\$1\" | grep -q 'NOT updated — git pull' && printf '%s' \"\$1\" | grep -q 'incomplete'" _ "$OUT"
expect_ok "upgrade sync: missing templates named" sh -c "printf '%s' \"\$1\" | grep -q 'denied until fixed: headscale'" _ "$OUT"
rm -f "$STUB_DIR/killed"
printf '{"started_unix": %s, "running": true, "ok": false, "sources": []}' "$NOW" > "$STUB_DIR/sync2"
OUT="$(hs)"
expect_ok "upgrade sync: a sync still running = timeout warning" sh -c "printf '%s' \"\$1\" | grep -q 'did not finish in time'" _ "$OUT"
rm -f "$STUB_DIR/killed"; touch "$STUB_DIR/killfail"
OUT="$(hs)"
expect_ok "upgrade sync: signal failure = warning with the manual fix" sh -c "printf '%s' \"\$1\" | grep -q 'Could not signal the Hub' && printf '%s' \"\$1\" | grep -q 'Sync All Sources'" _ "$OUT"
rm -f "$STUB_DIR/sync" "$STUB_DIR/sync2" "$STUB_DIR/kills" "$STUB_DIR/killed" "$STUB_DIR/killfail"
expect_ok "upgrade: pinned HUB_IMAGE warned" sh -c "printf '%s' \"\$1\" | grep -q 'NOT upgraded'" _ "$(HUB_IMAGE=x hub_pinned_warn 2>&1)"
expect_eq "upgrade: default HUB_IMAGE not warned" "$(unset HUB_IMAGE; hub_pinned_warn 2>&1)" ""
expect_ok "upgrade: pinned KEYCLOAK_IMAGE warned" sh -c "printf '%s' \"\$1\" | grep -q 'Keycloak is NOT upgraded'" _ "$(KEYCLOAK_IMAGE=x hub_pinned_warn 2>&1)"
expect_eq "upgrade: default KEYCLOAK_IMAGE not warned" "$(unset HUB_IMAGE KEYCLOAK_IMAGE; hub_pinned_warn 2>&1)" ""
# ── restore: never start Keycloak on an empty LLDAP over a database with users ──
lg_guard() { (RG_LL="$1" RG_KC="$2"; _restore_lldap_count() { echo "$RG_LL"; }; _restore_kc_federated_count() { echo "$RG_KC"; }; _restore_lldap_guard "$3" 2>&1); }
_rg() { lg_guard "$@" >/dev/null; }
expect_fail "restore guard: LLDAP without users, Keycloak has 5 = refused" _rg 0 5 false
expect_fail "restore guard: no LLDAP database, Keycloak has 5 = refused" _rg missing 5 false
expect_ok "restore guard: --allow-empty-lldap starts anyway" _rg 0 5 true
expect_ok "restore guard: LLDAP with users = ok" _rg 3 5 false
expect_ok "restore guard: both empty (fresh) = ok" _rg 0 0 false
expect_ok "restore guard: Keycloak count unknown = ok" _rg 0 "" false
expect_ok "restore guard: refusal explains the fix" sh -c "printf '%s' \"\$1\" | grep -q 'passkeys included' && printf '%s' \"\$1\" | grep -q -- '--allow-empty-lldap'" _ "$(lg_guard 0 5 false)"
B="$WORK/backup"
mkdir -p "$B/secrets/vault-unseal" "$B/certs"
echo 'PORTCULLIS_DOMAIN=x' > "$B/.env"
echo '{"root_token":"r","unseal_keys_b64":["k"]}' > "$B/secrets/vault-init.json"
printf k > "$B/secrets/vault-unseal/unseal-key"
mkdir -p "$B/secrets/lldap"; printf 'U0VFRC1TRUVELVNFRUQtU0VFRC1TRUVELVNFRUQtU0VFRC1TRUVELVNFRUQtU0VF' > "$B/secrets/lldap/key-seed"
echo snap > "$B/vault.snap"; echo PGDMP > "$B/postgres.dump"; echo 'with space' > "$B/certs/a b.crt"
_BACKUP_CFG='{"services":{"hub":{"image":"hub:1"},"keycloak":{"image":"kc:2"}}}'
_backup_manifest "$B"
expect_eq "manifest: format + every file" "$(jq -c '[.format, (.files | keys)]' "$B/MANIFEST.json")" \
  '[1,[".env","certs/a b.crt","postgres.dump","secrets/lldap/key-seed","secrets/vault-init.json","secrets/vault-unseal/unseal-key","vault.snap"]]'
expect_eq "manifest: hub image recorded" "$(jq -r .hub_image "$B/MANIFEST.json")" hub:1
expect_eq "manifest: keycloak image recorded" "$(jq -r .keycloak_image "$B/MANIFEST.json")" kc:2
expect_eq "MANIFEST.json records runtime {name, version}" "$(jq -c .runtime "$B/MANIFEST.json")" '{"name":"docker","version":"29.0.0"}'
expect_ok "manifest: checksums verify" _backup_check_manifest "$B"
echo tampered >> "$B/postgres.dump"
expect_fail "manifest: a modified file fails" _backup_check_manifest "$B"
echo lldap > "$B/lldap_data.tar.gz"
expect_ok "layout: complete backup accepted" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/monitoring.sh'; source '$HERE/../scripts/lib/users.sh'; source '$HERE/../scripts/lib/backup.sh'; _backup_check_layout '$B'"
rm "$B/secrets/vault-unseal/unseal-key"
expect_fail "layout: missing unseal key rejected" bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/monitoring.sh'; source '$HERE/../scripts/lib/users.sh'; source '$HERE/../scripts/lib/backup.sh'; _backup_check_layout '$B'"

BACKUP_ROOT="$WORK/backups"
mkdir -p "$BACKUP_ROOT"/{20260101-000000,20260102-000000,20260103-000000,pre-restore-20260101-000000,offsite-20260101-000000,20260104-000000.partial}
BACKUP_KEEP_LOCAL=2 _backup_prune_local >/dev/null
expect_eq "prune: keeps the newest BACKUP_KEEP_LOCAL, leaves other dirs" "$(cd "$BACKUP_ROOT" && ls -1 | tr '\n' ' ')" \
  "20260102-000000 20260103-000000 20260104-000000.partial offsite-20260101-000000 pre-restore-20260101-000000 "
expect_eq "backup dirs: only timestamped ones" "$(_backup_dirs | tr '\n' ' ')" "20260102-000000 20260103-000000 "
expect_eq "restic creds: BACKUP_<NAME> wins" "$(AWS_ACCESS_KEY_ID=dns BACKUP_AWS_ACCESS_KEY_ID=bak _backup_cred AWS_ACCESS_KEY_ID)" bak
expect_eq "restic creds: falls back to <NAME>" "$(B2_ACCOUNT_ID=b2 _backup_cred B2_ACCOUNT_ID)" b2

# backup_create never archives appfiles/: the Hub regenerates it from its
# state (hub_data), so a copy would only be stale, secret-bearing files.
BC_ROOT="$WORK/bc-root"
mkdir -p "$BC_ROOT/appfiles/echo-a" "$BC_ROOT/secrets" "$BC_ROOT/certs" "$BC_ROOT/templates/echo"
echo 'PORTCULLIS_DOMAIN=x' > "$BC_ROOT/.env"
echo '{"version":1,"instance":"echo-a","values":{"k":"APPFILE-MARKER"}}' > "$BC_ROOT/appfiles/echo-a/data.json"
echo k > "$BC_ROOT/secrets/k"
mkdir -p "$BC_ROOT/secrets/domains"
echo 198.51.99.7 > "$BC_ROOT/secrets/domains/last-public-ipv4"; echo 2a01:4f8::5 > "$BC_ROOT/secrets/domains/last-public-ipv6"
echo s > "$BC_ROOT/secrets/domains/api-secret"
echo RELAX_NOT_BEFORE=1 > "$BC_ROOT/secrets/domains/acme-relax.env"
# shellcheck disable=SC2034  # read by backup_create
( PORTCULLIS_ROOT="$BC_ROOT" BACKUP_ROOT="$BC_ROOT/backups" BACKUP_FILE_VOLUMES=""
  _BACKUP_CFG='{"services":{"hub":{"image":"hub:1"}}}'
  dc() { :; }; wait_healthy() { :; }; vault_wait_active() { :; }; vault_admin_env() { echo t; }
  _backup_vault_snapshot() { echo snap > "$1"; }; _backup_pg_dump() { echo PGDMP > "$1"; }
  _backup_metrics() { :; }
  backup_create ) >/dev/null 2>&1
BC_DIR="$(find "$BC_ROOT/backups" -mindepth 1 -maxdepth 1 -type d -name '2*' | head -n1)"
expect_ok "backup: a backup was made" test -f "$BC_DIR/MANIFEST.json"
expect_ok "backup: secrets/ archived (sanity)" test -f "$BC_DIR/secrets/k"
expect_eq "backup: last-public-ipv* never archived (host-specific), the rest of secrets/domains is" \
  "$(find "$BC_DIR/secrets/domains" -name 'last-public-*' | wc -l | tr -d ' '):$(cat "$BC_DIR/secrets/domains/api-secret"):$(jq -r '.files | keys[] | select(test("last-public"))' "$BC_DIR/MANIFEST.json")" "0:s:"
expect_ok "backup: the live last-public-ipv* stay" test -f "$BC_ROOT/secrets/domains/last-public-ipv4"
expect_eq "backup: the flip's settle point (acme-relax.env) never archived, the live one stays" \
  "$([ -e "$BC_DIR/secrets/domains/acme-relax.env" ] && echo archived):$(jq -r '.files | keys[] | select(test("acme-relax"))' "$BC_DIR/MANIFEST.json"):$([ -e "$BC_ROOT/secrets/domains/acme-relax.env" ] && echo live)" "::live"
expect_fail "backup: appfiles/ not archived" sh -c "find '$BC_DIR' -path '*appfiles*' | grep -q . || grep -rq APPFILE-MARKER '$BC_DIR'"
expect_eq "backup: appfiles/ not in the manifest" "$(jq -r '.files | keys[] | select(test("appfiles"))' "$BC_DIR/MANIFEST.json")" ""

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

# Keycloak LDAP federation: no user cache (group/attribute changes in LLDAP
# visible immediately) in the realm export AND enforced on existing realms
# by `keycloak configure` (_kc_ldap_patch), idempotently.
# shellcheck source=../scripts/lib/keycloak.sh
source "$HERE/../scripts/lib/keycloak.sh"
expect_eq "realm export: LDAP federation cachePolicy NO_CACHE" \
  "$(jq -r '.components["org.keycloak.storage.UserStorageProvider"][] | select(.providerId == "ldap") | .config.cachePolicy | join(",")' "$HERE/../keycloak/realm-export.json")" NO_CACHE
# AI support (contract §8 "Connection length and rotation"): the realm's
# offline upper bounds (the Hub sets shorter per-client values); refresh-token
# rotation pinned off (realm-wide it breaks concurrent forward-auth
# refreshes: e2e-login refresh_rotation), in the export AND pushed onto
# existing realms by configure.
expect_eq "realm export: offline session bounds 30 d idle / 90 d max, no refresh-token rotation" \
  "$(jq -c '[.offlineSessionIdleTimeout, .offlineSessionMaxLifespanEnabled, .offlineSessionMaxLifespan, .revokeRefreshToken, .refreshTokenMaxReuse]' "$HERE/../keycloak/realm-export.json")" \
  '[2592000,true,7776000,false,0]'
expect_eq "keycloak configure: the same realm token settings" "$(printf '%s' "$KC_REALM_TOKEN_SETTINGS" | jq -cS .)" \
  '{"offlineSessionIdleTimeout":2592000,"offlineSessionMaxLifespan":7776000,"offlineSessionMaxLifespanEnabled":true,"refreshTokenMaxReuse":0,"revokeRefreshToken":false}'
COMP='{"id":"x","providerId":"ldap","config":{"cachePolicy":["DEFAULT"],"editMode":["READ_ONLY"],"trustEmail":["true"]}}'
P1="$(printf '%s' "$COMP" | LLDAP_PASS=pw _kc_ldap_patch dc=ex,dc=org)"
expect_eq "keycloak configure: existing realm patched to NO_CACHE" "$(printf '%s' "$P1" | jq -r '.config.cachePolicy | join(",")')" NO_CACHE
expect_eq "keycloak configure: other provider settings kept" "$(printf '%s' "$P1" | jq -c '[.id, .config.editMode, .config.trustEmail, .config.bindDn, .config.bindCredential]')" \
  '["x",["READ_ONLY"],["false"],["uid=admin,ou=people,dc=ex,dc=org"],["pw"]]'
expect_eq "keycloak configure: LDAP patch idempotent" "$(printf '%s' "$P1" | LLDAP_PASS=pw _kc_ldap_patch dc=ex,dc=org | jq -cS .)" "$(printf '%s' "$P1" | jq -cS .)"

# Users / groups deleted in LLDAP leave Keycloak: removeInvalidUsersEnabled,
# hourly full sync, group mapper drops missing groups — in the export and
# enforced by configure, idempotently; READ_ONLY kept (never writes LDAP).
LDAPC='.components["org.keycloak.storage.UserStorageProvider"][] | select(.providerId == "ldap")'
expect_eq "realm export: removeInvalidUsersEnabled, hourly full sync, READ_ONLY" \
  "$(jq -c "$LDAPC | .config | [.removeInvalidUsersEnabled, .fullSyncPeriod, .editMode, .customUserSearchFilter]" "$HERE/../keycloak/realm-export.json")" \
  '[["true"],["3600"],["READ_ONLY"],["(!(uid=portcullis-hub))"]]'
expect_eq "realm export: group mapper drops groups gone from LLDAP" \
  "$(jq -c "$LDAPC"' | .subComponents["org.keycloak.storage.ldap.mappers.LDAPStorageMapper"][] | select(.providerId == "group-ldap-mapper") | .config | [.["drop.non.existing.groups.during.sync"], .mode]' "$HERE/../keycloak/realm-export.json")" \
  '[["true"],["READ_ONLY"]]'
expect_eq "keycloak configure: existing realm gets removal + hourly sync + READ_ONLY" \
  "$(printf '%s' '{"config":{"removeInvalidUsersEnabled":["false"],"fullSyncPeriod":["604800"],"editMode":["WRITABLE"]}}' | LLDAP_PASS=pw _kc_ldap_patch dc=ex,dc=org | jq -c '.config | [.removeInvalidUsersEnabled, .fullSyncPeriod, .editMode]')" \
  '[["true"],["3600"],["READ_ONLY"]]'
# Keycloak links an LDAP user by LLDAP's immutable entryUUID, never the
# username (a re-created name is a new identity) — in the export and pushed
# onto existing realms by configure; username / RDN stay uid.
expect_eq "realm export: users linked by entryUUID, username / RDN uid" \
  "$(jq -c "$LDAPC | .config | [.uuidLDAPAttribute, .usernameLDAPAttribute, .rdnLDAPAttribute]" "$HERE/../keycloak/realm-export.json")" \
  '[["entryUUID"],["uid"],["uid"]]'
expect_eq "keycloak configure: existing realm re-linked by entryUUID, username / RDN kept" \
  "$(printf '%s' '{"config":{"uuidLDAPAttribute":["uid"],"usernameLDAPAttribute":["uid"],"rdnLDAPAttribute":["uid"]}}' | LLDAP_PASS=pw _kc_ldap_patch dc=ex,dc=org | jq -c '.config | [.uuidLDAPAttribute, .usernameLDAPAttribute, .rdnLDAPAttribute]')" \
  '[["entryUUID"],["uid"],["uid"]]'
GM='{"id":"g","providerId":"group-ldap-mapper","config":{"groups.dn":["ou=groups,dc=old"],"drop.non.existing.groups.during.sync":["false"],"group.name.ldap.attribute":["cn"]}}'
G1="$(printf '%s' "$GM" | _kc_group_mapper_patch dc=ex,dc=org)"
expect_eq "keycloak configure: group mapper patched" "$(printf '%s' "$G1" | jq -c '.config | [.["groups.dn"], .["drop.non.existing.groups.during.sync"], .mode, .["group.name.ldap.attribute"]]')" \
  '[["ou=groups,dc=ex,dc=org"],["true"],["READ_ONLY"],["cn"]]'
expect_eq "keycloak configure: group mapper patch idempotent" "$(printf '%s' "$G1" | _kc_group_mapper_patch dc=ex,dc=org | jq -cS .)" "$(printf '%s' "$G1" | jq -cS .)"

# portcullis-forward-auth: configure sets the main callback and keeps the
# Hub's per-host extra-domain callbacks (forward-auth-ext, contract §5),
# nothing else; the export's placeholder host goes.
FWD='{"clientId":"portcullis-forward-auth","attributes":{"x":"1"},"defaultClientScopes":["groups"],"redirectUris":["https://auth.portcullis.local/oauth2/callback","https://grafana.team-b.example.org/oauth2/callback","https://x.team-b.example.org/oauth2/callback","https://evil.example.org/*","https://*.team-b.example.org/oauth2/callback","https://a.example.org/oauth2/callback/x","http://a.example.org/oauth2/callback","https://A.example.org/oauth2/callback","https://a.example.org:8443/oauth2/callback","https://a..example.org/oauth2/callback",7]}'
F1="$(printf '%s' "$FWD" | _kc_fwd_patch ex.org)"
expect_eq "keycloak configure: forward-auth redirect URIs = main callback + extra-domain callbacks" \
  "$(printf '%s' "$F1" | jq -c .redirectUris)" \
  '["https://auth.ex.org/oauth2/callback","https://grafana.team-b.example.org/oauth2/callback","https://x.team-b.example.org/oauth2/callback"]'
expect_eq "keycloak configure: forward-auth default acr removed (\"\"), PKCE S256 required, scopes kept" \
  "$(printf '%s' "$F1" | jq -c '[.attributes, .defaultClientScopes]')" '[{"x":"1","default.acr.values":"","pkce.code.challenge.method":"S256"},["acr","groups"]]'
expect_eq "keycloak configure: forward-auth patch idempotent" "$(printf '%s' "$F1" | _kc_fwd_patch ex.org | jq -cS .)" "$(printf '%s' "$F1" | jq -cS .)"
expect_eq "keycloak configure: placeholder kept when it is the domain" \
  "$(printf '%s' "$FWD" | _kc_fwd_patch portcullis.local | jq -c '.redirectUris[0:1]')" '["https://auth.portcullis.local/oauth2/callback"]'

# Invite IdP post-broker flow (contract §8): an invite login completes only
# for a client with the marker scope (portcullis-forward-auth), positive
# check + deny-unless-admitted (a missing scope or sub-flow denies), before
# the amr inv step; configure creates the scope (not a realm default).
EXP="$HERE/../keycloak/realm-export.json"
expect_eq "realm export: portcullis-invite-session = client check, deny, amr inv, template check" \
  "$(jq -c '[.authenticationFlows[] | select(.alias == "portcullis-invite-session") | .authenticationExecutions[] | [.priority, .requirement, (.flowAlias // .authenticator)]]' "$EXP")" \
  '[[10,"CONDITIONAL","portcullis-invite-client"],[20,"CONDITIONAL","portcullis-invite-deny"],[30,"REQUIRED","allow-access-authenticator"],[40,"REQUIRED","portcullis-template"]]'
# The setup link's session gets amr inv (contract §8 "Invite links"): no
# sign-in method, it meets no template; portcullis-template then writes
# the fresh note none (no stale pc_fresh) and refuses listed clients.
expect_eq "realm export: invite amr inv (10 h)" \
  "$(jq -c '.authenticatorConfig as $c | [.authenticationFlows[] | select(.alias == "portcullis-invite-session") | .authenticationExecutions[] | select(.authenticator == "allow-access-authenticator") | .authenticatorConfig as $a | $c[] | select(.alias == $a) | .config]' "$EXP")" \
  '[{"default.reference.value":"inv","default.reference.maxAge":"36000"}]'
expect_eq "realm export: invite client check = client scope condition (not negated) + allow" \
  "$(jq -c '.authenticatorConfig as $c | [.authenticationFlows[] | select(.alias == "portcullis-invite-client") | .authenticationExecutions[] | [.requirement, .authenticator, (.authenticatorConfig as $a | $c[] | select(.alias == $a) | .config)]]' "$EXP")" \
  "[[\"REQUIRED\",\"conditional-client-scope\",{\"client_scope\":\"$KC_INVITE_CLIENT_SCOPE\",\"negate\":\"false\"}],[\"REQUIRED\",\"allow-access-authenticator\"]]"
expect_eq "realm export: invite deny = not-executed(portcullis-invite-client) + deny" \
  "$(jq -c '.authenticatorConfig as $c | [.authenticationFlows[] | select(.alias == "portcullis-invite-deny") | .authenticationExecutions[] | [.requirement, .authenticator, (.authenticatorConfig as $a | $c[] | select(.alias == $a) | .config | del(.denyErrorMessage))]]' "$EXP")" \
  '[["REQUIRED","conditional-sub-flow-executed",{"flow_to_check":"portcullis-invite-client","check_result":"not-executed"}],["REQUIRED","deny-access-authenticator",{}]]'
expect_eq "realm export: the marker scope is no realm default" \
  "$(jq -c '[(.defaultDefaultClientScopes // [])[], (.defaultOptionalClientScopes // [])[], (.clients[] | (.defaultClientScopes // [])[], (.optionalClientScopes // [])[])] | map(select(. == "portcullis-invite-client"))' "$EXP")" '[]'
expect_eq "invite IdP: post-broker flow is portcullis-invite-session" \
  "$(jq -r .postBrokerLoginFlowAlias "$HERE/../keycloak/invite-idp.json")" portcullis-invite-session

# ── domains service files (scripts/lib/domains.sh, contract §12.1 / §12.4) ──
# shellcheck source=../scripts/lib/domains.sh
source "$HERE/../scripts/lib/domains.sh"
DR="$WORK/domroot"; mkdir -p "$DR/secrets"
mkdir -p "$WORK/dombin"
cat > "$WORK/dombin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
echo "$*" >> "$STUB_DIR/dom-calls"
case "$*" in
  *" keygen") printf '# created: x\n# public key: age1x\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n' ;;
esac
exit 0
STUB
chmod +x "$WORK/dombin/docker"
dom() { (set -euo pipefail; PATH="$WORK/dombin:$PATH" PORTCULLIS_ROOT="$DR" PORTCULLIS_PUBLIC_IPV4=203.0.113.9 PORTCULLIS_PUBLIC_IPV6='' "$@"); }
dom domains_prepare >/dev/null 2>&1; expect_eq "domains_prepare succeeds" "$?" 0
E="$DR/secrets/domains/certs-endpoint"
expect_ok "domains: api-secret >= 32 chars" test "$(wc -c < "$DR/secrets/domains/api-secret")" -ge 32
expect_ok "domains: age key generated by the domains image (offline)" grep -q '^AGE-SECRET-KEY-1' "$DR/secrets/domains/age.key"
expect_ok "domains: keygen ran without network" grep -q -- 'run --rm --network none .* portcullis-domains keygen' "$STUB_DIR/dom-calls"
expect_ok "domains: server cert signed by the endpoint CA" openssl verify -CAfile "$E/ca.crt" "$E/server.crt"
expect_ok "domains: client cert signed by the endpoint CA" openssl verify -CAfile "$E/ca.crt" "$E/client.crt"
expect_ok "domains: server cert SAN DNS:domains, serverAuth" sh -c "openssl x509 -in '$E/server.crt' -noout -text | grep -q 'DNS:domains' && openssl x509 -in '$E/server.crt' -noout -text | grep -q 'TLS Web Server Authentication'"
expect_ok "domains: client cert clientAuth" sh -c "openssl x509 -in '$E/client.crt' -noout -text | grep -q 'TLS Web Client Authentication'"
expect_ok "domains: ECDSA P-256" sh -c "openssl x509 -in '$E/server.crt' -noout -text | grep -qE 'prime256v1|P-256'"
expect_ok "domains: server/client valid until the CA expires (~10 years)" sh -c "openssl x509 -checkend $((3600*86400)) -noout -in '$E/server.crt' && openssl x509 -checkend $((3600*86400)) -noout -in '$E/client.crt' && ! openssl x509 -checkend $((3660*86400)) -noout -in '$E/client.crt'"
expect_eq "domains: public-ips.env written for compose (env_file)" "$(cat "$DR/secrets/domains/public-ips.env")" "DOMAINS_PUBLIC_IPV4=203.0.113.9
DOMAINS_PUBLIC_IPV6=
DOMAINS_MAIL=off"
expect_eq "domains: public-ips.env 0600" "$(file_mode "$DR/secrets/domains/public-ips.env")" 600
expect_ok "domains: CA valid ~10 years" sh -c "openssl x509 -checkend $((3600*86400)) -noout -in '$E/ca.crt'"
dom domains_fix_perms >/dev/null 2>&1
expect_eq "domains: ca.key operator-only" "$(file_mode "$E/ca.key")" 600
expect_eq "domains: server.key 0640" "$(file_mode "$E/server.key")" 640
expect_eq "domains: secrets/domains 0700" "$(file_mode "$DR/secrets/domains")" 700
S1="$(openssl x509 -noout -serial -in "$E/server.crt")"
RENEWED="$(dom eval 'domains_endpoint_certs >/dev/null; echo $DOMAINS_CERTS_RENEWED')"
expect_eq "domains: valid certificates are kept" "$RENEWED $(openssl x509 -noout -serial -in "$E/server.crt")" "false $S1"
# A certificate with < 30 days left is renewed and flags the restart.
(cd "$E" && openssl ecparam -name prime256v1 -genkey -noout -out short.key 2>/dev/null \
  && openssl req -new -key short.key -subj /CN=domains -out short.csr 2>/dev/null \
  && openssl x509 -req -in short.csr -CA ca.crt -CAkey ca.key -set_serial 7 -days 10 -out server.crt 2>/dev/null && mv short.key server.key && rm -f short.csr)
RENEWED="$(dom eval 'domains_endpoint_certs >/dev/null; echo $DOMAINS_CERTS_RENEWED')"
expect_eq "domains: expiring server certificate renewed, restart flagged" "$RENEWED" true
expect_ok "domains: renewed certificate valid until the CA expires" openssl x509 -checkend $((3600*86400)) -noout -in "$E/server.crt"
# Renewed certificates: domains restarts first, healthy, then traefik.
# shellcheck disable=SC2034  # read by domains_restart_if_renewed
expect_eq "domains: restart order after a renewal" "$(dc() { echo "dc $*" >> "$STUB_DIR/restart-calls"; }; wait_healthy() { echo "wait $*" >> "$STUB_DIR/restart-calls"; }
  rm -f "$STUB_DIR/restart-calls"; DOMAINS_CERTS_RENEWED=true; domains_restart_if_renewed; paste -sd' ' "$STUB_DIR/restart-calls")" \
  "dc restart domains wait 120 domains dc restart traefik"
CA1="$(openssl x509 -noout -serial -in "$E/ca.crt")"
: > "$STUB_DIR/dom-calls"
dom domains_prepare >/dev/null 2>&1
expect_eq "domains: re-run keeps the CA and age key (no keygen)" "$(openssl x509 -noout -serial -in "$E/ca.crt") $(grep -c keygen "$STUB_DIR/dom-calls")" "$CA1 0"
expect_eq "domains: public IPs exported for compose" "$(dom eval 'domains_public_ips; echo "$PORTCULLIS_PUBLIC_IPV4/$PORTCULLIS_PUBLIC_IPV6"')" "203.0.113.9/"

# ── mcp-gate files (scripts/lib/mcpgate.sh, contract §15 "Service, networks and secrets") ──
# shellcheck source=../scripts/lib/mcpgate.sh
source "$HERE/../scripts/lib/mcpgate.sh"
MR="$WORK/mcproot"; mkdir -p "$MR/secrets"
mkdir -p "$WORK/mcpbin"
cat > "$WORK/mcpbin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
echo "$*" >> "$STUB_DIR/mcp-calls"
case "$*" in
  *" keygen") printf '# created: 2026-11-05T10:00:00Z\n# public key: age1mcpgatetestrecipientqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\nAGE-SECRET-KEY-1MCPGATETESTQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n' ;;
esac
exit 0
STUB
chmod +x "$WORK/mcpbin/docker"
mcp() { (set -euo pipefail; PATH="$WORK/mcpbin:$PATH" PORTCULLIS_ROOT="$MR" "$@"); }
: > "$STUB_DIR/mcp-calls"
MOUT="$(mcp mcpgate_ensure_secrets 2>&1)"; expect_eq "mcpgate_ensure_secrets succeeds" "$?" 0
M="$MR/secrets/mcp-gate"
expect_ok "mcp-gate: age key generated by the mcp-gate image (offline)" grep -q '^AGE-SECRET-KEY-1' "$M/age.key"
expect_ok "mcp-gate: keygen ran without network, read-only, as 10005" \
  grep -q -- 'run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 10005:10005 portcullis-mcp-gate keygen' "$STUB_DIR/mcp-calls"
expect_eq "mcp-gate: age.pub = the key's recipient" "$(cat "$M/age.pub")" "age1mcpgatetestrecipientqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
expect_ok "mcp-gate: hub-secret is 48 random [A-Za-z0-9]" grep -Eqx '[A-Za-z0-9]{48}' "$M/hub-secret"
expect_eq "mcp-gate: secrets/mcp-gate 0700" "$(file_mode "$M")" 700
expect_eq "mcp-gate: age.key 0640" "$(file_mode "$M/age.key")" 640
expect_eq "mcp-gate: age.pub 0640" "$(file_mode "$M/age.pub")" 640
expect_eq "mcp-gate: hub-secret 0640" "$(file_mode "$M/hub-secret")" 640
# Groups go through the helper container (the stub): key → 10005, pub + secret → 10001.
expect_ok "mcp-gate: age.key group 10005 (the gate only)" grep -qE "src=$M/age.key,dst=/t/0 .* chown $(id -u):10005 /t/0\$" "$STUB_DIR/mcp-calls"
expect_ok "mcp-gate: age.pub + hub-secret group 10001 (Hub; the gate through group_add)" \
  grep -qE "src=$M/age.pub,dst=/t/0 --mount type=bind,src=$M/hub-secret,dst=/t/1 .* chown $(id -u):10001 /t/0 /t/1\$" "$STUB_DIR/mcp-calls"
expect_fail "mcp-gate: age.key never gets group 10001" grep -qE "src=$M/age.key,.* chown $(id -u):10001 " "$STUB_DIR/mcp-calls"
SECRET_NOW="$(cat "$M/hub-secret")"; KEY_NOW="$(grep '^AGE-SECRET-KEY-1' "$M/age.key")"
case "$MOUT" in *"$SECRET_NOW"*|*"$KEY_NOW"*|*AGE-SECRET-KEY*) t_fail "mcp-gate: a secret was printed" ;; *) t_pass "mcp-gate: no secret printed" ;; esac
: > "$STUB_DIR/mcp-calls"
MOUT="$(mcp mcpgate_ensure_secrets 2>&1)"
expect_eq "mcp-gate: re-run keeps the key, recipient and secret (no keygen)" \
  "$(cat "$M/hub-secret") $(grep '^AGE-SECRET-KEY-1' "$M/age.key") $(cat "$M/age.pub") $(grep -c keygen "$STUB_DIR/mcp-calls")" \
  "$SECRET_NOW $KEY_NOW age1mcpgatetestrecipientqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq 0"
case "$MOUT" in *"$SECRET_NOW"*|*AGE-SECRET-KEY*) t_fail "mcp-gate: a secret was printed on re-run" ;; *) t_pass "mcp-gate: no secret printed on re-run" ;; esac
# A lost or stale recipient is rewritten from the key; a short secret is replaced.
rm -f "$M/age.pub"; printf 'short' > "$M/hub-secret"
HS_INO="$(file_inode "$M/hub-secret")"
mcp mcpgate_ensure_secrets >/dev/null 2>&1
expect_eq "mcp-gate: hub-secret regenerated in place (the binds keep its inode)" "$(file_inode "$M/hub-secret")" "$HS_INO"
expect_eq "mcp-gate: missing age.pub rebuilt from age.key" "$(cat "$M/age.pub")" "age1mcpgatetestrecipientqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
expect_ok "mcp-gate: a hub-secret under 32 characters is regenerated" grep -Eqx '[A-Za-z0-9]{48}' "$M/hub-secret"
echo 'age1stale' > "$M/age.pub"
PUB_INO="$(file_inode "$M/age.pub")"
mcp mcpgate_ensure_secrets >/dev/null 2>&1
expect_eq "mcp-gate: age.pub rewritten in place (the Hub's bind keeps its inode)" "$(file_inode "$M/age.pub")" "$PUB_INO"
expect_eq "mcp-gate: stale age.pub rewritten" "$(cat "$M/age.pub")" "age1mcpgatetestrecipientqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
# A key without its recipient line: refuse (never guess, never regenerate over it).
printf 'AGE-SECRET-KEY-1XYZ\n' > "$M/age.key"
expect_fail "mcp-gate: an age.key without '# public key:' fails" mcp mcpgate_ensure_secrets
expect_eq "mcp-gate: ... and is kept" "$(cat "$M/age.key")" "AGE-SECRET-KEY-1XYZ"
case "$(mcp mcpgate_ensure_secrets 2>&1)" in
  *"never re-keys them"*"every AI resource would answer 503"*) t_pass "mcp-gate: the missing-recipient message says the gate refuses, not that the Hub re-mints" ;;
  *) t_fail "mcp-gate: missing-recipient message" ;;
esac
# A lost key with a recipient left from it: regenerated, with the warning
# that every AI resource answers 503 (docs review M4).
rm -f "$M/age.key"
MOUT="$(mcp mcpgate_ensure_secrets 2>&1)"
case "$MOUT" in
  *"was missing and has been regenerated"*"every AI resource answers 503"*"switch each app_token AI companion off and on"*) t_pass "mcp-gate: a regenerated key over an old recipient warns" ;;
  *) t_fail "mcp-gate: regenerated key warning: $MOUT" ;;
esac
case "$MOUT" in *"mints new"*) t_fail "mcp-gate: says the Hub mints new credentials" ;; *) t_pass "mcp-gate: never claims the Hub re-mints" ;; esac
expect_eq "mcp-gate: data volume owner = gate uid, Hub group" "$CT_UID_MCP_GATE:$CT_UID_HUB" "10005:10001"

# ── session store (scripts/lib/sessions.sh, oauth2-proxy #3486) ──
# shellcheck source=../scripts/lib/sessions.sh
source "$HERE/../scripts/lib/sessions.sh"
SR="$WORK/sessroot"; mkdir -p "$SR/secrets" "$WORK/sessbin"
cat > "$WORK/sessbin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
echo "$*" >> "$STUB_DIR/sess-calls"
case "$*" in *" ps -q --status running sessions") [ -f "$STUB_DIR/sess-running" ] && echo abc123 ;; esac
exit 0
STUB
chmod +x "$WORK/sessbin/docker"
SP1="Aa1$(gen_alnum 37)"; SP2="Bb2$(gen_alnum 37)"
sess() { (set -euo pipefail; PATH="$WORK/sessbin:$PATH" PORTCULLIS_ROOT="$SR" FORWARD_AUTH_REDIS_PASSWORD="$SP1" FORWARD_AUTH_EXT_REDIS_PASSWORD="$SP2" "$@"); }
: > "$STUB_DIR/sess-calls"
SOUT="$(sess sessions_prepare 2>&1)"; expect_eq "sessions_prepare succeeds" "$?" 0
SC="$SR/secrets/sessions/valkey.conf"
expect_eq "sessions: secrets/sessions 0700, valkey.conf 0640" "$(file_mode "$SR/secrets/sessions") $(file_mode "$SC")" "700 640"
expect_ok "sessions: valkey.conf group 1000 (the image's valkey group) through the helper" \
  grep -qE "src=$SC,dst=/t/0 .* chown $(id -u):1000 /t/0\$" "$STUB_DIR/sess-calls"
H1="$(printf '%s' "$SP1" | openssl dgst -sha256 -r | cut -d' ' -f1)"; H2="$(printf '%s' "$SP2" | openssl dgst -sha256 -r | cut -d' ' -f1)"
CMDS="-@all +ping +get +set +del +evalsha +eval +msetnx +mset +getrange +pexpire +mget"
expect_eq "sessions: the default user is off with no password, keys, channels or commands" \
  "$(grep '^user default ' "$SC")" "user default off resetpass resetkeys resetchannels -@all"
expect_eq "sessions: forward-auth = its own ticket keys + the commands oauth2-proxy sends, by password hash" \
  "$(grep '^user forward-auth ' "$SC")" "user forward-auth on resetpass resetkeys resetchannels $CMDS ~_oauth2_proxy-* #$H1"
expect_eq "sessions: forward-auth-ext = its own (__Host-portcullis_ext) ticket keys, same commands" \
  "$(grep '^user forward-auth-ext ' "$SC")" "user forward-auth-ext on resetpass resetkeys resetchannels $CMDS ~__Host-portcullis_ext-* #$H2"
expect_eq "sessions: exactly three users" "$(grep -c '^user ' "$SC")" 3
expect_eq "sessions: no persistence, bounded memory, TTL eviction" \
  "$(grep -E '^(save|appendonly|maxmemory|maxmemory-policy|dir|enable-debug-command|enable-module-command) ' "$SC" | paste -sd'|' -)" \
  'save ""|appendonly no|dir /data|maxmemory 64mb|maxmemory-policy volatile-ttl|enable-debug-command no|enable-module-command no'
if grep -qiE '(^| )(\+@all|allcommands|allkeys|~\*|nopass|>)|\+(flushall|flushdb|keys|scan|config|debug|acl|client|shutdown|module|script|function|monitor|subscribe|psubscribe|select|swapdb|migrate|restore|replicaof|slaveof|sync|psync|bgsave|save|bgrewriteaof)( |$)' <(grep '^user ' "$SC"); then
  t_fail "sessions: a broad or dangerous grant in the ACL"
else
  t_pass "sessions: no broad / dangerous grant, no cleartext password (>), no nopass"
fi
case "$(cat "$SC") $SOUT" in *"$SP1"*|*"$SP2"*) t_fail "sessions: a password in valkey.conf or the output" ;; *) t_pass "sessions: the passwords are neither in valkey.conf nor printed" ;; esac
rm -f "$SC"
expect_eq "sessions: a first write flags the change" "$(sess eval 'sessions_prepare >/dev/null; echo $SESSIONS_CONF_CHANGED')" true
INO="$(file_inode "$SC")"; BEFORE_CONF="$(cat "$SC")"
expect_eq "sessions: an unchanged config is not rewritten (no restart)" "$(sess eval 'sessions_prepare >/dev/null; echo $SESSIONS_CONF_CHANGED'):$(cat "$SC")" "false:$BEFORE_CONF"
SP1="Cc3$(gen_alnum 37)"
expect_eq "sessions: a rotated password rewrites the config and flags it" "$(sess eval 'sessions_prepare >/dev/null; echo $SESSIONS_CONF_CHANGED')" true
expect_eq "sessions: rewritten in place (same inode: the running container's bind mount)" "$(file_inode "$SC")" "$INO"
expect_ok "sessions: ... with the new hash" grep -qF "#$(printf '%s' "$SP1" | openssl dgst -sha256 -r | cut -d' ' -f1)" "$SC"
expect_eq "sessions: no temp file left" "$(find "$SR/secrets/sessions" -name '.valkey.conf.*' | wc -l | tr -d ' ')" 0
rc=0; (PATH="$WORK/sessbin:$PATH" PORTCULLIS_ROOT="$SR" FORWARD_AUTH_REDIS_PASSWORD='' FORWARD_AUTH_EXT_REDIS_PASSWORD="$SP2" sessions_prepare) >/dev/null 2>&1 || rc=$?
expect_eq "sessions: a missing password fails (never a default)" "$rc" 1
# HA (plan Task 25): secrets/sessions-ha/ for the Valkey pods and the
# Sentinels (ha.sh kube_sessions_ha_prepare).
sess eval 'kube_sessions_ha_prepare' >/dev/null 2>&1; expect_eq "sessions HA: kube_sessions_ha_prepare succeeds" "$?" 0
SH="$SR/secrets/sessions-ha"
expect_eq "sessions HA: secrets/sessions-ha 0700, its four files 0600" \
  "$(file_mode "$SH") $(file_mode "$SH/internal") $(file_mode "$SH/valkey.conf") $(file_mode "$SH/sentinel.conf") $(file_mode "$SH/sentinel-monitor.conf")" "700 600 600 600 600"
IPW="$(cat "$SH/internal")"; HI="$(printf '%s' "$IPW" | openssl dgst -sha256 -r | cut -d' ' -f1)"
HF1="$(printf '%s' "$SP1" | openssl dgst -sha256 -r | cut -d' ' -f1)"; HF2="$(printf '%s' "$SP2" | openssl dgst -sha256 -r | cut -d' ' -f1)"
expect_ok "sessions HA: the internal password is 40 alphanumerics" grep -qxE '[A-Za-z0-9]{40}' <<< "$IPW"
expect_eq "sessions HA: valkey.conf = the base users + the replica's link user + the Sentinels' user, masteruser / masterauth" \
  "$(grep -c '^user ' "$SH/valkey.conf"):$(grep '^user sessions-repl ' "$SH/valkey.conf"):$(grep -c "^masteruser sessions-repl$" "$SH/valkey.conf"):$(grep -cxF "masterauth $IPW" "$SH/valkey.conf")" \
  "5:user sessions-repl on resetpass resetkeys resetchannels -@all +psync +replconf +ping #$HI:1:1"
expect_eq "sessions HA: the Sentinels' user on Valkey = what a Sentinel sends (valkey 9.1.3 src/sentinel.c), its hello channel, no key" \
  "$(grep '^user sessions-admin ' "$SH/valkey.conf")" \
  "user sessions-admin on resetpass resetkeys resetchannels -@all +multi +exec +slaveof +replicaof +failover +ping +info +role +config|rewrite +client|setname +client|kill +script|kill +subscribe +publish &__sentinel__:hello #$HI"
expect_eq "sessions HA: the Sentinels' default user = both oauth2-proxies' passwords, only go-redis's failover commands and channels" \
  "$(grep '^user default ' "$SH/sentinel.conf")" \
  "user default on resetpass resetkeys resetchannels &+switch-master &+replica-reconf-done -@all +ping +subscribe +sentinel|get-master-addr-by-name +sentinel|sentinels +sentinel|replicas #$HF1 #$HF2"
if grep '^user default ' "$SH/sentinel.conf" | grep -qiE '\+sentinel( |$)|\+sentinel\|(failover|set|monitor|remove|reset|flushconfig|config|debug)|\+@all|allchannels|nopass|>'; then
  t_fail "sessions HA: the Sentinels' default user may fail over / reconfigure"
else t_pass "sessions HA: the Sentinels' default user can't fail over, set, monitor, remove or reset"; fi
expect_eq "sessions HA: the peers / guard user and the Sentinel names (hostnames)" \
  "$(grep -cE "^(user sessions-admin on resetpass resetkeys allchannels \+@all #$HI|sentinel sentinel-user sessions-admin|sentinel sentinel-pass $IPW|sentinel resolve-hostnames yes|sentinel announce-hostnames yes|port 26379)$" "$SH/sentinel.conf")" 6
expect_eq "sessions HA: the monitor tail: master portcullis-sessions, auth, 5 s down-after, 60 s failover timeout" \
  "$(paste -sd'|' "$SH/sentinel-monitor.conf")" \
  "sentinel auth-user portcullis-sessions sessions-admin|sentinel auth-pass portcullis-sessions $IPW|sentinel down-after-milliseconds portcullis-sessions 5000|sentinel failover-timeout portcullis-sessions 60000|sentinel parallel-syncs portcullis-sessions 1"
case "$(cat "$SH"/*.conf)" in *"$SP1"*|*"$SP2"*) t_fail "sessions HA: an oauth2-proxy's password in the HA configs" ;; *) t_pass "sessions HA: the oauth2-proxies' passwords only as hashes" ;; esac
sess eval 'kube_sessions_ha_prepare' >/dev/null 2>&1
expect_eq "sessions HA: the internal password is made once (kept on the next run)" "$(cat "$SH/internal")" "$IPW"
printf 'short' > "$SH/internal"
sess eval 'kube_sessions_ha_prepare' >/dev/null 2>&1
expect_ok "sessions HA: a malformed internal password is replaced" grep -qxE '[A-Za-z0-9]{40}' "$SH/internal"
expect_eq "sessions HA: no temp file left" "$(find "$SH" -name '.*' -type f | wc -l | tr -d ' ')" 0
# HA (plan Task 25, Amendment 2): the session store's init guard
# (charts/portcullis/files/sessions-ha/guard.sh) never elects itself.
GD="$WORK/guard"; rm -rf "$GD"; mkdir -p "$GD/bin"
cat > "$GD/bin/valkey-cli" <<'GSTUB'
#!/bin/sh
# Sentinel answers from $GD_DIR: master (its name, or empty), replicas, after-failover.
echo "$*" >> "$GD_DIR/calls"
case "$*" in
  *"sentinel get-master-addr-by-name portcullis-sessions")
    # Per Sentinel (master-<n>: that one's own answer, "-" = silent), else the common one.
    h="$*"; h="${h#*-h sessions-sentinel-}"; f="$GD_DIR/master-${h%%.*}"
    [ -e "$f" ] || f="$GD_DIR/master"
    [ -s "$f" ] && [ "$(cat "$f")" != - ] || exit 0
    if [ -e "$GD_DIR/failed-over" ]; then [ -e "$GD_DIR/silent-after" ] && exit 0; cat "$GD_DIR/after"; else cat "$f"; echo; fi; echo 6379 ;;
  *"-p 6379 info replication") [ -s "$GD_DIR/peer" ] || exit 1; cat "$GD_DIR/peer" ;;
  *"sentinel failover portcullis-sessions") [ -e "$GD_DIR/no-failover" ] || touch "$GD_DIR/failed-over"; echo OK ;;
esac
GSTUB
printf '#!/bin/sh\nexit 0\n' > "$GD/bin/sleep"
chmod +x "$GD/bin/valkey-cli" "$GD/bin/sleep"
guard() { # guard <master answer> <the other pod's INFO replication ("" = unreachable)> [after-failover master]
  rm -f "$GD/calls" "$GD/failed-over" "$GD/conf"; printf '%s' "$1" > "$GD/master"; printf '%s' "$2" > "$GD/peer"; printf '%s\n' "${3:-}" > "$GD/after"
  rm -f "$GD/term"
  ( export PATH="$GD/bin:$PATH" GD_DIR="$GD" POD_NAMESPACE=portcullis POD_NAME=sessions-1 GUARD_WAIT=3 GUARD_CONF="$GD/conf" GUARD_TERMLOG="$GD/term"
    sh "$HERE/../charts/portcullis/files/sessions-ha/guard.sh" ) >/dev/null 2>&1; echo "rc=$?"
}
P0=sessions-0.sessions-pods.portcullis.svc.cluster.local P1=sessions-1.sessions-pods.portcullis.svc.cluster.local
REP0="$(printf '# Replication\r\nrole:slave\r\nmaster_link_status:down\r\nmaster_repl_offset:133960\r\n')"
expect_eq "sessions guard: the Sentinels name another master → this pod replicates from it" \
  "$(guard "$P0" "")$(grep -c "^replicaof $P0 6379$" "$GD/conf")$(grep -c '^include /etc/valkey-ha/valkey.conf$' "$GD/conf")" "rc=011"
expect_eq "sessions guard: named itself (a fast restart, empty), the other pod a replica holding data (asked directly; its link down) → SENTINEL FAILOVER first, then a replica of the new master" \
  "$(guard "$P1" "$REP0" "$P0")$(grep -c 'sentinel failover portcullis-sessions' "$GD/calls")$(grep -c "^replicaof $P0 6379$" "$GD/conf")" "rc=011"
expect_eq "sessions guard: named itself, the Sentinels never fail over (a replica they refuse) → asked first, then the master after the wait (sign-in over the sessions)" \
  "$(touch "$GD/no-failover"; guard "$P1" "$REP0" "$P0"; rm -f "$GD/no-failover")$(grep -c 'sentinel failover portcullis-sessions' "$GD/calls")$(grep -c '^replicaof' "$GD/conf")$(grep -c '^include ' "$GD/conf")" "rc=0101"
expect_eq "sessions guard: named itself, the other pod unreachable or never replicated → the master (nothing to lose)" \
  "$(guard "$P1" "")$(grep -c '^replicaof' "$GD/conf")$(guard "$P1" "$(printf '%s' "$REP0" | sed 's/:133960/:0/')")$(grep -c '^replicaof' "$GD/conf")" "rc=00rc=00"
expect_eq "sessions guard: named itself while the other pod is a master with data → refused (exit 1), never two masters" \
  "$(guard "$P1" "$(printf '%s' "$REP0" | sed 's/role:slave/role:master/')")$(test -e "$GD/conf" && echo conf || echo noconf)" "rc=1noconf"
expect_eq "sessions guard: no Sentinel answers → refused (exit 1: never a second master), no config written" \
  "$(guard "" "")$(test -e "$GD/conf" && echo conf || echo noconf)" "rc=1noconf"
expect_eq "sessions guard: a Sentinel naming a host that isn't one of the two Valkey pods is ignored (refused)" \
  "$(guard "evil.example.org" "")" "rc=1"
expect_eq "sessions guard: every Sentinel silent after the FAILOVER → refused (exit 1), never a master config (review I1)" \
  "$(touch "$GD/silent-after"; guard "$P1" "$REP0" "$P0"; rm -f "$GD/silent-after")$(test -e "$GD/conf" && echo conf || echo noconf)" "rc=1noconf"
expect_eq "sessions guard: one Sentinel alone names another master (the others silent) → no two agreeing answers, refused (review M2)" \
  "$(printf '%s' - > "$GD/master-1"; printf '%s' - > "$GD/master-2"; guard "$P0" ""; rm -f "$GD"/master-[012])$(test -e "$GD/conf" && echo conf || echo noconf)" "rc=1noconf"
expect_eq "sessions guard: two of three Sentinels agree (the third names this pod) → the two decide: a replica of their master" \
  "$(printf '%s' "$P1" > "$GD/master-2"; guard "$P0" ""; rm -f "$GD"/master-[012])$(grep -c "^replicaof $P0 6379$" "$GD/conf")" "rc=01"
expect_eq "sessions guard: the three Sentinels disagree (two name different pods) → refused with the named error (the termination message the status and HA page show)" \
  "$(printf '%s' "$P1" > "$GD/master-1"; printf '%s' - > "$GD/master-2"; guard "$P0" ""; rm -f "$GD"/master-[012])$(grep -c '^portcullis-sessions: the Sentinels disagree on the master' "$GD/term")" "rc=11"
t0="$(date +%s)"; guard "" "" >/dev/null
expect_eq "sessions guard: the wait counts real seconds (GUARD_WAIT 3 → refused after 3-5 s, not 4 rounds of 2)" "$(( $(date +%s) - t0 >= 3 && $(date +%s) - t0 <= 6 ))" 1
# sentinel-init (review M-b): two agreeing other Sentinels decide; a split
# between them is a named error and the Valkey pods' own master decides;
# exactly one answering with no Valkey reachable is followed; else sessions-0.
SI="$WORK/sinit"; rm -rf "$SI"; mkdir -p "$SI/bin" "$SI/parts"; : > "$SI/parts/sentinel.conf"; : > "$SI/parts/sentinel-monitor.conf"
cat > "$SI/bin/valkey-cli" <<'SISTUB'
#!/bin/sh
h="$*"; h="${h#*-h }"; h="${h%% *}"
case "$*" in
  *"sentinel get-master-addr-by-name"*) f="$SI_DIR/s-${h%%.*}"; [ -s "$f" ] || exit 0; cat "$f"; echo; echo 6379 ;;
  *"info replication"*) f="$SI_DIR/v-${h%%.*}"; [ -s "$f" ] || exit 1; cat "$f" ;;
esac
SISTUB
chmod +x "$SI/bin/valkey-cli"
sinit() { # sinit <sentinel-1 answer> <sentinel-2 answer> <sessions-0 INFO> <sessions-1 INFO>
  rm -f "$SI"/s-* "$SI"/v-* "$SI/out" "$SI/term"
  printf '%s' "$1" > "$SI/s-sessions-sentinel-1"; printf '%s' "$2" > "$SI/s-sessions-sentinel-2"; printf '%s' "$3" > "$SI/v-sessions-0"; printf '%s' "$4" > "$SI/v-sessions-1"
  ( export PATH="$SI/bin:$PATH" SI_DIR="$SI" POD_NAMESPACE=portcullis POD_NAME=sessions-sentinel-0 SENTINEL_INIT_PARTS="$SI/parts" SENTINEL_INIT_OUT="$SI/out" SENTINEL_INIT_TERMLOG="$SI/term"
    sh "$HERE/../charts/portcullis/files/sessions-ha/sentinel-init.sh" ) >/dev/null 2>&1
  sed -n 's/^sentinel monitor portcullis-sessions \([^ .]*\).* 6379 2$/\1/p' "$SI/out"
}
MASTERINFO="$(printf 'role:master\r\nconnected_slaves:1\r\n')"
expect_eq "sentinel-init: both other Sentinels agree → their master" "$(sinit "$P1" "$P1" "$MASTERINFO" "")" sessions-1
expect_eq "sentinel-init: the other two disagree → a named error, and the Valkey pods' own master decides" "$(sinit "$P0" "$P1" "" "$MASTERINFO"):$(grep -c '^portcullis-sessions: the other two Sentinels disagree' "$SI/term")" "sessions-1:1"
expect_eq "sentinel-init: exactly one other Sentinel answers and no Valkey pod can be asked → follow it (never split from the one that's up)" "$(sinit "" "$P1" "" "")" sessions-1
expect_eq "sentinel-init: nobody answers → sessions-0 (a first start)" "$(sinit "" "" "" "")" sessions-0
expect_eq "sessions guard: the password never on valkey-cli's argv (VALKEYCLI_AUTH only)" "$(grep -c -- ' -a \| --pass ' "$GD/calls" || true)" 0
# Restart only a running store, only when its config changed, before compose up.
: > "$STUB_DIR/sess-calls"; rm -f "$STUB_DIR/sess-running"
sess eval 'SESSIONS_CONF_CHANGED=true; sessions_restart_if_changed' >/dev/null 2>&1
expect_fail "sessions: a store that isn't running is not restarted" grep -q 'restart sessions' "$STUB_DIR/sess-calls"
touch "$STUB_DIR/sess-running"
sess eval 'SESSIONS_CONF_CHANGED=false; sessions_restart_if_changed' >/dev/null 2>&1
expect_fail "sessions: an unchanged config restarts nothing" grep -q 'restart sessions' "$STUB_DIR/sess-calls"
sess eval 'SESSIONS_CONF_CHANGED=true; sessions_restart_if_changed' >/dev/null 2>&1
expect_ok "sessions: a changed config restarts the running store" grep -q 'compose --project-directory .* restart sessions$' "$STUB_DIR/sess-calls"
rm -f "$STUB_DIR/sess-running"
# stack_prepare renders it; secrets_fix_perms repairs its modes.
expect_ok "stack_prepare runs sessions_prepare" grep -q 'declare -F sessions_prepare' "$HERE/../scripts/lib/common.sh"
chmod 644 "$SC"; chmod 755 "$SR/secrets/sessions"
sess sessions_fix_perms >/dev/null 2>&1
expect_eq "sessions: fix_perms restores 0700 / 0640" "$(file_mode "$SR/secrets/sessions") $(file_mode "$SC")" "700 640"
expect_ok "sessions: the compose user matches CT_UID_SESSIONS:CT_GID_SESSIONS" \
  grep -qx "    user: \"$CT_UID_SESSIONS:$CT_GID_SESSIONS\"" "$HERE/../docker-compose.yml"

# ── public address detection (network.sh public_ip_detect; dns setup + domains) ──
mkdir -p "$WORK/ipbin" "$STUB_DIR/ip"
cat > "$WORK/ipbin/curl" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_DIR/ip-calls"
url="${*: -1}"
f="$STUB_DIR/ip/$(printf '%s' "$url" | tr -c 'A-Za-z0-9' '_')"
[ -f "$f" ] || exit 22
cat "$f"
STUB
chmod +x "$WORK/ipbin/curl"
ipans() { rm -f "$STUB_DIR"/ip/*; while [ $# -gt 0 ]; do printf '%s\n' "$2" > "$STUB_DIR/ip/$(printf '%s' "$1" | tr -c 'A-Za-z0-9' '_')"; shift 2; done; }
detect() { (PATH="$WORK/ipbin:$PATH"; public_ip_detect "$1"); }
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.7 https://ifconfig.me/ip 198.51.99.7
expect_eq "public ip: three HTTPS services agree" "$(detect 4)" 198.51.99.7
expect_ok "public ip: HTTPS only, TLS >= 1.2" sh -c "grep -q -- \"--proto =https --tlsv1.2\" '$STUB_DIR/ip-calls' && ! grep -q 'http://' '$STUB_DIR/ip-calls'"
ipans https://api.ipify.org 198.51.99.7 https://ifconfig.me/ip 198.51.99.7
expect_eq "public ip: two agreeing answers suffice" "$(detect 4)" 198.51.99.7
ipans https://api.ipify.org 198.51.99.7
expect_eq "public ip: one answer is not enough" "$(detect 4)" ""
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.8 https://ifconfig.me/ip 198.51.99.7
expect_eq "public ip: disagreement = nothing (fail closed)" "$(detect 4)" ""
for bad in 10.1.2.3 192.168.1.1 172.20.0.1 127.0.0.1 169.254.1.1 100.64.0.1 0.1.2.3 224.0.0.1 255.255.255.255 203.0.113.5 999.1.1.1 '<html>'; do
  ipans https://api.ipify.org "$bad" https://ipv4.icanhazip.com "$bad"
  expect_eq "public ip: refuses $bad" "$(detect 4)" ""
done
ipans https://api6.ipify.org 2a01:4f8:c0c:1::1 https://ipv6.icanhazip.com 2A01:4F8:C0C:1::1
expect_eq "public ip v6: agree (case-insensitive)" "$(detect 6)" 2a01:4f8:c0c:1::1
ipans https://api6.ipify.org 2a01:4f8:c0c:1::1 https://ipv6.icanhazip.com 2a01:4f8:c0c:1::1
expect_eq "public ip v6: agree" "$(detect 6)" 2a01:4f8:c0c:1::1
for bad in ::1 fe80::1 fd00::1 2001:db8::1 2001::1 ff02::1 '::ffff:1.2.3.4' 3fff:: '1.2.3.4'; do
  ipans https://api6.ipify.org "$bad" https://ipv6.icanhazip.com "$bad"
  expect_eq "public ip v6: refuses $bad" "$(detect 6)" ""
done
# The domains service: explicit values win; failed detection publishes nothing.
# dc stub: "domains enrolled" answers $STUB_DIR/enrolled (missing = not running).
pubips() { (PATH="$WORK/ipbin:$PATH"; dc() { [ -f "$STUB_DIR/enrolled" ] && cat "$STUB_DIR/enrolled"; }; "$@"; domains_public_ips 2>/dev/null; echo "$PORTCULLIS_PUBLIC_IPV4/$PORTCULLIS_PUBLIC_IPV6"); }
rm -f "$STUB_DIR/enrolled"
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.9
expect_eq "domains: no agreed IPv4 = none (no records)" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6)" "/"
expect_eq "domains: explicit IPv4 wins over detection" "$(pubips export PORTCULLIS_PUBLIC_IPV4=203.0.113.9 PORTCULLIS_PUBLIC_IPV6=)" "203.0.113.9/"
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.7 https://api6.ipify.org 2a01:4f8::5 https://ipv6.icanhazip.com 2a01:4f8::5
expect_eq "domains: detected IPv4 + IPv6" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6)" "198.51.99.7/2a01:4f8::5"

# The last detected address (last-public-ipv4 / -ipv6) is saved and used
# unless the running domains service confirms 0 domains; "unknown" (not
# running — `up` after a `down` —, an error) keeps it, so a transient IPv6
# failure never removes the AAAA records. Restore deletes the files
# (backup.sh _strip_host_files, tested with the backup below).
LASTD="$PORTCULLIS_ROOT/secrets/domains"
mkdir -p "$LASTD"
rm -f "$LASTD/last-public-ipv4" "$LASTD/last-public-ipv6"
lastn() { local n=0 f; for f in "$LASTD"/last-public-*; do [ -e "$f" ] && n=$((n + 1)); done; echo "$n"; }
expect_eq "domains: enrolled state: not running = unknown" "$(dc() { return 1; }; domains_enrolled_state)" unknown
expect_eq "domains: enrolled state: odd output = unknown" "$(dc() { echo 'oops'; }; domains_enrolled_state)" unknown
expect_eq "domains: enrolled state: 0 = none" "$(dc() { echo 0; }; domains_enrolled_state)" none
expect_eq "domains: enrolled state: 3 = enrolled" "$(dc() { echo 3; }; domains_enrolled_state)" enrolled
# A confirmed 0: a successful lookup saves nothing, a failed one publishes none.
echo 0 > "$STUB_DIR/enrolled"
: > "$STUB_DIR/ip-calls"
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.7 https://api6.ipify.org 2a01:4f8::5 https://ipv6.icanhazip.com 2a01:4f8::5
expect_eq "domains: no enrolled domain = lookups run, detected addresses published" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6)" "198.51.99.7/2a01:4f8::5"
expect_ok "domains: no enrolled domain = IPv4 and IPv6 looked up" sh -c "grep -q api.ipify.org '$STUB_DIR/ip-calls' && grep -q api6.ipify.org '$STUB_DIR/ip-calls'"
expect_eq "domains: no enrolled domain, no last-* written" "$(lastn)" 0
# Enrolled: a successful lookup saves them.
echo 2 > "$STUB_DIR/enrolled"
pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6 >/dev/null
expect_eq "domains: enrolled, last-* saved" "$(cat "$LASTD/last-public-ipv4")/$(cat "$LASTD/last-public-ipv6")" "198.51.99.7/2a01:4f8::5"
echo 0 > "$STUB_DIR/enrolled"
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.8
expect_eq "domains: confirmed 0, failed lookups = no address (not the last one)" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6 | tail -n1)" "/"
expect_eq "domains: confirmed 0, failed lookups write empty addresses" "$(cat "$PORTCULLIS_ROOT/secrets/domains/public-ips.env")" "DOMAINS_PUBLIC_IPV4=
DOMAINS_PUBLIC_IPV6=
DOMAINS_MAIL=off"
# Enrolled, a transient IPv6 / IPv4 detection failure keeps the last address.
echo 2 > "$STUB_DIR/enrolled"
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.7
expect_eq "domains: enrolled, IPv6 detection failure keeps the last address" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6)" "198.51.99.7/2a01:4f8::5"
expect_eq "domains: explicit empty IPv6 still means none" "$(pubips export PORTCULLIS_PUBLIC_IPV4=203.0.113.9 PORTCULLIS_PUBLIC_IPV6=)" "203.0.113.9/"
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.8
expect_eq "domains: enrolled, IPv4 detection failure keeps the last address" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6)" "198.51.99.7/2a01:4f8::5"
expect_eq "domains: the env file has the kept addresses" "$(cat "$PORTCULLIS_ROOT/secrets/domains/public-ips.env")" "DOMAINS_PUBLIC_IPV4=198.51.99.7
DOMAINS_PUBLIC_IPV6=2a01:4f8::5
DOMAINS_MAIL=off"
# `down` then `up` of an enrolled server: domains_prepare runs before the
# service starts (unknown); a transient IPv6 failure keeps the last IPv6
# (an empty one would remove the AAAA records at <d> and *.<d>).
rm -f "$STUB_DIR/enrolled"
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.7
expect_eq "domains: down/up (service unreachable), IPv6 failure keeps the last IPv6" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6)" "198.51.99.7/2a01:4f8::5"
ipans https://api.ipify.org 198.51.99.30 https://ipv4.icanhazip.com 198.51.99.30 https://api6.ipify.org 2a01:4f8::30 https://ipv6.icanhazip.com 2a01:4f8::30
pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6 >/dev/null
expect_eq "domains: service unreachable, a successful lookup updates last-*" "$(cat "$LASTD/last-public-ipv4")/$(cat "$LASTD/last-public-ipv6")" "198.51.99.30/2a01:4f8::30"
# A restored secrets/ (restore deleted last-*), the service down, failed
# lookups: no address at all, never the old server's.
# (an older backup still carrying them, restored into its own root)
mkdir -p "$WORK/rsec-backup/secrets/domains" "$WORK/rsec-root/secrets/domains"
cp "$LASTD/last-public-ipv4" "$LASTD/last-public-ipv6" "$WORK/rsec-backup/secrets/domains/"
echo keep > "$WORK/rsec-backup/secrets/domains/api-secret"
echo RELAX_NOT_BEFORE=1 > "$WORK/rsec-backup/secrets/domains/acme-relax.env"
echo RELAX_NOT_BEFORE=1900000000 > "$WORK/rsec-root/secrets/domains/acme-relax.env"
(PORTCULLIS_ROOT="$WORK/rsec-root"; secrets_fix_perms() { :; }; _restore_secrets "$WORK/rsec-backup")
expect_eq "restore: last-public-ipv* deleted, the live acme-relax.env kept (live DNS: a restore doesn't change it), the rest installed" \
  "$(find "$WORK/rsec-root/secrets" -name 'last-public-*' | wc -l | tr -d ' '):$(cat "$WORK/rsec-root/secrets/domains/acme-relax.env"):$(cat "$WORK/rsec-root/secrets/domains/api-secret")" "0:RELAX_NOT_BEFORE=1900000000:keep"
# secrets/kube/ (this host's cluster state: digests, values, the setup
# record) is never in a backup and never replaced: the live one stays, a
# stray one in the backup never lands.
mkdir -p "$WORK/rsec-root/secrets/kube" "$WORK/rsec-backup/secrets/kube"
echo '{"group-gate":"localhost/portcullis-group-gate@sha256:live"}' > "$WORK/rsec-root/secrets/kube/digests.json"
echo '{"group-gate":"from-the-backup"}' > "$WORK/rsec-backup/secrets/kube/digests.json"; echo stray > "$WORK/rsec-backup/secrets/kube/values.yaml"
(PORTCULLIS_ROOT="$WORK/rsec-root"; secrets_fix_perms() { :; }; _restore_secrets "$WORK/rsec-backup")
expect_eq "restore keeps this host's secrets/kube (digests.json) and installs none from the backup" \
  "$(cat "$WORK/rsec-root/secrets/kube/digests.json"):$(test -e "$WORK/rsec-root/secrets/kube/values.yaml" && echo stray || echo none):$(file_mode "$WORK/rsec-root/secrets/kube")" \
  '{"group-gate":"localhost/portcullis-group-gate@sha256:live"}:none:700'
# The same on this root (what restore leaves), then the first `up`.
_strip_host_files "$PORTCULLIS_ROOT/secrets"
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.8
expect_eq "domains: restored secrets/, service down, failed lookups = no address" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6 | tail -n1)" "/"
: > "$STUB_DIR/ip-calls"
expect_eq "domains: .env set = .env" "$(pubips export PORTCULLIS_PUBLIC_IPV4=203.0.113.44 PORTCULLIS_PUBLIC_IPV6=2a01:4f8::44 | tail -n1)" "203.0.113.44/2a01:4f8::44"
expect_eq "domains: .env set = no lookups" "$(wc -l < "$STUB_DIR/ip-calls" | tr -d ' ')" 0

# ══ backup: hub_secrets volume ═════════════════════════════
# shellcheck source=../scripts/lib/backup.sh
source "$HERE/../scripts/lib/backup.sh"
# hub_secrets volume must NOT be in BACKUP_FILE_VOLUMES (it's never backed up).
if echo "$BACKUP_FILE_VOLUMES" | grep -q hub_secrets; then
  t_fail "backup: hub_secrets must not be in BACKUP_FILE_VOLUMES"
else
  t_pass "backup: hub_secrets is excluded from backups"
fi
case " $BACKUP_FILE_VOLUMES " in
  *" mcp_gate_data:10005:10001 "*) t_pass "backup: mcp_gate_data (access log) archived as the gate's uid, Hub group" ;;
  *) t_fail "backup: mcp_gate_data missing from BACKUP_FILE_VOLUMES ($BACKUP_FILE_VOLUMES)" ;;
esac
case " $BACKUP_FILE_VOLUMES " in
  *" group_gate_data:10003:10001 "*) t_pass "BACKUP_FILE_VOLUMES lists group_gate_data (the opened log, kept a year) as group-gate's uid, Hub group" ;;
  *) t_fail "BACKUP_FILE_VOLUMES lists group_gate_data ($BACKUP_FILE_VOLUMES)" ;;
esac
# The MANIFEST of a backup must never list hub_secrets as a file.
expect_ok "backup: BACKUP_FILE_VOLUMES does not contain hub_secrets" bash -c '! echo "$BACKUP_FILE_VOLUMES" | grep -q hub_secrets'

# The backup reads the config of every profile (mail_acme is mounted only
# by the tools one-shot mail-cert).
( dc() { printf '%s\n' "$*" > "$WORK/bcfg-args"; echo '{"volumes":{}}'; }; _rt_docker_only() { :; }
  _BACKUP_CFG=""; _backup_load_cfg )
expect_eq "backup: the compose config of every profile" "$(cat "$WORK/bcfg-args")" "--profile * config --format json"
# Test server 2026-11-13: an empty domains_data turned 10003:10001 0750
# (group-gate's /data) at a backup — Docker copies the image's mountpoint
# owner and mode onto an empty named volume. The python helpers (group-gate's
# image) mount volumes at BACKUP_PY_MOUNT, which that image doesn't have.
rm -f "$STUB_DIR/calls"
( _py_image() { echo portcullis-group-gate; }
  _backup_volume_files portcullis_domains_data 10004 10004 >/dev/null 2>&1
  _BACKUP_CFG='{"volumes":{"lldap_data":{"name":"portcullis_lldap_data"}}}'
  _restore_lldap_count >/dev/null 2>&1 ) || true
expect_eq "backup: the snapshot helper mounts the volume at $BACKUP_PY_MOUNT, not /data" \
  "$(grep -c -- "--user 10004:10004 .*-v portcullis_domains_data:$BACKUP_PY_MOUNT portcullis-group-gate python3 -c" "$STUB_DIR/calls")" 1
expect_eq "restore: the LLDAP user count mounts lldap_data read-only at $BACKUP_PY_MOUNT" \
  "$(grep -c -- "-v portcullis_lldap_data:$BACKUP_PY_MOUNT:ro portcullis-group-gate python3 -c" "$STUB_DIR/calls")" 1
expect_eq "backup: no CLI helper mounts a volume at /data of the group-gate (python) image" \
  "$(grep -c -- ':/data.* portcullis-group-gate ' "$STUB_DIR/calls" || true)" 0
expect_eq "backup: the python helpers read BACKUP_PY_MOUNT (snapshot SRC, LLDAP count URI)" \
  "$(printf '%s\n' "$_BACKUP_PY_SNAPSHOT" | grep -cx "SRC = \"$BACKUP_PY_MOUNT\""):$(printf '%s\n' "$_BACKUP_PY_COUNT_LLDAP" | grep -cF "file:$BACKUP_PY_MOUNT/users.db")" "1:1"
expect_eq "backup: the group-gate image has no $BACKUP_PY_MOUNT (nothing to copy onto an empty volume)" \
  "$(grep -cE "(^|[[:space:]=])$BACKUP_PY_MOUNT([/[:space:]]|$)" "$HERE/../group-gate/Dockerfile" || true)" 0

# Restore must fail closed when hub_secrets volume removal fails (security: old hashes would survive).
# Override the existing docker stub to simulate a volume rm failure.
mv "$WORK/bin/docker" "$WORK/bin/docker-orig"
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
echo "$*" >> "$STUB_DIR/calls"
# Simulate docker volume rm succeeding (returns 0) but the volume still existing
# (docker volume inspect still finds it, meaning the rm actually failed).
if [ "$1 $2" = "volume inspect" ] && [ "$3" = "portcullis_hub_secrets" ]; then
  # Volume still exists after rm (the failure case)
  echo '[{"Name":"portcullis_hub_secrets"}]'
  exit 0
fi
# All other commands succeed
exit 0
STUB
chmod +x "$WORK/bin/docker"
# Test the restore behavior: the code in backup.sh must detect this and fail.
(
  export PORTCULLIS_ROOT="$WORK/restore-test"
  mkdir -p "$PORTCULLIS_ROOT"
  cd "$PORTCULLIS_ROOT" || exit 1
  # Simulate the emptying code from cmd_restore
  full="portcullis_hub_secrets"
  docker volume rm -f "$full" >/dev/null 2>&1 || true
  # The new fail-closed check: this should fail because volume inspect succeeds
  if docker volume inspect "$full" >/dev/null 2>&1; then
    # This is the failure path - volume still exists
    exit 1
  fi
  # Should not reach here
  exit 0
) >/dev/null 2>&1
if [ $? -ne 0 ]; then
  t_pass "restore: fails closed when hub_secrets volume removal fails"
else
  t_fail "restore: fails closed when hub_secrets volume removal fails"
fi
# Restore original docker stub
mv "$WORK/bin/docker-orig" "$WORK/bin/docker"

# F14 ownership test: _ensure_secrets_volume (via stack_prepare) runs helper with chown/chmod,
# and a failing helper makes it fail.
: > "$STUB_DIR/calls"
cat > "$WORK/bin/docker" <<STUB
#!/usr/bin/env bash
[ "\$1 \$3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
echo "\$*" >> "\$STUB_DIR/calls"
if [ "\$1" = "volume" ] && [ "\$2" = "inspect" ] && [ "\$3" = "portcullis_hub_secrets" ]; then
  # Volume doesn't exist yet
  exit 1
fi
if [ "\$1" = "volume" ] && [ "\$2" = "create" ]; then
  # Check labels are present
  if echo "\$*" | grep -q "com.docker.compose.project=portcullis" && \
     echo "\$*" | grep -q "com.docker.compose.volume=hub_secrets"; then
    exit 0
  fi
  exit 1
fi
if [ "\$1" = "run" ] && echo "\$*" | grep -q "chown $CT_UID_HUB:$CT_UID_HUB /v && chmod 0700 /v"; then
  # Helper with correct ownership command
  exit 0
fi
exit 0
STUB
chmod +x "$WORK/bin/docker"
(
  export PORTCULLIS_ROOT="$WORK/f14-test"
  mkdir -p "$PORTCULLIS_ROOT"
  cd "$PORTCULLIS_ROOT" || exit 1
  # Call _ensure_secrets_volume (the function in common.sh)
  _ensure_secrets_volume 2>/dev/null
) && t_pass "F14: _ensure_secrets_volume runs helper with chown $CT_UID_HUB:$CT_UID_HUB chmod 0700" \
  || t_fail "F14: _ensure_secrets_volume runs helper with chown $CT_UID_HUB:$CT_UID_HUB chmod 0700"
# Verify the calls include volume create with labels and the chown helper
if grep -q "volume create.*com.docker.compose.project=portcullis.*com.docker.compose.volume=hub_secrets" "$STUB_DIR/calls" && \
   grep -q "chown $CT_UID_HUB:$CT_UID_HUB /v && chmod 0700 /v" "$STUB_DIR/calls"; then
  t_pass "F14: helper called with correct chown/chmod"
else
  t_fail "F14: helper called with correct chown/chmod"
fi
# Test that a failing helper makes _ensure_secrets_volume fail
: > "$STUB_DIR/calls"
cat > "$WORK/bin/docker" <<STUB2
#!/usr/bin/env bash
[ "\$1 \$3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
echo "\$*" >> "\$STUB_DIR/calls"
if [ "\$1" = "volume" ] && [ "\$2" = "inspect" ]; then
  exit 1  # doesn't exist
fi
if [ "\$1" = "volume" ] && [ "\$2" = "create" ]; then
  exit 0
fi
if [ "\$1" = "run" ] && echo "\$*" | grep -q "chown.*chmod"; then
  # Helper fails
  exit 1
fi
exit 0
STUB2
chmod +x "$WORK/bin/docker"
(
  export PORTCULLIS_ROOT="$WORK/f14-fail-test"
  mkdir -p "$PORTCULLIS_ROOT"
  cd "$PORTCULLIS_ROOT" || exit 1
  _ensure_secrets_volume 2>/dev/null
) && t_fail "F14: _ensure_secrets_volume fails when helper fails" \
  || t_pass "F14: _ensure_secrets_volume fails when helper fails"

# Positive-path restore test: operations happen in the right order.
: > "$STUB_DIR/calls"
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
echo "$*" >> "$STUB_DIR/calls"
if [ "$1" = "volume" ] && [ "$2" = "rm" ]; then
  exit 0
fi
if [ "$1" = "volume" ] && [ "$2" = "inspect" ]; then
  # After rm, volume doesn't exist
  exit 1
fi
if [ "$1" = "volume" ] && [ "$2" = "create" ]; then
  exit 0
fi
if [ "$1" = "run" ] && echo "$*" | grep -q "chown.*chmod"; then
  # The helper
  exit 0
fi
if [ "$1" = "compose" ] && [ "$2" = "up" ]; then
  # compose up
  exit 0
fi
exit 0
STUB
chmod +x "$WORK/bin/docker"
(
  export PORTCULLIS_ROOT="$WORK/restore-order-test"
  mkdir -p "$PORTCULLIS_ROOT"
  cd "$PORTCULLIS_ROOT" || exit 1
  # Simulate the restore's hub_secrets emptying (from backup.sh)
  proj="portcullis"
  helper="alpine:latest"
  full="portcullis_hub_secrets"
  docker volume rm -f "$full" >/dev/null 2>&1 || true
  docker volume inspect "$full" >/dev/null 2>&1 && exit 1
  docker volume create --label "com.docker.compose.project=$proj" --label "com.docker.compose.volume=hub_secrets" "$full" >/dev/null || exit 1
  docker run --rm --network none -v "$full:/data" "$helper" sh -c "chown $CT_UID_HUB:$CT_UID_HUB /data && chmod 0700 /data" >/dev/null || exit 1
  # Now simulate compose up (would happen later)
  docker compose up -d hub >/dev/null 2>&1 || true
) && {
  # Check the order in calls: rm, then inspect, then create with labels, then run (helper), then compose up
  calls="$(cat "$STUB_DIR/calls")"
  if echo "$calls" | grep -q "volume rm.*portcullis_hub_secrets" && \
     echo "$calls" | grep -q "volume create.*com.docker.compose.project=portcullis.*com.docker.compose.volume=hub_secrets" && \
     echo "$calls" | grep -q "run.*chown $CT_UID_HUB:$CT_UID_HUB" && \
     echo "$calls" | grep -q "compose up"; then
    # Check order: find line numbers
    rm_line=$(echo "$calls" | grep -n "volume rm.*portcullis_hub_secrets" | head -1 | cut -d: -f1)
    create_line=$(echo "$calls" | grep -n "volume create.*com.docker.compose" | head -1 | cut -d: -f1)
    helper_line=$(echo "$calls" | grep -n "run.*chown $CT_UID_HUB:$CT_UID_HUB" | head -1 | cut -d: -f1)
    up_line=$(echo "$calls" | grep -n "compose up" | head -1 | cut -d: -f1)
    if [ "$rm_line" -lt "$create_line" ] && [ "$create_line" -lt "$helper_line" ] && [ "$helper_line" -lt "$up_line" ]; then
      t_pass "restore: empties hub_secrets in correct order (rm, create, chown, before compose up)"
    else
      t_fail "restore: empties hub_secrets in correct order (order wrong: rm=$rm_line create=$create_line helper=$helper_line up=$up_line)"
    fi
  else
    t_fail "restore: empties hub_secrets in correct order (missing operations)"
  fi
} || t_fail "restore: empties hub_secrets in correct order (restore failed)"
# Note: docker-orig was already restored by the fail-closed test above

# Test that _ensure_secrets_volume uses the fixed name portcullis_hub_secrets (or HUB_SECRETS_VOLUME),
# not one derived from COMPOSE_PROJECT_NAME (C4).
(
  export PORTCULLIS_ROOT="$WORK/esv-test" COMPOSE_PROJECT_NAME="myproject"
  mkdir -p "$PORTCULLIS_ROOT"
  : > "$STUB_DIR/calls"
  _ensure_secrets_volume
  if grep -q "volume inspect portcullis_hub_secrets" "$STUB_DIR/calls" && \
     grep -q "volume create.*portcullis_hub_secrets" "$STUB_DIR/calls"; then
    t_pass "_ensure_secrets_volume: uses portcullis_hub_secrets even with COMPOSE_PROJECT_NAME=myproject"
  else
    t_fail "_ensure_secrets_volume: should use portcullis_hub_secrets, not myproject_hub_secrets: $(tr '\n' '|' < "$STUB_DIR/calls")"
  fi
) || t_fail "_ensure_secrets_volume: test failed"

(
  export PORTCULLIS_ROOT="$WORK/esv-test2" HUB_SECRETS_VOLUME="custom_hub_secrets"
  mkdir -p "$PORTCULLIS_ROOT"
  : > "$STUB_DIR/calls"
  _ensure_secrets_volume
  if grep -q "volume inspect custom_hub_secrets" "$STUB_DIR/calls" && \
     grep -q "volume create.*custom_hub_secrets" "$STUB_DIR/calls"; then
    t_pass "_ensure_secrets_volume: uses HUB_SECRETS_VOLUME when set"
  else
    t_fail "_ensure_secrets_volume: should use HUB_SECRETS_VOLUME: $(tr '\n' '|' < "$STUB_DIR/calls")"
  fi
) || t_fail "_ensure_secrets_volume with HUB_SECRETS_VOLUME: test failed"

# ── restore with file-sharing apps running (contract §11.6) ──
# Fake docker: $STUB_DIR/rs-ctr lists "<id> <compose project>" of the
# containers mounting hub_secrets; `compose -p <p> down` removes <p>'s
# (fails while $STUB_DIR/rs-fail-<p> exists); every call is logged.
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
echo "$*" >> "$STUB_DIR/calls"
case "$1" in
  ps) [ "$*" = "ps -aq --filter volume=portcullis_hub_secrets" ] || exit 0
      [ -f "$STUB_DIR/rs-ctr" ] && cut -d' ' -f1 "$STUB_DIR/rs-ctr"; exit 0 ;;
  inspect) awk -v i="${*: -1}" '$1 == i { print $2; f = 1 } END { exit !f }' "$STUB_DIR/rs-ctr"; exit ;;
  compose)
    # Handle: compose --project-directory ... stop hub
    if [[ "$*" == *"--project-directory"*"stop hub" ]]; then
      exit 0
    fi
    # Handle: compose --project-directory ... start hub
    if [[ "$*" == *"--project-directory"*"start hub" ]]; then
      exit 0
    fi
    if [ "$2" = "-p" ] && [ "$4" = "down" ]; then
      [ -f "$STUB_DIR/rs-fail-$3" ] && exit 1
      awk -v p="$3" '$2 != p' "$STUB_DIR/rs-ctr" > "$STUB_DIR/rs-ctr.new" && mv "$STUB_DIR/rs-ctr.new" "$STUB_DIR/rs-ctr"
    fi
    exit 0 ;;
  volume) [ "$2" = inspect ] && exit 1; exit 0 ;;
esac
exit 0
STUB
chmod +x "$WORK/bin/docker"
# rs_restore: backup_restore over a fake backup; checks/config stubbed,
# stops at the first logical restore (_restore_pg exits 3).
rs_restore() {
  (
    export PORTCULLIS_ROOT="$WORK/rs-root" BACKUP_ROOT="$WORK/rs-root/backups"
    _backup_check_layout() { :; }; _backup_check_manifest() { :; }; network_check() { :; }
    stack_prepare() { :; }; env_reload() { :; }
    _backup_load_cfg() {
      _BACKUP_CFG='{"name":"portcullis","volumes":{"hub_secrets":{"name":"portcullis_hub_secrets"},"postgres_data":{"name":"portcullis_postgres_data"},"vault_data":{"name":"portcullis_vault_data"}}}'
    }
    _restore_pg() { exit 3; }
    backup_restore "$WORK/rs-backup" true false
  ) >"$WORK/rs-out" 2>&1
}
rs_setup() {
  rm -rf "$WORK/rs-root" "$WORK/rs-backup"; mkdir -p "$WORK/rs-root/backups" "$WORK/rs-backup"
  echo 'CURRENT=1' > "$WORK/rs-root/.env"; echo 'RESTORED=1' > "$WORK/rs-backup/.env"
  printf '{"created":"x","domain":"d"}' > "$WORK/rs-backup/MANIFEST.json"
  printf 'c1 portcullis\nc2 portcullis-samba\nc3 portcullis-timemachine\nc4 portcullis-samba\n' > "$STUB_DIR/rs-ctr"
  rm -f "$STUB_DIR"/rs-fail-*; : > "$STUB_DIR/calls"
}
line_of() { grep -n -m1 -e "$1" "$STUB_DIR/calls" | cut -d: -f1; }

rs_setup
rs_restore; rc=$?
stop_hub=$(line_of "^compose --project-directory .* stop hub$")
down_samba=$(line_of '^compose -p portcullis-samba down$')
down_tm=$(line_of '^compose -p portcullis-timemachine down$')
down_core=$(line_of "^compose --project-directory .* down$")
rm_pg=$(line_of '^volume rm -f portcullis_postgres_data')
if [ "$rc" = 3 ] && [ -n "$stop_hub" ] && [ -n "$down_samba" ] && [ -n "$down_tm" ] && [ -n "$down_core" ] && [ -n "$rm_pg" ] \
   && [ "$stop_hub" -lt "$down_samba" ] && [ "$stop_hub" -lt "$down_tm" ] \
   && [ "$down_samba" -lt "$down_core" ] && [ "$down_tm" -lt "$down_core" ] && [ "$down_core" -lt "$rm_pg" ]; then
  t_pass "restore: Hub stopped, then apps taken down, then core down, then volumes touched (correct order)"
else
  t_fail "restore: order wrong (rc=$rc stop_hub=$stop_hub samba=$down_samba tm=$down_tm core=$down_core rm_pg=$rm_pg): $(tr '\n' '|' < "$STUB_DIR/calls")"
fi
expect_eq "restore's last line (T24): authenticator apps and passkeys removed since the backup work again" \
  "$(bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/backup.sh'; _restore_lost_devices_note" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')" \
  "$(printf '%s' "==> Authenticator apps and passkeys removed after this backup's date work again: remove the ones reported lost since then (People → person → Sign-in).")"
# Both runtimes' restores end with it (docker / podman and kubernetes).
expect_eq "the lost-devices note is the last call of the docker and the kubernetes restore" \
  "$(for f in _backup_restore_docker _backup_restore_kube; do sed -n "/^$f() {/,/^}/p" "$HERE"/../scripts/lib/backup.sh "$HERE"/../scripts/lib/kube.sh | grep -v '^ *#' | grep -v '^}' | tail -n1 | tr -d ' '; done | tr '\n' ' ')" \
  "_restore_lost_devices_note _restore_lost_devices_note "
expect_eq "restore: each app project downed once, never the core project by -p" \
  "$(grep -c '^compose -p ' "$STUB_DIR/calls")" "2"
expect_ok "restore: no app down removes volumes" sh -c "! grep -q '^compose -p .* -v' '$STUB_DIR/calls'"

# Test a failing dc stop hub (N2)
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
echo "$*" >> "$STUB_DIR/calls"
case "$1" in
  compose)
    # Fail on stop hub
    if [[ "$*" == *"--project-directory"*"stop hub" ]]; then
      exit 1
    fi
    exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$WORK/bin/docker"
rs_setup
rs_restore; rc=$?
if [ "$rc" != 0 ] && [ "$rc" != 3 ] \
   && ! grep -q -e "start hub" -e '--project-directory .* down$' -e '^compose -p ' -e '^volume rm' "$STUB_DIR/calls" \
   && [ "$(cat "$WORK/rs-root/.env")" = "CURRENT=1" ] && [ -z "$(ls "$WORK/rs-root/backups")" ] \
   && grep -q "could not stop the Hub" "$WORK/rs-out" && grep -q "nothing was restored" "$WORK/rs-out"; then
  t_pass "restore: a failing dc stop hub aborts before anything changes (N2)"
else
  t_fail "restore: failing stop hub should abort early (rc=$rc): $(tr '\n' '|' < "$STUB_DIR/calls") / $(tr '\n' '|' < "$WORK/rs-out")"
fi

# Restore the normal stub
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
echo "$*" >> "$STUB_DIR/calls"
case "$1" in
  ps) [ "$*" = "ps -aq --filter volume=portcullis_hub_secrets" ] || exit 0
      [ -f "$STUB_DIR/rs-ctr" ] && cut -d' ' -f1 "$STUB_DIR/rs-ctr"; exit 0 ;;
  inspect) awk -v i="${*: -1}" '$1 == i { print $2; f = 1 } END { exit !f }' "$STUB_DIR/rs-ctr"; exit ;;
  compose)
    # Handle: compose --project-directory ... stop hub
    if [[ "$*" == *"--project-directory"*"stop hub" ]]; then
      exit 0
    fi
    # Handle: compose --project-directory ... start hub
    if [[ "$*" == *"--project-directory"*"start hub" ]]; then
      exit 0
    fi
    if [ "$2" = "-p" ] && [ "$4" = "down" ]; then
      [ -f "$STUB_DIR/rs-fail-$3" ] && exit 1
      awk -v p="$3" '$2 != p' "$STUB_DIR/rs-ctr" > "$STUB_DIR/rs-ctr.new" && mv "$STUB_DIR/rs-ctr.new" "$STUB_DIR/rs-ctr"
    fi
    exit 0 ;;
  volume) [ "$2" = inspect ] && exit 1; exit 0 ;;
esac
exit 0
STUB
chmod +x "$WORK/bin/docker"

rs_setup
touch "$STUB_DIR/rs-fail-portcullis-timemachine"
rs_restore; rc=$?
if [ "$rc" != 0 ] && [ "$rc" != 3 ] && ! grep -q -e '--project-directory .* down$' -e '^volume rm' -e '^run ' "$STUB_DIR/calls" \
   && [ "$(cat "$WORK/rs-root/.env")" = "CURRENT=1" ] && [ -z "$(ls "$WORK/rs-root/backups")" ] \
   && grep -q "could not take down" "$WORK/rs-out" && grep -q "nothing was restored" "$WORK/rs-out" \
   && grep -q "Hub running again" "$WORK/rs-out" \
   && grep -q "^compose --project-directory .* stop hub$" "$STUB_DIR/calls" \
   && grep -q "^compose --project-directory .* start hub$" "$STUB_DIR/calls"; then
  t_pass "restore: a failed app down restarts the Hub and aborts with nothing changed (N2)"
else
  t_fail "restore: failed app down should restart Hub (rc=$rc): $(tr '\n' '|' < "$STUB_DIR/calls") / $(tr '\n' '|' < "$WORK/rs-out")"
fi

rs_setup
printf 'c1 portcullis\nc9 portcullis-samba\n' > "$STUB_DIR/rs-ctr"
# A container the down leaves behind (re-created meanwhile): refused.
sed -i.bak 's/awk -v p="$3" .\$2 != p. "$STUB_DIR\/rs-ctr" > "$STUB_DIR\/rs-ctr.new" \&\& mv "$STUB_DIR\/rs-ctr.new" "$STUB_DIR\/rs-ctr"/[ -f "$STUB_DIR\/rs-stick" ] || &/' "$WORK/bin/docker"
touch "$STUB_DIR/rs-stick"
rs_restore; rc=$?
rm -f "$STUB_DIR/rs-stick"
if [ "$rc" != 0 ] && [ "$rc" != 3 ] && ! grep -q -e '--project-directory .* down$' -e '^volume rm' "$STUB_DIR/calls" \
   && grep -q "still mount portcullis_hub_secrets" "$WORK/rs-out"; then
  t_pass "restore: a container still mounting hub_secrets after the down aborts with nothing changed"
else
  t_fail "restore: container left after the down aborts (rc=$rc): $(tr '\n' '|' < "$WORK/rs-out")"
fi

rs_setup
: > "$STUB_DIR/rs-ctr"; echo 'c1 portcullis' > "$STUB_DIR/rs-ctr"
rs_restore; rc=$?
expect_eq "restore: only the core project mounts hub_secrets → no app down" "$(grep -c '^compose -p ' "$STUB_DIR/calls")" "0"

# ── signin_ca_reload: forward-auth(-ext) restart only when the CA bundle changed ──
ca_run() {
  # A fresh shell: stack.sh is sourced only here.
  bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/stack.sh'; $1" >/dev/null 2>&1
}
ca_restarts() { grep -c -- '--project-directory .* restart forward-auth forward-auth-ext$' "$STUB_DIR/calls" 2>/dev/null || true; }
mkdir -p "$PORTCULLIS_ROOT/certs"
rm -f "$PORTCULLIS_ROOT/certs/.ca-bundle.loaded"
printf 'bundle-a\n' > "$PORTCULLIS_ROOT/certs/ca-bundle.crt"
: > "$STUB_DIR/calls"
ca_run signin_ca_reload
expect_eq "ca bundle: nothing recorded → forward-auth(-ext) restarted once" "$(ca_restarts)" "1"
expect_ok "ca bundle: the loaded bundle's sha256 is recorded" test -s "$PORTCULLIS_ROOT/certs/.ca-bundle.loaded"
: > "$STUB_DIR/calls"
ca_run signin_ca_reload
expect_eq "ca bundle: unchanged → no restart" "$(ca_restarts)" "0"
printf 'bundle-a\nstaging-root\n' > "$PORTCULLIS_ROOT/certs/ca-bundle.crt"
: > "$STUB_DIR/calls"
ca_run signin_ca_reload
expect_eq "ca bundle: changed (e.g. ACME staging switched on) → restarted" "$(ca_restarts)" "1"
: > "$STUB_DIR/calls"
ca_run signin_ca_reload
expect_eq "ca bundle: changed once → restarted once" "$(ca_restarts)" "0"
printf 'bundle-b\n' > "$PORTCULLIS_ROOT/certs/ca-bundle.crt"
: > "$STUB_DIR/calls"
ca_run signin_ca_mark
ca_run signin_ca_reload
expect_eq "ca bundle: signin_ca_mark after an explicit restart → no second restart" "$(ca_restarts)" "0"
rm -f "$PORTCULLIS_ROOT/certs/ca-bundle.crt" "$PORTCULLIS_ROOT/certs/.ca-bundle.loaded"
: > "$STUB_DIR/calls"
ca_run signin_ca_reload
expect_eq "ca bundle: no bundle yet → nothing done" "$(ca_restarts)" "0"
# A failed restart must not record the new bundle (the next up retries).
printf 'bundle-c\n' > "$PORTCULLIS_ROOT/certs/ca-bundle.crt"
printf 'old\n' > "$PORTCULLIS_ROOT/certs/.ca-bundle.loaded"
cp "$WORK/bin/docker" "$WORK/docker.ok"
{ printf '#!/usr/bin/env bash\n'; cat "$WORK/stub-version"; printf 'echo "$*" >> "$STUB_DIR/calls"\ncase "$*" in *restart*) exit 1 ;; esac\nexit 0\n'; } > "$WORK/bin/docker"
ca_run 'set -e; signin_ca_reload'
expect_eq "ca bundle: a failed restart keeps the old record" "$(cat "$PORTCULLIS_ROOT/certs/.ca-bundle.loaded")" "old"
cp "$WORK/docker.ok" "$WORK/bin/docker"

# ── pki_files_reload (review I1): Traefik, Keycloak and group-gate restart
# whenever the internal CA's files differ from the persistent stamp ──
pki_restarts() { grep -c -- '--project-directory .* restart traefik keycloak group-gate$' "$STUB_DIR/calls" 2>/dev/null || true; }
PC="$PORTCULLIS_ROOT/certs"
rm -f "$PC/.pki-files.loaded" "$PC/ca-chain.crt"
: > "$STUB_DIR/calls"
ca_run pki_files_reload
expect_eq "pki files: no CA yet → nothing done" "$(pki_restarts):$([ -e "$PC/.pki-files.loaded" ] && echo stamp || echo none)" "0:none"
mkdir -p "$PC/truststore"
for f in ca-chain.crt ca-chain-yubikey.crt yubikey-ca.crt browser-ca.crt truststore/portcullis-ca-chain.pem truststore/portcullis-yubikey-ca.pem truststore/portcullis-browser-ca.pem; do
  printf 'pem %s\n' "$f" > "$PC/$f"
done
: > "$STUB_DIR/calls"
ca_run pki_files_reload
expect_eq "pki files: nothing recorded → traefik, keycloak, group-gate restarted once" "$(pki_restarts)" "1"
expect_ok "pki files: the stamp is written after the restart" test -s "$PC/.pki-files.loaded"
: > "$STUB_DIR/calls"
ca_run pki_files_reload
expect_eq "pki files: unchanged → no restart" "$(pki_restarts)" "0"
for f in ca-chain-yubikey.crt browser-ca.crt truststore/portcullis-browser-ca.pem; do
  printf 'new\n' >> "$PC/$f"
  : > "$STUB_DIR/calls"
  ca_run pki_files_reload
  expect_eq "pki files: $f changed → restarted" "$(pki_restarts)" "1"
done
: > "$STUB_DIR/calls"
printf 'again\n' >> "$PC/yubikey-ca.crt"
ca_run pki_files_mark
ca_run pki_files_reload
expect_eq "pki files: pki_files_mark after an explicit restart → no second restart" "$(pki_restarts)" "0"
# A failed restart keeps the old stamp: the next up / upgrade restarts them.
printf 'old\n' > "$PC/.pki-files.loaded"
printf 'more\n' >> "$PC/ca-chain.crt"
{ printf '#!/usr/bin/env bash\n'; cat "$WORK/stub-version"; printf 'echo "$*" >> "$STUB_DIR/calls"\ncase "$*" in *restart*) exit 1 ;; esac\nexit 0\n'; } > "$WORK/bin/docker"
rc=0; ca_run 'set -e; pki_files_reload' || rc=$?
expect_eq "pki files: a failed restart fails and keeps the old stamp" "$rc:$(cat "$PC/.pki-files.loaded")" "1:old"
cp "$WORK/docker.ok" "$WORK/bin/docker"
: > "$STUB_DIR/calls"
ca_run pki_files_reload
expect_eq "pki files: the next run restarts them" "$(pki_restarts)" "1"
rm -rf "$PC/truststore" "$PC/.pki-files.loaded"
for f in ca-chain.crt ca-chain-yubikey.crt yubikey-ca.crt browser-ca.crt; do rm -f "$PC/$f"; done

# ── config_reload: services restart only when their config files changed ──
cfg_run() {
  bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/stack.sh'; $1" >/dev/null 2>&1
}
cfg_restarts() { grep -- '--project-directory .* restart' "$STUB_DIR/calls" 2>/dev/null | sed 's/.*restart //' | sort | paste -sd' ' -; }
mkdir -p "$PORTCULLIS_ROOT/oauth2-proxy" "$PORTCULLIS_ROOT/group-gate" "$PORTCULLIS_ROOT/secrets"
printf 'alpha-config-v1\n' > "$PORTCULLIS_ROOT/oauth2-proxy/alpha.yaml"
printf 'map-v1\n' > "$PORTCULLIS_ROOT/group-gate/group-gate-map.conf"
: > "$STUB_DIR/calls"
cfg_run config_reload
expect_eq "config reload: no stamps → forward-auth(-ext), group-gate, enroll restarted once" \
  "$(cfg_restarts)" "forward-auth forward-auth-ext group-gate enroll"
expect_ok "config reload: stamps written" test -f "$PORTCULLIS_ROOT/secrets/.config-oauth2-proxy_alpha.yaml.loaded"
: > "$STUB_DIR/calls"
cfg_run config_reload
expect_eq "config reload: unchanged → no restart" "$(cfg_restarts)" ""
printf 'alpha-config-v2\n' > "$PORTCULLIS_ROOT/oauth2-proxy/alpha.yaml"
: > "$STUB_DIR/calls"
cfg_run config_reload
expect_eq "config reload: alpha.yaml changed → forward-auth(-ext) restarted, others not" \
  "$(cfg_restarts)" "forward-auth forward-auth-ext"
: > "$STUB_DIR/calls"
cfg_run config_reload
expect_eq "config reload: changed once → restarted once" "$(cfg_restarts)" ""
printf 'map-v2\n' > "$PORTCULLIS_ROOT/group-gate/group-gate-map.conf"
: > "$STUB_DIR/calls"
cfg_run config_reload
expect_eq "config reload: map.conf changed → group-gate, enroll restarted" \
  "$(cfg_restarts)" "group-gate enroll"
rm -f "$PORTCULLIS_ROOT/oauth2-proxy/alpha.yaml" "$PORTCULLIS_ROOT/secrets/.config-oauth2-proxy_alpha.yaml.loaded"
: > "$STUB_DIR/calls"
cfg_run config_reload
expect_eq "config reload: missing file → nothing done" "$(cfg_restarts)" ""
# A failed restart must not record the new hash (the next up retries).
printf 'alpha-config-v3\n' > "$PORTCULLIS_ROOT/oauth2-proxy/alpha.yaml"
printf 'old-hash\n' > "$PORTCULLIS_ROOT/secrets/.config-oauth2-proxy_alpha.yaml.loaded"
cp "$WORK/bin/docker" "$WORK/docker.ok"
{ printf '#!/usr/bin/env bash\n'; cat "$WORK/stub-version"; printf 'echo "$*" >> "$STUB_DIR/calls"\ncase "$*" in *restart*) exit 1 ;; esac\nexit 0\n'; } > "$WORK/bin/docker"
chmod +x "$WORK/bin/docker"
cfg_run 'set -e; config_reload'
expect_eq "config reload: a failed restart keeps the old stamp" "$(cat "$PORTCULLIS_ROOT/secrets/.config-oauth2-proxy_alpha.yaml.loaded")" "old-hash"
cp "$WORK/docker.ok" "$WORK/bin/docker"

# ══ config: config_apply (static TLS options, plan D18) ════
CA_ROOT="$WORK/config-apply"
mkdir -p "$CA_ROOT/traefik/dynamic" "$WORK/cabin"
cp "$HERE/../traefik/dynamic/tls.yml" "$CA_ROOT/traefik/dynamic/tls.yml"
printf '# x\nmiddlewares: {}\n' > "$CA_ROOT/traefik/dynamic/middlewares.yml"
printf 'PORTCULLIS_DOMAIN=ci.example.org\nACME_STAGING=true\n' > "$CA_ROOT/.env"
# No network: the staging root download fails (a warning).
printf '#!/usr/bin/env bash\nexit 7\n' > "$WORK/cabin/curl"
chmod +x "$WORK/cabin/curl"
traefik_sums() { find "$CA_ROOT/traefik" -type f -exec cksum {} + | sort; }
SUMS_BEFORE="$(traefik_sums)"
RC=0
(
  export PORTCULLIS_ROOT="$CA_ROOT" PATH="$WORK/cabin:$PATH"
  # shellcheck source=../scripts/lib/config.sh
  source "$HERE/../scripts/lib/config.sh"
  # shellcheck source=../scripts/lib/dns.sh
  source "$HERE/../scripts/lib/dns.sh"
  config_apply
) >"$WORK/ca-out" 2>&1 || RC=$?
expect_eq "config_apply with ACME_STAGING=true exits 0" "$RC" 0
expect_eq "config_apply with ACME_STAGING=true writes ACME_CA_SERVER staging and touches no traefik file" \
  "$(grep '^ACME_CA_SERVER=' "$CA_ROOT/.env"):$([ "$(traefik_sums)" = "$SUMS_BEFORE" ] && echo same)" \
  "ACME_CA_SERVER=https://acme-staging-v02.api.letsencrypt.org/directory:same"
expect_eq "config_apply prints no MTLS_ENABLED" "$(grep -c MTLS "$WORK/ca-out")" 0

# ── invite --replace-keys deletes every passkey kind (and nothing else) ──
RK_OUT="$(
  # shellcheck source=../scripts/lib/common.sh
  source "$HERE/../scripts/lib/common.sh"
  # shellcheck source=../scripts/lib/users.sh
  source "$HERE/../scripts/lib/users.sh"
  export KC_REALM=portcullis
  require_cmd() { :; }
  kc_login() { :; }
  _kc_report() { :; }
  kc_get() {
    case "$1" in
      */users\?username=*) echo '[{"id":"u1"}]' ;;
      */users/u1/credentials) echo '[{"id":"c1","type":"webauthn-passwordless"},{"id":"c2","type":"portcullis-security-key"},
                                    {"id":"c3","type":"portcullis-device-passkey"},{"id":"c4","type":"webauthn"},
                                    {"id":"c5","type":"password"},{"id":"c6","type":"otp"}]' ;;
    esac
  }
  kc_send() { echo "$1 $2" >&3; echo 204; }
  invite_replace_keys alice 3>&1 >/dev/null 2>&1
)"
expect_eq "invite --replace-keys deletes every passkey kind and every authenticator app (otp, T28), never a password, then signs out" \
  "$(printf '%s\n' "$RK_OUT" | sort | tr '\n' ' ')" \
  "DELETE /portcullis/users/u1/credentials/c1 DELETE /portcullis/users/u1/credentials/c2 DELETE /portcullis/users/u1/credentials/c3 DELETE /portcullis/users/u1/credentials/c4 DELETE /portcullis/users/u1/credentials/c6 POST /portcullis/users/u1/logout "
expect_eq "INVITE_PASSKEY_TYPES_JQ selects otp, never password" \
  "$(bash -c "source '$HERE/../scripts/lib/users.sh'; jq -c \"[\$INVITE_PASSKEY_TYPES_JQ]\" <<<'[{\"id\":\"o\",\"type\":\"otp\"},{\"id\":\"p\",\"type\":\"password\"}]'")" '["o"]'

# ── status_clock_synced (contract §8.1 "Authenticator-app codes"): systemd's
# NTPSynchronized, else chrony's offset under 5 s, else unknown ──
mkdir -p "$WORK/clk"
# clock_with <timedatectl answer|-> <chronyc tracking text|-> — the helper's
# answer with only the stubs given on PATH ("-" = that tool is absent).
clock_with() {
  rm -f "$WORK/clk/timedatectl" "$WORK/clk/chronyc"
  if [ "$1" != - ]; then printf '#!/bin/sh\n[ "$*" = "show -p NTPSynchronized --value" ] || exit 2\nprintf "%%s\\n" "%s"\n' "$1" > "$WORK/clk/timedatectl"; chmod +x "$WORK/clk/timedatectl"; fi
  if [ "$2" != - ]; then printf '#!/bin/sh\n[ "$1" = tracking ] || exit 2\ncat <<EOF\n%s\nEOF\n' "$2" > "$WORK/clk/chronyc"; chmod +x "$WORK/clk/chronyc"; fi
  # Only the stubs and the basic tools: no host timedatectl / chronyc.
  mkdir -p "$WORK/clk/bin"
  for t in awk sh cat; do ln -sf "$(command -v "$t")" "$WORK/clk/bin/$t"; done
  PATH="$WORK/clk:$WORK/clk/bin" "$BASH" -c "source '$HERE/../scripts/lib/status.sh'; status_clock_synced"
}
CHRONY_OK='Reference ID    : C0A80101 (ntp.example.com)
System time     : 0.000123456 seconds fast of NTP time
Leap status     : Normal'
CHRONY_OFF='System time     : 12.500000000 seconds slow of NTP time'
# An unsynchronised chronyd: a tiny offset (nothing to correct against), leap not Normal.
CHRONY_UNSYNC='Reference ID    : 00000000 ()
System time     : 0.000000001 seconds fast of NTP time
Leap status     : Not synchronised'
expect_eq "clock: timedatectl yes / no" "$(clock_with yes -):$(clock_with no "$CHRONY_OK")" "true:false"
expect_eq "clock: timedatectl without an answer → chrony's offset (under 5 s true, else false)" \
  "$(clock_with '' "$CHRONY_OK"):$(clock_with - "$CHRONY_OFF"):$(clock_with - 'System time     : 4.999 seconds fast of NTP time')" "true:false:true"
expect_eq "clock: chrony's Leap status Not synchronised → false, whatever the offset (T12-L3)" \
  "$(clock_with - "$CHRONY_UNSYNC"):$(clock_with '' "$CHRONY_UNSYNC")" "false:false"
expect_eq "clock: neither tool, or an answer that doesn't parse → unknown" \
  "$(clock_with - -):$(clock_with maybe -):$(clock_with - 'chronyc: cannot talk to daemon')" "unknown:unknown:unknown"

# ══ dns: plan / setup / check on the domains image's dns tool ═══
# docker stub: argv of every call → $STUB_DIR/dt/argv (one line each);
# the stdin of each `compose ... run ... dns-tool <sub>` → dt/stdin-<sub>;
# its stdout from dt/out-<sub> (default {} plan), exit from dt/rc-<sub>.
mkdir -p "$WORK/dtbin" "$STUB_DIR/dt"
cat > "$WORK/dtbin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
d="$STUB_DIR/dt"
echo "$*" >> "$d/argv"
case "$*" in
  "image inspect "*) exit 0 ;;
  "volume inspect portcullis_traefik_acme") [ -f "$d/acme-volume" ]; exit ;;
  run\ --rm\ --network\ none*traefik-account-uri*)
    [ ! -f "$d/traefik-fail" ] || exit 125
    [ -s "$d/traefik-uri" ] || exit 3   # the tool: no account in acme.json
    cat "$d/traefik-uri"; exit 0 ;;
  compose\ *\ run\ *dns-tool*)
    sub="$(printf '%s\n' "$@" | sed -n '/^dns-tool$/{n;p;}')"
    cat > "$d/stdin-$sub"
    echo "$sub" >> "$d/order"
    [ ! -f "$d/err-$sub" ] || cat "$d/err-$sub" >&2
    if [ -f "$d/out-$sub" ]; then cat "$d/out-$sub"; else cat "$d/out-default"; fi
    exit "$(cat "$d/rc-$sub" 2>/dev/null || echo 0)" ;;
  run\ --rm\ --network\ none\ -v\ portcullis_traefik_acme:/acme\ *rm\ -f\ /acme/acme.json)
    [ ! -f "$d/rm-term" ] || kill -TERM "$PPID"
    [ ! -f "$d/rm-hup" ] || kill -HUP "$PPID"
    [ ! -f "$d/rm-fail" ] || exit 1
    exit 0 ;;
  compose\ *\ build\ *domains)
    echo build >> "$d/order"
    exit 0 ;;
  compose\ *\ up\ -d\ --no-deps\ traefik)
    # What compose would interpolate: the shell's ACME_CA_SERVER wins over
    # .env (N1), and the sentinel at that moment.
    echo "CA=${ACME_CA_SERVER:-} sentinel=$(cat "$PORTCULLIS_ROOT/certs/.acme-staging-last" 2>/dev/null)" >> "$d/traefik-up"
    [ ! -f "$d/up-fail" ] || exit 1
    exit 0 ;;
  compose\ *\ exec\ -T\ domains\ domains\ report\ --main\ --json\ --fresh)
    [ ! -f "$d/report-old" ] || { echo "usage: domains report --main --json|--refresh" >&2; exit 2; }
    cat "$d/report-out" 2>/dev/null; exit 0 ;;
  compose\ *\ exec\ -T\ domains\ domains\ report\ --main\ --json)
    cat "$d/report-out" 2>/dev/null; exit 0 ;;
  compose\ *\ ps\ -aq\ traefik)
    [ ! -f "$d/traefik-exists" ] || echo c0ffee
    exit 0 ;;
  compose\ *\ stop\ traefik)
    [ ! -f "$d/stop-fail" ] || exit 1
    exit 0 ;;
  compose\ *\ start\ traefik)
    [ ! -f "$d/start-fail" ] || exit 1
    exit 0 ;;
  compose\ *\ ps\ -q\ --status\ running\ traefik)
    [ ! -f "$d/traefik-running" ] || echo c0ffee
    exit 0 ;;
  compose\ *\ exec\ -T\ domains\ domains\ report\ --main\ --refresh)
    echo refresh >> "$d/order"
    [ ! -f "$d/refresh-fail" ] || exit 1
    exit 0 ;;
esac
exit 0
STUB
chmod +x "$WORK/dtbin/docker"
jq -n '{name: "ci.example.org", checked_at: "2026-11-13T00:00:00Z", can_write: true,
        items: [{set: "address", name: "ci.example.org", type: "A", want: ["203.0.113.10"], live: [], status: "missing", severity: "problem", fix: "auto", steps: ["add A ci.example.org 203.0.113.10 (TTL 300)"]}],
        caa: {issuer: "letsencrypt.org", account_uri: "", would_issue: true},
        dnssec: {state: "unsigned", zone: "example.org.", provider_can_sign: false, ds: [], steps: ["Turn on DNSSEC signing"]}}' > "$STUB_DIR/dt/out-default"
cat > "$WORK/dtenv.sh" <<EOF
for l in common network domains stack config dns status; do source "$HERE/../scripts/lib/\$l.sh"; done
export PORTCULLIS_DOMAIN=ci.example.org PORTCULLIS_PUBLIC_IPV4=203.0.113.10 PORTCULLIS_PUBLIC_IPV6=
EOF
# dt <shell commands> — in a fresh shell with the libs, the stub and a
# clean log; prints the output (stderr too) and "rc=<n>".
dt() {
  rm -f "$STUB_DIR/dt/argv" "$STUB_DIR/dt/order" "$STUB_DIR/dt"/stdin-*
  (unset CLOUDFLARE_API_TOKEN AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_HOSTED_ZONE_ID HETZNER_API_KEY HETZNER_API_TOKEN \
      ACME_CA_SERVER ACME_STAGING DNS_CAA DNS_NOMAIL DNS_ACCOUNT_URI DNS_SETS DNS_PROVIDER
   PATH="$WORK/dtbin:$PATH" bash -c ". '$WORK/dtenv.sh'; $1" 2>&1; echo "rc=$?")
}
dtin() { jq -r "$2" "$STUB_DIR/dt/stdin-$1" 2>/dev/null; }

OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_setup true false ""')"
expect_eq "dns tool: credentials only on stdin (never in argv)" "$(grep -c 'tok-SECRET-123' "$STUB_DIR/dt/argv")" 0
expect_eq "dns tool: the token is the apply input's credentials.api_token" "$(dtin apply .credentials.api_token)" tok-SECRET-123
expect_eq "dns tool: the token never reaches the output" "$(printf '%s' "$OUT" | grep -c 'tok-SECRET-123')" 0
expect_eq "dns setup --yes: plan, apply, the service's main plan refreshed, check (no TTL read: no pin is replaced)" "$(paste -sd' ' "$STUB_DIR/dt/order")" "plan apply refresh check"
expect_eq "dns setup: apply waits by the stored TTL (--wait auto)" "$(grep -c 'dns-tool apply --wait auto$' "$STUB_DIR/dt/argv")" 1
expect_eq "dns setup: no 3 min cap (the operator runs it on purpose)" "$(grep -c -- '--wait-max' "$STUB_DIR/dt/argv" || true)" 0
expect_eq "dns setup: the default sets are address and caa" "$(dtin apply '.sets | join(",")')" "address,caa"
expect_eq "dns setup: the input's snake_case keys" "$(dtin apply '[keys[]] | join(",")')" "ca_server,caa,credentials,ipv4,ipv6,mail_from,name,nomail,provider,sets"
expect_eq "dns setup: caa block" "$(dtin apply '.caa | [.enabled, .account_uri, .issuer] | @json')" '[true,"",""]'
expect_eq "dns check: runs without credentials" "$(dtin check 'has("credentials"), .provider' | paste -sd' ' -)" 'false '
# wait_out <visible> <settled> <clears_in> <pending...> — the apply output
# with the tool's wait report (TTL 600 s, as Porkbun stores it).
wait_out() {
  local v="$1" st="$2" c="$3"; shift 3
  jq --argjson v "$v" --argjson s "$st" --argjson c "$c" --argjson x "${WAIT_EXTRA:-{\}}" --args '. + {wait: ({visible: $v, settled: $s, ttl: 600, limit: 660, waited: 660, pending: $ARGS.positional, clears_in: $c, written_at: 1800000000, settle_at: 1800000660, beyond_cap: false} + $x)}' \
    "$@" < "$STUB_DIR/dt/out-default" > "$STUB_DIR/dt/out-apply"
}
wait_out false false 324 8.8.8.8:53
echo 1 > "$STUB_DIR/dt/rc-apply"
OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_setup true false ""')"
case "$OUT" in *"DNS records (address caa) written; not yet stable at 8.8.8.8: it may serve the old records for up to 5 min 24 s more (until 2027-01-15 08:11 UTC)"*) t_pass "dns setup: a wait that hit its bound says written, not yet stable where, and for how long" ;;
  *) t_fail "dns setup wait timeout: $OUT" ;; esac
# E: written but not yet stable is no failure: no trailing check (it would
# hit a stale cache and say "problems"), exit 0, never "failed".
case "$OUT" in *"found problems"*|*"failed"*|*"could not"*) t_fail "dns setup not yet stable reads as a failure: $OUT" ;;
  *"dns check after 2027-01-15 08:11 UTC"*rc=0) t_pass "dns setup: not yet stable → exit 0, check after the time said" ;; *) t_fail "dns setup not yet stable: $OUT" ;; esac
expect_eq "dns setup: not yet stable → no trailing check" "$(paste -sd' ' "$STUB_DIR/dt/order")" "plan apply refresh"
# M1 / M2: the tool's progress line shows; its own timeout line doesn't
# (the shell words it once).
printf '%s\n' "domains dns apply: written; waiting up to 11m0s for 1.1.1.1:53, 8.8.8.8:53 (TTL 600 s)" \
  "domains dns apply: written; not yet stable at 8.8.8.8:53 after 11m0s (TTL 600 s; …)" > "$STUB_DIR/dt/err-apply"
OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_setup true false ""')"
case "$OUT" in *"domains dns apply: written; not yet stable"*) t_fail "dns setup: the timeout printed twice: $OUT" ;;
  *"written; waiting up to 11m0s for 1.1.1.1:53, 8.8.8.8:53"*"written; not yet stable at 8.8.8.8"*) t_pass "dns setup: progress shown, the timeout once" ;; *) t_fail "dns setup progress: $OUT" ;; esac
rm -f "$STUB_DIR/dt/rc-apply" "$STUB_DIR/dt/out-apply" "$STUB_DIR/dt/err-apply"

dt 'DNS_PROVIDER=route53 AWS_ACCESS_KEY_ID=AKIA-0123456789 AWS_SECRET_ACCESS_KEY=sec-0123456789 AWS_HOSTED_ZONE_ID=Z123 _dns_tool apply' >/dev/null
expect_eq "dns tool: route53 mapping" "$(dtin apply '.credentials | to_entries | map("\(.key)=\(.value)") | join(" ")')" \
  "access_key_id=AKIA-0123456789 secret_access_key=sec-0123456789 hosted_zone_id=Z123"
dt 'DNS_PROVIDER=route53 AWS_ACCESS_KEY_ID=AKIA-0123456789 AWS_SECRET_ACCESS_KEY=sec-0123456789 _dns_tool apply' >/dev/null
expect_eq "dns tool: route53 without the optional zone id" "$(dtin apply '.credentials | keys | join(",")')" "access_key_id,secret_access_key"
dt 'DNS_PROVIDER=hetzner HETZNER_API_KEY=legacy-0123456789 HETZNER_API_TOKEN=cloud-0123456789 _dns_tool apply' >/dev/null
expect_eq "dns tool: hetzner maps HETZNER_API_KEY" "$(dtin apply '[.provider, .credentials.api_token] | join(" ")')" "hetzner legacy-0123456789"
dt 'DNS_PROVIDER=hetzner-cloud HETZNER_API_KEY=legacy-0123456789 HETZNER_API_TOKEN=cloud-0123456789 _dns_tool apply' >/dev/null
expect_eq "dns tool: hetzner-cloud maps HETZNER_API_TOKEN" "$(dtin apply '[.provider, .credentials.api_token] | join(" ")')" "hetzner-cloud cloud-0123456789"

OUT="$(dt 'DNS_PROVIDER=cloudflare dns_setup true false ""')"
case "$OUT" in *"CLOUDFLARE_API_TOKEN is not set in .env (needed for DNS_PROVIDER=cloudflare)"*rc=1) t_pass "dns setup: missing CLOUDFLARE_API_TOKEN names the variable" ;;
  *) t_fail "dns setup: missing CLOUDFLARE_API_TOKEN: $OUT" ;; esac
expect_eq "dns setup: missing credential — the tool never ran" "$(grep -c 'dns-tool' "$STUB_DIR/dt/argv" 2>/dev/null || true)" 0
OUT="$(dt 'DNS_PROVIDER=cloudflare dns_check false')"
case "$OUT" in *rc=0) t_pass "dns check: works without credentials" ;; *) t_fail "dns check without credentials: $OUT" ;; esac

OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_setup false false "" </dev/null')"
case "$OUT" in *"non-interactive: pass --yes"*rc=1) t_pass "dns setup: non-interactive without --yes refuses" ;; *) t_fail "dns setup non-interactive: $OUT" ;; esac
expect_eq "dns setup: non-interactive refusal applies nothing" "$(paste -sd' ' "$STUB_DIR/dt/order")" "plan"

OUT="$(dt 'DNS_PROVIDER=gcloud dns_setup true false ""')"
case "$OUT" in *"create these records by hand"*"add A ci.example.org 203.0.113.10"*rc=0) t_pass "dns setup: manual provider prints steps, exit 0" ;;
  *) t_fail "dns setup manual provider: $OUT" ;; esac
expect_eq "dns setup: manual provider — plan only, read-only" "$(paste -sd' ' "$STUB_DIR/dt/order"):$(dtin plan 'has("credentials")')" "plan:false"

RC=0; "$CLI" dns setup --only bogus >/dev/null 2>"$WORK/dterr" </dev/null || RC=$?
expect_eq "dns setup --only bogus: usage error" "$RC:$(grep -c -- '--only must be address, caa, nomail or mail' "$WORK/dterr")" "2:1"
dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_setup true false caa' >/dev/null
expect_eq "dns setup --only caa: only that set" "$(dtin apply '.sets | join(",")')" "caa"
dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 DNS_NOMAIL=true dns_setup true false ""' >/dev/null
expect_eq "dns setup: DNS_NOMAIL=true adds nomail" "$(dtin apply '[.sets, .nomail] | @json')" '[["address","caa","nomail"],true]'
OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 DNS_CAA=yes dns_setup true false ""')"
case "$OUT" in *"DNS_CAA=yes must be true or false"*rc=1) t_pass "dns: DNS_CAA must be true or false" ;; *) t_fail "dns DNS_CAA=yes: $OUT" ;; esac

touch "$STUB_DIR/dt/acme-volume"
echo "https://acme-staging-v02.api.letsencrypt.org/acme/acct/42" > "$STUB_DIR/dt/traefik-uri"
dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_setup true false ""' >/dev/null
expect_eq "dns setup keeps Traefik's pin (apply)" "$(dtin apply .caa.account_uri)" "https://acme-staging-v02.api.letsencrypt.org/acme/acct/42"
expect_eq "dns check judges Traefik's pin" "$(dtin check .caa.account_uri)" "https://acme-staging-v02.api.letsencrypt.org/acme/acct/42"
: > "$STUB_DIR/dt/traefik-uri"
dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_setup true false ""' >/dev/null
expect_eq "dns setup: no Traefik account = CA-only" "$(dtin apply .caa.account_uri)" ""
touch "$STUB_DIR/dt/traefik-fail"
OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_setup true false ""')"
expect_eq "dns setup: an unreadable Traefik account leaves the live CAA alone" "$(dtin apply '.sets | join(",")')" "address"
case "$OUT" in *"couldn't be read"*) t_pass "dns setup: an unreadable Traefik account warns" ;; *) t_fail "unreadable account: $OUT" ;; esac
OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_setup true false caa')"
case "$OUT" in *"Nothing to apply"*rc=1) t_pass "dns setup --only caa: refused while the account can't be read" ;; *) t_fail "only caa unreadable: $OUT" ;; esac
rm -f "$STUB_DIR/dt/traefik-fail"
for bad in 'https://x.test/acct;validationmethods=http-01' 'http://x.test/acct' 'https://x.test/a b'; do
  printf '%s\n' "$bad" > "$STUB_DIR/dt/traefik-uri"
  expect_eq "traefik uri: '$bad' is refused" "$(dt 'dns_traefik_account_uri')" "rc=1"
done
: > "$STUB_DIR/dt/traefik-uri"
dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 DNS_ACCOUNT_URI=https://x.test/acct/1 dns_plan true' >/dev/null
expect_eq "dns plan: a caller's DNS_ACCOUNT_URI wins" "$(dtin plan .caa.account_uri)" "https://x.test/acct/1"
echo "https://acme-v02.api.letsencrypt.org/acme/acct/88" > "$STUB_DIR/dt/traefik-uri"
rm -f "$PORTCULLIS_ROOT/secrets/domains/main-domain.env"
OUT="$(dt 'dns_check true')"
expect_eq "dns check records Traefik's account in main-domain.env" "$(cat "$PORTCULLIS_ROOT/secrets/domains/main-domain.env" 2>/dev/null)" "DOMAINS_MAIN_ACME_ACCOUNT_URI=https://acme-v02.api.letsencrypt.org/acme/acct/88"
expect_eq "dns check --json: stdout is the plan alone" "$(printf '%s\n' "$OUT" | sed '$d' | grep -v '^==>' | jq -r .name 2>/dev/null)" "ci.example.org"
expect_eq "dns check: domains not running = not started for the new file" "$(grep -c ' up -d domains$' "$STUB_DIR/dt/argv" || true)" 0
rm -f "$PORTCULLIS_ROOT/secrets/domains/main-domain.env"
dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 DNS_ACCOUNT_URI=https://x.test/acct/1 dns_plan true' >/dev/null
expect_eq "dns plan: a caller's DNS_ACCOUNT_URI isn't recorded" "$(cat "$PORTCULLIS_ROOT/secrets/domains/main-domain.env" 2>/dev/null || echo none)" none
: > "$STUB_DIR/dt/traefik-uri"
rm -f "$STUB_DIR/dt/acme-volume"

dt 'ACME_STAGING=true dns_check true' >/dev/null
expect_eq "dns tool: ca_server from ACME_STAGING=true when ACME_CA_SERVER is empty" "$(dtin check .ca_server)" "https://acme-staging-v02.api.letsencrypt.org/directory"
dt 'ACME_STAGING=false dns_check true' >/dev/null
expect_eq "dns tool: ca_server from ACME_STAGING=false" "$(dtin check .ca_server)" "https://acme-v02.api.letsencrypt.org/directory"
dt 'ACME_CA_SERVER=https://pebble:14000/dir ACME_STAGING=true dns_check true' >/dev/null
expect_eq "dns tool: ACME_CA_SERVER wins" "$(dtin check .ca_server)" "https://pebble:14000/dir"

echo 1 > "$STUB_DIR/dt/rc-check"
OUT="$(dt 'dns_check false')"
case "$OUT" in *"CAA: issuer letsencrypt.org, account CA-only"*"DNSSEC: unsigned (zone example.org)"*rc=1) t_pass "dns check: renders the plan, exit 1 on a problem" ;;
  *) t_fail "dns check render/exit: $OUT" ;; esac
rm -f "$STUB_DIR/dt/rc-check"

# ══ dns lifecycle: Traefik pin, relax on a flip, main-domain.env, status ═══
touch "$STUB_DIR/dt/acme-volume"
echo "https://acme-v02.api.letsencrypt.org/acme/acct/77" > "$STUB_DIR/dt/traefik-uri"
OUT="$(dt 'dns_traefik_account_uri')"
expect_eq "traefik uri: printed" "$OUT" "https://acme-v02.api.letsencrypt.org/acme/acct/77
rc=0"
expect_eq "traefik uri: helper is network none, read-only volume, root" \
  "$(grep -c -- '^run --rm --network none --read-only --user 0:0 --cap-drop ALL --security-opt no-new-privileges:true -v portcullis_traefik_acme:/acme:ro portcullis-domains traefik-account-uri /acme/acme.json$' "$STUB_DIR/dt/argv")" 1
echo 'https://evil.test/acct/1 "x' > "$STUB_DIR/dt/traefik-uri"
OUT="$(dt 'dns_main_env_write "$(dns_traefik_account_uri)"; cat "$PORTCULLIS_ROOT/secrets/domains/main-domain.env" 2>/dev/null')"
case "$OUT" in *DOMAINS_MAIN*) t_fail "main-domain.env: a URI with quotes / spaces was written" ;; *) t_pass "main-domain.env: only a clean https URI is written" ;; esac
rm -f "$STUB_DIR/dt/acme-volume"
OUT="$(dt 'dns_traefik_account_uri')"
expect_eq "traefik uri: no volume = nothing (and no volume created)" "$OUT:$(grep -c -- '-v portcullis_traefik_acme' "$STUB_DIR/dt/argv")" "rc=0:0"

# tighten: a URI, the live pin differs (check says caa wrong) → pinned.
touch "$STUB_DIR/dt/acme-volume"
echo "https://acme-v02.api.letsencrypt.org/acme/acct/77" > "$STUB_DIR/dt/traefik-uri"
jq '.items = [{set: "caa", name: "ci.example.org", type: "CAA", want: ["x"], live: ["y"], status: "wrong", severity: "problem", fix: "auto", steps: []}] | .caa.would_issue = false' \
  "$STUB_DIR/dt/out-default" > "$STUB_DIR/dt/out-check"
rm -rf "$PORTCULLIS_ROOT/secrets/domains/main-domain.env"
OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_tighten_main')"
expect_eq "tighten: writes main-domain.env" "$(cat "$PORTCULLIS_ROOT/secrets/domains/main-domain.env")" "DOMAINS_MAIN_ACME_ACCOUNT_URI=https://acme-v02.api.letsencrypt.org/acme/acct/77"
expect_eq "tighten: main-domain.env is 0600" "$(file_mode "$PORTCULLIS_ROOT/secrets/domains/main-domain.env")" 600
expect_eq "tighten: domains recreated for the new env file" "$(grep -c ' up -d domains$' "$STUB_DIR/dt/argv")" 1
expect_eq "tighten: waits by the stored TTL (--wait auto, capped at 3 min, no --settle)" "$(grep -c 'dns-tool apply --wait auto --wait-max 3m$' "$STUB_DIR/dt/argv")" 1
expect_eq "tighten: pins when live differs (check, then apply caa with Traefik's URI)" \
  "$(paste -sd' ' "$STUB_DIR/dt/order"):$(dtin apply '[.sets, .caa.account_uri] | @json')" \
  'check apply refresh:[["caa"],"https://acme-v02.api.letsencrypt.org/acme/acct/77"]'
case "$OUT" in *rc=0) t_pass "tighten: returns 0" ;; *) t_fail "tighten: $OUT" ;; esac
# Live pin already right: no apply, no restart (the file is unchanged).
jq '.items = [{set: "caa", name: "ci.example.org", type: "CAA", want: ["x"], live: ["x"], status: "ok", severity: "ok", fix: "none", steps: []}] | .caa.would_issue = true' \
  "$STUB_DIR/dt/out-default" > "$STUB_DIR/dt/out-check"
dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_tighten_main' >/dev/null
expect_eq "tighten: live pin right = check only, no restart" "$(paste -sd' ' "$STUB_DIR/dt/order"):$(grep -c ' up -d domains$' "$STUB_DIR/dt/argv" || true)" "check:0"
# A failing apply only warns.
jq '.caa.would_issue = false' "$STUB_DIR/dt/out-check" > "$STUB_DIR/dt/out-check2" && mv "$STUB_DIR/dt/out-check2" "$STUB_DIR/dt/out-check"
echo 3 > "$STUB_DIR/dt/rc-apply"
OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_tighten_main')"
case "$OUT" in *"could not pin the CAA of ci.example.org to Traefik's account: the write failed"*rc=0) t_pass "tighten: a failed pin warns, returns 0" ;; *) t_fail "tighten failed pin: $OUT" ;; esac
echo 2 > "$STUB_DIR/dt/rc-apply"
OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_tighten_main')"
case "$OUT" in *"the write failed"*) t_fail "tighten exit 2 reads as a failed write: $OUT" ;; *"the domains image is older than this CLI"*rc=0) t_pass "tighten: exit 2 = an old domains image" ;; *) t_fail "tighten exit 2: $OUT" ;; esac
echo 3 > "$STUB_DIR/dt/rc-apply"
expect_eq "tighten: a failed pin still refreshes the main plan (a partial write)" "$(paste -sd' ' "$STUB_DIR/dt/order")" "check apply refresh"
# Written but not visible yet (Porkbun's 600 s TTL): honest, never "could not pin".
wait_out false false 324 8.8.8.8:53 1.1.1.1:53
echo 1 > "$STUB_DIR/dt/rc-apply"
OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_tighten_main')"
case "$OUT" in *"could not"*) t_fail "tighten timeout reads as a failure: $OUT" ;;
  *"The CAA pin of ci.example.org written; not yet stable at 8.8.8.8, 1.1.1.1: they may serve the old records for up to 5 min 24 s more (until 2027-01-15 08:11 UTC)"*rc=0) t_pass "tighten: a wait timeout says written, not yet stable where, and for how long" ;;
  *) t_fail "tighten timeout: $OUT" ;; esac
# Ruling (concern 2): the tighten isn't a safety step, so `up` is never held
# 15 min by it: its wait is capped at 3 min (--wait-max 3m), and reaching
# the cap is success. dns setup keeps the 15 min cap.
expect_eq "tighten: the stability wait is capped at 3 min" "$(grep -c 'dns-tool apply --wait auto --wait-max 3m$' "$STUB_DIR/dt/argv")" 1
rm -f "$STUB_DIR/dt/rc-apply" "$STUB_DIR/dt/out-apply"
# The refresh is best effort: the domains service down only skips it.
touch "$STUB_DIR/dt/refresh-fail"
rm -f "$STUB_DIR/dt/rc-apply"
OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_tighten_main')"
case "$OUT" in *"CAA of ci.example.org pinned"*rc=0) t_pass "tighten: a failed main-plan refresh is ignored" ;; *) t_fail "tighten refresh-fail: $OUT" ;; esac
OUT="$(dt 'DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_setup true false ""')"
case "$OUT" in *rc=0) t_pass "dns setup: a failed main-plan refresh is ignored" ;; *) t_fail "setup refresh-fail: $OUT" ;; esac
rm -f "$STUB_DIR/dt/refresh-fail"
echo 3 > "$STUB_DIR/dt/rc-apply"
rm -f "$STUB_DIR/dt/rc-apply" "$STUB_DIR/dt/out-check"
# No account within the poll window.
rm -f "$STUB_DIR/dt/acme-volume"
OUT="$(dt 'DNS_TIGHTEN_TIMEOUT=1 DNS_TIGHTEN_POLL=1 DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 dns_tighten_main')"
case "$OUT" in *"no ACME account yet"*rc=0) t_pass "tighten: no account within the poll window warns, returns 0" ;; *) t_fail "tighten no account: $OUT" ;; esac
expect_eq "tighten: polled more than once" "$([ "$(grep -c '^volume inspect portcullis_traefik_acme$' "$STUB_DIR/dt/argv")" -gt 1 ] && echo yes)" yes
dt 'DNS_PROVIDER=gcloud dns_tighten_main' >/dev/null
expect_eq "tighten: manual provider reads once, no poll" "$(grep -c '^volume inspect portcullis_traefik_acme$' "$STUB_DIR/dt/argv")" 1
dt 'DNS_CAA=false DNS_PROVIDER=cloudflare dns_tighten_main' >/dev/null
expect_eq "tighten: DNS_CAA=false reads once, no poll, no tool" "$(grep -c '^volume inspect portcullis_traefik_acme$' "$STUB_DIR/dt/argv"):$(grep -c dns-tool "$STUB_DIR/dt/argv" || true)" "1:0"
touch "$STUB_DIR/dt/acme-volume"
rm -f "$PORTCULLIS_ROOT/secrets/domains/main-domain.env"
dt 'DNS_CAA=false DNS_PROVIDER=cloudflare dns_tighten_main' >/dev/null
expect_eq "tighten: DNS_CAA=false still records the URI" "$(cat "$PORTCULLIS_ROOT/secrets/domains/main-domain.env")" "DOMAINS_MAIN_ACME_ACCOUNT_URI=https://acme-v02.api.letsencrypt.org/acme/acct/77"

# config apply on a staging flip: relax before acme.json is removed.
FL_ROOT="$WORK/flip"; mkdir -p "$FL_ROOT/certs"
echo false > "$FL_ROOT/certs/.acme-staging-last"
flip() { # flip <extra shell> — config_apply with ACME_STAGING=true after false
  printf 'PORTCULLIS_DOMAIN=ci.example.org\nACME_STAGING=true\n' > "$FL_ROOT/.env"
  echo false > "$FL_ROOT/certs/.acme-staging-last"
  rm -f "$STUB_DIR/dt/argv" "$STUB_DIR/dt/order"
  [ -f "$STUB_DIR/dt/keep-state" ] || rm -f "$FL_ROOT/secrets/domains/acme-relax.env"
  rm -f "$STUB_DIR/dt/traefik-up"
  (PATH="$WORK/dtbin:$WORK/cabin:$PATH" PORTCULLIS_ROOT="$FL_ROOT" bash -c ". '$WORK/dtenv.sh'; export PORTCULLIS_ROOT='$FL_ROOT' ACME_CA_SERVER=https://acme-v02.api.letsencrypt.org/directory; config_build_ca_bundle() { echo BUNDLE >> \"\$STUB_DIR/dt/argv\"; [ ! -f \"\$STUB_DIR/dt/bundle-fail\" ] || fail bundle; }; $1; config_apply" 2>&1; echo "rc=$?")
}
FCF='export DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123'
RELAXF="$FL_ROOT/secrets/domains/acme-relax.env"
argn() { grep -n -m1 -e "$1" "$STUB_DIR/dt/argv" | cut -d: -f1; }
OUT="$(flip "$FCF; dns_relax_main() { echo RELAX >> \"\$STUB_DIR/dt/argv\"; }")"
RL="$(argn '^RELAX$')" RM="$(argn 'rm -f /acme/acme.json')"
expect_eq "config apply flip: relax runs before acme.json is removed" "$([ -n "$RL" ] && [ -n "$RM" ] && [ "$RL" -lt "$RM" ] && echo yes)" yes
# A settled relax. I2: the relax and its wait run with Traefik up (CA-only
# lets its current account renew); only then stop, clear, and start it
# again (recreated: the new ACME_CA_SERVER) when it was running.
wait_out true true 0
echo '{"ttl": 600}' > "$STUB_DIR/dt/out-ttl"
touch "$STUB_DIR/dt/traefik-running"
OUT="$(flip "$FCF")"
expect_eq "config apply flip: relax applies caa CA-only" "$(dtin apply '[.sets, .caa.account_uri] | @json')" '[["caa"],""]'
expect_eq "config apply flip: the old pin's TTL read first, the domains image rebuilt before (I4), the public check last (N2)" "$(paste -sd' ' "$STUB_DIR/dt/order")" "build ttl apply refresh check"
expect_eq "config apply flip: relax settles past the saved point (--wait auto --settle --settle-after)" "$(grep -c 'dns-tool apply --wait auto --settle --settle-after [0-9][0-9]*$' "$STUB_DIR/dt/argv")" 1
expect_eq "config apply flip: settled relax → acme.json cleared, sentinel written, state removed" \
  "$(grep -c 'rm -f /acme/acme.json' "$STUB_DIR/dt/argv"):$(cat "$FL_ROOT/certs/.acme-staging-last"):$([ -e "$RELAXF" ] && echo kept || echo gone):${OUT##*rc=}" "1:true:gone:0"
A1="$(argn 'dns-tool apply')" A2="$(argn 'stop traefik')" A3="$(argn 'rm -f /acme/acme.json')" A4="$(argn 'up -d --no-deps traefik')"
expect_eq "config apply flip: relax, then stop, clear, start Traefik again" \
  "$([ -n "$A1" ] && [ -n "$A4" ] && [ "$A1" -lt "$A2" ] && [ "$A2" -lt "$A3" ] && [ "$A3" -lt "$A4" ] && echo yes)" yes
ord() { printf '%s\n' "$OUT" | grep -n -m1 -F "$1" | cut -d: -f1; }
O1="$(ord 'ACME_STAGING flipped')" O2="$(ord 'Relaxing the CAA')" O3="$(ord 'every cache of the old pin has expired')" O4="$(ord 'Stopping Traefik')" O5="$(ord "Clearing Traefik's ACME storage")" O6="$(ord 'Starting Traefik')"
expect_eq "config apply flip: messages in the order things happen" \
  "$([ -n "$O1" ] && [ -n "$O6" ] && [ "$O1" -lt "$O2" ] && [ "$O2" -lt "$O3" ] && [ "$O3" -lt "$O4" ] && [ "$O4" -lt "$O5" ] && [ "$O5" -lt "$O6" ] && echo yes)" yes
expect_eq "config apply flip: the flip line doesn't claim the clearing" "$(printf '%s' "$OUT" | grep 'ACME_STAGING flipped' | grep -c clearing || true)" 0
# N1: compose recreates Traefik with the NEW CA (the shell's variable wins
# over .env), and the sentinel is written only after that start.
expect_eq "config apply flip: Traefik recreated on the new CA, before the sentinel says done" \
  "$(cat "$STUB_DIR/dt/traefik-up" 2>/dev/null)" "CA=https://acme-staging-v02.api.letsencrypt.org/directory sentinel=false"
# I9: the CA bundle (it may download) is built before Traefik stops.
B1="$(argn '^BUNDLE$')" B2="$(argn 'stop traefik')"
expect_eq "config apply flip: CA bundle before the stop" "$([ -n "$B1" ] && [ -n "$B2" ] && [ "$B1" -lt "$B2" ] && echo yes)" yes
# I9: Traefik doesn't start on the new CA → fail, Traefik started again
# (EXIT trap), the flip stays pending.
touch "$STUB_DIR/dt/up-fail"
OUT="$(flip "$FCF")"
expect_eq "config apply flip: a failed start after the clear → rc 1, sentinel unchanged, Traefik started again" \
  "${OUT##*rc=}:$(cat "$FL_ROOT/certs/.acme-staging-last"):$(grep -c ' start traefik$' "$STUB_DIR/dt/argv" || true)" "1:false:1"
rm -f "$STUB_DIR/dt/up-fail"
# M5: exit 0 without settled: true is not settled.
wait_out true false 0
OUT="$(flip "$FCF")"
expect_eq "config apply flip: exit 0 without wait.settled is not settled" "$(grep -c 'rm -f /acme/acme.json' "$STUB_DIR/dt/argv" || true):${OUT##*rc=}" "0:1"
# Written but not settled: fail safe — acme.json kept, sentinel unchanged,
# Traefik never stopped (it ran on through the relax), exit 1.
wait_out false false 540 8.8.8.8:53
echo 1 > "$STUB_DIR/dt/rc-apply"
OUT="$(flip "$FCF")"
case "$OUT" in *"could not relax"*) t_fail "relax timeout reads as a failure: $OUT" ;;
  *"The CA-only CAA of ci.example.org written; not yet stable at 8.8.8.8: it may serve the old pin for up to 9 min more (until 2027-01-15 08:11 UTC)"*"after 2027-01-15 08:11 UTC"*"flip is not finished"*rc=1) t_pass "config apply flip: an unsettled relax refuses to go on, honestly worded, with the time to rerun" ;;
  *) t_fail "relax timeout: $OUT" ;; esac
expect_eq "config apply flip: unsettled → acme.json kept, sentinel unchanged, Traefik never stopped" \
  "$(grep -c 'rm -f /acme/acme.json' "$STUB_DIR/dt/argv" || true):$(cat "$FL_ROOT/certs/.acme-staging-last"):$(grep -c 'stop traefik' "$STUB_DIR/dt/argv" || true)" "0:false:0"
expect_eq "config apply flip: nothing claims Traefik's storage was cleared" "$(printf '%s' "$OUT" | grep -c "Clearing Traefik" || true)" 0
# M3: visible but not settled, one "but".
wait_out true false 3000
OUT="$(flip "$FCF")"
case "$OUT" in *"CA-only CAA of ci.example.org written; every resolver checked shows it, but the CA's resolvers may cache the old pin for up to 50 min"*rc=1) t_pass "config apply flip: visible but unsettled refuses too" ;;
  *) t_fail "relax visible-unsettled: $OUT" ;; esac
# I5 + F: beyond the cap — each cause worded on its own, with the time
# after which a rerun goes ahead. (a) The stored TTL is above the cap.
WAIT_EXTRA='{"ttl":3600,"beyond_cap":true,"settle_at":1800003660,"settle_cause":"ttl"}' wait_out true false 3660
OUT="$(flip "$FCF")"
case "$OUT" in *"the old pin's stored TTL (3600 s, 60 min) is above what one run waits (15 min)"*"goes ahead after 2027-01-15 09:01 UTC"*"lowering the CAA TTL at cloudflare first shortens it"*rc=1) t_pass "config apply flip: beyond the cap, the stored TTL named as the cause, and the time" ;;
  *) t_fail "relax beyond cap (ttl): $OUT" ;; esac
# (b) The F run: TTL 600 (below the cap), but 8.8.8.8 still serves the old
# pin with 547 s left — never "TTL 600 s, longer than one run waits".
WAIT_EXTRA='{"ttl":600,"beyond_cap":true,"settle_at":1800001115,"settle_cause":"resolver","held_by":["8.8.8.8:53"],"held_for":547}' wait_out true false 1115
OUT="$(flip "$FCF")"
case "$OUT" in *"longer than one run waits"*|*"stored TTL"*) t_fail "relax beyond cap (resolver) blames the TTL: $OUT" ;;
  *"but 8.8.8.8 still serves the old pin (547 s left), so caches (the CA's too) may hold it until 2027-01-15 08:19 UTC"*"goes ahead after 2027-01-15 08:19 UTC"*rc=1) t_pass "config apply flip: beyond the cap because a resolver holds the old pin: named, with the seconds left and the time" ;;
  *) t_fail "relax beyond cap (resolver): $OUT" ;; esac
# (c) An earlier run's saved settle point is past what one run waits.
WAIT_EXTRA='{"ttl":300,"beyond_cap":true,"settle_at":1800003600,"settle_cause":"saved"}' wait_out true false 3600
OUT="$(flip "$FCF")"
case "$OUT" in *"the settle point saved earlier"*"goes ahead after 2027-01-15 09:00 UTC"*rc=1) t_pass "config apply flip: beyond the cap because of the saved settle point: said, with the time" ;;
  *) t_fail "relax beyond cap (saved): $OUT" ;; esac
# C1: the settle point is saved (0600) before the write, from the old pin's
# TTL; a rerun passes it and never lowers it, even if the tool, seeing
# only the CA-only records it wrote, reports an earlier one.
echo '{"ttl": 3600}' > "$STUB_DIR/dt/out-ttl"
T0="$(date +%s)"
OUT="$(flip "$FCF")"
NB="$(sed -n 's/^RELAX_NOT_BEFORE=//p' "$RELAXF" 2>/dev/null)"
expect_eq "config apply flip: settle point saved, 0600, from the old pin's TTL" \
  "$(file_mode "$RELAXF"):$(sed -n 's/^RELAX_OLD_TTL=//p' "$RELAXF"):$([ -n "$NB" ] && [ "$NB" -ge $((T0 + 3660)) ] && echo ok)" "600:3600:ok"
touch "$STUB_DIR/dt/keep-state"
WAIT_EXTRA='{"ttl":300,"settle_at":1800000360}' wait_out true false 300
OUT="$(flip "$FCF")"
expect_eq "config apply flip: a rerun reads no TTL again and passes the saved point" \
  "$(paste -sd' ' "$STUB_DIR/dt/order"):$(grep -c "dns-tool apply --wait auto --settle --settle-after $NB\$" "$STUB_DIR/dt/argv")" "build apply refresh:1"
expect_eq "config apply flip: a rerun never lowers the saved point" "$(sed -n 's/^RELAX_NOT_BEFORE=//p' "$RELAXF" 2>/dev/null || echo gone)" "$NB"
rm -f "$STUB_DIR/dt/keep-state" "$STUB_DIR/dt/rc-apply"
# I3: a failed clear fails the run and keeps the flip pending.
wait_out true true 0
touch "$STUB_DIR/dt/rm-fail"
OUT="$(flip "$FCF")"
case "$OUT" in *"could not clear Traefik's ACME storage"*rc=1) t_pass "config apply flip: a failed clear fails the run" ;; *) t_fail "clear failure: $OUT" ;; esac
expect_eq "config apply flip: failed clear → sentinel unchanged, state kept, Traefik started again" \
  "$(cat "$FL_ROOT/certs/.acme-staging-last"):$([ -e "$RELAXF" ] && echo kept):$(grep -c ' start traefik$' "$STUB_DIR/dt/argv" || true)" "false:kept:1"
rm -f "$STUB_DIR/dt/rm-fail"
# I2: interrupted after the stop → the trap starts Traefik again (once).
touch "$STUB_DIR/dt/rm-term"
OUT="$(flip "$FCF")"
expect_eq "config apply flip: TERM after the stop starts Traefik again, sentinel unchanged" \
  "$(grep -c ' start traefik$' "$STUB_DIR/dt/argv" || true):$(cat "$FL_ROOT/certs/.acme-staging-last")" "1:false"
rm -f "$STUB_DIR/dt/rm-term"
# I9: an SSH drop (HUP) too.
touch "$STUB_DIR/dt/rm-hup"
OUT="$(flip "$FCF")"
expect_eq "config apply flip: HUP after the stop starts Traefik again, sentinel unchanged" \
  "$(grep -c ' start traefik$' "$STUB_DIR/dt/argv" || true):$(cat "$FL_ROOT/certs/.acme-staging-last")" "1:false"
rm -f "$STUB_DIR/dt/rm-hup"
# M15: Traefik doesn't stop → fail before the clear (acme.json is never
# cleared under a running Traefik), Traefik started again.
touch "$STUB_DIR/dt/stop-fail" "$STUB_DIR/dt/traefik-exists"
OUT="$(flip "$FCF")"
expect_eq "config apply flip: a failed stop → rc 1, no clear, sentinel unchanged" \
  "${OUT##*rc=}:$(grep -c 'rm -f /acme/acme.json' "$STUB_DIR/dt/argv" || true):$(cat "$FL_ROOT/certs/.acme-staging-last")" "1:0:false"
# M20: no Traefik container at all (after `down`): a failing stop isn't a failure.
rm -f "$STUB_DIR/dt/traefik-exists"
OUT="$(flip "$FCF")"
expect_eq "config apply flip: stop fails but no Traefik container exists → the flip goes on" \
  "${OUT##*rc=}:$(grep -c 'rm -f /acme/acme.json' "$STUB_DIR/dt/argv" || true):$(cat "$FL_ROOT/certs/.acme-staging-last")" "0:1:true"
rm -f "$STUB_DIR/dt/stop-fail"
# M16: no container to start (a recreate removed it) → the trap recreates it.
touch "$STUB_DIR/dt/rm-term" "$STUB_DIR/dt/start-fail"
OUT="$(flip "$FCF")"
S1="$(argn ' start traefik$')" S2="$(grep -n 'up -d --no-deps traefik' "$STUB_DIR/dt/argv" | tail -n1 | cut -d: -f1)"
expect_eq "config apply flip: dc start fails → the trap falls back to up -d --no-deps traefik" "$([ -n "$S1" ] && [ -n "$S2" ] && [ "$S1" -lt "$S2" ] && echo yes)" yes
rm -f "$STUB_DIR/dt/rm-term" "$STUB_DIR/dt/start-fail" "$STUB_DIR/dt/traefik-running"
# I9: a failure before the stop (the CA bundle) leaves Traefik alone.
touch "$STUB_DIR/dt/bundle-fail"
OUT="$(flip "$FCF")"
expect_eq "config apply flip: a failed CA bundle → rc 1, Traefik never stopped" "${OUT##*rc=}:$(grep -c 'stop traefik' "$STUB_DIR/dt/argv" || true)" "1:0"
rm -f "$STUB_DIR/dt/bundle-fail"
# Traefik wasn't running: it isn't started.
OUT="$(flip "$FCF")"
expect_eq "config apply flip: Traefik not started when it wasn't running" "$(grep -c -e ' start traefik$' -e 'up -d --no-deps traefik' "$STUB_DIR/dt/argv" || true):${OUT##*rc=}" "0:0"
# A failed write: a different message, same fail-safe stop.
echo 3 > "$STUB_DIR/dt/rc-apply"
OUT="$(flip "$FCF")"
case "$OUT" in *"could not relax the CAA of ci.example.org to CA-only: the write failed"*"flip is not finished"*rc=1) t_pass "config apply flip: a failed relax refuses to go on" ;; *) t_fail "relax failure: $OUT" ;; esac
expect_eq "config apply flip: acme.json kept after a failed relax" "$(grep -c 'rm -f /acme/acme.json' "$STUB_DIR/dt/argv" || true):$(cat "$FL_ROOT/certs/.acme-staging-last")" "0:false"
# I4: an old domains image refuses the arguments (exit 2): its own message.
echo 2 > "$STUB_DIR/dt/rc-apply"
OUT="$(flip "$FCF")"
case "$OUT" in *"the write failed"*) t_fail "exit 2 reads as a failed write: $OUT" ;;
  *"the domains image is older than this CLI"*rc=1) t_pass "config apply flip: exit 2 = an old domains image" ;; *) t_fail "relax exit 2: $OUT" ;; esac
# No flip pending: a leftover settle point is removed.
mkdir -p "$(dirname "$RELAXF")"; echo RELAX_NOT_BEFORE=1 > "$RELAXF"
printf 'PORTCULLIS_DOMAIN=ci.example.org\nACME_STAGING=true\n' > "$FL_ROOT/.env"; echo true > "$FL_ROOT/certs/.acme-staging-last"
(PATH="$WORK/dtbin:$WORK/cabin:$PATH" PORTCULLIS_ROOT="$FL_ROOT" bash -c ". '$WORK/dtenv.sh'; export PORTCULLIS_ROOT='$FL_ROOT'; config_build_ca_bundle() { :; }; $FCF; config_apply" >/dev/null 2>&1)
expect_eq "config apply: ACME_STAGING reverted mid-flip → the settle point stays in force" "$([ -e "$RELAXF" ] && echo kept || echo gone)" kept
# I10: a pin written again (the tighten after `up`, `dns setup`) never
# deletes it — caches may still hold the original long-TTL pin — and may
# only move it later: max(saved, now + OLD_TTL + 60). The next flip, still
# within the old TTL, passes it on.
touch "$STUB_DIR/dt/acme-volume"; echo "https://acme-v02.api.letsencrypt.org/acme/acct/77" > "$STUB_DIR/dt/traefik-uri"
jq '.items = [{set: "caa", name: "ci.example.org", type: "CAA", want: ["x"], live: ["y"], status: "wrong", severity: "problem", fix: "auto", steps: []}] | .caa.would_issue = false' "$STUB_DIR/dt/out-default" > "$STUB_DIR/dt/out-check"
rm -f "$STUB_DIR/dt/rc-apply"; wait_out true true 0
for how in tighten setup; do
  T0="$(date +%s)"
  printf 'RELAX_WRITTEN_AT=%s\nRELAX_OLD_TTL=3600\nRELAX_NOT_BEFORE=%s\n' "$((T0 - 10))" "$((T0 + 3650))" > "$RELAXF"
  if [ "$how" = tighten ]; then cmd=dns_tighten_main; else cmd='dns_setup true false ""'; fi
  (PATH="$WORK/dtbin:$PATH" PORTCULLIS_ROOT="$FL_ROOT" bash -c ". '$WORK/dtenv.sh'; export PORTCULLIS_ROOT='$FL_ROOT'; $FCF; $cmd" >/dev/null 2>&1)
  NB="$(sed -n 's/^RELAX_NOT_BEFORE=//p' "$RELAXF" 2>/dev/null)"
  expect_eq "$how: a re-pin keeps the settle point, moved to ≥ now + OLD_TTL + 60" "$([ -n "$NB" ] && [ "$NB" -ge $((T0 + 3660)) ] && echo ok)" ok
  # Then a flip, still within the old pin's TTL: the saved point is passed.
  touch "$STUB_DIR/dt/keep-state"
  WAIT_EXTRA='{"settle_at":1}' wait_out true false 3600; echo 1 > "$STUB_DIR/dt/rc-apply"
  OUT="$(flip "$FCF")"
  expect_eq "$how, then a flip: the relax passes the saved point (no fresh TTL read)" \
    "$(grep -c "settle-after $NB\$" "$STUB_DIR/dt/argv"):$(grep -c 'dns-tool ttl' "$STUB_DIR/dt/argv" || true)" "1:0"
  rm -f "$STUB_DIR/dt/keep-state" "$STUB_DIR/dt/rc-apply"; wait_out true true 0
done
rm -f "$STUB_DIR/dt/out-check" "$RELAXF"
# I6: no saved point (lost, corrupt) but the CAA is already CA-only: the
# old pin's TTL can't be known → now + 24 h, saved, with the time.
echo '{"ttl": 600, "caa_relaxed": true}' > "$STUB_DIR/dt/out-ttl"
MDE="$FL_ROOT/secrets/domains/main-domain.env"
# M19: Portcullis never pinned (main-domain.env never held an account URI):
# no old pin to wait out — no 24 h point; the public check guards the rest.
rm -f "$MDE" "$RELAXF"
echo '{"ttl": 0, "caa_relaxed": true}' > "$STUB_DIR/dt/out-ttl"
T0="$(date +%s)"; wait_out true true 0
OUT="$(flip "$FCF")"
case "$OUT" in *"24 h"*) t_fail "never pinned: 24 h: $OUT" ;; *rc=0) t_pass "relax: never pinned (no account URI ever recorded) → no 24 h, the flip goes on" ;; *) t_fail "never pinned: $OUT" ;; esac
echo '{"ttl": 600, "caa_relaxed": true}' > "$STUB_DIR/dt/out-ttl"
mkdir -p "$(dirname "$MDE")"; echo "DOMAINS_MAIN_ACME_ACCOUNT_URI=https://acme-v02.api.letsencrypt.org/acme/acct/77" > "$MDE"
for st in missing corrupt; do
  printf 'PORTCULLIS_DOMAIN=ci.example.org\nACME_STAGING=true\n' > "$FL_ROOT/.env"
  touch "$STUB_DIR/dt/keep-state"; rm -f "$RELAXF"
  [ "$st" = missing ] || { mkdir -p "$(dirname "$RELAXF")"; echo 'RELAX_NOT_BEFORE=soon' > "$RELAXF"; }
  T0="$(date +%s)"
  WAIT_EXTRA='{"beyond_cap":true,"settle_at":1}' wait_out true false 86400; echo 1 > "$STUB_DIR/dt/rc-apply"
  OUT="$(flip "$FCF")"
  NB="$(sed -n 's/^RELAX_NOT_BEFORE=//p' "$RELAXF" 2>/dev/null)"
  case "$st:$OUT" in missing:*"No Portcullis pin of ci.example.org is live"*"no settle record exists"*"the old pin's lifetime is unknown"*"24 h"*"can go ahead after"*rc=1|corrupt:*"unreadable"*"can't be known"*"24 h"*rc=1) t_pass "relax: $st settle point, CAA already relaxed → 24 h, said" ;; *) t_fail "relax $st: $OUT" ;; esac
  case "$OUT" in *"dns setup"*|*"pin the CAA again"*) t_fail "relax $st: the 24 h warning suggests a re-pin: $OUT" ;; *) t_pass "relax: $st — the 24 h warning offers no re-pin way around it" ;; esac
  expect_eq "relax: $st settle point → now + 24 h saved, passed on" \
    "$([ "${NB:-0}" -ge $((T0 + 86400)) ] 2>/dev/null && echo ok):$(grep -c "settle-after $NB\$" "$STUB_DIR/dt/argv")" "ok:1"
done
rm -f "$STUB_DIR/dt/keep-state" "$STUB_DIR/dt/rc-apply"
# A file that exists but can't be read means a relax happened once: 24 h
# even when the CAA is pinned now (a re-pin since), never a fresh read.
echo '{"ttl": 300, "caa_relaxed": false}' > "$STUB_DIR/dt/out-ttl"
touch "$STUB_DIR/dt/keep-state"; echo 'RELAX_NOT_BEFORE=soon' > "$RELAXF"
T0="$(date +%s)"
WAIT_EXTRA='{"beyond_cap":true,"settle_at":1}' wait_out true false 86400; echo 1 > "$STUB_DIR/dt/rc-apply"
OUT="$(flip "$FCF")"
NB="$(sed -n 's/^RELAX_NOT_BEFORE=//p' "$RELAXF" 2>/dev/null)"
expect_eq "relax: unreadable settle point, CAA pinned now → 24 h too" "$([ "${NB:-0}" -ge $((T0 + 86400)) ] 2>/dev/null && echo ok)" ok
rm -f "$STUB_DIR/dt/keep-state" "$STUB_DIR/dt/rc-apply"
echo '{"ttl": 600, "caa_relaxed": true}' > "$STUB_DIR/dt/out-ttl"
# One edited field can't move the point earlier: max(NOT_BEFORE, WRITTEN_AT + OLD_TTL + 60).
touch "$STUB_DIR/dt/keep-state"
printf 'RELAX_WRITTEN_AT=1900000000\nRELAX_OLD_TTL=3600\nRELAX_NOT_BEFORE=5\n' > "$RELAXF"
WAIT_EXTRA='{"beyond_cap":true}' wait_out true false 3600; echo 1 > "$STUB_DIR/dt/rc-apply"
OUT="$(flip "$FCF")"
expect_eq "relax: the saved point is max(NOT_BEFORE, WRITTEN_AT + OLD_TTL + 60)" "$(grep -c 'settle-after 1900003660$' "$STUB_DIR/dt/argv")" 1
rm -f "$STUB_DIR/dt/keep-state" "$STUB_DIR/dt/rc-apply"
# I7: the old pin's TTL can't be read (or isn't a number): refuse before
# any write, nothing saved.
for bad in rc3 nonum; do
  rm -f "$RELAXF"
  if [ "$bad" = rc3 ]; then echo 3 > "$STUB_DIR/dt/rc-ttl"; else echo '{"ttl": null}' > "$STUB_DIR/dt/out-ttl"; fi
  OUT="$(flip "$FCF")"
  case "$OUT" in *"could not read how long caches hold the CAA of ci.example.org"*"nothing changed"*rc=1) t_pass "relax: TTL unreadable ($bad) refuses" ;; *) t_fail "relax ttl $bad: $OUT" ;; esac
  expect_eq "relax: TTL unreadable ($bad) → no apply, nothing saved" "$(grep -c 'dns-tool apply' "$STUB_DIR/dt/argv" || true):$([ -e "$RELAXF" ] && echo saved)" "0:"
  rm -f "$STUB_DIR/dt/rc-ttl"
done
# I8: the settle point from the tool's progress line (written right after
# the write) is saved at once — also when the run dies during the wait.
echo '{"ttl": 600, "caa_relaxed": false}' > "$STUB_DIR/dt/out-ttl"
rm -f "$RELAXF"
echo "domains dns apply: written; waiting up to 11m0s for 1.1.1.1:53 (TTL 600 s); written_at=1899999340 settle_at=1900000000" > "$STUB_DIR/dt/err-apply"
echo 130 > "$STUB_DIR/dt/rc-apply"
OUT="$(flip "$FCF")"
expect_eq "relax: the progress line's settle point is saved even when the wait dies" "$(sed -n 's/^RELAX_NOT_BEFORE=//p' "$RELAXF" 2>/dev/null):${OUT##*rc=}" "1900000000:1"
# … and a failed save is a failure.
rm -f "$RELAXF"; chmod 500 "$(dirname "$RELAXF")"
OUT="$(flip "$FCF")"
chmod 700 "$(dirname "$RELAXF")"
case "$OUT" in *"could not save the relax's settle point"*rc=1) t_pass "relax: a failed save fails" ;; *) t_fail "relax failed save: $OUT" ;; esac
rm -f "$STUB_DIR/dt/err-apply" "$STUB_DIR/dt/rc-apply" "$RELAXF"
rm -f "$STUB_DIR/dt/out-ttl"
rm -f "$STUB_DIR/dt/rc-apply" "$RELAXF"
wait_out true true 0
echo '{"ttl": 600}' > "$STUB_DIR/dt/out-ttl"
OUT="$(flip 'export DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 DNS_CAA=yes')"
case "$OUT" in *"DNS_CAA=yes must be true or false"*rc=1) t_pass "config apply flip: DNS_CAA must be true or false" ;; *) t_fail "flip DNS_CAA=yes: $OUT" ;; esac
expect_eq "config apply flip: a bad DNS_CAA refuses before Traefik is stopped" "$(cat "$STUB_DIR/dt/argv" 2>/dev/null | grep -c 'stop traefik' || true)" 0
OUT="$(flip 'export DNS_PROVIDER=gcloud')"
expect_eq "config apply flip: no relax for a manual provider" "$(grep -c -e 'dns-tool apply' -e 'dns-tool ttl' "$STUB_DIR/dt/argv" || true)" 0
# Where Portcullis doesn't manage the CAA — DNS_CAA=false, no or a manual
# provider, an automated one without its credentials — a flip does no
# relax, no settle, no wait and no 24 h point: stop, clear, Traefik back
# on the new CA, sentinel (as before this branch, plus N1's export).
touch "$STUB_DIR/dt/traefik-running"
for unmanaged in 'export DNS_CAA=false DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123' 'export DNS_PROVIDER=none' \
    'export DNS_PROVIDER=gcloud' 'unset CLOUDFLARE_API_TOKEN; export DNS_PROVIDER=cloudflare'; do
  rm -f "$RELAXF"
  OUT="$(flip "$unmanaged")"
  expect_eq "config apply flip, CAA not managed ($unmanaged): no relax, no build, no settle point; cleared, new CA, done" \
    "${OUT##*rc=}:$(grep -c -e 'dns-tool apply' -e 'dns-tool ttl' -e 'build .*domains$' "$STUB_DIR/dt/argv" || true):$(paste -sd' ' "$STUB_DIR/dt/order"):$([ -e "$RELAXF" ] && echo saved):$(grep -c 'rm -f /acme/acme.json' "$STUB_DIR/dt/argv"):$(cat "$STUB_DIR/dt/traefik-up" 2>/dev/null):$(cat "$FL_ROOT/certs/.acme-staging-last")" \
    "0:0:check::1:CA=https://acme-staging-v02.api.letsencrypt.org/directory sentinel=false:true"
  case "$OUT" in *"24 h"*|*"Relaxing"*) t_fail "unmanaged flip ($unmanaged) waits: $OUT" ;; *) t_pass "config apply flip, CAA not managed ($unmanaged): no wait message" ;; esac
done
expect_eq "flip: the public check asks for a NEW account (CA-only) at the NEW CA, without credentials" \
  "$(dtin check '[.caa.account_uri, .ca_server, has("credentials")] | @json')" '["","https://acme-staging-v02.api.letsencrypt.org/directory",false]'
# N2: a pin is live (or cached) where Portcullis can't relax it — refused
# before anything changes, the pin named, what to do said.
jq '.items = [{set: "caa", name: "ci.example.org", type: "CAA", want: [], live: ["0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/5; validationmethods=dns-01\""], status: "wrong", severity: "problem", fix: "manual", steps: []}] | .caa.would_issue = false' \
  "$STUB_DIR/dt/out-default" > "$STUB_DIR/dt/out-check"
for pinned in 'export DNS_PROVIDER=none' 'export DNS_CAA=false DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123' 'unset CLOUDFLARE_API_TOKEN; export DNS_PROVIDER=cloudflare'; do
  OUT="$(flip "$pinned")"
  case "$OUT" in *"acct/5"*"remove that pin at"*"wait its TTL after removing it before running it again"*rc=1) t_pass "flip refused, a live pin Portcullis can't relax ($pinned)" ;; *) t_fail "flip with a live pin ($pinned): $OUT" ;; esac
  expect_eq "flip with a live pin ($pinned): nothing changed (no stop, no clear, sentinel unchanged)" \
    "$(grep -c -e 'stop traefik' -e 'rm -f /acme/acme.json' "$STUB_DIR/dt/argv" || true):$(cat "$FL_ROOT/certs/.acme-staging-last")" "0:false"
done
# A failed or unknown lookup refuses too (fail closed).
rm -f "$STUB_DIR/dt/out-check"; printf '' > "$STUB_DIR/dt/out-check"; echo 3 > "$STUB_DIR/dt/rc-check"
OUT="$(flip 'export DNS_PROVIDER=none')"
case "$OUT" in *"couldn't check"*rc=1) t_pass "flip: a failed public check refuses" ;; *) t_fail "flip failed check: $OUT" ;; esac
expect_eq "flip: a failed public check changes nothing" "$(grep -c 'stop traefik' "$STUB_DIR/dt/argv" || true):$(cat "$FL_ROOT/certs/.acme-staging-last")" "0:false"
rm -f "$STUB_DIR/dt/out-check" "$STUB_DIR/dt/rc-check"
# M22: the check ran but its CAA lookups failed (would_issue false, the
# caa item unknown): "couldn't check", never "wouldn't let … order"; still
# refused.
jq '.items = [{set: "caa", name: "ci.example.org", type: "CAA", want: [], live: [], status: "unknown", severity: "warning", fix: "none", steps: ["lookup failed (retry): i/o timeout"]}] | .caa.would_issue = false' \
  "$STUB_DIR/dt/out-default" > "$STUB_DIR/dt/out-check"
for how in 'export DNS_PROVIDER=none' 'export DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123'; do
  OUT="$(flip "$how")"
  case "$OUT" in *"wouldn't let"*) t_fail "flip, lookups failed ($how): worded as a refusal by the CAA: $OUT" ;;
    *"couldn't check the public CAA of ci.example.org (DNS lookups failed)"*"nothing changed"*rc=1) t_pass "flip, lookups failed ($how): \"couldn't check\", refused" ;;
    *) t_fail "flip, lookups failed ($how): $OUT" ;; esac
  expect_eq "flip, lookups failed ($how): nothing changed" "$(grep -c -e 'stop traefik' -e 'rm -f /acme/acme.json' "$STUB_DIR/dt/argv" || true):$(cat "$FL_ROOT/certs/.acme-staging-last")" "0:false"
done
# M23: the refusal on a live pin says how long its TTL is, to wait after
# removing it by hand.
jq '.items = [{set: "caa", name: "ci.example.org", type: "CAA", want: [], live: ["0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/5; validationmethods=dns-01\""], status: "wrong", severity: "problem", fix: "manual", steps: []}] | .caa.would_issue = false | .caa_ttl = 1800' \
  "$STUB_DIR/dt/out-default" > "$STUB_DIR/dt/out-check"
OUT="$(flip 'export DNS_PROVIDER=none')"
case "$OUT" in *"acct/5"*"remove that pin at"*"wait its TTL (1800 s, 30 min) after removing it"*rc=1) t_pass "flip refused on a live pin: the pin's TTL printed" ;; *) t_fail "flip live pin TTL: $OUT" ;; esac
rm -f "$STUB_DIR/dt/out-check"
# N2: DNS_CAA=false after a pin; `dns setup` removes it and saves a settle
# point (from the progress line); a flip right after refuses until then,
# managed or not.
rm -f "$RELAXF"
echo '{"ttl": 3600, "caa_relaxed": false}' > "$STUB_DIR/dt/out-ttl"
# pin_plan: the plan dns setup shows when the write replaces or removes a
# live Portcullis pin (the caa item wrong, a pinned entry live).
pin_plan() {
  jq '.items += [{set: "caa", name: "ci.example.org", type: "CAA", want: [], live: ["0 issue \"letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/5; validationmethods=dns-01\""], status: "wrong", severity: "info", fix: "auto", steps: []}]' \
    "$STUB_DIR/dt/out-default" > "$STUB_DIR/dt/out-plan"
}
pin_plan
SA=$(( $(date +%s) + 3660 ))
echo "domains dns apply: written; waiting up to 15m0s for 1.1.1.1:53 (TTL 3600 s); written_at=$(date +%s) settle_at=$SA" > "$STUB_DIR/dt/err-apply"
wait_out true true 0
(PATH="$WORK/dtbin:$PATH" PORTCULLIS_ROOT="$FL_ROOT" bash -c ". '$WORK/dtenv.sh'; export PORTCULLIS_ROOT='$FL_ROOT'; export DNS_CAA=false DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123; dns_setup true false caa" >/dev/null 2>&1)
expect_eq "dns setup removing a pin saves the settle point (0600)" "$(sed -n 's/^RELAX_NOT_BEFORE=//p' "$RELAXF" 2>/dev/null):$(file_mode "$RELAXF" 2>/dev/null)" "$SA:600"
expect_eq "dns setup: the pre-write TTL read asks for the caa set only (I1)" "$(dtin ttl '.sets | @json')" '["caa"]'
rm -f "$STUB_DIR/dt/err-apply" "$STUB_DIR/dt/out-plan"
touch "$STUB_DIR/dt/keep-state"
OUT="$(flip 'export DNS_CAA=false DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123')"
# I2: every settle time printed is rounded up to the minute and dated.
SAT="$(jq -rn --argjson t "$SA" '(($t + 59) / 60 | floor) * 60 | strftime("%Y-%m-%d %H:%M UTC")')"
case "$OUT" in *"cached until $SAT"*"run it again after $SAT"*rc=1) t_pass "flip right after dns setup removed a pin: refused until the saved point (dated, rounded up)" ;; *) t_fail "flip after removal: $OUT" ;; esac
expect_eq "flip refused by a saved point: nothing changed" "$(grep -c -e 'stop traefik' -e 'dns-tool check' "$STUB_DIR/dt/argv" || true):$(cat "$FL_ROOT/certs/.acme-staging-last")" "0:false"
OUT="$(flip 'export DNS_PROVIDER=none')"
case "$OUT" in *"after "*rc=1) t_pass "flip, unmanaged: a saved point in the future refuses too" ;; *) t_fail "unmanaged flip with a saved point: $OUT" ;; esac
rm -f "$STUB_DIR/dt/keep-state" "$RELAXF"
# M24: dns setup can't read the old pin's TTL before writing (a hand-made
# pin with an "auto" / zone-default TTL, or the read failed): the 24 h
# settle point is saved before the write, and the progress line's guess
# (write + 840 + 60) never lowers it.
echo 3 > "$STUB_DIR/dt/rc-ttl"
echo "domains dns ttl: can't tell how long caches hold portcullis CAA of ci.example.org: cloudflare reports no TTL" > "$STUB_DIR/dt/err-ttl"
pin_plan
T0="$(date +%s)"
echo "domains dns apply: written; waiting up to 15m0s for 1.1.1.1:53 (TTL 840 s); written_at=$T0 settle_at=$((T0 + 900))" > "$STUB_DIR/dt/err-apply"
setup_fl() { PATH="$WORK/dtbin:$PATH" PORTCULLIS_ROOT="$FL_ROOT" bash -c ". '$WORK/dtenv.sh'; export PORTCULLIS_ROOT='$FL_ROOT'; export DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123; rm -f '$STUB_DIR/dt/order' '$STUB_DIR/dt/argv'; dns_setup true false '$1'" 2>&1; echo "rc=$?"; }
OUT="$(setup_fl caa)"
NB="$(sed -n 's/^RELAX_NOT_BEFORE=//p' "$RELAXF" 2>/dev/null)"
expect_eq "dns setup, the CAA TTL unreadable over a live pin: the 24 h settle point saved (0600), not the 840 s guess" \
  "$([ "${NB:-0}" -ge $((T0 + 86400)) ] 2>/dev/null && echo ok):$(file_mode "$RELAXF" 2>/dev/null)" "ok:600"
case "$OUT" in *"cloudflare reports no TTL"*"24 h"*) t_pass "dns setup, CAA TTL unreadable: the tool's message shown, the 24 h wait said" ;; *) t_fail "dns setup TTL unreadable: $OUT" ;; esac
expect_eq "dns setup, CAA TTL unreadable: saved before the write, the read asks for caa only" "$(paste -sd' ' "$STUB_DIR/dt/order"):$(dtin ttl '.sets | @json')" 'plan ttl apply refresh check:["caa"]'
# I1: no live pin replaced (only an A record changes; its TTL unreadable
# would fail a TTL read): no TTL read, no settle point, no 24 h.
rm -f "$RELAXF" "$STUB_DIR/dt/out-plan"
OUT="$(setup_fl "")"
case "$OUT" in *"24 h"*) t_fail "dns setup, no pin replaced: 24 h said: $OUT" ;; *rc=0) t_pass "dns setup, an A record changes, no pin replaced: no 24 h" ;; *) t_fail "dns setup no pin: $OUT" ;; esac
expect_eq "dns setup, no pin replaced: no TTL read, no settle point" "$(grep -c 'dns-tool ttl' "$STUB_DIR/dt/argv" || true):$([ -e "$RELAXF" ] && echo saved)" "0:"
rm -f "$STUB_DIR/dt/rc-ttl" "$STUB_DIR/dt/err-ttl" "$STUB_DIR/dt/err-apply" "$RELAXF"
echo '{"ttl": 600}' > "$STUB_DIR/dt/out-ttl"
rm -f "$STUB_DIR/dt/traefik-running"
OUT="$(flip 'export DNS_PROVIDER=gcloud')"
expect_eq "config apply: ACME_DNS_PROVIDER written" "$(grep '^ACME_DNS_PROVIDER=' "$FL_ROOT/.env")" "ACME_DNS_PROVIDER=gcloud"
OUT="$(flip 'export DNS_PROVIDER=hetzner-cloud HETZNER_API_TOKEN=cloud-0123456789')"
expect_eq "config apply: hetzner-cloud is lego's hetzner" "$(grep '^ACME_DNS_PROVIDER=' "$FL_ROOT/.env")" "ACME_DNS_PROVIDER=hetzner"
OUT="$(flip 'export DNS_PROVIDER=hetzner HETZNER_API_KEY=legacy-0123456789 HETZNER_API_TOKEN=cloud-0123456789')"
case "$OUT" in *"HETZNER_API_TOKEN is set"*rc=1) t_pass "config apply: hetzner with HETZNER_API_TOKEN refused" ;; *) t_fail "hetzner + token: $OUT" ;; esac
OUT="$(flip 'export DNS_PROVIDER=hetzner-cloud HETZNER_API_KEY=legacy-0123456789 HETZNER_API_TOKEN=cloud-0123456789')"
case "$OUT" in *"HETZNER_API_KEY (the legacy DNS API) is set too"*rc=1) t_pass "config apply: hetzner-cloud with HETZNER_API_KEY refused" ;; *) t_fail "hetzner-cloud + key: $OUT" ;; esac
rm -f "$STUB_DIR/dt/acme-volume" "$STUB_DIR/dt/out-apply" "$STUB_DIR/dt/out-ttl"

# compose: Traefik's DNS-01 provider falls back to DNS_PROVIDER (F18).
REAL_DOCKER="$(PATH="$(printf '%s' "$PATH" | tr ':' '\n' | grep -v "^$WORK" | paste -sd: -)" command -v docker || true)"
if [ -n "$REAL_DOCKER" ] && "$REAL_DOCKER" compose version >/dev/null 2>&1; then
  CMP="$WORK/compose-env"; rm -rf "$CMP"; mkdir -p "$CMP"
  PORTCULLIS_ROOT="$CMP" "$CLI" init --env-only --non-interactive --domain ci.example.org --dns-provider none >/dev/null 2>&1 </dev/null
  sed -i.bak '/^DNS_PROVIDER=/d; /^ACME_DNS_PROVIDER=/d' "$CMP/.env"
  prov() { (cd "$HERE/.." && env -u ACME_DNS_PROVIDER "$@" "$REAL_DOCKER" compose -f docker-compose.yml --env-file "$CMP/.env" config --format json 2>/dev/null \
    | jq -r '.services.traefik.environment.TRAEFIK_CERTIFICATESRESOLVERS_LETSENCRYPT_ACME_DNSCHALLENGE_PROVIDER'); }
  expect_eq "compose: Traefik provider falls back to DNS_PROVIDER" "$(prov DNS_PROVIDER=porkbun)" porkbun
  expect_eq "compose: ACME_DNS_PROVIDER wins" "$(prov DNS_PROVIDER=hetzner-cloud ACME_DNS_PROVIDER=hetzner)" hetzner
  expect_eq "compose: cloudflare without either" "$(prov)" cloudflare
  expect_eq "compose: Traefik gets HETZNER_API_TOKEN" "$(cd "$HERE/.." && HETZNER_API_TOKEN=tk-0123456789 "$REAL_DOCKER" compose -f docker-compose.yml --env-file "$CMP/.env" config --format json 2>/dev/null | jq -r .services.traefik.environment.HETZNER_API_TOKEN)" tk-0123456789
else
  t_pass "compose: Traefik provider fallback (skipped: no docker compose)"
fi

# status: the DNS block from the domains service's report.
DNSR="$WORK/dns-report.json"
jq -n '
  def plan(n; wi; st): {name: n, checked_at: "x", can_write: false,
    items: [{set: "address", name: n, type: "A", want: ["203.0.113.10"], live: ["203.0.113.10"], status: "ok", severity: "ok", fix: "none", steps: []},
            {set: "caa", name: n, type: "CAA", want: ["a"], live: ["a"], status: "ok", severity: "ok", fix: "none", steps: []},
            {set: "address", name: ("old." + n), type: "CNAME", want: [], live: ["gone.test."], status: "foreign", severity: "warning", fix: "manual", steps: []}],
    caa: {issuer: "letsencrypt.org", account_uri: "https://acme/acct/1", would_issue: wi},
    dnssec: {state: st, zone: n, provider_can_sign: false, ds: [], steps: []}};
  {main: plan("ci.example.org"; true; "unsigned"), main_fresh: true, domains: {"team-b.test": plan("team-b.test"; true; "bogus")}}' > "$DNSR"
# Finding A: status asks for a fresh main plan (the service throttles a
# rebuild to one per 30 s); a cached one is said to be possibly stale.
dt 'dns_status_json' >/dev/null
expect_eq "status: the DNS report asks for a fresh main plan (--fresh)" "$(grep -c 'exec -T domains domains report --main --json --fresh$' "$STUB_DIR/dt/argv")" 1
SD="$(dt "_st_dns_json \"\$(cat '$DNSR')\" https://acme/acct/1 https://acme/acct/1")"
expect_eq "status --json: dns.main.fresh from the report" "$(printf '%s\n' "$SD" | head -n1 | jq -c '.main | [.fresh, .checked_at]')" '[true,"x"]'
LINES="$(dt "_st_dns_lines \"\$(_st_dns_json \"\$(cat '$DNSR')\" https://acme/acct/1 https://acme/acct/1)\"")"
case "$LINES" in *stale*) t_fail "status: a fresh plan said stale: $LINES" ;; *"✓ ci.example.org: CAA pinned"*) t_pass "status: a fresh plan, clean lines" ;; *) t_fail "status fresh: $LINES" ;; esac
LINES="$(dt "_st_dns_lines \"\$(_st_dns_json \"\$(jq '.main_fresh = false' '$DNSR')\" https://acme/acct/1 https://acme/acct/1)\"")"
case "$LINES" in *"! ci.example.org: the DNS plan couldn't be refreshed: the lines below are from x and may be stale"*"✓ ci.example.org: CAA pinned, the CA would issue (as of x, may be stale)"*) t_pass "status: a cached plan is flagged, and so is every clean line" ;; *) t_fail "status stale: $LINES" ;; esac
case "$LINES" in *"team-b.test: CAA pinned, the CA would issue (as of"*) t_fail "status stale: an enrolled domain flagged: $LINES" ;; *) t_pass "status: only the main plan is flagged stale" ;; esac
# M13: the lost-account ✗ on stale data says so too.
LINES="$(dt "_st_dns_lines \"\$(_st_dns_json \"\$(jq '.main_fresh = false | .main.caa.would_issue = false' '$DNSR')\" https://acme/acct/1 https://acme/acct/1)\"")"
case "$LINES" in *"CAA allows another ACME account than Traefik's — fix: ./portcullis dns setup (as of x, may be stale)"*) t_pass "status: the lost-account line on stale data says so" ;; *) t_fail "status stale lost: $LINES" ;; esac
# M10: an older domains image refuses --fresh: the cached report, and status
# says why, never "isn't running".
cp "$DNSR" "$STUB_DIR/dt/report-out"; touch "$STUB_DIR/dt/report-old"
SJ="$(dt 'dns_status_json' | head -n1)"
expect_eq "status: an old image's report → the cached one, image_old, not fresh" "$(printf '%s' "$SJ" | jq -c '[.image_old, .main_fresh]')" '[true,false]'
LINES="$(dt "_st_dns_lines \"\$(_st_dns_json \"\$(dns_status_json)\" https://acme/acct/1 https://acme/acct/1)\"")"
case "$LINES" in *"isn't running"*) t_fail "status old image: $LINES" ;; *"the domains image is older than this CLI (run ./portcullis up)"*) t_pass "status: an old domains image is named" ;; *) t_fail "status old image: $LINES" ;; esac
rm -f "$STUB_DIR/dt/report-old" "$STUB_DIR/dt/report-out"
# M18: an empty field (checked_at) doesn't shift the ones after it.
LINES="$(dt "_st_dns_lines \"\$(_st_dns_json \"\$(jq '.main.checked_at = \"\" | .main_fresh = false | .image_old = true' '$DNSR')\" https://acme/acct/1 https://acme/acct/1)\"")"
case "$LINES" in *"the domains image is older than this CLI (run ./portcullis up): the DNS lines below are from an earlier check"*) t_pass "status: an empty checked_at keeps the fields in place" ;; *) t_fail "status empty checked_at: $LINES" ;; esac
SD="$(dt "_st_dns_json \"\$(cat '$DNSR')\" https://acme/acct/1 https://acme/acct/1")"
expect_eq "status --json: dns.main summary from a fixture report" "$(printf '%s\n' "$SD" | head -n1 | jq -c '.main | del(.checks)')" \
  '{"address_ok":true,"address_unknown":false,"caa_ok":true,"would_issue":true,"dnssec":"unsigned","foreign":1,"problems":0,"name":"ci.example.org","lost_account":false,"fresh":true,"checked_at":"x","image_old":false}'
expect_eq "status: dnssec bogus is a problem (enrolled domain)" "$(printf '%s\n' "$SD" | head -n1 | jq -c '.domains["team-b.test"] | [.problems, .checks.dnssec, .checks.foreign]')" '[1,0,0]'
SD="$(dt "_st_dns_json \"\$(jq '.main.caa.would_issue = false' '$DNSR')\" https://acme/acct/1 https://acme/acct/1")"
expect_eq "status: CAA would_issue false is a problem (even with the URIs equal)" "$(printf '%s\n' "$SD" | head -n1 | jq -c '.main | [.lost_account, .problems]')" '[true,1]'
SD="$(dt "_st_dns_json \"\$(cat '$DNSR')\" https://acme/acct/2 https://acme/acct/1")"
expect_eq "status: stale main-domain.env URI is a problem" "$(printf '%s\n' "$SD" | head -n1 | jq -c '.main | [.lost_account, .problems]')" '[true,1]'
LINES="$(dt "_st_dns_lines \"\$(_st_dns_json \"\$(cat '$DNSR')\" https://acme/acct/2 https://acme/acct/1)\"")"
case "$LINES" in *"CAA allows another ACME account than Traefik's — fix: ./portcullis dns setup"*"team-b.test: DNSSEC bogus"*) t_pass "status: the lost-account line and the DNSSEC line" ;; *) t_fail "status lines: $LINES" ;; esac
# I3: no main-domain.env yet (Traefik registered after the last up) is a
# warning, not a lost account.
SD="$(dt "_st_dns_json \"\$(cat '$DNSR')\" https://acme/acct/1 ''")"
expect_eq "status: missing main-domain.env is not a lost account" "$(printf '%s\n' "$SD" | head -n1 | jq -c '.main | [.lost_account, .problems]')" '[false,0]'
LINES="$(dt "_st_dns_lines \"\$(_st_dns_json \"\$(cat '$DNSR')\" https://acme/acct/1 '')\" https://acme/acct/1 ''")"
case "$LINES" in *"! ci.example.org: the domains service doesn't know Traefik's ACME account yet"*) t_pass "status: missing main-domain.env warns" ;; *) t_fail "status missing env: $LINES" ;; esac
case "$LINES" in *"CAA allows another ACME account"*|*"team-b.test: the domains service doesn't know"*) t_fail "status missing env: lost / per-domain line: $LINES" ;; *) t_pass "status: missing main-domain.env — no lost-account line, main domain only" ;; esac
# I1: address items unknown (no server addresses) = a warning line, not ✗.
jq '.main.items = [.main.items[] | if .set == "address" and .status == "ok" then .status = "unknown" | .severity = "info" | .want = [] else . end]
    + [{set: "address", name: "ci.example.org", type: "AAAA", want: [], live: ["2001:db8::10"], status: "unknown", severity: "info", fix: "none", steps: []}]' "$DNSR" > "$WORK/dns-report-unknown.json"
SD="$(dt "_st_dns_json \"\$(cat '$WORK/dns-report-unknown.json')\" https://acme/acct/1 https://acme/acct/1")"
expect_eq "status: unknown addresses — address_ok false, address_unknown true, no problem" "$(printf '%s\n' "$SD" | head -n1 | jq -c '.main | [.address_ok, .address_unknown, .problems]')" '[false,true,0]'
LINES="$(dt "_st_dns_lines \"\$(_st_dns_json \"\$(cat '$WORK/dns-report-unknown.json')\" https://acme/acct/1 https://acme/acct/1)\"")"
case "$LINES" in *"! ci.example.org: A/AAAA can't be checked"*) t_pass "status: unknown addresses warn" ;; *) t_fail "status unknown addresses: $LINES" ;; esac
case "$LINES" in *"ci.example.org: A/AAAA records wrong"*) t_fail "status unknown addresses: a ✗ line: $LINES" ;; *) t_pass "status: unknown addresses — no ✗ line" ;; esac
# insecure (a signed zone under an unvalidated parent): no problem, dnssec check 1, a ✓ line.
SD="$(dt "_st_dns_json \"\$(jq '.main.dnssec.state = \"insecure\"' '$DNSR')\" https://acme/acct/1 https://acme/acct/1")"
expect_eq "status: dnssec insecure is no problem (check 1)" "$(printf '%s\n' "$SD" | head -n1 | jq -c '.main | [.problems, .checks.dnssec]')" '[0,1]'
LINES="$(dt "_st_dns_lines \"\$(_st_dns_json \"\$(jq '.main.dnssec.state = \"insecure\"' '$DNSR')\" https://acme/acct/1 https://acme/acct/1)\"")"
case "$LINES" in *"✓ ci.example.org: DNSSEC signed, under a parent zone that isn't validated"*) t_pass "status: dnssec insecure is a ✓ line" ;; *) t_fail "status insecure: $LINES" ;; esac
LINES="$(dt '_st_dns_lines ""')"
case "$LINES" in *"DNS checks unavailable"*) t_pass "status: DNS checks unavailable without the report" ;; *) t_fail "status unavailable: $LINES" ;; esac
expect_eq "status: no report = no dns block" "$(dt '_st_dns_json "" "" ""')" "rc=0"
STF_DNS="$(dt "_st_dns_json \"\$(cat '$DNSR')\" https://acme/acct/1 https://acme/acct/1" | head -n1)"
jq -n --argjson d "$STF_DNS" '{ok: true, services: [], vault: {active: true}, dns: $d}' > "$STUB_DIR/stf.json"
STF="$(stf)"
expect_eq "textfile: portcullis_dns_check lines" "$(printf '%s\n' "$STF" | grep '^portcullis_dns_check{' | sort | paste -sd'|' -)" \
  'portcullis_dns_check{name="ci.example.org",check="address"} 1|portcullis_dns_check{name="ci.example.org",check="caa"} 1|portcullis_dns_check{name="ci.example.org",check="dnssec"} 1|portcullis_dns_check{name="ci.example.org",check="foreign"} 0|portcullis_dns_check{name="team-b.test",check="address"} 1|portcullis_dns_check{name="team-b.test",check="caa"} 1|portcullis_dns_check{name="team-b.test",check="dnssec"} 0|portcullis_dns_check{name="team-b.test",check="foreign"} 0'
expect_eq "textfile: portcullis_dnssec_state lines" "$(printf '%s\n' "$STF" | grep '^portcullis_dnssec_state{' | paste -sd'|' -)" \
  'portcullis_dnssec_state{name="ci.example.org",state="unsigned"} 1|portcullis_dnssec_state{name="team-b.test",state="bogus"} 1'
jq --argjson d "$STF_DNS" -n '{ok: true, services: [], vault: {active: true}, dns: ($d | .main.dnssec = "")}' > "$STUB_DIR/stf.json"
expect_eq "textfile: no portcullis_dnssec_state for an empty state" "$(stf | grep '^portcullis_dnssec_state{' | paste -sd'|' -)" \
  'portcullis_dnssec_state{name="team-b.test",state="bogus"} 1'
jq -n '{ok: true, services: [], vault: {active: true}, dns: null}' > "$STUB_DIR/stf.json"
expect_eq "textfile: no dns series without the report" "$(stf | grep -c '^portcullis_dns' || true)" 0
# CI 43341512316: without main-domain.env, dns_main_env_uri must not fail
# under `set -euo pipefail` (status printed nothing and exited).
rm -f "$PORTCULLIS_ROOT/secrets/domains/main-domain.env"
expect_eq "dns_main_env_uri without the file: nothing, exit 0 under set -euo pipefail" \
  "$(dt 'set -euo pipefail; u="$(dns_main_env_uri)"; echo "got:$u"')" "got:
rc=0"
SJ="$(dt "set -euo pipefail; require_cmd() { :; }; dc() { :; }; rt_health() { echo healthy; }; kc_login() { return 1; }
        lldap_key_seed_problem() { :; }; lldap_key_seed_runtime_problems() { :; }
        proxy_dns_shadows() { :; }; _st_mcp_refusing() { :; }; vault_health_code() { echo 200; }
        vault_admin_env() { return 1; }
        dns_status_json() { cat '$DNSR'; }; dns_traefik_account_uri() { :; }
        status_run true 2>/dev/null")"
expect_eq "status --json without main-domain.env (set -euo pipefail, as the CLI) still prints the report" \
  "$(printf '%s\n' "$SJ" | sed '$d' | jq -c '[.dns.main.name, .dns.main.lost_account]' 2>/dev/null)" '["ci.example.org",false]'
# status --json carries the block (status_run with the report stubbed).
SJ="$( (require_cmd() { :; }; dc() { :; }; rt_health() { echo healthy; }; kc_login() { return 1; }
        proxy_dns_shadows() { :; }; _st_mcp_refusing() { :; }; vault_health_code() { echo 200; }
        vault_admin_env() { return 1; }
        dns_status_json() { cat "$DNSR"; }; dns_traefik_account_uri() { echo https://acme/acct/1; }; dns_main_env_uri() { echo https://acme/acct/1; }
        status_run true 2>/dev/null) || true)"
expect_eq "status --json: dns.main / dns.domains" "$(printf '%s' "$SJ" | jq -c '[.dns.main.name, (.dns.domains | keys), .ok]')" '["ci.example.org",["team-b.test"],false]'
expect_eq "status --json has runtime{}" "$(printf '%s' "$SJ" | jq -c '[.runtime.name, .runtime.version, .runtime.rootless, .runtime.checks, (.problems | type)]')" '["docker","29.0.0",false,[],"number"]'

# ══ runtime: CONTAINER_RUNTIME (scripts/lib/runtime.sh) ═════
# docker stub: the engine's components by DOCKER_HOST — the rootless Podman
# socket answers STUB_PODMAN_SOCK_ENGINE, anything else
# STUB_DOCKER_SOCK_ENGINE (Engine | Podman Engine | down); `compose ...
# config --format json` prints $STUB_DIR/rt-config.json; the host-check
# probes answer from STUB_CT_UID_MAP / STUB_CT_LIMITS. podman stub: unshare
# cat uid_map / gid_map (STUB_UID_MAP / STUB_GID_MAP), version
# (STUB_PODMAN_VERSION), build (logged).
mkdir -p "$WORK/rtbin" "$WORK/rt"
cat > "$WORK/rtbin/docker" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = version ] && [ "$3" = "{{json .Server.Components}}" ]; then
  echo "version DOCKER_HOST=${DOCKER_HOST:-}" >> "$STUB_DIR/rt-calls"
  case "${DOCKER_HOST:-}" in
    *podman/podman.sock) e="${STUB_PODMAN_SOCK_ENGINE:-down}" ;;
    *) e="${STUB_DOCKER_SOCK_ENGINE:-Engine}" ;;
  esac
  case "$e" in
    down) exit 1 ;;
    "Podman Engine") echo '[{"Name":"Podman Engine","Version":"5.4.2"}]' ;;
    *) echo '[{"Name":"Engine","Version":"29.0.0"}]' ;;
  esac
  exit 0
fi
echo "$*" >> "$STUB_DIR/rt-calls"
case "$*" in
  "compose --project-directory "*" config --format json") cat "$STUB_DIR/rt-config.json" ;;
  "compose version --short") echo 2.40.0 ;;
  "run "*" cat /proc/self/uid_map") printf '%b' "${STUB_CT_UID_MAP:-$STUB_UID_MAP}" ;;
  "create "*) echo probe1 ;;
  "network create "*) [ "${STUB_POOL_CREATE:-ok}" = ok ] || exit 1; echo net1 ;;
  "network inspect "*) echo "${STUB_POOL_SUBNET:-10.89.3.0/24} " ;;
  "network rm "*) exit 0 ;;
  "inspect --format {{.HostConfig.Memory}} {{.HostConfig.PidsLimit}} probe1") echo "${STUB_CT_LIMITS:-16777216 8}" ;;
  "image inspect "*) exit 1 ;;
  "volume inspect "*) exit 1 ;;
esac
exit 0
STUB
cat > "$WORK/rtbin/podman" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_DIR/podman-calls"
case "$*" in
  "unshare cat /proc/self/uid_map") printf '%b' "$STUB_UID_MAP" ;;
  "unshare cat /proc/self/gid_map") printf '%b' "$STUB_GID_MAP" ;;
  "version --format {{.Client.Version}}") echo "${STUB_PODMAN_VERSION:-5.4.2}" ;;
esac
exit 0
STUB
chmod +x "$WORK/rtbin/docker" "$WORK/rtbin/podman"
mksock() { python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$1"; }
RT_XDG="$WORK/rt/xdg"; mkdir -p "$RT_XDG/podman"; mksock "$RT_XDG/podman/podman.sock"
RT_PSOCK="$RT_XDG/podman/podman.sock"
mksock "$WORK/rt/docker.sock"
RT_UID="$(id -u)" RT_GID="$(id -g)"
export STUB_UID_MAP="         0       $RT_UID          1\n         1     100000      65536\n"
export STUB_GID_MAP="         0       $RT_GID          1\n         1     100000      65536\n"
# rt <shell code> — in a subshell with the runtime stubs, no runtime chosen;
# prints the code's output (stderr too), then "rc=<n>".
rt() {
  rm -f "$STUB_DIR/rt-calls" "$STUB_DIR/podman-calls"
  (unset CONTAINER_RUNTIME DOCKER_HOST COMPOSE_FILE PORTCULLIS_ENGINE_SOCKET _RT_CHECKED _RT_HOST_OK
   export PATH="$WORK/rtbin:$PATH" RT_DOCKER_SOCK="$WORK/rt/nosuch.sock" XDG_RUNTIME_DIR="$RT_XDG"
   eval "$1") 2>&1
  echo "rc=$?"
}

expect_eq "runtime_detect: docker socket without Podman component → docker" \
  "$(rt "RT_DOCKER_SOCK='$WORK/rt/docker.sock' runtime_detect")" "docker
rc=0"
expect_eq "runtime_detect: both present → docker" \
  "$(rt "RT_DOCKER_SOCK='$WORK/rt/docker.sock' STUB_PODMAN_SOCK_ENGINE='Podman Engine' runtime_detect")" "docker
rc=0"
expect_eq "runtime_detect: only the user's Podman socket answers → podman" \
  "$(rt "STUB_PODMAN_SOCK_ENGINE='Podman Engine' runtime_detect")" "podman
rc=0"
expect_eq "runtime_detect: a Docker socket whose engine is Podman is not docker" \
  "$(rt "RT_DOCKER_SOCK='$WORK/rt/docker.sock' STUB_DOCKER_SOCK_ENGINE='Podman Engine' STUB_PODMAN_SOCK_ENGINE='Podman Engine' runtime_detect")" "podman
rc=0"
expect_eq "runtime_detect: --runtime podman → podman" "$(rt 'runtime_detect podman')" "podman
rc=0"
expect_eq "runtime_detect: CONTAINER_RUNTIME from the environment" "$(rt 'CONTAINER_RUNTIME=podman runtime_detect')" "podman
rc=0"
OUT="$(rt "id() { if [ \"\$1\" = -u ]; then echo 0; else command id \"\$@\"; fi; }; STUB_PODMAN_SOCK_ENGINE='Podman Engine' runtime_detect")"
case "$OUT" in *"rootless Podman only"*"rc=1") t_pass "runtime_detect: podman as root → refused" ;; *) t_fail "runtime_detect as root: $OUT" ;; esac
OUT="$(rt "id() { if [ \"\$1\" = -u ]; then echo 0; else command id \"\$@\"; fi; }; runtime_detect podman")"
case "$OUT" in *"rootless Podman only"*"rc=1") t_pass "runtime_detect: --runtime podman as root → refused" ;; *) t_fail "runtime_detect --runtime podman as root: $OUT" ;; esac
OUT="$(rt 'runtime_detect')"
case "$OUT" in *"no container engine answers: pass --runtime docker|podman"*"/etc/subuid"*"enable-linger"*"podman.socket podman-restart.service"*"ip_unprivileged_port_start=80"*"rc=1") t_pass "runtime_detect: nothing answers → fails with the host-prep hints" ;; *) t_fail "runtime_detect nothing: $OUT" ;; esac
expect_eq "runtime_detect: an unknown runtime → refused" "$(rt 'runtime_detect lxc >/dev/null 2>&1')" "rc=1"

OUT="$(rt 'runtime_name')"
case "$OUT" in *"CONTAINER_RUNTIME is not set in .env (docker, podman or kubernetes): ./portcullis init writes it"*"rc=1") t_pass "runtime_name: unset → refused naming the variable" ;; *) t_fail "runtime_name unset: $OUT" ;; esac
OUT="$(rt 'CONTAINER_RUNTIME=Docker runtime_name')"
case "$OUT" in *"CONTAINER_RUNTIME=Docker is not docker, podman or kubernetes"*"rc=1") t_pass "runtime_name: another value → refused naming it" ;; *) t_fail "runtime_name bad: $OUT" ;; esac
OUT="$(rt 'CONTAINER_RUNTIME=docker STUB_DOCKER_SOCK_ENGINE="Podman Engine" runtime_check')"
case "$OUT" in *"CONTAINER_RUNTIME=docker but the engine is Podman Engine"*"rc=1") t_pass "runtime_check: CONTAINER_RUNTIME=docker but the engine is Podman → fails" ;; *) t_fail "runtime_check docker/podman: $OUT" ;; esac
OUT="$(rt "CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET='$RT_PSOCK' STUB_PODMAN_SOCK_ENGINE=Engine runtime_check")"
case "$OUT" in *"CONTAINER_RUNTIME=podman but the engine is Docker Engine"*"rc=1") t_pass "runtime_check: CONTAINER_RUNTIME=podman but the engine is Docker → fails" ;; *) t_fail "runtime_check podman/docker: $OUT" ;; esac
OUT="$(rt 'CONTAINER_RUNTIME=docker STUB_DOCKER_SOCK_ENGINE=down runtime_check')"
case "$OUT" in *"the container engine doesn't answer"*"rc=1") t_pass "runtime_check: no engine → fails" ;; *) t_fail "runtime_check down: $OUT" ;; esac
expect_eq "runtime_check: podman exports DOCKER_HOST=unix://<XDG>/podman/podman.sock" \
  "$(rt "CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET='$RT_PSOCK' STUB_PODMAN_SOCK_ENGINE='Podman Engine' runtime_check; echo \"\$DOCKER_HOST\"")" "unix://$RT_PSOCK
rc=0"
expect_eq "runtime_check: once per run" \
  "$(rt "CONTAINER_RUNTIME=docker; runtime_check; runtime_check; grep -c '^version' \"\$STUB_DIR/rt-calls\"")" "1
rc=0"
OUT="$(rt "CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET=/tmp/other.sock STUB_PODMAN_SOCK_ENGINE='Podman Engine' runtime_check")"
case "$OUT" in *"PORTCULLIS_ENGINE_SOCKET=/tmp/other.sock, but the rootless Podman socket is $RT_PSOCK"*"rc=1") t_pass "runtime_check: podman with another PORTCULLIS_ENGINE_SOCKET → fails" ;; *) t_fail "runtime_check socket: $OUT" ;; esac
OUT="$(rt "CONTAINER_RUNTIME=podman STUB_PODMAN_SOCK_ENGINE='Podman Engine' runtime_check")"
case "$OUT" in *"PORTCULLIS_ENGINE_SOCKET is not set"*"rc=1") t_pass "runtime_check: podman without PORTCULLIS_ENGINE_SOCKET → fails" ;; *) t_fail "runtime_check no socket: $OUT" ;; esac
OUT="$(rt "CONTAINER_RUNTIME=docker PORTCULLIS_ENGINE_SOCKET='$WORK/rt' runtime_check")"
case "$OUT" in *"is not a socket"*"rc=1") t_pass "runtime_check: docker with a PORTCULLIS_ENGINE_SOCKET that isn't a socket → fails" ;; *) t_fail "runtime_check docker socket: $OUT" ;; esac
OUT="$(rt "CONTAINER_RUNTIME=podman DOCKER_HOST=tcp://elsewhere:2375 PORTCULLIS_ENGINE_SOCKET='$RT_PSOCK' runtime_check")"
case "$OUT" in *"DOCKER_HOST=tcp://elsewhere:2375"*"unset DOCKER_HOST"*"rc=1") t_pass "runtime_export: podman refuses another DOCKER_HOST" ;; *) t_fail "runtime_export DOCKER_HOST: $OUT" ;; esac
OUT="$(rt "CONTAINER_RUNTIME=docker PORTCULLIS_ENGINE_SOCKET='$RT_PSOCK' STUB_PODMAN_SOCK_ENGINE='Podman Engine' runtime_check")"
case "$OUT" in *"CONTAINER_RUNTIME=docker but PORTCULLIS_ENGINE_SOCKET=$RT_PSOCK is Podman Engine"*"rc=1") t_pass "runtime_check: docker with a PORTCULLIS_ENGINE_SOCKET that is a Podman socket → fails" ;; *) t_fail "runtime_check docker/podman socket: $OUT" ;; esac
expect_eq "runtime_check: docker with a PORTCULLIS_ENGINE_SOCKET whose engine is Docker → ok" \
  "$(rt "CONTAINER_RUNTIME=docker PORTCULLIS_ENGINE_SOCKET='$WORK/rt/docker.sock' runtime_check")" "rc=0"
expect_eq "runtime_podman_socket falls back to /run/user/<uid>" "$(rt 'unset XDG_RUNTIME_DIR; runtime_podman_socket')" "/run/user/$RT_UID/podman/podman.sock
rc=0"

RX="$WORK/rt/root"; mkdir -p "$RX"; touch "$RX/docker-compose.override.yml"
RH="$(cd "$HERE/.." && pwd)"
expect_eq "runtime_export keeps docker-compose.override.yml beside the podman and SELinux overlays (absolute paths)" \
  "$(rt "PORTCULLIS_ROOT='$RX' CONTAINER_RUNTIME=podman; getenforce() { echo Enforcing; }; runtime_export; runtime_export; echo \"\$COMPOSE_FILE\"")" \
  "$RX/docker-compose.yml:$RX/docker-compose.override.yml:$RH/docker-compose.podman.yml:$RH/docker-compose.podman-selinux.yml
rc=0"
expect_eq "runtime_export: Podman's pools for the VPN readers (podman: 10.88/16 + the pinned 10.89/16; docker: empty, even if set outside)" \
  "$(rt "PORTCULLIS_ROOT='$RX' CONTAINER_RUNTIME=podman; getenforce() { echo Permissive; }; runtime_export; echo \"[\$PORTCULLIS_VPN_RUNTIME_POOLS]\"")|$(rt "PORTCULLIS_ROOT='$RX' CONTAINER_RUNTIME=docker PORTCULLIS_VPN_RUNTIME_POOLS=10.0.0.0/8; runtime_export; echo \"[\$PORTCULLIS_VPN_RUNTIME_POOLS]\"")" \
  "[10.88.0.0/16 10.89.0.0/16]
rc=0|[]
rc=0"
expect_eq "vpn_reserved_ranges: under podman Podman's pools follow the core subnets" \
  "$(rt "CONTAINER_RUNTIME=podman; getenforce() { echo Permissive; }; runtime_export; vpn_reserved_ranges")" \
  "172.16.0.0/12 192.168.0.0/16 10.214.0.0/24 172.31.250.0/24 172.31.251.0/28 172.31.252.0/28 172.31.253.0/28 172.31.254.0/26 172.31.254.64/28 172.31.255.16/28 172.31.254.80/29 172.31.254.128/26 10.88.0.0/16 10.89.0.0/16
rc=0"
expect_eq "runtime_export: an existing COMPOSE_FILE gets the overlay once" \
  "$(rt "PORTCULLIS_ROOT='$RX' CONTAINER_RUNTIME=podman COMPOSE_FILE=docker-compose.yml:ci.yml; getenforce() { echo Enforcing; }; runtime_export; runtime_export; echo \"\$COMPOSE_FILE\"")" \
  "docker-compose.yml:ci.yml:$RH/docker-compose.podman.yml:$RH/docker-compose.podman-selinux.yml
rc=0"
expect_eq "runtime_export: SELinux permissive → only the podman overlay (restart: always)" \
  "$(rt "PORTCULLIS_ROOT='$RX' CONTAINER_RUNTIME=podman; getenforce() { echo Permissive; }; runtime_export; echo \"[\${COMPOSE_FILE:-}]\"")" "[$RX/docker-compose.yml:$RX/docker-compose.override.yml:$RH/docker-compose.podman.yml]
rc=0"
expect_eq "runtime_export: a COMPOSE_FILE naming the overlays by basename isn't extended again" \
  "$(rt "PORTCULLIS_ROOT='$RX' CONTAINER_RUNTIME=podman COMPOSE_FILE=docker-compose.yml:docker-compose.podman.yml; getenforce() { echo Permissive; }; runtime_export; echo \"\$COMPOSE_FILE\"")" "docker-compose.yml:docker-compose.podman.yml
rc=0"
expect_eq "runtime_export: docker on an SELinux host → no overlay, no DOCKER_HOST" \
  "$(rt "PORTCULLIS_ROOT='$RX' CONTAINER_RUNTIME=docker; getenforce() { echo Enforcing; }; runtime_export; echo \"[\${COMPOSE_FILE:-}][\${DOCKER_HOST:-}]\"")" "[][]
rc=0"

expect_eq "runtime_id_maps: the default shape" \
  "$(rt 'runtime_id_maps && echo "$_RT_UID_OP $_RT_UID_START $_RT_UID_N $_RT_GID_OP $_RT_GID_START $_RT_GID_N"')" "$RT_UID 100000 65536 $RT_GID 100000 65536
rc=0"
expect_eq "runtime_id_maps: 65535 subuids → refused" \
  "$(rt "STUB_UID_MAP='0 $RT_UID 1\n1 100000 65535\n' runtime_id_maps")" "rc=1"
expect_eq "runtime_id_maps: another shape (keep-id) → refused" \
  "$(rt "STUB_UID_MAP='0 100000 $RT_UID\n$RT_UID $RT_UID 1\n$((RT_UID + 1)) $((100000 + RT_UID)) 65536\n' runtime_id_maps")" "rc=1"
expect_eq "runtime_id_maps: an unreadable map → refused" "$(rt "STUB_UID_MAP='' runtime_id_maps")" "rc=1"
expect_ok "_ver_ge 5.4.2 5.4" _ver_ge 5.4.2 5.4
expect_ok "_ver_ge 5.10.0 5.4" _ver_ge 5.10.0 5.4
expect_fail "_ver_ge 5.3.9 5.4" _ver_ge 5.3.9 5.4
expect_fail "_ver_ge '' 5.4" _ver_ge "" 5.4
echo 80 > "$WORK/rt/port80"; echo 1024 > "$WORK/rt/port1024"; echo junk > "$WORK/rt/portjunk"
expect_eq "runtime_port_start reads the sysctl" "$(RT_PROC_PORT_START="$WORK/rt/port80" runtime_port_start)" 80
expect_eq "runtime_port_start: unreadable or not a number → 1024" \
  "$(RT_PROC_PORT_START="$WORK/rt/nope" runtime_port_start) $(RT_PROC_PORT_START="$WORK/rt/portjunk" runtime_port_start)" "1024 1024"

# A prepared host: every † item ok (functions stand in for the host tools).
CG="$WORK/rt/cgroup"; mkdir -p "$CG/user.slice/user-$RT_UID.slice/user@$RT_UID.service"
echo "cpuset cpu io memory pids" > "$CG/user.slice/user-$RT_UID.slice/user@$RT_UID.service/cgroup.controllers"
mkdir -p "$WORK/rt/aa/local"; echo N > "$WORK/rt/aa-off"; echo Y > "$WORK/rt/aa-on"
RT_HOST="CONTAINER_RUNTIME=podman RT_CGROUP_ROOT='$CG' RT_PROC_PORT_START='$WORK/rt/port80' RT_APPARMOR_DIR='$WORK/rt/aa' RT_APPARMOR_ENABLED='$WORK/rt/aa-off'
  loginctl() { echo yes; }; systemctl() { echo enabled; }; nft() { :; }; passt() { :; }; getenforce() { echo Enforcing; }"
OUT="$(rt "$RT_HOST; runtime_host_checks")"
expect_eq "runtime_host_checks: a prepared host → no fail line" "$(printf '%s\n' "$OUT" | grep -c '^fail' || true)" 0
case "$OUT" in *"ok	SELinux Enforcing"*"rc=0") t_pass "runtime_host_checks: SELinux mode is an ok line" ;; *) t_fail "runtime_host_checks prepared: $OUT" ;; esac
OUT="$(rt "$RT_HOST; RT_PROC_PORT_START='$WORK/rt/port1024'; runtime_host_checks")"
case "$OUT" in *"fail	net.ipv4.ip_unprivileged_port_start = 1024"*) t_pass "runtime_host_checks: port start 1024 → fail line naming ip_unprivileged_port_start" ;; *) t_fail "runtime_host_checks port: $OUT" ;; esac
echo "cpuset cpu io memory" > "$CG/user.slice/user-$RT_UID.slice/user@$RT_UID.service/cgroup.controllers"
OUT="$(rt "$RT_HOST; runtime_host_checks")"
case "$OUT" in *"fail	cgroup v2: memory and pids aren't both delegated"*) t_pass "runtime_host_checks: no pids in cgroup.controllers → fail" ;; *) t_fail "runtime_host_checks pids: $OUT" ;; esac
echo "memory pids" > "$CG/user.slice/user-$RT_UID.slice/user@$RT_UID.service/cgroup.controllers"
OUT="$(rt "$RT_HOST; export STUB_CT_LIMITS='0 0'; runtime_host_checks")"
case "$OUT" in *"fail	cgroup v2: a probe container"*) t_pass "runtime_host_checks: a probe without Memory/PidsLimit → fail" ;; *) t_fail "runtime_host_checks probe: $OUT" ;; esac
OUT="$(rt "$RT_HOST; export STUB_CT_UID_MAP='0 100000 65536\n'; runtime_host_checks")"
case "$OUT" in *"fail	containers don't run in the user's default user namespace"*) t_pass "runtime_host_checks: a container map ≠ the unshare map (userns=auto) → fail" ;; *) t_fail "runtime_host_checks userns: $OUT" ;; esac
OUT="$(rt "$RT_HOST; loginctl() { echo no; }; systemctl() { echo disabled; }; export STUB_PODMAN_VERSION=5.3.1; runtime_host_checks")"
case "$OUT" in *"fail	linger is off"*"fail	user unit podman.socket is not enabled"*"fail	user unit podman-restart.service is not enabled"*"fail	podman 5.3.1"*) t_pass "runtime_host_checks: linger, user units, podman < 5.4 → fail lines" ;; *) t_fail "runtime_host_checks linger/units/version: $OUT" ;; esac
OUT="$(rt "$RT_HOST; nft() { return 1; }; unset -f nft; PATH=\"$WORK/rtbin:/usr/bin:/bin\"; command -v nft >/dev/null || command -v iptables >/dev/null || runtime_host_checks")"
case "$OUT" in *"warn	neither nft nor iptables"*|"rc=0") t_pass "runtime_host_checks: no nft / iptables → warn (or the host has one)" ;; *) t_fail "runtime_host_checks nft: $OUT" ;; esac
# Podman's address pools (I3 ruling): the operator's containers.conf pins
# default_subnet_pools to 10.89.0.0/16 (/24s), so every Podman network
# lies in 10.88.0.0/16 (the default network) or 10.89.0.0/16, both
# reserved against VPN provider ranges.
POOL_LINE='default_subnet_pools = [{"base" = "10.89.0.0/16", "size" = 24}]'
# Podman's effective pool (M5 ruling): a probe network shows where Podman
# allocates, whatever config set it ($CONTAINERS_CONF, an override, the
# system or the user file). Outside 10.89.0.0/16: fail with the wg profile
# on (VPN wiring needs it), warn with it off.
OUT="$(rt "$RT_HOST; runtime_host_checks")"
case "$OUT" in *"ok	Podman networks come from 10.89.0.0/16 (a probe network got 10.89.3.0/24)"*) t_pass "runtime_host_checks: the pinned Podman pool is an ok line" ;; *) t_fail "runtime_host_checks pool ok: $OUT" ;; esac
expect_eq "runtime_host_checks: the probe network is created, inspected and removed" \
  "$(rt "$RT_HOST; runtime_host_checks >/dev/null; grep -cE '^network (create|inspect|rm) .*portcullis-pool-probe-' \"\$STUB_DIR/rt-calls\"")" "3
rc=0"
OUT="$(rt "$RT_HOST; export STUB_POOL_SUBNET=10.128.5.0/24 COMPOSE_PROFILES=monitoring,wg; runtime_host_checks")"
case "$OUT" in *"fail	Podman's network pool isn't pinned (a probe network got 10.128.5.0/24, outside 10.89.0.0/16"*"$POOL_LINE"*) t_pass "runtime_host_checks: an unpinned pool with the wg profile on → fail with the exact line" ;; *) t_fail "runtime_host_checks pool wg: $OUT" ;; esac
OUT="$(rt "$RT_HOST; export STUB_POOL_SUBNET=10.128.5.0/24 COMPOSE_PROFILES=monitoring; runtime_host_checks")"
case "$OUT" in *"warn	Podman's network pool isn't pinned (a probe network got 10.128.5.0/24"*) t_pass "runtime_host_checks: an unpinned pool without the wg profile → warn" ;; *) t_fail "runtime_host_checks pool no wg: $OUT" ;; esac
case "$OUT" in *"fail	Podman's network pool"*) t_fail "runtime_host_checks pool no wg: a fail line" ;; *) t_pass "runtime_host_checks: without the wg profile the pool never refuses" ;; esac
OUT="$(rt "$RT_HOST; export STUB_POOL_CREATE=no COMPOSE_PROFILES=wg; runtime_host_checks")"
case "$OUT" in *"fail	Podman's network pool isn't pinned (no probe network could be created"*) t_pass "runtime_host_checks: no probe network with wg on → fail (never assumed pinned)" ;; *) t_fail "runtime_host_checks pool probe failed: $OUT" ;; esac
expect_eq "runtime_host_checks: docker → nothing" "$(rt 'CONTAINER_RUNTIME=docker runtime_host_checks')" "rc=0"
OUT="$(rt "$RT_HOST; loginctl() { echo no; }; RT_PROC_PORT_START='$WORK/rt/port1024'; runtime_require_host")"
case "$OUT" in *"isn't prepared for rootless Podman"*"  - linger is off"*"  - net.ipv4.ip_unprivileged_port_start = 1024"*"rc=1") t_pass "runtime_require_host: lists every failed item, refuses" ;; *) t_fail "runtime_require_host: $OUT" ;; esac
expect_eq "runtime_require_host: docker → no-op" "$(rt 'CONTAINER_RUNTIME=docker runtime_require_host')" "rc=0"
OUT="$(rt "$RT_HOST; export STUB_PODMAN_SOCK_ENGINE='Podman Engine'; runtime_export; runtime_status_json")"
expect_eq "runtime_status_json: podman" "$(printf '%s\n' "$OUT" | head -n1 | jq -c '[.name, .version, .rootless, .subuid_start, .subuid_count, .subgid_count, .port_start, (.checks | length > 5), ([.checks[] | select(.status == "fail")] | length)]')" \
  '["podman","5.4.2",true,100000,65536,65536,80,true,0]'
expect_eq "runtime_status_json: docker" "$(rt 'CONTAINER_RUNTIME=docker runtime_status_json' | head -n1 | jq -c '[.name, .version, .rootless, .checks]')" '["docker","29.0.0",false,[]]'

# Local images: podman build from the merged config, never the compat /build.
cat > "$STUB_DIR/rt-config.json" <<'JSON'
{"name":"portcullis","services":{
 "domains":{"image":"portcullis-domains","build":{"context":"/src/domains","dockerfile":"Dockerfile","args":{"GO_TAGS":"testprovider"}}},
 "enroll":{"build":{"context":"/src/enroll","dockerfile":"Dockerfile"}},
 "mcp-gate":{"image":"portcullis-mcp-gate","build":{"context":"/src/mcp-gate","dockerfile":"/src/mcp-gate/Dockerfile.x"}},
 "dns-tool":{"image":"portcullis-domains"},
 "vault":{"image":"hashicorp/vault:2"}}}
JSON
OUT="$(rt "CONTAINER_RUNTIME=podman; rt_up >/dev/null 2>&1; echo \"\$?\"; sort \"\$STUB_DIR/podman-calls\"; grep -E '^compose .* (up|build)( |$)' \"\$STUB_DIR/rt-calls\" | sed 's/--project-directory [^ ]* //'")"
expect_eq "stack_compose_up on podman builds with podman build and runs up --no-build" "$OUT" "0
build --format docker -t portcullis-domains -f /src/domains/Dockerfile --build-arg GO_TAGS=testprovider /src/domains
build --format docker -t portcullis-enroll -f /src/enroll/Dockerfile /src/enroll
build --format docker -t portcullis-mcp-gate -f /src/mcp-gate/Dockerfile.x /src/mcp-gate
compose up -d --no-build
rc=0"
OUT="$(rt "CONTAINER_RUNTIME=docker; rt_up hub >/dev/null 2>&1; grep -E '^compose ' \"\$STUB_DIR/rt-calls\" | sed 's/--project-directory [^ ]* //'; test ! -e \"\$STUB_DIR/podman-calls\"")"
expect_eq "stack_compose_up on docker: build --quiet first, then up -d --no-build, no podman" "$OUT" "compose build --quiet
compose up -d --no-build hub
rc=0"
expect_eq "runtime_no_build: --no-build under podman, nothing under docker" \
  "[$(CONTAINER_RUNTIME=podman runtime_no_build)][$(CONTAINER_RUNTIME=docker runtime_no_build)]" "[--no-build][]"
# A rebuilt image reaches its container (test server 2026-11-13 finding A):
# compose recreates on a changed image only if no up pins the decision, so
# no `dc up` in the CLI says --no-recreate, --force-recreate is only the
# restore's fresh Vault, and every up outside stack_compose_up builds
# nothing itself (podman: --no-build; docker: compose builds only a missing image).
LIBS="$HERE/../scripts/lib"
expect_eq "no dc up in the CLI passes --no-recreate" "$(grep -n 'dc up .*--no-recreate' "$LIBS"/*.sh "$HERE/../portcullis" || true)" ""
expect_eq "--force-recreate only on the restore's fresh Vault" \
  "$(grep -h 'dc up .*--force-recreate' "$LIBS"/*.sh | sed 's/^ *//')" 'dc up -d $(runtime_no_build) --no-deps --force-recreate vault >/dev/null'
expect_eq "every dc up outside stack_compose_up passes \$(runtime_no_build)" \
  "$(grep -n 'dc up ' "$LIBS"/*.sh | grep -v '^\s*#' | grep -vF '$(runtime_no_build)' | grep -v '/runtime.sh:' || true)" ""
expect_eq "no dc up --build anywhere: rt_up (= stack_compose_up on docker / podman) builds first (init, up, upgrade, restore go through it; init's last kubernetes rt_up too)" \
  "$(grep -n 'dc up .*--build' "$LIBS"/*.sh | grep -v -- '--no-build' || true):$(grep -c '^ *rt_up\b' "$LIBS/stack.sh") $(grep -c '^ *rt_up ||' "$LIBS/backup.sh")" ":4 1"
expect_eq "rt_up on docker / podman is stack_compose_up (the kcwait tests below run through it)" \
  "$( (stack_compose_up() { echo "scu $*"; }; CONTAINER_RUNTIME=docker; rt_up wg traefik hub; CONTAINER_RUNTIME=podman; rt_up) )" "scu wg traefik hub
scu "
# restore builds on both runtimes, as up does (docker used to start the
# images it had: a git pull before a restore left them old).
for RTN in docker podman; do
  OUT="$(rt "CONTAINER_RUNTIME=$RTN; compose_health_report() { :; }; rt_up >/dev/null 2>&1; echo \"\$?\"; grep -cE '^compose .* up -d --(no-)?build$' \"\$STUB_DIR/rt-calls\"; grep -c '^build ' \"\$STUB_DIR/podman-calls\" 2>/dev/null || echo 0")"
  case "$RTN:$OUT" in
    "docker:0"$'\n'"1"$'\n'"0"$'\n'"rc=0"|"podman:0"$'\n'"1"$'\n'"3"$'\n'"rc=0") t_pass "stack_compose_up on $RTN: the local images built, one up that lets compose recreate changed ones" ;;
    *) t_fail "stack_compose_up on $RTN: $OUT" ;;
  esac
done
OUT="$(rt "CONTAINER_RUNTIME=podman PORTCULLIS_ROOT='$RX'; domains_image_ensure >/dev/null 2>&1; echo \"\$?\"; cat \"\$STUB_DIR/podman-calls\"; grep -c ' build' \"\$STUB_DIR/rt-calls\"; true")"
expect_eq "domains_image_ensure on podman runs podman build, never dc build" "$OUT" "0
build --format docker -t portcullis-domains -f /src/domains/Dockerfile --build-arg GO_TAGS=testprovider /src/domains
0
rc=0"
OUT="$(rt "CONTAINER_RUNTIME=docker PORTCULLIS_ROOT='$RX'; domains_image_ensure >/dev/null 2>&1; grep -E '^compose ' \"\$STUB_DIR/rt-calls\" | sed 's/--project-directory [^ ]* //'")"
expect_eq "domains_image_ensure on docker: dc build --quiet domains (unchanged)" "$OUT" "compose build --quiet domains
rc=0"
expect_eq "runtime_build_local: an unknown service → refused" "$(rt 'CONTAINER_RUNTIME=podman; runtime_build_local nope >/dev/null 2>&1')" "rc=1"

# hub_env_write: the port start for the Hub's RootlessCompat, podman only.
PH="$WORK/rt/hubroot"; mkdir -p "$PH"; echo 'PORTCULLIS_DOMAIN=hub.test' > "$PH/.env"
expect_eq "hub_env_write: PORTCULLIS_UNPRIVILEGED_PORT_START only under podman" \
  "$(rt "PORTCULLIS_ROOT='$PH' RT_PROC_PORT_START='$WORK/rt/port80'; CONTAINER_RUNTIME=podman hub_env_write; grep -c '^PORTCULLIS_UNPRIVILEGED_PORT_START=80$' '$PH/secrets/hub/core.env'; CONTAINER_RUNTIME=docker hub_env_write; grep -c '^PORTCULLIS_UNPRIVILEGED_PORT_START=' '$PH/secrets/hub/core.env'; true")" "1
0
rc=0"
expect_eq "hub_env_write: HUB_SHARED_ENV can't inject PORTCULLIS_UNPRIVILEGED_PORT_START" \
  "$(rt "PORTCULLIS_ROOT='$PH' RT_PROC_PORT_START='$WORK/rt/port80' PORTCULLIS_UNPRIVILEGED_PORT_START=1 HUB_SHARED_ENV=PORTCULLIS_UNPRIVILEGED_PORT_START; CONTAINER_RUNTIME=docker hub_env_write; grep -c '^PORTCULLIS_UNPRIVILEGED_PORT_START=' '$PH/secrets/hub/core.env'; true")" "0
rc=0"
expect_eq "need_env: no CONTAINER_RUNTIME → refused naming the variable" \
  "$(rt "PORTCULLIS_ROOT='$PH'; need_env 2>&1 | grep -c 'CONTAINER_RUNTIME is not set in .env'; true")" "1
rc=0"

# Restores keep this host's runtime keys, never the backup's (P6).
# rr <current .env|-> <backup .env> [code] — backup_restore over a fake
# backup (stops at the first logical restore), then the restored .env.
rr() {
  rm -rf "$WORK/rr-root" "$WORK/rr-backup"; mkdir -p "$WORK/rr-root/backups" "$WORK/rr-backup"
  [ "$1" = - ] || printf '%b' "$1" > "$WORK/rr-root/.env"
  printf '%b' "$2" > "$WORK/rr-backup/.env"
  printf '{"created":"x","domain":"d"}' > "$WORK/rr-backup/MANIFEST.json"
  rt "export PORTCULLIS_ROOT='$WORK/rr-root' BACKUP_ROOT='$WORK/rr-root/backups'
    _backup_check_layout() { :; }; _backup_check_manifest() { :; }; network_check() { :; }
    stack_prepare() { :; }; runtime_require_host() { echo require_host >> \"\$STUB_DIR/rt-calls\"; }
    _backup_load_cfg() { _BACKUP_CFG='{\"name\":\"portcullis\",\"volumes\":{\"hub_secrets\":{\"name\":\"portcullis_hub_secrets\"},\"postgres_data\":{\"name\":\"portcullis_postgres_data\"},\"vault_data\":{\"name\":\"portcullis_vault_data\"}}}'; }
    _restore_pg() { exit 3; }
    ${3:-}
    [ ! -f \"\$PORTCULLIS_ROOT/.env\" ] || env_load
    backup_restore '$WORK/rr-backup' true false >/dev/null 2>&1" >/dev/null
  grep -E '^(CONTAINER_RUNTIME|PORTCULLIS_ENGINE_SOCKET|RESTORED)=' "$WORK/rr-root/.env" | sort | paste -sd' ' -
}
expect_eq "restore keeps the host's runtime keys (a Docker backup's .env without them over podman)" \
  "$(rr "CONTAINER_RUNTIME=podman\nPORTCULLIS_ENGINE_SOCKET=$RT_PSOCK\n" 'RESTORED=1\n' "export STUB_PODMAN_SOCK_ENGINE='Podman Engine'")" \
  "CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET=$RT_PSOCK RESTORED=1"
expect_eq "restore keeps the host's runtime keys (the backup says docker)" \
  "$(rr "CONTAINER_RUNTIME=podman\nPORTCULLIS_ENGINE_SOCKET=$RT_PSOCK\n" 'RESTORED=1\nCONTAINER_RUNTIME=docker\n' "export STUB_PODMAN_SOCK_ENGINE='Podman Engine'")" \
  "CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET=$RT_PSOCK RESTORED=1"
expect_eq "restore onto docker drops a podman backup's PORTCULLIS_ENGINE_SOCKET" \
  "$(rr 'CONTAINER_RUNTIME=docker\n' "RESTORED=1\nCONTAINER_RUNTIME=podman\nPORTCULLIS_ENGINE_SOCKET=/run/user/1001/podman/podman.sock\n")" \
  "CONTAINER_RUNTIME=docker RESTORED=1"
expect_eq "restore without .env detects the runtime before any docker call" \
  "$(rr - 'RESTORED=1\n' "export RT_DOCKER_SOCK='$WORK/rt/docker.sock'"):$(head -n1 "$STUB_DIR/rt-calls" | cut -d' ' -f1):$(grep -v '^version' "$STUB_DIR/rt-calls" | head -n1)" \
  "CONTAINER_RUNTIME=docker RESTORED=1:version:require_host"
expect_eq "restore without .env onto podman writes the rootless socket" \
  "$(rr - 'RESTORED=1\nCONTAINER_RUNTIME=docker\n' "export STUB_PODMAN_SOCK_ENGINE='Podman Engine'")" \
  "CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET=$RT_PSOCK RESTORED=1"
expect_eq "restore: a host that isn't prepared for podman is refused before anything stops" \
  "$(rr "CONTAINER_RUNTIME=podman\nPORTCULLIS_ENGINE_SOCKET=$RT_PSOCK\n" 'RESTORED=1\n' "export STUB_PODMAN_SOCK_ENGINE='Podman Engine'; runtime_require_host() { exit 1; }"):$(grep -c 'stop hub' "$STUB_DIR/rt-calls")" \
  "CONTAINER_RUNTIME=podman PORTCULLIS_ENGINE_SOCKET=$RT_PSOCK:0"

# ══ ownership under the user namespace (rootless Podman) ═══
# Container id c: 0 → the operator, 1 ≤ c < 65536 → subuid_start + c − 1.
expect_eq "ct_operator_id: docker → the operator's uid, podman → 0" \
  "$(CONTAINER_RUNTIME=docker ct_operator_id) $(rt 'CONTAINER_RUNTIME=podman ct_operator_id' | head -n1)" "$RT_UID 0"
expect_eq "ct_host_id: 0 → operator, 10001 → subuid+10000, 70000 → error" \
  "$(rt 'CONTAINER_RUNTIME=podman; ct_host_id 0; ct_host_id 10001; ct_host_id 65536 2>/dev/null || echo e65536; ct_host_id 70000 2>/dev/null || echo e70000')" "$RT_UID
110000
e65536
e70000
rc=0"
expect_eq "ct_host_gid: 0 → the operator's group, 10001 → subgid+10000" \
  "$(rt 'CONTAINER_RUNTIME=podman; ct_host_gid 0; ct_host_gid 10001')" "$RT_GID
110000
rc=0"
expect_eq "ct_host_id: docker → the same id" "$(rt 'CONTAINER_RUNTIME=docker ct_host_id 10001')" "10001
rc=0"
expect_eq "ct_host_id: an unreadable id map → refused" \
  "$(rt "CONTAINER_RUNTIME=podman STUB_UID_MAP=''; ct_host_id 10001 2>&1 | grep -c 'podman unshare'; true")" "1
rc=0"
OWN_STAT="stat() { case \"\${*: -1}\" in */op) echo $RT_UID:$RT_GID ;; */hub) echo 110000:110000 ;; */root) echo 0:0 ;; */mixed) echo $RT_UID:0 ;; */big) echo 165536:110000 ;; esac; }"
expect_eq "_owner_of_ct: host operator → 0, subuid+10000 → 10001, host root → unmapped" \
  "$(rt "CONTAINER_RUNTIME=podman; $OWN_STAT; _owner_of_ct /x/op; _owner_of_ct /x/hub; _owner_of_ct /x/root; _owner_of_ct /x/mixed; _owner_of_ct /x/big")" "0:0
10001:10001
unmapped
unmapped
unmapped
rc=0"
expect_eq "_owner_of_ct: docker → the host ids" "$(rt "CONTAINER_RUNTIME=docker; $OWN_STAT; _owner_of_ct /x/hub")" "110000:110000
rc=0"
expect_eq "ct_hint_chown: sudo chown (docker), podman unshare chown (podman), every path single-quoted" \
  "$(CONTAINER_RUNTIME=docker ct_hint_chown 1000:10001 /a /b)|$(CONTAINER_RUNTIME=podman ct_hint_chown 0:10001 /a)" "sudo chown 1000:10001 '/a' '/b'|podman unshare chown 0:10001 '/a'"
# shellcheck disable=SC2016  # $(id) is the literal path under test
HINT_PATH='/srv/my dir/it'"'"'s $(id)'
HINT="$(CONTAINER_RUNTIME=docker ct_hint_chown 0:0 "$HINT_PATH")"
# shellcheck disable=SC2016
expect_eq "ct_hint_chown: a path with a space, a ' and \$(id) is one quoted word" "$HINT" "sudo chown 0:0 '/srv/my dir/it'\''s \$(id)'"
mkdir -p "$WORK/rt/hint"
expect_eq "ct_hint_chown: the hint, run by a shell, sees exactly that path (nothing runs)" \
  "$(cd "$WORK/rt/hint" && sudo() { shift; printf '%s\n' "$@"; }; eval "${HINT}" | tail -n1)" "$HINT_PATH"

OWN_F="$WORK/rt/own"; mkdir -p "$OWN_F"; : > "$OWN_F/op"; : > "$OWN_F/hub"
OWN_STAT2="stat() { case \"\${*: -1}\" in */hub) echo 110000:110000 ;; *) echo $RT_UID:$RT_GID ;; esac; }"
OUT="$(rt "CONTAINER_RUNTIME=podman; export STUB_UID_MAP='0 0 1\n1 100000 65536\n'; $OWN_STAT2; id() { if [ \"\$1\" = -u ]; then echo 0; else command id \"\$@\"; fi; }; chown() { echo direct-chown >> \"\$STUB_DIR/rt-calls\"; }
  getenforce() { echo Enforcing; }
  ct_own 0:10001 '$OWN_F/op' '$OWN_F/hub'; grep -cx 'unshare chown -- 0:10001 $OWN_F/op $OWN_F/hub' \"\$STUB_DIR/podman-calls\"; cat \"\$STUB_DIR/rt-calls\" 2>/dev/null | grep -c 'direct-chown\|^run '; true")"
expect_eq "ct_own on podman (SELinux enforcing) runs podman unshare chown: no helper container, no bind mount, never chown directly (even as uid 0)" "$OUT" "1
0
rc=0"
OUT="$(rt "CONTAINER_RUNTIME=podman; $OWN_STAT2; ct_own 10001:10001 '$OWN_F/hub'; ct_own 0:0 '$OWN_F/op'; test ! -e \"\$STUB_DIR/rt-calls\" && echo none")"
expect_eq "ct_own on podman is a no-op when _owner_of_ct matches" "$OUT" "none
rc=0"
OUT="$(rt "CONTAINER_RUNTIME=podman; $OWN_STAT2; podman() { case \"\$1 \$2\" in 'unshare chown') return 1 ;; esac; command podman \"\$@\"; }; ct_own 10001:10001 '$OWN_F/op'")"
case "$OUT" in *"try: podman unshare chown 10001:10001 '$OWN_F/op'"*"rc=1") t_pass "ct_own on podman: the failure hint is podman unshare chown" ;; *) t_fail "ct_own podman hint: $OUT" ;; esac
OUT="$(rt "CONTAINER_RUNTIME=podman; $OWN_STAT2; ct_group_read 10002 '$OWN_F/hub'; grep -cx 'unshare chown -- 0:10002 $OWN_F/hub' \"\$STUB_DIR/podman-calls\"; true")"
expect_eq "ct_group_read on podman passes 0:<gid>" "$OUT" "1
rc=0"
OUT="$(rt "CONTAINER_RUNTIME=docker; ct_group_read 10002 '$OWN_F/op'; grep -c 'chown $RT_UID:10002 /t/0$' \"\$STUB_DIR/rt-calls\"; true")"
expect_eq "ct_group_read on docker passes <operator uid>:<gid> (unchanged)" "$OUT" "1
rc=0"
OUT="$(rt "CONTAINER_RUNTIME=podman; PORTCULLIS_ROOT='$WORK/rt/sp'; mkdir -p '$WORK/rt/sp/secrets/hub'; chmod 500 '$WORK/rt/sp/secrets/hub'; stack_prepare")"
chmod 700 "$WORK/rt/sp/secrets/hub"
case "$OUT" in *"is not writable"*"Fix: podman unshare chown -R 0:0 \"$WORK/rt/sp/secrets\""*"rc=1") t_pass "stack_prepare on podman: the writability hint is podman unshare chown -R 0:0" ;; *) t_fail "stack_prepare podman hint: $OUT" ;; esac

# restic as container root = the operator, without capabilities.
OUT="$(rt "CONTAINER_RUNTIME=podman BACKUP_REPOSITORY='$WORK/rt/repo' BACKUP_ROOT='$WORK/rt/bk' BACKUP_PASSWORD=x; _restic snapshots >/dev/null 2>&1; grep -E '^run ' \"\$STUB_DIR/rt-calls\"")"
case "$OUT" in "run --rm -i --user 0:0 --cap-drop ALL "*) t_pass "_restic on podman runs --user 0:0 --cap-drop ALL" ;; *) t_fail "_restic podman: $OUT" ;; esac
case "$OUT" in *" --security-opt label=disable "*) t_pass "_restic on podman: label=disable (a CLI helper bind-mounting backups/)" ;; *) t_fail "_restic podman label: $OUT" ;; esac
case "$OUT" in *:[zZ]" "*|*:[zZ]|*,[zZ]" "*|*"ro,z"*|*"ro,Z"*|*:z,*|*:Z,*) t_fail "_restic on podman relabels a bind: $OUT" ;; *) t_pass "_restic on podman: no :z / :Z on its binds" ;; esac
OUT="$(rt "CONTAINER_RUNTIME=docker BACKUP_REPOSITORY='$WORK/rt/repo' BACKUP_ROOT='$WORK/rt/bk' BACKUP_PASSWORD=x; _restic snapshots >/dev/null 2>&1; grep -E '^run ' \"\$STUB_DIR/rt-calls\"")"
case "$OUT" in "run --rm -i --user $RT_UID:$RT_GID --cap-drop ALL "*) t_pass "_restic on docker runs as the operator (unchanged)" ;; *) t_fail "_restic docker: $OUT" ;; esac
case "$OUT" in *label=disable*) t_fail "_restic on docker carries label=disable: $OUT" ;; *) t_pass "_restic on docker: no label option (unchanged)" ;; esac
expect_eq "ct_run on podman: --security-opt label=disable, the binds as given (no :z / :Z)" \
  "$(rt "CONTAINER_RUNTIME=podman; ct_run --rm --network none -v '$WORK/rt/bk:/backup:ro' alpine true; cat \"\$STUB_DIR/rt-calls\"")" "run --security-opt label=disable --rm --network none -v $WORK/rt/bk:/backup:ro alpine true
rc=0"
expect_eq "ct_run on docker: plain docker run (unchanged)" \
  "$(rt "CONTAINER_RUNTIME=docker; ct_run --rm --network none -v '$WORK/rt/bk:/backup:ro' alpine true; cat \"\$STUB_DIR/rt-calls\"")" "run --rm --network none -v $WORK/rt/bk:/backup:ro alpine true
rc=0"
expect_eq "every CLI helper that bind-mounts a host path goes through ct_run / ct_own / _restic (no bare docker run with a host bind)" \
  "$(grep -nE 'docker run .*(-v "\$(dir|path|BACKUP_ROOT|PORTCULLIS_ROOT)|--mount "type=bind)' "$HERE"/../scripts/lib/*.sh | grep -v 'scripts/lib/common.sh:.*mounts+=' || true)" ""
expect_eq "no CLI bind ever relabels (:z / :Z / selinux)" "$(grep -nE '(-v|--volume) "[^"]*:[zZ](,|")|,[zZ]"|selinux=' "$HERE"/../scripts/lib/*.sh || true)" ""
OUT="$(rt "CONTAINER_RUNTIME=podman; backup_schedule_systemd '*-*-* 03:15:00' ''")"
case "$OUT" in *"After=network-online.target podman.socket"*"Requires=podman.socket"*"WantedBy=default.target"*) t_pass "backup schedule --systemd on podman writes user units (Requires=podman.socket, WantedBy=default.target)" ;; *) t_fail "schedule podman: $OUT" ;; esac
case "$OUT" in *"User="*|*"docker.service"*) t_fail "backup schedule on podman: no User=, no docker.service" ;; *) t_pass "backup schedule on podman: no User=, no docker.service" ;; esac
OUT="$(rt "CONTAINER_RUNTIME=podman; backup_schedule_systemd 'Sun 04:00' '$WORK/rt/units'")"
case "$OUT" in *"~/.config/systemd/user"*"systemctl --user daemon-reload"*"systemctl --user enable --now portcullis-backup.timer"*) t_pass "backup schedule --output on podman: user-unit install commands" ;; *) t_fail "schedule podman output: $OUT" ;; esac
OUT="$(rt "CONTAINER_RUNTIME=docker; backup_schedule_systemd '*-*-* 03:15:00' ''")"
case "$OUT" in *"Requires=docker.service"*"User=$(id -un)"*"WantedBy=timers.target"*) t_pass "backup schedule on docker: system units (unchanged)" ;; *) t_fail "schedule docker: $OUT" ;; esac
# Kubernetes: no engine unit (a k3s host without Docker would never start
# the timer); k3s.service when this host runs it, else nothing.
OUT="$(rt "CONTAINER_RUNTIME=kubernetes; systemctl() { [ \"\$1 \$2\" = 'cat k3s.service' ]; }; backup_schedule_systemd '*-*-* 03:15:00' ''")"
case "$OUT" in *"After=network-online.target k3s.service"*"Requires=k3s.service"*"User=$(id -un)"*"WantedBy=timers.target"*) t_pass "backup schedule on kubernetes (k3s host): After/Requires k3s.service, system units" ;; *) t_fail "schedule kube k3s: $OUT" ;; esac
case "$OUT" in *docker*|*podman*) t_fail "backup schedule on kubernetes: an engine dependency: $OUT" ;; *) t_pass "backup schedule on kubernetes: no docker / podman dependency" ;; esac
OUT="$(rt "CONTAINER_RUNTIME=kubernetes; systemctl() { return 1; }; backup_schedule_systemd '*-*-* 03:15:00' ''")"
case "$OUT" in *"Requires="*|*k3s*|*docker*) t_fail "backup schedule on kubernetes (remote cluster): a unit dependency: $OUT" ;;
  *"After=network-online.target"*"User=$(id -un)"*"WantedBy=timers.target"*) t_pass "backup schedule on kubernetes (no k3s here): no Requires=, After=network-online.target only" ;; *) t_fail "schedule kube remote: $OUT" ;; esac

# Every bind source of the SELinux overlay exists before `up`: in git, or
# made by stack_prepare (the overlay's long-syntax binds never create a
# missing source). A real stack_prepare in a fresh root, docker stubbed.
SPX="$WORK/spx-root"; mkdir -p "$SPX" "$WORK/spxbin"
{ printf '#!/usr/bin/env bash\n'; cat "$WORK/stub-version"; cat <<'STUB'
case "$*" in
  *" keygen") printf '# created: x\n# public key: age1qqqq\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n' ;;
esac
exit 0
STUB
} > "$WORK/spxbin/docker"
chmod +x "$WORK/spxbin/docker"
SPX_OUT="$(PATH="$WORK/spxbin:$PATH" PORTCULLIS_ROOT="$SPX" bash -c '
  set -euo pipefail
  for l in common network vault pki certs keycloak users domains mcpgate sessions dns config status monitoring backup signin stack; do
    # shellcheck disable=SC1090
    . "$1/scripts/lib/$l.sh"
  done
  export CONTAINER_RUNTIME=docker PORTCULLIS_PUBLIC_IPV4=203.0.113.9 PORTCULLIS_PUBLIC_IPV6= \
    FORWARD_AUTH_REDIS_PASSWORD=a FORWARD_AUTH_EXT_REDIS_PASSWORD=b PORTCULLIS_DOMAIN=ci.example.org
  lldap_key_seed_generate  # init makes it (never stack_prepare: up refuses without it)
  stack_prepare' _ "$HERE/.." 2>&1)"; SPX_RC=$?
expect_eq "stack_prepare in a fresh root (docker stubbed) succeeds" "$SPX_RC" 0
[ "$SPX_RC" = 0 ] || printf '%s\n' "$SPX_OUT" | tail -n 5
SPX_MISSING=""
while IFS= read -r src; do
  src="${src#./}"
  if [ -n "$(git -C "$HERE/.." ls-files -- "$src" | head -n1)" ] || [ -e "$SPX/$src" ]; then continue; fi
  SPX_MISSING="$SPX_MISSING $src"
done < <(sed -n 's/.*type: bind, source: *\([^,}]*\).*/\1/p' "$HERE/../docker-compose.podman-selinux.yml" | sort -u)
expect_eq "every SELinux-overlay bind source is in git or made by stack_prepare (or init: the LLDAP key seed)" "$SPX_MISSING" ""
expect_eq "the overlay has bind sources to check" "$(grep -c 'type: bind, source:' "$HERE/../docker-compose.podman-selinux.yml" | awk '{print ($1 >= 45)}')" 1

# ── vexec: VAULT_TOKEN by name only while it is in the environment (Podman's
# compat exec refuses a bare name: 400 "badly formed, must be key=value") ──
mkdir -p "$WORK/vxbin"
{ printf '#!/usr/bin/env bash\n'; cat "$WORK/stub-version"; cat <<'STUB'
echo "$*" >> "$STUB_DIR/vx-calls"
case "$*" in
  *" exec "*) echo "Error response from daemon: environment variable \"X\" badly formed, must be key=value" >&2; exit 1 ;;
esac
exit 0
STUB
} > "$WORK/vxbin/docker"
chmod +x "$WORK/vxbin/docker"
vx() { rm -f "$STUB_DIR/vx-calls"; (PATH="$WORK/vxbin:$PATH"; unset VAULT_TOKEN; eval "$1") >"$WORK/vx-out" 2>&1; sed 's/--project-directory [^ ]* //' "$STUB_DIR/vx-calls"; }
expect_eq "vexec: VAULT_TOKEN unset → no -e VAULT_TOKEN" "$(vx 'vexec status -format=json')" "compose exec -T vault vault status -format=json"
expect_eq "vexec: VAULT_TOKEN only a shell variable (not exported) → no -e VAULT_TOKEN" "$(vx 'VAULT_TOKEN=s3cr3t-tok; vexec status')" "compose exec -T vault vault status"
expect_eq "vexec: VAULT_TOKEN exported → -e VAULT_TOKEN by name, the value never on argv" \
  "$(vx 'export VAULT_TOKEN=s3cr3t-tok; vexec status')" "compose exec -T -e VAULT_TOKEN vault vault status"
expect_eq "the container vault CLI wrapper: the same rule" \
  "$(vx 'export VAULT_TOKEN=s3cr3t-tok; command() { [ "$2" = vault ] && return 1; builtin command "$@"; }; vault_use_container_cli; vault read x; unset VAULT_TOKEN; vault read y')" \
  "compose exec -T -e VAULT_TOKEN vault vault read x
compose exec -T vault vault read y"
vx 'sleep() { :; }; _vault_start_and_status' >/dev/null
case "$(cat "$WORK/vx-out")" in
  *"vault status (exit 1) said:"*"badly formed, must be key=value"*"Vault API did not come up"*) t_pass "the Vault API wait prints the last vault status error when it gives up" ;;
  *) t_fail "Vault API wait error: $(tail -n 5 "$WORK/vx-out")" ;;
esac

# ── a failed `up` names each unhealthy container with its last health checks ──
mkdir -p "$WORK/hcbin"
{ printf '#!/usr/bin/env bash\n'; cat "$WORK/stub-version"; cat <<'STUB'
case "$*" in
  "compose --project-directory "*" up "*) exit 1 ;;
  "compose --project-directory "*" ps -aq") printf 'c1\nc2\n' ;;
  "inspect --format {{.Name}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} c1") echo "/portcullis-keycloak-1 unhealthy" ;;
  "inspect --format {{.Name}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} c2") echo "/portcullis-vault-1 healthy" ;;
  "inspect --format {{json .State.Health.Log}} c1") echo '[{"ExitCode":1,"Output":"old"},{"ExitCode":1,"Output":"a\n b"},{"ExitCode":1,"Output":"bash: connect: Connection refused\n"},{"ExitCode":-1,"Output":"timed out"}]' ;;
esac
exit 0
STUB
} > "$WORK/hcbin/docker"
chmod +x "$WORK/hcbin/docker"
HC_OUT="$( (PATH="$WORK/hcbin:$PATH"; CONTAINER_RUNTIME=docker; rt_up keycloak; echo "rc=$?") 2>&1)"
case "$HC_OUT" in
  *"portcullis-keycloak-1 is unhealthy; its last health checks:"*"exit 1: a b"*"exit 1: bash: connect: Connection refused"*"exit -1: timed out"*"rc=1") t_pass "stack_compose_up: a failed up prints each unhealthy container's last three health checks" ;;
  *) t_fail "stack_compose_up health report: $HC_OUT" ;;
esac
case "$HC_OUT" in *vault-1*|*"exit 1: old"*) t_fail "stack_compose_up health report: a healthy container or an old check listed: $HC_OUT" ;; *) t_pass "stack_compose_up health report: healthy containers and older checks left out" ;; esac

# ── a failed up while a dependency is still starting: wait, one more up ──
# (test server 2026-11-13 finding A). The stub's up fails while
# $SU/kc-health isn't "healthy"; keycloak's state / restart count / health
# come from $SU/kc-state, $SU/kc-restarts, $SU/kc-health; every `sleep`
# runs $SU/tick (the test's script for what changes meanwhile).
SU="$WORK/su"; mkdir -p "$WORK/subin" "$SU"
{ printf '#!/usr/bin/env bash\n'; cat "$WORK/stub-version"; cat <<'STUB'
echo "$*" >> "$SU/calls"
case "$*" in
  "compose --project-directory "*" build"*) exit 0 ;;
  "compose --project-directory "*" up "*)
    [ "$(cat "$SU/kc-health")" = healthy ] || { echo "dependency failed to start: container portcullis-keycloak-1 is unhealthy" >&2; exit 1; } ;;
  "compose --project-directory "*" ps -aq") printf 'c1\nc2\nc3\n' ;;
  "inspect --format {{index .Config.Labels \"com.docker.compose.service\"}} "*" c1")
    echo "keycloak $(cat "$SU/kc-state") $(cat "$SU/kc-restarts") $(cat "$SU/kc-health")" ;;
  "inspect --format {{index .Config.Labels \"com.docker.compose.service\"}} "*" c2") echo "vault running 0 healthy" ;;
  "inspect --format {{index .Config.Labels \"com.docker.compose.service\"}} "*" c3") echo "forward-auth created 0 none" ;;
  "inspect --format {{.Name}} "*" c1") echo "/portcullis-keycloak-1 $(cat "$SU/kc-health")" ;;
  "inspect --format {{.Name}} "*) echo "/portcullis-other-1 healthy" ;;
  "inspect --format {{json .State.Health.Log}} c1") echo '[{"ExitCode":1,"Output":"kc not ready"}]' ;;
esac
exit 0
STUB
} > "$WORK/subin/docker"
chmod +x "$WORK/subin/docker"
# su_run <state> <restarts> <health> <tick script> — stack_compose_up keycloak
# with the wait at 30 s (6 polls); prints its output, the up / build calls and rc.
su_run() {
  rm -f "$SU/calls"; : > "$SU/ticks"; echo "$1" > "$SU/kc-state"; echo "$2" > "$SU/kc-restarts"; echo "$3" > "$SU/kc-health"
  printf '%s\n' "$4" > "$SU/tick"
  ( PATH="$WORK/subin:$PATH"; export SU STACK_UP_WAIT=30; CONTAINER_RUNTIME=docker
    sleep() { echo x >> "$SU/ticks"; bash "$SU/tick"; }
    rt_up keycloak; echo "rc=$?" ) 2>&1
  echo "ticks=$(wc -l < "$SU/ticks" | tr -d " ")"
  grep -E '^compose .* (up|build)( |$)' "$SU/calls" | sed 's/--project-directory [^ ]* //'
}
# Slow but healthy: unhealthy at compose's deadline, healthy two polls later.
OUT="$(su_run running 0 unhealthy 'n=$(wc -l < "$SU/ticks"); [ "$n" -lt 2 ] || echo healthy > "$SU/kc-health"')"
case "$OUT" in
  *"compose up stopped while keycloak still starting"*"Healthy now: running compose up again"*"rc=0"*"ticks=2"*) t_pass "stack_compose_up: a slow-healthy Keycloak → waited, one more up, success" ;;
  *) t_fail "stack_compose_up slow keycloak: $OUT" ;;
esac
expect_eq "stack_compose_up slow keycloak: the build once, before the first up; the up twice, never rebuilding" \
  "$(printf '%s\n' "$OUT" | grep '^compose ')" "compose build --quiet
compose up -d --no-build keycloak
compose up -d --no-build keycloak"
# Starting (still inside start_period at compose's deadline) counts too.
OUT="$(su_run running 0 starting 'echo healthy > "$SU/kc-health"')"
case "$OUT" in *"rc=0"*"ticks=1"*) t_pass "stack_compose_up: a starting Keycloak → waited, success" ;; *) t_fail "stack_compose_up starting keycloak: $OUT" ;; esac
# Crash loop: restarting → no wait, fails naming it, with the health report.
OUT="$(su_run restarting 3 unhealthy ':')"
case "$OUT" in
  *"keycloak is restarting (not a slow start)"*"portcullis-keycloak-1 is unhealthy; its last health checks:"*"kc not ready"*"rc=1"*"ticks=0"*) t_pass "stack_compose_up: a crash-looping Keycloak fails at once, named, with its health checks" ;;
  *) t_fail "stack_compose_up crash loop: $OUT" ;;
esac
expect_eq "stack_compose_up crash loop: one up only" "$(printf '%s\n' "$OUT" | grep -c '^compose up ')" "1"
# Running at first but restarted during the wait → a crash, not a slow start.
OUT="$(su_run running 0 unhealthy 'echo 1 > "$SU/kc-restarts"')"
case "$OUT" in *"keycloak is restarted (not a slow start)"*"rc=1"*"ticks=1"*) t_pass "stack_compose_up: Keycloak restarted during the wait → fails at once" ;; *) t_fail "stack_compose_up restarted: $OUT" ;; esac
# Exited: no wait.
OUT="$(su_run exited 0 unhealthy ':')"
case "$OUT" in *"keycloak is exited (not a slow start)"*"rc=1"*"ticks=0"*) t_pass "stack_compose_up: an exited Keycloak fails at once" ;; *) t_fail "stack_compose_up exited: $OUT" ;; esac
# Never healthy: the whole bounded wait, then fails loudly, no second up.
OUT="$(su_run running 0 unhealthy ':')"
case "$OUT" in
  *"keycloak still not healthy after 30s"*"portcullis-keycloak-1 is unhealthy; its last health checks:"*"rc=1"*"ticks=6"*) t_pass "stack_compose_up: Keycloak unhealthy after the wait → fails, named, with its health checks" ;;
  *) t_fail "stack_compose_up never healthy: $OUT" ;;
esac
expect_eq "stack_compose_up never healthy: one up only" "$(printf '%s\n' "$OUT" | grep -c '^compose up ')" "1"
# Keycloak's healthcheck budget: start_period 300 s, interval / retries kept.
expect_eq "keycloak healthcheck: start_period 300s, interval 10s, retries 12, CMD-SHELL" \
  "$(awk '/^  keycloak:/{k=1} k && /^  [a-z]/ && !/^  keycloak:/{k=0} k' "$HERE/../docker-compose.yml" | grep -E '^      (test|interval|retries|start_period):' | sed -E 's/^ +//; s/^(test: \["CMD-SHELL").*/\1/')" \
  'test: ["CMD-SHELL"
interval: 10s
retries: 12
start_period: 300s'

# ── network_state under rootless Podman: its compat inspect has no IPRange
# (Podman keeps the range as a lease range: first+1 .. last); the range is
# read from the host's `podman network inspect` (libpod JSON) ──
mkdir -p "$WORK/nsbin"
cat > "$WORK/nsbin/podman" <<'STUB'
#!/usr/bin/env bash
if [ "$1 $2" = "network inspect" ] && [ "$4 $5" = "--format json" ]; then
  [ -f "$STUB_DIR/libpod-json-$3" ] || exit 125
  cat "$STUB_DIR/libpod-json-$3"; exit 0
fi
exit 0
STUB
{ printf '#!/usr/bin/env bash\n'; cat "$WORK/stub-version"; cat <<'STUB'
if [ "$1 $2" = "network inspect" ] && [ "$4 $5" = "--format {{json .IPAM.Config}}" ]; then
  if [ -f "$STUB_DIR/ipam-json-$3" ]; then cat "$STUB_DIR/ipam-json-$3"; exit 0; fi
  [ "$3" = portcullis-proxy ] && [ -f "$STUB_DIR/ipam-json" ] && { cat "$STUB_DIR/ipam-json"; exit 0; }
  exit 1
fi
exit 0
STUB
} > "$WORK/nsbin/docker"
chmod +x "$WORK/nsbin/podman" "$WORK/nsbin/docker"
ns() { (PATH="$WORK/nsbin:$PATH" CONTAINER_RUNTIME=podman; "$@") 2>/dev/null; }
rm -f "$STUB_DIR"/libpod-json-* "$STUB_DIR/ipam-json"
# Podman's compat shape: Subnet + Gateway, no IPRange.
printf '%s' '[{"Subnet":"172.31.250.0/24","Gateway":"172.31.250.1"}]' > "$STUB_DIR/ipam-json"
printf '%s' '[{"name":"portcullis-proxy","subnets":[{"subnet":"172.31.250.0/24","gateway":"172.31.250.1","lease_range":{"start_ip":"172.31.250.129","end_ip":"172.31.250.255"}}]}]' > "$STUB_DIR/libpod-json-portcullis-proxy"
expect_eq "podman net: compat inspect without IPRange + the libpod lease range of the .env range → ok" "$(ns proxy_network_state)" ok
printf '%s' '[{"name":"portcullis-proxy","subnets":[{"subnet":"172.31.250.0/24","gateway":"172.31.250.1","lease_range":{"start_ip":"172.31.250.65","end_ip":"172.31.250.127"}}]}]' > "$STUB_DIR/libpod-json-portcullis-proxy"
expect_eq "podman net: another lease range → mismatch" "$(ns proxy_network_state)" mismatch
printf '%s' '[{"name":"portcullis-proxy","subnets":[{"subnet":"172.31.250.0/24","gateway":"172.31.250.1"}]}]' > "$STUB_DIR/libpod-json-portcullis-proxy"
expect_eq "podman net: no lease range where .env sets one → mismatch" "$(ns proxy_network_state)" mismatch
printf '%s' '[{"Subnet":"10.89.0.0/24","Gateway":"10.89.0.1"}]' > "$STUB_DIR/ipam-json"
expect_eq "podman net: another subnet → mismatch (never subnet-blind)" "$(ns proxy_network_state)" mismatch
printf '%s' '[{"Subnet":"172.31.250.0/24","Gateway":"172.31.250.1"}]' > "$STUB_DIR/ipam-json"
rm -f "$STUB_DIR/libpod-json-portcullis-proxy"
expect_eq "podman net: the libpod inspect fails → unknown" "$(ns proxy_network_state)" unknown
OUT="$(PATH="$WORK/nsbin:$PATH" CONTAINER_RUNTIME=podman bash -c "source '$HERE/../scripts/lib/common.sh'; source '$HERE/../scripts/lib/network.sh'; proxy_dns_shadows() { :; }; network_check" 2>&1)"
case "$OUT" in *"can't read the IP range of portcullis-proxy"*) t_pass "podman net: network_check refuses an unreadable range (fail closed)" ;; *) t_fail "podman net unknown: $OUT" ;; esac
printf '%s' '[{"Subnet":"172.31.252.0/28","Gateway":"172.31.252.1"}]' > "$STUB_DIR/ipam-json-portcullis_portcullis-domains"
printf '%s' '[{"subnets":[{"subnet":"172.31.252.0/28","gateway":"172.31.252.1"}]}]' > "$STUB_DIR/libpod-json-portcullis_portcullis-domains"
expect_eq "podman net: domains (no range expected, none set) → ok" "$(ns domains_network_state)" ok
printf '%s' '[{"subnets":[{"subnet":"172.31.252.0/28","gateway":"172.31.252.1","lease_range":{"start_ip":"172.31.252.9","end_ip":"172.31.252.15"}}]}]' > "$STUB_DIR/libpod-json-portcullis_portcullis-domains"
expect_eq "podman net: domains with a lease range nobody asked for → mismatch" "$(ns domains_network_state)" mismatch
expect_eq "docker net: the Docker shape is unchanged (IPRange compared)" \
  "$(printf '%s' '[{"Subnet":"172.31.250.0/24","IPRange":"172.31.250.128/25"}]' > "$STUB_DIR/ipam-json"; PATH="$WORK/nsbin:$PATH" CONTAINER_RUNTIME=docker proxy_network_state)|$(printf '%s' '[{"Subnet":"172.31.250.0/24","IPRange":"172.31.250.0/25"}]' > "$STUB_DIR/ipam-json"; PATH="$WORK/nsbin:$PATH" CONTAINER_RUNTIME=docker proxy_network_state)" "ok|mismatch"
expect_eq "int_to_ip / the /32 lease rule" "$(int_to_ip "$(ip_to_int 172.31.250.129)")" 172.31.250.129
rm -f "$STUB_DIR"/libpod-json-* "$STUB_DIR/ipam-json" "$STUB_DIR/ipam-json-portcullis_portcullis-domains"

# hub_started_unix: Podman reports StartedAt in the host's local time.
HS() { (dc() { echo cid; }; docker() { echo "$HS_AT"; }; hub_started_unix); }
expect_eq "hub_started_unix: Docker's UTC Z form" "$(HS_AT=2026-11-13T04:12:06.123456789Z HS)" 1794543126
if date -u -d 2026-11-13T05:12:06+01:00 +%s >/dev/null 2>&1; then
  expect_eq "hub_started_unix: an RFC 3339 offset (Podman, local time)" "$(HS_AT=2026-11-13T05:12:06.5+01:00 HS)" 1794543126
fi
expect_eq "hub_started_unix: no StartedAt → 0" "$(HS_AT='' HS)" 0

# AppArmor (Ubuntu bug 2154379): pasta must accept podman's SIGTERM.
AA="$WORK/rt/aa"
aa() { rt "CONTAINER_RUNTIME=podman RT_APPARMOR_DIR='$AA' RT_APPARMOR_ENABLED='$WORK/rt/$1' RT_APPARMOR_POLICY='${AA_POLICY:-$WORK/rt/aa-nopolicy}'; _rt_apparmor_pasta_check" | head -n1 | cut -f1; }
rm -f "$AA/podman" "$AA/usr.bin.pasta" "$AA/local/usr.bin.pasta"
expect_eq "AppArmor check: disabled → ok" "$(aa aa-off)" ok
expect_eq "AppArmor check: enabled, no podman / pasta profiles → ok" "$(aa aa-on)" ok
printf 'profile podman /usr/bin/podman flags=(unconfined) {\n}\n' > "$AA/podman"
printf 'profile pasta /usr/bin/pasta{,.avx2} flags=(attach_disconnected) {\n  include <abstractions/pasta>\n  include if exists <local/usr.bin.pasta>\n}\n' > "$AA/usr.bin.pasta"
expect_eq "AppArmor check: Ubuntu's profiles without the rule → fail" "$(aa aa-on)" fail
case "$(rt "CONTAINER_RUNTIME=podman RT_APPARMOR_DIR='$AA' RT_APPARMOR_ENABLED='$WORK/rt/aa-on' RT_APPARMOR_POLICY='$WORK/rt/aa-nopolicy'; _rt_apparmor_pasta_check")" in
  *"signal (receive) set=(term) peer=podman,"*"apparmor_parser -r"*) t_pass "AppArmor check: the fail line gives the rule and the reload" ;; *) t_fail "AppArmor check hint" ;; esac
echo '# signal (receive) set=(term) peer=podman,' > "$AA/local/usr.bin.pasta"
expect_eq "AppArmor check: a commented-out rule → fail" "$(aa aa-on)" fail
echo 'signal (receive) set=(term) peer=podman,' > "$AA/local/usr.bin.pasta"
expect_eq "AppArmor check: the rule in local/usr.bin.pasta → ok" "$(aa aa-on)" ok
printf 'profile pasta /usr/bin/pasta {\n  include <abstractions/pasta>\n}\n' > "$AA/usr.bin.pasta"
expect_eq "AppArmor check: a local rule the profile doesn't include → fail" "$(aa aa-on)" fail
printf 'profile pasta /usr/bin/pasta {\n  include if exists <local/usr.bin.pasta>\n}\n' > "$AA/usr.bin.pasta"
echo 'signal (receive) set=(term) peer=podman,' > "$AA/local/usr.bin.pasta"
touch -t 202601010000 "$WORK/rt/aa-policy-old"; : > "$WORK/rt/aa-policy-new"
expect_eq "AppArmor check: the loaded policy older than the profile files (stale) → warn (reload it)" "$(AA_POLICY="$WORK/rt/aa-policy-old" aa aa-on)" warn
touch "$AA/usr.bin.pasta" "$AA/local/usr.bin.pasta"; sleep 1; touch "$WORK/rt/aa-policy-new"
expect_eq "AppArmor check: the loaded policy newer than the profile files (fresh) → ok" "$(AA_POLICY="$WORK/rt/aa-policy-new" aa aa-on)" ok
expect_eq "AppArmor check: the loaded policy unreadable (no root) → ok, unchecked" "$(AA_POLICY="$WORK/rt/aa-nopolicy" aa aa-on)" ok
rm -f "$AA/local/usr.bin.pasta"
rm -f "$AA/local/usr.bin.pasta"
printf 'profile pasta /usr/bin/pasta {\n  signal receive set=(term hup kill int quit) peer=podman,\n}\n' > "$AA/usr.bin.pasta"
expect_eq "AppArmor check: the rule in the profile itself → ok" "$(aa aa-on)" ok

# ── lldap-ui under rootless Podman: a loopback-only forwarder, never a
# container-IP tunnel (the address is inside the rootless netns) ──
mkdir -p "$WORK/luibin" "$WORK/lui-root"
cat > "$WORK/luibin/docker" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = version ]; then
  case "${DOCKER_HOST:-}" in *podman.sock) echo '[{"Name":"Podman Engine","Version":"5.7.0"}]' ;; *) echo '[{"Name":"Engine","Version":"29.0.0"}]' ;; esac
  exit 0
fi
echo "$*" >> "$STUB_DIR/lui-calls"
case "$*" in
  "compose --project-directory "*" ps -q lldap") echo lldapcid ;;
  "inspect -f {{with index .NetworkSettings.Networks \"portcullis\"}}{{.IPAddress}}{{end}} lldapcid") echo 10.88.0.7 ;;
  "inspect -f {{.State.Running}} "*) echo false ;;
esac
exit 0
STUB
chmod +x "$WORK/luibin/docker"
lui() {
  rm -f "$STUB_DIR/lui-calls"
  (unset CONTAINER_RUNTIME DOCKER_HOST COMPOSE_FILE PORTCULLIS_ENGINE_SOCKET _RT_CHECKED
   export PATH="$WORK/luibin:$PATH" PORTCULLIS_ROOT="$WORK/lui-root" XDG_RUNTIME_DIR="$RT_XDG"
   bash -c 'for l in common network users; do . "$1/scripts/lib/$l.sh"; done; getenforce() { echo Disabled; }; cmd_lldap_ui' _ "$HERE/..") 2>&1
}
printf 'CONTAINER_RUNTIME=podman\nPORTCULLIS_ENGINE_SOCKET=%s\n' "$RT_PSOCK" > "$WORK/lui-root/.env"
LUI="$(lui)"
case "$LUI" in *"ssh -N -L 17170:127.0.0.1:17170 "*) t_pass "lldap-ui on podman: the tunnel targets the server's 127.0.0.1:17170" ;; *) t_fail "lldap-ui podman tunnel: $LUI" ;; esac
case "$LUI" in *10.88.0.7*) t_fail "lldap-ui on podman printed a container-IP tunnel" ;; *) t_pass "lldap-ui on podman: never a container-IP tunnel" ;; esac
expect_eq "lldap-ui on podman: the forwarder (socat, read-only, no capabilities, loopback publish), removed at exit" \
  "$(grep -c "^run -d --rm --name portcullis-lldap-ui-[0-9]* --network portcullis -p 127.0.0.1:17170:17170 --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 65534:65534 --memory 32m --pids-limit 32 docker.io/alpine/socat:[^ ]*@sha256:[0-9a-f]\{64\} TCP-LISTEN:17170,fork,reuseaddr TCP:lldap:17170$" "$STUB_DIR/lui-calls"):$(grep -c '^rm -f portcullis-lldap-ui-' "$STUB_DIR/lui-calls")" "1:1"
printf 'CONTAINER_RUNTIME=docker\n' > "$WORK/lui-root/.env"
LUI="$(lui)"
case "$LUI" in *"ssh -N -L 17170:10.88.0.7:17170 "*) t_pass "lldap-ui on docker: the container-IP tunnel (unchanged)" ;; *) t_fail "lldap-ui docker: $LUI" ;; esac
expect_eq "lldap-ui on docker: no forwarder" "$(grep -c '^run ' "$STUB_DIR/lui-calls")" 0
rm -f "$WORK/lui-root/.env"
case "$(lui)" in *"not found. Run ./portcullis init first"*) t_pass "lldap-ui needs .env (need_env, the runtime check)" ;; *) t_fail "lldap-ui without .env" ;; esac
# Kubernetes: a port-forward; no docker needed (a k3s host has none).
mkdir -p "$WORK/luik/bin" "$WORK/luik/root"
printf '#!/bin/sh\necho "kubectl $*" >> "%s"\n' "$WORK/luik/calls" > "$WORK/luik/bin/kubectl"; chmod +x "$WORK/luik/bin/kubectl"
printf 'CONTAINER_RUNTIME=kubernetes\nPORTCULLIS_KUBE_CONTEXT=ci\n' > "$WORK/luik/root/.env"
LUI="$( (unset CONTAINER_RUNTIME DOCKER_HOST COMPOSE_FILE _RT_CHECKED
  export PATH="$WORK/luik/bin:$PATH" PORTCULLIS_ROOT="$WORK/luik/root"
  bash -c 'for l in common network users; do . "$1/scripts/lib/$l.sh"; done
    require_cmd() { [ "$1" != docker ] || { echo "REQUIRED docker"; exit 9; }; }
    kube_runtime_check() { :; }; rt_running() { [ "$1" = lldap ]; }; cmd_lldap_ui' _ "$HERE/..") 2>&1; echo "rc=$?"; cat "$WORK/luik/calls" 2>/dev/null)"
case "$LUI" in *"REQUIRED docker"*) t_fail "lldap-ui on kubernetes requires docker: $LUI" ;;
  *"127.0.0.1:17170 (this server only)"*"rc=0"*"kubectl --context ci -n "*" port-forward --address 127.0.0.1 svc/lldap 17170:17170"*) t_pass "lldap-ui on kubernetes: a loopback port-forward, no docker needed" ;;
  *) t_fail "lldap-ui on kubernetes: $LUI" ;; esac

OUT="$(rt "$RT_HOST; id() { case \"\$1\" in -un) echo \"o'brien\" ;; *) command id \"\$@\" ;; esac; }; export STUB_UID_MAP=''; runtime_host_checks")"
case "$OUT" in *"--add-subgids 100000-165535 'o'\\''brien', then podman system migrate"*) t_pass "runtime_host_checks: the usermod hint single-quotes the user" ;; *) t_fail "usermod hint: $(printf '%s' "$OUT" | grep subuid)" ;; esac

# A restarted podman.socket leaves the proxies on a dead inode: up restarts
# the unhealthy ones (podman only).
expect_eq "runtime_proxies_refresh on podman: restarts the unhealthy proxy only" \
  "$( (CONTAINER_RUNTIME=podman; rt_health() { [ "$1" = socket-proxy-hub ] && echo unhealthy || echo healthy; }; dc() { echo "dc $*" >> "$WORK/prx-calls"; }; rm -f "$WORK/prx-calls"; runtime_proxies_refresh) 2>/dev/null; cat "$WORK/prx-calls")" "dc restart socket-proxy-hub"
expect_eq "runtime_proxies_refresh on docker: nothing" \
  "$( (CONTAINER_RUNTIME=docker; rt_health() { echo unhealthy; }; dc() { echo "dc $*"; }; runtime_proxies_refresh) 2>/dev/null)" ""

# ══ vpn: ./portcullis vpn … (scripts/lib/vpn.sh, contract §16) ═══════
# shellcheck source=../scripts/lib/vpn.sh
source "$HERE/../scripts/lib/vpn.sh"
VPN_PRIV="cHJpdmF0ZS1rZXktb2YtdGhlLXRlc3Qtc3R1Yi0wMDAwMDA="
VPN_PUB="cHVibGljLWtleS1vZi10aGUtdGVzdC1zdHViLTAwMDAwMDA="
# vt <script> — runs <script> in a subshell with a fresh root (.env from
# $VT_ENV), every engine / Hub call stubbed and logged to $WORK/vt/log
# (argv), Hub stdin to $WORK/vt/stdin, jq argv to $WORK/vt/jq.
vt() {
  rm -rf "$WORK/vt"; mkdir -p "$WORK/vt/root/secrets/wg" "$WORK/vt/root/secrets/monitoring/prometheus"
  printf '%s\n' "${VT_ENV:-PORTCULLIS_DOMAIN=vpn.example.org}" > "$WORK/vt/root/.env"
  : > "$WORK/vt/root/secrets/wg/people.key"
  (
    export PORTCULLIS_ROOT="$WORK/vt/root" MONITORING_SECRETS="$WORK/vt/root/secrets/monitoring"
    unset COMPOSE_PROFILES PORTCULLIS_VPN_MODE PORTCULLIS_VPN_PUBLIC_ENROL PORTCULLIS_VPN_BUILTIN PORTCULLIS_VPN_PORT PORTCULLIS_VPN_SUBNET \
      PORTCULLIS_EP_CORE PORTCULLIS_EP_ADMIN PORTCULLIS_EP_ENROL
    env_load
    L="$WORK/vt/log"
    dc() {
      echo "dc $*" >> "$L"
      case "$*" in
        "exec -T hub hub vpn host-info")
          [ "${VT_HUB_DOWN:-}" != 1 ] || return 1
          # VT_HUB_ANSWER_AFTER=n: the first n-1 calls fail (a Hub still starting).
          echo x >> "$WORK/vt/hostinfo-calls"
          [ "$(wc -l < "$WORK/vt/hostinfo-calls")" -ge "${VT_HUB_ANSWER_AFTER:-1}" ] || return 1
          printf '%s' "${VT_HOSTINFO:-$VT_HOSTINFO_DEFAULT}" ;;
        "exec -T wg /wg keypair") printf '{"private_key":"%s","public_key":"%s"}\n' "$VPN_PRIV" "$VPN_PUB" ;;
        "exec -T hub hub vpn add-device "*) cat >> "$WORK/vt/stdin"; echo '{"address":"10.213.0.5","server_public_key":"U2VydmVy","endpoint":"vpn.example.org:51820","allowed_ips":"10.213.0.1/32","dns":"10.213.0.1","mtu":1280}' ;;
        "exec -T wg /wg qr") cat >> "$WORK/vt/qr"; echo QR ;;
        "ps -q --status running wg") echo cid ;;
      esac
    }
    docker() {
      echo "docker $*" >> "$L"
      case "$1 $2" in
        "network ls") echo n1 ;;
        "network inspect") printf '%s\n' "${VT_DOCKER_SUBNETS:-172.17.0.0/16}" ;;
      esac
    }
    ct_run() { echo "ct_run $*" >> "$L"; local a; for a in "$@"; do case "$a" in type=bind,src=*) a="${a#type=bind,src=}"; printf 'S0VZ\n' > "${a%%,dst=*}" ;; esac; done; }
    runtime_build_service() { echo "runtime_build_service $*" >> "$L"; }
    stack_compose_up() { echo "stack_compose_up $*" >> "$L"; }
    hub_env_write() { echo "hub_env_write" >> "$L"; }
    ct_group_read() { echo "ct_group_read $*" >> "$L"; }
    monitoring_fix_perms() { :; }
    rt_health() { echo "${VT_HUB_HEALTH:-healthy}"; }
    wait_healthy() { echo "wait_healthy $*" >> "$L"; }
    jq() { printf '%s\n' "$*" >> "$WORK/vt/jq"; command jq "$@"; }
    eval "$1"
  )
}
vte() { cat "$WORK/vt/root/.env"; }
VT_HOSTINFO_DEFAULT='{"local_networks":["10.0.0.0/8","192.168.0.0/16"],"provider_ranges":[],"admin_device_seen":false}'

VE_OPEN_EP=$'PORTCULLIS_EP_CORE=websecure,vpnsecure\nPORTCULLIS_EP_ADMIN=websecure,vpnsecure\nPORTCULLIS_EP_ENROL=websecure,vpnsecure'
VE_OPEN_WEB=$'PORTCULLIS_WEB_CORE=websecure\nPORTCULLIS_WEB_ADMIN=websecure\nPORTCULLIS_WEB_ENROL=websecure'
expect_eq "vpn_entrypoints: apps, public enrolment on" "$(vpn_entrypoints apps true)" "$VE_OPEN_EP"$'\n'"$VE_OPEN_WEB"
expect_eq "vpn_entrypoints: apps, public enrolment off" "$(vpn_entrypoints apps false)" "$(vpn_entrypoints apps true)"
expect_eq "vpn_entrypoints: admin, public enrolment on" "$(vpn_entrypoints admin true)" \
  "PORTCULLIS_EP_CORE=websecure,vpnsecure
PORTCULLIS_EP_ADMIN=vpnsecure
PORTCULLIS_EP_ENROL=websecure,vpnsecure
PORTCULLIS_WEB_CORE=websecure
PORTCULLIS_WEB_ADMIN=parked
PORTCULLIS_WEB_ENROL=websecure"
expect_eq "vpn_entrypoints: admin, public enrolment off" "$(vpn_entrypoints admin false)" "$(vpn_entrypoints admin true)"
expect_eq "vpn_entrypoints: server, public enrolment on" "$(vpn_entrypoints server true)" \
  "PORTCULLIS_EP_CORE=vpnsecure
PORTCULLIS_EP_ADMIN=vpnsecure
PORTCULLIS_EP_ENROL=websecure,vpnsecure
PORTCULLIS_WEB_CORE=parked
PORTCULLIS_WEB_ADMIN=parked
PORTCULLIS_WEB_ENROL=websecure"
expect_eq "vpn_entrypoints: server, public enrolment off" "$(vpn_entrypoints server false)" \
  "PORTCULLIS_EP_CORE=vpnsecure
PORTCULLIS_EP_ADMIN=vpnsecure
PORTCULLIS_EP_ENROL=vpnsecure
PORTCULLIS_WEB_CORE=parked
PORTCULLIS_WEB_ADMIN=parked
PORTCULLIS_WEB_ENROL=parked"
expect_fail "vpn_entrypoints: an unknown mode" vpn_entrypoints everything true

OUT="$(VT_DOCKER_SUBNETS=$'172.17.0.0/16\n10.213.0.0/24' vt 'vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init: subnet overlapping a Docker network → refused with a suggestion" \
  "$RC:$(printf '%s' "$OUT" | grep -c '10.213.0.0/24 (a Docker network)'):$(printf '%s' "$OUT" | grep -c 'Try: ./portcullis vpn init --subnet 10.213.4.0/22')" "1:1:1"
expect_eq "vpn init: a refusal writes nothing" "$(vte | grep -c 'PORTCULLIS_VPN\|COMPOSE_PROFILES' || true)" 0
OUT="$(VT_HOSTINFO='{"local_networks":["10.0.0.0/8","10.213.0.0/24"],"provider_ranges":[],"admin_device_seen":false}' vt 'vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init: overlapping a Local network from hub vpn host-info → refused" \
  "$RC:$(printf '%s' "$OUT" | grep -c '10.213.0.0/24 (a Local network')" "1:1"
OUT="$(VT_HOSTINFO='{"local_networks":[],"provider_ranges":["10.213.0.0/16"],"admin_device_seen":false}' vt 'vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init: overlapping a wired provider's range → refused, no free /22 suggested in it" \
  "$RC:$(printf '%s' "$OUT" | grep -c "a wired VPN provider's range"):$(printf '%s' "$OUT" | grep -c 'Try:' || true)" "1:1:0"
OUT="$(vt 'vpn_init on 51820 10.214.0.0/23' 2>&1)"; RC=$?
expect_eq "vpn init: the reserved link subnet → refused" "$RC:$(printf '%s' "$OUT" | grep -c 'reserved for server links')" "1:1"
OUT="$(vt 'vpn_init on 51820 172.31.254.0/24' 2>&1)"; RC=$?
expect_eq "vpn init: portcullis-vpn / -edge → refused" "$RC:$(printf '%s' "$OUT" | grep -c 'a Portcullis VPN network')" "1:2"
for s in 192.168.4.0/22 172.20.0.0/22; do
  OUT="$(vt "vpn_init on 51820 $s" 2>&1)"; RC=$?
  expect_eq "vpn init: $s, in Docker's default address pools → refused, saying Docker allocates networks there" \
    "$RC:$(printf '%s' "$OUT" | grep -c "(Docker's default address pool)"):$(printf '%s' "$OUT" | grep -c 'Docker allocates networks (app instances'"'"' too) from these ranges')" "1:1:1"
done
OUT="$(PORTCULLIS_VPN_RUNTIME_POOLS="10.88.0.0/16 10.89.0.0/16" vt 'vpn_init on 51820 10.89.4.0/22' 2>&1)"; RC=$?
expect_eq "vpn init under podman: a subnet in Podman's pool → refused, saying Podman allocates networks there" \
  "$RC:$(printf '%s' "$OUT" | grep -c "10.89.0.0/16 (Podman's address pool)"):$(printf '%s' "$OUT" | grep -c 'Podman allocates networks')" "1:1:1"
OUT="$(PORTCULLIS_VPN_RUNTIME_POOLS="10.88.0.0/16 10.89.0.0/16" vt 'vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init under podman: the default 10.213.0.0/22 is outside both pools" "$RC:$(printf '%s' "$OUT" | grep -c "address pool" || true)" "0:0"
OUT="$(PORTCULLIS_AUTH_SUBNET=10.213.8.0/28 vt 'vpn_init on 51820 10.213.8.0/22' 2>&1)"; RC=$?
expect_eq "vpn init: a fixed core subnet (moved into 10.213/16) → refused" "$RC:$(printf '%s' "$OUT" | grep -c '10.213.8.0/28 (a Portcullis core network)')" "1:1"
OUT="$(vt 'vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init: the default subnet clears the reserved ranges" "$(printf '%s' "$OUT" | grep -c "address pool\|core network" || true)" 0
# Under Podman an image HEALTHCHECK may not apply: the Hub is "running"
# (as ./portcullis up accepts); its answer to hub vpn host-info is the check.
OUT="$(vt 'CONTAINER_RUNTIME=podman; _rt_pool_check() { printf "fail\tPodman'"'"'s network pool isn'"'"'t pinned (stub)\n"; }; vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init under podman with Podman's pool unpinned → refused before anything is written" \
  "$RC:$(printf '%s' "$OUT" | grep -c "network pool isn't pinned"):$(vte | grep -c 'PORTCULLIS_VPN\|COMPOSE_PROFILES' || true)" "1:1:0"
OUT="$(vt 'CONTAINER_RUNTIME=podman; _rt_pool_check() { printf "ok\tPodman networks come from 10.89.0.0/16\n"; }; vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init under podman with the pool pinned → goes on" "$RC" 0
OUT="$(VT_HUB_HEALTH=running vt 'vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init: a Hub without a health status (running) that answers host-info → goes on" "$RC:$(printf '%s' "$OUT" | grep -c "the Hub isn't running" || true)" "0:0"
OUT="$(VT_HUB_HEALTH=running VT_HUB_DOWN=1 VPN_HUB_WAIT=1 vt 'vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init: a running Hub that never answers host-info → refused after the wait" "$RC:$(printf '%s' "$OUT" | grep -c "the Hub didn't answer hub vpn host-info within 1 s (state: running)")" "1:1"
OUT="$(VT_HUB_HEALTH=unhealthy vt 'vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init: an unhealthy Hub → refused at once" "$RC:$(printf '%s' "$OUT" | grep -c "the Hub isn't running (state: unhealthy)"):$(cat "$WORK/vt/log" 2>/dev/null | grep -c 'hub vpn host-info' || true)" "1:1:0"
for st in missing exited; do
  OUT="$(VT_HUB_HEALTH=$st vt 'vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
  expect_eq "vpn init: no Hub ($st) → refused at once" "$RC:$(printf '%s' "$OUT" | grep -c "the Hub isn't running (state: $st): ./portcullis up first")" "1:1"
done
# The Hub just restarted by ./portcullis up: health "starting" while it
# already answers, or answers after a few tries: vpn init waits for it.
OUT="$(VT_HUB_HEALTH=starting VT_HUB_ANSWER_AFTER=3 vt 'vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init: a starting Hub that answers on the third try → goes on" "$RC:$(grep -c 'hub vpn host-info' "$WORK/vt/log")" "0:3"
OUT="$(VT_HUB_HEALTH=starting VT_HUB_DOWN=1 VPN_HUB_WAIT=1 vt 'vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init: a starting Hub that never answers → refused after the wait, nothing written" \
  "$RC:$(printf '%s' "$OUT" | grep -c "didn't answer hub vpn host-info within 1 s (state: starting)"):$(vte | grep -c 'PORTCULLIS_VPN\|COMPOSE_PROFILES' || true)" "1:1:0"

OUT="$(VT_ENV=$'PORTCULLIS_DOMAIN=vpn.example.org\nCOMPOSE_PROFILES=monitoring' vt 'vpn_init on 51820 10.213.0.0/22; vpn_init on 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init writes the keys, adds wg to COMPOSE_PROFILES once" \
  "$RC:$(vte | grep -cx 'COMPOSE_PROFILES=monitoring,wg'):$(vte | grep -cx 'PORTCULLIS_VPN_BUILTIN=on'):$(vte | grep -cx 'PORTCULLIS_VPN_PORT=51820'):$(vte | grep -cx 'PORTCULLIS_VPN_SUBNET=10.213.0.0/22')" "0:1:1:1:1"
expect_eq "vpn init: the key generated once (a re-run keeps it), through ct_run in the wg image as the file's owner" \
  "$(grep -c '^ct_run ' "$WORK/vt/log"):$(grep -c "^ct_run --rm --network none --user $(id -u):10006 --cap-drop ALL --security-opt no-new-privileges:true --read-only --mount type=bind,src=$WORK/vt/root/secrets/wg/people.key,dst=/k --entrypoint /wg portcullis-wg genkey /k\$" "$WORK/vt/log"):$(cat "$WORK/vt/root/secrets/wg/people.key")" "1:1:S0VZ"
expect_eq "vpn init: the wg image is built before the key, then wg can read it, core.env refreshed, wg + Traefik + Hub started" \
  "$(grep -E '^(runtime_build_service|ct_run|ct_group_read|hub_env_write|stack_compose_up)' "$WORK/vt/log" | head -n5 | cut -d' ' -f1-2 | tr '\n' ';')" \
  "runtime_build_service wg;ct_run --rm;ct_group_read 10006;hub_env_write;stack_compose_up wg;"
expect_eq "vpn init: the wg Prometheus target once the profile is on" "$(jq -c '.[0].targets' "$WORK/vt/root/secrets/monitoring/prometheus/wg-targets.json")" '["wg-metrics:9100"]'
OUT="$(vt 'vpn_init off 51820 10.213.0.0/22' 2>&1)"; RC=$?
expect_eq "vpn init --builtin off: no key, PORTCULLIS_VPN_BUILTIN=off, the profile on" \
  "$RC:$(grep -c '^ct_run' "$WORK/vt/log" || true):$(vte | grep -cx 'PORTCULLIS_VPN_BUILTIN=off'):$(vte | grep -cx 'COMPOSE_PROFILES=wg')" "0:0:1:1"
expect_eq "vpn_prom_targets: no target without the profile (no TargetDown)" \
  "$(vt 'vpn_prom_targets; cat "$PORTCULLIS_ROOT/secrets/monitoring/prometheus/wg-targets.json"')" "[]"

OUT="$(vt 'vpn_mode server true false' 2>&1)"; RC=$?
expect_eq "vpn mode server without an admin device → refused naming --force" \
  "$RC:$(printf '%s' "$OUT" | grep -c -- '--force'):$(vte | grep -c PORTCULLIS_VPN_MODE || true):$(grep -c stack_compose_up "$WORK/vt/log" || true)" "1:1:0:0"
OUT="$(VT_HUB_DOWN=1 VPN_HUB_WAIT=1 vt 'vpn_mode admin true false' 2>&1)"; RC=$?
expect_eq "vpn mode admin with the Hub not answering → refused after the wait, naming --force, nothing written" \
  "$RC:$(printf '%s' "$OUT" | grep -c "didn't answer hub vpn host-info within 1 s"):$(printf '%s' "$OUT" | grep -c -- '--force'):$(vte | grep -c PORTCULLIS_VPN_MODE || true)" "1:1:1:0"
OUT="$(VT_HUB_HEALTH=starting VT_HUB_ANSWER_AFTER=3 VT_HOSTINFO='{"local_networks":[],"provider_ranges":[],"admin_device_seen":true}' vt 'vpn_mode admin true false' 2>&1)"; RC=$?
expect_eq "vpn mode admin: a starting Hub that answers on the third try → waited for, mode written" \
  "$RC:$(grep -c 'hub vpn host-info' "$WORK/vt/log"):$(vte | grep -cx 'PORTCULLIS_VPN_MODE=admin')" "0:3:1"
OUT="$(VT_HUB_HEALTH=exited vt 'vpn_mode admin true false' 2>&1)"; RC=$?
expect_eq "vpn mode admin: no Hub (exited) → refused at once, naming --force" \
  "$RC:$(printf '%s' "$OUT" | grep -c "the Hub isn't running (state: exited)"):$(printf '%s' "$OUT" | grep -c -- '--force'):$(cat "$WORK/vt/log" 2>/dev/null | grep -c 'host-info' || true)" "1:1:1:0"
OUT="$(VT_HOSTINFO='{"local_networks":[],"provider_ranges":[],"admin_device_seen":true}' vt 'vpn_mode server false false' 2>&1)"; RC=$?
expect_eq "vpn mode server with an admin device: mode, enrolment and the classes written, core recreated" \
  "$RC:$(vte | grep -cxE 'PORTCULLIS_VPN_MODE=server|PORTCULLIS_VPN_PUBLIC_ENROL=false|PORTCULLIS_EP_(CORE|ADMIN|ENROL)=vpnsecure|PORTCULLIS_WEB_(CORE|ADMIN|ENROL)=parked'):$(grep -cx 'stack_compose_up ' "$WORK/vt/log")" "0:8:1"
OUT="$(VT_HUB_DOWN=1 VT_ENV=$'PORTCULLIS_VPN_MODE=server\nPORTCULLIS_EP_CORE=vpnsecure' vt 'vpn_mode server true true' 2>&1)"; RC=$?
expect_eq "vpn mode server --force with the Hub down: no check, written" "$RC:$(grep -c 'host-info' "$WORK/vt/log" || true):$(vte | grep -cx 'PORTCULLIS_VPN_MODE=server')" "0:0:1"
OUT="$(VT_HUB_DOWN=1 VT_ENV=$'PORTCULLIS_VPN_MODE=server\nPORTCULLIS_EP_CORE=vpnsecure\nPORTCULLIS_EP_ADMIN=vpnsecure\nPORTCULLIS_EP_ENROL=vpnsecure\nPORTCULLIS_WEB_CORE=parked\nPORTCULLIS_WEB_ADMIN=parked\nPORTCULLIS_WEB_ENROL=parked' vt 'vpn_mode apps true false' 2>&1)"; RC=$?
expect_eq "vpn mode apps with wg and hub down → writes and recreates" \
  "$RC:$(grep -c '^dc exec' "$WORK/vt/log" || true):$(vte | grep -cxE 'PORTCULLIS_VPN_MODE=apps|PORTCULLIS_EP_(CORE|ADMIN|ENROL)=websecure,vpnsecure|PORTCULLIS_WEB_(CORE|ADMIN|ENROL)=websecure'):$(grep -cx 'stack_compose_up ' "$WORK/vt/log")" "0:0:7:1"

OUT="$(vt 'vpn_add_device alice laptop' 2>&1)"; RC=$?
ALL_ARGV="$(cat "$WORK/vt/log" "$WORK/vt/jq" 2>/dev/null)"
expect_eq "vpn add-device: the private key never on argv" "$RC:$(printf '%s' "$ALL_ARGV" | grep -c "$VPN_PRIV" || true)" "0:0"
expect_eq "vpn add-device: only the public key on the Hub's stdin" "$(cat "$WORK/vt/stdin")" "$VPN_PUB"
expect_eq "vpn add-device: the config has AllowedIPs = 10.213.0.1/32" \
  "$(printf '%s' "$OUT" | grep -cxE 'AllowedIPs = 10\.213\.0\.1/32|Address = 10\.213\.0\.5/32|DNS = 10\.213\.0\.1|PrivateKey = '"$VPN_PRIV"'|Endpoint = vpn\.example\.org:51820|MTU = 1280')" 6
expect_eq "vpn add-device: the QR code is drawn from the same config on stdin" "$(grep -c '^PrivateKey = ' "$WORK/vt/qr"):$(printf '%s' "$OUT" | grep -cx QR)" "1:1"
expect_eq "vpn add-device: the Hub call names the user and device" "$(grep -c '^dc exec -T hub hub vpn add-device --user alice --name laptop$' "$WORK/vt/log")" 1
expect_eq "vpn add-device: the Hub calls (host-info readiness, add-device) are hub vpn as the Hub container's own user, 10001 (no -u: the control socket is 0600, its own)" \
  "$(grep -c '^dc exec .*hub hub vpn' "$WORK/vt/log"):$(grep -c '^dc exec -T hub hub vpn ' "$WORK/vt/log")" "2:2"
# Every vpn subcommand that calls the Hub waits for it the same way
# (_vpn_hub_wait): a starting Hub is waited for, a stopped one refused at
# once — before wg makes a key pair.
for c in 'vpn_add_device alice laptop' 'vpn_devices "" false' 'vpn_revoke b1'; do
  OUT="$(VT_HUB_HEALTH=starting VT_HUB_ANSWER_AFTER=2 vt "$c" 2>&1)"; RC=$?
  expect_eq "$c: a starting Hub → host-info until it answers, then the call" \
    "$RC:$(grep -c 'hub vpn host-info' "$WORK/vt/log"):$(grep -cE 'hub vpn (add-device|devices|revoke)' "$WORK/vt/log")" "0:2:1"
  OUT="$(VT_HUB_HEALTH=missing vt "$c" 2>&1)"; RC=$?
  expect_eq "$c: no Hub → refused at once, no Hub call, no key pair" \
    "$RC:$(printf '%s' "$OUT" | grep -c "the Hub isn't running (state: missing)"):$(cat "$WORK/vt/log" 2>/dev/null | grep -cE 'hub vpn|wg keypair' || true)" "1:1:0"
done
expect_eq "vpn.sh: host-info is read only through _vpn_hub_wait" \
  "$(grep -c '_vpn_host_info' "$HERE/../scripts/lib/vpn.sh"):$(sed -n '/^_vpn_hub_wait()/,/^}/p' "$HERE/../scripts/lib/vpn.sh" | grep -c '_vpn_host_info')" "3:1"
expect_eq "vpn.sh: the Hub is reached only through _vpn_hub" \
  "$(grep -cE 'exec [^|]*hub -- hub ' "$HERE/../scripts/lib/vpn.sh")" 1
expect_ok "vpn add-device: keys stay in variables (no temp file, no -v mount)" bash -c "! grep -nE 'mktemp|> *\"?\\\$[a-z]*(key|kp)|--mount' <(sed -n '/^vpn_add_device()/,/^}/p' '$HERE/../scripts/lib/vpn.sh')"

OUT="$(vt 'vpn_builtin on' 2>&1)"; RC=$?
expect_eq "vpn builtin before vpn init (wg not in COMPOSE_PROFILES) → refused, nothing written or started" \
  "$RC:$(printf '%s' "$OUT" | grep -c 'run ./portcullis vpn init first'):$(vte | grep -c PORTCULLIS_VPN_BUILTIN || true):$(cat "$WORK/vt/log" 2>/dev/null | grep -cE 'ct_run|dc up|dc restart' || true)" "1:1:0:0"
OUT="$(VT_ENV=$'PORTCULLIS_DOMAIN=vpn.example.org\nCOMPOSE_PROFILES=wg' vt 'vpn_builtin off; vpn_builtin on' 2>&1)"; RC=$?
expect_eq "vpn builtin off empties the key, on makes a new one; wg recreated and restarted (it reads the key at start) both times" \
  "$RC:$(grep -c '^ct_run' "$WORK/vt/log"):$(grep -c '^dc up -d --no-deps.* wg$' "$WORK/vt/log"):$(grep -c '^dc restart wg$' "$WORK/vt/log"):$(vte | grep -cx 'PORTCULLIS_VPN_BUILTIN=on')" "0:1:2:2:1"
OUT="$(VT_ENV=$'PORTCULLIS_DOMAIN=vpn.example.org\nCOMPOSE_PROFILES=wg' vt 'printf KEY > "$PORTCULLIS_ROOT/secrets/wg/people.key"; vpn_builtin off; wc -c < "$PORTCULLIS_ROOT/secrets/wg/people.key"' 2>&1)"
expect_eq "vpn builtin off: the key file emptied in place" "$(printf '%s' "$OUT" | tail -n1 | tr -d ' ')" 0

# status: the vpn block, the textfile gauge.
SJ="$(vt 'export COMPOSE_PROFILES=wg PORTCULLIS_VPN_MODE=server
  dc() { case "$*" in
           "exec -T wg /wg status") printf "{\"version\":1,\"written\":\"%s\",\"mode\":\"server\",\"edge\":{\"ok\":true,\"error\":\"\"},\"people\":null}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" ;;
           "exec -T wg /wg providers") echo "{\"providers\":[{\"id\":\"hs\",\"label\":\"Tailnet\",\"ranges\":[\"100.64.0.0/10\"],\"devices\":3,\"refreshed_at\":null,\"fresh\":false}]}" ;;
         esac; }
  vpn_status_json')"
expect_eq "vpn_status_json: mode, up, providers, no problem while wg is up" \
  "$(printf '%s' "$SJ" | jq -c '[.enabled, .mode, .up, .problem, (.providers | length), .status.edge.ok]')" '[true,"server",true,false,1,true]'
SJ="$(vt 'export COMPOSE_PROFILES=wg PORTCULLIS_VPN_MODE=server; dc() { return 1; }; vpn_status_json')"
expect_eq "vpn_status_json: mode server with wg down → a problem" "$(printf '%s' "$SJ" | jq -c '[.up, .problem]')" '[false,true]'
SJ="$(vt 'dc() { return 1; }; vpn_status_json')"
expect_eq "vpn_status_json: apps without wg → not set up, no problem" "$(printf '%s' "$SJ" | jq -c '[.enabled, .mode, .problem]')" '[false,"apps",false]'
SJ="$( (require_cmd() { :; }; dc() { :; }; rt_health() { echo healthy; }; kc_login() { return 1; }
        proxy_dns_shadows() { :; }; _st_mcp_refusing() { :; }; vault_health_code() { echo 200; }
        vault_admin_env() { return 1; }; dns_status_json() { :; }
        vpn_status_json() { echo '{"enabled":true,"mode":"admin","public_enrol":true,"up":false,"providers":[],"problem":true}'; }
        status_run true 2>/dev/null) || true)"
expect_eq "status --json has vpn{}" "$(printf '%s' "$SJ" | jq -c '[.vpn.mode, .vpn.problem, .ok]')" '["admin",true,false]'
jq -n '{ok: true, services: [], vault: {active: true}, dns: null, vpn: {mode: "server"}}' > "$STUB_DIR/stf.json"
expect_eq "status textfile has portcullis_vpn_mode_restricted" "$(stf | grep '^portcullis_vpn_mode_restricted ')" "portcullis_vpn_mode_restricted 1"
jq -n '{ok: true, services: [], vault: {active: true}, dns: null, vpn: {mode: "apps"}}' > "$STUB_DIR/stf.json"
expect_eq "status textfile: apps → portcullis_vpn_mode_restricted 0" "$(stf | grep '^portcullis_vpn_mode_restricted ')" "portcullis_vpn_mode_restricted 0"

# ── SSH access (contract §18): status's SSH block, the textfile gauge ──
source "$HERE/../scripts/lib/ssh.sh"
SSH_ST='{"enabled":true,"user_ca_fp":"SHA256:u","host_ca_fp":"SHA256:h","problems":[],"cli_client_ready":true,"hosts":[{"id":"web-1","state":"ok","last_sync":null,"sync_age_s":12,"findings":0}]}'
SJ="$( (dc() { case "$*" in "exec -T hub hub ssh status") printf '%s' "$SSH_ST" ;; *) return 1 ;; esac; }; ssh_status_json) )"
expect_eq "ssh_status_json: on, fingerprints, hosts, no problem" "$(printf '%s' "$SJ" | jq -c '[.reachable, .enabled, .user_ca_fp, (.hosts | length), .problem]')" '[true,true,"SHA256:u",1,false]'
SJ="$( (dc() { case "$*" in "exec -T hub hub ssh status") printf '%s' '{"enabled":true,"problems":["ssh_user: no CA"],"cli_client_ready":true,"hosts":[]}' ;; *) return 1 ;; esac; }; ssh_status_json) )"
expect_eq "ssh_status_json: on with an enroll problem → a problem" "$(printf '%s' "$SJ" | jq -c '[.problem, .problems]')" '[true,["ssh_user: no CA"]]'
SJ="$( (dc() { case "$*" in "exec -T hub hub ssh status") printf '%s' '{"enabled":false,"problems":["ssh_user: no CA"],"hosts":[]}' ;; *) return 1 ;; esac; }; ssh_status_json) )"
expect_eq "ssh_status_json: off → no problem whatever enroll says" "$(printf '%s' "$SJ" | jq -c '[.enabled, .problem]')" '[false,false]'
SJ="$( (dc() { return 1; }; ssh_status_json) )"
expect_eq "ssh_status_json: the Hub not answering → unknown, no problem of its own" "$(printf '%s' "$SJ" | jq -c '[.reachable, .enabled, .problem]')" '[false,null,false]'
SJ="$( (require_cmd() { :; }; dc() { :; }; rt_health() { echo healthy; }; kc_login() { return 1; }
        proxy_dns_shadows() { :; }; _st_mcp_refusing() { :; }; vault_health_code() { echo 200; }
        vault_admin_env() { return 1; }; dns_status_json() { :; }
        ssh_status_json() { echo '{"reachable":true,"enabled":true,"user_ca_fp":"SHA256:u","host_ca_fp":"SHA256:h","cli_client_ready":true,"problems":["x"],"hosts":[],"problem":true}'; }
        status_run true 2>/dev/null) || true)"
expect_eq "status --json has ssh{} and its problem counts" "$(printf '%s' "$SJ" | jq -c '[.ssh.enabled, .ssh.problem, .ok]')" '[true,true,false]'
jq -n '{ok: true, services: [], vault: {active: true}, dns: null, vpn: {mode: "apps"}, ssh: {enabled: true, problems: []}}' > "$STUB_DIR/stf.json"
expect_eq "status textfile: portcullis_ssh_ca_ok 1" "$(stf | grep '^portcullis_ssh_ca_ok ')" "portcullis_ssh_ca_ok 1"
jq -n '{ok: true, services: [], vault: {active: true}, dns: null, vpn: {mode: "apps"}, ssh: {enabled: true, problems: ["x"]}}' > "$STUB_DIR/stf.json"
expect_eq "status textfile: portcullis_ssh_ca_ok 0 on a problem" "$(stf | grep '^portcullis_ssh_ca_ok ')" "portcullis_ssh_ca_ok 0"
jq -n '{ok: true, services: [], vault: {active: true}, dns: null, vpn: {mode: "apps"}, ssh: {enabled: false, problems: []}}' > "$STUB_DIR/stf.json"
expect_eq "status textfile: no portcullis_ssh_ca_ok while SSH is off" "$(stf | grep -c '^portcullis_ssh_ca_ok ' || true)" 0
# ssh_prepare: secrets/ssh/ 0750 and the record 0640, both group 10001.
(export PORTCULLIS_ROOT="$WORK/sshp"; mkdir -p "$PORTCULLIS_ROOT/secrets"; ct_own() { echo "$*" > "$WORK/sshp-own"; }; ssh_prepare)
expect_eq "ssh_prepare: secrets/ssh 0750, breakglass.jsonl 0640 (empty)" "$(file_mode "$WORK/sshp/secrets/ssh"):$(file_mode "$WORK/sshp/secrets/ssh/breakglass.jsonl"):$(wc -c < "$WORK/sshp/secrets/ssh/breakglass.jsonl" | tr -d ' ')" "750:640:0"
expect_eq "ssh_prepare: both group 10001 (the Hub)" "$(cut -d' ' -f1 "$WORK/sshp-own" | cut -d: -f2)" 10001

# Core's headscale leftovers are gone (V14: the template owns them).
expect_eq "keycloak.sh registers no headscale client" "$(grep -ciE 'headscale|headplane' "$HERE/../scripts/lib/keycloak.sh" || true)" 0
expect_eq "backup has no headscale-config.yaml" "$(grep -c 'headscale' "$HERE/../scripts/lib/backup.sh" || true)" 0
expect_eq "no headscale/ directory, nothing in the apps file" "$( [ -e "$HERE/../headscale" ] && echo dir || echo none):$(grep -ciE 'headscale|headplane' "$HERE/../docker-compose.apps.yml" || true)" "none:0"

# ══ kubernetes runtime (scripts/lib/kube.sh) ══════════════
# A kubectl stub with canned answers ($STUB_DIR/kube/*); every argv logged.
KS="$WORK/kstub"; mkdir -p "$KS/bin" "$KS/kube"
cat > "$KS/bin/kubectl" <<'KSTUB'
#!/usr/bin/env bash
# kubectl stub: canned answers from $STUB_DIR/kube/, every argv logged.
K="$STUB_DIR/kube"
printf '%s\n' "$*" >> "$STUB_DIR/kubectl-calls"
args=("$@")
if [ "${1:-}" = config ]; then
  [ "$2 $3 $4" = "get-contexts -o name" ] && { cat "$K/contexts" 2>/dev/null; exit 0; }
  exit 1
fi
[ "${1:-}" = --context ] || { echo "stub: no --context" >&2; exit 97; }
shift 2
ns=""
if [ "${1:-}" = -n ]; then ns="$2"; shift 2; fi
case "$*" in
  "version -o json") cat "$K/version.json" ;;
  "auth whoami -o json") [ -z "${STUB_WHOAMI_FAIL:-}" ] || exit 1; echo '{"status":{"userInfo":{"username":"system:admin"}}}' ;;
  "get nodes -o json") cat "$K/nodes.json" ;;
  "create --dry-run=server -f -") cat >/dev/null; cat "$K/svc-dryrun.err" >&2; exit 1 ;;
  "get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o json") cat "$K/eps.json" ;;
  "get --raw /api/v1/nodes/"*"/proxy/configz") n="$*"; n="${n#*nodes/}"; n="${n%%/*}"; cat "$K/configz-$n.json" 2>/dev/null || cat "$K/configz.json" 2>/dev/null || exit 1 ;;
  "get services -A -o json") [ ! -e "$K/svcs.fail" ] || { echo 'Error from server (Forbidden)' >&2; exit 1; }; cat "$K/svcs.json" 2>/dev/null || echo '{"items":[]}' ;;
  "get service traefik -o json") cat "$K/traefik-svc.json" 2>/dev/null || { echo 'Error from server (NotFound)' >&2; exit 1; } ;;
  "get namespace "*" -o json")
    n="${3}"; [ -f "$K/ns-$n.json" ] && { cat "$K/ns-$n.json"; exit 0; }
    echo "Error from server (NotFound): namespaces \"$n\" not found" >&2; exit 1 ;;
  "get namespace "*)
    n="${3}"; [ -f "$K/ns-$n.json" ] && exit 0
    echo "Error from server (NotFound): namespaces \"$n\" not found" >&2; exit 1 ;;
  "apply --server-side"*" -f -") cat >> "$STUB_DIR/kubectl-stdin"; echo --- >> "$STUB_DIR/kubectl-stdin"; [ -z "${STUB_APPLY_FAIL:-}" ] || exit 1 ;;
  "apply --server-side"*" -f "*)
    all="$*"; f="${all##* -f }"
    [ -z "${STUB_APPLY_FAIL_MATCH:-}" ] || case "$f" in *"$STUB_APPLY_FAIL_MATCH"*) echo "stub: apply of $f refused" >&2; exit 1 ;; esac
    [ -z "${STUB_APPLY_FAIL:-}" ] || exit 1
    case "$f" in *bindings.json)
      [ -z "${STUB_BINDINGS_FAIL:-}" ] || { echo "stub: bindings refused" >&2; exit 1; }
      mkdir -p "$STUB_DIR/live"
      for b in $(jq -r '.items[].metadata.name' "$f"); do
        jq --arg b "$b" '.items[] | select(.metadata.name == $b)' "$f" > "$STUB_DIR/live/Binding.$b.json"
      done
      printf 'apply bindings %s\n' "$(jq -r '.items[0].metadata.labels["portcullis.io/params-generation"]' "$f")" >> "$STUB_DIR/order" ;;
    esac ;;
  "create secret generic "*" --dry-run=client -o json"|"create configmap "*" --dry-run=client -o json")
    # The object as kubectl builds it: Secret data base64, ConfigMap data text.
    if [ "$2" = secret ]; then kind=Secret n="$4"; else kind=ConfigMap n="$3"; fi
    printf 'create %s %s\n' "$kind" "$n" >> "$STUB_DIR/order"
    all="$*"; d="${all##*--from-file=}"; d="${d%% *}"
    data='{}'
    for f in "$d"/*; do
      [ -f "$f" ] || continue
      if [ "$kind" = Secret ]; then v="$(base64 < "$f" | tr -d '\n')"; else v="$(cat "$f")"; fi
      data="$(printf '%s' "$data" | FK="${f##*/}" FV="$v" jq -c '.[env.FK] = env.FV')"
    done
    printf '%s' "$data" | KIND="$kind" N="$n" jq '{apiVersion: "v1", kind: env.KIND, metadata: {name: env.N, namespace: "portcullis"}, data: .}' ;;
  "get -f "*" -o name")
    lk="$(jq -r .kind "$3").$(jq -r .metadata.name "$3")"
    [ -e "$STUB_DIR/live/$lk.json" ] || { echo "Error from server (NotFound)" >&2; exit 1; }
    echo "$lk" ;;
  "replace --field-manager="*" -f "*|"create --field-manager="*" -f "*)
    all="$*"; f="${all##* -f }"
    lk="$(jq -r .kind "$f").$(jq -r .metadata.name "$f")"
    printf 'put %s %s\n' "$1" "$lk" >> "$STUB_DIR/order"
    cat "$f" >> "$STUB_DIR/kubectl-stdin"; echo --- >> "$STUB_DIR/kubectl-stdin"
    [ -z "${STUB_APPLY_FAIL:-}" ] || exit 1
    mkdir -p "$STUB_DIR/live"; cp "$f" "$STUB_DIR/live/$lk.json" ;;
  "create -f "*"bindings.yaml --dry-run=client -o json")
    python3 -c 'import json, sys, yaml; [print(json.dumps(d)) for d in yaml.safe_load_all(open(sys.argv[1])) if d]' "$3" ;;
  "get validatingadmissionpolicybinding -l portcullis.io/binding,portcullis.io/params-generation!="*" -o name")
    g="${4##*!=}"
    for b in "$STUB_DIR"/live/Binding.*.json; do [ -e "$b" ] || continue
      [ "$(jq -r '.metadata.labels["portcullis.io/params-generation"]' "$b")" = "$g" ] || echo "validatingadmissionpolicybinding.admissionregistration.k8s.io/$(jq -r .metadata.name "$b")"
    done ;;
  "get validatingadmissionpolicybinding -l portcullis.io/binding -o json")
    set -- "$STUB_DIR"/live/Binding.*.json
    if [ -e "$1" ]; then jq -s '{items: .}' "$@"; else echo '{"items":[]}'; fi ;;
  "delete validatingadmissionpolicybinding"*)
    for a in "$@"; do case "$a" in validatingadmissionpolicybinding.*/*) rm -f "$STUB_DIR/live/Binding.${a##*/}.json"; printf 'delete binding %s\n' "${a##*/}" >> "$STUB_DIR/order" ;; esac; done ;;
  "get configmap -l app.kubernetes.io/managed-by=portcullis,portcullis.io/params-generation,portcullis.io/params-generation!="*" -o json")
    g="${4##*!=}"; out='[]'
    for c in "$STUB_DIR"/live/ConfigMap.portcullis-admission-params-*.json; do [ -e "$c" ] || continue
      [ "$(jq -r '.metadata.labels["portcullis.io/params-generation"]' "$c")" = "$g" ] || out="$(jq -c --slurpfile c "$c" '. + $c' <<< "$out")"
    done; jq '{items: .}' <<< "$out" ;;
  "annotate configmap "*) c="$STUB_DIR/live/ConfigMap.$3.json"; v="${4#*=}"; jq --arg v "$v" '.metadata.annotations["portcullis.io/orphaned-at"] = $v' "$c" > "$c.t" && mv "$c.t" "$c"; printf 'stamp %s\n' "$3" >> "$STUB_DIR/order" ;;
  "delete configmap portcullis-admission-params-"*) rm -f "$STUB_DIR/live/ConfigMap.$3.json"; printf 'delete params %s\n' "$3" >> "$STUB_DIR/order" ;;
  "get ingressroutes.traefik.io -l portcullis.io/owner=hub -o json") cat "$K/edge-hub-ir.json" 2>/dev/null || echo '{"items":[]}' ;;
  "get middlewares.traefik.io -l portcullis.io/owner=hub -o json") echo '{"items":[]}' ;;
  "--as=system:serviceaccount:portcullis:portcullis-hub --as-group=system:masters replace --dry-run=server -f -")
    in="$(cat)"; case "$in" in *REFUSE-ME*) echo "ValidatingAdmissionPolicy 'portcullis-edge-routes' with binding 'portcullis-edge-guard-routes-x' denied request: a route on a reserved core hostname" >&2; exit 1 ;; esac ;;
  "delete ingressroutes.traefik.io "*) printf 'delete ir %s\n' "$3" >> "$STUB_DIR/order" ;;
  "--as=system:serviceaccount:portcullis:portcullis-hub --as-group=system:masters create --dry-run=server -f -")
    in="$(cat)"
    g="$(printf '%s' "$in" | jq -r '.metadata.annotations["portcullis.io/params-generation"] // ""')"
    k="$(printf '%s' "$in" | jq -r .kind)"
    case "$k:$ns" in
      Pod:portcullis-ingress) b=portcullis-ingress-guard-pods ;;
      Pod:*) b=portcullis-apps-guard-pods ;; Deployment:*) b=portcullis-apps-guard-workloads ;; Service:*) b=portcullis-apps-guard-services ;;
      NetworkPolicy:*) b=portcullis-apps-guard-netpol ;; IngressRoute:"${STUB_APPS_NS:-portcullis-apps}") b=portcullis-apps-guard-traefik ;; *) b=portcullis-edge-guard-routes ;;
    esac
    printf 'probe %s\n' "${g:+$b}" >> "$STUB_DIR/order"
    if [ -n "$g" ]; then
      if [ -z "${STUB_PROBE_STALE:-}" ] && [ "${STUB_PROBE_STALE_BINDING:-}" != "$b" ] && [ -e "$STUB_DIR/live/Binding.$b-$g.json" ] && [ -e "$STUB_DIR/live/ConfigMap.portcullis-admission-params-$g.json" ]; then
        echo "ValidatingAdmissionPolicy 'x' with binding '$b-$g' denied request: admission probe: params generation $g in effect" >&2
      else echo "denied request: failed to configure binding: no params found" >&2; fi
      exit 1
    fi
    case "$in" in *'Host(`portcullis-admission-probe.'*) exit 0 ;; esac
    echo "ValidatingAdmissionPolicy 'portcullis-edge-routes' with binding 'portcullis-edge-guard-routes-x' denied request: a route on a reserved core hostname" >&2; exit 1 ;;
  "--as=system:serviceaccount:portcullis-nodeadm:nodeadm --as-group=system:masters create --dry-run=server -f -"|"--as=system:serviceaccount:portcullis:portcullis-hub --as-group=system:masters create --raw "*|"--as=system:node:portcullis-admission-probe --as-group=system:nodes --as-group=system:authenticated create --dry-run=server -f -")
    # HA probes: nodeadm's Secret (a dry run), a node's Node, the Hub's exec.
    if [ "$4" = --raw ]; then
      b=portcullis-core-guard-exec g="${5##*command=probe-}"; g="${g%%&*}"
      [ "$6 $7" = "-f -" ] || { echo "stub: exec probe without -f -" >&2; exit 97; }
    else
      in="$(cat)"; g="$(printf '%s' "$in" | jq -r '.metadata.annotations["portcullis.io/params-generation"] // ""')"
      case "$(printf '%s' "$in" | jq -r .kind):$ns" in
        Secret:kube-system) b=portcullis-nodeadm-guard-tokens ;; Node:) b=portcullis-nodes-guard-labels ;; *) echo "stub: nodeadm probe $ns" >&2; exit 97 ;;
      esac
    fi
    printf 'probe %s\n' "$b" >> "$STUB_DIR/order"
    if [ -z "${STUB_PROBE_STALE:-}" ] && [ "${STUB_PROBE_STALE_BINDING:-}" != "$b" ] && [ -e "$STUB_DIR/live/Binding.$b-$g.json" ] && [ -e "$STUB_DIR/live/ConfigMap.portcullis-admission-params-$g.json" ]; then
      echo "ValidatingAdmissionPolicy 'x' with binding '$b-$g' denied request: admission probe: params generation $g in effect" >&2
    else echo "denied request: failed to configure binding: no params found" >&2; fi
    exit 1 ;;
  "get secrets -o json"|"get configmaps -o json")
    case "$ns" in
      portcullis)
        [ -z "${STUB_LIVE_LIST_FAIL:-}" ] || { echo "Error from server (Forbidden)" >&2; exit 1; }
        lk=Secret; [ "$2" = configmaps ] && lk=ConfigMap
        set -- "$STUB_DIR"/live/"$lk".*.json
        if [ -e "$1" ]; then jq -s '{items: .}' "$@"; else echo '{"items":[]}'; fi ;;
      portcullis-edge) cat "$K/edge-secrets.json" 2>/dev/null || echo '{"items":[]}' ;;
      *) cat "$K/apps-secrets.json" 2>/dev/null || echo '{"items":[]}' ;;
    esac ;;
  "create secret generic "*" --dry-run=client -o yaml"|"create configmap "*" --dry-run=client -o yaml")
    if [ "$2" = secret ]; then kn="secret $4"; else kn="configmap $3"; fi
    printf 'create %s\n' "$kn" >> "$STUB_DIR/order"
    all="$*"; d="${all##*--from-file=}"; d="${d%% *}"
    printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\ndata:\n' "${kn#* }"
    for f in "$d"/*; do printf '  %s: %s\n' "${f##*/}" "$(head -c 200 "$f" | head -n1)"; done ;;
  "apply -f -") cat >> "$STUB_DIR/kubectl-stdin"; [ -z "${STUB_APPLY_FAIL:-}" ] || exit 1 ;;
  "apply -f "*) [ -z "${STUB_APPLY_FAIL:-}" ] || exit 1 ;;
  "exec client-allowed -- nc"*) exit "${STUB_DIAL_ALLOWED:-0}" ;;
  "exec -i deploy/wg -c wg -- /wg keypair") printf '{"private_key":"%s","public_key":"%s"}\n' "${STUB_WG_PRIV:-cHJpdg==}" "${STUB_WG_PUB:-cHVi}" ;;
  "get pods -l portcullis.io/component=hub -o json"|"get pods -l portcullis.io/component=wg -o json") echo '{"items":[{"status":{"phase":"Running","containerStatuses":[{"ready":true,"started":true}]},"spec":{"containers":[{"readinessProbe":{}}]}}]}' ;;
  # _rtk_health / _rtk_wait_ready: every Deployment rolled out, its pod Running.
  "get deploy "*" -o json") echo '{"metadata":{"generation":1},"spec":{"replicas":1},"status":{"observedGeneration":1,"replicas":1,"updatedReplicas":1}}' ;;
  "get pods -l portcullis.io/component="*" -o json") echo '{"items":[{"status":{"phase":"Running","containerStatuses":[{"ready":true,"started":true}]},"spec":{"containers":[{"readinessProbe":{}}]}}]}' ;;
  "get pods -o json") cat "$K/pods.json" 2>/dev/null || echo '{"items":[]}' ;;
  "get events --field-selector "*) echo '{"items":[{"reason":"BackOff","message":"Back-off restarting failed container"}]}' ;;
  "get deployments -l portcullis.io/person-secrets -o json")
    [ -z "${STUB_PS_LIST_FAIL:-}" ] || exit 1
    if [ -n "${STUB_PS_NONE:-}" ]; then echo '{"items":[]}'; else echo '{"items":[{"metadata":{"labels":{"portcullis.io/instance":"samba"}}}]}'; fi ;;
  "create -f -") cat >> "$STUB_DIR/kubectl-stdin"; echo --- >> "$STUB_DIR/kubectl-stdin"; printf 'create pod\n' >> "$STUB_DIR/order" ;;
  "wait --for=jsonpath={.status.phase}=Succeeded pod/"*) printf 'wait %s\n' "$3" >> "$STUB_DIR/order"; exit "${STUB_WAIT_RC:-0}" ;;
  "wait --for=condition=Ready pod/keygen-"*) printf 'wait %s\n' "$3" >> "$STUB_DIR/order"; exit "${STUB_WAIT_RC:-0}" ;;
  "logs pod/keygen-"*) printf 'logs\n' >> "$STUB_DIR/order"; printf '# public key: age1kube\nAGE-SECRET-KEY-1KUBEQQQQ\n' ;;
  "exec keygen-"*" -c keygen -- sh -c "*"cat /k/key") printf 'exec cat\n' >> "$STUB_DIR/order"; printf '# public key: age1kube\nAGE-SECRET-KEY-1KUBEQQQQ\n' ;;
  "get pod keygen-"*" -o json") echo '{"status":{"phase":"Pending","containerStatuses":[{"name":"keygen","state":{"waiting":{"reason":"ErrImagePull","message":"failed to pull localhost/portcullis-domains@sha256:abc"}}}],"conditions":[{"type":"Ready","status":"False","reason":"ContainersNotReady"}]}}' ;;
  "scale "*|"patch "*|"annotate "*|"rollout "*|"wait "*) printf 'kubectl %s %s\n' "$ns" "$*" >> "$STUB_DIR/order" ;;
  "run "*) printf 'kubectl run\n' >> "$STUB_DIR/order"; cat >/dev/null; exit "${STUB_RUN_RC:-0}" ;;
  "create --dry-run=client -o json -f -") cat >/dev/null; printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"oneshot"},"spec":{"containers":[{"name":"x","image":"ghcr.io/porelli/portcullis-hub@sha256:%064d","command":["/usr/local/bin/hub"]}]}}\n' 1 ;;
  "exec client-ingress -- nc"*) exit "${STUB_DIAL_INGRESS:-1}" ;;
  "exec client-egress -- nc"*) exit "${STUB_DIAL_EGRESS:-1}" ;;
  "get pod server -o jsonpath={.status.podIP}") echo 10.42.0.9 ;;
  "get configmap portcullis-cluster-addresses -o json") cat "$K/cluster-addresses.json" 2>/dev/null || { echo 'Error from server (NotFound): configmaps "portcullis-cluster-addresses" not found' >&2; exit 1; } ;;
  "get configmap portcullis-admission-active -o json") cat "$K/active.json" 2>/dev/null || { echo 'Error from server (NotFound)' >&2; exit 1; } ;;
  "get configmap portcullis-admission-params-"*" -o json") g="${3#portcullis-admission-params-}"; cat "$K/params-$g.json" 2>/dev/null || { echo 'Error from server (NotFound)' >&2; exit 1; } ;;
  "get configmap portcullis-admission-params-"*" -o name") g="${3#portcullis-admission-params-}"; [ -e "$K/params-$g.json" ] && echo "configmap/$3" || { echo 'Error from server (NotFound)' >&2; exit 1; } ;;
  "get validatingadmissionpolicybinding -l portcullis.io/params-generation="*" -o json") g="${4#*=}"; cat "$K/bindings-$g.json" 2>/dev/null || echo '{"items":[]}' ;;
  # CNPG (Task 23): the live Cluster (NotFound unless a fixture) and the
  # labelled nodes at main (review I1).
  "get cluster.postgresql.cnpg.io portcullis-pg -o json")
    [ ! -e "$K/pg-cluster.fail" ] || { echo 'Error from server (Forbidden)' >&2; exit 1; }
    cat "$K/pg-cluster.json" 2>/dev/null || { echo 'Error from server (NotFound): clusters.postgresql.cnpg.io "portcullis-pg" not found' >&2; exit 1; } ;;
  "get nodes -l node-role.kubernetes.io/control-plane -o json") [ ! -e "$K/cp-nodes.fail" ] || exit 1; echo '{"items":[{"spec":{"podCIDR":"10.42.0.0/24"}}]}' ;;
  "get nodes -l portcullis.io/site=main,portcullis.io/class in (home,cloud) -o json")
    [ ! -e "$K/pg-nodes.fail" ] || exit 1; cat "$K/pg-nodes.json" 2>/dev/null || echo '{"items":[]}' ;;
  *) [ -n "${STUB_KUBE_SCRIPT:-}" ] && . "$STUB_KUBE_SCRIPT" ;;
esac
exit 0
KSTUB
cat > "$KS/bin/helm" <<'HSTUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_DIR/helm-calls"
printf 'helm %s\n' "$*" >> "$STUB_DIR/order"
case "$*" in
  *" template "*"--show-only templates/oneshot.yaml"*) printf 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: oneshot\nspec:\n  containers:\n    - name: x\n      image: ghcr.io/porelli/portcullis-hub@sha256:%064d\n      command: ["/usr/local/bin/hub"]\n' 1 ;;
  *" upgrade --install portcullis "*) [ -z "${STUB_HELM_FAIL:-}" ] || { echo "Error: context deadline exceeded" >&2; exit 1; } ;;
esac
exit 0
HSTUB
chmod +x "$KS/bin/kubectl" "$KS/bin/helm"
k_fixtures() {
  rm -rf "$KS/kube" "$KS/kubectl-calls" "$KS/kubectl-stdin" "$KS/live"; mkdir -p "$KS/kube"
  printf 'ci\nother\n' > "$KS/kube/contexts"
  echo '{"serverVersion":{"gitVersion":"v1.37.2+k3s1"}}' > "$KS/kube/version.json"
  cat > "$KS/kube/nodes.json" <<'J'
{"items":[{"metadata":{"name":"node1","labels":{"node-role.kubernetes.io/control-plane":"true"},"annotations":{"k3s.io/node-args":"[\"server\",\"--disable\",\"traefik\",\"--secrets-encryption\",\"--kubelet-arg\",\"pod-max-pids=1024\",\"--node-external-ip\",\"198.51.100.1\",\"--cluster-cidr\",\"10.42.0.0/24\"]"}},
  "spec":{"podCIDR":"10.42.0.0/24","podCIDRs":["10.42.0.0/24"]},
  "status":{"addresses":[{"type":"InternalIP","address":"10.1.0.4"},{"type":"ExternalIP","address":"198.51.100.1"}]}}]}
J
  echo 'The Service "portcullis-cidr-probe" is invalid: spec.clusterIPs: Invalid value: []string{"0.0.0.1"}: failed to allocate IP 0.0.0.1: the provided IP (0.0.0.1) is not in the valid range. The range of valid IPs is 10.43.0.0/16' > "$KS/kube/svc-dryrun.err"
  echo '{"items":[{"ports":[{"port":6443}],"endpoints":[{"addresses":["10.1.0.4"]}]}]}' > "$KS/kube/eps.json"
  echo '{"kubeletconfig":{"podPidsLimit":1024}}' > "$KS/kube/configz.json"
}
# kt <code> — run code with the libs, CONTAINER_RUNTIME=kubernetes and the stub.
kt() {
  ( export STUB_DIR="$KS" PATH="$KS/bin:$PATH" CONTAINER_RUNTIME=kubernetes PORTCULLIS_KUBE_CONTEXT=ci \
      PORTCULLIS_POD_CIDR=10.42.0.0/24 PORTCULLIS_SERVICE_CIDR=10.43.0.0/16 PORTCULLIS_KUBE_API_ENDPOINTS=10.1.0.4:6443 \
      PORTCULLIS_KUBE_INSTALL_ID=0b0e2b3c-1111-4222-8333-444455556666 KUBE_LOCAL_ADDRS="10.1.0.4 198.51.100.1" \
      PORTCULLIS_PUBLIC_IPV4=198.51.100.1 KUBE_TCP_PROBE=false PORTCULLIS_DOMAIN=k.example.org
    unset _RT_CHECKED _RT_HOST_OK
    ( eval "$1" ); echo "rc=$?" ) 2>&1
}

# The Vault raft snapshot on Kubernetes (plan Task 25, Amendment 2): from
# the voter whose own Vault says is_self (asked in each pod; no label
# decides), through a port-forward to that pod, retried, the token never
# on argv.
VS="$WORK/vsnap"; rm -rf "$VS"; mkdir -p "$VS/bin"
cat > "$VS/bin/curl" <<'VCURL'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$VS_DIR/curl-args"
out="" url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift ;; http*) url="$1" ;; esac; shift; done
port="${url#http://127.0.0.1:}"; port="${port%%/*}"
case "$url" in
  */v1/sys/leader) cat "$VS_DIR/leader-$port" 2>/dev/null || echo '{}' ;;
  */v1/sys/storage/raft/snapshot) echo "$port" >> "$VS_DIR/snap-ports"; cp "$VS_SNAP" "$out"; printf 200 ;;
esac
VCURL
chmod +x "$VS/bin/curl"
# The kubectl stub's port-forward (the real _kube_with_forward runs it as its
# own child): pod/vault-<n> → local port 701<n>, then held open.
cat > "$VS/pf.sh" <<'VPF'
case "$*" in
  "port-forward --address 127.0.0.1 pod/vault-"[0-9]" :8200")
    a="$*"; t="${a#*pod/vault-}"; echo "pod/vault-${t%% *}" >> "$VS_DIR/fwd"; echo "Forwarding from 127.0.0.1:701${t%% *} -> 8200"; exec sleep 47 ;;
esac
VPF
vsnap() { # vsnap <vault-0's status json> <vault-1's> <vault-2's> [extra code]
  rm -f "$VS"/leader-* "$VS/fwd" "$VS/snap-ports" "$VS/curl-args" "$VS/out.snap" "$VS"/st-*
  printf '%s' "$1" > "$VS/st-vault-0"; printf '%s' "$2" > "$VS/st-vault-1"; printf '%s' "$3" > "$VS/st-vault-2"
  for i in 0 1 2; do cp "$VS/st-vault-$i" "$VS/leader-701$i"; done
  kt "export VS_DIR='$VS' VS_SNAP='$WORK/good.snap' PATH='$VS/bin':\$PATH VAULT_TOKEN=s.vsnap-token-1234 KUBE_VAULT_SNAPSHOT_TRIES=2 KUBE_VAULT_SNAPSHOT_WAIT=0
    kube_vault_voters() { printf 'vault-0\nvault-1\nvault-2\n'; }
    export STUB_KUBE_SCRIPT='$VS/pf.sh'
    kube_ctl() { case \"\$*\" in *' exec vault-'[0-9]' -c vault -- vault status -format=json') a=\"\$*\"; p=\"\${a#* exec }\"; cat \"$VS/st-\${p%% *}\" ;; *) return 1 ;; esac; }
    ${4:-}
    _backup_vault_snapshot '$VS/out.snap'"
}
L='{"ha_enabled":true,"is_self":true}' S='{"ha_enabled":true,"is_self":false}'
OUT="$(vsnap "$S" "$L" "$S")"
expect_eq "backup: vault snapshot taken through the leader (the voter that says is_self, by its own pod)" \
  "$(printf '%s' "$OUT" | tail -n1):$(paste -sd, "$VS/fwd"):$(paste -sd, "$VS/snap-ports"):$(cmp -s "$VS/out.snap" "$WORK/good.snap" && echo same)" "rc=0:pod/vault-1:7011:same"
expect_eq "backup: the Vault token never on curl's argv" "$(grep -c 's.vsnap-token-1234' "$VS/curl-args")" 0
OUT="$(vsnap "$L" "$S" "$S" "printf '%s' '$S' > '$VS/leader-7010'")"
case "$OUT" in *"no Vault leader answers"*"rc=1") t_pass "backup: the leader's own API no longer says is_self (it stepped down) → no snapshot from it" ;; *) t_fail "vault snapshot stepped-down leader: $OUT" ;; esac
OUT="$(vsnap "$S" "$S" '')"
case "$OUT" in *"no leader answered in 2 tries"*"rc=1") t_pass "backup: no Vault leader anywhere (one voter unreachable) → refused after the tries, nothing written" ;; *) t_fail "vault snapshot without a leader: $OUT" ;; esac
[ ! -s "$VS/snap-ports" ] && t_pass "backup: no snapshot asked of a voter that isn't the leader" || t_fail "a snapshot was taken from a non-leader: $(cat "$VS/snap-ports")"
# Security review: no forward record on disk to plant. Planted records
# (symlinks, a file naming another process) in TMPDIR are never followed,
# written or acted on; the forwards end (no kubectl left running).
sleep 300 & VICTIM=$!
printf 'keep' > "$VS/planted-target"
for pfx in "${TMPDIR:-/tmp}/.portcullis-fwd-" "$VS/.portcullis-fwd-"; do
  ln -sf "$VS/planted-target" "${pfx}1-7011"; printf '7011' > "${pfx}$$-$VICTIM"
done
sleep 1; touch "$VS/planted-at"
OUT="$(TMPDIR="$VS" vsnap "$S" "$L" "$S")"
expect_eq "backup: a planted forward record / symlink neither kills its process nor gets written; no record made" \
  "$(printf '%s' "$OUT" | tail -n1):$(kill -0 "$VICTIM" 2>/dev/null && echo alive):$(cat "$VS/planted-target"):$(find "$VS" -maxdepth 1 -name '.portcullis-fwd-*' -newer "$VS/planted-at" | wc -l | tr -d ' ')" "rc=0:alive:keep:0"
kill "$VICTIM" 2>/dev/null; rm -f "${TMPDIR:-/tmp}"/.portcullis-fwd-1-7011 "${TMPDIR:-/tmp}/.portcullis-fwd-$$-$VICTIM" "$VS"/.portcullis-fwd-*
expect_eq "backup: the snapshot's port-forwards end with it (no stub kubectl left running)" "$(pgrep -fx 'sleep 47' | grep -c . || true)" 0
OUT="$(kt "kube_ctl() { case \"\$*\" in *' exec vault-1 '*) echo '{\"ha_enabled\":true,\"is_self\":true}' ;; *' get statefulset vault '*) echo 3 ;; *) return 1 ;; esac; }; kube_vault_pod_set; kube_ctl() { return 1; }; kube_vault_pod; echo \"cached=\$_K_VAULT_POD\"")"
expect_eq "kube_vault_pod: the leader (asked once, kept for the run)" "$(printf '%s\n' "$OUT" | head -n2 | tr '\n' ' ')" "vault-1 cached=vault-1 "
t0="$(date +%s)"; OUT="$(kt "_kube_bounded 1 sh -c 'sleep 30; echo late' | cat; echo after")"
expect_eq "_kube_bounded: a hung command (and its child holding the pipe) is cut at the bound" "$(printf '%s\n' "$OUT" | head -n1):$(( $(date +%s) - t0 < 10 ))" "after:1"
t0="$(date +%s)"; OUT="$(kt "_kube_bounded 20 echo quick | cat")"
expect_eq "_kube_bounded: a quick command returns at once (the watchdog holds no pipe)" "$(printf '%s\n' "$OUT" | head -n1):$(( $(date +%s) - t0 < 10 ))" "quick:1"
# Fewer voters (HA off, review M3, re-review I-a / M-a): through vault-0;
# the unhealthy dropped peers first, a quorum after every step (else refused
# before any removal, naming the down voter); the record before the first
# removal, finished (wiped + deleted) after the chart; HA on refused while
# it is there.
VSH="$WORK/vshrink"; rm -rf "$VSH"; mkdir -p "$VSH"
# vstate <map json> — autopilot's state: true = healthy, 3.2 ms since the
# leader's last contact; false = unhealthy, 14.5 s; an object as given.
vstate() {
  printf '%s' "${1:-{\"vault-0\":true,\"vault-1\":true,\"vault-2\":true\}}" | jq -c '{data: {servers: (to_entries | map({key, value: (.value
    | if type == "boolean" then {healthy: ., status: "voter", last_contact: (if . then "3.2ms" else "14.5s" end)} else . end)}) | from_entries)}}'
}
vshrink() { # vshrink <live replicas> <healthy map json> <extra code> [want: HA on = 3]
  rm -f "$VSH"/calls "$VSH"/peers "$VSH"/state "$VSH"/k "$VSH"/*.fail; printf 'vault-0\nvault-1\nvault-2\n' > "$VSH/peers"
  vstate "${2:-}" > "$VSH/state"; rm -f "$VSH/state.next"
  kt "export VAULT_TOKEN=s.shrink-tok KUBE_VAULT_REMOVE_WAIT=0 KUBE_VAULT_PROVE_WAIT=${VPROVE:-7} ${4:+PORTCULLIS_HA=on}
    _kube_vault_age() { echo ${VAGE:-9}; }
    kube_ctl() { echo \"\$*\" >> '$VSH/k'; case \"\$*\" in
      *'get statefulset vault -o jsonpath={.spec.replicas}') echo $1 ;;
      *'get configmap portcullis-vault-shrink -o json') [ -e '$VSH/rec' ] && jq -n --rawfile d '$VSH/rec' '{data: {dropped: \$d}}' || { echo 'Error from server (NotFound)'; return 1; } ;;
      *'apply -f -') jq -j 'select(.kind == \"ConfigMap\" and .metadata.name == \"portcullis-vault-shrink\" and .metadata.namespace == \"portcullis\") | .data.dropped' > '$VSH/rec.new'; [ -s '$VSH/rec.new' ] && mv '$VSH/rec.new' '$VSH/rec' || rm -f '$VSH/rec.new' ;;
      *'delete configmap portcullis-vault-shrink'*) rm -f '$VSH/rec' ;;
      *) return 1 ;; esac; }
    vexec() { echo \"\$* @\${_K_VAULT_POD:-}\" >> '$VSH/calls'; case \"\$1 \$2 \$3\" in
      'operator raft list-peers') [ ! -e '$VSH/list.fail' ] || return 1; jq -Rn '{data: {config: {servers: [inputs | {node_id: .}]}}}' < '$VSH/peers' ;;
      'read -format=json sys/storage/raft/autopilot/state') cat '$VSH/state' ;;
      'operator raft remove-peer') [ ! -e '$VSH/remove.fail' ] || return 1; grep -vx \"\$4\" '$VSH/peers' > '$VSH/p.tmp'; mv '$VSH/p.tmp' '$VSH/peers'; [ ! -e '$VSH/state.next' ] || mv '$VSH/state.next' '$VSH/state' ;;
    esac; }
    ${3:-}
    kube_vault_shrink_prepare; echo \"shrink=\$_KUBE_VAULT_SHRINK\""
}
removals() { grep -o 'remove-peer vault-[0-9] @vault-0' "$VSH/calls" 2>/dev/null | sed 's/remove-peer //; s/ @vault-0//' | paste -sd, -; }
rm -f "$VSH/rec"; OUT="$(vshrink 3)"
expect_eq "vault voters 3 → 1 (HA off), all healthy: vault-2 then vault-1 removed through vault-0, the peers then exactly vault-0, the record written first" \
  "$(printf '%s\n' "$OUT" | grep '^shrink='):$(removals):$(paste -sd, "$VSH/peers"):$(cat "$VSH/rec")" "shrink= vault-2 vault-1:vault-2,vault-1:vault-0:vault-2 vault-1"
rm -f "$VSH/rec"; OUT="$(vshrink 3 '{"vault-0":true,"vault-1":false,"vault-2":true}')"
expect_eq "vault voters 3 → 1 with vault-1 down (re-review I-a): the unhealthy vault-1 removed first, so {vault-0, vault-2} keeps its quorum" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(removals)" "rc=0:vault-1,vault-2"
rm -f "$VSH/rec"; OUT="$(vshrink 3 '{"vault-0":{"healthy":true,"status":"leader","last_contact":"0s"},"vault-1":{"healthy":true,"status":"voter","last_contact":"7.5s"},"vault-2":{"healthy":true,"status":"voter","last_contact":"850µs"}}')"
expect_eq "vault voters 3 → 1, vault-1 still healthy to autopilot but 7.5 s since its last echo (past the 5 s heartbeat + 2; re-review 2 M-2) → counted down, removed first; the leader's 0s and 850µs count as up" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(removals)" "rc=0:vault-1,vault-2"
rm -f "$VSH/rec"; OUT="$(VAGE=4 VPROVE=4 vshrink 3 '{"vault-0":{"healthy":true,"status":"leader","last_contact":"0s"},"vault-1":{"healthy":true,"status":"voter","last_contact":"2.5s"},"vault-2":{"healthy":true,"status":"voter","last_contact":"0.5s"}}')"
expect_eq "vault voters 3 → 1, vault-1 lost just before HA off (no echo since the round began 4 s ago, autopilot still healthy) → counted down, removed first; vault-2 echoed 0.5 s before the (≤ 2 s old) state, 4 s in → up" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(removals)" "rc=0:vault-1,vault-2"
rm -f "$VSH/rec"; OUT="$(VAGE=2 VPROVE=2 vshrink 3 '{"vault-0":{"healthy":true,"status":"leader","last_contact":"0s"},"vault-1":{"healthy":true,"status":"voter","last_contact":"0.5s"},"vault-2":{"healthy":true,"status":"voter","last_contact":"0.5s"}}')"
case "$OUT" in *"would leave no quorum after removing vault-2"*"rc=1") t_pass "vault voters 3 → 1, 2 s into the round a 0.5 s last contact is still unproven (autopilot's state may be 2 s old; re-review 3 M-3) → nobody counted up but the leader → refused before any removal" ;; *) t_fail "shrink cache margin: $OUT" ;; esac
rm -f "$VSH/rec"; OUT="$(vshrink 3 "" "printf 'vault-0\n' > '$VSH/peers'")"
expect_eq "vault voters 3 → 1, the raft peers already exactly vault-0 → nothing removed, but the record written and the dropped PVCs owed (re-review 3 N-f)" \
  "$(printf '%s\n' "$OUT" | grep '^shrink='):$(removals):$(cat "$VSH/rec")" "shrink= vault-2 vault-1::vault-2 vault-1"
rm -f "$VSH/rec"; OUT="$(vshrink 3 '{"vault-0":{"healthy":true,"status":"voter","last_contact":"1m2s"},"vault-1":{"healthy":true,"status":"leader","last_contact":"0s"},"vault-2":true}')"
case "$OUT" in *"would leave no quorum after removing vault-2 (down: vault-0), its failure tolerance below 0"*"rc=1") t_pass "vault voters 3 → 1, the kept vault-0 stale-healthy (1m2s since its last contact) → refused before any removal" ;; *) t_fail "shrink stale kept: $OUT" ;; esac
vstate '{"vault-0":{"healthy":true,"status":"voter","last_contact":"9s"},"vault-1":true}' > "$VSH/state.after"
rm -f "$VSH/rec"; OUT="$(vshrink 3 "" "cp '$VSH/state.after' '$VSH/state.next'")"
case "$OUT" in *"Vault's HA off stopped part way: removing vault-1 would leave no quorum (down: vault-0)"*"rc=1") t_pass "vault voters 3 → 1, vault-0 goes stale after the first removal → the fresh read refuses the second (Vault keeps its quorum)" ;; *) t_fail "shrink midway: $OUT" ;; esac
expect_eq "... vault-2 alone removed, the record kept for the next up" "$(removals):$(cat "$VSH/rec")" "vault-2:vault-2 vault-1"
rm -f "$VSH/rec"; OUT="$(vshrink 3 '{"vault-0":false,"vault-1":true,"vault-2":true}')"
case "$OUT" in *"would leave no quorum after removing vault-2 (down: vault-0)"*"rc=1") t_pass "vault voters 3 → 1 with the kept vault-0 down → refused before any removal, naming vault-0" ;; *) t_fail "shrink kept down: $OUT" ;; esac
expect_eq "... and nothing removed, nothing recorded" "$(removals):$(test -e "$VSH/rec" && echo rec || echo none)" ":none"
rm -f "$VSH/rec"; OUT="$(vshrink 1)"
expect_eq "vault voters unchanged, no record → no raft call" "$(printf '%s\n' "$OUT" | tail -n1):$(test -e "$VSH/calls" && echo calls || echo none)" "rc=0:none"
printf 'vault-2 vault-1' > "$VSH/rec"; OUT="$(vshrink 1)"
expect_eq "vault HA off interrupted after the chart (record left, voters already 1) → the next up owes the wipe (re-review M-a)" "$(printf '%s\n' "$OUT" | grep '^shrink=')" "shrink= vault-2 vault-1"
printf 'vault-2 vault-1' > "$VSH/rec"; OUT="$(vshrink 3 "" "" ha)"
case "$OUT" in *"Vault's HA off isn't finished: the volumes of vault-2 vault-1 are still to be wiped"*"rc=1") t_pass "vault HA off interrupted before the chart (3 replicas), then HA on → refused before helm (re-review 2 M-1)" ;; *) t_fail "shrink HA on cur 3 with record: $OUT" ;; esac
expect_eq "... no raft call" "$(test -e "$VSH/calls" && echo calls || echo none)" "none"
printf 'vault-2 vault-1' > "$VSH/rec"; OUT="$(vshrink 1 "" "" ha)"
case "$OUT" in *"Vault's HA off isn't finished: the volumes of vault-2 vault-1 are still to be wiped"*"rc=1") t_pass "vault HA on while an HA off still owes its wipe → refused" ;; *) t_fail "shrink HA on with record: $OUT" ;; esac
rm -f "$VSH/rec"; OUT="$(vshrink 3 "" "touch '$VSH/list.fail'")"
case "$OUT" in *"can't read Vault's raft peers: refusing"*"rc=1") t_pass "vault voters 3 → 1, the peers unreadable → refused, nothing deployed" ;; *) t_fail "shrink list fail: $OUT" ;; esac
rm -f "$VSH/rec"; OUT="$(vshrink 3 "" "touch '$VSH/remove.fail'")"
case "$OUT" in *"could not remove Vault's raft peer vault-2: refusing"*"rc=1") t_pass "vault voters 3 → 1, a removal fails → refused, the record kept for the next up" ;; *) t_fail "shrink remove fail: $OUT" ;; esac
rm -f "$VSH/rec"; OUT="$(vshrink 3 "" "printf 'vault-0\nvault-1\nstranger\n' > '$VSH/peers'")"
case "$OUT" in *"a peer stranger that isn't a voter of this chart"*"rc=1") t_pass "vault voters: a raft peer the chart doesn't know → refused, never removed blindly" ;; *) t_fail "shrink stranger: $OUT" ;; esac
rm -f "$VSH/k"; printf 'x' > "$VSH/rec"
OUT="$(kt "_KUBE_VAULT_SHRINK=' vault-2 vault-1'; kube_ctl() { echo \"\$*\" >> '$VSH/k'; case \"\$*\" in *' get pod vault-'*) echo 'Error from server (NotFound): pods \"x\" not found'; return 1 ;; *' get pvc data-vault-'*) echo pvc ;; esac; }; _kube_helper_pod() { echo \"helper-\$1\"; }; _kube_helper_done() { echo \"done \$1\" >> '$VSH/k'; }; kube_vault_shrink_finish")"
expect_eq "vault voters lowered: each removed voter's PVC emptied once its pod is gone, then the record deleted" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(grep -cE 'wait --for=delete pod/vault-[12]' "$VSH/k"):$(grep -cE 'exec helper-data-vault-[12] -- find /vol' "$VSH/k"):$(grep -c 'delete configmap portcullis-vault-shrink' "$VSH/k")" "rc=0:2:2:1"
OUT="$(kt "_KUBE_VAULT_SHRINK=' vault-1'; kube_ctl() { case \"\$*\" in *' get pod vault-1 '*) echo pod/vault-1 ;; esac; }; kube_vault_shrink_finish")"
case "$OUT" in *"the dropped voter vault-1 still runs"*"rc=1") t_pass "vault voters lowered, a dropped voter still running → its volume isn't touched, the record kept" ;; *) t_fail "shrink finish running: $OUT" ;; esac
rm -f "$VSH/k"
OUT="$(kt "_KUBE_VAULT_SHRINK=' vault-1'; kube_ctl() { echo \"\$*\" >> '$VSH/k'; case \"\$*\" in *' get pod vault-1 '*) echo 'Error from server (NotFound)'; return 1 ;; *' get pvc data-vault-1 '*) echo 'Unable to connect to the server: connection refused'; return 1 ;; esac; }; kube_vault_shrink_finish")"
case "$OUT" in *"can't read PVC data-vault-1: the removed voter's raft data is still to be wiped"*"rc=1") t_pass "vault voters lowered, the PVC unreadable (not NotFound) → refused, never counted as no PVC (re-review 2 N-a)" ;; *) t_fail "shrink finish pvc error: $OUT" ;; esac
expect_eq "... the record kept" "$(grep -c 'delete configmap' "$VSH/k")" "0"
OUT="$(kt "_KUBE_VAULT_SHRINK=' vault-1'; kube_ctl() { case \"\$*\" in *' get pod vault-1 '*) echo 'Unable to connect to the server'; return 1 ;; esac; }; kube_vault_shrink_finish")"
case "$OUT" in *"can't tell whether the dropped voter vault-1 still runs"*"rc=1") t_pass "vault voters lowered, the pod unreadable → refused, not counted as gone" ;; *) t_fail "shrink finish pod error: $OUT" ;; esac
# The join listener's TLS (review M1): a private CA here, one server
# certificate for every voter's name, the CA key never synced.
JT="$WORK/jtls"; rm -rf "$JT"; mkdir -p "$JT/secrets"
kt "PORTCULLIS_ROOT='$JT'; kube_vault_join_tls_prepare" >/dev/null
JD="$JT/secrets/vault-join-tls"
expect_eq "vault join TLS: 0700, the files 0600, the certificate verifies against the CA, serverAuth, every voter's name" \
  "$(file_mode "$JD"):$(file_mode "$JD/ca.key"):$(file_mode "$JD/tls.key"):$(openssl verify -CAfile "$JD/ca.crt" "$JD/tls.crt" 2>&1 | grep -c ': OK$'):$(openssl x509 -in "$JD/tls.crt" -noout -text | grep -c 'TLS Web Server Authentication'):$(openssl x509 -in "$JD/tls.crt" -noout -ext subjectAltName | grep -o 'vault-[0-9].vault-internal,' | sort -u | wc -l | tr -d ' ')" "700:600:600:1:1:3"
SUM="$(cat "$JD"/*.crt | openssl dgst -sha256 -r)"
kt "PORTCULLIS_ROOT='$JT'; kube_vault_join_tls_prepare" >/dev/null
expect_eq "vault join TLS: kept on the next run (not reissued)" "$(cat "$JD"/*.crt | openssl dgst -sha256 -r)" "$SUM"
expect_eq "vault join TLS: the CA key and the names file are never synced; the certificate and its key are" \
  "$(kt "_kube_sync_skip vault-join-tls/ca.key && echo skip; _kube_sync_skip vault-join-tls/sans && echo skip; _kube_sync_skip vault-join-tls/tls.key || echo sync" | grep -c -E '^(skip|sync)$')" 3
# Cluster DNS in HA (controller ruling 3, fix round 2): k3s's CoreDNS one
# per non-small node at main (never more: N-1), ours on the small nodes
# from kube/ha/coredns/small.yaml, PreferSameNode, a PDB; reverted with HA off.
CD="$WORK/coredns"; rm -rf "$CD"; mkdir -p "$CD"
cdns() { rm -f "$CD/k" "$CD/apply"; kt "kube_ctl() { echo \"\$*\" >> '$CD/k'; case \"\$*\" in *'get nodes -l portcullis.io/site=main,portcullis.io/class!=small -o json') printf '{\"items\":[%s]}' '$1' ;; *'get deployment coredns -o name') echo deployment.apps/coredns ;; *' patch '*) [ -z '${2:-}' ] || return 1 ;; esac; }; _ha_apply() { cat > '$CD/apply'; }; ha_coredns"; }
OUT="$(cdns '{},{},{}')"
P="$(grep 'patch deployment coredns' "$CD/k" | sed 's/.* -p //')"
expect_eq "HA CoreDNS: 3 non-small nodes at main → k3s's 3 replicas, required at main, one per node; PreferSameNode; our file applied" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(printf '%s' "$P" | jq -c '[.spec.replicas, .spec.template.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values, .spec.template.spec.affinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution[0].topologyKey, (.spec.template.spec | has("tolerations"))]'):$(grep -c 'patch service kube-dns --type=merge -p {"spec": {"trafficDistribution": "PreferSameNode"}}' "$CD/k"):$(cmp -s "$CD/apply" "$HERE/../kube/ha/coredns/small.yaml" && echo file)" \
  'rc=0:[3,["main"],"kubernetes.io/hostname",false]:1:file'
OUT="$(cdns '{}')"
expect_eq "HA CoreDNS: one non-small node at main → 1 replica (never one left Pending by the anti-affinity, re-review N-1)" "$(grep 'patch deployment coredns' "$CD/k" | sed 's/.* -p //' | jq -c .spec.replicas)" 1
OUT="$(cdns '{},{}' fail)"
case "$OUT" in *"could not spread CoreDNS"*"rc=1") t_pass "HA CoreDNS: a refused patch → refused (nothing deployed)" ;; *) t_fail "coredns patch fail: $OUT" ;; esac
OUT="$(kt "kube_ctl() { echo \"\$*\" >> '$CD/r'; case \"\$*\" in *'get service kube-dns -o jsonpath={.spec.trafficDistribution}') echo PreferSameNode ;; *'get daemonset portcullis-dns-small -o name') echo daemonset.apps/portcullis-dns-small ;; esac; }; ha_coredns_revert")"
expect_eq "HA off reverts the CoreDNS layout: k3s's 1 replica without affinity, no PreferSameNode, our DaemonSet and PDB gone (re-review N-3)" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(grep -c 'patch deployment coredns --type=merge -p {"spec": {"replicas": 1, "template": {"spec": {"affinity": null}}}}' "$CD/r"):$(grep -c '"trafficDistribution": null' "$CD/r"):$(grep -c 'delete daemonset portcullis-dns-small' "$CD/r"):$(grep -c 'delete poddisruptionbudget coredns' "$CD/r")" "rc=0:1:1:1:1"
rm -f "$CD/r"; OUT="$(kt "kube_ctl() { echo \"\$*\" >> '$CD/r'; }; ha_coredns_revert")"
expect_eq "HA off on a cluster that never had the layout → CoreDNS untouched" "$(grep -c 'patch\|delete' "$CD/r")" 0
OUT="$(kt "kube_ctl() { return 1; }; kube_vault_pod")"
expect_eq "kube_vault_pod: no leader (not initialised, or none answers) → vault-0" "$(printf '%s\n' "$OUT" | head -n1)" "vault-0"

# The cluster check's refresh (final review I4): `kube check`, the
# portcullis-kube-check.timer init installs (every 6 h), status at 20 / 24 h.
KCT="$WORK/kct"; rm -rf "$KCT"; mkdir -p "$KCT/bin"
printf '#!/bin/sh\n[ "$1 $2" = "cat k3s.service" ] && exit "${STUB_K3S_UNIT_RC:-0}"\nexit 0\n' > "$KCT/bin/systemctl"; chmod +x "$KCT/bin/systemctl"
OUT="$(kt "PATH='$KCT/bin':\$PATH; KUBECONFIG=/home/op/.kube/config; kube_check_timer_units '$KCT/u'; cat '$KCT/u/portcullis-kube-check.service' '$KCT/u/portcullis-kube-check.timer'")"
expect_eq "kube check timer: a oneshot as the operator after (and requiring) k3s.service, running kube check, with KUBECONFIG" \
  "$(printf '%s\n' "$OUT" | grep -cE '^(Type=oneshot|User=.+|After=network-online.target k3s.service|Requires=k3s.service|Environment=KUBECONFIG=/home/op/.kube/config|ExecStart=.*/portcullis kube check)$')" 6
expect_eq "kube check timer: every 6 h, persistent, timers.target" \
  "$(printf '%s\n' "$OUT" | grep -cE '^(OnCalendar=\*-\*-\* 00/6:00:00|Persistent=true|WantedBy=timers.target)$')" 3
OUT="$(kt "PATH='$KCT/bin':\$PATH; export STUB_K3S_UNIT_RC=1; unset KUBECONFIG; kube_check_timer_units '$KCT/v'; cat '$KCT/v/portcullis-kube-check.service'")"
expect_eq "kube check timer: no k3s.service on this host (a remote cluster) → no k3s dependency, no KUBECONFIG line" \
  "$(printf '%s\n' "$OUT" | grep -cE 'k3s.service|KUBECONFIG' || true):$(printf '%s\n' "$OUT" | grep -c '^After=network-online.target$')" "0:1"
OUT="$(kt "PATH='$KCT/bin':\$PATH; KUBE_SYSTEMD_RUN='$KCT/none'; kube_check_timer_install")"
case "$OUT" in *"No systemd: run ./portcullis kube check at least every 20 h"*"rc=0") t_pass "kube check timer: no systemd → a warning naming the 20 h, init goes on" ;; *) t_fail "kube timer no systemd: $OUT" ;; esac
expect_eq "init on kubernetes installs the kube check timer" "$(sed -n '/^init_run() {/,/^}/p' "$HERE"/../scripts/lib/stack.sh | grep -c '_rt_is_kube || kube_check_timer_install')" 1
# status: fresh ok, 21 h a warning, 25 h / failed / missing a problem.
ckl() { kt "KUBE_NOW=$2; kube_ctl() { case \"\$*\" in *'get configmap portcullis-cluster-check -o json'*) $1 ;; esac; }; kube_cluster_check_lines \"\$(kube_cluster_check_json)\""; }
CKD='{"data":{"checked_at":"2026-11-14T00:00:00Z","ok":"true","why":""}}'
T0=1794614400   # 2026-11-14T00:00:00Z
expect_eq "status: a cluster check 1 h old → ok" "$(ckl "echo '$CKD'" $((T0 + 3600)) | tr -d '\033' | sed 's/\[[0-9;]*m//g' | tr '\n' ' ')" "  ✓ kubernetes: cluster check ok (1 h old) rc=0 "
OUT="$(ckl "echo '$CKD'" $((T0 + 21 * 3600)))"
case "$OUT" in *"kubernetes: the cluster check is 21 h old: the Hub refuses every runtime operation once it is 24 h old"*"rc=0") t_pass "status: a cluster check 21 h old → a warning, not a problem" ;; *) t_fail "status check 21 h: $OUT" ;; esac
OUT="$(ckl "echo '$CKD'" $((T0 + 25 * 3600)))"
case "$OUT" in *"✗"*"the cluster check is 25 h old: the Hub refuses every runtime operation past 24 h"*"rc=1") t_pass "status: a cluster check 25 h old → a problem" ;; *) t_fail "status check 25 h: $OUT" ;; esac
OUT="$(ckl "echo '{\"data\":{\"checked_at\":\"2026-11-14T00:00:00Z\",\"ok\":\"false\",\"why\":\"bindings missing: x\"}}'" $((T0 + 60)))"
case "$OUT" in *"the cluster check failed (bindings missing: x)"*"rc=1") t_pass "status: a failed cluster check → a problem naming why" ;; *) t_fail "status check failed: $OUT" ;; esac
OUT="$(ckl "return 1" $T0)"
case "$OUT" in *"no cluster check (ConfigMap portcullis-cluster-check)"*"rc=1") t_pass "status: no readable cluster check → a problem" ;; *) t_fail "status check missing: $OUT" ;; esac
OUT="$(ckl "echo '{\"data\":{\"checked_at\":\"yesterday\",\"ok\":\"true\"}}'" $T0)"
case "$OUT" in *"rc=1") t_pass "status: an unparseable checked_at counts as too old" ;; *) t_fail "status check bad time: $OUT" ;; esac
expect_eq "status counts the cluster check (kube_cluster_check_lines) towards problems" "$(sed -n '/^status_run() {/,/^}/p' "$HERE"/../scripts/lib/status.sh | grep -c 'kube_cluster_check_lines .* || problems=1')" 1
# kube check: kube_cluster_check's verdict decides the exit status.
OUT="$(kt "kube_psa() { echo 'privileged baseline baseline'; }; kube_bindings_missing() { echo 'binding x missing'; }; kube_ctl() { case \"\$*\" in *'get namespace'*) echo '{\"metadata\":{\"labels\":{\"pod-security.kubernetes.io/enforce\":\"privileged\",\"pod-security.kubernetes.io/warn\":\"baseline\",\"pod-security.kubernetes.io/audit\":\"baseline\"}}}' ;; *apply*) cat > '$KCT/applied' ;; esac; }; kube_cluster_check 2>/dev/null; echo \"why=\$_K_CHECK_WHY\"; jq -r '.data.ok' '$KCT/applied'")"
expect_eq "kube_cluster_check: a missing binding → recorded for the Hub (ok false) and for kube check's exit status" "$(printf '%s\n' "$OUT" | head -n2 | tr '\n' ' ')" "why=binding x missing false "
expect_eq "cmd_kube check exits 1 on a failed check" "$(sed -n '/^cmd_kube() {/,/^}/p' "$HERE"/../scripts/lib/kube.sh | grep -c '\[ -z "\$_K_CHECK_WHY" \] || exit 1')" 1
# No CLI path deletes the apps or edge namespace (only the probe's own): the
# apps policies judge DELETE by the old object, and the namespace controller
# isn't exempt, so such a path would first have to delete the owner=core
# objects there as the CLI identity (ruling) — add that ordering with it.
expect_eq "the CLI deletes no namespace but the NetworkPolicy probe's" \
  "$(grep -rn 'delete namespace\|delete ns ' "$HERE"/../scripts/lib "$HERE"/../portcullis | grep -v '^[^:]*:[0-9]*: *#' | grep -vc 'KUBE_PROBE_NS' || true)" 0
# The AppArmor stacking host check (containerd#14485 / k3s#13625): with
# kernel.apparmor_restrict_unprivileged_unconfined=1 and containerd's
# profile in use, signals inside containers are denied (Postgres never
# finishes starting): refused, naming both ways out; never changed by us.
AA="$WORK/aa"; mkdir -p "$AA/sys" "$AA/sec"
LOCALNODE='{"items":[{"status":{"addresses":[{"type":"InternalIP","address":"10.1.0.4"}]}}]}'
REMOTENODE='{"items":[{"status":{"addresses":[{"type":"InternalIP","address":"192.0.2.9"}]}}]}'
aa() { # aa <sysctl value|-> <apparmor enabled Y|N> <profiles text|-> [node json]
  rm -f "$AA/sys/x" "$AA/sec/profiles"; [ "$1" = - ] || echo "$1" > "$AA/sys/x"
  echo "$2" > "$AA/enabled"; [ "$3" = - ] || printf '%s\n' "$3" > "$AA/sec/profiles"
  kt "KUBE_AA_SYSCTL='$AA/sys/x' KUBE_AA_ENABLED='$AA/enabled' KUBE_AA_PROFILES='$AA/sec/profiles'; _kube_apparmor_check '${4:-$LOCALNODE}'"
}
OUT="$(aa 1 Y 'cri-containerd.apparmor.d (enforce)')"
case "$OUT" in "fail	"*"apparmor_restrict_unprivileged_unconfined=1"*"containerd#14485"*"k3s#13625"*"sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=0"*"relaxes"*"a k3s with the fix"*) t_pass "AppArmor check: sysctl 1 + containerd's profile → fail naming the cause and both options" ;; *) t_fail "aa 1: $OUT" ;; esac
case "$(aa 1 Y -)" in "fail	"*) t_pass "AppArmor check: sysctl 1, profiles unreadable → fail (fail closed)" ;; *) t_fail "aa unreadable: $(aa 1 Y -)" ;; esac
case "$(aa 0 Y 'cri-containerd.apparmor.d (enforce)')" in "ok	"*"= 0"*) t_pass "AppArmor check: sysctl 0 → ok, the value shown" ;; *) t_fail "aa 0: $(aa 0 Y x)" ;; esac
case "$(aa - Y 'cri-containerd.apparmor.d (enforce)')" in "ok	"*"not on this kernel"*) t_pass "AppArmor check: no such sysctl → ok" ;; *) t_fail "aa none" ;; esac
case "$(aa 1 N -)" in "ok	"*"AppArmor off"*) t_pass "AppArmor check: AppArmor off → ok" ;; *) t_fail "aa off: $(aa 1 N -)" ;; esac
case "$(aa 1 Y 'docker-default (enforce)')" in "warn	"*"loaded yet"*) t_pass "AppArmor check: containerd's profile not loaded yet → warn" ;; *) t_fail "aa notloaded: $(aa 1 Y 'docker-default (enforce)')" ;; esac
case "$(aa 1 Y 'cri-containerd.apparmor.d (enforce)' "$REMOTENODE")" in "warn	"*"isn't this host"*) t_pass "AppArmor check: a remote node → warn (checked there)" ;; *) t_fail "aa remote" ;; esac
expect_eq "AppArmor check: the CLI never writes the sysctl (only the CI install script may)" \
  "$(grep -n 'apparmor_restrict_unprivileged_unconfined=0' "$HERE"/../scripts/lib/*.sh "$HERE"/../portcullis | grep -v '_rt_chk\|#' | grep -c 'sysctl -w\|tee\|> */proc' || true)" 0
expect_eq "AppArmor check runs in kube_host_checks (init / up refuse on fail; status shows it)" "$(sed -n '/^kube_host_checks() {/,/^}/p' "$HERE"/../scripts/lib/kube.sh | grep -c '_kube_apparmor_check')" 1
# _rtk_health: a rolling Deployment is "starting" (the old pod's readiness
# isn't the new config's); otherwise the newest non-terminating pod decides.
RH_POD='{"status":{"phase":"Running","containerStatuses":[{"ready":%s,"started":true}]},"spec":{"containers":[{"readinessProbe":{}}]},"metadata":{"creationTimestamp":"%s"%s}}'
rh() { # rh <deploy json> <pods json>
  kt "kube_ctl() { case \"\$*\" in *'get deploy keycloak'*) printf '%s' '$1' ;; *'get pods'*) printf '%s' '{\"items\":$2}' ;; esac; }; _rtk_health keycloak"
}
RH_OLD="$(printf "$RH_POD" true 2026-01-01T00:00:00Z '')" RH_NEW="$(printf "$RH_POD" false 2026-01-01T00:01:00Z '')"
RH_GONE="$(printf "$RH_POD" true 2026-01-01T00:02:00Z ',"deletionTimestamp":"2026-01-01T00:03:00Z"')"
expect_eq "_rtk_health: a Deployment not yet observed at its generation → starting (not the old pod's ready)" \
  "$(rh '{"metadata":{"generation":3},"spec":{"replicas":1},"status":{"observedGeneration":2,"replicas":1,"updatedReplicas":1}}' "[$RH_OLD]")" "starting
rc=0"
expect_eq "_rtk_health: old and new ReplicaSet pods both counted → starting" \
  "$(rh '{"metadata":{"generation":3},"spec":{"replicas":1},"status":{"observedGeneration":3,"replicas":2,"updatedReplicas":1}}' "[$RH_OLD,$RH_NEW]")" "starting
rc=0"
expect_eq "_rtk_health: rolled out → the newest pod decides, a terminating one ignored" \
  "$(rh '{"metadata":{"generation":3},"spec":{"replicas":1},"status":{"observedGeneration":3,"replicas":1,"updatedReplicas":1}}' "[$RH_GONE,$RH_OLD,$RH_NEW]")" "unhealthy
rc=0"
expect_eq "_rtk_health: rolled out and ready → healthy" \
  "$(rh '{"metadata":{"generation":3},"spec":{"replicas":1},"status":{"observedGeneration":3,"replicas":1,"updatedReplicas":1}}' "[$RH_OLD]")" "healthy
rc=0"
expect_eq "_rtk_health: no Deployment → missing" "$(kt "kube_ctl() { return 1; }; _rtk_health keycloak")" "missing
rc=0"
# _rtk_exec: kubectl's own "command terminated with exit code N" never
# reaches the caller; the command's stderr and exit code do.
expect_eq "_rtk_exec: an empty Vault list on kubernetes is the bare {} with exit 2 (vault_no_value accepts it)" \
  "$(kt "kube_ctl() { echo '{}' >&2; echo 'command terminated with exit code 2' >&2; return 2; }; out=\$(_rtk_exec vault -- vault list x 2>&1) || echo \"rc \$?\"; printf '%s|' \"\$out\"; vault_no_value \"\$out\" && echo no-value")" "rc 2
{}|no-value
rc=0"
# _rtk_wait_ready waits on _rtk_rolled_running (rollout-aware, phase
# Running whatever the probes say), never on a pod list.
expect_eq "_rtk_wait_ready: not yet, not yet, then rolled out and Running → done" \
  "$(rm -f "$WORK/rwr"; kt "sleep() { :; }; _rtk_rolled_running() { echo . >> '$WORK/rwr'; [ \$(wc -l < '$WORK/rwr') -ge 3 ]; }; _rtk_wait_ready keycloak; echo \"after \$(wc -l < '$WORK/rwr' | tr -d ' ')\"")" "after 3
rc=0"
expect_eq "_rtk_wait_ready: never rolled out within KUBE_READY_WAIT → fails" \
  "$(kt "KUBE_READY_WAIT=4; sleep() { :; }; _rtk_rolled_running() { return 1; }; _rtk_wait_ready keycloak")" "rc=1"
RR_DEP='{"metadata":{"generation":2},"spec":{"replicas":1},"status":{"observedGeneration":2,"replicas":1,"updatedReplicas":1}}'
rr() { kt "kube_ctl() { case \"\$*\" in *'get deploy vault'*) printf '%s' '$1' ;; *'get pods'*) printf '%s' '{\"items\":$2}' ;; esac; }; _rtk_rolled_running vault && echo yes || echo no"; }
expect_eq "_rtk_rolled_running: an unstarted (sealed) Vault pod in phase Running counts (the old wait's semantics)" \
  "$(rr "$RR_DEP" '[{"status":{"phase":"Running","containerStatuses":[{"ready":false,"started":false}]},"metadata":{"creationTimestamp":"2026-01-01T00:00:00Z"}}]')" "yes
rc=0"
expect_eq "_rtk_rolled_running: Pending → not yet" \
  "$(rr "$RR_DEP" '[{"status":{"phase":"Pending"},"metadata":{"creationTimestamp":"2026-01-01T00:00:00Z"}}]')" "no
rc=0"
expect_eq "_rtk_rolled_running: a rollout in progress → not yet, though the old pod runs" \
  "$(rr '{"metadata":{"generation":3},"spec":{"replicas":1},"status":{"observedGeneration":3,"replicas":2,"updatedReplicas":1}}' '[{"status":{"phase":"Running"},"metadata":{"creationTimestamp":"2026-01-01T00:00:00Z"}}]')" "no
rc=0"
case "$(declare -f _rtk_wait_ready _kube_wait_running 2>/dev/null; sed -n '/^_rtk_wait_ready()/,/^}/p;/^_kube_wait_running()/p' "$HERE/../scripts/lib/kube.sh")" in
  *"wait --for"*) t_fail "_rtk_wait_ready / _kube_wait_running use kubectl wait on a pod list" ;; *) t_pass "_rtk_wait_ready / _kube_wait_running: no kubectl wait on a pod list" ;; esac
k_fixtures
OUT="$(kt 'unset PORTCULLIS_KUBE_CONTEXT; runtime_check')"
case "$OUT" in *"PORTCULLIS_KUBE_CONTEXT is not set"*"rc=1") t_pass "need_env: kubernetes without PORTCULLIS_KUBE_CONTEXT → refused naming it" ;; *) t_fail "kube no context: $OUT" ;; esac
OUT="$(kt 'PORTCULLIS_KUBE_CONTEXT=nope; runtime_check')"
case "$OUT" in *"kube context nope"*"doesn't exist"*"rc=1") t_pass "runtime_check: a context that doesn't exist → refused" ;; *) t_fail "kube missing context: $OUT" ;; esac
k_fixtures
OUT="$(kt 'runtime_check && kube_ctl get nodes -o json >/dev/null && kube_helm list >/dev/null')"
expect_eq "runtime_check: the cluster's networks = .env → ok" "$(printf '%s\n' "$OUT" | tail -n1)" "rc=0"
expect_eq "kube_ctl / kube_helm always pass the context (never the current one)" \
  "$(grep -vc '^--context ci \|^config get-contexts' "$KS/kubectl-calls"):$(grep -c '^--kube-context ci ' "$KS/helm-calls")" "0:1"
OUT="$(kt 'PORTCULLIS_POD_CIDR=10.99.0.0/24; runtime_check')"
case "$OUT" in *"PORTCULLIS_POD_CIDR=10.99.0.0/24 in .env, but the cluster has 10.42.0.0/24"*"rc=1") t_pass "runtime_check: detected pod CIDR differs from .env → refused naming both" ;; *) t_fail "kube pod cidr mismatch: $OUT" ;; esac
OUT="$(kt 'PORTCULLIS_KUBE_API_ENDPOINTS=10.1.0.9:6443; runtime_check')"
case "$OUT" in *"PORTCULLIS_KUBE_API_ENDPOINTS=10.1.0.9:6443 in .env, but the cluster has 10.1.0.4:6443"*"rc=1") t_pass "runtime_check: a different API endpoint → refused naming both" ;; *) t_fail "kube api ep mismatch: $OUT" ;; esac
expect_eq "kube_detect_cidrs: pod, service CIDR and API endpoints" "$(kt 'kube_detect_cidrs; echo "$_K_POD_CIDR|$_K_SVC_CIDR|$_K_API_EP"')" "10.42.0.0/24|10.43.0.0/16|10.1.0.4:6443
rc=0"
echo 'error: something else entirely' > "$KS/kube/svc-dryrun.err"
OUT="$(kt 'kube_detect_cidrs')"
case "$OUT" in *"rc=1") t_pass "kube_detect_cidrs: an unparsable dry-run answer → refused" ;; *) t_fail "kube unparsable svc cidr: $OUT" ;; esac
# ── HA Task 17: init installs k3s on pcmesh (scripts/lib/kube_install.sh) ──
# A multi-node k3s cluster (Task 21, the Task 17 ruling): accepted, every
# node checked on its own — the server flags on every server, podPidsLimit
# on every node, AppArmor on this host only ("not checked" elsewhere); a
# multi-node cluster that isn't k3s stays refused.
k_fixtures
jq '.items = [.items[0], (.items[0] | .metadata.name = "n2" | .spec.podCIDRs = ["10.42.1.0/24"] | .status.addresses = [{"type":"InternalIP","address":"10.215.0.2"}]),
              (.items[0] | .metadata.name = "n3" | .spec.podCIDRs = ["10.42.2.0/24"] | .status.addresses = [{"type":"InternalIP","address":"10.215.0.3"}]
                 | .metadata.annotations["k3s.io/node-args"] = "[\"server\",\"--disable\",\"traefik\",\"--cluster-cidr\",\"10.42.0.0/24\"]")]' \
  "$KS/kube/nodes.json" > "$KS/kube/n3.json" && mv "$KS/kube/n3.json" "$KS/kube/nodes.json"
expect_eq "kube_detect_cidrs: a 3-node k3s cluster → accepted, the cluster CIDR from the servers' node-args" \
  "$(kt 'kube_detect_cidrs; echo "$_K_POD_CIDR"')" "10.42.0.0/24
rc=0"
echo '{"kubeletconfig":{"podPidsLimit":0}}' > "$KS/kube/configz-n2.json"
OUT="$(kt 'kube_host_checks')"
if [ "$(printf '%s\n' "$OUT" | grep -c "^fail	node n2: kubelet podPidsLimit is 0"):$(printf '%s\n' "$OUT" | grep -c "^fail	k3s server n3 runs without --secrets-encryption"):$(printf '%s\n' "$OUT" | grep -c "^ok	node node1: kubelet podPidsLimit 1024"):$(printf '%s\n' "$OUT" | grep -c "^ok	k3s server node1:")" = "1:1:1:1" ]; then
  t_pass "kube_host_checks (3 nodes): n2's podPidsLimit 0 and n3 without --secrets-encryption fail; node1 passes both"
else t_fail "kube_host_checks 3 nodes: $OUT"; fi
expect_eq "kube_host_checks (3 nodes): AppArmor not checked on the two other nodes" \
  "$(printf '%s\n' "$OUT" | grep -c "^warn	AppArmor stacking on node n[23]: not checked")" 2
# Roles come from the control-plane label, cross-checked with the API
# servers; node-args can't promote or demote a node.
expect_eq "kube_host_checks (3 nodes): control-plane nodes that aren't the API servers → fail" \
  "$(printf '%s\n' "$OUT" | grep -c "^fail	the control-plane nodes (10.1.0.4 10.215.0.2 10.215.0.3) aren't the API servers (10.1.0.4)")" 1
cp "$KS/kube/eps.json" "$KS/kube/eps.saved"
echo '{"items":[{"ports":[{"port":6443}],"endpoints":[{"addresses":["10.1.0.4"]},{"addresses":["10.215.0.2"]},{"addresses":["10.215.0.3"]}]}]}' > "$KS/kube/eps.json"
cp "$KS/kube/nodes.json" "$KS/kube/nodes.saved"
jq '.items[1].metadata.annotations["k3s.io/node-args"] = "[\"agent\"]" | .items[2].metadata.labels = {}' "$KS/kube/nodes.saved" > "$KS/kube/nodes.json"
OUT="$(kt 'kube_node_args_checks "$(kube_ctl get nodes -o json)"')"
if [ "$(printf '%s\n' "$OUT" | grep -c "^fail	k3s node n2 is a control-plane node but its node-args say agent"):$(printf '%s\n' "$OUT" | grep -c "^fail	k3s node n3: its node-args claim a server, but it has no control-plane label"):$(printf '%s\n' "$OUT" | grep -c "^fail	the control-plane nodes (10.1.0.4 10.215.0.2) aren't the API servers")" = "1:1:1" ]; then
  t_pass "kube_node_args_checks: a control-plane node claiming agent and an unlabelled node claiming server fail; the cross-check names the mismatch"
else t_fail "node args roles: $OUT"; fi
cp "$KS/kube/nodes.saved" "$KS/kube/nodes.json"
OUT="$(kt 'kube_node_args_checks "$(kube_ctl get nodes -o json)"')"
expect_eq "kube_node_args_checks: the control-plane nodes are exactly the API servers → ok" \
  "$(printf '%s\n' "$OUT" | grep -c "^ok	the control-plane nodes are the API servers (10.1.0.4 10.215.0.2 10.215.0.3)")" 1
mv "$KS/kube/eps.saved" "$KS/kube/eps.json"; rm -f "$KS/kube/nodes.saved"
rm -f "$KS/kube/configz-n2.json"
jq '.items |= map(.metadata.annotations = {} | .metadata.labels = {})' "$KS/kube/nodes.json" > "$KS/kube/n3.json" && mv "$KS/kube/n3.json" "$KS/kube/nodes.json"
OUT="$(kt 'kube_detect_cidrs || { echo "$_K_ERR"; exit 1; }')"
case "$OUT" in *"more than one node and isn't k3s"*"rc=1") t_pass "kube_detect_cidrs: three nodes of another distribution → refused" ;; *) t_fail "kube detect multi non-k3s: $OUT" ;; esac
k_fixtures
expect_eq "kube_detect_cidrs: k3s's --cluster-cidr node arg is the pod CIDR" "$(kt 'kube_detect_cidrs; echo "$_K_POD_CIDR"')" "10.42.0.0/24
rc=0"
jq '.items[0].metadata.annotations["k3s.io/node-args"] = "[\"agent\",\"--cluster-cidr\",\"10.99.0.0/16\"]"' "$KS/kube/nodes.json" > "$KS/kube/n1.json" && mv "$KS/kube/n1.json" "$KS/kube/nodes.json"
case "$(kt 'kube_detect_cidrs || { echo "$_K_ERR"; exit 1; }')" in
  *"node node1 is a control-plane node but its node-args say agent: refused"*"rc=1") t_pass "kube_detect_cidrs: a control-plane node whose node-args claim agent → refused (the role is the label's)" ;;
  *) t_fail "kube detect cp agent" ;; esac
# Two servers whose --cluster-cidr disagree → refused.
k_fixtures
jq '.items += [(.items[0] | .metadata.name = "node2" | .metadata.annotations["k3s.io/node-args"] = "[\"server\",\"--cluster-cidr=10.99.0.0/16\"]")]' "$KS/kube/nodes.json" > "$KS/kube/n1.json" && mv "$KS/kube/n1.json" "$KS/kube/nodes.json"
case "$(kt 'kube_detect_cidrs || { echo "$_K_ERR"; exit 1; }')" in
  *"the servers' --cluster-cidr disagree (10.42.0.0/24, 10.99.0.0/16 on node2)"*"rc=1") t_pass "kube_detect_cidrs: servers with different --cluster-cidr → refused" ;;
  *) t_fail "kube detect cidr disagree" ;; esac
# An unlabelled node's server node-args name no cluster CIDR (2 → spec.podCIDRs).
k_fixtures
jq '.items[0].metadata.labels = {}' "$KS/kube/nodes.json" > "$KS/kube/n1.json" && mv "$KS/kube/n1.json" "$KS/kube/nodes.json"
expect_eq "kube_detect_cidrs: node-args without the control-plane label decide nothing (the node's podCIDRs)" "$(kt 'kube_detect_cidrs; echo "$_K_POD_CIDR"')" "10.42.0.0/24
rc=0"
# The cluster addresses document (contract §20.9): checked against the
# fixed mesh and the cluster itself; it overrides nothing.
k_fixtures
echo '{"items":[{"ports":[{"port":6443}],"endpoints":[{"addresses":["10.215.0.1"]},{"addresses":["10.215.0.10"]}]}]}' > "$KS/kube/eps.json"
ca() { # ca <addresses.json> → the ConfigMap
  jq -n --arg d "$1" '{data: {"addresses.json": $d}}' > "$KS/kube/cluster-addresses.json"; }
CA_OK='{"v":1,"mesh_cidr":"10.215.0.0/24","cluster_cidr":"10.42.0.0/24","service_cidr":"10.43.0.0/16","api":["10.215.0.10","10.215.0.1"],"nodes":{"n1":{"mesh":"10.215.0.1"},"n2":{"mesh":"10.215.0.10"}}}'
car() { kt "PORTCULLIS_KUBE_API_ENDPOINTS='10.215.0.10:6443 10.215.0.1:6443'; kube_forward_core() { :; }; kube_runtime_check && echo \"\$PORTCULLIS_KUBE_API_ENDPOINTS\""; }
ca "$CA_OK"
expect_eq "kube_runtime_check: a cluster addresses document matching the mesh and the cluster → ok, nothing overridden" "$(car)" "10.215.0.10:6443 10.215.0.1:6443
rc=0"
ca "$(jq -c '.mesh_cidr = "0.0.0.0/0"' <<< "$CA_OK")"
case "$(car)" in *"give the mesh as 0.0.0.0/0, not 10.215.0.0/24"*"rc=1") t_pass "kube_cluster_addresses: a mesh_cidr other than 10.215.0.0/24 → refused" ;; *) t_fail "ca mesh: $(car)" ;; esac
ca "$(jq -c '.api = ["10.215.0.1","192.0.2.7"]' <<< "$CA_OK")"
case "$(car)" in *"list 192.0.2.7, which isn't an address in 10.215.0.0/24"*"rc=1") t_pass "kube_cluster_addresses: an API address outside the mesh → refused" ;; *) t_fail "ca api out: $(car)" ;; esac
ca "$(jq -c '.nodes.n2.mesh = "10.215.0.300"' <<< "$CA_OK")"
case "$(car)" in *"list 10.215.0.300, which isn't an address"*"rc=1") t_pass "kube_cluster_addresses: a node's mesh address that isn't an IPv4 address in the mesh → refused" ;; *) t_fail "ca node mesh: $(car)" ;; esac
ca "$(jq -c '.nodes.n2 = {"lan":[]}' <<< "$CA_OK")"
case "$(car)" in *"portcullis-cluster-addresses) don't parse"*"rc=1") t_pass "kube_cluster_addresses: a node without a mesh address → refused" ;; *) t_fail "ca no mesh: $(car)" ;; esac
ca "$(jq -c '.api = ["10.215.0.1"]' <<< "$CA_OK")"
case "$(car)" in *"list the API servers 10.215.0.1:6443, but the cluster has 10.215.0.10:6443 10.215.0.1:6443"*"rc=1") t_pass "kube_cluster_addresses: an api list ≠ the cluster's EndpointSlice → refused naming both" ;; *) t_fail "ca api diff: $(car)" ;; esac
ca "$(jq -c '.cluster_cidr = "10.99.0.0/16"' <<< "$CA_OK")"
case "$(car)" in *"give pods 10.99.0.0/16 and services 10.43.0.0/16, but the cluster has 10.42.0.0/24"*"rc=1") t_pass "kube_cluster_addresses: a cluster CIDR ≠ the cluster's → refused" ;; *) t_fail "ca cidr: $(car)" ;; esac
OUT="$(kt "PORTCULLIS_KUBE_API_ENDPOINTS='10.215.0.10:6443 10.215.0.1:6443'; kube_host_checks")"
case "$OUT" in *"fail	can't read the cluster's networks: the cluster addresses give pods 10.99.0.0/16"*) t_pass "kube_host_checks: a mismatched cluster addresses document → fail" ;; *) t_fail "ca host: $OUT" ;; esac
# ── HA Task 21: nodeadm's CLI side (scripts/lib/node.sh, ruling R-ADM) ──
# The params generation is nodeadm's (shared vectors).
PGV="$HERE/../nodeadm/testdata/params_generation_vectors.json"
bad=""
for i in $(seq 0 $(( $(jq length "$PGV") - 1 ))); do
  got="$(jq -r --argjson i "$i" '.[$i].params | to_entries[] | "\(.key)\t\(.value)"' "$PGV" | kt 'kube_params_generation' | head -n1)"
  [ "$got" = "$(jq -r --argjson i "$i" '.[$i].want_generation' "$PGV")" ] || bad="$bad $i"
done
expect_eq "params generation: vectors equal nodeadm's (kube_params_generation)" "$bad" ""
expect_eq "kube_admission_params_apply's generation is kube_params_generation, and it writes the active record after the probe" \
  "$(sed -n '/^kube_admission_params_apply() {/,/^}/p' "$HERE/../scripts/lib/kube.sh" | grep -c 'kube_params_generation\|kube_admission_active_put "$gen" "$params"')" 2
# The cluster addresses → the params' addresses: pending and active nodes,
# never a removed one; anything that doesn't validate changes nothing.
CA_ST='{"v":1,"mesh_cidr":"10.215.0.0/24","cluster_cidr":"10.42.0.0/24","service_cidr":"10.43.0.0/16","api":["10.215.0.10","10.215.0.1"],"nodes":{"n1":{"mesh":"10.215.0.1","lan":["192.0.2.10"],"public":["198.51.100.7"],"state":"active"},"n2":{"mesh":"10.215.0.10","lan":[],"public":[],"state":"pending"},"n3":{"mesh":"10.215.0.30","lan":["192.0.2.30"],"public":[],"state":"removed"}}}'
# The live nodes (the API server's view): n1 (with an ExternalIP the
# document doesn't list) and n2, both control-plane servers.
cp_node() { jq -nc --arg n "$1" --arg ip "$2" --arg ext "${3:-}" '{metadata: {name: $n, labels: {"node-role.kubernetes.io/control-plane": "true"},
    annotations: {"k3s.io/node-args": "[\"server\",\"--cluster-cidr\",\"10.42.0.0/24\"]"}},
  status: {addresses: ([{type: "InternalIP", address: $ip}] + (if $ext == "" then [] else [{type: "ExternalIP", address: $ext}] end))}}'; }
live_nodes() { printf '%s\n' "$@" | jq -s '{items: .}' > "$KS/kube/nodes.json"; }
live_nodes "$(cp_node n1 10.215.0.1 198.51.100.9)" "$(cp_node n2 10.215.0.10)"
kda() { kt "kube_doc_addresses && echo \"\$_K_DOC_NODES|\$_K_DOC_API\" || { r=\$?; echo \"rc\$r \${_K_ERR:-}\"; exit \$r; }"; }
ca "$CA_ST"
expect_eq "kube_doc_addresses: the pending and active nodes' addresses ∪ every live Node's (not a removed node without a Node), api, each /32" "$(kda)" "10.215.0.1/32 10.215.0.10/32 192.0.2.10/32 198.51.100.7/32 198.51.100.9/32|10.215.0.1/32 10.215.0.10/32
rc=0"
# A removed node whose Node object still exists stays excluded.
live_nodes "$(cp_node n1 10.215.0.1 198.51.100.9)" "$(cp_node n2 10.215.0.10)" "$(cp_node n3 10.215.0.30 | jq -c '.metadata.labels = {} | .metadata.annotations = {"k3s.io/node-args": "[\"agent\"]"}')"
case "$(kda)" in *"10.215.0.30/32"*"192.0.2.30/32"*"rc=0") t_pass "kube_doc_addresses: a removed node keeps its addresses excluded while its Node exists" ;; *) t_fail "kda removed live: $(kda)" ;; esac
# A live Node the document doesn't list: no sync.
live_nodes "$(cp_node n1 10.215.0.1 198.51.100.9)" "$(cp_node n2 10.215.0.10)" "$(cp_node n4 10.215.0.40 | jq -c '.metadata.labels = {} | .metadata.annotations = {}')"
case "$(kda)" in *"rc1 the cluster addresses don't list the node(s) n4"*) t_pass "kube_doc_addresses: a live Node missing from the document → refused" ;; *) t_fail "kda missing: $(kda)" ;; esac
live_nodes "$(cp_node n1 10.215.0.1 198.51.100.9)" "$(cp_node n2 10.215.0.10)"
# Strict IPv4: an IPv6 or out-of-range entry refuses the whole document.
for bad in '.nodes.n1.lan = ["2001:db8::1"]' '.nodes.n1.public = ["198.51.100.300"]' '.nodes.n2.lan = ["010.1.2.3"]' '.nodes.n1.public = ["::ffff:198.51.100.7"]'; do
  ca "$(printf '%s' "$CA_ST" | jq -c "$bad")"
  case "$(kda)" in *"rc1 "*"don't parse"*) t_pass "kube_doc_addresses: $bad → refused" ;; *) t_fail "kda strict $bad: $(kda)" ;; esac
done
# The node address rule nodeadm applies (tests/node_address_vectors.json,
# also TestNodeAddressVectors): the same verdict for every vector.
bad=""
NAV="$HERE/node_address_vectors.json"
for i in $(seq 0 $(( $(jq '.vectors | length' "$NAV") - 1 ))); do
  addr="$(jq -r --argjson i "$i" '.vectors[$i].address' "$NAV")"
  want="$(jq -r --argjson i "$i" '.vectors[$i].accept' "$NAV")"
  ca "$(printf '%s' "$CA_ST" | jq -c --arg a "$addr" '.nodes.n1.lan = [$a]')"
  case "$(kda)" in *"rc=0") got=true ;; *"don't parse"*) got=false ;; *) got=other ;; esac
  [ "$got" = "$want" ] || bad="$bad [$addr]=$got"
done
expect_eq "kube_doc_addresses: the shared node address vectors give nodeadm's verdict" "$bad" ""
ca "$CA_ST"
ca "$(printf '%s' "$CA_ST" | jq -c '.nodes.n2.state = "joining"')"
case "$(kda)" in *"rc1 the cluster addresses (ConfigMap portcullis-cluster-addresses) don't parse"*) t_pass "kube_doc_addresses: an unknown node state → refused" ;; *) t_fail "kda state: $(kda)" ;; esac
ca "$(printf '%s' "$CA_ST" | jq -c '.nodes.n1.public = ["not an address"]')"
case "$(kda)" in *"rc1 "*"don't parse"*) t_pass "kube_doc_addresses: a malformed address → refused" ;; *) t_fail "kda addr: $(kda)" ;; esac
rm -f "$KS/kube/cluster-addresses.json"
case "$(kda)" in *"rc2"*) t_pass "kube_doc_addresses: no document yet → 2 (the .env addresses)" ;; *) t_fail "kda none: $(kda)" ;; esac
# params-sync: the active generation's params with the document's four
# keys; unchanged → nothing; changed → the swap; refused → nothing.
PS_BASE="$(printf 'hubImage\tghcr.io/porelli/portcullis-hub@sha256:%064d\nappsNamespace\tportcullis-apps\nnodeAddresses\t10.215.0.1/32\napiAddresses\t10.215.0.1/32 10.215.0.10/32\npodCIDR\t10.42.0.0/24\nserviceCIDR\t10.43.0.0/16' 1)"
PS_BINDINGS="$(kt 'echo $KUBE_BINDINGS' | head -n1)"
psync() { # psync <base params lines> [drop binding] [record jq] → kube_params_sync with the stub's active record / params / bindings
  local g; g="$(printf '%s\n' "$1" | kt kube_params_generation | head -n1)"
  printf '%s\n' "$1" | jq -R 'split("\t") | {(.[0]): .[1]}' | jq -s --arg g "$g" '{data: (add + {generation: $g})}' > "$KS/kube/params-$g.json"
  jq -n --arg g "$g" --slurpfile p "$KS/kube/params-$g.json" '{data: {"active.json": ({generation: $g, node_addresses: ($p[0].data.nodeAddresses | split(" ")),
      api_addresses: ($p[0].data.apiAddresses | split(" ")), proven_at: "x"} | '"${3:-.}"' | tojson)}}' > "$KS/kube/active.json"
  printf '%s\n' $PS_BINDINGS | grep -vx "${2:-none}" | jq -R --arg g "$g" '{metadata: {name: (. + "-" + $g)}, spec: {paramRef: {name: ("portcullis-admission-params-" + $g)}}}' \
    | jq -s '{items: .}' > "$KS/kube/bindings-$g.json"
  kt "kube_admission_params_apply() { echo \"APPLY \$1\"; printf '%s\n' \"\$2\" | awk -F'\t' '\$1 ~ /Addresses\$/'; }; kube_params_sync"
}
ca "$CA_ST"
OUT="$(psync "$(printf '%s\n' "$PS_BASE" | sed 's#^nodeAddresses\t.*#nodeAddresses\t10.215.0.1/32 10.215.0.10/32 192.0.2.10/32 198.51.100.7/32 198.51.100.9/32#')")"
expect_eq "kube params-sync: the document's addresses already in the active generation → nothing" "$OUT" "rc=0"
# Unchanged but not judging (review I3): a binding gone, or the record
# naming other addresses → repaired by the same swap.
PS_SAME="$(printf '%s\n' "$PS_BASE" | sed 's#^nodeAddresses\t.*#nodeAddresses\t10.215.0.1/32 10.215.0.10/32 192.0.2.10/32 198.51.100.7/32 198.51.100.9/32#')"
OUT="$(psync "$PS_SAME" "$(printf '%s\n' $PS_BINDINGS | sed -n 3p)")"
case "$OUT" in *"is recorded but the binding $(printf '%s\n' $PS_BINDINGS | sed -n 3p)-"*"is missing: repairing it"*"APPLY "*"rc=0") t_pass "kube params-sync: an unchanged generation missing a binding → repaired" ;; *) t_fail "psync missing binding: $OUT" ;; esac
OUT="$(psync "$PS_SAME" none '.node_addresses = ["10.215.0.1/32"]')"
case "$OUT" in *"doesn't match it: repairing it"*"APPLY "*"rc=0") t_pass "kube params-sync: an unchanged generation whose record doesn't match → repaired" ;; *) t_fail "psync record: $OUT" ;; esac
expect_eq "kube params-sync and kube check run under cli_lock (review I3)" \
  "$(sed -n '/^cli_lock() {/,/^}/p' "$HERE/../scripts/lib/common.sh" | grep -c 'kube) case "$sub" in params-sync|check) ;; \*) return 0 ;; esac ;;')" 1
OUT="$(psync "$PS_BASE")"
case "$OUT" in *"APPLY ghcr.io/porelli/portcullis-hub@sha256:"*"nodeAddresses	10.215.0.1/32 10.215.0.10/32 192.0.2.10/32 198.51.100.7/32 198.51.100.9/32"*"apiAddresses	10.215.0.1/32 10.215.0.10/32"*"rc=0")
  t_pass "kube params-sync: a pending node's addresses → the swap with the document's addresses and the active hub image" ;; *) t_fail "psync change: $OUT" ;; esac
ca "$(printf '%s' "$CA_ST" | jq -c '.nodes.n2.mesh = "10.9.0.1"')"
OUT="$(psync "$PS_BASE")"
case "$OUT" in *APPLY*) t_fail "psync bad doc applied: $OUT" ;; *"rc=1") t_pass "kube params-sync: a node outside the mesh → nothing changed, exit 1" ;; *) t_fail "psync bad: $OUT" ;; esac
OUT="$(kt 'PORTCULLIS_POD_CIDR=10.42.9.0/24; kube_params_sync')"
case "$OUT" in *"the cluster CIDR is 10.42.0.0/24 but .env has PORTCULLIS_POD_CIDR=10.42.9.0/24: nothing is changed"*"rc=1") t_pass "kube params-sync: a cluster CIDR other than .env's → refused" ;; *) t_fail "psync cidr: $OUT" ;; esac
rm -f "$KS/kube/active.json"; ca "$CA_ST"
case "$(kt 'kube_params_sync')" in *"no active admission params yet"*"rc=1") t_pass "kube params-sync: no active record → refused (run up first)" ;; *) t_fail "psync no active" ;; esac
rm -f "$KS/kube/cluster-addresses.json"
case "$(kt 'kube_params_sync')" in *"no cluster addresses yet"*"rc=0") t_pass "kube params-sync: no document yet → nothing to sync" ;; *) t_fail "psync no doc" ;; esac
# portcullis-kube-params.timer: every 30 s, as the operator, kube params-sync.
OUT="$(kt "PATH='$KCT/bin':\$PATH; kube_params_timer_units '$KCT/p'; cat '$KCT/p/portcullis-kube-params.service' '$KCT/p/portcullis-kube-params.timer'")"
expect_eq "kube params timer: a oneshot as the operator running kube params-sync, every 30 s from boot" \
  "$(printf '%s\n' "$OUT" | grep -cE '^(Type=oneshot|User=.+|ExecStart=.*/portcullis kube params-sync|OnBootSec=30s|OnUnitActiveSec=30s|WantedBy=timers.target)$')" 6
expect_eq "init on kubernetes installs the params timer" "$(sed -n '/^init_run() {/,/^}/p' "$HERE"/../scripts/lib/stack.sh | grep -c '_rt_is_kube || kube_params_timer_install')" 1
# nodeadm's objects: off unless init installed k3s and the image is known;
# the server token reaches its Secret through --from-file only, once.
expect_eq "kube_nodeadm_on: needs PORTCULLIS_K3S_VERSION and a nodeadm image by digest" \
  "$(kt 'PORTCULLIS_K3S_VERSION=v1; PORTCULLIS_NODEADM_IMAGE=ghcr.io/x/nodeadm:edge; kube_nodeadm_on' | tail -n1):$(kt "PORTCULLIS_K3S_VERSION=v1; PORTCULLIS_NODEADM_IMAGE=ghcr.io/x/nodeadm@sha256:$(printf '%064d' 4); kube_nodeadm_on" | tail -n1)" "rc=1:rc=0"
KN="$WORK/kn"; rm -rf "$KN"; mkdir -p "$KN/var/lib/rancher/k3s/server" "$KN/root/secrets/enroll"
printf 'K10%064d::server:%s' 7 "s3cr3t-server-token-value" > "$KN/var/lib/rancher/k3s/server/token"
mkdir -p "$KN/etc/rancher/k3s"; printf 'agent-s3cr3t-value' > "$KN/etc/rancher/k3s/agent-token"
OUT="$(kt "PORTCULLIS_ROOT='$KN/root'; KUBE_INSTALL_PREFIX='$KN'; PORTCULLIS_K3S_VERSION=v1; PORTCULLIS_NODEADM_IMAGE=ghcr.io/x/nodeadm@sha256:$(printf '%064d' 4)
  kube_ctl() { printf 'ARGV %s\n' \"\$*\" >&2; case \"\$*\" in *'get secret nodeadm-k3s-token'*|*'get secret nodeadm-state'*|*'get configmap portcullis-cluster-addresses'*) return 1 ;;
    *'--dry-run=client -o json'*) printf '{\"metadata\":{}}' ;; *' get nodes -o json'*) echo '{\"items\":[]}' ;; esac; }
  kube_namespace_apply() { echo \"NS \$*\"; }; _kube_put() { echo PUT; }
  kube_nodeadm_prepare; kube_nodeadm_sync; stat -c %a '$KN/root/secrets/enroll/nodeadm-api-secret'")"
case "$OUT" in *"NS portcullis-nodeadm restricted restricted restricted"*"--from-file=bearer="*"--from-file=token="*"--from-file=agent="*"create --field-manager"*"state.json"*"addr.json"*"600"*"rc=0") t_pass "kube_nodeadm_sync: its namespace, its bearer and the server token by --from-file, the state Secret and the addresses ConfigMap created" ;; *) t_fail "nodeadm sync: $OUT" ;; esac
case "$OUT" in *"s3cr3t-server-token-value"*|*"agent-s3cr3t-value"*) t_fail "a k3s token reached argv or the output" ;; *) t_pass "kube_nodeadm_sync: the server and agent tokens are on no argv" ;; esac
rm -f "$KS/kube/cluster-addresses.json"
k_fixtures

# The installer sandbox: every host path under KUBE_INSTALL_PREFIX, a fake
# curl serving the pinned downloads, a fake installer recording its argv,
# environment and stdin, fake wg / systemctl.
KI="$WORK/ki"
ki_reset() {
  rm -rf "$KI"; mkdir -p "$KI/bin" "$KI/dl" "$KI/root/proc" "$KI/root/etc/rancher/k3s"
  printf 'MemTotal:        8000000 kB\n' > "$KI/root/proc/meminfo"
  printf '#!/bin/sh\nprintf "%%s\\n" "$@" > "%s/argv"\nenv > "%s/env"\ncat > "%s/stdin" </dev/null\necho "installer ran"\n' "$KI" "$KI" "$KI" > "$KI/dl/install.sh"
  printf 'K3S-BINARY\n' > "$KI/dl/k3s"
  printf '#!/bin/sh\necho "$*" >> "%s/k3s-calls"\n' "$KI" > "$KI/bin/k3s"
  cat > "$KI/bin/curl" <<'C'
#!/bin/sh
out="" url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift ;; -*) ;; *) url="$1" ;; esac; shift; done
echo "$url" >> "$KI_DIR/curl-calls"
case "$url" in
  https://raw.githubusercontent.com/k3s-io/k3s/v1.37.2%2Bk3s1/install.sh) cp "$KI_DIR/dl/install.sh" "$out" ;;
  https://github.com/k3s-io/k3s/releases/download/v1.37.2%2Bk3s1/k3s) cp "$KI_DIR/dl/k3s" "$out" ;;
  *) exit 22 ;;
esac
C
  printf '#!/bin/sh\necho "$*" >> "%s/systemctl-calls"\n' "$KI" > "$KI/bin/systemctl"
  printf '#!/bin/sh\necho "$*" >> "%s/wg-calls"\n[ "$1" = genkey ] && echo "PRIVKEY-FIXTURE-k3Jq9zZ0aWc="\nexit 0\n' "$KI" > "$KI/bin/wg"
  chmod +x "$KI/bin/"*
  printf 'apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: Q0E=\n    server: https://10.215.0.1:6443\n  name: default\ncontexts:\n- context:\n    cluster: default\n    user: default\n  name: default\ncurrent-context: default\nkind: Config\nusers:\n- name: default\n  user:\n    client-key-data: S0VZ\n' > "$KI/root/etc/rancher/k3s/k3s.yaml"
}
# kik <code> — kt with the sandbox: the pins = the fakes' sha256, amd64,
# no cluster answering, no Ready wait, no public address.
kik() {
  kt "export KI_DIR='$KI' PATH='$KI/bin':\$PATH KUBE_INSTALL_PREFIX='$KI/root' KUBE_INSTALL_ARCH=x86_64
    unset PORTCULLIS_PUBLIC_IPV4
    KUBE_K3S_SCRIPT_SHA256=\$(_kube_sha '$KI/dl/install.sh') KUBE_K3S_SHA256_AMD64=\$(_kube_sha '$KI/dl/k3s')
    _ki_cluster_answers() { return 1; }; _ki_wait_ready() { :; }
    $1"
}
ki_reset
OUT="$(kik "KUBE_K3S_SCRIPT_SHA256=$(printf '0%.0s' $(seq 64)); kube_install_k3s")"
case "$OUT" in *"install.sh doesn't match its pinned sha256"*"nothing was installed"*"rc=1") t_pass "kube_install_k3s: refuses a script whose sha256 differs (rc=1)" ;; *) t_fail "ki sha: $OUT" ;; esac
expect_eq "kube_install_k3s: a refused script → nothing executed, no binary, no token, no flannel conf" \
  "$(ls "$KI/argv" "$KI/root/usr/local/bin/k3s" "$KI/root/etc/rancher/k3s/token" "$KI/root/etc/rancher/k3s/flannel-net-conf.json" 2>/dev/null | wc -l | tr -d ' ')" 0
ki_reset; mkdir -p "$KI/tmp"
OUT="$(kik "export TMPDIR='$KI/tmp'; KUBE_K3S_SHA256_AMD64=$(printf 'a%.0s' $(seq 64)); kube_install_k3s")"
expect_eq "kube_install_k3s: a refused download leaves no temp directory" "$(ls -A "$KI/tmp" | wc -l | tr -d ' ')" 0
case "$OUT" in *"k3s doesn't match its pinned sha256"*"rc=1") t_pass "kube_install_k3s: refuses a binary whose sha256 differs" ;; *) t_fail "ki bin sha: $OUT" ;; esac
expect_eq "kube_install_k3s: a refused binary → the installer never ran" "$(test -e "$KI/argv" && echo ran || echo no)" no
ki_reset
printf 'FIXTURE-K3S-TOKEN-7f3a9c\n' > "$KI/root/etc/rancher/k3s/token"; chmod 600 "$KI/root/etc/rancher/k3s/token"
OUT="$(kik 'kube_install_k3s' 2>&1)"
cp "$KI/k3s-calls" "$WORK/k3s-calls.keep" 2>/dev/null || :
expect_eq "kube_install_k3s: installs (rc=0)" "$(printf '%s\n' "$OUT" | tail -n1)" "rc=0"
expect_eq "kube_install_k3s: flags exactly (the recorded argv = tests/fixtures/k3s-server-flags.txt, sorted)" \
  "$(head -n1 "$KI/argv"):$(tail -n +2 "$KI/argv" | LC_ALL=C sort | diff - "$HERE/fixtures/k3s-server-flags.txt" >/dev/null && echo same || tail -n +2 "$KI/argv" | LC_ALL=C sort | diff - "$HERE/fixtures/k3s-server-flags.txt")" "server:same"
expect_eq "kube_install_k3s: the installer skips its download and pins the version (no K3S_TOKEN in its environment)" \
  "$(grep -cxE 'INSTALL_K3S_SKIP_DOWNLOAD=true|INSTALL_K3S_VERSION=v1\.37\.2\+k3s1' "$KI/env"):$(grep -c '^K3S_' "$KI/env" || true)" "2:0"
expect_eq "kube_install_k3s: token never on argv (argv, environment, stdin, output, curl calls)" \
  "$(cat "$KI/argv" "$KI/env" "$KI/stdin" "$KI/curl-calls" | grep -c 'FIXTURE-K3S-TOKEN' || true):$(printf '%s' "$OUT" | grep -c 'FIXTURE-K3S-TOKEN' || true)" "0:0"
expect_eq "kube_install_k3s: an existing token file is kept, 0600" "$(cat "$KI/root/etc/rancher/k3s/token"):$(file_mode "$KI/root/etc/rancher/k3s/token")" "FIXTURE-K3S-TOKEN-7f3a9c:600"
expect_eq "kube_install_k3s: flannel's net-conf = tests/fixtures/k3s-flannel-net-conf.json (WireGuard on 51840, the cluster network)" \
  "$(diff "$KI/root/etc/rancher/k3s/flannel-net-conf.json" "$HERE/fixtures/k3s-flannel-net-conf.json" >/dev/null && echo same):$(jq -r '.Backend.ListenPort' "$KI/root/etc/rancher/k3s/flannel-net-conf.json")" "same:51840"
expect_eq "kube_install_k3s: k3s starts after pcmesh (a 10-pcmesh.conf drop-in)" \
  "$(grep -cxE '\[Unit\]|After=wg-quick@pcmesh\.service|Requires=wg-quick@pcmesh\.service' "$KI/root/etc/systemd/system/k3s.service.d/10-pcmesh.conf")" 3
expect_eq "kube_install_k3s: the pinned binary installed 0755" "$(cat "$KI/root/usr/local/bin/k3s"):$(file_mode "$KI/root/usr/local/bin/k3s")" "K3S-BINARY:755"
KCF="$PORTCULLIS_ROOT/secrets/kube/kubeconfig"
expect_eq "kube_install_k3s: the kubeconfig at secrets/kube/kubeconfig (0600), context portcullis, server https://10.215.0.1:6443" \
  "$(file_mode "$KCF"):$(grep -c 'name: portcullis$' "$KCF"):$(grep -c 'current-context: portcullis$' "$KCF"):$(grep -c 'server: https://10.215.0.1:6443$' "$KCF"):$(grep -c default "$KCF" || true)" "600:3:1:1:0"
rm -f "$KCF"
ki_reset
OUT="$(kik 'kube_install_k3s --node-external-ip=198.51.100.1')"
expect_eq "kube_install_k3s: a fresh token is 64 hex in a 0600 file, never printed; extra flags appended" \
  "$(grep -cE '^[0-9a-f]{64}$' "$KI/root/etc/rancher/k3s/token"):$(file_mode "$KI/root/etc/rancher/k3s/token"):$(printf '%s' "$OUT" | grep -c "$(cat "$KI/root/etc/rancher/k3s/token")" || true):$(tail -n1 "$KI/argv")" "1:600:0:--node-external-ip=198.51.100.1"
rm -f "$KCF"
ki_reset
OUT="$(kik '_ki_cluster_answers() { return 0; }; kube_install_k3s')"
case "$OUT" in *"already answers"*"rc=0") [ -e "$KI/argv" ] && t_fail "ki answers: ran" || t_pass "kube_install_k3s: a cluster answering on init's context → not installed again" ;; *) t_fail "ki answers: $OUT" ;; esac
# The class suggestion: small below 3.5 GiB (3 670 016 KiB) or on a Pi (no
# storage label), cloud when the public address is local, else home.
ki_reset; printf 'MemTotal:        3600000 kB\n' > "$KI/root/proc/meminfo"
expect_eq "kube_k3s_node_labels: 3 600 000 KiB (below 3.5 GiB) → small" "$(kik 'kube_k3s_node_labels | grep class=')" "portcullis.io/class=small
rc=0"
ki_reset; printf 'MemTotal:        3700000 kB\n' > "$KI/root/proc/meminfo"
expect_eq "kube_k3s_node_labels: 3 700 000 KiB (above 3.5 GiB) → home, storage on (and Longhorn's default disk: the first node is at main)" "$(kik 'kube_k3s_node_labels | grep -E "class=|storage=|create-default-disk" | tr "\n" " "')" "portcullis.io/class=home portcullis.io/storage=true node.longhorn.io/create-default-disk=true rc=0"
ki_reset; printf 'MemTotal:        2000000 kB\n' > "$KI/root/proc/meminfo"
expect_eq "kube_k3s_node_labels: 2 GB → class small, no storage label (no default disk)" "$(kik 'kube_k3s_node_labels | grep -E "class=|storage=|create-default-disk"')" "portcullis.io/class=small
rc=0"
ki_reset; mkdir -p "$KI/root/proc/device-tree"; printf 'Raspberry Pi 5 Model B Rev 1.0\0' > "$KI/root/proc/device-tree/model"
expect_eq "kube_k3s_node_labels: a Raspberry Pi → small" "$(kik 'kube_k3s_node_labels | grep -c class=small')" "1
rc=0"
ki_reset
expect_eq "kube_k3s_node_labels: the public address on this host → cloud" "$(kik 'PORTCULLIS_PUBLIC_IPV4=198.51.100.1; kube_k3s_node_labels | grep class=')" "portcullis.io/class=cloud
rc=0"
# Ruling R-NODELABELS: no placement label or portcullis.io/ taint among the
# kubelet's flags; the CLI labels the registered node.
expect_eq "kube_k3s_server_flags: no --node-label / --node-taint for the reserved prefixes" \
  "$(kik 'kube_k3s_server_flags' | grep -cE -- '^--node-(label|taint)=(portcullis\.io/|topology\.kubernetes\.io/|node\.longhorn\.io/|svccontroller\.k3s\.cattle\.io/)' || true)" "0"
expect_eq "kube_install_k3s: after Ready, the CLI labels node-1, then removes its unlabelled taint (k3s kubectl, its admin identity)" \
  "$(grep -nE '^kubectl (label|taint) node node-1' "$WORK/k3s-calls.keep" 2>/dev/null | cut -d: -f2-)" "kubectl label node node-1 --overwrite portcullis.io/class=home portcullis.io/site=main topology.kubernetes.io/zone=main portcullis.io/ingress=true svccontroller.k3s.cattle.io/enablelb=true portcullis.io/storage=true node.longhorn.io/create-default-disk=true
kubectl taint node node-1 nodeadm.portcullis/unlabelled:NoSchedule-"
expect_eq "kube_k3s_server_flags: the node registers with the unlabelled taint (the one registration portcullis-node-labels admits)" \
  "$(kik 'kube_k3s_server_flags' | grep -cx -- '--node-taint=nodeadm.portcullis/unlabelled=true:NoSchedule')" "1"
OUT="$(kik 'k3s() { case "$*" in *taint*) echo "error: taint \"nodeadm.portcullis/unlabelled:NoSchedule\" not found" >&2; return 1 ;; esac; }; _ki_label_node')"
expect_eq "_ki_label_node: the taint already gone → fine" "$OUT" "rc=0"
OUT="$(kik 'k3s() { case "$*" in *taint*) echo "error: Unauthorized" >&2; return 1 ;; esac; }; _ki_label_node')"
case "$OUT" in *"could not remove the taint nodeadm.portcullis/unlabelled from the node node-1"*"rc=1") t_pass "_ki_label_node: a refused taint removal fails init" ;; *) t_fail "label taint fail: $OUT" ;; esac

# The mesh: the private key generated here (0600), never printed and never
# in the config (PostUp loads it), wg-quick@pcmesh enabled.
ki_reset
OUT="$(kik 'kube_install_mesh')"
MK="$KI/root/etc/wireguard/pcmesh.key" MC="$KI/root/etc/wireguard/pcmesh.conf"
expect_eq "kube_install_mesh: private key mode 0600 (dir 0700) and never printed" \
  "$(cat "$MK"):$(file_mode "$MK"):$(file_mode "$(dirname "$MK")"):$(printf '%s' "$OUT" | grep -c PRIVKEY-FIXTURE || true)" "PRIVKEY-FIXTURE-k3Jq9zZ0aWc=:600:700:0"
expect_eq "kube_install_mesh: pcmesh.conf 0600, 10.215.0.1/24 on UDP 51830, MTU 1420, the key by PostUp only" \
  "$(file_mode "$MC"):$(grep -cxE 'Address = 10\.215\.0\.1/24|ListenPort = 51830|MTU = 1420|PostUp = wg set %i private-key /etc/wireguard/pcmesh\.key' "$MC"):$(grep -c 'PRIVKEY-FIXTURE\|PrivateKey' "$MC" || true)" "600:4:0"
expect_eq "kube_install_mesh: wg-quick@pcmesh enabled and checked active, wg only asked for genkey" "$(tr '\n' ' ' < "$KI/systemctl-calls"):$(cat "$KI/wg-calls")" "enable --now wg-quick@pcmesh is-active --quiet wg-quick@pcmesh :genkey"
printf '#!/bin/sh\necho "-- journal for $*"\necho "[#] wg set pcmesh private-key /etc/wireguard/pcmesh.key"\necho "PRIVKEY-FIXTURE-k3Jq9zZ0aWc= leaked line"\necho "Unable to read: Permission denied"\n' > "$KI/bin/journalctl"; chmod +x "$KI/bin/journalctl"
OUT="$(kik 'systemctl() { [ "$1" = enable ]; }; kube_install_mesh')"
case "$OUT" in *"last 20 journal lines of wg-quick@pcmesh"*"| -- journal for -u wg-quick@pcmesh -n 20"*"| Unable to read: Permission denied"*"didn't start (its last journal lines are above)"*"rc=1") t_pass "kube_install_mesh: enable --now answering 0 but the unit not active → its journal tail printed, then refused" ;; *) t_fail "ki mesh journal: $OUT" ;; esac
expect_eq "kube_install_mesh: the journal tail drops any line holding the mesh key" "$(printf '%s' "$OUT" | grep -c PRIVKEY-FIXTURE || true)" 0
rm -f "$KI/bin/journalctl"
OUT="$(kik 'kube_install_mesh')"
expect_eq "kube_install_mesh: a re-run keeps the key and the config" "$(cat "$MK"):$(cat "$KI/wg-calls")" "PRIVKEY-FIXTURE-k3Jq9zZ0aWc=:genkey"

# Host checks before the install, then ONE confirmation listing the
# packages to install (wireguard-tools here is installed).
ki_reset; mkdir -p "$KI/root/sys/module/wireguard"
kip() { kik "KUBE_INSTALL_OS=Linux; INIT_INTERACTIVE=true
  _ki_pkg_installed() { [ \"\$1\" = wireguard-tools ]; }; _ki_port_busy() { return 1; }; _ki_mesh_taken() { :; }; _ki_fs_type() { echo ext4; }; _ki_link_up() { return 1; }; _ki_k3s_ours() { return 1; }
  confirm() { echo \"CONFIRM \$1\" >> '$KI/log'; $1; }
  _ki_sudo() { echo \"SUDO \$*\" >> '$KI/log'; }
  $2"; }
OUT="$(kip 'return 0' 'kube_install_preflight')"
expect_eq "kube_host_checks: one confirmation lists open-iscsi nfs-common (wireguard-tools present)" \
  "$(grep -c '^CONFIRM' "$KI/log"):$(grep '^CONFIRM' "$KI/log" | grep -c 'k3s v1.37.2+k3s1.*pcmesh (10.215.0.1, UDP 51830), and the packages: open-iscsi nfs-common\. Continue?$')" "1:1"
expect_eq "kube_install_preflight: apt-get installs exactly those packages, iscsid enabled" \
  "$(grep -c '^SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends open-iscsi nfs-common$' "$KI/log"):$(grep -c '^SUDO systemctl enable --now iscsid$' "$KI/log")" "1:1"
case "$OUT" in *"open-iscsi is not installed"*"no watchdog device"*"rc=0") t_pass "kube_install_preflight: the node checks (open-iscsi, watchdog) are reported, not refused" ;; *) t_fail "ki preflight: $OUT" ;; esac
rm -f "$KI/log"
OUT="$(kip 'return 1' 'kube_install_preflight')"
case "$OUT" in *"nothing was installed"*"rc=1") [ "$(grep -c '^SUDO' "$KI/log" || true)" = 0 ] && t_pass "kube_install_preflight: the confirmation declined → refused, nothing installed" || t_fail "ki decline installed" ;; *) t_fail "ki decline: $OUT" ;; esac
rm -f "$KI/log"
OUT="$(kip 'return 0' '_ki_port_busy() { [ "$1" = 6443 ]; }; kube_install_preflight')"
case "$OUT" in *"port 6443/tcp is in use"*"sudo /usr/local/bin/k3s-uninstall.sh; sudo systemctl disable --now wg-quick@pcmesh; sudo rm -f /etc/wireguard/pcmesh.conf /etc/wireguard/pcmesh.key"*"rc=1") [ ! -e "$KI/log" ] && t_pass "kube_install_preflight: a failed host check (6443 in use) → refused before the confirmation" || t_fail "ki port: asked" ;; *) t_fail "ki port: $OUT" ;; esac
OUT="$(kip 'return 0' '_ki_mesh_taken() { echo 10.215.0.7; }; kube_install_host_checks')"
case "$OUT" in *"fail	the mesh subnet 10.215.0.0/24 is already in use on this host (10.215.0.7)"*) t_pass "kube_install_host_checks: the mesh subnet taken → fail" ;; *) t_fail "ki mesh taken: $OUT" ;; esac
OUT="$(kip 'return 0' 'mkdir -p "$KUBE_INSTALL_PREFIX/dev" && : > "$KUBE_INSTALL_PREFIX/dev/watchdog"; _ki_fs_type() { echo zfs; }; _ki_pkg_installed() { return 0; }; _ki_node_checks')"
case "$OUT" in *"ok	open-iscsi installed"*"ok	nfs-common installed"*"ok	watchdog device /dev/watchdog"*"warn	/var/lib is on ZFS"*) t_pass "_ki_node_checks: packages, the watchdog and ZFS reported" ;; *) t_fail "ki node checks: $OUT" ;; esac
OUT="$(kip 'return 0' '_ki_have() { [ "$1" != ss ]; }; kube_install_host_checks')"
case "$OUT" in *"fail	ss (iproute2) is missing: the ports can't be checked free"*) t_pass "kube_install_host_checks: no ss → fail (never every port free)" ;; *) t_fail "ki no ss: $OUT" ;; esac
OUT="$(KUBE_INSTALL_OS=Linux KUBE_INSTALL_PREFIX="$KI/root" bash -c '. "$1/scripts/lib/common.sh"; . "$1/scripts/lib/kube_install.sh"; _ki_port_busy() { return 1; }; kube_install_host_checks' _ "$HERE/.." 2>&1)"
case "$OUT" in *"fail	the mesh subnet 10.215.0.0/24 can't be checked free (network.sh isn't loaded)"*) t_pass "kube_install_host_checks: only common.sh + kube_install.sh (no cidr_contains) → the mesh check fails closed" ;; *) t_fail "ki no network.sh: $OUT" ;; esac
# A half-finished init of our own resumes (I3): pcmesh up with our config
# and key holds 51830; k3s with our token, net-conf and unit holds its ports.
kir() { kik "KUBE_INSTALL_OS=Linux; INIT_INTERACTIVE=false; _ki_pkg_installed() { return 0; }; _ki_mesh_taken() { :; }; _ki_fs_type() { echo ext4; }; _ki_link_up() { return 0; }
  $1"; }
ki_reset; mkdir -p "$KI/root/sys/module/wireguard"
kik 'kube_install_mesh' >/dev/null
OUT="$(kir '_ki_port_busy() { [ "$1" = 51830 ]; }; kube_install_preflight; echo resumed')"
case "$OUT" in *"pcmesh is a half-finished init's: resuming"*"resumed"*"rc=0") t_pass "kube_install_preflight: mesh up (ours), k3s failed → the re-run resumes" ;; *) t_fail "ki resume mesh: $OUT" ;; esac
kik 'kube_install_k3s' >/dev/null; rm -f "$PORTCULLIS_ROOT/secrets/kube/kubeconfig" "$KI/argv"
mkdir -p "$KI/root/etc/systemd/system"; : > "$KI/root/etc/systemd/system/k3s.service"
TOK="$(cat "$KI/root/etc/rancher/k3s/token")"
OUT="$(kir '_ki_port_busy() { return 0; }; kube_install_preflight && kube_install_mesh && kube_install_k3s')"
case "$OUT" in *"k3s is a half-finished init's: resuming"*"rc=0") t_pass "kube_install_preflight: k3s not Ready (ours, every port held) → the re-run resumes" ;; *) t_fail "ki resume k3s: $OUT" ;; esac
expect_eq "kube_install_k3s: the resumed run keeps the token and runs the installer again" "$([ "$(cat "$KI/root/etc/rancher/k3s/token")" = "$TOK" ] && echo kept):$(head -n1 "$KI/argv" 2>/dev/null)" "kept:server"
rm -f "$PORTCULLIS_ROOT/secrets/kube/kubeconfig"
echo '{"Network":"10.99.0.0/16"}' > "$KI/root/etc/rancher/k3s/flannel-net-conf.json"
OUT="$(kir '_ki_port_busy() { [ "$1" = 6443 ]; }; kube_install_preflight')"
case "$OUT" in *"port 6443/tcp is in use"*"k3s-uninstall.sh"*"rc=1") t_pass "kube_install_preflight: k3s that isn't ours (another net-conf) → refused with the teardown" ;; *) t_fail "ki not ours: $OUT" ;; esac
expect_eq "kube_host_checks runs the node checks only on init's own context" "$(sed -n '/^kube_host_checks() {/,/^}/p' "$HERE"/../scripts/lib/kube.sh | grep -c '"${PORTCULLIS_KUBE_CONTEXT:-}" != "$(kube_install_context)" ] || \[ ! -s "$(kube_install_kubeconfig)" \] || _ki_node_checks')" 1
OUT="$(kt "mkdir -p '$PORTCULLIS_ROOT/secrets/kube' && echo x > '$PORTCULLIS_ROOT/secrets/kube/kubeconfig'; KUBE_LOCAL_ADDRS=; kube_host_checks | grep -c 'watchdog' ; rm -f '$PORTCULLIS_ROOT/secrets/kube/kubeconfig'")"
expect_eq "kube_host_checks: another context (ci) with init's kubeconfig present → no node checks" "$(printf '%s\n' "$OUT" | head -n1)" 0
# kube_install_run: the order is preflight → mesh → k3s, and the context.
OUT="$(kik 'kube_install_preflight() { echo pre; }; kube_install_mesh() { echo mesh; }; kube_install_k3s() { echo k3s; }; kube_install_run; echo "ctx=$PORTCULLIS_KUBE_CONTEXT"; _K_POD_CIDR=10.42.0.0/16 _K_SVC_CIDR=10.43.0.0/16 _K_API_EP=10.215.0.1:6443; kube_env_keys portcullis | grep K3S')"
expect_eq "kube_install_run: preflight, mesh, k3s in that order; context portcullis; PORTCULLIS_K3S_VERSION written" "$(printf '%s\n' "$OUT" | tr '\n' ' ')" "pre mesh k3s ctx=portcullis PORTCULLIS_K3S_VERSION=v1.37.2+k3s1 rc=0 "
expect_eq "kube_env_keys: no PORTCULLIS_K3S_VERSION for a named cluster" "$(kt 'kube_detect_cidrs; kube_env_keys ci | grep -c K3S' | head -n1)" 0
expect_eq "kube.sh doesn't grow (plan R8: new kube CLI code in kube_install.sh)" "$([ "$(wc -l < "$HERE/../scripts/lib/kube.sh")" -le 2326 ] && echo ok)" ok
k_fixtures
OUT="$(kt 'kube_host_checks')"
expect_eq "kube_host_checks: a prepared k3s → no fail line" "$(printf '%s\n' "$OUT" | grep -c '^fail' || true)" 0
case "$OUT" in *"ok	Kubernetes v1.37.2+k3s1"*"ok	PORTCULLIS_TRAEFIK_SERVICE_IP=10.43.0.20 is free"*"ok	namespace portcullis: not there yet"*"ok	namespace portcullis-storage: not there yet"*) t_pass "kube_host_checks: version, fixed ClusterIPs, the three namespaces" ;; *) t_fail "kube_host_checks ok: $OUT" ;; esac
sed -i.bak 's/"10.42.0.0\/24","fd00:10:42::\/56"/X/; s/"podCIDRs":\["10.42.0.0\/24"\]/"podCIDRs":["10.42.0.0\/24","fd00:42::\/56"]/; s/\\"10.42.0.0\/24\\"\]/\\"10.42.0.0\/24,fd00:42::\/56\\"]/' "$KS/kube/nodes.json"
OUT="$(kt 'kube_host_checks')"
case "$OUT" in *"fail	dual-stack or IPv6 cluster"*) t_pass "kube_host_checks: an IPv6 pod CIDR → refused" ;; *) t_fail "kube ipv6: $OUT" ;; esac
OUT="$(kt 'runtime_check')"
case "$OUT" in *"dual-stack or IPv6 cluster"*"rc=1") t_pass "runtime_check: an IPv6 pod CIDR → refused" ;; *) t_fail "kube ipv6 runtime_check: $OUT" ;; esac
k_fixtures
echo '{"serverVersion":{"gitVersion":"v1.32.13+k3s1"}}' > "$KS/kube/version.json"
OUT="$(kt 'kube_host_checks')"
case "$OUT" in *"fail	Kubernetes v1.32.13+k3s1: Portcullis needs >= 1.33"*) t_pass "kube_host_checks: server v1.32 → refused (the floor is 1.33)" ;; *) t_fail "kube v1.31: $OUT" ;; esac
k_fixtures
echo '{"kubeletconfig":{"podPidsLimit":-1}}' > "$KS/kube/configz.json"
sed -i.bak 's/\\"--secrets-encryption\\",//' "$KS/kube/nodes.json"
OUT="$(kt 'kube_host_checks')"
case "$OUT" in *"fail	k3s runs without --secrets-encryption"*"fail	kubelet podPidsLimit is -1"*) t_pass "kube_host_checks: no secrets encryption, no pod pids limit → refused" ;; *) t_fail "kube flags: $OUT" ;; esac
k_fixtures
jq '.items[0].metadata.annotations = {}' "$KS/kube/nodes.json" > "$KS/kube/n.json" && mv "$KS/kube/n.json" "$KS/kube/nodes.json"
OUT="$(kt 'kube_host_checks')"
case "$OUT" in *"fail	k3s, but its node-args (k3s.io/node-args) are unreadable"*) t_pass "kube_host_checks: k3s with unreadable node-args → refused (M2)" ;; *) t_fail "kube unreadable node-args: $OUT" ;; esac
echo '{"serverVersion":{"gitVersion":"v1.37.2"}}' > "$KS/kube/version.json"
OUT="$(kt 'kube_host_checks')"
case "$OUT" in *"warn	not k3s: secrets encryption"*) case "$OUT" in *"node-args (k3s.io/node-args) are unreadable"*) t_fail "kube not k3s: refused" ;; *) t_pass "kube_host_checks: not k3s, no node-args → a warning only" ;; esac ;; *) t_fail "kube not k3s: $OUT" ;; esac
k_fixtures
touch "$KS/kube/svcs.fail"
OUT="$(kt 'kube_host_checks')"
case "$OUT" in *"fail	can't list Services: the fixed ClusterIPs can't be checked free"*) case "$OUT" in *"is free"*) t_fail "kube svcs list failed: still called free" ;; *) t_pass "kube_host_checks: an unreadable Services list → refused, nothing called free (M1)" ;; esac ;; *) t_fail "kube svcs list failed: $OUT" ;; esac
k_fixtures
# Task 0 Q1: the public address is local but ServiceLB publishes another.
OUT="$(kt 'KUBE_LOCAL_ADDRS="10.1.0.4 203.0.113.7"; PORTCULLIS_PUBLIC_IPV4=203.0.113.7; kube_host_checks')"
case "$OUT" in *"warn	client IPs will be rewritten"*"--node-external-ip=203.0.113.7"*) t_pass "kube_host_checks: public IP local but not an LB ingress address → warning naming --node-external-ip" ;; *) t_fail "kube source ip: $OUT" ;; esac
case "$OUT" in *"fail	client IPs"*) t_fail "kube source ip: a refusal" ;; *) t_pass "kube_host_checks: the source-IP row is never a refusal" ;; esac
OUT="$(kt 'kube_host_checks')"
case "$OUT" in *"ok	client addresses kept: 198.51.100.1"*) t_pass "kube_host_checks: the public IP is the node's ExternalIP → ok" ;; *) t_fail "kube source ip ok: $OUT" ;; esac
# K8: :6443 / :10250 answering on the public address → a warning.
OUT="$(kt 'KUBE_TCP_PROBE=true; kube_host_checks')"
case "$OUT" in *"warn	port 6443 answers on the public address 198.51.100.1"*"warn	port 10250 answers"*) t_pass "kube_host_checks: the API / kubelet on the public address → warning (K8)" ;; *) t_fail "kube K8: $OUT" ;; esac
# The fixed ClusterIPs: in the static band and free.
echo '{"items":[{"metadata":{"namespace":"kube-system","name":"x"},"spec":{"clusterIP":"10.43.0.21"}},{"metadata":{"namespace":"portcullis","name":"traefik"},"spec":{"clusterIP":"10.43.0.20"}}]}' > "$KS/kube/svcs.json"
OUT="$(kt 'kube_host_checks')"
case "$OUT" in *"ok	PORTCULLIS_TRAEFIK_SERVICE_IP=10.43.0.20 is free"*"fail	PORTCULLIS_TRAEFIK_VPN_SERVICE_IP=10.43.0.21 is already taken by Service kube-system/x"*) t_pass "kube_host_checks: a fixed ClusterIP held by another Service → refused (ours is fine)" ;; *) t_fail "kube svc ip taken: $OUT" ;; esac
OUT="$(kt 'PORTCULLIS_WG_EDGE_SERVICE_IP=10.43.9.1; kube_host_checks')"
case "$OUT" in *"fail	PORTCULLIS_WG_EDGE_SERVICE_IP=10.43.9.1 is outside the service CIDR's static band (the first 256 addresses"*) t_pass "kube_host_checks: a fixed ClusterIP outside the static band → refused" ;; *) t_fail "kube band: $OUT" ;; esac
k_fixtures
# K11: a namespace Portcullis didn't create is never adopted.
echo '{"metadata":{"name":"portcullis","labels":{"kubernetes.io/metadata.name":"portcullis"}}}' > "$KS/kube/ns-portcullis.json"
OUT="$(kt 'kube_require_host')"
case "$OUT" in *"isn't ready for Portcullis"*"namespace portcullis exists but isn't this install's"*"rc=1") t_pass "init kubernetes: foreign portcullis namespace → refused" ;; *) t_fail "kube foreign ns: $OUT" ;; esac
echo '{"metadata":{"name":"portcullis","labels":{"app.kubernetes.io/managed-by":"portcullis"},"annotations":{"portcullis.io/install":"ffffffff-1111-4222-8333-444455556666"}}}' > "$KS/kube/ns-portcullis.json"
OUT="$(kt 'kube_require_host')"
case "$OUT" in *"namespace portcullis exists but isn't this install's"*"rc=1") t_pass "init kubernetes: our label but another install id → refused" ;; *) t_fail "kube other install: $OUT" ;; esac
echo '{"metadata":{"name":"portcullis","labels":{"app.kubernetes.io/managed-by":"portcullis"},"annotations":{"portcullis.io/install":"0b0e2b3c-1111-4222-8333-444455556666"}}}' > "$KS/kube/ns-portcullis.json"
OUT="$(kt 'kube_host_checks | grep "namespace portcullis "; kube_require_host')"
case "$OUT" in *"ok	namespace portcullis belongs to this install"*"rc=0") t_pass "init kubernetes: matching install id → adopted" ;; *) t_fail "kube adopt: $OUT" ;; esac
k_fixtures
# The NetworkPolicy probe: proven only when both refusals hold AND the allowed dial succeeds.
OUT="$(kt 'sleep() { :; }; kube_netpol_probe')"
case "$OUT" in *"NetworkPolicies are enforced"*"rc=0") t_pass "kube_netpol_probe: ingress and egress refusals hold, allowed succeeds → proven" ;; *) t_fail "kube probe ok: $OUT" ;; esac
expect_eq "kube_netpol_probe: proven → ConfigMap portcullis-netpol-probe (proven_at) in portcullis-apps, the probe namespace deleted" \
  "$(grep -c 'name: portcullis-netpol-probe' "$KS/kubectl-stdin"):$(grep -c 'namespace: portcullis-apps' "$KS/kubectl-stdin"):$(grep -c 'proven_at: "20' "$KS/kubectl-stdin"):$(grep -c 'delete namespace portcullis-netpol-probe' "$KS/kubectl-calls")" "1:1:1:2"
k_fixtures
OUT="$(kt 'sleep() { :; }; export STUB_DIAL_ALLOWED=1; kube_netpol_probe')"
case "$OUT" in *"the allowed connection failed"*"rc=1") t_pass "kube_netpol_probe: allowed dial fails → not proven" ;; *) t_fail "kube probe allowed fails: $OUT" ;; esac
expect_eq "kube_netpol_probe: not proven → ConfigMap not written, probe namespace deleted" "$(test -e "$KS/kubectl-stdin" && echo written || echo none):$(grep -c 'delete namespace portcullis-netpol-probe' "$KS/kubectl-calls")" "none:2"
# Each direction on its own: a cluster that ignores ingress OR egress
# policies fails the probe (the review's fail-open case: one client denied
# both ways would pass with only one direction enforced).
k_fixtures
OUT="$(kt 'sleep() { :; }; export STUB_DIAL_INGRESS=0; kube_netpol_probe')"
case "$OUT" in *"ingress NetworkPolicies are NOT enforced"*"rc=1") t_pass "kube_netpol_probe: ingress policies ignored (client-ingress gets through) → not proven" ;; *) t_fail "kube probe ingress ignored: $OUT" ;; esac
expect_eq "kube_netpol_probe: ingress ignored → ConfigMap not written" "$(test -e "$KS/kubectl-stdin" && echo written || echo none)" none
k_fixtures
OUT="$(kt 'sleep() { :; }; export STUB_DIAL_EGRESS=0; kube_netpol_probe')"
case "$OUT" in *"egress NetworkPolicies are NOT enforced"*"rc=1") t_pass "kube_netpol_probe: egress policies ignored (client-egress gets through) → not proven" ;; *) t_fail "kube probe egress ignored: $OUT" ;; esac
expect_eq "kube_netpol_probe: egress ignored → ConfigMap not written" "$(test -e "$KS/kubectl-stdin" && echo written || echo none)" none
# The manifests themselves: the server admits exactly client-allowed and
# client-egress; client-ingress has the only egress allowance besides the
# control's; default deny both ways.
expect_eq "kube/probe: the server's ingress admits [allowed, egress-test]; egress allowed for ingress-test and allowed only; default deny both ways" \
  "$(python3 - "$HERE/../kube/probe" <<'PY2'
import sys, yaml, glob
docs = [d for f in sorted(glob.glob(sys.argv[1] + "/*.yaml")) for d in yaml.safe_load_all(open(f)) if d]
pols = {d["metadata"]["name"]: d["spec"] for d in docs if d["kind"] == "NetworkPolicy"}
ing = [p for p in pols.values() if "Ingress" in p["policyTypes"] and p["podSelector"].get("matchLabels") == {"portcullis.io/probe": "server"}]
adm = sorted(ing[0]["ingress"][0]["from"][0]["podSelector"]["matchExpressions"][0]["values"])
egr = sorted(p["podSelector"]["matchLabels"]["portcullis.io/probe"] for p in pols.values() if p["policyTypes"] == ["Egress"])
dd = [n for n, p in pols.items() if p["podSelector"] == {} and sorted(p["policyTypes"]) == ["Egress", "Ingress"] and not p.get("ingress") and not p.get("egress")]
print(adm, egr, len(dd))
PY2
)" "['allowed', 'egress-test'] ['allowed', 'ingress-test'] 1"
expect_eq "kube/probe/*.yaml run PORTCULLIS_HELPER_IMAGE (the CLI's pinned helper)" \
  "$(grep -h 'image:' "$HERE"/../kube/probe/*.yaml | sed 's/.*image: //' | sort -u)" "$PORTCULLIS_HELPER_IMAGE"
# ── cluster setup (Task 14) ──
HUBD="ghcr.io/porelli/portcullis-hub@sha256:$(printf '%064d' 7)"
k_fixtures
CS_ROOT="$WORK/cs-root"; rm -rf "$CS_ROOT"; mkdir -p "$CS_ROOT/secrets"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD'; kube_cluster_setup")"
case "$OUT" in *"rc=0") t_pass "kube_cluster_setup: every step applies" ;; *) t_fail "kube_cluster_setup: $OUT" ;; esac
PJ="$(ls "$KS"/live/ConfigMap.portcullis-admission-params-*.json | head -n1)"
G1="$(jq -r '.data.generation' "$PJ")"
case "$G1" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) t_pass "params generation: 16 hex, the ConfigMap portcullis-admission-params-<generation>" ;; *) t_fail "params generation: $G1" ;; esac
expect_eq "cluster setup: params ConfigMap carries the resolved Hub digest, the Hub's ServiceAccount, the node and API /32s" \
  "$(jq -r --arg h "$HUBD" '.data | [.hubImage == $h, .hubServiceAccount == "system:serviceaccount:portcullis:portcullis-hub", .nodeAddresses == "10.1.0.4/32 198.51.100.1/32", .apiAddresses == "10.1.0.4/32", .corePorts == "80 443 51820 8000 8081 8443 8444"] | map(select(.)) | length' "$PJ")" 5
expect_eq "cluster setup: the params ConfigMap has exactly params.tmpl.yaml's keys" \
  "$(jq -r '.data | keys | join(" ")' "$PJ") " \
  "$(sed -n '/^data:/,$p' "$HERE/../kube/admission/params.tmpl.yaml" | sed -n 's/^  \([A-Za-z]*\): .*/\1/p' | sort | tr '\n' ' ')"
expect_eq "cluster setup: the ten bindings as <name>-<generation> on portcullis-admission-params-<generation>, labelled with their base name" \
  "$(jq -s -r --arg g "$G1" 'map(select(.metadata.labels["portcullis.io/params-generation"] == $g) | [.metadata.name == .metadata.labels["portcullis.io/binding"] + "-" + $g, .spec.paramRef.name == "portcullis-admission-params-" + $g] | all) | [length, all] | map(tostring) | join(":")' "$KS"/live/Binding.*.json)" "10:true"
expect_eq "cluster setup: the five apps bindings select portcullis-apps, the edge one portcullis-edge, (HA) the exec one the core namespace, nodeadm's tokens kube-system, the ingress one portcullis-ingress" \
  "$(jq -s -r --arg g "$G1" 'map(select(.metadata.labels["portcullis.io/params-generation"] == $g) | .spec.matchResources.namespaceSelector.matchLabels["kubernetes.io/metadata.name"]) | group_by(.) | map("\(.[0])=\(length)") | join(" ")' "$KS"/live/Binding.*.json)" \
  "kube-system=1 portcullis=2 portcullis-apps=5 portcullis-edge=1 portcullis-ingress=1"
expect_eq "cluster setup: first run → params, bindings, probe (3 requests), nothing older to delete" \
  "$(grep -E '^(apply bindings|probe|delete binding|delete params|stamp)' "$KS/order" | sed "s/$G1/G1/; s/^probe .*/probe/" | uniq -c | tr -s ' ' | tr '\n' ';')" " 1 apply bindings G1; 12 probe;"
expect_eq "cluster setup: every one of the ten bindings probed with its own object" \
  "$(grep '^probe portcullis-' "$KS/order" | sort | tr '\n' ' ')" "$(printf 'probe %s\n' $KUBE_BINDINGS | sort | tr '\n' ' ')"
expect_eq "cluster setup: the five namespaces with PSA labels and K11's label + install annotation (server-side)" \
  "$(jq -cs '[.[] | select(.kind == "Namespace") | [.metadata.name, .metadata.labels["pod-security.kubernetes.io/enforce"], .metadata.labels["pod-security.kubernetes.io/warn"], .metadata.labels["app.kubernetes.io/managed-by"], .metadata.annotations["portcullis.io/install"]]]' < <(grep -v '^---$' "$KS/kubectl-stdin" | jq -c 'select(type == "object")' 2>/dev/null))" \
  '[["portcullis","restricted","restricted","portcullis","0b0e2b3c-1111-4222-8333-444455556666"],["portcullis-apps","privileged","baseline","portcullis","0b0e2b3c-1111-4222-8333-444455556666"],["portcullis-storage","privileged","baseline","portcullis","0b0e2b3c-1111-4222-8333-444455556666"],["portcullis-edge","restricted","restricted","portcullis","0b0e2b3c-1111-4222-8333-444455556666"],["portcullis-ingress","privileged","baseline","portcullis","0b0e2b3c-1111-4222-8333-444455556666"]]'
# (10.1.0.4/32 three times: the storage namespace's API egress, and
# cnpg-system's operator policy — its API egress and its webhook source.)
expect_eq "cluster setup: CRDs and VAPs applied server-side (never Helm), bindings.yaml never applied under its own names, the storage API egress to each endpoint" \
  "$(grep -c 'apply --server-side --force-conflicts --field-manager=portcullis-cli -f .*charts/portcullis/crds/traefik-v3.7.17.yaml' "$KS/kubectl-calls"):$(grep -c 'apply --server-side .* -f .*kube/admission/policies.yaml' "$KS/kubectl-calls"):$(grep -c 'apply --server-side .* -f .*kube/admission/bindings.yaml' "$KS/kubectl-calls"):$(grep -c 'apply --server-side .* -f .*/bindings.json' "$KS/kubectl-calls"):$(grep -c '"cidr": "10.1.0.4/32"' "$KS/kubectl-stdin")" "1:1:0:1:3"
expect_eq "cluster setup: applied.json records every step (0600)" \
  "$(jq -r 'keys | join(" ")' "$CS_ROOT/secrets/kube/applied.json"):$(file_mode "$CS_ROOT/secrets/kube/applied.json")" "cluster.admission cluster.cnpg cluster.crds cluster.namespaces cluster.params cluster.priorities cluster.storage:600"
rm -f "$KS/order"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD'; kube_cluster_setup")"
expect_eq "cluster setup: unchanged params → the same generation re-applied and probed, nothing deleted, no Hub scaling" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(grep -c 'delete binding\|scale deploy/hub' "$KS/order" || true):$(grep -c '^probe' "$KS/order")" "rc=0:0:12"
rm -f "$KS/order"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD' PORTCULLIS_KUBE_NODE_ADDRESSES='10.1.0.4 198.51.100.7'; kube_cluster_setup")"
G2="$(grep '^apply bindings ' "$KS/order" | tail -n1 | cut -d' ' -f3)"
expect_eq "cluster setup: changed params → create-before-delete: the new generation's bindings, the probe, only then the older bindings deleted; the older params stamped, not deleted; the Hub never scaled" \
  "$(printf '%s\n' "$OUT" | tail -n1):$([ "$G2" != "$G1" ] && echo new-gen):$(grep -E '^(apply bindings|probe|delete binding|delete params|stamp|kubectl .*scale)' "$KS/order" | sed "s/$G2/G2/; s/$G1/G1/; s/^probe .*/probe/" | uniq -c | tr -s ' ' | tr '\n' ';')" \
  "rc=0:new-gen: 1 apply bindings G2; 12 probe; 1 delete binding portcullis-apps-guard-netpol-G1; 1 delete binding portcullis-apps-guard-pods-G1; 1 delete binding portcullis-apps-guard-services-G1; 1 delete binding portcullis-apps-guard-traefik-G1; 1 delete binding portcullis-apps-guard-workloads-G1; 1 delete binding portcullis-core-guard-exec-G1; 1 delete binding portcullis-edge-guard-routes-G1; 1 delete binding portcullis-ingress-guard-pods-G1; 1 delete binding portcullis-nodeadm-guard-tokens-G1; 1 delete binding portcullis-nodes-guard-labels-G1; 1 stamp portcullis-admission-params-G1;"
echo '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"portcullis-admission-params-ffffffffffffffff","labels":{"app.kubernetes.io/managed-by":"portcullis","portcullis.io/params-generation":"ffffffffffffffff"},"annotations":{"portcullis.io/orphaned-at":"a[$(touch '"$WORK"'/pwned)]"}},"data":{}}' > "$KS/live/ConfigMap.portcullis-admission-params-ffffffffffffffff.json"
echo '{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"portcullis-admission-params-evil","labels":{"app.kubernetes.io/managed-by":"portcullis","portcullis.io/params-generation":"x"},"annotations":{"portcullis.io/orphaned-at":"1"}},"data":{}}' > "$KS/live/ConfigMap.portcullis-admission-params-evil.json"
rm -f "$KS/order"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD' PORTCULLIS_KUBE_NODE_ADDRESSES='10.1.0.4 198.51.100.7' KUBE_PARAMS_GRACE=0; kube_cluster_setup")"
expect_eq "cluster setup: an orphaned older params ConfigMap is deleted once past the grace" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(grep -c "^delete params portcullis-admission-params-$G1$" "$KS/order")" "rc=0:1"
expect_eq "params GC: an orphaned-at that isn't a timestamp is never evaluated (no command ran), the ConfigMap kept; a foreign name never touched" \
  "$(test -e "$WORK/pwned" && echo PWNED || echo safe):$(test -e "$KS/live/ConfigMap.portcullis-admission-params-ffffffffffffffff.json" && echo kept):$(printf '%s' "$OUT" | grep -c "isn't a timestamp"):$(test -e "$KS/live/ConfigMap.portcullis-admission-params-evil.json" && echo kept):$(printf '%s' "$OUT" | grep -c 'not an admission params name')" \
  "safe:kept:1:kept:1"
rm -f "$KS/live/ConfigMap.portcullis-admission-params-ffffffffffffffff.json" "$KS/live/ConfigMap.portcullis-admission-params-evil.json"
rm -f "$KS/order"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD' PORTCULLIS_KUBE_NODE_ADDRESSES='10.1.0.4 198.51.100.8' KUBE_ADMISSION_PROBE_WAIT=0; export STUB_PROBE_STALE=1; kube_cluster_setup")"
case "$OUT" in *"aren't live with their params"*"the older bindings still judge"*"rc=1") t_pass "cluster setup: the new generation doesn't probe live → refused, the older bindings kept" ;; *) t_fail "cluster setup stale probe: $OUT" ;; esac
rm -f "$KS/order"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD' PORTCULLIS_KUBE_NODE_ADDRESSES='10.1.0.4 198.51.100.8' KUBE_ADMISSION_PROBE_WAIT=0; export STUB_PROBE_STALE_BINDING=portcullis-apps-guard-netpol; kube_cluster_setup")"
case "$OUT" in *"not live with generation"*"portcullis-apps-guard-netpol"*"aren't live with their params"*"rc=1") t_pass "cluster setup: one binding of the six (netpol) not live → refused, the older bindings kept" ;; *) t_fail "cluster setup one stale binding: $OUT" ;; esac
expect_eq "cluster setup: one stale binding deletes nothing" "$(grep -c '^delete binding' "$KS/order" || true)" 0
expect_eq "cluster setup: a failed probe deletes no binding" "$(grep -c '^delete binding' "$KS/order" || true):$(ls "$KS"/live/Binding.*-"$G2".json | wc -l | tr -d ' ')" "0:10"
rm -f "$KS/order"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD' PORTCULLIS_KUBE_NODE_ADDRESSES='10.1.0.4 198.51.100.9'; export STUB_BINDINGS_FAIL=1; kube_cluster_setup")"
case "$OUT" in *"could not create the admission bindings of params generation"*"the older ones still judge"*"rc=1") t_pass "cluster setup: the new bindings can't be created → refused, nothing deleted" ;; *) t_fail "cluster setup bindings failure: $OUT" ;; esac
expect_eq "cluster setup: failed bindings → the older bindings kept" "$(grep -c '^delete binding' "$KS/order" || true):$(ls "$KS"/live/Binding.*-"$G2".json | wc -l | tr -d ' ')" "0:10"
echo '{"items":[{"kind":"IngressRoute","metadata":{"name":"app-ok","labels":{"portcullis.io/instance":"a"}}},{"kind":"IngressRoute","metadata":{"name":"app-bad","labels":{"portcullis.io/instance":"b"}},"spec":{"x":"REFUSE-ME"}}]}' > "$KS/kube/edge-hub-ir.json"
rm -f "$KS/order"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD'; kube_cluster_setup")"
expect_eq "cluster setup: every owner=hub edge object re-judged; the one the new policies refuse deleted and named" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(grep -c '^delete ir' "$KS/order"):$(grep -c '^delete ir app-bad$' "$KS/order"):$(printf '%s' "$OUT" | grep -c 'refuse ingressroutes app-bad (instance b): deleted')" "rc=0:1:1:1"
rm -f "$KS/kube/edge-hub-ir.json"
k_fixtures
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD' PORTCULLIS_APPS_NAMESPACE=team-apps; export STUB_APPS_NS=team-apps; kube_cluster_setup")"
expect_eq "cluster setup, PORTCULLIS_APPS_NAMESPACE=team-apps: the five apps bindings select team-apps, the edge one portcullis-edge (the HA ones unchanged)" \
  "$(printf '%s\n' "$OUT" | tail -n1) $(jq -s -r 'map(.spec.matchResources.namespaceSelector.matchLabels["kubernetes.io/metadata.name"]) | group_by(.) | map("\(.[0])=\(length)") | join(" ")' "$KS"/live/Binding.*.json)" \
  "rc=0 kube-system=1 portcullis=2 portcullis-edge=1 portcullis-ingress=1 team-apps=5"
expect_eq "no Hub scaling around the admission bindings (create-before-delete needs none)" "$(declare -f kube_admission_params_apply kube_cluster_setup | grep -c '_kube_scale\|deployment hub' || true)" 0
k_fixtures
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD'; export STUB_WHOAMI_FAIL=1; kube_cluster_setup")"
case "$OUT" in *"the admission params can't be built"*"rc=1") case "$(cat "$KS/kubectl-stdin" 2>/dev/null)" in *portcullis-admission-params*) t_fail "cluster setup wrote params after a refusal" ;; *) t_pass "cluster setup: a params refusal (no CLI identity) stops the setup, no params written" ;; esac ;; *) t_fail "cluster setup params refusal: $OUT" ;; esac
k_fixtures
echo '{"items":[{"metadata":{"name":"stray-tls"}}]}' > "$KS/kube/edge-secrets.json"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD'; kube_cluster_setup")"
case "$OUT" in *"the namespace portcullis-edge holds 1 Secrets: Traefik reads every Secret there"*"rc=1") t_pass "cluster setup: a Secret in the edge namespace (Traefik reads it) → refused" ;; *) t_fail "cluster setup edge secret: $OUT" ;; esac
k_fixtures
rm -rf "$CS_ROOT/secrets/kube"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD'; export STUB_APPLY_FAIL_MATCH=kube/admission/policies.yaml; kube_cluster_setup")"
case "$OUT" in *"could not apply the admission policies"*"rc=1") t_pass "cluster setup: a failed VAP apply fails the setup" ;; *) t_fail "cluster setup VAP failure: $OUT" ;; esac
expect_eq "cluster setup: a failed VAP apply leaves applied.json without the admission and params steps" \
  "$(jq -r 'keys | join(" ")' "$CS_ROOT/secrets/kube/applied.json")" "cluster.cnpg cluster.crds cluster.namespaces cluster.priorities cluster.storage"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE=ghcr.io/porelli/portcullis-hub:edge; kube_cluster_setup")"
case "$OUT" in *"isn't resolved to a digest"*"rc=1") t_pass "cluster setup: an unresolved Hub tag → refused (the params pin a digest)" ;; *) t_fail "cluster setup tag: $OUT" ;; esac
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' KUBE_HUB_IMAGE='$HUBD' PORTCULLIS_KUBE_NODE_ADDRESSES=' '; kube_ctl() { [ \"\$1 \$2\" = 'get nodes' ] && { echo '{\"items\":[]}'; return 0; }; command kubectl --context ci \"\$@\"; }; kube_admission_params x")"
case "$OUT" in *"no node address"*"rc=1") t_pass "admission params: no node address → refused (never params that can't exclude the nodes)" ;; *) t_fail "admission params no nodes: $OUT" ;; esac
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT'; export STUB_WHOAMI_FAIL=1; kube_admission_params x")"
case "$OUT" in *"can't tell this CLI's own identity"*"rc=1") t_pass "admission params: the CLI's identity unknown → refused (portcullis-edge-routes exempts it by name)" ;; *) t_fail "admission params whoami: $OUT" ;; esac
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' PORTCULLIS_DOMAIN=K.Example.org; kube_admission_params x | grep -E '^(reservedHosts|maxAppPriority)'" | tr '\t' '=' | sed -n '1,2p' | tr '\n' ';')"
expect_eq "admission params: reservedHosts = the apex + core-routes.json's subdomains (lowercase), maxAppPriority from core-routes.json" "$OUT" \
  "reservedHosts=k.example.org traefik.k.example.org hub.k.example.org directory.k.example.org metrics.k.example.org people.k.example.org mcp.k.example.org auth.k.example.org enroll.k.example.org;maxAppPriority=1000;"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT'; unset PORTCULLIS_DOMAIN; kube_reserved_hosts")"
case "$OUT" in *"PORTCULLIS_DOMAIN is not set"*"rc=1") t_pass "reservedHosts: no domain → refused" ;; *) t_fail "reservedHosts no domain: $OUT" ;; esac
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT'; unset PORTCULLIS_DOMAIN; kube_admission_params x")"
case "$OUT" in *"PORTCULLIS_DOMAIN is not set"*"rc=1") case "$OUT" in *reservedHosts*) t_fail "admission params written without a domain: $OUT" ;; *) t_pass "admission params: no domain → refused before any key is printed" ;; esac ;; *) t_fail "admission params no domain: $OUT" ;; esac
expect_eq "admission reservedHosts example = core-routes.json for portcullis.local" "$(sed -n 's/^  reservedHosts: //p' "$HERE/../kube/admission/params.yaml")" \
  "$(PORTCULLIS_DOMAIN=portcullis.local kube_reserved_hosts)"
OUT="$(kt "PORTCULLIS_ROOT='$CS_ROOT' PORTCULLIS_DOMAIN=k.example.org; kube_admission_params x | grep -E '^(cliUsername|appsNamespace|edgeNamespace|edgeCoreMiddlewares)'" | tr '\t' '=' | sed -n '1,4p' | tr '\n' ';')"
expect_eq "admission params: the CLI's identity (auth whoami), the apps / edge namespaces, the core edge Middlewares" "$OUT" \
  "cliUsername=system:admin;appsNamespace=portcullis-apps;edgeNamespace=portcullis-edge;edgeCoreMiddlewares=$KUBE_EDGE_CORE_MIDDLEWARES;"
# setup.sh (K3): uid / gid 1–65535, 3–4 octal digits; mkdir -m 0700, chmod, then chown;
# anything else refused, nothing created.
SB="$WORK/setupbin"; mkdir -p "$SB"
printf '#!/bin/sh\necho "chown $*" >> "$SETUP_LOG"\n' > "$SB/chown"; chmod +x "$SB/chown"
printf '#!/bin/sh\necho "mkdir $*" >> "$SETUP_LOG"\nexec /bin/mkdir "$@"\n' > "$SB/mkdir"; chmod +x "$SB/mkdir"
printf '#!/bin/sh\necho "chmod $*" >> "$SETUP_LOG"\nexec /bin/chmod "$@"\n' > "$SB/chmod"; chmod +x "$SB/chmod"
# stat -c %a: GNU (Linux CI) as is; BSD (macOS) through stat -f %Lp.
if stat -c %a / >/dev/null 2>&1; then :; else printf '#!/bin/sh\n[ "$1" = -c ] && shift 2\nm="$(/usr/bin/stat -f %%Mp%%Lp "$1")"; echo "${m#0}"\n' > "$SB/stat"; chmod +x "$SB/stat"; fi
# The parent carries the runner's own group: BSD (macOS) drops a setgid bit
# chmod sets on a directory whose group the caller isn't in.
mkdir -p "$WORK/volp"; chgrp "$(id -g)" "$WORK/volp"
setup_run() { rm -rf "$WORK/volp/vol" "$WORK/setup.log"; ( export PATH="$SB:$PATH" SETUP_LOG="$WORK/setup.log" VOL_DIR="$WORK/volp/vol" VOL_USER="$1" VOL_GROUP="$2" VOL_PERM="$3"; sh "$HERE/../kube/storage/setup.sh" ) 2>&1; echo "rc=$?"; }
OUT="$(setup_run 10001 10001 0750)"
expect_eq "setup.sh 10001/10001/0750 → mkdir 0700, chmod 0750, then chown 10001:10001" "$OUT|$(file_mode "$WORK/volp/vol")|$(cat "$WORK/setup.log" | tr '\n' ';')" "rc=0|750|mkdir -m 0700 $WORK/volp/vol;chmod 0750 $WORK/volp/vol;chown 10001:10001 $WORK/volp/vol;"
OUT="$(setup_run 10006 10001 2750)"
expect_eq "setup.sh 10006/10001/2750 → chmod 2750 while root's, then chown (a chmod without CAP_FSETID outside the group drops setgid; a chown keeps it on a directory); the directory is 2750" \
  "$OUT|$(cat "$WORK/setup.log" | tr '\n' ';')|$(file_mode "$WORK/volp/vol")" "rc=0|mkdir -m 0700 $WORK/volp/vol;chmod 2750 $WORK/volp/vol;chown 10006:10001 $WORK/volp/vol;|2750"
# A mode that doesn't stick is caught, read back after the chown: a chmod
# that drops setgid, or a chown that clears it, refuses.
printf '#!/bin/sh\necho "chmod $*" >> "$SETUP_LOG"\nexec /bin/chmod 0750 "$2"\n' > "$SB/chmod.lossy"
OUT="$(mv "$SB/chmod" "$SB/chmod.real"; cp "$SB/chmod.lossy" "$SB/chmod"; chmod +x "$SB/chmod"; setup_run 10006 10001 2750; mv "$SB/chmod.real" "$SB/chmod")"
case "$OUT" in *"portcullis-setup REFUSED:"*"is mode 750 after chmod 2750 and chown (want 2750)"*"rc=1") t_pass "setup.sh: a mode that doesn't stick (750 for 2750) refuses" ;; *) t_fail "setup.sh lossy chmod: $OUT" ;; esac
# g-s, not a numeric mode: GNU chmod keeps a directory's setgid for 0750.
printf '#!/bin/sh\necho "chown $*" >> "$SETUP_LOG"\nexec /bin/chmod g-s "$2"\n' > "$SB/chown.lossy"
OUT="$(mv "$SB/chown" "$SB/chown.real"; cp "$SB/chown.lossy" "$SB/chown"; chmod +x "$SB/chown"; setup_run 10006 10001 2750; mv "$SB/chown.real" "$SB/chown")"
case "$OUT" in *"portcullis-setup REFUSED:"*"is mode 750 after chmod 2750 and chown (want 2750)"*"rc=1") t_pass "setup.sh: a chown that clears setgid refuses (the mode is read back after it)" ;; *) t_fail "setup.sh lossy chown: $OUT" ;; esac
expect_eq "setup.sh: a refusal after the mkdir removes the directory (a retry can succeed)" "$(test -e "$WORK/volp/vol" && echo left || echo removed)" removed
OUT="$(setup_run 10006 10001 2750)"
expect_eq "setup.sh: the retry after a refusal succeeds" "$OUT|$(file_mode "$WORK/volp/vol")" "rc=0|2750"
for bad in ":10001:0750:uid ''" "x:10001:0750:uid 'x'" "65536:10001:0750:uid '65536'" "10001::0750:gid ''" "10001:0:0750:gid '0'" "10001:10001::mode ''" "10001:10001:0789:mode '0789'" "10001:10001:75:mode '75'" "010001:10001:0750:uid '010001'"; do
  IFS=: read -r u g m why <<< "$bad"
  OUT="$(setup_run "$u" "$g" "$m")"
  case "$OUT" in *"portcullis-setup REFUSED: bad $why"*"rc=1") ok_case=1 ;; *) ok_case=0 ;; esac
  expect_eq "setup.sh $u/$g/$m → REFUSED (bad $why), nothing created" "$ok_case:$(test -e "$WORK/vol" && echo made || echo none):$(test -e "$WORK/setup.log" && echo chown || echo none)" "1:none:none"
done
expect_eq "the provisioner: --service-account-name its own SA, --provisioner-name portcullis.io/local-path, the pinned image, never --allow-unsafe-helper-pod-template" \
  "$(grep -A1 -- '- --service-account-name' "$HERE/../kube/storage/provisioner.yaml" | tail -n1 | tr -d ' -'):$(grep -c 'portcullis.io/local-path' "$HERE/../kube/storage/provisioner.yaml" | awk '{print ($1>0)}'):$(grep -c 'image: docker.io/rancher/local-path-provisioner:v0.0.37@sha256:e757967a5ec338f6a9b371c5a9688bedaa8c3578ea3dd4db329ea0084be0a86f' "$HERE/../kube/storage/provisioner.yaml"):$(grep -rc 'allow-unsafe-helper-pod-template' "$HERE/../kube/storage" | awk -F: '{s+=$2} END {print s}')" "portcullislocalpath:1:1:1"
expect_eq "the helper pod: PORTCULLIS_HELPER_IMAGE, uid 0, the 11 other default caps dropped by name (CHOWN, DAC_OVERRIDE, FOWNER kept), nothing added" \
  "$(sed -n 's/.*image: //p' "$HERE/../kube/storage/helper-pod.yaml"):$(python3 -c 'import sys, yaml; c = yaml.safe_load(open(sys.argv[1]))["spec"]["containers"][0]["securityContext"]; print(c["runAsUser"], sorted(c["capabilities"]["drop"]) == sorted(["AUDIT_WRITE","FSETID","KILL","MKNOD","NET_BIND_SERVICE","NET_RAW","SETFCAP","SETGID","SETPCAP","SETUID","SYS_CHROOT"]), "add" in c["capabilities"], c["allowPrivilegeEscalation"], c["readOnlyRootFilesystem"])' "$HERE/../kube/storage/helper-pod.yaml")" \
  "$PORTCULLIS_HELPER_IMAGE:0 True False False True"
expect_eq "kube/storage/admission.yaml pins the same helper and provisioner images" \
  "$(grep -c "c.image == '$PORTCULLIS_HELPER_IMAGE'" "$HERE/../kube/storage/admission.yaml"):$(grep -c "c.image == 'docker.io/rancher/local-path-provisioner:v0.0.37@sha256:e757967a5ec338f6a9b371c5a9688bedaa8c3578ea3dd4db329ea0084be0a86f'" "$HERE/../kube/storage/admission.yaml")" "1:1"
expect_eq "StorageClasses: portcullis-core Retain, portcullis-apps Delete, both portcullis.io/local-path with the three owner patterns, never volumeType local" \
  "$(python3 -c 'import sys, yaml; print([(d["metadata"]["name"], d["reclaimPolicy"], d["provisioner"], sorted(d["parameters"]), "volumeType" in d["parameters"]) for d in yaml.safe_load_all(open(sys.argv[1]))])' "$HERE/../kube/storage/storageclasses.yaml")" \
  "[('portcullis-core', 'Retain', 'portcullis.io/local-path', ['groupPattern', 'permPattern', 'userPattern'], False), ('portcullis-apps', 'Delete', 'portcullis.io/local-path', ['groupPattern', 'permPattern', 'userPattern'], False)]"
expect_eq "kube/admission: ten policies (policies.yaml + nodeadm-tokens.yaml), ten bindings (portcullis-apps-guard-<policy>, portcullis-edge-guard-routes, HA: portcullis-core-guard-exec, portcullis-nodeadm-guard-tokens, portcullis-ingress-guard-pods; Deny, params missing = Deny, Fail)" \
  "$(python3 -c 'import sys, yaml; P = [d for f in sys.argv[2:] for d in yaml.safe_load_all(open(f)) if d]; B = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]; print(sorted(p["metadata"]["name"] for p in P), all(p["spec"]["failurePolicy"] == "Fail" for p in P), sorted((b["metadata"]["name"], b["spec"]["policyName"], b["spec"]["validationActions"] == ["Deny"], b["spec"]["paramRef"]["parameterNotFoundAction"]) for b in B))' "$HERE/../kube/admission/bindings.yaml" "$HERE/../kube/admission/policies.yaml" "$HERE/../kube/admission/nodeadm-tokens.yaml")" \
  "['portcullis-apps-netpol', 'portcullis-apps-pods', 'portcullis-apps-services', 'portcullis-apps-traefik', 'portcullis-apps-workloads', 'portcullis-core-exec', 'portcullis-edge-routes', 'portcullis-ingress-pods', 'portcullis-node-labels', 'portcullis-nodeadm-tokens'] True [('portcullis-apps-guard-netpol', 'portcullis-apps-netpol', True, 'Deny'), ('portcullis-apps-guard-pods', 'portcullis-apps-pods', True, 'Deny'), ('portcullis-apps-guard-services', 'portcullis-apps-services', True, 'Deny'), ('portcullis-apps-guard-traefik', 'portcullis-apps-traefik', True, 'Deny'), ('portcullis-apps-guard-workloads', 'portcullis-apps-workloads', True, 'Deny'), ('portcullis-core-guard-exec', 'portcullis-core-exec', True, 'Deny'), ('portcullis-edge-guard-routes', 'portcullis-edge-routes', True, 'Deny'), ('portcullis-ingress-guard-pods', 'portcullis-ingress-pods', True, 'Deny'), ('portcullis-nodeadm-guard-tokens', 'portcullis-nodeadm-tokens', True, 'Deny'), ('portcullis-nodes-guard-labels', 'portcullis-node-labels', True, 'Deny')]"
expect_eq "KUBE_BINDINGS lists portcullis-nodeadm-guard-tokens (and the other HA bindings), never a guard on admission objects (R-ADM)" \
  "$(for b in portcullis-core-guard-exec portcullis-nodeadm-guard-tokens portcullis-ingress-guard-pods portcullis-nodes-guard-labels; do case " $KUBE_BINDINGS " in *" $b "*) printf y ;; *) printf n ;; esac; done):$(printf '%s\n' $KUBE_BINDINGS | grep -c 'nodeadm-guard-admission')" yyyy:0
expect_eq "cluster setup applies the two policy files (KUBE_POLICY_FILES), never a binding of them" \
  "$KUBE_POLICY_FILES:$(grep -c 'kind: ValidatingAdmissionPolicyBinding' "$HERE/../kube/admission/nodeadm-tokens.yaml" "$HERE/../kube/admission/policies.yaml" | awk -F: '{s += $2} END {print s}')" "policies.yaml nodeadm-tokens.yaml:0"
# Every pod the CLI builds itself (keygen, the volume helpers) names
# portcullis-core (Task 18 ruling I5); only the server dry-run probes don't.
expect_eq "the CLI's jq-built pods name priorityClassName portcullis-core (the dry-run probes aside)" \
  "$(python3 - "$HERE"/../scripts/lib/*.sh <<'PY3'
import re, sys
bad = []
for f in sys.argv[1:]:
    lines = open(f).read().split("\n")
    fn = ""
    for i, l in enumerate(lines):
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\(\) \{", l)
        if m:
            fn = m.group(1)
        if 'kind: "Pod"' in l and fn not in ("_kube_probe_object", "_kube_probe_ha"):
            if 'priorityClassName: "portcullis-core"' not in "\n".join(lines[i:i + 4]):
                bad.append(f"{f.rsplit('/', 1)[-1]}:{i + 1} ({fn})")
print(" ".join(bad))
PY3
)" ""
expect_eq "cluster setup applies kube/priorityclasses.yaml (server-side) before the storage step (the provisioner names portcullis-core)" \
  "$(awk '/apply --server-side .* -f .*kube\/priorityclasses.yaml/ { p = NR } /apply --server-side .* -f .*kube\/storage\/namespace.yaml/ { s = NR } END { print (p > 0 && p < s) ? "first" : "p=" p " s=" s }' "$KS/kubectl-calls")" first
expect_eq "the CLI's KUBE_BINDINGS = bindings.yaml's names" \
  "$(python3 -c 'import sys, yaml; print(" ".join(d["metadata"]["name"] for d in yaml.safe_load_all(open(sys.argv[1])) if d))' "$HERE/../kube/admission/bindings.yaml")" "$KUBE_BINDINGS"
expect_eq "admission edgeCoreMiddlewares = the CLI's KUBE_EDGE_CORE_MIDDLEWARES = the params example's" "$(sed -n 's/^  edgeCoreMiddlewares: //p' "$HERE/../kube/admission/params.yaml")" "$KUBE_EDGE_CORE_MIDDLEWARES"
expect_eq "admission fileMiddlewares = the CLI's KUBE_FILE_NAMES = the params example's" "$(sed -n 's/^  fileMiddlewares: //p' "$HERE/../kube/admission/params.yaml")" "$KUBE_FILE_NAMES"
# ── Task 15: sync, values, the release, one-shots, restore, VPN, revocation ──
# shellcheck source=../scripts/lib/signin.sh
source "$HERE/../scripts/lib/signin.sh"
# shellcheck source=../scripts/lib/users.sh
source "$HERE/../scripts/lib/users.sh"
K15="$WORK/k15"
k15_root() {
  rm -rf "$K15"; mkdir -p "$K15/secrets/hub/lldap" "$K15/secrets/wg" "$K15/secrets/domains/certs-endpoint" "$K15/secrets/kube" "$K15/certs/revocation" "$K15/certs/truststore"
  printf 'SECRET-LLDAP-PW-123' > "$K15/secrets/hub/lldap/password"
  # LLDAP's key seed (users.sh; kube_sync_secrets refuses without one).
  mkdir -p "$K15/secrets/lldap"; printf 'LLDAPSEEDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' > "$K15/secrets/lldap/key-seed"
  printf 'portcullis-hub' > "$K15/secrets/hub/lldap/username"
  printf '{"root_token":"ROOT-TOKEN-XYZ"}' > "$K15/secrets/vault-init.json"
  printf 'CA-KEY-SECRET' > "$K15/secrets/domains/certs-endpoint/ca.key"
  printf 'client' > "$K15/secrets/domains/certs-endpoint/client.crt"
  : > "$K15/secrets/wg/people.key"
  printf 'cert' > "$K15/certs/ca-chain.crt"; printf 'KEY' > "$K15/certs/server.key"; printf '1a\n' > "$K15/certs/revocation/revoked-serials.txt"
  echo "PORTCULLIS_DOMAIN=k.example.org" > "$K15/.env"
}
K15_ENV="export PORTCULLIS_ROOT='$K15' FORWARD_AUTH_REDIS_PASSWORD=FA-REDIS-SECRET-111 FORWARD_AUTH_EXT_REDIS_PASSWORD=FAX-REDIS-SECRET-222 POSTGRES_PASSWORD=PG-SECRET-777 HUB_PROXY_SECRET=HUB-PROXY-SECRET-555 HUB_CLI_PROXY_SECRET=HUB-CLI-SECRET-666 KEYCLOAK_ADMIN_PASSWORD=KC-SECRET PORTCULLIS_DOMAIN=k.example.org PORTCULLIS_TRAEFIK_SERVICE_IP=10.43.0.20 PORTCULLIS_TRAEFIK_VPN_SERVICE_IP=10.43.0.21 PORTCULLIS_WG_EDGE_SERVICE_IP=10.43.0.22"
k_fixtures; k15_root; rm -f "$KS/order"
OUT="$(kt "set -euo pipefail; $K15_ENV; kube_sync_secrets" </dev/null)"
expect_eq "sync: every object applied (under set -euo pipefail)" "$(printf '%s\n' "$OUT" | tail -n1)" "rc=0"
expect_eq "sync: no secret on argv (kubectl / helm argv recorded)" \
  "$(cat "$KS/kubectl-calls" "$KS/helm-calls" 2>/dev/null | grep -cE 'SECRET-LLDAP-PW-123|PG-SECRET-777|HUB-PROXY-SECRET-555|KC-SECRET|ROOT-TOKEN-XYZ|CA-KEY-SECRET' || true)" 0
expect_eq "sync: Secrets from secrets/ dirs (--from-file), portcullis-env, ConfigMaps; never vault-init.json or the endpoint CA key" \
  "$(grep -cE 'create secret generic secrets-hub-lldap .*--from-file=|create secret generic portcullis-env .*--from-file=|create configmap certs-revocation .*--from-file=|create secret generic secrets-certs .*--from-file=' "$KS/kubectl-calls"):$(grep -rlE 'ROOT-TOKEN-XYZ|CA-KEY-SECRET' "$KS/kubectl-stdin" 2>/dev/null | wc -l | tr -d ' ')" "4:0"
expect_eq "sync: the session store's HA configs (plan Task 25) as the Secret secrets-sessions-ha, the oauth2-proxies' passwords never on argv or in it" \
  "$(grep -cE 'create secret generic secrets-sessions-ha .*--from-file=' "$KS/kubectl-calls"):$(cat "$KS/kubectl-calls" "$K15/secrets/sessions-ha"/* | grep -cE 'FA-REDIS-SECRET-111|FAX-REDIS-SECRET-222' || true)" "1:0"
expect_eq "sync: the hub-proxy-secret Middleware from stdin (jq), its secret not on argv" \
  "$(grep -c '"X-Portcullis-Proxy-Secret": "HUB-PROXY-SECRET-555"' "$KS/kubectl-stdin"):$(grep -c 'HUB-PROXY-SECRET-555' "$KS/kubectl-calls" || true)" "1:0"
expect_eq "sync: the hub-cli-proxy-secret Middleware from stdin (jq), its secret not on argv" \
  "$(grep -c '"X-Portcullis-Proxy-Secret": "HUB-CLI-SECRET-666"' "$KS/kubectl-stdin"):$(grep -c 'HUB-CLI-SECRET-666' "$KS/kubectl-calls" || true)" "1:0"
# The live objects decide (no local cache): unchanged → nothing put; a hand
# edit, a hand-added key or a deleted object → corrected; --full,
# KUBE_SYNC_FULL=1 or an unreadable live list → every object put.
k15_puts() { grep -c '^put .* \(Secret\|ConfigMap\)\.' "$KS/order" 2>/dev/null || true; }
expect_eq "sync: the first run creates every object (no live one yet)" \
  "$(grep -c '^put create Secret.portcullis-env$' "$KS/order"):$(grep -c '^put replace ' "$KS/order" || true)" "1:0"
rm -f "$KS/order"
kt "$K15_ENV; kube_sync_secrets" >/dev/null
expect_eq "sync: live objects equal → none put again (only the two proxy-secret Middlewares)" \
  "$(k15_puts):$(grep -c '^put .* Middleware.hub-proxy-secret$' "$KS/order"):$(grep -c '^put .* Middleware.hub-cli-proxy-secret$' "$KS/order")" "0:1:1"
jq '.data.password = "SEFDS0VE" | .data.extra = "eA=="' "$KS/live/Secret.secrets-hub-lldap.json" > "$KS/live.tmp" && mv "$KS/live.tmp" "$KS/live/Secret.secrets-hub-lldap.json"
rm -f "$KS/live/ConfigMap.certs-revocation.json" "$KS/order"
kt "$K15_ENV; kube_sync_secrets" >/dev/null
expect_eq "sync: a live Secret changed by hand (value and an added key) is replaced as staged; a deleted ConfigMap is created; nothing else put" \
  "$(grep -c '^put replace Secret.secrets-hub-lldap$' "$KS/order"):$(grep -c '^put create ConfigMap.certs-revocation$' "$KS/order"):$(k15_puts):$(jq -r '[.data.password, (.data | has("extra"))] | join(",")' "$KS/live/Secret.secrets-hub-lldap.json")" \
  "1:1:2:$(printf 'SECRET-LLDAP-PW-123' | base64),false"
printf 'CHANGED' > "$K15/secrets/hub/lldap/password"
rm -f "$KS/order"
kt "$K15_ENV; kube_sync_secrets" >/dev/null
expect_eq "sync: a changed file → only its object put" "$(k15_puts):$(grep -c '^put replace Secret.secrets-hub-lldap$' "$KS/order")" "1:1"
N_OBJ="$(find "$KS/live" -name 'Secret.*' -o -name 'ConfigMap.*' | wc -l | tr -d ' ')"
rm -f "$KS/order"
kt "$K15_ENV; kube_sync_secrets --full" >/dev/null
expect_eq "sync --full: every object put without comparing" "$(k15_puts)" "$N_OBJ"
rm -f "$KS/order"
kt "$K15_ENV; KUBE_SYNC_FULL=1 kube_sync_secrets" >/dev/null
expect_eq "sync with KUBE_SYNC_FULL=1 (restore): every object put" "$(k15_puts)" "$N_OBJ"
rm -f "$KS/order"
OUT="$(kt "$K15_ENV; STUB_LIVE_LIST_FAIL=1 kube_sync_secrets" 2>&1)"
case "$OUT" in *"can't list the live Secrets / ConfigMaps of portcullis: syncing every object"*"rc=0") t_pass "sync: an unreadable live list → every object put (warned)" ;; *) t_fail "sync live list failure: $OUT" ;; esac
expect_eq "sync: an unreadable live list puts every object" "$(k15_puts)" "$N_OBJ"
expect_eq "sync: the hub-proxy-secret Middleware lives in the edge namespace (Traefik's only one)" \
  "$(jq -r '.metadata.namespace' "$KS/live/Middleware.hub-proxy-secret.json")" "portcullis-edge"
expect_eq "sync: no secrets/kube/applied.json object cache is read or written" \
  "$(grep -c 'objects' <(declare -f kube_sync_secrets _rtk_up) || true):$(jq -r 'has("objects")' "$K15/secrets/kube/applied.json" 2>/dev/null || echo none)" "0:none"
expect_eq "restore: the Vault step and the whole restore force a full sync" \
  "$(declare -f _kube_restore_vault | grep -c 'kube_sync_secrets --full'):$(declare -f _backup_restore_kube | grep -c 'export KUBE_SYNC_FULL=1')" "1:1"
SH="$WORK/strip"; rm -rf "$SH"; mkdir -p "$SH/kube" "$SH/domains" "$SH/hub"; : > "$SH/kube/values.yaml"; : > "$SH/kube/applied.json"; : > "$SH/hub/core.env"
_strip_host_files "$SH"
expect_eq "backups / restores never carry secrets/kube (_strip_host_files)" "$(test -e "$SH/kube" && echo kept || echo gone):$(test -e "$SH/hub/core.env" && echo kept || echo gone)" "gone:kept"
# values: no secret, every key; a missing required one refused
k15_root
OUT="$(kt "$K15_ENV; _K_IMAGES='{\"hub\":\"ghcr.io/porelli/portcullis-hub@sha256:$(printf '%064d' 1)\"}'; kube_render_values; jq -c '[.domain, .podCIDR, .apiEndpoints, .nodeAddresses, .traefikServiceIP, .entrypoints.web.admin, .vpn.reservedPools, .hub.selfImage | tostring]' \"$K15/secrets/kube/values.yaml\"")"
expect_eq "kube_render_values: .env → values (the networks, the ClusterIPs, the six classes, the pools, the Hub's digest)" "$(printf '%s\n' "$OUT" | head -n1)" \
  "[\"k.example.org\",\"10.42.0.0/24\",\"[\\\"10.1.0.4:6443\\\"]\",\"[\\\"10.1.0.4\\\",\\\"198.51.100.1\\\"]\",\"10.43.0.20\",\"websecure\",\"10.42.0.0/24 10.43.0.0/16\",\"ghcr.io/porelli/portcullis-hub@sha256:$(printf '%064d' 1)\"]"
expect_eq "kube_render_values: no secret in values.yaml (0600)" "$(grep -cE 'PG-SECRET|HUB-PROXY|KC-SECRET' "$K15/secrets/kube/values.yaml" || true):$(file_mode "$K15/secrets/kube/values.yaml")" "0:600"
OUT="$(kt "$K15_ENV; export DNS_PROVIDER=porkbun; _K_IMAGES='{}'; kube_render_values; jq -r .dnsProvider \"$K15/secrets/kube/values.yaml\"; export DNS_PROVIDER='tok=SECRET'; kube_render_values; jq -r .dnsProvider \"$K15/secrets/kube/values.yaml\"")"
expect_eq "kube_render_values: dnsProvider = DNS_PROVIDER's name only (HUB_DNS_PROVIDER), never anything else" "$(printf '%s\n' "$OUT" | head -n2 | tr '\n' ' ')" "porkbun  "
expect_eq "hub_env_write: core.env carries DNS_PROVIDER's name (the HA page), and nothing that isn't a provider id" \
  "$( (export PORTCULLIS_ROOT="$WORK/dnsp"; mkdir -p "$PORTCULLIS_ROOT"; DNS_PROVIDER=route53 hub_env_write; grep '^DNS_PROVIDER=' "$PORTCULLIS_ROOT/secrets/hub/core.env"; DNS_PROVIDER='x y=SECRET' hub_env_write; grep '^DNS_PROVIDER=' "$PORTCULLIS_ROOT/secrets/hub/core.env") 2>/dev/null | tr '\n' ' ')" "DNS_PROVIDER=route53 DNS_PROVIDER= "
# HA (Task 19): ha.enabled from PORTCULLIS_HA=on, the non-small nodes at main.
OUT="$(kt "$K15_ENV; _K_IMAGES='{}'; kube_render_values; jq -c .ha \"$K15/secrets/kube/values.yaml\"")"
expect_eq "kube_render_values: ha off without PORTCULLIS_HA=on" "$(printf '%s\n' "$OUT" | head -n1)" '{"enabled":false,"nonSmallNodesAtPrimary":0,"primarySite":"main"}'
OUT="$(kt "$K15_ENV; export PORTCULLIS_HA=on; kube_nonsmall_at_primary() { echo 3; }; _K_IMAGES='{}'; kube_render_values; jq -c .ha \"$K15/secrets/kube/values.yaml\"")"
expect_eq "kube_render_values: PORTCULLIS_HA=on → ha.enabled, the non-small nodes at main (Keycloak ×3)" "$(printf '%s\n' "$OUT" | head -n1)" '{"enabled":true,"nonSmallNodesAtPrimary":3,"primarySite":"main"}'
OUT="$(kt "$K15_ENV; export PORTCULLIS_HA=on; kube_nonsmall_at_primary() { echo oops; }; _K_IMAGES='{}'; kube_render_values; jq -c .ha.nonSmallNodesAtPrimary \"$K15/secrets/kube/values.yaml\"")"
expect_eq "kube_render_values: an unreadable node count → 0 (Keycloak ×2)" "$(printf '%s\n' "$OUT" | head -n1)" "0"
# Task 20 (contract §20.11): the primary site is fixed to main, never from .env (no option).
OUT="$(kt "$K15_ENV; export PORTCULLIS_HA=on PORTCULLIS_PRIMARY_SITE=edge; kube_nonsmall_at_primary() { echo 2; }; _K_IMAGES='{}'; kube_render_values; jq -r .ha.primarySite \"$K15/secrets/kube/values.yaml\"")"
expect_eq "kube_render_values: ha.primarySite is main" "$(printf '%s\n' "$OUT" | head -n1)" "main"
OUT="$(kt "kube_ctl() { printf '%s' '{\"items\":[{\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"True\"}]}},{\"status\":{\"conditions\":[{\"type\":\"Ready\",\"status\":\"False\"}]}},{\"status\":{}}]}'; echo \"\$*\" > '$WORK/nsp-args'; }; kube_nonsmall_at_primary")"
expect_eq "kube_nonsmall_at_primary: Ready home / cloud nodes at main only (review M8)" "$(printf '%s\n' "$OUT" | head -n1 | sed 's/rc=0//'):$(cat "$WORK/nsp-args")" \
  "1:get nodes -l portcullis.io/site=main,portcullis.io/class in (home,cloud) -o json"
OUT="$(kt "for v in hub_data hub_secrets lldap_data domains_data wg_data traefik_acme; do kube_pvc_name \$v; done | tr '\n' ' '; export PORTCULLIS_HA=on; for v in hub_data hub_secrets lldap_data domains_data wg_data prometheus_data; do kube_pvc_name \$v; done | tr '\n' ' '; echo")"
expect_eq "kube_pvc_name: hub_data is hub-state; in HA the replicated ones are <name>-r (the chart's portcullis.pvcName)" "$(printf '%s\n' "$OUT" | head -n1)" \
  "hub-state hub-secrets lldap-data domains-data wg-data traefik-acme hub-state-r hub-secrets-r lldap-data domains-data-r wg-data-r prometheus-data "
OUT="$(kt "kube_traefik_peer; PORTCULLIS_HA=on kube_traefik_peer")"
expect_eq "kube_traefik_peer: the admission params' Traefik peer, its DaemonSet's pods in portcullis-ingress in HA" "$(printf '%s\n' "$OUT" | head -n2 | tr '\n' ' ')" \
  "portcullis:portcullis.io/component=traefik portcullis-ingress:app.kubernetes.io/name=traefik "
expect_eq "_kube_sync_ingress: Traefik's objects into portcullis-ingress, the endpoint Secret's client side only, never portcullis-env" \
  "$(declare -f _kube_sync_ingress | grep -c 'portcullis-env\|server.key'):$(declare -f _kube_sync_ingress | grep -c 'client.key=')" "0:1"
OUT="$(kt "$K15_ENV; unset PORTCULLIS_WG_EDGE_SERVICE_IP; _K_IMAGES='{}'; kube_render_values")"
case "$OUT" in *"PORTCULLIS_WG_EDGE_SERVICE_IP is not set in .env (required by the chart)"*"rc=1") t_pass "kube_render_values: a required key missing → refused naming it" ;; *) t_fail "values missing key: $OUT" ;; esac
# rt_up: K1 local builds first; helm failure → health report, applied.json unchanged
k_fixtures; k15_root; rm -f "$KS/order"
mkdir -p "$KS/bin2"
printf '#!/usr/bin/env bash\nprintf "docker %%s\\n" "$*" >> "$STUB_DIR/order"\n[ "$1" != save ] || echo IMAGE-TAR\nexit 0\n' > "$KS/bin2/docker"
printf '#!/usr/bin/env bash\nprintf "sudo %%s\\n" "$*" >> "$STUB_DIR/order"\ncase "$*" in *"images ls"*) printf "REF TYPE DIGEST\\nx y sha256:%%064d\\n" 9 ;; *"images import"*) cat >/dev/null ;; esac\n' > "$KS/bin2/sudo"
chmod +x "$KS/bin2/docker" "$KS/bin2/sudo"
echo '{"items":[{"metadata":{"name":"keycloak-abc"},"status":{"phase":"Running","containerStatuses":[{"ready":false,"restartCount":4}]}}]}' > "$KS/kube/pods.json"
OUT="$(kt "$K15_ENV; PATH='$KS/bin2':\$PATH PORTCULLIS_KUBE_IMAGES=local KUBE_HUB_IMAGE=; export STUB_HELM_FAIL=1; _kube_registry_digest() { echo \"\${1%:*}@sha256:$(printf '%064d' 3)\"; }; kube_netpol_probe() { :; }; _rtk_up")"
case "$OUT" in *"keycloak-abc Running restarts=4 is not ready; its last events:"*"BackOff: Back-off restarting failed container"*"rc=1") t_pass "rt_up kubernetes: helm timeout → kube_health_report (pods, restarts, last events)" ;; *) t_fail "rt_up helm failure: $OUT" ;; esac
expect_eq "K1 local: each import also tags its digest reference in containerd (the kubelet resolves localhost/…@sha256 only by that name)" \
  "$(grep -c '^sudo k3s ctr -n k8s.io images tag --force localhost/portcullis-[a-z-]*:local localhost/portcullis-[a-z-]*@sha256:' "$KS/order")" 5
expect_eq "rt_up kubernetes: every K1 local image built and imported before helm runs" \
  "$(awk '/^docker build/ {b++} /^sudo k3s ctr -n k8s.io images import/ {i++} /^helm .*upgrade --install/ {print b ":" i; exit}' "$KS/order")" "5:5"
expect_eq "rt_up kubernetes: helm failure → no digest cache" \
  "$(test -e "$K15/secrets/kube/digests.json" && echo cached || echo none)" "none"
expect_eq "rt_up kubernetes: helm upgrade --install --wait --timeout 10m --skip-crds on the context" \
  "$(grep -c '^--kube-context ci upgrade --install portcullis .* -n portcullis --skip-crds --wait --timeout 10m -f .*/secrets/kube/values.yaml' "$KS/helm-calls")" 1
k_fixtures; k15_root
OUT="$(kt "set -euo pipefail; $K15_ENV; _kube_registry_digest() { echo \"\${1%:*}@sha256:$(printf '%064d' 3)\"; }; kube_netpol_probe() { :; }; _rtk_up" </dev/null)"
expect_eq "rt_up kubernetes (under the CLI's set -euo pipefail): success → the objects live and the digest cache" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(test -e "$KS/live/Secret.portcullis-env.json" && echo true || echo false):$(jq -r '.hub' "$K15/secrets/kube/digests.json")" \
  "rc=0:true:ghcr.io/porelli/portcullis-hub@sha256:$(printf '%064d' 3)"
# _kube_keygen: created, waited for, read, deleted; a pod that never runs
# says why (phase, the container's waiting reason, events), never its logs.
k_fixtures; rm -f "$KS/order"
OUT="$(kt "_K_IMAGES='{\"domains\":\"localhost/portcullis-domains@sha256:$(printf '%064d' 5)\"}'; _kube_keygen domains 10004" 2>/dev/null)"
expect_eq "_kube_keygen kubernetes: the key read by exec cat from the pod's memory emptyDir, never its logs; create → wait → exec" \
  "$(printf '%s\n' "$OUT" | grep -c '^AGE-SECRET-KEY-1KUBE'):$(grep -E '^(create pod|wait|logs|exec)' "$KS/order" | cut -d' ' -f1 | tr '\n' ',')" "1:create,wait,exec,"
expect_eq "_kube_keygen kubernetes: a restricted pod (non-root 10004, no token, drop ALL, read-only root, RuntimeDefault)" \
  "$(grep -v '^---$' "$KS/kubectl-stdin" | jq -c 'select(.kind == "Pod") | [.spec.securityContext.runAsUser, .spec.automountServiceAccountToken, .spec.containers[0].securityContext.capabilities.drop, .spec.containers[0].securityContext.readOnlyRootFilesystem, .spec.securityContext.seccompProfile.type, .spec.containers[0].command[3], (.spec.containers[0].command[2] | test("keygen > /k/key.tmp")), .spec.volumes[0].emptyDir.medium]' 2>/dev/null)" \
  '[10004,false,["ALL"],true,"RuntimeDefault","domains",true,"Memory"]'
rm -f "$KS/order"
OUT="$(kt "export STUB_WAIT_RC=1; KUBE_POD_WAIT=1 _K_IMAGES='{\"domains\":\"localhost/portcullis-domains@sha256:$(printf '%064d' 5)\"}'; _kube_keygen domains 10004")"
case "$OUT" in *"did not complete: phase Pending; keygen: ErrImagePull failed to pull localhost/portcullis-domains@sha256:abc"*"BackOff"*"rc=1") t_pass "_kube_keygen kubernetes: a pod that never runs → its phase, waiting reason and events, rc 1" ;; *) t_fail "keygen diag: $OUT" ;; esac
expect_eq "_kube_keygen kubernetes: a failed pod is never read" "$(grep -c '^logs\|^exec' "$KS/order" || true)" 0
expect_eq "_kube_keygen never reads a keygen pod's logs" "$(sed -n '/^_kube_keygen() {/,/^}/p' "$HERE/../scripts/lib/kube.sh" | grep -c 'kube_ctl.* logs' || true)" 0

# down never uninstalls
k_fixtures; rm -f "$KS/order" "$KS/helm-calls"
OUT="$(kt 'rt_down')"
expect_eq "down never runs helm uninstall: every Deployment of both namespaces scaled to 0" \
  "$(test -e "$KS/helm-calls" && echo helm || echo none):$(grep -c 'scale deployment --all --replicas=0' "$KS/order")" "none:2"
expect_eq "no helm uninstall anywhere in the CLI" "$(grep -rn 'helm.*uninstall\|kube_helm uninstall' "$HERE/../scripts/lib" "$HERE/../portcullis" | grep -v '^[^:]*:[0-9]*: *#' | grep -vc 'never' || true)" 0
# restore keeps the host's kubernetes keys
RK="$WORK/rk"; rm -rf "$RK"; mkdir -p "$RK"
printf 'CONTAINER_RUNTIME=kubernetes\nPORTCULLIS_KUBE_CONTEXT=ci\nPORTCULLIS_POD_CIDR=10.42.0.0/24\nPORTCULLIS_SERVICE_CIDR=10.43.0.0/16\nPORTCULLIS_KUBE_API_ENDPOINTS=10.1.0.4:6443\nPORTCULLIS_KUBE_INSTALL_ID=0b0e2b3c-1111-4222-8333-444455556666\nPORTCULLIS_DOMAIN=host.example\n' > "$RK/.env"
OUT="$(kt "PORTCULLIS_ROOT='$RK'; unset PORTCULLIS_KUBE_CONTEXT PORTCULLIS_POD_CIDR PORTCULLIS_KUBE_INSTALL_ID; kube_forward_core() { :; }; restore_runtime_from_host >/dev/null; printf 'CONTAINER_RUNTIME=docker\nPORTCULLIS_DOMAIN=backup.example\nPORTCULLIS_KUBE_CONTEXT=backup-ctx\nPORTCULLIS_ENGINE_SOCKET=/x\n' > '$RK/.env'; _restore_runtime_keys; cat '$RK/.env'")"
expect_eq "restore keeps CONTAINER_RUNTIME and every PORTCULLIS_KUBE_* / network key from the host, never the backup's" \
  "$(printf '%s\n' "$OUT" | grep -E '^(CONTAINER_RUNTIME|PORTCULLIS_KUBE_CONTEXT|PORTCULLIS_POD_CIDR|PORTCULLIS_KUBE_INSTALL_ID|PORTCULLIS_ENGINE_SOCKET|PORTCULLIS_DOMAIN)=' | sort | tr '\n' ' ')" \
  "CONTAINER_RUNTIME=kubernetes PORTCULLIS_DOMAIN=backup.example PORTCULLIS_KUBE_CONTEXT=ci PORTCULLIS_KUBE_INSTALL_ID=0b0e2b3c-1111-4222-8333-444455556666 PORTCULLIS_POD_CIDR=10.42.0.0/24 "
# restore empties *-pw Secrets (after scaling those instances to 0)
k_fixtures; rm -f "$KS/order"
echo '{"items":[{"metadata":{"name":"samba--share-pw"}},{"metadata":{"name":"samba--env"}},{"metadata":{"name":"tm--share-pw"}}]}' > "$KS/kube/apps-secrets.json"
OUT="$(kt '_kube_restore_stop_secret_apps; echo "stopped=$RESTORE_STOPPED_APPS"')"
expect_eq "restore empties every *-pw Secret, after scaling the person-secret instances to 0 (and only those Secrets)" \
  "$(grep -E 'scale|patch' "$KS/order" | sed 's/--type=json.*//' | tr '\n' ';'):$(printf '%s\n' "$OUT" | grep -c 'stopped=samba')" \
  "kubectl portcullis-apps scale deployment -l portcullis.io/person-secrets --replicas=0;kubectl portcullis-apps patch secret samba--share-pw ;kubectl portcullis-apps patch secret tm--share-pw ;:1"
# No file-sharing instance: nothing to scale (kubectl scale -l on no match
# fails "no objects passed to scale"), the Secrets still emptied.
rm -f "$KS/order"
OUT="$(kt 'STUB_PS_NONE=1 _kube_restore_stop_secret_apps; echo "rc=$? stopped=[$RESTORE_STOPPED_APPS]"')"
expect_eq "restore with no person-secret instance: no scale, every *-pw Secret emptied, nothing stopped" \
  "$(grep -E 'scale|patch' "$KS/order" | sed 's/--type=json.*//' | tr '\n' ';'):$(printf '%s\n' "$OUT" | grep -c 'rc=0 stopped=\[\]')" \
  "kubectl portcullis-apps patch secret samba--share-pw ;kubectl portcullis-apps patch secret tm--share-pw ;:1"
rm -f "$KS/order"; : > "$KS/order"
OUT="$(kt 'STUB_PS_LIST_FAIL=1 _kube_restore_stop_secret_apps; echo "rc=$? msg=$_RESTORE_ERROR_MSG"')"
expect_eq "restore: an unreadable person-secret list refuses before anything changes" \
  "$(grep -cE 'scale|patch' "$KS/order" 2>/dev/null || true):$(printf '%s\n' "$OUT" | grep -c 'rc=1 msg=could not list the person-secret instances')" "0:1"
rm -f "$KS/order"; : > "$KS/order"; mv "$KS/kube/apps-secrets.json" "$KS/kube/apps-secrets.json.bak"; printf 'not json' > "$KS/kube/apps-secrets.json"
OUT="$(kt '_kube_restore_stop_secret_apps; echo "rc=$? msg=$_RESTORE_ERROR_MSG"')"
mv "$KS/kube/apps-secrets.json.bak" "$KS/kube/apps-secrets.json"
expect_eq "restore: an unreadable Secret list refuses (a credential would survive the restore)" \
  "$(grep -c 'patch' "$KS/order" 2>/dev/null || true):$(printf '%s\n' "$OUT" | grep -c "rc=1 msg=could not list the apps' Secrets")" "0:1"
# The kubernetes restore puts the backup's secret variables (portcullis-env:
# POSTGRES_PASSWORD) live BEFORE the emptied Postgres starts: it initialises
# with that password, which Keycloak then reads (the old one = Keycloak never
# connects again).
RB="$(sed -n '/^_backup_restore_kube() {/,/^}/p' "$HERE/../scripts/lib/kube.sh")"
expect_eq "kube restore: kube_sync_secrets and the roles' Secrets after the .env is restored, before the CNPG databases are replaced (plan Task 23)" \
  "$(printf '%s\n' "$RB" | awk '/cat "\$dir\/.env"/ {printf "cat "} /kube_sync_secrets/ {printf "kube_sync_secrets "} /^ *kube_pg_sync_secrets/ {printf "kube_pg_sync_secrets "} /_kube_restore_pg "/ {printf "_kube_restore_pg "}')" \
  "cat kube_sync_secrets kube_pg_sync_secrets _kube_restore_pg "
# The LLDAP guard on kubernetes counts LLDAP's users from its PVC (never the
# docker-only volume helper), and still refuses an empty LLDAP.
OUT="$(kt '_restore_lldap_count() { echo DOCKER-HELPER; }; _restore_kc_federated_count() { echo 5; }; _kube_restore_lldap_count() { echo 3; }; _restore_lldap_guard false; echo "rc=$?"')"
expect_eq "restore's LLDAP guard on kubernetes: LLDAP's own count (3 users, 5 federated) → goes on, the docker helper never runs" \
  "$(printf '%s\n' "$OUT" | grep -c DOCKER-HELPER):$(printf '%s\n' "$OUT" | tail -n1)" "0:rc=0"
OUT="$(kt '_restore_kc_federated_count() { echo 5; }; _kube_restore_lldap_count() { echo 0; }; _restore_lldap_guard false; echo "rc=$?"' 2>&1)"
case "$OUT" in *"LLDAP has no users (0) but the restored Keycloak database has 5 federated users"*"rc=1"*) t_pass "restore's LLDAP guard on kubernetes: an empty LLDAP with federated Keycloak users refuses" ;; *) t_fail "kube lldap guard empty: $OUT" ;; esac
# status on kubernetes: a Deployment whose pods crash-loop or restarted in
# the last 10 minutes is a problem; a Job's pod, an old restart and a
# terminating pod are not; an unreadable pod list is "unknown" (fail closed).
NOWISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; OLDISO="2020-01-01T00:00:00Z"
REC="$(date -u -d '-2 min' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-2M +%Y-%m-%dT%H:%M:%SZ)"
CRASH_CORE='{"items":[
 {"metadata":{"name":"hub-6ccdd8956b-w4tm4","labels":{"pod-template-hash":"6ccdd8956b"},"ownerReferences":[{"kind":"ReplicaSet","name":"hub-6ccdd8956b"}]},
  "status":{"containerStatuses":[{"restartCount":4,"state":{"waiting":{"reason":"CrashLoopBackOff"}},"lastState":{"terminated":{"finishedAt":"'"$NOWISO"'"}}}]}},
 {"metadata":{"name":"lldap-685d98967d-hz4l9","labels":{"pod-template-hash":"685d98967d"},"ownerReferences":[{"kind":"ReplicaSet","name":"lldap-685d98967d"}]},
  "status":{"containerStatuses":[{"restartCount":1,"state":{"running":{}},"lastState":{"terminated":{"finishedAt":"'"$OLDISO"'"}}}]}},
 {"metadata":{"name":"oneshot-x","ownerReferences":[{"kind":"Job","name":"oneshot"}]},
  "status":{"containerStatuses":[{"restartCount":0,"state":{"waiting":{"reason":"Error"}}}]}},
 {"metadata":{"name":"vault-58c5dcfdf7-old","deletionTimestamp":"'"$NOWISO"'","labels":{"pod-template-hash":"58c5dcfdf7"},"ownerReferences":[{"kind":"ReplicaSet","name":"vault-58c5dcfdf7"}]},
  "status":{"containerStatuses":[{"restartCount":0,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}}]}'
CRASH_APPS='{"items":[
 {"metadata":{"name":"echo-k--web-5d9f7c8b6-abcde","labels":{"pod-template-hash":"5d9f7c8b6"},"ownerReferences":[{"kind":"ReplicaSet","name":"echo-k--web-5d9f7c8b6"}]},
  "status":{"containerStatuses":[{"restartCount":2,"ready":false,"state":{"running":{}},"lastState":{"terminated":{"finishedAt":"'"$REC"'"}}}]}},
 {"metadata":{"name":"fa--x-6b7c8d9e0-zzzzz","labels":{"pod-template-hash":"6b7c8d9e0"},"ownerReferences":[{"kind":"ReplicaSet","name":"fa--x-6b7c8d9e0"}]},
  "status":{"containerStatuses":[{"restartCount":3,"ready":true,"state":{"running":{}},"lastState":{"terminated":{"finishedAt":"'"$REC"'"}}}]}}]}'
printf '%s' "$CRASH_CORE" > "$WORK/crash-core.json"; printf '%s' "$CRASH_APPS" > "$WORK/crash-apps.json"
cj() { kt "kube_ctl() { case \"\$*\" in *'-n cnpg-system get pods -o json'*) echo '{\"items\":[]}' ;; *'-n portcullis get pods -o json'*) ${1:-cat '$WORK/crash-core.json'} ;; *'-n portcullis-apps get pods -o json'*) cat '$WORK/crash-apps.json' ;; esac; }; kube_crashing_json"; }
expect_eq "kube_crashing_json: the crash-looping Hub and an app restarted 2 min ago and not ready; not one ready again, an old restart, a Job's pod or a terminating pod" \
  "$(cj | head -n1 | jq -c '[.[] | [.namespace, .deployment, .reason]]')" \
  '[["portcullis","hub","CrashLoopBackOff"],["portcullis-apps","echo-k--web","restarted"]]'
expect_eq "kube_crashing_json: an unreadable pod list → null (status counts it a problem)" "$(cj 'return 1' | head -n1)" "null"
printf '%s' '{"items":[{"metadata":{"name":"sessions-1","ownerReferences":[{"kind":"StatefulSet","name":"sessions"}]},
  "status":{"initContainerStatuses":[{"restartCount":3,"lastState":{"terminated":{"exitCode":1,"message":"portcullis-sessions: the Sentinels disagree on the master (x): refusing to start\n"}},"state":{"waiting":{"reason":"PodInitializing"}}}],
            "containerStatuses":[{"restartCount":0,"state":{"waiting":{"reason":"PodInitializing"}}}]}}]}' > "$WORK/crash-sess.json"
printf '%s' '{"items":[{"metadata":{"name":"echo-k--web-0","ownerReferences":[{"kind":"StatefulSet","name":"sessions"}]},
  "status":{"containerStatuses":[{"restartCount":1,"ready":false,"lastState":{"terminated":{"exitCode":1,"message":"portcullis-sessions: spoofed by an app","finishedAt":"'"$REC"'"}},"state":{"running":{}}}]}}]}' > "$WORK/crash-spoof.json"
expect_eq "kube_crashing_json: an apps-namespace pod writing the session store's prefix → its message is never the reason (security review)" \
  "$(kt "kube_ctl() { case \"\$*\" in *'-n cnpg-system get pods -o json'*) echo '{\"items\":[]}' ;; *'-n portcullis get pods -o json'*) echo '{\"items\":[]}' ;; *'-n portcullis-apps get pods -o json'*) cat '$WORK/crash-spoof.json' ;; esac; }; kube_crashing_json" | head -n1 | jq -c '[.[] | .reason]')" '["restarted"]'
printf '%s' '{"items":[{"metadata":{"name":"sessions-1","ownerReferences":[{"kind":"StatefulSet","name":"sessions"}]},
  "status":{"initContainerStatuses":[{"restartCount":2,"lastState":{"terminated":{"exitCode":1,"message":"portcullis-sessions: line one\u001b[31m\u009b2J\nline two '"$(printf 'x%.0s' $(seq 1 300))"'"}},"state":{"waiting":{"reason":"PodInitializing"}}}]}}]}' > "$WORK/crash-long.json"
expect_eq "kube_crashing_json: the named error stripped of C0, DEL and C1 control characters (CSI U+009B) and capped at 200 characters" \
  "$(cj "cat '$WORK/crash-long.json'" | head -n1 | jq -r '.[] | select(.namespace == "portcullis") | .reason' | LC_ALL=C awk '{ print length($0) ":" (index($0, "\033") == 0) ":" (index($0, "\302\233") == 0) }')" "200:1:1"
# The guard's master fallback names what it did and exits 0: that pod is
# healthy and not listed (re-review 2 N-d); a failed start (exit 1) is.
printf '%s' '{"items":[{"metadata":{"name":"sessions-0","ownerReferences":[{"kind":"StatefulSet","name":"sessions"}]},
  "status":{"initContainerStatuses":[{"restartCount":0,"ready":false,"state":{"terminated":{"exitCode":0,"reason":"Completed","message":"portcullis-sessions: started as the master; the sessions were lost"}}}],
            "containerStatuses":[{"restartCount":0,"ready":true,"state":{"running":{}}}]}}]}' > "$WORK/crash-fallback.json"
expect_eq "kube_crashing_json: a sessions pod whose guard named its fallback and exited 0 → healthy, not listed" \
  "$(cj "cat '$WORK/crash-fallback.json'" | head -n1 | jq -c '[.[] | select(.namespace == "portcullis")]')" '[]'
expect_eq "kube_crashing_json: a StatefulSet's pod with the session store's named error → that error is the reason (review M-b)" \
  "$(cj "cat '$WORK/crash-sess.json'" | head -n1 | jq -c '[.[] | select(.namespace == "portcullis") | [.deployment, .reason]]')" \
  '[["sessions","portcullis-sessions: the Sentinels disagree on the master (x): refusing to start"]]'
# status --json runtime
OUT="$(kt 'kube_status_json v1.37.2+k3s1')"
expect_eq "status --json runtime.name = kubernetes, runtime.context set, version, the § 6 rows as checks" \
  "$(printf '%s\n' "$OUT" | head -n1 | jq -c '[.name, .context, .version, (.checks | length > 5)]')" '["kubernetes","ci","v1.37.2+k3s1",true]'
# vpn init on kubernetes: the people key from wg keypair (variables), never argv
k_fixtures; k15_root
OUT="$(kt "PORTCULLIS_ROOT='$K15'; export STUB_WG_PRIV=UFJJVkFURS1LRVktOTk5 STUB_WG_PUB=UFVC; vpn_genkey_kube; cat '$K15/secrets/wg/people.key'; file_mode '$K15/secrets/wg/people.key'")"
expect_eq "vpn init kubernetes: people key from wg keypair (only the private key, 0640, in place)" "$(printf '%s\n' "$OUT" | head -n2 | tr '\n' ' ')" "UFJJVkFURS1LRVktOTk5 640 "
expect_eq "vpn init kubernetes: the private key never on argv" "$(grep -c 'UFJJVkFURS1LRVktOTk5' "$KS/kubectl-calls" || true)" 0
OUT="$(kt 'vpn_overlaps 10.42.0.0/22 "$(kube_vpn_reserved)" "{\"local_networks\":[],\"provider_ranges\":[]}"')"
case "$OUT" in *10.42.0.0/24*) t_pass "vpn init kubernetes: a subnet over the pod CIDR → refused" ;; *) t_fail "vpn pod cidr overlap: $OUT" ;; esac
OUT="$(kt 'vpn_overlaps 10.213.0.0/22 "$(kube_vpn_reserved)" "{\"local_networks\":[],\"provider_ranges\":[]}"')"
expect_eq "vpn init kubernetes: 10.213.0.0/22 is free of the pod / service CIDRs and the nodes" "$OUT" "rc=0"
# signin reset-core on kubernetes: Hub to 0, the one-shot, Hub to 1 (also on failure)
k_fixtures; k15_root; rm -f "$KS/order"
for RC_RUN in 0 1; do
  rm -f "$KS/order"
  # Under the CLI's own set -euo pipefail (a SIGPIPE'd pipeline must not abort it).
  OUT="$(kt "set -euo pipefail; $K15_ENV; export STUB_RUN_RC=$RC_RUN; kube_images_ready() { _K_IMAGES='{}'; }; kube_render_values() { : > '$K15/secrets/kube/values.yaml'; }; signin_reset_core" </dev/null)"
  expect_eq "signin reset-core kubernetes (run rc $RC_RUN): Hub scaled to 0, the one-shot, Hub scaled to 1" \
    "$(grep -E 'scale deploy/hub|kubectl run' "$KS/order" | sed 's/^kubectl portcullis //' | tr '\n' ';')" "scale deploy/hub --replicas=0;kubectl run;scale deploy/hub --replicas=1;"
done
expect_eq "rt_run kubernetes: the chart's one-shot pod (its image), the argv appended to its entrypoint, stdin attached, removed after" \
  "$(grep '^--context ci -n portcullis run oneshot-hub-' "$KS/kubectl-calls" | tail -n1 | sed -n 's/.*--overrides=//p' | jq -c '[.spec.containers[0].command, .spec.containers[0].stdin, .spec.containers[0].image]'):$(grep -c -- '--restart=Never --rm -i --quiet' "$KS/kubectl-calls")" \
  "[[\"/usr/local/bin/hub\",\"signin\",\"reset-core\"],true,\"ghcr.io/porelli/portcullis-hub@sha256:$(printf '%064d' 1)\"]:2"
# cert revoke / sync bump the annotation
k_fixtures; k15_root; rm -f "$KS/order" "$KS/kubectl-stdin"
OUT="$(kt "PORTCULLIS_ROOT='$K15'; kube_revocation_bump")"
expect_eq "cert revoke bumps portcullis.io/rev on group-gate's pod after syncing certs-revocation" \
  "$(grep -c 'create configmap certs-revocation' "$KS/order"):$(grep -c 'annotate pod -l portcullis.io/component=group-gate --overwrite portcullis.io/rev=' "$KS/order")" "1:1"
expect_eq "cert sync calls the kubernetes bump" "$(sed -n '/^cert_sync() {/,/^}/p' "$HERE/../scripts/lib/certs.sh" | grep -c 'kube_revocation_bump')" 1
# runtime_export under kubernetes: the pod + service CIDR are reserved (K-P11).
expect_eq "runtime_export kubernetes: PORTCULLIS_VPN_RUNTIME_POOLS = pod + service CIDR" \
  "$(kt 'runtime_export; echo "$PORTCULLIS_VPN_RUNTIME_POOLS"' | head -n1)" "10.42.0.0/24 10.43.0.0/16"
# hub_env_write: the _SOURCE pair (contract §2), the kube keys for the Hub.
HW="$WORK/hw"; rm -rf "$HW"; mkdir -p "$HW/secrets/hub"
( export PORTCULLIS_ROOT="$HW" CONTAINER_RUNTIME=docker PORTCULLIS_TRAEFIK_IP=172.31.250.2 PORTCULLIS_MCP_GATE_IP=172.31.250.3; hub_env_write )
expect_eq "hub_env_write: PORTCULLIS_TRAEFIK_SOURCE / _MCP_GATE_SOURCE = <ip>/32 on docker, no kube keys" \
  "$(grep -E '^PORTCULLIS_(TRAEFIK|MCP_GATE)_SOURCE=|^PORTCULLIS_(POD_CIDR|SERVICE_CIDR|WG_EDGE_SERVICE_IP|RUNTIME_ROOTS|KUBE_CONTEXT|KUBE_NODE_ADDRESSES)=' "$HW/secrets/hub/core.env")" \
  "PORTCULLIS_TRAEFIK_SOURCE=172.31.250.2/32
PORTCULLIS_MCP_GATE_SOURCE=172.31.250.3/32"
kt "PORTCULLIS_ROOT='$HW'; PORTCULLIS_WG_EDGE_SERVICE_IP=10.43.0.22 PORTCULLIS_TRAEFIK_SERVICE_IP=10.43.0.20 PORTCULLIS_KUBE_NODE_ADDRESSES='10.1.0.4 198.51.100.1'; hub_env_write" >/dev/null
expect_eq "hub_env_write: PORTCULLIS_TRAEFIK_SOURCE = the pod CIDR on kubernetes, plus the CIDRs, wg-edge, the runtime roots, the context and the node addresses" \
  "$(grep -E '^PORTCULLIS_(TRAEFIK|MCP_GATE)_SOURCE=|^PORTCULLIS_(POD_CIDR|SERVICE_CIDR|WG_EDGE_SERVICE_IP|TRAEFIK_SERVICE_IP|RUNTIME_ROOTS|KUBE_CONTEXT|KUBE_NODE_ADDRESSES)=' "$HW/secrets/hub/core.env")" \
  "PORTCULLIS_TRAEFIK_SOURCE=10.42.0.0/24
PORTCULLIS_MCP_GATE_SOURCE=10.42.0.0/24
PORTCULLIS_POD_CIDR=10.42.0.0/24
PORTCULLIS_SERVICE_CIDR=10.43.0.0/16
PORTCULLIS_WG_EDGE_SERVICE_IP=10.43.0.22
PORTCULLIS_TRAEFIK_SERVICE_IP=10.43.0.20
PORTCULLIS_RUNTIME_ROOTS=/var/lib/rancher/k3s /var/lib/portcullis-storage
PORTCULLIS_KUBE_CONTEXT=ci
PORTCULLIS_KUBE_NODE_ADDRESSES=10.1.0.4 198.51.100.1"
OUT="$(kt "PORTCULLIS_ROOT='$HW'; unset PORTCULLIS_POD_CIDR; hub_env_write")"
case "$OUT" in *"PORTCULLIS_POD_CIDR is not set (.env): refusing to write an empty PORTCULLIS_TRAEFIK_SOURCE"*"rc=1") t_pass "hub_env_write kubernetes: no PORTCULLIS_POD_CIDR → refused (never an empty _SOURCE)" ;; *) t_fail "hub_env_write empty pod cidr: $OUT" ;; esac
# jq 1.8: `A and B as $x | C` binds (A and B) to $x (jq 1.7 bound B
# alone): the two readings differ, so the kubernetes filters write the
# parentheses out.
JQF='{"items":[{"ok":true,"n":1}]}'
expect_eq "jq 1.8 precedence fixture: (A and B) as \$x and A and (B as \$x | …) differ" \
  "$(printf '%s' "$JQF" | jq -c '.items[0] | (.ok and .n) as $x | [$x]')|$(printf '%s' "$JQF" | jq -c '.items[0] | .ok and (.n as $x | [$x])')" "[true]|true"
expect_eq "every jq '... and/or ... as \$x' in the kubernetes code is parenthesised" \
  "$(grep -nE '(and|or) [^|()]+ as [$]' "$HERE/../scripts/lib/kube.sh" || true)" ""

# ══ mail (contract §19.10): the CLI on the Hub's host socket ══
# shellcheck source=../scripts/lib/mail.sh
source "$HERE/../scripts/lib/mail.sh"
ML="$WORK/mail"
# mt <script> — a subshell with a fresh root (.env: the slot open, docker
# runtime) and stubs: `hub mail <cmd>` (rt_exec hub) answers from
# $ML/hub-<cmd> (exit $ML/hub-<cmd>.rc), its stdin to $ML/hub-<cmd>.in;
# mail-cert / mail-tlsa (rt_run) answer from $ML/cert / $ML/tlsa-<sub>;
# every call goes to $ML/argv (docker's argv elements %q-quoted: one
# element stays one).
mt() {
  rm -rf "$ML"; mkdir -p "$ML/root/secrets/mail"
  printf 'PORTCULLIS_DOMAIN=mail.example\nPORTCULLIS_MAIL=on\nCONTAINER_RUNTIME=docker\nDNS_PROVIDER=porkbun\nPORKBUN_API_KEY=k\nPORKBUN_SECRET_API_KEY=s\n' > "$ML/root/.env"
  printf '%s' '{"renewed":false,"not_after":"2027-02-01T00:00:00Z","spki_sha256":"'"$(printf 'a%.0s' $(seq 64))"'"}' > "$ML/cert"
  printf '%s' '{"version":1,"current":"aa","next":null,"both_since":null,"phase":"steady","due":null,"publish":["aa"]}' > "$ML/tlsa-status"
  printf '%s' '{"slot":"open","wired":false,"warning":"This app becomes the mail server for every person and every mail domain."}' > "$ML/hub-provider"
  # hub mail status: a provider wired and serving (R2-H5/N1: hub mail tls
  # is asked only then); hub-tls.rc makes the tls answer fail.
  printf '%s' '{"wired":true,"instance":"stalwart","reachable":true,"void_owed":null,"held":null}' > "$ML/hub-status"
  for c in tls test action; do printf '{}' > "$ML/hub-$c"; done
  for c in install unwire; do printf '%s' '{"op_id":"op1","op":"mail-'"$c"'","instance":"stalwart","poll":"/api/instances/stalwart/op?op_id=op1"}' > "$ML/hub-$c"; done
  printf '%s' '{"op_id":"op1","running":false,"ok":true}' > "$ML/hub-op"
  printf '%s' '{"instance":"stalwart","creates":true}' > "$ML/hub-install-preview"
  printf '%s' '[{"name":"mail.example","state":"off"}]' > "$ML/hub-domains"
  printf '%s' '{"records":[{"name":"mail.example","type":"MX","ttl":3600,"value":"10 mail.mail.example."}],"rules":{"relay_include":"","dmarc_floor":"none","draining":false}}' > "$ML/hub-dns-main"
  (
    export PORTCULLIS_ROOT="$ML/root" MAIL_OP_POLL=0
    env_load
    # shellcheck source=../scripts/lib/stack.sh
    . "$HERE/../scripts/lib/stack.sh"
    # shellcheck source=../scripts/lib/dns.sh
    . "$HERE/../scripts/lib/dns.sh"
    rt_exec() {
      local -a a=("$@"); local i=0
      while [ "${a[$i]}" != -- ]; do i=$((i + 1)); done
      echo "rt_exec ${a[*]}" >> "$ML/argv"
      if [ "${a[$((i + 1))]}" = hub ] && [ "${a[$((i + 2))]}" = mail ]; then
        local c="${a[$((i + 3))]}"
        cat > "$ML/hub-$c.in"
        [ ! -f "$ML/hub-$c" ] || cat "$ML/hub-$c"
        [ ! -f "$ML/hub-$c.err" ] || cat "$ML/hub-$c.err" >&2
        return "$(cat "$ML/hub-$c.rc" 2>/dev/null || echo 0)"
      fi
      return 1
    }
    rt_run() {
      echo "rt_run $*" >> "$ML/argv"
      case "$*" in
        *"mail-tlsa "*) local all="$*" sub; sub="${all#*mail-tlsa }"; sub="${sub%% *}"; cat "$ML/tlsa-$sub" 2>/dev/null || cat "$ML/tlsa-status"; return "$(cat "$ML/tlsa-$sub.rc" 2>/dev/null || echo 0)" ;;
        *--next-key*) printf '%s\n' '{"spki_sha256":"bb"}' ;;
        *) cat > "$ML/cert.in"; cat "$ML/cert" ;;
      esac
    }
    rt_health() { echo healthy; }
    rt_running() { return 0; }
    rt_up_service() { echo "rt_up_service $*" >> "$ML/argv"; }
    stack_compose_up() { echo "stack_compose_up $*" >> "$ML/argv"; }
    stack_prepare() { echo "stack_prepare" >> "$ML/argv"; }
    runtime_check() { :; }
    rt_network_check() { :; }
    hub_env_write() { echo "hub_env_write" >> "$ML/argv"; }
    domains_image_ensure() { :; }
    volume_own() { echo "volume_own $*" >> "$ML/argv"; }
    mail_schedule_systemd() { echo "mail_schedule_systemd" >> "$ML/argv"; }
    _dns_tool() { echo "dns_tool $* sets=${DNS_SETS:-} recs=${DNS_MAIL_RECORDS:-} tlsa=${DNS_MAIL_TLSA:-} rules=${DNS_MAIL_RULES:-}" >> "$ML/argv"; }
    docker() { { printf docker; printf ' %q' "$@"; echo; } >> "$ML/argv"; case "$1" in ps) echo cid9 ;; exec) printf 'From MAILER-DAEMON Sun Nov 15 10:00:00 2026\nSubject: x\n\nhi\n' ;; esac; }
    [ "${MT_E:-}" != 1 ] || set -e
    eval "$1"
  ) >"$ML/out" 2>&1
}
mte() { MT_E=1 mt "$@"; }

# test_mail_enable_wires_after_typed_id: the slot open, the certificate,
# the Hub restarted, the keys to the Hub, the warning printed, then the
# install with the typed id (--yes = the id).
mte 'mail_enable "" "" stalwart true'; rc=$?
expect_eq "mail enable: rc 0, PORTCULLIS_MAIL=on in .env" "$rc:$(grep -c '^PORTCULLIS_MAIL=on$' "$ML/root/.env")" "0:1"
expect_eq "mail enable: the warning printed before the install" "$(grep -c 'This app becomes the mail server' "$ML/out")" 1
expect_eq "mail enable: hub mail install with the typed id" "$(jq -c . "$ML/hub-install.in")" '{"template":"stalwart","source":"portcullis","confirm":"stalwart"}'
expect_eq "mail enable: the install's op polled to its end (hub mail op {instance, op_id})" "$(jq -c . "$ML/hub-op.in"):$(grep -c 'is this server'"'"'s mail provider' "$ML/out")" '{"instance":"stalwart","op_id":"op1"}:1'
mte 'printf "%s" "{\"op_id\":\"op1\",\"running\":false,\"ok\":false,\"error\":\"void failed\"}" > "$ML/hub-op"; mail_enable "" "" stalwart true'; rc=$?
expect_eq "mail enable: a failed install op → refused, never \"is this server's mail provider\"" "$rc:$(grep -c 'op op1 failed: void failed' "$ML/out"):$(grep -c 'is this server'"'"'s mail provider' "$ML/out")" "1:1:0"
mte 'printf "%s" "{}" > "$ML/hub-install"; mail_enable "" "" stalwart true'; rc=$?
expect_eq "mail enable: an install answer with no op → refused" "$rc:$(grep -c 'started no op' "$ML/out")" "1:1"
mte 'printf "%s" "{\"op_id\":\"op1\",\"running\":true}" > "$ML/hub-op"; export MAIL_OP_WAIT=0; mail_enable "" "" stalwart true'; rc=$?
expect_eq "mail enable: an install op still running after MAIL_OP_WAIT → refused" "$rc:$(grep -c 'still runs after 0 s' "$ML/out")" "1:1"
mte 'printf "%s" "{\"op_id\":\"op2\",\"running\":false,\"ok\":true}" > "$ML/hub-op"; mail_enable "" "" stalwart true'; rc=$?
expect_eq "mail enable: the op record of another op → refused" "$rc:$(grep -c 'answered another op than op1' "$ML/out")" "1:1"
mte 'mail_enable "" "" stalwart true'
expect_eq "mail enable: the keys and not_after to hub mail tls" "$(jq -c . "$ML/hub-tls.in")" '{"spki_sha256":["aa"],"not_after":"2027-02-01T00:00:00Z"}'
expect_eq "mail enable: order (prepare, cert, hub_env_write, the Hub and domains restarted, then the Hub)" \
  "$(grep -oE '^(stack_prepare|rt_run mail-cert -i|hub_env_write|stack_compose_up hub domains)' "$ML/argv" | tr '\n' '|')" \
  "stack_prepare|rt_run mail-cert -i|hub_env_write|stack_compose_up hub domains|"
expect_eq "mail enable: the certificate metric written" "$(grep -c '^portcullis_mail_cert_expiry_seconds 1801440000$' "$ML/root/monitoring/textfile/mail_cert.prom")" 1
mte 'mail_enable "" "" stalwart false </dev/null'; rc=$?
expect_eq "mail enable without --yes and no terminal: refused, nothing installed" "$rc:$([ -f "$ML/hub-install.in" ] && echo installed || echo none):$(grep -c 'type the instance id to confirm' "$ML/out")" "1:none:1"
mte 'printf "%s" "{\"slot\":\"open\",\"wired\":true,\"instance\":\"stalwart\",\"template\":\"stalwart\",\"warning\":\"w\"}" > "$ML/hub-provider"; mail_enable "" "" stalwart true'; rc=$?
expect_eq "mail enable: already wired → no second install" "$rc:$([ -f "$ML/hub-install.in" ] && echo installed || echo none)" "0:none"
# test_mail_enable_waits_for_the_provider: right after the install op the
# provider may not serve yet (its containers starting): mail enable waits
# (MAIL_SERVING_WAIT) and then gives it the keys, never "its keys reach it
# when it is" (nothing else posts them before the daily timer).
mte 'n=0; _mail_serving() { n=$((n + 1)); [ "$n" -ge 3 ]; }; export MAIL_SERVING_WAIT=30 MAIL_SERVING_POLL=0; mail_enable "" "" stalwart true'; rc=$?
expect_eq "mail enable: a provider serving only on the third look still gets the keys" \
  "$rc:$(jq -c . "$ML/hub-tls.in" 2>/dev/null):$(grep -c 'its keys reach it when it is' "$ML/out")" '0:{"spki_sha256":["aa"],"not_after":"2027-02-01T00:00:00Z"}:0'
mte '_mail_serving() { return 1; }; export MAIL_SERVING_WAIT=0 MAIL_SERVING_POLL=0; mail_enable "" "" stalwart true'; rc=$?
expect_eq "mail enable: a provider never serving: rc 0, no keys posted, a warning naming mail rotate" \
  "$rc:$([ -f "$ML/hub-tls.in" ] && echo posted || echo none):$(grep -c 'not serving yet.*mail rotate' "$ML/out")" "0:none:1"
# test_mail_enable_confirms_the_previewed_instance (L3): the Hub's
# install-preview names the instance install would wire (an existing
# stalwart-2): that id is the one typed and confirmed.
mte 'printf "%s" "{\"instance\":\"stalwart-2\",\"creates\":false}" > "$ML/hub-install-preview"; mail_enable "" "" stalwart true'; rc=$?
expect_eq "mail enable: the previewed instance is the confirmed id" \
  "$rc:$(jq -c . "$ML/hub-install-preview.in"):$(jq -r .confirm "$ML/hub-install.in")" '0:{"template":"stalwart","source":"portcullis"}:stalwart-2'
mte 'echo 1 > "$ML/hub-install-preview.rc"; rm -f "$ML/hub-install-preview"; mail_enable "" "" stalwart true'; rc=$?
expect_eq "mail enable: no preview → refused, nothing installed" "$rc:$([ -f "$ML/hub-install.in" ] && echo installed || echo none)" "1:none"
# test_mail_enable_provider_none: the slot only.
mte 'mail_enable "" "" none true'; rc=$?
expect_eq "mail enable --provider none: the slot open, no install" "$rc:$([ -f "$ML/hub-install.in" ] && echo installed || echo none):$(grep -c '^PORTCULLIS_MAIL=on$' "$ML/root/.env")" "0:none:1"
# test_mail_enable_refusals: lego-only DNS, MAIL_IPV6, LAN-only on rootless
# Podman, the port start, Kubernetes — refused before anything is written.
for case in 'export DNS_PROVIDER=hetznerdns|mail needs a DNS provider Portcullis can write' \
            'export MAIL_IPV6=on|MAIL_IPV6 isn'"'"'t supported yet' \
            '_rt_is_podman() { return 0; }; runtime_port_start() { echo 25; }; export MAIL_SUBMISSION_LAN_ONLY=true|LAN-only needs the real client address' \
            '_rt_is_podman() { return 0; }; runtime_port_start() { echo 80; }|ip_unprivileged_port_start' \
            '_rt_is_kube() { return 0; }|mail isn'"'"'t available on Kubernetes yet'; do
  mt "printf 'PORTCULLIS_DOMAIN=mail.example\nCONTAINER_RUNTIME=docker\nDNS_PROVIDER=porkbun\n' > \"\$PORTCULLIS_ROOT/.env\"; ${case%%|*}; mail_enable '' '' stalwart true"; rc=$?
  expect_eq "mail enable refused: ${case#*|}" "$rc:$(grep -c "${case#*|}" "$ML/out"):$(grep -c '^PORTCULLIS_MAIL=' "$ML/root/.env"):$([ -f "$ML/hub-install.in" ] && echo installed || echo none)" "1:1:0:none"
done
# test_mail_disable_unwires_then_off: unwire (drain), every domain off →
# the main set removed, PORTCULLIS_MAIL=off, the Hub restarted; a domain
# still draining → nothing closed yet; --force unwires without the drain.
mte 'mail_disable true false'; rc=$?
expect_eq "mail disable: hub mail unwire {drain: true}, then off" \
  "$rc:$(jq -c . "$ML/hub-unwire.in"):$(grep -c '^PORTCULLIS_MAIL=off$' "$ML/root/.env"):$(grep -c '^dns_tool apply sets=mail recs=\[\]' "$ML/argv"):$(grep -c '^rt_up_service hub' "$ML/argv")" \
  '0:{"drain":true}:1:1:1'
mte 'printf "%s" "[{\"name\":\"mail.example\",\"state\":\"draining\"}]" > "$ML/hub-domains"; mail_disable true false'; rc=$?
expect_eq "mail disable while a domain drains: the slot stays open" "$rc:$(grep -c '^PORTCULLIS_MAIL=on$' "$ML/root/.env"):$(grep -c 'dns_tool' "$ML/argv")" "0:1:0"
mte 'mail_disable true true'; rc=$?
expect_eq "mail disable --force: {drain: false}, off at once" "$rc:$(jq -c . "$ML/hub-unwire.in"):$(grep -c '^PORTCULLIS_MAIL=off$' "$ML/root/.env")" '0:{"drain":false}:1'
mte 'echo 1 > "$ML/hub-unwire.rc"; printf "no mail provider is wired\n" > "$ML/hub-unwire.err"; mail_disable true true'; rc=$?
expect_eq "mail disable: the Hub's 409 no mail provider is wired → already unwired, the slot closed" "$rc:$(grep -c '^PORTCULLIS_MAIL=off$' "$ML/root/.env"):$(grep -c 'already unwired' "$ML/out")" "0:1:1"
mte 'echo 1 > "$ML/hub-unwire.rc"; printf "an unwire is already running\n" > "$ML/hub-unwire.err"; mail_disable true true'; rc=$?
expect_eq "mail disable: any other refusal fails" "$rc:$(grep -c '^PORTCULLIS_MAIL=on$' "$ML/root/.env"):$(grep -c 'an unwire is already running' "$ML/out")" "1:1:1"
mte 'echo 1 > "$ML/hub-unwire.rc"; mail_disable true true'; rc=$?
expect_eq "mail disable: the Hub refusing the unwire → refused, the slot stays open" "$rc:$(grep -c '^PORTCULLIS_MAIL=on$' "$ML/root/.env")" "1:1"
mte 'printf "%s" "{\"op_id\":\"op1\",\"running\":true}" > "$ML/hub-op"; export MAIL_OP_WAIT=0; mail_disable true true'; rc=$?
expect_eq "mail disable --force: the unwire op still running → the slot stays open, the Hub not restarted (R-H6)" \
  "$rc:$(grep -c '^PORTCULLIS_MAIL=on$' "$ML/root/.env"):$(grep -c '^rt_up_service' "$ML/argv"):$(grep -c '^dns_tool' "$ML/argv")" "1:1:0:0"
mte 'printf "%s" "{\"op_id\":\"op1\",\"running\":false,\"ok\":false,\"error\":\"stop failed\"}" > "$ML/hub-op"; mail_disable true true'; rc=$?
expect_eq "mail disable --force: a failed unwire op → the slot stays open" "$rc:$(grep -c '^PORTCULLIS_MAIL=on$' "$ML/root/.env"):$(grep -c 'op op1 failed: stop failed' "$ML/out")" "1:1:1"
mte 'mail_disable true true'; rc=$?
expect_eq "mail disable: the unwire op polled before the slot closes" "$rc:$(jq -c . "$ML/hub-op.in"):$(awk '/hub mail op/ && !o {o=NR} /^dns_tool/ && !d {d=NR} END {print (o > 0 && o < d)}' "$ML/argv")" '0:{"instance":"stalwart","op_id":"op1"}:1'
# test_mail_disable_removes_cert_metric (L11).
mte '_mail_cert_metric 2027-02-01T00:00:00Z; mail_disable true true'; rc=$?
expect_eq "mail disable: the certificate metric goes with the slot" "$rc:$([ -e "$ML/root/monitoring/textfile/mail_cert.prom" ] && echo kept || echo gone)" "0:gone"
# test_mail_export_argv_no_shell: the block's argv with {former_id}
# replaced as ONE element, exec'd in export.service, never a shell.
EXP='{"slot":"open","wired":true,"instance":"stalwart","template":"stalwart","warning":"w","export":{"service":"adapter","argv":["mailctl","export","--former","{former_id}"]}}'
mte 'printf "%s" '"'$EXP'"' > "$ML/hub-provider"; mail_export "former-6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b;touch pwned" ""'; rc=$?
F="$(ls "$ML/root/backups/mail-export/"*.mbox 2>/dev/null | head -n1)"
expect_eq "mail export: docker exec of the block's argv in the instance's service, the id one element" \
  "$rc:$(grep '^docker exec' "$ML/argv")" '0:docker exec -i cid9 mailctl export --former former-6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b\;touch\ pwned'
expect_eq "mail export: the container found by the instance's project and the block's service" \
  "$(grep -c '^docker ps -q --filter label=com.docker.compose.project=portcullis-stalwart --filter label=com.docker.compose.service=adapter --filter status=running$' "$ML/argv")" 1
expect_eq "mail export writes 0600 under backups/mail-export (dir 0700)" "$(file_mode "$F"):$(file_mode "$ML/root/backups/mail-export"):$(grep -c '^From ' "$F")" "600:700:1"
mte 'printf "%s" "{\"wired\":true,\"instance\":\"stalwart\",\"export\":null}" > "$ML/hub-provider"; mail_export former-6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b ""'; rc=$?
expect_eq "mail export: a provider without export says so" "$rc:$(grep -c 'has no export' "$ML/out")" "1:1"
mte 'printf "%s" '"'$EXP'"' > "$ML/hub-provider"; docker() { case "$1" in ps) echo cid9 ;; exec) printf partial; return 1 ;; esac; }; mail_export former-6f1c2a9e-3b4d-4e5f-8a7b-1c2d3e4f5a6b ""'; rc=$?
expect_eq "mail export: a failure leaves no file" "$rc:$(ls -A "$ML/root/backups/mail-export" | wc -l | tr -d ' ')" "1:0"
# test_mail_status_rows: the Hub's view plus core's rows; a void owed, a
# hold, nothing wired or a Problem check is a problem; the Hub not
# answering too.
# The Hub's HostMailStatusView: the provider's own name and version under
# .provider (L5: no top-level label / version).
HS='{"wired":true,"instance":"stalwart","template":"stalwart","provider":{"name":"Stalwart","version":"1.1.0"},"reachable":true,"void_owed":null,"held":null,"generation":4,"applied_generation":4,"checks":{"checks":[{"id":"blocklist","severity":"warning","detail":"listed"}]}}'
mt 'mail_cert_ensure >/dev/null; _mail_cert_metric 2027-02-01T00:00:00Z; printf "%s" '"'$HS'"' > "$ML/hub-status"; mail_status_json > "$ML/st.json"; mail_status_lines "$(cat "$ML/st.json")"'
expect_eq "mail status: no problem, the provider and core rows" \
  "$(jq -c '[.problem, .hub.instance, .cert.not_after, .tlsa.phase, .client_ip]' "$ML/st.json")" '[false,"stalwart","2027-02-01T00:00:00Z","steady","preserved"]'
expect_eq "mail status lines: provider, a warning check, certificate, TLSA" \
  "$(grep -cE 'provider stalwart \(Stalwart 1\.1\.0\)|check blocklist: listed|certificate mail\.mail\.example valid until|TLSA: steady, 1 key' "$ML/out")" 4
for p in '.void_owed = {"reason":"restore"}' '.held = {"reason":"template_changed"}' '.wired = false' '.reachable = false' '.checks.checks[0].severity = "problem"'; do
  J="$(printf '%s' "$HS" | jq -c "$p")"
  mt '_mail_cert_metric 2027-02-01T00:00:00Z; printf "%s" '"'$J'"' > "$ML/hub-status"; mail_status_json > "$ML/st.json"'
  expect_eq "mail status: $p → problem" "$(jq -r .problem "$ML/st.json")" true
done
# void_owed / held false → none (M7); true → owed with no detail.
J="$(printf '%s' "$HS" | jq -c '.void_owed = false | .held = false')"
mt '_mail_cert_metric 2027-02-01T00:00:00Z; printf "%s" '"'$J'"' > "$ML/hub-status"; mail_status_json > "$ML/st.json"; mail_status_lines "$(cat "$ML/st.json")"'
expect_eq "mail status: void_owed / held false → no problem, the block complete" "$(jq -c '[.problem, .hub.void_owed, .hub.held]' "$ML/st.json"):$(grep -c 'TLSA: steady' "$ML/out"):$(grep -c 'Cannot index' "$ML/out")" '[false,null,null]:1:0'
J="$(printf '%s' "$HS" | jq -c '.void_owed = true')"
mt '_mail_cert_metric 2027-02-01T00:00:00Z; printf "%s" '"'$J'"' > "$ML/hub-status"; mail_status_json > "$ML/st.json"; mail_status_lines "$(cat "$ML/st.json")"'
expect_eq "mail status: void_owed true → a problem with no detail" "$(jq -r .problem "$ML/st.json"):$(grep -c 'a void of every mail password is owed (?)' "$ML/out")" 'true:1'
mt '_mail_cert_metric 2027-02-01T00:00:00Z; echo 1 > "$ML/hub-status.rc"; rm -f "$ML/hub-status"; mail_status_json > "$ML/st.json"'
expect_eq "mail status: the Hub not answering → problem, hub null" "$(jq -c '[.problem, .hub]' "$ML/st.json")" '[true,null]'
mt 'printf "%s" '"'$HS'"' > "$ML/hub-status"; mail_status_json > "$ML/st.json"'
expect_eq "mail status: no certificate metric → problem (expiry unknown)" "$(jq -c '[.problem, .cert.not_after]' "$ML/st.json")" '[true,null]'
mt 'export PORTCULLIS_MAIL=off; mail_status_json > "$ML/st.json"'
expect_eq "mail status with the slot closed: nothing" "$(wc -c < "$ML/st.json" | tr -d ' ')" 0
# test_mail_rotate_textfile: the timer's step — the certificate, the TLSA
# state, the metric, the keys to the Hub, the main domain's set (the
# provider's records + mail_tlsa) through the dns tool.
mte 'mail_rotate ""'; rc=$?
expect_eq "mail rotate: rc 0, the metric, hub mail tls, the dns tool with the Hub's records, rules and the TLSA keys" \
  "$rc:$(grep -c '^portcullis_mail_cert_expiry_seconds 1801440000$' "$ML/root/monitoring/textfile/mail_cert.prom"):$(jq -c .spki_sha256 "$ML/hub-tls.in"):$(grep -c '^dns_tool apply sets=mail recs=\[{"name":"mail.example","type":"MX","ttl":3600,"value":"10 mail.mail.example."}\] tlsa=\["aa"\] rules={"relay_include":"","dmarc_floor":"none","draining":false}$' "$ML/argv")" \
  '0:1:["aa"]:1'
expect_eq "mail rotate: mail-tlsa gets --hostname (the switch checks the live TLSA)" "$(grep -c 'mail-tlsa status --hostname mail.mail.example$' "$ML/argv")" 1
mte 'printf "%s" "{\"phase\":\"rollover\",\"due\":\"switch\",\"publish\":[\"aa\",\"bb\"]}" > "$ML/tlsa-status"; printf "{}" > "$ML/tlsa-switch"; mail_rotate ""'; rc=$?
expect_eq "mail rotate: a due switch → mail-tlsa switch, then mail-cert --switch-key" \
  "$rc:$(grep -oE '^rt_run mail-cert (--entrypoint domains -- mail-tlsa switch|-i -- --switch-key)' "$ML/argv" | tr '\n' '|')" \
  "0:rt_run mail-cert --entrypoint domains -- mail-tlsa switch|rt_run mail-cert -i -- --switch-key|"
mte 'printf "%s" "{\"current\":\"bb\",\"phase\":\"retiring\",\"due\":\"drop\",\"publish\":[\"bb\",\"aa\"]}" > "$ML/tlsa-status"; printf "%s" "{\"phase\":\"steady\",\"due\":null,\"publish\":[\"bb\"]}" > "$ML/tlsa-drop"; mail_rotate ""'; rc=$?
expect_eq "mail rotate: a due drop → mail-tlsa drop, its keys to the Hub" "$rc:$(jq -c .spki_sha256 "$ML/hub-tls.in")" '0:["bb"]'
expect_eq "mail rotate: before the drop the Hub confirms the key that stays (hub mail tls, then mail-tlsa drop)" \
  "$(grep -oE 'hub mail tls|mail-tlsa drop' "$ML/argv" | tr '\n' '|')" "hub mail tls|mail-tlsa drop|hub mail tls|"
mte 'printf "%s" "{\"current\":\"bb\",\"phase\":\"retiring\",\"due\":\"drop\",\"publish\":[\"bb\",\"aa\"]}" > "$ML/tlsa-status"; echo 1 > "$ML/hub-tls.rc"; mail_rotate ""'; rc=$?
expect_eq "mail rotate: the Hub not confirming the staying key → no drop (M3)" "$rc:$(grep -c 'mail-tlsa drop' "$ML/argv"):$(jq -c .spki_sha256 "$ML/hub-tls.in")" '1:0:["bb"]'
mte 'mail_rotate --next-key'; rc=$?
expect_eq "mail rotate --next-key: mail-cert --next-key, then mail-tlsa next" \
  "$rc:$(grep -oE '^rt_run mail-cert (-- --next-key|--entrypoint domains -- mail-tlsa next)' "$ML/argv" | tr '\n' '|')" \
  "0:rt_run mail-cert -- --next-key|rt_run mail-cert --entrypoint domains -- mail-tlsa next|"
# test_mail_rotate_keys_despite_no_set: a provider just wired has no set
# until its first document, which the Hub sends only once its keys are
# posted: rotate still gives the serving provider its keys, then fails.
mte 'echo 1 > "$ML/hub-dns-main.rc"; rm -f "$ML/hub-dns-main"; printf "the provider has no set for mail.example yet: try again after its first document\n" > "$ML/hub-dns-main.err"; mail_rotate ""'; rc=$?
expect_eq "mail rotate: no set yet → the keys still posted, then rc 1 naming the set" \
  "$rc:$(jq -c .spki_sha256 "$ML/hub-tls.in" 2>/dev/null):$(grep -c "didn't give the main domain's mail set" "$ML/out")" '1:["aa"]:1'
mte 'echo 1 > "$ML/hub-dns-main.rc"; rm -f "$ML/hub-dns-main"; printf "no mail provider is wired\n" > "$ML/hub-dns-main.err"; mail_rotate ""'; rc=$?
expect_eq "mail rotate with exactly nothing wired: the main set withdrawn, rc 0 (H5)" "$rc:$(grep -c '^dns_tool apply sets=mail recs=\[\] tlsa= rules=$' "$ML/argv"):$(grep -c 'mail records are withdrawn' "$ML/out")" "0:1:1"
# test_mail_tls_only_when_serving (Ruling R2-H5/N1): nothing wired (the
# Hub's tls answer fails then) → the set withdrawn first, hub mail tls
# never asked, rc 0.
mte 'printf "%s" "{\"wired\":false,\"reachable\":false,\"void_owed\":null,\"held\":null}" > "$ML/hub-status"; echo 1 > "$ML/hub-tls.rc"; echo 1 > "$ML/hub-dns-main.rc"; rm -f "$ML/hub-dns-main"; printf "no mail provider is wired\n" > "$ML/hub-dns-main.err"; mail_rotate ""'; rc=$?
expect_eq "mail rotate, nothing wired, tls failing: withdrawn, hub mail tls never asked, rc 0" "$rc:$(grep -c '^dns_tool apply sets=mail recs=\[\]' "$ML/argv"):$(grep -c 'hub mail tls' "$ML/argv")" "0:1:0"
mte 'echo 1 > "$ML/hub-tls.rc"; mail_rotate ""'; rc=$?
expect_eq "mail rotate, serving, the tls answer refused (no drop due): a warning, rc 0" "$rc:$(grep -c "refused the mail certificate's keys" "$ML/out"):$(grep -c 'Mail rotation done' "$ML/out")" "0:1:1"
for p in '.void_owed = {"reason":"restore"}' '.held = {"reason":"template_changed"}' '.reachable = false'; do
  J="$(printf '%s' '{"wired":true,"instance":"stalwart","reachable":true,"void_owed":null,"held":null}' | jq -c "$p")"
  mte 'printf "%s" '"'$J'"' > "$ML/hub-status"; printf "%s" "{\"current\":\"bb\",\"phase\":\"retiring\",\"due\":\"drop\",\"publish\":[\"bb\",\"aa\"]}" > "$ML/tlsa-status"; mail_rotate ""'; rc=$?
  expect_eq "mail rotate, a due drop, not serving ($p): no drop, no tls, rc 0" "$rc:$(grep -c 'mail-tlsa drop' "$ML/argv"):$(grep -c 'hub mail tls' "$ML/argv"):$(grep -c 'drop waits for a serving' "$ML/out")" "0:0:0:1"
done
mte 'mail_enable "" "" none true'; rc=$?
expect_eq "mail enable --provider none: no hub mail tls (nothing serves)" "$rc:$([ -f "$ML/hub-tls.in" ] && echo asked || echo none)" "0:none"
mte 'echo 1 > "$ML/hub-tls.rc"; mail_enable "" "" stalwart true'; rc=$?
expect_eq "mail enable: the tls answer refused after the install → a warning, still wired, rc 0" "$rc:$(grep -c "refused the mail certificate's keys" "$ML/out"):$(grep -c 'is this server'"'"'s mail provider' "$ML/out")" "0:1:1"
mte 'mail_enable "" "" stalwart true'; rc=$?
expect_eq "mail enable: hub mail tls only after the install" "$rc:$(awk '/hub mail install/ && !i {i=NR} /hub mail tls/ && !t {t=NR} END {print (i > 0 && t > i)}' "$ML/argv")" "0:1"
# test_mail_restore_hold_clear (Ruling R2-N5): the hold read, typed clear
# (or --yes), removed as the Hub's uid, logged; no hold → nothing.
mte 'ct_run() { echo "ct_run $*" >> "$ML/argv"; case "$*" in *"cat /d/mail-restore-pending"*) cat "$ML/hold" 2>/dev/null || true ;; esac; }; echo stalwart/20261117T100000Z.tar > "$ML/hold"; mail_restore_hold_clear true'; rc=$?
expect_eq "mail restore-hold clear: the warning says it starts nothing (FH-H3c; L6)" "$(grep -c 'Lifting the hold starts nothing' "$ML/out")" 1
expect_eq "mail restore-hold clear --yes: removed as 10001, named, logged" "$rc:$(grep -c 'ct_run .*--user 10001:10001 -v portcullis_hub_data:/d .* rm -f /d/mail-restore-pending' "$ML/argv"):$(grep -c 'cleared (it named stalwart/20261117T100000Z.tar)' "$ML/out")" "0:1:1"
mt 'ct_run() { echo "ct_run $*" >> "$ML/argv"; case "$*" in *"cat /d/mail-restore-pending"*) echo stalwart/20261117T100000Z.tar ;; esac; }; mail_restore_hold_clear false </dev/null'; rc=$?
expect_eq "mail restore-hold clear without --yes and no terminal: refused, nothing removed" "$rc:$(grep -c 'rm -f /d/mail-restore-pending' "$ML/argv")" "1:0"
mte 'ct_run() { echo "ct_run $*" >> "$ML/argv"; }; mail_restore_hold_clear true'; rc=$?
expect_eq "mail restore-hold clear with no hold: nothing removed" "$rc:$(grep -c 'rm -f' "$ML/argv"):$(grep -c 'No mail restore hold' "$ML/out")" "0:0:1"
mte 'echo 1 > "$ML/hub-dns-main.rc"; rm -f "$ML/hub-dns-main"; printf "no mail provider is wired\n" > "$ML/hub-dns-main.err"; export DNS_NOMAIL=true; mail_rotate ""'; rc=$?
expect_eq "mail rotate, nothing wired, DNS_NOMAIL=true: the null-mail set back in the same run" "$rc:$(grep -c '^dns_tool apply sets=nomail mail recs=\[\]' "$ML/argv")" "0:1"
for f in '1|the provider has no set for mail.example yet' '1|' '2|hub: cannot reach the Hub'; do
  mt "echo ${f%%|*} > \"\$ML/hub-dns-main.rc\"; rm -f \"\$ML/hub-dns-main\"; printf '%s\n' '${f#*|}' > \"\$ML/hub-dns-main.err\"; mail_rotate ''"; rc=$?
  expect_eq "mail rotate: dns-main failing otherwise (rc ${f%%|*}: ${f#*|}) → exit 1, no DNS write, never done" "$rc:$(grep -c '^dns_tool' "$ML/argv"):$(grep -c 'Mail rotation done' "$ML/out")" "1:0:0"
done
mt 'printf "%s" "{\"records\":[]}" > "$ML/hub-dns-main"; mail_rotate ""'; rc=$?
expect_eq "mail rotate: a dns-main answer without rules → exit 1, no DNS write" "$rc:$(grep -c '^dns_tool' "$ML/argv"):$(grep -c 'answered no rules' "$ML/out")" "1:0:1"
mt 'export PORTCULLIS_MAIL=off; mail_rotate ""'; rc=$?
expect_eq "mail rotate with the slot closed: refused" "$rc:$(grep -c 'mail is off' "$ML/out")" "1:1"
# test / dkim rotate through the Hub's routes.
mte 'printf "%s" "{\"queue_id\":\"Q1\"}" > "$ML/hub-test"; mail_test x@example.net'; rc=$?
expect_eq "mail test: hub mail test {to}, the queue id" "$rc:$(jq -c . "$ML/hub-test.in"):$(grep -c 'Queued for x@example.net: Q1' "$ML/out")" '0:{"to":"x@example.net"}:1'
mte 'mail_dkim_rotate team-b.example.org'; rc=$?
expect_eq "mail dkim rotate: hub mail action" "$rc:$(jq -c . "$ML/hub-action.in")" '0:{"name":"dkim-rotate","domain":"team-b.example.org"}'
# dns setup / plan: the main set from the Hub (dns-main) plus the TLSA keys.
mte '. "$HERE/../scripts/lib/dns.sh"; _dns_mail_records false; printf "%s|%s" "$DNS_MAIL_RECORDS" "$DNS_MAIL_TLSA" > "$ML/dnsrec"'; rc=$?
expect_eq "dns: the main set from hub mail dns-main, the TLSA keys from mail-tlsa status" \
  "$rc:$(cat "$ML/dnsrec")" '0:[{"name":"mail.example","type":"MX","ttl":3600,"value":"10 mail.mail.example."}]|["aa"]'
mte '. "$HERE/../scripts/lib/dns.sh"; _dns_mail_records false; printf "%s" "$DNS_MAIL_RULES" > "$ML/dnsrec"'; rc=$?
expect_eq "dns: the main set's rules from hub mail dns-main" "$rc:$(cat "$ML/dnsrec")" '0:{"relay_include":"","dmarc_floor":"none","draining":false}'
# M4: an unreadable TLSA state leaves the mail set out (never published
# without its TLSA); --only mail fails. L10 / H5: a failing Hub says so.
mte '. "$HERE/../scripts/lib/dns.sh"; echo 1 > "$ML/tlsa-status.rc"; _dns_mail_records false; printf "[%s]" "$DNS_MAIL_RECORDS" > "$ML/dnsrec"'; rc=$?
expect_eq "dns: the TLSA state unreadable → no mail set this run, a warning" "$rc:$(cat "$ML/dnsrec"):$(grep -c "TLSA state couldn't be read" "$ML/out")" "0:[]:1"
mt '. "$HERE/../scripts/lib/dns.sh"; echo 1 > "$ML/tlsa-status.rc"; _dns_mail_records true'; rc=$?
expect_eq "dns --only mail: the TLSA state unreadable → refused" "$rc" 1
mte '. "$HERE/../scripts/lib/dns.sh"; echo 2 > "$ML/hub-dns-main.rc"; _dns_mail_records false; printf "[%s]" "$DNS_MAIL_RECORDS" > "$ML/dnsrec"'; rc=$?
expect_eq "dns: the Hub failing → no mail set this run, a warning" "$rc:$(cat "$ML/dnsrec"):$(grep -c "left out of this run" "$ML/out")" "0:[]:1"
mt '. "$HERE/../scripts/lib/dns.sh"; echo 2 > "$ML/hub-dns-main.rc"; _dns_mail_records true'; rc=$?
expect_eq "dns --only mail: the Hub failing → refused" "$rc" 1
mt '. "$HERE/../scripts/lib/dns.sh"; echo 1 > "$ML/hub-dns-main.rc"; printf "no mail provider is wired\n" > "$ML/hub-dns-main.err"; _dns_mail_records true'; rc=$?
expect_eq "dns --only mail: nothing wired → refused" "$rc:$(grep -c 'no mail provider is wired: nothing to write' "$ML/out")" "1:1"
mte '. "$HERE/../scripts/lib/dns.sh"; DNS_SETS=mail DNS_MAIL_RECORDS="[]" DNS_MAIL_TLSA="[\"aa\"]" _dns_tool_input read > "$ML/dnsin"'; rc=$?
expect_eq "dns tool input: mail [] carries no mail_tlsa" "$rc:$(jq -c '[.mail, has("mail_tlsa")]' "$ML/dnsin")" '0:[[],false]'
mte '. "$HERE/../scripts/lib/dns.sh"; DNS_SETS=mail DNS_MAIL_RECORDS="[{\"name\":\"mail.example\",\"type\":\"MX\",\"ttl\":3600,\"value\":\"10 mail.mail.example.\"}]" DNS_MAIL_TLSA="[\"aa\"]" _dns_tool_input read > "$ML/dnsin"'; rc=$?
expect_eq "dns tool input: records + mail_tlsa + mail_hostname on stdin" "$rc:$(jq -c '[.mail_tlsa, .mail_hostname]' "$ML/dnsin")" '0:[["aa"],"mail.mail.example"]'
mt '. "$HERE/../scripts/lib/dns.sh"; echo 1 > "$ML/hub-dns-main.rc"; rm -f "$ML/hub-dns-main"; _dns_mail_records true'; rc=$?
expect_eq "dns setup --only mail with dns-main refused (not the not-wired text): refused" "$rc:$(grep -c "The Hub didn't give\|the Hub didn't give" "$ML/out")" "1:1"
mte '. "$HERE/../scripts/lib/dns.sh"; DNS_SETS=mail DNS_MAIL_RECORDS="[{\"name\":\"mail.example\",\"type\":\"MX\",\"ttl\":3600,\"value\":\"10 mail.mail.example.\"}]" DNS_MAIL_RULES="{\"relay_include\":\"\",\"dmarc_floor\":\"reject\",\"draining\":false}" _dns_tool_input read > "$ML/dnsin"; DNS_SETS=mail DNS_MAIL_RECORDS="[]" DNS_MAIL_RULES="{\"dmarc_floor\":\"reject\"}" _dns_tool_input read > "$ML/dnsin2"'; rc=$?
expect_eq "dns tool input: mail_rules with a non-empty set only" "$rc:$(jq -c .mail_rules "$ML/dnsin"):$(jq -c 'has("mail_rules")' "$ML/dnsin2")" '0:{"relay_include":"","dmarc_floor":"reject","draining":false}:false'
# test_mail_dkim_written (security review): the main set's DKIM names are
# recorded after a write and passed back, so only those are removed.
mte 'printf "%s" "{\"records\":[{\"name\":\"Sel1._domainkey.mail.example.\",\"type\":\"TXT\",\"ttl\":3600,\"value\":\"v=DKIM1; p=x\"},{\"name\":\"a.b._domainkey.mail.example\",\"type\":\"TXT\",\"ttl\":3600,\"value\":\"v=DKIM1; p=y\"},{\"name\":\"mail.example\",\"type\":\"MX\",\"ttl\":3600,\"value\":\"10 mail.mail.example.\"}],\"rules\":{\"relay_include\":\"\",\"dmarc_floor\":\"none\",\"draining\":false}}" > "$ML/hub-dns-main"; mail_rotate ""; mail_rotate ""'; rc=$?
expect_eq "mail rotate: the written DKIM names recorded once (single-label selectors only)" "$rc:$(cat "$ML/root/secrets/mail/dkim-written" 2>/dev/null | tr '\n' '|')" "0:sel1._domainkey.mail.example|"
mte '. "$HERE/../scripts/lib/dns.sh"; mkdir -p "$PORTCULLIS_ROOT/secrets/mail"; echo sel1._domainkey.mail.example > "$PORTCULLIS_ROOT/secrets/mail/dkim-written"; DNS_SETS=mail DNS_MAIL_RECORDS="[]" _dns_tool_input read > "$ML/dnsin"'; rc=$?
expect_eq "dns tool input: mail_dkim_written passed (also when the set is withdrawn)" "$rc:$(jq -c .mail_dkim_written "$ML/dnsin")" '0:["sel1._domainkey.mail.example"]'
mte 'echo 1 > "$ML/hub-dns-main.rc"; rm -f "$ML/hub-dns-main"; printf "no mail provider is wired\n" > "$ML/hub-dns-main.err"; mail_rotate ""'; rc=$?
expect_eq "mail rotate: a withdrawal records nothing" "$rc:$([ -s "$ML/root/secrets/mail/dkim-written" ] && echo some || echo none)" "0:none"
# up / upgrade with the slot open: the refusals and the certificate when
# mail_tls has none.
mte 'mail_tls_present() { return 1; }; mail_up_steps up'; rc=$?
expect_eq "mail_up_steps: no chain in mail_tls → mail-cert" "$rc:$(grep -c '^rt_run mail-cert -i' "$ML/argv")" "0:1"
mt 'export MAIL_IPV6=on; mail_up_steps up'; rc=$?
expect_eq "mail_up_steps refuses MAIL_IPV6" "$rc" 1
mt 'export PORTCULLIS_MAIL=off; mail_up_steps up'; rc=$?
expect_eq "mail_up_steps with the slot closed: nothing" "$rc:$(wc -l < "$ML/argv" 2>/dev/null | tr -d ' ' || echo 0)" "0:0"
# With the slot open the domains service's env file says mail is on (its
# main plan then owns MAIL_HOSTNAME's addresses).
mt 'mkdir -p "$ML/root/secrets/domains"; export PORTCULLIS_PUBLIC_IPV4=203.0.113.25 PORTCULLIS_PUBLIC_IPV6=; domains_public_ips'
expect_eq "domains env file: DOMAINS_MAIL=on with the slot open" "$(grep '^DOMAINS_MAIL=' "$ML/root/secrets/domains/public-ips.env" 2>/dev/null)" "DOMAINS_MAIL=on"
# test_no_mailctl_exec: the CLI execs into no mail container (only the
# block's export argv, through _mail_instance_exec).
expect_eq "no mailctl exec / recovery session / old mail keys in the CLI" \
  "$(grep -nE 'mailctl|recovery|MAIL_RELAY|MAIL_DKIM_ROTATE|MAIL_FORMER_RETENTION|MAIL_SPAMHAUS|--rotate-key|COMPOSE_PROFILES.*mail' "$HERE/../scripts/lib/mail.sh" "$HERE/../scripts/lib/dns.sh" "$HERE/../scripts/lib/stack.sh" "$HERE/../scripts/lib/common.sh" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)" ""
# A link to a directory survives a volume archive (mail_tls: current ->
# .gen-*, mail-cert's pair, final review L8).
SN="$WORK/snap-links"; mkdir -p "$SN/vol/.gen-a"; echo k > "$SN/vol/.gen-a/privkey.pem"
ln -s .gen-a "$SN/vol/current"; ln -s current/privkey.pem "$SN/vol/privkey.pem"
printf '%s' "$_BACKUP_PY_SNAPSHOT" | sed "s#SRC = \"/vol\"#SRC = \"$SN/vol\"#" > "$SN/snap.py"
expect_eq "volume archive: links kept, a link to a directory included" \
  "$(python3 "$SN/snap.py" 2>/dev/null | tar -tzvf - | awk '$1 ~ /^l/ {print $(NF-2), $NF}' | sort | tr '\n' '|')" \
  "./current .gen-a|./privkey.pem current/privkey.pem|"
# Final review L2: the stack-changing commands run one at a time, shared
# with the timers (a held lock makes a second one wait, then refuse).
mkdir -p "$ML.lock-root"
( exec 8>>"$ML.lock-root/.portcullis.lock"; flock 8; sleep 4 ) & lockpid=$!
sleep 1
rc=0; ( export PORTCULLIS_ROOT="$ML.lock-root" PORTCULLIS_LOCK_WAIT=1; unset PORTCULLIS_LOCKED; cli_lock backup ) >/dev/null 2>&1 || rc=$?
expect_eq "cli_lock: a held lock → backup waits, then refuses" "$rc" 1
rc=0; ( export PORTCULLIS_ROOT="$ML.lock-root" PORTCULLIS_LOCK_WAIT=1; unset PORTCULLIS_LOCKED; cli_lock kube params-sync ) >/dev/null 2>&1 || rc=$?
expect_eq "cli_lock: a held lock → kube params-sync waits, then refuses (review I3)" "$rc" 1
rc=0; ( export PORTCULLIS_ROOT="$ML.lock-root" PORTCULLIS_LOCK_WAIT=1; unset PORTCULLIS_LOCKED; cli_lock mail rotate --help; cli_lock status; cli_lock kube status; cli_lock kube params-sync --help ) >/dev/null 2>&1 || rc=$?
expect_eq "cli_lock: --help and read-only commands never wait" "$rc" 0
wait "$lockpid" 2>/dev/null
rc=0; ( export PORTCULLIS_ROOT="$ML.lock-root" PORTCULLIS_LOCK_WAIT=1; unset PORTCULLIS_LOCKED; cli_lock mail rotate ) >/dev/null 2>&1 || rc=$?
expect_eq "cli_lock: free → taken" "$rc" 0
rm -rf "$ML.lock-root"
# Final review L7: a MAIL_HOSTNAME change records the old host; only
# recorded hosts reach the dns tool as mail_former_hosts.
mte '. "$HERE/../scripts/lib/dns.sh"; export MAIL_HOSTNAME=mail.mail.example; mail_hostname_track; mail_hostname_track; export MAIL_HOSTNAME=mx.mail.example; mail_hostname_track
  DNS_SETS=mail DNS_MAIL_RECORDS="[]" _dns_tool_input read > "$ML/dnsin"'; rc=$?
expect_eq "MAIL_HOSTNAME change → the old host recorded once, passed as mail_former_hosts" \
  "$rc:$(tr '\n' ' ' < "$ML/root/secrets/mail/former-hostnames"):$(cat "$ML/root/secrets/mail/hostname"):$(jq -c '[.mail_hostname, .mail_former_hosts]' "$ML/dnsin")" \
  '0:mail.mail.example :mx.mail.example:["mx.mail.example",["mail.mail.example"]]'
mte '. "$HERE/../scripts/lib/dns.sh"; DNS_SETS=mail DNS_MAIL_RECORDS="[]" _dns_tool_input read > "$ML/dnsin"'; rc=$?
expect_eq "no recorded former host → no mail_former_hosts" "$rc:$(jq -c 'has("mail_former_hosts")' "$ML/dnsin")" "0:false"
# IPv6 for mail isn't supported yet: a set MAIL_IPV6 is refused.
mt 'export MAIL_IPV6=on; mail_ipv6_refuse'; rc=$?
expect_eq "MAIL_IPV6 set → refused (isn't supported yet)" "$rc:$(grep -c "MAIL_IPV6 isn't supported yet" "$ML/out")" "1:1"
mt 'export MAIL_IPV6=off; mail_ipv6_refuse'; rc=$?
expect_eq "MAIL_IPV6=off is refused too (any value)" "$rc" 1
mt 'mail_ipv6_refuse'; rc=$?
expect_eq "MAIL_IPV6 unset → fine" "$rc" 0
expect_eq "no [::] port and no MAIL_IPV6 in compose" "$(grep -cE '\[::\]:(25|465|587|993):|MAIL_IPV6' "$HERE/../docker-compose.yml")" 0

# The mail certificate's CA (security review): MAIL_ACME_CA_SERVER is
# https only, and its CAA issuer is MAIL_CAA_ISSUER, never Traefik's.
# (stack.sh / dns.sh: loaded in the subshell only.)
SDL='source "$HERE/../scripts/lib/stack.sh"; source "$HERE/../scripts/lib/dns.sh"; '
mci() { mt "$SDL"'export DNS_PROVIDER=porkbun PORKBUN_API_KEY=k PORKBUN_SECRET_API_KEY=s DNS_CAA_ISSUER=traefik-ca.test '"$1"'; _mail_cert_input > "$ML/in"'; }
mci 'export MAIL_ACME_CA_SERVER=http://ca.test/dir'; rc=$?
expect_eq "MAIL_ACME_CA_SERVER http:// → refused" "$rc:$(grep -c 'must be an https://' "$ML/out")" "1:1"
mci 'export MAIL_ACME_CA_SERVER=ftp://ca.test/dir'; rc=$?
expect_eq "MAIL_ACME_CA_SERVER not https → refused" "$rc" 1
mci 'export MAIL_ACME_CA_SERVER=https://ca.test/dir'; rc=$?
expect_eq "MAIL_ACME_CA_SERVER https, no MAIL_CAA_ISSUER → issuer empty (mail-cert refuses), not DNS_CAA_ISSUER" \
  "$rc:$(jq -c '{ca_server, i: .caa.issuer}' "$ML/in")" '0:{"ca_server":"https://ca.test/dir","i":""}'
mci 'export MAIL_ACME_CA_SERVER=https://ca.test/dir MAIL_CAA_ISSUER=ca.test'; rc=$?
expect_eq "MAIL_ACME_CA_SERVER + MAIL_CAA_ISSUER → that issuer" "$rc:$(jq -r .caa.issuer "$ML/in")" "0:ca.test"
mci ':'; rc=$?
expect_eq "no MAIL_ACME_CA_SERVER → Traefik's CA and DNS_CAA_ISSUER" "$rc:$(jq -r '.ca_server + " " + .caa.issuer' "$ML/in")" \
  "0:https://acme-v02.api.letsencrypt.org/directory traefik-ca.test"
# The fake DNS provider: CI only.
mt "$SDL"'_dns_automated fake'; rc=$?
expect_eq "DNS_PROVIDER=fake without PORTCULLIS_TESTPROVIDER=1 → not automated" "$rc" 1
mt "$SDL"'export PORTCULLIS_TESTPROVIDER=1; _dns_automated fake && [ "$(_dns_cred_keys fake)" = FAKE_API_TOKEN:api_token ]'; rc=$?
expect_eq "fake with PORTCULLIS_TESTPROVIDER=1 → automated, FAKE_API_TOKEN" "$rc" 0

# ── backup / restore of the mail provider (contract §19.11, mail provider Task 24) ──
# bmp <.env extra> <script> — backup_create in a fresh root (set -e, as
# ./portcullis runs) with the Hub's `hub mail` stubbed ($BM/hub-<cmd>,
# calls in $BM/calls) and hub_data the one file volume (its archive call
# logged, so the order shows).
BM="$WORK/bmail"
bmp() {
  rm -rf "$BM"; mkdir -p "$BM/root/secrets" "$BM/root/certs"
  printf 'PORTCULLIS_DOMAIN=x\nCONTAINER_RUNTIME=docker\n%s\n' "$1" > "$BM/root/.env"
  printf '%s' '{"wired":true,"instance":"stalwart","template":"stalwart","warning":"w"}' > "$BM/hub-provider"
  printf '%s' '{"archive":"stalwart/20261117T100000Z.tar"}' > "$BM/hub-backup"
  (
    set -e
    export PORTCULLIS_ROOT="$BM/root" BACKUP_ROOT="$BM/root/backups" BACKUP_FILE_VOLUMES="hub_data:10001:10001"
    env_load
    _BACKUP_CFG='{"services":{"hub":{"image":"hub:1"}},"volumes":{"hub_data":{"name":"portcullis_hub_data"}}}'
    dc() { :; }; wait_healthy() { :; }; vault_wait_active() { :; }; vault_admin_env() { echo t; }
    _backup_vault_snapshot() { echo snap > "$1"; }; _backup_pg_dump() { echo PGDMP > "$1"; }
    _backup_metrics() { :; }; rt_health() { echo healthy; }; rt_running() { return 0; }
    docker() { :; }
    _backup_volume_files() { echo "archive $1" >> "$BM/calls"; printf 'x' | gzip; }
    rt_exec() {
      local -a a=("$@"); local i=0
      while [ "${a[$i]}" != -- ]; do i=$((i + 1)); done
      local c="${a[$((i + 3))]}"
      echo "hub mail $c" >> "$BM/calls"
      cat > /dev/null
      # $BM/hub-<cmd>.busy: that many answers of the Hub's 409 "in progress" first.
      local b; b="$(cat "$BM/hub-$c.busy" 2>/dev/null || echo 0)"
      if [ "$b" -gt 0 ]; then echo $((b - 1)) > "$BM/hub-$c.busy"; echo "stalwart: an operation is in progress: try again" >&2; return 1; fi
      cat "$BM/hub-$c"
      return "$(cat "$BM/hub-$c.rc" 2>/dev/null || echo 0)"
    }
    eval "$2"
    backup_create
  ) >"$BM/out" 2>&1
}
bm_dir() { find "$BM/root/backups" -mindepth 1 -maxdepth 1 -type d -name '2*' ! -name '*.partial' | head -n1; }
# test_backup_calls_hub_mail_backup_first
bmp 'PORTCULLIS_MAIL=on' ':'; rc=$?
expect_eq "backup: hub mail backup before hub_data is archived" "$rc:$(grep -vx 'hub mail provider' "$BM/calls" | tr '\n' '|')" "0:hub mail backup|archive portcullis_hub_data|"
# test_backup_manifest_names_archive
expect_eq "backup: MANIFEST.json names the provider's archive" "$(jq -r .mail_provider_archive "$(bm_dir)/MANIFEST.json")" "stalwart/20261117T100000Z.tar"
# test_backup_retries_hub_busy: the Hub's 409 "in progress" (a start-time
# void holds the instance lock) is retried within MAIL_OP_WAIT.
bmp 'PORTCULLIS_MAIL=on' 'echo 2 > "$BM/hub-backup.busy"; export MAIL_OP_POLL=0'; rc=$?
expect_eq "backup: hub mail backup busy twice, then done" "$rc:$(grep -c 'hub mail backup' "$BM/calls"):$(jq -r .mail_provider_archive "$(bm_dir)/MANIFEST.json")" "0:3:stalwart/20261117T100000Z.tar"
bmp 'PORTCULLIS_MAIL=on' 'echo 99 > "$BM/hub-backup.busy"; export MAIL_OP_POLL=0 MAIL_OP_WAIT=0'; rc=$?
expect_eq "backup: busy past MAIL_OP_WAIT fails (nothing saved)" "$rc:$([ -n "$(bm_dir)" ] && echo saved || echo none)" "1:none"
bmp 'PORTCULLIS_MAIL=on' 'echo 1 > "$BM/hub-backup.rc"'; rc=$?
expect_eq "backup: a failed provider backup fails the backup (nothing saved)" "$rc:$([ -n "$(bm_dir)" ] && echo saved || echo none)" "1:none"
# L4: an instance id with "_" (the Hub's archiveRe allows it) is a valid archive.
bmp 'PORTCULLIS_MAIL=on' 'printf "%s" "{\"archive\":\"mail_2/20261117T100000Z.tar\"}" > "$BM/hub-backup"'; rc=$?
expect_eq "backup: an instance id with _ names a valid archive" "$rc:$(jq -r .mail_provider_archive "$(bm_dir)/MANIFEST.json")" "0:mail_2/20261117T100000Z.tar"
bmp 'PORTCULLIS_MAIL=on' 'printf "%s" "{\"archive\":\"../../etc/x.tar\"}" > "$BM/hub-backup"'; rc=$?
expect_eq "backup: a malformed archive name from the Hub fails the backup" "$rc:$(grep -c 'names no archive' "$BM/out")" "1:1"
bmp 'PORTCULLIS_MAIL=on' 'printf "%s" "{\"wired\":false,\"warning\":\"w\"}" > "$BM/hub-provider"'; rc=$?
expect_eq "backup: the slot open, nothing wired → no provider backup, no manifest key" "$rc:$(grep -c 'hub mail backup' "$BM/calls"):$(jq -c 'has("mail_provider_archive")' "$(bm_dir)/MANIFEST.json")" "0:0:false"
# test_backup_without_slot_skips (set -e harness)
bmp '' ':'; rc=$?
expect_eq "backup with the slot closed: no Hub call, no manifest key" "$rc:$(grep -c 'hub mail' "$BM/calls"):$(jq -c 'has("mail_provider_archive")' "$(bm_dir)/MANIFEST.json")" "0:0:false"
expect_eq "backup: mail_acme and mail_tls archived online (tlsa.json and the keys), mail_slot never" \
  "$(tr ' ' '\n' <<<"$BACKUP_FILE_VOLUMES" | grep -E '^mail_' | tr '\n' ' ')" "mail_acme:10004:10004 mail_tls:10004:2000 "
# test_restore_stops_mail_provider (Ruling X-H2): the provider mounts no
# hub_secrets since R-POD2, so the restore takes it down itself — the
# Hub's wired instance and every project mounting the provider slot or
# mail_tls (core's own containers skipped); an unlistable engine fails
# closed. sp <script>: docker stubbed ($SP/ps-<volume> = ids,
# $SP/proj-<id> = project, $SP/ps.rc, $SP/down.rc), calls in $SP/calls.
SP="$WORK/stopmail"
sp() {
  rm -rf "$SP"; mkdir -p "$SP"
  (
    _BACKUP_CFG='{"volumes":{"mail_provider_slot":{"name":"portcullis_mail_provider_slot"},"mail_tls":{"name":"portcullis_mail_tls"}}}'
    export CONTAINER_RUNTIME=docker
    docker() {
      echo "docker $*" >> "$SP/calls"
      case "$1 $2" in
        "ps -aq") local v="${4#volume=}"; [ ! -f "$SP/ps.rc" ] || return "$(cat "$SP/ps.rc")"; cat "$SP/ps-$v" 2>/dev/null; return 0 ;;
        "inspect -f") cat "$SP/proj-$4"; return 0 ;;
        "compose -p") return "$(cat "$SP/down.rc" 2>/dev/null || echo 0)" ;;
      esac
    }
    eval "$1"
  ) >"$SP/out" 2>&1
}
sp 'echo c1 > "$SP/ps-portcullis_mail_provider_slot"; echo portcullis-stalwart > "$SP/proj-c1"; echo "c2 c3" > "$SP/ps-portcullis_mail_tls"; echo portcullis-stalwart > "$SP/proj-c2"; echo portcullis > "$SP/proj-c3"
    _restore_stop_mail_provider stalwart portcullis; echo "rc=$? mail=[$RESTORE_STOPPED_MAIL]"'
expect_eq "restore: the wired provider taken down once (Hub's id + its slot mounts), core's mail-cert skipped" \
  "$(grep -c 'compose -p portcullis-stalwart down' "$SP/calls"):$(grep -c 'compose -p portcullis down' "$SP/calls"):$(tail -n1 "$SP/out")" "1:0:rc=0 mail=[portcullis-stalwart]"
sp 'echo c9 > "$SP/ps-portcullis_mail_tls"; echo portcullis-mail2 > "$SP/proj-c9"; _restore_stop_mail_provider "" portcullis; echo "rc=$? mail=[$RESTORE_STOPPED_MAIL]"'
expect_eq "restore: the Hub unable to name it → the provider found by its volumes" "$(tail -n1 "$SP/out")" "rc=0 mail=[portcullis-mail2]"
sp 'echo 1 > "$SP/ps.rc"; _restore_stop_mail_provider stalwart portcullis; echo "rc=$? msg=$_RESTORE_ERROR_MSG"'
expect_eq "restore: an unlistable engine fails closed (nothing taken down)" \
  "$(grep -c 'compose -p' "$SP/calls" || true):$(grep -c 'rc=1 msg=can.t list the containers' "$SP/out")" "0:1"
sp 'echo c1 > "$SP/ps-portcullis_mail_provider_slot"; echo portcullis-stalwart > "$SP/proj-c1"; echo 1 > "$SP/down.rc"; _restore_stop_mail_provider stalwart portcullis; echo "rc=$? msg=$_RESTORE_ERROR_MSG"'
expect_eq "restore: a failed down of the provider fails closed" "$(grep -c 'rc=1 msg=could not take down the mail provider portcullis-stalwart' "$SP/out")" 1
sp 'echo c5 > "$SP/ps-portcullis_mail_provider_slot"; echo "" > "$SP/proj-c5"; _restore_stop_mail_provider "" portcullis; echo "rc=$?"'
expect_eq "restore: a container outside any compose project mounting the slot fails closed" "$(tail -n1 "$SP/out")" "rc=1"
expect_eq "restore: the provider stop runs right after the hub_secrets apps, before anything changes" \
  "$(declare -f _backup_restore_docker | grep -cE '_restore_stop_mail_provider "\$mail_inst"|_restore_stop_mail_provider "" portcullis'):$(declare -f _backup_restore_docker | grep -c 'mail_inst="\$(_restore_mail_instance)"')" "2:1"
# test_restore_mail_provider_first (Ruling R-C1, M8, M9): the manifest
# names an archive and the slot is open → the hold file into hub_data, the
# Hub started alone, `hub mail restore {archive}` waited for to its op's
# end — whether the instance's volumes exist or not; any failure returns 1
# (never an exit) and fails the restore at its end.
rmp() {
  rm -rf "$BM"; mkdir -p "$BM/root" "$BM/bk"
  printf 'PORTCULLIS_MAIL=on\nCONTAINER_RUNTIME=docker\n' > "$BM/root/.env"
  printf '%s' '{"mail_provider_archive":"stalwart/20261117T100000Z.tar"}' > "$BM/bk/MANIFEST.json"
  printf '%s' '{"wired":true}' > "$BM/hub-provider"
  printf '%s' '{"op_id":"op7","op":"mail-restore","instance":"stalwart","poll":"/api/instances/stalwart/op?op_id=op7"}' > "$BM/hub-restore"
  printf '%s' '{"op_id":"op7","running":false,"ok":true}' > "$BM/hub-op"
  (
    export PORTCULLIS_ROOT="$BM/root" MAIL_OP_POLL=0
    env_load
    _BACKUP_CFG='{"volumes":{"hub_data":{"name":"portcullis_hub_data"}}}'
    rt_health() { echo healthy; }
    rt_up_service() { echo "rt_up_service $*" >> "$BM/calls"; }
    ct_run() { echo "ct_run $*" >> "$BM/calls"; cat > "$BM/hold"; }
    docker() { echo "docker $*" >> "$BM/calls"; }
    rt_exec() {
      local -a a=("$@"); local i=0
      while [ "${a[$i]}" != -- ]; do i=$((i + 1)); done
      local c="${a[$((i + 3))]}"
      echo "hub mail $c" >> "$BM/calls"; cat > "$BM/hub-$c.in"
      local b; b="$(cat "$BM/hub-$c.busy" 2>/dev/null || echo 0)"
      if [ "$b" -gt 0 ]; then echo $((b - 1)) > "$BM/hub-$c.busy"; echo "stalwart: an operation is in progress: try again" >&2; return 1; fi
      cat "$BM/hub-$c"
      return "$(cat "$BM/hub-$c.rc" 2>/dev/null || echo 0)"
    }
    eval "$1"
    # shellcheck disable=SC2034  # read by _restore_mail_outcome
    RESTORE_MAIL_FAILED=false
    # shellcheck disable=SC2034
    _restore_mail_provider "$BM/bk" || RESTORE_MAIL_FAILED=true
    echo "after the provider restore" >> "$BM/calls"
    _restore_mail_outcome
  ) >"$BM/out" 2>&1
}
rmp ':'; rc=$?
expect_eq "restore: the hold, the Hub alone, hub mail restore {archive}, its op polled" \
  "$rc:$(jq -c . "$BM/hub-restore.in"):$(jq -c . "$BM/hub-op.in"):$(cat "$BM/hold"):$(grep -E '^(ct_run|rt_up_service|hub mail (restore|op))' "$BM/calls" | sed 's/ -v .*//' | tr '\n' '|')" \
  '0:{"archive":"stalwart/20261117T100000Z.tar"}:{"instance":"stalwart","op_id":"op7"}:stalwart/20261117T100000Z.tar:ct_run --rm -i --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --user 10001:10001|rt_up_service --deps hub|hub mail restore|hub mail op|'
expect_eq "restore: the hold written into hub_data as mail-restore-pending" "$(grep -c "portcullis_hub_data:/d .*cat > /d/mail-restore-pending" "$BM/calls")" 1
rmp 'docker() { echo "docker $*" >> "$BM/calls"; [ "$1 $2" != "volume ls" ] || echo portcullis-stalwart_data; }'; rc=$?
expect_eq "restore: the provider's volumes present → restored all the same (M9)" "$rc:$(grep -c 'hub mail restore' "$BM/calls")" "0:1"
# test_restore_retries_hub_busy
rmp 'echo 2 > "$BM/hub-restore.busy"'; rc=$?
expect_eq "restore: hub mail restore busy twice, then its op polled to ok" "$rc:$(grep -c 'hub mail restore' "$BM/calls"):$(grep -c 'hub mail op' "$BM/calls")" "0:3:1"
rmp 'echo 1 > "$BM/hub-restore.rc"'; rc=$?
expect_eq "restore: the Hub refusing the provider restore fails the restore at its end" "$rc:$(grep -c "couldn't be restored from its archive" "$BM/out"):$(grep -c 'after the provider restore' "$BM/calls")" "1:1:1"
expect_eq "restore: the failure names restore-hold clear as starting nothing (Retry starts the provider; FH-H3c)" \
  "$(grep -c "restore-hold clear (that starts nothing: the provider stays stopped until its Mail tab's Retry" "$BM/out"):$(grep -c 'then starts on what its volumes hold' "$BM/out")" "1:0"
rmp 'printf "%s" "{\"op_id\":\"op7\",\"running\":false,\"ok\":false,\"error\":\"tar: bad\"}" > "$BM/hub-op"'; rc=$?
expect_eq "restore: a failed restore op fails the restore at its end" "$rc:$(grep -c 'op op7 failed: tar: bad' "$BM/out")" "1:1"
rmp 'printf "%s" "{\"op_id\":\"op7\",\"running\":true}" > "$BM/hub-op"; export MAIL_RESTORE_WAIT=0'; rc=$?
expect_eq "restore: an op still running after MAIL_OP_WAIT fails (never done early)" "$rc:$(grep -c 'still runs after 0 s' "$BM/out")" "1:1"
rmp 'rt_health() { echo exited; }'; rc=$?
expect_eq "restore: a Hub that never answers → no exit mid-restore, failed at the end (M8)" "$rc:$(grep -c 'after the provider restore' "$BM/calls"):$(grep -c 'hub mail restore' "$BM/calls")" "1:1:0"
rmp 'export PORTCULLIS_MAIL=off'; rc=$?
expect_eq "restore: an archive with the slot closed → loud, failed at the end" "$rc:$(grep -c 'the mail slot is closed here' "$BM/out"):$(grep -c 'hub mail' "$BM/calls")" "1:1:0"
rmp 'printf "%s" "{}" > "$BM/bk/MANIFEST.json"'; rc=$?
expect_eq "restore: no archive in the manifest → nothing" "$rc:$(grep -vc 'after the provider restore' "$BM/calls")" "0:0"
# test_restore_order_behaviour (L15): the restore's own tail run with its
# steps stubbed — hub_secrets emptied, then the provider restore, then the
# stack up, then "Restore complete" only when the provider was restored.
rto() {
  rm -rf "$BM"; mkdir -p "$BM"
  (
    body="$(awk '/^_backup_restore_docker\(\) \{/{f=1} f && /info "Emptying hub_secrets volume\.\.\."/{p=1} p{print} f && p && /^}/{exit}' "$HERE/../scripts/lib/backup.sh")"
    eval "_rto_tail() { local dir=\"\$BM\" proj=portcullis helper=h full allow_empty_lldap=false pre=\"\" RESTORE_STOPPED_APPS=\"\"
$body"
    _volume_name() { echo "portcullis_$1"; }
    docker() { echo "docker $1 $2" >> "$BM/calls"; [ "$1 $2" != "volume inspect" ]; }
    _restore_lldap_guard() { :; }; stack_prepare() { :; }; config_build_ca_bundle() { :; }; vault_init() { :; }
    wait_healthy() { :; }; _restore_lost_devices_note() { echo "last line" >> "$BM/calls"; }
    rt_up() { echo "rt_up" >> "$BM/calls"; }
    _restore_mail_provider() { echo "provider restore" >> "$BM/calls"; eval "${RTO_MAIL:-:}"; }
    _rto_tail
  ) >"$BM/out" 2>&1
}
rto; rc=$?
expect_eq "restore order: hub_secrets emptied, the provider restored, then the stack up, complete" \
  "$rc:$(grep -E '^(docker volume rm|provider restore|rt_up|last line)' "$BM/calls" | tr '\n' '|'):$(grep -c 'Restore complete' "$BM/out")" \
  "0:docker volume rm|provider restore|rt_up|last line|:1"
# The provider slot volume (R-POD2) emptied with hub_secrets, when it exists.
rm -rf "$BM"; mkdir -p "$BM"
(
  body="$(awk '/^_backup_restore_docker\(\) \{/{f=1} f && /info "Emptying hub_secrets volume\.\.\."/{p=1} p{print} f && p && /^}/{exit}' "$HERE/../scripts/lib/backup.sh")"
  eval "_rto_tail() { local dir=\"\$BM\" proj=portcullis helper=h full allow_empty_lldap=false pre=\"\" RESTORE_STOPPED_APPS=\"\"
$body"
  _volume_name() { echo "portcullis_$1"; }
  docker() { echo "docker $*" >> "$BM/calls"; case "$1 $2 $3" in "volume inspect portcullis_hub_secrets") return 1 ;; esac; return 0; }
  _restore_lldap_guard() { :; }; stack_prepare() { :; }; config_build_ca_bundle() { :; }; vault_init() { :; }
  wait_healthy() { :; }; _restore_lost_devices_note() { :; }; rt_up() { :; }; _restore_mail_provider() { :; }
  _rto_tail
) >"$BM/out" 2>&1
expect_eq "restore empties the mail provider slot volume too (R-POD2)" "$(grep -c "docker run --rm --network none -v portcullis_mail_provider_slot:/data h sh -c find /data -mindepth 1 -delete" "$BM/calls")" 1
RTO_MAIL='return 1' rto; rc=$?
expect_eq "restore order: a failed provider restore → never \"Restore complete\"" "$rc:$(grep -c 'Restore complete' "$BM/out"):$(grep -c 'NOT restored from its archive' "$BM/out")" "0:0:1"
# test_backup_verify_mail_archive (M10): the archive the manifest names
# is a readable tar inside hub_data.tar.gz.
bvm() {
  rm -rf "$BM"; mkdir -p "$BM/bk" "$BM/src/backups/stalwart" "$BM/inner"
  printf '%s' '{"mail_provider_archive":"stalwart/20261117T100000Z.tar"}' > "$BM/bk/MANIFEST.json"
  echo m > "$BM/inner/msg"
  eval "$1"
  ( cd "$BM/src" && tar -czf "$BM/bk/hub_data.tar.gz" . )
  ( _backup_verify_mail_archive "$BM/bk" ) >"$BM/out" 2>&1
}
bvm 'tar -cf "$BM/src/backups/stalwart/20261117T100000Z.tar" -C "$BM/inner" msg'; rc=$?
expect_eq "backup verify: the provider's archive in hub_data.tar.gz → ok" "$rc:$(grep -c 'is in hub_data.tar.gz' "$BM/out")" "0:1"
bvm ':'; rc=$?
expect_eq "backup verify: the provider's archive missing from hub_data.tar.gz → fails" "$rc:$(grep -c 'missing from hub_data.tar.gz' "$BM/out")" "1:1"
bvm 'echo garbage > "$BM/src/backups/stalwart/20261117T100000Z.tar"'; rc=$?
expect_eq "backup verify: a provider archive that isn't a tar → fails" "$rc" "1"
bvm 'printf "%s" "{}" > "$BM/bk/MANIFEST.json"'; rc=$?
expect_eq "backup verify: no provider archive named → nothing to check" "$rc:$(wc -c < "$BM/out" | tr -d ' ')" "0:0"
expect_eq "no mail store copy, recovery session or void marker left in backup.sh" \
  "$(grep -cE '_backup_mail_data|BACKUP_MAIL_STOPPED|mail_void|recovery|mailctl' "$HERE/../scripts/lib/backup.sh")" 0

# test_no_committed_mailctl_binary (H1): the build output is ignored and
# not tracked (a checkout only; a tarball has no .git).
if git -C "$HERE/.." rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  expect_eq "mailctl/mailctl: ignored, never tracked" \
    "$(git -C "$HERE/.." check-ignore -q --no-index mailctl/mailctl && echo ignored || echo not-ignored):$(git -C "$HERE/.." ls-files mailctl/mailctl | wc -l | tr -d ' ')" "ignored:0"
fi

# ══ link: ./portcullis link … (scripts/lib/link.sh, contract §17) ═══════
# shellcheck source=../scripts/lib/link.sh
source "$HERE/../scripts/lib/link.sh"
# test_link_network_validation
expect_ok "link nets: the defaults are valid" validate_link_network_config
check_lnet() { PORTCULLIS_LINK_NET="$1" PORTCULLIS_LINK_HUB_IP="$2" PORTCULLIS_LINK_WG_IP="$3" PORTCULLIS_LINK_DATA_NET="$4" PORTCULLIS_LINK_DATA_IP_RANGE="$5" PORTCULLIS_LINK_DATA_WG_IP="$6" validate_link_network_config; }
expect_ok "link nets: moved together → valid" check_lnet 10.79.0.0/29 10.79.0.2 10.79.0.3 10.79.1.0/26 10.79.1.32/27 10.79.1.2
expect_fail "link nets: the Hub and wg at one address → fail" check_lnet 172.31.254.80/29 172.31.254.83 172.31.254.83 172.31.254.128/26 172.31.254.160/27 172.31.254.130
expect_fail "link nets: wg outside portcullis-link → fail" check_lnet 172.31.254.80/29 172.31.254.82 172.31.254.99 172.31.254.128/26 172.31.254.160/27 172.31.254.130
expect_fail "link nets: the gateway address → fail" check_lnet 172.31.254.80/29 172.31.254.81 172.31.254.83 172.31.254.128/26 172.31.254.160/27 172.31.254.130
expect_fail "link nets: wg's data address in the relays' range → fail" check_lnet 172.31.254.80/29 172.31.254.82 172.31.254.83 172.31.254.128/26 172.31.254.160/27 172.31.254.161
expect_fail "link nets: the two subnets overlap → fail" check_lnet 172.31.254.128/29 172.31.254.130 172.31.254.131 172.31.254.128/26 172.31.254.160/27 172.31.254.140
expect_fail "link nets: overlapping portcullis-vpn → fail" check_lnet 172.31.254.0/29 172.31.254.2 172.31.254.3 172.31.254.128/26 172.31.254.160/27 172.31.254.130
expect_fail "link nets: overlapping the link tunnel 10.214.0.0/24 → fail" check_lnet 10.214.0.0/29 10.214.0.2 10.214.0.3 172.31.254.128/26 172.31.254.160/27 172.31.254.130
expect_fail "link nets: not a CIDR → fail" check_lnet nope 172.31.254.82 172.31.254.83 172.31.254.128/26 172.31.254.160/27 172.31.254.130
expect_eq "vpn_reserved_ranges ends with the two link nets (= WG_CORE_SUBNETS' order)" \
  "$(vpn_reserved_ranges | awk '{print $(NF-1), $NF}')" "172.31.254.80/29 172.31.254.128/26"
expect_eq "network_check validates the link nets and guards both" \
  "$(declare -f network_check | grep -c 'validate_link_network_config\|link_network_state\|link_data_network_state')" 3
expect_eq "hub_env_write gives the Hub PORTCULLIS_LINK_DATA_WG_IP (the relays' upstream)" \
  "$( (export PORTCULLIS_ROOT="$WORK/lhe"; mkdir -p "$PORTCULLIS_ROOT"; hub_env_write; grep -x 'PORTCULLIS_LINK_DATA_WG_IP=172.31.254.130' "$PORTCULLIS_ROOT/secrets/hub/core.env") 2>/dev/null)" \
  "PORTCULLIS_LINK_DATA_WG_IP=172.31.254.130"

# test_link_doc_owner: stack_prepare owns link_doc 10001:10009 2750 and
# makes the link placeholders (0640, empty) and certs/node-ca.crt.
LP="$WORK/lp"; mkdir -p "$LP"
( PORTCULLIS_ROOT="$LP"
  volume_own() { echo "volume_own $*" >> "$STUB_DIR/lp-vol"; }; hub_env_write() { :; }; secrets_fix_perms() { :; }
  unset -f users_secret_files monitoring_prepare domains_prepare mcpgate_ensure_secrets sessions_prepare
  stack_prepare ) >/dev/null 2>&1
expect_ok "stack_prepare: link_doc owned 10001:10009, mode 2750" grep -qx 'volume_own link_doc 10001:10009 2750' "$STUB_DIR/lp-vol"
expect_eq "stack_prepare: link.key / link-tls.key / link-tls.crt empty placeholders 0640" \
  "$(for f in link.key link-tls.key link-tls.crt; do [ -f "$LP/secrets/wg/$f" ] && [ ! -s "$LP/secrets/wg/$f" ] && file_mode "$LP/secrets/wg/$f"; done | tr '\n' ' ')" "640 640 640 "
expect_eq "stack_prepare: certs/node-ca.crt an empty 0644 placeholder" \
  "$([ -f "$LP/certs/node-ca.crt" ] && [ ! -s "$LP/certs/node-ca.crt" ] && file_mode "$LP/certs/node-ca.crt")" 644
expect_eq "CT_GID_LINK_DOC is 10009 (never the Hub's 10001)" "$CT_GID_LINK_DOC" 10009
expect_eq "secrets_fix_perms keeps the link files wg's (group 10006)" \
  "$(declare -f secrets_fix_perms | grep -c 'CT_UID_WG.*link.key.*link-tls.key.*link-tls.crt')" 1

# A test CA standing in for pki_node, and a link.control cert from it.
LCA="$WORK/lca"; mkdir -p "$LCA"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$LCA/ca.key" -out "$LCA/ca.crt" -subj "/CN=t Node CA" -days 3650 >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$LCA/l.key" -out "$LCA/l.csr" -subj "/CN=link.control" >/dev/null 2>&1
printf 'extendedKeyUsage=clientAuth\n' > "$LCA/ext"
openssl x509 -req -in "$LCA/l.csr" -CA "$LCA/ca.crt" -CAkey "$LCA/ca.key" -CAcreateserial -out "$LCA/l.crt" -days 90 -extfile "$LCA/ext" >/dev/null 2>&1
openssl x509 -req -in "$LCA/l.csr" -CA "$LCA/ca.crt" -CAkey "$LCA/ca.key" -CAcreateserial -out "$LCA/l2.crt" -days 90 -extfile "$LCA/ext" >/dev/null 2>&1
# The same CN and CA, another key (not link-tls.key's).
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$LCA/o.key" -out "$LCA/o.csr" -subj "/CN=link.control" >/dev/null 2>&1
openssl x509 -req -in "$LCA/o.csr" -CA "$LCA/ca.crt" -CAkey "$LCA/ca.key" -CAcreateserial -out "$LCA/o.crt" -days 90 -extfile "$LCA/ext" >/dev/null 2>&1
# Off-CA: the same CN under another root.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$LCA/x.key" -out "$LCA/x.crt" -subj "/CN=link.control" -days 90 >/dev/null 2>&1
expect_fail "link_cert_due: a fresh 90 d certificate isn't due" link_cert_due "$LCA/l.crt"
expect_ok "link_cert_due: 90 d with 20 d left (< ⅓) is due" link_cert_due "$LCA/l.crt" "$(( $(date +%s) + 70 * 86400 ))"
expect_ok "link_cert_due: an empty file is due" link_cert_due /dev/null

# lt <script> — vt plus the link placeholders, certs/node-ca.crt and a
# stubbed Vault (curl logs argv to $WORK/vt/curl-argv and stdin to
# $WORK/vt/curl-stdin, answers $VT_SIGNED).
lt() {
  vt "mkdir -p \"\$PORTCULLIS_ROOT/certs\"; cp '$LCA/ca.crt' \"\$PORTCULLIS_ROOT/certs/node-ca.crt\"
      for f in link.key link-tls.key link-tls.crt; do : > \"\$PORTCULLIS_ROOT/secrets/wg/\$f\"; done
      export VAULT_TOKEN=s.vault-root-token-xyz LINK_UP_WAIT=0
      curl() {
        printf '%s\n' \"\$*\" >> \"$WORK/vt/curl-argv\"
        case \"\$*\" in *sys/health*) printf 200; return 0 ;; esac
        cat >> \"$WORK/vt/curl-stdin\"
        local o=\"\"
        while [ \$# -gt 0 ]; do case \"\$1\" in -o) o=\"\$2\"; shift ;; -H) case \"\$2\" in @/dev/fd/*|@/proc/*) cat \"\${2#@}\" >> \"$WORK/vt/curl-hdr\" ;; esac; shift ;; esac; shift; done
        jq -n --rawfile c \"\${VT_SIGNED:-$LCA/l.crt}\" '{data: {certificate: \$c}}' > \"\$o\"; printf '%s' \"\${VT_SIGN_CODE:-200}\"
      }
      _link_wg_run() { echo \"_link_wg_run \$*\" >> \"\$L\"; case \"\$*\" in *link-csr*) cat '$LCA/l.csr' ;; *) printf 'S0VZ\\n' > \"\$1\" ;; esac; }
      $1"
}
# test_link_init_refuses_overlap
for c in 'VT_DOCKER_SUBNETS=10.214.0.0/16|10.214.0.0/16 (a Docker network)' \
         'VT_HOSTINFO={"local_networks":["10.0.0.0/8","10.214.0.0/23"],"provider_ranges":[]}|10.214.0.0/23 (a Local network, Hub Settings)' \
         'VT_HOSTINFO={"local_networks":[],"provider_ranges":["10.214.0.0/20"]}|10.214.0.0/20 (a wired VPN provider'"'"'s range)' \
         'VT_ENV=PORTCULLIS_VPN_SUBNET=10.214.0.0/22|10.214.0.0/22 (the built-in VPN'"'"'s subnet)' \
         'PORTCULLIS_AUTH_SUBNET=10.214.0.16/28|10.214.0.16/28 (a reserved range)'; do
  set_="${c%%|*}"; want="${c#*|}"
  # shellcheck disable=SC2163  # VAR=value
  OUT="$(export "$set_"; lt 'link_init 51821' 2>&1)"; RC=$?
  expect_eq "link init: overlapping ${want%% (*} → refused naming it" "$RC:$(printf '%s' "$OUT" | grep -cF "  $want")" "1:1"
  expect_eq "link init: refused with ${want%% (*} → nothing written" "$(vte | grep -c 'PORTCULLIS_LINK\|COMPOSE_PROFILES' || true)" 0
done
OUT="$(lt 'link_init 51821' 2>&1)"; RC=$?
expect_eq "link init: the Hub's default Local networks (10.0.0.0/8) don't refuse" "$RC" 0
OUT="$(lt 'CONTAINER_RUNTIME=kubernetes; link_init 51821' 2>&1)"; RC=$?
expect_eq "link init on Kubernetes → refused (servers need a Docker or Podman primary), nothing asked" \
  "$RC:$(printf '%s' "$OUT" | grep -c 'servers need a Docker or Podman primary'):$(cat "$WORK/vt/log" 2>/dev/null | grep -c 'host-info' || true)" "1:1:0"
OUT="$(VT_ENV=$'PORTCULLIS_DOMAIN=x.org\nCOMPOSE_PROFILES=wg\nPORTCULLIS_VPN_PORT=51830' lt 'link_init 51830' 2>&1)"; RC=$?
expect_eq "link init: the built-in VPN's port → refused" "$RC:$(printf '%s' "$OUT" | grep -c "the built-in VPN's port")" "1:1"
# test_link_init_idempotent: keys once, wg once in COMPOSE_PROFILES, the
# certificate signed once while it isn't due; the second run regenerates
# nothing and signs nothing.
OUT="$(VT_ENV=$'PORTCULLIS_DOMAIN=x.org\nCOMPOSE_PROFILES=monitoring' lt 'link_init 51821 && cp "$PORTCULLIS_ROOT/.env" "$WORK/vt-env1" && cp -a "$PORTCULLIS_ROOT/secrets/wg" "$WORK/vt-wg1" && link_init 51821; cp "$WORK/vt/curl-argv" "$WORK/vt-curl" 2>/dev/null; true' 2>&1)"; RC=$?
expect_eq "link init twice: exit 0" "$RC" 0
expect_eq "link init: COMPOSE_PROFILES gains wg once; PORTCULLIS_LINK=on and the port, once each" \
  "$(grep -c '^COMPOSE_PROFILES=monitoring,wg$' "$WORK/vt/root/.env"):$(grep -c '^PORTCULLIS_LINK=on$' "$WORK/vt/root/.env"):$(grep -c '^PORTCULLIS_LINK_PORT=51821$' "$WORK/vt/root/.env")" "1:1:1"
expect_eq "link init: the second run writes the same .env" "$(diff "$WORK/vt-env1" "$WORK/vt/root/.env" && echo same)" same
expect_eq "link init: each key generated once (genkey, genkey-tls), the CSR made once" \
  "$(grep -c '_link_wg_run .* rw genkey /k' "$WORK/vt/log"):$(grep -c '_link_wg_run .* rw genkey-tls /k' "$WORK/vt/log"):$(grep -c '_link_wg_run .* ro link-csr' "$WORK/vt/log")" "1:1:1"
expect_eq "link init: signed once with pki_node/sign/node-link" "$(grep -c 'pki_node/sign/node-link' "$WORK/vt-curl")" 1
expect_eq "link init: the certificate written in place, the keys kept on the second run" \
  "$(cmp -s "$LCA/l.crt" "$WORK/vt/root/secrets/wg/link-tls.crt" && echo crt):$(cmp -s "$WORK/vt-wg1/link.key" "$WORK/vt/root/secrets/wg/link.key" && echo key)" "crt:key"
expect_eq "link init: hub_env_write, then wg, Traefik and the Hub" \
  "$(grep -c '^hub_env_write$' "$WORK/vt/log"):$(grep -c '^stack_compose_up wg traefik hub$' "$WORK/vt/log")" "2:2"
# test_link_no_secret_argv: the token through -H @<(...), the CSR on stdin.
expect_eq "link cert: the Vault token is never on curl's argv" "$(grep -c 'vault-root-token' "$WORK/vt-curl" || true)" 0
expect_eq "link cert: the CSR is never on curl's or jq's argv" "$(cat "$WORK/vt-curl" "$WORK/vt/jq" 2>/dev/null | grep -c 'BEGIN CERTIFICATE REQUEST' || true)" 0
expect_eq "link cert: the CSR goes in the request body (stdin)" "$(jq -r '.common_name + " " + .ttl + " " + (.csr | test("BEGIN CERTIFICATE REQUEST") | tostring)' "$WORK/vt/curl-stdin" | head -n1)" "link.control 2160h true"
expect_eq "link cert: the token header comes from a process substitution" "$(grep -c '^X-Vault-Token: s.vault-root-token-xyz$' "$WORK/vt/curl-hdr")" 1
OUT="$(VT_SIGNED="$LCA/x.crt" lt 'printf S > "$PORTCULLIS_ROOT/secrets/wg/link-tls.key"; link_cert_sign' 2>&1)"; RC=$?
expect_eq "link cert: a certificate not under certs/node-ca.crt → refused, nothing written" \
  "$RC:$(printf '%s' "$OUT" | grep -c 'nothing written'):$(wc -c < "$WORK/vt/root/secrets/wg/link-tls.crt" | tr -d ' ')" "1:1:0"
OUT="$(VT_SIGNED="$LCA/o.crt" lt 'printf S > "$PORTCULLIS_ROOT/secrets/wg/link-tls.key"; link_cert_sign' 2>&1)"; RC=$?
expect_eq "link cert: a valid link.control certificate for another key → refused, nothing written" \
  "$RC:$(printf '%s' "$OUT" | grep -c 'for link-tls.key under certs/node-ca.crt: nothing written'):$(wc -c < "$WORK/vt/root/secrets/wg/link-tls.crt" | tr -d ' ')" "1:1:0"
OUT="$(VT_SIGN_CODE=403 lt 'printf S > "$PORTCULLIS_ROOT/secrets/wg/link-tls.key"; link_cert_sign' 2>&1)"; RC=$?
expect_eq "link cert: Vault's refusal → exit 1 naming the path, nothing written" \
  "$RC:$(printf '%s' "$OUT" | grep -c 'pki_node/sign/node-link, HTTP 403'):$(wc -c < "$WORK/vt/root/secrets/wg/link-tls.crt" | tr -d ' ')" "1:1:0"
OUT="$(lt 'printf S > "$PORTCULLIS_ROOT/secrets/wg/link-tls.key"; : > "$PORTCULLIS_ROOT/certs/node-ca.crt"; link_cert_sign' 2>&1)"; RC=$?
expect_eq "link cert: no node CA exported yet → refused (pki setup)" "$RC:$(printf '%s' "$OUT" | grep -c 'pki setup')" "1:1"
# Renewal on up / upgrade: only with the role on, only when due.
OUT="$(LINK_NOW=$(( $(date +%s) + 70 * 86400 )) VT_SIGNED="$LCA/l2.crt" VT_ENV=$'PORTCULLIS_DOMAIN=x.org\nPORTCULLIS_LINK=on' lt 'printf S > "$PORTCULLIS_ROOT/secrets/wg/link-tls.key"; cp "'"$LCA"'/l.crt" "$PORTCULLIS_ROOT/secrets/wg/link-tls.crt"; link_cert_renew' 2>&1)"; RC=$?
expect_eq "link_cert_renew: 20 d left of 90 → re-signed" "$RC:$(grep -c 'node-link' "$WORK/vt/curl-argv"):$(cmp -s "$LCA/l2.crt" "$WORK/vt/root/secrets/wg/link-tls.crt" && echo new)" "0:1:new"
OUT="$(VT_ENV=$'PORTCULLIS_DOMAIN=x.org\nPORTCULLIS_LINK=on' lt 'cp "'"$LCA"'/l.crt" "$PORTCULLIS_ROOT/secrets/wg/link-tls.crt"; link_cert_renew' 2>&1)"; RC=$?
expect_eq "link_cert_renew: a fresh certificate → nothing asked" "$RC:$(cat "$WORK/vt/curl-argv" 2>/dev/null | grep -c node-link || true)" "0:0"
OUT="$(lt 'link_cert_renew' 2>&1)"; RC=$?
expect_eq "link_cert_renew: the role off → nothing" "$RC:$(cat "$WORK/vt/curl-argv" 2>/dev/null | wc -l | tr -d ' ')" "0:0"
expect_eq "up and upgrade renew the link certificate after Vault is healthy" \
  "$( (source "$HERE/../scripts/lib/stack.sh"; declare -f stack_up upgrade_run) 2>/dev/null | grep -c '^ *link_cert_renew')" 2

# status: the Servers block (link down, or a worker silent > 3 min).
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; OLD="$(date -u -d '-10 min' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-10M +%Y-%m-%dT%H:%M:%SZ)"
LST="{\"version\":1,\"written\":\"$NOW\",\"link\":{\"ok\":true,\"error\":\"\",\"public_key\":\"K\",\"port\":51821,\"peers\":[{\"id\":\"nas\",\"ip\":\"10.214.0.10\",\"handshake\":\"$NOW\",\"rx\":1,\"tx\":2},{\"id\":\"new\",\"ip\":\"10.214.0.11\",\"handshake\":null,\"rx\":0,\"tx\":0}]}}"
ls_json() { ( export PORTCULLIS_LINK="$1" LS_ANSWER="$2"; rt_exec() { printf '%s' "$LS_ANSWER"; }; link_status_json ); }
expect_eq "link status: the role off → not a problem, no wg call" "$(ls_json off '' | jq -c '{enabled, problem}')" '{"enabled":false,"problem":false}'
expect_eq "link status: up, a fresh and a never-shaken peer → no problem" \
  "$(ls_json on "$LST" | jq -c '{up, problem, peers: [.peers[] | {id, stale}]}')" '{"up":true,"problem":false,"peers":[{"id":"nas","stale":false},{"id":"new","stale":false}]}'
expect_eq "link status: a peer silent for 10 min → stale, a problem" \
  "$(ls_json on "${LST/\"handshake\":\"$NOW\"/\"handshake\":\"$OLD\"}" | jq -c '{problem, s: [.peers[] | .stale]}')" '{"problem":true,"s":[true,false]}'
expect_eq "link status: the role on, wg not answering → a problem" "$(ls_json on '' | jq -c '{up, problem}')" '{"up":false,"problem":true}'
expect_eq "link status: link null in a fresh status.json → down" "$(ls_json on "{\"version\":1,\"written\":\"$NOW\",\"link\":null}" | jq -c '{up, problem}')" '{"up":false,"problem":true}'

# ── HA Task 23: Postgres on CloudNativePG (scripts/lib/ha.sh) ──
CN="$WORK/cnpg"; rm -rf "$CN"; mkdir -p "$CN/kube/ha/cnpg" "$CN/charts/portcullis"
cp "$HERE/../kube/ha/cnpg/cloudnative-pg-0.29.2.tgz" "$HERE/../kube/ha/cnpg/values.yaml" "$HERE/../kube/ha/cnpg/rbac.yaml" "$CN/kube/ha/cnpg/"
cp "$HERE/../charts/portcullis/namespaces.json" "$CN/charts/portcullis/"
k_fixtures; rm -f "$KS/helm-calls" "$KS/kubectl-calls"; mkdir -p "$WORK/cnroot/secrets"
OUT="$(kt "PORTCULLIS_HOME='$CN' PORTCULLIS_ROOT='$WORK/cnroot'; ha_install_cnpg")"
expect_eq "ha_install_cnpg: applies pinned manifests only (digest check): the vendored chart with its values file, release cnpg in cnpg-system, waited for" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(grep -c "^--kube-context ci upgrade --install cnpg $CN/kube/ha/cnpg/cloudnative-pg-0.29.2.tgz -n cnpg-system -f $CN/kube/ha/cnpg/values.yaml --history-max 3 --wait --timeout 5m$" "$KS/helm-calls")" "rc=0:1"
expect_eq "ha_install_cnpg: never helm --set (with a secret or anything: every value in the vendored file)" \
  "$(grep -c -- '--set' "$KS/helm-calls" || true):$(declare -f ha_install_cnpg | grep -c -- '--set' || true)" "0:0"
expect_eq "ha_install_cnpg: cnpg-system with PSA restricted (namespaces.json cnpg) and the install's ownership" \
  "$(grep -v '^---$' "$KS/kubectl-stdin" | jq -c 'select(type == "object" and .kind == "Namespace" and .metadata.name == "cnpg-system") | [.metadata.labels["pod-security.kubernetes.io/enforce"], .metadata.annotations["portcullis.io/install"]]' 2>/dev/null)" \
  '["restricted","0b0e2b3c-1111-4222-8333-444455556666"]'
printf 'x' >> "$CN/kube/ha/cnpg/cloudnative-pg-0.29.2.tgz"; rm -f "$KS/helm-calls"
OUT="$(kt "PORTCULLIS_HOME='$CN' PORTCULLIS_ROOT='$WORK/cnroot'; ha_install_cnpg" 2>&1)"
case "$OUT" in *"the CloudNativePG pins don't hold: kube/ha/cnpg/cloudnative-pg-0.29.2.tgz has sha256 "*"not the pinned 9df3f074"*"rc=1") t_pass "ha_install_cnpg: a chart that isn't the pinned sha256 → refused, nothing installed" ;; *) t_fail "cnpg tampered chart: $OUT" ;; esac
expect_eq "ha_install_cnpg: the refused chart never reached helm" "$(cat "$KS/helm-calls" 2>/dev/null | grep -c upgrade || true)" 0
cp "$HERE/../kube/ha/cnpg/cloudnative-pg-0.29.2.tgz" "$CN/kube/ha/cnpg/"
sed -i.bak 's/^  tag: .*/  tag: "1.30.2"/' "$CN/kube/ha/cnpg/values.yaml" && rm -f "$CN/kube/ha/cnpg/values.yaml.bak"
OUT="$(kt "PORTCULLIS_HOME='$CN' PORTCULLIS_ROOT='$WORK/cnroot'; ha_install_cnpg" 2>&1)"
case "$OUT" in *"doesn't pin the operator image to sha256:f96f6be3"*"rc=1") t_pass "ha_install_cnpg: values without the pinned operator digest → refused" ;; *) t_fail "cnpg unpinned values: $OUT" ;; esac
expect_eq "the argv grep covers scripts/lib/ha.sh" "$(printf '%s\n' "$HERE"/../scripts/lib/*.sh | grep -c '/ha\.sh$')" 1
OUT="$(kt "kube_ctl() { echo '{\"items\":[{\"spec\":{\"podCIDR\":\"10.42.0.0/24\"}},{\"spec\":{\"podCIDR\":\"10.42.1.0/24\"}},{\"spec\":{}},{\"spec\":{\"podCIDR\":\"bogus\"}}]}'; }; kube_apiserver_sources; echo")"
expect_eq "kube_apiserver_sources: the API endpoints and each server's pod-range gateways (flannel .0, cni0 .1), nothing unparsable" \
  "$(printf '%s\n' "$OUT" | head -n1)" "10.1.0.4 10.42.0.0 10.42.0.1 10.42.1.0 10.42.1.1"
OUT="$(kt "kube_ctl() { return 1; }; kube_apiserver_sources && echo GOT; echo \"[\$(kube_apiserver_sources)]\"")"
expect_eq "kube_apiserver_sources: the nodes unreadable → nothing and exit 1, never the endpoints alone (re-review M-c)" "$(printf '%s\n' "$OUT" | grep -c 'GOT'):$(printf '%s\n' "$OUT" | grep -c '^\[\]$')" "0:1"
OUT="$(kt "PORTCULLIS_KUBE_API_ENDPOINTS=; kube_ctl() { return 1; }; kube_apiserver_sources; echo \"[\$(kube_apiserver_sources)]\"")"
expect_eq "kube_apiserver_sources: nothing readable → empty (kube_render_values then refuses)" "$(printf '%s\n' "$OUT" | grep -c '^\[\]$')" 1
k_fixtures; k15_root; rm -f "$KS/order"
OUT="$(kt "$K15_ENV LLDAP_PG_PASSWORD=LLPG-SECRET-888; kube_pg_sync_secrets" </dev/null)"
expect_eq "kube_pg_sync_secrets: the roles' basic-auth Secrets in cnpg-system and LLDAP's URL Secret in the core namespace, built --from-file" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(grep -cE 'create secret generic portcullis-pg-keycloak -n cnpg-system --type=kubernetes.io/basic-auth --from-file=|create secret generic portcullis-pg-lldap -n cnpg-system --type=kubernetes.io/basic-auth --from-file=|create secret generic portcullis-pg-lldap -n portcullis --from-file=' "$KS/kubectl-calls")" "rc=0:3"
expect_eq "kube_pg_sync_secrets: no password on argv (kubectl / helm argv recorded)" \
  "$(cat "$KS/kubectl-calls" "$KS/helm-calls" 2>/dev/null | grep -cE 'LLPG-SECRET-888|PG-SECRET-777' || true)" 0
expect_eq "kube_pg_sync_secrets: LLDAP's URL is the rw Service's, its password in the Secret (base64), never in a log" \
  "$(grep -c "$(printf 'postgres://lldap:LLPG-SECRET-888@portcullis-pg-rw.cnpg-system.svc.cluster.local:5432/lldap' | base64 | tr -d '\n')" "$KS/kubectl-stdin"):$(printf '%s\n' "$OUT" | grep -c 'LLPG-SECRET-888' || true)" "1:0"
expect_eq "kube_pg_sync_secrets: the roles' Secrets carry cnpg.io/reload (the operator re-applies a changed password only then)" \
  "$(grep -v '^---$' "$KS/kubectl-stdin" | jq -c 'select(type == "object" and .metadata.namespace? == "portcullis" and (.metadata.name | startswith("portcullis-pg-"))) | .metadata.labels["cnpg.io/reload"]' 2>/dev/null | sort | uniq -c | tr -s ' ')" "$(printf ' 2 "true"\n 1 null')"
# HA ← main (Task 26 ruling): LLDAP's key is the seed file on Kubernetes too,
# no keygen pod, no secrets-lldap-key.
expect_eq "kube: no LLDAP keygen pod or server key file left (the seed is secrets-lldap)" \
  "$(grep -c 'kube_lldap_server_key\|lldap-key\|secrets-lldap-key' "$HERE"/../scripts/lib/*.sh "$HERE"/../charts/portcullis/templates/*.yaml | awk -F: '{s += $2} END {print s}')" 0
expect_eq "kube_sync_secrets requires LLDAP's seed before anything is synced" \
  "$(declare -f kube_sync_prepare_t26 | grep -c lldap_key_seed_require):$(declare -f kube_sync_secrets | awk '/kube_sync_prepare_t26/ {r=NR} /kube_sync_stage/ {s=NR} END {print (r && s > r) ? "first" : "no"}')" 1:first
PGX="$WORK/pgx"; rm -rf "$PGX"; mkdir -p "$PGX/b1" "$PGX/b2" "$PGX/pre"
printf 'PGDMPkc' > "$PGX/b1/postgres.dump"; printf 'PGDMPll' > "$PGX/b1/lldap.dump"
printf 'PGDMPkc' > "$PGX/b2/postgres.dump"; printf 'tar' > "$PGX/b2/lldap_data.tar.gz"
# _kube_pg_exec's fake: every call logged; pg_dump prints a dump; a
# pg_restore into $PGX_FAIL fails (fault injection); the swap's SQL kept.
pgx() { kt "_kube_pg_wait() { :; }; _kube_pg_roles_wait() { echo \"PG roles-wait \$1\" >> '$PGX/calls'; }
  _kube_pg_exec() { echo \"PG \$*\" >> '$PGX/calls'; case \"\$1\" in pg_dump) printf PGDMPlive ;; pg_restore) cat > '$PGX/in-'\"\$3\"; [ \"\$3\" != \"\${PGX_FAIL:-}\" ] || return 1 ;; psql) cat > '$PGX/swap.sql' ;; esac; }
  kube_ctl() { echo \"KCTL \$*\" >> '$PGX/calls'; }; _kube_restore_pg '$1' '$PGX/pre'" 2>&1; }
rm -f "$PGX/calls" "$PGX/swap.sql"; OUT="$(pgx "$PGX/b1")"
expect_eq "_kube_restore_pg (test_restore_into_cnpg): the live keycloak and lldap dumped into the pre-restore dir first (review I3)" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(head -n2 "$PGX/calls" | tr '\n' ';'):$(cat "$PGX/pre/postgres.dump"):$(cat "$PGX/pre/lldap.dump")" \
  "rc=0:PG pg_dump -d keycloak -Fc;PG pg_dump -d lldap -Fc;:PGDMPlive:PGDMPlive"
expect_eq "_kube_restore_pg: each dump into <db>_restore as its own role in one transaction, never into the live database" \
  "$(grep -c '^PG pg_restore -d keycloak_restore --no-owner --no-privileges --role=keycloak --exit-on-error --single-transaction$\|^PG pg_restore -d lldap_restore --no-owner --no-privileges --role=lldap --exit-on-error --single-transaction$' "$PGX/calls"):$(grep -cE '^PG (pg_restore -d|dropdb .*) (keycloak|lldap)$' "$PGX/calls" || true):$(cat "$PGX/in-lldap_restore")" "2:0:PGDMPll"
expect_eq "_kube_restore_pg: then one transaction renames live → <db>_pre_restore and <db>_restore → live; Jobs removed; passwords waited for" \
  "$(grep -c '^alter database' "$PGX/swap.sql"):$(grep -c '^PG psql -X -q -v ON_ERROR_STOP=1 -1 -d postgres -f -$' "$PGX/calls"):$(grep -c 'KCTL -n portcullis delete job -l portcullis.io/component=lldap-schema' "$PGX/calls"):$(grep -c '^PG roles-wait 300$' "$PGX/calls")" "4:1:1:1"
# Fault injection (review I3): a broken lldap.dump → the live pair untouched.
rm -f "$PGX/calls" "$PGX/swap.sql"; OUT="$(PGX_FAIL=lldap_restore pgx "$PGX/b1")"
case "$OUT" in *"pg_restore of lldap.dump failed: the live databases are untouched (their dumps before this restore: $PGX/pre/postgres.dump, $PGX/pre/lldap.dump)"*"rc=1") t_pass "_kube_restore_pg: a pg_restore failure refuses naming the pre-restore dumps" ;; *) t_fail "restore fault: $OUT" ;; esac
expect_eq "_kube_restore_pg: after a failed pg_restore no rename, no drop of a live database, the half-made copies dropped" \
  "$(test -e "$PGX/swap.sql" && echo swapped || echo none):$(grep -cE '^PG dropdb .* (keycloak|lldap)$' "$PGX/calls" || true):$(grep -c '^PG dropdb --if-exists --force keycloak_restore$\|^PG dropdb --if-exists --force lldap_restore$' "$PGX/calls")" "none:0:4"
# Re-review N1: the swap is one transaction. A Postgres fake that applies
# the renames in order, all-or-nothing only under -1 -f -, with the second
# rename (lldap → lldap_pre_restore) refused: both live databases stay.
SW="$WORK/swap"; rm -rf "$SW"; mkdir -p "$SW"
cat > "$SW/pg.sh" <<'PGFAKE'
# _kube_pg_exec's fake: databases are lines of $SW/dbs.
_kube_pg_exec() {
  case "$1" in
    dropdb) shift; for a in "$@"; do :; done; grep -vx "$a" "$SW/dbs" > "$SW/dbs.t" || true; mv "$SW/dbs.t" "$SW/dbs" ;;
    psql)
      local tx=false sql state; case " $* " in *" -1 "*" -f - "*) tx=true ;; esac
      sql="$(cat)"; cp "$SW/dbs" "$SW/dbs.before"
      while IFS= read -r line; do
        case "$line" in "alter database "*" rename to "*)
          set -- $line; from="$3" to="${6%;}"
          if [ "$from" = lldap ]; then $tx && cp "$SW/dbs.before" "$SW/dbs"; return 1; fi
          sed -i.b "s/^$from\$/$to/" "$SW/dbs" && rm -f "$SW/dbs.b" ;;
        esac
      done <<< "$sql" ;;
  esac
}
PGFAKE
printf 'keycloak\nlldap\nkeycloak_restore\nlldap_restore\n' > "$SW/dbs"
OUT="$(kt "SW='$SW'; . '$SW/pg.sh'; sleep() { :; }; _kube_pg_swap && echo SWAPPED || echo REFUSED")"
expect_eq "_kube_pg_swap (re-review N1): the second rename refused → refused, both live databases and both copies still there" \
  "$(printf '%s\n' "$OUT" | grep -c '^REFUSED$'):$(sort "$SW/dbs" | tr '\n' ' ')" "1:keycloak keycloak_restore lldap lldap_restore "
rm -f "$PGX/calls" "$PGX/swap.sql"; OUT="$(pgx "$PGX/b2")"
case "$OUT" in *"the backup has no LLDAP database to restore"*"rc=1") t_pass "_kube_restore_pg: a Docker backup not converted first is refused (never an empty LLDAP)" ;; *) t_fail "restore pg docker backup unconverted: $OUT" ;; esac
rm -f "$PGX/calls" "$PGX/swap.sql"; OUT="$(KUBE_LLDAP_CONVERTED=true pgx "$PGX/b2")"
case "$OUT" in *"rc=0") t_pass "_kube_restore_pg: a converted Docker backup → Keycloak restored, the converted lldap_restore swapped in" ;; *) t_fail "restore pg docker backup converted: $OUT" ;; esac
expect_eq "_kube_restore_pg: the converted lldap_restore is kept as it is (never re-made, never pg_restore'd)" \
  "$(grep -c 'pg_restore -d lldap\|createdb -O lldap lldap_restore\|dropdb --if-exists --force lldap_restore$' "$PGX/calls" || true):$(grep -c '^alter database' "$PGX/swap.sql")" "0:4"
# ── Task 26: LLDAP SQLite → Postgres (lldap_convert.sh) ──
LC="$WORK/lconv"; rm -rf "$LC"; mkdir -p "$LC"
printf 'SQLite format 3\000rest' > "$LC/users.db"
printf 'postgres://lldap:SECRET-LLPW-42@h:5432/lldap_restore' > "$LC/url"
SUMS='users 3
uuids aa
groups bb
memberships cc
hash_count 2
hashes dd
attributes ee
rows:users ff
rows:groups 11'
# The fakes: _kube_pg_exec answers the emptiness check ($LC_TABLES), the
# columns, the dump (kept), the target summary ($LC_DST); the Python and
# create_schema are stubbed.
lconv() { kt "_lldap_convert_schema() { echo \"SCHEMA \$(cat \"\$1\" | wc -c)\" >> '$LC/calls'; }
  _lldap_convert_py() { echo \"PY \$1\" >> '$LC/calls'; case \"\$1\" in sql) printf 'BEGIN;\nINSERT 1;\nCOMMIT;\n' ;; summary) printf '%s\n' \"\$LC_SRC\" ;; rowsql) echo 'select rows;' ;; esac; }
  _kube_pg_exec() { echo \"PG \$*\" >> '$LC/calls'; case \"\$*\" in *pg_tables*) echo \"\${LC_TABLES:-0}\" ;; *information_schema*) echo '{\"users\":{\"uuid\":\"text\"}}' ;;
      'psql -X -q -v ON_ERROR_STOP=1 -v VERBOSITY=terse -v SHOW_CONTEXT=never -d lldap_restore -f -') cat > '$LC/dump.sql'
        [ -z \"\${LC_DUMP_ERR:-}\" ] || { printf '%s\n' \"\$LC_DUMP_ERR\" >&2; return 3; } ;;
      'psql -XtAq -d lldap_restore -f -') cat > '$LC/cleanup.sql' ;; *'-f -') cat > /dev/null; printf '%s\n' \"\$LC_DST\" ;; esac; }
  lldap_convert_sqlite_to_pg '$LC/users.db' '$LC/url'" 2>&1; }
rm -f "$LC/calls"; OUT="$(LC_SRC="$SUMS" LC_DST="$SUMS" lconv)"
case "$OUT" in *"3 user(s), 2 password hash(es)"*"rc=0") t_pass "lldap_convert: equal summaries → converted" ;; *) t_fail "lldap_convert ok: $OUT" ;; esac
expect_eq "lldap_convert: create_schema, the dump into the target, then both summaries (in that order)" \
  "$(grep -o '^SCHEMA\|^PY [a-z]*\|VERBOSITY=terse\|ON_ERROR_STOP=1 -d lldap_restore -f -' "$LC/calls" | tr '\n' ';')" "SCHEMA;PY sql;VERBOSITY=terse;PY summary;ON_ERROR_STOP=1 -d lldap_restore -f -;PY rowsql;ON_ERROR_STOP=1 -d lldap_restore -f -;"
for k in users uuids groups memberships hash_count hashes attributes rows:users rows:groups; do
  rm -f "$LC/calls"; OUT="$(LC_SRC="$SUMS" LC_DST="$(printf '%s\n' "$SUMS" | sed "s/^$k .*/$k XX/")" lconv)"
  case "$OUT" in *"LLDAP conversion changed $(_lldap_convert_what "$k"): nothing was switched"*"rc=1") t_pass "lldap_convert: a different $k → refused naming it" ;; *) t_fail "lldap_convert diff $k: $OUT" ;; esac
done
expect_ok "lldap_convert: a refusal empties the target again (public recreated for its owner)" grep -q "drop schema public cascade'; EXECUTE 'create schema public authorization ' || quote_ident((SELECT pg_get_userbyid(datdba)" "$LC/cleanup.sql"
rm -f "$LC/calls"; OUT="$(LC_TABLES=4 LC_SRC="$SUMS" LC_DST="$SUMS" lconv)"
case "$OUT" in *"the target database lldap_restore isn't empty (4)"*"rc=1") t_pass "lldap_convert: a target with tables is refused before anything is written" ;; *) t_fail "lldap_convert non-empty: $OUT" ;; esac
expect_eq "lldap_convert: nothing written into a non-empty target" "$(grep -c '^SCHEMA\|^PY' "$LC/calls" || true)" 0
rm -f "$LC/calls"; OUT="$(PORTCULLIS_DEV_LLDAP_CONVERT_FAULT='select 1;' LC_SRC="$SUMS" LC_DST="$SUMS" lconv)"
case "$OUT" in *"for development only (HUB_DEV=1)"*"rc=1") t_pass "lldap_convert: the fault hook is refused without HUB_DEV=1" ;; *) t_fail "lldap_convert fault hook: $OUT" ;; esac
rm -f "$LC/calls"; OUT="$(HUB_DEV=1 PORTCULLIS_DEV_LLDAP_CONVERT_FAULT='UPDATE users SET uuid = 1;' LC_SRC="$SUMS" LC_DST="$SUMS" lconv)"
expect_eq "lldap_convert: the dev fault goes inside the transaction, just before COMMIT" "$(tr '\n' ';' < "$LC/dump.sql")" "BEGIN;;INSERT 1;;UPDATE users SET uuid = 1;;COMMIT;;"
expect_eq "lldap_convert: the target URL (its password) never on argv or in output" \
  "$(cat "$LC/calls" | grep -c 'SECRET-LLPW-42' || true):$(printf '%s' "$OUT" | grep -c 'SECRET-LLPW-42' || true)" "0:0"
printf 'not sqlite' > "$LC/bad.db"
OUT="$(kt "lldap_convert_sqlite_to_pg '$LC/bad.db' '$LC/url'" 2>&1)"
case "$OUT" in *"is not a SQLite database"*"rc=1") t_pass "lldap_convert: a non-SQLite file refused" ;; *) t_fail "lldap_convert bad db: $OUT" ;; esac
expect_eq "lldap_convert: the pods get the URL from a temporary Secret (--from-file), labelled lldap-schema + lldap-convert, their log cut of credentials" \
  "$(declare -f _lldap_convert_pod | grep -c -- '--from-file="$st/s"'):$(declare -f _lldap_convert_pod | grep -c '"portcullis.io/component": "lldap-schema", "portcullis.io/lldap-convert": "true"'):$(declare -f _lldap_convert_pod | grep -c "s#://\[^/@ \]\*@#://\*\*\*@#g")" "1:1:1"
# Review M6: Postgres' errors print only the ERROR line, quoted data cut.
rm -f "$LC/calls"; OUT="$(LC_DUMP_ERR='psql:<stdin>:7: ERROR:  invalid input syntax for type boolean: "HASHSECRET-77fe" in "users"
DETAIL:  Failing row contains (alice, HASHSECRET-77fe, x).
LINE 1: INSERT INTO "users" VALUES (HASHSECRET-77fe)' LC_SRC="$SUMS" LC_DST="$SUMS" lconv)"
case "$OUT" in *"Postgres: invalid input syntax for type boolean: \"…\" in \"…\""*"Postgres refused the dump"*"rc=1") t_pass "lldap_convert: a refused dump prints only its ERROR line, values cut (no DETAIL / LINE)" ;; *) t_fail "lldap_convert pg error: $OUT" ;; esac
expect_eq "lldap_convert: no row content of a refused dump in the output" "$(printf '%s' "$OUT" | grep -c 'HASHSECRET\|DETAIL\|LINE 1' || true)" 0
# Review M3 + M2 on the real Python: a users.db without a private-key hash
# is refused; the full-row digests normalise per target type (a timestamp
# with nanoseconds and an offset, bytea, booleans, NULL).
if command -v python3 >/dev/null && python3 -c 'import sqlite3' 2>/dev/null; then
  PYD="$WORK/lpy"; rm -rf "$PYD"; mkdir -p "$PYD"
  python3 - "$PYD/u.db" <<'PY'
import sqlite3, sys
d = sqlite3.connect(sys.argv[1])
d.executescript("""create table metadata (version integer, private_key_hash blob, private_key_location text);
insert into metadata values (11, NULL, NULL);
create table users (user_id text, uuid text, password_hash blob, creation_date text, flag integer);
insert into users values ('a', 'u-1', x'0102', '2026-11-21T16:22:53.3628605+00:00', 1);
insert into users values ('b', 'u-2', NULL, '2026-11-21 16:22:53', 0);
create table groups (group_id integer, display_name text, uuid text);
create table memberships (user_id text, group_id integer);""")
d.commit()
PY
  echo '{"users":{"user_id":"character varying","uuid":"character varying","password_hash":"bytea","creation_date":"timestamp without time zone","flag":"boolean"},"groups":{"group_id":"integer","display_name":"text","uuid":"text"},"memberships":{"user_id":"text","group_id":"integer"},"metadata":{}}' > "$PYD/cols"
  pyrun() { { cat "$PYD/cols"; cat "$PYD/u.db"; } | python3 -c "$_LLDAP_CONVERT_PY" "$1" "users groups memberships" 2>&1; echo "rc=$?"; }
  OUT="$(pyrun sql)"
  case "$OUT" in *"users.db has no private-key hash: LLDAP would accept any seed (refused)"*) t_pass "lldap_convert (python): a users.db without a private-key hash → refused" ;; *) t_fail "lldap_convert no hash: $OUT" ;; esac
  want="$(printf '%s\n' "$(printf 'a\x1fu-1\x1f0102\x1f2026-11-21 16:22:53.362860\x1ftrue')" "$(printf 'b\x1fu-2\x1f\x01\x1f2026-11-21 16:22:53.000000\x1ffalse')" | LC_ALL=C sort | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.read().rstrip("\n").encode()).hexdigest())')"
  expect_eq "lldap_convert (python): full-row digest = the rows normalised by target type (µs half-even, wall time, bytea hex, booleans, NULL)" \
    "$(pyrun summary | awk '$1 == "rows:users" {print $2}')" "$want"
  expect_eq "lldap_convert (python): the Postgres side normalises the same way" \
    "$(pyrun rowsql | grep -c "to_char(\"creation_date\", 'YYYY-MM-DD HH24:MI:SS.US')\|encode(\"password_hash\", 'hex')")" 1
fi
# Review M8: the converted lldap_restore never outlives a failed restore.
OUT="$(kt "kube_lldap_convert_backup() { KUBE_LLDAP_CONVERTED=true; }; _kube_pg_exec() { echo \"PG \$*\" >> '$LC/m8'; }
  rm -f '$LC/m8'; mkdir -p '$LC/b'; printf x > '$LC/b/lldap_data.tar.gz'; kube_lldap_convert_preflight '$LC/b'; fail 'a later step failed'")"
expect_eq "kube restore: a failure after the conversion drops lldap_restore (EXIT trap)" "$(grep -c '^PG dropdb --if-exists --force lldap_restore$' "$LC/m8"):$(printf '%s' "$OUT" | tail -n1)" "1:rc=1"
# Review NN3: chained after the caller's own EXIT trap; a parent's (not live in a subshell) never runs.
OUT="$(kt "kube_lldap_convert_backup() { KUBE_LLDAP_CONVERTED=true; }; _kube_pg_exec() { echo \"PG \$*\" >> '$LC/m8'; }
  rm -f '$LC/m8'; mkdir -p '$LC/b'; printf x > '$LC/b/lldap_data.tar.gz'; trap 'echo CALLER-TRAP' EXIT; kube_lldap_convert_preflight '$LC/b'; fail 'a later step failed'")"
expect_eq "kube restore: the drop is chained before the caller's own EXIT trap (both run)" "$(grep -c '^PG dropdb --if-exists --force lldap_restore$' "$LC/m8"):$(printf '%s\n' "$OUT" | grep -c '^CALLER-TRAP$'):$(printf '%s' "$OUT" | tail -n1)" "1:1:rc=1"
OUT="$(trap 'echo PARENT-TRAP-RAN' EXIT; kt "kube_lldap_convert_backup() { :; }; mkdir -p '$LC/b'; printf x > '$LC/b/lldap_data.tar.gz'; _kube_pg_exec() { :; }; kube_lldap_convert_preflight '$LC/b'; trap -p EXIT")"
expect_eq "kube restore: a parent shell's EXIT trap (not live in the subshell) is never chained" "$(printf '%s\n' "$OUT" | grep -c 'PARENT-TRAP-RAN')" 1
# The queued early check: the backup's seed against its users.db, before anything changes.
OUT="$(kt "_kube_pg_wait() { :; }; _kube_pg_fresh_db() { :; }; LLDAP_PG_PASSWORD=x
  lldap_convert_sqlite_to_pg() { :; }; _lldap_convert_pod() { echo \"POD \$2 \$3\" >> '$LC/sc'; [ \"\$2\" != seedcheck ]; }
  _kube_pg_exec() { echo \"PG \$*\" >> '$LC/sc'; }; tar() { mkdir -p \"\${4}\" && printf 'SQLite format 3' > \"\${4}/users.db\"; }
  rm -f '$LC/sc'; mkdir -p '$LC/b/secrets/lldap'; printf s > '$LC/b/secrets/lldap/key-seed'; kube_lldap_convert_backup '$LC/b'")"
case "$OUT" in *"the backup's key seed doesn't open its users.db"*"nothing was switched"*"rc=1") t_pass "kube restore: the backup's seed checked against its converted users.db (refused → nothing switched)" ;; *) t_fail "seed check: $OUT" ;; esac
expect_eq "kube restore: the seed check runs LLDAP with the BACKUP's seed, and a refusal drops lldap_restore" \
  "$(grep -c "^POD seedcheck $LC/b/secrets/lldap/key-seed$" "$LC/sc"):$(grep -c '^PG dropdb --if-exists --force lldap_restore$' "$LC/sc")" "1:1"
expect_eq "lldap_convert: the seed check is LLDAP's own run + healthcheck readiness on the backup's seed (a temporary Secret)" \
  "$(declare -f _lldap_convert_pod | grep -c '"/app/lldap", "run", "--config-file", "/dev/null"'):$(declare -f _lldap_convert_pod | grep -c 'readinessProbe: {exec: {command: \["/app/lldap", "healthcheck"')" "1:1"
expect_eq "kube restore: the conversion runs before the Hub is stopped (a refusal changes nothing)" \
  "$(declare -f _backup_restore_kube | awk '/kube_lldap_convert_preflight/ {c=NR} /Stopping the Hub/ {h=NR} END {print (c && h > c) ? "first" : "no"}')" first
expect_eq "kube restore: the replaced databases dropped only after the stack is healthy" \
  "$(declare -f _backup_restore_kube | awk '/wait_healthy 300/ {w=NR} /_kube_pg_drop_pre_restore/ {d=NR} END {print (w && d > w) ? "after" : "no"}')" after
# Review I1: CNPG's instances follow the labelled nodes, never readiness;
# unreadable → refused; never below the live Cluster's (but KUBE_PG_SHRINK=1).
k_fixtures
echo '{"items":[{"status":{"conditions":[{"type":"Ready","status":"True"}]}},{"status":{"conditions":[{"type":"Ready","status":"False"}]}},{"status":{}}]}' > "$KS/kube/pg-nodes.json"
echo '{"spec":{"instances":3}}' > "$KS/kube/pg-cluster.json"
OUT="$(kt "kube_pg_nodes_at_primary; kube_pg_min_instances; kube_pg_min_instances --shrink")"
expect_eq "kube_pg_nodes_at_primary: NotReady and unknown nodes count (3 labelled); kube_pg_min_instances: the live 3 (0 only with the node-remove path's --shrink)" "$(printf '%s\n' "$OUT" | head -n3 | tr '\n' ' ')" "3 3 0 "
# Re-review N2: never from .env / the environment.
OUT="$(kt "export KUBE_PG_SHRINK=1; kube_pg_min_instances || echo REFUSED; KUBE_PG_SHRINK= kube_pg_min_instances --shrink || echo REFUSED" 2>&1)"
expect_eq "KUBE_PG_SHRINK in the environment (even empty) → refused, also with --shrink" \
  "$(printf '%s\n' "$OUT" | grep -c '^REFUSED$'):$(printf '%s\n' "$OUT" | grep -c 'KUBE_PG_SHRINK is set in .env or the environment: refused')" "2:2"
k15_root; printf 'KUBE_PG_SHRINK=1\n' >> "$K15/.env"
OUT="$(kt "$K15_ENV; export PORTCULLIS_HA=on; env_load; _K_IMAGES='{}'; kube_render_values" 2>&1)"
case "$OUT" in *"KUBE_PG_SHRINK is set in .env or the environment: refused"*"rc=1") t_pass "kube_render_values: a KUBE_PG_SHRINK line in .env refuses the render (the floor can't be switched off)" ;; *) t_fail "render KUBE_PG_SHRINK in .env: $OUT" ;; esac
touch "$KS/kube/pg-nodes.fail" "$KS/kube/pg-cluster.fail"
OUT="$(kt "kube_pg_nodes_at_primary || echo REFUSED; kube_pg_min_instances || echo REFUSED")"
expect_eq "unreadable nodes or Cluster → refused, never 0" "$(printf '%s\n' "$OUT" | grep -c '^REFUSED$')" 2
rm -f "$KS/kube/pg-nodes.fail" "$KS/kube/pg-cluster.fail" "$KS/kube/pg-cluster.json"
OUT="$(kt "kube_pg_min_instances")"
expect_eq "kube_pg_min_instances: no Cluster yet (NotFound) → 0" "$(printf '%s\n' "$OUT" | head -n1)" 0
k15_root; echo '{"spec":{"instances":2}}' > "$KS/kube/pg-cluster.json"
OUT="$(kt "$K15_ENV; export PORTCULLIS_HA=on; kube_nonsmall_at_primary() { echo 1; }; _K_IMAGES='{}'; kube_render_values; jq -c .cnpg \"$K15/secrets/kube/values.yaml\"")"
expect_eq "kube_render_values (HA, one main node NotReady): CNPG's input is the labelled count and its floor the live instances (no scale-down)" \
  "$(printf '%s\n' "$OUT" | head -n1)" '{"nodesAtPrimary":3,"minInstances":2}'
touch "$KS/kube/pg-nodes.fail"
OUT="$(kt "$K15_ENV; export PORTCULLIS_HA=on; _K_IMAGES='{}'; kube_render_values" 2>&1)"
case "$OUT" in *"can't read the nodes at main: Postgres' instance count would be a guess (nothing rendered)"*"rc=1") t_pass "kube_render_values (HA): unreadable nodes → refused" ;; *) t_fail "render pg nodes unreadable: $OUT" ;; esac
rm -f "$KS/kube/pg-nodes.fail" "$KS/kube/pg-cluster.json"
# Review M3: the primary is the Cluster's currentPrimary, the one Running pod labelled so.
pp() { kt "kube_ctl() { case \"\$*\" in *'get cluster'*) echo '{\"status\":{\"currentPrimary\":\"$1\"}}' ;; *'get pods'*) echo '$2' ;; esac; }; kube_pg_primary || echo NONE"; }
P1='{"metadata":{"name":"portcullis-pg-1"},"status":{"phase":"Running"}}'; P2='{"metadata":{"name":"portcullis-pg-2"},"status":{"phase":"Running"}}'
expect_eq "kube_pg_primary: currentPrimary = the one Running labelled pod → it; a stale second label, a mismatch or no status → none" \
  "$(pp portcullis-pg-1 "{\"items\":[$P1]}" | head -n1) $(pp portcullis-pg-1 "{\"items\":[$P1,$P2]}" | head -n1) $(pp portcullis-pg-2 "{\"items\":[$P1]}" | head -n1) $(pp '' "{\"items\":[$P1]}" | head -n1)" \
  "portcullis-pg-1 NONE NONE NONE"
# Review M5: a Failed schema Job is removed before the release (Helm makes it again).
OUT="$(kt "kube_ctl() { case \"\$*\" in *'get jobs'*) echo '{\"items\":[{\"metadata\":{\"name\":\"lldap-schema-a\"},\"status\":{\"conditions\":[{\"type\":\"Failed\",\"status\":\"True\"}]}},{\"metadata\":{\"name\":\"lldap-schema-b\"},\"status\":{\"succeeded\":1}}]}' ;; *) echo \"KCTL \$*\" >> '$WORK/retry-calls' ;; esac; }; rm -f '$WORK/retry-calls'; kube_lldap_schema_retry")"
expect_eq "kube_lldap_schema_retry: only the Failed Job deleted" "$(tr '\n' ';' < "$WORK/retry-calls")" "KCTL -n portcullis delete job lldap-schema-a;"
expect_eq "rt_up: Failed schema Jobs removed after the cluster setup, before the release" \
  "$(declare -f _rtk_up | awk '/kube_lldap_schema_retry/ {r=NR} /kube_helm upgrade/ {h=NR} END {print (r && h > r) ? "before" : "no"}')" before
# Review I4: cnpg-system's deny and the operator's flows from the CLI, before the operator.
k_fixtures; mkdir -p "$WORK/cnroot/secrets"; cp "$HERE/../kube/ha/cnpg/values.yaml" "$CN/kube/ha/cnpg/"
OUT="$(kt "PORTCULLIS_HOME='$CN' PORTCULLIS_ROOT='$WORK/cnroot'; kube_ctl() { echo \"K \$*\" >> '$WORK/cn-order'; case \"\$*\" in *'apply'*'-f -') cat > '$WORK/cn-pol.json' ;; *'get nodes'*) echo '{\"items\":[]}' ;; esac; }; kube_helm() { echo \"H \$*\" >> '$WORK/cn-order'; }; kube_namespace_apply() { echo \"NS \$1\" >> '$WORK/cn-order'; }; rm -f '$WORK/cn-order'; ha_install_cnpg")"
expect_eq "ha_install_cnpg: namespace → its NetworkPolicies → the operator's RBAC → helm (review I2, I4)" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(grep -v 'get nodes' "$WORK/cn-order" | sed -E 's/^(NS|K|H) .*(apply --server-side --force-conflicts --field-manager=portcullis-cli -f -|rbac.yaml|upgrade --install cnpg).*/\1 \2/; s/^NS .*/NS/' | tr '\n' ';')" \
  "rc=0:NS;K apply --server-side --force-conflicts --field-manager=portcullis-cli -f -;K rbac.yaml;H upgrade --install cnpg;"
expect_eq "ha_install_cnpg: default-deny, kube-dns and cnpg-operator (its webhook from the API endpoint only here), all in cnpg-system" \
  "$(jq -c '[.items[] | [.metadata.namespace, .metadata.name]]' "$WORK/cn-pol.json"):$(jq -c '[.items[] | select(.metadata.name == "cnpg-operator") | .spec.ingress[0].from[].ipBlock.cidr]' "$WORK/cn-pol.json")" \
  '[["cnpg-system","default-deny"],["cnpg-system","kube-dns"],["cnpg-system","cnpg-operator"]]:["10.1.0.4/32"]'
OUT="$(kt "PORTCULLIS_HOME='$CN' PORTCULLIS_ROOT='$WORK/cnroot' PORTCULLIS_KUBE_API_ENDPOINTS=; kube_ctl() { echo \"K \$*\"; return 1; }; kube_helm() { echo HELM-RAN; }; ha_install_cnpg" 2>&1)"
case "$OUT" in *"the CNPG webhook would admit nobody (nothing installed)"*"rc=1") t_pass "ha_install_cnpg: no API server address → refused before anything" ;; *) t_fail "cnpg no sources: $OUT" ;; esac
expect_eq "ha_install_cnpg: refused → no helm, no apply" "$(printf '%s\n' "$OUT" | grep -c 'HELM-RAN\|K apply' || true)" 0
OUT="$(kt "_kube_pg_exec() { echo 3; }; _kube_pg_lldap_count; _kube_pg_exec() { echo 'ERROR: relation \"users\" does not exist'; return 1; }; _kube_pg_lldap_count")"
expect_eq "the restore's LLDAP guard on Kubernetes counts LLDAP's users in Postgres; no schema → missing" "$(printf '%s\n' "$OUT" | head -n2 | tr '\n' ' ')" "3 missing "
OUT="$(kt "_kube_pg_exec() { echo \"PG \$*\"; }; rt_exec postgres -- pg_dump -d keycloak -Fc; rt_exec -i postgres -- pg_restore --list")"
expect_eq "rt_exec postgres on Kubernetes: the CNPG primary's postgres container" "$(printf '%s\n' "$OUT" | grep -c '^PG pg_dump -d keycloak -Fc$\|^PG pg_restore --list$')" 2

# ── HA Task 24: Longhorn, external-snapshotter, fencing, cert-manager (scripts/lib/ha.sh) ──
H24="$WORK/h24"; rm -rf "$H24"; mkdir -p "$H24/kube/storage" "$H24/charts/portcullis" "$WORK/h24root/secrets"
cp -R "$HERE/../kube/ha" "$H24/kube/"; cp "$HERE/../kube/storage/storageclass-replicated.yaml" "$H24/kube/storage/"
cp "$HERE/../charts/portcullis/namespaces.json" "$H24/charts/portcullis/"
# Nodes: m1, m2 (main storage), m3 (main small), e1 (edge).
H24_NODES='{"items":[
 {"metadata":{"name":"m1","labels":{"portcullis.io/site":"main","portcullis.io/class":"cloud","node.longhorn.io/create-default-disk":"true"}},"spec":{"podCIDR":"10.42.0.0/24"},"status":{"addresses":[{"type":"InternalIP","address":"10.215.0.1"}]}},
 {"metadata":{"name":"m2","labels":{"portcullis.io/site":"main","portcullis.io/class":"home","node.longhorn.io/create-default-disk":"true"}},"spec":{"podCIDR":"10.42.1.0/24"},"status":{"addresses":[{"type":"InternalIP","address":"10.215.0.2"}]}},
 {"metadata":{"name":"m3","labels":{"portcullis.io/site":"main","portcullis.io/class":"small"}},"spec":{"podCIDR":"10.42.2.0/24"},"status":{"addresses":[{"type":"InternalIP","address":"10.215.0.3"}]}},
 {"metadata":{"name":"e1","labels":{"portcullis.io/site":"edge","portcullis.io/class":"cloud"}},"spec":{"podCIDR":"10.42.3.0/24"},"status":{"addresses":[{"type":"InternalIP","address":"10.215.0.4"}]}}]}'
printf '%s' "$H24_NODES" > "$WORK/h24-nodes.json"
# h24 <code>: the libs on the copy; kube_ctl logs every call (order) and
# answers the nodes; the probes, the render and the waits are stubs set by
# the code (STUB_PROBE: lines to answer, else every check ok).
h24() {
  rm -f "$WORK/h24-calls" "$WORK/h24-applied"
  kt "PORTCULLIS_HOME='$H24' PORTCULLIS_ROOT='$WORK/h24root'
    kube_ctl() { echo \"K \$*\" >> '$WORK/h24-calls'
      case \"\$*\" in *'get nodes -o json'*) cat '$WORK/h24-nodes.json' ;; *'control-plane -o json'*) echo '{\"items\":[{\"spec\":{\"podCIDR\":\"10.42.0.0/24\"}}]}' ;; *'-f -')
        cat >> '$WORK/h24-applied' ;; *' get namespace '*) return 0 ;; esac; }
    kube_namespace_apply() { echo \"NS \$1 \$2\" >> '$WORK/h24-calls'; }
    _ha_node_probes() { local ns=\"\$1\" c=\"\$2\" n x; shift 2; echo \"PROBE \$ns \$c \$*\" >> '$WORK/h24-calls'
      for n in \"\$@\"; do for x in \$c; do
        if [ -n \"\${STUB_PROBE_FAIL:-}\" ] && [ \"\$n \$x\" = \"\${STUB_PROBE_FAIL%%:*}\" ]; then echo \"\$n \$x fail \${STUB_PROBE_FAIL#*:}\"; else echo \"\$n \$x ok\"; fi
      done; done; }
    ha_render() { echo \"RENDER \$*\" >> '$WORK/h24-calls'; echo '{}'; }
    _ha_wait() { echo \"WAIT \$2\" >> '$WORK/h24-calls'; }
    _ha_crds_established() { :; }; _ha_fencing_cert() { echo CERT >> '$WORK/h24-calls'; }
    _ha_probe_setup() { echo PROBESETUP >> '$WORK/h24-calls'; }
    _ha_policy_in_force() { echo \"INFORCE \$2\" >> '$WORK/h24-calls'; }
    ha_fencing_ready() { echo READY-CHECK >> '$WORK/h24-calls'; }
    _kube_apply_files() { echo \"FILES \$*\" >> '$WORK/h24-calls'; }
    $1" 2>&1
}
OUT="$(STUB_PROBE_FAIL='m2 iscsid:open-iscsi is not installed (apt install open-iscsi): Longhorn needs it' h24 ha_install_longhorn)"
case "$OUT" in *"node m2: open-iscsi is not installed"*"Longhorn needs these on every node it runs on"*"(nothing installed)"*"rc=1")
  t_pass "ha_install_longhorn: refuses without open-iscsi on every storage node (naming the node)" ;; *) t_fail "longhorn no iscsi: $OUT" ;; esac
expect_eq "ha_install_longhorn: a failed check → nothing rendered or applied but the namespace's own deny policies" \
  "$(grep -c 'RENDER\|FILES' "$WORK/h24-calls" || true):$(jq -r '.items[].metadata.name' "$WORK/h24-applied" | tr '\n' ' ')" "0:default-deny kube-dns kube-api longhorn-internal "
expect_eq "ha_install_longhorn: checks the main site's non-small nodes (not the small m3, not edge's e1); the ZFS check on the storage nodes" \
  "$(grep '^PROBE ' "$WORK/h24-calls" | tr '\n' ';')" "PROBE portcullis-ha-probe iscsid iscsi_tcp nfs_common multipath_blacklist m1 m2;PROBE portcullis-ha-probe longhorn_path m1 m2;"
OUT="$(STUB_PROBE_FAIL='m1 longhorn_path:/var/lib/longhorn is on a ZFS dataset: use a zvol or a separate disk' h24 ha_install_longhorn)"
case "$OUT" in *"node m1: /var/lib/longhorn is on a ZFS dataset"*"rc=1") t_pass "ha_install_longhorn: a ZFS dataset under /var/lib/longhorn → refused (spike S2)" ;; *) t_fail "longhorn zfs: $OUT" ;; esac
OUT="$(h24 ha_install_longhorn)"
expect_eq "ha_install_longhorn: namespace (PSA longhorn) → deny policies → node checks → render (API + initiator sources) → apply → waits → StorageClass" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(sed -E 's/^(K) .*apply --server-side.* -f -$/\1 apply/; s/^(NS) .*/\1/; s/^(PROBE [a-z-]+).*/\1/; s/^FILES .*\/(.*)$/FILES \1/' "$WORK/h24-calls" | grep -v 'get nodes' | uniq | tr '\n' ';')" \
  "rc=0:NS;K apply;PROBESETUP;PROBE portcullis-ha-probe;K get ValidatingWebhookConfiguration longhorn-webhook-validator -o name;K get MutatingWebhookConfiguration longhorn-webhook-mutator -o name;RENDER longhorn 10.1.0.4 10.42.0.0 10.42.0.1 10.215.0.1 10.42.0.0 10.42.0.1 10.215.0.2 10.42.1.0 10.42.1.1 10.215.0.3 10.42.2.0 10.42.2.1 10.215.0.4 10.42.3.0 10.42.3.1;K apply;WAIT Longhorn's manager (DaemonSet longhorn-manager);WAIT Longhorn's CSI driver;FILES storageclass-replicated.yaml;K get namespace longhorn-system -o name;K -n longhorn-system delete networkpolicy backup-destination --ignore-not-found;K -n longhorn-system delete networkpolicy backup-destination-manager backup-destination-instance-manager --ignore-not-found;K apply;"
expect_eq "ha_install_longhorn: then its backup target (Task 26; no destination here → an empty target, no egress policy)" \
  "$(grep -v '^---$' "$WORK/h24-applied" 2>/dev/null | jq -c 'select(.kind? == "BackupTarget") | .spec' 2>/dev/null | tail -n1)" '{"backupTargetURL":"","credentialSecret":"","pollInterval":"5m0s"}'
expect_eq "ha_install_longhorn: the namespace is longhorn-system with namespaces.json's longhorn levels; applied.json records ha.longhorn" \
  "$(grep '^NS' "$WORK/h24-calls"):$(jq -r 'has("ha.longhorn")' "$WORK/h24root/secrets/kube/applied.json")" "NS longhorn-system $(jq -r '.longhorn[0]' "$HERE/../charts/portcullis/namespaces.json"):true"
# Fix round 1: Longhorn's webhook configurations are the CLI's (no create
# right for Longhorn), empty, with wrangler's objectset labels so its apply
# patches them; present ones are left alone.
LHW="$(printf '%s' "/v1, Kind=Secretlonghorn-webhook-calonghorn-system" | { sha1sum 2>/dev/null || shasum -a 1; } | awk '{print $1}')"
OUT="$(kt "kube_ctl() { case \"\$*\" in get*) return 1 ;; *'create -f -'*) cat >> '$WORK/lhw.json' ;; esac; }; rm -f '$WORK/lhw.json'; _ha_longhorn_webhooks")"
expect_eq "_ha_longhorn_webhooks: the validator and the mutator made empty, labelled with wrangler's hash (owner = longhorn-webhook-ca)" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(jq -sc '[.[] | [.kind, .metadata.name, .metadata.labels["objectset.rio.cattle.io/hash"] == "'"$LHW"'", .metadata.annotations["objectset.rio.cattle.io/owner-name"], (.webhooks | length)]]' "$WORK/lhw.json")" \
  'rc=0:[["ValidatingWebhookConfiguration","longhorn-webhook-validator",true,"longhorn-webhook-ca",0],["MutatingWebhookConfiguration","longhorn-webhook-mutator",true,"longhorn-webhook-ca",0]]'
OUT="$(kt "kube_ctl() { case \"\$*\" in *'create'*) echo CREATED ;; esac; }; _ha_longhorn_webhooks")"
expect_eq "_ha_longhorn_webhooks: present ones are kept (no create)" "$(printf '%s\n' "$OUT" | grep -c CREATED || true)" 0
expect_eq "Longhorn's ClusterRole: no create on webhook configurations (the CLI makes them)" \
  "$(awk '/webhookconfigurations/ { w = 1; next } w && /verbs:/ { print; w = 0 }' "$HERE/../kube/ha/longhorn/rbac.yaml" | grep -c create || true)" 0
printf 'x' >> "$H24/kube/ha/longhorn/upstream/longhorn-1.13.0.tgz"
OUT="$(h24 ha_install_longhorn)"
case "$OUT" in *"the Longhorn pins don't hold: kube/ha/longhorn/upstream/longhorn-1.13.0.tgz has sha256"*"not the pinned e57f010d"*"rc=1") t_pass "ha_install_longhorn: a chart that isn't the pinned release asset → refused" ;; *) t_fail "longhorn pin: $OUT" ;; esac
expect_eq "ha_install_longhorn: a refused pin → not one cluster call" "$(cat "$WORK/h24-calls" 2>/dev/null | wc -l | tr -d ' ')" 0
cp "$HERE/../kube/ha/longhorn/upstream/longhorn-1.13.0.tgz" "$H24/kube/ha/longhorn/upstream/"
printf '%s' '{"items":[{"metadata":{"name":"m3","labels":{"portcullis.io/site":"main","portcullis.io/class":"small"}}}]}' > "$WORK/h24-nodes.json"
OUT="$(h24 ha_install_longhorn)"
case "$OUT" in *"no storage node at main"*"(nothing installed)"*"rc=1") t_pass "ha_install_longhorn: no storage node → refused" ;; *) t_fail "longhorn no storage: $OUT" ;; esac
printf '%s' "$H24_NODES" > "$WORK/h24-nodes.json"
OUT="$(h24 ha_install_fencing)"
case "$OUT" in *"the SNR image (ghcr.io/porelli/portcullis-snr:edge@sha256:0000"*"isn't published yet"*"nothing installed"*"rc=1")
  t_pass "ha_install_fencing: the placeholder SNR digest (before snr.yml's first main build) → refused" ;; *) t_fail "fencing placeholder: $OUT" ;; esac
expect_eq "ha_install_fencing: the placeholder refused before any cluster call" "$(cat "$WORK/h24-calls" 2>/dev/null | wc -l | tr -d ' ')" 0
ONES="1111111111111111111111111111111111111111111111111111111111111111"
OUT="$(kt "PORTCULLIS_HOME='$H24'; PORTCULLIS_DEV_SNR_IMAGE=localhost/x@sha256:$ONES; ha_snr_image; HUB_DEV=1 PORTCULLIS_DEV_SNR_IMAGE=localhost/x:tag ha_snr_image; HUB_DEV=1 PORTCULLIS_DEV_SNR_IMAGE=localhost/x@sha256:$ONES ha_snr_image" 2>&1)"
expect_eq "ha_snr_image: a dev SNR image only with HUB_DEV=1, and only name@sha256" \
  "$(printf '%s\n' "$OUT" | grep -c 'is for development only (HUB_DEV=1)\|must be name@sha256'):$(printf '%s\n' "$OUT" | grep -c '^localhost/x@sha256:1')" "2:1"
OUT="$(STUB_PROBE_FAIL='e1 watchdog:no watchdog device (/dev/watchdog; modprobe softdog provides it)' h24 "HUB_DEV=1 PORTCULLIS_DEV_SNR_IMAGE=localhost/portcullis-snr@sha256:1111111111111111111111111111111111111111111111111111111111111111; ha_install_fencing")"
case "$OUT" in *"node e1 has no watchdog: fencing can't be confirmed (no watchdog device"*"fencing needs a watchdog on every node"*"(nothing installed)"*"rc=1")
  t_pass "ha_install_fencing: refuses a node without /dev/watchdog: 'node <n> has no watchdog: fencing can't be confirmed'" ;; *) t_fail "fencing no watchdog: $OUT" ;; esac
expect_eq "ha_install_fencing: every node checked (the small one and the edge one too); refused → no certificate, render or config" \
  "$(grep '^PROBE ' "$WORK/h24-calls"):$(grep -c 'CERT\|RENDER\|FILES' "$WORK/h24-calls" || true)" "PROBE portcullis-ha-probe watchdog m1 m2 m3 e1:0"
OUT="$(h24 "HUB_DEV=1 PORTCULLIS_DEV_SNR_IMAGE=localhost/portcullis-snr@sha256:1111111111111111111111111111111111111111111111111111111111111111; ha_install_fencing")"
expect_eq "ha_install_fencing: namespace → policies → watchdogs → certificate → render → managers → config.yaml → agents → ha_fencing_ready" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(sed -E 's/^(K) .*apply --server-side.* -f -$/\1 apply/; s/^(NS) .*/\1/; s/^(PROBE [a-z-]+).*/\1/; s/^FILES .*\/(.*)$/FILES \1/' "$WORK/h24-calls" | grep -v 'get nodes' | uniq | tr '\n' ';')" \
  "rc=0:NS;K apply;PROBESETUP;PROBE portcullis-ha-probe;CERT;K apply;INFORCE portcullis-fencing-pods;RENDER fencing;K apply;WAIT SNR's manager;FILES config.yaml;WAIT SNR's agents (DaemonSet self-node-remediation-ds);READY-CHECK;"
expect_eq "ha_install_fencing: portcullis-fencing's policies: deny, DNS, API, SNR's peers on 30001 only between agents" \
  "$(jq -c '[.items[] | .metadata.name] + [.items[] | select(.metadata.name == "snr-peers") | .spec.ingress[0].ports[0].port]' < <(jq -cn 'first(inputs)' "$WORK/h24-applied" 2>/dev/null))" \
  '["default-deny","kube-dns","kube-api","snr-peers",30001]'
OUT="$(h24 ha_install_snapshotter)"
expect_eq "ha_install_snapshotter: its own kube-system policy first (only its pods), the CRDs, then the controller" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(head -c 4000 "$WORK/h24-applied" | jq -sc '.[0] | [.metadata.namespace, .spec.podSelector.matchLabels["app.kubernetes.io/name"], .spec.policyTypes]'):$(grep -o 'FILES .*crds.yaml\|RENDER snapshotter' "$WORK/h24-calls" | sed 's/FILES .*\//FILES /' | tr '\n' ';')" \
  'rc=0:["kube-system","snapshot-controller",["Ingress","Egress"]]:FILES crds.yaml;RENDER snapshotter;'
OUT="$(h24 ha_install_certmanager)"
expect_eq "ha_install_certmanager: cert-manager (restricted) → deny + its webhook :10250 from the API server only → render" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(grep '^NS' "$WORK/h24-calls"):$(jq -sc '.[0].items[] | select(.metadata.name == "webhook") | [[.spec.ingress[0].from[].ipBlock.cidr], .spec.ingress[0].ports[0].port]' "$WORK/h24-applied")" \
  'rc=0:NS cert-manager restricted:[["10.1.0.4/32","10.42.0.0/32","10.42.0.1/32"],10250]'
# Fix round 1 (security review): the host probes run in their own
# namespace, after its default-deny, the policy's params (the helper image
# and the exact script) and the policy itself.
rm -f "$WORK/ps-calls" "$WORK/ps-in" "$WORK/ps-pol"
OUT="$(kt "PORTCULLIS_HOME='$H24'; mkdir -p '$H24/kube/ha/probe'; cp '$HERE/../kube/ha/probe/admission.yaml' '$H24/kube/ha/probe/'
  kube_namespace_apply() { echo \"NS \$*\" >> '$WORK/ps-calls'; }; _ha_policy_in_force() { :; }
  kube_ctl() { echo \"K \$*\" >> '$WORK/ps-calls'; case \"\$*\" in *'create configmap'*) all=\"\$*\"; d=\"\${all##*--from-file=}\"; d=\"\${d%% *}\"; jq -n --rawfile i \"\$d/image\" --rawfile s \"\$d/script\" '{data: {image: \$i, script: \$s}}' ;; *'-f -'*) cat >> '$WORK/ps-in' ;; *admission.yaml) cp \"\${@: -1}\" '$WORK/ps-pol' ;; esac; }
  _ha_probe_setup; jq -sj '.[1].data.script' '$WORK/ps-in' | cmp -s - <(printf '%s' \"\$HA_PROBE_SH\") && echo SCRIPT-SAME")"
expect_eq "_ha_probe_setup: portcullis-ha-probe (PSA haprobe) → its default-deny → the params (helper image, the exact probe script) → the probe policy" \
  "$(printf '%s\n' "$OUT" | tail -n1):$(sed -E 's/^(K) .*(create configmap ha-probe-params).*/\1 \2/; s/^K .*apply.*-f -$/K apply/; s/^K .*apply.*admission.yaml$/K policy/' "$WORK/ps-calls" | tr '\n' ';')" \
  "rc=0:NS portcullis-ha-probe privileged privileged baseline;K apply;K create configmap ha-probe-params;K apply;K policy;"
expect_eq "_ha_probe_setup: the policy applied carries its own generation (no placeholder left), the one _ha_policy_gen names" \
  "$(grep -o 'portcullis-ha-probe-pods generation [0-9a-f]* is in force' "$WORK/ps-pol" | sort -u):$(grep -c '@POLICY_GENERATION@' "$WORK/ps-pol" || true)" \
  "portcullis-ha-probe-pods generation $(kt "_ha_policy_gen '$HERE/../kube/ha/probe/admission.yaml'" | head -n1) is in force:0"
expect_eq "_ha_probe_setup: the namespace's only policy is default-deny; the params hold the helper image and HA_PROBE_SH exactly" \
  "$(jq -sc '[.[0].items[].metadata.name]' "$WORK/ps-in"):$(jq -sr '.[1].data.image' "$WORK/ps-in"):$(printf '%s\n' "$OUT" | grep -c '^SCRIPT-SAME$')" \
  '["default-deny"]:docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a:1'
# Review M1: a policy is in force once a pod no shape admits is refused BY
# it (server dry-run); never refused → not in force (fail).
rm -f "$WORK/pif"
OUT="$(kt "sleep() { :; }; kube_ctl() { jq -r '.metadata.annotations[\"portcullis.io/policy-check\"]' > '$WORK/pif-ann'; echo . >> '$WORK/pif'; [ \$(wc -l < '$WORK/pif') -ge 3 ] && echo \"denied: ValidatingAdmissionPolicy 'portcullis-fencing-pods' with binding x denied request: portcullis-fencing-pods generation 0123456789abcdef is in force\" >&2; return 1; }; _ha_policy_in_force portcullis-fencing portcullis-fencing-pods 0123456789abcdef && echo IN-FORCE
  _ha_policy_in_force portcullis-fencing portcullis-fencing-pods fedcba9876543210 || echo OLD-GEN
  kube_ctl() { cat >/dev/null; return 0; }; _ha_policy_in_force portcullis-fencing portcullis-fencing-pods 0123456789abcdef || echo NOT-IN-FORCE")"
expect_eq "_ha_policy_in_force: refused by the policy with its generation (after two misses) → in force; another generation's refusal (an older copy) or admitted → not in force; the probe pod carries the generation" \
  "$(printf '%s\n' "$OUT" | grep -c '^IN-FORCE$\|^OLD-GEN$\|^NOT-IN-FORCE$'):$(cat "$WORK/pif-ann")" 3:fedcba9876543210
# ha_fencing_ready (the jq over SNR's agents → per node ready), fail closed.
FR_CFG='{"spec":{"watchdogFilePath":"/dev/watchdog","safeTimeToAssumeNodeRebootedSeconds":150}}'
fr() { kt "_ha_deploy_ready() { [ -z \"\${STUB_MGR_DOWN:-}\" ]; }; kube_ctl() { case \"\$*\" in *'get nodes'*) printf '%s' '{\"items\":[{\"metadata\":{\"name\":\"m1\"}},{\"metadata\":{\"name\":\"m2\"}}]}' ;;
    *'get pods'*) [ -n '$1' ] || return 1; printf '%s' '$1' ;; *selfnoderemediationconfigs*) printf '%s' '$2' ;; esac; }; ha_fencing_ready"; }
SNRIMG="ghcr.io/porelli/portcullis-snr:edge@sha256:0000000000000000000000000000000000000000000000000000000000000000"
AGENT='{"metadata":{"name":"self-node-remediation-ds-%s","ownerReferences":[{"kind":"DaemonSet","name":"self-node-remediation-ds"}]},"spec":{"nodeName":"%s","containers":[{"image":"%s"}]},"status":{"conditions":[{"type":"Ready","status":"%s"}]}}'
A1="$(printf "$AGENT" a m1 "$SNRIMG" True)" A2="$(printf "$AGENT" b m2 "$SNRIMG" True)" A2N="$(printf "$AGENT" b m2 "$SNRIMG" False)"
A2OLD="$(printf "$AGENT" b m2 "quay.io/medik8s/self-node-remediation-operator:v0.13.0@sha256:9ad002dca9ea183c72e350f72e47aff7020397fd476b4a3ac4ebc3627412a5b0" True)"
expect_eq "ha_fencing_ready: every node's agent Ready and our configuration → each node ready, exit 0" \
  "$(fr "{\"items\":[$A1,$A2]}" "$FR_CFG" | tr '\t\n' ' ;')" "m1 ready;m2 ready;rc=0;"
expect_eq "ha_fencing_ready: m2's agent of another (old) image → m2 not ready (review nit 7)" \
  "$(fr "{\"items\":[$A1,$A2OLD]}" "$FR_CFG" | tr '\t\n' ' ;')" "m1 ready;m2 not ready (no Ready SNR agent);rc=1;"
expect_eq "ha_fencing_ready: m2's agent not Ready → m2 not ready, exit 1 (Task 31 stops: no stateful failover)" \
  "$(fr "{\"items\":[$A1,$A2N]}" "$FR_CFG" | tr '\t\n' ' ;')" "m1 ready;m2 not ready (no Ready SNR agent);rc=1;"
expect_eq "ha_fencing_ready: another safe time / watchdog (not ours) → no node ready" \
  "$(fr "{\"items\":[$A1,$A2]}" '{"spec":{"watchdogFilePath":"/dev/watchdog","safeTimeToAssumeNodeRebootedSeconds":90}}' | grep -c 'not ready (SNR configuration missing or not ours)'):$(fr "{\"items\":[$A1,$A2]}" '{"spec":{}}' | tail -n1)" "2:rc=1"
expect_eq "ha_fencing_ready: SNR's manager not available → no node ready (no out-of-service taint)" \
  "$(STUB_MGR_DOWN=1 fr "{\"items\":[$A1,$A2]}" "$FR_CFG" | grep -c "not ready (SNR's manager isn't available)")" 2
OUT="$(fr "" "$FR_CFG")"
case "$OUT" in *"can't read SNR's agents: fencing unconfirmed"*"rc=1") t_pass "ha_fencing_ready: the agents unreadable → fencing unconfirmed, exit 1" ;; *) t_fail "fencing unreadable: $OUT" ;; esac
# Fail closed (Global Constraints [24]): no volume leaves an unfenced node by timeout.
expect_eq "fencing unconfirmed → no stateful failover: every server's kube-controller-manager never force-detaches (init flags, nodeadm's join flags)" \
  "$(grep -c '^--kube-controller-manager-arg=disable-force-detach-on-timeout=true$' "$HERE/fixtures/k3s-server-flags.txt"):$(grep -c '"--kube-controller-manager-arg=disable-force-detach-on-timeout=true"' "$HERE/../nodeadm/flags.go")" "1:1"
# The bundled settings (static; tests/k8s_hardening.py checks the render).
LHV="$HERE/../kube/ha/longhorn/values.yaml"
expect_eq "longhorn settings: node-down-pod-deletion-policy do-nothing, no soft anti-affinity, disks only on labelled nodes, system pods at main" \
  "$(grep -cE '^  (nodeDownPodDeletionPolicy: do-nothing|replicaSoftAntiAffinity: false|createDefaultDiskLabeledNodes: true|systemManagedComponentsNodeSelector: "portcullis.io/site:main"|upgradeChecker: false)$' "$LHV")" 5
expect_eq "fencing config: watchdog /dev/watchdog, safe time 150 (S3), small nodes tolerated; no NHC (nodeadm remediates)" \
  "$(grep -cE '^  (watchdogFilePath: /dev/watchdog|safeTimeToAssumeNodeRebootedSeconds: 150|maxApiErrorThreshold: 2)$|key: portcullis.io/small, operator: Exists' "$HERE/../kube/ha/fencing/config.yaml"):$(grep -c 'NodeHealthCheck\|node-healthcheck' "$HERE/../kube/ha/fencing/config.yaml" "$HERE/../kube/ha/fencing/kustomization.yaml" "$HERE/../kube/ha/fencing/rbac.yaml" "$HERE/../scripts/lib/ha.sh" | awk -F: '{s += $2} END {print s}')" "4:0"
# ha manifests: every image pinned by digest (lint_images over kube/ha;
# a broken digest in a values file and a kustomization fails it).
LT="$WORK/lint-ha"; rm -rf "$LT"; mkdir -p "$LT"
( cd "$HERE/.." && find . -path ./.git -prune -o -path './kube/ha/*/upstream' -prune -o -type f \( -name '*.yaml' -o -name '*.yml' -o -name '*.sh' \
    -o -name Dockerfile -o -name portcullis \) -print | tar -cf - -T - ) | tar -xf - -C "$LT"
expect_eq "ha manifests: every image pinned by digest (tests/lint_images.sh)" "$(bash "$LT/tests/lint_images.sh" >/dev/null 2>&1; echo $?)" 0
sed -i.bak 's/v2.18.0@sha256:[0-9a-f]*"/v2.18.0"/' "$LT/kube/ha/longhorn/values.yaml"
awk '!/^    digest: sha256:0000/' "$LT/kube/ha/fencing/kustomization.yaml" > "$LT/k.t" && mv "$LT/k.t" "$LT/kube/ha/fencing/kustomization.yaml"
OUT="$(bash "$LT/tests/lint_images.sh" 2>&1)"
expect_eq "ha manifests: a values tag without a digest and a kustomization image without one → lint fails naming both" \
  "$(printf '%s\n' "$OUT" | grep -c 'values.yaml:.*v2.18.0 (not <tag>@sha256)\|fencing/kustomization.yaml: image quay.io/medik8s/self-node-remediation-operator without a sha256 digest')" 2
# Never on a non-HA install: only ha enable (Task 31) calls them.
expect_eq "the Task 24 installs are never on a non-HA install (no caller in the cluster setup, rt_up, init or up)" \
  "$(grep -n 'ha_install_\(longhorn\|snapshotter\|fencing\|certmanager\)\|ha_fencing_ready' "$HERE"/../scripts/lib/*.sh "$HERE"/../portcullis | grep -v '^[^:]*ha\.sh:' | grep -vc '^[^:]*:[0-9]*: *#' || true)" 0
expect_eq "ha_install_*: never helm --set or helm install (a pinned render, applied server-side)" \
  "$(declare -f ha_render ha_install_longhorn ha_install_fencing ha_install_snapshotter ha_install_certmanager 2>/dev/null | grep -c -- '--set\|helm upgrade\|helm install\|kube_helm' || true)" 0
# ── LLDAP's key seed (users.sh): per install, never the public default ──
# shellcheck source=../scripts/lib/users.sh
source "$HERE/../scripts/lib/users.sh"
# shellcheck source=../scripts/lib/stack.sh
source "$HERE/../scripts/lib/stack.sh"
KS_ROOT="$WORK/ks-root"; mkdir -p "$KS_ROOT"
KS_OUT="$(PORTCULLIS_ROOT="$KS_ROOT" lldap_key_seed_generate 2>&1)"
KS_F="$KS_ROOT/secrets/lldap/key-seed"
# 64 bytes and one 64-character line: no newline.
expect_eq "lldap key seed: init makes 64 base64 characters (48 CSPRNG bytes), no newline" \
  "$(wc -c < "$KS_F" | tr -d ' '):$(LC_ALL=C grep -c '^[A-Za-z0-9+/]\{64\}$' "$KS_F")" "64:1"
expect_eq "lldap key seed: file 0600, directory 0700 as made" "$(file_mode "$KS_F"):$(file_mode "${KS_F%/*}")" "600:700"
case "$KS_OUT" in *"$(cat "$KS_F")"*) t_fail "lldap key seed: the seed was printed" ;; *) t_pass "lldap key seed: never printed" ;; esac
KS_OLD="$(cat "$KS_F")"
PORTCULLIS_ROOT="$KS_ROOT" lldap_key_seed_generate >/dev/null 2>&1
expect_eq "lldap key seed: a present seed is kept (never regenerated)" "$(cat "$KS_F")" "$KS_OLD"
KS_OTHER="$(PORTCULLIS_ROOT="$WORK/ks-other" lldap_key_seed_generate >/dev/null 2>&1; cat "$WORK/ks-other/secrets/lldap/key-seed")"
[ "$KS_OTHER" != "$KS_OLD" ] && t_pass "lldap key seed: each install gets its own" || t_fail "lldap key seed: two installs share a seed"
rm -f "$STUB_DIR/calls"
( PORTCULLIS_ROOT="$KS_ROOT"; _owner_of() { echo "$(id -u):9999"; }; lldap_key_seed_fix_perms ) >/dev/null 2>&1
expect_eq "lldap key seed: fix_perms → file 0640, directory 0700" "$(file_mode "$KS_F"):$(file_mode "${KS_F%/*}")" "640:700"
expect_ok "lldap key seed: group 1000 (the -rootless lldap) through ct_own" grep -q "chown $(id -u):1000 /t/0\$" "$STUB_DIR/calls"
expect_eq "lldap key seed: a good seed has no problem" "$(PORTCULLIS_ROOT="$KS_ROOT" lldap_key_seed_problem)" ""
ksp() { ( PORTCULLIS_ROOT="$WORK/ks-bad"; rm -rf "$PORTCULLIS_ROOT"; mkdir -p "$PORTCULLIS_ROOT/secrets/lldap"; eval "$1"; lldap_key_seed_problem ); }
case "$(ksp ':')" in *"missing or empty"*) t_pass "lldap key seed: missing → problem" ;; *) t_fail "lldap key seed: missing" ;; esac
case "$(ksp ': > "$PORTCULLIS_ROOT/secrets/lldap/key-seed"')" in *"missing or empty"*) t_pass "lldap key seed: empty → problem" ;; *) t_fail "lldap key seed: empty" ;; esac
case "$(ksp 'printf "RanD0m STR1ng" > "$PORTCULLIS_ROOT/secrets/lldap/key-seed"')" in *"public default seed"*) t_pass "lldap key seed: the upstream public default → problem" ;; *) t_fail "lldap key seed: public default" ;; esac
case "$(ksp 'printf "short-seed-123" > "$PORTCULLIS_ROOT/secrets/lldap/key-seed"')" in *"too short (14 characters"*) t_pass "lldap key seed: under 32 bytes of base64 → problem" ;; *) t_fail "lldap key seed: short" ;; esac
case "$(ksp 'mkdir "$PORTCULLIS_ROOT/secrets/lldap/key-seed"')" in *"is a directory"*) t_pass "lldap key seed: a directory (made by Docker) → problem" ;; *) t_fail "lldap key seed: directory" ;; esac
KS_REQ="$( (PORTCULLIS_ROOT="$WORK/ks-none"; lldap_key_seed_require) 2>&1; echo "rc=$?")"
case "$KS_REQ" in *"Refusing to start LLDAP without its own key seed"*"rc=1"*) t_pass "lldap key seed: require fails closed" ;; *) t_fail "lldap key seed require: $KS_REQ" ;; esac
KS_UP="$( (PORTCULLIS_ROOT="$WORK/ks-none"; VAULT_INIT_FILE="$KS_F"; env_require() { :; }; require_cmd() { :; }
  runtime_check() { echo REACHED-RUNTIME; }; stack_up) 2>&1; echo "rc=$?")"
case "$KS_UP" in *REACHED-RUNTIME*) t_fail "up without a key seed went on: $KS_UP" ;; *"Refusing to start LLDAP"*"rc=1"*) t_pass "up refuses without LLDAP's key seed, before anything starts" ;; *) t_fail "up without a seed: $KS_UP" ;; esac
# shellcheck disable=SC2034  # read by upgrade_run
KS_UG="$( (PORTCULLIS_ROOT="$WORK/ks-none"; VAULT_INIT_FILE="$KS_F"; env_require() { :; }; require_cmd() { :; }; env_generate_missing() { :; }
  runtime_check() { echo REACHED-RUNTIME; }; upgrade_run true) 2>&1; echo "rc=$?")"
case "$KS_UG" in *REACHED-RUNTIME*) t_fail "upgrade without a key seed went on" ;; *"Refusing to start LLDAP"*"rc=1"*) t_pass "upgrade refuses without LLDAP's key seed" ;; *) t_fail "upgrade without a seed: $KS_UG" ;; esac
# The running container (status): what LLDAP really has.
KS_RT="$( ( rt_running() { return 0; }; rt_exec() { printf '%s\n' "$@" > "$WORK/ks-exec"; printf 'checked\n'; }; lldap_key_seed_runtime_problems ) )"
expect_eq "lldap key seed (container): all well → nothing" "$KS_RT" ""
expect_ok "lldap key seed (container): only the public default goes on argv, no secret" sh -c "grep -qx 'RanD0m STR1ng' '$WORK/ks-exec' && ! grep -q '$KS_OLD' '$WORK/ks-exec'"
KS_RT="$( ( rt_running() { return 0; }; rt_exec() { printf 'plain-env\nno-seed-file\nkey-file\nconfig-default\nchecked\n'; }; lldap_key_seed_runtime_problems ) )"
expect_eq "lldap key seed (container): plain env, no seed file, a key file and the default in lldap_config.toml are each a problem" \
  "$(printf '%s\n' "$KS_RT" | grep -c .):$(printf '%s' "$KS_RT" | grep -c 'public default key_seed')" "4:1"
KS_RT="$( ( rt_running() { return 0; }; rt_exec() { return 1; }; lldap_key_seed_runtime_problems ) )"
case "$KS_RT" in *"couldn't be checked"*) t_pass "lldap key seed (container): a failed exec is a problem (fail closed)" ;; *) t_fail "lldap key seed exec failure: $KS_RT" ;; esac
expect_eq "lldap key seed (container): LLDAP not running → nothing here (status shows LLDAP down)" \
  "$( ( rt_running() { return 1; }; lldap_key_seed_runtime_problems ) )" ""
# A backup without the seed is incomplete (its users.db can't start without it).
KB="$WORK/ks-backup"; mkdir -p "$KB/secrets/vault-unseal"
printf '{"format":%s}' "$BACKUP_FORMAT" > "$KB/MANIFEST.json"
for f in .env vault.snap postgres.dump secrets/vault-unseal/unseal-key; do echo x > "$KB/$f"; done
echo '{"root_token":"t","unseal_keys_b64":["k"]}' > "$KB/secrets/vault-init.json"
KS_BK="$( (_backup_check_layout "$KB") 2>&1; echo "rc=$?")"
case "$KS_BK" in *"lacks secrets/lldap/key-seed"*"rc=1"*) t_pass "backup layout: no LLDAP key seed → incomplete backup" ;; *) t_fail "backup layout seed: $KS_BK" ;; esac
mkdir -p "$KB/secrets/lldap"; cp "$KS_F" "$KB/secrets/lldap/key-seed"
KS_BK="$( (_backup_check_layout "$KB") 2>&1; echo "rc=$?")"
case "$KS_BK" in *"lacks lldap_data.tar.gz"*"rc=1"*) t_pass "backup layout: a seed without its users.db archive → incomplete (never this host's users.db with the backup's seed)" ;; *) t_fail "backup layout lldap_data: $KS_BK" ;; esac
echo x > "$KB/lldap_data.tar.gz"
kbl() { (_backup_check_layout "$1"); }  # a subshell: fail exits
expect_ok "backup layout: the seed and lldap_data.tar.gz → complete" kbl "$KB"
printf 'short-seed' > "$KB/secrets/lldap/key-seed"
KS_BK="$( (_backup_check_layout "$KB") 2>&1; echo "rc=$?")"
case "$KS_BK" in *"in the backup, secrets/lldap/key-seed is too short"*"refusing to restore it"*"rc=1"*) t_pass "backup layout: a seed LLDAP can't use is refused before anything changes" ;; *) t_fail "backup layout bad seed: $KS_BK" ;; esac
printf 'RanD0m STR1ng' > "$KB/secrets/lldap/key-seed"
case "$( (_backup_check_layout "$KB") 2>&1)" in *"public default seed"*) t_pass "backup layout: the public default seed is refused" ;; *) t_fail "backup layout default seed" ;; esac
# A hand-made seed that isn't base64 (long enough) is a problem too.
case "$(ksp 'printf "%064d!" 0 > "$PORTCULLIS_ROOT/secrets/lldap/key-seed"')" in *"is not base64"*) t_pass "lldap key seed: not base64 → problem" ;; *) t_fail "lldap key seed: charset" ;; esac
# init never replaces a seed file: an empty one is refused, not rewritten.
KS_E="$WORK/ks-empty"; mkdir -p "$KS_E/secrets/lldap"; : > "$KS_E/secrets/lldap/key-seed"
KS_GEN="$( (PORTCULLIS_ROOT="$KS_E"; lldap_key_seed_generate) 2>&1; echo "rc=$?")"
case "$KS_GEN" in *"missing or empty"*"rc=1"*) t_pass "lldap key seed: init refuses an existing (empty) seed file instead of replacing it" ;; *) t_fail "init empty seed: $KS_GEN" ;; esac
expect_eq "lldap key seed: the empty file is left as it was" "$(wc -c < "$KS_E/secrets/lldap/key-seed" | tr -d ' ')" 0
expect_eq "lldap key seed: generation hard-links (ln never overwrites) and checks 64 characters" \
  "$(declare -f lldap_key_seed_generate | grep -c 'ln "$tmp" "$f"'):$(declare -f lldap_key_seed_generate | grep -c '!= 64')" "1:1"
# init on docker refuses a seed made next to an lldap_data holding a users.db.
KS_O="$WORK/ks-olddata"; rm -rf "$KS_O"; mkdir -p "$KS_O"
KS_OLD_OUT="$( (PORTCULLIS_ROOT="$KS_O"; lldap_key_seed_generate >/dev/null; docker() { echo "docker $*" >> "$WORK/ks-old-calls"; return 0; }
  lldap_key_seed_new_on_old_data) 2>&1; echo "rc=$?")"
case "$KS_OLD_OUT" in *"already holds a users.db"*"rc=1"*) t_pass "init: a new seed next to an existing users.db → refused up front" ;; *) t_fail "init old data: $KS_OLD_OUT" ;; esac
expect_eq "init: the seed just made is removed again (a re-run behaves the same)" "$([ -e "$KS_O/secrets/lldap/key-seed" ] && echo kept || echo removed)" removed
expect_ok "init: the users.db probe is read-only, no network, no capability" grep -q -- '--network none --read-only --cap-drop ALL .*type=volume,src=portcullis_lldap_data,dst=/v,readonly .* test -e /v/users.db' "$WORK/ks-old-calls"
KS_OLD_OUT="$( (PORTCULLIS_ROOT="$KS_O"; lldap_key_seed_generate >/dev/null; docker() { case "$*" in "volume inspect"*) return 1 ;; esac; return 0; }
  lldap_key_seed_new_on_old_data; echo "kept:$([ -s "$KS_O/secrets/lldap/key-seed" ] && echo yes)") 2>&1; echo "rc=$?")"
case "$KS_OLD_OUT" in *"kept:yes"*"rc=0"*) t_pass "init: no lldap_data volume → the new seed stays" ;; *) t_fail "init no volume: $KS_OLD_OUT" ;; esac
# shellcheck disable=SC2034  # read by lldap_key_seed_new_on_old_data
KS_OLD_OUT="$( (PORTCULLIS_ROOT="$KS_O"; LLDAP_KEY_SEED_MADE=false; docker() { echo CALLED; }; lldap_key_seed_new_on_old_data; echo no-probe) 2>&1)"
expect_eq "init: a seed that was already there → no probe" "$KS_OLD_OUT" no-probe
# compose / chart / overlay: one mechanism everywhere (LLDAP_KEY_SEED_FILE).
CY="$HERE/../docker-compose.yml"
expect_eq "compose lldap: the seed by file, no key file, no plain seed, no image entrypoint, no config file" \
  "$(yq -o=json '.services.lldap' "$CY" | jq -c '[.environment.LLDAP_KEY_SEED_FILE, .environment.LLDAP_KEY_FILE, (.environment | has("LLDAP_KEY_SEED")), .entrypoint, .command, (.volumes | index("./secrets/lldap/key-seed:/run/portcullis/lldap/key-seed:ro") != null), .healthcheck.test[-1]]')" \
  '["/run/portcullis/lldap/key-seed","",false,["tini","--","/app/lldap"],["run","--config-file","/dev/null"],true,"/dev/null"]'
expect_eq "the SELinux overlay labels the seed for LLDAP alone (Z)" \
  "$(grep -c 'source: ./secrets/lldap/key-seed, target: /run/portcullis/lldap/key-seed, read_only: true, bind: {selinux: Z}' "$HERE/../docker-compose.podman-selinux.yml")" 1
expect_eq "nothing else mounts LLDAP's seed" "$(grep -c '^ *- \./secrets/lldap' "$CY")" 1

# ── Task 26: the backup destination (backup.sh, ha.sh) ──
BD="$WORK/bdest"; rm -rf "$BD"; mkdir -p "$BD/root/secrets" "$BD/bin"
printf 'CONTAINER_RUNTIME=kubernetes\n' > "$BD/root/.env"
# curl stub: argv and stdin (curl's -K - config) logged apart; the status
# from STUB_CURL_PUT / STUB_CURL_DEL.
cat > "$BD/bin/curl" <<'CSTUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$BD_DIR/curl-argv"
cat >> "$BD_DIR/curl-stdin"
case "$*" in *"-X PUT"*) printf '%s' "${STUB_CURL_PUT:-200}" ;; *"-X DELETE"*) printf '%s' "${STUB_CURL_DEL:-204}" ;; *) printf 000 ;; esac
CSTUB
chmod +x "$BD/bin/curl"
BD_KEY="AKIATESTKEY0000SECRET1" BD_SEC="wJalrXUtnFEMI/K7MDENG/bPxRfiCYsecretKEY99"
# The in-cluster DNS probe's double (review NM4; the pod's Python has its
# own test below): the lookups from the getent stub, as the probe stops
# (an empty answer or a changed set), BD_TTL / BD_LONG as its TTL / verdict.
cat > "$BD/probe-double.sh" <<'PDOUBLE'
_backup_dest_dns_probe() {
  local i g first="" out="" n=0
  for ((i = 1; i <= ${BACKUP_DEST_RESOLVE_TRIES:-5}; i++)); do
    g="$(getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | LC_ALL=C sort -u | jq -Rsc 'split("\n") | map(select(. != ""))')"
    out="$out${out:+,}{\"ips\":$g,\"ttl\":${BD_TTL:-1}}"; n=$((n + 1))
    [ "$g" != "[]" ] || break
    [ -n "$first" ] || first="$g"
    [ "$g" = "$first" ] || break
    [ "${BD_LONG:-false}" = false ] || break
  done
  echo "{\"lookups\":[$out],\"long\":${BD_LONG:-false}}"
}
# hub vpn host-info: BD_HOSTINFO (exported; "fail" = the Hub not answering).
_vpn_host_info() {
  [ "${BD_HOSTINFO:-}" != fail ] || return 1
  local d='{"local_networks":["10.0.0.0/8"],"provider_ranges":[]}'
  printf '%s' "${BD_HOSTINFO:-$d}"
}
PDOUBLE
bdk() { rm -f "$BD/curl-argv" "$BD/curl-stdin"; k_fixtures; : > "$KS/kube/ns-cnpg-system.json"
  kt "export PORTCULLIS_ROOT=\"\${BD_ROOT:-$BD/root}\" BD_DIR='$BD' PATH='$BD/bin':\$PATH PORTCULLIS_KUBE_NODE_ADDRESSES=\${BD_NODES-198.51.100.1} BACKUP_DEST_RESOLVE_WAIT=0
    getent() { echo '203.0.113.50 STREAM s3.example.org'; }
    . '$BD/probe-double.sh'; env_load 2>/dev/null || true; $1"; }
OUT="$(printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\nAWS_DEFAULT_REGION=eu-west-1\n' "$BD_KEY" "$BD_SEC" \
  | bdk "backup_dest_set https://s3.example.org/pc-bucket/site-a")"
case "$OUT" in *"wrote and deleted a test object"*"Backup destination set: https://s3.example.org/pc-bucket/site-a"*"rc=0") t_pass "backup destination set: tested, then stored, synced" ;; *) t_fail "backup destination set: $OUT" ;; esac
expect_eq "backup destination set: credentials never on argv (stdin only) — not in curl's or kubectl's argv, nor in the output" \
  "$(cat "$BD/curl-argv" "$KS/kubectl-calls" 2>/dev/null | grep -c "$BD_KEY\|$BD_SEC" || true):$(printf '%s' "$OUT" | grep -c "$BD_KEY\|$BD_SEC" || true)" "0:0"
expect_eq "backup destination set: the key pair reaches curl on its stdin config (-K -), SigV4 with the region" \
  "$(grep -c "^user = \"$BD_KEY:$BD_SEC\"$" "$BD/curl-stdin"):$(grep -c '^aws-sigv4 = "aws:amz:eu-west-1:s3"$' "$BD/curl-stdin"):$(grep -c -- '-K - -X PUT' "$BD/curl-argv")" "2:2:1"
expect_eq "backup destination test: one PUT and one DELETE of the same test object under <url>/" \
  "$(grep -o -- '-X [A-Z]*' "$BD/curl-argv" | tr '\n' ' '):$(grep -o 'https://s3.example.org/pc-bucket/site-a/\.portcullis-test-[0-9]*-[0-9a-f]*$' "$BD/curl-argv" | sort -u | wc -l | tr -d ' ')" "-X PUT -X DELETE :1"
expect_eq "backup destination set: secrets/backup-destination.env 0600, the URL in .env" \
  "$(file_mode "$BD/root/secrets/backup-destination.env"):$(grep -c '^PORTCULLIS_BACKUP_S3_URL=https://s3.example.org/pc-bucket/site-a$' "$BD/root/.env")" "600:1"
expect_eq "backup destination set: the Secret backup-destination from files (base64 in its data), never a literal" \
  "$(grep -c -- '--from-literal' "$KS/kubectl-calls" || true):$(grep -c "$(printf '%s' "$BD_SEC" | base64 | tr -d '\n')" "$KS/kubectl-stdin"):$(grep -c "$BD_SEC" "$KS/kubectl-stdin" || true)" "0:1:0"
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.example.org/pc-bucket/site-a; backup_dest_show")"
case "$OUT" in *"credentials: set"*"region: eu-west-1"*) t_pass "backup destination show: URL, parts, region, credentials set" ;; *"region: eu-west-1"*"credentials: set"*) t_pass "backup destination show: URL, parts, region, credentials set" ;; *) t_fail "backup destination show: $OUT" ;; esac
expect_eq "backup destination show: no secret in output (not the key, not the secret, not a prefix of either)" \
  "$(printf '%s' "$OUT" | grep -c "${BD_KEY:0:8}\|${BD_SEC:0:8}" || true)" 0
for u in "http://s3.example.org/b1b/p|must be https" "https://AKIA:pw@s3.example.org/bkt|credentials, a query" "https://s3.example.org/bkt?x=1|a query" \
         "https://s3.example.org/B|no valid bucket" "https://s3.example.org/bkt/../x|. or .." "s3://bkt/p|https:// URL"; do
  case "$(backup_dest_url_problem "${u%%|*}")" in *"${u#*|}"*) t_pass "backup destination: ${u%%|*} refused" ;; *) t_fail "backup destination url ${u%%|*}: $(backup_dest_url_problem "${u%%|*}")" ;; esac
done
expect_eq "backup destination: an https bucket with a prefix is fine; http only with HUB_DEV=1" \
  "$(backup_dest_url_problem https://s3.eu.example.org:9000/pc-bkt/a/b):$(HUB_DEV=1 backup_dest_url_problem http://10.0.0.5:9000/pc-bkt)" ":"
OUT="$(printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SESSION_TOKEN=x\n' "$BD_KEY" | bdk "backup_dest_set https://s3.example.org/pc-bucket")"
case "$OUT" in *"unknown line on stdin"*"rc=1") t_pass "backup destination set: an unknown stdin line refused" ;; *) t_fail "backup destination unknown line: $OUT" ;; esac
OUT="$(printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "$BD_KEY" "$BD_SEC" | STUB_CURL_PUT=403 bdk "backup_dest_set https://s3.example.org/pc-bucket")"
case "$OUT" in *"refused a test write (HTTP 403"*"rc=1") t_pass "backup destination set: a refused test write fails (nothing synced)" ;; *) t_fail "backup destination 403: $OUT" ;; esac
# restic: the destination is the repository (s3:<url>/core), its keys BACKUP_AWS_*.
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.example.org/pc-bucket/site-a BACKUP_PASSWORD=x; _restic_require; echo \"REPO=\$BACKUP_REPOSITORY\"; [ \"\$BACKUP_AWS_SECRET_ACCESS_KEY\" = '$BD_SEC' ] && echo KEYS-OK")"
case "$OUT" in *"REPO=s3:https://s3.example.org/pc-bucket/site-a/core"*"KEYS-OK"*) t_pass "restic: with a destination the repository is s3:<url>/core with its keys (BACKUP_AWS_*)" ;; *) t_fail "restic destination: $OUT" ;; esac
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.example.org/pc-bucket/site-a BACKUP_PASSWORD=x BACKUP_REPOSITORY=/srv/elsewhere; _restic_require")"
case "$OUT" in *"isn't the backup destination's"*"rc=1") t_pass "restic: another BACKUP_REPOSITORY next to the destination is refused" ;; *) t_fail "restic two repositories: $OUT" ;; esac
# The chart's values and the Hub's record.
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9:9000/pc-bucket/site-a; f=\$(mktemp); echo '{}' > \$f; _kube_barman_ready() { return 0; }; kube_backup_values \$f; jq -c .backup \$f")"
case "$OUT" in *'{"destination":true,"cnpg":{"enabled":true,"destinationPath":"s3://pc-bucket/site-a/cnpg","endpointURL":"https://203.0.113.9:9000","port":9000,"serverName":"portcullis-pg-0b0e2b3c","publicEgress":false,"endpointCIDRs":["203.0.113.9/32"],'*) t_pass "kube_backup_values: the destination, CNPG's path and endpoint under <url>/cnpg" ;; *) t_fail "kube_backup_values: $OUT" ;; esac
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.example.org/pc-bucket; f=\$(mktemp); echo '{}' > \$f; _kube_barman_ready() { return 1; }; kube_backup_values \$f; jq -c '.backup | [.destination, .cnpg.enabled]' \$f")"
case "$OUT" in *'[true,false]'*) t_pass "kube_backup_values: no CNPG archive while the plugin isn't ready" ;; *) t_fail "kube_backup_values no plugin: $OUT" ;; esac
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=; f=\$(mktemp); echo '{}' > \$f; kube_backup_values \$f; jq -c '.backup | [.destination, .cnpg.enabled]' \$f")"
case "$OUT" in *'[false,false]'*) t_pass "kube_backup_values: no destination → nothing" ;; *) t_fail "kube_backup_values none: $OUT" ;; esac
# Review M1: a refused test leaves no file and .env as it was.
mkdir -p "$BD/root2/secrets"; printf 'CONTAINER_RUNTIME=kubernetes\n' > "$BD/root2/.env"
OUT="$(printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "$BD_KEY" "$BD_SEC" | BD_ROOT="$BD/root2" STUB_CURL_PUT=403 bdk "backup_dest_set https://s3.example.org/pc-bucket")"
expect_eq "backup destination set: after a 403, no credentials file and .env unchanged (tested from variables first)" \
  "$(printf '%s' "$OUT" | tail -n1):$(test -e "$BD/root2/secrets/backup-destination.env" && echo file || echo nofile):$(cat "$BD/root2/.env")" "rc=1:nofile:CONTAINER_RUNTIME=kubernetes"
OUT="$(printf 'AWS_ACCESS_KEY_ID=AKIA:X\nAWS_SECRET_ACCESS_KEY=%s\n' "$BD_SEC" | BD_ROOT="$BD/root2" bdk "backup_dest_set https://s3.example.org/pc-bucket")"
case "$OUT" in *"AWS_ACCESS_KEY_ID on stdin has a ':'"*"rc=1") t_pass "backup destination set: a ':' in the key id refused (curl's user value)" ;; *) t_fail "key id colon: $OUT" ;; esac
# Review I2: https checked at every use — an http URL in .env without HUB_DEV is refused.
for fn in "f=\$(mktemp); echo '{}' > \$f; kube_backup_values \$f" "BACKUP_PASSWORD=x _restic_require" ": > '$KS/kube/ns-longhorn-system.json'; ha_longhorn_backup_target" "backup_dest_test"; do
  OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=http://203.0.113.9/pc-bucket; unset HUB_DEV; $fn")"
  case "$OUT" in *"PORTCULLIS_BACKUP_S3_URL in .env: the destination must be https://"*"rc=1") t_pass "backup destination: http in .env without HUB_DEV refused at use (${fn%%;*})" ;; *) t_fail "http at use (${fn%%;*}): $OUT" ;; esac
done
# Review I1: the archive's serverName from the install id.
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9/pc-bucket; f=\$(mktemp); echo '{}' > \$f; _kube_barman_ready() { return 0; }; kube_backup_values \$f; jq -r .backup.cnpg.serverName \$f")"
expect_eq "kube_backup_values: serverName = portcullis-pg-<install id's first 8 hex>" "$(printf '%s\n' "$OUT" | head -n1)" "portcullis-pg-0b0e2b3c"
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9/pc-bucket PORTCULLIS_KUBE_INSTALL_ID=bogus; f=\$(mktemp); echo '{}' > \$f; _kube_barman_ready() { return 0; }; kube_backup_values \$f")"
case "$OUT" in *"isn't a uuid"*"rc=1") t_pass "kube_backup_values: no install id → refused (never a shared archive path)" ;; *) t_fail "serverName no id: $OUT" ;; esac
# Review I3: rotating addresses → any public address on 443; stable → pinned.
ROT="getent() { n=\$(cat '$BD/rot' 2>/dev/null || echo 0); echo \$((n + 1)) > '$BD/rot'; echo \"52.0.0.\$((n % 3 + 1)) STREAM\"; }"
# The opt-in is .env's (review NM3): BD_ALLOW writes it there.
BD_ALLOW="env_set PORTCULLIS_BACKUP_ALLOW_ROTATING true; export PORTCULLIS_BACKUP_ALLOW_ROTATING=true"
bd_allow_off() { grep -v '^PORTCULLIS_BACKUP_ALLOW_ROTATING=' "$BD/root/.env" > "$BD/env.tmp" || true; cat "$BD/env.tmp" > "$BD/root/.env"; }
rm -f "$BD/rot"; OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.us-east-1.amazonaws.com/pc-bucket; $ROT; backup_dest_egress_resolve")"
case "$OUT" in *"addresses rotate"*"Refused; to allow TCP 443 to any public address from the backup pods, set it again with --allow-rotating-addresses"*"rc=1") t_pass "backup egress: a rotating name without the opt-in → refused naming --allow-rotating-addresses (never automatic)" ;; *) t_fail "rotating no opt-in: $OUT" ;; esac
rm -f "$BD/rot"; OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.us-east-1.amazonaws.com/pc-bucket; $BD_ALLOW; $ROT; backup_dest_egress_resolve; echo \"MODE=\$_BD_EGRESS_MODE\"; printf '%s\n' \"\$_BD_EGRESS_EXCEPT\"")"; bd_allow_off
expect_eq "backup egress: a rotating name → public (the probe stops at the first change)" "$(printf '%s\n' "$OUT" | grep -c '^MODE=public$'):$(cat "$BD/rot")" "1:2"
expect_eq "backup egress (public): RFC 1918, CGNAT, link-local, loopback, the pod / service / mesh CIDRs, the nodes and API endpoints excepted" \
  "$(for c in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 127.0.0.0/8 10.42.0.0/24 10.43.0.0/16 10.215.0.0/24 198.51.100.1/32 10.1.0.4/32; do printf '%s\n' "$OUT" | grep -qx "$c" || echo "missing $c"; done)" ""
rm -f "$BD/rot"; OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.example.org:9000/pc-bucket; $BD_ALLOW; $ROT; backup_dest_egress_resolve")"; bd_allow_off
case "$OUT" in *"addresses rotate"*"its port is 9000 (refused)"*"rc=1") t_pass "backup egress: rotating addresses on a port other than 443 → refused" ;; *) t_fail "rotating 9000: $OUT" ;; esac
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.example.org/pc-bucket; backup_dest_egress_resolve; echo \"MODE=\$_BD_EGRESS_MODE \$_BD_EGRESS_CIDRS\"")"
expect_eq "backup egress: a stable name → pinned /32s" "$(printf '%s\n' "$OUT" | grep '^MODE=')" "MODE=pinned 203.0.113.50/32"
OUT="$(rm -f "$BD/rot"; bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.amazonaws.com/pc-bucket; $BD_ALLOW; $ROT; _ha_backup_egress longhorn-system backup-destination-manager '{\"matchLabels\":{\"app\":\"longhorn-manager\"}}'")"; bd_allow_off
expect_eq "_ha_backup_egress (public): the exact pods, 0.0.0.0/0 minus the private ranges, 443" \
  "$(grep -v '^---$' "$KS/kubectl-stdin" | jq -c 'select(.kind? == "NetworkPolicy") | [.spec.podSelector, .spec.egress[0].to[0].ipBlock.cidr, (.spec.egress[0].to[0].ipBlock.except | index("10.0.0.0/8") != null), .spec.egress[0].ports]')" \
  '[{"matchLabels":{"app":"longhorn-manager"}},"0.0.0.0/0",true,[{"protocol":"TCP","port":443}]]'
# Security review: the opt-in is set's flag, stored in .env, shown by show and status.
mkdir -p "$BD/root3/secrets"; printf 'CONTAINER_RUNTIME=kubernetes\n' > "$BD/root3/.env"
rm -f "$BD/rot"; OUT="$(printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "$BD_KEY" "$BD_SEC" | BD_ROOT="$BD/root3" bdk "$ROT; backup_dest_set https://s3.amazonaws.com/pc-bucket true; backup_dest_show")"
expect_eq "backup destination set --allow-rotating-addresses: PORTCULLIS_BACKUP_ALLOW_ROTATING=true in .env, shown by show" \
  "$(grep -c '^PORTCULLIS_BACKUP_ALLOW_ROTATING=true$' "$BD/root3/.env"):$(printf '%s\n' "$OUT" | grep -c 'rotating addresses: allowed'):$(printf '%s' "$OUT" | tail -n1)" "1:1:rc=0"
rm -f "$BD/rot" "$BD/root3/secrets/backup-destination.env"; printf 'CONTAINER_RUNTIME=kubernetes\n' > "$BD/root3/.env"
OUT="$(printf 'AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n' "$BD_KEY" "$BD_SEC" | BD_ROOT="$BD/root3" bdk "$ROT; backup_dest_set https://s3.amazonaws.com/pc-bucket false")"
expect_eq "backup destination set without the flag: a rotating destination refused, nothing written" \
  "$(printf '%s' "$OUT" | grep -c 'with --allow-rotating-addresses'):$(test -e "$BD/root3/secrets/backup-destination.env" && echo file || echo nofile):$(grep -c BACKUP_S3_URL "$BD/root3/.env" || true)" "1:nofile:0"
OUT="$( ( _st_line() { echo "$1 $2"; }; kube_backup_status_lines '{"egress":"public","allow_rotating":true,"cnpg":null,"longhorn":null}' ) )"
expect_eq "status: the rotating opt-in is shown" "$(printf '%s\n' "$OUT" | grep -c 'rotating addresses allowed (PORTCULLIS_BACKUP_ALLOW_ROTATING=true')" 1
# Security review: the instance-backup move never unpacks on the host (an
# archive with a symlink member pointing outside, and a file through it).
MV="$WORK/ibmove"; rm -rf "$MV"; mkdir -p "$MV/src/backups" "$MV/outside" "$MV/b"
ln -s "$MV/outside" "$MV/src/backups/evil"; tar -czf "$MV/b/hub_data.tar.gz" -C "$MV/src" ./backups
rm -rf "$MV/src"; mkdir -p "$MV/src2/backups/evil"; printf x > "$MV/src2/backups/evil/pwn"
tar -czf "$MV/b/hub_data2.tar.gz" -C "$MV/src2" ./backups && cat "$MV/b/hub_data2.tar.gz" >> "$MV/b/hub_data.tar.gz"
OUT="$(kt "_kube_restore_volume() { :; }; _kube_volume_exists() { :; }; _kube_empty_volume() { :; }; _kube_helper_done() { :; }
  _kube_helper_pod() { case \"\$1\" in hub-state*) echo src-pod ;; *) echo dst-pod ;; esac; }
  kube_ctl() { echo \"K \$*\" >> '$MV/calls'; case \"\$*\" in *'tar -cf -'*) printf TARSTREAM ;; *'tar -xf -'*) cat > '$MV/streamed' ;;
    *'du -sk'*) echo \"\${MV_DU:-100} /vol/backups\" ;; *'get pvc'*) printf 1Gi ;; esac; return 0; }
  cd '$MV' && _kube_restore_volume_t26 '$MV/b' hub_data 10001 10001")"
expect_eq "instance-backup move: pod to pod (hub-state's tar → hub-backups' tar), nothing unpacked on the host, a symlink member can't reach a host path" \
  "$(printf '%s' "$OUT" | tail -n1):$(grep -c 'exec src-pod -- tar -cf - -C /vol/backups .' "$MV/calls"):$(grep -c 'exec -i dst-pod -- sh -c m="$(stat -c %a /vol)" && tar -xf - -C /vol && chmod "$m" /vol' "$MV/calls"):$(cat "$MV/streamed"):$(test -e "$MV/outside/pwn" && echo PWNED || echo clean):$(declare -f _kube_restore_volume_t26 | grep -c 'tar -x[a-z]*f "\$dir' || true)" \
  "rc=0:1:1:TARSTREAM:clean:0"
# The first base backup after the release (found in e2e-k3s: not immediate).
kbar() { kt "KBAR_VF=\$(mktemp); echo '{\"backup\":{\"cnpg\":{\"enabled\":$1}}}' > \$KBAR_VF; kube_values_file() { echo \$KBAR_VF; }; KUBE_PG_ARCHIVE_WAIT=5
  kube_ctl() { echo \"K \$*\" >> '$BD/kbar'; case \"\$*\" in *'get cluster.postgresql.cnpg.io'*) echo '{\"spec\":{\"instances\":1},\"status\":{\"readyInstances\":1,\"conditions\":[{\"type\":\"ContinuousArchiving\",\"status\":\"$2\"}]}}' ;;
    *'get backups'*) echo '{\"items\":$3}' ;; 'create -f '*) jq -c . \"\${@: -1}\" >> '$BD/kbar' ;; esac; }; kube_backup_after_release"; }
rm -f "$BD/kbar"; OUT="$(kbar true True '[{"spec":{"method":"plugin","cluster":{"name":"portcullis-pg"}},"status":{"phase":"failed"}}]')"
expect_eq "kube_backup_after_release: archiving and no completed / running plugin Backup → one Backup (method plugin) made" \
  "$(grep -c '^{"apiVersion":"postgresql.cnpg.io/v1","kind":"Backup".*"spec":{"method":"plugin","pluginConfiguration":{"name":"barman-cloud.cloudnative-pg.io"},"cluster":{"name":"portcullis-pg"}}}$' "$BD/kbar"):$(printf '%s' "$OUT" | tail -n1)" "1:rc=0"
rm -f "$BD/kbar"; OUT="$(kbar true True '[{"spec":{"method":"plugin","cluster":{"name":"portcullis-pg"}},"status":{"phase":"completed"}}]')"
expect_eq "kube_backup_after_release: a completed plugin Backup → none made" "$(grep -c '"kind":"Backup"' "$BD/kbar" || true)" 0
rm -f "$BD/kbar"; OUT="$(kbar true False '[]')"
case "$OUT" in *"ContinuousArchiving is False"*"rc=0") t_pass "kube_backup_after_release: not archiving → a warning, no Backup, up goes on" ;; *) t_fail "after release not archiving: $OUT" ;; esac
rm -f "$BD/kbar"; OUT="$(kbar false True '[]')"
expect_eq "kube_backup_after_release: no archive → nothing asked" "$(test -e "$BD/kbar" && echo asked || echo none)" none
expect_eq "rt_up: the first base backup after the release (and Vault's voters)" \
  "$(declare -f _rtk_up | awk '/kube_helm upgrade/ {h=NR} /kube_backup_after_release/ {b=NR} END {print (h && b > h) ? "after" : "no"}')" after
# Review NM5: only this Cluster's Backups count; finalizing / walArchivingFailing are in progress.
kbar2() { kt "KBAR_VF=\$(mktemp); echo '{\"backup\":{\"cnpg\":{\"enabled\":true,\"serverName\":\"portcullis-pg-0b0e2b3c\"}}}' > \$KBAR_VF; kube_values_file() { echo \$KBAR_VF; }
  KUBE_PG_ARCHIVE_WAIT=\${KBAR_WAIT:-5} KUBE_PG_ARCHIVE_FALSE_WAIT=10; sleep() { :; }
  kube_ctl() { echo \"K \$*\" >> '$BD/kbar'; case \"\$*\" in *'get cluster.postgresql.cnpg.io'*) printf '%s' '$1' ;;
    *'get backups'*) echo '{\"items\":$2}' ;; 'create -f '*) jq -c . \"\${@: -1}\" >> '$BD/kbar' ;; esac; }; kube_backup_after_release"; }
KB_CL='{"metadata":{"uid":"u-1","creationTimestamp":"2026-11-20T10:00:00Z"},"spec":{"instances":1},"status":{"readyInstances":1,"conditions":[{"type":"ContinuousArchiving","status":"True"}]}}'
kb_made() { grep -c '"kind":"Backup"' "$BD/kbar" || true; }
KB_B() { local o=""; [ -z "${4:-}" ] || o=',"ownerReferences":[{"kind":"Cluster","uid":"'"$4"'"}]'
  printf '{"metadata":{"creationTimestamp":"%s"%s},"spec":{"method":"plugin","cluster":{"name":"portcullis-pg"}},"status":{"phase":"%s","serverName":"%s"}}' "$1" "$o" "$2" "$3"; }
for ph in finalizing walArchivingFailing running; do
  rm -f "$BD/kbar"; kbar2 "$KB_CL" "[$(KB_B 2026-11-20T11:00:00Z "$ph" portcullis-pg-0b0e2b3c)]" >/dev/null
  expect_eq "kube_backup_after_release: a $ph Backup of this archive → none made (in progress)" "$(kb_made)" 0
done
rm -f "$BD/kbar"; kbar2 "$KB_CL" "[$(KB_B 2026-11-20T11:00:00Z completed portcullis-pg-deadbeef)]" >/dev/null
expect_eq "kube_backup_after_release: a completed Backup of another serverName → the first base backup still made" "$(kb_made)" 1
rm -f "$BD/kbar"; kbar2 "$KB_CL" "[$(KB_B 2026-11-19T11:00:00Z completed portcullis-pg-0b0e2b3c)]" >/dev/null
expect_eq "kube_backup_after_release: a completed Backup older than the Cluster (an earlier incarnation) → made" "$(kb_made)" 1
rm -f "$BD/kbar"; kbar2 "$KB_CL" "[$(KB_B 2026-11-20T11:00:00Z completed portcullis-pg-0b0e2b3c u-0)]" >/dev/null
expect_eq "kube_backup_after_release: a completed Backup owned by another Cluster uid → made" "$(kb_made)" 1
rm -f "$BD/kbar"; kbar2 "$KB_CL" "[$(KB_B 2026-11-20T11:00:00Z completed portcullis-pg-0b0e2b3c u-1)]" >/dev/null
expect_eq "kube_backup_after_release: a completed Backup of this Cluster and archive → none made" "$(kb_made)" 0
rm -f "$BD/kbar"; OUT="$(KBAR_WAIT=300 kbar2 '{"spec":{"instances":1},"status":{"readyInstances":1,"conditions":[{"type":"ContinuousArchiving","status":"False","message":"unexpected failure invoking barman-cloud-wal-archive"}]}}' '[]')"
expect_eq "kube_backup_after_release: ContinuousArchiving already False → the wait ends early (not 300 s) with its message, no Backup" \
  "$(grep -c 'get cluster.postgresql.cnpg.io' "$BD/kbar"):$(printf '%s\n' "$OUT" | grep -c "ContinuousArchiving is False (unexpected failure invoking barman-cloud-wal-archive)"):$(kb_made):$(printf '%s' "$OUT" | tail -n1)" "2:1:0:rc=0"
# Review NM5 / NM1: status — no base backup yet is a warning naming the next one; the plugin down while the Cluster names it is a problem.
OUT="$( ( _st_line() { echo "$1 $2"; }; kube_backup_status_lines '{"egress":"pinned","cnpg":{"plugin":true,"plugin_ready":true,"archiving":true,"last_backup":"Unknown","next_base":"2026-11-22T03:15:00Z","message":""},"longhorn":null}'; echo "rc=$?" ) )"
expect_eq "status: WAL archived, no base backup yet → a warning naming when it's taken (not ok, not a problem)" \
  "$(printf '%s\n' "$OUT" | grep -c '^warn backup destination: Postgres archives WAL but has no base backup yet .*runs at 2026-11-22T03:15:00Z'):$(printf '%s\n' "$OUT" | grep -c '^ok '):$(printf '%s' "$OUT" | tail -n1)" "1:0:rc=0"
OUT="$( ( _st_line() { echo "$1 $2"; }; kube_backup_status_lines '{"egress":"pinned","cnpg":{"plugin":true,"plugin_ready":false,"archiving":true,"last_backup":"True","message":""},"longhorn":null}'; echo "rc=$?" ) )"
expect_eq "status: the Cluster archives through a plugin that isn't available → a problem of its own" \
  "$(printf '%s\n' "$OUT" | grep -c "^fail backup destination: the Postgres Cluster archives through the barman-cloud plugin, which isn't available"):$(printf '%s' "$OUT" | tail -n1)" "1:rc=1"
KBS="$BD/kbs.json"; echo '{"backup":{"cnpg":{"enabled":true}}}' > "$KBS"
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9/pc-bucket; kube_values_file() { echo '$KBS'; }; _kube_barman_ready() { return 1; }
  kube_ctl() { case \"\$*\" in *'get cluster.postgresql.cnpg.io'*) echo '{\"spec\":{\"plugins\":[{\"name\":\"barman-cloud.cloudnative-pg.io\"}]},\"status\":{\"conditions\":[{\"type\":\"ContinuousArchiving\",\"status\":\"True\"},{\"type\":\"LastBackupSucceeded\",\"status\":\"True\"}]}}' ;; *) return 1 ;; esac; }
  kube_backup_status_json")"
expect_eq "status json: the plugin down → the Cluster is still read (plugin named, not ready)" \
  "$(printf '%s\n' "$OUT" | head -n1 | jq -c '[.cnpg.plugin, .cnpg.plugin_ready, .cnpg.archiving, .cnpg.last_backup]')" '[true,false,true,"True"]'
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9/pc-bucket; kube_values_file() { echo '$KBS'; }; _kube_barman_ready() { return 1; }; kube_ctl() { return 1; }; kube_backup_status_json")"
expect_eq "status json: the plugin down and the Cluster unreadable while the release archives → unreadable (a problem)" "$(printf '%s\n' "$OUT" | head -n1 | jq -c .cnpg)" '{"unreadable":true}'
# Found in e2e-k3s: the plugin scaled to 0 isn't ready (0 of 0 available).
for rep in 0:0 1:1 1:0; do
  kbr_r="${rep%:*}" kbr_a="${rep#*:}"
  OUT="$(kt "kube_ctl() { echo '{\"metadata\":{\"generation\":2},\"spec\":{\"replicas\":$kbr_r},\"status\":{\"observedGeneration\":2,\"availableReplicas\":$kbr_a,\"updatedReplicas\":$kbr_a}}'; }; _kube_barman_ready && echo READY || echo NOT")"
  expect_eq "_kube_barman_ready: $kbr_r replica(s), $kbr_a available → $( [ "$kbr_a" = 1 ] && echo ready || echo not ready)" "$(printf '%s\n' "$OUT" | head -n1)" "$( [ "$kbr_a" = 1 ] && echo READY || echo NOT)"
done
# Review NM3: the opt-in is .env's only.
rm -f "$BD/rot"; OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.us-east-1.amazonaws.com/pc-bucket PORTCULLIS_BACKUP_ALLOW_ROTATING=true; $ROT; backup_dest_egress_resolve")"
case "$OUT" in *"PORTCULLIS_BACKUP_ALLOW_ROTATING in the environment (true) differs from .env (empty)"*"rc=1") t_pass "backup egress: the opt-in from the process environment alone → refused (.env only)" ;; *) t_fail "env opt-in: $OUT" ;; esac
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9/pc-bucket PORTCULLIS_BACKUP_ALLOW_ROTATING=true; _kube_barman_ready() { return 1; }; kube_ctl() { return 1; }; kube_backup_status_json")"
expect_eq "status json: allow_rotating is .env's, not the environment's" "$(printf '%s\n' "$OUT" | head -n1 | jq -c .allow_rotating)" false
expect_eq "restore keeps this host's PORTCULLIS_BACKUP_ALLOW_ROTATING (a kubernetes key)" "$(case " $(kt 'echo $RESTORE_KUBE_KEY_NAMES' | tr '\n' ' ') " in *" PORTCULLIS_BACKUP_ALLOW_ROTATING "*) echo kept ;; *) echo no ;; esac)" kept
RK="$WORK/rkeys"; rm -rf "$RK"; mkdir -p "$RK"; printf 'CONTAINER_RUNTIME=kubernetes\nPORTCULLIS_BACKUP_ALLOW_ROTATING=true\n' > "$RK/.env"
OUT="$(kt "export PORTCULLIS_ROOT='$RK'; RESTORE_RUNTIME=kubernetes RESTORE_KUBE_KEYS=\$'PORTCULLIS_KUBE_CONTEXT=ci\n'; _restore_runtime_keys")"
expect_eq "restore: the backup's opt-in dropped (this host's is off), with a line naming it" \
  "$(grep -c '^PORTCULLIS_BACKUP_ALLOW_ROTATING=true' "$RK/.env" || true):$(printf '%s\n' "$OUT" | grep -c "The backup's PORTCULLIS_BACKUP_ALLOW_ROTATING=true isn't kept")" "0:1"
printf 'CONTAINER_RUNTIME=kubernetes\n' > "$RK/.env"
OUT="$(kt "export PORTCULLIS_ROOT='$RK'; RESTORE_RUNTIME=kubernetes RESTORE_KUBE_KEYS=\$'PORTCULLIS_BACKUP_ALLOW_ROTATING=true\n'; _restore_runtime_keys")"
expect_eq "restore: this host's opt-in kept, with a line naming it" \
  "$(grep -c '^PORTCULLIS_BACKUP_ALLOW_ROTATING=true$' "$RK/.env"):$(printf '%s\n' "$OUT" | grep -c "Kept this host's PORTCULLIS_BACKUP_ALLOW_ROTATING=true")" "1:1"
# Review NM4: the TTL too long for the probe window → can't tell (the opt-in, an IP or a short TTL needed).
OUT="$(BD_LONG=true BD_TTL=300 bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.example.org/pc-bucket; backup_dest_egress_resolve")"
case "$OUT" in *"TTL of 300s, too long to tell"*"can't tell; addresses may rotate"*"--allow-rotating-addresses"*"rc=1") t_pass "backup egress: a TTL longer than the probe window → can't tell, refused without the opt-in" ;; *) t_fail "long ttl: $OUT" ;; esac
OUT="$(BD_LONG=true BD_TTL=300 bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.example.org/pc-bucket; $BD_ALLOW; backup_dest_egress_resolve; echo MODE=\$_BD_EGRESS_MODE")"; bd_allow_off
expect_eq "backup egress: a TTL longer than the window with the opt-in → public" "$(printf '%s\n' "$OUT" | grep '^MODE=')" "MODE=public"
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9/pc-bucket; _backup_dest_dns_probe() { echo PROBED; }; backup_dest_egress_resolve; echo MODE=\$_BD_EGRESS_MODE")"
expect_eq "backup egress: an IPv4 literal → pinned, no DNS probe" "$(printf '%s\n' "$OUT" | grep -c PROBED):$(printf '%s\n' "$OUT" | grep '^MODE=')" "0:MODE=pinned"
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.example.org/pc-bucket; _backup_dest_dns_probe() { return 1; }; backup_dest_egress_resolve")"
case "$OUT" in *"couldn't be looked up from inside the cluster (CoreDNS)"*"rc=1") t_pass "backup egress: the in-cluster probe failing → refused" ;; *) t_fail "probe fails: $OUT" ;; esac
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.example.org/pc-bucket; _kube_image_of() { echo gg@sha256:x; }; _kube_helper_pod() { echo \"POD \$*\" >> '$BD/probe'; echo dns-pod; }; _kube_helper_done() { echo \"DONE \$1\" >> '$BD/probe'; }
  kube_ctl() { echo \"K \${*:1:10} | \${*: -4}\" >> '$BD/probe'; [ \"\${11}\" != \"\$_BD_DNS_PROBE_PY\" ] || echo SRC-OK >> '$BD/probe'; echo '{\"lookups\":[{\"ips\":[\"203.0.113.50\"],\"ttl\":5}],\"long\":false}'; }; unset -f _backup_dest_dns_probe; . '$HERE/../scripts/lib/ha.sh'; _backup_dest_dns_probe s3.example.org")"; PRB="$(cat "$BD/probe" 2>/dev/null)"; rm -f "$BD/probe"
expect_eq "the DNS probe: a restricted helper pod (nobody, no volume) of group-gate's image, the Python on exec, the pod removed" \
  "$(printf '%s\n' "$PRB" | grep -c '^POD  65534:65534 ro gg@sha256:x backup-dns-probe$'):$(printf '%s\n' "$PRB" | grep -c '^K -n portcullis exec dns-pod -- env PYTHONDONTWRITEBYTECODE=1 python3 -I -c | s3.example.org 150 5 0$'):$(printf '%s\n' "$PRB" | grep -c '^SRC-OK$'):$(printf '%s\n' "$PRB" | grep -c '^DONE dns-pod$')" "1:1:1:1"
# The probe's Python against a fake DNS server (UDP): stable, rotating, a long TTL.
PRD="$WORK/dnsprobe"; rm -rf "$PRD"; mkdir -p "$PRD"; echo 'nameserver 127.0.0.1' > "$PRD/resolv"
cat > "$PRD/fakedns.py" <<'FDNS'
import itertools, socket, struct, sys
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.bind(("127.0.0.1", 0))
open(sys.argv[1], "w").write(str(sock.getsockname()[1]))
ttl = int(sys.argv[2]); sets = itertools.cycle([s.split(",") for s in sys.argv[3].split(";")])
while True:
    data, addr = sock.recvfrom(512)
    i = 12
    while data[i]:
        i += data[i] + 1
    ips = next(sets)
    ans = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip) for ip in ips)
    sock.sendto(data[:2] + struct.pack(">HHHHH", 0x8180, 1, len(ips), 0, 0) + data[12:i + 5] + ans, addr)
FDNS
prb() { rm -f "$PRD/port"; python3 "$PRD/fakedns.py" "$PRD/port" "$1" "$2" & local p=$! i
  for i in 1 2 3 4 5 6 7 8 9 10; do [ -s "$PRD/port" ] && break; sleep 0.2; done
  (cd "$PRD" && python3 -I -c "$(kt 'printf "%s" "$_BD_DNS_PROBE_PY"' | sed '$d')" s3.example.org "$3" 3 0 "$PRD/resolv" "$(cat "$PRD/port")"); kill "$p" 2>/dev/null; wait "$p" 2>/dev/null || true; }
expect_eq "DNS probe (Python): a stable set → every lookup the same, each past the TTL" "$(prb 0 '198.51.100.7,198.51.100.8' 30 | jq -c '[(.lookups | length), (.lookups | map(.ips) | unique), .long]')" '[3,[["198.51.100.7","198.51.100.8"]],false]'
expect_eq "DNS probe (Python): a rotating set → stops at the first change" "$(prb 0 '198.51.100.7;198.51.100.9' 30 | jq -c '[(.lookups | length), .lookups[1].ips, .long]')" '[2,["198.51.100.9"],false]'
expect_eq "DNS probe (Python): a TTL longer than the window → long after one lookup" "$(prb 300 '198.51.100.7' 30 | jq -c '[(.lookups | length), .lookups[0].ttl, .long]')" '[1,300,true]'
# Review NM2: public mode excepts the VPN subnet (custom), the Hub's Local
# networks / provider ranges, the server's public addresses and the special-purpose ranges.
mkdir -p "$BD/root/secrets/domains"; printf 'DOMAINS_PUBLIC_IPV4=203.0.113.77\n' > "$BD/root/secrets/domains/public-ips.env"; rm -f "$BD/root/secrets/kube/backup-egress-hub-ranges"
rm -f "$BD/rot"; OUT="$(BD_HOSTINFO='{"local_networks":["10.0.0.0/8","81.2.3.0/24","2001:db8::/32"],"provider_ranges":["45.1.0.0/16"]}' bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.amazonaws.com/pc-bucket PORTCULLIS_VPN_SUBNET=44.10.0.0/22 PORTCULLIS_MAIL_PUBLIC_IPV4=192.0.2.99; $BD_ALLOW; $ROT; backup_dest_egress_resolve; printf '%s\n' \"\$_BD_EGRESS_EXCEPT\"")"; bd_allow_off
expect_eq "backup egress (public): a custom VPN subnet, the Hub's Local networks / provider ranges, the public IPv4s and every special-purpose range excepted; IPv6 skipped" \
  "$(for c in 44.10.0.0/22 81.2.3.0/24 45.1.0.0/16 203.0.113.77/32 192.0.2.99/32 198.51.100.1/32 192.0.0.0/24 192.0.2.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 192.88.99.0/24 224.0.0.0/4 240.0.0.0/4 0.0.0.0/8; do printf '%s\n' "$OUT" | grep -qx "$c" || echo "missing $c"; done)$(printf '%s\n' "$OUT" | grep -c ':' || true):$(printf '%s' "$OUT" | tail -n1)" "0:rc=0"
expect_eq "backup egress (public): the Hub's ranges kept for an up with the Hub at 0" "$(tr '\n' ' ' < "$BD/root/secrets/kube/backup-egress-hub-ranges")" "10.0.0.0/8 81.2.3.0/24 2001:db8::/32 45.1.0.0/16 "
rm -f "$BD/rot"; OUT="$(BD_HOSTINFO=fail bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.amazonaws.com/pc-bucket; $BD_ALLOW; $ROT; backup_dest_egress_resolve; printf '%s\n' \"\$_BD_EGRESS_EXCEPT\"")"; bd_allow_off
expect_eq "backup egress (public): the Hub not answering → its ranges as last read, said so" \
  "$(printf '%s\n' "$OUT" | grep -cx '81.2.3.0/24'):$(printf '%s\n' "$OUT" | grep -c "the Hub didn't answer hub vpn host-info"):$(printf '%s' "$OUT" | tail -n1)" "1:1:rc=0"
rm -f "$BD/rot" "$BD/root/secrets/kube/backup-egress-hub-ranges"; OUT="$(BD_HOSTINFO=fail bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.amazonaws.com/pc-bucket; $BD_ALLOW; $ROT; backup_dest_egress_resolve")"; bd_allow_off
case "$OUT" in *"Local networks and wired-VPN provider ranges can't be read"*"(refused)"*"rc=1") t_pass "backup egress (public): the Hub's ranges never read and the Hub not answering → refused" ;; *) t_fail "no hub ranges: $OUT" ;; esac
rm -f "$BD/rot"; OUT="$(BD_HOSTINFO='{"local_networks":["81.2.3.0/33"],"provider_ranges":[]}' bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.amazonaws.com/pc-bucket; $BD_ALLOW; $ROT; backup_dest_egress_resolve")"; bd_allow_off
case "$OUT" in *"81.2.3.0/33 (the VPN subnet or a Hub Local network / provider range) isn't an IPv4 CIDR"*"rc=1") t_pass "backup egress (public): an invalid Hub range → refused" ;; *) t_fail "bad hub range: $OUT" ;; esac
rm -f "$BD/root/secrets/domains/public-ips.env" "$BD/root/secrets/kube/backup-egress-hub-ranges"
# Review NN7: one resolution per run (Longhorn's and CloudNativePG's policies the same).
CNT="getent() { n=\$(cat '$BD/cnt' 2>/dev/null || echo 0); echo \$((n + 1)) > '$BD/cnt'; echo '203.0.113.50 STREAM'; }"
rm -f "$BD/cnt"; OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.example.org/pc-bucket; $CNT; backup_dest_egress_resolve; f=\$(mktemp); echo '{}' > \$f; _kube_barman_ready() { return 0; }; kube_backup_values \$f; jq -c .backup.cnpg.endpointCIDRs \$f")"
expect_eq "kube_backup_values: the run's resolution reused (one probe of 5 lookups), the same /32s" "$(cat "$BD/cnt"):$(printf '%s\n' "$OUT" | head -n1)" '5:["203.0.113.50/32"]'
# Review NN2: the old namespace-wide policy goes before anything can refuse.
rm -f "$BD/rot" "$BD/lh"; OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.amazonaws.com/pc-bucket; $ROT
  kube_backup_destination_sync() { echo SYNC >> '$BD/lh'; }; kube_ctl() { echo \"K \$*\" >> '$BD/lh'; return 0; }; ha_longhorn_backup_target")"
expect_eq "ha_longhorn_backup_target: a rotating destination without the opt-in fails, the old policy already deleted first" \
  "$(head -n2 "$BD/lh" | sed -n 2p):$(printf '%s' "$OUT" | tail -n1)" "K -n longhorn-system delete networkpolicy backup-destination --ignore-not-found:rc=1"
# Review NM1: the CNPG namespace (operator + plugin) is judged for crashes too.
OUT="$(kt "kube_ctl() { echo \"\$2\" >> '$BD/crash'; echo '{\"items\":[]}'; }; kube_crashing_json")"; CR="$(sort -u "$BD/crash" | tr '\n' ' ')"; rm -f "$BD/crash"
expect_eq "kube_crashing_json: the core, apps and cnpg-system namespaces" "$CR:$(printf '%s\n' "$OUT" | head -n1)" "cnpg-system portcullis portcullis-apps :[]"
# Security review: empty / invalid API endpoints or node addresses refuse.
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9/pc-bucket PORTCULLIS_KUBE_API_ENDPOINTS=; backup_dest_cidrs")"
case "$OUT" in *"PORTCULLIS_KUBE_API_ENDPOINTS unknown: the backup destination can't be checked (refused)"*"rc=1") t_pass "backup_dest_cidrs: no API endpoints → refused" ;; *) t_fail "no api: $OUT" ;; esac
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9/pc-bucket PORTCULLIS_KUBE_API_ENDPOINTS='10.1.0.999:6443'; backup_dest_cidrs")"
case "$OUT" in *"the cluster address 10.1.0.999"*"isn't an IPv4 address"*"rc=1") t_pass "backup_dest_cidrs: an API endpoint that isn't an IPv4 → refused" ;; *) t_fail "bad api: $OUT" ;; esac
OUT="$(BD_NODES='198.51.100.1 node-x' bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9/pc-bucket; backup_dest_cidrs")"
case "$OUT" in *"the cluster address node-x"*"rc=1") t_pass "backup_dest_cidrs: a node address that isn't an IPv4 → refused" ;; *) t_fail "bad node: $OUT" ;; esac
# Review I1 / I3: status — not archiving, Longhorn unavailable, the public-egress notice.
OUT="$( ( _st_line() { echo "$1 $2"; }; kube_backup_status_lines '{"egress":"public","cnpg":{"plugin":true,"plugin_ready":true,"archiving":false,"last_backup":"True","message":"WAL upload failed"},"longhorn":{"available":false}}'; echo "rc=$?" ) )"
expect_eq "status: Postgres not archiving and Longhorn's target unavailable are problems; public egress a notice" \
  "$(printf '%s\n' "$OUT" | grep -c '^fail backup destination: Postgres isn.t archiving (WAL upload failed)'):$(printf '%s\n' "$OUT" | grep -c '^fail backup destination: Longhorn'):$(printf '%s\n' "$OUT" | grep -c '^warn backup egress: any public address on 443 (the destination.s addresses rotate)'):$(printf '%s\n' "$OUT" | tail -n1)" "1:1:1:rc=1"
OUT="$( ( _st_line() { echo "$1 $2"; }; kube_backup_status_lines '{"egress":"pinned","cnpg":{"plugin":true,"plugin_ready":true,"archiving":true,"last_backup":"True","message":""},"longhorn":{"available":true}}'; echo "rc=$?" ) )"
expect_eq "status: archiving + an available target → ok" "$(printf '%s\n' "$OUT" | grep -c '^ok '):$(printf '%s\n' "$OUT" | tail -n1)" "2:rc=0"
expect_eq "status runs the backup destination's check on Kubernetes" "$(grep -c 'kube_backup_status_lines' "$HERE/../scripts/lib/status.sh")" 2
# Security ruling: the backup egress reaches exactly the endpoint, from the exact pods.
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.ci.invalid/pc-bucket; getent() { [ \"\$1 \$2\" = 'ahostsv4 s3.ci.invalid' ] && printf '198.51.100.20 STREAM s3.ci.invalid\n198.51.100.21 STREAM\n198.51.100.20 DGRAM\n'; }; backup_dest_cidrs")"
expect_eq "backup_dest_cidrs: a host name resolved now, each IPv4 a /32, unique" "$(printf '%s\n' "$OUT" | tr '\n' ' ')" "198.51.100.20/32 198.51.100.21/32 rc=0 "
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.ci.invalid/pc-bucket; getent() { return 2; }; backup_dest_cidrs")"
case "$OUT" in *"doesn't resolve to an IPv4 address"*"rc=1") t_pass "backup_dest_cidrs: an unresolvable endpoint is refused (no policy)" ;; *) t_fail "backup_dest_cidrs unresolvable: $OUT" ;; esac
for ip in 10.42.0.7 10.43.0.1 10.215.0.2 198.51.100.1 10.1.0.4; do
  OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://$ip/pc-bucket PORTCULLIS_KUBE_NODE_ADDRESSES=198.51.100.1; backup_dest_cidrs")"
  case "$OUT" in *"resolves inside the cluster ($ip)"*"rc=1") t_pass "backup_dest_cidrs: an endpoint inside the cluster ($ip) is refused" ;; *) t_fail "backup_dest_cidrs in-cluster $ip: $OUT" ;; esac
done
# Security review (fail closed): unknown ranges / nodes, a bad range or a bad
# resolved address refuse instead of passing.
for c in "PORTCULLIS_POD_CIDR=|POD_CIDR / PORTCULLIS_SERVICE_CIDR unknown" "PORTCULLIS_SERVICE_CIDR=|POD_CIDR / PORTCULLIS_SERVICE_CIDR unknown" \
         "PORTCULLIS_POD_CIDR=10.42.0.0/99|isn't an IPv4 CIDR" "PORTCULLIS_SERVICE_CIDR=bogus|isn't an IPv4 CIDR"; do
  OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9/pc-bucket ${c%%|*}; backup_dest_cidrs")"
  case "$OUT" in *"${c#*|}"*"rc=1") t_pass "backup_dest_cidrs: ${c%%|*} → refused" ;; *) t_fail "backup_dest_cidrs ${c%%|*}: $OUT" ;; esac
done
OUT="$(BD_NODES='' bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9/pc-bucket; kube_node_addresses() { :; }; backup_dest_cidrs")"
case "$OUT" in *"the nodes' addresses are unknown"*"rc=1") t_pass "backup_dest_cidrs: no node addresses (none in .env, none from the cluster) → refused" ;; *) t_fail "backup_dest_cidrs no nodes: $OUT" ;; esac
OUT="$(BD_NODES='' bdk "export PORTCULLIS_BACKUP_S3_URL=https://198.51.100.77/pc-bucket; kube_node_addresses() { echo '198.51.100.77 198.51.100.78'; }; backup_dest_cidrs")"
case "$OUT" in *"resolves inside the cluster (198.51.100.77)"*"rc=1") t_pass "backup_dest_cidrs: the nodes from the cluster when .env has none (a node's address refused)" ;; *) t_fail "backup_dest_cidrs node fallback: $OUT" ;; esac
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://s3.ci.invalid/pc-bucket; getent() { echo '999.1.1.1 STREAM s3.ci.invalid'; }; backup_dest_cidrs")"
case "$OUT" in *"isn't an IPv4 address (refused)"*"rc=1") t_pass "backup_dest_cidrs: a resolved address cidr_contains can't judge → refused" ;; *) t_fail "backup_dest_cidrs bad address: $OUT" ;; esac
# Security review: the first version's namespace-wide backup-destination
# policy is deleted by up (kube_sync_prepare_t26 → ha_longhorn_backup_target),
# with a destination before the new ones, and without one.
printf 'LLDAPSEEDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' > "$BD/root/secrets/lldap/key-seed" 2>/dev/null || { mkdir -p "$BD/root/secrets/lldap"; printf 'LLDAPSEEDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' > "$BD/root/secrets/lldap/key-seed"; }
for d in "https://203.0.113.9/pc-bucket" ""; do
  OUT="$(bdk ": > '$KS/kube/ns-longhorn-system.json'; export PORTCULLIS_BACKUP_S3_URL=$d; kube_sync_prepare_t26")"
  expect_eq "up (${d:-no destination}): the old namespace-wide backup-destination policy in longhorn-system is deleted$( [ -n "$d" ] && echo ', before the new ones are applied')" \
    "$(printf '%s\n' "$OUT" | tail -n1):$(awk '/-n longhorn-system delete networkpolicy backup-destination( |$)/ {del=NR} /apply --server-side/ && !a {a=NR} END {print (del && (!a || del < a)) ? "deleted-first" : "no"}' "$KS/kubectl-calls")" "rc=0:deleted-first"
done
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=https://203.0.113.9/pc-bucket; _ha_backup_egress longhorn-system x '{}'")"
case "$OUT" in *"a pod selector naming the component is required"*"rc=1") t_pass "_ha_backup_egress: a namespace-wide selector is refused" ;; *) t_fail "_ha_backup_egress {}: $OUT" ;; esac
OUT="$(bdk "export HUB_DEV=1 PORTCULLIS_BACKUP_S3_URL=http://203.0.113.9/pc-bucket; _ha_backup_egress longhorn-system backup-destination-manager '{\"matchLabels\":{\"app\":\"longhorn-manager\"}}'")"
expect_eq "_ha_backup_egress: the exact pods, the endpoint's /32 and port only" \
  "$(grep -v '^---$' "$KS/kubectl-stdin" | jq -c 'select(.kind? == "NetworkPolicy") | [.spec.podSelector, .spec.egress]')" \
  '[{"matchLabels":{"app":"longhorn-manager"}},[{"to":[{"ipBlock":{"cidr":"203.0.113.9/32"}}],"ports":[{"protocol":"TCP","port":80}]}]]'
OUT="$(bdk "kube_backup_status_record")"
expect_eq "kube_backup_status_record: ConfigMap portcullis-backup-status with last_success (RFC 3339 UTC)" \
  "$(grep -v '^---$' "$KS/kubectl-stdin" | jq -r 'select(.metadata.name? == "portcullis-backup-status") | .data.last_success' | grep -cE '^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$')" 1
expect_eq "backup --offsite records the time for the Hub only after the upload (Kubernetes with a destination)" \
  "$(declare -f backup_offsite | awk '/restic backup failed/ {u=NR} /kube_backup_status_record/ {r=NR} END {print (u && r > u) ? "after" : "no"}')" after
OUT="$(bdk "export PORTCULLIS_BACKUP_S3_URL=; kube_backup_destination_sync")"
expect_eq "kube_backup_destination_sync: no destination → the Secret deleted in cnpg-system and longhorn-system" \
  "$(grep -c 'delete secret backup-destination --ignore-not-found' "$KS/kubectl-calls")" 2
expect_eq "the chart's Hub: HUB_BACKUP_DESTINATION from backup.destination only (never the URL)" \
  "$(grep -c '"HUB_BACKUP_DESTINATION" "value" (ternary "set" "" (.Values.backup.destination | default false))' "$HERE/../charts/portcullis/templates/hub.yaml"):$(grep -c 'destinationPath\|endpointURL\|backup-destination' "$HERE/../charts/portcullis/templates/hub.yaml" || true)" "1:0"
expect_eq "kube_sync_secrets syncs the destination's Secret" "$(declare -f kube_sync_prepare_t26 | grep -c 'kube_backup_destination_sync')" 1

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
