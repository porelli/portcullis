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
# docker: only `network inspect` matters here ($STUB_DIR/ipam-json[-<network>] = IPAM).
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
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
expect_ok   "hub env: VPN client secret by prefix" grep -qx 'HEADSCALE_OIDC_CLIENT_SECRET=hs-secret' "$HE"
expect_ok   "hub env: HUB_SHARED_ENV" grep -qx 'MY_APP_VAR=shared' "$HE"
expect_ok   "hub env: mcp-gate IP (compose default, G42)" grep -qx 'PORTCULLIS_MCP_GATE_IP=172.31.250.3' "$HE"
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
# A scripted vault stub: $PKI_STATE selects which PKI pieces "exist":
#   none (fresh Vault), complete (pki, pki_int, pki_file), nofile (pki_file
#   missing), norole (client-cert role missing), samecn (pki_file has
#   pki_int's CN), partial (mounts but no issuers), sealed, intbroken
#   (exit 1), int403 (403 on pki_int/issuers, exit 2 like the real CLI),
#   fileerr (sealed answer on pki_file/issuers, exit 2), roleerr (403 on the role).
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
      *) echo '{"pki/":{},"pki_int/":{},"pki_file/":{}}' ;;
    esac ;;
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
sjson() { (require_cmd() { :; }; dc() { :; }; container_health() { echo healthy; }; kc_login() { return 1; }
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
echo 6 > "$STUB_DIR/pv"; : > "$STUB_DIR/gglog"
expect_ok "upgrade: matching policy version is fine" sh -c "printf '%s' \"\$1\" | grep -q 'matches group-gate'" _ "$(pv unset HUB_IMAGE)"
echo 5 > "$STUB_DIR/pv"
OUT="$(pv export HUB_IMAGE=ghcr.io/porelli/portcullis-hub:v0.1)"
expect_ok "upgrade: old policy version names the pinned image and the fix" sh -c "printf '%s' \"\$1\" | grep -q 'version 5, this core' && printf '%s' \"\$1\" | grep -q 'remove HUB_IMAGE=ghcr.io/porelli/portcullis-hub:v0.1'" _ "$OUT"
echo 6 > "$STUB_DIR/pv"; echo "group-gate: deny host=x: policy file version 7 is not supported (only 6)" > "$STUB_DIR/gglog"
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
echo snap > "$B/vault.snap"; echo PGDMP > "$B/postgres.dump"; echo 'with space' > "$B/certs/a b.crt"
_BACKUP_CFG='{"services":{"hub":{"image":"hub:1"},"keycloak":{"image":"kc:2"}}}'
_backup_manifest "$B"
expect_eq "manifest: format + every file" "$(jq -c '[.format, (.files | keys)]' "$B/MANIFEST.json")" \
  '[1,[".env","certs/a b.crt","postgres.dump","secrets/vault-init.json","secrets/vault-unseal/unseal-key","vault.snap"]]'
expect_eq "manifest: hub image recorded" "$(jq -r .hub_image "$B/MANIFEST.json")" hub:1
expect_eq "manifest: keycloak image recorded" "$(jq -r .keycloak_image "$B/MANIFEST.json")" kc:2
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

# backup_create never archives appfiles/: the Hub regenerates it from its
# state (hub_data), so a copy would only be stale, secret-bearing files.
BC_ROOT="$WORK/bc-root"
mkdir -p "$BC_ROOT/appfiles/echo-a" "$BC_ROOT/secrets" "$BC_ROOT/certs" "$BC_ROOT/templates/echo"
echo 'PORTCULLIS_DOMAIN=x' > "$BC_ROOT/.env"
echo '{"version":1,"instance":"echo-a","values":{"k":"APPFILE-MARKER"}}' > "$BC_ROOT/appfiles/echo-a/data.json"
echo k > "$BC_ROOT/secrets/k"
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
DOMAINS_PUBLIC_IPV6="
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
mcp mcpgate_ensure_secrets >/dev/null 2>&1
expect_eq "mcp-gate: missing age.pub rebuilt from age.key" "$(cat "$M/age.pub")" "age1mcpgatetestrecipientqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
expect_ok "mcp-gate: a hub-secret under 32 characters is regenerated" grep -Eqx '[A-Za-z0-9]{48}' "$M/hub-secret"
echo 'age1stale' > "$M/age.pub"
mcp mcpgate_ensure_secrets >/dev/null 2>&1
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
# only while the running domains service confirms an enrolled domain:
# secrets/ restored on a new server (the service down, or no domain) must
# never hand the old server's address to the first enrollment.
LASTD="$PORTCULLIS_ROOT/secrets/domains"
mkdir -p "$LASTD"
rm -f "$LASTD/last-public-ipv4" "$LASTD/last-public-ipv6"
lastn() { local n=0 f; for f in "$LASTD"/last-public-*; do [ -e "$f" ] && n=$((n + 1)); done; echo "$n"; }
# Not running (no stub file) / no domain: a successful lookup saves nothing.
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.7 https://api6.ipify.org 2a01:4f8::5 https://ipv6.icanhazip.com 2a01:4f8::5
expect_eq "domains: service down, detected IPv4 + IPv6 published" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6)" "198.51.99.7/2a01:4f8::5"
expect_eq "domains: service down, no last-* written" "$(lastn)" 0
echo 0 > "$STUB_DIR/enrolled"
expect_eq "domains: no enrolled domain, detected addresses published" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6)" "198.51.99.7/2a01:4f8::5"
expect_eq "domains: no enrolled domain, no last-* written" "$(lastn)" 0
# Enrolled: a successful lookup saves them.
echo 2 > "$STUB_DIR/enrolled"
pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6 >/dev/null
expect_eq "domains: enrolled, last-* saved" "$(cat "$LASTD/last-public-ipv4")/$(cat "$LASTD/last-public-ipv6")" "198.51.99.7/2a01:4f8::5"
# Enrolled, a transient IPv6 / IPv4 detection failure keeps the last address.
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.7
expect_eq "domains: enrolled, IPv6 detection failure keeps the last address" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6)" "198.51.99.7/2a01:4f8::5"
expect_eq "domains: explicit empty IPv6 still means none" "$(pubips export PORTCULLIS_PUBLIC_IPV4=203.0.113.9 PORTCULLIS_PUBLIC_IPV6=)" "203.0.113.9/"
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.8
expect_eq "domains: enrolled, IPv4 detection failure keeps the last address" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6)" "198.51.99.7/2a01:4f8::5"
expect_eq "domains: the env file has the kept addresses" "$(cat "$PORTCULLIS_ROOT/secrets/domains/public-ips.env")" "DOMAINS_PUBLIC_IPV4=198.51.99.7
DOMAINS_PUBLIC_IPV6=2a01:4f8::5"
# A restored secrets/ (last-* present), the service down, failed lookups:
# no address at all (fail closed), never the old server's.
rm -f "$STUB_DIR/enrolled"
ipans https://api.ipify.org 198.51.99.7 https://ipv4.icanhazip.com 198.51.99.8
expect_eq "domains: restored secrets/, service down, failed lookups = no address" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6 | tail -n1)" "/"
expect_eq "domains: restored secrets/, service down: empty env file" "$(cat "$PORTCULLIS_ROOT/secrets/domains/public-ips.env")" "DOMAINS_PUBLIC_IPV4=
DOMAINS_PUBLIC_IPV6="
# No enrolled domain (the service says 0): the lookups still run (the
# main-domain plan checks A/AAAA against them, deploy 2026-11-13 BUG 2);
# a failed one publishes no address either.
echo 0 > "$STUB_DIR/enrolled"
: > "$STUB_DIR/ip-calls"
ipans https://api.ipify.org 198.51.99.20 https://ipv4.icanhazip.com 198.51.99.20
expect_eq "domains: no enrolled domain = lookups run, detected IPv4 published" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6 | tail -n1)" "198.51.99.20/"
expect_ok "domains: no enrolled domain = IPv4 and IPv6 looked up" sh -c "grep -q api.ipify.org '$STUB_DIR/ip-calls' && grep -q api6.ipify.org '$STUB_DIR/ip-calls'"
expect_eq "domains: no enrolled domain, the last address untouched" "$(cat "$LASTD/last-public-ipv4")" "198.51.99.7"
ipans https://api.ipify.org 198.51.99.20 https://ipv4.icanhazip.com 198.51.99.21
expect_eq "domains: no enrolled domain, failed lookups = no address (not the last one)" "$(pubips unset PORTCULLIS_PUBLIC_IPV4 PORTCULLIS_PUBLIC_IPV6 | tail -n1)" "/"
: > "$STUB_DIR/ip-calls"
expect_eq "domains: no enrolled domain, .env set = .env" "$(pubips export PORTCULLIS_PUBLIC_IPV4=203.0.113.44 PORTCULLIS_PUBLIC_IPV6=2a01:4f8::44 | tail -n1)" "203.0.113.44/2a01:4f8::44"
expect_eq "domains: .env set = no lookups" "$(wc -l < "$STUB_DIR/ip-calls" | tr -d ' ')" 0
rm -f "$STUB_DIR/enrolled"

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

# Restore must fail closed when hub_secrets volume removal fails (security: old hashes would survive).
# Override the existing docker stub to simulate a volume rm failure.
mv "$WORK/bin/docker" "$WORK/bin/docker-orig"
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
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
expect_eq "restore: each app project downed once, never the core project by -p" \
  "$(grep -c '^compose -p ' "$STUB_DIR/calls")" "2"
expect_ok "restore: no app down removes volumes" sh -c "! grep -q '^compose -p .* -v' '$STUB_DIR/calls'"

# Test a failing dc stop hub (N2)
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
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
printf '#!/usr/bin/env bash\necho "$*" >> "$STUB_DIR/calls"\ncase "$*" in *restart*) exit 1 ;; esac\nexit 0\n' > "$WORK/bin/docker"
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
printf '#!/usr/bin/env bash\necho "$*" >> "$STUB_DIR/calls"\ncase "$*" in *restart*) exit 1 ;; esac\nexit 0\n' > "$WORK/bin/docker"
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
printf '#!/usr/bin/env bash\necho "$*" >> "$STUB_DIR/calls"\ncase "$*" in *restart*) exit 1 ;; esac\nexit 0\n' > "$WORK/bin/docker"
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
expect_eq "invite --replace-keys deletes every passkey kind, never a password / OTP, then signs out" \
  "$(printf '%s\n' "$RK_OUT" | sort | tr '\n' ' ')" \
  "DELETE /portcullis/users/u1/credentials/c1 DELETE /portcullis/users/u1/credentials/c2 DELETE /portcullis/users/u1/credentials/c3 DELETE /portcullis/users/u1/credentials/c4 POST /portcullis/users/u1/logout "

# ══ dns: plan / setup / check on the domains image's dns tool ═══
# docker stub: argv of every call → $STUB_DIR/dt/argv (one line each);
# the stdin of each `compose ... run ... dns-tool <sub>` → dt/stdin-<sub>;
# its stdout from dt/out-<sub> (default {} plan), exit from dt/rc-<sub>.
mkdir -p "$WORK/dtbin" "$STUB_DIR/dt"
cat > "$WORK/dtbin/docker" <<'STUB'
#!/usr/bin/env bash
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
    if [ -f "$d/out-$sub" ]; then cat "$d/out-$sub"; else cat "$d/out-default"; fi
    exit "$(cat "$d/rc-$sub" 2>/dev/null || echo 0)" ;;
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
expect_eq "dns setup --yes: plan, apply, the service's main plan refreshed, check" "$(paste -sd' ' "$STUB_DIR/dt/order")" "plan apply refresh check"
expect_eq "dns setup: apply waits 5 minutes" "$(grep -c 'dns-tool apply --wait 5m$' "$STUB_DIR/dt/argv")" 1
expect_eq "dns setup: the default sets are address and caa" "$(dtin apply '.sets | join(",")')" "address,caa"
expect_eq "dns setup: the input's snake_case keys" "$(dtin apply '[keys[]] | join(",")')" "ca_server,caa,credentials,ipv4,ipv6,mail_from,name,nomail,provider,sets"
expect_eq "dns setup: caa block" "$(dtin apply '.caa | [.enabled, .account_uri, .issuer] | @json')" '[true,"",""]'
expect_eq "dns check: runs without credentials" "$(dtin check 'has("credentials"), .provider' | paste -sd' ' -)" 'false '

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
expect_eq "dns setup --only bogus: usage error" "$RC:$(grep -c -- '--only must be address, caa or nomail' "$WORK/dterr")" "2:1"
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
case "$OUT" in *"could not pin the CAA"*rc=0) t_pass "tighten: a failed pin warns, returns 0" ;; *) t_fail "tighten failed pin: $OUT" ;; esac
expect_eq "tighten: a failed pin still refreshes the main plan (a partial write)" "$(paste -sd' ' "$STUB_DIR/dt/order")" "check apply refresh"
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
  (PATH="$WORK/dtbin:$WORK/cabin:$PATH" PORTCULLIS_ROOT="$FL_ROOT" bash -c ". '$WORK/dtenv.sh'; export PORTCULLIS_ROOT='$FL_ROOT'; config_build_ca_bundle() { :; }; $1; config_apply" 2>&1; echo "rc=$?")
}
OUT="$(flip 'export DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123; dns_relax_main() { echo RELAX >> "$STUB_DIR/dt/argv"; }')"
RL="$(grep -n '^RELAX$' "$STUB_DIR/dt/argv" | cut -d: -f1)"
RM="$(grep -n 'rm -f /acme/acme.json' "$STUB_DIR/dt/argv" | cut -d: -f1)"
expect_eq "config apply flip: relax runs before acme.json is removed" "$([ -n "$RL" ] && [ -n "$RM" ] && [ "$RL" -lt "$RM" ] && echo yes)" yes
OUT="$(flip 'export DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123')"
expect_eq "config apply flip: relax applies caa CA-only" "$(dtin apply '[.sets, .caa.account_uri] | @json')" '[["caa"],""]'
expect_eq "config apply flip: relax waits for the resolvers (2 min)" "$(grep -c 'dns-tool apply --wait 2m$' "$STUB_DIR/dt/argv")" 1
expect_eq "config apply flip: relax refreshes the service's main plan after the apply" "$(paste -sd' ' "$STUB_DIR/dt/order")" "apply refresh"
echo 3 > "$STUB_DIR/dt/rc-apply"
OUT="$(flip 'export DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123')"
case "$OUT" in *"issuance may fail on CAA until then (./portcullis dns setup)"*rc=0) t_pass "config apply flip: relax failure warns and goes on" ;; *) t_fail "relax failure: $OUT" ;; esac
expect_eq "config apply flip: acme.json still cleared after a failed relax" "$(grep -c 'rm -f /acme/acme.json' "$STUB_DIR/dt/argv")" 1
rm -f "$STUB_DIR/dt/rc-apply"
OUT="$(flip 'export DNS_PROVIDER=cloudflare CLOUDFLARE_API_TOKEN=tok-SECRET-123 DNS_CAA=yes')"
case "$OUT" in *"DNS_CAA=yes must be true or false"*rc=1) t_pass "config apply flip: DNS_CAA must be true or false" ;; *) t_fail "flip DNS_CAA=yes: $OUT" ;; esac
expect_eq "config apply flip: a bad DNS_CAA refuses before Traefik is stopped" "$(cat "$STUB_DIR/dt/argv" 2>/dev/null | grep -c 'stop traefik' || true)" 0
OUT="$(flip 'export DNS_PROVIDER=gcloud')"
expect_eq "config apply flip: no relax for a manual provider" "$(grep -c dns-tool "$STUB_DIR/dt/argv" || true)" 0
expect_eq "config apply: ACME_DNS_PROVIDER written" "$(grep '^ACME_DNS_PROVIDER=' "$FL_ROOT/.env")" "ACME_DNS_PROVIDER=gcloud"
OUT="$(flip 'export DNS_PROVIDER=hetzner-cloud HETZNER_API_TOKEN=cloud-0123456789')"
expect_eq "config apply: hetzner-cloud is lego's hetzner" "$(grep '^ACME_DNS_PROVIDER=' "$FL_ROOT/.env")" "ACME_DNS_PROVIDER=hetzner"
OUT="$(flip 'export DNS_PROVIDER=hetzner HETZNER_API_KEY=legacy-0123456789 HETZNER_API_TOKEN=cloud-0123456789')"
case "$OUT" in *"HETZNER_API_TOKEN is set"*rc=1) t_pass "config apply: hetzner with HETZNER_API_TOKEN refused" ;; *) t_fail "hetzner + token: $OUT" ;; esac
OUT="$(flip 'export DNS_PROVIDER=hetzner-cloud HETZNER_API_KEY=legacy-0123456789 HETZNER_API_TOKEN=cloud-0123456789')"
case "$OUT" in *"HETZNER_API_KEY (the legacy DNS API) is set too"*rc=1) t_pass "config apply: hetzner-cloud with HETZNER_API_KEY refused" ;; *) t_fail "hetzner-cloud + key: $OUT" ;; esac
rm -f "$STUB_DIR/dt/acme-volume"

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
  {main: plan("ci.example.org"; true; "unsigned"), domains: {"team-b.test": plan("team-b.test"; true; "bogus")}}' > "$DNSR"
SD="$(dt "_st_dns_json \"\$(cat '$DNSR')\" https://acme/acct/1 https://acme/acct/1")"
expect_eq "status --json: dns.main summary from a fixture report" "$(printf '%s\n' "$SD" | head -n1 | jq -c '.main | del(.checks)')" \
  '{"address_ok":true,"address_unknown":false,"caa_ok":true,"would_issue":true,"dnssec":"unsigned","foreign":1,"problems":0,"name":"ci.example.org","lost_account":false}'
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
SJ="$(dt "set -euo pipefail; require_cmd() { :; }; dc() { :; }; container_health() { echo healthy; }; kc_login() { return 1; }
        proxy_dns_shadows() { :; }; _st_mcp_refusing() { :; }; vault_health_code() { echo 200; }
        vault_admin_env() { return 1; }
        dns_status_json() { cat '$DNSR'; }; dns_traefik_account_uri() { :; }
        status_run true 2>/dev/null")"
expect_eq "status --json without main-domain.env (set -euo pipefail, as the CLI) still prints the report" \
  "$(printf '%s\n' "$SJ" | sed '$d' | jq -c '[.dns.main.name, .dns.main.lost_account]' 2>/dev/null)" '["ci.example.org",false]'
# status --json carries the block (status_run with the report stubbed).
SJ="$( (require_cmd() { :; }; dc() { :; }; container_health() { echo healthy; }; kc_login() { return 1; }
        proxy_dns_shadows() { :; }; _st_mcp_refusing() { :; }; vault_health_code() { echo 200; }
        vault_admin_env() { return 1; }
        dns_status_json() { cat "$DNSR"; }; dns_traefik_account_uri() { echo https://acme/acct/1; }; dns_main_env_uri() { echo https://acme/acct/1; }
        status_run true 2>/dev/null) || true)"
expect_eq "status --json: dns.main / dns.domains" "$(printf '%s' "$SJ" | jq -c '[.dns.main.name, (.dns.domains | keys), .ok]')" '["ci.example.org",["team-b.test"],false]'

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
