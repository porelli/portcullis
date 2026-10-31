#!/usr/bin/env bash
#
# Unit tests for scripts/lib/proxy-network.sh and the revoked-serial sync in
# scripts/lib/vault-common.sh — no Docker/Vault needed: stub `docker` and
# `vault` executables on PATH answer from canned data and log every call.
#
# Run: bash tests/test_shell_libs.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); echo "ok   - $*"; }
bad()  { FAIL=$((FAIL + 1)); echo "FAIL - $*"; }
expect_ok()   { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
expect_fail() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$d"; else ok "$d"; fi; }
expect_eq()   { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }

# ── stub docker ────────────────────────────────────────────
# State lives in $STUB_DIR:
#   ipam            current IPAM of portcullis-proxy (absent = no network)
#   members         `docker ps -aq --filter network=...` output
#   project-/service-/aliases-<cid>   labels / aliases
#   connected-<cid> marker: container attached to portcullis-proxy
# Failure knobs: STUB_FAIL_RM=1, STUB_FAIL_UP=1, STUB_UP_NO_NET=1
mkdir -p "$WORK/bin"
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_DIR/calls"
case "$1 $2" in
  "network inspect")
    [ -f "$STUB_DIR/ipam" ] || exit 1
    cat "$STUB_DIR/ipam"; exit 0 ;;
  "network rm")
    [ "${STUB_FAIL_RM:-0}" = 1 ] && { echo "error: network has active endpoints" >&2; exit 1; }
    rm -f "$STUB_DIR/ipam"; exit 0 ;;
  "network disconnect") rm -f "$STUB_DIR/connected-${*: -1}"; exit 0 ;;
  "network connect")
    [ -f "$STUB_DIR/ipam" ] || exit 1
    touch "$STUB_DIR/connected-${*: -1}"; exit 0 ;;
  "compose up")
    [ "${STUB_UP_NO_NET:-0}" = 1 ] || printf '%s' '172.31.250.0/24|172.31.250.128/25;' > "$STUB_DIR/ipam"
    [ "${STUB_FAIL_UP:-0}" = 1 ] && exit 1
    exit 0 ;;
  "ps -aq") cat "$STUB_DIR/members" 2>/dev/null; exit 0 ;;
esac
if [ "$1" = inspect ]; then
  fmt="$3"; cid="$4"
  case "$fmt" in
    *yes*) [ -f "$STUB_DIR/connected-$cid" ] && echo yes ;;
    *'.Aliases'*) cat "$STUB_DIR/aliases-$cid" 2>/dev/null ;;
    *'.Name'*) echo "/name-$cid" ;;
    *'.Id'*) echo "${cid}0000000000000000" ;;
    *'com.docker.compose.project'*) cat "$STUB_DIR/project-$cid" 2>/dev/null ;;
    *'com.docker.compose.service'*) cat "$STUB_DIR/service-$cid" 2>/dev/null ;;
  esac
  exit 0
fi
exit 0
STUB

# ── stub vault ─────────────────────────────────────────────
# STUB_VAULT_RC / STUB_VAULT_OUT control `vault list` behaviour.
cat > "$WORK/bin/vault" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_DIR/vault-calls"
printf '%s\n' "${STUB_VAULT_OUT:-}"
exit "${STUB_VAULT_RC:-0}"
STUB
chmod +x "$WORK/bin/docker" "$WORK/bin/vault"
export PATH="$WORK/bin:$PATH"
export STUB_DIR="$WORK/stub"
mkdir -p "$STUB_DIR"

# shellcheck source=../scripts/lib/proxy-network.sh
source "$HERE/../scripts/lib/proxy-network.sh"
# shellcheck source=../scripts/lib/vault-common.sh
source "$HERE/../scripts/lib/vault-common.sh"

# ══ proxy-network: IP math / validation ════════════════════
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

# ══ proxy-network: state ═══════════════════════════════════
rm -f "$STUB_DIR/ipam"
expect_eq "state missing" "$(proxy_network_state)" missing
printf '%s' '172.31.250.0/24|172.31.250.128/25;' > "$STUB_DIR/ipam"
expect_eq "state ok" "$(proxy_network_state)" ok
printf '%s' '172.18.0.0/16|;' > "$STUB_DIR/ipam"
expect_eq "state mismatch (docker-assigned subnet)" "$(proxy_network_state)" mismatch
printf '%s' '172.31.250.0/24|;' > "$STUB_DIR/ipam"
expect_eq "state mismatch (no ip_range)" "$(proxy_network_state)" mismatch

# ══ proxy-network: migration ═══════════════════════════════
# grafana + wiki (app projects), core Traefik, and a docker-compose.apps.yml
# container that also belongs to the core project.
reset_net() {
  rm -f "$STUB_DIR"/connected-* "$STUB_DIR/calls"
  printf '%s' '172.18.0.0/16|;' > "$STUB_DIR/ipam"
  for c in aaaaaaaaaaaa bbbbbbbbbbbb cccccccccccc dddddddddddd; do touch "$STUB_DIR/connected-$c"; done
  : > "$STUB_DIR/calls"
}
printf 'aaaaaaaaaaaa\nbbbbbbbbbbbb\ncccccccccccc\ndddddddddddd\n' > "$STUB_DIR/members"
echo portcullis-grafana > "$STUB_DIR/project-aaaaaaaaaaaa"
echo grafana            > "$STUB_DIR/service-aaaaaaaaaaaa"
printf 'portcullis-grafana-grafana-1\ngrafana\naaaaaaaaaaaa\n' > "$STUB_DIR/aliases-aaaaaaaaaaaa"
echo portcullis-wiki    > "$STUB_DIR/project-bbbbbbbbbbbb"
echo wiki               > "$STUB_DIR/service-bbbbbbbbbbbb"
echo portcullis         > "$STUB_DIR/project-cccccccccccc"
echo traefik            > "$STUB_DIR/service-cccccccccccc"
echo portcullis         > "$STUB_DIR/project-dddddddddddd"
echo vault-ui           > "$STUB_DIR/service-dddddddddddd"
APPS="aaaaaaaaaaaa bbbbbbbbbbbb dddddddddddd"
all_connected() { local c; for c in "$@"; do [ -f "$STUB_DIR/connected-$c" ] || return 1; done; }

reset_net
proxy_network_migrate "$WORK/state-dry.tsv" true >/dev/null 2>&1
expect_fail "dry run makes no changes" grep -Eq '^network (rm|disconnect|connect)|^compose up' "$STUB_DIR/calls"
expect_eq "dry run records members" "$(wc -l < "$WORK/state-dry.tsv" | tr -d ' ')" 4

reset_net
expect_ok "migration succeeds" proxy_network_migrate "$WORK/state.tsv"
CALLS="$(cat "$STUB_DIR/calls")"
expect_eq "all 4 containers disconnected" "$(grep -c '^network disconnect -f portcullis-proxy' <<< "$CALLS")" 4
expect_ok "network removed" grep -q '^network rm portcullis-proxy$' <<< "$CALLS"
expect_ok "traefik force-recreated via compose" grep -q '^compose up -d --no-deps --force-recreate traefik$' <<< "$CALLS"
expect_ok "grafana reconnected with its aliases (short id dropped, deduped)" \
  grep -qx 'network connect --alias portcullis-grafana-grafana-1 --alias grafana portcullis-proxy aaaaaaaaaaaa' <<< "$CALLS"
expect_ok "wiki reconnected with service alias" \
  grep -qx 'network connect --alias wiki portcullis-proxy bbbbbbbbbbbb' <<< "$CALLS"
expect_ok "apps.yml container of the core project reconnected" \
  grep -qx 'network connect --alias vault-ui portcullis-proxy dddddddddddd' <<< "$CALLS"
expect_fail "core traefik not reconnected manually" grep -q 'network connect.*cccccccccccc' <<< "$CALLS"
order="$(grep -nE '^(network (disconnect|rm|connect)|compose up)' <<< "$CALLS" | sed -E 's/^([0-9]+):(network )?([a-z]+).*/\3/' | uniq | paste -sd' ' -)"
expect_eq "operation order" "$order" "disconnect rm compose connect"

# network rm fails → everyone (incl. Traefik) back on the OLD network
reset_net
rc=0; STUB_FAIL_RM=1 proxy_network_migrate "$WORK/state.tsv" >/dev/null 2>"$WORK/err" || rc=$?
expect_eq "rm failure returns non-zero" "$rc" 1
# shellcheck disable=SC2086
expect_ok "rm failure: apps reconnected to the old network" all_connected $APPS
expect_ok "rm failure: core Traefik reconnected too" all_connected cccccccccccc
expect_ok "rm failure: old network kept" grep -q '172.18.0.0/16' "$STUB_DIR/ipam"
expect_ok "rm failure: no compose up attempted" bash -c "! grep -q '^compose up' '$STUB_DIR/calls'"
expect_ok "rm failure: recovery help printed" grep -q 'Manual recovery' "$WORK/err"

# compose up fails but compose already created the network → reconnect
reset_net
rc=0; STUB_FAIL_UP=1 proxy_network_migrate "$WORK/state.tsv" >/dev/null 2>"$WORK/err" || rc=$?
expect_eq "traefik failure returns non-zero" "$rc" 1
# shellcheck disable=SC2086
expect_ok "traefik failure, network exists: apps reconnected" all_connected $APPS
expect_ok "traefik failure: recovery help printed" grep -q 'force-recreate traefik' "$WORK/err"

# compose up fails and no network → nothing to reconnect to, loud failure
reset_net
rc=0; STUB_FAIL_UP=1 STUB_UP_NO_NET=1 proxy_network_migrate "$WORK/state.tsv" >/dev/null 2>"$WORK/err" || rc=$?
expect_eq "no-network failure returns non-zero" "$rc" 1
expect_ok "no-network failure: says apps are disconnected" grep -q 'DISCONNECTED' "$WORK/err"
expect_ok "no-network failure: recovery uses the state file" grep -q "proxy_network_reconnect \"$WORK/state.tsv\"" "$WORK/err"
# …and the documented recovery works once the network is back.
printf '%s' '172.31.250.0/24|172.31.250.128/25;' > "$STUB_DIR/ipam"
expect_ok "recovery: proxy_network_reconnect succeeds" proxy_network_reconnect "$WORK/state.tsv"
# shellcheck disable=SC2086
expect_ok "recovery: apps reconnected" all_connected $APPS
: > "$STUB_DIR/calls"
proxy_network_reconnect "$WORK/state.tsv" >/dev/null 2>&1
expect_fail "reconnect is idempotent (no duplicate connects)" grep -q '^network connect' "$STUB_DIR/calls"

# ══ vault-common: write_revoked_serials ════════════════════
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

# ══ setup-vault-pki.sh: idempotency / partial-run handling ═══
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
run_pki() {  # run_pki <state> [args] — prints the script's exit code
  local rc=0
  rm -rf "$WORK/pki-certs" "$STUB_DIR/pki-calls"; touch "$STUB_DIR/pki-calls"
  PATH="$WORK/pki-bin:$PATH" PKI_STATE="$1" VAULT_TOKEN=t CERT_DIR="$WORK/pki-certs" \
    bash "$HERE/../scripts/setup-vault-pki.sh" "${@:2}" >"$WORK/pki-out" 2>&1 || rc=$?
  echo "$rc"
}
expect_eq "pki: fresh install succeeds" "$(run_pki none --with-server-cert)" 0
expect_ok "pki: fresh install generates a root" grep -q 'root/generate/internal' "$STUB_DIR/pki-calls"
expect_eq "pki: server.key is 0600" "$(stat -c %a "$WORK/pki-certs/server.key" 2>/dev/null || stat -f %Lp "$WORK/pki-certs/server.key")" 600
expect_ok "pki: ca-chain written" grep -q INT "$WORK/pki-certs/ca-chain.crt"
expect_eq "pki: complete PKI is a no-op" "$(run_pki complete)" 0
expect_fail "pki: complete PKI → no generate / disable" grep -Eq 'generate|secrets disable' "$STUB_DIR/pki-calls"
expect_ok "pki: complete PKI re-exports missing CA files" test -s "$WORK/pki-certs/ca-chain.crt"
expect_eq "pki: missing role only" "$(run_pki norole)" 0
expect_ok "pki: missing role is recreated" grep -q 'write pki_int/roles/client-cert' "$STUB_DIR/pki-calls"
expect_fail "pki: missing role does NOT wipe the CA" grep -Eq 'generate|secrets disable' "$STUB_DIR/pki-calls"
expect_eq "pki: partial run (no intermediate) is redone" "$(run_pki partial)" 0
expect_ok "pki: partial run wipes pki_int + pki first" grep -q 'secrets disable pki_int' "$STUB_DIR/pki-calls"
expect_eq "pki: sealed Vault fails" "$(run_pki sealed)" 1
expect_fail "pki: sealed Vault → nothing generated" grep -q generate "$STUB_DIR/pki-calls"
expect_eq "pki: read error on issuers fails" "$(run_pki intbroken)" 1
expect_fail "pki: read error → nothing wiped/generated" grep -Eq 'generate|secrets disable' "$STUB_DIR/pki-calls"

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
