#!/usr/bin/env bash
#
# Tests for ./portcullis argument parsing and dispatch: help output, every
# command's --help, usage errors (exit 2), and `init --env-only`. No Docker:
# a stub `docker` on PATH fails loudly if anything tries to use it.
#
# Run: bash tests/test_cli.sh
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
t_pass() { PASS=$((PASS + 1)); echo "ok   - $*"; }
t_fail() { FAIL=$((FAIL + 1)); echo "FAIL - $*"; }
expect_eq() { if [ "$2" = "$3" ]; then t_pass "$1"; else t_fail "$1 (got '$2', want '$3')"; fi; }
file_mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

mkdir -p "$WORK/bin"
cat > "$WORK/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker must not be called: $*" >&2
echo "$*" >> "$STUB_CALLS"
exit 99
STUB
chmod +x "$WORK/bin/docker"
export PATH="$WORK/bin:$PATH" STUB_CALLS="$WORK/docker-calls"
# An empty root: commands must not touch the real checkout.
export PORTCULLIS_ROOT="$WORK/root"
mkdir -p "$PORTCULLIS_ROOT"
unset PORTCULLIS_DOMAIN ACME_EMAIL DNS_PROVIDER CLOUDFLARE_API_TOKEN

# run <args...> — sets RC, OUT (stdout), ERR (stderr). stdin is /dev/null.
run() {
  RC=0
  "$CLI" "$@" >"$WORK/out" 2>"$WORK/err" </dev/null || RC=$?
  OUT="$(cat "$WORK/out")"; ERR="$(cat "$WORK/err")"
}

# ── top-level help / dispatch ──
run help;    expect_eq "help exits 0" "$RC" 0
HELP="$OUT"
run --help;  expect_eq "--help exits 0" "$RC" 0
expect_eq "--help == help" "$OUT" "$HELP"
run;         expect_eq "no command exits 2" "$RC" 2
expect_eq "no command prints help on stderr" "$ERR" "$HELP"
run frobnicate; expect_eq "unknown command exits 2" "$RC" 2
case "$ERR" in *"unknown command 'frobnicate'"*) t_pass "unknown command message" ;; *) t_fail "unknown command message: $ERR" ;; esac

# Every command listed in `portcullis help` must answer --help with its usage.
COMMANDS="$(printf '%s\n' "$HELP" | sed -n 's/^  \([a-z][a-z -]*[a-z]\)  .*/\1/p')"
expect_eq "help lists 24 commands" "$(printf '%s\n' "$COMMANDS" | wc -l | tr -d ' ')" 24
while IFS= read -r c; do
  # shellcheck disable=SC2086
  run $c --help
  expect_eq "'$c --help' exits 0" "$RC" 0
  case "$OUT" in "Usage: portcullis $c"*) t_pass "'$c --help' shows its usage" ;; *) t_fail "'$c --help' output: ${OUT%%$'\n'*}" ;; esac
  sub_help="$OUT"
  # shellcheck disable=SC2086
  run help $c
  expect_eq "'help $c' == '$c --help'" "$RC:$OUT" "0:$sub_help"
done <<< "$COMMANDS"

for g in vault pki keycloak oidc dns cert config; do
  run "$g";        expect_eq "'$g' without subcommand exits 2" "$RC" 2
  run "$g" --help; expect_eq "'$g --help' exits 0" "$RC" 0
  run "$g" bogus;  expect_eq "'$g bogus' exits 2" "$RC" 2
done

# ── usage errors (all before .env / docker are needed) ──
while IFS='|' read -r args want; do
  # shellcheck disable=SC2086
  run $args
  expect_eq "'$args' exits 2" "$RC" 2
  case "$ERR" in *"$want"*) t_pass "'$args' says: $want" ;; *) t_fail "'$args' stderr: $ERR" ;; esac
done <<'EOF'
status --bogus|unknown argument: --bogus
up extra|unknown argument: extra
down -v|unknown argument: -v
upgrade --dry-run|unknown argument: --dry-run
upgrade --migrate-vault|unknown argument: --migrate-vault
backup now|unknown argument: now
backup --frob|unknown argument: --frob
backup verify --frob|unknown argument: --frob
backup verify --snapshot|--snapshot needs a value
backup verify --local x --snapshot y|exclusive
backup schedule|--systemd is required
backup schedule --systemd --on-calendar|--on-calendar needs a value
backup schedule --cron|unknown argument: --cron
restore|expected <backup-dir> or --from-offsite
restore a b|unexpected argument: b
restore --frob|unknown option: --frob
version --bogus|unknown argument: --bogus
status --json --bogus|unknown argument: --bogus
init --domain|--domain needs a value
init --domain --email|--domain needs a value
init --frob|unknown argument: --frob
vault init --rotate-enroll-secret|unknown argument
pki setup --with-server-certs|unknown argument
cert enroll|expected <username> [email]
cert enroll a b c|expected <username> [email]
cert enroll 'bad;user'|invalid username
cert enroll --slot|--slot needs a value
cert revoke|expected exactly one <serial>
cert revoke a b|expected exactly one <serial>
cert revoke --force x|unknown option: --force
cert list --revoked|unknown option: --revoked
cert sync now|unexpected argument: now
config apply --force|unknown argument
config init --remote|--remote needs a value
config init --remote a --from b|mutually exclusive
dns setup --fix|unknown argument
keycloak configure --wipe|unknown argument
oidc register now|unknown argument
EOF

# version and backup schedule work without .env (and without docker).
run version
expect_eq "version without .env exits 0" "$RC" 0
case "$OUT" in "portcullis "*"hub image "*"ghcr.io/porelli/portcullis-hub:"*"(default)"*) t_pass "version shows core + hub image" ;; *) t_fail "version output: $OUT" ;; esac
RC=0; OUT="$(HUB_IMAGE=example/hub:1.2.3 "$CLI" version --json </dev/null)" || RC=$?
expect_eq "version --json honours HUB_IMAGE" "$RC:$(printf '%s' "$OUT" | jq -r '.hub_image + " " + .hub_image_source')" "0:example/hub:1.2.3 HUB_IMAGE"
run backup schedule --systemd
expect_eq "backup schedule --systemd exits 0" "$RC" 0
case "$OUT" in *"ExecStart=$(cd "$HERE/.." && pwd)/portcullis backup"*"ExecStopPost=-"*"status --textfile"*"OnCalendar=*-*-* 03:15:00"*"Persistent=true"*) t_pass "systemd units: backup + status, daily timer" ;; *) t_fail "systemd units: $OUT" ;; esac
case "$OUT" in *"backup --offsite"*) t_fail "no BACKUP_REPOSITORY → no --offsite" ;; *) t_pass "no BACKUP_REPOSITORY → local backup only" ;; esac
case "$OUT" in *"Environment=PORTCULLIS_ROOT=$PORTCULLIS_ROOT"*) t_pass "units keep PORTCULLIS_ROOT" ;; *) t_fail "units lack PORTCULLIS_ROOT" ;; esac
run backup schedule --systemd --on-calendar 'Sun 04:00' --output "$WORK/units"
expect_eq "backup schedule --output exits 0" "$RC" 0
expect_eq "timer written with OnCalendar" "$(grep -c '^OnCalendar=Sun 04:00$' "$WORK/units/portcullis-backup.timer" 2>/dev/null)" 1
expect_ok "service written" test -s "$WORK/units/portcullis-backup.service"
RC=0; OUT="$(BACKUP_REPOSITORY=/srv/restic "$CLI" backup schedule --systemd </dev/null)" || RC=$?
case "$OUT" in *"portcullis backup --offsite"*) t_pass "BACKUP_REPOSITORY → backup --offsite" ;; *) t_fail "no --offsite: $OUT" ;; esac
run restore --from-offsite
expect_eq "restore --from-offsite without a repository exits 1" "$RC" 1
case "$ERR" in *"BACKUP_REPOSITORY is not set"*) t_pass "restore --from-offsite explains BACKUP_REPOSITORY" ;; *) t_fail "restore --from-offsite: $ERR" ;; esac

# Commands that need .env fail cleanly without one (exit 1, no docker).
run up;          expect_eq "up without .env exits 1" "$RC" 1
case "$ERR" in *"portcullis init"*) t_pass "up without .env points to init" ;; *) t_fail "up without .env: $ERR" ;; esac
run cert list;   expect_eq "cert list without .env exits 1" "$RC" 1

# ── init --env-only ──
run init --env-only --non-interactive
expect_eq "init --non-interactive without a domain exits 2" "$RC" 2
run init --env-only --non-interactive --domain 'bad domain'
expect_eq "init rejects an invalid domain" "$RC" 1
run init --env-only --non-interactive --domain ci.example.org --dns-provider none
expect_eq "init --env-only succeeds" "$RC" 0
ENVF="$PORTCULLIS_ROOT/.env"
expect_eq ".env is 0600" "$(file_mode "$ENVF")" 600
get() { grep "^$1=" "$ENVF" | tail -n1 | cut -d= -f2-; }
expect_eq "domain written" "$(get PORTCULLIS_DOMAIN)" ci.example.org
expect_eq "email defaults to admin@domain" "$(get ACME_EMAIL)" admin@ci.example.org
expect_eq "LLDAP base DN from the domain" "$(get LLDAP_BASE_DN)" dc=ci,dc=example,dc=org
for v in POSTGRES_PASSWORD KEYCLOAK_ADMIN_PASSWORD LLDAP_ADMIN_PASSWORD LLDAP_JWT_SECRET \
         FORWARD_AUTH_CLIENT_SECRET FORWARD_AUTH_COOKIE_SECRET HUB_PROXY_SECRET; do
  val="$(get "$v")"
  if [ "${#val}" -ge 24 ]; then t_pass "$v generated"; else t_fail "$v not generated ('$val')"; fi
done
expect_eq "HUB_PROXY_SECRET is 64 hex chars" "$(get HUB_PROXY_SECRET | grep -Ec '^[0-9a-f]{64}$')" 1
expect_eq "no public default forward-auth secret" "$(grep -c 'portcullis-forward-auth-secret' "$ENVF")" 0
expect_eq "BACKUP_PASSWORD generated (48 chars)" "$(get BACKUP_PASSWORD | grep -Ec '^[A-Za-z0-9]{48}$')" 1
run backup verify --local
expect_eq "backup verify --local without backups exits 1" "$RC" 1
case "$ERR" in *"no local backups"*) t_pass "backup verify --local: no local backups" ;; *) t_fail "backup verify --local: $ERR" ;; esac
BEFORE="$(cat "$ENVF")"
run init --env-only --non-interactive --domain other.example
expect_eq "init re-run succeeds" "$RC" 0
expect_eq "init re-run keeps .env unchanged" "$(cat "$ENVF")" "$BEFORE"
case "$ERR" in *"ignored"*) t_pass "init re-run warns about ignored flags" ;; *) t_fail "no warning: $ERR" ;; esac
# A blanked secret is regenerated, the rest is untouched.
sed 's/^HUB_PROXY_SECRET=.*/HUB_PROXY_SECRET=/' "$ENVF" > "$WORK/e" && cat "$WORK/e" > "$ENVF"
run init --env-only --non-interactive
expect_eq "init fills a blank secret" "$(get HUB_PROXY_SECRET | grep -Ec '^[0-9a-f]{64}$')" 1
expect_eq "init keeps the other secrets" "$(get POSTGRES_PASSWORD)" "$(printf '%s\n' "$BEFORE" | grep '^POSTGRES_PASSWORD=' | cut -d= -f2-)"
# DNS credentials come from the environment, not argv.
rm -f "$ENVF"
RC=0; CLOUDFLARE_API_TOKEN=tok123 "$CLI" init --env-only --non-interactive --domain x.example --dns-provider cloudflare >/dev/null 2>&1 </dev/null || RC=$?
expect_eq "init with provider creds from env" "$RC:$(get CLOUDFLARE_API_TOKEN):$(get DNS_PROVIDER)" "0:tok123:cloudflare"

expect_eq "docker was never called" "$(cat "$STUB_CALLS" 2>/dev/null)" ""

echo ""
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
