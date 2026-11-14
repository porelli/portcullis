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
# The engine's /version components (runtime_check): a Docker Engine.
cat > "$WORK/stub-version" <<'STUBV'
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
STUBV
# Only the engine's version answers (runtime_check, not logged); anything
# else is logged and fails loudly.
{ printf '#!/usr/bin/env bash\n'; cat "$WORK/stub-version"; cat <<'STUB'
echo "docker must not be called: $*" >&2
echo "$*" >> "$STUB_CALLS"
exit 99
STUB
} > "$WORK/bin/docker"
chmod +x "$WORK/bin/docker"
# Only the version answers; nothing else is logged (version with an .env).
mkdir -p "$WORK/quietbin"
{ printf '#!/usr/bin/env bash\n'; cat "$WORK/stub-version"; printf 'exit 1\n'; } > "$WORK/quietbin/docker"
chmod +x "$WORK/quietbin/docker"
# runtime_detect's rootful socket: a real unix socket here (the main stub
# answers as a Docker Engine), never the host's.
python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$WORK/docker.sock"
export RT_DOCKER_SOCK="$WORK/docker.sock"
# No engine at all: every call (the version too) is logged and fails.
mkdir -p "$WORK/noengine"
cat > "$WORK/noengine/docker" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_CALLS_NOENGINE"
exit 99
STUB
chmod +x "$WORK/noengine/docker"
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

# init --help names every DNS provider `dns setup` supports (stack.sh DNS_PROVIDERS).
run init --help
INIT_PROVIDERS="$(printf '%s\n' "$OUT" | sed -n '/--dns-provider NAME/,/another lego provider/p' | tr -s ' |\n' '\n\n\n' | sort -u | paste -sd' ' -)"
for p in $(sed -n 's/^DNS_PROVIDERS="\(.*\)"$/\1/p' "$HERE/../scripts/lib/stack.sh"); do
  case " $INIT_PROVIDERS " in *" $p "*) t_pass "init --help lists the DNS provider $p" ;; *) t_fail "init --help misses the DNS provider $p" ;; esac
done

# Every command listed in `portcullis help` must answer --help with its usage.
COMMANDS="$(printf '%s\n' "$HELP" | sed -n 's/^  \([a-z][a-z -]*[a-z]\)  .*/\1/p')"
expect_eq "help lists 35 commands" "$(printf '%s\n' "$COMMANDS" | wc -l | tr -d ' ')" 35
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

# Every --help works with no engine (and never asks one), even next to an
# .env without CONTAINER_RUNTIME.
NE_ROOT="$WORK/ne-root"
mkdir -p "$NE_ROOT"
echo 'PORTCULLIS_DOMAIN=ne.example' > "$NE_ROOT/.env"
NE_BAD=""
: > "$WORK/noengine-calls"
while IFS= read -r c; do
  # shellcheck disable=SC2086
  PATH="$WORK/noengine:$PATH" PORTCULLIS_ROOT="$NE_ROOT" STUB_CALLS_NOENGINE="$WORK/noengine-calls" \
    "$CLI" $c --help >/dev/null 2>&1 </dev/null || NE_BAD="$NE_BAD $c"
done <<< "$COMMANDS"
expect_eq "every --help works with no engine" "$NE_BAD" ""
expect_eq "every --help works with no engine: the engine was never asked" "$(cat "$WORK/noengine-calls")" ""
run init --help
case "$OUT" in *"--runtime docker|podman"*"CONTAINER_RUNTIME"*"never switched"*) t_pass "init --help documents --runtime" ;; *) t_fail "init --help lacks --runtime" ;; esac

for g in vault pki keycloak oidc dns cert config signin vpn; do
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
backup --json|--json only goes with --list --offsite
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
init --runtime|--runtime needs a value
init --runtime lxc|--runtime must be docker, podman or kubernetes
init --runtime docker --kube-context ci|--kube-context goes with --runtime kubernetes
init --runtime kubernetes|--runtime kubernetes needs --kube-context
init --kube-context|--kube-context needs a value
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
dns plan --bogus|unknown argument
dns check --bogus|unknown argument
dns setup --only x|--only
dns setup --only|--only needs a value
dns setup --check|dns check
dns plan --yes|unknown argument
keycloak configure --wipe|unknown argument
oidc register now|unknown argument
invite|missing <user>
invite a b|one user only
invite --ttl|--ttl needs a value
invite a --to ftp://x|--to must be hub, portal or an https URL
invite 'bad;user'|invalid user name
invite a --frob|unknown option: --frob
lldap-ui now|unknown argument: now
signin reset-core --force|unknown argument: --force
signin reset-core|no terminal to confirm on: pass --yes
vpn init extra|unexpected argument: extra
vpn init --builtin|--builtin needs a value
vpn init --builtin maybe|--builtin must be on or off
vpn init --port 0|--port must be a UDP port number
vpn init --port x|--port must be a UDP port number
vpn init --subnet 10.213.0.1/22|--subnet must be an IPv4 network
vpn init --subnet 10.213.0.0/31|--subnet must be an IPv4 network
vpn init --subnet fd00::/64|--subnet must be an IPv4 network
vpn init --frob|unknown option: --frob
vpn mode|expected apps, admin or server
vpn mode everything|expected apps, admin or server
vpn mode apps admin|expected apps, admin or server
vpn mode server --public-enrol maybe|--public-enrol must be true or false
vpn mode server --public-enrol|--public-enrol needs a value
vpn builtin|expected on or off
vpn builtin maybe|expected on or off
vpn add-device alice|expected <user> <name>
vpn add-device 'Bad;user' phone|invalid user name
vpn add-device alice phone extra|expected <user> <name>
vpn devices --user|--user needs a value
vpn devices --user Alice|invalid user name
vpn devices bob|unexpected argument: bob
vpn revoke|expected exactly one <device-id>
vpn revoke a b|expected exactly one <device-id>
vpn revoke 'x;y'|invalid device id
vpn revoke --all|unknown option: --all
EOF

# ── no secret on a command line (CLAUDE.md: stdin, -H @<(...), key=-, jq
# --rawfile / env.X) ── lines marked "secret-argv-ok" are reviewed exceptions.
ARGV_RE='--from-literal|--set(-string|-json)?[ =][^ ]*(secrets/|\$\(cat|PASSWORD|SECRET|TOKEN)|--arg(json)? [A-Za-z_]+ "?\$\(cat|--arg(json)? [A-Za-z_]+ "?\$\{?[A-Za-z_]*(PASSWORD|SECRET|TOKEN|PASS)\b|--(admin-)?password[ =]"?\$|--token[ =]"?\$|(PASSWORD|SECRET|TOKEN)=[^ ]*\$\(cat '
HITS="$(grep -nE -e "$ARGV_RE" "$HERE/../portcullis" "$HERE"/../scripts/lib/*.sh | grep -v 'secret-argv-ok' | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)"
expect_eq "no secrets on argv in the CLI" "$HITS" ""
# Container root is the operator under rootless Podman: an operator-owned
# file is chowned to ct_operator_id, never $(id -u) (a subuid there).
# Contract §6: the engine socket reaches only the two socket proxies, from
# PORTCULLIS_ENGINE_SOCKET (rootless Podman's user socket) or Docker's.
ROOT_DIR_SOCK="$(cd "$HERE/.." && pwd)"
expect_eq "the engine-socket mount appears exactly twice in docker-compose.yml" \
  "$(grep -cF -- '- ${PORTCULLIS_ENGINE_SOCKET:-/var/run/docker.sock}:/var/run/docker.sock:ro' "$ROOT_DIR_SOCK/docker-compose.yml")" 2
expect_eq "no literal /var/run/docker.sock:/var/run/docker.sock mount anywhere" \
  "$(git -C "$ROOT_DIR_SOCK" grep -nF '/var/run/docker.sock:/var/run/docker.sock' -- . ':!tests/test_cli.sh' || true)" ""
# The SELinux overlay never labels the checkout, secrets/, backups/ or .env
# (or a parent of them): an escaped container_t process could read every
# secret. selinux_bad_sources <file> — each offending labelled source.
selinux_bad_sources() {
  sed -n 's/.*source: *\([^,}]*\).*selinux: *[zZ].*/\1/p' "$1" | while IFS= read -r src; do
    src="${src%/}"
    case "$src" in
      .|./secrets|./backups|./.env|.env|..|../*|/*|*/..|*/../*|"") echo "$src" ;;
      ./*) ;;
      *) echo "$src" ;;
    esac
  done
}
expect_eq "the SELinux overlay labels no checkout root, secrets/, backups/, .env or a parent" \
  "$(selinux_bad_sources "$ROOT_DIR_SOCK/docker-compose.podman-selinux.yml")" ""
printf '%s\n' '      - {type: bind, source: ., target: /p, bind: {selinux: z}}' '      - {type: bind, source: ./secrets/, target: /s, bind: {selinux: Z}}' \
  '      - {type: bind, source: ./backups, target: /b, bind: {selinux: z}}' '      - {type: bind, source: ./.env, target: /e, bind: {selinux: Z}}' \
  '      - {type: bind, source: .., target: /u, bind: {selinux: z}}' '      - {type: bind, source: ./secrets/hub/core.env, target: /ok, bind: {selinux: Z}}' > "$WORK/bad-overlay.yml"
expect_eq "selinux_bad_sources catches ., ./secrets, ./backups, ./.env and a parent (and passes a per-file secret)" \
  "$(selinux_bad_sources "$WORK/bad-overlay.yml" | paste -sd' ' -)" ". ./secrets ./backups ./.env .."
expect_eq "the SELinux overlay: the Hub's /project root is a tmpfs, not the checkout" \
  "$(grep -c '{type: tmpfs, target: /project,' "$ROOT_DIR_SOCK/docker-compose.podman-selinux.yml"):$(grep -cE 'source: \.[,}]|source: \./?, ' "$ROOT_DIR_SOCK/docker-compose.podman-selinux.yml")" "1:0"
# Healthchecks behave the same on Docker and Podman (whose compat API
# re-splits CMD arguments on whitespace): tests/lint_healthchecks.sh.
mkdir -p "$WORK/hl-root"
PORTCULLIS_ROOT="$WORK/hl-root" "$CLI" init --env-only --runtime docker --non-interactive --domain ci.example.org --dns-provider none >/dev/null 2>&1 </dev/null
expect_eq "every core healthcheck test: no CMD argument with whitespace, no newline, CMD-SHELL one string" \
  "$(PATH="${PATH#"$WORK/bin:"}" "$HERE/lint_healthchecks.sh" "$WORK/hl-root/.env" 2>&1; echo "rc=$?")" "rc=0"
mkdir -p "$WORK/hl/tests" "$WORK/hl/.github/workflows"
cp "$HERE/lint_healthchecks.sh" "$WORK/hl/tests/"
cat > "$WORK/hl/docker-compose.yml" <<'YML'
services:
  a:
    image: docker.io/library/alpine:3
    healthcheck:
      test: ["CMD", "python3", "-c", "import x; x.y()"]
  b:
    image: docker.io/library/alpine:3
    healthcheck:
      test: ["CMD-SHELL", "true", "false"]
  c:
    image: docker.io/library/alpine:3
    healthcheck:
      test: ["CMD-SHELL", "a\nb"]
  d:
    image: docker.io/library/alpine:3
    healthcheck:
      test: ["CMD", "wget", "-q", "http://127.0.0.1/"]
    tmpfs:
      - /tmp
      - /run:mode=1777,size=1m
  e:
    image: docker.io/library/alpine:3
    tmpfs:
      - /home/x:uid=10001,gid=10001,mode=0700
  f:
    image: docker.io/library/alpine:3
    volumes:
      - {type: volume, source: v, target: /v, volume: {nocopy: true}}
volumes:
  v: {}
YML
printf '      test: ["CMD", "wget", "-q", "http://127.0.0.1/"]\n      test: ["CMD", "bash", "-c", "a b"]\n' > "$WORK/hl/.github/workflows/x.yml"
expect_eq "lint_healthchecks.sh flags a spaced CMD argument, a split CMD-SHELL, a newline, a tmpfs uid= option, volume nocopy and an inline workflow override (a plain CMD, tmpfs mode / size pass)" \
  "$(PATH="${PATH#"$WORK/bin:"}" "$WORK/hl/tests/lint_healthchecks.sh" "$WORK/hl-root/.env" docker-compose.yml 2>&1 | sed 's/:[0-9]*:.*//' ; echo "rc=${PIPESTATUS[0]}")" "docker-compose.yml: a: a CMD argument has whitespace (Podman re-splits it): use one CMD-SHELL string
docker-compose.yml: b: CMD-SHELL needs exactly one command string
docker-compose.yml: c: a test element has a newline
docker-compose.yml: e: tmpfs /home/x:uid=10001,gid=10001,mode=0700 has an option Podman refuses (only size / mode / ro / rw / noexec / nosuid / nodev)
docker-compose.yml: f: volume nocopy on /v
a workflow's inline compose override has a CMD healthcheck argument with whitespace:
.github/workflows/x.yml:2
rc=1"

# GitHub refuses a workflow file over 500 KB (startup_failure, no jobs):
# tests/lint_ci_size.sh keeps ci.yml under 450,000 bytes, also in CI.
expect_eq "ci.yml is under 450,000 bytes" "$("$HERE/lint_ci_size.sh" 2>&1; echo "rc=$?")" "rc=0"
head -c 450000 /dev/zero > "$WORK/ci-450000.yml"
head -c 450001 /dev/zero > "$WORK/ci-450001.yml"
expect_eq "lint_ci_size.sh passes 450,000 bytes and fails 450,001" \
  "$("$HERE/lint_ci_size.sh" "$WORK/ci-450000.yml" >/dev/null; echo "rc=$?"):$("$HERE/lint_ci_size.sh" "$WORK/ci-450001.yml" >/dev/null; echo "rc=$?")" "rc=0:rc=1"
# Same-named branch lookups (Hub, Keycloak, templates): release tags are
# vX.Y.Z only — a `v*` glob also caught the branch vpn1 and quietly tested
# main / the published images — and the heads are listed once (a failed
# listing fails the step) and matched exactly (ls-remote patterns match
# suffixes too).
expect_eq "CI's same-named branch lookups: no v* tag glob, no ls-remote pattern lookup" \
  "$(grep -rnE '"\$REF" *(==|!=) *v\*|ls-remote --exit-code' "$HERE/../.github" | wc -l | tr -d ' ')" 0
expect_eq "CI's same-named branch lookups: every one lists the heads once and fails loudly" \
  "$(grep -cF 'heads=$(git ls-remote --heads "$url") || { echo "::error::git ls-remote $url failed"; exit 1; }' "$HERE/../.github/workflows/ci.yml" "$HERE/../.github/actions/hub-image/action.yml" "$HERE/../.github/actions/keycloak-image/action.yml" | awk -F: '{ s += $2 } END { print s }')" 11
# Client forwarded / address headers Traefik doesn't manage are deleted on
# every websecure and vpnsecure router (entrypoint http.middlewares).
expect_eq "strip-client-forwarded@file deletes Forwarded, X-Real-Ip's look-alikes and every unmanaged X-Forwarded-*" \
  "$(yq -o=json '.http.middlewares["strip-client-forwarded"].headers.customRequestHeaders' "$HERE/../traefik/dynamic/middlewares.yml" \
     | jq -c '[to_entries[] | select(.value != "") | .key] as $bad
              | ["Forwarded", "Forwarded-For", "X-Forwarded", "X-Forwarded-Prefix", "X-Forwarded-Uri", "X-Forwarded-Method", "X-Forwarded-Scheme",
                 "X-Forwarded-Ssl", "X-Forwarded-Protocol", "X-Url-Scheme", "X-Original-Forwarded-For", "X-Client-Ip", "True-Client-Ip",
                 "Cf-Connecting-Ip", "Fastly-Client-Ip", "X-Cluster-Client-Ip"] - keys | {missing: ., bad: $bad}')" '{"missing":[],"bad":[]}'
expect_eq "websecure and vpnsecure run strip-client-forwarded@file first" \
  "$(grep -cE '^      TRAEFIK_ENTRYPOINTS_(WEBSECURE|VPNSECURE)_HTTP_MIDDLEWARES: strip-client-forwarded@file$' "$HERE/../docker-compose.yml")" 2
# Fully qualified base images (rootless Podman: podman build never relies
# on registries.conf short names): tests/lint_images.sh, also in CI.
expect_eq "every Dockerfile FROM and compose image: is fully qualified" "$("$HERE/lint_images.sh" 2>&1; echo "rc=$?")" "rc=0"
mkdir -p "$WORK/lint/tests" "$WORK/lint/svc"
cp "$HERE/lint_images.sh" "$WORK/lint/tests/"
printf 'FROM alpine:3.24@sha256:00 AS build\nFROM build\nFROM docker.io/library/alpine:3.24@sha256:00\nFROM golang:1@sha256:00\n' > "$WORK/lint/svc/Dockerfile"
printf 'services:\n  a:\n    image: traefik/whoami:v1@sha256:00\n  b:\n    image: docker.io/library/nginx:1@sha256:00\n  c:\n    image: portcullis-domains\n  d:\n    image: ${HUB_IMAGE:-ghcr.io/x/y:edge}\n  e:\n    image: quay.io/x/y:1\n  f:\n    image: postgres:18@sha256:00\n' > "$WORK/lint/docker-compose.yml"
expect_eq "lint_images.sh flags alpine / golang FROMs and traefik/whoami / postgres images (a stage, docker.io/…, portcullis-*, \${VAR}, quay.io pass)" \
  "$("$WORK/lint/tests/lint_images.sh"; echo "rc=$?")" "svc/Dockerfile:1: alpine:3.24@sha256:00
svc/Dockerfile:4: golang:1@sha256:00
docker-compose.yml:3: traefik/whoami:v1@sha256:00
docker-compose.yml:13: postgres:18@sha256:00
rc=1"
# The CLI's image constants and the workflows' / CI templates' inline images.
mkdir -p "$WORK/lint/scripts/lib" "$WORK/lint/.github/workflows" "$WORK/lint/tests/e2e/apps/x"
printf 'A_IMAGE="alpine:3.24.3@sha256:0000000000000000000000000000000000000000000000000000000000000000"\nB_IMAGE="docker.io/library/alpine:3.24.3@sha256:0000000000000000000000000000000000000000000000000000000000000000"\n' > "$WORK/lint/scripts/lib/x.sh"
printf 'env:\n  ALPINE: alpine:3@sha256:0000000000000000000000000000000000000000000000000000000000000000\n  CURL_IMG: docker.io/curlimages/curl:8@sha256:0000000000000000000000000000000000000000000000000000000000000000\nrun: docker run --rm restic/restic:0.19.1@sha256:0000000000000000000000000000000000000000000000000000000000000000 x\n' > "$WORK/lint/.github/workflows/x.yml"
printf 'services:\n  a:\n    image: busybox:1@sha256:00\n' > "$WORK/lint/tests/e2e/apps/x/compose.yml"
OUT="$("$WORK/lint/tests/lint_images.sh"; echo "rc=$?")"
expect_eq "lint_images.sh flags short names in scripts/lib constants, workflow inline images and CI templates (qualified ones pass)" \
  "$(printf '%s\n' "$OUT" | grep -E '^(scripts|\.github|tests/e2e)' | sed 's/@sha256:.*//')" "tests/e2e/apps/x/compose.yml:3: busybox:1
scripts/lib/x.sh:1: alpine:3.24.3
.github/workflows/x.yml:2: alpine:3
.github/workflows/x.yml:4: restic/restic:0.19.1"
# Kubernetes (K1, K3): images.yaml, the chart templates, kube/**/*.yaml.
Z64=0000000000000000000000000000000000000000000000000000000000000000
mkdir -p "$WORK/lint/charts/portcullis/templates" "$WORK/lint/kube/storage"
printf 'images:\n  a: docker.io/library/postgres:18@sha256:%s\n  b: postgres:18@sha256:%s\n  c: docker.io/library/vault:2\n  d:\n    tag_ref: ghcr.io/porelli/portcullis-hub:edge\n  e:\n    tag_ref: docker.io/evil/hub:edge\n' "$Z64" "$Z64" > "$WORK/lint/charts/portcullis/images.yaml"
printf 'spec:\n  containers:\n    - image: {{ .Values.images.vault }}\n    - image: busybox:1@sha256:%s\n' "$Z64" > "$WORK/lint/charts/portcullis/templates/x.yaml"
printf 'spec:\n  image: docker.io/rancher/local-path-provisioner:v0.0.37\n' > "$WORK/lint/kube/storage/p.yaml"
OUT="$("$WORK/lint/tests/lint_images.sh"; echo "rc=$?")"
expect_eq "lint_images.sh flags an unqualified / unpinned images.yaml entry, a foreign tag_ref, and short or unpinned images in the chart templates and kube/" \
  "$(printf '%s\n' "$OUT" | grep -E '^(charts|kube)' | sed 's/@sha256:.*//' | sort -u)" "charts/portcullis/images.yaml:3: postgres:18
charts/portcullis/images.yaml:4: docker.io/library/vault:2 (not pinned tag@sha256)
charts/portcullis/images.yaml:8: docker.io/evil/hub:edge (a tag_ref outside ghcr.io/porelli/portcullis-*)
charts/portcullis/templates/x.yaml:4: busybox:1
kube/storage/p.yaml:2: docker.io/rancher/local-path-provisioner:v0.0.37"
# images.yaml is generated from compose (K1): a stale file fails --check.
mkdir -p "$WORK/gen/scripts" "$WORK/gen/charts/portcullis"
cp "$HERE/../scripts/gen-images-yaml.py" "$WORK/gen/scripts/"
cp "$HERE/../docker-compose.yml" "$WORK/gen/"
if python3 -c 'import yaml' 2>/dev/null; then
  python3 "$WORK/gen/scripts/gen-images-yaml.py"
  expect_eq "gen-images-yaml.py --check: a fresh file passes" "$(python3 "$WORK/gen/scripts/gen-images-yaml.py" --check 2>&1; echo "rc=$?")" "rc=0"
  sed -i.bak 's/postgres:18[^ ]*/postgres:17/' "$WORK/gen/charts/portcullis/images.yaml"
  expect_eq "gen-images-yaml.py --check: a stale file → exit 1" "$(python3 "$WORK/gen/scripts/gen-images-yaml.py" --check 2>&1; echo "rc=$?")" "charts/portcullis/images.yaml is stale: run scripts/gen-images-yaml.py
rc=1"
  expect_eq "charts/portcullis/images.yaml is current" "$(python3 "$HERE/../scripts/gen-images-yaml.py" --check 2>&1; echo "rc=$?")" "rc=0"
  expect_eq "images.yaml: the five core-built images, the Hub and Keycloak are tag_refs; no socket proxy" \
    "$(grep -c 'tag_ref: ghcr.io/porelli/portcullis-' "$HERE/../charts/portcullis/images.yaml"):$(grep -c 'socket-proxy' "$HERE/../charts/portcullis/images.yaml")" "8:0"
else
  t_fail "gen-images-yaml.py: python3 has no yaml module (pip install -r tests/k8s-requirements.txt)"
fi
expect_eq "the SELinux overlay adds only label=disable to security_opt (compose appends: a repeated no-new-privileges is a duplicate newer compose refuses)" \
  "$(grep -v '^[[:space:]]*#' "$ROOT_DIR_SOCK/docker-compose.podman-selinux.yml" | grep -c 'no-new-privileges'):$(grep -c '^    security_opt: \["label=disable"\]$' "$ROOT_DIR_SOCK/docker-compose.podman-selinux.yml")" "0:2"
expect_eq "docker-compose.podman.yml sets restart: always and nothing else (podman-restart.service starts only those at boot)" \
  "$(grep -vE '^[[:space:]]*(#|$)|^services:$|^  [a-z][a-z0-9-]*:$|^    restart: always$' "$ROOT_DIR_SOCK/docker-compose.podman.yml"):$(grep -c '^    restart: always$' "$ROOT_DIR_SOCK/docker-compose.podman.yml" | awk '{print ($1 >= 20)}')" ":1"
expect_eq "the SELinux overlay never names the engine socket" "$(grep -c 'docker.sock\|ENGINE_SOCKET' "$ROOT_DIR_SOCK/docker-compose.podman-selinux.yml")" 0
expect_eq "no ct_own \"\$(id -u)… in the CLI (ct_operator_id)" "$(grep -rnF 'ct_own "$(id -u)' "$HERE/../scripts/lib" "$HERE/../portcullis" || true)" ""
# ── the runtime layer (rt_*): no dc / docker call outside the docker
# branch. Every function (the libs sourced, bodies from `declare -f`, so
# comments are gone) that calls dc or docker in a command position must be
# `dc`, a `_rtd_*` docker-branch verb, or start with `_rt_docker_only`
# (refused under kubernetes). Quoted text without a command substitution
# (messages, hints) and the help_* texts are ignored.
rt_docker_hits() {
  ( set +eu
    PORTCULLIS_ROOT="$WORK/rtlint-root"
    for _l in common network vault pki certs keycloak users domains mcpgate sessions dns config status monitoring backup signin vpn stack; do
      # shellcheck source=/dev/null
      source "$HERE/../scripts/lib/$_l.sh"
    done
    for fn in $(declare -F | awk '{print $3}'); do
      case "$fn" in dc|_rtd_*|help_*|rt_docker_hits) continue ;; esac
      body="$(declare -f "$fn")"
      hit="$(printf '%s\n' "$body" | perl -0777 -pe 's/('"'"'[^'"'"']*'"'"')|"((?:[^"\\]|\\.)*)"/ defined($1) ? q{} : index($2, q{$(}) >= 0 ? qq{"$2"} : q{""} /gse' \
        | grep -vE '^[[:space:]]*[^ ()]+( \| [^ ()]+)*\)' | grep -E '(^|[;&|(!{`]|\$\(|then |do |else |&& |\|\| )[[:space:]]*(dc|docker)( |$)' || true)"
      [ -n "$hit" ] || continue
      first="$(printf '%s\n' "$body" | sed -n '3,$p' | grep -vE '^[[:space:]]*(local|declare) ' | head -n1 | tr -d ' ;')"
      [ "$first" = _rt_docker_only ] || printf '%s\n' "$fn"
    done ) 2>/dev/null
}
expect_eq "no dc / docker call outside the rt_* docker branch (functions starting with _rt_docker_only)" "$(rt_docker_hits | tr '\n' ' ')" ""
expect_eq "the rt_* lint catches a docker call in a function without the guard" \
  "$( (unguarded() { local x; x="$(dc ps -q)"; docker inspect "$x"; }; guarded() { local y=1; _rt_docker_only; docker ps "$y"; }
       msg() { warn "run: docker compose logs (docker compose -p x down)"; }
       for f in unguarded guarded msg; do body="$(declare -f "$f")"
         hit="$(printf '%s\n' "$body" | perl -0777 -pe 's/('"'"'[^'"'"']*'"'"')|"((?:[^"\\]|\\.)*)"/ defined($1) ? q{} : index($2, q{$(}) >= 0 ? qq{"$2"} : q{""} /gse' | grep -vE '^[[:space:]]*[^ ()]+( \| [^ ()]+)*\)' | grep -E '(^|[;&|(!{`]|\$\(|then |do |else |&& |\|\| )[[:space:]]*(dc|docker)( |$)' || true)"
         [ -n "$hit" ] || continue
         first="$(printf '%s\n' "$body" | sed -n '3,$p' | grep -vE '^[[:space:]]*(local|declare) ' | head -n1 | tr -d ' ;')"
         [ "$first" = _rt_docker_only ] || echo "$f"; done) 2>/dev/null)" "unguarded"
case "$(printf '%s\n' '  jq -n --arg p "$(cat "$f")" x' '  jq --arg pass "$LLDAP_ADMIN_PASSWORD"' '  kube_ctl create secret generic x --from-literal=a=b' '  kube_helm upgrade --set hub.secret=$(cat secrets/hub/x)' '  helm upgrade --set-string pw=$POSTGRES_PASSWORD' | grep -cE -e "$ARGV_RE")" in
  5) t_pass "argv secret pattern catches --arg \"\$(cat ...)\", secret variables, --from-literal and --set with a secret" ;; *) t_fail "argv secret pattern" ;; esac

# version and backup schedule work without .env (and without docker).
run version
expect_eq "version without .env exits 0" "$RC" 0
case "$OUT" in "portcullis "*"hub image "*"ghcr.io/porelli/portcullis-hub:"*"(default)"*) t_pass "version shows core + hub image" ;; *) t_fail "version output: $OUT" ;; esac
RC=0; OUT="$(HUB_IMAGE=example/hub:1.2.3 "$CLI" version --json </dev/null)" || RC=$?
expect_eq "version --json honours HUB_IMAGE" "$RC:$(printf '%s' "$OUT" | jq -r '.hub_image + " " + .hub_image_source')" "0:example/hub:1.2.3 HUB_IMAGE"
run version
case "$OUT" in *"keycloak image   ghcr.io/porelli/portcullis-keycloak:edge (default)"*) t_pass "version shows the keycloak image" ;; *) t_fail "version keycloak image: $OUT" ;; esac
RC=0; OUT="$(KEYCLOAK_IMAGE=example/kc:2 "$CLI" version --json </dev/null)" || RC=$?
expect_eq "version --json honours KEYCLOAK_IMAGE" "$RC:$(printf '%s' "$OUT" | jq -r '.keycloak_image + " " + .keycloak_image_source')" "0:example/kc:2 KEYCLOAK_IMAGE"
run backup schedule --systemd
expect_eq "backup schedule --systemd without .env exits 1" "$RC" 1
case "$ERR" in *"CONTAINER_RUNTIME"*) t_pass "backup schedule without .env names CONTAINER_RUNTIME" ;; *) t_fail "backup schedule without .env: $ERR" ;; esac
echo 'PORTCULLIS_DOMAIN=x' > "$PORTCULLIS_ROOT/.env"
run backup schedule --systemd
expect_eq "backup schedule with .env but no CONTAINER_RUNTIME exits 1" "$RC" 1
case "$ERR" in *"CONTAINER_RUNTIME is not set in .env"*) t_pass "backup schedule: no CONTAINER_RUNTIME → refused naming the variable" ;; *) t_fail "backup schedule without CONTAINER_RUNTIME: $ERR" ;; esac
printf 'PORTCULLIS_DOMAIN=x\nCONTAINER_RUNTIME=docker\n' > "$PORTCULLIS_ROOT/.env"
run backup schedule --systemd
expect_eq "backup schedule --systemd exits 0" "$RC" 0
case "$OUT" in *"ExecStart=$(cd "$HERE/.." && pwd)/portcullis backup"*"ExecStopPost=-"*"status --textfile"*"OnCalendar=*-*-* 03:15:00"*"Persistent=true"*) t_pass "systemd units: backup + status, daily timer" ;; *) t_fail "systemd units: $OUT" ;; esac
case "$OUT" in *"backup --offsite"*) t_fail "no BACKUP_REPOSITORY → no --offsite" ;; *) t_pass "no BACKUP_REPOSITORY → local backup only" ;; esac
case "$OUT" in *"Environment=PORTCULLIS_ROOT=$PORTCULLIS_ROOT"*) t_pass "units keep PORTCULLIS_ROOT" ;; *) t_fail "units lack PORTCULLIS_ROOT" ;; esac
run backup schedule --systemd --on-calendar 'Sun 04:00' --output "$WORK/units"
expect_eq "backup schedule --output exits 0" "$RC" 0
expect_eq "timer written with OnCalendar" "$(grep -c '^OnCalendar=Sun 04:00$' "$WORK/units/portcullis-backup.timer" 2>/dev/null)" 1
expect_eq "service written" "$(grep -c "^ExecStart=" "$WORK/units/portcullis-backup.service" 2>/dev/null)" 1
RC=0; OUT="$(BACKUP_REPOSITORY=/srv/restic "$CLI" backup schedule --systemd </dev/null)" || RC=$?
case "$OUT" in *"portcullis backup --offsite"*) t_pass "BACKUP_REPOSITORY → backup --offsite" ;; *) t_fail "no --offsite: $OUT" ;; esac
# version with an .env: its runtime; without CONTAINER_RUNTIME refused (P7).
RC=0; OUT="$(PATH="$WORK/quietbin:$PATH" "$CLI" version </dev/null)" || RC=$?
case "$RC:$OUT" in "0:"*"runtime          docker 29.0.0"*) t_pass "version with .env shows the runtime" ;; *) t_fail "version runtime: $RC $OUT" ;; esac
RC=0; OUT="$(PATH="$WORK/quietbin:$PATH" "$CLI" version --json </dev/null)" || RC=$?
expect_eq "version --json: runtime + runtime_version" "$RC:$(printf '%s' "$OUT" | jq -r '.runtime + " " + .runtime_version')" "0:docker 29.0.0"
RC=0; OUT="$(PATH="$WORK/noengine:$PATH" STUB_CALLS_NOENGINE="$WORK/noengine-calls2" "$CLI" version </dev/null)" || RC=$?
case "$RC:$OUT" in "0:"*"runtime          docker (engine not reachable)"*) t_pass "version: an engine that doesn't answer is only noted" ;; *) t_fail "version without engine: $RC $OUT" ;; esac
echo 'PORTCULLIS_DOMAIN=x' > "$PORTCULLIS_ROOT/.env"
run version
expect_eq "version with .env but no CONTAINER_RUNTIME → refused" "$RC" 1
case "$ERR" in *"CONTAINER_RUNTIME is not set in .env"*) t_pass "version names CONTAINER_RUNTIME" ;; *) t_fail "version without CONTAINER_RUNTIME: $ERR" ;; esac
# need_env: every command needing the runtime refuses without it.
run status
expect_eq "need_env: no CONTAINER_RUNTIME → refused naming the variable" "$RC:$(printf '%s' "$ERR" | grep -c 'CONTAINER_RUNTIME is not set in .env (docker, podman or kubernetes)')" "1:1"
rm -f "$PORTCULLIS_ROOT/.env"
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
RC=0; PATH="$WORK/noengine:$PATH" STUB_CALLS_NOENGINE="$WORK/noengine-calls3" "$CLI" init --env-only --non-interactive --domain ci.example.org --dns-provider none >"$WORK/out" 2>"$WORK/err" </dev/null || RC=$?
expect_eq "init --env-only: no engine and no --runtime → refused" "$RC:$(grep -c 'no container engine answers: pass --runtime docker|podman' "$WORK/err")" "1:1"
expect_eq "init --env-only: refused → no .env written" "$(test -e "$PORTCULLIS_ROOT/.env" && echo yes || echo no)" no
RC=0; CONTAINER_RUNTIME=podman "$CLI" init --env-only --non-interactive --domain ci.example.org --dns-provider none --runtime docker >/dev/null 2>"$WORK/err" </dev/null || RC=$?
expect_eq "init: --runtime contradicting CONTAINER_RUNTIME in the environment → refused" "$RC" 1
rm -f "$PORTCULLIS_ROOT/.env"
RC=0; XDG_RUNTIME_DIR=/run/user/4242 "$CLI" init --env-only --non-interactive --domain ci.example.org --dns-provider none --runtime podman >/dev/null 2>"$WORK/err" </dev/null || RC=$?
expect_eq "init --env-only writes CONTAINER_RUNTIME=podman and the rootless PORTCULLIS_ENGINE_SOCKET with --runtime podman" \
  "$RC:$(grep -c '^CONTAINER_RUNTIME=podman$' "$PORTCULLIS_ROOT/.env"):$(grep -c '^PORTCULLIS_ENGINE_SOCKET=/run/user/4242/podman/podman.sock$' "$PORTCULLIS_ROOT/.env")" "0:1:1"
rm -f "$PORTCULLIS_ROOT/.env"
# --runtime kubernetes: the context's networks detected, the kube keys
# written (a kubectl stub on the context ci; any other context fails).
mkdir -p "$WORK/kbin"
cat > "$WORK/kbin/kubectl" <<'KSTUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$KUBE_CALLS"
[ "$*" = "config get-contexts -o name" ] && { echo ci; exit 0; }
[ "$1 $2" = "--context ci" ] || exit 97
shift 2
case "$*" in
  "get nodes -o json") echo '{"items":[{"metadata":{"name":"n1"},"spec":{"podCIDRs":["10.42.0.0/24"]},"status":{"addresses":[{"type":"InternalIP","address":"10.1.0.4"}]}}]}' ;;
  "create --dry-run=server -f -") cat >/dev/null; echo 'The Service "portcullis-cidr-probe" is invalid: spec.clusterIPs: Invalid value: []string{"0.0.0.1"}: failed to allocate IP 0.0.0.1: the provided IP (0.0.0.1) is not in the valid range. The range of valid IPs is 10.43.0.0/16' >&2; exit 1 ;;
  "get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o json") echo '{"items":[{"ports":[{"port":6443}],"endpoints":[{"addresses":["10.1.0.4"]}]}]}' ;;
  *) exit 98 ;;
esac
KSTUB
chmod +x "$WORK/kbin/kubectl"
RC=0; PATH="$WORK/kbin:$PATH" KUBE_CALLS="$WORK/kube-calls" STUB_CALLS="$WORK/kdocker-calls" "$CLI" init --env-only --non-interactive --domain ci.example.org --dns-provider none --runtime kubernetes --kube-context ci >/dev/null 2>"$WORK/err" </dev/null || RC=$?
expect_eq "init --env-only --runtime kubernetes writes CONTAINER_RUNTIME=kubernetes, the context, namespaces, detected networks, the install id, registry images and the fixed ClusterIPs" \
  "$RC:$(grep -cxE 'CONTAINER_RUNTIME=kubernetes|PORTCULLIS_KUBE_CONTEXT=ci|PORTCULLIS_NAMESPACE=portcullis|PORTCULLIS_APPS_NAMESPACE=portcullis-apps|PORTCULLIS_POD_CIDR=10\.42\.0\.0/24|PORTCULLIS_SERVICE_CIDR=10\.43\.0\.0/16|PORTCULLIS_KUBE_API_ENDPOINTS=10\.1\.0\.4:6443|PORTCULLIS_KUBE_INSTALL_ID=[0-9a-f-]{36}|PORTCULLIS_KUBE_IMAGES=registry|PORTCULLIS_TRAEFIK_SERVICE_IP=10\.43\.0\.20|PORTCULLIS_TRAEFIK_VPN_SERVICE_IP=10\.43\.0\.21|PORTCULLIS_WG_EDGE_SERVICE_IP=10\.43\.0\.22' "$PORTCULLIS_ROOT/.env"):$(grep -vc '^--context ci \|^config get-contexts' "$WORK/kube-calls")" "0:12:0"
expect_eq "init --runtime kubernetes: no docker call" "$(cat "$WORK/kdocker-calls" 2>/dev/null)" ""
run init --env-only --non-interactive --runtime docker
expect_eq "init: CONTAINER_RUNTIME=kubernetes in .env, --runtime docker → refused" "$RC:$(grep -c 'never switched' <<< "$ERR")" "1:1"
rm -f "$PORTCULLIS_ROOT/.env"
RC=0; PATH="$WORK/kbin:$PATH" KUBE_CALLS="$WORK/kube-calls" "$CLI" init --env-only --non-interactive --domain ci.example.org --dns-provider none --runtime kubernetes --kube-context prod >/dev/null 2>"$WORK/err" </dev/null || RC=$?
expect_eq "init --runtime kubernetes: a context that doesn't exist → refused, no .env" "$RC:$(grep -c "kube context prod doesn't exist" "$WORK/err"):$(test -e "$PORTCULLIS_ROOT/.env" && echo yes || echo no)" "1:1:no"
run init --env-only --non-interactive --domain ci.example.org --dns-provider none --runtime docker
expect_eq "init --env-only succeeds" "$RC" 0
ENVF="$PORTCULLIS_ROOT/.env"
expect_eq ".env is 0600" "$(file_mode "$ENVF")" 600
get() { grep "^$1=" "$ENVF" | tail -n1 | cut -d= -f2-; }
expect_eq "domain written" "$(get PORTCULLIS_DOMAIN)" ci.example.org
expect_eq "CONTAINER_RUNTIME=docker written, no engine socket" "$(get CONTAINER_RUNTIME):$(grep -c '^PORTCULLIS_ENGINE_SOCKET=' "$ENVF")" "docker:0"
expect_eq ".env says the runtime is never switched" "$(grep -c 'never switched' "$ENVF")" 1
expect_eq "email defaults to admin@domain" "$(get ACME_EMAIL)" admin@ci.example.org
expect_eq "LLDAP base DN from the domain" "$(get LLDAP_BASE_DN)" dc=ci,dc=example,dc=org
for v in POSTGRES_PASSWORD KEYCLOAK_ADMIN_PASSWORD LLDAP_ADMIN_PASSWORD LLDAP_JWT_SECRET \
         FORWARD_AUTH_CLIENT_SECRET FORWARD_AUTH_COOKIE_SECRET FORWARD_AUTH_REDIS_PASSWORD \
         FORWARD_AUTH_EXT_REDIS_PASSWORD HUB_PROXY_SECRET; do
  val="$(get "$v")"
  if [ "${#val}" -ge 24 ]; then t_pass "$v generated"; else t_fail "$v not generated ('$val')"; fi
done
expect_eq "HUB_PROXY_SECRET is 64 hex chars" "$(get HUB_PROXY_SECRET | grep -Ec '^[0-9a-f]{64}$')" 1
expect_eq "no public default forward-auth secret" "$(grep -c 'portcullis-forward-auth-secret' "$ENVF")" 0
expect_eq "BACKUP_PASSWORD generated (48 chars)" "$(get BACKUP_PASSWORD | grep -Ec '^[A-Za-z0-9]{48}$')" 1
# The two session-store passwords: 40 random [A-Za-z0-9] each (hashed into
# secrets/sessions/valkey.conf), never the same.
expect_eq "FORWARD_AUTH_REDIS_PASSWORD / _EXT_ are 40 [A-Za-z0-9]" \
  "$(get FORWARD_AUTH_REDIS_PASSWORD | grep -Ec '^[A-Za-z0-9]{40}$')$(get FORWARD_AUTH_EXT_REDIS_PASSWORD | grep -Ec '^[A-Za-z0-9]{40}$')" 11
if [ "$(get FORWARD_AUTH_REDIS_PASSWORD)" != "$(get FORWARD_AUTH_EXT_REDIS_PASSWORD)" ]; then t_pass "the two session-store passwords differ"; else t_fail "the two session-store passwords are the same"; fi
expect_eq "the session-store passwords are core secrets (never shared with the Hub) and rotatable (upgrade generates them)" \
  "$(bash -c '. "$1/scripts/lib/common.sh"; for v in FORWARD_AUTH_REDIS_PASSWORD FORWARD_AUTH_EXT_REDIS_PASSWORD; do case " $CORE_SECRETS " in *" $v "*) ;; *) echo "$v not core";; esac; case " $ROTATABLE_SECRETS " in *" $v "*) ;; *) echo "$v not rotatable";; esac; done' _ "$HERE/..")" ""
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
run init --env-only --non-interactive --runtime podman
expect_eq "init: CONTAINER_RUNTIME=docker in .env, --runtime podman → refused" \
  "$RC:$(printf '%s' "$ERR" | grep -c 'CONTAINER_RUNTIME is docker in .env and is never switched (backup → fresh init → restore)')" "1:1"
RC=0; CONTAINER_RUNTIME=podman "$CLI" init --env-only --non-interactive >/dev/null 2>"$WORK/err" </dev/null || RC=$?
expect_eq "init: CONTAINER_RUNTIME=podman in the environment over a docker .env → refused" "$RC" 1
expect_eq "init: the refusals left CONTAINER_RUNTIME=docker" "$(get CONTAINER_RUNTIME)" docker
# A copied .env.example: no CONTAINER_RUNTIME → the detected value (P0).
sed '/^CONTAINER_RUNTIME=/d' "$ENVF" > "$WORK/e" && cat "$WORK/e" > "$ENVF"
run init --env-only --non-interactive
expect_eq "init: an existing .env without CONTAINER_RUNTIME gets the detected value" \
  "$RC:$(get CONTAINER_RUNTIME):$(printf '%s' "$OUT" | grep -c 'Set CONTAINER_RUNTIME=docker in .env')" "0:docker:1"
# DNS credentials come from the environment, not argv.
rm -f "$ENVF"
RC=0; CLOUDFLARE_API_TOKEN=tok123 "$CLI" init --env-only --non-interactive --domain x.example --dns-provider cloudflare --runtime docker >/dev/null 2>&1 </dev/null || RC=$?
expect_eq "init with provider creds from env" "$RC:$(get CLOUDFLARE_API_TOKEN):$(get DNS_PROVIDER)" "0:tok123:cloudflare"

# ── keycloak configure never touches the Hub's AI clients or mcp:* scopes
# (contract §8) and pushes the realm's offline bounds / refresh-token settings ──
# A stub curl answers the admin API: every request is logged as one JSON
# line {m, p, b}; writes answer 201 (POST) / 204, reads from the fixtures
# below ("[]" for collections, "{}" otherwise).
mkdir -p "$WORK/kcbin" "$WORK/kc"
cp -R "$HERE/../keycloak" "$PORTCULLIS_ROOT/keycloak"
cat > "$WORK/kc/clients.json" <<'JSON'
[{"id":"fwd-uuid","clientId":"portcullis-forward-auth","attributes":{}},
 {"id":"ai-uuid","clientId":"portcullis-ai-claude","attributes":{"portcullis.hub.template":"portcullis-ai"}}]
JSON
cat > "$WORK/kc/scopes.json" <<'JSON'
[{"id":"acr-id","name":"acr"},{"id":"groups-id","name":"groups"},
 {"id":"invite-id","name":"portcullis-invite-client"},{"id":"emailu-id","name":"email-unverified"},
 {"id":"mcp-id","name":"mcp:gitea.gitea","attributes":{"include.in.token.scope":"true"}}]
JSON
cat > "$WORK/kcbin/curl" <<'STUB'
#!/usr/bin/env bash
m=GET url="" w=false body=false
while [ $# -gt 0 ]; do
  case "$1" in
    -X) m="$2"; shift ;;
    -w) w=true; shift ;;
    -o|-H|--max-time|--data-urlencode) shift ;;
    --data-binary) body=true; shift ;;
    http://*|https://*) url="$1" ;;
  esac
  shift
done
p="/${url#*://*/}"
b=""
if $body; then b="$(cat)"; fi
case "$p" in */protocol/openid-connect/token) cat >/dev/null; echo '{"access_token":"stub"}'; exit 0 ;; esac
jq -nc --arg m "$m" --arg p "$p" --arg b "$b" '{m: $m, p: $p, b: $b}' >> "$KC_LOG"
if [ "$m" != GET ]; then
  if [ "$m" = POST ]; then c=201; else c=204; fi
  if $w; then printf '%s' "$c"; fi
  exit 0
fi
R=/admin/realms/portcullis
case "$p" in
  "$R/clients?max=-1") cat "$KC_FIX/clients.json" ;;
  "$R/clients?clientId=portcullis-forward-auth") jq -c '[.[] | select(.clientId == "portcullis-forward-auth")]' "$KC_FIX/clients.json" ;;
  "$R/clients/fwd-uuid") jq -c '.[0]' "$KC_FIX/clients.json" ;;
  "$R/clients/ai-uuid") jq -c '.[1]' "$KC_FIX/clients.json" ;;
  "$R/client-scopes") cat "$KC_FIX/scopes.json" ;;
  "$R/client-scopes/mcp-id") jq -c '.[4]' "$KC_FIX/scopes.json" ;;
  # What configure POSTed / PUT before (the Keycloak it talks to keeps it).
  "$R/client-scopes/acr-id/protocol-mappers/models")
    jq -sc --arg p "$p" '[.[] | select(.m == "POST" and .p == $p) | .b | fromjson]' "$KC_LOG" ;;
  "$R/authentication/required-actions/portcullis-impersonation-notice")
    jq -sc '[.[] | select(.m == "PUT" and (.p | endswith("/required-actions/portcullis-impersonation-notice"))) | .b | fromjson] | last
      // {"alias":"portcullis-impersonation-notice","name":"Impersonation notice","providerId":"portcullis-impersonation-notice","enabled":false,"defaultAction":false,"priority":90,"config":{}}' "$KC_LOG" ;;
  # A drifted passkey policy (the test server's); the realm PUTs configure
  # sent are applied on top unless KC_REALM_KEEP is set (Keycloak 26.8
  # keeping the policy).
  "$R")
    base='{"realm":"portcullis","browserFlow":"portcullis-universal","loginTheme":"portcullis","webAuthnPolicyPasswordlessAttestationConveyancePreference":"none","webAuthnPolicyPasswordlessAuthenticatorAttachment":"cross-platform","webAuthnPolicyPasswordlessRequireResidentKey":"Yes","webAuthnPolicyPasswordlessUserVerificationRequirement":"required"}'
    if [ -n "${KC_REALM_KEEP:-}" ]; then printf '%s' "$base"
    else jq -sc --argjson b "$base" --arg p "$p" 'reduce (.[] | select(.m == "PUT" and .p == $p) | .b | fromjson) as $x ($b; . + $x)' "$KC_LOG"; fi ;;
  "$R/authentication/flows/portcullis-universal/executions")
    echo '[{"providerId":"portcullis-x509","level":2,"authenticationConfig":"x509-id"},{"providerId":"portcullis-x509","level":2,"authenticationConfig":"x509b-id"},{"providerId":"portcullis-x509","level":2,"authenticationConfig":"x509c-id"},{"providerId":"portcullis-method","level":3},{"providerId":"portcullis-template","level":0}]' ;;
  "$R/authentication/config/x509-id") echo '{"id":"x509-id","alias":"x509-config","config":{"default.reference.value":"mtls","default.reference.maxAge":"36000"}}' ;;
  "$R/authentication/config/x509b-id") echo '{"id":"x509b-id","alias":"x509-browser-config","config":{"default.reference.value":"file","default.reference.maxAge":"36000"}}' ;;
  "$R/authentication/config/x509c-id") echo '{"id":"x509c-id","alias":"operator-x509","config":{"default.reference.value":"mtls","default.reference.maxAge":"36000"}}' ;;
  *\?*|*/flows|*/executions|*/client-scopes|*/models|*/instances|*-client-scopes|*/roles) echo '[]' ;;
  *) echo '{}' ;;
esac
STUB
chmod +x "$WORK/kcbin/curl"
: > "$WORK/kc/log"
RC=0
PATH="$WORK/kcbin:$PATH" KC_LOG="$WORK/kc/log" KC_FIX="$WORK/kc" \
  "$CLI" keycloak configure >"$WORK/out" 2>"$WORK/err" </dev/null || RC=$?
expect_eq "keycloak configure (stub admin API) exits 0" "$RC" 0
[ "$RC" = 0 ] || sed 's/^/    /' "$WORK/err" | tail -5
expect_eq "keycloak configure re-read the realm's passkey policy after its PUT (the drifted one fixed)" \
  "$(grep -c 'passkey policy: direct attestation' "$WORK/out")" 1
# Fail closed: Keycloak answered 204 but kept the drifted policy.
: > "$WORK/kc/log"
RC=0
PATH="$WORK/kcbin:$PATH" KC_LOG="$WORK/kc/log" KC_FIX="$WORK/kc" KC_REALM_KEEP=1 \
  "$CLI" keycloak configure >"$WORK/out2" 2>"$WORK/err2" </dev/null || RC=$?
expect_eq "keycloak configure fails when the realm keeps a drifted passkey policy after its PUT" \
  "$RC:$(grep -c "attestation none (wanted direct), attachment cross-platform (wanted not specified)" "$WORK/err2")" "1:1"
expect_eq "keycloak configure stops at the drifted policy (no flow sync after it)" \
  "$(jq -sc '[.[] | select(.p | test("/authentication/flows"))] | length' "$WORK/kc/log")" 0
: > "$WORK/kc/log"
PATH="$WORK/kcbin:$PATH" KC_LOG="$WORK/kc/log" KC_FIX="$WORK/kc" \
  "$CLI" keycloak configure >"$WORK/out" 2>"$WORK/err" </dev/null || true
expect_eq "keycloak configure listed the clients (the AI client was seen)" \
  "$(jq -sr '[.[] | select(.m == "GET" and .p == "/admin/realms/portcullis/clients?max=-1")] | length > 0' "$WORK/kc/log")" true
expect_eq "keycloak configure: no write to the portcullis-ai client or the mcp:* scope" \
  "$(jq -sc '[.[] | select(.m != "GET") | select((.p | test("ai-uuid|mcp-id")) or (.b | test("portcullis-ai|mcp:")))] | map(.m + " " + .p)' "$WORK/kc/log")" '[]'
expect_eq "keycloak configure: realm offline bounds + refresh-token settings pushed" \
  "$(jq -sc '[.[] | select(.m == "PUT" and .p == "/admin/realms/portcullis") | .b | fromjson
      | select(has("revokeRefreshToken")) | {offlineSessionIdleTimeout, offlineSessionMaxLifespanEnabled, offlineSessionMaxLifespan, revokeRefreshToken, refreshTokenMaxReuse}] | unique' "$WORK/kc/log")" \
  '[{"offlineSessionIdleTimeout":2592000,"offlineSessionMaxLifespanEnabled":true,"offlineSessionMaxLifespan":7776000,"revokeRefreshToken":false,"refreshTokenMaxReuse":0}]'
expect_eq "keycloak configure: the amr check walks the new browser flow (a portcullis-method without config warned, x509 not)" \
  "$(grep -c 'portcullis-universal/portcullis-method has no authenticator config' "$WORK/err"):$(grep -c 'portcullis-universal/portcullis-x509' "$WORK/err")" "1:0"
expect_eq "keycloak configure: x509-config pushed onto the portcullis-x509 execution's config" \
  "$(jq -sc '[.[] | select(.m == "PUT" and .p == "/admin/realms/portcullis/authentication/config/x509-id") | .b | fromjson | .config["x509-cert-auth.confirmation-page-disallowed"]]' "$WORK/kc/log")" '["true"]'
# x509_put <config id> — the method, reference, CA and CRL paths keycloak configure PUT there.
x509_put() { jq -sc --arg p "/admin/realms/portcullis/authentication/config/$1" '[.[] | select(.m == "PUT" and .p == $p) | .b | fromjson
    | {alias, m: .config["portcullis.method"], ref: .config["default.reference.value"], ca: .config["portcullis.ca"], crl: .config["x509-cert-auth.crl-relative-path"]}]' "$WORK/kc/log"; }
expect_eq "keycloak configure pushes x509-browser-config onto the browser execution and x509-config onto the YubiKey one (stubbed kc_get / kc_put)" \
  "$(x509_put x509-id) $(x509_put x509b-id)" \
  '[{"alias":"x509-config","m":"yubikey_cert","ref":"mtls","ca":"/opt/keycloak/conf/truststores/portcullis/portcullis-yubikey-ca.pem","crl":"http://vault:8200/v1/pki_int/crl##http://vault:8200/v1/pki_int/crl/delta"}] [{"alias":"x509-browser-config","m":"browser_cert","ref":"file","ca":"/opt/keycloak/conf/truststores/portcullis/portcullis-browser-ca.pem","crl":"http://vault:8200/v1/pki_file/crl##http://vault:8200/v1/pki_file/crl/delta"}]'
expect_eq "keycloak configure: an x509 config with another alias is left alone (warned)" \
  "$(x509_put x509c-id):$(grep -c 'x509 config operator-x509 is not one of' "$WORK/err")" '[]:1'
expect_eq "keycloak configure never touches the events config (no events request, no events keys in a realm PUT)" \
  "$(jq -sc '[.[] | select((.p | test("/events")) or (.m == "PUT" and .p == "/admin/realms/portcullis" and (.b | fromjson | keys | any(test("^(events|enabledEventTypes|adminEvents)")))))] | length' "$WORK/kc/log")" 0
expect_eq "keycloak configure: realm PUT has brute force (D6) and an empty acr.loa.map" \
  "$(jq -sc '[.[] | select(.m == "PUT" and .p == "/admin/realms/portcullis") | .b | fromjson
      | select(has("bruteForceProtected")) | {bruteForceProtected, failureFactor, waitIncrementSeconds, maxFailureWaitSeconds, permanentLockout, loa: .attributes["acr.loa.map"]}] | unique' "$WORK/kc/log")" \
  '[{"bruteForceProtected":true,"failureFactor":10,"waitIncrementSeconds":60,"maxFailureWaitSeconds":900,"permanentLockout":false,"loa":"{}"}]'
expect_eq "keycloak configure: forward-auth client PUT drops default.acr.values" \
  "$(jq -sc '[.[] | select(.m == "PUT" and .p == "/admin/realms/portcullis/clients/fwd-uuid") | .b | fromjson | .attributes["default.acr.values"] // "none"] | unique' "$WORK/kc/log")" '[""]'
expect_eq "keycloak configure: stock webauthn-register (two-factor) required action disabled" \
  "$(jq -sc '[.[] | select(.m == "PUT" and .p == "/admin/realms/portcullis/authentication/required-actions/webauthn-register") | .b | fromjson | .enabled] | unique' "$WORK/kc/log")" '[false]'
expect_eq "keycloak configure (stub admin API): the impersonation mapper POSTed onto the acr scope, the disabled notice action enabled (never registered)" \
  "$(jq -sc '[.[] | select(.m != "GET") | select(.p | test("acr-id/protocol-mappers|required-actions/portcullis-impersonation-notice")) | .m + " " + .p + " " + (.b | fromjson | .protocolMapper // (.enabled | tostring))]' "$WORK/kc/log")" \
  '["POST /admin/realms/portcullis/client-scopes/acr-id/protocol-mappers/models oidc-amr-mapper","POST /admin/realms/portcullis/client-scopes/acr-id/protocol-mappers/models portcullis-impersonation","PUT /admin/realms/portcullis/authentication/required-actions/portcullis-impersonation-notice true"]'

# ── keycloak configure: the impersonation mapper and the notice action
# (contract §8, sign-in part 3; F5), with kc_get / kc_send stubbed ──
# imp_configure <mappers JSON> <required action JSON> — runs the two steps
# against the fixtures; prints one line per write "<METHOD> <path> <body>".
imp_configure() {
  (
    export KC_IMP_MAPPERS="$1" KC_IMP_RA="$2" KC_IMP_LOG="$WORK/imp-log"
    : > "$KC_IMP_LOG"
    # shellcheck disable=SC1091
    . "$HERE/../scripts/lib/common.sh"
    # shellcheck disable=SC1091
    . "$HERE/../scripts/lib/keycloak.sh"
    kc_get() {
      case "$1" in
        */client-scopes/acr-id/protocol-mappers/models)
          # A POST that "took" (KC_IMP_KEEP unset) shows up in the next GET.
          if [ -z "${KC_IMP_KEEP:-}" ] && grep -q '^POST .*/protocol-mappers/models' "$KC_IMP_LOG"; then
            jq -c '. + [{"name":"impersonation","protocolMapper":"portcullis-impersonation"}]' <<<"$KC_IMP_MAPPERS"
          else printf '%s' "$KC_IMP_MAPPERS"; fi ;;
        */authentication/required-actions/portcullis-impersonation-notice)
          if [ -z "${KC_IMP_KEEP:-}" ] && grep -q '^PUT .*/required-actions/' "$KC_IMP_LOG"; then
            grep '^PUT .*/required-actions/' "$KC_IMP_LOG" | tail -n1 | cut -d' ' -f3-
          else printf '%s' "$KC_IMP_RA"; fi ;;
        *) echo '{}' ;;
      esac
    }
    kc_send() { printf '%s %s %s\n' "$1" "$2" "$(jq -cS . 2>/dev/null)" >> "$KC_IMP_LOG"; if [ "$1" = POST ]; then echo 201; else echo 204; fi; }
    rc=0
    ( _kc_impersonation_mapper acr-id >/dev/null 2>&1 ) || rc=$?
    [ "$rc" = 0 ] || { cat "$KC_IMP_LOG"; echo "mapper exit $rc"; exit 0; }
    ( _kc_impersonation_notice >/dev/null 2>&1 ) || rc=$?
    cat "$KC_IMP_LOG"
    [ "$rc" = 0 ] || echo "notice exit $rc"
  )
}
R=/portcullis
IMP_RA_ON='{"alias":"portcullis-impersonation-notice","name":"Impersonation notice","providerId":"portcullis-impersonation-notice","enabled":true,"defaultAction":false,"priority":90,"config":{}}'
expect_eq "keycloak configure ensures the impersonation mapper on acr (once, by protocolMapper) and the required action (stubbed kc_get / kc_send): no mapper, the action disabled at another priority → mapper POSTed, action enabled at 90" \
  "$(imp_configure '[{"name":"amr","protocolMapper":"oidc-amr-mapper"}]' "$(jq -c '.enabled = false | .priority = 120' <<<"$IMP_RA_ON")")" \
  "POST $R/client-scopes/acr-id/protocol-mappers/models {\"config\":{\"access.token.claim\":\"true\",\"id.token.claim\":\"true\",\"userinfo.token.claim\":\"true\"},\"name\":\"impersonation\",\"protocol\":\"openid-connect\",\"protocolMapper\":\"portcullis-impersonation\"}
PUT $R/authentication/required-actions/portcullis-impersonation-notice {\"alias\":\"portcullis-impersonation-notice\",\"config\":{},\"defaultAction\":false,\"enabled\":true,\"name\":\"Impersonation notice\",\"priority\":90,\"providerId\":\"portcullis-impersonation-notice\"}"
expect_eq "keycloak configure fails, without registering or PUTting it, when the realm lacks the notice action (a fresh realm import has it)" \
  "$(imp_configure '[{"protocolMapper":"portcullis-impersonation"}]' '' | tail -n1):$(imp_configure '[{"protocolMapper":"portcullis-impersonation"}]' '{}' | grep -c required-action || true)" \
  "notice exit 1:0"
expect_eq "keycloak configure: a mapper with protocolMapper portcullis-impersonation (any name) and the enabled action → no write" \
  "$(imp_configure '[{"name":"amr","protocolMapper":"oidc-amr-mapper"},{"name":"renamed","protocolMapper":"portcullis-impersonation"}]' "$IMP_RA_ON")" ""
expect_eq "keycloak configure: the action registered but disabled (or a default action) → one PUT, no registration" \
  "$(imp_configure '[{"protocolMapper":"portcullis-impersonation"}]' "$(jq -c '.enabled = false' <<<"$IMP_RA_ON")" | cut -d' ' -f1-2):$(imp_configure '[{"protocolMapper":"portcullis-impersonation"}]' "$(jq -c '.defaultAction = true' <<<"$IMP_RA_ON")" | jq -Rr 'split(" ")[2:] | join(" ") | fromjson | .defaultAction')" \
  "PUT $R/authentication/required-actions/portcullis-impersonation-notice:false"
# Fail closed (contract §8.1): configure stops (non-zero) when the mapper
# or the action isn't there afterwards.
expect_eq "keycloak configure fails when the impersonation mapper POST doesn't take (the acr scope still lacks it)" \
  "$(KC_IMP_KEEP=1 imp_configure '[]' "$IMP_RA_ON" | tail -n1)" "mapper exit 1"
expect_eq "keycloak configure fails when the acr scope's mappers can't be read (never 'present')" \
  "$(imp_configure '' "$IMP_RA_ON")" "mapper exit 1"
expect_eq "keycloak configure fails with two portcullis-impersonation mappers on acr" \
  "$(imp_configure '[{"protocolMapper":"portcullis-impersonation"},{"name":"x","protocolMapper":"portcullis-impersonation"}]' "$IMP_RA_ON")" "mapper exit 1"
expect_eq "keycloak configure fails when the notice action is still missing or disabled afterwards" \
  "$(KC_IMP_KEEP=1 imp_configure '[{"protocolMapper":"portcullis-impersonation"}]' "$(jq -c '.enabled = false' <<<"$IMP_RA_ON")" | tail -n1):$(KC_IMP_KEEP=1 imp_configure '[{"protocolMapper":"portcullis-impersonation"}]' '' | tail -n1)" \
  "notice exit 1:notice exit 1"
expect_eq "keycloak configure's impersonation steps never touch the events config" \
  "$(imp_configure '[]' '' | grep -c events || true)" 0

# ── status: the realm's passkey policy (contract §8.1 "Passkey kinds"),
# with kc_get stubbed: a drifted one fails status (a ✗ line, --json
# keycloak.passkey_policy, the textfile gauge) ──
PK_REALM_OK='{"realm":"portcullis","webAuthnPolicyPasswordlessAttestationConveyancePreference":"direct","webAuthnPolicyPasswordlessAuthenticatorAttachment":"not specified","webAuthnPolicyPasswordlessRequireResidentKey":"Yes","webAuthnPolicyPasswordlessUserVerificationRequirement":"required"}'
# pk_status <realm JSON> <two-factor action enabled> <json|text|textfile> — status_run's output, then "rc <n>".
pk_status() {
  (
    export PK_REALM="$1" PK_2FA="$2" KEYCLOAK_ADMIN_PASSWORD=stub CONTAINER_RUNTIME=docker
    for l in common keycloak status; do
      # shellcheck disable=SC1090
      . "$HERE/../scripts/lib/$l.sh"
    done
    dc() { echo '{"Service":"keycloak","State":"running","Health":"healthy","Status":"Up"}'; }
    vault_health_code() { echo 200; }
    vault_admin_env() { return 1; }
    rt_health() { echo healthy; }
    proxy_dns_shadows() { :; }
    domains_status_lines() { :; }
    _st_mcp_refusing() { :; }
    kc_login() { :; }
    metrics_textfile_write() { cat; }
    kc_get() {
      case "$1" in
        /portcullis) printf '%s' "$PK_REALM" ;;
        /portcullis/users/count) echo 3 ;;
        "/portcullis/clients?clientId=portcullis-forward-auth") echo '[{"id":"fwd"}]' ;;
        /portcullis/authentication/required-actions/webauthn-register-passwordless) echo '{"alias":"webauthn-register-passwordless","enabled":true}' ;;
        /portcullis/authentication/required-actions/webauthn-register) printf '{"alias":"webauthn-register","enabled":%s}' "$PK_2FA" ;;
        *) echo '{}' ;;
      esac
    }
    rc=0
    case "$3" in
      json) status_run true || rc=$? ;;
      textfile) status_textfile || rc=$? ;;
      *) status_run false 2>&1 || rc=$? ;;
    esac
    echo "rc $rc"
  )
}
expect_eq "status --json: the wanted passkey policy → ok, status ok" \
  "$(pk_status "$PK_REALM_OK" false json | jq -c 'select(type == "object") | [.ok, .keycloak.passkey_policy]')" '[true,{"ok":true,"problems":[]}]'
expect_eq "status: the wanted passkey policy → a ✓ line, exit 0" \
  "$(pk_status "$PK_REALM_OK" false text | grep -c '✓ passkey policy: direct attestation'):$(pk_status "$PK_REALM_OK" false text | tail -n1)" "1:rc 0"
PK_REALM_BAD="$(jq -c '.webAuthnPolicyPasswordlessAttestationConveyancePreference = "none" | .webAuthnPolicyPasswordlessAuthenticatorAttachment = "cross-platform"' <<<"$PK_REALM_OK")"
expect_eq "status: attestation none / cross-platform (the test server's drift) → a ✗ line naming both, exit 1" \
  "$(pk_status "$PK_REALM_BAD" false text | grep -F '✗' | sed 's/\x1b\[[0-9;]*m//g'):$(pk_status "$PK_REALM_BAD" false text | tail -n1)" \
  "  ✗ passkey policy: attestation none (wanted direct), attachment cross-platform (wanted not specified) — new passkeys can't be told apart; run ./portcullis keycloak configure:rc 1"
expect_eq "status --json: a drifted policy → ok false, the problems listed" \
  "$(pk_status "$PK_REALM_BAD" false json | jq -c 'select(type == "object") | [.ok, .keycloak.passkey_policy]')" \
  '[false,{"ok":false,"problems":["attestation none (wanted direct)","attachment cross-platform (wanted not specified)"]}]'
expect_eq "status --json: resident key / UV unset, the two-factor webauthn-register on → each a problem" \
  "$(pk_status "$(jq -c 'del(.webAuthnPolicyPasswordlessRequireResidentKey) | .webAuthnPolicyPasswordlessUserVerificationRequirement = "preferred"' <<<"$PK_REALM_OK")" true json | jq -c 'select(type == "object") | .keycloak.passkey_policy.problems')" \
  '["resident key unset (wanted Yes)","user verification preferred (wanted required)","required action webauthn-register enabled (wanted disabled)"]'
expect_eq "status --json: an unreadable realm or action → not ok (fail closed)" \
  "$(pk_status '' '"x"' json | jq -c 'select(type == "object") | .keycloak.passkey_policy.problems')" \
  "[\"the realm can't be read\",\"required action webauthn-register can't be read\"]"
expect_eq "status --textfile: portcullis_keycloak_passkey_policy_ok 1 / 0" \
  "$(pk_status "$PK_REALM_OK" false textfile | grep '^portcullis_keycloak_passkey_policy_ok '):$(pk_status "$PK_REALM_BAD" false textfile | grep '^portcullis_keycloak_passkey_policy_ok ')" \
  "portcullis_keycloak_passkey_policy_ok 1:portcullis_keycloak_passkey_policy_ok 0"

# ── realm-export.json: the sign-in flows of contract §8.1 (D6) ──
RX="$HERE/../keycloak/realm-export.json"
# flow <alias> — "<requirement> <authenticator or flowAlias>" per execution, by priority.
flow() { jq -c --arg a "$1" '[.authenticationFlows[] | select(.alias == $a) | .authenticationExecutions | sort_by(.priority)[]
    | .requirement + " " + (.authenticator // .flowAlias)]' "$RX"; }
# cfg <alias> <execution> — the config of an execution (authenticator or flowAlias) of a flow.
cfg() { jq -c --arg a "$1" --arg e "$2" '.authenticatorConfig as $c | [.authenticationFlows[] | select(.alias == $a) | .authenticationExecutions[]
    | select((.authenticator // .flowAlias) == $e) | .authenticatorConfig as $n | $c[] | select(.alias == $n) | .config][0]' "$RX"; }
expect_eq "realm export: portcullis-universal is REQUIRED portcullis-authenticate + REQUIRED portcullis-template" \
  "$(flow portcullis-universal)" '["REQUIRED portcullis-authenticate","REQUIRED portcullis-template"]'
expect_eq "realm export: portcullis-universal is the browser flow" "$(jq -r .browserFlow "$RX")" portcullis-universal
expect_eq "realm export: portcullis-authenticate = cookie | invite redirector | portcullis-signin" \
  "$(flow portcullis-authenticate)" '["ALTERNATIVE auth-cookie","ALTERNATIVE identity-provider-redirector","ALTERNATIVE portcullis-signin"]'
expect_eq "realm export: portcullis-signin = x509 | x509 | passkey sub-flow | password form" \
  "$(flow portcullis-signin)" '["ALTERNATIVE portcullis-x509","ALTERNATIVE portcullis-x509","ALTERNATIVE portcullis-signin-passkey","ALTERNATIVE portcullis-password-form"]'
expect_eq "realm-export: portcullis-signin = x509 (x509-config, mtls, yubikey CA), x509 (x509-browser-config, file, browser CA), passkey sub-flow, password form, in that order" \
  "$(jq -c '.authenticatorConfig as $c | [.authenticationFlows[] | select(.alias == "portcullis-signin") | .authenticationExecutions | sort_by(.priority)[]
      | (.authenticatorConfig // "") as $n | [.priority, (.authenticator // .flowAlias), $n,
         ([$c[] | select(.alias == $n) | .config | .["default.reference.value"], .["portcullis.method"], .["portcullis.ca"]] | map(. // "") | join(" "))]]' "$RX")" \
  '[[10,"portcullis-x509","x509-config","mtls yubikey_cert /opt/keycloak/conf/truststores/portcullis/portcullis-yubikey-ca.pem"],[20,"portcullis-x509","x509-browser-config","file browser_cert /opt/keycloak/conf/truststores/portcullis/portcullis-browser-ca.pem"],[30,"portcullis-signin-passkey","",""],[40,"portcullis-password-form","password-config","pwd  "]]'
expect_eq "realm-export: each x509 config's CRL paths name only its own mount" \
  "$(jq -c '[.authenticatorConfig[] | select(.config | has("portcullis.method")) | {(.alias): .config["x509-cert-auth.crl-relative-path"]}] | add' "$RX")" \
  '{"x509-config":"http://vault:8200/v1/pki_int/crl##http://vault:8200/v1/pki_int/crl/delta","x509-browser-config":"http://vault:8200/v1/pki_file/crl##http://vault:8200/v1/pki_file/crl/delta"}'
expect_eq "realm-export: both x509 configs check CRLs, abort on a stale CRL and keep the same X.509 settings" \
  "$(jq -c '[.authenticatorConfig[] | select(.config | has("portcullis.method")) | .config
      | del(.["portcullis.method"], .["portcullis.ca"], .["default.reference.value"], .["x509-cert-auth.crl-relative-path"])] | (unique | length), .[0]["x509-cert-auth.crl-checking-enabled"], .[0]["x509-cert-auth-crl-abort-if-non-updated"]' "$RX" | tr '\n' ' ')" '1 "true" "true" '
expect_eq "realm-export: events LOGIN, LOGIN_ERROR, IMPERSONATE, expiration 31536000" \
  "$(jq -c '[.eventsEnabled, (.enabledEventTypes | sort), .eventsExpiration]' "$RX")" '[true,["IMPERSONATE","LOGIN","LOGIN_ERROR"],31536000]'
expect_eq "realm-export: requiredActions has exactly the pinned portcullis-impersonation-notice entry; enabledEventTypes ⊇ LOGIN, LOGIN_ERROR, IMPERSONATE; no clientScopes" \
  "$(jq -cS '[.requiredActions[] | select(.alias == "portcullis-impersonation-notice" or .providerId == "portcullis-impersonation-notice")]' "$RX"):$(jq '.enabledEventTypes | contains(["LOGIN","LOGIN_ERROR","IMPERSONATE"])' "$RX"):$(jq 'has("clientScopes")' "$RX")" \
  "$(jq -cS '[.]' <<<'{"alias":"portcullis-impersonation-notice","name":"Impersonation notice","providerId":"portcullis-impersonation-notice","enabled":true,"defaultAction":false,"priority":90,"config":{}}'):true:false"
expect_eq "realm-export: no impersonation mapper anywhere (keycloak configure adds it, F5)" \
  "$(jq '[.. | objects | select(.protocolMapper? == "portcullis-impersonation")] | length' "$RX")" 0
expect_eq "realm export: portcullis-signin-passkey = REQUIRED portcullis-passkey + one CONDITIONAL sub-flow per kind" \
  "$(flow portcullis-signin-passkey)" '["REQUIRED portcullis-passkey","CONDITIONAL portcullis-passkey-security-key","CONDITIONAL portcullis-passkey-device","CONDITIONAL portcullis-passkey-synced"]'
for k in security-key:security_key:hwk device:passkey_device:dpk synced:passkey_synced:spk; do
  IFS=: read -r sub kind amr <<<"$k"
  expect_eq "realm export: portcullis-passkey-$sub = kind condition + portcullis-method" \
    "$(flow "portcullis-passkey-$sub")" '["REQUIRED portcullis-condition-passkey-kind","REQUIRED portcullis-method"]'
  expect_eq "realm export: portcullis-passkey-$sub condition kind $kind" \
    "$(cfg "portcullis-passkey-$sub" portcullis-condition-passkey-kind)" "{\"kind\":\"$kind\"}"
  expect_eq "realm export: portcullis-passkey-$sub method $kind, reference $amr" \
    "$(cfg "portcullis-passkey-$sub" portcullis-method | jq -c '{method, ref: .["default.reference.value"]}')" "{\"method\":\"$kind\",\"ref\":\"$amr\"}"
done
expect_eq "realm export: portcullis-x509 reference mtls, confirmation page disallowed" \
  "$(cfg portcullis-signin portcullis-x509 | jq -c '[.["default.reference.value"], .["x509-cert-auth.confirmation-page-disallowed"], .["x509-cert-auth.crl-checking-enabled"]]')" '["mtls","true","true"]'
expect_eq "realm export: portcullis-password-form reference pwd" \
  "$(cfg portcullis-signin portcullis-password-form | jq -r '.["default.reference.value"]')" pwd
expect_eq "no conditional-level-of-authentication anywhere" \
  "$(jq '[.. | strings | select(test("level-of-authentication|loa-"))] | length' "$RX")" 0
expect_eq "realm export: acr.loa.map is {}" "$(jq -r '.attributes["acr.loa.map"]' "$RX")" '{}'
expect_eq "every reference config has maxAge 36000" \
  "$(jq -c '[.authenticatorConfig[].config | select(has("default.reference.value")) | .["default.reference.maxAge"]] | unique' "$RX")" '["36000"]'
expect_eq "realm export: every amr of the browser and invite flows has a reference config" \
  "$(jq -c '[.authenticatorConfig[].config | .["default.reference.value"] // empty] | sort' "$RX")" '["dpk","file","hwk","inv","mtls","pwd","spk"]'
expect_eq "realm export: the invite post-broker flow keeps admit / deny, records inv, ends with portcullis-template" \
  "$(flow portcullis-invite-session)" '["CONDITIONAL portcullis-invite-client","CONDITIONAL portcullis-invite-deny","REQUIRED allow-access-authenticator","REQUIRED portcullis-template"]'
expect_eq "invite amr configs say inv" \
  "$(jq -c '.authenticatorConfig as $c | [.authenticationFlows[] | select(.alias | startswith("portcullis-invite")) | .authenticationExecutions[]
      | .authenticatorConfig // empty | . as $n | $c[] | select(.alias == $n) | .config | .["default.reference.value"] // empty]' "$RX")" '["inv"]'
expect_eq "realm export: the invite admit / deny sub-flows are unchanged" \
  "$(flow portcullis-invite-client) $(flow portcullis-invite-deny)" \
  '["REQUIRED conditional-client-scope","REQUIRED allow-access-authenticator"] ["REQUIRED conditional-sub-flow-executed","REQUIRED deny-access-authenticator"]'
expect_eq "bruteForceProtected true" \
  "$(jq -c '[.bruteForceProtected, .failureFactor, .waitIncrementSeconds, .maxFailureWaitSeconds, .permanentLockout]' "$RX")" '[true,10,60,900,false]'
expect_eq "realm export: passwordless policy direct, any attachment, resident key + UV required" \
  "$(jq -c '[.webAuthnPolicyPasswordlessAttestationConveyancePreference, .webAuthnPolicyPasswordlessAuthenticatorAttachment, .webAuthnPolicyPasswordlessRequireResidentKey, .webAuthnPolicyPasswordlessUserVerificationRequirement]' "$RX")" \
  '["direct","not specified","Yes","required"]'
expect_eq "keycloak configure's sign-in settings name the passwordless RP (Keycloak applies the policy only then) as the export does" \
  "$(PORTCULLIS_LIB="$HERE/../scripts/lib" bash -c 'source "$PORTCULLIS_LIB/keycloak.sh" 2>/dev/null; printf "%s" "$KC_REALM_SIGNIN_SETTINGS"' | jq -r .webAuthnPolicyPasswordlessRpEntityName)" \
  "$(jq -r .webAuthnPolicyPasswordlessRpEntityName "$RX")"
expect_eq "realm export: stock webauthn-register (two-factor) disabled, passwordless enabled" \
  "$(jq -c '[.requiredActions[] | select(.alias | startswith("webauthn-register")) | [.alias, .enabled]] | sort' "$RX")" '[["webauthn-register",false],["webauthn-register-passwordless",true]]'
expect_eq "realm export: forward-auth client has no default.acr.values" \
  "$(jq -c '.clients[] | select(.clientId == "portcullis-forward-auth") | .attributes | has("default.acr.values")' "$RX")" false
expect_eq "realm export: every authenticator config is used by exactly one execution" \
  "$(jq -c '[.authenticationFlows[].authenticationExecutions[].authenticatorConfig // empty] as $u | [.authenticatorConfig[].alias | . as $a | ($u | map(select(. == $a)) | length)] | unique' "$RX")" '[1]'
expect_eq "realm export: every sub-flow an execution names exists" \
  "$(jq -c '[.authenticationFlows[].alias] as $f | [.authenticationFlows[].authenticationExecutions[] | .flowAlias // empty | select(. as $x | $f | index($x) | not)]' "$RX")" '[]'

# ── docker-compose.yml: Keycloak is the portcullis-keycloak image ──
KC_SVC="$(awk '/^  keycloak:$/ {on = 1; next} on && /^  [a-z]/ {exit} on' "$HERE/../docker-compose.yml")"
# shellcheck disable=SC2016  # a literal ${KEYCLOAK_IMAGE:-...}
expect_eq 'compose keycloak image is ${KEYCLOAK_IMAGE:-ghcr.io/porelli/portcullis-keycloak:edge}' \
  "$(printf '%s\n' "$KC_SVC" | sed -n 's/^    image: //p')" '${KEYCLOAK_IMAGE:-ghcr.io/porelli/portcullis-keycloak:edge}'
expect_eq "keycloak mounts hub_data read-only at /hub-data" \
  "$(printf '%s\n' "$KC_SVC" | grep -cxF '      - hub_data:/hub-data:ro')" 1
expect_eq "keycloak command disables the impersonation feature (and no KC_FEATURES* env could re-enable it)" \
  "$(printf '%s\n' "$KC_SVC" | grep -cxF -- '      - --features-disabled=impersonation'):$(printf '%s\n' "$KC_SVC" | grep -cE -- '--features(-enabled)?=.*impersonation' || true):$(cat "$HERE"/../docker-compose*.yml | grep -cE '^[[:space:]]*-?[[:space:]]*KC_FEATURES' || true)" "1:0:0"
# shellcheck disable=SC2016  # a literal ${PORTCULLIS_DOMAIN:-...}
expect_eq "keycloak gets PORTCULLIS_PORTAL_URL = the portal" \
  "$(printf '%s\n' "$KC_SVC" | sed -n 's/^      PORTCULLIS_PORTAL_URL: //p')" 'https://${PORTCULLIS_DOMAIN:-portcullis.local}/'
expect_eq "every forward-auth middleware's authResponseHeaders lists X-Forwarded-Impersonator and X-Forwarded-Impersonation" \
  "$(sed -n 's/^      traefik\.http\.middlewares\.\([a-z-]*\)\.forwardauth\.authResponseHeaders: \(.*\)$/\1 \2/p' "$HERE/../docker-compose.yml" \
      | while read -r mw hdrs; do
          if printf ',%s,' "$hdrs" | grep -q ',X-Forwarded-Impersonator,' && printf ',%s,' "$hdrs" | grep -q ',X-Forwarded-Impersonation,'; then
            echo "$mw"
          else echo "$mw: missing an impersonation header"; fi
        done | sort | tr '\n' ' ')" "portcullis-auth portcullis-auth-console portcullis-auth-ext portcullis-groups portcullis-groups-vpn "
# The login theme passes the extension's hints to the registration script.
expect_eq "theme: webauthn-register.ftl hands portcullisHints to webauthnRegister.js" \
  "$(grep -cF 'portcullisHints : ${(portcullisHints!"[]")?c}' "$HERE/../keycloak/themes/portcullis/login/webauthn-register.ftl" 2>/dev/null || echo 0)" 1
expect_eq "theme: webauthnRegister.js asks for direct attestation and sets hints" \
  "$(grep -cE 'attestation = "direct"|publicKey\.hints = ' "$HERE/../keycloak/themes/portcullis/login/resources/js/webauthnRegister.js")" 2

# ── Hub startup race fix: init starts hub after lldap_service_account,
# up/upgrade restart hub only when the account changed ──
# Mock docker compose to track calls: config --services returns the service list,
# up/restart are logged. lldap_service_account is stubbed to return 0 (unchanged)
# or 1 (changed) based on a signal file.
mkdir -p "$WORK/dcbin"
DC_CALLS="$WORK/dc-calls"
cat > "$WORK/dcbin/docker" <<DCSTUB
#!/usr/bin/env bash
[ "\$1 \$3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
if [ "\$1" != compose ]; then exit 0; fi
shift
# Skip --project-directory and its value
if [ "\$1" = "--project-directory" ]; then shift 2; fi
# Now \$1 should be the command (config, up, restart, etc.)
cmd="\$1"
shift
# Handle config --services specially
if [ "\$cmd" = "config" ] && [ "\$1" = "--services" ]; then
  printf 'vault\nlldap\nkeycloak\nhub\ntraefik\n'
  exit 0
fi
# For other commands, filter out -d, --build and --no-build, log the rest
args=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    -d|--build|--no-build) shift; continue ;;
    *) args="\$args \$1"; shift ;;
  esac
done
printf '%s%s\n' "\$cmd" "\$args" >> "$DC_CALLS"
exit 0
DCSTUB
chmod +x "$WORK/dcbin/docker"
# Stub rt_health: returns "healthy" for vault/lldap/keycloak, "healthy" for hub (its image HEALTHCHECK).
cat > "$WORK/test-init-stub.sh" <<INITSTUB
rt_health() {
  case "\$1" in
    vault|lldap|keycloak|postgres) echo healthy ;;
    hub) echo healthy ;;
    *) echo missing ;;
  esac
}
wait_healthy() {
  local timeout="\$1"; shift
  for svc in "\$@"; do
    [ "\$(rt_health "\$svc")" = healthy ] || return 1
  done
}
# Stub the functions init_run calls that touch Vault/Keycloak/DNS.
vault_init() { :; }
pki_setup() { :; }
config_build_ca_bundle() { :; }
config_apply() { :; }
keycloak_configure() { :; }
oidc_register() { :; }
network_check() { :; }
stack_prepare() { :; }
sessions_restart_if_changed() { echo sessions_restart_if_changed >> "$DC_CALLS"; }
dns_setup() { [ \$# -eq 3 ] || { echo "dns_setup: want 3 arguments" >&2; return 1; }; }
dns_tighten_main() { wc -l < "$DC_CALLS" | tr -d " " > "$WORK/tighten-at"; }
config_init() { :; }
invite_create() { echo '{"url":"http://test","expires_at":"never"}'; }
lldap_service_account() {
  LLDAP_SA_CHANGED=false
  [ -f "\$LLDAP_ACCOUNT_CHANGED" ] && LLDAP_SA_CHANGED=true
  return 0
}
INITSTUB
# Source the common + stack libs with the stubs.
LLDAP_ACCOUNT_CHANGED="$WORK/lldap-changed"
rm -f "$LLDAP_ACCOUNT_CHANGED" "$DC_CALLS"
(
  export PATH="$WORK/dcbin:$PATH" LLDAP_ACCOUNT_CHANGED
  # shellcheck disable=SC1091
  . "$HERE/../scripts/lib/common.sh"
  # shellcheck disable=SC1091
  . "$WORK/test-init-stub.sh"
  # shellcheck disable=SC1091
  . "$HERE/../scripts/lib/stack.sh"
  # Call init_run (env_only=false, skip_dns=true, config_repo=false).
  init_run ci.example.org admin@ci.example.org none false true false >/dev/null 2>&1 || true
)
calls="$(cat "$DC_CALLS" 2>/dev/null || true)"
expect_eq "init: first up excludes hub" \
  "$(printf '%s\n' "$calls" | grep -c '^up.*vault.*lldap.*keycloak' || true)" 1
expect_eq "init: the session store's restart check runs before the first up" \
  "$(printf '%s\n' "$calls" | grep -E '^(sessions_restart_if_changed|up)' | head -n2 | paste -sd' ' - | cut -c1-30)" "sessions_restart_if_changed up"
expect_eq "init: first up does not include hub in the list" \
  "$(printf '%s\n' "$calls" | grep '^up' | head -1 | grep -c 'hub' || true)" 0
expect_eq "init: hub started after the service account step" \
  "$(printf '%s\n' "$calls" | grep -n 'up' | tail -1 | cut -d: -f1)" \
  "$(printf '%s\n' "$calls" | wc -l | tr -d ' ')"
expect_eq "init: second up is 'up hub'" \
  "$(printf '%s\n' "$calls" | tail -1 | tr -s ' ')" "up hub"
expect_eq "init: tighten runs at the end (after the Hub's up)" "$(cat "$WORK/tighten-at" 2>/dev/null)" "$(printf '%s\n' "$calls" | wc -l | tr -d ' ')"

# Test stack_up and upgrade_run: restart hub only when lldap_service_account changed.
# Set up VAULT_INIT_FILE
VAULT_INIT_FILE="$PORTCULLIS_ROOT/secrets/vault-init.json"
mkdir -p "$PORTCULLIS_ROOT/secrets"
echo '{}' > "$VAULT_INIT_FILE"
cat > "$WORK/test-up-stub.sh" <<UPSTUB
rt_health() {
  case "\$1" in vault|lldap|keycloak|postgres) echo healthy ;; *) echo running ;; esac
}
wait_healthy() {
  local timeout="\$1"; shift
  for svc in "\$@"; do [ "\$(rt_health "\$svc")" = healthy ] || return 1; done
}
vault_init() { :; }
pki_setup() { PKI_CREATED=false; PKI_TRUSTSTORE_CHANGED=false; }
config_build_ca_bundle() { :; }
config_apply() { :; }
keycloak_configure() { :; }
oidc_register() { :; }
network_check() { :; }
stack_prepare() { :; }
domains_restart_if_renewed() { :; }
monitoring_reload() { :; }
sessions_restart_if_changed() { echo sessions_restart_if_changed >> "$DC_CALLS"; }
hub_pinned_warn() { :; }
backup_create() { :; }
hub_policy_check() { :; }
hub_sources_sync() { :; }
dns_tighten_main() { echo dns_tighten_main >> "$DC_CALLS"; }
lldap_service_account() {
  LLDAP_SA_CHANGED=false
  [ -f "\$LLDAP_ACCOUNT_CHANGED" ] && LLDAP_SA_CHANGED=true
  return 0
}
UPSTUB
# stack_up when account unchanged: no restart.
rm -f "$LLDAP_ACCOUNT_CHANGED" "$DC_CALLS"
(
  export PATH="$WORK/dcbin:$PATH" LLDAP_ACCOUNT_CHANGED PORTCULLIS_ROOT VAULT_INIT_FILE
  export PORTCULLIS_DOMAIN=test.example POSTGRES_PASSWORD=x KEYCLOAK_ADMIN_PASSWORD=x CONTAINER_RUNTIME=docker
  export LLDAP_ADMIN_PASSWORD=x LLDAP_JWT_SECRET=x FORWARD_AUTH_CLIENT_SECRET=x
  export FORWARD_AUTH_COOKIE_SECRET=x FORWARD_AUTH_REDIS_PASSWORD=x FORWARD_AUTH_EXT_REDIS_PASSWORD=y HUB_PROXY_SECRET=x
  # shellcheck disable=SC1091
  . "$HERE/../scripts/lib/common.sh"
  # shellcheck disable=SC1091
  . "$WORK/test-up-stub.sh"
  # shellcheck disable=SC1091
  . "$HERE/../scripts/lib/stack.sh"
  stack_up >/dev/null 2>&1 || true
)
expect_eq "up: account unchanged, no hub restart" \
  "$(grep -c '^restart.*hub' "$DC_CALLS" 2>/dev/null || true)" 0
# A changed session-store config is applied (restart) before compose recreates the oauth2-proxies.
expect_eq "up: the session store's restart check runs before docker compose up" \
  "$(grep -E '^(sessions_restart_if_changed|up)' "$DC_CALLS" | head -n2 | paste -sd' ' -)" "sessions_restart_if_changed up"
# The local images are built before the first up recreates anything
# (test server 2026-11-13: a build next to Keycloak's restart).
expect_eq "up: the local images are built before the first docker compose up" \
  "$(grep -E '^(build|up)( |$)' "$DC_CALLS" | head -n2 | paste -sd'|' -)" "build --quiet|up"

# stack_up when account changed: restart hub.
touch "$LLDAP_ACCOUNT_CHANGED"
rm -f "$DC_CALLS"
(
  export PATH="$WORK/dcbin:$PATH" LLDAP_ACCOUNT_CHANGED PORTCULLIS_ROOT VAULT_INIT_FILE
  export PORTCULLIS_DOMAIN=test.example POSTGRES_PASSWORD=x KEYCLOAK_ADMIN_PASSWORD=x CONTAINER_RUNTIME=docker
  export LLDAP_ADMIN_PASSWORD=x LLDAP_JWT_SECRET=x FORWARD_AUTH_CLIENT_SECRET=x
  export FORWARD_AUTH_COOKIE_SECRET=x FORWARD_AUTH_REDIS_PASSWORD=x FORWARD_AUTH_EXT_REDIS_PASSWORD=y HUB_PROXY_SECRET=x
  # shellcheck disable=SC1091
  . "$HERE/../scripts/lib/common.sh"
  # shellcheck disable=SC1091
  . "$WORK/test-up-stub.sh"
  # shellcheck disable=SC1091
  . "$HERE/../scripts/lib/stack.sh"
  stack_up >/dev/null 2>&1 || true
)
expect_eq "up: account changed, hub restarted" \
  "$(grep -c '^restart.*hub' "$DC_CALLS" 2>/dev/null || true)" 1
expect_eq "up: the CAA tighten runs once, after compose up" \
  "$(grep -E '^(up|dns_tighten_main)' "$DC_CALLS" | paste -sd' ' - | cut -c1-2)$(grep -c '^dns_tighten_main$' "$DC_CALLS")" "up1"

# upgrade_run when account changed: restart hub.
touch "$LLDAP_ACCOUNT_CHANGED"
rm -f "$DC_CALLS"
(
  export PATH="$WORK/dcbin:$PATH" LLDAP_ACCOUNT_CHANGED PORTCULLIS_ROOT VAULT_INIT_FILE
  export PORTCULLIS_DOMAIN=test.example POSTGRES_PASSWORD=x KEYCLOAK_ADMIN_PASSWORD=x CONTAINER_RUNTIME=docker
  export LLDAP_ADMIN_PASSWORD=x LLDAP_JWT_SECRET=x FORWARD_AUTH_CLIENT_SECRET=x
  export FORWARD_AUTH_COOKIE_SECRET=x FORWARD_AUTH_REDIS_PASSWORD=x FORWARD_AUTH_EXT_REDIS_PASSWORD=y HUB_PROXY_SECRET=x
  # shellcheck disable=SC1091
  . "$HERE/../scripts/lib/common.sh"
  # shellcheck disable=SC1091
  . "$WORK/test-up-stub.sh"
  # shellcheck disable=SC1091
  . "$HERE/../scripts/lib/stack.sh"
  upgrade_run true >/dev/null 2>&1 || true
)
expect_eq "upgrade: account changed, hub restarted" \
  "$(grep -c '^restart.*hub' "$DC_CALLS" 2>/dev/null || true)" 1
expect_eq "upgrade: the CAA tighten runs once" "$(grep -c '^dns_tighten_main$' "$DC_CALLS")" 1

# upgrade_run when account unchanged: no restart.
rm -f "$LLDAP_ACCOUNT_CHANGED" "$DC_CALLS"
(
  export PATH="$WORK/dcbin:$PATH" LLDAP_ACCOUNT_CHANGED PORTCULLIS_ROOT VAULT_INIT_FILE
  export PORTCULLIS_DOMAIN=test.example POSTGRES_PASSWORD=x KEYCLOAK_ADMIN_PASSWORD=x CONTAINER_RUNTIME=docker
  export LLDAP_ADMIN_PASSWORD=x LLDAP_JWT_SECRET=x FORWARD_AUTH_CLIENT_SECRET=x
  export FORWARD_AUTH_COOKIE_SECRET=x FORWARD_AUTH_REDIS_PASSWORD=x FORWARD_AUTH_EXT_REDIS_PASSWORD=y HUB_PROXY_SECRET=x
  # shellcheck disable=SC1091
  . "$HERE/../scripts/lib/common.sh"
  # shellcheck disable=SC1091
  . "$WORK/test-up-stub.sh"
  # shellcheck disable=SC1091
  . "$HERE/../scripts/lib/stack.sh"
  upgrade_run true >/dev/null 2>&1 || true
)
expect_eq "upgrade: account unchanged, no hub restart" \
  "$(grep -c '^restart.*hub' "$DC_CALLS" 2>/dev/null || true)" 0
expect_eq "upgrade: the session store's restart check runs before docker compose up" \
  "$(grep -E '^(sessions_restart_if_changed|up)' "$DC_CALLS" | head -n2 | paste -sd' ' -)" "sessions_restart_if_changed up"
# The local images are built before the first up recreates anything
# (test server 2026-11-13: a build next to Keycloak's restart).
expect_eq "upgrade: the local images are built before the first docker compose up" \
  "$(grep -E '^(build|up)( |$)' "$DC_CALLS" | head -n2 | paste -sd'|' -)" "build --quiet|up"

# ── static TLS options (contract §5 "TLS tier per host", plan D18) ──
ROOT_DIR="$(cd "$HERE/.." && pwd)"
expect_eq "MTLS_ENABLED appears nowhere in portcullis scripts/lib docker-compose.yml" \
  "$(grep -l MTLS_ENABLED "$ROOT_DIR/portcullis" "$ROOT_DIR"/scripts/lib/*.sh "$ROOT_DIR/docker-compose.yml" "$ROOT_DIR/.env.example" 2>/dev/null || true)" ""
TLS_YML="$ROOT_DIR/traefik/dynamic/tls.yml"
# One line per option: <name> <clientAuthType or none> <every caFiles entry, comma-joined> <minVersion> <sniStrict>.
TLS_GOT="$(awk '
  /^    [a-z-]+:$/ { if (n) print n, (t ? t : "none"), (ca ? ca : "-"), v, s; n = $1; sub(/:$/, "", n); t = ""; ca = ""; v = ""; s = ""; next }
  /clientAuthType:/ { t = $2 } /^[[:space:]]*- / { ca = (ca ? ca "," : "") $2 } /minVersion:/ { v = $2 } /sniStrict:/ { s = $2 }
  END { if (n) print n, (t ? t : "none"), (ca ? ca : "-"), v, s }' "$TLS_YML")"
expect_eq "traefik/dynamic/tls.yml defines exactly protected, protected-any, authaware, public with those clientAuth types and chains" "$TLS_GOT" \
"protected RequireAndVerifyClientCert /certs/ca-chain-yubikey.crt VersionTLS12 false
protected-any RequireAndVerifyClientCert /certs/ca-chain.crt VersionTLS12 false
authaware VerifyClientCertIfGiven /certs/ca-chain.crt VersionTLS12 false
public none - VersionTLS12 false"
expect_eq "tls.yml: only the tls.options block" "$(grep -cvE '^[[:space:]]*(#|$)' "$TLS_YML")" 26
expect_eq "tls.yml is tracked by git" "$(git -C "$ROOT_DIR" ls-files traefik/dynamic/tls.yml)" "traefik/dynamic/tls.yml"
# Every core router carries authaware@file.
ROUTERS="$(grep -oE 'traefik\.http\.routers\.[a-z0-9-]+\.rule' "$ROOT_DIR/docker-compose.yml" | sed 's/^traefik\.http\.routers\.//; s/\.rule$//' | sort -u)"
BAD=""
for r in $ROUTERS; do
  grep -qE "^[[:space:]]+traefik\.http\.routers\.$r\.tls\.options: authaware@file$" "$ROOT_DIR/docker-compose.yml" || BAD="$BAD $r"
done
expect_eq "every core router in docker-compose.yml uses authaware@file" "${BAD:-none}:$(printf '%s\n' "$ROUTERS" | grep -c .)" "none:24"
expect_eq "no other tls.options in docker-compose.yml" "$(grep -E 'tls\.options:' "$ROOT_DIR/docker-compose.yml" | grep -vc 'authaware@file$' || true)" 0
# VPN (contract §16, security ruling): every core router's entrypoints
# label is literally its class: routers without group-gate take
# PORTCULLIS_EP_* (websecure,vpnsecure or vpnsecure); routers through
# group-gate are split — the websecure one takes PORTCULLIS_WEB_* (websecure
# or parked, never vpnsecure) with portcullis-groups@docker, its -vpn twin is
# on vpnsecure only with portcullis-groups-vpn@docker (group-gate's VPN path,
# the only one a VPN binding is satisfied on); the two friendly routers sit
# on websecure. vpnsecure trusts PROXY only from wg's edge address.
EP_GOT="$(sed -n 's/^[[:space:]]*traefik\.http\.routers\.\([a-z0-9-]*\)\.entrypoints: \(.*\)$/\1 \2/p' "$ROOT_DIR/docker-compose.yml" | LC_ALL=C sort | tr '\n' ';')"
EP_WANT=""
for r in dashboard keycloak-admin hub grafana-metrics; do EP_WANT="$EP_WANT$r \${PORTCULLIS_WEB_ADMIN:-websecure}"$'\n'; done
for r in portal people; do EP_WANT="$EP_WANT$r \${PORTCULLIS_WEB_CORE:-websecure}"$'\n'; done
EP_WANT="${EP_WANT}people-vpn-enrol \${PORTCULLIS_WEB_ENROL:-websecure}"$'\n'
for r in lldap mcp hub-mcp people-mcp; do EP_WANT="$EP_WANT$r \${PORTCULLIS_EP_ADMIN:-websecure,vpnsecure}"$'\n'; done
for r in keycloak keycloak-resources oauth2-callback enroll-invite; do EP_WANT="$EP_WANT$r \${PORTCULLIS_EP_ENROL:-websecure,vpnsecure}"$'\n'; done
for r in dashboard keycloak-admin hub grafana-metrics portal people people-vpn-enrol; do EP_WANT="$EP_WANT$r-vpn vpnsecure"$'\n'; done
for r in core-vpn-required keycloak-admin-vpn-required; do EP_WANT="$EP_WANT$r websecure"$'\n'; done
EP_WANT="$(printf '%s' "$EP_WANT" | LC_ALL=C sort | tr '\n' ';')"
expect_eq "every core router's entrypoints is its class (EP_* without group-gate, WEB_* + a -vpn twin through it)" "$EP_GOT" "$EP_WANT"
expect_eq "every core router with a rule has an entrypoints label" \
  "$(printf '%s\n' "$ROUTERS" | LC_ALL=C sort | tr '\n' ' ')" \
  "$(printf '%s' "$EP_GOT" | tr ';' '\n' | awk 'NF {print $1}' | LC_ALL=C sort | tr '\n' ' ')"
# The VPN middlewares only on vpnsecure-only routers; the normal ones never on vpnsecure.
MW_BAD=""
while read -r r mw; do
  ep="$(sed -n "s/^[[:space:]]*traefik\.http\.routers\.$r\.entrypoints: //p" "$ROOT_DIR/docker-compose.yml")"
  case ",$mw," in
    *,portcullis-groups-vpn@docker,*|*,portal-vpn-path@docker,*|*,portcullis-public-guard-vpn@docker,*)
      [ "$ep" = vpnsecure ] || MW_BAD="$MW_BAD $r:$ep" ;;
    *,portcullis-groups@docker,*|*,portal-path@docker,*|*,portcullis-public-guard@docker,*)
      case "$ep" in *vpnsecure*) MW_BAD="$MW_BAD $r:$ep" ;; esac ;;
  esac
done < <(sed -n 's/^[[:space:]]*traefik\.http\.routers\.\([a-z0-9-]*\)\.middlewares: \(.*\)$/\1 \2/p' "$ROOT_DIR/docker-compose.yml")
expect_eq "the VPN gate middlewares are on vpnsecure-only routers, the normal ones never on vpnsecure" "${MW_BAD:-none}" none
# Each -vpn twin is its router with only the gate swapped.
TWIN_BAD=""
for r in dashboard keycloak-admin hub grafana-metrics portal people people-vpn-enrol; do
  for a in rule tls.options service priority; do
    [ "$(sed -n "s/^[[:space:]]*traefik\.http\.routers\.$r\.$a: //p" "$ROOT_DIR/docker-compose.yml")" = \
      "$(sed -n "s/^[[:space:]]*traefik\.http\.routers\.$r-vpn\.$a: //p" "$ROOT_DIR/docker-compose.yml")" ] || TWIN_BAD="$TWIN_BAD $r.$a"
  done
  [ "$(sed -n "s/^[[:space:]]*traefik\.http\.routers\.$r\.middlewares: //p" "$ROOT_DIR/docker-compose.yml" | sed 's/portcullis-groups@docker/portcullis-groups-vpn@docker/; s/portal-path@docker/portal-vpn-path@docker/')" = \
    "$(sed -n "s/^[[:space:]]*traefik\.http\.routers\.$r-vpn\.middlewares: //p" "$ROOT_DIR/docker-compose.yml")" ] || TWIN_BAD="$TWIN_BAD $r.middlewares"
done
expect_eq "each core -vpn twin = its router with portcullis-groups-vpn / portal-vpn-path" "${TWIN_BAD:-none}" none
expect_eq "the VPN gate paths and the parked entrypoint (Traefik's container loopback)" \
  "$(grep -cxE '      (traefik\.http\.middlewares\.portcullis-groups-vpn\.forwardauth\.address: http://group-gate:8080/auth/vpn|traefik\.http\.middlewares\.portcullis-public-guard-vpn\.forwardauth\.address: http://group-gate:8080/public-guard/vpn|traefik\.http\.middlewares\.portal-vpn-path\.replacepath\.path: /portal/vpn|TRAEFIK_ENTRYPOINTS_PARKED_ADDRESS: 127\.0\.0\.1:8441)' "$ROOT_DIR/docker-compose.yml")" 4
expect_eq "vpnsecure trusts PROXY from wg's portcullis-vpn-edge address only" \
  "$(grep -cF 'TRAEFIK_ENTRYPOINTS_VPNSECURE_PROXYPROTOCOL_TRUSTEDIPS: ${PORTCULLIS_VPN_EDGE_WG_IP:-172.31.254.67}/32' "$ROOT_DIR/docker-compose.yml"):$(grep -cF 'ipv4_address: ${PORTCULLIS_VPN_EDGE_WG_IP:-172.31.254.67}' "$ROOT_DIR/docker-compose.yml"):$(grep -c 'PROXYPROTOCOL_TRUSTEDIPS' "$ROOT_DIR/docker-compose.yml")" "1:1:1"
expect_eq "Traefik is not on portcullis-vpn (gateways are)" \
  "$(awk '/^  traefik:$/ {on = 1; next} on && /^  [a-z][a-z0-9-]*:$/ {exit} on' "$ROOT_DIR/docker-compose.yml" | grep -c '^      portcullis-vpn:$' || true)" 0
expect_eq "no forwardedHeaders trust and no PROXY insecure on vpnsecure (or anywhere)" \
  "$(grep -ciE 'TRAEFIK_ENTRYPOINTS_[A-Z]+_(FORWARDEDHEADERS|PROXYPROTOCOL_INSECURE)' "$ROOT_DIR/docker-compose.yml" || true)" 0
expect_eq "vpnsecure is bound to Traefik's portcullis-vpn-edge address and drops header aliases" \
  "$(grep -cE '^      TRAEFIK_ENTRYPOINTS_VPNSECURE_(ADDRESS: \$\{PORTCULLIS_VPN_EDGE_TRAEFIK_IP:-172\.31\.254\.66\}:8443|HTTP_ALIASHEADERSSTRATEGY: delete)$' "$ROOT_DIR/docker-compose.yml")" 2
# The Hub can't write traefik/: /project is read-only and no writable mount
# (short or long syntax: bind, volume, tmpfs) has traefik in its source or
# target; the writable ones are exactly these.
HUB_SVC="$(awk '/^  hub:$/ { f = 1; next } f && /^  [a-z][a-z0-9-]*:$/ { exit } f' "$ROOT_DIR/docker-compose.yml")"
# hub_writable_mounts <compose-file> — one line "<source> -> <target>" per
# mount of the hub service that is writable: short syntax without :ro,
# long syntax (bind, volume, tmpfs) without read_only: true.
hub_writable_mounts() {
  awk '
    function flush() { if (inlong && ro != "true") print (src == "" ? "(" typ ")" : src) " -> " tgt; inlong = 0; src = ""; tgt = ""; ro = ""; typ = "" }
    /^  hub:$/ { svc = 1; next }
    svc && /^  [a-z][a-z0-9-]*:$/ { flush(); exit }
    !svc { next }
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    /^    volumes:$/ { vol = 1; next }
    vol && /^    [a-z_]+:/ { flush(); vol = 0; next }
    !vol { next }
    /^      - type:/ { flush(); inlong = 1; typ = $3; next }
    /^      - / { flush(); m = $0; sub(/^      - /, "", m); sub(/[[:space:]]+#.*$/, "", m); n = split(m, p, ":")
                  if (p[n] != "ro") print p[1] " -> " p[2]; next }
    inlong && /^        source:/ { src = $2 } inlong && /^        target:/ { tgt = $2 } inlong && /^        read_only:/ { ro = $2 }
    END { flush() }' "$1"
}
expect_eq "the hub service mounts nothing under traefik/ read-write" \
  "$(hub_writable_mounts "$ROOT_DIR/docker-compose.yml" | grep -c traefik || true)" 0
expect_eq "the hub mounts the checkout read-only" "$(printf '%s\n' "$HUB_SVC" | grep -c '^      - \.:/project:ro$')" 1
expect_eq "the Hub's writable mounts are exactly templates/, appfiles/, its volumes and the masking tmpfs" \
  "$(hub_writable_mounts "$ROOT_DIR/docker-compose.yml" | LC_ALL=C sort | tr '\n' ';')" \
  "(tmpfs) -> /project/backups;(tmpfs) -> /project/secrets;./appfiles -> /project/appfiles;./templates -> /project/templates;group_gate_data -> /group-gate-data;hub_data -> /data;hub_secrets -> /secrets;vpn_doc -> /vpn-doc;"
# The check itself catches both syntaxes (planted mounts on a copy).
awk '{ print } /^      - \.\/templates:\/project\/templates:rw$/ { print "      - ./traefik/dynamic:/project/traefik/dynamic" }' "$ROOT_DIR/docker-compose.yml" > "$WORK/compose-short.yml"
awk '{ print } /^      - \.\/templates:\/project\/templates:rw$/ { print "      - type: bind"; print "        source: ./traefik"; print "        target: /etc/x"; print "        read_only: false" }' "$ROOT_DIR/docker-compose.yml" > "$WORK/compose-long.yml"
awk '{ print } /^      - \.\/templates:\/project\/templates:rw$/ { print "      - type: bind"; print "        source: ./traefik"; print "        target: /etc/x"; print "        read_only: true" }' "$ROOT_DIR/docker-compose.yml" > "$WORK/compose-long-ro.yml"
expect_eq "the traefik mount check catches a short-syntax rw bind" "$(hub_writable_mounts "$WORK/compose-short.yml" | grep -c traefik || true)" 1
expect_eq "the traefik mount check catches a long-syntax rw bind" "$(hub_writable_mounts "$WORK/compose-long.yml" | grep -c traefik || true)" 1
expect_eq "the traefik mount check passes a long-syntax read-only bind" "$(hub_writable_mounts "$WORK/compose-long-ro.yml" | grep -c traefik || true)" 0

# ── sign-in part 2 wiring (contract §4, §5 "Core routers", §8.1, §8.2) ──
DC="$ROOT_DIR/docker-compose.yml"
# svc <name> — the lines of one compose service.
svc() { awk -v s="  $1:" '$0 == s { f = 1; next } f && /^  [a-z][a-z0-9-]*:$/ { exit } f' "$DC"; }
GG_SVC="$(svc group-gate)"
expect_eq "no router in docker-compose.yml routes enroll.<domain> except enroll-invite (PathPrefix /invite/)" \
  "$(grep -hE '^[[:space:]]+traefik\.http\.routers\.[a-z0-9-]+\.rule: .*enroll\.' "$DC" "$ROOT_DIR/docker-compose.apps.yml" "$ROOT_DIR/docker-compose.test.yml" | sed 's/^[[:space:]]*//')" \
  'traefik.http.routers.enroll-invite.rule: Host(`enroll.${PORTCULLIS_DOMAIN:-portcullis.local}`) && PathPrefix(`/invite/`)'
expect_eq "no enroll or enroll-self router labels left" \
  "$(grep -cE 'traefik\.http\.routers\.enroll(-self)?\.' "$DC" || true)" 0
expect_eq "no portcullis-self middleware and no \"/authenticated\" anywhere" \
  "$(git -C "$ROOT_DIR" grep -lE 'portcullis-self|/authenticated' -- ':!CHANGELOG.md' ':!tests/test_cli.sh' ':!tests/test_group_gate.py' || true)" ""
expect_eq "the people router uses client-cert-pem@file, before portcullis-groups@docker" \
  "$(svc hub | sed -n 's/^      traefik\.http\.routers\.people\.middlewares: //p')" \
  "rate-limit@file,client-cert-pem@file,portcullis-auth@docker,portcullis-groups@docker,hub-proxy-secret@docker,security-headers@file"
expect_eq "group-gate mounts group_gate_data read-write, has group_add 10001 (+ 10007 for vpn.json), and both CA files read-only; GATE_CRL_URLS lists pki_int and pki_file" \
  "$(printf '%s\n' "$GG_SVC" | grep -cxE '      - group_gate_data:/data|    group_add: \["10001", "10007"\]|      - \./certs/yubikey-ca\.crt:/etc/group-gate/ca/yubikey-ca\.crt:ro|      - \./certs/browser-ca\.crt:/etc/group-gate/ca/browser-ca\.crt:ro|      GATE_YUBIKEY_CA_FILE: /etc/group-gate/ca/yubikey-ca\.crt|      GATE_BROWSER_CA_FILE: /etc/group-gate/ca/browser-ca\.crt|      GATE_OPENED_DIR: /data/opened|      GATE_CRL_URLS: http://vault:8200/v1/pki_int/crl http://vault:8200/v1/pki_file/crl|      GATE_DELTA_CRL_URLS: http://vault:8200/v1/pki_int/crl/delta http://vault:8200/v1/pki_file/crl/delta'):$(printf '%s\n' "$GG_SVC" | grep -cE 'GATE_(DELTA_)?CRL_URL:' || true)" "9:0"
expect_eq "group-gate reads vpn.json from vpn_doc (read-only)" \
  "$(printf '%s\n' "$GG_SVC" | grep -cxE '      GATE_VPN_FILE: /vpn-doc/vpn\.json|      - vpn_doc:/vpn-doc:ro')" 2
# shellcheck disable=SC2016  # a literal ${IMPERSONATION_MAX_MINUTES:-30}
expect_eq "group-gate has GATE_IMPERSONATION_FILE under /hub-data; hub has HUB_IMPERSONATION_MAX_MINUTES" \
  "$(printf '%s\n' "$GG_SVC" | sed -n 's/^      GATE_IMPERSONATION_FILE: //p'):$(printf '%s\n' "$GG_SVC" | grep -cxF '      - hub_data:/hub-data:ro'):$(svc hub | sed -n 's/^      HUB_IMPERSONATION_MAX_MINUTES: //p')" \
  '/hub-data/impersonation.json:1:${IMPERSONATION_MAX_MINUTES:-30}'
expect_eq "hub mounts group_gate_data; HUB_CLIENT_CERT_TTL follows CLIENT_CERT_TTL" \
  "$(svc hub | grep -cxE '      - group_gate_data:/group-gate-data|      HUB_GROUP_GATE_DATA_DIR: /group-gate-data|      HUB_CLIENT_CERT_TTL: \$\{CLIENT_CERT_TTL:-720h\}|      HUB_CERT_EXPIRY_WARN_DAYS: \$\{CERT_EXPIRY_WARN_DAYS:-7\}')" 4
expect_eq "only group-gate and the Hub mount group_gate_data, and it is a declared volume" \
  "$(for s in $(grep -E '^  [a-z][a-z0-9-]*:$' "$DC" | tr -d ' :' | sort -u); do svc "$s" | grep -q '^      - group_gate_data:' && echo "$s"; done | tr '\n' ' ')$(awk '/^volumes:$/ { v = 1; next } v && /^  group_gate_data:$/ { print "declared" }' "$DC")" "group-gate hub declared"
# shellcheck disable=SC2016  # a literal ${PORTCULLIS_DOMAIN:-...}
expect_eq "keycloak gets PORTCULLIS_SIGNIN_URL = the Sign-in page" \
  "$(svc keycloak | sed -n 's/^      PORTCULLIS_SIGNIN_URL: //p')" 'https://people.${PORTCULLIS_DOMAIN:-portcullis.local}/signin'
expect_eq "group-gate-map.conf has no enroll entry" "$(grep -cE '^[[:space:]]*enroll[[:space:]]*=' "$ROOT_DIR/group-gate/group-gate-map.conf" || true)" 0
expect_eq "no file in the repo matches enroll\\.[^ ]*/self" \
  "$(git -C "$ROOT_DIR" grep -lE 'enroll\.[^ ]*/self' -- ':!CHANGELOG.md' ':!tests/test_cli.sh' || true)" ""
# User-facing texts (D34): "YubiKey certificate" / "Browser certificate"; a
# "client cert" stays only in code comments and contract internals.
expect_eq "no user-facing text (README, .env.example, docs, monitoring, theme, CLI output / help) says \"client certificate\"" \
  "$(git -C "$ROOT_DIR" grep -niE 'client cert' -- README.md .env.example docs monitoring keycloak/themes portcullis scripts/lib enroll/web group-gate/group-gate-map.conf \
      | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true)" ""
expect_eq "tls.yml's header says which option uses which chain and who uses it" \
  "$(grep -cE '^# (protected|protected-any|authaware|public): ' "$TLS_YML"):$(grep -c 'Used by' "$TLS_YML")" "4:4"

# config apply leaves tls.yml byte-identical and writes no traefik file.
CA_ROOT="$WORK/ca-root"
mkdir -p "$CA_ROOT/traefik/dynamic" "$WORK/cabin"
cp "$TLS_YML" "$CA_ROOT/traefik/dynamic/tls.yml"
printf 'PORTCULLIS_DOMAIN=ci.example.org\nACME_STAGING=false\nCONTAINER_RUNTIME=docker\n' > "$CA_ROOT/.env"
{ printf '#!/usr/bin/env bash\n'; cat "$WORK/stub-version"; printf 'exit 1\n'; } > "$WORK/cabin/docker"
chmod +x "$WORK/cabin/docker"
SUM_BEFORE="$(cksum < "$CA_ROOT/traefik/dynamic/tls.yml")"
RC=0; PATH="$WORK/cabin:$PATH" PORTCULLIS_ROOT="$CA_ROOT" "$CLI" config apply >"$WORK/out" 2>"$WORK/err" </dev/null || RC=$?
expect_eq "config apply exits 0" "$RC" 0
expect_eq "config apply leaves tls.yml byte-identical" "$(cksum < "$CA_ROOT/traefik/dynamic/tls.yml")" "$SUM_BEFORE"
expect_eq "config apply writes nothing else under traefik/" "$(find "$CA_ROOT/traefik" -type f | wc -l | tr -d ' ')" 1
case "$(cat "$WORK/out" "$WORK/err")" in *MTLS*|*mTLS*) t_fail "config apply mentions mTLS" ;; *) t_pass "config apply says nothing about mTLS" ;; esac

# ── signin reset-core (stubbed docker compose) ──
SR_ROOT="$WORK/sr-root"
mkdir -p "$SR_ROOT" "$WORK/srbin"
printf 'PORTCULLIS_DOMAIN=ci.example.org\nCONTAINER_RUNTIME=docker\n' > "$SR_ROOT/.env"
SR_CALLS="$WORK/sr-calls"
cat > "$WORK/srbin/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1 $3" = "version {{json .Server.Components}}" ] && { echo '[{"Name":"Engine","Version":"29.0.0"}]'; exit 0; }
[ "$1" = compose ] || exit 97
shift
[ "$1" = --project-directory ] && shift 2
echo "dc $*" >> "$SR_CALLS"
case "$1" in
  run) if [ -n "${SR_RUN_RC:-}" ]; then echo "signin reset-core: the Hub is running on this data directory"; exit "$SR_RUN_RC"; fi
       echo "core page hub: mine -> standard" ;;
  stop) exit "${SR_STOP_RC:-0}" ;;
  start) exit "${SR_START_RC:-0}" ;;
esac
exit 0
STUB
chmod +x "$WORK/srbin/docker"
sr() {
  RC=0; : > "$SR_CALLS"
  PATH="$WORK/srbin:$PATH" PORTCULLIS_ROOT="$SR_ROOT" SR_CALLS="$SR_CALLS" "$CLI" signin reset-core "$@" >"$WORK/out" 2>"$WORK/err" </dev/null || RC=$?
  OUT="$(cat "$WORK/out")"; ERR="$(cat "$WORK/err")"
}
sr
expect_eq "signin reset-core without --yes and no tty refuses" "$RC:$(cat "$SR_CALLS")" "2:"
SR_WANT="dc stop hub
dc run --rm --no-deps -T --user 10001:10001 --label traefik.enable=false --entrypoint /usr/local/bin/hub hub signin reset-core
dc start hub"
sr --yes
expect_eq "signin reset-core --yes runs dc stop hub, dc run --rm --no-deps --entrypoint /usr/local/bin/hub hub signin reset-core, dc start hub (stubbed dc)" "$RC:$(cat "$SR_CALLS")" "0:$SR_WANT"
case "$OUT" in *"core page hub: mine -> standard"*) t_pass "signin reset-core shows the Hub's output" ;; *) t_fail "signin reset-core output: $OUT" ;; esac
SR_RUN_RC=3 sr --yes
expect_eq "signin reset-core: a failed run still starts the Hub, then fails" "$RC:$(cat "$SR_CALLS")" "1:$SR_WANT"
case "$ERR" in *"failed (exit 3): signin reset-core: the Hub is running on this data directory; the Hub was started again"*) t_pass "signin reset-core: the failure names the exit status and the Hub's message" ;; *) t_fail "signin reset-core failure: $ERR" ;; esac
case "$OUT$ERR" in *"nothing was reset"*) t_fail "signin reset-core: a failed run claims nothing was reset" ;; *) t_pass "signin reset-core: a failed run never claims nothing was reset" ;; esac
SR_STOP_RC=1 sr --yes
expect_eq "signin reset-core: a failed stop starts the Hub again and runs nothing" "$RC:$(cat "$SR_CALLS")" "1:dc stop hub
dc start hub"
SR_START_RC=1 sr --yes
expect_eq "signin reset-core: a failed start fails" "$RC" 1
case "$ERR" in *"could not be started again"*) t_pass "signin reset-core: a failed start says so" ;; *) t_fail "signin reset-core failed start: $ERR" ;; esac
mv "$SR_ROOT/.env" "$SR_ROOT/.env.x"
sr --yes
expect_eq "signin reset-core --yes without .env exits 1 before docker" "$RC:$(cat "$SR_CALLS")" "1:"
mv "$SR_ROOT/.env.x" "$SR_ROOT/.env"

# ── enroll's Vault policy: exactly the D21 paths (contract §8.1) ──
POLICY_GOT="$(awk '
  function flush() { if (p != "") print p " " c (d != "" ? " deny=" d : ""); p = ""; c = ""; d = "" }
  /^[[:space:]]*path[[:space:]]+"/ { flush(); p = $2; gsub(/"/, "", p); ind = 0; next }
  /capabilities/ { c = $0; sub(/.*\[/, "", c); sub(/\].*/, "", c); gsub(/[" ]/, "", c); next }
  /denied_parameters/ { ind = 1; next }
  ind && /=[[:space:]]*\[\]/ { k = $1; gsub(/"/, "", k); d = (d == "" ? k : d "," k); next }
  ind && /^[[:space:]]*}/ { ind = 0; next }
  END { flush() }
' "$HERE/../vault/policies/enroll.hcl" | sort)"
POLICY_WANT="$(sort <<'EOF'
pki_int/sign/client-cert update deny=alt_names,ip_sans,uri_sans,other_sans
pki_file/sign/browser-cert update deny=alt_names,ip_sans,uri_sans,other_sans
pki_int/certs list
pki_file/certs list
pki_int/cert/* read
pki_file/cert/* read
pki_int/revoke update
pki_file/revoke update
pki_int/crl/rotate read
pki_file/crl/rotate read
EOF
)"
expect_eq "enroll.hcl grants exactly the D21 paths (sign/client-cert, sign/browser-cert, certs list, cert read, revoke, crl/rotate on both mounts) and nothing else" \
  "$POLICY_GOT" "$POLICY_WANT"
expect_eq "enroll.hcl has one path block per grant" \
  "$(grep -c '^[[:space:]]*path[[:space:]]' "$HERE/../vault/policies/enroll.hcl")" 10
expect_eq "enroll.hcl: only capabilities and denied_parameters (no allowed_parameters, no wildcard grants)" \
  "$(grep -vE '^[[:space:]]*(#|$|path "pki_(int|file)/[a-z/-]+\*?" \{|capabilities = \["(update|list|read)"\]|denied_parameters = \{|"(alt_names|ip_sans|uri_sans|other_sans)" += \[\]|\})' "$HERE/../vault/policies/enroll.hcl")" ""

# ── cert list / revoke / enroll over both CAs (stub vault + ykman) ──
CT_ROOT="$WORK/cert-root"
CT_BIN="$WORK/cert-bin"
CT_DATA="$WORK/cert-data"
mkdir -p "$CT_ROOT/certs/revocation" "$CT_BIN" "$CT_DATA"
printf 'PORTCULLIS_DOMAIN=example.test\nCONTAINER_RUNTIME=docker\n' > "$CT_ROOT/.env"
# ct_cert <serial> <cn> <revocation_time> — Vault's JSON for a certificate.
ct_cert() {
  openssl ecparam -genkey -name prime256v1 -out "$CT_DATA/$1.key" 2>/dev/null
  openssl req -new -x509 -key "$CT_DATA/$1.key" -subj "/CN=$2" -days 30 -out "$CT_DATA/$1.pem" 2>/dev/null
  jq -n --rawfile c "$CT_DATA/$1.pem" --argjson rt "$3" '{data: {certificate: $c, revocation_time: $rt}}' > "$CT_DATA/$1.json"
}
ct_cert aa_01 alice 0
ct_cert bb_02 alice 0
ct_cert bb_03 bob 1767225600
cat > "$CT_BIN/vault" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$CT_CALLS"
# Like the real CLI (Vault 1.17), every API error exits 2 with an error
# text; only "No value found at <path>" means nothing is there.
# CT_SEALED=1: the lists answer exit 0 with no list (a sealed Vault's empty table).
if [ -n "${CT_SEALED:-}" ] && [ "$1" = list ]; then exit 0; fi
case "$*" in
  "read -format=json pki_int/cert/dd:44")
    printf 'Error reading pki_int/cert/dd:44: Error making API request.\n\nCode: 403. Errors:\n\n* permission denied\n' >&2; exit 2 ;;
  "read -format=json pki_file/cert/dd:44") cat "$CT_DATA/bb_02.json" ;;
  "list -format=json pki_int/certs") echo '["aa:01"]' ;;
  "list -format=json pki_file/certs") echo '["bb:02","bb:03"]' ;;
  "read -format=json pki_int/cert/aa:01") cat "$CT_DATA/aa_01.json" ;;
  "read -format=json pki_file/cert/bb:02") cat "$CT_DATA/bb_02.json" ;;
  "read -format=json pki_file/cert/bb:03") cat "$CT_DATA/bb_03.json" ;;
  "read -format=json pki_"*/cert/*) echo "No value found at ${3}" >&2; exit 2 ;;
  "list -format=json pki_int/certs/revoked") echo "No value found at pki_int/certs/revoked" >&2; exit 2 ;;
  "list -format=json pki_file/certs/revoked") echo '["bb:02","bb:03"]' ;;
  "write -format=json pki_int/sign/client-cert "*) jq -n --rawfile c "$CT_DATA/aa_01.pem" '{data: {certificate: $c}}' ;;
  "write pki_"*/revoke\ *|"read -format=json pki_"*/crl/rotate) ;;
  *) echo "unexpected vault call: $*" >&2; exit 1 ;;
esac
STUB
cat > "$CT_BIN/ykman" <<'STUB'
#!/usr/bin/env bash
echo "ykman $*" >> "$CT_CALLS"
case "$1 $2 $3" in
  "piv keys generate"|"piv certificates request") eval "out=\${$#}"; echo PEM > "$out" ;;
esac
exit 0
STUB
chmod +x "$CT_BIN/vault" "$CT_BIN/ykman"
ct() {
  RC=0
  rm -f "$WORK/cert-calls"; touch "$WORK/cert-calls"
  PATH="$CT_BIN:$PATH" CT_SEALED="${CT_SEALED:-}" CT_CALLS="$WORK/cert-calls" CT_DATA="$CT_DATA" VAULT_TOKEN=t PORTCULLIS_ROOT="$CT_ROOT" \
    "$CLI" cert "$@" >"$WORK/out" 2>"$WORK/err" </dev/null || RC=$?
  OUT="$(cat "$WORK/out")"; ERR="$(cat "$WORK/err")"
}
ct list --all
expect_eq "cert list --all exits 0" "$RC" 0
expect_eq "cert list --all prints KIND YubiKey / Browser and revoked rows" \
  "$(printf '%s\n' "$OUT" | awk '{print $1, $2, $3, $4}')" \
  "SERIAL KIND COMMON NAME
aa:01 YubiKey alice valid
bb:02 Browser alice valid
bb:03 Browser bob revoked"
ct list
expect_eq "cert list hides revoked rows" "$(printf '%s\n' "$OUT" | awk 'NR > 1 {print $1}' | tr '\n' ' ')" "aa:01 bb:02 "
ct revoke --yes bb:02
expect_eq "cert revoke <pki_file serial> exits 0" "$RC" 0
expect_eq "cert revoke <pki_file serial> revokes on pki_file and rotates pki_file's CRL" \
  "$(grep -E '/revoke |crl/rotate' "$WORK/cert-calls")" \
  "write pki_file/revoke serial_number=bb:02
read -format=json pki_file/crl/rotate"
expect_eq "cert revoke looks the serial up on pki_int first" "$(grep -cx 'read -format=json pki_int/cert/bb:02' "$WORK/cert-calls")" 1
case "$OUT" in *"Browser certificate (pki_file)"*) t_pass "cert revoke names the certificate's kind" ;; *) t_fail "cert revoke kind: $OUT" ;; esac
expect_eq "cert revoke syncs the union of both CAs' revoked serials" \
  "$(grep -v '^#' "$CT_ROOT/certs/revocation/revoked-serials.txt" | tr '\n' ' ')" "bb:02 bb:03 "
ct revoke --yes aa:01
expect_eq "cert revoke <pki_int serial> revokes on pki_int and rotates pki_int's CRL" \
  "$(grep -E '/revoke |crl/rotate' "$WORK/cert-calls")" \
  "write pki_int/revoke serial_number=aa:01
read -format=json pki_int/crl/rotate"
ct revoke --yes cc:99
expect_eq "cert revoke of an unknown serial exits 1" "$RC" 1
expect_eq "cert revoke of an unknown serial revokes nothing" "$(grep -c '/revoke ' "$WORK/cert-calls")" 0
ct revoke --yes dd:44
expect_eq "cert revoke: a 403 on pki_int (exit 2) is an error, not 'look on pki_file'" "$RC" 1
expect_eq "cert revoke: a 403 on pki_int revokes nothing" "$(grep -c '/revoke ' "$WORK/cert-calls")" 0
expect_eq "cert revoke: a 403 on pki_int never reads pki_file" "$(grep -c 'pki_file/cert/dd:44' "$WORK/cert-calls")" 0
CT_SEALED=1 ct list --all
expect_eq "cert list: a sealed Vault's empty answer (exit 0, no list) fails" "$RC" 1
ct enroll alice
expect_eq "cert enroll exits 0 (stub ykman)" "$RC" 0
case "$OUT" in *"https://people.example.test/signin"*) t_pass "cert enroll's renewal hint names https://people.<domain>/signin" ;; *) t_fail "cert enroll's renewal hint: $OUT" ;; esac
case "$OUT" in *"enroll.example.test"*) t_fail "cert enroll still names enroll.<domain>" ;; *) t_pass "cert enroll no longer names enroll.<domain>" ;; esac
expect_eq "cert enroll signs with pki_int's client-cert role" "$(grep -c '^write -format=json pki_int/sign/client-cert .*common_name=alice' "$WORK/cert-calls")" 1

expect_eq "docker was never called" "$(cat "$STUB_CALLS" 2>/dev/null)" ""

echo ""
# lldap_service_account runs under set -e at init: it must never return
# non-zero to say "changed" (that would abort init right after creating the
# account) — it signals LLDAP_SA_CHANGED instead.
sa_body="$(sed -n '/^lldap_service_account() {/,/^}/p' "$HERE/../scripts/lib/users.sh")"
expect_eq "lldap_service_account never returns non-zero" "$(printf '%s\n' "$sa_body" | grep -cE 'return [1-9]|return \$' || true)" "0"
expect_eq "lldap_service_account sets LLDAP_SA_CHANGED" "$(printf '%s\n' "$sa_body" | grep -c 'LLDAP_SA_CHANGED=true' | awk '{print ($1>0)?"yes":"no"}')" "yes"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

