#!/usr/bin/env bash
# e2e-k3s phases (ci.yml job e2e-k3s; each step runs one):
#   docker   the Docker phase of the cross-runtime round trip (rootless P11):
#            init on Docker, the LLDAP fixture made by LLDAP itself (rt-person,
#            rt-alice and rt-bob with passwords, groups rt-g1 / rt-g2; plan
#            Task 26), a backup copied to
#            $RUNNER_TEMP/rt-backup (0700, never an artifact), the CA
#            chain's sha256; then down and wiped
#   init     .env for kubernetes (context ci, K1 local images), the CI TLS
#            certificate, ./portcullis init --runtime kubernetes
#   seed     the Hub's template source (tests/e2e/apps echo, folder-writer,
#            alias-echo, mcp-echo) into hub-state, the
#            fixer's /srv/e2e-k3s, an issued YubiKey certificate's serial
#   hub      tests/e2e/e2e_k3s.py through a port-forward to the Hub
#   vpn      vpn init (built-in on), a device handshake through wg-people
#            from netns ext, vpn mode admin, then the break-glass vpn mode
#            apps with the Hub at 0: the core routers' entrypoints move
#   restore  test_restore_into_cnpg (plan Task 23): a Kubernetes backup
#            (pg_dump keycloak + lldap from the CNPG primary) restored, LLDAP's
#            person back and Keycloak signing in; then the Docker phase's
#            backup restored onto k3s: first with a fault injected into the
#            LLDAP conversion (test_lldap_convert_refuses_on_diff: refused,
#            nothing switched, LLDAP's Deployment and database untouched),
#            then for real (test_lldap_convert_keeps_uuids: LLDAP's SQLite
#            converted into CNPG — the uuids, hashes and memberships the
#            Docker phase's, the fixture's passwords bind, Keycloak links
#            them by the same entryUUID); the host's kubernetes keys kept,
#            the CA chain the Docker phase's, Keycloak signs in, status clean
# Output goes through redact (setup links); no secret is printed.
set -euo pipefail
cd "$(dirname "$0")/../.."
K() { kubectl --context ci "$@"; }
redact() { sed -E 's#(https?://[^ ]*/invite/)[A-Za-z0-9_-]+#\1<redacted>#g'; }
fail() { echo "FAIL: $*"; exit 1; }
ALPINE="docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a"

status_wait() { # status_wait <seconds> — status --json clean (DNS problems allowed: portcullis.local has no records)
  local i
  for ((i = 0; i < $1; i += 10)); do
    ./portcullis status --json > /tmp/status.json 2>/dev/null || true
    if jq -e '.runtime.name == "kubernetes" and ([.runtime.checks[] | select(.status == "fail")] == [])
        and (.services | length > 0) and ([.services[] | select(.state != "running" or (.health != "healthy" and .health != "n/a"))] == [])
        and .vault.active and .netpol == "proven" and .admission == "ok"' /tmp/status.json >/dev/null 2>&1; then
      return 0
    fi
    sleep 10
  done
  jq -c '{runtime: .runtime.name, checks: [.runtime.checks[] | select(.status != "ok")], services: [.services[] | select(.health != "healthy" and .health != "n/a")], netpol, admission}' /tmp/status.json || true
  fail "status not clean after $1 s"
}

lldap_token() { # lldap_token <base> — admin's token (retried; the HTTP status on failure, never the token)
  local pw code tok out
  pw="$(grep '^LLDAP_ADMIN_PASSWORD=' .env | cut -d= -f2-)"; echo "::add-mask::$pw" >&2
  out="$(mktemp)"
  for _ in $(seq 1 30); do
    code="$(PW="$pw" jq -n '{username: "admin", password: env.PW}' \
      | curl -s -o "$out" -w '%{http_code}' --max-time 10 "$1/auth/simple/login" -H 'Content-Type: application/json' -d @- || true)"
    tok="$(jq -r '.token // empty' "$out" 2>/dev/null || true)"
    [ "$code" = 200 ] && [ -n "$tok" ] && { rm -f "$out"; printf '%s' "$tok"; return 0; }
    sleep 2
  done
  rm -f "$out"; echo "FAIL: LLDAP login as admin: HTTP ${code:-none}" >&2; return 1
}

pf_svc() { # pf_svc <svc> <port> — a port-forward to a core Service (dies with the script); prints the local port
  local log port
  log="$(mktemp)"
  K -n portcullis port-forward --address 127.0.0.1 "svc/$1" ":$2" > "$log" 2>&1 &
  for _ in $(seq 1 50); do grep -q 'Forwarding from' "$log" && break; sleep 0.2; done
  port="$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) .*/\1/p' "$log" | head -n1)"
  [ -n "$port" ] || fail "no port-forward to $1"
  printf '%s' "$port"
}

lldap_gql() { # lldap_gql <base> <query> — LLDAP's GraphQL as admin (the token never printed)
  local tok
  tok="$(lldap_token "$1")" || return 1; echo "::add-mask::$tok" >&2
  jq -n --arg q "$2" '{query: $q}' | curl -sf "$1/api/graphql" -H @<(printf 'Authorization: Bearer %s\n' "$tok") -H 'Content-Type: application/json' -d @-
}

lldap_has() { # lldap_has <base> <user> <true|false> — the user is (not) in LLDAP
  local out
  out="$(lldap_gql "$1" '{ users { id } }')" || return 1
  [ "$(printf '%s' "$out" | jq --arg u "$2" '[.data.users[].id] | index($u) != null')" = "$3" ]
}

lldap_login() { # lldap_login <base> <user> <password> — the user's password binds (HTTP 200; nothing printed)
  local code
  code="$(U="$2" PW="$3" jq -n '{username: env.U, password: env.PW}' | curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$1/auth/simple/login" -H 'Content-Type: application/json' -d @- || true)"
  [ "$code" = 200 ]
}

kc_signin() { # kc_signin — Keycloak's admin signs in (password grant on master, admin-cli) through a port-forward; the password from .env on stdin
  local pw port code out
  pw="$(grep '^KEYCLOAK_ADMIN_PASSWORD=' .env | cut -d= -f2-)"; echo "::add-mask::$pw"
  port="$(pf_svc keycloak 8080)"
  out="$(mktemp)"
  for _ in $(seq 1 60); do
    code="$(PW="$pw" jq -jn '"grant_type=password&client_id=admin-cli&username=admin&password=" + (env.PW | @uri)' \
      | curl -s -o "$out" -w '%{http_code}' --max-time 10 "http://127.0.0.1:$port/realms/master/protocol/openid-connect/token" \
          -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @- || true)"
    [ "$code" = 200 ] && jq -e '.access_token | length > 0' "$out" >/dev/null 2>&1 && { rm -f "$out"; return 0; }
    sleep 5
  done
  rm -f "$out"; echo "FAIL: Keycloak's admin doesn't sign in (HTTP ${code:-none})"; return 1
}

# E2E_K3S_SKIP_DOCKER=1 (local iteration, .github/ci/e2e-k3s-local.sh):
# the Docker phase and the Docker → Kubernetes restore are skipped; CI runs
# both.
if [ "${E2E_K3S_SKIP_DOCKER:-}" = 1 ]; then
  case "${1:-}" in docker|restore) echo "SKIPPED: $1 (E2E_K3S_SKIP_DOCKER=1)"; exit 0 ;; esac
fi

case "${1:-}" in
docker)
  ./portcullis init --env-only --runtime docker --non-interactive --domain "$E2E_DOMAIN" --email "ci@$E2E_DOMAIN" --dns-provider none
  printf 'services:\n  lldap:\n    ports:\n      - "127.0.0.1:17170:17170"\n' > docker-compose.ci.yml
  printf 'tls:\n  certificates:\n    - certFile: /certs/server.crt\n      keyFile: /certs/server.key\n' > traefik/dynamic/ci-certs.yml
  COMPOSE_FILE=docker-compose.yml:docker-compose.ci.yml ./portcullis init --runtime docker --non-interactive --domain "$E2E_DOMAIN" \
    --email "ci@$E2E_DOMAIN" --dns-provider none --no-config-repo 2>&1 | redact
  bash .github/ci/lldap-create-person.sh rt-person
  # The conversion's fixture (plan Task 26: 3 users, 2 groups, made by
  # LLDAP itself): rt-alice and rt-bob with passwords (CI test values, in
  # a 0600 file), rt-g1 = {rt-alice, rt-bob}, rt-g2 = {rt-bob, rt-person}.
  for u in rt-alice rt-bob; do bash .github/ci/lldap-create-person.sh "$u"; done
  (umask 077 && : > "$RUNNER_TEMP/rt-lldap.pw")
  tok="$(lldap_token http://127.0.0.1:17170)"; echo "::add-mask::$tok" >&2
  for u in rt-alice rt-bob; do
    pw="$(openssl rand -hex 16)"; echo "::add-mask::$pw"; printf '%s %s\n' "$u" "$pw" >> "$RUNNER_TEMP/rt-lldap.pw"
    # lldap_set_password takes the token on its argv only: inside the LLDAP
    # container, a short-lived token of this CI stack.
    printf '%s\n%s\n' "$tok" "$pw" | COMPOSE_FILE=docker-compose.yml:docker-compose.ci.yml docker compose exec -T lldap sh -c 'read -r T; read -r P; LLDAP_USER_PASSWORD="$P" exec /app/lldap_set_password -b http://127.0.0.1:17170 -t "$T" -u "$1"' _ "$u" >/dev/null \
      || fail "could not set $u's password"
  done
  for g in rt-g1 rt-g2; do lldap_gql http://127.0.0.1:17170 "mutation { createGroup(name: \"$g\") { id } }" | jq -e '.data.createGroup.id' >/dev/null || fail "could not create $g"; done
  gids="$(lldap_gql http://127.0.0.1:17170 '{ groups { id displayName } }')"
  for m in rt-g1:rt-alice rt-g1:rt-bob rt-g2:rt-bob rt-g2:rt-person; do
    gid="$(printf '%s' "$gids" | jq --arg g "${m%%:*}" '.data.groups[] | select(.displayName == $g) | .id')"
    lldap_gql http://127.0.0.1:17170 "mutation { addUserToGroup(userId: \"${m#*:}\", groupId: $gid) { ok } }" | jq -e '.data.addUserToGroup.ok' >/dev/null || fail "could not add ${m#*:} to ${m%%:*}"
  done
  COMPOSE_FILE=docker-compose.yml:docker-compose.ci.yml ./portcullis backup
  B="$(find backups -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | tail -n1)"
  jq -e '.runtime.name == "docker"' "$B/MANIFEST.json" >/dev/null || fail "the Docker backup's MANIFEST.json"
  (umask 077 && cp -r --preserve=mode,timestamps "$B" "$RUNNER_TEMP/rt-backup")
  chmod 700 "$RUNNER_TEMP/rt-backup"
  # The source's uuids, hashes (sha256 of each) and memberships, from the
  # backup's users.db (never the hashes themselves).
  t="$(mktemp -d)"; tar -xzf "$B/lldap_data.tar.gz" -C "$t" ./users.db
  python3 - "$t/users.db" > "$RUNNER_TEMP/rt-lldap-src.txt" <<'PY'
import hashlib, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
for u, uu, h in db.execute("select user_id, uuid, password_hash from users order by user_id"):
    print("U", u, uu, hashlib.sha256(h).hexdigest() if h else "-")
for u, g in db.execute("select m.user_id, g.display_name from memberships m join groups g using (group_id) order by 1, 2"):
    print("M", u, g)
PY
  rm -rf "$t"
  grep -q '^U rt-alice [0-9a-f-]\{36\} [0-9a-f]\{64\}$' "$RUNNER_TEMP/rt-lldap-src.txt" && [ "$(grep -c '^M ' "$RUNNER_TEMP/rt-lldap-src.txt")" -ge 4 ] \
    || fail "the Docker backup's users.db lacks the fixture"
  sha256sum certs/ca-chain.crt | cut -d' ' -f1 > "$RUNNER_TEMP/rt-ca.sha256"
  COMPOSE_FILE=docker-compose.yml:docker-compose.ci.yml ./portcullis down
  docker volume ls -q --filter label=com.docker.compose.project=portcullis | xargs -r docker volume rm
  sudo rm -rf .env secrets certs templates appfiles backups/2* docker-compose.ci.yml
  git checkout -- secrets/.gitkeep backups/.gitkeep
  echo "PASS: Docker phase: init, rt-person, backup (copied to \$RUNNER_TEMP/rt-backup, 0700), wiped"
  ;;
init)
  ./portcullis init --env-only --runtime kubernetes --kube-context ci --non-interactive --domain "$E2E_DOMAIN" \
    --email "ci@$E2E_DOMAIN" --dns-provider none
  for k in CONTAINER_RUNTIME=kubernetes PORTCULLIS_KUBE_CONTEXT=ci PORTCULLIS_POD_CIDR= PORTCULLIS_SERVICE_CIDR= PORTCULLIS_KUBE_INSTALL_ID=; do
    grep -q "^$k" .env || fail ".env lacks $k"
  done
  bash -c 'source scripts/lib/common.sh; env_set PORTCULLIS_KUBE_IMAGES local; env_set PORTCULLIS_PUBLIC_IPV4 198.51.100.1; env_set COMPOSE_PROFILES monitoring'
  printf 'tls:\n  certificates:\n    - certFile: /certs/server.crt\n      keyFile: /certs/server.key\n' > traefik/dynamic/ci-certs.yml
  ./portcullis init --runtime kubernetes --kube-context ci --non-interactive --no-config-repo 2>&1 | redact
  status_wait 600
  jq -c '.runtime | {name, version, context}' /tmp/status.json | tee -a "$GITHUB_STEP_SUMMARY"
  echo "PASS: init --runtime kubernetes; status clean"
  ;;
seed)
  pod="seed-$RANDOM"
  N="$pod" IMG="$ALPINE" jq -n '{apiVersion: "v1", kind: "Pod", metadata: {name: env.N, namespace: "portcullis", labels: {"portcullis.io/component": "volume-helper"}},
    spec: {restartPolicy: "Never", automountServiceAccountToken: false,
      securityContext: {runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: {type: "RuntimeDefault"}},
      containers: [{name: "c", image: env.IMG, command: ["sleep", "600"], resources: {limits: {memory: "64Mi"}, requests: {memory: "64Mi"}},
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}},
        volumeMounts: [{name: "d", mountPath: "/data"}]}], volumes: [{name: "d", persistentVolumeClaim: {claimName: "hub-state"}}]}}' | K create -f - >/dev/null
  K -n portcullis wait --for=condition=Ready "pod/$pod" --timeout=180s >/dev/null
  # The CI templates (mcp-echo: an AI companion with numeric users).
  tar -cf - -C tests/e2e/apps echo folder-writer alias-echo mcp-echo | K -n portcullis exec -i "$pod" -- sh -c 'mkdir -p /data/repos/ci && tar -C /data/repos/ci -xf - &&
    printf "sources:\n  - name: ci\n    url: \"\"\n    path: /data/repos/ci\n" > /data/state.yaml && chmod 600 /data/state.yaml'
  K -n portcullis delete pod "$pod" --wait=false >/dev/null
  K -n portcullis rollout restart deploy/hub >/dev/null
  K -n portcullis rollout status deploy/hub --timeout=300s
  sudo rm -rf "$E2E_FOLDER"; sudo install -d -o 1000 -g 1000 -m 0750 "$E2E_FOLDER"
  for f in 1 2 3; do echo "k3s $f" | sudo tee "$E2E_FOLDER/file-$f.txt" >/dev/null; done
  # A YubiKey-CA certificate to revoke (the root token on the vault pod's
  # stdin, never argv); its serial for the revocation SLA.
  root="$(jq -r .root_token secrets/vault-init.json)"; echo "::add-mask::$root"
  # shellcheck disable=SC2016  # expanded by the pod's sh
  serial="$(printf '%s\n' "$root" | K -n portcullis exec -i pod/vault-0 -c vault -- sh -c 'IFS= read -r t; VAULT_TOKEN="$t" VAULT_ADDR=http://127.0.0.1:8200 exec vault write -format=json pki_int/issue/client-cert common_name=rt-revoke ttl=1h' | jq -r '.data.serial_number')"
  [[ "$serial" =~ ^[0-9a-f:]+$ ]] || fail "could not issue a certificate to revoke"
  echo "E2E_REVOKE_SERIAL=$serial" >> "$GITHUB_ENV"
  echo "PASS: the Hub's template source (echo, folder-writer) seeded; $E2E_FOLDER ready; certificate $serial issued"
  ;;
hub)
  # The forward binds one pod when it starts: wait until the Hub's rollout
  # (the assertions' `./portcullis up`) is done, or it may be a terminating one.
  K -n portcullis rollout status deploy/hub --timeout=300s >/dev/null || fail "the Hub's rollout didn't finish"
  K -n portcullis wait --for=condition=Available deploy/hub --timeout=300s >/dev/null || fail "the Hub isn't available"
  pf_log="$(mktemp)"
  K -n portcullis port-forward --address 127.0.0.1 svc/hub :8888 > "$pf_log" 2>&1 &
  for i in $(seq 1 50); do grep -q 'Forwarding from' "$pf_log" && break; sleep 0.2; done
  port="$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9]*\) .*/\1/p' "$pf_log" | head -n1)"
  [ -n "$port" ] || fail "no port-forward to the Hub"
  sec="$(grep '^HUB_PROXY_SECRET=' .env | cut -d= -f2-)"; echo "::add-mask::$sec"
  HUB_API="http://127.0.0.1:$port" E2E_HUB_SECRET="$sec" python3 tests/e2e/e2e_k3s.py
  ;;
vpn)
  ./portcullis vpn init --builtin on --port 51820 2>&1 | redact
  K -n portcullis get svc wg-people -o json | jq -e '.spec.type == "LoadBalancer" and .spec.externalTrafficPolicy == "Local" and ([.spec.ports[].protocol] == ["UDP"])' >/dev/null \
    || fail "wg-people isn't a UDP-only LoadBalancer with externalTrafficPolicy Local"
  K -n portcullis get svc traefik -o json | jq -e '[.spec.ports[].port] == [80, 443]' >/dev/null || fail "the traefik LoadBalancer has ports beyond 80 / 443"
  ep() { K -n portcullis-edge get ingressroute "$1" -o jsonpath='{.spec.entryPoints}'; }
  [ "$(ep hub)" = '["websecure"]' ] || fail "apps mode: the hub router's entrypoints are $(ep hub)"
  ./portcullis vpn mode admin --force 2>&1 | redact
  [ "$(ep hub)" = '["parked"]' ] && [ "$(ep hub-vpn)" = '["vpnsecure"]' ] || fail "admin mode: hub $(ep hub), hub-vpn $(ep hub-vpn)"
  K -n portcullis scale deploy/hub --replicas=0 >/dev/null
  ./portcullis vpn mode apps 2>&1 | redact
  [ "$(ep hub)" = '["websecure"]' ] || fail "break-glass vpn mode apps with the Hub at 0: hub $(ep hub)"
  K -n portcullis get deploy group-gate -o json | jq -e '.spec.template.spec.containers[0].env[] | select(.name == "GATE_VPN_MODE") | .value == "apps"' >/dev/null \
    || fail "group-gate's GATE_VPN_MODE isn't apps after the break-glass"
  K -n portcullis scale deploy/hub --replicas=1 >/dev/null
  echo "PASS: vpn init (wg-people UDP LB, ETP Local), vpn mode admin parks the hub router, break-glass vpn mode apps with the Hub at 0"
  ;;
restore)
  # test_restore_into_cnpg (plan Task 23): a Kubernetes backup (pg_dump of
  # keycloak and lldap from the CNPG primary, the pod portcullis-pg-rw
  # selects) restored into the cluster; then the Docker phase's backup.
  lport="$(pf_svc lldap 17170)"
  bash .github/ci/lldap-create-person.sh k8s-person "http://127.0.0.1:$lport"
  # Review M9: k8s-person gets a password (a CI test value), so the restore
  # is proven by its bind (OPAQUE under the restored server key).
  kpw="$(openssl rand -hex 16)"; echo "::add-mask::$kpw"
  tok="$(lldap_token "http://127.0.0.1:$lport")"; echo "::add-mask::$tok" >&2
  # lldap_set_password takes the token on its argv only: inside the LLDAP pod,
  # a short-lived token of this CI stack (the password itself through env).
  printf '%s\n%s\n' "$tok" "$kpw" | K -n portcullis exec -i deploy/lldap -c lldap -- sh -c 'read -r T; read -r P; LLDAP_USER_PASSWORD="$P" exec /app/lldap_set_password -b http://127.0.0.1:17170 -t "$T" -u k8s-person' >/dev/null \
    || fail "could not set k8s-person's password"
  lldap_login "http://127.0.0.1:$lport" k8s-person "$kpw" || fail "k8s-person doesn't sign in to LLDAP before the backup"
  ./portcullis backup 2>&1 | redact
  B="$(find backups -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | tail -n1)"
  for f in postgres.dump lldap.dump; do [ "$(head -c 5 "$B/$f" 2>/dev/null)" = PGDMP ] || fail "the Kubernetes backup has no custom-format $f"; done
  [ ! -e "$B/lldap_data.tar.gz" ] || fail "the Kubernetes backup has an lldap_data volume (LLDAP is on Postgres)"
  ./portcullis backup verify --local "$B" 2>&1 | redact
  lldap_has "http://127.0.0.1:$lport" k8s-person true || fail "k8s-person isn't in LLDAP before the backup's restore"
  lldap_gql "http://127.0.0.1:$lport" 'mutation { deleteUser(userId: "k8s-person") { ok } }' >/dev/null
  lldap_has "http://127.0.0.1:$lport" k8s-person false || fail "k8s-person wasn't deleted before the restore"
  ./portcullis restore --yes "$B" 2>&1 | redact
  status_wait 600
  lport="$(pf_svc lldap 17170)"
  lldap_has "http://127.0.0.1:$lport" k8s-person true || fail "k8s-person isn't back in LLDAP after the restore (lldap.dump into CNPG)"
  lldap_login "http://127.0.0.1:$lport" k8s-person "$kpw" || fail "k8s-person's password doesn't bind after the restore (the restored hash under the restored server key)"
  K -n cnpg-system exec "$(K -n cnpg-system get cluster portcullis-pg -o jsonpath='{.status.currentPrimary}')" -c postgres -- psql -XtAq -c "select count(*) from pg_database where datname like '%\_pre\_restore' or datname like '%\_restore'" | grep -qx 0 \
    || fail "the restore left keycloak/lldap _restore or _pre_restore databases"
  kc_signin || exit 1
  echo "PASS: test_restore_into_cnpg: a Kubernetes backup (pg_dump keycloak + lldap) restored into CNPG through <db>_restore and a rename; LLDAP has k8s-person again and its password binds, Keycloak signs in, no leftover database"
  # The Docker phase's backup. test_lldap_convert_refuses_on_diff (plan
  # Task 26): one row changed inside the conversion's transaction (the
  # development hook, HUB_DEV=1) → refused before anything of the live
  # install changes: LLDAP's Deployment as it was, the live database still
  # k8s-person's, the Hub not stopped, no lldap_restore left.
  ldgen="$(K -n portcullis get deploy lldap -o jsonpath='{.metadata.generation}/{.spec.replicas}')"
  hubrep="$(K -n portcullis get deploy hub -o jsonpath='{.spec.replicas}')"
  rc=0
  HUB_DEV=1 PORTCULLIS_DEV_LLDAP_CONVERT_FAULT="UPDATE users SET uuid = '00000000-0000-4000-8000-000000000000' WHERE user_id = 'rt-alice';" \
    ./portcullis restore --yes "$RUNNER_TEMP/rt-backup" > "$RUNNER_TEMP/rt-fault.log" 2>&1 || rc=$?
  redact < "$RUNNER_TEMP/rt-fault.log" | tail -n 5
  [ "$rc" != 0 ] && grep -q "LLDAP conversion changed the users' uuids: nothing was switched" "$RUNNER_TEMP/rt-fault.log" || fail "test_lldap_convert_refuses_on_diff: the faulty conversion wasn't refused (rc $rc)"
  [ "$(K -n portcullis get deploy lldap -o jsonpath='{.metadata.generation}/{.spec.replicas}')" = "$ldgen" ] || fail "test_lldap_convert_refuses_on_diff: LLDAP's Deployment changed"
  [ "$(K -n portcullis get deploy hub -o jsonpath='{.spec.replicas}')" = "$hubrep" ] || fail "test_lldap_convert_refuses_on_diff: the Hub was stopped"
  pgp() { K -n cnpg-system exec -i "$(K -n cnpg-system get cluster portcullis-pg -o jsonpath='{.status.currentPrimary}')" -c postgres -- psql -XtAq "$@"; }
  [ "$(pgp -c "select count(*) from pg_database where datname = 'lldap_restore'")" = 0 ] || fail "test_lldap_convert_refuses_on_diff: lldap_restore was left behind"
  lport="$(pf_svc lldap 17170)"
  lldap_has "http://127.0.0.1:$lport" k8s-person true || fail "test_lldap_convert_refuses_on_diff: the live LLDAP database changed (k8s-person gone)"
  echo "PASS: test_lldap_convert_refuses_on_diff: a changed row refused (\"LLDAP conversion changed the users' uuids\"), LLDAP's Deployment, the Hub and the live database untouched, nothing left"
  # test_lldap_convert_keeps_uuids: the real restore (no --allow-empty-lldap).
  ./portcullis restore --yes "$RUNNER_TEMP/rt-backup" 2>&1 | redact | tee "$RUNNER_TEMP/rt-restore.log"
  grep -qE "LLDAP: [0-9]+ user\(s\), [0-9]+ password hash\(es\); uuids, groups, memberships, hashes and attributes equal the backup's" "$RUNNER_TEMP/rt-restore.log" || fail "restore didn't convert the Docker backup's LLDAP"
  grep -qx 'CONTAINER_RUNTIME=kubernetes' .env && grep -qx 'PORTCULLIS_KUBE_CONTEXT=ci' .env || fail "restore didn't keep this host's kubernetes keys"
  status_wait 600
  [ "$(sha256sum certs/ca-chain.crt | cut -d' ' -f1)" = "$(cat "$RUNNER_TEMP/rt-ca.sha256")" ] || fail "the CA chain isn't the Docker phase's"
  kc_signin || exit 1
  pgp -d lldap -c "select 'U ' || user_id || ' ' || uuid || ' ' || coalesce(encode(sha256(password_hash), 'hex'), '-') from users order by user_id" > "$RUNNER_TEMP/rt-lldap-dst.txt"
  pgp -d lldap -c "select 'M ' || m.user_id || ' ' || g.display_name from memberships m join groups g using (group_id) order by 1" >> "$RUNNER_TEMP/rt-lldap-dst.txt"
  # The fixture's rows (the CLI's own reconcile may rightly touch the Hub's
  # account after the start; the conversion itself compared every row).
  fx() { grep -E '^(U|M) rt-' "$1" | sort; }
  diff <(fx "$RUNNER_TEMP/rt-lldap-src.txt") <(fx "$RUNNER_TEMP/rt-lldap-dst.txt") >/dev/null || fail "test_lldap_convert_keeps_uuids: LLDAP's users / uuids / hashes / memberships in CNPG differ from the Docker backup's"
  lport="$(pf_svc lldap 17170)"
  for u in rt-person rt-alice rt-bob; do lldap_has "http://127.0.0.1:$lport" "$u" true || fail "$u isn't in LLDAP after the Docker → Kubernetes restore"; done
  while read -r u pw; do
    lldap_login "http://127.0.0.1:$lport" "$u" "$pw" || fail "test_lldap_convert_keeps_uuids: $u's password doesn't bind after the conversion (the hash under the backup's seed)"
  done < "$RUNNER_TEMP/rt-lldap.pw"
  # Keycloak finds the fixture user through LDAP federation, linked by
  # LLDAP's entryUUID: the uuid the Docker phase's users.db had.
  kpw="$(grep '^KEYCLOAK_ADMIN_PASSWORD=' .env | cut -d= -f2-)"; echo "::add-mask::$kpw"
  kport="$(pf_svc keycloak 8080)"
  ktok="$(PW="$kpw" jq -jn '"grant_type=password&client_id=admin-cli&username=admin&password=" + (env.PW | @uri)' \
    | curl -sf --max-time 10 "http://127.0.0.1:$kport/realms/master/protocol/openid-connect/token" -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @- | jq -r .access_token)"
  echo "::add-mask::$ktok"
  kid="$(curl -sf --max-time 20 -H @<(printf 'Authorization: Bearer %s\n' "$ktok") "http://127.0.0.1:$kport/admin/realms/portcullis/users?username=rt-alice&exact=true" | jq -r '.[0].attributes.LDAP_ID[0] // empty')"
  [ "$kid" = "$(awk '$1 == "U" && $2 == "rt-alice" { print $3 }' "$RUNNER_TEMP/rt-lldap-src.txt")" ] || fail "test_lldap_convert_keeps_uuids: Keycloak's rt-alice has LDAP_ID '$kid', not the Docker backup's uuid"
  [ "$(pgp -c "select count(*) from pg_database where datname like '%\_pre\_restore' or datname like '%\_restore'")" = 0 ] || fail "the restore left _restore / _pre_restore databases"
  echo "PASS: test_lldap_convert_keeps_uuids: the Docker backup's LLDAP converted into CNPG (uuids, password hashes and memberships equal the source, rt-alice and rt-bob bind with their passwords, Keycloak links rt-alice by the same entryUUID); host keys kept, status clean, the CA chain the Docker phase's, Keycloak signs in"
  ;;
*) echo "usage: $0 docker|init|seed|hub|vpn|restore" >&2; exit 2 ;;
esac
