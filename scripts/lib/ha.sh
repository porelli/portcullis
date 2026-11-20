# shellcheck shell=bash
#
# HA pieces of the CLI on Kubernetes (plan R8: new kube CLI code lives in
# kube_install.sh / ha.sh / node.sh). Sourced by runtime.sh after
# kube_install.sh. Bash 3.2 compatible.
#
# Postgres on CloudNativePG (plan Task 23, D8 "the HA shape always"): every
# Kubernetes install runs the CNPG operator (namespace cnpg-system, chart
# kube/ha/cnpg/, pinned by sha256 and image digest) and one Cluster
# portcullis-pg there (the core chart's templates/postgres-cnpg.yaml: 1
# instance, 2 or 3 in HA) with the databases keycloak and lldap; LLDAP runs
# on it (no lldap-data PVC). Here:
#   - ha_install_cnpg: the namespace (PSA from namespaces.json "cnpg") and
#     the operator (helm upgrade --install of the vendored chart with the
#     vendored values file only: never --set);
#   - the Postgres roles' Secrets (kube_pg_sync_secrets): in cnpg-system
#     portcullis-pg-keycloak / portcullis-pg-lldap (basic-auth, the managed
#     roles' passwords), in the core namespace portcullis-pg-lldap (LLDAP's
#     LLDAP_DATABASE_URL and PGPASSWORD for its schema Job), all built from
#     0600 files in a 0700 staging dir (--from-file), never argv;
#   - LLDAP's server key (kube_lldap_server_key): secrets/lldap-key/server_key,
#     made once by `lldap create_schema` in an offline pod and read with
#     exec cat (never a log), synced as Secret secrets-lldap-key;
#   - the primary (kube_pg_primary: the pod portcullis-pg-rw selects), its
#     health and exec for rt_health / rt_exec postgres.

KUBE_CNPG_NS="cnpg-system"
KUBE_PG_CLUSTER="portcullis-pg"
KUBE_CNPG_RELEASE="cnpg"
# The pins (plan Amendment 1: CloudNativePG v1.30.2): the chart release
# asset's sha256 (cloudnative-pg/charts cloudnative-pg-v0.29.2, appVersion
# 1.30.2) and the operator image's index digest, which the values file must
# name.
KUBE_CNPG_CHART="kube/ha/cnpg/cloudnative-pg-0.29.2.tgz"
KUBE_CNPG_CHART_SHA256="9df3f074ecaa8af10277ad155899470618ea9a565d7c7c48187bdc7887655960"
KUBE_CNPG_VALUES="kube/ha/cnpg/values.yaml"
KUBE_CNPG_IMAGE_DIGEST="sha256:f96f6be3d81ec93819b443c665c575c609342fca840df90d4d87dae314a5b913"
# The rw Service's selector (the primary) and its DNS name.
KUBE_PG_PRIMARY_SELECTOR="cnpg.io/cluster=$KUBE_PG_CLUSTER,cnpg.io/instanceRole=primary"
KUBE_PG_RW_HOST="$KUBE_PG_CLUSTER-rw.$KUBE_CNPG_NS.svc.cluster.local"

# ha_cnpg_pins_ok — the vendored chart has its pinned sha256 and the values
# file names the pinned operator digest (fail closed: anything else
# installs nothing).
ha_cnpg_pins_ok() {
  local tgz="$PORTCULLIS_HOME/$KUBE_CNPG_CHART" vf="$PORTCULLIS_HOME/$KUBE_CNPG_VALUES" got
  [ -f "$tgz" ] || { _K_ERR="$KUBE_CNPG_CHART is missing"; return 1; }
  got="$(_kube_sha "$tgz")"
  [ "$got" = "$KUBE_CNPG_CHART_SHA256" ] || { _K_ERR="$KUBE_CNPG_CHART has sha256 $got, not the pinned $KUBE_CNPG_CHART_SHA256"; return 1; }
  grep -Eq "^  tag: \"[0-9.]+@$KUBE_CNPG_IMAGE_DIGEST\"$" "$vf" 2>/dev/null \
    || { _K_ERR="$KUBE_CNPG_VALUES doesn't pin the operator image to $KUBE_CNPG_IMAGE_DIGEST"; return 1; }
  _K_ERR=""
}

# ha_install_cnpg — the operator (idempotent: every run re-applies, as the
# rest of kube_cluster_setup): cnpg-system with its PSA labels, then the
# pinned chart with the vendored values file (--wait: the webhook answers
# before the core chart's Cluster is sent).
ha_install_cnpg() {
  local psa
  ha_cnpg_pins_ok || fail "the CloudNativePG pins don't hold: $_K_ERR (nothing installed)"
  psa="$(kube_psa cnpg)" || exit 1
  # shellcheck disable=SC2086  # three single-word levels
  kube_namespace_apply "$KUBE_CNPG_NS" $psa || fail "could not create the namespace $KUBE_CNPG_NS"
  info "Cluster setup: CloudNativePG operator ($KUBE_CNPG_CHART)..."
  kube_helm upgrade --install "$KUBE_CNPG_RELEASE" "$PORTCULLIS_HOME/$KUBE_CNPG_CHART" -n "$KUBE_CNPG_NS" \
    -f "$PORTCULLIS_HOME/$KUBE_CNPG_VALUES" --history-max 3 --wait --timeout 5m >/dev/null \
    || fail "the CloudNativePG operator didn't install (see above)"
  _kube_applied_set cluster.cnpg "$KUBE_CNPG_CHART_SHA256"
}

# kube_apiserver_sources — the addresses the API server's webhook calls
# come from (the CNPG webhook admits only these, contract §20.1): every API
# endpoint, and per control-plane node the first two addresses of its pod
# range (flannel's and cni0's: kube-proxy masquerades the host's traffic to
# a pod onto them). Space-separated IPv4s; empty when unreadable.
kube_apiserver_sources() {
  local nodes ep
  # shellcheck disable=SC2086  # ip:port words
  ep="$(printf '%s\n' ${PORTCULLIS_KUBE_API_ENDPOINTS:-} | sed 's/:[0-9]*$//')"
  nodes="$(kube_ctl get nodes -l node-role.kubernetes.io/control-plane -o json 2>/dev/null \
    | jq -r '.items[].spec.podCIDR // empty | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$"))
        | split("/")[0] | split(".") | map(tonumber) as $o
        | ($o | map(tostring) | join(".")), ($o[0:3] + [$o[3] + 1] | map(tostring) | join("."))' 2>/dev/null || true)"
  printf '%s\n%s\n' "$ep" "$nodes" | awk 'NF && !seen[$0]++' | tr '\n' ' ' | sed 's/ $//'
}

# kube_pg_primary — the primary instance's pod name (the one portcullis-pg-rw
# selects); exit 1 when there is none.
kube_pg_primary() {
  local p
  p="$(kube_ctl -n "$KUBE_CNPG_NS" get pods -l "$KUBE_PG_PRIMARY_SELECTOR" -o json 2>/dev/null \
    | jq -r '[.items[] | select(.metadata.deletionTimestamp == null and .status.phase == "Running")] | .[0].metadata.name // empty' 2>/dev/null || true)"
  [ -n "$p" ] || return 1
  printf '%s\n' "$p"
}

# _kube_pg_health — rt_health postgres on Kubernetes: missing (no Cluster),
# healthy (its primary's postgres container Ready), else starting /
# unhealthy (the primary not ready after it started).
_kube_pg_health() {
  local p
  kube_ctl -n "$KUBE_CNPG_NS" get cluster.postgresql.cnpg.io "$KUBE_PG_CLUSTER" -o name >/dev/null 2>&1 || { echo missing; return 0; }
  p="$(kube_pg_primary)" || { echo starting; return 0; }
  kube_ctl -n "$KUBE_CNPG_NS" get pod "$p" -o json 2>/dev/null | jq -r '
      ([.status.containerStatuses[]? | select(.name == "postgres")] | .[0] // {}) as $c
      | if $c.ready == true then "healthy" elif $c.started == true then "unhealthy" else "starting" end' 2>/dev/null || echo missing
}

# _kube_pg_exec <argv…> — rt_exec postgres: the command in the primary's
# postgres container (as its own user postgres: the local socket's peer
# authentication, so pg_dump / pg_restore need no password), stdin passed.
_kube_pg_exec() {
  local p
  p="$(kube_pg_primary)" || { echo "no Postgres primary is running ($KUBE_CNPG_NS/$KUBE_PG_CLUSTER)" >&2; return 1; }
  kube_ctl -n "$KUBE_CNPG_NS" exec -i "$p" -c postgres -- "$@" \
    2> >(awk '!/^command terminated with exit code [0-9]+$/ { print; fflush() }' >&2)
}

# _kube_pg_wait <seconds> — the Cluster's primary accepts connections.
_kube_pg_wait() {
  local i
  for ((i = 0; i < "$1"; i += 2)); do
    _kube_pg_exec pg_isready -q >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

# kube_pg_sync_secrets — the roles' Secrets (see the header). LLDAP's
# password is generated into .env once (LLDAP_PG_PASSWORD): CNPG's managed
# role takes its password from the Secret on every reconcile, so a new one
# never locks LLDAP out.
kube_pg_sync_secrets() {
  local st f
  [ -n "${POSTGRES_PASSWORD:-}" ] || fail "POSTGRES_PASSWORD is not set in .env"
  [ -n "${LLDAP_PG_PASSWORD:-}" ] || env_generate_missing LLDAP_PG_PASSWORD
  [ -n "${LLDAP_PG_PASSWORD:-}" ] || fail "LLDAP_PG_PASSWORD could not be generated"
  st="$(mktemp -d)"; chmod 700 "$st"
  f="$st/obj.json"
  (umask 077
   mkdir -p "$st/kc" "$st/ll" "$st/url"
   printf 'keycloak' > "$st/kc/username"; printf '%s' "$POSTGRES_PASSWORD" > "$st/kc/password"
   printf 'lldap' > "$st/ll/username"; printf '%s' "$LLDAP_PG_PASSWORD" > "$st/ll/password"
   printf 'postgres://lldap:%s@%s:5432/lldap' "$LLDAP_PG_PASSWORD" "$KUBE_PG_RW_HOST" > "$st/url/LLDAP_DATABASE_URL"
   printf '%s' "$LLDAP_PG_PASSWORD" > "$st/url/PGPASSWORD")
  if ! { kube_ctl create secret generic portcullis-pg-keycloak -n "$KUBE_CNPG_NS" --type=kubernetes.io/basic-auth --from-file="$st/kc" --dry-run=client -o json > "$f" && _kube_put "$f"; } \
     || ! { kube_ctl create secret generic portcullis-pg-lldap -n "$KUBE_CNPG_NS" --type=kubernetes.io/basic-auth --from-file="$st/ll" --dry-run=client -o json > "$f" && _kube_put "$f"; } \
     || ! { kube_ctl create secret generic portcullis-pg-lldap -n "$(kube_ns)" --from-file="$st/url" --dry-run=client -o json > "$f" && _kube_put "$f"; }; then
    rm -rf "$st"; fail "could not sync the Postgres roles' Secrets"
  fi
  rm -rf "$st"
}

# kube_lldap_server_key — secrets/lldap-key/server_key (0600), LLDAP's one
# server key (plan Amendment 2: every replica mounts the same one; it
# protects the OPAQUE password files): kept when present (a restore brings
# the backup's), else made by `lldap create_schema` in an offline pod of
# the pinned LLDAP image (a throwaway SQLite database, LLDAP_KEY_FILE in a
# memory emptyDir; the dummy JWT secret / admin password it needs to start
# are no secrets), read with exec cat into the file, never through a log.
kube_lldap_server_key() {
  local d="$PORTCULLIS_ROOT/secrets/lldap-key" img name ns tmp rc=0
  [ -s "$d/server_key" ] && return 0
  kube_images_ready
  img="$(printf '%s' "$_K_IMAGES" | jq -r '.lldap // empty')"
  [ -n "$img" ] || fail "no image for lldap"
  ns="$(kube_ns)"
  name="lldap-key-$(openssl rand -hex 3)"
  N="$name" NS="$ns" IMG="$img" U="$CT_UID_LLDAP" jq -n '
    {apiVersion: "v1", kind: "Pod", metadata: {name: env.N, namespace: env.NS, labels: {"portcullis.io/component": "keygen"}},
     spec: {restartPolicy: "Never", priorityClassName: "portcullis-core", automountServiceAccountToken: false, enableServiceLinks: false, terminationGracePeriodSeconds: 1,
       securityContext: {runAsNonRoot: true, runAsUser: (env.U | tonumber), runAsGroup: (env.U | tonumber), seccompProfile: {type: "RuntimeDefault"}},
       volumes: [{name: "k", emptyDir: {medium: "Memory", sizeLimit: "16Mi"}}],
       containers: [{name: "keygen", image: env.IMG, workingDir: "/k",
         command: ["sh", "-c", "umask 077; /app/lldap create_schema >/dev/null 2>&1 && test -s /k/new/server_key && mv /k/new/server_key /k/server_key && exec sleep 600"],
         env: [{name: "LLDAP_DATABASE_URL", value: "sqlite:///k/keygen.db?mode=rwc"}, {name: "LLDAP_KEY_FILE", value: "/k/new/server_key"},
               {name: "LLDAP_KEY_SEED", value: ""}, {name: "LLDAP_JWT_SECRET", value: "keygen-only-not-a-secret"},
               {name: "LLDAP_LDAP_USER_PASS", value: "keygen-only-not-a-secret"}],
         volumeMounts: [{name: "k", mountPath: "/k"}],
         resources: {limits: {memory: "128Mi"}, requests: {memory: "128Mi"}},
         securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}}]}}' \
    | jq '.spec.initContainers = [.spec.containers[0] | .name = "mkdir" | .command = ["mkdir", "-p", "/k/new"] | del(.env) | del(.workingDir)]' \
    | kube_ctl create -f - >/dev/null || fail "the LLDAP key pod was refused (see above)"
  if ! kube_ctl -n "$ns" wait --for=condition=Ready "pod/$name" --timeout="${KUBE_POD_WAIT:-180}s" >/dev/null 2>&1; then
    _kube_pod_diag "$name"
    kube_ctl -n "$ns" delete pod "$name" --wait=false >/dev/null 2>&1 || true
    fail "could not make LLDAP's server key"
  fi
  (umask 077 && mkdir -p "$d")
  tmp="$(mktemp "$d/.server_key.XXXXXX")"
  kube_ctl -n "$ns" exec "$name" -c keygen -- sh -c 'i=0; while [ ! -s /k/server_key ] && [ "$i" -lt 300 ]; do sleep 0.1; i=$((i + 1)); done; cat /k/server_key' > "$tmp" 2>/dev/null || rc=$?
  kube_ctl -n "$ns" delete pod "$name" --wait=false >/dev/null 2>&1 || true
  if [ "$rc" != 0 ] || [ ! -s "$tmp" ]; then rm -f "$tmp"; fail "could not read the LLDAP key pod's key"; fi
  chmod 600 "$tmp" && mv -f "$tmp" "$d/server_key"
  ok "Made LLDAP's server key (secrets/lldap-key/server_key)."
}

# ── backup / restore of the CNPG databases (plan Task 23) ──

# _kube_pg_dump <db> <out> — pg_dump -Fc of one database from the primary
# (the pod portcullis-pg-rw selects), as postgres over the socket.
_kube_pg_dump() {
  _kube_pg_exec pg_dump -d "$1" -Fc > "$2" || fail "pg_dump of $1 failed"
  [ "$(head -c 5 "$2")" = PGDMP ] || fail "pg_dump of $1 is not a custom-format dump"
}

# _kube_pg_reset_db <db> <owner> — the database dropped (its sessions
# ended) and made again empty, owned by its role: the restore's "new
# cluster" (D8: no migration of an existing one, the dump replaces it).
# (The operator's Database lldap may make it again first: an empty one it
# made, owned by lldap, counts.)
_kube_pg_reset_db() {
  _kube_pg_exec dropdb --if-exists --force "$1" >/dev/null || return 1
  _kube_pg_exec createdb -O "$2" "$1" >/dev/null 2>&1 && return 0
  [ "$(_kube_pg_exec psql -XtAq -c "select pg_get_userbyid(datdba) from pg_database where datname = '$1'" 2>/dev/null)" = "$2" ]
}

# _kube_pg_restore <dump> <db> <owner> — the dump into the emptied database,
# every object owned by the database's role (--no-owner --role), in one
# transaction, stopping at the first error.
_kube_pg_restore() {
  _kube_pg_reset_db "$2" "$3" || fail "could not empty the database $2"
  _kube_pg_exec pg_restore -d "$2" --no-owner --no-privileges --role="$3" --exit-on-error --single-transaction < "$1" \
    || fail "pg_restore of $2 failed"
}

# _kube_restore_pg <dir> — restore on Kubernetes: Postgres' primary up,
# keycloak from postgres.dump; lldap from lldap.dump when the backup has one
# (a Kubernetes backup), else emptied (a Docker / Podman backup's LLDAP is
# SQLite in lldap_data.tar.gz: its conversion into Postgres is the restore
# step of plan Task 26, not done here) — LLDAP's schema Jobs are deleted so
# the release runs them again on the emptied database.
_kube_restore_pg() {
  local dir="$1"
  info "Restoring the databases into the CNPG cluster $KUBE_PG_CLUSTER (pg_restore)..."
  _kube_pg_wait 600 || fail "the Postgres primary ($KUBE_CNPG_NS/$KUBE_PG_CLUSTER) doesn't accept connections"
  _kube_pg_restore "$dir/postgres.dump" keycloak keycloak
  if [ -s "$dir/lldap.dump" ]; then
    _kube_pg_restore "$dir/lldap.dump" lldap lldap
  else
    _kube_pg_reset_db lldap lldap || fail "could not empty the database lldap"
    [ ! -f "$dir/lldap_data.tar.gz" ] \
      || warn "This backup's LLDAP is SQLite (lldap_data.tar.gz, made on Docker / Podman): it isn't converted into Postgres on Kubernetes yet, so LLDAP starts empty."
  fi
  kube_ctl -n "$(kube_ns)" delete job -l portcullis.io/component=lldap-schema --ignore-not-found >/dev/null \
    || fail "could not remove LLDAP's schema Jobs"
}

# _kube_pg_lldap_count — LLDAP's users besides admin / portcullis-hub in the
# database lldap, or "missing" (no schema, no primary).
_kube_pg_lldap_count() {
  local n
  n="$(_kube_pg_exec psql -XtAq -d lldap -c "select count(*) from users where user_id not in ('admin', 'portcullis-hub')" 2>/dev/null || true)"
  case "$n" in ''|*[!0-9]*) echo missing ;; *) echo "$n" ;; esac
}

# ── moved from kube.sh (plan R8: kube.sh doesn't grow) ──

# _kube_restore_lldap_count — LLDAP's users besides admin / portcullis-hub
# from its PVC (group-gate's python, read-only, as LLDAP's uid), or "missing".
_kube_restore_lldap_count() {
  local pod out
  # LLDAP on Postgres (plan Task 23): its database, not a PVC.
  if ! _kube_volume_exists lldap_data; then _kube_pg_lldap_count; return 0; fi
  pod="$(_kube_helper_pod lldap-data "$CT_UID_LLDAP:$CT_UID_LLDAP" ro "$(_kube_image_of group-gate)")" || { echo missing; return 0; }
  out="$(kube_ctl -n "$(kube_ns)" exec "$pod" -- env PYTHONDONTWRITEBYTECODE=1 python3 -c "$_BACKUP_PY_COUNT_LLDAP" 2>/dev/null || echo missing)"
  _kube_helper_done "$pod"
  echo "$out"
}

# _backup_verify_dir_kube <dir> — backup_verify_dir on kubernetes: the
# checksums, the raft snapshot, the dump (pg_restore --list in the running
# Postgres, over exec stdin), LLDAP's database (group-gate's python in a
# helper pod, the archive on stdin), every archive readable.
_backup_verify_dir_kube() {
  local dir="$1" t rc=0 n f pod
  _backup_check_layout "$dir"
  _backup_check_manifest "$dir" || fail "checksum mismatch in $dir"
  ok "checksums match MANIFEST.json ($(jq '.files | length' "$dir/MANIFEST.json") files)"
  t="$(mktemp -d)"
  if tar -xzf "$dir/vault.snap" -C "$t" 2>/dev/null && [ -s "$t/state.bin" ] && jq -e '.Index > 0' "$t/meta.json" >/dev/null 2>&1; then
    ok "vault.snap parses (raft index $(jq -r .Index "$t/meta.json"))"
  else
    rc=1; warn "vault.snap is not a valid raft snapshot"
  fi
  rm -rf "$t"
  if n="$(rt_exec -i postgres -- pg_restore --list < "$dir/postgres.dump" 2>/dev/null | grep -c 'TABLE DATA')" && [ "$n" -gt 0 ]; then
    ok "postgres.dump lists $n tables' data"
  else
    rc=1; warn "postgres.dump does not list (pg_restore --list)"
  fi
  if [ -f "$dir/lldap.dump" ]; then
    if n="$(rt_exec -i postgres -- pg_restore --list < "$dir/lldap.dump" 2>/dev/null | grep -c 'TABLE DATA')" && [ "$n" -gt 0 ]; then
      ok "lldap.dump lists $n tables' data"
    else
      rc=1; warn "lldap.dump does not list (pg_restore --list)"
    fi
  elif [ -f "$dir/lldap_data.tar.gz" ]; then
    if pod="$(_kube_helper_pod "" 65534:65534 ro "$(_kube_image_of group-gate)")"; then
      if f="$(kube_ctl -n "$(kube_ns)" exec -i "$pod" -- env PYTHONDONTWRITEBYTECODE=1 python3 -c "$_BACKUP_PY_CHECK_LLDAP" < "$dir/lldap_data.tar.gz")"; then
        ok "lldap: $f"
      else
        rc=1; warn "lldap_data.tar.gz: the LLDAP database is unusable"
      fi
      _kube_helper_done "$pod"
    else
      rc=1; warn "could not start a helper to check lldap_data.tar.gz"
    fi
  else
    rc=1; warn "no lldap.dump or lldap_data.tar.gz"
  fi
  for f in "$dir"/*.tar.gz; do
    [ -f "$f" ] || continue
    tar -tzf "$f" >/dev/null 2>&1 && ok "$(basename "$f") is a readable archive" || { rc=1; warn "$(basename "$f") is corrupt"; }
  done
  return "$rc"
}
