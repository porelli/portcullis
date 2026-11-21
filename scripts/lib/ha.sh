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
# The operator's RBAC (review I2: the chart runs with rbac.create false).
KUBE_CNPG_RBAC="kube/ha/cnpg/rbac.yaml"
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

# ha_cnpg_policies <api endpoints (ip:port words)> <API server sources
# (ip words)> — cnpg-system's own NetworkPolicies as a JSON List (review
# I4: the CLI's, applied before the operator runs and outliving the core
# release): default deny; kube-dns for every pod; the operator
# (app.kubernetes.io/name=cloudnative-pg) reaches the API endpoints and
# the instances' status port 8000, and its webhook :9443 admits only the
# API server's addresses. The instances' flows are the core chart's
# (templates/postgres-cnpg.yaml). tests/k8s_netpol_matrix.py judges them.
ha_cnpg_policies() {
  NS="$KUBE_CNPG_NS" API="$1" SRC="$2" jq -n '
    def words: split(" ") | map(select(. != ""));
    def meta($n): {name: $n, namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis"}};
    {apiVersion: "v1", kind: "List", items: [
      {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: meta("default-deny"),
       spec: {podSelector: {}, policyTypes: ["Ingress", "Egress"]}},
      {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: meta("kube-dns"),
       spec: {podSelector: {}, policyTypes: ["Egress"],
              egress: [{to: [{namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": "kube-system"}}, podSelector: {matchLabels: {"k8s-app": "kube-dns"}}}],
                        ports: [{protocol: "UDP", port: 53}, {protocol: "TCP", port: 53}]}]}},
      {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: meta("cnpg-operator"),
       spec: {podSelector: {matchLabels: {"app.kubernetes.io/name": "cloudnative-pg"}}, policyTypes: ["Ingress", "Egress"],
              ingress: [{from: [env.SRC | words | .[] | {ipBlock: {cidr: (. + "/32")}}], ports: [{protocol: "TCP", port: 9443}]}],
              egress: ([env.API | words | .[] | split(":") as $p | {to: [{ipBlock: {cidr: ($p[0] + "/32")}}], ports: [{protocol: "TCP", port: ($p[1] | tonumber)}]}]
                       + [{to: [{podSelector: {matchLabels: {"cnpg.io/cluster": "portcullis-pg"}}}], ports: [{protocol: "TCP", port: 8000}]}])}}]}'
}

# ha_install_cnpg — the operator (idempotent: every run re-applies, as the
# rest of kube_cluster_setup): cnpg-system with its PSA labels, its
# NetworkPolicies (ha_cnpg_policies, before anything runs there), the
# operator's RBAC (kube/ha/cnpg/rbac.yaml), then the pinned chart with the
# vendored values file (--wait: the webhook answers before the core
# chart's Cluster is sent).
ha_install_cnpg() {
  local psa src
  ha_cnpg_pins_ok || fail "the CloudNativePG pins don't hold: $_K_ERR (nothing installed)"
  src="$(kube_apiserver_sources)" || src=""
  [ -n "$src" ] || fail "can't read the API server's addresses (the API endpoints, the control-plane nodes' pod ranges): the CNPG webhook would admit nobody (nothing installed)"
  psa="$(kube_psa cnpg)" || exit 1
  # shellcheck disable=SC2086  # three single-word levels
  kube_namespace_apply "$KUBE_CNPG_NS" $psa || fail "could not create the namespace $KUBE_CNPG_NS"
  ha_cnpg_policies "${PORTCULLIS_KUBE_API_ENDPOINTS:-}" "$src" \
    | kube_ctl apply --server-side --force-conflicts --field-manager="$KUBE_FIELD_MANAGER" -f - >/dev/null \
    || fail "could not apply $KUBE_CNPG_NS's NetworkPolicies (nothing installed)"
  _kube_apply_files "$PORTCULLIS_HOME/$KUBE_CNPG_RBAC" || fail "could not apply the CloudNativePG operator's RBAC ($KUBE_CNPG_RBAC)"
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
# a pod onto them). Space-separated IPv4s; nothing and exit 1 when the
# nodes can't be read (re-review M-c: never a partial list that would drop
# a server's sources from the webhook's policy).
kube_apiserver_sources() {
  local nodes ep json
  # shellcheck disable=SC2086  # ip:port words
  ep="$(printf '%s\n' ${PORTCULLIS_KUBE_API_ENDPOINTS:-} | sed 's/:[0-9]*$//')"
  json="$(kube_ctl get nodes -l node-role.kubernetes.io/control-plane -o json 2>/dev/null)" && printf '%s' "$json" | jq -e '.items | type == "array"' >/dev/null 2>&1 || return 1
  nodes="$(printf '%s' "$json" \
    | jq -r '.items[].spec.podCIDR // empty | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$"))
        | split("/")[0] | split(".") | map(tonumber) as $o
        | ($o | map(tostring) | join(".")), ($o[0:3] + [$o[3] + 1] | map(tostring) | join("."))' 2>/dev/null || true)"
  printf '%s\n%s\n' "$ep" "$nodes" | awk 'NF && !seen[$0]++' | tr '\n' ' ' | sed 's/ $//'
}

# kube_pg_primary — the primary instance's pod name: the Cluster's
# status.currentPrimary, and only when it is the one Running pod labelled
# primary (review M3: a stale label on a lost node's pod, or two primaries
# mid-failover, is no answer); exit 1 otherwise.
kube_pg_primary() {
  local cur p
  cur="$(kube_ctl -n "$KUBE_CNPG_NS" get cluster.postgresql.cnpg.io "$KUBE_PG_CLUSTER" -o json 2>/dev/null | jq -r '.status.currentPrimary // empty' 2>/dev/null || true)"
  [ -n "$cur" ] || return 1
  p="$(kube_ctl -n "$KUBE_CNPG_NS" get pods -l "$KUBE_PG_PRIMARY_SELECTOR" -o json 2>/dev/null \
    | jq -r '[.items[] | select(.metadata.deletionTimestamp == null)] | if length == 1 and .[0].status.phase == "Running" then .[0].metadata.name else empty end' 2>/dev/null || true)"
  [ -n "$p" ] && [ "$p" = "$cur" ] || return 1
  printf '%s\n' "$p"
}

# kube_pg_nodes_at_primary — the labelled non-small nodes at the primary
# site, Ready or not (review I1: CNPG's instances follow the layout, never
# a moment's readiness); refuses (exit 1, a message) when unreadable.
kube_pg_nodes_at_primary() {
  local n
  n="$(kube_ctl get nodes -l "portcullis.io/site=$KUBE_PRIMARY_SITE,portcullis.io/class in (home,cloud)" -o json 2>/dev/null | jq -r '.items | length' 2>/dev/null || true)"
  [[ "$n" =~ ^[0-9]+$ ]] || { warn "can't read the nodes at $KUBE_PRIMARY_SITE: Postgres' instance count would be a guess (nothing rendered)"; return 1; }
  printf '%s\n' "$n"
}

# kube_pg_min_instances [--shrink] — the live Cluster's spec.instances (0
# before it exists), the render's floor (review I1): only the node-remove
# path (plan Tasks 30/31) passes --shrink, through kube_render_values'
# argument (re-review N2: never from .env or the environment — a
# KUBE_PG_SHRINK there is refused). Unreadable refuses.
kube_pg_min_instances() {
  local out rc=0
  [ -z "${KUBE_PG_SHRINK+x}" ] || { warn "KUBE_PG_SHRINK is set in .env or the environment: refused (only node remove may lower Postgres' instances)"; return 1; }
  [ "${1:-}" != --shrink ] || { echo 0; return 0; }
  out="$(kube_ctl -n "$KUBE_CNPG_NS" get cluster.postgresql.cnpg.io "$KUBE_PG_CLUSTER" -o json 2>&1)" || rc=$?
  if [ "$rc" != 0 ]; then
    case "$out" in *NotFound*|*"not found"*) echo 0; return 0 ;; esac
    warn "can't read the Cluster $KUBE_CNPG_NS/$KUBE_PG_CLUSTER: Postgres' instance count could shrink (nothing rendered)"; return 1
  fi
  out="$(printf '%s' "$out" | jq -r '.spec.instances // 0' 2>/dev/null || true)"
  [[ "$out" =~ ^[0-9]+$ ]] || { warn "the Cluster $KUBE_CNPG_NS/$KUBE_PG_CLUSTER has no readable spec.instances (nothing rendered)"; return 1; }
  printf '%s\n' "$out"
}

# kube_lldap_schema_retry — a Failed LLDAP schema Job is deleted before the
# release (review M5): Helm then makes it again under the same name.
kube_lldap_schema_retry() {
  local j
  for j in $(kube_ctl -n "$(kube_ns)" get jobs -l portcullis.io/component=lldap-schema -o json 2>/dev/null \
      | jq -r '.items[] | select(any(.status.conditions[]?; .type == "Failed" and .status == "True")) | .metadata.name' 2>/dev/null); do
    kube_ctl -n "$(kube_ns)" delete job "$j" >/dev/null 2>&1 || warn "could not remove the failed Job $j"
  done
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
  # cnpg.io/reload: the operator re-applies a role's password when its
  # Secret changes only with this label (a restored .env's passwords).
  if ! { kube_ctl create secret generic portcullis-pg-keycloak -n "$KUBE_CNPG_NS" --type=kubernetes.io/basic-auth --from-file="$st/kc" --dry-run=client -o json \
           | jq '.metadata.labels["cnpg.io/reload"] = "true"' > "$f" && _kube_put "$f"; } \
     || ! { kube_ctl create secret generic portcullis-pg-lldap -n "$KUBE_CNPG_NS" --type=kubernetes.io/basic-auth --from-file="$st/ll" --dry-run=client -o json \
           | jq '.metadata.labels["cnpg.io/reload"] = "true"' > "$f" && _kube_put "$f"; } \
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
# In HA the pod is pinned like the data (review M2): main, never small.
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
    | HA="$(kube_ha_on && echo on || true)" SITE="$KUBE_PRIMARY_SITE" jq 'if env.HA == "on" then .spec.affinity = {nodeAffinity: {requiredDuringSchedulingIgnoredDuringExecution: {nodeSelectorTerms: [{matchExpressions: [
        {key: "portcullis.io/site", operator: "In", values: [env.SITE]}, {key: "portcullis.io/class", operator: "NotIn", values: ["small"]}]}]}}} else . end' \
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

# _kube_pg_fresh_db <db> <owner> — an empty database owned by its role
# (dropped first when it exists; for the restore's <db>_restore only).
_kube_pg_fresh_db() {
  _kube_pg_exec dropdb --if-exists --force "$1" >/dev/null && _kube_pg_exec createdb -O "$2" "$1" >/dev/null
}

# _kube_pg_swap — the restored databases take the live names in ONE
# transaction (review I3, re-review N1: psql -1 applies only to -c / -f, so
# the SQL goes through -f - with -1 and ON_ERROR_STOP): keycloak / lldap →
# <db>_pre_restore, <db>_restore → <db>; their sessions ended first
# (Keycloak, LLDAP and the Hub are at 0; a straggler is terminated). Any
# statement refused (a session came back) rolls the whole swap back and it
# is retried, the live pair untouched until it commits.
_kube_pg_swap() {
  local i
  _kube_pg_exec dropdb --if-exists --force keycloak_pre_restore >/dev/null && _kube_pg_exec dropdb --if-exists --force lldap_pre_restore >/dev/null || return 1
  for i in 1 2 3 4 5; do
    _kube_pg_exec psql -X -q -v ON_ERROR_STOP=1 -1 -d postgres -f - >/dev/null <<'SQL' && return 0
select pg_terminate_backend(pid) from pg_stat_activity where datname in ('keycloak', 'lldap', 'keycloak_restore', 'lldap_restore') and pid <> pg_backend_pid();
alter database keycloak rename to keycloak_pre_restore;
alter database lldap rename to lldap_pre_restore;
alter database keycloak_restore rename to keycloak;
alter database lldap_restore rename to lldap;
SQL
    sleep 2
  done
  return 1
}

# _kube_pg_drop_pre_restore — after the restored stack is healthy: the
# databases the restore replaced (their dumps stay in the pre-restore dir).
_kube_pg_drop_pre_restore() {
  _kube_pg_exec dropdb --if-exists --force keycloak_pre_restore >/dev/null 2>&1 \
    && _kube_pg_exec dropdb --if-exists --force lldap_pre_restore >/dev/null 2>&1 \
    || warn "could not drop keycloak_pre_restore / lldap_pre_restore (the restore's replaced databases): drop them by hand"
}

# _kube_restore_pg <dir> <pre> — restore on Kubernetes (review I3: the live
# databases are never dropped before their replacements are whole):
#   1. the live keycloak and lldap dumped into <pre> (the pre-restore copy;
#      unreadable → nothing changed);
#   2. each dump pg_restore'd into <db>_restore, owned by its role
#      (--no-owner --role, one transaction, the first error stops it); lldap
#      from lldap.dump (a Kubernetes backup), else an empty lldap_restore
#      (a Docker / Podman backup's LLDAP is SQLite: its conversion is plan
#      Task 26's restore step) — any failure drops the half-made copies
#      and refuses, the live pair untouched;
#   3. _kube_pg_swap; then LLDAP's schema Jobs deleted (the release makes
#      them again) and the restored roles' passwords waited for.
_kube_restore_pg() {
  local dir="$1" pre="$2" db dump
  info "Restoring the databases into the CNPG cluster $KUBE_PG_CLUSTER (pg_restore)..."
  _kube_pg_wait 600 || fail "the Postgres primary ($KUBE_CNPG_NS/$KUBE_PG_CLUSTER) doesn't accept connections: nothing restored"
  _kube_pg_dump keycloak "$pre/postgres.dump"
  _kube_pg_dump lldap "$pre/lldap.dump"
  for db in keycloak lldap; do
    dump="$dir/postgres.dump"; [ "$db" = keycloak ] || dump="$dir/lldap.dump"
    if ! _kube_pg_fresh_db "${db}_restore" "$db"; then
      _kube_pg_exec dropdb --if-exists --force keycloak_restore >/dev/null 2>&1 || true
      fail "could not make the database ${db}_restore: the live databases are untouched"
    fi
    [ "$db" = keycloak ] || [ -s "$dump" ] || continue
    if ! _kube_pg_exec pg_restore -d "${db}_restore" --no-owner --no-privileges --role="$db" --exit-on-error --single-transaction < "$dump"; then
      _kube_pg_exec dropdb --if-exists --force keycloak_restore >/dev/null 2>&1 || true
      _kube_pg_exec dropdb --if-exists --force lldap_restore >/dev/null 2>&1 || true
      fail "pg_restore of ${dump##*/} failed: the live databases are untouched (their dumps before this restore: $pre/postgres.dump, $pre/lldap.dump)"
    fi
  done
  [ -s "$dir/lldap.dump" ] || [ ! -f "$dir/lldap_data.tar.gz" ] \
    || warn "This backup's LLDAP is SQLite (lldap_data.tar.gz, made on Docker / Podman): it isn't converted into Postgres on Kubernetes yet, so LLDAP starts empty."
  _kube_pg_swap || fail "could not put the restored databases in place (the live ones are untouched; dumps in $pre)"
  kube_ctl -n "$(kube_ns)" delete job -l portcullis.io/component=lldap-schema --ignore-not-found >/dev/null \
    || fail "could not remove LLDAP's schema Jobs"
  # The backup's role passwords (kube_pg_sync_secrets ran before) in effect
  # before Keycloak and LLDAP start on them.
  _kube_pg_roles_wait 300 || fail "the CNPG operator didn't apply the restored roles' passwords within 300 s"
}

# _kube_pg_roles_wait <seconds> — the operator has applied both roles'
# passwords from their Secrets as they are now (managedRolesStatus'
# passwordStatus names each Secret's resourceVersion).
_kube_pg_roles_wait() {
  local i want got
  for ((i = 0; i < "$1"; i += 3)); do
    want="$(kube_ctl -n "$KUBE_CNPG_NS" get secret portcullis-pg-keycloak portcullis-pg-lldap -o json 2>/dev/null | jq -c '[.items[].metadata.resourceVersion]' 2>/dev/null || true)"
    got="$(kube_ctl -n "$KUBE_CNPG_NS" get cluster.postgresql.cnpg.io "$KUBE_PG_CLUSTER" -o json 2>/dev/null \
      | jq -c '[.status.managedRolesStatus.passwordStatus.keycloak.resourceVersion, .status.managedRolesStatus.passwordStatus.lldap.resourceVersion]' 2>/dev/null || true)"
    [ -n "$want" ] && [ "$want" = "$got" ] && return 0
    sleep 3
  done
  return 1
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

# ══ HA infrastructure: Longhorn, external-snapshotter, fencing, cert-manager
# (plan Task 24, Amendments 1–2) ══
#
# Installed ONLY by `ha enable`'s step 3 (plan Task 31 calls these; never a
# non-HA install, never Docker / Podman). Each one, idempotent (every run
# re-applies):
#   1. checks the vendored upstream files against their sha256 pins
#      (_ha_pins) and refuses with nothing installed;
#   2. makes its namespace (PSA from namespaces.json) and applies its
#      default-deny + DNS + API egress + the operator's own flows
#      (ha_ns_policies) BEFORE anything runs there (as Task 23's I4);
#   3. checks the nodes it needs (the host probes: open-iscsi, iscsi_tcp,
#      nfs-common, the multipath blacklist, no ZFS dataset under Longhorn's
#      path; a watchdog for fencing) and refuses naming each node;
#   4. renders the pinned manifests (ha_render: helm template for Longhorn's
#      chart, then kubectl kustomize with kube/ha/<c>/kustomization.yaml —
#      images by digest, our PriorityClass, the narrowed RBAC; never --set),
#      applies them server-side and waits for them;
#   5. records ha.<c> in applied.json.
# Fencing fails closed: ha_fencing_ready answers per node, and every node
# must be ready before anything stateful fails over (Task 31 stops there);
# k3s runs kube-controller-manager with disable-force-detach-on-timeout (a
# volume never leaves an unfenced node by timeout) and Longhorn's
# node-down-pod-deletion-policy is do-nothing: only SNR's out-of-service
# taint moves a stateful pod off a dead node.

KUBE_LONGHORN_NS="longhorn-system"
KUBE_FENCING_NS="portcullis-fencing"
KUBE_CERTMANAGER_NS="cert-manager"
# The CLI's host probes (fix round 1, security review): their own namespace,
# no Role or workload of anyone there, pinned by portcullis-ha-probe-pods.
KUBE_HA_PROBE_NS="portcullis-ha-probe"
KUBE_HA_PROBE_POLICY="kube/ha/probe/admission.yaml"
# Our SNR image (kube/ha/fencing/snr-patch, .github/workflows/snr.yml; fix
# round 1): kube/ha/fencing pins this ref. Its digest is a placeholder
# until snr.yml's first main build: ha_install_fencing refuses it but for
# development / e2e, where HUB_DEV=1 lets PORTCULLIS_DEV_SNR_IMAGE (a
# name@sha256 ref) replace it.
HA_SNR_IMAGE="ghcr.io/porelli/portcullis-snr:edge@sha256:0000000000000000000000000000000000000000000000000000000000000000"
HA_SNR_PLACEHOLDER="sha256:0000000000000000000000000000000000000000000000000000000000000000"
HA_DIR="kube/ha"
KUBE_REPLICATED_SC="kube/storage/storageclass-replicated.yaml"

# _ha_pins <component> — "<path under kube/ha> <sha256>" words: the
# upstream artifacts (Amendment 1; cert-manager: Task 24's pin), the
# bundles' conversions (kube/ha/fencing/from-bundle.py) and SNR's agent
# template at the v0.13.0 tag (agent-daemonset.yaml.tmpl's base).
_ha_pins() {
  case "$1" in
    longhorn) echo "longhorn/upstream/longhorn-1.13.0.tgz e57f010d2a8bcf0da5b8b03ffecf49c5bc35ddc2663588ce8f22b7567b6133ed" ;;
    snapshotter) echo "snapshotter/upstream/crds.yaml 9942127fab40ddd5b991745c3aa9127f883df96639b538e3103e51a227a463d5
      snapshotter/upstream/rbac-snapshot-controller.yaml 99c4ac480b6c9563be0d85599e29cc7b68b25a82d250b0e789726727551e8d38
      snapshotter/upstream/setup-snapshot-controller.yaml 54b9342a7433c377b83a671babf416660078a716ec2e63f658a77aa629de5581" ;;
    fencing) echo "fencing/upstream/snr-v0.13.0-bundle.tar.gz c7d58af594390e5a544a4f0d51579e55462669bd8d5dfe37822dc833efd300c2
      fencing/upstream/snr-v0.13.0.yaml fc1076bb255eb59aa10a30386c0caf1a17b2f09922e50b3172344a13cac4f7ee
      fencing/upstream/self-node-remediation-deamonset.yaml.tmpl a82494959ab0cd212c466d67064df7cb23da1c3381da0974256ab26e106778c4" ;;
    certmanager) echo "cert-manager/upstream/cert-manager-v1.21.3.yaml c04a51295adda2b1a775146751f973e787190778c7f35180861d9678876e5c74" ;;
    *) return 1 ;;
  esac
}

# _ha_dir <component> — its directory under kube/ha.
_ha_dir() { case "$1" in certmanager) echo cert-manager ;; *) echo "$1" ;; esac; }

# ha_pins_ok <component> — every pinned file has its sha256 (fail closed:
# _K_ERR names the first that doesn't, nothing is installed).
ha_pins_ok() {
  local p f want got
  p="$(_ha_pins "$1")" || { _K_ERR="no pins for $1"; return 1; }
  set -- $p
  while [ $# -ge 2 ]; do
    f="$1" want="$2"; shift 2
    [ -f "$PORTCULLIS_HOME/$HA_DIR/$f" ] || { _K_ERR="$HA_DIR/$f is missing"; return 1; }
    got="$(_kube_sha "$PORTCULLIS_HOME/$HA_DIR/$f")"
    [ "$got" = "$want" ] || { _K_ERR="$HA_DIR/$f has sha256 $got, not the pinned $want"; return 1; }
  done
  _K_ERR=""
}

# ha_snr_image — the SNR image ha_render fencing uses: HA_SNR_IMAGE, or
# with HUB_DEV=1 a PORTCULLIS_DEV_SNR_IMAGE name@sha256 ref (development /
# e2e: the image built from kube/ha/fencing/snr-patch before it is
# published).
ha_snr_image() {
  if [ -n "${PORTCULLIS_DEV_SNR_IMAGE:-}" ]; then
    [ "${HUB_DEV:-}" = 1 ] || { echo "PORTCULLIS_DEV_SNR_IMAGE is for development only (HUB_DEV=1)" >&2; return 1; }
    [[ "$PORTCULLIS_DEV_SNR_IMAGE" =~ ^[a-z0-9.:/_-]+@sha256:[0-9a-f]{64}$ ]] || { echo "PORTCULLIS_DEV_SNR_IMAGE must be name@sha256:<64 hex>" >&2; return 1; }
    printf '%s\n' "$PORTCULLIS_DEV_SNR_IMAGE"; return 0
  fi
  printf '%s\n' "$HA_SNR_IMAGE"
}

# ha_render <component> [<API server sources> <iSCSI initiator sources>] —
# the component's manifests as `kubectl apply` gets them (YAML on stdout):
# kubectl kustomize of kube/ha/<c>/ (snapshotter: the controller only, its
# CRDs are upstream/crds.yaml; fencing: CRDs, managers, RBAC; its CRs are
# config.yaml), Longhorn first through `helm template` of the pinned chart
# with values.yaml and a generated sources file (the webhook's and the
# iSCSI initiators' addresses, space-separated IPv4s: both required — the
# chart's policies admit anyone without them). Local only (no cluster).
ha_render() {
  local c="$1" d="$PORTCULLIS_HOME/$HA_DIR" t rc=0
  case "$c" in
    snapshotter|certmanager) kubectl kustomize "$d/$(_ha_dir "$c")" ;;
    fencing)
      # The pinned SNR image, or the development one (a literal swap of the
      # one pinned ref: its Deployment, its agents' image, the pod policy).
      local img out
      img="$(ha_snr_image)" || return 1
      out="$(kubectl kustomize "$d/fencing")" || return 1
      printf '%s\n' "${out//"$HA_SNR_IMAGE"/"$img"}" ;;
    longhorn)
      [ -n "${2:-}" ] && [ -n "${3:-}" ] || { echo "ha_render longhorn: the webhook's and the iSCSI initiators' sources are required" >&2; return 1; }
      t="$(mktemp -d)"
      cp "$d/longhorn/kustomization.yaml" "$d/longhorn/rbac.yaml" "$t/"
      A="$2" I="$3" jq -n 'def cidrs: split(" ") | map(select(. != "") | . + "/32");
        {networkPolicies: {kubeAPIServerSourceCIDRs: (env.A | cidrs), v1DataEngineInitiatorSourceCIDRs: (env.I | cidrs)}}' > "$t/sources.json"
      { helm template longhorn "$d/longhorn/upstream/longhorn-1.13.0.tgz" -n "$KUBE_LONGHORN_NS" --no-hooks \
          -f "$d/longhorn/values.yaml" -f "$t/sources.json" > "$t/rendered.yaml" && kubectl kustomize "$t"; } || rc=1
      rm -rf "$t"; return "$rc" ;;
    *) echo "ha_render: unknown component $c" >&2; return 1 ;;
  esac
}

# kube_node_host_sources — the addresses a node's own host traffic to a pod
# comes from (Longhorn's iSCSI initiator runs in the host): every node's
# InternalIP and the first two addresses of its pod range (flannel's and
# cni0's, as kube_apiserver_sources). Empty and exit 1 when unreadable.
kube_node_host_sources() {
  local out
  out="$(kube_ctl get nodes -o json 2>/dev/null | jq -r '.items[]
      | ([.status.addresses[]? | select(.type == "InternalIP") | .address | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))][]),
        (.spec.podCIDR // empty | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$")) | split("/")[0] | split(".") | map(tonumber) as $o
         | ($o | map(tostring) | join(".")), ($o[0:3] + [$o[3] + 1] | map(tostring) | join(".")))' 2>/dev/null)" || return 1
  [ -n "$out" ] || return 1
  printf '%s\n' "$out" | awk 'NF && !seen[$0]++' | tr '\n' ' ' | sed 's/ $//'
}

# ha_ns_policies <namespace> <API endpoints (ip:port words)> [<webhook
# sources (ip words)>] — a namespace's CLI-owned NetworkPolicies (a JSON
# List): default-deny both ways, kube-dns, every pod's egress to the API
# endpoints, and its operator's flows:
#   longhorn-system  pods reach each other (the engines' replicas, the CSI
#                    plugin → the manager); who may reach them is Longhorn's
#                    own documented policies (the chart's, sources included);
#   portcullis-fencing  SNR's agents ask each other on TCP 30001 (peer health);
#   cert-manager     its webhook :10250 only from the API server's addresses.
ha_ns_policies() {
  NS="$1" API="$2" SRC="${3:-}" jq -n '
    def words: split(" ") | map(select(. != ""));
    def meta($n): {name: $n, namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis"}};
    def np($n; $spec): {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: meta($n), spec: $spec};
    def agents: {matchLabels: {"app.kubernetes.io/name": "self-node-remediation", "app.kubernetes.io/component": "agent"}};
    {apiVersion: "v1", kind: "List", items: ([
      np("default-deny"; {podSelector: {}, policyTypes: ["Ingress", "Egress"]}),
      np("kube-dns"; {podSelector: {}, policyTypes: ["Egress"],
         egress: [{to: [{namespaceSelector: {matchLabels: {"kubernetes.io/metadata.name": "kube-system"}}, podSelector: {matchLabels: {"k8s-app": "kube-dns"}}}],
                   ports: [{protocol: "UDP", port: 53}, {protocol: "TCP", port: 53}]}]}),
      np("kube-api"; {podSelector: {}, policyTypes: ["Egress"],
         egress: [env.API | words | .[] | split(":") as $p | {to: [{ipBlock: {cidr: ($p[0] + "/32")}}], ports: [{protocol: "TCP", port: ($p[1] | tonumber)}]}]})]
      + (if env.NS == "longhorn-system" then [np("longhorn-internal"; {podSelector: {}, policyTypes: ["Egress"], egress: [{to: [{podSelector: {}}]}]})]
         elif env.NS == "portcullis-fencing" then [np("snr-peers"; {podSelector: agents, policyTypes: ["Ingress", "Egress"],
           ingress: [{from: [{podSelector: agents}], ports: [{protocol: "TCP", port: 30001}]}],
           egress: [{to: [{podSelector: agents}], ports: [{protocol: "TCP", port: 30001}]}]})]
         elif env.NS == "cert-manager" then [np("webhook"; {podSelector: {matchLabels: {"app.kubernetes.io/component": "webhook"}}, policyTypes: ["Ingress"],
           ingress: [{from: [env.SRC | words | .[] | {ipBlock: {cidr: (. + "/32")}}], ports: [{protocol: "TCP", port: 10250}]}]})]
         else [] end))}'
}

# ha_snapshotter_policy <API endpoints> — the snapshot-controller's own
# policy in kube-system (only its pods: kube-system itself stays k3s'): no
# ingress, egress to the API endpoints and kube-dns only.
ha_snapshotter_policy() {
  API="$1" jq -n '
    def words: split(" ") | map(select(. != ""));
    {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy",
     metadata: {name: "snapshot-controller", namespace: "kube-system", labels: {"app.kubernetes.io/managed-by": "portcullis"}},
     spec: {podSelector: {matchLabels: {"app.kubernetes.io/name": "snapshot-controller"}}, policyTypes: ["Ingress", "Egress"],
       egress: ([env.API | words | .[] | split(":") as $p | {to: [{ipBlock: {cidr: ($p[0] + "/32")}}], ports: [{protocol: "TCP", port: ($p[1] | tonumber)}]}]
         + [{to: [{podSelector: {matchLabels: {"k8s-app": "kube-dns"}}}], ports: [{protocol: "UDP", port: 53}, {protocol: "TCP", port: 53}]}])}}'
}

# _ha_apply — server-side apply of stdin (our field manager).
_ha_apply() { kube_ctl apply --server-side --force-conflicts --field-manager="$KUBE_FIELD_MANAGER" -f - >/dev/null; }

# _ha_namespace <role> <namespace> <API endpoints> [<sources>] — the
# namespace with its PSA labels, then its policies (before anything runs).
_ha_namespace() {
  local psa
  psa="$(kube_psa "$1")" || exit 1
  # shellcheck disable=SC2086  # three single-word levels
  kube_namespace_apply "$2" $psa || fail "could not create the namespace $2 (nothing installed)"
  ha_ns_policies "$2" "$3" "${4:-}" | _ha_apply || fail "could not apply $2's NetworkPolicies (nothing installed)"
}

# The host probe (one pod per node, nodeName: a small node's taint doesn't
# keep it off; hostPID and the host's root read-only, as nobody, in its own
# PSA privileged namespace portcullis-ha-probe with no network, pinned by
# portcullis-ha-probe-pods): one line per check, "<id> ok|fail
# <detail>", the nodeagent's checks' texts (Hub internal/nodeagent/host).
# shellcheck disable=SC2016  # the probe's own shell
HA_PROBE_SH='
has() { for f in "$@"; do [ -e "/host$f" ] && return 0; done; return 1; }
running() { for c in /proc/[0-9]*/comm; do [ "$(cat "$c" 2>/dev/null)" = "$1" ] && return 0; done; return 1; }
for c in $CHECKS; do case "$c" in
  iscsid) if ! has /usr/sbin/iscsiadm /sbin/iscsiadm; then echo "iscsid fail open-iscsi is not installed (apt install open-iscsi): Longhorn needs it"
    elif ! running iscsid; then echo "iscsid fail open-iscsi is installed but iscsid is not running (systemctl enable --now iscsid)"; else echo "iscsid ok"; fi ;;
  iscsi_tcp) if [ -d /host/sys/module/iscsi_tcp ]; then echo "iscsi_tcp ok"; else echo "iscsi_tcp fail the iscsi_tcp module is not loaded (modprobe iscsi_tcp, and list it in /etc/modules-load.d/)"; fi ;;
  nfs_common) if has /usr/sbin/mount.nfs /sbin/mount.nfs; then echo "nfs_common ok"; else echo "nfs_common fail nfs-common is not installed (apt install nfs-common)"; fi ;;
  multipath_blacklist)
    if ! has /usr/sbin/multipathd /sbin/multipathd && ! running multipathd; then echo "multipath_blacklist ok"
    elif cat /host/etc/multipath.conf /host/etc/multipath/conf.d/*.conf 2>/dev/null | sed "s/#.*//" | awk '"'"'
        /^[[:space:]]*blacklist[[:space:]]*\{/ { b = 1; next } b && /\}/ { b = 0 } b { gsub(/[[:space:]]+/, " "); sub(/^ /, ""); sub(/ $/, ""); if ($0 == "devnode \"^sd[a-z0-9]+\"") f = 1 } END { exit !f }'"'"'; then echo "multipath_blacklist ok"
    else echo "multipath_blacklist fail multipathd has no blacklist for Longhorn devices: add blacklist { devnode \"^sd[a-z0-9]+\" } to /etc/multipath.conf and restart multipathd"; fi ;;
  longhorn_path) p=/host/var/lib/longhorn; while [ ! -e "$p" ] && [ "$p" != /host ]; do p="${p%/*}"; [ -n "$p" ] || p=/host; done
    t="$(stat -f -c %T "$p" 2>/dev/null)"
    case "$t" in "") echo "longhorn_path fail the file system of /var/lib/longhorn is unknown" ;;
      zfs) echo "longhorn_path fail /var/lib/longhorn is on a ZFS dataset: use a zvol or a separate disk" ;; *) echo "longhorn_path ok" ;; esac ;;
  watchdog) if [ -c /host/dev/watchdog ]; then echo "watchdog ok"; else echo "watchdog fail no watchdog device (/dev/watchdog; modprobe softdog provides it)"; fi ;;
esac; done'

# _ha_probe_setup — the probes' namespace (PSA from namespaces.json
# haprobe), its default-deny (the probe needs no network), the params of
# portcullis-ha-probe-pods (the helper image and the exact script, from
# files: kubectl --from-file) and that policy with its binding. Applied
# before every probe run (idempotent).
_ha_probe_setup() {
  local psa t
  psa="$(kube_psa haprobe)" || exit 1
  # shellcheck disable=SC2086  # three single-word levels
  kube_namespace_apply "$KUBE_HA_PROBE_NS" $psa || fail "could not create the namespace $KUBE_HA_PROBE_NS (nothing installed)"
  ha_ns_policies "$KUBE_HA_PROBE_NS" "" | jq '.items |= map(select(.metadata.name == "default-deny"))' | _ha_apply \
    || fail "could not apply $KUBE_HA_PROBE_NS's default-deny (nothing installed)"
  t="$(mktemp -d)"
  printf '%s' "$PORTCULLIS_HELPER_IMAGE" > "$t/image"
  printf '%s' "$HA_PROBE_SH" > "$t/script"
  if ! kube_ctl -n "$KUBE_HA_PROBE_NS" create configmap ha-probe-params --from-file="$t" --dry-run=client -o json | _ha_apply \
     || ! _kube_apply_files "$PORTCULLIS_HOME/$KUBE_HA_PROBE_POLICY"; then
    rm -rf "$t"; fail "could not apply the host probes' admission policy ($KUBE_HA_PROBE_POLICY; nothing installed)"
  fi
  rm -rf "$t"
  _ha_policy_in_force "$KUBE_HA_PROBE_NS" portcullis-ha-probe-pods || fail "the host probes' admission policy isn't in force (nothing installed)"
}

# _ha_policy_in_force <namespace> <policy> — a pod no shape admits is
# refused there BY that policy (server dry-run, ≤ 30 s): the policy and its
# binding are in force before anything runs (review M1).
_ha_policy_in_force() {
  local i out
  for ((i = 0; i < 15; i++)); do
    out="$(NS="$1" IMG="$PORTCULLIS_HELPER_IMAGE" jq -n '{apiVersion: "v1", kind: "Pod", metadata: {name: "portcullis-policy-check", namespace: env.NS},
        spec: {priorityClassName: "portcullis-core", containers: [{name: "x", image: env.IMG, command: ["true"]}]}}' | kube_ctl create --dry-run=server -f - 2>&1)" || true
    case "$out" in *"$2"*) return 0 ;; esac
    sleep 2
  done
  return 1
}

# _ha_probe_pod_json <name> <namespace> <node> <checks> — one host probe
# pod (the shape portcullis-ha-probe-pods admits; the admission vectors'
# base, tests/ha_admission_vectors.py).
_ha_probe_pod_json() {
  N="$1" NS="$2" NODE="$3" IMG="$PORTCULLIS_HELPER_IMAGE" C="$4" S="$HA_PROBE_SH" jq -n '
      {apiVersion: "v1", kind: "Pod", metadata: {name: env.N, namespace: env.NS, labels: {"portcullis.io/component": "ha-check"}},
       spec: {nodeName: env.NODE, restartPolicy: "Never", hostPID: true, priorityClassName: "portcullis-core",
         automountServiceAccountToken: false, enableServiceLinks: false, terminationGracePeriodSeconds: 1,
         securityContext: {runAsNonRoot: true, runAsUser: 65534, runAsGroup: 65534, seccompProfile: {type: "RuntimeDefault"}},
         tolerations: [{operator: "Exists"}],
         volumes: [{name: "host", hostPath: {path: "/", type: "Directory"}}],
         containers: [{name: "check", image: env.IMG, command: ["sh", "-c", env.S], env: [{name: "CHECKS", value: env.C}],
           volumeMounts: [{name: "host", mountPath: "/host", readOnly: true}],
           resources: {limits: {memory: "32Mi"}, requests: {memory: "32Mi"}},
           securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}}]}}'
}

# _ha_node_probes <namespace> <checks (words)> <node>… — runs the probe on
# each node (in parallel) and prints "<node> <id> ok|fail <detail>" lines;
# a probe that doesn't complete is "<node> probe fail <why>" (fail closed).
_ha_node_probes() {
  local ns="$1" checks="$2" n i=0 name names="" j phase k tmpd
  shift 2
  tmpd="$(mktemp -d)"
  for n in "$@"; do
    i=$((i + 1)); name="ha-check-$i-$(openssl rand -hex 3)"; names="$names $name=$n"
    _ha_probe_pod_json "$name" "$ns" "$n" "$checks" > "$tmpd/$name.json"
    # A policy binding just applied may take a moment to see its params:
    # retried, then a refusal is a failed check (fail closed).
    for ((j = 0; j < 10; j++)); do kube_ctl create -f "$tmpd/$name.json" >/dev/null 2> "$tmpd/err" && break; sleep 2; done
    [ "$j" -lt 10 ] || { echo "$n probe fail the check pod was refused: $(tr '\n' ' ' < "$tmpd/err" | cut -c1-300)"; names="${names% *}"; }
  done
  for k in $names; do
    name="${k%%=*}" n="${k#*=}" phase=""
    for ((j = 0; j < "${KUBE_POD_WAIT:-180}"; j += 2)); do
      phase="$(kube_ctl -n "$ns" get pod "$name" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
      case "$phase" in Succeeded|Failed) break ;; esac
      sleep 2
    done
    if [ "$phase" = Succeeded ]; then
      kube_ctl -n "$ns" logs "pod/$name" 2>/dev/null | awk -v n="$n" '$2 == "ok" || $2 == "fail" { print n " " $0 }'
    else
      echo "$n probe fail the check pod didn't complete (${phase:-no phase}) within ${KUBE_POD_WAIT:-180} s"
    fi
    kube_ctl -n "$ns" delete pod "$name" --wait=false >/dev/null 2>&1 || true
  done
  rm -rf "$tmpd"
}

# _ha_checks_refuse <what> <probe lines> — every failing check as
# "node <n>: <detail>", then refuses (fail closed: no line for a node is a
# failure too, the caller counts).
_ha_checks_refuse() {
  local bad
  bad="$(printf '%s\n' "$2" | awk '$3 == "fail" { n = $1; $1 = $2 = $3 = ""; sub(/^ +/, ""); print "  node " n ": " $0 }')"
  [ -z "$bad" ] && return 0
  printf '%s\n' "$bad" >&2
  fail "$1 (nothing installed)"
}

# _ha_nodes_json — the cluster's nodes, or fail (never a guess).
_ha_nodes_json() {
  local j
  j="$(kube_ctl get nodes -o json 2>/dev/null)" && printf '%s' "$j" | jq -e '.items | type == "array"' >/dev/null 2>&1 \
    || fail "can't read the cluster's nodes (nothing installed)"
  printf '%s\n' "$j"
}

# _ha_wait <seconds> <what> <cmd…> — retries cmd every 3 s; fails naming what.
_ha_wait() {
  local s="$1" what="$2" i
  shift 2
  for ((i = 0; i < s; i += 3)); do "$@" >/dev/null 2>&1 && return 0; sleep 3; done
  fail "$what didn't come up within $s s"
}

# _ha_ds_ready <ns> <name> — a DaemonSet rolled out on every node it wants.
_ha_ds_ready() {
  kube_ctl -n "$1" get ds "$2" -o json 2>/dev/null | jq -e '(.status.desiredNumberScheduled // 0) > 0
    and .status.observedGeneration == .metadata.generation and .status.numberReady == .status.desiredNumberScheduled
    and (.status.updatedNumberScheduled // 0) == .status.desiredNumberScheduled' >/dev/null
}

# _ha_deploy_ready <ns> <name>… — Deployments available at their generation.
_ha_deploy_ready() {
  local ns="$1" d
  shift
  for d in "$@"; do
    kube_ctl -n "$ns" get deploy "$d" -o json 2>/dev/null | jq -e '.status.observedGeneration == .metadata.generation
      and (.status.availableReplicas // 0) >= (.spec.replicas // 1) and (.status.updatedReplicas // 0) >= (.spec.replicas // 1)' >/dev/null || return 1
  done
}

# _ha_crds_established <file> — every CRD in the rendered file Established.
_ha_crds_established() {
  local crds
  crds="$(awk '/^kind: CustomResourceDefinition$/ { c = 1 } c && /^  name: / { print "crd/" $2; c = 0 }' "$1")"
  [ -z "$crds" ] && return 0
  # shellcheck disable=SC2086  # crd/<name> words
  kube_ctl wait --for=condition=Established $crds --timeout=120s >/dev/null
}

# ha_install_snapshotter — the VolumeSnapshot CRDs and the
# snapshot-controller in kube-system (its own policy first).
ha_install_snapshotter() {
  local t
  ha_pins_ok snapshotter || fail "the external-snapshotter pins don't hold: $_K_ERR (nothing installed)"
  [ -n "${PORTCULLIS_KUBE_API_ENDPOINTS:-}" ] || fail "no kube API endpoint (PORTCULLIS_KUBE_API_ENDPOINTS): the snapshot-controller's policy would reach nothing (nothing installed)"
  ha_snapshotter_policy "$PORTCULLIS_KUBE_API_ENDPOINTS" | _ha_apply || fail "could not apply the snapshot-controller's NetworkPolicy (nothing installed)"
  info "HA: external-snapshotter v8.7.0 (VolumeSnapshot CRDs, snapshot-controller)..."
  _kube_apply_files "$PORTCULLIS_HOME/$HA_DIR/snapshotter/upstream/crds.yaml" || fail "could not apply the VolumeSnapshot CRDs"
  _ha_crds_established "$PORTCULLIS_HOME/$HA_DIR/snapshotter/upstream/crds.yaml" || fail "the VolumeSnapshot CRDs aren't established"
  t="$(mktemp)"
  ha_render snapshotter > "$t" || { rm -f "$t"; fail "could not render the snapshot-controller (kubectl kustomize)"; }
  _ha_apply < "$t" || { rm -f "$t"; fail "could not apply the snapshot-controller"; }
  rm -f "$t"
  _ha_wait 300 "the snapshot-controller (kube-system)" _ha_deploy_ready kube-system snapshot-controller
  _kube_applied_set ha.snapshotter "$(_kube_sha "$PORTCULLIS_HOME/$HA_DIR/snapshotter"/*.yaml "$PORTCULLIS_HOME/$HA_DIR/snapshotter/upstream"/*)"
}

# ha_install_longhorn — Longhorn v1.13.0 in longhorn-system and the
# StorageClass portcullis-core-replicated. Refused (nothing installed)
# without a storage node, without the nodes' addresses, or while a check
# fails on a node Longhorn runs on (the main site's non-small nodes: they
# attach the volumes) — open-iscsi with iscsid running, iscsi_tcp,
# nfs-common, multipathd's blacklist — or a storage node's
# /var/lib/longhorn is on a ZFS dataset (spike S2).
ha_install_longhorn() {
  local nodes lh storage api init lines n t
  ha_pins_ok longhorn || fail "the Longhorn pins don't hold: $_K_ERR (nothing installed)"
  nodes="$(_ha_nodes_json)" || exit 1
  lh="$(printf '%s' "$nodes" | S="$KUBE_PRIMARY_SITE" jq -r '.items[] | select(.metadata.labels["portcullis.io/site"] == env.S and .metadata.labels["portcullis.io/class"] != "small") | .metadata.name')"
  storage="$(printf '%s' "$nodes" | S="$KUBE_PRIMARY_SITE" jq -r '.items[] | select(.metadata.labels["portcullis.io/site"] == env.S and .metadata.labels["node.longhorn.io/create-default-disk"] == "true") | .metadata.name')"
  [ -n "$storage" ] || fail "no storage node at $KUBE_PRIMARY_SITE (node.longhorn.io/create-default-disk=true): Longhorn would have no disk (nothing installed)"
  api="$(kube_apiserver_sources)"
  [ -n "$api" ] || fail "can't read the API server's addresses: Longhorn's webhook would admit nobody (nothing installed)"
  init="$(kube_node_host_sources)" || fail "can't read the nodes' addresses: Longhorn's iSCSI targets would be open to every pod (nothing installed)"
  _ha_namespace longhorn "$KUBE_LONGHORN_NS" "${PORTCULLIS_KUBE_API_ENDPOINTS:-}"
  info "HA: checking the nodes Longhorn runs on ($(printf '%s' "$lh" | tr '\n' ' ' | sed 's/ $//'))..."
  _ha_probe_setup
  # shellcheck disable=SC2086  # node names
  lines="$(_ha_node_probes "$KUBE_HA_PROBE_NS" "iscsid iscsi_tcp nfs_common multipath_blacklist" $lh)"
  # shellcheck disable=SC2086
  lines="$lines
$(_ha_node_probes "$KUBE_HA_PROBE_NS" "longhorn_path" $storage)"
  for n in $lh; do
    printf '%s\n' "$lines" | awk -v n="$n" '$1 == n && $2 == "iscsid" { f = 1 } END { exit !f }' || lines="$lines
$n probe fail no answer from the node's check"
  done
  _ha_checks_refuse "Longhorn needs these on every node it runs on: fix them and run it again" "$lines"
  _ha_longhorn_webhooks || fail "could not make Longhorn's webhook configurations (nothing installed)"
  info "HA: Longhorn v1.13.0 (longhorn-system)..."
  t="$(mktemp)"
  ha_render longhorn "$api" "$init" > "$t" || { rm -f "$t"; fail "could not render Longhorn (helm template + kubectl kustomize)"; }
  _ha_apply < "$t" || { rm -f "$t"; fail "could not apply Longhorn (see above)"; }
  rm -f "$t"
  _ha_wait 600 "Longhorn's manager (DaemonSet longhorn-manager)" _ha_ds_ready "$KUBE_LONGHORN_NS" longhorn-manager
  _ha_wait 600 "Longhorn's CSI driver" _ha_longhorn_csi_ready
  _kube_apply_files "$PORTCULLIS_HOME/$KUBE_REPLICATED_SC" || fail "could not apply the StorageClass portcullis-core-replicated"
  _kube_applied_set ha.longhorn "$(_kube_sha "$PORTCULLIS_HOME/$HA_DIR/longhorn"/*.yaml "$PORTCULLIS_HOME/$HA_DIR/longhorn/upstream"/* "$PORTCULLIS_HOME/$KUBE_REPLICATED_SC")"
}

# _ha_longhorn_webhooks — Longhorn's two webhook configurations made by the
# CLI before Longhorn runs (fix round 1, security review: Longhorn's
# identity may not create webhook configurations — a create can't be
# limited by name, and an admission policy can't judge them, R-ADM). Empty
# (no webhook: nothing is judged until Longhorn fills them in), carrying
# the labels and annotations of wrangler's apply that Longhorn uses
# (webhook/server/server.go: owner = the Secret longhorn-webhook-ca, set
# id empty; the hash is wrangler's objectSetHash), so its apply finds and
# patches them by name instead of creating. Kept as they are when present.
_ha_longhorn_webhooks() {
  local h k name
  h="$(printf '%s' "/v1, Kind=Secretlonghorn-webhook-ca$KUBE_LONGHORN_NS" | { sha1sum 2>/dev/null || shasum -a 1; } | awk '{print $1}')"
  for k in ValidatingWebhookConfiguration:longhorn-webhook-validator MutatingWebhookConfiguration:longhorn-webhook-mutator; do
    name="${k#*:}"
    kube_ctl get "${k%%:*}" "$name" -o name >/dev/null 2>&1 && continue
    K="${k%%:*}" N="$name" H="$h" NS="$KUBE_LONGHORN_NS" jq -n '
      {apiVersion: "admissionregistration.k8s.io/v1", kind: env.K,
       metadata: {name: env.N, labels: {"objectset.rio.cattle.io/hash": env.H, "app.kubernetes.io/managed-by": "portcullis"},
         annotations: {"objectset.rio.cattle.io/id": "", "objectset.rio.cattle.io/owner-gvk": "/v1, Kind=Secret",
           "objectset.rio.cattle.io/owner-name": "longhorn-webhook-ca", "objectset.rio.cattle.io/owner-namespace": env.NS}},
       webhooks: []}' | kube_ctl create -f - >/dev/null || return 1
  done
}

# _ha_longhorn_csi_ready — the driver deployer's CSI: the CSIDriver, the
# plugin DaemonSet and the four controllers.
_ha_longhorn_csi_ready() {
  kube_ctl get csidriver driver.longhorn.io -o name >/dev/null 2>&1 \
    && _ha_ds_ready "$KUBE_LONGHORN_NS" longhorn-csi-plugin \
    && _ha_deploy_ready "$KUBE_LONGHORN_NS" csi-attacher csi-provisioner csi-resizer csi-snapshotter
}

# ha_install_certmanager — cert-manager v1.21.3 (Amendment 2: only the
# barman-cloud plugin's certificates, in cnpg-system: Task 26 installs the
# plugin). Needs cnpg-system (its Role is there).
ha_install_certmanager() {
  local src t
  ha_pins_ok certmanager || fail "the cert-manager pins don't hold: $_K_ERR (nothing installed)"
  kube_ctl get namespace "$KUBE_CNPG_NS" -o name >/dev/null 2>&1 || fail "no namespace $KUBE_CNPG_NS: cert-manager serves only the CloudNativePG plugin there (nothing installed)"
  src="$(kube_apiserver_sources)"
  [ -n "$src" ] || fail "can't read the API server's addresses: cert-manager's webhook would admit nobody (nothing installed)"
  _ha_namespace certmanager "$KUBE_CERTMANAGER_NS" "${PORTCULLIS_KUBE_API_ENDPOINTS:-}" "$src"
  info "HA: cert-manager v1.21.3 (cert-manager; certificates in $KUBE_CNPG_NS only)..."
  t="$(mktemp)"
  ha_render certmanager > "$t" || { rm -f "$t"; fail "could not render cert-manager (kubectl kustomize)"; }
  _ha_apply < "$t" || { rm -f "$t"; fail "could not apply cert-manager (see above)"; }
  rm -f "$t"
  _ha_wait 300 "cert-manager" _ha_deploy_ready "$KUBE_CERTMANAGER_NS" cert-manager cert-manager-cainjector cert-manager-webhook
  _ha_wait 180 "cert-manager's webhook CA" _ha_certmanager_webhook_ready
  _kube_applied_set ha.certmanager "$(_kube_sha "$PORTCULLIS_HOME/$HA_DIR/cert-manager"/*.yaml "$PORTCULLIS_HOME/$HA_DIR/cert-manager/upstream"/*)"
}

# _ha_certmanager_webhook_ready — the cainjector put the webhook's CA into
# its validating configuration (until then every cert-manager object is
# refused).
_ha_certmanager_webhook_ready() {
  kube_ctl get validatingwebhookconfiguration cert-manager-webhook -o json 2>/dev/null | jq -e '[.webhooks[].clientConfig.caBundle // ""] | all(length > 0)' >/dev/null
}

# _ha_fencing_cert — the managers' webhook serving certificate (Secret
# fencing-webhook-cert): no webhook configuration is registered, the
# servers only have to start, so a throwaway self-signed one, made once
# (openssl into a 0700 dir, kubectl --from-file paths: never argv).
_ha_fencing_cert() {
  local t f
  kube_ctl -n "$KUBE_FENCING_NS" get secret fencing-webhook-cert -o name >/dev/null 2>&1 && return 0
  t="$(mktemp -d)"; chmod 700 "$t"; f="$t/s.json"
  if ! (umask 077 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=fencing-webhook" \
          -keyout "$t/tls.key" -out "$t/tls.crt" >/dev/null 2>&1) \
     || ! kube_ctl -n "$KUBE_FENCING_NS" create secret tls fencing-webhook-cert --cert="$t/tls.crt" --key="$t/tls.key" --dry-run=client -o json > "$f" \
     || ! _ha_apply < "$f"; then
    rm -rf "$t"; fail "could not make the fencing managers' webhook certificate (nothing installed)"
  fi
  rm -rf "$t"
}

# ha_install_fencing — our SNR (v0.13.0 + snr-patch) in portcullis-fencing
# (spike S3, OLM-free; fix round 1: no NHC, nodeadm creates the
# remediations) with config.yaml (watchdog /dev/watchdog, safe time 150 s)
# and the pod policy portcullis-fencing-pods. Refused (nothing installed) while
# any node has no watchdog: a node that can't be fenced is never declared
# dead, and no stateful failover would be safe there. Ends with
# ha_fencing_ready (every node's agent ready, or it fails).
ha_install_fencing() {
  local nodes all lines n t img
  ha_pins_ok fencing || fail "the fencing pins don't hold: $_K_ERR (nothing installed)"
  img="$(ha_snr_image)" || fail "the SNR image: see above (nothing installed)"
  case "$img" in *"@$HA_SNR_PLACEHOLDER") fail "the SNR image ($HA_SNR_IMAGE) isn't published yet (a placeholder digest until .github/workflows/snr.yml's first main build): nothing installed" ;; esac
  nodes="$(_ha_nodes_json)" || exit 1
  all="$(printf '%s' "$nodes" | jq -r '.items[].metadata.name')"
  [ -n "$all" ] || fail "the cluster has no node (nothing installed)"
  _ha_namespace fencing "$KUBE_FENCING_NS" "${PORTCULLIS_KUBE_API_ENDPOINTS:-}"
  info "HA: checking every node's watchdog..."
  _ha_probe_setup
  # shellcheck disable=SC2086  # node names
  lines="$(_ha_node_probes "$KUBE_HA_PROBE_NS" watchdog $all)"
  for n in $all; do
    printf '%s\n' "$lines" | awk -v n="$n" '$1 == n && $2 == "watchdog" && $3 == "ok" { f = 1 } END { exit !f }' && continue
    warn "node $n has no watchdog: fencing can't be confirmed$(printf '%s\n' "$lines" | awk -v n="$n" '$1 == n && $3 == "fail" { $1 = $2 = $3 = ""; sub(/^ +/, ""); print " (" $0 ")"; exit }')"
    t=refused
  done
  [ "${t:-}" != refused ] || fail "fencing needs a watchdog on every node: without it a node is never declared dead, so nothing stateful fails over (nothing installed)"
  _ha_fencing_cert
  # The pod policy first, in force before anything runs there (review M1):
  # the same image swap as ha_render's.
  t="$(mktemp)"
  { local pol; pol="$(cat "$PORTCULLIS_HOME/$HA_DIR/fencing/admission.yaml")"; printf '%s\n' "${pol//"$HA_SNR_IMAGE"/"$img"}"; } > "$t"
  _ha_apply < "$t" || { rm -f "$t"; fail "could not apply the fencing pod policy (nothing installed)"; }
  _ha_policy_in_force "$KUBE_FENCING_NS" portcullis-fencing-pods || { rm -f "$t"; fail "the fencing pod policy isn't in force (nothing installed)"; }
  info "HA: Self Node Remediation v0.13.0 + Portcullis' patch (portcullis-fencing)..."
  ha_render fencing > "$t" || { rm -f "$t"; fail "could not render fencing (kubectl kustomize)"; }
  _ha_apply < "$t" || { rm -f "$t"; fail "could not apply fencing (see above)"; }
  _ha_crds_established "$t" || { rm -f "$t"; fail "the fencing CRDs aren't established"; }
  rm -f "$t"
  _ha_wait 300 "SNR's manager" _ha_deploy_ready "$KUBE_FENCING_NS" self-node-remediation-controller-manager
  _kube_apply_files "$PORTCULLIS_HOME/$HA_DIR/fencing/config.yaml" || fail "could not apply the fencing configuration (kube/ha/fencing/config.yaml)"
  _ha_wait 300 "SNR's agents (DaemonSet self-node-remediation-ds)" _ha_snr_ds_current
  ha_fencing_ready >/dev/null || { ha_fencing_ready >&2 || true; fail "fencing isn't ready on every node (above): no stateful failover until it is"; }
  _kube_applied_set ha.fencing "$(_kube_sha "$PORTCULLIS_HOME/$HA_DIR/fencing"/*.yaml "$PORTCULLIS_HOME/$HA_DIR/fencing"/*.tmpl "$PORTCULLIS_HOME/$HA_DIR/fencing/upstream"/*)"
}

# _ha_snr_ds_current — the agents' DaemonSet carries config.yaml's
# tolerations (the manager re-rendered it) and is rolled out.
_ha_snr_ds_current() {
  kube_ctl -n "$KUBE_FENCING_NS" get ds self-node-remediation-ds -o json 2>/dev/null \
    | jq -e 'any(.spec.template.spec.tolerations[]?; .key == "portcullis.io/small")' >/dev/null \
    && _ha_ds_ready "$KUBE_FENCING_NS" self-node-remediation-ds
}

# ha_fencing_ready — per node "<node> ready|not ready (<why>)" and exit 0
# only when every node is ready: the SNR configuration is ours (the
# watchdog, the 150 s safe time), SNR's manager is available, and the
# node runs a Ready, current agent of the DaemonSet self-node-remediation-ds
# in our SNR image (review nit 7: an old image's agent isn't ready;
# nodeadm's snapshot counts the
# same pod for the Hub's ha_fencing_unavailable). Anything unreadable is
# not ready (fail closed: no stateful failover).
ha_fencing_ready() {
  local nodes pods cfg mgr
  nodes="$(kube_ctl get nodes -o json 2>/dev/null)" || { warn "can't read the nodes: fencing unconfirmed"; return 1; }
  pods="$(kube_ctl -n "$KUBE_FENCING_NS" get pods -l app.kubernetes.io/name=self-node-remediation,app.kubernetes.io/component=agent -o json 2>/dev/null)" \
    || { warn "can't read SNR's agents: fencing unconfirmed"; return 1; }
  cfg="$(kube_ctl -n "$KUBE_FENCING_NS" get selfnoderemediationconfigs.self-node-remediation.medik8s.io self-node-remediation-config -o json 2>/dev/null || echo '{}')"
  # The manager too: without it no out-of-service taint.
  mgr=ok
  _ha_deploy_ready "$KUBE_FENCING_NS" self-node-remediation-controller-manager || mgr=down
  M="$mgr" IMG="$(ha_snr_image)" jq -rn --argjson n "$nodes" --argjson p "$pods" --argjson c "$cfg" '
    ($c.spec // {}) as $s
    | (if $s.watchdogFilePath != "/dev/watchdog" or $s.safeTimeToAssumeNodeRebootedSeconds != 150 then "SNR configuration missing or not ours"
       elif env.M != "ok" then "SNR'"'"'s manager isn'"'"'t available" else "" end) as $bad
    | [$p.items[]? | select(.metadata.deletionTimestamp == null and (.metadata.name | startswith("self-node-remediation-ds-"))
        and any(.metadata.ownerReferences[]?; .kind == "DaemonSet" and .name == "self-node-remediation-ds")
        and ([.spec.containers[].image] == [env.IMG])
        and any(.status.conditions[]?; .type == "Ready" and .status == "True")) | .spec.nodeName] as $ok
    | [$n.items[] | .metadata.name as $m
        | if $bad != "" then "\($m)\tnot ready (\($bad))"
          elif ($ok | index($m)) then "\($m)\tready"
          else "\($m)\tnot ready (no Ready SNR agent)" end]
    | if length == 0 then "-\tnot ready (no node)" else .[] end' 2>/dev/null \
    | awk -F'\t' '{ print } $2 != "ready" { bad = 1 } END { exit bad }'
}
