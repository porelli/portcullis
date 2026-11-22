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
#   - LLDAP's key seed: secrets/lldap/key-seed (users.sh, made by init as
#     on Docker), synced like every secrets/<dir> as Secret secrets-lldap
#     and mounted on every replica and the schema Job (LLDAP_KEY_SEED_FILE);
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
#      from lldap.dump (a Kubernetes backup), else the lldap_restore the
#      restore's pre-flight converted from the SQLite users.db of a Docker /
#      Podman backup (lldap_convert.sh, KUBE_LLDAP_CONVERTED; kept as it
#      is) — any failure drops the half-made copies and refuses, the live
#      pair untouched;
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
    # The converted LLDAP (the pre-flight's lldap_restore) stays as it is.
    [ "$db" = keycloak ] || [ "${KUBE_LLDAP_CONVERTED:-false}" != true ] || continue
    if ! _kube_pg_fresh_db "${db}_restore" "$db"; then
      _kube_pg_exec dropdb --if-exists --force keycloak_restore >/dev/null 2>&1 || true
      fail "could not make the database ${db}_restore: the live databases are untouched"
    fi
    [ "$db" = keycloak ] || [ -s "$dump" ] || fail "the backup has no LLDAP database to restore (lldap.dump, or lldap_data.tar.gz converted first)"
    if ! _kube_pg_exec pg_restore -d "${db}_restore" --no-owner --no-privileges --role="$db" --exit-on-error --single-transaction < "$dump"; then
      _kube_pg_exec dropdb --if-exists --force keycloak_restore >/dev/null 2>&1 || true
      _kube_pg_exec dropdb --if-exists --force lldap_restore >/dev/null 2>&1 || true
      fail "pg_restore of ${dump##*/} failed: the live databases are untouched (their dumps before this restore: $pre/postgres.dump, $pre/lldap.dump)"
    fi
  done
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
# _ha_policy_gen <file> [<image>] — a pod policy file's generation: the
# sha256 (16 hex) of its text after the SNR image swap, placeholder kept.
# _ha_policy_text <file> [<image>] prints that text with @POLICY_GENERATION@
# replaced: the policy then refuses exactly a pod annotated
# portcullis.io/policy-check=<generation>, which _ha_policy_in_force sends
# (round 3 nit: the policy in force is the one just applied).
_ha_policy_gen() {
  local t; t="$(cat "$1")" || return 1
  [ -z "${2:-}" ] || t="${t//"$HA_SNR_IMAGE"/"$2"}"
  printf '%s\n' "$t" | _kube_sha | cut -c1-16
}
_ha_policy_text() {
  local t g; t="$(cat "$1")" || return 1
  [ -z "${2:-}" ] || t="${t//"$HA_SNR_IMAGE"/"$2"}"
  g="$(_ha_policy_gen "$1" "${2:-}")" || return 1
  printf '%s\n' "${t//@POLICY_GENERATION@/"$g"}"
}

ha_render() {
  local c="$1" d="$PORTCULLIS_HOME/$HA_DIR" t rc=0
  case "$c" in
    snapshotter|certmanager) kubectl kustomize "$d/$(_ha_dir "$c")" ;;
    fencing)
      # The pinned SNR image, or the development one (a literal swap of the
      # one pinned ref: its Deployment, its agents' image, the pod policy).
      local img out g
      img="$(ha_snr_image)" || return 1
      g="$(_ha_policy_gen "$d/fencing/admission.yaml" "$img")" || return 1
      out="$(kubectl kustomize "$d/fencing")" || return 1
      out="${out//"$HA_SNR_IMAGE"/"$img"}"
      printf '%s\n' "${out//@POLICY_GENERATION@/"$g"}" ;;
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
     || ! _ha_policy_text "$PORTCULLIS_HOME/$KUBE_HA_PROBE_POLICY" > "$t/admission.yaml" || ! _kube_apply_files "$t/admission.yaml"; then
    rm -rf "$t"; fail "could not apply the host probes' admission policy ($KUBE_HA_PROBE_POLICY; nothing installed)"
  fi
  rm -rf "$t"
  _ha_policy_in_force "$KUBE_HA_PROBE_NS" portcullis-ha-probe-pods "$(_ha_policy_gen "$PORTCULLIS_HOME/$KUBE_HA_PROBE_POLICY")" || fail "the host probes' admission policy isn't in force (nothing installed)"
}

# _ha_policy_in_force <namespace> <policy> <generation> — a pod annotated
# portcullis.io/policy-check=<generation> is refused there BY that policy
# with the generation's own message (server dry-run, ≤ 30 s): the policy
# just applied and its binding are in force before anything runs (review
# M1; round 3 nit: an older copy of the policy doesn't pass).
_ha_policy_in_force() {
  local i out
  [ -n "${3:-}" ] || return 1
  for ((i = 0; i < 15; i++)); do
    out="$(NS="$1" G="$3" IMG="$PORTCULLIS_HELPER_IMAGE" jq -n '{apiVersion: "v1", kind: "Pod",
        metadata: {name: "portcullis-policy-check", namespace: env.NS, annotations: {"portcullis.io/policy-check": env.G}},
        spec: {priorityClassName: "portcullis-core", containers: [{name: "x", image: env.IMG, command: ["true"]}]}}' | kube_ctl create --dry-run=server -f - 2>&1)" || true
    case "$out" in *"$2 generation $3 is in force"*) return 0 ;; esac
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
  # The backup destination as Longhorn's backup target (Task 26; none set:
  # an empty target).
  ha_longhorn_backup_target
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

# ══ The backup destination in the cluster (plan Task 26, spec §9.3, R5) ══
#
# The destination itself is backup.sh's (PORTCULLIS_BACKUP_S3_URL +
# secrets/backup-destination.env). Here:
#   - kube_backup_destination_sync: the Secret backup-destination in
#     cnpg-system (barman-cloud's ObjectStore) and, with Longhorn, in
#     longhorn-system (its backup target) — AWS_ACCESS_KEY_ID,
#     AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION and AWS_ENDPOINTS (Longhorn's
#     custom endpoint), built from 0600 files (--from-file), never argv;
#     removed from both when the destination is unset;
#   - kube_backup_values: the chart's backup.* (the Hub's presence flag;
#     CloudNativePG's archive only with the plugin installed);
#   - ha_install_barman: the barman-cloud plugin (needs cert-manager: HA
#     only, as the other Task 24 installs: `ha enable` calls it);
#   - ha_longhorn_backup_target: Longhorn's BackupTarget default = <url>/
#     longhorn, and its pods' egress to the destination's port;
#   - kube_backup_status_record: the last core backup that reached the
#     destination, for the Hub's backup_stale (ConfigMap
#     portcullis-backup-status, the Hub's core Role reads it by name).

KUBE_BACKUP_STATUS_CM="portcullis-backup-status"
# Kubernetes keeps the Hub's instance backups on their own PVC hub-backups
# (contract §20.1; on Docker they are inside hub_data): the core backup
# carries it too (Task 19 review M9).
# shellcheck disable=SC2034  # read by kube.sh (_backup_create_kube, _backup_restore_kube)
KUBE_BACKUP_EXTRA_VOLUMES="hub_backups:$CT_UID_HUB:$CT_UID_HUB"

# _kube_restore_volume_t26 <dir> <key> <uid> <gid> — _kube_restore_volume,
# then (queued item) a Docker / Podman backup's instance backups
# (hub_data's backups/: there they live inside hub_data) moved into the
# hub-backups PVC Kubernetes keeps them on (the Hub mounts it over
# /data/backups, so in hub-state they'd be hidden). Never extracted on the
# host (security review: an archive's symlink or hard-link member could
# reach host files): hub_data's own restore already unpacked it inside a
# helper pod; a hub-state helper tars backups/ out and a hub-backups helper
# unpacks it (pod to pod, both as the Hub, read-only roots), then hub-state's
# copy is emptied (the directory stays: the Hub's mount point). A
# Kubernetes backup has its own hub_backups.tar.gz.
_kube_restore_volume_t26() {
  local dir="$1" key="$2" src dst rc=0 ns used cap
  _kube_restore_volume "$@" || return 1
  [ "$key" = hub_data ] && [ ! -f "$dir/hub_backups.tar.gz" ] && _kube_volume_exists hub_backups || return 0
  ns="$(kube_ns)"
  src="$(_kube_helper_pod "$(kube_pvc_name hub_data)" "$CT_UID_HUB:$CT_UID_HUB" rw "$PORTCULLIS_HELPER_IMAGE")" || return 1
  if ! kube_ctl -n "$ns" exec "$src" -- sh -c '[ -d /vol/backups ] && [ ! -L /vol/backups ] && [ -n "$(ls -A /vol/backups)" ]' >/dev/null 2>&1; then
    _kube_helper_done "$src"; return 0
  fi
  # Review NN4: they must fit hub-backups (1Gi by default) before it is
  # emptied; refused, they stay in hub_data (nothing lost).
  used="$(kube_ctl -n "$ns" exec "$src" -- du -sk /vol/backups 2>/dev/null | awk 'NR == 1 {print $1}')"
  cap="$(_kube_quantity_kib "$(kube_ctl -n "$ns" get pvc "$(kube_pvc_name hub_backups)" -o jsonpath='{.status.capacity.storage}' 2>/dev/null)")"
  if ! [[ "$used" =~ ^[0-9]+$ ]] || ! [[ "$cap" =~ ^[0-9]+$ ]] || [ $((used + used / 20 + 1024)) -gt "$cap" ]; then
    _kube_helper_done "$src"
    fail "the backup's instance backups (${used:-?} KiB) don't fit the hub-backups volume (${cap:-?} KiB): they stay in hub_data. Grow the PVC $(kube_pvc_name hub_backups) (kubectl -n $ns edit pvc, where its storage class allows it) and restore again"
  fi
  info "Moving the instance backups from hub_data into hub-backups..."
  _kube_empty_volume hub_backups "$CT_UID_HUB" "$CT_UID_HUB" || { _kube_helper_done "$src"; return 1; }
  dst="$(_kube_helper_pod "$(kube_pvc_name hub_backups)" "$CT_UID_HUB:$CT_UID_HUB" rw "$PORTCULLIS_HELPER_IMAGE")" || { _kube_helper_done "$src"; return 1; }
  # The PVC root keeps its mode (tar's "." member would set the source's).
  kube_ctl -n "$ns" exec "$src" -- tar -cf - -C /vol/backups . \
    | kube_ctl -n "$ns" exec -i "$dst" -- sh -c 'm="$(stat -c %a /vol)" && tar -xf - -C /vol && chmod "$m" /vol' || rc=1
  _kube_helper_done "$dst"
  # The directory stays (the Hub's hub-backups mount point), its content goes.
  [ "$rc" != 0 ] || kube_ctl -n "$ns" exec "$src" -- find /vol/backups -mindepth 1 -delete || rc=1
  _kube_helper_done "$src"
  return "$rc"
}

# _kube_quantity_kib <quantity> — a Kubernetes storage quantity (Ki Mi Gi Ti
# Pi, k M G T P, or bytes) in KiB, rounded down; nothing for anything else.
_kube_quantity_kib() {
  local q="$1" n u
  [[ "$q" =~ ^([0-9]+)(Ki|Mi|Gi|Ti|Pi|k|M|G|T|P)?$ ]] || return 0
  n="${BASH_REMATCH[1]}" u="${BASH_REMATCH[2]}"
  case "$u" in
    "") echo $((n / 1024)) ;; Ki) echo "$n" ;; Mi) echo $((n * 1024)) ;; Gi) echo $((n * 1048576)) ;;
    Ti) echo $((n * 1073741824)) ;; Pi) echo $((n * 1099511627776)) ;;
    k) echo $((n * 1000 / 1024)) ;; M) echo $((n * 1000000 / 1024)) ;; G) echo $((n * 1000000000 / 1024)) ;;
    T) echo $((n * 1000000000000 / 1024)) ;; P) echo $((n * 1000000000000000 / 1024)) ;;
  esac
}

# kube_sync_prepare_t26 — kube_sync_secrets' first steps from Task 26: LLDAP's
# key seed (users.sh, made by init; synced as secrets-lldap with
# secrets/lldap/) required before anything is synced (fail closed), then
# the backup destination's Secret.
kube_sync_prepare_t26() {
  lldap_key_seed_require
  kube_backup_destination_sync || fail "could not sync the backup destination's Secret backup-destination"
  # Longhorn's target and egress, the endpoint re-resolved (no Longhorn: nothing).
  ha_longhorn_backup_target
}
KUBE_BARMAN_NS="$KUBE_CNPG_NS"

# kube_backup_destination_sync — the Secret backup-destination as described
# above (idempotent: put when it differs, deleted when unset).
kube_backup_destination_sync() {
  local st ns f rc=0
  if [ -z "${PORTCULLIS_BACKUP_S3_URL:-}" ]; then
    for ns in "$KUBE_CNPG_NS" "$KUBE_LONGHORN_NS"; do
      kube_ctl -n "$ns" delete secret backup-destination --ignore-not-found >/dev/null 2>&1 || rc=1
    done
    return "$rc"
  fi
  backup_dest_read
  backup_dest_parts
  st="$(mktemp -d)"; chmod 700 "$st"
  (umask 077 && mkdir -p "$st/s"
   printf '%s' "$_BD_AWS_ACCESS_KEY_ID" > "$st/s/AWS_ACCESS_KEY_ID"
   printf '%s' "$_BD_AWS_SECRET_ACCESS_KEY" > "$st/s/AWS_SECRET_ACCESS_KEY"
   printf '%s' "$_BD_AWS_DEFAULT_REGION" > "$st/s/AWS_DEFAULT_REGION"
   printf '%s' "$_BD_ENDPOINT" > "$st/s/AWS_ENDPOINTS")
  for ns in "$KUBE_CNPG_NS" "$KUBE_LONGHORN_NS"; do
    kube_ctl get namespace "$ns" -o name >/dev/null 2>&1 || continue
    f="$st/$ns.json"
    kube_ctl -n "$ns" create secret generic backup-destination --from-file="$st/s" --dry-run=client -o json \
      | jq '.metadata.labels["app.kubernetes.io/managed-by"] = "portcullis"' > "$f" && _kube_put "$f" || rc=1
  done
  rm -rf "$st"
  return "$rc"
}

# _kube_barman_ready — the plugin runs in cnpg-system (its Deployment
# available, at least one replica: one scaled to 0 is "ready" to
# _ha_deploy_ready but serves nothing — found in e2e-k3s): only then may
# the Cluster name it.
_kube_barman_ready() {
  _ha_deploy_ready "$KUBE_BARMAN_NS" barman-cloud >/dev/null 2>&1 \
    && kube_ctl -n "$KUBE_BARMAN_NS" get deploy barman-cloud -o json 2>/dev/null | jq -e '(.status.availableReplicas // 0) >= 1' >/dev/null 2>&1
}

# kube_backup_values <values file> — backup.* (see the header): destination
# = the URL is set; cnpg.* only when the plugin is ready too.
kube_backup_values() {
  local f="$1" dest=false cnpg=false path="" ep="" port=443 srv="" mode="" cidrs="" exc=""
  if [ -n "${PORTCULLIS_BACKUP_S3_URL:-}" ]; then
    dest=true
    backup_dest_parts
    path="s3://$_BD_BUCKET/${_BD_PREFIX:+$_BD_PREFIX/}cnpg" ep="$_BD_ENDPOINT"
    port="$(backup_dest_port)"
    if _kube_barman_ready; then
      cnpg=true
      backup_dest_egress_resolve || fail "the backup destination's endpoint: see above (nothing rendered)"
      srv="$(kube_pg_server_name)" || fail "PORTCULLIS_KUBE_INSTALL_ID isn't a uuid: CloudNativePG's archive needs this install's own serverName (nothing rendered)"
      # The run's one resolution (review NN7: Longhorn's policies have the same).
      mode="$_BD_EGRESS_MODE" cidrs="$_BD_EGRESS_CIDRS" exc="$_BD_EGRESS_EXCEPT"
    fi
  fi
  (umask 077 && jq --argjson d "$dest" --argjson c "$cnpg" --arg p "$path" --arg e "$ep" --argjson port "$port" --arg srv "$srv" \
       --arg mode "$mode" --arg cidrs "$cidrs" --arg exc "$exc" \
    'def lines: split("\n") | map(select(. != ""));
     .backup = {destination: $d, cnpg: {enabled: $c, destinationPath: $p, endpointURL: $e, port: $port, serverName: $srv,
       publicEgress: ($mode == "public"), endpointCIDRs: (if $mode == "public" then [] else ($cidrs | lines) end),
       publicExcept: (if $mode == "public" then ($exc | lines) else [] end), retention: "30d", schedule: "0 15 3 * * *"}}' "$f" > "$f.tmp") \
    && chmod 600 "$f.tmp" && mv -f "$f.tmp" "$f" || fail "could not write the backup destination's values"
}

# kube_backup_after_release — after the release, with the archive on
# (backup.cnpg.enabled): the first base backup, once the Cluster archives
# (≤ KUBE_PG_ARCHIVE_WAIT, 300 s; ContinuousArchiving False for
# KUBE_PG_ARCHIVE_FALSE_WAIT, 60 s, ends the wait early: review NM5) and no
# Backup of this archive is completed or in progress — the ScheduledBackup
# isn't immediate (found in e2e-k3s: an immediate one raced the instances'
# restart with the plugin's sidecar and failed "requested plugin is not
# available"). Only this Cluster's Backups count (review NM5): spec.cluster
# portcullis-pg, created since the Cluster was (and owned by its uid when
# they name a Cluster owner), status.serverName this install's (or not yet
# set); phases completed / pending / started / running / finalizing /
# walArchivingFailing (or none yet). A Backup object; status shows its
# result (LastBackupSucceeded). Never fails the up.
kube_backup_after_release() {
  local i a="" n f cl srv uid ct falsefor=0 msg
  [ "$(jq -r '.backup.cnpg.enabled // false' "$(kube_values_file)" 2>/dev/null)" = true ] || return 0
  srv="$(jq -r '.backup.cnpg.serverName // ""' "$(kube_values_file)" 2>/dev/null || true)"
  for ((i = 0; i < "${KUBE_PG_ARCHIVE_WAIT:-300}"; i += 5)); do
    cl="$(kube_ctl -n "$KUBE_CNPG_NS" get cluster.postgresql.cnpg.io "$KUBE_PG_CLUSTER" -o json 2>/dev/null || true)"
    a="$(printf '%s' "$cl" | jq -r '([.status.conditions[]? | select(.type == "ContinuousArchiving")][0].status // "") + " " + ((.status.readyInstances // 0) == (.spec.instances // -1) | tostring)' 2>/dev/null || true)"
    [ "$a" = "True true" ] && break
    case "$a" in False*) falsefor=$((falsefor + 5)) ;; *) falsefor=0 ;; esac
    [ "$falsefor" -lt "${KUBE_PG_ARCHIVE_FALSE_WAIT:-60}" ] || break
    sleep 5
  done
  if [ "$a" != "True true" ]; then
    case "$a" in
      False*) msg="$(printf '%s' "$cl" | jq -r '[.status.conditions[]? | select(.type == "ContinuousArchiving")][0].message // "" | .[0:300]' 2>/dev/null || true)"
              warn "CloudNativePG's ContinuousArchiving is False${msg:+ ($msg)}: no first base backup (see ./portcullis status)" ;;
      *) warn "CloudNativePG isn't archiving to the backup destination yet: no first base backup (see ./portcullis status)" ;;
    esac
    return 0
  fi
  uid="$(printf '%s' "$cl" | jq -r '.metadata.uid // ""')" ct="$(printf '%s' "$cl" | jq -r '.metadata.creationTimestamp // ""')"
  n="$(kube_ctl -n "$KUBE_CNPG_NS" get backups.postgresql.cnpg.io -o json 2>/dev/null \
    | jq -r --arg srv "$srv" --arg uid "$uid" --arg ct "$ct" --arg cl "$KUBE_PG_CLUSTER" '[.items[]
        | select(.spec.method == "plugin" and .spec.cluster.name == $cl)
        | select((.metadata.creationTimestamp // "") >= $ct)
        | select((.metadata.ownerReferences // []) | all(.kind != "Cluster" or .uid == $uid))
        | select((.status.serverName // "") | . == "" or . == $srv)
        | select((.status.phase // "") | IN("completed", "pending", "started", "running", "finalizing", "walArchivingFailing", ""))] | length' 2>/dev/null || echo x)"
  [ "$n" = 0 ] || return 0
  f="$(mktemp)"
  NS="$KUBE_CNPG_NS" N="portcullis-pg-base-$(date -u +%Y%m%d%H%M%S)" jq -n '{apiVersion: "postgresql.cnpg.io/v1", kind: "Backup",
      metadata: {name: env.N, namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis"}},
      spec: {method: "plugin", pluginConfiguration: {name: "barman-cloud.cloudnative-pg.io"}, cluster: {name: "portcullis-pg"}}}' > "$f"
  if kube_ctl create -f "$f" >/dev/null 2>&1; then info "CloudNativePG: the first base backup to the destination started"; else warn "could not start CloudNativePG's first base backup (see ./portcullis status)"; fi
  rm -f "$f"
}

# kube_pg_server_name — the archive's serverName (review I1):
# portcullis-pg-<the install id's first 8 hex>. The install id is a host key
# a restore keeps (RESTORE_KUBE_KEY_NAMES), so a re-made or restored
# cluster never writes into, or is stalled by, another cluster's archive
# (the plugin refuses a non-empty archive for a new cluster).
kube_pg_server_name() {
  local id="${PORTCULLIS_KUBE_INSTALL_ID:-}"
  [[ "$id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  printf 'portcullis-pg-%s\n' "${id:0:8}"
}

# kube_backup_status_record — ConfigMap portcullis-backup-status in the core
# namespace: last_success (RFC 3339, UTC) of the core backup that just
# reached the destination (the Hub's backup_stale, contract §14.5; no
# secret in it).
kube_backup_status_record() {
  local f rc=0
  f="$(mktemp)"
  NS="$(kube_ns)" N="$KUBE_BACKUP_STATUS_CM" T="$(date -u +%Y-%m-%dT%H:%M:%SZ)" jq -n '
    {apiVersion: "v1", kind: "ConfigMap", metadata: {name: env.N, namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis"}},
     data: {last_success: env.T, what: "core"}}' > "$f" && _kube_put "$f" || rc=1
  rm -f "$f"
  return "$rc"
}

# backup_dest_port — the destination's TCP port (its URL's, else 443 / 80).
backup_dest_port() {
  backup_dest_parts
  case "$_BD_HOST" in *:*) echo "${_BD_HOST##*:}" ;; *) if [ "$_BD_SCHEME" = https ]; then echo 443; else echo 80; fi ;; esac
}

# backup_dest_egress_resolve [<opt-in>] — how the backup pods reach the
# destination (security rulings, Task 26 + reviews I3 / NM2–NM4), into
# _BD_EGRESS_MODE / _CIDRS / _EXCEPT (one per line). The endpoint name is
# resolved as the pods resolve it — from inside the cluster through CoreDNS
# (_backup_dest_dns_probe: a short-lived restricted pod, up to
# BACKUP_DEST_RESOLVE_TRIES (5) lookups, each past the answer's TTL and at
# least BACKUP_DEST_RESOLVE_WAIT (2) s apart, within
# BACKUP_DEST_PROBE_WINDOW (150) s):
#   pinned  the same address set every time (or an IPv4 literal): exactly
#           those /32s on the destination's port;
#   public  the set rotates (AWS S3, R2, B2…: the pods' own lookups would
#           mostly miss a pinned set), or the TTL is too long for the window
#           to tell ("can't tell; addresses may rotate"): only with the
#           opt-in, TCP 443 to any PUBLIC address — 0.0.0.0/0 except
#           BACKUP_DEST_PRIVATE_CIDRS (RFC 1918, CGNAT, link-local,
#           loopback, 0/8 and the special-purpose ranges), the pod / service
#           / mesh CIDRs, the nodes, the API endpoints, the VPN subnet, the
#           Hub's Local networks and wired-VPN provider ranges and the
#           server's own public addresses (a port other than 443 is refused
#           in this mode). Status says so.
# The opt-in is .env's PORTCULLIS_BACKUP_ALLOW_ROTATING=true only (env_get,
# never the process environment: one that disagrees with .env is refused),
# or <opt-in> = set's flag (true / empty). Either way only the exact backup
# pods get it. Refused (fail closed): nothing resolves, an address inside
# the cluster, unknown pod / service CIDRs or node addresses, an invalid
# range or address, and in public mode the Hub's ranges unreadable (and
# never read before). Resolved once per run (_BD_EGRESS_KEY: URL + opt-in);
# the mode is recorded in secrets/kube/backup-egress for status.
# Re-resolved at every up, set and test.
BACKUP_DEST_PRIVATE_CIDRS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16 127.0.0.0/8 0.0.0.0/8 192.0.0.0/24 192.0.2.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 192.88.99.0/24 224.0.0.0/4 240.0.0.0/4"
# shellcheck disable=SC2120  # set's opt-in argument comes from backup.sh
backup_dest_egress_resolve() {
  local h ips="" seen="" a n nodes nets api bad="" stable=true port allow envv j long=false ttl=unknown extra
  backup_dest_parts
  if [ $# -gt 0 ]; then allow="$1"
  else
    envv="$(env_get PORTCULLIS_BACKUP_ALLOW_ROTATING 2>/dev/null || true)"
    [ "${PORTCULLIS_BACKUP_ALLOW_ROTATING:-}" = "$envv" ] \
      || { echo "PORTCULLIS_BACKUP_ALLOW_ROTATING in the environment (${PORTCULLIS_BACKUP_ALLOW_ROTATING:-empty}) differs from .env (${envv:-empty}): the opt-in is read from .env only (backup destination set --allow-rotating-addresses); unset it in the environment (refused)" >&2; return 1; }
    allow="$envv"
  fi
  [ "$allow" = true ] || allow=""
  [ "${_BD_EGRESS_KEY:-}" != "$PORTCULLIS_BACKUP_S3_URL|$allow" ] || [ -z "${_BD_EGRESS_MODE:-}" ] || return 0
  h="${_BD_HOST%:*}"
  [ -n "${PORTCULLIS_POD_CIDR:-}" ] && [ -n "${PORTCULLIS_SERVICE_CIDR:-}" ] \
    || { echo "PORTCULLIS_POD_CIDR / PORTCULLIS_SERVICE_CIDR unknown: the backup destination can't be checked against the cluster (refused)" >&2; return 1; }
  nodes="${PORTCULLIS_KUBE_NODE_ADDRESSES:-$(kube_node_addresses)}"
  [ -n "$nodes" ] || { echo "the nodes' addresses are unknown: the backup destination can't be checked against them (refused)" >&2; return 1; }
  nets="$PORTCULLIS_POD_CIDR $PORTCULLIS_SERVICE_CIDR $KUBE_MESH_CIDR 169.254.0.0/16 127.0.0.0/8"
  for n in $nets; do cidr_bounds "$n" >/dev/null 2>&1 || { echo "$n isn't an IPv4 CIDR: the backup destination can't be checked (refused)" >&2; return 1; }; done
  [ -n "${PORTCULLIS_KUBE_API_ENDPOINTS:-}" ] || { echo "PORTCULLIS_KUBE_API_ENDPOINTS unknown: the backup destination can't be checked (refused)" >&2; return 1; }
  api="$(printf '%s\n' ${PORTCULLIS_KUBE_API_ENDPOINTS} | sed 's/:[0-9]*$//' | tr '\n' ' ')"
  for a in $api $nodes; do
    ip_to_int "$a" >/dev/null 2>&1 || { echo "the cluster address $a (an API endpoint or a node) isn't an IPv4 address: the backup destination can't be checked (refused)" >&2; return 1; }
  done
  if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then ips="$h"
  else
    j="$(_backup_dest_dns_probe "$h")" && printf '%s' "$j" | jq -e '(.lookups | type == "array" and length > 0) and (.long | type == "boolean")' >/dev/null 2>&1 \
      || { echo "the backup destination's host $h couldn't be looked up from inside the cluster (CoreDNS): no egress policy for it (refused)" >&2; return 1; }
    [ "$(printf '%s' "$j" | jq -r 'all(.lookups[]; (.ips | length) > 0)')" = true ] \
      || { echo "the backup destination's host $h doesn't resolve to an IPv4 address in the cluster (CoreDNS): no egress policy for it" >&2; return 1; }
    ips="$(printf '%s' "$j" | jq -r '.lookups[0].ips | join(" ")')"
    seen="$(printf '%s' "$j" | jq -r '[.lookups[].ips[]] | unique | join(" ")')"
    [ "$(printf '%s' "$j" | jq -r '[.lookups[].ips] | unique | length')" = 1 ] || stable=false
    long="$(printf '%s' "$j" | jq -r '.long')"
    ttl="$(printf '%s' "$j" | jq -r '.lookups[0].ttl // "unknown"')"
  fi
  for a in $ips $seen; do
    ip_to_int "$a" >/dev/null 2>&1 || { echo "the backup destination's address $a isn't an IPv4 address (refused)" >&2; return 1; }
    for n in $nets; do ! cidr_contains "$n" "$a" || bad="$bad $a"; done
    case " $nodes $api " in *" $a "*) bad="$bad $a" ;; esac
  done
  [ -z "$bad" ] || { echo "the backup destination resolves inside the cluster ($(printf '%s\n' $bad | sort -u | tr '\n' ' ' | sed 's/ $//')): refused" >&2; return 1; }
  if [ "$stable" = true ] && [ "$long" = false ]; then
    _BD_EGRESS_MODE=pinned _BD_EGRESS_CIDRS="$(printf '%s/32\n' $ips)" _BD_EGRESS_EXCEPT=""
  else
    # Security review: never automatic — the operator opts in with
    # backup destination set --allow-rotating-addresses (.env
    # PORTCULLIS_BACKUP_ALLOW_ROTATING=true).
    if [ "$allow" != true ]; then
      if [ "$stable" = true ]; then
        echo "the backup destination's host $h answers with a TTL of ${ttl}s, too long to tell within ${BACKUP_DEST_PROBE_WINDOW:-150}s whether its addresses rotate: can't tell; addresses may rotate. Refused; use an IP address or a name with a short TTL, or, to allow TCP 443 to any public address from the backup pods, set it again with --allow-rotating-addresses" >&2
      else
        echo "the backup destination's addresses rotate ($(printf '%s\n' $seen | wc -l | tr -d ' ') seen from inside the cluster): its pods' own lookups would miss a pinned policy. Refused; to allow TCP 443 to any public address from the backup pods, set it again with --allow-rotating-addresses" >&2
      fi
      return 1
    fi
    port="$(backup_dest_port)"
    [ "$port" = 443 ] || { echo "the backup destination's addresses rotate (or may): egress then goes to any public address on 443 only, and its port is $port (refused)" >&2; return 1; }
    extra="$(_backup_dest_public_except)" || return 1
    _BD_EGRESS_MODE=public _BD_EGRESS_CIDRS="0.0.0.0/0"
    _BD_EGRESS_EXCEPT="$(printf '%s\n' $BACKUP_DEST_PRIVATE_CIDRS "$PORTCULLIS_POD_CIDR" "$PORTCULLIS_SERVICE_CIDR" "$KUBE_MESH_CIDR"; printf '%s/32\n' $nodes $api | LC_ALL=C sort -u; printf '%s\n' "$extra")"
    _BD_EGRESS_EXCEPT="$(printf '%s\n' "$_BD_EGRESS_EXCEPT" | awk 'NF && !s[$0]++')"
  fi
  _BD_EGRESS_KEY="$PORTCULLIS_BACKUP_S3_URL|$allow"
  { (umask 077 && mkdir -p "$PORTCULLIS_ROOT/secrets/kube" && printf '%s\n' "$_BD_EGRESS_MODE" > "$PORTCULLIS_ROOT/secrets/kube/backup-egress"); } 2>/dev/null || true
}

# _backup_dest_public_except — public mode's ranges beyond the fixed ones
# (review NM2), one per line: the VPN subnet (PORTCULLIS_VPN_SUBNET), the
# Hub's Local networks and wired-VPN provider ranges (hub vpn host-info;
# kept in secrets/kube/backup-egress-hub-ranges for an up with the Hub at 0:
# never read and the Hub not answering = refused), and the server's own
# public IPv4 (PORTCULLIS_PUBLIC_IPV4, secrets/domains/public-ips.env's
# DOMAINS_PUBLIC_IPV4, PORTCULLIS_MAIL_PUBLIC_IPV4: hairpin NAT reaches this
# install's Traefik from a trusted source). IPv6 entries are skipped (the
# policies are IPv4; IPv6 egress is denied). An invalid IPv4 range refuses.
_backup_dest_public_except() {
  local info c cache="$PORTCULLIS_ROOT/secrets/kube/backup-egress-hub-ranges" pips="$PORTCULLIS_ROOT/secrets/domains/public-ips.env" hub out=""
  if info="$(_vpn_host_info 2>/dev/null)" && printf '%s' "$info" | jq -e 'type == "object" and (.local_networks | type == "array")' >/dev/null 2>&1; then
    hub="$(printf '%s' "$info" | jq -r '[(.local_networks // [])[], (.provider_ranges // [])[]] | map(strings) | .[]')"
    { (umask 077 && mkdir -p "${cache%/*}" && printf '%s\n' "$hub" > "$cache"); } 2>/dev/null || true
  elif [ -f "$cache" ]; then
    hub="$(cat "$cache")"
    echo "the Hub didn't answer hub vpn host-info: its Local networks and provider ranges as last read are excepted" >&2
  else
    echo "the Hub's Local networks and wired-VPN provider ranges can't be read (hub vpn host-info: is the Hub running?): public backup egress needs them excepted (refused)" >&2
    return 1
  fi
  for c in ${PORTCULLIS_VPN_SUBNET:-} $hub; do
    case "$c" in *:*) continue ;; esac
    cidr_bounds "$c" >/dev/null 2>&1 || { echo "$c (the VPN subnet or a Hub Local network / provider range) isn't an IPv4 CIDR: public backup egress can't except it (refused)" >&2; return 1; }
    out="$out$c"$'\n'
  done
  for c in "${PORTCULLIS_PUBLIC_IPV4:-}" "$(env_get DOMAINS_PUBLIC_IPV4 "$pips" 2>/dev/null || true)" "${PORTCULLIS_MAIL_PUBLIC_IPV4:-}"; do
    [ -n "$c" ] || continue
    ip_to_int "$c" >/dev/null 2>&1 || { echo "the server's public address $c isn't an IPv4 address (refused)" >&2; return 1; }
    out="$out$c/32"$'\n'
  done
  printf '%s' "$out"
}

# _backup_dest_dns_probe <host> — JSON {lookups: [{ips, ttl}], long} of the
# name as the pods see it (review NM4): a restricted helper pod in the core
# namespace (nobody, no volume, only kube-dns reachable: the namespace's
# policies) of group-gate's image runs _BD_DNS_PROBE_PY against its
# resolv.conf's nameserver (CoreDNS), asking A records directly (no search
# list). Each lookup waits past the previous answer's TTL (the caches of
# CoreDNS and the node's resolver); a TTL that doesn't fit the window ends
# it "long". The name isn't a secret (argv).
_backup_dest_dns_probe() {
  local pod rc=0
  pod="$(_kube_helper_pod "" 65534:65534 ro "$(_kube_image_of group-gate)" backup-dns-probe)" || { echo "could not start the DNS probe pod" >&2; return 1; }
  kube_ctl -n "$(kube_ns)" exec "$pod" -- env PYTHONDONTWRITEBYTECODE=1 python3 -I -c "$_BD_DNS_PROBE_PY" "$1" "${BACKUP_DEST_PROBE_WINDOW:-150}" "${BACKUP_DEST_RESOLVE_TRIES:-5}" "${BACKUP_DEST_RESOLVE_WAIT:-2}" || rc=1
  _kube_helper_done "$pod"
  return "$rc"
}
# argv: host window tries gap [resolv.conf [port]] (the last two for tests).
_BD_DNS_PROBE_PY='import json, random, socket, struct, sys, time
host, window, tries, gap = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
conf = sys.argv[5] if len(sys.argv) > 5 else "/etc/resolv.conf"
port = int(sys.argv[6]) if len(sys.argv) > 6 else 53
ns = [l.split()[1] for l in open(conf) if l.split()[:1] == ["nameserver"]][0]
labels = host.rstrip(".").split(".")
if not all(0 < len(p) < 64 and p.isascii() for p in labels):
    sys.exit("not a DNS name")
def ask():
    qid = random.randrange(65536)
    msg = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"".join(bytes([len(p)]) + p.encode() for p in labels) + b"\0" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    try:
        s.sendto(msg, (ns, port))
        while True:
            data = s.recv(4096)
            if data[:2] == msg[:2]:
                break
    finally:
        s.close()
    if struct.unpack(">H", data[2:4])[0] & 0x0200:  # truncated: TCP
        t = socket.create_connection((ns, port), timeout=5)
        try:
            t.sendall(struct.pack(">H", len(msg)) + msg)
            buf = b""
            while len(buf) < 2 or len(buf) < 2 + struct.unpack(">H", buf[:2])[0]:
                c = t.recv(65535)
                if not c:
                    break
                buf += c
        finally:
            t.close()
        data = buf[2:]
    flags, qd, an = struct.unpack(">HHH", data[2:8])
    if data[:2] != msg[:2] or flags & 0x000F:
        return [], None
    def skip(i):
        while True:
            b = data[i]
            if b == 0:
                return i + 1
            if b & 0xC0 == 0xC0:
                return i + 2
            i += b + 1
    i = 12
    for _ in range(qd):
        i = skip(i) + 4
    ips, ttl = set(), None
    for _ in range(an):
        i = skip(i)
        typ, cls, rttl, rdlen = struct.unpack(">HHIH", data[i:i + 10])
        i += 10
        if cls == 1 and typ in (1, 5):
            ttl = rttl if ttl is None else min(ttl, rttl)
        if cls == 1 and typ == 1 and rdlen == 4:
            ips.add(socket.inet_ntoa(data[i:i + 4]))
        i += rdlen
    return sorted(ips), ttl
out, start, long_ = [], time.monotonic(), False
for n in range(tries):
    ips, ttl = ask()
    out.append({"ips": ips, "ttl": ttl})
    if not ips or n == tries - 1 or (n and ips != out[0]["ips"]):
        break
    # Past the TTL of the answer (the caches of the resolvers), within the window.
    wait = max(gap, (ttl or 0) + 1)
    if time.monotonic() - start + wait * (tries - 1 - n) > window:
        long_ = True
        break
    time.sleep(wait)
print(json.dumps({"lookups": out, "long": long_}))
'

# backup_dest_cidrs — the resolved egress as lines: the pinned /32s, or
# "public" (see above).
backup_dest_cidrs() {
  backup_dest_egress_resolve || return 1
  if [ "$_BD_EGRESS_MODE" = public ]; then echo public; else printf '%s\n' "$_BD_EGRESS_CIDRS"; fi
}

# _ha_backup_egress <namespace> <name> <pod selector json> — a CLI-owned
# NetworkPolicy: the selected pods (never all of a namespace: the exact
# component that talks to the destination) reach the destination
# endpoint's addresses (backup_dest_cidrs) on its port, nothing else.
_ha_backup_egress() {
  local port
  case "$3" in ''|'{}') echo "_ha_backup_egress: a pod selector naming the component is required" >&2; return 1 ;; esac
  backup_dest_egress_resolve || return 1
  port="$(backup_dest_port)"
  NS="$1" N="$2" SEL="$3" PORT="$port" C="$_BD_EGRESS_CIDRS" X="$_BD_EGRESS_EXCEPT" M="$_BD_EGRESS_MODE" jq -n '
    def lines: split("\n") | map(select(. != ""));
    {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy",
     metadata: {name: env.N, namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis"}},
     spec: {podSelector: (env.SEL | fromjson), policyTypes: ["Egress"],
       egress: [{to: (if env.M == "public" then [{ipBlock: {cidr: "0.0.0.0/0", except: (env.X | lines)}}]
                      else [env.C | lines | .[] | {ipBlock: {cidr: .}}] end),
                 ports: [{protocol: "TCP", port: (env.PORT | tonumber)}]}]}}' | _ha_apply
}

# The Longhorn pods that reach the backup target (v1.13.0, pinned labels:
# the chart's longhorn-manager DaemonSet app=longhorn-manager — it lists and
# syncs the backup target; the v1 data engine's instance managers
# longhorn.io/component=instance-manager, types.GetInstanceManagerLabels —
# their replicas upload and fetch the blocks). Backing images aren't used.
HA_LONGHORN_BACKUP_PODS='backup-destination-manager {"matchLabels":{"app":"longhorn-manager"}}
backup-destination-instance-manager {"matchLabels":{"longhorn.io/component":"instance-manager"}}'
# The names earlier versions used (always deleted): backup-destination
# selected every pod of longhorn-system.
HA_LONGHORN_BACKUP_OLD="backup-destination"

# kube_backup_status_json — the destination's health for status (reviews I1
# / I3 / NM1 / NM5): {egress, allow_rotating, cnpg: {plugin, plugin_ready,
# archiving, last_backup (True / False / Unknown), next_base, message},
# longhorn: {available}}; null without a destination. The Cluster is read
# whenever the last render archived (backup.cnpg.enabled) or the plugin
# runs — whatever the plugin's state: a Cluster naming a plugin that isn't
# available is a problem of its own. An unreadable Cluster / BackupTarget
# is a problem (fail closed). The opt-in is .env's (env_get).
kube_backup_status_json() {
  local c="null" l="null" e="" up want=false ready=false next
  [ -n "${PORTCULLIS_BACKUP_S3_URL:-}" ] || { echo null; return 0; }
  up="$(backup_dest_url_problem "${PORTCULLIS_BACKUP_S3_URL%/}")"
  [ -z "$up" ] || { jq -nc --arg p "$up" '{url_problem: $p}'; return 0; }
  e="$(cat "$PORTCULLIS_ROOT/secrets/kube/backup-egress" 2>/dev/null || true)"
  [ "$(jq -r '.backup.cnpg.enabled // false' "$(kube_values_file)" 2>/dev/null)" != true ] || want=true
  ! _kube_barman_ready || ready=true
  # Re-review R2-M1: the plugin installed but down at the last up (the
  # render then left it out) still gets a Postgres line: "stopped".
  local inst=false
  [ "$ready" = true ] || ! kube_ctl -n "$KUBE_BARMAN_NS" get deploy barman-cloud -o name >/dev/null 2>&1 || inst=true
  if [ "$want" = true ] || [ "$ready" = true ] || [ "$inst" = true ]; then
    # The ScheduledBackup's next run (chart: 03:15 UTC daily).
    next=$(( $(date -u +%s) / 86400 * 86400 + 11700 )); [ "$next" -gt "$(date -u +%s)" ] || next=$((next + 86400))
    c="$(kube_ctl -n "$KUBE_CNPG_NS" get cluster.postgresql.cnpg.io "$KUBE_PG_CLUSTER" -o json 2>/dev/null | jq -c --argjson want "$want" --argjson ready "$ready" --argjson next "$next" '
      [.status.conditions[]?] as $c
      | ((.spec.plugins // []) | any(.name == "barman-cloud.cloudnative-pg.io")) as $p
      | if ($p | not) and ($want | not) then {plugin: false, plugin_ready: $ready, archiving: false, stopped: true, last_backup: "Unknown", message: ""} else
        {plugin: $p, plugin_ready: $ready,
         archiving: (($c | map(select(.type == "ContinuousArchiving"))[0].status // "Unknown") == "True"),
         last_backup: ($c | map(select(.type == "LastBackupSucceeded"))[0].status // "Unknown"),
         next_base: ($next | todate),
         message: ([$c[] | select((.type == "ContinuousArchiving" or .type == "LastBackupSucceeded") and .status == "False") | .message // .reason] | join("; "))} end' 2>/dev/null || echo '{"unreadable":true}')"
  fi
  if kube_ctl get namespace "$KUBE_LONGHORN_NS" -o name >/dev/null 2>&1; then
    l="$(kube_ctl -n "$KUBE_LONGHORN_NS" get backuptargets.longhorn.io default -o json 2>/dev/null | jq -c '{available: (.status.available == true)}' 2>/dev/null || echo '{"available":false}')"
  fi
  jq -nc --arg e "$e" --argjson c "${c:-null}" --argjson l "${l:-null}" --arg ar "$(env_get PORTCULLIS_BACKUP_ALLOW_ROTATING 2>/dev/null || true)" \
    '{egress: (if $e == "" then null else $e end), allow_rotating: ($ar == "true"), cnpg: $c, longhorn: $l}'
}

# kube_backup_status_lines <json> — status' lines; exit 1 on a problem.
_bsl_q() { printf '%s' "$2" | jq -r "$1"; }
kube_backup_status_lines() {
  local j="$1" rc=0
  [ -n "$j" ] && [ "$j" != null ] || return 0
  if [ "$(_bsl_q '.url_problem // ""' "$j")" != "" ]; then
    _st_line fail "backup destination: PORTCULLIS_BACKUP_S3_URL is refused ($(_bsl_q .url_problem "$j")): nothing backs up to it"; return 1
  fi
  if [ "$(_bsl_q '.cnpg.unreadable // false' "$j")" = true ]; then
    _st_line fail "backup destination: the Postgres Cluster's archive state can't be read"; rc=1
  elif [ "$(_bsl_q '.cnpg.stopped // false' "$j")" = true ]; then
    _st_line fail "backup destination: Postgres archiving stopped: the Cluster doesn't name the barman-cloud plugin ($(_bsl_q 'if .cnpg.plugin_ready then "it is available now" else "it is not available" end' "$j"); it wasn't at the last ./portcullis up). Run ./portcullis up once the plugin runs (kubectl -n $KUBE_BARMAN_NS get deploy barman-cloud)"; rc=1
  elif [ "$(_bsl_q '.cnpg != null' "$j")" = true ]; then
    if [ "$(_bsl_q '.cnpg.plugin and (.cnpg.plugin_ready | not)' "$j")" = true ]; then
      _st_line fail "backup destination: the Postgres Cluster archives through the barman-cloud plugin, which isn't available (kubectl -n $KUBE_BARMAN_NS get deploy barman-cloud): WAL piles up until the disk fills"; rc=1
    elif [ "$(_bsl_q '.cnpg.archiving and .cnpg.last_backup != "False"' "$j")" != true ]; then
      _st_line fail "backup destination: Postgres isn't archiving ($(_bsl_q '.cnpg.message | if . == "" then "ContinuousArchiving / LastBackupSucceeded not true" else .[0:300] end' "$j")): WAL piles up until the disk fills"; rc=1
    elif [ "$(_bsl_q '.cnpg.last_backup' "$j")" != True ]; then
      _st_line warn "backup destination: Postgres archives WAL but has no base backup yet (not restorable from the destination until one): the daily one runs at $(_bsl_q '.cnpg.next_base' "$j"), or ./portcullis up starts one now"
    else
      _st_line ok "backup destination: Postgres archiving (WAL + base backups)"
    fi
  fi
  if [ "$(_bsl_q '.longhorn != null' "$j")" = true ]; then
    if [ "$(_bsl_q '.longhorn.available' "$j")" = true ]; then _st_line ok "backup destination: Longhorn's backup target available"
    else _st_line fail "backup destination: Longhorn's backup target isn't available (kubectl -n longhorn-system get backuptargets default)"; rc=1; fi
  fi
  [ "$(_bsl_q '.egress' "$j")" != public ] || _st_line warn "backup egress: any public address on 443 (the destination's addresses rotate)"
  [ "$(_bsl_q '.allow_rotating' "$j")" != true ] || _st_line warn "backup destination: rotating addresses allowed (PORTCULLIS_BACKUP_ALLOW_ROTATING=true, set with --allow-rotating-addresses)"
  return "$rc"
}

# _ha_pins barmancloud: the plugin's release asset (Amendment 1).
_ha_barman_pins() { echo "barman-cloud/upstream/plugin-barman-cloud-v0.16.0.yaml aee614683892dd4b44ff9f7afaca55254f1c28de17abbaa0552bf2e1228f7155"; }

# ha_barman_policies — cnpg-system's flows for the plugin (CLI-owned, as
# ha_cnpg_policies): the plugin (app=barman-cloud) takes :9090 from the CNPG
# operator only and reaches the API endpoints; the operator reaches it.
ha_barman_policies() {
  NS="$KUBE_BARMAN_NS" API="${PORTCULLIS_KUBE_API_ENDPOINTS:-}" jq -n '
    def words: split(" ") | map(select(. != ""));
    def meta($n): {name: $n, namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis"}};
    def op: {matchLabels: {"app.kubernetes.io/name": "cloudnative-pg"}};
    def plugin: {matchLabels: {app: "barman-cloud"}};
    {apiVersion: "v1", kind: "List", items: [
      {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: meta("barman-cloud"),
       spec: {podSelector: plugin, policyTypes: ["Ingress", "Egress"],
              ingress: [{from: [{podSelector: op}], ports: [{protocol: "TCP", port: 9090}]}],
              egress: [env.API | words | .[] | split(":") as $p | {to: [{ipBlock: {cidr: ($p[0] + "/32")}}], ports: [{protocol: "TCP", port: ($p[1] | tonumber)}]}]}},
      {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: meta("cnpg-operator-barman"),
       spec: {podSelector: op, policyTypes: ["Egress"],
              egress: [{to: [{podSelector: plugin}], ports: [{protocol: "TCP", port: 9090}]}]}}]}'
}

# ha_install_barman — the barman-cloud plugin v0.16.0 in cnpg-system (plan
# Task 26; Amendment 2: its certificates are cert-manager's, so after
# ha_install_certmanager): pins checked, its flows first, the render
# applied server-side, then its certificates and the Deployment waited for.
# Refused (nothing installed) without cnpg-system or cert-manager.
ha_install_barman() {
  local t f want got
  read -r f want <<< "$(_ha_barman_pins)"
  [ -f "$PORTCULLIS_HOME/$HA_DIR/$f" ] || fail "$HA_DIR/$f is missing (nothing installed)"
  got="$(_kube_sha "$PORTCULLIS_HOME/$HA_DIR/$f")"
  [ "$got" = "$want" ] || fail "$HA_DIR/$f has sha256 $got, not the pinned $want (nothing installed)"
  kube_ctl get namespace "$KUBE_BARMAN_NS" -o name >/dev/null 2>&1 || fail "no namespace $KUBE_BARMAN_NS: the plugin serves CloudNativePG there (nothing installed)"
  _ha_deploy_ready "$KUBE_CERTMANAGER_NS" cert-manager cert-manager-webhook >/dev/null 2>&1 && _ha_certmanager_webhook_ready \
    || fail "cert-manager isn't ready (ha_install_certmanager first): the plugin's certificates are its (nothing installed)"
  [ -n "${PORTCULLIS_KUBE_API_ENDPOINTS:-}" ] || fail "no kube API endpoint (PORTCULLIS_KUBE_API_ENDPOINTS): the plugin's policy would reach nothing (nothing installed)"
  ha_barman_policies | _ha_apply || fail "could not apply the plugin's NetworkPolicies (nothing installed)"
  # Review M4: its Role / RoleBinding creates pinned by an admission policy,
  # in force before its RBAC and before it runs.
  _ha_barman_policy_apply || fail "the plugin's admission policy (kube/ha/barman-cloud/admission.yaml) isn't in force (nothing installed)"
  info "HA: CloudNativePG's barman-cloud plugin v0.16.0 ($KUBE_BARMAN_NS)..."
  t="$(mktemp)"
  kubectl kustomize "$PORTCULLIS_HOME/$HA_DIR/barman-cloud" > "$t" || { rm -f "$t"; fail "could not render the barman-cloud plugin (kubectl kustomize)"; }
  _ha_apply < "$t" || { rm -f "$t"; fail "could not apply the barman-cloud plugin (see above)"; }
  _ha_crds_established "$t" || { rm -f "$t"; fail "the ObjectStore CRD isn't established"; }
  rm -f "$t"
  _ha_wait 300 "the plugin's certificates (cert-manager)" _ha_barman_certs_ready
  _ha_wait 300 "the barman-cloud plugin" _ha_deploy_ready "$KUBE_BARMAN_NS" barman-cloud
  _kube_applied_set ha.barman "$(_kube_sha "$PORTCULLIS_HOME/$HA_DIR/barman-cloud"/*.yaml "$PORTCULLIS_HOME/$HA_DIR/barman-cloud/upstream"/*)"
}

# _ha_barman_policy_apply — portcullis-barman-rbac with this generation,
# then the plugin's Role (its rights to create roles), then the in-force
# check AS the plugin: a dry-run Role annotated with the generation is
# refused by the policy naming it (≤ 30 s), so nothing it writes is
# unguarded.
_ha_barman_policy_apply() {
  local f="$PORTCULLIS_HOME/$HA_DIR/barman-cloud/admission.yaml" g t i out
  g="$(_ha_policy_gen "$f")" || return 1
  t="$(mktemp)"
  _ha_policy_text "$f" > "$t" && _kube_apply_files "$t" || { rm -f "$t"; return 1; }
  rm -f "$t"
  _kube_apply_files "$PORTCULLIS_HOME/$HA_DIR/barman-cloud/rbac.yaml" || return 1
  for ((i = 0; i < 15; i++)); do
    out="$(NS="$KUBE_BARMAN_NS" G="$g" jq -n '{apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role",
        metadata: {name: "portcullis-pg-barman-cloud", namespace: env.NS, annotations: {"portcullis.io/policy-check": env.G}}, rules: []}' \
      | kube_ctl --as=system:serviceaccount:"$KUBE_BARMAN_NS":plugin-barman-cloud create --dry-run=server -f - 2>&1)" || true
    case "$out" in *"portcullis-barman-rbac generation $g is in force"*) return 0 ;; esac
    sleep 2
  done
  return 1
}

# _ha_barman_certs_ready — both plugin certificates issued (their Secrets).
_ha_barman_certs_ready() {
  kube_ctl -n "$KUBE_BARMAN_NS" get secret barman-cloud-server-tls barman-cloud-client-tls -o name >/dev/null 2>&1
}

# ha_longhorn_backup_target — with a destination and Longhorn: the Secret
# (kube_backup_destination_sync), the pods' egress to it, and Longhorn's
# BackupTarget default = s3://<bucket>@<region>/<prefix>/longhorn with that
# Secret (server-side apply of spec only; the manager keeps its status).
# Without a destination: the target emptied and the egress removed.
ha_longhorn_backup_target() {
  local f url="" n sel
  kube_ctl get namespace "$KUBE_LONGHORN_NS" -o name >/dev/null 2>&1 || return 0
  # The first version's namespace-wide policy (security review): gone
  # first, before anything here can refuse (review NN2).
  kube_ctl -n "$KUBE_LONGHORN_NS" delete networkpolicy $HA_LONGHORN_BACKUP_OLD --ignore-not-found >/dev/null \
    || fail "could not delete the old backup egress policy ($HA_LONGHORN_BACKUP_OLD) in $KUBE_LONGHORN_NS"
  if [ -n "${PORTCULLIS_BACKUP_S3_URL:-}" ]; then
    backup_dest_read; backup_dest_parts
    kube_backup_destination_sync || fail "could not sync the destination's Secret into $KUBE_LONGHORN_NS"
    backup_dest_egress_resolve || fail "the backup destination's endpoint: see above (Longhorn's egress not applied)"
    while read -r n sel; do
      _ha_backup_egress "$KUBE_LONGHORN_NS" "$n" "$sel" || fail "could not apply Longhorn's egress to the backup destination ($n)"
    done <<< "$HA_LONGHORN_BACKUP_PODS"
    url="s3://$_BD_BUCKET@$_BD_AWS_DEFAULT_REGION/${_BD_PREFIX:+$_BD_PREFIX/}longhorn"
  else
    kube_ctl -n "$KUBE_LONGHORN_NS" delete networkpolicy backup-destination-manager backup-destination-instance-manager --ignore-not-found >/dev/null \
      || fail "could not delete Longhorn's backup egress policies"
  fi
  f="$(mktemp)"
  NS="$KUBE_LONGHORN_NS" U="$url" jq -n '{apiVersion: "longhorn.io/v1beta2", kind: "BackupTarget", metadata: {name: "default", namespace: env.NS},
      spec: {backupTargetURL: env.U, credentialSecret: (if env.U == "" then "" else "backup-destination" end), pollInterval: "5m0s"}}' > "$f"
  _ha_apply < "$f" || { rm -f "$f"; fail "could not set Longhorn's backup target"; }
  rm -f "$f"
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
  _ha_policy_text "$PORTCULLIS_HOME/$HA_DIR/fencing/admission.yaml" "$img" > "$t" || { rm -f "$t"; fail "could not read the fencing pod policy (nothing installed)"; }
  _ha_apply < "$t" || { rm -f "$t"; fail "could not apply the fencing pod policy (nothing installed)"; }
  _ha_policy_in_force "$KUBE_FENCING_NS" portcullis-fencing-pods "$(_ha_policy_gen "$PORTCULLIS_HOME/$HA_DIR/fencing/admission.yaml" "$img")" || { rm -f "$t"; fail "the fencing pod policy isn't in force (nothing installed)"; }
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

# ── Valkey Sentinel and Vault raft (plan Task 25) ─────────

# The session store in HA (charts/portcullis/templates/sessions.yaml): two
# Valkey pods and three Sentinels, master name portcullis-sessions, quorum
# 2. Their configs are the CLI's, in secrets/sessions-ha/ (0700, files
# 0600; synced as the Secret secrets-sessions-ha; made on every
# Kubernetes install, used in HA):
#   internal               the replication and Sentinel users' password
#                          (40 alphanumerics, made once): only the Valkey
#                          and Sentinel pods hold it (env VALKEYCLI_AUTH,
#                          masterauth, sentinel-pass / auth-pass);
#   valkey.conf            sessions_conf's (the two oauth2-proxies' users)
#                          plus sessions-repl (+psync +replconf +ping: the
#                          replica's link) and sessions-admin (what a
#                          Sentinel sends a Valkey node — valkey 9.1.3
#                          src/sentinel.c: AUTH, CLIENT SETNAME / KILL, PING,
#                          INFO, PUBLISH / SUBSCRIBE __sentinel__:hello,
#                          MULTI / EXEC, SLAVEOF, FAILOVER, CONFIG REWRITE,
#                          SCRIPT KILL — and ROLE; the init guard and the
#                          readiness probe use it too), masteruser /
#                          masterauth;
#   sentinel.conf          the Sentinels' ACL: the default user (what
#                          oauth2-proxy v7.15.6 authenticates as: it sends
#                          no Sentinel user name) with BOTH oauth2-proxies'
#                          own passwords (SHA-256; OAUTH2_PROXY_REDIS_
#                          SENTINEL_PASSWORD = each one's
#                          FORWARD_AUTH[_EXT]_REDIS_PASSWORD), limited to
#                          what go-redis v9.23.0's failover client sends
#                          (PING, SENTINEL get-master-addr-by-name /
#                          sentinels / replicas, SUBSCRIBE +switch-master /
#                          +replica-reconf-done): never FAILOVER / SET /
#                          MONITOR / REMOVE; sessions-admin for the peers
#                          and the guard (sentinel-user / sentinel-pass);
#   sentinel-monitor.conf  after the pod's monitor line: auth-user /
#                          auth-pass, down-after 5 s, failover-timeout 60 s,
#                          parallel-syncs 1.
KUBE_SESSIONS_MASTER="portcullis-sessions"
KUBE_SESSIONS_ADMIN_ACL="+multi +exec +slaveof +replicaof +failover +ping +info +role +config|rewrite +client|setname +client|kill +script|kill +subscribe +publish"
KUBE_SENTINEL_CLIENT_ACL="+ping +subscribe +sentinel|get-master-addr-by-name +sentinel|sentinels +sentinel|replicas"

_kube_sessions_ha_dir() { echo "$PORTCULLIS_ROOT/secrets/sessions-ha"; }

# _kube_sessions_internal — the internal password (stdout); refuses a file
# that isn't 40 alphanumerics.
_kube_sessions_internal() {
  local f pw
  f="$(_kube_sessions_ha_dir)/internal"
  pw="$(cat "$f" 2>/dev/null)" || return 1
  [[ "$pw" =~ ^[A-Za-z0-9]{40}$ ]] || return 1
  printf '%s' "$pw"
}

# kube_sessions_ha_valkey_conf — the HA Valkey config on stdout.
kube_sessions_ha_valkey_conf() {
  local pw h
  pw="$(_kube_sessions_internal)" || fail "secrets/sessions-ha/internal isn't 40 alphanumerics"
  h="$(printf '%s' "$pw" | _sessions_hash)"
  [[ "$h" =~ ^[0-9a-f]{64}$ ]] || fail "could not hash the session store's internal password (openssl)"
  sessions_conf
  cat <<EOC
# HA (plan Task 25): the replica's link and the Sentinels / init guard.
user sessions-repl on resetpass resetkeys resetchannels -@all +psync +replconf +ping #$h
user sessions-admin on resetpass resetkeys resetchannels -@all $KUBE_SESSIONS_ADMIN_ACL &__sentinel__:hello #$h
masteruser sessions-repl
masterauth $pw
replica-read-only yes
EOC
}

# kube_sessions_ha_sentinel_conf — the Sentinels' static part on stdout.
kube_sessions_ha_sentinel_conf() {
  local pw h fwd ext
  pw="$(_kube_sessions_internal)" || fail "secrets/sessions-ha/internal isn't 40 alphanumerics"
  h="$(printf '%s' "$pw" | _sessions_hash)"
  fwd="$(printf '%s' "$FORWARD_AUTH_REDIS_PASSWORD" | _sessions_hash)"
  ext="$(printf '%s' "$FORWARD_AUTH_EXT_REDIS_PASSWORD" | _sessions_hash)"
  [[ "$h$fwd$ext" =~ ^[0-9a-f]{192}$ ]] || fail "could not hash the Sentinels' passwords (openssl)"
  cat <<EOC
# Generated by ./portcullis (scripts/lib/ha.sh). Do not edit: every up
# rewrites it. The pod's start adds its announce-ip and monitor lines.
port 26379
dir /data
sentinel resolve-hostnames yes
sentinel announce-hostnames yes
user default on resetpass resetkeys resetchannels &+switch-master &+replica-reconf-done -@all $KUBE_SENTINEL_CLIENT_ACL #$fwd #$ext
user sessions-admin on resetpass resetkeys allchannels +@all #$h
sentinel sentinel-user sessions-admin
sentinel sentinel-pass $pw
EOC
}

# kube_sessions_ha_monitor_conf — the lines after the monitor line.
kube_sessions_ha_monitor_conf() {
  local pw
  pw="$(_kube_sessions_internal)" || fail "secrets/sessions-ha/internal isn't 40 alphanumerics"
  cat <<EOC
sentinel auth-user $KUBE_SESSIONS_MASTER sessions-admin
sentinel auth-pass $KUBE_SESSIONS_MASTER $pw
sentinel down-after-milliseconds $KUBE_SESSIONS_MASTER 5000
sentinel failover-timeout $KUBE_SESSIONS_MASTER 60000
sentinel parallel-syncs $KUBE_SESSIONS_MASTER 1
EOC
}

# kube_sessions_ha_prepare — secrets/sessions-ha/: the internal password
# once, the three configs rewritten when they differ (0600, in place).
kube_sessions_ha_prepare() {
  local d f tmp pw
  env_require FORWARD_AUTH_REDIS_PASSWORD FORWARD_AUTH_EXT_REDIS_PASSWORD
  d="$(_kube_sessions_ha_dir)"
  (umask 077 && mkdir -p "$d")
  chmod 700 "$d"
  if ! _kube_sessions_internal >/dev/null; then
    pw="$(gen_alnum 40)"
    tmp="$(umask 077 && mktemp "$d/.internal.XXXXXX")"
    printf '%s' "$pw" > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$d/internal" || { rm -f "$tmp"; fail "could not write secrets/sessions-ha/internal"; }
  fi
  for f in valkey.conf sentinel.conf sentinel-monitor.conf; do
    tmp="$(umask 077 && mktemp "$d/.$f.XXXXXX")"
    case "$f" in
      valkey.conf) kube_sessions_ha_valkey_conf ;;
      sentinel.conf) kube_sessions_ha_sentinel_conf ;;
      sentinel-monitor.conf) kube_sessions_ha_monitor_conf ;;
    esac > "$tmp" || { rm -f "$tmp"; fail "could not render secrets/sessions-ha/$f"; }
    if cmp -s "$tmp" "$d/$f"; then rm -f "$tmp"; else chmod 600 "$tmp" && mv -f "$tmp" "$d/$f"; fi
  done
}

# Vault's voters (templates/vault.yaml): vault-0 without HA, vault-0..2 in
# HA (the StatefulSet's replicas).
kube_vault_voters() {
  local n
  n="$(kube_ctl -n "$(kube_ns)" get statefulset vault -o jsonpath='{.spec.replicas}' 2>/dev/null)" || n=""
  [[ "$n" =~ ^[1-9][0-9]*$ ]] || n="$(_rtk_replicas vault)"
  local i; for ((i = 0; i < n; i++)); do echo "vault-$i"; done
}

# _kube_bounded <seconds> <command…> — the command (a function too), killed
# after <seconds> (kubectl's --request-timeout doesn't bound an exec whose
# kubelet is gone: found live, ~30 s per lost voter).
_kube_bounded() {
  local s="$1" p w rc=0
  shift
  "$@" 9>&- & p=$!
  # The function's own children (kubectl) first: they hold the pipe open.
  # shellcheck disable=SC2046  # pid words
  # The watchdog holds no pipe of the caller's (else a reader waits for it).
  ( sleep "$s"; kill $(pgrep -P "$p" 2>/dev/null) "$p" 2>/dev/null ) </dev/null >/dev/null 2>&1 9>&- & w=$!
  wait "$p" 2>/dev/null || rc=$?
  # shellcheck disable=SC2046  # pid words
  kill $(pgrep -P "$w" 2>/dev/null) "$w" 2>/dev/null; wait "$w" 2>/dev/null
  return "$rc"
}

# kube_vault_leader — the voter whose own Vault says is_self (`vault
# status` in each pod, ≤ 6 s each: a pod on a lost node doesn't hold the
# CLI up). Prints the pod name; exit 1 when none leads. No label decides:
# Vault has no Kubernetes service registration (vault.hcl.tmpl).
kube_vault_leader() {
  local v
  for v in $(kube_vault_voters); do
    if _kube_bounded 6 kube_ctl -n "$(kube_ns)" --request-timeout=5s exec "$v" -c vault -- vault status -format=json 2>/dev/null \
        | jq -e '.is_self == true and .ha_enabled == true' >/dev/null 2>&1; then
      echo "$v"; return 0
    fi
  done
  return 1
}

# kube_vault_pod_set — _K_VAULT_POD = the leader, asked once and kept for
# the run (call it in the caller's shell, not in a $(…), so it sticks);
# unset while none leads. kube_vault_pod prints the pod the CLI talks to
# (rt_exec vault, the Vault port-forward): that leader, else vault-0 (not
# initialised yet, or no leader: init and its unseal go there; a standby
# forwards every other request to the leader).
kube_vault_pod_set() {
  [ -z "${_K_VAULT_POD:-}" ] || return 0
  local p
  if p="$(kube_vault_leader)"; then _K_VAULT_POD="$p"; fi
  return 0
}
kube_vault_pod() { kube_vault_pod_set; echo "${_K_VAULT_POD:-vault-0}"; }

# _kube_vault_snapshot_get <out> — through KUBE_FWD_PORT: "not-leader"
# unless that Vault still says is_self, else the snapshot GET's status.
_kube_vault_snapshot_get() {
  curl -s --max-time 5 "http://127.0.0.1:$KUBE_FWD_PORT/v1/sys/leader" 2>/dev/null | jq -e '.is_self == true' >/dev/null 2>&1 || { echo not-leader; return 0; }
  _backup_vault_fetch "http://127.0.0.1:$KUBE_FWD_PORT" "$1"
}

# _kube_vault_snapshot <out> — the raft snapshot from the leader
# (Amendment 2: every voter asked, kube_vault_leader), through a
# port-forward to that pod, which must still say is_self; 5 tries 15 s
# apart (a leader's node lost: the election and its stale endpoints).
# Validated like the compose one.
_kube_vault_snapshot() {
  local out="$1" i leader code
  for ((i = 1; i <= ${KUBE_VAULT_SNAPSHOT_TRIES:-5}; i++)); do
    code=""
    if leader="$(kube_vault_leader)"; then
      code="$(_kube_with_forward "pod/$leader" 8200 _kube_vault_snapshot_get "$out" 2>/dev/null)" || code=""
    fi
    case "$code" in
      200) _backup_vault_check "$out"; return ;;
      ""|not-leader) warn "no Vault leader answers (try $i)" ;;
      *) warn "Vault raft snapshot from $leader: HTTP $code (try $i)" ;;
    esac
    [ "$i" -ge "${KUBE_VAULT_SNAPSHOT_TRIES:-5}" ] || sleep "${KUBE_VAULT_SNAPSHOT_WAIT:-15}"
  done
  fail "Vault raft snapshot failed: no leader answered in ${KUBE_VAULT_SNAPSHOT_TRIES:-5} tries"
}

# ── the kube runtime verbs' StatefulSet side (plan Task 25; kube.sh R8) ──

# _rtk_ref <service> — its workload (_rtk_kind: the kind alone): statefulset/<svc> (Vault always, plan
# Task 25; in HA the session store, its Sentinels, Keycloak, the gates) or
# deploy/<svc>.
_rtk_ref() { echo "$(_rtk_kind "$1")/$1"; }
_rtk_kind() {
  if [ "$(kube_ctl -n "$(kube_ns)" get statefulset "$1" -o name 2>/dev/null)" = "statefulset.apps/$1" ]; then echo statefulset; else echo deploy; fi
}

# _rtk_replicas <service> — the replicas a start scales a stopped workload
# to: Vault's voters (3 in HA) and the session store's (2 in HA) as the
# chart renders them; any other service 1 (Keycloak and the gates in HA too:
# the next `up` gives them the chart's count back).
_rtk_replicas() {
  case "$1" in
    vault) if kube_ha_on; then echo 3; else echo 1; fi ;;
    sessions) if kube_ha_on; then echo 2; else echo 1; fi ;;
    sessions-sentinel) echo 3 ;;
    *) echo 1 ;;
  esac
}

# _kube_with_forward <target> <remote port> <command…> — the command with
# KUBE_FWD_PORT = a local port forwarded to <target> (pod/<name> or
# svc/<name>) by a kubectl port-forward this shell starts as its own child
# ($!) and ends itself after the command, whatever it returns. No record on
# disk (security review: a predictable record file could be planted and
# name another process to kill); the forward's output goes to a mktemp
# file, removed once its port is read.
_kube_with_forward() {
  local target="$1" port="$2" log pid i lp="" rc=0
  shift 2
  [ -n "${PORTCULLIS_KUBE_CONTEXT:-}" ] || fail "PORTCULLIS_KUBE_CONTEXT is not set in .env: CONTAINER_RUNTIME=kubernetes never uses the current context"
  log="$(mktemp)" || return 1
  # kubectl itself (not the kube_ctl function) is the background child, so
  # $! is the process to end.
  # Never the CLI lock (fd 9, cli_lock): a forward left behind would hold
  # it, and params-sync (the joins) would wait for ever (found live, Task
  # 30). kube.sh's two background forwards close it the same way.
  kubectl --context "$PORTCULLIS_KUBE_CONTEXT" -n "$(kube_ns)" port-forward --address 127.0.0.1 "$target" ":$port" >"$log" 2>&1 9>&- &
  pid=$!
  # The CLI killed meanwhile (by pid): the forward ends with it (review N2).
  local parent=$$
  ( while kill -0 "$parent" 2>/dev/null && kill -0 "$pid" 2>/dev/null; do sleep 1; done; kill "$pid" 2>/dev/null ) </dev/null >/dev/null 2>&1 9>&- &
  for ((i = 0; i < 100; i++)); do
    lp="$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9][0-9]*\) -> .*/\1/p' "$log" | head -n1)"
    [ -z "$lp" ] || break
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  rm -f "$log"
  if [ -n "$lp" ]; then KUBE_FWD_PORT="$lp" "$@" || rc=$?; else rc=1; fi
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  return "$rc"
}

# _kube_empty_vault — every voter's PVC (data-vault-<n>, StatefulSet vault;
# plan Task 25) emptied as Vault's owner: a restore starts one fresh raft.
_kube_empty_vault() {
  local p pod
  for p in $(kube_ctl -n "$(kube_ns)" get pvc -o json 2>/dev/null | jq -r '.items[].metadata.name | select(test("^data-vault-[0-9]+$"))'); do
    pod="$(_kube_helper_pod "$p" "100:1000" rw "$PORTCULLIS_HELPER_IMAGE")" || return 1
    kube_ctl -n "$(kube_ns)" exec "$pod" -- find /vol -mindepth 1 -maxdepth 1 -exec rm -rf {} + || { _kube_helper_done "$pod"; return 1; }
    _kube_helper_done "$pod"
  done
}

# ── Vault's join listener TLS (plan Task 25, review M1) ──

# retry_join posts the raft challenge and its answer to leader_api_addr,
# and the answer carries the raft cluster's TLS keyring (vault v2.2.1
# vault/raft.go joinRaftSendAnswer). So the voters' join listener (:8202,
# vault.hcl.tmpl) is TLS-only, and retry_join trusts exactly this CA
# (leader_ca_cert_file). secrets/vault-join-tls/ (0700, files 0600): a
# private CA made here (EC P-256, 10 years, renewed with a year left; its
# key never leaves this host: _kube_sync_skip) and one server certificate
# for every voter's name (vault-<n>.vault-internal, short and FQDN), valid
# until the CA expires, renewed with 30 days left or when the names
# change; synced as Secret secrets-vault-join-tls (ca.crt, tls.crt,
# tls.key), mounted in the Vault pods only.
KUBE_VAULT_MAX_VOTERS=3
_kube_vault_tls_sans() {
  local i ns; ns="$(kube_ns)"
  for ((i = 0; i < KUBE_VAULT_MAX_VOTERS; i++)); do
    printf 'DNS:vault-%s.vault-internal,DNS:vault-%s.vault-internal.%s.svc,DNS:vault-%s.vault-internal.%s.svc.cluster.local,' "$i" "$i" "$ns" "$i" "$ns"
  done | sed 's/,$//'
}
kube_vault_join_tls_prepare() {
  local d sans days end cnf
  d="$PORTCULLIS_ROOT/secrets/vault-join-tls"
  (umask 077 && mkdir -p "$d")
  chmod 700 "$d"
  sans="$(_kube_vault_tls_sans)"
  cnf="$(mktemp)"
  printf '[ca]\nbasicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash\n[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = Portcullis Vault join CA\n[server]\nbasicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = serverAuth\nsubjectAltName = %s\n' "$sans" > "$cnf"
  if [ ! -s "$d/ca.key" ] || ! openssl x509 -checkend $((365 * 86400)) -noout -in "$d/ca.crt" >/dev/null 2>&1; then
    (umask 077 \
      && openssl ecparam -name prime256v1 -genkey -noout -out "$d/ca.key.new" 2>/dev/null \
      && openssl req -x509 -new -key "$d/ca.key.new" -days 3650 -sha256 -config "$cnf" -extensions ca -out "$d/ca.crt.new" 2>/dev/null) \
      || { rm -f "$cnf" "$d/ca.key.new" "$d/ca.crt.new"; fail "could not create Vault's join CA (openssl)"; }
    mv -f "$d/ca.key.new" "$d/ca.key"; mv -f "$d/ca.crt.new" "$d/ca.crt"
    rm -f "$d/tls.crt"
  fi
  if [ ! -s "$d/tls.key" ] || ! openssl x509 -checkend $((30 * 86400)) -noout -in "$d/tls.crt" >/dev/null 2>&1 \
     || ! openssl verify -CAfile "$d/ca.crt" "$d/tls.crt" >/dev/null 2>&1 || [ "$(cat "$d/sans" 2>/dev/null)" != "$sans" ]; then
    end="$(to_epoch "$(openssl x509 -noout -enddate -in "$d/ca.crt" | cut -d= -f2)")"
    days=$(( (end - $(date +%s)) / 86400 )); [ "$days" -ge 1 ] || days=1
    (umask 077 \
      && openssl ecparam -name prime256v1 -genkey -noout -out "$d/tls.key.new" 2>/dev/null \
      && openssl req -new -key "$d/tls.key.new" -subj "/CN=vault-internal" -out "$d/tls.csr" 2>/dev/null \
      && openssl x509 -req -in "$d/tls.csr" -CA "$d/ca.crt" -CAkey "$d/ca.key" -set_serial "0x$(openssl rand -hex 16)" \
           -days "$days" -sha256 -extfile "$cnf" -extensions server -out "$d/tls.crt.new" 2>/dev/null) \
      || { rm -f "$cnf" "$d/tls.csr" "$d/tls.key.new" "$d/tls.crt.new"; fail "could not create Vault's join certificate (openssl)"; }
    mv -f "$d/tls.key.new" "$d/tls.key"; mv -f "$d/tls.crt.new" "$d/tls.crt"
    (umask 077 && printf '%s' "$sans" > "$d/sans")
  fi
  rm -f "$cnf" "$d/tls.csr"
  chmod 600 "$d"/*
}

# ── fewer Vault voters (HA off; plan Task 25, review M3, fix round 2) ──

# kube_vault_shrink_prepare — before the chart lowers StatefulSet vault's
# replicas (HA off: 3 → 1), the voters it drops leave raft first: `vault
# operator raft remove-peer` through vault-0 (the voter that stays). The
# order keeps a quorum after every step (re-review I-a: hashicorp/raft
# v1.7.3 applies a configuration on append and commits it on a majority of
# the new one, so removing a healthy peer while another is down leaves a
# configuration nobody can commit): the unhealthy ones first (autopilot,
# sys/storage/raft/autopilot/state), then the healthy, highest first; the
# whole plan is checked before any removal, and a step that would leave
# fewer healthy voters than a quorum refuses, naming the down voter(s).
# Then the peers must read back exactly the kept set. Resumable (re-review
# M-a): ConfigMap portcullis-vault-shrink records the dropped voters before
# the first removal; kube_vault_shrink_finish wipes their volumes after the
# chart and deletes it, so an interrupted run (before or after helm) is
# finished by the next `up` with HA off, and HA on refuses while the record
# is there. Anything unreadable or a failed removal refuses (nothing
# deployed). _KUBE_VAULT_SHRINK = the dropped pods, for the finish.
_KUBE_VAULT_SHRINK=""
KUBE_VAULT_SHRINK_CM="portcullis-vault-shrink"
_kube_vault_shrink_record() {
  local out
  if out="$(kube_ctl -n "$(kube_ns)" get configmap "$KUBE_VAULT_SHRINK_CM" -o json 2>&1)"; then
    printf '%s' "$out" | jq -r '.data.dropped // empty'
  else
    case "$out" in *NotFound*|*"not found"*) return 0 ;; esac
    return 1
  fi
}
# _KUBE_VAULT_PLAN_JQ — from autopilot's state (env S), the raft peers (P),
# the voters kept (K) and the seconds since this round began (AGE):
# {plan, bad, unproven}. plan = the peers to drop, the down ones first, then
# highest first; bad = the first step after which the up voters are no
# majority of what is left (failure tolerance below 0), with the ones
# counted down; unproven = voters not yet seen alive this round.
# Up (re-review 2 M-2, checked against Vault v2.2.1): autopilot says
# healthy AND it is the leader, or it echoed since this round began and
# within the heartbeat plus 2 s. last_contact is the leader's
# now − LastHeartbeat (physical/raft/raft_autopilot.go:491), a follower
# echoes every clusterHeartbeatInterval, 5 s by default
# (vault/request_forwarding.go:411): a healthy follower reads 0–5 s (seen
# live: 0.8–4.9 s), and autopilot itself calls a lost one healthy for
# ~14 s. "Since this round began" (last_contact + 3 s ≤ AGE: 1 s for the
# whole-second AGE, 2 s for autopilot's cached state, raft-autopilot's
# DefaultUpdateInterval; re-review 3 M-3) means a voter
# lost before the round can't count up. The Duration.String() forms:
# "0s", "3.1ms", "850µs", "1m2s"; unreadable = down.
_KUBE_VAULT_PLAN_JQ='
  def secs: if type != "string" then null else
      [scan("([0-9]+(?:\\.[0-9]+)?)(ns|us|µs|ms|h|m|s)")] as $p
      | if ($p | length) == 0 then null
        else $p | map((.[0] | tonumber) * ({"ns": 1e-9, "us": 1e-6, "µs": 1e-6, "ms": 1e-3, "s": 1, "m": 60, "h": 3600}[.[1]])) | add end end;
  (env.AGE | tonumber) as $age
  | def up($s): ($s.healthy == true) and ($s.status == "leader"
      or (($s.last_contact | secs) as $d | $d != null and $d < 7 and $d + 3 <= $age));
  def maybe($s): ($s.healthy == true) and ($s.status != "leader")
      and (($s.last_contact | secs) as $d | $d != null and $d < 7 and $d + 3 > $age);
  (env.S | fromjson | .data.servers) as $st
  | (env.P | split(" ") | map(select(. != ""))) as $peers
  | (env.K | split(" ") | map(select(. != ""))) as $keep
  | ($peers | map(select(. as $p | $keep | index($p) | not))
     | sort_by([(. as $p | up($st[$p] // {})), (ltrimstr("vault-") | tonumber | -.)])) as $plan
  | (reduce $plan[] as $x ({cfg: $peers, bad: null};
      if .bad != null then . else
        (.cfg - [$x]) as $c | ($c | map(select(. as $p | up($st[$p] // {})))) as $h
        | {cfg: $c, bad: (if ($h | length) < (($c | length) / 2 | floor) + 1 then {step: $x, down: ($c - $h)} else null end)}
      end)) as $r
  | {plan: $plan, bad: $r.bad, unproven: ($peers | map(select(. as $p | maybe($st[$p] // {}))))}'
# Seconds since <epoch> (a function: the tests set the clock).
_kube_vault_age() { echo $(( $(date +%s) - $1 )); }

# _kube_vault_shrink_read <keep> — through vault-0: the raft peers and
# autopilot's state, re-read each second until every voter is seen alive
# this round or KUBE_VAULT_PROVE_WAIT (9 s: the 5 s heartbeat, the 2 s
# cache, 2 s slack) has passed,
# then the plan (_KVS_PLAN, _KVS_BAD_STEP, _KVS_DOWN); 1 when either can't
# be read; a peer this chart doesn't know fails.
_kube_vault_shrink_read() {
  local peers state out id t0 age
  t0="$(date +%s)"
  while :; do
    _KVS_PLAN=""; _KVS_BAD_STEP=""; _KVS_DOWN=""; _KVS_WHY=""
    peers="$(vexec operator raft list-peers -format=json 2>/dev/null | jq -r '.data.config.servers[].node_id' 2>/dev/null)" \
      && [ -n "$peers" ] || { _KVS_WHY="can't read Vault's raft peers"; return 1; }
    for id in $peers; do
      [[ "$id" =~ ^vault-[0-9]+$ ]] || fail "Vault's raft has a peer $id that isn't a voter of this chart: refusing to lower its voters (nothing deployed)"
    done
    state="$(vexec read -format=json sys/storage/raft/autopilot/state 2>/dev/null)" \
      && printf '%s' "$state" | jq -e '.data.servers | type == "object"' >/dev/null 2>&1 \
      || { _KVS_WHY="can't read Vault's autopilot state (which voters are healthy)"; return 1; }
    age="$(_kube_vault_age "$t0")"
    # shellcheck disable=SC2086  # one id per word
    out="$(S="$state" P="$(printf '%s ' $peers)" K="$1" AGE="$age" jq -nc "$_KUBE_VAULT_PLAN_JQ" 2>/dev/null)" \
      || { _KVS_WHY="can't plan from Vault's autopilot state"; return 1; }
    [ "$(printf '%s' "$out" | jq '.unproven | length')" != 0 ] && [ "$age" -lt "${KUBE_VAULT_PROVE_WAIT:-9}" ] || break
    sleep 1
  done
  _KVS_PLAN="$(printf '%s' "$out" | jq -r '.plan | join(" ")')"
  _KVS_BAD_STEP="$(printf '%s' "$out" | jq -r '.bad.step // empty')"
  _KVS_DOWN="$(printf '%s' "$out" | jq -r '(.bad.down // []) | join(" ")')"
}

kube_vault_shrink_prepare() {
  local cur want id keep i rec first=1 limit removed=0 since=""
  _KUBE_VAULT_SHRINK=""
  cur="$(kube_ctl -n "$(kube_ns)" get statefulset vault -o jsonpath='{.spec.replicas}' 2>/dev/null)" || cur=""
  [[ "$cur" =~ ^[0-9]+$ ]] || return 0        # no Vault yet (a first install)
  want="$(_rtk_replicas vault)"
  rec="$(_kube_vault_shrink_record)" || fail "can't read ConfigMap $KUBE_VAULT_SHRINK_CM (an unfinished HA off of Vault?): refusing (nothing deployed)"
  if [ -n "$rec" ]; then
    # Every voter the record drops must stay dropped (re-review 2 M-1: an
    # HA off interrupted before the chart, then HA on, would run removed
    # voters again).
    for id in $rec; do
      [[ "$id" =~ ^vault-([0-9]+)$ ]] && [ "${BASH_REMATCH[1]}" -ge "$want" ] \
        || fail "Vault's HA off isn't finished: the volumes of $rec are still to be wiped. Run ./portcullis up with HA off first, then turn HA on (nothing deployed)"
    done
    _KUBE_VAULT_SHRINK=" $rec"
  fi
  [ "$cur" -gt "$want" ] || return 0
  vault_admin_env >/dev/null 2>&1 || fail "lowering Vault's voters ($cur → $want) needs its root token (secrets/vault-init.json): refusing (nothing deployed)"
  # Through vault-0, the voter that stays (a standby forwards to the
  # leader; a removed peer's own API would answer no more).
  _K_VAULT_POD=vault-0
  keep=""; for ((i = 0; i < want; i++)); do keep="$keep vault-$i"; done
  limit="${KUBE_VAULT_REMOVE_WAIT:-60}"
  # One removal at a time, each on a fresh read of the peers and of
  # autopilot (re-review 2 M-2): the order and the quorum check follow what
  # Vault says right before it. Before the first removal anything wrong
  # refuses at once (nothing removed); after one, a leader removed or an
  # election makes the reads fail or the health lag a moment: retried up
  # to KUBE_VAULT_REMOVE_WAIT, then refused, the record kept.
  while :; do
    if ! _kube_vault_shrink_read "$keep" || [ -n "$_KVS_BAD_STEP" ]; then
      if [ "$first" = 1 ]; then
        [ -z "$_KVS_WHY" ] || fail "$_KVS_WHY: refusing to lower its voters $cur → $want (nothing deployed)"
        fail "lowering Vault's voters $cur → $want would leave no quorum after removing $_KVS_BAD_STEP (down: ${_KVS_DOWN:-?}), its failure tolerance below 0: bring ${_KVS_DOWN:-the down voter} back first; nothing removed, nothing deployed"
      fi
      # Real seconds since this step's first failed read (re-review 3 N-e:
      # each read itself can take up to KUBE_VAULT_PROVE_WAIT).
      [ -n "$since" ] || since="$(date +%s)"
      [ $(( $(date +%s) - since )) -lt "$limit" ] || fail "Vault's HA off stopped part way: ${_KVS_WHY:-removing $_KVS_BAD_STEP would leave no quorum (down: ${_KVS_DOWN:-?})} for $limit s. Vault keeps its quorum; nothing more removed, nothing deployed — run ./portcullis up again once ${_KVS_DOWN:-every voter} is back"
      sleep 2; continue
    fi
    if [ "$first" = 1 ]; then
      # The record first, even with nothing to remove (re-review 3 N-f: the
      # dropped replicas' PVCs are wiped all the same): an interruption
      # anywhere after this still owes the wipe.
      rec=""; for ((i = cur - 1; i >= want; i--)); do rec="$rec vault-$i"; done
      N="$KUBE_VAULT_SHRINK_CM" NS="$(kube_ns)" D="${rec# }" jq -n '{apiVersion: "v1", kind: "ConfigMap",
          metadata: {name: env.N, namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis"}}, data: {dropped: env.D}}' \
        | kube_ctl apply -f - >/dev/null \
        || fail "could not record the voters being dropped (ConfigMap $KUBE_VAULT_SHRINK_CM): nothing removed, nothing deployed"
      first=0
    fi
    [ -n "$_KVS_PLAN" ] || break
    id="${_KVS_PLAN%% *}"
    removed=$((removed + 1))
    [ "$removed" -le "$cur" ] || fail "Vault's raft still lists $_KVS_PLAN after $cur removals: refusing to lower its voters (nothing deployed; run ./portcullis up again)"
    info "Vault: removing raft peer $id (voters $cur → $want)..."
    vexec operator raft remove-peer "$id" >/dev/null 2>&1 || fail "could not remove Vault's raft peer $id: refusing to lower its voters (nothing deployed; run ./portcullis up again to resume)"
    since=""
  done
  # A removed leader steps down: the kept voters elect again before the
  # configuration reads back (found live: ~10 s). ≤ KUBE_VAULT_REMOVE_WAIT.
  local want_set peers
  since="$(date +%s)"
  want_set="$(printf '%s\n' $keep | sort | paste -sd' ' -)"
  while :; do
    peers="$(vexec operator raft list-peers -format=json 2>/dev/null | jq -r '[.data.config.servers[].node_id] | sort | join(" ")' 2>/dev/null)" || peers=""
    [ "$peers" != "$want_set" ] || break
    [ $(( $(date +%s) - since )) -lt "$limit" ] \
      || fail "Vault's raft peers are '$peers' $limit s after the removals, not '$want_set': refusing to lower its voters (nothing deployed)"
    sleep 2
  done
  _KUBE_VAULT_SHRINK="$rec"
}

# _kube_exists <kind> <name> — 0 it is there, 1 NotFound, 2 anything else
# (the API unreadable: the caller can't tell).
_kube_exists() {
  local out
  out="$(kube_ctl -n "$(kube_ns)" get "$1" "$2" -o name 2>&1)" && return 0
  case "$out" in *NotFound*|*"not found"*) return 1 ;; esac
  return 2
}

# kube_vault_shrink_finish — after the chart dropped them: each removed
# voter's PVC emptied once its pod is gone (its raft data names a cluster
# it left; a later HA on starts it fresh, and it joins by retry_join), then
# the record deleted.
kube_vault_shrink_finish() {
  local id pod rc
  [ -n "${_KUBE_VAULT_SHRINK// /}" ] || return 0
  for id in $_KUBE_VAULT_SHRINK; do
    kube_ctl -n "$(kube_ns)" wait --for=delete "pod/$id" --timeout=180s >/dev/null 2>&1 || true
    # Only NotFound counts as gone (re-review 2 N-a): an unreadable API
    # keeps the record, the wipe still owed.
    rc=0; _kube_exists pod "$id" || rc=$?
    case "$rc" in
      0) fail "the dropped voter $id still runs: its volume isn't wiped (run ./portcullis up again)" ;;
      2) fail "can't tell whether the dropped voter $id still runs: its volume isn't wiped (run ./portcullis up again)" ;;
    esac
    rc=0; _kube_exists pvc "data-$id" || rc=$?
    case "$rc" in
      1) continue ;;
      2) fail "can't read PVC data-$id: the removed voter's raft data is still to be wiped (run ./portcullis up again)" ;;
    esac
    pod="$(_kube_helper_pod "data-$id" "100:1000" rw "$PORTCULLIS_HELPER_IMAGE")" || fail "could not empty data-$id (the removed voter's raft data; run ./portcullis up again)"
    kube_ctl -n "$(kube_ns)" exec "$pod" -- find /vol -mindepth 1 -maxdepth 1 -exec rm -rf {} + || { _kube_helper_done "$pod"; fail "could not empty data-$id"; }
    _kube_helper_done "$pod"
  done
  kube_ctl -n "$(kube_ns)" delete configmap "$KUBE_VAULT_SHRINK_CM" --ignore-not-found >/dev/null || fail "could not delete ConfigMap $KUBE_VAULT_SHRINK_CM (the wipe is done)"
  _KUBE_VAULT_SHRINK=""
}

# ── cluster DNS in HA (plan Task 25, controller ruling 3; fix round 2) ──

# ha_coredns — k3s's packaged CoreDNS is one replica: losing its node
# stopped all cluster DNS (~6 min measured), and with a replica on a lost
# node half the lookups still went there until its endpoint left, holding
# Valkey's Sentinels in TILT (~100 s instead of ~9 s). In HA, one CoreDNS
# on every node (at the primary site and at every other), and each pod
# asks its own node's:
#   - k3s's Deployment coredns: one replica per non-small node at main
#     (never more than those nodes: a required hostname anti-affinity, so
#     a replica that can't be placed would stay Pending — re-review N-1),
#     required at main, one per node (k3s's own spread is judged only at
#     scheduling: a rollout left two on one node);
#   - kube/ha/coredns/small.yaml: our restricted DaemonSet (its own
#     read-only ServiceAccount portcullis-dns, Task 28 fix round 1) of the same
#     CoreDNS on each small node at main and on every node at another
#     site (Task 28: an edge pod resolves on its own node, never across
#     sites), and the PDB coredns (both sets);
#   - Service kube-dns: trafficDistribution PreferSameNode (a lost node
#     answers no other node's pods; kube-proxy falls back cluster-wide only
#     when a node's own endpoint is not ready — a hung but ready one fails
#     that node's lookups until its readiness probe trips, ~6 s).
# What survives k3s (its pinned source): pkg/deploy/controller.go forces a
# re-apply of manifests/coredns.yaml at every k3s start (listFiles(force),
# :98-101, :164-167) through wrangler's three-way apply, which keeps the
# fields its manifest doesn't set (replicas, affinity, the Service's
# trafficDistribution) but replaces those it does (the tolerations list) —
# hence our own DaemonSet for the small nodes. Re-applied by every `up`;
# ha_coredns_revert undoes it all with HA off (re-review N-3).
KUBE_COREDNS_FILE="kube/ha/coredns/small.yaml"
ha_coredns() {
  local n patch
  n="$(kube_ctl get nodes -l "portcullis.io/site=$KUBE_PRIMARY_SITE,portcullis.io/class!=small" -o json 2>/dev/null | jq -r '.items | length' 2>/dev/null)" || n=""
  [[ "$n" =~ ^[0-9]+$ ]] || fail "can't count the nodes at $KUBE_PRIMARY_SITE for CoreDNS (nothing deployed)"
  [ "$n" -ge 1 ] || n=1
  kube_ctl -n kube-system get deployment coredns -o name >/dev/null 2>&1 || fail "no Deployment kube-system/coredns (k3s's packaged CoreDNS): HA needs it (nothing deployed)"
  patch="$(N="$n" SITE="$KUBE_PRIMARY_SITE" jq -cn '{spec: {replicas: (env.N | tonumber), template: {spec: {
      affinity: {nodeAffinity: {requiredDuringSchedulingIgnoredDuringExecution: {nodeSelectorTerms: [{matchExpressions: [{key: "portcullis.io/site", operator: "In", values: [env.SITE]}]}]}},
        podAntiAffinity: {requiredDuringSchedulingIgnoredDuringExecution: [{topologyKey: "kubernetes.io/hostname", labelSelector: {matchLabels: {"k8s-app": "kube-dns"}}}]}}}}}}')"
  kube_ctl -n kube-system patch deployment coredns --type=merge -p "$patch" >/dev/null || fail "could not spread CoreDNS over $KUBE_PRIMARY_SITE (nothing deployed)"
  _ha_apply < "$PORTCULLIS_HOME/$KUBE_COREDNS_FILE" || fail "could not apply CoreDNS on the small nodes / its PodDisruptionBudget ($KUBE_COREDNS_FILE; nothing deployed)"
  kube_ctl -n kube-system patch service kube-dns --type=merge -p '{"spec": {"trafficDistribution": "PreferSameNode"}}' >/dev/null \
    || fail "could not set kube-dns's trafficDistribution PreferSameNode (nothing deployed)"
  _kube_applied_set ha.coredns "$n"
}

# ha_coredns_revert — HA off: k3s's CoreDNS as k3s ships it (one replica,
# no affinity), no PreferSameNode, our DaemonSet and PDB gone. Only when
# the HA layout is there (our DaemonSet, or the Service's setting).
ha_coredns_revert() {
  local td
  td="$(kube_ctl -n kube-system get service kube-dns -o jsonpath='{.spec.trafficDistribution}' 2>/dev/null)" || td=""
  [ "$(kube_ctl -n kube-system get daemonset portcullis-dns-small -o name 2>/dev/null)" = daemonset.apps/portcullis-dns-small ] || [ "$td" = PreferSameNode ] || return 0
  info "HA off: CoreDNS back to k3s's layout..."
  kube_ctl -n kube-system patch deployment coredns --type=merge -p '{"spec": {"replicas": 1, "template": {"spec": {"affinity": null}}}}' >/dev/null \
    && kube_ctl -n kube-system patch service kube-dns --type=merge -p '{"spec": {"trafficDistribution": null}}' >/dev/null \
    && kube_ctl -n kube-system delete daemonset portcullis-dns-small --ignore-not-found >/dev/null \
    && kube_ctl -n kube-system delete poddisruptionbudget coredns --ignore-not-found >/dev/null \
    && kube_ctl -n kube-system delete serviceaccount portcullis-dns --ignore-not-found >/dev/null \
    && kube_ctl delete clusterrolebinding portcullis-dns --ignore-not-found >/dev/null \
    && kube_ctl delete clusterrole portcullis-dns --ignore-not-found >/dev/null \
    || fail "could not put CoreDNS back to k3s's layout (HA off)"
}

# ── the front door's Secrets in a core backup (HA; Task 29 fix round 1, I2) ──
# frontdoor-acme (its ACME accounts, one per CA) and frontdoor-cert (the
# main domain's certificate) live only in the cluster: a fresh cluster
# without them serves no main certificate and holds no account the live
# CAA pins. The backup keeps them as frontdoor.age, age-encrypted to the
# domains service's own key (secrets/domains/age.key, like store.age), by a
# domains-image helper pod (no PVC, no network label): the Secrets' data
# never touches the disk in clear, and never argv.

# _kube_domains_recipient — the age public key of secrets/domains/age.key.
_kube_domains_recipient() {
  sed -n 's/^# public key: \(age1[0-9a-z]*\)$/\1/p' "$PORTCULLIS_ROOT/secrets/domains/age.key" 2>/dev/null | head -n1
}

# _kube_backup_frontdoor <work> — <work>/frontdoor.age (HA with the
# Secrets only; fails closed when they exist but can't be sealed).
_kube_backup_frontdoor() {
  local work="$1" ns pod rcpt rc=0
  kube_ha_on || return 0
  ns="$(kube_ns)"
  # Skipped only when neither exists (NotFound for both); any other
  # answer (an API error, a timeout, one of the two missing) fails closed
  # (fix round 2, R-M1).
  local found
  found="$(kube_ctl -n "$ns" get secret frontdoor-acme frontdoor-cert -o name --ignore-not-found)" \
    || { echo "could not read the front door's Secrets (frontdoor-acme, frontdoor-cert)" >&2; return 1; }
  [ -n "$found" ] || return 0
  [ "$(printf '%s\n' "$found" | grep -c .)" = 2 ] || { echo "only one of the front door's Secrets exists ($found): refusing an incomplete backup" >&2; return 1; }
  rcpt="$(_kube_domains_recipient)"
  [ -n "$rcpt" ] || { echo "secrets/domains/age.key has no public key line: the front door's Secrets can't be sealed" >&2; return 1; }
  pod="$(_kube_helper_pod "" "$CT_UID_DOMAINS:$CT_UID_DOMAINS" ro "$(_kube_image_of domains)" frontdoor-seal)" || return 1
  kube_ctl -n "$ns" get secret frontdoor-acme frontdoor-cert -o json \
    | jq -c '{v: 1, secrets: [.items[] | {name: .metadata.name, data: (.data // {})}]}' \
    | kube_ctl -n "$ns" exec -i "$pod" -- domains seal "$rcpt" > "$work/frontdoor.age" || rc=$?
  _kube_helper_done "$pod"
  [ "$rc" -eq 0 ] && grep -q '^-----BEGIN AGE ENCRYPTED FILE-----' "$work/frontdoor.age" || { rm -f "$work/frontdoor.age"; return 1; }
}

# _kube_restore_frontdoor <dir> — frontdoor.age back into the two Secrets
# (after the release created them): each one's data replaced from the
# unsealed document (the identity on the helper's stdin, never argv).
_kube_restore_frontdoor() {
  local dir="$1" ns pod name rc=0
  [ -f "$dir/frontdoor.age" ] || return 0
  kube_ha_on || { warn "the backup holds the front door's Secrets (HA) but this install isn't HA: not restored"; return 0; }
  ns="$(kube_ns)"
  pod="$(_kube_helper_pod "" "$CT_UID_DOMAINS:$CT_UID_DOMAINS" ro "$(_kube_image_of domains)" frontdoor-seal)" || return 1
  for name in frontdoor-acme frontdoor-cert; do
    { cat "$PORTCULLIS_ROOT/secrets/domains/age.key"; printf '\n'; cat "$dir/frontdoor.age"; } \
      | kube_ctl -n "$ns" exec -i "$pod" -- domains unseal \
      | N="$name" jq -c '{data: ([.secrets[] | select(.name == env.N)][0].data // error("no \(env.N) in frontdoor.age"))}' \
      | kube_ctl -n "$ns" patch secret "$name" --type=merge --patch-file=/dev/stdin >/dev/null || { rc=1; break; }
  done
  _kube_helper_done "$pod"
  [ "$rc" -eq 0 ] || return 1
  ok "The front door's ACME accounts and certificate restored (frontdoor-acme, frontdoor-cert)."
}

# kube_frontdoor_backup_step <work> / kube_frontdoor_restore_step <dir> —
# the backup's and the restore's front-door step (kube.sh calls them).
kube_frontdoor_backup_step() {
  kube_ha_on || return 0
  printf '  %-26s' "front door (age)"
  _kube_backup_frontdoor "$1" || fail "could not back up the front door's Secrets (frontdoor-acme, frontdoor-cert)"
  printf ' %sdone%s\n' "$C_GREEN" "$C_NC"
}
kube_frontdoor_restore_step() {
  _kube_restore_frontdoor "$1" || fail "could not restore the front door's Secrets (frontdoor-acme, frontdoor-cert) from $1/frontdoor.age: the main domain has no certificate until they are (secrets/domains/age.key from another install?). Everything else is restored; run the same ./portcullis restore again once the key matches (the front-door step is its last)"
}

# ── ./portcullis ha status | enable (plan Task 31, D5) ────
#
# `ha enable` turns a Kubernetes install's single-node shape into HA as one
# resumable operation; `ha status` shows where it is and the Hub's HA page
# (`hub ha checklist`, its CLI twin: the checklist, quorum, nodes,
# guarantee). Docker and Podman never change (§20: "high availability needs
# Kubernetes"); there is no `ha disable` (R4: backup → init → restore).
#
# The steps, each recorded in secrets/kube/ha-enable.json (0600, written
# atomically) only after it succeeded, so a re-run (after a refusal, a
# failure, Stop / SIGINT, a CLI crash or a node lost) starts at the first
# step not recorded and never repeats a recorded one:
#    1 checklist  the Hub's checklist all green (N−1 only shown: the
#                 single-node shape is never N−1 green; step 10 gates it),
#                 and the CLI's own: an
#                 automated DNS provider for the main domain with its
#                 credentials (the front door writes its addresses and
#                 orders its certificate), no unfinished Vault HA off; any
#                 red item refuses, naming each, before anything is written;
#    2 confirm    one confirmation naming the sign-in downtime, that HA is
#                 experimental and the CAA wait (--yes: none);
#    3 installs   external-snapshotter, Longhorn, fencing (Self Node
#                 Remediation, every node's agent ready or it stops), then
#                 cert-manager and the barman-cloud plugin (Task 26 M5:
#                 before Postgres scales out, so its replicas archive), and
#                 a release with HA off so the one-instance Cluster adopts
#                 the plugin (WAL archiving healthy before the switch);
#    4 volumes    the writers (Hub, domains, wg) scaled to 0 and gone, then
#                 hub-state, hub-secrets, hub-backups, domains-data and
#                 wg-data each copied into <name>-r on the replicated tier
#                 (owner-uid helper pods, pod to pod), the two sides'
#                 manifests (paths, types, modes, owners, sha256) equal; the
#                 writers stay at 0 (never two writers, never the old and
#                 the new volume attached to a running writer);
#    5 switch     the front door's DNS credentials (Secret frontdoor-env)
#                 and the main domain's current certificate (Traefik's, from
#                 acme.json) as the front door's served pair (frontdoor-cert),
#                 so the HA ingress serves the same certificate from its
#                 first second until the account switch orders the front
#                 door's own (Task 29: in HA no other certificate is served);
#                 the copies checked again; PORTCULLIS_HA=on in .env; `up`
#                 (the chart in HA: the gates ×N, Keycloak ×2/3, Vault ×3,
#                 Postgres ×2/3, Sentinel + replica, Traefik as a DaemonSet
#                 on the ingress nodes, the front door);
#    6 postgres   CloudNativePG's instances ready and a synchronous standby
#                 streaming;
#    7 vault      raft lists 3 voters;
#    8 sessions   two Valkey pods, three Sentinels agreeing on the master
#                 with its replica;
#    9 frontdoor  the CAA account switch to the front door's ACME account
#                 (dns_flip_main_account: relax, settle, order, re-pin; not
#                 settled yet = run it again later), then the old Traefik's
#                 traefik-acme volume deleted;
#   10 status     `ha status` all green.
# Deviation from the plan's order (5–7 before 8): the chart renders Vault's
# peers, the Sentinel StatefulSet and Postgres' HA placement only from
# ha.enabled, so they scale out with the switch and steps 6–8 wait for them.

HA_ENABLE_STEPS="checklist confirm installs volumes switch postgres vault sessions frontdoor status"
# The core volumes on the replicated tier in HA (contract §20.1 "Core
# volumes", the chart's portcullis.pvcName): <pvc>:<uid>:<gid>.
HA_ENABLE_VOLUMES="hub-state:$CT_UID_HUB:$CT_UID_HUB hub-secrets:$CT_UID_HUB:$CT_UID_HUB hub-backups:$CT_UID_HUB:$CT_UID_HUB domains-data:$CT_UID_DOMAINS:$CT_UID_DOMAINS wg-data:$CT_UID_WG:$CT_UID_HUB"
# Their writers (Deployments), stopped for the copy.
HA_ENABLE_WRITERS="hub domains wg"
HA_TEXT_NEEDS_KUBE="high availability needs Kubernetes"

_ha_enable_file() { echo "$(kube_dir)/ha-enable.json"; }

# _ha_enable_done <step> — the record lists it.
_ha_enable_done() {
  jq -e --arg s "$1" 'any(.done[]?; .step == $s)' "$(_ha_enable_file)" >/dev/null 2>&1
}

# _ha_enable_next — the first step not recorded (nothing: all done).
_ha_enable_next() {
  local s
  for s in $HA_ENABLE_STEPS; do _ha_enable_done "$s" || { echo "$s"; return 0; }; done
}

# _ha_step_n <step> — its number (1–10).
_ha_step_n() {
  local s n=0
  for s in $HA_ENABLE_STEPS; do n=$((n + 1)); [ "$s" != "$1" ] || { echo "$n"; return 0; }; done
  echo 0
}

# _ha_enable_record <step> — the step appended to the record, atomically
# (a temp file in the same 0700 directory, then rename): an interruption
# leaves the previous record whole.
_ha_enable_record() {
  local f d tmp old='{"v":1,"done":[]}'
  f="$(_ha_enable_file)"; d="$(dirname "$f")"
  (umask 077 && mkdir -p "$d")
  [ ! -s "$f" ] || old="$(cat "$f")"
  tmp="$(umask 077 && mktemp "$d/.ha-enable.XXXXXX")" || fail "could not write $f"
  if ! printf '%s' "$old" | S="$1" N="$(_ha_step_n "$1")" AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
       jq '.v = 1 | .done = ((.done // []) + [{step: env.S, n: (env.N | tonumber), at: env.AT}])' > "$tmp" \
     || ! mv -f "$tmp" "$f"; then
    rm -f "$tmp"; fail "could not record step $1 in $f"
  fi
}

# _ha_hub_view — _HA_VIEW = the Hub's HA view (`hub ha checklist` in the
# writer Hub pod); exit 1 with _HA_VIEW empty and the reason in _HA_ERR.
# Call it in the caller's shell (not in a $(…)): it sets both.
_ha_hub_view() {
  local errf rc=0
  _HA_VIEW="" _HA_ERR=""
  errf="$(mktemp)"
  _HA_VIEW="$(kube_ctl -n "$(kube_ns)" exec "$(_node_hub_ref)" -c hub -- hub ha checklist </dev/null 2>"$errf")" || rc=$?
  _HA_ERR="$(grep -v '^command terminated with exit code' "$errf" | tr '\n' ' ' | sed 's/ *$//' | cut -c1-300)"
  rm -f "$errf"
  if [ "$rc" != 0 ] || ! printf '%s' "$_HA_VIEW" | jq -e 'type == "object" and (.checklist | type == "array")' >/dev/null 2>&1; then
    [ -n "$_HA_ERR" ] || _HA_ERR="the Hub's answer isn't its HA view"
    _HA_VIEW=""
    return 1
  fi
  _HA_ERR=""
}

# _ha_cli_items — the CLI's own checklist items (JSON array of {id, ok,
# text}): the main domain's DNS provider automated with its credentials
# (the front door's), no unfinished Vault HA off.
_ha_cli_items() {
  local p="${DNS_PROVIDER:-none}" dns=true dtext="" vs=true vtext="" rec
  if ! _dns_automated "$p" || ! _dns_creds_present "$p"; then
    dns=false dtext="the main domain's DNS provider (DNS_PROVIDER=$p) must be automated with its credentials in .env: in HA the front door moves the main domain's addresses and orders its certificate"
  fi
  if ! rec="$(_kube_vault_shrink_record)"; then vs=false vtext="can't read ConfigMap $KUBE_VAULT_SHRINK_CM"
  elif [ -n "$rec" ]; then vs=false vtext="Vault's HA off isn't finished (ConfigMap $KUBE_VAULT_SHRINK_CM): run ./portcullis up first"; fi
  jq -nc --argjson d "$dns" --arg dt "$dtext" --argjson v "$vs" --arg vt "$vtext" \
    '[{id: "dns_provider", ok: $d, text: $dt}, {id: "vault_shrink", ok: $v, text: $vt}]'
}

HA_ITEM_LABELS='{"nodes":"3 or more nodes","servers":"3 or more servers","storage":"Storage nodes","ingress":"Ingress nodes",
  "backup_destination":"Offsite backup destination","n_minus_1":"N−1 check","watchdog":"Watchdogs (fencing)",
  "site_gateway":"A reachable node at every site","site_rtt":"Servers within 100 ms of each other",
  "dns_provider":"The main domain'"'"'s DNS provider","vault_shrink":"No unfinished Vault HA off"}'

# _ha_checklist_lines <items JSON> — one line per item.
_ha_checklist_lines() {
  printf '%s' "$1" | jq -r --argjson l "$HA_ITEM_LABELS" '.[] | (if .ok then "  ok       " else "  not yet  " end) + ($l[.id] // .id) + (if .ok then "" else ": " + .text end)'
}

# ha_enable_step_checklist — step 1. Refuses (exit 1) naming every red
# item; reads only.
ha_enable_step_checklist() {
  local items red
  _ha_hub_view || fail "can't read the Hub's HA checklist (${_HA_ERR}): nothing changed. Is the Hub running? (./portcullis status)"
  items="$(jq -c --argjson cli "$(_ha_cli_items)" '.checklist + $cli' <<<"$_HA_VIEW")"
  # N−1 (found live): the single-node shape is never N−1 green — Vault has
  # one voter (nodeadm counts its minimum as 2), the node-local pods have
  # nowhere to go — and the HA shape doesn't exist yet to be judged. So
  # before the switch it is shown, not gated; step 10 refuses to finish
  # until it is green in HA.
  if ! kube_ha_on && jq -e 'any(.[]; .id == "n_minus_1" and .ok != true)' <<<"$items" >/dev/null; then
    warn "N−1 isn't green yet ($(jq -r '.[] | select(.id == "n_minus_1") | .text' <<<"$items")): the single-node shape can't be; ha enable's last step (10) requires it green once HA runs."
    items="$(jq -c 'map(select(.id != "n_minus_1"))' <<<"$items")"
  fi
  red="$(jq -r '[.[] | select(.ok != true)] | length' <<<"$items")"
  if [ "$red" != 0 ]; then
    warn "High availability can't be turned on yet:"
    _ha_checklist_lines "$(jq -c '[.[] | select(.ok != true)]' <<<"$items")" >&2
    fail "$red checklist item(s) not green: nothing changed. Fix them (the Hub's Settings → High availability shows the same list), then run ./portcullis ha enable again"
  fi
  ok "The HA checklist is green."
}

# ha_enable_step_confirm <yes> — step 2: one confirmation (or --yes).
ha_enable_step_confirm() {
  cat >&2 <<EOC
Turning high availability on — EXPERIMENTAL. This:
  - installs Longhorn, fencing (Self Node Remediation), the snapshot controller,
    cert-manager and CloudNativePG's backup plugin;
  - stops the Hub, the domains service and the VPN service while their volumes are
    copied to the replicated tier (the Hub's pages and new VPN sign-ins are down);
  - moves Traefik to the ingress nodes: SIGN-IN IS DOWN for a few minutes while it
    restarts there (and while Keycloak, Vault and Postgres scale out);
  - switches the main domain's certificate to the front door's own ACME account:
    the CAA record is relaxed to CA-only and the switch WAITS until no cache can hold
    the old pin (its TTL + 1 min, at most 15 min per run; a longer TTL means running
    ./portcullis ha enable again later). The current certificate stays served meanwhile.
There is no ha disable: leaving HA is backup → init → restore.
EOC
  if [ "$1" != true ]; then
    local reply=""
    read -rp 'Type "enable" to turn high availability on: ' reply || reply=""
    [ "$reply" = enable ] || fail "Cancelled: nothing changed."
  fi
}

# ha_enable_step_installs — step 3 (each install fails closed: nothing of
# it installed past its own refusal; a re-run installs again, idempotent).
# It ends with the barman-cloud plugin adopted by the one-instance Cluster
# (fix round 1, I1; found live): a release with HA still off renders the
# Cluster's plugins stanza now, and the step waits for WAL archiving through
# it. Otherwise the switch's release added the plugin and the scale-out
# together: CloudNativePG restarted the primary in place without the
# plugin's sidecar, its smart shutdown waited on the failing archive
# command, Postgres was down ~4 min and helm's --wait timed out.
ha_enable_step_installs() {
  ha_install_snapshotter
  ha_install_longhorn
  ha_install_fencing
  ha_fencing_ready >&2 || fail "fencing isn't ready on every node (above): HA stops here; run ./portcullis ha enable again once it is"
  ha_install_certmanager
  ha_install_barman
  info "Postgres adopts the backup plugin at one instance (./portcullis up, HA still off)..."
  stack_up
  _ha_until "${HA_ARCHIVE_WAIT:-600}" "Postgres didn't archive its WAL through the backup plugin (ContinuousArchiving)" _ha_pg_archiving
  ok "Postgres archives through the backup plugin."
}

# _ha_pg_archiving — the release enabled CloudNativePG's backup
# (backup.cnpg.enabled), the Cluster names the barman-cloud plugin as its
# WAL archiver, every instance is ready and ContinuousArchiving is True.
_ha_pg_archiving() {
  local c
  [ "$(jq -r '.backup.cnpg.enabled // false' "$(kube_values_file)" 2>/dev/null)" = true ] || return 1
  c="$(kube_ctl -n "$KUBE_CNPG_NS" get cluster.postgresql.cnpg.io "$KUBE_PG_CLUSTER" -o json 2>/dev/null)" || return 1
  jq -e 'any(.spec.plugins[]?; .name == "barman-cloud.cloudnative-pg.io" and .isWALArchiver == true)
    and (.status.readyInstances // 0) == .spec.instances
    and any(.status.conditions[]?; .type == "ContinuousArchiving" and .status == "True")' <<<"$c" >/dev/null
}

# _ha_scale_writers — the writers to 0 and their pods gone (each one that
# exists; fail closed on anything unreadable).
_ha_scale_writers() {
  local ns d out
  ns="$(kube_ns)"
  for d in $HA_ENABLE_WRITERS; do
    out="$(kube_ctl -n "$ns" get deployment "$d" -o name 2>&1)" || {
      case "$out" in *NotFound*|*"not found"*) continue ;; esac
      fail "can't read the Deployment $d: nothing copied"
    }
    kube_ctl -n "$ns" scale deployment "$d" --replicas=0 >/dev/null || fail "could not stop $d (scale to 0): nothing copied"
  done
  for d in $HA_ENABLE_WRITERS; do
    kube_ctl -n "$ns" wait --for=delete pod -l "portcullis.io/component=$d" --timeout=180s >/dev/null 2>&1 \
      || [ "$(kube_ctl -n "$ns" get pods -l "portcullis.io/component=$d" -o json 2>/dev/null | jq -r '.items | length' 2>/dev/null)" = 0 ] \
      || fail "$d's pods are still there after 3 min: nothing copied (run ./portcullis ha enable again)"
  done
}

# _ha_writers_stopped — every writer that exists is at 0 replicas with no pod.
_ha_writers_stopped() {
  local ns d r
  ns="$(kube_ns)"
  for d in $HA_ENABLE_WRITERS; do
    r="$(kube_ctl -n "$ns" get deployment "$d" -o jsonpath='{.spec.replicas}' 2>/dev/null)" || continue
    [ "$r" = 0 ] || return 1
    [ "$(kube_ctl -n "$ns" get pods -l "portcullis.io/component=$d" -o json 2>/dev/null | jq -r '.items | length' 2>/dev/null)" = 0 ] || return 1
  done
}

# _ha_replicated_pvc <pvc> — <pvc>-r on portcullis-core-replicated, made
# like <pvc> (its size and the K3 owner annotations, as the chart's
# portcullis.pvc renders it in HA) with Helm's ownership metadata, so the
# release adopts it at the switch (helm v4.3.1 pkg/action/validate.go
# checkOwnership: managed-by Helm, release name and namespace). Kept when
# it is bound; an unbound one (no data: a copy stopped before its volume
# was provisioned, its WaitForFirstConsumer node maybe one without
# Longhorn) is made again.
_ha_replicated_pvc() {
  local src ns phase
  ns="$(kube_ns)"
  if phase="$(kube_ctl -n "$ns" get pvc "$1-r" -o jsonpath='{.status.phase}' 2>/dev/null)"; then
    [ "$phase" != Bound ] || return 0
    kube_ctl -n "$ns" delete pvc "$1-r" --wait=true --timeout=60s >/dev/null || { echo "can't remove the unbound PVC $1-r" >&2; return 1; }
  fi
  src="$(kube_ctl -n "$ns" get pvc "$1" -o json 2>/dev/null)" || { echo "can't read the PVC $1" >&2; return 1; }
  printf '%s' "$src" | N="$1-r" NS="$ns" R="$KUBE_RELEASE" jq '{apiVersion: "v1", kind: "PersistentVolumeClaim",
      metadata: {name: env.N, namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "Helm"},
        annotations: ((.metadata.annotations // {} | with_entries(select(.key | startswith("portcullis.io/"))))
          + {"helm.sh/resource-policy": "keep", "meta.helm.sh/release-name": env.R, "meta.helm.sh/release-namespace": env.NS})},
      spec: {storageClassName: "portcullis-core-replicated", accessModes: ["ReadWriteOnce"],
        resources: {requests: {storage: .spec.resources.requests.storage}}}}' | kube_ctl create -f - >/dev/null
}

# _ha_copy_pod <pvc> <uid> <gid> <ro|rw> — a helper pod (the volume's
# owner, the helper image, no network: _kube_helper_pod's shape) with
# fsGroup <gid> (a fresh Longhorn volume's root is root's: the kubelet
# gives it the group, as it does the chart's pods); its name. A <pvc>-r
# (replicated) one runs where Longhorn does — the primary site's non-small
# nodes, as the chart pins the core pods (found live: a fresh
# WaitForFirstConsumer volume would be provisioned on whatever node the
# pod lands on, a small node has no Longhorn); a local one goes where its
# volume is (the small node too: a Vault voter's).
_ha_copy_pod() {
  local name
  name="ha-copy-$(openssl rand -hex 4)"
  N="$name" NS="$(kube_ns)" P="$1" U="$2" G="$3" RO="$4" IMG="$PORTCULLIS_HELPER_IMAGE" SITE="$KUBE_PRIMARY_SITE" jq -n '
    (env.P | endswith("-r")) as $rep
    | {apiVersion: "v1", kind: "Pod",
     metadata: {name: env.N, namespace: env.NS, labels: {"portcullis.io/component": "volume-helper"}},
     spec: ({restartPolicy: "Never", priorityClassName: "portcullis-core", automountServiceAccountToken: false, enableServiceLinks: false,
       securityContext: {runAsNonRoot: true, runAsUser: (env.U | tonumber), runAsGroup: (env.G | tonumber), fsGroup: (env.G | tonumber),
         fsGroupChangePolicy: "OnRootMismatch", seccompProfile: {type: "RuntimeDefault"}}}
       + (if $rep then {affinity: {nodeAffinity: {requiredDuringSchedulingIgnoredDuringExecution: {nodeSelectorTerms: [{matchExpressions: [
             {key: "portcullis.io/site", operator: "In", values: [env.SITE]}, {key: "portcullis.io/class", operator: "NotIn", values: ["small"]}]}]}}}}
          else {tolerations: [{key: "portcullis.io/small", operator: "Exists", effect: "NoSchedule"}]} end)
       + {
       containers: [{name: "helper", image: env.IMG, command: ["sleep", "3600"],
         resources: {limits: {memory: "256Mi"}, requests: {memory: "256Mi"}},
         securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}},
         volumeMounts: [{name: "tmp", mountPath: "/tmp"}, {name: "vol", mountPath: "/vol", readOnly: (env.RO == "ro")}]}],
       volumes: [{name: "tmp", emptyDir: {medium: "Memory"}}, {name: "vol", persistentVolumeClaim: {claimName: env.P, readOnly: (env.RO == "ro")}}]})}' \
    | kube_ctl create -f - >/dev/null || return 1
  # Recorded for Stop (fix round 1, M1): an interrupted step removes them.
  [ -z "${_HA_HELPERS:-}" ] || printf '%s\n' "$name" >> "$_HA_HELPERS"
  if ! kube_ctl -n "$(kube_ns)" wait --for=condition=Ready "pod/$name" --timeout="${KUBE_POD_WAIT:-300}s" >/dev/null; then
    _kube_pod_diag "$name"; _kube_helper_done "$name"; return 1
  fi
  echo "$name"
}

# _ha_helpers_done — every copy helper this run made, removed (Stop, a
# failure: a deleted one is no harm).
_ha_helpers_done() {
  local n
  [ -n "${_HA_HELPERS:-}" ] && [ -f "$_HA_HELPERS" ] || return 0
  while IFS= read -r n; do
    [[ "$n" =~ ^ha-copy-[0-9a-f]{8}$ ]] && _kube_helper_done "$n"
  done < "$_HA_HELPERS"
  rm -f "$_HA_HELPERS"
}

# The manifest of a volume (in its helper pod): every entry but the root
# and Longhorn's lost+found, sorted — type, mode, owner, a file's sha256,
# a link's target — hashed; exit 3 when anything can't be read. A
# directory counts by its path and permission bits without the setgid bit
# and without its owner (found live): on the replicated volume the
# kubelet's fsGroup makes the root setgid, so every directory made in it
# inherits the bit, and an unprivileged copy owns what it creates (an
# empty root-owned mount point such as hub-state's backups/, which the
# Hub's hub-backups volume covers). Files and links keep their full mode
# and owner.
# shellcheck disable=SC2016  # the pod's own shell
HA_MANIFEST_SH='cd /vol || exit 3
find . -mindepth 1 \( -path ./lost+found -prune \) -o -print | LC_ALL=C sort | while IFS= read -r f; do
  if [ -L "$f" ]; then printf "l %s %s %s\n" "$(stat -c "%u %g" "$f")" "$f" "$(readlink "$f")"
  elif [ -d "$f" ]; then m="$(stat -c %a "$f")"; case "$m" in 2???) m="${m#2}" ;; 3???) m="1${m#3}" ;; 6???) m="4${m#6}" ;; 7???) m="5${m#7}" ;; esac; printf "d %s %s\n" "$m" "$f"
  elif [ -f "$f" ]; then h="$(sha256sum < "$f" | cut -d" " -f1)" || h=UNREADABLE; printf "f %s %s %s\n" "$(stat -c "%a %u %g" "$f")" "${h:-UNREADABLE}" "$f"
  else printf "o %s %s\n" "$(stat -c "%F %a %u %g" "$f")" "$f"; fi
done > /tmp/manifest || exit 3
grep -q UNREADABLE /tmp/manifest && exit 3
sha256sum < /tmp/manifest | cut -d" " -f1'
# The entries to copy (the root's children but lost+found), for tar -T.
HA_LIST_SH='cd /vol && find . -mindepth 1 -maxdepth 1 ! -name lost+found > /tmp/list && cat /tmp/list | wc -l'

# _ha_manifest <pod> — its volume's manifest hash (nothing, exit 1: unreadable).
_ha_manifest() {
  local m
  m="$(kube_ctl -n "$(kube_ns)" exec "$1" -- sh -c "$HA_MANIFEST_SH" 2>/dev/null)" || return 1
  [[ "$m" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$m"
}

# _ha_copy_volume <pvc> <uid> <gid> — <pvc> into <pvc>-r: the target
# emptied (a resumed copy starts over), the source's entries streamed pod
# to pod (tar, as the owner), then both manifests compared. Exit 1 on any
# failure or difference (the source is never written: mounted read-only).
_ha_copy_volume() {
  local pvc="$1" u="$2" g="$3" src dst n ms md rc=0 ns
  ns="$(kube_ns)"
  _ha_replicated_pvc "$pvc" || { warn "could not make the PVC $pvc-r"; return 1; }
  src="$(_ha_copy_pod "$pvc" "$u" "$g" ro)" || { warn "no helper pod on $pvc"; return 1; }
  dst="$(_ha_copy_pod "$pvc-r" "$u" "$g" rw)" || { _kube_helper_done "$src"; warn "no helper pod on $pvc-r"; return 1; }
  kube_ctl -n "$ns" exec "$dst" -- find /vol -mindepth 1 -maxdepth 1 ! -name lost+found -exec rm -rf {} + || rc=1
  if [ "$rc" = 0 ]; then
    n="$(kube_ctl -n "$ns" exec "$src" -- sh -c "$HA_LIST_SH" 2>/dev/null | tr -d ' ')" || rc=1
    if [ "$rc" = 0 ] && [ "${n:-0}" != 0 ]; then
      kube_ctl -n "$ns" exec "$src" -- tar -cf - -C /vol -T /tmp/list \
        | kube_ctl -n "$ns" exec -i "$dst" -- tar -xpf - -C /vol || rc=1
    fi
  fi
  if [ "$rc" = 0 ]; then
    ms="$(_ha_manifest "$src")" && md="$(_ha_manifest "$dst")" && [ "$ms" = "$md" ] || rc=1
    [ "$rc" = 0 ] || warn "$pvc and $pvc-r differ after the copy (or one can't be read: a file not owned by $u?)"
  fi
  _kube_helper_done "$dst"; _kube_helper_done "$src"
  # Both helpers gone before anything mounts either volume again.
  kube_ctl -n "$ns" wait --for=delete "pod/$dst" "pod/$src" --timeout=120s >/dev/null 2>&1 || true
  return "$rc"
}

# _ha_volumes_same — every <pvc> and <pvc>-r still have equal manifests
# (the switch's check: nothing wrote since the copy).
_ha_volumes_same() {
  local spec pvc u g src dst ms md rc=0
  for spec in $HA_ENABLE_VOLUMES; do
    IFS=: read -r pvc u g <<< "$spec"
    kube_ctl -n "$(kube_ns)" get pvc "$pvc-r" -o name >/dev/null 2>&1 || return 1
    src="$(_ha_copy_pod "$pvc" "$u" "$g" ro)" || return 1
    dst="$(_ha_copy_pod "$pvc-r" "$u" "$g" ro)" || { _kube_helper_done "$src"; return 1; }
    ms="$(_ha_manifest "$src")" && md="$(_ha_manifest "$dst")" && [ "$ms" = "$md" ] || rc=1
    _kube_helper_done "$dst"; _kube_helper_done "$src"
    kube_ctl -n "$(kube_ns)" wait --for=delete "pod/$dst" "pod/$src" --timeout=120s >/dev/null 2>&1 || true
    [ "$rc" = 0 ] || return 1
  done
}

# ha_enable_step_volumes — step 4: writers stopped, then each volume
# copied and checked. A failure stops here with the writers still at 0 on
# their old volumes (the copy is redone by the re-run).
ha_enable_step_volumes() {
  local spec pvc u g
  for spec in $HA_ENABLE_VOLUMES; do
    kube_ctl -n "$(kube_ns)" get pvc "${spec%%:*}" -o name >/dev/null 2>&1 || fail "the PVC ${spec%%:*} doesn't exist (or can't be read): nothing copied"
  done
  info "Stopping the Hub, the domains service and the VPN service for the copy..."
  _ha_scale_writers
  for spec in $HA_ENABLE_VOLUMES; do
    IFS=: read -r pvc u g <<< "$spec"
    info "Copying $pvc to $pvc-r (replicated)..."
    _ha_copy_volume "$pvc" "$u" "$g" || fail "the copy of $pvc failed (above): the Hub, domains and wg stay stopped on their old volumes; run ./portcullis ha enable again to redo it"
    ok "$pvc copied, the manifests equal."
  done
}

# ha_frontdoor_env_sync — the Secret frontdoor-env (credentials.json: the
# main domain's provider and its credentials, the dns tool's keys) from
# .env, the front door's alone (contract §20.8). The values reach jq
# through its environment and kubectl on stdin, never argv or a file.
ha_frontdoor_env_sync() {
  local p="${DNS_PROVIDER:-none}" line var key map="[]"
  _dns_automated "$p" && _dns_creds_present "$p" || fail "the front door needs the main domain's DNS credentials: DNS_PROVIDER=$p is not automated or its credentials aren't in .env"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    var="${line%%:*}" key="${line#*:}"
    [ -n "${!var:-}" ] || continue
    export "${var?}"
    map="$(jq -c --arg v "$var" --arg k "$key" '. + [{var: $v, key: $k}]' <<<"$map")"
  done < <(_dns_cred_keys "$p")
  NS="$(kube_ns)" P="$p" jq -n --argjson map "$map" '{apiVersion: "v1", kind: "Secret", type: "Opaque",
      metadata: {name: "frontdoor-env", namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis", "portcullis.io/owner": "core"}},
      data: {"credentials.json": ({provider: env.P, credentials: ($map | map({key: .key, value: env[.var]}) | from_entries)} | tojson | @base64)}}' \
    | _ha_apply || fail "could not write the Secret frontdoor-env (the front door's DNS credentials)"
}

# The served certificate's validity floor at the switch (fix round 1, I2):
# it must outlast the worst case of the account switch (step 9), which
# waits for the old CAA pin to leave every cache — dns_relax_main's
# settle point, at least the 24 h it assumes when the old pin's lifetime
# is unknown, and a saved point further out — plus a 7-day margin for the
# reruns it may need. _ha_cert_floor prints it in seconds.
HA_CERT_MARGIN=$((7 * 86400))
_ha_cert_floor() {
  local now nb wait=$((86400 + 60))
  now="$(date +%s)"
  nb="$(_dns_relax_point 2>/dev/null || true)"
  if [[ "$nb" =~ ^[0-9]+$ ]] && [ $((nb - now)) -gt "$wait" ]; then wait=$((nb - now)); fi
  echo $((wait + HA_CERT_MARGIN))
}

# _ha_cert_ok <pem> <floor seconds> — the leaf names exactly <d> and *.<d>
# (as the domains service's servableHA wants) and is valid for <floor>
# more seconds; else _HA_CERT_WHY says why.
_ha_cert_ok() {
  local pem="$1" floor="$2" d="$PORTCULLIS_DOMAIN" names end
  _HA_CERT_WHY=""
  names="$(printf '%s\n' "$pem" | openssl x509 -noout -text 2>/dev/null | sed -n '/Subject Alternative Name/{n;p;}' | tr ',' '\n' | sed -n 's/^ *DNS://p' | LC_ALL=C sort | paste -sd' ' -)"
  [ -n "$names" ] || { _HA_CERT_WHY="it doesn't parse or names no DNS name"; return 1; }
  [ "$names" = "*.$d $d" ] || { _HA_CERT_WHY="it names $names, not exactly $d and *.$d"; return 1; }
  end="$(printf '%s\n' "$pem" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
  if ! printf '%s\n' "$pem" | openssl x509 -noout -checkend "$floor" >/dev/null 2>&1; then
    _HA_CERT_WHY="it expires $end, under the $((floor / 86400)) days the account switch may need (the CAA settle's worst case + $((HA_CERT_MARGIN / 86400)) days)"
    return 1
  fi
}

# _ha_dynamic_pairs — traefik/dynamic's certificates ("<cert> <key>" host
# paths of certs/, one per line: their certFile / keyFile under /certs).
_ha_dynamic_pairs() {
  cat "$PORTCULLIS_HOME"/traefik/dynamic/*.yml 2>/dev/null | awk '
    /certFile:/ { c = $NF } /keyFile:/ { k = $NF }
    c != "" && k != "" { print c " " k; c = ""; k = "" }' \
  | sed -n 's#^/certs/\([^ /]*\) /certs/\([^ /]*\)$#\1 \2#p' | while read -r c k; do
      printf '%s %s\n' "$PORTCULLIS_ROOT/certs/$c" "$PORTCULLIS_ROOT/certs/$k"
    done
}

# _HA_ACME_SEL — acme.json's certificate of <d> with exactly *.<d> (jq).
# shellcheck disable=SC2016  # jq's own variables
_HA_ACME_SEL='(.letsencrypt.Certificates // []) | map(select(.domain.main == env.D and ((.domain.sans // []) | sort) == ["*." + env.D])) | .[0] // empty'

# _ha_main_cert_plan — step 5's first check, before anything changes (fix
# round 1, I2: fail closed): the certificate the HA ingress serves from the
# switch until the front door orders its own, valid for _ha_cert_floor.
# _HA_CERT_SRC = kept (frontdoor-cert already holds such a pair), acme
# (Traefik's acme.json, seeded) or "dynamic <cert> <key>" (a pair of
# traefik/dynamic, seeded); anything else refuses, naming what each
# source holds and how to fix it.
_ha_main_cert_plan() {
  local ns d="$PORTCULLIS_DOMAIN" floor have pem pod c k why=""
  ns="$(kube_ns)"; floor="$(_ha_cert_floor)"
  _HA_CERT_SRC=""
  have="$(kube_ctl -n "$ns" get secret frontdoor-cert -o json 2>/dev/null | jq -r '.data["tls.crt"] // empty' 2>/dev/null)" || have=""
  if [ -n "$have" ]; then
    pem="$(printf '%s' "$have" | base64 -d 2>/dev/null)" || pem=""
    if _ha_cert_ok "$pem" "$floor"; then _HA_CERT_SRC=kept; return 0; fi
    why="$why
  - frontdoor-cert holds a pair, but $_HA_CERT_WHY"
  fi
  if _kube_volume_exists traefik_acme; then
    pod="$(_kube_helper_pod traefik-acme 65532:65532 ro "$PORTCULLIS_HELPER_IMAGE")" || fail "no helper pod on traefik-acme (Traefik's certificate can't be read): nothing changed"
    pem="$(kube_ctl -n "$ns" exec "$pod" -- cat /vol/acme.json 2>/dev/null | D="$d" jq -r "$_HA_ACME_SEL | .certificate" 2>/dev/null | base64 -d 2>/dev/null)" || pem=""
    _kube_helper_done "$pod"
    if [ -n "$pem" ] && _ha_cert_ok "$pem" "$floor"; then _HA_CERT_SRC=acme; return 0; fi
    if [ -n "$pem" ]; then why="$why
  - Traefik's ACME certificate: $_HA_CERT_WHY"; else why="$why
  - Traefik's acme.json holds no certificate of $d and *.$d"; fi
  else
    why="$why
  - there is no traefik-acme volume (Traefik's ACME storage)"
  fi
  while read -r c k; do
    [ -n "$c" ] || continue
    if [ ! -r "$c" ] || [ ! -r "$k" ]; then why="$why
  - traefik/dynamic names ${c#"$PORTCULLIS_ROOT"/} / ${k#"$PORTCULLIS_ROOT"/}, not both readable here"; continue; fi
    if _ha_cert_ok "$(cat "$c")" "$floor"; then _HA_CERT_SRC="dynamic $c $k"; return 0; fi
    why="$why
  - traefik/dynamic's ${c#"$PORTCULLIS_ROOT"/}: $_HA_CERT_WHY"
  done < <(_ha_dynamic_pairs)
  [ -n "$(_ha_dynamic_pairs)" ] || why="$why
  - traefik/dynamic names no certificate"
  printf 'No certificate of %s can be served from the switch until the front door orders its own:%s\n' "$d" "$why" >&2
  fail "nothing changed. Fix one: let Traefik order or renew its certificate (./portcullis up with the DNS provider working; check ./portcullis status), or put a pair for $d and *.$d valid $((floor / 86400)) more days under certs/ and name it in traefik/dynamic; then run ./portcullis ha enable again"
}

# _ha_frontdoor_cert_seed — before Traefik moves: _ha_main_cert_plan's
# pair as frontdoor-cert's served pair (tls.crt, tls.key, account-uri:
# Traefik's account, empty for a traefik/dynamic pair), with Helm's
# ownership metadata (the chart creates the Secret empty: the release
# adopts it, its data kept). The front door keeps a served pair until its
# own account's slot holds a servable one (domains/frontdoor/cert.go
# Promote), so no other certificate is served before the account switch.
# The key travels on pipes only (acme.json: pod → jq → kubectl; a
# traefik/dynamic key: jq reads the file).
_ha_frontdoor_cert_seed() {
  local ns pod d="$PORTCULLIS_DOMAIN" c k
  ns="$(kube_ns)"
  # shellcheck disable=SC2016  # jq's own variables
  local secret='{apiVersion: "v1", kind: "Secret", type: "Opaque",
           metadata: {name: "frontdoor-cert", namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "Helm"},
             annotations: {"helm.sh/resource-policy": "keep", "meta.helm.sh/release-name": env.R, "meta.helm.sh/release-namespace": env.NS}},
           data: {"tls.crt": $crt, "tls.key": $key, "account-uri": ($uri | @base64)}}'
  case "$_HA_CERT_SRC" in
    kept) info "frontdoor-cert already holds a current certificate of $d: kept."; return 0 ;;
    acme)
      pod="$(_kube_helper_pod traefik-acme 65532:65532 ro "$PORTCULLIS_HELPER_IMAGE")" || fail "no helper pod on traefik-acme: nothing switched"
      kube_ctl -n "$ns" exec "$pod" -- cat /vol/acme.json \
        | D="$d" NS="$ns" R="$KUBE_RELEASE" jq -c "($_HA_ACME_SEL) as \$c | (.letsencrypt.Account.Registration.uri // \"\") as \$uri
            | if \$c == null then error(\"no certificate\") else . end | \$c.certificate as \$crt | \$c.key as \$key | $secret" \
        | _ha_apply || { _kube_helper_done "$pod"; fail "could not carry Traefik's certificate of $d into frontdoor-cert: nothing switched"; }
      _kube_helper_done "$pod" ;;
    dynamic\ *)
      read -r _ c k <<< "$_HA_CERT_SRC"
      NS="$ns" R="$KUBE_RELEASE" jq -nc --rawfile c "$c" --rawfile k "$k" "(\$c | @base64) as \$crt | (\$k | @base64) as \$key | \"\" as \$uri | $secret" \
        | _ha_apply || fail "could not carry traefik/dynamic's certificate of $d into frontdoor-cert: nothing switched" ;;
    *) fail "internal: no certificate plan (_ha_main_cert_plan first)" ;;
  esac
  ok "The certificate of $d Traefik serves now ($_HA_CERT_SRC) is the front door's served one until the account switch."
}

# _ha_writers_on_replicated — a writer's Deployment already mounts a
# <pvc>-r (an earlier switch applied it): its data is the replicated
# copy's now, which must never be copied over again.
_ha_writers_on_replicated() {
  local d
  for d in $HA_ENABLE_WRITERS; do
    kube_ctl -n "$(kube_ns)" get deployment "$d" -o json 2>/dev/null       | jq -e 'any(.spec.template.spec.volumes[]?; (.persistentVolumeClaim.claimName // "") | endswith("-r"))' >/dev/null && return 0
  done
  return 1
}

# HA_MOVED_SERVICES — Traefik's Services that move to the ingress
# namespace in HA (charts/portcullis/templates/services.yaml): traefik and
# traefik-vpn keep their fixed ClusterIPs there, keycloak-internal and
# traefik-metrics stay in the core namespace as ExternalName names.
HA_MOVED_SERVICES="traefik traefik-vpn keycloak-internal traefik-metrics"

# _ha_services_move — right before an HA release (_rtk_up, after the
# images, the sync and the probes, so sign-in stops as late as possible):
# the core namespace's
# old Services of HA_MOVED_SERVICES deleted (found live: the release
# creates traefik in portcullis-ingress at the same fixed ClusterIP, which
# the old one still held — "provided IP is already allocated" — and a
# ClusterIP Service can't become an ExternalName in place). Sign-in stops
# here until the release's Traefik DaemonSet serves (the confirmed
# downtime). An ExternalName one (the release made it) is kept.
_ha_services_move() {
  local ns s t
  ns="$(kube_ns)"
  for s in $HA_MOVED_SERVICES; do
    t="$(kube_ctl -n "$ns" get service "$s" -o jsonpath='{.spec.type}' 2>/dev/null)" || continue
    [ "$t" != ExternalName ] || continue
    kube_ctl -n "$ns" delete service "$s" --wait=true --timeout=60s >/dev/null || fail "could not delete the Service $s in $ns (Traefik's moves to $KUBE_INGRESS_NS): run ./portcullis ha enable again"
  done
}

# ha_enable_step_switch — step 5.
ha_enable_step_switch() {
  _ha_main_cert_plan
  if _ha_writers_on_replicated; then
    info "The core writers already run on the replicated volumes (an earlier switch): no copy again."
  elif ! _ha_writers_stopped || ! _ha_volumes_same; then
    info "Something wrote to the core volumes since the copy (or a writer runs again): copying them again..."
    ha_enable_step_volumes
  fi
  ha_frontdoor_env_sync
  _ha_frontdoor_cert_seed
  env_set PORTCULLIS_HA on
  export PORTCULLIS_HA=on
  info "HA on (PORTCULLIS_HA=on in .env): deploying the HA shape (./portcullis up)..."
  stack_up
}

# _ha_until <seconds> <what> <cmd…> — cmd every 5 s until it passes; fails
# naming what.
_ha_until() {
  local s="$1" what="$2" t0
  shift 2
  t0="$(date +%s)"
  until "$@" >/dev/null 2>&1; do
    [ $(( $(date +%s) - t0 )) -lt "$s" ] || fail "$what within $s s: HA stops here; run ./portcullis ha enable again to wait on"
    sleep "${HA_POLL:-5}"
  done
}

# _ha_pg_synced — the Cluster at its HA instances (min(3, the labelled
# non-small nodes at main)), all ready, and with 2 or more a standby
# streaming synchronously (pg_stat_replication on the primary).
_ha_pg_synced() {
  local want c n
  want="$(kube_pg_nodes_at_primary)" || return 1
  [ "$want" -le 3 ] || want=3; [ "$want" -ge 1 ] || want=1
  c="$(kube_ctl -n "$KUBE_CNPG_NS" get cluster.postgresql.cnpg.io "$KUBE_PG_CLUSTER" -o json 2>/dev/null)" || return 1
  W="$want" jq -e '(.spec.instances | tostring) == env.W and (.status.readyInstances // 0) == .spec.instances' <<<"$c" >/dev/null || return 1
  [ "$want" -ge 2 ] || return 0
  n="$(_kube_pg_exec psql -tAqc "select count(*) from pg_stat_replication where state = 'streaming' and sync_state in ('sync', 'quorum')" 2>/dev/null | tr -d '[:space:]')" || return 1
  [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ]
}
ha_enable_step_postgres() {
  info "Waiting for Postgres' instances and a synchronous standby..."
  _ha_until "${HA_PG_WAIT:-900}" "Postgres didn't reach its HA instances with a synchronous standby" _ha_pg_synced
  ok "Postgres: every instance ready, a synchronous standby streaming."
}

# _ha_vault_voters3 — StatefulSet vault 3/3 ready and raft listing 3 voters.
_ha_vault_voters3() {
  local n
  [ "$(kube_ctl -n "$(kube_ns)" get statefulset vault -o jsonpath='{.status.readyReplicas}' 2>/dev/null)" = 3 ] || return 1
  _K_VAULT_POD=""; kube_vault_pod_set
  n="$(vexec operator raft list-peers -format=json 2>/dev/null | jq -r '[.data.config.servers[] | select(.voter == true)] | length' 2>/dev/null)" || return 1
  [ "$n" = 3 ]
}
ha_enable_step_vault() {
  vault_admin_env >/dev/null || fail "Vault's root token (secrets/vault-init.json) is needed to read its raft peers"
  info "Waiting for Vault's 3 raft voters..."
  _ha_until "${HA_VAULT_WAIT:-600}" "Vault's raft didn't list 3 voters" _ha_vault_voters3
  ok "Vault: 3 raft voters."
}

# _ha_sentinel_ok — 2 Valkey pods and 3 Sentinels ready, and a Sentinel
# sees the master with a replica and the 2 other Sentinels.
_ha_sentinel_ok() {
  local ns out
  ns="$(kube_ns)"
  [ "$(kube_ctl -n "$ns" get statefulset sessions -o jsonpath='{.status.readyReplicas}' 2>/dev/null)" = 2 ] || return 1
  [ "$(kube_ctl -n "$ns" get statefulset sessions-sentinel -o jsonpath='{.status.readyReplicas}' 2>/dev/null)" = 3 ] || return 1
  out="$(kube_ctl -n "$ns" exec sessions-sentinel-0 -- valkey-cli --no-auth-warning -t 2 --user sessions-admin -h 127.0.0.1 -p 26379 \
    SENTINEL master "$KUBE_SESSIONS_MASTER" </dev/null 2>/dev/null)" || return 1
  printf '%s\n' "$out" | awk 'p == "flags" { f = $0 } p == "num-slaves" { s = $0 } p == "num-other-sentinels" { o = $0 } { p = $0 }
    END { exit !(f == "master" && s + 0 >= 1 && o + 0 == 2) }'
}
ha_enable_step_sessions() {
  info "Waiting for the session store's Sentinels and replica..."
  _ha_until "${HA_SESSIONS_WAIT:-600}" "the Sentinels didn't agree on the session store's master with its replica" _ha_sentinel_ok
  ok "Sessions: a master, its replica, 3 Sentinels."
}

# ha_enable_step_frontdoor — step 9: the CAA account switch, then the old
# Traefik's volume (its account and certificate: nothing serves them now).
ha_enable_step_frontdoor() {
  local uri rc=0
  uri="$(dns_frontdoor_account_uri)" || fail "the front door's ACME account couldn't be read: run ./portcullis ha enable again"
  dns_flip_main_account "$uri" || rc=$?
  case "$rc" in
    0) ;;
    1) fail "the CAA account switch isn't done yet (above): the current certificate stays served; run ./portcullis ha enable again at the time given" ;;
    *) fail "the CAA account switch failed (above): the current certificate stays served; run ./portcullis ha enable again" ;;
  esac
  dns_relax_done
  kube_ctl -n "$(kube_ns)" delete pvc traefik-acme --ignore-not-found --wait=false >/dev/null || warn "could not delete the old Traefik's volume traefik-acme (delete it by hand: kubectl -n $(kube_ns) delete pvc traefik-acme)"
  ok "The main domain's certificate and CAA pin are the front door's ($uri)."
}

# _ha_green <view> — enabled, every item ok, every quorum full (etcd ≥ 3,
# Vault and Sentinel 3), zero loss, the front door leading or standing by,
# every replicated volume healthy. Prints the reasons it isn't.
_ha_green() {
  jq -r --argjson l "$HA_ITEM_LABELS" '
    [ (if .enabled != true then "HA isn'"'"'t on in the Hub (HUB_HA)" else empty end),
      (.checklist[]? | select(.ok != true) | ($l[.id] // .id) + ": " + .text),
      (.quorum // {} | to_entries[] | select(.value.healthy != .value.voters or .value.voters < 3) | "\(.key): \(.value.healthy)/\(.value.voters) healthy"),
      (if .guarantee != "Zero loss on one failure" then "Postgres: " + (.guarantee // "unknown") else empty end),
      (if (.frontdoor.state // "") == "" then "the front door: " + (.frontdoor.error // "no state") else empty end),
      (.volumes[]? | select(.robustness != "healthy") | "volume \(.name): \(.robustness)")
    ] | .[]' <<<"$1"
}
# _ha_spread_lines — fix round 1, M2: each core component whose 2 or more
# running replicas all sit on one node (found live: the switch's rollout,
# short of memory on the other node, packed both gates, both Keycloaks and
# both Valkeys onto one), one line each with its fix; nothing when spread.
# A node-local per-replica volume (the gates' logs) pins the pod: its fix
# names the PVC too. Unreadable pods print one line (fail closed).
_ha_spread_lines() {
  local pods
  pods="$(kube_ctl -n "$(kube_ns)" get pods -o json 2>/dev/null)" || { echo "the core pods can't be read: their spread is unknown"; return 0; }
  NS="$(kube_ns)" jq -r '
    [.items[] | select(.status.phase == "Running" and .metadata.deletionTimestamp == null and (.metadata.labels["portcullis.io/component"] // "") != "")
      | {c: .metadata.labels["portcullis.io/component"], n: .spec.nodeName, p: .metadata.name,
         pvc: ([.spec.volumes[]? | .persistentVolumeClaim.claimName // empty | select(startswith("data-"))] | first // "")}]
    | group_by(.c)[] | select(length >= 2 and ([.[].n] | unique | length) == 1)
    | (sort_by(.p) | last) as $x
    | "\(.[0].c): all \(length) replicas on node \(.[0].n) (one node lost takes them all): "
      + (if $x.pvc != "" then "kubectl -n \(env.NS) delete pvc \($x.pvc) --wait=false && kubectl -n \(env.NS) delete pod \($x.p) (its node-local volume goes too: a gate'"'"'s own log)"
         else "kubectl -n \(env.NS) delete pod \($x.p) (it starts again on another node)" end)' <<<"$pods" 2>/dev/null
}

ha_enable_step_status() {
  local t0 why
  t0="$(date +%s)"
  info "Waiting for ha status to be all green..."
  while :; do
    if _ha_hub_view; then
      why="$(_ha_green "$_HA_VIEW"; _ha_spread_lines)"
      [ -n "$why" ] || break
    else
      why="the Hub's HA view: $_HA_ERR"
    fi
    if [ $(( $(date +%s) - t0 )) -ge "${HA_STATUS_WAIT:-900}" ]; then
      printf '  %s\n' "$why" >&2
      fail "ha status isn't all green (above): run ./portcullis ha enable again to wait on"
    fi
    sleep "${HA_POLL:-5}"
  done
  ok "ha status: all green."
}

# _ha_stopped — Stop (SIGINT / SIGTERM) between or during steps: the
# record holds every finished step (written atomically), the next run
# resumes at the first one not in it.
_ha_stopped() {
  echo >&2
  _ha_helpers_done
  warn "ha enable stopped: steps done are recorded in $(_ha_enable_file); run ./portcullis ha enable again to resume at step $(_ha_step_n "$(_ha_enable_next)") ($(_ha_enable_next))"
  exit 130
}

ha_enable() {
  local yes="$1" s n
  if kube_ha_on && [ ! -s "$(_ha_enable_file)" ]; then
    ok "High availability is already on (PORTCULLIS_HA=on)."
    ha_status; return
  fi
  if [ -z "$(_ha_enable_next)" ]; then
    ok "High availability is on: every step of ha enable is done."
    ha_status; return
  fi
  if ! _ha_enable_done confirm && [ "$yes" != true ] && [ ! -t 0 ]; then
    usage_error "ha enable" "no terminal to confirm on: pass --yes to enable without asking"
  fi
  _HA_HELPERS="$(mktemp)"
  trap _ha_stopped INT TERM
  for s in $HA_ENABLE_STEPS; do
    _ha_enable_done "$s" && continue
    n="$(_ha_step_n "$s")"
    info "ha enable: step $n of 10 ($s)..."
    case "$s" in
      confirm) ha_enable_step_confirm "$yes" ;;
      *) "ha_enable_step_$s" ;;
    esac
    _ha_enable_record "$s"
  done
  trap - INT TERM
  _ha_helpers_done
  ok "High availability is on (experimental). ./portcullis ha status shows it; the Hub's Settings → High availability too."
}

# ha_status [--json] — the enable record and the Hub's HA view.
ha_status() {
  local json="${1:-false}" view="" rec='{"v":1,"done":[]}' next
  [ ! -s "$(_ha_enable_file)" ] || rec="$(cat "$(_ha_enable_file)")"
  _ha_hub_view || true
  view="$_HA_VIEW"
  if [ "$json" = true ]; then
    jq -n --argjson r "$rec" --arg v "$view" --arg e "${_HA_ERR:-}" --arg ha "${PORTCULLIS_HA:-off}" \
      '{ha: ($ha == "on"), enable: $r, hub: (if $v == "" then null else ($v | fromjson) end), hub_error: (if $v == "" then $e else null end)}'
    return 0
  fi
  next="$(_ha_enable_next)"
  if kube_ha_on; then
    printf 'High availability: on (experimental)\n'
  else
    printf 'High availability: off (experimental: ./portcullis ha enable turns it on)\n'
  fi
  if [ -s "$(_ha_enable_file)" ]; then
    if [ -n "$next" ]; then
      printf 'ha enable: %s of 10 steps done; next: step %s (%s): run ./portcullis ha enable to resume\n' \
        "$(jq -r '.done | length' <<<"$rec")" "$(_ha_step_n "$next")" "$next"
    else
      printf 'ha enable: done (%s)\n' "$(jq -r '.done[-1].at' <<<"$rec")"
    fi
  fi
  if [ -z "$view" ]; then
    if [ -n "$next" ] && _ha_enable_done volumes && ! _ha_enable_done switch; then
      printf 'The Hub is stopped by ha enable (its volumes are copied: step 4 done) until the switch (step 5).\n'
    else
      printf 'The Hub'"'"'s HA view: unreadable (%s)\n' "${_HA_ERR:-?}"
    fi
    return 0
  fi
  printf '\nChecklist:\n'
  _ha_checklist_lines "$(jq -c '.checklist' <<<"$view")"
  jq -r '"\nGuarantee: " + (.guarantee // "?"),
    ((.quorum // {}) as $q | "Quorum: " + ([["etcd", "etcd"], ["vault", "Vault"], ["sentinel", "Sentinel"]] | map(.[1] + " " + (($q[.[0]] // {healthy: 0, voters: 0}) | "\(.healthy)/\(.voters)")) | join(", "))),
    (if .enabled then "Front door: " + (if (.frontdoor.state // "") != "" then .frontdoor.state else "unknown (" + (.frontdoor.error // "?") + ")" end) else empty end),
    "\nNodes:",
    "  NODE                 ROLE    CLASS  SITE     READY  FENCING  N-1",
    (.nodes[]? | "  " + (.name + "                    ")[0:20] + " " + (.role + "        ")[0:7] + " " + ((.class // "-") + "       ")[0:6] + " " + ((.site // "-") + "         ")[0:8] + " " + (if .ready then "yes  " else "no   " end) + "  " + (if .fencing then "yes    " else "no     " end) + "  " + .n_minus_1),
    (if (.warnings // []) | length > 0 then "\nWarnings:", (.warnings[] | "  " + .) else empty end)' <<<"$view"
  if kube_ha_on; then
    local sp; sp="$(_ha_spread_lines)"
    if [ -n "$sp" ]; then printf '\nNot spread:\n'; printf '%s\n' "$sp" | sed 's/^/  /'; fi
  fi
}

help_ha() {
  cat <<'HELP'
Usage: portcullis ha <subcommand>

  status   High availability: the checklist, quorum, nodes and guarantee
  enable   Turn high availability on (experimental; resumable)

Kubernetes only. Run 'portcullis ha <subcommand> --help' for details.
HELP
}

help_ha_status() {
  cat <<'HELP'
Usage: portcullis ha status [--json]

Kubernetes only. Prints whether high availability is on, how far
`ha enable` got (its record, secrets/kube/ha-enable.json), and the Hub's HA
view (`hub ha checklist`, as Settings → High availability shows it): the
checklist ha enable needs all green, the Postgres guarantee, the etcd,
Vault and Sentinel quorums, each node (role, class, site, ready, fencing,
N−1) and the warnings. While ha enable has the Hub stopped (its volumes
copied, before the switch) it says so. --json prints
{ha, enable, hub, hub_error}.
HELP
}

help_ha_enable() {
  cat <<'HELP'
Usage: portcullis ha enable [--yes]

Kubernetes only; EXPERIMENTAL. Turns this cluster's single-node shape into
high availability, step by step, each step recorded in
secrets/kube/ha-enable.json once it succeeded; run it again after a
refusal, a failure or Stop (Ctrl-C) and it resumes at the first step not
recorded:
   1  the checklist all green (nothing changes on a red item; each is named)
   2  one confirmation (it names the sign-in downtime and the CAA wait)
   3  Longhorn, fencing, the snapshot controller, cert-manager, the backup plugin
   4  the Hub, domains and wg stopped; their volumes copied to the replicated
      tier and checked
   5  the switch: the front door's credentials and the current certificate,
      PORTCULLIS_HA=on, ./portcullis up (Traefik moves to the ingress nodes:
      sign-in is down for a few minutes)
   6  Postgres: its instances and a synchronous standby
   7  Vault: 3 raft voters
   8  the session store: its replica and 3 Sentinels
   9  the CAA account switch to the front door's ACME account (waits until no
      cache can hold the old pin; if longer than one run waits, run it again
      later), then the old Traefik volume deleted
  10  ha status all green
There is no ha disable: leaving HA is backup, init, restore.

Options:
  --yes   don't ask (scripts); without a terminal --yes is required
HELP
}

cmd_ha() {
  local sub="${1:-}" yes=false json=false
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_ha; [ -n "$sub" ] || exit 2; return 0 ;;
    status|enable) ;;
    *) usage_error ha "unknown subcommand: $sub" ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) "help_ha_$sub"; return 0 ;;
      --yes|-y) [ "$sub" = enable ] || usage_error "ha $sub" "unknown option: $1"; yes=true ;;
      --json) [ "$sub" = status ] || usage_error "ha $sub" "unknown option: $1"; json=true ;;
      -*) usage_error "ha $sub" "unknown option: $1" ;;
      *) usage_error "ha $sub" "unexpected argument: $1" ;;
    esac
    shift
  done
  need_env
  _rt_is_kube || fail "$HA_TEXT_NEEDS_KUBE (CONTAINER_RUNTIME is $(runtime_name)): Docker and Podman installs don't change"
  case "$sub" in
    status) ha_status "$json" ;;
    enable) ha_enable "$yes" ;;
  esac
}
