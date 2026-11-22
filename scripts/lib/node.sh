# shellcheck shell=bash
#
# nodeadm's CLI side (contract §20.2, §20.9; ruling R-ADM; plan R8: the new
# kube CLI code lives in kube_install.sh / ha.sh / node.sh, kube.sh doesn't
# grow). Sourced by runtime.sh after kube_install.sh. Bash 3.2 compatible.
#
#   - nodeadm's objects the CLI creates (never Helm): its namespace, the
#     Secrets nodeadm-k3s-token (the k3s server token, created once from
#     /var/lib/rancher/k3s/server/token; nodeadm rotates it afterwards),
#     nodeadm-state (empty), nodeadm-enroll (its enroll bearer, in its own
#     namespace) and the ConfigMap portcullis-cluster-addresses (empty);
#   - `./portcullis kube params-sync`, the only writer of the admission
#     params on a cluster: the cluster addresses nodeadm writes turned into
#     a params generation (§6's create-before-delete swap), then the record
#     portcullis-admission-active nodeadm reads before it releases a join;
#   - portcullis-kube-params.timer, every 30 s on the install host;
#   - the per-node host checks of a multi-node k3s cluster (Task 17 ruling).
#
# Secrets: the server token and the enroll bearer reach Kubernetes only
# through 0600 files in a 0700 staging directory (--from-file), never argv.

KUBE_NODEADM_NS="portcullis-nodeadm"
KUBE_K3S_SERVER_TOKEN="/var/lib/rancher/k3s/server/token"
KUBE_ADMISSION_ACTIVE="portcullis-admission-active"
KUBE_CLUSTER_ADDRESSES="portcullis-cluster-addresses"
# The DNS providers' API hosts: the probes' egress reference (§20.4).
KUBE_PROBE_EGRESS_HOSTS="cloudflare=api.cloudflare.com porkbun=api.porkbun.com route53=route53.amazonaws.com digitalocean=api.digitalocean.com hetzner=dns.hetzner.com hetzner-cloud=api.hetzner.cloud"

# kube_nodeadm_on — nodeadm runs here: init installed k3s on this host
# (PORTCULLIS_K3S_VERSION) and nodeadm's image is known by digest
# (PORTCULLIS_NODEADM_IMAGE, until release.yml pins it).
kube_nodeadm_on() {
  [ -n "${PORTCULLIS_K3S_VERSION:-}" ] && [[ "${PORTCULLIS_NODEADM_IMAGE:-}" =~ ^[a-z0-9./-]+(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$ ]]
}

# kube_probe_egress_host — the main domain's DNS provider API host, or "".
kube_probe_egress_host() {
  local p
  for p in $KUBE_PROBE_EGRESS_HOSTS; do
    [ "${p%%=*}" != "${DNS_PROVIDER:-}" ] || { echo "${p#*=}"; return 0; }
  done
}

# kube_nodeadm_prepare — before the Secrets are staged: nodeadm's enroll
# bearer, secrets/enroll/nodeadm-api-secret (48 random characters, 0600;
# synced into secrets-enroll, which enroll mounts).
kube_nodeadm_prepare() {
  kube_nodeadm_on || return 0
  local f="$PORTCULLIS_ROOT/secrets/enroll/nodeadm-api-secret"
  [ -s "$f" ] || (umask 077 && mkdir -p "$(dirname "$f")" && gen_alnum 48 > "$f") || fail "could not write $f"
}

# _kn_create_once <kind> <name> <namespace> <file|""> — the object, from a
# kubectl create … --dry-run=client file, only when it doesn't exist.
_kn_create_once() {
  kube_ctl -n "$3" get "$1" "$2" -o name >/dev/null 2>&1 && return 0
  kube_ctl -n "$3" create --field-manager="$KUBE_FIELD_MANAGER" -f "$4" >/dev/null
}

# kube_nodeadm_sync — after the Secrets: nodeadm's namespace and objects.
kube_nodeadm_sync() {
  kube_nodeadm_on || return 0
  local ns tmp psa
  ns="$(kube_ns)"
  psa="$(kube_psa nodeadm)" || exit 1
  # shellcheck disable=SC2086  # three single-word levels
  kube_namespace_apply "$KUBE_NODEADM_NS" $psa || fail "could not create the namespace $KUBE_NODEADM_NS"
  tmp="$(mktemp -d)"; chmod 700 "$tmp"
  # nodeadm's enroll bearer in its own namespace (put when it differs).
  (umask 077 && cp "$PORTCULLIS_ROOT/secrets/enroll/nodeadm-api-secret" "$tmp/bearer") \
    && kube_ctl create secret generic nodeadm-enroll -n "$KUBE_NODEADM_NS" --from-file=bearer="$tmp/bearer" --dry-run=client -o json \
       | jq '.metadata.labels = {"app.kubernetes.io/managed-by": "portcullis"}' > "$tmp/enroll.json" \
    && _kube_put "$tmp/enroll.json" || { rm -rf "$tmp"; fail "could not sync nodeadm's enroll bearer"; }
  # The server token: once, from the server's own token file (root's);
  # nodeadm rotates it afterwards, so a later run never overwrites it.
  if ! kube_ctl -n "$ns" get secret nodeadm-k3s-token -o name >/dev/null 2>&1; then
    # The agents' token in k3s's full form, K10<the CA hash>::node:<token>
    # (the hash is the server token's prefix: no secret on argv).
    (umask 077 && _ki_sudo cat "$(_ki_p "$KUBE_K3S_SERVER_TOKEN")" > "$tmp/token") && [ -s "$tmp/token" ] \
      || { rm -rf "$tmp"; fail "could not read the k3s server token ($KUBE_K3S_SERVER_TOKEN)"; }
    (umask 077 && { sed -n 's/^\(K10[0-9a-f]\{64\}\)::.*/\1::node:/p' "$tmp/token" | tr -d '\n'; _ki_sudo cat "$(_ki_p "$KUBE_K3S_AGENT_TOKEN_FILE")"; } > "$tmp/agent") \
      && grep -q '^K10[0-9a-f]\{64\}::node:.' "$tmp/agent" \
      || { rm -rf "$tmp"; fail "could not read the k3s agent token ($KUBE_K3S_AGENT_TOKEN_FILE)"; }
    kube_ctl create secret generic nodeadm-k3s-token -n "$ns" --from-file=token="$tmp/token" --from-file=agent="$tmp/agent" --dry-run=client -o json \
      | jq '.metadata.labels = {"app.kubernetes.io/managed-by": "portcullis"}' > "$tmp/token.json" \
      && _kn_create_once secret nodeadm-k3s-token "$ns" "$tmp/token.json" || { rm -rf "$tmp"; fail "could not create the Secret nodeadm-k3s-token"; }
  fi
  NS="$ns" jq -n '{apiVersion: "v1", kind: "Secret", type: "Opaque",
      metadata: {name: "nodeadm-state", namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis"}}}' > "$tmp/state.json" \
    && _kn_create_once secret nodeadm-state "$ns" "$tmp/state.json" || { rm -rf "$tmp"; fail "could not create the Secret nodeadm-state"; }
  NS="$ns" N="$KUBE_CLUSTER_ADDRESSES" jq -n '{apiVersion: "v1", kind: "ConfigMap",
      metadata: {name: env.N, namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis"}}}' > "$tmp/addr.json" \
    && _kn_create_once configmap "$KUBE_CLUSTER_ADDRESSES" "$ns" "$tmp/addr.json" || { rm -rf "$tmp"; fail "could not create the ConfigMap $KUBE_CLUSTER_ADDRESSES"; }
  rm -rf "$tmp"
  kube_first_node_addresses
}

# kube_first_node_addresses — the first node's LAN and public addresses on
# its node object (annotation portcullis.io/addresses, which nodeadm writes
# for every node it enrols): this host's IPv4 addresses outside the mesh,
# loopback and the cluster's networks, and the public IPv4. Once.
kube_first_node_addresses() {
  local node lan="" pub a
  node="$(kube_ctl get nodes -o json 2>/dev/null | jq -r --arg ip "$KUBE_MESH_IP" \
    '[.items[] | select([.status.addresses[]? | select(.type == "InternalIP") | .address] | index($ip))
     | select((.metadata.annotations["portcullis.io/addresses"] // "") == "") | .metadata.name][0] // empty' 2>/dev/null || true)"
  [ -n "$node" ] || return 0
  for a in $(_kube_local_addrs); do
    case "$a" in 127.*) continue ;; esac
    cidr_contains "$KUBE_MESH_CIDR" "$a" && continue
    { [ -n "${PORTCULLIS_POD_CIDR:-}" ] && cidr_contains "$PORTCULLIS_POD_CIDR" "$a"; } && continue
    { [ -n "${PORTCULLIS_SERVICE_CIDR:-}" ] && cidr_contains "$PORTCULLIS_SERVICE_CIDR" "$a"; } && continue
    lan="$lan $a"
  done
  pub="$(_kube_public_ipv4)"
  a="$(L="$lan" P="$pub" jq -cn '{lan: (env.L | split(" ") | map(select(. != "")) | unique), public: (if env.P == "" then [] else [env.P] end)}')"
  kube_ctl annotate node "$node" "portcullis.io/addresses=$a" >/dev/null || warn "could not record node $node's addresses (nodeadm writes no cluster addresses without them)"
}

# kube_nodeadm_values <values file> — nodeadm's chart values merged in.
kube_nodeadm_values() {
  local f="$1" on=false
  ! kube_nodeadm_on || on=true
  (umask 077 && jq --argjson on "$on" --arg img "${PORTCULLIS_NODEADM_IMAGE:-}" --arg eg "$(kube_probe_egress_host)" \
    '.nodeadm = {enabled: $on, image: (if $on then $img else "" end), probeEgressHost: $eg}' "$f" > "$f.tmp") \
    && chmod 600 "$f.tmp" && mv -f "$f.tmp" "$f" || fail "could not write nodeadm's values"
}

# ── the admission params from the cluster addresses (ruling R-ADM) ──

# kube_params_generation — key<TAB>value lines on stdin → the generation:
# the first 16 hex digits of the sha256 of every line, sorted bytewise
# (nodeadm's paramsGeneration; vectors nodeadm/testdata/params_generation_vectors.json).
kube_params_generation() {
  awk -F'\t' '$1 != "generation"' | LC_ALL=C sort | { sha256sum 2>/dev/null || shasum -a 256; } | cut -c1-16
}

# kube_doc_addresses — the admission params' addresses from
# portcullis-cluster-addresses (§20.9) and the live nodes: _K_DOC_NODES =
# every address of every pending and active node, of every removed node
# whose Node object still exists, and every InternalIP / ExternalIP of every
# live Node (the union: the document is nodeadm's, the Node objects the API
# server's); _K_DOC_API = api; each a /32, sorted unique, space-separated.
# Strict IPv4 only (an IPv4 single-stack cluster: octets 0–255, no leading
# zero; any IPv6 or malformed entry refuses the whole document). 0 = used;
# 2 = no document yet; 1 = refused (_K_ERR): it doesn't parse, a live Node
# is missing from it, or kube_cluster_addresses refuses it (fail closed).
kube_doc_addresses() {
  local out doc vals live
  _K_DOC_NODES="" _K_DOC_API=""
  if ! out="$(kube_ctl -n "$(kube_ns)" get configmap "$KUBE_CLUSTER_ADDRESSES" -o json 2>&1)"; then
    case "$out" in *NotFound*) return 2 ;; esac
    _K_ERR="the cluster addresses (ConfigMap $KUBE_CLUSTER_ADDRESSES) can't be read"; return 1
  fi
  doc="$(printf '%s' "$out" | jq -r '.data["addresses.json"] // empty' 2>/dev/null)"
  [ -n "$doc" ] || return 2
  [ -n "${_K_API_EP:-}" ] || kube_detect_cidrs || return 1
  kube_cluster_addresses || return 1
  live="$(kube_ctl get nodes -o json 2>/dev/null)" || { _K_ERR="kubectl get nodes failed: nothing is changed"; return 1; }
  vals="$(printf '%s' "$doc" | jq -r --argjson live "$live" '
      def oct: "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
      def ip4: type == "string" and test("^" + oct + "([.]" + oct + "){3}$");
      ([$live.items[].metadata.name]) as $names
      | ([$live.items[].status.addresses[]? | select(.type == "InternalIP" or .type == "ExternalIP") | .address]) as $laddr
      | select((.nodes | type == "object") and (.api | type == "array" and all(ip4))
          and (.nodes | all(.[]; (.state == "pending" or .state == "active" or .state == "removed")
               and (.mesh | ip4) and (.lan | type == "array" and all(ip4)) and (.public | type == "array" and all(ip4))))
          and ($laddr | all(type == "string")))
      | . as $d | ([$names[] | . as $n | select(($d.nodes | has($n)) | not)]) as $missing
      | if ($missing | length) > 0 then "MISSING\t" + ($missing | join(" "))
        else [([(.nodes | to_entries[] | select(.value.state != "removed" or (.key as $k | $names | index($k)))
                 | .value | .mesh, .lan[], .public[]), ($laddr[] | select(ip4))] | map(. + "/32") | unique | join(" ")),
              (.api | map(. + "/32") | unique | join(" "))] | @tsv end' 2>/dev/null)"
  case "$vals" in
    "") _K_ERR="the cluster addresses (ConfigMap $KUBE_CLUSTER_ADDRESSES) don't parse: nothing is changed"; return 1 ;;
    MISSING*) _K_ERR="the cluster addresses don't list the node(s) ${vals#MISSING$'\t'}: nothing is changed"; return 1 ;;
  esac
  IFS=$'\t' read -r _K_DOC_NODES _K_DOC_API <<< "$vals"
  [ -n "$_K_DOC_NODES" ] && [ -n "$_K_DOC_API" ] || { _K_ERR="the cluster addresses list no node or no API server: nothing is changed"; return 1; }
}

# kube_params_addresses — the nodeAddresses / apiAddresses kube_admission_params
# writes: the cluster addresses document's once it exists (refused while it
# doesn't validate), else PORTCULLIS_KUBE_NODE_ADDRESSES (or the nodes') and
# PORTCULLIS_KUBE_API_ENDPOINTS. Sets _K_PARAM_NODES / _K_PARAM_API.
kube_params_addresses() {
  local a ep rc=0
  _K_PARAM_NODES="" _K_PARAM_API=""
  kube_doc_addresses || rc=$?
  case "$rc" in
    0) _K_PARAM_NODES="$_K_DOC_NODES" _K_PARAM_API="$_K_DOC_API"; return 0 ;;
    1) fail "$_K_ERR (admission params)" ;;
  esac
  for a in ${PORTCULLIS_KUBE_NODE_ADDRESSES:-$(kube_node_addresses)}; do _K_PARAM_NODES+="${_K_PARAM_NODES:+ }$a/32"; done
  for ep in ${PORTCULLIS_KUBE_API_ENDPOINTS:-}; do _K_PARAM_API+="${_K_PARAM_API:+ }${ep%:*}/32"; done
}

# kube_admission_active_put <generation> <params lines> — after a proven
# swap: the record portcullis-admission-active nodeadm reads (§20.9),
# {"generation", "node_addresses", "api_addresses", "proven_at"}.
kube_admission_active_put() {
  local gen="$1" nodes api
  nodes="$(printf '%s\n' "$2" | awk -F'\t' '$1 == "nodeAddresses" { print $2 }')"
  api="$(printf '%s\n' "$2" | awk -F'\t' '$1 == "apiAddresses" { print $2 }')"
  G="$gen" N="$nodes" A="$api" NS="$(kube_ns)" AN="$KUBE_ADMISSION_ACTIVE" AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" jq -n '
    {apiVersion: "v1", kind: "ConfigMap",
     metadata: {name: env.AN, namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis"}},
     data: {"active.json": ({generation: env.G, node_addresses: (env.N | split(" ") | map(select(. != ""))),
                             api_addresses: (env.A | split(" ") | map(select(. != ""))), proven_at: env.AT} | tojson)}}' \
    | kube_ctl apply --server-side --force-conflicts --field-manager="$KUBE_FIELD_MANAGER" -f - >/dev/null \
    || fail "could not write $KUBE_ADMISSION_ACTIVE (params generation $gen is live; nodeadm releases no join until it is written)"
}

# kube_params_sync — `./portcullis kube params-sync` (§20.9): the active
# generation's params with the cluster addresses' four keys; a different
# generation runs §6's swap (kube_admission_params_apply), which writes the
# active record once it is proven. No document yet: nothing to do. A
# document that doesn't validate: nothing changed, exit 1.
kube_params_sync() {
  local rc=0 cur gen base hub params
  kube_detect_cidrs || fail "can't read the cluster's networks: $_K_ERR"
  [ "$_K_POD_CIDR" = "${PORTCULLIS_POD_CIDR:-}" ] \
    || fail "params-sync: the cluster CIDR is $_K_POD_CIDR but .env has PORTCULLIS_POD_CIDR=${PORTCULLIS_POD_CIDR:-}: nothing is changed"
  kube_doc_addresses || rc=$?
  case "$rc" in
    2) info "params-sync: no cluster addresses yet (nodeadm writes them): nothing to sync"; return 0 ;;
    1) fail "params-sync: $_K_ERR" ;;
  esac
  cur="$(kube_ctl -n "$(kube_ns)" get configmap "$KUBE_ADMISSION_ACTIVE" -o json 2>/dev/null | jq -r '.data["active.json"] // empty | fromjson | .generation // empty' 2>/dev/null || true)"
  [[ "$cur" =~ ^[0-9a-f]{16}$ ]] || fail "params-sync: no active admission params yet ($KUBE_ADMISSION_ACTIVE): run ./portcullis up first"
  base="$(kube_ctl -n "$(kube_ns)" get configmap "portcullis-admission-params-$cur" -o json 2>/dev/null \
    | jq -r '.data // {} | del(.generation) | to_entries[] | "\(.key)\t\(.value)"' 2>/dev/null || true)"
  [ -n "$base" ] || fail "params-sync: the active params portcullis-admission-params-$cur can't be read"
  hub="$(printf '%s\n' "$base" | awk -F'\t' '$1 == "hubImage" { print $2 }')"
  params="$(printf '%s\n' "$base" | awk -F'\t' -v n="$_K_DOC_NODES" -v a="$_K_DOC_API" -v p="$_K_POD_CIDR" -v s="$_K_SVC_CIDR" 'BEGIN { OFS = "\t" }
    $1 == "nodeAddresses" { $2 = n } $1 == "apiAddresses" { $2 = a } $1 == "podCIDR" { $2 = p } $1 == "serviceCIDR" { $2 = s } { print }')"
  gen="$(printf '%s\n' "$params" | kube_params_generation)"
  if [ "$gen" = "$cur" ]; then
    # Unchanged only when it still judges (review I3): every binding of the
    # generation, its params and the record naming them; else repaired.
    local why
    why="$(kube_params_intact "$cur" "$params")"
    [ -n "$why" ] || return 0
    warn "params-sync: admission params generation $cur is recorded but $why: repairing it..."
  else
    info "params-sync: the cluster addresses changed: admission params generation $gen (was $cur)..."
  fi
  kube_admission_params_apply "$hub" "$params"
}

# kube_params_intact <gen> <params lines> — prints why generation <gen>
# doesn't judge as recorded (nothing = intact): each of the KUBE_BINDINGS
# <binding>-<gen> exists, labelled with <gen> and naming
# portcullis-admission-params-<gen>; that ConfigMap exists; the record
# portcullis-admission-active names <gen> with the params' addresses.
kube_params_intact() {
  local gen="$1" params="$2" live b rec nodes api
  live="$(kube_ctl get validatingadmissionpolicybinding -l "portcullis.io/params-generation=$gen" -o json 2>/dev/null)" \
    || { echo "its bindings can't be listed"; return 0; }
  for b in $KUBE_BINDINGS; do
    printf '%s' "$live" | N="$b-$gen" P="portcullis-admission-params-$gen" jq -e \
      '[.items[] | select(.metadata.name == env.N and .spec.paramRef.name == env.P)] | length == 1' >/dev/null 2>&1 \
      || { echo "the binding $b-$gen is missing"; return 0; }
  done
  kube_ctl -n "$(kube_ns)" get configmap "portcullis-admission-params-$gen" -o name >/dev/null 2>&1 \
    || { echo "its params portcullis-admission-params-$gen are missing"; return 0; }
  nodes="$(printf '%s\n' "$params" | awk -F'\t' '$1 == "nodeAddresses" { print $2 }')"
  api="$(printf '%s\n' "$params" | awk -F'\t' '$1 == "apiAddresses" { print $2 }')"
  rec="$(kube_ctl -n "$(kube_ns)" get configmap "$KUBE_ADMISSION_ACTIVE" -o json 2>/dev/null | jq -r '.data["active.json"] // empty' 2>/dev/null)"
  printf '%s' "$rec" | G="$gen" N="$nodes" A="$api" jq -e 'fromjson? // . | .generation == env.G
      and (.node_addresses | join(" ")) == env.N and (.api_addresses | join(" ")) == env.A' >/dev/null 2>&1 \
    || { echo "the record $KUBE_ADMISSION_ACTIVE doesn't match it"; return 0; }
}

# cmd_kube_params_sync — `./portcullis kube params-sync` (cmd_kube).
cmd_kube_params_sync() {
  case "${1:-}" in -h|--help) help_kube_params_sync; return 0 ;; "") ;; *) usage_error "kube params-sync" "unknown argument: $1" ;; esac
  need_env
  _rt_is_kube || { warn "kube params-sync: CONTAINER_RUNTIME is $(runtime_name), not kubernetes"; exit 1; }
  kube_params_sync
}

help_kube_params_sync() {
  cat <<'HELP'
Usage: portcullis kube params-sync

Kubernetes only. Turns the cluster addresses nodeadm writes (ConfigMap
portcullis-cluster-addresses: every node, pending node and node being
removed) into the admission params: when the computed params generation
differs from the active one, it runs the create-before-delete swap and its
probe, then records the proven generation in portcullis-admission-active,
which nodeadm reads before it gives a joining node its k3s material. The
only writer of the admission params besides `up` / `upgrade`;
portcullis-kube-params.timer runs it every 30 s on the install host.

A document that doesn't parse, a node without a mesh address or an address
outside the mesh changes nothing (exit 1).
HELP
}

# kube_check_timer_units <dir> — portcullis-kube-check.service / .timer:
# backup schedule's system-unit pattern (User=, After network-online and
# k3s.service when this host runs it, Requires it then), every 6 h
# (Persistent: a host that was off catches up at boot). KUBECONFIG goes
# along when set (the operator's kubeconfig, never copied).
kube_check_timer_units() {
  local out="$1" user after="network-online.target" requires="" env_root="" env_kc=""
  user="$(id -un)"
  if systemctl cat k3s.service >/dev/null 2>&1; then after="$after k3s.service" requires="k3s.service"; fi
  [ "$PORTCULLIS_ROOT" = "$PORTCULLIS_HOME" ] || env_root="Environment=PORTCULLIS_ROOT=$PORTCULLIS_ROOT"
  [ -z "${KUBECONFIG:-}" ] || env_kc="Environment=KUBECONFIG=$KUBECONFIG"
  mkdir -p "$out"
  cat > "$out/portcullis-kube-check.service" <<UNIT
# portcullis-kube-check.service — generated by ./portcullis init (kubernetes)
[Unit]
Description=Portcullis cluster check (the Hub refuses runtime operations once it is 24 h old)
Wants=network-online.target
After=$after
${requires:+Requires=$requires
}
[Service]
Type=oneshot
User=$user
WorkingDirectory=$PORTCULLIS_ROOT
Environment=NO_COLOR=1
${env_root}
${env_kc}
ExecStart=$PORTCULLIS_HOME/portcullis kube check
TimeoutStartSec=10min
UNIT
  cat > "$out/portcullis-kube-check.timer" <<UNIT
# portcullis-kube-check.timer — generated by ./portcullis init (kubernetes)
[Unit]
Description=Portcullis cluster check every 6 hours

[Timer]
OnCalendar=*-*-* 00/6:00:00
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
UNIT
}

# kube_check_timer_install — init on kubernetes: the units into
# /etc/systemd/system (root, else sudo), enabled and started. Without
# systemd or after a failed install: a warning with the manual steps (status
# warns at 20 h, the Hub refuses at 24 h: fail closed either way).
kube_check_timer_install() {
  local tmp sudo="" kd="$PORTCULLIS_ROOT/secrets/kube/systemd"
  if ! command -v systemctl >/dev/null 2>&1 || [ ! -d "${KUBE_SYSTEMD_RUN:-/run/systemd/system}" ]; then
    warn "No systemd: run ./portcullis kube check at least every 20 h (cron); the Hub refuses every runtime operation once the cluster check is 24 h old."
    return 0
  fi
  [ "$(id -u)" = 0 ] || sudo=sudo
  tmp="$(mktemp -d)"
  kube_check_timer_units "$tmp"
  info "Installing portcullis-kube-check.timer (the cluster check every 6 h)..."
  if $sudo install -m 0644 "$tmp/portcullis-kube-check.service" "$tmp/portcullis-kube-check.timer" /etc/systemd/system/ \
     && $sudo systemctl daemon-reload && $sudo systemctl enable --now portcullis-kube-check.timer >/dev/null 2>&1; then
    ok "portcullis-kube-check.timer enabled (systemctl list-timers portcullis-kube-check.timer)"
  else
    kube_check_timer_units "$kd"
    warn "Could not install portcullis-kube-check.timer. As root:"
    printf '  install -m 0644 %s %s /etc/systemd/system/\n  systemctl daemon-reload && systemctl enable --now portcullis-kube-check.timer\n' \
      "$(_sq "$kd/portcullis-kube-check.service")" "$(_sq "$kd/portcullis-kube-check.timer")" >&2
  fi
  rm -rf "$tmp"
}

# kube_params_timer_units <dir> — portcullis-kube-params.{service,timer}:
# every 30 s, as the operator (the CLI's kubeconfig; a root-owned file in
# the install would break the operator's next run), after k3s when it runs
# here.
kube_params_timer_units() {
  local out="$1" user after="network-online.target" requires="" env_root="" env_kc=""
  user="$(id -un)"
  if systemctl cat k3s.service >/dev/null 2>&1; then after="$after k3s.service" requires="k3s.service"; fi
  [ "$PORTCULLIS_ROOT" = "$PORTCULLIS_HOME" ] || env_root="Environment=PORTCULLIS_ROOT=$PORTCULLIS_ROOT"
  [ -z "${KUBECONFIG:-}" ] || env_kc="Environment=KUBECONFIG=$KUBECONFIG"
  mkdir -p "$out"
  cat > "$out/portcullis-kube-params.service" <<UNIT
# portcullis-kube-params.service — generated by ./portcullis init (kubernetes)
[Unit]
Description=Portcullis admission params from the cluster addresses (joins wait for it)
Wants=network-online.target
After=$after
${requires:+Requires=$requires
}
[Service]
Type=oneshot
User=$user
WorkingDirectory=$PORTCULLIS_ROOT
Environment=NO_COLOR=1
${env_root}
${env_kc}
ExecStart=$PORTCULLIS_HOME/portcullis kube params-sync
TimeoutStartSec=5min
UNIT
  cat > "$out/portcullis-kube-params.timer" <<UNIT
# portcullis-kube-params.timer — generated by ./portcullis init (kubernetes)
[Unit]
Description=Portcullis admission params sync every 30 seconds

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=1s

[Install]
WantedBy=timers.target
UNIT
}

# kube_params_timer_install — init on kubernetes: the units into
# /etc/systemd/system (root, else sudo), enabled and started. Without
# systemd or after a failed install: a warning with the manual steps (joins
# wait while nothing runs params-sync; a running cluster isn't affected).
kube_params_timer_install() {
  local tmp sudo="" kd="$PORTCULLIS_ROOT/secrets/kube/systemd"
  if ! command -v systemctl >/dev/null 2>&1 || [ ! -d "${KUBE_SYSTEMD_RUN:-/run/systemd/system}" ]; then
    warn "No systemd: run ./portcullis kube params-sync while a node joins (it waits for it, waiting_admission)."
    return 0
  fi
  [ "$(id -u)" = 0 ] || sudo=sudo
  tmp="$(mktemp -d)"
  kube_params_timer_units "$tmp"
  info "Installing portcullis-kube-params.timer (the admission params sync every 30 s)..."
  if $sudo install -m 0644 "$tmp/portcullis-kube-params.service" "$tmp/portcullis-kube-params.timer" /etc/systemd/system/ \
     && $sudo systemctl daemon-reload && $sudo systemctl enable --now portcullis-kube-params.timer >/dev/null 2>&1; then
    ok "portcullis-kube-params.timer enabled (systemctl list-timers portcullis-kube-params.timer)"
  else
    kube_params_timer_units "$kd"
    warn "Could not install portcullis-kube-params.timer. As root:"
    printf '  install -m 0644 %s %s /etc/systemd/system/\n  systemctl daemon-reload && systemctl enable --now portcullis-kube-params.timer\n' \
      "$(_sq "$kd/portcullis-kube-params.service")" "$(_sq "$kd/portcullis-kube-params.timer")" >&2
  fi
  rm -rf "$tmp"
}

# ── per-node host checks (Task 17 ruling: nodeadm lifts the multi-node gate) ──

# kube_multi_node_checks <nodes json> — a cluster of several nodes: the
# server flags on every server, podPidsLimit on every node, AppArmor "not
# checked" on every node but this host (whose check kube_host_checks runs);
# sets _K_MULTI. 1 (nothing done) for a single node.
kube_multi_node_checks() {
  _K_MULTI=""
  [ "$(printf '%s' "$1" | jq -r '.items | length' 2>/dev/null)" -gt 1 ] 2>/dev/null || return 1
  _K_MULTI=1
  kube_node_args_checks "$1"
  kube_pids_checks "$1"
  kube_other_nodes_apparmor "$1"
}

# _kn_roles <nodes json> — one line per node: name, "server" when it
# carries node-role.kubernetes.io/control-plane=true (a label NodeRestriction
# keeps a kubelet from setting on itself) else "agent", what its node-args
# (k3s.io/node-args, which the node itself writes) claim ("server", "agent"
# or "" when unreadable), the rest of its node-args, its InternalIPs.
_kn_roles() {
  printf '%s' "$1" | jq -r '.items[] | (.metadata.annotations["k3s.io/node-args"] // "" | (fromjson? // [])) as $a
      | [.metadata.name, (if (.metadata.labels // {})["node-role.kubernetes.io/control-plane"] == "true" then "server" else "agent" end),
         (if ($a | type) == "array" and ($a | length) > 0 and (($a[0] == "server") or ($a[0] == "agent")) then $a[0] else "" end),
         (if ($a | type) == "array" then ($a[1:] | map(tostring) | join(" ")) else "" end),
         ([.status.addresses[]? | select(.type == "InternalIP") | .address] | join(" "))] | map(explode | map(if . == 31 or . == 10 then 32 else . end) | implode) | join("\u001f")' 2>/dev/null
}

# kube_cluster_cidr <nodes json> — _K_POD_CIDR = the cluster CIDR of a k3s
# cluster: every control-plane node's --cluster-cidr (k3s's default
# 10.42.0.0/16 without one), which must all agree; a control-plane node
# whose node-args don't say server fails closed. 2 = no control-plane node
# (not k3s: the caller reads spec.podCIDRs); 1 = refused (_K_ERR).
kube_cluster_cidr() {
  local name role kind args ips c cidr="" n=0
  while IFS=$'\x1f' read -r name role kind args ips; do
    [ "$role" = server ] || continue
    n=$((n + 1))
    [ "$kind" = server ] || { _K_ERR="node $name is a control-plane node but its node-args say ${kind:-nothing readable}: refused"; return 1; }
    c="10.42.0.0/16"
    case " $args " in
      *" --cluster-cidr="*) c="${args#*--cluster-cidr=}"; c="${c%% *}" ;;
      *" --cluster-cidr "*) c="${args#*--cluster-cidr }"; c="${c%% *}" ;;
    esac
    c="${c//,/ }"
    [ -z "$cidr" ] || [ "$cidr" = "$c" ] || { _K_ERR="the servers' --cluster-cidr disagree ($cidr, $c on $name): refused"; return 1; }
    cidr="$c"
  done < <(_kn_roles "$1")
  [ "$n" -gt 0 ] || return 2
  _K_POD_CIDR="$cidr"
}

# kube_node_args_checks <nodes json> — every server's node-args:
# --secrets-encryption, --disable=traefik, the network policy controller,
# ServiceLB ("ok|fail<TAB>text" lines). A node is a server by its
# control-plane label, never by its own node-args: a labelled node whose
# node-args say otherwise (or are unreadable), an unlabelled one claiming to
# be a server, and a set of control-plane nodes other than the API servers
# (the kubernetes EndpointSlice) fail.
kube_node_args_checks() {
  local name role kind args ips bad cp="" api
  while IFS=$'\x1f' read -r name role kind args ips; do
    [ -n "$name" ] || continue
    if [ "$role" = agent ]; then
      case "$kind" in
        agent) ;;
        server) _rt_chk fail "k3s node $name: its node-args claim a server, but it has no control-plane label" ;;
        *) _rt_chk fail "k3s node $name: its node-args (k3s.io/node-args) are unreadable: it can't be told apart" ;;
      esac
      continue
    fi
    cp="$cp $ips"
    if [ "$kind" != server ]; then
      _rt_chk fail "k3s node $name is a control-plane node but its node-args say ${kind:-nothing readable}: secrets encryption, the network policy controller, the bundled ingress and ServiceLB can't be checked"
      continue
    fi
    args=" $args " bad=""
    case "$args" in *" --secrets-encryption "*|*" --secrets-encryption=true "*) ;; *) bad="$bad, without --secrets-encryption" ;; esac
    case "$args" in *" --disable traefik "*|*" --disable=traefik "*|*" --disable=traefik,"*|*",traefik "*|*",traefik,"*) ;; *) bad="$bad, with its bundled Traefik (--disable=traefik missing)" ;; esac
    case "$args" in *" --disable-network-policy "*) bad="$bad, with --disable-network-policy" ;; esac
    case "$args" in *" --disable servicelb "*|*" --disable=servicelb "*|*"servicelb,"*|*",servicelb "*) bad="$bad, with ServiceLB disabled" ;; esac
    if [ -n "$bad" ]; then _rt_chk fail "k3s server $name runs${bad#,}: reinstall it with the init flags"; else _rt_chk ok "k3s server $name: secrets encryption, --disable=traefik, network policy, ServiceLB"; fi
  done < <(_kn_roles "$1")
  # The control-plane nodes are exactly the API servers.
  cp="$(printf '%s\n' $cp | grep . | LC_ALL=C sort -u | tr '\n' ' ')"
  api="$(kube_ctl get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o json 2>/dev/null \
    | jq -r '[.items[].endpoints[].addresses[]] | unique | .[]' 2>/dev/null | LC_ALL=C sort -u | tr '\n' ' ')"
  if [ -z "$api" ] || [ "$cp" != "$api" ]; then
    _rt_chk fail "the control-plane nodes (${cp% }) aren't the API servers (${api% }): the server roles can't be trusted"
  else
    _rt_chk ok "the control-plane nodes are the API servers (${cp% })"
  fi
}

# kube_pids_checks <nodes json> — the kubelet's podPidsLimit is 1024 on
# every node (configz through the API server's node proxy).
kube_pids_checks() {
  local name pids
  for name in $(printf '%s' "$1" | jq -r '.items[].metadata.name' 2>/dev/null); do
    pids="$(kube_ctl get --raw "/api/v1/nodes/$name/proxy/configz" 2>/dev/null | jq -r '.kubeletconfig.podPidsLimit // empty' 2>/dev/null || true)"
    if [ "$pids" = 1024 ]; then
      _rt_chk ok "node $name: kubelet podPidsLimit 1024"
    else
      _rt_chk fail "node $name: kubelet podPidsLimit is ${pids:-unset}, not 1024: reinstall k3s there with --kubelet-arg=pod-max-pids=1024 (the only per-pod pids cap)"
    fi
  done
}

# kube_other_nodes_apparmor <nodes json> — the AppArmor stacking check runs
# on this host only: each other node is "not checked" (a warning).
kube_other_nodes_apparmor() {
  local addrs name ips ip local_node
  addrs=" $(_kube_local_addrs) "
  while IFS=$'\t' read -r name ips; do
    [ -n "$name" ] || continue
    local_node=false
    for ip in $ips; do case "$addrs" in *" $ip "*) local_node=true ;; esac; done
    [ "$local_node" = true ] || _rt_chk warn "AppArmor stacking on node $name: not checked (it isn't this host): check kernel.apparmor_restrict_unprivileged_unconfined there (containerd#14485)"
  done < <(printf '%s' "$1" | jq -r '.items[] | [.metadata.name, ([.status.addresses[]? | select(.type == "InternalIP" or .type == "ExternalIP") | .address] | join(" "))] | @tsv' 2>/dev/null)
}

# ── the first node's nodeagent (plan Task 30 carry; contract §20.11) ──
#
# init's host is the cluster's first node: it never joins, so nothing gave
# it the nodeagent every other node runs (the Hub pushes it the mesh peers
# and reads its pcmesh key; nodeadm has it rotate tokens and remove etcd
# members; joining nodes measure their RTT against its echo). `up` adopts
# it once nodeadm runs, and renews its certificate (kube check too):
#   - the binary from nodeadm's image by its pinned digest (this host's
#     containerd; the copy nodeadm serves joining nodes), installed as
#     /usr/local/lib/portcullis/nodeagent, on the Node named by k3s's own
#     --node-name here (never one found by its address);
#   - `nodeagent adopt-csr <id>`: the key made on this host by the agent
#     (root's 0600 file; the CLI never reads it), the CSR printed;
#   - Vault pki_node/sign/node-cluster (the root token, as link.control):
#     <id>.cluster.portcullis.internal, client + server, 30 d;
#   - `nodeagent adopt` with the certificate, the CA, the node's id, mesh
#     address, site and class on stdin: the state, the unit started.
# Again when the certificate has ⅓ of its life left or the binary differs
# from nodeadm's. Fail closed: any check failing installs nothing.

KUBE_NODEAGENT_BIN=/usr/local/lib/portcullis/nodeagent
KUBE_NODEAGENT_STATE=/var/lib/portcullis/nodeagent
KUBE_CLUSTER_DOMAIN=cluster.portcullis.internal

# kube_first_node_name — this host's Kubernetes Node: the --node-name init
# gave k3s here (its unit's ExecStart, which install.sh writes), never a
# Node found by its address (a node identity may register a Node naming
# any InternalIP; security review). Printed only when that Node's
# InternalIP is the first mesh address and no other Node claims it: in
# _KN_NAME (else empty, and why in _KN_WHY; set, not printed, so the
# reason survives).
kube_first_node_name() {
  local name nodes
  _KN_WHY="" _KN_NAME=""
  name="$(_ki_sudo cat "$(_ki_p /etc/systemd/system/k3s.service)" 2>/dev/null \
    | sed -n "s/^[[:space:]]*'--node-name=\([a-z][a-z0-9-]*\)'.*/\1/p" | head -n1)"
  [[ "$name" =~ $NODE_ID_RE ]] || { _KN_WHY="k3s's unit here names no --node-name"; return 0; }
  nodes="$(kube_ctl get nodes -o json 2>/dev/null)" || { _KN_WHY="the Nodes can't be read"; return 0; }
  printf '%s' "$nodes" | jq -e --arg ip "$KUBE_MESH_IP" --arg n "$name" '
    [.items[] | select([.status.addresses[]? | select(.type == "InternalIP") | .address] | index($ip)) | .metadata.name] == [$n]' >/dev/null 2>&1 \
    || { _KN_WHY="this host's Node $name must be the only Node with InternalIP $KUBE_MESH_IP"; return 0; }
  _KN_NAME="$name"
}

# _kn_agent_from_image <arch> <out> — nodeagent-<arch> out of nodeadm's
# image by its pinned digest (PORTCULLIS_NODEADM_IMAGE, name@sha256:…; the
# trust anchor is the CLI's own pin, never a pod; security review): this
# host's containerd (k3s ctr, namespace k8s.io) holds it by that digest
# (pulled by digest when absent), its rootfs mounted read-only, the file
# copied, unmounted. Content is verified by containerd against the digest.
_kn_agent_from_image() {
  local ref="$PORTCULLIS_NODEADM_IMAGE" arch="$1" out="$2" dig have mnt rc=0
  dig="${ref##*@}"
  have="$(_ki_sudo k3s ctr -n k8s.io images ls "name==$ref" 2>/dev/null | awk 'NR > 1 { print $3; exit }')"
  if [ -z "$have" ]; then
    _ki_sudo k3s ctr -n k8s.io images pull --platform "linux/$arch" "$ref" >/dev/null 2>&1 || { _KN_WHY="nodeadm's image $ref couldn't be pulled by its digest"; return 1; }
    have="$(_ki_sudo k3s ctr -n k8s.io images ls "name==$ref" 2>/dev/null | awk 'NR > 1 { print $3; exit }')"
  fi
  [ "$have" = "$dig" ] || { _KN_WHY="containerd holds $ref as ${have:-nothing}, not its pinned digest"; return 1; }
  mnt="$(_ki_sudo mktemp -d)" || return 1
  _ki_sudo k3s ctr -n k8s.io images mount --platform "linux/$arch" "$ref" "$mnt" >/dev/null 2>&1 || rc=1
  [ "$rc" != 0 ] || _ki_sudo cat "$mnt$KUBE_NODEAGENT_BIN-$arch" > "$out" 2>/dev/null || rc=1
  _ki_sudo k3s ctr -n k8s.io images unmount "$mnt" >/dev/null 2>&1 || true
  _ki_sudo rmdir "$mnt" 2>/dev/null || true
  [ "$rc" = 0 ] && [ -s "$out" ] || { _KN_WHY="nodeagent-$arch couldn't be read from nodeadm's image $ref"; return 1; }
}

# _kn_here_first — this host is the first node: init installed k3s here
# (PORTCULLIS_K3S_VERSION), it runs the k3s server, and pcmesh holds the
# first mesh address.
_kn_here_first() {
  [ -n "${PORTCULLIS_K3S_VERSION:-}" ] && _ki_sudo test -d "$(_ki_p /var/lib/rancher/k3s/server)" \
    && { [ -n "${KUBE_INSTALL_PREFIX:-}" ] || ip -4 -o addr show dev "$KUBE_MESH_IF" 2>/dev/null | grep -q " $KUBE_MESH_IP/"; }
}

# _kn_agent_due <nodeadm sha256> — 0 when the adoption is owed: no state,
# the installed binary isn't nodeadm's, or the certificate is missing or
# has at most ⅓ of its life left (KUBE_NODEAGENT_NOW: the tests' clock).
_kn_agent_due() {
  local want="$1" have dates nb na now
  _ki_sudo test -s "$(_ki_p "$KUBE_NODEAGENT_STATE/state.json")" || return 0
  have="$(_ki_sudo cat "$(_ki_p "$KUBE_NODEAGENT_BIN")" 2>/dev/null | _kube_sha)"
  [ "$have" = "$want" ] || return 0
  # node.pem holds the key, then the certificate: x509 reads the certificate only.
  dates="$(_ki_sudo openssl x509 -in "$(_ki_p "$KUBE_NODEAGENT_STATE/node.pem")" -noout -startdate -enddate 2>/dev/null)" || return 0
  nb="$(to_epoch "$(printf '%s\n' "$dates" | sed -n 's/^notBefore=//p')")"
  na="$(to_epoch "$(printf '%s\n' "$dates" | sed -n 's/^notAfter=//p')")"
  { [ "${nb:-0}" -gt 0 ] && [ "${na:-0}" -gt "$nb" ]; } || return 0
  now="${KUBE_NODEAGENT_NOW:-$(date +%s)}"
  [ $((na - now)) -le $(((na - nb) / 3)) ]
}

# _kn_sign_node_cluster <cn> <csr file> <out file> — Vault's node-cluster
# certificate for the CSR (pki_node/sign/node-cluster, the root token in a
# header from a pipe, never argv), checked: CN, chains to the node CA for
# server and client auth, the CSR's key.
_kn_sign_node_cluster() {
  local cn="$1" csr="$2" out="$3" ca="$PORTCULLIS_ROOT/certs/node-ca.crt" code resp want d
  [ -s "$ca" ] || { warn "first node: $ca is empty (./portcullis pki setup)"; return 1; }
  vault_admin_env >/dev/null 2>&1 || { warn "first node: no Vault root token (secrets/vault-init.json)"; return 1; }
  want="$(openssl req -in "$csr" -noout -pubkey 2>/dev/null)"
  [ -n "$want" ] || { warn "first node: nodeagent adopt-csr printed no readable CSR"; return 1; }
  d="$(dirname "$out")"
  code="$(jq -Rs --arg cn "$cn" '{csr: ., common_name: $cn, ttl: "720h", format: "pem"}' < "$csr" \
    | curl -s --max-time 30 -o "$d/vault.json" -w '%{http_code}' -X POST \
        -H @<(printf 'X-Vault-Token: %s\n' "$VAULT_TOKEN") -H 'Content-Type: application/json' --data-binary @- \
        "${VAULT_ADDR:-http://127.0.0.1:8200}/v1/pki_node/sign/node-cluster" || true)"
  if [ "$code" != 200 ]; then
    resp="$(jq -r '(.errors // []) | join("; ")' "$d/vault.json" 2>/dev/null | cut -c1-200)"
    warn "first node: Vault refused to sign the node-cluster certificate (HTTP ${code:-none})${resp:+: $resp}"
    return 1
  fi
  jq -r '.data.certificate // empty' "$d/vault.json" > "$out" 2>/dev/null
  if [ "$(openssl x509 -in "$out" -noout -subject -nameopt RFC2253 2>/dev/null)" != "subject=CN=$cn" ] \
     || ! openssl verify -CAfile "$ca" -purpose sslserver "$out" >/dev/null 2>&1 \
     || ! openssl verify -CAfile "$ca" -purpose sslclient "$out" >/dev/null 2>&1 \
     || [ "$(openssl x509 -in "$out" -noout -pubkey 2>/dev/null)" != "$want" ]; then
    warn "first node: Vault's certificate isn't a $cn certificate (server + client auth) for the adoption key under certs/node-ca.crt: nothing installed"
    return 1
  fi
}

# kube_first_nodeagent — `up` (after the release is ready) and `kube
# check`: the first node's nodeagent adopted or renewed when owed. Not
# this host's business (no nodeadm, not init's k3s host): nothing. A
# failure warns (joins need it: the Hub's doctor names the node) and
# returns 1; nothing half-installed (the agent's own checks come first).
kube_first_nodeagent() {
  kube_nodeadm_on || return 0
  # Without a terminal (kube check's timer) only with passwordless sudo.
  if [ -z "${KUBE_INSTALL_PREFIX:-}" ] && [ "$(id -u)" != 0 ] && [ ! -t 0 ] && ! sudo -n true 2>/dev/null; then
    [ -z "${PORTCULLIS_K3S_VERSION:-}" ] || warn "first node: its nodeagent is installed and renewed by ./portcullis up (no passwordless sudo here)"
    return 0
  fi
  _kn_here_first || return 0
  local id arch want tmp labels site class
  kube_first_node_name
  id="$_KN_NAME"
  [[ "$id" =~ $NODE_ID_RE ]] || { warn "first node: ${_KN_WHY:-no Node for this host}: its nodeagent isn't installed"; return 1; }
  case "$(_ki_arch)" in amd64|arm64) arch="$(_ki_arch)" ;; *) warn "first node: no nodeagent for $(_ki_arch)"; return 1 ;; esac
  tmp="$(mktemp -d)" || return 1
  chmod 700 "$tmp"
  _kn_agent_from_image "$arch" "$tmp/nodeagent" || { rm -rf "$tmp"; warn "first node: $_KN_WHY: nothing installed"; return 1; }
  want="$(_kube_sha "$tmp/nodeagent")"
  _kn_agent_due "$want" || { rm -rf "$tmp"; return 0; }
  labels="$(kube_ctl get node "$id" -o json 2>/dev/null | jq -r '[.metadata.labels["portcullis.io/site"] // "", .metadata.labels["portcullis.io/class"] // ""] | @tsv')" || labels=""
  IFS=$'\t' read -r site class <<< "$labels"
  [[ "$site" =~ $NODE_ID_RE ]] && case "$class" in small|home|cloud) true ;; *) false ;; esac \
    || { rm -rf "$tmp"; warn "first node: node $id has no portcullis.io/site and class labels (init sets them): its nodeagent isn't installed"; return 1; }
  info "First node $id: installing / renewing its nodeagent..." >&2
  _ki_sudo mkdir -p "$(_ki_p "$(dirname "$KUBE_NODEAGENT_BIN")")" \
    && _ki_sudo install -m 0755 "$tmp/nodeagent" "$(_ki_p "$KUBE_NODEAGENT_BIN").new" \
    && _ki_sudo mv -f "$(_ki_p "$KUBE_NODEAGENT_BIN").new" "$(_ki_p "$KUBE_NODEAGENT_BIN")" \
    || { rm -rf "$tmp"; warn "first node: could not install $KUBE_NODEAGENT_BIN"; return 1; }
  _ki_sudo "$(_ki_p "$KUBE_NODEAGENT_BIN")" adopt-csr "$id" > "$tmp/csr" 2> "$tmp/err" \
    || { warn "first node: nodeagent adopt-csr: $(head -c 300 "$tmp/err")"; rm -rf "$tmp"; return 1; }
  _kn_sign_node_cluster "$id.$KUBE_CLUSTER_DOMAIN" "$tmp/csr" "$tmp/crt" || { rm -rf "$tmp"; return 1; }
  if ! jq -n --arg id "$id" --arg ip "$KUBE_MESH_IP" --arg site "$site" --arg class "$class" \
        --rawfile cert "$tmp/crt" --rawfile ca "$PORTCULLIS_ROOT/certs/node-ca.crt" \
        '{id: $id, mesh_ip: $ip, site: $site, class: $class, certificate: $cert, ca: $ca}' \
      | _ki_sudo "$(_ki_p "$KUBE_NODEAGENT_BIN")" adopt > /dev/null 2> "$tmp/err"; then
    warn "first node: nodeagent adopt: $(head -c 300 "$tmp/err")"; rm -rf "$tmp"; return 1
  fi
  rm -rf "$tmp"
  ok "First node $id: its nodeagent runs (certificate until $(_ki_sudo openssl x509 -in "$(_ki_p "$KUBE_NODEAGENT_STATE/node.pem")" -noout -enddate 2>/dev/null | cut -d= -f2))." >&2
}

# ── ./portcullis node … (plan Task 30; contract §20.1 "The CLI twins") ──
#
# Thin clients of the running Hub: `hub servers …` through `kubectl exec
# -i` into the Hub pod (the Lease holder in HA), which talks to its own
# host control socket. The Hub does the work, so its op, its audit (actor
# cli) and its Lease apply once. Requests go on stdin, never argv: the
# Hub's argv is only the subcommand and an id. The join code is printed
# alone on stdout (once; never logged); everything else goes to stderr.

NODE_ID_RE='^[a-z][a-z0-9-]{0,30}$'

help_node() {
  cat <<'HELP'
Usage: portcullis node <subcommand>

  add      A join code for a new cluster node (the code on stdout)
  list     The cluster's nodes, as the Hub lists them
  remove   Drain and remove a node (asks for its typed id)
  revoke   Cut a lost or compromised node off now (asks for its typed id)

Kubernetes only. Run 'portcullis node <subcommand> --help' for details.
HELP
}

help_node_add() {
  cat <<'HELP'
Usage: portcullis node add <id> [--role server|agent] [--class small|home|cloud] [--site <site>]

Kubernetes only. Has the Hub make a join code for the cluster node <id>
(its Kubernetes name, ^[a-z][a-z0-9-]{0,30}$): the same as Servers → Add
server on the Hub, audited as server.add by actor cli. Role and class
default to the Hub's suggestion, site to main.

The join code alone goes to stdout (redirect it to a 0600 file if you need
to carry it); the one-liner to run on the new machine and the rest go to
stderr. The code is a secret, valid 15 minutes and used once: on the new
machine, run the printed `curl … | sudo sh` and paste the code when asked
(it is never typed on a command line). Joining as a server gives that
machine full control of the cluster.
HELP
}

help_node_list() {
  cat <<'HELP'
Usage: portcullis node list [--json]

Kubernetes only. The servers the Hub lists (the cluster's nodes, joining
ones included): id, role, class, site, mesh address and state. --json
prints the Hub's answer as it is.
HELP
}

help_node_remove() {
  cat <<'HELP'
Usage: portcullis node remove <id>

Kubernetes only. Removes the cluster node <id> cooperatively, as the Hub's
Remove: cordon, drain (the replica and quorum minimums apply), Longhorn's
replicas moved, its etcd member removed (a server), its Node deleted and
its certificate revoked. Asks for the node's id, typed (read from stdin),
and refuses on a mismatch. Waits for the Hub's operation and prints its
outcome.
HELP
}

help_node_revoke() {
  cat <<'HELP'
Usage: portcullis node revoke <id>

Kubernetes only. Revokes the cluster node <id> at once, as the Hub's
Revoke (a lost or compromised machine): its certificate revoked, its
tokens deleted, the cluster's k3s tokens rotated, its Node and etcd member
removed; no drain. Asks for the node's id, typed (read from stdin), and
refuses on a mismatch. While etcd lacks quorum the removal is parked (the
security steps done) and the Hub finishes it later.
HELP
}

# _node_hub_ref — the Hub pod `hub servers` runs in: the holder of the
# Lease portcullis-hub (the writer in HA) when that pod exists, else the
# Deployment's.
_node_hub_ref() {
  local h
  h="$(kube_ctl -n "$(kube_ns)" get lease portcullis-hub -o jsonpath='{.spec.holderIdentity}' 2>/dev/null)" || h=""
  if [[ "$h" =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ ]] && kube_ctl -n "$(kube_ns)" get pod "$h" -o name >/dev/null 2>&1; then
    echo "pod/$h"
  else
    echo "deploy/hub"
  fi
}

# _node_hub <args…> — `hub servers <args…>` in the Hub pod, stdin passed
# through; its stdout and exit code (0 done, 1 refused, 2 usage), its
# stderr minus kubectl's "command terminated" line.
_node_hub() {
  kube_ctl -n "$(kube_ns)" exec -i "$(_node_hub_ref)" -c hub -- hub servers "$@" \
    2> >(awk '!/^command terminated with exit code [0-9]+$/ { print; fflush() }' >&2)
}

_node_kube() {
  need_env
  _rt_is_kube || fail "node $1: Kubernetes only (CONTAINER_RUNTIME is $(runtime_name)): a Docker or Podman server joins with the Hub's Add server and ./portcullis worker join"
}

_node_id() {
  [[ "$2" =~ $NODE_ID_RE ]] || usage_error "node $1" "invalid node id: $2 (^[a-z][a-z0-9-]{0,30}\$)"
}

_node_add() {
  local id="" role="" class="" site="" body tmp code rc=0
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) help_node_add; return 0 ;;
      --role) need_value "node add" "$1" "${2:-}"; role="$2"; shift ;;
      --role=*) role="${1#*=}" ;;
      --class) need_value "node add" "$1" "${2:-}"; class="$2"; shift ;;
      --class=*) class="${1#*=}" ;;
      --site) need_value "node add" "$1" "${2:-}"; site="$2"; shift ;;
      --site=*) site="${1#*=}" ;;
      -*) usage_error "node add" "unknown option: $1" ;;
      *) [ -z "$id" ] || usage_error "node add" "unexpected argument: $1"; id="$1" ;;
    esac
    shift
  done
  [ -n "$id" ] || usage_error "node add" "expected <id>"
  _node_id add "$id"
  case "$role" in ""|server|agent) ;; *) usage_error "node add" "--role must be server or agent" ;; esac
  case "$class" in ""|small|home|cloud) ;; *) usage_error "node add" "--class must be small, home or cloud" ;; esac
  [ -z "$site" ] || [[ "$site" =~ $NODE_ID_RE ]] || usage_error "node add" "--site must match ^[a-z][a-z0-9-]{0,30}\$"
  _node_kube add
  body="$(jq -nc --arg id "$id" --arg role "$role" --arg class "$class" --arg site "$site" \
    '{id: $id} + (if $role != "" then {role: $role} else {} end) + (if $class != "" then {class: $class} else {} end) + (if $site != "" then {site: $site} else {} end)')" \
    || fail "could not build the request"
  tmp="$(mktemp -d)" || fail "no temporary directory"
  chmod 700 "$tmp"
  # The code into a 0600 file (never a variable a trace could print), the
  # answer's rest into another.
  (umask 077 && printf '%s' "$body" | _node_hub add-cluster-node > "$tmp/code" 2> "$tmp/rest") || rc=$?
  if [ "$rc" != 0 ]; then
    # A refusal's text (no code in it); kubectl's own errors too.
    sed -e 's/pcj2\.[A-Za-z0-9_-]*/<redacted>/g' "$tmp/rest" >&2
    rm -rf "$tmp"
    fail "the Hub made no join code for $id"
  fi
  code="$(tr -d '\r\n' < "$tmp/code")"
  case "$code" in pcj2.?*) ;; *) rm -rf "$tmp"; fail "the Hub answered no join code" ;; esac
  if ! jq -e 'type == "object" and (.command | type == "string")' "$tmp/rest" >/dev/null 2>&1; then
    rm -rf "$tmp"
    fail "the Hub's answer is unreadable (the code is not shown: make a new one with ./portcullis node add)"
  fi
  {
    jq -r --arg id "$id" '"Node \($id): join code made (role \(.role), class \(.class), site \(.site); valid until \(.expires_at), used once)."' "$tmp/rest"
    jq -r '(.warnings // [])[] | "Warning: \(.)"' "$tmp/rest"
    jq -r 'select(.notice) | .notice' "$tmp/rest"
    echo "On the new machine, run:"
    jq -r '"  \(.command)"' "$tmp/rest"
    echo "and paste the join code below when it asks (it isn't shown there). It is a secret: never put it on a command line, in a chat or a ticket."
    echo "Progress: ./portcullis node list, or the Hub's Servers page."
  } >&2
  rm -rf "$tmp"
  printf '%s\n' "$code"
}

_node_list() {
  local json=false out
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) help_node_list; return 0 ;;
      --json) json=true ;;
      -*) usage_error "node list" "unknown option: $1" ;;
      *) usage_error "node list" "unexpected argument: $1" ;;
    esac
    shift
  done
  _node_kube list
  out="$(_node_hub list </dev/null)" || fail "the Hub didn't list its servers"
  if [ "$json" = true ]; then printf '%s\n' "$out"; return 0; fi
  printf '%s' "$out" | jq -r '
    ["ID", "ROLE", "CLASS", "SITE", "MESH IP", "STATE"],
    (.servers[] | select(.kind == "cluster-node" or .id == "primary")
      | [.id, (.role // "-"), (.class // "-"), (.site // "-"), (.mesh_ip // "-"), (.state + (if .error then " (" + .error + ")" else "" end))])
    | @tsv' | column -t -s "$(printf '\t')" \
    || fail "the Hub's server list is unreadable"
}

# _node_confirm <cmd> <id> — the typed id, read from stdin (a terminal, or
# a pipe for scripts); a mismatch refuses before the Hub is asked.
_node_confirm() {
  local typed=""
  printf 'Type the node id (%s) to %s it: ' "$2" "$1" >&2
  IFS= read -r typed || true
  [ -t 0 ] || echo >&2
  [ "$typed" = "$2" ] || fail "node $1: the typed id doesn't match $2: nothing was changed"
}

# _node_wait <id> <op_id> — polls the Hub's op until it finished (60 min,
# the Hub's own enrol/removal bounds are shorter); 0 it succeeded.
_node_wait() {
  local rec i last=""
  for ((i = 0; i < 1200; i++)); do
    rec="$(_node_hub op "$1" "$2" </dev/null 2>/dev/null)" || rec=""
    if [ -n "$rec" ] && printf '%s' "$rec" | jq -e 'type == "object"' >/dev/null 2>&1; then
      local step
      step="$(printf '%s' "$rec" | jq -r '[(.steps // [])[] | select(.state == "running") | .label] | first // empty' 2>/dev/null)"
      [ -z "$step" ] || [ "$step" = "$last" ] || { echo "    $step..." >&2; last="$step"; }
      if printf '%s' "$rec" | jq -e '.running != true' >/dev/null 2>&1; then
        printf '%s' "$rec" | jq -e '.ok == true' >/dev/null 2>&1 && return 0
        warn "node: the Hub's operation failed: $(printf '%s' "$rec" | jq -r '.error // "no reason given"')"
        return 1
      fi
    fi
    sleep 3
  done
  warn "node: the Hub's operation is still running after 60 min: ./portcullis node list"
  return 1
}

_node_remove() {
  local cmd="$1" id="" out
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) "help_node_$cmd"; return 0 ;;
      -*) usage_error "node $cmd" "unknown option: $1" ;;
      *) [ -z "$id" ] || usage_error "node $cmd" "unexpected argument: $1"; id="$1" ;;
    esac
    shift
  done
  [ -n "$id" ] || usage_error "node $cmd" "expected <id>"
  _node_id "$cmd" "$id"
  _node_kube "$cmd"
  _node_confirm "$cmd" "$id"
  out="$(jq -nc --arg id "$id" '{confirm: $id}' | _node_hub "$cmd" "$id")" || fail "the Hub refused to $cmd $id"
  if [ "$cmd" = revoke ]; then
    if printf '%s' "$out" | jq -e '.parked == true' >/dev/null 2>&1; then
      warn "$(printf '%s' "$out" | jq -r '.warning // empty')"
      warn "$(printf '%s' "$out" | jq -r '.detail // empty')"
      ok "$id revoked (parked: the Hub finishes the removal once etcd has quorum)" >&2
    else
      ok "$id revoked" >&2
    fi
    return 0
  fi
  local op
  op="$(printf '%s' "$out" | jq -r '.op_id // empty')"
  [ -n "$op" ] || fail "the Hub's answer names no operation"
  info "Removing $id (the Hub's operation $op)..." >&2
  _node_wait "$id" "$op" || fail "$id wasn't removed (see above; the Hub's Servers page has the steps)"
  ok "$id removed" >&2
}

cmd_node() {
  local sub="${1:-}"
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_node; [ -n "$sub" ] || exit 2; return 0 ;;
    add) _node_add "$@" ;;
    list) _node_list "$@" ;;
    remove|revoke) _node_remove "$sub" "$@" ;;
    *) usage_error node "unknown subcommand: $sub" ;;
  esac
}
