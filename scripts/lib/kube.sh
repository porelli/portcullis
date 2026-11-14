# shellcheck shell=bash
#
# CONTAINER_RUNTIME=kubernetes: core as the Helm chart charts/portcullis on
# a single-node k3s, driven against the named context
# PORTCULLIS_KUBE_CONTEXT (never the current one). Sourced at the end of
# runtime.sh. Every kubectl / helm call goes through kube_ctl / kube_helm.
#
# .env keys (written by `init --runtime kubernetes`, never switched):
#   PORTCULLIS_KUBE_CONTEXT          the kubeconfig context (required)
#   PORTCULLIS_NAMESPACE             core's namespace (portcullis)
#   PORTCULLIS_APPS_NAMESPACE        the app instances' namespace (portcullis-apps)
#   PORTCULLIS_POD_CIDR / _SERVICE_CIDR / PORTCULLIS_KUBE_API_ENDPOINTS
#                                    detected at init, re-checked by runtime_check
#   PORTCULLIS_KUBE_INSTALL_ID       owns the four namespaces (K11)
#   PORTCULLIS_KUBE_IMAGES           registry | local (K1)
#   PORTCULLIS_TRAEFIK_SERVICE_IP, PORTCULLIS_TRAEFIK_VPN_SERVICE_IP,
#   PORTCULLIS_WG_EDGE_SERVICE_IP    fixed ClusterIPs (service network + 20/21/22)
#
# Overridable for tests: KUBE_LOCAL_ADDRS (the node's local IPv4 addresses,
# space-separated), KUBE_PROBE_DIR, KUBE_TCP_PROBE (a function name).

KUBE_MIN_VERSION="1.32"
KUBE_STORAGE_NS="portcullis-storage"
# Traefik's only watched namespace (the chart's edgeNamespace): the core
# IngressRoutes and Middlewares, hub-proxy-secret, never a Secret.
KUBE_EDGE_NS="portcullis-edge"
# The six admission bindings (kube/admission/bindings.yaml), live as
# <name>-<params generation> (kube_admission_params_apply).
KUBE_BINDINGS="portcullis-apps-guard-pods portcullis-apps-guard-workloads portcullis-apps-guard-services portcullis-apps-guard-traefik portcullis-apps-guard-netpol portcullis-edge-guard-routes"
KUBE_PROBE_NS="portcullis-netpol-probe"
KUBE_MANAGED_LABEL="app.kubernetes.io/managed-by"
KUBE_INSTALL_ANNOTATION="portcullis.io/install"
# The fixed ClusterIPs: offsets from the service network's address.
KUBE_TRAEFIK_SVC_OFFSET=20
KUBE_TRAEFIK_VPN_SVC_OFFSET=21
KUBE_WG_EDGE_SVC_OFFSET=22
# The forbidden roots for the Hub's doctor (PORTCULLIS_RUNTIME_ROOTS): k3s'
# data directory (containerd's root inside it) and the provisioner's path.
# shellcheck disable=SC2034  # used by common.sh hub_env_write
KUBE_RUNTIME_ROOTS="/var/lib/rancher/k3s /var/lib/portcullis-storage"

kube_ns() { echo "${PORTCULLIS_NAMESPACE:-portcullis}"; }
kube_apps_ns() { echo "${PORTCULLIS_APPS_NAMESPACE:-portcullis-apps}"; }

_rt_is_kube() { [ "${CONTAINER_RUNTIME:-}" = kubernetes ]; }

# kube_ctl <kubectl args> — kubectl on PORTCULLIS_KUBE_CONTEXT, always
# with --context (a wrong current context can't hit another cluster).
kube_ctl() {
  [ -n "${PORTCULLIS_KUBE_CONTEXT:-}" ] || fail "PORTCULLIS_KUBE_CONTEXT is not set in .env: CONTAINER_RUNTIME=kubernetes never uses the current context"
  kubectl --context "$PORTCULLIS_KUBE_CONTEXT" "$@"
}

# kube_helm <helm args> — helm on PORTCULLIS_KUBE_CONTEXT (--kube-context).
kube_helm() {
  [ -n "${PORTCULLIS_KUBE_CONTEXT:-}" ] || fail "PORTCULLIS_KUBE_CONTEXT is not set in .env: CONTAINER_RUNTIME=kubernetes never uses the current context"
  helm --kube-context "$PORTCULLIS_KUBE_CONTEXT" "$@"
}

# kube_context_exists <ctx> — the context is in the operator's kubeconfig.
kube_context_exists() {
  # grep reads it all (no -q): an early exit would SIGPIPE kubectl under pipefail.
  kubectl config get-contexts -o name 2>/dev/null | grep -xF -- "$1" >/dev/null
}

# _kube_cidr_ok <cidr> — an IPv4 CIDR whose address is its network.
_kube_cidr_ok() {
  local first last
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || return 1
  read -r first last <<< "$(cidr_bounds "$1" 2>/dev/null)" || return 1
  [ -n "$first" ] && [ "$(ip_to_int "${1%/*}")" = "$first" ]
}

# kube_detect_cidrs — sets _K_POD_CIDR (the node's spec.podCIDRs, space-
# separated), _K_SVC_CIDR (from a server dry-run Service with clusterIP
# 0.0.0.1, whose rejection names the valid range) and _K_API_EP (the
# default/kubernetes EndpointSlice: ip:port, space-separated, sorted).
# An unparsable answer is refused (return 1, _K_ERR says why).
kube_detect_cidrs() {
  local nodes out
  _K_POD_CIDR="" _K_SVC_CIDR="" _K_API_EP="" _K_ERR=""
  nodes="$(kube_ctl get nodes -o json 2>/dev/null)" || { _K_ERR="kubectl get nodes failed"; return 1; }
  case "$(printf '%s' "$nodes" | jq -r '.items | length' 2>/dev/null)" in
    1) ;;
    0|"") _K_ERR="the cluster has no node"; return 1 ;;
    *) _K_ERR="the cluster has more than one node (Portcullis runs on a single-node k3s)"; return 1 ;;
  esac
  _K_POD_CIDR="$(printf '%s' "$nodes" | jq -r '.items[0].spec | (.podCIDRs // [.podCIDR // empty]) | join(" ")' 2>/dev/null || true)"
  [ -n "$_K_POD_CIDR" ] || { _K_ERR="the node has no spec.podCIDRs"; return 1; }
  # A Service no cluster can allocate: the API server names the range.
  out="$(kube_ctl create --dry-run=server -f - 2>&1 >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata:
  name: portcullis-cidr-probe
  namespace: default
spec:
  clusterIP: 0.0.0.1
  ports:
    - port: 1
EOF
)" || true
  _K_SVC_CIDR="$(printf '%s\n' "$out" | sed -n 's/.*[Tt]he range of valid IPs is \([0-9a-fA-F.:/, ]*[0-9a-fA-F]\).*/\1/p' | head -n1 | tr -d ',' | xargs)"
  [ -n "$_K_SVC_CIDR" ] || { _K_ERR="could not read the service CIDR from the API server's answer: $(printf '%s' "$out" | head -c 300)"; return 1; }
  _K_API_EP="$(kube_ctl get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o json 2>/dev/null \
    | jq -r '[.items[] | (.ports[0].port | tostring) as $p | .endpoints[] | .addresses[] | "\(.):\($p)"] | sort | join(" ")' 2>/dev/null || true)"
  [ -n "$_K_API_EP" ] || { _K_ERR="could not read the API endpoints (default/kubernetes EndpointSlice)"; return 1; }
}

# _kube_ipv6_in <list> — true when an entry of the list is IPv6.
_kube_ipv6_in() { case " $1 " in *:*) return 0 ;; *) return 1 ;; esac; }

# kube_svc_ip <offset> [service cidr] — the service network's address + n.
kube_svc_ip() {
  local first last
  read -r first last <<< "$(cidr_bounds "${2:-$PORTCULLIS_SERVICE_CIDR}" 2>/dev/null)" || return 1
  [ -n "$first" ] || return 1
  int_to_ip $((first + $1))
}

# _kube_static_band <service cidr> — the size of the static ClusterIP band:
# the first min(max(16, size/16), 256) addresses.
_kube_static_band() {
  local first last size band
  read -r first last <<< "$(cidr_bounds "$1" 2>/dev/null)" || return 1
  [ -n "$first" ] || return 1
  size=$((last - first + 1))
  band=$((size / 16))
  [ "$band" -ge 16 ] || band=16
  [ "$band" -le 256 ] || band=256
  echo "$band"
}

# kube_server_version — the API server's gitVersion (e.g. v1.37.2+k3s1).
kube_server_version() {
  kube_ctl version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion // empty' 2>/dev/null || true
}

# _kube_local_addrs — this host's IPv4 addresses (the CLI runs on the node).
_kube_local_addrs() {
  if [ -n "${KUBE_LOCAL_ADDRS+x}" ]; then echo "$KUBE_LOCAL_ADDRS"; return 0; fi
  ip -4 -o addr show 2>/dev/null | awk '{ sub("/.*", "", $4); print $4 }' | tr '\n' ' '
}

# _kube_public_ipv4 — PORTCULLIS_PUBLIC_IPV4, else the last detected one.
_kube_public_ipv4() {
  if [ -n "${PORTCULLIS_PUBLIC_IPV4:-}" ]; then echo "$PORTCULLIS_PUBLIC_IPV4"; return 0; fi
  cat "$PORTCULLIS_ROOT/secrets/domains/last-public-ipv4" 2>/dev/null || true
}

# _kube_tcp_open <ip> <port> — something accepts TCP there (2 s).
_kube_tcp_open() {
  if [ -n "${KUBE_TCP_PROBE:-}" ]; then "$KUBE_TCP_PROBE" "$1" "$2"; return; fi
  timeout 2 bash -c ': < "/dev/tcp/$1/$2"' 2>/dev/null
}

# _kube_ns_check <namespace> — K11: absent (created later), or ours: label
# app.kubernetes.io/managed-by=portcullis and annotation
# portcullis.io/install = PORTCULLIS_KUBE_INSTALL_ID.
_kube_ns_check() {
  local ns="$1" json mine
  if ! json="$(kube_ctl get namespace "$ns" -o json 2>&1)"; then
    if printf '%s' "$json" | grep -q 'NotFound'; then
      _rt_chk ok "namespace $ns: not there yet (init creates it)"
    else
      _rt_chk fail "namespace $ns: can't be read (kubectl get namespace $ns failed)"
    fi
    return 0
  fi
  mine="$(printf '%s' "$json" | jq -r --arg l "$KUBE_MANAGED_LABEL" --arg a "$KUBE_INSTALL_ANNOTATION" --arg id "${PORTCULLIS_KUBE_INSTALL_ID:-}" \
    '((.metadata.labels[$l] // "") == "portcullis" and $id != "" and (.metadata.annotations[$a] // "") == $id)' 2>/dev/null)"
  if [ "$mine" = true ]; then
    _rt_chk ok "namespace $ns belongs to this install"
  else
    _rt_chk fail "namespace $ns exists but isn't this install's (needs label $KUBE_MANAGED_LABEL=portcullis and annotation $KUBE_INSTALL_ANNOTATION=PORTCULLIS_KUBE_INSTALL_ID): Portcullis never adopts a namespace it didn't create"
  fi
}

# _kube_svc_ip_check <name> <ip> <service cidr> <band> <svc json> — the
# fixed ClusterIP lies in the static band and no Service but ours holds it.
_kube_svc_ip_check() {
  local name="$1" ip="$2" cidr="$3" band="$4" svcs="$5" first n holder
  read -r first _ <<< "$(cidr_bounds "$cidr")"
  if ! n="$(ip_to_int "$ip" 2>/dev/null)" || ! cidr_contains "$cidr" "$ip"; then
    _rt_chk fail "$name=$ip is not inside the service CIDR $cidr"; return 0
  fi
  if [ $((n - first)) -lt 1 ] || [ $((n - first)) -ge "$band" ]; then
    _rt_chk fail "$name=$ip is outside the service CIDR's static band (the first $band addresses of $cidr): a dynamic Service could take it"; return 0
  fi
  holder="$(printf '%s' "$svcs" | jq -r --arg ip "$ip" --arg ns "$(kube_ns)" '
      [.items[] | select(.spec.clusterIP == $ip or ((.spec.clusterIPs // []) | index($ip)))
       | select((.metadata.namespace == $ns) | not) | "\(.metadata.namespace)/\(.metadata.name)"] | join(", ")' 2>/dev/null)"
  if [ -n "$holder" ]; then
    _rt_chk fail "$name=$ip is already taken by Service $holder"
  else
    _rt_chk ok "$name=$ip is free in the static band"
  fi
}

# kube_host_checks — the cluster prerequisites (spec §6, K8, K10, K11), one
# "ok|warn|fail<TAB>text" line each (fail = refuse: init, up, upgrade,
# restore).
kube_host_checks() {
  local v ver nodes args cfg pids svcs band pub ingress addrs local_ip a ns
  for v in kubectl helm; do
    if command -v "$v" >/dev/null 2>&1; then _rt_chk ok "$v present"; else _rt_chk fail "$v is missing (install it on this host)"; fi
  done
  if [ -z "${PORTCULLIS_KUBE_CONTEXT:-}" ]; then
    _rt_chk fail "PORTCULLIS_KUBE_CONTEXT is not set"; return 0
  fi
  if ! kube_context_exists "$PORTCULLIS_KUBE_CONTEXT"; then
    _rt_chk fail "the kube context $PORTCULLIS_KUBE_CONTEXT doesn't exist (kubectl config get-contexts)"; return 0
  fi
  ver="$(kube_server_version)"
  if [ -z "$ver" ]; then
    _rt_chk fail "the cluster behind $PORTCULLIS_KUBE_CONTEXT doesn't answer (kubectl version)"; return 0
  fi
  if _ver_ge "${ver#v}" "$KUBE_MIN_VERSION"; then
    _rt_chk ok "Kubernetes $ver (>= $KUBE_MIN_VERSION)"
  else
    _rt_chk fail "Kubernetes $ver: Portcullis needs >= $KUBE_MIN_VERSION (ValidatingAdmissionPolicy GA)"
  fi
  case "$ver" in *+k3s*) _rt_chk ok "k3s" ;; *) _rt_chk warn "not k3s ($ver): should work, not CI-tested" ;; esac
  nodes="$(kube_ctl get nodes -o json 2>/dev/null || true)"
  # k3s records its server flags on the node.
  args="$(printf '%s' "$nodes" | jq -r '.items[0].metadata.annotations["k3s.io/node-args"] // empty' 2>/dev/null | jq -r 'join(" ")' 2>/dev/null || true)"
  if [ -n "$args" ]; then
    args=" $args "
    case "$args" in
      *" --secrets-encryption "*|*" --secrets-encryption=true "*) _rt_chk ok "k3s --secrets-encryption" ;;
      *) _rt_chk fail "k3s runs without --secrets-encryption (Secrets would sit unencrypted in its datastore): reinstall k3s with it" ;;
    esac
    case "$args" in
      *" --disable traefik "*|*" --disable=traefik "*|*" --disable=traefik,"*|*",traefik "*|*",traefik,"*) _rt_chk ok "k3s --disable=traefik" ;;
      *) _rt_chk fail "k3s runs its bundled Traefik: reinstall k3s with --disable=traefik (core ships its own)" ;;
    esac
    case "$args" in
      *" --disable-network-policy "*) _rt_chk fail "k3s runs with --disable-network-policy: NetworkPolicies wouldn't be enforced" ;;
      *) _rt_chk ok "k3s network policy controller on" ;;
    esac
    case "$args" in
      *" --disable servicelb "*|*" --disable=servicelb "*|*"servicelb,"*|*",servicelb "*) _rt_chk fail "k3s runs with ServiceLB disabled: Traefik's LoadBalancer Service needs it" ;;
      *) _rt_chk ok "k3s ServiceLB on" ;;
    esac
  else
    _rt_chk warn "not k3s, or its node-args are unreadable: secrets encryption, the bundled ingress and ServiceLB can't be checked"
  fi
  cfg="$(kube_ctl get --raw "/api/v1/nodes/$(printf '%s' "$nodes" | jq -r '.items[0].metadata.name // "?"' 2>/dev/null)/proxy/configz" 2>/dev/null || true)"
  pids="$(printf '%s' "$cfg" | jq -r '.kubeletconfig.podPidsLimit // empty' 2>/dev/null || true)"
  if [ "$pids" = 1024 ]; then
    _rt_chk ok "kubelet podPidsLimit 1024"
  else
    _rt_chk fail "kubelet podPidsLimit is ${pids:-unset}, not 1024: reinstall k3s with --kubelet-arg=pod-max-pids=1024 (the only per-pod pids cap)"
  fi
  if kube_detect_cidrs; then
    if _kube_ipv6_in "$_K_POD_CIDR $_K_SVC_CIDR"; then
      _rt_chk fail "dual-stack or IPv6 cluster (pods $_K_POD_CIDR, services $_K_SVC_CIDR): Portcullis supports IPv4 single-stack only"
    elif [ "${_K_POD_CIDR// /}" != "$_K_POD_CIDR" ] || [ "${_K_SVC_CIDR// /}" != "$_K_SVC_CIDR" ]; then
      _rt_chk fail "more than one pod or service CIDR (pods $_K_POD_CIDR, services $_K_SVC_CIDR): Portcullis supports one of each"
    else
      _rt_chk ok "IPv4 single-stack: pods $_K_POD_CIDR, services $_K_SVC_CIDR, API $_K_API_EP"
      for a in "PORTCULLIS_POD_CIDR:$_K_POD_CIDR" "PORTCULLIS_SERVICE_CIDR:$_K_SVC_CIDR" "PORTCULLIS_KUBE_API_ENDPOINTS:$_K_API_EP"; do
        v="${a%%:*}"
        [ -z "${!v:-}" ] || [ "${!v}" = "${a#*:}" ] || _rt_chk fail "$v=${!v} in .env, but the cluster has ${a#*:}"
      done
      band="$(_kube_static_band "$_K_SVC_CIDR")"
      svcs="$(kube_ctl get services -A -o json 2>/dev/null || echo '{"items":[]}')"
      _kube_svc_ip_check PORTCULLIS_TRAEFIK_SERVICE_IP "${PORTCULLIS_TRAEFIK_SERVICE_IP:-$(kube_svc_ip "$KUBE_TRAEFIK_SVC_OFFSET" "$_K_SVC_CIDR")}" "$_K_SVC_CIDR" "$band" "$svcs"
      _kube_svc_ip_check PORTCULLIS_TRAEFIK_VPN_SERVICE_IP "${PORTCULLIS_TRAEFIK_VPN_SERVICE_IP:-$(kube_svc_ip "$KUBE_TRAEFIK_VPN_SVC_OFFSET" "$_K_SVC_CIDR")}" "$_K_SVC_CIDR" "$band" "$svcs"
      _kube_svc_ip_check PORTCULLIS_WG_EDGE_SERVICE_IP "${PORTCULLIS_WG_EDGE_SERVICE_IP:-$(kube_svc_ip "$KUBE_WG_EDGE_SVC_OFFSET" "$_K_SVC_CIDR")}" "$_K_SVC_CIDR" "$band" "$svcs"
    fi
  else
    _rt_chk fail "can't read the cluster's networks: $_K_ERR"
  fi
  for ns in "$(kube_ns)" "$(kube_apps_ns)" "$KUBE_STORAGE_NS" "$KUBE_EDGE_NS"; do
    _kube_ns_check "$ns"
  done
  # Task 0 Q1: ServiceLB keeps the client address only for an address it
  # publishes (the traefik Service's ingress, else the node's ExternalIP or
  # InternalIP); a public address that is a second local address is SNATed.
  pub="$(_kube_public_ipv4)"
  if [ -n "$pub" ]; then
    ingress="$(kube_ctl -n "$(kube_ns)" get service traefik -o json 2>/dev/null | jq -r '[.status.loadBalancer.ingress[]?.ip // empty] | join(" ")' 2>/dev/null || true)"
    [ -n "$ingress" ] || ingress="$(printf '%s' "$nodes" | jq -r '(.items[0].status.addresses // []) as $a | ([$a[] | select(.type == "ExternalIP") | .address] | if length > 0 then . else [$a[] | select(.type == "InternalIP") | .address] end) | join(" ")' 2>/dev/null || true)"
    addrs=" $(_kube_local_addrs) "
    local_ip=false
    case "$addrs" in *" $pub "*) local_ip=true ;; esac
    if [ "$local_ip" = true ] && ! case " $ingress " in *" $pub "*) true ;; *) false ;; esac; then
      _rt_chk warn "client IPs will be rewritten: the public address $pub is local but ServiceLB publishes ${ingress:-nothing}: reinstall k3s with --node-external-ip=$pub"
    else
      _rt_chk ok "client addresses kept: $pub reaches Traefik through ${ingress:-the node} (ServiceLB, externalTrafficPolicy Local)"
    fi
    # K8: the kube API and the kubelet should not answer on the public address.
    for a in 6443 10250; do
      if _kube_tcp_open "$pub" "$a"; then
        _rt_chk warn "port $a answers on the public address $pub: restrict it in the firewall"
      fi
    done
  else
    _rt_chk warn "the public IPv4 is unknown (PORTCULLIS_PUBLIC_IPV4): the client-address and exposed-API checks were skipped"
  fi
}

# kube_require_host — refuse (listing every failed item) while a † cluster
# item fails.
kube_require_host() {
  local lines fails
  [ -z "${_RT_HOST_OK:-}" ] || return 0
  lines="$(kube_host_checks)" || exit 1
  fails="$(printf '%s\n' "$lines" | awk -F'\t' '$1 == "fail" { print "  - " $2 }')"
  [ -z "$fails" ] || fail "this cluster isn't ready for Portcullis (docs: operations/kubernetes):"$'\n'"$fails"
  _RT_HOST_OK=1
}

# kube_runtime_check — runtime_check under kubernetes: the context is set
# and exists, the cluster answers, and the networks it has are the ones in
# .env (a different pod / service CIDR or API endpoint is refused naming
# both values; an IPv6 entry is refused).
kube_runtime_check() {
  local a v
  [ -n "${PORTCULLIS_KUBE_CONTEXT:-}" ] || fail "PORTCULLIS_KUBE_CONTEXT is not set in .env (CONTAINER_RUNTIME=kubernetes): ./portcullis init --runtime kubernetes --kube-context <ctx> writes it; the current context is never used"
  command -v kubectl >/dev/null 2>&1 || fail "kubectl is missing (CONTAINER_RUNTIME=kubernetes)"
  kube_context_exists "$PORTCULLIS_KUBE_CONTEXT" || fail "the kube context $PORTCULLIS_KUBE_CONTEXT (PORTCULLIS_KUBE_CONTEXT) doesn't exist in the kubeconfig"
  kube_detect_cidrs || fail "can't read the cluster behind $PORTCULLIS_KUBE_CONTEXT: $_K_ERR"
  ! _kube_ipv6_in "$_K_POD_CIDR $_K_SVC_CIDR" || fail "dual-stack or IPv6 cluster (pods $_K_POD_CIDR, services $_K_SVC_CIDR): Portcullis supports IPv4 single-stack only"
  for a in "PORTCULLIS_POD_CIDR:$_K_POD_CIDR" "PORTCULLIS_SERVICE_CIDR:$_K_SVC_CIDR" "PORTCULLIS_KUBE_API_ENDPOINTS:$_K_API_EP"; do
    v="${a%%:*}"
    [ -n "${!v:-}" ] || fail "$v is not set in .env (./portcullis init --runtime kubernetes detects it)"
    [ "${!v}" = "${a#*:}" ] || fail "$v=${!v} in .env, but the cluster has ${a#*:}: refusing to deploy against a different network"
  done
  # The CLI's Vault / Keycloak calls go through port-forwards when the
  # release runs (127.0.0.1 inside the pods).
  kube_forward_core
}

# kube_env_keys — the .env lines of a new kubernetes install (after
# kube_detect_cidrs): context, namespaces, networks, install id, images,
# the three fixed ClusterIPs.
kube_env_keys() {
  local ctx="$1" id
  id="$(uuidgen 2>/dev/null | tr 'A-Z' 'a-z')" || true
  [ -n "$id" ] || id="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
  [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || fail "could not generate PORTCULLIS_KUBE_INSTALL_ID (uuidgen)"
  cat <<EOF
PORTCULLIS_KUBE_CONTEXT=$ctx
PORTCULLIS_NAMESPACE=portcullis
PORTCULLIS_APPS_NAMESPACE=portcullis-apps
PORTCULLIS_POD_CIDR=$_K_POD_CIDR
PORTCULLIS_SERVICE_CIDR=$_K_SVC_CIDR
PORTCULLIS_KUBE_API_ENDPOINTS=$_K_API_EP
PORTCULLIS_KUBE_INSTALL_ID=$id
PORTCULLIS_KUBE_IMAGES=registry
PORTCULLIS_TRAEFIK_SERVICE_IP=$(kube_svc_ip "$KUBE_TRAEFIK_SVC_OFFSET" "$_K_SVC_CIDR")
PORTCULLIS_TRAEFIK_VPN_SERVICE_IP=$(kube_svc_ip "$KUBE_TRAEFIK_VPN_SVC_OFFSET" "$_K_SVC_CIDR")
PORTCULLIS_WG_EDGE_SERVICE_IP=$(kube_svc_ip "$KUBE_WG_EDGE_SVC_OFFSET" "$_K_SVC_CIDR")
EOF
}

# ── NetworkPolicy enforcement probe (spec §6) ─────────────

# _kube_dial <pod> <ip> — the probe client dials the server's :8080 (3 s).
_kube_dial() {
  kube_ctl -n "$KUBE_PROBE_NS" exec "$1" -- nc -w 3 "$2" 8080 </dev/null >/dev/null 2>&1
}

_kube_probe_cleanup() {
  kube_ctl delete namespace "$KUBE_PROBE_NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}

# kube_netpol_probe — prove NetworkPolicies are enforced, each direction on
# its own (kube/probe/*): client-ingress (egress allowed, the server's
# ingress refuses it) and client-egress (the server admits it, no egress
# allowed) must NOT reach the server, and client-allowed (both allowed)
# MUST. Only then the ConfigMap portcullis-netpol-probe (proven_at, UTC)
# is written in the apps namespace (the Hub reads it, never as enough by
# itself); the scratch namespace is deleted either way. Returns 1 (nothing
# written) when not proven.
kube_netpol_probe() {
  local dir="${KUBE_PROBE_DIR:-$PORTCULLIS_HOME/kube/probe}" f ip i allowed=false ingress_held=false egress_held=false
  _kube_probe_cleanup
  kube_ctl wait --for=delete "namespace/$KUBE_PROBE_NS" --timeout=120s >/dev/null 2>&1 || true
  for f in namespace deny allow; do
    kube_ctl apply -f "$dir/$f.yaml" >/dev/null || { _kube_probe_cleanup; warn "could not apply the NetworkPolicy probe ($f.yaml)"; return 1; }
  done
  if ! kube_ctl -n "$KUBE_PROBE_NS" wait --for=jsonpath='{.status.phase}'=Running pod/server pod/client-ingress pod/client-egress pod/client-allowed --timeout=180s >/dev/null 2>&1; then
    _kube_probe_cleanup; warn "the NetworkPolicy probe pods didn't start"; return 1
  fi
  ip="$(kube_ctl -n "$KUBE_PROBE_NS" get pod server -o jsonpath='{.status.podIP}' 2>/dev/null || true)"
  [ -n "$ip" ] || { _kube_probe_cleanup; warn "the probe server has no address"; return 1; }
  # The control may need the policy controller a moment: retried.
  for ((i = 0; i < 10; i++)); do
    if _kube_dial client-allowed "$ip"; then allowed=true; break; fi
    sleep 2
  done
  if ! _kube_dial client-ingress "$ip"; then ingress_held=true; fi
  if ! _kube_dial client-egress "$ip"; then egress_held=true; fi
  _kube_probe_cleanup
  if [ "$allowed" != true ]; then
    warn "NetworkPolicy probe: the allowed connection failed (pod networking broken?): not proven"; return 1
  fi
  if [ "$ingress_held" != true ]; then
    warn "NetworkPolicy probe: a connection the server's ingress policy refuses got through: ingress NetworkPolicies are NOT enforced"; return 1
  fi
  if [ "$egress_held" != true ]; then
    warn "NetworkPolicy probe: a connection no egress policy allows got through: egress NetworkPolicies are NOT enforced"; return 1
  fi
  kube_ctl apply -f - >/dev/null <<EOF || { warn "could not write the ConfigMap portcullis-netpol-probe"; return 1; }
apiVersion: v1
kind: ConfigMap
metadata:
  name: portcullis-netpol-probe
  namespace: $(kube_apps_ns)
  labels:
    $KUBE_MANAGED_LABEL: portcullis
data:
  proven_at: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EOF
  ok "NetworkPolicies are enforced in both directions (probe: ingress and egress refusals held, the allowed dial succeeded)."
}

# ── port-forward ──────────────────────────────────────────

# kube_port_forward <service> <port> — a background `kubectl port-forward`
# of the core Service to a random loopback port. Sets _K_PF_PORT (and
# prints it). Call it directly, never in $(...): the forwarder belongs to
# this shell, and kube_port_forward_stop (the caller's trap) kills it.
kube_port_forward() {
  local svc="$1" port="$2" log i lp="" pid
  log="$(mktemp)"
  kube_ctl -n "$(kube_ns)" port-forward --address 127.0.0.1 "svc/$svc" ":$port" >"$log" 2>&1 &
  pid=$!
  _K_PF_PIDS="${_K_PF_PIDS:-} $pid"
  for ((i = 0; i < 100; i++)); do
    lp="$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9][0-9]*\) -> .*/\1/p' "$log" | head -n1)"
    [ -z "$lp" ] || break
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  rm -f "$log"
  [ -n "$lp" ] || { kube_port_forward_stop; fail "kubectl port-forward to $svc:$port failed"; }
  _K_PF_PORT="$lp"
  echo "$lp"
}

kube_port_forward_stop() {
  local p
  for p in ${_K_PF_PIDS:-}; do kill "$p" 2>/dev/null || true; done
  _K_PF_PIDS=""
}

# kube_node_addresses — every InternalIP and ExternalIP of the cluster's
# nodes, space-separated, sorted (PORTCULLIS_KUBE_NODE_ADDRESSES, core.env).
kube_node_addresses() {
  kube_ctl get nodes -o json 2>/dev/null \
    | jq -r '[.items[].status.addresses[]? | select(.type == "InternalIP" or .type == "ExternalIP") | .address
              | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))] | unique | join(" ")' 2>/dev/null || true
}

# kube_status_json <server version> — status --json's runtime object under
# kubernetes: {name, version, rootless, uid, …, context, checks}.
kube_status_json() {
  local checks
  checks="$(kube_host_checks | jq -Rsc 'split("\n") | map(select(. != "") | split("\t") | {status: .[0], text: (.[1:] | join("\t"))})')"
  jq -nc --arg v "${1:-}" --argjson u "$(id -u)" --arg ctx "${PORTCULLIS_KUBE_CONTEXT:-}" --argjson c "$checks" \
    '{name: "kubernetes", version: (if $v == "" then null else $v end), rootless: false, uid: $u,
      subuid_start: null, subuid_count: null, subgid_start: null, subgid_count: null, port_start: null,
      context: $ctx, checks: $c}'
}

# ── rt_* on kubernetes (common.sh dispatches here) ────────
# Every core service is a Deployment named after it in the core namespace,
# its pod labelled portcullis.io/component=<service>, its container named
# after it too (charts/portcullis).

_KUBE_COMPONENT="portcullis.io/component"

# _rtk_pods_json <service> — the service's pods (JSON list).
_rtk_pods_json() {
  kube_ctl -n "$(kube_ns)" get pods -l "$_KUBE_COMPONENT=$1" -o json 2>/dev/null | jq -c '.items // []' 2>/dev/null
}

# The rt_health vocabulary from one pod: no probe → running; Ready →
# healthy; the startup probe not passed yet → starting; else unhealthy;
# a pod that isn't running (or a container waiting in a crash loop) → exited.
_KUBE_POD_HEALTH_JQ='
  def health:
    (.status.containerStatuses // [] | .[0] // {}) as $cs
    | (.spec.containers[0] // {}) as $c
    | if (.status.phase // "") == "Pending" then "starting"
      elif (.status.phase // "") != "Running" then "exited"
      elif ($cs.state.waiting.reason // "") == "CrashLoopBackOff" then "exited"
      elif ($c.readinessProbe == null) then "running"
      elif ($cs.ready == true) then "healthy"
      elif ($cs.started != true) then "starting"
      else "unhealthy" end;'

_rtk_health() {
  local pods
  pods="$(_rtk_pods_json "$1")" || { echo missing; return 0; }
  printf '%s' "$pods" | jq -r "$_KUBE_POD_HEALTH_JQ"' if length == 0 then "missing" else (.[0] | health) end' 2>/dev/null || echo missing
}

_rtk_running() {
  [ "$(_rtk_pods_json "$1" | jq -r '[.[] | select(.status.phase == "Running")] | length' 2>/dev/null)" -gt 0 ] 2>/dev/null
}

# _rtk_ps [--json] — the core pods as compose's JSON lines (Service, Name,
# State, Health, Status), so status reads one format.
_rtk_ps() {
  local all
  all="$(kube_ctl -n "$(kube_ns)" get pods -l "$_KUBE_COMPONENT" -o json 2>/dev/null)" || return 1
  if [ "${1:-}" = --json ]; then
    printf '%s' "$all" | jq -c "$_KUBE_POD_HEALTH_JQ"'
      .items[] | (.status.containerStatuses // [] | .[0] // {}) as $cs | health as $h
      | {Service: .metadata.labels["portcullis.io/component"], Name: .metadata.name,
         State: (if .status.phase == "Running" then "running" elif .status.phase == "Pending" then "created" else "exited" end),
         Health: (if $h == "running" then "" else $h end),
         Status: "\(.status.phase) (restarts \($cs.restartCount // 0))"}'
  else
    kube_ctl -n "$(kube_ns)" get pods -l "$_KUBE_COMPONENT"
  fi
}

_rtk_exec() {
  local svc="$1"
  shift
  [ "${1:-}" != -- ] || shift
  kube_ctl -n "$(kube_ns)" exec -i "deploy/$svc" -c "$svc" -- "$@"
}

# _rtk_logs <service> [compose logs options] — --tail / --since kept,
# -t → --timestamps, --no-color dropped.
_rtk_logs() {
  local svc="$1"
  shift
  local -a opts=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --tail=*|--since=*) opts+=("$1") ;;
      --tail|--since) opts+=("$1=$2"); shift ;;
      -t|--timestamps) opts+=(--timestamps) ;;
      --no-color) ;;
      *) fail "rt_logs: $1 is not supported on kubernetes" ;;
    esac
    shift
  done
  kube_ctl -n "$(kube_ns)" logs "deploy/$svc" -c "$svc" ${opts[@]+"${opts[@]}"}
}

# _rtk_wait_ready <service>... — a pod of each service is Running (as
# docker's start / restart: health is the caller's wait_healthy).
_rtk_wait_ready() {
  local svc
  for svc in "$@"; do
    kube_ctl -n "$(kube_ns)" wait --for=jsonpath='{.status.phase}'=Running pod -l "$_KUBE_COMPONENT=$svc" --timeout=300s >/dev/null || return 1
  done
}

_rtk_restart() {
  local svc
  for svc in "$@"; do
    kube_ctl -n "$(kube_ns)" rollout restart "deploy/$svc" >/dev/null || return 1
  done
  _rtk_wait_ready "$@"
}

# _rtk_stop <service>... — scale to 0 and wait until its pods are gone.
_rtk_stop() {
  local svc
  for svc in "$@"; do
    kube_ctl -n "$(kube_ns)" scale "deploy/$svc" --replicas=0 >/dev/null || return 1
    kube_ctl -n "$(kube_ns)" wait --for=delete pod -l "$_KUBE_COMPONENT=$svc" --timeout=180s >/dev/null 2>&1 || true
  done
}

_rtk_start() {
  local svc
  for svc in "$@"; do
    kube_ctl -n "$(kube_ns)" scale "deploy/$svc" --replicas=1 >/dev/null || return 1
  done
  _rtk_wait_ready "$@"
}

# _rtk_up_service [--deps] <service>... — the services are part of the
# release: scaled to 1 and waited for (their dependencies already are).
_rtk_up_service() {
  [ "$1" != --deps ] || shift
  _rtk_start "$@"
}

# ── the docker-only helpers' kubernetes forms ──

# _kube_keygen <svc> <uid> — `<svc> keygen` (an age identity, offline) in a
# one-shot pod of the service's image: no network label, no volume, its uid.
_kube_keygen() {
  local svc="$1" u="$2" img name spec
  kube_images_ready
  img="$(printf '%s' "$_K_IMAGES" | jq -r --arg s "$svc" '.[$s] // empty')"
  [ -n "$img" ] || fail "no image for $svc"
  name="keygen-$svc-$(openssl rand -hex 3)"
  spec="$(N="$name" IMG="$img" U="$u" S="$svc" jq -nc '
    {apiVersion: "v1", kind: "Pod", metadata: {name: env.N, labels: {"portcullis.io/component": "keygen"}},
     spec: {restartPolicy: "Never", automountServiceAccountToken: false, enableServiceLinks: false,
       securityContext: {runAsNonRoot: true, runAsUser: (env.U | tonumber), runAsGroup: (env.U | tonumber), seccompProfile: {type: "RuntimeDefault"}},
       containers: [{name: env.N, image: env.IMG, command: [env.S, "keygen"],
         resources: {limits: {memory: "64Mi"}, requests: {memory: "64Mi"}},
         securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}}]}}')"
  kube_ctl -n "$(kube_ns)" run "$name" --image="$img" --restart=Never --rm -i --quiet --overrides="$spec" </dev/null
}

# _kube_acme_account_uri — Traefik's ACME account URI from acme.json on the
# traefik-acme PVC (read-only, as Traefik's uid, the domains image's reader).
_kube_acme_account_uri() {
  local pod uri rc=0
  _kube_volume_exists traefik_acme || return 0
  pod="$(_kube_helper_pod traefik-acme 65532:65532 ro "$(_kube_image_of domains)")" || return 1
  uri="$(kube_ctl -n "$(kube_ns)" exec "$pod" -- domains traefik-account-uri /vol/acme.json 2>/dev/null | head -n1)" || rc=$?
  _kube_helper_done "$pod"
  case "$rc" in 0) ;; 3) return 0 ;; *) return 1 ;; esac
  printf '%s\n' "$uri"
}

# _kube_acme_exists / _kube_acme_clear / _kube_traefik_exists — config
# apply's ACME_STAGING flip on kubernetes (acme.json removed by a helper
# pod as Traefik's uid on its PVC).
_kube_acme_exists() { _kube_volume_exists traefik_acme; }
_kube_acme_clear() {
  local pod rc=0
  pod="$(_kube_helper_pod traefik-acme 65532:65532 rw "$PORTCULLIS_HELPER_IMAGE")" || return 1
  kube_ctl -n "$(kube_ns)" exec "$pod" -- rm -f /vol/acme.json || rc=$?
  _kube_helper_done "$pod"
  return "$rc"
}
_kube_traefik_exists() { kube_ctl -n "$(kube_ns)" get deploy traefik >/dev/null 2>&1; }

# kube_revocation_bump — cert revoke / sync: the certs-revocation ConfigMap
# synced now, then group-gate's pod annotation portcullis.io/rev bumped so
# the kubelet resyncs the volume at once (enforced within 10 s).
kube_revocation_bump() {
  local d ns
  ns="$(kube_ns)"
  d="$(mktemp -d)"
  cp "$PORTCULLIS_ROOT/certs/revocation/revoked-serials.txt" "$d/" || { rm -rf "$d"; return 1; }
  kube_ctl create configmap certs-revocation -n "$ns" --from-file="$d" --dry-run=client -o yaml \
    | kube_ctl apply --server-side --force-conflicts --field-manager="$KUBE_FIELD_MANAGER" -f - >/dev/null || { rm -rf "$d"; return 1; }
  rm -rf "$d"
  kube_ctl -n "$ns" annotate pod -l "$_KUBE_COMPONENT=group-gate" --overwrite "portcullis.io/rev=$(date -u +%Y%m%dT%H%M%SZ)-$$" >/dev/null
}

# kube_vpn_reserved — what a built-in VPN subnet may not overlap on
# kubernetes: the pod and service CIDRs and every node address (instead of
# Docker's networks), one per line.
kube_vpn_reserved() {
  local a
  printf '%s\n' "${PORTCULLIS_POD_CIDR:?}" "${PORTCULLIS_SERVICE_CIDR:?}"
  for a in ${PORTCULLIS_KUBE_NODE_ADDRESSES:-$(kube_node_addresses)}; do printf '%s/32\n' "$a"; done
}

# kube_status_extra — status --json's kubernetes fields: netpol (the CLI's
# probe ConfigMap), admission (the six bindings), dns_shadows (an app
# Service named like a core one), kube_api_public (K8).
kube_status_extra() {
  local np adm b shadows pub api=false a
  np="$(kube_ctl -n "$(kube_apps_ns)" get configmap portcullis-netpol-probe -o json 2>/dev/null | jq -r '.data.proven_at // empty' 2>/dev/null || true)"
  adm=ok
  [ -z "$(kube_bindings_missing)" ] || adm=missing
  shadows="$(jq -cn --argjson core "$(kube_ctl -n "$(kube_ns)" get services -o json 2>/dev/null | jq -c '[.items[].metadata.name]' 2>/dev/null || echo '[]')" \
    --argjson apps "$(kube_ctl -n "$(kube_apps_ns)" get services -o json 2>/dev/null | jq -c '[.items[].metadata.name]' 2>/dev/null || echo '[]')" \
    '[$apps[] | select(. as $a | $core | index($a))]')"
  pub="$(_kube_public_ipv4)"
  if [ -n "$pub" ]; then
    for a in 6443 10250; do _kube_tcp_open "$pub" "$a" && api=true; done
  fi
  jq -nc --arg np "$np" --arg adm "$adm" --argjson sh "$shadows" --argjson api "$api" \
    '{netpol: (if $np == "" then "unproven" else "proven" end), netpol_proven_at: (if $np == "" then null else $np end),
      admission: $adm, dns_shadows: $sh, kube_api_public: $api}'
}

_rtk_kill() { _rtk_exec "$1" -- kill -s "$2" 1; }

_rtk_image() {
  _rtk_pods_json "$1" | jq -r '[.[] | select(.status.phase == "Running") | (.status.containerStatuses // [])[0] | select(. != null) | "\(.image) (\(.imageID))"][0] // empty' 2>/dev/null || true
}

_rtk_started_at() {
  _rtk_pods_json "$1" | jq -r '[.[] | (.status.containerStatuses // [])[0].state.running.startedAt // empty][0] // empty' 2>/dev/null || true
}

_rtk_services() {
  kube_ctl -n "$(kube_ns)" get deployments -o json 2>/dev/null | jq -r '.items[].metadata.name' 2>/dev/null
}

_rtk_require_tools() {
  require_cmd kubectl helm jq
}

# _rtk_down — every Deployment of both namespaces scaled to 0 (never `helm
# uninstall`: the release, its PVCs and Secrets stay).
_rtk_down() {
  local ns
  for ns in "$(kube_ns)" "$(kube_apps_ns)"; do
    kube_ctl -n "$ns" scale deployment --all --replicas=0 >/dev/null || fail "could not scale the Deployments in $ns to 0"
  done
}

# kube_init_cluster — init / up / upgrade under kubernetes, before anything
# is deployed: the cluster setup (namespaces, storage, CRDs, admission),
# then NetworkPolicy enforcement must be proven (spec §6), else nothing is
# deployed.
kube_init_cluster() {
  kube_images_ready
  kube_cluster_setup
  kube_netpol_probe || fail "NetworkPolicy enforcement isn't proven (see above): nothing is deployed"
  _K_PROBED=1
}

# kube_images_ready — K1 local images built + imported (once per run), then
# every image resolved to a digest (KUBE_HUB_IMAGE among them).
kube_images_ready() {
  if [ "${PORTCULLIS_KUBE_IMAGES:-registry}" = local ] && [ -z "${_K_LOCAL:-}" ]; then kube_build_local; fi
  [ -n "${_K_IMAGES:-}" ] || kube_resolve_images
}

# ── cluster setup (Task 14) ───────────────────────────────

KUBE_FIELD_MANAGER="portcullis-cli"

kube_applied_file() { echo "$PORTCULLIS_ROOT/secrets/kube/applied.json"; }

# _kube_applied_set <key> <value> — record a step in secrets/kube/applied.json
# (0600, written atomically) only after it succeeded. A record for the
# operator only: nothing reads it to skip work (every run re-applies).
_kube_applied_set() {
  local f tmp
  f="$(kube_applied_file)"
  (umask 077 && mkdir -p "$(dirname "$f")")
  [ -s "$f" ] || (umask 077 && echo '{}' > "$f")
  tmp="$(mktemp "$f.XXXXXX")"
  K="$1" V="$2" jq '.[env.K] = env.V' "$f" > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$f" || { rm -f "$tmp"; fail "could not write $f"; }
}

# _kube_sha <file>... — sha256 over the files' contents (in order).
_kube_sha() { cat "$@" | { sha256sum 2>/dev/null || shasum -a 256; } | awk '{print $1}'; }

# _kube_apply_files <file>... — server-side apply, our field manager.
_kube_apply_files() {
  local f
  for f in "$@"; do
    kube_ctl apply --server-side --force-conflicts --field-manager="$KUBE_FIELD_MANAGER" -f "$f" >/dev/null || return 1
  done
}

# kube_namespace_apply <name> <enforce> <warn> <audit> — the namespace with
# its PSA labels and K11's ownership label + install annotation.
kube_namespace_apply() {
  [ -n "${PORTCULLIS_KUBE_INSTALL_ID:-}" ] || fail "PORTCULLIS_KUBE_INSTALL_ID is not set (.env): refusing to create or adopt namespaces"
  N="$1" E="$2" W="$3" A="$4" L="$KUBE_MANAGED_LABEL" AN="$KUBE_INSTALL_ANNOTATION" ID="$PORTCULLIS_KUBE_INSTALL_ID" jq -n '
    {apiVersion: "v1", kind: "Namespace",
     metadata: {name: env.N,
       labels: {(env.L): "portcullis", "pod-security.kubernetes.io/enforce": env.E,
                "pod-security.kubernetes.io/warn": env.W, "pod-security.kubernetes.io/audit": env.A},
       annotations: {(env.AN): env.ID}}}' \
    | kube_ctl apply --server-side --force-conflicts --field-manager="$KUBE_FIELD_MANAGER" -f - >/dev/null
}

# kube_admission_params <hub image> — the params ConfigMap's keys as
# "key<TAB>value" lines (kube/admission/params.tmpl.yaml lists them).
kube_admission_params() {
  local hub="$1" ns roots nodes api a ep
  ns="$(kube_ns)"
  roots="${HUB_OVERRIDE_BIND_ROOTS:-/srv:/mnt:/media}"
  nodes="" api=""
  for a in ${PORTCULLIS_KUBE_NODE_ADDRESSES:-$(kube_node_addresses)}; do nodes+="${nodes:+ }$a/32"; done
  for ep in ${PORTCULLIS_KUBE_API_ENDPOINTS:-}; do api+="${api:+ }${ep%:*}/32"; done
  [ -n "$nodes" ] || fail "no node address (PORTCULLIS_KUBE_NODE_ADDRESSES): refusing to write admission params that couldn't exclude the nodes"
  [ -n "$api" ] || fail "no kube API endpoint (PORTCULLIS_KUBE_API_ENDPOINTS): refusing to write admission params"
  local me
  me="$(kube_ctl auth whoami -o json 2>/dev/null | jq -r '.status.userInfo.username // empty' 2>/dev/null || true)"
  [ -n "$me" ] || fail "can't tell this CLI's own identity (kubectl auth whoami): refusing to write admission params"
  local reserved maxprio
  reserved="$(kube_reserved_hosts)" || exit 1
  maxprio="$(jq -r '.maxAppPriority | select(type == "number" and . >= 0)' "$PORTCULLIS_HOME/charts/portcullis/core-routes.json" 2>/dev/null || true)"
  [ -n "$maxprio" ] || fail "charts/portcullis/core-routes.json has no maxAppPriority: refusing to write admission params"
  printf '%s\t%s\n' \
    hubImage "$hub" \
    hubServiceAccount "system:serviceaccount:$ns:portcullis-hub" \
    bindRoots "${roots//:/ }" \
    corePorts "80 443 ${PORTCULLIS_VPN_PORT:-51820} 8000 8081 8443 8444" \
    podCIDR "${PORTCULLIS_POD_CIDR:?}" \
    serviceCIDR "${PORTCULLIS_SERVICE_CIDR:?}" \
    nodeAddresses "$nodes" \
    apiAddresses "$api" \
    kubeDNS "kube-system:k8s-app=kube-dns" \
    traefik "$ns:portcullis.io/component=traefik" \
    mcpGate "$ns:portcullis.io/component=mcp-gate" \
    wg "$ns:portcullis.io/component=wg" \
    fileMiddlewares "$KUBE_FILE_NAMES" \
    cliUsername "$me" \
    appsNamespace "$(kube_apps_ns)" \
    edgeNamespace "$KUBE_EDGE_NS" \
    edgeCoreMiddlewares "$KUBE_EDGE_CORE_MIDDLEWARES" \
    reservedHosts "$reserved" \
    maxAppPriority "$maxprio"
}

# kube_reserved_hosts — every host a core route serves (the chart's
# core-routes.json, the same list ingressroutes-core.yaml renders): the apex
# and <subdomain>.<domain>, lowercase, space-separated.
kube_reserved_hosts() {
  local d="${PORTCULLIS_DOMAIN:-}"
  [ -n "$d" ] || fail "PORTCULLIS_DOMAIN is not set: refusing to write admission params without the reserved hosts"
  D="${d,,}" jq -r '[env.D] + [.subdomains[] | . + "." + env.D] | join(" ")' "$PORTCULLIS_HOME/charts/portcullis/core-routes.json"
}

# kube_admission_params_apply <hub image> — the admission params and
# bindings for this params generation (the sha256 of every key=value, 16
# hex), create-before-delete so no object is ever unbound (contract K6):
#   1. ConfigMap portcullis-admission-params-<gen> (kube_admission_params +
#      generation; replaced whole);
#   2. bindings.yaml's six bindings as <name>-<gen> on those params (labels
#      portcullis.io/binding = the base name, portcullis.io/params-generation);
#      older generations' bindings stay and judge too (stricter, fail safe);
#   3. kube_admission_probe <gen>: the <gen> bindings are live with these
#      params, within KUBE_ADMISSION_PROBE_WAIT (60) s — else refused, the
#      older bindings kept;
#   4. only then every other generation's bindings and params are deleted;
#   5. every owner=hub object in the edge namespace is re-judged (server
#      dry-run replace as the probe identity); one the policies now refuse
#      is deleted and named.
# A ConfigMap is never replaced under a live binding, so the API server's
# stale-params cache (seen on k3s 1.37 after a key-set change) can't apply.
kube_admission_params_apply() {
  local hub="$1" adm="$PORTCULLIS_HOME/kube/admission" tmp gen params pns
  # The params live in the core namespace: no Role of the Hub (or any other
  # ServiceAccount) there, so nothing judged by them can rewrite them.
  pns="$(kube_ns)"
  # Captured first: a refusal inside it (no node address, no identity, no
  # domain) must stop the setup, which a process substitution would hide.
  params="$(kube_admission_params "$hub")" || fail "the admission params can't be built (see above): nothing written"
  tmp="$(mktemp -d)"
  mkdir "$tmp/data"
  while IFS=$'\t' read -r f ep; do printf '%s' "$ep" > "$tmp/data/$f"; done <<< "$params"
  gen="$(printf '%s\n' "$params" | LC_ALL=C sort | { sha256sum 2>/dev/null || shasum -a 256; } | cut -c1-16)"
  printf '%s' "$gen" > "$tmp/data/generation"
  kube_ctl create configmap "portcullis-admission-params-$gen" -n "$pns" --from-file="$tmp/data" --dry-run=client -o json \
    | G="$gen" jq '.metadata.labels = {"app.kubernetes.io/managed-by": "portcullis", "portcullis.io/params-generation": env.G}' > "$tmp/params.json" \
    && kube_ctl create -f "$adm/bindings.yaml" --dry-run=client -o json \
    | G="$gen" NS="$pns" jq -s '{apiVersion: "v1", kind: "List", items: [.[] | (if .kind == "List" then .items[] else . end)
        | .metadata.labels = {"app.kubernetes.io/managed-by": "portcullis", "portcullis.io/binding": .metadata.name, "portcullis.io/params-generation": env.G}
        | .metadata.name += "-" + env.G
        | .spec.paramRef.name = "portcullis-admission-params-" + env.G | .spec.paramRef.namespace = env.NS]}' > "$tmp/bindings.json" \
    || { rm -rf "$tmp"; fail "could not build the admission params / bindings"; }
  [ "$(jq '.items | length' "$tmp/bindings.json")" = "$(printf '%s\n' $KUBE_BINDINGS | wc -l | tr -d ' ')" ] \
    || { rm -rf "$tmp"; fail "kube/admission/bindings.yaml doesn't hold the $(printf '%s\n' $KUBE_BINDINGS | wc -l | tr -d ' ') bindings KUBE_BINDINGS names"; }
  _kube_put "$tmp/params.json" || { rm -rf "$tmp"; fail "could not write portcullis-admission-params-$gen"; }
  _kube_apply_files "$tmp/bindings.json" || { rm -rf "$tmp"; fail "could not create the admission bindings of params generation $gen: the older ones still judge"; }
  _kube_applied_set cluster.params "$gen"
  rm -rf "$tmp"
  kube_admission_probe "$gen" || fail "the admission bindings of params generation $gen aren't live with their params (see above): the older bindings still judge; nothing deployed"
  # Only now: the other generations.
  local old
  old="$(kube_ctl get validatingadmissionpolicybinding -l "portcullis.io/binding,portcullis.io/params-generation!=$gen" -o name 2>/dev/null)" \
    || fail "can't list the older admission bindings"
  if [ -n "$old" ]; then
    info "Cluster setup: params generation $gen is live: removing the older bindings..."
    # shellcheck disable=SC2086  # resource names
    kube_ctl delete $old --wait >/dev/null || fail "could not delete the older admission bindings (they still judge: stricter, not unsafe)"
  fi
  _kube_params_gc "$gen"
  kube_edge_rejudge
}

# _kube_params_gc <gen> — older params ConfigMaps no binding names any more
# are deleted only once they have been orphaned for KUBE_PARAMS_GRACE (300)
# s: the API server keeps a deleted binding for a while, and a binding whose
# params are gone denies every request (parameterNotFoundAction Deny — even
# the CLI's own). The first run that finds one orphaned stamps it. Only
# ConfigMaps managed by portcullis and named portcullis-admission-params-<16
# hex> are touched; a stamp that isn't 1–12 digits is skipped (never
# evaluated: the value comes from the cluster).
_kube_params_gc() {
  local gen="$1" pns cms now name at
  pns="$(kube_ns)"
  now="$(date +%s)"
  cms="$(kube_ctl -n "$pns" get configmap -l "app.kubernetes.io/managed-by=portcullis,portcullis.io/params-generation,portcullis.io/params-generation!=$gen" -o json 2>/dev/null)" \
    || { warn "could not list older admission params"; return 0; }
  while IFS=$'\t' read -r name at; do
    [[ "$name" =~ ^portcullis-admission-params-[0-9a-f]{16}$ ]] || { [ -z "$name" ] || warn "skipping ConfigMap $name (not an admission params name)"; continue; }
    if [ -z "$at" ]; then
      kube_ctl -n "$pns" annotate configmap "$name" "portcullis.io/orphaned-at=$now" >/dev/null || warn "could not stamp $name"
    elif [[ ! "$at" =~ ^[0-9]{1,12}$ ]]; then
      warn "skipping $name: its portcullis.io/orphaned-at isn't a timestamp"
    elif [ "$((now - 10#$at))" -ge "${KUBE_PARAMS_GRACE:-300}" ]; then
      kube_ctl -n "$pns" delete configmap "$name" >/dev/null || warn "could not delete the older admission params $name"
    fi
  done < <(printf '%s' "$cms" | jq -r '.items[] | [.metadata.name, (.metadata.annotations["portcullis.io/orphaned-at"] // "")] | @tsv' 2>/dev/null || true)
}

# kube_edge_rejudge — every owner=hub IngressRoute / Middleware of the edge
# namespace through the live policies (server dry-run replace as the Hub's
# ServiceAccount, with system:masters only so RBAC lets it reach
# admission); one they refuse is deleted and named.
# Any other failure stops the setup.
kube_edge_rejudge() {
  local kind list n i obj out
  for kind in ingressroutes.traefik.io middlewares.traefik.io; do
    list="$(kube_ctl -n "$KUBE_EDGE_NS" get "$kind" -l portcullis.io/owner=hub -o json)" || fail "can't list the Hub's $kind in $KUBE_EDGE_NS"
    n="$(printf '%s' "$list" | jq '.items | length')"
    for ((i = 0; i < n; i++)); do
      obj="$(printf '%s' "$list" | jq -c --argjson i "$i" '.items[$i]')"
      if ! out="$(printf '%s' "$obj" | kube_ctl -n "$KUBE_EDGE_NS" --as="$(_kube_hub_sa)" --as-group=system:masters replace --dry-run=server -f - 2>&1)"; then
        case "$out" in
          *"ValidatingAdmissionPolicy"*"denied request"*)
            warn "the admission policies refuse ${kind%%.*} $(printf '%s' "$obj" | jq -r .metadata.name) (instance $(printf '%s' "$obj" | jq -r '.metadata.labels["portcullis.io/instance"] // "?"')): deleted (${out##*denied request: })"
            kube_ctl -n "$KUBE_EDGE_NS" delete "$kind" "$(printf '%s' "$obj" | jq -r .metadata.name)" >/dev/null || fail "could not delete a refused ${kind%%.*}" ;;
          *) fail "could not re-judge ${kind%%.*} $(printf '%s' "$obj" | jq -r .metadata.name): ${out:0:300}" ;;
        esac
      fi
    done
  done
}

# kube_bindings_missing — "" when each of KUBE_BINDINGS is live as a
# binding labelled portcullis.io/binding=<name> on existing params, else why.
kube_bindings_missing() {
  local live b
  live="$(kube_ctl get validatingadmissionpolicybinding -l portcullis.io/binding -o json 2>/dev/null)" || { echo "the admission bindings can't be listed"; return 0; }
  for b in $KUBE_BINDINGS; do
    printf '%s' "$live" | B="$b" jq -e '[.items[] | select(.metadata.labels["portcullis.io/binding"] == env.B)] | length > 0' >/dev/null 2>&1 \
      || { echo "the binding $b is missing"; return 0; }
  done
}

_kube_hub_sa() { echo "system:serviceaccount:$(kube_ns):portcullis-hub"; }

# kube_admission_probe <gen> — every binding of params generation <gen> is
# live with its params. As the Hub's ServiceAccount (the identity the
# policies judge; system:masters only so RBAC lets the request reach
# admission), server dry-run, nothing kept:
#   - one object per policy annotated portcullis.io/params-generation=<gen>
#     (a Pod, a Deployment, a Service, an apps IngressRoute, a NetworkPolicy,
#     an edge IngressRoute) is refused by <binding>-<gen> naming <gen> (each
#     policy refuses exactly its own params' generation first; older
#     generations' bindings let it by);
#   - a route on a reserved host is refused by an edge binding;
#   - the same route on a free host, unannotated, is admitted.
# Retried for KUBE_ADMISSION_PROBE_WAIT seconds (60).
kube_admission_probe() {
  local gen="${1:?}" d reserved i missing refused admitted out b
  d="${PORTCULLIS_DOMAIN:?}"
  reserved="$(kube_reserved_hosts)" || return 1
  reserved="${reserved%% *}"
  for ((i = 0; ; i += 3)); do
    missing="" refused=false admitted=false
    for b in $KUBE_BINDINGS; do
      if out="$(_kube_probe_object "$b" "$gen" 2>&1)"; then missing+=" $b (admitted)"; continue; fi
      case "$out" in *"binding '$b-$gen'"*"admission probe: params generation $gen in effect"*) ;; *) missing+=" $b" ;; esac
    done
    if ! out="$(_kube_probe_route "$reserved" "" 2>&1)"; then
      case "$out" in *"binding 'portcullis-edge-guard-routes-"*"reserved core hostname"*) refused=true ;; esac
    fi
    if _kube_probe_route "portcullis-admission-probe.${d,,}" "" >/dev/null 2>&1; then admitted=true; fi
    [ -n "$missing" ] || [ "$refused $admitted" != "true true" ] || return 0
    [ "$i" -lt "${KUBE_ADMISSION_PROBE_WAIT:-60}" ] || break
    sleep 3
  done
  warn "admission probe after ${KUBE_ADMISSION_PROBE_WAIT:-60} s: ${missing:+not live with generation $gen:$missing; }a route on $reserved $([ "$refused" = true ] && echo refused || echo "not refused"), one on a free host $([ "$admitted" = true ] && echo admitted || echo refused)"
  return 1
}

# _kube_probe_object <binding> <gen> — a server dry-run, as the Hub, of one
# object the binding's policy judges, annotated with the generation. Each
# object is otherwise admissible (an older generation's binding must let it
# by: the API server reports one refusal, from any binding).
_kube_probe_object() {
  local b="$1" ns kind
  case "$b" in
    portcullis-edge-guard-routes) _kube_probe_route "portcullis-admission-probe.${PORTCULLIS_DOMAIN,,}" "$2"; return ;;
    portcullis-apps-guard-pods) kind=Pod ;;
    portcullis-apps-guard-workloads) kind=Deployment ;;
    portcullis-apps-guard-services) kind=Service ;;
    portcullis-apps-guard-traefik) kind=IngressRoute ;;
    portcullis-apps-guard-netpol) kind=NetworkPolicy ;;
    *) echo "no probe object for $b"; return 1 ;;
  esac
  ns="$(kube_apps_ns)"
  K="$kind" G="$2" IMG="${KUBE_HUB_IMAGE:-$PORTCULLIS_HELPER_IMAGE}" jq -n '
    {name: "portcullis-admission-probe--probe", labels: {"portcullis.io/instance": "portcullis-admission-probe"},
     annotations: {"portcullis.io/params-generation": env.G}} as $m
    | {name: "c", image: env.IMG, command: ["true"]} as $c
    | if env.K == "Pod" then {apiVersion: "v1", kind: "Pod", metadata: $m, spec: {automountServiceAccountToken: false, containers: [$c]}}
      elif env.K == "Deployment" then {apiVersion: "apps/v1", kind: "Deployment", metadata: $m,
        spec: {selector: {matchLabels: $m.labels}, template: {metadata: {labels: $m.labels}, spec: {automountServiceAccountToken: false, containers: [$c]}}}}
      elif env.K == "Service" then {apiVersion: "v1", kind: "Service", metadata: $m, spec: {ports: [{port: 80}], selector: $m.labels}}
      elif env.K == "IngressRoute" then {apiVersion: "traefik.io/v1alpha1", kind: "IngressRoute", metadata: $m,
        spec: {routes: [{match: "Host(`portcullis-admission-probe.invalid`)", kind: "Rule", services: [{name: "x", port: 80}]}]}}
      else {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", metadata: $m,
        spec: {podSelector: {matchLabels: ($m.labels + {"portcullis.io/egress": "true"})}, policyTypes: ["Ingress"]}} end' \
    | kube_ctl -n "$ns" --as="$(_kube_hub_sa)" --as-group=system:masters create --dry-run=server -f -
}

# _kube_probe_route <host> <generation|""> — a server dry-run of a
# Hub-shaped IngressRoute (annotated with the generation when given).
_kube_probe_route() {
  H="$1" G="$2" APPS="$(kube_apps_ns)" jq -n '{apiVersion: "traefik.io/v1alpha1", kind: "IngressRoute",
      metadata: ({name: "portcullis-admission-probe", labels: {"portcullis.io/owner": "hub", "portcullis.io/instance": "portcullis-admission-probe"}}
        + (if env.G == "" then {} else {annotations: {"portcullis.io/params-generation": env.G}} end)),
      spec: {entryPoints: ["websecure"], routes: [{match: ("Host(`" + env.H + "`)"), kind: "Rule",
        services: [{name: "portcullis-admission-probe", namespace: env.APPS, port: 80}]}],
        tls: {options: {name: "authaware@file"}}}}' \
    | kube_ctl -n "$KUBE_EDGE_NS" --as="$(_kube_hub_sa)" --as-group=system:masters create --dry-run=server -f -
}

# The owner=core Middlewares of portcullis-edge (the chart's four and the
# CLI's hub-proxy-secret): no Hub route or chain may name them.
KUBE_EDGE_CORE_MIDDLEWARES="hub-proxy-secret portcullis-auth-console portal-path portal-vpn-path directory-redirect"

# The @file names apps may use (K15, contract §5): middlewares.yml's six,
# the core middlewares and the three core services of traefik-dynamic.
KUBE_FILE_NAMES="client-headers@file client-cert-pem@file rate-limit@file rate-limit-auth@file security-headers@file strip-client-forwarded@file portcullis-auth@file portcullis-auth-ext@file portcullis-groups@file portcullis-groups-vpn@file portcullis-public-guard@file portcullis-public-guard-vpn@file vpn-required-path@file group-gate@file forward-auth-ext@file mcp-gate@file"

# _kube_configmap_from <name> <namespace> <dir> — a ConfigMap whose keys are
# the dir's files (kubectl builds it; applied server-side from stdin).
_kube_configmap_from() {
  kube_ctl create configmap "$1" -n "$2" --from-file="$3" --dry-run=client -o yaml \
    | kube_ctl apply --server-side --force-conflicts --field-manager="$KUBE_FIELD_MANAGER" -f - >/dev/null
}

# kube_cluster_setup — idempotent, server-side; each step is recorded in
# secrets/kube/applied.json only after it succeeded:
#   namespaces  portcullis (restricted), portcullis-apps (enforce privileged,
#               warn / audit baseline), portcullis-storage (enforce
#               privileged: its helpers need hostPath; warn / audit
#               baseline; pinned by kube/storage/admission.yaml),
#               portcullis-edge (restricted: Traefik's only watched
#               namespace, no pod, no Secret), all with K11's label +
#               annotation;
#   storage     the provisioner portcullis.io/local-path (kube/storage),
#               its ConfigMap, the StorageClasses, its deny policy + API egress;
#   crds        the Traefik CRDs (K14: kubectl --server-side, never Helm);
#   admission   the six VAPs and their six bindings (kube/admission);
#   params      portcullis-admission-params: the Hub's resolved digest
#               (KUBE_HUB_IMAGE, name@sha256:…), roots, ports, networks, peers.
kube_cluster_setup() {
  local hub="${KUBE_HUB_IMAGE:-}" tmp f ep
  [[ "$hub" =~ ^[a-z0-9.-]+(:[0-9]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]] \
    || fail "the Hub's image isn't resolved to a digest (KUBE_HUB_IMAGE=${hub:-unset}): refusing to write admission params that pin another helper image"
  local st="$PORTCULLIS_HOME/kube/storage" adm="$PORTCULLIS_HOME/kube/admission" crds
  crds="$(find "$PORTCULLIS_HOME/charts/portcullis/crds" -name 'traefik-*.yaml' | sort | head -n1)"
  [ -n "$crds" ] || fail "no Traefik CRD bundle in charts/portcullis/crds"

  info "Cluster setup: namespaces..."
  kube_namespace_apply "$(kube_ns)" restricted restricted restricted || fail "could not create the namespace $(kube_ns)"
  kube_namespace_apply "$(kube_apps_ns)" privileged baseline baseline || fail "could not create the namespace $(kube_apps_ns)"
  kube_namespace_apply "$KUBE_STORAGE_NS" privileged baseline baseline || fail "could not create the namespace $KUBE_STORAGE_NS"
  kube_namespace_apply "$KUBE_EDGE_NS" restricted restricted restricted || fail "could not create the namespace $KUBE_EDGE_NS"
  _kube_applied_set cluster.namespaces "${PORTCULLIS_KUBE_INSTALL_ID}"

  info "Cluster setup: storage (portcullis.io/local-path)..."
  tmp="$(mktemp -d)"
  cp "$st/config.json" "$tmp/config.json"
  cp "$st/setup.sh" "$tmp/setup"
  cp "$st/teardown.sh" "$tmp/teardown"
  cp "$st/helper-pod.yaml" "$tmp/helperPod.yaml"
  if ! _kube_apply_files "$st/namespace.yaml" "$st/admission.yaml" \
       || ! _kube_configmap_from portcullis-local-path-config "$KUBE_STORAGE_NS" "$tmp" \
       || ! _kube_apply_files "$st/provisioner.yaml" "$st/storageclasses.yaml"; then
    rm -rf "$tmp"; fail "the storage setup failed (see above): nothing recorded"
  fi
  rm -rf "$tmp"
  # The provisioner's only egress: the kube API endpoints.
  # shellcheck disable=SC2086  # ip:port words
  printf '%s\n' ${PORTCULLIS_KUBE_API_ENDPOINTS:?} | jq -R . | jq -s --arg ns "$KUBE_STORAGE_NS" '
      {apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy",
       metadata: {name: "kube-api", namespace: $ns},
       spec: {podSelector: {matchLabels: {app: "portcullis-local-path"}}, policyTypes: ["Egress"],
              egress: [.[] | split(":") as $p | {to: [{ipBlock: {cidr: ($p[0] + "/32")}}], ports: [{protocol: "TCP", port: ($p[1] | tonumber)}]}]}}' \
    | kube_ctl apply --server-side --force-conflicts --field-manager="$KUBE_FIELD_MANAGER" -f - >/dev/null \
    || fail "could not apply the storage namespace's API egress policy"
  _kube_applied_set cluster.storage "$(_kube_sha "$st"/*)"

  info "Cluster setup: Traefik CRDs ($(basename "$crds" .yaml))..."
  _kube_apply_files "$crds" || fail "could not apply the Traefik CRDs"
  _kube_applied_set cluster.crds "$(_kube_sha "$crds")"

  info "Cluster setup: admission policies..."
  # The bindings are per params generation (kube_admission_params_apply).
  _kube_apply_files "$adm/policies.yaml" || fail "could not apply the admission policies (see above): nothing recorded"
  _kube_applied_set cluster.admission "$(_kube_sha "$adm/policies.yaml")"

  info "Cluster setup: admission params..."
  kube_admission_params_apply "$hub"

  # Traefik's Role reads every Secret of the edge namespace: none may be there.
  local n
  n="$(kube_ctl -n "$KUBE_EDGE_NS" get secrets -o json 2>/dev/null | jq -r '.items | length' 2>/dev/null || true)"
  [ "$n" = 0 ] || fail "the namespace $KUBE_EDGE_NS holds ${n:-an unreadable list of} Secrets: Traefik reads every Secret there, so it must hold none (delete them): nothing deployed"
}

# ══ Task 15: images, sync, values, the release ════════════

KUBE_CORE_BUILT="group-gate enroll domains mcp-gate wg"
KUBE_RELEASE="portcullis"

kube_dir() { echo "$PORTCULLIS_ROOT/secrets/kube"; }
kube_values_file() { echo "$(kube_dir)/values.yaml"; }
kube_digests_file() { echo "$(kube_dir)/digests.json"; }

# ── images (K1) ──

# _kube_registry_digest <name:tag> — the registry's manifest(-list) digest
# for a tag (anonymous pull token; ghcr.io only: every tag ref is one of
# ours). Prints name@sha256:…; exit 1 when it can't be resolved.
_kube_registry_digest() {
  local ref="$1" host rest repo tag tok dig
  host="${ref%%/*}" rest="${ref#*/}"
  repo="${rest%:*}" tag="${rest##*:}"
  [ "$host" = ghcr.io ] && [ "$repo" != "$rest" ] || { echo "can't resolve $ref: only ghcr.io tags are resolved (pin it name@sha256:…)" >&2; return 1; }
  tok="$(curl -fsS --max-time 20 "https://ghcr.io/token?scope=repository:$repo:pull" | jq -r '.token // empty')" || return 1
  [ -n "$tok" ] || return 1
  dig="$(curl -fsSI --max-time 20 -H @<(printf 'Authorization: Bearer %s\n' "$tok") \
      -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
      "https://ghcr.io/v2/$repo/manifests/$tag" | tr -d '\r' | awk -F': ' 'tolower($1) == "docker-content-digest" { print $2 }')" || return 1
  [[ "$dig" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  echo "$host/$repo@$dig"
}

# _kube_local_import <local image> <svc> — K1 local: save the image from the
# builder (docker or podman) and import it into k3s's containerd as
# localhost/portcullis-<svc>:local; prints localhost/portcullis-<svc>@sha256:….
_kube_local_import() {
  local img="$1" svc="$2" name="localhost/portcullis-$2:local" builder dig
  builder=docker; command -v docker >/dev/null 2>&1 || builder=podman
  "$builder" tag "$img" "$name" >/dev/null || return 1
  "$builder" save "$name" | sudo k3s ctr -n k8s.io images import - >/dev/null || return 1
  dig="$(sudo k3s ctr -n k8s.io images ls "name==$name" 2>/dev/null | awk 'NR > 1 { print $3; exit }')"
  [[ "$dig" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  echo "localhost/portcullis-$svc@$dig"
}

# kube_build_local — K1 local (PORTCULLIS_KUBE_IMAGES=local; CI and
# development): every core-built image from this checkout, `docker build`
# or `podman build --format docker` (HEALTHCHECK kept), BEFORE anything is
# deployed (kcwait's "build before up"). Sets _K_LOCAL[<svc>] refs.
kube_build_local() {
  local svc builder img ref
  _K_LOCAL='{}'
  builder=docker; command -v docker >/dev/null 2>&1 || builder=podman
  for svc in $KUBE_CORE_BUILT; do
    img="portcullis-$svc:kube-local"
    info "Building $img ($builder build)..."
    # The image builder on this host (not a runtime: k3s has none): docker,
    # else podman with --format docker (the OCI format drops HEALTHCHECK).
    local -a fmt=()
    [ "$builder" != podman ] || fmt=(--format docker)
    "$builder" build ${fmt[@]+"${fmt[@]}"} -t "$img" "$PORTCULLIS_HOME/$svc" >&2 || fail "$builder build of $svc failed"
    ref="$(_kube_local_import "$img" "$svc")" || fail "could not import $img into k3s (sudo k3s ctr images import)"
    _K_LOCAL="$(printf '%s' "$_K_LOCAL" | S="$svc" R="$ref" jq -c '.[env.S] = env.R')"
  done
  # The Hub / Keycloak from a local image (CI: the same-named branches'):
  # HUB_IMAGE / KEYCLOAK_IMAGE without a registry (portcullis-hub:ci).
  for svc in hub:"${HUB_IMAGE:-}" keycloak:"${KEYCLOAK_IMAGE:-}"; do
    img="${svc#*:}" svc="${svc%%:*}"
    case "$img" in ''|*/*) continue ;; esac
    ref="$(_kube_local_import "$img" "$svc")" || fail "could not import $img into k3s"
    _K_LOCAL="$(printf '%s' "$_K_LOCAL" | S="$svc" R="$ref" jq -c '.[env.S] = env.R')"
  done
}

# kube_resolve_images — _K_IMAGES (JSON {svc: name@sha256:…}) for every
# entry of charts/portcullis/images.json: pinned refs as they are, tag refs
# (the five, the Hub, Keycloak; HUB_IMAGE / KEYCLOAK_IMAGE override) by the
# registry, or the local imports (K1 local). Nothing unresolved passes.
kube_resolve_images() {
  local json svc ref out="{}" r base
  json="$(jq -c '.images' "$PORTCULLIS_HOME/charts/portcullis/images.json")" || fail "charts/portcullis/images.json is unreadable"
  while IFS=$'\t' read -r svc ref; do
    case "$svc" in
      hub) [ -z "${HUB_IMAGE:-}" ] || ref="$HUB_IMAGE" ;;
      keycloak) [ -z "${KEYCLOAK_IMAGE:-}" ] || ref="$KEYCLOAK_IMAGE" ;;
    esac
    r="" base="$svc"
    [ "$svc" != dns-tool ] || base=domains
    [ "${PORTCULLIS_KUBE_IMAGES:-registry}" != local ] || r="$(printf '%s' "${_K_LOCAL:-{\}}" | B="$base" jq -r '.[env.B] // empty')"
    if [ -n "$r" ]; then
      :
    elif [[ "$ref" =~ ^(.+):[^/:@]+@(sha256:[0-9a-f]{64})$ ]]; then
      r="${BASH_REMATCH[1]}@${BASH_REMATCH[2]}"
    elif [[ "$ref" =~ ^[^@]+@sha256:[0-9a-f]{64}$ ]]; then
      r="$ref"
    else
      r="$(_kube_registry_digest "$ref")" || fail "could not resolve $ref to a digest (images.$svc): nothing deployed"
    fi
    out="$(printf '%s' "$out" | S="$svc" R="$r" jq -c '.[env.S] = env.R')"
  done < <(printf '%s' "$json" | jq -r 'to_entries[] | [.key, (if (.value | type) == "object" then .value.tag_ref else .value end)] | @tsv')
  _K_IMAGES="$out"
  KUBE_HUB_IMAGE="$(printf '%s' "$out" | jq -r '.hub')"
}

# ── sync: Secrets and ConfigMaps (files only, never argv) ──

# The secret variables the pods read (portcullis-env): the core secrets and
# the DNS providers' credentials present in .env.
KUBE_ENV_SECRETS="POSTGRES_PASSWORD KEYCLOAK_ADMIN_PASSWORD LLDAP_ADMIN_PASSWORD LLDAP_JWT_SECRET FORWARD_AUTH_CLIENT_SECRET FORWARD_AUTH_COOKIE_SECRET FORWARD_AUTH_REDIS_PASSWORD FORWARD_AUTH_EXT_REDIS_PASSWORD HUB_PROXY_SECRET CLOUDFLARE_API_TOKEN PORKBUN_API_KEY PORKBUN_SECRET_API_KEY AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_HOSTED_ZONE_ID DO_AUTH_TOKEN HETZNER_API_KEY HETZNER_API_TOKEN"

# secrets/ files never synced: the CLI's own (kube/), the Vault root token
# (nothing in the cluster mounts it),
# the endpoint CA's key, the host-specific addresses.
_kube_sync_skip() {
  case "$1" in
    kube/*|vault-init.json|domains/certs-endpoint/ca.key|domains/last-public-ipv4|domains/last-public-ipv6|domains/acme-relax.env|domains/public-ips.env|domains/main-domain.env|.gitkeep|*/.gitkeep) return 0 ;;
  esac
  return 1
}

# _kube_dir_hash <dir> — sha256 over the regular files' names and contents.
_kube_dir_hash() {
  (cd "$1" && find . -maxdepth 1 -type f | LC_ALL=C sort | while IFS= read -r f; do printf '%s\0' "$f"; cat "$f"; printf '\0'; done) \
    | { sha256sum 2>/dev/null || shasum -a 256; } | awk '{print $1}'
}

# _kube_stage <kind secret|configmap> <name> <dir> — queue one object.
_kube_stage() { _K_STAGED+=("$1|$2|$3"); }

# _kube_flatten <src tree> <dst dir> <values key> — a nested host tree as one
# flat ConfigMap (keys: the relative path, "/" → "__") and its items list
# (configItems.<values key>) to rebuild the tree in the pod.
_kube_flatten() {
  local src="$1" dst="$2" key="$3" rel k items="[]"
  mkdir -p "$dst"
  [ -d "$src" ] || { _K_ITEMS="$(printf '%s' "${_K_ITEMS:-{\}}" | K="$key" jq -c '.[env.K] = []')"; return 0; }
  while IFS= read -r rel; do
    rel="${rel#./}"
    k="${rel//\//__}"
    cp "$src/$rel" "$dst/$k"
    items="$(printf '%s' "$items" | K="$k" P="$rel" jq -c '. + [{key: env.K, path: env.P}]')"
  done < <(cd "$src" && find . -type f ! -name '.gitkeep' | LC_ALL=C sort)
  _K_ITEMS="$(printf '%s' "${_K_ITEMS:-{\}}" | K="$key" V="$items" jq -c '.[env.K] = (env.V | fromjson)')"
}

# kube_sync_stage — build every object's files in a 0600 staging dir
# (removed by the caller's trap): Secrets from secrets/ (one per directory,
# secrets-<path with - for />), portcullis-env from the secret variables,
# domains-env from its env files, the core's host config as ConfigMaps.
# Sets _K_STAGE (the dir), _K_STAGED (kind|name|dir) and _K_ITEMS.
kube_sync_stage() {
  local root="$PORTCULLIS_ROOT" st d rel name f v
  _K_STAGE="$(mktemp -d)"; chmod 700 "$_K_STAGE"
  _K_STAGED=() _K_ITEMS='{}'
  st="$_K_STAGE"
  # secrets/<dir>/<files> → Secret secrets-<dir>.
  while IFS= read -r d; do
    rel="${d#"$root/secrets"}"; rel="${rel#/}"
    [ -n "$rel" ] || continue
    case "$rel" in kube|kube/*) continue ;; esac
    name="secrets-${rel//\//-}"
    mkdir -p "$st/$name"; chmod 700 "$st/$name"
    for f in "$d"/*; do
      [ -f "$f" ] || continue
      _kube_sync_skip "$rel/${f##*/}" && continue
      cp "$f" "$st/$name/"
    done
    _kube_stage secret "$name" "$st/$name"
  done < <(find "$root/secrets" -type d | LC_ALL=C sort)
  # The secret variables, one file each (never argv, never logged).
  mkdir -p "$st/portcullis-env"; chmod 700 "$st/portcullis-env"
  for v in $KUBE_ENV_SECRETS; do
    [ -n "${!v:-}" ] || continue
    (umask 077 && printf '%s' "${!v}" > "$st/portcullis-env/$v")
  done
  _kube_stage secret portcullis-env "$st/portcullis-env"
  # domains' env files (public addresses, Traefik's ACME account).
  mkdir -p "$st/domains-env"
  for f in public-ips.env main-domain.env; do
    [ -f "$root/secrets/domains/$f" ] || continue
    while IFS= read -r line; do
      _env_parse_line "$line" || continue
      printf '%s' "$_ENV_VAL" > "$st/domains-env/$_ENV_KEY"
    done < "$root/secrets/domains/$f"
  done
  _kube_stage secret domains-env "$st/domains-env"
  # certs/: public files (ConfigMap certs), the TLS key (Secret secrets-certs),
  # revocation/ and truststore/.
  mkdir -p "$st/certs" "$st/secrets-certs" "$st/certs-revocation" "$st/certs-truststore"
  for f in "$root/certs"/*; do
    [ -f "$f" ] || continue
    case "${f##*/}" in server.key) cp "$f" "$st/secrets-certs/" ;; .*) ;; *) cp "$f" "$st/certs/" ;; esac
  done
  [ ! -d "$root/certs/revocation" ] || find "$root/certs/revocation" -maxdepth 1 -type f ! -name '.*' -exec cp {} "$st/certs-revocation/" \;
  [ ! -d "$root/certs/truststore" ] || find "$root/certs/truststore" -maxdepth 1 -type f ! -name '.*' -exec cp {} "$st/certs-truststore/" \;
  _kube_stage configmap certs "$st/certs"
  _kube_stage secret secrets-certs "$st/secrets-certs"
  _kube_stage configmap certs-revocation "$st/certs-revocation"
  _kube_stage configmap certs-truststore "$st/certs-truststore"
  # The checkout's config.
  mkdir -p "$st/config-traefik-dynamic"
  find "$PORTCULLIS_HOME/traefik/dynamic" -maxdepth 1 -type f -name '*.yml' -exec cp {} "$st/config-traefik-dynamic/" \;
  _kube_stage configmap config-traefik-dynamic "$st/config-traefik-dynamic"
  mkdir -p "$st/config-keycloak-realm" "$st/config-oauth2-proxy" "$st/config-group-gate" "$st/config-monitoring-blackbox"
  cp "$PORTCULLIS_HOME/keycloak/realm-export.json" "$st/config-keycloak-realm/"
  cp "$PORTCULLIS_HOME/oauth2-proxy/alpha.yaml" "$st/config-oauth2-proxy/"
  cp "$PORTCULLIS_HOME/group-gate/group-gate-map.conf" "$st/config-group-gate/"
  cp "$PORTCULLIS_HOME/monitoring/blackbox/blackbox.yml" "$st/config-monitoring-blackbox/"
  for f in config-keycloak-realm config-oauth2-proxy config-group-gate config-monitoring-blackbox; do _kube_stage configmap "$f" "$st/$f"; done
  _kube_flatten "$PORTCULLIS_HOME/vault" "$st/config-vault" vault
  _kube_flatten "$PORTCULLIS_HOME/keycloak/themes/portcullis" "$st/config-keycloak-theme" keycloakTheme
  _kube_flatten "$PORTCULLIS_HOME/monitoring/prometheus" "$st/config-monitoring-prometheus" prometheus
  # Traefik's metrics have their own Service on Kubernetes (the LB carries
  # 80 / 443 only).
  sed -i.bak 's/"traefik:8082"/"traefik-metrics:8082"/' "$st/config-monitoring-prometheus/prometheus.yml" && rm -f "$st/config-monitoring-prometheus/prometheus.yml.bak"
  _kube_flatten "$PORTCULLIS_HOME/monitoring/grafana/provisioning" "$st/config-monitoring-grafana-provisioning" grafanaProvisioning
  _kube_flatten "$PORTCULLIS_HOME/monitoring/grafana/dashboards" "$st/config-monitoring-grafana-dashboards" grafanaDashboards
  _kube_flatten "$PORTCULLIS_ROOT/monitoring/textfile" "$st/config-monitoring-textfile" textfile
  for f in config-vault config-keycloak-theme config-monitoring-prometheus config-monitoring-grafana-provisioning config-monitoring-grafana-dashboards config-monitoring-textfile; do
    _kube_stage configmap "$f" "$st/$f"
  done
}

# _kube_put <file> — the object exactly as in the file: replaced when it
# exists (a key added or changed by hand is gone, unlike an apply, which
# keeps other managers' fields), else created. Our field manager.
_kube_put() {
  if kube_ctl get -f "$1" -o name >/dev/null 2>&1; then
    kube_ctl replace --field-manager="$KUBE_FIELD_MANAGER" -f "$1" >/dev/null
  else
    kube_ctl create --field-manager="$KUBE_FIELD_MANAGER" -f "$1" >/dev/null
  fi
}

# kube_sync_secrets [--full] — stage everything and put each object whose
# LIVE content (data + binaryData, read with kubectl get) differs from the
# staged one, or that is missing: no local cache decides (a restore, a reset
# cluster or a hand edit is always corrected). --full (or KUBE_SYNC_FULL=1:
# restore) puts every object without comparing; an unreadable live list does
# too. Objects are built by `kubectl create … --from-file=<dir> --dry-run=client
# -o json` into the 0700 staging dir (never argv), and the hub-proxy-secret
# Middleware (its header holds the secret: built by jq from the environment)
# goes to the edge namespace, Traefik's only one. Sets _K_HASHES (JSON
# {name: content hash}) for the chart's rollout annotations.
kube_sync_secrets() {
  local full=false item kind name dir h ns want live
  [ "${1:-}" = --full ] || [ "${KUBE_SYNC_FULL:-}" = 1 ] && full=true
  ns="$(kube_ns)"
  kube_sync_stage
  _K_HASHES='{}'
  live="$_K_STAGE/.live" want="$_K_STAGE/.live/want.json"
  (umask 077 && mkdir -p "$live")
  if [ "$full" = false ]; then
    kube_ctl -n "$ns" get secrets -o json > "$live/secret.json" 2>/dev/null \
      && kube_ctl -n "$ns" get configmaps -o json > "$live/configmap.json" 2>/dev/null \
      || { warn "can't list the live Secrets / ConfigMaps of $ns: syncing every object"; full=true; }
  fi
  for item in "${_K_STAGED[@]}"; do
    IFS='|' read -r kind name dir <<< "$item"
    h="$(_kube_dir_hash "$dir")"
    _K_HASHES="$(printf '%s' "$_K_HASHES" | N="$name" H="$h" jq -c '.[env.N] = env.H')"
    if [ "$kind" = secret ]; then
      kube_ctl create secret generic "$name" -n "$ns" --from-file="$dir" --dry-run=client -o json
    else
      kube_ctl create configmap "$name" -n "$ns" --from-file="$dir" --dry-run=client -o json
    fi > "$want" || { rm -rf "$_K_STAGE"; fail "could not build $kind $name"; }
    if [ "$full" = false ] && jq -n -e --slurpfile w "$want" --slurpfile l "$live/$kind.json" '
        def body: {data: (.data // {}), binaryData: (.binaryData // {})};
        ($w[0] | body) as $b
        | [$l[0].items[] | select(.metadata.name == $w[0].metadata.name)]
        | (length == 1) and ((.[0] | body) == $b)' >/dev/null 2>&1; then
      continue
    fi
    _kube_put "$want" || { rm -rf "$_K_STAGE"; fail "could not sync $kind $name"; }
  done
  [ -n "${HUB_PROXY_SECRET:-}" ] || { rm -rf "$_K_STAGE"; fail "HUB_PROXY_SECRET is not set in .env"; }
  NS="$KUBE_EDGE_NS" jq -n '{apiVersion: "traefik.io/v1alpha1", kind: "Middleware",
      metadata: {name: "hub-proxy-secret", namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis", "portcullis.io/owner": "core"}},
      spec: {headers: {customRequestHeaders: {"X-Portcullis-Proxy-Secret": env.HUB_PROXY_SECRET}}}}' > "$want" \
    && _kube_put "$want" || { rm -rf "$_K_STAGE"; fail "could not apply the hub-proxy-secret Middleware"; }
  rm -rf "$_K_STAGE"
}

# ── values (no secret ever) ──

# kube_render_values — secrets/kube/values.yaml from .env, the resolved
# images, the synced objects' hashes and nested items (JSON, which Helm
# reads as YAML). A required key missing in .env refuses, naming it.
kube_render_values() {
  local f v cls
  for v in PORTCULLIS_DOMAIN PORTCULLIS_POD_CIDR PORTCULLIS_SERVICE_CIDR PORTCULLIS_KUBE_API_ENDPOINTS PORTCULLIS_TRAEFIK_SERVICE_IP PORTCULLIS_TRAEFIK_VPN_SERVICE_IP PORTCULLIS_WG_EDGE_SERVICE_IP; do
    [ -n "${!v:-}" ] || fail "$v is not set in .env (required by the chart)"
  done
  [ -n "${_K_IMAGES:-}" ] || fail "kube_render_values: the images aren't resolved"
  cls="$(vpn_entrypoints "${PORTCULLIS_VPN_MODE:-apps}" "${PORTCULLIS_VPN_PUBLIC_ENROL:-true}")" || fail "invalid PORTCULLIS_VPN_MODE"
  f="$(kube_values_file)"
  (umask 077 && mkdir -p "$(dirname "$f")")
  local ep_core ep_admin ep_enrol web_core web_admin web_enrol
  ep_core="${PORTCULLIS_EP_CORE:-$(sed -n 's/^PORTCULLIS_EP_CORE=//p' <<< "$cls")}"
  ep_admin="${PORTCULLIS_EP_ADMIN:-$(sed -n 's/^PORTCULLIS_EP_ADMIN=//p' <<< "$cls")}"
  ep_enrol="${PORTCULLIS_EP_ENROL:-$(sed -n 's/^PORTCULLIS_EP_ENROL=//p' <<< "$cls")}"
  web_core="${PORTCULLIS_WEB_CORE:-$(sed -n 's/^PORTCULLIS_WEB_CORE=//p' <<< "$cls")}"
  web_admin="${PORTCULLIS_WEB_ADMIN:-$(sed -n 's/^PORTCULLIS_WEB_ADMIN=//p' <<< "$cls")}"
  web_enrol="${PORTCULLIS_WEB_ENROL:-$(sed -n 's/^PORTCULLIS_WEB_ENROL=//p' <<< "$cls")}"
  local mon=false wg=false
  case ",${COMPOSE_PROFILES:-}," in *,monitoring,*) mon=true ;; esac
  case ",${COMPOSE_PROFILES:-}," in *,wg,*) wg=true ;; esac
  jq -n --argjson images "$_K_IMAGES" --argjson hashes "${_K_HASHES:-{\}}" --argjson items "${_K_ITEMS:-{\}}" \
    --argjson mon "$mon" --argjson wg "$wg" \
    --arg domain "$PORTCULLIS_DOMAIN" --arg pod "$PORTCULLIS_POD_CIDR" --arg svc "$PORTCULLIS_SERVICE_CIDR" \
    --arg api "$PORTCULLIS_KUBE_API_ENDPOINTS" --arg nodes "${PORTCULLIS_KUBE_NODE_ADDRESSES:-$(kube_node_addresses)}" \
    --arg tip "$PORTCULLIS_TRAEFIK_SERVICE_IP" --arg tvip "$PORTCULLIS_TRAEFIK_VPN_SERVICE_IP" --arg weip "$PORTCULLIS_WG_EDGE_SERVICE_IP" \
    --arg epc "$ep_core" --arg epa "$ep_admin" --arg epe "$ep_enrol" --arg wc "$web_core" --arg wa "$web_admin" --arg we "$web_enrol" \
    --arg mode "${PORTCULLIS_VPN_MODE:-apps}" --arg pe "${PORTCULLIS_VPN_PUBLIC_ENROL:-true}" \
    --arg core "$(proxy_subnet) $(auth_subnet) $(domains_subnet) $(mcp_subnet) $(vpn_net) $(vpn_edge_subnet)" \
    --arg pools "$PORTCULLIS_POD_CIDR $PORTCULLIS_SERVICE_CIDR" \
    --arg builtin "${PORTCULLIS_VPN_BUILTIN:-off}" --arg wsub "${PORTCULLIS_VPN_SUBNET:-10.213.0.0/22}" \
    --arg wport "${PORTCULLIS_VPN_PORT:-51820}" --arg wdns "${PORTCULLIS_VPN_DNS_UPSTREAM:-1.1.1.1,9.9.9.9}" \
    --arg mpp "${PORTCULLIS_VPN_EDGE_MAX_PER_PROVIDER:-1024}" --arg mpu "${PORTCULLIS_VPN_EDGE_MAX_PER_USER:-128}" \
    --arg mpc "${PORTCULLIS_VPN_EDGE_MAX_PER_CLIENT:-32}" --arg ppct "${PORTCULLIS_VPN_EDGE_PRESSURE_PERCENT:-90}" \
    --arg pidle "${PORTCULLIS_VPN_EDGE_PRESSURE_IDLE:-2m}" \
    --arg email "${ACME_EMAIL:-admin@$PORTCULLIS_DOMAIN}" --arg ca "${ACME_CA_SERVER:-https://acme-v02.api.letsencrypt.org/directory}" \
    --arg dnsp "${ACME_DNS_PROVIDER:-${DNS_PROVIDER:-cloudflare}}" --arg cfm "${CF_API_EMAIL:-}" --arg gce "${GCE_PROJECT:-}" \
    --arg caa "${DNS_CAA:-true}" --arg caai "${DNS_CAA_ISSUER:-}" --arg caaio "${DNS_CAA_IODEF:-}" \
    --arg kca "${KEYCLOAK_ADMIN:-admin}" --arg bdn "${LLDAP_BASE_DN:-dc=portcullis,dc=local}" \
    --arg roots "${HUB_OVERRIDE_BIND_ROOTS:-}" --arg ipg "${INVITE_PROTECTED_GROUPS:-}" --arg pdn "${PORTAL_DISPLAY_NAME:-Portcullis}" \
    --arg ttl "${CLIENT_CERT_TTL:-720h}" --arg warn "${CERT_EXPIRY_WARN_DAYS:-7}" --arg imp "${IMPERSONATION_MAX_MINUTES:-30}" \
    --arg smtp "${ALERT_SMTP_FROM:-}" --arg ret "${PROMETHEUS_RETENTION:-30d}" --arg apps "$(kube_apps_ns)" '
    def words: split(" ") | map(select(. != ""));
    {domain: $domain, podCIDR: $pod, serviceCIDR: $svc, apiEndpoints: ($api | words), nodeAddresses: ($nodes | words),
     traefikServiceIP: $tip, traefikVPNServiceIP: $tvip, wgEdgeServiceIP: $weip,
     images: $images, hashes: $hashes, configItems: $items,
     monitoring: {enabled: $mon, prometheusRetention: $ret},
     wg: {enabled: $wg, builtin: $builtin, subnet: $wsub, dnsUpstream: $wdns, people: {port: ($wport | tonumber)},
          edge: {maxPerProvider: ($mpp | tonumber), maxPerUser: ($mpu | tonumber), maxPerClient: ($mpc | tonumber),
                 pressurePercent: ($ppct | tonumber), pressureIdle: $pidle}},
     vpn: {mode: $mode, publicEnrol: $pe, reservedPools: $pools, coreSubnets: $core},
     entrypoints: {ep: {core: $epc, admin: $epa, enrol: $epe}, web: {core: $wc, admin: $wa, enrol: $we}},
     acme: {email: $email, caServer: $ca, dnsProvider: $dnsp, cfApiEmail: $cfm, gceProject: $gce},
     dns: {caa: $caa, caaIssuer: $caai, caaIodef: $caaio},
     keycloak: {admin: $kca}, lldap: {baseDN: $bdn},
     hub: {bindRoots: $roots, invitesProtectedGroups: $ipg, portalDisplayName: $pdn, clientCertTTL: $ttl,
           certExpiryWarnDays: $warn, impersonationMaxMinutes: $imp, selfImage: $images.hub, appsNamespace: $apps},
     alerting: {smtpFrom: $smtp}, appsNamespace: $apps}' > "$f.tmp" && chmod 600 "$f.tmp" && mv -f "$f.tmp" "$f" \
    || fail "could not write $f"
}

# ── the release ──

# kube_health_report — after a failed helm run: each core pod that isn't
# Ready, its restarts and its last 3 events (reasons and messages only:
# never env, never a Secret). Best effort.
kube_health_report() {
  local ns pods p
  ns="$(kube_ns)"
  pods="$(kube_ctl -n "$ns" get pods -o json 2>/dev/null)" || return 0
  printf '%s' "$pods" | jq -r '.items[] | select(([.status.containerStatuses[]?.ready] | all) | not)
      | "\(.metadata.name) \(.status.phase) restarts=\([.status.containerStatuses[]?.restartCount] | add // 0)"' 2>/dev/null \
  | while IFS= read -r p; do
      warn "$p is not ready; its last events:"
      kube_ctl -n "$ns" get events --field-selector "involvedObject.name=${p%% *}" -o json 2>/dev/null \
        | jq -r '(.items // []) | sort_by(.lastTimestamp // .eventTime // "") | .[-3:][] | "    \(.reason): \((.message // "") | gsub("\\s+"; " ") | .[0:300])"' >&2 2>/dev/null || true
    done
  return 0
}

# kube_cluster_check — the Hub's cluster check input (contract §6): the apps
# namespace's PSA labels and the six bindings, written as the ConfigMap
# portcullis-cluster-check (checked_at RFC 3339 UTC, ok true|false, why).
kube_cluster_check() {
  local ns why="" b psa
  ns="$(kube_apps_ns)"
  psa="$(kube_ctl get namespace "$ns" -o json 2>/dev/null | jq -r '[.metadata.labels["pod-security.kubernetes.io/enforce"], .metadata.labels["pod-security.kubernetes.io/warn"], .metadata.labels["pod-security.kubernetes.io/audit"]] | join(",")' 2>/dev/null || true)"
  [ "$psa" = privileged,baseline,baseline ] || why="the apps namespace's PSA labels are '${psa:-unreadable}' (want enforce privileged, warn / audit baseline)"
  [ -n "$why" ] || why="$(kube_bindings_missing)"
  NS="$(kube_ns)" OK="$([ -z "$why" ] && echo true || echo false)" WHY="$why" AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" jq -n '
    {apiVersion: "v1", kind: "ConfigMap",
     metadata: {name: "portcullis-cluster-check", namespace: env.NS, labels: {"app.kubernetes.io/managed-by": "portcullis"}},
     data: {checked_at: env.AT, ok: env.OK, why: env.WHY}}' \
    | kube_ctl apply --server-side --force-conflicts --field-manager="$KUBE_FIELD_MANAGER" -f - >/dev/null \
    || warn "could not write portcullis-cluster-check"
  [ -z "$why" ] || warn "cluster check: $why"
}

# _rtk_up [service...] — the whole release (a service list is accepted and
# ignored): K1 local images built and imported first, the images resolved,
# Secrets / ConfigMaps synced, the cluster setup, the NetworkPolicy probe
# (proven for this run only), values, then `helm upgrade --install --wait
# --timeout 10m --skip-crds` (the CRDs are init's, K14). Only after Helm
# succeeded: the digest cache. A failed or timed-out run prints
# kube_health_report and writes nothing.
_rtk_up() {
  local rc=0 vf
  local -a wait=(--wait --timeout 10m)
  # init's first installs (Vault not initialised yet, the Hub without its
  # LLDAP account) don't wait for readiness: its own wait_healthy does.
  [ "${KUBE_HELM_WAIT:-true}" = true ] || wait=()
  kube_images_ready
  hub_env_write
  kube_sync_secrets
  kube_cluster_setup
  if [ -z "${_K_PROBED:-}" ]; then
    kube_netpol_probe || fail "NetworkPolicy enforcement isn't proven (see above): nothing deployed"
    _K_PROBED=1
  fi
  kube_render_values
  vf="$(kube_values_file)"
  info "helm upgrade --install $KUBE_RELEASE${wait[*]:+ (waits up to 10 minutes)}..."
  kube_helm upgrade --install "$KUBE_RELEASE" "$PORTCULLIS_HOME/charts/portcullis" -n "$(kube_ns)" \
    --skip-crds ${wait[@]+"${wait[@]}"} -f "$vf" >&2 || rc=$?
  if [ "$rc" -ne 0 ]; then
    kube_health_report
    return "$rc"
  fi
  (umask 077 && printf '%s\n' "$_K_IMAGES" > "$(kube_digests_file)")
  kube_cluster_check
  kube_forward_core
}

# _rtk_pull — the images are resolved (by digest) at every up; nothing to pull.
_rtk_pull() { kube_resolve_images; }

# ── one-shots (K16) ──

# _rtk_run <service> [--user …] [--entrypoint E] [--label …] -- <args…> —
# a one-shot pod from the chart's own spec for it (templates/oneshot.yaml,
# rendered with the live values), the args appended to its command,
# attached with stdin (`kubectl run --rm -i`), removed on exit. Secrets
# only on stdin; --user / --label are the docker branch's.
_rtk_run() {
  local svc="$1" ep="" spec name img
  shift
  kube_images_ready
  [ -s "$(kube_values_file)" ] || kube_render_values
  while [ "$1" != -- ]; do
    case "$1" in --entrypoint) ep="$2"; shift 2 ;; --user|--label) shift 2 ;; *) shift ;; esac
  done
  shift
  spec="$(kube_helm template "$KUBE_RELEASE" "$PORTCULLIS_HOME/charts/portcullis" -n "$(kube_ns)" -f "$(kube_values_file)" \
      --set-string "oneshot=$svc" --show-only templates/oneshot.yaml \
    | kube_ctl create --dry-run=client -o json -f -)" || fail "no one-shot spec for $svc in the chart"
  name="oneshot-$svc-$(openssl rand -hex 3)"
  img="$(printf '%s' "$spec" | jq -r '.spec.containers[0].image')"
  spec="$(printf '%s' "$spec" | N="$name" E="$ep" jq -c --args '
      .metadata.name = env.N | .spec.containers[0].stdin = true | .spec.containers[0].stdinOnce = true
      | .spec.containers[0].name = env.N
      | .spec.containers[0].command = ((if env.E != "" then [env.E] else .spec.containers[0].command end) + $ARGS.positional)' -- "$@")"
  kube_ctl -n "$(kube_ns)" run "$name" --image="$img" --restart=Never --rm -i --quiet --overrides="$spec"
}

# ── volumes (K16: owner-uid helper pods in the core namespace) ──

# _rtk_volume_pod <pvc> <uid:gid> <ro|rw> — a restricted helper pod (the
# CLI's pinned helper image, the volume's owner, no network, the PVC at
# /vol); prints its name.
_rtk_volume_pod() {
  local pvc="$1" u="${2%%:*}" g="${2#*:}" ro="$3" name
  [ "$u" != 0 ] || fail "a volume helper never runs as root on Kubernetes (PSA restricted): pass the volume's owner"
  name="volume-$pvc-$(openssl rand -hex 3)"
  N="$name" NS="$(kube_ns)" P="$pvc" U="$u" G="$g" RO="$ro" IMG="$PORTCULLIS_HELPER_IMAGE" jq -n '
    {apiVersion: "v1", kind: "Pod",
     metadata: {name: env.N, namespace: env.NS, labels: {"portcullis.io/component": "volume-helper", "portcullis.io/helper": "volume"}},
     spec: {restartPolicy: "Never", automountServiceAccountToken: false, enableServiceLinks: false,
       securityContext: {runAsNonRoot: true, runAsUser: (env.U | tonumber), runAsGroup: (env.G | tonumber), seccompProfile: {type: "RuntimeDefault"}},
       containers: [{name: "helper", image: env.IMG, command: ["sleep", "3600"],
         resources: {limits: {memory: "64Mi"}, requests: {memory: "64Mi"}},
         securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}},
         volumeMounts: [{name: "vol", mountPath: "/vol", readOnly: (env.RO == "ro")}]}],
       volumes: [{name: "vol", persistentVolumeClaim: {claimName: env.P, readOnly: (env.RO == "ro")}}]}}' \
    | kube_ctl create -f - >/dev/null || return 1
  kube_ctl -n "$(kube_ns)" wait --for=condition=Ready "pod/$name" --timeout=180s >/dev/null || { kube_ctl -n "$(kube_ns)" delete pod "$name" --wait=false >/dev/null 2>&1; return 1; }
  echo "$name"
}

# _rtk_volume_out <pvc> <path> <uid:gid> — tar of <path> under the PVC on stdout.
_rtk_volume_out() {
  local pod rc=0
  pod="$(_rtk_volume_pod "$1" "${3:?the volume owner uid:gid}" ro)" || fail "could not start a volume helper for $1"
  kube_ctl -n "$(kube_ns)" exec "$pod" -- tar -C /vol -cf - "${2:-.}" || rc=$?
  kube_ctl -n "$(kube_ns)" delete pod "$pod" --wait=false >/dev/null 2>&1 || true
  return "$rc"
}

# _rtk_volume_in <pvc> <path> <uid:gid> — a tar on stdin extracted under <path>.
_rtk_volume_in() {
  local pod rc=0
  pod="$(_rtk_volume_pod "$1" "${3:?the volume owner uid:gid}" rw)" || fail "could not start a volume helper for $1"
  kube_ctl -n "$(kube_ns)" exec -i "$pod" -- tar -C "/vol/${2:-.}" -xf - || rc=$?
  kube_ctl -n "$(kube_ns)" delete pod "$pod" --wait=false >/dev/null 2>&1 || true
  return "$rc"
}

# ── forwards to Vault and Keycloak (spec §3) ──

# kube_forward_core — port-forwards to vault:8200 and keycloak:8080 for
# the CLI's curl code (they arrive on 127.0.0.1 inside the pod: Keycloak
# never sees a trusted proxy); exports VAULT_ADDR / KEYCLOAK_URL. Each
# forwarder dies with this shell (a watcher), no trap needed.
kube_forward_core() {
  local svc port var pf
  for svc in vault:8200:VAULT_ADDR keycloak:8080:KEYCLOAK_URL; do
    IFS=: read -r svc port var <<< "$svc"
    rt_running "$svc" || continue
    pf="$(_kube_forward "$svc" "$port")" || { warn "no port-forward to $svc:$port"; continue; }
    export "$var=http://127.0.0.1:$pf"
  done
}

# _kube_forward <service> <port> — a port-forward that lives as long as this
# shell; prints the local port.
_kube_forward() {
  local log i lp="" pid parent=$$
  log="$(mktemp)"
  kube_ctl -n "$(kube_ns)" port-forward --address 127.0.0.1 "svc/$1" ":$2" >"$log" 2>&1 &
  pid=$!
  ( while kill -0 "$parent" 2>/dev/null && kill -0 "$pid" 2>/dev/null; do sleep 1; done; kill "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  for ((i = 0; i < 100; i++)); do
    lp="$(sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9][0-9]*\) -> .*/\1/p' "$log" | head -n1)"
    [ -z "$lp" ] || break
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  rm -f "$log"
  [ -n "$lp" ] || { kill "$pid" 2>/dev/null; return 1; }
  echo "$lp"
}

# ── backup / restore on kubernetes (Task 15; spec §9) ─────

# The PVC of a compose volume key (lldap_data → lldap-data) and its owner
# on Kubernetes (BACKUP_FILE_VOLUMES' owners; traefik_acme: Traefik's 65532).
kube_pvc_name() { echo "${1//_/-}"; }
kube_volume_owner() {
  case "$1" in
    traefik_acme) echo "65532:65532" ;;
    postgres_data) echo "70:70" ;;
    vault_data) echo "100:1000" ;;
    hub_secrets) echo "$CT_UID_HUB:$CT_UID_HUB" ;;
    *) echo "$2:$3" ;;
  esac
}

# _kube_image_of <svc> — the digest the release runs (digests.json, else resolved now).
_kube_image_of() {
  local r
  r="$(jq -r --arg s "$1" '.[$s] // empty' "$(kube_digests_file)" 2>/dev/null || true)"
  if [ -z "$r" ]; then kube_resolve_images; r="$(printf '%s' "$_K_IMAGES" | jq -r --arg s "$1" '.[$s] // empty')"; fi
  [ -n "$r" ] || fail "no image for $1"
  echo "$r"
}

# _kube_helper_pod <pvc|""> <uid:gid> <ro|rw> <image> [component] — a
# restricted helper pod in the core namespace (non-root, no capability, no
# network label: default deny), the PVC at /vol; prints its name.
_kube_helper_pod() {
  local pvc="$1" u="${2%%:*}" g="${2#*:}" ro="$3" img="$4" comp="${5:-volume-helper}" name
  [ "$u" != 0 ] || fail "a helper pod never runs as root on Kubernetes (PSA restricted)"
  name="$comp-$(openssl rand -hex 4)"
  N="$name" NS="$(kube_ns)" P="$pvc" U="$u" G="$g" RO="$ro" IMG="$img" C="$comp" jq -n '
    {apiVersion: "v1", kind: "Pod",
     metadata: {name: env.N, namespace: env.NS, labels: {"portcullis.io/component": env.C}},
     spec: {restartPolicy: "Never", automountServiceAccountToken: false, enableServiceLinks: false,
       securityContext: {runAsNonRoot: true, runAsUser: (env.U | tonumber), runAsGroup: (env.G | tonumber), seccompProfile: {type: "RuntimeDefault"}},
       containers: [{name: "helper", image: env.IMG, command: ["sleep", "3600"],
         resources: {limits: {memory: "256Mi"}, requests: {memory: "256Mi"}},
         securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}},
         volumeMounts: ([{name: "tmp", mountPath: "/tmp"}] + (if env.P == "" then [] else [{name: "vol", mountPath: "/vol", readOnly: (env.RO == "ro")}] end))}],
       volumes: ([{name: "tmp", emptyDir: {medium: "Memory"}}] + (if env.P == "" then [] else [{name: "vol", persistentVolumeClaim: {claimName: env.P, readOnly: (env.RO == "ro")}}] end))}}' \
    | kube_ctl create -f - >/dev/null || return 1
  if ! kube_ctl -n "$(kube_ns)" wait --for=condition=Ready "pod/$name" --timeout=180s >/dev/null; then
    kube_ctl -n "$(kube_ns)" delete pod "$name" --wait=false >/dev/null 2>&1 || true
    return 1
  fi
  echo "$name"
}
_kube_helper_done() { kube_ctl -n "$(kube_ns)" delete pod "$1" --wait=false >/dev/null 2>&1 || true; }

# _kube_backup_volume <key> <uid> <gid> — the volume's tar.gz on stdout:
# group-gate's image (python3) runs the SQLite-aware snapshot as the
# volume's owner with the PVC read-only at /vol, streamed over exec.
_kube_backup_volume() {
  local pod rc=0
  pod="$(_kube_helper_pod "$(kube_pvc_name "$1")" "$(kube_volume_owner "$1" "$2" "$3")" ro "$(_kube_image_of group-gate)" volume-backup)" \
    || { echo "could not start a backup helper for $1" >&2; return 1; }
  kube_ctl -n "$(kube_ns)" exec "$pod" -- env PYTHONDONTWRITEBYTECODE=1 python3 -c "$_BACKUP_PY_SNAPSHOT" || rc=$?
  _kube_helper_done "$pod"
  return "$rc"
}

# _kube_volume_exists <key>
_kube_volume_exists() { kube_ctl -n "$(kube_ns)" get pvc "$(kube_pvc_name "$1")" >/dev/null 2>&1; }

# _backup_create_kube — backup_create on kubernetes: the same layout and
# MANIFEST.json (the Vault snapshot through the port-forward, pg_dump by
# exec, the volumes by owner-uid helper pods), secrets/kube/values.yaml
# with secrets/.
_backup_create_kube() {
  local dir work t0 spec key uid gid old_umask f
  require_cmd jq curl gzip tar kubectl
  t0="$(date +%s)"
  _BACKUP_CFG='{}'
  dir="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
  work="$dir.partial"
  [ ! -e "$dir" ] && [ ! -e "$work" ] || fail "$dir already exists"
  wait_healthy 120 postgres vault
  [ -n "${VAULT_ADDR:-}" ] || kube_forward_core
  vault_wait_active 90 || fail "Vault is not active — ./portcullis vault unseal"
  vault_admin_env >/dev/null || fail "no Vault admin token (secrets/vault-init.json or VAULT_TOKEN)"
  info "Creating backup in $dir..."
  old_umask="$(umask)"
  umask 077
  mkdir -p "$work"
  chmod 700 "$BACKUP_ROOT" "$work"
  cp "$(env_file)" "$work/.env"
  [ ! -f "$PORTCULLIS_ROOT/keycloak/realm-export.json" ] || cp "$PORTCULLIS_ROOT/keycloak/realm-export.json" "$work/realm-export.json"
  [ ! -d "$PORTCULLIS_ROOT/config" ] || cp -a "$PORTCULLIS_ROOT/config" "$work/config"
  [ ! -d "$PORTCULLIS_ROOT/certs" ] || cp -a "$PORTCULLIS_ROOT/certs" "$work/certs"
  [ ! -d "$PORTCULLIS_ROOT/secrets" ] || cp -a "$PORTCULLIS_ROOT/secrets" "$work/secrets"
  _strip_host_files "$work/secrets"
  printf '  %-26s' "vault (raft snapshot)"; _backup_vault_snapshot "$work/vault.snap"; printf ' %sdone%s\n' "$C_GREEN" "$C_NC"
  printf '  %-26s' "postgres (pg_dump)"; _backup_pg_dump "$work/postgres.dump"; printf ' %sdone%s\n' "$C_GREEN" "$C_NC"
  for spec in $BACKUP_FILE_VOLUMES; do
    IFS=: read -r key uid gid <<< "$spec"
    _kube_volume_exists "$key" || continue
    printf '  %-26s' "$key"
    _kube_backup_volume "$key" "$uid" "$gid" > "$work/$key.tar.gz" 2>"$work/.err" \
      || { cat "$work/.err" >&2; fail "could not back up volume $key"; }
    printf ' %sdone%s %s\n' "$C_GREEN" "$C_NC" "$(cat "$work/.err")"
    rm -f "$work/.err"
  done
  for f in "$work"/*.tar.gz; do
    [ -f "$f" ] && { gzip -t "$f" || fail "$f is corrupt"; }
  done
  _BACKUP_CFG="$(jq -nc --arg h "$(jq -r '.hub // empty' "$(kube_digests_file)" 2>/dev/null)" --arg k "$(jq -r '.keycloak // empty' "$(kube_digests_file)" 2>/dev/null)" \
    '{services: {hub: {image: $h}, keycloak: {image: $k}}}')"
  _backup_manifest "$work"
  mv "$work" "$dir"
  umask "$old_umask"
  # shellcheck disable=SC2034
  BACKUP_LAST_DIR="$dir"
  _backup_metrics local $(( $(date +%s) - t0 )) "$(_backup_size_bytes "$dir")"
  _backup_prune_local
  ok "Backup saved to $dir"
  warn "It contains secrets/ (Vault root token + unseal key): protect it like the keys themselves."
}

# _kube_empty_volume <key> <uid> <gid> — the PVC emptied in place, as its owner.
_kube_empty_volume() {
  local pod
  _kube_volume_exists "$1" || return 0
  pod="$(_kube_helper_pod "$(kube_pvc_name "$1")" "$(kube_volume_owner "$1" "$2" "$3")" rw "$PORTCULLIS_HELPER_IMAGE")" || return 1
  kube_ctl -n "$(kube_ns)" exec "$pod" -- find /vol -mindepth 1 -maxdepth 1 -exec rm -rf {} + || { _kube_helper_done "$pod"; return 1; }
  _kube_helper_done "$pod"
}

# _kube_restore_volume <dir> <key> <uid> <gid> — the archive into the
# emptied PVC, as its owner (single-owner volumes), over exec stdin.
_kube_restore_volume() {
  local pod rc=0
  _kube_empty_volume "$2" "$3" "$4" || return 1
  pod="$(_kube_helper_pod "$(kube_pvc_name "$2")" "$(kube_volume_owner "$2" "$3" "$4")" rw "$PORTCULLIS_HELPER_IMAGE")" || return 1
  kube_ctl -n "$(kube_ns)" exec -i "$pod" -- tar -xzf - -C /vol < "$1/$2.tar.gz" || rc=$?
  _kube_helper_done "$pod"
  return "$rc"
}

# _kube_restore_stop_secret_apps — the instances that mount *-pw Secrets
# (label portcullis.io/person-secrets) scaled to 0, then every *-pw Secret
# emptied (contract §6: a restore voids every credential).
_kube_restore_stop_secret_apps() {
  local ns s
  ns="$(kube_apps_ns)"
  kube_ctl -n "$ns" scale deployment -l portcullis.io/person-secrets --replicas=0 >/dev/null \
    || { _RESTORE_ERROR_MSG="could not scale the person-secret instances to 0: nothing was restored"; return 1; }
  RESTORE_STOPPED_APPS="$(kube_ctl -n "$ns" get deployments -l portcullis.io/person-secrets -o json 2>/dev/null | jq -r '[.items[].metadata.labels["portcullis.io/instance"] // empty] | unique | join(" ")' || true)"
  for s in $(kube_ctl -n "$ns" get secrets -o json 2>/dev/null | jq -r '.items[].metadata.name | select(endswith("-pw"))'); do
    kube_ctl -n "$ns" patch secret "$s" --type=json -p '[{"op": "replace", "path": "/data", "value": {}}]' >/dev/null \
      || { _RESTORE_ERROR_MSG="could not empty the Secret $s: nothing was restored"; return 1; }
  done
}

# _kube_scale <svc> <n> — scale without waiting for readiness.
_kube_scale() { kube_ctl -n "$(kube_ns)" scale "deploy/$1" --replicas="$2" >/dev/null; }

# _kube_wait_running <svc> — a pod of the service is Running (not Ready).
_kube_wait_running() {
  kube_ctl -n "$(kube_ns)" wait --for=jsonpath='{.status.phase}'=Running pod -l "$_KUBE_COMPONENT=$1" --timeout=300s >/dev/null
}

# _kube_restore_vault <dir> — the fresh Vault (its PVC emptied) initialised
# with throwaway keys, the snapshot force-restored through the forward,
# then the backup's secrets/ (its unseal key) synced and Vault restarted.
_kube_restore_vault() {
  local dir="$1" init tmp_key tmp_root code pf
  unset VAULT_TOKEN
  _kube_scale vault 1 && _kube_wait_running vault || fail "the fresh Vault doesn't start"
  pf="$(_kube_forward vault 8200)" || fail "no port-forward to Vault"
  export VAULT_ADDR="http://127.0.0.1:$pf"
  init="$(vexec operator init -key-shares=1 -key-threshold=1 -format=json)" || fail "temporary vault init failed"
  tmp_key="$(printf '%s' "$init" | jq -r '.unseal_keys_b64[0]')"
  tmp_root="$(printf '%s' "$init" | jq -r '.root_token')"
  printf '%s' "$tmp_key" | vexec write -format=json sys/unseal key=- >/dev/null || fail "temporary unseal failed"
  vault_wait_active 60 || fail "temporary Vault did not become active"
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 300 -X POST \
    -H @<(printf 'X-Vault-Token: %s\n' "$tmp_root") --data-binary @"$dir/vault.snap" \
    "$VAULT_ADDR/v1/sys/storage/raft/snapshot-force" || true)"
  [ "$code" = 204 ] || [ "$code" = 200 ] || fail "Vault snapshot restore failed (HTTP ${code:-none})"
  _restore_secrets "$dir"
  kube_sync_secrets --full
  kube_ctl -n "$(kube_ns)" rollout restart deploy/vault >/dev/null && _kube_wait_running vault || fail "could not restart Vault"
  pf="$(_kube_forward vault 8200)" || fail "no port-forward to Vault"
  export VAULT_ADDR="http://127.0.0.1:$pf"
  vault_wait_active 120 || fail "Vault did not unseal with the restored key (secrets/ and vault.snap from different installs?)"
  ok "Vault restored and unsealed with the original key."
}

# _kube_restore_lldap_count — LLDAP's users besides admin / portcullis-hub
# from its PVC (group-gate's python, read-only, as LLDAP's uid), or "missing".
_kube_restore_lldap_count() {
  local pod out
  _kube_volume_exists lldap_data || { echo missing; return 0; }
  pod="$(_kube_helper_pod lldap-data "$CT_UID_LLDAP:$CT_UID_LLDAP" ro "$(_kube_image_of group-gate)")" || { echo missing; return 0; }
  out="$(kube_ctl -n "$(kube_ns)" exec "$pod" -- env PYTHONDONTWRITEBYTECODE=1 python3 -c "$_BACKUP_PY_COUNT_LLDAP" 2>/dev/null || echo missing)"
  _kube_helper_done "$pod"
  echo "$out"
}

# _backup_restore_kube <dir> <yes> <allow-empty-lldap> — restore on
# kubernetes: the Hub to 0, the person-secret instances to 0 and their *-pw
# Secrets emptied; the pre-restore copy; everything to 0; .env (keeping this
# host's runtime and PORTCULLIS_KUBE_* keys), certs/, config/; Postgres and
# Vault emptied and restored (pg_restore by exec, the raft snapshot through
# the forward); each volume through an owner-uid helper; the LLDAP guard;
# then the release (helm upgrade --wait).
_backup_restore_kube() {
  local dir="$1" yes="$2" allow_empty_lldap="${3:-false}" pre spec key uid gid
  require_cmd jq curl tar gzip kubectl helm
  [ -d "$dir" ] || fail "Backup directory not found: $dir"
  dir="$(cd "$dir" && pwd)"
  _backup_check_layout "$dir"
  _backup_check_manifest "$dir" || fail "checksum mismatch in $dir — refusing to restore a damaged backup"
  echo "This replaces .env (keeping this host's runtime keys), certs/, secrets/, Vault, the Keycloak database and"
  echo "$(for spec in $BACKUP_FILE_VOLUMES; do key="${spec%%:*}"; [ ! -f "$dir/$key.tar.gz" ] || printf ' %s' "$key"; done) on the cluster $PORTCULLIS_KUBE_CONTEXT,"
  echo "with the backup from $(jq -r .created "$dir/MANIFEST.json") ($(jq -r '.domain' "$dir/MANIFEST.json"); made on $(jq -r '.runtime.name // "docker"' "$dir/MANIFEST.json"))."
  if [ "$yes" != true ]; then
    confirm "Continue with restore?" || { echo "Cancelled."; return 0; }
  fi
  [ -n "$RESTORE_RUNTIME" ] || restore_runtime_from_host
  # Every later sync of this run puts every object (never compared).
  export KUBE_SYNC_FULL=1
  info "Stopping the Hub..."
  _kube_scale hub 0 || fail "could not stop the Hub: nothing was restored"
  if ! _kube_restore_stop_secret_apps; then
    _kube_scale hub 1 || true
    fail "$_RESTORE_ERROR_MSG, Hub running again"
  fi
  pre="$BACKUP_ROOT/pre-restore-$(date +%Y%m%d-%H%M%S)"
  info "Saving the current .env, secrets/ and certs/ to $pre..."
  (umask 077 && mkdir -p "$pre" && cp "$(env_file)" "$pre/.env" \
    && { [ ! -d "$PORTCULLIS_ROOT/secrets" ] || cp -a "$PORTCULLIS_ROOT/secrets" "$pre/secrets"; } \
    && { [ ! -d "$PORTCULLIS_ROOT/certs" ] || cp -a "$PORTCULLIS_ROOT/certs" "$pre/certs"; }) \
    || { _kube_scale hub 1 || true; fail "could not save pre-restore copy: nothing was restored, Hub running again"; }
  info "Stopping services..."
  rt_down
  (umask 077 && cat "$dir/.env" > "$(env_file)")
  chmod 600 "$(env_file)" 2>/dev/null || true
  _restore_runtime_keys
  [ ! -f "$dir/realm-export.json" ] || cp "$dir/realm-export.json" "$PORTCULLIS_ROOT/keycloak/realm-export.json"
  if [ -d "$dir/config" ] && [ ! -e "$PORTCULLIS_ROOT/config" ]; then cp -a "$dir/config" "$PORTCULLIS_ROOT/config"; fi
  if [ -d "$dir/certs" ]; then
    rm -rf "$PORTCULLIS_ROOT/certs.restore-tmp" && cp -a "$dir/certs" "$PORTCULLIS_ROOT/certs.restore-tmp"
    rm -rf "$PORTCULLIS_ROOT/certs" && mv "$PORTCULLIS_ROOT/certs.restore-tmp" "$PORTCULLIS_ROOT/certs"
  fi
  env_reload
  runtime_export
  # Fresh Postgres and Vault (emptied in place, as their owners).
  _kube_empty_volume postgres_data 70 70 || fail "could not empty postgres-data"
  _kube_empty_volume vault_data 100 1000 || fail "could not empty vault-data"
  info "Starting Postgres..."
  _kube_scale postgres 1 && rt_start postgres || fail "Postgres doesn't start on the emptied volume"
  _restore_pg "$dir"
  _kube_restore_vault "$dir"
  for spec in $BACKUP_FILE_VOLUMES; do
    IFS=: read -r key uid gid <<< "$spec"
    [ -f "$dir/$key.tar.gz" ] || continue
    info "Restoring volume $key..."
    _kube_restore_volume "$dir" "$key" "$uid" "$gid" || fail "could not restore volume $key"
  done
  info "Emptying hub-secrets (a restore voids every per-person credential)..."
  _kube_empty_volume hub_secrets "$CT_UID_HUB" "$CT_UID_HUB" || fail "could not empty hub-secrets"
  _restore_lldap_guard "$allow_empty_lldap" || return 1
  stack_prepare
  config_build_ca_bundle
  vault_init false
  rt_up || warn "some services did not start — check ./portcullis status"
  wait_healthy 300 vault postgres lldap keycloak
  ok "Restore complete. Previous .env/secrets/certs: $pre. Verify with ./portcullis status"
  [ -z "${RESTORE_STOPPED_APPS:-}" ] || warn "Scaled to 0 for the restore and NOT started again: $RESTORE_STOPPED_APPS (their file-share passwords were voided). Start each one from the Hub."
}

# ── offsite on kubernetes: the host's restic (K16) ──

KUBE_RESTIC_MIN="0.19.1"

# _restic_host <restic args...> — the host restic (>= 0.19.1, the pinned
# image's version), the repository password and provider credentials by
# environment in a subshell; container paths of _RESTIC_MOUNTS mapped back
# to the host paths.
_restic_host() {
  local v m src dst a
  local -a args=()
  command -v restic >/dev/null 2>&1 || fail "restic is missing: on kubernetes the off-host backup runs the host's restic (>= $KUBE_RESTIC_MIN)"
  v="$(restic version 2>/dev/null | awk '{print $2}')"
  _ver_ge "$v" "$KUBE_RESTIC_MIN" || fail "restic ${v:-?} is older than $KUBE_RESTIC_MIN (the pinned image's version)"
  for a in "$@"; do
    for ((m = 0; m < ${#_RESTIC_MOUNTS[@]}; m += 2)); do
      [ "${_RESTIC_MOUNTS[m]}" = -v ] || continue
      IFS=: read -r src dst _ <<< "${_RESTIC_MOUNTS[m + 1]}"
      [ "$a" != "$dst" ] || a="$src"
    done
    args+=("$a")
  done
  (umask 077 && mkdir -p "$BACKUP_ROOT/.restic-cache")
  (
    for v in $RESTIC_PROVIDER_VARS; do
      val="$(_backup_cred "$v")"
      [ -z "$val" ] || export "$v=$val"
    done
    export RESTIC_REPOSITORY="${BACKUP_REPOSITORY#local:}" RESTIC_PASSWORD="$BACKUP_PASSWORD" RESTIC_CACHE_DIR="$BACKUP_ROOT/.restic-cache" RESTIC_PROGRESS_FPS=0.2
    restic "${args[@]}"
  )
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
  if [ -f "$dir/lldap_data.tar.gz" ]; then
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
    rc=1; warn "no lldap_data.tar.gz"
  fi
  for f in "$dir"/*.tar.gz; do
    [ -f "$f" ] || continue
    tar -tzf "$f" >/dev/null 2>&1 && ok "$(basename "$f") is a readable archive" || { rc=1; warn "$(basename "$f") is corrupt"; }
  done
  return "$rc"
}
