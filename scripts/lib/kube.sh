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
#   PORTCULLIS_KUBE_INSTALL_ID       owns the three namespaces (K11)
#   PORTCULLIS_KUBE_IMAGES           registry | local (K1)
#   PORTCULLIS_TRAEFIK_SERVICE_IP, PORTCULLIS_TRAEFIK_VPN_SERVICE_IP,
#   PORTCULLIS_WG_EDGE_SERVICE_IP    fixed ClusterIPs (service network + 20/21/22)
#
# Overridable for tests: KUBE_LOCAL_ADDRS (the node's local IPv4 addresses,
# space-separated), KUBE_PROBE_DIR, KUBE_TCP_PROBE (a function name).

KUBE_MIN_VERSION="1.32"
KUBE_STORAGE_NS="portcullis-storage"
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
  kubectl config get-contexts -o name 2>/dev/null | grep -qxF -- "$1"
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
  _K_POD_CIDR="$(printf '%s' "$nodes" | jq -r '.items[0].spec | (.podCIDRs // [.podCIDR // empty]) | join(" ")' 2>/dev/null)"
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
    | jq -r '[.items[] | (.ports[0].port | tostring) as $p | .endpoints[] | .addresses[] | "\(.):\($p)"] | sort | join(" ")' 2>/dev/null)"
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
  kube_ctl version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion // empty' 2>/dev/null
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
  for ns in "$(kube_ns)" "$(kube_apps_ns)" "$KUBE_STORAGE_NS"; do
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

# kube_netpol_probe — prove NetworkPolicies are enforced: in a scratch
# namespace (kube/probe/*) a client the policies deny must NOT reach the
# server and the one they allow MUST. Only then the ConfigMap
# portcullis-netpol-probe (proven_at, UTC) is written in the apps
# namespace (the Hub reads it); the scratch namespace is deleted either
# way. Returns 1 (nothing written) when not proven.
kube_netpol_probe() {
  local dir="${KUBE_PROBE_DIR:-$PORTCULLIS_HOME/kube/probe}" f ip i allowed=false denied_failed=false
  _kube_probe_cleanup
  kube_ctl wait --for=delete "namespace/$KUBE_PROBE_NS" --timeout=120s >/dev/null 2>&1 || true
  for f in namespace deny allow; do
    kube_ctl apply -f "$dir/$f.yaml" >/dev/null || { _kube_probe_cleanup; warn "could not apply the NetworkPolicy probe ($f.yaml)"; return 1; }
  done
  if ! kube_ctl -n "$KUBE_PROBE_NS" wait --for=jsonpath='{.status.phase}'=Running pod/server pod/client-denied pod/client-allowed --timeout=180s >/dev/null 2>&1; then
    _kube_probe_cleanup; warn "the NetworkPolicy probe pods didn't start"; return 1
  fi
  ip="$(kube_ctl -n "$KUBE_PROBE_NS" get pod server -o jsonpath='{.status.podIP}' 2>/dev/null)"
  [ -n "$ip" ] || { _kube_probe_cleanup; warn "the probe server has no address"; return 1; }
  # The allowed dial may need the policy controller a moment: retried.
  for ((i = 0; i < 10; i++)); do
    if _kube_dial client-allowed "$ip"; then allowed=true; break; fi
    sleep 2
  done
  if ! _kube_dial client-denied "$ip"; then denied_failed=true; fi
  _kube_probe_cleanup
  if [ "$allowed" != true ]; then
    warn "NetworkPolicy probe: the allowed connection failed (pod networking broken?): not proven"; return 1
  fi
  if [ "$denied_failed" != true ]; then
    warn "NetworkPolicy probe: a connection every policy denies got through: NetworkPolicies are NOT enforced (k3s without its network policy controller?)"; return 1
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
  ok "NetworkPolicies are enforced (probe: the denied dial failed, the allowed one succeeded)."
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
              | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))] | unique | join(" ")' 2>/dev/null
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

# _rtk_wait_ready <service>... — the Deployment rolled out (Ready).
_rtk_wait_ready() {
  local svc
  for svc in "$@"; do
    kube_ctl -n "$(kube_ns)" rollout status "deploy/$svc" --timeout=600s >/dev/null || return 1
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

# The rest of the kubernetes branch (the Helm release, one-shot pods, image
# digests, volume helpers) is in Task 15's part below; until then refused.
_rtk_up() { fail "rt_up: not available on kubernetes yet"; }
_rtk_run() { fail "rt_run: not available on kubernetes yet"; }
_rtk_pull() { fail "rt_pull: not available on kubernetes yet"; }
_rtk_volume_out() { fail "rt_volume_out: not available on kubernetes yet"; }
_rtk_volume_in() { fail "rt_volume_in: not available on kubernetes yet"; }

# kube_init_cluster — init / up / upgrade under kubernetes, before anything
# is deployed: NetworkPolicy enforcement must be proven (spec §6), else
# nothing is deployed.
kube_init_cluster() {
  kube_netpol_probe || fail "NetworkPolicy enforcement isn't proven (see above): nothing is deployed"
}
