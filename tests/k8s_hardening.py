#!/usr/bin/env python3
"""The hardening baseline on every pod the chart renders (Task 13, spec §5):
portcullis.io/component, its net labels, automountServiceAccountToken false
(but traefik and hub), drop ALL, no privilege escalation, a read-only root
(but keycloak, as on Docker), RuntimeDefault seccomp, runAsNonRoot,
the memory request portcullis.memRequest's (≤ the limit), portcullis.io/config-hash; and no workload in the
core namespace that PSA `restricted` would refuse. Also: no randAlphaNum /
randAscii / genPrivateKey anywhere in the chart, every image by digest.
Secret access (least privilege): every ServiceAccount's get / list / watch
on Secrets, per namespace, from the chart's and kube/storage's RBAC, is
exactly SECRET_READERS (Traefik only the edge namespace, which renders no
Secret; the Hub only the apps namespace; nobody the core one, which holds
portcullis-env, the age / wg / vault Secrets); Traefik watches only the edge
namespace, and every core IngressRoute / Middleware lives there.
HA (contract §20.10, plan Task 19): the baseline on every HA pod; the HA
shape (tests/k8s-ci-values-ha.yaml): the gates ×ha.gateReplicas (group-gate
and mcp-gate StatefulSets with a data PVC per replica), Keycloak ×2/3 and
Alertmanager ×2 StatefulSets, a PDB from 2 replicas, spread, no replicated
pod (nor the Hub) on a node-local PVC, the 30 s tolerations, the replicated
volumes <name>-r, Traefik a DaemonSet in portcullis-ingress with hostPort
80 / 443 only there; the log ports and the gate's own pruning only in HA, no
shared gate / wg data mount. Memory: request = the measured peak × 1.25
(values memoryPeakMi), at most the limit.

  python3 tests/k8s_hardening.py
"""
import re
import copy
import json
import sys

import yaml

import k8s_lib as K

F = K.Failures("k8s_hardening")
TOKEN_OK = {"traefik", "hub", "frontdoor"}  # frontdoor: HA only (its Lease, frontdoor-status)
WRITABLE_ROOT_OK = {"keycloak"}  # compose: not read_only (`start` re-augments)
# ServiceAccount (namespace/name) → the namespaces whose Secrets it may read.
SECRET_READERS = {
    f"{K.NS}/traefik": {K.EDGE_NS},
    f"{K.NS}/portcullis-hub": {K.APPS_NS},
}
# HA (plan Amendment 3): Traefik's ServiceAccount lives in its own namespace.
SECRET_READERS_HA = {
    f"{K.INGRESS_NS}/traefik": {K.EDGE_NS},
    f"{K.NS}/portcullis-hub": {K.APPS_NS},
}
# By-name Secret grants that don't make a ServiceAccount a reader of the
# namespace: (namespace, ServiceAccount) → the names its rules may list.
# The Hub's portcullis-hub-core: the published Secret only (contract §6).
# Any rule, from any Role, granting it more Secrets there counts in full.
SECRET_BY_NAME = {(K.NS, f"{K.NS}/portcullis-hub"): {"pub-mcp-credentials"}}
SECRET_READ_VERBS = {"get", "list", "watch", "*"}
RESTRICTED_VOLUMES = {"configMap", "csi", "downwardAPI", "emptyDir", "ephemeral", "persistentVolumeClaim", "projected", "secret"}


def check_pod(name, ns, labels, spec, ann):
    if labels.get("portcullis.io/component") is None:
        F.add(f"{name}: no portcullis.io/component label")
    if spec.get("priorityClassName") != "portcullis-core":
        F.add(f"{name}: priorityClassName {spec.get('priorityClassName')} (every core pod: portcullis-core)")
    if not any(k.startswith("portcullis.io/net-") for k in labels) and labels.get("portcullis.io/component") not in ("hub-oneshot",):
        F.add(f"{name}: no portcullis.io/net-* label")
    tok = spec.get("automountServiceAccountToken")
    if name in TOKEN_OK:
        if tok is not True:
            F.add(f"{name}: needs its ServiceAccount token")
    elif tok is not False:
        F.add(f"{name}: automountServiceAccountToken must be false")
    if name not in TOKEN_OK and spec.get("serviceAccountName") not in (None, "default"):
        F.add(f"{name}: a ServiceAccount other than default")
    psc = spec.get("securityContext", {})
    if psc.get("runAsNonRoot") is not True:
        F.add(f"{name}: runAsNonRoot not set")
    if psc.get("runAsUser") in (0, None):
        F.add(f"{name}: runAsUser {psc.get('runAsUser')}")
    for k in ("hostNetwork", "hostPID", "hostIPC"):
        if spec.get(k):
            F.add(f"{name}: {k}")
    for v in spec.get("volumes", []):
        kinds = set(v) - {"name"}
        if not kinds <= RESTRICTED_VOLUMES:
            F.add(f"{name}: volume {v['name']} of type {sorted(kinds)} (restricted allows {sorted(RESTRICTED_VOLUMES)})")
    if "portcullis.io/config-hash" not in ann and ns == K.NS and labels.get("portcullis.io/oneshot") != "true":
        F.add(f"{name}: no portcullis.io/config-hash annotation")
    for c in spec.get("containers", []) + spec.get("initContainers", []):
        cn = f"{name}/{c['name']}"
        sc = c.get("securityContext", {})
        if sc.get("allowPrivilegeEscalation") is not False:
            F.add(f"{cn}: allowPrivilegeEscalation not false")
        if sc.get("privileged"):
            F.add(f"{cn}: privileged")
        caps = sc.get("capabilities", {})
        if caps.get("drop") != ["ALL"]:
            F.add(f"{cn}: capabilities don't drop ALL")
        if set(caps.get("add", [])) - {"NET_BIND_SERVICE"}:
            F.add(f"{cn}: adds {caps.get('add')} (restricted allows NET_BIND_SERVICE only)")
        ro = sc.get("readOnlyRootFilesystem")
        # The writable root is the service's own container's (init
        # containers, portcullis-bin, are read-only everywhere).
        if name in WRITABLE_ROOT_OK and c in spec.get("containers", []):
            if ro is not False:
                F.add(f"{cn}: expected the writable root compose gives it")
        elif ro is not True:
            F.add(f"{cn}: readOnlyRootFilesystem not true")
        seccomp = (sc.get("seccompProfile") or psc.get("seccompProfile") or {}).get("type")
        if seccomp != "RuntimeDefault":
            F.add(f"{cn}: seccomp {seccomp}")
        if sc.get("runAsUser") == 0:
            F.add(f"{cn}: runs as root")
        res = c.get("resources", {})
        lim, req = res.get("limits", {}).get("memory"), res.get("requests", {}).get("memory")
        # A service's own container: the request is portcullis.memRequest's
        # (the measured peak × 1.25, never above the limit); init containers
        # request their limit.
        want = K.mem_request(name, lim) if lim and c in spec.get("containers", []) else (K.mem_bytes(lim) if lim else None)
        if not lim or not req or K.mem_bytes(req) != want or K.mem_bytes(req) > K.mem_bytes(lim):
            F.add(f"{cn}: memory request {req} (limit {lim}; want {want} bytes: the measured peak × 1.25, at most the limit)")
        for p in c.get("ports", []):
            # Only Traefik's DaemonSet in portcullis-ingress (HA, plan
            # Amendment 3): 80 → 8000 and 443 → 8443.
            ok = (name, ns, p.get("hostPort"), p.get("containerPort")) in {("traefik", K.INGRESS_NS, 80, 8000), ("traefik", K.INGRESS_NS, 443, 8443)}
            if p.get("hostPort") and not ok:
                F.add(f"{cn}: hostPort {p['hostPort']}")
        if not re.search(r"@sha256:[0-9a-f]{64}$", c["image"]):
            F.add(f"{cn}: image {c['image']} not by digest")
        if c.get("securityContext", {}).get("procMount") not in (None, "Default"):
            F.add(f"{cn}: procMount")
    if spec.get("securityContext", {}).get("sysctls"):
        F.add(f"{name}: sysctls")


FRONTDOOR_RULES = [
    {"apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "resourceNames": ["portcullis-frontdoor"], "verbs": ["get", "update"]},
    {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["frontdoor-status"], "verbs": ["get", "update"]},
]


def check_frontdoor():
    """HA only (contract §20.8): the front door's pod has the baseline, its
    Role is exactly its Lease and frontdoor-status (get / update, by name),
    it reads no Secret through the API (its credentials are a file mount)
    and only it mounts frontdoor-env and frontdoor-control-tls."""
    docs = K.render({"ha": {"enabled": True}})
    if [x for x in K.by_kind(K.render(), "Lease") if x["metadata"]["name"] == "portcullis-frontdoor"]:
        F.add("the front door's objects render without ha.enabled")
    pods = [p for p in K.pod_specs(docs) if p[0] == "frontdoor"]
    if len(pods) != 1:
        F.add(f"ha: {len(pods)} frontdoor pods")
    for name, ns, labels, spec, ann in pods:
        check_pod(name, ns, labels, spec, ann)
        if spec.get("serviceAccountName") != "frontdoor":
            F.add("frontdoor: ServiceAccount must be frontdoor")
    roles = [r for r in K.by_kind(docs, "Role") if r["metadata"]["name"] == "frontdoor"]
    if len(roles) != 1 or roles[0]["rules"] != FRONTDOOR_RULES:
        F.add(f"the front door's Role must be exactly {FRONTDOOR_RULES}")
    for name, ns, labels, spec, ann in K.pod_specs(docs):
        secrets = {v["secret"]["secretName"] for v in spec.get("volumes", []) if "secret" in v}
        for p in spec.get("volumes", []):
            for src in p.get("projected", {}).get("sources", []):
                if "secret" in src:
                    secrets.add(src["secret"]["name"])
        if name != "frontdoor" and secrets & {"frontdoor-env", "frontdoor-control-tls"}:
            F.add(f"{name}: mounts the front door's Secrets")
        if name == "frontdoor" and secrets != {"frontdoor-env", "frontdoor-control-tls"}:
            F.add(f"frontdoor: mounts {sorted(secrets)}")
    check_secret_access(docs + storage_docs(), ha=True)


# The Hub's own: no reader mounts them (contract §4, §20.1 "Core volumes").
PUB_PVCS = {"hub-state", "hub-state-r", "vpn-doc"}


def check_hub_core():
    """Contract §6 "On Kubernetes" / §20.5, every Kubernetes install (HA or
    not): the Role portcullis-hub-core is the byte copy of the Hub's
    role-core.yaml (here in the release namespace), bound to the Hub's
    ServiceAccount alone; its Secret rule names only pub-mcp-credentials;
    the Hub's Lease portcullis-hub is rendered once with no spec; the Hub
    has POD_NAME from metadata.name; HUB_GATE_REPLICAS = ha.gateReplicas
    in HA only (with the log ports); and no pod but the Hub (and its
    one-shot) mounts hub-state(-r) or vpn-doc ("ha: no pod but hub mounts
    hub-state")."""
    want = yaml.safe_load((K.CHART / "files" / "hub-role-core.yaml").read_text())
    for label, extra in (("", None), ("ha: ", {"ha": {"enabled": True}}), ("ha: ", {"ha": {"enabled": True, "gateReplicas": 2}})):
        docs = K.render(extra)
        roles = [r for r in K.by_kind(docs, "Role") if r["metadata"]["name"] == "portcullis-hub-core"]
        if len(roles) != 1 or roles[0]["metadata"]["namespace"] != K.NS or roles[0]["rules"] != want["rules"] \
                or roles[0]["metadata"].get("labels") != want["metadata"].get("labels"):
            F.add(f"{label}the Role portcullis-hub-core must be files/hub-role-core.yaml in {K.NS}, once")
        binds = [b for b in K.by_kind(docs, "RoleBinding") if b["roleRef"]["name"] == "portcullis-hub-core"]
        if len(binds) != 1 or binds[0]["metadata"]["namespace"] != K.NS or binds[0]["roleRef"]["kind"] != "Role" \
                or binds[0]["subjects"] != [{"kind": "ServiceAccount", "name": "portcullis-hub", "namespace": K.NS}]:
            F.add(f"{label}portcullis-hub-core must be bound to the Hub's ServiceAccount alone, in {K.NS}")
        for r in roles:
            for rule in r["rules"]:
                if reads_secrets(rule) and rule.get("resourceNames") != ["pub-mcp-credentials"]:
                    F.add(f"{label}portcullis-hub-core reads Secrets beyond pub-mcp-credentials: {rule}")
        leases = [x for x in K.by_kind(docs, "Lease") if x["metadata"]["name"] == "portcullis-hub"]
        if len(leases) != 1 or leases[0]["metadata"]["namespace"] != K.NS or "spec" in leases[0]:
            F.add(f"{label}the Lease portcullis-hub must render once in {K.NS}, with no spec")
        pods = {n: sp for n, _, _, sp, _ in K.pod_specs(docs)}
        env = {e["name"]: e for e in pods["hub"]["containers"][0].get("env", [])}
        if env.get("POD_NAME", {}).get("valueFrom") != {"fieldRef": {"fieldPath": "metadata.name"}}:
            F.add(f"{label}the Hub needs POD_NAME from the downward API (metadata.name): its Lease identity")
        ha = bool(extra)
        gr = str((extra or {}).get("ha", {}).get("gateReplicas", K.values()["ha"]["gateReplicas"]))
        if ha and env.get("HUB_GATE_REPLICAS", {}).get("value") != gr:
            F.add(f"{label}the Hub's HUB_GATE_REPLICAS {env.get('HUB_GATE_REPLICAS')} != ha.gateReplicas {gr}")
        if not ha and "HUB_GATE_REPLICAS" in env:
            F.add("HUB_GATE_REPLICAS without ha.enabled (the Hub reads the gates' files there)")
        for n, sp in pods.items():
            for v in sp.get("volumes", []):
                c = (v.get("persistentVolumeClaim") or {}).get("claimName")
                if c in PUB_PVCS and n not in ("hub", "oneshot-hub"):
                    F.add(f"{label}{n} mounts {c}: no pod but the Hub mounts its PVCs (readers get the published documents)")
    docs = K.render() + K.render({"oneshot": "hub"}, "templates/oneshot.yaml")
    if not any(n == "oneshot-hub" for n, *_ in K.pod_specs(docs)):
        F.add("the hub one-shot isn't rendered (check_hub_core's exception is stale)")
    # A by-name grant is allowed only for exactly its names: an extra Role
    # giving the Hub any other Secret of the core namespace (or all) counts.
    base = K.render()
    hub_sa = f"{K.NS}/portcullis-hub"
    if secret_access(base).get(hub_sa) != {K.APPS_NS}:
        F.add(f"the Hub's Secret access {secret_access(base).get(hub_sa)} (want {K.APPS_NS}, plus pub-mcp-credentials by name)")
    for names in (None, ["portcullis-env"], ["pub-mcp-credentials", "portcullis-env"]):
        rule = {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}
        if names:
            rule["resourceNames"] = names
        extra = [{"kind": "Role", "metadata": {"name": "x", "namespace": K.NS}, "rules": [rule]},
                 {"kind": "RoleBinding", "metadata": {"name": "x", "namespace": K.NS}, "roleRef": {"kind": "Role", "name": "x"},
                  "subjects": [{"kind": "ServiceAccount", "name": "portcullis-hub", "namespace": K.NS}]}]
        if K.NS not in secret_access(base + extra).get(hub_sa, set()):
            F.add(f"secret_access misses a second Role giving the Hub core Secrets {names or 'all'} (mutation test)")
    # The byte copy's namespace is rewritten to the release namespace.
    other = "portcullis-x"
    out = K.subprocess.run([K.os.environ.get("HELM", "helm"), "template", "portcullis", str(K.CHART), "-n", other,
                            "-f", str(K.ROOT / "tests" / "k8s-ci-values.yaml"), "-f", "/dev/stdin", "--show-only", "templates/hub-rbac.yaml"],
                           input=yaml.safe_dump(K.images_values()), check=True, capture_output=True, text=True).stdout
    core = [d for d in yaml.safe_load_all(out) if d and d.get("kind") == "Role" and d["metadata"]["name"] == "portcullis-hub-core"]
    if len(core) != 1 or core[0]["metadata"]["namespace"] != other:
        F.add(f"portcullis-hub-core doesn't follow the release namespace ({other}): {[c['metadata'].get('namespace') for c in core]}")


LOG_PORTS = {"group-gate": ("GATE_LOG_PORT", "8091", 8091), "mcp-gate": ("MCP_GATE_LOG_LISTEN", ":8092", 8092),
             "wg": ("WG_STATUS_LISTEN", "$(WG_POD_IP):8093", 8093)}


def local_pvcs(docs):
    """The node-local PVCs (StorageClass portcullis-core): a pod mounting one
    is pinned to that node."""
    return {c["metadata"]["name"] for c in K.by_kind(docs, "PersistentVolumeClaim") if c["spec"].get("storageClassName") == "portcullis-core"}


def mounts_local(spec, local):
    return {(v.get("persistentVolumeClaim") or {}).get("claimName") for v in spec.get("volumes", [])} & local


# HA (spec §6, plan Task 19): the replicated workloads, their kind and
# their replicas from the CI HA values (tests/k8s-ci-values-ha.yaml); every
# other core workload is one replica. Keycloak 3 from 3 non-small nodes at
# the primary site (P33), else 2; enroll stays 1 (its invites live in its
# memory: a Task 19 concern).
def ha_replicas(vals):
    g = int(vals["ha"].get("gateReplicas", K.values()["ha"]["gateReplicas"]))
    kc = 3 if int(vals["ha"].get("nonSmallNodesAtPrimary", 0)) >= 3 else 2
    return {"group-gate": ("StatefulSet", g), "mcp-gate": ("StatefulSet", g), "forward-auth": ("Deployment", g),
            "forward-auth-ext": ("Deployment", g), "keycloak": ("StatefulSet", kc), "alertmanager": ("StatefulSet", 2)}


def gate_shape_problems(docs, vals=None):
    """The HA shape: the replicated workloads exactly (kind, replicas), every
    other one 1 replica (Traefik a DaemonSet on the ingress nodes); a PDB
    minAvailable 1 exactly for those of 2 or more; each spread over the
    nodes (hostname, maxSkew 1, ScheduleAnyway for the stateless pieces); no
    replicated pod mounts a node-local PVC (every replica would be pinned to
    that node); the gates' StatefulSets with a data PVC per replica
    (portcullis-core, the owner annotations, Retain), Parallel, port-bound;
    Alertmanager's too, its peers named through a headless Service; the
    Hub mounts no node-local PVC at all (it moves on a node loss)."""
    vals = vals or {"ha": {}}
    out = []
    want = ha_replicas(vals)
    pdbs = {d["spec"]["selector"]["matchLabels"].get("portcullis.io/component"): d["spec"] for d in K.by_kind(docs, "PodDisruptionBudget")}
    local = local_pvcs(docs)
    for d in docs:
        if d.get("kind") not in ("Deployment", "StatefulSet", "DaemonSet"):
            continue
        name, kind, sp = d["metadata"]["name"], d["kind"], d["spec"]
        tpl = sp["template"]["spec"]
        if name == "traefik":
            if kind != "DaemonSet" or d["metadata"]["namespace"] != K.INGRESS_NS or tpl.get("nodeSelector") != {"portcullis.io/ingress": "true"}:
                out.append("traefik: a DaemonSet in portcullis-ingress on the portcullis.io/ingress nodes")
            continue
        wk, wn = want.get(name, ("Deployment", 1))
        n = sp.get("replicas")
        if (kind, n) != (wk, wn):
            out.append(f"{name}: {kind} of {n} (want a {wk} of {wn})")
        if isinstance(n, int) and n > 1 and mounts_local(tpl, local):
            out.append(f"{name}: {n} replicas pinned to one node by {sorted(mounts_local(tpl, local))}")
        if name == "hub" and mounts_local(tpl, local):
            out.append(f"hub: mounts node-local {sorted(mounts_local(tpl, local))} (it would be pinned to that node)")
        replicated = isinstance(n, int) and n >= 2
        if replicated and (pdbs.get(name) is None or pdbs[name].get("minAvailable") != 1):
            out.append(f"{name}: no PodDisruptionBudget minAvailable 1")
        if not replicated and name in pdbs:
            out.append(f"{name}: a PodDisruptionBudget with {n} replica(s) blocks every drain")
        spread = tpl.get("topologySpreadConstraints") or []
        # Review I1 / M2: the node-local data replicas and Keycloak never
        # co-locate (DoNotSchedule, a tainted node no empty domain); the
        # stateless Deployments ScheduleAnyway.
        hard = name in DO_NOT_SCHEDULE
        want_sp = {"maxSkew": 1, "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "DoNotSchedule" if hard else "ScheduleAnyway",
                   "labelSelector": {"matchLabels": {"portcullis.io/component": name}}}
        if hard:
            want_sp["nodeTaintsPolicy"] = "Honor"
        if replicated and spread != [want_sp]:
            out.append(f"{name}: spread {spread} (want {want_sp})")
        if replicated and kind == "Deployment" and sp.get("strategy", {}).get("rollingUpdate", {}).get("maxUnavailable") != 0:
            out.append(f"{name}: a rollout may take every replica down (RollingUpdate maxUnavailable 0)")
        if kind != "StatefulSet":
            continue
        claims = sp.get("volumeClaimTemplates") or []
        want_claims = ["data"] if name in ("group-gate", "mcp-gate", "alertmanager") else []
        if [c["metadata"]["name"] for c in claims] != want_claims:
            out.append(f"{name}: per-replica PVCs {[c['metadata']['name'] for c in claims]} (want {want_claims})")
        for c in claims:
            a = c["metadata"].get("annotations", {})
            if c["spec"].get("storageClassName") != "portcullis-core" or not {"portcullis.io/uid", "portcullis.io/gid", "portcullis.io/mode"} <= set(a):
                out.append(f"{name}: its data PVCs need portcullis-core and the owner annotations")
        if sp.get("persistentVolumeClaimRetentionPolicy") != {"whenDeleted": "Retain", "whenScaled": "Retain"}:
            out.append(f"{name}: its PVCs must be kept (Retain)")
        if sp.get("podManagementPolicy") != "Parallel":
            out.append(f"{name}: podManagementPolicy {sp.get('podManagementPolicy')} (want Parallel)")
        if name in ("group-gate", "mcp-gate", "keycloak", "alertmanager") and sp["template"]["metadata"]["labels"].get("portcullis.io/ingress") != "bound":
            out.append(f"{name}: not port-bound (portcullis.io/ingress: bound)")
        heads = {"keycloak": "keycloak-pods", "alertmanager": "alertmanager-peers"}
        if name in heads:
            svc = [s for s in K.by_kind(docs, "Service") if s["metadata"]["name"] == heads[name]]
            if sp.get("serviceName") != heads[name] or len(svc) != 1 or svc[0]["spec"].get("clusterIP") != "None":
                out.append(f"{name}: its pods' names need the headless Service {heads[name]}")
    for name, (wk, wn) in want.items():
        if wn > 1 and not any(d.get("kind") == wk and d["metadata"]["name"] == name for d in docs):
            out.append(f"{name}: no {wk}")
    return out


DO_NOT_SCHEDULE = {"group-gate", "mcp-gate", "alertmanager", "keycloak"}


HA_TOLERATIONS = [{"key": "node.kubernetes.io/not-ready", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": 30},
                  {"key": "node.kubernetes.io/unreachable", "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": 30}]


def check_ha_shape():
    """Task 19: the HA render with tests/k8s-ci-values-ha.yaml (and its
    variants: 3 non-small nodes at main, gateReplicas 3) has the replica
    counts, PDBs, spread and classes; every HA pod tolerates a lost node for
    30 s (contract §3.4), none without HA (nodeadm keeps its own); the
    replicated volumes are <name>-r on portcullis-core-replicated in HA,
    portcullis-core without; the Traefik DaemonSet in portcullis-ingress;
    no LoadBalancer for Traefik in HA, wg-people Cluster in HA and Local
    without."""
    base = yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-ha.yaml").read_text())
    for label, vals in (("ha", base), ("ha 3 nodes", {"ha": dict(base["ha"], nonSmallNodesAtPrimary=3)}),
                        ("ha gates 3", {"ha": dict(base["ha"], gateReplicas=3)})):
        docs = K.render(vals)
        for p in gate_shape_problems(docs, vals):
            F.add(f"{label}: {p}")
        for name, ns, labels, spec, ann in K.pod_specs(docs):
            if name == "nodeadm":
                continue
            if spec.get("tolerations") != HA_TOLERATIONS:
                F.add(f"{label}: {name}: tolerations {spec.get('tolerations')} (want not-ready / unreachable at 30 s)")
        pvcs = {c["metadata"]["name"]: c["spec"].get("storageClassName") for c in K.by_kind(docs, "PersistentVolumeClaim")}
        for n in ("hub-state", "hub-secrets", "hub-backups", "domains-data", "wg-data"):
            if pvcs.get(n + "-r") != "portcullis-core-replicated" or n in pvcs:
                F.add(f"{label}: {n}-r must be on portcullis-core-replicated (and no {n}): {pvcs.get(n + '-r')}")
        if "traefik-acme" in pvcs or "vpn-doc" in pvcs:
            F.add(f"{label}: traefik-acme / vpn-doc rendered in HA")
        for s in K.by_kind(docs, "Service"):
            if s["metadata"]["name"] == "traefik" and (s["spec"].get("type") == "LoadBalancer" or s["metadata"]["namespace"] != K.INGRESS_NS):
                F.add(f"{label}: the traefik Service must be a ClusterIP in {K.INGRESS_NS} (hostPorts, no ServiceLB)")
            if s["metadata"]["name"] == "wg-people" and s["spec"].get("externalTrafficPolicy") != "Cluster":
                F.add(f"{label}: wg-people externalTrafficPolicy {s['spec'].get('externalTrafficPolicy')} (want Cluster)")
    plain = K.render()
    for name, ns, labels, spec, ann in K.pod_specs(plain):
        if spec.get("tolerations"):
            F.add(f"{name}: tolerations without ha.enabled")
    pvcs = {c["metadata"]["name"]: c["spec"].get("storageClassName") for c in K.by_kind(plain, "PersistentVolumeClaim")}
    for n in ("hub-state", "hub-secrets", "hub-backups", "domains-data", "wg-data"):
        if pvcs.get(n) != "portcullis-core":
            F.add(f"{n} must be on portcullis-core without HA: {pvcs.get(n)}")
    if [d for d in plain if d.get("kind") in ("StatefulSet", "DaemonSet", "PodDisruptionBudget")]:
        F.add("StatefulSets / DaemonSets / PDBs without ha.enabled")
    for s in K.by_kind(plain, "Service"):
        if s["metadata"]["name"] == "wg-people" and s["spec"].get("externalTrafficPolicy") != "Local":
            F.add("wg-people externalTrafficPolicy must stay Local without HA")
    # The pinning rule bites: a replicated pod on a node-local PVC.
    import copy as _c
    docs = K.render(base)
    bad = _c.deepcopy(docs)
    ff = next(d for d in bad if d.get("kind") == "Deployment" and d["metadata"]["name"] == "forward-auth")
    ff["spec"]["template"]["spec"].setdefault("volumes", []).append({"name": "x", "persistentVolumeClaim": {"claimName": "lldap-data"}})
    if not any("pinned" in p for p in gate_shape_problems(bad, base)):
        F.add("gate_shape_problems misses a replicated pod on a node-local PVC (mutation test)")


def check_log_ports():
    """HA (contract §20.10): every HA pod has the baseline; group-gate and
    mcp-gate are StatefulSets of ha.gateReplicas, each replica its own
    `data` PVC (no shared group-gate-data / mcp-gate-data), port-bound,
    with a PDB keeping one up; the log ports and group-gate's own pruning
    are set only in HA, and there no pod but its owner mounts a gate's or
    wg's data (the Hub reads them over the ports: HUB_GATE_LOG_SOURCES)."""
    ha = K.render({"ha": {"enabled": True}})
    plain = K.render()
    for name, ns, labels, spec, ann in K.pod_specs(ha):
        check_pod(name, ns, labels, spec, ann)
    envs = lambda docs: {n: {e["name"]: e.get("value") for c in sp["containers"] for e in c.get("env", [])}
                         for n, _, _, sp, _ in K.pod_specs(docs)}
    ports = lambda docs: {n: {p["containerPort"] for c in sp["containers"] for p in c.get("ports", [])}
                          for n, _, _, sp, _ in K.pod_specs(docs)}
    he, pe, hp, pp = envs(ha), envs(plain), ports(ha), ports(plain)
    for svc, (var, value, port) in LOG_PORTS.items():
        if he.get(svc, {}).get(var) != value or port not in hp.get(svc, set()):
            F.add(f"ha: {svc} must serve its log port {port} ({var}={value})")
        if var in pe.get(svc, {}) or port in pp.get(svc, set()):
            F.add(f"{svc}: the log port {port} without ha.enabled")
    if he.get("group-gate", {}).get("GATE_OPENED_PRUNE_DAYS") != "365" or "GATE_OPENED_PRUNE_DAYS" in pe.get("group-gate", {}):
        F.add("group-gate prunes its own log (GATE_OPENED_PRUNE_DAYS=365) in HA only")
    if he.get("hub", {}).get("HUB_GATE_LOG_SOURCES") != "http" or "HUB_GATE_LOG_SOURCES" in pe.get("hub", {}):
        F.add("the Hub reads the gates over HTTP (HUB_GATE_LOG_SOURCES=http) in HA only")
    for n in (0, 17):
        try:
            K.render({"ha": {"enabled": True, "gateReplicas": n}})
            F.add(f"ha: gateReplicas {n} renders (must be refused: the Hub takes 1-16)")
        except K.subprocess.CalledProcessError:
            pass
    K.render({"ha": {"enabled": True, "gateReplicas": 16}})
    pvcs = {c["metadata"]["name"] for c in K.by_kind(ha, "PersistentVolumeClaim")}
    if pvcs & {"group-gate-data", "mcp-gate-data"}:
        F.add(f"ha: the shared gate PVCs still render: {sorted(pvcs & {'group-gate-data', 'mcp-gate-data'})}")
    for name, _, _, spec, _ in K.pod_specs(ha):
        for v in spec.get("volumes", []):
            c = (v.get("persistentVolumeClaim") or {}).get("claimName")
            if c in ("group-gate-data", "mcp-gate-data", "wg-data") and name != c[: -len("-data")]:
                F.add(f"ha: {name} mounts {c} (the log ports replace it)")


def main():
    # Every profile on, and the one-shots.
    docs = K.render()
    for oneshot in ("dns-tool", "hub"):
        docs += K.render({"oneshot": oneshot}, "templates/oneshot.yaml")
    for name, ns, labels, spec, ann in K.pod_specs(docs):
        if ns != K.NS:
            F.add(f"{name}: a workload outside the core namespace ({ns})")
        check_pod(name, ns, labels, spec, ann)
    for p in sorted((K.CHART / "templates").glob("*")):
        t = p.read_text()
        for bad in ("randAlphaNum", "randAscii", "randAlpha", "randNumeric", "genPrivateKey", "genCA", "genSignedCert", "genSelfSignedCert", "lookup "):
            if bad in t:
                F.add(f"{p.name}: {bad} (the chart never generates or looks up secrets)")
    # Services: no NodePort, no externalIPs; LoadBalancers only traefik and wg-people.
    for s in K.by_kind(docs, "Service"):
        sp = s["spec"]
        if sp.get("type") == "NodePort" or sp.get("externalIPs"):
            F.add(f"service {s['metadata']['name']}: NodePort / externalIPs")
        if sp.get("type") == "LoadBalancer":
            ports = sorted((p["port"], p.get("protocol", "TCP")) for p in sp["ports"])
            if s["metadata"]["name"] == "traefik" and ports != [(80, "TCP"), (443, "TCP")]:
                F.add(f"service traefik: LoadBalancer ports {ports} (only 80, 443)")
            elif s["metadata"]["name"] == "wg-people" and [p for _, p in ports] != ["UDP"]:
                F.add(f"service wg-people: ports {ports}")
            elif s["metadata"]["name"] not in ("traefik", "wg-people"):
                F.add(f"service {s['metadata']['name']}: a LoadBalancer")
    # The Hub's Role: exactly the contract's rules (K2), nothing cluster-scoped.
    for r in K.by_kind(docs, "ClusterRole") + K.by_kind(docs, "ClusterRoleBinding"):
        F.add(f"{r['kind']} {r['metadata']['name']}: nothing cluster-scoped")
    hub_roles = [r for r in K.by_kind(docs, "Role") if r["metadata"]["name"] == "portcullis-hub"]
    if sorted(r["metadata"]["namespace"] for r in hub_roles) != sorted([K.APPS_NS, K.EDGE_NS]):
        F.add(f"the Hub's Roles must be exactly two, in {K.APPS_NS} and {K.EDGE_NS}")
    for r in hub_roles:
        traefik_rules = [x for x in r["rules"] if "traefik.io" in x.get("apiGroups", [])]
        if r["metadata"]["namespace"] == K.EDGE_NS:
            if sorted((tuple(x["apiGroups"]), tuple(sorted(x["resources"]))) for x in r["rules"]) != [(("",), ("services",)), (("traefik.io",), ("ingressroutes", "middlewares"))]:
                F.add(f"the Hub's Role in {K.EDGE_NS}: only traefik.io ingressroutes + middlewares and services (its pinned ExternalName backends), got {r['rules']}")
        elif traefik_rules:
            F.add(f"the Hub's Role in {r['metadata']['namespace']}: traefik.io (Traefik objects live in {K.EDGE_NS})")
    # The Hub's edge Services are safe only under portcullis-edge-routes'
    # Service rule (ExternalName pinned to its own apps name): a Role that
    # grants services there without that rule fails.
    pol = next((d for d in yaml.safe_load_all((K.ROOT / "kube" / "admission" / "policies.yaml").read_text())
                if d and d.get("metadata", {}).get("name") == "portcullis-edge-routes"), None)
    judges_svc = bool(pol) and any("" in rr.get("apiGroups", []) and "services" in rr.get("resources", [])
                                   and {"CREATE", "UPDATE", "DELETE"} <= set(rr.get("operations", []))
                                   for rr in pol["spec"]["matchConstraints"]["resourceRules"])
    pins = bool(pol) and any("object.spec.externalName == object.metadata.name + '.' + variables.apps + '.svc.cluster.local'" in v["expression"]
                             for v in pol["spec"]["validations"])
    # CEL strings are single-quoted: an odd count of quotes in an expression
    # is a string that never ends (the API server refuses the whole policy).
    for d in yaml.safe_load_all((K.ROOT / "kube" / "admission" / "policies.yaml").read_text()):
        if not d or d.get("kind") != "ValidatingAdmissionPolicy":
            continue
        exprs = [v.get("expression", "") for v in d["spec"].get("variables", [])]
        exprs += [v.get(k, "") for v in d["spec"].get("validations", []) for k in ("expression", "messageExpression")]
        for e in exprs:
            # A YAML '' escape leaked into CEL (apps'' …) or an odd count.
            if e.replace("\\'", "").count("'") % 2 or re.search(r"[A-Za-z]''[A-Za-z ]", e):
                F.add(f"policy {d['metadata']['name']}: broken quotes in CEL: {e[:120]}")
    # The root shape is written once per policy (rootPod, rootShaped) and
    # used by both oneShot and the root init containers: the pods and the
    # workloads policies must agree on it, and on oneShot's tail.
    pols = {d["metadata"]["name"]: d for d in yaml.safe_load_all((K.ROOT / "kube" / "admission" / "policies.yaml").read_text())
            if d and d.get("kind") == "ValidatingAdmissionPolicy"}
    def var(pol, name):
        return next((" ".join(v["expression"].split()) for v in pols.get(pol, {}).get("spec", {}).get("variables", []) if v["name"] == name), None)
    for name in ("rootPod", "rootShaped"):
        a, b = var("portcullis-apps-pods", name), var("portcullis-apps-workloads", name)
        if not a or a != b:
            F.add(f"policies: the {name} variable differs between portcullis-apps-pods and portcullis-apps-workloads (or is missing)")
    tails = [(var(p, "oneShot") or "").partition("&& variables.rootPod")[2] for p in ("portcullis-apps-pods", "portcullis-apps-workloads")]
    if not tails[0] or tails[0] != tails[1] or "variables.rootShaped" not in tails[0]:
        F.add("policies: oneShot's root-shape tail (rootPod, own volumes, rootShaped) differs between the pods and workloads policies")
    for p in ("portcullis-apps-pods", "portcullis-apps-workloads"):
        if not any("c.name in variables.initNames && variables.rootPod && c.name in variables.rootShaped" in " ".join(v["expression"].split())
                   for v in pols.get(p, {}).get("spec", {}).get("validations", [])):
            F.add(f"policy {p}: the root init-container rule doesn't use rootPod and rootShaped")
    for r in hub_roles:
        if r["metadata"]["namespace"] == K.EDGE_NS and any("services" in x["resources"] for x in r["rules"]) and not (judges_svc and pins):
            F.add(f"the Hub's Role in {K.EDGE_NS} grants services but portcullis-edge-routes doesn't judge and pin Services (CREATE / UPDATE / DELETE, externalName = <name>.<apps ns>.svc.cluster.local)")
    for r in hub_roles + [x for x in K.by_kind(docs, "Role") if x["metadata"]["name"] == "portcullis-hub-core"]:
        for rule in r["rules"]:
            if "pods/exec" in rule["resources"] and rule["verbs"] != ["create"]:
                F.add("the Hub's Role: pods/exec must be create only, never get (K2)")
            if "pods" in rule["resources"] and set(rule["verbs"]) & {"patch", "update"}:
                F.add("the Hub's Role: never patch / update on pods")
            if set(rule["resources"]) & {"roles", "rolebindings", "serviceaccounts", "namespaces", "nodes", "pods/ephemeralcontainers"}:
                F.add(f"the Hub's Role: {rule['resources']}")
            if set(rule["verbs"]) & {"escalate", "bind", "impersonate", "*"}:
                F.add(f"the Hub's Role: verbs {rule['verbs']}")
            if "metrics.k8s.io" in rule.get("apiGroups", []) and (rule["resources"] != ["pods"] or sorted(rule["verbs"]) != ["get", "list"]):
                F.add("the Hub's Role: metrics.k8s.io only pods get/list (the Usage page; never nodes)")
            if any(x.startswith("nodes") for x in rule["resources"]):
                F.add(f"the Hub's Role: never nodes, nodes/stats or nodes/proxy ({rule['resources']})")
    # What Traefik 3.7's CRD provider lists in a watched namespace: a
    # resource it can't list keeps it from loading any route (e2e-k3s saw
    # configmaps forbidden → every core route 404).
    TRAEFIK_NEEDS = {("", "services"), ("", "secrets"), ("", "configmaps"), ("discovery.k8s.io", "endpointslices"),
                     ("traefik.io", "ingressroutes"), ("traefik.io", "middlewares"), ("traefik.io", "serverstransports"),
                     ("traefik.io", "tlsoptions"), ("traefik.io", "tlsstores"), ("traefik.io", "traefikservices")}
    for r in K.by_kind(docs, "Role"):
        if r["metadata"]["name"] == "traefik":
            have = {(g, res) for rule in r["rules"] if {"list", "watch"} <= set(rule["verbs"]) for g in rule["apiGroups"] for res in rule["resources"]}
            for g, res in sorted(TRAEFIK_NEEDS - have):
                F.add(f"Traefik's Role in {r['metadata']['namespace']}: no list / watch on {g or 'core'}/{res} (its CRD provider loads no route without it)")
            for rule in r["rules"]:
                if set(rule["verbs"]) - {"get", "list", "watch"}:
                    F.add(f"Traefik's Role in {r['metadata']['namespace']}: {rule['verbs']} (read-only)")
    check_secret_access(docs + storage_docs())
    check_edge(docs)
    check_edge(K.render(yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-ha.yaml").read_text())))
    check_frontdoor()
    check_hub_core()
    check_nodeadm()
    check_log_ports()
    check_ha_shape()
    check_psa()
    check_priorities()
    check_classes(docs + K.render({"ha": {"enabled": True}}))
    check_core_exec()
    check_placement_twins()
    check_token_literal()
    check_ingress_allowlists(K.render({"ha": {"enabled": True}}) + docs)
    # Every PVC a pod claims is rendered, with and without the optional
    # profiles (compose's named volumes exist in every profile), and in HA.
    for extra in (None, {"wg": {"enabled": False}}, {"ha": {"enabled": True}}):
        d = K.render(extra)
        have = {c["metadata"]["name"] for c in K.by_kind(d, "PersistentVolumeClaim")}
        for name, _, _, spec, _ in K.pod_specs(d):
            for v in spec.get("volumes", []):
                c = (v.get("persistentVolumeClaim") or {}).get("claimName")
                if c and c not in have:
                    F.add(f"{name}: claims PVC {c}, not rendered ({'CI values' if extra is None else extra})")
    return F.done()


# The PSA levels: charts/portcullis/namespaces.json is the one source (the
# CLI's kube_psa and templates/namespaces.yaml read it). Core and edge
# restricted; apps (root one-shots), storage (the helpers' hostPath) and
# (HA) ingress (Traefik's hostPort 80/443, pinned by portcullis-ingress-pods)
# can't be stricter than enforce privileged, warn / audit baseline.
PSA_WANT = {"core": ["restricted"] * 3, "apps": ["privileged", "baseline", "baseline"],
            "storage": ["privileged", "baseline", "baseline"], "edge": ["restricted"] * 3,
            "ingress": ["privileged", "baseline", "baseline"],
            # nodeadm: restricted (no etcd key, no hostPath: review I6).
            "nodeadm": ["restricted"] * 3}


NODEADM_NS = "portcullis-nodeadm"
NODEADM_VALUES = {"nodeadm": {"enabled": True, "image": "ghcr.io/porelli/portcullis-nodeadm@sha256:" + "4" * 64}}
NODEADM_CLUSTER_RULES = [
    {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get", "list", "watch", "patch", "delete"]},
    {"apiGroups": [""], "resources": ["pods"], "verbs": ["list", "watch"]},
    {"apiGroups": [""], "resources": ["pods/eviction"], "verbs": ["create"]},
    {"apiGroups": ["postgresql.cnpg.io"], "resources": ["clusters"], "verbs": ["get", "list"]},
    {"apiGroups": ["longhorn.io"], "resources": ["volumes", "nodes", "replicas"], "verbs": ["get", "list"]},
    {"apiGroups": ["self-node-remediation.medik8s.io"], "resources": ["selfnoderemediations"], "verbs": ["get", "list"]},
]
NODEADM_CORE_RULES = [
    {"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["nodeadm-k3s-token", "frontdoor-control-tls", "nodeadm-state"], "verbs": ["get", "update"]},
    {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["portcullis-cluster-addresses"], "verbs": ["update"]},
    {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["portcullis-admission-active"], "verbs": ["get"]},
    {"apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "resourceNames": ["portcullis-nodeadm"], "verbs": ["get", "update"]},
]
NODEADM_KUBE_SYSTEM_RULES = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create", "delete"]}]
NODEADM_LONGHORN_RULES = [{"apiGroups": ["longhorn.io"], "resources": ["nodes"], "verbs": ["get", "patch"]}]
ADMISSION_RESOURCES = {"validatingadmissionpolicies", "validatingadmissionpolicybindings", "mutatingwebhookconfigurations",
                       "validatingwebhookconfigurations", "mutatingadmissionpolicies", "mutatingadmissionpolicybindings"}


def check_nodeadm():
    """nodeadm (contract §20.2, ruling R-ADM), rendered with nodeadm.enabled
    only: one pod in portcullis-nodeadm on a server node; one container,
    restricted as 10010; no init container, no hostPath, no etcd key (review
    I6); its RBAC exactly the contract's (no admission object anywhere, no
    ConfigMap create, Secrets only by name in the core namespace and create /
    delete in kube-system: bootstrap tokens)."""
    if [d for d in K.render() if d.get("metadata", {}).get("namespace") == NODEADM_NS or "nodeadm" in d.get("metadata", {}).get("name", "")]:
        F.add("nodeadm renders without nodeadm.enabled")
    for ha in (False, True):
        vals = dict(NODEADM_VALUES, ha={"enabled": ha})
        docs = K.render(vals)
        pods = [p for p in K.pod_specs(docs) if p[0] == "nodeadm"]
        if len(pods) != 1 or pods[0][1] != NODEADM_NS:
            F.add(f"nodeadm: {len(pods)} pods (want one in {NODEADM_NS})")
            return
        name, ns, labels, spec, ann = pods[0]
        if spec.get("nodeSelector") != {"node-role.kubernetes.io/control-plane": "true"}:
            F.add(f"nodeadm: nodeSelector {spec.get('nodeSelector')} (server nodes only)")
        if spec.get("priorityClassName") != "portcullis-core" or spec.get("serviceAccountName") != "nodeadm":
            F.add("nodeadm: priority class / ServiceAccount")
        for k in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(k):
                F.add(f"nodeadm: {k}")
        for v in spec.get("volumes", []):
            kinds = set(v) - {"name"}
            if not kinds <= RESTRICTED_VOLUMES:
                F.add(f"nodeadm: volume {v['name']} {sorted(kinds)} (restricted volumes only)")
        inits, mains = spec.get("initContainers", []), spec.get("containers", [])
        if inits or [c["name"] for c in mains] != ["nodeadm"]:
            F.add("nodeadm: containers")
            return
        for c in inits + mains:
            sc = c.get("securityContext", {})
            if sc.get("allowPrivilegeEscalation") is not False or sc.get("privileged") or sc.get("readOnlyRootFilesystem") is not True \
                    or sc.get("capabilities") != {"drop": ["ALL"]}:
                F.add(f"nodeadm/{c['name']}: the baseline (no escalation, drop ALL and add nothing, read-only root)")
            res = c.get("resources", {})
            if not res.get("limits", {}).get("memory") or res["limits"]["memory"] != res.get("requests", {}).get("memory"):
                F.add(f"nodeadm/{c['name']}: memory limit != request")
            if not re.search(r"@sha256:[0-9a-f]{64}$", c["image"]):
                F.add(f"nodeadm/{c['name']}: image not by digest")
        msc = mains[0]["securityContext"]
        if msc.get("runAsUser") != 10010 or msc.get("runAsNonRoot") is not True:
            F.add(f"nodeadm: runs as {msc.get('runAsUser')} (10010, non-root)")
        if (spec.get("securityContext", {}).get("seccompProfile") or {}).get("type") != "RuntimeDefault":
            F.add("nodeadm: seccomp")
        secrets = {v["secret"]["secretName"] for v in spec.get("volumes", []) if "secret" in v}
        if secrets != {"nodeadm-enroll"}:
            F.add(f"nodeadm: mounts {sorted(secrets)}")
        # RBAC.
        cr = [d for d in K.by_kind(docs, "ClusterRole") if d["metadata"]["name"] == "portcullis-nodeadm"]
        if len(cr) != 1 or cr[0]["rules"] != NODEADM_CLUSTER_RULES:
            F.add(f"nodeadm's ClusterRole must be exactly {NODEADM_CLUSTER_RULES}")
        roles = {(r["metadata"]["namespace"], r["metadata"]["name"]): r["rules"] for r in K.by_kind(docs, "Role")
                 if any(s.get("name") == "nodeadm" for b in K.by_kind(docs, "RoleBinding")
                        if b["roleRef"]["name"] == r["metadata"]["name"] and b["metadata"]["namespace"] == r["metadata"]["namespace"]
                        for s in b.get("subjects", []))}
        want = {(K.NS, "portcullis-nodeadm"): NODEADM_CORE_RULES, ("kube-system", "portcullis-nodeadm"): NODEADM_KUBE_SYSTEM_RULES}
        if ha:
            want[("longhorn-system", "portcullis-nodeadm")] = NODEADM_LONGHORN_RULES
        if roles != want:
            F.add(f"nodeadm's Roles {roles} != {want}")
        for d in K.by_kind(docs, "ClusterRole") + K.by_kind(docs, "Role"):
            if "nodeadm" in d["metadata"]["name"]:
                for r in d["rules"]:
                    if set(r.get("resources", [])) & ADMISSION_RESOURCES or "*" in r.get("resources", []) + r.get("verbs", []):
                        F.add(f"{d['kind']} {d['metadata']['name']}: an admission object or a wildcard (ruling R-ADM)")
                    if "configmaps" in r.get("resources", []) and {"create", "delete", "patch"} & set(r["verbs"]):
                        F.add(f"{d['kind']} {d['metadata']['name']}: configmaps {r['verbs']} (update the addresses, get the active record only)")
        got = secret_access(docs).get(f"{NODEADM_NS}/nodeadm", set())
        if got != {K.NS}:
            F.add(f"nodeadm reads Secrets in {sorted(got)} (the core namespace's three, by name)")
        if any(d.get("kind") in ("Secret", "ConfigMap") and d["metadata"]["name"] in ("nodeadm-k3s-token", "nodeadm-state", "portcullis-cluster-addresses")
               for d in docs):
            F.add("the chart renders an object nodeadm writes (the CLI creates them, never Helm)")


def check_psa():
    src = json.loads((K.CHART / "namespaces.json").read_text())
    for role, want in PSA_WANT.items():
        if src.get(role) != want:
            F.add(f"namespaces.json {role}: {src.get(role)} (want {want})")
    names = {"core": K.NS, "apps": K.APPS_NS, "storage": "portcullis-storage", "edge": K.EDGE_NS, "ingress": "portcullis-ingress",
             "nodeadm": NODEADM_NS}
    ns = {d["metadata"]["name"]: d["metadata"].get("labels", {}) for d in K.by_kind(K.render({"renderNamespaces": True}), "Namespace")}
    for role, n in names.items():
        got = [ns.get(n, {}).get(f"pod-security.kubernetes.io/{m}") for m in ("enforce", "warn", "audit")]
        if got != src.get(role):
            F.add(f"the chart's namespace {n}: PSA {got} != namespaces.json {role} {src.get(role)}")
    kube = (K.ROOT / "scripts" / "lib" / "kube.sh").read_text()
    if re.search(r"kube_namespace_apply\s+\S+\s+(privileged|baseline|restricted)\b", kube) or re.search(r"(privileged|baseline|restricted),(privileged|baseline|restricted)", kube):
        F.add("scripts/lib/kube.sh spells PSA levels itself: kube_psa reads charts/portcullis/namespaces.json")


# The PriorityClasses (NEW, HA; plan Global Constraints): exactly five, no
# globalDefault (every pod names its class), portcullis-low never preempts.
PRIORITIES = {"portcullis-core": (1000000, "PreemptLowerPriority"), "portcullis-critical": (100000, "PreemptLowerPriority"),
              "portcullis-high": (10000, "PreemptLowerPriority"), "portcullis-normal": (1000, "PreemptLowerPriority"),
              "portcullis-low": (100, "Never")}


def check_priorities():
    docs = [d for d in yaml.safe_load_all((K.ROOT / "kube" / "priorityclasses.yaml").read_text()) if d]
    got = {d["metadata"]["name"]: (d["value"], d.get("preemptionPolicy"), d.get("globalDefault", False)) for d in docs if d.get("kind") == "PriorityClass"}
    want = {n: (v, p, False) for n, (v, p) in PRIORITIES.items()}  # no globalDefault (M-B)
    if got != want or len(docs) != len(want):
        F.add(f"kube/priorityclasses.yaml {got} != {want}")
    for p in sorted((K.CHART / "templates").glob("*")):
        if "kind: PriorityClass" in p.read_text():
            F.add(f"{p.name}: a PriorityClass in the chart (kube/priorityclasses.yaml is the CLI's, applied before anything names one)")


# Every pod that isn't an app's names a class (Task 18 fix round, ruling
# I5): without one it has priority 0 and app pods at any class preempt it,
# and N−1 counts it as evictable. Core and infrastructure: portcullis-core,
# or portcullis-critical where the plan assigns it to an infrastructure
# piece (the coordinator's I5 ruling allows it), or a system-* class. Every
# pod template of the chart (every profile, HA too) and of kube/ (the CLI's
# manifests, HA infrastructure included); the CLI's jq-built pods are held
# to portcullis-core by tests/test_shell_libs.sh.
CLASS_OK = re.compile(r"^(portcullis-core|portcullis-critical|system-node-critical|system-cluster-critical)$")
POD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}


def pod_spec_of(d):
    k = d.get("kind")
    if k == "Pod":
        return d.get("spec", {})
    if k == "CronJob":
        return d["spec"]["jobTemplate"]["spec"]["template"].get("spec", {})
    return d.get("spec", {}).get("template", {}).get("spec", {})


def check_classes(chart_docs):
    kube_docs = []
    for f in sorted((K.ROOT / "kube").rglob("*.yaml")):
        if "admission" in f.parts or f.name.endswith(".tmpl.yaml"):
            continue
        kube_docs += [(f.relative_to(K.ROOT), d) for d in yaml.safe_load_all(f.read_text()) if d]
    for where, d in [("chart", d) for d in chart_docs] + kube_docs:
        if not isinstance(d, dict) or d.get("kind") not in POD_KINDS:
            continue
        c = pod_spec_of(d).get("priorityClassName")
        if not c or not CLASS_OK.match(c):
            F.add(f"{where}: {d['kind']} {d['metadata'].get('name')}: priorityClassName {c} (every non-app pod: portcullis-core, portcullis-critical or system-*)")


# The placement rules are written twice (pods, workloads): equal but for the
# guard (tests can't make CEL share an expression).
def check_placement_twins():
    pols = {d["metadata"]["name"]: d for d in yaml.safe_load_all((K.ROOT / "kube" / "admission" / "policies.yaml").read_text()) if d}
    msgs = ("app pods may use only", "the portcullis.io/small toleration", "nodeName is refused", "topologySpreadConstraints and affinity")

    def block(name):
        out = []
        for v in pols[name]["spec"]["validations"]:
            if any(str(v.get("message", "")).startswith(m) for m in msgs):
                e = v["expression"].split("\n", 1)[1]
                out.append((v["message"], e.replace("request.operation != 'CREATE' || ", "")))
        return out
    a, b = block("portcullis-apps-pods"), block("portcullis-apps-workloads")
    if len(a) != 4 or a != b:
        F.add("the placement rules of portcullis-apps-pods and portcullis-apps-workloads differ (beyond the guard and the pod-only nodeName create)")


# The token policy's matchCondition literal is the CLI's KUBE_NODEADM_SA
# (a matchCondition can't read params).
def check_token_literal():
    pol = [d for d in yaml.safe_load_all((K.ROOT / "kube" / "admission" / "nodeadm-tokens.yaml").read_text()) if d][0]
    sa = re.search(r'^KUBE_NODEADM_SA="([^"]+)"', (K.ROOT / "scripts" / "lib" / "kube_install.sh").read_text(), re.M)
    conds = [c["expression"] for c in pol["spec"].get("matchConditions", [])]
    if not sa or conds != [f"request.userInfo.username == '{sa.group(1)}'"]:
        F.add(f"portcullis-nodeadm-tokens matchConditions {conds} != the CLI's KUBE_NODEADM_SA {sa and sa.group(1)}")


# portcullis-ingress-pods' allowlists hold the chart's Traefik pod: its
# environment names, its Secrets (volumes and valueFrom) and ConfigMaps, no
# command or args, no exec probe but `traefik healthcheck --ping`, no
# lifecycle hook but sleep. A Traefik pod in portcullis-ingress (Task 19's
# DaemonSet) is also held to the policy's volume kinds (emptyDir,
# configMap, secret, projected): the chart's acme PVC must be gone by then
# (today's Traefik is the core namespace's Deployment).
def check_ingress_allowlists(docs):
    pol = next(d for d in yaml.safe_load_all((K.ROOT / "kube" / "admission" / "policies.yaml").read_text())
               if d and d["metadata"]["name"] == "portcullis-ingress-pods")
    var = {v["name"]: set(re.findall(r"'([^']*)'", v["expression"])) for v in pol["spec"]["variables"] if v["name"].startswith("traefik")}
    found = False
    for d in docs:
        if d.get("kind") not in POD_KINDS or d["metadata"].get("name") != "traefik":
            continue
        found = True
        spec = pod_spec_of(d)
        in_ingress = d["metadata"].get("namespace") == "portcullis-ingress"
        for c in spec["containers"]:
            if c.get("command") or c.get("args") or c.get("envFrom"):
                F.add("traefik: command / args / envFrom (portcullis-ingress-pods refuses them)")
            for pr in ("startupProbe", "livenessProbe", "readinessProbe"):
                ex = c.get(pr, {}).get("exec")
                if ex is not None and ex.get("command") != ["traefik", "healthcheck", "--ping"]:
                    F.add(f"traefik: {pr} exec {ex} (only traefik healthcheck --ping)")
            for hk, h in c.get("lifecycle", {}).items():
                if set(h) - {"sleep"}:
                    F.add(f"traefik: lifecycle {hk} {h} (sleep only)")
            for e in c.get("env", []):
                if e["name"] not in var["traefikEnv"]:
                    F.add(f"traefik: env {e['name']} not in portcullis-ingress-pods' traefikEnv")
                ref = e.get("valueFrom", {}).get("secretKeyRef")
                if e.get("valueFrom") and (not ref or ref["name"] not in var["traefikSecrets"]):
                    F.add(f"traefik: env {e['name']} from {e['valueFrom']} (only secretKeyRef of traefikSecrets)")
        for v in spec.get("volumes", []):
            kinds = set(v) - {"name"}
            if in_ingress and not kinds <= {"emptyDir", "configMap", "secret", "projected"}:
                F.add(f"traefik in portcullis-ingress: volume {v['name']} {sorted(kinds)} (only emptyDir, configMap, secret, projected)")
            srcs = v.get("projected", {}).get("sources", []) + [v]
            for s in srcs:
                if "configMap" in s and s["configMap"]["name"] not in var["traefikConfigMaps"]:
                    F.add(f"traefik: ConfigMap {s['configMap']['name']} not in traefikConfigMaps")
                if "secret" in s and (s["secret"].get("secretName") or s["secret"].get("name")) not in var["traefikSecrets"]:
                    F.add(f"traefik: Secret {s['secret']} not in traefikSecrets")
    if not found:
        F.add("no traefik pod rendered")


# portcullis-core-exec (NEW, HA; contract §6 "core exec"): its document
# literals are tests/published_docs.json's: /vpn-doc vpn, /hub-data the
# other seven; the reader pod prefixes are the documents' readers.
def check_core_exec():
    pol = next((d for d in yaml.safe_load_all((K.ROOT / "kube" / "admission" / "policies.yaml").read_text())
                if d and d.get("metadata", {}).get("name") == "portcullis-core-exec"), None)
    if not pol:
        F.add("kube/admission/policies.yaml has no portcullis-core-exec")
        return
    expr = "\n".join(v["expression"] for v in pol["spec"]["validations"])
    docs = json.loads((K.ROOT / "tests" / "published_docs.json").read_text())
    by_mount = {}
    for d in docs:
        by_mount.setdefault(d["mount"], []).append(d["doc"])
    hub = re.search(r"variables\.cmd\[2\] == '/hub-data'\s*&& \(variables\.cmd\[3\] in \[([^\]]*)\]", expr)
    vpn = re.findall(r"variables\.cmd\[2\] == '/vpn-doc' && variables\.cmd\[3\] == '([^']*)'", expr)
    hub_docs = re.findall(r"'([^']*)'", hub.group(1)) if hub else None
    if hub_docs != by_mount.get("/hub-data") or vpn != by_mount.get("/vpn-doc"):
        F.add(f"portcullis-core-exec documents /hub-data {hub_docs}, /vpn-doc {vpn} != tests/published_docs.json {by_mount}")
    prefixes = re.search(r"\[([^\]]*)\]\.exists\(p, request\.name\.startsWith\(p\)\)", expr)
    readers = sorted({r + "-" for d in docs for r in d["readers"]})
    if not prefixes or sorted(re.findall(r"'([^']*)'", prefixes.group(1))) != readers:
        F.add(f"portcullis-core-exec reader pods {prefixes and prefixes.group(1)} != the documents' readers {readers}")


APP_ENTRYPOINTS = {"web", "websecure", "vpnsecure"}


def core_route_problems(docs, cr):
    """Hosts are disjoint (reservedHosts), so a core route can lose to an app
    route only where a core rule without Host(...) can match an app host:
    every such rule must be on an entrypoint apps can't use, or rank above
    maxAppPriority (its priority, else Traefik's default len(rule)); every
    Host-limited core rule names reserved hosts only. Defence in depth (a
    host-check bypass): every core route on an app entrypoint has an
    explicit priority above maxAppPriority."""
    dom = K.domain(docs)
    reserved = {dom} | {f"{s}.{dom}" for s in cr["subdomains"]}
    out = []
    for ir in K.by_kind(docs, "IngressRoute"):
        name, eps = ir["metadata"]["name"], set(ir["spec"].get("entryPoints") or [])
        for r in ir["spec"]["routes"]:
            if eps & APP_ENTRYPOINTS and not (isinstance(r.get("priority"), int) and r["priority"] > cr["maxAppPriority"]):
                out.append(f"IngressRoute {name}: on {sorted(eps & APP_ENTRYPOINTS)} at priority {r.get('priority')} (needs an explicit one above maxAppPriority {cr['maxAppPriority']})")
            hosts = re.findall(r"Host\(`([^`]*)`\)", r["match"])
            if not hosts:
                prio = r.get("priority") or len(r["match"])
                if (not eps or eps & APP_ENTRYPOINTS) and prio <= cr["maxAppPriority"]:
                    out.append(f"IngressRoute {name}: a rule without Host(...) on {sorted(eps) or 'every entrypoint'} at priority {prio} <= maxAppPriority {cr['maxAppPriority']}")
            for h in hosts:
                if h.lower() not in reserved:
                    out.append(f"IngressRoute {name}: host {h} isn't in reservedHosts (core-routes.json)")
    return out


def _hostless_on_websecure(docs):
    ir = next(d for d in docs if d.get("kind") == "IngressRoute" and d["metadata"]["name"] == "kcinternal")
    ir["spec"]["entryPoints"] = ["websecure"]
    ir["spec"]["routes"][0]["priority"] = 5
    return docs


def _hostless_no_entrypoints(docs):
    ir = next(d for d in docs if d.get("kind") == "IngressRoute" and d["metadata"]["name"] == "kcinternal")
    del ir["spec"]["entryPoints"]
    return docs


def _unreserved_host(docs):
    ir = next(d for d in docs if d.get("kind") == "IngressRoute" and d["metadata"]["name"] == "hub")
    ir["spec"]["routes"][0]["match"] = ir["spec"]["routes"][0]["match"].replace("hub.", "hubx.")
    return docs


def _core_low_priority(docs):
    ir = next(d for d in docs if d.get("kind") == "IngressRoute" and d["metadata"]["name"] == "core-vpn-required")
    ir["spec"]["routes"][0]["priority"] = 1
    return docs


def _core_no_priority(docs):
    ir = next(d for d in docs if d.get("kind") == "IngressRoute" and d["metadata"]["name"] == "hub")
    del ir["spec"]["routes"][0]["priority"]
    return docs


MUTATIONS = [
    ("a core route on websecure at priority 1", _core_low_priority),
    ("a core route on websecure without an explicit priority", _core_no_priority),
    ("a Host-less rule on websecure below the cap", _hostless_on_websecure),
    ("a Host-less rule on every entrypoint", _hostless_no_entrypoints),
    ("a core host outside reservedHosts", _unreserved_host),
]


def storage_docs():
    out = []
    for p in sorted((K.ROOT / "kube" / "storage").glob("*.yaml")):
        out += [d for d in yaml.safe_load_all(p.read_text()) if d]
    return out


def reads_secrets(rule):
    return (set(rule.get("apiGroups", [])) & {"", "*"}) and (set(rule.get("resources", [])) & {"secrets", "*"}) \
        and (set(rule.get("verbs", [])) & SECRET_READ_VERBS)


def secret_access(docs):
    """{"ns/sa": {namespace or "*"}} — where each ServiceAccount may read Secrets."""
    roles = {(d["kind"], d["metadata"].get("namespace", ""), d["metadata"]["name"]): d
             for d in docs if d.get("kind") in ("Role", "ClusterRole")}
    out = {}
    for b in docs:
        if b.get("kind") not in ("RoleBinding", "ClusterRoleBinding"):
            continue
        ref = b["roleRef"]
        bns = b["metadata"].get("namespace", "")
        role = roles.get((ref["kind"], bns if ref["kind"] == "Role" else "", ref["name"]))
        if role is None:
            F.add(f"{b['kind']} {bns}/{b['metadata']['name']}: its {ref['kind']} {ref['name']} isn't rendered")
            continue
        rules = [r for r in role.get("rules", []) if reads_secrets(r)]
        if not rules:
            continue
        where = bns if b["kind"] == "RoleBinding" else "*"
        for s in b.get("subjects", []):
            key = f"{s.get('namespace', bns)}/{s['name']}" if s["kind"] == "ServiceAccount" else f"{s['kind']}:{s['name']}"
            names = SECRET_BY_NAME.get((where, key))
            if names is not None and all(r.get("resourceNames") and set(r["resourceNames"]) <= names for r in rules):
                continue
            out.setdefault(key, set()).add(where)
    return out


def check_secret_access(docs, ha=False):
    got = secret_access(docs)
    want = SECRET_READERS_HA if ha else SECRET_READERS
    for sa in sorted(set(got) | set(want)):
        if got.get(sa, set()) != want.get(sa, set()):
            F.add(f"{'ha: ' if ha else ''}Secret access of {sa}: {sorted(got.get(sa, set()))} (want {sorted(want.get(sa, set()))})")
    # portcullis-env lives in the core namespace: Traefik may never read it.
    for sa in (f"{K.NS}/traefik", f"{K.INGRESS_NS}/traefik"):
        if K.NS in got.get(sa, set()) or "*" in got.get(sa, set()):
            F.add("Traefik's ServiceAccount can read portcullis-env (Secrets of the core namespace)")


def check_edge(docs):
    for d in docs:
        ns = d.get("metadata", {}).get("namespace")
        if d.get("kind") == "Secret" and ns == K.EDGE_NS:
            F.add(f"Secret {d['metadata']['name']} in {K.EDGE_NS} (Traefik reads every Secret there)")
        if d.get("kind") in ("IngressRoute", "Middleware", "IngressRouteTCP", "IngressRouteUDP", "TLSOption", "TLSStore",
                             "ServersTransport", "TraefikService", "MiddlewareTCP"):
            if ns != K.EDGE_NS:
                F.add(f"{d['kind']} {d['metadata']['name']} in {ns}: core Traefik objects live in {K.EDGE_NS} (Traefik's only watched namespace)")
            if (d["metadata"].get("labels") or {}).get("portcullis.io/owner") != "core":
                F.add(f"{d['kind']} {d['metadata']['name']}: no portcullis.io/owner=core (the Hub could change it)")
    # The apps' bounds (core-routes.json → params reservedHosts /
    # maxAppPriority), with their mutation tests.
    cr = json.loads((K.CHART / "core-routes.json").read_text())
    for p in core_route_problems(docs, cr):
        F.add(p)
    for what, mutate in MUTATIONS:
        if not core_route_problems(mutate(copy.deepcopy(docs)), cr):
            F.add(f"core_route_problems misses {what} (mutation test)")
    # Chart objects the admission policies judge (apps and edge namespaces)
    # carry portcullis.io/owner=core: the CLI's identity is what exempts
    # them, the label says whose they are.
    judged = {"NetworkPolicy", "Service", "Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Secret",
              "IngressRoute", "Middleware", "IngressRouteTCP", "IngressRouteUDP", "TLSOption", "TLSStore", "ServersTransport",
              "TraefikService", "MiddlewareTCP"}
    for d in docs:
        m = d.get("metadata", {})
        if m.get("namespace") in (K.APPS_NS, K.EDGE_NS) and d.get("kind") in judged \
                and (m.get("labels") or {}).get("portcullis.io/owner") != "core":
            F.add(f"{d['kind']} {m.get('namespace')}/{m['name']}: a chart object the policies judge without portcullis.io/owner=core")
    # The params' edgeCoreMiddlewares (no Hub route may name them) = the
    # chart's edge Middlewares + the CLI's hub-proxy-secret / hub-cli-proxy-secret.
    want = sorted(["hub-proxy-secret", "hub-cli-proxy-secret"] + [d["metadata"]["name"] for d in K.by_kind(docs, "Middleware")])
    params = yaml.safe_load((K.ROOT / "kube" / "admission" / "params.yaml").read_text())["data"]
    if sorted(params["edgeCoreMiddlewares"].split()) != want:
        F.add(f"kube/admission/params.yaml edgeCoreMiddlewares {params['edgeCoreMiddlewares']!r} != the core edge Middlewares {want}")
    tr = next(d for d in docs if d.get("kind") in ("Deployment", "DaemonSet") and d["metadata"]["name"] == "traefik")
    env = {e["name"]: e.get("value") for e in tr["spec"]["template"]["spec"]["containers"][0]["env"]}
    if env.get("TRAEFIK_PROVIDERS_KUBERNETESCRD_NAMESPACES") != K.EDGE_NS:
        F.add(f"traefik: kubernetesCRD namespaces {env.get('TRAEFIK_PROVIDERS_KUBERNETESCRD_NAMESPACES')!r} (want {K.EDGE_NS} only)")
    if env.get("TRAEFIK_PROVIDERS_KUBERNETESCRD_DISABLECLUSTERSCOPERESOURCES") != "true":
        F.add("traefik: kubernetesCRD disableClusterScopeResources must be true (its Role is namespaced: a Node list it can't make loads no route)")
    if env.get("TRAEFIK_PROVIDERS_KUBERNETESCRD_ALLOWEXTERNALNAMESERVICES") != "true":
        F.add("traefik: allowExternalNameServices must be true (the apps' backends are the Hub's pinned ExternalName Services in the edge namespace)")
    if env.get("TRAEFIK_PROVIDERS_KUBERNETESCRD_ALLOWCROSSNAMESPACE") != "false":
        F.add("traefik: allowCrossNamespace must be false (every route names edge-local or @file objects)")
    # Core's own objects are never ExternalName but these, each pinned (the
    # Hub's in the edge namespace are admitted by portcullis-edge-routes),
    # and the chart's only Service in the edge namespace is portcullis-node
    # (nodeadm's public paths, contract §20.2; owner=core, which the policy
    # refuses the Hub any change to).
    pinned = {(K.EDGE_NS, "portcullis-node"): "nodeadm.portcullis-nodeadm.svc.cluster.local",
              (K.NS, "keycloak-internal"): f"keycloak-internal.{K.INGRESS_NS}.svc.cluster.local",
              (K.NS, "traefik-metrics"): f"traefik-metrics.{K.INGRESS_NS}.svc.cluster.local"}
    for s in K.by_kind(docs, "Service"):
        key = (s["metadata"].get("namespace"), s["metadata"]["name"])
        if s["spec"].get("type") == "ExternalName" and pinned.get(key) != s["spec"].get("externalName"):
            F.add(f"service {s['metadata']['name']}: ExternalName {s['spec'].get('externalName')} (core's are only {pinned})")
        if key[0] == K.EDGE_NS and (key not in pinned or s["spec"].get("type") != "ExternalName"
                                   or (s["metadata"].get("labels") or {}).get("portcullis.io/owner") != "core"):
            F.add(f"service {s['metadata']['name']}: in {K.EDGE_NS} (only the Hub's ExternalName Services and core's pinned portcullis-node live there)")


if __name__ == "__main__":
    sys.exit(main())
