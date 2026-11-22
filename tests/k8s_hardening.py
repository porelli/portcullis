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
import os
import pathlib
import re
import subprocess
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
    # LLDAP's schema Job (plan Task 23) talks to Postgres only, by its own
    # policy (to-postgres): no compose network; its pod template is
    # immutable, so its name, not a config-hash, follows its inputs.
    if not any(k.startswith("portcullis.io/net-") for k in labels) and labels.get("portcullis.io/component") not in ("hub-oneshot", "lldap-schema"):
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
    if "portcullis.io/config-hash" not in ann and ns == K.NS and labels.get("portcullis.io/oneshot") != "true" and name != "lldap-schema":
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


DNS_RULES = [{"apiGroups": [""], "resources": ["services", "namespaces"], "verbs": ["list", "watch"]},
             {"apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["list", "watch"]}]

EDGE_DNS_TERMS = [
    {"matchExpressions": [{"key": "portcullis.io/site", "operator": "In", "values": ["main"]},
                          {"key": "portcullis.io/class", "operator": "In", "values": ["small"]}]},
    {"matchExpressions": [{"key": "portcullis.io/site", "operator": "Exists"},
                          {"key": "portcullis.io/site", "operator": "NotIn", "values": ["main"]}]},
]


def coredns_small_problems(docs):
    """kube/ha/coredns/small.yaml (plan Task 25 fix round 2, re-review M-c):
    our CoreDNS DaemonSet on the small nodes is restricted — non-root,
    RuntimeDefault, drop ALL plus NET_BIND_SERVICE alone (it binds :53),
    no escalation, read-only root,
    no host namespace / hostPath / privileged, only ConfigMap volumes —, on
    k3s's CoreDNS image by digest, on the small nodes at main and every node
    outside main only (Task 28: edge pods resolve on their own node), and
    the PDB minAvailable 1 over both CoreDNS sets."""
    out = []
    ds = [d for d in docs if d.get("kind") == "DaemonSet"]
    pdb = [d for d in docs if d.get("kind") == "PodDisruptionBudget"]
    if len(ds) != 1 or len(pdb) != 1 or sorted(d.get("kind") for d in docs) != ["ClusterRole", "ClusterRoleBinding", "DaemonSet", "PodDisruptionBudget", "ServiceAccount"]:
        return ["coredns small: exactly one DaemonSet, one PodDisruptionBudget and its ServiceAccount, ClusterRole and binding"]
    # Task 28 fix round 1 (review M6): its own ServiceAccount, reading only
    # what CoreDNS's kubernetes plugin watches (no pods, no endpoints).
    cr = next(d for d in docs if d["kind"] == "ClusterRole")
    crb = next(d for d in docs if d["kind"] == "ClusterRoleBinding")
    sa = next(d for d in docs if d["kind"] == "ServiceAccount")
    if cr["metadata"]["name"] != "portcullis-dns" or cr.get("rules") != DNS_RULES or sa["metadata"] != {"name": "portcullis-dns", "namespace": "kube-system", "labels": {"app.kubernetes.io/managed-by": "portcullis"}} \
            or crb["roleRef"] != {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "portcullis-dns"} \
            or crb["subjects"] != [{"kind": "ServiceAccount", "name": "portcullis-dns", "namespace": "kube-system"}]:
        return [f"coredns small: the ServiceAccount portcullis-dns bound to exactly {DNS_RULES}"]
    sp = ds[0]["spec"]["template"]["spec"]
    psc = sp.get("securityContext", {})
    if psc.get("runAsNonRoot") is not True or not psc.get("runAsUser") or (psc.get("seccompProfile") or {}).get("type") != "RuntimeDefault":
        out.append("coredns small: pod runAsNonRoot, a non-zero runAsUser and RuntimeDefault seccomp")
    if psc.get("sysctls"):
        out.append("coredns small: no sysctls")
    if any(sp.get(k) for k in ("hostNetwork", "hostPID", "hostIPC")) or sp.get("initContainers") or len(sp.get("containers", [])) != 1:
        out.append("coredns small: no host namespace, one container, no init container")
    if any(set(v) - {"name", "configMap"} for v in sp.get("volumes", [])):
        out.append("coredns small: ConfigMap volumes only")
    c = sp["containers"][0]
    sc = c.get("securityContext", {})
    caps = sc.get("capabilities", {})
    if sc.get("allowPrivilegeEscalation") is not False or sc.get("readOnlyRootFilesystem") is not True or sc.get("privileged") \
            or caps.get("drop") != ["ALL"] or caps.get("add") != ["NET_BIND_SERVICE"] or (sc.get("seccompProfile") or {}).get("type") != "RuntimeDefault":
        out.append("coredns small: container no escalation, read-only root, drop ALL plus NET_BIND_SERVICE alone, RuntimeDefault")
    # A container-level override wins over the pod's (re-review 2 N-c).
    if sc.get("runAsNonRoot", True) is not True or sc.get("runAsUser", 1) in (0, None) or sc.get("runAsGroup", 1) in (0, None):
        out.append("coredns small: no container-level root override (runAsNonRoot false, runAsUser / runAsGroup 0)")
    if any("hostPort" in pt or "hostIP" in pt for pt in c.get("ports", [])):
        out.append("coredns small: no hostPort")
    if not re.fullmatch(r"docker\.io/rancher/mirrored-coredns-coredns:[0-9.]+@sha256:[0-9a-f]{64}", c.get("image", "")):
        out.append(f"coredns small: image {c.get('image')} (k3s's CoreDNS, by digest)")
    # Task 28: the small nodes at main and every node at another site (an
    # edge pod resolves on its own node), nothing else: exactly these two
    # ORed terms, no other placement field.
    if sp.get("nodeSelector") != {"kubernetes.io/os": "linux"} or sp.get("affinity") != {"nodeAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": EDGE_DNS_TERMS}}} \
            or sp.get("nodeName") or sp.get("serviceAccountName") != "portcullis-dns":
        out.append("coredns small: the small nodes at main and every node outside main, the ServiceAccount portcullis-dns")
    if sp.get("tolerations") != [{"key": "portcullis.io/small", "operator": "Exists", "effect": "NoSchedule"}, {"key": "CriticalAddonsOnly", "operator": "Exists"}]:
        out.append("coredns small: tolerates the small taint and CriticalAddonsOnly only")
    if ds[0]["spec"]["template"]["metadata"]["labels"].get("k8s-app") != "kube-dns" or pdb[0]["spec"] != {"minAvailable": 1, "selector": {"matchLabels": {"k8s-app": "kube-dns"}}}:
        out.append("coredns small: labelled k8s-app=kube-dns; the PDB minAvailable 1 on k8s-app=kube-dns")
    return out


def check_coredns_small():
    docs = [d for d in yaml.safe_load_all((K.ROOT / "kube" / "ha" / "coredns" / "small.yaml").read_text()) if d]
    for p in coredns_small_problems(docs):
        F.add(p)
    ds = lambda d: next(x for x in d if x["kind"] == "DaemonSet")["spec"]["template"]["spec"]
    for mutate in (lambda d: ds(d)["containers"][0]["securityContext"]["capabilities"].__setitem__("add", ["NET_BIND_SERVICE", "NET_ADMIN"]),
                   lambda d: ds(d)["securityContext"].pop("runAsNonRoot"),
                   lambda d: ds(d).__setitem__("hostNetwork", True),
                   lambda d: ds(d)["containers"][0].__setitem__("image", "docker.io/rancher/mirrored-coredns-coredns:1.14.7"),
                   lambda d: ds(d)["volumes"].append({"name": "h", "hostPath": {"path": "/"}}),
                   lambda d: ds(d)["containers"][0]["securityContext"].__setitem__("runAsNonRoot", False),
                   lambda d: ds(d)["containers"][0]["securityContext"].__setitem__("runAsUser", 0),
                   lambda d: ds(d)["containers"][0]["ports"][0].__setitem__("hostPort", 53),
                   # Task 28: placement — every node, a third term, an extra toleration.
                   lambda d: ds(d).pop("affinity"),
                   lambda d: ds(d)["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"].append({"matchExpressions": [{"key": "kubernetes.io/os", "operator": "Exists"}]}),
                   lambda d: ds(d)["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]["nodeSelectorTerms"][1]["matchExpressions"].pop(1),
                   lambda d: ds(d)["tolerations"].append({"operator": "Exists"}),
                   # Review M6: k3s's broad ServiceAccount, or pods read again.
                   lambda d: ds(d).__setitem__("serviceAccountName", "coredns"),
                   lambda d: next(x for x in d if x["kind"] == "ClusterRole")["rules"][0]["resources"].append("pods")):
        bad = copy.deepcopy(docs)
        mutate(bad)
        if not coredns_small_problems(bad):
            F.add("coredns_small_problems misses a mutated DaemonSet (mutation test)")


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
            "forward-auth-ext": ("Deployment", g), "keycloak": ("StatefulSet", kc), "alertmanager": ("StatefulSet", 2),
            # LLDAP on Postgres (plan Task 23, Amendment 2: 2 replicas are safe).
            "lldap": ("Deployment", 2),
            # Plan Task 25: Vault's three raft voters; the session store's
            # master + replica and its three Sentinels.
            "vault": ("StatefulSet", 3), "sessions": ("StatefulSet", 2), "sessions-sentinel": ("StatefulSet", 3)}


# Plan Task 25: a quorum of three keeps two through a drain.
QUORUM_PDB = {"vault": 2, "sessions-sentinel": 2}
# Plan Task 25: the quorum pieces' third member may run on the small node.
SMALL_TOLERATION = {"key": "portcullis.io/small", "operator": "Exists", "effect": "NoSchedule"}
SMALL_TOLERATED = {"vault", "sessions-sentinel"}


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
        if replicated and (pdbs.get(name) is None or pdbs[name].get("minAvailable") != QUORUM_PDB.get(name, 1)):
            out.append(f"{name}: no PodDisruptionBudget minAvailable {QUORUM_PDB.get(name, 1)}")
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
        want_claims = ["data"] if name in ("group-gate", "mcp-gate", "alertmanager", "vault") else []
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
        heads = {"keycloak": "keycloak-pods", "alertmanager": "alertmanager-peers", "vault": "vault-internal",
                 "sessions": "sessions-pods", "sessions-sentinel": "sessions-sentinel"}
        if name in heads:
            svc = [s for s in K.by_kind(docs, "Service") if s["metadata"]["name"] == heads[name]]
            if sp.get("serviceName") != heads[name] or len(svc) != 1 or svc[0]["spec"].get("clusterIP") != "None":
                out.append(f"{name}: its pods' names need the headless Service {heads[name]}")
    for name, (wk, wn) in want.items():
        if wn > 1 and not any(d.get("kind") == wk and d["metadata"]["name"] == name for d in docs):
            out.append(f"{name}: no {wk}")
    return out


DO_NOT_SCHEDULE = {"group-gate", "mcp-gate", "alertmanager", "keycloak", "lldap", "vault", "sessions", "sessions-sentinel"}


def check_traefik_peer():
    """The Hub's HUB_TRAEFIK_PEER (its routed apps' NetworkPolicy peer, Hub
    Task 13) is exactly the admission params' traefik value the CLI writes
    (kube_traefik_peer), with and without HA: the policy compares the two."""
    for ha in (False, True):
        out = K.subprocess.run(["bash", "-c", f'source "{K.ROOT}/scripts/lib/common.sh" >/dev/null 2>&1; '
                                f'PORTCULLIS_NAMESPACE={K.NS} {"PORTCULLIS_HA=on " if ha else ""}kube_traefik_peer'],
                               check=True, capture_output=True, text=True).stdout.strip()
        docs = K.render({"ha": {"enabled": ha}})
        hub = next(sp for n, _, _, sp, _ in K.pod_specs(docs) if n == "hub")
        env = {e["name"]: e.get("value") for e in hub["containers"][0].get("env", [])}
        if not out or env.get("HUB_TRAEFIK_PEER") != out:
            F.add(f"{'ha: ' if ha else ''}the Hub's HUB_TRAEFIK_PEER {env.get('HUB_TRAEFIK_PEER')!r} != the params' traefik {out!r} (kube_traefik_peer)")


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
            want_t = HA_TOLERATIONS + ([SMALL_TOLERATION] if name in SMALL_TOLERATED else [])
            if spec.get("tolerations") != want_t:
                F.add(f"{label}: {name}: tolerations {spec.get('tolerations')} (want not-ready / unreachable at 30 s{', the small taint' if name in SMALL_TOLERATED else ''})")
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
        if spec.get("tolerations") and spec["tolerations"] != ([SMALL_TOLERATION] if name in SMALL_TOLERATED else []):
            F.add(f"{name}: tolerations without ha.enabled")
    pvcs = {c["metadata"]["name"]: c["spec"].get("storageClassName") for c in K.by_kind(plain, "PersistentVolumeClaim")}
    for n in ("hub-state", "hub-secrets", "hub-backups", "domains-data", "wg-data"):
        if pvcs.get(n) != "portcullis-core":
            F.add(f"{n} must be on portcullis-core without HA: {pvcs.get(n)}")
    # Vault is a StatefulSet of one voter in both modes (plan Task 25).
    if [d for d in plain if d.get("kind") in ("StatefulSet", "DaemonSet", "PodDisruptionBudget")
            and not (d["kind"] == "StatefulSet" and d["metadata"]["name"] == "vault" and d["spec"].get("replicas") == 1)]:
        F.add("StatefulSets / DaemonSets / PDBs without ha.enabled (Vault's one voter aside)")
    for s in K.by_kind(plain, "Service"):
        if s["metadata"]["name"] == "wg-people" and s["spec"].get("externalTrafficPolicy") != "Local":
            F.add("wg-people externalTrafficPolicy must stay Local without HA")
    # The pinning rule bites: a replicated pod on a node-local PVC.
    import copy as _c
    docs = K.render(base)
    bad = _c.deepcopy(docs)
    ff = next(d for d in bad if d.get("kind") == "Deployment" and d["metadata"]["name"] == "forward-auth")
    ff["spec"]["template"]["spec"].setdefault("volumes", []).append({"name": "x", "persistentVolumeClaim": {"claimName": "prometheus-data"}})
    if not any("pinned" in p for p in gate_shape_problems(bad, base)):
        F.add("gate_shape_problems misses a replicated pod on a node-local PVC (mutation test)")


REPLICATED_CLASS = "portcullis-core-replicated"


def replicated_mount_problems(docs):
    """Contract §20.11 (storage only at main): a pod mounting a volume of
    portcullis-core-replicated (a PVC of that class, or a StatefulSet claim
    of it) must be one of the pinned set (K.SITE_PINNED) and carry the site
    term: Longhorn's replicas live at main only, so a pod elsewhere would
    reach its volume across the mesh (or not at all)."""
    rep = {c["metadata"]["name"] for c in K.by_kind(docs, "PersistentVolumeClaim") if c["spec"].get("storageClassName") == REPLICATED_CLASS}
    out = []
    for d in docs:
        if d.get("kind") not in ("Deployment", "StatefulSet", "DaemonSet", "Pod"):
            continue
        name = d["metadata"]["name"]
        spec = pod_spec_of(d)
        uses = {(v.get("persistentVolumeClaim") or {}).get("claimName") for v in spec.get("volumes", [])} & rep
        uses |= {c["metadata"]["name"] for c in d.get("spec", {}).get("volumeClaimTemplates", []) or []
                 if c["spec"].get("storageClassName") == REPLICATED_CLASS}
        if uses and (name not in K.SITE_PINNED or not K.site_pinned(spec)):
            out.append(f"{name} mounts {sorted(uses)} ({REPLICATED_CLASS}) but isn't pinned to {K.PRIMARY_SITE}")
    return out


def check_sites_storage():
    """Task 20: "sites: no pod but the pinned set's may mount
    portcullis-core-replicated", on the HA renders (the one-shots too), with
    a mutation test (Grafana given hub-state-r; the Hub's pin dropped)."""
    base = yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-ha.yaml").read_text())
    sites = yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-ha-sites.yaml").read_text())
    for label, vals in (("ha", base), ("ha sites", dict(base, ha=dict(base["ha"], **sites["ha"])))):
        docs = K.render(vals)
        for os_ in ("dns-tool", "hub"):
            docs += K.render(dict(vals, oneshot=os_), "templates/oneshot.yaml")
        if not any(c["spec"].get("storageClassName") == REPLICATED_CLASS for c in K.by_kind(docs, "PersistentVolumeClaim")):
            F.add(f"{label}: no {REPLICATED_CLASS} PVC rendered (the check would pass vacuously)")
        for p in replicated_mount_problems(docs):
            F.add(f"sites: {label}: {p}")
    docs = K.render(base)
    bad = copy.deepcopy(docs)
    gf = next(d for d in bad if d.get("kind") == "Deployment" and d["metadata"]["name"] == "grafana")
    gf["spec"]["template"]["spec"].setdefault("volumes", []).append({"name": "x", "persistentVolumeClaim": {"claimName": "hub-state-r"}})
    hub = next(d for d in bad if d["metadata"]["name"] == "hub" and d.get("kind") == "Deployment")
    hub["spec"]["template"]["spec"].pop("affinity", None)
    got = replicated_mount_problems(bad)
    if not any(p.startswith("grafana ") for p in got) or not any(p.startswith("hub ") for p in got):
        F.add(f"replicated_mount_problems misses Grafana on hub-state-r or an unpinned Hub (mutation test): {got}")


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


CNPG_CHART_SHA256 = "9df3f074ecaa8af10277ad155899470618ea9a565d7c7c48187bdc7887655960"
CNPG_IMAGE = "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.2@sha256:f96f6be3d81ec93819b443c665c575c609342fca840df90d4d87dae314a5b913"


def check_cnpg():
    """Plan Task 23 (spec §7.4, ruling I5, security): the vendored operator
    chart is the pinned release asset (and ha.sh pins the same sha256 and
    image digest); its render runs the pinned image by digest, every pod
    portcullis-core and restricted, namespaced, the chart's RBAC off; ours
    (kube/ha/cnpg/rbac.yaml) is the chart's Role in cnpg-system verbatim
    and its cluster-wide rules with the webhook configurations narrowed by
    resourceNames to its own two (review I2: no Secret, pod, exec or other
    webhook right outside cnpg-system); its webhooks name its own Service.
    The Cluster (every render): portcullis-core, its image by digest, no
    superuser."""
    import hashlib
    tgz = K.ROOT / "kube" / "ha" / "cnpg" / "cloudnative-pg-0.29.2.tgz"
    if hashlib.sha256(tgz.read_bytes()).hexdigest() != CNPG_CHART_SHA256:
        F.add(f"{tgz.name}: not the pinned release asset ({CNPG_CHART_SHA256})")
    ha_sh = (K.ROOT / "scripts" / "lib" / "ha.sh").read_text()
    if f'KUBE_CNPG_CHART_SHA256="{CNPG_CHART_SHA256}"' not in ha_sh or f'KUBE_CNPG_IMAGE_DIGEST="{CNPG_IMAGE.split("@")[1]}"' not in ha_sh:
        F.add("scripts/lib/ha.sh: KUBE_CNPG_CHART_SHA256 / KUBE_CNPG_IMAGE_DIGEST differ from the pins")
    docs = K.render_cnpg()
    for d in docs:
        if d.get("kind") in POD_KINDS:
            sp = pod_spec_of(d)
            if sp.get("priorityClassName") != "portcullis-core":
                F.add(f"cnpg: {d['kind']} {d['metadata']['name']}: priorityClassName {sp.get('priorityClassName')} (ruling I5)")
            psc = sp.get("securityContext", {})
            for c in sp.get("containers", []) + sp.get("initContainers", []):
                sc = c.get("securityContext", {})
                if c["image"] != CNPG_IMAGE or sc.get("allowPrivilegeEscalation") is not False or sc.get("capabilities", {}).get("drop") != ["ALL"] \
                        or sc.get("readOnlyRootFilesystem") is not True or psc.get("runAsNonRoot") is not True \
                        or (sc.get("seccompProfile") or psc.get("seccompProfile") or {}).get("type") != "RuntimeDefault":
                    F.add(f"cnpg: {d['metadata']['name']}/{c['name']}: the pinned image, restricted (no escalation, drop ALL, read-only, non-root, RuntimeDefault)")
            if sp.get("hostNetwork") or any("hostPath" in v for v in sp.get("volumes", [])):
                F.add(f"cnpg: {d['metadata']['name']}: hostNetwork / hostPath")
            env = {e["name"]: e.get("value") for e in sp["containers"][0].get("env", [])}
            if env.get("WATCH_NAMESPACE") != K.CNPG_NS or env.get("OPERATOR_IMAGE_NAME") != CNPG_IMAGE:
                F.add(f"cnpg: the operator watches {env.get('WATCH_NAMESPACE')} (want {K.CNPG_NS} only) and copies {env.get('OPERATOR_IMAGE_NAME')}")
    # Review I2: the chart's RBAC is off; ours (kube/ha/cnpg/rbac.yaml) is the
    # chart's Role verbatim and its cluster-wide rules with the webhook
    # configurations narrowed by resourceNames to the operator's own two.
    if [d["kind"] for d in docs if d.get("kind") in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding")]:
        F.add("cnpg: the chart renders RBAC (rbac.create must be false: kube/ha/cnpg/rbac.yaml is the operator's)")
    mine = [d for d in yaml.safe_load_all((K.ROOT / "kube" / "ha" / "cnpg" / "rbac.yaml").read_text()) if d]
    chart = K.render_cnpg("--set", "rbac.create=true")
    sa = next(d for d in docs if d.get("kind") == "ServiceAccount")["metadata"]
    hooks = {d["kind"]: d["metadata"]["name"] for d in docs if d.get("kind") in ("MutatingWebhookConfiguration", "ValidatingWebhookConfiguration")}
    roles = [d for d in mine if d["kind"] == "Role"]
    chart_role = [d for d in chart if d.get("kind") == "Role"]
    if len(roles) != 1 or roles[0]["metadata"].get("namespace") != K.CNPG_NS or len(chart_role) != 1 or roles[0]["rules"] != chart_role[0]["rules"]:
        F.add("cnpg: rbac.yaml's one Role (in cnpg-system) must be the chart's namespaced rules verbatim")
    # Re-review M-a: derived from the chart's bound ClusterRole (a chart bump
    # that adds a rule must show here): each webhook-configuration resource
    # becomes its own rule naming the operator's configuration of that kind.
    hook_of = {"mutatingwebhookconfigurations": hooks.get("MutatingWebhookConfiguration"),
               "validatingwebhookconfigurations": hooks.get("ValidatingWebhookConfiguration")}
    chart_bound = {b["roleRef"]["name"] for b in chart if b.get("kind") == "ClusterRoleBinding"}
    want_cr = []
    for r in (r for cr in chart if cr.get("kind") == "ClusterRole" and cr["metadata"]["name"] in chart_bound for r in cr.get("rules", [])):
        hooked = [x for x in r.get("resources", []) if x in hook_of]
        rest = [x for x in r.get("resources", []) if x not in hook_of]
        if rest:
            want_cr.append(dict(r, resources=rest))
        for x in hooked:
            want_cr.append({"apiGroups": r["apiGroups"], "resources": [x], "resourceNames": [hook_of[x]], "verbs": r["verbs"]})
    if len(want_cr) != 4 or None in hook_of.values():
        F.add(f"cnpg: the chart's cluster-wide rules changed ({want_cr}): review rbac.yaml against them")
    crs = [d for d in mine if d["kind"] == "ClusterRole"]
    if len(crs) != 1 or crs[0]["rules"] != want_cr:
        F.add(f"cnpg: rbac.yaml's ClusterRole must be exactly {want_cr} (webhook configurations by resourceNames, review I2)")
    for r in (r for cr in crs for r in cr.get("rules", [])):
        if any(res.endswith("webhookconfigurations") for res in r.get("resources", [])) and not r.get("resourceNames"):
            F.add("cnpg: a webhook-configuration rule without resourceNames (every webhook in the cluster)")
    for b in (d for d in mine if d["kind"] in ("RoleBinding", "ClusterRoleBinding")):
        ref = {"RoleBinding": "Role", "ClusterRoleBinding": "ClusterRole"}[b["kind"]]
        if b["roleRef"]["kind"] != ref or b["roleRef"]["name"] not in {d["metadata"]["name"] for d in mine if d["kind"] == ref} \
                or b["subjects"] != [{"kind": "ServiceAccount", "name": sa["name"], "namespace": K.CNPG_NS}]:
            F.add(f"cnpg: {b['kind']} {b['metadata']['name']} binds {b['roleRef']} to {b['subjects']} (want its {ref} to the operator's ServiceAccount {sa['name']})")
    if sorted(d["kind"] for d in mine) != ["ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding"]:
        F.add(f"cnpg: rbac.yaml holds {sorted(d['kind'] for d in mine)} (one Role, ClusterRole and their bindings)")
    for w in (d for d in docs if d.get("kind") in ("MutatingWebhookConfiguration", "ValidatingWebhookConfiguration")):
        for h in w["webhooks"]:
            svc = h["clientConfig"].get("service") or {}
            if (svc.get("namespace"), svc.get("name")) != (K.CNPG_NS, "cnpg-webhook-service") or "url" in h["clientConfig"]:
                F.add(f"cnpg: webhook {h['name']} calls {h['clientConfig']}")
    for vals in ({}, yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-ha.yaml").read_text())):
        c = K.cnpg_cluster(K.render(vals))
        s = (c or {}).get("spec", {})
        if c is None or s.get("priorityClassName") != "portcullis-core" or not re.search(r"@sha256:[0-9a-f]{64}$", s.get("imageName", "")) \
                or s.get("enableSuperuserAccess") is not False:
            F.add("the CNPG Cluster: priorityClassName portcullis-core, imageName by digest, enableSuperuserAccess false")


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
    check_coredns_small()
    check_hub_core()
    check_nodeadm()
    check_log_ports()
    check_ha_shape()
    check_traefik_peer()
    check_sites_storage()
    check_psa()
    check_cnpg()
    check_ha_infra()
    check_backup_egress()
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
            "nodeadm": ["restricted"] * 3,
            # cnpg-system (plan Task 23, spec §7.4): restricted.
            "cnpg": ["restricted"] * 3,
            # HA, plan Task 24: Longhorn's and fencing's pods are privileged
            # (iSCSI, the watchdog; warn privileged: every apply would warn),
            # cert-manager restricted.
            "longhorn": ["privileged", "privileged", "baseline"], "fencing": ["privileged", "privileged", "baseline"],
            "certmanager": ["restricted"] * 3,
            # The CLI's host probes (fix round 1): hostPID + the host's /.
            "haprobe": ["privileged", "privileged", "baseline"]}


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
# Fix round 1 (Task 24): nodeadm creates / removes SNR's remediation requests.
NODEADM_FENCING_RULES = [{"apiGroups": ["self-node-remediation.medik8s.io"], "resources": ["selfnoderemediations"], "verbs": ["create", "delete"]}]
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
            want[("portcullis-fencing", "portcullis-nodeadm")] = NODEADM_FENCING_RULES
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
             "nodeadm": NODEADM_NS, "cnpg": "cnpg-system"}
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
        # kube/ha/*/upstream: vendored, as published (check_ha_infra judges
        # what ha_render makes of them).
        if "admission" in f.parts or f.name.endswith(".tmpl.yaml") or "upstream" in f.parts:
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



# ── HA infrastructure (plan Task 24): Longhorn, external-snapshotter,
# fencing, cert-manager as ha_render renders them (helm template + kubectl
# kustomize; HELM / KUBECTL point at the binaries). ──
HA_API_SOURCES = "10.1.0.4 10.42.0.0 10.42.0.1"
HA_INITIATORS = "10.215.0.1 10.42.0.0 10.42.0.1"
IMAGE_REF = re.compile(r"(?:^|[\s=\"'])((?:[a-z0-9.-]+\.[a-z]{2,}|localhost)(?::\d+)?/[a-z0-9._/-]+(?::[A-Za-z0-9._-]+)?(?:@sha256:[0-9a-f]{64})?)(?=$|[\s\"',])")


def ha_render(c):
    """ha.sh's ha_render <c> (the same code the CLI applies)."""
    env = dict(os.environ)
    tools = pathlib.Path(env.get("RUNNER_TEMP", "/tmp")) / "k8s-tools"
    env["PATH"] = os.pathsep.join(p for p in (str(pathlib.Path(env["HELM"]).parent) if env.get("HELM") else "",
                                              str(pathlib.Path(env["KUBECTL"]).parent) if env.get("KUBECTL") else "", str(tools), env["PATH"]) if p)
    out = subprocess.run(["bash", "-c", 'source "$1/scripts/lib/common.sh"; ha_render "$2" "$3" "$4"', "_", str(K.ROOT), c, HA_API_SOURCES, HA_INITIATORS],
                         check=True, capture_output=True, text=True, env=env).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def strings_of(o):
    if isinstance(o, str):
        yield o
    elif isinstance(o, dict):
        for v in o.values():
            yield from strings_of(v)
    elif isinstance(o, list):
        for v in o:
            yield from strings_of(v)


def ha_image_problems(name, docs):
    """Every container image, and every image-shaped value in a pod's args
    and env (Longhorn hands its engine / CSI images on that way), is a
    qualified name:tag@sha256 ref."""
    out = []
    for d in docs:
        if d.get("kind") not in POD_KINDS:
            continue
        sp = pod_spec_of(d)
        for c in sp.get("containers", []) + sp.get("initContainers", []):
            refs = [c["image"]] + [m.group(1) for v in strings_of({"a": c.get("args", []), "c": c.get("command", []), "e": c.get("env", [])})
                                   for m in IMAGE_REF.finditer(v) if "/" in m.group(1) and ":" in m.group(1).split("/", 1)[1]]
            for r in refs:
                if not re.search(r"@sha256:[0-9a-f]{64}$", r) or not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}/", r):
                    out.append(f"{name}: {d['metadata']['name']}/{c['name']}: {r} (not a qualified name:tag@sha256)")
    return out


def rules_of(docs, kind, names=None):
    return [(d["metadata"]["name"], r) for d in docs if d.get("kind") == kind and (names is None or d["metadata"]["name"] in names) for r in d.get("rules", [])]


def bound_cluster_roles(docs, sa_ns):
    """The ClusterRoles a render binds cluster-wide to a ServiceAccount of sa_ns."""
    return {b["roleRef"]["name"] for b in docs if b.get("kind") == "ClusterRoleBinding"
            and any(x.get("kind") == "ServiceAccount" and x.get("namespace") == sa_ns for x in b.get("subjects", []))}


def wide_rule_problems(name, docs, sa_ns, allow_secret_read=False):
    """The hardening floor of a vendored operator's cluster-wide rights: no
    cluster-admin, no ClusterRole / ClusterRoleBinding / CRD write, no
    Node create / delete, Secrets at most read (and only where allowed), a
    webhook-configuration or Lease write only by resourceNames (create
    aside: RBAC can't name one)."""
    out = []
    bound = bound_cluster_roles(docs, sa_ns)
    if "cluster-admin" in bound:
        out.append(f"{name}: a ServiceAccount of {sa_ns} is bound to cluster-admin")
    for role, r in rules_of(docs, "ClusterRole", bound):
        res, verbs, named = set(r.get("resources", [])), set(r.get("verbs", [])), bool(r.get("resourceNames"))
        core = "" in r.get("apiGroups", [])
        write = verbs & {"*", "create", "update", "patch", "delete", "deletecollection", "escalate", "bind"}
        if "*" in res and r.get("apiGroups") != ["longhorn.io"]:
            out.append(f"{name}: {role}: every resource of {r.get('apiGroups')}")
        if res & {"clusterroles", "clusterrolebindings", "roles", "rolebindings"} and (write - ({"update"} if named else set())):
            out.append(f"{name}: {role}: RBAC write {sorted(write)} on {sorted(res)}")
        if "customresourcedefinitions" in res and write and (not named or write - {"update", "patch"}):
            out.append(f"{name}: {role}: CRDs {sorted(verbs)} (read, and update its own by name)")
        if core and "nodes" in res and verbs & {"*", "create", "delete", "deletecollection"}:
            out.append(f"{name}: {role}: Nodes {sorted(verbs)} (no create / delete)")
        if core and "secrets" in res and (write or not allow_secret_read):
            out.append(f"{name}: {role}: Secrets {sorted(verbs)} cluster-wide")
        if core and res & {"configmaps", "serviceaccounts", "pods/exec", "pods/log"}:
            out.append(f"{name}: {role}: {sorted(res & {'configmaps', 'serviceaccounts', 'pods/exec', 'pods/log'})} cluster-wide")
        if any(x.endswith("webhookconfigurations") for x in res) and (write - {"create"}) and not named:
            out.append(f"{name}: {role}: webhook configurations {sorted(write)} without resourceNames")
    return out


def snr_agent_problems(fe):
    """Security ruling (plan Task 24): SNR's agent ClusterRole has no
    Secret rule at all; its one Secret is the Role's get by name."""
    out = []
    for _, r in rules_of(fe, "ClusterRole", {"portcullis-snr-agent"}):
        res, verbs = set(r["resources"]), set(r["verbs"])
        if "secrets" in res or "*" in res or res & {"pods", "namespaces"} or ("nodes" in res and verbs - {"get", "list", "watch", "update"}) \
                or res & {"daemonsets", "volumeattachments", "pods/exec"} or "*" in verbs:
            out.append(f"fencing: the agent's ClusterRole rule {r} (no Secret at all, its Node's annotations, nothing else written)")
    # Review round 4 I1: SNR's resources read only — no status subresource,
    # no write verb (a node could forge another remediation's phase).
    for kind in ("ClusterRole", "Role"):
        for _, r in rules_of(fe, kind, {"portcullis-snr-agent"}):
            groups, res, verbs = set(r.get("apiGroups", [])), set(r["resources"]), set(r["verbs"])
            if (groups & {"self-node-remediation.medik8s.io", "*"}) and (verbs - {"get", "list", "watch"} or any(x.endswith("/status") or x == "*" for x in res)):
                out.append(f"fencing: the agent's {kind} writes SNR resources or their status: {r} (read only)")
    agent_role = [r for _, r in rules_of(fe, "Role", {"portcullis-snr-agent"})]
    # get / list / watch by name: the patched cache lists with the
    # metadata.name field selector (RBAC checks resourceNames then).
    if agent_role != [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["self-node-remediation-certificates"], "verbs": ["get", "list", "watch"]},
                      {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}]:
        out.append(f"fencing: the agent's Role {agent_role} (only its peers' certificate Secret by name, and its peers' pods)")
    return out


def check_ha_infra():
    """Plan Task 24: the pins, the images by digest, every pod portcullis-core
    (ruling I5), the narrowed RBAC (Task 23's I2 lesson: resourceNames where
    possible; the hardening floor in wide_rule_problems, each narrowed role
    a subset of upstream's), Longhorn's settings, the fencing conversion
    reproducible, the StorageClass."""
    import hashlib
    ha_sh = (K.ROOT / "scripts" / "lib" / "ha.sh").read_text()
    pins = re.findall(r"([a-z-]+/upstream/[A-Za-z0-9._-]+) ([0-9a-f]{64})", ha_sh)
    if len(pins) != 9:
        F.add(f"ha.sh _ha_pins / _ha_barman_pins: {len(pins)} pins (want the 9 upstream files)")
    for f, want in pins:
        got = hashlib.sha256((K.ROOT / "kube" / "ha" / f).read_bytes()).hexdigest()
        if got != want:
            F.add(f"kube/ha/{f}: sha256 {got} != the pin {want}")
    renders = {c: ha_render(c) for c in ("longhorn", "snapshotter", "fencing", "certmanager")}
    renders["snapshotter-crds"] = [d for d in yaml.safe_load_all((K.ROOT / "kube/ha/snapshotter/upstream/crds.yaml").read_text()) if d]
    renders["barman"] = barman_render()
    for c, docs in renders.items():
        for p in ha_image_problems(c, docs):
            F.add(p)
        for d in docs:
            if d.get("kind") in POD_KINDS and pod_spec_of(d).get("priorityClassName") != "portcullis-core":
                F.add(f"{c}: {d['kind']} {d['metadata']['name']}: priorityClassName {pod_spec_of(d).get('priorityClassName')} (ruling I5)")
            if d.get("kind") in ("Namespace", "PriorityClass"):
                F.add(f"{c}: renders {d['kind']} {d['metadata']['name']} (the CLI makes the namespace; one set of classes)")
    # Mutation: the image check bites on a tag-only arg.
    bad = [{"kind": "Deployment", "metadata": {"name": "x"}, "spec": {"template": {"spec": {"containers": [
        {"name": "x", "image": "docker.io/a/b:1@sha256:" + "0" * 64, "args": ["--engine-image=docker.io/longhornio/longhorn-engine:v1.13.0"]}]}}}}]
    if not ha_image_problems("mut", bad):
        F.add("ha_image_problems misses a tag-only image in args (mutation test)")
    lh = renders["longhorn"]
    # Longhorn: the chart's own bound ClusterRole is gone, ours a subset of it.
    if {d["metadata"]["name"] for d in lh if d.get("kind") in ("ClusterRole", "ClusterRoleBinding", "PriorityClass")} \
            - {"portcullis-longhorn", "longhorn-csi-role", "longhorn-csi-bind"}:
        F.add(f"longhorn: cluster objects {sorted(d['metadata']['name'] for d in lh if d.get('kind') in ('ClusterRole', 'ClusterRoleBinding', 'PriorityClass'))} (the chart's longhorn-role / -bind / -support-bundle / -critical must be gone)")
    for p in wide_rule_problems("longhorn", lh, K_LONGHORN_NS):
        F.add(p)
    chart = [d for d in yaml.safe_load_all(subprocess.run([os.environ.get("HELM", "helm"), "template", "longhorn", str(K.ROOT / "kube/ha/longhorn/upstream/longhorn-1.13.0.tgz"),
             "-n", K_LONGHORN_NS, "--no-hooks", "-f", str(K.ROOT / "kube/ha/longhorn/values.yaml")], check=True, capture_output=True, text=True).stdout) if d]
    up = [r for _, r in rules_of(chart, "ClusterRole", {"longhorn-role"})]
    for _, r in rules_of(lh, "ClusterRole", {"portcullis-longhorn"}):
        if not any(set(r["apiGroups"]) <= set(u["apiGroups"]) and set(r["resources"]) <= set(u["resources"])
                   and (set(r["verbs"]) <= set(u["verbs"]) or "*" in u["verbs"]) for u in up):
            F.add(f"longhorn: portcullis-longhorn's rule {r} isn't within the chart's longhorn-role")
    for _, r in rules_of(lh, "ClusterRole", {"portcullis-longhorn"}):
        if "" in r["apiGroups"] and "pods" in r["resources"] and set(r["verbs"]) - {"get", "list", "watch"}:
            F.add(f"longhorn: {r} (pods deleted only in longhorn-system, review M9)")
        if any(x.endswith("webhookconfigurations") for x in r["resources"]) and set(r["verbs"]) & {"create", "*", "update"}:
            F.add(f"longhorn: {r} (no webhook-configuration create: the CLI makes Longhorn's two, fix round 1)")
    crd_names = sorted(d["metadata"]["name"] for d in lh if d.get("kind") == "CustomResourceDefinition")
    crd_w = [r for _, r in rules_of(lh, "ClusterRole", {"portcullis-longhorn"}) if "customresourcedefinitions" in r["resources"] and set(r["verbs"]) - {"get", "list", "watch"}]
    if len(crd_w) != 1 or sorted(crd_w[0].get("resourceNames", [])) != crd_names or crd_w[0]["verbs"] != ["update"]:
        F.add(f"longhorn: CRD writes must be update on its own {len(crd_names)} by name only")
    settings = yaml.safe_load(next(d for d in lh if d.get("kind") == "ConfigMap" and d["metadata"]["name"] == "longhorn-default-setting")["data"]["default-setting.yaml"])
    want = {"create-default-disk-labeled-nodes": True, "node-down-pod-deletion-policy": "do-nothing", "replica-soft-anti-affinity": False,
            "auto-delete-pod-when-volume-detached-unexpectedly": False,
            "system-managed-components-node-selector": "portcullis.io/site:main", "priority-class": "portcullis-core", "upgrade-checker": False,
            "allow-collecting-longhorn-usage-metrics": False, "default-data-locality": "best-effort"}
    for k, v in want.items():
        if settings.get(k) != v:
            F.add(f"longhorn setting {k}: {settings.get(k)!r} (want {v!r})")
    for d in lh:
        if d.get("kind") in ("DaemonSet", "Deployment") and pod_spec_of(d).get("nodeSelector") != {"portcullis.io/site": K.PRIMARY_SITE}:
            F.add(f"longhorn: {d['metadata']['name']} runs off the primary site ({pod_spec_of(d).get('nodeSelector')}; T24/H6)")
    pols = {d["metadata"]["name"]: d for d in lh if d.get("kind") == "NetworkPolicy"}
    im = pols.get("instance-manager", {}).get("spec", {}).get("ingress", [])
    if not im or any(not r.get("from") for r in im):
        F.add("longhorn: instance-manager's ingress (iSCSI 3260) open to every source: the initiators' sources are missing")
    if any(not r.get("from") for r in pols.get("longhorn-webhook", {}).get("spec", {}).get("ingress", [{}])):
        F.add("longhorn: the webhook's ingress open to every source")
    # Snapshotter: its Lease only by name; the Deployment portcullis-core.
    sn = renders["snapshotter"]
    for role, r in rules_of(sn, "Role"):
        if "leases" in r["resources"] and set(r["verbs"]) - {"create"} and not r.get("resourceNames"):
            F.add(f"snapshotter: {role}: every Lease in kube-system ({r['verbs']})")
    for p in wide_rule_problems("snapshotter", sn, "kube-system"):
        F.add(p)
    # Fencing: the conversion reproduces, the CSVs' wide roles replaced by
    # narrower ones (subsets), Secrets read only (SNR's cluster-wide cache).
    fdir = K.ROOT / "kube/ha/fencing"
    for b, out in (("snr-v0.13.0-bundle.tar.gz", "snr-v0.13.0.yaml"),):
        got = subprocess.run([sys.executable, str(fdir / "from-bundle.py"), str(fdir / "upstream" / b), K_FENCING_NS], check=True, capture_output=True, text=True).stdout
        if got != (fdir / "upstream" / out).read_text():
            F.add(f"kube/ha/fencing/upstream/{out} isn't from-bundle.py's conversion of {b}")
    fe = renders["fencing"]
    for p in wide_rule_problems("fencing", fe, K_FENCING_NS, allow_secret_read=True):
        F.add(p)
    csv = [d for d in yaml.safe_load_all((fdir / "upstream" / "snr-v0.13.0.yaml").read_text()) if d]
    for mine, theirs in (("portcullis-snr", "self-node-remediation-controller-manager"),):
        up = [r for _, r in rules_of(csv, "ClusterRole", {theirs})]
        for _, r in rules_of(fe, "ClusterRole", {mine}):
            if not any(set(r["apiGroups"]) <= set(u["apiGroups"]) and set(r["resources"]) <= set(u["resources"])
                       and (set(r["verbs"]) <= set(u["verbs"]) or "*" in u["verbs"]) for u in up):
                F.add(f"fencing: {mine}'s rule {r} isn't within the CSV's {theirs}")
    # Review round 5 M1: only nodeadm creates or deletes SelfNodeRemediations
    # (its Role in the chart, not in this render). Task 24 re-review 4 nit 2:
    # every rendered fencing ClusterRole / Role is judged, not only the
    # manager's.
    def snr_cr_writes(docs):
        return [(kind, name, r) for kind in ("ClusterRole", "Role") for name, r in rules_of(docs, kind)
                if set(r.get("apiGroups", [])) & {"self-node-remediation.medik8s.io", "*"}
                and set(r["resources"]) & {"selfnoderemediations", "*"} and set(r["verbs"]) & {"create", "delete", "deletecollection", "*"}]
    for kind, name, r in snr_cr_writes(fe):
        F.add(f"fencing: {kind} {name} may create / delete SelfNodeRemediations: {r} (nodeadm alone does)")
    for kind, name, extra in (("ClusterRole", "portcullis-snr", {"apiGroups": ["self-node-remediation.medik8s.io"], "resources": ["selfnoderemediations"], "verbs": ["create"]}),
                              ("ClusterRole", "portcullis-snr-agent", {"apiGroups": ["*"], "resources": ["selfnoderemediations"], "verbs": ["delete"]}),
                              ("Role", "portcullis-snr-agent", {"apiGroups": ["self-node-remediation.medik8s.io"], "resources": ["*"], "verbs": ["deletecollection"]})):
        mut_fe = copy.deepcopy(fe)
        next(d for d in mut_fe if d.get("kind") == kind and d["metadata"]["name"] == name)["rules"].append(extra)
        if not snr_cr_writes(mut_fe):
            F.add(f"snr_cr_writes misses {extra} on {kind} {name} (mutation test)")
    # Nit 1: the manager's verbs on the object are v0.13.0's exactly
    # (Update for its finalizer; status through the subresource).
    mgr_snr = [set(r["verbs"]) for _, r in rules_of(fe, "ClusterRole", {"portcullis-snr"}) if r["resources"] == ["selfnoderemediations"]]
    if mgr_snr != [{"get", "list", "update", "watch"}]:
        F.add(f"fencing: portcullis-snr's SelfNodeRemediation verbs {mgr_snr} (want get, list, update, watch: v0.13.0 only Updates its finalizer)")
    # The CSV's wide role and its aggregated ext-remediation role (create /
    # delete on SNR CRs, aggregated to NHC) stay deleted (kustomization.yaml).
    # (The CSV's namespaced Role of the manager stays: its leader Lease etc.)
    gone = {"ClusterRole": {"self-node-remediation-controller-manager", "self-node-remediation-ext-remediation"},
            "Role": {"self-node-remediation-ext-remediation"}}
    for kind in ("ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding"):
        for d in fe:
            names = gone["Role" if kind in ("Role", "RoleBinding") else "ClusterRole"]
            if d.get("kind") == kind and (d["metadata"]["name"] in names
                                          or (kind.endswith("Binding") and d["roleRef"]["name"] in gone[d["roleRef"]["kind"]])):
                F.add(f"fencing: the CSV's {kind} {d['metadata']['name']} is still rendered")
    # Fix round 1: no Node Healthcheck at all; no Secret in any fencing
    # ClusterRole (our SNR caches one Secret by name in its namespace); the
    # manager's DaemonSet writes by name; our image, the same ref in the
    # Deployment, its agents' env and the pod policy, = ha.sh HA_SNR_IMAGE.
    if any("node-healthcheck" in d["metadata"].get("name", "") or d.get("kind") == "NodeHealthCheck"
           or "remediation.medik8s.io" == d.get("spec", {}).get("group") for d in fe):
        F.add("fencing: a Node Healthcheck object is still rendered (nodeadm replaces it)")
    for role, r in rules_of(fe, "ClusterRole"):
        if "secrets" in r.get("resources", []) or "*" in r.get("resources", []):
            F.add(f"fencing: ClusterRole {role} has a Secret rule {r} (none cluster-wide, fix round 1)")
    for role, r in rules_of(fe, "Role"):
        if r.get("resources") == ["secrets"] and set(r["verbs"]) - {"create"} and r.get("resourceNames") != ["self-node-remediation-certificates"]:
            F.add(f"fencing: Role {role}'s Secret rule {r} (only the peers' certificate by name; create can't be named)")
        if "daemonsets" in r.get("resources", []) and set(r["verbs"]) - {"create"} and r.get("resourceNames") != ["self-node-remediation-ds"]:
            F.add(f"fencing: Role {role}'s DaemonSet rule {r} (writes by name)")
    snr_img = re.search(r'^HA_SNR_IMAGE="([^"]+)"$', ha_sh, re.M)
    snr_img = snr_img.group(1) if snr_img else None
    for d in fe:
        if d.get("kind") == "Deployment":
            c = pod_spec_of(d)["containers"][0]
            env = {e["name"]: e.get("value") for e in c.get("env", [])}
            if c["image"] != snr_img or env.get("SELF_NODE_REMEDIATION_IMAGE") != snr_img:
                F.add(f"fencing: SNR's manager runs {c['image']} / its agents {env.get('SELF_NODE_REMEDIATION_IMAGE')} (want {snr_img}, ha.sh HA_SNR_IMAGE)")
    pols = [d for d in fe if d.get("kind") == "ValidatingAdmissionPolicy"]
    binds = [d for d in fe if d.get("kind") == "ValidatingAdmissionPolicyBinding"]
    if len(pols) != 1 or pols[0]["metadata"]["name"] != "portcullis-fencing-pods" or f"'{snr_img}'" not in json.dumps(pols[0]) \
            or len(binds) != 1 or binds[0]["spec"]["policyName"] != "portcullis-fencing-pods" or binds[0]["spec"]["validationActions"] != ["Deny"] \
            or binds[0]["spec"]["matchResources"]["namespaceSelector"]["matchLabels"] != {"kubernetes.io/metadata.name": K_FENCING_NS}:
        F.add("fencing: the pod policy portcullis-fencing-pods (our SNR image, Deny, bound to portcullis-fencing) is missing or off")
    snr_src = (fdir / "snr-patch" / "Dockerfile").read_text()
    psha = hashlib.sha256((fdir / "snr-patch" / "0001-secret-cache-own-namespace.patch").read_bytes()).hexdigest()
    if snr_src.count(f"ARG PATCH_SHA256={psha}") != 2 or "ARG SNR_COMMIT=79fb792830c6db78b0dab45c45f5b79591118c76" not in snr_src:
        F.add("snr-patch/Dockerfile: the patch's sha256 / the upstream commit aren't the pinned ones")
    if any(d.get("kind") in ("ValidatingWebhookConfiguration", "MutatingWebhookConfiguration") for d in fe):
        F.add("fencing: a webhook configuration (none is registered)")
    # Security ruling: SNR's agents (every node) have their own
    # ServiceAccount: the template differs from upstream's in exactly the
    # ServiceAccount, the class and the pull policy; the agent's identity
    # never writes a Secret, never creates or deletes a Node; the managers
    # run only on the primary site's non-small nodes.
    up_t = (fdir / "upstream/self-node-remediation-deamonset.yaml.tmpl").read_text().splitlines()
    my_t = [re.sub(r"  # reviewed exception: .*$", "", l) for l in (fdir / "agent-daemonset.yaml.tmpl").read_text().splitlines() if not l.startswith("#")]
    diff = [(a, b) for a, b in zip(up_t, my_t) if a != b]
    if len(up_t) != len(my_t) or diff != [("      serviceAccountName: self-node-remediation-controller-manager", "      serviceAccountName: self-node-remediation-agent"),
                                          ("      priorityClassName: system-node-critical", "      priorityClassName: portcullis-core"),
                                          ("        imagePullPolicy: Always", "        imagePullPolicy: IfNotPresent")]:
        F.add(f"fencing: agent-daemonset.yaml.tmpl differs from SNR's template beyond the ServiceAccount / class / pull policy: {diff}")
    agent_roles = {b["roleRef"]["name"] for b in fe if b.get("kind") in ("ClusterRoleBinding", "RoleBinding")
                   and any(x.get("name") == "self-node-remediation-agent" for x in b.get("subjects", []))}
    if agent_roles != {"portcullis-snr-agent"}:
        F.add(f"fencing: the agent's ServiceAccount is bound to {sorted(agent_roles)} (only portcullis-snr-agent)")
    for p in snr_agent_problems(fe):
        F.add(p)
    mut_fe = copy.deepcopy(fe)
    next(d for d in mut_fe if d.get("kind") == "ClusterRole" and d["metadata"]["name"] == "portcullis-snr-agent")["rules"].append(
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["list", "watch"]})
    if not snr_agent_problems(mut_fe):
        F.add("snr_agent_problems misses a cluster-wide Secret rule on portcullis-snr-agent (mutation test)")
    for extra in ({"apiGroups": ["self-node-remediation.medik8s.io"], "resources": ["selfnoderemediations/status"], "verbs": ["get", "patch", "update"]},
                  {"apiGroups": ["self-node-remediation.medik8s.io"], "resources": ["selfnoderemediations"], "verbs": ["patch"]}):
        mut_fe = copy.deepcopy(fe)
        next(d for d in mut_fe if d.get("kind") == "ClusterRole" and d["metadata"]["name"] == "portcullis-snr-agent")["rules"].append(extra)
        if not any("writes SNR resources" in p for p in snr_agent_problems(mut_fe)):
            F.add(f"snr_agent_problems misses {extra} on portcullis-snr-agent (mutation test)")
    mgr_sa = {b["roleRef"]["name"] for b in fe if b.get("kind") == "ClusterRoleBinding"
              and any(x.get("name") == "self-node-remediation-controller-manager" for x in b.get("subjects", []))}
    if "portcullis-snr-agent" in mgr_sa or any(d.get("kind") == "DaemonSet" for d in fe):
        F.add("fencing: the manager holds the agent's role, or a DaemonSet is rendered (the manager makes it from the template)")
    for d in fe:
        if d.get("kind") == "Deployment":
            terms = (((pod_spec_of(d).get("affinity") or {}).get("nodeAffinity") or {}).get("requiredDuringSchedulingIgnoredDuringExecution") or {}).get("nodeSelectorTerms", [])
            exprs = [e for t in terms for e in t.get("matchExpressions", [])]
            if len(terms) != 1 or {"key": "portcullis.io/site", "operator": "In", "values": [K.PRIMARY_SITE]} not in exprs \
                    or {"key": "portcullis.io/class", "operator": "NotIn", "values": ["small"]} not in exprs:
                F.add(f"fencing: {d['metadata']['name']} isn't pinned to {K.PRIMARY_SITE}'s non-small nodes")
            mounts = {m["mountPath"]: m for c in pod_spec_of(d)["containers"] for m in c.get("volumeMounts", [])}
            if d["metadata"]["name"].startswith("self-node-remediation") and mounts.get("/install/self-node-remediation-deamonset.yaml", {}).get("subPath") != "self-node-remediation-deamonset.yaml":
                F.add("fencing: SNR's manager doesn't render our agent template (/install from the ConfigMap snr-install)")
    pol = (K.ROOT / "kube/admission/policies.yaml").read_text()
    if "system:serviceaccount:portcullis-fencing:self-node-remediation-agent" not in pol or "authentication.kubernetes.io/node-name" not in pol:
        F.add("admission: portcullis-node-labels doesn't hold SNR's agent to its own Node")
    cfg = [d for d in yaml.safe_load_all((fdir / "config.yaml").read_text()) if d]
    snrc = next(d for d in cfg if d["kind"] == "SelfNodeRemediationConfig")["spec"]
    if (snrc.get("watchdogFilePath"), snrc.get("safeTimeToAssumeNodeRebootedSeconds")) != ("/dev/watchdog", 150) \
            or not any(t.get("key") == "portcullis.io/small" for t in snrc.get("customDsTolerations", [])):
        F.add(f"fencing config: {snrc} (watchdog /dev/watchdog, safe time 150, small tolerated: S3)")
    if [d["kind"] for d in cfg] != ["SelfNodeRemediationConfig"]:
        F.add(f"fencing config.yaml: {[d['kind'] for d in cfg]} (only the SelfNodeRemediationConfig: nodeadm creates the remediations)")
    # The pod policies' admission vectors (fix round 1, security review):
    # current with the real shapes (e2e-ha-admission.sh runs them live).
    r = subprocess.run([sys.executable, str(K.ROOT / "tests" / "ha_admission_vectors.py"), "--check"], capture_output=True, text=True)
    if r.returncode != 0:
        F.add(f"tests/ha_admission_vectors.json: {(r.stderr or r.stdout).strip()}")
    else:
        vecs = json.loads((K.ROOT / "tests" / "ha_admission_vectors.json").read_text())
        for pol in ("portcullis-fencing-pods", "portcullis-ha-probe-pods"):
            vs = [v for v in vecs if v["policy"] == pol]
            if sum(v["allowed"] for v in vs) < 1 or sum(not v["allowed"] for v in vs) < 20 or not any(v.get("ephemeral") for v in vs):
                F.add(f"ha_admission_vectors: {pol} needs its admitted base(s) and the refused variants")
        # Round 3 I1: the storm guard's admission vectors (node identities, SNR's manager).
        nl = [v for v in vecs if v["policy"] == "portcullis-node-labels"]
        if not any(v["allowed"] and v["as"]["user"].startswith("system:node:") for v in nl) \
                or sum(not v["allowed"] for v in nl) < 10 or not any(v["allowed"] and v.get("taints_add") for v in nl):
            F.add("ha_admission_vectors: portcullis-node-labels needs a node's and the manager's refused / admitted vectors")
        # Task 28 fix round 1 (review M2): who may write frontdoor-status.
        fs = [v for v in vecs if v["policy"] == "portcullis-frontdoor-status"]
        if sum(v["allowed"] for v in fs) != 1 or sum(not v["allowed"] for v in fs) < 5:
            F.add("ha_admission_vectors: portcullis-frontdoor-status needs the front door's own write admitted and the forged ones refused")
    fsp = next((d for d in yaml.safe_load_all((K.ROOT / "kube/admission/policies.yaml").read_text())
                if d and d.get("kind") == "ValidatingAdmissionPolicy" and d["metadata"]["name"] == "portcullis-frontdoor-status"), None)
    fsb = next((d for d in yaml.safe_load_all((K.ROOT / "kube/admission/bindings.yaml").read_text())
                if d and d["metadata"]["name"] == "portcullis-core-guard-frontdoor-status"), None)
    if not fsp or not fsb or fsp["spec"].get("failurePolicy") != "Fail" or fsp["spec"]["matchConditions"] != [{"name": "frontdoor-status", "expression": "request.name == 'frontdoor-status'"}] \
            or fsb["spec"]["policyName"] != "portcullis-frontdoor-status" or fsb["spec"]["validationActions"] != ["Deny"]:
        F.add("admission: portcullis-frontdoor-status (Fail, frontdoor-status only) and its Deny binding on the core namespace")
    # Round 3 I1: portcullis-node-labels guards the storm guard's inputs.
    nlp = next((d for d in yaml.safe_load_all((K.ROOT / "kube/admission/policies.yaml").read_text())
                if d and d.get("kind") == "ValidatingAdmissionPolicy" and d["metadata"]["name"] == "portcullis-node-labels"), None)
    if not nlp:
        F.add("policies.yaml: portcullis-node-labels missing")
    else:
        nv = {v["name"]: v["expression"] for v in nlp["spec"]["variables"]}
        nexpr = "\n".join(v["expression"] for v in nlp["spec"]["validations"])
        if "'remediation.medik8s.io/'" not in nv.get("placed", "") or "'nodeadm.portcullis/'" not in nv.get("annPrefixes", "") \
                or "variables.newUnsched == variables.oldUnsched" not in nexpr \
                or "self-node-remediation-controller-manager'" not in nexpr \
                or "variables.newLabels == variables.oldLabels && variables.newAnn == variables.oldAnn" not in nexpr \
                or "system:serviceaccount:portcullis-fencing:" not in nlp["spec"]["matchConditions"][0]["expression"] \
                or "object.metadata.ownerReferences" not in nv.get("newOwners", "") or "object.metadata.finalizers" not in nv.get("newFinalizers", "") \
                or "variables.newOwners.all(o, o in variables.oldOwners) && variables.oldOwners.all(o, o in variables.newOwners)" not in nexpr \
                or "variables.newFinalizers.all(f, f in variables.oldFinalizers) && variables.oldFinalizers.all(f, f in variables.newFinalizers)" not in nexpr \
                or "managerTaints" in nv \
                or any(("t.key == 'remediation.medik8s.io/self-node-remediation' && t.effect == 'NoSchedule' && (!has(t.value) || t.value == '')" not in nv.get(k, "")
                        or "t.key == 'node.kubernetes.io/out-of-service' && t.effect == 'NoExecute' && has(t.value) && t.value == 'nodeshutdown'" not in nv.get(k, ""))
                       for k in ("newOtherTaints", "oldOtherTaints")) \
                or "variables.newOtherTaints.all(t, t in variables.oldOtherTaints) && variables.oldOtherTaints.all(t, t in variables.newOtherTaints)" not in nexpr:
            F.add("policies.yaml portcullis-node-labels: remediation.medik8s.io/ labels, nodeadm.portcullis/ annotations, cordons, owners / finalizers and the manager's own-taints-only rule")
    # Round 5 C1: the manager's NoSchedule taint key = the agent template's
    # NoSchedule toleration of SNR's own key (upstream-diffed, sha-pinned).
    tol = re.findall(r'- key: "([^"]*medik8s\.io[^"]*)"\n +operator: "Exists"\n +effect: "NoSchedule"',
                     (K.ROOT / "kube/ha/fencing/agent-daemonset.yaml.tmpl").read_text())
    nv_taints = {v["name"]: v["expression"] for v in nlp["spec"]["variables"]}.get("newOtherTaints", "") if nlp else ""
    if tol != ["remediation.medik8s.io/self-node-remediation"] or f"t.key == '{tol[0] if tol else ''}' && t.effect == 'NoSchedule'" not in nv_taints:
        F.add(f"policies.yaml: the manager's NoSchedule taint isn't SNR's own key (the agent template tolerates {tol})")
    # Round 3 M2 + nit: the manager's probes pinned exactly; each pod policy refuses its own generation first.
    fa = (K.ROOT / "kube/ha/fencing/admission.yaml").read_text()
    for probe, path in (("livenessProbe", "/healthz"), ("readinessProbe", "/readyz"), ("startupProbe", "/healthz")):
        b = f"variables.c.{probe}"
        for want in (f"{b}.httpGet.path == '{path}'", f"string({b}.httpGet.port) == '8081'", f"!has({b}.httpGet.host)",
                     f"!has({b}.httpGet.httpHeaders)", f"(!has({b}.httpGet.scheme) || {b}.httpGet.scheme == 'HTTP')",
                     f"!has({b}.exec)", f"!has({b}.tcpSocket)", f"!has({b}.grpc)"):
            if want not in fa:
                F.add(f"fencing admission.yaml: the manager's {probe} isn't pinned ({want})")
    for f, pol in (("kube/ha/fencing/admission.yaml", "portcullis-fencing-pods"), ("kube/ha/probe/admission.yaml", "portcullis-ha-probe-pods")):
        d = next(x for x in yaml.safe_load_all((K.ROOT / f).read_text()) if x and x["kind"] == "ValidatingAdmissionPolicy")
        v0 = d["spec"]["validations"][0]
        if "'@POLICY_GENERATION@'" not in v0["expression"] or v0.get("message") != f"{pol} generation @POLICY_GENERATION@ is in force":
            F.add(f"{f}: the first validation must refuse the in-force check of its own generation")
    probe_pol = [d for d in yaml.safe_load_all((K.ROOT / "kube/ha/probe/admission.yaml").read_text()) if d]
    pb = next((d for d in probe_pol if d["kind"] == "ValidatingAdmissionPolicyBinding"), None)
    if not pb or pb["spec"]["paramRef"] != {"name": "ha-probe-params", "namespace": "portcullis-ha-probe", "parameterNotFoundAction": "Deny"} \
            or pb["spec"]["matchResources"]["namespaceSelector"]["matchLabels"] != {"kubernetes.io/metadata.name": "portcullis-ha-probe"}:
        F.add("probe: portcullis-ha-probe-guard-pods must bind portcullis-ha-probe with its params, missing = deny")
    if "_ha_node_probes \"$KUBE_HA_PROBE_NS\"" not in ha_sh or ha_sh.count("_ha_probe_setup\n") < 2:
        F.add("ha.sh: the host probes must run in portcullis-ha-probe after _ha_probe_setup")
    # cert-manager: only cnpg-system and its own namespace; no ACME.
    cm = renders["certmanager"]
    for p in wide_rule_problems("certmanager", cm, K_CERTMANAGER_NS):
        F.add(p)
    for d in cm:
        if d.get("kind") in ("Role", "RoleBinding") and d["metadata"].get("namespace") not in (K_CERTMANAGER_NS, K.CNPG_NS):
            F.add(f"certmanager: {d['kind']} {d['metadata']['name']} in {d['metadata'].get('namespace')}")
    ctrl = next(d for d in cm if d.get("kind") == "Deployment" and d["metadata"]["name"] == "cert-manager")
    args = pod_spec_of(ctrl)["containers"][0]["args"]
    if f"--namespace={K.CNPG_NS}" not in args or any("acme" in a for a in args):
        F.add(f"certmanager: the controller's args {args} (--namespace={K.CNPG_NS}, no ACME)")
    for p in barman_problems(renders["barman"]):
        F.add(p)
    # The StorageClass.
    sc = yaml.safe_load((K.ROOT / "kube/storage/storageclass-replicated.yaml").read_text())
    if (sc["metadata"]["name"], sc["provisioner"], sc["reclaimPolicy"], sc["parameters"].get("numberOfReplicas"), sc["parameters"].get("dataLocality")) \
            != ("portcullis-core-replicated", "driver.longhorn.io", "Retain", "2", "best-effort"):
        F.add(f"storageclass-replicated.yaml: {sc} (Longhorn, 2 replicas, Retain, best-effort)")
    # The hardening floor bites (mutation): a Secret write, a ClusterRole write, cluster-admin.
    mut = [{"kind": "ClusterRole", "metadata": {"name": "m"}, "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "create"]},
            {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["clusterroles"], "verbs": ["create"]}]},
           {"kind": "ClusterRoleBinding", "metadata": {"name": "m"}, "roleRef": {"name": "m"}, "subjects": [{"kind": "ServiceAccount", "namespace": "x"}]},
           {"kind": "ClusterRoleBinding", "metadata": {"name": "a"}, "roleRef": {"name": "cluster-admin"}, "subjects": [{"kind": "ServiceAccount", "namespace": "x"}]}]
    if len(wide_rule_problems("mut", mut, "x")) != 3:
        F.add(f"wide_rule_problems misses a mutation: {wide_rule_problems('mut', mut, 'x')}")


K_LONGHORN_NS, K_FENCING_NS, K_CERTMANAGER_NS = "longhorn-system", "portcullis-fencing", "cert-manager"


def check_backup_egress():
    """Security ruling (Task 26): the backup egress reaches exactly the
    destination endpoint's addresses on its port, from exactly the pods that
    talk to it — the chart's portcullis-pg-backup (the CNPG instance pods
    only) and ha.sh's Longhorn policies (longhorn-manager and the instance
    managers, never a namespace-wide {}); a non-/32 endpoint is refused at
    render time."""
    import copy
    base = yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-ha.yaml").read_text())
    bk = yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-backup.yaml").read_text())
    vals = copy.deepcopy(base); vals.update(bk)
    docs = K.render(vals, "templates/postgres-cnpg.yaml")
    pols = [d for d in K.by_kind(docs, "NetworkPolicy") if d["metadata"]["name"] == "portcullis-pg-backup"]
    if len(pols) != 1:
        F.add(f"backup egress: {len(pols)} portcullis-pg-backup policies (want 1 with backup.cnpg.enabled)")
    else:
        sp = pols[0]["spec"]
        if sp["podSelector"] != {"matchLabels": {"cnpg.io/cluster": "portcullis-pg", "cnpg.io/podRole": "instance"}}:
            F.add(f"backup egress: portcullis-pg-backup selects {sp['podSelector']} (the instance pods only)")
        to = [t for e in sp.get("egress", []) for t in e.get("to", [])]
        if to != [{"ipBlock": {"cidr": c}} for c in bk["backup"]["cnpg"]["endpointCIDRs"]] or sp.get("ingress"):
            F.add(f"backup egress: portcullis-pg-backup reaches {to} (exactly the endpoint's /32s)")
        if [p for e in sp["egress"] for p in e.get("ports", [])] != [{"protocol": "TCP", "port": bk["backup"]["cnpg"]["port"]}]:
            F.add("backup egress: portcullis-pg-backup's port isn't the destination's")
    # Review I1: the archive's serverName is this install's (the CLI derives
    # it from PORTCULLIS_KUBE_INSTALL_ID); none / another shape is refused.
    cl = K.by_kind(docs, "Cluster")[0]
    plug = [p for p in cl["spec"].get("plugins", []) if p["name"] == "barman-cloud.cloudnative-pg.io"]
    if len(plug) != 1 or plug[0]["parameters"].get("serverName") != bk["backup"]["cnpg"]["serverName"] \
            or not re.match(r"^portcullis-pg-[0-9a-f]{8}$", plug[0]["parameters"].get("serverName", "")):
        F.add(f"backup: the plugin's serverName {plug} (portcullis-pg-<install id>)")
    for sn in ("", "portcullis-pg", "other"):
        bad = copy.deepcopy(vals); bad["backup"]["cnpg"]["serverName"] = sn
        try:
            K.render(bad, "templates/postgres-cnpg.yaml"); F.add(f"backup: serverName {sn!r} renders (want refused)")
        except subprocess.CalledProcessError:
            pass
    # Review I3: rotating addresses → any public address on 443, the private
    # and cluster ranges excepted; another port refused.
    pub = copy.deepcopy(vals)
    priv = re.search(r'^BACKUP_DEST_PRIVATE_CIDRS="([^"]*)"', (K.ROOT / "scripts/lib/ha.sh").read_text(), re.M).group(1).split()
    exc = priv + ["10.42.0.0/24", "10.43.0.0/16", "10.215.0.0/24", "198.51.100.1/32"]
    pub["backup"]["cnpg"].update({"publicEgress": True, "endpointCIDRs": [], "publicExcept": exc})
    pp = [d for d in K.by_kind(K.render(pub, "templates/postgres-cnpg.yaml"), "NetworkPolicy") if d["metadata"]["name"] == "portcullis-pg-backup"]
    if not pp or pp[0]["spec"]["egress"] != [{"to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": exc}}], "ports": [{"protocol": "TCP", "port": 443}]}] \
            or pp[0]["spec"]["podSelector"] != {"matchLabels": {"cnpg.io/cluster": "portcullis-pg", "cnpg.io/podRole": "instance"}}:
        F.add(f"backup egress (public): {pp and pp[0]['spec']}")
    for mut in ({"port": 8443}, {"publicExcept": exc[1:]}, {"publicExcept": [c for c in exc if c != "198.18.0.0/15"]}):
        bad = copy.deepcopy(pub); bad["backup"]["cnpg"].update(mut)
        try:
            K.render(bad, "templates/postgres-cnpg.yaml"); F.add(f"backup egress (public): {mut} renders (want refused)")
        except subprocess.CalledProcessError:
            pass
    bad = copy.deepcopy(vals); bad["backup"]["cnpg"]["endpointCIDRs"] = ["0.0.0.0/0"]
    try:
        K.render(bad, "templates/postgres-cnpg.yaml")
        F.add("backup egress: an endpointCIDRs of 0.0.0.0/0 renders (want refused)")
    except subprocess.CalledProcessError:
        pass
    if [d for d in K.by_kind(K.render(base, "templates/postgres-cnpg.yaml"), "NetworkPolicy") if d["metadata"]["name"] == "portcullis-pg-backup"]:
        F.add("backup egress: portcullis-pg-backup without a destination")
    ha_sh = (K.ROOT / "scripts" / "lib" / "ha.sh").read_text()
    if "_ha_backup_egress \"$KUBE_LONGHORN_NS\" backup-destination '{}'" in ha_sh or re.search(r"_ha_backup_egress [^\n]*'\{\}'", ha_sh):
        F.add("ha.sh: a namespace-wide ({}) backup egress policy")
    m = re.search(r"HA_LONGHORN_BACKUP_PODS='([^']*)'", ha_sh)
    want = {"backup-destination-manager": {"matchLabels": {"app": "longhorn-manager"}},
            "backup-destination-instance-manager": {"matchLabels": {"longhorn.io/component": "instance-manager"}}}
    got = {ln.split(" ", 1)[0]: json.loads(ln.split(" ", 1)[1]) for ln in (m.group(1).splitlines() if m else []) if ln.strip()}
    if got != want:
        F.add(f"ha.sh HA_LONGHORN_BACKUP_PODS {got} (longhorn-manager and the instance managers, by their pinned labels)")


def barman_render():
    """kubectl kustomize kube/ha/barman-cloud (ha_install_barman's render)."""
    env = dict(os.environ)
    kc = env.get("KUBECTL") or "kubectl"
    out = subprocess.run([kc, "kustomize", str(K.ROOT / "kube/ha/barman-cloud")], check=True, capture_output=True, text=True, env=env).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def barman_problems(docs):
    """Plan Task 26: the barman-cloud plugin's rights end at cnpg-system
    (WATCH_NAMESPACE; no ClusterRole / ClusterRoleBinding at all), Secrets
    read only, RBAC writes only its Cluster's pair by name (create aside),
    its Lease by name; the sidecar image pinned; no upstream Secret."""
    out = []
    for d in docs:
        k, n, ns = d.get("kind"), d["metadata"]["name"], d["metadata"].get("namespace")
        if k in ("ClusterRole", "ClusterRoleBinding"):
            out.append(f"barman: renders {k} {n} (its rights are Roles in {K.CNPG_NS})")
        if k not in ("CustomResourceDefinition", "ClusterRole", "ClusterRoleBinding") and ns != K.CNPG_NS:
            out.append(f"barman: {k} {n} outside {K.CNPG_NS} ({ns})")
        if k == "Secret":
            out.append(f"barman: renders the Secret {n} (the sidecar image is pinned in the Deployment)")
    for _, r in rules_of(docs, "Role"):
        res, verbs, named = set(r.get("resources", [])), set(r.get("verbs", [])), r.get("resourceNames")
        if "" in r.get("apiGroups", []) and "secrets" in res and verbs - {"get", "list", "watch"}:
            out.append(f"barman: Secrets {sorted(verbs)} (read only)")
        if res & {"roles", "rolebindings"} and (verbs - {"get", "list", "watch", "create"}) and named != ["portcullis-pg-barman-cloud"]:
            out.append(f"barman: RBAC {sorted(verbs)} on {sorted(res)} not by the Cluster's name")
        if "leases" in res and (verbs - {"create"}) and named != ["822e3f5c.cnpg.io"]:
            out.append(f"barman: Leases {sorted(verbs)} not by its name")
        if "*" in verbs or "*" in res or "escalate" in verbs or "bind" in verbs:
            out.append(f"barman: a wildcard / escalate / bind rule {r}")
    dep = next((d for d in docs if d.get("kind") == "Deployment" and d["metadata"]["name"] == "barman-cloud"), None)
    if dep is None:
        return out + ["barman: no Deployment barman-cloud"]
    # Mutation: the rule checks bite (a Secret write, an unnamed RBAC
    # patch, a ClusterRole).
    if docs and docs[0].get("metadata", {}).get("name") != "m":
        mut = [{"kind": "Role", "metadata": {"name": "m", "namespace": K.CNPG_NS}, "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "create"]},
                {"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles"], "verbs": ["patch"]}]},
               {"kind": "ClusterRole", "metadata": {"name": "c"}, "rules": []}]
        if len([p for p in barman_problems(mut) if "no Deployment" not in p]) != 3:
            out.append(f"barman_problems misses a mutation: {barman_problems(mut)}")
    c = pod_spec_of(dep)["containers"][0]
    env = {e["name"]: e.get("value") for e in c.get("env", [])}
    if env.get("WATCH_NAMESPACE") != K.CNPG_NS:
        out.append(f"barman: WATCH_NAMESPACE {env.get('WATCH_NAMESPACE')} (want {K.CNPG_NS})")
    if env.get("SIDECAR_IMAGE") != "ghcr.io/cloudnative-pg/plugin-barman-cloud-sidecar:v0.16.0@sha256:c669259e20ed1e11fad821f735c396c19d929985aa05b9544b13ecc8b5a386d0":
        out.append(f"barman: SIDECAR_IMAGE {env.get('SIDECAR_IMAGE')} (the pinned sidecar by digest)")
    sc = c.get("securityContext") or {}
    if sc.get("allowPrivilegeEscalation") is not False or sc.get("readOnlyRootFilesystem") is not True or (sc.get("capabilities") or {}).get("drop") != ["ALL"]:
        out.append(f"barman: the plugin container's securityContext {sc}")
    return out


if __name__ == "__main__":
    sys.exit(main())
