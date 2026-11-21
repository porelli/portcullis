#!/usr/bin/env python3
"""The HA pod admission vectors (plan Task 24 fix round 1, security
review): portcullis-fencing-pods (kube/ha/fencing/admission.yaml),
portcullis-ha-probe-pods (kube/ha/probe/admission.yaml) and, from round 3,
portcullis-node-labels' storm-guard rules (kube/admission/policies.yaml:
node identities and SNR's manager on a Node). The pod bases are the
real shapes — SNR's manager from ha_render fencing, its agent from
kube/ha/fencing/agent-daemonset.yaml.tmpl, the host probe from ha.sh
_ha_probe_pod_json — and every refused variant the reviews named is one
mutation of a base.

  python3 tests/ha_admission_vectors.py           # print the vectors
  python3 tests/ha_admission_vectors.py --check   # == tests/ha_admission_vectors.json

.github/ci/e2e-ha-admission.sh tries each against a cluster (server
dry-run); tests/k8s_hardening.py runs --check.
"""
import copy
import json
import pathlib
import re
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "ha_admission_vectors.json"


def bash(code, *args):
    return subprocess.run(["bash", "-c", f'source "$1/scripts/lib/common.sh"; {code}', "_", str(ROOT), *args],
                          check=True, capture_output=True, text=True).stdout


def pod(spec, ns, name):
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": ns}, "spec": spec}


def manager_base():
    docs = [d for d in yaml.safe_load_all(bash("ha_render fencing")) if d]
    dep = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "self-node-remediation-controller-manager")
    spec = copy.deepcopy(dep["spec"]["template"]["spec"])
    spec["containers"][0]["volumeMounts"].append({"name": "kube-api-access", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": True})
    spec["volumes"].append({"name": "kube-api-access", "projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]}})
    return pod(spec, "portcullis-fencing", "v-manager")


# SNR v0.13.0's SelfNodeRemediationConfig defaults (its CRD), under
# kube/ha/fencing/config.yaml's values: what SNR's manager renders into the
# agent template (durations as nanoseconds, internal/controller
# selfnoderemediationconfig_controller.go).
SNR_DEFAULTS = {"watchdogFilePath": "/dev/watchdog", "peerApiServerTimeout": "5s", "apiCheckInterval": "15s", "peerUpdateInterval": "15m",
                "apiServerTimeout": "5s", "peerDialTimeout": "5s", "peerRequestTimeout": "7s", "maxApiErrorThreshold": 3,
                "isSoftwareRebootEnabled": True, "endpointHealthCheckUrl": "", "hostPort": 30001, "minPeersForRemediation": 1}


def ns(d):
    m = re.fullmatch(r"(\d+)(s|m)", d)
    return str(int(m.group(1)) * (60 if m.group(2) == "m" else 1) * 10**9)


def agent_values():
    cfg = next(d for d in yaml.safe_load_all((ROOT / "kube/ha/fencing/config.yaml").read_text()) if d)["spec"]
    v = dict(SNR_DEFAULTS) | {k: cfg[k] for k in SNR_DEFAULTS if k in cfg}
    return {"WatchdogPath": v["watchdogFilePath"], "PeerApiServerTimeout": ns(v["peerApiServerTimeout"]),
            "ApiCheckInterval": ns(v["apiCheckInterval"]), "PeerUpdateInterval": ns(v["peerUpdateInterval"]),
            "ApiServerTimeout": ns(v["apiServerTimeout"]), "PeerDialTimeout": ns(v["peerDialTimeout"]),
            "PeerRequestTimeout": ns(v["peerRequestTimeout"]), "MaxApiErrorThreshold": str(v["maxApiErrorThreshold"]),
            "IsSoftwareRebootEnabled": '"' + str(v["isSoftwareRebootEnabled"]).lower() + '"',
            "EndpointHealthCheckUrl": v["endpointHealthCheckUrl"] or '""', "HostPort": str(v["hostPort"]),
            "MinPeersForRemediation": str(v["minPeersForRemediation"])}


def agent_base(image):
    t = (ROOT / "kube/ha/fencing/agent-daemonset.yaml.tmpl").read_text()
    t = t.replace("{{.Image}}", image).replace("{{.Namespace}}", "portcullis-fencing")
    for k, val in agent_values().items():
        t = t.replace("{{." + k + "}}", val)
    if "{{" in t:
        sys.exit("agent-daemonset.yaml.tmpl has a placeholder agent_values() doesn't know")
    ds = yaml.safe_load(t)
    spec = copy.deepcopy(ds["spec"]["template"]["spec"])
    spec["volumes"].append({"name": "kube-api-access", "projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]}})
    return pod(spec, "portcullis-fencing", "v-agent")


def probe_base():
    p = json.loads(bash('_ha_probe_pod_json v-probe portcullis-ha-probe node-x "iscsid watchdog"'))
    return p


def mut(base, name, fn):
    p = copy.deepcopy(base)
    fn(p["spec"])
    p["metadata"]["name"] = "v-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:50]
    return p


def c0(s):
    return s["containers"][0]


def csc(s):
    return c0(s).setdefault("securityContext", {})


def plain(c, name):
    """A copy of a container that is valid as another one (no ports, probes
    or lifecycle: those would be the API server's refusals, not the
    policy's)."""
    c = copy.deepcopy(c)
    for k in ("ports", "lifecycle", "livenessProbe", "readinessProbe", "startupProbe"):
        c.pop(k, None)
    return c | {"name": name}


def extra_container(s):
    s["containers"].append(plain(c0(s), "extra"))


def init_container(s):
    s["initContainers"] = [plain(c0(s), "init")]


def privileged(s):
    csc(s).update(privileged=True, allowPrivilegeEscalation=True)


def vectors():
    mgr = manager_base()
    image = mgr["spec"]["containers"][0]["image"]
    agent, probe = agent_base(image), probe_base()
    out = []

    def add(policy, base, name, fn=None, allowed=False):
        out.append({"policy": policy, "name": name, "allowed": allowed, "pod": mut(base, name, fn) if fn else copy.deepcopy(base)})

    F, P = "portcullis-fencing-pods", "portcullis-ha-probe-pods"
    add(F, agent, "agent: the template's shape", allowed=True)
    for name, fn in [
        ("agent: another image", lambda s: c0(s).__setitem__("image", "docker.io/library/alpine:3.24.3@sha256:" + "a" * 64)),
        ("agent: a second container", extra_container),
        ("agent: an init container", init_container),
        ("agent: another command", lambda s: c0(s).__setitem__("command", ["/bin/sh"])),
        ("agent: other args", lambda s: c0(s).__setitem__("args", ["--is-manager=true"])),
        ("agent: hostNetwork", lambda s: s.__setitem__("hostNetwork", True)),
        ("agent: hostIPC", lambda s: s.__setitem__("hostIPC", True)),
        ("agent: hostPID off (not the template's)", lambda s: s.__setitem__("hostPID", False)),
        ("agent: the host's / mounted", lambda s: s["volumes"].append({"name": "root", "hostPath": {"path": "/"}})),
        ("agent: hostPath /etc instead of /dev", lambda s: s["volumes"][0]["hostPath"].__setitem__("path", "/etc")),
        ("agent: an added capability", lambda s: csc(s).__setitem__("capabilities", {"add": ["SYS_ADMIN"]})),
        ("agent: another hostPort", lambda s: c0(s)["ports"].append({"containerPort": 22, "hostPort": 22})),
        ("agent: another ServiceAccount", lambda s: s.__setitem__("serviceAccountName", "self-node-remediation-controller-manager")),
        ("agent: an SELinux override", lambda s: csc(s).__setitem__("seLinuxOptions", {"type": "spc_t"})),
        ("agent: a postStart hook", lambda s: c0(s).__setitem__("lifecycle", {"postStart": {"exec": {"command": ["/bin/bash", "-c", "id"]}}})),
        ("agent: an exec liveness probe", lambda s: c0(s).__setitem__("livenessProbe", {"exec": {"command": ["/bin/bash", "-c", "id"]}})),
        ("agent: an exec readiness probe", lambda s: c0(s).__setitem__("readinessProbe", {"exec": {"command": ["/bin/bash", "-c", "id"]}})),
        ("agent: envFrom", lambda s: c0(s).__setitem__("envFrom", [{"configMapRef": {"name": "x"}}])),
        ("agent: a workingDir", lambda s: c0(s).__setitem__("workingDir", "/tmp")),
        ("agent: stdin", lambda s: c0(s).__setitem__("stdin", True)),
        ("agent: tty", lambda s: c0(s).__setitem__("tty", True)),
        ("agent: an extra env (LD_PRELOAD)", lambda s: c0(s)["env"].append({"name": "LD_PRELOAD", "value": "/dev/shm/x.so"})),
        ("agent: another watchdog path", lambda s: next(e for e in c0(s)["env"] if e["name"] == "WATCHDOG_PATH").__setitem__("value", "/dev/null")),
        ("agent: an env from a Secret", lambda s: c0(s)["env"][2].__setitem__("valueFrom", {"secretKeyRef": {"name": "x", "key": "y"}}) or c0(s)["env"][2].pop("value")),
        ("agent: the node name from another field", lambda s: c0(s)["env"][0]["valueFrom"]["fieldRef"].__setitem__("fieldPath", "metadata.name")),
        ("agent: a projected Secret source", lambda s: s["volumes"][-1]["projected"]["sources"].append({"secret": {"name": "x"}})),
    ]:
        add(F, agent, name, fn)
    add(F, mgr, "manager: the CSV's shape", allowed=True)
    for name, fn in [
        ("manager: container runAsUser 0", lambda s: csc(s).__setitem__("runAsUser", 0)),
        ("manager: container runAsNonRoot false", lambda s: csc(s).__setitem__("runAsNonRoot", False)),
        ("manager: pod runAsNonRoot false", lambda s: s["securityContext"].__setitem__("runAsNonRoot", False)),
        ("manager: an added capability", lambda s: csc(s)["capabilities"].__setitem__("add", ["NET_ADMIN"])),
        ("manager: drop removed", lambda s: csc(s).__setitem__("capabilities", {})),
        ("manager: allowPrivilegeEscalation", lambda s: csc(s).__setitem__("allowPrivilegeEscalation", True)),
        ("manager: privileged", privileged),
        ("manager: writable root", lambda s: csc(s).__setitem__("readOnlyRootFilesystem", False)),
        ("manager: hostPID", lambda s: s.__setitem__("hostPID", True)),
        ("manager: hostIPC", lambda s: s.__setitem__("hostIPC", True)),
        ("manager: hostNetwork", lambda s: s.__setitem__("hostNetwork", True)),
        ("manager: a hostPath", lambda s: s["volumes"].append({"name": "root", "hostPath": {"path": "/"}})),
        ("manager: a hostPort", lambda s: c0(s)["ports"].append({"containerPort": 2222, "hostPort": 2222})),
        ("manager: another command", lambda s: c0(s).__setitem__("command", ["/bin/sh", "-c", "id"])),
        ("manager: an extra arg", lambda s: c0(s)["args"].append("--zap-devel")),
        ("manager: a second container", extra_container),
        ("manager: an init container", init_container),
        ("manager: another image", lambda s: c0(s).__setitem__("image", "docker.io/library/alpine:3.24.3@sha256:" + "a" * 64)),
        ("manager: another postStart hook", lambda s: c0(s)["lifecycle"]["postStart"]["exec"].__setitem__("command", ["/bin/sh", "-c", "id"])),
        ("manager: another preStop hook", lambda s: c0(s)["lifecycle"]["preStop"]["exec"].__setitem__("command", ["/bin/sh", "-c", "id"])),
        ("manager: an exec liveness probe", lambda s: c0(s).__setitem__("livenessProbe", {"exec": {"command": ["/bin/sh", "-c", "id"]}})),
        ("manager: an exec startup probe", lambda s: c0(s).__setitem__("startupProbe", {"exec": {"command": ["/bin/sh", "-c", "id"]}})),
        # Round 3 M2: every httpGet probe exactly the CSV's.
        ("manager: a liveness probe host", lambda s: c0(s)["livenessProbe"]["httpGet"].__setitem__("host", "169.254.169.254")),
        ("manager: readiness probe httpHeaders", lambda s: c0(s)["readinessProbe"]["httpGet"].__setitem__("httpHeaders", [{"name": "Authorization", "value": "x"}])),
        ("manager: another startup probe path", lambda s: c0(s)["startupProbe"]["httpGet"].__setitem__("path", "/metrics")),
        ("manager: another liveness probe port", lambda s: c0(s)["livenessProbe"]["httpGet"].__setitem__("port", 8443)),
        ("manager: readiness probe scheme HTTPS", lambda s: c0(s)["readinessProbe"]["httpGet"].__setitem__("scheme", "HTTPS")),
        ("manager: a tcpSocket readiness probe", lambda s: c0(s).__setitem__("readinessProbe", {"tcpSocket": {"port": 8081}})),
        ("manager: envFrom", lambda s: c0(s).__setitem__("envFrom", [{"configMapRef": {"name": "x"}}])),
        ("manager: a workingDir", lambda s: c0(s).__setitem__("workingDir", "/tmp")),
        ("manager: tty", lambda s: c0(s).__setitem__("tty", True)),
        ("manager: an extra env", lambda s: c0(s)["env"].append({"name": "LD_PRELOAD", "value": "/tmp/x.so"})),
        ("manager: another agent image in env", lambda s: next(e for e in c0(s)["env"] if e["name"] == "SELF_NODE_REMEDIATION_IMAGE").__setitem__("value", "docker.io/library/alpine:3.24.3@sha256:" + "a" * 64)),
        ("manager: pod seccomp Unconfined", lambda s: s["securityContext"].__setitem__("seccompProfile", {"type": "Unconfined"})),
        ("manager: container seccomp Unconfined", lambda s: csc(s).__setitem__("seccompProfile", {"type": "Unconfined"})),
        ("manager: container AppArmor Unconfined", lambda s: csc(s).__setitem__("appArmorProfile", {"type": "Unconfined"})),
        ("manager: a projected Secret source", lambda s: s["volumes"][-1]["projected"]["sources"].append({"secret": {"name": "x"}})),
    ]:
        add(F, mgr, name, fn)
    add(P, probe, "probe: the CLI's shape", allowed=True)
    for name, fn in [
        ("probe: container runAsUser 0", lambda s: csc(s).__setitem__("runAsUser", 0)),
        ("probe: container runAsNonRoot false", lambda s: csc(s).__setitem__("runAsNonRoot", False)),
        ("probe: pod runAsUser 0", lambda s: s["securityContext"].__setitem__("runAsUser", 0)),
        ("probe: pod runAsNonRoot false", lambda s: s["securityContext"].__setitem__("runAsNonRoot", False)),
        ("probe: a supplemental group 0", lambda s: s["securityContext"].__setitem__("supplementalGroups", [0])),
        ("probe: an added capability", lambda s: csc(s)["capabilities"].__setitem__("add", ["SYS_ADMIN"])),
        ("probe: drop removed", lambda s: csc(s).__setitem__("capabilities", {})),
        ("probe: allowPrivilegeEscalation", lambda s: csc(s).__setitem__("allowPrivilegeEscalation", True)),
        ("probe: privileged", privileged),
        ("probe: writable root", lambda s: csc(s).__setitem__("readOnlyRootFilesystem", False)),
        ("probe: hostIPC", lambda s: s.__setitem__("hostIPC", True)),
        ("probe: hostNetwork", lambda s: s.__setitem__("hostNetwork", True)),
        ("probe: another command", lambda s: c0(s).__setitem__("command", ["sh", "-c", "cat /host/etc/shadow"])),
        ("probe: args added", lambda s: c0(s).__setitem__("args", ["x"])),
        ("probe: another env", lambda s: c0(s)["env"].append({"name": "X", "value": "y"})),
        ("probe: a CHECKS value that isn't check ids", lambda s: c0(s)["env"][0].__setitem__("value", "$(id)")),
        ("probe: an init container", init_container),
        ("probe: a second container", extra_container),
        ("probe: the mount writable", lambda s: c0(s)["volumeMounts"][0].__setitem__("readOnly", False)),
        ("probe: hostPath /etc", lambda s: s["volumes"][0]["hostPath"].__setitem__("path", "/etc")),
        ("probe: an extra volume", lambda s: s["volumes"].append({"name": "tmp", "emptyDir": {}})),
        ("probe: a subPath", lambda s: c0(s)["volumeMounts"][0].__setitem__("subPath", "etc")),
        ("probe: the token mounted", lambda s: s.__setitem__("automountServiceAccountToken", True)),
        ("probe: another ServiceAccount", lambda s: s.__setitem__("serviceAccountName", "vector-sa")),
        ("probe: another image", lambda s: c0(s).__setitem__("image", "docker.io/library/busybox:1@sha256:" + "b" * 64)),
        ("probe: a port", lambda s: c0(s).__setitem__("ports", [{"containerPort": 80}])),
        ("probe: a postStart hook", lambda s: c0(s).__setitem__("lifecycle", {"postStart": {"exec": {"command": ["sh", "-c", "id"]}}})),
        ("probe: an exec liveness probe", lambda s: c0(s).__setitem__("livenessProbe", {"exec": {"command": ["sh", "-c", "id"]}})),
        ("probe: envFrom", lambda s: c0(s).__setitem__("envFrom", [{"configMapRef": {"name": "x"}}])),
        ("probe: CHECKS from a field", lambda s: c0(s)["env"][0].pop("value") and c0(s)["env"][0].__setitem__("valueFrom", {"fieldRef": {"fieldPath": "metadata.name"}})),
        ("probe: a workingDir", lambda s: c0(s).__setitem__("workingDir", "/host")),
        ("probe: stdin", lambda s: c0(s).__setitem__("stdin", True)),
        ("probe: tty", lambda s: c0(s).__setitem__("tty", True)),
        ("probe: container seccomp Unconfined", lambda s: csc(s).__setitem__("seccompProfile", {"type": "Unconfined"})),
        ("probe: container AppArmor Unconfined", lambda s: csc(s).__setitem__("appArmorProfile", {"type": "Unconfined"})),
        ("probe: pod AppArmor Unconfined", lambda s: s["securityContext"].__setitem__("appArmorProfile", {"type": "Unconfined"})),
    ]:
        add(P, probe, name, fn)
    # pods/ephemeralcontainers (review I2): an ephemeral container added to
    # an admitted pod (e2e: the pod created, then the subresource dry-run).
    for pol, base in ((F, mgr), (P, probe)):
        e = copy.deepcopy(base)
        e["metadata"]["name"] = base["metadata"]["name"] + "-eph"
        out.append({"policy": pol, "name": f"{pol}: an ephemeral container added", "allowed": False, "ephemeral": True, "pod": e,
                    "ephemeralContainers": [{"name": "debug", "image": "docker.io/library/alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a",
                                             "command": ["sh"]}]})
    # portcullis-node-labels (round 3 I1): the storm guard's inputs. A
    # "node" vector is a merge patch of the cluster's first Node (@NODE@)
    # as a node identity or SNR's manager (impersonated, server dry-run);
    # "taints_add" appends to the Node's live taints.
    NL = "portcullis-node-labels"
    node_id = {"user": "system:node:@NODE@", "groups": ["system:nodes", "system:authenticated"]}
    manager_id = {"user": "system:serviceaccount:portcullis-fencing:self-node-remediation-controller-manager",
                  "groups": ["system:serviceaccounts", "system:serviceaccounts:portcullis-fencing", "system:authenticated"]}
    exclude = {"metadata": {"labels": {"remediation.medik8s.io/exclude-from-remediation": "true"}}}
    nodeadm_ann = {"metadata": {"annotations": {"nodeadm.portcullis/remediated-at": "2999-01-01T00:00:00Z"}}}
    cordon = {"spec": {"unschedulable": True}}
    harmless = {"metadata": {"annotations": {"example.org/vector": "1"}}}
    # SNR v0.13.0's own taints, as its controller writes them (round 5 C1):
    # NodeNoScheduleTaint (no value) and OutOfServiceTaint.
    remediation_taint = {"key": "remediation.medik8s.io/self-node-remediation", "effect": "NoSchedule"}
    for who, ident, cases in (
        ("a node", node_id, [("labels itself excluded from remediation", exclude, False),
                             ("adds a nodeadm.portcullis/ annotation", nodeadm_ann, False),
                             ("cordons itself", cordon, False),
                             ("adds a harmless annotation", harmless, True)]),
        ("SNR's manager", manager_id, [("labels a node excluded from remediation", exclude, False),
                                       ("adds a nodeadm.portcullis/ annotation", nodeadm_ann, False),
                                       ("cordons a node", cordon, False),
                                       ("adds a harmless annotation", harmless, False)])):
        for what, patch, ok in cases:
            out.append({"policy": NL, "name": f"{who} {what}", "allowed": ok, "node": True, "as": ident, "patch": patch})
    # Round 4 M2: owners and finalizers (a dangling owner = the GC deletes the
    # Node), and the manager's taints pinned to its own two keys (nit 4).
    owner = {"metadata": {"ownerReferences": [{"apiVersion": "v1", "kind": "Node", "name": "gone", "uid": "00000000-0000-4000-8000-000000000001"}]}}
    finalizer = {"metadata": {"finalizers": ["example.org/hold"]}}
    for who, ident, what, patch, target in (
            ("a node", node_id, "adds an owner reference to its own Node", owner, "@NODE@"),
            ("a node", node_id, "adds a finalizer to its own Node", finalizer, "@NODE@"),
            ("SNR's manager", manager_id, "adds a finalizer to another Node", finalizer, "@NODE2@"),
            ("SNR's manager", manager_id, "adds an owner reference to another Node", owner, "@NODE2@")):
        v = {"policy": NL, "name": f"{who} {what}", "allowed": False, "node": True, "as": ident, "patch": patch, "target": target}
        if ident is node_id and patch is owner:
            # NodeRestriction refuses a kubelet's ownerReferences change
            # first on current releases (k3s 1.35: "is not allowed to modify
            # ownerReferences"); the policy covers it where it doesn't.
            v["also_refused_by"] = "is not allowed to modify ownerReferences"
        out.append(v)
    out.append({"policy": NL, "name": "SNR's manager adds another NoExecute taint", "allowed": False, "node": True, "as": manager_id,
                "taints_add": [{"key": "example.org/evict", "value": "x", "effect": "NoExecute"}]})
    out.append({"policy": NL, "name": "SNR's manager adds its remediation taint", "allowed": True, "node": True, "as": manager_id,
                "taints_add": [remediation_taint]})
    out.append({"policy": NL, "name": "SNR's manager adds the out-of-service taint", "allowed": True, "node": True, "as": manager_id,
                "taints_add": [{"key": "node.kubernetes.io/out-of-service", "value": "nodeshutdown", "effect": "NoExecute"}]})
    for what, t in (("its remediation key with NoExecute", {"key": "remediation.medik8s.io/self-node-remediation", "effect": "NoExecute"}),
                    ("its remediation key with a value", {"key": "remediation.medik8s.io/self-node-remediation", "value": "x", "effect": "NoSchedule"}),
                    ("out-of-service with another value", {"key": "node.kubernetes.io/out-of-service", "value": "x", "effect": "NoExecute"}),
                    ("the round-4 wrong key medik8s.io/remediation", {"key": "medik8s.io/remediation", "value": "self-node-remediation", "effect": "NoExecute"})):
        out.append({"policy": NL, "name": f"SNR's manager adds {what}", "allowed": False, "node": True, "as": manager_id, "taints_add": [t]})
    # portcullis-barman-rbac (Task 26 review M4): the barman-cloud plugin's
    # Role / RoleBinding creates in cnpg-system, as the plugin.
    BR, plugin = "portcullis-barman-rbac", {"user": "system:serviceaccount:cnpg-system:plugin-barman-cloud", "groups": []}
    meta = {"name": "portcullis-pg-barman-cloud", "namespace": "cnpg-system"}
    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": dict(meta), "rules": [
        {"apiGroups": ["barmancloud.cnpg.io"], "resources": ["objectstores"], "resourceNames": ["portcullis-backup"], "verbs": ["get", "watch", "list"]},
        {"apiGroups": ["barmancloud.cnpg.io"], "resources": ["objectstores/status"], "resourceNames": ["portcullis-backup"], "verbs": ["update"]},
        {"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["backup-destination"], "verbs": ["get", "watch", "list"]}]}
    rb = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": dict(meta),
          "subjects": [{"kind": "ServiceAccount", "apiGroup": "", "name": "portcullis-pg", "namespace": "cnpg-system"}],
          "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "portcullis-pg-barman-cloud"}}

    def obj(name, base, fn=None, allowed=False, also=None):
        o = copy.deepcopy(base)
        if fn:
            fn(o)
        v = {"policy": BR, "name": name, "allowed": allowed, "as": plugin, "object": o}
        # The Role exists (a RoleBinding create needs it): its own vectors are updates.
        if o["kind"] == "Role" and o["metadata"]["name"] == "portcullis-pg-barman-cloud":
            v["update"] = True
        if also:
            v["also_refused_by"] = also  # RBAC's own check may come first
        out.append(v)
    obj("barman: the plugin's Role (pinned BuildRoleRules)", role, allowed=True)
    obj("barman: the plugin's RoleBinding (pinned BuildRoleBinding)", rb, allowed=True)
    obj("barman: a Role of another name", role, lambda o: o["metadata"].update(name="other"))
    obj("barman: a RoleBinding of another name", rb, lambda o: o["metadata"].update(name="other"))
    obj("barman: a Role rule without resourceNames", role, lambda o: o["rules"][2].pop("resourceNames"))
    # Review NN8: the names pinned (BuildRoleRules' ObjectStore / Secret).
    obj("barman: a Role reading another ObjectStore", role, lambda o: o["rules"][0].update(resourceNames=["portcullis-backup", "other"]))
    obj("barman: a Role updating another ObjectStore's status", role, lambda o: o["rules"][1].update(resourceNames=["other"]))
    obj("barman: a Role reading another Secret", role, lambda o: o["rules"][2].update(resourceNames=["portcullis-pg-app"]))
    esc = "is attempting to grant RBAC permissions not currently held"
    obj("barman: a Role reading pods", role, lambda o: o["rules"].append({"apiGroups": [""], "resources": ["pods"], "resourceNames": ["x"], "verbs": ["get"]}), also=esc)
    obj("barman: a Role writing secrets", role, lambda o: o["rules"][2].update(verbs=["get", "update"]), also=esc)
    obj("barman: a binding of its own Role portcullis-barman-cloud", rb, lambda o: o["roleRef"].update(name="portcullis-barman-cloud"))
    obj("barman: a binding to a ServiceAccount in another namespace", rb, lambda o: o["subjects"][0].update(namespace="portcullis"))
    obj("barman: a binding to a second subject", rb, lambda o: o["subjects"].append({"kind": "ServiceAccount", "name": "x", "namespace": "cnpg-system"}))
    obj("barman: a binding to a ClusterRole", rb, lambda o: o["roleRef"].update(kind="ClusterRole", name="portcullis-pg-barman-cloud"), also="not found")
    obj("barman: a binding to a user", rb, lambda o: o["subjects"].__setitem__(0, {"kind": "User", "apiGroup": "rbac.authorization.k8s.io", "name": "mallory"}))
    return out


if __name__ == "__main__":
    text = json.dumps(vectors(), indent=1, sort_keys=True) + "\n"
    if sys.argv[1:] == ["--check"]:
        if OUT.read_text() != text:
            sys.exit(f"{OUT.relative_to(ROOT)} is stale: run python3 tests/ha_admission_vectors.py > {OUT.relative_to(ROOT)}")
        print(f"ha_admission_vectors: {len(json.loads(text))} vectors, current")
    else:
        sys.stdout.write(text)
