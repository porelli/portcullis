#!/usr/bin/env python3
"""The HA pod admission vectors (plan Task 24 fix round 1, security
review): portcullis-fencing-pods (kube/ha/fencing/admission.yaml) and
portcullis-ha-probe-pods (kube/ha/probe/admission.yaml). The bases are the
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


def agent_base(image):
    t = (ROOT / "kube/ha/fencing/agent-daemonset.yaml.tmpl").read_text()
    t = t.replace("{{.Image}}", image).replace("{{.Namespace}}", "portcullis-fencing").replace("{{.HostPort}}", "30001")
    t = re.sub(r"\{\{\.[A-Za-z]+\}\}", "v", t)
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
    ]:
        add(P, probe, name, fn)
    return out


if __name__ == "__main__":
    text = json.dumps(vectors(), indent=1, sort_keys=True) + "\n"
    if sys.argv[1:] == ["--check"]:
        if OUT.read_text() != text:
            sys.exit(f"{OUT.relative_to(ROOT)} is stale: run python3 tests/ha_admission_vectors.py > {OUT.relative_to(ROOT)}")
        print(f"ha_admission_vectors: {len(json.loads(text))} vectors, current")
    else:
        sys.stdout.write(text)
