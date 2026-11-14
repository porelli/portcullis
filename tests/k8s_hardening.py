#!/usr/bin/env python3
"""The hardening baseline on every pod the chart renders (Task 13, spec §5):
portcullis.io/component, its net labels, automountServiceAccountToken false
(but traefik and hub), drop ALL, no privilege escalation, a read-only root
(but keycloak, as on Docker), RuntimeDefault seccomp, runAsNonRoot,
memory limit = request, portcullis.io/config-hash; and no workload in the
core namespace that PSA `restricted` would refuse. Also: no randAlphaNum /
randAscii / genPrivateKey anywhere in the chart, every image by digest.
Secret access (least privilege): every ServiceAccount's get / list / watch
on Secrets, per namespace, from the chart's and kube/storage's RBAC, is
exactly SECRET_READERS (Traefik only the edge namespace, which renders no
Secret; the Hub only the apps namespace; nobody the core one, which holds
portcullis-env, the age / wg / vault Secrets); Traefik watches only the edge
namespace, and every core IngressRoute / Middleware lives there.

  python3 tests/k8s_hardening.py
"""
import re
import sys

import yaml

import k8s_lib as K

F = K.Failures("k8s_hardening")
TOKEN_OK = {"traefik", "hub"}
WRITABLE_ROOT_OK = {"keycloak"}  # compose: not read_only (`start` re-augments)
# ServiceAccount (namespace/name) → the namespaces whose Secrets it may read.
SECRET_READERS = {
    f"{K.NS}/traefik": {K.EDGE_NS},
    f"{K.NS}/portcullis-hub": {K.APPS_NS},
}
SECRET_READ_VERBS = {"get", "list", "watch", "*"}
RESTRICTED_VOLUMES = {"configMap", "csi", "downwardAPI", "emptyDir", "ephemeral", "persistentVolumeClaim", "projected", "secret"}


def check_pod(name, ns, labels, spec, ann):
    if labels.get("portcullis.io/component") is None:
        F.add(f"{name}: no portcullis.io/component label")
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
        if name in WRITABLE_ROOT_OK:
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
        if not lim or lim != req:
            F.add(f"{cn}: memory limit {lim} != request {req}")
        for p in c.get("ports", []):
            if p.get("hostPort"):
                F.add(f"{cn}: hostPort {p['hostPort']}")
        if not re.search(r"@sha256:[0-9a-f]{64}$", c["image"]):
            F.add(f"{cn}: image {c['image']} not by digest")
        if c.get("securityContext", {}).get("procMount") not in (None, "Default"):
            F.add(f"{cn}: procMount")
    if spec.get("securityContext", {}).get("sysctls"):
        F.add(f"{name}: sysctls")


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
    if [r["metadata"]["namespace"] for r in hub_roles] != [K.APPS_NS]:
        F.add(f"the Hub's Role must be exactly one, in {K.APPS_NS}")
    for r in hub_roles:
        for rule in r["rules"]:
            if "pods/exec" in rule["resources"] and rule["verbs"] != ["create"]:
                F.add("the Hub's Role: pods/exec must be create only, never get (K2)")
            if "pods" in rule["resources"] and set(rule["verbs"]) & {"patch", "update"}:
                F.add("the Hub's Role: never patch / update on pods")
            if set(rule["resources"]) & {"roles", "rolebindings", "serviceaccounts", "namespaces", "nodes", "pods/ephemeralcontainers"}:
                F.add(f"the Hub's Role: {rule['resources']}")
            if set(rule["verbs"]) & {"escalate", "bind", "impersonate", "*"}:
                F.add(f"the Hub's Role: verbs {rule['verbs']}")
    for r in K.by_kind(docs, "Role"):
        if r["metadata"]["name"] == "traefik":
            for rule in r["rules"]:
                if set(rule["verbs"]) - {"get", "list", "watch"}:
                    F.add(f"Traefik's Role in {r['metadata']['namespace']}: {rule['verbs']} (read-only)")
    check_secret_access(docs + storage_docs())
    check_edge(docs)
    return F.done()


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
        if not any(reads_secrets(r) for r in role.get("rules", [])):
            continue
        where = bns if b["kind"] == "RoleBinding" else "*"
        for s in b.get("subjects", []):
            key = f"{s.get('namespace', bns)}/{s['name']}" if s["kind"] == "ServiceAccount" else f"{s['kind']}:{s['name']}"
            out.setdefault(key, set()).add(where)
    return out


def check_secret_access(docs):
    got = secret_access(docs)
    for sa in sorted(set(got) | set(SECRET_READERS)):
        if got.get(sa, set()) != SECRET_READERS.get(sa, set()):
            F.add(f"Secret access of {sa}: {sorted(got.get(sa, set()))} (want {sorted(SECRET_READERS.get(sa, set()))})")
    # portcullis-env lives in the core namespace: Traefik may never read it.
    if K.NS in got.get(f"{K.NS}/traefik", set()) or "*" in got.get(f"{K.NS}/traefik", set()):
        F.add("Traefik's ServiceAccount can read portcullis-env (Secrets of the core namespace)")


def check_edge(docs):
    for d in docs:
        ns = d.get("metadata", {}).get("namespace")
        if d.get("kind") == "Secret" and ns == K.EDGE_NS:
            F.add(f"Secret {d['metadata']['name']} in {K.EDGE_NS} (Traefik reads every Secret there)")
        if d.get("kind") in ("IngressRoute", "Middleware", "IngressRouteTCP", "IngressRouteUDP", "TLSOption", "TLSStore",
                             "ServersTransport", "TraefikService", "MiddlewareTCP") and ns != K.EDGE_NS:
            F.add(f"{d['kind']} {d['metadata']['name']} in {ns}: core Traefik objects live in {K.EDGE_NS} (Traefik's only watched namespace)")
    env = {e["name"]: e.get("value") for e in K.deployments(docs)["traefik"]["spec"]["template"]["spec"]["containers"][0]["env"]}
    if env.get("TRAEFIK_PROVIDERS_KUBERNETESCRD_NAMESPACES") != K.EDGE_NS:
        F.add(f"traefik: kubernetesCRD namespaces {env.get('TRAEFIK_PROVIDERS_KUBERNETESCRD_NAMESPACES')!r} (want {K.EDGE_NS} only)")


if __name__ == "__main__":
    sys.exit(main())
