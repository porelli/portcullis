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
import copy
import json
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
    for r in hub_roles:
        if r["metadata"]["namespace"] == K.EDGE_NS and any("services" in x["resources"] for x in r["rules"]) and not (judges_svc and pins):
            F.add(f"the Hub's Role in {K.EDGE_NS} grants services but portcullis-edge-routes doesn't judge and pin Services (CREATE / UPDATE / DELETE, externalName = <name>.<apps ns>.svc.cluster.local)")
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
    check_psa()
    # Every PVC a pod claims is rendered, with and without the optional
    # profiles (compose's named volumes exist in every profile).
    for extra in (None, {"wg": {"enabled": False}}):
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
# restricted; apps (root one-shots) and storage (the helpers' hostPath)
# can't be stricter than enforce privileged, warn / audit baseline.
PSA_WANT = {"core": ["restricted"] * 3, "apps": ["privileged", "baseline", "baseline"],
            "storage": ["privileged", "baseline", "baseline"], "edge": ["restricted"] * 3}


def check_psa():
    src = json.loads((K.CHART / "namespaces.json").read_text())
    for role, want in PSA_WANT.items():
        if src.get(role) != want:
            F.add(f"namespaces.json {role}: {src.get(role)} (want {want})")
    names = {"core": K.NS, "apps": K.APPS_NS, "storage": "portcullis-storage", "edge": K.EDGE_NS}
    ns = {d["metadata"]["name"]: d["metadata"].get("labels", {}) for d in K.by_kind(K.render({"renderNamespaces": True}), "Namespace")}
    for role, n in names.items():
        got = [ns.get(n, {}).get(f"pod-security.kubernetes.io/{m}") for m in ("enforce", "warn", "audit")]
        if got != src.get(role):
            F.add(f"the chart's namespace {n}: PSA {got} != namespaces.json {role} {src.get(role)}")
    kube = (K.ROOT / "scripts" / "lib" / "kube.sh").read_text()
    if re.search(r"kube_namespace_apply\s+\S+\s+(privileged|baseline|restricted)\b", kube) or re.search(r"(privileged|baseline|restricted),(privileged|baseline|restricted)", kube):
        F.add("scripts/lib/kube.sh spells PSA levels itself: kube_psa reads charts/portcullis/namespaces.json")


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
    # chart's edge Middlewares + the CLI's hub-proxy-secret.
    want = sorted(["hub-proxy-secret"] + [d["metadata"]["name"] for d in K.by_kind(docs, "Middleware")])
    params = yaml.safe_load((K.ROOT / "kube" / "admission" / "params.yaml").read_text())["data"]
    if sorted(params["edgeCoreMiddlewares"].split()) != want:
        F.add(f"kube/admission/params.yaml edgeCoreMiddlewares {params['edgeCoreMiddlewares']!r} != the core edge Middlewares {want}")
    env = {e["name"]: e.get("value") for e in K.deployments(docs)["traefik"]["spec"]["template"]["spec"]["containers"][0]["env"]}
    if env.get("TRAEFIK_PROVIDERS_KUBERNETESCRD_NAMESPACES") != K.EDGE_NS:
        F.add(f"traefik: kubernetesCRD namespaces {env.get('TRAEFIK_PROVIDERS_KUBERNETESCRD_NAMESPACES')!r} (want {K.EDGE_NS} only)")
    if env.get("TRAEFIK_PROVIDERS_KUBERNETESCRD_DISABLECLUSTERSCOPERESOURCES") != "true":
        F.add("traefik: kubernetesCRD disableClusterScopeResources must be true (its Role is namespaced: a Node list it can't make loads no route)")
    if env.get("TRAEFIK_PROVIDERS_KUBERNETESCRD_ALLOWEXTERNALNAMESERVICES") != "true":
        F.add("traefik: allowExternalNameServices must be true (the apps' backends are the Hub's pinned ExternalName Services in the edge namespace)")
    if env.get("TRAEFIK_PROVIDERS_KUBERNETESCRD_ALLOWCROSSNAMESPACE") != "false":
        F.add("traefik: allowCrossNamespace must be false (every route names edge-local or @file objects)")
    # Core's own objects are never ExternalName (only the Hub's pinned ones
    # in the edge namespace, admitted by portcullis-edge-routes), and the
    # chart puts no Service in the edge namespace at all.
    for s in K.by_kind(docs, "Service"):
        if s["spec"].get("type") == "ExternalName":
            F.add(f"service {s['metadata']['name']}: ExternalName (core's Services never are)")
        if s["metadata"].get("namespace") == K.EDGE_NS:
            F.add(f"service {s['metadata']['name']}: in {K.EDGE_NS} (only the Hub's ExternalName Services live there)")


if __name__ == "__main__":
    sys.exit(main())
