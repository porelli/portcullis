"""Shared helpers of the Kubernetes static checks (k8s_parity.py,
k8s_netpol_matrix.py, k8s_hardening.py): docker-compose.yml, the rendered
chart (helm template with tests/k8s-ci-values.yaml), the reviewed deltas.
Needs PyYAML (tests/k8s-requirements.txt) and helm on PATH (or $HELM)."""
import hashlib
import os
import pathlib
import subprocess
import tempfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHART = ROOT / "charts" / "portcullis"
NS = "portcullis"
APPS_NS = "portcullis-apps"
EDGE_NS = "portcullis-edge"
STORAGE_NS = "portcullis-storage"
INGRESS_NS = "portcullis-ingress"
# Compose services with no Kubernetes form (the Roles replace the socket
# proxies; the mail slot is Docker / Podman only, contract §19.12).
ABSENT = {"socket-proxy-traefik", "socket-proxy-hub", "mail-cert"}
# Compose services whose Kubernetes form isn't a workload of the chart
# (plan Task 23): Postgres is the CloudNativePG Cluster portcullis-pg in
# CNPG_NS (k8s_parity.py check_postgres, k8s_netpol_matrix.py
# check_postgres hold it to its own rules).
REPLACED = {"postgres"}
CNPG_NS = "cnpg-system"
PG_CLUSTER = "portcullis-pg"
# Compose networks with no Kubernetes form (the link networks too: Servers
# needs a Docker or Podman primary, contract §17.1).
ABSENT_NETS = {"socket-proxy-traefik", "socket-proxy-hub",
               "portcullis-mail-api", "portcullis-metrics-mail",
               "portcullis-link", "portcullis-link-data",
               # The Hub's usage metrics listener is Docker / Podman only (U20).
               "portcullis-metrics-hub"}
# The VPN networks: port-bound rules only (netpol-wg-edge.yaml), K7.
VPN_NETS = {"portcullis-vpn", "portcullis-vpn-edge", "portcullis-metrics-wg"}


def compose():
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text())


def deltas():
    return yaml.safe_load((ROOT / "tests" / "k8s_parity_deltas.yaml").read_text()) or {}


def images_values():
    """images.<svc>: images.yaml's pinned refs; tag_refs get a fixed fake digest."""
    imgs = yaml.safe_load((CHART / "images.yaml").read_text())["images"]
    out = {}
    for svc, ref in imgs.items():
        if isinstance(ref, dict):
            repo = ref["tag_ref"].rsplit(":", 1)[0]
            out[svc] = f"{repo}@sha256:{hashlib.sha256(repo.encode()).hexdigest()}"
        else:
            out[svc] = ref
    return {"images": out}


def render(extra=None, show_only=None):
    """The chart rendered with the CI values (+ extra values), as a list of docs."""
    helm = os.environ.get("HELM", "helm")
    with tempfile.TemporaryDirectory() as d:
        iv = pathlib.Path(d) / "images.yaml"
        iv.write_text(yaml.safe_dump(images_values()))
        args = [helm, "template", "portcullis", str(CHART), "-n", NS,
                "-f", str(ROOT / "tests" / "k8s-ci-values.yaml"), "-f", str(iv)]
        if extra:
            ev = pathlib.Path(d) / "extra.yaml"
            ev.write_text(yaml.safe_dump(extra))
            args += ["-f", str(ev)]
        if show_only:
            args += ["--show-only", show_only]
        out = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    return [doc for doc in yaml.safe_load_all(out) if doc]


def render_helper(body, extra=None):
    """One helper call rendered alone: a copy of the chart with a template
    holding only <body> (the chart's own values, the CI values + extra)."""
    import shutil
    helm = os.environ.get("HELM", "helm")
    with tempfile.TemporaryDirectory() as d:
        c = pathlib.Path(d) / "portcullis"
        shutil.copytree(CHART, c)
        (c / "templates" / "zz-helper-test.yaml").write_text(body + "\n")
        iv = pathlib.Path(d) / "images.yaml"
        iv.write_text(yaml.safe_dump(images_values()))
        ev = pathlib.Path(d) / "extra.yaml"
        ev.write_text(yaml.safe_dump(extra or {}))
        out = subprocess.run([helm, "template", "portcullis", str(c), "-n", NS, "-f", str(ROOT / "tests" / "k8s-ci-values.yaml"),
                              "-f", str(iv), "-f", str(ev), "--show-only", "templates/zz-helper-test.yaml"],
                             capture_output=True, text=True)
    if out.returncode != 0 and "could not find template" in out.stderr:
        return ""  # an empty render: helm has no document to show
    out.check_returncode()
    return out.stdout.split("\n", 2)[2] if out.stdout.startswith("---\n# Source:") else out.stdout


def cnpg_cluster(docs):
    """The CNPG Cluster portcullis-pg of a render (None without)."""
    return next((d for d in docs if d.get("kind") == "Cluster" and d["metadata"]["name"] == PG_CLUSTER), None)


def render_cnpg(*extra):
    """The CloudNativePG operator as ./portcullis installs it (ha_install_cnpg):
    the vendored chart with the vendored values file, release cnpg in
    CNPG_NS (extra: helm flags, e.g. the chart's own RBAC for a comparison)."""
    helm = os.environ.get("HELM", "helm")
    out = subprocess.run([helm, "template", "cnpg", str(ROOT / "kube" / "ha" / "cnpg" / "cloudnative-pg-0.29.2.tgz"), "-n", CNPG_NS,
                          "-f", str(ROOT / "kube" / "ha" / "cnpg" / "values.yaml"), *extra], check=True, capture_output=True, text=True).stdout
    return [doc for doc in yaml.safe_load_all(out) if doc]


# The API server's webhook sources the static checks assume (what
# kube_apiserver_sources gives on the CI values' cluster: the endpoint and
# the node's pod-range gateways).
CNPG_API_SOURCES = "10.1.0.4 10.42.0.0 10.42.0.1"


def cnpg_policies():
    """cnpg-system's own NetworkPolicies as the CLI applies them (ha.sh
    ha_cnpg_policies, review I4) for the CI values' API endpoints."""
    import json
    api = " ".join(yaml.safe_load((ROOT / "tests" / "k8s-ci-values.yaml").read_text())["apiEndpoints"])
    out = subprocess.run(["bash", "-c", 'source "$1/scripts/lib/common.sh"; ha_cnpg_policies "$2" "$3"', "_", str(ROOT), api, CNPG_API_SOURCES],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out)["items"]


def placement_specs(docs):
    """{name: pod spec} of every pod the chart renders, plus "postgres":
    the CNPG Cluster's instances, as a pod spec holding the Cluster's
    nodeAffinity (CNPG copies spec.affinity.nodeAffinity onto each)."""
    out = {n: sp for n, _, _, sp, _ in pod_specs(docs)}
    c = cnpg_cluster(docs)
    if c is not None:
        na = (c["spec"].get("affinity") or {}).get("nodeAffinity")
        out["postgres"] = {"affinity": {"nodeAffinity": na}} if na else {}
    return out


def by_kind(docs, kind):
    return [d for d in docs if d.get("kind") == kind]


def deployments(docs):
    return {d["metadata"]["name"]: d for d in by_kind(docs, "Deployment")}


def pod_specs(docs):
    """(name, namespace, labels, pod spec, annotations) of every pod the chart renders."""
    out = []
    for d in docs:
        if d.get("kind") in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
            t = d["spec"]["template"]
            # A Job by its component (its name carries a hash of its inputs).
            name = t["metadata"].get("labels", {}).get("portcullis.io/component", d["metadata"]["name"]) if d["kind"] == "Job" else d["metadata"]["name"]
            out.append((name, d["metadata"]["namespace"], t["metadata"].get("labels", {}), t["spec"], t["metadata"].get("annotations", {})))
        elif d.get("kind") == "Pod":
            out.append((d["metadata"]["name"], d["metadata"]["namespace"], d["metadata"].get("labels", {}), d["spec"], d["metadata"].get("annotations", {})))
    return out


def mem_bytes(v):
    v = str(v)
    units = {"k": 1000, "m": 1000 ** 2, "g": 1000 ** 3, "Ki": 1024, "Mi": 1024 ** 2, "Gi": 1024 ** 3,
             "kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3}
    for u in sorted(units, key=len, reverse=True):
        if v.endswith(u):
            n = float(v[: -len(u)])
            # compose's m / g are binary (docker: 512m = 512 MiB).
            if u in ("k", "m", "g"):
                return int(n * {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[u])
            return int(n * units[u])
    return int(v)


def seconds(v):
    v = str(v)
    if v.endswith("ms"):
        return float(v[:-2]) / 1000
    if v.endswith("s"):
        return float(v[:-1])
    if v.endswith("m"):
        return float(v[:-1]) * 60
    return float(v)


class Failures:
    def __init__(self, name):
        self.name, self.items = name, []

    def add(self, msg):
        self.items.append(msg)

    def done(self):
        for m in self.items:
            print(f"FAIL: {m}")
        print(f"{self.name}: {len(self.items)} failure(s)" if self.items else f"{self.name}: ok")
        return 1 if self.items else 0


def domain(docs=None):
    """The CI values' domain (tests/k8s-ci-values.yaml)."""
    return yaml.safe_load((ROOT / "tests" / "k8s-ci-values.yaml").read_text())["domain"]


def mem_request(name, limit):
    """The memory request the chart must render for a core service
    (portcullis.memRequest, user ruling 2026-11-19 / plan Amendment 2): the
    measured peak (values.yaml memoryPeakMi) × 1.25 rounded up to 16 Mi, at
    most the limit; a service without a measurement requests its limit."""
    import math
    vals = yaml.safe_load((CHART / "values.yaml").read_text())
    peaks = vals.get("memoryPeakMi") or {}
    fixed = vals.get("memoryRequestMi") or {}
    if name in fixed:  # a reviewed request (Keycloak: review I2)
        return int(fixed[name]) * 1024 ** 2
    if name not in peaks:
        return mem_bytes(limit)
    req = math.ceil(peaks[name] * 1.25 / 16) * 16 * 1024 ** 2
    return min(req, mem_bytes(limit))


def values():
    """charts/portcullis/values.yaml (the chart's defaults)."""
    return yaml.safe_load((CHART / "values.yaml").read_text())


# Sites (contract §20.11, plan Task 20): the pods pinned to the primary
# site main in HA (a required node affinity portcullis.io/site In [main] in
# every term, merged with any class term). CNPG's instances (the Cluster
# portcullis-pg's affinity, "postgres": k8s_parity.py check_sites) and
# LLDAP's schema Job (Task 23); the Sentinels and Longhorn's disks add
# themselves when Task 24 creates them. LLDAP is pinned with
# the sign-in pieces (its data lives at main). The hub one-shot mounts the
# Hub's replicated volume. Never pinned: the Traefik DaemonSet (ingress
# nodes at every site), frontdoor (it must write DNS when main's uplink is
# down) and nodeadm (any server); every other pod (monitoring) carries no
# site term either.
PRIMARY_SITE = "main"
SITE_KEY = "portcullis.io/site"
SITE_PINNED = {"postgres", "vault", "sessions", "hub", "domains", "keycloak", "forward-auth", "forward-auth-ext",
               "group-gate", "enroll", "mcp-gate", "wg", "lldap", "oneshot-hub", "lldap-schema"}
SITE_FREE = {"traefik", "frontdoor", "nodeadm"}


def node_terms(spec):
    """The required node affinity terms of a pod spec ([] without)."""
    na = (spec.get("affinity") or {}).get("nodeAffinity") or {}
    return (na.get("requiredDuringSchedulingIgnoredDuringExecution") or {}).get("nodeSelectorTerms") or []


def site_exprs(spec):
    """Every portcullis.io/site expression of a pod spec: its required and
    preferred node affinity terms and its nodeSelector."""
    out = [e for t in node_terms(spec) for e in t.get("matchExpressions", []) + t.get("matchFields", []) if e.get("key") == SITE_KEY]
    na = (spec.get("affinity") or {}).get("nodeAffinity") or {}
    for w in na.get("preferredDuringSchedulingIgnoredDuringExecution") or []:
        out += [e for e in w.get("preference", {}).get("matchExpressions", []) if e.get("key") == SITE_KEY]
    if SITE_KEY in (spec.get("nodeSelector") or {}):
        out.append({"key": SITE_KEY, "nodeSelector": spec["nodeSelector"][SITE_KEY]})
    return out


def site_pinned(spec):
    """True when every required term holds portcullis.io/site In [main]
    (and there is at least one term)."""
    want = {"key": SITE_KEY, "operator": "In", "values": [PRIMARY_SITE]}
    terms = node_terms(spec)
    return bool(terms) and all(want in t.get("matchExpressions", []) for t in terms)
