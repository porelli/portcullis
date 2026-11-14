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
# Compose services with no Kubernetes form (the Roles replace them).
ABSENT = {"socket-proxy-traefik", "socket-proxy-hub"}
# Compose networks with no Kubernetes form.
ABSENT_NETS = {"socket-proxy-traefik", "socket-proxy-hub"}
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


def by_kind(docs, kind):
    return [d for d in docs if d.get("kind") == kind]


def deployments(docs):
    return {d["metadata"]["name"]: d for d in by_kind(docs, "Deployment")}


def pod_specs(docs):
    """(name, namespace, labels, pod spec, annotations) of every pod the chart renders."""
    out = []
    for d in docs:
        if d.get("kind") == "Deployment":
            t = d["spec"]["template"]
            out.append((d["metadata"]["name"], d["metadata"]["namespace"], t["metadata"].get("labels", {}), t["spec"], t["metadata"].get("annotations", {})))
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
