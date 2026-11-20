#!/usr/bin/env python3
"""e2e-k3s "HA admission vectors" (contract §6, NEW HA; plan Task 18): every
case of tests/admission_vectors.json tagged "ha" (a byte copy of the Hub's
internal/runtime/kube/testdata/admission_vectors.json) against the live
policies, server dry-run (an exec can't be dry-run: no vector names a pod
that exists, and admission answers before the pod is looked up, so past
admission the answer is NotFound):
  hub / intruder / nodeadm  kubectl --as=<ServiceAccount> --as-group=system:masters
                            (RBAC lets every shape reach admission)
  cli                       the context's own identity (params cliUsername)
A denial must come from a Portcullis binding and carry the vector's reason.
The vectors' test values are mapped to the live params: the Traefik image
to traefikImage, the test generation 0123456789abcdef to the live one,
${NOW+<n>m} to now + n minutes. An op update / delete judges its existing
object: fetched when it exists (and then never deleted: k3s's own
kube-system Secrets; the judged delete is a dry run), else created as the
CLI first (a Pod never scheduled, owned by the live DaemonSet traefik or
one made for the run) and deleted afterwards; a subresource is sent as one.
A case with "params" (only a create of an apps NetworkPolicy, Task 19
review C1: the HA `traefik` peer) is judged under the live params with those
keys replaced: its own ConfigMap portcullis-admission-params-e2e-<n> and a
binding portcullis-apps-guard-netpol-e2e-<n> of portcullis-apps-netpol on a
namespace portcullis-apps-e2e-<n>, where the object is sent (the live apps
bindings don't select it); all three are deleted afterwards. Every vector
prints PASS or FAIL; the run fails at the end when any did.
  python3 .github/ci/e2e-k3s-ha-admission.py [<context>]   (default ci)
"""
import datetime
import json
import pathlib
import re
import subprocess
import sys
import time
import time
import urllib.parse

CTX = sys.argv[1] if len(sys.argv) > 1 else "ci"
ROOT = pathlib.Path(__file__).resolve().parents[2]
IDS = {"hub": "system:serviceaccount:portcullis:portcullis-hub", "intruder": "system:serviceaccount:portcullis:intruder",
       "nodeadm": "system:serviceaccount:portcullis-nodeadm:nodeadm",
       "daemonset-controller": "system:serviceaccount:kube-system:daemon-set-controller"}
TEST_TRAEFIK = "docker.io/library/traefik:v3.7.0@sha256:" + "2" * 64
TEST_GEN = "0123456789abcdef"


def k(args, stdin=""):
    p = subprocess.run(["kubectl", "--context", CTX, *args], input=stdin, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def kjson(args):
    """kubectl … -o json: (the object, None) or (None, why) — stdout only (a
    warning on stderr never breaks the parse)."""
    p = subprocess.run(["kubectl", "--context", CTX, *args, "-o", "json"], capture_output=True, text=True)
    if p.returncode != 0:
        return None, (p.stderr or p.stdout).strip()[:300]
    try:
        return json.loads(p.stdout), None
    except ValueError:
        return None, f"not JSON: {p.stdout[:120]!r} {p.stderr[:200]!r}"


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


rc, out = k(["get", "validatingadmissionpolicybinding", "-l", "portcullis.io/binding=portcullis-apps-guard-pods", "-o", "json"])
if rc != 0:
    fail(f"can't read the bindings: {out[:300]}")
ref = json.loads(out)["items"][0]["spec"]["paramRef"]
rc, out = k(["-n", ref["namespace"], "get", "configmap", ref["name"], "-o", "json"])
if rc != 0:
    fail(f"can't read the params {ref['name']}: {out[:300]}")
params = json.loads(out)["data"]
for key in ("traefikImage", "generation", "nodeadmServiceAccount"):
    if not params.get(key):
        fail(f"the live params have no {key}")
# Traefik's ServiceAccount (the pods name it; the ServiceAccount admission
# plugin refuses a pod naming a missing one).
created_sa = k(["-n", "portcullis-ingress", "get", "serviceaccount", "traefik"])[0] != 0
if created_sa and k(["-n", "portcullis-ingress", "create", "serviceaccount", "traefik"])[0] != 0:
    fail("can't create the ServiceAccount portcullis-ingress/traefik")

vectors = json.loads((ROOT / "tests" / "admission_vectors.json").read_text())
NEVER = {"portcullis.io/e2e-never": "true"}  # no node matches: nothing runs
results = []  # (name, ok, why)
override_sets = []  # each distinct "params" override (sorted JSON); its index = <n>


def override_ns(over):
    """The namespace judged under the live params with <over> (made once:
    the namespace, the params ConfigMap, the netpol binding)."""
    key = json.dumps(over, sort_keys=True)
    if key in override_sets:
        return f"portcullis-apps-e2e-{override_sets.index(key)}"
    n = len(override_sets)
    override_sets.append(key)
    ns, cm, b = f"portcullis-apps-e2e-{n}", f"portcullis-admission-params-e2e-{n}", f"portcullis-apps-guard-netpol-e2e-{n}"
    objs = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}},
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": cm, "namespace": ref["namespace"]}, "data": dict(params, **over)},
            {"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingAdmissionPolicyBinding", "metadata": {"name": b},
             "spec": {"policyName": "portcullis-apps-netpol", "validationActions": ["Deny"],
                      "paramRef": {"name": cm, "namespace": ref["namespace"], "parameterNotFoundAction": "Deny"},
                      "matchResources": {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}}}}}]
    for o in objs:
        rc, out = k(["create", "-f", "-"], json.dumps(o))
        if rc != 0:
            raise RuntimeError(f"can't create {o['kind']} {o['metadata']['name']}: {out[:300]}")
    # A new binding takes effect asynchronously: wait until a shape every
    # params refuse (an ingress peer from the whole internet) is refused by it.
    probe = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
             "metadata": {"name": "e2e-wait", "namespace": ns, "labels": {"portcullis.io/instance": "app"}},
             "spec": {"podSelector": {"matchLabels": {"portcullis.io/instance": "app", "portcullis.io/service": "web"}},
                      "policyTypes": ["Ingress"], "ingress": [{"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}]}}
    for _ in range(60):
        rc, out = k([f"--as={IDS['hub']}", "--as-group=system:masters", "create", "--dry-run=server", "-f", "-"], json.dumps(probe))
        if rc != 0 and f"binding '{b}'" in out:
            return ns
        time.sleep(1)
    raise RuntimeError(f"the binding {b} never took effect")


def drop_overrides():
    for n in range(len(override_sets)):
        k(["delete", "validatingadmissionpolicybinding", f"portcullis-apps-guard-netpol-e2e-{n}", "--ignore-not-found"])
        k(["-n", ref["namespace"], "delete", "configmap", f"portcullis-admission-params-e2e-{n}", "--ignore-not-found"])
        k(["delete", "namespace", f"portcullis-apps-e2e-{n}", "--ignore-not-found", "--wait=false"])


def owner_daemonset():
    """The DaemonSet traefik's uid for an existing Pod's owner reference (the
    garbage collector deletes a pod whose owner doesn't exist): the live one,
    else one created for this run (Traefik's shape, never scheduled)."""
    ds, _ = kjson(["-n", "portcullis-ingress", "get", "daemonset", "traefik"])
    if ds:
        return ds["metadata"]["uid"], False
    base = next(v["object"] for v in vectors if v.get("ha") and v["object"].get("kind") == "DaemonSet" and v["want"] == "allow")
    d = json.loads(json.dumps(base).replace(TEST_TRAEFIK, params["traefikImage"]))
    d["spec"]["template"]["spec"]["nodeSelector"] = NEVER
    rc, out = k(["create", "-f", "-"], json.dumps(d))
    if rc != 0:
        raise RuntimeError(f"can't create the DaemonSet portcullis-ingress/traefik for the existing pods: {out[:300]}")
    ds, why = kjson(["-n", "portcullis-ingress", "get", "daemonset", "traefik"])
    if not ds:
        raise RuntimeError(f"the DaemonSet traefik vanished: {why}")
    return ds["metadata"]["uid"], True


def run(v, owner):
    """One vector: (ok, output) — ok = admitted (past admission)."""
    raw = json.dumps(v["object"]).replace(TEST_TRAEFIK, params["traefikImage"]).replace(TEST_GEN, params["generation"])
    raw = re.sub(r"\$\{NOW\+([0-9]+)m\}", lambda m: (datetime.datetime.now(datetime.timezone.utc)
                 + datetime.timedelta(minutes=int(m.group(1)))).strftime("%Y-%m-%dT%H:%M:%SZ"), raw)
    o = json.loads(raw)
    if v.get("params"):
        if o.get("kind") != "NetworkPolicy" or o["metadata"].get("namespace") != "portcullis-apps" or v.get("existing") or v.get("op"):
            return None, "a params case must be a create of an apps NetworkPolicy"
        o["metadata"]["namespace"] = override_ns(v["params"])
    if v["as"] == "cli":
        who = []
    elif v["as"] == "node":
        # A kubelet (R-NODELABELS): its own Node's name, group system:nodes
        # (what portcullis-node-labels matches; NodeRestriction too);
        # system:masters only gets RBAC out of the way.
        who = [f"--as=system:node:{o['metadata']['name']}", "--as-group=system:nodes", "--as-group=system:authenticated", "--as-group=system:masters"]
    else:
        who = [f"--as={IDS[v['as']]}", "--as-group=system:masters"]
    if v.get("op") in ("exec", "attach", "portforward"):
        md = o["metadata"]
        q = [("command", c) for c in o.get("command", [])] + [(f, "true") for f in ("stdin", "stdout", "stderr", "tty") if o.get(f)]
        q += [("ports", str(p)) for p in o.get("ports", [])]
        if o.get("container"):
            q.append(("container", o["container"]))
        url = f"/api/v1/namespaces/{md['namespace']}/pods/{md['name']}/{v['op']}?" + urllib.parse.urlencode(q)
        rc, out = k([*who, "create", "--raw", url, "-f", "-"])
        return rc == 0 or (("NotFound" in out or "not found" in out) and "denied request" not in out), out
    if not v.get("existing"):
        rc, out = k([*who, "create", "--dry-run=server", "-f", "-"], json.dumps(o))
        # AlreadyExists comes after admission (a live DaemonSet traefik).
        return rc == 0 or ("AlreadyExists" in out and "denied request" not in out), out
    # An update / delete of an existing object: created (as the CLI) when
    # missing, judged, then deleted.
    ex = json.loads(json.dumps(v["existing"]).replace(TEST_TRAEFIK, params["traefikImage"]))
    md = ex["metadata"]
    kind = ex["kind"].lower()
    nsa = ["-n", md["namespace"]] if md.get("namespace") else []  # a Node has none
    if ex["kind"] == "Pod":
        for x in (ex, o):
            x["spec"]["nodeSelector"] = NEVER
            for r in x["metadata"].get("ownerReferences", []):
                if r.get("kind") == "DaemonSet" and r.get("name") == "traefik":
                    r["uid"] = owner()
    cur, _ = kjson([*nsa, "get", kind, md["name"]])
    made = cur is None  # a live object (k3s's own Secrets) is never deleted
    if made:
        rc, out = k(["create", "-f", "-"], json.dumps(ex))
        if rc != 0:
            return None, f"creating the existing object: {out[:300]}"
        cur, why = kjson([*nsa, "get", kind, md["name"]])
        if cur is None:
            return None, f"the existing object is gone after its create: {why}"
    try:
        if v.get("op") == "delete":
            rc, out = k([*who, *nsa, "delete", kind, md["name"], "--dry-run=server"])
            return rc == 0, out
        for _ in range(15):  # a controller's own write in between: fetch again
            if ex["kind"] == "Node":
                # The live Node with only the vector's label change (the node
                # lifecycle controller's taints and status stay: NodeRestriction
                # refuses a kubelet changing taints before any policy).
                gone = set(ex["metadata"].get("labels", {})) - set(o["metadata"].get("labels", {}))
                labels = {kk: vv for kk, vv in cur["metadata"].get("labels", {}).items() if kk not in gone}
                labels.update(o["metadata"].get("labels", {}))
                o = json.loads(json.dumps(cur))
                o["metadata"]["labels"] = labels
            o["metadata"]["resourceVersion"] = cur["metadata"]["resourceVersion"]
            sub = [f"--subresource={v['subresource']}"] if v.get("subresource") else []
            rc, out = k([*who, "replace", "--dry-run=server", *sub, "-f", "-"], json.dumps(o))
            # A fresh Node gets the lifecycle controller's taints: until they
            # settle the copy is stale ("not allowed to modify taints").
            if "the object has been modified" not in out and "not allowed to modify taints" not in out:
                return rc == 0, out
            time.sleep(2)
            cur, why = kjson([*nsa, "get", kind, md["name"]])
            if cur is None:
                return None, f"the existing object is gone: {why}"
        return rc == 0, out
    finally:
        if made:
            k([*nsa, "delete", kind, md["name"], "--wait=true", "--timeout=60s", "--ignore-not-found"])
        drop_made_ds()


owner_uid = []
made_ds = []


def owner():
    if not owner_uid:
        uid, made = owner_daemonset()
        owner_uid.append(uid)
        made_ds.append(made)
    return owner_uid[0]


def drop_made_ds():
    """The DaemonSet made for an existing pod goes with it."""
    if made_ds and made_ds[0]:
        k(["-n", "portcullis-ingress", "delete", "daemonset", "traefik", "--wait=true", "--timeout=60s", "--ignore-not-found"])
    owner_uid.clear()
    made_ds.clear()


try:
    for v in vectors:
        if not v.get("ha"):
            continue
        reason = v["reason_contains"].replace(TEST_GEN, params["generation"])
        try:
            ok, out = run(v, owner)
        except Exception as e:  # one broken case never hides the others
            ok, out = None, f"{type(e).__name__}: {e}"
        first = out.splitlines()[0][:300] if out else ""
        if ok is None:
            results.append((v["name"], False, f"error: {first}"))
        elif v["want"] == "allow":
            results.append((v["name"], ok, "" if ok else f"refused, want admitted: {first}"))
        else:
            good = not ok and "with binding 'portcullis-" in out and reason in out
            results.append((v["name"], good, "" if good else f"want a denial with {reason!r} from a Portcullis binding, got: {out[:300]}"))
        name, good, why = results[-1]
        print(f"{'PASS' if good else 'FAIL'}: {name}{'' if good else ': ' + why}", flush=True)
finally:
    drop_made_ds()
    drop_overrides()
    if created_sa:
        k(["-n", "portcullis-ingress", "delete", "serviceaccount", "traefik", "--ignore-not-found"])
bad = [r for r in results if not r[1]]
admitted = sum(1 for r, v in zip(results, [v for v in vectors if v.get("ha")]) if r[1] and v["want"] == "allow")
print(f"{'FAIL' if bad else 'PASS'}: HA admission vectors: {len(results) - len(bad)} of {len(results)} as wanted "
      f"({admitted} admitted, {len(results) - len(bad) - admitted} refused by their bindings){f', {len(bad)} failed' if bad else ''}")
sys.exit(1 if bad else 0)
