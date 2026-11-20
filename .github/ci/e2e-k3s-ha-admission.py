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
${NOW+<n>m} to now + n minutes. Binding denials are skipped: the API server
never runs API-defined policies on admission policies or bindings (Hub
envtest TestAdmissionPolicyObjectsNotJudged).
  python3 .github/ci/e2e-k3s-ha-admission.py [<context>]   (default ci)
"""
import datetime
import json
import pathlib
import re
import subprocess
import sys
import urllib.parse

CTX = sys.argv[1] if len(sys.argv) > 1 else "ci"
ROOT = pathlib.Path(__file__).resolve().parents[2]
IDS = {"hub": "system:serviceaccount:portcullis:portcullis-hub", "intruder": "system:serviceaccount:portcullis:intruder",
       "nodeadm": "system:serviceaccount:portcullis-nodeadm:nodeadm"}
TEST_TRAEFIK = "docker.io/library/traefik:v3.7.0@sha256:" + "2" * 64
TEST_GEN = "0123456789abcdef"


def k(args, stdin=""):
    p = subprocess.run(["kubectl", "--context", CTX, *args], input=stdin, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


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
admitted = refused = skipped = 0
try:
    for v in vectors:
        if not v.get("ha"):
            continue
        if v["object"].get("kind") == "ValidatingAdmissionPolicyBinding" and v["want"] == "deny":
            skipped += 1
            continue
        raw = json.dumps(v["object"]).replace(TEST_TRAEFIK, params["traefikImage"]).replace(TEST_GEN, params["generation"])
        raw = re.sub(r"\$\{NOW\+([0-9]+)m\}", lambda m: (datetime.datetime.now(datetime.timezone.utc)
                     + datetime.timedelta(minutes=int(m.group(1)))).strftime("%Y-%m-%dT%H:%M:%SZ"), raw)
        reason = v["reason_contains"].replace(TEST_GEN, params["generation"])
        o = json.loads(raw)
        who = [] if v["as"] == "cli" else [f"--as={IDS[v['as']]}", "--as-group=system:masters"]
        if v.get("existing"):
            fail(f"{v['name']}: an existing object outside the skipped binding cases")
        if v.get("op") == "exec":
            md = o["metadata"]
            q = [("command", c) for c in o.get("command", [])] + [(f, "true") for f in ("stdin", "stdout", "stderr", "tty") if o.get(f)]
            if o.get("container"):
                q.append(("container", o["container"]))
            url = f"/api/v1/namespaces/{md['namespace']}/pods/{md['name']}/exec?" + urllib.parse.urlencode(q)
            rc, out = k([*who, "create", "--raw", url, "-f", "-"])
            ok = rc == 0 or ("NotFound" in out or "not found" in out) and "denied request" not in out
        else:
            rc, out = k([*who, "create", "--dry-run=server", "-f", "-"], json.dumps(o))
            ok = rc == 0
        if v["want"] == "allow":
            if not ok:
                fail(f"refused, want admitted: {v['name']}: {out.splitlines()[0][:400] if out else ''}")
            admitted += 1
        else:
            if ok or "with binding 'portcullis-" not in out or reason not in out:
                fail(f"want a denial with {reason!r} from a Portcullis binding: {v['name']}: {out[:400]}")
            refused += 1
finally:
    if created_sa:
        k(["-n", "portcullis-ingress", "delete", "serviceaccount", "traefik", "--ignore-not-found"])
print(f"PASS: HA admission vectors: {admitted} admitted, {refused} refused by their bindings, {skipped} binding denials skipped (no admission policy judges a binding)")
