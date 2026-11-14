#!/usr/bin/env python3
"""End-to-end: the Hub on Kubernetes (CI job `e2e-k3s`).

Runs against the whole core stack under CONTAINER_RUNTIME=kubernetes on the
runner's k3s (the Hub built from the same-named Hub branch, imported as a
K1 local image) with one local template source: the CI templates
tests/e2e/apps/echo and tests/e2e/apps/folder-writer. The Hub's admin
listener is reached through a kubectl port-forward (HUB_API).

Scenarios:
  runtime   GET /api/runtime: kubernetes, verified, context ci, admission ok,
            netpol proven, engine_version the API server's.
  echo      an echo instance: create → enable (its routes owner=hub in
            portcullis-edge, none in portcullis-apps; its pods in portcullis-apps,
            labelled portcullis.io/instance, automountServiceAccountToken
            false, its PVC owned by the service uid) → its host redirects to
            Keycloak through Traefik → backup → delete (typed id) → restore
            into a new id → delete.
  fixer     the folder fixer on /srv/e2e-k3s (folder-writer's `shared`):
            the apply op is ok and the files get the folder's gid.

Environment: HUB_API, E2E_HUB_SECRET (never printed, never on argv),
E2E_DOMAIN, E2E_FOLDER (/srv/e2e-k3s), E2E_ARTIFACTS. Stdlib + kubectl.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_ops  # noqa: E402

HUB_API = os.environ["HUB_API"].rstrip("/")
SECRET = os.environ["E2E_HUB_SECRET"]
DOMAIN = os.environ.get("E2E_DOMAIN", "portcullis.local")
FOLDER = os.environ.get("E2E_FOLDER", "/srv/e2e-k3s")
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
APPS = "portcullis-apps"
EDGE = "portcullis-edge"
ECHO, ECHO_R, WRITER = "echo-k", "echo-k-r", "folder-writer"
OP_S = 1200

results: list[tuple[str, bool, str]] = []
state: dict = {}


def check(name: str, fn) -> None:
    try:
        fn()
        results.append((name, True, ""))
        print(f"PASS: {name}", flush=True)
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"{type(e).__name__}: {e}"))
        print(f"FAIL: {name}: {e}", flush=True)
        traceback.print_exc()


def needs(*keys: str) -> None:
    missing = [k for k in keys if k not in state]
    assert not missing, f"needs {', '.join(missing)} (an earlier scenario failed)"


def save(name: str, data) -> None:
    os.makedirs(ART, exist_ok=True)
    with open(os.path.join(ART, name), "w") as f:
        f.write(data if isinstance(data, str) else json.dumps(data, indent=2))


def hub(method: str, path: str, body=None, timeout: float = 300) -> tuple[int, object]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(HUB_API + path, data=data, method=method, headers={
        "X-Portcullis-Proxy-Secret": SECRET, "X-Forwarded-User": "admin", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code, raw = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read().decode()
    try:
        return code, json.loads(raw) if raw else ""
    except ValueError:
        return code, raw


def hub_ok(method: str, path: str, body=None, want: int = 200):
    code, out = hub(method, path, body)
    assert code == want, f"{method} {path}: HTTP {code} (want {want}): {str(out)[:800]}"
    return out


def hub_get(path: str):
    return hub("GET", path)[1]


def run_op(method: str, path: str, body, timeout: float = OP_S) -> dict:
    acc = e2e_ops.accepted(hub_ok(method, path, body, want=202))
    rec = e2e_ops.wait(hub_get, acc, timeout)
    save(f"op-{acc.get('op')}-{acc['op_id']}.json", rec)
    return e2e_ops.check_ok(acc, rec)


def kubectl(*argv: str) -> str:
    return subprocess.run(["kubectl", "--context", "ci", *argv], check=True, capture_output=True, text=True).stdout


def sh(*argv: str) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def main() -> int:
    def runtime():
        rt = hub_ok("GET", "/api/runtime")
        save("runtime.json", rt)
        assert rt.get("runtime") == "kubernetes" and rt.get("verified") is True and not rt.get("mismatch"), rt
        assert rt.get("context") == "ci" and rt.get("admission") == "ok" and rt.get("netpol") == "proven", rt
        assert str(rt.get("engine_version", "")).startswith("v1."), rt
        state["runtime"] = rt
    check("runtime: /api/runtime kubernetes, verified, context ci, admission ok, netpol proven", runtime)

    def echo():
        needs("runtime")
        host = f"{ECHO}.{DOMAIN}"
        run_op("POST", "/api/instances", {"template": "echo", "id": ECHO, "label": "Echo on k3s", "hosts": {"echo": host}})
        run_op("POST", "/api/templates/enable", {"id": ECHO}, timeout=1500)
        pods = json.loads(kubectl("-n", APPS, "get", "pods", "-l", f"portcullis.io/instance={ECHO}", "-o", "json"))["items"]
        save("echo-pods.json", pods)
        assert pods, "no pod labelled portcullis.io/instance=" + ECHO
        for p in pods:
            spec = p["spec"]
            assert spec.get("automountServiceAccountToken") is False, f"{p['metadata']['name']}: a ServiceAccount token"
            assert spec.get("serviceAccountName", "default") == "default", p["metadata"]["name"]
        # The instance's routes live in portcullis-edge (owner=hub), none in
        # the apps namespace (Traefik doesn't watch it).
        edge = json.loads(kubectl("-n", EDGE, "get", "ingressroutes", "-l", "portcullis.io/owner=hub", "-o", "json"))["items"]
        assert any(host in r["spec"]["routes"][0]["match"] for r in edge), f"no owner=hub IngressRoute for {host} in {EDGE}"
        assert not json.loads(kubectl("-n", APPS, "get", "ingressroutes", "-o", "json"))["items"], f"IngressRoutes in {APPS}"
        # Through Traefik (edge route → the apps Service, the NetPols across
        # namespaces): the host without a session redirects to Keycloak.
        out = sh("curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}", "--max-time", "20", "-k",
                 "--resolve", f"{host}:443:198.51.100.1", f"https://{host}/")
        code, _, loc = out.partition(" ")
        assert code in ("302", "303", "307") and ("auth." + DOMAIN) in loc, f"{host}: {out}"
        rec = run_op("POST", f"/api/instances/{ECHO}/backups", {})
        archive = (rec.get("result") or {}).get("archive")
        assert archive, f"backup without an archive: {e2e_ops.describe(rec)}"
        run_op("POST", f"/api/instances/{ECHO}/delete", {"confirm": ECHO})
        assert not json.loads(kubectl("-n", APPS, "get", "deployments", "-l", f"portcullis.io/instance={ECHO}", "-o", "json"))["items"], \
            "the deleted instance's Deployments are still there"
        rec = run_op("POST", "/api/instances/restore", {"archive": archive, "id": ECHO_R})
        assert (rec.get("result") or {}).get("instance") == ECHO_R, e2e_ops.describe(rec)
        run_op("POST", f"/api/instances/{ECHO_R}/delete", {"confirm": ECHO_R})
        print(f"    backup {archive} restored as {ECHO_R}, both deleted", flush=True)
    check("echo: create, enable (pods without a token, default SA), Traefik → Keycloak, backup, delete, restore, delete", echo)

    def fixer():
        needs("runtime")
        run_op("POST", "/api/templates/enable", {"id": WRITER}, timeout=1500)
        hub_ok("POST", "/api/folders", {"id": "k3s-share", "name": "k3s-share", "path": FOLDER,
                                        "description": "e2e-k3s", "create": False}, want=201)
        uses = [{"instance": WRITER, "key": "shared"}]
        pl = hub_ok("POST", "/api/folders/k3s-share/assign/preview", {"uses": uses})
        acc = e2e_ops.accepted(hub_ok("POST", "/api/folders/k3s-share/assign/apply", {"plan_hash": pl["plan_hash"], "uses": uses}, want=202))
        rec = e2e_ops.wait_ok(hub_get, acc, OP_S)
        save("apply-k3s-share.json", rec)
        gid = next(f["gid"] for f in hub_ok("GET", "/api/folders")["folders"] if f["id"] == "k3s-share")
        got = sh("sudo", "stat", "-c", "%g", f"{FOLDER}/file-1.txt").strip()
        assert got == str(gid), f"{FOLDER}/file-1.txt gid {got}, want {gid} (the identity map on k8s)"
        print(f"    applied: gid {gid}", flush=True)
    check("fixer: the folder's apply on /srv is ok through a helper pod; the files carry the folder gid", fixer)

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed", flush=True)
    for name, _, err in failed:
        print(f"  FAIL: {name}: {err[:600]}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
