#!/usr/bin/env python3
"""End-to-end: the Hub on rootless Podman (CI job `e2e-podman`).

Runs against the whole core stack under CONTAINER_RUNTIME=podman (the
runner user is the operator, the Hub built from the same-named Hub branch)
with one local template source: the CI templates tests/e2e/apps/echo and
tests/e2e/apps/folder-writer and the templates repo's scrutiny. The Hub's
listener is reached on a CI-only loopback publish (rootless container
addresses live in the rootless network namespace, not on the host).

Scenarios:
  runtime      GET /api/runtime: podman, verified, rootless, uid_map[0].host
               is this user (container root = the operator), port start ≤ 80.
  echo         an echo instance: create → enable → (forward-auth: the app
               host answers a redirect that ends at Keycloak's
               auth.<domain>, reached through host-gateway) → backup →
               disable → restore into a new id (op polling: e2e_ops).
  fixer_ok     folder pod-ok on the operator-owned /srv/e2e-pod/ok assigned
               to folder-writer's `shared`: the apply op is ok and the files
               get the folder's gid (a subgid on the host).
  fixer_root   folder pod-root on /srv/e2e-pod/rooted, whose child
               root-owned/ belongs to host root: the apply is refused (409,
               or a failed op record) with "is owned by a host account
               outside Portcullis' id range" and the child's path.
  scrutiny     creating scrutiny answers 409 naming SYS_RAWIO (raw disk
               access can't work without host root).

Environment: HUB_API (http://127.0.0.1:<port>), E2E_HUB_SECRET (the proxy
secret; never printed, never on argv), E2E_POD (/srv/e2e-pod), E2E_DOMAIN,
E2E_ARTIFACTS. Stdlib only.
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
import e2e_ops  # noqa: E402  (the op record poll, contract §11.7)

HUB_API = os.environ["HUB_API"].rstrip("/")
SECRET = os.environ["E2E_HUB_SECRET"]
POD = os.environ.get("E2E_POD", "/srv/e2e-pod")
DOMAIN = os.environ.get("E2E_DOMAIN", "portcullis.local")
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
UNMAPPED = "is owned by a host account outside Portcullis' id range"
ECHO, ECHO_R = "echo-pod", "echo-pod-r"
WRITER, WRITER_ROOT = "folder-writer", "fw-root"
OP_S = 900

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
    """Fail closed: a scenario built on an earlier one fails when that one did."""
    missing = [k for k in keys if k not in state]
    assert not missing, f"needs {', '.join(missing)} (an earlier scenario failed)"


def save(name: str, data) -> None:
    os.makedirs(ART, exist_ok=True)
    with open(os.path.join(ART, name), "w") as f:
        f.write(data if isinstance(data, str) else json.dumps(data, indent=2))


def hub(method: str, path: str, body=None, timeout: float = 300) -> tuple[int, object]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(HUB_API + path, data=data, method=method, headers={
        "X-Portcullis-Proxy-Secret": SECRET, "X-Forwarded-User": "admin",
        "Content-Type": "application/json"})
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
    """A 202 operation polled (e2e_ops) until it ended; it must be ok."""
    acc = e2e_ops.accepted(hub_ok(method, path, body, want=202))
    rec = e2e_ops.wait(hub_get, acc, timeout)
    save(f"op-{acc.get('op')}-{acc['op_id']}.json", rec)
    return e2e_ops.check_ok(acc, rec)


def sh(*argv: str) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def curl_status(host: str, url: str) -> tuple[str, str]:
    """(HTTP status, redirect target) of one GET through Traefik on the
    host's published :443 (the internal CA's wildcard certificate)."""
    out = sh("curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}", "--max-time", "20",
             "--cacert", "certs/ca-chain.crt", "--resolve", f"{host}:443:127.0.0.1", url)
    code, _, loc = out.partition(" ")
    return code, loc


def main() -> int:
    def runtime():
        rt = hub_ok("GET", "/api/runtime")
        save("runtime.json", rt)
        assert rt.get("runtime") == "podman" and rt.get("verified") is True and rt.get("rootless") is True, rt
        assert not rt.get("mismatch"), rt
        um = rt.get("uid_map") or []
        assert um and um[0].get("host") == os.getuid(), f"uid_map[0] {um[:1]}, want host {os.getuid()} (the operator)"
        ps = rt.get("unprivileged_port_start")
        assert isinstance(ps, int) and ps <= 80, f"unprivileged_port_start {ps!r}"
        print(f"    {rt.get('engine')} {rt.get('engine_version')}, uid_map {um}, ports ≥ {ps}", flush=True)
        state["runtime"] = rt
    check("runtime: /api/runtime podman, verified, rootless, uid_map[0].host = this user, ports ≥ ≤ 80", runtime)

    def echo():
        needs("runtime")
        host = f"{ECHO}.{DOMAIN}"
        run_op("POST", "/api/instances", {"template": "echo", "id": ECHO, "label": "Echo on Podman", "hosts": {"echo": host}})
        run_op("POST", "/api/templates/enable", {"id": ECHO}, timeout=1500)
        state["echo_enabled"] = True
        # Forward-auth (oauth2-proxy) reaches auth.<domain> through
        # host-gateway: an app host without a session is sent, redirect by
        # redirect, to Keycloak's authorization endpoint.
        url, seen = f"https://{host}/", []
        for _ in range(4):
            h = url.split("/")[2]
            deadline = time.time() + 90
            while True:
                code, loc = curl_status(h, url)
                if code in ("301", "302", "303", "307") or time.time() > deadline:
                    break
                time.sleep(3)
            seen.append(f"{code} {url}")
            assert code in ("301", "302", "303", "307") and loc, f"no redirect: {seen}"
            url = loc
            if url.startswith(f"https://auth.{DOMAIN}/realms/portcullis/protocol/openid-connect/auth"):
                break
        assert url.startswith(f"https://auth.{DOMAIN}/realms/portcullis/protocol/openid-connect/auth"), \
            f"the app host's redirects never reached Keycloak: {seen} → {url}"
        print("    " + " → ".join(seen), flush=True)
        rec = run_op("POST", f"/api/instances/{ECHO}/backups", {})
        archive = (rec.get("result") or {}).get("archive")
        assert archive, f"backup without an archive: {e2e_ops.describe(rec)}"
        run_op("POST", "/api/templates/disable", {"id": ECHO})
        rec = run_op("POST", "/api/instances/restore", {"archive": archive, "id": ECHO_R})
        assert (rec.get("result") or {}).get("instance") == ECHO_R, e2e_ops.describe(rec)
        listed = hub_ok("GET", "/api/instances")
        assert any(i.get("id") == ECHO_R and i.get("template") == "echo" for i in listed), str(listed)[:600]
        print(f"    backup {archive} restored as {ECHO_R}", flush=True)
    check("echo: create, enable (forward-auth reaches Keycloak through host-gateway), backup, disable, "
          "restore into a new id", echo)

    def assign(folder: str, path: str, instance: str) -> tuple[int, object]:
        """Create the folder, preview its use by `instance`'s shared option,
        then send the apply (its HTTP status and body)."""
        hub_ok("POST", "/api/folders", {"id": folder, "name": folder, "path": path,
                                        "description": "e2e-podman", "create": False}, want=201)
        uses = [{"instance": instance, "key": "shared"}]
        code, pl = hub("POST", f"/api/folders/{folder}/assign/preview", {"uses": uses})
        save(f"preview-{folder}.json", pl)
        if code != 200:
            return code, pl
        return hub("POST", f"/api/folders/{folder}/assign/apply", {"plan_hash": pl["plan_hash"], "uses": uses})

    def fixer_ok():
        needs("runtime")
        run_op("POST", "/api/templates/enable", {"id": WRITER}, timeout=1500)
        code, out = assign("pod-ok", f"{POD}/ok", WRITER)
        assert code == 202, f"apply: HTTP {code}: {str(out)[:800]}"
        acc = e2e_ops.accepted(out)
        rec = e2e_ops.wait_ok(hub_get, acc, OP_S)
        save("apply-pod-ok.json", rec)
        gid = next(f["gid"] for f in hub_ok("GET", "/api/folders")["folders"] if f["id"] == "pod-ok")
        host_gid = None
        for r in state["runtime"].get("gid_map") or []:
            if r["container"] <= gid < r["container"] + r["size"]:
                host_gid = r["host"] + gid - r["container"]
        assert host_gid is not None, f"gid {gid} outside the gid map {state['runtime'].get('gid_map')}"
        got = sh("stat", "-c", "%g", f"{POD}/ok/file-1.txt").strip()
        assert got == str(host_gid), f"{POD}/ok/file-1.txt host gid {got}, want {host_gid} (container gid {gid})"
        print(f"    applied: container gid {gid} = host gid {host_gid}", flush=True)
    check("fixer_ok: the operator-owned folder's apply is ok; its files carry the folder gid (a subgid on the host)",
          fixer_ok)

    def fixer_root():
        needs("runtime")
        run_op("POST", "/api/instances", {"template": "folder-writer", "id": WRITER_ROOT, "label": "Writer (root child)",
                                          "hosts": {"folder-writer": f"{WRITER_ROOT}.{DOMAIN}"}})
        code, out = assign("pod-root", f"{POD}/rooted", WRITER_ROOT)
        text = json.dumps(out) if not isinstance(out, str) else out
        if code == 202:
            rec = e2e_ops.wait(hub_get, e2e_ops.accepted(out), OP_S)
            save("apply-pod-root.json", rec)
            assert rec.get("ok") is not True, f"the apply over a root-owned child succeeded: {e2e_ops.describe(rec)}"
            text = json.dumps(rec)
        else:
            assert code == 409, f"apply over a root-owned child: HTTP {code} (want 409): {text[:800]}"
        assert UNMAPPED in text and "root-owned" in text, f"the refusal doesn't name the child: {text[:1200]}"
        print(f"    refused ({code}): {text[:300]}", flush=True)
    check("fixer_root: a root-owned child is refused per path (owned by a host account outside Portcullis' id range)",
          fixer_root)

    def scrutiny():
        code, out = hub("POST", "/api/instances", {"template": "scrutiny", "id": "scrutiny", "label": "Scrutiny"})
        text = out if isinstance(out, str) else json.dumps(out)
        save("scrutiny.txt", f"{code} {text}")
        assert code == 409 and "SYS_RAWIO" in text, f"scrutiny: HTTP {code}: {text[:800]}"
        print(f"    {text[:300]}", flush=True)
    check("scrutiny: creating it answers 409 naming SYS_RAWIO", scrutiny)

    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed", flush=True)
    for name, _, err in failed:
        print(f"  FAIL: {name}: {err[:600]}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
