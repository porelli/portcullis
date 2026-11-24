#!/usr/bin/env python3
"""End-to-end: the Hub's Usage page (contract §11.11) on a real engine.

Runs in CI after the stack is up (e2e-instances on Docker, the e2e-podman
leg on rootless Podman) against the Hub's admin listener, with the CI
template tests/e2e/apps/echo: web (no memory limit) and hold
(mem_limit 32m, pids_limit 32, network_mode none). The instance
E2E_USAGE_INSTANCE is created and enabled when it doesn't exist yet.

  python3 tests/e2e/e2e_usage.py live      the sampler (GET /api/usage …)
  python3 tests/e2e/e2e_usage.py storage   the storage measurer (op _usage)

live:
  usage_lists_echo         two sweeps: the instance's group, web's memory
                           with no limit, hold's 32 MiB limit and null
                           network rates (network_mode none).
  usage_cpu_second_sample  web's cpu_cores is a number once two samples exist.
  usage_core_group         the core group lists hub and traefik.
  usage_csv                export.csv?view=apps has the contract's header.
  usage_people_404         the people listener answers 404 (E2E_PEOPLE_API).
  usage_podman_nulls       (Podman) blk_read_bps is a number or null, never missing.
storage:
  measure_instance         the instance's data volume has alloc_bytes > 0 and
                           web's writable layer is listed.
  measure_conflict         a second start while one runs is 409.
  measure_all_core         the core list holds portcullis_hub_data; a disk
                           with total_bytes > 0.
  stop_between_targets     a Stop at once ends stopped (or ok: a fast run),
                           never with an error.
  audit_actor              usage.measure is audited with the admin's LLDAP username.
  no_helper_left           no io.portcullis.hub.helper container 30 s later.

Environment: HUB_API (http://<hub>:8888), E2E_HUB_SECRET (the proxy secret;
never printed, never on argv), E2E_HUB_USER (default admin), E2E_DOMAIN,
E2E_PEOPLE_API (optional: http://<hub>:8889), E2E_RUNTIME (docker | podman),
E2E_USAGE_INSTANCE (default echo-use), E2E_ARTIFACTS. Stdlib only; no
outside host is contacted.
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
import scenarios  # noqa: E402  (E2E_SCENARIOS: single-scenario reruns)

scenarios.always("setup")

HUB_API = os.environ["HUB_API"].rstrip("/")
SECRET = os.environ["E2E_HUB_SECRET"]
USER = os.environ.get("E2E_HUB_USER", "admin")
DOMAIN = os.environ.get("E2E_DOMAIN", "portcullis.local")
PEOPLE_API = os.environ.get("E2E_PEOPLE_API", "").rstrip("/")
RUNTIME = os.environ.get("E2E_RUNTIME", "docker")
INST = os.environ.get("E2E_USAGE_INSTANCE", "echo-use")
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
APPS_HEADER = ("server,instance,template,name,status,cpu_cores,mem_bytes,mem_limit_bytes,cpu_limit_cores,pids,pids_limit,"
               "net_rx_bps,net_tx_bps,blk_read_bps,blk_write_bps,partial,measured_at")

results: list[tuple[str, bool, str]] = []
state: dict = {}


def check(name: str, fn) -> None:
    if scenarios.skip(name):  # E2E_SCENARIOS (tests/e2e/scenarios.py)
        return
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


def call(base: str, method: str, path: str, body=None, timeout: float = 120) -> tuple[int, object]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers={
        "X-Portcullis-Proxy-Secret": SECRET, "X-Forwarded-User": USER, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code, raw = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read().decode()
    try:
        return code, json.loads(raw) if raw else ""
    except ValueError:
        return code, raw


def hub(method: str, path: str, body=None) -> tuple[int, object]:
    return call(HUB_API, method, path, body)


def hub_ok(method: str, path: str, body=None, want: int = 200):
    code, out = hub(method, path, body)
    assert code == want, f"{method} {path}: HTTP {code} (want {want}): {str(out)[:800]}"
    return out


def hub_get(path: str):
    return hub("GET", path)[1]


def group(view: dict, inst: str):
    return next((g for g in view.get("apps") or [] if g.get("instance") == inst), None)


def container(g: dict, service: str):
    return next((c for c in g.get("containers") or [] if c.get("service") == service), None)


def wait_for(what: str, fn, timeout: float, every: float = 3):
    deadline, last = time.time() + timeout, None
    while True:
        try:
            out = fn()
            if out:
                return out
        except AssertionError as e:
            last = e
        if time.time() > deadline:
            raise AssertionError(f"{what}: not within {timeout:.0f} s ({last})")
        time.sleep(every)


def setup() -> None:
    insts = hub_ok("GET", "/api/instances")
    me = next((i for i in insts if i.get("id") == INST), None)
    if me is None:
        acc = e2e_ops.accepted(hub_ok("POST", "/api/instances", {"template": "echo", "id": INST, "label": "Usage",
                                                                   "hosts": {"echo": f"{INST}.{DOMAIN}"}}, want=202))
        e2e_ops.wait_ok(hub_get, acc, 300)
        me = {"state": "created"}
    if me.get("state") != "enabled":
        acc = e2e_ops.accepted(hub_ok("POST", "/api/templates/enable", {"id": INST}, want=202))
        e2e_ops.wait_ok(hub_get, acc, 1500)
    state["setup"] = True


def live() -> None:
    check("setup: the echo instance exists and is enabled", setup)

    def lists_echo():
        needs("setup")

        def sampled():
            v = hub_ok("GET", "/api/usage")
            g = group(v, INST)
            assert g, f"no group {INST}: {[a.get('instance') for a in v.get('apps') or []]}"
            web, hold = container(g, "web"), container(g, "hold")
            assert web and hold, f"containers {[c.get('service') for c in g.get('containers') or []]}"
            assert isinstance(web["sample"].get("mem_bytes"), int) and web["sample"]["mem_bytes"] > 0, f"web sample {web['sample']}"
            return v, g, web, hold
        v, g, web, hold = wait_for("the echo group sampled", sampled, 90)
        save("usage-overview.json", v)
        assert v.get("interval_s") == 15 and v["engine"]["verified"] is True and v["engine"]["runtime"] == RUNTIME, \
            f"header {v.get('interval_s')} {v.get('engine')}"
        assert web["limits"]["mem_bytes"] == 0, f"web limits {web['limits']}"
        assert hold["limits"]["mem_bytes"] == 32 << 20 and hold["limits"]["pids"] == 32, f"hold limits {hold['limits']}"
        assert "net_rx_bps" in hold["sample"] and hold["sample"]["net_rx_bps"] is None, f"hold sample {hold['sample']}"
        state["lists"] = True
    check("usage_lists_echo: the group, web without a limit, hold's 32 MiB limit and null network", lists_echo)

    def cpu_second():
        needs("lists")

        def cpu():
            web = container(group(hub_ok("GET", "/api/usage"), INST), "web")
            c = web["sample"].get("cpu_cores")
            return isinstance(c, (int, float)) and c >= 0
        wait_for("web's cpu_cores", cpu, 60)
    check("usage_cpu_second_sample: cpu_cores is a number after the second sweep", cpu_second)

    def core_group():
        needs("lists")
        core = hub_ok("GET", "/api/usage")["core"]
        services = {c.get("service") for c in core.get("containers") or []}
        assert core.get("instance") == "core" and {"hub", "traefik"} <= services, f"core {core.get('instance')} {sorted(services)}"
    check("usage_core_group: the core group lists hub and traefik", core_group)

    def csv():
        needs("setup")
        code, out = hub("GET", "/api/usage/export.csv?view=apps")
        assert code == 200 and isinstance(out, str), f"HTTP {code}"
        assert out.splitlines()[0] == APPS_HEADER, f"header {out.splitlines()[0]!r}"
    check("usage_csv: export.csv?view=apps has the contract's header", csv)

    if PEOPLE_API:
        def people_404():
            code, _ = call(PEOPLE_API, "GET", "/api/usage")
            assert code == 404, f"people /api/usage: HTTP {code}"
        check("usage_people_404: the people listener has no usage routes", people_404)

    if RUNTIME == "podman":
        def podman_nulls():
            needs("lists")
            g = group(hub_ok("GET", "/api/usage"), INST)
            for c in g["containers"]:
                assert "blk_read_bps" in c["sample"], f"{c['service']}: blk_read_bps missing"
                v = c["sample"]["blk_read_bps"]
                assert v is None or isinstance(v, (int, float)), f"{c['service']}: blk_read_bps {v!r}"
        check("usage_podman_nulls: block IO is a number or null on Podman", podman_nulls)


def measure(body: dict) -> dict:
    return e2e_ops.accepted(hub_ok("POST", "/api/usage/storage/measure", body, want=202), op="usage_measure")


def storage() -> None:
    check("setup: the echo instance exists and is enabled", setup)

    def instance():
        needs("setup")
        acc = measure({"instance": INST})
        assert acc["poll"] == "/api/usage/storage/op", f"poll {acc['poll']}"
        rec = e2e_ops.wait_ok(hub_get, acc, 180)
        save("usage-measure-instance.json", rec)
        g = hub_ok("GET", f"/api/usage/instances/{INST}")
        save("usage-instance.json", g)
        items = (g.get("storage") or {}).get("items") or []
        vols = [i for i in items if i.get("kind") == "volume" and i.get("target", "").endswith("-data")]
        assert vols and isinstance(vols[0].get("alloc_bytes"), int) and vols[0]["alloc_bytes"] > 0, f"volumes {vols} (items {items})"
        layers = [i for i in items if i.get("kind") == "layer" and i.get("target", "").startswith("web.")]
        assert layers, f"no web layer: {items}"
        if RUNTIME != "podman":
            assert isinstance(layers[0].get("alloc_bytes"), int), f"web layer {layers[0]}"
        state["measured"] = True
    check("measure_instance: the data volume has alloc_bytes > 0, web's layer is listed", instance)

    def conflict():
        needs("measured")
        acc = measure({})
        code, out = hub("POST", "/api/usage/storage/measure", {})
        rec = e2e_ops.wait(hub_get, acc, 900)
        save("usage-measure-all.json", rec)
        assert code == 409 or rec.get("running") is False, f"second start: HTTP {code} {out}"
        if code != 409:
            # The first run was already over: a run that fast can't be raced.
            print("    the first run ended before the second start", flush=True)
        e2e_ops.check_ok(acc, rec)
        state["all"] = True
    check("measure_conflict: a second start while one runs is 409", conflict)

    def all_core():
        needs("all")
        v = hub_ok("GET", "/api/usage/storage")
        save("usage-storage.json", v)
        core = [i.get("target") for i in v.get("core") or []]
        assert "portcullis_hub_data" in core, f"core {core}"
        assert any((d.get("total_bytes") or 0) > 0 for d in v.get("disks") or []), f"disks {v.get('disks')}"
    check("measure_all_core: core volumes and a disk", all_core)

    def stop():
        needs("all")
        acc = measure({})
        code, out = hub("POST", "/api/usage/storage/op/stop", {"op_id": acc["op_id"]})
        assert code in (202, 409), f"stop: HTTP {code} {out}"
        rec = e2e_ops.wait(hub_get, acc, 900)
        save("usage-measure-stop.json", rec)
        stopped = rec.get("ok") is False and rec.get("stopped_by") == USER and not rec.get("error")
        assert stopped or rec.get("ok") is True, f"record {e2e_ops.describe(rec)}"
    check("stop_between_targets: a Stop ends the run stopped, never with an error", stop)

    def audit():
        needs("measured")
        es = hub_ok("GET", "/api/directory/audit")
        mine = [e for e in es if e.get("action") == "usage.measure"]
        assert mine and all(e.get("actor") == USER for e in mine), f"usage.measure entries {mine[:3]}"
        assert any(e.get("detail", "").endswith(f"scope={INST}") for e in mine), f"no scope={INST}: {mine[:3]}"
    check("audit_actor: usage.measure carries the admin's LLDAP username", audit)

    def no_helper():
        needs("measured")
        time.sleep(30)
        out = subprocess.run(["docker", "ps", "-aq", "--filter", "label=io.portcullis.hub.helper"], capture_output=True, text=True, check=True).stdout.strip()
        assert out == "", f"helpers left: {out}"
    check("no_helper_left: no Hub helper container remains", no_helper)


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "live":
        live()
    elif mode == "storage":
        storage()
    else:
        print("usage: e2e_usage.py live|storage", file=sys.stderr)
        return 2
    failed = [r for r in results if not r[1]]
    print(f"{len(results) - len(failed)}/{len(results)} usage checks passed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
