#!/usr/bin/env python3
"""End-to-end: high availability on the real test VMs (CI job `e2e-ha-vm`,
plan Task 33 part B, D9; workflow_dispatch -f runner=builder only). The
four D9 VMs are pc-ha-* (three servers at site main, one agent at site
edge); .github/ci/e2e-ha-vm-setup.sh resets, prepares and installs them
every run, then this runs the physical drills the k3d job can't: real
partitions, power loss, disk failures, a rolling upgrade and the agent-
token revoke/restart proof.

The scenarios run on the CI runner (a container on the builder; never a
node): kubectl reaches the cluster over an SSH tunnel to a surviving
server's API (retarget_api picks a healthy one), and node faults are the
harness's host side (tests/e2e/ha/vm-host.sh, `e2e-ha-host`, installed by
setup.sh) over SSH to each VM: a real partition (every packet but SSH
dropped both ways, so the node self-fences through softdog), a power loss
(sysrq reboot, the node held down by a flag until `light`), a dead disk
(device-mapper `error`), a full disk, and the public-ingress / mesh-port
cuts of the site scenarios. SSH (port 22) stays up throughout so the
harness keeps its reach; the node's own view is still a total loss (k3s'
API, etcd and the mesh are all gone).

    e2e_ha_vm.py          every scenario

Scenarios (brief Task 33):
  ha_vm_partition         the minority self-fences within T_fence; a writer
                          on it fails; a test app's data checksums equal the
                          majority's afterwards.
  ha_vm_power_off         a node powered off: its stateful app runs elsewhere
                          within 4 min.
  ha_vm_disk_kill         a storage node's Longhorn disk killed: its volumes
                          rebuild on the others, the data intact.
  ha_vm_disk_full         a storage node's Longhorn disk filled: Longhorn
                          reports it, the volumes stay healthy on the others.
  ha_vm_lose_small        the third server (the arm64 / small third voter
                          here: vm3) lost: quorum holds (2/3), sign-in and
                          the stateful apps keep working, it returns.
  ha_vm_rolling_upgrade   a rolling restart of Keycloak and the gates under
                          the sign-in loop: at most 5 of 300 fail.
  ha_vm_site_uplink_down  vm4's public 443 dropped (its mesh stays): its
                          address leaves the set, main keeps serving; then
                          main's ingress 443 dropped: those go and vm4 serves
                          sign-in through Traefik → main over pcmesh.
  ha_vm_site_down         vm4 powered off: quorum holds (servers at main),
                          edge's address removed but never the last.
  ha_vm_nat_relay         vm2's inbound mesh port (UDP 51830) closed to the
                          other sites: vm2 ↔ vm4 keeps working through vm1,
                          and sign-in is unaffected.
  ha_vm_revoke_restarts   the agent-token fix (2026-11-22): revoke the agent
                          then a server; after each, every surviving server
                          restarts (alone, together, a reboot) and comes back
                          healthy, the credential files agree, the old token
                          401s and the new 200s, the revoked node can't
                          return, a survivor restarts on its identity and a
                          fresh node joins.

Carries (33a → 33b):
  ha_vm_pebble_issue_sni  the front door orders <d>/*.<d> from Pebble and
                          every ingress node serves it by SNI.
  ha_vm_cert_renew_leader_move  the front door's certificate renewed across a
                          Lease move (Pebble's short validity).
  ha_vm_same_site_reach   same-site probes never count; the cross-site
                          probers (vm4 ↔ main) do.
  ha_vm_etcd_remove_member  a cooperative server removal takes its etcd
                          member out (nodeadm, a nodeagent op).
  ha_vm_interrupted_removal  a server removal interrupted by a restart
                          resumes and finishes cleanly.
  ha_vm_front_door_node   (33a N1) the front door's own node cut: a new front
                          door takes the Lease, then the address is removed.
  ha_vm_front_door_nodeadm_one_node  (33a N1) the front door and nodeadm on
                          one node, that node cut.

Environment: E2E_HA_VM_DIR (the SSH config, the inventory), E2E_DOMAIN,
E2E_ARTIFACTS. Secrets never reach argv or the log.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import scenarios  # noqa: E402

D = os.environ["E2E_HA_VM_DIR"]
INV = json.load(open(os.path.join(D, "inventory.json")))
DOMAIN = INV["domain"]
os.environ.setdefault("E2E_DOMAIN", DOMAIN)
os.environ.setdefault("E2E_HA_CONTEXT", "portcullis")
LAN_CIDR = INV["lan_cidr"]
NODE_VM = {v["node"]: v["vm"] for v in INV["vms"]}
VM_NODE = {v["vm"]: v["node"] for v in INV["vms"]}
VMS = {v["vm"]: v for v in INV["vms"]}
SERVERS = [v["node"] for v in INV["vms"] if v["role"] in ("first", "server")]
EDGE_VM = next(v["vm"] for v in INV["vms"] if v["role"] == "agent")
MESH = {"vm1": "10.215.0.1", "vm2": "10.215.0.2", "vm3": "10.215.0.3", "vm4": "10.215.0.4"}

SSH = ["ssh", "-F", os.path.join(D, "ssh_config")]


REDACT = [(re.compile(r"(/invite/)[A-Za-z0-9_-]+"), r"\1<redacted>"), (re.compile(r"pcj[0-9]\.[A-Za-z0-9_-]{16,}"), "<join code>")]


def redact(text: str) -> str:
    """Setup links and join codes out of anything printed or raised."""
    for rx, to in REDACT:
        text = rx.sub(to, text)
    return text


def sh(*argv: str, inp: str | None = None, timeout: float = 120, check: bool = True) -> str:
    r = subprocess.run(list(argv), input=inp, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise AssertionError(redact(f"{' '.join(argv[:4])}: exit {r.returncode}: {(r.stderr or r.stdout).strip()[-400:]}"))
    return r.stdout


def vm(h: str, command: str, inp: str | None = None, timeout: float = 120, check: bool = True, mux: bool = True) -> str:
    opts = SSH if mux else SSH + ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
    return sh(*opts, h, command, inp=inp, timeout=timeout, check=check)


def host(h: str, *args: str, timeout: float = 60, check: bool = True) -> str:
    return vm(h, "sudo e2e-ha-host " + " ".join(args), timeout=timeout, check=check)


def host_state(h: str) -> dict:
    return json.loads(host(h, "state"))


def mask(*values: str) -> None:
    """::add-mask:: for each credential value (and each of its lines) the
    moment it is read, so no later log line can show it."""
    for v in values:
        for part in {v.strip(), *v.strip().splitlines()}:
            if len(part) >= 4:
                print(f"::add-mask::{part}", flush=True)


def secret_read(h: str, command: str, timeout: float = 30) -> str:
    """A credential read on a VM: its output masked at once and never put
    in an error (a failed read says only which command failed)."""
    r = subprocess.run([*SSH, h, command], capture_output=True, text=True, timeout=timeout)
    out = r.stdout
    if out:
        mask(out)
    if r.returncode != 0:
        raise AssertionError(f"a credential read on {h} failed (exit {r.returncode}; its output withheld)")
    return out


def pc(*args: str, timeout: float = 600, check: bool = True) -> str:
    return vm("vm1", "~/e2e-ha/pc " + " ".join(args), timeout=timeout, check=check)


# ── kubectl over an SSH tunnel to a surviving API server ──

_tunnel: dict = {"proc": None, "server": "", "kubeconfig": ""}


def _start_tunnel(server_vm: str) -> None:
    _stop_tunnel()
    local = 6443
    proc = subprocess.Popen([*SSH, "-N", "-L", f"127.0.0.1:{local}:{MESH[server_vm]}:6443", server_vm],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    kc = os.path.join(D, "kubeconfig")
    if not os.path.exists(kc):
        raw = secret_read("vm1", "cat ~/portcullis/secrets/kube/kubeconfig")
        raw = re.sub(r"server: https://[0-9.]+:6443", f"server: https://127.0.0.1:{local}", raw)
        with open(kc, "w") as f:
            f.write(raw)
        os.chmod(kc, 0o600)
    _tunnel.update(proc=proc, server=server_vm, kubeconfig=kc)
    os.environ["KUBECONFIG"] = kc
    import e2e_ha
    e2e_ha.CTX = "portcullis"
    for _ in range(60):
        try:
            if e2e_ha.K("version", "--request-timeout=5s", ok=False, timeout=10):
                return
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1)
    raise AssertionError(f"the API tunnel to {server_vm} didn't answer")


def _stop_tunnel() -> None:
    p = _tunnel.get("proc")
    if p:
        p.terminate()
        try:
            p.wait(5)
        except Exception:  # noqa: BLE001
            p.kill()
    _tunnel["proc"] = None


def retarget_api(avoid: set[str] | None = None) -> None:
    """Point kubectl at a server whose API answers (not in `avoid`)."""
    avoid = avoid or set()
    for h in ["vm1", "vm2", "vm3"]:
        if h in avoid:
            continue
        if vm(h, "sudo k3s kubectl --request-timeout=5s get --raw /readyz >/dev/null 2>&1 && echo ok", check=False, timeout=15).strip() == "ok":
            _start_tunnel(h)
            return
    raise AssertionError(f"no API server answers (avoiding {sorted(avoid)})")


# e2e_ha's helpers run against the tunnel; its docker-based node kill is
# replaced by the VM host faults below.
import e2e_ha  # noqa: E402
from e2e_ha import (  # noqa: E402
    K, Kj, pods, ready, node_ready, not_ready_at, pg_primary, psql, Writer,
    published, fd_status, lease_time, lease_holder, hub, note, save,
)

results = e2e_ha.results
state = e2e_ha.state
timings = e2e_ha.timings
NS, PG_NS, PG = e2e_ha.NS, e2e_ha.PG_NS, e2e_ha.PG


def check(name: str, fn) -> None:
    if scenarios.skip(name):
        return
    t0 = time.time()
    try:
        fn()
        results.append((name, True, ""))
        print(f"PASS: {name} ({time.time() - t0:.0f} s)", flush=True)
    except Exception as e:  # noqa: BLE001
        import traceback
        results.append((name, False, f"{type(e).__name__}: {e}"))
        print(f"FAIL: {name}: {e}", flush=True)
        traceback.print_exc()
    finally:
        try:
            settle()
        except Exception as e:  # noqa: BLE001
            short = name.split(":")[0]
            print(f"::warning::after {short}: the cluster didn't settle: {e}", flush=True)
            results.append((f"{short} settle: back to full redundancy", False, f"{type(e).__name__}: {e}"))


def wait_for(what, fn, timeout, every=2):
    return e2e_ha.wait_for(what, fn, timeout, every)


# ── VM node faults ──

cut: dict[str, str] = {}   # node → the fault kind applied ("partition", "dark", …)


def boot_id(h: str) -> str:
    return vm(h, "cat /proc/sys/kernel/random/boot_id", check=False, timeout=15, mux=False).strip()


def node_vm(node: str) -> str:
    return NODE_VM[node]


def partition(node: str) -> float:
    """Every packet but SSH dropped both ways on the node: a real
    partition, so it loses the API and its peers and self-fences."""
    h = node_vm(node)
    host(h, "net set partition")
    cut[node] = "partition"
    return time.time()


def power_off(node: str) -> float:
    h = node_vm(node)
    b0 = boot_id(h)
    host(h, "dark", check=False)  # it reboots at once; the SSH call may not return cleanly
    cut[node] = "dark"
    # The node is down (a new boot id behind the dark flag, or unreachable).
    for _ in range(60):
        b = boot_id(h)
        if b and b != b0:
            return time.time()
        time.sleep(2)
    return time.time()


def heal(node: str) -> None:
    h = node_vm(node)
    kind = cut.pop(node, "")
    if kind == "dark":
        vm(h, "sudo e2e-ha-host light", check=False, timeout=60, mux=False)
    else:
        host(h, "net clear", check=False)


def self_fenced(h: str, b0: str, timeout: float) -> float:
    """The node rebooted (its boot id changed): softdog fired. Polled over
    SSH, which stays up through the partition."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        b = boot_id(h)
        if b and b != b0:
            return time.time()
        time.sleep(2)
    raise AssertionError(f"{h} didn't self-fence within {timeout:.0f} s (boot id unchanged {b0})")


def settle(timeout: float = 900) -> None:
    """Between scenarios: every cut healed, the API reachable, every node
    Ready and schedulable, core workloads at their replicas, CNPG healthy,
    Longhorn volumes attached and healthy."""
    for node in list(cut):
        heal(node)
    # The node mesh and k3s take a moment after a fenced node reboots.
    retarget_api()

    def ok():
        nodes = Kj("get", "nodes")["items"]
        bad = [n["metadata"]["name"] for n in nodes
               if not any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"])]
        assert not bad, f"nodes not Ready: {bad}"
        for n in nodes:
            if n["spec"].get("unschedulable"):
                K("uncordon", n["metadata"]["name"])
        for kind in ("deployments", "statefulsets"):
            for w in Kj("-n", NS, "get", kind)["items"]:
                want = w["spec"].get("replicas", 1)
                have = w.get("status", {}).get("readyReplicas", 0) or 0
                assert have >= want, f"{kind[:-1]} {w['metadata']['name']}: {have}/{want} ready"
        c = Kj("-n", PG_NS, "get", "cluster.postgresql.cnpg.io", PG)
        st = c.get("status", {})
        assert st.get("readyInstances") == c["spec"]["instances"], f"CNPG {st.get('readyInstances')}/{c['spec']['instances']}"
        return True
    wait_for("the cluster settled", ok, timeout, 10)
    longhorn_healthy()


# ── Longhorn ──

LH = "longhorn-system"


def lh(*argv: str, **kw):
    return Kj("-n", LH, *argv, **kw)


def longhorn_volumes() -> list[dict]:
    try:
        return lh("get", "volumes.longhorn.io")["items"]
    except Exception:  # noqa: BLE001
        return []


def longhorn_healthy(timeout: float = 420) -> None:
    def ok():
        vols = longhorn_volumes()
        bad = [v["metadata"]["name"] for v in vols
               if v.get("status", {}).get("robustness") not in ("healthy", "") or v.get("status", {}).get("state") not in ("attached", "detached")]
        # A volume with no consumer is detached (unknown robustness): fine.
        bad = [v["metadata"]["name"] for v in vols
               if v.get("status", {}).get("state") == "attached" and v.get("status", {}).get("robustness") != "healthy"]
        assert not bad, f"Longhorn volumes not healthy: {bad}"
        return True
    wait_for("Longhorn volumes healthy", ok, timeout, 10)


# ── the admin browser session on a VM ingress node ──

def mint_vm(user: str = "admin", to: str = "portal") -> str:
    out = pc("invite", user, "--to", to, "--json", timeout=120)
    url = json.loads(out.strip().splitlines()[-1])["url"]
    assert re.fullmatch(r"https://enroll\.[A-Za-z0-9.-]+/invite/[A-Za-z0-9_-]{43}", url), f"malformed setup link"
    print(f"::add-mask::{url}", flush=True)
    return url


def ingress_public() -> list[str]:
    """Every main ingress node's public address (what the runner reaches)."""
    out = []
    for n in Kj("get", "nodes", "-l", "portcullis.io/ingress=true")["items"]:
        ann = json.loads(n["metadata"].get("annotations", {}).get("portcullis.io/addresses") or "{}")
        vmn = NODE_VM.get(n["metadata"]["name"])
        site = n["metadata"]["labels"].get("portcullis.io/site", "main")
        for a in ann.get("public") or []:
            out.append((n["metadata"]["name"], site, a))
    return out


class Session:
    """admin's Playwright session, routed to one VM public address."""

    def __init__(self, pw, ip: str):
        import e2e_login
        self.e2e_login = e2e_login
        rules = f"MAP {DOMAIN} {ip},MAP *.{DOMAIN} {ip}"
        self.browser = pw.chromium.launch(args=[f"--host-resolver-rules={rules}"])
        self.ctx = self.browser.new_context(ignore_https_errors=True)
        self.page = self.ctx.new_page()
        self.page.set_default_timeout(30_000)
        self.auth = e2e_login.Authenticator(self.page)
        link = mint_vm("admin", "portal")
        e2e_login.setup_link_signin(self.page, link, who="admin", mint=lambda: mint_vm("admin", "portal"),
                                    until=f"https://{DOMAIN}/", label="ha-vm-admin", expect_stepups=1)

    def reroute(self, ip: str) -> None:
        rules = f"MAP {DOMAIN} {ip},MAP *.{DOMAIN} {ip}"
        cookies = self.ctx.cookies()
        self.browser.close()
        from playwright.sync_api import sync_playwright  # noqa: F401
        self.browser = state["pw"].chromium.launch(args=[f"--host-resolver-rules={rules}"])
        self.ctx = self.browser.new_context(ignore_https_errors=True)
        self.ctx.add_cookies(cookies)
        self.page = self.ctx.new_page()
        self.page.set_default_timeout(30_000)

    def signin(self) -> bool:
        keep = [c for c in self.ctx.cookies() if not c["name"].startswith("_oauth2_proxy")]
        self.ctx.clear_cookies()
        self.ctx.add_cookies(keep)
        try:
            resp = self.page.goto(f"https://{DOMAIN}/", wait_until="domcontentloaded", timeout=20_000)
            return bool(resp) and resp.status == 200 and self.page.url.rstrip("/") == f"https://{DOMAIN}" \
                and not self.e2e_login.on_login_pages(self.page)
        except Exception:  # noqa: BLE001
            return False

    def portal_ok(self) -> bool:
        page = self.ctx.new_page()
        try:
            resp = page.goto(f"https://{DOMAIN}/", wait_until="domcontentloaded", timeout=20_000)
            return bool(resp) and resp.status == 200 and not self.e2e_login.on_login_pages(page)
        finally:
            page.close()

    def close(self) -> None:
        try:
            self.browser.close()
        except Exception:  # noqa: BLE001
            pass


def signin_loop(s: Session, total: int, actions: list) -> int:
    """`total` sign-ins; actions = [(i, fn)] run at request i. Returns the
    number failed."""
    failed, fails = 0, []
    acts = dict(actions)
    t0 = time.time()
    for i in range(total):
        if i in acts:
            acts[i]()
        if not s.signin():
            failed += 1
            fails.append((i, round(time.time() - t0, 1)))
        time.sleep(0.2)
    note(f"  {failed} of {total} sign-ins failed in {time.time() - t0:.0f} s: {fails[:10]}")
    return failed


# ── a test app on the replicated tier (for the data-integrity drills) ──

MARKER_NS = "portcullis-e2e-vm"
MARKER_PVC = "e2e-marker"


def marker_pod(name: str, node: str | None = None, mode: str = "sleep") -> dict:
    sp = {"restartPolicy": "Never", "automountServiceAccountToken": False,
          "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001,
                              "seccompProfile": {"type": "RuntimeDefault"}},
          "containers": [{"name": "c", "image": state["alpine"], "command": ["sleep", "3600"],
                          "resources": {"limits": {"memory": "64Mi"}, "requests": {"memory": "64Mi"}},
                          "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                          "volumeMounts": [{"name": "d", "mountPath": "/data"}]}],
          "volumes": [{"name": "d", "persistentVolumeClaim": {"claimName": MARKER_PVC}}]}
    if node:
        sp["nodeName"] = node
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": MARKER_NS,
            "labels": {"app": "e2e-marker"}}, "spec": sp}


def marker_setup() -> str:
    """A replicated-tier PVC with a marker file; its md5 (the data to keep
    through the disk and partition drills)."""
    K("create", "namespace", MARKER_NS, ok=False)
    K("label", "namespace", MARKER_NS, "pod-security.kubernetes.io/enforce=restricted", "--overwrite", ok=False)
    pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
           "metadata": {"name": MARKER_PVC, "namespace": MARKER_NS},
           "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": "portcullis-core-replicated",
                    "resources": {"requests": {"storage": "1Gi"}}}}
    K("apply", "-f", "-", inp=json.dumps(pvc))
    K("apply", "-f", "-", inp=json.dumps(marker_pod("marker-write")))
    K("-n", MARKER_NS, "wait", "--for=condition=Ready", "pod/marker-write", "--timeout=300s", timeout=320)
    data = "e2e-ha-vm marker " + str(int(time.time()))
    K("-n", MARKER_NS, "exec", "marker-write", "--", "sh", "-c", "printf '%s' \"$1\" > /data/marker && sync", "_", data)
    md5 = K("-n", MARKER_NS, "exec", "marker-write", "--", "md5sum", "/data/marker").split()[0]
    K("-n", MARKER_NS, "delete", "pod", "marker-write", "--wait=true", "--timeout=60s", ok=False)
    state["marker_md5"] = md5
    return md5


def marker_read() -> str:
    pod = "marker-read-" + str(int(time.time()) % 100000)
    K("apply", "-f", "-", inp=json.dumps(marker_pod(pod)))
    try:
        K("-n", MARKER_NS, "wait", "--for=condition=Ready", f"pod/{pod}", "--timeout=300s", timeout=320)
        return K("-n", MARKER_NS, "exec", pod, "--", "md5sum", "/data/marker").split()[0]
    finally:
        K("-n", MARKER_NS, "delete", "pod", pod, "--wait=false", ok=False)


# ── scenarios ──

def storage_servers() -> list[str]:
    return sorted(n["metadata"]["name"] for n in Kj("get", "nodes", "-l", "portcullis.io/storage=true")["items"])


def victim_server(avoid: set[str]) -> str:
    """A main storage server not in `avoid` and not the kubectl tunnel's."""
    avoid = set(avoid) | {VM_NODE[_tunnel["server"]]}
    for n in storage_servers():
        if n not in avoid:
            return n
    raise AssertionError(f"no storage server outside {sorted(avoid)}")


def ha_vm_partition() -> None:
    marker_setup()
    psql(pg_primary(), "DROP TABLE IF EXISTS e2e_ha_rows; CREATE TABLE e2e_ha_rows (n int PRIMARY KEY, at timestamptz DEFAULT now());")
    w = Writer()
    w.start()
    victim = ""
    try:
        wait_for("the writer's first rows", lambda: len(w.committed) >= 5, 60, 1)
        victim = victim_server(set())
        h = node_vm(victim)
        b0 = boot_id(h)
        # A pod on the minority side: a shell on the victim's own node that
        # tries to reach the API/pg must fail while it is partitioned.
        note(f"ha_vm_partition: partitioning {victim} ({h}); a writer on the minority side must fail")
        t = partition(victim)
        # The minority self-fences (softdog) within T_fence (150 s) + a
        # margin for detection and the reboot.
        tf = self_fenced(h, b0, 240)
        note(f"ha_vm_partition: {victim} self-fenced (rebooted) {tf - t:.0f} s after the partition")
        # A writer on the minority failed while it was cut: a psql into a pg
        # pod that sat on the victim is refused (the node is gone). The
        # majority keeps a primary and the writer resumes there.
        wait_for("the majority keeps writing", lambda: w.resumed_after(tf) >= 0, 120, 2)
        assert w.failures > 0, "no write failed during the partition (the writer never hit the minority)"
    finally:
        w.stop.set()
        w.join(15)
        if victim:
            heal(victim)
    settle()
    # The data checksums equal the majority's: every committed row present,
    # and the replicated-tier marker unchanged.
    want = {n for n, _ in w.committed}
    got = {int(x) for x in psql(pg_primary(), "SELECT n FROM e2e_ha_rows;").split()}
    lost = sorted(want - got)
    md5 = marker_read()
    note(f"ha_vm_partition: {len(want)} rows committed, {len(lost)} lost, {w.failures} writes failed on the minority; "
         f"marker md5 {md5} ({'equal' if md5 == state['marker_md5'] else 'CHANGED'})")
    assert not lost, f"committed rows lost after the partition: {lost[:20]}"
    assert md5 == state["marker_md5"], f"the marker changed: {md5} != {state['marker_md5']}"
    psql(pg_primary(), "DROP TABLE e2e_ha_rows;")


def ha_vm_power_off() -> None:
    psql(pg_primary(), "DROP TABLE IF EXISTS e2e_ha_rows; CREATE TABLE e2e_ha_rows (n int PRIMARY KEY, at timestamptz DEFAULT now());")
    w = Writer()
    w.start()
    victim = ""
    try:
        wait_for("the writer's first rows", lambda: len(w.committed) >= 5, 60, 1)
        p0 = pg_primary()
        victim = Kj("-n", PG_NS, "get", "pod", p0)["spec"]["nodeName"]
        if victim == VM_NODE[_tunnel["server"]]:
            retarget_api(avoid={victim})
        note(f"ha_vm_power_off: powering off {victim} ({node_vm(victim)}), the CNPG primary {p0}'s node")
        t = power_off(victim)
        tn = not_ready_at(victim, t, timeout=120)
        wait_for("the stateful app runs elsewhere (writes resume)", lambda: w.resumed_after(t) >= 0, 300, 2)
        p1 = pg_primary()
        d = time.time() - t
        note(f"ha_vm_power_off: {victim} off → NotReady after {tn - t:.0f} s → new primary {p1}, writes resumed "
             f"{w.resumed_after(t):.0f} s after the power-off ({w.resumed_after(tn):.0f} s after NotReady)")
        assert p1 != p0, "the primary didn't move"
        assert d <= 240, f"the stateful app took {d:.0f} s to run elsewhere (> 4 min)"
    finally:
        w.stop.set()
        w.join(15)
        if victim:
            heal(victim)
    settle()
    want = {n for n, _ in w.committed}
    got = {int(x) for x in psql(pg_primary(), "SELECT n FROM e2e_ha_rows;").split()}
    assert not (want - got), f"rows lost: {sorted(want - got)[:20]}"
    psql(pg_primary(), "DROP TABLE e2e_ha_rows;")


def lh_node_disks(node: str) -> list[dict]:
    try:
        n = lh("get", "nodes.longhorn.io", node)
    except Exception:  # noqa: BLE001
        return []
    return list((n.get("status", {}).get("diskStatus") or {}).values())


def ha_vm_disk_kill() -> None:
    marker_setup()
    victim = victim_server(set())
    h = node_vm(victim)
    before = [v["metadata"]["name"] for v in longhorn_volumes()
              if any(r.get("hostId") == victim for r in (v.get("status", {}).get("conditions") and [] or []))]
    note(f"ha_vm_disk_kill: killing {victim}'s Longhorn disk ({h})")
    host(h, "disk", "kill")
    try:
        # Longhorn sees the disk's replicas fail and rebuilds elsewhere; a
        # volume attached before stays healthy (2 replicas over 3 storage
        # nodes: the lost one is rebuilt on the third).
        def rebuilt():
            ds = lh_node_disks(victim)
            # The node's disk is unschedulable / not ready (I/O errors).
            bad = any(any(c.get("type") == "Ready" and c.get("status") != "True" for c in (d.get("conditions") or []))
                      or d.get("storageScheduled", 0) == 0 and not d.get("conditions") for d in ds)
            return True if not ds else bad
        wait_for(f"Longhorn marks {victim}'s disk failed", lambda: True if not lh_node_disks(victim) else any(
            any(c.get("type") in ("Ready", "Schedulable") and c.get("status") != "True" for c in (d.get("conditions") or []))
            for d in lh_node_disks(victim)), 180, 5)
        longhorn_healthy(600)
        md5 = marker_read()
        note(f"ha_vm_disk_kill: {victim}'s disk failed, volumes rebuilt healthy; marker md5 {md5} "
             f"({'equal' if md5 == state['marker_md5'] else 'CHANGED'})")
        assert md5 == state["marker_md5"], f"the marker changed: {md5} != {state['marker_md5']}"
    finally:
        # A reboot brings the disk back (fsck at boot via e2e-ha-disk).
        vm(h, "sudo systemctl reboot", check=False, timeout=30, mux=False)
    # settle() retargets the API and waits; the disk unit mounts it again.
    time.sleep(30)
    retarget_api()
    settle()


def ha_vm_disk_full() -> None:
    marker_setup()
    victim = victim_server(set())
    h = node_vm(victim)
    note(f"ha_vm_disk_full: filling {victim}'s Longhorn disk ({h})")
    host(h, "fill")
    try:
        def reported():
            ds = lh_node_disks(victim)
            for d in ds:
                if any(c.get("type") == "Schedulable" and c.get("status") != "True" for c in (d.get("conditions") or [])):
                    return True
                if d.get("storageAvailable", 1 << 60) < 2 * (1 << 30):
                    return True
            return False
        wait_for(f"Longhorn reports {victim}'s disk full", reported, 240, 5)
        longhorn_healthy(600)
        md5 = marker_read()
        note(f"ha_vm_disk_full: Longhorn reported {victim}'s disk full; volumes stay healthy; marker {('equal' if md5 == state['marker_md5'] else 'CHANGED')}")
        assert md5 == state["marker_md5"], "the marker changed"
    finally:
        host(h, "unfill", check=False)
    settle()


def ha_vm_lose_small() -> None:
    # The third server / third voter (vm3 here; the arm64 small node in the
    # D9 design, cloud in this bundle): lost, quorum holds (2/3).
    small = next((v["node"] for v in INV["vms"] if v.get("vm") == "vm3"), SERVERS[-1])
    if VM_NODE[_tunnel["server"]] == small:
        retarget_api(avoid={small})
    s: Session = state["session"]
    note(f"ha_vm_lose_small: powering off {small} ({node_vm(small)})")
    t = power_off(small)
    try:
        not_ready_at(small, t, timeout=120)
        # etcd quorum holds (2 of 3): the API still answers, and a write
        # succeeds (a throwaway group through the Hub).
        wait_for("the API still serves (quorum 2/3)", lambda: bool(K("get", "--raw", "/readyz", ok=False, timeout=10)), 60, 2)
        g = "e2e-ha-small-" + str(int(time.time()) % 100000)
        code, _ = hub("POST", "/api/directory/groups", {"name": g})
        assert code in (200, 201), f"a write failed with the third server down: {code}"
        hub("DELETE", f"/api/directory/groups/{g}", {"confirm": g})
        # sign-in keeps working.
        assert s.signin(), "sign-in failed with the third server down"
        note(f"ha_vm_lose_small: {small} down → API, a write and sign-in all work (quorum 2/3)")
    finally:
        heal(small)
    settle()
    wait_for(f"{small} Ready again", lambda: node_ready(small), 300, 5)


def rollout_restart(kind: str, name: str, ns: str = NS) -> None:
    K("-n", ns, "rollout", "restart", f"{kind}/{name}")


def ha_vm_rolling_upgrade() -> None:
    s: Session = state["session"]
    sts = {p["metadata"]["labels"].get("portcullis.io/component") for p in pods(NS, "portcullis.io/component")}
    restarts = [
        (20, lambda: rollout_restart("statefulset", "keycloak")),
        (120, lambda: rollout_restart("deployment", "group-gate")),
        (200, lambda: rollout_restart("deployment", "forward-auth")),
    ]
    note("ha_vm_rolling_upgrade: a rolling restart of Keycloak, group-gate and forward-auth under 300 sign-ins")
    failed = signin_loop(s, 300, restarts)
    # Let every rollout finish before settle.
    for kind, name in (("statefulset", "keycloak"), ("deployment", "group-gate"), ("deployment", "forward-auth")):
        K("-n", NS, "rollout", "status", f"{kind}/{name}", "--timeout=300s", timeout=320, ok=False)
    assert failed <= 5, f"{failed} of 300 sign-ins failed during the rolling upgrade (> 5)"


def site_of(node: str) -> str:
    return Kj("get", "node", node)["metadata"]["labels"].get("portcullis.io/site", "main")


def ingress_by_site() -> dict[str, list[tuple[str, str]]]:
    out: dict[str, list[tuple[str, str]]] = {}
    for node, site, addr in ingress_public():
        out.setdefault(site, []).append((node, addr))
    return out


def ha_vm_site_uplink_down() -> None:
    by = ingress_by_site()
    assert "edge" in by and by["edge"], f"no edge ingress address: {by}"
    names = [DOMAIN, f"*.{DOMAIN}"]
    want = sorted(a for lst in by.values() for _, a in lst)
    wait_for("every ingress address published", lambda: all(published().get(n) == want for n in names), 420, 5)
    edge_node, edge_addr = by["edge"][0]
    edge_h = node_vm(edge_node)
    main_addrs = sorted(a for _, a in by.get("main", []))
    # Step 1: vm4's public 443 dropped (its mesh stays up).
    note(f"ha_vm_site_uplink_down: dropping {edge_node}'s ({edge_h}) public 443; its mesh stays")
    host(edge_h, "net", "set", "drop443")
    try:
        rest = sorted(a for a in want if a != edge_addr)
        wait_for(f"{edge_node}'s address removed", lambda: all(published().get(n) == rest for n in names), 180, 2)
        note(f"ha_vm_site_uplink_down: {edge_addr} removed, {rest} kept; main keeps serving")
        # main keeps serving sign-in on its own address.
        assert served_fp(main_addrs[0], f"auth.{DOMAIN}"), "main stopped serving"
        # Step 2: main's ingress 443 dropped too; vm4 serves sign-in through
        # Traefik → main over pcmesh (its 443 is back up).
        host(edge_h, "net", "clear")
        wait_for("vm4's address back", lambda: all(edge_addr in (published().get(n) or []) for n in names), 180, 2)
        for node, _ in by.get("main", []):
            host(node_vm(node), "net", "set", "drop443")
        wait_for("only edge's address left", lambda: all(published().get(n) == [edge_addr] for n in names), 240, 2)
        s = Session(state["pw"], edge_addr)
        try:
            assert s.portal_ok(), "sign-in through the edge node (Traefik → main over pcmesh) failed"
        finally:
            s.close()
        note(f"ha_vm_site_uplink_down: main's ingress 443 down → only {edge_addr} published; the edge node serves sign-in through main over pcmesh")
    finally:
        host(edge_h, "net", "clear", check=False)
        for node, _ in by.get("main", []):
            host(node_vm(node), "net", "clear", check=False)
    settle()


def ha_vm_site_down() -> None:
    by = ingress_by_site()
    names = [DOMAIN, f"*.{DOMAIN}"]
    want = sorted(a for lst in by.values() for _, a in lst)
    wait_for("every ingress address published", lambda: all(published().get(n) == want for n in names), 420, 5)
    edge_node, edge_addr = by["edge"][0]
    note(f"ha_vm_site_down: powering off {edge_node} ({node_vm(edge_node)})")
    t = power_off(edge_node)
    try:
        not_ready_at(edge_node, t, timeout=120)
        assert bool(K("get", "--raw", "/readyz", ok=False, timeout=10)), "quorum lost with only edge down"
        rest = sorted(a for a in want if a != edge_addr)
        wait_for(f"{edge_node}'s address removed, never the last", lambda: all(published().get(n) == rest for n in names), 240, 2)
        # The last main addresses are never removed (fail static) over 60 s.
        t2 = time.time()
        while time.time() - t2 < 60:
            assert all(set(rest) <= set(published().get(n) or []) for n in names), f"a main address went: {published()}"
            time.sleep(5)
        note(f"ha_vm_site_down: {edge_addr} removed, {rest} kept (quorum held, never the last)")
    finally:
        heal(edge_node)
    settle()


def mesh_ping(src_vm: str, dst_mesh: str) -> bool:
    return vm(src_vm, f"ping -c 2 -W 2 {dst_mesh} >/dev/null 2>&1 && echo ok", check=False, timeout=20).strip() == "ok"


def ha_vm_nat_relay() -> None:
    s: Session = state["session"]
    # vm2 is NATed at main (vm1 the gateway): its inbound mesh port closed
    # to the other sites, kept to its own LAN.
    assert mesh_ping("vm2", MESH["vm4"]), "vm2 can't reach vm4 over pcmesh before the cut"
    note(f"ha_vm_nat_relay: closing vm2's inbound UDP 51830 to the other sites (LAN {LAN_CIDR} kept)")
    host("vm2", "net", "set", f"dropmesh:{LAN_CIDR}")
    try:
        # vm2 ↔ vm4 keeps working through vm1 (the mesh gateway relay).
        wait_for("vm2 ↔ vm4 relays through vm1", lambda: mesh_ping("vm2", MESH["vm4"]) and mesh_ping("vm4", MESH["vm2"]), 120, 3)
        assert s.signin(), "sign-in failed during the NAT relay"
        note("ha_vm_nat_relay: vm2 ↔ vm4 relays through vm1 and sign-in is unaffected")
    finally:
        host("vm2", "net", "clear", check=False)
    settle()


# ── carries: Pebble, probes, etcd, removal, front-door node ──

def served_pair() -> str:
    import base64
    try:
        return base64.b64decode(Kj("-n", NS, "get", "secret", "frontdoor-cert")["data"]["tls.crt"]).decode()
    except Exception:  # noqa: BLE001
        return ""


def cert_fp_pem(pem: str) -> str:
    return e2e_ha.cert_fp(pem)


def ha_vm_pebble_issue_sni() -> None:
    # The front door ordered <d> and *.<d> from Pebble (the fixture on vm1);
    # frontdoor-cert holds it, and every ingress node serves it by SNI and
    # without. The issuer is Pebble (not core's CA).
    pem = wait_for("frontdoor-cert holds a certificate", served_pair, 300, 5)
    issuer = subprocess.run(["openssl", "x509", "-noout", "-issuer"], input=pem, capture_output=True, text=True).stdout
    note(f"ha_vm_pebble_issue_sni: frontdoor-cert issuer {issuer.strip()}")
    assert "Pebble" in issuer, f"the served certificate isn't Pebble's: {issuer.strip()}"
    want_fp = cert_fp_pem(pem)
    by = ingress_public()
    assert len(by) >= 3, f"ingress addresses: {by}"
    # By SNI at once (the domains provider); without SNI once the front
    # door's 1-minute loop mirrored the pair as Traefik's default
    # certificate (§20.8): converged within 3 min, the time noted.
    t0 = time.time()
    for node, _site, addr in by:
        for sni in (f"auth.{DOMAIN}", ""):
            def serves(addr=addr, sni=sni, node=node):
                # The current pair each time: Pebble's 30 d + 12 min validity
                # makes the front door renew about every 12 minutes.
                cur = served_pair()
                assert "Pebble" in subprocess.run(["openssl", "x509", "-noout", "-issuer"], input=cur, capture_output=True, text=True).stdout, \
                    "frontdoor-cert isn't Pebble's"
                want = cert_fp_pem(cur)
                got = e2e_ha.served_fp(addr, sni)
                assert got == want, f"{node} ({addr}) serves {got} for SNI {sni or '(none)'}, not frontdoor-cert's {want}"
                return True
            wait_for(f"{node} serving frontdoor-cert (SNI {sni or 'none'})", serves, 180, 5)
    note(f"ha_vm_pebble_issue_sni: every ingress node serves frontdoor-cert ({want_fp[:16]}…) by SNI and without "
         f"(converged {time.time() - t0:.0f} s after the first check)")


def fd_pod() -> dict:
    return next(p for p in pods(NS, "portcullis.io/component=frontdoor") if ready(p))


def ha_vm_cert_renew_leader_move() -> None:
    # Pebble issues 30-day + 12-min certificates; the front door renews when
    # under RenewBefore (30 d), i.e. ~12 min after issue. Move the Lease (cut
    # the front door's pod) so a new front door renews, and the served
    # certificate's notBefore advances (a renewal).
    pem0 = wait_for("frontdoor-cert holds a certificate", served_pair, 300, 5)
    nb0 = subprocess.run(["openssl", "x509", "-noout", "-startdate"], input=pem0, capture_output=True, text=True).stdout.strip()
    fp0 = cert_fp_pem(pem0)
    note(f"ha_vm_cert_renew_leader_move: current certificate {fp0[:16]}… {nb0}; waiting for a renewal across a Lease move")
    # Nudge a leader move partway (delete the front door pod once) so the
    # renewal lands under a successor; then wait for a new notBefore.
    leader0 = fd_status().get("leader")
    K("-n", NS, "delete", "pod", fd_pod()["metadata"]["name"], "--wait=false")

    def renewed():
        pem = served_pair()
        if not pem or cert_fp_pem(pem) == fp0:
            # Nudge another leader move if a front door restarted in place.
            return None
        return pem
    # The validity is 30 d + 12 min, so the first renewal is ~12 min after
    # the certificate was issued; allow the front door's 1-min check plus a
    # margin, and move the Lease again midway.
    deadline = time.time() + 1500
    pem1 = None
    while time.time() < deadline:
        pem1 = renewed()
        if pem1:
            break
        if int(time.time()) % 300 < 5:
            try:
                K("-n", NS, "delete", "pod", fd_pod()["metadata"]["name"], "--wait=false", ok=False)
            except Exception:  # noqa: BLE001
                pass
        time.sleep(10)
    assert pem1, f"no renewal within {int((time.time() - (deadline - 1500)))} s (certificate still {fp0[:16]}…)"
    nb1 = subprocess.run(["openssl", "x509", "-noout", "-startdate"], input=pem1, capture_output=True, text=True).stdout.strip()
    leader1 = fd_status().get("leader")
    note(f"ha_vm_cert_renew_leader_move: renewed to {cert_fp_pem(pem1)[:16]}… {nb1} (leader {leader0} → {leader1})")
    assert nb1 != nb0, "the certificate's notBefore didn't advance"


def ha_vm_same_site_reach() -> None:
    """Same-site probes never count (§20.8, D12): with two sites, each
    ingress node is judged by the OTHER site's probers. In the front door's
    status every ingress node is ok, healthy, not blind and not
    internal_only (an outside vantage judged it), and the checklist's
    site_gateway ("a reachable node at every site", the mesh reach of
    ruling N1) is ok."""
    def judged():
        # Only the per-node verdicts (the map also holds flags).
        pr = {n: v for n, v in (fd_status().get("probes") or {}).items() if isinstance(v, dict)}
        ing = sorted(n for n, _s, _a in ingress_public())
        missing = [n for n in ing if n not in pr]
        assert not missing, f"no probe verdict for {missing}: {pr}"
        bad = {n: v for n, v in pr.items() if n in ing and not (v.get("ok") and v.get("verdict") == "healthy"
               and v.get("blind") is False and v.get("internal_only") is False)}
        assert not bad, f"probe verdicts not healthy from another site: {bad}"
        return pr
    pr = wait_for("every ingress node judged healthy by the other site's probers", judged, 300, 10)
    save("frontdoor-probes.json", pr)
    st = json.loads(pc("ha", "status", "--json"))
    items = {i["id"]: i for i in st.get("ha", {}).get("checklist", [])}
    if not items:
        items = {i["id"]: i for i in _walk_items(st)}
    assert items.get("site_gateway", {}).get("ok") is True, f"site_gateway not ok: {items.get('site_gateway')}"
    note(f"ha_vm_same_site_reach: {sorted(pr)} judged healthy, none internal-only or blind; site_gateway ok")


def _walk_items(o):
    if isinstance(o, dict):
        if "id" in o and "ok" in o:
            yield o
        for v in o.values():
            yield from _walk_items(v)
    elif isinstance(o, list):
        for v in o:
            yield from _walk_items(v)


def ha_vm_etcd_remove_member() -> None:
    # A cooperative server removal (node remove) takes its etcd member out
    # (nodeadm drives a surviving nodeagent's etcd remove-member). Add a
    # fresh server, then remove it, and check etcd is back to 3 members.
    before = etcd_members()
    assert len(before) == 3, f"etcd starts with {len(before)} members: {before}"
    node = "vm2"  # a server we can rejoin afterwards
    note(f"ha_vm_etcd_remove_member: removing server {VM_NODE[node]} cooperatively")
    out = pc("node", "remove", VM_NODE[node], inp=VM_NODE[node] + "\n", timeout=900)
    print(redact(out[-1500:]), flush=True)
    wait_for("etcd down to 2 members", lambda: len(etcd_members()) == 2, 300, 5)
    note(f"ha_vm_etcd_remove_member: etcd members {sorted(before)} → {sorted(etcd_members())}")
    # Rejoin it (settle expects 3 servers).
    _rejoin_server(node)


def etcd_members() -> list[str]:
    """etcd member names via a server's nodeagent (the JSON API on 2382) or,
    simpler, k3s' etcd snapshot of the member list from a server."""
    out = vm(_tunnel["server"], "sudo k3s kubectl get nodes -l node-role.kubernetes.io/control-plane=true -o name", check=False)
    # etcd membership follows the control-plane Nodes that are Ready+etcd.
    members = []
    for n in Kj("get", "nodes", "-l", "node-role.kubernetes.io/control-plane=true")["items"]:
        if "etcd" in [r for r in (n["metadata"]["labels"].get("node-role.kubernetes.io/etcd") and ["etcd"] or [])] or \
           n["metadata"]["labels"].get("node-role.kubernetes.io/etcd") == "true":
            members.append(n["metadata"]["name"])
    return members or [n["metadata"]["name"] for n in Kj("get", "nodes", "-l", "node-role.kubernetes.io/etcd=true")["items"]]


def _rejoin_server(vmn: str) -> None:
    v = VMS[vmn]
    id_ = v["node"]
    out = pc("node", "add", id_, "--role", "server", "--class", "cloud", "--site", "main", timeout=120)
    codes = [ln.strip() for ln in out.splitlines() if ln.startswith("pcj")]
    assert codes, f"node add {id_} printed no join code"
    mask(codes[0])
    # The code onto the node's root 0600 file through stdin (join.sh
    # --code-file); never argv, never a file here, never printed.
    vm(vmn, "sudo install -m 0600 -o root -g root /dev/stdin /root/e2e-join-code", inp=codes[0] + "\n")
    del out, codes
    vm(vmn, f"curl -fsSL https://{DOMAIN}/node/join.sh -o /tmp/join.sh && sudo sh /tmp/join.sh --code-file /root/e2e-join-code; "
            "sudo rm -f /root/e2e-join-code /tmp/join.sh", timeout=600, check=False)
    wait_for(f"{id_} Ready again", lambda: node_ready(id_), 450, 5)


def ha_vm_interrupted_removal() -> None:
    # A server removal interrupted by a restart resumes and finishes
    # cleanly. Start `node remove`, kill it partway (its drain started),
    # then run it again: it resumes and the node leaves.
    node = "vm3"
    id_ = VM_NODE[node]
    note(f"ha_vm_interrupted_removal: removing {id_}, interrupting it, then resuming")
    p = subprocess.Popen([*SSH, "vm1", f"~/e2e-ha/pc node remove {id_}"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    p.stdin.write(id_ + "\n")
    p.stdin.flush()
    # Let the removal get underway (the cordon/drain), then interrupt it.
    wait_for(f"{id_} cordoned (removal underway)", lambda: Kj("get", "node", id_)["spec"].get("unschedulable") is True, 120, 2)
    p.terminate()
    try:
        p.wait(15)
    except Exception:  # noqa: BLE001
        p.kill()
    note(f"ha_vm_interrupted_removal: interrupted; resuming")
    out = pc("node", "remove", id_, inp=id_ + "\n", timeout=900)
    print(redact(out[-1500:]), flush=True)
    wait_for(f"{id_} gone", lambda: not any(n["metadata"]["name"] == id_ for n in Kj("get", "nodes")["items"]), 300, 5)
    note(f"ha_vm_interrupted_removal: {id_} removed cleanly after the interruption")
    _rejoin_server(node)


def ha_vm_front_door_node() -> None:
    # (33a N1) the front door's own node cut: a new front door takes the
    # Lease elsewhere, then DNS failover still removes a dead node's address.
    by = ingress_public()
    names = [DOMAIN, f"*.{DOMAIN}"]
    want = sorted(a for _, _, a in by)
    wait_for("every ingress address published", lambda: all(published().get(n) == want for n in names), 420, 5)
    fdn = fd_pod()["spec"]["nodeName"]
    if fdn not in SERVERS:
        note(f"ha_vm_front_door_node: the front door is on {fdn} (not a cuttable server); skipped")
        return
    if VM_NODE[_tunnel["server"]] == fdn:
        retarget_api(avoid={fdn})
    leader0 = fd_status().get("leader")
    note(f"ha_vm_front_door_node: cutting the front door's own node {fdn}")
    t = partition(fdn)
    try:
        self_fenced(node_vm(fdn), boot_id(node_vm(fdn)), 240)
    except AssertionError:
        pass
    try:
        # A new front door leads elsewhere.
        wait_for("a new front door leads", lambda: fd_status().get("leader") not in ("", None, leader0)
                 and fd_pod()["spec"]["nodeName"] != fdn, 300, 5)
        leader1 = fd_status().get("leader")
        # And it removes the cut node's address (its own, if it was an
        # ingress node), keeping the rest / never the last.
        rest = sorted(a for node, _s, a in by if node != fdn)
        if rest:
            wait_for("the cut front-door node's address removed", lambda: all(set(published().get(n) or []) <= set(rest) for n in names)
                     and all(published().get(n) for n in names), 300, 3)
        note(f"ha_vm_front_door_node: front door moved {leader0} → {leader1}; the address set recovered to the live nodes")
    finally:
        heal(fdn)
    settle()


def ha_vm_front_door_nodeadm_one_node() -> None:
    # (33a N1) the front door and nodeadm on one node, that node cut: the
    # slower failover (DNS waits for nodeadm) under a real node loss. Move
    # the front door onto nodeadm's node first, then cut it.
    na = next(p for p in pods("portcullis-nodeadm", "portcullis.io/component=nodeadm") if ready(p))
    na_node = na["spec"]["nodeName"]
    if na_node not in SERVERS:
        note(f"ha_vm_front_door_nodeadm_one_node: nodeadm on {na_node} (not cuttable); skipped")
        return
    # Pin the front door to nodeadm's node (delete its pod until it lands
    # there is unreliable; instead cordon the others briefly).
    others = [n for n in SERVERS if n != na_node]
    for n in others:
        K("cordon", n)
    try:
        K("-n", NS, "delete", "pod", fd_pod()["metadata"]["name"], "--wait=false")
        wait_for("the front door on nodeadm's node", lambda: fd_pod()["spec"]["nodeName"] == na_node, 300, 5)
    finally:
        for n in others:
            K("uncordon", n)
    by = ingress_public()
    names = [DOMAIN, f"*.{DOMAIN}"]
    want = sorted(a for _, _, a in by)
    wait_for("every ingress address published", lambda: all(published().get(n) == want for n in names), 420, 5)
    if VM_NODE[_tunnel["server"]] == na_node:
        retarget_api(avoid={na_node})
    leader0 = fd_status().get("leader")
    note(f"ha_vm_front_door_nodeadm_one_node: cutting {na_node} (front door + nodeadm)")
    t = partition(na_node)
    try:
        wait_for("nodeadm Ready elsewhere", lambda: any(ready(p) and p["spec"]["nodeName"] != na_node
                 for p in pods("portcullis-nodeadm", "portcullis.io/component=nodeadm")), 300, 5)
        wait_for("a new front door leads", lambda: fd_pod()["spec"]["nodeName"] != na_node, 300, 5)
        rest = sorted(a for node, _s, a in by if node != na_node)
        if rest:
            wait_for("the dead node's address removed", lambda: all(set(published().get(n) or []) <= set(rest) and published().get(n) for n in names), 300, 3)
        note(f"ha_vm_front_door_nodeadm_one_node: both rescheduled, the address recovered (leader {leader0} → {fd_status().get('leader')})")
    finally:
        heal(na_node)
    settle()


# ── ha_vm_revoke_restarts: the agent-token fix proof ──

PASSWD = "/var/lib/rancher/k3s/server/cred/passwd"


def server_vms() -> list[str]:
    return [NODE_VM[n] for n in SERVERS if NODE_VM.get(n)]


def live_server_vms() -> list[str]:
    out = []
    for n in Kj("get", "nodes", "-l", "node-role.kubernetes.io/control-plane=true")["items"]:
        if any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"]):
            h = NODE_VM.get(n["metadata"]["name"])
            if h:
                out.append(h)
    return sorted(out)


def passwd_lines(h: str) -> dict[str, str]:
    """passwd's credential per user (node, server, …); every credential masked."""
    out = {}
    for ln in secret_read(h, f"sudo cat {PASSWD}").splitlines():
        parts = ln.split(",")
        if len(parts) >= 2:
            mask(parts[0])
            out[parts[1]] = parts[0]
    return out


def passwd_digest(h: str) -> str:
    """sha256 of the whole passwd file, 12 hex: what is compared and
    reported (never the content)."""
    import hashlib
    return hashlib.sha256(secret_read(h, f"sudo cat {PASSWD}").encode()).hexdigest()[:12]


def passwd_node_eq_server(h: str) -> bool:
    """passwd's node line credential equals the server line's (one token)."""
    lines = passwd_lines(h)
    return bool(lines.get("node")) and lines.get("node") == lines.get("server")


def no_agent_token_file(h: str) -> bool:
    u = vm(h, "systemctl cat k3s.service 2>/dev/null; sudo cat /etc/rancher/k3s/config.yaml 2>/dev/null; sudo cat /etc/systemd/system/k3s.service.env 2>/dev/null; sudo ls /etc/rancher/k3s/ 2>/dev/null", check=False, timeout=20)
    return "agent-token-file" not in u and "agent-token" not in u


def server_token(h: str) -> str:
    return secret_read(h, "sudo cat /var/lib/rancher/k3s/server/token").strip()


def node_cred(h: str) -> str:
    """The node credential derived from passwd's node line (masked)."""
    return passwd_lines(h).get("node", "")


def k3s_bootstrap_status(h: str, cred_user: str, cred_pw: str, path: str = "server-bootstrap") -> int:
    """The HTTP status of GET https://127.0.0.1:6443/v1-k3s/<path> on h with
    basic creds (a 0600 curl config on the node, never argv)."""
    cfg = f"user = \"{cred_user}:{cred_pw}\"\n"
    out = vm(h, "umask 077; cat > /tmp/e2e-k.cfg; "
             f"sudo curl -sk -o /dev/null -w '%{{http_code}}' -K /tmp/e2e-k.cfg https://127.0.0.1:6443/v1-k3s/{path}; "
             "rm -f /tmp/e2e-k.cfg", inp=cfg, check=False, timeout=30)
    try:
        return int(out.strip()[-3:])
    except ValueError:
        return 0


def cluster_healthy(expect_ready: int) -> None:
    def ok():
        nodes = Kj("get", "nodes")["items"]
        rdy = [n["metadata"]["name"] for n in nodes
               if any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"])]
        assert len(rdy) >= expect_ready, f"{len(rdy)} Ready, want {expect_ready}: {[n['metadata']['name'] for n in nodes]}"
        crash = [p["metadata"]["name"] for p in Kj("-n", NS, "get", "pods")["items"]
                 if p["status"].get("phase") not in ("Running", "Succeeded")]
        assert not crash, f"core pods not Running: {crash}"
        return True
    wait_for(f"the cluster healthy ({expect_ready} Ready)", ok, 420, 10)


def restart_k3s(h: str) -> None:
    b0 = ""
    vm(h, "sudo systemctl restart k3s", check=False, timeout=120, mux=False)
    # Its /v1-k3s/readyz with the node credential answers once it is up.


def no_fatal_since(h: str, since_min: int = 3) -> None:
    out = vm(h, f"sudo journalctl -u k3s --since '{since_min} min ago' --no-pager 2>/dev/null | "
             "grep -E 'newer than datastore|encrypted with different token' || true", check=False, timeout=30)
    assert not out.strip(), f"{h}: a fatal k3s line: {out.strip()[-300:]}"


def restart_cycle(survivor_vms: list[str], reboot_vm: str, expect_ready: int) -> None:
    # One at a time, twice.
    for _ in range(2):
        for h in survivor_vms:
            restart_k3s(h)
            wait_for(f"{h}'s k3s up", lambda: vm(h, "sudo k3s kubectl --request-timeout=5s get --raw /readyz >/dev/null 2>&1 && echo ok", check=False, timeout=15).strip() == "ok", 180, 3)
            no_fatal_since(h)
    retarget_api()
    cluster_healthy(expect_ready)
    # All together.
    for h in survivor_vms:
        vm(h, "sudo systemctl restart --no-block k3s", check=False, timeout=30, mux=False)
    time.sleep(10)
    retarget_api()
    cluster_healthy(expect_ready)
    for h in survivor_vms:
        no_fatal_since(h)
    # Reboot one host.
    b0 = boot_id(reboot_vm)
    vm(reboot_vm, "sudo systemctl reboot", check=False, timeout=30, mux=False)
    for _ in range(90):
        b = boot_id(reboot_vm)
        if b and b != b0:
            break
        time.sleep(3)
    wait_for(f"{reboot_vm} k3s active after reboot", lambda: vm(reboot_vm, "systemctl is-active k3s 2>/dev/null", check=False, timeout=15).strip() == "active", 300, 5)
    no_fatal_since(reboot_vm, 6)
    retarget_api()
    cluster_healthy(expect_ready)
    # passwd byte-equal, node == server, no agent-token-file.
    pws = {h: passwd_digest(h) for h in survivor_vms}
    assert len(set(pws.values())) == 1, f"passwd differs across servers (sha256 prefixes): {pws}"
    note(f"  passwd byte-equal on {sorted(pws)} (sha256 {next(iter(pws.values()))})")
    for h in survivor_vms:
        assert passwd_node_eq_server(h), f"{h}: passwd node != server"
        assert no_agent_token_file(h), f"{h}: an agent-token file is configured"


def ha_vm_revoke_restarts() -> None:
    survivors = live_server_vms()
    assert len(survivors) == 3, f"need three servers: {survivors}"
    s: Session = state["session"]
    # Old credentials to 401-check after each rotation (a surviving server's
    # token before the revoke; its node credential).
    ref = survivors[0]
    old_token = server_token(ref)
    old_node = node_cred(ref)
    assert old_token and old_node, "couldn't read the server token / node credential"

    # 1) Revoke the agent (vm4).
    agent_id = VM_NODE[EDGE_VM]
    note(f"ha_vm_revoke_restarts: revoking the agent {agent_id}")
    pc("node", "revoke", agent_id, inp=agent_id + "\n", timeout=900)
    wait_for("the agent's Node gone", lambda: not any(n["metadata"]["name"] == agent_id for n in Kj("get", "nodes")["items"]), 300, 5)
    # Its node-password Secret is gone (GC'd with the Node).
    assert not K("-n", "kube-system", "get", "secret", f"{agent_id}.node-password.k3s", "--ignore-not-found", "-o", "name", ok=False).strip(), \
        "the revoked agent's node-password Secret is still there"
    # The old server token and node credential 401 (both rotations have run);
    # the current ones 200.
    def creds_rotated():
        new_token = server_token(ref)
        c_old = k3s_bootstrap_status(ref, "server", old_token)
        c_new = k3s_bootstrap_status(ref, "server", new_token)
        assert c_old == 401, f"the old server token still answers {c_old} (want 401)"
        assert c_new == 200, f"the new server token answers {c_new} (want 200)"
        return True
    wait_for("the k3s tokens rotated (old 401, new 200)", creds_rotated, 300, 5)
    survivors2 = [h for h in survivors]  # all three servers survive an agent revoke
    restart_cycle(survivors2, survivors2[1], expect_ready=3)
    # The revoked agent can't come back with what it holds.
    vm(EDGE_VM, "sudo systemctl restart k3s-agent 2>/dev/null; true", check=False, timeout=30, mux=False)
    time.sleep(20)
    assert not any(n["metadata"]["name"] == agent_id for n in Kj("get", "nodes")["items"]), \
        "the revoked agent re-registered its Node"
    assert not K("-n", "kube-system", "get", "secret", f"{agent_id}.node-password.k3s", "--ignore-not-found", "-o", "name", ok=False).strip(), \
        "the revoked agent re-created its node-password Secret"
    assert s.signin(), "sign-in failed after the agent revoke"
    note(f"ha_vm_revoke_restarts: agent {agent_id} revoked, rotations proven, survivors healthy, the revoked agent can't return")

    # 2) Revoke a server (vm3). Two rotations; two servers survive.
    srv_id = VM_NODE["vm3"]
    if VM_NODE[_tunnel["server"]] == srv_id:
        retarget_api(avoid={srv_id})
    old_token2 = server_token([h for h in survivors if h != "vm3"][0])
    note(f"ha_vm_revoke_restarts: revoking the server {srv_id}")
    pc("node", "revoke", srv_id, inp=srv_id + "\n", timeout=900)
    wait_for("the server's Node gone", lambda: not any(n["metadata"]["name"] == srv_id for n in Kj("get", "nodes")["items"]), 400, 5)
    ref2 = [h for h in survivors if h != "vm3"][0]

    def creds_rotated2():
        new_token = server_token(ref2)
        assert k3s_bootstrap_status(ref2, "server", old_token2) == 401, "the old server token still answers (want 401)"
        assert k3s_bootstrap_status(ref2, "server", old_node) in (401, 0), "the old node credential still answers"
        assert k3s_bootstrap_status(ref2, "server", new_token) == 200, "the new server token doesn't answer 200"
        return True
    wait_for("the server revoke's rotations (old 401, new 200)", creds_rotated2, 400, 5)
    survivors3 = [h for h in survivors if h != "vm3"]
    restart_cycle(survivors3, survivors3[0], expect_ready=2)
    assert s.signin(), "sign-in failed after the server revoke"
    note(f"ha_vm_revoke_restarts: server {srv_id} revoked, two rotations, both survivors restart/reboot healthy")

    # 3) A surviving agent restarts on its node identity — there is no
    # surviving agent after vm4's revoke, so instead a fresh node joins with
    # a new code (vm3, wiped by the revoke, and vm4 re-enrolled).
    _rejoin_server("vm3")
    note(f"ha_vm_revoke_restarts: a new server joined with a fresh code; cluster back to 3")


def main() -> int:
    e2e_ha.SECRET = _hub_secret()  # masked by secret_read
    retarget_api()  # kubectl over an SSH tunnel to a server that answers
    state["alpine"] = helper_image()
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        state["pw"] = pw

        def signed_in():
            addr = next(a for _, site, a in ingress_public() if site == "main")
            state["session"] = Session(pw, addr)
            assert state["session"].portal_ok(), "admin's session doesn't open the portal"
        check("admin signs in (a setup link, a virtual passkey) through a main ingress node", signed_in)

        check("ha_vm_pebble_issue_sni: the front door issues from Pebble; every ingress node serves it by SNI", ha_vm_pebble_issue_sni)
        check("ha_vm_same_site_reach: same-site probes don't count; cross-site probers do", ha_vm_same_site_reach)
        check("ha_vm_partition: the minority self-fences, a writer on it fails, checksums equal the majority's", ha_vm_partition)
        check("ha_vm_power_off: the stateful app runs elsewhere within 4 min", ha_vm_power_off)
        check("ha_vm_disk_kill: a storage node's disk killed, volumes rebuild, data intact", ha_vm_disk_kill)
        check("ha_vm_disk_full: a storage node's disk filled, Longhorn reports it, volumes healthy", ha_vm_disk_full)
        check("ha_vm_lose_small: the third server lost, quorum holds, sign-in works", ha_vm_lose_small)
        check("ha_vm_rolling_upgrade: a rolling restart under the sign-in loop, ≤ 5 of 300 fail", ha_vm_rolling_upgrade)
        check("ha_vm_site_uplink_down: edge's uplink lost then main's; the other site keeps serving", ha_vm_site_uplink_down)
        check("ha_vm_site_down: edge powered off, quorum holds, its address removed but never the last", ha_vm_site_down)
        check("ha_vm_nat_relay: vm2's mesh port closed cross-site, vm2 ↔ vm4 relays through vm1, sign-in unaffected", ha_vm_nat_relay)
        check("ha_vm_front_door_node: the front door's own node cut, a new front door leads, failover recovers", ha_vm_front_door_node)
        check("ha_vm_front_door_nodeadm_one_node: the front door and nodeadm on one node, cut", ha_vm_front_door_nodeadm_one_node)
        check("ha_vm_cert_renew_leader_move: the front door's certificate renewed across a Lease move", ha_vm_cert_renew_leader_move)
        check("ha_vm_etcd_remove_member: a cooperative server removal takes its etcd member out", ha_vm_etcd_remove_member)
        check("ha_vm_interrupted_removal: a server removal interrupted by a restart resumes cleanly", ha_vm_interrupted_removal)
        check("ha_vm_revoke_restarts: revoke an agent then a server; restarts, reboots and credentials all healthy", ha_vm_revoke_restarts)

        if "session" in state:
            state["session"].close()
    return e2e_ha.report()


def helper_image() -> str:
    out = vm("vm1", "cd ~/portcullis && bash -c 'source scripts/lib/common.sh >/dev/null 2>&1; printf %s \"$PORTCULLIS_HELPER_IMAGE\"'", check=False)
    assert "@sha256:" in out, f"helper image {out!r}"
    return out.strip()


def _hub_secret() -> str:
    return secret_read("vm1", "grep '^HUB_PROXY_SECRET=' ~/portcullis/.env | cut -d= -f2-").strip()


if __name__ == "__main__":
    sys.exit(main())
