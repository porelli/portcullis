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


def pc(*args: str, inp: str | None = None, timeout: float = 600, check: bool = True) -> str:
    """./portcullis on vm1 (through its harness wrapper); inp on its stdin
    (a typed confirmation, never argv)."""
    return vm("vm1", "~/e2e-ha/pc " + " ".join(args), inp=inp, timeout=timeout, check=check)


# ── kubectl over an SSH tunnel to a surviving API server ──

_tunnel: dict = {"proc": None, "server": "", "port": 0}
import atexit  # noqa: E402
atexit.register(lambda: _stop_tunnel())  # no tunnel outlives the run (a leftover holds its port)
OPERATOR_VM = "vm1"  # the first node: the CLI, Pebble, S3 and the fake zone live there; never cut
CONN_ERRORS = ("connection to the server", "Unable to connect to the server", "connection refused", "EOF",
               "ServiceUnavailable", "unable to handle the request", "TLS handshake timeout", "i/o timeout",
               "no route to host", "context deadline exceeded", "http2: client connection lost")


_kc_fetched: list[bool] = []


def _kubeconfig() -> str:
    """The CLI's kubeconfig, fetched once per run (a copy from an earlier
    install carries another cluster CA: TLS fails)."""
    kc = os.path.join(D, "kubeconfig")
    if not _kc_fetched:
        raw = secret_read("vm1", "cat ~/portcullis/secrets/kube/kubeconfig")
        raw = re.sub(r"server: https://[0-9.]+:6443", "server: https://127.0.0.1:16443", raw)
        fd = os.open(kc, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(raw)
        os.chmod(kc, 0o600)
        _kc_fetched.append(True)
    return kc


def _api_ok() -> bool:
    """The API itself answers through the tunnel (/readyz), not just kubectl."""
    r = subprocess.run(["kubectl", "--context", "portcullis", "--server", f"https://127.0.0.1:{_tunnel['port']}",
                        "--request-timeout=6s", "get", "--raw", "/readyz"], capture_output=True, text=True, timeout=15)
    return r.returncode == 0 and r.stdout.strip() == "ok"


def _start_tunnel(server_vm: str) -> None:
    _stop_tunnel()
    port = 16440 + int(server_vm[-1])  # one local port per server: a dying tunnel never holds the next one's
    proc = subprocess.Popen([*SSH, "-N", "-o", "ExitOnForwardFailure=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                             "-L", f"127.0.0.1:{port}:{MESH[server_vm]}:6443", server_vm],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    kc = _kubeconfig()
    os.environ["KUBECONFIG"] = kc
    _tunnel.update(proc=proc, server=server_vm, port=port)
    cl = subprocess.run(["kubectl", "config", "view", "-o", "jsonpath={.contexts[?(@.name==\"portcullis\")].context.cluster}"],
                        capture_output=True, text=True, timeout=15, check=True).stdout.strip()
    assert cl, "the kubeconfig has no context portcullis"
    subprocess.run(["kubectl", "config", "set-cluster", cl, f"--server=https://127.0.0.1:{port}"],
                   capture_output=True, timeout=15, check=True)
    e2e_ha.CTX = "portcullis"
    for _ in range(30):
        if proc.poll() is not None:
            break
        if _api_ok():
            return
        time.sleep(1)
    _stop_tunnel()
    raise AssertionError(f"the API tunnel to {server_vm} didn't answer /readyz")


def _stop_tunnel() -> None:
    p = _tunnel.get("proc")
    if p:
        p.terminate()
        try:
            p.wait(5)
        except Exception:  # noqa: BLE001
            p.kill()
    _tunnel["proc"] = None


def tunnel_node() -> str:
    return VM_NODE.get(_tunnel.get("server", ""), "")


def retarget_api(avoid: set[str] | None = None) -> None:
    """kubectl through a server whose API answers /readyz, never one in
    `avoid` (node names or VM names). The current tunnel is kept when it
    still answers and isn't avoided."""
    av = set(avoid or set())
    av |= {NODE_VM[n] for n in list(av) if n in NODE_VM}
    if _tunnel.get("proc") and _tunnel["proc"].poll() is None and _tunnel["server"] not in av:
        try:
            if _api_ok():
                return
        except Exception:  # noqa: BLE001
            pass
    last = ""
    for _ in range(3):
        for h in ["vm1", "vm2", "vm3"]:
            if h in av:
                continue
            try:
                _start_tunnel(h)
                return
            except AssertionError as e:
                last = str(e)
        time.sleep(10)
    raise AssertionError(f"no API server answers (avoiding {sorted(av)}): {last}")


# e2e_ha's helpers run against the tunnel; its docker-based node kill is
# replaced by the VM host faults below.
import e2e_ha  # noqa: E402
from e2e_ha import (  # noqa: E402
    K, Kj, pods, ready, node_ready, not_ready_at, pg_primary, psql, Writer,
    published, fd_status, lease_time, lease_holder, hub, note, save,
)

_K_raw = e2e_ha.K


def _K_failover(*argv: str, inp: str | None = None, timeout: float = 120, ok: bool = True, ctx: str | None = None) -> str:
    """e2e_ha.K that moves the tunnel to another answering server once when
    the API connection itself failed (a server going down mid-drill)."""
    try:
        return _K_raw(*argv, inp=inp, timeout=timeout, ok=ok, ctx=ctx)
    except (AssertionError, subprocess.TimeoutExpired) as e:
        if not any(c in str(e) for c in CONN_ERRORS):
            raise
        print(f"  (the API through {_tunnel.get('server')} failed: moving the tunnel)", flush=True)
        retarget_api(avoid={_tunnel.get("server", "")})
        return _K_raw(*argv, inp=inp, timeout=timeout, ok=ok, ctx=ctx)


e2e_ha.K = _K_failover
K = _K_failover

results = e2e_ha.results
state = e2e_ha.state
timings = e2e_ha.timings
NS, PG_NS, PG = e2e_ha.NS, e2e_ha.PG_NS, e2e_ha.PG


def check(name: str, fn) -> None:
    if scenarios.skip(name):
        return
    t0 = time.time()
    try:
        retarget_api()
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
last_cut: dict[str, float] = {}  # node → when a drill last cut it (nodeadm's 20 min remediation back-off)


def boot_id(h: str) -> str:
    return vm(h, "cat /proc/sys/kernel/random/boot_id", check=False, timeout=15, mux=False).strip()


def node_vm(node: str) -> str:
    return NODE_VM[node]


def partition(node: str) -> float:
    """Every packet but SSH (and the machine's own metadata / DHCP) dropped
    both ways on the node: a real partition, so it loses the API and its
    peers and self-fences."""
    h = node_vm(node)
    assert h != OPERATOR_VM, f"refusing to cut {node}: vm1 is the operator and fixture host"
    retarget_api(avoid={node})
    host(h, "net set partition")
    cut[node] = "partition"
    last_cut[node] = time.time()
    return time.time()


def power_off(node: str) -> float:
    h = node_vm(node)
    assert h != OPERATOR_VM, f"refusing to power off {node}: vm1 is the operator and fixture host"
    retarget_api(avoid={node})
    b0 = boot_id(h)
    host(h, "dark", check=False)  # it reboots at once; the SSH call may not return cleanly
    cut[node] = "dark"
    last_cut[node] = time.time()
    for _ in range(60):
        b = boot_id(h)
        if b and b != b0:
            return time.time()
        time.sleep(2)
    return time.time()


def heal(node: str) -> None:
    h = node_vm(node)
    kind = cut.get(node, "")
    # Never silent: a heal that didn't happen leaves the node cut and every
    # later drill on a broken cluster (run 45892504006: SSH to vm1 refused,
    # the heal ignored, two servers left dark, etcd without quorum).
    last = ""
    for _ in range(10):
        try:
            if kind == "dark":
                vm(h, "sudo e2e-ha-host light", timeout=60, mux=False)
            else:
                host(h, "net clear")
            st = host_state(h)
            assert not st["dark"] and not st["net"] and st["live_rules"] == 0, f"{h} still cut: {st}"
            cut.pop(node, None)
            return
        except (AssertionError, subprocess.TimeoutExpired) as e:
            last = str(e)
            time.sleep(10)
    raise AssertionError(f"couldn't heal {node} ({h}): {last}")


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


def fixtures_ok() -> None:
    """vm1's fixtures answer (the fake zone, Pebble, the S3 server): a dead
    one fails every drill in confusing ways (run 2: the zone down, every
    front-door round skipped, every probe verdict "none")."""
    priv = VMS[OPERATOR_VM]["private"]
    out = vm(OPERATOR_VM, f"curl -s -o /dev/null -w '%{{http_code}} ' -X POST -d '{{}}' http://{priv}:8054/; "
             f"curl -sk -o /dev/null -w '%{{http_code}} ' https://{priv}:14443/dir; curl -s -o /dev/null -w '%{{http_code}}' http://{priv}:9100/",
             check=False, timeout=40).split()
    assert len(out) == 3 and out[0] != "000" and out[1] == "200" and out[2] != "000", \
        f"vm1's fixtures don't all answer (fake zone, Pebble, S3: {out}): `docker ps -a` on vm1"


def settle(timeout: float = 900) -> None:
    """Between scenarios: every cut healed, the API reachable, every node
    Ready and schedulable, core workloads at their replicas, CNPG healthy,
    Longhorn volumes attached and healthy."""
    for node in list(cut):
        heal(node)
    # The node mesh and k3s take a moment after a fenced node reboots.
    retarget_api()
    fixtures_ok()

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
    """`total` sign-ins; actions = [(i, fn)] run at request i. Each failure
    is recorded with its time and the page it ended on (no query string).
    Returns the number failed."""
    failed, fails = 0, []
    acts = dict(actions)
    t0 = time.time()
    for i in range(total):
        if i in acts:
            acts[i]()
        if not s.signin():
            failed += 1
            fails.append((i, round(time.time() - t0, 1), s.page.url.split("?")[0][:120]))
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
    # On the storage nodes only, as the replicated tier's own pods: Longhorn
    # has no disk or CSI topology elsewhere (run 2: scheduled on the edge
    # agent, "no topology key found for node vm4", the claim never bound).
    sp["nodeSelector"] = {"portcullis.io/storage": "true"}
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
    return fresh_victim(avoid, need_fence=False)


def ha_vm_partition() -> None:
    """The minority self-fences within T_fence; a writer on it fails; the
    test app's data afterwards is the majority's. A writer (the test app on
    the replicated tier) runs on the victim; the victim is partitioned (every
    packet but SSH dropped, kept across its reboot). Pass: it reboots by its
    watchdog within T_fence (150 s); the app runs on the majority; the
    minority writer's last line in the data is no later than its fence (it
    failed: nothing it wrote after the cut survives as acknowledged history
    beyond the fence), the log is one history (no gap, repeat or overlap of
    writers) and the marker's md5 is unchanged."""
    victim = fresh_victim()
    p0 = writer_start(victim)
    h = node_vm(victim)
    b0 = boot_id(h)
    note(f"ha_vm_partition: partitioning {victim} ({h}) with the writer {p0['metadata']['name']} on it")
    t = partition(victim)
    try:
        tf = self_fenced(h, b0, 240)
        note(f"ha_vm_partition: {victim} self-fenced (rebooted) {tf - t:.0f} s after the partition")
        assert tf - t <= 150 + 10, f"self-fenced {tf - t:.0f} s after the partition (T_fence 150 s)"
        p1 = writer_elsewhere(p0, victim, 420)
        t_mv = time.time()
        time.sleep(8)
        rows = writer_log(p1["metadata"]["name"])
    finally:
        heal(victim)
    old = [r for r in rows if r[2] == p0["metadata"]["name"]]
    new = [r for r in rows if r[2] == p1["metadata"]["name"]]
    assert old and new, f"the log lacks a writer (old {len(old)} lines, new {len(new)})"
    log_consistent(rows)
    assert old[-1][1] <= int(tf) + 2, f"the minority writer's line at {old[-1][1]} survives past its fence at {int(tf)}"
    note(f"ha_vm_partition: the writer ran on {p1['spec']['nodeName']} {t_mv - t:.0f} s after the cut; the minority's last kept line "
         f"{old[-1][1] - int(t):+d} s from the cut, the majority's first {new[0][1] - int(t):+d} s; {len(rows)} lines, one history")
    writer_stop()
    settle()
    md5 = marker_read()
    assert md5 == state["marker_md5"], f"the marker changed: {md5} != {state['marker_md5']}"


def marker_app(prefer: str) -> dict:
    """The stateful test app: a Deployment (1 replica, Recreate) on the
    marker's replicated-tier claim, preferring `prefer`, never on vm1's
    node (the operator host stays up), tolerating a dead node for 30 s like
    the HA pods (§3.4)."""
    pod = marker_pod("x")["spec"]
    pod.pop("nodeName", None)
    pod["restartPolicy"] = "Always"
    pod["affinity"] = {"nodeAffinity": {
        "requiredDuringSchedulingIgnoredDuringExecution": {"nodeSelectorTerms": [{"matchExpressions": [
            {"key": "kubernetes.io/hostname", "operator": "NotIn", "values": [VM_NODE[OPERATOR_VM]]},
            {"key": "node-role.kubernetes.io/control-plane", "operator": "In", "values": ["true"]}]}]},
        "preferredDuringSchedulingIgnoredDuringExecution": [{"weight": 100, "preference": {"matchExpressions": [
            {"key": "kubernetes.io/hostname", "operator": "In", "values": [prefer]}]}}]}}
    pod["tolerations"] = [{"key": k, "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": 30}
                          for k in ("node.kubernetes.io/unreachable", "node.kubernetes.io/not-ready")]
    return {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "marker-app", "namespace": MARKER_NS},
            "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": {"app": "e2e-marker-app"}},
                     "template": {"metadata": {"labels": {"app": "e2e-marker-app"}}, "spec": pod}}}


def ha_vm_power_off() -> None:
    """A node powered off (sysrq reboot held dark): its stateful app runs
    elsewhere within 4 min, its data one history and the marker unchanged;
    Postgres' committed rows all there."""
    victim = fresh_victim()
    p0 = writer_start(victim)
    psql(pg_primary(), "DROP TABLE IF EXISTS e2e_ha_rows; CREATE TABLE e2e_ha_rows (n int PRIMARY KEY, at timestamptz DEFAULT now());")
    w = Writer()
    w.start()
    try:
        wait_for("the Postgres writer's first rows", lambda: len(w.committed) >= 5, 60, 1)
        note(f"ha_vm_power_off: powering off {victim} ({node_vm(victim)}), the writer's node")
        t = power_off(victim)
        tn = not_ready_at(victim, t, timeout=120)
        p1 = writer_elsewhere(p0, victim, 330)
        d = time.time() - t
        time.sleep(5)
        rows = writer_log(p1["metadata"]["name"])
        log_consistent(rows)
        note(f"ha_vm_power_off: {victim} off → NotReady after {tn - t:.0f} s → the app Ready on {p1['spec']['nodeName']} "
             f"{d:.0f} s after the power-off; {len(rows)} lines, one history")
        assert d <= 240, f"the stateful app took {d:.0f} s to run elsewhere (> 4 min)"
    finally:
        w.stop.set()
        w.join(15)
        heal(victim)
        writer_stop()
    settle()
    want = {n for n, _ in w.committed}
    got = {int(x) for x in psql(pg_primary(), "SELECT n FROM e2e_ha_rows;").split()}
    assert not (want - got), f"committed rows lost: {sorted(want - got)[:20]}"
    psql(pg_primary(), "DROP TABLE e2e_ha_rows;")
    md5 = marker_read()
    assert md5 == state["marker_md5"], f"the marker changed: {md5} != {state['marker_md5']}"


def lh_node_disks(node: str) -> list[dict]:
    try:
        n = lh("get", "nodes.longhorn.io", node)
    except Exception:  # noqa: BLE001
        return []
    return list((n.get("status", {}).get("diskStatus") or {}).values())


def ha_vm_disk_kill() -> None:
    """A storage node's Longhorn disk killed (device-mapper error: every
    I/O fails) under a writing app with a replica on it: Longhorn fails that
    replica and rebuilds one on another node, the volume healthy again, the
    app kept writing (one history), the marker unchanged (≤ 10 min).
    Longhorn sees a dead disk through its replicas' I/O, not its node disk
    conditions (run 3: the conditions stayed Ready on an idle volume)."""
    app_node = fresh_victim(need_fence=False)
    p0 = writer_start(app_node)
    vol = lh_volume_of_claim(MARKER_NS, MARKER_PVC)
    reps = wait_for("the volume's replicas running", lambda: (lambda r: r if len(r) >= 2 and all(x.get("status", {}).get("currentState") == "running" for x in r) else None)(lh_replicas(vol)), 300, 5)
    nodes = [r["spec"]["nodeID"] for r in reps]
    victim = next((n for n in nodes if n not in (app_node, VM_NODE[OPERATOR_VM])), None) or \
        next((n for n in nodes if n != VM_NODE[OPERATOR_VM]), None)
    assert victim, f"every replica of the test volume is on vm1: {nodes}"
    h = node_vm(victim)
    dead = next(r["metadata"]["name"] for r in reps if r["spec"]["nodeID"] == victim)
    note(f"ha_vm_disk_kill: the writer on {app_node}; replicas on {nodes}; killing {victim}'s disk (replica {dead[:28]}…)")
    t = time.time()
    host(h, "disk", "kill")
    last_cut[victim] = t
    try:
        def rebuilt():
            rs = lh_replicas(vol)
            failed = any(r["metadata"]["name"] == dead and (r["spec"].get("failedAt") or r.get("status", {}).get("currentState") != "running") for r in rs) \
                or not any(r["metadata"]["name"] == dead for r in rs)
            live = [r for r in rs if r["spec"]["nodeID"] != victim and r.get("status", {}).get("currentState") == "running" and not r["spec"].get("failedAt")]
            v = lh("get", "volumes.longhorn.io", vol)
            healthy = v.get("status", {}).get("robustness") == "healthy"
            return failed and len(live) >= 2 and healthy
        wait_for("the dead disk's replica replaced on another node and the volume healthy", rebuilt, 600, 10)
        d = time.time() - t
        p = writer_pod()
        rows = writer_log(p["metadata"]["name"])
        log_consistent(rows)
        assert rows[-1][1] >= int(t) + 10, "the app stopped writing after the disk died"
        note(f"ha_vm_disk_kill: {victim}'s replica failed and rebuilt elsewhere, the volume healthy {d:.0f} s after the kill; "
             f"the app kept writing ({len(rows)} lines, one history)")
    finally:
        writer_stop()
        # The disk comes back at the node's boot (e2e-ha-disk: fsck, then the
        # linear table again).
        vm(h, "sudo systemctl reboot", check=False, timeout=30, mux=False)
    time.sleep(30)
    retarget_api()
    settle()
    md5 = marker_read()
    assert md5 == state["marker_md5"], f"the marker changed: {md5} != {state['marker_md5']}"


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
    """The third server lost (D9's small third voter; a cloud server in
    this bundle): quorum holds (2/3), a write through the Hub succeeds, and
    sign-in keeps working: 60 sign-ins across the outage, at most 3 failed,
    each failure's page and time recorded."""
    small = next((v["node"] for v in INV["vms"] if v.get("vm") == "vm3"), SERVERS[-1])
    s: Session = state["session"]
    note(f"ha_vm_lose_small: powering off {small} ({node_vm(small)}) under 60 sign-ins")
    t = power_off(small)
    try:
        failed = signin_loop(s, 60, [])
        not_ready_at(small, t, timeout=120)
        wait_for("the API still serves (quorum 2/3)", lambda: bool(K("get", "--raw", "/readyz", ok=False, timeout=10)), 60, 2)
        g = "e2e-ha-small-" + str(int(time.time()) % 100000)
        code, _ = hub("POST", "/api/directory/groups", {"name": g})
        assert code in (200, 201), f"a write failed with the third server down: {code}"
        hub("DELETE", f"/api/directory/groups/{g}", {"confirm": g})
        assert failed <= 3, f"{failed} of 60 sign-ins failed with the third server down (> 3)"
        note(f"ha_vm_lose_small: {small} down → the API, a write and sign-in work (quorum 2/3; {failed} of 60 sign-ins failed)")
    finally:
        heal(small)
    settle()
    wait_for(f"{small} Ready again", lambda: node_ready(small), 300, 5)


def rollout_restart(name: str, ns: str = NS) -> None:
    K("-n", ns, "rollout", "restart", f"{workload_kind(name, ns)}/{name}")


def ha_vm_rolling_upgrade() -> None:
    """A rolling restart of Keycloak, group-gate and forward-auth (each by
    its real kind: in HA group-gate is a StatefulSet) under 300 sign-ins:
    at most 5 fail."""
    s: Session = state["session"]
    names = ("keycloak", "group-gate", "forward-auth")
    kinds = {n: workload_kind(n) for n in names}
    note(f"ha_vm_rolling_upgrade: a rolling restart of {', '.join(f'{k}/{n}' for n, k in kinds.items())} under 300 sign-ins")
    failed = signin_loop(s, 300, [(20, lambda: rollout_restart("keycloak")), (120, lambda: rollout_restart("group-gate")),
                                  (200, lambda: rollout_restart("forward-auth"))])
    for n, k in kinds.items():
        K("-n", NS, "rollout", "status", f"{k}/{n}", "--timeout=300s", timeout=320, ok=False)
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
        assert e2e_ha.served_fp(main_addrs[0], f"auth.{DOMAIN}"), "main stopped serving"
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


def wg_route(src_vm: str, mesh_ip: str) -> str:
    """The pcmesh peer on src_vm whose allowed IPs carry mesh_ip: that
    peer's own mesh address (direct when it is mesh_ip itself)."""
    for ln in vm(src_vm, "sudo wg show pcmesh allowed-ips", timeout=20).splitlines():
        parts = ln.split()
        nets = parts[1:]
        if f"{mesh_ip}/32" in nets:
            own = next((n.split("/")[0] for n in nets if n.endswith("/32") and n.split("/")[0] in MESH.values() and n != f"{mesh_ip}/32"), mesh_ip)
            return own if len(nets) > 1 else mesh_ip
    return ""


def ha_vm_nat_relay() -> None:
    """(controller ruling, run 3 triage: the product as designed.) vm2
    behind a real NAT (NEW inbound UDP 51830 from outside its LAN dropped,
    replies kept: vm-host.sh natmesh), then vm4 too: vm2 ↔ vm4 keeps working
    in both directions at every check over 3 min each (the mesh plan has
    vm2 dial vm4 directly; behind two NATs the fixed ports punch through),
    the path vm4 uses to reach vm2 is recorded, and sign-in is unaffected.
    Reviewed deviation: the relay through vm1 (the plan's NAT↔NAT pair) is
    the meshplan unit vectors': on this layout the Hub keeps proving vm4's
    endpoint by vm4's own handshakes, so it never plans that relay."""
    s: Session = state["session"]
    assert mesh_ping("vm2", MESH["vm4"]) and mesh_ping("vm4", MESH["vm2"]), "vm2 ↔ vm4 don't ping before the cut"
    paths = {"before": wg_route("vm4", MESH["vm2"])}
    try:
        for step, nodes in (("vm2 behind a NAT", ["vm2"]), ("vm2 and vm4 behind a NAT", ["vm2", "vm4"])):
            for h in nodes:
                host(h, "net", "set", f"natmesh:{LAN_CIDR}")
            t = time.time()
            fails = 0
            while time.time() - t < 180:
                if not (mesh_ping("vm2", MESH["vm4"]) and mesh_ping("vm4", MESH["vm2"])):
                    fails += 1
                time.sleep(15)
            paths[step] = wg_route("vm4", MESH["vm2"])
            assert fails == 0, f"{step}: vm2 ↔ vm4 failed {fails} checks over 3 min"
            assert s.signin(), f"{step}: sign-in failed"
            note(f"ha_vm_nat_relay: {step}: vm2 ↔ vm4 kept working for 3 min (vm4 reaches vm2 via "
                 f"{'direct' if paths[step] == MESH['vm2'] else paths[step] or '?'}); sign-in unaffected")
    finally:
        for h in ("vm2", "vm4"):
            host(h, "net", "clear", check=False)
    note(f"ha_vm_nat_relay: paths {paths}")
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
    # (Its top-level "ha" is a flag, not an object: the items are found by shape.)
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
    """(carry) A server's etcd member removed by the cluster (nodeadm →
    a surviving server's nodeagent POST /v1/etcd/remove-member), judged on
    the REAL member list (k3s' etcd JSON API) around revoke_restarts' server
    revoke: three members → the revoked one gone (two) → three again with
    the fresh server. (A cooperative removal below three servers is refused
    by design: `removing <node> would leave fewer than 3 servers`.)"""
    needs("etcd_revoke", "etcd_rejoin")
    ev = state["etcd_revoke"]
    assert len(ev["before"]) == 3 and member_of(ev["node"], ev["before"]), f"etcd before the revoke: {ev['before']}"
    assert len(ev["after"]) == 2 and not member_of(ev["node"], ev["after"]), f"etcd after the revoke: {ev['after']}"
    assert len(state["etcd_rejoin"]) == 3, f"etcd after the rejoin: {state['etcd_rejoin']}"
    note(f"ha_vm_etcd_remove_member: {ev['before']} → {ev['after']} → {state['etcd_rejoin']}")


def ha_vm_interrupted_removal() -> None:
    """A removal interrupted and resumed (redesign, controller ruling: a
    server removal below 3 servers is refused by design, so the agent):
    `node remove` of the agent, the Hub restarted while it runs, the
    operation's state read, `node remove` again → the node gone cleanly (its
    Node, no leftover op); then it joins again with a fresh code."""
    agent = VM_NODE[EDGE_VM]
    note(f"ha_vm_interrupted_removal: removing {agent}, the Hub restarted mid-way, then the removal again")
    logf = tempfile.NamedTemporaryFile("w+", prefix="remove-", dir=D, delete=False)
    p = subprocess.Popen([*SSH, OPERATOR_VM, f"~/e2e-ha/pc node remove {agent}"], stdin=subprocess.PIPE, stdout=logf,
                         stderr=subprocess.STDOUT, text=True)
    p.stdin.write(agent + "\n")
    p.stdin.close()
    try:
        def underway() -> bool:
            # A CLI that already ended refused or failed: its output says why.
            assert p.poll() is None, f"node remove {agent} ended early (exit {p.returncode}): {redact(open(logf.name).read())[-600:]}"
            return Kj("get", "node", agent)["spec"].get("unschedulable") is True
        wait_for(f"{agent} cordoned (removal underway)", underway, 240, 2)
        hubp = next(x for x in pods(NS, "portcullis.io/component=hub") if ready(x))
        K("-n", NS, "delete", "pod", hubp["metadata"]["name"], "--wait=false")
        note(f"  the Hub {hubp['metadata']['name']} restarted while the removal ran")
        p.wait(900)
    finally:
        if p.poll() is None:
            p.terminate()
    first = redact(open(logf.name).read())
    os.unlink(logf.name)
    note(f"  the first removal ended (exit {p.returncode}): {first.strip().splitlines()[-1][:200] if first.strip() else '(no output)'}")
    wait_for("the Hub answering again", lambda: hub("GET", "/api/directory/users/e2e-ha-pub")[0] in (200, 404), 600, 5)
    if any(n["metadata"]["name"] == agent for n in Kj("get", "nodes")["items"]):
        out = pc("node", "remove", agent, inp=agent + "\n", timeout=900, check=False)
        note(f"  the removal again: {redact(out).strip().splitlines()[-1][:200] if out.strip() else '(no output)'}")
    wait_for(f"{agent} gone", lambda: not any(n["metadata"]["name"] == agent for n in Kj("get", "nodes")["items"]), 400, 5)
    lst = pc("node", "list")
    assert agent not in [ln.split()[0] for ln in lst.splitlines()[1:] if ln.split()], f"{agent} still listed after its removal: {lst}"
    note(f"ha_vm_interrupted_removal: {agent} removed cleanly after the interrupted first run")
    rejoin(EDGE_VM, "agent", VMS[EDGE_VM]["site"], f"--public-endpoint {VMS[EDGE_VM]['public']}:51830")


SINGLETONS = {"frontdoor": (NS, "portcullis.io/component=frontdoor"),
              "nodeadm": ("portcullis-nodeadm", "portcullis.io/component=nodeadm")}


def singleton(kind: str) -> dict | None:
    ns, sel = SINGLETONS[kind]
    return next((p for p in pods(ns, sel) if ready(p)), None)


def place(target: str, kinds: list[str]) -> None:
    """Each singleton of `kinds` Ready on `target` (the other servers
    cordoned while its pod is deleted, then uncordoned)."""
    others = [n for n in SERVERS if n != target]
    for kind in kinds:
        cur = singleton(kind)
        if cur and cur["spec"].get("nodeName") == target:
            continue
        for n in others:
            K("cordon", n)
        try:
            ns, sel = SINGLETONS[kind]
            if cur:
                K("-n", ns, "delete", "pod", cur["metadata"]["name"], "--wait=false")
            wait_for(f"{kind} Ready on {target}", lambda kind=kind: (lambda p: p and p["spec"].get("nodeName") == target)(singleton(kind)), 300, 5)
        finally:
            for n in others:
                K("uncordon", n)


def away(node: str, kinds: list[str]) -> None:
    """Each singleton of `kinds` off `node` (onto another non-vm1 server)."""
    for kind in kinds:
        cur = singleton(kind)
        if cur and cur["spec"].get("nodeName") == node:
            place(next(n for n in SERVERS if n not in (node, VM_NODE[OPERATOR_VM])), [kind])


def ha_vm_front_door_node() -> None:
    """(33a N1) The front door's own node cut: a new front door takes the
    Lease on another server and DNS failover still works: the cut node's
    address goes, the others stay, never the last."""
    victim = victim_server(set())
    place(victim, ["frontdoor"])
    away(victim, ["nodeadm"])  # this drill is the front door alone; nodeadm's case is the next one
    by = ingress_public()
    names = [DOMAIN, f"*.{DOMAIN}"]
    want = sorted(a for _, _, a in by)
    wait_for("every ingress address published", lambda: all(published().get(n) == want for n in names), 420, 5)
    leader0 = fd_status().get("leader")
    rest = sorted(a for node, _s, a in by if node != victim)
    note(f"ha_vm_front_door_node: cutting {victim}, the front door's own node (leader {leader0})")
    t = partition(victim)
    try:
        wait_for("a new front door leads on another node", lambda: (lambda p: p and p["spec"].get("nodeName") != victim
                 and fd_status().get("leader") == p["metadata"]["name"] != leader0)(singleton("frontdoor")), 300, 5)
        t_lead = time.time()

        def removed():
            pub = published()
            for n in names:
                got = pub.get(n) or []
                assert not got or set(rest) <= set(got), f"{n} lost a live node's address: {got}"
            return all(published().get(n) == rest for n in names)
        wait_for(f"{victim}'s address removed by the new front door, the others kept", removed, 300, 3)
        note(f"ha_vm_front_door_node: new front door {fd_status().get('leader')} led {t_lead - t:.0f} s after the cut; "
             f"the address went {time.time() - t:.0f} s after the cut; {rest} kept")
    finally:
        heal(victim)
    settle()


def ha_vm_front_door_nodeadm_one_node() -> None:
    """(33a N1) The front door and nodeadm on one node (about one install
    in three, both singletons on the servers), that node cut: both come
    back elsewhere, then the dead node's address goes; the others are kept
    throughout (fail static while there is no snapshot)."""
    victim = victim_server(set())
    place(victim, ["frontdoor", "nodeadm"])
    by = ingress_public()
    names = [DOMAIN, f"*.{DOMAIN}"]
    want = sorted(a for _, _, a in by)
    wait_for("every ingress address published", lambda: all(published().get(n) == want for n in names), 420, 5)
    rest = sorted(a for node, _s, a in by if node != victim)
    note(f"ha_vm_front_door_nodeadm_one_node: cutting {victim} (front door + nodeadm)")
    t = partition(victim)
    try:
        def others_kept_until_back():
            pub = published()
            for n in names:
                got = pub.get(n) or []
                assert not got or set(rest) <= set(got), f"{n} lost a live node's address: {got}"
            fd, na = singleton("frontdoor"), singleton("nodeadm")
            return fd and na and fd["spec"].get("nodeName") != victim and na["spec"].get("nodeName") != victim
        wait_for("the front door and nodeadm both Ready elsewhere (the others kept meanwhile)", others_kept_until_back, 360, 3)
        t_back = time.time()
        wait_for(f"{victim}'s address removed", lambda: all(published().get(n) == rest for n in names), 300, 3)
        note(f"ha_vm_front_door_nodeadm_one_node: both back elsewhere {t_back - t:.0f} s after the cut, "
             f"the address removed {time.time() - t:.0f} s after the cut; {rest} kept")
    finally:
        heal(victim)
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
    """The agent-token fix's proof (2026-11-22): revoke the agent, then a
    server (two rotations). After each: every surviving server restarted
    one at a time, then together, then one host rebooted, each back with no
    fatal; passwd byte-equal (by sha256), node == server, no
    --agent-token-file; the old server token 401, the new 200; the revoked
    node can't return. Before the agent's revoke, it restarts on its node
    identity; after the server's, a fresh server joins with a new code. The
    server revoke's etcd member removal is recorded for
    ha_vm_etcd_remove_member (the real member list)."""
    survivors = live_server_vms()
    assert len(survivors) == 3, f"need three servers: {survivors}"
    s: Session = state["session"]
    ref = next(h for h in survivors if h != "vm3")
    old_token = server_token(ref)
    assert old_token, "couldn't read the server token"
    # The agent restarts on its node identity (its bootstrap token is gone
    # once it joined).
    agent_id = VM_NODE[EDGE_VM]
    vm(EDGE_VM, "sudo systemctl restart k3s-agent", timeout=120, mux=False)
    wait_for(f"{agent_id} Ready after a restart on its node identity", lambda: node_ready(agent_id), 180, 5)
    # 1) Revoke the agent.
    note(f"ha_vm_revoke_restarts: revoking the agent {agent_id}")
    pc("node", "revoke", agent_id, inp=agent_id + "\n", timeout=900)
    wait_for("the agent's Node gone", lambda: not any(n["metadata"]["name"] == agent_id for n in Kj("get", "nodes")["items"]), 300, 5)

    def rotated(h, old):
        new = server_token(h)
        assert k3s_bootstrap_status(h, "server", old) == 401, "the old server token still answers (want 401)"
        assert k3s_bootstrap_status(h, "server", new) == 200, "the new server token doesn't answer 200"
        return True
    wait_for("the k3s tokens rotated (old 401, new 200)", lambda: rotated(ref, old_token), 300, 5)
    restart_cycle(survivors, next(h for h in survivors if h != OPERATOR_VM), expect_ready=3)
    vm(EDGE_VM, "sudo systemctl restart k3s-agent 2>/dev/null; true", check=False, timeout=60, mux=False)
    time.sleep(30)
    assert not any(n["metadata"]["name"] == agent_id for n in Kj("get", "nodes")["items"]), "the revoked agent re-registered its Node"
    assert not K("-n", "kube-system", "get", "secret", f"{agent_id}.node-password.k3s", "--ignore-not-found", "-o", "name", ok=False).strip(), \
        "the revoked agent re-created its node-password Secret"
    assert s.signin(), "sign-in failed after the agent revoke"
    note(f"ha_vm_revoke_restarts: agent {agent_id} revoked; rotations proven; the survivors restarted, together and rebooted, healthy; it can't return")
    # 2) Revoke a server (vm3), two rotations; the real etcd member list.
    srv_id = VM_NODE["vm3"]
    before = etcd_member_names(ref)
    old_token2 = server_token(ref)
    note(f"ha_vm_revoke_restarts: revoking the server {srv_id} (etcd members {before})")
    pc("node", "revoke", srv_id, inp=srv_id + "\n", timeout=900)
    wait_for("the server's Node gone", lambda: not any(n["metadata"]["name"] == srv_id for n in Kj("get", "nodes")["items"]), 400, 5)
    wait_for("the server revoke's rotations (old 401, new 200)", lambda: rotated(ref, old_token2), 400, 5)
    after = wait_for("its etcd member removed", lambda: (lambda m: m if not member_of(srv_id, m) else None)(etcd_member_names(ref)), 300, 5)
    state["etcd_revoke"] = {"node": srv_id, "before": before, "after": after}
    survivors3 = [h for h in survivors if h != "vm3"]
    restart_cycle(survivors3, next(h for h in survivors3 if h != OPERATOR_VM), expect_ready=2)
    assert s.signin(), "sign-in failed after the server revoke"
    note(f"ha_vm_revoke_restarts: server {srv_id} revoked, two rotations, etcd {before} → {after}; both survivors healthy")
    # A fresh server joins with a new code; etcd back to three members.
    new_id = rejoin("vm3", "server", "main")
    state["etcd_rejoin"] = wait_for("etcd three members again", lambda: (lambda m: m if len(m) == 3 and member_of(new_id, m) else None)(etcd_member_names(ref)), 300, 5)


def fresh_victim(avoid=frozenset(), need_fence: bool = True) -> str:
    """A main storage server (never vm1), the one cut longest ago. With
    need_fence (the drill needs nodeadm to fence it): never one cut within
    the remediation back-off (nodeadm/remediate.go remediationBackoff, 20
    min; run 3's power_off reused vm2 4 min after the partition: no
    fencing, the volume never detached); the run waits instead, and says so."""
    cands = [n for n in storage_servers() if n not in avoid and n != VM_NODE[OPERATOR_VM]]
    assert cands, f"no storage server outside vm1 and {sorted(avoid)}"
    n = min(cands, key=lambda c: last_cut.get(c, 0.0))
    if need_fence:
        wait = last_cut.get(n, 0.0) + BACKOFF_S - time.time()
        if wait > 0:
            note(f"  {n} was cut {(time.time() - last_cut[n]) / 60:.0f} min ago: waiting {wait / 60:.1f} min for nodeadm's remediation back-off")
            time.sleep(wait)
    return n


BACKOFF_S = 21 * 60


WRITER = ('n=$(tail -n1 /data/log 2>/dev/null | cut -d" " -f1); n=${n:-0}; '
          'while :; do n=$((n+1)); echo "$n $(date +%s) $HOSTNAME" >> /data/log && sync; sleep 1; done')


def writer_app(prefer: str) -> dict:
    """The stateful test app: a Deployment (1 replica, Recreate) on the
    marker's replicated-tier claim that appends `seq epoch pod` to /data/log
    every second (synced), on the storage servers but never vm1, preferring
    `prefer`; HA pods' 30 s toleration of a dead node (§3.4)."""
    d = marker_app(prefer)
    c = d["spec"]["template"]["spec"]["containers"][0]
    c["command"] = ["sh", "-c", WRITER]
    d["metadata"]["name"] = "writer-app"
    d["spec"]["selector"] = {"matchLabels": {"app": "e2e-writer"}}
    d["spec"]["template"]["metadata"]["labels"] = {"app": "e2e-writer"}
    return d


def writer_pod() -> dict | None:
    return next((p for p in Kj("-n", MARKER_NS, "get", "pods", "-l", "app=e2e-writer")["items"]
                 if not p["metadata"].get("deletionTimestamp")), None)


def writer_start(prefer: str) -> dict:
    marker_setup()
    K("apply", "-f", "-", inp=json.dumps(writer_app(prefer)))
    p = wait_for(f"the writer Ready on {prefer}", lambda: (lambda p: p if p and ready(p) and p["spec"].get("nodeName") == prefer else None)(writer_pod()), 300, 5)
    wait_for("the writer's first lines", lambda: len(writer_log(p["metadata"]["name"])) >= 3, 60, 2)
    return p


def writer_log(pod: str) -> list[tuple[int, int, str]]:
    out = K("-n", MARKER_NS, "exec", pod, "--", "cat", "/data/log", ok=False, timeout=30)
    rows = []
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            rows.append((int(parts[0]), int(parts[1]), parts[2]))
    return rows


def writer_elsewhere(old: dict, victim: str, timeout: float) -> dict:
    def moved():
        p = writer_pod()
        return p if p and p["metadata"]["uid"] != old["metadata"]["uid"] and ready(p) and p["spec"].get("nodeName") != victim else None
    return wait_for("the writer Running elsewhere", moved, timeout, 3)


def log_consistent(rows: list[tuple[int, int, str]]) -> None:
    """One history: seq strictly 1, 2, 3, … (a gap or a repeat = lost or
    forked writes), each writer's lines contiguous, and the writers' time
    spans never overlap (two writers never wrote at once)."""
    assert rows, "the writer's log is empty"
    seqs = [r[0] for r in rows]
    bad = [(a, b) for a, b in zip(seqs, seqs[1:]) if b != a + 1]
    assert not bad and seqs[0] == 1, f"the log isn't one history (breaks at {bad[:5]}, starts at {seqs[0]})"
    spans: dict[str, list[int]] = {}
    order: list[str] = []
    for _, t, w in rows:
        if w not in spans:
            order.append(w)
            spans[w] = [t, t]
        spans[w][1] = t
        assert w == order[-1], f"writer {w} wrote again after {order[-1]} took over"
    for a, b in zip(order, order[1:]):
        assert spans[a][1] <= spans[b][0], f"writers {a} and {b} overlap ({spans[a]} / {spans[b]})"


def writer_stop() -> None:
    K("-n", MARKER_NS, "delete", "deployment", "writer-app", "--wait=false", ok=False)


def lh_volume_of_claim(ns: str, claim: str) -> str:
    return Kj("-n", ns, "get", "pvc", claim)["spec"]["volumeName"]


def lh_replicas(volume: str) -> list[dict]:
    return [r for r in lh("get", "replicas.longhorn.io")["items"] if r["spec"].get("volumeName") == volume]


def workload_kind(name: str, ns: str = NS) -> str:
    for kind in ("statefulset", "deployment"):
        if K("-n", ns, "get", kind, name, "--ignore-not-found", "-o", "name", ok=False).strip():
            return kind
    raise AssertionError(f"no StatefulSet or Deployment {name} in {ns}")


def rename_node(vmn: str, new_id: str) -> None:
    """vmn's node is now new_id (a removed or revoked name never re-enrols:
    the rejoin takes a fresh id); every map follows."""
    old = VM_NODE.get(vmn)
    if old in NODE_VM:
        del NODE_VM[old]
    NODE_VM[new_id] = vmn
    VM_NODE[vmn] = new_id
    if old in SERVERS:
        SERVERS[SERVERS.index(old)] = new_id


def fresh_id(vmn: str) -> str:
    base = VMS[vmn]["node"]
    taken = {n["metadata"]["name"] for n in Kj("get", "nodes")["items"]}
    for i in range(2, 20):
        cand = f"{base}-{i}"
        if cand not in taken:
            return cand
    raise AssertionError(f"no fresh id for {vmn}")


def wipe_node(vmn: str) -> None:
    """A node's k3s and nodeagent leftovers gone (after its removal or
    revoke), without a reboot: what a fresh machine would be."""
    vm(vmn, "sudo bash -c 'systemctl disable --now portcullis-nodeagent k3s k3s-agent >/dev/null 2>&1; "
            "[ -x /usr/local/bin/k3s-agent-uninstall.sh ] && /usr/local/bin/k3s-agent-uninstall.sh >/dev/null 2>&1; "
            "[ -x /usr/local/bin/k3s-uninstall.sh ] && /usr/local/bin/k3s-uninstall.sh >/dev/null 2>&1; "
            "ip link del pcmesh 2>/dev/null; rm -rf /usr/local/lib/portcullis /var/lib/portcullis /etc/rancher /var/lib/rancher "
            "/etc/wireguard/pcmesh.conf /etc/wireguard/pcmesh.key /etc/systemd/system/portcullis-nodeagent.service; "
            "systemctl daemon-reload; true'", timeout=300, mux=False)


def rejoin(vmn: str, role: str, site: str, extra: str = "") -> str:
    """vmn joined again under a fresh id (its old name is burned): the
    code from node add on the node's stdin into a root 0600 file
    (join.sh --code-file), the public address named as setup does; the
    maps follow. The new id."""
    new_id = fresh_id(vmn)
    wipe_node(vmn)
    out = pc("node", "add", new_id, "--role", role, "--class", "cloud", "--site", site, extra, timeout=120)
    codes = [ln.strip() for ln in out.splitlines() if ln.startswith("pcj")]
    assert codes, f"node add {new_id} printed no join code"
    mask(codes[0])
    vm(vmn, "sudo install -m 0600 -o root -g root /dev/stdin /root/e2e-join-code", inp=codes[0] + "\n")
    del out, codes
    vm(vmn, f"curl -fsSL https://{DOMAIN}/node/join.sh -o /tmp/join.sh && sudo sh /tmp/join.sh --code-file /root/e2e-join-code; "
            "rc=$?; sudo rm -f /root/e2e-join-code /tmp/join.sh; exit $rc", timeout=600)
    wait_for(f"{new_id} Ready", lambda: node_ready(new_id), 450, 5)
    # The local images onto it, the peer list, the public address (as setup's join_node).
    vm(OPERATOR_VM, "sudo bash -c 'refs=$(/usr/local/bin/k3s ctr -n k8s.io images ls -q | grep -E \"^localhost/portcullis-\" | sort -u); "
                    "t=$(mktemp /var/tmp/e2e-imp.XXXXXX); /usr/local/bin/k3s ctr -n k8s.io images export --platform linux/amd64 $t $refs && "
                    f"ssh -F /etc/e2e-ha/ssh_config {vmn} sudo k3s ctr -n k8s.io images import - < $t >/dev/null; rm -f $t; "
                    f"grep -qx {vmn} /etc/e2e-ha/peers || echo {vmn} >> /etc/e2e-ha/peers'", timeout=600)
    ann = json.dumps({"lan": [VMS[vmn]["private"]], "public": [VMS[vmn]["public"]]})
    K("annotate", "node", new_id, "--overwrite", f"portcullis.io/addresses={ann}")
    rename_node(vmn, new_id)
    note(f"  {vmn} joined again as {new_id} ({role}, {site}) with a fresh code")
    return new_id


def etcd_member_names(h: str) -> list[str]:
    """The REAL etcd member list (k3s' etcd JSON API on 2382, the server's
    own etcd client certificate, paths only on argv)."""
    out = vm(h, "sudo curl -s --max-time 10 --cacert /var/lib/rancher/k3s/server/tls/etcd/server-ca.crt "
                "--cert /var/lib/rancher/k3s/server/tls/etcd/client.crt --key /var/lib/rancher/k3s/server/tls/etcd/client.key "
                "-X POST -d '{}' https://127.0.0.1:2382/v3/cluster/member/list", timeout=30)
    return sorted(m.get("name", "") for m in json.loads(out).get("members") or [])


def member_of(node: str, members: list[str]) -> bool:
    return any(m == node or m.startswith(node + "-") for m in members)


def needs(*keys: str) -> None:
    missing = [k for k in keys if k not in state]
    assert not missing, f"needs {', '.join(missing)} (an earlier scenario failed)"


def main() -> int:
    e2e_ha.SECRET = _hub_secret()  # masked by secret_read
    retarget_api()  # kubectl over an SSH tunnel to a server that answers
    fixtures_ok()
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
        check("ha_vm_nat_relay: vm2, then vm4 too, behind a real NAT: vm2 ↔ vm4 keeps working, sign-in unaffected", ha_vm_nat_relay)
        check("ha_vm_front_door_node: the front door's own node cut, a new front door leads, failover recovers", ha_vm_front_door_node)
        check("ha_vm_front_door_nodeadm_one_node: the front door and nodeadm on one node, cut", ha_vm_front_door_nodeadm_one_node)
        check("ha_vm_cert_renew_leader_move: the front door's certificate renewed across a Lease move", ha_vm_cert_renew_leader_move)
        check("ha_vm_interrupted_removal: a removal interrupted by a Hub restart resumes cleanly (the agent)", ha_vm_interrupted_removal)
        check("ha_vm_revoke_restarts: revoke an agent then a server; restarts, reboots and credentials all healthy", ha_vm_revoke_restarts)
        check("ha_vm_etcd_remove_member: the revoked server's etcd member removed (the real member list)", ha_vm_etcd_remove_member)

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
