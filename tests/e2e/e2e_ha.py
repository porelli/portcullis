#!/usr/bin/env python3
"""End-to-end: high availability on k3d (CI job `e2e-ha-k3d`, plan Task 33
part A; spec §19.2 — the logic, not the storage).

Runs against core in HA on the k3d cluster `ha` (.github/ci/e2e-ha-k3d-
install.sh main: 3 servers + 1 small agent on 10.215.0.0/24, every server
at site main and an ingress node; e2e-ha-k3d-phases.sh init + ha). Node
"failures" are `docker kill` of a node container and `docker start` after:
the kubelet and everything on the node stop at once (not a power loss or a
partition: those are e2e-ha-vm's, part B).

    e2e_ha.py main    the scenarios on `ha`
    e2e_ha.py sites   ha_dns_failover_sites on `sites` (install.sh sites)

Scenarios (main):
  ha_cnpg_failover       a writer inserts one row a second into the CNPG
                         primary; its pod is deleted, then the new primary's
                         node container killed: writes resume within 60 s
                         each time, and every committed row is there after.
  ha_sentinel_promotion  the Valkey master pod is deleted: the Sentinels
                         promote the replica within 30 s, the old pod comes
                         back as a replica, and a signed-in session (its
                         ticket in Valkey) still opens the portal.
  ha_vault_leader_loss   the active Vault voter is deleted: another voter is
                         active within 30 s and issues a certificate; the
                         earlier one is still readable by its serial.
  ha_hub_lease_handover  a second Hub pod (the Deployment at 2) never holds
                         the Lease portcullis-hub and answers 503 "standing
                         by" to a write; the holder deleted, the second
                         takes the Lease within LeaseDuration (15 s) + its
                         retry, and then writes.
  ha_published_docs      a group created and then deleted through the Hub:
                         the removal reaches every group-gate replica's
                         mounted policy (pub-group-gate-policy, a projected
                         volume, kubelet sync-frequency=10s) within 20 s.
  ha_signin_continuity   admin signs in once (setup link, virtual passkey);
                         then 300 sign-ins (the oauth2-proxy ticket dropped
                         before each: oauth2 start → Keycloak's SSO → the
                         callback → group-gate → the portal) while a
                         Keycloak pod, a group-gate and a forward-auth
                         replica are killed: at most 5 fail.
  ha_n_minus_1           the N−1 result for a server (the Hub's
                         availability view of a CI echo instance) against
                         the scheduler: that node cordoned and drained,
                         every pod of it the check placed starts elsewhere.
  ha_coredns_node_kill   (carry) the node of a CoreDNS replica killed: a
                         pod on another node keeps resolving the cluster
                         names (k3s' CoreDNS spread over two nodes and
                         portcullis-dns-small on the small node, ha_coredns).

Scenarios (sites): ha_dns_failover_sites — see sites_main().

Environment: E2E_DOMAIN, E2E_ARTIFACTS, E2E_HA_CONTEXT (default ha),
HUB_PROXY_SECRET read from .env (never printed or on argv). Every secret
goes through stdin or a 0600 file.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scenarios  # noqa: E402  (E2E_SCENARIOS: single-scenario reruns)

CTX = os.environ.get("E2E_HA_CONTEXT", "ha")
DOMAIN = os.environ.get("E2E_DOMAIN", "portcullis.local")
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
NS, PG_NS, PG = "portcullis", "cnpg-system", "portcullis-pg"
LEASE_S, RETRY_S = 15, 2

results: list[tuple[str, bool, str]] = []
state: dict = {}
timings: list[str] = []


def check(name: str, fn) -> None:
    if scenarios.skip(name):  # E2E_SCENARIOS (tests/e2e/scenarios.py)
        return
    t0 = time.time()
    try:
        fn()
        results.append((name, True, ""))
        print(f"PASS: {name} ({time.time() - t0:.0f} s)", flush=True)
    except Exception as e:  # noqa: BLE001
        results.append((name, False, f"{type(e).__name__}: {e}"))
        print(f"FAIL: {name}: {e}", flush=True)
        traceback.print_exc()
    finally:
        try:
            settle()
        except Exception as e:  # noqa: BLE001 — a cluster that didn't come back fails the next one
            print(f"::warning::after {name.split(':')[0]}: the cluster didn't settle: {e}", flush=True)


def needs(*keys: str) -> None:
    missing = [k for k in keys if k not in state]
    assert not missing, f"needs {', '.join(missing)} (an earlier scenario failed)"


def note(text: str) -> None:
    print(text, flush=True)
    timings.append(text)


def save(name: str, data) -> None:
    os.makedirs(ART, exist_ok=True)
    with open(os.path.join(ART, name), "w") as f:
        f.write(data if isinstance(data, str) else json.dumps(data, indent=2))


# ── kubectl / docker ──

def K(*argv: str, inp: str | None = None, timeout: float = 120, ok: bool = True, ctx: str | None = None) -> str:
    r = subprocess.run(["kubectl", "--context", ctx or CTX, *argv], input=inp, capture_output=True, text=True, timeout=timeout)
    if ok and r.returncode != 0:
        raise AssertionError(f"kubectl {' '.join(argv[:6])}: exit {r.returncode}: {r.stderr.strip()[-400:]}")
    return r.stdout


def Kj(*argv: str, ctx: str | None = None):
    return json.loads(K(*argv, "-o", "json", ctx=ctx))


def docker(*argv: str, timeout: float = 120) -> str:
    r = subprocess.run(["docker", *argv], capture_output=True, text=True, timeout=timeout)
    assert r.returncode == 0, f"docker {' '.join(argv)}: {r.stderr.strip()[-300:]}"
    return r.stdout


def wait_for(what: str, fn, timeout: float, every: float = 2):
    deadline, last = time.time() + timeout, None
    while True:
        try:
            out = fn()
            if out:
                return out
        except (AssertionError, subprocess.TimeoutExpired, ValueError, KeyError) as e:
            last = e
        if time.time() > deadline:
            raise AssertionError(f"{what}: not within {timeout:.0f} s ({last})")
        time.sleep(every)


def pods(ns: str, selector: str, ctx: str | None = None) -> list[dict]:
    return [p for p in Kj("-n", ns, "get", "pods", "-l", selector, ctx=ctx)["items"] if not p["metadata"].get("deletionTimestamp")]


def ready(p: dict) -> bool:
    return p.get("status", {}).get("phase") == "Running" and all(c.get("ready") for c in p["status"].get("containerStatuses") or [{}])


killed: set[str] = set()


ISOLATE = "PCE2E"


def kill_node(node: str) -> float:
    """The node cut off (its container's eth0 dropped both ways in its own
    chain: the kubelet's heartbeats, etcd, the pods' tunnels and its public
    address all go silent; the API port answers a reset so the harness's
    load balancer skips it at once). A node that stops answering, as on a
    VM; its processes run on and resume when it's healed (a restarted k3d
    server container didn't come back Ready in CI). The time it happened."""
    rules = [["-N", ISOLATE], ["-A", ISOLATE, "-i", "lo", "-j", "RETURN"], ["-A", ISOLATE, "-o", "lo", "-j", "RETURN"],
             ["-A", ISOLATE, "-i", "eth0", "-p", "tcp", "--dport", "6443", "-j", "REJECT", "--reject-with", "tcp-reset"],
             ["-A", ISOLATE, "-j", "DROP"], ["-I", "INPUT", "1", "-j", ISOLATE], ["-I", "OUTPUT", "1", "-j", ISOLATE],
             ["-I", "FORWARD", "1", "-j", ISOLATE]]
    for r in rules:
        docker("exec", node, "iptables", "-w", *r)
    killed.add(node)
    return time.time()


def start_node(node: str) -> None:
    for r in (["-D", "INPUT", "-j", ISOLATE], ["-D", "OUTPUT", "-j", ISOLATE], ["-D", "FORWARD", "-j", ISOLATE], ["-F", ISOLATE], ["-X", ISOLATE]):
        subprocess.run(["docker", "exec", node, "iptables", "-w", *r], capture_output=True, timeout=30)
    killed.discard(node)
    wait_for(f"node {node} Ready again", lambda: node_ready(node), 300, 5)


def not_ready_at(node: str, since: float, timeout: float = 180) -> float:
    """When the API server marked node NotReady (polled every second)."""
    wait_for(f"node {node} NotReady", lambda: not node_ready(node), timeout, 1)
    return time.time()


def node_ready(node: str) -> bool:
    n = Kj("get", "node", node)
    return any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"])


def settle(timeout: float = 600) -> None:
    """Between scenarios: every killed node started again, every node Ready
    and schedulable, every core workload at its replicas, CNPG healthy."""
    for n in list(killed):
        start_node(n)
    for n in Kj("get", "nodes")["items"]:
        if n["spec"].get("unschedulable"):
            K("uncordon", n["metadata"]["name"])

    def ok():
        bad = [n["metadata"]["name"] for n in Kj("get", "nodes")["items"]
               if not any(c["type"] == "Ready" and c["status"] == "True" for c in n["status"]["conditions"])]
        assert not bad, f"nodes not Ready: {bad}"
        for kind in ("deployments", "statefulsets"):
            for w in Kj("-n", NS, "get", kind)["items"]:
                want = w["spec"].get("replicas", 1)
                have = w.get("status", {}).get("readyReplicas", 0) or 0
                assert have >= want, f"{kind[:-1]} {w['metadata']['name']}: {have}/{want} ready"
        c = Kj("-n", PG_NS, "get", "cluster.postgresql.cnpg.io", PG)
        st = c.get("status", {})
        assert st.get("readyInstances") == c["spec"]["instances"], f"CNPG {st.get('readyInstances')}/{c['spec']['instances']} ready ({st.get('phase')})"
        return True
    wait_for("the cluster settled", ok, timeout, 5)


# ── the Hub's admin API (a port-forward; the proxy secret from .env) ──

def env_value(key: str) -> str:
    with open(".env") as f:
        for line in f:
            if line.startswith(key + "="):
                return line.rstrip("\n").split("=", 1)[1]
    raise AssertionError(f".env has no {key}")


SECRET = ""


class Forward:
    """kubectl port-forward to <target> (svc/hub, pod/<name>) on a free
    local port; ended with the object."""

    def __init__(self, target: str, port: int, ns: str = NS):
        self.log = tempfile.NamedTemporaryFile(prefix="pf-", delete=False)
        self.p = subprocess.Popen(["kubectl", "--context", CTX, "-n", ns, "port-forward", "--address", "127.0.0.1", target, f":{port}"],
                                  stdout=self.log, stderr=subprocess.STDOUT)
        self.port = 0
        for _ in range(100):
            m = re.search(rb"Forwarding from 127\.0\.0\.1:(\d+)", open(self.log.name, "rb").read())
            if m:
                self.port = int(m.group(1))
                break
            time.sleep(0.2)
        assert self.port, f"no port-forward to {target}: {open(self.log.name).read()[-300:]}"

    def close(self) -> None:
        self.p.terminate()
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()
        os.unlink(self.log.name)


def hub_call(port: int, method: str, path: str, body=None, timeout: float = 60) -> tuple[int, object]:
    for attempt in range(4):
        try:
            return _hub_call(port, method, path, body, timeout)
        except (ConnectionError, urllib.error.URLError, http.client.RemoteDisconnected):
            if attempt == 3:
                raise
            time.sleep(2)
    raise AssertionError("unreachable")


def _hub_call(port: int, method: str, path: str, body=None, timeout: float = 60) -> tuple[int, object]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method, headers={
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


class HubAPI:
    """The Hub through svc/hub, re-forwarded when the forward broke (a Hub
    pod went away)."""

    def __init__(self):
        self.f: Forward | None = None

    def __call__(self, method: str, path: str, body=None, timeout: float = 60) -> tuple[int, object]:
        for attempt in (1, 2, 3):
            if self.f is None:
                self.f = Forward("svc/hub", 8888)
            try:
                return hub_call(self.f.port, method, path, body, timeout)
            except (urllib.error.URLError, ConnectionError, TimeoutError):
                self.f.close()
                self.f = None
                if attempt == 3:
                    raise
                time.sleep(3)
        raise AssertionError("unreachable")

    def ok(self, method: str, path: str, body=None, want: int = 200):
        code, out = self(method, path, body)
        assert code == want, f"{method} {path}: HTTP {code} (want {want}): {str(out)[:600]}"
        return out


hub = HubAPI()


# ── scenarios ──

def pg_primary() -> str:
    c = Kj("-n", PG_NS, "get", "cluster.postgresql.cnpg.io", PG)
    return c["status"]["currentPrimary"]


def psql(pod: str, sql: str, timeout: float = 8) -> str:
    return K("-n", PG_NS, "exec", "-i", pod, "-c", "postgres", "--", "psql", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1",
             "-d", "postgres", "-f", "-", inp=sql, timeout=timeout)


class Writer(threading.Thread):
    """One INSERT a second into the CNPG primary (as postgres, over the
    pod's local socket); a row is committed when psql returned 0 (with
    synchronous replication ANY 1, a standby has it). Records each commit's
    time; re-resolves the primary on a failure."""

    def __init__(self):
        super().__init__(daemon=True)
        self.stop = threading.Event()
        self.committed: list[tuple[int, float]] = []
        self.failures = 0
        self.n = 0

    def run(self) -> None:
        pod = None
        while not self.stop.is_set():
            self.n += 1
            try:
                pod = pod or pg_primary()
                psql(pod, f"INSERT INTO e2e_ha_rows (n) VALUES ({self.n});", timeout=5)
                self.committed.append((self.n, time.time()))
            except Exception:  # noqa: BLE001 — counted; the primary is asked again
                self.failures += 1
                pod = None
            self.stop.wait(1)

    def resumed_after(self, t: float) -> float:
        later = [at for _, at in self.committed if at > t]
        return later[0] - t if later else -1


def cnpg_failover() -> None:
    c = Kj("-n", PG_NS, "get", "cluster.postgresql.cnpg.io", PG)
    assert c["spec"]["instances"] >= 2, f"CNPG has {c['spec']['instances']} instance(s): not HA"
    p0 = pg_primary()
    psql(p0, "DROP TABLE IF EXISTS e2e_ha_rows; CREATE TABLE e2e_ha_rows (n int PRIMARY KEY, at timestamptz DEFAULT now());")
    w = Writer()
    w.start()
    node, d2 = "", -1.0
    try:
        wait_for("the writer's first rows", lambda: len(w.committed) >= 5, 60, 1)
        # 1: the primary's pod deleted.
        t = time.time()
        K("-n", PG_NS, "delete", "pod", p0, "--wait=false")
        wait_for("writes resume after the primary pod's deletion", lambda: w.resumed_after(t) >= 0, 60, 1)
        d1 = w.resumed_after(t)
        p1 = wait_for("a new primary", lambda: (pg_primary() != p0 and pg_primary()), 60)
        note(f"ha_cnpg_failover: primary pod {p0} deleted → writes resumed after {d1:.1f} s (new primary {p1})")
        assert d1 <= 60, f"writes resumed after {d1:.1f} s (> 60)"
        # 2: the new primary's node container killed.
        node = Kj("-n", PG_NS, "get", "pod", p1)["spec"]["nodeName"]
        wait_for("the writer committing again", lambda: len([1 for _, at in w.committed if at > time.time() - 3]) > 0, 30, 1)
        t = kill_node(node)
        tn = not_ready_at(node, t)
        wait_for(f"writes resume after node {node} died", lambda: w.resumed_after(t) >= 0, 240, 1)
        d2 = w.resumed_after(tn)
        note(f"ha_cnpg_failover: node {node} (primary {p1}) cut off → NotReady after {tn - t:.1f} s → writes resumed "
             f"{w.resumed_after(t):.1f} s after the cut, {d2:.1f} s after NotReady (new primary {pg_primary()})")
        time.sleep(5)
    finally:
        w.stop.set()
        w.join(15)
    if node:
        start_node(node)
    want = {n for n, _ in w.committed}
    got = {int(x) for x in psql(pg_primary(), "SELECT n FROM e2e_ha_rows;").split()}
    lost = sorted(want - got)
    note(f"ha_cnpg_failover: {len(want)} rows committed, {len(lost)} lost, {w.failures} failed attempts")
    assert not lost, f"committed rows lost: {lost[:20]}"
    # The node's own loss is detected by the kubelet's lease (k3s'
    # node-monitor grace); the failover itself is CNPG's: 60 s from there.
    assert 0 <= d2 <= 60, f"writes resumed {d2:.1f} s after the node went NotReady (> 60)"
    psql(pg_primary(), "DROP TABLE e2e_ha_rows;")


def sentinel(*cmd: str, pod: str = "sessions-sentinel-0") -> str:
    return K("-n", NS, "exec", pod, "--", "valkey-cli", "--no-auth-warning", "-t", "2", "--user", "sessions-admin",
             "-h", "127.0.0.1", "-p", "26379", *cmd, timeout=15)


def valkey_master() -> str:
    host = sentinel("SENTINEL", "get-master-addr-by-name", "portcullis-sessions").split()[0]
    return host.split(".")[0]


def sentinel_promotion() -> None:
    m0 = valkey_master()
    assert re.fullmatch(r"sessions-\d+", m0), f"the Sentinels' master is {m0!r}"
    t = time.time()
    K("-n", NS, "delete", "pod", m0, "--wait=false")
    m1 = wait_for("a promoted master", lambda: (valkey_master() != m0 and valkey_master()), 30, 0.5)
    d = time.time() - t
    note(f"ha_sentinel_promotion: master {m0} deleted → {m1} promoted after {d:.1f} s")

    def back_as_replica():
        out = K("-n", NS, "get", "pod", m0, "-o", "json")
        assert ready(json.loads(out)), f"{m0} not ready"
        info = sentinel("SENTINEL", "replicas", "portcullis-sessions")
        return m0 in info and valkey_master() == m1
    wait_for(f"{m0} back as a replica of {m1}", back_as_replica, 180, 3)
    if "session" in state:
        state["session"].assert_open("after the promotion")


def vault_status(pod: str) -> dict:
    return json.loads(K("-n", NS, "exec", pod, "-c", "vault", "--", "vault", "status", "-format=json", ok=False, timeout=10) or "{}")


def vault_active() -> str:
    for p in pods(NS, "portcullis.io/component=vault"):
        st = vault_status(p["metadata"]["name"])
        if st.get("is_self") and st.get("ha_enabled") and not st.get("sealed"):
            return p["metadata"]["name"]
    return ""


def vault_issue(pod: str, cn: str) -> str:
    root = json.load(open("secrets/vault-init.json"))["root_token"]
    out = K("-n", NS, "exec", "-i", pod, "-c", "vault", "--", "sh", "-c",
            'IFS= read -r t; VAULT_TOKEN="$t" VAULT_ADDR=http://127.0.0.1:8200 exec vault write -format=json pki_int/issue/client-cert common_name="$1" ttl=1h',
            "_", cn, inp=root + "\n", timeout=30)
    return json.loads(out)["data"]["serial_number"]


def vault_read_cert(pod: str, serial: str) -> bool:
    out = K("-n", NS, "exec", pod, "-c", "vault", "--", "sh", "-c",
            'VAULT_ADDR=http://127.0.0.1:8200 exec vault read -format=json "pki_int/cert/$1"', "_", serial, timeout=20, ok=False)
    return bool(out) and "BEGIN CERTIFICATE" in out


def vault_leader_loss() -> None:
    a0 = wait_for("an active Vault voter", vault_active, 60)
    s0 = vault_issue(a0, "e2e-ha-before")
    t = time.time()
    K("-n", NS, "delete", "pod", a0, "--wait=false")
    a1 = wait_for("another active voter", lambda: (vault_active() not in ("", a0) and vault_active()), 30, 0.5)
    d = time.time() - t
    note(f"ha_vault_leader_loss: active {a0} deleted → {a1} active after {d:.1f} s")
    s1 = wait_for("a certificate issued by the new leader", lambda: vault_issue(a1, "e2e-ha-after"), 30, 2)
    assert vault_read_cert(a1, s0), f"the certificate {s0} issued before isn't readable"
    note(f"ha_vault_leader_loss: issued {s1}; {s0} (before) still readable")


def lease_holder() -> str:
    return Kj("-n", NS, "get", "lease", "portcullis-hub")["spec"].get("holderIdentity") or ""


def hub_pods() -> list[str]:
    return sorted(p["metadata"]["name"] for p in pods(NS, "portcullis.io/component=hub") if ready(p))


def second_hub(name: str) -> dict:
    """A second Hub pod: the running Hub's own spec, its own pod name (the
    Lease identity), its data volumes as emptyDirs (two Hubs never share
    a data directory: the Hub's .hub.lock refuses the second), out of the
    hub Service (component hub-e2e-second); created by the CLI's identity,
    which the admission policies don't judge."""
    live = next(p for p in pods(NS, "portcullis.io/component=hub") if ready(p))
    spec = live["spec"]
    for k in ("nodeName", "hostname", "subdomain"):
        spec.pop(k, None)
    vols = []
    for v in spec.get("volumes", []):
        if "persistentVolumeClaim" in v:
            v = {"name": v["name"], "emptyDir": {}}
        vols.append(v)
    spec["volumes"] = vols
    labels = dict(live["metadata"].get("labels", {}))
    labels.pop("pod-template-hash", None)
    labels["portcullis.io/component"] = "hub-e2e-second"
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": NS, "labels": labels,
            "annotations": live["metadata"].get("annotations", {})}, "spec": spec}


def hub_lease_handover() -> None:
    h0 = wait_for("the Lease held by a Hub pod", lambda: lease_holder() in hub_pods() and lease_holder(), 120)
    other = f"hub-e2e-second-{int(time.time()) % 10000}"
    K("apply", "-f", "-", inp=json.dumps(second_hub(other)))
    try:
        K("-n", NS, "wait", "--for=condition=Ready", f"pod/{other}", "--timeout=300s", timeout=320, ok=False)
        # Watched over 30 s: the second pod never holds the Lease and
        # refuses every write (the leader gate, before any handler).
        f = Forward(f"pod/{other}", 8888)
        try:
            for _ in range(10):
                assert lease_holder() == h0, f"the Lease moved to {lease_holder()} while {h0} runs"
                code, out = hub_call(f.port, "POST", "/api/directory/groups", {"name": "e2e-ha-standby"})
                assert code == 503 and "standing by" in str(out), f"the standby {other} answered a write {code}: {str(out)[:200]}"
                time.sleep(3)
        finally:
            f.close()
        # The holder gone (its Deployment at 0, so only the second is left).
        K("-n", NS, "scale", "deployment/hub", "--replicas=0")
        t = time.time()
        wait_for(f"{other} takes the Lease", lambda: lease_holder() == other, LEASE_S + RETRY_S + 60, 0.5)
        d = time.time() - t
        note(f"ha_hub_lease_handover: holder {h0} stopped → {other} holds the Lease after {d:.1f} s")
        f = Forward(f"pod/{other}", 8888)
        try:
            code, out = wait_for("the new holder writes", lambda: (lambda r: r if r[0] != 503 else None)(
                hub_call(f.port, "POST", "/api/directory/groups", {"name": "e2e-ha-lease"})), 30, 1)
            assert code in (200, 201), f"the new holder's write: {code} {str(out)[:200]}"
            hub_call(f.port, "DELETE", "/api/directory/groups/e2e-ha-lease", {"confirm": "e2e-ha-lease"})
        finally:
            f.close()
        # The old holder stops on SIGTERM within its grace period; the
        # Lease's own clock: LeaseDuration after its last renewal.
        assert d <= LEASE_S + RETRY_S + 35, f"handover took {d:.1f} s (> LeaseDuration {LEASE_S} s + retry {RETRY_S} s + the 30 s grace)"
    finally:
        K("-n", NS, "delete", "pod", other, "--wait=false", ok=False)
        K("-n", NS, "scale", "deployment/hub", "--replicas=1")


def gate_policies() -> dict[str, str]:
    """Each group-gate replica's mounted policy (the projected volume)."""
    out = {}
    for p in pods(NS, "portcullis.io/component=group-gate"):
        n = p["metadata"]["name"]
        out[n] = K("-n", NS, "exec", n, "-c", "group-gate", "--", "cat", "/hub-data/group-gate-policy.json", timeout=15)
    return out


def published_policy() -> str:
    return Kj("-n", NS, "get", "configmap", "pub-group-gate-policy")["data"]["group-gate-policy.json"]


def published_docs() -> None:
    """A test person in a group until a time (the policy's `expiring`
    list names the membership, so group-gate enforces it); the group
    deleted through the Hub: the Hub publishes the policy without it, and
    every group-gate replica's mounted copy equals it within 20 s of the
    DELETE. (Never LLDAP's admin: a person of its own.)"""
    from datetime import datetime, timedelta, timezone
    u, g = "e2e-ha-pub", f"e2e-ha-pub-{int(time.time()) % 100000}"
    if hub("GET", f"/api/directory/users/{u}")[0] != 200:
        hub.ok("POST", "/api/directory/users", {"username": u, "email": f"{u}@{DOMAIN}", "display_name": "HA publish"})
    hub.ok("POST", "/api/directory/groups", {"name": g})
    until = (datetime.now(timezone.utc) + timedelta(hours=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    hub.ok("POST", f"/api/directory/groups/{g}/members", {"username": u, "until": until})
    wait_for(f"{g} in the published policy and every replica's copy",
             lambda: g in published_policy() and len(gate_policies()) >= 2 and all(v == published_policy() for v in gate_policies().values()), 180, 2)
    before = published_policy()
    t = time.time()
    code, out = hub("DELETE", f"/api/directory/groups/{g}", {"confirm": g})
    assert code in (200, 204), f"DELETE {g}: {code} {str(out)[:300]}"
    new = wait_for("the Hub publishes the policy without the group", lambda: (lambda v: v if v != before and g not in v else None)(published_policy()), 30, 0.5)
    tp = time.time() - t
    seen: dict[str, float] = {}

    def arrived():
        for n, v in gate_policies().items():
            if v == new and n not in seen:
                seen[n] = time.time() - t
        return len(seen) >= 2 and len(seen) == len(gate_policies())
    wait_for("the new policy in every group-gate replica", arrived, 60, 0.5)
    note(f"ha_published_docs: published {tp:.1f} s after the DELETE; reached " + ", ".join(f"{n} after {s:.1f} s" for n, s in sorted(seen.items())))
    worst = max(seen.values())
    assert worst <= 20, f"the removal took {worst:.1f} s (> 20) to reach a replica"


def ingress_ips() -> list[str]:
    out = []
    for n in Kj("get", "nodes", "-l", "portcullis.io/ingress=true")["items"]:
        out += [a["address"] for a in n["status"]["addresses"] if a["type"] == "InternalIP"]
    return sorted(out)


class Session:
    """admin's browser session (Playwright Chromium, a virtual passkey),
    reaching Traefik's hostPort on one ingress node."""

    def __init__(self, pw, ip: str):
        import e2e_login  # the setup-link helpers (needs E2E_DOMAIN)
        self.e2e_login = e2e_login
        rules = f"MAP {DOMAIN} {ip},MAP *.{DOMAIN} {ip}"
        self.browser = pw.chromium.launch(args=[f"--host-resolver-rules={rules}"])
        self.ctx = self.browser.new_context()
        self.page = self.ctx.new_page()
        self.page.set_default_timeout(30_000)
        self.auth = e2e_login.Authenticator(self.page)
        link = e2e_login.mint_setup_link("admin", "portal")
        e2e_login.setup_link_signin(self.page, link, who="admin", mint=lambda: e2e_login.mint_setup_link("admin", "portal"),
                                    until=f"https://{DOMAIN}/", label="ha-admin", expect_stepups=1)

    def portal_ok(self) -> bool:
        r = self.ctx.request.get(f"https://{DOMAIN}/", max_redirects=0, timeout=10_000)
        return r.status == 200

    def assert_open(self, when: str) -> None:
        assert self.portal_ok(), f"admin's session doesn't open the portal {when}"

    def signin(self) -> bool:
        """One sign-in: the ticket cookie dropped, then the portal: oauth2
        start → Keycloak (its SSO cookie, no prompt) → the callback →
        group-gate → the portal."""
        keep = [c for c in self.ctx.cookies() if not c["name"].startswith("_oauth2_proxy")]
        self.ctx.clear_cookies()
        self.ctx.add_cookies(keep)
        try:
            resp = self.page.goto(f"https://{DOMAIN}/", wait_until="domcontentloaded", timeout=15_000)
            return bool(resp) and resp.status == 200 and self.page.url.rstrip("/") == f"https://{DOMAIN}" \
                and not self.e2e_login.on_login_pages(self.page)
        except Exception:  # noqa: BLE001 — a failed request
            return False

    def close(self) -> None:
        self.browser.close()


def signin_continuity() -> None:
    needs("session")
    s: Session = state["session"]
    kc = sorted(p["metadata"]["name"] for p in pods(NS, "portcullis.io/component=keycloak") if ready(p))
    gg = sorted(p["metadata"]["name"] for p in pods(NS, "portcullis.io/component=group-gate") if ready(p))
    fa = sorted(p["metadata"]["name"] for p in pods(NS, "portcullis.io/component=forward-auth") if ready(p))
    assert len(kc) >= 2 and len(gg) >= 2 and len(fa) >= 2, f"replicas: keycloak {kc}, group-gate {gg}, forward-auth {fa}"
    total, failed, fails = 300, 0, []
    t0 = time.time()
    for i in range(total):
        if i == 30:
            K("-n", NS, "delete", "pod", kc[0], "--grace-period=0", "--force", "--wait=false")
            note(f"ha_signin_continuity: request {i}: Keycloak {kc[0]} killed")
        if i == 150:
            K("-n", NS, "delete", "pod", gg[0], fa[0], "--grace-period=0", "--force", "--wait=false")
            note(f"ha_signin_continuity: request {i}: group-gate {gg[0]} and forward-auth {fa[0]} killed")
        if not s.signin():
            failed += 1
            fails.append((i, round(time.time() - t0, 1), s.page.url.split("?")[0]))
        time.sleep(0.3)
    note(f"ha_signin_continuity: {failed} of {total} sign-ins failed in {time.time() - t0:.0f} s: {fails[:10]}")
    assert failed <= 5, f"{failed} of {total} sign-ins failed (> 5): {fails[:20]}"


def seed_echo() -> None:
    """An instance of the CI template echo (the phases' ha step seeded the
    source), for the N−1 view (GET /api/instances/{id}/availability)."""
    import e2e_ops
    if hub("GET", "/api/instances/echo-ha")[0] == 200:
        return
    acc = e2e_ops.accepted(hub.ok("POST", "/api/instances", {"template": "echo", "id": "echo-ha", "label": "Echo HA",
                                                            "hosts": {"echo": f"echo-ha.{DOMAIN}"}}, want=202))
    rec = e2e_ops.wait(lambda path: hub("GET", path)[1], acc, 600)
    e2e_ops.check_ok(acc, rec)


def n_minus_1() -> None:
    seed_echo()
    v = wait_for("the N−1 view", lambda: (lambda r: r[1] if r[0] == 200 and r[1].get("n_minus_1") else None)(
        hub("GET", "/api/instances/echo-ha/availability")), 120, 5)
    save("n-minus-1.json", v)
    res = {r["node"]: r for r in v["n_minus_1"]}
    servers = sorted(n["metadata"]["name"] for n in Kj("get", "nodes", "-l", "node-role.kubernetes.io/control-plane=true")["items"])
    # The node whose result the scheduler can prove most: not red, and the
    # one holding the most core pods.
    load = {n: len([p for p in Kj("-n", NS, "get", "pods", "--field-selector", f"spec.nodeName={n}")["items"]]) for n in servers}
    cand = [n for n in servers if res.get(n, {}).get("level") in ("green", "yellow")]
    assert cand, f"no server green or yellow: {[(n, res.get(n, {}).get('level')) for n in servers]}"
    node = max(cand, key=lambda n: load[n])
    unplaced = set(res[node]["unplaced"])
    on_node = [p for p in Kj("get", "pods", "-A", "--field-selector", f"spec.nodeName={node}")["items"]
               if not any(o.get("kind") == "DaemonSet" for o in p["metadata"].get("ownerReferences") or [])
               and p["status"].get("phase") == "Running"]
    placeable = []
    for p in on_node:
        ns, name = p["metadata"]["namespace"], p["metadata"]["name"]
        key = name if ns == NS else f"{ns}/{name}"
        if key not in unplaced:
            placeable.append((ns, name, p["metadata"].get("ownerReferences", [{}])[0].get("name", "")))
    note(f"ha_n_minus_1: {node} is {res[node]['level']}: unplaced {sorted(unplaced)}; {len(placeable)} placeable pods")
    K("drain", node, "--ignore-daemonsets", "--delete-emptydir-data", "--force", "--timeout=300s", timeout=330, ok=False)
    try:
        def started():
            missing = []
            for ns, name, owner in placeable:
                live = [p for p in Kj("-n", ns, "get", "pods")["items"]
                        if any(o.get("name") == owner for o in p["metadata"].get("ownerReferences") or [])
                        and p["spec"].get("nodeName") not in (None, node) and ready(p)] if owner else []
                if not live:
                    missing.append(f"{ns}/{name}")
            assert not missing, f"not started elsewhere: {missing}"
            return True
        wait_for(f"every pod the check placed off {node} running elsewhere", started, 420, 10)
    finally:
        K("uncordon", node)


def coredns_node_kill() -> None:
    cd = [p for p in pods("kube-system", "k8s-app=kube-dns") if ready(p)]
    nodes = sorted({p["spec"]["nodeName"] for p in cd})
    assert len(nodes) >= 2, f"CoreDNS runs on {nodes}: one node only"
    # The probe runs where a CoreDNS replica stays (the Service prefers the
    # node's own: trafficDistribution PreferSameNode, ha_coredns).
    victim = next(n for n in nodes if "agent" not in n)
    probe_node = next(n for n in nodes if n != victim)
    # A probe pod (portcullis-e2e, restricted) on another server.
    K("create", "namespace", "portcullis-e2e", ok=False)
    spec = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "dns-probe", "namespace": "portcullis-e2e"},
            "spec": {"nodeName": probe_node, "restartPolicy": "Never", "automountServiceAccountToken": False,
                     "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "c", "image": helper_image(), "command": ["sleep", "3600"],
                                     "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                                     "resources": {"limits": {"memory": "32Mi"}}}]}}
    K("apply", "-f", "-", inp=json.dumps(spec))
    try:
        K("-n", "portcullis-e2e", "wait", "--for=condition=Ready", "pod/dns-probe", "--timeout=120s", timeout=150)
        t = kill_node(victim)
        total, failed = 0, 0
        while time.time() - t < 90:
            total += 1
            r = subprocess.run(["kubectl", "--context", CTX, "-n", "portcullis-e2e", "exec", "dns-probe", "--",
                                "nslookup", "kubernetes.default.svc.cluster.local"], capture_output=True, text=True, timeout=20)
            if r.returncode != 0:
                failed += 1
            time.sleep(1)
        note(f"ha_coredns_node_kill: CoreDNS node {victim} killed: {failed} of {total} lookups failed over 90 s")
        assert failed <= 3, f"{failed} of {total} lookups failed after the CoreDNS node died"
    finally:
        K("-n", "portcullis-e2e", "delete", "pod", "dns-probe", "--wait=false", ok=False)


# ── the front door's DNS failover ──

CLUSTER_DOMAIN = "cluster.portcullis.internal"


def node_facts(ctx: str | None = None) -> list[dict]:
    out = []
    for n in Kj("get", "nodes", ctx=ctx)["items"]:
        lb = n["metadata"]["labels"]
        ann = json.loads(n["metadata"].get("annotations", {}).get("portcullis.io/addresses") or "{}")
        out.append({"name": n["metadata"]["name"], "site": lb.get("portcullis.io/site", "main"), "class": lb.get("portcullis.io/class", ""),
                    "ingress": lb.get("portcullis.io/ingress") == "true",
                    "role": "server" if lb.get("node-role.kubernetes.io/control-plane") == "true" else "agent",
                    "mesh": next(a["address"] for a in n["status"]["addresses"] if a["type"] == "InternalIP"),
                    "public": ann.get("public") or []})
    return sorted(out, key=lambda x: x["name"])


def sign_node_cert(cn: str, d: str, ctx: str | None = None) -> None:
    """d/key.pem + d/cert.pem: a node-cluster certificate (Vault pki_node,
    the root token and the CSR on the vault pod's stdin; the key made here,
    0600, never printed)."""
    subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-keyout", f"{d}/key.pem", "-out", f"{d}/csr.pem", "-subj", f"/CN={cn}"], check=True, capture_output=True)
    os.chmod(f"{d}/key.pem", 0o600)
    root = json.load(open("secrets/vault-init.json"))["root_token"]
    pod = wait_for("an active Vault voter", vault_active, 60)
    out = K("-n", NS, "exec", "-i", pod, "-c", "vault", "--", "sh", "-c",
            'IFS= read -r t; VAULT_TOKEN="$t" VAULT_ADDR=http://127.0.0.1:8200 exec vault write -format=json pki_node/sign/node-cluster common_name="$1" ttl=48h csr=-',
            "_", cn, inp=root + "\n" + open(f"{d}/csr.pem").read(), timeout=30, ctx=ctx)
    with open(f"{d}/cert.pem", "w") as f:
        f.write(json.loads(out)["data"]["certificate"] + "\n")


def probes_up(ctx: str | None = None) -> None:
    """tests/e2e/ha/nodeagent-probes.yaml on every node: each node's
    state, its node-cluster certificate and nodeadm's probe targets in the
    Secret nodeagent-probes (files in a 0700 temp dir, --from-file)."""
    nodes = node_facts(ctx)
    targets = {"domain": DOMAIN, "egress_host": "",
               "targets": [{"node": n["name"], "site": n["site"], "address": a} for n in nodes if n["ingress"] for a in n["public"]]}
    with tempfile.TemporaryDirectory() as d:
        os.chmod(d, 0o700)
        files, items = ["--from-file=ca.crt=certs/node-ca.crt"], []
        for n in nodes:
            nd = os.path.join(d, n["name"])
            os.mkdir(nd, 0o700)
            sign_node_cert(f"{n['name']}.{CLUSTER_DOMAIN}", nd, ctx)
            with open(f"{nd}/node.pem", "w") as f:
                f.write(open(f"{nd}/key.pem").read() + open(f"{nd}/cert.pem").read())
            json.dump({"v": 1, "id": n["name"], "mesh_ip": n["mesh"], "role": n["role"], "site": n["site"], "class": n["class"]},
                      open(f"{nd}/state.json", "w"))
            json.dump(targets, open(f"{nd}/targets.json", "w"))
            base = "var/lib/portcullis/nodeagent"
            for k in ("state.json", "node.pem", "targets.json"):
                files.append(f"--from-file={n['name']}.{k}={nd}/{k}")
                items.append({"key": f"{n['name']}.{k}", "path": f"{n['name']}/{base}/{k}"})
            items.append({"key": "ca.crt", "path": f"{n['name']}/{base}/ca.crt"})
        tpl = open("tests/e2e/ha/nodeagent-probes.yaml").read()
        img = subprocess.run(["bash", "-c", "source scripts/lib/common.sh; _kube_local_import portcullis-nodeagent:ci nodeagent"],
                             capture_output=True, text=True, check=True).stdout.strip()
        assert re.fullmatch(r"localhost/portcullis-nodeagent@sha256:[0-9a-f]{64}", img), f"nodeagent image {img!r}"
        docs = tpl.replace("@IMAGE@", img).replace("@ITEMS@", json.dumps(items))
        K("apply", "-f", "-", inp=docs.split("---\n", 1)[0], ctx=ctx)
        sec = K("-n", "portcullis-e2e", "create", "secret", "generic", "nodeagent-probes", *files, "--dry-run=client", "-o", "json", ctx=ctx)
        K("apply", "-f", "-", inp=sec, ctx=ctx)
        K("apply", "-f", "-", inp=docs.split("---\n", 1)[1], ctx=ctx)
    K("-n", "portcullis-e2e", "rollout", "status", "daemonset/nodeagent-probes", "--timeout=180s", timeout=200, ctx=ctx)


def fd_status(ctx: str | None = None) -> dict:
    cm = Kj("-n", NS, "get", "configmap", "frontdoor-status", ctx=ctx)
    return json.loads(cm.get("data", {}).get("status.json") or "{}")


def published(ctx: str | None = None) -> dict[str, list[str]]:
    st = fd_status(ctx)
    return {n: sorted(v.get("addresses") or []) for n, v in (st.get("names") or {}).items()}


def cert_fp(pem: str) -> str:
    r = subprocess.run(["openssl", "x509", "-noout", "-fingerprint", "-sha256"], input=pem, capture_output=True, text=True, check=True)
    return r.stdout.strip().split("=", 1)[1]


def served_fp(addr: str, sni: str) -> str:
    """The leaf a TLS handshake to addr:443 gets (from the runner, routed to
    the node's public address)."""
    argv = ["openssl", "s_client", "-connect", f"{addr}:443", "-showcerts"] + (["-servername", sni] if sni else ["-noservername"])
    out = subprocess.run(argv, input="", capture_output=True, text=True, timeout=20).stdout
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", out, re.S)
    assert m, f"no certificate from {addr} (SNI {sni or 'none'})"
    return cert_fp(m.group(0))


def block_443(addr: str, on: bool, ctx_nodes: list[str]) -> None:
    """Traefik unreachable at addr (TCP 443 dropped in the raw table, before
    the hostPort DNAT, on every node: the probers' and the node's own)."""
    for n in ctx_nodes:
        op = "-I" if on else "-D"
        docker("exec", n, "iptables", "-t", "raw", op, "PREROUTING", "-d", addr, "-p", "tcp", "--dport", "443", "-j", "DROP")
        docker("exec", n, "iptables", "-t", "raw", op, "OUTPUT", "-d", addr, "-p", "tcp", "--dport", "443", "-j", "DROP")


def dns_failover() -> None:
    """The front door (testprovider: the fake DNS zone), its probers (the
    probes DaemonSet): every ingress node's public address published for
    <d> and *.<d>; a dead ingress node's address removed after about 30 s
    (3 failed rounds), the others kept; then Traefik made unreachable on the
    other ingress nodes one at a time: the second one's goes, the last one
    is never removed (fail static)."""
    probes_up()
    nodes = node_facts()
    ing = {n["name"]: n["public"][0] for n in nodes if n["ingress"] and n["public"]}
    assert len(ing) >= 3, f"ingress nodes {ing}"
    names = [DOMAIN, f"*.{DOMAIN}"]
    want = sorted(ing.values())
    # Every ingress node serves the front door's served pair (frontdoor-cert
    # → the domains provider → each Traefik replica), by SNI and without.
    import base64
    served = base64.b64decode(Kj("-n", NS, "get", "secret", "frontdoor-cert")["data"]["tls.crt"]).decode()
    want_fp = cert_fp(served)
    for n, a in sorted(ing.items()):
        for sni in (f"auth.{DOMAIN}", ""):
            got = served_fp(a, sni)
            assert got == want_fp, f"{n} ({a}) serves {got} for SNI {sni or '(none)'}, not frontdoor-cert's {want_fp}"
    note(f"ha_dns_failover: every ingress node serves frontdoor-cert's certificate ({want_fp[:16]}…), with and without SNI")
    wait_for("every ingress address published", lambda: all(published().get(n) == want for n in names), 420, 5)
    save("frontdoor-status-before.json", fd_status())
    fd_node = Kj("-n", NS, "get", "pods", "-l", "portcullis.io/component=frontdoor")["items"][0]["spec"]["nodeName"]
    victim = next(n for n in sorted(ing) if n != fd_node)
    t = kill_node(victim)
    rest = sorted(a for n, a in ing.items() if n != victim)
    wait_for(f"{victim}'s address removed", lambda: all(published().get(n) == rest for n in names), 180, 2)
    d = time.time() - t
    note(f"ha_dns_failover: ingress node {victim} killed → {ing[victim]} removed after {d:.0f} s; {rest} kept")
    assert 25 <= d <= 120, f"removed after {d:.0f} s (want about 30 s: 3 failed rounds 10 s apart)"
    alive = [n["name"] for n in nodes if n["name"] != victim]
    second = next(n for n in sorted(ing) if n not in (victim, fd_node))
    block_443(ing[second], True, alive)
    try:
        last = sorted(a for n, a in ing.items() if n not in (victim, second))
        wait_for(f"{second}'s address removed (Traefik unreachable)", lambda: all(published().get(n) == last for n in names), 240, 2)
        note(f"ha_dns_failover: {second}'s Traefik unreachable → {ing[second]} removed; {last} left")
        block_443(last[0], True, alive)
        try:
            t2 = time.time()
            while time.time() - t2 < 90:
                assert all(published().get(n) == last for n in names), f"the last address changed: {published()}"
                time.sleep(5)
            note(f"ha_dns_failover: the last address {last} failing too → kept for 90 s (fail static)")
        finally:
            block_443(last[0], False, alive)
    finally:
        block_443(ing[second], False, alive)
    save("frontdoor-status-after.json", fd_status())


def helper_image() -> str:
    out = subprocess.run(["bash", "-c", 'source scripts/lib/common.sh >/dev/null 2>&1; printf "%s" "$PORTCULLIS_HELPER_IMAGE"'],
                         capture_output=True, text=True, check=True).stdout
    assert "@sha256:" in out, f"helper image {out!r}"
    return out


def main() -> int:
    global SECRET
    SECRET = env_value("HUB_PROXY_SECRET")
    print(f"::add-mask::{SECRET}", flush=True)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        def signed_in():
            # Keycloak reads the Hub's published sign-in settings
            # (pub-signin-keycloak, projected at /hub-data): every replica
            # holds the published copy first.
            def kc_settings():
                want = Kj("-n", NS, "get", "configmap", "pub-signin-keycloak").get("data", {}).get("signin-keycloak.json", "")
                assert want, "pub-signin-keycloak is empty"
                for p in pods(NS, "portcullis.io/component=keycloak"):
                    got = K("-n", NS, "exec", p["metadata"]["name"], "-c", "keycloak", "--", "cat", "/hub-data/signin-keycloak.json", ok=False, timeout=15)
                    assert got == want, f"{p['metadata']['name']} doesn't hold the published sign-in settings yet"
                return True
            wait_for("every Keycloak replica holding the sign-in settings", kc_settings, 300, 5)
            state["session"] = Session(pw, ingress_ips()[0])
            state["session"].assert_open("after the setup link")
        check("admin signs in (a setup link, a virtual passkey) through an ingress node", signed_in)
        check("ha_cnpg_failover: the primary pod, then its node; writes resume within 60 s, no committed row lost", cnpg_failover)
        check("ha_sentinel_promotion: the master pod deleted, a replica promoted, the session kept", sentinel_promotion)
        check("ha_vault_leader_loss: the active voter deleted, another active and issuing", vault_leader_loss)
        check("ha_hub_lease_handover: a second Hub never writes; the handover within the Lease", hub_lease_handover)
        check("ha_published_docs: a group removal reaches group-gate within 20 s", published_docs)
        check("ha_signin_continuity: 300 sign-ins over a Keycloak and a gate kill, at most 5 failed", signin_continuity)
        check("ha_coredns_node_kill: CoreDNS keeps answering with a node dead", coredns_node_kill)
        check("ha_dns_failover: a dead ingress node's address removed after ~30 s, never the last", dns_failover)
        check("ha_n_minus_1: the N−1 page agrees with the scheduler", n_minus_1)
        if "session" in state:
            state["session"].close()
    return report()


def sites_main() -> int:
    check("ha_dns_failover_sites: three sites, an uplink lost, a blind site, the tie-breaker", sites_scenario)
    return report()


def uplink(nodes: list[str], down: bool, inbound: bool = True, outbound: bool = True) -> None:
    """A site's uplink (its public side) cut on its node containers: the
    public range TEST-NET-3 dropped both ways (inbound: no other site reaches
    its addresses; outbound: its probers reach nothing). The mesh range
    stays (the site's nodes still talk to the cluster)."""
    op = "-I" if down else "-D"
    for n in nodes:
        if inbound:
            docker("exec", n, "iptables", "-t", "raw", op, "PREROUTING", "-d", "203.0.113.0/24", "-j", "DROP")
        if outbound:
            docker("exec", n, "iptables", "-t", "raw", op, "OUTPUT", "-d", "203.0.113.0/24", "-j", "DROP")


def quiet_for(what: str, fn, seconds: float) -> None:
    t = time.time()
    first = fn()
    while time.time() - t < seconds:
        cur = fn()
        assert cur == first, f"{what} changed: {first} → {cur}"
        time.sleep(5)


def sites_scenario() -> None:
    """ruling P48: 5 servers, main ×2 and edge ×2 (ingress), tb ×1 (small,
    the tie-breaker); the probes DaemonSet on every node. An uplink lost at
    edge: only edge's addresses go, main's stay; a blind site (edge's
    probers cut off, its addresses still reachable) changes nothing;
    stopping tb keeps quorum (4/5) and the set; stopping edge and tb loses
    quorum (2/5) and nothing is changed."""
    probes_up()
    nodes = node_facts()
    by_site: dict[str, list[dict]] = {}
    for n in nodes:
        by_site.setdefault(n["site"], []).append(n)
    assert sorted(by_site) == ["edge", "main", "tb"] and len(by_site["main"]) == 2 and len(by_site["edge"]) == 2, \
        f"sites {[(k, [n['name'] for n in v]) for k, v in by_site.items()]}"
    pub = {n["name"]: n["public"][0] for n in nodes if n["ingress"]}
    names = [DOMAIN, f"*.{DOMAIN}"]
    every = sorted(pub.values())
    wait_for("every ingress address published", lambda: all(published().get(n) == every for n in names), 600, 5)
    edge = [n["name"] for n in by_site["edge"]]
    main_only = sorted(pub[n["name"]] for n in by_site["main"])
    # 1: edge's uplink lost.
    t = time.time()
    uplink(edge, True)
    try:
        wait_for("only edge's addresses removed", lambda: all(published().get(n) == main_only for n in names), 240, 2)
        note(f"ha_dns_failover_sites: edge's uplink cut → its addresses removed after {time.time() - t:.0f} s; main's {main_only} kept")
    finally:
        uplink(edge, False)
    wait_for("edge's addresses back (2 min passing)", lambda: all(published().get(n) == every for n in names), 420, 5)
    # 2: a blind site: edge's probers reach nothing, its addresses still answer.
    uplink(edge, True, inbound=False)
    try:
        quiet_for("the published set (edge blind)", published, 90)
        note("ha_dns_failover_sites: edge's probers blind for 90 s → nothing changed")
    finally:
        uplink(edge, False, inbound=False)
    # 3: the tie-breaker stopped: 4/5 servers, quorum kept.
    tb = by_site["tb"][0]["name"]
    kill_node(tb)
    try:
        wait_for("the API answering with tb down", lambda: K("get", "--raw", "/readyz", timeout=10) .strip() == "ok", 60, 3)
        quiet_for("the published set (tb down)", published, 60)
        note("ha_dns_failover_sites: tb stopped → quorum kept (API ready), the set unchanged")
        # 4: edge and tb down: 2/5, no quorum; nothing changes.
        before = fd_status()
        for n in edge:
            kill_node(n)
        time.sleep(90)
    finally:
        for n in edge + [tb]:
            if n in killed:
                docker("start", n)
                killed.discard(n)
    wait_for("the API back", lambda: K("get", "--raw", "/readyz", timeout=10, ok=False).strip() == "ok", 300, 5)
    after = fd_status()
    for n in names:
        b, a = before.get("names", {}).get(n, {}), after.get("names", {}).get(n, {})
        assert a.get("addresses") == b.get("addresses") and a.get("last_change") == b.get("last_change"), \
            f"{n} changed during the quorum loss: {b} → {a}"
    note("ha_dns_failover_sites: edge + tb stopped (2/5) for 90 s → nothing changed (addresses, last change)")


def report() -> int:
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = [f"- {'✅' if ok else '❌'} {n.split(':')[0]}{': ' + why if why else ''}" for n, ok, why in results] + [f"  - {t}" for t in timings]
    if summary:
        with open(summary, "a") as f:
            f.write("\n".join(lines) + "\n")
    save(f"e2e-ha-{CTX}-results.json", {"results": results, "timings": timings})
    bad = [n for n, ok, _ in results if not ok]
    print(f"{len(results) - len(bad)} passed, {len(bad)} failed" + (f": {', '.join(b.split(':')[0] for b in bad)}" if bad else ""), flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "main"
    if which == "sites":
        CTX = os.environ.get("E2E_HA_CONTEXT", "sites")
        sys.exit(sites_main())
    sys.exit(main())
