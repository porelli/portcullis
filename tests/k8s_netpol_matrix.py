#!/usr/bin/env python3
"""The chart's NetworkPolicies against the compose network map (Task 13).

From docker-compose.yml it derives which core pod may reach which (they
share a network that has a Kubernetes form), then evaluates the rendered
policies (both directions: the source's egress and the target's ingress,
default deny) for every pair and every container port of the target, and
asserts they allow exactly that — except the port-bound rules of Global
Constraints and K7, which replace a network for one port:

  Keycloak :8080 ← Traefik only; :9000 ← Prometheus only;
  Traefik :8000/:8443 ← any pod (and the world); :8081 ← hub, enroll,
    forward-auth, forward-auth-ext, mcp-gate; :8444 ← wg; :8082 ← Prometheus;
  Grafana :3000 ← Traefik only (its proxy whitelist is the pod CIDR);
  wg: :9100 ← Prometheus; :9001+n ← apps pods labelled vpn-slot n only;
    nothing else reaches wg; wg reaches Traefik :8444 only (+ the internet).

Synthetic peers: an app pod, VPN gateway pods (slots 0, 1 and 46) in the
apps namespace, an external address and a node address.

HA (ha.enabled, contract §20.1 "Network flows", §20.8, §20.10): the
whole compose matrix again, with group-gate and mcp-gate port-bound (their
gate port as compose says; the log ports group-gate :8091, mcp-gate :8092
and wg :8093 admit the Hub pod alone, every other core pod, an app pod, a
gateway, a pod of another namespace labelled as the Hub and the internet
denied). The front door
reaches exactly nodeadm :8443, the nodeagents :7443 on the node mesh, the
public internet on 443 and the API endpoints; only Prometheus reaches it
(:9106); every other core pod, an app pod and the internet are denied both
ways.

  python3 tests/k8s_netpol_matrix.py
"""
import ipaddress
import sys

import k8s_lib as K

F = K.Failures("k8s_netpol_matrix")
NODE = "10.1.0.4"
EXTERNAL = "203.0.113.9"


class Peer:
    def __init__(self, name, ns, labels, ports=(), ip=None):
        self.name, self.ns, self.labels, self.ports, self.ip = name, ns, labels, list(ports), ip

    def __repr__(self):
        return self.name


def sel_match(sel, labels):
    if sel is None:
        return True
    for k, v in (sel.get("matchLabels") or {}).items():
        if labels.get(k) != v:
            return False
    for e in sel.get("matchExpressions") or []:
        op, k = e["operator"], e["key"]
        if op == "In" and labels.get(k) not in e["values"]:
            return False
        if op == "NotIn" and labels.get(k) in e["values"]:
            return False
        if op == "Exists" and k not in labels:
            return False
        if op == "DoesNotExist" and k in labels:
            return False
    return True


def peer_match(p, policy_ns, target):
    """A NetworkPolicy peer against a target Peer (pod or address)."""
    if "ipBlock" in p:
        if target.ip is None:
            return False  # pods are matched by selectors (ipBlock is for cluster-external addresses)
        net = ipaddress.ip_network(p["ipBlock"]["cidr"])
        ip = ipaddress.ip_address(target.ip)
        return ip in net and not any(ip in ipaddress.ip_network(x) for x in p["ipBlock"].get("except", []))
    if target.ip is not None:
        return False
    if "namespaceSelector" in p:
        nsl = {"kubernetes.io/metadata.name": target.ns}
        if not sel_match(p["namespaceSelector"], nsl):
            return False
        return sel_match(p.get("podSelector"), target.labels)
    return target.ns == policy_ns and sel_match(p.get("podSelector"), target.labels)


def port_match(ports, port, proto):
    if not ports:
        return True
    return any(int(x.get("port")) == port and x.get("protocol", "TCP") == proto for x in ports)


def allowed(policies, src, dst, port, proto="TCP", ingress_only=False):
    def side(pod, other, direction, field, peers_key):
        if pod.ip is not None:
            return True  # an address outside the cluster: no policy of ours
        sel = [p for p in policies if p["metadata"]["namespace"] == pod.ns and direction in p["spec"].get("policyTypes", [])
               and sel_match(p["spec"]["podSelector"], pod.labels)]
        if not sel:
            # The core, apps, ingress (HA) and nodeadm namespaces are default-deny.
            return pod.ns not in (K.NS, K.APPS_NS, K.INGRESS_NS, "portcullis-nodeadm", K.CNPG_NS)
        for p in sel:
            for rule in p["spec"].get(field) or []:
                peers = rule.get(peers_key)
                if not peers:
                    F.add(f"policy {p['metadata']['name']}: a rule without {peers_key} (all peers)")
                    continue
                if any(peer_match(x, p["metadata"]["namespace"], other) for x in peers) and port_match(rule.get("ports"), port, proto):
                    return True
        return False
    # ingress_only: an apps-namespace source, whose egress is the Hub's
    # per-instance policies (not this chart's): judge core's ingress alone.
    return (ingress_only or side(src, dst, "Egress", "egress", "to")) and side(dst, src, "Ingress", "ingress", "from")


MESH_AGENT = "10.215.0.2"


def check_ha():
    docs = K.render(K.yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-ha.yaml").read_text()))
    pols = K.by_kind(docs, "NetworkPolicy")
    pods = {}
    for name, ns, labels, spec, _ in K.pod_specs(docs):
        ports = [(p["containerPort"], p.get("protocol", "TCP")) for c in spec["containers"] for p in c.get("ports", [])]
        pods[name] = Peer(name, ns, labels, ports)
    fd = pods.get("frontdoor")
    if fd is None:
        F.add("ha: no frontdoor pod")
        return
    nodeadm = Peer("nodeadm", "portcullis-nodeadm", {"portcullis.io/component": "nodeadm"})
    agent, ext, node = Peer("nodeagent", None, {}, ip=MESH_AGENT), Peer("external", None, {}, ip=EXTERNAL), Peer("node", None, {}, ip=NODE)
    app = Peer("app", K.APPS_NS, {"portcullis.io/instance": "echo", "portcullis.io/service": "web"})
    api = [(e.split(":")[0], int(e.split(":")[1])) for e in K.yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values.yaml").read_text())["apiEndpoints"]]
    rows = [(fd, nodeadm, 8443, True), (fd, agent, 7443, True), (fd, ext, 443, True)]
    rows += [(fd, Peer("api", None, {}, ip=ip), port, True) for ip, port in api]
    rows += [(pods["prometheus"], fd, 9106, True)]
    # Denials: the other ports and peers of each flow.
    rows += [(fd, nodeadm, 8080, False), (fd, nodeadm, 9105, False), (fd, agent, 443, False), (fd, agent, 7444, False),
             (fd, ext, 80, False), (fd, ext, 7443, False), (fd, node, 443, False), (fd, node, 10250, False),
             (fd, Peer("pod-cidr", None, {}, ip="10.42.0.9"), 443, False), (fd, Peer("svc-cidr", None, {}, ip="10.43.0.10"), 443, False),
             (fd, Peer("link-local", None, {}, ip="169.254.169.254"), 443, False)]
    for name, peer in sorted(pods.items()):
        if name == "frontdoor":
            continue
        for port, proto in peer.ports:
            if not (name == "nodeadm" and port == 8443):  # its own flow, above
                rows.append((fd, peer, port, False))
        for port in (8090, 9106):
            if not (name == "prometheus" and port == 9106):
                rows.append((peer, fd, port, False))
    for port in (8090, 9106):
        rows += [(app, fd, port, False), (ext, fd, port, False)]
    for src, dst, port, want in rows:
        got = allowed(pols, src, dst, port, ingress_only=src is app)
        if got != want:
            F.add(f"ha: {src} → {dst}:{port}: {'allowed' if got else 'denied'}, want {'allowed' if want else 'denied'}")


def check_log_ports():
    """HA (contract §20.10): group-gate :8091, mcp-gate :8092 and wg :8093
    admit the Hub alone — every other core pod, an app pod, a VPN gateway
    and the internet are denied — and the Hub reaches each."""
    docs = K.render({"ha": {"enabled": True}})
    pols = K.by_kind(docs, "NetworkPolicy")
    pods = {name: Peer(name, ns, labels) for name, ns, labels, _, _ in K.pod_specs(docs)}
    others = [Peer("app", K.APPS_NS, {"portcullis.io/instance": "echo", "portcullis.io/service": "web"}),
              Peer("gateway-0", K.APPS_NS, {"portcullis.io/instance": "hs", "portcullis.io/vpn-slot": "0"}),
              Peer("external", None, {}, ip=EXTERNAL), Peer("node", None, {}, ip=NODE),
              # A pod elsewhere wearing the Hub's label: never the Hub.
              Peer("fake-hub-apps", K.APPS_NS, {"portcullis.io/component": "hub", "portcullis.io/instance": "x"}),
              Peer("fake-hub-edge", K.EDGE_NS, {"portcullis.io/component": "hub"})]
    for dst, port in (("group-gate", 8091), ("mcp-gate", 8092), ("wg", 8093)):
        if dst not in pods:
            F.add(f"ha: no {dst} pod")
            continue
        if not allowed(pols, pods["hub"], pods[dst], port):
            F.add(f"ha: hub → {dst}:{port} denied")
        for name, src in sorted(pods.items()):
            if name != "hub" and allowed(pols, src, pods[dst], port):
                F.add(f"ha: {name} → {dst}:{port} allowed (the Hub alone)")
        for src in others:
            if allowed(pols, src, pods[dst], port, ingress_only=src.ns in (K.APPS_NS, K.EDGE_NS)):
                F.add(f"ha: {src} → {dst}:{port} allowed (the Hub alone)")
        # Without HA the port isn't there and no policy names it.
    for p in K.by_kind(K.render(), "NetworkPolicy"):
        for rule in (p["spec"].get("ingress") or []) + (p["spec"].get("egress") or []):
            if any(int(x.get("port", 0)) in (8091, 8092, 8093) for x in rule.get("ports") or []):
                F.add(f"policy {p['metadata']['name']} names a log port without ha.enabled")


def check_nodeadm():
    """nodeadm (contract §20.1 "Network flows"; nodeadm.enabled): only the
    Hub and the front door reach its :8443, only Traefik its :8080, only
    Prometheus its :9105; it reaches only enroll :8444, the node mesh's
    :7443 / :6443 (no etcd :2379: review I6), the API endpoints and
    kube-dns."""
    for ha in (False, True):
        docs = K.render({"ha": {"enabled": ha}, "nodeadm": {"enabled": True, "image": "ghcr.io/porelli/portcullis-nodeadm@sha256:" + "4" * 64}})
        pols = K.by_kind(docs, "NetworkPolicy")
        pods = {}
        for name, ns, labels, spec, _ in K.pod_specs(docs):
            ports = [(p["containerPort"], p.get("protocol", "TCP")) for c in spec["containers"] for p in c.get("ports", [])]
            pods[name] = Peer(name, ns, labels, ports)
        na = pods.get("nodeadm")
        if na is None:
            F.add("nodeadm: no pod")
            return
        agent, ext, node = Peer("nodeagent", None, {}, ip=MESH_AGENT), Peer("external", None, {}, ip=EXTERNAL), Peer("node", None, {}, ip=NODE)
        app = Peer("app", K.APPS_NS, {"portcullis.io/instance": "echo", "portcullis.io/service": "web"})
        ingress_traefik = Peer("traefik-ds", "portcullis-ingress", {"app.kubernetes.io/name": "traefik"})
        allowed_in = {8443: {"hub", "frontdoor"}, 8080: {"traefik"}, 9105: {"prometheus"}}
        rows = []
        for port, who in allowed_in.items():
            for name, peer in sorted(pods.items()):
                if name != "nodeadm":
                    rows.append((peer, na, port, name in who))
            rows += [(app, na, port, False), (ext, na, port, False)]
        # The ingress namespace's Traefik only in HA (review M4: the
        # core-namespace peer only without HA).
        rows += [(ingress_traefik, na, 8080, ha), (ingress_traefik, na, 8443, False)]
        rows += [(na, pods["enroll"], 8444, True), (na, agent, 7443, True), (na, agent, 2379, False), (na, agent, 6443, True),
                 (na, agent, 22, False), (na, ext, 443, False), (na, node, 10250, False), (na, app, 80, False)]
        for name, peer in sorted(pods.items()):
            for port, proto in peer.ports:
                if not (name == "enroll" and port == 8444) and name != "nodeadm":
                    rows.append((na, peer, port, False))
        for src, dst, port, want in rows:
            if (src.name, dst.name) == ("frontdoor", "nodeadm") and not ha:
                continue  # the front door is HA only
            got = allowed(pols, src, dst, port, ingress_only=src.ns in (K.APPS_NS, "portcullis-ingress"))
            if got != want:
                F.add(f"nodeadm (ha {ha}): {src} → {dst}:{port}: {'allowed' if got else 'denied'}, want {'allowed' if want else 'denied'}")


def check_ha_flows():
    """Task 19's HA flows (plan Amendments 2, 3; preflight P39), on the CI HA
    values: Keycloak ↔ Keycloak on 7800 / 57800 (Infinispan) and nothing
    else reaches those ports (every other core pod, an app pod, Traefik, the
    internet); the session store and its Sentinels (Task 25) on 6379 /
    26379 among themselves and from the two oauth2-proxies only;
    Alertmanager ↔ Alertmanager on 9094 TCP / UDP and no other
    core pod or app pod (review M1); Traefik's 8081 / 8444 / 8082 from no
    app pod nor the internet (M3); the Hub
    alone of the core pods (the front door and nodeadm aside, their own
    flows) reaches the nodeagents' :7443 on the mesh, and no other mesh
    port; Traefik in portcullis-ingress reaches nodeadm :8080 and no
    internet, the world reaches its 8000 / 8443 and not its ping 8080; a pod
    of portcullis-ingress without Traefik's name label reaches no core
    pod."""
    vals = K.yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-ha.yaml").read_text())
    docs = K.render(vals)
    pols = K.by_kind(docs, "NetworkPolicy")
    pods = {}
    for name, ns, labels, spec, _ in K.pod_specs(docs):
        ports = [(p["containerPort"], p.get("protocol", "TCP")) for c in spec["containers"] for p in c.get("ports", [])]
        pods[name] = Peer(name, ns, labels, ports)
    kc, am, tr = pods["keycloak"], pods["alertmanager"], pods["traefik"]
    kc2, am2 = Peer("keycloak-1", kc.ns, kc.labels), Peer("alertmanager-1", am.ns, am.labels)
    app = Peer("app", K.APPS_NS, {"portcullis.io/instance": "echo", "portcullis.io/service": "web"})
    ext, agent = Peer("external", None, {}, ip=EXTERNAL), Peer("nodeagent", None, {}, ip=MESH_AGENT)
    stray = Peer("stray-ingress", K.INGRESS_NS, {"portcullis.io/component": "traefik"})
    nodeadm = Peer("nodeadm", "portcullis-nodeadm", {"portcullis.io/component": "nodeadm"})
    rows = [(kc, kc2, 7800, "TCP", True), (kc, kc2, 57800, "TCP", True), (kc2, kc, 7800, "TCP", True),
            (am, am2, 9094, "TCP", True), (am, am2, 9094, "UDP", True),
            (app, kc, 7800, "TCP", False), (app, kc, 57800, "TCP", False), (app, am, 9094, "TCP", False),
            (ext, kc, 7800, "TCP", False), (tr, kc, 7800, "TCP", False),
            (pods["hub"], agent, 7443, "TCP", True), (pods["hub"], agent, 7444, "TCP", False), (pods["hub"], agent, 10250, "TCP", False),
            (tr, nodeadm, 8080, "TCP", True), (tr, ext, 443, "TCP", False), (tr, ext, 80, "TCP", False),
            (ext, tr, 8000, "TCP", True), (ext, tr, 8443, "TCP", True), (ext, tr, 8080, "TCP", False), (app, tr, 8080, "TCP", False)]
    # Plan Task 25: the session store's master / replica and its Sentinels
    # reach each other; the oauth2-proxies reach both; nothing else does.
    ss, se = pods["sessions"], pods["sessions-sentinel"]
    ss2, se2 = Peer("sessions-1", ss.ns, ss.labels), Peer("sessions-sentinel-1", se.ns, se.labels)
    rows += [(ss, ss2, 6379, "TCP", True), (se, ss, 6379, "TCP", True), (ss, se, 26379, "TCP", True), (se, se2, 26379, "TCP", True),
             (pods["forward-auth"], se, 26379, "TCP", True), (pods["forward-auth-ext"], se, 26379, "TCP", True),
             (pods["forward-auth"], ss, 6379, "TCP", True), (app, se, 26379, "TCP", False), (ext, se, 26379, "TCP", False)]
    for name, peer in sorted(pods.items()):
        if name not in ("sessions", "sessions-sentinel", "forward-auth", "forward-auth-ext"):
            rows += [(peer, se, 26379, "TCP", False), (peer, ss, 6379, "TCP", False)]
    # Review M3: Traefik's internal entrypoints from an app pod and the
    # internet (core pods: check_compose).
    for port in (8081, 8444, 8082):
        rows += [(app, tr, port, "TCP", False), (ext, tr, port, "TCP", False)]
    # Review M1: the gossip port from every other core pod.
    for name, peer in sorted(pods.items()):
        if name != "alertmanager":
            rows += [(peer, am, 9094, "TCP", False), (peer, am, 9094, "UDP", False)]
    for name, peer in sorted(pods.items()):
        if name not in ("keycloak",):
            rows += [(peer, kc, 7800, "TCP", False), (peer, kc, 57800, "TCP", False)]
        if name not in ("hub", "frontdoor", "nodeadm"):
            rows.append((peer, agent, 7443, "TCP", False))
        for port, proto in peer.ports:
            if peer.ns == K.NS:
                rows.append((stray, peer, port, proto, False))
    for src, dst, port, proto, want in rows:
        got = allowed(pols, src, dst, port, proto, ingress_only=src.ns == K.APPS_NS)
        if got != want:
            F.add(f"ha flows: {src} → {dst}:{port}/{proto}: {'allowed' if got else 'denied'}, want {'allowed' if want else 'denied'}")


def check_postgres():
    """Plan Task 23 (contract §20.1 "Network flows"; spec §7.4): cnpg-system
    is default-deny; Postgres :5432 on the CNPG instances admits Keycloak,
    LLDAP and LLDAP's schema Job from the core namespace and the instances
    themselves, nothing else (every other core pod, a pod of another
    namespace wearing Keycloak's label, an app pod, the operator, the
    internet); the instances talk to each other on 5432 / 8000 and to the
    API server; the operator reaches the API server and the instances' 8000
    (not 5432), and its webhook :9443 admits only the API server's
    addresses (K.CNPG_API_SOURCES; the CLI's ha_cnpg_policies): no pod, not the internet; nothing
    else reaches the operator. Without and with HA."""
    vals = K.yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values.yaml").read_text())
    srcs = K.CNPG_API_SOURCES.split()
    api = [(e.split(":")[0], int(e.split(":")[1])) for e in vals["apiEndpoints"]]
    for ha in (False, True):
        docs = K.render({"ha": {"enabled": ha}})
        # cnpg-system's deny / DNS / operator flows are the CLI's (review I4),
        # the instances' the chart's: judged together, and the chart renders
        # none of the CLI's.
        mine = K.cnpg_policies()
        chart_cnpg = {p["metadata"]["name"] for p in K.by_kind(docs, "NetworkPolicy") if p["metadata"]["namespace"] == K.CNPG_NS}
        if chart_cnpg != {"portcullis-pg"}:
            F.add(f"postgres: the chart's cnpg-system policies {sorted(chart_cnpg)} (only portcullis-pg; the rest is the CLI's)")
        pols = K.by_kind(docs, "NetworkPolicy") + mine
        pods = {}
        for name, ns, labels, spec, _ in K.pod_specs(docs):
            ports = [(p["containerPort"], p.get("protocol", "TCP")) for c in spec["containers"] for p in c.get("ports", [])]
            pods[name] = Peer(name, ns, labels, ports)
        if not any(p["metadata"]["name"] == "default-deny" and p["spec"] == {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]} for p in mine):
            F.add("postgres: the CLI's cnpg-system policies have no default-deny of both directions")
        if "lldap-schema" not in pods:
            F.add("postgres: no lldap-schema Job pod rendered")
            return
        inst = Peer("portcullis-pg-1", K.CNPG_NS, {"cnpg.io/cluster": K.PG_CLUSTER, "cnpg.io/podRole": "instance"})
        inst2 = Peer("portcullis-pg-2", K.CNPG_NS, {"cnpg.io/cluster": K.PG_CLUSTER, "cnpg.io/podRole": "instance"})
        op = Peer("cnpg-operator", K.CNPG_NS, {"app.kubernetes.io/name": "cloudnative-pg", "app.kubernetes.io/instance": "cnpg"})
        stray = Peer("cnpg-stray", K.CNPG_NS, {"app": "x"})
        fake_kc = Peer("fake-keycloak", K.APPS_NS, {"portcullis.io/component": "keycloak", "portcullis.io/instance": "x"})
        app = Peer("app", K.APPS_NS, {"portcullis.io/instance": "echo", "portcullis.io/service": "web"})
        ext = Peer("external", None, {}, ip=EXTERNAL)
        rows = [(pods[n], inst, 5432, n in ("keycloak", "lldap", "lldap-schema")) for n in sorted(pods)]
        rows += [(inst, inst2, 5432, True), (inst2, inst, 8000, True), (op, inst, 8000, True), (op, inst, 5432, False),
                 (fake_kc, inst, 5432, False), (app, inst, 5432, False), (ext, inst, 5432, False), (stray, inst, 5432, False),
                 (stray, op, 9443, False), (inst, op, 9443, False), (pods["hub"], op, 9443, False), (ext, op, 9443, False),
                 (inst, ext, 443, False), (op, ext, 443, False), (inst, pods["hub"], 8888, False)]
        rows += [(Peer(f"apiserver-{ip}", None, {}, ip=ip), op, 9443, True) for ip in srcs]
        rows += [(Peer("node", None, {}, ip="10.1.0.9"), op, 9443, False)]
        rows += [(x, Peer("api", None, {}, ip=ip), port, True) for ip, port in api for x in (op, inst)]
        rows += [(stray, Peer("api", None, {}, ip=ip), port, False) for ip, port in api]
        for n in ("keycloak", "lldap", "lldap-schema"):
            rows += [(pods[n], inst, 8000, False), (pods[n], op, 9443, False)]
        for src, dst, port, want in rows:
            got = allowed(pols, src, dst, port, ingress_only=src.ns == K.APPS_NS)
            if got != want:
                F.add(f"postgres (ha {ha}): {src} → {dst}:{port}: {'allowed' if got else 'denied'}, want {'allowed' if want else 'denied'}")


def main():
    check_postgres()
    check_ha_flows()
    check_nodeadm()
    check_ha()
    check_log_ports()
    check_compose(K.render(), ha=False)
    check_compose(K.render({"ha": {"enabled": True}}), ha=True)
    return F.done()


def check_compose(docs, ha):
    """The compose network pairs (+ the port-bound rules); in HA the gates
    are port-bound too (their gate port as compose, the log port the Hub's)."""
    tag = "ha: " if ha else ""
    comp = K.compose()
    pols = K.by_kind(docs, "NetworkPolicy")
    pods = {}
    for name, ns, labels, spec, _ in K.pod_specs(docs):
        ports = []
        for c in spec["containers"]:
            for p in c.get("ports", []):
                ports.append((p["containerPort"], p.get("protocol", "TCP")))
        pods[name] = Peer(name, ns, labels, ports)
    nets = {}
    for name, svc in comp["services"].items():
        if name in K.ABSENT or name in K.REPLACED or name == "dns-tool":
            continue
        n = svc.get("networks") or []
        nets[name] = set(n if isinstance(n, list) else n.keys()) - K.ABSENT_NETS - K.VPN_NETS
    bound = {
        "keycloak": {8080: {"traefik"}, 9000: {"prometheus"}},
        "traefik": {8000: "any", 8443: "any", 8081: {"hub", "enroll", "forward-auth", "forward-auth-ext", "mcp-gate"},
                    8444: {"wg"}, 8082: {"prometheus"}, 8080: set()},
        "grafana": {3000: {"traefik"}},
        "wg": {9100: {"prometheus"}},
    }
    if ha:
        bound["group-gate"] = {8080: "any", 8091: {"hub"}}
        bound["mcp-gate"] = {8080: "any", 8092: {"hub"}}
        bound["wg"][8093] = {"hub"}
        # Review M1: Alertmanager's gossip, its peer alone.
        bound["alertmanager"] = {9093: "any", 9094: {"alertmanager"}}
    for src in sorted(nets):
        for dst in sorted(nets):
            if src == dst:
                continue
            for port, proto in pods[dst].ports:
                if dst in bound:
                    b = bound[dst].get(port)
                    if dst == "wg" and port not in (9100, 8093):
                        want = False  # edge and people ports: no core pod
                    elif b == "any":
                        want = bool(nets[src] & nets[dst])
                    else:
                        want = src in (b or set())
                elif src == "wg":
                    want = False
                else:
                    want = bool(nets[src] & nets[dst])
                if src == "wg" and dst == "traefik":
                    want = port == 8444
                got = allowed(pols, pods[src], pods[dst], port, proto)
                if got != want:
                    F.add(f"{tag}{src} → {dst}:{port}/{proto}: {'allowed' if got else 'denied'}, compose says {'allowed' if want else 'denied'}")
    # Synthetic peers.
    app = Peer("app", K.APPS_NS, {"portcullis.io/instance": "echo", "portcullis.io/service": "web"})
    gws = {n: Peer(f"gateway-{n}", K.APPS_NS, {"portcullis.io/instance": "hs", "portcullis.io/vpn-slot": str(n)}) for n in (0, 1, 46)}
    ext, node = Peer("external", None, {}, ip=EXTERNAL), Peer("node", None, {}, ip=NODE)
    for dst, port in [("traefik", 8000), ("traefik", 8443)]:
        if not allowed(pols, app, pods[dst], port, ingress_only=True) or not allowed(pols, ext, pods[dst], port):
            F.add(f"{tag}an app pod / the internet can't reach {dst}:{port}")
    for dst in sorted(nets):
        for port, proto in pods[dst].ports:
            if dst == "traefik" and port in (8000, 8443):
                continue
            if allowed(pols, app, pods[dst], port, proto, ingress_only=True):
                F.add(f"{tag}an app pod reaches {dst}:{port}")
            if dst == "wg" and port == 51820:
                if not allowed(pols, ext, pods[dst], port, proto):
                    F.add("the internet can't reach wg's people port")
                continue
            if allowed(pols, ext, pods[dst], port, proto):
                F.add(f"{tag}the internet reaches {dst}:{port}")
    for n, gw in gws.items():
        for m in (0, 1, 46):
            got = allowed(pols, gw, pods["wg"], 9001 + m, ingress_only=True)
            if got != (n == m):
                F.add(f"gateway slot {n} → wg:{9001 + m}: {'allowed' if got else 'denied'}")
        if allowed(pols, gw, pods["wg"], 9100, ingress_only=True):
            F.add(f"gateway slot {n} reaches wg's metrics")
    for name, peer in pods.items():
        if ha and name not in nets:
            continue  # the HA-only pods (the front door): check_ha
        eg = peer.labels.get("portcullis.io/egress") == "true"
        if allowed(pols, peer, ext, 443) != eg:
            F.add(f"{name}: internet egress {'denied' if eg else 'allowed'} (portcullis.io/egress {eg})")
        for port in (6443, 10250):
            want = port == 6443 and name in ("hub", "traefik")
            if allowed(pols, peer, node, port) != want:
                F.add(f"{name} → node:{port}: {'allowed' if not want else 'denied'}")
        if eg and not allowed(pols, peer, node, 443):
            F.add(f"{name}: no hairpin to the node on 443")
    if allowed(pols, pods["wg"], node, 6443):
        F.add("wg reaches the kube API")
    # Every policy names its peers (no rule without from / to).
    for p in pols:
        for field, key in (("ingress", "from"), ("egress", "to")):
            for rule in p["spec"].get(field) or []:
                if not rule.get(key):
                    F.add(f"{tag}policy {p['metadata']['name']}: a {field} rule without {key}")


if __name__ == "__main__":
    sys.exit(main())
