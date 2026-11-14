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
            return pod.ns not in (K.NS, K.APPS_NS)  # both namespaces are default-deny
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


def main():
    comp = K.compose()
    docs = K.render()
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
        if name in K.ABSENT or name == "dns-tool":
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
    for src in sorted(nets):
        for dst in sorted(nets):
            if src == dst:
                continue
            for port, proto in pods[dst].ports:
                if dst in bound:
                    b = bound[dst].get(port)
                    if dst == "wg" and port != 9100:
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
                    F.add(f"{src} → {dst}:{port}/{proto}: {'allowed' if got else 'denied'}, compose says {'allowed' if want else 'denied'}")
    # Synthetic peers.
    app = Peer("app", K.APPS_NS, {"portcullis.io/instance": "echo", "portcullis.io/service": "web"})
    gws = {n: Peer(f"gateway-{n}", K.APPS_NS, {"portcullis.io/instance": "hs", "portcullis.io/vpn-slot": str(n)}) for n in (0, 1, 46)}
    ext, node = Peer("external", None, {}, ip=EXTERNAL), Peer("node", None, {}, ip=NODE)
    for dst, port in [("traefik", 8000), ("traefik", 8443)]:
        if not allowed(pols, app, pods[dst], port, ingress_only=True) or not allowed(pols, ext, pods[dst], port):
            F.add(f"an app pod / the internet can't reach {dst}:{port}")
    for dst in sorted(nets):
        for port, proto in pods[dst].ports:
            if dst == "traefik" and port in (8000, 8443):
                continue
            if allowed(pols, app, pods[dst], port, proto, ingress_only=True):
                F.add(f"an app pod reaches {dst}:{port}")
            if dst == "wg" and port == 51820:
                if not allowed(pols, ext, pods[dst], port, proto):
                    F.add("the internet can't reach wg's people port")
                continue
            if allowed(pols, ext, pods[dst], port, proto):
                F.add(f"the internet reaches {dst}:{port}")
    for n, gw in gws.items():
        for m in (0, 1, 46):
            got = allowed(pols, gw, pods["wg"], 9001 + m, ingress_only=True)
            if got != (n == m):
                F.add(f"gateway slot {n} → wg:{9001 + m}: {'allowed' if got else 'denied'}")
        if allowed(pols, gw, pods["wg"], 9100, ingress_only=True):
            F.add(f"gateway slot {n} reaches wg's metrics")
    for name, peer in pods.items():
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
                    F.add(f"policy {p['metadata']['name']}: a {field} rule without {key}")
    return F.done()


if __name__ == "__main__":
    sys.exit(main())
