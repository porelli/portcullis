#!/usr/bin/env python3
"""The chart against docker-compose.yml, service by service (spec §3, Task 13):
image, uid/gid and groups, capabilities, read-only root, memory, environment
keys, mount targets (every one of the 46 project binds a ConfigMap / Secret
mount), probes (Task 4's mapping, K17), network labels; then every core
router's entrypoints for vpn mode apps|admin|server, its rule, priority,
middlewares and service; the entrypoint middlewares; the Traefik CRD bundle
at the compose Traefik version (K14). Reviewed differences live in
tests/k8s_parity_deltas.yaml, each with its reason; a delta that no longer
applies fails too (the list can't rot).

  python3 tests/k8s_parity.py
"""
import math
import re
import subprocess
import sys

import k8s_lib as K

F = K.Failures("k8s_parity")
D = K.deltas()
USED = set()


def delta(kind, svc, item):
    """True when (kind, svc, item) is a reviewed delta."""
    for e in D.get(kind, []):
        if e.get("service") in (svc, "*") and str(e.get("item")) == str(item):
            USED.add((kind, e.get("service"), str(e.get("item"))))
            return True
    return False


def interp(v):
    """compose ${VAR:-default} → default (the CI-values view of compose)."""
    if not isinstance(v, str):
        return v
    prev = None
    while prev != v:
        prev = v
        v = re.sub(r"\$\{[A-Z0-9_]+:-((?:[^{}]|\{[^{}]*\})*)\}", r"\1", v)
        v = re.sub(r"\$\{[A-Z0-9_]+(:?\?[^}]*)?\}", "", v)
    return v


def env_keys(svc):
    e = svc.get("environment") or {}
    if isinstance(e, list):
        return {x.split("=", 1)[0] for x in e}
    return set(e)


def health_cmd(test):
    if test[0] == "CMD-SHELL":
        return ["sh", "-c", test[1]]
    if test[0] == "CMD":
        return list(test[1:])
    return None


def mount_covers(target, mounts, vols):
    """A compose target is a chart mount target, or a path inside one whose
    volume carries it (an item path / the whole object)."""
    for m in mounts:
        mp = m["mountPath"]
        if target == mp:
            return m
        if target.startswith(mp.rstrip("/") + "/"):
            rel = target[len(mp.rstrip("/")) + 1:]
            v = vols.get(m["name"], {})
            srcs = []
            if "projected" in v:
                srcs = [s.get("configMap") or s.get("secret") for s in v["projected"]["sources"]]
            elif "configMap" in v or "secret" in v:
                srcs = [v.get("configMap") or v.get("secret")]
            for s in srcs:
                items = (s or {}).get("items")
                if not items:
                    return m
                for it in items:
                    if it["path"] == rel or it["path"].startswith(rel + "/"):
                        return m
    return None


def check_services(comp, docs):
    deps = K.deployments(docs)
    imgs = K.images_values()["images"]
    for name, svc in sorted(comp["services"].items()):
        if name in K.ABSENT or name == "dns-tool":
            continue
        dep = deps.get(name)
        if not dep:
            F.add(f"{name}: no Deployment in the chart")
            continue
        pod = dep["spec"]["template"]["spec"]
        c = pod["containers"][0]
        sc = c.get("securityContext", {})
        psc = pod.get("securityContext", {})
        labels = dep["spec"]["template"]["metadata"].get("labels", {})
        # image: the chart's images.<svc>, = compose's ref for a pinned one.
        if c["image"] != imgs.get(name):
            F.add(f"{name}: image {c['image']} is not images.{name}")
        ci = interp(svc.get("image", ""))
        if "@sha256:" in ci and ci.split("@")[1] != c["image"].split("@")[1]:
            F.add(f"{name}: image digest differs from compose ({ci})")
        # uid / gid
        if "user" in svc:
            u, _, g = str(svc["user"]).partition(":")
            if (str(psc.get("runAsUser")), str(psc.get("runAsGroup"))) != (u, g or u) and not delta("user", name, svc["user"]):
                F.add(f"{name}: runAs {psc.get('runAsUser')}:{psc.get('runAsGroup')} != compose user {svc['user']}")
        elif not delta("user", name, f"{psc.get('runAsUser')}:{psc.get('runAsGroup')}"):
            F.add(f"{name}: compose has no user (the image's), the chart runs {psc.get('runAsUser')}:{psc.get('runAsGroup')}: add a reviewed delta")
        ga = sorted(int(x) for x in svc.get("group_add", []))
        if ga != sorted(psc.get("supplementalGroups", [])):
            F.add(f"{name}: supplementalGroups {psc.get('supplementalGroups')} != group_add {ga}")
        # capabilities
        add = sorted(svc.get("cap_add", []))
        cadd = sorted(sc.get("capabilities", {}).get("add", []))
        if add != cadd and not delta("caps", name, ",".join(add) + "->" + ",".join(cadd)):
            F.add(f"{name}: capabilities add {cadd} != compose cap_add {add}")
        if sc.get("capabilities", {}).get("drop") != ["ALL"]:
            F.add(f"{name}: capabilities don't drop ALL")
        # read-only root
        if bool(svc.get("read_only", False)) != bool(sc.get("readOnlyRootFilesystem")):
            F.add(f"{name}: readOnlyRootFilesystem {sc.get('readOnlyRootFilesystem')} != compose read_only {svc.get('read_only', False)}")
        # memory
        lim = c.get("resources", {}).get("limits", {}).get("memory")
        req = c.get("resources", {}).get("requests", {}).get("memory")
        if "mem_limit" in svc and (lim is None or K.mem_bytes(lim) != K.mem_bytes(svc["mem_limit"]) or lim != req):
            F.add(f"{name}: memory limit {lim} / request {req} != compose mem_limit {svc['mem_limit']}")
        # environment keys
        ck = env_keys(svc)
        kk = {e["name"] for e in c.get("env", [])}
        for k in sorted(ck - kk):
            if not delta("env-missing", name, k):
                F.add(f"{name}: env {k} (compose) missing in the chart")
        for k in sorted(kk - ck):
            if not delta("env-extra", name, k):
                F.add(f"{name}: env {k} only in the chart")
        # mounts
        mounts = c.get("volumeMounts", [])
        vols = {v["name"]: v for v in pod.get("volumes", [])}
        for v in svc.get("volumes", []):
            if isinstance(v, str):
                parts = v.split(":")
                src, target = parts[0], parts[1]
            else:
                src, target = v.get("source", ""), v["target"]
            if "docker.sock" in target:
                continue
            m = mount_covers(target, mounts, vols)
            if not m:
                if not delta("mount", name, target):
                    F.add(f"{name}: mount target {target} (compose {src}) has no chart mount")
                continue
            vol = vols.get(m["name"], {})
            bind = isinstance(v, str) and (src.startswith(".") or src.startswith("$"))
            if bind and not any(k in vol for k in ("configMap", "secret", "projected")) and not delta("bind", name, target):
                F.add(f"{name}: project bind {src} → {target} is not a ConfigMap / Secret mount")
        for t in svc.get("tmpfs", []):
            target = t.split(":")[0]
            m = mount_covers(target, mounts, vols)
            if not m or "emptyDir" not in vols.get(m["name"], {}):
                F.add(f"{name}: tmpfs {target} is not an emptyDir")
            elif ":" in t and "mode=" in t and not delta("tmpfs-mode", name, target):
                F.add(f"{name}: tmpfs {t}: the mode isn't carried (add a reviewed delta)")
        # probes (K17)
        hc = svc.get("healthcheck")
        if hc and not hc.get("disable"):
            cmd = health_cmd(hc["test"])
            iv, to, re_ = K.seconds(hc.get("interval", "30s")), K.seconds(hc.get("timeout", "30s")), int(hc.get("retries", 3))
            rp, lp, sp = c.get("readinessProbe"), c.get("livenessProbe"), c.get("startupProbe")
            want = {"command": cmd, "periodSeconds": iv, "timeoutSeconds": to}
            for nm, p, fth in (("readiness", rp, re_), ("liveness", lp, re_ * 2)):
                if not p:
                    F.add(f"{name}: no {nm}Probe for the compose healthcheck")
                    continue
                got = {"command": p["exec"]["command"], "periodSeconds": p["periodSeconds"], "timeoutSeconds": p["timeoutSeconds"]}
                if got != want or p["failureThreshold"] != fth or "initialDelaySeconds" in p:
                    F.add(f"{name}: {nm}Probe {p} != compose healthcheck {hc}")
            if "start_period" in hc:
                st = K.seconds(hc["start_period"])
                fth = math.ceil(st / iv) + re_
                if not sp or sp["exec"]["command"] != cmd or sp["periodSeconds"] != iv or sp["failureThreshold"] != fth:
                    F.add(f"{name}: startupProbe {sp} != start_period {hc['start_period']} (want failureThreshold {fth})")
            elif sp:
                F.add(f"{name}: a startupProbe without a compose start_period")
        elif any(c.get(p) for p in ("readinessProbe", "livenessProbe", "startupProbe")):
            F.add(f"{name}: probes without a compose healthcheck")
        # networks → labels
        nets = svc.get("networks") or ["default"]
        nets = set(nets if isinstance(nets, list) else nets.keys()) - K.ABSENT_NETS
        lab = {k[len("portcullis.io/net-"):] for k in labels if k.startswith("portcullis.io/net-")}
        if nets != lab:
            F.add(f"{name}: net labels {sorted(lab)} != compose networks {sorted(nets)}")
        nonint = {n for n in nets if not (comp["networks"].get(n) or {}).get("internal")}
        if bool(nonint) != (labels.get("portcullis.io/egress") == "true"):
            F.add(f"{name}: portcullis.io/egress {labels.get('portcullis.io/egress')} but non-internal networks {sorted(nonint)}")
        if labels.get("portcullis.io/component") != name:
            F.add(f"{name}: portcullis.io/component label missing")
    # dns-tool: the one-shot pod.
    one = [d for d in K.render({"oneshot": "dns-tool"}, "templates/oneshot.yaml") if d.get("kind") == "Pod"]
    if not one:
        F.add("dns-tool: no one-shot pod (templates/oneshot.yaml)")
    else:
        c = one[0]["spec"]["containers"][0]
        if c["command"] != comp["services"]["dns-tool"]["entrypoint"]:
            F.add(f"dns-tool: command {c['command']} != compose entrypoint")
        if c["image"] != imgs.get("dns-tool"):
            F.add("dns-tool: image isn't images.dns-tool")


def count_binds(comp):
    n = 0
    for name, svc in comp["services"].items():
        for v in svc.get("volumes", []):
            if isinstance(v, str) and (v.startswith(".") or v.startswith("${PORTCULLIS_ENGINE")) and "docker.sock" not in v:
                n += 1
    return n


# ── routers ──

DOCKER_TO_K8S = {
    "portcullis-auth": "portcullis-auth@file", "portcullis-auth-ext": "portcullis-auth-ext@file",
    "portcullis-groups": "portcullis-groups@file", "portcullis-groups-vpn": "portcullis-groups-vpn@file",
    "portcullis-public-guard": "portcullis-public-guard@file", "portcullis-public-guard-vpn": "portcullis-public-guard-vpn@file",
    "vpn-required-path": "vpn-required-path@file",
    "hub-proxy-secret": "hub-proxy-secret", "portcullis-auth-console": "portcullis-auth-console",
    "portal-path": "portal-path", "portal-vpn-path": "portal-vpn-path", "directory-redirect": "directory-redirect",
}


def classes(mode):
    out = subprocess.run(["bash", "-c", f'source "{K.ROOT}/scripts/lib/common.sh" >/dev/null 2>&1; source "{K.ROOT}/scripts/lib/network.sh"; source "{K.ROOT}/scripts/lib/vpn.sh"; vpn_entrypoints {mode} true'],
                         check=True, capture_output=True, text=True).stdout
    return dict(line.split("=", 1) for line in out.split())


def compose_routers(comp, cls):
    routers = {}
    for name, svc in comp["services"].items():
        if name in K.ABSENT:
            continue
        labels = svc.get("labels") or {}
        if isinstance(labels, list):
            labels = dict(x.split("=", 1) for x in labels)
        for k, v in labels.items():
            m = re.match(r"traefik\.http\.routers\.([^.]+)\.(.+)$", k)
            if not m:
                continue
            r = routers.setdefault(m.group(1), {"owner": name})
            val = str(v)
            for key, cv in cls.items():
                val = re.sub(r"\$\{" + key + r":-[^}]*\}", cv, val)
            r[m.group(2)] = interp(val)
    return routers


def compose_ports(comp):
    """{traefik service name: its loadbalancer.server.port} from compose labels."""
    out = {}
    for svc in comp["services"].values():
        labels = svc.get("labels") or {}
        if isinstance(labels, list):
            labels = dict(x.split("=", 1) for x in labels)
        for k, v in labels.items():
            m = re.match(r"traefik\.http\.services\.([^.]+)\.loadbalancer\.server\.port$", k)
            if m:
                out[m.group(1)] = str(v)
    return out


def check_routers(comp):
    for mode in ("apps", "admin", "server"):
        cls = classes(mode)
        vals = {"entrypoints": {"ep": {"core": cls["PORTCULLIS_EP_CORE"], "admin": cls["PORTCULLIS_EP_ADMIN"], "enrol": cls["PORTCULLIS_EP_ENROL"]},
                                "web": {"core": cls["PORTCULLIS_WEB_CORE"], "admin": cls["PORTCULLIS_WEB_ADMIN"], "enrol": cls["PORTCULLIS_WEB_ENROL"]}},
                "vpn": {"mode": mode}}
        docs = K.render(vals)
        irs = {d["metadata"]["name"]: d for d in K.by_kind(docs, "IngressRoute")}
        cr = compose_routers(comp, cls)
        for rname, r in sorted(cr.items()):
            ir = irs.get(rname)
            if not ir:
                F.add(f"router {rname} ({r['owner']}): no IngressRoute")
                continue
            want_ep = r.get("entrypoints", "websecure").split(",")
            if ir["spec"]["entryPoints"] != want_ep:
                F.add(f"vpn mode {mode}: router {rname} entrypoints {ir['spec']['entryPoints']} != compose {want_ep}")
            route = ir["spec"]["routes"][0]
            want_rule = r["rule"].replace("ci.example.org", "ci.example.org")
            if route["match"] != interp(want_rule).replace("portcullis.local", "ci.example.org"):
                F.add(f"router {rname}: rule {route['match']!r} != compose {r['rule']!r}")
            # Core routes rank above every app route on Kubernetes: 10000 +
            # compose's priority (else Traefik's default len(rule)).
            want_prio = 10000 + (int(r["priority"]) if r.get("priority") else len(route["match"]))
            if route.get("priority") != want_prio:
                F.add(f"router {rname}: priority {route.get('priority')} != 10000 + compose's {r.get('priority') or 'len(rule)'} ({want_prio})")
            want_mw = []
            for mw in [x for x in r.get("middlewares", "").split(",") if x]:
                base, _, prov = mw.partition("@")
                want_mw.append(DOCKER_TO_K8S.get(base, mw) if prov == "docker" else mw)
            got_mw = [m["name"] for m in route.get("middlewares", [])]
            if got_mw != want_mw:
                F.add(f"router {rname}: middlewares {got_mw} != compose {want_mw}")
            svc = r.get("service", rname)
            gs = route["services"][0]["name"]
            # Core backends are file-provider services core-<service>-<port>@file
            # (the IngressRoutes live in the edge namespace): compare the
            # service and the compose port.
            m = re.match(r"^core-(.+)-([0-9]+)@file$", gs)
            if m:
                gs = m.group(1)
                want_port = compose_ports(comp).get(svc)
                if want_port and m.group(2) != want_port:
                    F.add(f"router {rname}: port {m.group(2)} != compose {want_port}")
            elif not gs.endswith("@internal"):
                F.add(f"router {rname}: service {gs} isn't a core-<service>-<port>@file or @internal service")
            if gs != svc and not (svc == "hub-people" and gs == "hub") and not (svc == rname and gs == r["owner"]) \
               and not (svc == "grafana-metrics" and gs == "grafana"):
                F.add(f"router {rname}: service {gs} != compose {svc}")
            if ir["spec"].get("tls", {}).get("options", {}).get("name") != r.get("tls.options"):
                F.add(f"router {rname}: tls options {ir['spec'].get('tls')} != compose {r.get('tls.options')}")
        for extra in sorted(set(irs) - set(cr) - {"kcinternal"}):
            F.add(f"IngressRoute {extra}: no compose router")


def check_traefik(comp, docs):
    c = K.deployments(docs)["traefik"]["spec"]["template"]["spec"]["containers"][0]
    env = {e["name"]: e.get("value") for e in c["env"]}
    ce = comp["services"]["traefik"]["environment"]
    for ep in ("WEBSECURE", "VPNSECURE"):
        k = f"TRAEFIK_ENTRYPOINTS_{ep}_HTTP_MIDDLEWARES"
        if env.get(k) != ce.get(k):
            F.add(f"traefik: {k} {env.get(k)} != compose {ce.get(k)}")
    for ep in ("WEBSECURE", "VPNSECURE", "KCINTERNAL"):
        if env.get(f"TRAEFIK_ENTRYPOINTS_{ep}_HTTP_MIDDLEWARES") != "strip-client-forwarded@file":
            F.add(f"traefik: entrypoint {ep} doesn't run strip-client-forwarded@file first")
        if env.get(f"TRAEFIK_ENTRYPOINTS_{ep}_HTTP_ALIASHEADERSSTRATEGY") != "delete":
            F.add(f"traefik: entrypoint {ep} keeps header aliases")
    for k, v in env.items():
        if re.search(r"FORWARDEDHEADERS|PROXYPROTOCOL_INSECURE", k):
            F.add(f"traefik: {k} must never be set")
    # K14: the CRD bundle follows the compose Traefik version.
    ver = re.search(r"traefik:(v[0-9.]+)@", comp["services"]["traefik"]["image"]).group(1)
    crds = sorted(p.name for p in (K.CHART / "crds").glob("*.yaml"))
    if crds != [f"traefik-{ver}.yaml"]:
        F.add(f"charts/portcullis/crds: {crds} != [traefik-{ver}.yaml] (K14: the compose Traefik version)")


def main():
    comp = K.compose()
    docs = K.render()
    nb = count_binds(comp)
    if nb != 46:
        F.add(f"compose has {nb} project binds, the parity map expects 46 (update this check and docker-compose.podman-selinux.yml)")
    check_services(comp, docs)
    check_routers(comp)
    check_traefik(comp, docs)
    for kind, items in D.items():
        for e in items:
            if (kind, e.get("service"), str(e.get("item"))) not in USED:
                F.add(f"stale delta {kind} {e.get('service')} {e.get('item')}: it no longer applies")
            if not e.get("reason"):
                F.add(f"delta {kind} {e.get('service')} {e.get('item')} has no reason")
    return F.done()


if __name__ == "__main__":
    sys.exit(main())
