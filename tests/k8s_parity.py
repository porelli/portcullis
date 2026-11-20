#!/usr/bin/env python3
"""The chart against docker-compose.yml, service by service (spec §3, Task 13):
image, uid/gid and groups, capabilities, read-only root, memory, environment
keys, mount targets (every one of the 51 project binds a ConfigMap / Secret
mount), probes (Task 4's mapping, K17), network labels; then every core
router's entrypoints for vpn mode apps|admin|server, its rule, priority,
middlewares and service; the entrypoint middlewares; the Traefik CRD bundle
at the compose Traefik version (K14); the published documents (contract §4:
"ha: every reader mounts its published documents through a projected
volume, never subPath", in every render). Reviewed differences live in
tests/k8s_parity_deltas.yaml, each with its reason; a delta that no longer
applies fails too (the list can't rot).

  python3 tests/k8s_parity.py
"""
import json
import math
import re
import subprocess
import sys

import k8s_lib as K
yaml = K.yaml

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
        if name in K.ABSENT or name in K.REPLACED or name == "dns-tool":
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
        ga = sorted(int(x) for x in svc.get("group_add", []) if not delta("groups", name, x))
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
        # The limit is compose's mem_limit; the request the measured peak
        # × 1.25 (values memoryPeakMi, plan Amendment 2), never above it.
        if "mem_limit" in svc and (lim is None or K.mem_bytes(lim) != K.mem_bytes(svc["mem_limit"])
                                   or req is None or K.mem_bytes(req) != K.mem_request(name, lim)):
            F.add(f"{name}: memory limit {lim} / request {req} != compose mem_limit {svc['mem_limit']} / request {K.mem_request(name, lim) if lim else '?'}")
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
        elif c.get("livenessProbe") or c.get("startupProbe"):
            F.add(f"{name}: liveness / startup probes without a compose healthcheck")
        elif c.get("readinessProbe"):
            rp = c["readinessProbe"]
            hg = rp.get("httpGet") or {}
            if "exec" in rp or not hg or not delta("kube-probe", name, f"{hg.get('path')}:{hg.get('port')}"):
                F.add(f"{name}: a readinessProbe without a compose healthcheck (only a reviewed kube-probe httpGet)")
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
    "hub-proxy-secret": "hub-proxy-secret", "hub-cli-proxy-secret": "hub-cli-proxy-secret", "portcullis-auth-console": "portcullis-auth-console",
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
            if gs != svc and not (svc in ("hub-people", "hub-cli") and gs == "hub") and not (svc == rname and gs == r["owner"]) \
               and not (svc == "grafana-metrics" and gs == "grafana"):
                F.add(f"router {rname}: service {gs} != compose {svc}")
            if ir["spec"].get("tls", {}).get("options", {}).get("name") != r.get("tls.options"):
                F.add(f"router {rname}: tls options {ir['spec'].get('tls')} != compose {r.get('tls.options')}")
        for extra in sorted(set(irs) - set(cr) - {"kcinternal", "portcullis-node"}):
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


PUB_DIRS = ("/hub-data", "/vpn-doc")


def published_problems(docs):
    """Contract §4 "On Kubernetes: published documents", against the rows of
    tests/published_docs.json (the Hub's byte copy): the eight objects
    rendered empty (no key) and kept; every reader mounts its rows through
    ONE projected volume per directory, read-only, never subPath, each
    object exactly once with items [its key, .rev → .rev-<doc>] at the
    row's mode and optional: true; the Secret's reader has the row's
    fsGroup; no reader mounts the Hub's PVCs there; every reader has the
    portcullis-bin init container (the Hub's image) and /portcullis-bin
    read-only in its container; no other pod projects a pub-* object."""
    out = []
    rows = json.loads((K.ROOT / "tests" / "published_docs.json").read_text())
    # The chart renders from its own byte copy: both are the Hub's file.
    if (K.CHART / "files" / "published_docs.json").read_bytes() != (K.ROOT / "tests" / "published_docs.json").read_bytes():
        out.append("charts/portcullis/files/published_docs.json differs from tests/published_docs.json (both are byte copies of the Hub's)")
    objs = {(d["kind"], d["metadata"]["name"]): d for d in docs if d.get("kind") in ("ConfigMap", "Secret")
            and d["metadata"]["name"].startswith("pub-")}
    want = {("Secret" if r["kind"] == "secret" else "ConfigMap", r["object"]) for r in rows}
    if set(objs) != want:
        out.append(f"published objects {sorted(objs)} != published_docs.json {sorted(want)}")
    for (kind, name), d in objs.items():
        if d.get("data") or d.get("stringData") or d.get("binaryData"):
            out.append(f"{kind} {name}: rendered with keys (the chart creates it empty; the Hub writes the document and .rev)")
        if (d["metadata"].get("annotations") or {}).get("helm.sh/resource-policy") != "keep":
            out.append(f"{kind} {name}: not helm.sh/resource-policy: keep")
    readers = sorted({x for r in rows for x in r["readers"]})
    hub_img = K.images_values()["images"]["hub"]
    pods = {n: sp for n, _, _, sp, _ in K.pod_specs(docs)}
    for name, sp in sorted(pods.items()):
        vols = {v["name"]: v for v in sp.get("volumes", [])}
        projected = {s_.get(k, {}).get("name") for v in vols.values() for s_ in v.get("projected", {}).get("sources", []) for k in ("configMap", "secret")}
        projected |= {(v.get("configMap") or {}).get("name") for v in vols.values()} | {(v.get("secret") or {}).get("secretName") for v in vols.values()}
        if name not in readers:
            if any(str(x).startswith("pub-") for x in projected):
                out.append(f"{name}: mounts a published document but isn't its reader")
            continue
        mine = [r for r in rows if name in r["readers"]]
        c = sp["containers"][0]
        for d_ in PUB_DIRS:
            rs = [r for r in mine if r["mount"] == d_]
            ms = [m for c_ in sp["containers"] for m in c_.get("volumeMounts", []) if m["mountPath"] == d_ or m["mountPath"].startswith(d_ + "/")]
            if not rs:
                if ms:
                    out.append(f"{name}: mounts {d_} without a document there")
                continue
            if len(ms) != 1 or ms[0]["mountPath"] != d_ or "subPath" in ms[0] or "subPathExpr" in ms[0] or ms[0].get("readOnly") is not True:
                out.append(f"{name}: {d_} must be one read-only mount of the whole projected volume, never subPath: {ms}")
                continue
            v = vols.get(ms[0]["name"], {})
            if set(v) != {"name", "projected"}:
                out.append(f"{name}: {d_} is {sorted(set(v) - {'name'})}, not a projected volume (never the Hub's PVC)")
                continue
            got = {}
            for src in v["projected"]["sources"]:
                (k, o), = src.items()
                got.setdefault(o["name"], []).append((k, o))
            if sorted(got) != sorted(r["object"] for r in rs):
                out.append(f"{name}: {d_} projects {sorted(got)} != its rows {sorted(r['object'] for r in rs)}")
            for r in rs:
                srcs = got.get(r["object"], [])
                if len(srcs) != 1:
                    continue
                k, o = srcs[0]
                mode = int(r["mode"], 8)
                if r["rev_path"] != f"{d_}/.rev-{r['doc']}":
                    out.append(f"published_docs.json {r['doc']}: rev_path {r['rev_path']} (want {d_}/.rev-{r['doc']})")
                items = [{"key": r["key"], "path": r["key"], "mode": mode}, {"key": ".rev", "path": r["rev_path"][len(d_) + 1:], "mode": mode}]
                if k != ("secret" if r["kind"] == "secret" else "configMap") or o.get("items") != items \
                        or o.get("optional") is not r["optional"] or set(o) != {"name", "items", "optional"}:
                    out.append(f"{name}: {r['object']} projected as {k} {o} (want items {items}, optional {r['optional']})")
                if r["fs_group"] is not None and sp.get("securityContext", {}).get("fsGroup") != r["fs_group"]:
                    out.append(f"{name}: fsGroup {sp.get('securityContext', {}).get('fsGroup')} (reads {r['object']}: fs_group {r['fs_group']})")
        inits = [i for i in sp.get("initContainers", []) if i["name"] == "portcullis-bin"]
        binm = [m for m in c.get("volumeMounts", []) if m["mountPath"] == "/portcullis-bin"]
        if len(inits) != 1 or inits[0]["image"] != hub_img \
                or inits[0].get("command") != ["/usr/local/bin/hub", "seed-self", "/portcullis-bin"] \
                or [(m["mountPath"], m.get("readOnly", False)) for m in inits[0].get("volumeMounts", [])] != [("/portcullis-bin", False)]:
            out.append(f"{name}: no portcullis-bin init container with the Hub's image copying hub to /portcullis-bin")
        elif len(binm) != 1 or binm[0].get("readOnly") is not True or "emptyDir" not in vols.get(binm[0]["name"], {}) \
                or binm[0]["name"] != inits[0]["volumeMounts"][0]["name"]:
            out.append(f"{name}: /portcullis-bin isn't the init container's emptyDir, read-only in {c['name']}")
    for r in readers:
        if r not in pods:
            out.append(f"reader {r}: no pod rendered")
    return out


def check_published():
    for label, extra in (("", None), ("ha: ", {"ha": {"enabled": True}}), ("ha: ", {"ha": {"enabled": True, "gateReplicas": 2}})):
        for p in published_problems(K.render(extra)):
            F.add(f"{label}{p}")
    # The check bites: a subPath, a PVC, a missing optional, a stray reader.
    import copy as _c
    base = K.render({"ha": {"enabled": True}})
    if published_problems(base):
        return  # reported above; the mutations need a passing chart

    def pod(docs, n):
        return next(sp for nm, _, _, sp, _ in K.pod_specs(docs) if nm == n)

    def subpath(d):
        m = next(m for m in pod(d, "group-gate")["containers"][0]["volumeMounts"] if m["mountPath"] == "/hub-data")
        m["subPath"] = "group-gate-policy.json"

    def pvc(d):
        v = next(v for v in pod(d, "keycloak")["volumes"] if v["name"] == "hub-data")
        v.pop("projected")
        v["persistentVolumeClaim"] = {"claimName": "hub-data", "readOnly": True}

    def required(d):
        v = next(v for v in pod(d, "mcp-gate")["volumes"] if v["name"] == "hub-data")
        v["projected"]["sources"][0][next(iter(v["projected"]["sources"][0]))]["optional"] = False

    def stray(d):
        pod(d, "lldap")["volumes"].append({"name": "x", "projected": {"sources": [{"configMap": {"name": "pub-vpn"}}]}})

    def nobin(d):
        sp = pod(d, "wg")
        sp["initContainers"] = []

    for what, mut in (("a subPath", subpath), ("a reader on the Hub's PVC", pvc), ("a required source", required),
                      ("a non-reader projecting pub-vpn", stray), ("a reader without portcullis-bin", nobin)):
        d = _c.deepcopy(base)
        mut(d)
        if not published_problems(d):
            F.add(f"published_problems misses {what} (mutation test)")


NODE_PATHS = ["/node/join.sh", "/node/nodeagent-amd64", "/node/nodeagent-arm64", "/node/v1/nonce", "/node/v1/enrol",
              "/node/v1/join", "/node/v1/renew", "/node/v1/renew/confirm"]
ACME_ENV = re.compile(r"^(TRAEFIK_CERTIFICATESRESOLVERS_|TRAEFIK_ENTRYPOINTS_(WEBSECURE|VPNSECURE)_HTTP_TLS_|CF_|GCE_|PORKBUN_|AWS_|DO_|HETZNER_)")


def check_ha():
    """Task 19, HA against the plain chart (compose's form on Kubernetes):
    "ha: wg-people externalTrafficPolicy Cluster" (Local without HA); the
    Traefik DaemonSet has the Deployment's environment minus the ACME
    resolver and the DNS credentials (no ACME in HA), hostPort 80 / 443 on
    web / websecure; the Keycloak routers (and kcinternal) end with
    core-retry@file in HA only, no other router has it (not the single Hub:
    review M6); traefik-dynamic's core-retry is 3 attempts, the Keycloak
    services alone have the passive health check and the fast dial,
    Keycloak's servers its replicas by name;
    router portcullis-node (nodeadm on, both modes) is the main domain's
    exact /node/ paths with rate-limit@file to the edge Service
    portcullis-node:8080."""
    vals = yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-ha.yaml").read_text())
    ha, plain = K.render(vals), K.render()
    svc = lambda docs, n: next(s for s in K.by_kind(docs, "Service") if s["metadata"]["name"] == n)
    if svc(ha, "wg-people")["spec"].get("externalTrafficPolicy") != "Cluster":
        F.add("ha: wg-people externalTrafficPolicy Cluster (contract §16.1: a handshake through any ingress node)")
    if svc(plain, "wg-people")["spec"].get("externalTrafficPolicy") != "Local":
        F.add("wg-people externalTrafficPolicy Local without HA")
    tr = lambda docs, k: next(d for d in docs if d.get("kind") == k and d["metadata"]["name"] == "traefik")["spec"]["template"]["spec"]["containers"][0]
    ce, he = tr(plain, "Deployment"), tr(ha, "DaemonSet")
    want = {e["name"]: e for e in ce["env"] if not ACME_ENV.match(e["name"])}
    if {e["name"]: e for e in he["env"]} != want:
        F.add(f"ha: traefik's environment differs from the Deployment's beyond the ACME resolver: {sorted(set(e['name'] for e in he['env']) ^ set(want))}")
    hp = {p["name"]: p.get("hostPort") for p in he["ports"]}
    if hp != {"web": 80, "websecure": 443, "kcinternal": None, "vpnsecure": None, "ping": None, "metrics": None}:
        F.add(f"ha: traefik hostPorts {hp} (web 80, websecure 443 only)")
    retry_svcs = ("keycloak",)  # not the single Hub (review M6)
    for label, docs in (("ha: ", ha), ("", plain)):
        for ir in K.by_kind(docs, "IngressRoute"):
            r = ir["spec"]["routes"][0]
            mws = [m["name"] for m in r.get("middlewares", [])]
            svcname = r["services"][0]["name"]
            want_retry = bool(label) and (ir["metadata"]["name"] == "kcinternal" or any(svcname.startswith(f"core-{s}-") for s in retry_svcs))
            if ("core-retry@file" in mws) != want_retry or (want_retry and mws[-1] != "core-retry@file"):
                F.add(f"{label}router {ir['metadata']['name']}: middlewares {mws} ({'last core-retry@file' if want_retry else 'no core-retry@file'})")
    dyn = next(c for c in ha if c.get("kind") == "ConfigMap" and c["metadata"]["name"] == "traefik-dynamic")
    if dyn["metadata"]["namespace"] != K.INGRESS_NS:
        F.add(f"ha: traefik-dynamic in {dyn['metadata']['namespace']} (Traefik's namespace)")
    http = yaml.safe_load(dyn["data"]["kubernetes.yml"])["http"]
    if http["middlewares"].get("core-retry", {}).get("retry", {}).get("attempts") != 3:
        F.add("ha: core-retry must be retry attempts 3")
    kc = 3 if vals["ha"].get("nonSmallNodesAtPrimary", 0) >= 3 else 2
    for name, s in http["services"].items():
        lb = s["loadBalancer"]
        hc = name.startswith("core-keycloak-")
        if hc != ("passiveHealthCheck" in lb) or hc != (lb.get("serversTransport") == "core-fast"):
            F.add(f"ha: service {name}: passive health check / core-fast {'missing' if hc else 'unexpected'}")
        if name == "core-keycloak-8080" and [x["url"] for x in lb["servers"]] != [f"http://keycloak-{i}.keycloak-pods.{K.NS}.svc.cluster.local:8080" for i in range(kc)]:
            F.add(f"ha: core-keycloak-8080 servers {lb['servers']} (Keycloak's {kc} replicas by name)")
    if http.get("serversTransports", {}).get("core-fast", {}).get("forwardingTimeouts", {}).get("dialTimeout") != "3s":
        F.add("ha: serversTransport core-fast (dialTimeout 3s)")
    yp = yaml.safe_load(next(c for c in plain if c.get("kind") == "ConfigMap" and c["metadata"]["name"] == "traefik-dynamic")["data"]["kubernetes.yml"])["http"]
    if "core-retry" in yp["middlewares"] or "serversTransports" in yp or any("passiveHealthCheck" in s["loadBalancer"] for s in yp["services"].values()):
        F.add("retry / passive health checks without ha.enabled")
    want_rule = f"Host(`{K.domain()}`) && (" + " || ".join(f"Path(`{p}`)" for p in NODE_PATHS) + ")"
    for label, docs in (("ha: ", ha), ("", K.render({"nodeadm": vals["nodeadm"]}))):
        irs = [d for d in K.by_kind(docs, "IngressRoute") if d["metadata"]["name"] == "portcullis-node"]
        if len(irs) != 1:
            F.add(f"{label}router portcullis-node: {len(irs)} rendered")
            continue
        r = irs[0]["spec"]["routes"][0]
        if r["match"] != want_rule or [m["name"] for m in r.get("middlewares", [])] != ["rate-limit@file"] \
                or r["services"] != [{"name": "portcullis-node", "kind": "Service", "port": 8080}] \
                or irs[0]["spec"]["entryPoints"] != ["websecure", "vpnsecure"] or irs[0]["spec"]["tls"] != {"options": {"name": "authaware@file"}}:
            F.add(f"{label}router portcullis-node: {irs[0]['spec']} (want {want_rule}, rate-limit@file, portcullis-node:8080)")
        es = [s for s in K.by_kind(docs, "Service") if s["metadata"]["name"] == "portcullis-node"]
        if len(es) != 1 or es[0]["metadata"]["namespace"] != K.EDGE_NS or es[0]["spec"].get("externalName") != "nodeadm.portcullis-nodeadm.svc.cluster.local":
            F.add(f"{label}the edge Service portcullis-node must be ExternalName nodeadm.portcullis-nodeadm.svc.cluster.local")
    if [d for d in K.by_kind(plain, "IngressRoute") if d["metadata"]["name"] == "portcullis-node"]:
        F.add("router portcullis-node without nodeadm.enabled")


def site_problems(docs, ha=True):
    """Contract §20.11 on one render: in HA every pinned pod (K.SITE_PINNED)
    requires portcullis.io/site In [main] in each of its required terms, and
    no other pod carries any site term (frontdoor, nodeadm and the Traefik
    DaemonSet included); without HA no pod carries one."""
    out = []
    pods = K.placement_specs(docs)
    for n, sp in sorted(pods.items()):
        pinned = ha and n in K.SITE_PINNED
        if pinned and not K.site_pinned(sp):
            out.append(f"{n}: no required node affinity portcullis.io/site In [{K.PRIMARY_SITE}] (pinned to the primary site)")
        if pinned and len(K.site_exprs(sp)) != len(K.node_terms(sp)):
            out.append(f"{n}: site terms {K.site_exprs(sp)} beyond the one In [{K.PRIMARY_SITE}] per term")
        if not pinned and K.site_exprs(sp):
            out.append(f"{n}: a site term {K.site_exprs(sp)} ({'never pinned' if n in K.SITE_FREE else 'not in the pinned set'}{'' if ha else ', and none without HA'})")
    return out


def check_sites():
    """Task 20 (contract §20.11): "sites: every pinned component requires
    portcullis.io/site In [main]"; "sites: frontdoor, nodeadm, traefik carry
    no site term" (and they are rendered, so the check bites); none without
    HA; tests/k8s-ci-values-ha-sites.yaml (ha.primarySite main, as
    kube_render_values writes it) renders the same; any other primarySite is
    refused at render time; portcullis.sitePin merges a class term into the
    site term (never replacing it: the CNPG instances' main + NotIn small,
    Task 23) and renders only the class term without a pin."""
    ha_vals = yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-ha.yaml").read_text())
    sites_vals = yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-ha-sites.yaml").read_text())
    merged = dict(ha_vals, ha=dict(ha_vals["ha"], **sites_vals.get("ha", {})))
    if merged["ha"].get("primarySite") != K.PRIMARY_SITE:
        F.add(f"tests/k8s-ci-values-ha-sites.yaml: ha.primarySite {merged['ha'].get('primarySite')} (main, as kube_render_values writes it)")
    if K.values()["ha"].get("primarySite") != K.PRIMARY_SITE:
        F.add(f"values.yaml: ha.primarySite {K.values()['ha'].get('primarySite')} (main)")
    for label, vals, ha in (("sites", ha_vals, True), ("sites (ha-sites values)", merged, True),
                            ("sites (3 nodes, 3 gates)", {"ha": dict(ha_vals["ha"], nonSmallNodesAtPrimary=3, gateReplicas=3), "nodeadm": ha_vals["nodeadm"]}, True),
                            ("sites without HA", {"nodeadm": ha_vals["nodeadm"]}, False)):
        docs = K.render(vals) + K.render(dict(vals, oneshot="hub"), "templates/oneshot.yaml")
        for p in site_problems(docs, ha):
            F.add(f"{label}: {p}")
        names = set(K.placement_specs(docs))
        want = K.SITE_PINNED | (K.SITE_FREE if ha else {"traefik", "nodeadm"})  # frontdoor: HA only
        if not want <= names:
            F.add(f"{label}: not rendered {sorted(want - names)} (the site check would pass vacuously)")
    # The check bites (mutation tests): a pin removed, a site term on frontdoor.
    docs = K.render(ha_vals)
    bad = [json.loads(json.dumps(d)) for d in docs]
    kc = next(d for d in bad if d.get("kind") == "StatefulSet" and d["metadata"]["name"] == "keycloak")
    kc["spec"]["template"]["spec"].pop("affinity", None)
    fd = next(d for d in bad if d.get("kind") == "Deployment" and d["metadata"]["name"] == "frontdoor")
    fd["spec"]["template"]["spec"]["nodeSelector"] = {K.SITE_KEY: K.PRIMARY_SITE}
    pg = K.cnpg_cluster(bad)
    pg["spec"]["affinity"].pop("nodeAffinity", None)
    got = site_problems(bad)
    if not any(p.startswith("keycloak:") for p in got) or not any(p.startswith("frontdoor:") for p in got) \
            or not any(p.startswith("postgres:") for p in got):
        F.add(f"site_problems misses an unpinned keycloak, an unpinned CNPG Cluster or a pinned frontdoor (mutation test): {got}")
    # Any other primary site is refused at render time, with or without HA.
    for extra in ({"ha": dict(ha_vals["ha"], primarySite="edge")}, {"ha": {"primarySite": "edge"}}, {"ha": {"primarySite": ""}}):
        try:
            K.render(extra)
            F.add(f"the chart renders with ha.primarySite {extra['ha']['primarySite']!r} (only main in this version)")
        except subprocess.CalledProcessError as e:
            if "ha.primarySite" not in e.stderr:
                F.add(f"ha.primarySite {extra['ha']['primarySite']!r} refused without naming ha.primarySite: {e.stderr.strip()[-200:]}")
    # portcullis.sitePin merges a class term (Task 23's CNPG instances).
    for label, spec, ha, want in (
            ("pin + class", '"pin" true "nodeExpressions" (list (dict "key" "portcullis.io/class" "operator" "NotIn" "values" (list "small")))', True,
             [{"matchExpressions": [{"key": K.SITE_KEY, "operator": "In", "values": [K.PRIMARY_SITE]},
                                    {"key": "portcullis.io/class", "operator": "NotIn", "values": ["small"]}]}]),
            ("pin", '"pin" true', True, [{"matchExpressions": [{"key": K.SITE_KEY, "operator": "In", "values": [K.PRIMARY_SITE]}]}]),
            ("class only", '"nodeExpressions" (list (dict "key" "portcullis.io/class" "operator" "NotIn" "values" (list "small")))', True,
             [{"matchExpressions": [{"key": "portcullis.io/class", "operator": "NotIn", "values": ["small"]}]}]),
            ("pin without HA", '"pin" true', False, []),
            ("no pin", '', True, [])):
        got = K.render_helper(f'{{{{ include "portcullis.sitePin" (dict "root" . "s" (dict {spec})) }}}}', {"ha": {"enabled": ha}})
        terms = ((yaml.safe_load(got) or {}).get("nodeAffinity") or {}).get("requiredDuringSchedulingIgnoredDuringExecution", {}).get("nodeSelectorTerms", [])
        if terms != want:
            F.add(f"portcullis.sitePin {label}: {terms} (want {want})")


def pg_problems(docs, vals):
    """One render's Postgres (plan Task 23, D8; Amendment 2; preflight
    P36 / P40): no postgres Deployment / Service / PVC; the CNPG Cluster
    portcullis-pg in cnpg-system on images.postgres, with
    portcullis.pgInstances' instances (1, in HA min(3, non-small nodes at
    main)) and their synchronous setting (none / preferred / required),
    required hostname anti-affinity, in HA the class term NotIn [small]
    (never without HA); storage portcullis-core with the K3 owner
    annotations (26:26 0700), priority portcullis-core, no superuser; the
    roles keycloak / lldap from the CLI's Secrets, the databases keycloak
    (initdb) and lldap (Database); Keycloak's KC_DB_URL its rw Service;
    LLDAP's LLDAP_DATABASE_URL from the Secret portcullis-pg-lldap, its key
    file from secrets-lldap-key with the seed emptied, no PVC, its schema
    Job; in HA 2 LLDAP replicas."""
    out = []
    ha = bool((vals.get("ha") or {}).get("enabled"))
    nsp = int((vals.get("ha") or {}).get("nonSmallNodesAtPrimary") or 0)
    want_n = max(1, min(3, nsp)) if ha else 1
    for d in docs:
        if d.get("kind") in ("Deployment", "StatefulSet", "Service", "PersistentVolumeClaim") and d["metadata"]["name"] in ("postgres", "postgres-data", "lldap-data"):
            out.append(f"{d['kind']} {d['metadata']['name']}: Postgres is the CNPG Cluster (no compose-shaped postgres, no lldap-data)")
    c = K.cnpg_cluster(docs)
    if c is None:
        return out + ["no CNPG Cluster portcullis-pg"]
    s = c["spec"]
    if c["metadata"]["namespace"] != K.CNPG_NS:
        out.append(f"Cluster in {c['metadata']['namespace']} (want {K.CNPG_NS})")
    if s.get("imageName") != K.images_values()["images"]["postgres"]:
        out.append(f"Cluster imageName {s.get('imageName')} is not images.postgres")
    if s.get("instances") != want_n:
        out.append(f"Cluster instances {s.get('instances')} (want {want_n})")
    sync = (s.get("postgresql") or {}).get("synchronous")
    want_sync = None if want_n == 1 else {"method": "any", "number": 1, "dataDurability": "required" if want_n == 3 else "preferred"}
    if sync != want_sync:
        out.append(f"Cluster synchronous {sync} (want {want_sync})")
    a = s.get("affinity") or {}
    if (a.get("enablePodAntiAffinity"), a.get("topologyKey"), a.get("podAntiAffinityType")) != (True, "kubernetes.io/hostname", "required"):
        out.append(f"Cluster affinity {a}: required anti-affinity on kubernetes.io/hostname")
    cls = {"key": "portcullis.io/class", "operator": "NotIn", "values": ["small"]}
    terms = ((a.get("nodeAffinity") or {}).get("requiredDuringSchedulingIgnoredDuringExecution") or {}).get("nodeSelectorTerms") or []
    if ha != (bool(terms) and all(cls in t.get("matchExpressions", []) for t in terms)):
        out.append(f"Cluster class term NotIn [small]: {terms} ({'every term' if ha else 'none without HA'})")
    st = s.get("storage") or {}
    ann = (s.get("inheritedMetadata") or {}).get("annotations") or {}
    if st.get("storageClass") != "portcullis-core" or ann.get("portcullis.io/uid") != "26" or ann.get("portcullis.io/gid") != "26" or ann.get("portcullis.io/mode") != "0700":
        out.append(f"Cluster storage {st} / owner annotations {ann} (portcullis-core, 26:26 0700)")
    if s.get("priorityClassName") != "portcullis-core" or s.get("enableSuperuserAccess") is not False:
        out.append("Cluster: priorityClassName portcullis-core and enableSuperuserAccess false")
    roles = {r["name"]: r.get("passwordSecret", {}).get("name") for r in (s.get("managed") or {}).get("roles", [])}
    if roles != {"keycloak": "portcullis-pg-keycloak", "lldap": "portcullis-pg-lldap"}:
        out.append(f"Cluster managed roles {roles}")
    if (s.get("bootstrap") or {}).get("initdb", {}).get("database") != "keycloak":
        out.append("Cluster bootstrap initdb database keycloak")
    dbs = [(d["spec"].get("name"), d["spec"].get("owner"), d["spec"]["cluster"]["name"]) for d in K.by_kind(docs, "Database")]
    if dbs != [("lldap", "lldap", K.PG_CLUSTER)]:
        out.append(f"Databases {dbs} (want lldap owned by lldap)")
    wl = {d["metadata"]["name"]: d for d in docs if d.get("kind") in ("Deployment", "StatefulSet")}
    env = lambda n: {e["name"]: e for e in wl[n]["spec"]["template"]["spec"]["containers"][0].get("env", [])}
    if env("keycloak")["KC_DB_URL"].get("value") != f"jdbc:postgresql://{K.PG_CLUSTER}-rw.{K.CNPG_NS}.svc.cluster.local:5432/keycloak":
        out.append(f"keycloak KC_DB_URL {env('keycloak')['KC_DB_URL']}")
    le = env("lldap")
    if le.get("LLDAP_DATABASE_URL", {}).get("valueFrom") != {"secretKeyRef": {"name": "portcullis-pg-lldap", "key": "LLDAP_DATABASE_URL"}}:
        out.append(f"lldap LLDAP_DATABASE_URL {le.get('LLDAP_DATABASE_URL')} (from the Secret portcullis-pg-lldap)")
    if le.get("LLDAP_KEY_SEED", {}).get("value") != "" or le.get("LLDAP_KEY_FILE", {}).get("value") != "/run/lldap-key/server_key":
        out.append("lldap: LLDAP_KEY_FILE /run/lldap-key/server_key, LLDAP_KEY_SEED empty")
    lp = wl["lldap"]["spec"]["template"]["spec"]
    vols = {v["name"]: v for v in lp.get("volumes", [])}
    if any("persistentVolumeClaim" in v for v in vols.values()) or vols.get("key", {}).get("secret", {}).get("secretName") != "secrets-lldap-key":
        out.append(f"lldap volumes {sorted(vols)}: no PVC, the key from secrets-lldap-key")
    if [c["name"] for c in lp.get("initContainers", [])] != ["wait-schema"] or lp.get("enableServiceLinks") is not False:
        out.append("lldap: the init container wait-schema, enableServiceLinks false")
    if wl["lldap"]["spec"].get("replicas") != (2 if ha else 1):
        out.append(f"lldap replicas {wl['lldap']['spec'].get('replicas')} (want {2 if ha else 1})")
    jobs = [j for j in K.by_kind(docs, "Job") if j["metadata"]["name"].startswith("lldap-schema-")]
    if len(jobs) != 1 or [c["name"] for c in jobs[0]["spec"]["template"]["spec"].get("initContainers", [])] != ["wait-postgres", "create-schema"]:
        out.append("one Job lldap-schema-<hash> (wait-postgres, create-schema, record)")
    return out


def check_postgres():
    """Task 23: "postgres: CNPG cluster, LLDAP DATABASE_URL from Secret",
    without HA, on the CI HA values and with 3 non-small nodes; and the
    check bites (mutation tests)."""
    ha_vals = yaml.safe_load((K.ROOT / "tests" / "k8s-ci-values-ha.yaml").read_text())
    for label, vals in (("postgres", {}), ("postgres (ha)", ha_vals),
                        ("postgres (ha, 3 nodes)", dict(ha_vals, ha=dict(ha_vals["ha"], nonSmallNodesAtPrimary=3))),
                        ("postgres (ha, 1 node)", dict(ha_vals, ha=dict(ha_vals["ha"], nonSmallNodesAtPrimary=1)))):
        for p in pg_problems(K.render(vals), vals):
            F.add(f"{label}: {p}")
    docs = K.render(ha_vals)
    for mutate in (lambda c: c["spec"].__setitem__("instances", 3), lambda c: c["spec"]["postgresql"]["synchronous"].__setitem__("dataDurability", "required"),
                   lambda c: c["spec"].__setitem__("enableSuperuserAccess", True), lambda c: c["spec"]["storage"].__setitem__("storageClass", "portcullis-core-replicated")):
        bad = [json.loads(json.dumps(d)) for d in docs]
        mutate(K.cnpg_cluster(bad))
        if not pg_problems(bad, ha_vals):
            F.add("pg_problems misses a mutated Cluster (mutation test)")


def main():
    comp = K.compose()
    docs = K.render()
    nb = count_binds(comp)
    if nb != 51:
        F.add(f"compose has {nb} project binds, the parity map expects 51 (update this check and docker-compose.podman-selinux.yml)")
    check_services(comp, docs)
    check_routers(comp)
    check_traefik(comp, docs)
    check_published()
    check_ha()
    check_sites()
    check_postgres()
    for kind, items in D.items():
        for e in items:
            if (kind, e.get("service"), str(e.get("item"))) not in USED:
                F.add(f"stale delta {kind} {e.get('service')} {e.get('item')}: it no longer applies")
            if not e.get("reason"):
                F.add(f"delta {kind} {e.get('service')} {e.get('item')} has no reason")
    return F.done()


if __name__ == "__main__":
    sys.exit(main())
