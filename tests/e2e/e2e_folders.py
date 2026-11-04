#!/usr/bin/env python3
"""End-to-end: shared folders and the doctor on a real stack (contract §14).

Runs in CI (job `e2e-folders` in .github/workflows/ci.yml) against the
whole core stack and the Hub (built from the same-named Hub branch), with
one template source holding the templates repo's jellyfin (same-named
templates branch: its folder blocks) and the CI fixture
tests/e2e/apps/folder-writer (alpine as 2001:2001, umask 022, option
`shared` with folder access write, runs_as 2001:2001; port WRITER_PORT
lan_only). The Hub reaches Docker only through core's unchanged
socket-proxy-hub; the folder fixer is the Hub's own image, started by the
Hub, on the runner's ext4 root with ACLs.

The workflow created /srv/e2e-media (sudo): 6 directories (the root and
d1..d5) 1000:1000 0750, 50 files (10 per subdirectory) 1000:1000 0640,
and installed `acl`. No browser: every step is the Hub's admin API (as
Traefik calls it) plus the host's view of the tree (sudo find / getfacl)
and docker.

Scenarios:
  tree       the tree is as the workflow made it (50 files, 6 dirs,
             1000:1000, 0640 / 0750, no ACL), before anything runs.
  enable     jellyfin and folder-writer enabled through the Hub; the
             writer can't write anywhere yet (no folder).
  check      POST /api/folders/check: exists · ext4 · ACLs and xattrs
             supported · 50 files (owners 1000:1000).
  create     folder media → gid 60000 (the first of the range).
  preview    jellyfin movies_path (read) + folder-writer shared (write):
             the lines name gid 60000, "Group 1000 keeps …" and the
             restarts of both instances; nothing changed on disk.
  apply      op ok (56 entries); on the host every entry has gid 60000,
             dirs setgid, default ACL group::rwx mask::rwx (no entry for
             group 1000 there, contract §14.2), access ACL group:1000:r-x
             on dirs and group:1000:r-- on files; the writer's new file is
             gid 60000 and group-writable (umask 022); inside jellyfin
             `id -G` has 60000, /data/movies lists the files and
             `touch /data/movies/x` fails read-only.
  drift      a disk check finds no folder_owner; after `sudo chgrp 1000`
             of one file (the writer's, so every use can still reach it)
             a disk check gives a folder_owner Warning (undo offered).
  undo       undo preview (56 entries back, 0 changed since) → apply:
             the 56 original entries are 1000:1000 with their old modes
             and `getfacl --skip-base` prints nothing for them; the
             writer's files (not in the snapshot) are left alone.
  exposure   the writer's lan_only port on 0.0.0.0 → lan_only_exposed
             Warning; rebind_port 127.0.0.1 → op ok, `docker port` shows
             127.0.0.1 only, the finding is gone.
  proxy      socket-proxy-hub is main's, unchanged (same compose
             service), the Hub has no socket mount and talks to it.

Environment: HUB_IP, E2E_HUB_SECRET (the proxy secret; never printed, never
on argv), E2E_MEDIA (/srv/e2e-media), E2E_ARTIFACTS.
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
from datetime import datetime

HUB_API = f"http://{os.environ['HUB_IP']}:8888"
SECRET = os.environ["E2E_HUB_SECRET"]
MEDIA = os.environ.get("E2E_MEDIA", "/srv/e2e-media")
ART = os.environ.get("E2E_ARTIFACTS", "e2e-artifacts")
FOLDER = "media"
GID = 60000
WRITER = "folder-writer"
JELLYFIN = "jellyfin"
USES = [{"instance": JELLYFIN, "key": "movies_path"}, {"instance": WRITER, "key": "shared"}]
N_FILES, N_DIRS = 50, 6
OP_S = 900  # an apply / undo with two restarts (Jellyfin's start included)

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
    """Fail closed: a scenario that builds on an earlier one fails when that
    one did, never passes on missing state."""
    missing = [k for k in keys if k not in state]
    assert not missing, f"needs {', '.join(missing)} (an earlier scenario failed)"


def until(what: str, fn, seconds: float, every: float = 3):
    deadline, last = time.time() + seconds, None
    while True:
        try:
            got = fn()
            if got:
                return got
            last = got
        except Exception as e:  # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
        if time.time() > deadline:
            raise AssertionError(f"{what}: not within {seconds:.0f} s (last: {str(last)[:600]})")
        time.sleep(every)


def save(name: str, data) -> None:
    os.makedirs(ART, exist_ok=True)
    with open(os.path.join(ART, name), "w") as f:
        f.write(data if isinstance(data, str) else json.dumps(data, indent=2))


# ── the Hub's admin API (as Traefik calls it: proxy secret + identity) ──

def hub(method: str, path: str, body=None, timeout: float = 300) -> tuple[int, dict | list | str]:
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


def hub_ok(method: str, path: str, body=None, want: int = 200, timeout: float = 300):
    code, out = hub(method, path, body, timeout)
    assert code == want, f"{method} {path}: HTTP {code} (want {want}): {str(out)[:800]}"
    return out


def run_op(method: str, path: str, body) -> dict:
    """A 202 operation, polled at its `poll` until its record (same op_id)
    is no longer running; the record must be ok."""
    acc = hub_ok(method, path, body, want=202)
    op_id, poll = acc.get("op_id"), acc.get("poll")
    assert op_id and poll, f"202 without op_id / poll: {acc}"
    rec = until(f"{acc.get('op')} {op_id} finished",
                lambda: (r := hub("GET", poll)[1]) and isinstance(r, dict) and r.get("op_id") == op_id
                and not r.get("running") and r, OP_S, every=2)
    save(f"op-{acc.get('op')}-{op_id}.json", rec)
    assert rec.get("ok") is True, f"{acc.get('op')}: {json.dumps(rec)[:1500]}"
    return rec


def doctor() -> dict:
    rep = hub_ok("GET", "/api/doctor")
    assert isinstance(rep.get("findings"), list), f"doctor report: {str(rep)[:400]}"
    return rep


def disk_check() -> dict:
    """POST /api/doctor/scan (202) → the _doctor record ok → the report,
    whose scans must list the folder with a time after the request."""
    t0 = time.time()
    run_op("POST", "/api/doctor/scan", {})
    rep = doctor()
    scans = [s for s in rep.get("scans") or [] if s.get("target") == MEDIA]
    assert scans, f"no disk scan of {MEDIA} in the report: {rep.get('scans')}"
    at = scans[0]["at"]
    got = datetime.fromisoformat(at.replace("Z", "+00:00")).timestamp()
    assert got >= t0 - 5, f"the scan of {MEDIA} is from {at}, before the request"
    assert scans[0].get("entries", 0) >= N_FILES + N_DIRS and not scans[0].get("partial"), scans[0]
    return rep


def findings(rep: dict, kind: str, *, instance: str | None = None, folder: str | None = None) -> list[dict]:
    return [f for f in rep["findings"] if f.get("kind") == kind
            and (instance is None or instance in (f.get("instances") or []))
            and (folder is None or folder in (f.get("folders") or []))]


# ── the host and docker ──

def sh(*argv: str, sudo: bool = False, check_rc: bool = True, timeout: float = 120) -> str:
    p = subprocess.run((["sudo", "-n"] if sudo else []) + list(argv), capture_output=True, text=True, timeout=timeout)
    if check_rc and p.returncode != 0:
        raise AssertionError(f"{' '.join(argv[:3])}…: rc {p.returncode}: {p.stderr.strip()[:400]}")
    return p.stdout


def docker(*args: str, check_rc: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=120)
    if check_rc and p.returncode != 0:
        raise AssertionError(f"docker {' '.join(args[:3])}…: rc {p.returncode}: {p.stderr.strip()[:400]}")
    return p


def container(project: str, service: str) -> str:
    ids = docker("ps", "-q", "--filter", f"label=com.docker.compose.project=portcullis-{project}",
                 "--filter", f"label=com.docker.compose.service={service}").stdout.split()
    assert len(ids) == 1, f"{project}/{service}: running containers {ids}"
    return ids[0]


def tree() -> dict[str, dict]:
    """Every entry under MEDIA (the root is "."): uid, gid, mode (octal,
    with setgid), type (d / f)."""
    out = sh("find", MEDIA, "-printf", r"%P\t%U\t%G\t%m\t%y\n", sudo=True)
    entries = {}
    for line in out.splitlines():
        p, u, g, m, y = line.split("\t")
        entries[p or "."] = {"uid": int(u), "gid": int(g), "mode": int(m, 8), "type": y}
    return entries


def original(entries: dict) -> dict:
    """The 56 entries the workflow made (the writer's new-*.txt excluded)."""
    return {p: e for p, e in entries.items() if not os.path.basename(p).startswith("new-")}


def getfacl(rel: str, *flags: str) -> list[str]:
    path = MEDIA if rel == "." else os.path.join(MEDIA, rel)
    out = sh("getfacl", "--omit-header", "--absolute-names", *flags, path, sudo=True)
    return [line.split("#")[0].strip() for line in out.splitlines() if line.strip()]


def writer_files() -> dict:
    return {p: e for p, e in tree().items() if os.path.basename(p).startswith("new-") and e["type"] == "f"}


def main() -> int:
    # ── tree: as the workflow made it ──
    def tree_before():
        t = tree()
        files = [p for p, e in t.items() if e["type"] == "f"]
        dirs = [p for p, e in t.items() if e["type"] == "d"]
        assert (len(files), len(dirs)) == (N_FILES, N_DIRS), f"{len(files)} files, {len(dirs)} dirs: {sorted(t)}"
        bad = {p: e for p, e in t.items() if (e["uid"], e["gid"]) != (1000, 1000)
               or e["mode"] != (0o750 if e["type"] == "d" else 0o640)}
        assert not bad, f"not 1000:1000 0640/0750: {bad}"
        acl = sh("getfacl", "-R", "--skip-base", "--absolute-names", MEDIA, sudo=True).strip()
        assert acl == "", f"ACLs before anything ran: {acl[:400]}"
        state["before"] = t
    check(f"tree: {MEDIA} has {N_FILES} files 1000:1000 0640 and {N_DIRS} dirs 0750, no ACL", tree_before)

    # ── enable both apps ──
    def enable():
        for inst in (JELLYFIN, WRITER):
            t0 = time.time()
            out = hub_ok("POST", "/api/templates/enable", {"id": inst}, timeout=1500)
            print(f"    enabled {inst} in {time.time() - t0:.0f} s: {json.dumps(out.get('warnings'))[:300]}", flush=True)
        container(JELLYFIN, "jellyfin")
        w = container(WRITER, "app")
        until("the writer's start line", lambda: "can't write" in docker("logs", w).stdout + docker("logs", w).stderr, 60)
        assert not writer_files(), f"the writer wrote before any assignment: {writer_files()}"
        state["enabled"] = True
    check("enable: jellyfin and folder-writer enabled through the Hub; the writer can't write yet", enable)

    # ── check path ──
    def check_path():
        pc = hub_ok("POST", "/api/folders/check", {"path": MEDIA, "create": False})
        save("check-path.json", pc)
        want = f"exists · ext4 · ACLs and xattrs supported · {N_FILES} files"
        assert str(pc.get("summary", "")).startswith(want), f"summary {pc.get('summary')!r}, want {want!r}…"
        assert (pc.get("exists"), pc.get("created"), pc.get("fs_type"), pc.get("acl"), pc.get("xattr")) == \
            (True, False, "ext4", True, True), pc
        assert (pc.get("files"), pc.get("dirs"), pc.get("partial")) == (N_FILES, N_DIRS, False), pc
        assert not pc.get("problems"), pc
        print(f"    {pc['summary']}", flush=True)
    check(f"check: POST /api/folders/check → exists · ext4 · ACLs and xattrs supported · {N_FILES} files", check_path)

    # ── create the folder ──
    def create():
        out = hub_ok("POST", "/api/folders", {"id": FOLDER, "name": "Media", "path": MEDIA,
                                              "description": "e2e-folders", "create": False}, want=201)
        f = out["folder"]
        assert (f.get("id"), f.get("gid"), f.get("adopted"), f.get("path")) == (FOLDER, GID, False, MEDIA), f
        listed = hub_ok("GET", "/api/folders")["folders"]
        assert [x["id"] for x in listed] == [FOLDER] and listed[0]["gid"] == GID, listed
        state["folder"] = f
    check(f"create: folder {FOLDER} → gid {GID}", create)

    # ── assignment preview ──
    def preview():
        needs("enabled", "folder")
        pl = hub_ok("POST", f"/api/folders/{FOLDER}/assign/preview", {"uses": USES})
        save("assign-preview.json", pl)
        lines = pl.get("lines") or []
        text = "\n".join(lines)
        print("    " + "\n    ".join(lines), flush=True)
        assert pl.get("gid") == GID, pl.get("gid")
        assert f"gid {GID} is allocated for this folder (shown as *Media*)." in lines, text
        assert f"Group 1000 keeps the access it has now through an ACL on {N_FILES + N_DIRS} entries." in lines, text
        assert f"{N_FILES} files and {N_DIRS} folders change group 1000 → {GID}." in lines, text
        assert sorted(pl.get("restarts") or []) == [WRITER, JELLYFIN], pl.get("restarts")
        assert any("stopped for" in ln and "Jellyfin" in ln and "Folder Writer" in ln and ln.endswith("then started.")
                   for ln in lines), text
        uses = {(u["instance"], u["key"]): u for u in pl.get("uses") or []}
        assert uses.keys() == {(JELLYFIN, "movies_path"), (WRITER, "shared")}, uses.keys()
        assert (uses[(JELLYFIN, "movies_path")]["access"], uses[(JELLYFIN, "movies_path")]["read_only"]) == ("read", True), uses
        assert (uses[(WRITER, "shared")]["access"], uses[(WRITER, "shared")]["read_only"]) == ("write", False), uses
        assert all(u["change"] == "add" for u in uses.values()), uses
        d = pl.get("disk") or {}
        assert d.get("files") == "rw" and d.get("entries") == N_FILES + N_DIRS and not d.get("partial"), d
        assert pl.get("plan_hash"), pl
        assert tree() == state["before"], "the preview changed the tree"
        state["plan"] = pl
    check(f"preview: jellyfin movies_path (read) + folder-writer shared (write): gid {GID}, "
          "group 1000 keeps its access, both restart; nothing changes", preview)

    # ── apply and verify on the host ──
    def apply():
        needs("plan")
        rec = run_op("POST", f"/api/folders/{FOLDER}/assign/apply",
                     {"plan_hash": state["plan"]["plan_hash"], "uses": USES})
        res = rec.get("result") or {}
        assert res.get("entries") == str(N_FILES + N_DIRS) and res.get("snapshot"), rec
        assert (res.get("add"), res.get("remove")) == ("2", "0"), rec
        state["applied"] = rec
    check("apply: the assignment's op is ok (56 entries, a snapshot)", apply)

    def verify_host():
        needs("applied")
        t = tree()
        save("tree-after-apply.json", t)
        orig = original(t)
        assert orig.keys() == state["before"].keys(), f"entries: {sorted(orig)}"
        not_gid = {p: e for p, e in t.items() if e["gid"] != GID}
        assert not not_gid, f"entries not gid {GID}: {not_gid}"
        for p, e in orig.items():
            assert e["uid"] == 1000, f"{p}: owner changed: {e}"
            if e["type"] == "d":
                assert e["mode"] == 0o2770, f"{p}: dir mode {e['mode']:o} (want 2770: g+rwx, setgid)"
            else:
                assert e["mode"] == 0o660, f"{p}: file mode {e['mode']:o} (want 660: g+rw, a use writes)"
        for p, e in orig.items():
            acl = getfacl(p)
            acc = [x for x in acl if not x.startswith("default:")]
            dflt = [x for x in acl if x.startswith("default:")]
            if e["type"] == "d":
                for want in ("group::rwx", "group:1000:r-x", "mask::rwx"):
                    assert want in acc, f"{p}: access ACL {acc} lacks {want}"
                for want in ("default:group::rwx", "default:mask::rwx", "default:other::---"):
                    assert want in dflt, f"{p}: default ACL {dflt} lacks {want}"
                assert not any(x.startswith("default:group:1000") for x in dflt), f"{p}: default ACL {dflt}"
            else:
                assert not dflt, f"{p}: a file with a default ACL {dflt}"
                for want in ("group::rw-", "group:1000:r--", "mask::rw-"):
                    assert want in acc, f"{p}: access ACL {acc} lacks {want}"
        print(f"    {len(orig)} entries: gid {GID}, dirs 2770 + default ACL, group 1000 kept by named entries", flush=True)
    check(f"apply: on the host every entry is gid {GID}, dirs setgid with default group::rwx mask::rwx, "
          "group 1000 keeps r-x (dirs) / r-- (files) through named entries", verify_host)

    def verify_writer():
        needs("applied")
        nf = until("the writer's new file", writer_files, 120)
        p, e = sorted(nf.items())[0]
        assert (e["uid"], e["gid"]) == (2001, GID), f"{p}: {e}"
        assert e["mode"] & 0o020, f"{p}: mode {e['mode']:o} not group-writable (umask 022)"
        acc = getfacl(p)
        assert "mask::rw-" in acc or "group::rw-" in acc, f"{p}: {acc}"
        state["writer_file"] = p
        print(f"    {p}: {e['uid']}:{e['gid']} {e['mode']:o}", flush=True)
    check(f"apply: the writer's new file (umask 022) is gid {GID} and group-writable", verify_writer)

    def verify_jellyfin():
        needs("applied")
        cid = container(JELLYFIN, "jellyfin")
        groups = docker("exec", cid, "id", "-G").stdout.split()
        assert str(GID) in groups, f"jellyfin id -G: {groups}"
        listed = docker("exec", cid, "ls", "/data/movies").stdout.split()
        assert {"d1", "d2", "d3", "d4", "d5"} <= set(listed), f"jellyfin /data/movies: {listed}"
        t = docker("exec", cid, "touch", "/data/movies/x", check_rc=False)
        assert t.returncode != 0 and "Read-only file system" in t.stderr, f"touch: rc {t.returncode}: {t.stderr}"
        assert "x" not in tree(), "jellyfin created /data/movies/x"
    check(f"apply: inside jellyfin id -G has {GID}, /data/movies lists the folder, touch /data/movies/x fails read-only",
          verify_jellyfin)

    # ── doctor: drift ──
    def no_drift():
        needs("applied", "writer_file")
        rep = disk_check()
        save("doctor-after-apply.json", rep)
        fo = findings(rep, "folder_owner", folder=FOLDER)
        assert not fo, f"folder_owner right after the apply: {fo}"
        state["clean_scan"] = True
    check("drift: a disk check right after the apply finds no folder_owner", no_drift)

    def drift():
        needs("clean_scan")
        sh("chgrp", "1000", os.path.join(MEDIA, state["writer_file"]), sudo=True)
        rep = disk_check()
        save("doctor-drift.json", rep)
        fo = findings(rep, "folder_owner", folder=FOLDER)
        assert len(fo) == 1, f"folder_owner findings: {fo}"
        f = fo[0]
        assert f["severity"] == "warning", f
        assert f.get("fix_kind") == "reapply_folder" and "undo_folder" in (f.get("more_fix_kinds") or []), f
        assert "1 entries with another group" in f.get("why", ""), f
        print(f"    {f['title']} {f['why']}", flush=True)
    check("drift: after sudo chgrp 1000 of one file a disk check gives a folder_owner Warning (reapply, undo offered)",
          drift)

    # ── undo ──
    def undo():
        needs("applied")
        pl = hub_ok("POST", f"/api/folders/{FOLDER}/undo/preview", {})
        save("undo-preview.json", pl)
        lines = pl.get("lines") or []
        print("    " + "\n    ".join(lines), flush=True)
        want = f"{N_FILES + N_DIRS} entries go back to the owner, group, mode and ACLs they had before the fix; " \
               "0 changed since the fix and are left alone."
        assert want in lines, "\n".join(lines)
        assert sorted(pl.get("restarts") or []) == [WRITER, JELLYFIN], pl.get("restarts")
        writer_before = writer_files()
        rec = run_op("POST", f"/api/folders/{FOLDER}/undo/apply", {"plan_hash": pl["plan_hash"]})
        res = rec.get("result") or {}
        assert res.get("entries") == str(N_FILES + N_DIRS) and res.get("changed_since") == "0", rec
        t = tree()
        save("tree-after-undo.json", t)
        orig = original(t)
        assert orig == state["before"], \
            f"not back: {[(p, e, state['before'].get(p)) for p, e in orig.items() if e != state['before'].get(p)][:5]}"
        acl = [ln for p in sorted(orig) for ln in getfacl(p, "--skip-base")]
        assert acl == [], f"ACL entries left on the original entries: {acl[:10]}"
        for p, e in writer_before.items():
            assert t.get(p) == e, f"the undo touched the writer's {p}: {e} → {t.get(p)}"
        assert hub_ok("GET", "/api/folders")["folders"][0].get("last_apply") is None, "last_apply kept after an undo"
        state["undone"] = True
    check(f"undo: preview ({N_FILES + N_DIRS} back, 0 changed since) → apply: the original entries are 1000:1000 "
          "0640/0750 again, getfacl --skip-base prints nothing; the writer's files are left alone", undo)

    # ── exposure: lan_only port ──
    def exposure():
        needs("enabled")
        cid = container(WRITER, "app")
        before = docker("port", cid, "8080/tcp").stdout.split()
        assert any(b.startswith("0.0.0.0:") for b in before), f"docker port before: {before}"
        rep = doctor()
        fs = findings(rep, "lan_only_exposed", instance=WRITER)
        assert len(fs) == 1, f"lan_only_exposed: {fs}"
        f = fs[0]
        assert f["severity"] == "warning" and f.get("fix_kind") == "rebind_port", f
        plan = hub_ok("POST", f"/api/doctor/findings/{f['fp']}/preview", {"params": {"address": "127.0.0.1"}})
        save("rebind-preview.json", plan)
        assert any("WRITER_PORT bind 0.0.0.0 → 127.0.0.1" in ln for ln in plan.get("lines") or []), plan
        rec = run_op("POST", f"/api/doctor/findings/{f['fp']}/apply",
                     {"plan_hash": plan["plan_hash"], "params": {"address": "127.0.0.1"}})
        assert rec.get("op") == "rebind", rec
        cid = container(WRITER, "app")
        after = docker("port", cid, "8080/tcp").stdout.split()
        assert after and all(a.startswith("127.0.0.1:") for a in after), f"docker port after: {after}"
        left = findings(doctor(), "lan_only_exposed", instance=WRITER)
        assert not left, f"lan_only_exposed after the rebind: {left}"
        print(f"    docker port: {before} → {after}", flush=True)
    check("exposure: the lan_only port on 0.0.0.0 is a Warning; rebind_port 127.0.0.1 publishes on 127.0.0.1 only "
          "and the finding is gone", exposure)

    # ── the socket proxy: main's, unchanged ──
    def proxy():
        def svc(*files: str) -> dict:
            argv = ["compose"] + [x for f in files for x in ("-f", f)] + ["--project-directory", ".", "config", "--format", "json"]
            return json.loads(docker(*argv).stdout)["services"]["socket-proxy-hub"]
        main_svc = svc("/tmp/main-docker-compose.yml")
        here = svc("docker-compose.yml", "docker-compose.ci.yml")
        assert here == main_svc, f"socket-proxy-hub differs from main's:\n{json.dumps(here)}\n{json.dumps(main_svc)}"
        hub_c = docker("compose", "ps", "-q", "hub").stdout.strip()
        info = json.loads(docker("inspect", hub_c).stdout)[0]
        env = dict(x.split("=", 1) for x in info["Config"]["Env"])
        assert env.get("DOCKER_HOST") == "tcp://socket-proxy-hub:2375", env.get("DOCKER_HOST")
        socks = [m for m in info["Mounts"] if "docker.sock" in (m.get("Source") or "")]
        assert not socks, f"the Hub mounts the socket: {socks}"
        assert not docker("ps", "-aq", "--filter", "label=io.portcullis.hub.helper").stdout.strip(), "fixers left behind"
    check("proxy: socket-proxy-hub is main's unchanged service (no new flag); the Hub reaches Docker only through it, "
          "no fixer left behind", proxy)

    return report()


def report() -> int:
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    for name, _, err in failed:
        print(f"  FAIL {name}: {err}")
    return 1 if failed or not results else 0


if __name__ == "__main__":
    sys.exit(main())
