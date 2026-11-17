#!/usr/bin/env python3
"""Run one ci.yml job's steps the way GitHub Actions does (inside the job
container of run-job.sh, as user `runner`).

    steps.py --workflow .github/workflows/ci.yml --job e2e-mail [--input k=v]…

What it does like Actions: the workflow, job and step `env` (expressions
evaluated), `if:` (default success(); always() / failure() / cancelled()),
`run:` with Actions' shells (`bash -e {0}` by default, `bash --noprofile
--norc -eo pipefail {0}` for `shell: bash`), `working-directory`,
`timeout-minutes` (step and job; a job timeout cancels and still runs the
always() steps), `continue-on-error`, GITHUB_ENV / GITHUB_OUTPUT /
GITHUB_PATH / GITHUB_STEP_SUMMARY files, step outputs and outcomes, local
composite actions (./.github/actions/*) with their inputs. The event is a
workflow_dispatch on the checked-out branch (so nothing saves caches).

`uses:` steps that need GitHub's services are emulated locally:
  actions/checkout          the workspace is already checked out; another
                            repository / path is cloned from GitHub
  actions/setup-go          Go from go.dev (sha256 from go.dev's list) into
                            /opt/hostedtoolcache/go/<v>/x64, on PATH
  actions/cache[/restore|/save]   no-op (cache miss); pip, Playwright and Go
                            caches live on the container's cache volumes
  actions/upload-artifact   copied to $PCCI_ARTIFACTS/<name>/ (the host's
                            run directory)
  docker/setup-buildx-action, docker/setup-qemu-action   no-op (the default
                            builder; binfmt is a host-kernel setting)
  docker/build-push-action  `docker buildx build --load` (no gha cache, never
                            a push)
Anything else fails the step, named.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import yaml

# ── expressions ──────────────────────────────────────────────────────────────

_TOK = re.compile(r"""\s*(?:
    (?P<num>-?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][-+]?\d+)?))|
    (?P<str>'(?:[^']|'')*')|
    (?P<op>==|!=|<=|>=|&&|\|\||[!<>()\[\],.*])|
    (?P<id>[A-Za-z_][A-Za-z0-9_-]*)
)""", re.X)


class ExprError(Exception):
    pass


def _tokens(s: str) -> list[tuple[str, str]]:
    out, i = [], 0
    while i < len(s):
        if s[i:].strip() == "":
            break
        m = _TOK.match(s, i)
        if not m or m.end() == i:
            raise ExprError(f"cannot parse {s!r} at {s[i:]!r}")
        kind = m.lastgroup
        out.append((kind, m.group(kind)))
        i = m.end()
    return out


def _num(v):
    if v is None:
        return 0
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        t = v.strip()
        if t == "":
            return 0
        try:
            return int(t, 0) if re.fullmatch(r"-?(0x[0-9a-fA-F]+|\d+)", t) else float(t)
        except ValueError:
            return math.nan
    return math.nan


def truthy(v) -> bool:
    if v is None or v is False:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return not (v == 0 or (isinstance(v, float) and math.isnan(v)))
    if isinstance(v, str):
        return v != ""
    return True


def _eq(a, b) -> bool:
    if type(a) is type(b) or (isinstance(a, (int, float)) and isinstance(b, (int, float))
                              and not isinstance(a, bool) and not isinstance(b, bool)):
        if isinstance(a, str):
            return a.lower() == b.lower()
        return a == b
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return a is b
    return _num(a) == _num(b)


def tostr(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, (dict, list)):
        return json.dumps(v, indent=2)
    return str(v)


class Evaluator:
    def __init__(self, ctx: dict, funcs: dict):
        self.ctx, self.funcs = ctx, funcs

    def eval(self, src: str):
        self.t, self.i = _tokens(src), 0
        v = self._or()
        if self.i != len(self.t):
            raise ExprError(f"unexpected {self.t[self.i][1]!r} in {src!r}")
        return v

    def _peek(self, *vals):
        return self.i < len(self.t) and self.t[self.i][1] in vals and self.t[self.i][0] == "op"

    def _take(self, val):
        if not self._peek(val):
            raise ExprError(f"expected {val!r}")
        self.i += 1

    def _or(self):
        v = self._and()
        while self._peek("||"):
            self.i += 1
            r = self._and()
            v = v if truthy(v) else r
        return v

    def _and(self):
        v = self._cmp()
        while self._peek("&&"):
            self.i += 1
            r = self._cmp()
            v = r if truthy(v) else v
        return v

    def _cmp(self):
        v = self._unary()
        while self._peek("==", "!=", "<", ">", "<=", ">="):
            op = self.t[self.i][1]
            self.i += 1
            r = self._unary()
            if op == "==":
                v = _eq(v, r)
            elif op == "!=":
                v = not _eq(v, r)
            else:
                a, b = (v.lower(), r.lower()) if isinstance(v, str) and isinstance(r, str) else (_num(v), _num(r))
                v = {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[op]
        return v

    def _unary(self):
        if self._peek("!"):
            self.i += 1
            return not truthy(self._unary())
        return self._postfix(self._primary())

    def _postfix(self, v):
        while True:
            if self._peek("."):
                self.i += 1
                kind, name = self.t[self.i]
                self.i += 1
                if name == "*":
                    v = list(v.values()) if isinstance(v, dict) else v
                    continue
                v = _get(v, name)
            elif self._peek("["):
                self.i += 1
                k = self._or()
                self._take("]")
                if isinstance(v, list):
                    n = _num(k)
                    v = v[int(n)] if isinstance(n, (int, float)) and not math.isnan(n) and 0 <= int(n) < len(v) else None
                else:
                    v = _get(v, tostr(k))
            else:
                return v

    def _primary(self):
        if self.i >= len(self.t):
            raise ExprError("unexpected end of expression")
        kind, val = self.t[self.i]
        self.i += 1
        if kind == "num":
            return int(val, 0) if re.fullmatch(r"-?(0x[0-9a-fA-F]+|\d+)", val) else float(val)
        if kind == "str":
            return val[1:-1].replace("''", "'")
        if kind == "op" and val == "(":
            v = self._or()
            self._take(")")
            return v
        if kind == "id":
            low = val.lower()
            if low in ("true", "false"):
                return low == "true"
            if low == "null":
                return None
            if self._peek("("):
                self.i += 1
                args = []
                if not self._peek(")"):
                    args.append(self._or())
                    while self._peek(","):
                        self.i += 1
                        args.append(self._or())
                self._take(")")
                fn = self.funcs.get(low)
                if not fn:
                    raise ExprError(f"unknown function {val}()")
                return fn(*args)
            return _get(self.ctx, val)
        raise ExprError(f"unexpected {val!r}")


def _get(obj, name):
    if isinstance(obj, dict):
        if name in obj:
            return obj[name]
        low = name.lower()
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() == low:
                return v
    return None


def _format(fmt, *args):
    def rep(m):
        if m.group(0) == "{{":
            return "{"
        if m.group(0) == "}}":
            return "}"
        return tostr(args[int(m.group(1))])
    return re.sub(r"\{\{|\}\}|\{(\d+)\}", rep, tostr(fmt))


def _contains(hay, needle):
    if isinstance(hay, list):
        return any(_eq(x, needle) for x in hay)
    return tostr(needle).lower() in tostr(hay).lower()


# ── the job ──────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    print(msg, flush=True)


class Cancelled(Exception):
    pass


class Job:
    def __init__(self, a):
        self.a = a
        self.ws = Path(os.getcwd())
        wf = yaml.safe_load(Path(a.workflow).read_text())
        self.wf = wf
        if a.job not in wf["jobs"]:
            sys.exit(f"no job {a.job!r} in {a.workflow} (jobs: {' '.join(wf['jobs'])})")
        self.job = wf["jobs"][a.job]
        self.temp = Path(os.environ.get("RUNNER_TEMP") or tempfile.mkdtemp(prefix="runner-temp-"))
        self.temp.mkdir(parents=True, exist_ok=True)
        self.artifacts = Path(os.environ.get("PCCI_ARTIFACTS", self.temp / "artifacts"))
        self.inputs = dict(kv.split("=", 1) for kv in a.input)
        ref_name = a.ref_name
        self.github = {
            "event_name": "workflow_dispatch", "ref": f"refs/heads/{ref_name}", "ref_name": ref_name,
            "ref_type": "branch", "head_ref": "", "base_ref": "", "sha": a.sha, "repository": a.repository,
            "repository_owner": a.repository.split("/")[0], "workflow": wf.get("name", ""), "job": a.job,
            "run_id": str(int(time.time())), "run_number": "1", "run_attempt": "1", "actor": "local",
            "triggering_actor": "local", "server_url": "https://github.com", "api_url": "https://api.github.com",
            "workspace": str(self.ws), "event": {"inputs": self.inputs}, "token": "", "action": "",
        }
        self.runner = {"os": "Linux", "arch": "X64", "name": "pcci-local", "temp": str(self.temp),
                       "tool_cache": os.environ.get("RUNNER_TOOL_CACHE", "/opt/hostedtoolcache"),
                       "environment": "self-hosted", "debug": ""}
        self.env: dict[str, str] = {}
        self.paths: list[str] = []
        self.failed = False
        self.cancelled = False
        # PCCI_TIMEOUT_FACTOR (run-job.sh --timeout-factor): every job / step
        # timeout-minutes times this (a shared host is slower than a fresh
        # GitHub runner; ci.yml's limits are sized for GitHub).
        self.factor = float(os.environ.get("PCCI_TIMEOUT_FACTOR") or 1)
        self.deadline = time.time() + float(self.job.get("timeout-minutes", 360)) * 60 * self.factor
        self.summary = self.temp / "_step_summary.md"
        self.summary.touch()
        self.results: list[tuple[str, str, float]] = []

    # contexts / expressions
    def ctx(self, steps: dict, inputs: dict | None = None) -> dict:
        return {"github": self.github, "env": dict(self.env), "inputs": self.inputs if inputs is None else inputs,
                "runner": self.runner, "steps": steps, "job": {"status": self.status()}, "secrets": {},
                "vars": {}, "matrix": {}, "strategy": {}, "needs": {}}

    def status(self) -> str:
        return "cancelled" if self.cancelled else "failure" if self.failed else "success"

    def funcs(self) -> dict:
        return {
            "success": lambda: not self.failed and not self.cancelled,
            "failure": lambda: self.failed,
            "always": lambda: True,
            "cancelled": lambda: self.cancelled,
            "contains": _contains,
            "startswith": lambda a, b: tostr(a).lower().startswith(tostr(b).lower()),
            "endswith": lambda a, b: tostr(a).lower().endswith(tostr(b).lower()),
            "format": _format,
            "join": lambda a, sep=",": tostr(sep).join(tostr(x) for x in a) if isinstance(a, list) else tostr(a),
            "tojson": lambda v: json.dumps(v, indent=2),
            "fromjson": lambda s: json.loads(tostr(s)),
            "hashfiles": self._hashfiles,
        }

    def _hashfiles(self, *patterns):
        files = set()
        for p in patterns:
            for m in glob.glob(str(self.ws / tostr(p)), recursive=True):
                if os.path.isfile(m):
                    files.add(m)
        if not files:
            return ""
        h = hashlib.sha256()
        for f in sorted(files):
            h.update(hashlib.sha256(Path(f).read_bytes()).digest())
        return h.hexdigest()

    def ev(self, expr: str, steps: dict, inputs=None):
        return Evaluator(self.ctx(steps, inputs), self.funcs()).eval(expr)

    def sub(self, value, steps: dict, inputs=None):
        """${{ }} substitution in a string (other types unchanged)."""
        if not isinstance(value, str):
            return value
        if re.fullmatch(r"\s*\$\{\{(.*?)\}\}\s*", value, re.S) and value.count("${{") == 1:
            return self.ev(re.fullmatch(r"\s*\$\{\{(.*?)\}\}\s*", value, re.S).group(1), steps, inputs)
        return re.sub(r"\$\{\{(.*?)\}\}", lambda m: tostr(self.ev(m.group(1), steps, inputs)), value, flags=re.S)

    def cond(self, raw, steps: dict, inputs=None) -> bool:
        if raw is None or raw == "":
            return not self.failed and not self.cancelled
        if isinstance(raw, bool):
            return raw and not self.failed and not self.cancelled
        expr = str(raw).strip()
        m = re.fullmatch(r"\$\{\{(.*)\}\}", expr, re.S)
        if m:
            expr = m.group(1)
        if not re.search(r"\b(success|failure|always|cancelled)\s*\(", expr):
            expr = f"success() && ({expr})"
        return truthy(self.ev(expr, steps, inputs))

    # environment of a step
    def step_env(self, extra: dict) -> dict:
        e = dict(os.environ)
        e.update({
            "CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(self.ws),
            "GITHUB_REPOSITORY": self.github["repository"], "GITHUB_REPOSITORY_OWNER": self.github["repository_owner"],
            "GITHUB_REF": self.github["ref"], "GITHUB_REF_NAME": self.github["ref_name"], "GITHUB_REF_TYPE": "branch",
            "GITHUB_HEAD_REF": "", "GITHUB_BASE_REF": "", "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_SHA": self.github["sha"], "GITHUB_RUN_ID": self.github["run_id"], "GITHUB_RUN_NUMBER": "1",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": self.a.job, "GITHUB_ACTOR": "local",
            "GITHUB_WORKFLOW": self.github["workflow"], "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_API_URL": "https://api.github.com", "RUNNER_TEMP": str(self.temp), "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64", "RUNNER_NAME": "pcci-local", "RUNNER_TOOL_CACHE": self.runner["tool_cache"],
            "GITHUB_STEP_SUMMARY": str(self.summary),
        })
        e.update(self.env)
        e.update({k: tostr(v) for k, v in extra.items()})
        if self.paths:
            e["PATH"] = ":".join(reversed(self.paths)) + ":" + e.get("PATH", "")
        return e

    def read_cmd_files(self, envf: Path, outf: Path, pathf: Path) -> dict:
        self.env.update(_kv_file(envf))
        for line in pathf.read_text().splitlines() if pathf.exists() else []:
            if line.strip():
                self.paths.append(line.strip())
        return _kv_file(outf)

    # running
    def run(self) -> int:
        workflow_env = self.wf.get("env") or {}
        for k, v in workflow_env.items():
            self.env[k] = tostr(self.sub(v, {}))
        for k, v in (self.job.get("env") or {}).items():
            self.env[k] = tostr(self.sub(v, {}))
        for k in ("PCCI_EXTRA_ENV",):
            for kv in filter(None, os.environ.get(k, "").split("\n")):
                n, _, v = kv.partition("=")
                self.env[n] = v
        log(f"LOCAL {self.a.job}: {len(self.job.get('steps', []))} steps, ref {self.github['ref_name']} "
            f"({self.github['sha'][:12]}), timeout {self.job.get('timeout-minutes', 360)} min × {self.factor:g}")
        self.run_steps(self.job.get("steps", []), {}, None, prefix="")
        log("")
        log(f"LOCAL {self.a.job}: {self.status().upper()}")
        for name, res, dt in self.results:
            log(f"  {res:9} {dt:7.1f}s  {name}")
        if self.summary.stat().st_size:
            log("── step summary ──")
            log(self.summary.read_text())
        return 0 if self.status() == "success" else 1

    def run_steps(self, steps: list, ctx_steps: dict, inputs, prefix: str, composite_dir: Path | None = None):
        for n, st in enumerate(steps, 1):
            name = st.get("name") or (f"uses {st['uses']}" if "uses" in st else (st.get("run") or "").strip().split("\n")[0][:70])
            label = f"{prefix}{n}"
            sid = st.get("id")
            if time.time() > self.deadline and not self.cancelled:
                log(f"::error::the job's timeout-minutes ({self.job.get('timeout-minutes')}) passed: cancelling")
                self.cancelled = True
            try:
                name = tostr(self.sub(name, ctx_steps, inputs))
            except ExprError:
                pass
            try:
                go = self.cond(st.get("if"), ctx_steps, inputs)
            except ExprError as e:
                log(f"::error::[{label}] {name}: if: {e}")
                self.failed = True
                go = False
            if not go:
                self.results.append((f"[{label}] {name}", "skipped", 0.0))
                if sid:
                    ctx_steps[sid] = {"outputs": {}, "outcome": "skipped", "conclusion": "skipped"}
                continue
            log(f"\n━━━ [{label}] {name}")
            t0 = time.time()
            try:
                ok, outputs = self.step(st, ctx_steps, inputs, label, composite_dir)
            except (ExprError, Cancelled) as e:
                log(f"::error::{e}")
                ok, outputs = False, {}
            dt = time.time() - t0
            coe = truthy(self.sub(st.get("continue-on-error", False), ctx_steps, inputs))
            outcome = "success" if ok else "failure"
            if not ok and not coe:
                self.failed = True
            res = outcome if ok or not coe else "failure (continue-on-error)"
            self.results.append((f"[{label}] {name}", res, dt))
            log(f"━━━ [{label}] {outcome} in {dt:.1f} s")
            if sid:
                ctx_steps[sid] = {"outputs": outputs, "outcome": outcome,
                                  "conclusion": "success" if ok or coe else "failure"}

    def step(self, st, ctx_steps, inputs, label, composite_dir):
        env = {k: tostr(self.sub(v, ctx_steps, inputs)) for k, v in (st.get("env") or {}).items()}
        tmo = st.get("timeout-minutes")
        limit = self.deadline - time.time()
        if tmo is not None:
            limit = min(limit, float(self.sub(tmo, ctx_steps, inputs)) * 60 * self.factor)
        if self.cancelled:
            limit = max(limit, 600)  # always() steps after a cancel: 10 min each
        if "run" in st:
            script = tostr(self.sub(st["run"], ctx_steps, inputs))
            shell = st.get("shell") or ((self.job.get("defaults") or {}).get("run") or {}).get("shell") \
                or ((self.wf.get("defaults") or {}).get("run") or {}).get("shell")
            wd = st.get("working-directory") or ((self.job.get("defaults") or {}).get("run") or {}).get("working-directory")
            cwd = self.ws / tostr(self.sub(wd, ctx_steps, inputs)) if wd else self.ws
            return self.run_script(script, shell, cwd, env, limit, label)
        if "uses" in st:
            with_ = {k: self.sub(v, ctx_steps, inputs) for k, v in (st.get("with") or {}).items()}
            return self.uses(st["uses"], with_, env, limit, label, composite_dir)
        raise ExprError(f"step [{label}] has neither run nor uses")

    def run_script(self, script, shell, cwd, env, limit, label):
        d = Path(tempfile.mkdtemp(prefix=f"step-{label}-", dir=self.temp))
        f = d / "script.sh"
        f.write_text(script)
        envf, outf, pathf, statef = d / "env", d / "output", d / "path", d / "state"
        for p in (envf, outf, pathf, statef):
            p.touch()
        e = self.step_env(env)
        e.update({"GITHUB_ENV": str(envf), "GITHUB_OUTPUT": str(outf), "GITHUB_PATH": str(pathf),
                  "GITHUB_STATE": str(statef)})
        if shell in (None, ""):
            argv = ["bash", "-e", str(f)]
        elif shell == "bash":
            argv = ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(f)]
        elif shell == "sh":
            argv = ["sh", "-e", str(f)]
        elif shell == "python":
            f.rename(d / "script.py")
            argv = ["python3", str(d / "script.py")]
        else:
            argv = [x.replace("{0}", str(f)) for x in shell.split()]
        rc = _run(argv, cwd, e, limit)
        if rc == "timeout":
            log(f"::error::step timed out after {limit / 60:.1f} min")
            if time.time() >= self.deadline:
                self.cancelled = True
            rc = 124
        outputs = self.read_cmd_files(envf, outf, pathf)
        if rc != 0:
            log(f"::error::Process completed with exit code {rc}.")
        return rc == 0, outputs

    def uses(self, ref, with_, env, limit, label, composite_dir):
        if ref.startswith("./"):
            adir = self.ws / ref
            af = next((adir / n for n in ("action.yml", "action.yaml") if (adir / n).exists()), None)
            if not af:
                raise ExprError(f"no action.yml in {ref}")
            action = yaml.safe_load(af.read_text())
            runs = action.get("runs") or {}
            if runs.get("using") != "composite":
                raise ExprError(f"{ref}: only composite local actions are emulated")
            ainputs = {}
            for k, spec in (action.get("inputs") or {}).items():
                ainputs[k] = tostr(with_[k]) if k in with_ else tostr(self.sub((spec or {}).get("default", ""), {}))
            before = self.failed
            self.failed = False
            sub_steps: dict = {}
            # composite steps see the step's env as their base
            saved = dict(self.env)
            self.env.update(env)
            try:
                self.run_steps(runs.get("steps") or [], sub_steps, ainputs, prefix=f"{label}.", composite_dir=adir)
            finally:
                added = {k: v for k, v in self.env.items() if saved.get(k) != v and k not in env}
                self.env = {**saved, **added}
            ok = not self.failed
            self.failed = before
            return ok, {}
        name, _, _ver = ref.partition("@")
        if name == "actions/checkout":
            repo, path = with_.get("repository"), with_.get("path")
            if not repo and not path:
                log("    (local: the workspace is already checked out)")
                return True, {}
            dest = self.ws / tostr(path or ".")
            url = f"https://github.com/{tostr(repo or self.github['repository'])}"
            argv = ["git", "clone", "--quiet", "--depth=1"] + (["--branch", tostr(with_["ref"])] if with_.get("ref") else []) \
                + [url, str(dest)]
            return _run(argv, self.ws, self.step_env(env), limit) == 0, {}
        if name == "actions/setup-go":
            return self.setup_go(with_)
        if name in ("actions/cache", "actions/cache/restore", "actions/cache/save"):
            log("    (local: no Actions cache — a miss; the container's cache volumes keep pip / Playwright / Go)")
            return True, {"cache-hit": "false", "cache-primary-key": tostr(with_.get("key", "")), "cache-matched-key": ""}
        if name == "actions/upload-artifact":
            dest = self.artifacts / tostr(with_.get("name", "artifact"))
            n = 0
            for pat in tostr(with_.get("path", "")).splitlines():
                pat = pat.strip()
                if not pat or pat.startswith("!"):
                    continue
                for m in glob.glob(str(self.ws / pat) if not pat.startswith("/") else pat, recursive=True):
                    src = Path(m)
                    rel = src.relative_to(self.ws) if src.is_relative_to(self.ws) else Path(src.name)
                    tgt = dest / rel
                    tgt.parent.mkdir(parents=True, exist_ok=True)
                    (shutil.copytree(src, tgt, dirs_exist_ok=True, symlinks=True) if src.is_dir() else shutil.copy2(src, tgt))
                    n += 1
            log(f"    (local: {n} path(s) copied to {dest})")
            return True, {}
        if name in ("docker/setup-buildx-action", "docker/setup-qemu-action"):
            log("    (local: no-op — the engine's default builder; binfmt/QEMU is a host-kernel setting and is never changed)")
            return True, {}
        if name == "docker/build-push-action":
            if truthy(with_.get("push")):
                raise ExprError("docker/build-push-action with push: true is never run locally")
            argv = ["docker", "buildx", "build", "--load"]
            for t in re.split(r"[\n,]", tostr(with_.get("tags", ""))):
                if t.strip():
                    argv += ["-t", t.strip()]
            for b in tostr(with_.get("build-args", "")).splitlines():
                if b.strip():
                    argv += ["--build-arg", b.strip()]
            if with_.get("file"):
                argv += ["-f", tostr(with_["file"])]
            if with_.get("target"):
                argv += ["--target", tostr(with_["target"])]
            for opt in ("provenance", "sbom"):
                if opt in with_ and tostr(with_[opt]) in ("false", "true"):
                    argv.append(f"--{opt}={tostr(with_[opt])}")
            plats = [p for p in tostr(with_.get("platforms", "")).split(",") if p.strip()]
            if len(plats) == 1:
                argv += ["--platform", plats[0].strip()]
            iid = Path(tempfile.mktemp(dir=self.temp))
            argv += ["--iidfile", str(iid), tostr(with_.get("context") or ".")]
            ok = _run(argv, self.ws, self.step_env(env), limit) == 0
            i = iid.read_text().strip() if iid.exists() else ""
            return ok, {"imageid": i, "digest": i}
        raise ExprError(f"`uses: {ref}` isn't emulated locally (run-job.sh); this job needs GitHub")

    def setup_go(self, with_):
        v = tostr(with_.get("go-version", "")).strip()
        if not v and with_.get("go-version-file"):
            txt = (self.ws / tostr(with_["go-version-file"])).read_text()
            m = re.search(r"^toolchain go(\S+)", txt, re.M) or re.search(r"^go (\S+)", txt, re.M)
            v = m.group(1) if m else ""
        if not v:
            raise ExprError("setup-go: no go-version")
        rel = json.load(urllib.request.urlopen("https://go.dev/dl/?mode=json&include=all", timeout=60))
        files = [f for r in rel for f in r["files"] if f["os"] == "linux" and f["arch"] == "amd64" and f["kind"] == "archive"]
        want = [f for f in files if f["version"] == f"go{v}"] or \
            sorted((f for f in files if re.fullmatch(rf"go{re.escape(v)}(\.\d+)?", f["version"])),
                   key=lambda f: [int(x) for x in re.findall(r"\d+", f["version"])], reverse=True)
        if not want:
            raise ExprError(f"setup-go: no Go release {v}")
        f = want[0]
        ver = f["version"][2:]
        root = Path(self.runner["tool_cache"]) / "go" / ver / "x64"
        if not (root / "bin" / "go").exists():
            log(f"    downloading {f['filename']}")
            tmp = Path(tempfile.mktemp(dir=self.temp))
            urllib.request.urlretrieve(f"https://go.dev/dl/{f['filename']}", tmp)
            got = hashlib.sha256(tmp.read_bytes()).hexdigest()
            if got != f["sha256"]:
                raise ExprError(f"setup-go: sha256 mismatch for {f['filename']}")
            root.parent.mkdir(parents=True, exist_ok=True)
            x = Path(tempfile.mkdtemp(dir=root.parent))
            subprocess.run(["tar", "-C", str(x), "-xzf", str(tmp)], check=True)
            if root.exists():
                shutil.rmtree(root)
            (x / "go").rename(root)
            shutil.rmtree(x, ignore_errors=True)
            tmp.unlink()
        self.paths += [str(root / "bin"), str(Path.home() / "go" / "bin")]
        log(f"    Go {ver} at {root}")
        return True, {"go-version": ver, "cache-hit": "false"}


def _kv_file(p: Path) -> dict:
    out: dict = {}
    if not p.exists():
        return out
    lines = p.read_text().split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line.strip():
            continue
        m = re.match(r"^([^=<]+)<<(.+)$", line)
        if m:
            name, delim, buf = m.group(1), m.group(2), []
            while i < len(lines) and lines[i] != delim:
                buf.append(lines[i])
                i += 1
            i += 1
            out[name] = "\n".join(buf)
        elif "=" in line:
            k, _, v = line.partition("=")
            out[k] = v
    return out


def _run(argv, cwd, env, limit):
    """Run argv in its own process group; 'timeout' after limit seconds."""
    p = subprocess.Popen(argv, cwd=cwd, env=env, start_new_session=True)
    try:
        return p.wait(timeout=max(1, limit))
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGTERM)
        try:
            p.wait(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
        return "timeout"
    except KeyboardInterrupt:
        os.killpg(p.pid, signal.SIGTERM)
        p.wait()
        raise


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workflow", default=".github/workflows/ci.yml")
    ap.add_argument("--job", required=True)
    ap.add_argument("--input", action="append", default=[], help="k=v: the workflow_dispatch inputs")
    ap.add_argument("--ref-name", default="main")
    ap.add_argument("--sha", default="")
    ap.add_argument("--repository", default="porelli/portcullis")
    a = ap.parse_args()
    if not a.sha:
        a.sha = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    job = Job(a)
    try:
        return job.run()
    except KeyboardInterrupt:
        log("LOCAL: interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
