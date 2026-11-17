"""Single-scenario reruns for the e2e runners (E2E_SCENARIOS).

E2E_SCENARIOS (ci.yml's workflow_dispatch input `scenarios`, a comma and/or
space separated list; empty = every scenario) names the scenarios a runner
runs. A scenario's name comes from its check() name:

    "4 mail_password_flow"                      -> "4", "mail_password_flow"
    "3 gtube_rejected_at_data, between_..."     -> "3", "gtube_rejected_at_data", "between_..."
    "cross_domain_sso: a stale ext cookie ..."  -> "cross_domain_sso"
    "imp_refused_concurrent + imp_next_bound (reuse): ..." -> both names
    "fourth_refused / remove: ..."              -> "fourth_refused", "remove"

i.e. the text before the first ':' (the whole name when there is none),
parenthesised parts dropped, split on ',', '+' and '/', with an optional
leading scenario number; every part must be one lowercase identifier. A
check whose name gives no such key ("alice, bob and carol: setup link →
passkey → portal", "the session reaches the app") is setup and always runs,
and so does one whose key a runner declares as setup with always() (the
defaults: setup, seed, finally). Several checks may share a name (all run).

The known names are read from every tests/e2e/e2e_*.py file's check("…")
calls (the source, with ast: the list can't drift from the checks); a name
no runner knows fails the runner at import (exit 2), and `scenarios.py check`
fails a workflow_dispatch run before any stack boots. Only the Python
runners' checks are filtered: the job's shell steps (stack start, backups,
shell assertions) still run. A scenario that builds on an earlier one's
state (the runners' needs()) fails closed when that one wasn't named: name
both.

    python3 tests/e2e/scenarios.py list [<runner.py>…]
    python3 tests/e2e/scenarios.py check --jobs "<jobs input>" --scenarios "<names>" [--workflow ci.yml]
"""
from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENV = "E2E_SCENARIOS"
_IDENT = re.compile(r"^[a-z][a-z0-9_]*$")
_ALWAYS = {"setup", "seed", "finally"}


def split_names(text: str) -> list[str]:
    """The names of an E2E_SCENARIOS / input value (commas and/or spaces)."""
    return [n for n in re.split(r"[,\s]+", text or "") if n]


def keys(name: str) -> list[str]:
    """The scenario names a check() name gives ([] = setup, always runs)."""
    head = name.split(":", 1)[0] if ":" in name else name
    head = re.sub(r"\([^)]*\)", " ", head).strip()
    out: list[str] = []
    m = re.match(r"^(\d+)\s+(.*)$", head)
    if m:
        out.append(m.group(1))
        head = m.group(2)
    parts = [p.strip() for p in re.split(r"[,+/]", head)]
    if not parts or not all(_IDENT.match(p) for p in parts):
        return out if m and not head else []
    return out + parts


def _fn_facts(node: ast.AST) -> tuple[set[str], set[str]]:
    """(the state keys node's code needs(), the ones it sets as state["k"] = …)."""
    need, made = set(), set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "needs":
            need.update(a.value for a in n.args if isinstance(a, ast.Constant) and isinstance(a.value, str))
        targets = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(n, (ast.AugAssign, ast.AnnAssign)) else []
        for t in targets:
            for e in (t.elts if isinstance(t, ast.Tuple) else [t]):
                if (isinstance(e, ast.Subscript) and isinstance(e.value, ast.Name) and e.value.id == "state"
                        and isinstance(e.slice, ast.Constant) and isinstance(e.slice.value, str)):
                    made.add(e.slice.value)
    return need, made


def _checks(path: Path) -> list[tuple[str, set[str], set[str]]]:
    """path's check("…", fn) calls: (name or its literal prefix, the state
    keys fn needs(), the keys it sets). fn = a function defined before the
    call (the last one of that name) or a lambda (and the functions it calls)."""
    tree = ast.parse(path.read_text(), str(path))
    defs: dict[str, list[ast.AST]] = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defs.setdefault(n.name, []).append(n)

    def resolve(name: str, line: int) -> list[ast.AST]:
        cands = [d for d in defs.get(name, []) if d.lineno <= line] or defs.get(name, [])
        return [max(cands, key=lambda d: d.lineno)] if cands else []

    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and len(node.args) >= 2):
            continue
        f = node.func
        if (f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else "") != "check":
            continue
        a = node.args[0]
        if isinstance(a, ast.Constant) and isinstance(a.value, str):
            name = a.value
        elif isinstance(a, ast.JoinedStr) and a.values and isinstance(a.values[0], ast.Constant):
            name = str(a.values[0].value)
        elif isinstance(a, ast.BinOp) and isinstance(a.left, ast.Constant) and isinstance(a.left.value, str):
            name = a.left.value
        else:
            name = ""
        fn = node.args[1]
        bodies: list[ast.AST] = []
        if isinstance(fn, ast.Name):
            bodies = resolve(fn.id, node.lineno)
        elif isinstance(fn, ast.Lambda):
            bodies = [fn] + [d for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                             for d in resolve(c.func.id, node.lineno)]
        need, made = set(), set()
        for b in bodies:
            n_, m_ = _fn_facts(b)
            need |= n_
            made |= m_
        out.append((name, need, made))
    return out


def _check_names(path: Path) -> list[str]:
    return [c[0] for c in _checks(path)]


def known(runners: list[Path] | None = None) -> dict[str, set[str]]:
    """runner file name -> the scenario names its checks give."""
    out = {}
    for p in runners if runners is not None else sorted(HERE.glob("e2e_*.py")):
        ks: set[str] = set()
        for n in _check_names(p):
            ks.update(keys(n))
        out[p.name] = ks
    return out


def closure(want: set[str], runners: list[Path] | None = None) -> set[str]:
    """want plus every scenario whose check sets a state key a wanted one
    needs() (transitively), per runner (the runners' needs() fail closed
    on missing state: this is what makes a single scenario runnable)."""
    out = set(want)
    for p in runners if runners is not None else sorted(HERE.glob("e2e_*.py")):
        cs = [(set(keys(n)), need, made) for n, need, made in _checks(p)]
        mine = set(want)
        while True:
            need = set().union(*(nd for ks, nd, _ in cs if ks & mine)) if cs else set()
            add = set().union(*(ks for ks, _, md in cs if md & need)) if cs else set()
            if add <= mine:
                break
            mine |= add
        out |= mine
    return out


def always(*names: str) -> None:
    """Declare scenario keys that are this runner's setup (always run)."""
    _ALWAYS.update(names)


_WANT: set[str] | None = None


def _wanted_set() -> set[str]:
    global _WANT
    if _WANT is None:
        named = set(split_names(os.environ.get(ENV, "")))
        _WANT = closure(named) if named else set()
    return _WANT


def wanted(name: str) -> bool:
    """Whether check(name) runs under E2E_SCENARIOS (empty: everything)."""
    want = _wanted_set()
    if not want:
        return True
    ks = keys(name)
    return not ks or bool(set(ks) & _ALWAYS) or bool(set(ks) & want)


def skip(name: str) -> bool:
    """For a runner's check(): True (and says so) when name is filtered out."""
    if wanted(name):
        return False
    print(f"SKIP: {name} ({ENV})", flush=True)
    return True


def _validate_env() -> None:
    want = set(split_names(os.environ.get(ENV, "")))
    if not want:
        return
    all_known = set().union(*known().values())
    bad = sorted(want - all_known)
    if bad:
        print(f"FAIL: {ENV}: unknown scenario name(s): {' '.join(bad)} "
              f"(`python3 tests/e2e/scenarios.py list` names them)", file=sys.stderr, flush=True)
        sys.exit(2)
    extra = sorted(_wanted_set() - want - _ALWAYS)
    print(f"{ENV}: only {' '.join(sorted(want))}" + (f" + what they need: {' '.join(extra)}" if extra else "")
          + " (plus setup)", flush=True)


def job_runners(workflow: Path) -> dict[str, list[Path]]:
    """ci.yml job -> the e2e runners it starts (its run: text and the
    .github/ci/*.sh scripts it calls), read as text (no YAML parser on the
    hosted runner's system Python)."""
    root = workflow.resolve().parents[2]
    jobs: dict[str, str] = {}
    cur = None
    in_jobs = False
    for line in workflow.read_text().splitlines():
        if line.startswith("jobs:"):
            in_jobs = True
            continue
        if in_jobs and re.match(r"^\S", line):
            in_jobs = False
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line) if in_jobs else None
        if m:
            cur = m.group(1)
            jobs[cur] = ""
        elif cur and in_jobs:
            jobs[cur] += line + "\n"
    out = {}
    for job, text in jobs.items():
        text = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
        for script in set(re.findall(r"\.github/ci/[A-Za-z0-9_.-]+\.sh", text)):
            p = root / script
            if p.is_file():
                text += "\n".join(ln for ln in p.read_text().splitlines() if not ln.lstrip().startswith("#"))
        files = sorted({HERE / f for f in re.findall(r"tests/e2e/(e2e_[a-z0-9_]+\.py)", text)} |
                       {HERE / f for f in re.findall(r"\b(e2e_[a-z0-9_]+\.py)\b", text)})
        out[job] = [f for f in files if f.is_file()]
    return out


def _cli(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="scenarios.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list", help="the scenario names per runner")
    ls.add_argument("runners", nargs="*")
    ck = sub.add_parser("check", help="fail on a name none of the chosen jobs' runners knows")
    ck.add_argument("--jobs", default="all")
    ck.add_argument("--scenarios", default="")
    ck.add_argument("--workflow", default=str(HERE.parents[1] / ".github/workflows/ci.yml"))
    a = ap.parse_args(argv)
    if a.cmd == "list":
        for runner, ks in known([Path(r) for r in a.runners] or None).items():
            if ks:
                print(f"{runner}: {' '.join(sorted(ks, key=lambda k: (not k.isdigit(), int(k) if k.isdigit() else 0, k)))}")
        return 0
    want = split_names(a.scenarios)
    if not want:
        print("scenarios: all")
        return 0
    per_job = job_runners(Path(a.workflow))
    jobs = split_names(a.jobs)
    if not jobs or jobs == ["all"]:
        jobs = list(per_job)
    runners = sorted({r for j in jobs for r in per_job.get(j, [])})
    if not runners:
        print(f"::error::scenarios: the chosen jobs ({' '.join(jobs)}) start no e2e runner", file=sys.stderr)
        return 1
    k = known(runners)
    names = set().union(*k.values())
    bad = [n for n in want if n not in names]
    if bad:
        print(f"::error::scenarios: unknown for {' '.join(jobs)}: {' '.join(bad)} "
              f"(known: {' '.join(sorted(names))})", file=sys.stderr)
        return 1
    full = closure(set(want), runners)
    for r, ks in k.items():
        hit = sorted(full & ks)
        print(f"{r}: {' '.join(hit) if hit else '(setup only)'}")
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))

_validate_env()
