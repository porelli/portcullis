#!/usr/bin/env python3
"""e2e-mail's remote Stalwart: apply tests/e2e/mail/remote/plan.json over
its management JMAP as the recovery admin (stdlib only).

  python3 tests/e2e/e2e_mailremote.py apply <management url>
      environment: REMOTE_ADMIN (user:password, the recovery admin),
      and every {{VAR}} the plan names (REMOTE_PASSWORD, REMOTE_DKIM_PEM,
      PORTCULLIS_MX, RESOLVER_IP, RESOLVER_PORT, REMOTE_USER).

The plan: `collections` (each object's wanted items by `key`, created when
missing; `destroy_others` destroys every other one; `_none` = no key, the
one item is made once), then `singletons` (patches, in order), `disable`
(every object of that type gets enable false) and `actions`. Strings are
templated (`{{VAR}}`), `@id:<Object>:<key value>` is an id made earlier and
`#<n>` a number. Secrets come from the environment only and are never
printed.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request

USING = ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"]
PLAN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mail", "remote", "plan.json")


class JmapError(Exception):
    pass


class Jmap:
    def __init__(self, url: str, user: str, password: str):
        self.url = url.rstrip("/") + "/jmap"
        tok = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Authorization": "Basic " + tok, "Content-Type": "application/json", "Accept": "application/json"}

    def call(self, method: str, args: dict) -> dict:
        body = json.dumps({"using": USING, "methodCalls": [[method, args, "0"]]}).encode()
        req = urllib.request.Request(self.url, data=body, headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                out = json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise JmapError(f"{method}: HTTP {e.code}") from None
        name, res, _ = out["methodResponses"][0]
        if name == "error":
            raise JmapError(f"{method}: {res.get('type')}: {res.get('description', '')}")
        return res

    def get_all(self, obj: str) -> list[dict]:
        ids = self.call(f"x:{obj}/query", {}).get("ids") or []
        if not ids:
            return []
        return self.call(f"x:{obj}/get", {"ids": ids}).get("list") or []

    def set(self, obj: str, create=None, update=None, destroy=None) -> dict:
        args: dict = {}
        if create:
            args["create"] = create
        if update:
            args["update"] = update
        if destroy:
            args["destroy"] = destroy
        res = self.call(f"x:{obj}/set", args)
        for kind in ("notCreated", "notUpdated", "notDestroyed"):
            if res.get(kind):
                # The SetError carries no secret (Stalwart names the field).
                raise JmapError(f"x:{obj}/set {kind}: {json.dumps(res[kind])[:600]}")
        return res


_VAR = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def render(v, env: dict, ids: dict):
    if isinstance(v, dict):
        return {render(k, env, ids): render(x, env, ids) for k, x in v.items()}
    if isinstance(v, list):
        return [render(x, env, ids) for x in v]
    if isinstance(v, str):
        def sub(m):
            if m.group(1) not in env:
                raise KeyError(f"the plan needs {m.group(1)} in the environment")
            return env[m.group(1)]
        s = _VAR.sub(sub, v)
        if s.startswith("@id:"):
            _, obj, key = s.split(":", 2)
            if (obj, key) not in ids:
                raise KeyError(f"no id for {obj} {key} (made earlier in the plan?)")
            return ids[(obj, key)]
        if s.startswith("#") and s[1:].isdigit():
            return int(s[1:])
        return s
    return v


def apply(j: Jmap, plan: dict, env: dict, log=print) -> dict:
    ids: dict = {}
    for c in plan["collections"]:
        obj, key = c["object"], c["key"]
        want = [render(w, env, ids) for w in c["want"]]
        have = j.get_all(obj)
        if key == "_none":
            if have:
                ids[(obj, "_none")] = have[0]["id"]
                continue
            res = j.set(obj, create={"n": want[0]})
            ids[(obj, "_none")] = res["created"]["n"]["id"]
            log(f"remote: {obj} made")
            continue
        names = {w[key] for w in want}
        if c.get("destroy_others"):
            gone = [h["id"] for h in have if h.get(key) not in names]
            if gone:
                j.set(obj, destroy=gone)
            have = [h for h in have if h.get(key) in names]
        for h in have:
            ids[(obj, h[key])] = h["id"]
        create = {f"c{i}": w for i, w in enumerate(want) if (obj, w[key]) not in ids}
        if create:
            res = j.set(obj, create=create)
            for cid, w in create.items():
                ids[(obj, w[key])] = res["created"][cid]["id"]
            log(f"remote: {obj} made {', '.join(sorted(str(w[key]) for w in create.values()))}")
    for s in plan["singletons"]:
        j.set(s["object"], update={"singleton": render(s["patch"], env, ids)})
    for obj in plan.get("disable", []):
        off = {h["id"]: {"enable": False} for h in j.get_all(obj) if h.get("enable") is not False}
        if off:
            j.set(obj, update=off)
    for a in plan.get("actions", []):
        j.set("Action", create={"a": {"@type": a}})
    log("remote: plan applied")
    return {f"{o}:{k}": v for (o, k), v in ids.items()}


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "apply":
        print(__doc__, file=sys.stderr)
        return 2
    user, _, pw = os.environ["REMOTE_ADMIN"].partition(":")
    with open(PLAN) as f:
        plan = json.load(f)
    try:
        apply(Jmap(argv[2], user, pw), plan, dict(os.environ))
    except (JmapError, KeyError) as e:
        print(f"remote: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
