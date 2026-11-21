# shellcheck shell=bash
#
# LLDAP SQLite → Postgres on Kubernetes (plan Task 26, D8; Amendment 2's
# measured steps, spike-components.md Step 4): a Docker / Podman backup's
# lldap_data (users.db) restored into the CNPG database LLDAP runs on.
# Sourced by runtime.sh after ha.sh. Bash 3.2 compatible.
#
# LLDAP's documented migration (docs/database_migration.md at v0.6.3, the
# pinned image's tag), step by step:
#   1. the schema on the target: `lldap create_schema` (the pinned image,
#      the target's URL from a temporary Secret, LLDAP's env and this
#      install's seed, cwd /tmp) — tables only, no admin, no group;
#   2. the dump: scripts/sqlite_dump_commands.sh's tables and filter
#      (_LLDAP_DUMP_TABLES below; never metadata or sqlite_sequence), read
#      with Python's sqlite3 in group-gate's image (no network, users.db on
#      exec stdin) instead of the sqlite3 shell, which no image here has;
#   3. the sanitizing: done by type, not by sed — every value is written as
#      the TARGET column's type (information_schema): bytea as '\x…', a
#      boolean from 0/1, the rest as quoted text; the doc's setval of
#      groups.group_id; one transaction;
#   4. the insert: psql in the primary (as postgres over the socket,
#      ON_ERROR_STOP, the whole dump one transaction);
#   5. the switch: the caller's (the restore's rename swap).
# Plus, beyond the doc: metadata's private_key_hash / private_key_location
# copied (the doc's dump leaves metadata out, so LLDAP would accept ANY seed
# at its first start and every password would silently stop binding; with
# the hash LLDAP refuses a seed that isn't the one that made the hashes),
# and the two databases compared before anything is switched: the user
# count, the users' uuids, the groups, the memberships, the password-hash
# count, the password hashes and the attributes — any difference refuses
# with "LLDAP conversion changed <what>: nothing was switched" and drops
# the half-made target.
# Nothing secret is printed or put on argv: the target URL is a file (a
# Secret from --from-file), users.db and the SQL go over stdin, the
# comparison is of sha256 digests.

# The tables sqlite_dump_commands.sh dumps (v0.6.3), in its order;
# user_attribute_schema without LLDAP's three built-in rows (create_schema
# makes them).
# Plus the two object-class tables schema v11 has and the script predates
# (user_object_classes, group_object_classes): a table users.db has and
# this list doesn't is refused, never dropped.
_LLDAP_DUMP_TABLES="users groups memberships jwt_refresh_storage jwt_storage password_reset_tokens group_attribute_schema group_attributes user_attribute_schema user_attributes user_object_classes group_object_classes"

# Runs in group-gate's image: stdin = one JSON line (the target's columns,
# {table: {column: data_type}}), then users.db's bytes. argv[1] = sql
# (the dump as Postgres SQL on stdout) | summary (the comparison lines:
# the seven named ones, then "rows:<table> <digest>" for every carried
# table) | rowsql (the SQL that computes the same rows: lines in Postgres).
# Full-row digests (review M2): every column of every carried row,
# normalised by the TARGET column's type on both sides — bytea as hex,
# booleans true/false, integers as decimals, timestamps to microseconds
# (round half to even, as Postgres; UTC for timestamptz, the wall time for
# timestamp), text as is, NULL as \x01 — joined by \x1f, sorted, sha256.
read -r -d '' _LLDAP_CONVERT_PY <<'PY' || true
import hashlib, json, sqlite3, sys
mode, tables = sys.argv[1], sys.argv[2].split()
cols = json.loads(sys.stdin.buffer.readline())
with open("/tmp/users.db", "wb") as f:
    f.write(sys.stdin.buffer.read())
db = sqlite3.connect("file:/tmp/users.db?mode=ro", uri=True)
if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
    sys.exit("users.db fails integrity_check")
have = {r[0] for r in db.execute("select name from sqlite_master where type = 'table'")}
skip = {"metadata", "sqlite_sequence"}
extra = sorted(have - skip - set(tables))
if extra:
    sys.exit("users.db has tables LLDAP's migration doesn't carry: " + ", ".join(extra))
def lit(v, t):
    if v is None:
        return "NULL"
    if t == "bytea":
        b = v if isinstance(v, bytes) else str(v).encode()
        return "'\\x" + b.hex() + "'"
    if t == "boolean":
        if v in (0, 1):
            return "true" if v else "false"
        raise SystemExit(f"a value for a boolean column isn't 0 / 1")
    if isinstance(v, bytes):
        raise SystemExit(f"a blob for a {t} column")
    if isinstance(v, (int, float)) and t not in ("text", "character varying"):
        return repr(v)
    return "'" + str(v).replace("'", "''") + "'"
import re
from decimal import Decimal, ROUND_HALF_EVEN
from datetime import datetime, timedelta, timezone
TS = re.compile(r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}(?::?\d{2})?)?$")
INTS = ("smallint", "integer", "bigint")
def ts_norm(v, t):
    m = TS.match(str(v))
    if not m:
        raise SystemExit(f"a value for a {t} column isn't a timestamp")
    d = datetime.strptime(m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S")
    us = int((Decimal("0." + (m.group(3) or "0")) * 1000000).quantize(Decimal(1), rounding=ROUND_HALF_EVEN))
    d = d + timedelta(microseconds=us)
    if t == "timestamp with time zone" and m.group(4) and m.group(4) != "Z":
        o = m.group(4).replace(":", "")
        off = timedelta(hours=int(o[1:3]), minutes=int(o[3:5] or 0))
        d = d - off if o[0] == "+" else d + off
    return d.strftime("%Y-%m-%d %H:%M:%S.%f")
def py_norm(v, t):
    if v is None:
        return "\x01"
    if t == "bytea":
        return (v if isinstance(v, bytes) else str(v).encode()).hex()
    if t == "boolean":
        return "true" if v in (1, True, "1", "true") else "false"
    if t in INTS:
        return str(int(v))
    if t.startswith("timestamp"):
        return ts_norm(v, t)
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return str(v)
def pg_norm(n, t):
    c = '"' + n + '"'
    if t == "bytea":
        e = f"encode({c}, 'hex')"
    elif t == "timestamp with time zone":
        e = f"to_char({c} at time zone 'UTC', 'YYYY-MM-DD HH24:MI:SS.US')"
    elif t.startswith("timestamp"):
        e = f"to_char({c}, 'YYYY-MM-DD HH24:MI:SS.US')"
    else:
        e = f"{c}::text"
    return f"coalesce({e}, E'\\x01')"
def rows(t):
    q = f'select * from "{t}"'
    if t == "user_attribute_schema":
        q += " where user_attribute_schema_name not in ('first_name', 'last_name', 'avatar')"
    c = db.execute(q)
    return [d[0] for d in c.description], c.fetchall()
if mode == "sql":
    out = ["BEGIN;"]
    for t in tables:
        if t not in have:
            continue
        if t not in cols:
            sys.exit(f"the target has no table {t}")
        names, rs = rows(t)
        miss = [n for n in names if n not in cols[t]]
        if miss:
            sys.exit(f"the target's {t} has no column " + ", ".join(miss))
        head = f'INSERT INTO "{t}" (' + ",".join(f'"{n}"' for n in names) + ") VALUES ("
        for r in rs:
            out.append(head + ",".join(lit(v, cols[t][n]) for n, v in zip(names, r)) + ");")
    out.append("SELECT setval(pg_get_serial_sequence('groups', 'group_id'), COALESCE((SELECT MAX(group_id) FROM groups), 1));")
    if "metadata" not in have:
        sys.exit("users.db has no metadata table")
    c = db.execute("select * from metadata")
    mc, m = [d[0] for d in c.description], c.fetchall()
    if len(m) != 1:
        sys.exit(f"users.db's metadata has {len(m)} rows (want 1)")
    md = dict(zip(mc, m[0]))
    out.append(f"DO $$ BEGIN IF (SELECT version FROM metadata) IS DISTINCT FROM {int(md['version'])} THEN RAISE EXCEPTION 'schema version differs'; END IF; END $$;")
    # Review M3: without the hash LLDAP would accept ANY seed at its first
    # start and every password would silently stop binding.
    if md.get("private_key_hash") is None:
        sys.exit("users.db has no private-key hash: LLDAP would accept any seed (refused)")
    out.append("UPDATE metadata SET private_key_hash = " + lit(md["private_key_hash"], "bytea")
               + ", private_key_location = " + lit(md.get("private_key_location"), "text") + ";")
    out.append("COMMIT;")
    sys.stdout.write("\n".join(out) + "\n")
elif mode == "rowsql":
    for t in tables:
        if t not in have:
            continue
        names, _ = rows(t)
        expr = " || E'\\x1f' || ".join(pg_norm(n, cols[t].get(n, "text")) for n in names)
        where = " where user_attribute_schema_name not in ('first_name', 'last_name', 'avatar')" if t == "user_attribute_schema" else ""
        print(f"select 'rows:{t} ' || encode(sha256(convert_to(coalesce(string_agg(l, E'\\n' order by l collate \"C\"), ''), 'UTF8')), 'hex') from (select {expr} as l from \"{t}\"{where}) s;")
else:
    def q(sql):
        return [r[0] for r in db.execute(sql)]
    def has(t):
        return t in have
    def digest(lines):
        return hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()
    print("users", db.execute("select count(*) from users").fetchone()[0])
    print("uuids", digest(q("select uuid from users")))
    print("groups", digest(q("select group_id || '|' || display_name || '|' || uuid from groups")))
    print("memberships", digest(q("select m.user_id || '|' || g.uuid from memberships m join groups g using (group_id)")))
    print("hash_count", db.execute("select count(*) from users where password_hash is not null").fetchone()[0])
    print("hashes", digest(q("select user_id || '|' || lower(hex(password_hash)) from users where password_hash is not null")))
    print("attributes", digest(q("select user_attribute_user_id || '|' || user_attribute_name || '|' || lower(hex(user_attribute_value)) from user_attributes") if has("user_attributes") else []))
    for t in tables:
        if t not in have:
            continue
        names, rs = rows(t)
        lines = ["\x1f".join(py_norm(v, cols.get(t, {}).get(n, "text")) for n, v in zip(names, r)) for r in rs]
        print(f"rows:{t}", digest(lines))
PY

# The same lines from Postgres (psql -XtA, one per line, sha256 over the
# lines sorted byte-wise: collate "C", joined by newlines as Python does).
read -r -d '' _LLDAP_CONVERT_PG_SUMMARY <<'SQL' || true
select 'users ' || count(*) from users;
select 'uuids ' || encode(sha256(convert_to(coalesce(string_agg(uuid, E'\n' order by uuid collate "C"), ''), 'UTF8')), 'hex') from users;
select 'groups ' || encode(sha256(convert_to(coalesce(string_agg(l, E'\n' order by l collate "C"), ''), 'UTF8')), 'hex') from (select group_id || '|' || display_name || '|' || uuid as l from groups) s;
select 'memberships ' || encode(sha256(convert_to(coalesce(string_agg(l, E'\n' order by l collate "C"), ''), 'UTF8')), 'hex') from (select m.user_id || '|' || g.uuid as l from memberships m join groups g using (group_id)) s;
select 'hash_count ' || count(*) from users where password_hash is not null;
select 'hashes ' || encode(sha256(convert_to(coalesce(string_agg(l, E'\n' order by l collate "C"), ''), 'UTF8')), 'hex') from (select user_id || '|' || encode(password_hash, 'hex') as l from users where password_hash is not null) s;
select 'attributes ' || encode(sha256(convert_to(coalesce(string_agg(l, E'\n' order by l collate "C"), ''), 'UTF8')), 'hex') from (select user_attribute_user_id || '|' || user_attribute_name || '|' || encode(user_attribute_value, 'hex') as l from user_attributes) s;
SQL

# _lldap_convert_pg_error <stderr file> — the first ERROR line only, its
# quoted values cut unless they are plain identifiers (review M6).
_lldap_convert_pg_error() {
  grep -m1 'ERROR:' "$1" | sed -E 's/^.*ERROR: +/Postgres: /; s/"([^"]*[^a-z0-9_"][^"]*)"/"…"/g' | cut -c1-300
}

# What each summary line names in the refusal.
_lldap_convert_what() {
  case "$1" in
    users) echo "the user count" ;; uuids) echo "the users' uuids" ;; groups) echo "the groups" ;;
    memberships) echo "the group memberships" ;; hash_count) echo "the password-hash count" ;;
    hashes) echo "the password hashes" ;; attributes) echo "the user attributes" ;;
    rows:*) echo "the rows of ${1#rows:}" ;; *) echo "$1" ;;
  esac
}

# _lldap_convert_db_of <pg-url-file> — the URL's database name (its path's
# last segment, a plain identifier), or nothing.
_lldap_convert_db_of() {
  local u
  u="$(cat "$1" 2>/dev/null)" || return 1
  u="${u%%\?*}"; u="${u##*/}"
  [[ "$u" =~ ^[a-z_][a-z0-9_]*$ ]] || return 1
  printf '%s' "$u"
}

# _lldap_convert_pod <pg-url-file> schema|seedcheck [<seed file>] — a
# one-shot pod of the pinned LLDAP image labelled lldap-schema (the chart's
# Postgres flow) and portcullis.io/lldap-convert, the URL (and for
# seedcheck the backup's seed) from a temporary Secret built --from-file,
# LLDAP's JWT secret / admin password from portcullis-env,
# --config-file /dev/null, cwd a memory emptyDir:
#   schema     `lldap create_schema` on the empty target (step 1; this
#              install's seed, secrets-lldap: create_schema stores no key);
#   seedcheck  `lldap run` on the converted target with the BACKUP's seed
#              (the queued early check): LLDAP compares the carried
#              private-key hash with its key and refuses a mismatch at
#              start; Ready (its own healthcheck) = the seed matches.
# Its log is never printed whole (a database error could name the URL): on
# failure the last lines with any "://user:pass@" cut. Leftovers of a killed
# run (same label) are removed first and on exit (review N4).
_lldap_convert_sweep() {
  kube_ctl -n "$(kube_ns)" delete pod,secret -l portcullis.io/lldap-convert=true --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
_lldap_convert_pod() {
  local url="$1" mode="$2" seed="${3:-}" ns img name st rc=0 i phase="" ready=""
  ns="$(kube_ns)"
  img="$(_kube_image_of lldap)" || return 1
  _lldap_convert_sweep
  name="lldap-convert-$(openssl rand -hex 4)"
  st="$(mktemp -d)"; chmod 700 "$st"
  (umask 077 && mkdir -p "$st/s" && cp "$url" "$st/s/LLDAP_DATABASE_URL" && { [ -z "$seed" ] || cp "$seed" "$st/s/key-seed"; })
  if ! kube_ctl -n "$ns" create secret generic "$name" --from-file="$st/s" --dry-run=client -o json \
         | jq '.metadata.labels["portcullis.io/lldap-convert"] = "true"' > "$st/secret.json" \
     || ! kube_ctl create -f "$st/secret.json" >/dev/null; then
    rm -rf "$st"; echo "could not make the conversion's temporary Secret" >&2; return 1
  fi
  rm -rf "$st"
  N="$name" NS="$ns" IMG="$img" U="$CT_UID_LLDAP" M="$mode" jq -n '
    def sec: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}};
    {apiVersion: "v1", kind: "Pod", metadata: {name: env.N, namespace: env.NS, labels: {"portcullis.io/component": "lldap-schema", "portcullis.io/lldap-convert": "true"}},
     spec: {restartPolicy: "Never", priorityClassName: "portcullis-core", automountServiceAccountToken: false, enableServiceLinks: false,
       securityContext: {runAsNonRoot: true, runAsUser: (env.U | tonumber), runAsGroup: (env.U | tonumber), fsGroup: (env.U | tonumber), seccompProfile: {type: "RuntimeDefault"}},
       containers: [({name: "lldap", image: env.IMG, workingDir: "/tmp",
         command: (if env.M == "schema" then ["/app/lldap", "create_schema", "--config-file", "/dev/null"] else ["/app/lldap", "run", "--config-file", "/dev/null"] end),
         env: [{name: "LLDAP_DATABASE_URL", valueFrom: {secretKeyRef: {name: env.N, key: "LLDAP_DATABASE_URL"}}},
               {name: "LLDAP_JWT_SECRET", valueFrom: {secretKeyRef: {name: "portcullis-env", key: "LLDAP_JWT_SECRET"}}},
               {name: "LLDAP_LDAP_USER_PASS", valueFrom: {secretKeyRef: {name: "portcullis-env", key: "LLDAP_ADMIN_PASSWORD"}}},
               {name: "LLDAP_KEY_SEED_FILE", value: "/run/portcullis/lldap/key-seed"}, {name: "LLDAP_KEY_FILE", value: ""}],
         resources: {limits: {memory: "256Mi"}, requests: {memory: "256Mi"}}, securityContext: sec,
         volumeMounts: [{name: "tmp", mountPath: "/tmp"}, {name: "data", mountPath: "/data"}, {name: "key-seed", mountPath: "/run/portcullis/lldap", readOnly: true}]}
         + (if env.M == "seedcheck" then {readinessProbe: {exec: {command: ["/app/lldap", "healthcheck", "--config-file", "/dev/null"]}, periodSeconds: 2, failureThreshold: 1}} else {} end))],
       volumes: [{name: "tmp", emptyDir: {medium: "Memory"}}, {name: "data", emptyDir: {medium: "Memory", sizeLimit: "16Mi"}},
                 (if env.M == "schema" then {name: "key-seed", secret: {secretName: "secrets-lldap", defaultMode: 288, items: [{key: "key-seed", path: "key-seed"}]}}
                  else {name: "key-seed", secret: {secretName: env.N, defaultMode: 288, items: [{key: "key-seed", path: "key-seed"}]}} end)]}}' \
    | kube_ctl create -f - >/dev/null || rc=1
  if [ "$rc" = 0 ]; then
    for ((i = 0; i < "${KUBE_POD_WAIT:-300}"; i += 2)); do
      phase="$(kube_ctl -n "$ns" get pod "$name" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
      case "$phase" in Succeeded|Failed) break ;; esac
      if [ "$mode" = seedcheck ]; then
        ready="$(kube_ctl -n "$ns" get pod "$name" -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || true)"
        [ "$ready" != true ] || break
      fi
      sleep 2
    done
    if { [ "$mode" = schema ] && [ "$phase" != Succeeded ]; } || { [ "$mode" = seedcheck ] && [ "$ready" != true ]; }; then
      rc=1
      echo "LLDAP's $mode on the target didn't succeed (${phase:-no phase}); its last lines:" >&2
      kube_ctl -n "$ns" logs "pod/$name" 2>/dev/null | tail -n 5 | sed -E 's#://[^/@ ]*@#://***@#g' | cut -c1-300 >&2 || true
    fi
  fi
  kube_ctl -n "$ns" delete pod "$name" --wait=false >/dev/null 2>&1 || true
  kube_ctl -n "$ns" delete secret "$name" >/dev/null 2>&1 || true
  return "$rc"
}
_lldap_convert_schema() { _lldap_convert_pod "$1" schema; }

# _lldap_convert_py <mode> <users.db> <columns-json-file> — the Python above
# in group-gate's image (a helper pod: no network, no volume, nobody's uid).
_lldap_convert_py() {
  local pod rc=0
  pod="$(_kube_helper_pod "" 65534:65534 ro "$(_kube_image_of group-gate)" lldap-convert)" || { echo "could not start the conversion's helper pod" >&2; return 1; }
  { tr -d '\n' < "$3"; echo; cat "$2"; } | kube_ctl -n "$(kube_ns)" exec -i "$pod" -- env PYTHONDONTWRITEBYTECODE=1 python3 -c "$_LLDAP_CONVERT_PY" "$1" "$_LLDAP_DUMP_TABLES" || rc=$?
  _kube_helper_done "$pod"
  return "$rc"
}

# lldap_convert_sqlite_to_pg <users.db> <pg-url-file> — users.db (a host
# file) into the EMPTY Postgres database the URL names (steps 1–4 above),
# then the comparison. Fails (and drops what it made in the target) on any
# step; the caller switches only after it returned 0. The target must hold
# no table: a conversion never writes over data.
lldap_convert_sqlite_to_pg() {
  local db="$1" url="$2" tdb tmp n k v what
  tdb="$(_lldap_convert_db_of "$url")" || fail "LLDAP conversion: the target URL names no plain database"
  [ -s "$db" ] && [ "$(head -c 15 "$db")" = "SQLite format 3" ] || fail "LLDAP conversion: $db is not a SQLite database"
  n="$(_kube_pg_exec psql -XtAq -d "$tdb" -c "select count(*) from pg_tables where schemaname = 'public'" 2>/dev/null || true)"
  [ "$n" = 0 ] || fail "LLDAP conversion: the target database $tdb isn't empty (${n:-unreadable}): nothing was converted"
  tmp="$(mktemp -d)"; chmod 700 "$tmp"
  # A failure leaves the target as empty as it was (public recreated,
  # owned by the database's owner, so a retry's create_schema can write).
  _lldap_convert_fail() {
    printf '%s\n' "DO \$\$ BEGIN EXECUTE 'drop schema public cascade'; EXECUTE 'create schema public authorization ' || quote_ident((SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database())); END \$\$;" \
      | _kube_pg_exec psql -XtAq -d "$tdb" -f - >/dev/null 2>&1 || true
    rm -rf "$tmp"; fail "$1"; }
  info "LLDAP: converting the backup's SQLite database into Postgres ($tdb)..."
  _lldap_convert_schema "$url" || _lldap_convert_fail "LLDAP conversion: create_schema failed: nothing was switched"
  _kube_pg_exec psql -XtAq -d "$tdb" -c "select coalesce(json_object_agg(table_name, c), '{}') from (select table_name, json_object_agg(column_name, data_type) as c from information_schema.columns where table_schema = 'public' group by table_name) s" > "$tmp/cols.json" 2>/dev/null \
    && jq -e 'type == "object" and has("users")' "$tmp/cols.json" >/dev/null 2>&1 && jq -c . "$tmp/cols.json" > "$tmp/cols.min" \
    || _lldap_convert_fail "LLDAP conversion: the target's schema couldn't be read: nothing was switched"
  _lldap_convert_py sql "$db" "$tmp/cols.min" > "$tmp/dump.sql" || _lldap_convert_fail "LLDAP conversion: the SQLite dump failed (see above): nothing was switched"
  # Development / e2e only (HUB_DEV=1): one statement appended inside the
  # transaction, the fault test_lldap_convert_refuses_on_diff injects.
  if [ -n "${PORTCULLIS_DEV_LLDAP_CONVERT_FAULT:-}" ]; then
    [ "${HUB_DEV:-}" = 1 ] || _lldap_convert_fail "PORTCULLIS_DEV_LLDAP_CONVERT_FAULT is for development only (HUB_DEV=1)"
    awk -v f="$PORTCULLIS_DEV_LLDAP_CONVERT_FAULT" '$0 == "COMMIT;" { print f } { print }' "$tmp/dump.sql" > "$tmp/dump.f" && mv "$tmp/dump.f" "$tmp/dump.sql"
  fi
  # Review M6: Postgres' errors can quote row contents (DETAIL: Failing row
  # contains …, LINE 1: …, a refused value): terse, no context, and only the
  # ERROR line is printed, every quoted value but a plain identifier cut.
  if ! _kube_pg_exec psql -X -q -v ON_ERROR_STOP=1 -v VERBOSITY=terse -v SHOW_CONTEXT=never -d "$tdb" -f - < "$tmp/dump.sql" >/dev/null 2> "$tmp/err"; then
    _lldap_convert_pg_error "$tmp/err" >&2
    _lldap_convert_fail "LLDAP conversion: Postgres refused the dump: nothing was switched"
  fi
  rm -f "$tmp/dump.sql"
  _lldap_convert_py summary "$db" "$tmp/cols.min" > "$tmp/src" || _lldap_convert_fail "LLDAP conversion: the source couldn't be summarised: nothing was switched"
  printf '%s\n' "$_LLDAP_CONVERT_PG_SUMMARY" | _kube_pg_exec psql -XtAq -v ON_ERROR_STOP=1 -d "$tdb" -f - > "$tmp/dst" 2>/dev/null \
    || _lldap_convert_fail "LLDAP conversion: the target couldn't be summarised: nothing was switched"
  _lldap_convert_py rowsql "$db" "$tmp/cols.min" | _kube_pg_exec psql -XtAq -v ON_ERROR_STOP=1 -d "$tdb" -f - >> "$tmp/dst" 2>/dev/null \
    || _lldap_convert_fail "LLDAP conversion: the target's rows couldn't be summarised: nothing was switched"
  [ "$(grep -c '^rows:' "$tmp/src")" -ge 1 ] && [ "$(grep -vc '^rows:' "$tmp/src")" = 7 ] || _lldap_convert_fail "LLDAP conversion: the source summary is incomplete: nothing was switched"
  while read -r k v; do
    [ "$(awk -v k="$k" '$1 == k { print $2; exit }' "$tmp/dst")" = "$v" ] && continue
    what="$(_lldap_convert_what "$k")"
    _lldap_convert_fail "LLDAP conversion changed $what: nothing was switched"
  done < "$tmp/src"
  ok "LLDAP: $(awk '$1 == "users" { print $2 }' "$tmp/src") user(s), $(awk '$1 == "hash_count" { print $2 }' "$tmp/src") password hash(es); uuids, groups, memberships, hashes and attributes equal the backup's."
  rm -rf "$tmp"
}

# kube_lldap_convert_backup <backup dir> — the restore's pre-flight for a
# Docker / Podman backup on Kubernetes: users.db out of lldap_data.tar.gz
# (host tar, a 0700 temp dir) converted into a fresh lldap_restore, owned by
# lldap, BEFORE anything of the live install changes (the caller then keeps
# lldap_restore for the rename swap). A refusal leaves the live databases,
# LLDAP's Deployment and everything else as they were.
kube_lldap_convert_backup() {
  local dir="$1" tmp
  tmp="$(mktemp -d)"; chmod 700 "$tmp"
  if ! tar -xzf "$dir/lldap_data.tar.gz" -C "$tmp" ./users.db 2>/dev/null && ! tar -xzf "$dir/lldap_data.tar.gz" -C "$tmp" users.db 2>/dev/null; then
    rm -rf "$tmp"; fail "LLDAP conversion: lldap_data.tar.gz holds no users.db: nothing was switched"
  fi
  _kube_pg_wait 600 || { rm -rf "$tmp"; fail "the Postgres primary ($KUBE_CNPG_NS/$KUBE_PG_CLUSTER) doesn't accept connections: nothing restored"; }
  [ -n "${LLDAP_PG_PASSWORD:-}" ] || { rm -rf "$tmp"; fail "LLDAP_PG_PASSWORD is not set in .env: nothing restored"; }
  _kube_pg_fresh_db lldap_restore lldap || { rm -rf "$tmp"; fail "could not make the database lldap_restore: nothing restored"; }
  (umask 077 && printf 'postgres://lldap:%s@%s:5432/lldap_restore' "$LLDAP_PG_PASSWORD" "$KUBE_PG_RW_HOST" > "$tmp/url")
  ( trap _lldap_convert_sweep EXIT; lldap_convert_sqlite_to_pg "$tmp/users.db" "$tmp/url" ) || {
    _kube_pg_exec dropdb --if-exists --force lldap_restore >/dev/null 2>&1 || true
    rm -rf "$tmp"; exit 1; }
  # The backup's seed against the converted users.db's key hash, now
  # (queued item: before anything of the live install changes).
  info "LLDAP: checking the backup's key seed against its users.db..."
  if ! ( trap _lldap_convert_sweep EXIT; _lldap_convert_pod "$tmp/url" seedcheck "$dir/secrets/lldap/key-seed" ); then
    _kube_pg_exec dropdb --if-exists --force lldap_restore >/dev/null 2>&1 || true
    rm -rf "$tmp"; fail "LLDAP conversion: the backup's key seed doesn't open its users.db (LLDAP refused it at start): nothing was switched"
  fi
  ok "LLDAP: the backup's key seed matches its users.db."
  rm -rf "$tmp"
  # shellcheck disable=SC2034  # read by _kube_restore_pg
  KUBE_LLDAP_CONVERTED=true
}

# kube_lldap_convert_preflight <backup dir> — the restore's first step for
# a backup whose LLDAP is SQLite (lldap_data.tar.gz, no lldap.dump): the
# conversion above, before anything of the live install changes.
# KUBE_LLDAP_CONVERTED tells _kube_restore_pg to keep the result.
kube_lldap_convert_preflight() {
  # shellcheck disable=SC2034  # read by _kube_restore_pg (ha.sh)
  KUBE_LLDAP_CONVERTED=false
  [ ! -s "$1/lldap.dump" ] && [ -s "$1/lldap_data.tar.gz" ] || return 0
  # Review M8: the converted copy (every hash) never outlives this run: any
  # later failure exits through this trap; after the swap it's gone anyway.
  trap _kube_lldap_restore_drop EXIT
  kube_lldap_convert_backup "$1"
}

# _kube_lldap_restore_drop — the EXIT trap above: drop lldap_restore if it
# is still there (the swap renames it; a failed restore leaves it).
_kube_lldap_restore_drop() {
  _kube_pg_exec dropdb --if-exists --force lldap_restore >/dev/null 2>&1 || true
}
