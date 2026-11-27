#!/bin/sh
# Liveness of a session-store pod in HA (Task 33 part B, VM run 6): the
# process answers (an unauthenticated PING gets NOAUTH), and it isn't stuck
# in a replication the Sentinels can't repair:
#   - a replica whose link is down and whose master says it is a replica
#     itself (a loop: no master; the Sentinels refuse every failover, "no
#     good slave"), or
#   - a replica whose link is down while two Sentinels name it the master.
# Either, for the probe's whole failure window (20 × 5 s), restarts the pod,
# and its start guard recovers (the Sentinels name it: a failover, else the
# master after its wait; or it follows a real master). A master that is
# just unreachable (a failover under way) is never a reason: a restart
# empties this replica's in-memory copy. Passwords only through
# VALKEYCLI_AUTH (the env), never argv.
set -u
env -u VALKEYCLI_AUTH valkey-cli --no-auth-warning -h 127.0.0.1 ping 2>&1 | grep -q NOAUTH || exit 1
cli() { valkey-cli --no-auth-warning -t 2 --user sessions-admin "$@"; }
r="$(cli -h 127.0.0.1 info replication 2>/dev/null | tr -d '\r')" || exit 0
printf '%s\n' "$r" | grep -qx 'role:slave' || exit 0
printf '%s\n' "$r" | grep -qx 'master_link_status:up' && exit 0
mh="$(printf '%s\n' "$r" | sed -n 's/^master_host://p')"
if [ -n "$mh" ] && [ "$(cli -h "$mh" -p 6379 info replication 2>/dev/null | tr -d '\r' | sed -n 's/^role://p')" = slave ]; then
  echo "a replica of a replica ($mh): no master"
  exit 1
fi
NS="${POD_NAMESPACE:-}" ME="${POD_NAME:-}"
[ -n "$NS" ] && [ -n "$ME" ] || exit 0
me="$ME.sessions-pods.$NS.svc.cluster.local"
n=0
for i in 0 1 2; do
  x="$(cli -h "sessions-sentinel-$i.sessions-sentinel.$NS.svc.cluster.local" -p 26379 sentinel get-master-addr-by-name portcullis-sessions 2>/dev/null | head -n1)"
  [ "$x" = "$me" ] && n=$((n + 1))
done
if [ "$n" -ge 2 ]; then
  echo "a replica that $n Sentinels name the master"
  exit 1
fi
exit 0
