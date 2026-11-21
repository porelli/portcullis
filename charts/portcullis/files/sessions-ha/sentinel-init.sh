#!/bin/sh
# A Sentinel's start in HA (plan Task 25): writes /conf/sentinel.conf (an
# emptyDir: Sentinel rewrites its own config) from the CLI's parts
# (secrets-sessions-ha: sentinel.conf — ACL users, the peers' user — and
# sentinel-monitor.conf — auth and timings, after the monitor line) with
# this pod's announced name and the master to monitor: the one both other
# Sentinels name; else the Valkey pod that is a master with replicas (or a
# master at all); else sessions-0 (a first start). Only the two Valkey pods'
# names are ever monitored. Passwords only in the Secret's files and
# VALKEYCLI_AUTH, never argv.
set -u
NS="${POD_NAMESPACE:?}" ME="${POD_NAME:?}"
MASTER_NAME=portcullis-sessions
SVC="sessions-pods.$NS.svc.cluster.local"
me="$ME.sessions-sentinel.$NS.svc.cluster.local"
cli() { valkey-cli --no-auth-warning -t 2 --user sessions-admin "$@"; }
ours() { case "$1" in "sessions-0.$SVC" | "sessions-1.$SVC") return 0 ;; esac; return 1; }
# The master both other Sentinels name (two agreeing answers, review M2:
# one stale Sentinel alone never decides).
m="" seen=""
for i in 0 1 2; do
  s="sessions-sentinel-$i.sessions-sentinel.$NS.svc.cluster.local"
  [ "$s" != "$me" ] || continue
  a="$(cli -h "$s" -p 26379 sentinel get-master-addr-by-name "$MASTER_NAME" 2>/dev/null | head -n1)"
  ours "$a" || continue
  if [ "$a" = "$seen" ]; then m="$a"; break; fi
  seen="$a"
done
if [ -z "$m" ]; then
  cand=""
  for v in "sessions-0.$SVC" "sessions-1.$SVC"; do
    r="$(cli -h "$v" -p 6379 info replication 2>/dev/null | tr -d '\r')" || continue
    printf '%s\n' "$r" | grep -qx 'role:master' || continue
    if printf '%s\n' "$r" | grep -Eqx 'connected_slaves:[1-9][0-9]*'; then m="$v"; break; fi
    [ -n "$cand" ] || cand="$v"
  done
  m="${m:-$cand}"
fi
m="${m:-sessions-0.$SVC}"
{
  cat /etc/sessions-ha/sentinel.conf
  echo "sentinel announce-ip $me"
  echo "sentinel monitor $MASTER_NAME $m 6379 2"
  cat /etc/sessions-ha/sentinel-monitor.conf
} > /conf/sentinel.conf
echo "sentinel-init: monitoring $m" >&2
