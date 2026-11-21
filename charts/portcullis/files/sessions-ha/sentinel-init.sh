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
TERMLOG="${SENTINEL_INIT_TERMLOG:-/dev/termination-log}" PARTS="${SENTINEL_INIT_PARTS:-/etc/sessions-ha}" OUT="${SENTINEL_INIT_OUT:-/conf/sentinel.conf}"
# named <message> — shown by the status and nodeadm's snapshot (the HA
# page): this init container's termination message (review M-b).
named() { echo "sentinel-init: $*" >&2; printf 'portcullis-sessions: %s\n' "$*" > "$TERMLOG" 2>/dev/null || true; }
ours() { case "$1" in "sessions-0.$SVC" | "sessions-1.$SVC") return 0 ;; esac; return 1; }
# The master both other Sentinels name (two agreeing answers, review M2:
# one stale Sentinel alone never decides).
m="" seen="" answers=0 differ=""
for i in 0 1 2; do
  s="sessions-sentinel-$i.sessions-sentinel.$NS.svc.cluster.local"
  [ "$s" != "$me" ] || continue
  a="$(cli -h "$s" -p 26379 sentinel get-master-addr-by-name "$MASTER_NAME" 2>/dev/null | head -n1)"
  ours "$a" || continue
  answers=$((answers + 1))
  if [ "$a" = "$seen" ]; then m="$a"; break; fi
  [ -z "$seen" ] || differ="$seen / $a"
  seen="$a"
done
[ -z "$differ" ] || named "the other two Sentinels disagree on the master ($differ): monitoring the Valkey pods' own master; if this persists delete the three Sentinel pods together (docs: HA, the session store)"
if [ -z "$m" ]; then
  cand="" reached=0
  for v in "sessions-0.$SVC" "sessions-1.$SVC"; do
    r="$(cli -h "$v" -p 6379 info replication 2>/dev/null | tr -d '\r')"
    printf '%s\n' "$r" | grep -q '^role:' || continue
    reached=$((reached + 1))
    printf '%s\n' "$r" | grep -qx 'role:master' || continue
    if printf '%s\n' "$r" | grep -Eqx 'connected_slaves:[1-9][0-9]*'; then m="$v"; break; fi
    [ -n "$cand" ] || cand="$v"
  done
  m="${m:-$cand}"
  # Review M-b: exactly one other Sentinel answers and no Valkey pod can be
  # asked — follow that Sentinel rather than the sessions-0 default, so the
  # two that are up never disagree (this steers only this Sentinel; a
  # Valkey pod still needs two agreeing Sentinels to start).
  if [ -z "$m" ] && [ "$answers" = 1 ] && [ "$reached" = 0 ]; then m="$seen"; fi
fi
m="${m:-sessions-0.$SVC}"
{
  cat "$PARTS/sentinel.conf"
  echo "sentinel announce-ip $me"
  echo "sentinel monitor $MASTER_NAME $m 6379 2"
  cat "$PARTS/sentinel-monitor.conf"
} > "$OUT"
echo "sentinel-init: monitoring $m" >&2
