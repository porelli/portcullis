#!/bin/sh
# The session store's init guard in HA (plan Task 25, Amendment 2; spike 2
# Step 5): a Valkey pod never elects itself.
#   - Ask the Sentinels (portcullis-sessions) for the master, up to 60 s;
#     no answer → exit 1 (crash loop): starting as a second master is how a
#     node restart lost every session in the spike.
#   - The master named is this pod (it restarted empty, faster than the
#     Sentinels saw it down): if the other pod is a replica holding data
#     (asked directly), SENTINEL FAILOVER first and wait for the new master
#     (≤ 60 s), then replicate from it; if the Sentinels won't (a replica
#     disconnected too long for them), start as the master after all — the
#     sessions are lost, sign-in isn't; if the other pod is unreachable or
#     never replicated, start as the master (nothing to lose).
#   - Otherwise replicate from the master named.
# Writes /conf/valkey.conf: the CLI's config (secrets-sessions-ha, the ACL
# users and masterauth) by include, this pod's announced name and, as a
# replica, replicaof. Passwords only through VALKEYCLI_AUTH (the env, from
# the Secret), never argv or the written file.
set -u
NS="${POD_NAMESPACE:?}" ME="${POD_NAME:?}"
MASTER_NAME=portcullis-sessions
WAIT="${GUARD_WAIT:-60}" CONF="${GUARD_CONF:-/conf/valkey.conf}"
SVC="sessions-pods.$NS.svc.cluster.local"
me="$ME.$SVC"
sentinels="sessions-sentinel-0.sessions-sentinel.$NS.svc.cluster.local sessions-sentinel-1.sessions-sentinel.$NS.svc.cluster.local sessions-sentinel-2.sessions-sentinel.$NS.svc.cluster.local"
cli() { valkey-cli --no-auth-warning -t 2 --user sessions-admin "$@"; }
log() { echo "sessions-guard: $*" >&2; }
# ours <host> — one of the two Valkey pods' names (a Sentinel's answer is
# never trusted beyond that).
ours() { case "$1" in "sessions-0.$SVC" | "sessions-1.$SVC") return 0 ;; esac; return 1; }
# ask_master — the master at least two Sentinels name (quorum 2: a
# restarted or partitioned Sentinel alone never steers this pod); exit 1
# without two agreeing answers.
ask_master() {
  a=""
  for s in $sentinels; do
    x="$(cli -h "$s" -p 26379 sentinel get-master-addr-by-name "$MASTER_NAME" 2>/dev/null | head -n1)"
    ours "$x" || continue
    case " $a " in *" $x "*) printf '%s\n' "$x"; return 0 ;; esac
    a="$a $x"
  done
  return 1
}
# peer_state — the other Valkey pod's own replication view, asked directly
# (the Sentinels' replica list lags: found live, a rolling restart's new
# replica wasn't in it yet and the master came back empty): "replica"
# (role slave, offset > 0: it holds the data), "master" (role master,
# offset > 0), else "none" (unreachable, or never replicated).
peer_state() {
  case "$me" in "sessions-0.$SVC") p="sessions-1.$SVC" ;; *) p="sessions-0.$SVC" ;; esac
  r="$(cli -h "$p" -p 6379 info replication 2>/dev/null | tr -d '\r')" || { echo none; return; }
  off="$(printf '%s\n' "$r" | sed -n 's/^master_repl_offset://p')"
  [ "${off:-0}" -gt 0 ] 2>/dev/null || { echo none; return; }
  case "$(printf '%s\n' "$r" | sed -n 's/^role://p')" in slave) echo replica ;; master) echo master ;; *) echo none ;; esac
}
i=0
until m="$(ask_master)"; do
  i=$((i + 2))
  [ "$i" -lt "$WAIT" ] || { log "no Sentinel named the master in $WAIT s: refusing to start (never a second master)"; exit 1; }
  sleep 2
done
if [ "$m" = "$me" ]; then
  peer="$(peer_state)"
  if [ "$peer" = master ]; then
    log "the Sentinels name this pod, but the other one is a master with data: not starting (the Sentinels settle it)"
    exit 1
  fi
  if [ "$peer" = replica ]; then
    log "the Sentinels still name this pod the master and a replica is healthy: failing over first"
    for s in $sentinels; do [ "$(cli -h "$s" -p 26379 sentinel failover "$MASTER_NAME" 2>/dev/null)" = OK ] && break; done
    # Until two Sentinels name another master. No answer is no reason to
    # start (review I1: a failed query used to end the wait with this pod
    # starting as the master): only the explicit timeout below does that.
    i=0 last=""
    while :; do
      if n="$(ask_master)"; then last="$n"; [ "$n" = "$me" ] || { m="$n"; break; }; else last=""; fi
      i=$((i + 2))
      if [ "$i" -ge "$WAIT" ] && [ -z "$last" ]; then
        log "no two Sentinels answer after the failover: refusing to start (never a master on silence)"
        exit 1
      fi
      if [ "$i" -ge "$WAIT" ]; then
        # The Sentinels refuse a replica whose link was down longer than 10
        # × down-after (valkey src/sentinel.c sentinelSelectReplica: found
        # live after a long DNS outage): they'd never fail over, and this
        # pod would never start. The sessions are disposable (everyone signs
        # in again), sign-in isn't: start as the master.
        log "the Sentinels didn't fail over in $WAIT s (no replica they accept): starting as the master; the sessions are lost (everyone signs in again)"
        m=""
        break
      fi
      sleep 2
    done
  else
    log "the master, the other pod holds no data (unreachable or never replicated)"
    m=""
  fi
fi
{
  echo "include /etc/valkey-ha/valkey.conf"
  echo "replica-announce-ip $me"
  [ -z "$m" ] || echo "replicaof $m 6379"
} > "$CONF"
if [ -n "$m" ]; then log "starting as a replica of $m"; else log "starting as the master"; fi
