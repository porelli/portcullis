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
#   - Otherwise replicate from the master named, once it says role:master
#     itself (never a replica of a replica: asked again, then refused).
# Writes /conf/valkey.conf: the CLI's config (secrets-sessions-ha, the ACL
# users and masterauth) by include, this pod's announced name and, as a
# replica, replicaof. Passwords only through VALKEYCLI_AUTH (the env, from
# the Secret), never argv or the written file.
set -u
NS="${POD_NAMESPACE:?}" ME="${POD_NAME:?}"
MASTER_NAME=portcullis-sessions
WAIT="${GUARD_WAIT:-60}" CONF="${GUARD_CONF:-/conf/valkey.conf}" TERMLOG="${GUARD_TERMLOG:-/dev/termination-log}"
SVC="sessions-pods.$NS.svc.cluster.local"
me="$ME.$SVC"
sentinels="sessions-sentinel-0.sessions-sentinel.$NS.svc.cluster.local sessions-sentinel-1.sessions-sentinel.$NS.svc.cluster.local sessions-sentinel-2.sessions-sentinel.$NS.svc.cluster.local"
cli() { valkey-cli --no-auth-warning -t 2 --user sessions-admin "$@"; }
log() { echo "sessions-guard: $*" >&2; }
# named <message> — the error the status and nodeadm's snapshot (the HA
# page) show: the container's termination message, "portcullis-sessions:"
# first (review M-b).
named() { log "$*"; printf 'portcullis-sessions: %s\n' "$*" > "$TERMLOG" 2>/dev/null || true; }
# elapsed — seconds since $start (review N-2: a wait counts real seconds;
# one round of questions can take 6 s).
elapsed() { echo $(( $(date +%s) - start )); }
# ours <host> — one of the two Valkey pods' names (a Sentinel's answer is
# never trusted beyond that).
ours() { case "$1" in "sessions-0.$SVC" | "sessions-1.$SVC") return 0 ;; esac; return 1; }
# ask_master — the master at least two Sentinels name (quorum 2: a
# restarted or partitioned Sentinel alone never steers this pod); exit 1
# without two agreeing answers.
ANSWERS=""
ask_master() {
  a="" ANSWERS=""
  for s in $sentinels; do
    x="$(cli -h "$s" -p 26379 sentinel get-master-addr-by-name "$MASTER_NAME" 2>/dev/null | head -n1)"
    ANSWERS="$ANSWERS ${s%%.*}=${x:-none}"
    ours "$x" || continue
    case " $a " in *" $x "*) printf '%s\n' "$x"; return 0 ;; esac
    a="$a $x"
  done
  # Two or more Sentinels answer, each naming another pod: they disagree.
  set -- $a
  [ $# -ge 2 ] && DISAGREE=1
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
start="$(date +%s)"
while :; do
  DISAGREE=""
  ask_master > "$CONF.ask" && { m="$(cat "$CONF.ask")"; rm -f "$CONF.ask"; break; }
  # ask_master ran in this shell (no $(…)), so DISAGREE / ANSWERS stick.
  if [ "$(elapsed)" -ge "$WAIT" ]; then
    rm -f "$CONF.ask"
    if [ -n "$DISAGREE" ]; then
      named "the Sentinels disagree on the master ($ANSWERS ): no two agree, refusing to start; recover by deleting the three Sentinel pods together (docs: HA, the session store)"
    else
      named "no two Sentinels named the master in $WAIT s ($ANSWERS ): refusing to start (never a second master)"
    fi
    exit 1
  fi
  sleep 2
done
if [ "$m" = "$me" ]; then
  peer="$(peer_state)"
  if [ "$peer" = master ]; then
    named "the Sentinels name this pod, but the other one is a master with data: not starting (the Sentinels settle it)"
    exit 1
  fi
  if [ "$peer" = replica ]; then
    log "the Sentinels still name this pod the master and a replica is healthy: failing over first"
    for s in $sentinels; do [ "$(cli -h "$s" -p 26379 sentinel failover "$MASTER_NAME" 2>/dev/null)" = OK ] && break; done
    # Until two Sentinels name another master. No answer is no reason to
    # start (review I1: a failed query used to end the wait with this pod
    # starting as the master): only the explicit timeout below does that.
    start="$(date +%s)" last=""
    while :; do
      if n="$(ask_master)"; then last="$n"; [ "$n" = "$me" ] || { m="$n"; break; }; else last=""; fi
      # One reading of the clock per round (found under load: two readings
      # could straddle the deadline — the silence check saw it not yet due,
      # the next one due — and a silent round started this pod as the
      # master). Past the wait, silence refuses; only the Sentinels still
      # naming this pod starts it.
      t="$(elapsed)"
      if [ "$t" -ge "$WAIT" ] && [ -z "$last" ]; then
        named "no two Sentinels answer after the failover: refusing to start (never a master on silence)"
        exit 1
      fi
      if [ "$t" -ge "$WAIT" ]; then
        # The Sentinels refuse a replica whose link was down longer than 10
        # × down-after (valkey src/sentinel.c sentinelSelectReplica: found
        # live after a long DNS outage): they'd never fail over, and this
        # pod would never start. The sessions are disposable (everyone signs
        # in again), sign-in isn't: start as the master.
        named "the Sentinels didn't fail over in $WAIT s (no replica they accept): started as the master; the sessions were lost (everyone signs in again)"
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
# Never a replica of a replica (Task 33 part B, VM run 6: each pod had
# followed the master two Sentinels named at its own start, a failover fell
# between the two starts, and each replicated from the other; no master,
# and the Sentinels could never promote): the master named must say
# role:master itself (asked directly). Until it does, the Sentinels are
# asked again (they may name another pod by then) for at most $WAIT s;
# then refused (crash loop: the next start asks anew). Named this pod
# meanwhile: exit, so the next start takes the path above.
role_of() { cli -h "$1" -p 6379 info replication 2>/dev/null | tr -d '\r' | sed -n 's/^role://p'; }
if [ -n "$m" ]; then
  start="$(date +%s)"
  while :; do
    r="$(role_of "$m")"
    [ "$r" = master ] && break
    if [ "$(elapsed)" -ge "$WAIT" ]; then
      named "the master the Sentinels name ($m) says role ${r:-unknown (unreachable)}: refusing to start as its replica (never a replica of a replica)"
      exit 1
    fi
    sleep 2
    if n="$(ask_master)"; then
      if [ "$n" = "$me" ]; then
        named "the Sentinels now name this pod the master: restarting the guard (its own-master path)"
        exit 1
      fi
      m="$n"
    fi
  done
fi
{
  echo "include /etc/valkey-ha/valkey.conf"
  echo "replica-announce-ip $me"
  [ -z "$m" ] || echo "replicaof $m 6379"
} > "$CONF"
if [ -n "$m" ]; then log "starting as a replica of $m"; else log "starting as the master"; fi
