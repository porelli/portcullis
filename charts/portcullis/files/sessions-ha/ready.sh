#!/bin/sh
# Readiness of a session-store pod in HA (spike 2 Step 5): the master, or a
# replica whose link is up and not in a full sync. With minReadySeconds 10
# a rolling restart waits for the replica to hold the data again.
out="$(valkey-cli --no-auth-warning -t 2 --user sessions-admin -h 127.0.0.1 info replication 2>/dev/null | tr -d '\r')" || exit 1
printf '%s\n' "$out" | grep -qx 'role:master' && exit 0
printf '%s\n' "$out" | grep -qx 'master_link_status:up' && ! printf '%s\n' "$out" | grep -qx 'master_sync_in_progress:1'
