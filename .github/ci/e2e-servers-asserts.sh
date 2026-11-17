#!/usr/bin/env bash
# ci.yml jobs e2e-servers / e2e-servers-podman, e2e_servers.py
# socket_rule_both_stacks (contract §6): on the primary only the two socket
# proxies mount the engine socket (relays included in the check); on each
# worker only socket-proxy-agent does, read-only. Live, from the engines.
set -euo pipefail
kind="${1:?dind|podman}"
W=".github/ci/e2e-servers-worker.sh"
mounts() {  # [exec <worker>] — "<container name> <source> <destination> <rw>" for every engine-socket mount
  local ids
  ids="$("$@" docker ps -aq)"
  [ -n "$ids" ] || return 0
  # shellcheck disable=SC2086
  "$@" docker inspect $ids | jq -r '.[] | .Name as $n | .Mounts[]?
      | select((.Source // "" | test("(docker|podman)\\.sock$")) or .Destination == "/var/run/docker.sock")
      | "\($n | ltrimstr("/")) \(.Source) \(.Destination) \(.RW)"'
}
P="$(mounts)"
echo "primary: $P"
[ "$(printf '%s\n' "$P" | awk 'NF { print $1 }' | sed -E 's/-[0-9]+$//' | sort | paste -sd' ' -)" = "portcullis-socket-proxy-hub portcullis-socket-proxy-traefik" ] \
  || { echo "FAIL: on the primary, containers other than the two proxies mount the engine socket"; exit 1; }
printf '%s\n' "$P" | awk 'NF && $4 != "false" { bad = 1 } END { exit bad }' || { echo "FAIL: a writable socket mount on the primary"; exit 1; }
workers="w1"
[ "$kind" != dind ] || ! docker inspect e2e-w3 >/dev/null 2>&1 || workers="w1 w3"
for w in $workers; do
  M="$(mounts bash "$W" exec "$w")"
  echo "$w: $M"
  [ "$(printf '%s\n' "$M" | awk 'NF { print $1 }' | sed -E 's/-[0-9]+$//' | sort -u | paste -sd' ' -)" = "portcullis-worker-socket-proxy-agent" ] \
    || { echo "FAIL: on $w, containers other than socket-proxy-agent mount the engine socket"; exit 1; }
  printf '%s\n' "$M" | awk 'NF && $4 != "false" { bad = 1 } END { exit bad }' || { echo "FAIL: a writable socket mount on $w"; exit 1; }
done
echo "PASS: socket rule on both stacks: the primary's two proxies, each worker's socket-proxy-agent, all read-only"
