#!/usr/bin/env bash
# ci.yml mail jobs: `./portcullis mail enable --provider <p> --yes` with
# the wired instance's container logs kept while it runs (the Hub rolls a
# failed install back: its containers are removed with their logs).
#   mail-enable-logged.sh <provider> <out file>
# Exit: mail enable's. On a failure the last lines of every container the
# instance had are printed (logs saved under $MAIL_CI_LOGS, default
# /tmp/mail-instance-logs).
set -uo pipefail
provider="${1:?usage: mail-enable-logged.sh <provider> <out file>}"
out="${2:?usage: mail-enable-logged.sh <provider> <out file>}"
logs="${MAIL_CI_LOGS:-/tmp/mail-instance-logs}"
rm -rf "$logs" && mkdir -p "$logs"
# Every container of the project, once per id (a job re-run is a new
# container): its log appended as <service>.log, its state kept; polled
# every half second (the Hub removes a failed install's containers within
# seconds).
(
  while :; do
    for c in $(docker ps -aq --filter "label=com.docker.compose.project=portcullis-$provider" 2>/dev/null); do
      n="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$c" 2>/dev/null)" || continue
      st="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$c" 2>/dev/null)" || continue
      docker logs "$c" > "$logs/$n.$c.log" 2>&1 || true
      echo "$st" > "$logs/$n.$c.state"
    done
    sleep 0.5
  done
) &
keeper=$!
./portcullis mail enable --provider "$provider" --yes > "$out" 2>&1
rc=$?
kill "$keeper" 2>/dev/null
wait "$keeper" 2>/dev/null
cat "$out"
if [ "$rc" != 0 ]; then
  for f in "$logs"/*.log; do
    [ -e "$f" ] || continue
    s="${f%.log}.state"
    echo "--- $(basename "$f" .log) ($(cat "$s" 2>/dev/null))"
    tail -n 40 "$f"
  done
fi
exit "$rc"
