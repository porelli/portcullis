#!/usr/bin/env bash
# ci.yml mail jobs: `./portcullis mail enable --provider <p> --yes` with
# the wired instance's container logs kept while it runs (the Hub rolls a
# failed install back: its containers are removed with their logs).
#   mail-enable-logged.sh <provider> <out file>
# Exit: mail enable's. On a failure the last lines of every container the
# instance had are printed (logs saved under $MAIL_CI_LOGS, default
# /tmp/mail-instance-logs). On a success it then waits (≤ 300 s) for the
# instance's restart that the first posted mail key owes when the block
# has admin_view (contract §19.3: the read-only view pins the key): the
# Hub's record for <provider> a finished, ok restart; exit 1 otherwise.
# The Hub: $HUB_API when set (rootless Podman's published port), else its
# address on the portcullis network; the proxy secret from .env, never
# printed.
set -uo pipefail
provider="${1:?usage: mail-enable-logged.sh <provider> <out file>}"
out="${2:?usage: mail-enable-logged.sh <provider> <out file>}"
logs="${MAIL_CI_LOGS:-/tmp/mail-instance-logs}"
rm -rf "$logs" && mkdir -p "$logs"
# Every container of the project, once per id (a job re-run is a new
# container): its log as <service>.<id>.log, its state kept; polled
# every half second (the Hub removes a failed install's containers within
# seconds).
(
  while :; do
    for c in $(docker ps -aq --filter "label=com.docker.compose.project=portcullis-$provider" 2>/dev/null); do
      n="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.service"}}' "$c" 2>/dev/null)" || continue
      st="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$c" 2>/dev/null)" || continue
      # Kept only when read (a container removed meanwhile keeps its last copy).
      docker logs "$c" > "$logs/.tmp" 2>&1 && mv "$logs/.tmp" "$logs/$n.$c.log"
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
[ "$rc" = 0 ] || exit "$rc"
# A block with admin_view runs the view's service (the stalwart template's
# admin-view).
if [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=portcullis-$provider" --filter label=com.docker.compose.service=admin-view 2>/dev/null)" ]; then
  hub_url="${HUB_API:-http://$(docker inspect -f '{{(index .NetworkSettings.Networks "portcullis").IPAddress}}' "$(docker compose ps -q hub)"):8888}"
  secret="$(grep '^HUB_PROXY_SECRET=' .env | cut -d= -f2-)"
  [ -z "${GITHUB_ACTIONS:-}" ] || echo "::add-mask::$secret"
  for i in $(seq 1 150); do
    curl -s --max-time 30 -H @<(printf 'X-Portcullis-Proxy-Secret: %s\nX-Forwarded-User: admin\n' "$secret") \
      "$hub_url/api/instances/$provider/op" > "$logs/op.json" || true
    jq -e '.op == "restart" and (.running | not)' "$logs/op.json" >/dev/null 2>&1 && break
    [ "$i" -eq 150 ] && { echo "FAIL: $provider's restart for its first mail key never ended: $(head -c 600 "$logs/op.json")"; exit 1; }
    sleep 2
  done
  jq -e '.ok == true' "$logs/op.json" >/dev/null || { echo "FAIL: $provider's restart for its first mail key failed: $(head -c 600 "$logs/op.json")"; exit 1; }
  echo "PASS: the first mail key restarted $provider (its admin view pins the key)"
fi
exit 0
