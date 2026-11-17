#!/usr/bin/env bash
# usage-prometheus-labels.sh <app instance id>
#
# The Hub's usage metrics as Prometheus stores them (contract §16.2,
# FR-H1): a throwaway Prometheus with core's real prometheus.yml scrapes
# hub-metrics:9100 over portcullis-metrics-hub, so the scrape's own target
# labels (job, instance; honor_labels false) apply. Every hub-usage series
# keeps instance = the target and its app label; none was renamed to
# exported_*; the dashboard's per-app sums answer per app.
set -euo pipefail

app="$1"
net=portcullis_portcullis-metrics-hub
prom="$(docker compose -f docker-compose.yml --profile '*' config --format json | jq -r .services.prometheus.image)"
bb=docker.io/library/busybox:1.38.0-musl@sha256:80e38f9a1b39188b8bdb28879178edb322a4402b081a9aedda1924609decd6f6
name="usage-prom-$$"

docker run -d --rm --name "$name" --network "$net" -v "$PWD/monitoring/prometheus:/etc/prometheus:ro" "$prom" \
  --config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/prometheus >/dev/null
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT

# q <promql>: the query's result array (JSON).
q() {
  local enc
  enc="$(jq -rn --arg q "$1" '$q|@uri')"
  docker run --rm --network "$net" "$bb" wget -q -T 10 -O - "http://$name:9090/api/v1/query?query=$enc" | jq -c .data.result
}

series="portcullis_container_memory_working_set_bytes{job=\"hub-usage\",app=\"$app\"}"
for i in $(seq 1 40); do
  [ "$(q "$series" 2>/dev/null | jq length 2>/dev/null || echo 0)" -gt 0 ] && break
  [ "$i" -eq 40 ] && { echo "FAIL: Prometheus has no $series"; docker logs --tail=40 "$name"; exit 1; }
  sleep 5
done
bad="$(q "$series" | jq -r '.[] | select(.metric.instance != "hub-metrics:9100") | .metric | tostring')"
[ -z "$bad" ] || { echo "FAIL: a hub-usage series' instance isn't the target: $bad"; exit 1; }
[ "$(q '{job="hub-usage",exported_instance!=""}' | jq length)" -eq 0 ] || { echo "FAIL: a hub-usage label clashed with a target label (exported_instance)"; exit 1; }
[ "$(q '{job="hub-usage",exported_job!=""}' | jq length)" -eq 0 ] || { echo "FAIL: a hub-usage label clashed with a target label (exported_job)"; exit 1; }
apps="$(q 'sum by (app) (portcullis_container_memory_working_set_bytes)' | jq -r '[.[].metric.app] | sort | join(",")')"
for want in "$app" core; do
  grep -qx "$want" <<<"${apps//,/$'\n'}" || { echo "FAIL: the dashboard's per-app sum gave [$apps], no $want"; exit 1; }
done
echo "PASS: Prometheus keeps app=$app with instance=hub-metrics:9100 (per-app sums: $apps)"
