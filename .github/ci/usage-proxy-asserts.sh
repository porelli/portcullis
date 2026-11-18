#!/usr/bin/env bash
# usage-proxy-asserts.sh <network> <container id> [podman]
#
# The Hub's Usage page reads through socket-proxy-hub with no flag change
# (integration contract §6 "Resource usage"): one-shot stats, the
# size=true inspect and the image inspect pass CONTAINERS / IMAGES, while
# SYSTEM (/system/df), ALLOW_TOP (/containers/<id>/top) and Podman's own
# /libpod/containers/stats stay denied. <network> is socket-proxy-hub's
# network, <container id> a running container of a project started
# through the proxy. A future proxy flag change breaks this check.
set -euo pipefail

net="$1" cid="$2" runtime="${3:-docker}"
img="$(docker inspect -f '{{.Image}}' "$cid")"
cli=docker.io/library/docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb
base=http://socket-proxy-hub:2375

# hp <url>: the body on stdout, the status line(s) on stderr (wget -S).
hp() { docker run --rm --network "$net" --entrypoint wget "$cli" -q -O - -S "$@"; }
code() { hp "$@" 2>&1 >/dev/null | grep -o 'HTTP/[0-9.]* [0-9]*' | tail -n1 | cut -d' ' -f2; }

body="$(hp "$base/containers/$cid/stats?stream=false&one-shot=true" 2>/dev/null)" || { echo "FAIL: stats through socket-proxy-hub"; exit 1; }
grep -q '"memory_stats"' <<<"$body" || { echo "FAIL: the stats answer has no memory_stats"; exit 1; }
body="$(hp "$base/containers/$cid/json?size=true" 2>/dev/null)" || { echo "FAIL: inspect size=true through socket-proxy-hub"; exit 1; }
if [ "$runtime" != podman ]; then
  grep -q '"SizeRw"' <<<"$body" || { echo "FAIL: the size=true inspect has no SizeRw"; exit 1; }
fi
[ "$(code "$base/images/$img/json")" = 200 ] || { echo "FAIL: image inspect through socket-proxy-hub"; exit 1; }
for denied in /system/df "/containers/$cid/top" /libpod/containers/stats; do
  [ "$(code "$base$denied")" = 403 ] || { echo "FAIL: socket-proxy-hub allowed $denied"; exit 1; }
done
echo "PASS: stats and size through CONTAINERS; system/df, top and libpod stats stay denied"
