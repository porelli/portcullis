#!/usr/bin/env bash
#
# Prints every unqualified image name (one "file:line: ref" per line) in the
# Dockerfiles' FROM lines and the compose files' image: lines; exit 1 when
# there is one. Qualified = the first path component is a registry host
# (has a "." or ":", or is localhost): docker.io/library/alpine:…, not
# alpine:…. Exempt: locally built images (portcullis-*), ${VAR:-…}
# defaults (HUB_IMAGE / KEYCLOAK_IMAGE: ghcr.io), FROM <earlier stage>.
# Used by CI unit-tests and tests/test_cli.sh. Run from anywhere.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
bad=0
qualified() {
  case "$1" in portcullis-*|'${'*) return 0 ;; esac
  case "$1" in */*) ;; *) return 1 ;; esac
  case "${1%%/*}" in *.*|*:*|localhost) return 0 ;; esac
  return 1
}
for f in */Dockerfile "$@"; do
  [ -f "$f" ] || continue
  stages=" "
  while IFS=: read -r n line; do
    # shellcheck disable=SC2086
    set -- $line
    ref="${2:-}"
    [ "${3:-}" = AS ] || [ "${3:-}" = as ] && stages+="${4:-} "
    case "$stages" in *" $ref "*) continue ;; esac
    qualified "$ref" || { echo "$f:$n: $ref"; bad=1; }
  done < <(grep -nE '^FROM[[:space:]]' "$f")
done
for f in docker-compose*.yml; do
  while IFS=: read -r n line; do
    ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*image:[[:space:]]*//; s/[[:space:]]+#.*$//; s/^"(.*)"$/\1/')"
    qualified "$ref" || { echo "$f:$n: $ref"; bad=1; }
  done < <(grep -nE '^[[:space:]]+image:[[:space:]]' "$f")
done
exit "$bad"
