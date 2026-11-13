#!/usr/bin/env bash
#
# lint_healthchecks.sh <env-file> [<compose file set>...] — every healthcheck `test` in the core
# compose files (every profile, the apps and test files, the SELinux overlay)
# must behave the same on Docker and on Podman's compat API, which re-splits
# exec-form (CMD) arguments on whitespace (a `bash -c '<script>'` reached the
# container as `bash -c '{'`). Fails (exit 1, one line per problem) on:
#   - a CMD-form argument with whitespace (use one CMD-SHELL string);
#   - any element with a newline;
#   - a CMD-SHELL test that isn't exactly ["CMD-SHELL", "<one string>"].
# Also scans the compose overrides written inline in the workflows for an
# exec-form test with a spaced argument. Used by CI unit-tests and
# tests/test_cli.sh.
set -uo pipefail
env_file="$(cd "$(dirname "${1:?usage: lint_healthchecks.sh <env-file> [file set...]}")" && pwd)/$(basename "$1")"
shift
cd "$(dirname "$0")/.." || exit 2
sets=("docker-compose.yml" "docker-compose.yml -f docker-compose.podman-selinux.yml"
      "docker-compose.yml -f docker-compose.apps.yml" "docker-compose.test.yml")
[ "$#" -eq 0 ] || sets=("$@")
bad=0
for files in "${sets[@]}"; do
  # shellcheck disable=SC2086
  if ! cfg="$(env -u COMPOSE_FILE docker compose --env-file "$env_file" -f $files --profile '*' config --format json 2>&1)"; then
    echo "$files: docker compose config failed: $cfg"; bad=1; continue
  fi
  out="$(printf '%s' "$cfg" | jq -r --arg f "$files" '
      .services | to_entries[] | .key as $s | (.value.healthcheck.test // empty) as $t
      | if ($t | type) == "string" then
          (if ($t | test("\n")) then "\($f): \($s): the test has a newline" else empty end)
        else
          (if any($t[]; test("\n")) then "\($f): \($s): a test element has a newline" else empty end),
          (if $t[0] == "CMD" and any($t[1:][]; test("\\s")) then "\($f): \($s): a CMD argument has whitespace (Podman re-splits it): use one CMD-SHELL string" else empty end),
          (if $t[0] == "CMD-SHELL" and ($t | length) != 2 then "\($f): \($s): CMD-SHELL needs exactly one command string" else empty end)
        end')"
  [ -z "$out" ] || { echo "$out"; bad=1; }
done
inline="$(grep -HnE 'test: *\[ *"CMD" *,.*"[^"]*[[:space:]][^"]*"' .github/workflows/*.yml 2>/dev/null || true)"
[ -z "$inline" ] || { echo "a workflow's inline compose override has a CMD healthcheck argument with whitespace:"; echo "$inline"; bad=1; }
exit "$bad"
