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
# And the other compose options Podman's compat API treats differently:
#   - a tmpfs option outside size / mode / ro / rw / noexec / nosuid / nodev
#     (uid= / gid=: "unknown mount option" at create);
#   - bind propagation, volume nocopy, volume / network driver_opts, sysctls.
# Also scans the compose overrides written inline in the workflows for an
# exec-form test with a spaced argument. Used by CI unit-tests and
# tests/test_cli.sh.
set -uo pipefail
env_file="$(cd "$(dirname "${1:?usage: lint_healthchecks.sh <env-file> [file set...]}")" && pwd)/$(basename "$1")"
shift
cd "$(dirname "$0")/.." || exit 2
sets=("docker-compose.yml" "docker-compose.yml -f docker-compose.podman.yml -f docker-compose.podman-selinux.yml"
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
  out2="$(printf '%s' "$cfg" | jq -r --arg f "$files" '
      def tmpfs_ok: ["size", "mode", "ro", "rw", "noexec", "nosuid", "nodev"] as $ok
        | (split(":")[1:] | join(":") | split(",") | map(select(. != "") | split("=")[0])) as $o | all($o[]; . as $x | $ok | index($x));
      (.services | to_entries[] | .key as $s | .value
        | ((.tmpfs // []) | if type == "string" then [.] else . end | .[] | select(tmpfs_ok | not)
             | "\($f): \($s): tmpfs \(.) has an option Podman refuses (only size / mode / ro / rw / noexec / nosuid / nodev)"),
          ((.volumes // [])[] | select(.type == "tmpfs") | (.tmpfs // {}) | keys[] | select(. != "size" and . != "mode")
             | "\($f): \($s): a tmpfs volume option \(.) (only size / mode)"),
          ((.volumes // [])[] | select(.bind.propagation != null) | "\($f): \($s): bind propagation on \(.target)"),
          ((.volumes // [])[] | select(.volume.nocopy != null) | "\($f): \($s): volume nocopy on \(.target)"),
          (select(.sysctls != null) | "\($f): \($s): sysctls")),
      ((.volumes // {}) | to_entries[] | select(.value.driver_opts != null) | "\($f): volume \(.key): driver_opts"),
      ((.networks // {}) | to_entries[] | select(.value.driver_opts != null) | "\($f): network \(.key): driver_opts")')"
  [ -z "$out2" ] || { echo "$out2"; bad=1; }
done
inline=""
while IFS= read -r hit; do
  arr="$(printf '%s' "${hit#*:*:}" | sed -E 's/^[^[]*//')"
  printf '%s' "$arr" | jq -e '.[0] == "CMD" and any(.[1:][]; test("\\s"))' >/dev/null 2>&1 && inline+="${hit%%:*}:$(printf '%s' "$hit" | cut -d: -f2)"$'\n'
done < <(grep -HnE '^[[:space:]]*test:[[:space:]]*\[' .github/workflows/*.yml .github/ci/*.sh 2>/dev/null)
[ -z "$inline" ] || { echo "a workflow's inline compose override has a CMD healthcheck argument with whitespace:"; printf '%s' "$inline"; bad=1; }
exit "$bad"
