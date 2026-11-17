#!/usr/bin/env bash
# lint_builder_cache.sh <workflow.yml>… — a job that can run on the
# self-hosted dev builder (its runs-on names `inputs.runner == 'builder'`)
# must never write GitHub's shared Actions cache from there: GitHub-hosted
# runs restore it. Every cache-writing step of such a job carries the guard
#   !(github.event_name == 'workflow_dispatch' && inputs.runner == 'builder')
# or writes only on a push (`github.event_name == 'push' && …`, never the
# builder: it takes workflow_dispatch runs only):
#   actions/setup-go|node|python   with.cache false or guarded (absent = on)
#   actions/cache, actions/cache/save   if: guarded
#   docker/build-push-action       with.cache-to empty or guarded
#   ./.github/actions/cached-images   with.save false or guarded
# Restores are fine. Byte copies: core tests/lint_builder_cache.sh and
# porelli/portcullis-hub .github/lint_builder_cache.sh (keep them equal).
set -euo pipefail
[ $# -gt 0 ] || { echo "usage: $0 <workflow.yml>…" >&2; exit 2; }
rc=0
for wf in "$@"; do
  out="$(yq -o json '.' "$wf" | jq -r '
    def guard: "!(github.event_name == '"'"'workflow_dispatch'"'"' && inputs.runner == '"'"'builder'"'"')";
    def ok: (tostring) as $s | ($s | contains(guard))
      or ($s | test("^(\\$\\{\\{\\s*)?github\\.event_name == '"'"'push'"'"' && "));
    .jobs | to_entries[] | select((.value["runs-on"] | tostring) | contains("inputs.runner == '"'"'builder'"'"'"))
    | .key as $job | (.value.steps // []) | to_entries[] | .key as $i | .value as $s | ($s.uses // "") as $u
    | (if ($u | test("^actions/setup-(go|node|python)@")) then
         (if ($s.with.cache == false or $s.with.cache == "false" or (($s.with.cache // null) != null and ($s.with.cache | ok))) then empty
          else "\($job) step \($i + 1) (\($s.name // $u)): \($u | split("@")[0]) caches unless with.cache is false or guarded" end)
       elif ($u | test("^actions/cache(/save)?@")) then
         (if (($s.if // null) != null and ($s.if | ok)) then empty
          else "\($job) step \($i + 1) (\($s.name // $u)): \($u | split("@")[0]) without the builder guard in if:" end)
       elif ($u | test("^docker/build-push-action@")) then
         (if ((($s.with["cache-to"] // "") | tostring) == "" or ($s.with["cache-to"] | ok)) then empty
          else "\($job) step \($i + 1) (\($s.name // $u)): cache-to without the builder guard" end)
       elif $u == "./.github/actions/cached-images" then
         (if ((($s.with.save // "false") | tostring) == "false" or ($s.with.save | ok)) then empty
          else "\($job) step \($i + 1) (\($s.name // $u)): save without the builder guard" end)
       else empty end)')"
  if [ -n "$out" ]; then
    echo "FAIL: $wf: a builder-switchable job writes the shared Actions cache:"; echo "$out" | sed 's/^/  /'; rc=1
  else
    echo "ok: $wf (no Actions cache write from the builder)"
  fi
done
exit "$rc"
