#!/usr/bin/env bash
# Dependabot auto-merge. Run by .github/workflows/dependabot-automerge.yml
# (workflow_run after the required workflows, or dispatched with a PR number).
# The same file lives in porelli/portcullis, portcullis-hub and
# portcullis-templates; keep the copies identical. Tests: .github/automerge/test.sh.
#
# It never checks out or runs PR code: every fact comes from the GitHub API.
#
#   decide    read the PR, its head commit and the required workflow runs and
#             print one JSON decision (also written to $GITHUB_OUTPUT)
#   pr        act on the PR (merge / label major / close pre-release);
#             needs contents: write + pull-requests: write
#   issue     open, update or close the `update-failed` issue; issues: write
#   dispatch  start the post-merge workflows on the base branch (a merge made
#             with GITHUB_TOKEN starts no push workflows), skipping any that
#             is already queued or running there; actions: write
#   classify FROM TO [docker]   print the update type (tests)
#   prerelease VERSION          exit 0 if VERSION is a pre-release (tests)
#
# Rules (user-approved, see portcullis-hub docs/superpowers/specs/
# 2026-11-02-app-updates-design.md, Calls 6-8):
#   - only PRs opened by dependabot[bot] from this repo, one commit, signed,
#     authored by Dependabot, head SHA = the SHA the required workflows tested;
#   - pre-releases (alpha/beta/rc/dev/..., PEP 440 a1/b2/rc3, Go
#     pseudo-versions) are closed with a comment, unless the dependency is
#     already on one (then it's left open like a major);
#   - patch, minor and digest-only updates merge once EVERY required workflow
#     succeeded on the head SHA (`gh pr merge --squash --match-head-commit`);
#   - majors (and anything whose type can't be derived) are labelled
#     `major-update` and left open;
#   - red: the PR stays open and one issue per app + version jump (label
#     `update-failed`) gets the failing jobs and run links.
#
# Env: REPO (owner/name), BASE_BRANCH (default main), and
#   decide:   RUN_ID (triggering workflow run) or PR (number);
#             REQUIRED_WORKFLOWS (workflow file paths, space/newline separated)
#   pr/issue/dispatch: DECISION (decide's JSON)
#   dispatch: POST_MERGE_WORKFLOWS (lines "file.yml [input=value ...]"; the
#             value {apps} becomes the PR's top-level dirs, the input is
#             dropped when one of them isn't an app id)
set -euo pipefail

BOT='dependabot[bot]'
BASE_BRANCH=${BASE_BRANCH:-main}
MAJOR_LABEL=major-update
FAILED_LABEL=update-failed

die() { echo "::error::$*" >&2; exit 1; }

# jq helpers shared by decide and the test entry points.
# shellcheck disable=SC2016  # jq program, not shell
JQ_LIB='
def rank: {"digest":0,"patch":1,"minor":2,"major":3,"unknown":4}[.];
def unrank: ["digest","patch","minor","major","unknown"][.];
def prerelease:
  test("(^|[^a-z])(alpha|beta|rc|dev|preview|pre|nightly|snapshot|canary|unstable|insiders)([^a-z]|$)"; "i")
  or test("[0-9](a|b|rc)[0-9]+([^a-z0-9]|$)"; "i")
  or test("[-.][0-9]{14}-[0-9a-f]{12}$");
def ver: ltrimstr("v") | (capture("^(?<num>[0-9]+(?:\\.[0-9]+)*)(?<rest>.*)$") // null);
# Update type of one from -> to jump. Digest-only = same tag (Dependabot then
# shows the short digests); any change of the tag flavour (alpine -> bookworm)
# or a downgrade = unknown.
def classify($from; $to; $docker):
  if $from == $to then (if $docker then "digest" else "unknown" end)
  elif $docker and ($from|test("^[0-9a-f]{7,64}$")) and ($to|test("^[0-9a-f]{7,64}$")) then "digest"
  else ($from|ver) as $f | ($to|ver) as $t
    | if $f == null or $t == null then "unknown"
      elif ($f.rest|gsub("[0-9.]";"")) != ($t.rest|gsub("[0-9.]";"")) then "unknown"
      else ($f.num|split(".")|map(tonumber)) as $a | ($t.num|split(".")|map(tonumber)) as $b
        | if $b[0] != $a[0] then (if $b[0] > $a[0] then "major" else "unknown" end)
          elif ($b[1] // 0) != ($a[1] // 0) then (if ($b[1] // 0) > ($a[1] // 0) then "minor" else "unknown" end)
          elif $b > $a then "patch"
          elif $b == $a and $t.rest != $f.rest then "patch"
          else "unknown" end
      end
  end;
def unq: gsub("^[\"'\'']|[\"'\'']$"; "");
def clean: gsub("^`"; "") | gsub("`?\\.?$"; "");
# Dependabot commit message: the updated-dependencies YAML block ...
def yaml_deps:
  split("\n") as $l
  | ([$l | to_entries[] | select(.value == "updated-dependencies:") | .key][0]) as $s
  | if $s == null then [] else
      ($l[$s+1:]) as $rest
      | ([$rest | to_entries[] | select(.value == "...") | .key][0] // ($rest|length)) as $e
      | reduce $rest[:$e][] as $x ([];
          if ($x|test("^- dependency-name: ")) then . + [{name: ($x|sub("^- dependency-name: ";"")|unq)}]
          elif length > 0 and ($x|test("^  [a-z-]+: ")) then
            ($x|capture("^  (?<k>[a-z-]+): (?<v>.*)$")) as $kv | .[-1][$kv.k] = ($kv.v|unq)
          else . end)
    end;
# ... and its prose ("Bumps [x](url) from A to B.", "Updates `x` from A to B").
def jumps:
  [scan("(?:Updates `([^`]+)`|Bumps \\[([^\\]]+)\\]\\([^)]*\\)|Bumps ([^ \\[`]+)) from (\\S+) to (\\S+)")
   | {name: (.[0] // .[1] // .[2]), from: (.[3]|clean), to: (.[4]|clean)}] | unique;
'

# Mapped by the tests' fake gh; everything goes through `gh api` except the
# merge itself.
api() { gh api "$@"; }
uri() { jq -rn --arg v "$1" '$v|@uri'; }

decision_out() { # json
  local d=$1
  echo "$d"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
      echo "action=$(jq -r .action <<<"$d")"
      echo "issue=$(jq -r .issue <<<"$d")"
      echo "decision=$(jq -c . <<<"$d")"
    } >> "$GITHUB_OUTPUT"
  fi
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    jq -r '"### Dependabot auto-merge: \(.action)\n\n\(.reason)\n\n" + (if .pr then "PR #\(.pr) at `\(.sha)`, app `\(.app // "")`, update type `\(.update_type // "")`, CI \(.ci // "n/a")\n" else "" end)' <<<"$d" >> "$GITHUB_STEP_SUMMARY"
  fi
}

# A no-op decision. Security refusals are warnings; benign skips notices.
skip() { # action reason [pr sha]
  local level=notice
  [ "$1" = refuse ] && level=warning
  echo "::$level title=Dependabot auto-merge::$2" >&2
  decision_out "$(jq -nc --arg a "$1" --arg r "$2" --arg pr "${3:-}" --arg sha "${4:-}" \
    '{action: $a, issue: "none", reason: $r, pr: (if $pr == "" then null else ($pr|tonumber) end), sha: (if $sha == "" then null else $sha end)}')"
  exit 0
}

decide() {
  : "${REPO:?}" "${REQUIRED_WORKFLOWS:?}"
  local run sha branch pr_json pr commit msg files runs
  if [ -n "${RUN_ID:-}" ]; then
    [[ $RUN_ID =~ ^[0-9]+$ ]] || die "RUN_ID must be a number"
    run=$(api "repos/$REPO/actions/runs/$RUN_ID")
    local event head_repo
    event=$(jq -r .event <<<"$run")
    head_repo=$(jq -r '.head_repository.full_name // ""' <<<"$run")
    [ "$event" = pull_request ] || skip refuse "run $RUN_ID is a $event run, not pull_request"
    [ "$head_repo" = "$REPO" ] || skip refuse "run $RUN_ID tested $head_repo, not $REPO (fork)"
    sha=$(jq -r .head_sha <<<"$run")
    branch=$(jq -r .head_branch <<<"$run")
    pr_json=$(api "repos/$REPO/pulls?state=open&head=$(uri "${REPO%%/*}:$branch")&per_page=10" | jq -c '.[0] // empty')
    [ -n "$pr_json" ] || skip none "no open PR from $branch (merged, closed, or not a PR run)"
    # The list omits fields (commits, ...): read the PR itself.
    pr_json=$(api "repos/$REPO/pulls/$(jq -r .number <<<"$pr_json")")
    [ "$(jq -r .head.sha <<<"$pr_json")" = "$sha" ] \
      || skip refuse "run $RUN_ID tested $sha but PR #$(jq -r .number <<<"$pr_json") head is $(jq -r .head.sha <<<"$pr_json") (stale run or new commits)" "$(jq -r .number <<<"$pr_json")" "$sha"
  elif [ -n "${PR:-}" ]; then
    [[ $PR =~ ^[0-9]+$ ]] || die "PR must be a number"
    pr_json=$(api "repos/$REPO/pulls/$PR")
    sha=$(jq -r .head.sha <<<"$pr_json")
    branch=$(jq -r .head.ref <<<"$pr_json")
  else
    die "set RUN_ID or PR"
  fi
  pr=$(jq -r .number <<<"$pr_json")

  # ── Who and what: only Dependabot's own, single, signed commit ──
  local got
  [ "$(jq -r .state <<<"$pr_json")" = open ] || skip none "PR #$pr is $(jq -r .state <<<"$pr_json")" "$pr" "$sha"
  got=$(jq -r .user.login <<<"$pr_json")
  [ "$got" = "$BOT" ] || skip refuse "PR #$pr was opened by $got, not $BOT" "$pr" "$sha"
  got=$(jq -r '.head.repo.full_name // "(deleted fork)"' <<<"$pr_json")
  [ "$got" = "$REPO" ] || skip refuse "PR #$pr comes from $got, not $REPO (fork)" "$pr" "$sha"
  got=$(jq -r '"\(.base.repo.full_name):\(.base.ref)"' <<<"$pr_json")
  [ "$got" = "$REPO:$BASE_BRANCH" ] || skip refuse "PR #$pr targets $got, not $REPO:$BASE_BRANCH" "$pr" "$sha"
  [ "$(jq -r .draft <<<"$pr_json")" != true ] || skip none "PR #$pr is a draft" "$pr" "$sha"
  [[ $branch == dependabot/* ]] || skip refuse "PR #$pr branch $branch is not dependabot/*" "$pr" "$sha"
  got=$(jq -r .commits <<<"$pr_json")
  [ "$got" = 1 ] || skip refuse "PR #$pr has $got commits (someone pushed to Dependabot's branch)" "$pr" "$sha"
  commit=$(api "repos/$REPO/commits/$sha")
  got=$(jq -r '"\(.author.login // "?")/\(.commit.verification.verified)"' <<<"$commit")
  [ "$got" = "$BOT/true" ] || skip refuse "PR #$pr head $sha is not a signed $BOT commit ($got)" "$pr" "$sha"
  msg=$(jq -r .commit.message <<<"$commit")

  # ── What changed: dependencies, jumps, update type, app ──
  local docker=false deps
  [[ $branch == dependabot/docker* ]] && docker=true
  deps=$(jq -Rsc --argjson docker "$docker" "$JQ_LIB"'
    . as $msg | ($msg|yaml_deps) as $y | ($msg|jumps) as $j
    | (if ($y|length) > 0 then $y else [$j[] | {name}] | unique end)
    | map(. as $d | [$j[] | select(.name == $d.name)] as $m
        | if ($m|length) == 0 then [$d + {from: null, to: ($d["dependency-version"] // null), type: "unknown"}]
          else [$m[] | $d + {from, to}
                | .type = ([classify(.from; .to; $docker),
                            ((.["update-type"] // "") | sub("^version-update:semver-"; "") | select(. != ""))]
                           | map(rank) | max | unrank)]
          end)
    | flatten
    # A pre-release target is closed, unless the dependency already was on a
    # pre-release (e.g. a Go pseudo-version pinned on purpose): then it is
    # left to a human (type unknown = handled like a major).
    | map(.from_prerelease = ((.from // "") | prerelease))
    | map(. as $d | ((($d.to // "") | prerelease) or (($d["dependency-version"] // "") | prerelease)) as $p
        | .prerelease = ($p and ($d.from_prerelease | not))
        | if $p and $d.from_prerelease then .type = "unknown" else . end
        | del(.from_prerelease))' <<<"$msg")
  [ "$(jq length <<<"$deps")" -gt 0 ] || deps='[{"name":"(unparsed)","from":null,"to":null,"type":"unknown","prerelease":false}]'

  files=$(api --paginate "repos/$REPO/pulls/$pr/files?per_page=100" | jq -sc 'add // []')
  local app
  app=$(jq -r '[.[].filename | if test("/") then split("/")[0] else "(root)" end] | unique | join(",")' <<<"$files")

  # ── CI: every required workflow, latest run for this exact SHA ──
  runs=$(api "repos/$REPO/actions/runs?head_sha=$sha&event=pull_request&per_page=100")
  local ci
  ci=$(jq -c --arg sha "$sha" --arg repo "$REPO" --arg req "$REQUIRED_WORKFLOWS" '
    [.workflow_runs[] | select(.head_sha == $sha and .head_repository.full_name == $repo)] as $rs
    | [$req | splits("[ \n]+") | select(length > 0)] as $wfs
    | [$wfs[] as $wf
       | ([$rs[] | select((.path|sub("@.*$";"")) == $wf)] | max_by(.id)) as $r
       | {workflow: $wf, id: ($r.id // null), name: ($r.name // $wf), url: ($r.html_url // null),
          state: (if $r == null then "missing"
                  elif $r.status != "completed" then "pending"
                  elif $r.conclusion == "success" then "success"
                  elif ($r.conclusion | IN("failure","timed_out","startup_failure")) then "failure"
                  else "pending" end),
          conclusion: ($r.conclusion // $r.status // "missing")}]
    | {runs: ., status: (if any(.state == "failure") then "red"
                         elif all(.state == "success") then "green" else "pending" end)}' <<<"$runs")

  local failures='[]' id
  if [ "$(jq -r .status <<<"$ci")" = red ]; then
    for id in $(jq -r '.runs[] | select(.state == "failure") | .id' <<<"$ci"); do
      failures=$(jq -c --argjson f "$failures" --argjson r "$(jq -c --argjson id "$id" '.runs[] | select(.id == $id)' <<<"$ci")" \
        '$f + [$r + {jobs: [.jobs[] | select(.conclusion | IN("failure","timed_out","startup_failure")) | {name, url: .html_url}]}]' \
        <<<"$(api "repos/$REPO/actions/runs/$id/jobs?per_page=100")")
    done
  fi

  # ── Decision ──
  local d
  d=$(jq -nc --argjson pr "$pr_json" --arg sha "$sha" --arg branch "$branch" --arg app "$app" \
    --argjson deps "$deps" --argjson ci "$ci" --argjson failures "$failures" "$JQ_LIB"'
    ($deps | map(.type|rank) | max | unrank) as $type
    | ($ci.status) as $st
    | ($deps | map("\(.name) \(.from // "?") → \(.to // "?")") | join(", ")) as $jump
    | {pr: $pr.number, sha: $sha, branch: $branch, title: $pr.title, url: $pr.html_url,
       labels: [$pr.labels[]?.name], app: $app, update_type: $type, deps: $deps, ci: $st,
       runs: $ci.runs, failures: $failures, jump: $jump,
       issue_title: "Update failed: \($app): \($jump)"}
    | if any($deps[]; .prerelease) then
        .action = "prerelease" | .issue = "none"
        | .reason = "pre-release (\([$deps[] | select(.prerelease) | .to] | join(", "))): closed, Portcullis tracks stable releases only"
      elif ($type | IN("major","unknown")) then
        .action = "major" | .issue = (if $st == "red" then "open" else "none" end)
        | .reason = (if $type == "major" then "major update" else "update type unknown" end) + ": labelled `major-update`, left open; CI \($st)"
      elif $st == "green" then
        .action = "merge" | .issue = "close" | .reason = "\($type) update, every required workflow passed on \($sha): merging"
      elif $st == "red" then
        .action = "report" | .issue = "open" | .reason = "\($type) update, CI red: PR left open, `update-failed` issue opened/updated"
      else
        .action = "none" | .issue = "none"
        | .reason = "\($type) update, waiting for: \([$ci.runs[] | select(.state != "success") | "\(.name) (\(.conclusion))"] | join(", "))"
      end') || die "decision failed"
  decision_out "$d"
}

need_decision() {
  : "${REPO:?}" "${DECISION:?}"
  jq -e '.pr and .sha' <<<"$DECISION" >/dev/null || die "DECISION has no PR"
}
field() { jq -r ".$1" <<<"$DECISION"; }

ensure_label() { # name color description
  api -X POST "repos/$REPO/labels" -f name="$1" -f color="$2" -f description="$3" >/dev/null 2>&1 || true
}

pr_act() {
  need_decision
  local pr sha branch
  pr=$(field pr) sha=$(field sha) branch=$(field branch)
  case "$(field action)" in
    merge)
      # --match-head-commit: GitHub refuses the merge if the head moved after
      # the tested SHA.
      gh pr merge "$pr" -R "$REPO" --squash --match-head-commit "$sha"
      [[ $branch == dependabot/* ]] && { api -X DELETE "repos/$REPO/git/refs/heads/$branch" >/dev/null 2>&1 || true; }
      echo "Merged #$pr at $sha"
      ;;
    major)
      if jq -e --arg l "$MAJOR_LABEL" '.labels | index($l)' <<<"$DECISION" >/dev/null; then
        echo "#$pr already labelled $MAJOR_LABEL"; return 0
      fi
      ensure_label "$MAJOR_LABEL" d93f0b "Major update: not auto-merged, needs an upgrade path and a manual merge"
      api -X POST "repos/$REPO/issues/$pr/labels" -f "labels[]=$MAJOR_LABEL" >/dev/null
      api -X POST "repos/$REPO/issues/$pr/comments" -F body=@- >/dev/null <<EOF
Not merged automatically: $(field reason).

$(field jump)

Majors are never auto-merged (no upgrade-path checks yet): review the upstream release notes and the template's upgrade notes, then merge by hand once CI is green.
EOF
      echo "Labelled #$pr $MAJOR_LABEL"
      ;;
    prerelease)
      api -X POST "repos/$REPO/issues/$pr/comments" -F body=@- >/dev/null <<EOF
Closing: $(field jump) is a pre-release. Portcullis only tracks stable releases; \`.github/dependabot.yml\` ignores pre-release versions and the auto-merge workflow closes any that get through.
EOF
      api -X PATCH "repos/$REPO/pulls/$pr" -f state=closed >/dev/null
      echo "Closed #$pr (pre-release)"
      ;;
    *) die "nothing to do on the PR for action $(field action)" ;;
  esac
}

issue_act() {
  need_decision
  local mode title num pr
  mode=$(field issue) title=$(field issue_title) pr=$(field pr)
  num=$(api "repos/$REPO/issues?state=open&labels=$FAILED_LABEL&per_page=100" \
    | jq -r --arg t "$title" '[.[] | select(.title == $t and (.pull_request | not))][0].number // empty')
  case "$mode" in
    open)
      local report links seen
      report=$(jq -r '
        "- App: `\(.app)`\n- Update: \(.jump) (\(.update_type))\n- PR: #\(.pr) (\(.title)), head `\(.sha)`\n"
        + ([.failures[] | "- Failed: **\(.name)** — \(.url)" + ([.jobs[] | "\n  - job `\(.name)`: \(.url)"] | join(""))] | join("\n"))' <<<"$DECISION")
      links=$(jq -r '.failures[].url' <<<"$DECISION")
      if [ -n "$num" ]; then
        seen=$(api "repos/$REPO/issues/$num" | jq -r .body; api --paginate "repos/$REPO/issues/$num/comments?per_page=100" | jq -r '.[].body')
        local l new=false
        for l in $links; do grep -qF "$l" <<<"$seen" || new=true; done
        if [ "$new" = false ]; then echo "Issue #$num already has these runs"; return 0; fi
        api -X POST "repos/$REPO/issues/$num/comments" -F body=@- >/dev/null <<<"Still failing:

$report"
        echo "Updated issue #$num"
      else
        ensure_label "$FAILED_LABEL" b60205 "A Dependabot update failed CI; its PR stays open"
        api -X POST "repos/$REPO/issues" -f title="$title" -f "labels[]=$FAILED_LABEL" -F body=@- >/dev/null <<<"A Dependabot update failed CI, so it was not merged; the PR stays open. Fix the template (or core) on main and Dependabot rebases the PR, or close the PR to skip this version.

$report

Opened by .github/workflows/dependabot-automerge.yml. Further failures of the same jump are added as comments; the issue is closed when the update merges."
        echo "Opened issue: $title"
      fi
      ;;
    close)
      [ -n "$num" ] || { echo "No open issue for this jump"; return 0; }
      api -X POST "repos/$REPO/issues/$num/comments" -f body="Fixed: #$pr passed CI and was merged at $(field sha)." >/dev/null
      api -X PATCH "repos/$REPO/issues/$num" -f state=closed -f state_reason=completed >/dev/null
      echo "Closed issue #$num"
      ;;
    none) echo "No issue change" ;;
    *) die "unknown issue mode $mode" ;;
  esac
}

busy() { # workflow file
  local s n=0
  for s in queued in_progress; do
    n=$((n + $(api "repos/$REPO/actions/workflows/$1/runs?branch=$BASE_BRANCH&status=$s&per_page=1" | jq '.total_count // 0' || echo 0)))
  done
  [ "$n" -gt 0 ]
}

dispatch_act() {
  need_decision
  [ "$(field action)" = merge ] || die "dispatch only follows a merge"
  local apps line wf rest args a
  apps=$(jq -r '.app | split(",") | if all(test("^[a-z0-9][a-z0-9_-]*$") and . != "tests") then join(" ") else "" end' <<<"$DECISION")
  while read -r line; do
    [ -n "$line" ] || continue
    read -r wf rest <<<"$line"
    args=()
    for a in ${rest:-}; do
      if [ "${a#*=}" = "{apps}" ]; then [ -n "$apps" ] && args+=(-f "${a%%=*}=$apps")
      else args+=(-f "$a"); fi
    done
    # Never start one while a run of it is queued or running on the branch:
    # the workflows' concurrency groups would cancel that run (e.g. a human
    # push's cache save or image publish). The merge was tested on the PR.
    if busy "$wf"; then echo "Skipped $wf: a run is already queued or in progress on $BASE_BRANCH"; continue; fi
    gh workflow run "$wf" -R "$REPO" --ref "$BASE_BRANCH" ${args[@]+"${args[@]}"}
    echo "Dispatched $wf on $BASE_BRANCH ${args[*]-}"
  done <<<"${POST_MERGE_WORKFLOWS:-}"
}

case "${1:-}" in
  decide) decide ;;
  pr) pr_act ;;
  issue) issue_act ;;
  dispatch) dispatch_act ;;
  classify) jq -rn --arg f "$2" --arg t "$3" --argjson d "$([ "${4:-}" = docker ] && echo true || echo false)" "$JQ_LIB"'classify($f; $t; $d)' ;;
  prerelease) jq -en --arg v "$2" "$JQ_LIB"'$v | prerelease' >/dev/null ;;
  *) echo "usage: $0 decide|pr|issue|dispatch|classify FROM TO [docker]|prerelease VERSION" >&2; exit 2 ;;
esac
