#!/usr/bin/env bash
# Tests for automerge.sh with a fake `gh` serving API fixtures (no network).
# Run: bash .github/automerge/test.sh
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=$HERE/automerge.sh
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

export REPO=porelli/portcullis-templates
export REQUIRED_WORKFLOWS=".github/workflows/lint.yml .github/workflows/test-apps.yml"
export FIX=$WORK/fix GH_LOG=$WORK/gh.log
unset GITHUB_OUTPUT GITHUB_STEP_SUMMARY RUN_ID PR DECISION || true
SHA=1111111111111111111111111111111111111111
OTHER_SHA=2222222222222222222222222222222222222222

# ── fake gh: GET endpoints from $FIX/<key>.json, everything else logged ──
mkdir -p "$WORK/bin"
cat > "$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >> "$GH_LOG"
for a in "$@"; do [ "$a" = body=@- ] && { cat >> "$GH_LOG"; echo >> "$GH_LOG"; }; done
[ "$1" = api ] || exit 0
shift; method=GET ep=
while [ $# -gt 0 ]; do
  case $1 in
    -X|--method) method=$2; shift 2 ;;
    -f|-F) shift 2 ;;
    --paginate) shift ;;
    *) ep=$1; shift ;;
  esac
done
[ "$method" = GET ] || { echo '{}'; exit 0; }
key=$(printf %s "${ep#repos/*/*/}" | tr '/?&=:%' '______')
if [ -f "$FIX/$key.json" ]; then cat "$FIX/$key.json"; else echo "gh: Not Found (HTTP 404) $ep" >&2; exit 1; fi
EOF
chmod +x "$WORK/bin/gh"
export PATH="$WORK/bin:$PATH"

put() { # endpoint json
  local key
  key=$(printf %s "${1#repos/*/*/}" | tr '/?&=:%' '______')
  printf '%s\n' "$2" > "$FIX/$key.json"
}
enc() { jq -rn --arg v "$1" '$v|@uri'; }

# ── a case: defaults below, override the variables before calling setup ──
defaults() {
  NUM=4 BRANCH=dependabot/docker_compose/matrix/element-hq/synapse-v1.164.2
  AUTHOR='dependabot[bot]' HEAD_REPO=$REPO RUN_REPO=$REPO RUN_EVENT=pull_request
  PR_SHA=$SHA RUN_SHA=$SHA COMMITS=1 COMMIT_AUTHOR='dependabot[bot]' VERIFIED=true
  LINT=success TEST=success TEST_STATUS=completed LABELS='[]'
  FILES='["matrix/compose.yml"]' ISSUES='[]'
  MSG='templates: bump element-hq/synapse from v1.164.1 to v1.164.2 in /matrix

Bumps [element-hq/synapse](https://github.com/element-hq/synapse) from v1.164.1 to v1.164.2.
- [Release notes](https://github.com/element-hq/synapse/releases)

---
updated-dependencies:
- dependency-name: element-hq/synapse
  dependency-version: v1.164.2
  dependency-type: direct:production
...

Signed-off-by: dependabot[bot] <support@github.com>'
}
setup() {
  rm -rf "$FIX"; mkdir -p "$FIX"; : > "$GH_LOG"
  put "repos/$REPO/actions/runs/900" "$(jq -n --arg e "$RUN_EVENT" --arg r "$RUN_REPO" --arg s "$RUN_SHA" --arg b "$BRANCH" \
    '{id: 900, event: $e, head_repository: {full_name: $r}, head_sha: $s, head_branch: $b}')"
  local pr
  pr=$(jq -n --argjson n "$NUM" --arg u "$AUTHOR" --arg hr "$HEAD_REPO" --arg s "$PR_SHA" --arg b "$BRANCH" \
    --argjson c "$COMMITS" --argjson l "$LABELS" --arg repo "$REPO" \
    '{number: $n, state: "open", draft: false, title: "templates: bump something", html_url: "https://github.com/\($repo)/pull/\($n)",
      user: {login: $u}, head: {sha: $s, ref: $b, repo: {full_name: $hr}}, base: {ref: "main", repo: {full_name: $repo}},
      commits: $c, labels: ($l | map({name: .}))}')
  put "repos/$REPO/pulls/$NUM" "$pr"
  put "repos/$REPO/pulls?state=open&head=$(enc "${REPO%%/*}:$BRANCH")&per_page=10" "[$pr]"
  put "repos/$REPO/commits/$PR_SHA" "$(jq -n --arg a "$COMMIT_AUTHOR" --argjson v "$VERIFIED" --arg m "$MSG" \
    '{author: {login: $a}, commit: {message: $m, verification: {verified: $v}}}')"
  put "repos/$REPO/pulls/$NUM/files?per_page=100" "$(jq -c 'map({filename: .})' <<<"$FILES")"
  put "repos/$REPO/actions/runs?head_sha=$PR_SHA&event=pull_request&per_page=100" "$(jq -n --arg s "$PR_SHA" --arg repo "$REPO" \
    --arg lint "$LINT" --arg test "$TEST" --arg ts "$TEST_STATUS" '
    def run($id; $name; $path; $st; $c): {id: $id, name: $name, path: $path, head_sha: $s, status: $st,
      conclusion: (if $st == "completed" then $c else null end), head_repository: {full_name: $repo},
      html_url: "https://github.com/\($repo)/actions/runs/\($id)"};
    {workflow_runs: [
      run(10; "Lint"; ".github/workflows/lint.yml"; "completed"; "failure"),
      run(11; "Lint"; ".github/workflows/lint.yml"; "completed"; $lint),
      run(20; "Test Apps"; ".github/workflows/test-apps.yml"; $ts; $test),
      run(30; "Notify docs"; ".github/workflows/docs-dispatch.yml"; "completed"; "failure")]}')"
  put "repos/$REPO/actions/runs/20/jobs?per_page=100" "$(jq -n --arg repo "$REPO" \
    '{jobs: [{name: "gate", conclusion: "success", html_url: "u1"},
             {name: "test (matrix)", conclusion: "failure", html_url: "https://github.com/\($repo)/actions/runs/20/job/7"}]}')"
  put "repos/$REPO/actions/runs/11/jobs?per_page=100" '{"jobs":[{"name":"lint","conclusion":"failure","html_url":"https://x/lintjob"}]}'
  put "repos/$REPO/issues?state=open&labels=update-failed&per_page=100" "$ISSUES"
}

PASS=0 FAILN=0
ok() { PASS=$((PASS + 1)); echo "ok   $1"; }
bad() { FAILN=$((FAILN + 1)); echo "FAIL $1"; [ -z "${2:-}" ] || echo "     $2"; }
expect() { # description jq-filter (on $OUT)
  if jq -e "$2" <<<"$OUT" >/dev/null 2>&1; then ok "$1"; else bad "$1" "$(jq -c '{action, issue, reason, update_type, ci}' <<<"$OUT" 2>/dev/null || echo "$OUT")"; fi
}
logged() { # description grep-pattern
  if grep -qE -- "$2" "$GH_LOG"; then ok "$1"; else bad "$1" "log: $(tr '\n' '|' < "$GH_LOG")"; fi
}
not_logged() {
  if grep -qE -- "$2" "$GH_LOG"; then bad "$1" "log: $(tr '\n' '|' < "$GH_LOG")"; else ok "$1"; fi
}
decide() { OUT=$(RUN_ID=900 bash "$SCRIPT" decide 2>/dev/null); }
act() { DECISION=$OUT bash "$SCRIPT" "$1" >/dev/null 2>&1; }

echo "# classification"
while read -r from to docker want; do
  got=$(bash "$SCRIPT" classify "$from" "$to" "$docker")
  [ "$got" = "$want" ] && ok "classify $from -> $to ($docker) = $want" || bad "classify $from -> $to ($docker) = $want" "got $got"
done <<'EOF'
v1.164.1 v1.164.2 docker patch
v0.9.5-omnibus v0.10.0-omnibus docker minor
3.15.2-alpine3.24 3.15.3-alpine3.25 docker patch
17 18 docker major
26.2 27.0 none major
3.15.2-alpine 3.15.2-alpine docker digest
1830542 c098726 docker digest
1830542 c098726 none unknown
3.15.2-alpine 3.15.2-bookworm docker unknown
2.0 1.9 none unknown
latest stable docker unknown
0.30.0 0.31.0 none minor
EOF
for v in 3.16.0a1-alpine 3.16.0a1-alpine3.24 1.0.0-rc.1 18beta1 1.28rc1-alpine 1.0.0-dev v2.0.0-alpha.1 v1.2.4-0.20240101123456-abcdef123456; do
  bash "$SCRIPT" prerelease "$v" && ok "pre-release: $v" || bad "pre-release: $v"
done
for v in 3.15.2-alpine3.24 v0.10.0-omnibus 1.2.3-src v1.164.2 2024.10.1 latest-devel 1.27-alpine; do
  bash "$SCRIPT" prerelease "$v" && bad "stable: $v" || ok "stable: $v"
done

echo "# patch, green -> merge (squash, --match-head-commit), issue closed if one exists"
defaults
ISSUES='[{"number":77,"title":"Update failed: matrix: element-hq/synapse v1.164.1 → v1.164.2"},{"number":78,"title":"other"}]'
setup; decide
expect "action merge" '.action == "merge" and .update_type == "patch" and .ci == "green" and .issue == "close" and .app == "matrix"'
act pr
logged "merged with --match-head-commit" "^gh pr merge 4 -R $REPO --squash --match-head-commit $SHA$"
logged "branch deleted" "DELETE repos/$REPO/git/refs/heads/dependabot/docker_compose/matrix"
act issue
logged "issue 77 closed" "PATCH repos/$REPO/issues/77 -f state=closed"
not_logged "issue 78 untouched" "issues/78"
POST_MERGE_WORKFLOWS=$'lint.yml\ntest-apps.yml apps={apps}\ndocs-dispatch.yml' DECISION=$OUT bash "$SCRIPT" dispatch >/dev/null
logged "dispatched lint on main" "^gh workflow run lint.yml -R $REPO --ref main$"
logged "dispatched test-apps apps=matrix" "^gh workflow run test-apps.yml -R $REPO --ref main -f apps=matrix$"
logged "dispatched docs" "^gh workflow run docs-dispatch.yml"

echo "# minor, green -> merge"
defaults
MSG='templates: bump analogj/scrutiny in /scrutiny

Bumps [analogj/scrutiny](https://github.com/AnalogJ/scrutiny) from v0.9.5-omnibus to v0.10.0-omnibus.

---
updated-dependencies:
- dependency-name: analogj/scrutiny
  dependency-version: v0.10.0-omnibus
  dependency-type: direct:production
...'
FILES='["scrutiny/compose.yml"]'
setup; decide
expect "action merge (minor)" '.action == "merge" and .update_type == "minor"'

echo "# digest-only refresh, green -> merge"
defaults
MSG='templates: bump postgres in /gitea

Bumps postgres from `1830542` to `c098726`.

---
updated-dependencies:
- dependency-name: postgres
  dependency-version: 18.1-alpine
  dependency-type: direct:production
...'
setup; decide
expect "action merge (digest)" '.action == "merge" and .update_type == "digest"'

echo "# grouped patch (core-style message, metadata update-type) -> merge; tests dir -> dispatch all apps"
defaults
BRANCH=dependabot/docker/enroll/enroll-images-0123456789
FILES='["enroll/Dockerfile","tests/x"]'
MSG='build(deps): bump the enroll-images group

Bumps the enroll-images group with 2 updates in the /enroll directory: golang and alpine.

Updates `golang` from 1.27.3-alpine3.24 to 1.27.4-alpine3.24

Updates `alpine` from 3.24.3 to 3.24.4

---
updated-dependencies:
- dependency-name: golang
  dependency-version: 1.27.4-alpine3.24
  dependency-type: direct:production
  update-type: version-update:semver-patch
  dependency-group: enroll-images
- dependency-name: alpine
  dependency-version: 3.24.4
  dependency-type: direct:production
  update-type: version-update:semver-patch
  dependency-group: enroll-images
...'
setup; decide
expect "grouped: merge, 2 deps, app list" '.action == "merge" and .update_type == "patch" and (.deps|length) == 2 and .app == "enroll,tests"'
POST_MERGE_WORKFLOWS='test-apps.yml apps={apps}' DECISION=$OUT bash "$SCRIPT" dispatch >/dev/null
logged "non-app dir: dispatch without apps (= all)" "^gh workflow run test-apps.yml -R $REPO --ref main$"

echo "# metadata says major although the prose looks minor -> major wins"
defaults
MSG=${MSG/  dependency-type: direct:production/  dependency-type: direct:production
  update-type: version-update:semver-major}
setup; decide
expect "max(metadata, derived) = major" '.action == "major" and .update_type == "major"'

echo "# major -> label major-update + comment, never merged; red major also gets an issue"
defaults
MSG='templates: bump postgres from 17.6 to 18.1 in /gitea

Bumps postgres from 17.6 to 18.1.

---
updated-dependencies:
- dependency-name: postgres
  dependency-version: "18.1"
  dependency-type: direct:production
  update-type: version-update:semver-major
...'
FILES='["gitea/compose.yml"]'
setup; decide
expect "action major, no issue" '.action == "major" and .issue == "none" and .update_type == "major"'
act pr
logged "label added" "POST repos/$REPO/issues/4/labels -f labels\\[\\]=major-update"
logged "comment posted" "POST repos/$REPO/issues/4/comments"
not_logged "not merged" "pr merge"
LABELS='["major-update"]'; setup; decide; : > "$GH_LOG"; act pr
not_logged "already labelled: no second comment" "comments"
TEST=failure; setup; decide
expect "red major: label + issue" '.action == "major" and .issue == "open"'

echo "# unknown update type -> treated as major"
defaults
MSG='templates: bump foo in /x

Updates the requirements on [foo](https://x) to permit the latest version.

---
updated-dependencies:
- dependency-name: foo
  dependency-version: 2.0.0
...'
setup; decide
expect "unknown -> major" '.action == "major" and .update_type == "unknown"'

echo "# pre-release -> closed with a comment, whatever CI says"
defaults
BRANCH=dependabot/docker_compose/jellyfin/python-3.16.0a1-alpine NUM=2
MSG='templates: bump python in /jellyfin

Bumps python from 3.15.2-alpine to 3.16.0a1-alpine.

---
updated-dependencies:
- dependency-name: python
  dependency-version: 3.16.0a1-alpine
  dependency-type: direct:production
  update-type: version-update:semver-minor
...'
FILES='["jellyfin/compose.yml"]'
setup; decide
expect "action prerelease" '.action == "prerelease" and .issue == "none"'
act pr
logged "comment" "POST repos/$REPO/issues/2/comments"
logged "closed" "PATCH repos/$REPO/pulls/2 -f state=closed"
not_logged "not merged" "pr merge"

echo "# pre-release -> pre-release (already pinned to a pseudo-version): left to a human"
defaults
BRANCH=dependabot/go_modules/go-0123456789
MSG='build(deps): bump the go group

Updates `github.com/vjeantet/ldapserver` from 1.0.2-0.20260725103726-663e6b9910fb to 1.0.2-0.20261001000000-0123456789ab

---
updated-dependencies:
- dependency-name: github.com/vjeantet/ldapserver
  dependency-version: 1.0.2-0.20261001000000-0123456789ab
  dependency-type: direct:production
  dependency-group: go
...'
FILES='["go.mod","go.sum"]'
setup; decide
expect "pseudo -> pseudo: major (not closed)" '.action == "major" and .update_type == "unknown" and .app == "(root)"'

echo "# red patch -> PR left open, update-failed issue opened, then updated, then left alone"
defaults
TEST=failure
setup; decide
expect "action report, issue open" '.action == "report" and .issue == "open" and .ci == "red" and (.failures|length) == 1 and .failures[0].jobs[0].name == "test (matrix)"'
act issue
logged "issue created with label + title" "POST repos/$REPO/issues -f title=Update failed: matrix: element-hq/synapse v1.164.1 → v1.164.2 -f labels\\[\\]=update-failed"
logged "body has failing job + run link" "job .test \\(matrix\\).: https://github.com/$REPO/actions/runs/20/job/7"
not_logged "PR not merged" "pr merge"
ISSUES='[{"number":55,"title":"Update failed: matrix: element-hq/synapse v1.164.1 → v1.164.2"}]'
setup; decide
put "repos/$REPO/issues/55" '{"body":"old run https://github.com/porelli/portcullis-templates/actions/runs/19"}'
put "repos/$REPO/issues/55/comments?per_page=100" '[]'
act issue
logged "existing issue: comment" "POST repos/$REPO/issues/55/comments"
not_logged "existing issue: no new issue" "POST repos/$REPO/issues -f title"
put "repos/$REPO/issues/55/comments?per_page=100" '[{"body":"Still failing: https://github.com/porelli/portcullis-templates/actions/runs/20"}]'
: > "$GH_LOG"; act issue
not_logged "same run already reported: no comment" "POST"
LINT=failure; setup; decide
expect "both red: two failures" '(.failures|length) == 2'

echo "# pending -> nothing yet"
defaults
TEST_STATUS=in_progress
setup; decide
expect "action none (waiting)" '.action == "none" and .issue == "none" and .ci == "pending"'
defaults; TEST=cancelled; setup; decide
expect "cancelled = waiting" '.action == "none" and .ci == "pending"'

echo "# refusals"
defaults; AUTHOR=someone; setup; decide
expect "wrong PR author" '.action == "refuse" and (.reason|test("opened by someone"))'
defaults; RUN_REPO=evil/fork; setup; decide
expect "fork run" '.action == "refuse" and (.reason|test("fork"))'
defaults; HEAD_REPO=evil/fork; setup; decide
expect "fork PR head" '.action == "refuse" and (.reason|test("fork"))'
defaults; PR_SHA=$OTHER_SHA; setup; decide
expect "SHA mismatch (PR head moved)" '.action == "refuse" and (.reason|test("stale"))'
defaults; COMMITS=2; setup; decide
expect "extra commits" '.action == "refuse" and (.reason|test("2 commits"))'
defaults; COMMIT_AUTHOR=mallory; setup; decide
expect "head commit not Dependabot's" '.action == "refuse" and (.reason|test("signed"))'
defaults; VERIFIED=false; setup; decide
expect "unsigned head commit" '.action == "refuse"'
defaults; RUN_EVENT=push; setup; decide
expect "push run" '.action == "refuse" and (.reason|test("push run"))'
defaults; BRANCH=feature/x; setup; decide
expect "not a dependabot/ branch" '.action == "refuse"'
defaults; AUTHOR=someone; setup
OUT=$(PR=4 bash "$SCRIPT" decide 2>/dev/null)
expect "dispatch mode (PR=4) checks too" '.action == "refuse"'
defaults; setup
OUT=$(PR=4 bash "$SCRIPT" decide 2>/dev/null)
expect "dispatch mode (PR=4) merges a green patch" '.action == "merge"'
DECISION='{"action":"major","pr":4,"sha":"x","issue":"none"}' bash "$SCRIPT" dispatch >/dev/null 2>&1 && bad "dispatch refuses without a merge" || ok "dispatch refuses without a merge"
DECISION='{"action":"report","pr":4,"sha":"x"}' bash "$SCRIPT" pr >/dev/null 2>&1 && bad "pr refuses action report" || ok "pr refuses action report"

echo
echo "$PASS passed, $FAILN failed"
[ "$FAILN" -eq 0 ]
