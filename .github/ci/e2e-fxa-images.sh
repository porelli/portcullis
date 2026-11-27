#!/usr/bin/env bash
# ci.yml job e2e-fxa, step "List the images this job runs": e2e-mail's list
# plus the images of the templates repo's firefox-sync-fxa (same-named
# branch, else main), checked out here into $RUNNER_TEMP/templates, where
# mail-templates-checkout.sh (the stack's start) finds it and doesn't clone
# again. Every template image is pinned tag@sha256 (the templates' lint).
#   e2e-fxa-images.sh <out file>
set -euo pipefail
out="${1:?usage: e2e-fxa-images.sh <out file>}"
dest="$RUNNER_TEMP/templates"
REF="${REF:-${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-main}}}"
url=https://github.com/porelli/portcullis-templates
ref=main
heads=$(git ls-remote --heads "$url") || { echo "::error::git ls-remote $url failed"; exit 1; }
if [[ "$REF" =~ ^[A-Za-z0-9._/-]+$ ]] && [ "$REF" != main ] && ! [[ "$REF" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    && awk -v r="refs/heads/$REF" '$2 == r { f = 1 } END { exit !f }' <<<"$heads"; then
  ref="$REF"
fi
git clone --quiet --depth=1 --branch "$ref" "$url" "$dest"
echo "Templates: portcullis-templates@$ref ($(git -C "$dest" rev-parse --short HEAD))" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
T="$dest/firefox-sync-fxa/compose.yml"
[ -f "$T" ] || { echo "::error::no firefox-sync-fxa in portcullis-templates@$ref"; exit 1; }
re='^    image: ([a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64})$'
n_img="$(grep -cE '^    image: ' "$T")"
n_pin="$(grep -cE "$re" "$T")"
[ "$n_img" = "$n_pin" ] || { echo "::error::$T: $((n_img - n_pin)) image line(s) not pinned tag@sha256"; exit 1; }
{
  docker compose config --images | grep -vxE 'portcullis-(enroll|group-gate|domains|mcp-gate)|ghcr\.io/porelli/portcullis-(hub|keycloak):.*'
  grep -ohE '[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' .github/ci/e2e-mail-*.sh .github/ci/e2e-fxa-*.sh scripts/lib/common.sh \
    | grep -E '^docker\.io/(library/alpine|curlimages/curl):'
  sed -nE "s#$re#\\1#p" "$T"
} | sort -u > "$out"
echo "PASS: $(wc -l < "$out") images ($n_pin of firefox-sync-fxa)"
