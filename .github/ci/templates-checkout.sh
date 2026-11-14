#!/usr/bin/env bash
# templates-checkout.sh <template>… — porelli/portcullis-templates at the
# same-named branch (REF), else main, into $RUNNER_TEMP/templates; each named
# template must carry an ai: block. A failed listing fails (never a quiet
# main). Exactly refs/heads/<REF>; release tags are vX.Y.Z only.
set -euo pipefail
url=https://github.com/porelli/portcullis-templates
ref=main
heads=$(git ls-remote --heads "$url") || { echo "::error::git ls-remote $url failed"; exit 1; }
if [[ "${REF:-}" =~ ^[A-Za-z0-9._/-]+$ ]] && [ "$REF" != main ] && ! [[ "$REF" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    && awk -v r="refs/heads/$REF" '$2 == r { f = 1 } END { exit !f }' <<<"$heads"; then
  ref="$REF"
fi
git clone --quiet --depth=1 --branch "$ref" "$url" "$RUNNER_TEMP/templates"
echo "Templates: portcullis-templates@$ref ($(git -C "$RUNNER_TEMP/templates" rev-parse --short HEAD))" | tee -a "${GITHUB_STEP_SUMMARY:-/dev/null}"
for t in "$@"; do
  grep -q '^ai:' "$RUNNER_TEMP/templates/$t/manifest.yaml" || { echo "FAIL: the templates checkout's $t has no ai: block"; exit 1; }
done
