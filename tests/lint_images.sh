#!/usr/bin/env bash
#
# Prints every unqualified image name (one "file:line: ref" per line) in the
# Dockerfiles' FROM lines, the compose files' image: lines (core and the CI
# templates tests/e2e/apps/*/compose.yml), and every pinned ref
# (name:tag@sha256:<64 hex>) the CLI (portcullis, scripts/lib/*.sh: the
# helper, restic, lldap-ui forwarder constants) or a workflow / action runs
# inline, plus the Kubernetes chart's images.yaml, its templates and
# kube/**/*.yaml; exit 1 when there is one. Qualified = the first path component is a registry host
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
for f in docker-compose*.yml tests/e2e/apps/*/compose.yml; do
  [ -f "$f" ] || continue
  while IFS=: read -r n line; do
    ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*image:[[:space:]]*//; s/[[:space:]]+#.*$//; s/^"(.*)"$/\1/')"
    qualified "$ref" || { echo "$f:$n: $ref"; bad=1; }
  done < <(grep -nE '^[[:space:]]+image:[[:space:]]' "$f")
done
# Kubernetes (K1, K3): the chart's generated images.yaml — every entry a
# qualified ref, a string pinned tag@sha256, a tag_ref one of our own
# ghcr.io/porelli/portcullis-* tags (the CLI resolves it to a digest) —, and
# every literal image: in the chart templates and kube/**/*.yaml (the probe,
# the provisioner and its helper); templated ones ({{ ... }}) come from
# images.yaml.
if [ -f charts/portcullis/images.yaml ]; then
  while IFS=: read -r n line; do
    ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]]*(tag_ref:[[:space:]]*|[a-z0-9-]+:[[:space:]]*)//; s/[[:space:]]+#.*$//; s/^"(.*)"$/\1/')"
    [ -n "$ref" ] || continue
    case "$line" in
      *tag_ref:*)
        case "$ref" in ghcr.io/porelli/portcullis-*:*) ;; *) echo "charts/portcullis/images.yaml:$n: $ref (a tag_ref outside ghcr.io/porelli/portcullis-*)"; bad=1; continue ;; esac ;;
      *)
        [[ "$ref" =~ @sha256:[0-9a-f]{64}$ ]] || { echo "charts/portcullis/images.yaml:$n: $ref (not pinned tag@sha256)"; bad=1; continue; } ;;
    esac
    qualified "$ref" || { echo "charts/portcullis/images.yaml:$n: $ref"; bad=1; }
  done < <(grep -nE '^[[:space:]]+[a-z0-9_-]+:[[:space:]]*[^[:space:]{]' charts/portcullis/images.yaml)
fi
while IFS= read -r f; do
  while IFS=: read -r n line; do
    ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]-]*image:[[:space:]]*//; s/[[:space:]]+#.*$//; s/^"(.*)"$/\1/')"
    case "$ref" in *'{{'*) continue ;; esac
    qualified "$ref" && [[ "$ref" =~ @sha256:[0-9a-f]{64}$ ]] || { echo "$f:$n: $ref"; bad=1; }
  done < <(grep -nE '^[[:space:]-]*image:[[:space:]]' "$f")
done < <(find charts/portcullis/templates kube -name '*.yaml' ! -path 'kube/ha/*/upstream/*' 2>/dev/null | sort)
# kube/ha/** (HA, plan Task 24): the vendored upstream files
# (kube/ha/<c>/upstream/, sha256-pinned in scripts/lib/ha.sh) name tags;
# what pins them is ours: every values file's `tag:` (a chart's image tag)
# is <tag>@sha256:<64 hex>, every kustomization images: entry has a
# sha256 digest. The rendered result is checked whole by
# tests/k8s_hardening.py check_ha_images (every image, arg and env value).
while IFS= read -r f; do
  while IFS=: read -r n line; do
    ref="$(printf '%s' "$line" | sed -E 's/.*tag:[[:space:]]*//; s/[}[:space:]]+$//; s/^"(.*)"$/\1/')"
    [[ "$ref" =~ @sha256:[0-9a-f]{64}$ ]] || { echo "$f:$n: tag $ref (not <tag>@sha256)"; bad=1; }
  done < <(grep -nE '(^|[{,[:space:]])tag:[[:space:]]' "$f")
done < <(find kube/ha -name 'values.yaml' ! -path '*/upstream/*' 2>/dev/null | sort)
while IFS= read -r f; do
  awk -v f="$f" '
    /^images:/ { i = 1; next } /^[^ #-]/ { i = 0 }
    i && /^  - name:/ { if (name != "" && !dig) { print f ": image " name " without a sha256 digest"; bad = 1 } name = $3; dig = 0 }
    i && /^    digest: sha256:[0-9a-f]{64}$/ { dig = 1 }
    END { if (name != "" && !dig) { print f ": image " name " without a sha256 digest"; bad = 1 } exit bad }' "$f" || bad=1
done < <(find kube/ha -name 'kustomization.yaml' ! -path '*/upstream/*' 2>/dev/null | sort)
# Inline pinned refs: a pinned ref is what the CLI and CI pull / run.
for f in portcullis scripts/lib/*.sh .github/workflows/*.yml .github/ci/*.sh .github/actions/*/action.yml $(find charts/portcullis kube -name '*.yaml' ! -path 'kube/ha/*/upstream/*' 2>/dev/null | sort); do
  [ -f "$f" ] || continue
  while IFS=: read -r n ref; do
    qualified "$ref" || { echo "$f:$n: $ref"; bad=1; }
  done < <(grep -noE '[A-Za-z0-9][A-Za-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' "$f")
done
exit "$bad"
