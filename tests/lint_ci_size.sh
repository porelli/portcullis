#!/usr/bin/env bash
#
# Fails (exit 1) when a workflow file is larger than 450,000 bytes. GitHub
# refuses a workflow file over 500 KB: the run ends in startup_failure with
# no jobs. Move long inline `run:` scripts into .github/ci/*.sh instead.
# Default file: .github/workflows/ci.yml. Used by CI unit-tests and
# tests/test_cli.sh. Run from anywhere.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
max=450000
f="${1:-.github/workflows/ci.yml}"
[ -f "$f" ] || { echo "$f: not found"; exit 2; }
size="$(wc -c < "$f" | tr -d ' ')"
if [ "$size" -gt "$max" ]; then
  echo "$f is $size bytes, over $max (GitHub refuses a workflow over 500 KB): move long run: scripts into .github/ci/"
  exit 1
fi
exit 0
