#!/usr/bin/env bash
#
# Fails (exit 1) when a tracked file is a compiled program: an ELF,
# Mach-O or PE (Windows) executable — a local `go build` committed by
# mistake (final review M10). Used by CI unit-tests. Run from anywhere.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
bad=()
while IFS= read -r -d '' f; do
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  magic="$(head -c 4 -- "$f" | od -An -tx1 | tr -d ' \n')"
  case "$magic" in
    7f454c46|feedface|feedfacf|cefaedfe|cffaedfe|4d5a*) bad+=("$f") ;;
  esac
done < <(git ls-files -z)
if [ "${#bad[@]}" -gt 0 ]; then
  printf 'a compiled program is tracked (remove it and add it to .gitignore): %s\n' "${bad[@]}"
  exit 1
fi
exit 0
