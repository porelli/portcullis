#!/bin/sh
# Teardown for portcullis.io/local-path: only portcullis-apps (reclaim
# Delete) ever runs it; portcullis-core is Retain.
set -eu
[ -n "${VOL_DIR:-}" ] || { echo "portcullis-teardown REFUSED: no VOL_DIR" >&2; exit 1; }
case "$VOL_DIR" in /var/lib/portcullis-storage/?*) ;; *) echo "portcullis-teardown REFUSED: $VOL_DIR is outside /var/lib/portcullis-storage" >&2; exit 1 ;; esac
case "$VOL_DIR" in *'/..'*) echo "portcullis-teardown REFUSED: $VOL_DIR climbs" >&2; exit 1 ;; esac
rm -rf "$VOL_DIR"
