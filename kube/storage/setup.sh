#!/bin/sh
# The local-path provisioner's setup script for portcullis.io/local-path
# (K3, mechanism (a) native): the StorageClass's userPattern / groupPattern
# / permPattern turn a PVC's annotations portcullis.io/uid, /gid and /mode
# into VOL_USER, VOL_GROUP and VOL_PERM. The directory is created 0700
# (root's), given its mode, then owned by that uid:gid, and the mode is read
# back. That order: without CAP_FSETID a chmod by a process outside the
# directory's group drops setgid (chown → chmod gave 750 for 2750, Linux
# 7.0), while a chown never clears it on a directory. Any missing
# or bad value, or a mode that didn't stick, refuses (exit 1): the PVC stays Pending,
# the provisioner logs "portcullis-setup REFUSED: <why>". Runs in the
# helper pod (uid 0, CAP_CHOWN / DAC_OVERRIDE / FOWNER only).
set -eu
made=""
# A refusal after the mkdir removes that (empty) directory: else every retry
# of the PVC refuses "already exists" for good.
refuse() { echo "portcullis-setup REFUSED: $*" >&2; [ -z "$made" ] || rmdir "$VOL_DIR" 2>/dev/null || true; exit 1; }
id_ok() {
  case "$1" in ''|*[!0-9]*|0*) return 1 ;; esac
  [ "${#1}" -le 5 ] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}
[ -n "${VOL_DIR:-}" ] || refuse "no VOL_DIR"
case "$VOL_DIR" in /*) ;; *) refuse "VOL_DIR '$VOL_DIR' is not absolute" ;; esac
case "$VOL_DIR" in *'/../'*|*'/..') refuse "VOL_DIR '$VOL_DIR' climbs" ;; esac
id_ok "${VOL_USER:-}" || refuse "bad uid '${VOL_USER:-}' (portcullis.io/uid: 1-65535)"
id_ok "${VOL_GROUP:-}" || refuse "bad gid '${VOL_GROUP:-}' (portcullis.io/gid: 1-65535)"
case "${VOL_PERM:-}" in
  [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;;
  *) refuse "bad mode '${VOL_PERM:-}' (portcullis.io/mode: 3-4 octal digits)" ;;
esac
[ ! -e "$VOL_DIR" ] || refuse "$VOL_DIR already exists"
mkdir -m 0700 "$VOL_DIR"
made=1
chmod "$VOL_PERM" "$VOL_DIR" || refuse "chmod $VOL_PERM $VOL_DIR failed"
chown "$VOL_USER:$VOL_GROUP" "$VOL_DIR" || refuse "chown $VOL_USER:$VOL_GROUP $VOL_DIR failed"
want="$(printf '%o' "0$VOL_PERM")"
got="$(stat -c %a "$VOL_DIR")"
[ "$got" = "$want" ] || refuse "$VOL_DIR is mode $got after chmod $VOL_PERM and chown (want $want)"
