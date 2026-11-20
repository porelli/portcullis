#!/bin/sh
# Portcullis: join this machine to a cluster (contract §20.3).
#
#   curl -fsSL https://<domain>/node/join.sh | sudo sh
#   sudo sh join.sh --code-file <file>     (a regular file, mode 0600, owned by root)
#
# The join code is a secret: it is read from the terminal with echo off
# (or from the --code-file), never from the command line, and it never
# reaches argv, the environment of another program, a log or the screen.
# Steps: the script checks its own sha256 against the code's
# script_sha256, downloads nodeagent-<arch> from the code's endpoint and
# checks it against agent_sha256, then runs `nodeagent join` with the code
# on stdin. The sha256 checks catch corruption only (whoever serves this
# script controls them too); the trust root is TLS to the domain and the
# nodeagent's check of the cluster's CA against the code's ca_sha256.
set -eu
umask 077

die() { printf 'join.sh: %s\n' "$1" >&2; exit "${2:-1}"; }

AGENT_DIR=/usr/local/lib/portcullis
code_file=""
parent_work=""
while [ $# -gt 0 ]; do
  case "$1" in
    --code-file) [ $# -ge 2 ] || die "--code-file needs a path" 2; code_file="$2"; shift 2 ;;
    --code-file=*) code_file="${1#--code-file=}"; shift ;;
    # Internal: the verified copy run by a piped one (its work dir goes too).
    --parent-work) [ $# -ge 2 ] || die "--parent-work needs a path" 2; parent_work="$2"; shift 2 ;;
    -h|--help) sed -n '2,7p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "unknown argument (the join code is a secret: paste it when asked, or use --code-file)" 2 ;;
  esac
done

[ "$(id -u)" = 0 ] || die "run it as root (… | sudo sh)"
for t in curl sha256sum base64 sed tr uname mktemp stat; do
  command -v "$t" >/dev/null 2>&1 || die "$t is missing on this machine"
done

work="$(mktemp -d /tmp/portcullis-join.XXXXXX)"
tty_echo_off=false
cleanup() {
  if [ "$tty_echo_off" = true ]; then stty echo </dev/tty 2>/dev/null || true; fi
  rm -rf "$work"
  if [ -n "$parent_work" ]; then rm -rf "$parent_work"; fi
}
trap cleanup EXIT
if [ -n "$parent_work" ]; then
  case "$parent_work" in /tmp/portcullis-join.??????) ;; *) die "--parent-work isn't a join work directory" 2 ;; esac
  [ -d "$parent_work" ] && [ ! -L "$parent_work" ] && [ "$(stat -c '%a %u' "$parent_work")" = "700 0" ] || die "--parent-work isn't a join work directory" 2
fi
trap 'exit 130' INT TERM HUP

# The code: from the 0600 root-owned file, else from the terminal.
if [ -n "$code_file" ]; then
  [ -f "$code_file" ] && [ ! -L "$code_file" ] || die "--code-file must be a regular file"
  [ "$(stat -c '%a %u' "$code_file")" = "600 0" ] || die "--code-file must be mode 0600 and owned by root"
  code="$(head -c 4097 "$code_file" | tr -d '\r\n')"
else
  [ -r /dev/tty ] || die "no terminal to read the join code from: use --code-file"
  printf 'Paste the join code (it is not shown): ' >/dev/tty
  stty -echo </dev/tty
  tty_echo_off=true
  IFS= read -r code </dev/tty || code=""
  stty echo </dev/tty
  tty_echo_off=false
  printf '\n' >/dev/tty
fi
case "$code" in pcj2.*) ;; *) die "not a pcj2 join code" ;; esac
[ "${#code}" -le 4096 ] || die "the join code is too long"
printf '%s' "$code" > "$work/code"

# Decode it (base64url without padding → JSON) only to read the endpoint and
# the sha256s; the nodeagent decodes it strictly.
b64="$(printf '%s' "${code#pcj2.}" | tr '_-' '/+')"
case $(( ${#b64} % 4 )) in 2) b64="$b64==" ;; 3) b64="$b64=" ;; 1) die "not a pcj2 join code" ;; esac
json="$(printf '%s' "$b64" | base64 -d 2>/dev/null)" || die "not a pcj2 join code"
field() { printf '%s' "$json" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
endpoint="$(field endpoint)"
script_sha="$(field script_sha256)"
agents="$(printf '%s' "$json" | sed -n 's/.*"agent_sha256":{\([^}]*\)}.*/\1/p')"
unset json b64 code
case "$endpoint" in https://*/node) ;; *) die "the join code's endpoint isn't https://<domain>/node" ;; esac

# This script's own sha256. Run from a file, that file is checked. Piped
# into sh it has no file: the served copy is fetched, checked, and that
# verified copy runs the rest (exec, with the code in its 0600 file), so
# the code that installs anything is the code that was checked (review M4).
self=""
case "$0" in */*) [ -f "$0" ] && self="$0" ;; esac
if [ -z "$self" ]; then
  [ -z "$parent_work" ] || die "the verified copy has no file" 2
  curl -fsSL --proto '=https' --tlsv1.2 -o "$work/join.sh" "$endpoint/join.sh" || die "could not download $endpoint/join.sh"
  [ "$(sha256sum "$work/join.sh" | cut -d' ' -f1)" = "$script_sha" ] || die "join.sh doesn't match the join code's script_sha256: nothing was installed"
  trap - EXIT
  exec sh "$work/join.sh" --code-file "$work/code" --parent-work "$work"
fi
[ "$(sha256sum "$self" | cut -d' ' -f1)" = "$script_sha" ] || die "join.sh doesn't match the join code's script_sha256: nothing was installed (download it again from $endpoint/join.sh)"

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "no nodeagent for $(uname -m) (amd64 and arm64 only)" ;;
esac
want="$(printf '%s' "$agents" | sed -n "s/.*\"$arch\":\"\([0-9a-f]\{64\}\)\".*/\1/p")"
[ -n "$want" ] || die "the join code has no agent_sha256 for $arch"
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/nodeagent" "$endpoint/nodeagent-$arch" || die "could not download nodeagent-$arch"
[ "$(sha256sum "$work/nodeagent" | cut -d' ' -f1)" = "$want" ] || die "nodeagent-$arch doesn't match the join code's agent_sha256: nothing was installed"

mkdir -p "$AGENT_DIR"
chmod 0755 "$AGENT_DIR"
install -m 0755 -o root -g root "$work/nodeagent" "$AGENT_DIR/nodeagent"
echo "Joining the cluster (nodeagent join)..."
"$AGENT_DIR/nodeagent" join < "$work/code"
