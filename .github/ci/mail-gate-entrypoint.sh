#!/usr/bin/env bash
# The mail container's start gate, run for real (final review M2 / M3 / M4):
# called by build-and-test-mail-service.sh (Docker) and e2e-podman-mail.sh
# (rootless Podman) once mail is enabled and healthy. Run from the
# workspace root. Every case starts mail's own entrypoint:
#
#   - gate/void-pending present → refused ("not voided yet");
#   - gate/.present missing, or (Docker) the gate unreadable → refused
#     ("the mail gate isn't readable");
#   - recovery mode with a session file of another boot → refused;
#   - recovery mode with this boot's session file (the recovery overlay)
#     → runs, on portcullis-mail only, publishing nothing: the host's
#     25 / 465 / 587 / 993 are refused meanwhile;
#
# then mail is back in normal mode and healthy.
set -euo pipefail
G=secrets/mail/gate
CI_RUNTIME="${1:-docker}"
fail() { echo "FAIL: $*"; docker compose --profile mail logs --tail=40 mail 2>/dev/null || true; exit 1; }
lib() { bash -c 'set -euo pipefail; source scripts/lib/common.sh; source scripts/lib/network.sh; source scripts/lib/mail.sh; env_load; runtime_export; '"$1"; }
cid() { docker compose --profile mail ps -aq mail; }
health() { docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$(cid)" 2>/dev/null || echo missing; }
wait_healthy() { for _ in $(seq 1 60); do [ "$(health)" = healthy ] && return 0; sleep 3; done; fail "mail not healthy ($(health))"; }
# refused <message> — mail's log since $since carries the refusal and the
# container isn't running Stalwart (exited or restarting).
refused() {
  local out
  for _ in $(seq 1 30); do
    out="$(docker logs --since "$since" "$(cid)" 2>&1 || true)"
    if grep -qF "$1" <<<"$out"; then
      case "$(docker inspect -f '{{.State.Status}}' "$(cid)")" in
        running) [ "$(docker inspect -f '{{.State.Restarting}}' "$(cid)")" = true ] || { sleep 1; continue; } ;;
      esac
      grep -q 'Stalwart' <<<"$out" && fail "Stalwart ran although the gate refused: $(tail -3 <<<"$out")"
      return 0
    fi
    sleep 1
  done
  fail "no refusal \"$1\" in mail's log: $(tail -5 <<<"$out")"
}
restart_mail() { since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; sleep 1; docker compose --profile mail restart mail >/dev/null 2>&1 || true; }

[ "$(cat "$G/.present")" = portcullis-mail-gate ] || fail "gate/.present isn't written by the CLI"
wait_healthy

# 1. The void-pending marker.
: > "$G/void-pending"
restart_mail
refused "mail passwords from a restore are not voided yet"
rm -f "$G/void-pending"
echo "PASS: the entrypoint refuses with the void-pending marker"

# 2. No sentinel; (Docker) an unreadable gate.
mv "$G/.present" "$G/.present.ci"
restart_mail
refused "the mail gate isn't readable"
mv "$G/.present.ci" "$G/.present"
if [ "$CI_RUNTIME" = docker ]; then
  mode="$(stat -c %a "$G")"
  sudo chmod 000 "$G"
  restart_mail
  refused "the mail gate isn't readable"
  sudo chmod "$mode" "$G"
fi
echo "PASS: the entrypoint fails closed without its sentinel (and on an unreadable gate)"

# 3. Recovery mode: another boot's session file, then this boot's (the
# recovery overlay: no port, portcullis-mail only, restart no).
RF="$(lib '_mail_recovery_files')"
docker compose --profile mail stop mail >/dev/null
(umask 077 && printf 'STALWART_RECOVERY_MODE=1\nSTALWART_RECOVERY_ADMIN=portcullis-recovery:%s\n' "$(openssl rand -hex 24)" > secrets/mail/recovery.env)
printf '00000000-0000-4000-8000-000000000000\n' > "$G/recovery-session"
lib "ct_group_read \"\$CT_UID_MAIL\" $G/recovery-session"
cleanup() {
  rm -f secrets/mail/recovery.env "$G/recovery-session"
  docker compose --profile mail rm -sf mail >/dev/null 2>&1 || true
  docker compose --profile mail up -d --no-deps mail >/dev/null
}
trap cleanup EXIT
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; sleep 1
COMPOSE_FILE="$RF" docker compose --profile mail up -d --no-deps mail >/dev/null 2>&1 || true
refused "a recovery-mode start outside a live recovery session of this boot"
cat /proc/sys/kernel/random/boot_id > "$G/recovery-session"
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; sleep 1
COMPOSE_FILE="$RF" docker compose --profile mail start mail >/dev/null
wait_healthy
c="$(cid)"
[ "$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$c")" = "portcullis-mail " ] \
  || fail "the recovery-mode container is on $(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$c")"
case "$(docker inspect -f '{{len .HostConfig.PortBindings}}:{{.HostConfig.RestartPolicy.Name}}' "$c")" in 0:no|0:) ;; *) false ;; esac \
  || fail "the recovery-mode container publishes $(docker inspect -f '{{json .HostConfig.PortBindings}} restart {{.HostConfig.RestartPolicy.Name}}' "$c")"
[ "$(docker network inspect -f '{{.Internal}}' portcullis-mail)" = true ] || fail "portcullis-mail isn't internal"
for p in 25 465 587 993; do
  set +e
  timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$p" 2>/dev/null; rc=$?
  set -e
  [ "$rc" = 1 ] || fail "the host's $p during a recovery-mode start: rc $rc (want 1: connection refused)"
done
echo "PASS: recovery mode only with this boot's session file; meanwhile no port published, portcullis-mail only, restart no"

# 4. Back to normal.
trap - EXIT
cleanup
wait_healthy
echo "PASS: mail back in normal mode"
