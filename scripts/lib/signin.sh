# shellcheck shell=bash
#
# `portcullis signin reset-core` — the recovery when no administrator can
# sign in to the Hub (contract §8.1 "Lockout guard and signin reset-core").
#
# Stops the Hub, runs `hub signin reset-core` against its data directory in
# a one-off container of the Hub's own image, as the image's user (uid
# 10001: a root-owned file or lock in hub_data would stop the Hub starting),
# then starts the Hub again — also when the reset failed. The Hub side puts
# the `hub` and `people` core pages on the built-in Standard template,
# restores and enables Standard, switches its methods back on and audits
# `signin.reset_core` (actor `cli`); it prints what changed.

# signin_reset_core — the stop / run / start sequence. Never leaves the Hub
# stopped silently: every failure after the stop starts it again first.
signin_reset_core() {
  local rc=0
  info "Stopping the Hub..."
  dc stop hub || fail "could not stop the Hub: nothing was reset"
  # An interrupt between the stop and the start still starts the Hub.
  trap 'dc start hub >/dev/null 2>&1 || true; exit 130' INT TERM
  info "Resetting the Hub's core sign-in settings (hub signin reset-core)..."
  dc run --rm --no-deps -T --user "$CT_UID_HUB:$CT_UID_HUB" \
    --entrypoint /usr/local/bin/hub hub signin reset-core || rc=$?
  info "Starting the Hub..."
  if ! dc start hub; then
    trap - INT TERM
    if [ "$rc" -ne 0 ]; then
      fail "hub signin reset-core failed (exit $rc, its message is above) and the Hub could not be started again: run ./portcullis up"
    fi
    fail "the reset is done, but the Hub could not be started again: run ./portcullis up"
  fi
  trap - INT TERM
  [ "$rc" -eq 0 ] || fail "hub signin reset-core failed (exit $rc, its message is above): nothing was reset; the Hub is running again"
  ok "Done: hub and people use the Standard template with its methods switched on. Sign in with a passkey or your YubiKey."
}

help_signin() {
  cat <<'EOF'
Usage: portcullis signin <subcommand>

  reset-core   Put the Hub's core pages back on the Standard sign-in template (lockout recovery)

Run 'portcullis signin <subcommand> --help' for details.
EOF
}

help_signin_reset_core() {
  cat <<'EOF'
Usage: portcullis signin reset-core [--yes]

Recovery when no administrator can sign in to the Hub (for example after
switching off the only methods the administrators have set up). Stops the
Hub, then, in a one-off container of the Hub's image (as its user, uid
10001), runs `hub signin reset-core` against the Hub's data:
  - the hub and people core pages go back to the built-in Standard template;
  - Standard's rule is restored and the template enabled;
  - Standard's methods are switched back on (any passkey or a YubiKey
    certificate; the browser certificate stays off);
  - audited as signin.reset_core, actor cli.
Everything else (other templates, apps' picks, passwords) is kept. It prints
what changed, then starts the Hub again — also when the reset failed.

Asks you to type "reset" to confirm.

Options:
  --yes   don't ask (scripts / CI); without a terminal --yes is required
EOF
}

cmd_signin() {
  local sub="${1:-}" assume_yes=false reply
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_signin; [ -n "$sub" ] || exit 2; return 0 ;;
    reset-core) ;;
    *) usage_error signin "unknown subcommand: $sub" ;;
  esac
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) help_signin_reset_core; return 0 ;;
      -y|--yes) assume_yes=true ;;
      *) usage_error "signin reset-core" "unknown argument: $1" ;;
    esac
    shift
  done
  if [ "$assume_yes" != true ] && [ ! -t 0 ]; then
    usage_error "signin reset-core" "no terminal to confirm on: pass --yes to reset without asking"
  fi
  need_env
  if [ "$assume_yes" != true ]; then
    printf 'This stops the Hub, puts its hub and people pages back on the Standard sign-in\n'
    printf 'template with its methods switched on, and starts the Hub again.\n'
    read -rp 'Type "reset" to continue: ' reply || reply=""
    [ "$reply" = reset ] || { echo "Cancelled: nothing changed."; return 1; }
  fi
  signin_reset_core
}
