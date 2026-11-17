# shellcheck shell=bash
#
# `portcullis ssh …` — SSH access on the server side (contract §18):
#
#   ssh enroll-self [--no-ssh] [--ca-file <pem>] < code.txt
#       make this server a managed SSH host: the Hub image's own
#       `portcullis` binary, installed root-owned, runs `host enroll` with
#       the one-time code on standard input (never argv).
#   ssh breakglass-cert (--user <name> | --account <name>) --host-group <hg>
#                       --ttl <5m–12h> --key <public key file> [--note <text>]
#                       [--privileged]
#       the Hub is down, Vault is up: a user certificate signed directly on
#       ssh_user/sign/hg-<hg> with the root token (vault_admin: by name in
#       the container's environment, never argv), key id
#       pc-breakglass:<note>; every use appended to
#       secrets/ssh/breakglass.jsonl, which the Hub imports into its audit.
#
# ssh_prepare (stack_prepare): secrets/ssh/ (0750) and the record
# breakglass.jsonl (0640), both group 10001 (the Hub reads them read-only).

SSH_BREAKGLASS_FILE_REL="secrets/ssh/breakglass.jsonl"
SSH_PORTCULLIS_BIN="/usr/local/bin/portcullis"
# The username / account grammar (contract §18.12, the Hub's cliapi).
SSH_ACCOUNT_RE='^[a-z_][a-z0-9._-]{0,31}$'
SSH_HOSTGROUP_RE='^[a-z][a-z0-9-]{0,30}$'
SSH_NOTE_RE='^[A-Za-z0-9 ._:@/-]{1,128}$'

# ssh_prepare — the break-glass record's directory and file exist before
# the Hub's bind (a missing source would become a root-owned directory).
ssh_prepare() {
  local d="$PORTCULLIS_ROOT/secrets/ssh"
  (umask 027 && mkdir -p "$d")
  [ -w "$d" ] || fail "$d is not writable (made by Docker as root?): fix its owner and run again"
  [ ! -d "$d/breakglass.jsonl" ] || fail "$d/breakglass.jsonl is a directory: remove it (rmdir) and run again"
  [ -f "$d/breakglass.jsonl" ] || (umask 027 && : > "$d/breakglass.jsonl")
  ssh_fix_perms
}

# ssh_fix_perms — secrets/ssh/ for the Hub (group 10001, read-only).
ssh_fix_perms() {
  local d="$PORTCULLIS_ROOT/secrets/ssh"
  ct_group_read "$CT_UID_HUB" "$d" "$d/breakglass.jsonl"
}

help_ssh() {
  cat <<'EOF'
Usage: portcullis ssh <subcommand>

  enroll-self       Make this Portcullis server a managed SSH host (code on stdin)
  breakglass-cert   Sign an SSH certificate straight from Vault (the Hub is down)

Run 'portcullis ssh <subcommand> --help' for details.
EOF
}

help_ssh_enroll_self() {
  cat <<'EOF'
Usage: portcullis ssh enroll-self [--no-ssh] [--ca-file <pem>] < code.txt

Makes this Portcullis server a managed SSH host. First add it in Hub → SSH
access → Hosts → Add host (any host group) and save the one-time code in a
file. The command copies the `portcullis` binary out of the running Hub
container (nothing is downloaded), installs it root-owned as
/usr/local/bin/portcullis (sudo) and runs `portcullis host enroll` with the
code on standard input — never on a command line. Enrolling changes this
host's sshd drop-in, /etc/ssh/portcullis/, the accounts Portcullis creates
and a systemd service.

Options:
  --no-ssh          Do nothing and exit 0 (for scripts that call it unconditionally)
  --ca-file <pem>   Trust an extra CA for people.<domain> (a test server on
                    staging certificates)
EOF
}

help_ssh_breakglass_cert() {
  cat <<'EOF'
Usage: portcullis ssh breakglass-cert (--user <name> | --account <name>) --host-group <hg>
                                      --ttl <duration> --key <public key file> [--note <text>]
                                      [--privileged]

For when the Hub is down and Vault is up: signs one SSH user certificate
directly on Vault's ssh_user/sign/hg-<hg> with the root token from
secrets/vault-init.json (VAULT_TOKEN if set; passed to the Vault container
by name, never on a command line) and prints it.

  --user <name>       a person's own account: principal u:<name>@<hg>
  --account <name>    a shared account: principal s:<name>@<hg>
  --host-group <hg>   the host group (its Vault role must list the principal)
  --ttl <duration>    5m to 12h (e.g. 30m, 1h)
  --key <file>        the public key to certify (ed25519 or ECDSA P-256, also
                      their security-key forms)
  --note <text>       why (default "breakglass"): the key id is
                      pc-breakglass:<note>, which every host's sshd logs
  --privileged        the approved principal up:<name>@<hg> / sp:<name>@<hg>
                      (a privileged grant's): the only kind an account with
                      sudo on a host accepts

Every use is appended to secrets/ssh/breakglass.jsonl; the Hub writes it to
its audit (ssh.certificate.breakglass) at its next start and the doctor
warns.
EOF
}

# _ssh_ttl_seconds <5m–12h> — the duration in seconds, or fail.
_ssh_ttl_seconds() {
  local n u
  [[ "$1" =~ ^([1-9][0-9]{0,3})(m|h)$ ]] || usage_error "ssh breakglass-cert" "--ttl must be like 30m or 1h"
  n="${BASH_REMATCH[1]}" u="${BASH_REMATCH[2]}"
  [ "$u" = h ] && n=$((n * 60))
  [ "$n" -ge 5 ] && [ "$n" -le 720 ] || usage_error "ssh breakglass-cert" "--ttl must be between 5m and 12h"
  echo $((n * 60))
}

ssh_breakglass_cert() {
  local person="$1" account="$2" hg="$3" ttl="$4" keyfile="$5" note="$6" privileged="${7:-false}"
  local kind name principal secs pub type out signed info serial vb fp rec got
  require_cmd jq ssh-keygen
  if [ -n "$person" ] && [ -n "$account" ]; then usage_error "ssh breakglass-cert" "--user or --account, not both"; fi
  if [ -n "$person" ]; then kind=u name="$person"; elif [ -n "$account" ]; then kind=s name="$account"; else usage_error "ssh breakglass-cert" "--user or --account is required"; fi
  [[ "$name" =~ $SSH_ACCOUNT_RE ]] || usage_error "ssh breakglass-cert" "not an account name: $name"
  [ -n "$hg" ] || usage_error "ssh breakglass-cert" "--host-group is required"
  [[ "$hg" =~ $SSH_HOSTGROUP_RE ]] && [[ "$hg" != portcullis-* ]] || usage_error "ssh breakglass-cert" "not a host group id: $hg"
  [ -n "$ttl" ] || usage_error "ssh breakglass-cert" "--ttl is required"
  secs="$(_ssh_ttl_seconds "$ttl")" || exit 2
  [ -n "$keyfile" ] || usage_error "ssh breakglass-cert" "--key is required"
  [[ "$note" =~ $SSH_NOTE_RE ]] || usage_error "ssh breakglass-cert" "--note may hold letters, digits, space and . _ : @ / - (1–128)"
  [ -r "$keyfile" ] || fail "cannot read $keyfile"
  # One public key line, an accepted type (Vault's role checks again).
  pub="$(grep -v '^[[:space:]]*$' "$keyfile" | head -n 2)"
  [ "$(printf '%s\n' "$pub" | wc -l | tr -d ' ')" = 1 ] || fail "$keyfile must hold exactly one public key line"
  type="${pub%% *}"
  case "$type" in
    ssh-ed25519|ecdsa-sha2-nistp256|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com) ;;
    *) fail "key type ${type:-?} isn't accepted (ed25519, ECDSA P-256 or their security-key forms)" ;;
  esac
  case "$pub" in *PRIVATE*) fail "$keyfile is a private key: pass the .pub file" ;; esac
  fp="$(printf '%s\n' "$pub" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')"
  [[ "$fp" == SHA256:* ]] || fail "$keyfile isn't an SSH public key"
  # The approved namespace (Ruling RR3) when asked: an account with sudo
  # accepts only up:/sp: principals.
  [ "$privileged" = true ] && kind="${kind}p"
  principal="$kind:$name@$hg"
  vault_admin
  out="$(jq -n --arg pk "$pub" --arg p "$principal" --arg t "${secs}s" --arg k "pc-breakglass:$note" \
      '{public_key: $pk, valid_principals: $p, ttl: $t, extensions: {"permit-pty": ""}, key_id: $k}' \
    | vault write -format=json "ssh_user/sign/hg-$hg" -)" \
    || fail "Vault refused the certificate (is $principal in host group $hg's role? the Hub writes the roles from its grants)"
  signed="$(printf '%s' "$out" | jq -r '.data.signed_key // empty')"
  [ -n "$signed" ] || fail "Vault answered no certificate"
  info="$(printf '%s\n' "$signed" | TZ=UTC ssh-keygen -L -f - 2>/dev/null)" || fail "Vault's certificate doesn't parse"
  serial="$(printf '%s\n' "$info" | awk '$1 == "Serial:" {print $2; exit}')"
  vb="$(printf '%s\n' "$info" | awk '$1 == "Valid:" {print $5; exit}')"
  [[ "$serial" =~ ^[0-9]+$ ]] && [ -n "$vb" ] || fail "Vault's certificate lacks a serial or validity"
  # Exactly the one principal asked for (L-A6: not a pattern, not "among").
  got="$(printf '%s\n' "$info" | awk '/^[[:space:]]*Principals:/ {p = 1; next} /^[[:space:]]*Critical Options:/ {p = 0} p {sub(/^[[:space:]]+/, ""); print}')"
  [ "$got" = "$principal" ] || fail "Vault's certificate names other principals"
  rec="$(jq -cn --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg u "$name" --arg hg "$hg" --arg p "$principal" --arg fp "$fp" \
      --arg s "$serial" --arg vb "${vb}Z" --arg n "$note" --arg pk "$pub" \
      '{time: $t, user: $u, host_group: $hg, principals: [$p], key_fp: $fp, serial: $s, valid_before: $vb, note: $n, public_key: $pk}')"
  # Appended to the record ./portcullis up made (group 10001 for the Hub);
  # made here if missing (then `up` gives the Hub its group).
  if [ ! -f "$PORTCULLIS_ROOT/$SSH_BREAKGLASS_FILE_REL" ]; then
    (umask 027 && mkdir -p "$PORTCULLIS_ROOT/secrets/ssh" && : > "$PORTCULLIS_ROOT/$SSH_BREAKGLASS_FILE_REL") \
      || fail "cannot write $SSH_BREAKGLASS_FILE_REL"
    warn "$SSH_BREAKGLASS_FILE_REL was missing: ./portcullis up gives the Hub read access to it" >&2
  fi
  printf '%s\n' "$rec" >> "$PORTCULLIS_ROOT/$SSH_BREAKGLASS_FILE_REL" || fail "cannot append to $SSH_BREAKGLASS_FILE_REL"
  printf '%s\n' "$signed"
  warn "break-glass certificate $serial for $principal until ${vb}Z (recorded in $SSH_BREAKGLASS_FILE_REL; the Hub audits it at its next start)" >&2
}

ssh_enroll_self() {
  local cafile="$1" tmp code
  local -a sudo=()
  if [ "$(id -u)" != 0 ]; then require_cmd sudo; sudo=(sudo); fi
  if [ -t 0 ]; then fail "pass the one-time code on standard input: ./portcullis ssh enroll-self < code.txt"; fi
  code="$(head -c 8192)"
  [ -n "$code" ] || fail "no one-time code on standard input"
  need_env
  case "$(rt_health hub)" in
    healthy|running|starting) ;;
    *) code=""; fail "the Hub isn't running: ./portcullis up first" ;;
  esac
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064  # expand now: the trap must remove this dir
  trap "rm -rf '$tmp'" EXIT
  rt_exec hub -- cat "$SSH_PORTCULLIS_BIN" > "$tmp/portcullis" || { code=""; fail "the Hub image has no $SSH_PORTCULLIS_BIN (a Hub with SSH access is needed)"; }
  chmod 0755 "$tmp/portcullis"
  "$tmp/portcullis" version >/dev/null 2>&1 || { code=""; fail "the binary from the Hub image doesn't run here"; }
  # Root-owned, not writable by anyone else: the root service it installs
  # refuses any other binary (CheckRootExecutable).
  "${sudo[@]}" install -o root -g root -m 0755 "$tmp/portcullis" "$SSH_PORTCULLIS_BIN" || { code=""; fail "could not install $SSH_PORTCULLIS_BIN"; }
  local -a args=(host enroll)
  [ -z "$cafile" ] || args+=(--ca-file "$cafile")
  printf '%s\n' "$code" | "${sudo[@]}" "$SSH_PORTCULLIS_BIN" "${args[@]}"
  local rc=$?
  code=""
  return "$rc"
}

cmd_ssh() {
  local sub="${1:-}"
  [ $# -gt 0 ] && shift
  case "$sub" in
    ""|-h|--help|help) help_ssh; [ -n "$sub" ] || exit 2; return 0 ;;
    enroll-self|breakglass-cert) ;;
    *) usage_error ssh "unknown subcommand: $sub" ;;
  esac
  local fn="help_ssh_${sub//-/_}" noop=false cafile="" person="" account="" hg="" ttl="" key="" note="breakglass" privileged=false
  while [ $# -gt 0 ]; do
    case "$sub:$1" in
      *:-h|*:--help) "$fn"; return 0 ;;
      enroll-self:--no-ssh) noop=true ;;
      enroll-self:--ca-file) need_value "ssh enroll-self" "$1" "${2:-}"; cafile="$2"; shift ;;
      breakglass-cert:--user) need_value "ssh breakglass-cert" "$1" "${2:-}"; person="$2"; shift ;;
      breakglass-cert:--account) need_value "ssh breakglass-cert" "$1" "${2:-}"; account="$2"; shift ;;
      breakglass-cert:--host-group) need_value "ssh breakglass-cert" "$1" "${2:-}"; hg="$2"; shift ;;
      breakglass-cert:--ttl) need_value "ssh breakglass-cert" "$1" "${2:-}"; ttl="$2"; shift ;;
      breakglass-cert:--key) need_value "ssh breakglass-cert" "$1" "${2:-}"; key="$2"; shift ;;
      breakglass-cert:--note) need_value "ssh breakglass-cert" "$1" "${2:-}"; note="$2"; shift ;;
      breakglass-cert:--privileged) privileged=true ;;
      *:-*) usage_error "ssh $sub" "unknown option: $1" ;;
      *) usage_error "ssh $sub" "unexpected argument (the code goes on standard input): $1" ;;
    esac
    shift
  done
  case "$sub" in
    enroll-self)
      [ "$noop" = false ] || return 0
      ssh_enroll_self "$cafile" ;;
    breakglass-cert) ssh_breakglass_cert "$person" "$account" "$hg" "$ttl" "$key" "$note" "$privileged" ;;
  esac
}

# ssh_status_json — the SSH block of `portcullis status` (`ssh{}` in
# --json), from the Hub's `hub ssh status` over its control socket:
# on/off, both CA fingerprints, enroll's §18.7 problems (mounts, caps, CA
# key types, the host role) and the managed hosts with their sync age.
# The Hub not answering: reachable false, no problem of its own (the Hub's
# own line says it). SSH on with a problem: problem true.
ssh_status_json() {
  local raw=""
  raw="$(rt_exec hub -- hub ssh status 2>/dev/null)" || raw=""
  jq -n --arg raw "$raw" '
    ($raw | try fromjson catch null) as $s
    | if $s == null or ($s | type) != "object" then {reachable: false, enabled: null, problem: false, problems: [], hosts: []}
      else {reachable: true, enabled: ($s.enabled == true), user_ca_fp: ($s.user_ca_fp // ""), host_ca_fp: ($s.host_ca_fp // ""),
            cli_client_ready: ($s.cli_client_ready == true), problems: ($s.problems // []), hosts: ($s.hosts // [])}
        | .problem = (.enabled and ((.problems | length) > 0 or (.cli_client_ready | not)))
      end'
}

# ssh_status_lines <ssh json> — the SSH block's lines.
ssh_status_lines() {
  local j="$1" st text
  printf '\n%sSSH access%s\n' "$C_CYAN" "$C_NC"
  while IFS=$'\t' read -r st text; do
    [ -n "$st" ] && _st_line "$st" "$text"
  done < <(printf '%s' "$j" | jq -r '
    if (.reachable | not) then ["warn", "the Hub didn'"'"'t answer: SSH access unknown"]
    elif (.enabled | not) then ["ok", "off (Hub → SSH access → Settings)"]
    else
      ["ok", "on: user CA \(if .user_ca_fp == "" then "?" else .user_ca_fp end), host CA \(if .host_ca_fp == "" then "?" else .host_ca_fp end)"],
      (if .cli_client_ready then empty else ["fail", "the portcullis-cli sign-in client isn'"'"'t ready (Keycloak)"] end),
      (.problems[] | ["fail", .]),
      (.hosts[] | [(if .sync_age_s < 0 or .sync_age_s > 300 then "warn" else "ok" end),
         "host \(.id): \(.state // "?"), last sync \(if .sync_age_s < 0 then "never" else "\(.sync_age_s) s ago" end)"
         + (if (.findings // 0) > 0 then ", \(.findings) finding(s)" else "" end)])
    end | @tsv')
}
