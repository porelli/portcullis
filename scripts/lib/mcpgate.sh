# shellcheck shell=bash
#
# Files of the MCP gate (integration contract §15 "Service, networks and
# secrets"), kept in place by stack_prepare on every init / up / upgrade /
# restore. Never env vars, never printed:
#
#   secrets/mcp-gate/age.key     age X25519 identity: decrypts the Hub's
#                                mcp-credentials.json (the gate only:
#                                group 10005), 0640
#   secrets/mcp-gate/age.pub     its recipient, the "# public key:" line of
#                                age.key (the Hub encrypts to it: group
#                                10001), 0640
#   secrets/mcp-gate/hub-secret  48 random characters, X-Portcullis-MCP-Secret
#                                between the gate and the Hub's :8890 listener
#                                (group 10001; the gate reads it through
#                                group_add), 0640
#
# The directory is 0700: nothing traverses it (single-file bind mounts).

MCPGATE_IMAGE_NAME="portcullis-mcp-gate"  # built locally from mcp-gate/ (compose image name)

_mcpgate_dir() { echo "$PORTCULLIS_ROOT/secrets/mcp-gate"; }

# _mcpgate_keygen <file> — a new age identity, generated offline by the
# mcp-gate image itself (filippo.io/age), straight into the file.
_mcpgate_keygen() {
  local f="$1" tmp
  if ! docker image inspect "$MCPGATE_IMAGE_NAME" >/dev/null 2>&1; then
    info "Building the mcp-gate image (needed to generate its age key)..."
    dc build mcp-gate >/dev/null || fail "could not build the mcp-gate image"
  fi
  tmp="$(mktemp "$f.XXXXXX")"
  chmod 600 "$tmp"
  docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
    --user "$CT_UID_MCP_GATE:$CT_UID_MCP_GATE" "$MCPGATE_IMAGE_NAME" keygen > "$tmp" \
    && grep -q '^AGE-SECRET-KEY-1' "$tmp" \
    && grep -Eq '^# public key: age1[0-9a-z]+$' "$tmp" \
    || { rm -f "$tmp"; fail "could not generate secrets/mcp-gate/age.key"; }
  mv -f "$tmp" "$f"
  ok "Generated secrets/mcp-gate/age.key (decrypts the Hub's AI credentials; backed up with secrets/)."
}

# mcpgate_ensure_secrets — create what is missing (age key, recipient,
# hub secret), rewrite a missing or stale recipient from the key, replace a
# hub secret under 32 characters (the gate and the Hub refuse it), then fix
# modes and groups. Idempotent; prints no secret.
mcpgate_ensure_secrets() {
  local d pub cur
  d="$(_mcpgate_dir)"
  (umask 077 && mkdir -p "$d")
  if [ ! -s "$d/hub-secret" ] || [ "$(tr -d '[:space:]' < "$d/hub-secret" | wc -c | tr -d ' ')" -lt 32 ]; then
    (umask 077 && gen_alnum 48 > "$d/hub-secret.new") && mv -f "$d/hub-secret.new" "$d/hub-secret"
    info "Generated secrets/mcp-gate/hub-secret (shared by mcp-gate and the Hub)."
  fi
  [ -s "$d/age.key" ] || _mcpgate_keygen "$d/age.key"
  pub="$(sed -n 's/^# public key: \(age1[0-9a-z]*\)$/\1/p' "$d/age.key" | head -n1)"
  [ -n "$pub" ] || fail "secrets/mcp-gate/age.key has no '# public key: age1...' line: restore it from a backup (deleting it makes every stored AI credential unreadable; the Hub then mints new ones)"
  cur="$(cat "$d/age.pub" 2>/dev/null || true)"
  if [ "$cur" != "$pub" ]; then
    (umask 077 && printf '%s\n' "$pub" > "$d/age.pub.new") && mv -f "$d/age.pub.new" "$d/age.pub"
    info "Wrote secrets/mcp-gate/age.pub (the gate's recipient, for the Hub)."
  fi
  mcpgate_fix_perms
}

# mcpgate_fix_perms — called by secrets_fix_perms (and the above).
mcpgate_fix_perms() {
  local d f
  d="$(_mcpgate_dir)"
  [ -d "$d" ] || return 0
  chmod 700 "$d"
  for f in "$d/age.key" "$d/age.pub" "$d/hub-secret"; do
    [ ! -e "$f" ] || chmod 640 "$f"
  done
  [ ! -e "$d/age.key" ] || ct_own "$(id -u):$CT_UID_MCP_GATE" "$d/age.key"
  ct_own "$(id -u):$CT_UID_HUB" "$d/age.pub" "$d/hub-secret"
}
