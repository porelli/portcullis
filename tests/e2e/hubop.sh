# shellcheck shell=bash
# The Hub's background operations for ci.yml's e2e steps (contract §11.7).
# Sourced by a step that defines `hub` (curl to the Hub's admin API) and
# `hubc` (the same, body to /tmp/hub.out, prints the HTTP status).
#
# Every lifecycle route (enable, disable, restart, create, an AI switch on
# an enabled instance, backup, restore, delete) answers 202
# {op_id, op, instance, poll}; the record at `poll` is read every 2 s until
# it is no longer running, then `ok` decides. Never a retry: a busy 409
# (the running record) or a failed record fails the step.

# hubop_explain: the record in /tmp/op.json as a failure message (error,
# hint, status, stopped_by, each step, the end of compose's output).
hubop_explain() {
  jq -r '"op \(.op) \(.op_id): ok \(.ok) error \(.error // "-") hint \(.hint // "-") status \(.status // "-") stopped_by \(.stopped_by // "-")",
         (.steps // [] | map("  step \(.key): \(.state)\(if .detail then " (\(.detail))" else "" end)") | .[]),
         (if .output then "  output: \(.output[-1500:])" else empty end)' /tmp/op.json 2>/dev/null \
    || head -c 1500 /tmp/op.json
}

# hubop_end <poll> <op_id> <timeout s>: the record (same op_id) once it
# ended → /tmp/op.json, ok or not (1 only when it is still running).
hubop_end() {
  local poll="$1" opid="$2" limit="$3" t0=$SECONDS
  while :; do
    hub GET "$poll" > /tmp/op.json || true
    jq -e --arg o "$opid" '.op_id == $o and (.running | not)' /tmp/op.json >/dev/null 2>&1 && return 0
    if (( SECONDS - t0 >= limit )); then
      echo "FAIL: op $opid still running after $limit s:"; hubop_explain; return 1
    fi
    sleep 2
  done
}

# hubop_wait <poll> <op_id> <timeout s>: hubop_end, then 0 when the record
# is ok, else its failure and 1.
hubop_wait() {
  hubop_end "$@" || return 1
  jq -e '.ok == true' /tmp/op.json >/dev/null && return 0
  echo "FAIL: op $2 ($1) failed:"; hubop_explain
  docker compose logs --tail=30 hub
  return 1
}

# hubop_start <method> <path> [curl args]: the 202 → HUBOP_ID, HUBOP_POLL.
hubop_start() {
  local code
  code=$(hubc "$@")
  [ "$code" = 202 ] || { echo "FAIL: $1 $2: HTTP $code (want 202) $(head -c 1500 /tmp/hub.out)"; docker compose logs --tail=30 hub; return 1; }
  HUBOP_ID="$(jq -r '.op_id // empty' /tmp/hub.out)"; HUBOP_POLL="$(jq -r '.poll // empty' /tmp/hub.out)"
  [ -n "$HUBOP_ID" ] && [ -n "$HUBOP_POLL" ] || { echo "FAIL: $1 $2: 202 without op_id / poll: $(head -c 400 /tmp/hub.out)"; return 1; }
}

# hubop <method> <path> [curl args]: start, then wait up to HUBOP_TIMEOUT
# seconds (default 600) for an ok record (→ /tmp/op.json).
hubop() {
  hubop_start "$@" || return 1
  hubop_wait "$HUBOP_POLL" "$HUBOP_ID" "${HUBOP_TIMEOUT:-600}"
}
