# shellcheck shell=bash
#
# Monitoring support (opt-in compose profile `monitoring`, see
# docs/monitoring.md): files the Prometheus / Alertmanager / Grafana
# containers read, the scoped Vault metrics token, and the textfile metrics
# the CLI publishes (backup age, client-cert / CA expiry) through the
# textfile exporter.
#
#   secrets/monitoring/prometheus/    group 65534 (prometheus = nobody)
#     vault-token                     Vault token, policy portcullis-metrics (sys/metrics read only)
#     tls-targets.json                file_sd: the public endpoint whose certificate is probed
#   secrets/monitoring/alertmanager/  group 65534
#     alertmanager.yml                generated from ALERT_* in .env (JSON is valid YAML)
#   secrets/monitoring/grafana/       group 472 (grafana)
#     admin-password                  random; the login form and basic auth are off anyway
#   monitoring/textfile/*.prom        0644, read by the textfile exporter (no secrets)

CT_UID_MONITORING=65534   # prom/prometheus, alertmanager, blackbox, node-exporter: nobody
CT_UID_GRAFANA=472        # grafana/grafana
MONITORING_SECRETS="$PORTCULLIS_ROOT/secrets/monitoring"
MONITORING_TEXTFILE_DIR="${MONITORING_TEXTFILE_DIR:-$PORTCULLIS_ROOT/monitoring/textfile}"
VAULT_METRICS_POLICY="portcullis-metrics"
VAULT_METRICS_POLICY_FILE="$PORTCULLIS_ROOT/vault/policies/metrics.hcl"
VAULT_METRICS_TOKEN_FILE="$MONITORING_SECRETS/prometheus/vault-token"
# The metrics token is recreated by `vault init` when it has less than this left.
VAULT_METRICS_TOKEN_TTL="87600h"        # 10 years
VAULT_METRICS_TOKEN_MIN_LEFT=31536000   # 1 year

# alertmanager_config — Alertmanager configuration (JSON) from .env:
#   ALERT_WEBHOOK_URL   generic webhook (Alertmanager JSON payload)
#   ALERT_NTFY_URL      ntfy topic URL, e.g. https://ntfy.sh/<topic>; sent
#                       with ?template=alertmanager (ntfy formats the alert)
#   ALERT_SMTP_SMARTHOST host:port, ALERT_SMTP_FROM, ALERT_SMTP_TO,
#   ALERT_SMTP_USERNAME, ALERT_SMTP_PASSWORD, ALERT_SMTP_REQUIRE_TLS (true)
# None set → a receiver without integrations (alerts only visible in
# Grafana / Prometheus). Values are JSON-encoded by jq, so any character
# is safe.
alertmanager_config() {
  local ntfy="${ALERT_NTFY_URL:-}"
  if [ -n "$ntfy" ]; then
    case "$ntfy" in *\?*) ntfy="$ntfy&template=alertmanager" ;; *) ntfy="$ntfy?template=alertmanager" ;; esac
  fi
  ALERT_SMTP_PASSWORD="${ALERT_SMTP_PASSWORD:-}" jq -n \
    --arg webhook "${ALERT_WEBHOOK_URL:-}" --arg ntfy "$ntfy" \
    --arg smarthost "${ALERT_SMTP_SMARTHOST:-}" --arg from "${ALERT_SMTP_FROM:-}" --arg to "${ALERT_SMTP_TO:-}" \
    --arg user "${ALERT_SMTP_USERNAME:-}" \
    --arg tls "${ALERT_SMTP_REQUIRE_TLS:-true}" --arg domain "${PORTCULLIS_DOMAIN:-portcullis.local}" '
    def nonempty: . != "";
    ([ (if $webhook | nonempty then {url: $webhook, send_resolved: true} else empty end),
       (if $ntfy | nonempty then {url: $ntfy, send_resolved: true} else empty end) ]) as $hooks
    | (if ($smarthost | nonempty) and ($to | nonempty) then
         [{to: $to, from: (if $from | nonempty then $from else "portcullis@" + $domain end),
           smarthost: $smarthost, require_tls: ($tls != "false"), send_resolved: true}
          + (if $user | nonempty then {auth_username: $user, auth_password: env.ALERT_SMTP_PASSWORD} else {} end)]
       else [] end) as $mails
    | {
        route: {receiver: "portcullis", group_by: ["alertname", "severity"],
                group_wait: "30s", group_interval: "5m", repeat_interval: "4h"},
        receivers: [{name: "portcullis"}
                    + (if ($hooks | length) > 0 then {webhook_configs: $hooks} else {} end)
                    + (if ($mails | length) > 0 then {email_configs: $mails} else {} end)],
        inhibit_rules: [{source_matchers: ["alertname = VaultSealedOrDown"],
                         target_matchers: ["alertname =~ TargetDown|ServiceProbeFailed"]}]
      }'
}

# monitoring_prepare — create/refresh everything the monitoring containers
# mount (run by stack_prepare, so on every init/up/upgrade/restore). Cheap
# and harmless when the profile is not enabled.
monitoring_prepare() {
  local m="$MONITORING_SECRETS" pw
  (umask 077 && mkdir -p "$m/prometheus" "$m/alertmanager" "$m/grafana")
  chmod 700 "$m"
  # tls-targets.json: the public endpoint (Traefik's ACME certificate).
  jq -n --arg d "${PORTCULLIS_DOMAIN:-portcullis.local}" \
    '[{targets: ["auth." + $d + ":443"], labels: {probe: "public-cert"}}]' > "$m/prometheus/tls-targets.json"
  alertmanager_config > "$m/alertmanager/alertmanager.yml.tmp"
  if ! cmp -s "$m/alertmanager/alertmanager.yml.tmp" "$m/alertmanager/alertmanager.yml"; then
    cat "$m/alertmanager/alertmanager.yml.tmp" > "$m/alertmanager/alertmanager.yml"
    # shellcheck disable=SC2034  # read by stack_up (reload)
    MONITORING_ALERTMANAGER_CHANGED=true
  fi
  rm -f "$m/alertmanager/alertmanager.yml.tmp"
  if [ ! -s "$m/grafana/admin-password" ]; then
    pw="$(gen_alnum 32)"
    (umask 077 && printf '%s' "$pw" > "$m/grafana/admin-password")
  fi
  mkdir -p "$MONITORING_TEXTFILE_DIR"
  chmod 755 "$PORTCULLIS_ROOT/monitoring" "$MONITORING_TEXTFILE_DIR" 2>/dev/null || true
  monitoring_fix_perms
}

# monitoring_reload — after `up`: a running Alertmanager re-reads a changed
# config on SIGHUP.
monitoring_reload() {
  [ "${MONITORING_ALERTMANAGER_CHANGED:-false}" = true ] || return 0
  [ -n "$(dc ps -q --status running alertmanager 2>/dev/null)" ] || return 0
  dc kill -s HUP alertmanager >/dev/null 2>&1 && info "Alertmanager reloaded its receivers." || true
}

# monitoring_fix_perms — part of secrets_fix_perms.
monitoring_fix_perms() {
  local m="$MONITORING_SECRETS" f
  [ -d "$m" ] || return 0
  chmod 700 "$m"
  ct_group_read "$CT_UID_MONITORING" "$m/prometheus" "$m/alertmanager"
  for f in "$m"/prometheus/* "$m"/alertmanager/*; do
    [ -f "$f" ] && ct_group_read "$CT_UID_MONITORING" "$f"
  done
  ct_group_read "$CT_UID_GRAFANA" "$m/grafana" "$m/grafana/admin-password"
}

# vault_metrics_token — (re)create the token Prometheus scrapes
# /v1/sys/metrics with: policy portcullis-metrics only (read sys/metrics),
# orphan, no default policy, not renewable, 10-year TTL (the token auth
# mount's max TTL is raised to allow that; every other token keeps its own
# TTL). Kept while it has more than a year left. Uses vexec + the admin
# token in VAULT_TOKEN; secrets go through stdin, never argv.
vault_metrics_token() {
  local f="$VAULT_METRICS_TOKEN_FILE" ttl="" new
  (umask 077 && mkdir -p "$(dirname "$f")")
  vexec policy write "$VAULT_METRICS_POLICY" - < "$VAULT_METRICS_POLICY_FILE" >/dev/null
  if [ -s "$f" ]; then
    ttl="$(vexec write -format=json auth/token/lookup token=- < "$f" 2>/dev/null \
      | jq -r 'select(.data.policies == ["portcullis-metrics"]) | .data.ttl // empty' 2>/dev/null || true)"
  fi
  if [[ "$ttl" =~ ^[0-9]+$ ]] && [ "$ttl" -gt "$VAULT_METRICS_TOKEN_MIN_LEFT" ]; then
    ok "Vault metrics token is valid."
    return 0
  fi
  vexec write sys/auth/token/tune max_lease_ttl="$VAULT_METRICS_TOKEN_TTL" >/dev/null
  new="$(vexec token create -policy="$VAULT_METRICS_POLICY" -no-default-policy -orphan \
    -renewable=false -ttl="$VAULT_METRICS_TOKEN_TTL" -display-name=prometheus -field=token)" \
    || fail "could not create the Vault metrics token"
  [ ! -s "$f" ] || vexec write auth/token/revoke token=- < "$f" >/dev/null 2>&1 || true
  _write_secret "$f" "$new"
  ct_group_read "$CT_UID_MONITORING" "$f"
  ok "Issued the Vault metrics token ($f, policy $VAULT_METRICS_POLICY)."
}

# metrics_textfile_write <name> — stdin → monitoring/textfile/<name>.prom,
# atomically (the exporter only reads *.prom).
metrics_textfile_write() {
  local d="$MONITORING_TEXTFILE_DIR" tmp
  mkdir -p "$d" 2>/dev/null || return 0
  tmp="$d/.$1.prom.tmp"
  cat > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$d/$1.prom"
}

# metrics_label <value> — escape for a Prometheus label value.
metrics_label() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\n'; }
