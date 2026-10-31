# Prometheus scrape token (monitoring profile, docs/monitoring.md).
# Created by ./portcullis vault init as an orphan token with ONLY this
# policy (no `default`), stored in secrets/monitoring/prometheus/vault-token.
path "sys/metrics" {
  capabilities = ["read"]
}
