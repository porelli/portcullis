#!/usr/bin/env bash
# ci.yml job e2e-fxa, step "Mail's certificate trusted like a public one".
# fxa-auth (NODE_EXTRA_CA_CERTS) and the Hub (its sender) check the mail
# server's certificate against certs/ca-bundle.crt: the host's system CAs,
# Portcullis's CA (and Let's Encrypt staging with ACME_STAGING=true). In CI
# mail-cert's issuer is Pebble, whose root (/tmp/e2e-pebble-root.pem,
# fetched by the start script) goes into the runner's system trust store,
# then `config apply --bundle-only`: the documented way for a mail server
# with its own CA. Checked: STARTTLS on 587 with mail.<d>'s name verifies
# against the bundle.
set -euo pipefail
grep -q 'BEGIN CERTIFICATE' /tmp/e2e-pebble-root.pem || { echo "FAIL: no Pebble root"; exit 1; }
sudo cp /tmp/e2e-pebble-root.pem /usr/local/share/ca-certificates/e2e-pebble-root.crt
sudo update-ca-certificates >/dev/null
./portcullis config apply --bundle-only
out="$(openssl s_client -connect 127.0.0.1:587 -starttls smtp -servername "mail.$E2E_DOMAIN" -verify_hostname "mail.$E2E_DOMAIN" \
  -CAfile certs/ca-bundle.crt -verify_return_error </dev/null 2>&1 || true)"
grep -q 'Verify return code: 0 (ok)' <<<"$out" \
  || { echo "FAIL: mail.$E2E_DOMAIN:587 doesn't verify against certs/ca-bundle.crt: $(grep -E 'verify|Verify|error' <<<"$out" | head -5)"; exit 1; }
echo "PASS: mail.$E2E_DOMAIN's STARTTLS certificate verifies against certs/ca-bundle.crt (Pebble's root in the system store)"
