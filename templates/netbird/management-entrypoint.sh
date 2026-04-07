#!/bin/sh
CONFIG="/etc/netbird/management.json"
TEMPLATE="/etc/netbird/management.json.tmpl"

if [ ! -f "$CONFIG" ]; then
  echo "Generating management.json from template..."
  NETBIRD_DOMAIN="netbird.${PORTCULLIS_DOMAIN}"
  TURN_HOST="${COTURN_EXTERNAL_IP:-${NETBIRD_DOMAIN}}"
  sed \
    -e "s|\${PORTCULLIS_DOMAIN}|${PORTCULLIS_DOMAIN}|g" \
    -e "s|\${NETBIRD_DOMAIN}|${NETBIRD_DOMAIN}|g" \
    -e "s|\${TURN_HOST}|${TURN_HOST}|g" \
    -e "s|\${COTURN_AUTH_SECRET}|${COTURN_AUTH_SECRET}|g" \
    -e "s|\${NETBIRD_OIDC_CLIENT_SECRET}|${NETBIRD_OIDC_CLIENT_SECRET}|g" \
    "$TEMPLATE" > "$CONFIG"
  echo "Config generated:"
  cat "$CONFIG"
else
  echo "management.json already exists, skipping generation."
fi

exec /go/bin/netbird-mgmt management "$@"
