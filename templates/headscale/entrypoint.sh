#!/bin/sh
CONFIG="/etc/headscale/config.yaml"
TEMPLATE="/etc/headscale/config.yaml.tmpl"

if [ ! -f "$CONFIG" ]; then
  echo "Generating headscale config from template..."
  sed \
    -e "s|PORTCULLIS_DOMAIN_PLACEHOLDER|${PORTCULLIS_DOMAIN}|g" \
    -e "s|HEADSCALE_OIDC_SECRET_PLACEHOLDER|${HEADSCALE_OIDC_CLIENT_SECRET}|g" \
    "$TEMPLATE" > "$CONFIG"
  echo "Config generated."
fi

exec headscale serve "$@"
