#!/bin/sh
# Patch CloudBeaver's persisted runtime config to enable reverse proxy auth.
# The GlobalConfiguration only applies on first run; after the setup wizard,
# .data/.cloudbeaver.runtime.conf takes precedence with reverseProxy disabled.

RUNTIME_CONF="/opt/cloudbeaver/workspace/.data/.cloudbeaver.runtime.conf"

if [ -f "$RUNTIME_CONF" ]; then
  # Enable reverse proxy auth flag
  sed -i 's/"enableReverseProxyAuth": false/"enableReverseProxyAuth": true/' "$RUNTIME_CONF"

  # Add reverseProxy to enabledAuthProviders if empty
  sed -i 's/"enabledAuthProviders": \[\]/"enabledAuthProviders": ["reverseProxy"]/' "$RUNTIME_CONF"

  # Check if authConfigurations block exists
  if ! grep -q '"authConfigurations"' "$RUNTIME_CONF"; then
    # Insert authConfigurations before the last closing brace of "app"
    sed -i '/"enabledAuthProviders"/a\
    ,"authConfigurations": [{"id":"portcullis-proxy","provider":"reverseProxy","displayName":"Portcullis SSO","disabled":false,"parameters":{"user-header":"X-Forwarded-User","first-name-header":"","last-name-header":"","team-header":"","team-delimiter":"|"}}]' "$RUNTIME_CONF"
  fi

  echo "entrypoint: reverse proxy auth config patched"
fi

exec ./launch-product.sh
