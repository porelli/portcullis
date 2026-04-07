#!/bin/sh
# Render traefik.yml from template with environment variables, then start Traefik.
sed -e "s|\${PORTCULLIS_DOMAIN}|${PORTCULLIS_DOMAIN}|g" \
    -e "s|\${ACME_EMAIL}|${ACME_EMAIL}|g" \
    -e "s|\${ACME_CA_SERVER}|${ACME_CA_SERVER}|g" \
    -e "s|\${DNS_PROVIDER}|${DNS_PROVIDER}|g" \
    /etc/traefik/traefik.yml.tpl > /etc/traefik/traefik.yml
exec traefik "$@"
