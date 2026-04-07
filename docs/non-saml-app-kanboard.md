# Configuring a Non-SAML App: Kanboard

This guide shows how to add Kanboard (a project management tool) behind Portcullis
using mTLS identity headers instead of SAML. This pattern works for any app that
can read HTTP headers for authentication — no SAML or OIDC support needed.

## Overview

```
User (YubiKey) → Traefik (mTLS) → Kanboard
                     │
                     └── X-Forwarded-Tls-Client-Cert-Info: Subject="CN=alice"...
```

Traefik verifies the client certificate and passes the user's identity as HTTP
headers to the backend. Kanboard reads these headers and logs the user in
automatically. No redirect to Keycloak, no SAML dance — the authentication
already happened at the TLS layer.

## Step 1: Deploy Kanboard

Create a `docker-compose.kanboard.yml`:

```yaml
services:
  kanboard:
    image: kanboard/kanboard:latest
    environment:
      # Enable reverse proxy authentication
      PLUGIN_INSTALLER: "true"
    volumes:
      - kanboard_data:/var/www/app/data
      - kanboard_plugins:/var/www/app/plugins
      - ./kanboard/config.php:/var/www/app/config.php:ro
    networks:
      - portcullis
    labels:
      traefik.enable: "true"
      traefik.http.routers.kanboard.rule: Host(`kanboard.${PORTCULLIS_DOMAIN:-portcullis.local}`)
      traefik.http.routers.kanboard.entrypoints: websecure
      traefik.http.routers.kanboard.tls.options: protected
      traefik.http.routers.kanboard.middlewares: client-headers@file,security-headers@file
      traefik.http.services.kanboard.loadbalancer.server.port: "80"

networks:
  portcullis:
    external: true

volumes:
  kanboard_data:
  kanboard_plugins:
```

## Step 2: Configure Kanboard for Reverse Proxy Auth

Create `kanboard/config.php`:

```php
<?php

// Enable reverse proxy authentication
define('REVERSE_PROXY_AUTH', true);

// The header that contains the authenticated username.
// Traefik's passTLSClientCert middleware sends the full cert info in
// X-Forwarded-Tls-Client-Cert-Info. We need to extract the CN.
//
// Option A: Use a custom header set by a middleware (see Step 3).
define('REVERSE_PROXY_USER_HEADER', 'X-Portcullis-User');

// Default admin username (must match a CN in your directory)
define('REVERSE_PROXY_DEFAULT_ADMIN', 'admin');

// Automatically create users that don't exist in Kanboard's local DB
define('REVERSE_PROXY_DEFAULT_DOMAIN', '');

// LDAP for user/group sync (optional but recommended)
define('LDAP_AUTH', true);
define('LDAP_SERVER', 'lldap');
define('LDAP_PORT', 3890);
define('LDAP_START_TLS', false);
define('LDAP_USERNAME_CASE_SENSITIVE', false);
define('LDAP_BIND_TYPE', 'proxy');
define('LDAP_USERNAME', 'uid=admin,ou=people,dc=portcullis,dc=local');
define('LDAP_PASSWORD', 'changeme');  // Use your LLDAP admin password
define('LDAP_USER_BASE_DN', 'ou=people,dc=portcullis,dc=local');
define('LDAP_USER_FILTER', 'uid=%s');
define('LDAP_USER_ATTRIBUTE_USERNAME', 'uid');
define('LDAP_USER_ATTRIBUTE_FULLNAME', 'cn');
define('LDAP_USER_ATTRIBUTE_EMAIL', 'mail');
define('LDAP_GROUP_ADMIN_DN', 'cn=admins,ou=groups,dc=portcullis,dc=local');

// Group sync
define('LDAP_GROUP_PROVIDER', true);
define('LDAP_GROUP_BASE_DN', 'ou=groups,dc=portcullis,dc=local');
define('LDAP_GROUP_FILTER', '');
define('LDAP_GROUP_ATTRIBUTE_NAME', 'cn');
```

**Important**: Replace `dc=portcullis,dc=local` with your actual `LLDAP_BASE_DN`
and `changeme` with your LLDAP admin password.

## Step 3: Extract Username from Traefik's Header

Traefik's `passTLSClientCert` middleware sends cert info in a URL-encoded header
like:

```
X-Forwarded-Tls-Client-Cert-Info: Subject="CN=alice,O=Portcullis";Issuer="CN=portcullis.local Intermediate CA";Serial="..."
```

Most apps can't parse this natively. We have two options:

### Option A: Traefik middleware plugin (cleanest)

Use the [Header Transformation middleware](https://doc.traefik.io/traefik/middlewares/http/headers/)
to add a simple header. Add to `traefik/dynamic/middlewares.yml`:

```yaml
http:
  middlewares:
    # ... existing middlewares ...

    # Extract CN from client cert and set as a simple header.
    # Use with apps that need a plain username header.
    portcullis-user:
      plugin:
        rewriteHeaders:
          rewrites:
            - header: X-Forwarded-Tls-Client-Cert-Info
              regex: '.*CN=([^,;"]+).*'
              replacement: "$1"
              headerOut: X-Portcullis-User
```

> Note: This requires the `rewriteHeaders` Traefik plugin. If not available,
> use Option B.

### Option B: Small sidecar (more portable)

Add a tiny middleware container that parses the header. Or, simpler — many apps
can be configured to parse the full header themselves.

### Option C: Parse in the app

If the app allows custom header parsing (e.g., via a plugin or custom code),
parse the `X-Forwarded-Tls-Client-Cert-Info` header directly to extract the CN.

For Kanboard specifically, you can write a small plugin or use the built-in
reverse proxy auth with a Lua/nginx sidecar.

### Simplest approach for Kanboard

Since Kanboard's reverse proxy auth reads a single header for the username,
the simplest production approach is a small nginx sidecar:

Add to your `docker-compose.kanboard.yml`:

```yaml
services:
  kanboard-proxy:
    image: nginx:alpine
    volumes:
      - ./kanboard/nginx.conf:/etc/nginx/conf.d/default.conf:ro
    networks:
      - portcullis
    labels:
      traefik.enable: "true"
      traefik.http.routers.kanboard.rule: Host(`kanboard.${PORTCULLIS_DOMAIN:-portcullis.local}`)
      traefik.http.routers.kanboard.entrypoints: websecure
      traefik.http.routers.kanboard.tls.options: protected
      traefik.http.routers.kanboard.middlewares: client-headers@file,security-headers@file
      traefik.http.services.kanboard.loadbalancer.server.port: "80"

  kanboard:
    image: kanboard/kanboard:latest
    # Remove traefik labels from kanboard itself — the proxy handles routing
    volumes:
      - kanboard_data:/var/www/app/data
      - ./kanboard/config.php:/var/www/app/config.php:ro
    networks:
      - portcullis
```

Create `kanboard/nginx.conf`:

```nginx
server {
    listen 80;

    location / {
        # Extract CN from Traefik's cert info header
        set $client_cn "";
        if ($http_x_forwarded_tls_client_cert_info ~* "CN=([^,;\"]+)") {
            set $client_cn $1;
        }

        proxy_pass http://kanboard:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        # Pass the extracted username as a simple header
        proxy_set_header X-Portcullis-User $client_cn;
    }
}
```

## Step 4: Start Kanboard

```bash
docker compose -f docker-compose.kanboard.yml up -d
```

Visit `https://kanboard.<your-domain>` — tap your YubiKey, and you'll be logged
in automatically as the user matching your certificate's CN.

## Step 5: Create an Admin User

The first time, you need to bootstrap an admin user in Kanboard:

1. In LLDAP, create a user (e.g., `admin`) if not already present
2. Enroll their YubiKey with `./scripts/enroll-yubikey.sh admin admin@example.com`
3. Visit Kanboard with that cert — the user is created automatically
4. If you configured `REVERSE_PROXY_DEFAULT_ADMIN`, that user gets admin rights

## General Pattern for Non-SAML Apps

This pattern works for any app that supports "reverse proxy authentication"
or "trusted header authentication":

| App | Auth Header Config |
|-----|-------------------|
| **Kanboard** | `REVERSE_PROXY_USER_HEADER` |
| **Gitea** | `[service] ENABLE_REVERSE_PROXY_AUTHENTICATION = true` + `REVERSE_PROXY_AUTHENTICATION_USER = X-Portcullis-User` |
| **Grafana** | `[auth.proxy] enabled = true` + `header_name = X-Portcullis-User` |
| **Wiki.js** | Authentication → Header strategy → `X-Portcullis-User` |
| **Portainer** | Not supported natively — use OIDC via Keycloak instead |
| **Uptime Kuma** | Not supported — use Keycloak OIDC or accept mTLS as the auth boundary |
| **pgAdmin** | `AUTHENTICATION_SOURCES = ['webserver']` + `WEBSERVER_REMOTE_USER = X-Portcullis-User` |

### If the app has no header auth support

Some apps don't support trusted header authentication at all. For these, use
Keycloak as an OIDC provider instead:

1. Register the app as an OIDC client in Keycloak
2. Configure the app's OIDC settings to point to:
   - Issuer: `https://auth.<domain>/realms/portcullis`
   - The user is already authenticated at the mTLS layer, so Keycloak will
     issue tokens without prompting for credentials

See also: [SAML App Configuration (Nextcloud)](saml-app-nextcloud.md) for
the SAML equivalent.

## Troubleshooting

### User shows as blank / anonymous

- Check that the `X-Forwarded-Tls-Client-Cert-Info` header reaches the app:
  ```bash
  curl -v --cert /tmp/client.crt --key /tmp/client.key \
    https://kanboard.<domain>/
  ```
- Verify the nginx sidecar is correctly extracting the CN
- Check the header name matches what the app expects

### User not found / not created

- Ensure `REVERSE_PROXY_AUTH` is `true` in Kanboard's config
- If using LDAP sync, verify the LDAP connection details match your LLDAP setup
- Check that the CN in the certificate matches the `uid` in LLDAP

### 403 from Traefik

- The `protected` TLS option requires a valid client cert
- Verify the cert was issued by your Vault CA and hasn't expired:
  ```bash
  ykman piv certificates export 9a - | openssl x509 -text -noout
  ```

### Header spoofing concerns

Traefik's `client-headers@file` middleware sets the `X-Forwarded-Tls-Client-Cert-Info`
header based on the actual TLS handshake — it cannot be spoofed by the client.
The nginx sidecar then extracts the CN from this trusted header. Ensure that
your backend only accepts connections from the Docker network, not directly
from the internet.
