# Configuring a SAML App: Nextcloud

This guide shows how to add Nextcloud as a SAML-authenticated application behind
Portcullis. The same pattern applies to any SAML-capable application.

## Overview

```
User (YubiKey) → Traefik (mTLS) → Nextcloud
                                      │
                                      ▼ SAML SSO
                                   Keycloak (IdP)
                                      │
                                      ▼ user lookup
                                    LLDAP
```

The user taps their YubiKey to pass through Traefik. Nextcloud then uses SAML
to verify the user's identity via Keycloak, which looks up users in LLDAP.

## Step 1: Deploy Nextcloud

Create a `docker-compose.nextcloud.yml` (or add to your existing compose file):

```yaml
services:
  nextcloud:
    image: nextcloud:29-apache
    environment:
      NEXTCLOUD_ADMIN_USER: admin
      NEXTCLOUD_ADMIN_PASSWORD: ${NEXTCLOUD_ADMIN_PASSWORD:-changeme}
      NEXTCLOUD_TRUSTED_DOMAINS: "nextcloud.${PORTCULLIS_DOMAIN:-portcullis.local}"
      POSTGRES_HOST: nextcloud-db
      POSTGRES_DB: nextcloud
      POSTGRES_USER: nextcloud
      POSTGRES_PASSWORD: ${NEXTCLOUD_DB_PASSWORD:-changeme}
    volumes:
      - nextcloud_data:/var/www/html
    networks:
      - portcullis
    labels:
      traefik.enable: "true"
      traefik.http.routers.nextcloud.rule: Host(`nextcloud.${PORTCULLIS_DOMAIN:-portcullis.local}`)
      traefik.http.routers.nextcloud.entrypoints: websecure
      traefik.http.routers.nextcloud.tls.options: protected
      traefik.http.routers.nextcloud.middlewares: client-headers@file,security-headers@file,nextcloud-redirectregex
      traefik.http.services.nextcloud.loadbalancer.server.port: "80"
      # Nextcloud-specific: redirect CalDAV/CardDAV
      traefik.http.middlewares.nextcloud-redirectregex.redirectregex.regex: "https://(.*)/.well-known/(?:card|cal)dav"
      traefik.http.middlewares.nextcloud-redirectregex.redirectregex.replacement: "https://$${1}/remote.php/dav/"
      traefik.http.middlewares.nextcloud-redirectregex.redirectregex.permanent: "true"
    depends_on:
      - nextcloud-db

  nextcloud-db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: nextcloud
      POSTGRES_USER: nextcloud
      POSTGRES_PASSWORD: ${NEXTCLOUD_DB_PASSWORD:-changeme}
    volumes:
      - nextcloud_db:/var/lib/postgresql/data
    networks:
      - portcullis

networks:
  portcullis:
    external: true

volumes:
  nextcloud_data:
  nextcloud_db:
```

Start it:

```bash
docker compose -f docker-compose.nextcloud.yml up -d
```

Nextcloud should now be accessible at `https://nextcloud.<your-domain>` (with
YubiKey authentication required by Traefik).

## Step 2: Register Nextcloud as a SAML Client in Keycloak

### 2a. Open Keycloak Admin

Go to `https://auth.<your-domain>/admin/` and log in with your admin credentials.

Select the **portcullis** realm from the dropdown in the top left.

### 2b. Create a new SAML Client

1. Navigate to **Clients** → **Create client**
2. Set:
   - **Client type**: SAML
   - **Client ID**: `https://nextcloud.<your-domain>/apps/user_saml/saml/metadata`
   - Click **Next**
3. On the next screen:
   - **Name**: Nextcloud
   - **Root URL**: `https://nextcloud.<your-domain>`
   - **Valid redirect URIs**: `https://nextcloud.<your-domain>/*`
   - Click **Save**

### 2c. Configure SAML settings

In the client settings, go to the **Settings** tab:

- **Name ID format**: username
- **Force name ID format**: ON
- **Sign assertions**: ON
- **Signature algorithm**: RSA_SHA256
- **SAML signature key name**: KEY_ID

Go to the **Keys** tab:
- **Client signature required**: OFF (unless Nextcloud is configured to sign requests)

### 2d. Add attribute mappers

Go to **Client scopes** → click the client's dedicated scope → **Add mapper** → **By configuration**:

**Email mapper:**
- Mapper type: User Property
- Name: `email`
- Property: `email`
- SAML Attribute Name: `urn:oid:0.9.2342.19200300.100.1.3`
- SAML Attribute NameFormat: URI Reference

**Username mapper:**
- Mapper type: User Property
- Name: `username`
- Property: `username`
- SAML Attribute Name: `urn:oid:0.9.2342.19200300.100.1.1`
- SAML Attribute NameFormat: URI Reference

**Display name mapper:**
- Mapper type: User Property
- Name: `displayName`
- Property: `firstName`
- SAML Attribute Name: `urn:oid:2.16.840.1.113730.3.1.241`
- SAML Attribute NameFormat: URI Reference

### 2e. Note the IdP metadata URL

You'll need this for Nextcloud:

```
https://auth.<your-domain>/realms/portcullis/protocol/saml/descriptor
```

## Step 3: Configure Nextcloud for SAML

### 3a. Enable the SAML app

Log into Nextcloud as admin, then:

1. Go to **Apps** → search for "SSO & SAML authentication"
2. Enable the **SSO & SAML authentication** app

Or via CLI:

```bash
docker compose -f docker-compose.nextcloud.yml exec nextcloud \
  php occ app:enable user_saml
```

### 3b. Configure SAML in Nextcloud

Go to **Administration settings** → **SSO & SAML authentication**:

**General:**
- **Attribute to map the UID to**: `urn:oid:0.9.2342.19200300.100.1.1`
- Check "Only allow authentication if an account exists on some other backend (e.g. LDAP)"
  if you want to require users to exist in LDAP first

**Identity Provider Data:**
- **Identifier of the IdP entity**: `https://auth.<your-domain>/realms/portcullis`
- **URL target of the IdP where the SP will send the Authentication Request**:
  `https://auth.<your-domain>/realms/portcullis/protocol/saml`
- **URL Location of IdP where the SP will send the SLO Request**:
  `https://auth.<your-domain>/realms/portcullis/protocol/saml`
- **Public X.509 certificate of the IdP**:
  Download from `https://auth.<your-domain>/realms/portcullis/protocol/saml/descriptor`,
  extract the `<ds:X509Certificate>` value, and paste it here.

**Service Provider Data:**
- **Identifier of the SP entity**:
  `https://nextcloud.<your-domain>/apps/user_saml/saml/metadata`
- Leave other SP fields at defaults

**Attribute mapping:**
- **Attribute to map the displayname to**: `urn:oid:2.16.840.1.113730.3.1.241`
- **Attribute to map the email address to**: `urn:oid:0.9.2342.19200300.100.1.3`

Click **Save**.

### 3c. Test SAML login

1. Open a private/incognito window
2. Go to `https://nextcloud.<your-domain>`
3. You should see a "Login with SSO" button (or be redirected automatically)
4. Keycloak authenticates via your client certificate (YubiKey tap already happened at Traefik)
5. You're logged into Nextcloud

## Step 4: Optional — LDAP User Backend

For richer user integration (groups, quotas, etc.), you can also configure
Nextcloud's LDAP backend to read from LLDAP directly:

1. Enable the LDAP app: **Apps** → **LDAP user and group backend**
2. Configure:
   - **Host**: `lldap` (Docker service name)
   - **Port**: `3890`
   - **User DN**: `uid=admin,ou=people,dc=portcullis,dc=local` (use your base DN)
   - **Password**: your LLDAP admin password
   - **Base DN**: `dc=portcullis,dc=local`
3. Under **Users** tab:
   - **Object classes**: `person`
4. Under **Login Attributes** tab:
   - **LDAP/AD Username**: `uid`
   - **LDAP/AD Email**: `mail`
5. Under **Groups** tab:
   - **Object classes**: `groupOfUniqueNames`

This way, users and groups from LLDAP appear directly in Nextcloud, and SAML
handles the authentication flow.

## Troubleshooting

### "Invalid signature" on SAML response

- Ensure the IdP certificate in Nextcloud matches the one from Keycloak's SAML descriptor
- Check that "Sign assertions" is ON in the Keycloak client config

### User not found after SAML login

- Verify the UID attribute mapping matches between Keycloak and Nextcloud
- Check that the user exists in LLDAP and has synced to Keycloak:
  Keycloak admin → Users → search for the username

### SAML loop / redirect issues

- Ensure `NEXTCLOUD_TRUSTED_DOMAINS` includes your full domain
- Check that the Nextcloud entity ID in Keycloak matches exactly:
  `https://nextcloud.<domain>/apps/user_saml/saml/metadata`
- Verify the ACS URL is correct in Keycloak's Valid Redirect URIs

### Mixed content / proxy issues

Add to Nextcloud's `config.php` (via volume or exec):

```php
'overwriteprotocol' => 'https',
'overwrite.cli.url' => 'https://nextcloud.<your-domain>',
'trusted_proxies' => ['172.16.0.0/12', '10.0.0.0/8'],
```
