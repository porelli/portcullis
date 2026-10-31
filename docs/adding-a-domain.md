# Adding a New Domain

This guide covers how to configure Portcullis to serve applications under your domain.

## Prerequisites

- A domain you control (e.g., `example.com`)
- DNS hosted on a supported provider (Cloudflare, Porkbun, Route53, DigitalOcean, Hetzner, or [any lego provider](https://doc.traefik.io/traefik/https/acme/#providers))
- A server with a public IP running Portcullis

## Step 1: Configure DNS

### Option A: Wildcard DNS record (recommended)

Create a single wildcard A record pointing all subdomains to your server:

```
*.portcullis.example.com  A  203.0.113.10
```

This means `auth.portcullis.example.com`, `directory.portcullis.example.com`,
`grafana.portcullis.example.com`, etc. all resolve to your server without
creating individual records.

In Cloudflare:
1. Go to your zone's DNS settings
2. Add record: Type `A`, Name `*.portcullis`, Content `<your server IP>`
3. **Disable the orange cloud (proxy)** — Cloudflare's proxy interferes with mTLS

You also need a record for the bare subdomain (for redirect purposes):

```
portcullis.example.com    A  203.0.113.10
```

### Option B: Individual DNS records

If you prefer explicit records, create one for each service:

```
auth.portcullis.example.com       A  203.0.113.10
directory.portcullis.example.com  A  203.0.113.10
enroll.portcullis.example.com     A  203.0.113.10
traefik.portcullis.example.com    A  203.0.113.10
```

You'll need to add a record each time you add a new service.

`./portcullis dns setup` creates the A/AAAA records for the domain and its
wildcard with the provider's API (Cloudflare, Porkbun, …; see `--help`).

## Step 2: Create DNS Provider API Token

Portcullis needs a DNS API token to solve ACME DNS-01 challenges for the
wildcard certificate. Only `*.portcullis.example.com` appears in Certificate
Transparency logs — individual subdomain names are never leaked.

### Cloudflare

1. Go to https://dash.cloudflare.com/profile/api-tokens
2. Click "Create Token" → "Edit zone DNS" template
3. **Permissions**: Zone > DNS > Edit
4. Set in `.env`: `DNS_PROVIDER=cloudflare` and `CLOUDFLARE_API_TOKEN=your-token`

### Porkbun

1. Go to https://porkbun.com/account/api
2. Enable API access for your domain
3. Create API key + secret key
4. Set in `.env`:
   ```
   DNS_PROVIDER=porkbun
   PORKBUN_API_KEY=pk1_...
   PORKBUN_SECRET_API_KEY=sk1_...
   ```

### AWS Route 53

```
DNS_PROVIDER=route53
AWS_ACCESS_KEY_ID=your-key
AWS_SECRET_ACCESS_KEY=your-secret
AWS_HOSTED_ZONE_ID=Z1234567890
```

### DigitalOcean

```
DNS_PROVIDER=digitalocean
DO_AUTH_TOKEN=your-token
```

### Hetzner

```
DNS_PROVIDER=hetzner
HETZNER_API_KEY=your-key
```

### Other Providers

Traefik supports 80+ DNS providers via [lego](https://doc.traefik.io/traefik/https/acme/#providers).
Set `DNS_PROVIDER=<lego-provider-name>` and its required env vars in `.env`.

## Step 3: Configure Portcullis

### First-time setup

`portcullis init` prompts for your domain, email and DNS provider (the
provider's API credentials are read with a hidden prompt, or from the
environment):

```bash
./portcullis init
# or unattended:
PORKBUN_API_KEY=pk1_... PORKBUN_SECRET_API_KEY=sk1_... \
  ./portcullis init --non-interactive --domain portcullis.example.com --dns-provider porkbun
```

### If updating an existing installation

Edit `.env`:

```bash
PORTCULLIS_DOMAIN=portcullis.example.com
ACME_EMAIL=admin@example.com
DNS_PROVIDER=porkbun
PORKBUN_API_KEY=pk1_...
PORKBUN_SECRET_API_KEY=sk1_...
LLDAP_BASE_DN=dc=portcullis,dc=example,dc=com
```

Then restart services (and refresh the Keycloak redirect URI for the new
domain):

```bash
./portcullis down
./portcullis up
./portcullis keycloak configure
```

Traefik will automatically request and renew the wildcard certificate.

## Step 4: Verify

Check that the certificate was issued:

```bash
# Check Traefik logs for ACME
docker compose logs traefik | grep -i acme

# Test with curl
curl -v https://auth.portcullis.example.com 2>&1 | grep "subject:"
```

You should see a Let's Encrypt certificate for `*.portcullis.example.com`.

## Using a Different DNS Provider

Portcullis supports any DNS provider that Traefik/lego supports. Traefik is
configured entirely through environment variables in `docker-compose.yml`
(there is no `traefik.yml`): set `DNS_PROVIDER` in `.env` and the
provider's required env vars.

For the full list of 80+ providers, see the
[Traefik ACME DNS providers documentation](https://doc.traefik.io/traefik/https/acme/#providers).

If your provider's env vars aren't already in `docker-compose.yml`, add them to
the traefik service's `environment` section in a `docker-compose.override.yml`.

## One domain per installation

A Portcullis installation serves exactly one base domain,
`PORTCULLIS_DOMAIN`: every app lives at `<subdomain>.${PORTCULLIS_DOMAIN}`.
This is enforced, not just a default:

- group-gate denies every request whose host is not exactly
  `<label>.${PORTCULLIS_DOMAIN}` (it looks policies and groups up by that
  label);
- the Hub rejects templates whose routers use any other domain
  (integration contract §4);
- Traefik requests one wildcard certificate (`${PORTCULLIS_DOMAIN}` +
  `*.${PORTCULLIS_DOMAIN}`), oauth2-proxy's cookie and redirect whitelist
  cover `.${PORTCULLIS_DOMAIN}` only, and Keycloak's hostname is
  `auth.${PORTCULLIS_DOMAIN}`.

To serve a second domain, run a second installation. Supporting several
domains in one installation would need: group-gate keyed by full host (or a
domain list), the Hub's host validation and policy file keyed the same way,
a certificate (and DNS records) per domain, oauth2-proxy cookies per domain
(a session cookie cannot span unrelated domains, so users would sign in per
domain), and Keycloak redirect URIs for each.

## Local Development (No Public Domain)

For local development without a real domain or ACME:

1. Set `PORTCULLIS_DOMAIN=portcullis.local` in `.env`
2. Run `./portcullis init` (it also issues a self-signed wildcard server cert for local use)
3. Add entries to `/etc/hosts`:

```
127.0.0.1  auth.portcullis.local directory.portcullis.local enroll.portcullis.local traefik.portcullis.local
```

4. Import `certs/root-ca.crt` into your browser/OS trust store to avoid certificate warnings

Note: mTLS with client certificates works the same way locally — the only
difference is the server certificate is self-signed instead of from Let's Encrypt.
