# Gigahost module for Caddy

This package contains a DNS provider module for [Caddy](https://github.com/caddyserver/caddy). It can be used to manage DNS records with [Gigahost](https://gigahost.no) accounts.

## Caddy module name

```
dns.providers.gigahost
```

## Gigahost name servers

If you're pointing your domain to Gigahost, use the following name servers:

```
ns1.gigahost.no
ns2.gigahost.no
ns3.gigahost.no
```

## Config examples

To use this module for the ACME DNS challenge, [configure the ACME issuer in your Caddy JSON](https://caddyserver.com/docs/json/apps/tls/automation/policies/issuer/acme/) like so:

```json
{
    "module": "acme",
    "challenges": {
        "dns": {
            "provider": {
                "name": "gigahost",
                "username": "{env.GIGAHOST_USERNAME}",
                "password": "{env.GIGAHOST_PASSWORD}"
            }
        }
    }
}
```

or with the Caddyfile:

```
your.domain.no {
    respond "Hello World"
    tls {
        dns gigahost {
            username {env.GIGAHOST_USERNAME}
            password {env.GIGAHOST_PASSWORD}
        }
    }
}
```

You can replace the environment variable placeholders with actual values if you prefer.

## Authenticating

This module authenticates with the [Gigahost API](https://gigahost.no/api-dokumentasjon) using your regular Gigahost account credentials — the same username and password you use to log in to [flux.gigahost.no](https://flux.gigahost.no). The Gigahost API does not have separate API keys; it uses your account credentials directly.

The module sends a `POST` to `/authenticate` with your credentials and receives a bearer token that is cached and automatically refreshed before it expires.

### Basic setup (recommended)

```
tls {
    dns gigahost {
        username {env.GIGAHOST_USERNAME}
        password {env.GIGAHOST_PASSWORD}
    }
}
```

### Creating a dedicated API user (best practice)

For production use, create a dedicated Gigahost contact/user without 2FA:

1. Log in to [flux.gigahost.no](https://flux.gigahost.no)
2. Go to **Account** → **Contacts**
3. Click **Add new user**
4. Fill in:
   - **Name**: e.g., "Caddy DNS API"
   - **Email**: a valid email address
   - **Access level**: Select **Administrator** (required for DNS API access)
5. **Do NOT enable 2FA** for this user
6. Use this user's credentials in your Caddy configuration

### With two-factor authentication

If your Gigahost account has 2FA enabled, you can provide a TOTP code:

```
tls {
    dns gigahost {
        username {env.GIGAHOST_USERNAME}
        password {env.GIGAHOST_PASSWORD}
        totp_code {env.GIGAHOST_TOTP}
    }
}
```

> **⚠️ 2FA is problematic for automated setups.** TOTP codes rotate every 30 seconds. Caddy runs as a long-lived daemon and needs to re-authenticate whenever the token expires. This means you would need a way to continuously generate fresh TOTP codes and feed them to Caddy, which is impractical for most setups.
>
> **Recommended approach:** Use a dedicated API user without 2FA (see "Creating a dedicated API user" above).
## Building

### Build a Caddy Docker image

```bash
docker build -t caddy-with-gigahost-dns .
```

### Building a Caddy binary using xcaddy

Install [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

Then build Caddy:

```bash
xcaddy build \
    --with github.com/caddy-dns/gigahost@master
```
