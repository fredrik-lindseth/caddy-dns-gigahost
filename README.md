# Gigahost module for Caddy

This package contains a DNS provider module for [Caddy](https://github.com/caddyserver/caddy). It can be used to manage DNS records with [Gigahost](https://gigahost.no) accounts.

## Caddy module name

```
dns.providers.gigahost
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

This module uses Gigahost account credentials (username and password) to authenticate with the [Gigahost API](https://gigahost.no/api-dokumentasjon). If your account has two-factor authentication enabled, you can also provide a TOTP code:

```
tls {
    dns gigahost {
        username {env.GIGAHOST_USERNAME}
        password {env.GIGAHOST_PASSWORD}
        totp_code {env.GIGAHOST_TOTP}
    }
}
```

**Note:** TOTP codes are time-based and expire quickly. For automated setups, consider using an API-compatible TOTP generator or disabling 2FA for the API account.

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
