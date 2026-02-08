# Agent Context: caddy-dns-gigahost

## What this is

A Caddy DNS provider module for [Gigahost](https://gigahost.no), a Norwegian hosting provider. It lets Caddy automatically manage DNS records (primarily for ACME DNS-01 challenges to get TLS certificates) via the Gigahost API.

## Gigahost name servers

```
ns1.gigahost.no
ns2.gigahost.no
ns3.gigahost.no
```

## Architecture

```
gigahost.go              ← Caddy module wrapper (registration, Caddyfile parsing, placeholder resolution)
gigahost_test.go         ← Tests for the Caddy module layer

provider/
  provider.go            ← Core implementation: Gigahost API client, libdns interface (GetRecords, AppendRecords, SetRecords, DeleteRecords)
  provider_test.go       ← Tests with httptest mock server simulating the Gigahost API

Dockerfile               ← Builds a Caddy Docker image with this module baked in
```

The two-package split is a Caddy DNS provider convention:
- **Root package** (`gigahost`): Caddy-specific glue — module registration, Caddyfile unmarshalling, env placeholder resolution.
- **`provider/` package** (`gigahost`): Pure DNS logic — API client, auth, record CRUD. Implements the [libdns](https://github.com/libdns/libdns) interfaces. No Caddy dependency.

## Key interfaces implemented

The provider implements these libdns interfaces:
- `libdns.RecordGetter` — `GetRecords(ctx, zone)`
- `libdns.RecordAppender` — `AppendRecords(ctx, zone, recs)`
- `libdns.RecordSetter` — `SetRecords(ctx, zone, recs)` (upsert)
- `libdns.RecordDeleter` — `DeleteRecords(ctx, zone, recs)`

## Gigahost API

- Base URL: `https://api.gigahost.no/api/v0`
- Docs: https://gigahost.no/api-dokumentasjon
- Auth: POST `/authenticate` with username/password (optional TOTP code) → bearer token
- Zones: GET `/dns/zones` → list of `{zone_id, zone_name}`
- Records: GET/POST `/dns/zones/{id}/records`, PUT/DELETE `/dns/zones/{id}/records/{record_id}`
- All responses wrapped in `{"meta": {"status": ..., "message": ...}, "data": ...}`
- The API does NOT return `record_id` on POST (create), so the code re-fetches and matches by name+type+value.
- DELETE requires query params `?name=...&type=...` in addition to the record ID in the path.

### Authentication details

The Gigahost API uses **regular account credentials** (same as flux.gigahost.no login). There are no separate API keys.

```
POST /authenticate
{
  "username": "your-gigahost-username",
  "password": "your-password",
  "code": 123456              // optional, only if 2FA is enabled
}
→ { "data": { "token": "xxx", "token_expire": <unix-timestamp>, "customer_id": "xxx" } }
```

The token is then sent as `Authorization: Bearer <token>` on all subsequent requests.

**2FA caveat**: The `code` field is a TOTP code that rotates every 30 seconds. Since Caddy is a long-running daemon that re-authenticates when tokens expire, 2FA is impractical for automated use. 

**Recommended approach**: Create a dedicated Gigahost contact/user without 2FA for API use:
1. Log in to https://flux.gigahost.no
2. Go to **Account** → **Contacts**
3. Click **Add new user**
4. Fill in Name, Email, and set Access level to **Administrator**
5. **Do NOT enable 2FA** for this user
6. Use this user's credentials in Caddy configuration

### Known API quirks

- **Zone creation** uses `zone_name` as the field name (not `name` or `zone`): `POST /dns/zones {"zone_name": "example.no"}`. Not used by the Caddy module (it only manages records), but relevant if extending the code.
- **DELETE may silently no-op**: `DELETE /dns/zones/{id}/records/{record_id}` can return 200 "Record deleted successfully" but the record remains. This seems to happen with default/protected records. The code does not verify deletion after the fact.
- **`customer_id` type varies**: The `/authenticate` response returns `customer_id` as a number, but it may appear as a string in other contexts. The code uses `json.RawMessage` to avoid type mismatch.

## How to work with this code

### Build and test

```bash
go test ./...                    # Run all tests
go test -v ./...                 # Verbose
go test -run TestGetRecords ./provider/  # Specific test
go vet ./...                     # Static analysis
```

### Build a Caddy binary with this module

```bash
# Install xcaddy first: go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
xcaddy build --with github.com/fredrik-lindseth/caddy-dns-gigahost@master
```

### Docker

```bash
docker build -t caddy-with-gigahost-dns .
```

## Testing approach

Tests use `net/http/httptest` to mock the entire Gigahost API. The package-level `baseURL` var is overridden in tests to point at the mock server. No real API calls are made.

The mock server (`setupTestServer`) simulates:
- Authentication (validates username/password/TOTP)
- Zone listing
- Record CRUD with mutable state (`mockState`)

## Things to know

- **Zone names**: Gigahost uses bare names (`example.no`), libdns uses FQDN with trailing dot (`example.no.`). Conversion happens at the boundary.
- **Record names**: Gigahost uses `@` for zone apex. libdns also uses `@`. Empty string maps to `@`.
- **MX records**: Priority is a separate field in the Gigahost API (`record_priority`), not part of the value. The code handles the split/merge.
- **CNAME/NS targets**: Trailing dots are stripped when sending to Gigahost, added when reading back.
- **Token management**: Bearer tokens are cached and refreshed 30 seconds before expiry. All API calls go through `doRequest` which calls `ensureAuth`.
- **Concurrency**: A single `sync.Mutex` protects all API operations (auth + requests).
- **libdns typed records**: The code uses typed libdns records (`libdns.Address`, `libdns.TXT`, `libdns.MX`, etc.) where possible, falling back to `libdns.RR` for unknown types.

## Dependencies

- `github.com/caddyserver/caddy/v2` — Caddy module system, Caddyfile parsing
- `github.com/libdns/libdns` — Standard DNS provider interface
- Go 1.24+
