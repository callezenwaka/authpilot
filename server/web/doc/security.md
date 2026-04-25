# Security

## Admin API Key

Furnace auto-generates a cryptographically random key (`furn_<40 hex chars>`) on
startup when `FURNACE_API_KEY` is not set and prints it to stdout:

```
[furnace] Admin API Key: furn_a3f9c2d18e4b7a6f0c5d2e1b9a8f3c7d4e2b
[furnace] Set FURNACE_API_KEY env var to persist this key across restarts.
```

The key is also visible in the admin UI under **Config → Admin API Key** — masked
by default with a one-click copy button.

To make it persistent:

```bash
# .env  (add to .gitignore — share with your team via a secrets tool)
FURNACE_API_KEY=furn_a3f9c2d18e4b7a6f0c5d2e1b9a8f3c7d4e2b
```

Pass the key in requests:

```bash
curl -H "X-Furnace-Api-Key: <key>" http://localhost:8025/api/v1/users
# or
curl -H "Authorization: Bearer <key>" http://localhost:8025/api/v1/users
```

Furnace logs a `WARN` at startup when the key is shorter than 16 characters. Use
a randomly generated key of at least 32 characters in any network-exposed deployment:

```bash
openssl rand -hex 32
```

---

## CSRF Protection

The server-rendered login form at `/login` uses the double-submit cookie pattern.
On every `GET /login` a random 32-byte token is generated, set as the
`furnace_csrf` HttpOnly cookie, and embedded as a hidden field in the form.
The `POST /login/select-user` handler rejects requests where the cookie and form
field are absent or do not match, returning `403 CSRF_INVALID`.

---

## CORS

By default the API returns `Access-Control-Allow-Origin: *`, which is safe for
local development. For hosted deployments, restrict allowed origins:

```bash
FURNACE_CORS_ORIGINS=https://admin.example.com,https://id.example.com \
go run ./server/cmd/furnace
```

When set, only requests whose `Origin` header matches one of the listed values
receive a matching CORS response header.

---

## Network Exposure

Furnace binds to `0.0.0.0` by default. Before exposing to a network:

- Set a strong `FURNACE_API_KEY` (32+ chars, randomly generated).
- Set `FURNACE_CORS_ORIGINS` to your admin SPA origin.
- Place Furnace behind a TLS-terminating reverse proxy (nginx, Caddy, or a load
  balancer). WebAuthn requires HTTPS for any origin other than `localhost`.
