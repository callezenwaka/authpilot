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

## OIDC Signing Key Rotation

Furnace issues tokens signed with an RSA-3072 key. The active key is published
at `/.well-known/jwks.json`; retired keys remain in the set for the configured
overlap window so in-flight tokens continue to verify until they expire.

Enable automatic rotation:

```bash
FURNACE_KEY_ROTATION_INTERVAL=24h   # rotate daily
FURNACE_KEY_ROTATION_OVERLAP=48h    # keep retired key in JWKS for 48 h
```

Rotation failures are logged at `WARN` and do not crash the server. The overlap
window should be at least as long as your longest JWKS consumer cache TTL.

---

## OPA Decision Log Hardening

The OPA decision log can contain sensitive claim values. Controls available:

| Setting | Default | Purpose |
|---------|---------|---------|
| `include_input` | `false` | Opt-in to logging the full input document |
| `redact_fields` | `[]` | Dot-paths redacted to `[REDACTED]` before writing |
| `scrub_policy_credentials` | `false` | Remove bearer tokens / passwords from policy text |
| `retention_days` | `0` (unlimited) | Prune entries older than N days on startup |

In multi-tenant mode, each tenant can add further restrictions via
`opa.tenant_budgets.<id>.decision_log`. Per-tenant settings are strictly
additive — they can redact more fields and shorten retention, but cannot
re-enable fields the global config suppresses.

See [Configuration → OPA Decision Log](configuration#opa-decision-log) for YAML
examples.

---

## Audit Log Integrity

The SQLite audit log uses an append-only table with a tamper-evident SHA-256
hash chain. Each row's `chain_hash` covers the previous row's hash and the
current event JSON, so any row deletion or modification breaks the chain.

Verify the chain at any time:

```bash
curl http://localhost:8025/api/v1/audit/verify
```

Returns `200 {"ok": true}` when the chain is intact or `409 {"ok": false,
"broken_at": "<event-id>"}` at the first mismatch. The in-memory store
(persistence disabled) returns `ok: true` with a note that no chain is
maintained.

---

## Network Exposure

Furnace binds to `0.0.0.0` by default. Before exposing to a network:

- Set a strong `FURNACE_API_KEY` (32+ chars, randomly generated).
- Set `FURNACE_CORS_ORIGINS` to your admin SPA origin.
- Place Furnace behind a TLS-terminating reverse proxy (nginx, Caddy, or a load
  balancer). WebAuthn requires HTTPS for any origin other than `localhost`.
