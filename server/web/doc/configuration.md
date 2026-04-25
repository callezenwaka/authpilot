# Configuration

Config precedence: runtime flags > environment variables > YAML file > defaults.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FURNACE_HTTP_ADDR` | `:8025` | Management server listen address |
| `FURNACE_PROTOCOL_ADDR` | `:8026` | Protocol server listen address |
| `FURNACE_OIDC_ISSUER_URL` | `http://localhost:8026` | Issuer URL in tokens and discovery |
| `FURNACE_API_KEY` | _(auto-generated)_ | Protects `/api/v1/`; printed on startup if not set |
| `FURNACE_SCIM_KEY` | _(unset)_ | Separate bearer key for `/scim/v2`; falls back to `API_KEY` |
| `FURNACE_PERSISTENCE_ENABLED` | `true` | `false` = in-memory only (resets on restart) |
| `FURNACE_SQLITE_PATH` | `./data/furnace.db` | SQLite database path |
| `FURNACE_CORS_ORIGINS` | _(none = `*`)_ | Comma-separated allowed origins for the protocol server |
| `FURNACE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |
| `FURNACE_RATE_LIMIT` | `0` (disabled) | Requests per minute per IP on `/api/v1` |
| `FURNACE_PROVIDER` | `default` | Active provider personality |
| `FURNACE_TENANCY` | `single` | `single` or `multi` |
| `FURNACE_SCIM_MODE` | _(unset)_ | Set to `client` to push mutations to an external SCIM target |
| `FURNACE_SCIM_TARGET` | _(unset)_ | External SCIM base URL (required when `FURNACE_SCIM_MODE=client`) |
| `FURNACE_HEADER_PROPAGATION` | `false` | Inject `X-User-*` headers on `/userinfo` responses |
| `FURNACE_SEED_USERS` | _(unset)_ | Inline YAML list of users to create at startup |
| `FURNACE_SAML_ENTITY_ID` | `http://localhost:8026` | SAML IdP entity ID |
| `FURNACE_SAML_CERT_DIR` | _(unset)_ | Persist SAML signing key and cert across restarts |

---

## Provider Personality

Switch the claim shape Furnace issues to match a target IdP:

```bash
FURNACE_PROVIDER=azure-ad go run ./server/cmd/furnace
```

| Provider | Key remappings |
|----------|----------------|
| `default` | Standard OIDC (`email`, `name`, `sub`) |
| `azure-ad` | `preferred_username`, `tid` tenant claim |
| `okta` | `login`, `groups` array |
| `google-workspace` | `email`, `email_verified`, `hd` hosted domain |
| `google` | `email`, `email_verified` |
| `github` | `login`, `avatar_url` |
| `onelogin` | `email`, `name` with OneLogin extras |

Set via `FURNACE_PROVIDER` env var or `provider:` in YAML config. Requires restart.

---

## Multi-Tenancy

```yaml
# furnace.yaml
tenancy: multi
tenants:
  - id: acme
    api_key: key-acme
    scim_key: scim-acme
  - id: widgets
    api_key: key-widgets
```

Each tenant's API key scopes all store operations to that tenant.
Single-mode behaviour is unchanged.

---

## SCIM Client Mode

Push user mutations to an external SCIM provider:

```bash
FURNACE_SCIM_MODE=client \
FURNACE_SCIM_TARGET=https://scim.example.com/v2 \
go run ./server/cmd/furnace
```

Outbound requests are non-blocking — SCIM push failures are logged but do not
fail management API calls. View the event log at `GET /api/v1/scim/events`.

---

## Seed Users

```bash
FURNACE_SEED_USERS='[{email: alice@example.com, display_name: Alice, active: true}]' \
go run ./server/cmd/furnace
```

Users are upserted idempotently at startup — safe to restart without duplicates.

---

## Header Propagation

Inject `X-User-*` headers on `/userinfo` responses for service mesh and nginx
`auth_request` patterns:

```bash
FURNACE_HEADER_PROPAGATION=true go run ./server/cmd/furnace
```

Headers injected: `X-User-ID`, `X-User-Email`, `X-User-Groups` (comma-joined).

---

## Persistence

```bash
# Enable (default)
FURNACE_PERSISTENCE_ENABLED=true go run ./server/cmd/furnace

# Disable (CI / ephemeral environments)
FURNACE_PERSISTENCE_ENABLED=false go run ./server/cmd/furnace
```

SQLite stores users, groups, flows, sessions, and audit events.
Flows and sessions survive server restarts when persistence is enabled.
