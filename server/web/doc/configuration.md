# Configuration

Config precedence: runtime flags > environment variables > YAML file > defaults.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FURNACE_HTTP_ADDR` | `:8025` | Management server listen address |
| `FURNACE_PROTOCOL_ADDR` | `:8026` | Protocol server listen address |
| `FURNACE_OIDC_ISSUER_URL` | `http://localhost:8026` | Issuer URL in tokens and discovery |
| `FURNACE_API_KEY` | _(auto-generated)_ | Protects `/api/v1/`; auto-generated on first start if unset — copy it from the **Config** page in the admin UI |
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
| `FURNACE_KEY_ROTATION_INTERVAL` | `0` (disabled) | How often the OIDC signing key rotates, e.g. `24h`. `0` disables automatic rotation |
| `FURNACE_KEY_ROTATION_OVERLAP` | `24h` | How long a retired key stays published in JWKS after rotation; must exceed your JWKS cache TTL |
| `FURNACE_OPA_DECISION_LOG_REDACT_FIELDS` | _(unset)_ | Comma-separated dot-paths in input to redact before logging, e.g. `user.claims.email,user.claims.ssn` |
| `FURNACE_OPA_DECISION_LOG_SCRUB_CREDENTIALS` | `false` | Scrub bearer tokens, passwords, and base64 secrets from policy text before logging |
| `FURNACE_OPA_DECISION_LOG_RETENTION_DAYS` | `0` (unlimited) | Prune decision log entries older than N days at startup (file destination only) |

---

## Admin API Key

`FURNACE_API_KEY` is optional. If it is not set, Furnace auto-generates a `furn_…` key on startup and injects it into the admin SPA at serve time — so the browser UI works immediately without any configuration.

**Finding the key for curl or CI scripts**

Open the admin UI, go to **Config**, and look for the **Admin API Key** row. The value is masked by default; click **Show** to reveal it and **Copy** to put it on the clipboard.

```bash
# once you have the key:
curl -H "X-Furnace-Api-Key: furn_..." http://localhost:8025/api/v1/users
```

**Persisting the key across restarts**

An auto-generated key is ephemeral — it changes every time the process starts. Set `FURNACE_API_KEY` explicitly to keep it stable:

```bash
# generate once, add to .env or docker-compose environment:
export FURNACE_API_KEY=$(openssl rand -hex 20)
```

In Docker Compose:

```yaml
environment:
  FURNACE_API_KEY: ${FURNACE_API_KEY}   # read from host .env
```

> The key is never written to logs. The only place it appears outside the process is the admin **Config** page and the injected `window.__FURNACE__` object in the served HTML (visible in browser DevTools).

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

---

## OIDC Key Rotation

Furnace rotates its RSA signing key on a configurable interval. Retired keys
remain published in JWKS for the overlap window so downstream caches have time
to refresh before the key is removed.

```yaml
# furnace.yaml
oidc:
  key_rotation_interval: 24h   # rotate every 24 hours; 0 = disabled
  key_rotation_overlap: 48h    # keep the retired key in JWKS for 48 hours
```

Or via environment variables:

```bash
FURNACE_KEY_ROTATION_INTERVAL=24h
FURNACE_KEY_ROTATION_OVERLAP=48h
```

The overlap window should exceed your JWKS consumer's cache TTL. The default
overlap is `24h`; set it to `0` if you want the retired key removed immediately
after rotation (only safe when no consumer caches JWKS).

---

## OPA Decision Log

The embedded OPA engine writes one NDJSON line per evaluation to the configured
destination.

```yaml
# furnace.yaml
opa:
  decision_log:
    enabled: true
    destination: /var/log/furnace/decisions.ndjson   # stdout | stderr | file path
    include_input: false           # opt-in: log the full input document
    include_policy: false          # opt-in: log the policy text
    redact_fields:                 # dot-paths redacted from input before logging
      - user.claims.email
      - user.claims.ssn
    scrub_policy_credentials: true # remove bearer tokens / passwords from policy text
    retention_days: 90             # prune entries older than 90 days on open (file only)
```

### Per-tenant overrides

In multi-tenant mode, each tenant can tighten the global decision log settings.
Per-tenant values can only add restrictions — they cannot disable global
redaction, restore scrubbed fields, or extend retention beyond the global limit.

```yaml
opa:
  tenant_budgets:
    acme:
      decision_log:
        additional_redact_fields:   # merged with global redact_fields
          - user.claims.phone
          - user.attributes.manager_id
        scrub_policy_credentials: true   # enable scrubbing even if global is false
        retention_days: 30               # prune acme entries after 30 days (tighter than global)
    widgets:
      decision_log:
        additional_redact_fields:
          - user.claims.dob
```

---

## OPA Resource Budgets

Hard limits applied per evaluation. Per-tenant values narrow the global limits —
a per-tenant value larger than the global is silently ignored.

```yaml
opa:
  compile_timeout: 2s
  eval_timeout: 5s
  max_policy_bytes: 65536   # 64 KiB
  max_data_bytes: 5242880   # 5 MiB
  max_batch_checks: 100

  tenant_budgets:
    acme:
      compile_timeout: 1s
      eval_timeout: 2s
      max_policy_bytes: 32768
      max_batch_checks: 25
```
