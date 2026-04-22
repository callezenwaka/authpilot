# Authpilot

A local-first authentication development platform. Build and test OIDC flows against a real protocol implementation before connecting to a production SSO provider.

## Ports

| Port | Purpose |
|------|---------|
| `:8025` | Web UI, admin SPA, management API |
| `:8026` | OIDC, SAML, WS-Fed protocol endpoints |

## Quick Start

```bash
git clone https://github.com/<owner>/authpilot
cd authpilot
make setup
make dev
```

`make setup` installs frontend dependencies for both SPAs. `make dev` starts the Go server with hot-reload (`air`) and watches both SPAs for changes. Open `http://localhost:18025` for the admin UI.

With a config file:

```bash
go run ./server/cmd/authpilot -config ./configs/authpilot.yaml
```

With Docker Compose:

```bash
docker compose up --build
```

## Make Targets

| Target | Description |
|--------|-------------|
| `make setup` | Install npm dependencies for both SPAs (run once after clone) |
| `make dev` | Start server with hot-reload + watch both SPAs for changes |
| `make build` | Compile the binary |
| `make test` | Run all tests |
| `make lint` | Run golangci-lint |
| `make run` | Start on dev-safe ports (`:18025` / `:18026`) |
| `make run-default` | Start on default ports (`:8025` / `:8026`) |
| `make run-auto` | Try default ports, fall back to dev-safe ports |
| `make run-bg` | Start in background, logs to `.tmp/authpilot.log` |
| `make health` | Check health endpoint |
| `make stop` | Stop the tracked process |
| `make stop ALL=1` | Broader cleanup including default ports |
| `make admin-build` | Build the Vue admin SPA |
| `make notify-build` | Build the Vue notification hub SPA |

Override ports at invocation time:

```bash
make run RUN_HTTP_ADDR=:19025 RUN_PROTOCOL_ADDR=:19026
```

Rebuild the admin SPA before starting:

```bash
make run BUILD=1
```

## Configuration

Config precedence: runtime flags > environment variables > YAML file > defaults.

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTHPILOT_HTTP_ADDR` | `:8025` | Web UI and API address |
| `AUTHPILOT_PROTOCOL_ADDR` | `:8026` | OIDC protocol address |
| `AUTHPILOT_OIDC_ISSUER_URL` | `http://localhost:8026` | Issuer URL in tokens and discovery |
| `AUTHPILOT_PERSISTENCE_ENABLED` | `false` | Enable SQLite persistence for users/groups |
| `AUTHPILOT_SQLITE_PATH` | `./data/authpilot.db` | SQLite database path |
| `AUTHPILOT_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |
| `AUTHPILOT_API_KEY` | _(unset)_ | Protect `/api/v1` with a static key |
| `AUTHPILOT_SCIM_KEY` | _(unset)_ | Separate bearer key for `/scim/v2`; falls back to `API_KEY` |
| `AUTHPILOT_SAML_ENTITY_ID` | `http://localhost:8026` | SAML IdP entity ID |
| `AUTHPILOT_SAML_CERT_DIR` | _(unset)_ | Persist SAML signing key and cert across restarts |
| `AUTHPILOT_RATE_LIMIT` | `0` (disabled) | Requests per minute per IP on `/api/v1` |
| `AUTHPILOT_PROVIDER` | `default` | Active provider personality: `okta`, `azure-ad`, `google-workspace`, `github`, `onelogin` |
| `AUTHPILOT_TENANCY` | `single` | `single` or `multi`; multi mode requires a `tenants:` block in YAML |
| `AUTHPILOT_SCIM_MODE` | _(unset)_ | Set to `client` to push user mutations to an external SCIM target |
| `AUTHPILOT_SCIM_TARGET` | _(unset)_ | External SCIM base URL (required when `AUTHPILOT_SCIM_MODE=client`) |
| `AUTHPILOT_HEADER_PROPAGATION` | `false` | Inject `X-User-ID`, `X-User-Email`, `X-User-Groups` on `/userinfo` responses |
| `AUTHPILOT_SEED_USERS` | _(unset)_ | Inline YAML list of users to create at startup |

Enable persistence:

```bash
go run ./server/cmd/authpilot -persistence-enabled=true -sqlite-path ./data/authpilot.db
```

### Provider Personality

Switch the claim shape Authpilot issues to match a target IdP:

```bash
AUTHPILOT_PROVIDER=azure-ad go run ./server/cmd/authpilot
```

| Provider | Key remappings |
|----------|---------------|
| `default` | Standard OIDC (`email`, `name`, `sub`) |
| `azure-ad` | `preferred_username`, `tid` tenant claim |
| `okta` | `login`, `groups` array |
| `google-workspace` | `email`, `email_verified`, `hd` hosted domain |
| `github` | `login`, `avatar_url` |
| `onelogin` | `email`, `name` with OneLogin extras |

### Multi-Tenancy

```yaml
# authpilot.yaml
tenancy: multi
tenants:
  - id: acme
    api_key: key-acme
    scim_key: scim-acme
  - id: widgets
    api_key: key-widgets
```

Each tenant's API key scopes all store operations to that tenant. Single-mode behaviour is unchanged.

### SCIM Client Mode

Push user mutations to an external SCIM provider:

```bash
AUTHPILOT_SCIM_MODE=client \
AUTHPILOT_SCIM_TARGET=https://scim.example.com/v2 \
go run ./server/cmd/authpilot
```

Outbound requests are non-blocking — SCIM push failures are logged but do not fail management API calls. View the event log at `GET /api/v1/scim/events`.

### Seed Users

```bash
AUTHPILOT_SEED_USERS='[{email: alice@example.com, display_name: Alice, active: true}]' \
go run ./server/cmd/authpilot
```

Users are upserted idempotently at startup — safe to restart without duplicates.

## OIDC Endpoints

Served on `:8026`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | Discovery document |
| `/.well-known/jwks.json` | GET | Public signing keys |
| `/authorize` | GET | Start authorization (redirects to `/login`) |
| `/authorize/complete` | GET | Issue auth code after login completes |
| `/oauth2/token` | POST | Exchange code for tokens; refresh token grant |
| `/oauth2/introspect` | POST | RFC 7662 token introspection |
| `/userinfo` | GET | User profile (Bearer token required) |
| `/revoke` | POST | Token revocation |

PKCE is required on every authorization request (`S256` or `plain`).

## SAML Endpoints

Served on `:8026` alongside OIDC.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/saml/metadata` | GET | IdP metadata XML — includes SSO and SLO endpoints |
| `/saml/sso` | GET, POST | SP-initiated SSO — HTTP-Redirect and HTTP-POST bindings |
| `/saml/slo` | GET, POST | Single Logout — SP-initiated (SAMLRequest) and IdP-initiated (`?user_id=`) |
| `/saml/cert` | GET | Download the IdP signing certificate (PEM) |
| `/saml/flows` | GET | Debug list of active SAML flows |

Configure your SP with:
- **IdP Entity ID:** `http://localhost:8026`
- **SSO URL:** `http://localhost:8026/saml/sso`
- **SLO URL:** `http://localhost:8026/saml/slo`
- **Metadata URL:** `http://localhost:8026/saml/metadata`
- **Signing Certificate:** `http://localhost:8026/saml/cert`

To trigger IdP-initiated logout for a user:

```bash
curl http://localhost:8026/saml/slo?user_id=<user-id>
```

## SCIM 2.0 Endpoints

Served on `:8025` under `/scim/v2`. Backed by the same user and group stores as the management API. Obeys the same API key protection when `AUTHPILOT_SCIM_KEY` (or `AUTHPILOT_API_KEY`) is set.

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/scim/v2/ServiceProviderConfig` | GET | Server capabilities |
| `/scim/v2/Schemas` | GET | All schema definitions |
| `/scim/v2/Schemas/{id}` | GET | Single schema by URN |
| `/scim/v2/Users` | GET, POST | List (with `filter=`) / create users |
| `/scim/v2/Users/{id}` | GET, PUT, PATCH, DELETE | Read / replace / patch / delete a user |
| `/scim/v2/Groups` | GET, POST | List / create groups |
| `/scim/v2/Groups/{id}` | GET, PUT, PATCH, DELETE | Read / replace / patch / delete a group |

PATCH supports `add`, `replace`, and `remove` operations on members. Filter supports `userName eq "..."` and `displayName eq "..."` on the Users collection.

## WS-Federation Endpoints

Served on `:8026` alongside OIDC and SAML.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/wsfed` | GET, POST | Passive requestor endpoint (`wa=wsignin1.0` / `wsignout1.0`) |
| `/federationmetadata/2007-06/federationmetadata.xml` | GET | Federation metadata XML |

Configure your relying party with:
- **Passive Requestor Endpoint:** `http://localhost:8026/wsfed`
- **Federation Metadata URL:** `http://localhost:8026/federationmetadata/2007-06/federationmetadata.xml`
- **Token type:** SAML 1.1 (signed with RSA-SHA256, exc-c14n)

## Management API

Served on `:8025` under `/api/v1`. Every response includes an `X-Request-ID` header for log correlation.

| Resource | Endpoints |
|----------|-----------|
| Users | `GET/POST /api/v1/users`, `GET/PUT/DELETE /api/v1/users/{id}` |
| Groups | `GET/POST /api/v1/groups`, `GET/PUT/DELETE /api/v1/groups/{id}` |
| Flows | `GET/POST /api/v1/flows`, `GET /api/v1/flows/{id}` |
| Flow actions | `POST /api/v1/flows/{id}/select-user` · `verify-mfa` · `approve` · `deny` · `webauthn-response` |
| Sessions | `GET /api/v1/sessions` |
| Notifications | `GET /api/v1/notifications?flow_id=<id>`, `GET /api/v1/notifications/all` |
| Audit | `GET /api/v1/audit`, `GET /api/v1/audit/export?format=<fmt>` |
| Tokens | `POST /api/v1/tokens/mint` |
| Config | `GET /api/v1/config`, `PATCH /api/v1/config` |
| SCIM events | `GET /api/v1/scim/events` |
| Export | `GET /api/v1/export?format=<fmt>` |
| Debug | `GET /api/v1/debug/token-compare` |
| API contract | `GET /api/v1/openapi.json`, `GET /api/v1/docs` |

### Export

Export all users and groups to a format suitable for bulk import into an identity provider:

```bash
# SCIM 2.0 JSON (generic IdP)
curl http://localhost:8025/api/v1/export?format=scim -o users.json

# Okta CSV bulk import
curl http://localhost:8025/api/v1/export?format=okta -o users.csv

# Azure AD JSON bulk import
curl http://localhost:8025/api/v1/export?format=azure -o azure-users.json

# Google Workspace CSV bulk upload
curl http://localhost:8025/api/v1/export?format=google -o google-users.csv
```

### Audit

```bash
# All events
curl http://localhost:8025/api/v1/audit

# Filter by type and time window
curl "http://localhost:8025/api/v1/audit?event_type=user.created&since=2026-01-01T00:00:00Z"

# Export as JSON-ND (Splunk/Elastic), CEF (ArcSight), or Syslog (RFC 5424)
curl http://localhost:8025/api/v1/audit/export?format=json-nd -o audit.jsonl
curl http://localhost:8025/api/v1/audit/export?format=cef -o audit.cef
curl http://localhost:8025/api/v1/audit/export?format=syslog -o audit.log
```

### Token Minting

Mint tokens for a user without running the full OAuth flow — useful for CI/CD tests:

```bash
curl -X POST http://localhost:8025/api/v1/tokens/mint \
  -H "Content-Type: application/json" \
  -d '{"user_id": "usr_123", "client_id": "myapp", "expires_in": 3600}'
```

### Token Compare (Debug)

Compare the claim shape of an Authpilot token against a real provider token:

```bash
curl "http://localhost:8025/api/v1/debug/token-compare?authpilot_token=eyJ...&provider_token=eyJ..."
```

Returns a `differences` array with `path`, `authpilot_value`, `provider_value`, and `note` for each divergent claim.

### Live Config

Read and update token TTLs without restarting:

```bash
# Read current TTLs
curl http://localhost:8025/api/v1/config

# Update access token TTL
curl -X PATCH http://localhost:8025/api/v1/config \
  -H "Content-Type: application/json" \
  -d '{"tokens": {"access_token_ttl": 7200}}'
```

### OpenAPI

```bash
curl http://localhost:8025/api/v1/openapi.json
```

Interactive Swagger UI: `http://localhost:8025/api/v1/docs`

### Idempotency

All `POST` endpoints on `/api/v1` support idempotency keys:

```bash
curl -X POST http://localhost:8025/api/v1/users \
  -H "Idempotency-Key: my-unique-key-123" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","display_name":"Alice"}'
```

Repeat the same request within 5 minutes with the same key — the handler runs once and subsequent calls return the cached response with an `Idempotent-Replayed: true` header.

### Rate Limiting

```bash
AUTHPILOT_RATE_LIMIT=60 go run ./server/cmd/authpilot
```

Requests over the limit receive `429 Too Many Requests` with `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After` headers.

### Protected Mode

```bash
AUTHPILOT_API_KEY=mysecret go run ./server/cmd/authpilot
```

```bash
curl -H "X-Authpilot-Api-Key: mysecret" http://localhost:8025/api/v1/users
# or
curl -H "Authorization: Bearer mysecret" http://localhost:8025/api/v1/users
```

### Error Envelope

```json
{
  "error": {
    "code": "FLOW_NOT_FOUND",
    "message": "flow not found",
    "retryable": false,
    "docs_url": "/admin/docs/errors#flow_not_found",
    "details": {"flow_id": "abc123"}
  },
  "request_id": "req_01abc..."
}
```

## Login Simulation

The login UI at `/login` lets you pick any seeded user and walk through a flow without a real password. Set `next_flow` on a user to inject a scenario:

| Scenario | Behaviour |
|----------|-----------|
| `normal` | Straight-through login |
| `mfa_fail` | First MFA attempt fails |
| `account_locked` | Flow errors immediately |
| `slow_mfa` | Push approval delayed 10 seconds |
| `expired_token` | Tokens issued with negative TTL |

MFA methods available (set on user):

| Method | Behaviour |
|--------|-----------|
| `totp` | 6-digit time-based code; visible in Notification Hub |
| `push` | Approve/deny push notification; visible in Notification Hub |
| `sms` | 6-digit code sent to phone; visible in Notification Hub |
| `magic_link` | One-click sign-in link; visible in Notification Hub |
| `webauthn` | Passkey simulation; challenge visible in Notification Hub |

## Admin UI

```bash
make admin-build
```

Then visit `http://localhost:8025/admin`. Re-run after code changes if the page is stale.

**Views available:**
- **Dashboard** — user/group/flow/session counts and recent sessions
- **Users** — list, search, create, edit, delete
- **Groups** — list, create, edit (including member IDs), delete
- **Sessions** — list with expandable detail rows
- **Audit Log** — filterable event table with event type and time range filters (`/admin/audit`)
- **Config** — live token TTL editor and provider personality switcher (`/admin/config`)
- **Token Diff** — side-by-side claim comparison between Authpilot and provider tokens (`/admin/diff`)
- **SCIM** — SCIM client mode event log; expandable request/response rows (`/admin/scim`)

A tenant selector in the topbar switches context in multi-tenant mode.

## Notification Hub

The notification hub intercepts outbound MFA messages during local testing — no real delivery provider needed.

```bash
make notify-build
```

Then visit `http://localhost:8025/notify`. Re-run after code changes if the page is stale.

**Tabs:**
- **TOTP** — 6-digit codes with countdown timer; copy or navigate directly to the MFA page
- **Push** — pending push approvals; approve or deny
- **SMS** — outbound SMS codes; copy to paste into the MFA page
- **Magic Links** — one-click sign-in links; click to complete login
- **Passkeys** — WebAuthn simulation; challenge display and one-click authenticate

The hub polls `/api/v1/notifications/all` every 3 seconds.

## Header Propagation

Enable `X-User-*` headers on `/userinfo` responses for service mesh and nginx `auth_request` patterns:

```bash
AUTHPILOT_HEADER_PROPAGATION=true go run ./server/cmd/authpilot
```

Headers injected: `X-User-ID`, `X-User-Email`, `X-User-Groups` (comma-joined).

## Ecosystem Components

### Helm Chart

```bash
helm install authpilot ./deploy/helm/authpilot \
  --set config.apiKey=mysecret \
  --set image.tag=v0.1.0
```

```bash
helm upgrade authpilot ./deploy/helm/authpilot --set image.tag=v0.2.0
```

Key values: `persistence.enabled`, `replicaCount`, `image.tag`, `config.apiKey`, `config.provider`, `config.tenancy`, `seedUsers`.

### Terraform Provider

```hcl
terraform {
  required_providers {
    authpilot = {
      source = "callezenwaka/authpilot"
    }
  }
}

provider "authpilot" {
  base_url = "http://localhost:8025"
  api_key  = "mysecret"
}

resource "authpilot_user" "alice" {
  email        = "alice@example.com"
  display_name = "Alice"
  active       = true
}
```

```bash
terraform import authpilot_user.alice usr_123
```

### Kubernetes Operator

Apply a user manifest — the operator syncs it to Authpilot via SCIM:

```yaml
apiVersion: authpilot.io/v1alpha1
kind: AuthpilotUser
metadata:
  name: alice
spec:
  email: alice@example.com
  displayName: Alice
  active: true
```

```bash
kubectl apply -f alice.yaml
```

Configure the operator with `AUTHPILOT_SCIM_URL` and `AUTHPILOT_SCIM_KEY` environment variables (typically mounted from a Kubernetes Secret).

## Release Versioning

Each component uses path-prefixed git tags. Pushing a tag triggers its own workflow:

| Tag pattern | Workflow | Artifact |
|-------------|----------|----------|
| `server/v*` | `release-server.yml` | GitHub Release + `ghcr.io/<owner>/authpilot:<version>` |
| `helm/v*` | `release-helm.yml` | Helm chart published to GitHub Pages |
| `terraform/v*` | `release-terraform.yml` | Terraform provider binaries (GPG-signed) |
| `operator/v*` | `release-operator.yml` | `ghcr.io/<owner>/authpilot-operator:<version>` |

## Folder Structure

```text
.
├── client/
│   ├── admin-spa/        # Vue 3 admin SPA
│   └── notify-spa/       # Vue 3 notification hub SPA
├── server/
│   ├── cmd/authpilot/    # Binary entrypoint
│   ├── internal/
│   │   ├── app/          # Startup wiring
│   │   ├── audit/        # Audit event helpers and constants
│   │   ├── config/       # Config loading and validation
│   │   ├── domain/       # Core models
│   │   ├── export/       # Migration export formatters (SCIM, Okta, Azure, Google)
│   │   ├── flow/         # Flow state machine
│   │   ├── httpapi/      # Web UI and management API handlers
│   │   ├── notify/       # MFA notification payload generation
│   │   ├── oidc/         # OIDC engine
│   │   ├── personality/  # Provider personality claim mappings
│   │   ├── saml/         # SAML 2.0 engine
│   │   ├── scim/         # SCIM 2.0 provisioning engine
│   │   ├── scimclient/   # SCIM client mode (outbound push)
│   │   ├── tenant/       # Multi-tenant context helpers
│   │   ├── wsfed/        # WS-Federation passive requestor engine
│   │   └── store/        # Memory, SQLite, and tenanted store wrappers
│   └── web/
│       ├── static/       # Built SPA assets
│       └── templates/    # Server-rendered login pages
├── configs/              # Example YAML configs
├── deploy/
│   └── helm/authpilot/   # Helm chart
├── operator/             # Kubernetes operator (controller-runtime)
├── terraform/            # Terraform provider (Plugin Framework)
└── scripts/              # Helper scripts
```
