# Furnace

A local-first authentication development platform. Build and test OIDC flows against a real protocol implementation before connecting to a production SSO provider.

## Ports

| Port | Purpose |
|------|---------|
| `:8025` | Web UI, admin SPA, management API |
| `:8026` | OIDC, SAML, WS-Fed protocol endpoints |

## Quick Start

```bash
git clone https://github.com/<owner>/furnace
cd furnace
make setup
make dev
```

`make setup` installs frontend dependencies for both SPAs. `make dev` starts the Go server with hot-reload (`air`) and watches both SPAs for changes. Open `http://localhost:18025` for the admin UI.

With a config file:

```bash
go run ./server/cmd/furnace -config ./configs/furnace.yaml
```

With Docker Compose:

```bash
docker compose up --build
```

## Docker

### How the image is built

The Dockerfile uses a three-stage build:

1. **`node:22-alpine`** — builds the admin SPA (`npm run build`)
2. **`golang:1.26.2-alpine3.23`** — copies the SPA dist into `server/web/static/admin`, then compiles the Go binary with `-tags prod` which embeds the SPA and login templates via `//go:embed`
3. **`cgr.dev/chainguard/static`** — copies only the binary; no Node, no Go toolchain, no static files on disk

The result is a single self-contained binary in a minimal image. No volume mounts are needed for the admin UI.

### Docker Compose (recommended)

```bash
docker compose up --build
```

This builds the image and starts Furnace with:
- SQLite persistence at `/data/furnace.db` (named volume `furnace_data`)
- Management API + login UI on port `8025`
- Protocol server (OIDC / SAML / WS-Fed) on port `8026`

**Admin API key** — on first run, Furnace generates a random key and prints it to the logs:

```
[furnace] Admin API Key: furn_a3f9c2d18e4b7a6f0c5d2e1b9a8f3c7d4e2b
[furnace] Set FURNACE_API_KEY env var to persist this key across restarts.
```

The key is also visible in the admin UI under **Config → Admin API Key** where you can copy it with one click. To make it persistent across restarts, add it to a `.env` file:

```bash
# .env  (add to .gitignore — share with your team via a secrets tool)
FURNACE_API_KEY=furn_a3f9c2d18e4b7a6f0c5d2e1b9a8f3c7d4e2b
```

`docker-compose.yml` reads it automatically:

```yaml
environment:
  FURNACE_API_KEY: ${FURNACE_API_KEY}
```

To run without persisting data between restarts:

```bash
FURNACE_PERSISTENCE_ENABLED=false docker compose up --build
```

### docker build + docker run

```bash
docker build -t furnace .

docker run --rm \
  -p 8025:8025 \
  -p 8026:8026 \
  -v furnace_data:/data \
  furnace
```

Furnace auto-generates an admin key on startup and prints it to the terminal. Open `http://localhost:8025/admin`, go to **Config → Admin API Key**, and copy it from there. Pass it as `FURNACE_API_KEY` on subsequent runs to keep the same key.

### Ports

| Port | Purpose |
|------|---------|
| `8025` | Management API (`/api/v1/`), admin SPA (`/admin`), login UI (`/login`) |
| `8026` | Protocol server — OIDC, SAML, WS-Fed endpoints |

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FURNACE_HTTP_ADDR` | `:8025` | Management server listen address |
| `FURNACE_PROTOCOL_ADDR` | `:8026` | Protocol server listen address |
| `FURNACE_API_KEY` | _(auto-generated)_ | Protects `/api/v1/`; auto-generated and printed on startup if not set; visible in **Config → Admin API Key** |
| `FURNACE_PERSISTENCE_ENABLED` | `true` | `false` = in-memory only (resets on restart) |
| `FURNACE_SQLITE_PATH` | `./data/furnace.db` | SQLite database path |
| `FURNACE_CORS_ORIGINS` | _(none = `*`)_ | Comma-separated allowed origins for the protocol server |
| `FURNACE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |

### Running the published image

Pre-built images are published to both registries on every release. No clone required:

**Docker Hub:**
```bash
docker run --rm \
  -p 8025:8025 \
  -p 8026:8026 \
  -v furnace_data:/data \
  callezenwaka/furnace:latest
```

**GitHub Container Registry (GHCR):**
```bash
docker run --rm \
  -p 8025:8025 \
  -p 8026:8026 \
  -v furnace_data:/data \
  ghcr.io/callezenwaka/furnace:latest
```

An admin key is auto-generated on first run. Open `http://localhost:8025/admin` → **Config → Admin API Key** to copy it. Add `-e FURNACE_API_KEY=<your-key>` to subsequent runs to keep it stable.

Pin a specific version by replacing `:latest` with `:v0.1.0`.

### Publishing a release

Tag the commit and push — `release-server.yml` builds multi-arch images (`linux/amd64`, `linux/arm64`) and pushes to both Docker Hub and GHCR automatically:

```bash
git tag server/v0.1.0
git push origin server/v0.1.0
```

Requires `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` set as repository secrets in GitHub → Settings → Secrets and variables → Actions.

## Make Targets

| Target | Description |
|--------|-------------|
| `make setup` | Install npm dependencies for both SPAs (run once after clone) |
| `make dev` | Start server with hot-reload + watch both SPAs for changes |
| `make build` | Compile the production binary (`-tags prod`, embeds SPA and templates) |
| `make test` | Run all tests |
| `make lint` | Run golangci-lint |
| `make run` | Start on dev-safe ports (`:18025` / `:18026`) |
| `make run-default` | Start on default ports (`:8025` / `:8026`) |
| `make run-auto` | Try default ports, fall back to dev-safe ports |
| `make run-bg` | Start in background, logs to `.tmp/furnace.log` |
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
| `FURNACE_HTTP_ADDR` | `:8025` | Web UI and API address |
| `FURNACE_PROTOCOL_ADDR` | `:8026` | OIDC protocol address |
| `FURNACE_OIDC_ISSUER_URL` | `http://localhost:8026` | Issuer URL in tokens and discovery |
| `FURNACE_PERSISTENCE_ENABLED` | `false` | Enable SQLite persistence for users/groups |
| `FURNACE_SQLITE_PATH` | `./data/furnace.db` | SQLite database path |
| `FURNACE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |
| `FURNACE_API_KEY` | _(unset)_ | Protect `/api/v1` with a static key |
| `FURNACE_SCIM_KEY` | _(unset)_ | Separate bearer key for `/scim/v2`; falls back to `API_KEY` |
| `FURNACE_SAML_ENTITY_ID` | `http://localhost:8026` | SAML IdP entity ID |
| `FURNACE_SAML_CERT_DIR` | _(unset)_ | Persist SAML signing key and cert across restarts |
| `FURNACE_RATE_LIMIT` | `0` (disabled) | Requests per minute per IP on `/api/v1` |
| `FURNACE_PROVIDER` | `default` | Active provider personality: `okta`, `azure-ad`, `google-workspace`, `github`, `onelogin` |
| `FURNACE_TENANCY` | `single` | `single` or `multi`; multi mode requires a `tenants:` block in YAML |
| `FURNACE_SCIM_MODE` | _(unset)_ | Set to `client` to push user mutations to an external SCIM target |
| `FURNACE_SCIM_TARGET` | _(unset)_ | External SCIM base URL (required when `FURNACE_SCIM_MODE=client`) |
| `FURNACE_HEADER_PROPAGATION` | `false` | Inject `X-User-ID`, `X-User-Email`, `X-User-Groups` on `/userinfo` responses |
| `FURNACE_SEED_USERS` | _(unset)_ | Inline YAML list of users to create at startup |

Enable persistence:

```bash
go run ./server/cmd/furnace -persistence-enabled=true -sqlite-path ./data/furnace.db
```

### Provider Personality

Switch the claim shape Furnace issues to match a target IdP:

```bash
FURNACE_PROVIDER=azure-ad go run ./server/cmd/furnace
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
# furnace.yaml
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
FURNACE_SCIM_MODE=client \
FURNACE_SCIM_TARGET=https://scim.example.com/v2 \
go run ./server/cmd/furnace
```

Outbound requests are non-blocking — SCIM push failures are logged but do not fail management API calls. View the event log at `GET /api/v1/scim/events`.

### Seed Users

```bash
FURNACE_SEED_USERS='[{email: alice@example.com, display_name: Alice, active: true}]' \
go run ./server/cmd/furnace
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

Served on `:8025` under `/scim/v2`. Backed by the same user and group stores as the management API. Obeys the same API key protection when `FURNACE_SCIM_KEY` (or `FURNACE_API_KEY`) is set.

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

Compare the claim shape of an Furnace token against a real provider token:

```bash
curl "http://localhost:8025/api/v1/debug/token-compare?furnace_token=eyJ...&provider_token=eyJ..."
```

Returns a `differences` array with `path`, `furnace_value`, `provider_value`, and `note` for each divergent claim.

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
FURNACE_RATE_LIMIT=60 go run ./server/cmd/furnace
```

Requests over the limit receive `429 Too Many Requests` with `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After` headers.

### Protected Mode

```bash
FURNACE_API_KEY=mysecret go run ./server/cmd/furnace
```

```bash
curl -H "X-Furnace-Api-Key: mysecret" http://localhost:8025/api/v1/users
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

## Security

### CSRF Protection

The server-rendered login form at `/login` uses the double-submit cookie pattern. On every `GET /login` request a random 32-byte token is generated, set as the `furnace_csrf` HttpOnly cookie, and embedded as a hidden `csrf_token` field in the form. The `POST /login/select-user` handler rejects requests where the cookie and form field are absent or do not match, returning `403 CSRF_INVALID`. Cross-origin form submissions cannot read the cookie value, so forged requests are blocked without requiring a session.

### CORS

By default the API returns `Access-Control-Allow-Origin: *`, which is safe for local development. For hosted deployments, restrict the allowed origins:

```bash
FURNACE_CORS_ORIGINS=https://admin.example.com,https://id.example.com go run ./server/cmd/furnace
```

When set, only requests whose `Origin` header matches one of the listed values receive a matching `Access-Control-Allow-Origin` response header. Requests from unlisted origins receive no CORS header.

### API Key Strength

```bash
FURNACE_API_KEY=mysecret go run ./server/cmd/furnace
```

Furnace logs a `WARN` at startup when the API key is shorter than 16 characters. Use a randomly generated key of at least 32 characters in any network-exposed deployment.

```bash
openssl rand -hex 32
```

### Network Exposure

Furnace binds to `0.0.0.0` by default. In local development this is intentional. Before exposing Furnace to a network:

- Set a strong `FURNACE_API_KEY`.
- Set `FURNACE_CORS_ORIGINS` to your admin SPA origin.
- Place Furnace behind a TLS-terminating reverse proxy (nginx, Caddy, or a load balancer). WebAuthn requires HTTPS for any origin other than `localhost`.

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
- **Token Diff** — side-by-side claim comparison between Furnace and provider tokens (`/admin/diff`)
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
FURNACE_HEADER_PROPAGATION=true go run ./server/cmd/furnace
```

Headers injected: `X-User-ID`, `X-User-Email`, `X-User-Groups` (comma-joined).

## Ecosystem Components

### Helm Chart

```bash
helm install furnace ./deploy/helm/furnace \
  --set config.apiKey=mysecret \
  --set image.tag=v0.1.0
```

```bash
helm upgrade furnace ./deploy/helm/furnace --set image.tag=v0.2.0
```

Key values: `persistence.enabled`, `replicaCount`, `image.tag`, `config.apiKey`, `config.provider`, `config.tenancy`, `seedUsers`.

### Terraform Provider

```hcl
terraform {
  required_providers {
    furnace = {
      source = "callezenwaka/furnace"
    }
  }
}

provider "furnace" {
  base_url = "http://localhost:8025"
  api_key  = "mysecret"
}

resource "furnace_user" "alice" {
  email        = "alice@example.com"
  display_name = "Alice"
  active       = true
}
```

```bash
terraform import furnace_user.alice usr_123
```

### Kubernetes Operator

Apply CRD manifests from the latest operator release, then deploy the operator:

```bash
kubectl apply -f https://github.com/<owner>/furnace/releases/latest/download/furnace.io_furnaceusers.yaml
kubectl apply -f https://github.com/<owner>/furnace/releases/latest/download/furnace.io_furnacegroups.yaml
```

Apply a user manifest — the operator syncs it to Furnace via SCIM:

```yaml
apiVersion: furnace.io/v1beta1
kind: FurnaceUser
metadata:
  name: alice
spec:
  email: alice@example.com
  displayName: Alice
  active: true
  mfaMethod: totp   # one of: none, totp, sms, push, magic_link, webauthn
```

```bash
kubectl apply -f alice.yaml
kubectl get furnaceuser alice
# NAME    EMAIL                  ACTIVE   SYNCED   AGE
# alice   alice@example.com      true     True     10s
```

The `SYNCED` column reflects the reconciliation state: `True` (synced), `False` (SCIM error), or `Unknown` (pending deletion). Failed SCIM calls surface as a condition on the object and are retried with exponential backoff — no manual intervention needed.

Configure the operator with `FURNACE_SCIM_URL` and `FURNACE_SCIM_KEY` environment variables (typically mounted from a Kubernetes Secret).

## Release Versioning

Each component uses path-prefixed git tags. Pushing a tag triggers its own workflow:

| Tag pattern | Workflow | Artifact |
|-------------|----------|----------|
| `server/v*` | `release-server.yml` | GitHub Release + `ghcr.io/<owner>/furnace:<version>` |
| `helm/v*` | `release-helm.yml` | Helm chart published to GitHub Pages |
| `terraform/v*` | `release-terraform.yml` | Terraform provider binaries (GPG-signed) |
| `operator/v*` | `release-operator.yml` | `ghcr.io/<owner>/furnace-operator:<version>` + CRD YAML manifests |

## Folder Structure

```text
.
├── client/
│   ├── admin-spa/        # Vue 3 admin SPA
│   └── notify-spa/       # Vue 3 notification hub SPA
├── server/
│   ├── cmd/furnace/    # Binary entrypoint
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
│   └── helm/furnace/   # Helm chart
├── operator/             # Kubernetes operator (controller-runtime)
├── terraform/            # Terraform provider (Plugin Framework)
└── scripts/              # Helper scripts
```
