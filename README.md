# Furnace

A local-first authentication development platform. Build and test OIDC, SAML, and
WS-Federation flows against a real protocol implementation before connecting to a
production SSO provider.

## Ports

| Port | Purpose |
|------|---------|
| `:8025` | Admin UI (`/admin`), management API (`/api/v1`), login UI (`/login`) |
| `:8026` | OIDC, SAML, WS-Fed protocol endpoints |

## Docker

### Docker Compose (recommended)

```bash
docker compose up --build
```

Open `http://localhost:8025` once the container starts.

**Admin API key** — auto-generated on first start, never printed to logs. Open the admin UI,
go to **Config → Admin API Key**, and copy it from there.

To make it persistent across restarts, add it to a `.env` file:

```bash
# .env  (add to .gitignore)
FURNACE_API_KEY=furn_...   # paste from Config page
```

### docker run

```bash
docker run --rm \
  -p 8025:8025 \
  -p 8026:8026 \
  -v furnace_data:/data \
  callezenwaka/furnace:latest
```

Open `http://localhost:8025` once running.

### Published images

```bash
# Docker Hub
docker run --rm -p 8025:8025 -p 8026:8026 -v furnace_data:/data \
  callezenwaka/furnace:latest

# GHCR
docker run --rm -p 8025:8025 -p 8026:8026 -v furnace_data:/data \
  ghcr.io/callezenwaka/furnace:latest
```

Pin a specific version by replacing `:latest` with `:v0.1.0`.

### Key environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FURNACE_API_KEY` | _(auto-generated)_ | Protects `/api/v1/`; copy from Admin UI → Config → Admin API Key |
| `FURNACE_SESSION_HASH_KEY` | _(auto-generated)_ | Signs session cookies; copy from Admin UI → Config → Session Hash Key to persist across volume wipes |
| `FURNACE_PERSISTENCE_ENABLED` | `true` | `false` = in-memory only |
| `FURNACE_SQLITE_PATH` | `./data/furnace.db` | SQLite database path |
| `FURNACE_PROVIDER` | `default` | Provider personality: `okta`, `azure-ad`, `google`, `github`, `onelogin` |
| `FURNACE_CORS_ORIGINS` | _(none = `*`)_ | Comma-separated allowed origins |
| `FURNACE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |

Full variable reference: [doc/configuration.md](server/web/doc/configuration.md)

## Documentation

| Doc | Contents |
|-----|----------|
| [Installation](server/web/doc/installation.md) | Docker setup, persistence options, getting your API key |
| [Onboarding](server/web/doc/onboarding.md) | Step-by-step: create users, groups, and test a login flow |
| [Providers](server/web/doc/providers.md) | Provider personalities — config, claims, wiring, and pitfalls |
| [Integration Guide](server/web/doc/integration.md) | Connecting your OIDC client to Furnace |
| [API Reference](server/web/doc/api-reference.md) | All endpoints — OIDC, SAML, WS-Fed, SCIM, management API |
| [Configuration](server/web/doc/configuration.md) | All environment variables, multi-tenancy, SCIM client mode |
| [Security](server/web/doc/security.md) | API key, CSRF, CORS, network exposure |
| [Login Simulation](server/web/doc/login-simulation.md) | Flow scenarios and MFA methods |

---

Contributing? See [CONTRIBUTING.md](CONTRIBUTING.md).
