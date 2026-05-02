# Furnace

A local-first authentication development platform. Build and test OIDC, SAML, and
WS-Federation flows against a real protocol implementation before connecting to a
production SSO provider.

## Ports

| Port | Purpose |
|------|---------|
| `:8025` | Admin UI (`/admin`), management API (`/api/v1`), login UI (`/login`) |
| `:8026` | OIDC, SAML, WS-Fed protocol endpoints |

## Quick Start

```bash
git clone https://github.com/<owner>/furnace
cd furnace
make setup
make dev
```

`make setup` installs frontend dependencies. `make dev` starts the Go server with
hot-reload and watches the SPA for changes. Open `http://localhost:18025` for the
home page, or go straight to `http://localhost:18025/admin` for the admin UI.

With a config file:

```bash
go run ./server/cmd/furnace -config ./configs/furnace.yaml
```

## Docker

### Docker Compose (recommended)

```bash
docker compose up --build
```

**Admin API key** — auto-generated on first start. It is never printed to logs. Open the admin UI, go to **Config → Admin API Key**, and copy it from there.

To make it persistent across restarts, add it to a `.env` file:

```bash
# .env  (add to .gitignore)
FURNACE_API_KEY=furn_...   # paste from Config page
```

### docker run

```bash
docker build -t furnace .

docker run --rm \
  -p 8025:8025 \
  -p 8026:8026 \
  -v furnace_data:/data \
  furnace
```

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

## Make Targets

| Target | Description |
|--------|-------------|
| `make setup` | Install npm dependencies (run once after clone) |
| `make dev` | Start server with hot-reload + SPA watcher |
| `make build` | Compile the production binary (embeds SPA) |
| `make test` | Run all tests |
| `make lint` | Run golangci-lint |
| `make run` | Start on dev-safe ports (`:18025` / `:18026`) |

## Ecosystem

### Helm Chart

```bash
helm install furnace ./deploy/helm/furnace \
  --set config.apiKey=mysecret \
  --set image.tag=v0.1.0
```

### Terraform Provider

```hcl
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

### Kubernetes Operator

```bash
kubectl apply -f https://github.com/<owner>/furnace/releases/latest/download/furnace.io_furnaceusers.yaml
kubectl apply -f https://github.com/<owner>/furnace/releases/latest/download/furnace.io_furnacegroups.yaml
```

```yaml
apiVersion: furnace.io/v1beta1
kind: FurnaceUser
metadata:
  name: alice
spec:
  email: alice@example.com
  displayName: Alice
  active: true
```

```bash
kubectl get furnaceuser alice
# NAME    EMAIL               ACTIVE   SYNCED   AGE
# alice   alice@example.com   true     True     10s
```

## Release Versioning

| Tag pattern | Workflow | Artifact |
|-------------|----------|----------|
| `server/v*` | `release-server.yml` | GitHub Release + Docker image |
| `helm/v*` | `release-helm.yml` | Helm chart on GitHub Pages |
| `terraform/v*` | `release-terraform.yml` | Terraform provider binaries |
| `operator/v*` | `release-operator.yml` | Operator image + CRD YAML manifests |

```bash
git tag server/v0.1.0
git push origin server/v0.1.0
```

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

## Folder Structure

```text
.
├── client/
│   └── admin-spa/        # Vue 3 admin SPA
├── server/
│   ├── cmd/furnace/      # Binary entrypoint
│   ├── internal/         # Protocol engine, API handlers, stores
│   └── web/doc/          # Markdown docs (served at /doc/*)
├── configs/              # Example YAML configs
├── deploy/
│   └── helm/furnace/     # Helm chart
├── operator/             # Kubernetes operator (controller-runtime)
├── terraform/            # Terraform provider (Plugin Framework)
└── scripts/              # Helper scripts
```
