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

**Admin API key** — on first run, Furnace generates a random key and prints it:

```
[furnace] Admin API Key: furn_a3f9c2d18e4b7a6f0c5d2e1b9a8f3c7d4e2b
[furnace] Set FURNACE_API_KEY env var to persist this key across restarts.
```

The key is also visible in the admin UI under **Config → Admin API Key**.
To make it persistent, add it to a `.env` file:

```bash
# .env  (add to .gitignore)
FURNACE_API_KEY=furn_a3f9c2d18e4b7a6f0c5d2e1b9a8f3c7d4e2b
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
| `FURNACE_API_KEY` | _(auto-generated)_ | Protects `/api/v1/`; printed on startup if not set |
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
| [Onboarding](server/web/doc/onboarding.md) | Step-by-step: create users, groups, and test a login flow |
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
