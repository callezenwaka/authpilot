# Contributing to Furnace

## Development Setup

```bash
git clone https://github.com/callezenwaka/furnace
cd furnace
make setup   # install npm dependencies + pre-commit hook
make dev     # hot-reload Go server + SPA watcher
```

Open `http://localhost:18025` for the home page, or `http://localhost:18025/admin` for the admin UI.

With a config file:

```bash
go run ./server/cmd/furnace -config ./configs/furnace.yaml
```

## Make Targets

| Target | Description |
|--------|-------------|
| `make setup` | Install npm dependencies + pre-commit hook (run once after clone) |
| `make dev` | Start server with hot-reload + SPA watcher |
| `make build` | Compile the production binary (embeds SPA) |
| `make test` | Run all tests |
| `make lint` | Run golangci-lint |
| `make run` | Start on dev-safe ports (`:18025` / `:18026`) |

## Testing Docker locally

Build and run from source to verify the production image before pushing:

```bash
docker build -t furnace .

docker run --rm \
  -p 8025:8025 \
  -p 8026:8026 \
  -v furnace_data:/data \
  furnace
```

Open `http://localhost:8025` once the container starts.

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

## Release Versioning

Tags follow a `<component>/v*` prefix pattern so a single monorepo can release
each artifact independently.

| Tag pattern | Workflow | Artifact |
|-------------|----------|----------|
| `server/v*` | `release-server.yml` | GitHub Release + Docker image |
| `helm/v*` | `release-helm.yml` | Helm chart on GitHub Pages |
| `terraform/v*` | `release-terraform.yml` | Terraform provider binaries |
| `operator/v*` | `release-operator.yml` | Operator image + CRD YAML manifests |

```bash
git tag server/v0.2.0
git push origin server/v0.2.0
```

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
kubectl apply -f https://github.com/callezenwaka/furnace/releases/latest/download/furnace.io_furnaceusers.yaml
kubectl apply -f https://github.com/callezenwaka/furnace/releases/latest/download/furnace.io_furnacegroups.yaml
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
