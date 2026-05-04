# Configuration

Furnace is configured through four layers — built-in defaults, a YAML file, environment variables, and CLI flags. Every setting has a sensible default; configure only what your environment needs to change.

Config precedence: runtime flags > environment variables > YAML file > defaults.

## Furnace Variables

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

## Usage

Each layer overrides everything below it. Select a layer to see when and why to use it:

<div class="tabs" data-tabs>
<div class="tab-list">
<button class="tab-btn active" data-tab="defaults">Defaults</button>
<button class="tab-btn" data-tab="yaml">furnace.yaml</button>
<button class="tab-btn" data-tab="env">Env vars</button>
<button class="tab-btn" data-tab="flags">CLI flags</button>
</div>

<div class="tab-panel active" data-panel="defaults">

<p><strong>Use when:</strong> you are running Furnace locally and don't need to share config with a team.</p>

<p>Every setting has a built-in default. For local development you need zero configuration — run <code>furnace</code> with no arguments and it starts on <code>:8025</code>/<code>:8026</code> with SQLite persistence, an auto-generated API key, and the default OIDC provider. Open the admin UI at <code>http://localhost:8025/admin</code> and go.</p>

<p><strong>When to move away from defaults:</strong></p>
<ul>
  <li>You need stable API keys across restarts → set <code>FURNACE_API_KEY</code></li>
  <li>You are sharing config with teammates → add a <code>furnace.yaml</code></li>
  <li>You are running in Docker or CI → use env vars</li>
</ul>

</div>

<div class="tab-panel" data-panel="yaml">

<p><strong>Use when:</strong> you want to commit a shared base config that the whole team uses.</p>

<p><code>furnace.yaml</code> is not auto-discovered — pass it explicitly with <code>-config furnace.yaml</code>. Any key not present in the file falls through to the built-in default. Env vars and CLI flags still override the file, so teammates can layer their own overrides without editing it.</p>

<p><strong>Good candidates for YAML:</strong></p>
<ul>
  <li>Ports, log level, provider personality</li>
  <li>Seed users for a shared dev dataset</li>
  <li>OPA resource budgets and decision log settings</li>
  <li>Multi-tenant IDs and per-tenant limits</li>
  <li>OIDC token TTLs and key rotation schedule</li>
</ul>

<p><strong>Never put in YAML:</strong> <code>FURNACE_API_KEY</code>, <code>FURNACE_SCIM_KEY</code>, <code>FURNACE_SESSION_HASH_KEY</code> — these have no YAML equivalent by design to avoid committing secrets.</p>

</div>

<div class="tab-panel" data-panel="env">

<p><strong>Use when:</strong> configuring Docker containers, CI pipelines, or anything where you can't pass CLI flags directly.</p>

<p>Every YAML key has an equivalent <code>FURNACE_*</code> env var. Env vars override the YAML file but are overridden by CLI flags. They are the right place for:</p>
<ul>
  <li><strong>Secrets</strong> — <code>FURNACE_API_KEY</code>, <code>FURNACE_SCIM_KEY</code>, <code>FURNACE_SESSION_HASH_KEY</code> are env-var only (no YAML equivalent)</li>
  <li><strong>Environment-specific values</strong> — a different <code>FURNACE_SQLITE_PATH</code> in staging vs production</li>
  <li><strong>CI overrides</strong> — disable persistence (<code>FURNACE_PERSISTENCE_ENABLED=false</code>) for ephemeral test runs</li>
</ul>

<p>In Docker Compose, read secrets from a host <code>.env</code> file so they are never committed:</p>
<pre><code>FURNACE_API_KEY: ${FURNACE_API_KEY}
FURNACE_SESSION_HASH_KEY: ${FURNACE_SESSION_HASH_KEY}</code></pre>

</div>

<div class="tab-panel" data-panel="flags">

<p><strong>Use when:</strong> you want a one-off override without editing any file or env var.</p>

<p>CLI flags are the highest-priority layer — they override the YAML file and all env vars for that single process run. Nothing is persisted; the next run reverts to whatever the lower layers say.</p>

<p><strong>Common one-off uses:</strong></p>
<ul>
  <li>Test against a different provider: <code>-provider azure-ad</code></li>
  <li>Increase verbosity for a debugging session: <code>-log-level debug</code></li>
  <li>Run ephemeral with no database: <code>-persistence-enabled false</code></li>
  <li>Point at a different SQLite file: <code>-sqlite-path ./test.db</code></li>
</ul>

<p>Flags complement <code>furnace.yaml</code> — run with <code>-config furnace.yaml</code> to load the shared base, then add flags for what you want to change for this session only.</p>

</div>

</div>

---

## Configuration Layers

Full sample for each layer — copy, uncomment, and edit what you need:

<div class="tabs" data-tabs>
<div class="tab-list">
<button class="tab-btn active" data-tab="defaults">Defaults</button>
<button class="tab-btn" data-tab="yaml">furnace.yaml</button>
<button class="tab-btn" data-tab="env">Env vars</button>
<button class="tab-btn" data-tab="flags">CLI flags</button>
</div>

<div class="tab-panel active" data-panel="defaults">

<p>Built-in values the binary uses when a setting is not overridden at any higher layer.</p>

<pre><code># Effective defaults — what Furnace uses when nothing overrides a setting

http_addr:                  :8025
protocol_addr:              :8026
log_level:                  info
rate_limit:                 0           # disabled
provider:                   default
tenancy:                    single
header_propagation:         false
cors_origins:               *           # all origins allowed on the protocol server

persistence.enabled:        true
persistence.sqlite_path:    ./data/furnace.db

oidc.issuer_url:            http://localhost:8026
oidc.access_token_ttl:      1h
oidc.id_token_ttl:          1h
oidc.refresh_token_ttl:     720h
oidc.key_rotation_interval: 0           # disabled — key never rotates
oidc.key_rotation_overlap:  24h

saml.entity_id:             http://localhost:8026
saml.cert_dir:              ""          # ephemeral — new key on every restart

webauthn.rp_id:             localhost   # auto-derived from http_addr
webauthn.origin:            http://localhost:8025

api_key:                    furn_...    # auto-generated — copy from Admin → Config
session_hash_key:           (random)    # auto-generated — sessions reset on restart

opa.compile_timeout:        2s
opa.eval_timeout:           5s
opa.max_policy_bytes:       65536       # 64 KiB
opa.max_data_bytes:         5242880     # 5 MiB
opa.max_batch_checks:       100
opa.max_concurrent:         runtime.NumCPU()
opa.decision_log.enabled:   false</code></pre>

</div>

<div class="tab-panel" data-panel="yaml">

<p>Pass the path with <code>-config</code> — the file is not auto-discovered.</p>

<pre><code>furnace -config furnace.yaml
go run ./server/cmd/furnace -config furnace.yaml
docker run -v $(pwd)/furnace.yaml:/furnace.yaml ghcr.io/... -config /furnace.yaml</code></pre>

<pre><code># furnace.yaml — full reference
# Omit any key to use the built-in default.
# FURNACE_API_KEY, FURNACE_SCIM_KEY, FURNACE_SESSION_HASH_KEY have no YAML
# equivalent — set them as env vars to keep secrets out of version control.

http_addr: ":8025"
protocol_addr: ":8026"
log_level: info             # debug | info | warn | error
rate_limit: 0               # requests/min per IP on /api/v1; 0 = disabled
provider: default           # default | okta | azure-ad | google-workspace | google | github | onelogin
tenancy: single             # single | multi
header_propagation: false
cors_origins: []            # empty = allow all origins on the protocol server
trusted_proxy_cidrs: []     # honour X-Forwarded-For only from these CIDRs

persistence:
  enabled: true
  sqlite_path: ./data/furnace.db

oidc:
  issuer_url: http://localhost:8026
  access_token_ttl: 1h
  id_token_ttl: 1h
  refresh_token_ttl: 720h
  key_rotation_interval: 0    # e.g. 24h; 0 = disabled
  key_rotation_overlap: 24h   # keep retired key in JWKS for this long after rotation

saml:
  entity_id: http://localhost:8026
  cert_dir: ""                # set to persist SAML signing key across restarts

webauthn:
  rp_id: ""                   # domain only, e.g. example.com; defaults to localhost
  origin: ""                  # full URL, e.g. https://example.com

tokens:
  include_jti: false          # add jti (unique token ID) to every token
  aud_as_array: false         # emit aud as ["clientID"] instead of "clientID"
  include_scope: false        # add scope claim to access token

# Users created idempotently at startup — safe to restart without duplicates
seed_users:
  - email: alice@example.com
    display_name: Alice
    mfa_method: totp          # totp | sms | push | magic | webauthn | ""
    next_flow: normal         # normal | mfa_fail | slow_mfa | account_locked
    active: true
    groups: [engineering]
    phone_number: "+15550001234"
    claims:
      department: engineering

# Multi-tenancy — requires tenancy: multi
tenants:
  - id: acme
    api_key: key-acme
    scim_key: scim-acme
    oidc_issuer_url: ""       # optional per-tenant issuer override
  - id: widgets
    api_key: key-widgets

opa:
  compile_timeout: 2s
  eval_timeout: 5s
  max_policy_bytes: 65536     # 64 KiB
  max_data_bytes: 5242880     # 5 MiB
  max_batch_checks: 100
  max_concurrent: 0           # 0 = runtime.NumCPU()
  decision_log:
    enabled: false
    destination: stdout       # stdout | stderr | /path/to/file.ndjson
    include_input: false
    include_policy: false
    redact_fields:
      - user.claims.email
      - user.claims.ssn
    scrub_policy_credentials: false
    retention_days: 0         # 0 = unlimited
  tenant_budgets:             # per-tenant limits — can only be tighter than global
    acme:
      eval_timeout: 2s
      max_batch_checks: 25
      decision_log:
        additional_redact_fields:
          - user.claims.phone
        retention_days: 30</code></pre>

</div>

<div class="tab-panel" data-panel="env">

<p>Every setting except the three secrets at the bottom can also be set in <code>furnace.yaml</code>.</p>

<pre><code># Shell
export FURNACE_HTTP_ADDR=":8025"
export FURNACE_PROTOCOL_ADDR=":8026"
export FURNACE_LOG_LEVEL=info
export FURNACE_RATE_LIMIT=0
export FURNACE_PROVIDER=default
export FURNACE_TENANCY=single
export FURNACE_HEADER_PROPAGATION=false
export FURNACE_CORS_ORIGINS=""
export FURNACE_PERSISTENCE_ENABLED=true
export FURNACE_SQLITE_PATH=./data/furnace.db
export FURNACE_OIDC_ISSUER_URL=http://localhost:8026
export FURNACE_KEY_ROTATION_INTERVAL=0
export FURNACE_KEY_ROTATION_OVERLAP=24h
export FURNACE_SAML_ENTITY_ID=http://localhost:8026
export FURNACE_SAML_CERT_DIR=""
export FURNACE_WEBAUTHN_RP_ID=""
export FURNACE_WEBAUTHN_ORIGIN=""
export FURNACE_SCIM_MODE=""
export FURNACE_SCIM_TARGET=""
export FURNACE_OPA_DECISION_LOG_REDACT_FIELDS=""
export FURNACE_OPA_DECISION_LOG_SCRUB_CREDENTIALS=false
export FURNACE_OPA_DECISION_LOG_RETENTION_DAYS=0
export FURNACE_SEED_USERS='[{email: alice@example.com, display_name: Alice, active: true}]'

# Secrets — env-var only, no YAML equivalent
export FURNACE_API_KEY="$(openssl rand -hex 20)"
export FURNACE_SCIM_KEY=""
export FURNACE_SESSION_HASH_KEY="$(openssl rand -base64 32)"</code></pre>

<p>Docker Compose <code>environment:</code> block:</p>

<pre><code>environment:
  FURNACE_HTTP_ADDR: ":8025"
  FURNACE_PROTOCOL_ADDR: ":8026"
  FURNACE_LOG_LEVEL: info
  FURNACE_PROVIDER: default
  FURNACE_PERSISTENCE_ENABLED: "true"
  FURNACE_SQLITE_PATH: /data/furnace.db
  FURNACE_OIDC_ISSUER_URL: http://localhost:8026
  # Secrets — read from host .env so they are never committed
  FURNACE_API_KEY: ${FURNACE_API_KEY}
  FURNACE_SESSION_HASH_KEY: ${FURNACE_SESSION_HASH_KEY}</code></pre>

</div>

<div class="tab-panel" data-panel="flags">

<p>Flags override env vars and <code>furnace.yaml</code>. Changes apply to this run only — nothing is persisted.</p>

<pre><code>furnace \
  -config              furnace.yaml       # path to YAML file (not auto-discovered)
  -http-addr           :8025              # management server listen address
  -protocol-addr       :8026              # OIDC/SAML protocol server listen address
  -log-level           info               # debug | info | warn | error
  -provider            default            # default | okta | azure-ad | google-workspace | google | github | onelogin
  -sqlite-path         ./data/furnace.db  # SQLite database path
  -persistence-enabled true               # true | false
  -cleanup-interval    5m                 # how often expired flows/sessions are pruned</code></pre>

<p>Common one-liners:</p>

<pre><code># Load shared YAML base but switch provider for this session only
furnace -config furnace.yaml -provider azure-ad

# Ephemeral in-memory run — nothing written to disk
furnace -persistence-enabled false

# Debug logging without touching furnace.yaml
furnace -config furnace.yaml -log-level debug

# go run with multiple overrides
go run ./server/cmd/furnace -config furnace.yaml -provider okta -log-level debug</code></pre>

</div>

</div>

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

Switch the claim shape Furnace issues to match a target IdP. Takes effect immediately — no restart required.

| Provider | Key remappings |
|----------|----------------|
| `default` | Standard OIDC (`email`, `name`, `sub`) |
| `azure-ad` | `preferred_username`, `tid` tenant claim |
| `okta` | `login`, `groups` array |
| `google-workspace` | `email`, `email_verified`, `hd` hosted domain |
| `google` | `email`, `email_verified` |
| `github` | `login`, `avatar_url` |
| `onelogin` | `email`, `name` with OneLogin extras |

Four ways to set it — all are equivalent and live:

**Admin UI** — go to **Config → Provider Personality** and click a card.

**Environment variable:**
```bash
FURNACE_PROVIDER=okta docker run ...
```

**CLI flag:**
```bash
go run ./server/cmd/furnace -provider azure-ad
```

**YAML config** (`provider:` key):
```yaml
provider: okta
```

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
