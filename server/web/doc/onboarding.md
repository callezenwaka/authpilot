# Onboarding

Quick guide to get a project set up with users, groups, and a working login flow.

## Prerequisites

- Go installed (`brew install go`)
- `air` installed for hot-reload (`go install github.com/air-verse/air@latest`)

---

## 1. Start the Server

```bash
make setup   # install frontend dependencies (once after clone)
make dev     # start server with hot-reload + SPA watchers
```

| Service | URL |
|---------|-----|
| Home | http://localhost:18025 |
| Admin UI | http://localhost:18025/admin |
| Login UI | http://localhost:18025/login |
| API Docs | http://localhost:18025/api/v1/docs |

The Notification Hub is embedded in the Admin UI — click the bell icon (top-right)
or the **Notify Hub** button in the sidebar.

---

## 2. Get Your API Key

On first run, Furnace prints a generated key to stdout:

```
[furnace] Admin API Key: furn_a3f9c2d18e4b7a6f0c5d2e1b9a8f3c7d4e2b
```

It is also visible in the Admin UI under **Config → Admin API Key**. Copy it and
set it as an environment variable to make it persistent:

```bash
export FURNACE_API_KEY=furn_a3f9c2d18e4b7a6f0c5d2e1b9a8f3c7d4e2b
```

All API calls below assume this export is in place, or pass the header explicitly:

```bash
-H "X-Furnace-Api-Key: $FURNACE_API_KEY"
```

---

## 3. Create a Group

`id` is optional — omit it for an auto-generated `grp_<id>`, or supply one for a
stable reference you can reuse in scripts and CI:

```bash
# Auto-generated ID
curl -X POST http://localhost:18025/api/v1/groups \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"display_name":"Engineering"}'

# Explicit ID (deterministic — safe to re-run)
curl -X POST http://localhost:18025/api/v1/groups \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"id":"grp_engineering","display_name":"Engineering"}'
```

---

## 4. Create Users

`id` is optional on all user requests. Omit it to let the server generate a
`usr_<id>`, or provide one to import existing IDs from another system.

**Alice — no MFA:**

```bash
curl -X POST http://localhost:18025/api/v1/users \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "display_name": "Alice",
    "active": true,
    "groups": ["grp_engineering"]
  }'
```

**Bob — TOTP MFA (explicit ID for CI seeding):**

```bash
curl -X POST http://localhost:18025/api/v1/users \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "usr_bob",
    "email": "bob@example.com",
    "display_name": "Bob",
    "active": true,
    "mfa_method": "totp",
    "groups": ["grp_engineering"]
  }'
```

**Carol — push MFA:**

```bash
curl -X POST http://localhost:18025/api/v1/users \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "carol@example.com",
    "display_name": "Carol",
    "active": true,
    "mfa_method": "push",
    "groups": ["grp_engineering"]
  }'
```

---

## 5. Verify

```bash
curl -H "X-Furnace-Api-Key: $FURNACE_API_KEY" http://localhost:18025/api/v1/users
```

---

## 6. Test Login

1. Open `http://localhost:18025/login` in your browser
2. Select a user and click **Continue**
3. If the user has MFA, open the Notify Hub (bell icon) to retrieve the code or
   approve the push

See [login-simulation.md](login-simulation.md) for all MFA methods and flow scenarios.

---

## 7. Mint a Token (CI / Testing)

Skip the browser flow and get a token directly:

```bash
curl -X POST http://localhost:18025/api/v1/tokens/mint \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"usr_bob","client_id":"myapp","expires_in":3600}'
```
