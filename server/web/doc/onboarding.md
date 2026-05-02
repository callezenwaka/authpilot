# Onboarding

Quick guide to get Furnace set up with users, groups, and a working login flow.

> New here? Start with [Installation](/doc/installation) to get Furnace running first.

---

## 1. Get Your API Key

Open the Admin UI, go to **Config**, and copy the value from the **Admin API Key** row.

Export it along with the base URL so the `curl` commands below work without modification:

```bash
export FURNACE_API_KEY=furn_...        # paste your key here
export FURNACE_URL=$FURNACE_URL   # Docker; use :18025 for make dev
```

---

## 2. Create a Group

`id` is optional — omit it for an auto-generated `grp_<id>`, or supply one for a
stable reference you can reuse in scripts and CI:

```bash
# Auto-generated ID
curl -X POST $FURNACE_URL/api/v1/groups \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"display_name":"Engineering"}'

# Explicit ID (deterministic — safe to re-run)
curl -X POST $FURNACE_URL/api/v1/groups \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"id":"grp_engineering","display_name":"Engineering"}'
```

---

## 3. Create Users

`id` is optional on all user requests. Omit it to let the server generate a
`usr_<id>`, or provide one to import existing IDs from another system.

**Alice — no MFA:**

```bash
curl -X POST $FURNACE_URL/api/v1/users \
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
curl -X POST $FURNACE_URL/api/v1/users \
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
curl -X POST $FURNACE_URL/api/v1/users \
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

## 4. Verify

```bash
curl -H "X-Furnace-Api-Key: $FURNACE_API_KEY" $FURNACE_URL/api/v1/users
```

---

## 5. Test Login

1. Open `$FURNACE_URL/login` in your browser
2. Select a user and click **Continue**
3. If the user has MFA, click the bell icon (top-right in the Admin UI) to retrieve
   the code or approve the push

See [login-simulation.md](/doc/login-simulation) for all MFA methods and flow scenarios.

---

## 6. Mint a Token (CI / Testing)

Skip the browser flow and get a token directly:

```bash
curl -X POST $FURNACE_URL/api/v1/tokens/mint \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"usr_bob","client_id":"myapp","expires_in":3600}'
```
