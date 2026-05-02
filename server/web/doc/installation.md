# Installation

Get Furnace running in under five minutes.

---

## What you need

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running — that's it.

No accounts, no sign-ups, no API keys to configure upfront.

---

## Option 1 — Single container (quickest)

```bash
docker run -p 8025:8025 -p 8026:8026 callezenwaka/furnace:latest
```

Once it starts, open **[http://localhost:8025/admin](http://localhost:8025/admin)** in your browser.

> Data and sessions are lost when the container stops. This is fine for a quick evaluation — use Option 2 if you want them to persist.

---

## Option 2 — Docker Compose (recommended for teams)

Create a `docker-compose.yml`:

```yaml
services:
  furnace:
    image: callezenwaka/furnace:latest
    ports:
      - "8025:8025"
      - "8026:8026"
    volumes:
      - furnace_data:/data

volumes:
  furnace_data:
```

Start:

```bash
docker compose up
```

The volume keeps your users, groups, policies, and generated keys across restarts — so login sessions survive container restarts automatically. No manual key setup required.

---

## Persistence reference

| What you want | How to get it |
|---|---|
| Fully ephemeral — fresh state on every run | Plain `docker run`, no volume, no env vars |
| Data **and** sessions persist across restarts | Add a volume (`-v` or `volumes:` in Compose) — Furnace stores its generated keys in SQLite automatically |
| Sessions persist, data resets on restart | Set `FURNACE_SESSION_HASH_KEY` env var without a volume |
| Data persists, sessions reset on restart | Volume only, no `FURNACE_SESSION_HASH_KEY` — unusual but valid |

For most teams, a volume is all you need. For a solo developer evaluating, neither is required.

---

## Check it's working

| Page | URL |
|------|-----|
| Home | http://localhost:8025 |
| Admin UI | http://localhost:8025/admin |
| Login UI | http://localhost:8025/login |
| API Docs | http://localhost:8025/api/v1/docs |
| OIDC Discovery | http://localhost:8026/.well-known/openid-configuration |

---

## Get your API key

Furnace generates an admin API key automatically on first start. You won't see it in the logs — open the Admin UI, go to **Config**, and copy it from the **Admin API Key** row.

You'll need this key for any `curl` commands in the other guides:

```bash
export FURNACE_API_KEY=furn_...   # paste your key here
```

---

## Session key

Furnace also generates a session signing key automatically on first start. It controls whether active login sessions survive a container restart. You can find it in **Admin UI → Config → Session Hash Key**.

You do not need to do anything with it in the common cases:

| Setup | Session behaviour |
|---|---|
| `docker run` (no volume) | New key every start — sessions reset on restart (expected) |
| Docker Compose with volume | Key stored in SQLite and reused — sessions survive restarts automatically |

The only time to copy and set `FURNACE_SESSION_HASH_KEY` explicitly is when you need sessions to survive a complete volume wipe — for example, when migrating to a new server and recreating the volume from scratch.

---

Next: [Onboarding →](/doc/onboarding)
