# API Reference

All management API endpoints are served on `:8025`. Every response includes an
`X-Request-ID` header for log correlation. All `/api/v1` endpoints require the
`X-Furnace-Api-Key` or `Authorization: Bearer` header.

---

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

---

## SAML Endpoints

Served on `:8026` alongside OIDC.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/saml/metadata` | GET | IdP metadata XML |
| `/saml/sso` | GET, POST | SP-initiated SSO — HTTP-Redirect and HTTP-POST bindings |
| `/saml/slo` | GET, POST | Single Logout — SP-initiated and IdP-initiated |
| `/saml/cert` | GET | Download the IdP signing certificate (PEM) |
| `/saml/flows` | GET | Debug list of active SAML flows |

Configure your SP with:
- **IdP Entity ID:** `http://localhost:8026`
- **SSO URL:** `http://localhost:8026/saml/sso`
- **SLO URL:** `http://localhost:8026/saml/slo`
- **Metadata URL:** `http://localhost:8026/saml/metadata`

To trigger IdP-initiated logout:

```bash
curl http://localhost:8026/saml/slo?user_id=<user-id>
```

---

## WS-Federation Endpoints

Served on `:8026`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/wsfed` | GET, POST | Passive requestor endpoint |
| `/federationmetadata/2007-06/federationmetadata.xml` | GET | Federation metadata XML |

Configure your relying party with:
- **Passive Requestor Endpoint:** `http://localhost:8026/wsfed`
- **Metadata URL:** `http://localhost:8026/federationmetadata/2007-06/federationmetadata.xml`
- **Token type:** SAML 1.1 (signed with RSA-SHA256, exc-c14n)

---

## SCIM 2.0 Endpoints

Served on `:8025` under `/scim/v2`.

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/scim/v2/ServiceProviderConfig` | GET | Server capabilities |
| `/scim/v2/Schemas` | GET | All schema definitions |
| `/scim/v2/Schemas/{id}` | GET | Single schema by URN |
| `/scim/v2/Users` | GET, POST | List (with `filter=`) / create users |
| `/scim/v2/Users/{id}` | GET, PUT, PATCH, DELETE | Read / replace / patch / delete a user |
| `/scim/v2/Groups` | GET, POST | List / create groups |
| `/scim/v2/Groups/{id}` | GET, PUT, PATCH, DELETE | Read / replace / patch / delete a group |

PATCH supports `add`, `replace`, and `remove` operations on members.
Filter supports `userName eq "..."` and `displayName eq "..."` on Users.

---

## Management API

Served on `:8025` under `/api/v1`.

| Resource | Endpoints |
|----------|-----------|
| Users | `GET/POST /api/v1/users`, `GET/PUT/DELETE /api/v1/users/{id}` |
| Groups | `GET/POST /api/v1/groups`, `GET/PUT/DELETE /api/v1/groups/{id}` |
| Flows | `GET/POST /api/v1/flows`, `GET /api/v1/flows/{id}` |
| Flow actions | `POST /api/v1/flows/{id}/select-user` · `verify-mfa` · `approve` · `deny` · `webauthn-response` |
| Sessions | `GET /api/v1/sessions` |
| Notifications | `GET /api/v1/notifications?flow_id=<id>`, `GET /api/v1/notifications/all` |
| Audit | `GET /api/v1/audit`, `GET /api/v1/audit/export?format=<fmt>`, `GET /api/v1/audit/verify` |
| Tokens | `POST /api/v1/tokens/mint` |
| Config | `GET /api/v1/config`, `PATCH /api/v1/config` |
| SCIM events | `GET /api/v1/scim/events` |
| Export | `GET /api/v1/export?format=<fmt>` |
| Debug | `GET /api/v1/debug/token-compare` |
| API contract | `GET /api/v1/openapi.json`, `GET /api/v1/docs` |

### Export

```bash
curl http://localhost:8025/api/v1/export?format=scim   -o users.json
curl http://localhost:8025/api/v1/export?format=okta   -o users.csv
curl http://localhost:8025/api/v1/export?format=azure  -o azure-users.json
curl http://localhost:8025/api/v1/export?format=google -o google-users.csv
```

### Audit

```bash
curl http://localhost:8025/api/v1/audit
curl "http://localhost:8025/api/v1/audit?event_type=user.created&since=2026-01-01T00:00:00Z"
curl http://localhost:8025/api/v1/audit/export?format=json-nd -o audit.jsonl
curl http://localhost:8025/api/v1/audit/export?format=cef     -o audit.cef
curl http://localhost:8025/api/v1/audit/export?format=syslog  -o audit.log
```

#### Audit Log Integrity

`GET /api/v1/audit/verify` walks every entry in the audit log and recomputes the
tamper-evident hash chain. Returns `200` with `"ok": true` when the chain is
intact, or `409` with `"ok": false` and a `broken_at` event ID when a mismatch
is detected.

```bash
curl http://localhost:8025/api/v1/audit/verify
```

```json
{ "ok": true, "checked": 1042, "message": "chain intact" }
```

```json
{ "ok": false, "checked": 207, "broken_at": "evt_0a1b2c3d", "message": "hash mismatch" }
```

### Token Minting

Mint tokens for CI/CD without running the full OAuth flow:

```bash
curl -X POST http://localhost:8025/api/v1/tokens/mint \
  -H "Content-Type: application/json" \
  -d '{"user_id": "usr_123", "client_id": "myapp", "expires_in": 3600}'
```

### Token Compare

Compare claim shape between a Furnace token and a real provider token:

```bash
curl "http://localhost:8025/api/v1/debug/token-compare?furnace_token=eyJ...&provider_token=eyJ..."
```

Returns a `differences` array with `path`, `furnace_value`, `provider_value`, and `note`.

### Live Config

```bash
curl http://localhost:8025/api/v1/config
curl -X PATCH http://localhost:8025/api/v1/config \
  -H "Content-Type: application/json" \
  -d '{"tokens": {"access_token_ttl": 7200}}'
```

### Idempotency

All `POST /api/v1` endpoints support idempotency keys:

```bash
curl -X POST http://localhost:8025/api/v1/users \
  -H "Idempotency-Key: my-unique-key-123" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","display_name":"Alice"}'
```

Repeat with the same key within 5 minutes — the handler runs once and returns
`Idempotent-Replayed: true` on subsequent calls.

### Rate Limiting

```bash
FURNACE_RATE_LIMIT=60 go run ./server/cmd/furnace
```

Requests over the limit receive `429 Too Many Requests` with `Retry-After` and
`X-RateLimit-*` headers.

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
