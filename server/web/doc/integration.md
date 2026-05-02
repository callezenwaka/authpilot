# Integration Guide

Use Furnace as a drop-in replacement for Okta, Azure AD, Google, or any OIDC
provider during local development and CI. Your application connects to Furnace
exactly as it would connect to a real IdP — using the standard discovery
endpoint, PKCE flows, token exchange, and JWKS verification.

---

## Step 1 — Start Furnace

**Quick start (single container)**

```bash
docker run -p 8025:8025 -p 8026:8026 callezenwaka/furnace:latest
```

**Teams — Docker Compose with persistence (recommended)**

```yaml
# docker-compose.yml
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

```bash
docker compose up
```

No env vars required. Furnace auto-generates its API key and session key on first start. With a volume, both keys persist across restarts automatically.

> Copy the API key from **Admin UI → Config → Admin API Key** and export it before running the `curl` commands below:
>
> ```bash
> export FURNACE_API_KEY=furn_...   # paste from Config page
> ```

| Endpoint | URL |
|----------|-----|
| OIDC Discovery | `http://localhost:8026/.well-known/openid-configuration` |
| JWKS | `http://localhost:8026/.well-known/jwks.json` |
| Authorization | `http://localhost:8026/authorize` |
| Token | `http://localhost:8026/oauth2/token` |
| Userinfo | `http://localhost:8026/userinfo` |
| Introspect | `http://localhost:8026/oauth2/introspect` |

---

## Step 2 — Wire your OIDC client

Replace your real IdP's discovery URL with Furnace's. Client ID and secret can
be any non-empty string — Furnace does not validate them.

**Next.js / Auth.js**

```js
// auth.ts
providers: [
  {
    id: "furnace",
    name: "Furnace",
    type: "oidc",
    issuer: "http://localhost:8026",
    clientId: "myapp",
    clientSecret: "dev-secret",
  }
]
```

**Python (Authlib / FastAPI)**

```python
oauth.register(
    name="furnace",
    server_metadata_url="http://localhost:8026/.well-known/openid-configuration",
    client_id="myapp",
    client_secret="dev-secret",
)
```

**Generic env vars**

```bash
OIDC_ISSUER=http://localhost:8026
OIDC_CLIENT_ID=myapp
OIDC_CLIENT_SECRET=dev-secret   # any non-empty value
```

> PKCE (`S256`) is required on every authorization request. Furnace rejects `plain`.

---

## Step 3 — Choose a provider personality

Set `FURNACE_PROVIDER` to the IdP you are simulating. Furnace reshapes the ID
token claims to match that provider's schema so your application sees exactly
the claim names and structure it would receive from the real service.

Select the tab for your target provider:

<div class="tabs" data-tabs>
<div class="tab-list">
<button class="tab-btn active" data-tab="default">Default</button>
<button class="tab-btn" data-tab="azure-ad">Azure AD</button>
<button class="tab-btn" data-tab="okta">Okta</button>
<button class="tab-btn" data-tab="google-workspace">Google Workspace</button>
<button class="tab-btn" data-tab="github">GitHub</button>
<button class="tab-btn" data-tab="onelogin">OneLogin</button>
</div>

<div class="tab-panel active" data-panel="default">

<h3>Activate</h3>
<p>Default is active when <code>FURNACE_PROVIDER</code> is unset. Standard OIDC claim names — no remapping.</p>

<h3>ID token claims</h3>
<table>
  <thead><tr><th>Claim</th><th>Example value</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td><code>sub</code></td><td><code>usr_abc123</code></td><td>Furnace user ID</td></tr>
    <tr><td><code>email</code></td><td><code>alice@example.com</code></td><td></td></tr>
    <tr><td><code>name</code></td><td><code>Alice</code></td><td></td></tr>
    <tr><td><code>groups</code></td><td><code>["engineering"]</code></td><td>Array of group IDs</td></tr>
    <tr><td><code>iss</code></td><td><code>http://localhost:8026</code></td><td></td></tr>
    <tr><td><code>aud</code></td><td><code>myapp</code></td><td>Your client ID</td></tr>
  </tbody>
</table>

<h3>Seed a user</h3>
<pre><code>curl -X POST http://localhost:8025/api/v1/users \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "display_name": "Alice",
    "active": true,
    "groups": ["engineering"]
  }'</code></pre>

<h3>What to check in your app</h3>
<p>Read <code>email</code> for identity and <code>groups</code> for role-based access control. No provider-specific claim names — this is the baseline.</p>

</div>

<div class="tab-panel" data-panel="azure-ad">

<h3>Activate</h3>
<pre><code>FURNACE_PROVIDER=azure-ad</code></pre>
<p>Or in <code>furnace.yaml</code>: <code>provider: azure-ad</code></p>

<h3>ID token claims</h3>
<table>
  <thead><tr><th>Claim</th><th>Example value</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td><code>sub</code></td><td><code>usr_abc123</code></td><td></td></tr>
    <tr><td><code>preferred_username</code></td><td><code>alice@example.com</code></td><td>Remapped from <code>email</code></td></tr>
    <tr><td><code>name</code></td><td><code>Alice</code></td><td></td></tr>
    <tr><td><code>groups</code></td><td><code>["engineering"]</code></td><td></td></tr>
    <tr><td><code>tid</code></td><td><code>common</code></td><td>Static tenant ID</td></tr>
    <tr><td><code>ver</code></td><td><code>2.0</code></td><td>Token version</td></tr>
  </tbody>
</table>

<h3>Seed a user</h3>
<pre><code>curl -X POST http://localhost:8025/api/v1/users \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@contoso.com",
    "display_name": "Alice",
    "active": true,
    "groups": ["grp_engineering"],
    "claims": {"oid": "00000000-0000-0000-0000-000000000001"}
  }'</code></pre>

<h3>What to check in your app</h3>
<p>Azure AD apps typically read <code>preferred_username</code> (not <code>email</code>) for the user's UPN, and may gate access on <code>tid</code> matching an expected tenant ID. Verify your app handles both correctly.</p>

</div>

<div class="tab-panel" data-panel="okta">

<h3>Activate</h3>
<pre><code>FURNACE_PROVIDER=okta</code></pre>
<p>Or in <code>furnace.yaml</code>: <code>provider: okta</code></p>

<h3>ID token claims</h3>
<table>
  <thead><tr><th>Claim</th><th>Example value</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td><code>sub</code></td><td><code>usr_abc123</code></td><td></td></tr>
    <tr><td><code>login</code></td><td><code>alice@example.com</code></td><td>Remapped from <code>email</code></td></tr>
    <tr><td><code>name</code></td><td><code>Alice</code></td><td></td></tr>
    <tr><td><code>groups</code></td><td><code>["engineering"]</code></td><td></td></tr>
    <tr><td><code>ver</code></td><td><code>1</code></td><td>Okta token version</td></tr>
    <tr><td><code>jti</code></td><td><code>okta-jti-placeholder</code></td><td>Unique token ID</td></tr>
  </tbody>
</table>

<h3>Seed a user</h3>
<pre><code>curl -X POST http://localhost:8025/api/v1/users \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "display_name": "Alice",
    "active": true,
    "groups": ["Everyone", "engineering"]
  }'</code></pre>

<h3>What to check in your app</h3>
<p>Okta applications typically read <code>login</code> (not <code>email</code>) as the primary identifier. The <code>groups</code> claim is an array — verify your app handles array-format group membership rather than a space-separated string.</p>

</div>

<div class="tab-panel" data-panel="google-workspace">

<h3>Activate</h3>
<pre><code>FURNACE_PROVIDER=google-workspace</code></pre>
<p>Or in <code>furnace.yaml</code>: <code>provider: google-workspace</code></p>

<h3>ID token claims</h3>
<table>
  <thead><tr><th>Claim</th><th>Example value</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td><code>sub</code></td><td><code>usr_abc123</code></td><td></td></tr>
    <tr><td><code>email</code></td><td><code>alice@example.com</code></td><td></td></tr>
    <tr><td><code>name</code></td><td><code>Alice</code></td><td></td></tr>
    <tr><td><code>groups</code></td><td><code>["engineering"]</code></td><td></td></tr>
    <tr><td><code>hd</code></td><td><code>example.com</code></td><td>Hosted domain — static</td></tr>
    <tr><td><code>email_verified</code></td><td><code>true</code></td><td></td></tr>
    <tr><td><code>locale</code></td><td><code>en</code></td><td></td></tr>
  </tbody>
</table>

<h3>Seed a user</h3>
<pre><code>curl -X POST http://localhost:8025/api/v1/users \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "display_name": "Alice",
    "active": true,
    "groups": ["engineering"]
  }'</code></pre>

<h3>What to check in your app</h3>
<p>Google Workspace apps often restrict access by checking the <code>hd</code> (hosted domain) claim against an allowlist — e.g. only users from <code>example.com</code>. The static value is <code>example.com</code>; to test a domain restriction failure, check against a different value in your policy or OPA rule.</p>

</div>

<div class="tab-panel" data-panel="github">

<h3>Activate</h3>
<pre><code>FURNACE_PROVIDER=github</code></pre>
<p>Or in <code>furnace.yaml</code>: <code>provider: github</code></p>

<h3>ID token claims</h3>
<table>
  <thead><tr><th>Claim</th><th>Example value</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td><code>sub</code></td><td><code>usr_abc123</code></td><td></td></tr>
    <tr><td><code>email</code></td><td><code>alice@example.com</code></td><td></td></tr>
    <tr><td><code>name</code></td><td><code>Alice</code></td><td></td></tr>
    <tr><td><code>login</code></td><td><code>github-user</code></td><td>Static placeholder</td></tr>
    <tr><td><code>groups</code></td><td><code>["engineering"]</code></td><td></td></tr>
  </tbody>
</table>

<p class="tab-note">To test with a specific GitHub username, add <code>"claims": {"login": "alice-gh"}</code> when creating the user. Custom claims on the user object take precedence over the static placeholder.</p>

<h3>Seed a user</h3>
<pre><code>curl -X POST http://localhost:8025/api/v1/users \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "display_name": "Alice",
    "active": true,
    "groups": ["engineering"],
    "claims": {"login": "alice-gh"}
  }'</code></pre>

<h3>What to check in your app</h3>
<p>GitHub OAuth apps use <code>login</code> as the primary identifier (the GitHub username), not <code>email</code>. Verify your app reads <code>login</code> where it would normally read the GitHub username from the API.</p>

</div>

<div class="tab-panel" data-panel="onelogin">

<h3>Activate</h3>
<pre><code>FURNACE_PROVIDER=onelogin</code></pre>
<p>Or in <code>furnace.yaml</code>: <code>provider: onelogin</code></p>

<h3>ID token claims</h3>
<table>
  <thead><tr><th>Claim</th><th>Example value</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td><code>sub</code></td><td><code>usr_abc123</code></td><td></td></tr>
    <tr><td><code>email</code></td><td><code>alice@example.com</code></td><td></td></tr>
    <tr><td><code>name</code></td><td><code>Alice</code></td><td></td></tr>
    <tr><td><code>groups</code></td><td><code>["engineering"]</code></td><td></td></tr>
    <tr><td><code>params</code></td><td><code>{}</code></td><td>OneLogin custom params — extend via user claims</td></tr>
  </tbody>
</table>

<p class="tab-note">Populate <code>params</code> with your application's OneLogin custom attributes by adding them to <code>"claims": {"params": {"department": "eng"}}</code> when seeding the user.</p>

<h3>Seed a user</h3>
<pre><code>curl -X POST http://localhost:8025/api/v1/users \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "display_name": "Alice",
    "active": true,
    "groups": ["engineering"],
    "claims": {"params": {"department": "eng", "cost_center": "1001"}}
  }'</code></pre>

<h3>What to check in your app</h3>
<p>OneLogin apps that consume custom parameters should verify that <code>params</code> is present and contains the expected keys. Test both the happy path (correct params) and the missing-params path to confirm your app handles absent custom attributes gracefully.</p>

</div>
</div>

---

## Step 4 — Run the browser flow or mint a token

**Browser flow** — open `http://localhost:8026/authorize` with your app's OIDC
client, complete the login UI at `/login`, and your app will receive a real
authorization code it can exchange at `/oauth2/token`.

**CI / testing** — skip the browser entirely and mint a token directly:

```bash
curl -X POST http://localhost:8025/api/v1/tokens/mint \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"usr_abc123","client_id":"myapp","expires_in":3600}'
```

---

## Step 5 — Verify the token

Inspect the token your app received against Furnace's introspect endpoint to
confirm the claim shape matches what you expect:

```bash
curl -X POST http://localhost:8026/oauth2/introspect \
  -d "token=<access_token>"
```

Or decode it directly:

```bash
echo "<token>" | cut -d. -f2 | base64 -d | jq .
```

---

## Multi-provider comparison

Use `"provider": "all"` on the `/opa/evaluate` endpoint to run your
authorization policy against every personality simultaneously and see which
providers would grant or deny access:

```bash
curl -X POST http://localhost:8025/api/v1/opa/evaluate \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": "package authz\ndefault allow := false\nallow if { input.user.claims.email != \"\" }",
    "user_id": "usr_abc123",
    "action": "read",
    "resource": "document",
    "provider": "all"
  }'
```

Returns a `results_by_provider` map showing each provider's decision side by side.
