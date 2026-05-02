# Providers

Furnace simulates six identity providers out of the box. Each section below compares all providers side by side — select the tab for the provider you are targeting.

---

## 1. Config Provider

Set `FURNACE_PROVIDER` before starting the container and restart. Not running yet? See [Installation](/doc/installation) for the full setup.

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
<p>Default is active when <code>FURNACE_PROVIDER</code> is unset. No environment variable needed.</p>
<pre><code>docker compose up</code></pre>
<p>Or as a one-liner:</p>
<pre><code>docker run -p 8025:8025 -p 8026:8026 callezenwaka/furnace:latest</code></pre>
</div>

<div class="tab-panel" data-panel="azure-ad">
<p>Add to your <code>docker-compose.yml</code> environment section and restart:</p>
<pre><code>FURNACE_PROVIDER: azure-ad</code></pre>
<p>Or as a one-liner:</p>
<pre><code>FURNACE_PROVIDER=azure-ad docker compose up</code></pre>
</div>

<div class="tab-panel" data-panel="okta">
<p>Add to your <code>docker-compose.yml</code> environment section and restart:</p>
<pre><code>FURNACE_PROVIDER: okta</code></pre>
<p>Or as a one-liner:</p>
<pre><code>FURNACE_PROVIDER=okta docker compose up</code></pre>
</div>

<div class="tab-panel" data-panel="google-workspace">
<p>Add to your <code>docker-compose.yml</code> environment section and restart:</p>
<pre><code>FURNACE_PROVIDER: google-workspace</code></pre>
<p>Or as a one-liner:</p>
<pre><code>FURNACE_PROVIDER=google-workspace docker compose up</code></pre>
</div>

<div class="tab-panel" data-panel="github">
<p>Add to your <code>docker-compose.yml</code> environment section and restart:</p>
<pre><code>FURNACE_PROVIDER: github</code></pre>
<p>Or as a one-liner:</p>
<pre><code>FURNACE_PROVIDER=github docker compose up</code></pre>
</div>

<div class="tab-panel" data-panel="onelogin">
<p>Add to your <code>docker-compose.yml</code> environment section and restart:</p>
<pre><code>FURNACE_PROVIDER: onelogin</code></pre>
<p>Or as a one-liner:</p>
<pre><code>FURNACE_PROVIDER=onelogin docker compose up</code></pre>
</div>
</div>

---

## 2. What this provider is

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
<p>The baseline. Standard OIDC claim names with no remapping. Use this when your app follows the OIDC spec directly and is not targeting a specific provider. It is also useful as a reference point when comparing how other providers reshape the same data.</p>
</div>

<div class="tab-panel" data-panel="azure-ad">
<p>Microsoft Entra ID (formerly Azure AD) is the identity platform used by enterprises running Microsoft 365, Teams, and Azure. It is the most common SSO provider in large organizations. Apps built for Entra ID read <code>preferred_username</code> as the user's identity — not <code>email</code> — and often gate access on <code>tid</code> matching an expected tenant ID.</p>
</div>

<div class="tab-panel" data-panel="okta">
<p>Okta is one of the most widely used workforce identity providers. It uses <code>login</code> as the primary identifier instead of <code>email</code>, and returns group membership as an array. Teams evaluating Okta before committing to a contract can test their full integration — claims, groups, MFA flows — against Furnace without an Okta account.</p>
</div>

<div class="tab-panel" data-panel="google-workspace">
<p>Google Workspace (formerly G Suite) is Google's enterprise identity platform used by organizations running Gmail, Docs, and Drive. It adds an <code>hd</code> (hosted domain) claim that many apps use to restrict access to a specific company domain — for example, only allowing users from <code>yourcompany.com</code> to log in.</p>
</div>

<div class="tab-panel" data-panel="github">
<p>GitHub OAuth is commonly used by developer tools, open-source projects, and internal tooling where GitHub identity is the natural login method. The primary identifier is <code>login</code> — the GitHub username — not <code>email</code>. Email may not even be present if the user has kept it private on GitHub.</p>
</div>

<div class="tab-panel" data-panel="onelogin">
<p>OneLogin is an enterprise SSO provider that supports custom user attributes via a <code>params</code> claim. Organizations use it to pass application-specific data — department, cost centre, role codes — alongside the user's identity. Apps that depend on these custom attributes must handle a missing or empty <code>params</code> object gracefully.</p>
</div>
</div>

---

## 3. Activate

Set the environment variable and restart. The token issued will contain the claim shape for that provider.

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
<p>Default is active when <code>FURNACE_PROVIDER</code> is unset.</p>
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
</div>

<div class="tab-panel" data-panel="azure-ad">
<pre><code>FURNACE_PROVIDER=azure-ad</code></pre>
<table>
  <thead><tr><th>Claim</th><th>Example value</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td><code>sub</code></td><td><code>usr_abc123</code></td><td></td></tr>
    <tr><td><code>preferred_username</code></td><td><code>alice@example.com</code></td><td>Remapped from <code>email</code></td></tr>
    <tr><td><code>name</code></td><td><code>Alice</code></td><td></td></tr>
    <tr><td><code>groups</code></td><td><code>["engineering"]</code></td><td></td></tr>
    <tr><td><code>tid</code></td><td><code>common</code></td><td>Static tenant ID</td></tr>
    <tr><td><code>ver</code></td><td><code>2.0</code></td><td>Token version</td></tr>
    <tr><td><code>oid</code></td><td><code>00000000-…</code></td><td>Object ID — set via custom claims on user</td></tr>
  </tbody>
</table>
</div>

<div class="tab-panel" data-panel="okta">
<pre><code>FURNACE_PROVIDER=okta</code></pre>
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
</div>

<div class="tab-panel" data-panel="google-workspace">
<pre><code>FURNACE_PROVIDER=google-workspace</code></pre>
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
</div>

<div class="tab-panel" data-panel="github">
<pre><code>FURNACE_PROVIDER=github</code></pre>
<table>
  <thead><tr><th>Claim</th><th>Example value</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td><code>sub</code></td><td><code>usr_abc123</code></td><td></td></tr>
    <tr><td><code>email</code></td><td><code>alice@example.com</code></td><td></td></tr>
    <tr><td><code>name</code></td><td><code>Alice</code></td><td></td></tr>
    <tr><td><code>login</code></td><td><code>alice-gh</code></td><td>GitHub username — set via custom claim</td></tr>
    <tr><td><code>groups</code></td><td><code>["engineering"]</code></td><td></td></tr>
  </tbody>
</table>
<p class="tab-note">The <code>login</code> claim defaults to a static placeholder. Set it to a real GitHub username by adding <code>"claims": {"login": "alice-gh"}</code> when seeding the user.</p>
</div>

<div class="tab-panel" data-panel="onelogin">
<pre><code>FURNACE_PROVIDER=onelogin</code></pre>
<table>
  <thead><tr><th>Claim</th><th>Example value</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td><code>sub</code></td><td><code>usr_abc123</code></td><td></td></tr>
    <tr><td><code>email</code></td><td><code>alice@example.com</code></td><td></td></tr>
    <tr><td><code>name</code></td><td><code>Alice</code></td><td></td></tr>
    <tr><td><code>groups</code></td><td><code>["engineering"]</code></td><td></td></tr>
    <tr><td><code>params</code></td><td><code>{"department":"eng"}</code></td><td>Custom attributes — set via user claims</td></tr>
  </tbody>
</table>
<p class="tab-note">Populate <code>params</code> with your application's OneLogin custom attributes by adding <code>"claims": {"params": {"department": "eng"}}</code> when seeding the user.</p>
</div>
</div>

---

## 4. Wire your app

All providers use the same Furnace OIDC endpoints. Point your OIDC client at the protocol server and use any non-empty string for client ID and secret — Furnace does not validate them.

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
<pre><code>OIDC_ISSUER=http://localhost:8026
OIDC_CLIENT_ID=myapp
OIDC_CLIENT_SECRET=dev-secret</code></pre>
<p>Read <code>email</code> for identity and <code>groups</code> for role-based access control. No provider-specific claim names to remap. See the <a href="/doc/integration">Integration Guide</a> for framework-specific wiring (Next.js, Python, etc.).</p>
</div>

<div class="tab-panel" data-panel="azure-ad">
<pre><code>OIDC_ISSUER=http://localhost:8026
OIDC_CLIENT_ID=myapp
OIDC_CLIENT_SECRET=dev-secret</code></pre>
<p>Update your app to read <code>preferred_username</code> instead of <code>email</code> for the user's identity. If your app validates <code>tid</code>, set the expected value to <code>common</code> in your dev config. See the <a href="/doc/integration">Integration Guide</a> for framework-specific wiring.</p>
</div>

<div class="tab-panel" data-panel="okta">
<pre><code>OIDC_ISSUER=http://localhost:8026
OIDC_CLIENT_ID=myapp
OIDC_CLIENT_SECRET=dev-secret</code></pre>
<p>Okta's real discovery URL follows <code>https://your-domain.okta.com/.well-known/openid-configuration</code>. For local testing, replace it with Furnace's. Update your app to read <code>login</code> instead of <code>email</code> for the user's identity. See the <a href="/doc/integration">Integration Guide</a> for framework-specific wiring.</p>
</div>

<div class="tab-panel" data-panel="google-workspace">
<pre><code>OIDC_ISSUER=http://localhost:8026
OIDC_CLIENT_ID=myapp
OIDC_CLIENT_SECRET=dev-secret</code></pre>
<p>If your app restricts access by <code>hd</code> (hosted domain), set the expected domain to <code>example.com</code> in your dev config. To test a domain restriction failure, configure your app to check for a different domain. See the <a href="/doc/integration">Integration Guide</a> for framework-specific wiring.</p>
</div>

<div class="tab-panel" data-panel="github">
<pre><code>OIDC_ISSUER=http://localhost:8026
OIDC_CLIENT_ID=myapp
OIDC_CLIENT_SECRET=dev-secret</code></pre>
<p>GitHub's real OAuth uses a custom API for user info rather than standard OIDC. Furnace provides a standards-compliant OIDC layer that emits GitHub-shaped claims — useful for testing claim-reading logic even if the real GitHub integration uses a different flow. Update your app to read <code>login</code> as the primary identifier. See the <a href="/doc/integration">Integration Guide</a> for framework-specific wiring.</p>
</div>

<div class="tab-panel" data-panel="onelogin">
<pre><code>OIDC_ISSUER=http://localhost:8026
OIDC_CLIENT_ID=myapp
OIDC_CLIENT_SECRET=dev-secret</code></pre>
<p>No OneLogin-specific wiring is required — the OIDC config is the same as any other provider. Read <code>email</code> for identity and <code>params</code> for custom application attributes. See the <a href="/doc/integration">Integration Guide</a> for framework-specific wiring.</p>
</div>
</div>

---

## 5. Seed a user

Create a test user via the Admin API. You will need your API key from **Admin UI → Config → Admin API Key**.

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
<pre><code>curl -X POST http://localhost:8025/api/v1/users \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "display_name": "Alice",
    "active": true,
    "groups": ["engineering"]
  }'</code></pre>
</div>

<div class="tab-panel" data-panel="azure-ad">
<p>Use a UPN-style email. Add an <code>oid</code> custom claim if your app reads object IDs for user lookup.</p>
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
</div>

<div class="tab-panel" data-panel="okta">
<p>Include <code>Everyone</code> in groups — real Okta always adds it.</p>
<pre><code>curl -X POST http://localhost:8025/api/v1/users \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "display_name": "Alice",
    "active": true,
    "groups": ["Everyone", "engineering"]
  }'</code></pre>
</div>

<div class="tab-panel" data-panel="google-workspace">
<pre><code>curl -X POST http://localhost:8025/api/v1/users \
  -H "X-Furnace-Api-Key: $FURNACE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "display_name": "Alice",
    "active": true,
    "groups": ["engineering"]
  }'</code></pre>
</div>

<div class="tab-panel" data-panel="github">
<p>Always set a custom <code>login</code> claim so the GitHub username is distinct per user.</p>
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
</div>

<div class="tab-panel" data-panel="onelogin">
<p>Add application-specific custom attributes in <code>params</code>.</p>
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
</div>
</div>

---

## 6. Run the login flow

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
<p>Open <strong>Admin UI → Login Simulator</strong>, select Alice, and click <strong>Continue</strong>. Furnace completes the OIDC flow and issues a token. No browser redirect to an external service — everything stays local.</p>
</div>

<div class="tab-panel" data-panel="azure-ad">
<p>Open <strong>Admin UI → Login Simulator</strong>, select Alice, and click <strong>Continue</strong>. The token issued will contain <code>preferred_username</code> and <code>tid</code> exactly as a real Entra ID token would.</p>
</div>

<div class="tab-panel" data-panel="okta">
<p>Open <strong>Admin UI → Login Simulator</strong>, select Alice, and click <strong>Continue</strong>. The token issued will contain <code>login</code> and <code>groups</code> as a real Okta token would. Use the bell icon (top-right in the Admin UI) to approve any MFA challenges if the user has MFA configured.</p>
</div>

<div class="tab-panel" data-panel="google-workspace">
<p>Open <strong>Admin UI → Login Simulator</strong>, select Alice, and click <strong>Continue</strong>. The token will contain <code>hd</code>, <code>email_verified</code>, and <code>locale</code> as a real Google Workspace token would.</p>
</div>

<div class="tab-panel" data-panel="github">
<p>Open <strong>Admin UI → Login Simulator</strong>, select Alice, and click <strong>Continue</strong>. The token will contain <code>login</code> set to <code>alice-gh</code> as a real GitHub token would surface the username.</p>
</div>

<div class="tab-panel" data-panel="onelogin">
<p>Open <strong>Admin UI → Login Simulator</strong>, select Alice, and click <strong>Continue</strong>. The token will contain the <code>params</code> object with the custom attributes you seeded. Run a second test with a user seeded without custom claims to confirm your app handles an empty <code>params: {}</code> gracefully.</p>
</div>
</div>

---

## 7. Verify claims

After the login flow, inspect the token against Furnace's introspect endpoint or use the Token Diff tool to confirm the claim shape matches what your app expects.

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
<p>Open <strong>Admin UI → Token Diff</strong>. Select the Default provider and confirm the token contains <code>email</code>, <code>name</code>, and <code>groups</code> with the values you seeded.</p>
<p>Or decode the token directly:</p>
<pre><code>curl -X POST http://localhost:8026/oauth2/introspect \
  -d "token=&lt;access_token&gt;"</code></pre>
</div>

<div class="tab-panel" data-panel="azure-ad">
<p>Open <strong>Admin UI → Token Diff</strong>. Select the Azure AD provider and confirm <code>preferred_username</code> is present (not <code>email</code>), <code>tid</code> is <code>common</code>, and <code>ver</code> is <code>2.0</code>. If your app reads <code>email</code> instead of <code>preferred_username</code>, you will see a blank identity — fix that before going to production.</p>
<pre><code>curl -X POST http://localhost:8026/oauth2/introspect \
  -d "token=&lt;access_token&gt;"</code></pre>
</div>

<div class="tab-panel" data-panel="okta">
<p>Open <strong>Admin UI → Token Diff</strong>. Select the Okta provider and confirm <code>login</code> is present (not <code>email</code>), <code>groups</code> is an array, <code>ver</code> is <code>1</code>, and <code>jti</code> is present. If your app reads <code>email</code> for identity, it will get <code>undefined</code> — switch it to <code>login</code>.</p>
<pre><code>curl -X POST http://localhost:8026/oauth2/introspect \
  -d "token=&lt;access_token&gt;"</code></pre>
</div>

<div class="tab-panel" data-panel="google-workspace">
<p>Open <strong>Admin UI → Token Diff</strong>. Select the Google Workspace provider and confirm <code>hd</code> is <code>example.com</code>, <code>email_verified</code> is <code>true</code>, and <code>locale</code> is present. If your app enforces a domain allowlist, test both the passing case (<code>example.com</code>) and a failing case by temporarily changing the expected domain in your app config.</p>
<pre><code>curl -X POST http://localhost:8026/oauth2/introspect \
  -d "token=&lt;access_token&gt;"</code></pre>
</div>

<div class="tab-panel" data-panel="github">
<p>Open <strong>Admin UI → Token Diff</strong>. Select the GitHub provider and confirm <code>login</code> is present and matches the value you set in the custom claim. If <code>login</code> shows <code>github-user</code>, the custom claim was not set when seeding.</p>
<pre><code>curl -X POST http://localhost:8026/oauth2/introspect \
  -d "token=&lt;access_token&gt;"</code></pre>
</div>

<div class="tab-panel" data-panel="onelogin">
<p>Open <strong>Admin UI → Token Diff</strong>. Select the OneLogin provider and confirm <code>params</code> is present and contains the expected keys. Run the flow again with a user that has no custom claims and verify <code>params</code> is <code>{}</code> — your app must not crash or block access when custom attributes are absent.</p>
<pre><code>curl -X POST http://localhost:8026/oauth2/introspect \
  -d "token=&lt;access_token&gt;"</code></pre>
</div>
</div>

---

## 8. Common pitfalls

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
<p>N/A — this is the baseline. If something breaks here, it is a Furnace configuration issue, not a provider-specific one.</p>
</div>

<div class="tab-panel" data-panel="azure-ad">
<ul>
  <li><strong><code>email</code> claim is absent.</strong> Entra ID does not include <code>email</code> by default. Apps that read <code>email</code> for identity will get <code>undefined</code>. Switch to <code>preferred_username</code>.</li>
  <li><strong>Tenant ID check fails.</strong> If your app validates <code>tid</code> against a specific tenant GUID, update the expected value to <code>common</code> in your dev config, or seed a user with a matching <code>tid</code> custom claim.</li>
  <li><strong>Missing <code>oid</code>.</strong> Some libraries use <code>oid</code> as the stable user identifier. Set it explicitly in the user's <code>claims</code> when seeding.</li>
</ul>
</div>

<div class="tab-panel" data-panel="okta">
<ul>
  <li><strong>App reads <code>email</code> instead of <code>login</code>.</strong> This is the most common Okta integration bug. Okta does not include <code>email</code> at the top level — identity comes from <code>login</code>.</li>
  <li><strong>Groups treated as a string.</strong> Some frameworks join array claims into a space-separated string. Verify your app handles <code>groups</code> as a JSON array.</li>
  <li><strong>Missing <code>Everyone</code> group.</strong> Real Okta always includes an <code>Everyone</code> group. Include it when seeding users to match production behaviour.</li>
</ul>
</div>

<div class="tab-panel" data-panel="google-workspace">
<ul>
  <li><strong>Domain restriction blocks all users.</strong> If your app checks <code>hd</code> against a hardcoded domain and that domain is not <code>example.com</code>, all logins will be rejected. Update your dev config to expect <code>example.com</code>.</li>
  <li><strong><code>email_verified</code> check.</strong> Some apps reject tokens where <code>email_verified</code> is false or absent. Furnace sets it to <code>true</code> — verify your app does not invert this logic accidentally.</li>
  <li><strong>Personal Google accounts vs Workspace.</strong> Real personal Google accounts do not include <code>hd</code>. If your app allows both, test the no-<code>hd</code> case using the Default provider personality.</li>
</ul>
</div>

<div class="tab-panel" data-panel="github">
<ul>
  <li><strong>Static <code>login</code> placeholder.</strong> If you seed a user without <code>"claims": {"login": "..."}</code>, the <code>login</code> claim will be <code>github-user</code> for every user. Always set a custom <code>login</code> when seeding to simulate distinct GitHub usernames.</li>
  <li><strong>App reads <code>email</code> for GitHub identity.</strong> GitHub users can hide their email. Apps should use <code>login</code> as the primary identifier, with <code>email</code> as optional supplementary data.</li>
</ul>
</div>

<div class="tab-panel" data-panel="onelogin">
<ul>
  <li><strong>App assumes <code>params</code> always has specific keys.</strong> In production, OneLogin admins control which custom attributes are configured. Your app must handle missing keys in <code>params</code> without throwing an error.</li>
  <li><strong>Empty <code>params</code> treated as missing.</strong> Furnace always includes <code>params: {}</code> even when no custom attributes are set. Some apps check for the presence of <code>params</code> rather than the presence of specific keys inside it — make sure the distinction is handled correctly.</li>
</ul>
</div>
</div>

---

## 9. What to check in your app

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
<p>Read <code>email</code> for identity and <code>groups</code> for role-based access control. No provider-specific claim names — this is the baseline.</p>
</div>

<div class="tab-panel" data-panel="azure-ad">
<p>Read <code>preferred_username</code> (not <code>email</code>) for the user's UPN. Gate access on <code>tid</code> matching your expected tenant ID. Verify your app handles <code>oid</code> correctly if it uses object IDs for user lookup.</p>
</div>

<div class="tab-panel" data-panel="okta">
<p>Read <code>login</code> (not <code>email</code>) as the primary identifier. Verify <code>groups</code> is handled as an array. Confirm MFA flows work end-to-end using the Login Simulator and the bell icon (Notification Hub) in the Admin UI.</p>
</div>

<div class="tab-panel" data-panel="google-workspace">
<p>Verify your domain allowlist logic against <code>hd</code>. Confirm <code>email_verified</code> is handled correctly. Test both passing and failing domain restriction cases before going to production.</p>
</div>

<div class="tab-panel" data-panel="github">
<p>Read <code>login</code> as the primary identifier. Treat <code>email</code> as optional — do not require it for authentication. Verify your app handles distinct <code>login</code> values correctly across multiple test users.</p>
</div>

<div class="tab-panel" data-panel="onelogin">
<p>Verify <code>params</code> is present and contains the expected keys. Test both the happy path (correct params populated) and the empty-params path to confirm your app handles absent custom attributes gracefully.</p>
</div>
</div>
