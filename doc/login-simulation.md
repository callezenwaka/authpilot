# Login Simulation

The login UI at `/login` lets you pick any seeded user and walk through a flow
without a real password. No credentials are checked — Furnace is a local dev tool.

## Flow Scenarios

Set `next_flow` on a user to inject a scenario:

| Scenario | Behaviour |
|----------|-----------|
| `normal` | Straight-through login |
| `mfa_fail` | First MFA attempt fails |
| `account_locked` | Flow errors immediately |
| `slow_mfa` | Push approval delayed 10 seconds |
| `expired_token` | Tokens issued with negative TTL |

## MFA Methods

Set `mfa_method` on a user to trigger a specific MFA flow:

| Method | What happens |
|--------|-------------|
| _(none)_ | Login completes immediately after user selection |
| `totp` | 6-digit time-based code; visible in Notify Hub → TOTP tab |
| `push` | Approve/deny push notification; visible in Notify Hub → Push tab |
| `sms` | 6-digit code; visible in Notify Hub → SMS tab |
| `magic_link` | One-click sign-in link; visible in Notify Hub → Magic Links tab |
| `webauthn` | Passkey simulation; challenge and authenticate button in Notify Hub → Passkeys tab |

## Notify Hub

The Notify Hub intercepts all outbound MFA messages during local testing —
no real delivery provider needed. Access it via the bell icon (top-right) or
the **Notify Hub** button in the admin sidebar.

The hub polls `/api/v1/notifications/all` every 3 seconds while open.
