# ExpireIn in Practice

Choosing `expireIn` affects both security and UX. Short-lived tokens limit damage if leaked; long-lived ones reduce re-login frequency. The library enforces a maximum of **1 year** for `expireIn` and expects clocks to be roughly in sync (e.g. NTP) so expiration is reliable.

## Recommended ranges by token type

| Token type            | Typical `expireIn` | Notes                                                             |
| :-------------------- | :----------------- | :---------------------------------------------------------------- |
| Access token          | `15m` – `1h`       | Short; use with refresh token for long sessions.                  |
| Refresh token         | `7d` – `30d`       | Longer; only used to obtain new access tokens.                    |
| API key / machine     | `90d` – `1y`       | Max 1 year; rotate via [migration window](./migration-window.md). |
| One-time / magic link | `5m` – `15m`       | Single use; keep short.                                           |

Example:

```ts
import JWT from '@neabyte/secure-token'

// Step: create access token signer (short TTL, e.g. 15m)
const jwtAccess = new JWT({
  secret: Deno.env.get('SECRET') ?? '',
  version: '1.0.0',
  expireIn: '15m'
})
// Step: create refresh token signer (longer TTL, e.g. 7d)
const jwtRefresh = new JWT({
  secret: Deno.env.get('SECRET') ?? '',
  version: '1.0.0',
  expireIn: '7d'
})
```

## Max 1 year and clock skew

> [!NOTE]
>
> - **Max 1 year:** Values like `2y` or `400d` will throw. For longer validity, use a refresh flow or re-issue before expiry.
> - **Clock skew:** Expiration is checked with `exp <= now` (Unix seconds). If server clocks drift, tokens may be rejected too early or accepted too long. Use NTP (or equivalent) on all nodes that sign or verify tokens.

> [!TIP]
> Ensure time sync (NTP) on signers and verifiers so expiration is consistent across environments.
