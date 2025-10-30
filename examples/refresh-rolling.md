# Refresh Token Pattern (Rolling Expiration)

In many authentication systems, you'll want to keep user sessions alive for days or weeks, but tokens only valid for a shorter time, to reduce risk if leaked. This pattern issues a short-lived access token and a longer-lived refresh token.

## Token lifetimes
- **Access Token**: short-lived (e.g., 15 minutes); used for most API requests.
- **Refresh Token**: long-lived (e.g., 7 days); only exchanged for a new access token.

## Example: Issue and refresh

```ts
import JWT from '@neabyte/secure-token'

const jwtAccess = new JWT({
  secret: Deno.env.get('SECRET') ?? '',
  version: '1.0.0',
  expireIn: '15m',
})
const jwtRefresh = new JWT({
  secret: Deno.env.get('SECRET') ?? '',
  version: '1.0.0',
  expireIn: '7d',
})

// On login (or token refresh):
const payload = { userId: '123', role: 'user' }
const accessToken = await jwtAccess.sign(payload)
const refreshToken = await jwtRefresh.sign(payload)

// ---
// On each API call:
try {
  await jwtAccess.verify(accessToken)
  // valid, proceed
} catch {
  // try refresh
  try {
    await jwtRefresh.verify(refreshToken)
    // valid refresh token: issue new access + refresh tokens!
  } catch {
    // both invalid: force full re-login
  }
}
```

> [!IMPORTANT]
> - Always store access token in memory (not localStorage); refresh token in httpOnly cookie (if in browser).
> - Rotate/expire refresh tokens on password change or suspicious activity.
> - Avoid issuing a new refresh token unless the old one is still valid (rotate on use).
> - For sensitive actions, consider requiring a re-login instead of accepting a refresh.
