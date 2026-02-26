# Error Handling

`sign` and `decode` throw on failure; `verify` returns `false` and does not throw. Map `error.message` from `decode` (or `sign`) to the right action: refresh/re-login for expired, upgrade client for version mismatch, 401 for invalid format or tampering.

> [!NOTE]
> Use `verify` when you only need to know if the token is valid (no payload). It never throws; use try/catch only for `sign` and `decode`.

## Error messages and actions

| Message (contains)                                     | Meaning                             | Suggested action                    |
| :----------------------------------------------------- | :---------------------------------- | :---------------------------------- |
| `Token expired`                                        | Token or payload past `exp`         | Refresh token or force re-login     |
| `Version mismatch`                                     | Token version ≠ instance            | Ask client to upgrade; or migration |
| `Invalid token format`                                 | Base64/JSON decode failed           | 401 Unauthorized                    |
| `Invalid token structure`                              | Missing/wrong envelope fields       | 401 Unauthorized                    |
| `Invalid payload format` / `Invalid payload structure` | Decrypt ok but payload invalid      | 401 Unauthorized                    |
| `Token timestamp mismatch`                             | Outer and inner iat/exp don’t match | 401 Unauthorized                    |
| `Data cannot be null or undefined`                     | `sign(null)` or `sign(undefined)`   | 400 Bad Request (caller bug)        |

> [!TIP]
> Decryption failures (wrong secret, wrong issuer, tampered ciphertext) typically surface as a generic error from the cipher; treat as 401.

## Example: try/catch decode and branch by message

```ts
import JWT from '@neabyte/secure-token'

// Step: create JWT instance
const jwt = new JWT({
  secret: Deno.env.get('SECRET') ?? '',
  version: '1.0.0',
  expireIn: '15m'
})

async function handleToken(token: string): Promise<{ status: number; body?: unknown }> {
  try {
    // Step: decode and return payload on success
    const payload = await jwt.decode(token)
    return { status: 200, body: payload }
  } catch (err) {
    // Step: read error message and map to status + body
    const msg = err instanceof Error ? err.message : String(err)
    if (msg.includes('Token expired')) {
      return { status: 401, body: { code: 'TOKEN_EXPIRED', hint: 'Refresh or re-login' } }
    }
    if (msg.includes('Version mismatch')) {
      return { status: 401, body: { code: 'VERSION_MISMATCH', hint: 'Upgrade client' } }
    }
    return { status: 401, body: { code: 'INVALID_TOKEN' } }
  }
}
```

For routes that only need validity (no payload), use `verify` and avoid try/catch:

```ts
// Step: verify returns boolean; no try/catch needed
const isValid = await jwt.verify(token)
if (!isValid) {
  return { status: 401, body: { code: 'INVALID_TOKEN' } }
}
```
