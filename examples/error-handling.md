# Error Handling

`sign` and `decode` throw on failure; `verify` returns `false` and does not throw. The library normalizes all **decode** failures to a single message so callers cannot distinguish causes (no information leakage).

> [!NOTE]
> Use `verify` when you only need to know if the token is valid (no payload). It never throws; use try/catch only for `sign` and `decode`.

## Decode: single message

All failures from `decode` (invalid format, expired, wrong version, wrong secret, tampered, etc.) throw with the same message: **`'Invalid token'`**. You cannot branch by cause; treat any decode failure as 401 and direct the user to re-login or refresh.

## Messages you can branch on

| Message (exact or contains)             | When                                   | Suggested action              |
| :-------------------------------------- | :------------------------------------- | :---------------------------- |
| `Invalid token`                         | `decode` failed (any cause)            | 401; re-login or refresh      |
| `Data cannot be null or undefined`      | `sign(null)` or `sign(undefined)`      | 400 Bad Request (caller bug)  |
| Constructor / options / expireIn errors | Invalid options, empty secret, bad TTL | 400 or 500; fix configuration |

Constructor and `sign` may throw other messages (e.g. `Secret must be a non-empty string`, `Invalid time format`). Only **decode** is normalized to `'Invalid token'`.

## Example: try/catch decode

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
    // Step: all decode failures are 'Invalid token'; return 401
    const msg = err instanceof Error ? err.message : String(err)
    if (msg === 'Invalid token') {
      return { status: 401, body: { code: 'INVALID_TOKEN', hint: 'Re-login or refresh' } }
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
