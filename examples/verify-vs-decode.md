# Verify vs Decode

Use **verify** when you only need to know if the token is valid. Use **decode** when you need the payload. Verify is cheaper (validates then decrypts; you can short-circuit or avoid reading payload). Decode returns the decrypted data and throws on failure.

## When to use which

| Use case                   | Method   | Reason                                    |
| :------------------------- | :------- | :---------------------------------------- |
| Middleware: “is token ok?” | `verify` | Boolean; no try/catch; no payload needed. |
| Health / readiness check   | `verify` | Only need valid/invalid.                  |
| Handler: need userId, role | `decode` | Need payload data.                        |
| Audit / logging (payload)  | `decode` | Need decrypted claims.                    |

## Middleware: verify only

Middleware that protects routes without reading the payload. No try/catch; `verify` returns `false` when invalid.

```ts
import JWT from '@neabyte/secure-token'

// Step: create JWT instance
const jwt = new JWT({
  secret: Deno.env.get('SECRET') ?? '',
  version: '1.0.0',
  expireIn: '15m'
})

async function authMiddleware(req: Request): Promise<Response | null> {
  // Step: extract Bearer token
  const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') ?? ''
  if (!token) {
    return new Response('Missing token', { status: 401 })
  }
  // Step: verify only (no payload); return 401 if invalid
  const isValid = await jwt.verify(token)
  if (!isValid) {
    return new Response('Invalid token', { status: 401 })
  }
  return null
}
```

Return `null` when the request is allowed; return a `Response` when you want to short-circuit (e.g. 401). Downstream handler can decode the same token if it needs the payload.

## Handler: decode when you need payload

Once the middleware has confirmed the token (or you have decided to trust it), decode in the handler that needs claims.

```ts
async function handleProfile(req: Request): Promise<Response> {
  // Step: extract token and decode to get payload
  const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') ?? ''
  try {
    const payload = await jwt.decode(token)
    const data = payload as { userId: string; role: string }
    return new Response(JSON.stringify({ userId: data.userId, role: data.role }), {
      headers: { 'Content-Type': 'application/json' }
    })
  } catch {
    return new Response('Invalid token', { status: 401 })
  }
}
```

If middleware already ran and returned 401 for invalid tokens, you can assume the token is valid here; decode is for reading the payload only.

## Pattern: middleware + handler

```ts
async function handleRequest(req: Request): Promise<Response> {
  // Step: run middleware first; short-circuit on 401
  const authResponse = await authMiddleware(req)
  if (authResponse !== null) {
    return authResponse
  }
  // Step: token valid; handler can decode to read payload
  const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') ?? ''
  return handleProfile(req)
}
```

Middleware uses **verify** (no throw, no payload). Handler uses **decode** to get payload. One verify per request; decode only in handlers that need the data.

> [!TIP]
> Prefer verify in middleware and decode only where you need payload; avoids unnecessary decrypt in routes that do not use claims.
