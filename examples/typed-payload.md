# Typed Payload

`decode` returns `unknown`. Define an interface for your payload and narrow after decode (cast or type guard) so handlers get typed data.

## Define payload shape

```ts
interface AuthPayload {
  userId: string
  role: string
}
```

Use the same shape when signing and when asserting after decode.

## Option 1: Type assertion after decode

```ts
import JWT from '@neabyte/secure-token'

interface AuthPayload {
  userId: string
  role: string
}

// Step: create JWT instance
const jwt = new JWT({
  secret: Deno.env.get('SECRET') ?? '',
  version: '1.0.0',
  expireIn: '15m'
})

async function getAuthPayload(token: string): Promise<AuthPayload | null> {
  try {
    // Step: decode and cast to payload type
    const data = await jwt.decode(token)
    return data as AuthPayload
  } catch {
    return null
  }
}

// Step: extract Bearer token and get payload
const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') ?? ''
const payload = await getAuthPayload(token)
if (!payload) {
  return new Response('Unauthorized', { status: 401 })
}
console.log(payload.userId, payload.role)
```

Assertion is simple but does not validate at runtime; only use when the signer is trusted and you control the payload shape.

## Option 2: Type guard after decode

Validate shape at runtime so invalid or tampered payloads do not leak into your types.

```ts
// Step: type guard to validate payload shape at runtime
function isAuthPayload(data: unknown): data is AuthPayload {
  return (
    typeof data === 'object' &&
    data !== null &&
    'userId' in data &&
    'role' in data &&
    typeof (data as AuthPayload).userId === 'string' &&
    typeof (data as AuthPayload).role === 'string'
  )
}

async function getAuthPayload(token: string): Promise<AuthPayload | null> {
  try {
    // Step: decode then validate shape with guard
    const data = await jwt.decode(token)
    if (!isAuthPayload(data)) {
      return null
    }
    return data
  } catch {
    return null
  }
}
```

Use the guard whenever the token might come from untrusted input or you want to tolerate legacy/malformed payloads without crashing.

## Usage in handler

```ts
async function handleRequest(req: Request): Promise<Response> {
  // Step: extract token and get typed payload
  const token = req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '') ?? ''
  const payload = await getAuthPayload(token)
  if (!payload) {
    return new Response(JSON.stringify({ error: 'INVALID_TOKEN' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    })
  }
  // Step: return response with payload data
  return new Response(JSON.stringify({ userId: payload.userId, role: payload.role }), {
    headers: { 'Content-Type': 'application/json' }
  })
}
```

> [!TIP]
> Keep the payload interface in a shared types file so sign and decode sites stay in sync.
