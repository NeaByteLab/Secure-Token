# Serverless and Env-Based Secrets

On Deno Deploy, Fly, Cloud Run, or similar, load the secret from the environment or a secret manager. Create **one** JWT instance per process (or cold start) and reuse it for all requests instead of constructing a new instance on every request.

> [!NOTE]
> One JWT instance per process avoids repeated env reads and re-validation of options; the instance is stateless and safe to reuse across concurrent requests.

## Why one instance per process

- Avoids repeated reads from env/secret manager per request.
- Constructor validates options and parses `expireIn`; no need to repeat on every call.
- The instance is stateless; `sign`, `verify`, and `decode` are safe to call concurrently.

## Example: module-level instance

```ts
import JWT from '@neabyte/secure-token'

// Step: read secret from env and fail fast if missing
const secret = Deno.env.get('SECRET')
if (!secret) {
  throw new Error('SECRET is required')
}

// Step: create one JWT instance at module load (reused for all requests)
const jwt = new JWT({
  secret,
  version: Deno.env.get('TOKEN_VERSION') ?? '1.0.0',
  expireIn: Deno.env.get('TOKEN_EXPIRE_IN') ?? '1h'
})

export async function handler(req: Request): Promise<Response> {
  // Step: extract Bearer token from Authorization header
  const auth = req.headers.get('Authorization')
  const token = auth?.replace(/^Bearer\s+/i, '')
  if (!token) {
    return new Response(JSON.stringify({ error: 'Missing token' }), { status: 401 })
  }
  // Step: verify without decoding; reject if invalid
  const isValid = await jwt.verify(token)
  if (!isValid) {
    return new Response(JSON.stringify({ error: 'Invalid token' }), { status: 401 })
  }
  // Step: decode and return payload
  const payload = await jwt.decode(token)
  return Response.json({ data: payload })
}
```

## Secret managers

- **Deno Deploy:** Use [environment variables](https://docs.deno.com/deploy/classic/environment-variables/); they are available as `Deno.env.get('SECRET')`.
- **Fly:** Set secrets with `fly secrets set SECRET=...`; same env access.
- **Cloud Run:** Use Secret Manager and inject as env or volume; read in code and pass to `JWT` when building the instance.

> [!IMPORTANT]
> Ensure the secret is set before the first request (or fail fast at startup if missing). The library rejects an empty `secret` and will throw in the constructor.
