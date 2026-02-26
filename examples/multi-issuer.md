# Multi-Issuer Setup (Microservices)

It's common in microservice or hybrid systems to validate tokens from different trusted issuers (e.g., one for users, one for backend processes, one for partner APIs or integrations).

## Why multiple issuers?

- User-facing tokens may have one issuer/config, contain user-related claims.
- Internal services may use another, with separate secret, version, issuer, and claims.

## Example: Verify by issuer/config

```ts
import JWT from '@neabyte/secure-token'

// Step: create JWT instance for user tokens (issuer frontend-app)
const jwtUser = new JWT({
  secret: Deno.env.get('USER_SECRET') ?? '',
  issuer: 'frontend-app',
  version: '1.0.0',
  expireIn: '15m'
})
// Step: create JWT instance for worker/internal tokens (issuer internal-job)
const jwtWorker = new JWT({
  secret: Deno.env.get('WORKER_SECRET') ?? '',
  issuer: 'internal-job',
  version: '1.0.0',
  expireIn: '1h'
})

// On inbound request:
async function handleRequest(token) {
  // Step: try decoding as user token first
  try {
    const user = await jwtUser.decode(token)
    if (user.role) {
      return `user-api:${user.userId}`
    }
  } catch {
    // not a user token; try next
  }
  // Step: try decoding as worker token
  try {
    const job = await jwtWorker.decode(token)
    if (job.task) {
      return `internal-job:${job.task}`
    }
  } catch {
    // not a worker token
  }
  // Step: no issuer matched
  return 'unauthorized'
}
```

## Distinguishing tokens

- Use `issuer` (bound in AAD): ensures you only trust tokens from the expected source.
- Use custom claims in your payload: e.g., `role`, `userId` for users; `task`, `batch` for jobs. You can add an `aud` (audience) field in the payload if you need audience scoping.

> [!IMPORTANT]
>
> - Never share the same secret/issuer for user and machine tokens.
> - Regularly rotate/service each set separately.
