# Multi-Issuer Setup (Microservices)

It's common in microservice or hybrid systems to validate tokens from different trusted issuers (e.g., one for users, one for backend processes, one for partner APIs or integrations).

## Why multiple issuers?
- User-facing tokens may have one issuer/config, contain user-related claims.
- Internal services may use another, with separate secret, version, issuer, and claims.

## Example: Verify by issuer/config

```ts
import JWT from '@neabyte/secure-token'

const jwtUser = new JWT({
  secret: Deno.env.get('USER_SECRET') ?? '',
  issuer: 'frontend-app',
  version: '1.0.0',
  expireIn: '15m',
})
const jwtWorker = new JWT({
  secret: Deno.env.get('WORKER_SECRET') ?? '',
  issuer: 'internal-job',
  version: '1.0.0',
  expireIn: '1h',
})

// On inbound request:
async function handleRequest(token) {
  // Try user first
  try {
    const user = await jwtUser.decode(token)
    if (user.role) {
      return `user-api:${user.userId}`
    }
  } catch {
    // continue to next try
  }
  // Try internal job
  try {
    const job = await jwtWorker.decode(token)
    if (job.task) {
      return `internal-job:${job.task}`
    }
  } catch {
    // continue to next try
  }
  // ...
  return 'unauthorized'
}
```

## Distinguishing tokens
- Use `issuer` claim: ensures you only trust tokens from expected source.
- Use custom claims: e.g., `role`, `userId` for users; `task`, `batch` for jobs.
- Optionally, check JWT `aud` (audience) for further scoping.

> [!IMPORTANT]
> - Never share the same secret/issuer for user and machine tokens.
> - Regularly rotate/service each set separately.
