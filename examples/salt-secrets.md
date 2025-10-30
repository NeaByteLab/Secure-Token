# Salt Secrets with a Strong Random Generator

Use a strong, unpredictable secret for key derivation. Generate it once per environment and store it securely (e.g., secret manager or encrypted KV). Do not regenerate on every deploy or process start.

## Generate a secret

```ts
// One-time generation (run locally or in a secure init job)
// Produces a 32-byte base64 string suitable as SECRET
function generateSecret(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return btoa(String.fromCharCode(...bytes))
}

console.log(generateSecret())
```

Store the output as an environment/config secret (e.g., `SECRET=...`).

## Use the secret with JWT

```ts
import JWT from '@neabyte/secure-token'

const jwt = new JWT({
  secret: Deno.env.get('SECRET') ?? '',
  version: '1.0.0',
  expireIn: '1h'
})
```

## Optional: add an application-scoped salt

If you have a base secret managed centrally and want to bind tokens to a specific app/service, derive an app-scoped secret. Keep both values static and secret.

```ts
const baseSecret = Deno.env.get('SECRET') ?? ''
const appSalt = Deno.env.get('APP_SALT') ?? '' // another random 32B value

// Simple composition; for stronger derivation, use a KDF (e.g., HKDF)
const appScopedSecret = `${baseSecret}:${appSalt}`

const jwt = new JWT({
  secret: appScopedSecret,
  version: '1.0.0',
  expireIn: '1h'
})
```

> [!NOTE]
> - Prefer at least 32 random bytes for secrets; longer is fine.
> - Keep secrets out of source control; use environment or secret managers.
> - Do not rotate salts or secrets unintentionally; rotation invalidates existing tokens.
