# Salt Secrets With a Strong Random Generator

Use a strong, unpredictable secret for key derivation. Generate it once per environment and store it securely (e.g., secret manager or encrypted KV). Do not regenerate on every deploy or process start.

> [!TIP]
> Generate the secret once (e.g. locally or in a secure init job), then store it in env or a secret manager. Never commit it to source control.

## Generate a secret

```ts
// One-time generation (run locally or in a secure init job)
// Produces a 32-byte base64 string suitable as SECRET
function generateSecret(): string {
  // Step: allocate 32 bytes
  const bytes = new Uint8Array(32)
  // Step: fill with CSPRNG
  crypto.getRandomValues(bytes)
  // Step: encode as base64 string
  return btoa(String.fromCharCode(...bytes))
}

console.log(generateSecret())
```

Store the output as an environment/config secret (e.g., `SECRET=...`).

## Use the secret with JWT

```ts
import JWT from '@neabyte/secure-token'

// Step: read secret from env (validate before use if needed)
const jwt = new JWT({
  secret: Deno.env.get('SECRET') ?? '',
  version: '1.0.0',
  expireIn: '1h'
})
```

> [!NOTE]
> If `SECRET` is unset, the constructor receives an empty string and will throw (`Secret must be a non-empty string`). Validate or provide a default before creating the JWT instance if needed.

## Optional: add an application-scoped salt

If you have a base secret managed centrally and want to bind tokens to a specific app/service, derive an app-scoped secret. Keep both values static and secret.

```ts
// Step: read base secret and app-specific salt from env
const baseSecret = Deno.env.get('SECRET') ?? ''
const appSalt = Deno.env.get('APP_SALT') ?? '' // another random 32B value
// Step: derive app-scoped secret (for stronger derivation use a KDF e.g. HKDF)
const appScopedSecret = `${baseSecret}:${appSalt}`

// Step: create JWT instance with derived secret
const jwt = new JWT({
  secret: appScopedSecret,
  version: '1.0.0',
  expireIn: '1h'
})
```

> [!NOTE]
>
> - Prefer at least 32 random bytes for secrets; longer is fine.
> - Keep secrets out of source control; use environment or secret managers.
> - Do not rotate salts or secrets unintentionally; rotation invalidates existing tokens.
