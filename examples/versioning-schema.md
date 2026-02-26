# Versioning Schema

The `version` option is bound into the token (in AAD and in the payload). Use it to enforce breaking changes: when you change payload shape or semantics, bump `version` so old tokens are rejected until clients migrate. Combine with a [migration window](./migration-window.md) to reissue old tokens under the new version without breaking active sessions.

## When to bump version

- You change the **shape** of the payload (e.g. rename `userId` to `sub`, or add required fields).
- You change the **meaning** of a claim (e.g. `role` values or semantics).
- You rotate **secret** or **algorithm** and want a clear cutoff; version helps distinguish old vs new tokens during the window.

> [!NOTE]
> Tokens signed with one `version` only decode with an instance that has the same `version`. After a bump, old tokens fail until you either keep an old instance for the migration period or reissue them (see below).

## Pattern: bump version and run a migration window

1. Deploy new code that uses a new `version` (and optionally new `secret`).
2. For a limited time, accept **old** tokens (old version/secret), decode them, and **reissue** with the new config (new version/secret). Return the new token to the client.
3. Once traffic has moved to the new tokens, remove support for the old config.

Example: see [Token Reissue During Rotation Window](./migration-window.md) for full code. The idea is:

```ts
// Step: new instance with bumped version (target config)
const jwtNew = new JWT({
  secret: Deno.env.get('SECRET_NEW') ?? '',
  version: '1.1.0',
  expireIn: '1h'
})

// Step: tokens signed with version 1.0.0 fail verify/decode with jwtNew.
// During migration window: decode with jwtOld, then reissue with jwtNew.sign(payload).
```

## Semantic versioning (optional)

> [!TIP]
> You can align `version` with your app version (e.g. `1.0.0`, `1.1.0`). The library does not interpret the string; it only checks equality. Any scheme (semver, date, build id) works as long as signer and verifier use the same value.
