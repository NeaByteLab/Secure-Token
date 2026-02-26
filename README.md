# Secure Token

[![Deno](https://img.shields.io/badge/Deno-2.5.4-blue)](https://deno.com) [![JSR](https://jsr.io/badges/@neabyte/secure-token)](https://jsr.io/@neabyte/secure-token) [![CI](https://github.com/NeaByteLab/Secure-Token/actions/workflows/ci.yaml/badge.svg)](https://github.com/NeaByteLab/Secure-Token/actions/workflows/ci.yaml) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Protect credentials with confidential tokens ensuring integrity and privacy.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Methods Overview](#methods-overview)
- [Options](#options)
- [Basic Usage](#basic-usage)
- [API Reference](#api-reference)
- [How This Works](#how-this-works)
- [Token Format](#token-format)
- [Environment & Compatibility](#environment--compatibility)
- [Tips & Best Practices](#tips--best-practices)
- [Troubleshooting](#troubleshooting)
- [Testing](#testing)
- [License](#license)

## Installation

```sh
deno add jsr:@neabyte/secure-token
```

> [!NOTE]
> Requires [Deno](https://deno.com). The package is published on [JSR](https://jsr.io/@neabyte/secure-token).

## Quick Start

Only `secret`, `version`, and `expireIn` are required. See [Options](#options) for full config.

> [!TIP]
> Use try/catch for `sign` and `decode`; they throw on failure. `verify` returns `true`/`false` and does not throw.

```ts
import JWT from '@neabyte/secure-token'

// create instance with secret, version, expireIn
const jwt = new JWT({
  secret: 'super-secret',
  version: '1.0.0',
  expireIn: '1h'
})

// issue token
const token = await jwt.sign({ userId: '123', role: 'admin' })
// check without reading payload
const isValid = await jwt.verify(token)
// decrypt and get payload
const payload = await jwt.decode(token)
```

## Methods Overview

| Method              | Input             | Returns            | Description                                                                            |
| :------------------ | :---------------- | :----------------- | :------------------------------------------------------------------------------------- |
| `jwt.sign(data)`    | JSON-serializable | `Promise<string>`  | Encrypt payload, return Base64 token.                                                  |
| `jwt.verify(token)` | token string      | `Promise<boolean>` | Validate structure, expiry, version, decrypt; returns `true`/`false` (does not throw). |
| `jwt.decode(token)` | token string      | `Promise<unknown>` | Decrypt and return original payload data.                                              |

## Options

**JWTOptions** for the constructor:

| Option      | Type                             | Required | Description                                         |
| :---------- | :------------------------------- | :------: | :-------------------------------------------------- |
| `secret`    | `string`                         |   yes    | Secret used to derive the encryption key.           |
| `version`   | `string`                         |   yes    | Application token version (bound in AAD).           |
| `expireIn`  | `string`                         |   yes    | Duration, e.g. `'30m'`, `'7d'`, `'500ms'` (max 1y). |
| `algorithm` | `'aes-128-gcm' \| 'aes-256-gcm'` |    no    | Default: `'aes-128-gcm'`.                           |
| `issuer`    | `string`                         |    no    | Issuer bound in AAD. Default: `'secure-token'`.     |
| `cipher`    | `Cipher`                         |    no    | Custom encrypt/decrypt; default uses AES-GCM.       |

```ts
const options = {
  secret: 'super-secret',
  version: '1.0.0',
  expireIn: '1h',
  algorithm: 'aes-128-gcm', // optional
  issuer: 'secure-token', // optional
  cipher: undefined // optional; pluggable cipher
}
```

## Basic Usage

### Sign a payload

```ts
const payload = { userId: 123, role: 'admin' }
const token = await jwt.sign(payload)
```

### Verify a token

```ts
const isValid = await jwt.verify(token)
```

### Decode a token

```ts
const payload = await jwt.decode(token)
```

`decode` throws on invalid, expired, or wrong-version tokens. Use try/catch and optionally check `error.message` (e.g. `'Token expired at ...'`, `'Version mismatch...'`, `'Invalid token format'`).

```ts
try {
  const payload = await jwt.decode(token)
  // use payload
} catch (err) {
  const msg = err instanceof Error ? err.message : ''
  if (msg.includes('expired')) {
    // token expired; re-login or refresh
  } else if (msg.includes('Version mismatch')) {
    // wrong app version
  } else {
    // invalid format, tampered, or wrong secret/issuer
  }
}
```

### Using AES-256-GCM

Pass `algorithm: 'aes-256-gcm'` for a 32-byte key. Use a secret long enough (e.g. 32+ chars or a 32-byte base64 value from a secure generator).

```ts
const jwt = new JWT({
  secret: 'your-secret-at-least-32-chars-long!!!!!!!!',
  version: '1.0.0',
  expireIn: '1h',
  algorithm: 'aes-256-gcm'
})
```

### Custom cipher

You can plug in a custom encrypt/decrypt implementation via the `Cipher` interface (see exported type `Cipher`). It must expose `encrypt(plaintext, secret, keySizeBytes, issuer, version)` and `decrypt(token, secret, keySizeBytes, issuer, version)`, both returning a Promise.

```ts
import JWT, { type Cipher, type TokenEncrypted } from '@neabyte/secure-token'

const myCipher: Cipher = {
  async encrypt(plaintext, _secret, _keySizeBytes, _issuer, _version) {
    // your encrypt logic → return { encrypted, iv, tag } (hex strings)
    return { encrypted: '...', iv: '...', tag: '...' }
  },
  async decrypt(token: TokenEncrypted, _secret, _keySizeBytes, _issuer, _version) {
    // your decrypt logic → return plaintext string
    return '...'
  }
}

const jwt = new JWT({
  secret: 'secret',
  version: '1.0.0',
  expireIn: '1h',
  cipher: myCipher
})
```

### Sign non-object data

Payload is not limited to objects. You can sign strings, numbers, booleans, or arrays; `decode` returns the same value. Only `null` and `undefined` are rejected.

```ts
await jwt.sign('user-123') // string
await jwt.sign(42) // number
await jwt.sign(true) // boolean
await jwt.sign(['a', 'b', 'c']) // array
await jwt.sign({ a: 1, b: 2 }) // object

const token = await jwt.sign(['a', 1, false])
const data = await jwt.decode(token) // data === ['a', 1, false]
```

## API Reference

### constructor(options)

Use when creating a JWT instance with secret, version, and expiration.

- `options` `<JWTOptions>`: `secret`, `version`, `expireIn` (required); `algorithm?`, `issuer?`, `cipher?`.
- Returns: `<JWT>`.
- Validates options and parses `expireIn` to milliseconds.

### jwt.sign(data)

Use when you need to issue a token from arbitrary JSON-serializable data.

- `data` `<unknown>`: Payload to embed (object, array, string, number, boolean).
- Returns: `<Promise<string>>` Base64 token.
- Encrypts with AES-GCM, AAD `issuer-version`; throws on invalid input.

### jwt.verify(token)

Use when you only need to know if the token is valid (no payload).

- `token` `<string>`: Token string from `sign`.
- Returns: `<Promise<boolean>>` — `true` if valid, `false` if invalid or expired. **Does not throw.**
- Validates structure, expiration, version, and decryptability.

### jwt.decode(token)

Use when you need the decrypted payload from the token.

- `token` `<string>`: Token string from `sign`.
- Returns: `<Promise<unknown>>` Original `data`.
- Decrypts and validates; throws on invalid, expired, or version mismatch.

> [!IMPORTANT]
> **`sign`** and **`decode`** throw on failure (invalid input, invalid format, version mismatch, expired, decryption error). **`verify`** does not throw; it returns `false` when the token is invalid. Use try/catch for sign and decode.
>
> ```ts
> try {
>   const token = await jwt.sign({ userId: '123' })
>   const isValid = await jwt.verify(token) // false if invalid; does not throw
>   if (!isValid) {
>     // token invalid or expired
>   }
> } catch (error) {
>   // sign failed (e.g. null/undefined payload)
> }
> ```

## How This Works

### End-to-end flow

- **Sign:** Validate input → build payload `{ data, iat, exp, version }` → encrypt with AES-GCM (AAD: `issuer-version`) → assemble `TokenData` → return `btoa(JSON.stringify(TokenData))`.
- **Decode:** Validate string → `atob` → parse `TokenData` → check `exp` and `version` → decrypt with AAD → validate payload → return `payload.data`.
- **Verify:** Same as decode; returns `true` on success, `false` on failure.

### Security properties

- AES-GCM provides confidentiality and integrity (auth tag).
- AAD binds tokens to `issuer` and `version`.
- Expiration enforced; max 1 year.
- Outer and inner `{ iat, exp, version }` must match.

## Token Format

Base64-encoded JSON:

```json
{
  "encrypted": "<hex>",
  "iv": "<hex>",
  "tag": "<hex>",
  "exp": 1735689600,
  "iat": 1735686000,
  "version": "1.0.0"
}
```

Inner payload `{ data, iat, exp, version }` is JSON-encoded then AES-GCM encrypted to produce the hex fields.

## Environment & Compatibility

> [!NOTE]
> Requires **WebCrypto** (`crypto.subtle`). Supported in Deno (version in badge). No Node polyfills; use in Deno without extra flags.

## Tips & Best Practices

- [Salt Secrets With a Strong Random Generator](./examples/salt-secrets.md)
- [Token Reissue During Rotation Window](./examples/migration-window.md)
- [Refresh Token Pattern (Rolling Expiration)](./examples/refresh-rolling.md)
- [Multi-Issuer Setup (Microservices)](./examples/multi-issuer.md)
- [Custom Cipher](./examples/custom-cipher.md) — KMS, key from env, or different algorithm.
- [ExpireIn in Practice](./examples/expire-in-practice.md) — Access vs refresh vs API key; max 1y and NTP.
- [Versioning Schema](./examples/versioning-schema.md) — Breaking changes and migration window.
- [Error Handling](./examples/error-handling.md) — Map error messages to refresh, upgrade, or 401.
- [Serverless and Env-Based Secrets](./examples/serverless-env.md) — One JWT instance per process; Deno Deploy, Fly, Cloud Run.

### Security Considerations

> [!IMPORTANT]
>
> - Use strong, unique secrets per environment.
> - Keep secrets out of source control; use secret managers.
> - Ensure time sync (NTP) on all nodes; expiration depends on accurate clocks.

## Troubleshooting

| Issue                         | Cause / fix                                                                              |
| :---------------------------- | :--------------------------------------------------------------------------------------- |
| Invalid time format           | `expireIn` must be digits + unit: `ms`, `s`, `m`, `h`, `d`, `M`, `y` (e.g. `1h`, `30m`). |
| Invalid token format          | Pass the exact string from `sign`; avoid whitespace or encoding changes.                 |
| Token expired                 | Increase `expireIn` or issue a new token.                                                |
| Version mismatch              | Instance `version` must match the token’s embedded version.                              |
| Wrong issuer/secret/algorithm | Changing any of these invalidates existing tokens.                                       |

## Testing

```sh
deno task test
```

## Contributing

Contributions welcome. Open a [Pull Request](https://github.com/NeaByteLab/Secure-Token/pulls).

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for details.
