# Secure Token [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE) [![Deno](https://img.shields.io/badge/Deno-2.5.4-blue)](https://deno.land) [![JSR](https://jsr.io/badges/@neabyte/secure-token)](https://jsr.io/@neabyte/secure-token)

Protect credentials with confidential tokens ensuring integrity and privacy.

## Installation

```sh
deno add jsr:@neabyte/secure-token
```

## Quick Start

```ts
import JWT from '@neabyte/secure-token'

const jwt = new JWT({
  secret: 'super-secret',
  version: '1.0.0',
  expireIn: '1h'
})

const token = await jwt.sign({ userId: '123', role: 'admin' })
const isValid = await jwt.verify(token)
const payload = await jwt.decode(token)
```

## Configuration

### JWT Options

```ts
const options = {
  algorithm: 'aes-128-gcm',  // optional (default: 'aes-128-gcm')
  secret: 'super-secret',    // required (secret used to derive the encryption key)
  issuer: 'secure-token',    // optional (default: 'secure-token')
  version: '1.0.0',          // required (application token version)
  expireIn: '1h'             // required (e.g., '30m', '7d', '500ms')
}
```

## Basic Usage

### Sign a payload

```ts
const payload = { userId: 123, role: 'admin' }
const token = await jwt.sign(payload)
console.log(token) // <base64-encoded-token>
```

### Verify a token

```ts
const isValid = await jwt.verify(token)
console.log(isValid) // true | false
```

### Decode a token

```ts
const payload = await jwt.decode(token)
console.log(payload) // { userId: 123, role: 'admin' }
```

### Sign non-object data

`sign` accepts any JSON-serializable value (not just objects). `null` and `undefined` are rejected.

```ts
await jwt.sign('user-123')         // string
await jwt.sign(42)                 // number
await jwt.sign(true)               // boolean
await jwt.sign(['a', 'b', 'c'])    // array
await jwt.sign({ a: 1, b: 2 })     // object

// Decoding returns the original value
const token = await jwt.sign(['a', 1, false])
const data = await jwt.decode(token)
// data => ['a', 1, false]
```

## API Reference

### constructor

Creates a JWT instance with validated options and parsed expiration.

```typescript
new JWT(options)
```

- `options` `<JWTOptions>`: Configuration for the instance. See Configuration → JWT Options.
  - `algorithm` `<'aes-128-gcm' | 'aes-256-gcm'>`: (Optional) Default: `"aes-128-gcm"`.
  - `secret` `<string>`: Secret used to derive the encryption key.
  - `issuer` `<string>`: (Optional) Issuer bound via AAD. Default: `"secure-token"`.
  - `version` `<string>`: Application token version to bind and validate.
  - `expireIn` `<string>`: Expiration duration like `"1h"`, `"30m"`, `"7d"` (max 1 year).
- Returns: `JWT`

### sign

Signs data into a token using AES-GCM with issuer-version AAD and Base64-encodes the result.

```typescript
jwt.sign(data)
```

- `data` `<unknown>`: Arbitrary JSON-serializable data to embed in the token payload.
- Returns: `Promise<string>`

### verify

Validates structure, expiration, version binding, and decryptability. Returns `true` when valid.

```typescript
jwt.verify(token)
```

- `token` `<string>`: Token string previously produced by `sign`.
- Returns: `Promise<boolean>`

### decode

Decrypts and validates the token, returning the original `data` on success.

```typescript
jwt.decode(token)
```

- `token` `<string>`: Token string previously produced by `sign`.
- Returns: `Promise<unknown>`

> [!IMPORTANT]
> All operations throw on failure (e.g., invalid format, version mismatch, expired token, or decryption error). Wrap calls in try/catch and handle errors explicitly, and surface meaningful error messages.
>
> ```ts
> try {
>   const token = await jwt.sign({ userId: '123' })
>   const isValid = await jwt.verify(token)
> } catch (error) {
>   // handle or log the error message
> }
> ```

## How This Works

### End-to-end flow

- Sign
  - Validate input → build payload `{ data, iat, exp, version }`
  - Encrypt payload JSON with AES-GCM using AAD: `issuer-version`
  - Assemble `TokenData` `{ encrypted, iv, tag, iat, exp, version }`
  - Return `btoa(JSON.stringify(TokenData))`

- Decode
  - Validate token string → `atob` → parse `TokenData`
  - Check `exp`, ensure `version` matches instance
  - Decrypt with AES-GCM using AAD: `issuer-version` → parse payload
  - Validate payload, check timestamps/version match outer token
  - Return `payload.data`

- Verify
  - Calls `decode(token)` and returns `true` if it succeeds, else `false`

### Security properties

- AES-GCM provides confidentiality and integrity (auth tag)
- AAD binds tokens to `issuer` and `version` (context-bound tokens)
- Expiration enforced and capped (max 1 year)
- Outer and inner `{ iat, exp, version }` must match

## Token Format

The final token is a Base64 string of a JSON object:

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

The inner payload `{ data, iat, exp, version }` is JSON-encoded, then AES-GCM encrypted to produce the hex fields above, ensuring integrity, authenticity, and issuer-version binding enforcement throughout.

## Environment & Compatibility

- Requires WebCrypto (`crypto.subtle`), available in Deno ≥ the version shown in the badge.
- Works in Deno without additional flags. No Node polyfills included.

## Tips & Best Practices

- [Salt Secrets with a Strong Random Generator](./examples/salt-secrets.md)
- [Token Reissue During Rotation Window](./examples/migration-window.md)
- [Refresh Token Pattern (Rolling Expiration)](./examples/refresh-rolling.md)
- [Multi-Issuer Setup (Microservices)](./examples/multi-issuer.md)

### Security Considerations

- Keep secrets out of source control. Use secret managers; never commit or log secrets.
- Use strong, unique secrets per environment. Don't reuse secrets between staging, production, or projects.
- Ensure time synchronization. JWT requires accurate clocks. Enable NTP or secure time on all nodes.

## Troubleshooting

### Common Issues

- **Invalid time format**: Ensure `expireIn` follows `^(\\d+)(ms|s|m|h|d|M|y)$`.
- **Version mismatch**: The instance `version` must match the token’s embedded version.
- **Token expired**: Increase `expireIn` or renew the token.
- **Invalid token format/structure**: Ensure you pass the exact string returned by `sign` and avoid accidental whitespace/encoding changes and mismatched base64 or JSON corruption.
- **Wrong issuer/secret/algorithm**: Tokens are bound to `issuer` and `version`; changing any of `issuer`, `version`, `secret`, or `algorithm` after issuing will invalidate existing tokens.

## Testing

```sh
deno task test
```

## Contributing

Contributions are welcome! Please feel free to submit a [Pull Request](https://github.com/NeaByteLab/Secure-Token/pulls).

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
