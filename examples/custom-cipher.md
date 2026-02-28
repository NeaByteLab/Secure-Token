# Custom Cipher

Use a custom cipher when you need compliance with a specific KMS, key storage, or algorithm that the default AES-GCM implementation does not cover. The library accepts any object that implements the `Cipher` interface: `decrypt` and `encrypt` with the correct signatures and return shapes.

## When to use a custom cipher

- **KMS or HSM:** Encrypt/decrypt with keys from AWS KMS, GCP KMS, or an HSM; the cipher calls your KMS API and returns the expected envelope.
- **Key from env or secret manager:** You already have a raw key (e.g. base64) and want to use it directly instead of deriving from a string secret.
- **Different algorithm:** You need another AEAD or format; implement it behind the same `Cipher` contract so the rest of the token flow (expiry, version, issuer) stays unchanged.

## Contract: return shape

> [!NOTE]
> Your implementation must return values that match the library’s expectations:

- **encrypt:** `(plaintext, secret, keySizeBytes, issuer, version)` → `Promise<{ encrypted: string, iv: string, tag: string }>`. All three fields are **hex strings**. For compatibility: **iv 24 hex chars** (12 bytes), **tag 32 hex chars** (16 bytes).
- **decrypt:** `(token, secret, keySizeBytes, issuer, version)` → `Promise<string>`. The string is the decrypted plaintext (usually JSON of the inner payload).

The library builds the outer token from your `encrypted`, `iv`, and `tag` and passes the same envelope back into `decrypt`.

## Contract: isolation (security)

Your implementation **must** satisfy these for correct isolation:

1. **Use `secret`:** Derive or resolve the key from `secret` (or ensure one key per secret). Do not use a single fixed key for all secrets, or tokens from one secret can be decoded with another.
2. **Bind `issuer` and `version`:** Use them (e.g. as AAD) so tokens cannot be used across issuer/version. If your backend uses AAD, bind `${issuer}-${version}` the same way as the default cipher.
3. **Return shape:** `encrypt` must return hex strings with **iv 24 chars**, **tag 32 chars** for interoperability.

## Example: cipher that derives key from secret (contract-compliant)

This minimal example derives the key from `secret` and binds `issuer`/`version` as AAD. It satisfies the contract so tokens are isolated per secret and per issuer/version.

```ts
import JWT, { type Cipher, type TokenEncrypted } from '@neabyte/secure-token'

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

async function deriveKey(secret: string, keySizeBytes: 16 | 32): Promise<CryptoKey> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret))
  const keyBytes = new Uint8Array(hash).slice(0, keySizeBytes)
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt'
  ])
}

const compliantCipher: Cipher = {
  async encrypt(plaintext, secret, keySizeBytes, issuer, version) {
    // Step: derive key and generate IV
    const key = await deriveKey(secret, keySizeBytes)
    const iv = crypto.getRandomValues(new Uint8Array(12))
    // Step: bind issuer and version as AAD
    const aad = new TextEncoder().encode(`${issuer}-${version}`)
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad },
      key,
      new TextEncoder().encode(plaintext)
    )
    // Step: split ciphertext and tag; return hex (iv 24, tag 32 chars)
    const bytes = new Uint8Array(ct)
    return {
      encrypted: bytesToHex(bytes.slice(0, -16)),
      iv: bytesToHex(iv),
      tag: bytesToHex(bytes.slice(-16))
    }
  },
  async decrypt(token: TokenEncrypted, secret, keySizeBytes, issuer, version) {
    // Step: derive key and parse envelope from hex
    const key = await deriveKey(secret, keySizeBytes)
    const iv = hexToBytes(token.iv)
    const aad = new TextEncoder().encode(`${issuer}-${version}`)
    const combined = new Uint8Array(
      hexToBytes(token.encrypted).length + hexToBytes(token.tag).length
    )
    combined.set(hexToBytes(token.encrypted))
    combined.set(hexToBytes(token.tag), hexToBytes(token.encrypted).length)
    // Step: decrypt and return plaintext string
    const dec = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad },
      key,
      combined
    )
    return new TextDecoder().decode(dec)
  }
}

// Step: create JWT with custom cipher
const jwt = new JWT({
  secret: 'my-secret',
  version: '1.0.0',
  expireIn: '1h',
  cipher: compliantCipher
})
const token = await jwt.sign({ userId: '1' })
const payload = await jwt.decode(token)
```

## Example: wrapper with key from env

Assume you have a pre-derived key in env (e.g. 32-byte hex). This example wraps the built-in AES-GCM style but uses that key instead of deriving from a string secret. In practice you could replace the crypto calls with KMS encrypt/decrypt.

> [!WARNING]
> When using your own key (env/KMS), you must still ensure isolation: use one key per secret or per issuer, or bind secret/issuer/version in AAD so tokens cannot be used across tenants.

```ts
import JWT, { type Cipher, type TokenEncrypted } from '@neabyte/secure-token'

// Step: key from env (e.g. 32-byte hex from KMS or secret manager)
const KEY_HEX = Deno.env.get('TOKEN_KEY_HEX') ?? ''

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

// Step: derive CryptoKey from hex key (slice to 16 or 32 bytes per algorithm)
async function getKey(keySizeBytes: 16 | 32): Promise<CryptoKey> {
  const keyBytes = hexToBytes(KEY_HEX).slice(0, keySizeBytes)
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt'
  ])
}

const customCipher: Cipher = {
  async encrypt(plaintext, _secret, keySizeBytes, issuer, version) {
    // Step: get key and generate IV
    const key = await getKey(keySizeBytes)
    const iv = crypto.getRandomValues(new Uint8Array(12))
    // Step: build AAD from issuer and version (must match library contract)
    const aad = new TextEncoder().encode(`${issuer}-${version}`)
    const ct = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: aad
      },
      key,
      new TextEncoder().encode(plaintext)
    )
    // Step: split ciphertext and tag; return as hex strings
    const bytes = new Uint8Array(ct)
    const tag = bytes.slice(-16)
    const encrypted = bytes.slice(0, -16)
    return {
      encrypted: bytesToHex(encrypted),
      iv: bytesToHex(iv),
      tag: bytesToHex(tag)
    }
  },
  async decrypt(token: TokenEncrypted, _secret, keySizeBytes, issuer, version) {
    // Step: get key and decode hex envelope to bytes
    const key = await getKey(keySizeBytes)
    const iv = hexToBytes(token.iv)
    const aad = new TextEncoder().encode(`${issuer}-${version}`)
    const ciphertext = hexToBytes(token.encrypted)
    const tag = hexToBytes(token.tag)
    // Step: combine ciphertext + tag and decrypt
    const combined = new Uint8Array(ciphertext.length + tag.length)
    combined.set(ciphertext)
    combined.set(tag, ciphertext.length)
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: aad
      },
      key,
      combined
    )
    return new TextDecoder().decode(decrypted)
  }
}

// Step: create JWT with custom cipher (library still requires non-empty secret in options)
const jwt = new JWT({
  secret: 'placeholder-or-config-secret',
  version: '1.0.0',
  expireIn: '1h',
  cipher: customCipher
})

// Step: sign and decode work as usual; cipher handles encrypt/decrypt
const token = await jwt.sign({ userId: '1' })
const payload = await jwt.decode(token)
```

> [!NOTE]
> The library requires a non-empty `secret` in options. When your cipher uses its own key (env/KMS), pass a placeholder or config value; ensure isolation per secret/issuer (e.g. different keys per tenant or bind them in AAD).
