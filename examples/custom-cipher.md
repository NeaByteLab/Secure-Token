# Custom Cipher

Use a custom cipher when you need compliance with a specific KMS, key storage, or algorithm that the default AES-GCM implementation does not cover. The library accepts any object that implements the `Cipher` interface: `decrypt` and `encrypt` with the correct signatures and return shapes.

## When to use a custom cipher

- **KMS or HSM:** Encrypt/decrypt with keys from AWS KMS, GCP KMS, or an HSM; the cipher calls your KMS API and returns the expected envelope.
- **Key from env or secret manager:** You already have a raw key (e.g. base64) and want to use it directly instead of deriving from a string secret.
- **Different algorithm:** You need another AEAD or format; implement it behind the same `Cipher` contract so the rest of the token flow (expiry, version, issuer) stays unchanged.

## Contract: return shape

> [!NOTE]
> Your implementation must return values that match the library’s expectations:

- **encrypt:** `(plaintext, secret, keySizeBytes, issuer, version)` → `Promise<{ encrypted: string, iv: string, tag: string }>`. All three fields are **hex strings** (lowercase or uppercase).
- **decrypt:** `(token, secret, keySizeBytes, issuer, version)` → `Promise<string>`. The string is the decrypted plaintext (usually JSON of the inner payload).

The library builds the outer token from your `encrypted`, `iv`, and `tag` and passes the same envelope back into `decrypt`. AAD is implied by `issuer` and `version`; if your backend uses AAD, bind it the same way.

## Example: wrapper with key from env

Assume you have a pre-derived key in env (e.g. 32-byte hex). This example wraps the built-in AES-GCM style but uses that key instead of deriving from a string secret. In practice you could replace the crypto calls with KMS encrypt/decrypt.

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

// Step: create JWT with custom cipher (secret still required by API but cipher can ignore it)
const jwt = new JWT({
  secret: 'unused-when-cipher-uses-own-key',
  version: '1.0.0',
  expireIn: '1h',
  cipher: customCipher
})

// Step: sign and decode work as usual; cipher handles encrypt/decrypt
const token = await jwt.sign({ userId: '1' })
const payload = await jwt.decode(token)
```

> [!NOTE]
> The library still requires a non-empty `secret` in options for validation; when using a key from env/KMS, you can pass a placeholder or the same secret you use for other config. The cipher receives it but may ignore it if it uses its own key.
