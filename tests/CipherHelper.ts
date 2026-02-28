import type * as Types from '@app/Types.ts'

/**
 * Contract-compliant cipher for tests.
 * @description AES-GCM, key from secret, AAD issuer-version, iv 24 hex, tag 32 hex.
 */
export function buildContractCompliantCipher(): Types.Cipher {
  const hexToBytes = (hex: string) => {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
    }
    return bytes
  }
  const bytesToHex = (bytes: Uint8Array) =>
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  const deriveKey = async (secret: string, keySizeBytes: 16 | 32) => {
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(secret))
    const keyBytes = new Uint8Array(hash).slice(0, keySizeBytes)
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
      'encrypt',
      'decrypt'
    ])
  }
  return {
    async encrypt(plaintext, secret, keySizeBytes, issuer, version) {
      const key = await deriveKey(secret, keySizeBytes)
      const iv = crypto.getRandomValues(new Uint8Array(12))
      const aad = new TextEncoder().encode(`${issuer}-${version}`)
      const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad },
        key,
        new TextEncoder().encode(plaintext)
      )
      const bytes = new Uint8Array(ct)
      return {
        encrypted: bytesToHex(bytes.slice(0, -16)),
        iv: bytesToHex(iv),
        tag: bytesToHex(bytes.slice(-16))
      }
    },
    async decrypt(token, secret, keySizeBytes, issuer, version) {
      const key = await deriveKey(secret, keySizeBytes)
      const iv = hexToBytes(token.iv)
      const aad = new TextEncoder().encode(`${issuer}-${version}`)
      const enc = hexToBytes(token.encrypted)
      const tag = hexToBytes(token.tag)
      const combined = new Uint8Array(enc.length + tag.length)
      combined.set(enc)
      combined.set(tag, enc.length)
      const dec = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad },
        key,
        combined
      )
      return new TextDecoder().decode(dec)
    }
  }
}
