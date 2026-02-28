/**
 * Crypto helpers for AES-GCM and encoding.
 * @description Key derivation, IV, hex, and AAD.
 */
export class Shared {
  /** Max ciphertext size in bytes (DoS mitigation). */
  static readonly maxEncryptedBytes = 256 * 1024
  /** Auth tag length in bytes (AES-GCM). */
  static readonly tagBytes = 16
  /** IV length in bytes (AES-GCM). */
  static readonly ivBytes = 12
  /** Decode ArrayBuffer to UTF-8 string */
  static readonly decoder = new TextDecoder()
  /** Encode string to UTF-8 bytes */
  static readonly encoder = new TextEncoder()

  /**
   * Build additional authenticated data.
   * @description Encodes issuer-version for AAD.
   * @param issuer - Issuer string
   * @param version - Version string
   * @returns AAD as Uint8Array
   */
  static buildAad(issuer: string, version: string): Uint8Array {
    return Shared.encoder.encode(`${issuer}-${version}`)
  }

  /**
   * Convert bytes to lowercase hex string.
   * @description Two hex chars per byte.
   * @param bytes - Bytes to encode
   * @returns Hex string
   */
  static bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  }

  /**
   * Derive AES-GCM key from secret.
   * @description SHA-256 then slice to key size.
   * @param secret - Shared secret string
   * @param keySizeBytes - 16 or 32
   * @returns CryptoKey for encrypt/decrypt
   */
  static async deriveKey(secret: string, keySizeBytes: 16 | 32): Promise<CryptoKey> {
    const encoder = new TextEncoder()
    const secretBytes = encoder.encode(secret)
    const hashBuffer = await crypto.subtle.digest('SHA-256', secretBytes)
    const keyData = new Uint8Array(hashBuffer).slice(0, keySizeBytes)
    const extractable = false
    const keyUsages: KeyUsage[] = ['encrypt', 'decrypt']
    return crypto.subtle.importKey('raw', keyData, { name: 'AES-GCM' }, extractable, keyUsages)
  }

  /**
   * Generate random 12-byte IV.
   * @description Uses crypto.getRandomValues.
   * @returns 12-byte IV for AES-GCM
   */
  static generateIV(): Uint8Array {
    const iv = new Uint8Array(12)
    crypto.getRandomValues(iv)
    return iv
  }

  /**
   * Parse hex string to bytes.
   * @description Decodes hex to bytes; validates format and max length.
   * @param hex - Hex string (even length, 0-9a-fA-F only)
   * @param maxBytes - Optional max size in bytes; throws if exceeded
   * @returns Decoded bytes
   * @throws {Error} When hex length odd, non-hex chars, or exceeds maxBytes
   */
  static hexToBytes(hex: string, maxBytes?: number): Uint8Array {
    if (typeof hex !== 'string') {
      throw new Error('Invalid hex length')
    }
    if (hex.length === 0) {
      return new Uint8Array(0)
    }
    if (hex.length % 2 !== 0) {
      throw new Error('Invalid hex length')
    }
    const byteCount = hex.length / 2
    if (maxBytes !== undefined && byteCount > maxBytes) {
      throw new Error('Token too large')
    }
    if (!/^[0-9a-fA-F]+$/.test(hex)) {
      throw new Error('Invalid hex format')
    }
    const bytes = new Uint8Array(byteCount)
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
    }
    return bytes
  }
}
