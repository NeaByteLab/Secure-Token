/**
 * Crypto helpers for AES-GCM and encoding.
 * @description Key derivation, IV, hex, and AAD.
 */
export class Shared {
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
   * @description Two hex chars per byte.
   * @param hex - Hex string
   * @returns Decoded bytes
   */
  static hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
    }
    return bytes
  }
}
