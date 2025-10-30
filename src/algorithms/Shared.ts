/** The encoder for converting strings to bytes */
export const encoder = new TextEncoder()

/** The decoder for converting bytes to strings */
export const decoder = new TextDecoder()

/**
 * Converts bytes to a lowercase hexadecimal string.
 * @param bytes - Byte array to convert
 * @returns Hexadecimal string representation
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Derives an AES-GCM cryptographic key from a secret.
 * @param secret - Input secret string
 * @param keySizeBytes - Key size in bytes (16 or 32)
 * @returns Imported CryptoKey usable for AES-GCM
 */
export async function deriveKey(secret: string, keySizeBytes: 16 | 32): Promise<CryptoKey> {
  const encoder = new TextEncoder()
  const data = encoder.encode(secret)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const keyData = new Uint8Array(hashBuffer).slice(0, keySizeBytes)
  const extractable = false
  const keyUsages: KeyUsage[] = ['encrypt', 'decrypt']
  return crypto.subtle.importKey('raw', keyData, { name: 'AES-GCM' }, extractable, keyUsages)
}

/**
 * Generates a random 96-bit IV for AES-GCM.
 * @returns Randomly generated IV bytes
 */
export function generateIV(): Uint8Array {
  const iv = new Uint8Array(12)
  crypto.getRandomValues(iv)
  return iv
}

/**
 * Converts a hex string to bytes.
 * @param hex - Hexadecimal string (no prefix)
 * @returns Corresponding byte array
 */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}
