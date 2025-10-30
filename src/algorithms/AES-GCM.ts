import type { TokenEncrypted } from '@app/Types.ts'
import {
  bytesToHex,
  decoder,
  deriveKey,
  encoder,
  generateIV,
  hexToBytes
} from '@algorithms/Shared.ts'

/**
 * AES-GCM implementation.
 * @description AES-GCM encrypt/decrypt with AAD and issuer-version.
 */
export class AESGCM {
  /** Supported key sizes in bytes (16 or 32) */
  readonly #keySizeBytes: 16 | 32

  /**
   * Creates an AES-GCM instance.
   * @param keySizeBytes - Supported key sizes in bytes (16 or 32)
   */
  constructor(keySizeBytes: 16 | 32) {
    this.#keySizeBytes = keySizeBytes
  }

  /**
   * Decrypts an encrypted token into plaintext.
   * @param token - Encrypted token parts (ciphertext, iv, tag)
   * @param secret - Secret string used to derive the key
   * @param issuer - Issuer bound to AAD
   * @param version - Version bound to AAD
   * @returns Decrypted plaintext string
   * @throws {Error} When decryption fails
   */
  async decrypt(
    token: TokenEncrypted,
    secret: string,
    issuer: string,
    version: string
  ): Promise<string> {
    try {
      const key = await deriveKey(secret, this.#keySizeBytes)
      const iv = hexToBytes(token.iv)
      const tag = hexToBytes(token.tag)
      const encrypted = hexToBytes(token.encrypted)
      const aad = encoder.encode(`${issuer}-${version}`)
      const combined = new Uint8Array(encrypted.length + tag.length)
      combined.set(encrypted)
      combined.set(tag, encrypted.length)
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv as unknown as ArrayBuffer, additionalData: aad },
        key,
        combined
      )
      return decoder.decode(decrypted)
    } catch (error) {
      throw new Error(error instanceof Error ? error.message : 'Unknown error')
    }
  }

  /**
   * Encrypts plaintext and returns token parts.
   * @param data - Plaintext string to encrypt
   * @param secret - Secret string used to derive the key
   * @param issuer - Issuer bound to AAD
   * @param version - Version bound to AAD
   * @returns Encrypted token parts (ciphertext, iv, tag)
   * @throws {Error} When encryption fails
   */
  async encrypt(
    data: string,
    secret: string,
    issuer: string,
    version: string
  ): Promise<TokenEncrypted> {
    try {
      const key = await deriveKey(secret, this.#keySizeBytes)
      const iv = generateIV()
      const encodedData = encoder.encode(data)
      const aad = encoder.encode(`${issuer}-${version}`)
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv as unknown as ArrayBuffer, additionalData: aad },
        key,
        encodedData
      )
      const encryptedBytes = new Uint8Array(encrypted)
      const tag = encryptedBytes.slice(-16)
      const ciphertext = encryptedBytes.slice(0, -16)
      return {
        encrypted: bytesToHex(ciphertext),
        iv: bytesToHex(iv),
        tag: bytesToHex(tag)
      }
    } catch (error) {
      throw new Error(error instanceof Error ? error.message : 'Unknown error')
    }
  }
}
