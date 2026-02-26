import type * as Types from '@app/Types.ts'
import * as Helper from '@app/Helper.ts'
import * as Shared from '@cipher/Shared.ts'

/**
 * AES-GCM encrypt and decrypt implementation.
 * @description Uses Web Crypto and Shared helpers.
 */
export class AESGCM {
  /**
   * Decrypt token envelope to plaintext.
   * @description Derives key, decodes hex, verifies tag.
   * @param token - Encrypted envelope with iv and tag
   * @param secret - Shared secret
   * @param keySizeBytes - 16 or 32
   * @param issuer - Issuer for AAD
   * @param version - Version for AAD
   * @returns Decrypted plaintext string
   * @throws {Error} When decrypt or decode fails
   */
  static async decrypt(
    token: Types.TokenEncrypted,
    secret: string,
    keySizeBytes: 16 | 32,
    issuer: string,
    version: string
  ): Promise<string> {
    try {
      const derivedKey = await Shared.Shared.deriveKey(secret, keySizeBytes)
      const iv = Shared.Shared.hexToBytes(token.iv)
      const tag = Shared.Shared.hexToBytes(token.tag)
      const encrypted = Shared.Shared.hexToBytes(token.encrypted)
      const aad = Shared.Shared.buildAad(issuer, version)
      const ciphertextWithTag = new Uint8Array(encrypted.length + tag.length)
      ciphertextWithTag.set(encrypted)
      ciphertextWithTag.set(tag, encrypted.length)
      const decrypted = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv as unknown as ArrayBuffer,
          additionalData: aad as unknown as ArrayBuffer
        },
        derivedKey,
        ciphertextWithTag
      )
      return Shared.Shared.decoder.decode(decrypted)
    } catch (caughtError: unknown) {
      throw Helper.Helper.normalizeToError(caughtError)
    }
  }

  /**
   * Encrypt plaintext to token envelope.
   * @description Derives key, generates IV, returns hex.
   * @param plaintext - String to encrypt
   * @param secret - Shared secret
   * @param keySizeBytes - 16 or 32
   * @param issuer - Issuer for AAD
   * @param version - Version for AAD
   * @returns Encrypted envelope with iv and tag
   * @throws {Error} When encrypt fails
   */
  static async encrypt(
    plaintext: string,
    secret: string,
    keySizeBytes: 16 | 32,
    issuer: string,
    version: string
  ): Promise<Types.TokenEncrypted> {
    try {
      const derivedKey = await Shared.Shared.deriveKey(secret, keySizeBytes)
      const iv = Shared.Shared.generateIV()
      const encodedPlaintext = Shared.Shared.encoder.encode(plaintext)
      const aad = Shared.Shared.buildAad(issuer, version)
      const encrypted = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv as unknown as ArrayBuffer,
          additionalData: aad as unknown as ArrayBuffer
        },
        derivedKey,
        encodedPlaintext
      )
      const encryptedBytes = new Uint8Array(encrypted)
      const tag = encryptedBytes.slice(-16)
      const ciphertext = encryptedBytes.slice(0, -16)
      return {
        encrypted: Shared.Shared.bytesToHex(ciphertext),
        iv: Shared.Shared.bytesToHex(iv),
        tag: Shared.Shared.bytesToHex(tag)
      }
    } catch (caughtError: unknown) {
      throw Helper.Helper.normalizeToError(caughtError)
    }
  }
}
