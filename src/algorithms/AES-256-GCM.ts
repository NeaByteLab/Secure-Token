import type { TokenEncrypted } from '@app/Types.ts'
import { AESGCM } from '@algorithms/AES-GCM.ts'

/**
 * AES-256-GCM encryption/decryption utility.
 * @description Encrypts and decrypts payloads using AES-GCM with 256-bit key.
 */
export class AES256GCM {
  /** AES-GCM implementation with 256-bit key */
  readonly #impl = new AESGCM(32)

  /**
   * Decrypts an encrypted token.
   * @param token - Encrypted token parts (ciphertext, iv, tag)
   * @param secret - Secret string used to derive the key
   * @param issuer - Issuer to bind as additional authenticated data
   * @param version - Version to bind as additional authenticated data
   * @returns Decrypted plaintext string
   * @throws {Error} When decryption fails or input is invalid
   */
  decrypt(token: TokenEncrypted, secret: string, issuer: string, version: string): Promise<string> {
    return this.#impl.decrypt(token, secret, issuer, version)
  }

  /**
   * Encrypts plaintext into an authenticated token.
   * @param data - Plaintext data to encrypt
   * @param secret - Secret string used to derive the key
   * @param issuer - Issuer to bind as additional authenticated data
   * @param version - Version to bind as additional authenticated data
   * @returns Encrypted token parts (ciphertext, iv, tag)
   * @throws {Error} When encryption fails or input is invalid
   */
  encrypt(data: string, secret: string, issuer: string, version: string): Promise<TokenEncrypted> {
    return this.#impl.encrypt(data, secret, issuer, version)
  }
}
