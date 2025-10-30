import type { JWTOptions, PayloadData, TokenData, TokenEncrypted } from '@app/Types.ts'
import { AES128GCM } from '@algorithms/AES-128-GCM.ts'
import { AES256GCM } from '@algorithms/AES-256-GCM.ts'
import { parseTimeToMs } from '@app/Parser.ts'
import {
  checkExpiration,
  isValidPayload,
  isValidToken,
  validateData,
  validateOptions,
  validateSecret,
  validateToken,
  validateVersion
} from '@app/Validator.ts'

/**
 * JSON Web Token utility backed by AES-GCM encryption.
 * @description Signs, verifies, and decodes tokens with versioning, expiration handling.
 */
export default class JWT {
  /** The encryption algorithm implementation */
  readonly #algorithm: AES128GCM | AES256GCM
  /** The issuer bound to the token */
  readonly #issuer: string
  /** The secret used to derive the encryption key */
  readonly #secret: string
  /** The expiration time in milliseconds */
  readonly #expireInMs: number
  /** The version of the token */
  readonly #version: string

  /**
   * Creates a JWT instance with the provided options.
   * @param options - Configuration including secret, version, expiration, and algorithm
   */
  constructor(options: JWTOptions) {
    validateOptions(options)
    validateSecret(options.secret)
    this.#secret = options.secret
    this.#issuer = options.issuer ?? 'secure-token'
    this.#algorithm = options.algorithm
      ? options.algorithm === 'aes-128-gcm' ? new AES128GCM() : new AES256GCM()
      : new AES128GCM()
    this.#expireInMs = parseTimeToMs(options.expireIn)
    this.#version = options.version
  }

  /**
   * Decodes a token and returns the original payload.
   * @param token - Encoded token string
   * @returns Decoded payload data
   * @throws {Error} When token format/structure is invalid or verification fails
   */
  async decode(token: string): Promise<unknown> {
    validateToken(token)
    let tokenData: TokenData
    try {
      tokenData = JSON.parse(atob(token))
    } catch {
      throw new Error('Invalid token format')
    }
    if (!isValidToken(tokenData)) {
      throw new Error('Invalid token structure')
    }
    checkExpiration(tokenData.exp)
    validateVersion(tokenData.version, this.#version)
    const tokenEncrypted: TokenEncrypted = {
      encrypted: tokenData.encrypted,
      iv: tokenData.iv,
      tag: tokenData.tag
    }
    const payloadDecrypted = await this.#algorithm.decrypt(
      tokenEncrypted,
      this.#secret,
      this.#issuer,
      this.#version
    )
    let payload: PayloadData
    try {
      payload = JSON.parse(payloadDecrypted)
    } catch {
      throw new Error('Invalid payload format')
    }
    if (!isValidPayload(payload)) {
      throw new Error('Invalid payload structure')
    }
    validateVersion(payload.version, tokenData.version)
    checkExpiration(payload.exp)
    if (payload.exp !== tokenData.exp || payload.iat !== tokenData.iat) {
      throw new Error('Token timestamp mismatch')
    }
    return payload.data
  }

  /**
   * Signs arbitrary data into a token string.
   * @param data - Data to embed in the token payload
   * @returns Encoded token string
   * @throws {Error} When input validation or encryption fails
   */
  async sign(data: unknown): Promise<string> {
    validateData(data)
    const now = Math.floor(Date.now() / 1000)
    const exp = now + Math.ceil(this.#expireInMs / 1000)
    const payload: PayloadData = {
      data,
      exp,
      iat: now,
      version: this.#version
    }
    const payloadString = JSON.stringify(payload)
    const tokenEncrypted: TokenEncrypted = await this.#algorithm.encrypt(
      payloadString,
      this.#secret,
      this.#issuer,
      this.#version
    )
    const tokenData: TokenData = {
      encrypted: tokenEncrypted.encrypted,
      iv: tokenEncrypted.iv,
      tag: tokenEncrypted.tag,
      exp,
      iat: now,
      version: this.#version
    }
    const tokenString = JSON.stringify(tokenData)
    return btoa(tokenString)
  }

  /**
   * Verifies token validity.
   * @param token - Encoded token string
   * @returns True when the token is valid; false otherwise
   */
  async verify(token: string): Promise<boolean> {
    try {
      await this.decode(token)
      return true
    } catch {
      return false
    }
  }
}

/**
 * Types re-export.
 * @description Public API for types used by this package.
 */
export * from '@app/Types.ts'
