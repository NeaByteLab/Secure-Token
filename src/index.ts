import type * as Types from '@app/Types.ts'
import * as Cipher from '@cipher/index.ts'
import * as Helper from '@app/Helper.ts'
import * as Parser from '@app/Parser.ts'
import * as Validator from '@app/Validator.ts'

/**
 * Signed, encrypted token API.
 * @description Sign payloads and decode/verify tokens with AES-GCM.
 */
export default class JWT {
  /** Pluggable encrypt/decrypt implementation */
  readonly #cipher: Types.Cipher
  /** AES key size in bytes (16 or 32) */
  readonly #keySizeBytes: 16 | 32
  /** Issuer string used in AAD */
  readonly #issuer: string
  /** Shared secret for key derivation */
  readonly #secret: string
  /** Token lifetime in milliseconds */
  readonly #expireInMs: number
  /** Schema version for AAD and validation */
  readonly #version: string
  /** Single message for decode failures. */
  static readonly #decodeErrorMessage = 'Invalid token'
  /** Default AES-GCM cipher for JWT. */
  static readonly #defaultCipher: Types.Cipher = {
    encrypt: (plaintext, secret, keySizeBytes, issuer, version) =>
      Cipher.AESGCM.encrypt(plaintext, secret, keySizeBytes, issuer, version),
    decrypt: (token, secret, keySizeBytes, issuer, version) =>
      Cipher.AESGCM.decrypt(token, secret, keySizeBytes, issuer, version)
  }

  /**
   * Create JWT instance with options.
   * @description Validates options and parses expireIn.
   * @param options - Secret, version, expireIn, optional cipher and issuer
   */
  constructor(options: Types.JWTOptions) {
    Validator.Validator.validateOptions(options)
    const opts = options as unknown as Record<string, unknown>
    Validator.Validator.validateRequiredOptionsOwn(opts, ['secret', 'version', 'expireIn'])
    Validator.Validator.validateSecret(opts['secret'])
    this.#secret = opts['secret'] as string
    this.#version = opts['version'] as string
    this.#expireInMs = Parser.Parser.parseTimeToMs(opts['expireIn'] as string)
    this.#cipher = Object.hasOwn(opts, 'cipher') && opts['cipher'] != null
      ? (opts['cipher'] as Types.Cipher)
      : JWT.#defaultCipher
    this.#issuer = Object.hasOwn(opts, 'issuer') && typeof opts['issuer'] === 'string'
      ? opts['issuer']
      : 'secure-token'
    this.#keySizeBytes = Object.hasOwn(opts, 'algorithm') && opts['algorithm'] === 'aes-256-gcm'
      ? 32
      : 16
  }

  /**
   * Decode token and return payload data
   * @description Validates structure, expiry, version; returns payload.data.
   * @param token - Base64-encoded token string
   * @returns Decrypted payload data
   * @throws {Error} When invalid, expired, or version mismatch
   */
  async decode(token: string): Promise<unknown> {
    try {
      Validator.Validator.validateToken(token)
      let tokenData: Types.TokenData
      try {
        tokenData = JSON.parse(atob(token))
      } catch {
        throw new Error(JWT.#decodeErrorMessage)
      }
      if (!Validator.Validator.isValidToken(tokenData)) {
        throw new Error(JWT.#decodeErrorMessage)
      }
      Validator.Validator.checkExpiration(tokenData.exp)
      Validator.Validator.validateVersion(tokenData.version, this.#version)
      const tokenEncrypted: Types.TokenEncrypted = {
        encrypted: tokenData.encrypted,
        iv: tokenData.iv,
        tag: tokenData.tag
      }
      const payloadDecrypted = await this.#cipher.decrypt(
        tokenEncrypted,
        this.#secret,
        this.#keySizeBytes,
        this.#issuer,
        this.#version
      )
      let payload: Types.PayloadData
      try {
        payload = JSON.parse(payloadDecrypted)
      } catch {
        throw new Error(JWT.#decodeErrorMessage)
      }
      if (!Validator.Validator.isValidPayload(payload)) {
        throw new Error(JWT.#decodeErrorMessage)
      }
      Validator.Validator.validateVersion(payload.version, tokenData.version)
      Validator.Validator.checkExpiration(payload.exp)
      if (payload.exp !== tokenData.exp || payload.iat !== tokenData.iat) {
        throw new Error(JWT.#decodeErrorMessage)
      }
      return payload.data
    } catch (err) {
      throw err instanceof Error && err.message === JWT.#decodeErrorMessage
        ? err
        : new Error(JWT.#decodeErrorMessage)
    }
  }

  /**
   * Sign payload and return token.
   * @description Encrypts with exp/iat/version; returns base64 token.
   * @param payloadData - User data to embed in token
   * @returns Base64-encoded signed token
   * @throws {Error} When data null/undefined or cipher fails
   */
  async sign(payloadData: unknown): Promise<string> {
    Validator.Validator.validateData(payloadData)
    const currentUnixTime = Helper.Helper.currentUnixSeconds()
    const expiresAtUnix = currentUnixTime + Math.ceil(this.#expireInMs / 1000)
    const payload: Types.PayloadData = {
      data: payloadData,
      exp: expiresAtUnix,
      iat: currentUnixTime,
      version: this.#version
    }
    const payloadString = JSON.stringify(payload)
    const tokenEncrypted: Types.TokenEncrypted = await this.#cipher.encrypt(
      payloadString,
      this.#secret,
      this.#keySizeBytes,
      this.#issuer,
      this.#version
    )
    const tokenData: Types.TokenData = {
      encrypted: tokenEncrypted.encrypted,
      iv: tokenEncrypted.iv,
      tag: tokenEncrypted.tag,
      exp: expiresAtUnix,
      iat: currentUnixTime,
      version: this.#version
    }
    const tokenString = JSON.stringify(tokenData)
    return btoa(tokenString)
  }

  /**
   * Verify token without returning payload.
   * @description Returns true if decode succeeds, false otherwise.
   * @param token - Base64-encoded token string
   * @returns True when valid and not expired
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
 * Re-export public types.
 * @description Exposes Types module for consumers.
 */
export * from '@app/Types.ts'
