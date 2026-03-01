import type * as Types from '@app/Types.ts'
import * as Helper from '@app/Helper.ts'

/**
 * Validation for options, token, and payload.
 * @description Guards and type guards for JWT flow.
 */
export class Validator {
  /** Max token string length (DoS mitigation). */
  static readonly maxTokenLength = 512 * 1024

  /**
   * Throws if token or payload expired.
   * @description Compares exp to current Unix time.
   * @param expiresAtUnix - Expiration Unix timestamp
   * @throws {Error} When expired
   */
  static checkExpiration(expiresAtUnix: number): void {
    if (!Number.isFinite(expiresAtUnix)) {
      throw new Error('Invalid expiration')
    }
    const currentUnixTime = Helper.Helper.currentUnixSeconds()
    if (expiresAtUnix <= currentUnixTime) {
      throw new Error(`Token expired at ${new Date(expiresAtUnix * 1000).toISOString()}`)
    }
  }

  /**
   * Type guard for PayloadData shape.
   * @description Checks data, exp, iat, version types.
   * @param payload - Value to check
   * @returns True when valid PayloadData
   */
  static isValidPayload(payload: unknown): payload is Types.PayloadData {
    if (typeof payload !== 'object' || payload === null) {
      return false
    }
    const payloadRecord = payload as Record<string, unknown>
    if (
      !Object.hasOwn(payloadRecord, 'data') ||
      !Object.hasOwn(payloadRecord, 'exp') ||
      !Object.hasOwn(payloadRecord, 'iat') ||
      !Object.hasOwn(payloadRecord, 'version')
    ) {
      return false
    }
    const expirationTimestamp = payloadRecord['exp']
    const issuedAtTimestamp = payloadRecord['iat']
    return (
      typeof expirationTimestamp === 'number' &&
      Number.isFinite(expirationTimestamp) &&
      typeof issuedAtTimestamp === 'number' &&
      Number.isFinite(issuedAtTimestamp) &&
      typeof payloadRecord['version'] === 'string'
    )
  }

  /**
   * Type guard for TokenData shape.
   * @description Checks encrypted, iv, tag, exp, iat, version.
   * @param tokenData - Value to check
   * @returns True when valid TokenData
   */
  static isValidToken(tokenData: unknown): tokenData is Types.TokenData {
    if (typeof tokenData !== 'object' || tokenData === null) {
      return false
    }
    const tokenRecord = tokenData as Record<string, unknown>
    if (
      !Object.hasOwn(tokenRecord, 'encrypted') ||
      !Object.hasOwn(tokenRecord, 'iv') ||
      !Object.hasOwn(tokenRecord, 'tag') ||
      !Object.hasOwn(tokenRecord, 'exp') ||
      !Object.hasOwn(tokenRecord, 'iat') ||
      !Object.hasOwn(tokenRecord, 'version')
    ) {
      return false
    }
    const expirationTimestamp = tokenRecord['exp']
    const issuedAtTimestamp = tokenRecord['iat']
    return (
      typeof tokenRecord['encrypted'] === 'string' &&
      typeof tokenRecord['iv'] === 'string' &&
      typeof tokenRecord['tag'] === 'string' &&
      typeof expirationTimestamp === 'number' &&
      Number.isFinite(expirationTimestamp) &&
      typeof issuedAtTimestamp === 'number' &&
      Number.isFinite(issuedAtTimestamp) &&
      typeof tokenRecord['version'] === 'string'
    )
  }

  /**
   * Reject null or undefined payload data.
   * @description Ensures sign payload is defined.
   * @param payloadData - Data to validate
   * @throws {Error} When null or undefined
   */
  static validateData(payloadData: unknown): void {
    if (payloadData === null || payloadData === undefined) {
      throw new Error('Data cannot be null or undefined')
    }
  }

  /**
   * Ensure options is a non-null object.
   * @description Validates constructor options shape.
   * @param options - Options to validate
   * @throws {Error} When not object
   */
  static validateOptions(options: unknown): void {
    if (options === null || options === undefined || typeof options !== 'object') {
      throw new Error('Options must be an object')
    }
  }

  /**
   * Require required option keys as own properties (prototype-pollution safe).
   * @description In browser env, only own properties must be used for security.
   * @param options - Options object
   * @param requiredKeys - Required own property names
   * @throws {Error} When a required key is missing or not own
   */
  static validateRequiredOptionsOwn(
    options: Record<string, unknown>,
    requiredKeys: readonly string[]
  ): void {
    for (const key of requiredKeys) {
      if (!Object.hasOwn(options, key)) {
        throw new Error(`Options must include own property: ${key}`)
      }
    }
  }

  /**
   * Ensure secret is non-empty string.
   * @description Validates shared secret.
   * @param secret - Secret to validate
   * @throws {Error} When empty or not string
   */
  static validateSecret(secret: unknown): void {
    if (typeof secret !== 'string' || secret.length === 0) {
      throw new Error('Secret must be a non-empty string')
    }
  }

  /**
   * Validate token string and size limit.
   * @description Validates token input for decode/verify; rejects oversized tokens.
   * @param tokenString - Token to validate
   * @throws {Error} When empty, not string, or exceeds max length
   */
  static validateToken(tokenString: unknown): void {
    if (typeof tokenString !== 'string' || tokenString.length === 0) {
      throw new Error('Token must be a non-empty string')
    }
    if (tokenString.length > Validator.maxTokenLength) {
      throw new Error('Token too large')
    }
  }

  /**
   * Ensure token version matches instance.
   * @description Prevents cross-version decode.
   * @param tokenVersion - Version from token
   * @param instanceVersion - Version from options
   * @throws {Error} When mismatch
   */
  static validateVersion(tokenVersion: string, instanceVersion: string): void {
    if (tokenVersion !== instanceVersion) {
      throw new Error(
        `Version mismatch: token version ${tokenVersion} does not match instance version ${instanceVersion}`
      )
    }
  }
}
