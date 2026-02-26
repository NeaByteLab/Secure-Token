import type * as Types from '@app/Types.ts'
import * as Helper from '@app/Helper.ts'

/**
 * Validation for options, token, and payload.
 * @description Guards and type guards for JWT flow.
 */
export class Validator {
  /**
   * Throws if token or payload expired.
   * @description Compares exp to current Unix time.
   * @param expiresAtUnix - Expiration Unix timestamp
   * @throws {Error} When expired
   */
  static checkExpiration(expiresAtUnix: number): void {
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
    return (
      typeof payload === 'object' &&
      payload !== null &&
      'data' in payload &&
      'exp' in payload &&
      'iat' in payload &&
      'version' in payload &&
      typeof (payload as Types.PayloadData).exp === 'number' &&
      typeof (payload as Types.PayloadData).iat === 'number' &&
      typeof (payload as Types.PayloadData).version === 'string'
    )
  }

  /**
   * Type guard for TokenData shape.
   * @description Checks encrypted, iv, tag, exp, iat, version.
   * @param tokenData - Value to check
   * @returns True when valid TokenData
   */
  static isValidToken(tokenData: unknown): tokenData is Types.TokenData {
    return (
      typeof tokenData === 'object' &&
      tokenData !== null &&
      'encrypted' in tokenData &&
      'iv' in tokenData &&
      'tag' in tokenData &&
      'exp' in tokenData &&
      'iat' in tokenData &&
      'version' in tokenData &&
      typeof (tokenData as Types.TokenData).encrypted === 'string' &&
      typeof (tokenData as Types.TokenData).iv === 'string' &&
      typeof (tokenData as Types.TokenData).tag === 'string' &&
      typeof (tokenData as Types.TokenData).exp === 'number' &&
      typeof (tokenData as Types.TokenData).iat === 'number' &&
      typeof (tokenData as Types.TokenData).version === 'string'
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
   * Ensure token is non-empty string.
   * @description Validates token input for decode/verify.
   * @param tokenString - Token to validate
   * @throws {Error} When empty or not string
   */
  static validateToken(tokenString: unknown): void {
    if (typeof tokenString !== 'string' || tokenString.length === 0) {
      throw new Error('Token must be a non-empty string')
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
