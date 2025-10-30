import type { PayloadData, TokenData } from '@app/Types.ts'

/**
 * Ensures expiration timestamp is in the future.
 * @param exp - Expiration timestamp (seconds since epoch)
 * @returns Void
 * @throws {Error} When the token is expired
 */
export function checkExpiration(exp: number): void {
  const now = Math.floor(Date.now() / 1000)
  if (exp <= now) {
    throw new Error(`Token expired at ${new Date(exp * 1000).toISOString()}`)
  }
}

/**
 * Type guard validating payload structure.
 * @param payload - Value to validate
 * @returns True when payload matches expected shape
 */
export function isValidPayload(payload: unknown): payload is PayloadData {
  return (
    typeof payload === 'object' &&
    payload !== null &&
    'data' in payload &&
    'exp' in payload &&
    'iat' in payload &&
    'version' in payload &&
    typeof (payload as PayloadData).exp === 'number' &&
    typeof (payload as PayloadData).iat === 'number' &&
    typeof (payload as PayloadData).version === 'string'
  )
}

/**
 * Type guard validating token structure.
 * @param tokenData - Value to validate
 * @returns True when token matches expected shape
 */
export function isValidToken(tokenData: unknown): tokenData is TokenData {
  return (
    typeof tokenData === 'object' &&
    tokenData !== null &&
    'encrypted' in tokenData &&
    'iv' in tokenData &&
    'tag' in tokenData &&
    'exp' in tokenData &&
    'iat' in tokenData &&
    'version' in tokenData &&
    typeof (tokenData as TokenData).encrypted === 'string' &&
    typeof (tokenData as TokenData).iv === 'string' &&
    typeof (tokenData as TokenData).tag === 'string' &&
    typeof (tokenData as TokenData).exp === 'number' &&
    typeof (tokenData as TokenData).iat === 'number' &&
    typeof (tokenData as TokenData).version === 'string'
  )
}

/**
 * Validates that data exists.
 * @param data - Data to validate
 * @returns Void
 * @throws {Error} When null or undefined
 */
export function validateData(data: unknown): void {
  if (data === null || data === undefined) {
    throw new Error('Data cannot be null or undefined')
  }
}

/**
 * Validates the options object.
 * @param options - Options to validate
 * @returns Void
 * @throws {Error} When not a non-null object
 */
export function validateOptions(options: unknown): void {
  if (options === null || options === undefined || typeof options !== 'object') {
    throw new Error('Options must be an object')
  }
}

/**
 * Validates the secret string.
 * @param secret - Secret to validate
 * @returns Void
 * @throws {Error} When not a non-empty string
 */
export function validateSecret(secret: unknown): void {
  if (typeof secret !== 'string' || secret.length === 0) {
    throw new Error('Secret must be a non-empty string')
  }
}

/**
 * Validates the token string.
 * @param token - Token to validate
 * @returns Void
 * @throws {Error} When not a non-empty string
 */
export function validateToken(token: unknown): void {
  if (typeof token !== 'string' || token.length === 0) {
    throw new Error('Token must be a non-empty string')
  }
}

/**
 * Validates that two versions are identical.
 * @param version1 - First version
 * @param version2 - Second version
 * @returns Void
 * @throws {Error} When versions do not match
 */
export function validateVersion(version1: string, version2: string): void {
  if (version1 !== version2) {
    throw new Error(
      `Version mismatch: token version ${version1} does not match instance version ${version2}`
    )
  }
}
