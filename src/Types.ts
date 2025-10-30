/**
 * Supported encryption algorithms.
 */
export type EncryptionAlgo = 'aes-128-gcm' | 'aes-256-gcm'

/**
 * Options for creating a JWT instance.
 */
export interface JWTOptions {
  /** The encryption algorithm to use */
  algorithm?: EncryptionAlgo
  /** The secret used to derive the encryption key */
  secret: string
  /** The issuer bound to the token */
  issuer?: string
  /** The version of the token */
  version: string
  /** The expiration time in milliseconds */
  expireIn: string
}

/**
 * Token data persisted in the final token string.
 */
export interface TokenData {
  /** The encrypted token parts */
  encrypted: string
  /** The initialization vector */
  iv: string
  /** The authentication tag */
  tag: string
  /** The expiration timestamp */
  exp: number
  /** The issued at timestamp */
  iat: number
  /** The version of the token */
  version: string
}

/**
 * Encrypted token parts produced by AES-GCM.
 */
export interface TokenEncrypted {
  /** The encrypted token parts */
  encrypted: string
  /** The initialization vector */
  iv: string
  /** The authentication tag */
  tag: string
}

/**
 * Decrypted payload structure.
 */
export interface PayloadData {
  /** The data to embed in the token payload */
  data: unknown
  /** The expiration timestamp */
  exp: number
  /** The issued at timestamp */
  iat: number
  /** The version of the token */
  version: string
}

/**
 * Parsed time unit.
 */
export interface TimeUnit {
  /** The value of the time unit */
  value: number
  /** The unit of the time unit */
  unit: 'ms' | 's' | 'm' | 'h' | 'd' | 'M' | 'y'
}
