/**
 * Encrypt/decrypt contract for token cipher.
 * @description Pluggable cipher implementation interface.
 */
export interface Cipher {
  /**
   * Decrypt token envelope to plaintext.
   * @description Decodes hex and verifies tag.
   * @param token - Encrypted envelope
   * @param secret - Shared secret
   * @param keySizeBytes - 16 or 32
   * @param issuer - Issuer for AAD
   * @param version - Version for AAD
   * @returns Decrypted plaintext string
   */
  decrypt(
    token: TokenEncrypted,
    secret: string,
    keySizeBytes: 16 | 32,
    issuer: string,
    version: string
  ): Promise<string>
  /**
   * Encrypt plaintext to token envelope.
   * @description Produces encrypted hex, IV, and tag.
   * @param plaintext - String to encrypt
   * @param secret - Shared secret
   * @param keySizeBytes - 16 or 32
   * @param issuer - Issuer for AAD
   * @param version - Version for AAD
   * @returns Encrypted envelope with iv and tag
   */
  encrypt(
    plaintext: string,
    secret: string,
    keySizeBytes: 16 | 32,
    issuer: string,
    version: string
  ): Promise<TokenEncrypted>
}

/** Supported AES-GCM algorithm names. */
export type EncryptionAlgo = 'aes-128-gcm' | 'aes-256-gcm'

/**
 * JWT constructor and runtime options.
 * @description Config for signing, expiry, and cipher.
 */
export interface JWTOptions {
  /** Algorithm name for key size */
  algorithm?: EncryptionAlgo
  /** Custom encrypt/decrypt implementation */
  cipher?: Cipher
  /** Expiration duration e.g. 1h, 7d */
  expireIn: string
  /** Issuer identifier in AAD */
  issuer?: string
  /** Shared secret for key derivation */
  secret: string
  /** Version string for AAD and validation */
  version: string
}

/**
 * Signed payload with timestamps and version.
 * @description Decrypted payload shape for validation.
 */
export interface PayloadData {
  /** User payload */
  data: unknown
  /** Expiration Unix timestamp */
  exp: number
  /** Issued-at Unix timestamp */
  iat: number
  /** Payload version string */
  version: string
}

/**
 * Parsed time value and unit.
 * @description Result of parseTimeString.
 */
export interface TimeUnit {
  /** Unit: ms, s, m, h, d, M, y */
  unit: 'ms' | 's' | 'm' | 'h' | 'd' | 'M' | 'y'
  /** Numeric amount */
  value: number
}

/**
 * Decoded token envelope (encrypted + metadata).
 * @description Base64-decoded token shape before decrypt.
 */
export interface TokenData {
  /** Ciphertext in hex */
  encrypted: string
  /** Expiration Unix timestamp */
  exp: number
  /** Issued-at Unix timestamp */
  iat: number
  /** IV in hex */
  iv: string
  /** Auth tag in hex */
  tag: string
  /** Token version string */
  version: string
}

/**
 * Encrypted payload plus IV and tag.
 * @description Output of encrypt; input to decrypt.
 */
export interface TokenEncrypted {
  /** Ciphertext in hex */
  encrypted: string
  /** IV in hex */
  iv: string
  /** Auth tag in hex */
  tag: string
}
