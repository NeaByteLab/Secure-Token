/**
 * Shared utilities for time and errors.
 * @description Unix time and error normalization.
 */
export class Helper {
  /**
   * Current time as Unix seconds.
   * @description Floor of Date.now() / 1000.
   * @returns Current Unix timestamp in seconds
   */
  static currentUnixSeconds(): number {
    return Math.floor(Date.now() / 1000)
  }

  /**
   * Normalize unknown to Error instance.
   * @description Returns Error or wraps non-Error in Error.
   * @param err - Caught value to normalize
   * @returns Error instance
   */
  static normalizeToError(err: unknown): Error {
    return err instanceof Error ? err : new Error('Unknown error')
  }
}
