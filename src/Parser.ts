import type * as Types from '@app/Types.ts'

/**
 * Time string parsing and conversion.
 * @description Parses e.g. 1h, 7d and converts to ms.
 */
export class Parser {
  /**
   * Parse duration into value and unit.
   * @description Expects format like 1h, 30m, 7d.
   * @param timeString - Duration string e.g. 1h, 7d
   * @returns Parsed value and unit
   * @throws {Error} When format invalid or value non-positive
   */
  static parseTimeString(timeString: string): Types.TimeUnit {
    const timeRegex = /^(\d+)(ms|s|m|h|d|M|y)$/
    const match = timeRegex.exec(timeString.trim())
    if (!match || match.length < 3 || !match[1] || !match[2]) {
      throw new Error(
        `Invalid time format: ${timeString}. Expected format: '1h', '30m', '7d', etc.`
      )
    }
    const timeValue = parseInt(match[1], 10)
    const unit = match[2] as Types.TimeUnit['unit']
    if (timeValue <= 0) {
      throw new Error(`Time value must be positive: ${timeString}`)
    }
    return { value: timeValue, unit }
  }

  /**
   * Convert duration string to milliseconds.
   * @description Parses string and caps at one year.
   * @param timeString - Duration string e.g. 1h, 7d
   * @returns Duration in milliseconds
   * @throws {Error} When invalid or over one year
   */
  static parseTimeToMs(timeString: string): number {
    if (typeof timeString !== 'string' || timeString.length === 0) {
      throw new Error('Time string must be a non-empty string')
    }
    const timeUnit = Parser.parseTimeString(timeString)
    const milliseconds = Parser.timeToMs(timeUnit)
    const maxExpirationMs = 365 * 24 * 60 * 60 * 1000
    if (milliseconds > maxExpirationMs) {
      throw new Error(`Time value too large (max 1 year): ${timeString}`)
    }
    return milliseconds
  }

  /**
   * Convert TimeUnit to milliseconds.
   * @description Maps unit to ms multiplier.
   * @param timeUnit - Parsed value and unit
   * @returns Duration in milliseconds
   * @throws {Error} When unit unsupported
   */
  static timeToMs(timeUnit: Types.TimeUnit): number {
    const timeValue = timeUnit.value
    const timeUnitKind = timeUnit.unit
    switch (timeUnitKind) {
      case 'ms':
        return timeValue
      case 's':
        return timeValue * 1000
      case 'm':
        return timeValue * 60 * 1000
      case 'h':
        return timeValue * 60 * 60 * 1000
      case 'd':
        return timeValue * 24 * 60 * 60 * 1000
      case 'M':
        return timeValue * 30 * 24 * 60 * 60 * 1000
      case 'y':
        return timeValue * 365 * 24 * 60 * 60 * 1000
      default:
        throw new Error(`Unsupported time unit: ${timeUnitKind}`)
    }
  }
}
