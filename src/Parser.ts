import type { TimeUnit } from '@app/Types.ts'

/**
 * Parses a compact time string into a structured unit.
 * @param timeString - String like '1h', '30m', '7d', '500ms'
 * @returns Parsed time unit with value and unit
 * @throws {Error} When the format is invalid or value non-positive
 */
export function parseTimeString(timeString: string): TimeUnit {
  const timeRegex = /^(\d+)(ms|s|m|h|d|M|y)$/
  const match = timeRegex.exec(timeString.trim())
  if (!match || match.length < 3 || !match[1] || !match[2]) {
    throw new Error(`Invalid time format: ${timeString}. Expected format: '1h', '30m', '7d', etc.`)
  }
  const value = parseInt(match[1], 10)
  const unit = match[2] as TimeUnit['unit']
  if (value <= 0) {
    throw new Error(`Time value must be positive: ${timeString}`)
  }
  return { value, unit }
}

/**
 * Converts a compact time string to milliseconds.
 * @param timeString - String like '1h', '30m', '7d', '500ms'
 * @returns Milliseconds represented by the input
 * @throws {Error} When the string is invalid or exceeds max duration
 */
export function parseTimeToMs(timeString: string): number {
  if (typeof timeString !== 'string' || timeString.length === 0) {
    throw new Error('Time string must be a non-empty string')
  }
  const timeUnit = parseTimeString(timeString)
  const milliseconds = timeToMs(timeUnit)
  const maxExpirationMs = 365 * 24 * 60 * 60 * 1000
  if (milliseconds > maxExpirationMs) {
    throw new Error(`Time value too large (max 1 year): ${timeString}`)
  }
  return milliseconds
}

/**
 * Converts a structured time unit to milliseconds.
 * @param timeUnit - Parsed time unit with value and unit
 * @returns Milliseconds represented by the unit
 * @throws {Error} When the time unit is unsupported
 */
export function timeToMs(timeUnit: TimeUnit): number {
  const { value, unit } = timeUnit
  switch (unit) {
    case 'ms':
      return value
    case 's':
      return value * 1000
    case 'm':
      return value * 60 * 1000
    case 'h':
      return value * 60 * 60 * 1000
    case 'd':
      return value * 24 * 60 * 60 * 1000
    case 'M':
      return value * 30 * 24 * 60 * 60 * 1000
    case 'y':
      return value * 365 * 24 * 60 * 60 * 1000
    default:
      throw new Error(`Unsupported time unit: ${unit}`)
  }
}
