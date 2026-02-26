import { assertEquals, assertThrows } from '@std/assert'
import { Parser } from '@app/Parser.ts'

Deno.test('Parser - parseTimeString invalid format', () => {
  assertThrows(
    () => {
      Parser.parseTimeString('invalid')
    },
    Error,
    'Invalid time format'
  )
})

Deno.test('Parser - parseTimeString invalid unit', () => {
  assertThrows(
    () => {
      Parser.parseTimeString('1x')
    },
    Error,
    'Invalid time format'
  )
})

Deno.test('Parser - parseTimeString negative value', () => {
  assertThrows(
    () => {
      Parser.parseTimeString('-1h')
    },
    Error,
    'Invalid time format'
  )
})

Deno.test('Parser - parseTimeString trims whitespace', () => {
  const result = Parser.parseTimeString('  2m  ')
  assertEquals(result, { value: 2, unit: 'm' })
})

Deno.test('Parser - parseTimeString zero value throws', () => {
  assertThrows(
    () => {
      Parser.parseTimeString('0h')
    },
    Error,
    'Time value must be positive'
  )
})

Deno.test('Parser - parseTimeToMs empty string', () => {
  assertThrows(
    () => {
      Parser.parseTimeToMs('')
    },
    Error,
    'Time string must be a non-empty string'
  )
})

Deno.test('Parser - parseTimeToMs non-string throws', () => {
  assertThrows(
    () => {
      Parser.parseTimeToMs(1 as unknown as string)
    },
    Error,
    'Time string must be a non-empty string'
  )
})

Deno.test('Parser - parseTimeToMs too large', () => {
  assertThrows(
    () => {
      Parser.parseTimeToMs('2y')
    },
    Error,
    'Time value too large'
  )
})

Deno.test('Parser - parseTimeToMs with days', () => {
  const result = Parser.parseTimeToMs('7d')
  assertEquals(result, 7 * 24 * 60 * 60 * 1000)
})

Deno.test('Parser - parseTimeToMs with hours', () => {
  const result = Parser.parseTimeToMs('2h')
  assertEquals(result, 2 * 60 * 60 * 1000)
})

Deno.test('Parser - parseTimeToMs with milliseconds', () => {
  const result = Parser.parseTimeToMs('100ms')
  assertEquals(result, 100)
})

Deno.test('Parser - parseTimeToMs with minutes', () => {
  const result = Parser.parseTimeToMs('5m')
  assertEquals(result, 5 * 60 * 1000)
})

Deno.test('Parser - parseTimeToMs with months', () => {
  const result = Parser.parseTimeToMs('1M')
  assertEquals(result, 30 * 24 * 60 * 60 * 1000)
})

Deno.test('Parser - parseTimeToMs with seconds', () => {
  const result = Parser.parseTimeToMs('30s')
  assertEquals(result, 30000)
})

Deno.test('Parser - parseTimeToMs with trimmed string', () => {
  const result = Parser.parseTimeToMs('  5s  ')
  assertEquals(result, 5000)
})

Deno.test('Parser - parseTimeToMs with years', () => {
  const result = Parser.parseTimeToMs('1y')
  assertEquals(result, 365 * 24 * 60 * 60 * 1000)
})

Deno.test('Parser - timeToMs all units', () => {
  assertEquals(Parser.timeToMs({ value: 1, unit: 'ms' }), 1)
  assertEquals(Parser.timeToMs({ value: 1, unit: 's' }), 1000)
  assertEquals(Parser.timeToMs({ value: 1, unit: 'm' }), 60000)
  assertEquals(Parser.timeToMs({ value: 1, unit: 'h' }), 3600000)
  assertEquals(Parser.timeToMs({ value: 1, unit: 'd' }), 86400000)
  assertEquals(Parser.timeToMs({ value: 1, unit: 'M' }), 2592000000)
  assertEquals(Parser.timeToMs({ value: 1, unit: 'y' }), 31536000000)
})
