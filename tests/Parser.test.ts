import { assertEquals, assertThrows } from '@std/assert'
import { parseTimeString, parseTimeToMs, timeToMs } from '@app/Parser.ts'

Deno.test('Parser - parseTimeToMs with milliseconds', () => {
  const result = parseTimeToMs('100ms')
  assertEquals(result, 100)
})

Deno.test('Parser - parseTimeToMs with seconds', () => {
  const result = parseTimeToMs('30s')
  assertEquals(result, 30000)
})

Deno.test('Parser - parseTimeToMs with minutes', () => {
  const result = parseTimeToMs('5m')
  assertEquals(result, 5 * 60 * 1000)
})

Deno.test('Parser - parseTimeToMs with hours', () => {
  const result = parseTimeToMs('2h')
  assertEquals(result, 2 * 60 * 60 * 1000)
})

Deno.test('Parser - parseTimeToMs with days', () => {
  const result = parseTimeToMs('7d')
  assertEquals(result, 7 * 24 * 60 * 60 * 1000)
})

Deno.test('Parser - parseTimeToMs with months', () => {
  const result = parseTimeToMs('1M')
  assertEquals(result, 30 * 24 * 60 * 60 * 1000)
})

Deno.test('Parser - parseTimeToMs with years', () => {
  const result = parseTimeToMs('1y')
  assertEquals(result, 365 * 24 * 60 * 60 * 1000)
})

Deno.test('Parser - parseTimeString invalid format', () => {
  assertThrows(
    () => {
      parseTimeString('invalid')
    },
    Error,
    'Invalid time format'
  )
})

Deno.test('Parser - parseTimeString negative value', () => {
  assertThrows(
    () => {
      parseTimeString('-1h')
    },
    Error,
    'Invalid time format'
  )
})

Deno.test('Parser - parseTimeToMs empty string', () => {
  assertThrows(
    () => {
      parseTimeToMs('')
    },
    Error,
    'Time string must be a non-empty string'
  )
})

Deno.test('Parser - parseTimeToMs too large', () => {
  assertThrows(
    () => {
      parseTimeToMs('2y')
    },
    Error,
    'Time value too large'
  )
})

Deno.test('Parser - timeToMs all units', () => {
  assertEquals(timeToMs({ value: 1, unit: 'ms' }), 1)
  assertEquals(timeToMs({ value: 1, unit: 's' }), 1000)
  assertEquals(timeToMs({ value: 1, unit: 'm' }), 60000)
  assertEquals(timeToMs({ value: 1, unit: 'h' }), 3600000)
  assertEquals(timeToMs({ value: 1, unit: 'd' }), 86400000)
  assertEquals(timeToMs({ value: 1, unit: 'M' }), 2592000000)
  assertEquals(timeToMs({ value: 1, unit: 'y' }), 31536000000)
})
