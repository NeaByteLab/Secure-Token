import { assert, assertEquals, assertThrows } from '@std/assert'
import {
  checkExpiration,
  isValidPayload,
  isValidToken,
  validateData,
  validateOptions,
  validateSecret,
  validateToken,
  validateVersion
} from '@app/Validator.ts'
import type { PayloadData, TokenData } from '@app/Types.ts'

Deno.test('Validator - validateOptions with null', () => {
  assertThrows(
    () => {
      validateOptions(null)
    },
    Error,
    'Options must be an object'
  )
})

Deno.test('Validator - validateOptions with undefined', () => {
  assertThrows(
    () => {
      validateOptions(undefined)
    },
    Error,
    'Options must be an object'
  )
})

Deno.test('Validator - validateSecret with empty string', () => {
  assertThrows(
    () => {
      validateSecret('')
    },
    Error,
    'Secret must be a non-empty string'
  )
})

Deno.test('Validator - validateSecret with non-string', () => {
  assertThrows(
    () => {
      validateSecret(123 as unknown as string)
    },
    Error,
    'Secret must be a non-empty string'
  )
})

Deno.test('Validator - validateData with null', () => {
  assertThrows(
    () => {
      validateData(null)
    },
    Error,
    'Data cannot be null or undefined'
  )
})

Deno.test('Validator - validateData with undefined', () => {
  assertThrows(
    () => {
      validateData(undefined)
    },
    Error,
    'Data cannot be null or undefined'
  )
})

Deno.test('Validator - validateToken with empty string', () => {
  assertThrows(
    () => {
      validateToken('')
    },
    Error,
    'Token must be a non-empty string'
  )
})

Deno.test('Validator - checkExpiration with expired token', () => {
  const expiredTime = Math.floor(Date.now() / 1000) - 10
  assertThrows(
    () => {
      checkExpiration(expiredTime)
    },
    Error,
    'Token expired'
  )
})

Deno.test('Validator - checkExpiration with current time', () => {
  const currentTime = Math.floor(Date.now() / 1000)
  assertThrows(
    () => {
      checkExpiration(currentTime)
    },
    Error,
    'Token expired'
  )
})

Deno.test('Validator - validateVersion mismatch', () => {
  assertThrows(
    () => {
      validateVersion('1.0.0', '2.0.0')
    },
    Error,
    'Version mismatch'
  )
})

Deno.test('Validator - isValidToken with valid data', () => {
  const validTokenData: TokenData = {
    encrypted: 'test',
    iv: 'test',
    tag: 'test',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  const result = isValidToken(validTokenData)
  assert(result)
})

Deno.test('Validator - isValidToken with invalid data', () => {
  const invalidTokenData = {
    test: 'data'
  }
  const result = isValidToken(invalidTokenData)
  const shouldBeFalse = false
  assertEquals(result, shouldBeFalse)
})

Deno.test('Validator - isValidPayload with valid data', () => {
  const validPayloadData: PayloadData = {
    data: { test: 'data' },
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  const result = isValidPayload(validPayloadData)
  assert(result)
})

Deno.test('Validator - isValidPayload with invalid data', () => {
  const invalidPayloadData = {
    test: 'data'
  }
  const result = isValidPayload(invalidPayloadData)
  const shouldBeFalse = false
  assertEquals(result, shouldBeFalse)
})
