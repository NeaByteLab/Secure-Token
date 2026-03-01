import { assert, assertEquals, assertThrows } from '@std/assert'
import type * as Types from '@app/Types.ts'
import { Validator } from '@app/Validator.ts'

Deno.test('Validator - checkExpiration with expired token', () => {
  const expiredTime = Math.floor(Date.now() / 1000) - 10
  assertThrows(
    () => {
      Validator.checkExpiration(expiredTime)
    },
    Error,
    'Token expired'
  )
})

Deno.test('Validator - checkExpiration with future time does not throw', () => {
  const futureTime = Math.floor(Date.now() / 1000) + 3600
  Validator.checkExpiration(futureTime)
})

Deno.test('Validator - checkExpiration with NaN throws', () => {
  assertThrows(() => Validator.checkExpiration(NaN), Error, 'Invalid expiration')
})

Deno.test('Validator - checkExpiration with Infinity throws', () => {
  assertThrows(() => Validator.checkExpiration(Infinity), Error, 'Invalid expiration')
})

Deno.test('Validator - isValidPayload with exp NaN returns false', () => {
  const payload = {
    data: {},
    exp: NaN,
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  assertEquals(Validator.isValidPayload(payload), false)
})

Deno.test('Validator - isValidPayload with exp Infinity returns false', () => {
  const payload = {
    data: {},
    exp: Infinity,
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  assertEquals(Validator.isValidPayload(payload), false)
})

Deno.test('Validator - isValidPayload with empty object returns false', () => {
  assertEquals(Validator.isValidPayload({}), false)
})

Deno.test('Validator - isValidToken with exp NaN returns false', () => {
  const tokenData = {
    encrypted: 'e',
    iv: '0'.repeat(24),
    tag: '0'.repeat(32),
    exp: NaN,
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  assertEquals(Validator.isValidToken(tokenData), false)
})

Deno.test('Validator - isValidToken with exp Infinity returns false', () => {
  const tokenData = {
    encrypted: 'e',
    iv: '0'.repeat(24),
    tag: '0'.repeat(32),
    exp: Infinity,
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  assertEquals(Validator.isValidToken(tokenData), false)
})

Deno.test('Validator - isValidPayload rejects empty object under prototype pollution', () => {
  const future = Math.floor(Date.now() / 1000) + 3600
  const proto = Object.getPrototypeOf({}) as Record<string, unknown>
  proto['data'] = {}
  proto['exp'] = future
  proto['iat'] = Math.floor(Date.now() / 1000)
  proto['version'] = '1.0.0'
  try {
    assertEquals(Validator.isValidPayload({}), false)
  } finally {
    delete proto['data']
    delete proto['exp']
    delete proto['iat']
    delete proto['version']
  }
})

Deno.test('Validator - isValidPayload with exp as string', () => {
  const payloadData = {
    data: {},
    exp: '123',
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  const result = Validator.isValidPayload(payloadData)
  assertEquals(result, false)
})

Deno.test('Validator - isValidPayload with invalid data', () => {
  const invalidPayloadData = {
    test: 'data'
  }
  const result = Validator.isValidPayload(invalidPayloadData)
  const shouldBeFalse = false
  assertEquals(result, shouldBeFalse)
})

Deno.test('Validator - isValidPayload with missing data', () => {
  const payloadData = {
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  const result = Validator.isValidPayload(payloadData)
  assertEquals(result, false)
})

Deno.test('Validator - isValidPayload with valid data', () => {
  const validPayloadData: Types.PayloadData = {
    data: { test: 'data' },
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  const result = Validator.isValidPayload(validPayloadData)
  assert(result)
})

Deno.test('Validator - isValidToken with exp as string', () => {
  const tokenData = {
    encrypted: 'e',
    iv: 'i',
    tag: 't',
    exp: '123',
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  const result = Validator.isValidToken(tokenData)
  assertEquals(result, false)
})

Deno.test('Validator - isValidToken with invalid data', () => {
  const invalidTokenData = {
    test: 'data'
  }
  const result = Validator.isValidToken(invalidTokenData)
  const shouldBeFalse = false
  assertEquals(result, shouldBeFalse)
})

Deno.test('Validator - isValidToken with missing encrypted', () => {
  const tokenData = {
    iv: 'i',
    tag: 't',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  const result = Validator.isValidToken(tokenData)
  assertEquals(result, false)
})

Deno.test('Validator - isValidToken with valid data', () => {
  const validTokenData: Types.TokenData = {
    encrypted: 'test',
    iv: 'test',
    tag: 'test',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  const result = Validator.isValidToken(validTokenData)
  assert(result)
})

Deno.test('Validator - validateData with null', () => {
  assertThrows(
    () => {
      Validator.validateData(null)
    },
    Error,
    'Data cannot be null or undefined'
  )
})

Deno.test('Validator - validateData with undefined', () => {
  assertThrows(
    () => {
      Validator.validateData(undefined)
    },
    Error,
    'Data cannot be null or undefined'
  )
})

Deno.test('Validator - validateOptions with null', () => {
  assertThrows(
    () => {
      Validator.validateOptions(null)
    },
    Error,
    'Options must be an object'
  )
})

Deno.test('Validator - validateOptions with number', () => {
  assertThrows(
    () => {
      Validator.validateOptions(42 as unknown as object)
    },
    Error,
    'Options must be an object'
  )
})

Deno.test('Validator - validateOptions with string', () => {
  assertThrows(
    () => {
      Validator.validateOptions('options' as unknown as object)
    },
    Error,
    'Options must be an object'
  )
})

Deno.test('Validator - validateOptions with undefined', () => {
  assertThrows(
    () => {
      Validator.validateOptions(undefined)
    },
    Error,
    'Options must be an object'
  )
})

Deno.test('Validator - validateRequiredOptionsOwn rejects missing required key', () => {
  assertThrows(
    () =>
      Validator.validateRequiredOptionsOwn({ secret: 'x', version: '1' }, [
        'secret',
        'version',
        'expireIn'
      ]),
    Error,
    'own property: expireIn'
  )
})

Deno.test('Validator - validateRequiredOptionsOwn rejects inherited key', () => {
  const proto = { secret: 'x', version: '1', expireIn: '1h' }
  const opts = Object.create(proto)
  assertThrows(
    () =>
      Validator.validateRequiredOptionsOwn(opts as Record<string, unknown>, [
        'secret',
        'version',
        'expireIn'
      ]),
    Error,
    'own property: secret'
  )
})

Deno.test('Validator - validateRequiredOptionsOwn accepts all own keys', () => {
  Validator.validateRequiredOptionsOwn({ secret: 'x', version: '1', expireIn: '1h' }, [
    'secret',
    'version',
    'expireIn'
  ])
})

Deno.test('Validator - validateSecret with empty string', () => {
  assertThrows(
    () => {
      Validator.validateSecret('')
    },
    Error,
    'Secret must be a non-empty string'
  )
})

Deno.test('Validator - validateSecret with non-string', () => {
  assertThrows(
    () => {
      Validator.validateSecret(123 as unknown as string)
    },
    Error,
    'Secret must be a non-empty string'
  )
})

Deno.test('Validator - validateToken with empty string', () => {
  assertThrows(
    () => {
      Validator.validateToken('')
    },
    Error,
    'Token must be a non-empty string'
  )
})

Deno.test('Validator - validateToken with null', () => {
  assertThrows(
    () => {
      Validator.validateToken(null as unknown as string)
    },
    Error,
    'Token must be a non-empty string'
  )
})

Deno.test('Validator - validateToken with non-string', () => {
  assertThrows(
    () => {
      Validator.validateToken(123 as unknown as string)
    },
    Error,
    'Token must be a non-empty string'
  )
})

Deno.test('Validator - validateVersion mismatch', () => {
  assertThrows(
    () => {
      Validator.validateVersion('1.0.0', '2.0.0')
    },
    Error,
    'Version mismatch'
  )
})

Deno.test('Validator - validateVersion same version does not throw', () => {
  Validator.validateVersion('1.0.0', '1.0.0')
})
