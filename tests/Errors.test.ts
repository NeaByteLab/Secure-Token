import type { JWTOptions } from '@app/Types.ts'
import { assertRejects, assertThrows } from '@std/assert'
import JWT from '@app/index.ts'

Deno.test('Errors - empty secret should fail', () => {
  assertThrows(
    () => {
      new JWT({
        secret: '',
        algorithm: 'aes-128-gcm',
        expireIn: '1h',
        version: '1.0.0'
      })
    },
    Error,
    'Secret must be a non-empty string'
  )
})

Deno.test('Errors - null options should fail', () => {
  assertThrows(
    () => {
      new JWT(null as unknown as JWTOptions)
    },
    Error,
    'Options must be an object'
  )
})

Deno.test('Errors - null data should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  await assertRejects(
    async () => {
      await jwt.sign(null)
    },
    Error,
    'Data cannot be null or undefined'
  )
})

Deno.test('Errors - undefined data should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  await assertRejects(
    async () => {
      await jwt.sign(undefined)
    },
    Error,
    'Data cannot be null or undefined'
  )
})

Deno.test('Errors - invalid token format should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  await assertRejects(async () => {
    await jwt.decode('not-a-valid-token')
  }, Error)
})

Deno.test('Errors - invalid base64 should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  await assertRejects(async () => {
    await jwt.decode('invalid-base64!!!')
  }, Error)
})

Deno.test('Errors - invalid JSON in token should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const invalidJson = btoa('not valid json')
  await assertRejects(
    async () => {
      await jwt.decode(invalidJson)
    },
    Error,
    'Invalid token format'
  )
})

Deno.test('Errors - invalid token structure should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const invalidStructure = btoa(JSON.stringify({ test: 'data' }))
  await assertRejects(
    async () => {
      await jwt.decode(invalidStructure)
    },
    Error,
    'Invalid token structure'
  )
})
