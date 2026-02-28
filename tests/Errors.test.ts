import { assertRejects, assertThrows } from '@std/assert'
import type * as Types from '@app/Types.ts'
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

Deno.test('Errors - empty token should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  await assertRejects(
    async () => {
      await jwt.decode('')
    },
    Error,
    'Invalid token'
  )
})

Deno.test('Errors - invalid payload format should fail', async () => {
  const badPayload = 'not valid json'
  const customCipher = {
    encrypt: () =>
      Promise.resolve({
        encrypted: 'ee',
        iv: '112233445566778899aabbcc',
        tag: '00112233445566778899aabbccddeeff'
      }),
    decrypt: () => Promise.resolve(badPayload)
  }
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0',
    cipher: customCipher as import('@app/Types.ts').Cipher
  })
  const token = await jwt.sign({ x: 1 })
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('Errors - invalid payload structure should fail', async () => {
  const badPayload = JSON.stringify({ wrong: 'shape' })
  const customCipher = {
    encrypt: () =>
      Promise.resolve({
        encrypted: 'ee',
        iv: '112233445566778899aabbcc',
        tag: '00112233445566778899aabbccddeeff'
      }),
    decrypt: () => Promise.resolve(badPayload)
  }
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0',
    cipher: customCipher as import('@app/Types.ts').Cipher
  })
  const token = await jwt.sign({ x: 1 })
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('Errors - invalid token format (base64 or JSON) should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  await assertRejects(
    async () => {
      await jwt.decode('invalid-base64!!!')
    },
    Error,
    'Invalid token'
  )
  const invalidJson = btoa('not valid json')
  await assertRejects(
    async () => {
      await jwt.decode(invalidJson)
    },
    Error,
    'Invalid token'
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
    'Invalid token'
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

Deno.test('Errors - null options should fail', () => {
  assertThrows(
    () => {
      new JWT(null as unknown as Types.JWTOptions)
    },
    Error,
    'Options must be an object'
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
