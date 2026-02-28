import { assert, assertEquals, assertExists } from '@std/assert'
import JWT from '@app/index.ts'

Deno.test('JWT - create instance', () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  assertExists(jwt)
})

Deno.test('JWT - custom cipher is used when provided', async () => {
  const plaintexts: string[] = []
  // Mock ignores secret/issuer for simplicity; production cipher must use them for isolation.
  const customCipher = {
    encrypt: (plaintext: string) => {
      plaintexts.push(plaintext)
      return Promise.resolve({
        encrypted: 'ee',
        iv: '112233445566778899aabbcc',
        tag: '00112233445566778899aabbccddeeff'
      })
    },
    decrypt: () => Promise.resolve(plaintexts[0] ?? '{}')
  }
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0',
    cipher: customCipher as import('@app/Types.ts').Cipher
  })
  const data = { custom: true }
  const token = await jwt.sign(data)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, data)
})

Deno.test('JWT - instance with aes-256-gcm', async () => {
  const jwt = new JWT({
    secret: 'test-secret-32-bytes-long!!!!!!',
    expireIn: '1h',
    version: '1.0.0',
    algorithm: 'aes-256-gcm'
  })
  const data = { role: 'admin' }
  const token = await jwt.sign(data)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, data)
})

Deno.test('JWT - instance with custom issuer', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0',
    issuer: 'my-app'
  })
  const data = { userId: 1 }
  const token = await jwt.sign(data)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, data)
})

Deno.test('JWT - sign and decode object', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const data = { userId: 123, role: 'admin' }
  const token = await jwt.sign(data)
  assertExists(token)
  assertEquals(typeof token, 'string')
  const decoded = await jwt.decode(token)
  assertEquals(decoded, data)
})

Deno.test('JWT - sign and verify', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const data = { userId: 123 }
  const token = await jwt.sign(data)
  const isValid = await jwt.verify(token)
  assert(isValid)
})

Deno.test('JWT - token is base64 encoded', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const token = await jwt.sign({ data: 'test' })
  const base64Regex = /^[A-Za-z0-9+/=]+$/
  assert(base64Regex.test(token))
})

Deno.test('JWT - verify returns false for empty token', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const isValid = await jwt.verify('')
  assertEquals(isValid, false)
})

Deno.test('JWT - verify returns false for garbage token', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const isValid = await jwt.verify('not-valid-base64!!!')
  assertEquals(isValid, false)
})

Deno.test('JWT - verify returns false for tampered token', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const token = await jwt.sign({ x: 1 })
  const tampered = token.slice(0, -2) + 'XX'
  const isValid = await jwt.verify(tampered)
  assertEquals(isValid, false)
})
