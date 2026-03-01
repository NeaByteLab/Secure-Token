import { assert, assertEquals, assertExists, assertThrows } from '@std/assert'
import JWT from '@app/index.ts'
import type * as Types from '@app/Types.ts'

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
  const customCipher: Types.Cipher = {
    encrypt: (
      plaintext: string,
      _secret: string,
      _keySizeBytes: 16 | 32,
      _issuer: string,
      _version: string
    ) => {
      plaintexts.push(plaintext)
      return Promise.resolve({
        encrypted: 'ee',
        iv: '112233445566778899aabbcc',
        tag: '00112233445566778899aabbccddeeff'
      })
    },
    decrypt: (
      _token: Types.TokenEncrypted,
      _secret: string,
      _keySizeBytes: 16 | 32,
      _issuer: string,
      _version: string
    ) => Promise.resolve(plaintexts[0] ?? '{}')
  }
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0',
    cipher: customCipher
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

Deno.test('JWT - constructor rejects options with only inherited required keys', () => {
  const proto = { secret: 'from-proto', version: '1.0.0', expireIn: '1h' }
  const options = Object.create(proto) as import('@app/Types.ts').JWTOptions
  assertThrows(() => new JWT(options), Error, 'own property: secret')
})

Deno.test('JWT - constructor ignores prototype cipher when options has no own cipher', async () => {
  const maliciousDecoded: unknown[] = []
  const proto = {
    cipher: {
      encrypt: (
        _plaintext: string,
        _secret: string,
        _keySizeBytes: 16 | 32,
        _issuer: string,
        _version: string
      ) =>
        Promise.resolve({
          encrypted: 'evil',
          iv: '0'.repeat(24),
          tag: '0'.repeat(32)
        }),
      decrypt: (
        _token: Types.TokenEncrypted,
        _secret: string,
        _keySizeBytes: 16 | 32,
        _issuer: string,
        _version: string
      ) => {
        maliciousDecoded.push('decrypt-called')
        return Promise.resolve(
          JSON.stringify({
            data: { injected: true },
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
            version: '1.0.0'
          })
        )
      }
    } satisfies Types.Cipher
  }
  const options = Object.create(proto) as Record<string, unknown>
  options['secret'] = 'own-secret'
  options['version'] = '1.0.0'
  options['expireIn'] = '1h'
  const jwt = new JWT(options as unknown as Types.JWTOptions)
  const token = await jwt.sign({ real: true })
  const decoded = await jwt.decode(token)
  assertEquals(decoded, { real: true })
  assertEquals(maliciousDecoded.length, 0)
})
