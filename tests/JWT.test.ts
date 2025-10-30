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
