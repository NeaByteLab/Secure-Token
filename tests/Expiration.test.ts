import { assert, assertEquals, assertRejects } from '@std/assert'
import { delay } from '@std/async'
import JWT from '@app/index.ts'

Deno.test('Expiration - token should be valid before expiry', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const token = await jwt.sign({ data: 'test' })
  const isValid = await jwt.verify(token)
  assert(isValid)
})

Deno.test('Expiration - expired token should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1s',
    version: '1.0.0'
  })
  const token = await jwt.sign({ data: 'test' })
  await delay(1200)
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Token expired'
  )
})

Deno.test('Expiration - expired token verify returns false', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1s',
    version: '1.0.0'
  })
  const token = await jwt.sign({ data: 'test' })
  await delay(1200)
  const isValid = await jwt.verify(token)
  const shouldBeInvalid = false
  assertEquals(isValid, shouldBeInvalid)
})

Deno.test('Expiration - token exp matches expected time', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '30m',
    version: '1.0.0'
  })
  const token = await jwt.sign({ data: 'test' })
  const decoded = atob(token)
  const tokenData = JSON.parse(decoded)
  const now = Math.floor(Date.now() / 1000)
  assertEquals(tokenData.exp - now, 1800)
})
