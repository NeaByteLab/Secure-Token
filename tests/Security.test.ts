import { assertEquals, assertRejects } from '@std/assert'
import JWT from '@app/index.ts'

Deno.test('Security - wrong secret should fail', async () => {
  const jwt1 = new JWT({
    secret: 'secret1',
    expireIn: '1h',
    version: '1.0.0'
  })
  const jwt2 = new JWT({
    secret: 'secret2',
    expireIn: '1h',
    version: '1.0.0'
  })
  const token = await jwt1.sign({ data: 'test' })
  await assertRejects(
    async () => {
      await jwt2.decode(token)
    },
    Error,
    'Decryption failed'
  )
})

Deno.test('Security - wrong secret verify returns false', async () => {
  const jwt1 = new JWT({
    secret: 'secret1',
    expireIn: '1h',
    version: '1.0.0'
  })
  const jwt2 = new JWT({
    secret: 'secret2',
    expireIn: '1h',
    version: '1.0.0'
  })
  const token = await jwt1.sign({ data: 'test' })
  const isValid = await jwt2.verify(token)
  const shouldBeInvalid = false
  assertEquals(isValid, shouldBeInvalid)
})

Deno.test('Security - version mismatch should fail', async () => {
  const jwt1 = new JWT({
    secret: 'secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const jwt2 = new JWT({
    secret: 'secret',
    expireIn: '1h',
    version: '2.0.0'
  })
  const token = await jwt1.sign({ data: 'test' })
  await assertRejects(
    async () => {
      await jwt2.decode(token)
    },
    Error,
    'Version mismatch'
  )
})

Deno.test('Security - tampered token should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const token = await jwt.sign({ data: 'test' })
  const parts = token.split('')
  const tampered = parts.map((c, i) => (i === 10 ? 'X' : c)).join('')
  await assertRejects(async () => {
    await jwt.decode(tampered)
  }, Error)
})

Deno.test('Security - manually expired token should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const token = await jwt.sign({ data: 'test' })
  const parts = JSON.parse(atob(token))
  parts.exp = Math.floor(Date.now() / 1000) - 10
  const tampered = btoa(JSON.stringify(parts))
  await assertRejects(
    async () => {
      await jwt.decode(tampered)
    },
    Error,
    'Token expired'
  )
})

Deno.test('Security - timestamp mismatch should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const token = await jwt.sign({ data: 'test' })
  const parts = JSON.parse(atob(token))
  parts.iat = parts.iat + 10
  const tampered = btoa(JSON.stringify(parts))
  await assertRejects(
    async () => {
      await jwt.decode(tampered)
    },
    Error,
    'Token timestamp mismatch'
  )
})
