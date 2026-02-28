import { assertEquals, assertRejects } from '@std/assert'
import JWT from '@app/index.ts'
import { buildContractCompliantCipher } from '@tests/CipherHelper.ts'

Deno.test('Security - aes-128 token decoded with aes-256 instance fails', async () => {
  const jwt128 = new JWT({
    secret: 'short-secret',
    expireIn: '1h',
    version: '1.0.0',
    algorithm: 'aes-128-gcm'
  })
  const jwt256 = new JWT({
    secret: 'short-secret',
    expireIn: '1h',
    version: '1.0.0',
    algorithm: 'aes-256-gcm'
  })
  const token = await jwt128.sign({ data: 'test' })
  await assertRejects(async () => {
    await jwt256.decode(token)
  }, Error)
})

Deno.test('Security - custom cipher binding issuer isolates instances', async () => {
  const cipher = buildContractCompliantCipher()
  const jwtA = new JWT({
    secret: 'same-secret',
    version: '1.0.0',
    expireIn: '1h',
    issuer: 'app-a',
    cipher
  })
  const jwtB = new JWT({
    secret: 'same-secret',
    version: '1.0.0',
    expireIn: '1h',
    issuer: 'app-b',
    cipher
  })
  const token = await jwtA.sign({ scope: 'a' })
  await assertRejects(
    async () => {
      await jwtB.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('Security - custom cipher using secret isolates instances', async () => {
  const cipher = buildContractCompliantCipher()
  const jwtA = new JWT({
    secret: 'secret-a',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const jwtB = new JWT({
    secret: 'secret-b',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const token = await jwtA.sign({ role: 'admin' })
  await assertRejects(
    async () => {
      await jwtB.decode(token)
    },
    Error,
    'Invalid token'
  )
  const decodedByA = await jwtA.decode(token)
  assertEquals((decodedByA as { role: string }).role, 'admin')
})

Deno.test('Security - different issuer should fail', async () => {
  const jwt1 = new JWT({
    secret: 'same-secret',
    expireIn: '1h',
    version: '1.0.0',
    issuer: 'app-one'
  })
  const jwt2 = new JWT({
    secret: 'same-secret',
    expireIn: '1h',
    version: '1.0.0',
    issuer: 'app-two'
  })
  const token = await jwt1.sign({ data: 'test' })
  await assertRejects(async () => {
    await jwt2.decode(token)
  }, Error)
})

Deno.test('Security - DoS via huge token allocates then fails at decrypt', async () => {
  const twoMillionHex = '00'.repeat(1_000_000)
  const fakeTokenData = {
    encrypted: twoMillionHex,
    iv: '00'.repeat(12),
    tag: '00'.repeat(16),
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    version: '1.0.0'
  }
  const fakeToken = btoa(JSON.stringify(fakeTokenData))
  const jwt = new JWT({
    secret: 'any-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  await assertRejects(async () => {
    await jwt.decode(fakeToken)
  }, Error)
  assertEquals(fakeTokenData.encrypted.length, 2_000_000)
})

Deno.test('Security - encrypted hex too large should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const bigFake = btoa(
    JSON.stringify({
      encrypted: 'ab'.repeat(256 * 1024 + 1),
      iv: '000000000000000000000000',
      tag: '00000000000000000000000000000000',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      version: '1.0.0'
    })
  )
  await assertRejects(
    async () => {
      await jwt.decode(bigFake)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('Security - invalid hex (non-hex chars) should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const badHexToken = btoa(
    JSON.stringify({
      encrypted: 'gggggggggggggggggggggggggggggggg',
      iv: '112233445566778899aabbcc',
      tag: '00112233445566778899aabbccddeeff',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      version: '1.0.0'
    })
  )
  await assertRejects(
    async () => {
      await jwt.decode(badHexToken)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('Security - invalid hex (odd length) should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const oddHexToken = btoa(
    JSON.stringify({
      encrypted: 'abc',
      iv: '112233445566778899aabbcc',
      tag: '00112233445566778899aabbccddeeff',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      version: '1.0.0'
    })
  )
  await assertRejects(
    async () => {
      await jwt.decode(oddHexToken)
    },
    Error,
    'Invalid token'
  )
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
    'Invalid token'
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
    'Invalid token'
  )
})

Deno.test('Security - token string too large should fail', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const hugeToken = 'a'.repeat(512 * 1024 + 1)
  await assertRejects(
    async () => {
      await jwt.decode(hugeToken)
    },
    Error,
    'Invalid token'
  )
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
    'Invalid token'
  )
})

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
    'Invalid token'
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
