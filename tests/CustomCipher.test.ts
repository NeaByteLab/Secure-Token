import { assert, assertEquals, assertRejects } from '@std/assert'
import { buildContractCompliantCipher } from '@tests/CipherHelper.ts'
import JWT from '@app/index.ts'
import type * as Types from '@app/Types.ts'

function fixedEnvelope(): Types.TokenEncrypted {
  return {
    encrypted: 'ee',
    iv: '112233445566778899aabbcc',
    tag: '00112233445566778899aabbccddeeff'
  }
}

function tokenData(overrides: Partial<Types.TokenData>): Types.TokenData {
  const now = Math.floor(Date.now() / 1000)
  return {
    encrypted: 'aa',
    iv: '112233445566778899aabbcc',
    tag: '00112233445566778899aabbccddeeff',
    exp: now + 3600,
    iat: now,
    version: '1.0.0',
    ...overrides
  }
}

Deno.test('CustomCipher - contract-compliant iv 24 hex tag 32 hex in envelope', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const token = await jwt.sign({})
  const raw = JSON.parse(atob(token))
  assertEquals(typeof raw.iv, 'string')
  assertEquals(raw.iv.length, 24)
  assertEquals(/^[0-9a-f]+$/.test(raw.iv), true)
  assertEquals(typeof raw.tag, 'string')
  assertEquals(raw.tag.length, 32)
  assertEquals(/^[0-9a-f]+$/.test(raw.tag), true)
  assertEquals(typeof raw.encrypted, 'string')
})

Deno.test('CustomCipher - contract-compliant round-trip same instance', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 'my-secret',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const data = { id: 1, role: 'user' }
  const token = await jwt.sign(data)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, data)
})

Deno.test('CustomCipher - contract-compliant with aes-256-gcm round-trip', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 'secret-32-bytes-long!!!!!!!!',
    version: '2.0',
    expireIn: '7d',
    algorithm: 'aes-256-gcm',
    cipher
  })
  const data = { scope: 'admin' }
  const token = await jwt.sign(data)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, data)
})

Deno.test('CustomCipher - contract-compliant with custom issuer round-trip', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 'shared',
    version: '1.0.0',
    expireIn: '1h',
    issuer: 'my-app',
    cipher
  })
  const data = { uid: 'u1' }
  const token = await jwt.sign(data)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, data)
})

Deno.test('CustomCipher - decrypt receives token secret keySizeBytes issuer version', async () => {
  const args: { token: Types.TokenEncrypted; secret: string; issuer: string; version: string }[] =
    []
  const customCipher: Types.Cipher = {
    encrypt: () => Promise.resolve(fixedEnvelope()),
    decrypt: (token, secret, _keySizeBytes, issuer, version) => {
      args.push({ token: { ...token }, secret, issuer, version })
      return Promise.resolve(
        JSON.stringify({
          data: { x: 1 },
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000),
          version
        })
      )
    }
  }
  const jwt = new JWT({
    secret: 'dec-secret',
    version: '1.0.0',
    expireIn: '1h',
    issuer: 'dec-issuer',
    cipher: customCipher
  })
  const token = await jwt.sign({ x: 1 })
  await jwt.decode(token)
  assertEquals(args.length, 1)
  const decArgs = args[0]
  assert(decArgs !== undefined)
  assertEquals(decArgs.secret, 'dec-secret')
  assertEquals(decArgs.issuer, 'dec-issuer')
  assertEquals(decArgs.version, '1.0.0')
  assertEquals(decArgs.token.iv, fixedEnvelope().iv)
  assertEquals(decArgs.token.tag, fixedEnvelope().tag)
})

Deno.test('CustomCipher - decrypt returns empty string yields Invalid token', async () => {
  const customCipher: Types.Cipher = {
    encrypt: () => Promise.resolve(fixedEnvelope()),
    decrypt: () => Promise.resolve('')
  }
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher: customCipher
  })
  const token = await jwt.sign({ a: 1 })
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('CustomCipher - decrypt returns non-JSON yields Invalid token', async () => {
  const customCipher: Types.Cipher = {
    encrypt: () => Promise.resolve(fixedEnvelope()),
    decrypt: () => Promise.resolve('not valid json')
  }
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher: customCipher
  })
  const token = await jwt.sign({ a: 1 })
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test(
  'CustomCipher - decrypt returns payload exp iat mismatch yields Invalid token',
  async () => {
    const jwt = new JWT({
      secret: 's',
      version: '1.0.0',
      expireIn: '1h',
      cipher: {
        encrypt: () => Promise.resolve(fixedEnvelope()),
        decrypt: (_, __, ___, ____, version) =>
          Promise.resolve(
            JSON.stringify({
              data: { x: 1 },
              exp: 999,
              iat: 888,
              version
            })
          )
      } as Types.Cipher
    })
    const token = await jwt.sign({ x: 1 })
    await assertRejects(
      async () => {
        await jwt.decode(token)
      },
      Error,
      'Invalid token'
    )
  }
)

Deno.test(
  'CustomCipher - decrypt returns payload version mismatch yields Invalid token',
  async () => {
    const now = Math.floor(Date.now() / 1000)
    const customCipher: Types.Cipher = {
      encrypt: () => Promise.resolve(fixedEnvelope()),
      decrypt: () =>
        Promise.resolve(
          JSON.stringify({
            data: {},
            exp: now + 3600,
            iat: now,
            version: 'other-version'
          })
        )
    }
    const jwt = new JWT({
      secret: 's',
      version: '1.0.0',
      expireIn: '1h',
      cipher: customCipher
    })
    const token = await jwt.sign({})
    await assertRejects(
      async () => {
        await jwt.decode(token)
      },
      Error,
      'Invalid token'
    )
  }
)

Deno.test('CustomCipher - decrypt returns wrong payload shape yields Invalid token', async () => {
  const customCipher: Types.Cipher = {
    encrypt: () => Promise.resolve(fixedEnvelope()),
    decrypt: () => Promise.resolve(JSON.stringify({ wrong: 'shape' }))
  }
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher: customCipher
  })
  const token = await jwt.sign({ a: 1 })
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('CustomCipher - decrypt throws yields Invalid token', async () => {
  const customCipher: Types.Cipher = {
    encrypt: () => Promise.resolve(fixedEnvelope()),
    decrypt: () => Promise.reject(new Error('decrypt failed'))
  }
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher: customCipher
  })
  const token = await jwt.sign({ a: 1 })
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test(
  'CustomCipher - encrypt receives plaintext secret keySizeBytes issuer version',
  async () => {
    const args: {
      plaintext: string
      secret: string
      keySizeBytes: 16 | 32
      issuer: string
      version: string
    }[] = []
    const customCipher: Types.Cipher = {
      encrypt: (plaintext, secret, keySizeBytes, issuer, version) => {
        args.push({ plaintext, secret, keySizeBytes, issuer, version })
        return Promise.resolve(fixedEnvelope())
      },
      decrypt: () =>
        Promise.resolve(
          JSON.stringify({
            data: {},
            exp: Math.floor(Date.now() / 1000) + 3600,
            iat: Math.floor(Date.now() / 1000),
            version: '1.0.0'
          })
        )
    }
    const jwt = new JWT({
      secret: 'my-secret',
      version: 'v1',
      expireIn: '1h',
      issuer: 'my-issuer',
      cipher: customCipher
    })
    await jwt.sign({ foo: 'bar' })
    assertEquals(args.length, 1)
    const encArgs = args[0]
    assert(encArgs !== undefined)
    assertEquals(encArgs.secret, 'my-secret')
    assertEquals(encArgs.issuer, 'my-issuer')
    assertEquals(encArgs.version, 'v1')
    assertEquals(encArgs.keySizeBytes, 16)
    assertEquals(JSON.parse(encArgs.plaintext).data, { foo: 'bar' })
  }
)

Deno.test('CustomCipher - encrypt throws sign rejects with error', async () => {
  const customCipher: Types.Cipher = {
    encrypt: () => Promise.reject(new Error('encrypt failed')),
    decrypt: () => Promise.resolve('')
  }
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher: customCipher
  })
  await assertRejects(
    async () => {
      await jwt.sign({ x: 1 })
    },
    Error,
    'encrypt failed'
  )
})

Deno.test('CustomCipher - envelope encrypted non-string fails decode', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const broken = tokenData({ encrypted: [] as unknown as string })
  const token = btoa(JSON.stringify(broken))
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('CustomCipher - envelope iv non-string fails decode', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const broken = tokenData({ iv: 123 as unknown as string })
  const token = btoa(JSON.stringify(broken))
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('CustomCipher - envelope missing encrypted fails decode', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const td = tokenData({})
  const broken = { ...td } as Record<string, unknown>
  delete broken['encrypted']
  const token = btoa(JSON.stringify(broken))
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('CustomCipher - envelope missing iv fails decode', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const td = tokenData({})
  const broken = { ...td } as Record<string, unknown>
  delete broken['iv']
  const token = btoa(JSON.stringify(broken))
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('CustomCipher - envelope missing tag fails decode', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const td = tokenData({})
  const broken = { ...td } as Record<string, unknown>
  delete broken['tag']
  const token = btoa(JSON.stringify(broken))
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('CustomCipher - envelope tag non-string fails decode', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const broken = tokenData({ tag: true as unknown as string })
  const token = btoa(JSON.stringify(broken))
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('CustomCipher - issuer isolation different issuer fails decode', async () => {
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

Deno.test('CustomCipher - keySizeBytes isolation aes-128 token aes-256 decode fails', async () => {
  const cipher = buildContractCompliantCipher()
  const jwtSign = new JWT({
    secret: 'shared-secret',
    version: '1.0.0',
    expireIn: '1h',
    algorithm: 'aes-128-gcm',
    cipher
  })
  const jwtDecode = new JWT({
    secret: 'shared-secret',
    version: '1.0.0',
    expireIn: '1h',
    algorithm: 'aes-256-gcm',
    cipher
  })
  const token = await jwtSign.sign({ id: 1 })
  await assertRejects(
    async () => {
      await jwtDecode.decode(token)
    },
    Error,
    'Invalid token'
  )
  const decoded = await jwtSign.decode(token)
  assertEquals((decoded as { id: number }).id, 1)
})

Deno.test('CustomCipher - secret isolation different secret fails decode', async () => {
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
  assertEquals((await jwtA.decode(token)) as { role: string }, { role: 'admin' })
})

Deno.test('CustomCipher - token version differs from instance yields Invalid token', async () => {
  const cipher = buildContractCompliantCipher()
  const jwtSign = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const jwtDecode = new JWT({
    secret: 's',
    version: '2.0.0',
    expireIn: '1h',
    cipher
  })
  const token = await jwtSign.sign({ data: 'x' })
  await assertRejects(
    async () => {
      await jwtDecode.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('CustomCipher - tokenData exp non-number fails decode', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const broken = tokenData({ exp: 'invalid' as unknown as number })
  const token = btoa(JSON.stringify(broken))
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('CustomCipher - tokenData iat non-number fails decode', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const broken = tokenData({ iat: null as unknown as number })
  const token = btoa(JSON.stringify(broken))
  await assertRejects(
    async () => {
      await jwt.decode(token)
    },
    Error,
    'Invalid token'
  )
})

Deno.test('CustomCipher - version isolation different version fails decode', async () => {
  const cipher = buildContractCompliantCipher()
  const jwtA = new JWT({
    secret: 'same-secret',
    version: '1.0.0',
    expireIn: '1h',
    issuer: 'app',
    cipher
  })
  const jwtB = new JWT({
    secret: 'same-secret',
    version: '2.0.0',
    expireIn: '1h',
    issuer: 'app',
    cipher
  })
  const token = await jwtA.sign({ x: 1 })
  await assertRejects(
    async () => {
      await jwtB.decode(token)
    },
    Error,
    'Invalid token'
  )
  const decodedByA = await jwtA.decode(token)
  assertEquals((decodedByA as { x: number }).x, 1)
})

Deno.test('CustomCipher - verify returns false when custom cipher decrypt fails', async () => {
  const customCipher: Types.Cipher = {
    encrypt: () => Promise.resolve(fixedEnvelope()),
    decrypt: () => Promise.reject(new Error('auth failed'))
  }
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher: customCipher
  })
  const token = await jwt.sign({ a: 1 })
  const ok = await jwt.verify(token)
  assertEquals(ok, false)
})

Deno.test('CustomCipher - verify returns true when custom cipher round-trip succeeds', async () => {
  const cipher = buildContractCompliantCipher()
  const jwt = new JWT({
    secret: 's',
    version: '1.0.0',
    expireIn: '1h',
    cipher
  })
  const token = await jwt.sign({ a: 1 })
  const ok = await jwt.verify(token)
  assertEquals(ok, true)
})
