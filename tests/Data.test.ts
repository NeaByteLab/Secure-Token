import { assert, assertEquals } from '@std/assert'
import JWT from '@app/index.ts'

Deno.test('Data Types - sign and decode array', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const original = [1, 2, 3, 'test', true]
  const token = await jwt.sign(original)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, original)
  assert(Array.isArray(decoded))
})

Deno.test('Data Types - sign and decode array with null', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const original = [1, null, 'a']
  const token = await jwt.sign(original)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, original)
  assert(Array.isArray(decoded) && decoded[1] === null)
})

Deno.test('Data Types - sign and decode boolean', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const original = true
  const token = await jwt.sign(original)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, original)
  assertEquals(typeof decoded, 'boolean')
})

Deno.test('Data Types - sign and decode empty array', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const original: unknown[] = []
  const token = await jwt.sign(original)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, original)
  assert(Array.isArray(decoded) && decoded.length === 0)
})

Deno.test('Data Types - sign and decode empty object', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const original = {}
  const token = await jwt.sign(original)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, original)
  assert(typeof decoded === 'object' && decoded !== null && !Array.isArray(decoded))
})

Deno.test('Data Types - sign and decode nested object', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const original = {
    nested: {
      deep: {
        value: 123,
        array: [1, 2, { obj: 'test' }]
      }
    }
  }
  const token = await jwt.sign(original)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, original)
  assertEquals(typeof decoded, 'object')
})

Deno.test('Data Types - sign and decode number', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const original = 42
  const token = await jwt.sign(original)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, original)
  assertEquals(typeof decoded, 'number')
})

Deno.test('Data Types - sign and decode string', async () => {
  const jwt = new JWT({
    secret: 'test-secret',
    expireIn: '1h',
    version: '1.0.0'
  })
  const original = 'Hello World!'
  const token = await jwt.sign(original)
  const decoded = await jwt.decode(token)
  assertEquals(decoded, original)
  assertEquals(typeof decoded, 'string')
})
