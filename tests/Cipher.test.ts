import { assertEquals, assertRejects } from '@std/assert'
import { AESGCM } from '@cipher/index.ts'
import { Shared } from '@cipher/Shared.ts'

Deno.test('AESGCM - aes-256 round-trip', async () => {
  const plaintext = 'hello'
  const secret = 'secret-32-bytes-long!!!!!!!!!!!!!'
  const keySizeBytes = 32 as 16 | 32
  const issuer = 'app'
  const version = '2.0'
  const encrypted = await AESGCM.encrypt(plaintext, secret, keySizeBytes, issuer, version)
  const decrypted = await AESGCM.decrypt(encrypted, secret, keySizeBytes, issuer, version)
  assertEquals(decrypted, plaintext)
})

Deno.test('AESGCM - encrypt and decrypt round-trip', async () => {
  const plaintext = '{"data":1,"exp":999,"iat":0,"version":"1.0.0"}'
  const secret = 'test-secret'
  const keySizeBytes = 16 as 16 | 32
  const issuer = 'test-issuer'
  const version = '1.0.0'
  const encrypted = await AESGCM.encrypt(plaintext, secret, keySizeBytes, issuer, version)
  assertEquals(typeof encrypted.encrypted, 'string')
  assertEquals(typeof encrypted.iv, 'string')
  assertEquals(typeof encrypted.tag, 'string')
  assertEquals(encrypted.iv.length, 24)
  assertEquals(encrypted.tag.length, 32)
  const decrypted = await AESGCM.decrypt(encrypted, secret, keySizeBytes, issuer, version)
  assertEquals(decrypted, plaintext)
})

Deno.test('AESGCM - wrong issuer fails', async () => {
  const plaintext = 'data'
  const secret = 'secret'
  const keySizeBytes = 16 as 16 | 32
  const version = '1.0.0'
  const encrypted = await AESGCM.encrypt(plaintext, secret, keySizeBytes, 'issuer-a', version)
  await assertRejects(async () => {
    await AESGCM.decrypt(encrypted, secret, keySizeBytes, 'issuer-b', version)
  }, Error)
})

Deno.test('AESGCM - wrong secret fails', async () => {
  const plaintext = 'data'
  const secret = 'correct-secret'
  const keySizeBytes = 16 as 16 | 32
  const issuer = 'app'
  const version = '1.0.0'
  const encrypted = await AESGCM.encrypt(plaintext, secret, keySizeBytes, issuer, version)
  await assertRejects(async () => {
    await AESGCM.decrypt(encrypted, 'wrong-secret', keySizeBytes, issuer, version)
  }, Error)
})

Deno.test('AESGCM - wrong version fails', async () => {
  const plaintext = 'data'
  const secret = 'secret'
  const keySizeBytes = 16 as 16 | 32
  const issuer = 'app'
  const encrypted = await AESGCM.encrypt(plaintext, secret, keySizeBytes, issuer, '1.0.0')
  await assertRejects(async () => {
    await AESGCM.decrypt(encrypted, secret, keySizeBytes, issuer, '2.0.0')
  }, Error)
})

Deno.test('Shared - bytesToHex and hexToBytes round-trip', () => {
  const bytes = new Uint8Array([0, 15, 255, 16])
  const hex = Shared.bytesToHex(bytes)
  assertEquals(hex, '000fff10')
  const back = Shared.hexToBytes(hex)
  assertEquals(back.length, bytes.length)
  for (let i = 0; i < bytes.length; i++) {
    assertEquals(back[i], bytes[i])
  }
})

Deno.test('Shared - generateIV length 12', () => {
  const iv = Shared.generateIV()
  assertEquals(iv.length, 12)
})

Deno.test('Shared - hexToBytes empty string', () => {
  const bytes = Shared.hexToBytes('')
  assertEquals(bytes.length, 0)
})
