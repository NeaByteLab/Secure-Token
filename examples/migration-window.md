# Token Reissue During Rotation Window

When rotating `version` or `secret`, previously issued tokens become invalid by design. To avoid breaking active sessions, run a temporary migration window that accepts old tokens once and reissues new ones.

## Example

```ts
import JWT from '@neabyte/secure-token'

// Step: old config (to be removed after the migration window)
const jwtOld = new JWT({
  secret: Deno.env.get('SECRET_OLD') ?? '',
  version: '1.0.0',
  expireIn: '1h'
})

// Step: new config (target)
const jwtNew = new JWT({
  secret: Deno.env.get('SECRET_NEW') ?? '',
  version: '1.1.0',
  expireIn: '1h'
})

export async function authenticateAndRefresh(token: string): Promise<string> {
  // Step 1: try new config first (verify returns boolean; it does not throw)
  if (await jwtNew.verify(token)) {
    return token
  }

  // Step 2: invalid for new config — decode with old config and reissue with new
  try {
    const payload = await jwtOld.decode(token)
    return await jwtNew.sign(payload)
  } catch {
    // Step: token invalid under both configurations
    throw new Error('Unauthorized')
  }
}
```

## Operational guidance

> [!IMPORTANT]
>
> - Announce the rotation and enable this migration path.
> - Monitor reissuance rate; once traffic mostly uses new tokens, remove old config.
> - Keep the window short to limit exposure; hours to a few days is typical.
> - Rotating `version` and `secret` simultaneously is fine; the same pattern applies.
