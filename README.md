# edge_token_verifier

**Experimental token verifier that works on the Edge.**

Hello there! This is an early stage experimental Deno module to verify tokens on
edge runtimes. We are also experimenting with
[`dnt`](https://github.com/denoland/dnt) to create the the Node.js compatible
module.

We are currently testing the module on different edge runtimes. The current
releases are only for testing purposes.

```js
import { AppCheckTokenVerifier } from 'https://deno.land/x/edge_token_verifier@v0.2.0/mod.ts';
```

## Node.js

```js
import { AppCheckTokenVerifier } from '@lahirumaramba/edge-token-verifier';
```

# Examples on the Edge

## Netlify Edge Functions

```js
// examples/netlify-edge/netlify/edge-functions/hello.ts
import { AppCheckTokenVerifier } from 'https://deno.land/x/edge_token_verifier@v0.2.0/mod.ts';

export default async (request: Request) => {
  const appCheckToken = request.headers.get('X-Firebase-AppCheck');
  const appCheckClaims = await verifyAppCheckToken(appCheckToken);

  if (!appCheckClaims) {
    return Response.json(
      { message: 'Unauthorized access. Invalid App Check token.' },
      { status: 401, headers: { "content-type": "application/json" } },
    );
  }
  return new Response(`Hello world Netlify Edge: App:${appCheckClaims.app_id}`);
};

const tokenVerifier = new AppCheckTokenVerifier();
const verifyAppCheckToken = async (appCheckToken: string | null) => {
  if (!appCheckToken) {
    return null;
  }
  try {
    return await tokenVerifier.verify(appCheckToken, 'project-id');
  } catch (_err) {
    return null;
  }
};

export const config = { path: '/api' };
```

## Vercel Edge Functions (Next.js Middleware)

```js
// examples/edge-token-vc/middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { AppCheckTokenVerifier } from '@lahirumaramba/edge-token-verifier';

export async function middleware(request: NextRequest) {
  const verifyAppCheckToken = async (appCheckToken: string | null) => {
    if (!appCheckToken) {
      return null;
    }
    const tokenVerifier = new AppCheckTokenVerifier();
    try {
      return await tokenVerifier.verify(appCheckToken, 'project-id');
    } catch (_err) {
      return null;
    }
  };
  const appCheckToken = request.headers.get('X-Firebase-AppCheck');
  const appCheckClaims = await verifyAppCheckToken(appCheckToken);

  if (!appCheckClaims) {
    return NextResponse.json(
      { message: 'Unauthorized access. Invalid App Check token.' },
      { status: 401, headers: { 'content-type': 'application/json' } },
    );
  }
  return NextResponse.next();
}

export const config = {
  matcher: '/api/hello/:path*',
};
```
