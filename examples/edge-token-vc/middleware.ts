// middleware.ts
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
