import { AppCheckTokenVerifier } from "https://deno.land/x/edge_token_verifier@v0.2.0/mod.ts";

export default async (request: Request) => {
  const appCheckToken = request.headers.get("X-Firebase-AppCheck");
  const appCheckClaims = await verifyAppCheckToken(appCheckToken);

  if (!appCheckClaims) {
    return Response.json(
      { message: "Unauthorized access. Invalid App Check token." },
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
    return await tokenVerifier.verify(appCheckToken, "project-id");
  } catch (_err) {
    return null;
  }
};

export const config = { path: "/api" };
