/*!
 * Copyright 2023 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as jose from 'https://deno.land/x/jose@v4.11.2/index.ts';
import {
  assertEquals,
  assertRejects,
} from 'https://deno.land/std@0.175.0/testing/asserts.ts';
import { denock } from 'https://deno.land/x/denock@0.2.0/mod.ts';

import { AppCheckTokenVerifier } from './verify.ts';

// Randomly generated JSON Web Key Sets that do not correspond to anything related to Firebase.
// eslint-disable-next-line @typescript-eslint/no-var-requires
import jwksResponse from '../utils/mock.jwks.json' assert { type: 'json' };

// Randomly generated key pairs that don't correspond to anything related to Firebase or GCP
// The private key for this key pair is identical to the one used in ./mock.jwks.json
import jwksPrivateKey from '../utils/mock.private.json' assert { type: 'json' };

const ALGORITHM = 'RS256' as const;
const ONE_HOUR_IN_STRING = '1h';

export const projectId = 'project_id';
export const projectNumber = '12345678';
export const appId = '12345678:app:ID';
export const developerClaims = {
  one: 'uno',
  two: 'dos',
};

/**
 * Generates a mocked App Check token.
 */
export async function generateAppCheckToken(opts?: {
  alg?: string;
  aud?: string;
  exp?: number;
  sub?: string;
  iss?: string;
}): Promise<string> {
  const privateKey = await jose.importPKCS8(
    jwksPrivateKey.privateKey,
    opts?.alg ?? ALGORITHM,
  );
  return await new jose.SignJWT(developerClaims)
    .setProtectedHeader({
      alg: opts?.alg ?? ALGORITHM,
      kid: jwksResponse.keys[0].kid,
    })
    .setAudience(
      opts?.aud ?? ['projects/' + projectNumber, 'projects/' + projectId],
    )
    .setExpirationTime(opts?.exp ?? ONE_HOUR_IN_STRING)
    .setIssuer(
      opts?.iss ?? 'https://firebaseappcheck.googleapis.com/' + projectNumber,
    )
    .setSubject(opts?.sub ?? appId)
    .sign(privateKey);
}

Deno.test('should verify a valid app check token', async () => {
  const interceptor = denock({
    method: 'GET',
    protocol: 'https',
    host: 'firebaseappcheck.googleapis.com',
    path: '/v1/jwks',
    replyStatus: 200,
    responseBody: jwksResponse,
  });

  const mockAppCheckToken = await generateAppCheckToken();
  const verifier = new AppCheckTokenVerifier();
  const decoded = await verifier.verify(mockAppCheckToken, projectId);
  assertEquals(
    decoded.iss,
    'https://firebaseappcheck.googleapis.com/' + projectNumber,
  );

  interceptor.destroy();
});

Deno.test('should throw for invalid algorithm', async () => {
  const mockAppCheckToken = await generateAppCheckToken({ alg: 'RS384' });
  const verifier = new AppCheckTokenVerifier();

  await assertRejects(
    async () => {
      return await verifier.verify(mockAppCheckToken, projectId);
    },
    Error,
    'invalid-argument: The provided App Check token has incorrect algorithm. Expected "RS256" but got "RS384"',
  );
});

Deno.test('should throw for invalid issuer', async () => {
  const mockAppCheckToken = await generateAppCheckToken({
    iss: 'incorrectIssuer',
  });
  const verifier = new AppCheckTokenVerifier();

  await assertRejects(
    async () => {
      return await verifier.verify(mockAppCheckToken, projectId);
    },
    Error,
    'invalid-argument: The provided App Check token has incorrect "iss" (issuer) claim.',
  );
});

Deno.test('should throw for invalid audience', async () => {
  const mockAppCheckToken = await generateAppCheckToken({
    aud: 'incorrectAudience',
  });
  const verifier = new AppCheckTokenVerifier();

  await assertRejects(
    async () => {
      return await verifier.verify(mockAppCheckToken, projectId);
    },
    Error,
    'invalid-argument: The provided App Check token has incorrect "aud" (audience) claim. Expected "projects/project_id" but got "incorrectAudience". Make sure the App Check token comes from the same Firebase project as the service account used to authenticate this SDK.',
  );
});
