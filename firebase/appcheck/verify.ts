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

import * as jwt from "../utils/jwt.ts";

const APP_CHECK_ISSUER = "https://firebaseappcheck.googleapis.com/";
const JWKS_URL = "https://firebaseappcheck.googleapis.com/v1/jwks";

export class AppCheckTokenVerifier {
  private signatureVerifier: jwt.SignatureVerifier;

  constructor() {
    this.signatureVerifier = jwt.PublicKeySignatureVerifier.withJwksUrl(
      JWKS_URL,
    );
  }

  async verify(
    token: string,
    projectId?: string,
  ): Promise<DecodedAppCheckToken> {
    projectId = projectId ??
      (Deno.env.get("GOOGLE_CLOUD_PROJECT") ||
        Deno.env.get("GCLOUD_PROJECT") ||
        "");

    const { header, payload } = await jwt.decodeJwt(token);

    this.verifyContent({ header, payload }, projectId);

    await this.signatureVerifier.verify(token);
    const decodedAppCheckToken = payload as DecodedAppCheckToken;
    decodedAppCheckToken.app_id = decodedAppCheckToken.sub;
    return decodedAppCheckToken;
  }

  private verifyContent(
    fullDecodedToken: jwt.DecodedToken,
    projectId: string,
  ): void {
    const { header, payload } = fullDecodedToken;

    const projectIdMatchMessage =
      " Make sure the App Check token comes from the same " +
      "Firebase project as the service account used to authenticate this SDK.";
    const scopedProjectId = `projects/${projectId}`;

    let errorMessage: string | undefined;
    if (header.alg !== jwt.ALGORITHM_RS256) {
      errorMessage =
        "The provided App Check token has incorrect algorithm. Expected " +
        `"${jwt.ALGORITHM_RS256}" but got "${header.alg}".`;
    } else if (
      !isNonEmptyArray(payload.aud) ||
      !payload.aud.includes(scopedProjectId)
    ) {
      errorMessage =
        'The provided App Check token has incorrect "aud" (audience) claim. Expected "' +
        scopedProjectId +
        '" but got "' +
        payload.aud +
        '".' +
        projectIdMatchMessage;
    } else if (
      typeof payload.iss !== "string" ||
      !payload.iss.startsWith(APP_CHECK_ISSUER)
    ) {
      errorMessage =
        'The provided App Check token has incorrect "iss" (issuer) claim.';
    } else if (typeof payload.sub !== "string") {
      errorMessage =
        'The provided App Check token has no "sub" (subject) claim.';
    } else if (payload.sub === "") {
      errorMessage =
        'The provided App Check token has an empty string "sub" (subject) claim.';
    }
    if (errorMessage) {
      throw new Error(`invalid-argument: ${errorMessage}`);
    }
  }
}

function isNonEmptyArray<T>(value: unknown): value is T[] {
  return Array.isArray(value) && value.length !== 0;
}

export interface DecodedAppCheckToken {
  /**
   * The issuer identifier for the issuer of the response.
   * This value is a URL with the format
   * `https://firebaseappcheck.googleapis.com/<PROJECT_NUMBER>`, where `<PROJECT_NUMBER>` is the
   * same project number specified in the {@link DecodedAppCheckToken.aud | aud} property.
   */
  iss: string;

  /**
   * The Firebase App ID corresponding to the app the token belonged to.
   * As a convenience, this value is copied over to the {@link DecodedAppCheckToken.app_id | app_id} property.
   */
  sub: string;

  /**
   * The audience for which this token is intended.
   * This value is a JSON array of two strings, the first is the project number of your
   * Firebase project, and the second is the project ID of the same project.
   */
  aud: string[];

  /**
   * The App Check token's expiration time, in seconds since the Unix epoch. That is, the
   * time at which this App Check token expires and should no longer be considered valid.
   */
  exp: number;

  /**
   * The App Check token's issued-at time, in seconds since the Unix epoch. That is, the
   * time at which this App Check token was issued and should start to be considered
   * valid.
   */
  iat: number;

  /**
   * The App ID corresponding to the App the App Check token belonged to.
   * This value is not actually one of the JWT token claims. It is added as a
   * convenience, and is set as the value of the {@link DecodedAppCheckToken.sub | sub} property.
   */
  app_id: string;
  [key: string]: unknown;
}
