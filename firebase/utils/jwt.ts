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

import * as jose from "https://deno.land/x/jose@v4.11.2/index.ts";
import { GetKeyFunction } from "https://deno.land/x/jose@v4.11.2/types.d.ts";

const HOUR_IN_SECONDS = 3600;
export const ALGORITHM_RS256 = "RS256" as const;

export type Dictionary = { [key: string]: unknown };

export type DecodedToken = {
  header: Dictionary;
  payload: Dictionary;
};

export interface SignatureVerifier {
  verify(token: string): Promise<void>;
}

interface KeyFetcher {
  fetchPublicKeys(): Promise<{ [key: string]: string }>;
}

/**
 * Class to fetch public keys from a client certificates URL.
 */
export class CertKeyFetcher implements KeyFetcher {
  private publicKeys: { [key: string]: string } = {};
  private publicKeysExpireAt = 0;

  constructor(private clientCertUrl: string) {
    // TODO: validate the url
  }

  public fetchPublicKeys(): Promise<{ [key: string]: string }> {
    if (this.shouldRefresh()) {
      return this.refresh();
    }
    return Promise.resolve(this.publicKeys);
  }

  private shouldRefresh(): boolean {
    return !this.publicKeys || this.publicKeysExpireAt <= Date.now();
  }

  private async refresh(): Promise<{ [key: string]: string }> {
    const jsonResponse = await fetch(this.clientCertUrl);
    const jsonData = await jsonResponse.json();

    // reset expire at from previous set of keys.
    this.publicKeysExpireAt = 0;
    if (jsonResponse.headers.has("cache-control")) {
      const cacheControlHeader: string =
        jsonResponse.headers.get("cache-control") ?? "";
      const parts = cacheControlHeader.split(",");
      parts.forEach((part) => {
        const subParts = part.trim().split("=");
        if (subParts[0] === "max-age") {
          const maxAge: number = +subParts[1];
          this.publicKeysExpireAt = Date.now() + maxAge * 1000;
        }
      });
    }
    this.publicKeys = jsonData;
    return jsonData;
  }
}

/**
 * Class for verifying JWT signature with a public key.
 */
export class PublicKeySignatureVerifier implements SignatureVerifier {
  constructor(
    private keyFetcher:
      | KeyFetcher
      | GetKeyFunction<jose.JWSHeaderParameters, jose.FlattenedJWSInput>,
  ) {}

  public static withJwksUrl(jwksUrl: string): PublicKeySignatureVerifier {
    const remoteKeySet = jose.createRemoteJWKSet(new URL(jwksUrl), {
      cacheMaxAge: HOUR_IN_SECONDS * 6,
    });
    return new PublicKeySignatureVerifier(remoteKeySet);
  }

  public static withCertificateUrl(
    certUrl: string,
  ): PublicKeySignatureVerifier {
    const kFetcher = new CertKeyFetcher(certUrl);
    return new PublicKeySignatureVerifier(kFetcher);
  }

  public async verify(token: string): Promise<void> {
    if (this.keyFetcher instanceof CertKeyFetcher) {
      return await this.verifyWithKey(token, this.keyFetcher);
    }
    return await this.verifyWithJWK(
      token,
      this.keyFetcher as GetKeyFunction<
        jose.JWSHeaderParameters,
        jose.FlattenedJWSInput
      >,
    );
  }

  private async verifyWithJWK(
    token: string,
    remoteKeySet: GetKeyFunction<
      jose.JWSHeaderParameters,
      jose.FlattenedJWSInput
    >,
  ): Promise<void> {
    await jose.jwtVerify(token, remoteKeySet);
  }

  private async verifyWithKey(
    token: string,
    keyFetcher: KeyFetcher,
  ): Promise<void> {
    const header = jose.decodeProtectedHeader(token);
    const kid = header.kid ?? "";
    const publicKeys = await keyFetcher.fetchPublicKeys();
    const publicKey = await jose.importSPKI(publicKeys[kid], ALGORITHM_RS256);
    await jose.jwtVerify(token, publicKey);
  }
}

/**
 * Decodes JWTs. This method does not verify the signature.
 *
 * @param jwtToken - JWT to be decoded.
 * @returns Decoded token containing the header and payload.
 */
export function decodeJwt(jwtToken: string): Promise<DecodedToken> {
  const header = jose.decodeProtectedHeader(jwtToken);
  const payload = jose.decodeJwt(jwtToken);
  return Promise.resolve({ header, payload });
}
