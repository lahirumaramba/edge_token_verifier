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

const ALGORITHM = "RS256" as const;

async function writeFile(path: string, text: string): Promise<void> {
  return await Deno.writeTextFile(path, text);
}

const { publicKey, privateKey } = await jose.generateKeyPair(ALGORITHM, {
  extractable: true,
});
const pkcs8Pem = await jose.exportPKCS8(privateKey);
//console.log(pkcs8Pem);
writeFile("./private.txt", pkcs8Pem);

const spkiPem = await jose.exportSPKI(publicKey);
//console.log(spkiPem);
writeFile("./public.txt", spkiPem);

const publicJwk = await jose.exportJWK(publicKey);
//console.log(publicJwk);
writeFile("./public-jwk.json", JSON.stringify(publicJwk, null, 2));
