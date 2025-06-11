/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { BusinessError } from "@ohos.base";
import cert from "@ohos.security.cert";
import utils from "./test_utils";

let certData = '-----BEGIN CERTIFICATE-----\n' +
  'MIIBLzCB1QIUO/QDVJwZLIpeJyPjyTvE43xvE5cwCgYIKoZIzj0EAwIwGjEYMBYG\n' +
  'A1UEAwwPRXhhbXBsZSBSb290IENBMB4XDTIzMDkwNDExMjAxOVoXDTI2MDUzMDEx\n' +
  'MjAxOVowGjEYMBYGA1UEAwwPRXhhbXBsZSBSb290IENBMFkwEwYHKoZIzj0CAQYI\n' +
  'KoZIzj0DAQcDQgAEHjG74yMIueO7z3T+dyuEIrhxTg2fqgeNB3SGfsIXlsiUfLTa\n' +
  'tUsU0i/sePnrKglj2H8Abbx9PK0tsW/VgqwDIDAKBggqhkjOPQQDAgNJADBGAiEA\n' +
  '0ce/fvA4tckNZeB865aOApKXKlBjiRlaiuq5mEEqvNACIQDPD9WyC21MXqPBuRUf\n' +
  'BetUokslUfjT6+s/X4ByaxycAA==\n' +
  '-----END CERTIFICATE-----\n';

function testX509CertAsync() {
  try {
    let encodingBlob: cert.EncodingBlob = {
      data: utils.stringToUint8Array(certData),
      encodingFormat: cert.EncodingFormat.FORMAT_PEM
    };
    let x509Cert = await cert.createX509Cert(encodingBlob);
    let pubKey = x509Cert.getPublicKey();
    let pkBlob = pubKey.getEncoded();
    let pkStr = utils.uint8ArrayToHexStr(pkBlob.data);
    console.println("X509Cert pubKey: " + pkStr);
    await x509Cert.verify(pubKey);
    console.println("X509Cert success");
  } catch (err: BusinessError) {
    console.println(`[error] X509Cert: ${err.code} ${err.message}`);
  }
}

export function testX509Cert() {
  console.println(">>>>>>>>>>>>>>>>>>>> X509CertAsync");
  testX509CertAsync();
}
