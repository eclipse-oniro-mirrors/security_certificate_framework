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
import cryptoFramework from '@ohos.security.cryptoFramework';

let crlData = '-----BEGIN X509 CRL-----\n' +
  'MIHzMF4CAQMwDQYJKoZIhvcNAQEEBQAwFTETMBEGA1UEAxMKQ1JMIGlzc3VlchcN\n' +
  'MTcwODA3MTExOTU1WhcNMzIxMjE0MDA1MzIwWjAVMBMCAgPoFw0zMjEyMTQwMDUz\n' +
  'MjBaMA0GCSqGSIb3DQEBBAUAA4GBACEPHhlaCTWA42ykeaOyR0SGQIHIOUR3gcDH\n' +
  'J1LaNwiL+gDxI9rMQmlhsUGJmPIPdRs9uYyI+f854lsWYisD2PUEpn3DbEvzwYeQ\n' +
  '5SqQoPDoM+YfZZa23hoTLsu52toXobP74sf/9K501p/+8hm4ROMLBoRT86GQKY6g\n' +
  'eavsH0Q3\n' +
  '-----END X509 CRL-----\n';

let certData = '-----BEGIN CERTIFICATE-----\n' +
  'MIIBLzCB1QIUO/QDVJwZLIpeJyPjyTvE43xvE5cwCgYIKoZIzj0EAwIwGjEYMBYG\n' +
  'A1UEAwwPRXhhbXBsZSBSb290IENBMB4XDTIzMDkwNDExMjAxOVoXDTI2MDUzMDEx\n' +
  'MjAxOVowGjEYMBYGA1UEAwwPRXhhbXBsZSBSb290IENBMFkwEwYHKoZIzj0CAQYI\n' +
  'KoZIzj0DAQcDQgAEHjG74yMIueO7z3T+dyuEIrhxTg2fqgeNB3SGfsIXlsiUfLTa\n' +
  'tUsU0i/sePnrKglj2H8Abbx9PK0tsW/VgqwDIDAKBggqhkjOPQQDAgNJADBGAiEA\n' +
  '0ce/fvA4tckNZeB865aOApKXKlBjiRlaiuq5mEEqvNACIQDPD9WyC21MXqPBuRUf\n' +
  'BetUokslUfjT6+s/X4ByaxycAA==\n' +
  '-----END CERTIFICATE-----\n';

let pubKeyData = new Uint8Array([
  0x30, 0x81, 0x9F, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
  0x05, 0x00, 0x03, 0x81, 0x8D, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xDC, 0x4C, 0x2D,
  0x57, 0x49, 0x3D, 0x42, 0x52, 0x1A, 0x09, 0xED, 0x3E, 0x90, 0x29, 0x51, 0xF7, 0x70, 0x15, 0xFE,
  0x76, 0xB0, 0xDB, 0xDF, 0xA1, 0x2C, 0x6C, 0x67, 0x95, 0xDA, 0x63, 0x3D, 0x4F, 0x71, 0x48, 0x8C,
  0x3E, 0xFA, 0x24, 0x79, 0xE9, 0xF2, 0xF2, 0x20, 0xCB, 0xF1, 0x59, 0x6B, 0xED, 0xC8, 0x72, 0x66,
  0x6E, 0x31, 0xD4, 0xF3, 0xCE, 0x0B, 0x12, 0xC4, 0x17, 0x39, 0xB4, 0x52, 0x16, 0xD3, 0xE3, 0xC0,
  0xF8, 0x48, 0xB3, 0xF6, 0x40, 0xD5, 0x47, 0x23, 0x30, 0x7F, 0xA7, 0xC5, 0x5A, 0x5A, 0xBB, 0x5C,
  0x7B, 0xEF, 0x69, 0xE2, 0x74, 0x35, 0x24, 0x22, 0x25, 0x45, 0x7E, 0xFC, 0xE8, 0xC4, 0x52, 0x65,
  0xA0, 0x4E, 0xBC, 0xFD, 0x3F, 0xD9, 0x85, 0x14, 0x8A, 0x5A, 0x93, 0x02, 0x24, 0x6C, 0x19, 0xBA,
  0x81, 0xBE, 0x65, 0x2E, 0xCB, 0xBB, 0xE9, 0x91, 0x7B, 0x7C, 0x47, 0xC2, 0x61, 0x02, 0x03, 0x01,
  0x00, 0x01
]);

let priKeyData = new Uint8Array([
  0x30, 0x82, 0x02, 0x77, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
  0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x02, 0x61, 0x30, 0x82, 0x02, 0x5D, 0x02, 0x01,
  0x00, 0x02, 0x81, 0x81, 0x00, 0xDC, 0x4C, 0x2D, 0x57, 0x49, 0x3D, 0x42, 0x52, 0x1A, 0x09, 0xED,
  0x3E, 0x90, 0x29, 0x51, 0xF7, 0x70, 0x15, 0xFE, 0x76, 0xB0, 0xDB, 0xDF, 0xA1, 0x2C, 0x6C, 0x67,
  0x95, 0xDA, 0x63, 0x3D, 0x4F, 0x71, 0x48, 0x8C, 0x3E, 0xFA, 0x24, 0x79, 0xE9, 0xF2, 0xF2, 0x20,
  0xCB, 0xF1, 0x59, 0x6B, 0xED, 0xC8, 0x72, 0x66, 0x6E, 0x31, 0xD4, 0xF3, 0xCE, 0x0B, 0x12, 0xC4,
  0x17, 0x39, 0xB4, 0x52, 0x16, 0xD3, 0xE3, 0xC0, 0xF8, 0x48, 0xB3, 0xF6, 0x40, 0xD5, 0x47, 0x23,
  0x30, 0x7F, 0xA7, 0xC5, 0x5A, 0x5A, 0xBB, 0x5C, 0x7B, 0xEF, 0x69, 0xE2, 0x74, 0x35, 0x24, 0x22,
  0x25, 0x45, 0x7E, 0xFC, 0xE8, 0xC4, 0x52, 0x65, 0xA0, 0x4E, 0xBC, 0xFD, 0x3F, 0xD9, 0x85, 0x14,
  0x8A, 0x5A, 0x93, 0x02, 0x24, 0x6C, 0x19, 0xBA, 0x81, 0xBE, 0x65, 0x2E, 0xCB, 0xBB, 0xE9, 0x91,
  0x7B, 0x7C, 0x47, 0xC2, 0x61, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x81, 0x80, 0x5A, 0xCF, 0x0F,
  0xF5, 0xA6, 0x1C, 0x19, 0x65, 0x8C, 0x94, 0x40, 0xF6, 0x84, 0x28, 0x74, 0x40, 0x42, 0x34, 0xDE,
  0xC3, 0x00, 0x5E, 0x72, 0x4D, 0x96, 0xE9, 0x4C, 0xBD, 0xC9, 0xDB, 0x14, 0x9F, 0xD5, 0xBB, 0xA9,
  0x0C, 0x20, 0xC2, 0xBE, 0x7A, 0x80, 0x89, 0xEC, 0x99, 0x04, 0xF0, 0xEE, 0x7B, 0x83, 0x20, 0x1D,
  0x37, 0x19, 0x55, 0x85, 0xF6, 0x8E, 0x3B, 0xFB, 0x16, 0xF3, 0xD3, 0x6F, 0xEE, 0x73, 0x12, 0x53,
  0xCA, 0x77, 0xD7, 0x6C, 0x29, 0xF5, 0x08, 0xA3, 0x09, 0x01, 0x0B, 0x00, 0x05, 0x57, 0xAD, 0x4D,
  0xF0, 0x92, 0xB2, 0x5A, 0x8B, 0x19, 0x09, 0x81, 0x86, 0xFE, 0x66, 0xB9, 0x33, 0x88, 0x28, 0xF3,
  0x37, 0x73, 0x09, 0x5F, 0xD7, 0xC9, 0xC6, 0xFA, 0x13, 0x74, 0xFE, 0xAE, 0x53, 0xA9, 0x71, 0x67,
  0xCE, 0x3A, 0xE6, 0x8D, 0x35, 0xD1, 0xB8, 0xFD, 0x6F, 0x0D, 0x43, 0xC2, 0xD1, 0x02, 0x41, 0x00,
  0xF7, 0x33, 0xE5, 0x6C, 0x29, 0x5A, 0x30, 0x58, 0xA4, 0x52, 0x65, 0xA0, 0x39, 0xC2, 0xE8, 0xAE,
  0x5F, 0xA3, 0x2D, 0x0C, 0x65, 0xB1, 0x7B, 0xFD, 0x92, 0xBF, 0x47, 0x87, 0x97, 0x40, 0xCB, 0x54,
  0xF9, 0xBB, 0x50, 0x27, 0x70, 0x51, 0xD0, 0xD8, 0x48, 0x0D, 0xC6, 0x47, 0x60, 0xF8, 0x4E, 0x0A,
  0x32, 0x76, 0x6D, 0xA4, 0xBA, 0x40, 0xE5, 0x58, 0xF8, 0x4A, 0x39, 0x4E, 0xF8, 0x3F, 0x4E, 0x2D,
  0x02, 0x41, 0x00, 0xE4, 0x23, 0x2A, 0x5F, 0x59, 0xCF, 0x7C, 0x91, 0x24, 0x0D, 0xA2, 0x44, 0x17,
  0xCD, 0x37, 0xDE, 0x1F, 0x53, 0x4D, 0x33, 0x9F, 0x90, 0x4D, 0xD9, 0x72, 0x64, 0x25, 0xBA, 0xAB,
  0x47, 0x91, 0xC4, 0x99, 0x95, 0x86, 0xB5, 0x8A, 0xEA, 0x77, 0xF7, 0x64, 0x72, 0x5E, 0xB7, 0xBB,
  0x16, 0xA1, 0x64, 0xA4, 0xE1, 0x2D, 0x76, 0x6D, 0xEF, 0xB1, 0x5E, 0xD6, 0x17, 0xE8, 0xAA, 0xB6,
  0xA0, 0xD9, 0x85, 0x02, 0x41, 0x00, 0xDF, 0xC8, 0x5B, 0x28, 0x4F, 0x47, 0x15, 0xFD, 0x28, 0xC4,
  0x6E, 0xBB, 0x5D, 0x8E, 0xD4, 0x95, 0x06, 0x7E, 0xF1, 0x89, 0x07, 0x86, 0x64, 0x78, 0x69, 0x20,
  0x3F, 0xE0, 0xBF, 0x4C, 0x28, 0xC6, 0x04, 0x4D, 0x4D, 0x82, 0x66, 0x6B, 0xAA, 0x64, 0x20, 0xD6,
  0x57, 0x68, 0xC6, 0xA0, 0x02, 0x05, 0xB9, 0x28, 0xFC, 0x98, 0xE3, 0x03, 0x5C, 0x9B, 0xEE, 0x29,
  0x43, 0x37, 0xFA, 0x03, 0x55, 0x01, 0x02, 0x40, 0x69, 0x5B, 0x7C, 0x24, 0x10, 0xDB, 0xEB, 0x91,
  0x33, 0xEF, 0x3F, 0xF2, 0xE6, 0x73, 0x15, 0xCB, 0xF4, 0xF7, 0x89, 0x7D, 0xBF, 0xC0, 0xEA, 0xD2,
  0xF3, 0x2B, 0x20, 0xE9, 0x76, 0x54, 0x55, 0x13, 0x50, 0x42, 0x67, 0xB5, 0xCB, 0x73, 0xC0, 0xF7,
  0x75, 0x62, 0x04, 0x30, 0x21, 0xAC, 0xAF, 0xD8, 0x44, 0xF4, 0xE1, 0x04, 0x02, 0x7D, 0x61, 0x92,
  0x84, 0x99, 0x02, 0x10, 0x64, 0xCB, 0x1F, 0xE9, 0x02, 0x41, 0x00, 0xAB, 0x4B, 0x7D, 0x90, 0x7C,
  0x57, 0x08, 0x6B, 0xC0, 0x43, 0x72, 0x09, 0x8A, 0x18, 0x35, 0x36, 0x64, 0x9D, 0x84, 0x8D, 0xF1,
  0x84, 0x94, 0x48, 0xC6, 0x80, 0x9D, 0xB9, 0xA2, 0x58, 0x0A, 0x4D, 0x0A, 0xCA, 0x1E, 0xD6, 0x05,
  0x55, 0x5B, 0xFE, 0xD7, 0xAA, 0x70, 0xED, 0x76, 0xB3, 0x40, 0x2E, 0xA0, 0xB3, 0x32, 0x37, 0xB0,
  0xA0, 0xB9, 0x96, 0x2D, 0xC4, 0x70, 0xE9, 0x99, 0x10, 0x67, 0x8D
]);

let encodingBlob: cert.EncodingBlob = {
  data: utils.stringToUint8Array(crlData),
  encodingFormat: cert.EncodingFormat.FORMAT_PEM
};

let certEncodingBlob: cert.EncodingBlob = {
  data: utils.stringToUint8Array(certData),
  encodingFormat: cert.EncodingFormat.FORMAT_PEM
};

function testX509CrlAsync() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    console.println("createX509CRL success");
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("createX509CRL failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testIsRevoked() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let x509Cert = await cert.createX509Cert(certEncodingBlob);
    let isRevoked = x509CRL.isRevoked(x509Cert);
    console.println("isRevoked: " + isRevoked);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("isRevoked failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testGetType() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let type = x509CRL.getType();
    console.println("type: " + type);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getType failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testGetEncoded() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let encoded = x509CRL.getEncoded();
    console.println("encoded: " + encoded);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getEncodedSync failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testVerifySync() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    // Generate the public key by AsyKeyGenerator.
    let keyGenerator = cryptoFramework.createAsyKeyGenerator('RSA1024|PRIMES_3');
    console.log('createAsyKeyGenerator success');
    let priEncodingBlob: cryptoFramework.DataBlob = {
      data: priKeyData,
    };
    let pubEncodingBlob: cryptoFramework.DataBlob = {
      data: pubKeyData,
    };
    let keyPair = await keyGenerator.convertKey(pubEncodingBlob, priEncodingBlob);
    console.log('convert key success');
    let data = x509CRL.verify(keyPair.pubKey);
    console.log('verify success, data is ' + data);
    console.println("verifySync success");
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("verifySync failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetVersion() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let version = x509CRL.getVersion();
    console.println("version: " + version);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getVersion failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testGetIssuerName() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let issuername = x509CRL.getIssuerName();
    console.println("issuername: " + issuername);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getIssuerName failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetlastUpdate() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let lastUpdate = x509CRL.getLastUpdate();
    console.println("lastUpdate: " + lastUpdate);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getLastUpdate failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetnextUpdate() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let nextUpdate = x509CRL.getNextUpdate();
    console.println("nextUpdate: " + nextUpdate);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getNextUpdate failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetRevokedCertificates() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let serialNumber = BigInt(1000);
    let revokedCertificates = x509CRL.getRevokedCert(serialNumber);
    console.println("getRevokedCert : " + revokedCertificates);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getRevokedCert  failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetRevokedCertWithCert() {
  let crlData2 = '-----BEGIN X509 CRL-----\n' +
  'MIIBjjB4AgEBMA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNVBAMMB1Jvb3QgQ0EXDTI0\n' +
  'MDMxOTAyMDQwN1oXDTI0MDQxODAyMDQwN1owIjAgAgEEFw0yNDAzMTkwMjA0MDZa\n' +
  'MAwwCgYDVR0VBAMKAQGgDjAMMAoGA1UdFAQDAgEAMA0GCSqGSIb3DQEBCwUAA4IB\n' +
  'AQCbjvmHxC8dW6WCS/ga73kx2b7f8I/2eVuDYyReuBiGWeJ9vDmGqimJ9VwOk+ph\n' +
  'LvG/2Zvh9I8qXxnOWeseA2C0bEshJGvXpquIjm00OUyLlK6jdfRbhXT8OyvDjqZs\n' +
  'e1IsMV7Zo11SUc8nR2d0QQ7EVDCN/XFKPsmoK7PhJnRh5gc8W3FKQ6b8H9kdjgTa\n' +
  'KQUap1OIDReVsjPBmRAbwMMLtbrAMllF7E6x7uHgHTGaK1ZPJDtsnCJ45ur3mk/o\n' +
  'HAJFwHNjNDltiEfvMSs76/X0cwitpeW4dFk6c3QtqhxJrHDD4gl8di+xHOyHXpzX\n' +
  '+i2osvdPWRia0dJCL1PCA14k\n' +
  '-----END X509 CRL-----\n';

let certData2 = '-----BEGIN CERTIFICATE-----\n' +
  'MIIDTjCCAjagAwIBAgIBBDANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdSb290\n' +
  'IENBMB4XDTI0MDMxOTAyMDQwMVoXDTM0MDMxNzAyMDQwMVowEjEQMA4GA1UEAwwH\n' +
  'ZGV2aWNlMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMIXL3e7UE/c\n' +
  'Z1dPVgRZ5L8gsQ/azuYVBvoFf7o8ksYrL7G1+qZIJjVRqZkuTirLW4GicbkIkPNW\n' +
  'eix5cDhkjkC+q5SBCOrSSTTlvX3xcOY1gMlA5MgeBfGixFusq4d5VPF2KceZ20/a\n' +
  'ygwGD0Uv0X81OERyPom/dYdJUvfaD9ifPFJ1fKIj/cPFG3yJK/ojpEfndZNdESQL\n' +
  'TkoDekilg2UGOLtY6fb9Ns37ncuIj33gCS/R9m1tgtmqCTcgOQ4hwKhjVF3InmPO\n' +
  '2BbWKvD1RUX+rHC2a2HHDQILOOtDTy8dHvE+qZlK0efrpRgoFEERJAGPi1GDGWiA\n' +
  '7UX1c4MCxIECAwEAAaOBrjCBqzAJBgNVHRMEAjAAMB0GA1UdDgQWBBQbkAcMT7ND\n' +
  'fGp3VPFzYHppZ1zxLTAfBgNVHSMEGDAWgBR0W/koCbvDtFGHUQZLM3j6HKsW2DAd\n' +
  'BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwCwYDVR0PBAQDAgeAMDIGCCsG\n' +
  'AQUFBwEBBCYwJDAiBggrBgEFBQcwAYYWaHR0cHM6Ly8xMjcuMC4wLjE6OTk5OTAN\n' +
  'BgkqhkiG9w0BAQsFAAOCAQEAF1OTzTmbklFOdZCxrF3zg9owUPJR5RB+PbuBlUfI\n' +
  '8tkGXkMltQ8PN1dv6Cq+d8BluiJdWEzqVoJa/e5SHHJyYQSOhlurRG0GBXllVQ1I\n' +
  'n1PFaI40+9X2X6wrEcdC5nbzogR1jSiksCiTcARMddj0Xrp5FMrFaaGY8M/xqzdW\n' +
  'LTDl4nfbuxtA71cIjnE4kOcaemly9/S2wYWdPktsPxQPY1nPUOeJFI7o0sH3rK0c\n' +
  'JSqtgAG8vnjK+jbx9RpkgqCsXgUbIahL573VTgxrNrsRjCuVal7XVxl/xOKXr6Er\n' +
  'Gpc+OCrXbHNZkUQE5fZH3yL2tXd7EASEb6J3aEWHfF8YBA==\n' +
  '-----END CERTIFICATE-----\n';

let certEncodingBlob2: cert.EncodingBlob = {
  data: utils.stringToUint8Array(certData2),
  encodingFormat: cert.EncodingFormat.FORMAT_PEM
};

let encodingBlob2: cert.EncodingBlob = {
  data: utils.stringToUint8Array(crlData2),
  encodingFormat: cert.EncodingFormat.FORMAT_PEM
};
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob2);
    let x509Cert = await cert.createX509Cert(certEncodingBlob2);
    let revokedCertificates = x509CRL.getRevokedCertWithCert(x509Cert);
    console.println("getRevokedCertWithCert: " + revokedCertificates);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getRevokedCertWithCert failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetRevokedCerts() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let revokedCerts = x509CRL.getRevokedCerts();
    console.println("getRevokedCerts: " + revokedCerts);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getRevokedCerts failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetSignature() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let signature = x509CRL.getSignature();
    console.println("getSignature: " + signature);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getSignature failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetSignatureAlgName() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let signatureAlgorithm = x509CRL.getSignatureAlgName();
    console.println("getSignatureAlgName: " + signatureAlgorithm);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getSignatureAlgName failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetSignatureAlgOid() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let signatureAlgorithm = x509CRL.getSignatureAlgOid();
    console.println("getSignatureAlgOid: " + signatureAlgorithm);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getSignatureAlgOid failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetSignatureAlgParams() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let signatureAlgorithm = x509CRL.getSignatureAlgParams();
    console.println("getSignatureAlgParams: " + signatureAlgorithm);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getSignatureAlgParams failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetTBSinfo() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let tbsinfo = x509CRL.getTBSInfo();
    console.println("getTBSinfo: " + tbsinfo);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getTBSinfo failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetExtensions() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let extensions = x509CRL.getExtensions();
    console.println("getExtensions: " + extensions);
  } catch (err) {
    if (!(err instanceof BusinessError)){
      throw err;
    }
    console.println("getExtensions failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testmatch() {
  const certData = "-----BEGIN CERTIFICATE-----\r\n" +
  "MIIC8TCCAdmgAwIBAgIIFB75m06RTHwwDQYJKoZIhvcNAQELBQAwWDELMAkGA1UE\r\n" +
  "BhMCQ04xEDAOBgNVBAgTB0ppYW5nc3UxEDAOBgNVBAcTB05hbmppbmcxCzAJBgNV\r\n" +
  "BAoTAnRzMQswCQYDVQQLEwJ0czELMAkGA1UEAxMCdHMwHhcNMjMxMTIzMDMzMjAw\r\n" +
  "WhcNMjQxMTIzMDMzMjAwWjBhMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHSmlhbmdz\r\n" +
  "dTEQMA4GA1UEBxMHTmFuamluZzEMMAoGA1UEChMDdHMxMQwwCgYDVQQLEwN0czEx\r\n" +
  "EjAQBgNVBAMTCTEyNy4wLjAuMTAqMAUGAytlcAMhALsWnY9cMNC6jzduM69vI3Ej\r\n" +
  "pUlgHtEHS8kRfmYBupJSo4GvMIGsMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFNSg\r\n" +
  "poQvfxR8A1Y4St8NjOHkRpm4MAsGA1UdDwQEAwID+DAnBgNVHSUEIDAeBggrBgEF\r\n" +
  "BQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMEMBQGA1UdEQQNMAuCCTEyNy4wLjAuMTAR\r\n" +
  "BglghkgBhvhCAQEEBAMCBkAwHgYJYIZIAYb4QgENBBEWD3hjYSBjZXJ0aWZpY2F0\r\n" +
  "ZTANBgkqhkiG9w0BAQsFAAOCAQEAfnLmPF6BtAUCZ9pjt1ITdXc5M4LJfMw5IPcv\r\n" +
  "fUAvhdaUXtqBQcjGCWtDdhyb1n5Xp+N7oKz/Cnn0NGFTwVArtFiQ5NEP2CmrckLh\r\n" +
  "Da4VnsDFU+zx2Bbfwo5Ms7iArxyx0fArbMZzN9D1lZcVjiIxp1+3k1/0sdCemcY/\r\n" +
  "y7mw5NwkcczLWLBZl1/Ho8b4dlo1wTA7TZk9uu8UwYBwXDrQe6S9rMcvMcRKiJ9e\r\n" +
  "V4SYZIO7ihr8+n4LQDQP+spvX4cf925a3kyZrftfvGCJ2ZNwvsPhyumYhaBqAgSy\r\n" +
  "Up2BImymAqPi157q9EeYcQz170TtDZHGmjYzdQxhOAHRb6/IdQ==\r\n" +
  "-----END CERTIFICATE-----\r\n";
  const certEncodingBlob: cert.EncodingBlob = {
    data: utils.stringToUint8Array(certData),
    encodingFormat: cert.EncodingFormat.FORMAT_PEM,
  };
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let x509Cert = await cert.createX509Cert(certEncodingBlob);
    const param: cert.X509CRLMatchParameters = {
      issuer: [new Uint8Array([0x30, 0x58, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x07, 0x4A, 0x69, 0x61, 0x6E, 0x67, 0x73, 0x75, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x4E, 0x61, 0x6E, 0x6A, 0x69, 0x6E, 0x67, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x02, 0x74, 0x73, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x02, 0x74, 0x73, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x02, 0x74, 0x73])],
      x509Cert: x509Cert
    }
    let match = x509CRL.match(param);
    console.println("match: " + match);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("match failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetissuerX500DistinguishedName() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let issuerX500DistinguishedName = x509CRL.getIssuerX500DistinguishedName();
    console.println("getIssuerX500DistinguishedName: " + issuerX500DistinguishedName);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getIssuerX500DistinguishedName failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testToString() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let string = x509CRL.toString();
    console.println('crlToString success: ' + JSON.stringify(string));
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("toString failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testhashcode() {
  try {
    let x509CRL = await cert.createX509CRL(encodingBlob);
    let hashCode = x509CRL.hashCode();
    console.println('crlHashCode success: ' + JSON.stringify(hashCode));
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("hashCode failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

function testgetExtensionObj() {
  let crlData1 = '-----BEGIN X509 CRL-----\n' +
    'MIIB6DCB0QIBATANBgkqhkiG9w0BAQsFADCBjjELMAkGA1UEBhMCUlUxFTATBgNV\n' +
    'BAgMDNCc0L7RgdC60LLQsDELMAkGA1UECgwC0K8xCzAJBgNVBAsMAtCvMSowKAYD\n' +
    'VQQDDCHQlNC80LjRgtGA0LjQuSDQkdC10LvRj9Cy0YHQutC40LkxIjAgBgkqhkiG\n' +
    '9w0BCQEWE2JlbGRtaXRAZXhhbXBsZS5jb20XDTE3MDQyNDEzMjUzMVoXDTE3MDUy\n' +
    'NDEzMjUzMVqgDjAMMAoGA1UdFAQDAgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCF5eX+\n' +
    '1BM/BxoHU2/3pQHJgPSKevN0/K/daiFHiJl7Kb9GCwKY14B1RvbN2rUP/58Mt+aq\n' +
    'jvauf1yBzlaJQeJKZcsCmG9p6Tr1y0BJXhrq5kC0SLyNDsfGUTfuxnwmo+clHXRU\n' +
    '+gKuk+h0WkJL022ZYbJ38w588k4NT3CWVHeE23EDC264p942mlDE7en6MyL152Pe\n' +
    'Ld9YrWiq5iOIOrIbQLErq0EjwxvHG9sMiYFUa6VrwmRf26nyZ7u9RKJDP+o2dltw\n' +
    'diBaSXC3Qt3pZ8BIfv/l81lwp8Dr63SwCII2pIRplyICdQqmX/a+1q8kThXIP2Kx\n' +
    '+X48g7VE2o2X4cfy\n' +
    '-----END X509 CRL-----\n';

  let crlEncodingBlob1: cert.EncodingBlob = {
    data: utils.stringToUint8Array(crlData1),
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  };
  try {
    let x509CRL = await cert.createX509CRL(crlEncodingBlob1);
    let extensionObj = x509CRL.getExtensionsObject();
    console.println('crlGetExtensionObj success');
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println("getExtensionObj failed, errCode: " + err.code + ", errMsg: " + err.message);
  }
}

export function testX509Crl() {
  console.println(">>>>>>>>>>>>>>>>>>>> X509CrlAsync");
  testX509CrlAsync();
  console.println(">>>>>>>>>>>>>>>>>>>> testIsRevoked");
  testIsRevoked();
  console.println(">>>>>>>>>>>>>>>>>>>> testGetType");
  testGetType();
  console.println(">>>>>>>>>>>>>>>>>>>> testGetEncoded");
  testGetEncoded();
  console.println(">>>>>>>>>>>>>>>>>>>> testVerifySync");
  testVerifySync();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetVersion");
  testgetVersion();
  console.println(">>>>>>>>>>>>>>>>>>>> testGetIssuerName");
  testGetIssuerName();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetlastUpdate");
  testgetlastUpdate();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetnextUpdate");
  testgetnextUpdate();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetRevokedCertificates");
  testgetRevokedCertificates();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetRevokedCertWithCert");
  testgetRevokedCertWithCert();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetRevokedCerts");
  testgetRevokedCerts();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetSignature");
  testgetSignature();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetSignatureAlgName");
  testgetSignatureAlgName();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetSignatureAlgOid");
  testgetSignatureAlgOid();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetSignatureAlgParams");
  testgetSignatureAlgParams();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetTBSinfo");
  testgetTBSinfo();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetExtensions");
  testgetExtensions();
  console.println(">>>>>>>>>>>>>>>>>>>> testmatch");
  testmatch();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetissuerX500DistinguishedName");
  testgetissuerX500DistinguishedName();
  console.println(">>>>>>>>>>>>>>>>>>>> testToString");
  testToString();
  console.println(">>>>>>>>>>>>>>>>>>>> testhashcode");
  testhashcode();
  console.println(">>>>>>>>>>>>>>>>>>>> testgetExtensionObj");
  testgetExtensionObj();
}
