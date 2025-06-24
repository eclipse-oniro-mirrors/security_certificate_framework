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
  'MIIBHTCBwwICA+gwCgYIKoZIzj0EAwIwGjEYMBYGA1UEAwwPRXhhbXBsZSBSb290\n' +
  'IENBMB4XDTIzMDkwNTAyNDgyMloXDTI2MDUzMTAyNDgyMlowGjEYMBYGA1UEAwwP\n' +
  'RXhhbXBsZSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHjG74yMI\n' +
  'ueO7z3T+dyuEIrhxTg2fqgeNB3SGfsIXlsiUfLTatUsU0i/sePnrKglj2H8Abbx9\n' +
  'PK0tsW/VgqwDIDAKBggqhkjOPQQDAgNJADBGAiEApVZno/Z7WyDc/muRN1y57uaY\n' +
  'Mjrgnvp/AMdE8qmFiDwCIQCrIYdHVO1awaPgcdALZY+uLQi6mEs/oMJLUcmaag3E\n' +
  'Qw==\n' +
  '-----END CERTIFICATE-----\n';

let crlData = '-----BEGIN X509 CRL-----\n' +
  'MIHzMF4CAQMwDQYJKoZIhvcNAQEEBQAwFTETMBEGA1UEAxMKQ1JMIGlzc3VlchcN\n' +
  'MTcwODA3MTExOTU1WhcNMzIxMjE0MDA1MzIwWjAVMBMCAgPoFw0zMjEyMTQwMDUz\n' +
  'MjBaMA0GCSqGSIb3DQEBBAUAA4GBACEPHhlaCTWA42ykeaOyR0SGQIHIOUR3gcDH\n' +
  'J1LaNwiL+gDxI9rMQmlhsUGJmPIPdRs9uYyI+f854lsWYisD2PUEpn3DbEvzwYeQ\n' +
  '5SqQoPDoM+YfZZa23hoTLsu52toXobP74sf/9K501p/+8hm4ROMLBoRT86GQKY6g\n' +
  'eavsH0Q3\n' +
  '-----END X509 CRL-----\n';

function createX509Cert(
  data: Uint8Array = utils.stringToUint8Array(certData),
  encodingFormat: cert.EncodingFormat = cert.EncodingFormat.FORMAT_PEM
) {
  let encodingBlob: cert.EncodingBlob = {
    data: data,
    encodingFormat: encodingFormat
  };
  let x509Cert = await cert.createX509Cert(encodingBlob);
  return x509Cert;
}

function createX509CRL(
  data: Uint8Array = utils.stringToUint8Array(crlData),
  encodingFormat: cert.EncodingFormat = cert.EncodingFormat.FORMAT_PEM
) {
  let encodingBlob: cert.EncodingBlob = {
    data: data,
    encodingFormat: encodingFormat
  };
  let x509Crl = await cert.createX509CRL(encodingBlob);
  return x509Crl;
}

function testCreateCertCRLCollection() {
  try {
    let x509Cert = createX509Cert();
    let x509Crl = createX509CRL();
    let collection = cert.createCertCRLCollection([x509Cert], [x509Crl]);
    console.println('CertCRLCollection success');
  } catch (err: BusinessError) {
    console.println(`[error] CertCRLCollection: ${err.code} ${err.message}`);
  }
}

function testCertCRLCollectionSelectCerts()
{
  try {
    let x509Cert = createX509Cert();
    let collection = cert.createCertCRLCollection([x509Cert]);
    let dataArr = new Uint8Array([
      0x30, 0x1a, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F, 0x45, 0x78, 0x61,
      0x6D, 0x70, 0x6C, 0x65, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41
    ]);
    const param: cert.X509CertMatchParameters = {
      x509Cert,
      validDate: '20231121074700Z',
      issuer: dataArr,
      subject: dataArr,
      publicKeyAlgID: '1.2.840.10045.2.1'
    };
    let certs = await collection.selectCerts(param);
    console.println('selectCerts success');
  } catch (err: BusinessError) {
    console.println(`[error] CertCRLCollection: ${err.code} ${err.message}`);
  }
}

function testCertCRLCollectionSelectCRLs()
{
  try {
    let x509Cert = createX509Cert();
    let x509Crl = createX509CRL();
    let collection = cert.createCertCRLCollection([], [x509Crl]);
    let dataArr = new Uint8Array([
      0x30, 0x58, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x4E, 0x31,
      0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x07, 0x4A, 0x69, 0x61, 0x6E, 0x67, 0x73,
      0x75, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x07, 0x4E, 0x61, 0x6E, 0x6A,
      0x69, 0x6E, 0x67, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x02, 0x74, 0x73,
      0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x02, 0x74, 0x73, 0x31, 0x0B, 0x30,
      0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x02, 0x74, 0x73
    ]);
    let param: cert.X509CRLMatchParameters = {
      issuer: [dataArr],
      x509Cert: x509Cert
    }
    let crls = await collection.selectCRLs(param);
    console.println('selectCRLs success');
  } catch (err: BusinessError) {
    console.println(`[error] CertCRLCollection: ${err.code} ${err.message}`);
  }
}

export function testCertCrlCollection() {
  console.println(">>>>>>>>>>>>>>>>>>>> CreateCertCRLCollection");
  testCreateCertCRLCollection();
  console.println(">>>>>>>>>>>>>>>>>>>> CertCRLCollectionSelectCerts");
  testCertCRLCollectionSelectCerts();
  console.println(">>>>>>>>>>>>>>>>>>>> CertCRLCollectionSelectCRLs");
  testCertCRLCollectionSelectCRLs();
}
