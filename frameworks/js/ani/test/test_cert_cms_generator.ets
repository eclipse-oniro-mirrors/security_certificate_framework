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

function createCsrTest() {
  let nameStr = '/CN=John Doe/OU=IT Department/O=ACME Inc./L=San Francisco/ST=California/C=US/CN=ALN C/CN=XTS';
  let prikeyEnstr: string =
    '-----BEGIN RSA PRIVATE KEY-----\n'                                  +
      'Proc-Type: 4,ENCRYPTED\n'                                           +
      'DEK-Info: AES-128-CBC,B5FFA3AEEE7176106FDDB0988B532F07\n\n'         +
      't3zNRGKp5X4BNkcsYATad/Le+94yMIX9CoNAGsBIDzQw+773UMGIoeGEYVlXWc8x\n' +
      'N1XWDinn4ytWw9x9OfUYgmNnrdkWRSaIuw+SpQfBgJip+MsNERYOHZ5TYWTR8n3k\n' +
      '7/jHY8eCgTsP3hbNtyaePIrtbTLZGZAHG1YWY5UmLaYoI1O6/Vvobx72lx3b43Tx\n' +
      '4j5lkknpLl85fcs1s4TYMOd8vEwhdpouR4VY8kfRSm44WQLtGXrce0An3MG3pXyZ\n' +
      'GhpmJyTcg0epTEYVzglENlBJrBVDL+bJ8uvHGH4tmeQb77e6ILXoxZntM7zQMMFo\n' +
      'A7dilqO6FBxu20n2TidVGCa0Yn+DZLpry2OdwVUC2nXyCHCehr3jAZz6k20FWg5B\n' +
      'EsU16yOIB+bp9BUKdTpJVtc/pmZJtnlA9pSCUVmWdltOsjjxkE94wfAUOYhO3Mvz\n' +
      'gF9KR1/bdAbLw4t7bGeuyV4N2iYr83FodLLXpupM6Qfb51+HVgHvm2aaHv2Q4sf3\n' +
      'poCVTNlegoVV9x3+7HqXY6MjlG8aU6LcWqH34ySqRBQrKL1PuDzQSY5/RmP7PUhG\n' +
      'ym4l6KbEaRC2H/XS2qKa4VCMgBCgA0hoiw4s48Xd4h2GUTuxLM9wGyW89OEaHky7\n' +
      'VE7t3O9a2zhkRTYDDYQ8QCycKhNrsKySyItRUWn/w2lXvuKM7PpAzYH7Ey3W1eZG\n' +
      'PyyeGG9exjpdIvD3tx5Hl/OWwBkW1DAzO40gT6sdD5FXzRv4fCHuCrIow5QMLF4T\n' +
      'd5Y4a6q13V4O5b73T5INmKl8rEbPGIw7WLR7BNj05QuzNcn5kA1aBFIJqsxQv46l\n' +
      '-----END RSA PRIVATE KEY-----\n';
  let priKeyInfo: cert.PrivateKeyInfo = {
    key: prikeyEnstr,
    password : "123abc"
  }
  let keyUsage: cert.CsrAttribute = {
    type: "keyUsage",
    value: "digitalSignature, keyEncipherment"
  };

  let challengePassword: cert.CsrAttribute = {
    type:"challengePassword",
    value: "123456"
  };
  let attribute: cert.CsrAttribute[] = [
    keyUsage,challengePassword
  ];
  try {
    let data = await cert.createX500DistinguishedName(nameStr);
    console.println('createX500DistinguishedName success' + data.getName("CN").toString());
    let conf: cert.CsrGenerationConfig = {
      subject: data,
      mdName: "SHA256",
      outFormat: cert.EncodingBaseFormat.PEM,
      attributes: attribute
    }
    console.println('set config success');
    try {
      console.println('generateCsr start');
      let csrStr = cert.generateCsr(priKeyInfo, conf)
      console.println('generateCsr success return str is' + csrStr)
    } catch (error: BusinessError) {
      let e: BusinessError = error as BusinessError;
      console.error('generateCsr failed, errCode: ' + e.code + ', errMsg: ' + e.message);
    }
  } catch (error: BusinessError) {
    let e: BusinessError = error as BusinessError;
    console.error('createX500DistinguishedName catch, errCode: ' + e.code + ', errMsg: ' + e.message);
  }
}


let certData = '-----BEGIN CERTIFICATE-----\n' +
  'MIICXjCCAcegAwIBAgIGAXKnJjrAMA0GCSqGSIb3DQEBCwUAMEgxCzAJBgNVBAYT\n' +
  'AkNOMQwwCgYDVQQIDANzaGExDTALBgNVBAcMBHhpYW4xDTALBgNVBAoMBHRlc3Qx\n' +
  'DTALBgNVBAMMBHRlc3QwHhcNMjQxMTIyMDkwNTIyWhcNMzQxMTIwMDkwNTIyWjBI\n' +
  'MQswCQYDVQQGEwJDTjEMMAoGA1UECAwDc2hhMQ0wCwYDVQQHDAR4aWFuMQ0wCwYD\n' +
  'VQQKDAR0ZXN0MQ0wCwYDVQQDDAR0ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\n' +
  'iQKBgQC6nCZTM16Rk2c4P/hwfVm++jqe6GCA/PXXGe4YL218q1dTKMHBGEw8kXi0\n' +
  'XLDcyyC2yUn8ywN2QSyly6ke9EE6PGfZywStLp4g2PTTWB04sS3aXT2y+fToiTXQ\n' +
  '3AxfFYRpB+EgSdSCkJs6jKXVwbzu54kEtQTfs8UdBQ9nVKaJLwIDAQABo1MwUTAd\n' +
  'BgNVHQ4EFgQU6QXnt1smb2HRSO/2zuRQnz/SDxowHwYDVR0jBBgwFoAU6QXnt1sm\n' +
  'b2HRSO/2zuRQnz/SDxowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOB\n' +
  'gQBPR/+5xzFG1XlTdgwWVvqVxvhGUkbMTGW0IviJ+jbKsi57vnVsOtFzEA6y+bYx\n' +
  'xG/kEOcwLtzeVHOQA+ZU5SVcc+qc0dfFiWjL2PSAG4bpqSTjujpuUk+g8ugixbG1\n' +
  'a26pkDJhNeB/E3eBIbeydSY0A/dIGb6vbGo6BSq2KvnWAA==\n' +
  '-----END CERTIFICATE-----\n';

let rsaStr1024: string  =
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'Proc-Type: 4,ENCRYPTED\n' +
  'DEK-Info: DES-EDE3-CBC,DB0AC6E3BEE16420\n\n' +
  '1N5xykdckthZnswMV7blxXm2RCqe/OByBfMwFI7JoXR8STtMiStd4xA3W405k1Ma\n' +
  'ExpsHgWwZaS23x+sQ1sL1dsqIPMrw1Vr+KrL20vQcCVjXPpGKauafVbtcWQ1r2PZ\n' +
  'QJ4KWP6FhUp+sGt2ItODW3dK+1GdqL22ZtANrgFzS42Wh8FSn0UMCf6RG62DK62J\n' +
  'z2jtf4XaorrGSjdTeY+fyyGfSyKidIMMBe+IXwlhCgAe7aHSaqXtMsv+BibB7PJ3\n' +
  'XmEp1D/0ptL3r46txyYcuy8jSNCkW8er93KKnlRN6KbuYZPvPNncWkzZBzV17t5d\n' +
  'QgtvVh32AKgqk5jm8YVnspOFiPrbrK9UN3IW15juFkfnhriM3IrKap4/kW+tfawZ\n' +
  'DmHkSyl8xqFK413Rv0UvYBTjOcGbs2BSJYEvp8CIjtA17SvLmNw70K2nXWuQYutY\n' +
  '+HyucPtHfEqUPQRzWTAMMntTru77u7dxo2WMMMxOtMJO5h7MAnZH9bAFiuO3ewcY\n' +
  'eEePg10d8Owcfh9G6kc0HIGT9MMLMi0mTXhpoQTuWPYuSx6uUZL1fsp1x2fuM0qn\n' +
  'bdf3+UnATYUu4tgvBHrMV7405Y6Y3PnqOFxVMeAHeOTo6UThtJ10mfeCPXGcUaHo\n' +
  'P5enw7h4145cha3+S4hNrUwj3skrtavld7tY74p4DvgZSlCMF3JAm3DhpnEMVcYP\n' +
  'Y6TkSevvxOpBvEHE41Y4VBCBwd9clcixI6cSBJKPUU4A/sc/kkNdGFcbzLQCg/zR\n' +
  '1m7YmBROb2qy4w3lv/uwVnPGLg/YV465irRaN3hgz7/1lm8STKQhmQ==\n' +
  '-----END RSA PRIVATE KEY-----\n';


function testAddSigner() {
  let certEncodingBlob: cert.EncodingBlob = {
    data: utils.stringToUint8Array(certData),
    encodingFormat: cert.EncodingFormat.FORMAT_PEM
  };
  let x509Cert = await cert.createX509Cert(certEncodingBlob);
  if (x509Cert) {
    try {
        let cmsContentType = cert.CmsContentType.SIGNED_DATA;
        let cmsGenerator = cert.createCmsGenerator(cmsContentType);
        console.println('testAddSigner createCmsGenerator success.');
        let privateKeyInfo: cert.PrivateKeyInfo = {
          key: rsaStr1024,
          password: '123456'
        };
        let config: cert.CmsSignerConfig = {
          mdName:'SHA256',
          addCert:false,
          addAttr:false,
          addSmimeCapAttr:false
        }
        cmsGenerator.addSigner(x509Cert, privateKeyInfo, config);
        console.println('testAddSigner addSigner success.');
    } catch (err: BusinessError) {
        let e: BusinessError = err as BusinessError;
        console.println('testAddSigner failed, errCode: ' + e.code + ', errMsg: ' + e.message);
    }
  }
}

function testAddCert() {
    let certEncodingBlob: cert.EncodingBlob = {
      data: utils.stringToUint8Array(certData),
      encodingFormat: cert.EncodingFormat.FORMAT_PEM
    };
    let x509Cert = await cert.createX509Cert(certEncodingBlob);
    if (x509Cert) {
        try {
            let cmsContentType = cert.CmsContentType.SIGNED_DATA;
            let cmsGenerator = cert.createCmsGenerator(cmsContentType);
            console.println('testAddCert createCmsGenerator success.');
            cmsGenerator.addCert(x509Cert);
            console.println('testAddCert addCert success.');
        } catch (err: BusinessError) {
            let e: BusinessError = err as BusinessError;
            console.println('testAddCert failed, errCode: ' + e.code + ', errMsg: ' + e.message);
        }
    }
}

function testDoFinalByPromise() {
    let certEncodingBlob: cert.EncodingBlob = {
      data: utils.stringToUint8Array(certData),
      encodingFormat: cert.EncodingFormat.FORMAT_PEM
    };
    let x509Cert = await cert.createX509Cert(certEncodingBlob);
      if (x509Cert) {
        try {
          let cmsContentType = cert.CmsContentType.SIGNED_DATA;
          let cmsGenerator = cert.createCmsGenerator(cmsContentType);
          console.println('testDoFinalByPromise createCmsGenerator success.');
          let privateKeyInfo: cert.PrivateKeyInfo = {
            key: rsaStr1024,
            password: '123456'
          };
          let config: cert.CmsSignerConfig = {
            mdName:'SHA256',
            addCert:false,
            addAttr:true,
            addSmimeCapAttr:true
          }
          cmsGenerator.addSigner(x509Cert, privateKeyInfo, config);
          console.println('testDoFinalByPromise addSigner success.');
          cmsGenerator.addCert(x509Cert);
          console.println('testDoFinalByPromise addCert success.');
          let content = new Uint8Array([1,2,3,4]);
          let optionsFinal: cert.CmsGeneratorOptions = {
            contentDataFormat : cert.CmsContentDataFormat.BINARY,
            outFormat : cert.CmsFormat.PEM,
            isDetached : true
          };
          let output = cmsGenerator.doFinalSync(content, optionsFinal);
          console.println('testDoFinalSync doFinalSync success, out = ' + output);
        } catch (err: BusinessError) {
          let e: BusinessError = err as BusinessError;
          console.println('testDoFinalSync failed, errCode: ' + e.code + ', errMsg: ' + e.message);
        }
      }
}

export function testCertCmsGenerator() {
    console.println(">>>>>>>>>>>>>>>>>>>>createCsrTest start");
    createCsrTest();
    console.println(">>>>>>>>>>>>>>>>>>>>testAddSigner start");
    testAddSigner();
    console.println(">>>>>>>>>>>>>>>>>>>>testAddCert start");
    testAddCert();
    console.println(">>>>>>>>>>>>>>>>>>>>testDoFinalByPromise start");
    testDoFinalByPromise();
}