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


let extData = new Uint8Array([
    0x30, 0x40, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D,
    0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03,
    0x01, 0x01, 0xFF, 0x30, 0x0E, 0x06, 0x03, 0x55,
    0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03,
    0x02, 0x01, 0xC6, 0x30, 0x1D, 0x06, 0x03, 0x55,
    0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xE0, 0x8C,
    0x9B, 0xDB, 0x25, 0x49, 0xB3, 0xF1, 0x7C, 0x86,
    0xD6, 0xB2, 0x42, 0x87, 0x0B, 0xD0, 0x6B, 0xA0,
    0xD9, 0xE4
  ]);


let encodingBlob: cert.EncodingBlob = {
  data: extData,
  encodingFormat: cert.EncodingFormat.FORMAT_DER
};

function createCertExtensionTest() {
  let certExt = await cert.createCertExtension(encodingBlob);
  if (certExt) {
    console.println('createCertExtension success');
    try {
        let oid = new Uint8Array([0x32, 0x2e, 0x35, 0x2e, 0x32, 0x39, 0x2e, 0x31, 0x35]);
        let oidBlob: cert.DataBlob = {
          data: oid
        }
        try {
            let entry = certExt.getEntry(cert.ExtensionEntryType.EXTENSION_ENTRY_TYPE_ENTRY, oidBlob);
            console.println('ext getEntry success, entry = ' + JSON.stringify(entry));
        } catch (err) {
            if (!(err instanceof BusinessError)) {
              throw err;
            }
            let e: BusinessError = err as BusinessError;
            console.println('ext getEntry failed, errCode: ' + e.code + ', errMsg: ' + e.message);
        }
    } catch (err) {
        if (!(err instanceof BusinessError)) {
          throw err;
        }
        let e: BusinessError = err as BusinessError;
        console.println('ext getOidList failed, errCode: ' + e.code + ', errMsg: ' + e.message);
        }
    }
}

function testGetOidList() {
  try {
    let certExt = await cert.createCertExtension(encodingBlob);
    console.println('createCertExtension success');
    try {
        let oidList = certExt.getOidList(cert.ExtensionOidType.EXTENSION_OID_TYPE_ALL);
    } catch (err) {
      if (!(err instanceof BusinessError)) {
        throw err;
      }
      let e: BusinessError = err as BusinessError;
      console.println('ext getOidList failed, errCode: ' + e.code + ', errMsg: ' + e.message);
    }
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    let e: BusinessError = err as BusinessError;
    console.println('createCertExtension failed, errCode: ' + e.code + ', errMsg: ' + e.message);
  }
}

function testGetEncoded() {
  try {
    let certExt = await cert.createCertExtension(encodingBlob);
    console.println('createCertExtension success');
    let extEncodedBlob = certExt.getEncoded();
    console.println('ext getEncoded success, encoded = ' + JSON.stringify(extEncodedBlob));
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    let e: BusinessError = err as BusinessError;
    console.println('ext getEncoded failed, errCode: ' + e.code + ', errMsg: ' + e.message);
  }
}

function testCheckCA() {
  try {
    let certExt = await cert.createCertExtension(encodingBlob);
    console.println('createCertExtension success');
    let res = certExt.checkCA();
    console.println('ext checkCA success, res = ' + res);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    let e: BusinessError = err as BusinessError;
    console.println('ext checkCA failed, errCode: ' + e.code + ', errMsg: ' + e.message);
  }
}


function testHasUnsupportedCriticalExtension() {
  try {
  let extensionObj = await cert.createCertExtension(encodingBlob);
    console.println('createCertExtension success!');
    const result = extensionObj.hasUnsupportedCriticalExtension()
    console.println('has unsupported critical extension result is:' + result);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    let e: BusinessError = err as BusinessError;
    console.println('createCertExtension failed, errCode: ' + e.code + ', errMsg: ' + e.message);
  }
}

export function testCertExtension() {
  console.println(">>>>>>>>>>>>>>>>>>>> testCertExtension");
  createCertExtensionTest();
  console.println(">>>>>>>>>>>>>>>>>>>> testGetOidList");
  testGetOidList();
  console.println(">>>>>>>>>>>>>>>>>>>> testGetEncoded");
  testGetEncoded();
  console.println(">>>>>>>>>>>>>>>>>>>> testCheckCA");
  testCheckCA();
  console.println(">>>>>>>>>>>>>>>>>>>> testHasUnsupportedCriticalExtension");
  testHasUnsupportedCriticalExtension();
}