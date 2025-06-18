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

function createX500DistinguishedNameStrTest() {
  try {
    let nameStr = '/CN=John Doe/OU=IT Department/O=ACME Inc./L=San Francisco/ST=California/C=US/CN=ALN C/CN=XTS';
    let data = await cert.createX500DistinguishedName(nameStr);
    console.println('createX500DistinguishedName success, name is ' + data.getName("CN").toString());
  } catch (error: BusinessError) {
    let e: BusinessError = error as BusinessError;
    console.error('createX500DistinguishedName failed, errCode: ' + e.code + ', errMsg: ' + e.message);
  }
}

function createX500DistinguishedNameDerTest() {
  try {
    let nameDer = new Uint8Array([48,41,49,11,48,9,6,3,85,4,3,12,2,67,65,49,13,48,11,6,3,85,4,10,12,4,116,101,115,116,49,11,48,9,6,3,85,4,6,19,2,67,78]);
    let data = await cert.createX500DistinguishedName(nameDer);
    console.println('createX500DistinguishedName success, name is ' + JSON.stringify(data.getName()))
  } catch (error: BusinessError) {
    let e: BusinessError = error as BusinessError;
    console.error('createX500DistinguishedName failed, errCode: ' + e.code + ', errMsg: ' + e.message);
  }
}

function getEncodedTest() {
  try {
    let nameStr = '/CN=John Doe/OU=IT Department/O=ACME Inc./L=San Francisco/ST=California/C=US/CN=ALN C/CN=XTS';
    let data = await cert.createX500DistinguishedName(nameStr);
    let encoded = data.getEncoded();
    if (encoded) {
      console.println('getEncoded success, code is ' + encoded.data);
      console.println('getEncoded success, encoded is ' + encoded.encodingFormat);
    } else {
      console.error('getEncoded failed, encoded is null');
    }
  } catch (error: BusinessError) {
    let e: BusinessError = error as BusinessError;
    console.error('getEncoded failed, errCode: ' + e.code + ', errMsg: ' + e.message);
  }
}

export function testX500DistinguishedName() {
    console.println(">>>>>>>>>>>>>>>>>>>>createX500DistinguishedNameStrTest start");
    createX500DistinguishedNameStrTest();
    console.println(">>>>>>>>>>>>>>>>>>>>createX500DistinguishedNameDerTest start");
    createX500DistinguishedNameDerTest();
    console.println(">>>>>>>>>>>>>>>>>>>>getEncodedTest start");
    getEncodedTest();
}