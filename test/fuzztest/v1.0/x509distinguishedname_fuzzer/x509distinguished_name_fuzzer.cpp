/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "x509distinguished_name_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include "securec.h"

#include "cf_memory.h"
#include "cf_blob.h"
#include "cf_result.h"
#include "x509_distinguished_name.h"

namespace OHOS {
    static char g_nameStr[] = "/CN=John Doe/OU=IT Department/O=ACME Inc./L=San Francisco/ST=California/C=US";
    static uint8_t g_nameDer[] = {
        0x30, 0x44, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
        0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c, 0x44, 0x69,
        0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x1e, 0x30, 0x1c,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x15, 0x47, 0x65, 0x6f, 0x54, 0x72, 0x75, 0x73,
        0x74, 0x20, 0x52, 0x53, 0x41, 0x20, 0x43, 0x4e, 0x20, 0x43, 0x41, 0x20, 0x47, 0x32
    };
    static char g_queryStr[] = "CN";
    static bool g_testFlag = true;

    static void TestQuery(HcfX509DistinguishedName *x509DistinguishedNameObj)
    {
        CfBlob name = { 0 };
        (void)x509DistinguishedNameObj->getName(x509DistinguishedNameObj, nullptr, &name, nullptr);

        CfArray array = { 0 };
        CfBlob type = { 0 };
        type.data = reinterpret_cast<uint8_t *>(g_queryStr);
        type.size = strlen(g_queryStr) + 1;
        (void)x509DistinguishedNameObj->getName(x509DistinguishedNameObj, &type, nullptr, &array);
        CfArrayDataClearAndFree(&array);

        CfEncodingBlob hashCodeBlob = { 0 };
        (void)x509DistinguishedNameObj->getEncode(x509DistinguishedNameObj, &hashCodeBlob);
        CfEncodingBlobDataFree(&hashCodeBlob);
    }

    static void CreateOneDistinguishedName(void)
    {
        CfBlob nameDerStream = { 0 };
        nameDerStream.data = g_nameDer;
        nameDerStream.size = sizeof(g_nameDer) / sizeof(uint8_t) + 1;
        HcfX509DistinguishedName *x509DistinguishedNameObj = nullptr;
        CfResult res = HcfX509DistinguishedNameCreate(&nameDerStream, false, &x509DistinguishedNameObj);
        if (res != CF_SUCCESS) {
            return;
        }
        TestQuery(x509DistinguishedNameObj);
        CfObjDestroy(x509DistinguishedNameObj);

        // in param string
        x509DistinguishedNameObj = nullptr;
        CfBlob nameStrStream = { 0 };
        nameStrStream.data = reinterpret_cast<uint8_t *>(g_nameStr);
        nameStrStream.size = strlen(g_nameStr) + 1;
        res = HcfX509DistinguishedNameCreate(&nameStrStream, true, &x509DistinguishedNameObj);
        if (res != CF_SUCCESS) {
            return;
        }
        TestQuery(x509DistinguishedNameObj);
        CfObjDestroy(x509DistinguishedNameObj);
    }

    bool X509DistinguishedNameFuzzTest(const uint8_t* data, size_t size)
    {
        if (g_testFlag) {
            CreateOneDistinguishedName();
            g_testFlag = false;
        }
        if (data == nullptr || size < 1) {
            return false;
        }
        uint8_t *testData = (uint8_t *)CfMalloc(size + 1, sizeof(uint8_t));
        if (testData == nullptr) {
            return false;
        }
        CfBlob inStream = { 0 };
        inStream.data = testData;
        inStream.size = size + 1;
        HcfX509DistinguishedName *x509DistinguishedNameObj = nullptr;
        CfResult res = HcfX509DistinguishedNameCreate(&inStream, false, &x509DistinguishedNameObj);
        if (res != CF_SUCCESS) {
            CfFree(testData);
            return false;
        }
        CfObjDestroy(x509DistinguishedNameObj);

        // in param string
        x509DistinguishedNameObj = nullptr;
        res = HcfX509DistinguishedNameCreate(&inStream, true, &x509DistinguishedNameObj);
        if (res != CF_SUCCESS) {
            CfFree(testData);
            return false;
        }
        CfObjDestroy(x509DistinguishedNameObj);
        CfFree(testData);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::X509DistinguishedNameFuzzTest(data, size);
    return 0;
}
