/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "certificate_openssl_common.h"

#include <securec.h>
#include <string.h>

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "config.h"

#include <openssl/err.h>

typedef struct {
    char *oid;
    char *algorithmName;
} OidToAlgorithmName;

static const OidToAlgorithmName g_oidToNameMap[] = {
    { "1.2.840.113549.1.1.2", "MD2withRSA" },
    { "1.2.840.113549.1.1.4", "MD5withRSA" },
    { "1.2.840.113549.1.1.5", "SHA1withRSA" },
    { "1.2.840.10040.4.3", "SHA1withDSA" },
    { "1.2.840.10045.4.1", "SHA1withECDSA" },
    { "1.2.840.113549.1.1.14", "SHA224withRSA" },
    { "1.2.840.113549.1.1.11", "SHA256withRSA" },
    { "1.2.840.113549.1.1.12", "SHA384withRSA" },
    { "1.2.840.113549.1.1.13", "SHA512withRSA" },
    { "2.16.840.1.101.3.4.3.1", "SHA224withDSA" },
    { "2.16.840.1.101.3.4.3.2", "SHA256withDSA" },
    { "1.2.840.10045.4.3.1", "SHA224withECDSA" },
    { "1.2.840.10045.4.3.2", "SHA256withECDSA" },
    { "1.2.840.10045.4.3.3", "SHA384withECDSA" },
    { "1.2.840.10045.4.3.4", "SHA512withECDSA" }
};

const char *GetAlgorithmName(const char *oid)
{
    if (oid == NULL) {
        LOGE("Oid is null!");
        return NULL;
    }

    uint32_t oidCount = sizeof(g_oidToNameMap) / sizeof(OidToAlgorithmName);
    for (uint32_t i = 0; i < oidCount; i++) {
        if (strcmp(g_oidToNameMap[i].oid, oid) == 0) {
            return g_oidToNameMap[i].algorithmName;
        }
    }
    LOGE("Can not find algorithmName! [oid]: %s", oid);
    return NULL;
}

void CfPrintOpensslError(void)
{
    char szErr[LOG_PRINT_MAX_LEN] = {0};
    unsigned long errCode;

    errCode = ERR_get_error();
    ERR_error_string_n(errCode, szErr, LOG_PRINT_MAX_LEN);

    LOGE("[Openssl]: engine fail, error code = %lu, error string = %s", errCode, szErr);
}

CfResult DeepCopyDataToBlob(const unsigned char *data, uint32_t len, CfBlob *outBlob)
{
    uint8_t *tmp = (uint8_t *)CfMalloc(len);
    if (tmp == NULL) {
        CF_LOG_E("Failed to malloc");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(tmp, len, data, len);

    outBlob->data = tmp;
    outBlob->size = len;
    return CF_SUCCESS;
}

CfResult CopyExtensionsToBlob(const X509_EXTENSIONS *exts, CfBlob *outBlob)
{
    if (exts == NULL) { /* if not exist extension, return success */
        LOGD("No extension!");
        return CF_SUCCESS;
    }

    if (sk_X509_EXTENSION_num(exts) <= 0) {
        LOGD("exts number is smaller than 0");
        return CF_SUCCESS;
    }

    unsigned char *extbytes = NULL;
    int32_t extLen = i2d_X509_EXTENSIONS(exts, &extbytes);
    if (extLen <= 0 || extbytes == NULL) {
        CF_LOG_E("get extLen failed!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfResult ret = DeepCopyDataToBlob(extbytes, (uint32_t)extLen, outBlob);
    OPENSSL_free(extbytes);
    return ret;
}
