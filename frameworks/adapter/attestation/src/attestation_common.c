/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include <string.h>
#include <stdbool.h>
#include "openssl/err.h"
#include "cf_log.h"
#include "attestation_common.h"

bool CmpObjOid(ASN1_OBJECT *obj, const uint8_t *oid, uint32_t oidLen)
{
    if (obj == NULL || oid == NULL || oidLen == 0) {
        return false;
    }

    if (OBJ_length(obj) != oidLen) {
        return false;
    }

    if (memcmp(OBJ_get0_data(obj), oid, oidLen) != 0) {
        return false;
    }
    return true;
}

CfResult FindCertExt(const X509 *cert, const uint8_t *oid, uint32_t oidLen, X509_EXTENSION **extension)
{
    if (cert == NULL || oid == NULL || oidLen == 0 || extension == NULL) {
        return CF_NULL_POINTER;
    }
    const X509_EXTENSIONS *extensions = X509_get0_extensions(cert);
    if (extensions == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }

    int extCount = sk_X509_EXTENSION_num(extensions);
    if (extCount <= 0) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }

    X509_EXTENSION *tmp = NULL;
    int i;
    for (i = 0; i < extCount; i++) {
        tmp = sk_X509_EXTENSION_value(extensions, i);
        if (tmp == NULL) {
            continue;
        }
        if (CmpObjOid(X509_EXTENSION_get_object(tmp), oid, oidLen) == true) { // OBJ_create() is not thread safe
            *extension = tmp;
            return CF_SUCCESS;
        }
    }

    return CF_ERR_EXTENSION_NOT_EXIST;
}

CfResult GetOctectOrUtf8Data(ASN1_TYPE *v, CfBlob *out)
{
    if (v == NULL) {
        return CF_ERR_EXTENSION_NOT_EXIST;
    }

    if (ASN1_TYPE_get(v) == V_ASN1_OCTET_STRING) {
        out->size = (uint32_t)ASN1_STRING_length(v->value.octet_string);
        out->data = (uint8_t *)ASN1_STRING_get0_data(v->value.octet_string);
    } else if (ASN1_TYPE_get(v) == V_ASN1_UTF8STRING) {
        out->size = (uint32_t)ASN1_STRING_length(v->value.utf8string);
        out->data = (uint8_t *)ASN1_STRING_get0_data(v->value.utf8string);
    } else {
        return CF_ERR_INVALID_EXTENSION;
    }
    return CF_SUCCESS;
}

#define MAX_OPENSSL_ERROR_DEPTH 16
#define MAX_OPENSSL_ERROR_LEN 256
void ProcessOpensslError(CfResult ret)
{
    if (ret != CF_ERR_CRYPTO_OPERATION) {
        return;
    }
    char errStr[MAX_OPENSSL_ERROR_LEN] = { 0 };
    unsigned long errCode = ERR_get_error();
    uint32_t depth = MAX_OPENSSL_ERROR_DEPTH;
    while (errCode != 0 && depth > 0) {
        ERR_error_string_n(errCode, errStr, MAX_OPENSSL_ERROR_LEN);
        LOGE("Call openssl failed, error code = %{public}lu, error string = %{public}s", errCode, errStr);
        errCode = ERR_get_error();
        depth--;
    }
}
