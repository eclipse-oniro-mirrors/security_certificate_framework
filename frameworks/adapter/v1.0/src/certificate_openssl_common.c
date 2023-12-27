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
    char szErr[LOG_PRINT_MAX_LEN] = { 0 };
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

CfResult DeepCopyBlobToBlob(const CfBlob *inBlob, CfBlob **outBlob)
{
    if (inBlob == NULL || outBlob == NULL) {
        return CF_SUCCESS;
    }

    CfBlob *tmp = (CfBlob *)HcfMalloc(sizeof(CfBlob), 0);
    if (tmp == NULL) {
        LOGE("malloc failed");
        return CF_ERR_MALLOC;
    }
    CfResult res = DeepCopyDataToBlob((const unsigned char *)inBlob->data, inBlob->size, tmp);
    if (res != CF_SUCCESS) {
        LOGE("DeepCopyDataToBlob failed");
        CfFree(tmp);
        return res;
    }
    *outBlob = tmp;
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
    if (extLen <= 0) {
        CF_LOG_E("get extLen failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfResult ret = DeepCopyDataToBlob(extbytes, (uint32_t)extLen, outBlob);
    OPENSSL_free(extbytes);
    return ret;
}

CfResult CompareDateWithCertTime(const X509 *x509, const ASN1_TIME *inputDate)
{
    ASN1_TIME *startDate = X509_get_notBefore(x509);
    ASN1_TIME *expirationDate = X509_get_notAfter(x509);
    if ((startDate == NULL) || (expirationDate == NULL)) {
        LOGE("Date is null in x509 cert!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = CF_SUCCESS;
    /* 0: equal in ASN1_TIME_compare, -1: a < b, 1: a > b, -2: error. */
    if (ASN1_TIME_compare(inputDate, startDate) < 0) {
        LOGE("Date is not validate in x509 cert!");
        res = CF_ERR_CERT_NOT_YET_VALID;
    } else if (ASN1_TIME_compare(expirationDate, inputDate) < 0) {
        LOGE("Date is expired in x509 cert!");
        res = CF_ERR_CERT_HAS_EXPIRED;
    }
    return res;
}

CfResult ConvertNameDerDataToString(const unsigned char *data, uint32_t derLen, CfBlob *out)
{
    if (data == NULL || derLen == 0 || out == NULL) {
        LOGE("input params valid!");
        return CF_INVALID_PARAMS;
    }
    X509_NAME *x509Name = d2i_X509_NAME(NULL, &data, derLen);
    if (x509Name == NULL) {
        LOGE("x509Name is null!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    char *name = X509_NAME_oneline(x509Name, NULL, 0);
    if (name == NULL || strlen(name) > HCF_MAX_STR_LEN) {
        LOGE("name is null!");
        CfPrintOpensslError();
        X509_NAME_free(x509Name);
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = DeepCopyDataToBlob((const unsigned char *)name, strlen(name) + 1, out);
    OPENSSL_free(name);
    X509_NAME_free(x509Name);
    return res;
}

CfResult CompareNameObject(const X509 *cert, const CfBlob *derBlob, X509NameType type, bool *compareRes)
{
    X509_NAME *name = NULL;
    if (type == NAME_TYPE_SUBECT) {
        name = X509_get_subject_name(cert);
    } else if (type == NAME_TYPE_ISSUER) {
        name = X509_get_issuer_name(cert);
    }
    if (name == NULL) {
        LOGE("x509Cert get name failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    char *nameStr = X509_NAME_oneline(name, NULL, 0);
    if (nameStr == NULL) {
        LOGE("x509Cert name oneline failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfBlob nameBlob = { 0 };
    CfResult res = ConvertNameDerDataToString(derBlob->data, derBlob->size, &nameBlob);
    if (res != CF_SUCCESS) {
        LOGE("x509Cert ConvertNameDerDataToString failed!");
        OPENSSL_free(nameStr);
        return res;
    }
    uint32_t len = strlen(nameStr) + 1;
    if (len != nameBlob.size || strncmp((const char *)nameStr, (const char *)nameBlob.data, nameBlob.size) != 0) {
        LOGE("name do not match!");
        *compareRes = false;
    } else {
        *compareRes = true;
    }
    CfBlobDataFree(&nameBlob);
    OPENSSL_free(nameStr);
    return CF_SUCCESS;
}

CfResult CompareBigNum(const CfBlob *lhs, const CfBlob *rhs, int *out)
{
    if ((lhs->data == NULL) || (lhs->size == 0) || (rhs->data == NULL) || (rhs->size == 0)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }

    BIGNUM *lhsBigNum = BN_bin2bn(lhs->data, lhs->size, NULL);
    if (lhsBigNum == NULL) {
        LOGE("bin to big number fail!");
        CfPrintOpensslError();
        return CF_INVALID_PARAMS;
    }
    BIGNUM *rhsBigNum = BN_bin2bn(rhs->data, rhs->size, NULL);
    if (rhsBigNum == NULL) {
        LOGE("bin to big number fail!");
        CfPrintOpensslError();
        BN_free(lhsBigNum);
        return CF_INVALID_PARAMS;
    }
    *out = BN_cmp(lhsBigNum, rhsBigNum);
    BN_free(lhsBigNum);
    BN_free(rhsBigNum);
    return CF_SUCCESS;
}

uint8_t *GetX509EncodedDataStream(const X509 *certificate, int *dataLength)
{
    if (certificate == NULL) {
        LOGE("Failed to convert internal x509 to der format!");
        return NULL;
    }

    unsigned char *der = NULL;
    int32_t length = i2d_X509(certificate, &der);
    if (length <= 0) {
        LOGE("Failed to convert internal x509 to der format!");
        CfPrintOpensslError();
        return NULL;
    }
    uint8_t *data = (uint8_t *)HcfMalloc(length, 0);
    if (data == NULL) {
        LOGE("Failed to malloc for x509 der data!");
        OPENSSL_free(der);
        return NULL;
    }
    (void)memcpy_s(data, length, der, length);
    OPENSSL_free(der);
    *dataLength = length;

    return data;
}