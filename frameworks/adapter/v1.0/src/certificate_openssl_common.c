/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <securec.h>
#include <string.h>

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "config.h"

#define TIME_MON_LEN 2
#define TIME_HOUR_LEN 8
#define TIME_MIN_LEN 10
#define TIME_SEC_LEN 12

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
    uint8_t *tmp = (uint8_t *)CfMalloc(len, 0);
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

    CfBlob *tmp = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
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
    uint8_t *data = (uint8_t *)CfMalloc(length, 0);
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

char *Asn1TimeToStr(const ASN1_GENERALIZEDTIME *time)
{
    char buffer[24];
    if (time == NULL || time->data == NULL) {
        return NULL;
    }

    if (snprintf_s(buffer, sizeof(buffer), sizeof(buffer) - 1, "%.6s-", time->data + TIME_MON_LEN) < 0 ||
        snprintf_s(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), sizeof(buffer) - strlen(buffer) - 1,
            "%.2s:", time->data + TIME_HOUR_LEN) < 0 ||
        snprintf_s(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), sizeof(buffer) - strlen(buffer) - 1,
            "%.2s:", time->data + TIME_MIN_LEN) < 0 ||
        snprintf_s(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), sizeof(buffer) - strlen(buffer) - 1,
            "%.2sZ", time->data + TIME_SEC_LEN) < 0) {
        return NULL;
    }

    char *result = strdup(buffer);
    if (result == NULL) {
        return NULL;
    }

    return result;
}

bool CfArrayContains(const CfArray *self, const CfArray *sub)
{
    for (uint32_t i = 0; i < self->count; ++i) {
        bool found = false;
        for (uint32_t j = 0; j < sub->count; ++j) {
            if (self->data[i].size == sub->data[j].size &&
                memcmp(self->data[i].data, sub->data[j].data, self->data[i].size) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    return true;
}

CfResult DeepCopyDataToOut(const char *data, uint32_t len, CfBlob *out)
{
    out->data = (uint8_t *)CfMalloc(len, 0);
    if (out->data == NULL) {
        LOGE("Failed to malloc for sig algorithm params!");
        return CF_ERR_MALLOC;
    }
    if (memcpy_s(out->data, len, data, len) != EOK) {
        CF_LOG_E("Failed to memcpy_s");
        CfFree(out->data);
        return CF_ERR_COPY;
    }
    out->size = len;
    return CF_SUCCESS;
}

bool CheckIsSelfSigned(const X509 *cert)
{
    bool ret = false;
    X509_NAME *issuer = X509_get_issuer_name(cert);
    if (issuer == NULL) {
        LOGE("x509 get issuer name failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    X509_NAME *subject = X509_get_subject_name(cert);
    if (subject == NULL) {
        LOGE("x509 get subject name failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    ret = (X509_NAME_cmp(issuer, subject) == 0);
    LOGI("The ret of whether the cert is self signed is %d.", ret);
    return ret;
}

bool CheckIsLeafCert(X509 *cert)
{
    if (cert == NULL) {
        return false;
    }

    bool ret = true;
    if (X509_check_ca(cert)) {
        return false;
    }

    return ret;
}

CfResult IsOrderCertChain(STACK_OF(X509) * certsChain, bool *isOrder)
{
    int num = sk_X509_num(certsChain);
    if (num == 1) {
        LOGI("1 certs is order chain.");
        return CF_SUCCESS;
    }

    X509 *cert = NULL;
    X509 *certNext = NULL;
    X509_NAME *issuerName = NULL;
    X509_NAME *subjectName = NULL;
    for (int i = num - 1; i > 0; --i) {
        cert = sk_X509_value(certsChain, i);
        if (cert == NULL) {
            LOGE("sk X509 value is null, failed!");
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }
        certNext = sk_X509_value(certsChain, i - 1);
        if (certNext == NULL) {
            LOGE("sk X509 value is null, failed!");
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }

        subjectName = X509_get_subject_name(cert);
        if (subjectName == NULL) {
            LOGE("x509 get subject name failed!");
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }
        issuerName = X509_get_issuer_name(certNext);
        if (issuerName == NULL) {
            LOGE("x509 get subject name failed!");
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }

        if (X509_NAME_cmp(subjectName, issuerName) != 0) {
            *isOrder = false;
            LOGI("is a misOrder chain.");
            break;
        }
    }

    return CF_SUCCESS;
}

CfResult CheckSelfPubkey(X509 *cert, const EVP_PKEY *pubKey)
{
    EVP_PKEY *certPublicKey = X509_get_pubkey(cert);
    if (certPublicKey == NULL) {
        LOGE("get cert public key failed!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    int isMatch = EVP_PKEY_cmp(certPublicKey, pubKey);
    if (isMatch != CF_OPENSSL_SUCCESS) {
        LOGE("cmp cert public key failed!");
        CfPrintOpensslError();
        EVP_PKEY_free(certPublicKey);
        return CF_ERR_CRYPTO_OPERATION;
    }

    EVP_PKEY_free(certPublicKey);
    return CF_SUCCESS;
}

X509 *FindCertificateBySubject(STACK_OF(X509) * certs, X509_NAME *subjectName)
{
    X509_STORE_CTX *ctx = NULL;
    X509 *cert = NULL;
    X509_OBJECT *obj;

    X509_STORE *store = X509_STORE_new();
    if (store == NULL) {
        return NULL;
    }
    for (int i = 0; i < sk_X509_num(certs); i++) {
        cert = sk_X509_value(certs, i);
        X509_STORE_add_cert(store, cert);
    }

    if (!(ctx = X509_STORE_CTX_new())) {
        X509_STORE_free(store);
        return NULL;
    }
    if (X509_STORE_CTX_init(ctx, store, NULL, NULL) != 1) {
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        return NULL;
    }
    obj = X509_STORE_CTX_get_obj_by_subject(ctx, X509_LU_X509, subjectName);
    if (obj == NULL) {
        X509_STORE_free(store);
        X509_STORE_CTX_free(ctx);
        return NULL;
    }
    cert = X509_OBJECT_get0_X509(obj);
    X509_STORE_free(store);
    X509_OBJECT_free(obj);
    X509_STORE_CTX_free(ctx);

    return cert;
}

void SubAltNameArrayDataClearAndFree(SubAltNameArray *array)
{
    if (array == NULL) {
        LOGD("The input array is null, no need to free.");
        return;
    }
    if (array->data != NULL) {
        for (uint32_t i = 0; i < array->count; ++i) {
            CF_FREE_BLOB(array->data[i].name);
        }
        CfFree(array->data);
        array->data = NULL;
        array->count = 0;
    }
}