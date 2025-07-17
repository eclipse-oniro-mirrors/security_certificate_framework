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
    LOGE("Can not find algorithmName! [oid]: %{public}s", oid);
    return NULL;
}

void CfPrintOpensslError(void)
{
    char szErr[LOG_PRINT_MAX_LEN] = { 0 };
    unsigned long errCode;

    errCode = ERR_get_error();
    ERR_error_string_n(errCode, szErr, LOG_PRINT_MAX_LEN);

    LOGE("[Openssl]: engine fail, error code = %{public}lu, error string = %{public}s", errCode, szErr);
}

CfResult DeepCopyDataToBlob(const unsigned char *data, uint32_t len, CfBlob *outBlob)
{
    if (data == NULL || outBlob == NULL) {
        CF_LOG_E("The input params invalid.");
        return CF_INVALID_PARAMS;
    }
    uint8_t *tmp = (uint8_t *)CfMalloc(len, 0);
    if (tmp == NULL) {
        CF_LOG_E("Failed to malloc.");
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
        LOGE("The input params invalid!");
        return CF_INVALID_PARAMS;
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
        tmp = NULL;
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
        LOGE("The input params invalid!");
        return CF_INVALID_PARAMS;
    }
    X509_NAME *x509Name = d2i_X509_NAME(NULL, &data, derLen);
    if (x509Name == NULL) {
        LOGE("x509Name is null!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    char *name = X509_NAME_oneline(x509Name, NULL, 0);
    if (name == NULL) {
        LOGE("name is null!");
        CfPrintOpensslError();
        X509_NAME_free(x509Name);
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (strlen(name) > HCF_MAX_STR_LEN) {
        LOGE("name is to long!");
        CfPrintOpensslError();
        OPENSSL_free(name);
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
    if (type == NAME_TYPE_SUBJECT) {
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
        LOGE("Invalid params!");
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
        LOGE("The input params null.");
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
        out->data = NULL;
        return CF_ERR_COPY;
    }
    out->size = len;
    return CF_SUCCESS;
}

bool CheckIsSelfSigned(const X509 *cert)
{
    if (cert == NULL) {
        return false;
    }
    bool ret = false;
    X509_NAME *issuer = X509_get_issuer_name(cert);
    if (issuer == NULL) {
        LOGE("x509 get issuer name failed!");
        CfPrintOpensslError();
        return ret;
    }

    X509_NAME *subject = X509_get_subject_name(cert);
    if (subject == NULL) {
        LOGE("x509 get subject name failed!");
        CfPrintOpensslError();
        return ret;
    }

    ret = (X509_NAME_cmp(issuer, subject) == 0);
    return ret;
}

bool CheckIsLeafCert(X509 *cert)
{
    if (cert == NULL) {
        return false;
    }

    if (X509_check_ca(cert)) {
        return false;
    }

    return true;
}

CfResult IsOrderCertChain(STACK_OF(X509) *certsChain, bool *isOrder)
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

X509 *FindCertificateBySubject(STACK_OF(X509) *certs, X509_NAME *subjectName)
{
    X509_STORE_CTX *ctx = NULL;
    X509 *cert = NULL;
    X509_OBJECT *obj = NULL;

    X509_STORE *store = X509_STORE_new();
    if (store == NULL) {
        return NULL;
    }
    for (int i = 0; i < sk_X509_num(certs); i++) {
        cert = sk_X509_value(certs, i);
        if (X509_STORE_add_cert(store, cert) != 1) {
            X509_STORE_free(store);
            return NULL;
        }
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

CfResult GetPubKeyDataFromX509(X509 *x509, CfBlob **pub)
{
    EVP_PKEY *pkey = X509_get0_pubkey(x509);
    if (pkey == NULL) {
        return CF_ERR_CRYPTO_OPERATION;
    }

    *pub = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (*pub == NULL) {
        LOGE("Failed to malloc pub key!");
        return CF_ERR_MALLOC;
    }

    int32_t size = i2d_PUBKEY(pkey, &((*pub)->data));
    if (size <= 0) {
        LOGE("Failed to convert public key to DER format");
        CfFree(*pub);
        *pub = NULL;
        return CF_INVALID_PARAMS;
    }
    (*pub)->size = (uint32_t)size;
    return CF_SUCCESS;
}

CfResult GetSubjectNameFromX509(X509 *cert, CfBlob **sub)
{
    if (cert == NULL) {
        LOGE("No certificate found in when get subject name");
        return CF_INVALID_PARAMS;
    }
    X509_NAME *name = X509_get_subject_name(cert);
    if (!name) {
        LOGE("Failed to get subject name!");
        return CF_INVALID_PARAMS;
    }
    *sub = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (*sub == NULL) {
        LOGE("Failed to malloc pub key!");
        return CF_ERR_MALLOC;
    }

    int32_t size = i2d_X509_NAME(name, &((*sub)->data));
    if (size <= 0) {
        LOGE("Failed to get subject DER data!");
        CfFree(*sub);
        *sub = NULL;
        return CF_ERR_CRYPTO_OPERATION;
    }
    (*sub)->size = (uint32_t)size;
    return CF_SUCCESS;
}

CfResult GetNameConstraintsFromX509(X509 *cert, CfBlob **name)
{
    if (cert == NULL) {
        LOGE("No certificate found in when get name constraints");
        return CF_INVALID_PARAMS;
    }
    ASN1_BIT_STRING *nc = X509_get_ext_d2i(cert, NID_name_constraints, NULL, NULL);
    if (!nc) {
        LOGE("No nameConstraints found in certificate");
        return CF_INVALID_PARAMS;
    }
    *name = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (*name == NULL) {
        LOGE("Failed to malloc pub key!");
        return CF_ERR_MALLOC;
    }
    int32_t size = i2d_ASN1_BIT_STRING(nc, &((*name)->data));
    ASN1_BIT_STRING_free(nc);
    if (size < 0) {
        LOGE("Failed to get name DER data!");
        CfFree(*name);
        *name = NULL;
        return CF_ERR_CRYPTO_OPERATION;
    }
    (*name)->size = (uint32_t)size;
    return CF_SUCCESS;
}

CfResult CopyMemFromBIO(BIO *bio, CfBlob *outBlob)
{
    if (bio == NULL || outBlob == NULL) {
        LOGE("Invalid input.");
        return CF_ERR_INTERNAL;
    }
    int len = BIO_pending(bio);
    if (len <= 0) {
        LOGE("Bio len less than or equal to 0.");
        return CF_ERR_INTERNAL;
    }
    uint8_t *buff = (uint8_t *)CfMalloc(len, 0);
    if (buff == NULL) {
        LOGE("Malloc mem for buff fail.");
        return CF_ERR_MALLOC;
    }
    if (BIO_read(bio, buff, len) <= 0) {
        LOGE("Bio read fail.");
        CfPrintOpensslError();
        CfFree(buff);
        buff = NULL;
        return CF_ERR_CRYPTO_OPERATION;
    }
    outBlob->size = (uint32_t)len;
    outBlob->data = buff;
    return CF_SUCCESS;
}

CfResult CfDeepCopyExtendedKeyUsage(const STACK_OF(ASN1_OBJECT) *extUsage,
    int32_t index, CfArray *keyUsageOut)
{
    if (extUsage == NULL || keyUsageOut == NULL) {
        LOGE("Invalid input.");
        return CF_ERR_INTERNAL;
    }
    char usage[OID_STR_MAX_LEN] = { 0 };
    int32_t resLen = OBJ_obj2txt(usage, OID_STR_MAX_LEN, sk_ASN1_OBJECT_value(extUsage, index), 1);
    if ((resLen <= 0) || (resLen >= OID_STR_MAX_LEN)) {
        LOGE("Failed to convert x509 object to text!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t len = strlen(usage) + 1;
    keyUsageOut->data[index].data = (uint8_t *)CfMalloc(len, 0);
    if (keyUsageOut->data[index].data == NULL) {
        LOGE("Failed to malloc for key usage!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(keyUsageOut->data[index].data, len, usage, len);
    keyUsageOut->data[index].size = len;
    return CF_SUCCESS;
}

CfResult CfDeepCopyAlternativeNames(const STACK_OF(GENERAL_NAME) *altNames, int32_t index, CfArray *outName)
{
    if (altNames == NULL || outName == NULL) {
        LOGE("Invalid input.");
        return CF_ERR_INTERNAL;
    }
    GENERAL_NAME *general = sk_GENERAL_NAME_value(altNames, index);
    int32_t generalType = 0;
    ASN1_STRING *ans1Str = GENERAL_NAME_get0_value(general, &generalType);
    const char *str = (const char *)ASN1_STRING_get0_data(ans1Str);
    if ((str == NULL) || (strlen(str) > HCF_MAX_STR_LEN)) {
        LOGE("Failed to get x509 altNames string in openssl!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t nameLen = strlen(str) + 1;
    outName->data[index].data = (uint8_t *)CfMalloc(nameLen, 0);
    if (outName->data[index].data == NULL) {
        LOGE("Failed to malloc for outName!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(outName->data[index].data, nameLen, str, nameLen);
    outName->data[index].size = nameLen;
    return CF_SUCCESS;
}

CfResult CfDeepCopySubAltName(
    const STACK_OF(GENERAL_NAME) * altname, int32_t index, const SubAltNameArray *subAltNameArrayOut)
{
    if (altname == NULL || subAltNameArrayOut == NULL) {
        LOGE("Invalid input.");
        return CF_ERR_INTERNAL;
    }
    GENERAL_NAME *generalName = sk_GENERAL_NAME_value(altname, index);
    if (generalName == NULL) {
        LOGE("Failed to get general name from altname!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    unsigned char *derData = NULL;
    int derLength = i2d_GENERAL_NAME(generalName, &derData);
    if (derLength <= 0 || derData == NULL) {
        LOGE("Get generalName failed!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    SubjectAlternaiveNameData *subAltNameData = &(subAltNameArrayOut->data[index]);
    subAltNameData->name.data = CfMalloc(derLength, 0);
    if (subAltNameData->name.data == NULL) {
        LOGE("Failed to malloc for sub alt name data!");
        OPENSSL_free(derData);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(subAltNameData->name.data, derLength, derData, derLength);
    subAltNameData->name.size = (uint32_t)derLength;
    subAltNameData->type = generalName->type;
    OPENSSL_free(derData);
    return CF_SUCCESS;
}

CfResult CfDeepCopyCertPolices(const CERTIFICATEPOLICIES *certPolicesIn, int32_t index, CfArray *certPolices)
{
    if (certPolicesIn == NULL || certPolices == NULL) {
        LOGE("Invalid input.");
        return CF_ERR_INTERNAL;
    }
    POLICYINFO *policy = sk_POLICYINFO_value(certPolicesIn, index);
    if (policy == NULL) {
        LOGE("Failed to get policy info from cert policies!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    ASN1_OBJECT *policyOid = policy->policyid;
    char policyBuff[OID_STR_MAX_LEN] = { 0 };
    int32_t resLen = OBJ_obj2txt(policyBuff, OID_STR_MAX_LEN, policyOid, 1);
    if ((resLen <= 0) || (resLen >= OID_STR_MAX_LEN)) {
        LOGE("Failed to convert x509 object to text!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t len = strlen(policyBuff) + 1;
    certPolices->data[index].data = (uint8_t *)CfMalloc(len, 0);
    if (certPolices->data[index].data == NULL) {
        LOGE("Failed to malloc for cert policies!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(certPolices->data[index].data, len, policyBuff, len);
    certPolices->data[index].size = len;
    return CF_SUCCESS;
}

static CfResult DeepCopyURIs(ASN1_STRING *uri, uint32_t index, CfArray *outURI)
{
    if (index >= outURI->count) { /* exceed the maximum memory capacity. */
        LOGE("exceed the maximum memory capacity, uriCount = %{public}u, malloc count = %{public}u",
            index, outURI->count);
        return CF_ERR_CRYPTO_OPERATION;
    }

    const char *str = (const char *)ASN1_STRING_get0_data(uri);
    if ((str == NULL) || (strlen(str) > HCF_MAX_STR_LEN)) {
        LOGE("Failed to get CRL DP URI string in openssl!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    uint32_t uriLen = strlen(str) + 1;
    outURI->data[index].data = (uint8_t *)CfMalloc(uriLen, 0);
    if (outURI->data[index].data == NULL) {
        LOGE("Failed to malloc for outURI[%{public}u]!", index);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(outURI->data[index].data, uriLen, str, uriLen);
    outURI->data[index].size = uriLen;
    return CF_SUCCESS;
}

CfResult CfConvertAsn1String2BoolArray(const ASN1_BIT_STRING *string, CfBlob *boolArr)
{
    if (string == NULL || boolArr == NULL) {
        LOGE("Invalid input.");
        return CF_ERR_INTERNAL;
    }
    uint32_t length = (uint32_t)ASN1_STRING_length(string) * CHAR_TO_BIT_LEN;
    if ((uint32_t)(string->flags) & ASN1_STRING_FLAG_BITS_LEFT) {
        length -= (uint32_t)(string->flags) & FLAG_BIT_LEFT_NUM;
    }
    boolArr->data = (uint8_t *)CfMalloc(length, 0);
    if (boolArr->data == NULL) {
        LOGE("Failed to malloc for bit array data!");
        return CF_ERR_MALLOC;
    }
    for (uint32_t i = 0; i < length; i++) {
        boolArr->data[i] = ASN1_BIT_STRING_get_bit(string, i);
    }
    boolArr->size = length;
    return CF_SUCCESS;
}

bool CfCompareGN2Blob(const GENERAL_NAME *gen, CfBlob *nc)
{
    if (gen == NULL || nc == NULL) {
        LOGE("Invalid input.");
        return CF_ERR_INTERNAL;
    }
    unsigned char *bytes = NULL;
    unsigned char *point = NULL;
    int32_t len = 0;
    bool ret = false;
    switch (gen->type) {
        case GEN_X400:
            len = sizeof(uint8_t) * (gen->d.x400Address->length);
            bytes = (unsigned char *)gen->d.x400Address->data;
            break;
        case GEN_EDIPARTY:
            len = i2d_EDIPARTYNAME(gen->d.ediPartyName, &bytes);
            point = bytes;
            break;
        case GEN_OTHERNAME:
            len = i2d_OTHERNAME(gen->d.otherName, &bytes);
            point = bytes;
            break;
        case GEN_EMAIL:
        case GEN_DNS:
        case GEN_URI:
            len = i2d_ASN1_IA5STRING(gen->d.ia5, &bytes);
            point = bytes;
            break;
        case GEN_DIRNAME:
            len = i2d_X509_NAME(gen->d.dirn, &bytes);
            point = bytes;
            break;
        case GEN_IPADD:
            len = i2d_ASN1_OCTET_STRING(gen->d.ip, &bytes);
            point = bytes;
            break;
        case GEN_RID:
            len = i2d_ASN1_OBJECT(gen->d.rid, &bytes);
            point = bytes;
            break;
        default:
            LOGE("Unknown type.");
            break;
    }
    ret = (len == (int32_t)(nc->size)) && (strncmp((const char *)bytes, (const char *)nc->data, len) == 0);
    if (point != NULL) {
        OPENSSL_free(point);
    }

    return ret;
}

static CfResult GetDpURIFromGenName(GENERAL_NAME *genName, bool isFormatOutURI, uint32_t *uriCount, CfArray *outURI)
{
    int type = 0;
    ASN1_STRING *uri = GENERAL_NAME_get0_value(genName, &type);
    if (uri == NULL) {
        LOGE("get uri asn1 string failed");
        return CF_ERR_CRYPTO_OPERATION;
    }

    if (type != GEN_URI) {
        LOGI("not URI type, type is %{public}d", type);
        return CF_SUCCESS;
    }

    if (isFormatOutURI) {
        CfResult ret = DeepCopyURIs(uri, *uriCount, outURI);
        if (ret != CF_SUCCESS) {
            LOGE("copy URI[%{public}u] failed", *uriCount);
            return ret;
        }
    }
    *uriCount += 1;
    return CF_SUCCESS;
}

static CfResult GetDpURIFromGenNames(GENERAL_NAMES *genNames, bool isFormatOutURI, uint32_t *uriCount,
    CfArray *outURI)
{
    CfResult ret = CF_SUCCESS;
    int genNameNum = sk_GENERAL_NAME_num(genNames);
    for (int i = 0; i < genNameNum; ++i) {
        GENERAL_NAME *genName = sk_GENERAL_NAME_value(genNames, i);
        if (genName == NULL) {
            LOGE("get gen name failed!");
            ret = CF_ERR_CRYPTO_OPERATION;
            break;
        }

        ret = GetDpURIFromGenName(genName, isFormatOutURI, uriCount, outURI);
        if (ret != CF_SUCCESS) {
            LOGE("get gen name failed!");
            break;
        }
    }
    return ret;
}

static CfResult GetDpURI(STACK_OF(DIST_POINT) *crlDp, int32_t dpNumber, bool isFormatOutURI,
    uint32_t *uriCount, CfArray *outURI)
{
    CfResult ret = CF_SUCCESS;
    for (int i = 0; i < dpNumber; ++i) {
        DIST_POINT *dp = sk_DIST_POINT_value(crlDp, i);
        if (dp == NULL) {
            LOGE("get distribution point failed!");
            ret = CF_ERR_CRYPTO_OPERATION;
            break;
        }

        if (dp->distpoint == NULL || dp->distpoint->type != 0) {
            LOGI("not fullnames, continue!");
            continue;
        }

        ret = GetDpURIFromGenNames(dp->distpoint->name.fullname, isFormatOutURI, uriCount, outURI);
        if (ret != CF_SUCCESS) {
            LOGE("get dp uri from general names failed");
            break;
        }
    }
    if (ret == CF_SUCCESS && isFormatOutURI) {
        outURI->count = *uriCount;
    }
    return ret;
}

CfResult CfGetCRLDpURI(STACK_OF(DIST_POINT) *crlDp, CfArray *outURI)
{
    if (crlDp == NULL || outURI == NULL) {
        LOGE("Invalid input.");
        return CF_ERR_INTERNAL;
    }
    /* 1. get CRL distribution point URI count */
    int32_t dpNumber = sk_DIST_POINT_num(crlDp);
    uint32_t uriCount = 0;
    CfResult ret = GetDpURI(crlDp, dpNumber, false, &uriCount, outURI);
    if (ret != CF_SUCCESS) {
        LOGE("get dp URI count failed, ret = %{public}d", ret);
        return ret;
    }
    if (uriCount == 0) {
        LOGE("CRL DP URI not exist");
        return CF_NOT_EXIST;
    }
    if (uriCount > CF_MAX_URI_COUNT) {
        LOGE("uriCount[%{public}u] exceed max count", uriCount);
        return CF_ERR_CRYPTO_OPERATION;
    }

    /* 2. malloc outArray buffer */
    int32_t blobSize = (int32_t)(sizeof(CfBlob) * uriCount);
    outURI->data = (CfBlob *)CfMalloc(blobSize, 0);
    if (outURI->data == NULL) {
        LOGE("Failed to malloc for outURI array!");
        return CF_ERR_MALLOC;
    }
    outURI->count = uriCount;

    /* 2. copy CRL distribution point URIs */
    uriCount = 0;
    ret = GetDpURI(crlDp, dpNumber, true, &uriCount, outURI);
    if (ret != CF_SUCCESS) {
        LOGE("get dp URI format failed, ret = %{public}d", ret);
        CfArrayDataClearAndFree(outURI);
        return ret;
    }

    return ret;
}
