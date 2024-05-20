/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "cf_adapter_cert_openssl.h"

#include "securec.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "cf_check.h"
#include "cf_log.h"
#include "cf_magic.h"
#include "cf_memory.h"
#include "cf_result.h"

#define CF_OPENSSL_ERROR_LEN 128

static void CfPrintOpensslError(void)
{
    char szErr[CF_OPENSSL_ERROR_LEN] = {0};
    unsigned long errCode = ERR_get_error();
    ERR_error_string_n(errCode, szErr, CF_OPENSSL_ERROR_LEN);

    CF_LOG_E("[Openssl]: engine fail, error code = %lu, error string = %s", errCode, szErr);
}

static int32_t DeepCopyDataToBlob(const unsigned char *data, uint32_t len, CfBlob *outBlob)
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

static int32_t CreateX509Cert(const CfEncodingBlob *inData, CfOpensslCertObj *certObj)
{
    BIO *bio = BIO_new_mem_buf(inData->data, inData->len);
    if (bio == NULL) {
        CF_LOG_E("malloc failed");
        CfPrintOpensslError();
        return CF_ERR_MALLOC;
    }

    /* format has checked in external. value is CF_FORMAT_PEM or CF_FORMAT_DER */
    if (inData->encodingFormat == CF_FORMAT_PEM) {
        certObj->x509Cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    } else { /* CF_FORMAT_DER */
        certObj->x509Cert = d2i_X509_bio(bio, NULL);
    }
    BIO_free(bio);

    if (certObj->x509Cert == NULL) {
        CF_LOG_E("Failed to create cert object");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

int32_t CfOpensslCreateCert(const CfEncodingBlob *inData, CfBase **object)
{
    if ((CfCheckEncodingBlob(inData, MAX_LEN_CERTIFICATE) != CF_SUCCESS) || (object == NULL)) {
        CF_LOG_E("invalid input params");
        return CF_INVALID_PARAMS;
    }

    CfOpensslCertObj *certObj = CfMalloc(sizeof(CfOpensslCertObj), 0);
    if (certObj == NULL) {
        CF_LOG_E("malloc failed");
        return CF_ERR_MALLOC;
    }
    certObj->base.type = CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_CERT);

    int32_t ret = CreateX509Cert(inData, certObj);
    if (ret != CF_SUCCESS) {
        CfFree(certObj);
        return ret;
    }

    *object = &certObj->base;
    return CF_SUCCESS;
}

void CfOpensslDestoryCert(CfBase **object)
{
    if ((object == NULL) || (*object == NULL)) {
        CF_LOG_E("invalid input params");
        return;
    }

    CfOpensslCertObj *certObj = (CfOpensslCertObj *)*object;
    if (certObj->base.type != CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_CERT)) {
        CF_LOG_E("the object is invalid , type = %lu", certObj->base.type);
        return;
    }

    if (certObj->x509Cert != NULL) {
        X509_free(certObj->x509Cert);
    }
    CfFree(certObj);
    *object = NULL;
    return;
}

int32_t CfOpensslVerifyCert(const CfBase *certObj, const CfBlob *pubKey)
{
    (void)certObj;
    (void)pubKey;
    return CF_SUCCESS;
}

static int32_t GetCertTbs(const CfOpensslCertObj *certObj, CfBlob *outBlob)
{
    X509 *tmp = X509_dup(certObj->x509Cert);
    if (tmp == NULL) {
        CF_LOG_E("Failed to copy x509Cert!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    unsigned char *out = NULL;
    int len = i2d_re_X509_tbs(tmp, &out);
    if (len <= 0) {
        CF_LOG_E("Failed to convert internal tbs to der format, tbs len is : %d", len);
        X509_free(tmp);
        return CF_ERR_CRYPTO_OPERATION;
    }

    int32_t ret = DeepCopyDataToBlob(out, (uint32_t)len, outBlob);
    X509_free(tmp);
    OPENSSL_free(out);
    return ret;
}

static int32_t GetCertIssuerUniqueId(const CfOpensslCertObj *certObj, CfBlob *outBlob)
{
    const ASN1_BIT_STRING *issuerUid = NULL;
    (void)X509_get0_uids(certObj->x509Cert, &issuerUid, NULL);
    if (issuerUid == NULL) {
        CF_LOG_E("Failed to get internal issuerUid!");
        return CF_NOT_EXIST;
    }

    unsigned char *out = NULL;
    int len = i2d_ASN1_BIT_STRING((ASN1_BIT_STRING *)issuerUid, &out);
    if (len <= 0) {
        CF_LOG_E("Failed to convert internal issuerUid to der format, issuerUid len is : %d", len);
        return CF_ERR_CRYPTO_OPERATION;
    }

    int32_t ret = DeepCopyDataToBlob(out, (uint32_t)len, outBlob);
    OPENSSL_free(out);
    return ret;
}

static int32_t GetCertSubjectUniqueId(const CfOpensslCertObj *certObj, CfBlob *outBlob)
{
    const ASN1_BIT_STRING *subjectUid = NULL;
    (void)X509_get0_uids(certObj->x509Cert, NULL, &subjectUid);
    if (subjectUid == NULL) {
        CF_LOG_E("Failed to get internal subjectUid!");
        return CF_NOT_EXIST;
    }

    unsigned char *out = NULL;
    int len = i2d_ASN1_BIT_STRING((ASN1_BIT_STRING *)subjectUid, &out);
    if (len <= 0) {
        CF_LOG_E("Failed to convert internal subjectUid to der format, subjectUid len is : %d", len);
        return CF_ERR_CRYPTO_OPERATION;
    }

    int32_t ret = DeepCopyDataToBlob(out, (uint32_t)len, outBlob);
    OPENSSL_free(out);
    return ret;
}

static int32_t GetCertPubKey(const CfOpensslCertObj *certObj, CfBlob *outBlob)
{
    EVP_PKEY *pubKey = (EVP_PKEY *)X509_get_pubkey(certObj->x509Cert);
    if (pubKey == NULL) {
        CfPrintOpensslError();
        CF_LOG_E("the x509 cert data is error!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    unsigned char *pubKeyBytes = NULL;
    int32_t pubKeyLen = i2d_PUBKEY(pubKey, &pubKeyBytes);
    if (pubKeyLen <= 0) {
        EVP_PKEY_free(pubKey);
        CfPrintOpensslError();
        CF_LOG_E("Failed to convert internal pubkey to der format!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    int32_t ret = DeepCopyDataToBlob(pubKeyBytes, (uint32_t)pubKeyLen, outBlob);
    EVP_PKEY_free(pubKey);
    OPENSSL_free(pubKeyBytes);
    return ret;
}

static int32_t GetCertExtensions(const CfOpensslCertObj *certObj, CfBlob *outBlob)
{
    int32_t ret = CF_SUCCESS;
    unsigned char *extbytes = NULL;
    do {
        X509_EXTENSIONS *exts = (X509_EXTENSIONS *)X509_get0_extensions(certObj->x509Cert);
        if (exts == NULL) {
            CF_LOG_E("the x509 cert data is error!");
            ret = CF_ERR_CRYPTO_OPERATION;
            break;
        }

        if (sk_X509_EXTENSION_num(exts) <= 0) { /* check whether extensions is valid */
            CF_LOG_E("No extension in certificate!");
            ret = CF_NOT_EXIST;
            break;
        }

        int32_t extLen = i2d_X509_EXTENSIONS(exts, &extbytes);
        if (extLen <= 0) {
            CF_LOG_E("get extLen failed!");
            ret = CF_ERR_CRYPTO_OPERATION;
            break;
        }

        ret = DeepCopyDataToBlob(extbytes, (uint32_t)extLen, outBlob);
    } while (0);

    if (extbytes != NULL) {
        OPENSSL_free(extbytes);
    }
    if (ret != CF_SUCCESS) {
        CfPrintOpensslError();
    }
    return ret;
}

int32_t CfOpensslGetCertItem(const CfBase *object, CfItemId id, CfBlob *outBlob)
{
    if (object == NULL || outBlob == NULL) {
        CF_LOG_E("invalid input params");
        return CF_INVALID_PARAMS;
    }

    const CfOpensslCertObj *certObj = (const CfOpensslCertObj *)object;
    if (certObj->base.type != CF_MAGIC(CF_MAGIC_TYPE_ADAPTER_RESOURCE, CF_OBJ_TYPE_CERT) ||
        certObj->x509Cert == NULL) {
        CF_LOG_E("the object is invalid , type = %lu", certObj->base.type);
        return CF_INVALID_PARAMS;
    }

    switch (id) {
        case CF_ITEM_TBS:
            return GetCertTbs(certObj, outBlob);
        case CF_ITEM_ISSUER_UNIQUE_ID:
            return GetCertIssuerUniqueId(certObj, outBlob);
        case CF_ITEM_SUBJECT_UNIQUE_ID:
            return GetCertSubjectUniqueId(certObj, outBlob);
        case CF_ITEM_EXTENSIONS:
            return GetCertExtensions(certObj, outBlob);
        case CF_ITEM_PUBLIC_KEY:
            return GetCertPubKey(certObj, outBlob);
        default:
            CF_LOG_E("the value of id is wrong, id = %d", (int32_t)id);
            return CF_INVALID_PARAMS;
    }
}

