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

#include "x509_certificate_openssl.h"

#include <securec.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "config.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "result.h"
#include "utils.h"
#include "x509_certificate.h"
#include "certificate_openssl_class.h"
#include "certificate_openssl_common.h"

#define X509_CERT_PUBLIC_KEY_OPENSSL_CLASS "X509CertPublicKeyOpensslClass"
#define OID_STR_MAX_LEN 128
#define CHAR_TO_BIT_LEN 8
#define MAX_DATE_STR_LEN 128
#define FLAG_BIT_LEFT_NUM 0x07
#define DATETIME_LEN 15
#define MIN_PATH_LEN_CONSTRAINT (-2)

typedef struct {
    HcfPubKey base;
    EVP_PKEY *pubKey;
} X509PubKeyOpensslImpl;

static CfResult GetSubjectDNX509Openssl(HcfX509CertificateSpi *self, CfBlob *out);
static CfResult GetIssuerDNX509Openssl(HcfX509CertificateSpi *self, CfBlob *out);
static CfResult GetKeyUsageX509Openssl(HcfX509CertificateSpi *self, CfBlob *boolArr);
static CfResult GetSerialNumberX509Openssl(HcfX509CertificateSpi *self, CfBlob *out);
static CfResult GetSigAlgOidX509Openssl(HcfX509CertificateSpi *self, CfBlob *out);
static CfResult GetSubjectPubKeyAlgOidX509Openssl(HcfX509CertificateSpi *self, CfBlob *out);

static const char *GetX509CertClass(void)
{
    return X509_CERT_OPENSSL_CLASS;
}

static void DestroyX509Openssl(CfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509_free(realCert->x509);
    realCert->x509 = NULL;
    CfFree(realCert);
}

static const char *GetX509CertPubKeyClass(void)
{
    return X509_CERT_PUBLIC_KEY_OPENSSL_CLASS;
}

static void DestroyX509PubKeyOpenssl(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsPubKeyClassMatch(self, GetX509CertPubKeyClass())) {
        LOGE("Input wrong class type!");
        return;
    }
    X509PubKeyOpensslImpl *impl = (X509PubKeyOpensslImpl *)self;
    if (impl->pubKey != NULL) {
        EVP_PKEY_free(impl->pubKey);
        impl->pubKey = NULL;
    }
    CfFree(impl);
}

static const char *GetPubKeyAlgorithm(HcfKey *self)
{
    (void)self;
    LOGD("Not supported!");
    return NULL;
}

static HcfResult GetPubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if (self == NULL || returnBlob == NULL) {
        LOGE("Input params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsPubKeyClassMatch((HcfObjectBase *)self, GetX509CertPubKeyClass())) {
        LOGE("Input wrong class type!");
        return HCF_INVALID_PARAMS;
    }
    X509PubKeyOpensslImpl *impl = (X509PubKeyOpensslImpl *)self;

    unsigned char *pkBytes = NULL;
    int32_t pkLen = i2d_PUBKEY(impl->pubKey, &pkBytes);
    if (pkLen <= 0) {
        CfPrintOpensslError();
        LOGE("Failed to convert internal pubkey to der format!");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    returnBlob->data = (uint8_t *)CfMalloc(pkLen, 0);
    if (returnBlob->data == NULL) {
        LOGE("Failed to malloc for sig algorithm params!");
        OPENSSL_free(pkBytes);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(returnBlob->data, pkLen, pkBytes, pkLen);
    returnBlob->len = (size_t)pkLen;

    OPENSSL_free(pkBytes);
    return HCF_SUCCESS;
}

static const char *GetPubKeyFormat(HcfKey *self)
{
    (void)self;
    LOGD("Not supported!");
    return NULL;
}

static CfResult VerifyX509Openssl(HcfX509CertificateSpi *self, HcfPubKey *key)
{
    if ((self == NULL) || (key == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass()) ||
        (!IsPubKeyClassMatch((HcfObjectBase *)key, GetX509CertPubKeyClass()))) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    X509PubKeyOpensslImpl *keyImpl = (X509PubKeyOpensslImpl *)key;
    EVP_PKEY *pubKey = keyImpl->pubKey;
    if (X509_verify(x509, pubKey) != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to verify x509 cert's signature.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    return CF_SUCCESS;
}

static CfResult GetEncodedX509Openssl(HcfX509CertificateSpi *self, CfEncodingBlob *encodedByte)
{
    if ((self == NULL) || (encodedByte == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    int32_t length = i2d_X509(x509, NULL);
    if ((length <= 0) || (x509 == NULL)) {
        LOGE("Failed to convert internal x509 to der format!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    unsigned char *der = NULL;
    (void)i2d_X509(x509, &der);
    encodedByte->data = (uint8_t *)CfMalloc(length, 0);
    if (encodedByte->data == NULL) {
        LOGE("Failed to malloc for x509 der data!");
        OPENSSL_free(der);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(encodedByte->data, length, der, length);
    OPENSSL_free(der);
    encodedByte->len = length;
    encodedByte->encodingFormat = CF_FORMAT_DER;
    return CF_SUCCESS;
}

static CfResult GetPublicKeyX509Openssl(HcfX509CertificateSpi *self, HcfPubKey **keyOut)
{
    if ((self == NULL) || (keyOut == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    EVP_PKEY *pubKey = X509_get_pubkey(x509);
    if (pubKey == NULL) {
        LOGE("Failed to get publick key from x509 cert.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    X509PubKeyOpensslImpl *keyImpl = (X509PubKeyOpensslImpl *)CfMalloc(sizeof(X509PubKeyOpensslImpl), 0);
    if (keyImpl == NULL) {
        LOGE("Failed to malloc for public key obj!");
        EVP_PKEY_free(pubKey);
        return CF_ERR_MALLOC;
    }
    keyImpl->pubKey = pubKey;
    keyImpl->base.base.base.destroy = DestroyX509PubKeyOpenssl;
    keyImpl->base.base.base.getClass = GetX509CertPubKeyClass;
    keyImpl->base.base.getEncoded = GetPubKeyEncoded;
    keyImpl->base.base.getAlgorithm = GetPubKeyAlgorithm;
    keyImpl->base.base.getFormat = GetPubKeyFormat;
    *keyOut = (HcfPubKey *)keyImpl;
    return CF_SUCCESS;
}

static CfResult CompareCertBlobX509Openssl(HcfX509CertificateSpi *self, HcfCertificate *x509Cert, bool *out)
{
    CfResult res = CF_SUCCESS;
    CfEncodingBlob encodedBlobSelf = { NULL, 0, CF_FORMAT_DER };
    CfEncodingBlob encodedBlobParam = { NULL, 0, CF_FORMAT_DER };
    if (x509Cert != NULL) {
        res = x509Cert->getEncoded(x509Cert, &encodedBlobParam);
        if (res != CF_SUCCESS) {
            LOGE("x509Cert getEncoded failed!");
            return res;
        }
        res = GetEncodedX509Openssl(self, &encodedBlobSelf);
        if (res != CF_SUCCESS) {
            LOGE("x509Cert GetEncodedX509Openssl failed!");
            CfFree(encodedBlobParam.data);
            return res;
        }
        if ((encodedBlobSelf.len != encodedBlobParam.len) ||
            (memcmp(encodedBlobSelf.data, encodedBlobParam.data, encodedBlobSelf.len) != 0)) {
            *out = false;
        }

        CfFree(encodedBlobParam.data);
        CfFree(encodedBlobSelf.data);
    }

    return res;
}

static CfResult GetAuKeyIdDNX509Openssl(HcfX509CertificateSpi *self, CfBlob *out)
{
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    AUTHORITY_KEYID *akid = X509_get_ext_d2i(x509, NID_authority_key_identifier, NULL, NULL);
    if (akid == NULL) {
        LOGE("Failed to get authority key identifier!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    unsigned char *akidBytes = NULL;
    int32_t akidLen = i2d_AUTHORITY_KEYID(akid, &akidBytes);
    if (akidLen <= 0) {
        AUTHORITY_KEYID_free(akid);
        CfPrintOpensslError();
        LOGE("Failed to convert akid to der format!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = DeepCopyDataToBlob(akidBytes, (uint32_t)akidLen, out);
    AUTHORITY_KEYID_free(akid);
    OPENSSL_free(akidBytes);
    return res;
}

static CfResult GetSubKeyIdDNX509Openssl(HcfX509CertificateSpi *self, CfBlob *out)
{
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    ASN1_OCTET_STRING *skid = X509_get_ext_d2i(x509, NID_subject_key_identifier, NULL, NULL);
    if (skid == NULL) {
        LOGE("Failed to get subject key identifier!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    unsigned char *skidBytes = NULL;
    int32_t nLen = i2d_ASN1_OCTET_STRING(skid, &skidBytes);
    if (nLen <= 0) {
        ASN1_OCTET_STRING_free(skid);
        CfPrintOpensslError();
        LOGE("Failed to convert subject key id to der format!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = DeepCopyDataToBlob(skidBytes, (uint32_t)nLen, out);
    ASN1_OCTET_STRING_free(skid);
    OPENSSL_free(skidBytes);
    return res;
}

static CfResult convertNameDerDataToString(const CfBlob *blobObj, CfBlob *cfBlobDataParam, X509NameType nameType)
{
    switch (nameType) {
        case NAME_TYPE_SUBECT:
        case NAME_TYPE_ISSUER:
            return ConvertNameDerDataToString(blobObj->data, blobObj->size, cfBlobDataParam);
        case NAME_TYPE_AUKEYID:
        case NAME_TYPE_SUBKEYID:
            return DeepCopyDataToBlob(blobObj->data, blobObj->size, cfBlobDataParam);
        default:
            return CF_INVALID_PARAMS;
    }
}

static CfResult CompareNameObjectX509Openssl(
    HcfX509CertificateSpi *self, const CfBlob *blobObj, X509NameType nameType, bool *out)
{
    CfResult res = CF_SUCCESS;
    CfBlob cfBlobDataSelf = { 0 };
    CfBlob cfBlobDataParam = { 0 };

    if (blobObj != NULL) {
        res = convertNameDerDataToString(blobObj, &cfBlobDataParam, nameType);
        if (res != CF_SUCCESS) {
            LOGE("Convert name der data to string failed!");
            return res;
        }

        switch (nameType) {
            case NAME_TYPE_SUBECT:
                res = GetSubjectDNX509Openssl(self, &cfBlobDataSelf);
                break;
            case NAME_TYPE_ISSUER:
                res = GetIssuerDNX509Openssl(self, &cfBlobDataSelf);
                break;
            case NAME_TYPE_AUKEYID:
                res = GetAuKeyIdDNX509Openssl(self, &cfBlobDataSelf);
                break;
            case NAME_TYPE_SUBKEYID:
                res = GetSubKeyIdDNX509Openssl(self, &cfBlobDataSelf);
                break;
            default:
                LOGE("Unknown nameType!");
                return CF_INVALID_PARAMS;
        }

        if (res != CF_SUCCESS) {
            LOGE("X509Cert get param object failed!");
            CfFree(cfBlobDataParam.data);
            return res;
        }

        *out =
            (cfBlobDataSelf.size == cfBlobDataParam.size) &&
            (strncmp((const char *)cfBlobDataSelf.data, (const char *)cfBlobDataParam.data, cfBlobDataSelf.size) == 0);
        CfFree(cfBlobDataSelf.data);
        CfFree(cfBlobDataParam.data);
    }

    return res;
}

static CfResult CheckValidityWithDateX509Openssl(HcfX509CertificateSpi *self, const char *date)
{
    if ((self == NULL) || (date == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    ASN1_TIME *asn1InputDate = ASN1_TIME_new();
    if (asn1InputDate == NULL) {
        LOGE("Failed to malloc for asn1 time.");
        return CF_ERR_MALLOC;
    }
    if (ASN1_TIME_set_string(asn1InputDate, date) != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to set time for asn1 time.");
        CfPrintOpensslError();
        ASN1_TIME_free(asn1InputDate);
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = CompareDateWithCertTime(x509, asn1InputDate);
    ASN1_TIME_free(asn1InputDate);
    return res;
}

static CfResult CompareKeyUsageX509Openssl(HcfX509CertificateSpi *self, const CfBlob *keyUsage, bool *out)
{
    if (keyUsage == NULL) {
        return CF_SUCCESS;
    }
    if (keyUsage->size == 0 || keyUsage->data == NULL) {
        LOGE("invalid param!");
        return CF_INVALID_PARAMS;
    }
    CfBlob cfBlobDataSelf = { 0 };
    CfResult res = GetKeyUsageX509Openssl(self, &cfBlobDataSelf);
    if ((res != CF_SUCCESS) && (res != CF_ERR_CRYPTO_OPERATION)) {
        LOGE("x509Cert GetKeyUsageX509Openssl failed!");
        return res;
    }
    /*
     * Check If the position of the true value in both arrays is the same.
     * When two array is in different length, it is considered as match success if the values of the over size part are
     * false.
     */
    uint32_t index = 0;
    for (; index < keyUsage->size && index < cfBlobDataSelf.size; ++index) {
        if ((keyUsage->data[index] & 0x01) != (cfBlobDataSelf.data[index] & 0x01)) {
            *out = false;
            break;
        }
    }
    if (!(*out)) {
        CfFree(cfBlobDataSelf.data);
        return CF_SUCCESS;
    }
    for (; index < cfBlobDataSelf.size; ++index) {
        if (cfBlobDataSelf.data[index] != 0) {
            *out = false;
            break;
        }
    }
    for (; index < keyUsage->size; ++index) {
        if (keyUsage->data[index] != 0) {
            *out = false;
            break;
        }
    }
    CfFree(cfBlobDataSelf.data);
    return CF_SUCCESS;
}

static CfResult CompareSerialNumberX509Openssl(HcfX509CertificateSpi *self, const CfBlob *serialNumber, bool *out)
{
    CfResult res = CF_SUCCESS;
    CfBlob cfBlobDataSelf = { 0 };

    if (serialNumber != NULL) {
        if (serialNumber->size == 0 || serialNumber->data == NULL) {
            LOGE("invalid param!");
            return CF_INVALID_PARAMS;
        }

        res = GetSerialNumberX509Openssl(self, &cfBlobDataSelf);
        if (res != CF_SUCCESS) {
            LOGE("x509Cert GetSerialNumberX509Openssl failed!");
            return res;
        }
        do {
            if (cfBlobDataSelf.size != serialNumber->size) {
                *out = false;
                break;
            }
            int ret = 0;
            res = CompareBigNum(&cfBlobDataSelf, serialNumber, &ret);
            if (res != CF_SUCCESS) {
                LOGE("x509Cert CompareBigNum failed!");
                break;
            }
            if (ret != 0) {
                *out = false;
                break;
            }
        } while (0);

        CfFree(cfBlobDataSelf.data);
    }

    return res;
}

static CfResult GetCertPubKey(HcfX509CertificateSpi *self, CfBlob *outBlob)
{
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    EVP_PKEY *pubKey = X509_get_pubkey(x509);
    if (pubKey == NULL) {
        CfPrintOpensslError();
        LOGE("the x509 cert data is error!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    unsigned char *pubKeyBytes = NULL;
    int32_t pubKeyLen = i2d_PUBKEY(pubKey, &pubKeyBytes);
    if (pubKeyLen <= 0) {
        EVP_PKEY_free(pubKey);
        CfPrintOpensslError();
        LOGE("Failed to convert internal pubkey to der format!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    int32_t ret = DeepCopyDataToBlob(pubKeyBytes, (uint32_t)pubKeyLen, outBlob);
    EVP_PKEY_free(pubKey);
    OPENSSL_free(pubKeyBytes);
    return ret;
}

static CfResult ComparePublicKeyX509Openssl(HcfX509CertificateSpi *self, const CfBlob *pubKey, bool *out)
{
    CfResult res = CF_SUCCESS;
    CfBlob cfBlobDataSelf = { 0, NULL };

    if (pubKey != NULL) {
        if (pubKey->size == 0 || pubKey->data == NULL) {
            LOGE("invalid param!");
            return CF_INVALID_PARAMS;
        }
        res = GetCertPubKey(self, &cfBlobDataSelf);
        if (res != CF_SUCCESS) {
            LOGE("x509Cert GetCertPubKey failed!");
            return CF_ERR_CRYPTO_OPERATION;
        }

        if (cfBlobDataSelf.size != pubKey->size) {
            *out = false;
            CfBlobDataFree(&cfBlobDataSelf);
            return res;
        }
        if (memcmp(cfBlobDataSelf.data, pubKey->data, cfBlobDataSelf.size) != 0) {
            *out = false;
        }
        CfBlobDataFree(&cfBlobDataSelf);
    }

    return res;
}

static CfResult ComparePublicKeyAlgOidX509Openssl(HcfX509CertificateSpi *self, const CfBlob *publicKeyAlgOid, bool *out)
{
    CfResult res = CF_SUCCESS;
    CfBlob cfBlobDataSelf = { 0 };

    if (publicKeyAlgOid != NULL) {
        if (!CfBlobIsStr(publicKeyAlgOid)) {
            LOGE("publicKeyAlgOid is not string!");
            return CF_INVALID_PARAMS;
        }
        res = GetSubjectPubKeyAlgOidX509Openssl(self, &cfBlobDataSelf);
        if (res != CF_SUCCESS) {
            LOGE("x509Cert ComparePublicKeyAlgOidX509Openssl failed!");
            return res;
        }

        if (cfBlobDataSelf.size != publicKeyAlgOid->size ||
            strncmp((const char *)cfBlobDataSelf.data, (const char *)publicKeyAlgOid->data, cfBlobDataSelf.size) != 0) {
            *out = false;
        }
        CfFree(cfBlobDataSelf.data);
    }

    return res;
}

static long GetVersionX509Openssl(HcfX509CertificateSpi *self)
{
    if (self == NULL) {
        LOGE("The input data is null!");
        return INVALID_VERSION;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return INVALID_VERSION;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    return X509_get_version(x509) + 1;
}

static CfResult GetSerialNumberX509Openssl(HcfX509CertificateSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }

    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    const ASN1_INTEGER *serial = X509_get0_serialNumber(x509);
    if (serial == NULL) {
        LOGE("Failed to get serial number!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    unsigned char *serialNumBytes = NULL;
    int serialNumLen = i2d_ASN1_INTEGER((ASN1_INTEGER *)serial, &serialNumBytes);
    if (serialNumLen <= SERIAL_NUMBER_HEDER_SIZE) {
        CfPrintOpensslError();
        LOGE("Failed to get serialNumLen!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfResult ret = DeepCopyDataToOut((const char *)(serialNumBytes + SERIAL_NUMBER_HEDER_SIZE),
        (uint32_t)(serialNumLen - SERIAL_NUMBER_HEDER_SIZE), out);
    OPENSSL_free(serialNumBytes);
    return ret;
}

static CfResult GetIssuerDNX509Openssl(HcfX509CertificateSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("[Get issuerDN openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    X509_NAME *issuerName = X509_get_issuer_name(x509);
    if (issuerName == NULL) {
        LOGE("Failed to get x509 issuerName in openssl!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    char *issuer = (char *)CfMalloc(HCF_MAX_STR_LEN + 1, 0);
    if (issuer == NULL) {
        LOGE("Failed to malloc for issuer buffer!");
        return CF_ERR_MALLOC;
    }

    CfResult res = CF_SUCCESS;
    do {
        X509_NAME_oneline(issuerName, issuer, HCF_MAX_STR_LEN);
        size_t length = strlen(issuer) + 1;
        if (length == 1) {
            LOGE("Failed to get oneline issuerName in openssl!");
            res = CF_ERR_CRYPTO_OPERATION;
            CfPrintOpensslError();
            break;
        }
        res = DeepCopyDataToOut(issuer, length, out);
    } while (0);
    CfFree(issuer);
    return res;
}

static CfResult GetSubjectDNX509Openssl(HcfX509CertificateSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("[Get subjectDN openssl]The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    X509_NAME *subjectName = X509_get_subject_name(x509);
    if (subjectName == NULL) {
        LOGE("Failed to get x509 subjectName in openssl!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    char *subject = (char *)CfMalloc(HCF_MAX_STR_LEN + 1, 0);
    if (subject == NULL) {
        LOGE("Failed to malloc for subject buffer!");
        return CF_ERR_MALLOC;
    }

    CfResult res = CF_SUCCESS;
    do {
        X509_NAME_oneline(subjectName, subject, HCF_MAX_STR_LEN);
        size_t length = strlen(subject) + 1;
        if (length == 1) {
            LOGE("Failed to get oneline subjectName in openssl!");
            CfPrintOpensslError();
            res = CF_ERR_CRYPTO_OPERATION;
            break;
        }
        res = DeepCopyDataToOut(subject, length, out);
    } while (0);
    CfFree(subject);
    return res;
}

static CfResult GetNotBeforeX509Openssl(HcfX509CertificateSpi *self, CfBlob *outDate)
{
    if ((self == NULL) || (outDate == NULL)) {
        LOGE("Get not before, input is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Get not before, input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    ASN1_TIME *notBeforeDate = X509_get_notBefore(x509);
    if (notBeforeDate == NULL) {
        LOGE("NotBeforeDate is null in x509 cert!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (ASN1_TIME_normalize(notBeforeDate) != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to normalize notBeforeDate!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    const char *date = (const char *)(notBeforeDate->data);
    if ((date == NULL) || (strlen(date) > HCF_MAX_STR_LEN)) {
        LOGE("Failed to get notBeforeDate data!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t length = strlen(date) + 1;
    return DeepCopyDataToOut(date, length, outDate);
}

static CfResult GetNotAfterX509Openssl(HcfX509CertificateSpi *self, CfBlob *outDate)
{
    if ((self == NULL) || (outDate == NULL)) {
        LOGE("Get not after, input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Get not after, input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    ASN1_TIME *notAfterDate = X509_get_notAfter(x509);
    if (notAfterDate == NULL) {
        LOGE("NotAfterDate is null in x509 cert!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (ASN1_TIME_normalize(notAfterDate) != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to normalize notAfterDate!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    const char *date = (const char *)(notAfterDate->data);
    if ((date == NULL) || (strlen(date) > HCF_MAX_STR_LEN)) {
        LOGE("Failed to get notAfterDate data!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t length = strlen(date) + 1;
    return DeepCopyDataToOut(date, length, outDate);
}

static CfResult GetSignatureX509Openssl(HcfX509CertificateSpi *self, CfBlob *sigOut)
{
    if ((self == NULL) || (sigOut == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    const ASN1_BIT_STRING *signature;
    X509_get0_signature(&signature, NULL, x509);
    if ((signature == NULL) || (signature->length == 0) || (signature->length > HCF_MAX_BUFFER_LEN)) {
        LOGE("Failed to get x509 signature in openssl!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    sigOut->data = (uint8_t *)CfMalloc(signature->length, 0);
    if (sigOut->data == NULL) {
        LOGE("Failed to malloc for signature data!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(sigOut->data, signature->length, signature->data, signature->length);
    sigOut->size = signature->length;
    return CF_SUCCESS;
}

static CfResult GetSigAlgNameX509Openssl(HcfX509CertificateSpi *self, CfBlob *outName)
{
    if ((self == NULL) || (outName == NULL)) {
        LOGE("[GetSigAlgName openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("[GetSigAlgName openssl] Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    const X509_ALGOR *alg;
    X509_get0_signature(NULL, &alg, x509);
    const ASN1_OBJECT *oidObj;
    X509_ALGOR_get0(&oidObj, NULL, NULL, alg);
    char oidStr[OID_STR_MAX_LEN] = { 0 };
    int32_t resLen = OBJ_obj2txt(oidStr, OID_STR_MAX_LEN, oidObj, 1);
    if ((resLen < 0) || (resLen >= OID_STR_MAX_LEN)) {
        LOGE("Failed to convert x509 object to text!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    const char *algName = GetAlgorithmName(oidStr);
    if (algName == NULL) {
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t len = strlen(algName) + 1;
    return DeepCopyDataToOut(algName, len, outName);
}

static CfResult GetSigAlgOidX509Openssl(HcfX509CertificateSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("[GetSigAlgOID openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("[GetSigAlgOID openssl] Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    const X509_ALGOR *alg;
    X509_get0_signature(NULL, &alg, x509);
    const ASN1_OBJECT *oid;
    X509_ALGOR_get0(&oid, NULL, NULL, alg);
    char algOid[OID_STR_MAX_LEN] = { 0 };
    int32_t resLen = OBJ_obj2txt(algOid, OID_STR_MAX_LEN, oid, 1);
    if ((resLen < 0) || (resLen >= OID_STR_MAX_LEN)) {
        LOGE("Failed to convert x509 object to text!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t len = strlen(algOid) + 1;
    return DeepCopyDataToOut(algOid, len, out);
}

static CfResult GetSigAlgParamsX509Openssl(HcfX509CertificateSpi *self, CfBlob *sigAlgParamsOut)
{
    if ((self == NULL) || (sigAlgParamsOut == NULL)) {
        LOGE("[GetSigAlgParams openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("[GetSigAlgParams openssl] Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    const X509_ALGOR *alg;
    X509_get0_signature(NULL, &alg, x509);
    int32_t paramType = 0;
    const void *paramValue = NULL;
    X509_ALGOR_get0(NULL, &paramType, &paramValue, alg);
    if (paramType == V_ASN1_UNDEF) {
        LOGE("get_X509_ALGOR_parameter, no parameters!");
        return CF_NOT_SUPPORT;
    }
    ASN1_TYPE *param = ASN1_TYPE_new();
    if (param == NULL) {
        LOGE("Failed to malloc for asn1 type data!");
        return CF_ERR_MALLOC;
    }
    if (ASN1_TYPE_set1(param, paramType, paramValue) != CF_OPENSSL_SUCCESS) {
        LOGE("Failed to set asn1 type in openssl!");
        CfPrintOpensslError();
        ASN1_TYPE_free(param);
        return CF_ERR_CRYPTO_OPERATION;
    }
    unsigned char *out = NULL;
    int32_t len = i2d_ASN1_TYPE(param, NULL);
    if (len <= 0) {
        LOGE("Failed to convert ASN1_TYPE!");
        CfPrintOpensslError();
        ASN1_TYPE_free(param);
        return CF_ERR_CRYPTO_OPERATION;
    }
    (void)i2d_ASN1_TYPE(param, &out);
    ASN1_TYPE_free(param);
    CfResult res = DeepCopyDataToOut((const char *)out, len, sigAlgParamsOut);
    OPENSSL_free(out);
    return res;
}

static CfResult ConvertAsn1String2BoolArray(const ASN1_BIT_STRING *string, CfBlob *boolArr)
{
    uint32_t length = ASN1_STRING_length(string) * CHAR_TO_BIT_LEN;
    if (string->flags & ASN1_STRING_FLAG_BITS_LEFT) {
        length -= string->flags & FLAG_BIT_LEFT_NUM;
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

static CfResult GetKeyUsageX509Openssl(HcfX509CertificateSpi *self, CfBlob *boolArr)
{
    if ((self == NULL) || (boolArr == NULL)) {
        LOGE("[GetKeyUsage openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;

    ASN1_BIT_STRING *keyUsage = (ASN1_BIT_STRING *)X509_get_ext_d2i(x509, NID_key_usage, NULL, NULL);
    if ((keyUsage == NULL) || (keyUsage->length <= 0)|| (keyUsage->length >= HCF_MAX_STR_LEN)) {
        LOGE("Failed to get x509 keyUsage in openssl!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = ConvertAsn1String2BoolArray(keyUsage, boolArr);
    ASN1_BIT_STRING_free(keyUsage);
    return res;
}

static CfResult DeepCopyExtendedKeyUsage(const STACK_OF(ASN1_OBJECT) *extUsage,
    int32_t i, CfArray *keyUsageOut)
{
    char usage[OID_STR_MAX_LEN] = { 0 };
    int32_t resLen = OBJ_obj2txt(usage, OID_STR_MAX_LEN, sk_ASN1_OBJECT_value(extUsage, i), 1);
    if ((resLen < 0) || (resLen >= OID_STR_MAX_LEN)) {
        LOGE("Failed to convert x509 object to text!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t len = strlen(usage) + 1;
    keyUsageOut->data[i].data = (uint8_t *)CfMalloc(len, 0);
    if (keyUsageOut->data[i].data == NULL) {
        LOGE("Failed to malloc for key usage!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(keyUsageOut->data[i].data, len, usage, len);
    keyUsageOut->data[i].size = len;
    return CF_SUCCESS;
}

static CfResult GetExtendedKeyUsageX509Openssl(HcfX509CertificateSpi *self, CfArray *keyUsageOut)
{
    if ((self == NULL) || (keyUsageOut == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    STACK_OF(ASN1_OBJECT) *extUsage = X509_get_ext_d2i(x509, NID_ext_key_usage, NULL, NULL);
    if (extUsage == NULL) {
        LOGE("Failed to get x509 extended keyUsage in openssl!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = CF_SUCCESS;
    do {
        int32_t size = sk_ASN1_OBJECT_num(extUsage);
        if (size <= 0) {
            LOGE("The extended key usage size in openssl is invalid!");
            CfPrintOpensslError();
            res = CF_ERR_CRYPTO_OPERATION;
            break;
        }
        int32_t blobSize = sizeof(CfBlob) * size;
        keyUsageOut->data = (CfBlob *)CfMalloc(blobSize, 0);
        if (keyUsageOut->data == NULL) {
            LOGE("Failed to malloc for keyUsageOut array!");
            res = CF_ERR_MALLOC;
            break;
        }
        keyUsageOut->count = (uint32_t)size;
        for (int32_t i = 0; i < size; ++i) {
            res = DeepCopyExtendedKeyUsage(extUsage, i, keyUsageOut);
            if (res != CF_SUCCESS) {
                LOGE("Falied to copy extended key usage!");
                break;
            }
        }
    } while (0);
    if (res != CF_SUCCESS) {
        CfArrayDataClearAndFree(keyUsageOut);
    }
    sk_ASN1_OBJECT_pop_free(extUsage, ASN1_OBJECT_free);
    return res;
}

static int32_t GetBasicConstraintsX509Openssl(HcfX509CertificateSpi *self)
{
    if (self == NULL) {
        LOGE("The input data is null!");
        return INVALID_CONSTRAINTS_LEN;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return INVALID_CONSTRAINTS_LEN;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    BASIC_CONSTRAINTS *constraints = (BASIC_CONSTRAINTS *)X509_get_ext_d2i(x509, NID_basic_constraints, NULL, NULL);
    if (constraints == NULL) {
        LOGE("Failed to get basic constraints in openssl!");
        return INVALID_CONSTRAINTS_LEN;
    }
    /* Path len is only valid for CA cert. */
    if (!constraints->ca) {
        BASIC_CONSTRAINTS_free(constraints);
        LOGI("The cert in not a CA!");
        return INVALID_CONSTRAINTS_LEN;
    }
    if ((constraints->pathlen == NULL) || (constraints->pathlen->type == V_ASN1_NEG_INTEGER)) {
        BASIC_CONSTRAINTS_free(constraints);
        LOGE("The cert path len is negative in openssl!");
        return INVALID_CONSTRAINTS_LEN;
    }
    long pathLen = ASN1_INTEGER_get(constraints->pathlen);
    if ((pathLen < 0) || (pathLen > INT_MAX)) {
        BASIC_CONSTRAINTS_free(constraints);
        LOGE("Get the overflow path length in openssl!");
        return INVALID_CONSTRAINTS_LEN;
    }
    BASIC_CONSTRAINTS_free(constraints);
    return (int32_t)pathLen;
}

static CfResult DeepCopyAlternativeNames(const STACK_OF(GENERAL_NAME) *altNames, int32_t i, CfArray *outName)
{
    GENERAL_NAME *general = sk_GENERAL_NAME_value(altNames, i);
    int32_t generalType = 0;
    ASN1_STRING *ans1Str = GENERAL_NAME_get0_value(general, &generalType);
    const char *str = (const char *)ASN1_STRING_get0_data(ans1Str);
    if ((str == NULL) || (strlen(str) > HCF_MAX_STR_LEN)) {
        LOGE("Failed to get x509 altNames string in openssl!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t nameLen = strlen(str) + 1;
    outName->data[i].data = (uint8_t *)CfMalloc(nameLen, 0);
    if (outName->data[i].data == NULL) {
        LOGE("Failed to malloc for outName!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(outName->data[i].data, nameLen, str, nameLen);
    outName->data[i].size = nameLen;
    return CF_SUCCESS;
}

static CfResult GetSubjectAltNamesX509Openssl(HcfX509CertificateSpi *self, CfArray *outName)
{
    if ((self == NULL) || (outName == NULL)) {
        LOGE("[GetSubjectAltNames openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    STACK_OF(GENERAL_NAME) *subjectAltName = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
    if (subjectAltName == NULL) {
        LOGE("Failed to get subjectAltName in openssl!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = CF_SUCCESS;
    do {
        int32_t size = sk_GENERAL_NAME_num(subjectAltName);
        if (size <= 0) {
            LOGE("The subjectAltName number in openssl is invalid!");
            CfPrintOpensslError();
            res = CF_ERR_CRYPTO_OPERATION;
            break;
        }
        int32_t blobSize = sizeof(CfBlob) * size;
        outName->data = (CfBlob *)CfMalloc(blobSize, 0);
        if (outName->data == NULL) {
            LOGE("Failed to malloc for subjectAltName array!");
            res = CF_ERR_MALLOC;
            break;
        }
        outName->count = (uint32_t)size;
        for (int32_t i = 0; i < size; ++i) {
            res = DeepCopyAlternativeNames(subjectAltName, i, outName);
            if (res != CF_SUCCESS) {
                LOGE("Falied to copy subjectAltName!");
                break;
            }
        }
    } while (0);
    if (res != CF_SUCCESS) {
        CfArrayDataClearAndFree(outName);
    }
    GENERAL_NAMES_free(subjectAltName);
    return res;
}

static CfResult GetIssuerAltNamesX509Openssl(HcfX509CertificateSpi *self, CfArray *outName)
{
    if ((self == NULL) || (outName == NULL)) {
        LOGE("[GetIssuerAltNames openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    STACK_OF(GENERAL_NAME) *issuerAltName = X509_get_ext_d2i(x509, NID_issuer_alt_name, NULL, NULL);
    if (issuerAltName == NULL) {
        LOGE("Failed to get issuerAltName in openssl!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = CF_SUCCESS;
    do {
        int32_t size = sk_GENERAL_NAME_num(issuerAltName);
        if (size <= 0) {
            LOGE("The issuerAltName number in openssl is invalid!");
            CfPrintOpensslError();
            res = CF_ERR_CRYPTO_OPERATION;
            break;
        }
        int32_t blobSize = sizeof(CfBlob) * size;
        outName->data = (CfBlob *)CfMalloc(blobSize, 0);
        if (outName->data == NULL) {
            LOGE("Failed to malloc for issuerAltName array!");
            res = CF_ERR_MALLOC;
            break;
        }
        outName->count = (uint32_t)size;
        for (int32_t i = 0; i < size; ++i) {
            res = DeepCopyAlternativeNames(issuerAltName, i, outName);
            if (res != CF_SUCCESS) {
                LOGE("Falied to copy issuerAltName!");
                break;
            }
        }
    } while (0);
    if (res != CF_SUCCESS) {
        CfArrayDataClearAndFree(outName);
    }
    GENERAL_NAMES_free(issuerAltName);
    return res;
}

static CfResult ToStringX509Openssl(HcfX509CertificateSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        LOGE("BIO_new error");
        return CF_ERR_MALLOC;
    }

    int len = X509_print(bio, realCert->x509);
    if (len < 0) {
        LOGE("X509_print error");
        BIO_free(bio);
        return CF_ERR_CRYPTO_OPERATION;
    }
    BUF_MEM *bufMem = NULL;
    if (BIO_get_mem_ptr(bio, &bufMem) > 0 && bufMem != NULL) {
        CfResult res = DeepCopyDataToOut(bufMem->data, bufMem->length, out);
        BIO_free(bio);
        return res;
    }

    BIO_free(bio);
    LOGE("BIO_get_mem_ptr error");
    return CF_ERR_CRYPTO_OPERATION;
}

static CfResult HashCodeX509Openssl(HcfX509CertificateSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    unsigned char *buf = NULL;
    int len = i2d_X509(x509, &buf);
    if (len < 0 || buf == NULL) {
        LOGE("i2d_X509 error");
        return CF_ERR_CRYPTO_OPERATION;
    }

    out->data = (uint8_t *)CfMalloc(SHA256_DIGEST_LENGTH, 0);
    if (out->data == NULL) {
        LOGE("CfMalloc error");
        CfFree(buf);
        return CF_ERR_MALLOC;
    }
    SHA256(buf, len, out->data);
    out->size = SHA256_DIGEST_LENGTH;
    CfFree(buf);
    return CF_SUCCESS;
}

static CfResult GetExtensionsObjectX509Openssl(HcfX509CertificateSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    int len = i2d_X509_EXTENSIONS(X509_get0_extensions(realCert->x509), &out->data);
    if (len < 0) {
        LOGE("i2d_X509_EXTENSIONS error");
        return CF_ERR_CRYPTO_OPERATION;
    }
    out->size = len;
    return CF_SUCCESS;
}

static CfResult MatchPart1(HcfX509CertificateSpi *self, const HcfX509CertMatchParams *matchParams, bool *out)
{
    CfResult res = CF_SUCCESS;
    *out = true;

    // x509Cert
    res = CompareCertBlobX509Openssl(self, matchParams->x509Cert, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to CompareCertBlob!");
        return res;
    }
    // subject
    res = CompareNameObjectX509Openssl(self, matchParams->subject, NAME_TYPE_SUBECT, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to CompareSubject!");
        return res;
    }
    // validDate
    if (matchParams->validDate != NULL) {
        if (!CfBlobIsStr(matchParams->validDate)) {
            LOGE("Invalid param!");
            return CF_INVALID_PARAMS;
        }
        res = CheckValidityWithDateX509Openssl(self, (const char *)matchParams->validDate->data);
        if ((res == CF_ERR_CERT_NOT_YET_VALID) || (res == CF_ERR_CERT_HAS_EXPIRED)) {
            *out = false;
            return CF_SUCCESS;
        }
        if (res != CF_SUCCESS) {
            LOGE("Failed to CheckValidityWithDate!");
            return res;
        }
    }
    // issuer
    res = CompareNameObjectX509Openssl(self, matchParams->issuer, NAME_TYPE_ISSUER, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to CompareIssuer!");
        return res;
    }
    return res;
}

static CfResult MatchPart2(HcfX509CertificateSpi *self, const HcfX509CertMatchParams *matchParams, bool *out)
{
    CfResult res = CF_SUCCESS;
    *out = true;

    // keyUsage
    res = CompareKeyUsageX509Openssl(self, matchParams->keyUsage, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to CompareKeyUsage!");
        return res;
    }
    // serialNumber
    res = CompareSerialNumberX509Openssl(self, matchParams->serialNumber, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to CompareSerialNumber!");
        return res;
    }
    // publicKey
    res = ComparePublicKeyX509Openssl(self, matchParams->publicKey, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to ComparePublicKey!");
        return res;
    }
    // publicKeyAlgID
    res = ComparePublicKeyAlgOidX509Openssl(self, matchParams->publicKeyAlgID, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to ComparePublicKeyAlgOid!");
        return res;
    }

    return CF_SUCCESS;
}

static CfResult DeepCopySubAltName(
    const STACK_OF(GENERAL_NAME) * altname, int32_t i, const SubAltNameArray *subAltNameArrayOut)
{
    GENERAL_NAME *generalName = sk_GENERAL_NAME_value(altname, i);
    int derLength = i2d_GENERAL_NAME(generalName, NULL);
    if (derLength <= 0) {
        LOGE("Get generalName failed!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    unsigned char *derData = (unsigned char *)CfMalloc(derLength, 0);
    unsigned char *p = derData;
    derLength = i2d_GENERAL_NAME(generalName, &p);
    if (derData == NULL) {
        LOGE("Failed to get derData!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    SubjectAlternaiveNameData *subAltNameData = &(subAltNameArrayOut->data[i]);
    subAltNameData->name.data = CfMalloc(derLength, 0);
    if (subAltNameData->name.data == NULL) {
        LOGE("Failed to malloc for sub alt name data!");
        CfFree(derData);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(subAltNameData->name.data, derLength, derData, derLength);
    subAltNameData->name.size = (uint32_t)derLength;
    subAltNameData->type = generalName->type;
    CfFree(derData);
    return CF_SUCCESS;
}

static bool IsMatch(SubjectAlternaiveNameData *subAltName, SubAltNameArray *subArraySelf)
{
    if (subAltName == NULL || subArraySelf == NULL) {
        return false;
    }
    for (uint32_t j = 0; j < subArraySelf->count; j++) {
        if (subAltName->type == subArraySelf->data[j].type &&
            subAltName->name.size == subArraySelf->data[j].name.size &&
            memcmp(subAltName->name.data, subArraySelf->data[j].name.data, subAltName->name.size) == 0) {
            return true;
        }
    }
    return false;
}

static bool CompareSubAltNameMatch(const SubAltNameArray *subArrayInput, SubAltNameArray *subArraySelf, bool matchAll)
{
    if (matchAll) {
        if (subArrayInput->count != subArraySelf->count) {
            return false;
        }
        for (uint32_t i = 0; i < subArrayInput->count; i++) {
            if (!IsMatch(&subArrayInput->data[i], subArraySelf)) {
                return false;
            }
        }
        return true;
    } else {
        for (uint32_t i = 0; i < subArrayInput->count; i++) {
            if (IsMatch(&subArrayInput->data[i], subArraySelf)) {
                return true;
            }
        }
        return false;
    }
}

static bool DetailForMinPathLenConstraint(X509 *x509, int minPathLenConstraint)
{
    if (minPathLenConstraint == MIN_PATH_LEN_CONSTRAINT) {
        X509_EXTENSION *ext = X509_get_ext(x509, X509_get_ext_by_NID(x509, NID_basic_constraints, -1));
        if (ext == NULL) {
            // when minPathLenConstraint is -2 and get basic_constraints from cert failed is ok, return true.
            return true;
        }
        BASIC_CONSTRAINTS *bc = X509V3_EXT_d2i(ext);
        if (bc == NULL) {
            return false;
        }
        bool ca = (bc->ca != 0);
        BASIC_CONSTRAINTS_free(bc);
        if (!ca) {
            return true;
        }
        return false;
    } else if (minPathLenConstraint >= 0) {
        X509_EXTENSION *ext = X509_get_ext(x509, X509_get_ext_by_NID(x509, NID_basic_constraints, -1));
        if (ext == NULL) {
            return false;
        }
        BASIC_CONSTRAINTS *bc = X509V3_EXT_d2i(ext);
        if (bc == NULL) {
            return false;
        }
        bool ca = (bc->ca != 0);
        long pathLen = ASN1_INTEGER_get(bc->pathlen);
        BASIC_CONSTRAINTS_free(bc);
        if (ca && (pathLen >= minPathLenConstraint || pathLen == -1)) {
            return true;
        }
        return false;
    } else {
        return true;
    }
}

static bool CompareGN2Blob(const GENERAL_NAME *gen, CfBlob *nc)
{
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

static CfResult CompareSubAltNameX509Openssl(
    HcfX509CertificateSpi *self, const SubAltNameArray *subAltNameArray, const bool matchAllSubAltNames, bool *out)
{
    if (subAltNameArray == NULL) {
        LOGE("The input data is null!");
        return CF_SUCCESS;
    }
    *out = false;
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    STACK_OF(GENERAL_NAME) *altname = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
    if (altname == NULL) {
        LOGE("Failed to get subject alternative name!");
        return CF_SUCCESS;
    }
    SubAltNameArray subAltNameArrayOut = { 0 };
    CfResult res = CF_SUCCESS;
    do {
        int32_t size = sk_GENERAL_NAME_num(altname);
        if (size <= 0) {
            LOGE("The altname in openssl is invalid!");
            res = CF_ERR_CRYPTO_OPERATION;
            break;
        }
        if ((size_t)size > SIZE_MAX / sizeof(SubjectAlternaiveNameData)) {
            LOGE("Size is out of max!");
            res = CF_ERR_MALLOC;
            break;
        }
        int32_t blobSize = sizeof(SubjectAlternaiveNameData) * size;
        subAltNameArrayOut.data = (SubjectAlternaiveNameData *)CfMalloc(blobSize, 0);
        if (subAltNameArrayOut.data == NULL) {
            LOGE("Failed to malloc for subject alternative name array!");
            res = CF_ERR_MALLOC;
            break;
        }
        subAltNameArrayOut.count = (uint32_t)size;
        for (int32_t i = 0; i < size; ++i) {
            res = DeepCopySubAltName(altname, i, &subAltNameArrayOut);
            if (res != CF_SUCCESS) {
                LOGE("Falied to copy subject alternative Name!");
                break;
            }
        }
    } while (0);
    if (res == CF_SUCCESS && CompareSubAltNameMatch(subAltNameArray, &subAltNameArrayOut, matchAllSubAltNames)) {
        *out = true;
    }
    sk_GENERAL_NAME_free(altname);
    SubAltNameArrayDataClearAndFree(&subAltNameArrayOut);
    return res;
}

static CfResult ComparePathLenConstraintX509Openssl(HcfX509CertificateSpi *self, const int32_t minPath, bool *out)
{
    if (minPath < 0 && minPath != MIN_PATH_LEN_CONSTRAINT) {
        LOGE("The input minpath is invalid!");
        return CF_SUCCESS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    if (!DetailForMinPathLenConstraint(x509, minPath)) {
        *out = false;
    }
    return CF_SUCCESS;
}

static CfResult CompareExtendKeyUsageX509Openssl(HcfX509CertificateSpi *self, const CfArray *extendKeyUsage, bool *out)
{
    if (extendKeyUsage == NULL) {
        LOGE("The input data is null!");
        return CF_SUCCESS;
    }
    CfArray extendout = { 0 };
    CfResult res = GetExtendedKeyUsageX509Openssl(self, &extendout);
    if (res == CF_SUCCESS) {
        if (!CfArrayContains(extendKeyUsage, &extendout)) {
            *out = false;
        }
    }
    CfArrayDataClearAndFree(&extendout);
    return res;
}

static CfResult CompareNameConstraintsX509Openssl(HcfX509CertificateSpi *self, CfBlob *nameConstraints, bool *out)
{
    if (nameConstraints == NULL) {
        LOGE("The input data is null!");
        return CF_SUCCESS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    NAME_CONSTRAINTS *nc = X509_get_ext_d2i(x509, NID_name_constraints, NULL, NULL);
    if (nc == NULL || nc->permittedSubtrees == NULL || nc->excludedSubtrees == NULL) {
        if (nc != NULL) {
            OPENSSL_free(nc);
        }
        LOGE("Failed to get name constraints!");
        *out = false;
        return CF_SUCCESS;
    }

    int i = 0;
    for (i = 0; i < sk_GENERAL_SUBTREE_num(nc->permittedSubtrees); i++) {
        GENERAL_SUBTREE *tree = NULL;
        tree = sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, i);
        if (tree != NULL && CompareGN2Blob(tree->base, nameConstraints)) {
            OPENSSL_free(nc);
            return CF_SUCCESS;
        }
    }
    for (i = 0; i < sk_GENERAL_SUBTREE_num(nc->excludedSubtrees); i++) {
        GENERAL_SUBTREE *tree = NULL;
        tree = sk_GENERAL_SUBTREE_value(nc->excludedSubtrees, i);
        if (tree != NULL && CompareGN2Blob(tree->base, nameConstraints) == true) {
            OPENSSL_free(nc);
            return CF_SUCCESS;
        }
    }
    *out = false;
    OPENSSL_free(nc);
    return CF_SUCCESS;
}

static CfResult DeepCopyCertPolices(const CERTIFICATEPOLICIES *certPolicesIn, int32_t i, CfArray *certPolices)
{
    POLICYINFO *policy = sk_POLICYINFO_value(certPolicesIn, i);
    ASN1_OBJECT *policyOid = policy->policyid;
    char policyBuff[OID_STR_MAX_LEN] = { 0 };
    int32_t resLen = OBJ_obj2txt(policyBuff, OID_STR_MAX_LEN, policyOid, 1);
    if ((resLen < 0) || (resLen >= OID_STR_MAX_LEN)) {
        LOGE("Failed to convert x509 object to text!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t len = strlen(policyBuff) + 1;
    certPolices->data[i].data = (uint8_t *)CfMalloc(len, 0);
    if (certPolices->data[i].data == NULL) {
        LOGE("Failed to malloc for cert policies!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(certPolices->data[i].data, len, policyBuff, len);
    certPolices->data[i].size = len;
    return CF_SUCCESS;
}

static CfResult CompareCertPolicesX509Openssl(HcfX509CertificateSpi *self, CfArray *certPolices, bool *out)
{
    if (certPolices == NULL) {
        LOGE("The input data is null!");
        return CF_SUCCESS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    CERTIFICATEPOLICIES *extCpols = X509_get_ext_d2i(x509, NID_certificate_policies, NULL, NULL);
    if (extCpols == NULL) {
        LOGE("Failed to get x509 cert polices in openssl!");
        *out = false;
        return CF_SUCCESS;
    }
    CfResult res = CF_SUCCESS;
    CfArray certPolicesOut;
    do {
        int32_t size = sk_POLICYINFO_num(extCpols);
        if (size <= 0) {
            LOGE("The extended key usage size in openssl is invalid!");
            res = CF_ERR_CRYPTO_OPERATION;
            break;
        }
        if ((size_t)size > SIZE_MAX / sizeof(CfBlob)) {
            LOGE("Size is out of max!");
            res = CF_ERR_MALLOC;
            break;
        }
        int32_t blobSize = sizeof(CfBlob) * size;
        certPolicesOut.data = (CfBlob *)CfMalloc(blobSize, 0);
        if (certPolicesOut.data == NULL) {
            LOGE("Failed to malloc for certPolicesOut array!");
            res = CF_ERR_MALLOC;
            break;
        }
        certPolicesOut.count = (uint32_t)size;
        for (int32_t i = 0; i < size; ++i) {
            res = DeepCopyCertPolices(extCpols, i, &certPolicesOut);
            if (res != CF_SUCCESS) {
                LOGE("Falied to copy cert polices!");
                break;
            }
        }
    } while (0);
    if (res == CF_SUCCESS && !CfArrayContains(certPolices, &certPolicesOut)) {
        *out = false;
    }
    CERTIFICATEPOLICIES_free(extCpols);
    CfArrayDataClearAndFree(&certPolicesOut);
    return res;
}

static CfResult ComparePrivateKeyValidX509Openssl(HcfX509CertificateSpi *self, CfBlob *privateKeyValid, bool *out)
{
    if (privateKeyValid == NULL) {
        LOGE("The input data is null!");
        return CF_SUCCESS;
    }
    *out = false;
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    PKEY_USAGE_PERIOD *pKeyValid = X509_get_ext_d2i(x509, NID_private_key_usage_period, NULL, NULL);
    if (pKeyValid == NULL || pKeyValid->notBefore == NULL || pKeyValid->notAfter == NULL) {
        if (pKeyValid != NULL) {
            PKEY_USAGE_PERIOD_free(pKeyValid);
        }
        LOGE("Failed to get x509 Private key valid in openssl!");
        return CF_SUCCESS;
    }
    char *notBefore = Asn1TimeToStr(pKeyValid->notBefore);
    char *notAfter = Asn1TimeToStr(pKeyValid->notAfter);
    PKEY_USAGE_PERIOD_free(pKeyValid);
    if (notBefore == NULL || notAfter == NULL) {
        LOGE("Get original data failed");
        CfFree(notBefore);
        CfFree(notAfter);
        return CF_SUCCESS;
    }
    if (privateKeyValid->size < DATETIME_LEN || strlen(notBefore) < DATETIME_LEN || strlen(notAfter) < DATETIME_LEN) {
        LOGE("Get private key valid date is not valid!");
        CfFree(notBefore);
        CfFree(notAfter);
        return CF_INVALID_PARAMS;
    }
    if (strncmp((const char *)privateKeyValid->data, (const char *)notBefore, DATETIME_LEN) >= 0 &&
        strncmp((const char *)privateKeyValid->data, (const char *)notAfter, DATETIME_LEN) <= 0) {
        *out = true;
    }
    CfFree(notBefore);
    CfFree(notAfter);
    return CF_SUCCESS;
}

static CfResult MatchPart3(HcfX509CertificateSpi *self, const HcfX509CertMatchParams *matchParams, bool *out)
{
    CfResult res = CF_SUCCESS;
    *out = true;

    // subjectAlternativeNames
    res = CompareSubAltNameX509Openssl(
        self, matchParams->subjectAlternativeNames, matchParams->matchAllSubjectAltNames, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to compare subject alternative name!");
        return res;
    }
    // authorityKeyIdentifier
    res = CompareNameObjectX509Openssl(self, matchParams->authorityKeyIdentifier, NAME_TYPE_AUKEYID, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to compare authority key identifier!");
        return res;
    }
    // minPathLenConstraint
    res = ComparePathLenConstraintX509Openssl(self, matchParams->minPathLenConstraint, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to compare pathlen constraint!");
        return res;
    }
    // extendedKeyUsage Array<String>
    res = CompareExtendKeyUsageX509Openssl(self, matchParams->extendedKeyUsage, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to compare extended key usage!");
        return res;
    }
    // nameConstraints
    res = CompareNameConstraintsX509Openssl(self, matchParams->nameConstraints, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to compare name constraints!");
        return res;
    }
    // certPolicy Array<String>
    res = CompareCertPolicesX509Openssl(self, matchParams->certPolicy, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to compare cert polices!");
        return res;
    }
    // privateKeyValid
    res = ComparePrivateKeyValidX509Openssl(self, matchParams->privateKeyValid, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to compare private key valid!");
        return res;
    }
    // subjectKeyIdentifier
    res = CompareNameObjectX509Openssl(self, matchParams->subjectKeyIdentifier, NAME_TYPE_SUBKEYID, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to compare subject key identifier!");
        return res;
    }
    return res;
}

static CfResult MatchX509Openssl(HcfX509CertificateSpi *self, const HcfX509CertMatchParams *matchParams, bool *out)
{
    LOGI("enter MatchX509Openssl!");
    if ((self == NULL) || (matchParams == NULL) || (out == NULL)) {
        LOGE("[GetIssuerAltNames openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    CfResult res = CF_SUCCESS;
    *out = true;
    res = MatchPart1(self, matchParams, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to match part1!");
        return res;
    }

    res = MatchPart2(self, matchParams, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to match part2!");
        return res;
    }

    res = MatchPart3(self, matchParams, out);
    if (res != CF_SUCCESS || (*out == false)) {
        LOGE("Failed to match part3!");
        return res;
    }
    return CF_SUCCESS;
}

static CfResult DeepCopyURIs(ASN1_STRING *uri, uint32_t index, CfArray *outURI)
{
    if (index >= outURI->count) { /* exceed the maximum memory capacity. */
        LOGE("exceed the maximum memory capacity, uriCount = %u, malloc count = %u", index, outURI->count);
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
        LOGE("Failed to malloc for outURI[%u]!", index);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(outURI->data[index].data, uriLen, str, uriLen);
    outURI->data[index].size = uriLen;
    return CF_SUCCESS;
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
        LOGI("not URI type, type is %d", type);
        return CF_SUCCESS;
    }

    if (isFormatOutURI) {
        CfResult ret = DeepCopyURIs(uri, *uriCount, outURI);
        if (ret != CF_SUCCESS) {
            LOGE("copy URI[%u] failed", *uriCount);
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

static CfResult GetCRLDpURI(STACK_OF(DIST_POINT) *crlDp, CfArray *outURI)
{
    /* 1. get CRL distribution point URI count */
    int32_t dpNumber = sk_DIST_POINT_num(crlDp);
    uint32_t uriCount = 0;
    CfResult ret = GetDpURI(crlDp, dpNumber, false, &uriCount, outURI);
    if (ret != CF_SUCCESS) {
        LOGE("get dp URI count failed, ret = %d", ret);
        return ret;
    }
    if (uriCount == 0) {
        LOGE("CRL DP URI not exist");
        return CF_NOT_EXIST;
    }
    if (uriCount > CF_MAX_URI_COUNT) {
        LOGE("uriCount[%u] exceed max count", uriCount);
        return CF_ERR_CRYPTO_OPERATION;
    }
    LOGI("get uriCount success, uriCount = %u", uriCount);

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
        LOGE("get dp URI format failed, ret = %d", ret);
        CfArrayDataClearAndFree(outURI);
        return ret;
    }

    LOGI("get CRL dp URI success, count = %u", outURI->count);
    return ret;
}

static CfResult GetCRLDistributionPointsURIX509Openssl(HcfX509CertificateSpi *self, CfArray *outURI)
{
    if ((self == NULL) || (outURI == NULL)) {
        LOGE("[GetCRLDistributionPointsURI openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertClass())) {
        LOGE("[GetCRLDistributionPointsURI openssl] Input wrong class type!");
        return CF_INVALID_PARAMS;
    }

    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    STACK_OF(DIST_POINT) *crlDp = X509_get_ext_d2i(x509, NID_crl_distribution_points, NULL, NULL);
    if (crlDp == NULL) {
        LOGE("Failed to get crl distribution point in openssl!");
        CfPrintOpensslError();
        return CF_NOT_EXIST;
    }

    CfResult ret = GetCRLDpURI(crlDp, outURI);
    sk_DIST_POINT_pop_free(crlDp, DIST_POINT_free);
    return ret;
}

static CfResult GetSubjectPubKeyAlgOidX509Openssl(HcfX509CertificateSpi *self, CfBlob *out)
{
    CfResult res = CF_SUCCESS;
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)self;
    X509 *x509 = realCert->x509;
    EVP_PKEY *pubkey = X509_get_pubkey(x509);
    if (NULL == pubkey) {
        LOGE("Failed to get public key from x509 cert.");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    int nId = EVP_PKEY_get_base_id(pubkey);
    ASN1_OBJECT *obj = OBJ_nid2obj(nId);
    if (NULL == obj) {
        LOGE("Failed to get algObj from pubkey.");
        CfPrintOpensslError();
        EVP_PKEY_free(pubkey);
        return CF_ERR_CRYPTO_OPERATION;
    }

    char algOid[OID_STR_MAX_LEN] = { 0 };
    int32_t resLen = OBJ_obj2txt(algOid, OID_STR_MAX_LEN, obj, 1);
    if ((resLen < 0) || (resLen >= OID_STR_MAX_LEN)) {
        LOGE("Failed to convert x509 object to text!");
        CfPrintOpensslError();
        EVP_PKEY_free(pubkey);
        ASN1_OBJECT_free(obj);
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t len = strlen(algOid) + 1;
    res = DeepCopyDataToOut(algOid, len, out);
    EVP_PKEY_free(pubkey);
    ASN1_OBJECT_free(obj);
    return res;
}

static X509 *CreateX509CertInner(const CfEncodingBlob *encodingBlob)
{
    X509 *x509 = NULL;
    BIO *bio = BIO_new_mem_buf(encodingBlob->data, encodingBlob->len);
    if (bio == NULL) {
        LOGE("Openssl bio new buf failed.");
        return NULL;
    }
    LOGD("The input cert format is: %d.", encodingBlob->encodingFormat);
    if (encodingBlob->encodingFormat == CF_FORMAT_DER) {
        x509 = d2i_X509_bio(bio, NULL);
    } else if (encodingBlob->encodingFormat == CF_FORMAT_PEM) {
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    }
    BIO_free(bio);
    return x509;
}

CfResult OpensslX509CertSpiCreate(const CfEncodingBlob *inStream, HcfX509CertificateSpi **spi)
{
    if ((inStream == NULL) || (inStream->data == NULL) || (spi == NULL)) {
        LOGE("The input data blob is null!");
        return CF_INVALID_PARAMS;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)CfMalloc(sizeof(HcfOpensslX509Cert), 0);
    if (realCert == NULL) {
        LOGE("Failed to malloc for x509 instance!");
        return CF_ERR_MALLOC;
    }
    realCert->x509 = CreateX509CertInner(inStream);
    if (realCert->x509 == NULL) {
        CfFree(realCert);
        LOGE("Failed to create x509 cert from input data!");
        return CF_INVALID_PARAMS;
    }
    realCert->base.base.getClass = GetX509CertClass;
    realCert->base.base.destroy = DestroyX509Openssl;
    realCert->base.engineVerify = VerifyX509Openssl;
    realCert->base.engineGetEncoded = GetEncodedX509Openssl;
    realCert->base.engineGetPublicKey = GetPublicKeyX509Openssl;
    realCert->base.engineCheckValidityWithDate = CheckValidityWithDateX509Openssl;
    realCert->base.engineGetVersion = GetVersionX509Openssl;
    realCert->base.engineGetSerialNumber = GetSerialNumberX509Openssl;
    realCert->base.engineGetIssuerName = GetIssuerDNX509Openssl;
    realCert->base.engineGetSubjectName = GetSubjectDNX509Openssl;
    realCert->base.engineGetNotBeforeTime = GetNotBeforeX509Openssl;
    realCert->base.engineGetNotAfterTime = GetNotAfterX509Openssl;
    realCert->base.engineGetSignature = GetSignatureX509Openssl;
    realCert->base.engineGetSignatureAlgName = GetSigAlgNameX509Openssl;
    realCert->base.engineGetSignatureAlgOid = GetSigAlgOidX509Openssl;
    realCert->base.engineGetSignatureAlgParams = GetSigAlgParamsX509Openssl;
    realCert->base.engineGetKeyUsage = GetKeyUsageX509Openssl;
    realCert->base.engineGetExtKeyUsage = GetExtendedKeyUsageX509Openssl;
    realCert->base.engineGetBasicConstraints = GetBasicConstraintsX509Openssl;
    realCert->base.engineGetSubjectAltNames = GetSubjectAltNamesX509Openssl;
    realCert->base.engineGetIssuerAltNames = GetIssuerAltNamesX509Openssl;
    realCert->base.engineGetCRLDistributionPointsURI = GetCRLDistributionPointsURIX509Openssl;
    realCert->base.engineMatch = MatchX509Openssl;
    realCert->base.engineToString = ToStringX509Openssl;
    realCert->base.engineHashCode = HashCodeX509Openssl;
    realCert->base.engineGetExtensionsObject = GetExtensionsObjectX509Openssl;

    *spi = (HcfX509CertificateSpi *)realCert;
    return CF_SUCCESS;
}
