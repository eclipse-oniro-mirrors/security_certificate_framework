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

#include "x509_crl_openssl.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "certificate_openssl_class.h"
#include "certificate_openssl_common.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "config.h"
#include "fwk_class.h"
#include "securec.h"
#include "utils.h"
#include "x509_crl.h"
#include "x509_crl_entry_openssl.h"
#include "x509_crl_spi.h"

typedef struct {
    HcfX509CrlSpi base;
    X509_CRL *crl;
    CfBlob *certIssuer;
} HcfX509CRLOpensslImpl;

typedef enum {
    CRL_MAX,
    CRL_MIN,
} X509CRLType;

#define OPENSSL_INVALID_VERSION (-1)
#define OPENSSL_ERROR 0
#define TYPE_NAME "X509"
#define OID_LENGTH 128
#define MAX_REV_NUM 256
#define MAX_SIGNATURE_LEN 8192

static const char *GetClass(void)
{
    return X509_CRL_OPENSSL_CLASS;
}

static const char *GetType(HcfX509CrlSpi *self)
{
    if (self == NULL) {
        LOGE("Invalid Paramas!");
        return NULL;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return NULL;
    }
    return TYPE_NAME;
}

static X509_CRL *GetCrl(HcfX509CrlSpi *self)
{
    if (!IsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return NULL;
    }
    return ((HcfX509CRLOpensslImpl *)self)->crl;
}

static X509 *GetX509FromCertificate(const HcfCertificate *cert)
{
    if (!IsClassMatch((CfObjectBase *)cert, HCF_X509_CERTIFICATE_CLASS)) {
        LOGE("Input wrong openssl class type!");
        return NULL;
    }
    HcfX509CertificateImpl *impl = (HcfX509CertificateImpl *)cert;
    if (!IsClassMatch((CfObjectBase *)(impl->spiObj), X509_CERT_OPENSSL_CLASS)) {
        LOGE("Input wrong openssl class type!");
        return NULL;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)(impl->spiObj);
    return realCert->x509;
}

static bool IsRevoked(HcfX509CrlSpi *self, const HcfCertificate *cert)
{
    if ((self == NULL) || (cert == NULL)) {
        LOGE("Invalid Paramas!");
        return false;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return false;
    }
    X509 *certOpenssl = GetX509FromCertificate(cert);
    if (certOpenssl == NULL) {
        LOGE("Input Cert is wrong!");
        return false;
    }
    X509_CRL *crl = ((HcfX509CRLOpensslImpl *)self)->crl;
    if (crl == NULL) {
        LOGE("crl is null!");
        return false;
    }
    X509_REVOKED *rev = NULL;
    int32_t res = X509_CRL_get0_by_cert(crl, &rev, certOpenssl);
    return (res != 0);
}

static CfResult GetEncoded(HcfX509CrlSpi *self, CfEncodingBlob *encodedOut)
{
    if ((self == NULL) || (encodedOut == NULL)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    unsigned char *out = NULL;
    X509_CRL *crl = ((HcfX509CRLOpensslImpl *)self)->crl;
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }
    int32_t length = i2d_X509_CRL(crl, &out);
    if (length <= 0) {
        LOGE("Do i2d_X509_CRL fail!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    encodedOut->data = (uint8_t *)CfMalloc(length, 0);
    if (encodedOut->data == NULL) {
        LOGE("Failed to malloc for crl encoded data!");
        OPENSSL_free(out);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(encodedOut->data, length, out, length);
    OPENSSL_free(out);
    encodedOut->len = length;
    encodedOut->encodingFormat = CF_FORMAT_DER;
    return CF_SUCCESS;
}

static CfResult Verify(HcfX509CrlSpi *self, HcfPubKey *key)
{
    if ((self == NULL) || (key == NULL)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetClass()) ||
        (!IsPubKeyClassMatch((HcfObjectBase *)key, OPENSSL_RSA_PUBKEY_CLASS))) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    RSA *rsaPubkey = ((HcfOpensslRsaPubKey *)key)->pk;
    if (rsaPubkey == NULL) {
        LOGE("rsaPubkey is null!");
        return CF_INVALID_PARAMS;
    }
    EVP_PKEY *pubKey = EVP_PKEY_new();
    if (pubKey == NULL) {
        LOGE("pubKey is null!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    CfResult ret = CF_SUCCESS;
    do {
        if (EVP_PKEY_set1_RSA(pubKey, rsaPubkey) <= 0) {
            LOGE("Do EVP_PKEY_assign_RSA fail!");
            CfPrintOpensslError();
            ret = CF_ERR_CRYPTO_OPERATION;
            break;
        }

        X509_CRL *crl = ((HcfX509CRLOpensslImpl *)self)->crl;
        if (crl == NULL) {
            LOGE("crl is null!");
            ret = CF_INVALID_PARAMS;
            break;
        }

        int32_t res = X509_CRL_verify(crl, pubKey);
        if (res != CF_OPENSSL_SUCCESS) {
            LOGE("Verify fail!");
            CfPrintOpensslError();
            ret = CF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);

    EVP_PKEY_free(pubKey);
    return ret;
}

static long GetVersion(HcfX509CrlSpi *self)
{
    if (self == NULL) {
        LOGE("Invalid Paramas!");
        return OPENSSL_INVALID_VERSION;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return OPENSSL_INVALID_VERSION;
    }
    X509_CRL *crl = ((HcfX509CRLOpensslImpl *)self)->crl;
    if (crl == NULL) {
        LOGE("crl is null!");
        return OPENSSL_INVALID_VERSION;
    }
    return X509_CRL_get_version(crl) + 1;
}

static CfResult GetIssuerName(HcfX509CrlSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid Paramas for calling GetIssuerName!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }
    X509_NAME *x509Name = X509_CRL_get_issuer(crl);
    if (x509Name == NULL) {
        LOGE("Get Issuer DN fail!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    char *issuer = X509_NAME_oneline(x509Name, NULL, 0);
    if ((issuer == NULL) || (strlen(issuer) > HCF_MAX_STR_LEN)) {
        LOGE("X509Name convert char fail or issuer name is too long!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t length = strlen(issuer) + 1;
    out->data = (uint8_t *)CfMalloc(length, 0);
    if (out->data == NULL) {
        LOGE("Failed to malloc for crl issuer data!");
        OPENSSL_free(issuer);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(out->data, length, issuer, length);
    out->size = length;
    OPENSSL_free(issuer);
    return CF_SUCCESS;
}

static CfResult SetCertIssuer(HcfX509CrlSpi *self)
{
    ((HcfX509CRLOpensslImpl *)self)->certIssuer = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (((HcfX509CRLOpensslImpl *)self)->certIssuer == NULL) {
        LOGE("Failed to malloc for certIssuer!");
        return CF_ERR_MALLOC;
    }
    CfResult res = GetIssuerName(self, ((HcfX509CRLOpensslImpl *)self)->certIssuer);
    if (res != CF_SUCCESS) {
        CfFree(((HcfX509CRLOpensslImpl *)self)->certIssuer);
        ((HcfX509CRLOpensslImpl *)self)->certIssuer = NULL;
    }
    return res;
}

static CfResult GetLastUpdate(HcfX509CrlSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid Paramas for calling GetLastUpdate!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }
    const ASN1_TIME *time = X509_CRL_get0_lastUpdate(crl);
    if (time == NULL) {
        LOGE("Get this update time fail!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    const char *thisUpdate = (const char *)(time->data);
    if (thisUpdate == NULL || strlen(thisUpdate) > HCF_MAX_STR_LEN) {
        LOGE("ThisUpdate convert String fail, or thisUpdate is too long!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t length = strlen(thisUpdate) + 1;
    out->data = (uint8_t *)CfMalloc(length, 0);
    if (out->data == NULL) {
        LOGE("Failed to malloc for thisUpdate!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(out->data, length, thisUpdate, length);
    out->size = length;
    return CF_SUCCESS;
}

static CfResult GetNextUpdate(HcfX509CrlSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid Paramas for calling GetNextUpdate!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }
    const ASN1_TIME *time = X509_CRL_get0_nextUpdate(crl);
    if (time == NULL) {
        LOGE("Get next update time fail!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    const char *nextUpdate = (const char *)(time->data);
    if ((nextUpdate == NULL) || (strlen(nextUpdate) > HCF_MAX_STR_LEN)) {
        LOGE("Get next update time is null, or nextUpdate is too long!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t length = strlen(nextUpdate) + 1;
    out->data = (uint8_t *)CfMalloc(length, 0);
    if (out->data == NULL) {
        LOGE("Failed to malloc for nextUpdate!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(out->data, length, nextUpdate, length);
    out->size = length;
    return CF_SUCCESS;
}

static CfResult GetRevokedCert(HcfX509CrlSpi *self, const CfBlob *serialNumber, HcfX509CrlEntry **entryOut)
{
    if ((self == NULL) || (serialNumber == NULL) || (serialNumber->data == NULL) || (serialNumber->size == 0) ||
        (serialNumber->size > MAX_SN_BYTE_CNT) || (entryOut == NULL)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }

    BIGNUM *bigNum = BN_bin2bn(serialNumber->data, serialNumber->size, NULL);
    if (bigNum == NULL) {
        LOGE("bin to big number fail!");
        return CF_INVALID_PARAMS;
    }
    ASN1_INTEGER *serial = BN_to_ASN1_INTEGER(bigNum, NULL);

    if (serial == NULL) {
        LOGE("Serial init fail!");
        CfPrintOpensslError();
        BN_free(bigNum);
        return CF_ERR_CRYPTO_OPERATION;
    }

    X509_REVOKED *rev = NULL;
    int32_t opensslRes = X509_CRL_get0_by_serial(crl, &rev, serial);
    BN_free(bigNum);
    ASN1_INTEGER_free(serial);
    if (opensslRes != CF_OPENSSL_SUCCESS) {
        LOGE("Get revoked certificate fail, res : %d!", opensslRes);
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = HcfCX509CRLEntryCreate(rev, entryOut, ((HcfX509CRLOpensslImpl *)self)->certIssuer);
    if (res != CF_SUCCESS) {
        LOGE("X509 CRL entry create fail, res : %d!", res);
        return res;
    }
    return CF_SUCCESS;
}

static CfResult GetRevokedCertWithCert(HcfX509CrlSpi *self, HcfX509Certificate *cert, HcfX509CrlEntry **entryOut)
{
    if ((self == NULL) || (cert == NULL) || (entryOut == NULL)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    X509 *certOpenssl = GetX509FromCertificate((HcfCertificate *)cert);
    if (certOpenssl == NULL) {
        LOGE("Input Cert is wrong!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = ((HcfX509CRLOpensslImpl *)self)->crl;
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }
    X509_REVOKED *revokedRet = NULL;
    int32_t opensslRes = X509_CRL_get0_by_cert(crl, &revokedRet, certOpenssl);
    if (opensslRes != CF_OPENSSL_SUCCESS) {
        LOGE("Get revoked certificate with cert fail, res : %d!", opensslRes);
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    CfResult res = HcfCX509CRLEntryCreate(revokedRet, entryOut, ((HcfX509CRLOpensslImpl *)self)->certIssuer);
    if (res != CF_SUCCESS) {
        LOGE("X509 CRL entry create fail, res : %d!", res);
        return res;
    }
    return CF_SUCCESS;
}

static CfResult DeepCopyRevokedCertificates(
    HcfX509CrlSpi *self, const STACK_OF(X509_REVOKED) * entrys, int32_t i, CfArray *entrysOut)
{
    X509_REVOKED *rev = sk_X509_REVOKED_value(entrys, i);
    if (rev == NULL) {
        LOGE("sk_X509_REVOKED_value fail!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    HcfX509CrlEntry *crlEntry = NULL;
    CfResult res = HcfCX509CRLEntryCreate(rev, &crlEntry, ((HcfX509CRLOpensslImpl *)self)->certIssuer);
    if (res != CF_SUCCESS || crlEntry == NULL) {
        LOGE("X509 CRL entry create fail, res : %d!", res);
        return res;
    }
    entrysOut->data[i].data = (uint8_t *)crlEntry;
    entrysOut->data[i].size = sizeof(HcfX509CrlEntry);
    return CF_SUCCESS;
}

static void DestroyCRLEntryArray(CfArray *arr)
{
    if (arr == NULL) {
        LOGD("The input array is null, no need to free.");
        return;
    }
    for (uint32_t i = 0; i < arr->count; ++i) {
        if (arr->data[i].data == NULL) {
            continue;
        }
        HcfX509CrlEntry *crlEntry = (HcfX509CrlEntry *)(arr->data[i].data);
        crlEntry->base.destroy((CfObjectBase *)crlEntry);
        arr->data[i].data = NULL;
        arr->data[i].size = 0;
    }
    CfFree(arr->data);
    arr->data = NULL;
}

static CfResult GetRevokedCerts(HcfX509CrlSpi *self, CfArray *entrysOut)
{
    if ((self == NULL) || (entrysOut == NULL)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }
    STACK_OF(X509_REVOKED) *entrys = X509_CRL_get_REVOKED(crl);
    if (entrys == NULL) {
        LOGE("Get revoked certificates fail!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    int32_t revokedNum = sk_X509_REVOKED_num(entrys);
    if ((revokedNum <= 0) || (revokedNum > MAX_REV_NUM)) {
        LOGE("Get revoked invalid number!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t blobSize = sizeof(CfBlob) * revokedNum;
    entrysOut->data = (CfBlob *)CfMalloc(blobSize, 0);
    if (entrysOut->data == NULL) {
        LOGE("Failed to malloc for entrysOut array!");
        return CF_ERR_MALLOC;
    }
    entrysOut->count = revokedNum;
    for (int32_t i = 0; i < revokedNum; i++) {
        if (DeepCopyRevokedCertificates(self, entrys, i, entrysOut) != CF_SUCCESS) {
            LOGE("Falied to copy revoked certificates!");
            DestroyCRLEntryArray(entrysOut);
            return CF_ERR_MALLOC;
        }
    }
    return CF_SUCCESS;
}

static CfResult GetTbsList(HcfX509CrlSpi *self, CfBlob *tbsCertListOut)
{
    if ((self == NULL) || (tbsCertListOut == NULL)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }
    unsigned char *tbs = NULL;
    int32_t length = i2d_re_X509_CRL_tbs(crl, &tbs);
    if ((length <= 0) || (tbs == NULL)) {
        LOGE("Get TBS certList fail!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    tbsCertListOut->data = (uint8_t *)CfMalloc(length, 0);
    if (tbsCertListOut->data == NULL) {
        LOGE("Failed to malloc for tbs!");
        OPENSSL_free(tbs);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(tbsCertListOut->data, length, tbs, length);
    OPENSSL_free(tbs);
    tbsCertListOut->size = length;
    return CF_SUCCESS;
}

static CfResult GetSignature(HcfX509CrlSpi *self, CfBlob *signature)
{
    if ((self == NULL) || (signature == NULL)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }
    const ASN1_BIT_STRING *asn1Signature = NULL;
    X509_CRL_get0_signature(((HcfX509CRLOpensslImpl *)self)->crl, &asn1Signature, NULL);
    if (asn1Signature == NULL) {
        LOGE("Get signature is null!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    int32_t signatureLen = ASN1_STRING_length(asn1Signature);
    if (signatureLen <= 0) {
        LOGE("Get signature length is invalid!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    const unsigned char *signatureStr = ASN1_STRING_get0_data(asn1Signature);
    if ((signatureStr == NULL) || (signatureLen > MAX_SIGNATURE_LEN)) {
        LOGE("ASN1 get string fail, or signature length is too long!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    signature->data = (uint8_t *)CfMalloc(signatureLen, 0);
    if (signature->data == NULL) {
        LOGE("Failed to malloc for signature!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(signature->data, signatureLen, signatureStr, signatureLen);
    signature->size = signatureLen;
    return CF_SUCCESS;
}

static CfResult GetSignatureAlgOidInner(X509_CRL *crl, CfBlob *oidOut)
{
    const X509_ALGOR *palg = NULL;
    X509_CRL_get0_signature(crl, NULL, &palg);
    if (palg == NULL) {
        LOGE("alg is null!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    const ASN1_OBJECT *oid = NULL;
    X509_ALGOR_get0(&oid, NULL, NULL, palg);
    if (oid == NULL) {
        LOGE("oid is null!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    char *output = (char *)CfMalloc(OID_LENGTH, 0);
    if (output == NULL) {
        LOGE("Failed to malloc the output!");
        return CF_ERR_MALLOC;
    }
    int32_t resLen = OBJ_obj2txt(output, OID_LENGTH, oid, 1);
    if (resLen < 0) {
        LOGE("Failed to do OBJ_obj2txt!");
        CfPrintOpensslError();
        CfFree(output);
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t length = strlen(output) + 1;
    oidOut->data = (uint8_t *)CfMalloc(length, 0);
    if (oidOut->data == NULL) {
        LOGE("Failed to malloc for oidOut!");
        CfFree(output);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(oidOut->data, length, output, length);
    CfFree(output);
    oidOut->size = length;
    return CF_SUCCESS;
}

static CfResult GetSignatureAlgOid(HcfX509CrlSpi *self, CfBlob *oidOut)
{
    if ((self == NULL) || (oidOut == NULL)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }
    return GetSignatureAlgOidInner(crl, oidOut);
}

static CfResult GetSignatureAlgName(HcfX509CrlSpi *self, CfBlob *algNameOut)
{
    if ((self == NULL) || (algNameOut == NULL)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    CfBlob *oidOut = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    CfResult res = GetSignatureAlgOid(self, oidOut);
    if (res != CF_SUCCESS) {
        LOGE("Get signature algor oid failed!");
        CfFree(oidOut);
        return res;
    }
    const char *algName = GetAlgorithmName((const char *)(oidOut->data));
    CfFree(oidOut->data);
    CfFree(oidOut);
    if (algName == NULL) {
        LOGE("Can not find algorithmName!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t length = strlen(algName) + 1;
    algNameOut->data = (uint8_t *)CfMalloc(length, 0);
    if (algNameOut->data == NULL) {
        LOGE("Failed to malloc for algName!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(algNameOut->data, length, algName, length);
    algNameOut->size = length;
    return CF_SUCCESS;
}

static CfResult GetSignatureAlgParamsInner(X509_CRL *crl, CfBlob *sigAlgParamOut)
{
    const X509_ALGOR *palg = NULL;
    X509_CRL_get0_signature(crl, NULL, &palg);
    if (palg == NULL) {
        LOGE("Get alg is null!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    int32_t paramType = 0;
    const void *paramValue = NULL;
    X509_ALGOR_get0(NULL, &paramType, &paramValue, palg);
    if (paramType == V_ASN1_UNDEF) {
        LOGE("get_X509_ALGOR_parameter, no parameters!");
        CfPrintOpensslError();
        return CF_NOT_SUPPORT;
    }
    ASN1_TYPE *param = ASN1_TYPE_new();
    if (ASN1_TYPE_set1(param, paramType, paramValue) != CF_OPENSSL_SUCCESS) {
        LOGE("Set type fail!");
        ASN1_TYPE_free(param);
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    unsigned char *outParams = NULL;
    int32_t length = i2d_ASN1_TYPE(param, &outParams);
    ASN1_TYPE_free(param);
    if (length <= 0) {
        LOGE("Do i2d_ASN1_TYPE fail!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    sigAlgParamOut->data = (uint8_t *)CfMalloc(length, 0);
    if (sigAlgParamOut->data == NULL) {
        LOGE("Failed to malloc for sigAlgParam!");
        OPENSSL_free(outParams);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(sigAlgParamOut->data, length, outParams, length);
    sigAlgParamOut->size = length;
    OPENSSL_free(outParams);
    return CF_SUCCESS;
}

static CfResult GetSignatureAlgParams(HcfX509CrlSpi *self, CfBlob *sigAlgParamOut)
{
    if ((self == NULL) || (sigAlgParamOut == NULL)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }
    return GetSignatureAlgParamsInner(crl, sigAlgParamOut);
}

static CfResult GetExtensions(HcfX509CrlSpi *self, CfBlob *outBlob)
{
    if ((self == NULL) || (outBlob == NULL)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }

    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }

    X509_EXTENSIONS *exts = (X509_EXTENSIONS *)X509_CRL_get0_extensions(crl);
    CfResult ret = CopyExtensionsToBlob(exts, outBlob);
    if (ret != CF_SUCCESS) {
        CfPrintOpensslError();
    }
    return ret;
}

static CfResult ToString(HcfX509CrlSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        LOGE("BIO_new error");
        return CF_ERR_MALLOC;
    }

    int len = X509_CRL_print(bio, crl);
    if (len < 0) {
        LOGE("X509_CRL_print error");
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

static CfResult HashCode(HcfX509CrlSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }
    unsigned char *buf = NULL;
    int len = i2d_X509_CRL(crl, &buf);
    if (len < 0 || buf == NULL) {
        LOGE("i2d_X509_CRL error");
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

static CfResult GetExtensionsObject(HcfX509CrlSpi *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("crl is null!");
        return CF_INVALID_PARAMS;
    }

    int len = i2d_X509_EXTENSIONS(X509_CRL_get0_extensions(crl), &out->data);
    if (len < 0) {
        LOGE("i2d_X509_EXTENSIONS error");
        return CF_ERR_CRYPTO_OPERATION;
    }
    out->size = len;
    return CF_SUCCESS;
}

static CfResult GetNumOfCRL(HcfX509CrlSpi *self, CfBlob *outBlob)
{
    X509_CRL *crl = GetCrl(self);
    if (crl == NULL) {
        LOGE("Crl is null!");
        return CF_INVALID_PARAMS;
    }

    ASN1_INTEGER *crlNumber = X509_CRL_get_ext_d2i(crl, NID_crl_number, NULL, NULL);
    if (crlNumber == NULL) {
        LOGE("Crl number is null!");
        return CF_INVALID_PARAMS;
    }
    outBlob->data = (uint8_t *)CfMalloc(crlNumber->length, 0);
    if (!outBlob->data) {
        ASN1_INTEGER_free(crlNumber);
        LOGE("Malloc failed!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(outBlob->data, crlNumber->length, crlNumber->data, crlNumber->length);
    outBlob->size = (uint32_t)crlNumber->length;
    ASN1_INTEGER_free(crlNumber);
    return CF_SUCCESS;
}

static CfResult Comparex509CertX509Openssl(HcfX509CrlSpi *self, const HcfCertificate *x509Cert, bool *out)
{
    bool bRet = IsRevoked(self, x509Cert);
    if (!bRet) {
        *out = false;
        LOGI("Crl revoked is false!");
    }
    LOGI("x509Crl match x509Cert!");
    return CF_SUCCESS;
}

static CfResult CompareIssuerX509Openssl(HcfX509CrlSpi *self, const CfBlobArray *issuer, bool *out)
{
    if (issuer == NULL || issuer->data == NULL || issuer->count == 0) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    CfBlob outTmpSelf = { 0 };
    CfBlob cfBlobDataParam = { 0 };
    CfResult ret = GetIssuerName(self, &outTmpSelf);
    if (ret != CF_SUCCESS) {
        *out = false;
        LOGE("x509Crl GetIssuerName failed!");
        return ret;
    }

    *out = false;
    for (uint32_t i = 0; i < issuer->count; ++i) {
        ret = ConvertNameDerDataToString(issuer->data[i].data, issuer->data[i].size, &cfBlobDataParam);
        if (ret != CF_SUCCESS) {
            LOGE("ConvertNameDerDataToString failed!");
            CfFree(outTmpSelf.data);
            return ret;
        }
        if (outTmpSelf.size != cfBlobDataParam.size) {
            CfFree(cfBlobDataParam.data);
            continue;
        }
        if (strncmp((const char *)outTmpSelf.data, (const char *)cfBlobDataParam.data, outTmpSelf.size) == 0) {
            LOGI("x509Crl match issuer success!");
            *out = true;
            CfFree(cfBlobDataParam.data);
            break;
        }
        CfFree(cfBlobDataParam.data);
    }
    CfFree(outTmpSelf.data);
    return CF_SUCCESS;
}

static CfResult CompareUpdateDateTimeX509Openssl(HcfX509CrlSpi *self, const CfBlob *updateDateTime, bool *out)
{
    *out = false;
    CfBlob outNextUpdate = { 0 };
    CfBlob outThisUpdate = { 0 };
    CfResult res = GetNextUpdate(self, &outNextUpdate);
    if (res != CF_SUCCESS) {
        LOGE("X509Crl getNextUpdate failed!");
        return res;
    }
    res = GetLastUpdate(self, &outThisUpdate);
    if (res != CF_SUCCESS) {
        LOGE("X509Crl getLastUpdate failed!");
        CfFree(outNextUpdate.data);
        return res;
    }

    int ret = 0;
    res = CompareBigNum(updateDateTime, &outNextUpdate, &ret);
    if (res != CF_SUCCESS || ret > 0) {
        LOGE("updateDateTime should <= outNextUpdate!");
        CfFree(outNextUpdate.data);
        CfFree(outThisUpdate.data);
        return res;
    }
    res = CompareBigNum(updateDateTime, &outThisUpdate, &ret);
    if (res != CF_SUCCESS || ret < 0) {
        LOGE("updateDateTime should >= outThisUpdate!");
        CfFree(outNextUpdate.data);
        CfFree(outThisUpdate.data);
        return res;
    }
    *out = true;
    CfFree(outNextUpdate.data);
    CfFree(outThisUpdate.data);
    return CF_SUCCESS;
}

static CfResult CompareCRLX509Openssl(HcfX509CrlSpi *self, const CfBlob *crlBlob, X509CRLType type, bool *out)
{
    *out = false;
    CfBlob outNum = { 0, NULL };
    CfResult res = GetNumOfCRL(self, &outNum);
    if (res != CF_SUCCESS) {
        LOGE("X509Crl get num of CRL failed!");
        return res;
    }

    int ret = 0;
    res = CompareBigNum(crlBlob, &outNum, &ret);
    switch (type) {
        case CRL_MAX:
            if (res == CF_SUCCESS && ret > 0) {
                *out = true;
            }
            break;
        case CRL_MIN:
            if (res == CF_SUCCESS && ret < 0) {
                *out = true;
            }
            break;
        default:
            LOGE("Unknown type!");
            break;
    }
    CfFree(outNum.data);
    return CF_SUCCESS;
}

static CfResult MatchX509CRLOpensslPart2(HcfX509CrlSpi *self, const HcfX509CrlMatchParams *matchParams, bool *out)
{
    CfResult res = CF_SUCCESS;
    // updateDateTime
    if (matchParams->updateDateTime != NULL) {
        res = CompareUpdateDateTimeX509Openssl(self, matchParams->updateDateTime, out);
        if (res != CF_SUCCESS || (*out == false)) {
            LOGE("X509Crl match updateDateTime failed!");
            return res;
        }
    }

    // maxCRL & minCRL
    if ((matchParams->maxCRL != NULL) && (matchParams->minCRL != NULL)) {
        int ret = 0;
        res = CompareBigNum(matchParams->maxCRL, matchParams->minCRL, &ret);
        if (res != CF_SUCCESS || ret < 0) {
            LOGE("X509Crl minCRL should be smaller than maxCRL!");
            return CF_INVALID_PARAMS;
        }
    }

    // maxCRL
    if (matchParams->maxCRL != NULL) {
        res = CompareCRLX509Openssl(self, matchParams->maxCRL, CRL_MAX, out);
        if (res != CF_SUCCESS || (*out == false)) {
            LOGE("X509Crl match maxCRL failed!");
            return res;
        }
    }

    // minCRL
    if (matchParams->minCRL != NULL) {
        res = CompareCRLX509Openssl(self, matchParams->minCRL, CRL_MIN, out);
        if (res != CF_SUCCESS || (*out == false)) {
            LOGE("X509Crl match minCRL failed!");
            return res;
        }
    }
    return res;
}

static CfResult MatchX509CRLOpenssl(HcfX509CrlSpi *self, const HcfX509CrlMatchParams *matchParams, bool *out)
{
    LOGI("enter MatchX509CRLOpenssl!");
    if ((self == NULL) || (matchParams == NULL) || (out == NULL)) {
        LOGE("The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }

    *out = true;

    // x509Cert
    if (matchParams->x509Cert != NULL) {
        CfResult res = Comparex509CertX509Openssl(self, matchParams->x509Cert, out);
        if (res != CF_SUCCESS || (*out == false)) {
            LOGE("X509Crl match x509Cert failed!");
            return res;
        }
    }

    // issuer
    if (matchParams->issuer != NULL) {
        CfResult res = CompareIssuerX509Openssl(self, matchParams->issuer, out);
        if (res != CF_SUCCESS || (*out == false)) {
            LOGE("X509Crl match issuer failed!");
            return res;
        }
    }

    // updateDateTime、maxCRL、minCRL
    return MatchX509CRLOpensslPart2(self, matchParams, out);
}

static void Destroy(CfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetClass())) {
        LOGE("Input wrong class type!");
        return;
    }
    HcfX509CRLOpensslImpl *realCrl = (HcfX509CRLOpensslImpl *)self;
    X509_CRL_free(realCrl->crl);
    realCrl->crl = NULL;
    if (realCrl->certIssuer != NULL) {
        CfFree(realCrl->certIssuer->data);
        realCrl->certIssuer->data = NULL;
        CfFree(realCrl->certIssuer);
        realCrl->certIssuer = NULL;
    }
    CfFree(realCrl);
}

static X509_CRL *ParseX509CRL(const CfEncodingBlob *inStream)
{
    if ((inStream->data == NULL) || (inStream->len <= 0)) {
        LOGE("Invalid Paramas!");
        return NULL;
    }
    BIO *bio = BIO_new_mem_buf(inStream->data, inStream->len);
    if (bio == NULL) {
        LOGE("bio get null!");
        CfPrintOpensslError();
        return NULL;
    }
    X509_CRL *crlOut = NULL;
    switch (inStream->encodingFormat) {
        case CF_FORMAT_DER:
            crlOut = d2i_X509_CRL_bio(bio, NULL);
            break;
        case CF_FORMAT_PEM:
            crlOut = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
            break;
        default:
            LOGE("Not support format!");
            break;
    }
    BIO_free_all(bio);
    if (crlOut == NULL) {
        LOGE("Parse X509 CRL fail!");
        CfPrintOpensslError();
        return NULL;
    }
    return crlOut;
}

CfResult HcfCX509CrlSpiCreate(const CfEncodingBlob *inStream, HcfX509CrlSpi **spi)
{
    if ((inStream == NULL) || (inStream->data == NULL) || (spi == NULL)) {
        LOGE("Invalid Paramas!");
        return CF_INVALID_PARAMS;
    }
    HcfX509CRLOpensslImpl *returnCRL = (HcfX509CRLOpensslImpl *)CfMalloc(sizeof(HcfX509CRLOpensslImpl), 0);
    if (returnCRL == NULL) {
        LOGE("Failed to malloc for x509 instance!");
        return CF_ERR_MALLOC;
    }
    X509_CRL *crl = ParseX509CRL(inStream);
    if (crl == NULL) {
        LOGE("Failed to Parse x509 CRL!");
        CfFree(returnCRL);
        return CF_INVALID_PARAMS;
    }
    returnCRL->crl = crl;
    returnCRL->certIssuer = NULL;
    returnCRL->base.base.getClass = GetClass;
    returnCRL->base.base.destroy = Destroy;
    returnCRL->base.engineIsRevoked = IsRevoked;
    returnCRL->base.engineGetType = GetType;
    returnCRL->base.engineGetEncoded = GetEncoded;
    returnCRL->base.engineVerify = Verify;
    returnCRL->base.engineGetVersion = GetVersion;
    returnCRL->base.engineGetIssuerName = GetIssuerName;
    returnCRL->base.engineGetLastUpdate = GetLastUpdate;
    returnCRL->base.engineGetNextUpdate = GetNextUpdate;
    returnCRL->base.engineGetRevokedCert = GetRevokedCert;
    returnCRL->base.engineGetRevokedCertWithCert = GetRevokedCertWithCert;
    returnCRL->base.engineGetRevokedCerts = GetRevokedCerts;
    returnCRL->base.engineGetTbsInfo = GetTbsList;
    returnCRL->base.engineGetSignature = GetSignature;
    returnCRL->base.engineGetSignatureAlgName = GetSignatureAlgName;
    returnCRL->base.engineGetSignatureAlgOid = GetSignatureAlgOid;
    returnCRL->base.engineGetSignatureAlgParams = GetSignatureAlgParams;
    returnCRL->base.engineGetExtensions = GetExtensions;
    returnCRL->base.engineMatch = MatchX509CRLOpenssl;
    returnCRL->base.engineToString = ToString;
    returnCRL->base.engineHashCode = HashCode;
    returnCRL->base.engineGetExtensionsObject = GetExtensionsObject;
    if (SetCertIssuer((HcfX509CrlSpi *)returnCRL) != CF_SUCCESS) {
        LOGI("No cert issuer find or set cert issuer fail!");
    }
    *spi = (HcfX509CrlSpi *)returnCRL;
    return CF_SUCCESS;
}
