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

#include "x509_crl_entry_openssl.h"

#include "securec.h"

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "certificate_openssl_common.h"
#include "certificate_openssl_class.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "config.h"
#include "utils.h"
#include "x509_crl.h"
#include "x509_crl_entry.h"
#include "x509_crl_openssl.h"

static const char *GetClass(void)
{
    return "HcfX509CRLEntryOpensslImpl.HcfX509CrlEntry";
}

static X509_REVOKED *GetSelfRev(const HcfX509CrlEntry *self)
{
    if (!CfIsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return NULL;
    }
    return ((HcfX509CRLEntryOpensslImpl *)self)->rev;
}

static CfResult GetEncoded(HcfX509CrlEntry *self, CfEncodingBlob *encodedOut)
{
    if ((self == NULL) || (encodedOut == NULL)) {
        LOGE("Invalid params for calling GetEncoded!");
        return CF_INVALID_PARAMS;
    }
    X509_REVOKED *rev = GetSelfRev(self);
    if (rev == NULL) {
        LOGE("Rev is null!");
        return CF_INVALID_PARAMS;
    }
    unsigned char *out = NULL;
    int32_t length = i2d_X509_REVOKED(rev, &out);
    if (length <= 0) {
        LOGE("Do i2d_X509_REVOKED fail!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    encodedOut->data = (uint8_t *)CfMalloc(length, 0);
    if (encodedOut->data == NULL) {
        LOGE("Failed to malloc for encodedOut!");
        OPENSSL_free(out);
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(encodedOut->data, length, out, length);
    encodedOut->len = length;
    encodedOut->encodingFormat = CF_FORMAT_DER;
    OPENSSL_free(out);
    return CF_SUCCESS;
}

static CfResult GetSerialNumber(HcfX509CrlEntry *self, CfBlob *out)
{
    if (self == NULL) {
        LOGE("Invalid params for calling GetSerialNumber!");
        return CF_INVALID_PARAMS;
    }
    X509_REVOKED *rev = GetSelfRev(self);
    if (rev == NULL) {
        LOGE("Rev is null!");
        return CF_INVALID_PARAMS;
    }
    const ASN1_INTEGER *serialNumber = X509_REVOKED_get0_serialNumber(rev);
    if (serialNumber == NULL) {
        LOGE("Get serial number fail!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    unsigned char *serialNumBytes = NULL;
    int serialNumLen = i2d_ASN1_INTEGER((ASN1_INTEGER *)serialNumber, &serialNumBytes);
    if (serialNumLen <= SERIAL_NUMBER_HEDER_SIZE) {
        CfPrintOpensslError();
        LOGE("get serial num len failed!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    out->data = (uint8_t *)CfMalloc(serialNumLen - SERIAL_NUMBER_HEDER_SIZE, 0);
    if (out->data == NULL) {
        OPENSSL_free(serialNumBytes);
        LOGE("Failed to malloc serial num");
        return CF_ERR_MALLOC;
    }
    out->size = (uint32_t)(serialNumLen - SERIAL_NUMBER_HEDER_SIZE);
    (void)memcpy_s(out->data, out->size, serialNumBytes + SERIAL_NUMBER_HEDER_SIZE, out->size);
    OPENSSL_free(serialNumBytes);
    return CF_SUCCESS;
}

static CfResult GetCertIssuer(HcfX509CrlEntry *self, CfBlob *encodedOut)
{
    if ((self == NULL) || (encodedOut == NULL)) {
        LOGE("Invalid params for calling GetCertIssuer!");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return CF_INVALID_PARAMS;
    }
    CfBlob *certIssuer = ((HcfX509CRLEntryOpensslImpl *)self)->certIssuer;
    if (!CfIsBlobValid(certIssuer)) {
        LOGE("Get certIssuer fail! No certIssuer in CRL entry.");
        return CF_NOT_SUPPORT;
    }
    uint32_t length = certIssuer->size;
    encodedOut->data = (uint8_t *)CfMalloc(length, 0);
    if (encodedOut->data == NULL) {
        LOGE("Failed to malloc for encodedOut!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(encodedOut->data, length, certIssuer->data, length);
    encodedOut->size = length;
    return CF_SUCCESS;
}

static CfResult GetCertIssuerEx(HcfX509CrlEntry *self, CfEncodinigType encodingType, CfBlob *encodedOut)
{
    if ((self == NULL) || (encodedOut == NULL)) {
        LOGE("Invalid params for calling GetCertIssuerEx!");
        return CF_ERR_INTERNAL;
    }
    if (encodingType != CF_ENCODING_UTF8) {
        LOGE("encodingType is not utf8!");
        return CF_ERR_PARAMETER_CHECK;
    }

    if (!CfIsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return CF_ERR_INTERNAL;
    }
    CfBlob *certIssuer = ((HcfX509CRLEntryOpensslImpl *)self)->certIssuerUtf8;
    if (!CfIsBlobValid(certIssuer)) {
        LOGE("Get certIssuer fail! No certIssuer in CRL entry.");
        return CF_NOT_SUPPORT;
    }
    uint32_t length = certIssuer->size;
    encodedOut->data = (uint8_t *)CfMalloc(length, 0);
    if (encodedOut->data == NULL) {
        LOGE("Failed to malloc for encodedOut!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(encodedOut->data, length, certIssuer->data, length);
    encodedOut->size = length;
    return CF_SUCCESS;
}

static CfResult GetCertIssuerDer(HcfX509CrlEntry *self, CfBlob *encodedOut)
{
    if ((self == NULL) || (encodedOut == NULL)) {
        LOGE("Invalid params for calling GetCertIssuerEx!");
        return CF_ERR_INTERNAL;
    }

    if (!CfIsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return CF_ERR_INTERNAL;
    }
    X509_CRL *crl = ((HcfX509CRLEntryOpensslImpl *)self)->crl;
    X509_NAME *x509Name = X509_CRL_get_issuer(crl);
    if (x509Name == NULL) {
        LOGE("Failed to get issuer name!");
        CfPrintOpensslError();
        return CF_ERR_INTERNAL;
    }

    int32_t size = i2d_X509_NAME(x509Name, &(encodedOut->data));
    if (size <= 0) {
        LOGE("Failed to get subject DER data!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    encodedOut->size = (uint32_t)size;
    return CF_SUCCESS;
}

static CfResult GetRevocationDate(HcfX509CrlEntry *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("invalid params for calling GetRevocationDate!");
        return CF_INVALID_PARAMS;
    }
    X509_REVOKED *rev = GetSelfRev(self);
    if (rev == NULL) {
        LOGE("Rev is null!");
        return CF_INVALID_PARAMS;
    }
    const ASN1_TIME *time = X509_REVOKED_get0_revocationDate(rev);
    if (time == NULL) {
        LOGE("Get revocation date fail!");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    const char *revTime = (const char *)(time->data);
    if ((revTime == NULL) || (strlen(revTime) > HCF_MAX_STR_LEN)) {
        LOGE("Get revocation date from ASN1_TIME fail!");
        return CF_ERR_CRYPTO_OPERATION;
    }
    uint32_t length = strlen(revTime) + 1;
    out->data = (uint8_t *)CfMalloc(length, 0);
    if (out->data == NULL) {
        LOGE("Failed to malloc for revTime!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(out->data, length, revTime, length);
    out->size = length;
    return CF_SUCCESS;
}

static CfResult GetExtensions(HcfX509CrlEntry *self, CfBlob *outBlob)
{
    if ((self == NULL) || (outBlob == NULL)) {
        LOGE("Invalid params!");
        return CF_INVALID_PARAMS;
    }

    X509_REVOKED *rev = GetSelfRev(self);
    if (rev == NULL) {
        LOGE("Rev is null!");
        return CF_INVALID_PARAMS;
    }

    X509_EXTENSIONS *exts = (X509_EXTENSIONS *)X509_REVOKED_get0_extensions(rev);
    CfResult ret = CopyExtensionsToBlob(exts, outBlob);
    if (ret != CF_SUCCESS) {
        CfPrintOpensslError();
    }
    return ret;
}

static CfResult HasExtensions(HcfX509CrlEntry *self, bool *out)
{
    if (self == NULL || out == NULL) {
        LOGE("Invalid params!");
        return CF_INVALID_PARAMS;
    }

    X509_REVOKED *rev = GetSelfRev(self);
    if (rev == NULL) {
        LOGE("Rev is null!");
        return CF_INVALID_PARAMS;
    }

    X509_EXTENSIONS *exts = (X509_EXTENSIONS *)X509_REVOKED_get0_extensions(rev);
    if (exts == NULL) {
        *out = false;
    } else {
        *out = (sk_X509_EXTENSION_num(exts) > 0);
    }

    return CF_SUCCESS;
}

static CfResult ToString(HcfX509CrlEntry *self, CfBlob *outBlob)
{
    if ((self == NULL) || (outBlob == NULL)) {
        LOGE("Invalid params!");
        return CF_INVALID_PARAMS;
    }
    X509_REVOKED *rev = GetSelfRev(self);
    if (rev == NULL) {
        LOGE("Rev is null!");
        return CF_INVALID_PARAMS;
    }

    BIO *out = BIO_new(BIO_s_mem());
    if (out == NULL) {
        LOGE("BIO_new error");
        return CF_ERR_MALLOC;
    }
    BIO_printf(out, "    Serial Number: ");
    i2a_ASN1_INTEGER(out, X509_REVOKED_get0_serialNumber(rev));
    BIO_printf(out, "\n        Revocation Date: ");
    ASN1_TIME_print(out, X509_REVOKED_get0_revocationDate(rev));
    BIO_printf(out, "\n");
    int len = X509V3_extensions_print(out, "CRL entry extensions", X509_REVOKED_get0_extensions(rev), 0, 8);
    if (len <= 0) {
        LOGE("X509V3_extensions_print error");
        BIO_free(out);
        return CF_ERR_CRYPTO_OPERATION;
    }
    BUF_MEM *bufMem = NULL;
    if (BIO_get_mem_ptr(out, &bufMem) > 0 && bufMem != NULL) {
        CfResult res = DeepCopyDataToOut(bufMem->data, bufMem->length, outBlob);
        BIO_free(out);
        return res;
    }
    BIO_free(out);
    LOGE("BIO_get_mem_ptr error");
    return CF_ERR_CRYPTO_OPERATION;
}

static CfResult HashCode(HcfX509CrlEntry *self, CfBlob *outBlob)
{
    if ((self == NULL) || (outBlob == NULL)) {
        LOGE("Invalid params!");
        return CF_INVALID_PARAMS;
    }
    X509_REVOKED *rev = GetSelfRev(self);
    if (rev == NULL) {
        LOGE("Rev is null!");
        return CF_INVALID_PARAMS;
    }

    unsigned char *buf = NULL;
    int len = i2d_X509_REVOKED(rev, &buf);
    if (len < 0 || buf == NULL) {
        LOGE("i2d_X509_REVOKED error");
        return CF_ERR_CRYPTO_OPERATION;
    }

    outBlob->data = (uint8_t *)CfMalloc(SHA256_DIGEST_LENGTH, 0);
    if (outBlob->data == NULL) {
        LOGE("CfMalloc error");
        OPENSSL_free(buf);
        return CF_ERR_MALLOC;
    }
    if (SHA256(buf, len, (unsigned char *)outBlob->data) == NULL) {
        LOGE("Compute sha256 error");
        OPENSSL_free(buf);
        CfFree(outBlob->data);
        return CF_ERR_CRYPTO_OPERATION;
    }
    outBlob->size = SHA256_DIGEST_LENGTH;
    OPENSSL_free(buf);
    return CF_SUCCESS;
}

static CfResult GetExtensionsObject(HcfX509CrlEntry *self, CfBlob *outBlob)
{
    if ((self == NULL) || (outBlob == NULL)) {
        LOGE("Invalid params!");
        return CF_INVALID_PARAMS;
    }

    X509_REVOKED *rev = GetSelfRev(self);
    if (rev == NULL) {
        LOGE("Rev is null!");
        return CF_INVALID_PARAMS;
    }
    int len = i2d_X509_EXTENSIONS(X509_REVOKED_get0_extensions(rev), &outBlob->data);
    if (len < 0) {
        LOGE("i2d_X509_EXTENSIONS error");
        return CF_ERR_CRYPTO_OPERATION;
    }
    outBlob->size = len;
    return CF_SUCCESS;
}

static CfResult DeepCopyCertIssuer(HcfX509CRLEntryOpensslImpl *returnCRLEntry, CfBlob *certIssuer)
{
    returnCRLEntry->certIssuer = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (returnCRLEntry->certIssuer == NULL) {
        LOGE("Failed to malloc certIssuer!");
        return CF_ERR_MALLOC;
    }
    returnCRLEntry->certIssuer->size = certIssuer->size;
    returnCRLEntry->certIssuer->data = (uint8_t *)CfMalloc(certIssuer->size, 0);
    if (returnCRLEntry->certIssuer->data == NULL) {
        LOGE("Failed to malloc certIssuer data!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(returnCRLEntry->certIssuer->data, certIssuer->size, certIssuer->data, certIssuer->size);
    return CF_SUCCESS;
}

static CfResult DeepCopyCertIssuerUtf8(HcfX509CRLEntryOpensslImpl *returnCRLEntry, CfBlob *certIssuerUtf8)
{
    returnCRLEntry->certIssuerUtf8 = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (returnCRLEntry->certIssuerUtf8 == NULL) {
        LOGE("Failed to malloc certIssuerUtf8!");
        return CF_ERR_MALLOC;
    }
    returnCRLEntry->certIssuerUtf8->size = certIssuerUtf8->size;
    returnCRLEntry->certIssuerUtf8->data = (uint8_t *)CfMalloc(certIssuerUtf8->size, 0);
    if (returnCRLEntry->certIssuerUtf8->data == NULL) {
        LOGE("Failed to malloc certIssuerUtf8 data!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(returnCRLEntry->certIssuerUtf8->data, certIssuerUtf8->size, certIssuerUtf8->data,
        certIssuerUtf8->size);
    return CF_SUCCESS;
}

static void Destroy(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid params!");
        return;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetClass())) {
        LOGE("Input wrong class type!");
        return;
    }
    HcfX509CRLEntryOpensslImpl *realCrlEntry = (HcfX509CRLEntryOpensslImpl *)self;
    if (realCrlEntry->rev != NULL) {
        X509_REVOKED_free(realCrlEntry->rev);
        realCrlEntry->rev = NULL;
    }
    if (realCrlEntry->certIssuer != NULL) {
        CfFree(realCrlEntry->certIssuer->data);
        realCrlEntry->certIssuer->data = NULL;
        CfFree(realCrlEntry->certIssuer);
        realCrlEntry->certIssuer = NULL;
    }
    if (realCrlEntry->certIssuerUtf8 != NULL) {
        CfFree(realCrlEntry->certIssuerUtf8->data);
        realCrlEntry->certIssuerUtf8->data = NULL;
        CfFree(realCrlEntry->certIssuerUtf8);
        realCrlEntry->certIssuerUtf8 = NULL;
    }
    CfFree(realCrlEntry);
}

CfResult HcfCX509CRLEntryCreate(X509_REVOKED *rev, HcfX509CrlEntry **crlEntryOut, CfBlob *certIssuer,
    CfBlob *certIssuerUtf8, X509_CRL *crl)
{
    if ((rev == NULL) || (crlEntryOut == NULL) || certIssuer == NULL) {
        LOGE("Invalid params!");
        return CF_INVALID_PARAMS;
    }
    HcfX509CRLEntryOpensslImpl *returnCRLEntry = (HcfX509CRLEntryOpensslImpl *)CfMalloc(
        sizeof(HcfX509CRLEntryOpensslImpl), 0);
    if (returnCRLEntry == NULL) {
        LOGE("Failed to malloc for x509 entry instance!");
        return CF_ERR_MALLOC;
    }

    X509_REVOKED *tmp = X509_REVOKED_dup(rev);
    if (tmp == NULL) {
        CfFree(returnCRLEntry);
        LOGE("Failed to dup x509 revoked");
        return CF_ERR_MALLOC;
    }
    returnCRLEntry->rev = tmp;
    returnCRLEntry->certIssuer = NULL;
    returnCRLEntry->certIssuerUtf8 = NULL;
    returnCRLEntry->crl = crl;
    returnCRLEntry->base.base.getClass = GetClass;
    returnCRLEntry->base.base.destroy = Destroy;
    returnCRLEntry->base.getEncoded = GetEncoded;
    returnCRLEntry->base.getSerialNumber = GetSerialNumber;
    returnCRLEntry->base.getCertIssuer = GetCertIssuer;
    returnCRLEntry->base.getCertIssuerEx = GetCertIssuerEx;
    returnCRLEntry->base.getCertIssuerDer = GetCertIssuerDer;
    returnCRLEntry->base.getRevocationDate = GetRevocationDate;
    returnCRLEntry->base.getExtensions = GetExtensions;
    returnCRLEntry->base.hasExtensions = HasExtensions;
    returnCRLEntry->base.toString = ToString;
    returnCRLEntry->base.hashCode = HashCode;
    returnCRLEntry->base.getExtensionsObject = GetExtensionsObject;
    if (DeepCopyCertIssuer(returnCRLEntry, certIssuer) != CF_SUCCESS) {
        LOGI("No cert issuer find or deep copy cert issuer fail!");
    }
    if (DeepCopyCertIssuerUtf8(returnCRLEntry, certIssuerUtf8) != CF_SUCCESS) {
        LOGI("No cert utf8 issuer find or deep copy cert utf8 issuer fail!");
    }
    *crlEntryOut = (HcfX509CrlEntry *)returnCRLEntry;
    return CF_SUCCESS;
}
