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

#include "x509_crl.h"

#include "securec.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "config.h"
#include "utils.h"
#include "x509_crl.h"
#include "x509_crl_match_parameters.h"
#include "x509_crl_openssl.h"
#include "x509_crl_spi.h"

#define HCF_X509_CRL_CLASS "HcfX509Crl"
#define OPENSSL_INVALID_VERSION (-1)

typedef CfResult (*HcfX509CrlSpiCreateFunc)(const CfEncodingBlob *, HcfX509CrlSpi **);

typedef struct {
    HcfX509Crl base;
    HcfX509CrlSpi *spiObj;
    const char *certType;
} HcfX509CrlImpl;

typedef struct {
    HcfX509CrlSpiCreateFunc createFunc;
} HcfX509CrlFuncSet;

typedef struct {
    char *certType;
    HcfX509CrlFuncSet funcSet;
} HcfCCertFactoryAbility;

static const char *GetX509CrlClass(void)
{
    return HCF_X509_CRL_CLASS;
}

static const HcfCCertFactoryAbility X509_CRL_ABILITY_SET[] = {
    { "X509", { HcfCX509CrlSpiCreate, } }
};

static const HcfX509CrlFuncSet *FindAbility(const char *certType)
{
    if (certType == NULL) {
        LOGE("CertType is null!");
        return NULL;
    }
    for (uint32_t i = 0; i < sizeof(X509_CRL_ABILITY_SET) / sizeof(HcfCCertFactoryAbility); i++) {
        if (strcmp(X509_CRL_ABILITY_SET[i].certType, certType) == 0) {
            return &(X509_CRL_ABILITY_SET[i].funcSet);
        }
    }
    LOGE("Cert not support! [cert]: %s", certType);
    return NULL;
}

static void DestroyX509Crl(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    if (!IsClassMatch(self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfX509CrlImpl *impl = (HcfX509CrlImpl *)self;
    CfObjDestroy(impl->spiObj);
    CfFree(impl);
}

static const char *GetType(HcfCrl *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetType(
        ((HcfX509CrlImpl *)self)->spiObj);
}

static bool IsRevoked(HcfCrl *self, const HcfCertificate *cert)
{
    if ((self == NULL) || (cert == NULL)) {
        LOGE("Invalid input parameter.");
        return false;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return false;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineIsRevoked(
        ((HcfX509CrlImpl *)self)->spiObj, cert);
}

static CfResult Verify(HcfX509Crl *self, void *key)
{
    if ((self == NULL) || (key == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineVerify(
        ((HcfX509CrlImpl *)self)->spiObj, (HcfPubKey *)key);
}

static CfResult GetEncoded(HcfX509Crl *self, CfEncodingBlob *encodedByte)
{
    if ((self == NULL) || (encodedByte == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetEncoded(
        ((HcfX509CrlImpl *)self)->spiObj, encodedByte);
}

static long GetVersion(HcfX509Crl *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return OPENSSL_INVALID_VERSION;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return OPENSSL_INVALID_VERSION;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetVersion(
        ((HcfX509CrlImpl *)self)->spiObj);
}

static CfResult GetIssuerName(HcfX509Crl *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetIssuerName(
        ((HcfX509CrlImpl *)self)->spiObj, out);
}

static CfResult GetLastUpdate(HcfX509Crl *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetLastUpdate(
        ((HcfX509CrlImpl *)self)->spiObj, out);
}

static CfResult GetNextUpdate(HcfX509Crl *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetNextUpdate(
        ((HcfX509CrlImpl *)self)->spiObj, out);
}

static CfResult GetRevokedCert(HcfX509Crl *self, const CfBlob *serialNumber, HcfX509CrlEntry **entryOut)
{
    if (self == NULL || serialNumber == NULL || entryOut == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetRevokedCert(
        ((HcfX509CrlImpl *)self)->spiObj, serialNumber, entryOut);
}

static CfResult GetRevokedCertWithCert(HcfX509Crl *self, HcfX509Certificate *cert, HcfX509CrlEntry **entryOut)
{
    if ((self == NULL) || (cert == NULL) || (entryOut == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetRevokedCertWithCert(
        ((HcfX509CrlImpl *)self)->spiObj, cert, entryOut);
}

static CfResult GetRevokedCerts(HcfX509Crl *self, CfArray *entrysOut)
{
    if ((self == NULL) || (entrysOut == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetRevokedCerts(
        ((HcfX509CrlImpl *)self)->spiObj, entrysOut);
}

static CfResult GetTbsInfo(HcfX509Crl *self, CfBlob *tbsCertListOut)
{
    if ((self == NULL) || (tbsCertListOut == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetTbsInfo(
        ((HcfX509CrlImpl *)self)->spiObj, tbsCertListOut);
}

static CfResult GetSignature(HcfX509Crl *self, CfBlob *signature)
{
    if ((self == NULL) || (signature == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetSignature(
        ((HcfX509CrlImpl *)self)->spiObj, signature);
}

static CfResult GetSignatureAlgName(HcfX509Crl *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetSignatureAlgName(
        ((HcfX509CrlImpl *)self)->spiObj, out);
}

static CfResult GetSignatureAlgOid(HcfX509Crl *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetSignatureAlgOid(
        ((HcfX509CrlImpl *)self)->spiObj, out);
}

static CfResult GetSignatureAlgParams(HcfX509Crl *self, CfBlob *sigAlgParamOut)
{
    if ((self == NULL) || (sigAlgParamOut == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetSignatureAlgParams(
        ((HcfX509CrlImpl *)self)->spiObj, sigAlgParamOut);
}

static CfResult GetExtensions(HcfX509Crl *self, CfBlob *outBlob)
{
    if ((self == NULL) || (outBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetExtensions(
        ((HcfX509CrlImpl *)self)->spiObj, outBlob);
}

static CfResult ToString(HcfX509Crl *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineToString(
        ((HcfX509CrlImpl *)self)->spiObj, out);
}

static CfResult HashCode(HcfX509Crl *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineHashCode(
        ((HcfX509CrlImpl *)self)->spiObj, out);
}

static CfResult GetExtensionsOjbect(HcfX509Crl *self, CfBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineGetExtensionsObject(
        ((HcfX509CrlImpl *)self)->spiObj, out);
}

static CfResult Match(HcfX509Crl *self, const HcfX509CrlMatchParams *matchParams, bool *out)
{
    if ((self == NULL) || (matchParams == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CrlClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509CrlImpl *)self)->spiObj->engineMatch(
        ((HcfX509CrlImpl *)self)->spiObj, matchParams, out);
}

CfResult HcfX509CrlCreate(const CfEncodingBlob *inStream, HcfX509Crl **returnObj)
{
    CF_LOG_I("enter");
    if ((inStream == NULL) || (inStream->data == NULL) || (inStream->len > HCF_MAX_BUFFER_LEN) || (returnObj == NULL)) {
        LOGE("FuncSet is null!");
        return CF_INVALID_PARAMS;
    }
    const HcfX509CrlFuncSet *funcSet = FindAbility("X509");
    if (funcSet == NULL) {
        return CF_NOT_SUPPORT;
    }
    HcfX509CrlSpi *spiObj = NULL;
    CfResult res = funcSet->createFunc(inStream, &spiObj);
    if (res != CF_SUCCESS) {
        LOGE("Failed to create spi object!");
        return res;
    }
    HcfX509CrlImpl *x509CertImpl = (HcfX509CrlImpl *)CfMalloc(sizeof(HcfX509CrlImpl), 0);
    if (x509CertImpl == NULL) {
        LOGE("Failed to allocate x509CertImpl memory!");
        CfObjDestroy(spiObj);
        return CF_ERR_MALLOC;
    }
    x509CertImpl->base.base.base.getClass = GetX509CrlClass;
    x509CertImpl->base.base.base.destroy = DestroyX509Crl;
    x509CertImpl->base.base.getType = GetType;
    x509CertImpl->base.base.isRevoked = IsRevoked;
    x509CertImpl->base.verify = Verify;
    x509CertImpl->base.getEncoded = GetEncoded;
    x509CertImpl->base.getVersion = GetVersion;
    x509CertImpl->base.getIssuerName = GetIssuerName;
    x509CertImpl->base.getLastUpdate = GetLastUpdate;
    x509CertImpl->base.getNextUpdate = GetNextUpdate;
    x509CertImpl->base.getRevokedCert = GetRevokedCert;
    x509CertImpl->base.getRevokedCertWithCert = GetRevokedCertWithCert;
    x509CertImpl->base.getRevokedCerts = GetRevokedCerts;
    x509CertImpl->base.getTbsInfo = GetTbsInfo;
    x509CertImpl->base.getSignature = GetSignature;
    x509CertImpl->base.getSignatureAlgName = GetSignatureAlgName;
    x509CertImpl->base.getSignatureAlgOid = GetSignatureAlgOid;
    x509CertImpl->base.getSignatureAlgParams = GetSignatureAlgParams;
    x509CertImpl->base.getExtensions = GetExtensions;
    x509CertImpl->base.toString = ToString;
    x509CertImpl->base.hashCode = HashCode;
    x509CertImpl->base.getExtensionsObject = GetExtensionsOjbect;
    x509CertImpl->base.match = Match;
    x509CertImpl->spiObj = spiObj;
    *returnObj = (HcfX509Crl *)x509CertImpl;
    return CF_SUCCESS;
}