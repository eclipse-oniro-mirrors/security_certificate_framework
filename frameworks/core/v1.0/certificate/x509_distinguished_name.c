/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "x509_distinguished_name.h"
#include "x509_distinguished_name_spi.h"

#include <securec.h>

#include "config.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "utils.h"
#include "x509_distinguished_name_openssl.h"

#define HCF_X509_DISTINGUISHED_NAME_CLASS "HcfX509DistinguishedName"
typedef CfResult (*HcfX509DistinguishedNameSpiCreateFunc)(const CfBlob *, const bool, HcfX509DistinguishedNameSpi **);

typedef struct {
    HcfX509DistinguishedName base;
    HcfX509DistinguishedNameSpi *spiObj;
    const char *certType;
} HcfX509DistinguishedNameImpl;

typedef struct {
    HcfX509DistinguishedNameSpiCreateFunc createFunc;
} HcfX509DistinguishedNameFuncSet;

typedef struct {
    char *certType;
    HcfX509DistinguishedNameFuncSet funcSet;
} HcfDistiNameFactoryAbility;

static const char *GetX509DistinguishedNameClass(void)
{
    return HCF_X509_DISTINGUISHED_NAME_CLASS;
}

static const HcfDistiNameFactoryAbility X509_DISTINGUISHED_NAME_ABILITY_SET[] = {
    { "X509DistinguishedName", { OpensslX509DistinguishedNameSpiCreate, } }
};

static const HcfX509DistinguishedNameFuncSet *FindAbility(const char *certType)
{
    if (certType == NULL) {
        LOGE("CertType is null!");
        return NULL;
    }
    for (uint32_t i = 0; i < sizeof(X509_DISTINGUISHED_NAME_ABILITY_SET) / sizeof(HcfDistiNameFactoryAbility); i++) {
        if (strcmp(X509_DISTINGUISHED_NAME_ABILITY_SET[i].certType, certType) == 0) {
            return &(X509_DISTINGUISHED_NAME_ABILITY_SET[i].funcSet);
        }
    }
    LOGE("Cert not support! [cert]: %s", certType);
    return NULL;
}

static void DestroyX509DistinguishedName(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    if (!IsClassMatch(self, GetX509DistinguishedNameClass())) {
        LOGE("Class is not match.");
        return;
    }
    HcfX509DistinguishedNameImpl *impl = (HcfX509DistinguishedNameImpl *)self;
    CfObjDestroy(impl->spiObj);
    CfFree(impl);
}

static CfResult GetEncoded(HcfX509DistinguishedName *self, CfEncodingBlob *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509DistinguishedNameClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509DistinguishedNameImpl *)self)->spiObj->engineGetEncode(
        ((HcfX509DistinguishedNameImpl *)self)->spiObj, out);
}

static CfResult GetName(HcfX509DistinguishedName *self, CfBlob *type, CfBlob *out, CfArray *outArr)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509DistinguishedNameClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    return ((HcfX509DistinguishedNameImpl *)self)->spiObj->engineGetName(
        ((HcfX509DistinguishedNameImpl *)self)->spiObj, type, out, outArr);
}

CfResult HcfX509DistinguishedNameCreate(const CfBlob *inStream, bool bString, HcfX509DistinguishedName **returnObj)
{
    CF_LOG_I("enter");
    if ((inStream == NULL) || (returnObj == NULL)) {
        return CF_INVALID_PARAMS;
    }
    const HcfX509DistinguishedNameFuncSet *funcSet = FindAbility("X509DistinguishedName");
    if (funcSet == NULL) {
        return CF_NOT_SUPPORT;
    }
    HcfX509DistinguishedNameSpi *spiObj = NULL;
    CfResult res = funcSet->createFunc(inStream, bString, &spiObj);
    if (res != CF_SUCCESS) {
        LOGE("Failed to create spi object!");
        return res;
    }
    HcfX509DistinguishedNameImpl *x509NameImpl =
        (HcfX509DistinguishedNameImpl *)CfMalloc(sizeof(HcfX509DistinguishedNameImpl), 0);
    if (x509NameImpl == NULL) {
        LOGE("Failed to allocate x509DistinguishedNameImpl memory!");
        CfObjDestroy(spiObj);
        return CF_ERR_MALLOC;
    }
    x509NameImpl->base.base.getClass = GetX509DistinguishedNameClass;
    x509NameImpl->base.base.destroy = DestroyX509DistinguishedName;
    x509NameImpl->base.getEncode = GetEncoded;
    x509NameImpl->base.getName = GetName;
    x509NameImpl->spiObj = spiObj;
    *returnObj = (HcfX509DistinguishedName *)x509NameImpl;
    return CF_SUCCESS;
}