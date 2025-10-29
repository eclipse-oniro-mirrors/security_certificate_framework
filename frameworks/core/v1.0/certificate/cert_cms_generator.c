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

#include "cert_cms_generator.h"
#include <securec.h>
#include "cf_blob.h"
#include "cert_cms_generator_spi.h"
#include "config.h"
#include "cf_result.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "utils.h"
#include "cf_type.h"
#include "x509_cert_cms_generator_openssl.h"

typedef CfResult (*CertCmsGeneratorSpiCreateFunc)(HcfCmsContentType type, HcfCmsGeneratorSpi **);

typedef struct {
    HcfCmsGenerator base;
    HcfCmsGeneratorSpi *spiObj;
} CertCmsGeneratorImpl;

typedef struct {
    HcfCmsParser base;
    HcfCmsParserSpi *spiObj;
} CertCmsParserImpl;

typedef struct {
    CertCmsGeneratorSpiCreateFunc createFunc;
} HcfCmsGeneratorFuncSet;

typedef struct {
    HcfCmsContentType type;
    HcfCmsGeneratorFuncSet funcSet;
} HcfCmsGeneratorAbility;

static const HcfCmsGeneratorAbility CERT_PATH_CMS_GENERATOR_ABILITY_SET[] = {
    { SIGNED_DATA, { HcfCmsGeneratorSpiCreate } },
    { ENVELOPED_DATA, { HcfCmsGeneratorSpiCreate } }
};

static const HcfCmsGeneratorFuncSet *FindAbility(HcfCmsContentType type)
{
    for (uint32_t i = 0; i < sizeof(CERT_PATH_CMS_GENERATOR_ABILITY_SET) / sizeof(HcfCmsGeneratorAbility); i++) {
        if (CERT_PATH_CMS_GENERATOR_ABILITY_SET[i].type == type) {
            return &(CERT_PATH_CMS_GENERATOR_ABILITY_SET[i].funcSet);
        }
    }
    LOGE("Type for certCmsGenerator is not support! [type]: %{public}d", type);
    return NULL;
}

static const char *GetCertCmsGeneratorClass(void)
{
    return "HcfCmsGenerator";
}

static const char *GetCertCmsParserClass(void)
{
    return "HcfCmsParser";
}

static void DestroyCertCmsParser(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    if (!CfIsClassMatch(self, GetCertCmsParserClass())) {
        LOGE("Class is not match.");
        return;
    }
    CertCmsParserImpl *cmsParserImpl = (CertCmsParserImpl *)self;
    CfObjDestroy(cmsParserImpl->spiObj);
    CfFree(cmsParserImpl);
}

static void DestroyCertCmsGenerator(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    if (!CfIsClassMatch(self, GetCertCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return;
    }
    CertCmsGeneratorImpl *cmsImpl = (CertCmsGeneratorImpl *)self;
    CfObjDestroy(cmsImpl->spiObj);
    CfFree(cmsImpl);
}

static CfResult SetRawData(HcfCmsParser *self, const CfBlob *rawData, HcfCmsFormat cmsFormat)
{
    if (self == NULL || rawData == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCertCmsParserClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertCmsParserImpl *impl = (CertCmsParserImpl *)self;
    return impl->spiObj->engineSetRawData(impl->spiObj, rawData, cmsFormat);
}

static CfResult GetContentType(HcfCmsParser *self, HcfCmsContentType *contentType)
{
    if (self == NULL || contentType == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCertCmsParserClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertCmsParserImpl *impl = (CertCmsParserImpl *)self;
    return impl->spiObj->engineGetContentType(impl->spiObj, contentType);
}

static CfResult VerifySignedData(HcfCmsParser *self, const HcfCmsParserSignedDataOptions *options)
{
    if (self == NULL || options == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCertCmsParserClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertCmsParserImpl *impl = (CertCmsParserImpl *)self;
    return impl->spiObj->engineVerifySignedData(impl->spiObj, options);
}

static CfResult GetContentData(HcfCmsParser *self, CfBlob *contentData)
{
    if (self == NULL || contentData == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCertCmsParserClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertCmsParserImpl *impl = (CertCmsParserImpl *)self;
    return impl->spiObj->engineGetContentData(impl->spiObj, contentData);
}

static CfResult GetCerts(HcfCmsParser *self, HcfCmsCertType cmsCertType, HcfX509CertificateArray *certs)
{
    if (self == NULL || certs == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCertCmsParserClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertCmsParserImpl *impl = (CertCmsParserImpl *)self;
    return impl->spiObj->engineGetCerts(impl->spiObj, cmsCertType, certs);
}

static CfResult DecryptEnvelopedData(HcfCmsParser *self, const HcfCmsParserDecryptEnvelopedDataOptions *options,
    CfBlob *encryptedContentData)
{
    if (self == NULL || options == NULL || encryptedContentData == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCertCmsParserClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertCmsParserImpl *impl = (CertCmsParserImpl *)self;
    return impl->spiObj->engineDecryptEnvelopedData(impl->spiObj, options, encryptedContentData);
}

static CfResult AddSigner(HcfCmsGenerator *self, const HcfCertificate *x509Cert,
                          const PrivateKeyInfo *privateKey, const HcfCmsSignerOptions *options)
{
    if (self == NULL || x509Cert == NULL || privateKey == NULL || options == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCertCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertCmsGeneratorImpl *impl = (CertCmsGeneratorImpl *)self;
    return impl->spiObj->engineAddSigner(impl->spiObj, x509Cert, privateKey, options);
}

static CfResult AddCert(HcfCmsGenerator *self, const HcfCertificate *x509Cert)
{
    if ((self == NULL) || (x509Cert == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCertCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertCmsGeneratorImpl *impl = (CertCmsGeneratorImpl *)self;
    return impl->spiObj->engineAddCert(impl->spiObj, x509Cert);
}

static CfResult DoFinal(HcfCmsGenerator *self, const CfBlob *content, const HcfCmsGeneratorOptions *options,
                        CfBlob *out)
{
    if ((self == NULL) || (content == NULL) || (options == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCertCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertCmsGeneratorImpl *impl = (CertCmsGeneratorImpl *)self;
    return impl->spiObj->engineDoFinal(impl->spiObj, content, options, out);
}

static CfResult SetRecipientEncryptionAlgorithm(HcfCmsGenerator *self, CfCmsRecipientEncryptionAlgorithm alg)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCertCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return CF_ERR_PARAMETER_CHECK;
    }
    CertCmsGeneratorImpl *impl = (CertCmsGeneratorImpl *)self;
    return impl->spiObj->engineSetRecipientEncryptionAlgorithm(impl->spiObj, alg);
}

static CfResult AddRecipientInfo(HcfCmsGenerator *self, CmsRecipientInfo *recipientInfo)
{
    if (self == NULL || recipientInfo == NULL) {
        LOGE("Invalid input parameter.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCertCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return CF_ERR_PARAMETER_CHECK;
    }
    CertCmsGeneratorImpl *impl = (CertCmsGeneratorImpl *)self;
    return impl->spiObj->engineAddRecipientInfo(impl->spiObj, recipientInfo);
}

static CfResult GetEncryptedContentData(HcfCmsGenerator *self, CfBlob *out)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetCertCmsGeneratorClass())) {
        LOGE("Class is not match.");
        return CF_ERR_PARAMETER_CHECK;
    }
    CertCmsGeneratorImpl *impl = (CertCmsGeneratorImpl *)self;
    return impl->spiObj->engineGetEncryptedContentData(impl->spiObj, out);
}

CfResult HcfCreateCmsGenerator(HcfCmsContentType type, HcfCmsGenerator **cmsGenerator)
{
    const HcfCmsGeneratorFuncSet *func = FindAbility(type);
    if (func == NULL) {
        LOGE("Func is null!");
        return CF_INVALID_PARAMS;
    }

    HcfCmsGeneratorSpi *spiObj = NULL;
    CfResult res = func->createFunc(type, &spiObj);
    if (res != CF_SUCCESS) {
        LOGE("Failed to create cms generator spi object!");
        return res;
    }
    CertCmsGeneratorImpl *returnCmsGenerator = (CertCmsGeneratorImpl *)CfMalloc(sizeof(CertCmsGeneratorImpl), 0);
    if (returnCmsGenerator == NULL) {
        LOGE("Failed to allocate returnCmsGenerator memory!");
        CfObjDestroy(spiObj);
        return CF_ERR_MALLOC;
    }

    returnCmsGenerator->base.addSigner = AddSigner;
    returnCmsGenerator->base.addCert = AddCert;
    returnCmsGenerator->base.doFinal = DoFinal;
    returnCmsGenerator->base.setRecipientEncryptionAlgorithm = SetRecipientEncryptionAlgorithm;
    returnCmsGenerator->base.addRecipientInfo = AddRecipientInfo;
    returnCmsGenerator->base.getEncryptedContentData = GetEncryptedContentData;
    returnCmsGenerator->base.base.destroy = DestroyCertCmsGenerator;
    returnCmsGenerator->base.base.getClass = GetCertCmsGeneratorClass;
    returnCmsGenerator->spiObj = spiObj;
    *cmsGenerator = (HcfCmsGenerator *)returnCmsGenerator;
    return CF_SUCCESS;
}

CfResult HcfCreateCmsParser(HcfCmsParser **cmsParser)
{
    if (cmsParser == NULL) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    HcfCmsParserSpi *spiObj = NULL;
    CfResult res = HcfCmsParserSpiCreate(&spiObj);
    if (res != CF_SUCCESS) {
        LOGE("Failed to create cms parser spi object!");
        return res;
    }
    CertCmsParserImpl *returnCmsParser = (CertCmsParserImpl *)CfMalloc(sizeof(CertCmsParserImpl), 0);
    if (returnCmsParser == NULL) {
        LOGE("Failed to allocate cms parser memory!");
        CfObjDestroy(spiObj);
        return CF_ERR_MALLOC;
    }
    returnCmsParser->base.setRawData = SetRawData;
    returnCmsParser->base.getContentType = GetContentType;
    returnCmsParser->base.verifySignedData = VerifySignedData;
    returnCmsParser->base.getContentData = GetContentData;
    returnCmsParser->base.getCerts = GetCerts;
    returnCmsParser->base.decryptEnvelopedData = DecryptEnvelopedData;
    returnCmsParser->base.base.getClass = GetCertCmsParserClass;
    returnCmsParser->base.base.destroy = DestroyCertCmsParser;
    returnCmsParser->spiObj = spiObj;
    *cmsParser = (HcfCmsParser *)returnCmsParser;
    return CF_SUCCESS;
}
