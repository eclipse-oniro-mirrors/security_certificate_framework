/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "ani_cert_cms_generator.h"
#include "ani_common.h"
#include "x509_distinguished_name.h"
#include "securec.h"

namespace {
using namespace ANI::CertFramework;

bool CopyBlobDataToPrivateKey(CfBlob *blob, CfEncodingBlob *privateKey)
{
    privateKey->data = static_cast<uint8_t *>(CfMalloc(blob->size, 0));
    if (privateKey->data == nullptr) {
        LOGE("malloc private key data failed!");
        return false;
    }
    if (memcpy_s(privateKey->data, blob->size, blob->data, blob->size) != EOK) {
        LOGE("memcpy_s private key data failed!");
        CfFree(privateKey->data);
        privateKey->data = nullptr;
        return false;
    }
    privateKey->len = blob->size;
    return true;
}

bool SetMdName(char **mdName, const string& mdNameStr)
{
    if (mdName == nullptr) {
        return false;
    }

    *mdName = static_cast<char *>(CfMalloc(mdNameStr.size() + 1, 0));
    if (*mdName == nullptr) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc mdName failed");
        return false;
    }

    if (strcpy_s(*mdName, mdNameStr.size() + 1, mdNameStr.c_str()) != EOK) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "copy mdName failed");
        CfFree(*mdName);
        *mdName = nullptr;
        return false;
    }
    return true;
}

CfResult SetCsrAttribute(HcfAttributes *attr, const CsrAttribute& csrAttr)
{
    if (attr == nullptr) {
        return CF_INVALID_PARAMS;
    }

    size_t nameLen = csrAttr.type.size() + 1;
    attr->attributeName = static_cast<char *>(CfMalloc(nameLen, 0));
    if (attr->attributeName == nullptr) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc attribute name failed");
        return CF_ERR_MALLOC;
    }

    if (strcpy_s(attr->attributeName, nameLen, csrAttr.type.c_str()) != EOK) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "copy attribute name failed");
        CfFree(attr->attributeName);
        attr->attributeName = nullptr;
        return CF_INVALID_PARAMS;
    }

    size_t valueLen = csrAttr.value.size() + 1;
    attr->attributeValue = static_cast<char *>(CfMalloc(valueLen, 0));
    if (attr->attributeValue == nullptr) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc attribute value failed");
        CfFree(attr->attributeName);
        attr->attributeName = nullptr;
        return CF_ERR_MALLOC;
    }

    if (strcpy_s(attr->attributeValue, valueLen, csrAttr.value.c_str()) != EOK) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "copy attribute value failed");
        CfFree(attr->attributeValue);
        CfFree(attr->attributeName);
        attr->attributeName = nullptr;
        attr->attributeValue = nullptr;
        return CF_INVALID_PARAMS;
    }
    return CF_SUCCESS;
}

bool GetX509CsrSubject(HcfX509DistinguishedName **subject, CsrGenerationConfig const& config)
{
    HcfX509DistinguishedName *distinguishedName =
        reinterpret_cast<HcfX509DistinguishedName *>(config.subject->GetX500DistinguishedNameObj());
    if (distinguishedName == nullptr) {
        return false;
    }
    *subject = distinguishedName;
    return true;
}

void FreeCsrCfBlobArray(HcfAttributes *array, uint32_t arrayLen)
{
    if (array == NULL) {
        return;
    }

    for (uint32_t i = 0; i < arrayLen; ++i) {
        CfFree(array[i].attributeName);
        CfFree(array[i].attributeValue);
    }

    CfFree(array);
}

bool GetX509CsrAttributeArray(HcfAttributesArray *attribute, const optional_view<array<CsrAttribute>> attributes)
{
    bool hasProperty = attributes.has_value()? true : false;
    if (!hasProperty) {
        attribute->array = nullptr;
        attribute->attributeSize = 0;
        return true;
    }
    array<CsrAttribute> attrArray = attributes.value();
    size_t attrSize = attrArray.size();
    attribute->array = static_cast<HcfAttributes *>(CfMalloc(sizeof(HcfAttributes) * attrSize, 0));
    if (attribute->array == nullptr) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc attributes array failed");
        return false;
    }
    for (size_t i = 0; i < attrSize; i++) {
        CfResult ret = SetCsrAttribute(attribute->array + i, attrArray[i]);
        if (ret != CF_SUCCESS) {
            FreeCsrCfBlobArray(attribute->array, i);
            attribute->array = nullptr;
            attribute->attributeSize = 0;
            return false;
        }
    }
    attribute->attributeSize = attrSize;
    return true;
}

void FreeGenCsrConf(HcfGenCsrConf *conf)
{
    if (conf == nullptr) {
        return;
    }
    if (conf->attribute.array != NULL) {
        FreeCsrCfBlobArray(conf->attribute.array, conf->attribute.attributeSize);
    }

    if (conf->mdName != nullptr) {
        CfFree(conf->mdName);
        conf->mdName = nullptr;
    }

    CfFree(conf);
}

void FreeCmsSignerOptions(HcfCmsSignerOptions *options)
{
    if (options != nullptr) {
        CfFree(options->mdName);
        options->mdName = nullptr;
        CfFree(options);
        options = nullptr;
    }
}

void FreeCmsGeneratorOptions(HcfCmsGeneratorOptions *options)
{
    if (options != nullptr) {
        CfFree(options);
        options = nullptr;
    }
}
} // namespace

namespace ANI::CertFramework {
CmsGeneratorImpl::CmsGeneratorImpl() {}

CmsGeneratorImpl::CmsGeneratorImpl(HcfCmsGenerator *cmsGenerator) : cmsGenerator_(cmsGenerator) {}

CmsGeneratorImpl::~CmsGeneratorImpl()
{
    CfObjDestroy(this->cmsGenerator_);
    this->cmsGenerator_ = nullptr;
}

void FreePrivateKeyInfo(HcfPrivateKeyInfo *privateKey)
{
    if (privateKey != nullptr) {
        if (privateKey->privateKey != nullptr && privateKey->privateKey->data != nullptr) {
            memset_s(privateKey->privateKey->data, privateKey->privateKey->len, 0, privateKey->privateKey->len);
            CfFree(privateKey->privateKey->data);
            CfFree(privateKey->privateKey);
        }
        if (privateKey->privateKeyPassword != nullptr) {
            size_t len = strlen(privateKey->privateKeyPassword);
            if (len > 0) {
                (void)memset_s(privateKey->privateKeyPassword, len, 0, len);
                CfFree(privateKey->privateKeyPassword);
            }
        }
        CfFree(privateKey);
    }
}

void GetPrivateKeyPassword(char **password, ThPrivateKeyInfo const& keyInfo)
{
    if (keyInfo.password.has_value()) {
        size_t length = keyInfo.password.value().size();
        char *tmpPassword = static_cast<char *>(CfMalloc(length + 1, 0));
        if (tmpPassword == nullptr) {
            ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc password failed");
            return;
        }
        if (strcpy_s(tmpPassword, length + 1, keyInfo.password.value().c_str()) != EOK) {
            ANI_LOGE_THROW(CF_INVALID_PARAMS, "copy password failed");
            CfFree(tmpPassword);
            tmpPassword = nullptr;
            return;
        }
        *password = tmpPassword;
    }
}

void SetPrivateKeyInfo(ThPrivateKeyInfo const& keyInfo, HcfPrivateKeyInfo **privateKey)
{
    *privateKey = static_cast<HcfPrivateKeyInfo *>(CfMalloc(sizeof(HcfPrivateKeyInfo), 0));
    if (*privateKey == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "malloc private key info failed");
        return;
    }
    (*privateKey)->privateKey = static_cast<CfEncodingBlob *>(CfMalloc(sizeof(CfEncodingBlob), 0));
    if ((*privateKey)->privateKey == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "malloc private key blob failed");
        CfFree(*privateKey);
        *privateKey = nullptr;
        return;
    }
    CfBlob keyBlob = {};
    if (keyInfo.key.get_tag() == OptStrUint8Arr::tag_t::STRING) {
        StringToDataBlob(keyInfo.key.get_STRING_ref(), keyBlob);
    } else {
        ArrayU8ToDataBlob(keyInfo.key.get_UINT8ARRAY_ref(), keyBlob);
    }

    if (keyInfo.key.get_tag() == OptStrUint8Arr::tag_t::STRING) {
        (*privateKey)->privateKey->encodingFormat = CF_FORMAT_PEM;
    } else {
        (*privateKey)->privateKey->encodingFormat = CF_FORMAT_DER;
    }
    if (!CopyBlobDataToPrivateKey(&keyBlob, (*privateKey)->privateKey)) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "copy blob data to private key failed");
        CfFree((*privateKey)->privateKey);
        CfFree(*privateKey);
        *privateKey = nullptr;
        return;
    }
    GetPrivateKeyPassword(&(*privateKey)->privateKeyPassword, keyInfo);
}

void SetCmsSignerOptions(HcfCmsSignerOptions **options, CmsSignerConfig const& config)
{
    *options = static_cast<HcfCmsSignerOptions *>(CfMalloc(sizeof(HcfCmsSignerOptions), 0));
    if (!SetMdName(&(*options)->mdName, config.mdName)) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "set mdName failed");
        CfFree(*options);
        *options = nullptr;
        return;
    }
    (*options)->addCert = config.addCert.has_value() ? config.addCert.value() : false;
    (*options)->addAttr = config.addAttr.has_value() ? config.addAttr.value() : false;
    (*options)->addSmimeCapAttr = config.addSmimeCapAttr.has_value() ? config.addSmimeCapAttr.value() : false;
}

void CmsGeneratorImpl::AddSigner(weak::X509Cert cert, ThPrivateKeyInfo const& keyInfo, CmsSignerConfig const& config)
{
    if (this->cmsGenerator_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "CmsGenerator is not initialized");
        return;
    }
    HcfX509Certificate *x509Cert = reinterpret_cast<HcfX509Certificate *>(cert->GetX509CertObj());
    if (x509Cert == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Cert is null");
        return;
    }
    HcfPrivateKeyInfo *privateKey = nullptr;
    SetPrivateKeyInfo(keyInfo, &privateKey);
    HcfCmsSignerOptions *options = nullptr;
    SetCmsSignerOptions(&options, config);

    CfResult ret = this->cmsGenerator_->addSigner(this->cmsGenerator_, &(x509Cert->base), privateKey, options);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "add signer failed");
        FreePrivateKeyInfo(privateKey);
        FreeCmsSignerOptions(options);
        return;
    }
    FreePrivateKeyInfo(privateKey);
    FreeCmsSignerOptions(options);
}

void CmsGeneratorImpl::AddCert(weak::X509Cert cert)
{
    if (this->cmsGenerator_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "CmsGenerator is not initialized");
        return;
    }
    HcfX509Certificate *x509Cert = reinterpret_cast<HcfX509Certificate *>(cert->GetX509CertObj());
    if (x509Cert == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Cert is null");
        return;
    }
    CfResult ret = this->cmsGenerator_->addCert(this->cmsGenerator_, &(x509Cert->base));
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "add cert failed");
        return;
    }
}

void SetCmsGeneratorOptions(HcfCmsGeneratorOptions **cmsOptions, optional_view<CmsGeneratorOptions> const& config)
{
    *cmsOptions = static_cast<HcfCmsGeneratorOptions *>(CfMalloc(sizeof(HcfCmsGeneratorOptions), 0));
    (*cmsOptions)->dataFormat = config.has_value() ?
        static_cast<HcfCmsContentDataFormat>(config.value().contentDataFormat.value().get_value()) :
        HcfCmsContentDataFormat::BINARY;
    (*cmsOptions)->outFormat = config.has_value() ?
        static_cast<HcfCmsFormat>(config.value().outFormat.value().get_value()) : HcfCmsFormat::CMS_DER;
    (*cmsOptions)->isDetachedContent = config.has_value() ? config.value().isDetached.value() : false;
}

OptStrUint8Arr CmsGeneratorImpl::DoFinalSync(array_view<uint8_t> data, optional_view<CmsGeneratorOptions> options)
{
    if (this->cmsGenerator_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "CmsGenerator is not initialized");
        return OptStrUint8Arr::make_UINT8ARRAY(array<uint8_t>{});
    }
    HcfCmsGeneratorOptions *cmsOptions = nullptr;
    SetCmsGeneratorOptions(&cmsOptions, options);
    CfBlob contentBlob = { data.size(), data.data() };
    CfBlob outBlob = { 0,  nullptr, };
    CfResult ret = this->cmsGenerator_->doFinal(this->cmsGenerator_, &contentBlob, cmsOptions, &outBlob);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "do final failed");
        FreeCmsGeneratorOptions(cmsOptions);
        return OptStrUint8Arr::make_UINT8ARRAY(array<uint8_t>{});
    }
    if (cmsOptions->outFormat == HcfCmsFormat::CMS_PEM) {
        CfBlobDataClearAndFree(&outBlob);
        FreeCmsGeneratorOptions(cmsOptions);
        return OptStrUint8Arr::make_STRING(reinterpret_cast<char *>(outBlob.data), outBlob.size);
    } else {
        array<uint8_t> data = {};
        DataBlobToArrayU8({ outBlob.size, outBlob.data }, data);
        CfBlobDataClearAndFree(&outBlob);
        FreeCmsGeneratorOptions(cmsOptions);
        return OptStrUint8Arr::make_UINT8ARRAY(data);
    }
}

CmsGenerator CreateCmsGenerator(CmsContentType contentType)
{
    HcfCmsGenerator *cmsGenerator = nullptr;
    CfResult ret = HcfCreateCmsGenerator(static_cast<HcfCmsContentType>(contentType.get_value()), &cmsGenerator);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "create cms generator failed");
        return make_holder<CmsGeneratorImpl, CmsGenerator>();
    }
    return make_holder<CmsGeneratorImpl, CmsGenerator>(cmsGenerator);
}

void SetConfig(HcfGenCsrConf **csrConfig, CsrGenerationConfig const& config)
{
    HcfGenCsrConf *tmpConf = static_cast<HcfGenCsrConf *>(CfMalloc(sizeof(HcfGenCsrConf), 0));
    if (tmpConf == nullptr) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc csr config failed");
        return;
    }
    if (!GetX509CsrSubject(&tmpConf->subject, config)) {
        FreeGenCsrConf(tmpConf);
        return;
    }
    if (!GetX509CsrAttributeArray(&tmpConf->attribute, config.attributes)) {
        FreeGenCsrConf(tmpConf);
        return;
    }
    if (!SetMdName(&tmpConf->mdName, config.mdName)) {
        FreeGenCsrConf(tmpConf);
        return;
    }
    if (config.outFormat.has_value()) {
        tmpConf->isPem = (config.outFormat.value() == 0);
    }
    *csrConfig = tmpConf;
}

OptStrUint8Arr GenerateCsr(ThPrivateKeyInfo const& keyInfo, CsrGenerationConfig const& config)
{
    HcfPrivateKeyInfo *privateKey = nullptr;
    SetPrivateKeyInfo(keyInfo, &privateKey);
    HcfGenCsrConf *csrConfig = nullptr;
    SetConfig(&csrConfig, config);
    CfBlob csrBlob = {};
    CfResult ret = HcfX509CertificateGenCsr(privateKey, csrConfig, &csrBlob);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "GenerateCsr failed");
        FreePrivateKeyInfo(privateKey);
        FreeGenCsrConf(csrConfig);
        return OptStrUint8Arr::make_UINT8ARRAY(array<uint8_t>{});
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(csrBlob, data);
    CfBlobDataClearAndFree(&csrBlob);
    FreePrivateKeyInfo(privateKey);
    FreeGenCsrConf(csrConfig);
    return OptStrUint8Arr::make_UINT8ARRAY(data);
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateCmsGenerator(ANI::CertFramework::CreateCmsGenerator);
TH_EXPORT_CPP_API_GenerateCsr(ANI::CertFramework::GenerateCsr);
// NOLINTEND
