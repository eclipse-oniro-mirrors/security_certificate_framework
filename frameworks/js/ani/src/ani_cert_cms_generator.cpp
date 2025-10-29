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
#include "ani_x509_cert.h"
#include "x509_distinguished_name.h"

namespace {
using namespace ANI::CertFramework;

bool CopyString(const string &str, char **dst)
{
    *dst = static_cast<char *>(CfMalloc(str.size() + 1, 0));
    if (*dst == nullptr) {
        return false;
    }
    if (strcpy_s(*dst, str.size() + 1, str.c_str()) != EOK) {
        CF_FREE_PTR(*dst);
        return false;
    }
    return true;
}

bool CopyBlobDataToPrivateKey(CfBlob *blob, CfEncodingBlob *privateKey)
{
    privateKey->data = static_cast<uint8_t *>(CfMalloc(blob->size, 0));
    if (privateKey->data == nullptr) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc private key data failed!");
        return false;
    }
    if (memcpy_s(privateKey->data, blob->size, blob->data, blob->size) != EOK) {
        ANI_LOGE_THROW(CF_ERR_COPY, "memcpy_s private key data failed!");
        CF_FREE_PTR(privateKey->data);
        return false;
    }
    privateKey->len = blob->size;
    return true;
}

CfResult SetCsrAttribute(HcfAttributes *attr, const CsrAttribute& csrAttr)
{
    if (attr == nullptr) {
        return CF_INVALID_PARAMS;
    }

    if (!CopyString(csrAttr.type, &attr->attributeName)) {
        ANI_LOGE_THROW(CF_ERR_COPY, "copy attribute name failed");
        return CF_ERR_COPY;
    }

    if (!CopyString(csrAttr.value, &attr->attributeValue)) {
        ANI_LOGE_THROW(CF_ERR_COPY, "copy attribute value failed");
        CF_FREE_PTR(attr->attributeName);
        return CF_ERR_COPY;
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
    if (array == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < arrayLen; ++i) {
        CF_FREE_PTR(array[i].attributeName);
        CF_FREE_PTR(array[i].attributeValue);
    }

    CF_FREE_PTR(array);
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
    if (attrSize == 0) {
        attribute->array = nullptr;
        attribute->attributeSize = 0;
        return false;
    }
    attribute->array = static_cast<HcfAttributes *>(CfMalloc(sizeof(HcfAttributes) * attrSize, 0));
    if (attribute->array == nullptr) {
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

bool IsValidMdName(const char *mdName)
{
    if (mdName == nullptr) {
        return false;
    }
    static const std::unordered_map<std::string, bool> validNames = {
        {"SHA1", true},
        {"SHA256", true},
        {"SHA384", true},
        {"SHA512", true}
    };
    std::string name(mdName);
    return validNames.find(name) != validNames.end();
}

void FreeGenCsrConf(HcfGenCsrConf *conf)
{
    if (conf == nullptr) {
        return;
    }
    if (conf->attribute.array != nullptr) {
        FreeCsrCfBlobArray(conf->attribute.array, conf->attribute.attributeSize);
    }

    if (conf->mdName != nullptr) {
        CF_FREE_PTR(conf->mdName);
    }

    CF_FREE_PTR(conf);
}

bool SetConfig(HcfGenCsrConf **csrConfig, CsrGenerationConfig const& config)
{
    HcfGenCsrConf *tmpConf = static_cast<HcfGenCsrConf *>(CfMalloc(sizeof(HcfGenCsrConf), 0));
    if (tmpConf == nullptr) {
        return false;
    }
    if (!GetX509CsrSubject(&tmpConf->subject, config)) {
        FreeGenCsrConf(tmpConf);
        return false;
    }
    if (!GetX509CsrAttributeArray(&tmpConf->attribute, config.attributes)) {
        FreeGenCsrConf(tmpConf);
        return false;
    }
    char *mdName = const_cast<char *>(config.mdName.c_str());
    if (!IsValidMdName(mdName)) {
        FreeGenCsrConf(tmpConf);
        return false;
    }
    if (!CopyString(config.mdName, &tmpConf->mdName)) {
        FreeGenCsrConf(tmpConf);
        return false;
    }
    if (config.outFormat.has_value()) {
        tmpConf->isPem = config.outFormat.value() == 0 ? true : false;
    } else {
        tmpConf->isPem = true;
    }
    *csrConfig = tmpConf;
    return true;
}

void FreeCmsSignerOptions(HcfCmsSignerOptions *options)
{
    if (options != nullptr) {
        CF_FREE_PTR(options->mdName);
        CF_FREE_PTR(options);
    }
}

void FreePrivateKeyInfo(HcfPrivateKeyInfo **privateKey)
{
    if (*privateKey != nullptr) {
        if ((*privateKey)->privateKey != nullptr) {
            CfEncodingBlobDataFree((*privateKey)->privateKey);
            (*privateKey)->privateKey = nullptr;
        }
        if ((*privateKey)->privateKeyPassword != nullptr) {
            size_t len = strlen((*privateKey)->privateKeyPassword);
            if (len > 0) {
                (void)memset_s((*privateKey)->privateKeyPassword, len, 0, len);
                CF_FREE_PTR((*privateKey)->privateKeyPassword);
            }
        }
        CF_FREE_PTR(*privateKey);
    }
}

CfResult GetPrivateKeyPassword(char **password, ThPrivateKeyInfo const& keyInfo)
{
    if (keyInfo.password.has_value()) {
        if (!CopyString(keyInfo.password.value(), password)) {
            ANI_LOGE_THROW(CF_ERR_COPY, "copy password failed");
            return CF_ERR_COPY;
        }
        return CF_SUCCESS;
    }
    return CF_SUCCESS;
}

CfResult SetPrivateKeyInfo(ThPrivateKeyInfo const& keyInfo, HcfPrivateKeyInfo **privateKey)
{
    *privateKey = static_cast<HcfPrivateKeyInfo *>(CfMalloc(sizeof(HcfPrivateKeyInfo), 0));
    if (*privateKey == nullptr) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc private key info failed");
        return CF_ERR_MALLOC;
    }
    (*privateKey)->privateKey = static_cast<CfEncodingBlob *>(CfMalloc(sizeof(CfEncodingBlob), 0));
    if ((*privateKey)->privateKey == nullptr) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc private key blob failed");
        return CF_ERR_MALLOC;
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
        ANI_LOGE_THROW(CF_ERR_MALLOC, "copy blob data to private key failed");
        return CF_ERR_MALLOC;
    }
    CfResult ret = GetPrivateKeyPassword(&(*privateKey)->privateKeyPassword, keyInfo);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "get private key password failed");
        return ret;
    }
    return ret;
}

CfResult SetCmsSignerOptions(HcfCmsSignerOptions **options, CmsSignerConfig const& config)
{
    *options = static_cast<HcfCmsSignerOptions *>(CfMalloc(sizeof(HcfCmsSignerOptions), 0));
    if (*options == nullptr) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc cms signer options failed");
        return CF_ERR_MALLOC;
    }
    if (!CopyString(config.mdName, &(*options)->mdName)) {
        ANI_LOGE_THROW(CF_ERR_COPY, "copy mdName failed");
        CF_FREE_PTR(*options);
        return CF_ERR_COPY;
    }
    (*options)->padding = config.rsaSignaturePadding.has_value() ?
        static_cast<CfCmsRsaSignaturePadding>(config.rsaSignaturePadding.value().get_value()) : PKCS1_PADDING;
    (*options)->addCert = config.addCert.has_value() ? config.addCert.value() : true;
    (*options)->addAttr = config.addAttr.has_value() ? config.addAttr.value() : true;
    (*options)->addSmimeCapAttr = config.addSmimeCapAttr.has_value() ? config.addSmimeCapAttr.value() : true;
    return CF_SUCCESS;
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
    CfResult ret = SetPrivateKeyInfo(keyInfo, &privateKey);
    if (ret != CF_SUCCESS) {
        FreePrivateKeyInfo(&privateKey);
        ANI_LOGE_THROW(ret, "set private key info failed");
        return;
    }
    HcfCmsSignerOptions *options = nullptr;
    ret = SetCmsSignerOptions(&options, config);
    if (ret != CF_SUCCESS) {
        FreePrivateKeyInfo(&privateKey);
        ANI_LOGE_THROW(ret, "set cms signer options failed");
        return;
    }

    ret = this->cmsGenerator_->addSigner(this->cmsGenerator_, &(x509Cert->base), privateKey, options);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "add signer failed");
        FreePrivateKeyInfo(&privateKey);
        FreeCmsSignerOptions(options);
        return;
    }
    FreePrivateKeyInfo(&privateKey);
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

void CmsGeneratorImpl::SetRecipientEncryptionAlgorithm(CmsRecipientEncryptionAlgorithm algorithm)
{
    if (this->cmsGenerator_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "CmsGenerator is not initialized");
        return;
    }
    CfCmsRecipientEncryptionAlgorithm algo = static_cast<CfCmsRecipientEncryptionAlgorithm>(algorithm.get_value());
    CfResult res = this->cmsGenerator_->setRecipientEncryptionAlgorithm(this->cmsGenerator_, algo);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "set recipient encryption algorithm failed");
        return;
    }
}

void CmsGeneratorImpl::AddRecipientInfoSync(ThCmsRecipientInfo const& recipientInfo)
{
    if (this->cmsGenerator_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "CmsGenerator is not initialized");
        return;
    }
    HcfCmsRecipientInfo recInfo = {};
    KeyTransRecipientInfo keyTransInfo = {};
    KeyAgreeRecipientInfo keyAgreeInfo = {};
    if (recipientInfo.keyTransInfo.has_value()) {
        CmsKeyTransRecipientInfo keyTrans = recipientInfo.keyTransInfo.value();
        keyTransInfo.recipientCert = reinterpret_cast<HcfCertificate *>(keyTrans.cert->GetX509CertObj());
        recInfo.keyTransInfo = &keyTransInfo;
    }
    if (recipientInfo.keyAgreeInfo.has_value()) {
        CmsKeyAgreeRecipientInfo keyAgree = recipientInfo.keyAgreeInfo.value();
        keyAgreeInfo.recipientCert =
            reinterpret_cast<HcfCertificate *>(keyAgree.cert->GetX509CertObj());
        keyAgreeInfo.digestAlgorithm = keyAgree.digestAlgorithm.has_value() ?
            static_cast<CfCmsKeyAgreeRecipientDigestAlgorithm>(keyAgree.digestAlgorithm.value().get_value()) :
            CMS_SHA256;
        recInfo.keyAgreeInfo = &keyAgreeInfo;
    }
    CfResult res = this->cmsGenerator_->addRecipientInfo(this->cmsGenerator_, &recInfo);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "add recipient info failed");
        return;
    }
}

OptStrUint8Arr CmsGeneratorImpl::DoFinalSync(array_view<uint8_t> data, optional_view<CmsGeneratorOptions> options)
{
    if (this->cmsGenerator_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "CmsGenerator is not initialized");
        return OptStrUint8Arr::make_UINT8ARRAY(array<uint8_t>{});
    }
    HcfCmsGeneratorOptions cmsOptions = {};
    cmsOptions.dataFormat = HcfCmsContentDataFormat::BINARY;
    cmsOptions.outFormat = HcfCmsFormat::CMS_DER;
    cmsOptions.isDetachedContent = false;
    if (options.has_value()) {
        cmsOptions.dataFormat = options.value().contentDataFormat.has_value() ?
            static_cast<HcfCmsContentDataFormat>(options.value().contentDataFormat.value().get_value()) :
            HcfCmsContentDataFormat::BINARY;
        cmsOptions.outFormat = options.value().outFormat.has_value() ?
            static_cast<HcfCmsFormat>(options.value().outFormat.value().get_value()) :
            HcfCmsFormat::CMS_DER;
        cmsOptions.isDetachedContent = options.value().isDetached.has_value() ?
            options.value().isDetached.value() :
            false;
    }
    CfBlob contentBlob = { data.size(), data.data() };
    CfBlob outBlob = {};
    CfResult ret = this->cmsGenerator_->doFinal(this->cmsGenerator_, &contentBlob, &cmsOptions, &outBlob);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "do final failed");
        return OptStrUint8Arr::make_UINT8ARRAY(array<uint8_t>{});
    }
    OptStrUint8Arr result = OptStrUint8Arr::make_UINT8ARRAY(array<uint8_t>{});
    if (cmsOptions.outFormat == HcfCmsFormat::CMS_PEM) {
        result = OptStrUint8Arr::make_STRING(reinterpret_cast<char *>(outBlob.data), outBlob.size);
    } else {
        array<uint8_t> blob = {};
        DataBlobToArrayU8(outBlob, blob);
        result = OptStrUint8Arr::make_UINT8ARRAY(blob);
    }
    CfBlobDataClearAndFree(&outBlob);
    return result;
}

array<uint8_t> CmsGeneratorImpl::GetEncryptedContentDataSync()
{
    if (this->cmsGenerator_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "CmsGenerator is not initialized");
        return {};
    }
    CfBlob outBlob = {};
    CfResult res = this->cmsGenerator_->getEncryptedContentData(this->cmsGenerator_, &outBlob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get encrypted content data failed");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    CfBlobDataClearAndFree(&outBlob);
    return data;
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

CmsParserImpl::CmsParserImpl() {}

CmsParserImpl::CmsParserImpl(HcfCmsParser *cmsParser) : cmsParser_(cmsParser) {}

CmsParserImpl::~CmsParserImpl()
{
    CfObjDestroy(this->cmsParser_);
    this->cmsParser_ = nullptr;
}

void CmsParserImpl::SetRawDataSync(OptStrUint8Arr const& data, CmsFormat cmsFormat)
{
    if (this->cmsParser_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "cmsParser is not initialized");
        return;
    }
    CfBlob blob = {};
    if (data.get_tag() == OptStrUint8Arr::tag_t::STRING) {
        StringToDataBlob(data.get_STRING_ref(), blob);
    } else { // OptStrUint8Arr::tag_t::UINT8ARRAY
        ArrayU8ToDataBlob(data.get_UINT8ARRAY_ref(), blob);
    }
    HcfCmsFormat fmt = static_cast<HcfCmsFormat>(cmsFormat.get_value());
    CfResult res = this->cmsParser_->setRawData(this->cmsParser_, &blob, fmt);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "set raw data failed");
        return;
    }
}

CmsContentType CmsParserImpl::GetContentType()
{
    CmsContentType cmsType = CmsContentType(CmsContentType::key_t::SIGNED_DATA);
    if (this->cmsParser_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "cmsParser is not initialized");
        return cmsType;
    }
    HcfCmsContentType contentType;
    CfResult res = this->cmsParser_->getContentType(this->cmsParser_, &contentType);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get content type failed");
        return cmsType;
    }
    cmsType = CmsContentType(static_cast<CmsContentType::key_t>(contentType));
    return cmsType;
}

void CmsParserImpl::VerifySignedDataSync(CmsVerificationConfig const& config)
{
    if (this->cmsParser_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "cmsParser is not initialized");
        return;
    }
    CfBlob contentData = {};
    HcfCmsParserSignedDataOptions options = {};
    HcfX509CertificateArray trustCerts = {};
    HcfX509CertificateArray signerCerts = {};
    array<HcfX509Certificate *> trustCertsArray(config.trustCerts.size());
    array<HcfX509Certificate *> signerCertsArray(config.signerCerts.has_value() ?
        config.signerCerts.value().size() : 0);
    size_t i = 0;
    for (auto const& cert : config.trustCerts) {
        trustCertsArray[i++] = reinterpret_cast<HcfX509Certificate *>(cert->GetX509CertObj());
    }
    trustCerts.data = trustCertsArray.data();
    trustCerts.count = trustCertsArray.size();
    if (config.signerCerts.has_value()) {
        i = 0;
        for (auto const& cert : config.signerCerts.value()) {
            signerCertsArray[i++] = reinterpret_cast<HcfX509Certificate *>(cert->GetX509CertObj());
        }
        signerCerts.data = signerCertsArray.data();
        signerCerts.count = signerCertsArray.size();
    }
    options.trustCerts = &trustCerts;
    options.signerCerts = &signerCerts;
    if (config.contentData.has_value()) {
        ArrayU8ToDataBlob(config.contentData.value(), contentData);
        options.contentData = &contentData;
    }
    options.contentDataFormat = config.contentDataFormat.has_value() ?
        static_cast<HcfCmsContentDataFormat>(config.contentDataFormat.value().get_value()) : BINARY;
    CfResult res = this->cmsParser_->verifySignedData(this->cmsParser_, &options);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "verify signed data failed");
        return;
    }
}

array<uint8_t> CmsParserImpl::GetContentDataSync()
{
    if (this->cmsParser_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "cmsParser is not initialized");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->cmsParser_->getContentData(this->cmsParser_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get content data failed");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataClearAndFree(&blob);
    return data;
}

array<X509Cert> CmsParserImpl::GetCertsSync(CmsCertType type)
{
    if (this->cmsParser_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "cmsParser is not initialized");
        return {};
    }
    HcfX509CertificateArray hcfCerts = {};
    HcfCmsCertType cmsCertType = static_cast<HcfCmsCertType>(type.get_value());
    CfResult res = this->cmsParser_->getCerts(this->cmsParser_, cmsCertType, &hcfCerts);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get certs failed");
        return {};
    }
    array<X509Cert> certs(hcfCerts.count, make_holder<X509CertImpl, X509Cert>());
    for (size_t i = 0; i < hcfCerts.count; i++) {
        certs[i] = make_holder<X509CertImpl, X509Cert>(hcfCerts.data[i]);
    }
    return certs;
}

array<uint8_t> CmsParserImpl::DecryptEnvelopedDataSync(CmsEnvelopedDecryptionConfig const& config)
{
    if (this->cmsParser_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "cmsParser is not initialized");
        return {};
    }
    CfBlob blob = {};
    CfBlob encryptedContentData = {};
    HcfCmsParserDecryptEnvelopedDataOptions options = {};
    HcfPrivateKeyInfo *privateKey = nullptr;
    CfResult res = CF_SUCCESS;
    if (config.keyInfo.has_value()) {
        ThPrivateKeyInfo keyInfo = config.keyInfo.value();
        res = SetPrivateKeyInfo(keyInfo, &privateKey);
        if (res != CF_SUCCESS) {
            ANI_LOGE_THROW(res, "set private key info failed");
            return {};
        }
        options.privateKey = privateKey;
    }
    if (config.cert.has_value()) {
        options.cert = reinterpret_cast<HcfX509Certificate *>(config.cert.value()->GetX509CertObj());
    }
    if (config.encryptedContentData.has_value()) {
        ArrayU8ToDataBlob(config.encryptedContentData.value(), encryptedContentData);
        options.encryptedContentData = &encryptedContentData;
    }
    options.contentDataFormat = config.contentDataFormat.has_value() ?
        static_cast<HcfCmsContentDataFormat>(config.contentDataFormat.value().get_value()) : BINARY;
    res = this->cmsParser_->decryptEnvelopedData(this->cmsParser_, &options, &blob);
    FreePrivateKeyInfo(&privateKey);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "decrypt enveloped data failed");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataClearAndFree(&blob);
    return data;
}

CmsParser CreateCmsParser()
{
    HcfCmsParser *cmsParser = nullptr;
    CfResult res = HcfCreateCmsParser(&cmsParser);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "create cms parser failed!");
        return make_holder<CmsParserImpl, CmsParser>();
    }
    return make_holder<CmsParserImpl, CmsParser>(cmsParser);
}

OptStrUint8Arr GenerateCsr(ThPrivateKeyInfo const& keyInfo, CsrGenerationConfig const& config)
{
    HcfPrivateKeyInfo *privateKey = nullptr;
    CfResult ret = SetPrivateKeyInfo(keyInfo, &privateKey);
    if (ret != CF_SUCCESS) {
        FreePrivateKeyInfo(&privateKey);
        ANI_LOGE_THROW(ret, "set private key info failed");
        return OptStrUint8Arr::make_UINT8ARRAY(array<uint8_t>{});
    }
    HcfGenCsrConf *csrConfig = nullptr;
    if (!SetConfig(&csrConfig, config)) {
        FreePrivateKeyInfo(&privateKey);
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "set csr config failed");
        return OptStrUint8Arr::make_UINT8ARRAY(array<uint8_t>{});
    }
    CfBlob csrBlob = {};
    ret = HcfX509CertificateGenCsr(privateKey, csrConfig, &csrBlob);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "GenerateCsr failed");
        FreePrivateKeyInfo(&privateKey);
        FreeGenCsrConf(csrConfig);
        return OptStrUint8Arr::make_UINT8ARRAY(array<uint8_t>{});
    }
    OptStrUint8Arr result = OptStrUint8Arr::make_UINT8ARRAY(array<uint8_t>{});
    if (csrConfig->isPem) {
        string str = DataBlobToString(csrBlob);
        result = OptStrUint8Arr::make_STRING(str);
    } else {
        array<uint8_t> blob = {};
        DataBlobToArrayU8(csrBlob, blob);
        result = OptStrUint8Arr::make_UINT8ARRAY(blob);
    }
    CfBlobDataClearAndFree(&csrBlob);
    FreePrivateKeyInfo(&privateKey);
    FreeGenCsrConf(csrConfig);
    return result;
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateCmsGenerator(ANI::CertFramework::CreateCmsGenerator);
TH_EXPORT_CPP_API_CreateCmsParser(ANI::CertFramework::CreateCmsParser);
TH_EXPORT_CPP_API_GenerateCsr(ANI::CertFramework::GenerateCsr);
// NOLINTEND
