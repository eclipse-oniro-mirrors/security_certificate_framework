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

#include "ani_x509_cert_chain.h"

#include <securec.h>
#include "ani_x509_cert.h"
#include "ani_x509_cert_chain_validate_result.h"
#include "ani_cert_chain_build_result.h"
#include "ani_parameters.h"
#include "x509_cert_chain.h"
#include "x509_trust_anchor.h"
#include "cf_blob.h"

namespace {
using namespace ANI::CertFramework;

void FreePkcs12Data(HcfParsePKCS12Conf *conf, CfBlob *keyStore)
{
    if (conf != nullptr) {
        CfBlobDataClearAndFree(conf->pwd);
        CfFree(conf);
    }
    if (keyStore != nullptr) {
        CfBlobFree(&keyStore);
    }
}

CfResult SetParsePKCS12Conf(Pkcs12ParsingConfig const& config, HcfParsePKCS12Conf **conf)
{
    HcfParsePKCS12Conf *tmpConf = (HcfParsePKCS12Conf *)CfMalloc(sizeof(HcfParsePKCS12Conf), 0);
    if (tmpConf == nullptr) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc failed!");
        return CF_ERR_MALLOC;
    }
    CfBlob *tmpPwd = (CfBlob *)CfMalloc(config.password.size(), 0);
    if (tmpPwd == nullptr) {
        FreePkcs12Data(tmpConf, nullptr);
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc failed!");
        return CF_ERR_MALLOC;
    }
    tmpPwd->data = (uint8_t *)CfMalloc(config.password.size(), 0);
    if (tmpPwd->data == nullptr) {
        FreePkcs12Data(tmpConf, tmpPwd);
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc failed!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(tmpPwd->data, config.password.size(), config.password.data(), config.password.size());
    tmpPwd->size = config.password.size();
    tmpConf->pwd = tmpPwd;
    if (config.privateKeyFormat.has_value()) {
        tmpConf->isPem = config.privateKeyFormat.value() == 0 ? true : false;
    } else {
        tmpConf->isPem = true;
    }
    tmpConf->isGetPriKey = config.needsPrivateKey.has_value() ? config.needsPrivateKey.value() : true;
    tmpConf->isGetCert = config.needsCert.has_value() ? config.needsCert.value() : true;
    tmpConf->isGetOtherCerts = config.needsOtherCerts.has_value() ? config.needsOtherCerts.value() : false;
    *conf = tmpConf;
    return CF_SUCCESS;
}

CfResult SetKeyStore(array_view<uint8_t> data, CfBlob **keyStore)
{
    if (data.size() == 0) {
        *keyStore = nullptr;
        return CF_INVALID_PARAMS;
    }
    
    CfBlob *tmpKeyStore = (CfBlob *)CfMalloc(sizeof(CfBlob), 0);
    if (tmpKeyStore == nullptr) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc failed!");
        return CF_ERR_MALLOC;
    }
    tmpKeyStore->data = (uint8_t *)CfMalloc(data.size(), 0);
    if (tmpKeyStore->data == nullptr) {
        CfBlobFree(&tmpKeyStore);
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc failed!");
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(tmpKeyStore->data, data.size(), data.data(), data.size());
    tmpKeyStore->size = data.size();
    *keyStore = tmpKeyStore;
    return CF_SUCCESS;
}

CfResult SetPkcs12Data(Pkcs12ParsingConfig const& config, array_view<uint8_t> data,
    HcfParsePKCS12Conf **conf, CfBlob **keyStore)
{
    if (SetParsePKCS12Conf(config, conf) != CF_SUCCESS) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "set parse pkcs12 conf failed!");
        return CF_ERR_MALLOC;
    }
    if (SetKeyStore(data, keyStore) != CF_SUCCESS) {
        FreePkcs12Data(*conf, *keyStore);
        ANI_LOGE_THROW(CF_ERR_MALLOC, "set key store failed!");
        return CF_ERR_MALLOC;
    }
    return CF_SUCCESS;
}

uint32_t CountValidTrustAnchors(HcfX509TrustAnchorArray* trustAnchors)
{
    if (trustAnchors == nullptr || trustAnchors->data == nullptr) {
        return 0;
    }

    uint32_t validCount = 0;
    for (uint32_t i = 0; i < trustAnchors->count; i++) {
        if (trustAnchors->data[i] != nullptr) {
            validCount++;
        }
    }
    return validCount;
}

X509TrustAnchor CreateTrustAnchorFromHcf(HcfX509TrustAnchor* hcfAnchor)
{
    X509TrustAnchor anchor = {
        .CACert = optional<X509Cert>(std::nullopt),
        .CAPubKey = optional<array<uint8_t>>(std::nullopt),
        .CASubject = optional<array<uint8_t>>(std::nullopt),
        .nameConstraints = optional<array<uint8_t>>(std::nullopt)
    };

    if (hcfAnchor->CAPubKey != nullptr) {
        array<uint8_t> capubkey = {};
        DataBlobToArrayU8(*(hcfAnchor->CAPubKey), capubkey);
        anchor.CAPubKey = optional<array<uint8_t>>(std::in_place, capubkey);
    }

    if (hcfAnchor->CACert != nullptr) {
        anchor.CACert = optional<X509Cert>(std::in_place, make_holder<X509CertImpl, X509Cert>(hcfAnchor->CACert));
    }

    if (hcfAnchor->CASubject != nullptr) {
        array<uint8_t> casubject = {};
        DataBlobToArrayU8(*(hcfAnchor->CASubject), casubject);
        anchor.CASubject = optional<array<uint8_t>>(std::in_place, casubject);
    }

    if (hcfAnchor->nameConstraints != nullptr) {
        array<uint8_t> nameConstraints = {};
        DataBlobToArrayU8(*(hcfAnchor->nameConstraints), nameConstraints);
        anchor.nameConstraints = optional<array<uint8_t>>(std::in_place, nameConstraints);
    }

    return anchor;
}

void FreeX509CertChainBuildParameters(HcfX509CertChainBuildParameters *buildParam)
{
    if (buildParam == nullptr) {
        return;
    }
    FreeX509CertChainValidateParams(buildParam->validateParameters);
    FreeX509CertMatchParams(buildParam->certMatchParameters);
}

bool CreateParams(CertChainBuildParameters const& param, HcfX509CertChainBuildParameters *buildParam)
{
    int32_t maxlength = param.maxLength.has_value() ? param.maxLength.value() : -1;
    if (!BuildX509CertMatchParams(param.certMatchParameters, buildParam->certMatchParameters)) {
        return false;
    }
    buildParam->maxlength = maxlength;
    if (!BuildX509CertChainValidateParams(param.validationParameters, buildParam->validateParameters)) {
        return false;
    }
    return true;
}
} // namespace

namespace ANI::CertFramework {
X509CertChainImpl::X509CertChainImpl() {}

X509CertChainImpl::X509CertChainImpl(HcfCertChain *x509CertChain) : x509CertChain_(x509CertChain) {}

X509CertChainImpl::~X509CertChainImpl()
{
    CfObjDestroy(this->x509CertChain_);
    this->x509CertChain_ = nullptr;
}

array<X509Cert> X509CertChainImpl::GetCertList()
{
    if (this->x509CertChain_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CertChain_ is nullptr");
        return array<X509Cert>(0, make_holder<X509CertImpl, X509Cert>());
    }
    HcfX509CertificateArray certs = { nullptr, 0 };
    CfResult ret = this->x509CertChain_->getCertList(this->x509CertChain_, &certs);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "GetCertList failed");
        return array<X509Cert>(0, make_holder<X509CertImpl, X509Cert>());
    }
    array<X509Cert> result(certs.count, make_holder<X509CertImpl, X509Cert>());
    for (uint32_t i = 0; i < certs.count; i++) {
        result[i] = make_holder<X509CertImpl, X509Cert>(certs.data[i]);
    }
    return result;
}

CertChainValidationResult X509CertChainImpl::ValidateSync(CertChainValidationParameters const& param)
{
    HcfX509CertChainValidateParams validateParams = {};
    if (!BuildX509CertChainValidateParams(param, validateParams)) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "SetX509CertChainValidateParams failed");
        return make_holder<CertChainValidationResultImpl, CertChainValidationResult>();
    }

    HcfX509CertChainValidateResult *validateResult =
        (HcfX509CertChainValidateResult *)CfMalloc(sizeof(HcfX509CertChainValidateResult), 0);
    if (validateResult == nullptr) {
        FreeX509CertChainValidateParams(validateParams);
        ANI_LOGE_THROW(CF_ERR_MALLOC, "Failed to allocate validateResult");
        return make_holder<CertChainValidationResultImpl, CertChainValidationResult>();
    }
    CfResult ret = this->x509CertChain_->validate(this->x509CertChain_, &validateParams, validateResult);
    if (ret != CF_SUCCESS) {
        FreeX509CertChainValidateParams(validateParams);
        CfFree(validateResult);
        ANI_LOGE_THROW(ret, "ValidateSync failed");
        return make_holder<CertChainValidationResultImpl, CertChainValidationResult>();
    }

    CertChainValidationResult result =
        make_holder<CertChainValidationResultImpl, CertChainValidationResult>(validateResult);
    FreeX509CertChainValidateParams(validateParams);
    return result;
}

string X509CertChainImpl::ToString()
{
    if (this->x509CertChain_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CertChain_ is nullptr");
        return "";
    }
    CfBlob blob = { 0, nullptr };
    CfResult ret = this->x509CertChain_->toString(this->x509CertChain_, &blob);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "ToString failed");
        return "";
    }
    string str = DataBlobToString(blob);
    CfBlobDataClearAndFree(&blob);
    return str;
}

array<uint8_t> X509CertChainImpl::HashCode()
{
    if (this->x509CertChain_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CertChain_ is nullptr");
        return {};
    }
    CfBlob blob = { 0, nullptr };
    CfResult ret = this->x509CertChain_->hashCode(this->x509CertChain_, &blob);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "HashCode failed");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataClearAndFree(&blob);
    return data;
}

X509CertChain CreateX509CertChainSync(EncodingBlob const& inStream)
{
    HcfCertChain *x509CertChain = nullptr;
    CfEncodingBlob encodingBlob = {};
    encodingBlob.data = inStream.data.data();
    encodingBlob.len = inStream.data.size();
    encodingBlob.encodingFormat = static_cast<CfEncodingFormat>(static_cast<int>(inStream.encodingFormat));
    CfResult ret = HcfCertChainCreate(&encodingBlob, nullptr, &x509CertChain);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "CreateX509CertChainSync failed");
        return make_holder<X509CertChainImpl, X509CertChain>();
    }
    return make_holder<X509CertChainImpl, X509CertChain>(x509CertChain);
}

X509CertChain CreateX509CertChain(array_view<X509Cert> certs)
{
    HcfX509CertificateArray certsArray = { nullptr, 0 };
    certsArray.count = certs.size();
    if (certsArray.count == 0) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "certs is empty!");
        return make_holder<X509CertChainImpl, X509CertChain>();
    }
    certsArray.data = (HcfX509Certificate **)CfMalloc(certsArray.count * sizeof(HcfX509Certificate *), 0);
    if (certsArray.data == nullptr) {
        ANI_LOGE_THROW(CF_ERR_MALLOC, "malloc failed!");
        return make_holder<X509CertChainImpl, X509CertChain>();
    }
    for (uint32_t i = 0; i < certsArray.count; i++) {
        certsArray.data[i] = reinterpret_cast<HcfX509Certificate *>(certs[i]->GetX509CertObj());
    }
    HcfCertChain *x509CertChain = nullptr;
    CfResult ret = HcfCertChainCreate(nullptr, &certsArray, &x509CertChain);
    if (ret != CF_SUCCESS) {
        CfFree(certsArray.data);
        certsArray.data = nullptr;
        ANI_LOGE_THROW(ret, "CreateX509CertChain failed");
        return make_holder<X509CertChainImpl, X509CertChain>();
    }
    CfFree(certsArray.data);
    certsArray.data = nullptr;
    return make_holder<X509CertChainImpl, X509CertChain>(x509CertChain);
}

CertChainBuildResult BuildX509CertChainSync(CertChainBuildParameters const& param)
{
    HcfX509CertChainBuildResult *buildResult = nullptr;
    HcfX509CertChainBuildParameters buildParam = {};
    if (!CreateParams(param, &buildParam)) {
        FreeX509CertChainBuildParameters(&buildParam);
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "CreateParams failed");
        return make_holder<CertChainBuildResultImpl, CertChainBuildResult>();
    }
    CfResult ret = HcfCertChainBuildResultCreate(&buildParam, &buildResult);
    if (ret != CF_SUCCESS) {
        FreeX509CertChainBuildParameters(&buildParam);
        ANI_LOGE_THROW(ret, "BuildX509CertChainSync failed");
        return make_holder<CertChainBuildResultImpl, CertChainBuildResult>();
    }
    ret = buildResult->certChain->validate(buildResult->certChain,
        &(buildParam.validateParameters), &(buildResult->validateResult));
    if (ret != CF_SUCCESS) {
        FreeX509CertChainBuildParameters(&buildParam);
        ANI_LOGE_THROW(ret, "Validate failed");
        return make_holder<CertChainBuildResultImpl, CertChainBuildResult>();
    }
    CertChainBuildResult result = make_holder<CertChainBuildResultImpl, CertChainBuildResult>(buildResult);
    FreeX509CertChainBuildParameters(&buildParam);
    return result;
}

Pkcs12Data ParsePkcs12(array_view<uint8_t> data, Pkcs12ParsingConfig const& config)
{
    HcfX509P12Collection *p12Collection = nullptr;
    HcfParsePKCS12Conf *conf = nullptr;
    CfBlob *keyStore = nullptr;
    CfResult res = SetPkcs12Data(config, data, &conf, &keyStore);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "set pkcs12 data failed!");
        return {};
    }
    res = HcfParsePKCS12(keyStore, conf, &p12Collection);
    if (res != CF_SUCCESS) {
        FreePkcs12Data(conf, keyStore);
        ANI_LOGE_THROW(res, "parse pkcs12 failed!");
        return {};
    }
    Pkcs12Data pkcs12Data = {};
    if (p12Collection->prikey == nullptr) {
        pkcs12Data.privateKey = optional<OptStrUint8Arr>(std::nullopt);
    } else {
        if (p12Collection->isPem) {
            string str = DataBlobToString(*(p12Collection->prikey));
            pkcs12Data.privateKey = optional<OptStrUint8Arr>(std::in_place, OptStrUint8Arr::make_STRING(str));
        } else {
            array<uint8_t> blob = {};
            DataBlobToArrayU8(*(p12Collection->prikey), blob);
            pkcs12Data.privateKey = optional<OptStrUint8Arr>(std::in_place, OptStrUint8Arr::make_UINT8ARRAY(blob));
        }
        CfBlobDataClearAndFree(p12Collection->prikey);
        CfFree(p12Collection->prikey);
    }
    if (p12Collection->cert == nullptr) {
        pkcs12Data.cert = optional<X509Cert>(std::nullopt);
    } else {
        pkcs12Data.cert = optional<X509Cert>(std::in_place, make_holder<X509CertImpl, X509Cert>(p12Collection->cert));
    }
    if (p12Collection->otherCertsCount == 0) {
        pkcs12Data.otherCerts = optional<array<X509Cert>>(std::nullopt);
    } else {
        pkcs12Data.otherCerts = optional<array<X509Cert>>(std::in_place,
            array<X509Cert>(p12Collection->otherCertsCount, make_holder<X509CertImpl, X509Cert>()));
        for (uint32_t i = 0; i < p12Collection->otherCertsCount; i++) {
            (*pkcs12Data.otherCerts)[i] = make_holder<X509CertImpl, X509Cert>(p12Collection->otherCerts[i]);
        }
    }
    CfFree(p12Collection);
    FreePkcs12Data(conf, keyStore);
    return pkcs12Data;
}

array<X509TrustAnchor> CreateTrustAnchorsWithKeyStoreSync(array_view<uint8_t> keystore, string_view pwd)
{
    HcfX509TrustAnchorArray* trustAnchors = nullptr;
    CfBlob *keyStore = nullptr;
    CfResult ret = SetKeyStore(keystore, &keyStore);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "set key store failed!");
        return {};
    }
    uint32_t length = pwd.size();
    if (length == 0) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "pwd is empty!");
        return {};
    }
    CfBlob *pwdBlob = nullptr;
    if (!StringCopyToBlob(pwd, &pwdBlob)) {
        CfBlobFree(&keyStore);
        ANI_LOGE_THROW(CF_ERR_MALLOC, "set pwd blob failed!");
        return {};
    }
    ret = HcfCreateTrustAnchorWithKeyStore(keyStore, pwdBlob, &trustAnchors);
    if (ret != CF_SUCCESS) {
        CfBlobFree(&keyStore);
        CfBlobFree(&pwdBlob);
        ANI_LOGE_THROW(ret, "create trust anchors with keystore failed!");
        return {};
    }

    uint32_t validCount = CountValidTrustAnchors(trustAnchors);
    array<X509TrustAnchor> result(validCount);
    
    uint32_t index = 0;
    for (uint32_t i = 0; i < trustAnchors->count; i++) {
        if (trustAnchors->data[i] == nullptr) {
            continue;
        }
        result[index++] = CreateTrustAnchorFromHcf(trustAnchors->data[i]);
    }

    FreeTrustAnchorArray(trustAnchors);
    CfBlobFree(&keyStore);
    CfBlobFree(&pwdBlob);
    return result;
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateX509CertChainSync(ANI::CertFramework::CreateX509CertChainSync);
TH_EXPORT_CPP_API_CreateX509CertChain(ANI::CertFramework::CreateX509CertChain);
TH_EXPORT_CPP_API_BuildX509CertChainSync(ANI::CertFramework::BuildX509CertChainSync);
TH_EXPORT_CPP_API_ParsePkcs12(ANI::CertFramework::ParsePkcs12);
TH_EXPORT_CPP_API_CreateTrustAnchorsWithKeyStoreSync(ANI::CertFramework::CreateTrustAnchorsWithKeyStoreSync);
// NOLINTEND
