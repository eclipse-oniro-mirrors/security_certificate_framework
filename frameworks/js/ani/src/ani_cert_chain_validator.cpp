/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "cert_chain_validator.h"
#include "ani_cert_chain_validator.h"
#include "ani_parameters.h"
#include "ani_x509_cert.h"

namespace ANI::CertFramework {
VerifyCertResultImpl::VerifyCertResultImpl() {}

VerifyCertResultImpl::VerifyCertResultImpl(HcfX509CertificateArray result) : result_(result) {}

VerifyCertResultImpl::~VerifyCertResultImpl()
{
    for (uint32_t i = 0; i < result_.count; ++i) {
        CfObjDestroy(result_.data[i]);
        result_.data[i] = nullptr;
    }
    CF_FREE_PTR(result_.data);
}

array<X509Cert> VerifyCertResultImpl::GetCertChain()
{
    array<X509Cert> certChain(result_.count, make_holder<X509CertImpl, X509Cert>());
    for (uint32_t i = 0; i < result_.count; ++i) {
        certChain[i] = make_holder<X509CertImpl, X509Cert>(result_.data[i], false);
    }
    return certChain;
}

CertChainValidatorImpl::CertChainValidatorImpl() {}

CertChainValidatorImpl::CertChainValidatorImpl(HcfCertChainValidator *certChainValidator)
    : certChainValidator_(certChainValidator) {}

CertChainValidatorImpl::~CertChainValidatorImpl()
{
    CfObjDestroy(this->certChainValidator_);
    this->certChainValidator_ = nullptr;
}

void CertChainValidatorImpl::ValidateSync(CertChainData const& certChain)
{
    if (this->certChainValidator_ == nullptr) {
        ANI_LOGE_THROW(CF_ERR_ANI, "certChainValidator obj is nullptr!");
        return;
    }
    CfBlob blob = {};
    ArrayU8ToDataBlob(certChain.data, blob);
    HcfCertChainData certChainData = {
        .data = blob.data,
        .dataLen = blob.size,
        .count = certChain.count,
        .format = static_cast<CfEncodingFormat>(certChain.encodingFormat.get_value()),
    };
    CfResult res = this->certChainValidator_->validate(this->certChainValidator_, &certChainData);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "validate cert chain failed");
        return;
    }
}

CertValidationResult CertChainValidatorImpl::ValidateCertSync(weak::X509Cert cert, CertValidationParams const& params)
{
    if (this->certChainValidator_ == nullptr) {
        ANI_LOGE_THROW(CF_ERR_ANI, "certChainValidator obj is nullptr!");
        return make_holder<VerifyCertResultImpl, CertValidationResult>();
    }
    HcfX509Certificate *x509Cert = reinterpret_cast<HcfX509Certificate *>(cert->GetX509CertObj());
    if (x509Cert == nullptr) {
        ANI_LOGE_THROW(CF_ERR_PARAMETER_CHECK, "cert is nullptr!");
        return make_holder<VerifyCertResultImpl, CertValidationResult>();
    }
    HcfX509CertValidatorParams hcfParams = {};
    char *errMsg = nullptr;
    CfResult res = BuildX509CertValidatorParams(params, hcfParams, errMsg);
    if (res != CF_SUCCESS) {
        FreeX509CertValidatorParams(hcfParams);
        ANI_LOGE_THROW(res, errMsg != nullptr ? errMsg : "build validator params failed");
        CF_FREE_PTR(errMsg);
        return make_holder<VerifyCertResultImpl, CertValidationResult>();
    }
    HcfVerifyCertResult result = {};
    res = this->certChainValidator_->validateX509Cert(
        this->certChainValidator_, x509Cert, &hcfParams, &result);
    FreeX509CertValidatorParams(hcfParams);
    if (res != CF_SUCCESS) {
        FreeVerifyCertResult(result);
        ANI_LOGE_THROW(res, result.errorMsg != nullptr ? result.errorMsg : "validate cert failed");
        return make_holder<VerifyCertResultImpl, CertValidationResult>();
    }
    return make_holder<VerifyCertResultImpl, CertValidationResult>(result.certs);
}

string CertChainValidatorImpl::GetAlgorithm()
{
    if (this->certChainValidator_ == nullptr) {
        ANI_LOGE_THROW(CF_ERR_ANI, "certChainValidator obj is nullptr!");
        return "";
    }
    const char *algName = this->certChainValidator_->getAlgorithm(this->certChainValidator_);
    return (algName == nullptr) ? "" : string(algName);
}

CertChainValidator CreateCertChainValidator(string_view algorithm)
{
    HcfCertChainValidator *certChainValidator = nullptr;
    CfResult res = HcfCertChainValidatorCreate(algorithm.c_str(), &certChainValidator);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "create cert chain validator failed");
        return make_holder<CertChainValidatorImpl, CertChainValidator>();
    }
    return make_holder<CertChainValidatorImpl, CertChainValidator>(certChainValidator);
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateCertChainValidator(ANI::CertFramework::CreateCertChainValidator);
// NOLINTEND
