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

#include "cert_chain_validator.h"
#include "ani_cert_chain_validator.h"

using namespace taihe;
using namespace ohos::security::cert::cert;
using namespace ANI::CertFramework;

namespace ANI::CertFramework {
CertChainValidatorImpl::CertChainValidatorImpl() {}

CertChainValidatorImpl::CertChainValidatorImpl(HcfCertChainValidator *certChainValidator)
    : certChainValidator_(certChainValidator) {}

CertChainValidatorImpl::~CertChainValidatorImpl()
{
    CfObjDestroy(certChainValidator_);
    certChainValidator_ = nullptr;
}

void CertChainValidatorImpl::ValidateSync(CertChainData const& certChain)
{
    if (this->certChainValidator_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "certChainValidator obj is nullptr!");
        return;
    }
    HcfCertChainData certChainData = {
        .data = certChain.data.data(),
        .dataLen = certChain.data.size(),
        .count = certChain.count,
        .format = static_cast<CfEncodingFormat>(certChain.encodingFormat.get_value()),
    };
    CfResult res = this->certChainValidator_->validate(this->certChainValidator_, &certChainData);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "validate cert chain failed");
        return;
    }
}

string CertChainValidatorImpl::GetAlgorithm()
{
    if (this->certChainValidator_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "certChainValidator obj is nullptr!");
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
TH_EXPORT_CPP_API_CreateCertChainValidator(CreateCertChainValidator);
// NOLINTEND
