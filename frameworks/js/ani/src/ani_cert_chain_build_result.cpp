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

#include "ani_cert_chain_build_result.h"
#include "ani_x509_cert_chain.h"
#include "ani_x509_cert_chain_validate_result.h"

namespace ANI::CertFramework {
CertChainBuildResultImpl::CertChainBuildResultImpl() {}

CertChainBuildResultImpl::CertChainBuildResultImpl(HcfX509CertChainBuildResult *buildResult)
    : buildResult_(buildResult) {}

CertChainBuildResultImpl::~CertChainBuildResultImpl()
{
    CfObjDestroy(this->buildResult_);
    this->buildResult_ = nullptr;
}

X509CertChain CertChainBuildResultImpl::GetCertChain()
{
    if (this->buildResult_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "buildResult_ is nullptr!");
        return make_holder<X509CertChainImpl, X509CertChain>();
    }
    HcfCertChain *certChain = this->buildResult_->certChain;
    if (certChain == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "certChain is nullptr!");
        return make_holder<X509CertChainImpl, X509CertChain>();
    }
    return make_holder<X509CertChainImpl, X509CertChain>(certChain);
}

CertChainValidationResult CertChainBuildResultImpl::GetValidationResult()
{
    if (this->buildResult_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "buildResult_ is nullptr!");
        return make_holder<CertChainValidationResultImpl, CertChainValidationResult>();
    }

    HcfX509CertChainValidateResult *result = &(this->buildResult_->validateResult);
    return make_holder<CertChainValidationResultImpl, CertChainValidationResult>(result);
}
} // namespace ANI::CertFramework
