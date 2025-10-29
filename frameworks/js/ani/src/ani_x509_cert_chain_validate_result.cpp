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

#include "ani_x509_cert_chain_validate_result.h"
#include "ani_x509_cert.h"
#include "ani_parameters.h"

namespace ANI::CertFramework {
CertChainValidationResultImpl::CertChainValidationResultImpl() {}
CertChainValidationResultImpl::CertChainValidationResultImpl(HcfX509CertChainValidateResult *validateResult,
    bool owner /* = true */) : validateResult_(validateResult), owner_(owner) {}

CertChainValidationResultImpl::~CertChainValidationResultImpl()
{
    if (this->owner_) {
        FreeCertChainValidateResult(this->validateResult_);
        CF_FREE_PTR(this->validateResult_);
    }
}

int64_t CertChainValidationResultImpl::GetCertChainValidationResultObj()
{
    return reinterpret_cast<int64_t>(this->validateResult_);
}

X509TrustAnchor CertChainValidationResultImpl::GetTrustAnchor()
{
    if (this->validateResult_ == nullptr || this->validateResult_->trustAnchor == nullptr) {
        ANI_LOGE_THROW(CF_ERR_ANI, "trustAnchor is nullptr!");
        return {};
    }
    X509TrustAnchor anchor = {
        .CACert = optional<X509Cert>(std::nullopt),
        .CAPubKey = optional<array<uint8_t>>(std::nullopt),
        .CASubject = optional<array<uint8_t>>(std::nullopt),
        .nameConstraints = optional<array<uint8_t>>(std::nullopt)
    };

    if (this->validateResult_->trustAnchor->CAPubKey != nullptr) {
        array<uint8_t> caPubkey = {};
        DataBlobToArrayU8(*(this->validateResult_->trustAnchor->CAPubKey), caPubkey);
        anchor.CAPubKey = optional<array<uint8_t>>(std::in_place, caPubkey);
    }

    if (this->validateResult_->trustAnchor->CACert != nullptr) {
        anchor.CACert = optional<X509Cert>(std::in_place,
            make_holder<X509CertImpl, X509Cert>(this->validateResult_->trustAnchor->CACert, false));
    }

    if (this->validateResult_->trustAnchor->CASubject != nullptr) {
        array<uint8_t> caSubject = {};
        DataBlobToArrayU8(*(this->validateResult_->trustAnchor->CASubject), caSubject);
        anchor.CASubject = optional<array<uint8_t>>(std::in_place, caSubject);
    }

    if (this->validateResult_->trustAnchor->nameConstraints != nullptr) {
        array<uint8_t> nameConstraints = {};
        DataBlobToArrayU8(*(this->validateResult_->trustAnchor->nameConstraints), nameConstraints);
        anchor.nameConstraints = optional<array<uint8_t>>(std::in_place, nameConstraints);
    }

    return anchor;
}

X509Cert CertChainValidationResultImpl::GetEntityCert()
{
    if (this->validateResult_ == nullptr) {
        ANI_LOGE_THROW(CF_ERR_ANI, "validateResult_ is nullptr!");
        return make_holder<X509CertImpl, X509Cert>();
    }
    HcfX509Certificate *cert = this->validateResult_->entityCert;
    if (cert == nullptr) {
        ANI_LOGE_THROW(CF_ERR_ANI, "entityCert is nullptr!");
        return make_holder<X509CertImpl, X509Cert>();
    }
    return make_holder<X509CertImpl, X509Cert>(cert, false);
}
} // namespace ANI::CertFramework
