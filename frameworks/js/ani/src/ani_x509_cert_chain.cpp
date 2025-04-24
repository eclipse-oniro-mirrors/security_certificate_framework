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
#include "ani_x509_cert.h"

using namespace taihe;
using namespace ohos::security::cert::cert;
using namespace ANI::CertFramework;

namespace ANI::CertFramework {
CertChainValidationResultImpl::CertChainValidationResultImpl() {}

CertChainValidationResultImpl::~CertChainValidationResultImpl() {}

X509TrustAnchor CertChainValidationResultImpl::GetTrustAnchor()
{
    TH_THROW(std::runtime_error, "GetTrustAnchor not implemented");
}

X509Cert CertChainValidationResultImpl::GetEntityCert()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CertImpl, X509Cert>();
}

X509CertChainImpl::X509CertChainImpl() {}

X509CertChainImpl::~X509CertChainImpl() {}

array<X509Cert> X509CertChainImpl::GetCertList()
{
    TH_THROW(std::runtime_error, "GetCertList not implemented");
}

CertChainValidationResult X509CertChainImpl::ValidateSync()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CertChainValidationResultImpl, CertChainValidationResult>();
}

string X509CertChainImpl::ToString()
{
    TH_THROW(std::runtime_error, "ToString not implemented");
}

array<uint8_t> X509CertChainImpl::HashCode()
{
    TH_THROW(std::runtime_error, "HashCode not implemented");
}
} // namespace ANI::CertFramework

X509CertChain CreateX509CertChainSync(array_view<X509Cert> certs)
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CertChainImpl, X509CertChain>();
}

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateX509CertChainSync(CreateX509CertChainSync);
// NOLINTEND
