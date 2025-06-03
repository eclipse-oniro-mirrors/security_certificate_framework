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
#include "ani_x509_cert_chain_validate_result.h"
#include "ani_cert_chain_build_result.h"

namespace ANI::CertFramework {
X509CertChainImpl::X509CertChainImpl() {}

X509CertChainImpl::~X509CertChainImpl() {}

array<X509Cert> X509CertChainImpl::GetCertList()
{
    TH_THROW(std::runtime_error, "GetCertList not implemented");
}

CertChainValidationResult X509CertChainImpl::ValidateSync(CertChainValidationParameters const& param)
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

X509CertChain CreateX509CertChainSync(EncodingBlob const& inStream)
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CertChainImpl, X509CertChain>();
}

X509CertChain CreateX509CertChain(array_view<X509Cert> certs)
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CertChainImpl, X509CertChain>();
}

CertChainBuildResult BuildX509CertChainSync(CertChainBuildParameters const& param)
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CertChainBuildResultImpl, CertChainBuildResult>();
}

Pkcs12Data ParsePkcs12(array_view<uint8_t> data, Pkcs12ParsingConfig const& config)
{
    TH_THROW(std::runtime_error, "ParsePkcs12 not implemented");
}

array<X509TrustAnchor> CreateTrustAnchorsWithKeyStoreSync(array_view<uint8_t> keystore, string_view pwd)
{
    TH_THROW(std::runtime_error, "CreateTrustAnchorsWithKeyStoreSync not implemented");
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
