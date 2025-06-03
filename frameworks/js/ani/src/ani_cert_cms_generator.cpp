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

namespace ANI::CertFramework {
CmsGeneratorImpl::CmsGeneratorImpl() {}

CmsGeneratorImpl::~CmsGeneratorImpl() {}

void CmsGeneratorImpl::AddSigner(weak::X509Cert cert, PrivateKeyInfo const& keyInfo, CmsSignerConfig const& config)
{
    TH_THROW(std::runtime_error, "AddSigner not implemented");
}

void CmsGeneratorImpl::AddCert(weak::X509Cert cert)
{
    TH_THROW(std::runtime_error, "AddCert not implemented");
}

OptStrUint8Arr CmsGeneratorImpl::DoFinalSync(array_view<uint8_t> data, optional_view<CmsGeneratorOptions> options)
{
    TH_THROW(std::runtime_error, "DoFinalSync not implemented");
}

CmsGenerator CreateCmsGenerator(CmsContentType contentType)
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CmsGeneratorImpl, CmsGenerator>();
}

OptStrUint8Arr GenerateCsr(PrivateKeyInfo const& keyInfo, CsrGenerationConfig const& config)
{
    TH_THROW(std::runtime_error, "GenerateCsr not implemented");
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateCmsGenerator(ANI::CertFramework::CreateCmsGenerator);
TH_EXPORT_CPP_API_GenerateCsr(ANI::CertFramework::GenerateCsr);
// NOLINTEND
