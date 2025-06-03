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

#include "ani_cert_extension.h"

namespace ANI::CertFramework {
CertExtensionImpl::CertExtensionImpl() {}

CertExtensionImpl::~CertExtensionImpl() {}

EncodingBlob CertExtensionImpl::GetEncoded()
{
    TH_THROW(std::runtime_error, "GetEncoded not implemented");
}

DataArray CertExtensionImpl::GetOidList(ExtensionOidType valueType)
{
    TH_THROW(std::runtime_error, "GetOidList not implemented");
}

DataBlob CertExtensionImpl::GetEntry(ExtensionEntryType valueType, DataBlob const& oid)
{
    TH_THROW(std::runtime_error, "GetEntry not implemented");
}

int32_t CertExtensionImpl::CheckCA()
{
    TH_THROW(std::runtime_error, "CheckCA not implemented");
}

bool CertExtensionImpl::HasUnsupportedCriticalExtension()
{
    TH_THROW(std::runtime_error, "HasUnsupportedCriticalExtension not implemented");
}

CertExtension CreateCertExtensionSync(EncodingBlob const& inStream)
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CertExtensionImpl, CertExtension>();
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateCertExtensionSync(ANI::CertFramework::CreateCertExtensionSync);
// NOLINTEND
