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

#include "ani_x500_distinguished_name.h"

namespace ANI::CertFramework {
X500DistinguishedNameImpl::X500DistinguishedNameImpl() {}

X500DistinguishedNameImpl::~X500DistinguishedNameImpl() {}

string X500DistinguishedNameImpl::GetName()
{
    TH_THROW(std::runtime_error, "GetName not implemented");
}

string X500DistinguishedNameImpl::GetNameByEnum(EncodingType encodingType)
{
    TH_THROW(std::runtime_error, "GetNameByEnum not implemented");
}

array<string> X500DistinguishedNameImpl::GetNameByStr(string_view type)
{
    TH_THROW(std::runtime_error, "GetNameByStr not implemented");
}

EncodingBlob X500DistinguishedNameImpl::GetEncoded()
{
    TH_THROW(std::runtime_error, "GetEncoded not implemented");
}

X500DistinguishedName CreateX500DistinguishedNameByStrSync(string_view nameStr)
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
}

X500DistinguishedName CreateX500DistinguishedNameByDerSync(array_view<uint8_t> nameDer)
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateX500DistinguishedNameByStrSync(ANI::CertFramework::CreateX500DistinguishedNameByStrSync);
TH_EXPORT_CPP_API_CreateX500DistinguishedNameByDerSync(ANI::CertFramework::CreateX500DistinguishedNameByDerSync);
// NOLINTEND
