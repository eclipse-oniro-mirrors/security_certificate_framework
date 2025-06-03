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

#include "ani_x509_crl_entry.h"
#include "ani_cert_extension.h"
#include "ani_x500_distinguished_name.h"

namespace ANI::CertFramework {
X509CRLEntryImpl::X509CRLEntryImpl() {}

X509CRLEntryImpl::~X509CRLEntryImpl() {}

EncodingBlob X509CRLEntryImpl::GetEncodedSync()
{
    TH_THROW(std::runtime_error, "GetEncodedSync not implemented");
}

array<uint8_t> X509CRLEntryImpl::GetSerialNumber()
{
    TH_THROW(std::runtime_error, "GetSerialNumber not implemented");
}

DataBlob X509CRLEntryImpl::GetCertIssuer()
{
    TH_THROW(std::runtime_error, "GetCertIssuer not implemented");
}

string X509CRLEntryImpl::GetRevocationDate()
{
    TH_THROW(std::runtime_error, "GetRevocationDate not implemented");
}

DataBlob X509CRLEntryImpl::GetExtensions()
{
    TH_THROW(std::runtime_error, "GetExtensions not implemented");
}

bool X509CRLEntryImpl::HasExtensions()
{
    TH_THROW(std::runtime_error, "HasExtensions not implemented");
}

X500DistinguishedName X509CRLEntryImpl::GetCertIssuerX500DistinguishedName()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
}

string X509CRLEntryImpl::ToString()
{
    TH_THROW(std::runtime_error, "ToString not implemented");
}

array<uint8_t> X509CRLEntryImpl::HashCode()
{
    TH_THROW(std::runtime_error, "HashCode not implemented");
}

CertExtension X509CRLEntryImpl::GetExtensionsObject()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CertExtensionImpl, CertExtension>();
}
} // namespace ANI::CertFramework
