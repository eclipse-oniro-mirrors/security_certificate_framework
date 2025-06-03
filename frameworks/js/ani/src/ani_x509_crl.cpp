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

#include "ani_x509_crl.h"
#include "ani_x509_crl_entry.h"
#include "ani_cert_extension.h"
#include "ani_x500_distinguished_name.h"

namespace ANI::CertFramework {
X509CRLImpl::X509CRLImpl() {}

X509CRLImpl::~X509CRLImpl() {}

bool X509CRLImpl::IsRevoked(weak::X509Cert cert)
{
    TH_THROW(std::runtime_error, "IsRevoked not implemented");
}

string X509CRLImpl::GetType()
{
    TH_THROW(std::runtime_error, "GetType not implemented");
}

EncodingBlob X509CRLImpl::GetEncodedSync()
{
    TH_THROW(std::runtime_error, "GetEncodedSync not implemented");
}

void X509CRLImpl::VerifySync(cryptoFramework::weak::PubKey key)
{
    TH_THROW(std::runtime_error, "VerifySync not implemented");
}

int32_t X509CRLImpl::GetVersion()
{
    TH_THROW(std::runtime_error, "GetVersion not implemented");
}

DataBlob X509CRLImpl::GetIssuerName()
{
    TH_THROW(std::runtime_error, "GetIssuerName not implemented");
}

string X509CRLImpl::GetLastUpdate()
{
    TH_THROW(std::runtime_error, "GetLastUpdate not implemented");
}

string X509CRLImpl::GetNextUpdate()
{
    TH_THROW(std::runtime_error, "GetNextUpdate not implemented");
}

X509CRLEntry X509CRLImpl::GetRevokedCert(array_view<uint8_t> serialNumber)
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CRLEntryImpl, X509CRLEntry>();
}

X509CRLEntry X509CRLImpl::GetRevokedCertWithCert(weak::X509Cert cert)
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CRLEntryImpl, X509CRLEntry>();
}

array<X509CRLEntry> X509CRLImpl::GetRevokedCertsSync()
{
    TH_THROW(std::runtime_error, "GetRevokedCertsSync not implemented");
}

DataBlob X509CRLImpl::GetTBSInfo()
{
    TH_THROW(std::runtime_error, "GetTBSInfo not implemented");
}

DataBlob X509CRLImpl::GetSignature()
{
    TH_THROW(std::runtime_error, "GetSignature not implemented");
}

string X509CRLImpl::GetSignatureAlgName()
{
    TH_THROW(std::runtime_error, "GetSignatureAlgName not implemented");
}

string X509CRLImpl::GetSignatureAlgOid()
{
    TH_THROW(std::runtime_error, "GetSignatureAlgOid not implemented");
}

DataBlob X509CRLImpl::GetSignatureAlgParams()
{
    TH_THROW(std::runtime_error, "GetSignatureAlgParams not implemented");
}

DataBlob X509CRLImpl::GetExtensions()
{
    TH_THROW(std::runtime_error, "GetExtensions not implemented");
}

bool X509CRLImpl::Match(X509CRLMatchParameters const& param)
{
    TH_THROW(std::runtime_error, "Match not implemented");
}

X500DistinguishedName X509CRLImpl::GetIssuerX500DistinguishedName()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
}

string X509CRLImpl::ToString()
{
    TH_THROW(std::runtime_error, "ToString not implemented");
}

array<uint8_t> X509CRLImpl::HashCode()
{
    TH_THROW(std::runtime_error, "HashCode not implemented");
}

CertExtension X509CRLImpl::GetExtensionsObject()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CertExtensionImpl, CertExtension>();
}

X509CRL CreateX509CRLSync(EncodingBlob const& inStream)
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X509CRLImpl, X509CRL>();
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateX509CRLSync(ANI::CertFramework::CreateX509CRLSync);
// NOLINTEND
