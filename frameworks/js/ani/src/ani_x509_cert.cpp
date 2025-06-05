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

#include "ani_x509_cert.h"
#include "ani_pub_key.h"
#include "ani_cert_extension.h"
#include "ani_x500_distinguished_name.h"
#include "cf_type.h"

namespace ANI::CertFramework {
X509CertImpl::X509CertImpl() {}

X509CertImpl::X509CertImpl(HcfX509Certificate *cert) : cert_(cert) {}

X509CertImpl::~X509CertImpl()
{
    CfObjDestroy(this->cert_);
    this->cert_ = nullptr;
}

void X509CertImpl::VerifySync(cryptoFramework::weak::PubKey key)
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return;
    }
    HcfPubKey *hcfPubKey = reinterpret_cast<HcfPubKey *>(key->GetPubKeyObj());
    CfResult res = this->cert_->base.verify(&(this->cert_->base), hcfPubKey);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "verify cert failed!");
        return;
    }
}

EncodingBlob X509CertImpl::GetEncodedSync()
{
    EncodingBlob encodingBlob = { {}, EncodingFormat(EncodingFormat::key_t::FORMAT_DER) };
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return encodingBlob;
    }
    CfEncodingBlob outBlob = {};
    CfResult res = this->cert_->base.getEncoded(&(this->cert_->base), &outBlob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get cert encoded failed!");
        return encodingBlob;
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8({ outBlob.len, outBlob.data }, data);
    encodingBlob.data = data;
    encodingBlob.encodingFormat = static_cast<EncodingFormat::key_t>(outBlob.encodingFormat);
    CfEncodingBlobDataFree(&outBlob);
    return encodingBlob;
}

cryptoFramework::PubKey X509CertImpl::GetPublicKey()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return make_holder<PubKeyImpl, cryptoFramework::PubKey>();
    }
    HcfPubKey *pubKey = nullptr;
    CfResult res = this->cert_->base.getPublicKey(&(this->cert_->base), reinterpret_cast<void **>(&pubKey));
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get cert public key failed!");
        return make_holder<PubKeyImpl, cryptoFramework::PubKey>();
    }
    return make_holder<PubKeyImpl, cryptoFramework::PubKey>(pubKey);
}

void X509CertImpl::CheckValidityWithDate(string_view date)
{
    TH_THROW(std::runtime_error, "CheckValidityWithDate not implemented");
}

int32_t X509CertImpl::GetVersion()
{
    TH_THROW(std::runtime_error, "GetVersion not implemented");
}

int64_t X509CertImpl::GetSerialNumber()
{
    TH_THROW(std::runtime_error, "GetSerialNumber not implemented");
}

array<uint8_t> X509CertImpl::GetCertSerialNumber()
{
    TH_THROW(std::runtime_error, "GetCertSerialNumber not implemented");
}

DataBlob X509CertImpl::GetIssuerName()
{
    TH_THROW(std::runtime_error, "GetIssuerName not implemented");
}

string X509CertImpl::GetIssuerNameEx(EncodingType encodingType)
{
    TH_THROW(std::runtime_error, "GetIssuerNameEx not implemented");
}

DataBlob X509CertImpl::GetSubjectName(optional_view<EncodingType> encodingType)
{
    TH_THROW(std::runtime_error, "GetSubjectName not implemented");
}

string X509CertImpl::GetNotBeforeTime()
{
    TH_THROW(std::runtime_error, "GetNotBeforeTime not implemented");
}

string X509CertImpl::GetNotAfterTime()
{
    TH_THROW(std::runtime_error, "GetNotAfterTime not implemented");
}

DataBlob X509CertImpl::GetSignature()
{
    TH_THROW(std::runtime_error, "GetSignature not implemented");
}

string X509CertImpl::GetSignatureAlgName()
{
    TH_THROW(std::runtime_error, "GetSignatureAlgName not implemented");
}

string X509CertImpl::GetSignatureAlgOid()
{
    TH_THROW(std::runtime_error, "GetSignatureAlgOid not implemented");
}

DataBlob X509CertImpl::GetSignatureAlgParams()
{
    TH_THROW(std::runtime_error, "GetSignatureAlgParams not implemented");
}

DataBlob X509CertImpl::GetKeyUsage()
{
    TH_THROW(std::runtime_error, "GetKeyUsage not implemented");
}

DataArray X509CertImpl::GetExtKeyUsage()
{
    TH_THROW(std::runtime_error, "GetExtKeyUsage not implemented");
}

int32_t X509CertImpl::GetBasicConstraints()
{
    TH_THROW(std::runtime_error, "GetBasicConstraints not implemented");
}

DataArray X509CertImpl::GetSubjectAltNames()
{
    TH_THROW(std::runtime_error, "GetSubjectAltNames not implemented");
}

DataArray X509CertImpl::GetIssuerAltNames()
{
    TH_THROW(std::runtime_error, "GetIssuerAltNames not implemented");
}

DataBlob X509CertImpl::GetItem(CertItemType itemType)
{
    TH_THROW(std::runtime_error, "GetItem not implemented");
}

bool X509CertImpl::Match(X509CertMatchParameters const& param)
{
    TH_THROW(std::runtime_error, "Match not implemented");
}

DataArray X509CertImpl::GetCRLDistributionPoint()
{
    TH_THROW(std::runtime_error, "GetCRLDistributionPoint not implemented");
}

X500DistinguishedName X509CertImpl::GetIssuerX500DistinguishedName()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
}

X500DistinguishedName X509CertImpl::GetSubjectX500DistinguishedName()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
}

string X509CertImpl::ToString()
{
    TH_THROW(std::runtime_error, "ToString not implemented");
}

string X509CertImpl::ToStringEx(EncodingType encodingType)
{
    TH_THROW(std::runtime_error, "ToStringEx not implemented");
}

array<uint8_t> X509CertImpl::HashCode()
{
    TH_THROW(std::runtime_error, "HashCode not implemented");
}

CertExtension X509CertImpl::GetExtensionsObject()
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CertExtensionImpl, CertExtension>();
}

X509Cert CreateX509CertSync(EncodingBlob const& inStream)
{
    CfBlob blob = {};
    ArrayU8ToDataBlob(inStream.data, blob);
    CfEncodingBlob encodingBlob = {
        .data = blob.data,
        .len = blob.size,
        .encodingFormat = static_cast<CfEncodingFormat>(inStream.encodingFormat.get_value()),
    };
    HcfX509Certificate *cert = nullptr;
    CfResult res = HcfX509CertificateCreate(&encodingBlob, &cert);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "create x509cert obj failed!");
        return make_holder<X509CertImpl, X509Cert>();
    }
    return make_holder<X509CertImpl, X509Cert>(cert);
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateX509CertSync(ANI::CertFramework::CreateX509CertSync);
// NOLINTEND
