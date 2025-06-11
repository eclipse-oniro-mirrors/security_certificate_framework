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
#include "pub_key.h"

namespace ANI::CertFramework {
X509CRLImpl::X509CRLImpl() {}

X509CRLImpl::X509CRLImpl(HcfX509Crl *x509Crl) : x509Crl_(x509Crl) {}

X509CRLImpl::~X509CRLImpl()
{
    CfObjDestroy(this->x509Crl_);
    this->x509Crl_ = nullptr;
}

bool X509CRLImpl::IsRevoked(weak::X509Cert cert)
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return false;
    }
    HcfX509Certificate *x509cert = reinterpret_cast<HcfX509Certificate *>(cert->GetX509CertObj());
    return this->x509Crl_->base.isRevoked(&(this->x509Crl_->base), &(x509cert->base));
}

string X509CRLImpl::GetType()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return "";
    }
    const char *type = this->x509Crl_->base.getType(&(this->x509Crl_->base));
    return (type == nullptr) ? "" : string(type);
}

EncodingBlob X509CRLImpl::GetEncodedSync()
{
    EncodingBlob encodingBlob = { {}, EncodingFormat(EncodingFormat::key_t::FORMAT_DER) };
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return encodingBlob;
    }

    CfEncodingBlob blob = {};
    CfResult res = this->x509Crl_->getEncoded(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get crl encoded failed!");
        return encodingBlob;
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8({ blob.len, blob.data }, data);
    encodingBlob.data = data;
    encodingBlob.encodingFormat = static_cast<EncodingFormat::key_t>(blob.encodingFormat);
    CfEncodingBlobDataFree(&blob);
    return encodingBlob;
}

void X509CRLImpl::VerifySync(cryptoFramework::weak::PubKey key)
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return;
    }
    HcfPubKey *hcfPubKey = reinterpret_cast<HcfPubKey *>(key->GetPubKeyObj());
    CfResult res = this->x509Crl_->verify(this->x509Crl_, hcfPubKey);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "verify crl failed!");
        return;
    }
}

int32_t X509CRLImpl::GetVersion()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return -1;
    }
    return this->x509Crl_->getVersion(this->x509Crl_);
}

DataBlob X509CRLImpl::GetIssuerName()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->getIssuerName(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get issuer name failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return { data };
}

string X509CRLImpl::GetIssuerNameEx(EncodingType encodingType)
{
    // api 20
    TH_THROW(std::runtime_error, "GetIssuerNameEx not implemented");
}

string X509CRLImpl::GetLastUpdate()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->getLastUpdate(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get last update failed!");
        return "";
    }
    string str = string(reinterpret_cast<char *>(blob.data), blob.size);
    CfBlobDataFree(&blob);
    return str;
}

string X509CRLImpl::GetNextUpdate()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->getNextUpdate(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get next update failed!");
        return "";
    }
    string str = string(reinterpret_cast<char *>(blob.data), blob.size);
    CfBlobDataFree(&blob);
    return str;
}

X509CRLEntry X509CRLImpl::GetRevokedCert(array_view<uint8_t> serialNumber)
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return make_holder<X509CRLEntryImpl, X509CRLEntry>();
    }
    HcfX509CrlEntry *crlEntry = nullptr;
    CfBlob serialNumberBlob = {};
    ArrayU8ToBigInteger(serialNumber, serialNumberBlob);
    CfResult res = this->x509Crl_->getRevokedCert(this->x509Crl_, &serialNumberBlob, &crlEntry);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get revoked cert failed!");
        return make_holder<X509CRLEntryImpl, X509CRLEntry>();
    }
    return make_holder<X509CRLEntryImpl, X509CRLEntry>(crlEntry);
}

X509CRLEntry X509CRLImpl::GetRevokedCertWithCert(weak::X509Cert cert)
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return make_holder<X509CRLEntryImpl, X509CRLEntry>();
    }
    HcfX509CrlEntry *crlEntry = nullptr;
    HcfX509Certificate *x509Cert = reinterpret_cast<HcfX509Certificate *>(cert->GetX509CertObj());
    CfResult res = this->x509Crl_->getRevokedCertWithCert(this->x509Crl_, x509Cert, &crlEntry);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get revoked cert with cert failed!");
        return make_holder<X509CRLEntryImpl, X509CRLEntry>();
    }
    return make_holder<X509CRLEntryImpl, X509CRLEntry>(crlEntry);
}

array<X509CRLEntry> X509CRLImpl::GetRevokedCertsSync()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return {};
    }
    CfArray entrysOut = {};
    CfResult res = this->x509Crl_->getRevokedCerts(this->x509Crl_, &entrysOut);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get revoked certs failed!");
        return {};
    }
    array<X509CRLEntry> entrys(entrysOut.count, make_holder<X509CRLEntryImpl, X509CRLEntry>());
    for (uint32_t i = 0; i < entrysOut.count; i++) {
        HcfX509CrlEntry *crlEntry = reinterpret_cast<HcfX509CrlEntry *>(entrysOut.data[i].data);
        entrys[i] = make_holder<X509CRLEntryImpl, X509CRLEntry>(crlEntry);
    }
    return entrys;
}

DataBlob X509CRLImpl::GetTBSInfo()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->getTbsInfo(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get tbs info failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return { data };
}

DataBlob X509CRLImpl::GetSignature()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->getSignature(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get signature failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return { data };
}

string X509CRLImpl::GetSignatureAlgName()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->getSignature(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get signature failed!");
        return {};
    }
    string str = string(reinterpret_cast<char *>(blob.data), blob.size);
    CfBlobDataFree(&blob);
    return str;
}

string X509CRLImpl::GetSignatureAlgOid()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->getSignatureAlgOid(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get signature alg oid failed!");
        return "";
    }
    string str = string(reinterpret_cast<char *>(blob.data), blob.size);
    CfBlobDataFree(&blob);
    return str;
}

DataBlob X509CRLImpl::GetSignatureAlgParams()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->getSignatureAlgParams(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get signature alg params failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return { data };
}

DataBlob X509CRLImpl::GetExtensions()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->getExtensions(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get extensions failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return { data };
}

bool X509CRLImpl::Match(X509CRLMatchParameters const& param)
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return false;
    }
    CfBlobArray issuer = {};
    CfBlob updateDateTime = {};
    CfBlob maxCRL = {};
    CfBlob minCRL = {};
    HcfX509CrlMatchParams matchParams = {};
    array<CfBlob> blobs(param.issuer.has_value() ? param.issuer.value().size() : 0);
    if (param.issuer.has_value()) {
        uint32_t i = 0;
        for (auto const& blob : param.issuer.value()) {
            ArrayU8ToDataBlob(blob, blobs[i++]);
        }
        issuer.data = blobs.data();
        issuer.count = blobs.size();
        matchParams.issuer = &issuer;
    }
    if (param.x509Cert.has_value()) {
        matchParams.x509Cert = reinterpret_cast<HcfCertificate *>(param.x509Cert.value()->GetX509CertObj());
    }
    if (param.updateDateTime.has_value()) {
        StringToDataBlob(param.updateDateTime.value(), updateDateTime);
        matchParams.updateDateTime = &updateDateTime;
    }
    if (param.maxCRL.has_value()) {
        ArrayU8ToDataBlob(param.maxCRL.value(), maxCRL);
        matchParams.maxCRL = &maxCRL;
    }
    if (param.minCRL.has_value()) {
        ArrayU8ToDataBlob(param.minCRL.value(), minCRL);
        matchParams.minCRL = &minCRL;
    }

    bool flag = false;
    CfResult res = this->x509Crl_->match(this->x509Crl_, &matchParams, &flag);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "match failed!");
        return false;
    }
    return flag;
}

X500DistinguishedName X509CRLImpl::GetIssuerX500DistinguishedName()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->getIssuerName(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get issuer name failed!");
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    HcfX509DistinguishedName *x509Name = nullptr;
    res = HcfX509DistinguishedNameCreate(&blob, true, &x509Name);
    CfBlobDataFree(&blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "create x509Name obj failed");
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>(x509Name);
}

string X509CRLImpl::ToString()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->toString(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "to string failed!");
        return "";
    }
    string str = string(reinterpret_cast<char *>(blob.data), blob.size);
    CfBlobDataFree(&blob);
    return str;
}

string X509CRLImpl::ToStringEx(EncodingType encodingType)
{
    // api 20
    TH_THROW(std::runtime_error, "ToStringEx not implemented");
}

array<uint8_t> X509CRLImpl::HashCode()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->hashCode(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "hash code failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return data;
}

CertExtension X509CRLImpl::GetExtensionsObject()
{
    if (this->x509Crl_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509Crl obj is nullptr!");
        return make_holder<CertExtensionImpl, CertExtension>();
    }
    CfBlob blob = {};
    CfResult res = this->x509Crl_->getExtensionsObject(this->x509Crl_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get extensions object failed!");
        return make_holder<CertExtensionImpl, CertExtension>();
    }
    CfObject *object = nullptr;
    CfEncodingBlob encodingBlob = {};
    DataBlobToEncodingBlob(blob, encodingBlob);
    res = static_cast<CfResult>(CfCreate(CF_OBJ_TYPE_EXTENSION, &encodingBlob, &object));
    CfBlobDataFree(&blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "Cf create failed!");
        return make_holder<CertExtensionImpl, CertExtension>();
    }
    return make_holder<CertExtensionImpl, CertExtension>(object);
}

X509CRL CreateX509CRLSync(EncodingBlob const& inStream)
{
    CfBlob blob = {};
    ArrayU8ToDataBlob(inStream.data, blob);
    CfEncodingFormat encodingFormat = static_cast<CfEncodingFormat>(inStream.encodingFormat.get_value());
    CfEncodingBlob encodingBlob = {};
    DataBlobToEncodingBlob(blob, encodingBlob, encodingFormat);
    HcfX509Crl *x509Crl = nullptr;
    CfResult res = HcfX509CrlCreate(&encodingBlob, &x509Crl);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "create X509Crl obj failed!");
        return make_holder<X509CRLImpl, X509CRL>();
    }
    return make_holder<X509CRLImpl, X509CRL>(x509Crl);
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateX509CRLSync(ANI::CertFramework::CreateX509CRLSync);
// NOLINTEND
