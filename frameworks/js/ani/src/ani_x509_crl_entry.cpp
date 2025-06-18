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
#include "cf_type.h"

namespace ANI::CertFramework {
X509CRLEntryImpl::X509CRLEntryImpl() {}

X509CRLEntryImpl::X509CRLEntryImpl(HcfX509CrlEntry *x509CrlEntry) : x509CrlEntry_(x509CrlEntry) {}

X509CRLEntryImpl::~X509CRLEntryImpl()
{
    CfObjDestroy(this->x509CrlEntry_);
    this->x509CrlEntry_ = nullptr;
}

EncodingBlob X509CRLEntryImpl::GetEncodedSync()
{
    EncodingBlob encodingBlob = { {}, EncodingFormat(EncodingFormat::key_t::FORMAT_DER) };
    if (this->x509CrlEntry_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CrlEntry obj is nullptr!");
        return encodingBlob;
    }
    CfEncodingBlob blob = {};
    CfResult res = this->x509CrlEntry_->getEncoded(this->x509CrlEntry_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get cert encoded failed!");
        return encodingBlob;
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8({ blob.len, blob.data }, data);
    encodingBlob.data = data;
    encodingBlob.encodingFormat = static_cast<EncodingFormat::key_t>(blob.encodingFormat);
    CfEncodingBlobDataFree(&blob);
    return encodingBlob;
}

array<uint8_t> X509CRLEntryImpl::GetSerialNumber()
{
    if (this->x509CrlEntry_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CrlEntry obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->x509CrlEntry_->getSerialNumber(this->x509CrlEntry_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get serial number failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return data;
}

DataBlob X509CRLEntryImpl::GetCertIssuer()
{
    if (this->x509CrlEntry_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CrlEntry obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->x509CrlEntry_->getCertIssuer(this->x509CrlEntry_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get cert issuer failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return { data };
}

string X509CRLEntryImpl::GetCertIssuerEx(EncodingType encodingType)
{
    // api 20
    TH_THROW(std::runtime_error, "GetCertIssuerEx not implemented");
}

string X509CRLEntryImpl::GetRevocationDate()
{
    if (this->x509CrlEntry_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CrlEntry obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult res = this->x509CrlEntry_->getRevocationDate(this->x509CrlEntry_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get revocation date failed!");
        return "";
    }
    string str = string(reinterpret_cast<char *>(blob.data), blob.size);
    CfBlobDataFree(&blob);
    return str;
}

DataBlob X509CRLEntryImpl::GetExtensions()
{
    if (this->x509CrlEntry_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CrlEntry obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->x509CrlEntry_->getExtensions(this->x509CrlEntry_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get extensions failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return { data };
}

bool X509CRLEntryImpl::HasExtensions()
{
    if (this->x509CrlEntry_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CrlEntry obj is nullptr!");
        return false;
    }
    bool result = false;
    CfResult res = this->x509CrlEntry_->hasExtensions(this->x509CrlEntry_, &result);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "has extensions failed!");
        return false;
    }
    return result;
}

X500DistinguishedName X509CRLEntryImpl::GetCertIssuerX500DistinguishedName()
{
    if (this->x509CrlEntry_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CrlEntry obj is nullptr!");
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    CfBlob blob = {};
    CfResult res = this->x509CrlEntry_->getCertIssuer(this->x509CrlEntry_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get cert issuer failed!");
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

string X509CRLEntryImpl::ToString()
{
    if (this->x509CrlEntry_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CrlEntry obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult res = this->x509CrlEntry_->toString(this->x509CrlEntry_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "to string failed!");
        return "";
    }
    string str = string(reinterpret_cast<char *>(blob.data), blob.size);
    CfBlobDataFree(&blob);
    return str;
}

array<uint8_t> X509CRLEntryImpl::HashCode()
{
    if (this->x509CrlEntry_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CrlEntry obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->x509CrlEntry_->hashCode(this->x509CrlEntry_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "hash code failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return data;
}

CertExtension X509CRLEntryImpl::GetExtensionsObject()
{
    if (this->x509CrlEntry_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509CrlEntry obj is nullptr!");
        return make_holder<CertExtensionImpl, CertExtension>();
    }
    CfBlob blob = {};
    CfResult res = this->x509CrlEntry_->getExtensionsObject(this->x509CrlEntry_, &blob);
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
        ANI_LOGE_THROW(res, "create extension obj failed!");
        return make_holder<CertExtensionImpl, CertExtension>();
    }
    return make_holder<CertExtensionImpl, CertExtension>(object);
}
} // namespace ANI::CertFramework
