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
#include "ani_object.h"
#include "ani_parameters.h"
#include "ani_cert_extension.h"
#include "ani_x500_distinguished_name.h"
#include "cf_type.h"

namespace ANI::CertFramework {
X509CertImpl::X509CertImpl() {}

X509CertImpl::X509CertImpl(HcfX509Certificate *cert, bool owner /* = true */) : cert_(cert), owner_(owner)
{
    CfEncodingBlob encodingBlob = {};
    CfResult res = this->cert_->base.getEncoded(&(this->cert_->base), &encodingBlob);
    if (res != CF_SUCCESS) {
        return;
    }
    CfObject *object = nullptr;
    res = static_cast<CfResult>(CfCreate(CF_OBJ_TYPE_CERT, &encodingBlob, &object));
    CfEncodingBlobDataFree(&encodingBlob);
    if (res != CF_SUCCESS) {
        return;
    }
    this->object_ = object;
}

X509CertImpl::~X509CertImpl()
{
    if (this->owner_) {
        CfObjDestroy(this->cert_);
        this->cert_ = nullptr;
    }
    CfObjDestroy(this->object_);
    this->object_ = nullptr;
}

int64_t X509CertImpl::GetX509CertObj()
{
    return reinterpret_cast<int64_t>(this->cert_);
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
    CfEncodingBlob blob = {};
    CfResult res = this->cert_->base.getEncoded(&(this->cert_->base), &blob);
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
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return;
    }
    CfResult res = this->cert_->checkValidityWithDate(this->cert_, date.c_str());
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "check cert validity failed!");
        return;
    }
}

int32_t X509CertImpl::GetVersion()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return -1;
    }
    return this->cert_->getVersion(this->cert_);
}

array<uint8_t> X509CertImpl::GetCertSerialNumber()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->cert_->getSerialNumber(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "cert get serial num failed!");
        return {};
    }
    array<uint8_t> data = {};
    BigIntegerToArrayU8(blob, data, true);
    CfBlobDataFree(&blob);
    return data;
}

DataBlob X509CertImpl::GetIssuerName()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->cert_->getIssuerName(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get issuer name failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return { data };
}

string X509CertImpl::GetIssuerNameEx(EncodingType encodingType)
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfEncodinigType type = static_cast<CfEncodinigType>(encodingType.get_value());
    CfResult res = this->cert_->getIssuerNameEx(this->cert_, type, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get issuer name failed!");
        return "";
    }
    string str = DataBlobToString(blob);
    CfBlobDataFree(&blob);
    return str;
}

DataBlob X509CertImpl::GetSubjectName(optional_view<EncodingType> encodingType)
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = CF_INVALID_PARAMS;
    if (encodingType.has_value()) {
        CfEncodinigType type = static_cast<CfEncodinigType>(encodingType.value().get_value());
        res = this->cert_->getSubjectNameEx(this->cert_, type, &blob);
    } else {
        res = this->cert_->getSubjectName(this->cert_, &blob);
    }
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get subject name failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return { data };
}

string X509CertImpl::GetNotBeforeTime()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult res = this->cert_->getNotBeforeTime(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get not before time failed!");
        return "";
    }
    string str = DataBlobToString(blob);
    CfBlobDataFree(&blob);
    return str;
}

string X509CertImpl::GetNotAfterTime()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult res = this->cert_->getNotAfterTime(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get not before time failed!");
        return "";
    }
    string str = DataBlobToString(blob);
    CfBlobDataFree(&blob);
    return str;
}

DataBlob X509CertImpl::GetSignature()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->cert_->getSignature(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get issuer name failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return { data };
}

string X509CertImpl::GetSignatureAlgName()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult res = this->cert_->getSignatureAlgName(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get signature alg name failed!");
        return "";
    }
    string str = DataBlobToString(blob);
    CfBlobDataFree(&blob);
    return str;
}

string X509CertImpl::GetSignatureAlgOid()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult res = this->cert_->getSignatureAlgOid(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get signature alg oid failed!");
        return "";
    }
    string str = DataBlobToString(blob);
    CfBlobDataFree(&blob);
    return str;
}

DataBlob X509CertImpl::GetSignatureAlgParams()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->cert_->getSignatureAlgParams(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get signature alg params failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return { data };
}

DataBlob X509CertImpl::GetKeyUsage()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->cert_->getKeyUsage(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get key usage failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return { data };
}

DataArray X509CertImpl::GetExtKeyUsage()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return {};
    }
    CfArray cfArr = {};
    CfResult res = this->cert_->getExtKeyUsage(this->cert_, &cfArr);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get ext key usage failed!");
        return {};
    }
    DataArray dataArr = {};
    CfArrayToDataArray(cfArr, dataArr);
    CfArrayDataClearAndFree(&cfArr);
    return dataArr;
}

int32_t X509CertImpl::GetBasicConstraints()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return -1;
    }
    return this->cert_->getBasicConstraints(this->cert_);
}

DataArray X509CertImpl::GetSubjectAltNames()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return {};
    }
    CfArray cfArr = {};
    CfResult res = this->cert_->getSubjectAltNames(this->cert_, &cfArr);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get subject alt names failed!");
        return {};
    }
    DataArray dataArr = {};
    CfArrayToDataArray(cfArr, dataArr);
    CfArrayDataClearAndFree(&cfArr);
    return dataArr;
}

DataArray X509CertImpl::GetIssuerAltNames()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return {};
    }
    CfArray cfArr = {};
    CfResult res = this->cert_->getIssuerAltNames(this->cert_, &cfArr);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get issuer alt names failed!");
        return {};
    }
    DataArray dataArr = {};
    CfArrayToDataArray(cfArr, dataArr);
    CfArrayDataClearAndFree(&cfArr);
    return dataArr;
}

DataBlob X509CertImpl::GetItem(CertItemType itemType)
{
    const std::vector<CfParam> param = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_CERT_ITEM },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = itemType }
    };
    CfParamSet *paramSet = nullptr;
    std::string errMsg = "";
    CfResult res = DoCommonOperation(this->object_, param, &paramSet, errMsg);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, errMsg.c_str());
        return {};
    }
    CfParam *itemParam = nullptr; // CfGetParam will return a pointer to the param in the paramSet
    res = static_cast<CfResult>(CfGetParam(paramSet, CF_TAG_RESULT_BYTES, &itemParam));
    if (res != CF_SUCCESS) {
        CfFreeParamSet(&paramSet);
        ANI_LOGE_THROW(res, "get item failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(itemParam->blob, data);
    CfFreeParamSet(&paramSet);
    return { data };
}

bool X509CertImpl::Match(X509CertMatchParameters const& param)
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return false;
    }
    HcfX509CertMatchParams matchParam = {};
    if (!BuildX509CertMatchParams(param, matchParam)) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "build x509 cert match params failed!");
        return false;
    }
    bool flag = false;
    CfResult res = this->cert_->match(this->cert_, &matchParam, &flag);
    FreeX509CertMatchParams(matchParam);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "match cert failed!");
        return false;
    }
    return flag;
}

DataArray X509CertImpl::GetCRLDistributionPoint()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return {};
    }
    CfArray cfArr = {};
    CfResult res = this->cert_->getCRLDistributionPointsURI(this->cert_, &cfArr);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get crl distribution points uri failed!");
        return {};
    }
    DataArray dataArr = {};
    CfArrayToDataArray(cfArr, dataArr);
    CfArrayDataClearAndFree(&cfArr);
    return dataArr;
}

X500DistinguishedName X509CertImpl::GetIssuerX500DistinguishedName()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    CfBlob blob = {};
    // x509Name
    CfResult res = this->cert_->getIssuerName(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get issuer name failed!");
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    HcfX509DistinguishedName *x509Name = nullptr;
    res = HcfX509DistinguishedNameCreate(&blob, true, &x509Name);
    CfBlobDataFree(&blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "create x509 distinguished name failed!");
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    // x509NameUtf8
    res = this->cert_->getIssuerNameDer(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get issuer name der failed!");
        CfObjDestroy(x509Name);
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    HcfX509DistinguishedName *x509NameUtf8 = nullptr;
    res = HcfX509DistinguishedNameCreate(&blob, false, &x509NameUtf8);
    CfBlobDataFree(&blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "create x509 distinguished name failed!");
        CfObjDestroy(x509Name);
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>(x509Name, x509NameUtf8);
}

X500DistinguishedName X509CertImpl::GetSubjectX500DistinguishedName()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    CfBlob blob = {};
    // x509Name
    CfResult res = this->cert_->getSubjectName(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get subject name failed!");
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    HcfX509DistinguishedName *x509Name = nullptr;
    res = HcfX509DistinguishedNameCreate(&blob, true, &x509Name);
    CfBlobDataFree(&blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "create x509 distinguished name failed!");
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    // x509NameUtf8
    res = this->cert_->getSubjectNameDer(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "get subject name der failed!");
        CfObjDestroy(x509Name);
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    HcfX509DistinguishedName *x509NameUtf8 = nullptr;
    res = HcfX509DistinguishedNameCreate(&blob, false, &x509NameUtf8);
    CfBlobDataFree(&blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "create x509 distinguished name failed!");
        CfObjDestroy(x509Name);
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>(x509Name, x509NameUtf8);
}

string X509CertImpl::ToString()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult res = this->cert_->toString(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "to string failed!");
        return "";
    }
    string str = DataBlobToString(blob);
    CfBlobDataFree(&blob);
    return str;
}

string X509CertImpl::ToStringEx(EncodingType encodingType)
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfEncodinigType type = static_cast<CfEncodinigType>(encodingType.get_value());
    CfResult res = this->cert_->toStringEx(this->cert_, type, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "to string failed!");
        return "";
    }
    string str = DataBlobToString(blob);
    CfBlobDataFree(&blob);
    return str;
}

array<uint8_t> X509CertImpl::HashCode()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return {};
    }
    CfBlob blob = {};
    CfResult res = this->cert_->hashCode(this->cert_, &blob);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "hash code failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(blob, data);
    CfBlobDataFree(&blob);
    return data;
}

CertExtension X509CertImpl::GetExtensionsObject()
{
    if (this->cert_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x509cert obj is nullptr!");
        return make_holder<CertExtensionImpl, CertExtension>();
    }
    CfBlob blob = {};
    CfResult res = this->cert_->getExtensionsObject(this->cert_, &blob);
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

X509Cert CreateX509CertSync(EncodingBlob const& inStream)
{
    CfBlob blob = {};
    ArrayU8ToDataBlob(inStream.data, blob);
    CfEncodingBlob encodingBlob = {};
    CfEncodingFormat encodingFormat = static_cast<CfEncodingFormat>(inStream.encodingFormat.get_value());
    DataBlobToEncodingBlob(blob, encodingBlob, encodingFormat);
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
