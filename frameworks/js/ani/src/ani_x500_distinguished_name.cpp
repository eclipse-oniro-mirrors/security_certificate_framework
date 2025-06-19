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

X500DistinguishedNameImpl::X500DistinguishedNameImpl(HcfX509DistinguishedName *x509Name) : x509Name_(x509Name) {}

X500DistinguishedNameImpl::~X500DistinguishedNameImpl()
{
    CfObjDestroy(this->x509Name_);
    this->x509Name_ = nullptr;
}

int64_t X500DistinguishedNameImpl::GetX500DistinguishedNameObj()
{
    return reinterpret_cast<int64_t>(this->x509Name_);
}

X500DistinguishedName CreateX500DistinguishedNameInner(const CfBlob *inStream, bool bString)
{
    HcfX509DistinguishedName *x500DistinguishedName = nullptr;
    CfResult res = HcfX509DistinguishedNameCreate(inStream, bString, &x500DistinguishedName);
    if (res != CF_SUCCESS) {
        ANI_LOGE_THROW(res, "create x500 distinguished name failed.");
        return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>();
    }
    return make_holder<X500DistinguishedNameImpl, X500DistinguishedName>(x500DistinguishedName);
}

string X500DistinguishedNameImpl::GetName()
{
    if (this->x509Name_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x500 distinguished name obj is nullptr!");
        return "";
    }
    CfBlob blob = {};
    CfResult ret = this->x509Name_->getName(this->x509Name_, NULL, &blob, NULL);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "get name failed.");
        return "";
    }
    string result = string(reinterpret_cast<char *>(blob.data), blob.size);
    CfBlobDataFree(&blob);
    return result;
}

string X500DistinguishedNameImpl::GetNameByEnum(EncodingType encodingType)
{
    // api 20
    TH_THROW(std::runtime_error, "GetNameByEnum not implemented");
}

array<string> X500DistinguishedNameImpl::GetNameByStr(string_view type)
{
    if (this->x509Name_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x500 distinguished name obj is nullptr!");
        return array<string>{};
    }
    CfBlob inPara = {};
    StringToDataBlob(type, inPara);
    CfArray outArr = { nullptr, CF_FORMAT_DER, 0 };
    CfResult ret = this->x509Name_->getName(this->x509Name_, &inPara, NULL, &outArr);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "get name failed.");
        return array<string>{};
    }
    array<string> result = array<string>::make(outArr.count, {});
    for (uint32_t i = 0; i < outArr.count; i++) {
        result[i] = string(reinterpret_cast<char *>(outArr.data[i].data), outArr.data[i].size);
    }
    CfArrayDataClearAndFree(&outArr);
    return result;
}

EncodingBlob X500DistinguishedNameImpl::GetEncoded()
{
    EncodingBlob encodingBlob = { {}, EncodingFormat(EncodingFormat::key_t::FORMAT_DER) };
    if (this->x509Name_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "x500 distinguished name obj is nullptr!");
        return encodingBlob;
    }
    CfEncodingBlob blob = {};
    CfResult ret = this->x509Name_->getEncode(this->x509Name_, &blob);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "get encoded failed.");
        return encodingBlob;
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8({ blob.len, blob.data }, data);
    encodingBlob.data = data;
    encodingBlob.encodingFormat = static_cast<EncodingFormat::key_t>(blob.encodingFormat);
    CfEncodingBlobDataFree(&blob);
    return encodingBlob;
}

X500DistinguishedName CreateX500DistinguishedNameByStrSync(string_view nameStr)
{
    CfBlob nameStrBlob = {};
    StringToDataBlob(nameStr, nameStrBlob);
    return CreateX500DistinguishedNameInner(&nameStrBlob, true);
}

X500DistinguishedName CreateX500DistinguishedNameByDerSync(array_view<uint8_t> nameDer)
{
    CfBlob nameDerBlob = {};
    ArrayU8ToDataBlob(nameDer, nameDerBlob);
    return CreateX500DistinguishedNameInner(&nameDerBlob, false);
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateX500DistinguishedNameByStrSync(ANI::CertFramework::CreateX500DistinguishedNameByStrSync);
TH_EXPORT_CPP_API_CreateX500DistinguishedNameByDerSync(ANI::CertFramework::CreateX500DistinguishedNameByDerSync);
// NOLINTEND
