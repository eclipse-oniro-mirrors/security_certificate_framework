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

#include "ani_pub_key.h"

namespace ANI::CertFramework {
PubKeyImpl::PubKeyImpl() {}

PubKeyImpl::PubKeyImpl(HcfPubKey *pubKey) : pubKey_(pubKey) {}

PubKeyImpl::~PubKeyImpl()
{
    CfObjDestroy(this->pubKey_);
    this->pubKey_ = nullptr;
}

int64_t PubKeyImpl::GetPubKeyObj()
{
    return reinterpret_cast<int64_t>(this->pubKey_);
}

cryptoFramework::OptKeySpec PubKeyImpl::GetAsyKeySpec(cryptoFramework::AsyKeySpecItem itemType)
{
    ANI_LOGE_THROW(CF_NOT_SUPPORT, "GetAsyKeySpec not supported!");
    return cryptoFramework::OptKeySpec::make_INT32(-1);
}

cryptoFramework::DataBlob PubKeyImpl::GetEncodedDer(string_view format)
{
    ANI_LOGE_THROW(CF_NOT_SUPPORT, "GetEncodedDer not supported!");
    return {};
}

string PubKeyImpl::GetEncodedPem(string_view format)
{
    ANI_LOGE_THROW(CF_NOT_SUPPORT, "GetEncodedPem not supported!");
    return "";
}

int64_t PubKeyImpl::GetKeyObj()
{
    ANI_LOGE_THROW(CF_NOT_SUPPORT, "GetKeyObj not supported!");
    return -1;
}

cryptoFramework::DataBlob PubKeyImpl::GetEncoded()
{
    if (this->pubKey_ == nullptr) {
        ANI_LOGE_THROW(CF_ERR_ANI, "pubKey obj is nullptr!");
        return {};
    }
    HcfBlob outBlob = {};
    HcfResult res = this->pubKey_->base.getEncoded(&this->pubKey_->base, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(static_cast<CfResult>(res), "getEncoded failed.");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8({ outBlob.len, outBlob.data }, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

string PubKeyImpl::GetFormat()
{
    ANI_LOGE_THROW(CF_NOT_SUPPORT, "GetFormat not supported!");
    return "";
}

string PubKeyImpl::GetAlgName()
{
    ANI_LOGE_THROW(CF_NOT_SUPPORT, "GetAlgName not supported!");
    return "";
}
} // namespace ANI::CertFramework
