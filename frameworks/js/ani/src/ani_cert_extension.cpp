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
#include "ani_object.h"
#include "cf_type.h"
#include "cf_param.h"

namespace ANI::CertFramework {
CertExtensionImpl::CertExtensionImpl() {}

CertExtensionImpl::CertExtensionImpl(CfObject *object) : object_(object) {}

CertExtensionImpl::~CertExtensionImpl()
{
    CfObjDestroy(this->object_);
    this->object_ = nullptr;
}

EncodingBlob CertExtensionImpl::GetEncoded()
{
    EncodingBlob encodingBlob = { {}, EncodingFormat(EncodingFormat::key_t::FORMAT_DER) };
    if (this->object_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "object is nullptr");
        return encodingBlob;
    }

    const std::vector<CfParam> param = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ITEM },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = CF_ITEM_ENCODED }
    };
    std::string errMsg = "";
    CfParamSet *outParam = nullptr;
    CfResult ret = DoCommonOperation(this->object_, param, &outParam, errMsg);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, errMsg.c_str());
        return encodingBlob;
    }

    CfParam *resultParam = nullptr;
    ret = static_cast<CfResult>(CfGetParam(outParam, CF_TAG_RESULT_BYTES, &resultParam));
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "get result failed");
        CfFreeParamSet(&outParam);
        return encodingBlob;
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(resultParam->blob, data);
    encodingBlob.data = data;
    CfFreeParamSet(&outParam);
    return encodingBlob;
}

DataArray CertExtensionImpl::GetOidList(ExtensionOidType valueType)
{
    if (this->object_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "object is nullptr");
        return {};
    }

    const std::vector<CfParam> param = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_OIDS },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = static_cast<int32_t>(valueType) }
    };
    std::string errMsg = "";
    CfParamSet *outParamSet = nullptr;
    CfResult ret = DoCommonOperation(this->object_, param, &outParamSet, errMsg);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, errMsg.c_str());
        return {};
    }

    if (outParamSet->paramSetSize <= 1) {
        CfFreeParamSet(&outParamSet);
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "invalid param set size");
        return {};
    } else {
        uint32_t count = outParamSet->paramsCnt - 1;
        DataArray result = { array<array<uint8_t>>::make(count, {}) };
        for (uint32_t i = 0; i < count; ++i) {
            DataBlobToArrayU8(outParamSet->params[i + 1].blob, result.data[i]);
        }
        CfFreeParamSet(&outParamSet);
        return result;
    }
}

DataBlob CertExtensionImpl::GetEntry(ExtensionEntryType valueType, DataBlob const& oid)
{
    if (this->object_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "object is nullptr");
        return {};
    }
    CfBlob oidBlob = {};
    ArrayU8ToDataBlob(oid.data, oidBlob);
    const std::vector<CfParam> param = {
        { .tag = CF_TAG_GET_TYPE, .int32Param = CF_GET_TYPE_EXT_ENTRY },
        { .tag = CF_TAG_PARAM0_INT32, .int32Param = static_cast<int32_t>(valueType) },
        { .tag = CF_TAG_PARAM1_BUFFER, .blob = oidBlob },
    };
    std::string errMsg = "";
    CfParamSet *outParamSet = nullptr;
    CfResult ret = DoCommonOperation(this->object_, param, &outParamSet, errMsg);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, errMsg.c_str());
        return {};
    }

    CfParam *resultParam = nullptr;
    ret = static_cast<CfResult>(CfGetParam(outParamSet, CF_TAG_RESULT_BYTES, &resultParam));
    if (ret != CF_SUCCESS) {
        CfFreeParamSet(&outParamSet);
        ANI_LOGE_THROW(ret, "get result failed");
        return {};
    }

    array<uint8_t> data = {};
    DataBlobToArrayU8(resultParam->blob, data);
    CfFreeParamSet(&outParamSet);
    return { data };
}

int32_t CertExtensionImpl::CheckCA()
{
    if (this->object_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "object is nullptr");
        return CF_INVALID_PARAMS;
    }

    const std::vector<CfParam> param = {
        { .tag = CF_TAG_CHECK_TYPE, .int32Param = CF_CHECK_TYPE_EXT_CA },
    };
    std::string errMsg = "";
    CfParamSet *outParamSet = nullptr;
    CfResult ret = DoCommonOperation(this->object_, param, &outParamSet, errMsg);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, errMsg.c_str());
        return ret;
    }

    CfParam *resultParam = nullptr;
    ret = static_cast<CfResult>(CfGetParam(outParamSet, CF_TAG_RESULT_INT, &resultParam));
    if (ret != CF_SUCCESS) {
        CfFreeParamSet(&outParamSet);
        ANI_LOGE_THROW(ret, "get result failed");
        return ret;
    }
    int32_t result = resultParam->int32Param;
    CfFreeParamSet(&outParamSet);
    return result;
}

bool CertExtensionImpl::HasUnsupportedCriticalExtension()
{
    if (this->object_ == nullptr) {
        ANI_LOGE_THROW(CF_INVALID_PARAMS, "object is nullptr");
        return false;
    }

    const std::vector<CfParam> param = {
        { .tag = CF_TAG_CHECK_TYPE, .int32Param = CF_CHECK_TYPE_EXT_HAS_UN_SUPPORT },
    };
    std::string errMsg = "";
    CfParamSet *outParamSet = nullptr;
    CfResult ret = DoCommonOperation(this->object_, param, &outParamSet, errMsg);
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, errMsg.c_str());
        return false;
    }

    CfParam *resultParam = nullptr;
    ret = static_cast<CfResult>(CfGetParam(outParamSet, CF_TAG_RESULT_BOOL, &resultParam));
    if (ret != CF_SUCCESS) {
        CfFreeParamSet(&outParamSet);
        ANI_LOGE_THROW(ret, "get result failed");
        return false;
    }

    bool result = resultParam->boolParam;
    CfFreeParamSet(&outParamSet);
    return result;
}

CertExtension CreateCertExtensionSync(EncodingBlob const& inStream)
{
    CfObject *object = nullptr;
    CfEncodingBlob encodingBlob = {};
    encodingBlob.data = inStream.data.data();
    encodingBlob.len = inStream.data.size();
    encodingBlob.encodingFormat = static_cast<CfEncodingFormat>(static_cast<int>(inStream.encodingFormat));
    CfResult ret = static_cast<CfResult>(CfCreate(CF_OBJ_TYPE_EXTENSION, &encodingBlob, &object));
    if (ret != CF_SUCCESS) {
        ANI_LOGE_THROW(ret, "create cert extension failed");
        return make_holder<CertExtensionImpl, CertExtension>();
    }
    return make_holder<CertExtensionImpl, CertExtension>(object);
}
} // namespace ANI::CertFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateCertExtensionSync(ANI::CertFramework::CreateCertExtensionSync);
// NOLINTEND
