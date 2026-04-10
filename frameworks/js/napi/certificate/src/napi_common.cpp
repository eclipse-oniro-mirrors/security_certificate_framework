/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#include "napi_common.h"

#include <cstdarg>
#include <securec.h>

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_param.h"
#include "cf_result.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"

namespace OHOS {
namespace CertFramework {
CfResult NapiGetBlobElementNoCopy(napi_env env, napi_value element, const char *name, CfBlob &value, char **errMsg);
static bool GetCallback(napi_env env, napi_value object, napi_ref *callBack)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, object, &valueType);
    if (status != napi_ok) {
        CF_LOG_E("Failed to get object type");
        return false;
    }

    if (valueType != napi_function) {
        CF_LOG_E("wrong argument type. expect callback type. [Type]: %{public}d", valueType);
        return false;
    }

    napi_create_reference(env, object, 1, callBack);
    return true;
}

bool GetCallbackAndPromise(napi_env env, AsyncCtx async, napi_value arg)
{
    if (async->asyncType == ASYNC_TYPE_CALLBACK) {
        if (!GetCallback(env, arg, &async->callback)) {
            napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get callback type error"));
            CF_LOG_E("get callback failed!");
            return false;
        }
    } else {
        napi_create_promise(env, &async->deferred, &async->promise);
    }
    return true;
}

static void ReturnCallbackResult(napi_env env, AsyncCtx async, napi_value result)
{
    napi_value businessError = nullptr;
    if (async->errCode != CF_SUCCESS) {
        businessError = CertGenerateBusinessError(env, async->errCode, async->errMsg);
    }
    napi_value params[CALLBACK_NUM] = { businessError, result };

    napi_value func = nullptr;
    napi_get_reference_value(env, async->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, CALLBACK_NUM, params, &callFuncRet);
}

static void ReturnPromiseResult(napi_env env, AsyncCtx async, napi_value result)
{
    if (async->errCode == CF_SUCCESS) {
        napi_resolve_deferred(env, async->deferred, result);
    } else {
        napi_reject_deferred(env, async->deferred,
            CertGenerateBusinessError(env, async->errCode, async->errMsg));
    }
}

void ReturnJSResult(napi_env env, AsyncCtx async, napi_value result)
{
    if (async == nullptr) {
        return;
    }
    if (async->asyncType == ASYNC_TYPE_CALLBACK) {
        ReturnCallbackResult(env, async, result);
    } else {
        ReturnPromiseResult(env, async, result);
    }
}

napi_value GetResourceName(napi_env env, const char *name)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resourceName);
    return resourceName;
}

int32_t GetBlobArrayFromParamSet(const CfParamSet *paramSet, CfArray *outArray)
{
    if (paramSet->paramsCnt <= 1) {
        CF_LOG_E("invalid paramSet for blobArray");
        return CF_INVALID_PARAMS;
    }

    uint32_t oidsCnt = paramSet->paramsCnt - 1;
    CfBlob *blobs = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob) * oidsCnt, 0));
    if (blobs == nullptr) {
        CF_LOG_E("Failed to malloc blobs");
        return CF_ERR_MALLOC;
    }

    for (uint32_t i = 0; i < oidsCnt; ++i) {
        if (paramSet->params[i + 1].tag != CF_TAG_RESULT_BYTES) { /* index of blob is 1-based */
            CF_LOG_E("params[%{public}u] is invalid", i);
            FreeCfBlobArray(blobs, i);
            blobs = nullptr;
            return CF_INVALID_PARAMS;
        }

        uint32_t size = paramSet->params[i + 1].blob.size;
        blobs[i].data = static_cast<uint8_t *>(CfMalloc(size, 0));
        if (blobs[i].data == nullptr) {
            CF_LOG_E("Failed to malloc blob[%{public}u].data", i);
            FreeCfBlobArray(blobs, i);
            blobs = nullptr;
            return CF_ERR_MALLOC;
        }
        (void)memcpy_s(blobs[i].data, size, paramSet->params[i + 1].blob.data, size);
        blobs[i].size = size;
    }

    outArray->data = blobs;
    outArray->count = oidsCnt;
    outArray->format = CF_FORMAT_DER;
    return CF_SUCCESS;
}

napi_value ConvertBlobArrayToNapiValue(napi_env env, const CfParamSet *paramSet)
{
    CfArray outArray = { nullptr, CF_FORMAT_DER, 0 };
    int32_t ret = GetBlobArrayFromParamSet(paramSet, &outArray);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("Failed to get out array from paramSet");
        return nullptr;
    }

    napi_value returnValue = ConvertArrayToNapiValue(env, &outArray);
    CfArrayDataClearAndFree(&outArray);
    return returnValue;
}

void FreeAsyncContext(napi_env env, AsyncCtx &async)
{
    if (async == nullptr) {
        return;
    }
    if (async->asyncWork != nullptr) {
        napi_delete_async_work(env, async->asyncWork);
        async->asyncWork = nullptr;
    }

    if (async->callback != nullptr) {
        napi_delete_reference(env, async->callback);
        async->callback = nullptr;
    }
    if (async->paramRef != nullptr) {
        napi_delete_reference(env, async->paramRef);
        async->paramRef = nullptr;
    }
    CfFree(async);
    async = nullptr;
}

CfResult NapiGetProperty(napi_env env, napi_value arg, const char *name, napi_value &value, char **errMsg)
{
    bool hasValue = false;
    if (napi_has_named_property(env, arg, name, &hasValue) != napi_ok) {
        CfBuildErrorMsg(errMsg, "check property '%s' failed", name);
        return CF_ERR_NAPI;
    }
    if (!hasValue) {
        return CF_NOT_EXIST;
    }

    napi_value obj = nullptr;
    napi_status status = napi_get_named_property(env, arg, name, &obj);
    if (status != napi_ok) {
        CfBuildErrorMsg(errMsg, "get property '%s' failed!", name);
        return CF_ERR_NAPI;
    }
    if (obj == nullptr) {
        CfBuildErrorMsg(errMsg, "'%s' is null!", name);
        return CF_INVALID_PARAMS;
    }
    value = obj;
    return CF_SUCCESS;
}

void NapiFreeStringArray(HcfStringArray &array)
{
    if (array.data == nullptr) {
        return;
    }
    for (uint32_t i = 0; i < array.count; ++i) {
        CfFree(array.data[i]);
    }
    CfFree(array.data);
    array.data = nullptr;
    array.count = 0;
}

CfResult NapiGetBoolValueEx(napi_env env, napi_value arg, const char *name, bool &value, char **errMsg)
{
    napi_value obj = nullptr;
    CfResult ret = NapiGetProperty(env, arg, name, obj, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    napi_valuetype valueType;
    if (napi_typeof(env, obj, &valueType) != napi_ok) {
        CfBuildErrorMsg(errMsg, "'%s': get value type failed", name);
        return CF_ERR_NAPI;
    }
    if (valueType != napi_boolean) {
        CfBuildErrorMsg(errMsg, "'%s': valueType is not boolean", name);
        return CF_INVALID_PARAMS;
    }

    if (napi_get_value_bool(env, obj, &value) != napi_ok) {
        CfBuildErrorMsg(errMsg, "'%s': get value failed", name);
        return CF_ERR_NAPI;
    }
    return CF_SUCCESS;
}

static CfResult NapiGetStringFromElement(napi_env env, napi_value element, const NapiParamInfo *info,
    char *&value, char **errMsg)
{
    napi_valuetype valueType;
    if (napi_typeof(env, element, &valueType) != napi_ok) {
        CfBuildErrorMsg(errMsg, "'%s': get value type failed", info->name);
        return CF_ERR_NAPI;
    }
    if (valueType != napi_string) {
        CfBuildErrorMsg(errMsg, "'%s': valueType is not string", info->name);
        return CF_INVALID_PARAMS;
    }

    size_t strLen = 0;
    if (napi_get_value_string_utf8(env, element, NULL, 0, &strLen) != napi_ok) {
        CfBuildErrorMsg(errMsg, "'%s': get value length failed", info->name);
        return CF_ERR_NAPI;
    }

    if (strLen < static_cast<size_t>(info->minLen) || strLen > static_cast<size_t>(info->maxLen)) {
        CfBuildErrorMsg(errMsg, "'%s': value len is invalid, should be in [%d, %d]", info->name, info->minLen,
            info->maxLen);
        return CF_ERR_PARAMETER_CHECK;
    }

    char *str = static_cast<char *>(CfMallocEx(strLen + 1));
    if (str == nullptr) {
        CfBuildErrorMsg(errMsg, "'%s': allocate memory failed", info->name);
        return CF_ERR_MALLOC;
    }
    if (napi_get_value_string_utf8(env, element, str, strLen + 1, &strLen) != napi_ok) {
        CfFree(str);
        CfBuildErrorMsg(errMsg, "'%s': get value failed", info->name);
        return CF_ERR_NAPI;
    }
    value = str;
    return CF_SUCCESS;
}

CfResult NapiGetStringValueEx(napi_env env, napi_value arg, const NapiParamInfo *info, char *&value, char **errMsg)
{
    napi_value obj = nullptr;
    CfResult ret = NapiGetProperty(env, arg, info->name, obj, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    return NapiGetStringFromElement(env, obj, info, value, errMsg);
}

CfResult NapiGetBlobValueEx(napi_env env, napi_value arg, const char *name, CfBlob &value, char **errMsg)
{
    napi_value obj = nullptr;
    CfResult ret = NapiGetProperty(env, arg, name, obj, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    return NapiGetBlobElementNoCopy(env, obj, name, value, errMsg);
}

CfResult NapiGetArrayBaseInfoEx(napi_env env, napi_value arg, const NapiParamInfo *info, NapiArrayBaseInfo *out,
    char **errMsg)
{
    napi_value arrayObj = nullptr;
    uint32_t length = 0;
    CfResult ret = NapiGetProperty(env, arg, info->name, arrayObj, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    bool isArray = false;
    if (napi_is_array(env, arrayObj, &isArray) != napi_ok) {
        CfBuildErrorMsg(errMsg, "'%s': check type failed", info->name);
        return CF_ERR_NAPI;
    }
    if (!isArray) {
        CfBuildErrorMsg(errMsg, "'%s': valueType is not array", info->name);
        return CF_INVALID_PARAMS;
    }

    if (napi_get_array_length(env, arrayObj, &length) != napi_ok) {
        CfBuildErrorMsg(errMsg, "'%s': get length failed", info->name);
        return CF_ERR_NAPI;
    }

    if (length == 0) {
        return CF_NOT_EXIST;
    }

    if (length < static_cast<uint32_t>(info->minLen) || length > static_cast<uint32_t>(info->maxLen)) {
        CfBuildErrorMsg(errMsg, "'%s': length %u is invalid, should be in [%d, %d]",
            info->name, length, info->minLen, info->maxLen);
        return CF_ERR_PARAMETER_CHECK;
    }

    out->obj = arrayObj;
    out->length = length;
    return CF_SUCCESS;
}

CfResult NapiGetStringArrayEx(napi_env env, napi_value arg, const NapiParamInfo *info, HcfStringArray &value,
    char **errMsg)
{
    NapiArrayBaseInfo arrayInfo = {nullptr, 0};
    CfResult ret = NapiGetArrayBaseInfoEx(env, arg, info, &arrayInfo, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    value.data = static_cast<char **>(CfMallocEx(arrayInfo.length * sizeof(char *)));
    if (value.data == nullptr) {
        CfBuildErrorMsg(errMsg, "'%s': allocate memory failed", info->name);
        return CF_ERR_MALLOC;
    }

    for (uint32_t i = 0; i < arrayInfo.length; ++i) {
        napi_value element;
        if (napi_get_element(env, arrayInfo.obj, i, &element) != napi_ok) {
            NapiFreeStringArray(value);
            CfBuildErrorMsg(errMsg, "'%s': get element %u failed", info->name, i);
            return CF_ERR_NAPI;
        }

        char *str = nullptr;
        ret = NapiGetStringFromElement(env, element, info->innerParams, str, errMsg);
        if (ret != CF_SUCCESS) {
            NapiFreeStringArray(value);
            return ret;
        }
        value.data[i] = str;
    }
    value.count = arrayInfo.length;
    return CF_SUCCESS;
}

CfResult NapiGetBlobElementNoCopy(napi_env env, napi_value element, const char *name, CfBlob &value, char **errMsg)
{
    bool isTypedArray = false;
    if (napi_is_typedarray(env, element, &isTypedArray) != napi_ok) {
        CfBuildErrorMsg(errMsg, "'%s': check element type failed!", name);
        return CF_ERR_NAPI;
    }
    if (!isTypedArray) {
        CfBuildErrorMsg(errMsg, "'%s': valueType is not typedarray!", name);
        return CF_INVALID_PARAMS;
    }

    napi_typedarray_type arrayType;
    size_t length = 0;
    void *rawData = nullptr;
    napi_value arrayBuffer = nullptr;
    size_t offset = 0;

    napi_status status = napi_get_typedarray_info(env, element, &arrayType, &length, &rawData, &arrayBuffer, &offset);
    if (status != napi_ok) {
        CfBuildErrorMsg(errMsg, "'%s': get typedarray info failed!", name);
        return CF_ERR_NAPI;
    }
    if (arrayType != napi_uint8_array) {
        CfBuildErrorMsg(errMsg, "'%s': element is not uint8 array!", name);
        return CF_INVALID_PARAMS;
    }

    value.data = static_cast<uint8_t *>(rawData);
    value.size = length;
    return CF_SUCCESS;
}

CfResult NapiGetBlobArrayNoCopy(napi_env env, napi_value arg, const NapiParamInfo *info, CfBlobArray &value,
    char **errMsg)
{
    NapiArrayBaseInfo arrayInfo = {nullptr, 0};
    CfResult ret = NapiGetArrayBaseInfoEx(env, arg, info, &arrayInfo, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    value.data = static_cast<CfBlob *>(CfMallocEx(arrayInfo.length * sizeof(CfBlob)));
    if (value.data == nullptr) {
        CfBuildErrorMsg(errMsg, "'%s': allocate memory failed", info->name);
        return CF_ERR_MALLOC;
    }

    for (uint32_t i = 0; i < arrayInfo.length; ++i) {
        napi_value element;
        if (napi_get_element(env, arrayInfo.obj, i, &element) != napi_ok) {
            CfFree(value.data);
            value.data = nullptr;
            CfBuildErrorMsg(errMsg, "'%s': get element %u failed", info->name, i);
            return CF_ERR_NAPI;
        }

        ret = NapiGetBlobElementNoCopy(env, element, info->name, value.data[i], errMsg);
        if (ret != CF_SUCCESS) {
            CfFree(value.data);
            value.data = nullptr;
            return ret;
        }
    }

    value.count = arrayInfo.length;
    return CF_SUCCESS;
}

CfResult NapiGetInt32ArrayEx(napi_env env, napi_value arg, const NapiParamInfo *info,
    HcfInt32Array &value, char **errMsg)
{
    NapiArrayBaseInfo arrayInfo = {nullptr, 0};
    CfResult ret = NapiGetArrayBaseInfoEx(env, arg, info, &arrayInfo, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    value.data = static_cast<int *>(CfMallocEx(arrayInfo.length * sizeof(int32_t)));
    if (value.data == nullptr) {
        CfBuildErrorMsg(errMsg, "'%s': allocate memory failed", info->name);
        return CF_ERR_MALLOC;
    }

    for (uint32_t i = 0; i < arrayInfo.length; ++i) {
        napi_value element;
        if (napi_get_element(env, arrayInfo.obj, i, &element) != napi_ok) {
            CfFree(value.data);
            value.data = nullptr;
            value.count = 0;
            CfBuildErrorMsg(errMsg, "'%s': get element %u failed", info->name, i);
            return CF_ERR_NAPI;
        }

        napi_valuetype valueType;
        if (napi_typeof(env, element, &valueType) != napi_ok) {
            CfFree(value.data);
            value.data = nullptr;
            value.count = 0;
            CfBuildErrorMsg(errMsg, "'%s': element %u get type failed", info->name, i);
            return CF_ERR_NAPI;
        }
        if (valueType != napi_number) {
            CfFree(value.data);
            value.data = nullptr;
            value.count = 0;
            CfBuildErrorMsg(errMsg, "'%s': element %u is not number", info->name, i);
            return CF_INVALID_PARAMS;
        }

        int32_t numValue = 0;
        if (napi_get_value_int32(env, element, &numValue) != napi_ok) {
            CfFree(value.data);
            value.data = nullptr;
            value.count = 0;
            CfBuildErrorMsg(errMsg, "'%s': element %u get value failed", info->name, i);
            return CF_ERR_NAPI;
        }
        value.data[i] = numValue;
    }
    value.count = arrayInfo.length;
    return CF_SUCCESS;
}

CfResult NapiGetInt32Ex(napi_env env, napi_value arg, const char *name, int32_t &value, char **errMsg)
{
    napi_value element = nullptr;
    CfResult ret = NapiGetProperty(env, arg, name, element, errMsg);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, element, &valueType);
    if (valueType != napi_number) {
        CfBuildErrorMsg(errMsg, "'%s': valueType is not number", name);
        return CF_INVALID_PARAMS;
    }

    if (napi_get_value_int32(env, element, &value) != napi_ok) {
        CfBuildErrorMsg(errMsg, "'%s': get value failed", name);
        return CF_ERR_NAPI;
    }
    return CF_SUCCESS;
}

} // namespace CertFramework
} // namespace OHOS