/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "securec.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_param.h"
#include "cf_result.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"

namespace OHOS {
namespace CertFramework {
static bool GetCallback(napi_env env, napi_value object, napi_ref *callBack)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, object, &valueType);
    if (status != napi_ok) {
        CF_LOG_E("Failed to get object type");
        return false;
    }

    if (valueType != napi_function) {
        CF_LOG_E("wrong argument type. expect callback type. [Type]: %d", valueType);
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

int32_t CheckOutParamType(const CfParamSet *paramSet, CfTagType targetType)
{
    CfParam *resultTypeParam = nullptr;
    int32_t ret = CfGetParam(paramSet, CF_TAG_RESULT_TYPE, &resultTypeParam);
    if (ret != CF_SUCCESS) {
        CF_LOG_E("ext: Failed to get CF_TAG_RESULT_TYPE");
        return ret;
    }

    if (resultTypeParam->int32Param != targetType) {
        CF_LOG_E("ext: result type is not target type");
        return CF_NOT_SUPPORT;
    }
    return CF_SUCCESS;
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
            CF_LOG_E("params[%u] is invalid", i);
            FreeCfBlobArray(blobs, i);
            return CF_INVALID_PARAMS;
        }

        uint32_t size = paramSet->params[i + 1].blob.size;
        blobs[i].data = static_cast<uint8_t *>(CfMalloc(size, 0));
        if (blobs[i].data == nullptr) {
            CF_LOG_E("Failed to malloc blob[%u].data", i);
            FreeCfBlobArray(blobs, i);
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

napi_value ConvertBlobArrayToNapiValue(napi_env env,  const CfParamSet *paramSet)
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

} // namespace CertFramework
} // namespace OHOS