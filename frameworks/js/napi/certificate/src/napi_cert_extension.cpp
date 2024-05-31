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

#include "napi_cert_extension.h"

#include "napi/native_common.h"
#include "napi/native_api.h"

#include "cf_api.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_param.h"
#include "cf_result.h"

#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_common.h"
#include "napi_object.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiCertExtension::classRef_ = nullptr;

struct CfExtensionAsyncContext {
    AsyncCtx async = nullptr;

    CfEncodingBlob *encodingBlob = nullptr;
    CfObject *extsObj = nullptr;
};
using ExtsAsyncContext = CfExtensionAsyncContext *;

NapiCertExtension::NapiCertExtension(CfObject *object)
{
    this->object_ = object;
}

NapiCertExtension::~NapiCertExtension()
{
    if (this->object_ != nullptr) {
        this->object_->destroy(&this->object_);
    }
}

static ExtsAsyncContext NewExtsAsyncContext(void)
{
    ExtsAsyncContext extsAsyncCtx = static_cast<ExtsAsyncContext>(CfMalloc(sizeof(CfExtensionAsyncContext), 0));
    if (extsAsyncCtx == nullptr) {
        CF_LOG_E("Failed to malloc extension async context");
        return nullptr;
    }

    AsyncCtx asyncCtx = static_cast<AsyncCtx>(CfMalloc(sizeof(AsyncContext), 0));
    if (asyncCtx == nullptr) {
        CF_LOG_E("Failed to malloc async context");
        CfFree(extsAsyncCtx);
        return nullptr;
    }

    extsAsyncCtx->async = asyncCtx;
    return extsAsyncCtx;
}

static void DeleteExtsAsyncContext(napi_env env, ExtsAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    FreeAsyncContext(env, context->async);

    CfEncodingBlobDataFree(context->encodingBlob);
    CfFree(context->encodingBlob);
    context->encodingBlob = nullptr;

    CfFree(context);
}

static napi_value ParseCreateExtsJSParams(napi_env env, napi_callback_info info, ExtsAsyncContext context)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return nullptr;
    }

    if (!GetEncodingBlobFromValue(env, argv[PARAM0], &context->encodingBlob)) {
        CF_LOG_E("get encoding blob from data failed!");
        return nullptr;
    }

    context->async->asyncType = GetAsyncType(env, argc, ARGS_SIZE_TWO, argv[PARAM1]);
    if (!GetCallbackAndPromise(env, context->async, argv[PARAM1])) {
        return nullptr;
    }

    return NapiGetInt32(env, 0);
}

static napi_value CreateCertExtsJSInstance(napi_env env)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    napi_get_reference_value(env, NapiCertExtension::classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);
    return instance;
}

static void CreateCertExtsExecute(napi_env env, void *data)
{
    ExtsAsyncContext context = static_cast<ExtsAsyncContext>(data);
    context->async->errCode = CfCreate(CF_OBJ_TYPE_EXTENSION, context->encodingBlob, &context->extsObj);
    if (context->async->errCode != CF_SUCCESS) {
        context->async->errMsg = "create extension failed";
    }
}

static void CreateCertExtsComplete(napi_env env, napi_status status, void *data)
{
    ExtsAsyncContext context = static_cast<ExtsAsyncContext>(data);
    if (context->async->errCode != CF_SUCCESS) {
        ReturnJSResult(env, context->async, nullptr);
        DeleteExtsAsyncContext(env, context);
        return;
    }

    napi_value jsObject = CreateCertExtsJSInstance(env);
    NapiCertExtension *napiObject = new (std::nothrow) NapiCertExtension(context->extsObj);
    if (napiObject == nullptr) {
        context->async->errCode = CF_ERR_MALLOC;
        context->async->errMsg = "Failed to create napi extension class";
        CF_LOG_E("Failed to create napi extension class");
        if (context->extsObj != nullptr) {
            context->extsObj->destroy(&(context->extsObj));
        }
        ReturnJSResult(env, context->async, nullptr);
        DeleteExtsAsyncContext(env, context);
        return;
    }
    napi_wrap(
        env, jsObject, napiObject,
        [](napi_env env, void *data, void *hint) {
            NapiCertExtension *certExts = static_cast<NapiCertExtension *>(data);
            delete certExts;
            return;
        },
        nullptr, nullptr);

    ReturnJSResult(env, context->async, jsObject);
    DeleteExtsAsyncContext(env, context);
}

static napi_value CreateCertExtsAsyncWork(napi_env env, ExtsAsyncContext context)
{
    napi_create_async_work(
        env,
        nullptr,
        GetResourceName(env, "CreateCertExtsAsyncWork"),
        CreateCertExtsExecute,
        CreateCertExtsComplete,
        static_cast<void *>(context),
        &context->async->asyncWork);

    napi_queue_async_work(env, context->async->asyncWork);
    if (context->async->asyncType == ASYNC_TYPE_PROMISE) {
        return context->async->promise;
    } else {
        return NapiGetNull(env);
    }
    return nullptr;
}

napi_value NapiCreateCertExtension(napi_env env, napi_callback_info info)
{
    ExtsAsyncContext context = NewExtsAsyncContext();
    if (context == nullptr) {
        CF_LOG_E("Failed to new create exts async context");
        return nullptr;
    }

    napi_value result = ParseCreateExtsJSParams(env, info, context);
    if (result == nullptr) {
        CF_LOG_E("Failed to parse JS params for create exts object");
        DeleteExtsAsyncContext(env, context);
        return nullptr;
    }

    result = CreateCertExtsAsyncWork(env, context);
    if (result == nullptr) {
        CF_LOG_E("Failed to create exts object in async work");
        DeleteExtsAsyncContext(env, context);
        return nullptr;
    }

    return result;
}

static napi_value NapiCommonOperation(napi_env env, napi_callback_info info, int32_t opType, int32_t typeValue)
{
    napi_value jsObject = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &jsObject, nullptr);

    NapiCertExtension *napiExtsObj = nullptr;
    napi_unwrap(env, jsObject, reinterpret_cast<void **>(&napiExtsObj));
    if (napiExtsObj == nullptr) {
        CF_LOG_E("napi extension objtect is nullptr!");
        return nullptr;
    }

    CfObject *extsObj = napiExtsObj->GetObject();
    if (extsObj == nullptr) {
        CF_LOG_E("cf objtect is nullptr!");
        return nullptr;
    }
    return CommonOperation(env, info, extsObj, opType, typeValue);
}

napi_value NapiGetExtensionEncoded(napi_env env, napi_callback_info info)
{
    return NapiCommonOperation(env, info, OPERATION_TYPE_GET, CF_GET_TYPE_EXT_ITEM);
}

static napi_value NapiGetExtensionOidList(napi_env env, napi_callback_info info)
{
    return NapiCommonOperation(env, info, OPERATION_TYPE_GET, CF_GET_TYPE_EXT_OIDS);
}

static napi_value NapiGetExtensionEntry(napi_env env, napi_callback_info info)
{
    return NapiCommonOperation(env, info, OPERATION_TYPE_GET, CF_GET_TYPE_EXT_ENTRY);
}

static napi_value NapiExtensionCheckCA(napi_env env, napi_callback_info info)
{
    return NapiCommonOperation(env, info, OPERATION_TYPE_CHECK, CF_CHECK_TYPE_EXT_CA);
}

static napi_value NapiExtensionHasUnsupportCritical(napi_env env, napi_callback_info info)
{
    return NapiCommonOperation(env, info, OPERATION_TYPE_CHECK, CF_CHECK_TYPE_EXT_HAS_UN_SUPPORT);
}

static napi_value CertExtsConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

void NapiCertExtension::DefineCertExtensionJsClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createCertExtension", NapiCreateCertExtension),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor CertExtensionDesc[] = {
        DECLARE_NAPI_FUNCTION("getEncoded", NapiGetExtensionEncoded),
        DECLARE_NAPI_FUNCTION("getOidList", NapiGetExtensionOidList),
        DECLARE_NAPI_FUNCTION("getEntry", NapiGetExtensionEntry),
        DECLARE_NAPI_FUNCTION("checkCA", NapiExtensionCheckCA),
        DECLARE_NAPI_FUNCTION("hasUnsupportedCriticalExtension", NapiExtensionHasUnsupportCritical),
    };

    napi_value constructor = nullptr;
    napi_define_class(
        env,
        "CertExtension",
        NAPI_AUTO_LENGTH,
        CertExtsConstructor,
        nullptr,
        sizeof(CertExtensionDesc) / sizeof(CertExtensionDesc[0]),
        CertExtensionDesc,
        &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // namespace CertFramework
} // namespace OHOS
