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

#include "napi_x509_cert_chain.h"

#include "cf_api.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_param.h"
#include "cf_result.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_common.h"
#include "napi_object.h"
#include "napi_x509_cert_chain_validate_params.h"
#include "napi_x509_cert_chain_validate_result.h"
#include "napi_x509_trust_anchor.h"
#include "napi_cert_crl_common.h"
#include "securec.h"
#include "x509_cert_chain_validate_params.h"
#include "x509_certificate.h"
#include "x509_cert_chain.h"
#include "cert_crl_common.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiX509CertChain::classRef_ = nullptr;

struct CfCtx {
    AsyncCtx async;
    NapiX509CertChain *certChainClass = nullptr;
    HcfCertChain *certChain = nullptr;
    CfEncodingBlob *encodingBlob = nullptr;
    HcfX509CertChainValidateParams params;
    HcfX509CertChainValidateResult result;
};

NapiX509CertChain::NapiX509CertChain(HcfCertChain *certChain)
{
    this->certChain_ = certChain;
}

NapiX509CertChain::~NapiX509CertChain()
{
    CfObjDestroy(this->certChain_);
}

static CfCtx *BuildCertChainContext()
{
    CfCtx *context = static_cast<CfCtx *>(HcfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->async = static_cast<AsyncCtx>(HcfMalloc(sizeof(AsyncContext), 0));
    if (context->async == nullptr) {
        LOGE("malloc context failed!");
        CfFree(context);
        return nullptr;
    }
    return context;
}

static void DeleteCertChainContext(napi_env env, CfCtx *&context, bool freeCertFlag = false)
{
    if (context == nullptr) {
        return;
    }

    FreeAsyncContext(env, context->async);

    if (context->encodingBlob != nullptr) {
        CfEncodingBlobDataFree(context->encodingBlob);
        CF_FREE_PTR(context->encodingBlob);
    }

    FreeX509CertChainValidateParams(context->params);
    FreeX509CertChainValidateResult(context->result, freeCertFlag);

    CF_FREE_PTR(context);
}

static napi_value CreateCertChainJSInstance(napi_env env)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    napi_get_reference_value(env, NapiX509CertChain::classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);
    return instance;
}

static bool CreateCallbackAndPromise(
    napi_env env, CfCtx *context, size_t argc, size_t maxCount, napi_value callbackValue)
{
    context->async->asyncType = GetAsyncType(env, argc, maxCount, callbackValue);
    if (context->async->asyncType == ASYNC_TYPE_CALLBACK) {
        if (!CertGetCallbackFromJSParams(env, callbackValue, &context->async->callback)) {
            LOGE("x509 certificate: get callback failed!");
            return false;
        }
    } else {
        napi_create_promise(env, &context->async->deferred, &context->async->promise);
    }
    return true;
}

static void CreateCertChainExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    context->async->errCode = HcfCertChainCreate(context->encodingBlob, nullptr, &context->certChain);
    if (context->async->errCode != CF_SUCCESS) {
        context->async->errMsg = "create cert chain failed";
    }
}

static napi_value BuildCreateInstance(napi_env env, HcfCertChain *certChain)
{
    napi_value instance = CreateCertChainJSInstance(env);
    NapiX509CertChain *napiObject = new (std::nothrow) NapiX509CertChain(certChain);
    if (napiObject == nullptr) {
        LOGE("new napi object failed.");
        return nullptr;
    }
    napi_wrap(
        env, instance, napiObject,
        [](napi_env env, void *data, void *hint) {
            NapiX509CertChain *certchain = static_cast<NapiX509CertChain *>(data);
            delete certchain;
            return;
        },
        nullptr, nullptr);
    return instance;
}

static void CreateCertChainComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->async->errCode != CF_SUCCESS) {
        ReturnJSResult(env, context->async, nullptr);
        DeleteCertChainContext(env, context, false);
        return;
    }

    napi_value instance = BuildCreateInstance(env, context->certChain);
    if (instance == nullptr) {
        context->async->errCode = CF_ERR_MALLOC;
        context->async->errMsg = "Failed to create napi cert chain class";
        LOGE("Failed to create napi cert chain class");
        CfObjDestroy(context->certChain);
        context->certChain = nullptr;
    }
    ReturnJSResult(env, context->async, instance);
    DeleteCertChainContext(env, context);
}

static napi_value CreateCertChainAsyncWork(napi_env env, CfCtx *context)
{
    napi_create_async_work(env, nullptr, GetResourceName(env, "createX509CertChain"), CreateCertChainExecute,
        CreateCertChainComplete, static_cast<void *>(context), &context->async->asyncWork);

    napi_queue_async_work(env, context->async->asyncWork);
    if (context->async->asyncType == ASYNC_TYPE_PROMISE) {
        return context->async->promise;
    } else {
        return NapiGetNull(env);
    }
}

static void ValidateExecute(napi_env env, void *data)
{
    LOGI("enter");
    CfCtx *context = static_cast<CfCtx *>(data);
    context->async->errCode = context->certChain->validate(context->certChain, &context->params, &context->result);
    if (context->async->errCode != CF_SUCCESS) {
        context->async->errMsg = "create cert chain failed";
    }
}

static void ValidateComplete(napi_env env, napi_status status, void *data)
{
    LOGI("enter");
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->async->errCode != CF_SUCCESS) {
        ReturnJSResult(env, context->async, nullptr);
        DeleteCertChainContext(env, context, false);
        return;
    }
    napi_value instance = BuildX509CertChainValidateResultJS(env, &context->result);
    if (instance == nullptr) {
        LOGE("validate ret failed");
        context->async->errCode = CF_ERR_MALLOC;
        context->async->errMsg = "build return obj failed!";
        ReturnJSResult(env, context->async, nullptr);
        DeleteCertChainContext(env, context, true);
        return;
    }

    ReturnJSResult(env, context->async, instance);
    DeleteCertChainContext(env, context);
}

static napi_value ValidateAsyncWork(napi_env env, CfCtx *context)
{
    napi_create_async_work(env, nullptr, GetResourceName(env, "Validate"), ValidateExecute, ValidateComplete,
        static_cast<void *>(context), &context->async->asyncWork);

    napi_queue_async_work(env, context->async->asyncWork);
    if (context->async->asyncType == ASYNC_TYPE_PROMISE) {
        return context->async->promise;
    } else {
        return NapiGetNull(env);
    }
}

napi_value NapiX509CertChain::Validate(napi_env env, napi_callback_info info)
{
    LOGI("enter");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "check args count failed!"));
        LOGE("check args count failed.");
        return nullptr;
    }

    CfCtx *context = BuildCertChainContext();
    if (context == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc context failed!"));
        LOGE("malloc context failed.");
        return nullptr;
    }

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, argv[PARAM1])) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "CreateCallbackAndPromise failed!"));
        DeleteCertChainContext(env, context);
        LOGE("CreateCallbackAndPromise failed!");
        return nullptr;
    }
    context->certChainClass = this;
    context->certChain = GetCertChain();
    if (!BuildX509CertChainValidateParams(env, argv[PARAM0], context->params)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "BuildX509CertChainValidateParams failed!"));
        LOGE("BuildX509CertChainValidateParams failed!");
        DeleteCertChainContext(env, context);
        return nullptr;
    }

    return ValidateAsyncWork(env, context);
}

static napi_value CreateX509CertChainByArray(napi_env env, napi_value param)
{
    HcfX509CertificateArray certs = { nullptr, 0 };
    if (param != nullptr && !GetArrayCertFromNapiValue(env, param, &certs, false)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get cert arr failed!"));
        LOGE("get array cert from data failed!");
        return nullptr;
    }

    HcfCertChain *certChain = nullptr;
    CfResult res = HcfCertChainCreate(nullptr, &certs, &certChain);
    if (res != CF_SUCCESS) {
        LOGE("HcfCertChainCreate failed!");
        napi_throw(env, CertGenerateBusinessError(env, res, "create cert chain by arr failed!"));
        CF_FREE_PTR(certs.data);
        return nullptr;
    }
    napi_value instance = BuildCreateInstance(env, certChain);
    if (instance == nullptr) {
        LOGE("HcfCertChainCreate failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "create instance failed!"));
        CfObjDestroy(certChain);
        CF_FREE_PTR(certs.data);
        return nullptr;
    }
    return instance;
}

static napi_value CreateX509CertChainByEncodingBlob(napi_env env, size_t argc, napi_value param1, napi_value param2)
{
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        LOGE("CertCheckArgsCount failed");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "CertCheckArgsCount failed!"));
        return nullptr;
    }
    CfCtx *context = BuildCertChainContext();
    if (context == nullptr) {
        LOGE("context is nullptr");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "context is nullptr!"));
        return nullptr;
    }

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, param2)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create Callback Promise failed!"));
        LOGE("Create Callback Promise failed");
        DeleteCertChainContext(env, context);
        return nullptr;
    }
    if (!GetEncodingBlobFromValue(env, param1, &context->encodingBlob)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Get Encoding Blob failed!"));
        LOGE("Get Encoding Blob failed");
        DeleteCertChainContext(env, context);
        return nullptr;
    }

    return CreateCertChainAsyncWork(env, context);
}

napi_value NapiCreateX509CertChain(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    bool flag = false;
    napi_is_array(env, argv[PARAM0], &flag);
    napi_value instance = nullptr;
    if (flag) {
        if (argc != ARGS_SIZE_ONE) {
            LOGE("arg size is not correct");
            napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "arg size is not correct!"));
            return nullptr;
        }
        LOGI("NapiCreateX509CertChain : Array<X509Cert>!");
        instance = CreateX509CertChainByArray(env, argv[PARAM0]);
    } else {
        LOGI("NapiCreateX509CertChain : inStream: EncodingBlob!");
        instance = CreateX509CertChainByEncodingBlob(env, argc, argv[PARAM0], argv[PARAM1]);
    }
    return instance;
}

napi_value NapiGetCertList(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CertChain *napiCertChainObj = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCertChainObj));
    if (napiCertChainObj == nullptr) {
        LOGE("napi cert chain object is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "napi cert chain object is nullptr!"));
        return nullptr;
    }
    HcfCertChain *certChain = napiCertChainObj->GetCertChain();
    HcfX509CertificateArray certs = { nullptr, 0 };
    CfResult res = certChain->getCertList(certChain, &certs);
    if (res != CF_SUCCESS) {
        LOGE("napi getCertList failed!");
        napi_throw(env, CertGenerateBusinessError(env, res, "get cert list failed!"));
        return nullptr;
    }
    napi_value instance = ConvertCertArrToNapiValue(env, &certs);
    if (instance == nullptr) {
        LOGE("convert arr to instance failed!");
        napi_throw(env, CertGenerateBusinessError(env, res, "convert arr to instance failed!"));
        FreeCertArrayData(&certs);
        return nullptr;
    }
    CF_FREE_PTR(certs.data);
    return instance;
}

napi_value NapiValidate(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CertChain *napiCertChainObj = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCertChainObj));
    if (napiCertChainObj == nullptr) {
        LOGE("napi cert chain object is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "napi cert chain object is nullptr!"));
        return nullptr;
    }
    return napiCertChainObj->Validate(env, info);
}

static napi_value CertChainConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

void NapiX509CertChain::DefineX509CertChainJsClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createX509CertChain", NapiCreateX509CertChain),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor CertChainDesc[] = {
        DECLARE_NAPI_FUNCTION("getCertList", NapiGetCertList),
        DECLARE_NAPI_FUNCTION("validate", NapiValidate),
    };

    napi_value constructor = nullptr;
    napi_define_class(env, "X509CertChain", NAPI_AUTO_LENGTH, CertChainConstructor, nullptr,
        sizeof(CertChainDesc) / sizeof(CertChainDesc[0]), CertChainDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // namespace CertFramework
} // namespace OHOS
