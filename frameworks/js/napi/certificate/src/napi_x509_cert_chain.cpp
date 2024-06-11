/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "cert_crl_common.h"
#include "cf_api.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_param.h"
#include "cf_result.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_cert_crl_common.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_common.h"
#include "napi_object.h"
#include "napi_x509_cert_chain_validate_params.h"
#include "napi_x509_cert_chain_validate_result.h"
#include "napi_x509_cert_match_parameters.h"
#include "napi_x509_trust_anchor.h"
#include "securec.h"
#include "x509_cert_chain.h"
#include "x509_cert_chain_validate_params.h"
#include "x509_certificate.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiX509CertChain::classRef_ = nullptr;
thread_local napi_ref NapiX509CertChainBulidResult::classRef_ = nullptr;

struct CfCtx {
    AsyncCtx async;
    napi_ref cfRef = nullptr;
    napi_ref certChainValidateParamsRef = nullptr;
    NapiX509CertChain *certChainClass = nullptr;
    HcfCertChain *certChain = nullptr;
    CfEncodingBlob *encodingBlob = nullptr;
    HcfX509CertChainValidateParams params;
    HcfX509CertChainValidateResult result;
    HcfX509CertChainBuildParameters *bulidParams = nullptr;
    HcfX509CertChainBuildResult *buildResult = nullptr;
    CfBlob *keyStore = nullptr;
    CfBlob *pwd = nullptr;
    HcfX509TrustAnchorArray *trustAnchorArray = nullptr;
};

NapiX509CertChain::NapiX509CertChain(HcfCertChain *certChain)
{
    this->certChain_ = certChain;
}

NapiX509CertChain::~NapiX509CertChain()
{
    CfObjDestroy(this->certChain_);
}

NapiX509CertChainBulidResult::NapiX509CertChainBulidResult(HcfX509CertChainBuildResult *buildResult)
{
    this->buildResult_ = buildResult;
}

NapiX509CertChainBulidResult::~NapiX509CertChainBulidResult()
{
    CfObjDestroy(this->buildResult_);
}

static CfCtx *BuildCertChainContext()
{
    CfCtx *context = static_cast<CfCtx *>(CfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->async = static_cast<AsyncCtx>(CfMalloc(sizeof(AsyncContext), 0));
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

    if (context->cfRef != nullptr) {
        napi_delete_reference(env, context->cfRef);
        context->cfRef = nullptr;
    }
    if (context->certChainValidateParamsRef != nullptr) {
        napi_delete_reference(env, context->certChainValidateParamsRef);
        context->certChainValidateParamsRef = nullptr;
    }

    if (context->encodingBlob != nullptr) {
        CfEncodingBlobDataFree(context->encodingBlob);
        CF_FREE_PTR(context->encodingBlob);
    }

    FreeTrustAnchorArray(context->trustAnchorArray, freeCertFlag);
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

static void BuildX509CertChainExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    context->async->errCode = HcfCertChainBuildResultCreate(context->bulidParams, &context->buildResult);
    if (context->async->errCode == CF_SUCCESS) {
        HcfCertChain *certChain = context->buildResult->certChain;
        context->async->errCode = certChain->validate(
            certChain, &(context->bulidParams->validateParameters), &(context->buildResult->validateResult));
    }

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

static napi_value BuildCreateInstanceByBulidRlt(napi_env env, CfCtx *ctx)
{
    napi_value returnValue = nullptr;
    napi_create_object(env, &returnValue);
    if (ctx->buildResult != nullptr) {
        napi_value insCertChain = BuildCreateInstance(env, ctx->buildResult->certChain);
        if (insCertChain == nullptr) {
            LOGE("Build cert chain instance failed!");
            return nullptr;
        }
        napi_set_named_property(env, returnValue, CERT_CHAIN_BUILD_RESULLT_TAG_CERTCHAIN.c_str(), insCertChain);

        napi_value insValitateRes = BuildX509CertChainValidateResultJS(env, &(ctx->buildResult->validateResult));
        if (insValitateRes == nullptr) {
            LOGE("Build cert validate result failed!");
            return nullptr;
        }
        napi_set_named_property(env, returnValue, CERT_CHAIN_BUILD_RESULLT_TAG_VALIDATERESULT.c_str(), insValitateRes);
    }

    return returnValue;
}

static void BuildX509CertChainComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->async->errCode != CF_SUCCESS) {
        ReturnJSResult(env, context->async, nullptr);
        DeleteCertChainContext(env, context, false);
        return;
    }

    napi_value instance = BuildCreateInstanceByBulidRlt(env, context);
    if (instance == nullptr) {
        context->async->errCode = CF_ERR_MALLOC;
        context->async->errMsg = "Failed to create napi cert chain class";
        LOGE("Failed to create napi cert chain class");
        CfObjDestroy(context->buildResult->certChain);
        context->certChain = nullptr;
        DeleteCertChainContext(env, context, true);
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

static napi_value CreateCertChainExtAsyncWork(napi_env env, CfCtx *context)
{
    napi_create_async_work(env, nullptr, GetResourceName(env, "buildX509CertChain"), BuildX509CertChainExecute,
        BuildX509CertChainComplete, static_cast<void *>(context), &context->async->asyncWork);

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
        LOGE("check args count failed.");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "check args count failed!"));
        return nullptr;
    }

    CfCtx *context = BuildCertChainContext();
    if (context == nullptr) {
        LOGE("malloc context failed.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc context failed!"));
        return nullptr;
    }

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, argv[PARAM1])) {
        DeleteCertChainContext(env, context);
        LOGE("CreateCallbackAndPromise failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "CreateCallbackAndPromise failed!"));
        return nullptr;
    }
    context->certChainClass = this;
    context->certChain = GetCertChain();
    if (!BuildX509CertChainValidateParams(env, argv[PARAM0], context->params)) {
        LOGE("BuildX509CertChainValidateParams failed!");
        DeleteCertChainContext(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "BuildX509CertChainValidateParams failed!"));
        return nullptr;
    }

    if (napi_create_reference(env, thisVar, 1, &context->cfRef) != napi_ok) {
        LOGE("create reference failed!");
        DeleteCertChainContext(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create reference failed!"));
        return nullptr;
    }
    if (napi_create_reference(env, argv[PARAM0], 1, &context->certChainValidateParamsRef) != napi_ok) {
        LOGE("create param ref failed!");
        DeleteCertChainContext(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "create param ref failed!"));
        return nullptr;
    }

    return ValidateAsyncWork(env, context);
}

napi_value NapiX509CertChain::ToString(napi_env env, napi_callback_info info)
{
    HcfCertChain *certChain = GetCertChain();
    CfBlob blob = { 0, nullptr };
    CfResult result = certChain->toString(certChain, &blob);
    if (result != CF_SUCCESS) {
        LOGE("toString failed!");
        napi_throw(env, CertGenerateBusinessError(env, result, "toString failed"));
        return nullptr;
    }

    napi_value returnBlob = nullptr;
    napi_create_string_utf8(env, reinterpret_cast<char *>(blob.data), blob.size, &returnBlob);
    CfBlobDataFree(&blob);
    return returnBlob;
}

napi_value NapiX509CertChain::HashCode(napi_env env, napi_callback_info info)
{
    HcfCertChain *certChain = GetCertChain();
    CfBlob blob = { 0, nullptr };
    CfResult result = certChain->hashCode(certChain, &blob);
    if (result != CF_SUCCESS) {
        LOGE("toString failed!");
        napi_throw(env, CertGenerateBusinessError(env, result, "toString failed"));
        return nullptr;
    }
    napi_value returnBlob = ConvertBlobToUint8ArrNapiValue(env, &blob);
    CfBlobDataFree(&blob);
    return returnBlob;
}

static napi_value CreateX509CertChainByArray(napi_env env, napi_value param)
{
    HcfX509CertificateArray certs = { nullptr, 0 };
    if (param != nullptr && !GetArrayCertFromNapiValue(env, param, &certs, false)) {
        LOGE("get array cert from data failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get cert arr failed!"));
        return nullptr;
    }

    HcfCertChain *certChain = nullptr;
    CfResult res = HcfCertChainCreate(nullptr, &certs, &certChain);
    if (res != CF_SUCCESS) {
        LOGE("HcfCertChainCreate failed!");
        CF_FREE_PTR(certs.data);
        napi_throw(env, CertGenerateBusinessError(env, res, "create cert chain by arr failed!"));
        return nullptr;
    }
    napi_value instance = BuildCreateInstance(env, certChain);
    if (instance == nullptr) {
        LOGE("HcfCertChainCreate failed!");
        CfObjDestroy(certChain);
        CF_FREE_PTR(certs.data);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "create instance failed!"));
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
        LOGE("Create Callback Promise failed");
        DeleteCertChainContext(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create Callback Promise failed!"));
        return nullptr;
    }
    if (!GetEncodingBlobFromValue(env, param1, &context->encodingBlob)) {
        LOGE("Get Encoding Blob failed");
        DeleteCertChainContext(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Get Encoding Blob failed!"));
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

static void CreateTrustAnchorsWithKeyStoreExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context == nullptr) {
        LOGE("context is nullptr");
        return;
    }
    context->async->errCode =
        HcfCreateTrustAnchorWithKeyStore(context->keyStore, context->pwd, &context->trustAnchorArray);
    if (context->async->errCode != CF_SUCCESS) {
        context->async->errMsg = "Failed to create trust anchor from p12!";
    }
}

static napi_value ConvertX509CertToNapiValue(napi_env env, HcfX509Certificate *cert)
{
    if (cert == nullptr) {
        LOGE("ConvertX509CertToNapiValue:cert is nullptr.");
        return nullptr;
    }
    CfObject *certObj = nullptr;
    CfResult res = GetCertObject(cert, &certObj);
    if (res != CF_SUCCESS) {
        LOGE("GetCertObject failed.");
        return nullptr;
    }
    NapiX509Certificate *x509Cert = new (std::nothrow) NapiX509Certificate(cert, certObj);
    if (x509Cert == nullptr) {
        LOGE("new x509Cert failed!");
        certObj->destroy(&certObj);
        return nullptr;
    }
    napi_value instance = NapiX509Certificate::CreateX509Cert(env);
    napi_status status = napi_wrap(
        env, instance, x509Cert,
        [](napi_env env, void *data, void *hint) {
            NapiX509Certificate *certClass = static_cast<NapiX509Certificate *>(data);
            delete certClass;
            return;
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        LOGE("Failed to wrap x509Cert obj!");
        delete x509Cert;
        return nullptr;
    }

    return instance;
}

static napi_value ConvertCfBlobToNapiValue(napi_env env, CfBlob *blob)
{
    if (blob == NULL) {
        LOGE("ConvertCfBlobToNapiValue:blob is nullptr.");
        return nullptr;
    }
    uint8_t *buffer = static_cast<uint8_t *>(CfMalloc(blob->size, 0));
    if (buffer == nullptr) {
        LOGE("malloc uint8 array buffer failed!");
        return nullptr;
    }

    if (memcpy_s(buffer, blob->size, blob->data, blob->size) != EOK) {
        LOGE("memcpy_s data to buffer failed!");
        CfFree(buffer);
        return nullptr;
    }

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, blob->size, [](napi_env env, void *data, void *hint) { CfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        LOGE("create uint8 array buffer failed!");
        CfFree(buffer);
        return nullptr;
    }
    buffer = nullptr;
    return outBuffer;
}

static napi_value BuildCreateInstanceByTrustAnchorArray(napi_env env, HcfX509TrustAnchorArray *trustAnchorArray)
{
    if (trustAnchorArray == nullptr) {
        LOGE("Input data is null!");
        return nullptr;
    }
    napi_value instance;
    napi_create_array(env, &instance);
    if (instance == nullptr) {
        LOGE("Create return instance failed!");
        return nullptr;
    }
    int elementIdx = 0;
    for (uint32_t i = 0; i < trustAnchorArray->count; ++i) {
        napi_value element = NapiX509Certificate::CreateX509Cert(env);
        napi_value valueCACert = ConvertX509CertToNapiValue(env, trustAnchorArray->data[i]->CACert);
        if (valueCACert == nullptr) {
            LOGI("The CACert value is null, return to js is an enpty object!");
        }
        napi_set_named_property(env, element, CERT_CHAIN_TRUSTANCHOR_TAG_CACERT.c_str(), valueCACert);

        napi_value valuePubKey = ConvertCfBlobToNapiValue(env, trustAnchorArray->data[i]->CAPubKey);
        if (valuePubKey == nullptr) {
            LOGI("The PubKey value is null, return to js is an enpty object!");
        }
        napi_set_named_property(env, element, CERT_CHAIN_TRUSTANCHOR_TAG_CAPUBKEY.c_str(), valuePubKey);

        napi_value valueSub = ConvertCfBlobToNapiValue(env, trustAnchorArray->data[i]->CASubject);
        if (valueSub == nullptr) {
            LOGI("The CASubject value is null, return to js is an enpty object!");
        }
        napi_set_named_property(env, element, CERT_CHAIN_TRUSTANCHOR_TAG_CASUBJECT.c_str(), valueSub);

        napi_value valueName = ConvertCfBlobToNapiValue(env, trustAnchorArray->data[i]->nameConstraints);
        if (valueName == nullptr) {
            LOGI("The nameConsteaints value is null, return to js is an enpty object!");
        }
        napi_set_named_property(env, element, CERT_MATCH_TAG_NAME_CONSTRAINTS.c_str(), valueName);

        if (element != nullptr) {
            napi_set_element(env, instance, elementIdx++, element);
        }
    }
    return instance;
}

static void CreateTrustAnchorsWithKeyStoreComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->async->errCode != CF_SUCCESS) {
        ReturnJSResult(env, context->async, nullptr);
        DeleteCertChainContext(env, context, false);
        return;
    }
    napi_value instance = BuildCreateInstanceByTrustAnchorArray(env, context->trustAnchorArray);
    if (instance == nullptr) {
        context->async->errCode = CF_ERR_MALLOC;
        context->async->errMsg = "Failed to create trust anchor with KeyStore";
        LOGE("Failed to create trust anchor with KeyStore");
    }
    ReturnJSResult(env, context->async, instance);
    DeleteCertChainContext(env, context);
}

static napi_value CreateTrustAnchorsWithKeyStoreAsyncWork(napi_env env, CfCtx *context)
{
    napi_create_async_work(env, nullptr, GetResourceName(env, "createTrustAnchorsWithKeyStore"),
        CreateTrustAnchorsWithKeyStoreExecute, CreateTrustAnchorsWithKeyStoreComplete, static_cast<void *>(context),
        &context->async->asyncWork);

    napi_queue_async_work(env, context->async->asyncWork);
    if (context->async->asyncType == ASYNC_TYPE_PROMISE) {
        return context->async->promise;
    } else {
        return NapiGetNull(env);
    }
}

static napi_value CreateTrustAnchorsWithKeyStore(napi_env env, size_t argc, napi_value param1, napi_value param2)
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

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, nullptr)) {
        LOGE("CreateCallbackAndPromise failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "CreateCallbackAndPromise failed!"));
        return nullptr;
    }
    context->keyStore = CertGetBlobFromUint8ArrJSParams(env, param1);
    if (context->keyStore == nullptr) {
        return nullptr;
    }
    context->pwd = CertGetBlobFromStringJSParams(env, param2);
    if (context->pwd == nullptr) {
        return nullptr;
    }

    return CreateTrustAnchorsWithKeyStoreAsyncWork(env, context);
}

napi_value NapiCreateTrustAnchorsWithKeyStore(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    napi_value instance = CreateTrustAnchorsWithKeyStore(env, argc, argv[PARAM0], argv[PARAM1]);
    return instance;
}

bool GetCertMatchParameters(napi_env env, napi_value obj, HcfX509CertChainBuildParameters **bulidParams)
{
    napi_value data = nullptr;
    napi_status status = napi_get_named_property(env, obj, CERT_TAG_CERT_MATCH_PARAMS.c_str(), &data);
    if (status != napi_ok) {
        LOGE("failed to get cert match params!");
        return false;
    }
    HcfX509CertMatchParams *param = &((*bulidParams)->certMatchParameters);
    if (!BuildX509CertMatchParams(env, data, param)) {
        LOGE("BuildX509CertMatchParams failed!");
        return false;
    }
    return true;
}

bool GetMaxlength(napi_env env, napi_value obj, HcfX509CertChainBuildParameters **bulidParams)
{
    napi_value data = nullptr;
    napi_status status = napi_get_named_property(env, obj, CERT_TAG_MAX_LENGTH.c_str(), &data);
    if (status != napi_ok) {
        LOGE("failed to get max length!");
        return false;
    }
    napi_valuetype valueType;
    napi_typeof(env, data, &valueType);
    if ((valueType != napi_number) && (valueType != napi_undefined) && (valueType != napi_null)) {
        LOGE("%s valueType is null or undefined.", CERT_TAG_MAX_LENGTH.c_str());
        return false;
    }
    napi_get_value_uint32(env, data, reinterpret_cast<uint32_t *>(&((*bulidParams)->maxlength)));
    return true;
}

bool GetValidateParameters(napi_env env, napi_value obj, HcfX509CertChainBuildParameters **bulidParams)
{
    napi_value data = nullptr;
    napi_status status = napi_get_named_property(env, obj, CERT_TAG_VALIDATE_PARAMS.c_str(), &data);
    if (status != napi_ok) {
        LOGE("failed to get cert validate params!");
        return false;
    }
    if (!BuildX509CertChainValidateParams(env, data, (*bulidParams)->validateParameters)) {
        LOGE("BuildX509CertChainValidateParams failed!");
        return false;
    }
    return true;
}

bool GetChainBuildParametersFromValue(napi_env env, napi_value obj, HcfX509CertChainBuildParameters **bulidParams)
{
    HcfX509CertChainBuildParameters *buildParam =
        static_cast<HcfX509CertChainBuildParameters *>(CfMalloc(sizeof(HcfX509CertChainBuildParameters), 0));
    if (buildParam == nullptr) {
        LOGE("malloc cert chain build parameters failed!");
        return false;
    }
    buildParam->maxlength = -1;

    if (!GetCertMatchParameters(env, obj, &buildParam)) {
        LOGE("failed to get cert match parameters!");
        CfFree(buildParam);
        return false;
    }
    if (!GetMaxlength(env, obj, &buildParam)) {
        LOGE("failed to get max length!");
        CfFree(buildParam);
        return false;
    }
    if (!GetValidateParameters(env, obj, &buildParam)) {
        LOGE("failed to get validate parameters!");
        CfFree(buildParam);
        return false;
    }

    *bulidParams = buildParam;
    return true;
}

static napi_value CreateX509CertChainExtReturn(napi_env env, size_t argc, napi_value param)
{
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, false)) {
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

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_ONE, nullptr)) {
        LOGE("Create Callback Promise failed");
        DeleteCertChainContext(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create Callback Promise failed!"));
        return nullptr;
    }
    if (napi_create_reference(env, param, 1, &context->async->paramRef) != napi_ok) {
        LOGE("create param ref failed!");
        DeleteCertChainContext(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create param ref failed"));
        return nullptr;
    }
    if (!GetChainBuildParametersFromValue(env, param, &context->bulidParams)) {
        LOGE("Get Cert Chain Build Parameters failed!");
        DeleteCertChainContext(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Get Cert Chain Build Parameters failed!"));
        return nullptr;
    }

    return CreateCertChainExtAsyncWork(env, context);
}

napi_value NapiBuildX509CertChain(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    napi_value instance = nullptr;
    instance = CreateX509CertChainExtReturn(env, argc, argv[PARAM0]);
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
        FreeCertArrayData(&certs);
        napi_throw(env, CertGenerateBusinessError(env, res, "convert arr to instance failed!"));
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

napi_value NapiToString(napi_env env, napi_callback_info info)
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
    return napiCertChainObj->ToString(env, info);
}

napi_value NapiHashCode(napi_env env, napi_callback_info info)
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
    return napiCertChainObj->HashCode(env, info);
}

static napi_value CertChainConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiX509CertChain::Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiX509CertChain::ConvertToJsCertChain(napi_env env)
{
    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);

    return instance;
}

napi_value NapiX509CertChainBulidResult::Constructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiX509CertChainBulidResult::ConvertToJsBuildResult(napi_env env)
{
    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);

    if (this->buildResult_ != nullptr && this->buildResult_->certChain != nullptr) {
        NapiX509CertChain *napiObject = new (std::nothrow) NapiX509CertChain(this->buildResult_->certChain);
        if (napiObject == nullptr) {
            LOGE("new napi object failed.");
            return nullptr;
        }
        napi_value certChain = napiObject->ConvertToJsCertChain(env);
        napi_status status = napi_wrap(
            env, certChain, napiObject,
            [](napi_env env, void *data, void *hint) {
                NapiX509CertChain *napiObject = static_cast<NapiX509CertChain *>(data);
                delete napiObject;
                return;
            },
            nullptr, nullptr);
        if (status != napi_ok) {
            LOGE("failed to wrap certChain obj!");
            delete napiObject;
            return nullptr;
        }
        napi_set_named_property(env, instance, "certChain", certChain);
    }

    if (this->buildResult_ != nullptr) {
        napi_value validateResult = BuildX509CertChainValidateResultJS(env, &(this->buildResult_->validateResult));
        napi_set_named_property(env, instance, "validateResult", validateResult);
    }
    return instance;
}

void NapiX509CertChain::DefineX509CertChainJsClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createX509CertChain", NapiCreateX509CertChain),
        DECLARE_NAPI_FUNCTION("createTrustAnchorsWithKeyStore", NapiCreateTrustAnchorsWithKeyStore),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor CertChainDesc[] = {
        DECLARE_NAPI_FUNCTION("getCertList", NapiGetCertList),
        DECLARE_NAPI_FUNCTION("validate", NapiValidate),
        DECLARE_NAPI_FUNCTION("toString", NapiToString),
        DECLARE_NAPI_FUNCTION("hashCode", NapiHashCode),
    };

    napi_value constructor = nullptr;
    napi_define_class(env, "X509CertChain", NAPI_AUTO_LENGTH, CertChainConstructor, nullptr,
        sizeof(CertChainDesc) / sizeof(CertChainDesc[0]), CertChainDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}

void NapiX509CertChainBulidResult::DefineX509CertChainBuildResultJsClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = { DECLARE_NAPI_FUNCTION("buildX509CertChain", NapiBuildX509CertChain) };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor CertChainBuildResultDesc[] = {};
    napi_value constructor = nullptr;
    napi_define_class(env, "CertChainBuildResult", NAPI_AUTO_LENGTH, NapiX509CertChainBulidResult::Constructor, nullptr,
        sizeof(CertChainBuildResultDesc) / sizeof(CertChainBuildResultDesc[0]), CertChainBuildResultDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // namespace CertFramework
} // namespace OHOS
