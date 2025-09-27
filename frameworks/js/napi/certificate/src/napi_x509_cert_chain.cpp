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
#include "cf_blob.h"
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

#define CERT_PKCS12_DEFAULT_SALT_LEN 16
#define CERT_PKCS12_DEFAULT_ITERATION 2048

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiX509CertChain::classRef_ = nullptr;
thread_local napi_ref NapiX509CertChainBulidResult::classRef_ = nullptr;

struct ParsePkcs12Ctx {
    napi_env env = nullptr;

    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref cfRef = nullptr;

    CfBlob *keyStore = nullptr;
    HcfParsePKCS12Conf *conf = nullptr;

    CfResult errCode = CF_SUCCESS;
    const char *errMsg = nullptr;
    HcfX509P12Collection *p12Collection = nullptr;
};

struct CreatePkcs12Ctx {
    napi_env env = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref cfRef = nullptr;

    HcfX509P12Collection *p12Collection = nullptr;
    HcfPkcs12CreatingConfig *conf = nullptr;

    CfResult errCode = CF_SUCCESS;
    const char *errMsg = nullptr;
    CfBlob outBlob = { 0, nullptr };
};

struct CfCtx {
    AsyncCtx async;
    napi_ref cfRef = nullptr;
    napi_ref certChainValidateParamsRef = nullptr;
    NapiX509CertChain *certChainClass = nullptr;
    HcfCertChain *certChain = nullptr;
    CfEncodingBlob *encodingBlob = nullptr;
    HcfX509CertChainValidateParams params;
    HcfX509CertChainValidateResult result;
    HcfX509CertChainBuildParameters *buildParams = nullptr;
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
        LOGE("malloc cf ctx failed!");
        return nullptr;
    }
    context->async = static_cast<AsyncCtx>(CfMalloc(sizeof(AsyncContext), 0));
    if (context->async == nullptr) {
        LOGE("malloc async ctx failed!");
        CfFree(context);
        context = nullptr;
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

    CfBlobFree(&(context->keyStore));
    CfBlobDataClearAndFree(context->pwd);
    CfFree(context->pwd);
    context->pwd = nullptr;

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
    context->async->errCode = HcfCertChainBuildResultCreate(context->buildParams, &context->buildResult);
    if (context->async->errCode != CF_SUCCESS) {
        context->async->errMsg = "create cert chain failed";
        return;
    }
    HcfCertChain *certChain = context->buildResult->certChain;
    context->async->errCode = certChain->validate(
        certChain, &(context->buildParams->validateParameters), &(context->buildResult->validateResult));
    if (context->async->errCode != CF_SUCCESS) {
        context->async->errMsg = "validate failed";
        CfObjDestroy(context->buildResult->certChain);
        context->buildResult->certChain = nullptr;
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
    napi_status status = napi_wrap(
        env, instance, napiObject,
        [](napi_env env, void *data, void *hint) {
            NapiX509CertChain *certchain = static_cast<NapiX509CertChain *>(data);
            delete certchain;
            return;
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "failed to wrap obj!"));
        LOGE("failed to wrap obj!");
        delete napiObject;
        return nullptr;
    }
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
        napi_set_named_property(env, returnValue, CERT_CHAIN_BUILD_RESULT_TAG_CERTCHAIN.c_str(), insCertChain);

        napi_value insValitateRes = BuildX509CertChainValidateResultJS(env, &(ctx->buildResult->validateResult));
        if (insValitateRes == nullptr) {
            LOGE("Build cert validate result failed!");
            return nullptr;
        }
        napi_set_named_property(env, returnValue, CERT_CHAIN_BUILD_RESULT_TAG_VALIDATERESULT.c_str(), insValitateRes);
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
    CfCtx *context = static_cast<CfCtx *>(data);
    context->async->errCode = context->certChain->validate(context->certChain, &context->params, &context->result);
    if (context->async->errCode != CF_SUCCESS) {
        context->async->errMsg = "validate cert chain failed.";
    }
}

static void ValidateComplete(napi_env env, napi_status status, void *data)
{
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
        LOGE("hashCode failed!");
        napi_throw(env, CertGenerateBusinessError(env, result, "hashCode failed"));
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
        LOGE("BuildCreateInstance failed!");
        CfObjDestroy(certChain);
        CF_FREE_PTR(certs.data);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "build create instance failed!"));
        return nullptr;
    }
    CF_FREE_PTR(certs.data);
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
        certObj = nullptr;
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

static napi_value ConvertBlobToUint8ArrayNapiValue(napi_env env, CfBlob *blob)
{
    if (blob == nullptr) {
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
        buffer = nullptr;
        return nullptr;
    }

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, blob->size, [](napi_env env, void *data, void *hint) { CfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        LOGE("create uint8 array buffer failed!");
        CfFree(buffer);
        buffer = nullptr;
        return nullptr;
    }
    buffer = nullptr;

    napi_value outData = nullptr;
    napi_create_typedarray(env, napi_uint8_array, blob->size, outBuffer, 0, &outData);
    return outData;
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
        if (element == nullptr) {
            LOGE("Create x509Cert failed!");
            return nullptr;
        }
        napi_value valueCACert = ConvertX509CertToNapiValue(env, trustAnchorArray->data[i]->CACert);
        if (valueCACert == nullptr) {
            LOGI("The CACert value is null, return to js is an enpty object!");
        } else {
            trustAnchorArray->data[i]->CACert = nullptr;
        }
        napi_set_named_property(env, element, CERT_CHAIN_TRUSTANCHOR_TAG_CACERT.c_str(), valueCACert);

        napi_value valuePubKey = ConvertBlobToUint8ArrayNapiValue(env, trustAnchorArray->data[i]->CAPubKey);
        if (valuePubKey == nullptr) {
            LOGI("The PubKey value is null, return to js is an enpty object!");
        }
        napi_set_named_property(env, element, CERT_CHAIN_TRUSTANCHOR_TAG_CAPUBKEY.c_str(), valuePubKey);

        napi_value valueSub = ConvertBlobToUint8ArrayNapiValue(env, trustAnchorArray->data[i]->CASubject);
        if (valueSub == nullptr) {
            LOGI("The CASubject value is null, return to js is an enpty object!");
        }
        napi_set_named_property(env, element, CERT_CHAIN_TRUSTANCHOR_TAG_CASUBJECT.c_str(), valueSub);

        napi_value valueName = ConvertBlobToUint8ArrayNapiValue(env, trustAnchorArray->data[i]->nameConstraints);
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
    DeleteCertChainContext(env, context, true);
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

    context->async->asyncType = GetAsyncType(env, argc, ARGS_SIZE_TWO, nullptr);
    if (context->async->asyncType == ASYNC_TYPE_CALLBACK) {
        LOGE("ASYNC_TYPE_CALLBACK is not supported.");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "ASYNC_TYPE_CALLBACK is not supported."));
        DeleteCertChainContext(env, context);
        return nullptr;
    }
    napi_create_promise(env, &context->async->deferred, &context->async->promise);

    context->keyStore = CertGetBlobFromUint8ArrJSParams(env, param1);
    if (context->keyStore == nullptr) {
        DeleteCertChainContext(env, context);
        return nullptr;
    }
    context->pwd = CertGetBlobFromStringJSParams(env, param2);
    if (context->pwd == nullptr) {
        DeleteCertChainContext(env, context);
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

static bool GetP12ConfFromValue(napi_env env, napi_value arg, HcfParsePKCS12Conf *conf)
{
    conf->isPem = true;
    conf->isGetPriKey = true;
    conf->isGetCert = true;
    conf->isGetOtherCerts = false;

    if (!GetIsPemFromStringNapiValue(env, arg, conf->isPem, CERT_CHAIN_PKCS12_TAG_PRIKEY_FORMAT.c_str())) {
        return false;
    }
    if (!GetBoolFromNapiValue(env, arg, conf->isGetPriKey, CERT_CHAIN_PKCS12_TAG_NEEDS_PRIVATE_KEY.c_str())) {
        return false;
    }
    if (!GetBoolFromNapiValue(env, arg, conf->isGetCert, CERT_CHAIN_PKCS12_TAG_NEEDS_CERT.c_str())) {
        return false;
    }
    if (!GetBoolFromNapiValue(env, arg, conf->isGetOtherCerts, CERT_CHAIN_PKCS12_TAG_NEEDS_OTHER_CERTS.c_str())) {
        return false;
    }

    napi_value obj = GetProp(env, arg, CERT_CHAIN_PKCS12_TAG_PASSWORD.c_str());
    if (obj == nullptr) {
        LOGE("Failed to get p12 conf!");
        return false;
    }

    conf->pwd = CertGetBlobFromStringJSParams(env, obj);
    if (conf->pwd == nullptr) {
        LOGE("Out is nullptr");
        return false;
    }

    return true;
}

static void FreeP12CollectionCommon(HcfX509P12Collection *collection)
{
    if (collection == nullptr) {
        return;
    }
    if (collection->prikey != nullptr) {
        CfFree(collection->prikey->data);
        collection->prikey->data = nullptr;
        CfFree(collection->prikey);
        collection->prikey = nullptr;
    }
}

static void FreeP12Collection(HcfX509P12Collection *collection)
{
    FreeP12CollectionCommon(collection);
    if (collection->otherCerts != nullptr && collection->otherCertsCount != 0) {
        for (uint32_t i = 0; i < collection->otherCertsCount; i++) {
            if (collection->otherCerts[i] != nullptr) {
                CfFree(collection->otherCerts[i]);
                collection->otherCerts[i] = nullptr;
            }
        }
        CfFree(collection->otherCerts);
        collection->otherCerts = nullptr;
    }

    if (collection->cert != nullptr) {
        CfFree(collection->cert);
        collection->cert = nullptr;
    }
    CfFree(collection);
}

static void FreeCreateP12Collection(HcfX509P12Collection *collection)
{
    FreeP12CollectionCommon(collection);
    if (collection->otherCerts != nullptr) {
        CfFree(collection->otherCerts);
        collection->otherCerts = nullptr;
    }
    CF_FREE_PTR(collection);
}

static void FreeHcfParsePKCS12Conf(HcfParsePKCS12Conf *conf)
{
    if (conf == nullptr) {
        return;
    }
    CfBlobClearAndFree(&conf->pwd);
    CfFree(conf);
}

static void FreeHcfPkcs12CreateConf(HcfPkcs12CreatingConfig *conf)
{
    if (conf == nullptr) {
        return;
    }
    CfBlobDataClearAndFree(conf->pwd);
    conf->pwd = nullptr;
    CF_FREE_PTR(conf);
}

static napi_value ConvertBlobToStringNapiValue(napi_env env, CfBlob *blob)
{
    uint32_t len = blob->size;
    char *returnString = static_cast<char *>(CfMalloc(len, 0));
    if (returnString == nullptr) {
        LOGE("Failed to malloc return string.");
        return nullptr;
    }

    (void)memcpy_s(returnString, len, blob->data, len);
    napi_value instance = nullptr;
    napi_create_string_utf8(env, returnString, len, &instance);
    CfFree(returnString);
    returnString = nullptr;
    return instance;
}

static napi_value ConvertPkeyToInstance(napi_env env, HcfX509P12Collection *p12Collection)
{
    if (p12Collection->isPem) {
        return ConvertBlobToStringNapiValue(env, p12Collection->prikey);
    }

    return ConvertBlobToUint8ArrayNapiValue(env, p12Collection->prikey);
}

static napi_value BuildCreateInstanceByP12Collection(napi_env env, HcfX509P12Collection *p12Collection)
{
    napi_value instance;
    napi_create_array(env, &instance);

    if (instance == nullptr) {
        LOGE("Create return instance failed!");
        return nullptr;
    }

    if (p12Collection->cert != nullptr) {
        napi_value certInstance = ConvertCertToNapiValue(env, p12Collection->cert);
        if (certInstance == nullptr) {
            LOGE("certInstance is nullptr");
            return nullptr;
        }
        napi_set_named_property(env, instance, CERT_CHAIN_PKCS12_TAG_CERT.c_str(), certInstance);
    }

    if (p12Collection->prikey != nullptr) {
        napi_value pkeyInstance = ConvertPkeyToInstance(env, p12Collection);
        if (pkeyInstance == nullptr) {
            LOGE("pkeyInstance is nullptr");
            return nullptr;
        }
        napi_set_named_property(env, instance, CERT_CHAIN_PKCS12_TAG_PRIKEY.c_str(), pkeyInstance);
    }

    if (p12Collection->otherCerts == nullptr || p12Collection->otherCertsCount <= 0) {
        return instance;
    }

    HcfX509CertificateArray certs = { p12Collection->otherCerts, p12Collection->otherCertsCount };
    napi_value otherCertsInstance = ConvertCertArrToNapiValue(env, &certs);
    if (otherCertsInstance == nullptr) {
        LOGE("convert other certs to instance failed!");
        return nullptr;
    }
    napi_set_named_property(env, instance, CERT_CHAIN_PKCS12_TAG_OTHER_CERTS.c_str(), otherCertsInstance);

    return instance;
}

static napi_value ParsePKCS12WithKeyStore(napi_env env, size_t argc, napi_value param0, napi_value param1)
{
    CfBlob *keyStore = CertGetBlobFromUint8ArrJSParams(env, param0);
    if (keyStore == nullptr) {
        LOGE("Failed to get pkcs12!");
        return nullptr;
    }
    HcfParsePKCS12Conf *conf = static_cast<HcfParsePKCS12Conf *>(CfMalloc(sizeof(HcfParsePKCS12Conf), 0));
    if (conf == nullptr) {
        CfBlobFree(&keyStore);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to malloc conf"));
        LOGE("Failed to malloc conf!");
        return nullptr;
    };

    if (!GetP12ConfFromValue(env, param1, conf)) {
        CfBlobFree(&keyStore);
        FreeHcfParsePKCS12Conf(conf);
        conf = nullptr;
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Failed to get conf"));
        LOGE("Failed to get conf!");
        return nullptr;
    }

    HcfX509P12Collection *p12Collection = nullptr;
    CfResult ret = HcfParsePKCS12(keyStore, conf, &p12Collection);
    if (ret != CF_SUCCESS) {
        CfBlobFree(&keyStore);
        FreeHcfParsePKCS12Conf(conf);
        conf = nullptr;
        napi_throw(env, CertGenerateBusinessError(env, ret, "Failed to parse pkcs12"));
        LOGE("Failed to parse pkcs12!");
        return nullptr;
    }

    napi_value instance = BuildCreateInstanceByP12Collection(env, p12Collection);
    if (instance == nullptr) {
        CfBlobFree(&keyStore);
        FreeHcfParsePKCS12Conf(conf);
        conf = nullptr;
        FreeP12Collection(p12Collection);
        p12Collection = nullptr;
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to build instance"));
        LOGE("Failed to build instance!");
        return nullptr;
    }
    CfBlobFree(&keyStore);
    FreeHcfParsePKCS12Conf(conf);
    conf = nullptr;
    CfBlobFree(&p12Collection->prikey);
    CfFree(p12Collection);
    p12Collection = nullptr;
    return instance;
}

static void FreeParsePkcs12CtxCommon(napi_env env, ParsePkcs12Ctx *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }
    if (ctx->cfRef != nullptr) {
        napi_delete_reference(env, ctx->cfRef);
        ctx->cfRef = nullptr;
    }
    if (ctx->keyStore != nullptr) {
        CfBlobFree(&ctx->keyStore);
        ctx->keyStore = nullptr;
    }
    if (ctx->conf != nullptr) {
        FreeHcfParsePKCS12Conf(ctx->conf);
        ctx->conf = nullptr;
    }
}

static void FreeParsePkcs12Ctx(napi_env env, ParsePkcs12Ctx *ctx)
{
    FreeParsePkcs12CtxCommon(env, ctx);
    if (ctx->p12Collection != nullptr) {
        FreeP12Collection(ctx->p12Collection);
        ctx->p12Collection = nullptr;
    }
    CfFree(ctx);
}

static void FreePkcs12Ctx(napi_env env, ParsePkcs12Ctx *ctx)
{
    FreeParsePkcs12CtxCommon(env, ctx);
    if (ctx->p12Collection != nullptr) {
        FreeCreateP12Collection(ctx->p12Collection);
    }
    CfFree(ctx);
}

static void ParsePkcs12Execute(napi_env env, void *data)
{
    ParsePkcs12Ctx *ctx = static_cast<ParsePkcs12Ctx *>(data);
    ctx->errCode = HcfParsePKCS12(ctx->keyStore, ctx->conf, &ctx->p12Collection);
    if (ctx->errCode != CF_SUCCESS) {
        if (ctx->errCode == CF_INVALID_PARAMS) {
            ctx->errCode = CF_ERR_PARAMETER_CHECK;
        }
        LOGE("HcfParsePKCS12 failed.");
        ctx->errMsg = "HcfParsePKCS12 failed.";
        return;
    }
}

static void ReturnParsePkcs12Promise(napi_env env, ParsePkcs12Ctx *ctx, napi_value result)
{
    if (ctx->errCode == CF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            CertGenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void ParsePkcs12Complete(napi_env env, napi_status status, void *data)
{
    ParsePkcs12Ctx *ctx = static_cast<ParsePkcs12Ctx *>(data);
    if (ctx->errCode != CF_SUCCESS) {
        ReturnParsePkcs12Promise(env, ctx, nullptr);
        FreeParsePkcs12Ctx(env, ctx);
        return;
    }
    napi_value instance = BuildCreateInstanceByP12Collection(env, ctx->p12Collection);
    if (instance == nullptr) {
        LOGE("Failed to build instance from p12 collection.");
        ctx->errCode = CF_ERR_MALLOC;
        ctx->errMsg = "Failed to build instance from p12 collection.";
        ReturnParsePkcs12Promise(env, ctx, nullptr);
        FreeParsePkcs12Ctx(env, ctx);
        return;
    }
    ReturnParsePkcs12Promise(env, ctx, instance);
    FreePkcs12Ctx(env, ctx);
}

static napi_value ParsePkcs12AsyncWork(napi_env env, napi_value thisVar, ParsePkcs12Ctx *context)
{
    if (napi_create_reference(env, thisVar, 1, &context->cfRef) != napi_ok) {
        LOGE("create reference failed!");
        FreeParsePkcs12Ctx(env, context);
        context = nullptr;
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "Create reference failed!"));
        return nullptr;
    }

    if (napi_create_promise(env, &context->deferred, &context->promise) != napi_ok) {
        LOGE("create promise failed!");
        FreeParsePkcs12Ctx(env, context);
        context = nullptr;
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "Create promise failed!"));
        return nullptr;
    }
    napi_create_async_work(
        env, nullptr, CertGetResourceName(env, "parsePkcs12"),
        ParsePkcs12Execute,
        ParsePkcs12Complete,
        static_cast<void *>(context),
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        LOGE("napi_queue_async_work failed!");
        FreeParsePkcs12Ctx(env, context);
        context = nullptr;
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "napi_queue_async_work failed!"));
        return nullptr;
    }
    return context->promise;
}

static napi_value NapiParsePKCS12Async(napi_env env, napi_value thisVar, napi_value param1, napi_value param2)
{
    CfBlob *keyStore = CertGetBlobFromUint8ArrJSParams(env, param1);
    if (keyStore == nullptr) {
        LOGE("Failed to get pkcs12!");
        return nullptr;
    }
    HcfParsePKCS12Conf *conf = static_cast<HcfParsePKCS12Conf *>(CfMalloc(sizeof(HcfParsePKCS12Conf), 0));
    if (conf == nullptr) {
        CfBlobFree(&keyStore);
        keyStore = nullptr;
        LOGE("Failed to malloc conf!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to malloc conf."));
        return nullptr;
    };
    conf->pwd = CertGetBlobFromStringJSParams(env, param2);
    if (conf->pwd == nullptr) {
        CfBlobFree(&keyStore);
        keyStore = nullptr;
        FreeHcfParsePKCS12Conf(conf);
        conf = nullptr;
        LOGE("CertGetBlobFromStringJSParams failed.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK,
            "CertGetBlobFromStringJSParams failed."));
        return nullptr;
    }
    conf->isPem = true;
    conf->isGetPriKey = true;
    conf->isGetCert = true;
    conf->isGetOtherCerts = true;

    ParsePkcs12Ctx *context = static_cast<ParsePkcs12Ctx *>(CfMalloc(sizeof(ParsePkcs12Ctx), 0));
    if (context == nullptr) {
        CfBlobFree(&keyStore);
        keyStore = nullptr;
        FreeHcfParsePKCS12Conf(conf);
        conf = nullptr;
        LOGE("malloc context failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc context failed!"));
        return nullptr;
    }
    context->keyStore = keyStore;
    context->conf = conf;
    return ParsePkcs12AsyncWork(env, thisVar, context);
}

napi_value NapiParsePKCS12(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisVar;
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr) != napi_ok) {
        LOGE("Failed to get cb info!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "Get cb info failed!"));
        return nullptr;
    }
    if (argc != ARGS_SIZE_TWO) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "invalid params count."));
        LOGE("invalid params count!");
        return nullptr;
    }
    napi_valuetype valueType;
    napi_status status = napi_typeof(env, argv[PARAM1], &valueType);
    if (status != napi_ok) {
        LOGE("Failed to get object type!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "Get object type failed!"));
        return nullptr;
    }
    if (valueType == napi_string) {
        napi_value instance = NapiParsePKCS12Async(env, thisVar, argv[PARAM0], argv[PARAM1]);
        return instance;
    }
    napi_value instance = ParsePKCS12WithKeyStore(env, argc, argv[PARAM0], argv[PARAM1]);
    return instance;
}

static bool GetPriKeyFromData(napi_env env, napi_value arg, HcfX509P12Collection *data, const char *name)
{
    bool result = false;
    napi_status status = napi_has_named_property(env, arg, name, &result);
    if (status != napi_ok) {
        LOGE("check attributes property failed!");
        return false;
    }
    if (!result) {
        LOGI("%{public}s do not exist!", name);
        return true;
    }
    napi_value obj = nullptr;
    status = napi_get_named_property(env, arg, name, &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property %{public}s failed!", name);
        return false;
    }
    napi_valuetype valueType;
    status = napi_typeof(env, obj, &valueType);
    if (status != napi_ok) {
        LOGE("Failed to get object type!");
        return false;
    }
    if (valueType == napi_undefined) {
        LOGE("%{public}s valueType is null or undefined.", name);
        return false;
    }
    if (valueType == napi_string) {
        data->isPem = true;
        data->prikey = CertGetBlobFromStringJSParams(env, obj);
        if (data->prikey == nullptr) {
            LOGE("Failed to get private key!");
            return false;
        }
    } else {
        data->isPem = false;
        data->prikey = CertGetBlobFromUint8ArrJSParams(env, obj);
        if (data->prikey == nullptr) {
            LOGE("Failed to get private key!");
            return false;
        }
    }
    return true;
}

static bool GetCertFromData(napi_env env, napi_value arg, HcfX509P12Collection *data, const char *name)
{
    bool result = false;
    napi_status status = napi_has_named_property(env, arg, name, &result);
    if (status != napi_ok) {
        LOGE("check attributes property failed!");
        return false;
    }
    if (!result) {
        LOGI("%{public}s do not exist!", name);
        return true;
    }
    napi_value obj = nullptr;
    status = napi_get_named_property(env, arg, name, &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property %{public}s failed!", name);
        return false;
    }
    napi_valuetype valueType;
    status = napi_typeof(env, obj, &valueType);
    if (status != napi_ok) {
        LOGE("Failed to get object type!");
        return false;
    }
    if (valueType == napi_undefined) {
        LOGE("%{public}s valueType is null or undefined.", name);
        return false;
    }
    NapiX509Certificate *napiX509Cert = nullptr;
    status = napi_unwrap(env, obj, reinterpret_cast<void **>(&napiX509Cert));
    if (status != napi_ok || napiX509Cert == nullptr) {
        LOGE("Failed to unwrap x509Cert obj!");
        return false;
    }

    HcfX509Certificate *cert = napiX509Cert->GetX509Cert();
    if (cert == nullptr) {
        LOGE("cert is null!");
        return false;
    }
    data->cert = cert;
    return true;
}

static bool GetOtherCertsFromData(napi_env env, napi_value arg, HcfX509P12Collection *data, const char *name)
{
    bool result = false;
    napi_value obj = nullptr;
    napi_valuetype valueType;
    HcfX509CertificateArray certs = { nullptr, 0 };
    if (napi_has_named_property(env, arg, name, &result) != napi_ok) {
        LOGE("check attributes property failed!");
        return false;
    }
    if (!result) {
        LOGI("%{public}s do not exist!", name);
        return true;
    }
    if (napi_get_named_property(env, arg, name, &obj) != napi_ok || obj == nullptr ||
        napi_typeof(env, obj, &valueType) != napi_ok || valueType == napi_undefined) {
        LOGE("get property or type failed: %{public}s", name);
        return false;
    }
    if (!GetArrayCertFromNapiValue(env, obj, &certs)) {
        LOGE("get array cert from data failed!");
        return false;
    }
    if (certs.count == 0) {
        data->otherCerts = nullptr;
        data->otherCertsCount = 0;
        LOGI("otherCerts count is 0!");
        return true;
    }
    data->otherCertsCount = certs.count;
    data->otherCerts = static_cast<HcfX509Certificate **>(CfMalloc(certs.count * sizeof(HcfX509Certificate *), 0));
    if (data->otherCerts == nullptr) {
        LOGE("Failed to malloc otherCerts!");
        CF_FREE_PTR(certs.data);
        return false;
    }
    for (uint32_t i = 0; i < certs.count; i++) {
        if (certs.data[i] == nullptr) {
            LOGE("certs.data[%{public}u] is null!", i);
            CF_FREE_PTR(data->otherCerts);
            CF_FREE_PTR(certs.data);
            return false;
        }
        data->otherCerts[i] = certs.data[i];
    }
    CF_FREE_PTR(certs.data);
    return true;
}

static bool GetP12DataFromValue(napi_env env, napi_value arg, HcfX509P12Collection *data)
{
    if (!GetPriKeyFromData(env, arg, data, CERT_CHAIN_PKCS12_TAG_PRIKEY.c_str())) {
        return false;
    }
    if (!GetCertFromData(env, arg, data, CERT_CHAIN_PKCS12_TAG_CERT.c_str())) {
        return false;
    }
    if (!GetOtherCertsFromData(env, arg, data, CERT_CHAIN_PKCS12_TAG_OTHER_CERTS.c_str())) {
        return false;
    }
    return true;
}

static bool GetNumberFromNapiValue(napi_env env, napi_value arg, int32_t &number, const char *name)
{
    bool result = false;
    napi_status status = napi_has_named_property(env, arg, name, &result);
    if (status != napi_ok) {
        LOGE("check attributes property failed!");
        return false;
    }
    if (!result) {
        LOGI("%{public}s do not exist!", name);
        return true;
    }
    napi_value data = nullptr;
    status = napi_get_named_property(env, arg, name, &data);
    if (status != napi_ok) {
        LOGE("failed to get max length!");
        return false;
    }
    napi_valuetype valueType;
    status = napi_typeof(env, data, &valueType);
    if (status != napi_ok) {
        LOGE("Failed to get object type!");
        return false;
    }
    if ((valueType != napi_number) && (valueType != napi_undefined) && (valueType != napi_null)) {
        LOGE("%{public}s valueType is null or undefined.", name);
        return false;
    }
    napi_get_value_int32(env, data, &number);
    return true;
}

static bool GetPbesParamsFromNapiValue(napi_env env, napi_value arg, HcfPbesParams *params, const char *name)
{
    params->saltLen = CERT_PKCS12_DEFAULT_SALT_LEN;
    params->iteration = CERT_PKCS12_DEFAULT_ITERATION;
    params->alg = AES_256_CBC;

    bool result = false;
    napi_status status = napi_has_named_property(env, arg, name, &result);
    if (status != napi_ok) {
        LOGE("check attributes property failed!");
        return false;
    }
    if (!result) {
        LOGI("%{public}s do not exist!", name);
        return true;
    }
    napi_value data = nullptr;
    status = napi_get_named_property(env, arg, name, &data);
    if (status != napi_ok) {
        LOGE("napi_get_named_property failed!");
        return false;
    }

    if (!GetNumberFromNapiValue(env, data, params->saltLen, CERT_CHAIN_PKCS12_TAG_SALT_LEN.c_str())) {
        LOGE("Failed to get salt length from value!");
        return false;
    }
    if (!GetNumberFromNapiValue(env, data, params->iteration, CERT_CHAIN_PKCS12_TAG_ITERATIONS.c_str())) {
        LOGE("Failed to get iteration from value!");
        return false;
    }
    int32_t number = 0;
    if (!GetNumberFromNapiValue(env, data, number, CERT_CHAIN_PKCS12_TAG_ALG.c_str())) {
        LOGE("Failed to get iteration from value!");
        return false;
    }
    params->alg = static_cast<CfPbesEncryptionAlgorithm>(number);
    return true;
}

static bool GetEncryptCertFromNapiValue(napi_env env, napi_value arg, bool &encryptCert, const char *name)
{
    bool result = false;
    napi_status status = napi_has_named_property(env, arg, name, &result);
    if (status != napi_ok) {
        LOGE("check attributes property failed!");
        return false;
    }
    if (!result) {
        LOGI("%{public}s do not exist!", name);
        return true;
    }
    napi_value data = nullptr;
    status = napi_get_named_property(env, arg, name, &data);
    if (status != napi_ok) {
        LOGE("failed to get encrypt cert!");
        return false;
    }
    napi_valuetype valueType;
    status = napi_typeof(env, data, &valueType);
    if (status != napi_ok) {
        LOGE("Failed to get object type!");
        return false;
    }
    if ((valueType != napi_boolean) && (valueType != napi_undefined) && (valueType != napi_null)) {
        LOGE("%{public}s valueType is null or undefined.", name);
        return false;
    }
    napi_get_value_bool(env, data, &encryptCert);
    return true;
}

static bool GetPassWordFromNapiValue(napi_env env, napi_value arg, CfBlob **pwd)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_PKCS12_TAG_PASSWORD.c_str());
    if (obj == nullptr) {
        LOGE("Failed to get password from value!");
        return false;
    }
    *pwd = CertGetBlobFromStringJSParams(env, obj);
    if (*pwd == nullptr || (*pwd)->data == nullptr) {
        LOGE("Failed to get password data from value!");
        return false;
    }
    return true;
}

static bool GetP12CreateConfFromValue(napi_env env, napi_value arg, HcfPkcs12CreatingConfig *conf)
{
    conf->encryptCert = true;
    conf->macSaltLen = CERT_PKCS12_DEFAULT_SALT_LEN;
    conf->macIteration = CERT_PKCS12_DEFAULT_ITERATION;
    conf->macAlg = CF_MAC_SHA256;
    conf->keyEncParams.alg = AES_256_CBC;
    conf->certEncParams.alg = AES_256_CBC;

    if (!GetPbesParamsFromNapiValue(env, arg, &conf->keyEncParams, CERT_CHAIN_PKCS12_TAG_KEY_ENC_PARAMS.c_str())) {
        return false;
    }
    if (!GetEncryptCertFromNapiValue(env, arg, conf->encryptCert, CERT_CHAIN_PKCS12_TAG_ENCRYPT_CERT.c_str())) {
        return false;
    }
    if (!GetPbesParamsFromNapiValue(env, arg, &conf->certEncParams, CERT_CHAIN_PKCS12_TAG_CERT_ENC_PARAMS.c_str())) {
        return false;
    }
    
    if (!GetNumberFromNapiValue(env, arg, conf->macSaltLen, CERT_CHAIN_PKCS12_TAG_MAC_SALT_LEN.c_str())) {
        return false;
    }
    if (!GetNumberFromNapiValue(env, arg, conf->macIteration, CERT_CHAIN_PKCS12_TAG_MAC_ITERATIONS.c_str())) {
        return false;
    }
    int32_t number = 0;
    if (!GetNumberFromNapiValue(env, arg, number, CERT_CHAIN_PKCS12_TAG_MAC_ALG.c_str())) {
        LOGE("Failed to get iteration from value!");
        return false;
    }
    conf->macAlg = static_cast<CfPkcs12MacDigestAlgorithm>(number);

    if (!GetPassWordFromNapiValue(env, arg, &conf->pwd)) {
        return false;
    }
    return true;
}

static napi_value CreatePkcs12(napi_env env, size_t argc, napi_value param0, napi_value param1)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    if (p12Collection == nullptr) {
        LOGE("Failed to malloc p12Collection!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to malloc p12Collection!"));
        return nullptr;
    }
    if (!GetP12DataFromValue(env, param0, p12Collection)) {
        LOGE("Failed to get p12 data from value!");
        FreeCreateP12Collection(p12Collection);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "Failed to get p12 data from value!"));
        return nullptr;
    }

    HcfPkcs12CreatingConfig *conf =
        static_cast<HcfPkcs12CreatingConfig *>(CfMalloc(sizeof(HcfPkcs12CreatingConfig), 0));
    if (conf == nullptr) {
        FreeCreateP12Collection(p12Collection);
        LOGE("Failed to malloc conf!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to malloc conf!"));
        return nullptr;
    }
    if (!GetP12CreateConfFromValue(env, param1, conf)) {
        FreeCreateP12Collection(p12Collection);
        FreeHcfPkcs12CreateConf(conf);
        LOGE("GetP12CreateConfFromValue failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "GetP12CreateConfFromValue failed!"));
        return nullptr;
    }
    CfBlob blob = { 0, nullptr };

    CfResult ret = HcfCreatePkcs12(p12Collection, conf, &blob);
    if (ret != CF_SUCCESS) {
        FreeCreateP12Collection(p12Collection);
        FreeHcfPkcs12CreateConf(conf);
        LOGE("HcfCreatePkcs12 failed!");
        napi_throw(env, CertGenerateBusinessError(env, ret, "HcfCreatePkcs12 failed!"));
        return nullptr;
    }
    FreeCreateP12Collection(p12Collection);
    FreeHcfPkcs12CreateConf(conf);
    napi_value returnValue = ConvertBlobToUint8ArrNapiValue(env, &blob);
    CfBlobDataFree(&blob);
    return returnValue;
}

napi_value NapiCreatePkcs12Sync(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok) {
        LOGE("Failed to get cb info!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "Get cb info failed!"));
        return nullptr;
    }
    if (argc != ARGS_SIZE_TWO) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "invalid params count"));
        LOGE("invalid params count!");
        return nullptr;
    }
    napi_value instance = CreatePkcs12(env, argc, argv[PARAM0], argv[PARAM1]);
    return instance;
}

static void CreatePkcs12Execute(napi_env env, void *data)
{
    CreatePkcs12Ctx *ctx = static_cast<CreatePkcs12Ctx *>(data);
    ctx->errCode = HcfCreatePkcs12(ctx->p12Collection, ctx->conf, &(ctx->outBlob));
    if (ctx->errCode != CF_SUCCESS) {
        LOGE("HcfCreatePkcs12 failed.");
        ctx->errMsg = "HcfCreatePkcs12 failed.";
        return;
    }
}

static void FreeCreatePkcs12Ctx(napi_env env, CreatePkcs12Ctx *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
        ctx->asyncWork = nullptr;
    }
    if (ctx->cfRef != nullptr) {
        napi_delete_reference(env, ctx->cfRef);
        ctx->cfRef = nullptr;
    }

    if (ctx->p12Collection != nullptr) {
        FreeCreateP12Collection(ctx->p12Collection);
    }
    if (ctx->conf != nullptr) {
        FreeHcfPkcs12CreateConf(ctx->conf);
    }
    CfBlobDataFree(&ctx->outBlob);
   
    CfFree(ctx);
}

static void ReturnCreatePkcs12PromiseResult(napi_env env, CreatePkcs12Ctx *context, napi_value result)
{
    if (context->errCode == CF_SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result);
    } else {
        napi_reject_deferred(env, context->deferred,
            CertGenerateBusinessError(env, context->errCode, context->errMsg));
    }
}

static void CreatePkcs12Complete(napi_env env, napi_status status, void *data)
{
    CreatePkcs12Ctx *ctx = static_cast<CreatePkcs12Ctx *>(data);
    if (ctx->errCode != CF_SUCCESS) {
        ReturnCreatePkcs12PromiseResult(env, ctx, nullptr);
        FreeCreatePkcs12Ctx(env, ctx);
        return;
    }
    napi_value instance =  ConvertBlobToUint8ArrNapiValue(env, &ctx->outBlob);
    if (instance == nullptr) {
        LOGE("Failed to convert blob to instance.");
        ctx->errCode = CF_ERR_MALLOC;
        ctx->errMsg = "Failed to convert blob to instance.";
        ReturnCreatePkcs12PromiseResult(env, ctx, nullptr);
        FreeCreatePkcs12Ctx(env, ctx);
        return;
    }
    ReturnCreatePkcs12PromiseResult(env, ctx, instance);
    FreeCreatePkcs12Ctx(env, ctx);
}

static napi_value CreatePkcs12AsyncWork(napi_env env, napi_value thisVar, CreatePkcs12Ctx *context)
{
    if (napi_create_reference(env, thisVar, 1, &context->cfRef) != napi_ok) {
        LOGE("create reference failed!");
        FreeCreatePkcs12Ctx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "Create reference failed!"));
        return nullptr;
    }
    if (napi_create_promise(env, &context->deferred, &context->promise) != napi_ok) {
        LOGE("napi_create_promise failed!");
        FreeCreatePkcs12Ctx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "napi_create_promise failed!"));
        return nullptr;
    }

    napi_create_async_work(
        env, nullptr, CertGetResourceName(env, "createPkcs12"),
        CreatePkcs12Execute,
        CreatePkcs12Complete,
        static_cast<void *>(context),
        &context->asyncWork);

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        LOGE("napi_queue_async_work failed!");
        FreeCreatePkcs12Ctx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "napi_queue_async_work failed!"));
        return nullptr;
    }
    return context->promise;
}

static CreatePkcs12Ctx* BuildCreatePkcs12Context(napi_env env, napi_value* argv)
{
    HcfX509P12Collection *p12Collection =
        static_cast<HcfX509P12Collection *>(CfMalloc(sizeof(HcfX509P12Collection), 0));
    if (p12Collection == nullptr) {
        LOGE("Failed to malloc p12Collection!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to malloc p12Collection."));
        return nullptr;
    }
    if (!GetP12DataFromValue(env, argv[PARAM0], p12Collection)) {
        LOGE("Failed to get p12 data from value!");
        FreeCreateP12Collection(p12Collection);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "Failed to get p12 data from value."));
        return nullptr;
    }

    HcfPkcs12CreatingConfig *conf =
        static_cast<HcfPkcs12CreatingConfig *>(CfMalloc(sizeof(HcfPkcs12CreatingConfig), 0));
    if (conf == nullptr) {
        FreeCreateP12Collection(p12Collection);
        LOGE("Failed to malloc conf!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to malloc conf."));
        return nullptr;
    }
    if (!GetP12CreateConfFromValue(env, argv[PARAM1], conf)) {
        FreeCreateP12Collection(p12Collection);
        FreeHcfPkcs12CreateConf(conf);
        LOGE("Failed to get conf!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "Failed to get conf."));
        return nullptr;
    }
    CreatePkcs12Ctx *context = static_cast<CreatePkcs12Ctx *>(CfMalloc(sizeof(CreatePkcs12Ctx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        FreeCreateP12Collection(p12Collection);
        FreeHcfPkcs12CreateConf(conf);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc context failed!"));
        return nullptr;
    }
    context->p12Collection = p12Collection;
    context->conf = conf;
    return context;
}

napi_value NapiCreatePkcs12(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr) != napi_ok) {
        LOGE("Failed to get cb info!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "Get cb info failed!"));
        return nullptr;
    }
    if (argc != ARGS_SIZE_TWO) {
        LOGE("invalid params count!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "invalid params count"));
        return nullptr;
    }

    CreatePkcs12Ctx *context = BuildCreatePkcs12Context(env, argv);
    if (context == nullptr) {
        LOGE("BuildCreatePkcs12Context failed!");
        return nullptr;
    }
    return CreatePkcs12AsyncWork(env, thisVar, context);
}

bool GetCertMatchParameters(napi_env env, napi_value obj, HcfX509CertChainBuildParameters **buildParams)
{
    napi_value data = nullptr;
    napi_status status = napi_get_named_property(env, obj, CERT_TAG_CERT_MATCH_PARAMS.c_str(), &data);
    if (status != napi_ok) {
        LOGE("failed to get cert match params!");
        return false;
    }
    HcfX509CertMatchParams *param = &((*buildParams)->certMatchParameters);
    if (!BuildX509CertMatchParams(env, data, param)) {
        LOGE("BuildX509CertMatchParams failed!");
        return false;
    }
    return true;
}

bool GetMaxlength(napi_env env, napi_value obj, HcfX509CertChainBuildParameters **buildParams)
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
        LOGE("%{public}s valueType is null or undefined.", CERT_TAG_MAX_LENGTH.c_str());
        return false;
    }
    napi_get_value_uint32(env, data, reinterpret_cast<uint32_t *>(&((*buildParams)->maxlength)));
    return true;
}

bool GetValidateParameters(napi_env env, napi_value obj, HcfX509CertChainBuildParameters **buildParams)
{
    napi_value data = nullptr;
    napi_status status = napi_get_named_property(env, obj, CERT_TAG_VALIDATE_PARAMS.c_str(), &data);
    if (status != napi_ok) {
        LOGE("failed to get cert validate params!");
        return false;
    }
    if (!BuildX509CertChainValidateParams(env, data, (*buildParams)->validateParameters)) {
        LOGE("BuildX509CertChainValidateParams failed!");
        return false;
    }
    return true;
}

static void FreeHcfX509CertChainBuildParameters(HcfX509CertChainBuildParameters *param)
{
    if (param == nullptr) {
        return;
    }
    FreeX509CertMatchParamsInner(&param->certMatchParameters);
    FreeX509CertChainValidateParams(param->validateParameters);
    CfFree(param);
}

bool GetChainBuildParametersFromValue(napi_env env, napi_value obj, HcfX509CertChainBuildParameters **buildParams)
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
        FreeHcfX509CertChainBuildParameters(buildParam);
        buildParam = nullptr;
        return false;
    }
    if (!GetMaxlength(env, obj, &buildParam)) {
        LOGE("failed to get max length!");
        FreeHcfX509CertChainBuildParameters(buildParam);
        buildParam = nullptr;
        return false;
    }
    if (!GetValidateParameters(env, obj, &buildParam)) {
        LOGE("failed to get validate parameters!");
        FreeHcfX509CertChainBuildParameters(buildParam);
        buildParam = nullptr;
        return false;
    }

    *buildParams = buildParam;
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
    if (!GetChainBuildParametersFromValue(env, param, &context->buildParams)) {
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
    return CertChainConstructor(env, info);
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
    return CertChainConstructor(env, info);
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
        DECLARE_NAPI_FUNCTION("parsePkcs12", NapiParsePKCS12),
        DECLARE_NAPI_FUNCTION("createPkcs12Sync", NapiCreatePkcs12Sync),
        DECLARE_NAPI_FUNCTION("createPkcs12", NapiCreatePkcs12),
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
