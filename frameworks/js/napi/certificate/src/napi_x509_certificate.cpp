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

#include "napi_x509_certificate.h"

#include "napi/native_common.h"
#include "napi/native_api.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "utils.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "napi_cert_defines.h"
#include "napi_pub_key.h"
#include "napi_cert_utils.h"

#include "cf_type.h"
#include "napi_object.h"
#include "napi_x509_cert_match_parameters.h"
#include "napi_x509_distinguished_name.h"
#include "napi_cert_extension.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiX509Certificate::classRef_ = nullptr;

struct CfCtx {
    AsyncType asyncType = ASYNC_TYPE_CALLBACK;
    napi_value promise = nullptr;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref cfRef = nullptr;
    napi_ref pubKeyParamsRef = nullptr;

    CfEncodingBlob *encodingBlob = nullptr;
    NapiX509Certificate *certClass = nullptr;
    HcfPubKey *pubKey = nullptr;

    int32_t errCode = 0;
    const char *errMsg = nullptr;
    HcfX509Certificate *cert = nullptr;
    CfObject *object = nullptr;
    CfEncodingBlob *encoded = nullptr;
};

NapiX509Certificate::NapiX509Certificate(HcfX509Certificate *x509Cert, CfObject *object)
{
    this->x509Cert_ = x509Cert;
    this->certObject_ = object;
}

NapiX509Certificate::~NapiX509Certificate()
{
    CfObjDestroy(this->x509Cert_);
    if (this->certObject_ != nullptr) {
        this->certObject_->destroy(&(this->certObject_));
    }
}

static void FreeCryptoFwkCtx(napi_env env, CfCtx *context)
{
    if (context == nullptr) {
        return;
    }

    if (context->asyncWork != nullptr) {
        napi_delete_async_work(env, context->asyncWork);
    }

    if (context->callback != nullptr) {
        napi_delete_reference(env, context->callback);
    }

    if (context->cfRef != nullptr) {
        napi_delete_reference(env, context->cfRef);
        context->cfRef = nullptr;
    }
    if (context->pubKeyParamsRef != nullptr) {
        napi_delete_reference(env, context->pubKeyParamsRef);
        context->pubKeyParamsRef = nullptr;
    }

    CfEncodingBlobDataFree(context->encodingBlob);
    CfFree(context->encodingBlob);
    context->encodingBlob = nullptr;

    CfEncodingBlobDataFree(context->encoded);
    CfFree(context->encoded);
    context->encoded = nullptr;

    CfFree(context);
}

static void ReturnCallbackResult(napi_env env, CfCtx *context, napi_value result)
{
    napi_value businessError = nullptr;
    if (context->errCode != CF_SUCCESS) {
        businessError = CertGenerateBusinessError(env, context->errCode, context->errMsg);
    }
    napi_value params[ARGS_SIZE_TWO] = { businessError, result };

    napi_value func = nullptr;
    napi_get_reference_value(env, context->callback, &func);

    napi_value recv = nullptr;
    napi_value callFuncRet = nullptr;
    napi_get_undefined(env, &recv);
    napi_call_function(env, recv, func, ARGS_SIZE_TWO, params, &callFuncRet);
}

static void ReturnPromiseResult(napi_env env, CfCtx *context, napi_value result)
{
    if (context->errCode == CF_SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result);
    } else {
        napi_reject_deferred(env, context->deferred,
            CertGenerateBusinessError(env, context->errCode, context->errMsg));
    }
}

static void ReturnResult(napi_env env, CfCtx *context, napi_value result)
{
    if (context->asyncType == ASYNC_TYPE_CALLBACK) {
        ReturnCallbackResult(env, context, result);
    } else {
        ReturnPromiseResult(env, context, result);
    }
}

static bool CreateCallbackAndPromise(napi_env env, CfCtx *context, size_t argc,
    size_t maxCount, napi_value callbackValue)
{
    context->asyncType = GetAsyncType(env, argc, maxCount, callbackValue);
    if (context->asyncType == ASYNC_TYPE_CALLBACK) {
        if (!CertGetCallbackFromJSParams(env, callbackValue, &context->callback)) {
            LOGE("x509 certificate: get callback failed!");
            return false;
        }
    } else {
        napi_create_promise(env, &context->deferred, &context->promise);
    }
    return true;
}

static void VerifyExecute(napi_env env, void *data)
{
    LOGI("start to verify.");
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509Certificate *cert = context->certClass->GetX509Cert();
    context->errCode = cert->base.verify(&(cert->base), context->pubKey);
    if (context->errCode != CF_SUCCESS) {
        LOGE("verify cert failed!");
        context->errMsg = "verify cert failed";
    }
}

static void VerifyComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    ReturnResult(env, context, CertNapiGetNull(env));
    FreeCryptoFwkCtx(env, context);
}

static void GetEncodedExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509Certificate *cert = context->certClass->GetX509Cert();
    CfEncodingBlob *encodingBlob = static_cast<CfEncodingBlob *>(CfMalloc(sizeof(CfEncodingBlob), 0));
    if (encodingBlob == nullptr) {
        LOGE("malloc encoding blob failed!");
        context->errCode = CF_ERR_MALLOC;
        context->errMsg = "malloc encoding blob failed";
        return;
    }
    context->errCode = cert->base.getEncoded(&(cert->base), encodingBlob);
    if (context->errCode != CF_SUCCESS) {
        LOGE("get cert encoded failed!");
        context->errMsg = "get cert encoded failed";
    }
    context->encoded = encodingBlob;
}

static void GetEncodedComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->errCode != CF_SUCCESS) {
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_value returnEncodingBlob = ConvertEncodingBlobToNapiValue(env, context->encoded);
    ReturnResult(env, context, returnEncodingBlob);
    FreeCryptoFwkCtx(env, context);
}

napi_value NapiX509Certificate::Verify(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return nullptr;
    }

    CfCtx *context = static_cast<CfCtx *>(CfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->certClass = this;

    NapiPubKey *pubKey = nullptr;
    napi_unwrap(env, argv[PARAM0], (void**)&pubKey);
    if (pubKey == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "public key is null"));
        LOGE("pubKey is null!");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }
    context->pubKey = pubKey->GetPubKey();

    if (napi_create_reference(env, thisVar, 1, &context->cfRef) != napi_ok) {
        LOGE("create reference failed!");
        FreeCryptoFwkCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create reference failed"));
        return nullptr;
    }
    if (napi_create_reference(env, argv[PARAM0], 1, &context->pubKeyParamsRef) != napi_ok) {
        LOGE("create param ref failed!");
        FreeCryptoFwkCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create param ref failed"));
        return nullptr;
    }

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, argv[PARAM1])) {
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_create_async_work(env, nullptr, CertGetResourceName(env, "Verify"), VerifyExecute, VerifyComplete,
        static_cast<void *>(context), &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    }

    return CertNapiGetNull(env);
}

napi_value NapiX509Certificate::GetEncoded(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, false)) {
        return nullptr;
    }

    CfCtx *context = static_cast<CfCtx *>(CfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->certClass = this;
    if (napi_create_reference(env, thisVar, 1, &context->cfRef) != napi_ok) {
        LOGE("create reference failed!");
        FreeCryptoFwkCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create reference failed"));
        return nullptr;
    }

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_ONE, argv[PARAM0])) {
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_create_async_work(
        env, nullptr, CertGetResourceName(env, "GetEncoded"),
        GetEncodedExecute,
        GetEncodedComplete,
        static_cast<void *>(context),
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return CertNapiGetNull(env);
    }
}

napi_value NapiX509Certificate::GetPublicKey(napi_env env, napi_callback_info info)
{
    HcfX509Certificate *cert = GetX509Cert();
    HcfPubKey *returnPubKey = nullptr;
    CfResult ret = cert->base.getPublicKey(&(cert->base), (void **)&returnPubKey);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get cert public key failed!"));
        LOGE("get cert public key failed!");
        return nullptr;
    }

    NapiPubKey *pubKeyClass = new (std::nothrow) NapiPubKey(returnPubKey);
    if (pubKeyClass == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to create a pubkey class"));
        LOGE("create for x509 cert's public key obj failed");
        CfObjDestroy(returnPubKey);
        return nullptr;
    }
    napi_value instance = pubKeyClass->ConvertToJsPubKey(env);
    napi_wrap(
        env, instance, pubKeyClass,
        [](napi_env env, void *data, void *hint) {
            NapiPubKey *pubKeyClass = static_cast<NapiPubKey *>(data);
            CfObjDestroy(pubKeyClass->GetPubKey());
            delete pubKeyClass;
            return;
        },
        nullptr, nullptr);
    return instance;
}

napi_value NapiX509Certificate::CheckValidityWithDate(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, true)) {
        return nullptr;
    }
    std::string date;
    if (!CertGetStringFromJSParams(env, argv[PARAM0], date)) {
        LOGE("get date param failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->checkValidityWithDate(cert, date.c_str());
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "check cert validity failed!"));
        LOGE("check cert validity failed!");
    }
    return nullptr;
}

napi_value NapiX509Certificate::GetVersion(napi_env env, napi_callback_info info)
{
    HcfX509Certificate *cert = GetX509Cert();
    int version = cert->getVersion(cert);
    napi_value result = nullptr;
    napi_create_int32(env, version, &result);
    return result;
}

napi_value NapiX509Certificate::GetSerialNumber(napi_env env, napi_callback_info info)
{
    HcfX509Certificate *cert = GetX509Cert();
    CfBlob blob = { 0, nullptr };
    CfResult ret = cert->getSerialNumber(cert, &blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "cert get serial num failed"));
        LOGE("cert get serial num failed!");
        return nullptr;
    }

    napi_value result = ConvertBlobToInt64(env, blob);
    CfBlobDataFree(&blob);
    return result;
}

napi_value NapiX509Certificate::GetCertSerialNumber(napi_env env, napi_callback_info info)
{
    HcfX509Certificate *cert = GetX509Cert();
    CfBlob blob = { 0, nullptr };
    CfResult ret = cert->getSerialNumber(cert, &blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "cert get serial num failed"));
        LOGE("cert get serial num failed!");
        return nullptr;
    }

    napi_value result = ConvertBlobToBigIntWords(env, blob);
    CfBlobDataFree(&blob);
    return result;
}

napi_value NapiX509Certificate::GetIssuerName(napi_env env, napi_callback_info info)
{
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->getIssuerName(cert, blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get issuer name failed"));
        LOGE("getIssuerName failed!");
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value returnValue = CertConvertBlobToNapiValue(env, blob);
    CfBlobDataFree(blob);
    CfFree(blob);
    blob = nullptr;
    return returnValue;
}

napi_value NapiX509Certificate::GetSubjectName(napi_env env, napi_callback_info info)
{
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->getSubjectName(cert, blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get subject name failed"));
        LOGE("getSubjectName failed!");
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value returnValue = CertConvertBlobToNapiValue(env, blob);
    CfBlobDataFree(blob);
    CfFree(blob);
    blob = nullptr;
    return returnValue;
}

napi_value NapiX509Certificate::GetNotBeforeTime(napi_env env, napi_callback_info info)
{
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult res = cert->getNotBeforeTime(cert, blob);
    if (res != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, res, "get not before time failed"));
        LOGE("getNotBeforeTime failed!");
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value result = nullptr;
    uint32_t size = blob->data[blob->size - 1] == '\0' ? blob->size - 1 : blob->size;
    napi_create_string_utf8(env, reinterpret_cast<char *>(blob->data), size, &result);
    CfBlobDataFree(blob);
    CfFree(blob);
    blob = nullptr;
    return result;
}

napi_value NapiX509Certificate::GetNotAfterTime(napi_env env, napi_callback_info info)
{
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult res = cert->getNotAfterTime(cert, blob);
    if (res != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, res, "get not after time failed"));
        LOGE("getNotAfterTime failed!");
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value result = nullptr;
    uint32_t size = blob->data[blob->size - 1] == '\0' ? blob->size - 1 : blob->size;
    napi_create_string_utf8(env, reinterpret_cast<char *>(blob->data), size, &result);
    CfBlobDataFree(blob);
    CfFree(blob);
    blob = nullptr;
    return result;
}

napi_value NapiX509Certificate::GetSignature(napi_env env, napi_callback_info info)
{
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->getSignature(cert, blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get signature failed"));
        LOGE("getSignature failed!");
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value returnValue = CertConvertBlobToNapiValue(env, blob);
    CfBlobDataFree(blob);
    CfFree(blob);
    blob = nullptr;
    return returnValue;
}

napi_value NapiX509Certificate::GetSigAlgName(napi_env env, napi_callback_info info)
{
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult res = cert->getSignatureAlgName(cert, blob);
    if (res != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, res, "get signature alg name failed"));
        LOGE("getSignatureAlgName failed!");
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value result = nullptr;
    uint32_t size = blob->data[blob->size - 1] == '\0' ? blob->size - 1 : blob->size;
    napi_create_string_utf8(env, reinterpret_cast<char *>(blob->data), size, &result);
    CfBlobDataFree(blob);
    CfFree(blob);
    blob = nullptr;
    return result;
}

napi_value NapiX509Certificate::GetSigAlgOID(napi_env env, napi_callback_info info)
{
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult res = cert->getSignatureAlgOid(cert, blob);
    if (res != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, res, "get signature alg oid failed"));
        LOGE("getSignatureAlgOid failed!");
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value result = nullptr;
    uint32_t size = blob->data[blob->size - 1] == '\0' ? blob->size - 1 : blob->size;
    napi_create_string_utf8(env, reinterpret_cast<char *>(blob->data), size, &result);
    CfBlobDataFree(blob);
    CfFree(blob);
    blob = nullptr;
    return result;
}

napi_value NapiX509Certificate::GetSigAlgParams(napi_env env, napi_callback_info info)
{
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->getSignatureAlgParams(cert, blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get signature alg params failed"));
        LOGE("getSignatureAlgParams failed!");
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value returnValue = CertConvertBlobToNapiValue(env, blob);
    CfBlobDataFree(blob);
    CfFree(blob);
    blob = nullptr;
    return returnValue;
}

napi_value NapiX509Certificate::GetKeyUsage(napi_env env, napi_callback_info info)
{
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->getKeyUsage(cert, blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get key usage failed"));
        LOGE("getKeyUsage failed!");
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value returnValue = CertConvertBlobToNapiValue(env, blob);
    CfBlobDataFree(blob);
    CfFree(blob);
    blob = nullptr;
    return returnValue;
}

napi_value NapiX509Certificate::GetExtendedKeyUsage(napi_env env, napi_callback_info info)
{
    CfArray *array = reinterpret_cast<CfArray *>(CfMalloc(sizeof(CfArray), 0));
    if (array == nullptr) {
        LOGE("malloc array failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->getExtKeyUsage(cert, array);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get ext key usage failed"));
        LOGE("call getExtKeyUsage failed!");
        CfFree(array);
        array = nullptr;
        return nullptr;
    }
    napi_value returnValue = ConvertArrayToNapiValue(env, array);
    CfArrayDataClearAndFree(array);
    CfFree(array);
    array = nullptr;
    return returnValue;
}


napi_value NapiX509Certificate::GetBasicConstraints(napi_env env, napi_callback_info info)
{
    HcfX509Certificate *cert = GetX509Cert();
    int32_t constrains = cert->getBasicConstraints(cert);
    napi_value result = nullptr;
    napi_create_int32(env, constrains, &result);
    return result;
}

napi_value NapiX509Certificate::GetSubjectAlternativeNames(napi_env env, napi_callback_info info)
{
    CfArray *array = reinterpret_cast<CfArray *>(CfMalloc(sizeof(CfArray), 0));
    if (array == nullptr) {
        LOGE("malloc array failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->getSubjectAltNames(cert, array);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get subject alt names failed"));
        LOGE("call getSubjectAltNames failed!");
        CfFree(array);
        array = nullptr;
        return nullptr;
    }
    napi_value returnValue = ConvertArrayToNapiValue(env, array);
    CfArrayDataClearAndFree(array);
    CfFree(array);
    array = nullptr;
    return returnValue;
}

napi_value NapiX509Certificate::GetIssuerAlternativeNames(napi_env env, napi_callback_info info)
{
    CfArray *array = reinterpret_cast<CfArray *>(CfMalloc(sizeof(CfArray), 0));
    if (array == nullptr) {
        LOGE("malloc array failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->getIssuerAltNames(cert, array);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get issuer alt names failed"));
        LOGE("call getIssuerAltNames failed!");
        CfFree(array);
        array = nullptr;
        return nullptr;
    }
    napi_value returnValue = ConvertArrayToNapiValue(env, array);
    CfArrayDataClearAndFree(array);
    CfFree(array);
    array = nullptr;
    return returnValue;
}

napi_value NapiX509Certificate::Match(napi_env env, napi_callback_info info)
{
    LOGI("enter NapiX509Certificate::match");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, false)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "CertCheckArgsCount failed"));
        LOGE("CertCheckArgsCount failed!");
        return nullptr;
    }

    HcfX509CertMatchParams *param = static_cast<HcfX509CertMatchParams *>(CfMalloc(sizeof(HcfX509CertMatchParams), 0));
    if (param == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc param failed"));
        LOGE("malloc matchParams failed!");
        return nullptr;
    }
    if (!BuildX509CertMatchParams(env, argv[PARAM0], param)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "BuildX509CertMatchParams failed"));
        LOGE("BuildX509CertMatchParams failed!");
        FreeX509CertMatchParams(param);
        return nullptr;
    }
    bool boolFlag = false;
    CfResult result = MatchProc(param, boolFlag);
    if (result != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, result, "match failed"));
        LOGE("call match failed!");
        FreeX509CertMatchParams(param);
        return nullptr;
    }
    FreeX509CertMatchParams(param);
    napi_value ret = nullptr;
    napi_get_boolean(env, boolFlag, &ret);
    return ret;
}

napi_value NapiX509Certificate::ToString(napi_env env, napi_callback_info info)
{
    CfBlob blob = { 0, nullptr };
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->toString(cert, &blob);
    if (ret != CF_SUCCESS) {
        LOGE("toString failed!");
        napi_throw(env, CertGenerateBusinessError(env, ret, "toString failed"));
        return nullptr;
    }

    napi_value returnValue = nullptr;
    napi_create_string_utf8(env, reinterpret_cast<char *>(blob.data), blob.size, &returnValue);
    CfBlobDataFree(&blob);
    return returnValue;
}

napi_value NapiX509Certificate::HashCode(napi_env env, napi_callback_info info)
{
    CfBlob blob = { 0, nullptr };
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->hashCode(cert, &blob);
    if (ret != CF_SUCCESS) {
        LOGE("Hashcode failed!");
        napi_throw(env, CertGenerateBusinessError(env, ret, "Hashcode failed"));
        return nullptr;
    }
    napi_value returnValue = ConvertBlobToUint8ArrNapiValue(env, &blob);
    CfBlobDataFree(&blob);
    return returnValue;
}

static napi_value CreateCertExtsJSInstance(napi_env env)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    napi_get_reference_value(env, NapiCertExtension::classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);
    return instance;
}

static napi_value BuildCertExtsObject(napi_env env, CfEncodingBlob *encodingBlob)
{
    CfObject *extsObj = nullptr;
    int32_t res = CfCreate(CF_OBJ_TYPE_EXTENSION, encodingBlob, &extsObj);
    if (res != CF_SUCCESS) {
        LOGE("CfCreate error!");
        return nullptr;
    }
    napi_value jsObject = CreateCertExtsJSInstance(env);
    NapiCertExtension *napiObject = new (std::nothrow) NapiCertExtension(extsObj);
    if (napiObject == nullptr) {
        LOGE("Failed to create napi extension class");
        if (extsObj != nullptr) {
            extsObj->destroy(&(extsObj));
        }
        return nullptr;
    }
    napi_wrap(
        env, jsObject, napiObject,
        [](napi_env env, void *data, void *hint) {
            NapiCertExtension *certExts = static_cast<NapiCertExtension *>(data);
            delete certExts;
            return;
        }, nullptr, nullptr);
    return jsObject;
}

napi_value NapiX509Certificate::GetExtensionsObject(napi_env env, napi_callback_info info)
{
    CfBlob blob = { 0, nullptr };
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->getExtensionsObject(cert, &blob);
    if (ret != CF_SUCCESS) {
        LOGE("get Extensions Object  failed!");
        napi_throw(env, CertGenerateBusinessError(env, ret, "get Extensions Object failed"));
        return nullptr;
    }

    CfEncodingBlob *encodingBlob = static_cast<CfEncodingBlob *>(CfMalloc(sizeof(CfEncodingBlob), 0));
    if (encodingBlob == nullptr) {
        LOGE("malloc encoding blob failed!");
        CfBlobDataFree(&blob);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "CfMalloc failed"));
        return nullptr;
    }
    if (!ConvertBlobToEncodingBlob(blob, encodingBlob)) {
        LOGE("ConvertBlobToEncodingBlob failed!");
        CfBlobDataFree(&blob);
        CfFree(encodingBlob);
        encodingBlob = nullptr;
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_CRYPTO_OPERATION, "ConvertBlobToEncodingBlob failed"));
        return nullptr;
    }
    CfBlobDataFree(&blob);

    napi_value object = BuildCertExtsObject(env, encodingBlob);
    CfEncodingBlobDataFree(encodingBlob);
    CfFree(encodingBlob);
    encodingBlob = nullptr;
    if (object == nullptr) {
        LOGE("BuildCertExtsObject failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "BuildCertExtsObject failed"));
        return nullptr;
    }

    return object;
}

napi_value NapiX509Certificate::GetIssuerX500DistinguishedName(napi_env env, napi_callback_info info)
{
    HcfX509Certificate *cert = GetX509Cert();
    CfBlob blob = { 0, nullptr };
    CfResult ret = cert->getIssuerName(cert, &blob);
    if (ret != CF_SUCCESS) {
        LOGE("getIssuerName failed!");
        napi_throw(env, CertGenerateBusinessError(env, ret, "get issuer name failed"));
        return nullptr;
    }
    HcfX509DistinguishedName *x509Name = nullptr;
    ret = HcfX509DistinguishedNameCreate(&blob, true, &x509Name);
    if (ret != CF_SUCCESS || x509Name == nullptr) {
        LOGE("HcfX509DistinguishedNameCreate failed");
        napi_throw(env, CertGenerateBusinessError(env, ret, "HcfX509DistinguishedNameCreate failed"));
        CfBlobDataFree(&blob);
        return nullptr;
    }
    CfBlobDataFree(&blob);
    napi_value instance = NapiX509DistinguishedName::CreateX509DistinguishedName(env);
    NapiX509DistinguishedName *x509NameClass = new (std::nothrow) NapiX509DistinguishedName(x509Name);
    if (x509NameClass == nullptr) {
        LOGE("Failed to create a NapiX509DistinguishedName class");
        CfObjDestroy(x509Name);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "NapiX509DistinguishedName new failed"));
        return nullptr;
    }
    napi_wrap(
        env, instance, x509NameClass,
        [](napi_env env, void *data, void *hint) {
            NapiX509DistinguishedName *nameClass = static_cast<NapiX509DistinguishedName *>(data);
            delete nameClass;
            return;
        }, nullptr, nullptr);
    return instance;
}

napi_value NapiX509Certificate::GetSubjectX500DistinguishedName(napi_env env, napi_callback_info info)
{
    HcfX509Certificate *cert = GetX509Cert();
    CfBlob blob = { 0, nullptr };
    CfResult ret = cert->getSubjectName(cert, &blob);
    if (ret != CF_SUCCESS) {
        LOGE("getSubjectName failed!");
        napi_throw(env, CertGenerateBusinessError(env, ret, "get subject name failed"));
        return nullptr;
    }
    HcfX509DistinguishedName *x509Name = nullptr;
    ret = HcfX509DistinguishedNameCreate(&blob, true, &x509Name);
    if (ret != CF_SUCCESS || x509Name == nullptr) {
        LOGE("HcfX509DistinguishedNameCreate failed");
        napi_throw(env, CertGenerateBusinessError(env, ret, "HcfX509DistinguishedNameCreate failed"));
        CfBlobDataFree(&blob);
        return nullptr;
    }
    CfBlobDataFree(&blob);
    napi_value instance = NapiX509DistinguishedName::CreateX509DistinguishedName(env);
    NapiX509DistinguishedName *x509NameClass = new (std::nothrow) NapiX509DistinguishedName(x509Name);
    if (x509NameClass == nullptr) {
        LOGE("Failed to create a NapiX509DistinguishedName class");
        CfObjDestroy(x509Name);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "NapiX509DistinguishedName new failed"));
        return nullptr;
    }
    napi_wrap(
        env, instance, x509NameClass,
        [](napi_env env, void *data, void *hint) {
            NapiX509DistinguishedName *nameClass = static_cast<NapiX509DistinguishedName *>(data);
            delete nameClass;
            return;
        }, nullptr, nullptr);
    return instance;
}

napi_value NapiX509Certificate::GetCRLDistributionPointsURI(napi_env env, napi_callback_info info)
{
    CfArray *array = reinterpret_cast<CfArray *>(CfMalloc(sizeof(CfArray), 0));
    if (array == nullptr) {
        LOGE("malloc array failed!");
        return nullptr;
    }
    HcfX509Certificate *cert = GetX509Cert();
    CfResult ret = cert->getCRLDistributionPointsURI(cert, array);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get crl distribution points URI failed"));
        LOGE("call get crl distribution points URI  failed!");
        CfFree(array);
        array = nullptr;
        return nullptr;
    }
    napi_value returnValue = ConvertArrayToNapiValue(env, array);
    CfArrayDataClearAndFree(array);
    CfFree(array);
    array = nullptr;
    return returnValue;
}

CfResult NapiX509Certificate::MatchProc(HcfX509CertMatchParams *param, bool &boolFlag)
{
    HcfX509Certificate *cert = GetX509Cert();
    return cert->match(cert, param, &boolFlag);
}

static napi_value NapiVerify(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->Verify(env, info);
}

static napi_value NapiGetEncoded(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetEncoded(env, info);
}

static napi_value NapiGetPublicKey(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetPublicKey(env, info);
}

static napi_value NapiCheckValidityWithDate(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->CheckValidityWithDate(env, info);
}

static napi_value NapiGetVersion(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetVersion(env, info);
}

static napi_value NapiGetSerialNumber(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetSerialNumber(env, info);
}

static napi_value NapiGetCertSerialNumber(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetCertSerialNumber(env, info);
}

static napi_value NapiGetIssuerName(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetIssuerName(env, info);
}

static napi_value NapiGetSubjectName(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetSubjectName(env, info);
}

static napi_value NapiGetNotBeforeTime(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetNotBeforeTime(env, info);
}

static napi_value NapiGetNotAfterTime(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetNotAfterTime(env, info);
}

static napi_value NapiGetSignature(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetSignature(env, info);
}

static napi_value NapiGetSigAlgName(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetSigAlgName(env, info);
}

static napi_value NapiGetSigAlgOID(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetSigAlgOID(env, info);
}

static napi_value NapiGetSigAlgParams(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetSigAlgParams(env, info);
}

static napi_value NapiGetKeyUsage(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetKeyUsage(env, info);
}

static napi_value NapiGetExtendedKeyUsage(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetExtendedKeyUsage(env, info);
}

static napi_value NapiGetBasicConstraints(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetBasicConstraints(env, info);
}

static napi_value NapiGetSubjectAlternativeNames(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetSubjectAlternativeNames(env, info);
}

static napi_value NapiGetIssuerAlternativeNames(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetIssuerAlternativeNames(env, info);
}

static napi_value NapiGetItem(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    CfObject *obj = x509Cert->GetCertObject();
    if (obj == nullptr) {
        LOGE("object is nullptr!");
        return nullptr;
    }

    return CommonOperation(env, info, obj, OPERATION_TYPE_GET, CF_GET_TYPE_CERT_ITEM);
}

static napi_value NapiGetCRLDistributionPointsURI(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetCRLDistributionPointsURI(env, info);
}

static napi_value NapiMatch(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->Match(env, info);
}
//v3
static napi_value NapiToString(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->ToString(env, info);
}

static napi_value NapiHashCode(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->HashCode(env, info);
}

static napi_value NapiGetExtensionsObject(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetExtensionsObject(env, info);
}

static napi_value NapiGetIssuerX500DistinguishedName(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetIssuerX500DistinguishedName(env, info);
}

static napi_value NapiGetSubjectX500DistinguishedName(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Certificate *x509Cert = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Cert));
    if (x509Cert == nullptr) {
        LOGE("x509Cert is nullptr!");
        return nullptr;
    }
    return x509Cert->GetSubjectX500DistinguishedName(env, info);
}

void NapiX509Certificate::CreateX509CertExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    context->errCode = HcfX509CertificateCreate(context->encodingBlob, &context->cert);
    if (context->errCode != CF_SUCCESS) {
        context->errMsg = "create X509Cert failed";
        return;
    }

    context->errCode = CfCreate(CF_OBJ_TYPE_CERT, context->encodingBlob, &context->object);
    if (context->errCode != CF_SUCCESS) {
        context->errMsg = "create certObj failed";
    }
}

void NapiX509Certificate::CreateX509CertComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->errCode != CF_SUCCESS) {
        LOGE("call create X509Cert failed!");
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_value instance = CreateX509Cert(env);
    NapiX509Certificate *x509CertClass = new (std::nothrow) NapiX509Certificate(context->cert, context->object);
    if (x509CertClass == nullptr) {
        context->errCode = CF_ERR_MALLOC;
        context->errMsg = "Failed to create x509Cert class";
        LOGE("Failed to create x509Cert class");
        CfObjDestroy(context->cert);
        if (context->object != nullptr) {
            context->object->destroy(&(context->object));
        }
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_wrap(
        env, instance, x509CertClass,
        [](napi_env env, void *data, void *hint) {
            NapiX509Certificate *certClass = static_cast<NapiX509Certificate *>(data);
            delete certClass;
            return;
        },
        nullptr, nullptr);
    ReturnResult(env, context, instance);
    FreeCryptoFwkCtx(env, context);
}

napi_value NapiX509Certificate::NapiCreateX509Cert(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return nullptr;
    }

    CfCtx *context = static_cast<CfCtx *>(CfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    if (!GetEncodingBlobFromValue(env, argv[PARAM0], &context->encodingBlob)) {
        LOGE("get encoding blob from data failed!");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    if (napi_create_reference(env, thisVar, 1, &context->cfRef) != napi_ok) {
        LOGE("create reference failed!");
        FreeCryptoFwkCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create reference failed"));
        return nullptr;
    }

    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, argv[PARAM1])) {
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_create_async_work(
        env, nullptr, CertGetResourceName(env, "CreateX509Cert"),
        CreateX509CertExecute,
        CreateX509CertComplete,
        static_cast<void *>(context),
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return CertNapiGetNull(env);
    }
}

static napi_value X509CertConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

void NapiX509Certificate::DefineX509CertJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createX509Cert", NapiCreateX509Cert),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor x509CertDesc[] = {
        DECLARE_NAPI_FUNCTION("verify", NapiVerify),
        DECLARE_NAPI_FUNCTION("getEncoded", NapiGetEncoded),
        DECLARE_NAPI_FUNCTION("getPublicKey", NapiGetPublicKey),
        DECLARE_NAPI_FUNCTION("checkValidityWithDate", NapiCheckValidityWithDate),
        DECLARE_NAPI_FUNCTION("getVersion", NapiGetVersion),
        DECLARE_NAPI_FUNCTION("getSerialNumber", NapiGetSerialNumber),
        DECLARE_NAPI_FUNCTION("getCertSerialNumber", NapiGetCertSerialNumber),
        DECLARE_NAPI_FUNCTION("getIssuerName", NapiGetIssuerName),
        DECLARE_NAPI_FUNCTION("getSubjectName", NapiGetSubjectName),
        DECLARE_NAPI_FUNCTION("getNotBeforeTime", NapiGetNotBeforeTime),
        DECLARE_NAPI_FUNCTION("getNotAfterTime", NapiGetNotAfterTime),
        DECLARE_NAPI_FUNCTION("getSignature", NapiGetSignature),
        DECLARE_NAPI_FUNCTION("getSignatureAlgName", NapiGetSigAlgName),
        DECLARE_NAPI_FUNCTION("getSignatureAlgOid", NapiGetSigAlgOID),
        DECLARE_NAPI_FUNCTION("getSignatureAlgParams", NapiGetSigAlgParams),
        DECLARE_NAPI_FUNCTION("getKeyUsage", NapiGetKeyUsage),
        DECLARE_NAPI_FUNCTION("getExtKeyUsage", NapiGetExtendedKeyUsage),
        DECLARE_NAPI_FUNCTION("getBasicConstraints", NapiGetBasicConstraints),
        DECLARE_NAPI_FUNCTION("getSubjectAltNames", NapiGetSubjectAlternativeNames),
        DECLARE_NAPI_FUNCTION("getIssuerAltNames", NapiGetIssuerAlternativeNames),
        DECLARE_NAPI_FUNCTION("getItem", NapiGetItem),
        DECLARE_NAPI_FUNCTION("match", NapiMatch),
        DECLARE_NAPI_FUNCTION("toString", NapiToString),
        DECLARE_NAPI_FUNCTION("hashCode", NapiHashCode),
        DECLARE_NAPI_FUNCTION("getExtensionsObject", NapiGetExtensionsObject),
        DECLARE_NAPI_FUNCTION("getIssuerX500DistinguishedName", NapiGetIssuerX500DistinguishedName),
        DECLARE_NAPI_FUNCTION("getSubjectX500DistinguishedName", NapiGetSubjectX500DistinguishedName),
        DECLARE_NAPI_FUNCTION("getCRLDistributionPoint", NapiGetCRLDistributionPointsURI),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "X509Cert", NAPI_AUTO_LENGTH, X509CertConstructor, nullptr,
        sizeof(x509CertDesc) / sizeof(x509CertDesc[0]), x509CertDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}

napi_value NapiX509Certificate::CreateX509Cert(napi_env env)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);
    return instance;
}
} // namespace CertFramework
} // namespace OHOS
