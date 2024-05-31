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

#include "napi_x509_crl_entry.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "utils.h"
#include "napi_x509_distinguished_name.h"
#include "napi_cert_extension.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiX509CrlEntry::classCrlRef_ = nullptr;
thread_local napi_ref NapiX509CrlEntry::classCRLRef_ = nullptr;

struct CfCtx {
    AsyncType asyncType = ASYNC_TYPE_CALLBACK;
    napi_value promise = nullptr;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref cfRef = nullptr;

    NapiX509CrlEntry *crlEntryClass = nullptr;

    int32_t errCode = 0;
    const char *errMsg = nullptr;
    CfEncodingBlob *encoded = nullptr;
    CfBlob *blob = nullptr;
};

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

    CfEncodingBlobDataFree(context->encoded);
    CfFree(context->encoded);
    context->encoded = nullptr;

    CfBlobDataFree(context->blob);
    CfFree(context->blob);
    context->blob = nullptr;

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
        napi_reject_deferred(env, context->deferred, CertGenerateBusinessError(env, context->errCode, context->errMsg));
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

static bool CreateCallbackAndPromise(
    napi_env env, CfCtx *context, size_t argc, size_t maxCount, napi_value callbackValue)
{
    context->asyncType = GetAsyncType(env, argc, maxCount, callbackValue);
    if (context->asyncType == ASYNC_TYPE_CALLBACK) {
        if (!CertGetCallbackFromJSParams(env, callbackValue, &context->callback)) {
            LOGE("x509 crl entry: get callback failed!");
            return false;
        }
    } else {
        napi_create_promise(env, &context->deferred, &context->promise);
    }
    return true;
}

NapiX509CrlEntry::NapiX509CrlEntry(HcfX509CrlEntry *x509CrlEntry)
{
    this->x509CrlEntry_ = x509CrlEntry;
}

NapiX509CrlEntry::~NapiX509CrlEntry()
{
    CfObjDestroy(this->x509CrlEntry_);
}

static void GetEncodedExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509CrlEntry *x509CrlEntry = context->crlEntryClass->GetX509CrlEntry();
    CfEncodingBlob *encodingBlob = static_cast<CfEncodingBlob *>(CfMalloc(sizeof(CfEncodingBlob), 0));
    if (encodingBlob == nullptr) {
        LOGE("malloc encoding blob failed!");
        context->errCode = CF_ERR_MALLOC;
        context->errMsg = "malloc encoding blob failed";
        return;
    }

    context->errCode = x509CrlEntry->getEncoded(x509CrlEntry, encodingBlob);
    if (context->errCode != CF_SUCCESS) {
        LOGE("get encoded failed!");
        context->errMsg = "get encoded failed";
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

napi_value NapiX509CrlEntry::GetEncoded(napi_env env, napi_callback_info info)
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
    context->crlEntryClass = this;

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

    napi_create_async_work(env, nullptr, CertGetResourceName(env, "GetEncoded"), GetEncodedExecute, GetEncodedComplete,
        static_cast<void *>(context), &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return CertNapiGetNull(env);
    }
}

napi_value NapiX509CrlEntry::GetCrlEntrySerialNumber(napi_env env, napi_callback_info info)
{
    HcfX509CrlEntry *x509CrlEntry = GetX509CrlEntry();
    CfBlob blob = { 0, nullptr };
    CfResult ret = x509CrlEntry->getSerialNumber(x509CrlEntry, &blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "crl entry get serial num failed"));
        LOGE("crl entry get serial num failed!");
        return nullptr;
    }

    napi_value result = ConvertBlobToInt64(env, blob);
    CfBlobDataFree(&blob);
    return result;
}

napi_value NapiX509CrlEntry::GetCRLEntrySerialNumber(napi_env env, napi_callback_info info)
{
    HcfX509CrlEntry *x509CrlEntry = GetX509CrlEntry();
    CfBlob blob = { 0, nullptr };
    CfResult ret = x509CrlEntry->getSerialNumber(x509CrlEntry, &blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "crl entry get serial num failed"));
        LOGE("crl entry get serial num failed!");
        return nullptr;
    }

    napi_value result = ConvertBlobToBigIntWords(env, blob);
    CfBlobDataFree(&blob);
    return result;
}

napi_value NapiX509CrlEntry::GetCertificateIssuer(napi_env env, napi_callback_info info)
{
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }

    HcfX509CrlEntry *x509CrlEntry = GetX509CrlEntry();
    CfResult ret = x509CrlEntry->getCertIssuer(x509CrlEntry, blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get subject name failed"));
        LOGE("get cert issuer failed!");
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

napi_value NapiX509CrlEntry::GetRevocationDate(napi_env env, napi_callback_info info)
{
    HcfX509CrlEntry *x509CrlEntry = GetX509CrlEntry();
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    CfResult ret = x509CrlEntry->getRevocationDate(x509CrlEntry, blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get revocation date failed"));
        LOGE("get revocation date failed!");
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value returnDate = nullptr;
    uint32_t size = blob->data[blob->size - 1] == '\0' ? blob->size - 1 : blob->size;
    napi_create_string_utf8(env, reinterpret_cast<char *>(blob->data), size, &returnDate);
    CfBlobDataFree(blob);
    CfFree(blob);
    blob = nullptr;
    return returnDate;
}

napi_value NapiX509CrlEntry::GetExtensions(napi_env env, napi_callback_info info)
{
    HcfX509CrlEntry *x509CrlEntry = GetX509CrlEntry();
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    CfResult result = x509CrlEntry->getExtensions(x509CrlEntry, blob);
    if (result != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, result, "get extensions failed"));
        LOGE("getExtensions failed!");
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    napi_value returnBlob = CertConvertBlobToNapiValue(env, blob);
    CfBlobDataFree(blob);
    CfFree(blob);
    blob = nullptr;
    return returnBlob;
}

napi_value NapiX509CrlEntry::HasExtensions(napi_env env, napi_callback_info info)
{
    HcfX509CrlEntry *x509CrlEntry = GetX509CrlEntry();
    bool boolResult = false;
    CfResult result = x509CrlEntry->hasExtensions(x509CrlEntry, &boolResult);
    if (result != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, result, "has extensions failed"));
        LOGE("hasExtensions failed!");
        return nullptr;
    }
    napi_value ret = nullptr;
    napi_get_boolean(env, boolResult, &ret);
    return ret;
}

napi_value NapiX509CrlEntry::ToString(napi_env env, napi_callback_info info)
{
    HcfX509CrlEntry *x509CrlEntry = GetX509CrlEntry();
    CfBlob blob = { 0, nullptr };
    CfResult result = x509CrlEntry->toString(x509CrlEntry, &blob);
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

napi_value NapiX509CrlEntry::HashCode(napi_env env, napi_callback_info info)
{
    HcfX509CrlEntry *x509CrlEntry = GetX509CrlEntry();
    CfBlob blob = { 0, nullptr };
    CfResult result = x509CrlEntry->hashCode(x509CrlEntry, &blob);
    if (result != CF_SUCCESS) {
        LOGE("HashCode failed!");
        napi_throw(env, CertGenerateBusinessError(env, result, "HashCode failed"));
        return nullptr;
    }
    napi_value returnBlob = ConvertBlobToUint8ArrNapiValue(env, &blob);
    CfBlobDataFree(&blob);
    return returnBlob;
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

napi_value NapiX509CrlEntry::GetExtensionsObject(napi_env env, napi_callback_info info)
{
    HcfX509CrlEntry *x509CrlEntry = GetX509CrlEntry();
    CfBlob blob = { 0, nullptr };
    CfResult result = x509CrlEntry->getExtensionsObject(x509CrlEntry, &blob);
    if (result != CF_SUCCESS) {
        LOGE("get Extensions Object failed!");
        napi_throw(env, CertGenerateBusinessError(env, result, "get Extensions Object failed"));
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

napi_value NapiX509CrlEntry::GetCertIssuerX500DistinguishedName(napi_env env, napi_callback_info info)
{
    HcfX509CrlEntry *x509CrlEntry = GetX509CrlEntry();
    CfBlob blob = { 0, nullptr };
    CfResult result = x509CrlEntry->getCertIssuer(x509CrlEntry, &blob);
    if (result != CF_SUCCESS) {
        LOGE("getIssuerDN failed!");
        napi_throw(env, CertGenerateBusinessError(env, result, "get issuer name failed"));
        return nullptr;
    }
    HcfX509DistinguishedName *x509Name = nullptr;
    CfResult ret = HcfX509DistinguishedNameCreate(&blob, true, &x509Name);
    CfBlobDataFree(&blob);
    if (ret != CF_SUCCESS || x509Name == nullptr) {
        LOGE("HcfX509DistinguishedNameCreate failed");
        napi_throw(env, CertGenerateBusinessError(env, ret, "HcfX509DistinguishedNameCreate failed"));
        return nullptr;
    }
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

static napi_value NapiGetEncoded(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CrlEntry *x509CrlEntry = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509CrlEntry));
    if (x509CrlEntry == nullptr) {
        LOGE("x509CrlEntry is nullptr!");
        return nullptr;
    }
    return x509CrlEntry->GetEncoded(env, info);
}

static napi_value NapiCrlEntryGetSerialNumber(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CrlEntry *x509CrlEntry = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509CrlEntry));
    if (x509CrlEntry == nullptr) {
        LOGE("x509CrlEntry is nullptr!");
        return nullptr;
    }
    return x509CrlEntry->GetCrlEntrySerialNumber(env, info);
}

static napi_value NapiCRLEntryGetSerialNumber(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CrlEntry *x509CrlEntry = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509CrlEntry));
    if (x509CrlEntry == nullptr) {
        LOGE("x509CrlEntry is nullptr!");
        return nullptr;
    }
    return x509CrlEntry->GetCRLEntrySerialNumber(env, info);
}

static napi_value NapiGetCertificateIssuer(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CrlEntry *x509CrlEntry = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509CrlEntry));
    if (x509CrlEntry == nullptr) {
        LOGE("x509CrlEntry is nullptr!");
        return nullptr;
    }
    return x509CrlEntry->GetCertificateIssuer(env, info);
}

static napi_value NapiGetRevocationDate(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CrlEntry *x509CrlEntry = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509CrlEntry));
    if (x509CrlEntry == nullptr) {
        LOGE("x509CrlEntry is nullptr!");
        return nullptr;
    }
    return x509CrlEntry->GetRevocationDate(env, info);
}

static napi_value NapiGetExtensions(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CrlEntry *x509CrlEntry = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509CrlEntry));
    if (x509CrlEntry == nullptr) {
        LOGE("x509CrlEntry is nullptr!");
        return nullptr;
    }
    return x509CrlEntry->GetExtensions(env, info);
}

static napi_value NapiHasExtensions(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CrlEntry *x509CrlEntry = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509CrlEntry));
    if (x509CrlEntry == nullptr) {
        LOGE("x509CrlEntry is nullptr!");
        return nullptr;
    }
    return x509CrlEntry->HasExtensions(env, info);
}

static napi_value NapiToString(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CrlEntry *x509CrlEntry = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509CrlEntry));
    if (x509CrlEntry == nullptr) {
        LOGE("x509CrlEntry is nullptr!");
        return nullptr;
    }
    return x509CrlEntry->ToString(env, info);
}

static napi_value NapiHashCode(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CrlEntry *x509CrlEntry = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509CrlEntry));
    if (x509CrlEntry == nullptr) {
        LOGE("x509CrlEntry is nullptr!");
        return nullptr;
    }
    return x509CrlEntry->HashCode(env, info);
}

static napi_value NapiGetExtensionsObject(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CrlEntry *x509CrlEntry = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509CrlEntry));
    if (x509CrlEntry == nullptr) {
        LOGE("x509CrlEntry is nullptr!");
        return nullptr;
    }
    return x509CrlEntry->GetExtensionsObject(env, info);
}

static napi_value NapiGetCertIssuerX500DistinguishedName(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509CrlEntry *x509CrlEntry = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509CrlEntry));
    if (x509CrlEntry == nullptr) {
        LOGE("x509CrlEntry is nullptr!");
        return nullptr;
    }
    return x509CrlEntry->GetCertIssuerX500DistinguishedName(env, info);
}

static napi_value X509CrlEntryConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

void NapiX509CrlEntry::DefineX509CrlEntryJSClass(napi_env env, std::string className)
{
    if (className == std::string("X509CrlEntry")) {
        napi_property_descriptor x509CrlEntryDesc[] = {
            DECLARE_NAPI_FUNCTION("getEncoded", NapiGetEncoded),
            DECLARE_NAPI_FUNCTION("getSerialNumber", NapiCrlEntryGetSerialNumber),
            DECLARE_NAPI_FUNCTION("getCertIssuer", NapiGetCertificateIssuer),
            DECLARE_NAPI_FUNCTION("getRevocationDate", NapiGetRevocationDate),
            DECLARE_NAPI_FUNCTION("toString", NapiToString),
            DECLARE_NAPI_FUNCTION("hashCode", NapiHashCode),
            DECLARE_NAPI_FUNCTION("getExtensionsObject", NapiGetExtensionsObject),
            DECLARE_NAPI_FUNCTION("getCertIssuerX500DistinguishedName", NapiGetCertIssuerX500DistinguishedName),
        };
        napi_value constructor = nullptr;
        napi_define_class(env, className.c_str(), NAPI_AUTO_LENGTH, X509CrlEntryConstructor, nullptr,
            sizeof(x509CrlEntryDesc) / sizeof(x509CrlEntryDesc[0]), x509CrlEntryDesc, &constructor);
        napi_create_reference(env, constructor, 1, &classCrlRef_);
    } else {
        napi_property_descriptor x509CrlEntryDesc[] = {
            DECLARE_NAPI_FUNCTION("getEncoded", NapiGetEncoded),
            DECLARE_NAPI_FUNCTION("getSerialNumber", NapiCRLEntryGetSerialNumber),
            DECLARE_NAPI_FUNCTION("getCertIssuer", NapiGetCertificateIssuer),
            DECLARE_NAPI_FUNCTION("getRevocationDate", NapiGetRevocationDate),
            DECLARE_NAPI_FUNCTION("getExtensions", NapiGetExtensions),
            DECLARE_NAPI_FUNCTION("hasExtensions", NapiHasExtensions),
            DECLARE_NAPI_FUNCTION("toString", NapiToString),
            DECLARE_NAPI_FUNCTION("hashCode", NapiHashCode),
            DECLARE_NAPI_FUNCTION("getExtensionsObject", NapiGetExtensionsObject),
            DECLARE_NAPI_FUNCTION("getCertIssuerX500DistinguishedName", NapiGetCertIssuerX500DistinguishedName),
        };
        napi_value constructor = nullptr;
        napi_define_class(env, className.c_str(), NAPI_AUTO_LENGTH, X509CrlEntryConstructor, nullptr,
            sizeof(x509CrlEntryDesc) / sizeof(x509CrlEntryDesc[0]), x509CrlEntryDesc, &constructor);
        napi_create_reference(env, constructor, 1, &classCRLRef_);
    }
}

napi_value NapiX509CrlEntry::CreateX509CrlEntry(napi_env env, std::string className)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    if (className == std::string("X509CrlEntry")) {
        napi_get_reference_value(env, classCrlRef_, &constructor);
    } else {
        napi_get_reference_value(env, classCRLRef_, &constructor);
    }
    napi_new_instance(env, constructor, 0, nullptr, &instance);
    return instance;
}
} // namespace CertFramework
} // namespace OHOS
