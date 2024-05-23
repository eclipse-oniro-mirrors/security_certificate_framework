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

#include "napi_x509_crl.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "config.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_pub_key.h"
#include "napi_x509_certificate.h"
#include "napi_x509_crl_entry.h"
#include "securec.h"
#include "napi_x509_crl_match_parameters.h"
#include "utils.h"
#include "napi_x509_distinguished_name.h"
#include "napi_cert_extension.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiX509Crl::classCrlRef_ = nullptr;
thread_local napi_ref NapiX509Crl::classCRLRef_ = nullptr;

struct CfCtx {
    AsyncType asyncType = ASYNC_TYPE_CALLBACK;
    napi_value promise = nullptr;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref cfRef = nullptr;
    napi_ref pubKeyParamsRef = nullptr;

    CfEncodingBlob *encodingBlob = nullptr;
    NapiX509Crl *crlClass = nullptr;
    HcfX509Certificate *certificate = nullptr;
    HcfPubKey *pubKey = nullptr;
    int32_t serialNumber = 0;
    std::string createX509CrlName;
    std::string returnClassName;

    HcfX509CrlEntry *crlEntry = nullptr;
    int32_t errCode = 0;
    const char *errMsg = nullptr;
    HcfX509Crl *crl;
    CfEncodingBlob *encoded = nullptr;
    CfBlob *blob = nullptr;
    CfArray *array = nullptr;
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

    CfBlobDataFree(context->blob);
    CfFree(context->blob);
    context->blob = nullptr;

    if (context->array != nullptr) {
        CfFree(context->array->data);
        context->array->data = nullptr;
        CfFree(context->array);
        context->array = nullptr;
    }

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
            LOGE("x509 crl: get callback failed!");
            return false;
        }
    } else {
        napi_create_promise(env, &context->deferred, &context->promise);
    }
    return true;
}

NapiX509Crl::NapiX509Crl(HcfX509Crl *x509Crl)
{
    this->x509Crl_ = x509Crl;
}

NapiX509Crl::~NapiX509Crl()
{
    CfObjDestroy(this->x509Crl_);
}

static void GetEncodedExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509Crl *x509Crl = context->crlClass->GetX509Crl();
    CfEncodingBlob *encodingBlob = static_cast<CfEncodingBlob *>(CfMalloc(sizeof(CfEncodingBlob), 0));
    if (encodingBlob == nullptr) {
        LOGE("malloc encoding blob failed!");
        context->errCode = CF_ERR_MALLOC;
        context->errMsg = "malloc encoding blob failed";
        return;
    }
    context->errCode = x509Crl->getEncoded(x509Crl, encodingBlob);
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

static void VerifyExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509Crl *x509Crl = context->crlClass->GetX509Crl();
    context->errCode = x509Crl->verify(x509Crl, context->pubKey);
    if (context->errCode != CF_SUCCESS) {
        LOGE("verify crl failed!");
        context->errMsg = "verify crl failed";
    }
}

static void VerifyComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    ReturnResult(env, context, CertNapiGetNull(env));
    FreeCryptoFwkCtx(env, context);
}

void GetRevokedCertificatesExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfX509Crl *x509Crl = context->crlClass->GetX509Crl();
    CfArray *array = reinterpret_cast<CfArray *>(CfMalloc(sizeof(CfArray), 0));
    if (array == nullptr) {
        LOGE("malloc array failed!");
        context->errCode = CF_ERR_MALLOC;
        context->errMsg = "malloc array failed";
        return;
    }
    context->errCode = x509Crl->getRevokedCerts(x509Crl, array);
    if (context->errCode != CF_SUCCESS) {
        LOGE("get revoked certs failed!");
        context->errMsg = "get revoked certs failed";
    }
    context->array = array;
}

static napi_value GenerateCrlEntryArray(napi_env env, CfArray *array, std::string returnClassName)
{
    if (array == nullptr) {
        LOGE("crl entry array is null!");
        return nullptr;
    }
    if (array->count == 0) {
        LOGE("crl entry array count is 0!");
        return nullptr;
    }
    napi_value returnArray = nullptr;
    napi_create_array(env, &returnArray);
    for (uint32_t i = 0; i < array->count; i++) {
        CfBlob *blob = reinterpret_cast<CfBlob *>(array->data + i);
        HcfX509CrlEntry *entry = reinterpret_cast<HcfX509CrlEntry *>(blob->data);
        napi_value instance = NapiX509CrlEntry::CreateX509CrlEntry(env, returnClassName);
        NapiX509CrlEntry *x509CrlEntryClass = new (std::nothrow) NapiX509CrlEntry(entry);
        if (x509CrlEntryClass == nullptr) {
            napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to create a x509CrlEntry class"));
            LOGE("Failed to create a x509CrlEntry class");
            CfObjDestroy(entry);
            return nullptr; /* the C++ objects wrapped will be automatically released by scope manager. */
        }
        napi_wrap(
            env, instance, x509CrlEntryClass,
            [](napi_env env, void *data, void *hint) {
                NapiX509CrlEntry *x509CrlEntryClass = static_cast<NapiX509CrlEntry *>(data);
                delete x509CrlEntryClass;
                return;
            },
            nullptr, nullptr);
        napi_set_element(env, returnArray, i, instance);
    }
    return returnArray;
}

void GetRevokedCertificatesComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->errCode != CF_SUCCESS) {
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_value returnArray = GenerateCrlEntryArray(env, context->array, context->returnClassName);
    ReturnResult(env, context, returnArray);
    FreeCryptoFwkCtx(env, context);
}

napi_value NapiX509Crl::IsRevoked(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, true)) {
        return nullptr;
    }

    NapiX509Certificate *napiX509Cert = nullptr;
    napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&napiX509Cert));
    if (napiX509Cert == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "napiX509Cert is null"));
        LOGE("napiX509Cert is null!");
        return nullptr;
    }

    HcfX509Crl *x509Crl = GetX509Crl();
    HcfX509Certificate *certificate = napiX509Cert->GetX509Cert();
    bool isRevoked = x509Crl->base.isRevoked(&(x509Crl->base), &(certificate->base));
    napi_value result = nullptr;
    napi_get_boolean(env, isRevoked, &result);
    return result;
}

napi_value NapiX509Crl::GetType(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    const char *type = x509Crl->base.getType(&(x509Crl->base));
    napi_value result = nullptr;
    napi_create_string_utf8(env, type, strlen(type), &result);
    return result;
}

napi_value NapiX509Crl::GetEncoded(napi_env env, napi_callback_info info)
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
    context->crlClass = this;

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

__attribute__((no_sanitize("cfi"))) napi_value NapiX509Crl::Verify(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return nullptr;
    }

    NapiPubKey *pubKey = nullptr;
    napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&pubKey));
    if (pubKey == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "public key is null"));
        LOGE("pubKey is null!");
        return nullptr;
    }

    CfCtx *context = static_cast<CfCtx *>(CfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->pubKey = pubKey->GetPubKey();
    context->crlClass = this;

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
    } else {
        return CertNapiGetNull(env);
    }
}

napi_value NapiX509Crl::GetVersion(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    int version = x509Crl->getVersion(x509Crl);
    napi_value result = nullptr;
    napi_create_int32(env, version, &result);
    return result;
}

napi_value NapiX509Crl::GetIssuerDN(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    CfResult ret = x509Crl->getIssuerName(x509Crl, blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get issuer name failed"));
        LOGE("getIssuerDN failed!");
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

napi_value NapiX509Crl::GetThisUpdate(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    CfResult ret = x509Crl->getLastUpdate(x509Crl, blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get last update failed"));
        LOGE("getLastUpdate failed!");
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

napi_value NapiX509Crl::GetNextUpdate(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    CfResult ret = x509Crl->getNextUpdate(x509Crl, blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get next update failed"));
        LOGE("getNextUpdate failed!");
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

static bool GetCrlSerialNumberFromNapiValue(napi_env env, napi_value arg, CfBlob &outBlob)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_number) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "param type error"));
        LOGE("wrong argument type. expect int type. [Type]: %d", valueType);
        return false;
    }

    uint8_t serialBuf[MAX_SN_BYTE_CNT] = { 0 };
    uint32_t serialLen = sizeof(int64_t);
    int64_t tmpData = 0;
    if (napi_get_value_int64(env, arg, &tmpData) != napi_ok || tmpData < 0) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get serialNum failed"));
        LOGE("can not get int64 value");
        return false;
    }

    if (memcpy_s(serialBuf, sizeof(serialBuf), &tmpData, sizeof(int64_t)) != EOK) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_COPY, "copy serialNum failed"));
        LOGE("copy serialNum failed");
        return false;
    }

    outBlob.size = serialLen;
    outBlob.data = static_cast<uint8_t *>(CfMalloc(serialLen, 0));
    if (outBlob.data == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc serialNum failed"));
        LOGE("malloc blob data failed!");
        return false;
    }
    // reverse data: because BN_bin2bn() converts the positive integer in big-endian form of length len into a BIGNUM
    for (uint32_t i = 0; i < serialLen; ++i) {
        outBlob.data[i] = serialBuf[outBlob.size - 1 - i];
    }

    return true;
}

napi_value NapiX509Crl::GetRevokedCertificate(napi_env env, napi_callback_info info, std::string returnClassName)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, true)) {
        return nullptr;
    }

    CfBlob serialNumber = { 0, nullptr };
    bool getSnRet = false;
    if (returnClassName == std::string("X509CrlEntry")) {
        getSnRet = GetCrlSerialNumberFromNapiValue(env, argv[PARAM0], serialNumber);
    } else {
        getSnRet = CertGetSerialNumberFromBigIntJSParams(env, argv[PARAM0], serialNumber);
    }
    if (!getSnRet) {
        LOGE("get serialNumber failed");
        return nullptr;
    }

    HcfX509Crl *x509Crl = GetX509Crl();
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = x509Crl->getRevokedCert(x509Crl, &serialNumber, &crlEntry);
    CF_FREE_PTR(serialNumber.data);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get revoked cert failed!"));
        LOGE("get revoked cert failed!");
        return nullptr;
    }

    napi_value instance = NapiX509CrlEntry::CreateX509CrlEntry(env, returnClassName);
    NapiX509CrlEntry *x509CrlEntryClass = new (std::nothrow) NapiX509CrlEntry(crlEntry);
    if (x509CrlEntryClass == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to create a x509CrlEntry class"));
        LOGE("Failed to create a x509CrlEntry class");
        CfObjDestroy(crlEntry);
        return nullptr;
    }

    napi_wrap(
        env, instance, x509CrlEntryClass,
        [](napi_env env, void *data, void *hint) {
            NapiX509CrlEntry *x509CrlEntryClass = static_cast<NapiX509CrlEntry *>(data);
            delete x509CrlEntryClass;
            return;
        },
        nullptr, nullptr);
    return instance;
}

napi_value NapiX509Crl::GetRevokedCertificateWithCert(
    napi_env env, napi_callback_info info, std::string returnClassName)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, true)) {
        return nullptr;
    }

    NapiX509Certificate *napiX509Cert = nullptr;
    napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&napiX509Cert));
    if (napiX509Cert == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "napiX509Cert is null"));
        LOGE("napiX509Cert is null!");
        return nullptr;
    }

    HcfX509Certificate *certificate = napiX509Cert->GetX509Cert();
    HcfX509Crl *x509Crl = GetX509Crl();
    HcfX509CrlEntry *crlEntry = nullptr;
    CfResult ret = x509Crl->getRevokedCertWithCert(x509Crl, certificate, &crlEntry);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get revoked cert with cert failed!"));
        LOGE("get revoked cert with cert failed!");
        return nullptr;
    }

    napi_value instance = NapiX509CrlEntry::CreateX509CrlEntry(env, returnClassName);
    NapiX509CrlEntry *x509CrlEntryClass = new (std::nothrow) NapiX509CrlEntry(crlEntry);
    if (x509CrlEntryClass == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to create a x509CrlEntry class"));
        LOGE("Failed to create a x509CrlEntry class");
        CfObjDestroy(crlEntry);
        return nullptr;
    }
    napi_wrap(
        env, instance, x509CrlEntryClass,
        [](napi_env env, void *data, void *hint) {
            NapiX509CrlEntry *x509CrlEntryClass = static_cast<NapiX509CrlEntry *>(data);
            delete x509CrlEntryClass;
            return;
        },
        nullptr, nullptr);
    return instance;
}

napi_value NapiX509Crl::GetRevokedCertificates(napi_env env, napi_callback_info info, std::string returnClassName)
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
    context->crlClass = this;

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

    context->returnClassName = returnClassName;

    napi_create_async_work(env, nullptr, CertGetResourceName(env, "GetRevokedCertificates"),
        GetRevokedCertificatesExecute, GetRevokedCertificatesComplete, static_cast<void *>(context),
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return CertNapiGetNull(env);
    }
}

napi_value NapiX509Crl::GetTBSCertList(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    CfResult result = x509Crl->getTbsInfo(x509Crl, blob);
    if (result != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, result, "get tbs info failed"));
        LOGE("get tbs info failed!");
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

napi_value NapiX509Crl::ToString(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob blob = { 0, nullptr };
    CfResult result = x509Crl->toString(x509Crl, &blob);
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

napi_value NapiX509Crl::HashCode(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob blob = { 0, nullptr };
    CfResult result = x509Crl->hashCode(x509Crl, &blob);
    if (result != CF_SUCCESS) {
        LOGE("hashCode failed!");
        napi_throw(env, CertGenerateBusinessError(env, result, "hashCode failed"));
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

napi_value NapiX509Crl::GetExtensionsObject(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob blob = { 0, nullptr };
    CfResult result = x509Crl->getExtensionsObject(x509Crl, &blob);
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

napi_value NapiX509Crl::GetIssuerX500DistinguishedName(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob blob = { 0, nullptr };
    CfResult ret = x509Crl->getIssuerName(x509Crl, &blob);
    if (ret != CF_SUCCESS) {
        LOGE("getIssuerName failed!");
        napi_throw(env, CertGenerateBusinessError(env, ret, "get issuer name failed"));
        return nullptr;
    }
    HcfX509DistinguishedName *x509Name = nullptr;
    ret = HcfX509DistinguishedNameCreate(&blob, true, &x509Name);
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

napi_value NapiX509Crl::GetSignature(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    CfResult result = x509Crl->getSignature(x509Crl, blob);
    if (result != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, result, "get signature failed"));
        LOGE("getSignature failed!");
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

napi_value NapiX509Crl::GetSigAlgName(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    CfResult ret = x509Crl->getSignatureAlgName(x509Crl, blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get signature alg name failed"));
        LOGE("getSigAlgName failed!");
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

napi_value NapiX509Crl::GetSigAlgOID(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    CfResult ret = x509Crl->getSignatureAlgOid(x509Crl, blob);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "get signature alg oid failed"));
        LOGE("getSigAlgOID failed!");
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

napi_value NapiX509Crl::GetSigAlgParams(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    CfResult result = x509Crl->getSignatureAlgParams(x509Crl, blob);
    if (result != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, result, "get signature alg params failed"));
        LOGE("getSigAlgParams failed!");
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

napi_value NapiX509Crl::GetExtensions(napi_env env, napi_callback_info info)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    CfBlob *blob = reinterpret_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (blob == nullptr) {
        LOGE("malloc blob failed!");
        return nullptr;
    }
    CfResult result = x509Crl->getExtensions(x509Crl, blob);
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

napi_value NapiX509Crl::Match(napi_env env, napi_callback_info info)
{
    LOGI("enter NapiX509Crl::match");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, false)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "CertCheckArgsCount failed"));
        LOGE("CertCheckArgsCount failed!");
        return nullptr;
    }

    HcfX509CrlMatchParams *param = static_cast<HcfX509CrlMatchParams *>(CfMalloc(sizeof(HcfX509CrlMatchParams), 0));
    if (param == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc matchParams failed"));
        LOGE("malloc matchParams failed!");
        return nullptr;
    }
    if (!BuildX509CrlMatchParams(env, argv[PARAM0], param)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "BuildX509CrlMatchParams failed"));
        LOGE("BuildX509CrlMatchParams failed!");
        FreeX509CrlMatchParams(param);
        return nullptr;
    }

    bool boolFlag = false;
    CfResult result = MatchProc(param, boolFlag);
    if (result != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, result, "match failed"));
        LOGE("call match failed!");
        FreeX509CrlMatchParams(param);
        return nullptr;
    }
    FreeX509CrlMatchParams(param);
    napi_value ret = nullptr;
    napi_get_boolean(env, boolFlag, &ret);
    return ret;
}

CfResult NapiX509Crl::MatchProc(HcfX509CrlMatchParams *param, bool &boolFlag)
{
    HcfX509Crl *x509Crl = GetX509Crl();
    return x509Crl->match(x509Crl, param, &boolFlag);
}

static napi_value NapiIsRevoked(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->IsRevoked(env, info);
}

static napi_value NapiGetType(napi_env env, napi_callback_info info)
{
    LOGI("napi get crl type called.");
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    LOGI("unwrap x509 crl class success.");
    return x509Crl->GetType(env, info);
}

static napi_value NapiGetEncoded(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetEncoded(env, info);
}

static napi_value NapiVerify(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->Verify(env, info);
}

static napi_value NapiGetVersion(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetVersion(env, info);
}

static napi_value NapiGetIssuerDN(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetIssuerDN(env, info);
}

static napi_value NapiGetThisUpdate(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetThisUpdate(env, info);
}

static napi_value NapiGetNextUpdate(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetNextUpdate(env, info);
}

static napi_value NapiCrlGetRevokedCertificate(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetRevokedCertificate(env, info, std::string("X509CrlEntry"));
}

static napi_value NapiCrlGetRevokedCertificateWithCert(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetRevokedCertificateWithCert(env, info, std::string("X509CrlEntry"));
}

static napi_value NapiCrlGetRevokedCertificates(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetRevokedCertificates(env, info, std::string("X509CrlEntry"));
}

static napi_value NapiCRLGetRevokedCertificate(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetRevokedCertificate(env, info, std::string("X509CRLEntry"));
}

static napi_value NapiCRLGetRevokedCertificateWithCert(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetRevokedCertificateWithCert(env, info, std::string("X509CRLEntry"));
}

static napi_value NapiCRLGetRevokedCertificates(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetRevokedCertificates(env, info, std::string("X509CRLEntry"));
}

static napi_value NapiCrlGetTBSCertList(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetTBSCertList(env, info);
}

static napi_value NapiCRLGetTBSCertList(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetTBSCertList(env, info);
}

static napi_value NapiToString(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->ToString(env, info);
}

static napi_value NapiHashCode(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->HashCode(env, info);
}

static napi_value NapiGetExtensionsObject(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetExtensionsObject(env, info);
}

static napi_value NapiGetIssuerX500DistinguishedName(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetIssuerX500DistinguishedName(env, info);
}

static napi_value NapiGetSignature(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetSignature(env, info);
}

static napi_value NapiGetSigAlgName(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetSigAlgName(env, info);
}

static napi_value NapiGetSigAlgOID(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetSigAlgOID(env, info);
}

static napi_value NapiGetSigAlgParams(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetSigAlgParams(env, info);
}

static napi_value NapiGetExtensions(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->GetExtensions(env, info);
}

static napi_value NapiMatch(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509Crl *x509Crl = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Crl));
    if (x509Crl == nullptr) {
        LOGE("x509Crl is nullptr!");
        return nullptr;
    }
    return x509Crl->Match(env, info);
}

void NapiX509Crl::CreateX509CrlExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    context->errCode = HcfX509CrlCreate(context->encodingBlob, &context->crl);
    if (context->errCode != CF_SUCCESS) {
        context->errMsg = "create X509Crl failed";
    }
}

void NapiX509Crl::CreateX509CrlComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->errCode != CF_SUCCESS) {
        LOGE("call create X509Crl failed!");
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_value instance = CreateX509Crl(env, context->createX509CrlName);
    NapiX509Crl *x509CrlClass = new (std::nothrow) NapiX509Crl(context->crl);
    if (x509CrlClass == nullptr) {
        context->errCode = CF_ERR_MALLOC;
        context->errMsg = "Failed to create a x509Crl class";
        LOGE("Failed to create a x509Crl class");
        CfObjDestroy(context->crl);
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_wrap(
        env, instance, x509CrlClass,
        [](napi_env env, void *data, void *hint) {
            NapiX509Crl *crlClass = static_cast<NapiX509Crl *>(data);
            delete crlClass;
            return;
        },
        nullptr, nullptr);
    ReturnResult(env, context, instance);
    FreeCryptoFwkCtx(env, context);
}

napi_value NapiX509Crl::NapiCreateX509CrlBase(napi_env env, napi_callback_info info, std::string createName)
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

    context->createX509CrlName = createName;

    napi_create_async_work(env, nullptr, CertGetResourceName(env, createName.c_str()), CreateX509CrlExecute,
        CreateX509CrlComplete, static_cast<void *>(context), &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    } else {
        return CertNapiGetNull(env);
    }
}

napi_value NapiX509Crl::NapiCreateX509Crl(napi_env env, napi_callback_info info)
{
    return NapiCreateX509CrlBase(env, info, std::string("createX509Crl"));
}

napi_value NapiX509Crl::NapiCreateX509CRL(napi_env env, napi_callback_info info)
{
    return NapiCreateX509CrlBase(env, info, std::string("createX509CRL"));
}

static napi_value X509CrlConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

void NapiX509Crl::DefineX509CrlJS(napi_env env, napi_value exports, std::string className)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION(className.c_str(), NapiCreateX509Crl),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor x509CrlDesc[] = {
        DECLARE_NAPI_FUNCTION("isRevoked", NapiIsRevoked),
        DECLARE_NAPI_FUNCTION("getType", NapiGetType),
        DECLARE_NAPI_FUNCTION("getEncoded", NapiGetEncoded),
        DECLARE_NAPI_FUNCTION("verify", NapiVerify),
        DECLARE_NAPI_FUNCTION("getVersion", NapiGetVersion),
        DECLARE_NAPI_FUNCTION("getIssuerName", NapiGetIssuerDN),
        DECLARE_NAPI_FUNCTION("getLastUpdate", NapiGetThisUpdate),
        DECLARE_NAPI_FUNCTION("getNextUpdate", NapiGetNextUpdate),
        DECLARE_NAPI_FUNCTION("getSignature", NapiGetSignature),
        DECLARE_NAPI_FUNCTION("getSignatureAlgName", NapiGetSigAlgName),
        DECLARE_NAPI_FUNCTION("getSignatureAlgOid", NapiGetSigAlgOID),
        DECLARE_NAPI_FUNCTION("getSignatureAlgParams", NapiGetSigAlgParams),
        DECLARE_NAPI_FUNCTION("getRevokedCert", NapiCrlGetRevokedCertificate),
        DECLARE_NAPI_FUNCTION("getRevokedCerts", NapiCrlGetRevokedCertificates),
        DECLARE_NAPI_FUNCTION("getRevokedCertWithCert", NapiCrlGetRevokedCertificateWithCert),
        DECLARE_NAPI_FUNCTION("getTbsInfo", NapiCrlGetTBSCertList),
        DECLARE_NAPI_FUNCTION("toString", NapiToString),
        DECLARE_NAPI_FUNCTION("hashCode", NapiHashCode),
        DECLARE_NAPI_FUNCTION("getExtensionsObject", NapiGetExtensionsObject),
        DECLARE_NAPI_FUNCTION("getIssuerX500DistinguishedName", NapiGetIssuerX500DistinguishedName),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), NAPI_AUTO_LENGTH, X509CrlConstructor, nullptr,
        sizeof(x509CrlDesc) / sizeof(x509CrlDesc[0]), x509CrlDesc, &constructor);

    napi_create_reference(env, constructor, 1, &classCrlRef_);
}

void NapiX509Crl::DefineX509CRLJS(napi_env env, napi_value exports, std::string className)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION(className.c_str(), NapiCreateX509CRL),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor x509CrlDesc[] = {
        DECLARE_NAPI_FUNCTION("isRevoked", NapiIsRevoked),
        DECLARE_NAPI_FUNCTION("getType", NapiGetType),
        DECLARE_NAPI_FUNCTION("getEncoded", NapiGetEncoded),
        DECLARE_NAPI_FUNCTION("verify", NapiVerify),
        DECLARE_NAPI_FUNCTION("getVersion", NapiGetVersion),
        DECLARE_NAPI_FUNCTION("getIssuerName", NapiGetIssuerDN),
        DECLARE_NAPI_FUNCTION("getLastUpdate", NapiGetThisUpdate),
        DECLARE_NAPI_FUNCTION("getNextUpdate", NapiGetNextUpdate),
        DECLARE_NAPI_FUNCTION("getSignature", NapiGetSignature),
        DECLARE_NAPI_FUNCTION("getSignatureAlgName", NapiGetSigAlgName),
        DECLARE_NAPI_FUNCTION("getSignatureAlgOid", NapiGetSigAlgOID),
        DECLARE_NAPI_FUNCTION("getSignatureAlgParams", NapiGetSigAlgParams),
        DECLARE_NAPI_FUNCTION("getExtensions", NapiGetExtensions),
        DECLARE_NAPI_FUNCTION("getRevokedCert", NapiCRLGetRevokedCertificate),
        DECLARE_NAPI_FUNCTION("getRevokedCerts", NapiCRLGetRevokedCertificates),
        DECLARE_NAPI_FUNCTION("getRevokedCertWithCert", NapiCRLGetRevokedCertificateWithCert),
        DECLARE_NAPI_FUNCTION("getTBSInfo", NapiCRLGetTBSCertList),
        DECLARE_NAPI_FUNCTION("match", NapiMatch),
        DECLARE_NAPI_FUNCTION("toString", NapiToString),
        DECLARE_NAPI_FUNCTION("hashCode", NapiHashCode),
        DECLARE_NAPI_FUNCTION("getExtensionsObject", NapiGetExtensionsObject),
        DECLARE_NAPI_FUNCTION("getIssuerX500DistinguishedName", NapiGetIssuerX500DistinguishedName),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, className.c_str(), NAPI_AUTO_LENGTH, X509CrlConstructor, nullptr,
        sizeof(x509CrlDesc) / sizeof(x509CrlDesc[0]), x509CrlDesc, &constructor);

    napi_create_reference(env, constructor, 1, &classCRLRef_);
}

void NapiX509Crl::DefineX509CrlJSClass(napi_env env, napi_value exports, std::string className)
{
    std::string createName;
    if (className == std::string("X509Crl")) {
        createName = "createX509Crl";
        DefineX509CrlJS(env, exports, createName);
    } else {
        createName = "createX509CRL";
        DefineX509CRLJS(env, exports, createName);
    }
}

napi_value NapiX509Crl::CreateX509Crl(napi_env env, std::string createName)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    if (createName == std::string("createX509Crl")) {
        napi_get_reference_value(env, classCrlRef_, &constructor);
    } else {
        napi_get_reference_value(env, classCRLRef_, &constructor);
    }
    napi_new_instance(env, constructor, 0, nullptr, &instance);
    return instance;
}
} // namespace CertFramework
} // namespace OHOS
