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

#include "napi_cert_crl_collection.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "config.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_common.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_pub_key.h"
#include "napi_x509_certificate.h"
#include "napi_x509_crl.h"
#include "napi_x509_cert_match_parameters.h"
#include "napi_x509_crl_match_parameters.h"
#include "napi_cert_crl_common.h"
#include "securec.h"
#include "utils.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiCertCRLCollection::classRef_ = nullptr;

struct CfCertCRLColCtx {
    AsyncType asyncType = ASYNC_TYPE_CALLBACK;
    napi_value promise = nullptr;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref cfCertCRLCollectionRef = nullptr;
    napi_ref certMatchParamsRef = nullptr;
    napi_ref crlMatchParamsRef = nullptr;
    CfResult errCode = CF_SUCCESS;
    const char *errMsg = nullptr;

    NapiCertCRLCollection *certCRLColClass = nullptr;
    HcfX509CertMatchParams *certMatchParam = nullptr;
    HcfX509CrlMatchParams *crlMatchParam = nullptr;
    HcfX509CertificateArray retCerts { nullptr, 0 };
    HcfX509CrlArray retCrls { nullptr, 0 };
};

static void FreeCryptoFwkCtx(napi_env env, CfCertCRLColCtx *&context)
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

    if (context->cfCertCRLCollectionRef != nullptr) {
        napi_delete_reference(env, context->cfCertCRLCollectionRef);
        context->cfCertCRLCollectionRef = nullptr;
    }
    if (context->certMatchParamsRef != nullptr) {
        napi_delete_reference(env, context->certMatchParamsRef);
        context->certMatchParamsRef = nullptr;
    }
    if (context->crlMatchParamsRef != nullptr) {
        napi_delete_reference(env, context->crlMatchParamsRef);
        context->crlMatchParamsRef = nullptr;
    }

    if (context->certMatchParam != nullptr) {
        FreeX509CertMatchParams(context->certMatchParam);
    }
    if (context->crlMatchParam != nullptr) {
        FreeX509CrlMatchParams(context->crlMatchParam);
    }
    CF_FREE_PTR(context->retCerts.data);
    context->retCerts.count = 0;
    CF_FREE_PTR(context->retCrls.data);
    context->retCrls.count = 0;

    CF_FREE_PTR(context);
}

static void ReturnCallbackResult(napi_env env, CfCertCRLColCtx *context, napi_value result)
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

static void ReturnPromiseResult(napi_env env, CfCertCRLColCtx *context, napi_value result)
{
    if (context->errCode == CF_SUCCESS) {
        napi_resolve_deferred(env, context->deferred, result);
    } else {
        napi_reject_deferred(env, context->deferred, CertGenerateBusinessError(env, context->errCode, context->errMsg));
    }
}

static void ReturnResult(napi_env env, CfCertCRLColCtx *context, napi_value result)
{
    if (context->asyncType == ASYNC_TYPE_CALLBACK) {
        ReturnCallbackResult(env, context, result);
    } else {
        ReturnPromiseResult(env, context, result);
    }
}

static bool CreateCallbackAndPromise(
    napi_env env, CfCertCRLColCtx *context, size_t argc, size_t maxCount, napi_value callbackValue)
{
    context->asyncType = GetAsyncType(env, argc, maxCount, callbackValue);
    if (context->asyncType == ASYNC_TYPE_CALLBACK) {
        if (!CertGetCallbackFromJSParams(env, callbackValue, &context->callback)) {
            LOGE("CerCRLColletion: get callback failed!");
            return false;
        }
    } else {
        napi_create_promise(env, &context->deferred, &context->promise);
    }
    return true;
}

NapiCertCRLCollection::NapiCertCRLCollection(HcfCertCrlCollection *collection)
{
    certCrlCollection_ = collection;
}

NapiCertCRLCollection::~NapiCertCRLCollection()
{
    CfObjDestroy(this->certCrlCollection_);
}

napi_value NapiCertCRLCollection::SelectCRLsRet(napi_env env, const HcfX509CrlArray *crls)
{
    napi_value instance;
    napi_create_array(env, &instance);
    if (instance == nullptr) {
        LOGE("create return array failed!");
        return nullptr;
    }
    if (crls == nullptr) {
        LOGI("return emtpy erray!");
        return instance;
    }
    int j = 0;
    for (uint32_t i = 0; i < crls->count; ++i) {
        HcfX509Crl *crl = crls->data[i];
        NapiX509Crl *x509Crl = new (std::nothrow) NapiX509Crl(crl);
        if (x509Crl == nullptr) {
            LOGE("new x509Crl failed!");
            continue;
        }
        napi_value element = NapiX509Crl::CreateX509Crl(env, "createX509CRL");
        napi_wrap(
            env, element, x509Crl,
            [](napi_env env, void *data, void *hint) {
                NapiX509Crl *crl = static_cast<NapiX509Crl *>(data);
                delete crl;
                return;
            },
            nullptr, nullptr);
        napi_set_element(env, instance, j++, element);
    }
    return instance;
}

static void SelectCertsExecute(napi_env env, void *data)
{
    LOGI("enter SelectCertsExecute");
    CfCertCRLColCtx *context = static_cast<CfCertCRLColCtx *>(data);
    NapiCertCRLCollection *certCrlCol = context->certCRLColClass;
    HcfCertCrlCollection *collection = certCrlCol->GetCertCrlCollection();
    CfResult res = collection->selectCerts(collection, context->certMatchParam, &context->retCerts);
    if (res != CF_SUCCESS) {
        LOGE("selectCerts failed!");
        context->errCode = res;
        context->errMsg = "selectCerts failed!";
    }
}

static void SelectCertsComplete(napi_env env, napi_status status, void *data)
{
    LOGI("enter SelectCertsComplete");
    CfCertCRLColCtx *context = static_cast<CfCertCRLColCtx *>(data);
    if (context->errCode != CF_SUCCESS) {
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_value instance = ConvertCertArrToNapiValue(env, &context->retCerts);
    ReturnResult(env, context, instance);
    FreeCryptoFwkCtx(env, context);
}

static napi_value NapiSelectCerts(napi_env env, napi_callback_info info)
{
    LOGI("enter NapiSelectCerts");
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    if (thisVar == nullptr) {
        LOGE("thisVar is nullptr");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "thisVar is nullptr."));
        return nullptr;
    }
    NapiCertCRLCollection *certCrlCol = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&certCrlCol));
    if (certCrlCol == nullptr) {
        LOGE("certCrlCol is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "certCrlCol is nullptr."));
        return nullptr;
    }
    return certCrlCol->SelectCerts(env, info);
}

static bool GetCertMatchParams(napi_env env, napi_value arg, CfCertCRLColCtx *context)
{
    HcfX509CertMatchParams *param = static_cast<HcfX509CertMatchParams *>(CfMalloc(sizeof(HcfX509CertMatchParams), 0));
    if (param == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Malloc matchParams failed"));
        LOGE("malloc matchParams failed!");
        return false;
    }
    if (!BuildX509CertMatchParams(env, arg, param)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Build X509 cert match params failed"));
        LOGE("build X509 cert match params failed!");
        FreeX509CertMatchParams(param);
        return false;
    }
    context->certMatchParam = param;
    return true;
}

napi_value NapiCertCRLCollection::SelectCerts(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "CertCheckArgsCount failed."));
        LOGE("CertCheckArgsCount is not 2!");
        return nullptr;
    }

    CfCertCRLColCtx *context = static_cast<CfCertCRLColCtx *>(CfMalloc(sizeof(CfCertCRLColCtx), 0));
    if (context == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc context failed"));
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->certCRLColClass = this;

    if (!GetCertMatchParams(env, argv[PARAM0], context)) {
        CfFree(context);
        return nullptr;
    }

    if (napi_create_reference(env, thisVar, 1, &context->cfCertCRLCollectionRef) != napi_ok) {
        LOGE("create reference failed!");
        FreeCryptoFwkCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create reference failed"));
        return nullptr;
    }
    if (napi_create_reference(env, argv[PARAM0], 1, &context->certMatchParamsRef) != napi_ok) {
        LOGE("create param ref failed!");
        FreeCryptoFwkCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create param ref failed"));
        return nullptr;
    }
    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, argv[PARAM1])) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "CreateCallbackAndPromise failed"));
        LOGE("CreateCallbackAndPromise failed!");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }
    napi_create_async_work(env, nullptr, CertGetResourceName(env, "SelectCerts"), SelectCertsExecute,
        SelectCertsComplete, static_cast<void *>(context), &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    }

    return CertNapiGetNull(env);
}

static napi_value NapiSelectCRLs(napi_env env, napi_callback_info info)
{
    LOGI("enter NapiSelectCRLs");
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    if (thisVar == nullptr) {
        LOGE("thisVar is nullptr");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "thisVar is nullptr."));
        return nullptr;
    }
    NapiCertCRLCollection *certCrlCol = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&certCrlCol));
    if (certCrlCol == nullptr) {
        LOGE("certCrlCol is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "certCrlCol is nullptr."));
        return nullptr;
    }
    return certCrlCol->SelectCRLs(env, info);
}

static void SelectCRLExecute(napi_env env, void *data)
{
    CfCertCRLColCtx *context = static_cast<CfCertCRLColCtx *>(data);
    NapiCertCRLCollection *certCrlCol = context->certCRLColClass;
    HcfCertCrlCollection *collection = certCrlCol->GetCertCrlCollection();
    CfResult res = collection->selectCRLs(collection, context->crlMatchParam, &context->retCrls);
    if (res != CF_SUCCESS) {
        LOGE("selectCrls failed!");
        context->errCode = res;
        context->errMsg = "selectCrls failed!";
    }
}

static void SelectCRLComplete(napi_env env, napi_status status, void *data)
{
    CfCertCRLColCtx *context = static_cast<CfCertCRLColCtx *>(data);
    if (context->errCode != CF_SUCCESS) {
        ReturnResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    NapiCertCRLCollection *certCrlCol = context->certCRLColClass;
    napi_value instance = certCrlCol->SelectCRLsRet(env, &context->retCrls);
    ReturnResult(env, context, instance);
    FreeCryptoFwkCtx(env, context);
}

static bool GetCrlMatchParam(napi_env env, napi_value arg, CfCertCRLColCtx *context)
{
    HcfX509CrlMatchParams *param = static_cast<HcfX509CrlMatchParams *>(CfMalloc(sizeof(HcfX509CrlMatchParams), 0));
    if (param == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Malloc matchParams failed"));
        LOGE("malloc matchParams failed!");
        return false;
    }
    if (!BuildX509CrlMatchParams(env, arg, param)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Build X509 crl match params failed"));
        LOGE("build X509 crl match params failed!");
        FreeX509CrlMatchParams(param);
        return false;
    }
    context->crlMatchParam = param;

    return true;
}

napi_value NapiCertCRLCollection::SelectCRLs(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        return nullptr;
    }

    CfCertCRLColCtx *context = static_cast<CfCertCRLColCtx *>(CfMalloc(sizeof(CfCertCRLColCtx), 0));
    if (context == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc context failed"));
        LOGE("malloc context failed!");
        return nullptr;
    }
    context->certCRLColClass = this;

    if (!GetCrlMatchParam(env, argv[PARAM0], context)) {
        CfFree(context);
        return nullptr;
    }

    if (napi_create_reference(env, thisVar, 1, &context->cfCertCRLCollectionRef) != napi_ok) {
        LOGE("create reference failed!");
        FreeCryptoFwkCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create reference failed"));
        return nullptr;
    }
    if (napi_create_reference(env, argv[PARAM0], 1, &context->crlMatchParamsRef) != napi_ok) {
        LOGE("create param ref failed!");
        FreeCryptoFwkCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create param ref failed"));
        return nullptr;
    }
    if (!CreateCallbackAndPromise(env, context, argc, ARGS_SIZE_TWO, argv[PARAM1])) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "CreateCallbackAndPromise failed"));
        LOGE("BuildX509CrlMatchParamss failed!");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_create_async_work(env, nullptr, CertGetResourceName(env, "SelectCRLs"), SelectCRLExecute, SelectCRLComplete,
        static_cast<void *>(context), &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return context->promise;
    }

    return CertNapiGetNull(env);
}

static napi_value CertCRLColConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

static CfResult ParseCreateCertCRLColJSParams(napi_env env, napi_callback_info info, HcfCertCrlCollection *&out)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    HcfX509CertificateArray certs = { nullptr, 0 };
    if (argc > PARAM0 && !GetArrayCertFromNapiValue(env, argv[PARAM0], &certs)) {
        LOGE("get array cert from data failed!");
        return CF_INVALID_PARAMS;
    }
    HcfX509CrlArray crls = { nullptr, 0 };
    if (argc > PARAM1 && !GetArrayCRLFromNapiValue(env, argv[PARAM1], &crls)) {
        LOGE("get array crl from data failed!");
        CF_FREE_PTR(certs.data);
        return CF_INVALID_PARAMS;
    }

    HcfCertCrlCollection *collection = nullptr;
    CfResult res = HcfCertCrlCollectionCreate(&certs, &crls, &collection);
    if (res != CF_SUCCESS) {
        LOGE("get array crl from data failed!");
        CF_FREE_PTR(certs.data);
        CF_FREE_PTR(crls.data);
        return res;
    }
    CF_FREE_PTR(certs.data);
    CF_FREE_PTR(crls.data);
    out = collection;
    return CF_SUCCESS;
}

static napi_value NapiCreateCertCRLCollection(napi_env env, napi_callback_info info)
{
    LOGI("enter NapiCreateCertCRLCollection");
    HcfCertCrlCollection *collection = nullptr;
    CfResult res = ParseCreateCertCRLColJSParams(env, info, collection);
    if (res != CF_SUCCESS) {
        LOGE("Failed to parse JS params for create certcrlcollection object");
        napi_throw(env, CertGenerateBusinessError(env, res, "parse param failed."));
        return nullptr;
    }
    NapiCertCRLCollection *napiObject = new (std::nothrow) NapiCertCRLCollection(collection);
    if (napiObject == nullptr) {
        LOGE("Failed to create napi certcrlcolletion class");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc napiObject failed."));
        return nullptr;
    }

    napi_value instance = NapiCertCRLCollection::CreateCertCRLCollection(env);
    napi_wrap(
        env, instance, napiObject,
        [](napi_env env, void *data, void *hint) {
            NapiCertCRLCollection *objClass = static_cast<NapiCertCRLCollection *>(data);
            delete objClass;
            return;
        },
        nullptr, nullptr);

    return instance;
}

void NapiCertCRLCollection::DefineCertCRLCollectionJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createCertCRLCollection", NapiCreateCertCRLCollection),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor certCrlColDesc[] = {
        DECLARE_NAPI_FUNCTION("selectCerts", NapiSelectCerts),
        DECLARE_NAPI_FUNCTION("selectCRLs", NapiSelectCRLs),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "CertCrlCollection", NAPI_AUTO_LENGTH, CertCRLColConstructor, nullptr,
        sizeof(certCrlColDesc) / sizeof(certCrlColDesc[0]), certCrlColDesc, &constructor);

    napi_create_reference(env, constructor, 1, &classRef_);
}

napi_value NapiCertCRLCollection::CreateCertCRLCollection(napi_env env)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);
    return instance;
}
} // namespace CertFramework
} // namespace OHOS
