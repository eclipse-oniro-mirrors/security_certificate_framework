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

#include "napi_cert_chain_validator.h"

#include "napi/native_common.h"
#include "napi/native_api.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "utils.h"
#include "cf_result.h"
#include "cf_object_base.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_cert_crl_common.h"
#include "napi_x509_certificate.h"
#include "napi_x509_cert_chain_validate_params.h"
#include "napi_x509_cert_chain_validate_result.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiCertChainValidator::classRef_ = nullptr;

struct CfCtx {
    AsyncType asyncType = ASYNC_TYPE_CALLBACK;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref cfRef = nullptr;

    NapiCertChainValidator *ccvClass = nullptr;
    HcfCertChainData *certChainData = nullptr;

    int32_t errCode = 0;
    const char *errMsg = nullptr;
};

struct ValidateX509CertCtx {
    napi_deferred deferred = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref cfRef = nullptr;
    napi_ref certRef = nullptr;       /* Reference to cert object */
    napi_ref paramsRef = nullptr;     /* Reference to params object */

    NapiCertChainValidator *ccvClass = nullptr;
    HcfX509Certificate *cert = nullptr;
    HcfX509CertValidatorParams params = {};

    int32_t errCode = 0;
    const char *errMsg = nullptr;
    HcfVerifyCertResult result = {};
    CfObject **certObj = nullptr;
    uint32_t certObjCount = 0;
};

NapiCertChainValidator::NapiCertChainValidator(HcfCertChainValidator *certChainValidator)
{
    this->certChainValidator_ = certChainValidator;
}

NapiCertChainValidator::~NapiCertChainValidator()
{
    CfObjDestroy(this->certChainValidator_);
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

    if (context->certChainData != nullptr) {
        CfFree(context->certChainData->data);
        context->certChainData->data = nullptr;
        CfFree(context->certChainData);
        context->certChainData = nullptr;
    }

    CfFree(context);
}

static void FreeValidateX509CertCtx(napi_env env, ValidateX509CertCtx *context)
{
    if (context == nullptr) {
        return;
    }

    if (context->asyncWork != nullptr) {
        napi_delete_async_work(env, context->asyncWork);
    }

    if (context->cfRef != nullptr) {
        napi_delete_reference(env, context->cfRef);
        context->cfRef = nullptr;
    }

    if (context->certRef != nullptr) {
        napi_delete_reference(env, context->certRef);
        context->certRef = nullptr;
    }

    if (context->paramsRef != nullptr) {
        napi_delete_reference(env, context->paramsRef);
        context->paramsRef = nullptr;
    }

    CfFree(context);
}

static void FreeValidateX509CertCtxComplete(napi_env env, ValidateX509CertCtx *context)
{
    if (context == nullptr) {
        return;
    }
    FreeX509CertValidatorParams(context->params);
    FreeVerifyCertResult(context->result, context->certObj, context->certObjCount);
    FreeValidateX509CertCtx(env, context);
}

static bool CreateValidateX509CertRefs(napi_env env, napi_value thisVar, napi_value certArg,
    napi_value paramsArg, ValidateX509CertCtx *context)
{
    if (napi_create_reference(env, thisVar, 1, &context->cfRef) != napi_ok) {
        LOGE("create thisVar reference failed!");
        return false;
    }
    if (napi_create_reference(env, certArg, 1, &context->certRef) != napi_ok) {
        LOGE("create cert reference failed!");
        napi_delete_reference(env, context->cfRef);
        context->cfRef = nullptr;
        return false;
    }
    if (napi_create_reference(env, paramsArg, 1, &context->paramsRef) != napi_ok) {
        LOGE("create params reference failed!");
        napi_delete_reference(env, context->certRef);
        context->certRef = nullptr;
        napi_delete_reference(env, context->cfRef);
        context->cfRef = nullptr;
        return false;
    }
    return true;
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

static void ValidateExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    HcfCertChainValidator *validator = context->ccvClass->GetCertChainValidator();
    context->errCode = validator->validate(validator, context->certChainData);
    if (context->errCode != CF_SUCCESS) {
        LOGE("validate cert chain failed!");
        context->errMsg = "validate cert chain failed";
    }
}

static void ValidateComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    ReturnResult(env, context, CertNapiGetNull(env));
    FreeCryptoFwkCtx(env, context);
}

static void FreeCreatedCertObjects(CfObject **certObj, uint32_t count)
{
    for (uint32_t j = 0; j < count; j++) {
        if (certObj[j] != nullptr) {
            certObj[j]->destroy(&certObj[j]);
        }
    }
    CfFree(certObj);
}

static void ValidateX509CertExecute(napi_env env, void *data)
{
    ValidateX509CertCtx *context = static_cast<ValidateX509CertCtx *>(data);
    if (context == nullptr || context->ccvClass == nullptr) {
        LOGE("context or ccvClass is nullptr!");
        return;
    }
    HcfCertChainValidator *validator = context->ccvClass->GetCertChainValidator();
    if (validator == nullptr) {
        LOGE("validator is nullptr!");
        context->errCode = CF_ERR_CRYPTO_OPERATION;
        context->errMsg = "validator is nullptr";
        return;
    }
    context->errCode = validator->validateX509Cert(validator, context->cert, &context->params, &context->result);
    if (context->errCode != CF_SUCCESS) {
        LOGE("validate X509 cert failed, errCode = %{public}d!", context->errCode);
        context->errMsg = context->result.errorMsg;
        return;
    }

    if (context->result.certs.data == nullptr || context->result.certs.count == 0) {
        context->errCode = CF_ERR_INTERNAL;
        context->errMsg = "validate X509 cert success, but cert chain is empty";
        return;
    }

    /* Create CfObject for each cert in result chain (in async thread to avoid blocking JS thread) */
    context->certObjCount = context->result.certs.count;
    context->certObj = static_cast<CfObject **>(CfMallocEx(context->certObjCount * sizeof(CfObject *)));
    if (context->certObj == nullptr) {
        LOGE("malloc certObj array failed!");
        context->errCode = CF_ERR_MALLOC;
        context->errMsg = "validate X509 cert success, but malloc certObj array failed";
        return;
    }
    for (uint32_t i = 0; i < context->certObjCount; i++) {
        CfResult ret = GetCertObject(context->result.certs.data[i], &context->certObj[i]);
        if (ret != CF_SUCCESS) {
            LOGE("GetCertObject failed at index %{public}u", i);
            context->errCode = ret;
            context->errMsg = "validate X509 cert success, but getCertObject failed";
            FreeCreatedCertObjects(context->certObj, i);
            context->certObj = nullptr;
            context->certObjCount = 0;
            return;
        }
    }
}

static void ValidateX509CertComplete(napi_env env, napi_status status, void *data)
{
    ValidateX509CertCtx *context = static_cast<ValidateX509CertCtx *>(data);
    if (context->errCode == CF_SUCCESS) {
        napi_value result = nullptr;
        CfResult ret = BuildVerifyCertResultJS(env, &context->result, context->certObj, context->certObjCount, &result);
        if (ret != CF_SUCCESS) {
            napi_reject_deferred(env, context->deferred,
                CertGenerateBusinessError(env, ret, "build verify cert result failed"));
        } else {
            napi_resolve_deferred(env, context->deferred, result);
        }
    } else {
        napi_reject_deferred(env, context->deferred,
            CertGenerateBusinessError(env, context->errCode, context->errMsg));
    }
    FreeValidateX509CertCtxComplete(env, context);
}

static ValidateX509CertCtx *CreateValidateX509CertContext(napi_env env, napi_value thisVar,
    napi_value certArg, napi_value paramsArg, NapiCertChainValidator *validator)
{
    ValidateX509CertCtx *context = static_cast<ValidateX509CertCtx *>(CfMallocEx(sizeof(ValidateX509CertCtx)));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to allocate memory"));
        return nullptr;
    }
    context->ccvClass = validator;
    NapiX509Certificate *napiCert = nullptr;
    napi_unwrap(env, certArg, reinterpret_cast<void **>(&napiCert));
    if (napiCert == nullptr) {
        LOGE("napi cert object is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Invalid X509Cert parameter"));
        CfFree(context);
        return nullptr;
    }
    context->cert = napiCert->GetX509Cert();
    char *errMsg = nullptr;
    CfResult ret = BuildX509CertValidatorParams(env, paramsArg, context->params, &errMsg);
    if (ret != CF_SUCCESS) {
        const char *finalErrMsg = errMsg ? errMsg : "Build validator params failed!";
        LOGE("Build validator params failed: %{public}s", finalErrMsg);
        napi_throw(env, CertGenerateBusinessError(env, ret, finalErrMsg));
        if (errMsg) {
            CfFree(errMsg);
        }
        CfFree(context);
        return nullptr;
    }
    if (!CreateValidateX509CertRefs(env, thisVar, certArg, paramsArg, context)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "Failed to create reference"));
        FreeValidateX509CertCtxComplete(env, context);
        return nullptr;
    }
    return context;
}

napi_value NapiCertChainValidator::ValidateX509Cert(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_TWO, false)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Invalid parameter count"));
        return nullptr;
    }
    ValidateX509CertCtx *context = CreateValidateX509CertContext(env, thisVar, argv[PARAM0], argv[PARAM1], this);
    if (context == nullptr) {
        return nullptr;
    }
    napi_value promise = nullptr;
    napi_create_promise(env, &context->deferred, &promise);
    napi_status status = napi_create_async_work(
        env, nullptr, CertGetResourceName(env, "ValidateX509Cert"),
        ValidateX509CertExecute, ValidateX509CertComplete,
        static_cast<void *>(context), &context->asyncWork);
    if (status != napi_ok) {
        LOGE("create async work failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "create async work failed"));
        FreeValidateX509CertCtxComplete(env, context);
        return nullptr;
    }
    status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        LOGE("queue async work failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "queue async work failed"));
        FreeValidateX509CertCtxComplete(env, context);
        return nullptr;
    }
    return promise;
}

napi_value NapiCertChainValidator::Validate(napi_env env, napi_callback_info info)
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
    context->ccvClass = this;

    context->asyncType = GetAsyncType(env, argc, ARGS_SIZE_TWO, argv[PARAM1]);
    if (!GetCertChainFromValue(env, argv[PARAM0], &context->certChainData)) {
        LOGE("get cert chain data from napi value failed!");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    if (napi_create_reference(env, thisVar, 1, &context->cfRef) != napi_ok) {
        LOGE("create reference failed!");
        FreeCryptoFwkCtx(env, context);
        return nullptr;
    }

    napi_value promise = nullptr;
    if (context->asyncType == ASYNC_TYPE_CALLBACK) {
        if (!CertGetCallbackFromJSParams(env, argv[PARAM1], &context->callback)) {
            LOGE("get callback failed!");
            FreeCryptoFwkCtx(env, context);
            return nullptr;
        }
    } else {
        napi_create_promise(env, &context->deferred, &promise);
    }

    napi_create_async_work(
        env, nullptr, CertGetResourceName(env, "Validate"),
        ValidateExecute,
        ValidateComplete,
        static_cast<void *>(context),
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    if (context->asyncType == ASYNC_TYPE_PROMISE) {
        return promise;
    } else {
        return CertNapiGetNull(env);
    }
}

static napi_value NapiValidate(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = 0;
    napi_get_cb_info(env, info, &argc, nullptr, &thisVar, nullptr);
    NapiCertChainValidator *certChainValidator = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&certChainValidator));
    if (certChainValidator == nullptr) {
        LOGE("certChainValidator is nullptr!");
        return nullptr;
    }

    /* Need at least 1 parameter for validate */
    if (argc < ARGS_SIZE_ONE) {
        LOGE("Invalid parameter count, expected at least 1");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Invalid parameter count"));
        return nullptr;
    }

    /* Get the second parameter if exists to determine which function to call */
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    if (argc >= ARGS_SIZE_TWO) {
        napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[PARAM1], &valueType);
        /* If the second parameter is a function, it's the old callback interface */
        if (valueType == napi_function) {
            return certChainValidator->Validate(env, info);
        }
        /* If the second parameter is an object, it's the new params interface */
        if (valueType == napi_object) {
            return certChainValidator->ValidateX509Cert(env, info);
        }
        /* Invalid second parameter type */
        LOGE("Invalid second parameter type, expected function or object");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "The second parameter type is incorrect"));
        return nullptr;
    }

    /* Default: old validate(certChainData) signature */
    return certChainValidator->Validate(env, info);
}

static napi_value CertChainValidatorConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

static bool WrapCertChainValidatorInstance(napi_env env, napi_value instance, HcfCertChainValidator *certChainValidator)
{
    NapiCertChainValidator *ccvClass = new (std::nothrow) NapiCertChainValidator(certChainValidator);
    if (!ccvClass) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to create a ccv class"));
        LOGE("Failed to create a ccv class");
        CfObjDestroy(certChainValidator);
        return false;
    }
    napi_status status = napi_wrap(
        env, instance, ccvClass,
        [](napi_env env, void* data, void *hint) {
            delete static_cast<NapiCertChainValidator *>(data);
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "failed to wrap obj!"));
        LOGE("failed to wrap obj!");
        delete ccvClass;
        return false;
    }
    return true;
}

napi_value NapiCertChainValidator::CreateCertChainValidator(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    if (argc != ARGS_SIZE_ONE) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "invalid params count"));
        LOGE("invalid params count!");
        return nullptr;
    }

    std::string algorithm;
    if (!CertGetStringFromJSParams(env, argv[PARAM0], algorithm)) {
        LOGE("Failed to get algorithm.");
        return nullptr;
    }
    HcfCertChainValidator *certChainValidator = nullptr;
    CfResult res = HcfCertChainValidatorCreate(algorithm.c_str(), &certChainValidator);
    if (res != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, res, "create cert chain validator failed"));
        LOGE("Failed to create c cert chain validator.");
        return nullptr;
    }
    const char *returnAlgorithm = certChainValidator->getAlgorithm(certChainValidator);
    napi_value algValue = nullptr;
    napi_create_string_utf8(env, returnAlgorithm, NAPI_AUTO_LENGTH, &algValue);
    napi_value constructor = nullptr;
    napi_value validatorInstance = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &validatorInstance);
    napi_set_named_property(env, validatorInstance, CERT_TAG_ALGORITHM.c_str(), algValue);
    if (!WrapCertChainValidatorInstance(env, validatorInstance, certChainValidator)) {
        return nullptr;
    }
    return validatorInstance;
}

void NapiCertChainValidator::DefineCertChainValidatorJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createCertChainValidator", CreateCertChainValidator),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor validatorDesc[] = {
        DECLARE_NAPI_FUNCTION("validate", NapiValidate),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "CertChainValidator", NAPI_AUTO_LENGTH, CertChainValidatorConstructor, nullptr,
        sizeof(validatorDesc) / sizeof(validatorDesc[0]), validatorDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // namespace CertFramework
} // namespace OHOS