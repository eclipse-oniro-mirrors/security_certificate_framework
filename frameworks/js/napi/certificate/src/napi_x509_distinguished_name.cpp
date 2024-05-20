/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "napi_x509_distinguished_name.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "utils.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiX509DistinguishedName::classRef_ = nullptr;

struct CfCtx {
    napi_value promise = nullptr;
    napi_deferred deferred = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref cfRef = nullptr;

    CfBlob *inPara = nullptr;
    bool paraIsString = true;
    HcfX509DistinguishedName *x509Name = nullptr;
    NapiX509DistinguishedName *nameClass = nullptr;
    int32_t errCode = 0;
    const char *errMsg = nullptr;
};

NapiX509DistinguishedName::NapiX509DistinguishedName(HcfX509DistinguishedName *x509Name_)
{
    this->x509Name_ = x509Name_;
}

NapiX509DistinguishedName::~NapiX509DistinguishedName()
{
    CfObjDestroy(this->x509Name_);
}

static void FreeCryptoFwkCtx(napi_env env, CfCtx *context)
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

    if (context->inPara != nullptr) {
        CfFree(context->inPara);
        context->inPara = nullptr;
    }

    CfFree(context);
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

void NapiX509DistinguishedName::CreateDistinguishedNameExecute(napi_env env, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);

    context->errCode = HcfX509DistinguishedNameCreate(context->inPara, context->paraIsString, &context->x509Name);
    if (context->errCode != CF_SUCCESS) {
        context->errMsg = "create x509DistinguishedName failed";
    }
}

void NapiX509DistinguishedName::CreateDistinguishedNameComplete(napi_env env, napi_status status, void *data)
{
    CfCtx *context = static_cast<CfCtx *>(data);
    if (context->errCode != CF_SUCCESS) {
        LOGE("call create x509DistinguisehdName failed!");
        ReturnPromiseResult(env, context, nullptr);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_value instance = CreateX509DistinguishedName(env);
    NapiX509DistinguishedName *x509NameClass = new (std::nothrow) NapiX509DistinguishedName(context->x509Name);
    if (x509NameClass == nullptr) {
        context->errCode = CF_ERR_MALLOC;
        context->errMsg = "Failed to create x509DistinguisehdName class";
        LOGE("Failed to create x509DistinguisehdName class");
        ReturnPromiseResult(env, context, nullptr);
        CfObjDestroy(context->x509Name);
        FreeCryptoFwkCtx(env, context);
        return;
    }
    napi_wrap(
        env, instance, x509NameClass,
        [](napi_env env, void *data, void *hint) {
            NapiX509DistinguishedName *nameClass = static_cast<NapiX509DistinguishedName *>(data);
            delete nameClass;
            return;
        },
        nullptr, nullptr);
    ReturnPromiseResult(env, context, instance);
    FreeCryptoFwkCtx(env, context);
}

napi_value NapiX509DistinguishedName::GetEncoded(napi_env env, napi_callback_info info)
{
    HcfX509DistinguishedName *x509Name = GetX509DistinguishedName();
    CfEncodingBlob blob = {nullptr, 0, CF_FORMAT_DER};
    CfResult ret = x509Name->getEncode(x509Name, &blob);
    if (ret != CF_SUCCESS) {
        LOGE("Distinguished Name get encoded failed");
        napi_throw(env, CertGenerateBusinessError(env, ret, "Distinguished Name get encoded failed"));
        return nullptr;
    }
    napi_value result = ConvertEncodingBlobToNapiValue(env, &blob);
    CfEncodingBlobDataFree(&blob);
    return result;
}

napi_value NapiX509DistinguishedName::GetName(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, false)) {
        LOGE("CertCheckArgsCount error");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "CertCheckArgsCount failed"));
        return nullptr;
    }
    HcfX509DistinguishedName *x509Name = GetX509DistinguishedName();
    if (argc == PARAM0) {
        LOGI("GetName PARAM0");
        CfBlob blob = { 0, nullptr };
        CfResult ret = x509Name->getName(x509Name, NULL, &blob, NULL);
        if (ret != CF_SUCCESS) {
            LOGE("Distinguished Name get name failed");
            napi_throw(env, CertGenerateBusinessError(env, ret, "Distinguished Name get name failed"));
            return nullptr;
        }

        napi_value result = nullptr;
        napi_create_string_utf8(env, reinterpret_cast<char *>(blob.data), blob.size, &result);
        CfBlobDataFree(&blob);
        return result;
    } else if (argc == ARGS_SIZE_ONE) {
        LOGI("GetName PARAM1");
        CfBlob *inPara = CertGetBlobFromStringJSParams(env, argv[PARAM0]);
        if (inPara != nullptr) {
            CfArray outArr = { nullptr, CF_FORMAT_DER, 0 };
            CfResult ret = x509Name->getName(x509Name, inPara, NULL, &outArr);
            if (ret != CF_SUCCESS) {
                LOGE("Distinguished Name get name failed");
                CfBlobFree(&inPara);
                napi_throw(env, CertGenerateBusinessError(env, ret, "Distinguished Name get name failed"));
                return nullptr;
            }

            napi_value result = ConvertArrayStringToNapiValue(env, &outArr);
            CfBlobFree(&inPara);
            CfArrayDataClearAndFree(&outArr);
            return result;
        }
    }
    return nullptr;
}

static napi_value NapiGetEncoded(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509DistinguishedName *x509Name = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Name));
    if (x509Name == nullptr) {
        LOGE("x509Name is nullptr!");
        return nullptr;
    }
    return x509Name->GetEncoded(env, info);
}

static napi_value NapiGetName(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiX509DistinguishedName *x509Name = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&x509Name));
    if (x509Name == nullptr) {
        LOGE("x509Name is nullptr!");
        return nullptr;
    }
    return x509Name->GetName(env, info);
}

static napi_value X509DistinguishedNameConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiX509DistinguishedName::NapiCreateX509DistinguishedName(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, false)) {
        LOGE("CertCheckArgsCount error");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "CertCheckArgsCount failed"));
        return nullptr;
    }

    CfCtx *context = static_cast<CfCtx *>(CfMalloc(sizeof(CfCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "CfMalloc failed"));
        return nullptr;
    }

    napi_create_promise(env, &context->deferred, &context->promise);

    napi_valuetype valueType;
    napi_typeof(env, argv[PARAM0], &valueType);
    if (valueType != napi_string) {
        LOGI("NapiCreateX509DistinguishedName nameDer");
        context->inPara = CertGetBlobFromUint8ArrJSParams(env, argv[PARAM0]);
        context->paraIsString = false;
    } else {
        LOGI("NapiCreateX509DistinguishedName nameStr");
        context->inPara = CertGetBlobFromStringJSParams(env, argv[PARAM0]);
        context->paraIsString = true;
    }

    if (napi_create_reference(env, thisVar, 1, &context->cfRef) != napi_ok) {
        LOGE("create reference failed!");
        FreeCryptoFwkCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "Create reference failed"));
        return nullptr;
    }

    napi_create_async_work(env, nullptr, CertGetResourceName(env, "createX500DistinguishedName"),
        CreateDistinguishedNameExecute,
        CreateDistinguishedNameComplete,
        static_cast<void *>(context),
        &context->asyncWork);

    napi_queue_async_work(env, context->asyncWork);
    return context->promise;
}

void NapiX509DistinguishedName::DefineX509DistinguishedNameJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createX500DistinguishedName", NapiCreateX509DistinguishedName),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor x509NameDesc[] = {
        DECLARE_NAPI_FUNCTION("getEncoded", NapiGetEncoded),
        DECLARE_NAPI_FUNCTION("getName", NapiGetName),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "X500DistinguishedName", NAPI_AUTO_LENGTH, X509DistinguishedNameConstructor, nullptr,
        sizeof(x509NameDesc) / sizeof(x509NameDesc[0]), x509NameDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
    LOGI("DefineX509DistinguishedNameJSClass end");
}

napi_value NapiX509DistinguishedName::CreateX509DistinguishedName(napi_env env)
{
    napi_value constructor = nullptr;
    napi_value instance = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);
    return instance;
}
} // namespace CertFramework
} // namespace OHOS
