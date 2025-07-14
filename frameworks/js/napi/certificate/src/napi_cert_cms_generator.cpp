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

#include "napi_cert_cms_generator.h"
#include "napi/native_common.h"
#include "napi/native_api.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "utils.h"
#include "cf_result.h"
#include "cf_object_base.h"
#include "securec.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_x509_certificate.h"
#include "napi_common.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiCertCmsGenerator::classRef_ = nullptr;
struct CmsDoFinalCtx {
    napi_env env = nullptr;

    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref generatorRef = nullptr;

    HcfCmsGenerator *cmsGenerator = nullptr;
    CfBlob *content = nullptr;
    HcfCmsGeneratorOptions *options = nullptr;

    CfResult errCode = CF_SUCCESS;
    const char *errMsg = nullptr;

    CfBlob outBlob = { 0, nullptr };
};

static void FreeCmsSignerOptions(HcfCmsSignerOptions *options)
{
    if (options != nullptr) {
        CfFree(options->mdName);
        options->mdName = nullptr;
        CfFree(options);
        options = nullptr;
    }
}

static void FreeCmsGeneratorOptions(HcfCmsGeneratorOptions *options)
{
    if (options != nullptr) {
        CfFree(options);
        options = nullptr;
    }
}

static void FreeCmsDoFinalCtx(napi_env env, CmsDoFinalCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
    }
    if (ctx->generatorRef != nullptr) {
        napi_delete_reference(env, ctx->generatorRef);
        ctx->generatorRef = nullptr;
    }
    if (ctx->content != nullptr) {
        CfBlobDataFree(ctx->content);
        ctx->content = nullptr;
    }
    if (ctx->options != nullptr) {
        FreeCmsGeneratorOptions(ctx->options);
        ctx->options = nullptr;
    }
    if (ctx->outBlob.data != nullptr) {
        CfBlobDataFree(&ctx->outBlob);
        ctx->outBlob.data = nullptr;
    }
    CfFree(ctx);
}

NapiCertCmsGenerator::NapiCertCmsGenerator(HcfCmsGenerator *certCmsGenerator)
{
    this->cmsGenerator_ = certCmsGenerator;
}

NapiCertCmsGenerator::~NapiCertCmsGenerator()
{
    CfObjDestroy(this->cmsGenerator_);
}

napi_value NapiCertCmsGenerator::AddSigner(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = ARGS_SIZE_THREE;
    size_t argc = expectedArgc;
    napi_value argv[ARGS_SIZE_THREE] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (argc != expectedArgc) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "wrong argument num."));
        LOGE("wrong argument num. require %{public}zu arguments. [Argc]: %{public}zu!", ARGS_SIZE_THREE, argc);
        return nullptr;
    }

    NapiCertCmsGenerator *napiCmsGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCmsGenerator));
    if (status != napi_ok || napiCmsGenerator == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "failed to unwrap napi cms generator obj."));
        LOGE("failed to unwrap napi cms generator obj.");
        return nullptr;
    }

    HcfCmsGenerator *cmsGenerator = napiCmsGenerator->GetCertCmsGenerator();
    NapiX509Certificate *napiX509Cert = nullptr;
    napi_unwrap(env, argv[PARAM0], reinterpret_cast<void **>(&napiX509Cert));
    if (napiX509Cert == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "napiX509Cert is null."));
        LOGE("napiX509Cert is null!");
        return nullptr;
    }

    PrivateKeyInfo *privateKey = nullptr;
    if (!GetPrivateKeyInfoFromValue(env, argv[PARAM1], &privateKey)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get private key info from data failed!"));
        LOGE("get private key info from data failed!");
        return nullptr;
    }

    HcfCmsSignerOptions *options = nullptr;
    if (!GetCmsSignerOptionsFromValue(env, argv[PARAM2], &options)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get cms signer options from data failed!"));
        LOGE("get cms signer options from data failed!");
        FreePrivateKeyInfo(privateKey);
        return nullptr;
    }
 
    HcfX509Certificate *certificate = napiX509Cert->GetX509Cert();
    CfResult ret = cmsGenerator->addSigner(cmsGenerator, &(certificate->base), privateKey, options);
    FreePrivateKeyInfo(privateKey);
    FreeCmsSignerOptions(options);
    if (ret != CF_SUCCESS) {
        LOGE("add signer fail.");
        napi_throw(env, CertGenerateBusinessError(env, ret, "add signer fail."));
        return nullptr;
    }
    return NapiGetNull(env);
}

static napi_value NapiAddSigner(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsGenerator *cmsGenerator = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsGenerator));
    if (cmsGenerator == nullptr) {
        LOGE("cmsGenerator is nullptr!");
        return nullptr;
    }
    return cmsGenerator->AddSigner(env, info);
}

napi_value NapiCertCmsGenerator::AddCert(napi_env env, napi_callback_info info)
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

    NapiCertCmsGenerator *napiCmsGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCmsGenerator));
    if (status != napi_ok || napiCmsGenerator == nullptr) {
        LOGE("failed to unwrap napi cms generator obj.");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "failed to unwrap napi cms generator obj."));
        return nullptr;
    }

    HcfCmsGenerator *cmsGenerator = napiCmsGenerator->GetCertCmsGenerator();
    HcfX509Certificate *certificate = napiX509Cert->GetX509Cert();

    CfResult ret = cmsGenerator->addCert(cmsGenerator, &(certificate->base));
    if (ret != CF_SUCCESS) {
        LOGE("add cert fail.");
        napi_throw(env, CertGenerateBusinessError(env, ret, "add cert fail."));
        return nullptr;
    }
    napi_value instance = NapiGetNull(env);
    return instance;
}

static napi_value NapiAddCert(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsGenerator *cmsGenerator = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsGenerator));
    if (cmsGenerator == nullptr) {
        LOGE("cmsGenerator is nullptr!");
        return nullptr;
    }
    return cmsGenerator->AddCert(env, info);
}

static bool BuildCmsDoFinalCtx(napi_env env, napi_callback_info info, CmsDoFinalCtx *ctx)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = ARGS_SIZE_TWO;
    size_t argc = expectedArgc;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != expectedArgc) && (argc != (expectedArgc - 1))) {
        LOGE("wrong argument num. require %{public}zu arguments. [Argc]: %{public}zu!", expectedArgc, argc);
        return false;
    }
    NapiCertCmsGenerator *napiCmsGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCmsGenerator));
    if (status != napi_ok || napiCmsGenerator == nullptr) {
        LOGE("failed to unwrap napi cms generator obj.");
        return false;
    }
    ctx->content = CertGetBlobFromUint8ArrJSParams(env, argv[PARAM0]);
    if (ctx->content == nullptr) {
        return false;
    }
    if (argc == expectedArgc) {
        if (!GetCmsGeneratorOptionsFromValue(env, argv[PARAM1], &ctx->options)) {
            return false;
        }
    }
    ctx->cmsGenerator = napiCmsGenerator->GetCertCmsGenerator();
    if (napi_create_reference(env, thisVar, 1, &ctx->generatorRef) != napi_ok) {
        LOGE("create generator ref failed!");
        return false;
    }
    napi_create_promise(env, &ctx->deferred, &ctx->promise);
    return true;
}

static void CmsDoFinalAsyncWorkProcess(napi_env env, void *data)
{
    CmsDoFinalCtx *ctx = static_cast<CmsDoFinalCtx *>(data);
    ctx->errCode = ctx->cmsGenerator->doFinal(ctx->cmsGenerator, ctx->content, ctx->options, &(ctx->outBlob));
    if (ctx->errCode != CF_SUCCESS) {
        LOGE("Cms do final fail.");
        ctx->errMsg = "Cms do final fail.";
    }
}

static void ReturnPromiseResult(napi_env env, CmsDoFinalCtx *ctx, napi_value result)
{
    if (ctx->errCode == CF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            CertGenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void CmsDoFinalAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    CmsDoFinalCtx *ctx = static_cast<CmsDoFinalCtx *>(data);
    if (ctx->errCode != CF_SUCCESS) {
        ReturnPromiseResult(env, ctx, nullptr);
        FreeCmsDoFinalCtx(env, ctx);
        return;
    }
    napi_value instance = nullptr;
    if (ctx->options->outFormat == CMS_PEM) {
        napi_create_string_utf8(env, reinterpret_cast<char *>(ctx->outBlob.data), ctx->outBlob.size, &instance);
    } else {
        instance = ConvertBlobToUint8ArrNapiValue(env, &ctx->outBlob);
    }
    ReturnPromiseResult(env, ctx, instance);
    FreeCmsDoFinalCtx(env, ctx);
}

static napi_value NewCmsDoFinalAsyncWork(napi_env env, CmsDoFinalCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "doFinal", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            CmsDoFinalAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            CmsDoFinalAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    return ctx->promise;
}

napi_value NapiCertCmsGenerator::DoFinal(napi_env env, napi_callback_info info)
{
    CmsDoFinalCtx *ctx = static_cast<CmsDoFinalCtx *>(CfMalloc(sizeof(CmsDoFinalCtx), 0));
    if (ctx == nullptr) {
        LOGE("create context fail.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "create context fail!"));
        return nullptr;
    }
    ctx->options = static_cast<HcfCmsGeneratorOptions *>(CfMalloc(sizeof(HcfCmsGeneratorOptions), 0));
    if (ctx->options == nullptr) {
        LOGE("create options fail.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "create options fail!"));
        FreeCmsDoFinalCtx(env, ctx);
        return nullptr;
    }
    ctx->options->dataFormat = BINARY;
    ctx->options->outFormat = CMS_DER;
    ctx->options->isDetachedContent = false;

    if (!BuildCmsDoFinalCtx(env, info, ctx)) {
        LOGE("build context fail.");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "build cms doFinal Ctx fail."));
        FreeCmsDoFinalCtx(env, ctx);
        return nullptr;
    }
    return NewCmsDoFinalAsyncWork(env, ctx);
}

static napi_value NapiDoFinal(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsGenerator *cmsGenerator = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsGenerator));
    if (cmsGenerator == nullptr) {
        LOGE("cmsGenerator is nullptr!");
        return nullptr;
    }
    return cmsGenerator->DoFinal(env, info);
}

static napi_value GetDoFinalResult(napi_env env, NapiCertCmsGenerator *napiCmsGenerator, CfBlob *content,
    HcfCmsGeneratorOptions *options)
{
    CfBlob outBlob = { 0,  nullptr, };
    HcfCmsGenerator *cmsGenerator = napiCmsGenerator->GetCertCmsGenerator();
    CfResult ret = cmsGenerator->doFinal(cmsGenerator, content, options, &outBlob);
    if (ret != CF_SUCCESS) {
        LOGE("Cms do final fail.");
        napi_throw(env, CertGenerateBusinessError(env, ret, "Cms do final fail."));
        CfBlobDataFree(content);
        FreeCmsGeneratorOptions(options);
        return nullptr;
    }
    napi_value instance = nullptr;
    if (options->outFormat == CMS_PEM) {
        napi_create_string_utf8(env, reinterpret_cast<char *>(outBlob.data), outBlob.size, &instance);
    } else {
        instance = ConvertBlobToUint8ArrNapiValue(env, &outBlob);
    }
    CfBlobDataFree(&outBlob);
    CfBlobDataFree(content);
    FreeCmsGeneratorOptions(options);
    return instance;
}

napi_value NapiCertCmsGenerator::DoFinalSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    size_t expectedArgc = ARGS_SIZE_TWO;
    size_t argc = expectedArgc;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if ((argc != expectedArgc) && (argc != (expectedArgc - 1))) {
        LOGE("wrong argument num. require %{public}zu arguments. [Argc]: %{public}zu!", expectedArgc, argc);
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "wrong argument num."));
        return nullptr;
    }
    NapiCertCmsGenerator *napiCmsGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCmsGenerator));
    if (status != napi_ok || napiCmsGenerator == nullptr) {
        LOGE("failed to unwrap napi cms generator obj.");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "failed to unwrap napi cms generator obj."));
        return nullptr;
    }
    CfBlob *content = CertGetBlobFromUint8ArrJSParams(env, argv[PARAM0]);
    if (content == nullptr) {
        return nullptr;
    }
    HcfCmsGeneratorOptions *options = nullptr;
    options = static_cast<HcfCmsGeneratorOptions *>(CfMalloc(sizeof(HcfCmsGeneratorOptions), 0));
    if (options == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc options failed!"));
        CfBlobDataFree(content);
        return nullptr;
    }
    options->dataFormat = BINARY;
    options->outFormat = CMS_DER;
    options->isDetachedContent = false;
    if (argc == expectedArgc) {
        if (!GetCmsGeneratorOptionsFromValue(env, argv[PARAM1], &options)) {
            napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS,
            "GetCmsGeneratorOptionsFromValue failed!"));
            CfBlobDataFree(content);
            FreeCmsGeneratorOptions(options);
            return nullptr;
        }
    }
    return GetDoFinalResult(env, napiCmsGenerator, content, options);
}

static napi_value NapiDoFinalSync(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsGenerator *cmsGenerator = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsGenerator));
    if (cmsGenerator == nullptr) {
        LOGE("cmsGenerator is nullptr!");
        return nullptr;
    }
    return cmsGenerator->DoFinalSync(env, info);
}

static napi_value CmsGeneratorConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiCertCmsGenerator::CreateCmsGenerator(napi_env env, napi_callback_info info)
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

    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, argc, argv, &instance);

    int32_t cmsContentType = 0;
    if (!CertGetInt32FromJSParams(env, argv[PARAM0], cmsContentType)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get cmsContentType failed!"));
        LOGE("get cmsContentType failed!");
        return nullptr;
    }
    HcfCmsGenerator *cmsGenerator = nullptr;
    CfResult res = HcfCreateCmsGenerator(static_cast<HcfCmsContentType>(cmsContentType), &cmsGenerator);
    if (res != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, res, "create cms generator failed"));
        LOGE("Failed to create cms generator.");
        return nullptr;
    }
   
    NapiCertCmsGenerator *napiCmsGenerator = new (std::nothrow) NapiCertCmsGenerator(cmsGenerator);
    if (napiCmsGenerator == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to create a cmsGenerator class"));
        LOGE("Failed to create a cmsGenerator class");
        CfObjDestroy(cmsGenerator);
        return nullptr;
    }

    napi_status status = napi_wrap(env, instance, napiCmsGenerator,
        [](napi_env env, void *data, void *hint) {
            NapiCertCmsGenerator *napiCertCmsGenerator = static_cast<NapiCertCmsGenerator *>(data);
            delete napiCertCmsGenerator;
            return;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "failed to wrap napiCertCmsGenerator obj!"));
        LOGE("failed to wrap napiCertCmsGenerator obj!");
        delete napiCmsGenerator;
        return nullptr;
    }
    return instance;
}

void NapiCertCmsGenerator::DefineCertCmsGeneratorJSClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createCmsGenerator", CreateCmsGenerator),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("addSigner", NapiAddSigner),
        DECLARE_NAPI_FUNCTION("addCert", NapiAddCert),
        DECLARE_NAPI_FUNCTION("doFinal", NapiDoFinal),
        DECLARE_NAPI_FUNCTION("doFinalSync", NapiDoFinalSync),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "CmsGenerator", NAPI_AUTO_LENGTH, CmsGeneratorConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // namespace CertFramework
} // namespace OHOS