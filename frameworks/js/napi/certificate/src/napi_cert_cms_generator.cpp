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
#include "napi_cert_utils.h"
#include "napi_cert_crl_common.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiCertCmsGenerator::classRef_ = nullptr;
thread_local napi_ref NapiCertCmsParser::classRef_ = nullptr;
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

struct CmsGetEncryptedContentCtx {
    napi_env env = nullptr;

    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref generatorRef = nullptr;

    HcfCmsGenerator *cmsGenerator = nullptr;

    CfResult errCode = CF_SUCCESS;
    const char *errMsg = nullptr;

    CfBlob outBlob = { 0, nullptr };
};

struct AddRecInfoCtx {
    napi_env env = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref cfRef = nullptr;

    HcfCmsGenerator *cmsGenerator = nullptr;
    CmsRecipientInfo *recipientInfo = nullptr;

    CfResult errCode = CF_SUCCESS;
    const char *errMsg = nullptr;
};

struct CmsParserCtx {
    napi_env env = nullptr;
    napi_deferred deferred = nullptr;
    napi_value promise = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref parserRef = nullptr;
    napi_ref certParamsRef = nullptr;

    HcfCmsParser *cmsParser = nullptr;
    CfBlob *rawData = nullptr;
    HcfCmsFormat cmsFormat = CMS_DER;
    HcfCmsParserSignedDataOptions *options = nullptr;
    CfBlob contentData = { 0, nullptr };
    CfBlob encryptedContentData = { 0, nullptr };
    HcfCmsCertType cmsCertType = CMS_CERT_SIGNER_CERTS;
    HcfX509CertificateArray certs = { nullptr, 0 };
    HcfCmsParserDecryptEnvelopedDataOptions *decryptEnvelopedDataOptions = nullptr;
    CfResult errCode = CF_SUCCESS;
    const char *errMsg = nullptr;
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

static void FreeCmsGetEncryptedContentCtx(napi_env env, CmsGetEncryptedContentCtx *ctx)
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
    if (ctx->outBlob.data != nullptr) {
        CfBlobDataFree(&ctx->outBlob);
        ctx->outBlob.data = nullptr;
    }
    CfFree(ctx);
}

static void FreeCmsParserCtx(napi_env env, CmsParserCtx *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    if (ctx->asyncWork != nullptr) {
        napi_delete_async_work(env, ctx->asyncWork);
    }
    if (ctx->parserRef != nullptr) {
        napi_delete_reference(env, ctx->parserRef);
        ctx->parserRef = nullptr;
    }
    if (ctx->certParamsRef != nullptr) {
        napi_delete_reference(env, ctx->certParamsRef);
        ctx->certParamsRef = nullptr;
    }
    if (ctx->rawData != nullptr) {
        CfBlobDataFree(ctx->rawData);
    }
    if (ctx->options != nullptr) {
        FreeCmsParserSignedDataOptions(ctx->options);
        ctx->options = nullptr;
    }
    if (ctx->decryptEnvelopedDataOptions != nullptr) {
        FreeCmsParserDecryptEnvelopedDataOptions(ctx->decryptEnvelopedDataOptions);
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

NapiCertCmsParser::NapiCertCmsParser(HcfCmsParser *cmsParser)
{
    this->cmsParser_ = cmsParser;
}

NapiCertCmsParser::~NapiCertCmsParser()
{
    CfObjDestroy(this->cmsParser_);
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

static CfBlob *CertGetCmsBlobFromUint8ArrJSParams(napi_env env, napi_value arg)
{
    size_t len = 0;
    size_t offset = 0;
    void *data = nullptr;
    napi_value arrayBuffer = nullptr;
    napi_typedarray_type arrayType;
    napi_status status = napi_get_typedarray_info(
        env, arg, &arrayType, &len, reinterpret_cast<void **>(&data), &arrayBuffer, &offset);
    if (status != napi_ok) {
        LOGE("failed to get valid data.");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "failed to get valid data!"));
        return nullptr;
    }
    if (arrayType != napi_uint8_array) {
        LOGE("input data is not uint8 array.");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "input data is not uint8 array!"));
        return nullptr;
    }

    if (len == 0 || data == nullptr) {
        LOGE("array len is 0!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "array len is 0!"));
        return nullptr;
    }

    CfBlob *blob = static_cast<CfBlob *>(CfMallocEx(sizeof(CfBlob)));
    if (blob == nullptr) {
        LOGE("Failed to allocate blob memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed!"));
        return nullptr;
    }

    blob->size = len;
    blob->data = static_cast<uint8_t *>(CfMallocEx(len));
    if (blob->data == nullptr) {
        LOGE("malloc blob data failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed!"));
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    if (memcpy_s(blob->data, len, data, len) != EOK) {
        LOGE("memcpy_s blob data failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_COPY, "copy memory failed!"));
        CfFree(blob->data);
        blob->data = nullptr;
        CfFree(blob);
        blob = nullptr;
        return nullptr;
    }
    return blob;
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
    ctx->content = CertGetCmsBlobFromUint8ArrJSParams(env, argv[PARAM0]);
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

static napi_value ConvertCmsBlobToUint8ArrNapiValue(napi_env env, CfBlob *blob)
{
    if (blob == nullptr || blob->data == nullptr || blob->size == 0) {
        LOGE("Invalid blob!");
        return nullptr;
    }
    uint8_t *buffer = static_cast<uint8_t *>(CfMallocEx(blob->size));
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
        instance = ConvertCmsBlobToUint8ArrNapiValue(env, &ctx->outBlob);
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
        instance = ConvertCmsBlobToUint8ArrNapiValue(env, &outBlob);
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
    CfBlob *content = CertGetCmsBlobFromUint8ArrJSParams(env, argv[PARAM0]);
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

napi_value NapiCertCmsGenerator::SetRecipientEncryptionAlgorithm(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr) != napi_ok) {
        LOGE("Failed to get cb info!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "Get cb info failed!"));
        return nullptr;
    }
    if (argc != ARGS_SIZE_ONE) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "invalid params count."));
        LOGE("invalid params count!");
        return nullptr;
    }

    int32_t algorithm = 0;
    if (!CertGetInt32FromJSParams(env, argv[PARAM0], algorithm)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "get algorithm failed!"));
        LOGE("get algorithm failed!");
        return nullptr;
    }

    NapiCertCmsGenerator *napiCmsGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCmsGenerator));
    if (status != napi_ok || napiCmsGenerator == nullptr) {
        LOGE("failed to unwrap napi cms generator obj.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "failed to unwrap napi cms generator obj."));
        return nullptr;
    }

    HcfCmsGenerator *cmsGenerator = napiCmsGenerator->GetCertCmsGenerator();
    CfResult ret = cmsGenerator->setRecipientEncryptionAlgorithm(cmsGenerator,
        static_cast<CfCmsRecipientEncryptionAlgorithm>(algorithm));
    if (ret != CF_SUCCESS) {
        LOGE("set recipient encryption algorithm fail.");
        napi_throw(env, CertGenerateBusinessError(env, ret, "set recipient encryption algorithm fail."));
        return nullptr;
    }
    return NapiGetNull(env);
}

static bool GetCertFromValue(napi_env env, napi_value value, HcfX509Certificate **outputCert)
{
    if (outputCert == nullptr) {
        LOGE("outputCert is null!");
        return false;
    }
    
    bool result = false;
    napi_status status = napi_has_named_property(env, value, "cert", &result);
    if (status != napi_ok) {
        LOGE("check cert property failed!");
        return false;
    }
    if (!result) {
        LOGI("cert property do not exist!");
        return false;
    }
    napi_value obj = nullptr;
    status = napi_get_named_property(env, value, "cert", &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property cert failed!");
        return false;
    }
    napi_valuetype valueType;
    status = napi_typeof(env, obj, &valueType);
    if (status != napi_ok) {
        LOGE("Failed to get object type!");
        return false;
    }
    if (valueType == napi_undefined) {
        LOGI("cert valueType is undefined.");
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
    *outputCert = cert;
    return true;
}

static CfResult GetKeyTransInfo(napi_env env, napi_value arg, CmsRecipientInfo *recInfo, const char *name)
{
    bool result = false;
    if (napi_has_named_property(env, arg, name, &result) != napi_ok) {
        LOGE("check %{public}s property failed!", name);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "napi_has_named_property failed!"));
        return CF_ERR_NAPI;
    }
    if (!result) {
        LOGI("%{public}s do not exist!", name);
        return CF_SUCCESS;  // It's optional, so return true if not present
    }

    napi_value keyTransInfoObj = nullptr;
    napi_status status = napi_get_named_property(env, arg, name, &keyTransInfoObj);
    if (status != napi_ok || keyTransInfoObj == nullptr) {
        LOGE("get property %{public}s failed!", name);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "napi_get_named_property failed!"));
        return CF_ERR_NAPI;
    }
    
    napi_valuetype valueType;
    status = napi_typeof(env, keyTransInfoObj, &valueType);
    if (status != napi_ok) {
        LOGE("Failed to get %{public}s object type!", name);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "napi_typeof failed!"));
        return CF_ERR_NAPI;
    }
    if (valueType == napi_undefined) {
        LOGI("%{public}s is undefined", name);
        return CF_SUCCESS;
    }

    // Allocate KeyTransRecipientInfo structure with zero initialization
    KeyTransRecipientInfo *keyTransInfo = static_cast<KeyTransRecipientInfo *>(
        CfMalloc(sizeof(KeyTransRecipientInfo), 0));
    if (keyTransInfo == nullptr) {
        LOGE("malloc KeyTransRecipientInfo failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc KeyTransRecipientInfo failed!"));
        return CF_ERR_MALLOC;
    }

    // Initialize the structure to zero
    (void)memset_s(keyTransInfo, sizeof(KeyTransRecipientInfo), 0, sizeof(KeyTransRecipientInfo));

    HcfX509Certificate *outputCert = nullptr;
    if (!GetCertFromValue(env, keyTransInfoObj, &outputCert)) {
        CfFree(keyTransInfo);
        LOGE("GetCertFromValue failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "GetCertFromValue failed!"));
        return CF_ERR_PARAMETER_CHECK;
    }
    keyTransInfo->recipientCert = &(outputCert->base);
    recInfo->keyTransInfo = keyTransInfo;
    return CF_SUCCESS;
}

static bool GetDigestAlgorithm(napi_env env, napi_value value, CfCmsKeyAgreeRecipientDigestAlgorithm *alg)
{
    bool result = false;
    napi_status status = napi_has_named_property(env, value, CMS_GENERATOR_DIGESTALG.c_str(), &result);
    if (status != napi_ok) {
        LOGE("check %{public}s property failed!", CMS_GENERATOR_DIGESTALG.c_str());
        return false;
    }
    
    if (!result) {
        LOGI("%{public}s do not exist, using default SHA256!", CMS_GENERATOR_DIGESTALG.c_str());
        return true;
    }
    
    napi_value digestObj = nullptr;
    status = napi_get_named_property(env, value, CMS_GENERATOR_DIGESTALG.c_str(), &digestObj);
    if (status != napi_ok || digestObj == nullptr) {
        LOGE("get property %{public}s failed!", CMS_GENERATOR_DIGESTALG.c_str());
        return false;
    }
    
    napi_valuetype valueType;
    status = napi_typeof(env, digestObj, &valueType);
    if (status != napi_ok) {
        LOGE("Failed to get digest algorithm object type!");
        return false;
    }
    
    if (valueType == napi_undefined) {
        LOGI("digest algorithm is undefined");
        return true;
    }
    
    int32_t digestValue = 0;
    if (!CertGetInt32FromJSParams(env, digestObj, digestValue)) {
        LOGE("Failed to get digest algorithm value!");
        return false;
    }
    *alg = static_cast<CfCmsKeyAgreeRecipientDigestAlgorithm>(digestValue);
    return true;
}

static bool GetKeyAgreeRecipientInfoFromValue(napi_env env, napi_value obj, KeyAgreeRecipientInfo *keyAgreeInfo)
{
    HcfX509Certificate *cert = nullptr;
    if (!GetCertFromValue(env, obj, &cert)) {
        LOGE("GetCertFromValue failed!");
        return false;
    }
    CfCmsKeyAgreeRecipientDigestAlgorithm alg = CMS_SHA256; // Default to SHA256
    if (!GetDigestAlgorithm(env, obj, &alg)) {
        LOGE("GetDigestAlgorithm failed!");
        return false;
    }
    keyAgreeInfo->recipientCert = &(cert->base);
    keyAgreeInfo->digestAlgorithm = alg;
    return true;
}

static CfResult GetKeyAgreeInfo(napi_env env, napi_value arg, CmsRecipientInfo *recInfo, const char *name)
{
    bool result = false;
    if (napi_has_named_property(env, arg, name, &result) != napi_ok) {
        LOGE("check %{public}s property failed!", name);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "napi_has_named_property failed!"));
        return CF_ERR_NAPI;
    }
    if (!result) {
        LOGI("%{public}s do not exist!", name);
        return CF_SUCCESS;  // It's optional, so return true if not present
    }
    
    napi_value keyAgreeInfoObj = nullptr;
    napi_status status = napi_get_named_property(env, arg, name, &keyAgreeInfoObj);
    if (status != napi_ok || keyAgreeInfoObj == nullptr) {
        LOGE("get property %{public}s failed!", name);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "napi_get_named_property failed!"));
        return CF_ERR_NAPI;
    }
    
    napi_valuetype valueType;
    status = napi_typeof(env, keyAgreeInfoObj, &valueType);
    if (status != napi_ok) {
        LOGE("Failed to get %{public}s object type!", name);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "napi_typeof failed!"));
        return CF_ERR_NAPI;
    }
    if (valueType == napi_undefined) {
        LOGI("%{public}s is undefined", name);
        return CF_SUCCESS;
    }

    // Allocate KeyAgreeRecipientInfo structure with zero initialization
    KeyAgreeRecipientInfo *keyAgreeInfo = static_cast<KeyAgreeRecipientInfo *>(
        CfMalloc(sizeof(KeyAgreeRecipientInfo), 0));
    if (keyAgreeInfo == nullptr) {
        LOGE("malloc KeyAgreeRecipientInfo failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc KeyAgreeRecipientInfo failed!"));
        return CF_ERR_MALLOC;
    }

    // Initialize the structure to zero
    (void)memset_s(keyAgreeInfo, sizeof(KeyAgreeRecipientInfo), 0, sizeof(KeyAgreeRecipientInfo));

    if (!GetKeyAgreeRecipientInfoFromValue(env, keyAgreeInfoObj, keyAgreeInfo)) {
        CfFree(keyAgreeInfo);
        LOGE("GetKeyAgreeRecipientInfoFromValue failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK,
            "GetKeyAgreeRecipientInfoFromValue failed!"));
        return CF_ERR_PARAMETER_CHECK;
    }
    recInfo->keyAgreeInfo = keyAgreeInfo;
    return CF_SUCCESS;
}

static void FreeCmsRecipientInfo(CmsRecipientInfo *recInfo)
{
    if (recInfo == nullptr) {
        return;
    }
    
    if (recInfo->keyTransInfo != nullptr) {
        CfFree(recInfo->keyTransInfo);
        recInfo->keyTransInfo = nullptr;
    }
    
    if (recInfo->keyAgreeInfo != nullptr) {
        CfFree(recInfo->keyAgreeInfo);
        recInfo->keyAgreeInfo = nullptr;
    }
}

static void FreeAddRecInfoCtx(napi_env env, AddRecInfoCtx *context)
{
    if (context == nullptr) {
        return;
    }
    
    if (context->recipientInfo != nullptr) {
        FreeCmsRecipientInfo(context->recipientInfo);
        CfFree(context->recipientInfo);
        context->recipientInfo = nullptr;
    }
    
    if (context->cfRef != nullptr) {
        napi_delete_reference(env, context->cfRef);
        context->cfRef = nullptr;
    }
    
    if (context->asyncWork != nullptr) {
        napi_delete_async_work(env, context->asyncWork);
        context->asyncWork = nullptr;
    }
    
    CfFree(context);
}

static void AddRecipientInfoExecute(napi_env env, void *data)
{
    AddRecInfoCtx *context = static_cast<AddRecInfoCtx *>(data);
    
    context->errCode = context->cmsGenerator->addRecipientInfo(context->cmsGenerator, context->recipientInfo);
    if (context->errCode != CF_SUCCESS) {
        context->errMsg = "addRecipientInfo failed";
        LOGE("addRecipientInfo failed, errCode: %{public}d", context->errCode);
    }
}

static void AddRecipientInfoComplete(napi_env env, napi_status status, void *data)
{
    AddRecInfoCtx *context = static_cast<AddRecInfoCtx *>(data);
    if (context->errCode != CF_SUCCESS) {
        napi_reject_deferred(env, context->deferred,
            CertGenerateBusinessError(env, context->errCode, context->errMsg));
        FreeAddRecInfoCtx(env, context);
        return;
    }
    napi_resolve_deferred(env, context->deferred, CertNapiGetNull(env));
    FreeAddRecInfoCtx(env, context);
}

static CfResult GetCmsRecipientInfoFromValue(napi_env env, napi_value arg, CmsRecipientInfo *recInfo)
{
    CfResult ret = GetKeyTransInfo(env, arg, recInfo, CMS_GENERATOR_KEY_TRANSINFO.c_str());
    if (ret != CF_SUCCESS) {
        LOGE("GetKeyTransInfo for KeyTransInfo failed!");
        return ret;
    }
    ret = GetKeyAgreeInfo(env, arg, recInfo, CMS_GENERATOR_KEY_AGREEINFO.c_str());
    if (ret != CF_SUCCESS) {
        LOGE("GetKeyAgreeInfo for KeyAgreeInfo failed!");
        return ret;
    }
    return CF_SUCCESS;
}

AddRecInfoCtx *AllocAddRecInfoCtx(napi_env env, NapiCertCmsGenerator *napiCmsGenerator, napi_value thisVar)
{
    AddRecInfoCtx *context = static_cast<AddRecInfoCtx *>(CfMalloc(sizeof(AddRecInfoCtx), 0));
    if (context == nullptr) {
        LOGE("malloc context failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc context failed!"));
        return nullptr;
    }
    context->cmsGenerator = napiCmsGenerator->GetCertCmsGenerator();
    if (napi_create_reference(env, thisVar, 1, &context->cfRef) != napi_ok) {
        LOGE("create reference failed!");
        FreeAddRecInfoCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "create reference failed!"));
        return nullptr;
    }
    return context;
}

CmsRecipientInfo *AllocRecipientInfo(napi_env env, AddRecInfoCtx *context, napi_value arg)
{
    CmsRecipientInfo *recInfo = static_cast<CmsRecipientInfo *>(CfMalloc(sizeof(CmsRecipientInfo), 0));
    if (recInfo == nullptr) {
        LOGE("malloc recipient info failed!");
        FreeAddRecInfoCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc recipient info failed!"));
        return nullptr;
    }
    CfResult ret = GetCmsRecipientInfoFromValue(env, arg, recInfo);
    if (ret != CF_SUCCESS) {
        LOGE("get recipient info from value failed!");
        CfFree(recInfo);
        FreeAddRecInfoCtx(env, context);
        return nullptr;
    }
    return recInfo;
}

bool SetupAddRecipientInfoAsync(napi_env env, AddRecInfoCtx *context)
{
    napi_status status = napi_create_promise(env, &context->deferred, &context->promise);
    if (status != napi_ok) {
        LOGE("create promise failed!");
        FreeAddRecInfoCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "create promise failed!"));
        return false;
    }
    napi_create_async_work(
        env, nullptr, CertGetResourceName(env, "addRecipientInfo"),
        AddRecipientInfoExecute,
        AddRecipientInfoComplete,
        static_cast<void *>(context),
        &context->asyncWork);
    status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        LOGE("queue async work failed!");
        FreeAddRecInfoCtx(env, context);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "queue async work failed!"));
        return false;
    }
    return true;
}

napi_value NapiCertCmsGenerator::AddRecipientInfo(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    
    if (napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr) != napi_ok) {
        LOGE("Failed to get cb info!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "Get cb info failed!"));
        return nullptr;
    }
    
    if (argc != ARGS_SIZE_ONE) {
        LOGE("invalid params count!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "invalid params count."));
        return nullptr;
    }
    NapiCertCmsGenerator *napiCmsGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCmsGenerator));
    if (status != napi_ok || napiCmsGenerator == nullptr) {
        LOGE("failed to unwrap napi cms generator obj.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "failed to unwrap napi cms generator obj."));
        return nullptr;
    }
    AddRecInfoCtx *context = AllocAddRecInfoCtx(env, napiCmsGenerator, thisVar);
    if (context == nullptr) {
        return nullptr;
    }
    CmsRecipientInfo *recInfo = AllocRecipientInfo(env, context, argv[PARAM0]);
    if (recInfo == nullptr) {
        return nullptr;
    }
    context->recipientInfo = recInfo;
    if (!SetupAddRecipientInfoAsync(env, context)) {
        return nullptr;
    }
    return context->promise;
}

static void CmsGetEncryptedContentDataExecute(napi_env env, void *data)
{
    CmsGetEncryptedContentCtx *ctx = static_cast<CmsGetEncryptedContentCtx *>(data);
    ctx->errCode = ctx->cmsGenerator->getEncryptedContentData(ctx->cmsGenerator, &(ctx->outBlob));
    if (ctx->errCode != CF_SUCCESS) {
        LOGE("Get encrypted content data fail.");
        ctx->errMsg = "Get encrypted content data fail.";
    }
}

static void CmsGetEncryptedContentDataComplete(napi_env env, napi_status status, void *data)
{
    CmsGetEncryptedContentCtx *ctx = static_cast<CmsGetEncryptedContentCtx *>(data);
    
    if (ctx->errCode != CF_SUCCESS) {
        napi_reject_deferred(env, ctx->deferred,
            CertGenerateBusinessError(env, ctx->errCode, ctx->errMsg));
        FreeCmsGetEncryptedContentCtx(env, ctx);
        return;
    }
    
    // Convert encrypted content to Uint8Array
    napi_value instance = ConvertCmsBlobToUint8ArrNapiValue(env, &ctx->outBlob);
    napi_resolve_deferred(env, ctx->deferred, instance);
    FreeCmsGetEncryptedContentCtx(env, ctx);
}

napi_value NapiCertCmsGenerator::GetEncryptedContentData(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    
    NapiCertCmsGenerator *napiCmsGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCmsGenerator));
    if (status != napi_ok || napiCmsGenerator == nullptr) {
        LOGE("failed to unwrap napi cms generator obj.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "failed to unwrap napi cms generator obj."));
        return nullptr;
    }
    
    CmsGetEncryptedContentCtx *ctx = static_cast<CmsGetEncryptedContentCtx *>(
        CfMalloc(sizeof(CmsGetEncryptedContentCtx), 0));
    if (ctx == nullptr) {
        LOGE("create context fail.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "create context fail!"));
        return nullptr;
    }
    ctx->cmsGenerator = napiCmsGenerator->GetCertCmsGenerator();
    if (napi_create_reference(env, thisVar, 1, &ctx->generatorRef) != napi_ok) {
        LOGE("create generator ref failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "create generator ref failed!"));
        CfFree(ctx);
        return nullptr;
    }
    napi_create_promise(env, &ctx->deferred, &ctx->promise);
    napi_create_async_work(
        env, nullptr, CertGetResourceName(env, "getEncryptedContentData"),
        [](napi_env env, void *data) {
            CmsGetEncryptedContentDataExecute(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            CmsGetEncryptedContentDataComplete(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);
    napi_queue_async_work(env, ctx->asyncWork);
    return ctx->promise;
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

static napi_value NapiSetRecipientEncryptionAlgorithm(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsGenerator *cmsGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsGenerator));
    if (status != napi_ok || cmsGenerator == nullptr) {
        LOGE("cmsGenerator is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "napi_unwrap failed!"));
        return nullptr;
    }
    return cmsGenerator->SetRecipientEncryptionAlgorithm(env, info);
}

static napi_value NapiAddRecipientInfo(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsGenerator *cmsGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsGenerator));
    if (status != napi_ok || cmsGenerator == nullptr) {
        LOGE("cmsGenerator is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "napi_unwrap failed!"));
        return nullptr;
    }
    return cmsGenerator->AddRecipientInfo(env, info);
}

static napi_value NapiGetEncryptedContentData(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsGenerator *cmsGenerator = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsGenerator));
    if (status != napi_ok || cmsGenerator == nullptr) {
        LOGE("cmsGenerator is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "napi_unwrap failed!"));
        return nullptr;
    }
    return cmsGenerator->GetEncryptedContentData(env, info);
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
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "failed to wrap napiCertCmsGenerator obj!"));
        LOGE("failed to wrap napiCertCmsGenerator obj!");
        delete napiCmsGenerator;
        return nullptr;
    }
    return instance;
}

static void CmsSetRawDataAsyncWorkProcess(napi_env env, void *data)
{
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(data);
    ctx->errCode = ctx->cmsParser->setRawData(ctx->cmsParser, ctx->rawData, ctx->cmsFormat);
    if (ctx->errCode != CF_SUCCESS) {
        LOGE("Cms do final fail.");
        ctx->errMsg = "Cms do final fail.";
    }
}

static void ReturnParserPromiseResult(napi_env env, CmsParserCtx *ctx, napi_value result)
{
    if (ctx->errCode == CF_SUCCESS) {
        napi_resolve_deferred(env, ctx->deferred, result);
    } else {
        napi_reject_deferred(env, ctx->deferred,
            CertGenerateBusinessError(env, ctx->errCode, ctx->errMsg));
    }
}

static void CmsVerifySignedDataAsyncWorkProcess(napi_env env, void *data)
{
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(data);
    ctx->errCode = ctx->cmsParser->verifySignedData(ctx->cmsParser, ctx->options);
    if (ctx->errCode != CF_SUCCESS) {
        LOGE("Cms verify signed data fail.");
        ctx->errMsg = "Cms verify signed data fail.";
    }
}

static void CmsVerifySignedDataAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(data);
    if (ctx->errCode != CF_SUCCESS) {
        ReturnParserPromiseResult(env, ctx, nullptr);
        FreeCmsParserCtx(env, ctx);
        return;
    }
    napi_value result = CertNapiGetNull(env);
    ReturnParserPromiseResult(env, ctx, result);
    FreeCmsParserCtx(env, ctx);
    return;
}

static void CmsGetContentDataAsyncWorkProcess(napi_env env, void *data)
{
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(data);
    ctx->errCode = ctx->cmsParser->getContentData(ctx->cmsParser, &(ctx->contentData));
    if (ctx->errCode != CF_SUCCESS) {
        LOGE("Cms get content data fail.");
        ctx->errMsg = "Cms get content data fail.";
    }
}
    
static void CmsGetContentDataAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(data);
    if (ctx->errCode != CF_SUCCESS) {
        ReturnParserPromiseResult(env, ctx, nullptr);
        FreeCmsParserCtx(env, ctx);
        return;
    }
    napi_value result = ConvertBlobToUint8ArrNapiValue(env, &(ctx->contentData));
    ReturnParserPromiseResult(env, ctx, result);
    FreeCmsParserCtx(env, ctx);
    return;
}

static void CmsGetCertsAsyncWorkProcess(napi_env env, void *data)
{
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(data);
    ctx->errCode = ctx->cmsParser->getCerts(ctx->cmsParser, ctx->cmsCertType, &(ctx->certs));
    if (ctx->errCode != CF_SUCCESS) {
        LOGE("Cms get certs fail.");
        ctx->errMsg = "Cms get certs fail.";
    }
}

static void CmsGetCertsAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(data);
    if (ctx->errCode != CF_SUCCESS) {
        ReturnParserPromiseResult(env, ctx, nullptr);
        FreeCmsParserCtx(env, ctx);
        return;
    }
    napi_value result = ConvertCertArrToNapiValue(env, &(ctx->certs));
    ReturnParserPromiseResult(env, ctx, result);
    FreeCmsParserCtx(env, ctx);
    return;
}

static void CmsDecryptEnvelopedDataAsyncWorkProcess(napi_env env, void *data)
{
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(data);
    ctx->errCode = ctx->cmsParser->decryptEnvelopedData(ctx->cmsParser, ctx->decryptEnvelopedDataOptions,
        &(ctx->encryptedContentData));
    if (ctx->errCode != CF_SUCCESS) {
        LOGE("Cms decrypt enveloped data fail.");
        ctx->errMsg = "Cms decrypt enveloped data fail.";
    }
}

static void CmsDecryptEnvelopedDataAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(data);
    if (ctx->errCode != CF_SUCCESS) {
        ReturnParserPromiseResult(env, ctx, nullptr);
        FreeCmsParserCtx(env, ctx);
        return;
    }
    napi_value result = ConvertBlobToUint8ArrNapiValue(env, &(ctx->encryptedContentData));
    ReturnParserPromiseResult(env, ctx, result);
    FreeCmsParserCtx(env, ctx);
    return;
}

static void CmsSetRawDataAsyncWorkReturn(napi_env env, napi_status status, void *data)
{
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(data);
    if (ctx->errCode != CF_SUCCESS) {
        ReturnParserPromiseResult(env, ctx, nullptr);
        FreeCmsParserCtx(env, ctx);
        return;
    }
    napi_value result = CertNapiGetNull(env);
    ReturnParserPromiseResult(env, ctx, result);
    FreeCmsParserCtx(env, ctx);
    return;
}

static napi_value NewCmsSetRawDataAsyncWork(napi_env env, CmsParserCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "setRawData", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            CmsSetRawDataAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            CmsSetRawDataAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    return ctx->promise;
}

static bool BuildRawData(napi_env env, napi_value arg, CmsParserCtx *ctx)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType == napi_string) {
        ctx->rawData = CertGetBlobFromStringJSParams(env, arg);
        if (ctx->rawData == nullptr) {
            LOGE("Failed to get private key!");
            return false;
        }
    } else {
        ctx->rawData = CertGetBlobFromUint8ArrJSParams(env, arg);
        if (ctx->rawData == nullptr) {
            LOGE("Failed to get private key!");
            return false;
        }
    }
    return true;
}

static napi_value NewCmsVerifySignedDataAsyncWork(napi_env env, CmsParserCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "verifySignedData", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            CmsVerifySignedDataAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            CmsVerifySignedDataAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    return ctx->promise;
}

static napi_value NewCmsGetContentDataAsyncWork(napi_env env, CmsParserCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "getContentData", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            CmsGetContentDataAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            CmsGetContentDataAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    return ctx->promise;
}

static napi_value NewCmsGetCertsAsyncWork(napi_env env, CmsParserCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "getCerts", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            CmsGetCertsAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            CmsGetCertsAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);

    napi_queue_async_work(env, ctx->asyncWork);
    return ctx->promise;
}

static napi_value NewCmsDecryptEnvelopedDataAsyncWork(napi_env env, CmsParserCtx *ctx)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, "decryptEnvelopedData", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            CmsDecryptEnvelopedDataAsyncWorkProcess(env, data);
            return;
        },
        [](napi_env env, napi_status status, void *data) {
            CmsDecryptEnvelopedDataAsyncWorkReturn(env, status, data);
            return;
        },
        static_cast<void *>(ctx),
        &ctx->asyncWork);
    napi_queue_async_work(env, ctx->asyncWork);
    return ctx->promise;
}

napi_value NapiCertCmsParser::SetRawData(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_TWO, true)) {
        return nullptr;
    }

    NapiCertCmsParser *napiCmsParser = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCmsParser));
    if (status != napi_ok || napiCmsParser == nullptr) {
        LOGE("failed to unwrap napi cms parser obj.");
        napi_throw(env,
            CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "failed to unwrap napi cms parser obj."));
        return nullptr;
    }

    HcfCmsParser *cmsParser = napiCmsParser->GetCertCmsParser();
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(CfMalloc(sizeof(CmsParserCtx), 0));
    if (ctx == nullptr) {
        LOGE("create context fail.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to create a cmsParser class"));
        return nullptr;
    }
    ctx->cmsParser = cmsParser;
    if (!BuildRawData(env, argv[PARAM0], ctx)) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "failed to build raw data."));
        FreeCmsParserCtx(env, ctx);
        return nullptr;
    }

    int32_t format = 0;
    if (!CertGetInt32FromJSParams(env, argv[PARAM1], format)) {
        LOGE("get cmsFormat failed");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "get cmsFormat failed"));
        CfBlobFree(&ctx->rawData);
        FreeCmsParserCtx(env, ctx);
        return nullptr;
    }
    ctx->cmsFormat = static_cast<HcfCmsFormat>(format);
    napi_create_promise(env, &ctx->deferred, &ctx->promise);

    return NewCmsSetRawDataAsyncWork(env, ctx);
}

napi_value NapiCertCmsParser::GetContentType(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsParser *napiCmsParser = nullptr;
    napi_status status = napi_unwrap(env, thisVar, (void **)&napiCmsParser);
    if (status != napi_ok || napiCmsParser == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "get cmsParser instance failed"));
        LOGE("get cmsParser instance failed");
        return nullptr;
    }

    HcfCmsParser *cmsParser = napiCmsParser->GetCertCmsParser();
    if (cmsParser == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "cmsParser is null"));
        LOGE("cmsParser is null");
        return nullptr;
    }
    HcfCmsContentType contentType;
    CfResult res = cmsParser->getContentType(cmsParser, &contentType);
    if (res != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, res, "getContentType failed"));
        LOGE("getContentType failed");
        return nullptr;
    }

    napi_value result = nullptr;
    napi_create_int32(env, static_cast<int32_t>(contentType), &result);
    return result;
}

static CfResult BuildVerifySignedDataOption(napi_env env, napi_value arg, CmsParserCtx *ctx)
{
    napi_valuetype type;
    napi_typeof(env, arg, &type);
    if (type != napi_object) {
        LOGE("wrong argument type. expect object type. [Type]: %{public}d", type);
        return CF_ERR_NAPI;
    }

    ctx->options = nullptr;
    CfResult res = CertGetCmsParserSignedDataOptionsFromValue(env, arg, &ctx->options);
    if (res != CF_SUCCESS) {
        LOGE("Cert SignedDataOptions failed!");
        return res;
    }

    return CF_SUCCESS;
}

napi_value NapiCertCmsParser::VerifySignedData(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, true)) {
        return nullptr;
    }

    NapiCertCmsParser *napiCmsParser = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCmsParser));
    if (status != napi_ok || napiCmsParser == nullptr) {
        LOGE("failed to unwrap napi cms parser obj.");
        napi_throw(env,
            CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "failed to unwrap napi cms parser obj."));
        return nullptr;
    }

    HcfCmsParser *cmsParser = napiCmsParser->GetCertCmsParser();
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(CfMalloc(sizeof(CmsParserCtx), 0));
    if (ctx == nullptr) {
        LOGE("create context fail.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to create a cmsParser class"));
        return nullptr;
    }
    ctx->cmsParser = cmsParser;
    CfResult res = BuildVerifySignedDataOption(env, argv[PARAM0], ctx);
    if (res != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, res, "failed to build verify signed data."));
        FreeCmsParserCtx(env, ctx);
        return nullptr;
    }

    if (napi_create_reference(env, thisVar, 1, &ctx->parserRef) != napi_ok) {
        LOGE("create reference failed!");
        FreeCmsParserCtx(env, ctx);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "create reference failed!"));
        return nullptr;
    }

    if (napi_create_reference(env, argv[PARAM0], 1, &ctx->certParamsRef) != napi_ok) {
        LOGE("create param ref failed!");
        FreeCmsParserCtx(env, ctx);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "Create param ref failed"));
        return nullptr;
    }

    napi_create_promise(env, &ctx->deferred, &ctx->promise);

    return NewCmsVerifySignedDataAsyncWork(env, ctx);
}

napi_value NapiCertCmsParser::GetContentData(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsParser *napiCmsParser = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCmsParser));
    if (status != napi_ok || napiCmsParser == nullptr) {
        LOGE("failed to unwrap napi cms parser obj.");
        napi_throw(env,
            CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "failed to unwrap napi cms parser obj."));
        return nullptr;
    }

    HcfCmsParser *cmsParser = napiCmsParser->GetCertCmsParser();
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(CfMalloc(sizeof(CmsParserCtx), 0));
    if (ctx == nullptr) {
        LOGE("create context fail.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to create a cmsParser class"));
        return nullptr;
    }
    ctx->cmsParser = cmsParser;

    napi_create_promise(env, &ctx->deferred, &ctx->promise);

    return NewCmsGetContentDataAsyncWork(env, ctx);
}

napi_value NapiCertCmsParser::GetCerts(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, true)) {
        return nullptr;
    }
    NapiCertCmsParser *napiCmsParser = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCmsParser));
    if (status != napi_ok || napiCmsParser == nullptr) {
        LOGE("failed to unwrap napi cms parser obj.");
        napi_throw(env,
            CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "failed to unwrap napi cms parser obj."));
        return nullptr;
    }
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(CfMalloc(sizeof(CmsParserCtx), 0));
    if (ctx == nullptr) {
        LOGE("create context fail.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to create a cmsParser class"));
        return nullptr;
    }
    HcfCmsParser *cmsParser = napiCmsParser->GetCertCmsParser();
    if (cmsParser == nullptr) {
        LOGE("cmsParser is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "cmsParser is nullptr!"));
        return nullptr;
    }
    ctx->cmsParser = cmsParser;
    int32_t format = 0;
    if (!CertGetInt32FromJSParams(env, argv[PARAM0], format)) {
        LOGE("get cmsFormat failed");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "get cmsFormat failed"));
        return nullptr;
    }
    ctx->cmsCertType = static_cast<HcfCmsCertType>(format);
    napi_create_promise(env, &ctx->deferred, &ctx->promise);
    return NewCmsGetCertsAsyncWork(env, ctx);
}

static CfResult BuildDecryptEnvelopedDataOption(napi_env env, napi_value arg, CmsParserCtx *ctx)
{
    if (arg == nullptr || ctx == nullptr) {
        LOGE("Invalid input parameters!");
        return CF_ERR_PARAMETER_CHECK;
    }
    ctx->decryptEnvelopedDataOptions = nullptr;
    CfResult res = CertGetCmsParserEnvelopedDataOptionsFromValue(env, arg, &ctx->decryptEnvelopedDataOptions);
    if (res != CF_SUCCESS) {
        LOGE("Cert EnvelopedDataOptions failed!");
        FreeCmsParserCtx(env, ctx);
        return res;
    }
    return CF_SUCCESS;
}

napi_value NapiCertCmsParser::DecryptEnvelopedData(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = { nullptr };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);
    if (!CertCheckArgsCount(env, argc, ARGS_SIZE_ONE, true)) {
        return nullptr;
    }
    NapiCertCmsParser *napiCmsParser = nullptr;
    napi_status status = napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiCmsParser));
    if (status != napi_ok || napiCmsParser == nullptr) {
        LOGE("failed to unwrap napi cms parser obj.");
        napi_throw(env,
            CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "failed to unwrap napi cms parser obj."));
        return nullptr;
    }
    HcfCmsParser *cmsParser = napiCmsParser->GetCertCmsParser();
    CmsParserCtx *ctx = static_cast<CmsParserCtx *>(CfMalloc(sizeof(CmsParserCtx), 0));
    if (ctx == nullptr) {
        LOGE("create context fail.");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to create a cmsParser class"));
        return nullptr;
    }
    ctx->cmsParser = cmsParser;
    CfResult res = BuildDecryptEnvelopedDataOption(env, argv[PARAM0], ctx);
    if (res != CF_SUCCESS) {
        napi_throw(env,
            CertGenerateBusinessError(env, res, "failed to build decrypt enveloped data."));
        FreeCmsParserCtx(env, ctx);
        return nullptr;
    }

    if (napi_create_reference(env, thisVar, 1, &ctx->parserRef) != napi_ok) {
        LOGE("create reference failed!");
        FreeCmsParserCtx(env, ctx);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_PARAMETER_CHECK, "create reference failed!"));
        return nullptr;
    }

    if (napi_create_reference(env, argv[PARAM0], 1, &ctx->certParamsRef) != napi_ok) {
        LOGE("create param ref failed!");
        FreeCmsParserCtx(env, ctx);
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "Create param ref failed"));
        return nullptr;
    }
    napi_create_promise(env, &ctx->deferred, &ctx->promise);
    return NewCmsDecryptEnvelopedDataAsyncWork(env, ctx);
}

static napi_value NapiSetRawData(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsParser *cmsParser = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsParser));
    if (cmsParser == nullptr) {
        LOGE("cmsParser is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "cmsParser is nullptr!"));
        return nullptr;
    }
    return cmsParser->SetRawData(env, info);
}

static napi_value NapiGetContentType(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsParser *cmsParser = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsParser));
    if (cmsParser == nullptr) {
        LOGE("cmsParser is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "cmsParser is nullptr!"));
        return nullptr;
    }
    return cmsParser->GetContentType(env, info);
}

static napi_value NapiVerifySignedData(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsParser *cmsParser = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsParser));
    if (cmsParser == nullptr) {
        LOGE("cmsParser is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "cmsParser is nullptr!"));
        return nullptr;
    }
    return cmsParser->VerifySignedData(env, info);
}

static napi_value NapiGetContentData(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsParser *cmsParser = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsParser));
    if (cmsParser == nullptr) {
        LOGE("cmsParser is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "cmsParser is nullptr!"));
        return nullptr;
    }
    return cmsParser->GetContentData(env, info);
}

static napi_value NapiGetCerts(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsParser *cmsParser = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsParser));
    if (cmsParser == nullptr) {
        LOGE("cmsParser is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "cmsParser is nullptr!"));
        return nullptr;
    }
    return cmsParser->GetCerts(env, info);
}

static napi_value NapiDecryptEnvelopedData(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiCertCmsParser *cmsParser = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&cmsParser));
    if (cmsParser == nullptr) {
        LOGE("cmsParser is nullptr!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "cmsParser is nullptr!"));
        return nullptr;
    }
    return cmsParser->DecryptEnvelopedData(env, info);
}


static napi_value CmsParserConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

napi_value NapiCertCmsParser::CreateCertCmsParser(napi_env env, napi_callback_info info)
{
    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);

    HcfCmsParser *cmsParser = nullptr;
    CfResult res = HcfCreateCmsParser(&cmsParser);
    if (res != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, res, "create cms parser failed"));
        LOGE("Failed to create cms parser.");
        return nullptr;
    }

    NapiCertCmsParser *napiCmsParser = new (std::nothrow) NapiCertCmsParser(cmsParser);
    if (napiCmsParser == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "Failed to create a cmsParser class"));
        LOGE("Failed to create a cmsParser class");
        CfObjDestroy(cmsParser);
        return nullptr;
    }

    napi_status status = napi_wrap(env, instance, napiCmsParser,
        [](napi_env env, void *data, void *hint) {
            NapiCertCmsParser *CmsParser = static_cast<NapiCertCmsParser *>(data);
            delete CmsParser;
            return;
        }, nullptr, nullptr);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_NAPI, "failed to wrap obj!"));
        LOGE("Failed to wrap cmsParser instance");
        delete napiCmsParser;
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
        DECLARE_NAPI_FUNCTION("setRecipientEncryptionAlgorithm", NapiSetRecipientEncryptionAlgorithm),
        DECLARE_NAPI_FUNCTION("addRecipientInfo", NapiAddRecipientInfo),
        DECLARE_NAPI_FUNCTION("getEncryptedContentData", NapiGetEncryptedContentData),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "CmsGenerator", NAPI_AUTO_LENGTH, CmsGeneratorConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}

void NapiCertCmsParser::DefineCertCmsParserJsClass(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = { DECLARE_NAPI_FUNCTION("createCmsParser", CreateCertCmsParser) };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);

    napi_property_descriptor CertCmsParserDesc[] = {
        DECLARE_NAPI_FUNCTION("setRawData", NapiSetRawData),
        DECLARE_NAPI_FUNCTION("getContentType", NapiGetContentType),
        DECLARE_NAPI_FUNCTION("verifySignedData", NapiVerifySignedData),
        DECLARE_NAPI_FUNCTION("getContentData", NapiGetContentData),
        DECLARE_NAPI_FUNCTION("getCerts", NapiGetCerts),
        DECLARE_NAPI_FUNCTION("decryptEnvelopedData", NapiDecryptEnvelopedData),

    };
    napi_value constructor = nullptr;
    napi_define_class(env, "CertCmsParser", NAPI_AUTO_LENGTH, CmsParserConstructor, nullptr,
        sizeof(CertCmsParserDesc) / sizeof(CertCmsParserDesc[0]), CertCmsParserDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // namespace CertFramework
} // namespace OHOS