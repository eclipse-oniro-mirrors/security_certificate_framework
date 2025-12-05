/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_cert_utils.h"
#include <string>
#include "cf_log.h"
#include "cf_memory.h"
#include "cipher.h"
#include "config.h"
#include "detailed_ccm_params.h"
#include "detailed_gcm_params.h"
#include "detailed_iv_params.h"
#include "napi_cert_defines.h"
#include "napi_x509_certificate.h"
#include "napi_cert_crl_common.h"
#include "securec.h"
#include "utils.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CertFramework {
using namespace std;

struct CfResultCodeMap {
    CfResult retValue;
    ResultCode retCode;
};

const struct CfResultCodeMap CODE_MAP[] = {
    { CF_SUCCESS, JS_SUCCESS },
    { CF_INVALID_PARAMS, JS_ERR_CERT_INVALID_PARAMS },
    { CF_NOT_SUPPORT, JS_ERR_CERT_NOT_SUPPORT },
    { CF_ERR_MALLOC, JS_ERR_CERT_OUT_OF_MEMORY },
    { CF_ERR_CRYPTO_OPERATION, JS_ERR_CERT_CRYPTO_OPERATION },
    { CF_ERR_CERT_SIGNATURE_FAILURE, JS_ERR_CERT_SIGNATURE_FAILURE },
    { CF_ERR_CERT_NOT_YET_VALID, JS_ERR_CERT_NOT_YET_VALID },
    { CF_ERR_CERT_HAS_EXPIRED, JS_ERR_CERT_HAS_EXPIRED },
    { CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, JS_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { CF_ERR_KEYUSAGE_NO_CERTSIGN, JS_ERR_KEYUSAGE_NO_CERTSIGN },
    { CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, JS_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE },
    { CF_ERR_CERT_INVALID_PRIVATE_KEY, JS_ERR_CERT_INVALID_PRIVATE_KEY },
    { CF_ERR_NAPI, JS_ERR_CERT_RUNTIME_ERROR },
    { CF_ERR_INTERNAL, JS_ERR_CERT_RUNTIME_ERROR },
    { CF_ERR_PARAMETER_CHECK, JS_ERR_CERT_PARAMETER_CHECK },
};

napi_value CertNapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_value ConvertArrayToNapiValue(napi_env env, CfArray *array)
{
    if (array == nullptr) {
        LOGE("array is null!");
        return nullptr;
    }
    if (array->count == 0) {
        LOGE("array count is 0!");
        return nullptr;
    }
    napi_value returnArray = nullptr;
    napi_create_array(env, &returnArray);
    if (returnArray == nullptr) {
        LOGE("create return array failed!");
        return nullptr;
    }
    for (uint32_t i = 0; i < array->count; i++) {
        CfBlob *blob = reinterpret_cast<CfBlob *>(array->data + i);
        napi_value outBuffer = GenerateArrayBuffer(env, blob->data, blob->size);
        if (outBuffer == nullptr) {
            LOGE("generate array buffer failed!");
            return nullptr;
        }
        napi_value element = nullptr;
        napi_create_typedarray(env, napi_uint8_array, blob->size, outBuffer, 0, &element);
        napi_set_element(env, returnArray, i, element);
    }
    napi_value returnValue = nullptr;
    napi_create_object(env, &returnValue);
    napi_set_named_property(env, returnValue, CERT_TAG_DATA.c_str(), returnArray);
    return returnValue;
}

napi_value GenerateArrayBuffer(napi_env env, uint8_t *data, uint32_t size)
{
    uint8_t *buffer = static_cast<uint8_t *>(CfMalloc(size, 0));
    if (buffer == nullptr) {
        LOGE("malloc uint8 array buffer failed!");
        return nullptr;
    }

    if (memcpy_s(buffer, size, data, size) != EOK) {
        LOGE("memcpy_s data to buffer failed!");
        CfFree(buffer);
        buffer = nullptr;
        return nullptr;
    }

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, size, [](napi_env env, void *data, void *hint) { CfFree(data); }, nullptr, &outBuffer);
    if (status != napi_ok) {
        LOGE("create uint8 array buffer failed!");
        CfFree(buffer);
        buffer = nullptr;
        return nullptr;
    }
    buffer = nullptr;
    return outBuffer;
}

static bool GetDataOfEncodingBlob(napi_env env, napi_value data, CfEncodingBlob *encodingBlob)
{
    napi_typedarray_type arrayType;
    napi_value arrayBuffer = nullptr;
    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;

    napi_status status = napi_get_typedarray_info(env, data, &arrayType, &length,
        reinterpret_cast<void **>(&rawData), &arrayBuffer, &offset);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get array data failed"));
        LOGE("failed to get array data!");
        return false;
    }
    if (arrayType != napi_uint8_array) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "array type is not uint8 array"));
        LOGE("array is not uint8 array!");
        return false;
    }

    if (length == 0) {
        LOGE("input data length is 0");
        return false;
    }
    encodingBlob->data = static_cast<uint8_t *>(CfMalloc(length, 0));
    if (encodingBlob->data == nullptr) {
        LOGE("malloc encoding blob data failed!");
        return false;
    }
    if (memcpy_s(encodingBlob->data, length, rawData, length) != EOK) {
        LOGE("memcpy_s encoding blob data failed!");
        CfFree(encodingBlob->data);
        encodingBlob->data = nullptr;
        return false;
    }
    encodingBlob->len = length;
    return true;
}

static char *CertGetStringFromValue(napi_env env, napi_value arg)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_string) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "param type is not string"));
        LOGE("wrong argument type. expect string type. [Type]: %{public}d", valueType);
        return nullptr;
    }

    size_t length = 0;
    if (napi_get_value_string_utf8(env, arg, nullptr, 0, &length) != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "can not get string length!"));
        LOGE("can not get string length");
        return nullptr;
    }

    if (length == 0) {
        LOGE("string length is 0");
        return nullptr;
    }

    char *value = static_cast<char *>(CfMalloc(length + 1, 0));
    if (value == nullptr) {
        LOGE("Failed to allocate value memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed!"));
        return nullptr;
    }

    if (napi_get_value_string_utf8(env, arg, value, length + 1, &length) != napi_ok) {
        LOGE("can not get value value");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get value failed"));
        memset_s(value, length + 1, 0, length + 1);
        CfFree(value);
        value = nullptr;
        return nullptr;
    }
    return value;
}

bool GetEncodingBlobFromValue(napi_env env, napi_value obj, CfEncodingBlob **encodingBlob)
{
    *encodingBlob = static_cast<CfEncodingBlob *>(CfMalloc(sizeof(CfEncodingBlob), 0));
    if (*encodingBlob == nullptr) {
        LOGE("malloc encoding blob failed!");
        return false;
    }
    napi_value data = nullptr;
    napi_status status = napi_get_named_property(env, obj, CERT_TAG_DATA.c_str(), &data);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get encoding blob data failed"));
        LOGE("failed to get encoding blob data!");
        CfFree(*encodingBlob);
        *encodingBlob = nullptr;
        return false;
    }
    if (!GetDataOfEncodingBlob(env, data, *encodingBlob)) {
        CfFree(*encodingBlob);
        *encodingBlob = nullptr;
        return false;
    }
    napi_value format = nullptr;
    status = napi_get_named_property(env, obj, CERT_TAG_ENCODING_FORMAT.c_str(), &format);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get encoding blob format failed"));
        LOGE("failed to get encoding blob format!");
        CfFree((*encodingBlob)->data);
        (*encodingBlob)->data = nullptr;
        CfFree(*encodingBlob);
        *encodingBlob = nullptr;
        return false;
    }
    napi_get_value_uint32(env, format, reinterpret_cast<uint32_t *>(&(*encodingBlob)->encodingFormat));
    return true;
}

static bool AllocatePrivateKey(PrivateKeyInfo **privateKey)
{
    (*privateKey)->privateKey = static_cast<CfEncodingBlob *>(CfMalloc(sizeof(CfEncodingBlob), 0));
    return (*privateKey)->privateKey != nullptr;
}

static bool GetBlobFromData(napi_env env, napi_value data, CfBlob **blob, napi_valuetype valueType)
{
    if (valueType == napi_string) {
        *blob = CertGetBlobFromStringJSParams(env, data);
        if (*blob == nullptr) {
            LOGE("get private key from string failed!");
            return false;
        }
        return true;
    } else {
        *blob = CertGetBlobFromUint8ArrJSParams(env, data);
        if (*blob == nullptr) {
            LOGE("get private key from uint8 array failed!");
            return false;
        }
        return true;
    }
}

static bool CopyBlobDataToPrivateKey(CfBlob *blob, CfEncodingBlob *privateKey)
{
    privateKey->data = static_cast<uint8_t *>(CfMalloc(blob->size, 0));
    if (privateKey->data == nullptr) {
        LOGE("malloc private key data failed!");
        return false;
    }
    if (memcpy_s(privateKey->data, blob->size, blob->data, blob->size) != EOK) {
        LOGE("memcpy_s private key data failed!");
        CfFree(privateKey->data);
        privateKey->data = nullptr;
        return false;
    }
    privateKey->len = blob->size;
    return true;
}

static bool GetPrivateKeyFromValue(napi_env env, napi_value obj, PrivateKeyInfo **privateKey)
{
    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, obj, CERT_PRIVATE_KEY.c_str(), &data);
    if (status != napi_ok || data == nullptr) {
        LOGE("Failed to get private key property!");
        return false;
    }

    napi_typeof(env, data, &valueType);
    if (valueType == napi_undefined) {
        LOGE("Invalid type for private key property!");
        return false;
    }

    if (!AllocatePrivateKey(privateKey)) {
        LOGE("malloc private key failed!");
        return false;
    }

    CfBlob *blob = nullptr;
    if (!GetBlobFromData(env, data, &blob, valueType)) {
        CfFree((*privateKey)->privateKey);
        (*privateKey)->privateKey = nullptr;
        return false;
    }

    (*privateKey)->privateKey->encodingFormat = (valueType == napi_string) ? CF_FORMAT_PEM : CF_FORMAT_DER;

    if (!CopyBlobDataToPrivateKey(blob, (*privateKey)->privateKey)) {
        CfFree(blob);
        blob = nullptr;
        CfFree((*privateKey)->privateKey);
        (*privateKey)->privateKey = nullptr;
        return false;
    }

    CfFree(blob);
    blob = nullptr;
    return true;
}

static bool GetPrivateKeyPasswordFromValue(napi_env env, napi_value obj, PrivateKeyInfo **privateKey)
{
    bool result = false;
    napi_has_named_property(env, obj, CERT_PASSWORD.c_str(), &result);
    if (!result) {
        return true;
    }
    napi_value password = nullptr;
    napi_status status = napi_get_named_property(env, obj, CERT_PASSWORD.c_str(), &password);
    if (status != napi_ok || password == nullptr) {
        LOGE("get property %{public}s failed!", CERT_PASSWORD.c_str());
        return false;
    }
    (*privateKey)->privateKeyPassword = CertGetStringFromValue(env, password);
    return true;
}

bool GetPrivateKeyInfoFromValue(napi_env env, napi_value obj, PrivateKeyInfo **privateKey)
{
    *privateKey = static_cast<PrivateKeyInfo *>(CfMalloc(sizeof(PrivateKeyInfo), 0));
    if (*privateKey == nullptr) {
        LOGE("malloc private key failed!");
        return false;
    }
    if (!GetPrivateKeyFromValue(env, obj, privateKey)) {
        CfFree(*privateKey);
        *privateKey = nullptr;
        return false;
    }
    if (!GetPrivateKeyPasswordFromValue(env, obj, privateKey)) {
        CfFree(*privateKey);
        *privateKey = nullptr;
        return false;
    }
    return true;
}

void FreePrivateKeyInfo(PrivateKeyInfo *privateKey)
{
    if (privateKey != nullptr) {
        if (privateKey->privateKey != nullptr) {
            memset_s(privateKey->privateKey->data, privateKey->privateKey->len, 0, privateKey->privateKey->len);
            CF_FREE_PTR(privateKey->privateKey->data);
            CF_FREE_PTR(privateKey->privateKey);
        }
        if (privateKey->privateKeyPassword != nullptr) {
            (void)memset_s(privateKey->privateKeyPassword, strlen(privateKey->privateKeyPassword), 0,
                strlen(privateKey->privateKeyPassword));
            CF_FREE_PTR(privateKey->privateKeyPassword);
        }
        CF_FREE_PTR(privateKey);
    }
}

static bool GetMdName(napi_env env, napi_value arg, char **mdName)
{
    bool result = false;
    napi_has_named_property(env, arg, CMS_GENERATOR_MDNAME.c_str(), &result);
    if (!result) {
        LOGI("%{public}s do not exist!", CMS_GENERATOR_MDNAME.c_str());
        return false;
    }
    napi_value obj = nullptr;
    napi_status status = napi_get_named_property(env, arg, CMS_GENERATOR_MDNAME.c_str(), &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property %{public}s failed!", CMS_GENERATOR_MDNAME.c_str());
        return false;
    }
    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType == napi_undefined) {
        LOGE("%{public}s valueType is null or undefined.", CMS_GENERATOR_MDNAME.c_str());
        return false;
    }
    *mdName = CertGetStringFromValue(env, obj);
    return true;
}

static bool GetRsaSigPadding(napi_env env, napi_value arg, CfCmsRsaSignaturePadding *rsaSigPadding)
{
    bool result = false;
    napi_status status = napi_has_named_property(env, arg, CMS_GENERATOR_RSA_SIG_PADDING.c_str(), &result);
    if (status != napi_ok) {
        LOGE("check attributes property failed!");
        return false;
    }
    if (!result) {
        LOGI("%{public}s do not exist!", CMS_GENERATOR_RSA_SIG_PADDING.c_str());
        *rsaSigPadding = PKCS1_PADDING;  // Set default padding to PKCS1
        return true;
    }
    napi_value obj = nullptr;
    status = napi_get_named_property(env, arg, CMS_GENERATOR_RSA_SIG_PADDING.c_str(), &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property %{public}s failed!", CMS_GENERATOR_RSA_SIG_PADDING.c_str());
        return false;
    }
    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType == napi_undefined) {
        LOGI("%{public}s valueType undefined.", CMS_GENERATOR_RSA_SIG_PADDING.c_str());
        *rsaSigPadding = PKCS1_PADDING;  // Set default padding to PKCS1
        return true;
    }
    status = napi_get_value_uint32(env, obj, reinterpret_cast<uint32_t *>(rsaSigPadding));
    if (status != napi_ok) {
        LOGE("get rsa signature padding value failed!");
        return false;
    }
    return true;
}

static bool GetAddCert(napi_env env, napi_value arg, bool *addCert)
{
    bool result = false;
    napi_has_named_property(env, arg, CMS_GENERATOR_ADD_CERT.c_str(), &result);
    if (!result) {
        LOGI("%{public}s do not exist!", CMS_GENERATOR_ADD_CERT.c_str());
        *addCert = true;
        return true;
    }
    napi_value obj = nullptr;
    napi_status status = napi_get_named_property(env, arg, CMS_GENERATOR_ADD_CERT.c_str(), &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property %{public}s failed!", CMS_GENERATOR_ADD_CERT.c_str());
        return false;
    }
    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType == napi_undefined) {
        LOGE("%{public}s valueType is null or undefined.", CMS_GENERATOR_ADD_CERT.c_str());
        return false;
    }
    napi_get_value_bool(env, obj, addCert);
    return true;
}

static bool GetAddSmimeCapAttr(napi_env env, napi_value arg, bool *addSmimeCapAttr)
{
    bool result = false;
    napi_has_named_property(env, arg, CMS_GENERATOR_ADD_SMIME_CAP_ATTR.c_str(), &result);
    if (!result) {
        LOGI("%{public}s do not exist!", CMS_GENERATOR_ADD_SMIME_CAP_ATTR.c_str());
        *addSmimeCapAttr = true;
        return true;
    }
    napi_value obj = nullptr;
    napi_status status = napi_get_named_property(env, arg, CMS_GENERATOR_ADD_SMIME_CAP_ATTR.c_str(), &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property %{public}s failed!", CMS_GENERATOR_ADD_SMIME_CAP_ATTR.c_str());
        return false;
    }
    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType == napi_undefined) {
        LOGE("%{public}s valueType is null or undefined.", CMS_GENERATOR_ADD_SMIME_CAP_ATTR.c_str());
        return false;
    }
    napi_get_value_bool(env, obj, addSmimeCapAttr);
    return true;
}

static bool GetAddAttr(napi_env env, napi_value arg, bool *addAttr)
{
    bool result = false;
    napi_has_named_property(env, arg, CMS_GENERATOR_ADD_ATTR.c_str(), &result);
    if (!result) {
        LOGI("%{public}s do not exist!", CMS_GENERATOR_ADD_ATTR.c_str());
        *addAttr = true;
        return true;
    }
    napi_value obj = nullptr;
    napi_status status = napi_get_named_property(env, arg, CMS_GENERATOR_ADD_ATTR.c_str(), &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property %{public}s failed!", CMS_GENERATOR_ADD_ATTR.c_str());
        return false;
    }
    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType == napi_undefined) {
        LOGE("%{public}s valueType is null or undefined.", CMS_GENERATOR_ADD_ATTR.c_str());
        return false;
    }
    napi_get_value_bool(env, obj, addAttr);
    return true;
}

static bool BuildCmsSignerOptions(napi_env env, napi_value obj, HcfCmsSignerOptions *options)
{
    napi_valuetype type;
    napi_typeof(env, obj, &type);
    if (type != napi_object) {
        LOGE("wrong argument type. expect object type. [Type]: %{public}d", type);
        return false;
    }
    if (!GetMdName(env, obj, &options->mdName)) {
        return false;
    }
    if (!GetRsaSigPadding(env, obj, &options->padding)) {
        return false;
    }
    if (!GetAddCert(env, obj, &options->addCert)) {
        return false;
    }
    if (!GetAddAttr(env, obj, &options->addAttr)) {
        return false;
    }
    if (!GetAddSmimeCapAttr(env, obj, &options->addSmimeCapAttr)) {
        return false;
    }
    return true;
}

bool GetCmsSignerOptionsFromValue(napi_env env, napi_value obj, HcfCmsSignerOptions **cmsSignerOptions)
{
    *cmsSignerOptions = static_cast<HcfCmsSignerOptions *>(CfMalloc(sizeof(HcfCmsSignerOptions), 0));
    if (*cmsSignerOptions == nullptr) {
        LOGE("malloc cms signer options failed!");
        return false;
    }
    if (!BuildCmsSignerOptions(env, obj, *cmsSignerOptions)) {
        CfFree((*cmsSignerOptions)->mdName);
        (*cmsSignerOptions)->mdName = nullptr;
        CfFree(*cmsSignerOptions);
        *cmsSignerOptions = nullptr;
        return false;
    }
    return true;
}

static bool GetFormat(napi_env env, napi_value arg, HcfCmsFormat *format)
{
    bool result = false;
    napi_has_named_property(env, arg, CMS_GENERATOR_OUT_FORMAT.c_str(), &result);
    if (!result) {
        LOGI("%{public}s do not exist!", CMS_GENERATOR_OUT_FORMAT.c_str());
        return true;
    }
    napi_value obj = nullptr;
    napi_status status = napi_get_named_property(env, arg, CMS_GENERATOR_OUT_FORMAT.c_str(), &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property %{public}s failed!", CMS_GENERATOR_OUT_FORMAT.c_str());
        return false;
    }
    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType == napi_undefined) {
        LOGE("%{public}s valueType is null or undefined.", CMS_GENERATOR_OUT_FORMAT.c_str());
        return false;
    }
    napi_get_value_uint32(env, obj, reinterpret_cast<uint32_t *>(format));
    return true;
}

static bool GetIsDetachedContent(napi_env env, napi_value arg, bool *isDetachedContent)
{
    bool result = false;
    napi_has_named_property(env, arg, CMS_GENERATOR_IS_DETACHED_CONTENT.c_str(), &result);
    if (!result) {
        LOGI("%{public}s do not exist!", CMS_GENERATOR_IS_DETACHED_CONTENT.c_str());
        return true;
    }
    napi_value obj = nullptr;
    napi_status status = napi_get_named_property(env, arg, CMS_GENERATOR_IS_DETACHED_CONTENT.c_str(), &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property %{public}s failed!", CMS_GENERATOR_IS_DETACHED_CONTENT.c_str());
        return false;
    }
    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType == napi_undefined) {
        LOGE("%{public}s valueType is null or undefined.", CMS_GENERATOR_IS_DETACHED_CONTENT.c_str());
        return false;
    }
    napi_get_value_bool(env, obj, isDetachedContent);
    return true;
}

static bool GetContentDataFormat(napi_env env, napi_value arg, HcfCmsContentDataFormat *dataFormat)
{
    bool result = false;
    napi_has_named_property(env, arg, CMS_GENERATOR_CONTENT_DATA_FORMAT.c_str(), &result);
    if (!result) {
        LOGI("%{public}s do not exist!", CMS_GENERATOR_CONTENT_DATA_FORMAT.c_str());
        return true;
    }
    napi_value obj = nullptr;
    napi_status status = napi_get_named_property(env, arg, CMS_GENERATOR_CONTENT_DATA_FORMAT.c_str(), &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property %{public}s failed!", CMS_GENERATOR_CONTENT_DATA_FORMAT.c_str());
        return false;
    }
    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType == napi_undefined) {
        LOGE("%{public}s valueType is null or undefined.", CMS_GENERATOR_CONTENT_DATA_FORMAT.c_str());
        return false;
    }
    napi_get_value_uint32(env, obj, reinterpret_cast<uint32_t *>(dataFormat));
    return true;
}

bool GetCmsGeneratorOptionsFromValue(napi_env env, napi_value obj, HcfCmsGeneratorOptions **options)
{
    napi_valuetype type;
    napi_typeof(env, obj, &type);
    if (type != napi_object) {
        LOGE("wrong argument type. expect object type. [Type]: %{public}d", type);
        return false;
    }
    if (!GetContentDataFormat(env, obj, &(*options)->dataFormat)) {
        LOGE("GetContentDataFormat failed!");
        return false;
    }
    if (!GetFormat(env, obj, &(*options)->outFormat)) {
        LOGE("GetFormat failed!");
        return false;
    }
    if (!GetIsDetachedContent(env, obj, &(*options)->isDetachedContent)) {
        LOGE("GetIsDetachedContent failed!");
        return false;
    }
    return true;
}
napi_value ConvertEncodingBlobToNapiValue(napi_env env, CfEncodingBlob *encodingBlob)
{
    napi_value outBuffer = GenerateArrayBuffer(env, encodingBlob->data, encodingBlob->len);
    if (outBuffer == nullptr) {
        LOGE("generate array buffer failed!");
        return nullptr;
    }
    napi_value outData = nullptr;
    napi_create_typedarray(env, napi_uint8_array, encodingBlob->len, outBuffer, 0, &outData);
    napi_value encoding = nullptr;
    napi_create_uint32(env, encodingBlob->encodingFormat, &encoding);
    napi_value returnEncodingBlob = nullptr;
    napi_create_object(env, &returnEncodingBlob);
    napi_set_named_property(env, returnEncodingBlob, CERT_TAG_DATA.c_str(), outData);
    napi_set_named_property(env, returnEncodingBlob, CERT_TAG_ENCODING_FORMAT.c_str(), encoding);
    return returnEncodingBlob;
}

CfBlob *CertGetBlobFromNapiValue(napi_env env, napi_value arg)
{
    if ((env == nullptr) || (arg == nullptr)) {
        LOGE("Invalid parmas!");
        return nullptr;
    }
    napi_value data = nullptr;
    napi_status status = napi_get_named_property(env, arg, CERT_TAG_DATA.c_str(), &data);
    if ((status != napi_ok) || (data == nullptr)) {
        LOGE("failed to get valid data property!");
        return nullptr;
    }
    return CertGetBlobFromUint8ArrJSParams(env, data);
}

napi_value CertConvertBlobToNapiValue(napi_env env, CfBlob *blob)
{
    napi_value outData = ConvertBlobToUint8ArrNapiValue(env, blob);
    if (outData == nullptr) {
        LOGE("convert to uint8 arr failed");
        return nullptr;
    }
    napi_value dataBlob = nullptr;
    napi_create_object(env, &dataBlob);
    napi_set_named_property(env, dataBlob, CERT_TAG_DATA.c_str(), outData);

    return dataBlob;
}

napi_value ConvertBlobToUint8ArrNapiValue(napi_env env, CfBlob *blob)
{
    if (blob == nullptr || blob->data == nullptr || blob->size == 0) {
        LOGE("Invalid blob!");
        return nullptr;
    }
    /* free in napi_create_external_arraybuffer, not in this scope. */
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

static bool GetDataOfCertChain(napi_env env, napi_value data, HcfCertChainData *certChain)
{
    napi_typedarray_type arrayType;
    napi_value arrayBuffer = nullptr;
    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;

    napi_status status = napi_get_typedarray_info(env, data, &arrayType, &length,
        reinterpret_cast<void **>(&rawData), &arrayBuffer, &offset);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get array data failed"));
        LOGE("failed to get array data!");
        return false;
    }
    if (arrayType != napi_uint8_array) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "array type is not uint8 array"));
        LOGE("array is not uint8 array!");
        return false;
    }

    if (length == 0) {
        LOGE("input data length is 0");
        return false;
    }
    certChain->data = static_cast<uint8_t *>(CfMalloc(length, 0));
    if (certChain->data == nullptr) {
        LOGE("malloc cert chain data failed!");
        return false;
    }
    if (memcpy_s(certChain->data, length, rawData, length) != EOK) {
        LOGE("memcpy_s cert chain data failed!");
        CfFree(certChain->data);
        certChain->data = nullptr;
        return false;
    }
    certChain->dataLen = length;
    return true;
}

bool GetCertChainFromValue(napi_env env, napi_value obj, HcfCertChainData **certChainData)
{
    *certChainData = static_cast<HcfCertChainData *>(CfMalloc(sizeof(HcfCertChainData), 0));
    if (*certChainData == nullptr) {
        LOGE("malloc certChainData failed!");
        return false;
    }
    napi_value data = nullptr;
    napi_status status = napi_get_named_property(env, obj, CERT_TAG_DATA.c_str(), &data);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get cert chain data failed"));
        LOGE("failed to get cert chain data!");
        CfFree(*certChainData);
        *certChainData = nullptr;
        return false;
    }
    if (!GetDataOfCertChain(env, data, *certChainData)) {
        CfFree(*certChainData);
        *certChainData = nullptr;
        return false;
    }

    napi_value certCount = nullptr;
    status = napi_get_named_property(env, obj, CERT_TAG_COUNT.c_str(), &certCount);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get cert chain count failed"));
        LOGE("failed to get cert count!");
        CfFree((*certChainData)->data);
        (*certChainData)->data = nullptr;
        CfFree(*certChainData);
        *certChainData = nullptr;
        return false;
    }
    napi_get_value_uint32(env, certCount, reinterpret_cast<uint32_t *>(&(*certChainData)->count));

    napi_value format = nullptr;
    status = napi_get_named_property(env, obj, CERT_TAG_ENCODING_FORMAT.c_str(), &format);
    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get cert chain format failed"));
        LOGE("failed to get cert chain format!");
        CfFree((*certChainData)->data);
        (*certChainData)->data = nullptr;
        CfFree(*certChainData);
        *certChainData = nullptr;
        return false;
    }
    napi_get_value_uint32(env, format, reinterpret_cast<uint32_t *>(&(*certChainData)->format));
    return true;
}

CfBlob *CertGetBlobFromUint8ArrJSParams(napi_env env, napi_value arg)
{
    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;
    napi_value arrayBuffer = nullptr;
    napi_typedarray_type arrayType;
    // Warning: Do not release the rawData returned by this interface because the rawData is managed by VM.
    napi_status status = napi_get_typedarray_info(
        env, arg, &arrayType, &length, reinterpret_cast<void **>(&rawData), &arrayBuffer, &offset);
    if (status != napi_ok) {
        LOGE("failed to get valid rawData.");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "failed to get valid rawData!"));
        return nullptr;
    }
    if (arrayType != napi_uint8_array) {
        LOGE("input data is not uint8 array.");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "input data is not uint8 array!"));
        return nullptr;
    }

    if (length == 0 || rawData == nullptr) {
        LOGE("array length is 0!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "array length is 0!"));
        return nullptr;
    }

    CfBlob *newBlob = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (newBlob == nullptr) {
        LOGE("Failed to allocate newBlob memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed!"));
        return nullptr;
    }

    newBlob->size = length;
    newBlob->data = static_cast<uint8_t *>(CfMalloc(length, 0));
    if (newBlob->data == nullptr) {
        LOGE("malloc blob data failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed!"));
        CfFree(newBlob);
        newBlob = nullptr;
        return nullptr;
    }
    if (memcpy_s(newBlob->data, length, rawData, length) != EOK) {
        LOGE("memcpy_s blob data failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_COPY, "copy memory failed!"));
        CfFree(newBlob->data);
        newBlob->data = nullptr;
        CfFree(newBlob);
        newBlob = nullptr;
        return nullptr;
    }
    return newBlob;
}

CfBlob *CertGetBlobFromStringJSParams(napi_env env, napi_value arg)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_string) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "param type is not string"));
        LOGE("wrong argument type. expect string type. [Type]: %{public}d", valueType);
        return nullptr;
    }

    size_t length = 0;
    if (napi_get_value_string_utf8(env, arg, nullptr, 0, &length) != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "can not get string length!"));
        LOGE("can not get string length");
        return nullptr;
    }

    if (length == 0) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "string length is 0!"));
        LOGE("string length is 0");
        return nullptr;
    }

    CfBlob *newBlob = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (newBlob == nullptr) {
        LOGE("Failed to allocate newBlob memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed!"));
        return nullptr;
    }

    newBlob->size = length + 1;
    newBlob->data = static_cast<uint8_t *>(CfMalloc(newBlob->size, 0));
    if (newBlob->data == nullptr) {
        LOGE("malloc blob data failed!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed"));
        CfFree(newBlob);
        newBlob = nullptr;
        return nullptr;
    }

    if (napi_get_value_string_utf8(env, arg, reinterpret_cast<char *>(newBlob->data), newBlob->size, &length) !=
        napi_ok) {
        LOGE("can not get string value");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get string failed"));
        CfFree(newBlob->data);
        newBlob->data = nullptr;
        CfFree(newBlob);
        newBlob = nullptr;
        return nullptr;
    }
    return newBlob;
}

napi_value GetProp(napi_env env, napi_value arg, const char *name)
{
    bool result = false;
    napi_has_named_property(env, arg, name, &result);
    if (!result) {
        LOGI("%{public}s do not exist!", name);
        return nullptr;
    }
    napi_value obj = nullptr;
    napi_status status = napi_get_named_property(env, arg, name, &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGI("get property %{public}s failed!", name);
        return nullptr;
    }
    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType == napi_undefined) {
        LOGI("%{public}s valueType is null or undefined.", name);
        return nullptr;
    }

    LOGI("%{public}s is not null!", name);
    return obj;
}

CfBlobArray *CertGetBlobArrFromArrUarrJSParams(napi_env env, napi_value arg)
{
    bool flag = false;
    napi_status status = napi_is_array(env, arg, &flag);
    if (status != napi_ok || !flag) {
        LOGE("not array!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "not array!"));
        return nullptr;
    }
    uint32_t length = 0;
    status = napi_get_array_length(env, arg, &length);
    if (status != napi_ok || length == 0 || length > MAX_NAPI_ARRAY_OF_U8ARR) {
        LOGE("length is invalid!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "length is invalid!"));
        return nullptr;
    }

    CfBlobArray *newBlobArr = static_cast<CfBlobArray *>(CfMalloc(sizeof(CfBlobArray), 0));
    if (newBlobArr == nullptr) {
        LOGE("Failed to allocate newBlobArr memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed"));
        return nullptr;
    }

    newBlobArr->count = length;
    newBlobArr->data = static_cast<CfBlob *>(CfMalloc(length * sizeof(CfBlob), 0));
    if (newBlobArr->data == nullptr) {
        LOGE("Failed to allocate data memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed"));
        CF_FREE_PTR(newBlobArr);
        return nullptr;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        if (napi_get_element(env, arg, i, &element) == napi_ok) {
            CfBlob *blob = CertGetBlobFromUint8ArrJSParams(env, element);
            if (blob != nullptr) {
                newBlobArr->data[i] = *blob;
                CfFree(blob); // release blob object, not release blob data
                blob = nullptr;
                continue;
            }
        }
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "input arr is invalid"));
        FreeCfBlobArray(newBlobArr->data, newBlobArr->count);
        CF_FREE_PTR(newBlobArr);
        LOGE("Failed to allocate data memory!");
        return nullptr;
    }
    return newBlobArr;
}

static bool GetArrayLen(napi_env env, napi_value arg, uint32_t &length)
{
    bool flag = false;
    napi_status status = napi_is_array(env, arg, &flag);
    if (status != napi_ok || !flag) {
        LOGE("not array!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "not array!"));
        return false;
    }

    status = napi_get_array_length(env, arg, &length);
    if (status != napi_ok || length == 0) {
        LOGE("array length = 0!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "array length = 0!"));
        return false;
    }
    return true;
}

CfBlob *CertGetBlobFromArrBoolJSParams(napi_env env, napi_value arg)
{
    uint32_t length = 0;
    if (!GetArrayLen(env, arg, length)) {
        LOGE("get array length failed!");
        return nullptr;
    }

    CfBlob *newBlob = static_cast<CfBlob *>(CfMalloc(sizeof(CfBlob), 0));
    if (newBlob == nullptr) {
        LOGE("Failed to allocate newBlob memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed"));
        return nullptr;
    }

    newBlob->size = length;
    newBlob->data = static_cast<uint8_t *>(CfMalloc(length, 0));
    if (newBlob->data == nullptr) {
        LOGE("Failed to allocate data memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed"));
        CfFree(newBlob);
        newBlob = nullptr;
        return nullptr;
    }
    napi_status status = napi_ok;
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        status = napi_get_element(env, arg, i, &element);
        if (status != napi_ok) {
            LOGE("Failed to get element!");
            break;
        }
        bool elemResult = false;
        status = napi_get_value_bool(env, element, &elemResult);
        if (status != napi_ok) {
            LOGE("Failed to get value bool!");
            break;
        }
        newBlob->data[i] = (elemResult ? 1 : 0);
    }

    if (status != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "invalid params!"));
        CfFree(newBlob->data);
        newBlob->data = nullptr;
        CfFree(newBlob);
        newBlob = nullptr;
        return nullptr;
    }

    return newBlob;
}

bool ParserArray(napi_env env, napi_value arg, uint32_t &arrayLen)
{
    bool flag = false;
    napi_status status = napi_is_array(env, arg, &flag);
    if (status != napi_ok || !flag) {
        return false;
    }
    uint32_t length = 0;
    status = napi_get_array_length(env, arg, &length);
    if (status != napi_ok || length == 0 || length > MAX_NAPI_ARRAY_OF_U8ARR) {
        return false;
    }
    arrayLen = length;
    return true;
}

void SubAltNameArrayDataClearAndFree(SubAltNameArray *array)
{
    if (array == NULL) {
        LOGD("The input array is null, no need to free.");
        return;
    }
    if (array->data != NULL) {
        for (uint32_t i = 0; i < array->count; ++i) {
            CF_FREE_BLOB(array->data[i].name);
        }
        CfFree(array->data);
        array->data = NULL;
        array->count = 0;
    }
}

SubAltNameArray *CertGetSANArrFromArrUarrJSParams(napi_env env, napi_value arg)
{
    uint32_t length = 0;
    if (!ParserArray(env, arg, length)) {
        LOGE("Length is invalid!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "length is invalid!"));
        return nullptr;
    }

    SubAltNameArray *newSANArr = static_cast<SubAltNameArray *>(CfMalloc(sizeof(SubAltNameArray), 0));
    if (newSANArr == nullptr) {
        LOGE("Failed to allocate newSANArr memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed"));
        return nullptr;
    }

    newSANArr->count = length;
    newSANArr->data =
        static_cast<SubjectAlternaiveNameData *>(CfMalloc(length * sizeof(SubjectAlternaiveNameData), 0));
    if (newSANArr->data == nullptr) {
        LOGE("Failed to allocate data memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed"));
        goto exit;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        if (napi_get_element(env, arg, i, &element) == napi_ok) {
            napi_value obj = GetProp(env, element, CERT_MATCH_TAG_SUBJECT_ALT_NAMES_TYPE.c_str());
            if (obj == nullptr || napi_get_value_int32(env, obj, (int32_t *)&(newSANArr->data[i].type)) != napi_ok) {
                LOGE("Failed to get type!");
                goto exit;
            }
            obj = GetProp(env, element, CERT_MATCH_TAG_SUBJECT_ALT_NAMES_DATA.c_str());
            CfBlob *blob = CertGetBlobFromUint8ArrJSParams(env, obj);
            if (blob != nullptr) {
                newSANArr->data[i].name = *blob;
                CfFree(blob);
                blob = nullptr;
                continue;
            }
        }
        LOGE("Failed to allocate data memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "input arr is invalid"));
        goto exit;
    }
    return newSANArr;
exit:
    SubAltNameArrayDataClearAndFree(newSANArr);
    CfFree(newSANArr);
    newSANArr = nullptr;
    return nullptr;
}

CfArray *CertGetArrFromArrUarrJSParams(napi_env env, napi_value arg)
{
    bool flag = false;
    napi_status status = napi_is_array(env, arg, &flag);
    if (status != napi_ok || !flag) {
        LOGE("Not array!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "not array!"));
        return nullptr;
    }
    uint32_t length = 0;
    status = napi_get_array_length(env, arg, &length);
    if (status != napi_ok || length == 0 || length > MAX_NAPI_ARRAY_OF_U8ARR) {
        LOGE("Length is invalid!");
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "length is invalid!"));
        return nullptr;
    }
    CfArray *newBlobArr = static_cast<CfArray *>(CfMalloc(sizeof(CfArray), 0));
    if (newBlobArr == nullptr) {
        LOGE("Failed to allocate newBlobArr memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed"));
        return nullptr;
    }
    newBlobArr->count = length;
    newBlobArr->format = CF_FORMAT_DER;
    newBlobArr->data = static_cast<CfBlob *>(CfMalloc(length * sizeof(CfBlob), 0));
    if (newBlobArr->data == nullptr) {
        LOGE("Failed to allocate data memory!");
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc failed"));
        CF_FREE_PTR(newBlobArr);
        return nullptr;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        if (napi_get_element(env, arg, i, &element) == napi_ok) {
            CfBlob *blob = CertGetBlobFromStringJSParams(env, element);
            if (blob != nullptr) {
                newBlobArr->data[i] = *blob;
                CF_FREE_PTR(blob);
                continue;
            }
        }
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "input arr is invalid"));
        FreeCfBlobArray(newBlobArr->data, newBlobArr->count);
        CF_FREE_PTR(newBlobArr);
        LOGE("Failed to allocate data memory!");
        return nullptr;
    }
    return newBlobArr;
}

bool CertGetBlobFromBigIntJSParams(napi_env env, napi_value arg, CfBlob &outBlob)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_bigint) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "param type error"));
        LOGE("Wrong argument type. expect int type. [Type]: %{public}d", valueType);
        return false;
    }

    int signBit;
    size_t wordCount;

    napi_get_value_bigint_words(env, arg, nullptr, &wordCount, nullptr);
    if ((wordCount == 0) || (wordCount > (MAX_SN_BYTE_CNT / sizeof(uint64_t)))) {
        LOGE("Get big int failed.");
        return false;
    }
    int length = wordCount * sizeof(uint64_t);
    uint8_t *retArr = reinterpret_cast<uint8_t *>(CfMalloc(length, 0));
    if (retArr == nullptr) {
        LOGE("Malloc blob data failed!");
        return false;
    }
    if (napi_get_value_bigint_words(env, arg, &signBit, &wordCount, reinterpret_cast<uint64_t *>(retArr)) != napi_ok) {
        CfFree(retArr);
        retArr = nullptr;
        LOGE("Failed to get valid rawData.");
        return false;
    }
    if (signBit != 0) {
        CfFree(retArr);
        retArr = nullptr;
        LOGE("Failed to get gegative rawData.");
        return false;
    }
    outBlob.data = retArr;
    outBlob.size = (uint32_t)length;
    return true;
}

bool CertGetSerialNumberFromBigIntJSParams(napi_env env, napi_value arg, CfBlob &outBlob)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_bigint) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "param type error"));
        LOGE("wrong argument type. expect int type. [Type]: %{public}d", valueType);
        return false;
    }

    size_t wordCount = 0;
    if (napi_get_value_bigint_words(env, arg, nullptr, &wordCount, nullptr) != napi_ok) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get serialNum failed"));
        LOGE("can not get word count");
        return false;
    }
    if (wordCount == 0 || wordCount > (MAX_SN_BYTE_CNT / sizeof(int64_t))) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get serialNum len failed"));
        LOGE("can not get wordCount, wordCount = %{public}zu", wordCount);
        return false;
    }

    uint8_t serialBuf[MAX_SN_BYTE_CNT] = { 0 };
    uint32_t serialLen = sizeof(int64_t) * wordCount;

    int sign = 0;
    if (napi_get_value_bigint_words(env, arg, &sign, &wordCount, reinterpret_cast<uint64_t *>(serialBuf)) != napi_ok ||
        sign > 0) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "get serialNum len failed"));
        LOGE("can not get bigint value, sign = %{public}d", sign); // sign 0 : positive, sign 1 : negative
        return false;
    }
    outBlob.data = static_cast<uint8_t *>(CfMalloc(serialLen, 0));
    if (outBlob.data == nullptr) {
        napi_throw(env, CertGenerateBusinessError(env, CF_ERR_MALLOC, "malloc serialNum failed"));
        LOGE("malloc blob data failed!");
        return false;
    }
    outBlob.size = serialLen;
    // reverse data: because BN_bin2bn() converts the positive integer in big-endian form of length len into a BIGNUM
    for (uint32_t i = 0; i < serialLen; ++i) {
        outBlob.data[i] = serialBuf[outBlob.size - 1 - i];
    }

    return true;
}

bool CertGetStringFromJSParams(napi_env env, napi_value arg, string &returnStr)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_string) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "param type is not string"));
        LOGE("wrong argument type. expect string type. [Type]: %{public}d", valueType);
        return false;
    }

    size_t length = 0;
    if (napi_get_value_string_utf8(env, arg, nullptr, 0, &length) != napi_ok) {
        LOGE("can not get string length");
        return false;
    }
    returnStr.reserve(length + 1);
    returnStr.resize(length);
    if (napi_get_value_string_utf8(env, arg, returnStr.data(), (length + 1), &length) != napi_ok) {
        LOGE("can not get string value");
        return false;
    }
    return true;
}

bool CertGetInt32FromJSParams(napi_env env, napi_value arg, int32_t &returnInt)
{
    napi_valuetype valueType;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_number) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "param type is not number"));
        LOGE("wrong argument type. expect int type. [Type]: %{public}d", valueType);
        return false;
    }

    if (napi_get_value_int32(env, arg, &returnInt) != napi_ok) {
        LOGE("can not get int value");
        return false;
    }
    return true;
}

CfResult CertGetInt32FromJSParamsNotThrow(napi_env env, napi_value arg, int32_t &returnInt)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);

    if (valueType == napi_undefined) {
        LOGD("param type is undefined");
        return CF_SUCCESS;
    }
    if (valueType != napi_number) {
        LOGE("wrong argument type. expect int type. [Type]: %{public}d", valueType);
        return CF_INVALID_PARAMS;
    }

    if (napi_get_value_int32(env, arg, &returnInt) != napi_ok) {
        LOGE("can not get int value");
        return CF_ERR_NAPI;
    }
    return CF_SUCCESS;
}

bool CertGetCallbackFromJSParams(napi_env env, napi_value arg, napi_ref *returnCb)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);
    if (valueType != napi_function) {
        napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "param type is not function"));
        LOGE("wrong argument type. expect callback type. [Type]: %{public}d", valueType);
        return false;
    }

    napi_create_reference(env, arg, 1, returnCb);
    return true;
}

static uint32_t GetCertErrValueByErrCode(int32_t errCode)
{
    uint32_t count = sizeof(CODE_MAP) / sizeof(CODE_MAP[0]);
    for (uint32_t i = 0; i < count; i++) {
        if (errCode == CODE_MAP[i].retValue) {
            return CODE_MAP[i].retCode;
        }
    }
    return JS_ERR_CERT_RUNTIME_ERROR;
}

napi_value CertGenerateBusinessError(napi_env env, int32_t errCode, const char *errMsg)
{
    napi_value businessError = nullptr;

    napi_value code = nullptr;
    napi_create_uint32(env, GetCertErrValueByErrCode(errCode), &code);

    napi_value msg = nullptr;
    napi_create_string_utf8(env, errMsg, NAPI_AUTO_LENGTH, &msg);

    napi_create_error(env, nullptr, msg, &businessError);
    napi_set_named_property(env, businessError, CERT_TAG_ERR_CODE.c_str(), code);

    return businessError;
}

bool CertCheckArgsCount(napi_env env, size_t argc, size_t expectedCount, bool isSync)
{
    if (isSync) {
        if (argc != expectedCount) {
            napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "invalid params count"));
            LOGE("invalid params count!");
            return false;
        }
    } else {
        if ((argc != expectedCount) && (argc != (expectedCount - ARGS_SIZE_ONE))) {
            napi_throw(env, CertGenerateBusinessError(env, CF_INVALID_PARAMS, "invalid params count"));
            LOGE("invalid params count!");
            return false;
        }
    }
    return true;
}

AsyncType GetAsyncType(napi_env env, size_t argc, size_t maxCount, napi_value arg)
{
    if (argc == (maxCount - 1)) { /* inner caller func: maxCount is bigger than 1 */
        return ASYNC_TYPE_PROMISE;
    }

    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);
    /* If the input is undefined or null, the value is processed as promise type. */
    if ((valueType == napi_undefined) || (valueType == napi_null)) {
        CF_LOG_I("input value is undefined or null");
        return ASYNC_TYPE_PROMISE;
    }

    return ASYNC_TYPE_CALLBACK;
}

napi_value CertGetResourceName(napi_env env, const char *name)
{
    napi_value resourceName = nullptr;
    napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &resourceName);
    return resourceName;
}

bool GetBoolFromNapiValue(napi_env env, napi_value arg, bool &out, const char *name)
{
    napi_value obj = GetProp(env, arg, name);
    if (obj == nullptr) {
        return true;
    }

    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType != napi_boolean) {
        LOGE("Get %{public}s obj is not bool!", name);
        return false;
    }

    napi_status status = napi_get_value_bool(env, obj, &out);
    if (status != napi_ok) {
        LOGE("Failed to get value bool!");
        return false;
    }
    return true;
}

CfResult GetBoolFromNameValue(napi_env env, napi_value arg, bool *out, const char *name)
{
    bool result = false;
    napi_status status = napi_has_named_property(env, arg, name, &result);
    if (status != napi_ok) {
        LOGE("check %{public}s property failed!", name);
        return CF_ERR_NAPI;
    }
    if (!result) {
        LOGI("%{public}s do not exist!", name);
        *out = false;
        return CF_SUCCESS;
    }
    napi_value obj = nullptr;
    status = napi_get_named_property(env, arg, name, &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property %{public}s failed!", name);
        return CF_ERR_NAPI;
    }
    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType == napi_undefined) {
        LOGI("%{public}s valueType is undefined.", name);
        *out = false;
        return CF_SUCCESS;
    }
    status = napi_get_value_bool(env, obj, out);
    if (status != napi_ok) {
        LOGE("Failed to get value bool!");
        return CF_ERR_NAPI;
    }
    return CF_SUCCESS;
}

bool GetIsPemFromStringNapiValue(napi_env env, napi_value arg, bool &out, const char *name)
{
    napi_value obj = GetProp(env, arg, name);
    if (obj == nullptr) {
        return true;
    }
    CfEncodinigBaseFormat encodingBaseFormat = PEM;
    napi_status status = napi_get_value_int32(env, obj, (int32_t *)&encodingBaseFormat);
    if (status != napi_ok) {
        LOGE("get privateKeyFormat failed!");
        return false;
    }
    if (encodingBaseFormat == DER) {
        out = false;
    }
    return true;
}

napi_value ConvertBlobToNapiValue(napi_env env, const CfBlob *blob)
{
    if (blob == nullptr || blob->data == nullptr || blob->size == 0) {
        LOGE("Invalid blob!");
        return nullptr;
    }
    uint8_t *buffer = static_cast<uint8_t *>(CfMalloc(blob->size, 0));
    if (buffer == nullptr) {
        LOGE("malloc uint8 array buffer failed!");
        return nullptr;
    }

    (void)memcpy_s(buffer, blob->size, blob->data, blob->size);
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
    napi_value dataBlob = nullptr;
    napi_create_object(env, &dataBlob);
    napi_set_named_property(env, dataBlob, CERT_TAG_DATA.c_str(), outData);

    return dataBlob;
}

static CfResult ConvertBlobToWords(const CfBlob &blob, uint64_t *&words, uint32_t &wordsCount)
{
    uint32_t blockSize = sizeof(uint64_t);
    uint32_t convertDataSize = ((blob.size + (blockSize - 1)) >> QUAD_WORD_ALIGN_UP) << QUAD_WORD_ALIGN_UP;
    uint8_t *convertData = static_cast<uint8_t *>(CfMalloc(convertDataSize, 0));
    if (convertData == nullptr) {
        LOGE("malloc convert data failed");
        return CF_ERR_MALLOC;
    }

    /* convertData has been initialized 0, reverse blob data */
    for (uint32_t i = 0; i < blob.size; ++i) {
        convertData[i] = blob.data[blob.size - 1 - i];
    }

    words = reinterpret_cast<uint64_t *>(convertData);
    wordsCount = convertDataSize / blockSize;
    return CF_SUCCESS;
}

napi_value ConvertBlobToBigIntWords(napi_env env, const CfBlob &blob)
{
    if (blob.data == nullptr || blob.size == 0 || blob.size > MAX_SN_BYTE_CNT) {
        LOGE("Invalid blob!");
        return nullptr;
    }

    uint64_t *words = nullptr;
    uint32_t wordsCount = 0;
    CfResult ret = ConvertBlobToWords(blob, words, wordsCount);
    if (ret != CF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, ret, "convert data to words failed"));
        LOGE("convert data to words failed");
        return nullptr;
    }

    napi_value result = nullptr;
    napi_create_bigint_words(env, 0, wordsCount, words, &result);
    CfFree(words);
    words = nullptr;
    return result;
}

napi_value ConvertBlobToInt64(napi_env env, const CfBlob &blob)
{
    if (blob.data == nullptr || blob.size == 0 || blob.size > sizeof(int64_t)) {
        LOGE("Invalid blob!");
        return nullptr;
    }

    uint64_t serialNumber = 0;
    for (uint32_t i = 0; i < blob.size; ++i) {
        serialNumber = ((serialNumber << (BYTE_TO_BIT_CNT * i)) | static_cast<uint64_t>(blob.data[i]));
    }

    napi_value result = nullptr;
    napi_create_int64(env, static_cast<long>(serialNumber), &result);
    return result;
}

napi_value ConvertArrayStringToNapiValue(napi_env env, CfArray *array)
{
    if (array == nullptr) {
        LOGE("array is null!");
        return nullptr;
    }
    if (array->count == 0) {
        LOGE("array count is 0!");
        return nullptr;
    }
    napi_value returnArray = nullptr;
    napi_create_array(env, &returnArray);
    if (returnArray == nullptr) {
        LOGE("create return array failed!");
        return nullptr;
    }
    for (uint32_t i = 0; i < array->count; i++) {
        CfBlob *blob = reinterpret_cast<CfBlob *>(array->data + i);
        napi_value element = nullptr;
        napi_create_string_utf8(env, reinterpret_cast<char *>(blob->data), blob->size, &element);
        napi_set_element(env, returnArray, i, element);
    }
    return returnArray;
}

bool ConvertBlobToEncodingBlob(const CfBlob &blob, CfEncodingBlob *encodingBlob)
{
    if (blob.data == nullptr || blob.size == 0) {
        LOGE("Invalid blob!");
        return false;
    }

    encodingBlob->data = static_cast<uint8_t *>(CfMalloc(blob.size, 0));
    if (encodingBlob->data == nullptr) {
        LOGE("malloc encoding blob data failed!");
        return false;
    }
    if (memcpy_s(encodingBlob->data, blob.size, blob.data, blob.size) != EOK) {
        LOGE("memcpy_s encoding blob data failed!");
        CfFree(encodingBlob->data);
        encodingBlob->data = nullptr;
        return false;
    }
    encodingBlob->len = blob.size;
    encodingBlob->encodingFormat = CF_FORMAT_DER;
    return true;
}

void FreeCmsParserSignedDataOptions(HcfCmsParserSignedDataOptions *options)
{
    if (options == nullptr) {
        return;
    }
    options->trustCerts = nullptr;
    options->signerCerts = nullptr;
    CfBlobDataFree(options->contentData);
    options->contentDataFormat = BINARY;
    CfFree(options);
    options = nullptr;
}

static CfResult GetCmsCertsFromData(napi_env env, napi_value arg, HcfX509CertificateArray **certs, const char *name,
    bool isOptional)
{
    napi_value obj = nullptr;
    napi_valuetype valueType;
    HcfX509CertificateArray *certsArray =
        static_cast<HcfX509CertificateArray *>(CfMalloc(sizeof(HcfX509CertificateArray), 0));
    if (certsArray == nullptr) {
        LOGE("malloc certsArray failed!");
        return CF_ERR_MALLOC;
    }
    bool result = false;
    if (napi_has_named_property(env, arg, name, &result) != napi_ok) {
        CfFree(certsArray);
        LOGE("check attributes property failed!");
        return CF_ERR_NAPI;
    }
    if (!result && isOptional) {
        CfFree(certsArray);
        LOGI("%{public}s do not exist!", name);
        return CF_SUCCESS;
    }
    if (napi_get_named_property(env, arg, name, &obj) != napi_ok || obj == nullptr ||
        napi_typeof(env, obj, &valueType) != napi_ok || valueType == napi_undefined) {
        CfFree(certsArray);
        LOGE("get property or type failed: %{public}s", name);
        return CF_ERR_NAPI;
    }
    if (!GetArrayCertFromNapiValue(env, obj, certsArray)) {
        CfFree(certsArray);
        LOGE("get array cert from data failed!");
        return CF_ERR_NAPI;
    }
    *certs = certsArray;
    return CF_SUCCESS;
}

static CfResult GetContentDataFromValue(napi_env env, napi_value obj, CfBlob **contentData, const char *name)
{
    bool hasProperty = false;
    napi_has_named_property(env, obj, name, &hasProperty);
    if (!hasProperty) {
        *contentData = NULL;
        return CF_SUCCESS;
    }

    napi_value data = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_get_named_property(env, obj, name, &data);
    if (status != napi_ok || data == nullptr) {
        LOGE("Failed to get %{public}s property!", name);
        return CF_ERR_NAPI;
    }

    napi_typeof(env, data, &valueType);
    if (valueType == napi_undefined) {
        LOGE("Invalid type for %{public}s property!", name);
        return CF_INVALID_PARAMS;
    }

    if (valueType == napi_object) {
        size_t length = 0;
        size_t offset = 0;
        void *rawData = nullptr;
        napi_value arrayBuffer = nullptr;
        napi_typedarray_type arrayType;
        napi_status status = napi_get_typedarray_info(
            env, data, &arrayType, &length, reinterpret_cast<void **>(&rawData), &arrayBuffer, &offset);
        if (status == napi_ok && arrayType == napi_uint8_array) {
            if (length == 0 || rawData == nullptr) {
                LOGD("verify content data is support empty!");
                *contentData = nullptr;
                return CF_SUCCESS;
            }
        }
    }

    CfBlob *blob = nullptr;
    if (!GetBlobFromData(env, data, &blob, valueType)) {
        LOGE("get blob from data failed!");
        return CF_ERR_NAPI;
    }
    *contentData = blob;
    return CF_SUCCESS;
}

static CfResult GetContentDataFormatFromValue(napi_env env, napi_value obj, HcfCmsContentDataFormat *contentDataFormat)
{
    CfResult res = CF_SUCCESS;
    bool hasProperty = false;
    napi_has_named_property(env, obj, CMS_PARSER_CONTENT_DATA_FORMAT.c_str(), &hasProperty);
    if (!hasProperty) {
        LOGD("contentDataFormat do not exist, use default value BINARY!");
        *contentDataFormat = BINARY;
        return CF_SUCCESS;
    }

    napi_value formatValue = nullptr;
    napi_status status = napi_get_named_property(env, obj, CMS_PARSER_CONTENT_DATA_FORMAT.c_str(), &formatValue);
    if (status != napi_ok || formatValue == nullptr) {
        LOGE("Failed to get contentDataFormat from napi value!");
        return CF_ERR_NAPI;
    }
    int32_t format = 0;
    res = CertGetInt32FromJSParamsNotThrow(env, formatValue, format);
    if (res != CF_SUCCESS) {
        LOGE("Failed to get contentDataFormat!");
        return res;
    }
    HcfCmsContentDataFormat dataFormat = static_cast<HcfCmsContentDataFormat>(format);
    *contentDataFormat = dataFormat;
    return CF_SUCCESS;
}

CfResult CertGetCmsParserSignedDataOptionsFromValue(napi_env env, napi_value obj,
    HcfCmsParserSignedDataOptions **options)
{
    if (obj == nullptr || options == nullptr) {
        LOGE("Invalid input parameters!");
        return CF_ERR_PARAMETER_CHECK;
    }
    HcfCmsParserSignedDataOptions *tmpOptions =
        (HcfCmsParserSignedDataOptions *)CfMalloc(sizeof(HcfCmsParserSignedDataOptions), 0);
    if (tmpOptions == NULL) {
        LOGE("Failed to allocate memory for options!");
        return CF_ERR_MALLOC;
    }
    CfResult res = CF_SUCCESS;
    res = GetCmsCertsFromData(env, obj, &tmpOptions->trustCerts, CMS_PARSER_TRUST_CERTS.c_str(), false);
    if (res != CF_SUCCESS) {
        LOGE("Failed to get trustCerts!");
        FreeCmsParserSignedDataOptions(tmpOptions);
        return res;
    }
    res = GetCmsCertsFromData(env, obj, &tmpOptions->signerCerts, CMS_PARSER_SIGNER_CERTS.c_str(), true);
    if (res != CF_SUCCESS) {
        LOGE("Failed to get signerCerts!");
        FreeCmsParserSignedDataOptions(tmpOptions);
        return res;
    }

    res = GetContentDataFromValue(env, obj, &tmpOptions->contentData, CMS_PARSER_CONTENT_DATA.c_str());
    if (res != CF_SUCCESS) {
        LOGE("Failed to get contentData!");
        FreeCmsParserSignedDataOptions(tmpOptions);
        return res;
    }

    res = GetContentDataFormatFromValue(env, obj, &tmpOptions->contentDataFormat);
    if (res != CF_SUCCESS) {
        LOGE("Failed to get contentDataFormat!");
        FreeCmsParserSignedDataOptions(tmpOptions);
        return res;
    }
    *options = tmpOptions;
    return res;
}

static CfResult GetKeyInfoFromValue(napi_env env, napi_value obj, PrivateKeyInfo **keyInfo)
{
    CfResult res = CF_SUCCESS;
    bool hasProperty = false;
    napi_has_named_property(env, obj, CMS_PARSER_PRIVATE_KEY.c_str(), &hasProperty);
    if (!hasProperty) {
        *keyInfo = NULL;
        return res;
    }

    napi_value keyInfoValue = nullptr;
    napi_status status = napi_get_named_property(env, obj, CMS_PARSER_PRIVATE_KEY.c_str(), &keyInfoValue);
    if (status != napi_ok || keyInfoValue == nullptr) {
        *keyInfo = NULL;
        return res;
    }

    if (!GetPrivateKeyInfoFromValue(env, keyInfoValue, keyInfo)) {
        LOGE("Failed to get keyInfo!");
        return CF_ERR_NAPI;
    }
    return res;
}

static CfResult GetCertFromValue(napi_env env, napi_value obj, HcfX509Certificate **cert)
{
    CfResult res = CF_SUCCESS;
    bool hasProperty = false;
    napi_has_named_property(env, obj, CMS_PARSER_CERT.c_str(), &hasProperty);
    if (!hasProperty) {
        *cert = NULL;
        return res;
    }

    napi_value certValue = nullptr;
    napi_status status = napi_get_named_property(env, obj, CMS_PARSER_CERT.c_str(), &certValue);
    if (status != napi_ok || certValue == nullptr) {
        *cert = NULL;
        return res;
    }

    NapiX509Certificate *napiCertObj = nullptr;
    napi_unwrap(env, certValue, reinterpret_cast<void **>(&napiCertObj));
    if (napiCertObj == nullptr) {
        LOGE("Failed to get certificate!");
        return CF_ERR_NAPI;
    }

    *cert = napiCertObj->GetX509Cert();
    return res;
}

void FreeCmsParserDecryptEnvelopedDataOptions(HcfCmsParserDecryptEnvelopedDataOptions *options)
{
    if (options == nullptr) {
        return;
    }
    FreePrivateKeyInfo(options->privateKey);
    options->cert = nullptr;
    CfBlobDataFree(options->encryptedContentData);
    options->contentDataFormat = BINARY;
    CF_FREE_PTR(options);
    options = nullptr;
}

CfResult CertGetCmsParserEnvelopedDataOptionsFromValue(napi_env env, napi_value obj,
    HcfCmsParserDecryptEnvelopedDataOptions **options)
{
    if (obj == nullptr || options == nullptr) {
        LOGE("Invalid input parameters!");
        return CF_ERR_PARAMETER_CHECK;
    }
    HcfCmsParserDecryptEnvelopedDataOptions *tmpOptions =
        (HcfCmsParserDecryptEnvelopedDataOptions *)CfMalloc(sizeof(HcfCmsParserDecryptEnvelopedDataOptions), 0);
    if (tmpOptions == NULL) {
        LOGE("Failed to allocate memory for options!");
        return CF_ERR_MALLOC;
    }

    CfResult res = GetKeyInfoFromValue(env, obj, &tmpOptions->privateKey);
    if (res != CF_SUCCESS) {
        LOGE("Failed to get keyInfo!");
        FreeCmsParserDecryptEnvelopedDataOptions(tmpOptions);
        return res;
    }

    res = GetCertFromValue(env, obj, &tmpOptions->cert);
    if (res != CF_SUCCESS) {
        LOGE("Failed to get cert!");
        FreeCmsParserDecryptEnvelopedDataOptions(tmpOptions);
        return res;
    }

    res = GetContentDataFromValue(
        env, obj, &tmpOptions->encryptedContentData, CMS_PARSER_ENCRYPTED_CONTENT_DATA.c_str());
    if (res != CF_SUCCESS) {
        LOGE("Failed to get encryptedContentData!");
        FreeCmsParserDecryptEnvelopedDataOptions(tmpOptions);
        return res;
    }

    res = GetContentDataFormatFromValue(env, obj, &tmpOptions->contentDataFormat);
    if (res != CF_SUCCESS) {
        LOGE("Failed to get contentDataFormat!");
        FreeCmsParserDecryptEnvelopedDataOptions(tmpOptions);
        return res;
    }

    *options = tmpOptions;
    return res;
}

}  // namespace CertFramework
}  // namespace OHOS
