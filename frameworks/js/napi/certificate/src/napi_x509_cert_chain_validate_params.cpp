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

#include "napi_x509_cert_chain_validate_params.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_type.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_cert_crl_collection.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_object.h"
#include "napi_x509_trust_anchor.h"
#include "napi_x509_certificate.h"
#include "utils.h"
#include "x509_cert_chain_validate_params.h"

namespace OHOS {
namespace CertFramework {

static bool GetValidDate(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_DATE.c_str());
    if (obj == nullptr) {
        LOGI("prop date do not exist!");
        return true;
    }
    out = CertGetBlobFromStringJSParams(env, obj);
    if (out == nullptr) {
        LOGE("get blob failed!");
        return false;
    }
    return true;
}

static bool GetArrayLength(napi_env env, napi_value arg, uint32_t &length)
{
    bool flag = false;
    napi_status status = napi_is_array(env, arg, &flag);
    if (status != napi_ok || !flag) {
        LOGE("param type not array!");
        return false;
    }
    status = napi_get_array_length(env, arg, &length);
    if (status != napi_ok || length == 0 || length > MAX_LEN_OF_ARRAY) {
        LOGE("array length is invalid!");
        return false;
    }
    return true;
}

static bool GetX509TrustAnchorArray(napi_env env, napi_value arg, HcfX509TrustAnchorArray *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_TRUSTANCHORS.c_str());
    if (obj == nullptr) {
        LOGE("param type not array!");
        return false;
    }

    uint32_t length;
    if (!GetArrayLength(env, obj, length)) {
        LOGE("get array length failed!");
        return false;
    }

    out = static_cast<HcfX509TrustAnchorArray *>(HcfMalloc(sizeof(HcfX509TrustAnchorArray), 0));
    if (out == nullptr) {
        LOGE("Failed to allocate out memory!");
        return false;
    }

    out->count = length;
    out->data = static_cast<HcfX509TrustAnchor **>(HcfMalloc(length * sizeof(HcfX509TrustAnchor *), 0));
    if (out->data == nullptr) {
        LOGE("Failed to allocate data memory!");
        CfFree(out);
        out = nullptr;
        return false;
    }
    for (uint32_t i = 0; i < length; ++i) {
        napi_value element;
        if (napi_get_element(env, obj, i, &element) != napi_ok) {
            LOGE("get element failed!");
            CfFree(out->data);
            CfFree(out);
            out = nullptr;
            return false;
        }

        if (!BuildX509TrustAnchorObj(env, element, out->data[i])) {
            LOGE("get element failed!");
            CfFree(out->data);
            CfFree(out);
            out = nullptr;
            return false;
        }
    }
    return true;
}

static bool GetCertCRLCollectionArray(napi_env env, napi_value arg, HcfCertCRLCollectionArray *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_CERTCRLS.c_str());
    if (obj == nullptr) {
        LOGI("prop certCRLs do not exist!");
        return true;
    }

    uint32_t length;
    if (!GetArrayLength(env, obj, length)) {
        LOGE("get array length failed!");
        return false;
    }

    out = static_cast<HcfCertCRLCollectionArray *>(HcfMalloc(sizeof(HcfCertCRLCollectionArray), 0));
    if (out == nullptr) {
        LOGE("Failed to allocate out memory!");
        return false;
    }
    out->count = length;
    out->data = static_cast<HcfCertCrlCollection **>(HcfMalloc(length * sizeof(HcfCertCrlCollection *), 0));
    if (out->data == nullptr) {
        LOGE("Failed to allocate data memory!");
        CfFree(out);
        out = nullptr;
        return false;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        napi_status status = napi_get_element(env, obj, i, &element);
        if (status != napi_ok) {
            LOGE("get element failed!");
            CfFree(out->data);
            CfFree(out);
            out = nullptr;
            return false;
        }
        NapiCertCRLCollection *napiCertCrlCollectionObj = nullptr;
        napi_unwrap(env, element, reinterpret_cast<void **>(&napiCertCrlCollectionObj));
        if (napiCertCrlCollectionObj == nullptr) {
            LOGE("napi cert crl collection object is nullptr!");
            CfFree(out->data);
            CfFree(out);
            out = nullptr;
            return false;
        }
        out->data[i] = napiCertCrlCollectionObj->GetCertCrlCollection();
    }
    return true;
}

void FreeX509CertChainValidateParams(HcfX509CertChainValidateParams &param)
{
    CfBlobFree(&param.date);
    if (param.trustAnchors != nullptr) {
        for (uint32_t i = 0; i < param.trustAnchors->count; ++i) {
            FreeX509TrustAnchorObj(param.trustAnchors->data[i]);
        }
        CfFree(param.trustAnchors);
        param.trustAnchors = nullptr;
    }

    if (param.certCRLCollections != nullptr) {
        CfFree(param.certCRLCollections->data);
        CfFree(param.certCRLCollections);
        param.certCRLCollections = nullptr;
    }
}

bool BuildX509CertChainValidateParams(napi_env env, napi_value arg, HcfX509CertChainValidateParams &param)
{
    napi_valuetype type;
    napi_typeof(env, arg, &type);
    if (type != napi_object) {
        LOGE("wrong argument type. expect string type. [Type]: %d", type);
        return false;
    }

    if (!GetValidDate(env, arg, param.date)) {
        LOGE("GetValidDate failed");
        return false;
    }
    if (!GetX509TrustAnchorArray(env, arg, param.trustAnchors)) {
        LOGE("GetX509TrustAnchorArray failed");
        return false;
    }
    if (!GetCertCRLCollectionArray(env, arg, param.certCRLCollections)) {
        LOGE("GetCertCRLCollectionArray failed");
        return false;
    }

    return true;
}

} // namespace CertFramework
} // namespace OHOS