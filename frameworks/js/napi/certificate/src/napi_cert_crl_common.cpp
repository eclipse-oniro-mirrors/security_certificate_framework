/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "napi_cert_crl_common.h"

#include "cf_blob.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "config.h"
#include "securec.h"
#include "cipher.h"
#include "napi_cert_defines.h"
#include "napi_x509_certificate.h"
#include "napi_x509_crl.h"

namespace OHOS {
namespace CertFramework {

napi_value ConvertCertArrToNapiValue(napi_env env, HcfX509CertificateArray *certs)
{
    napi_value instance;
    napi_create_array(env, &instance);
    if (instance == nullptr) {
        LOGE("create return array failed!");
        return nullptr;
    }
    if (certs == nullptr) {
        LOGI("return emtpy erray!");
        return instance;
    }
    int j = 0;
    for (uint32_t i = 0; i < certs->count; ++i) {
        napi_value element = ConvertCertToNapiValue(env, certs->data[i]);
        if (element != nullptr) {
            napi_set_element(env, instance, j++, element);
        }
    }
    return instance;
}

napi_value ConvertCertToNapiValue(napi_env env, HcfX509Certificate *cert)
{
    if (cert == nullptr) {
        LOGE("ConvertCertToNapiValue:cert is nullptr.");
        return nullptr;
    }
    CfObject *certObj = nullptr;
    CfResult res = GetCertObject(cert, &certObj);
    if (res != CF_SUCCESS) {
        LOGE("GetCertObject failed.");
        return nullptr;
    }
    NapiX509Certificate *x509Cert = new (std::nothrow) NapiX509Certificate(cert, certObj);
    if (x509Cert == nullptr) {
        LOGE("new x509Cert failed!");
        certObj->destroy(&certObj);
        return nullptr;
    }
    napi_value instance = NapiX509Certificate::CreateX509Cert(env);
    napi_status status = napi_wrap(
        env, instance, x509Cert,
        [](napi_env env, void *data, void *hint) {
            NapiX509Certificate *certClass = static_cast<NapiX509Certificate *>(data);
            delete certClass;
            return;
        },
        nullptr, nullptr);
    if (status != napi_ok) {
        LOGE("failed to wrap NapiX509Certificate obj!");
        delete x509Cert;
        return nullptr;
    }
    return instance;
}

bool GetArrayCertFromNapiValue(napi_env env, napi_value object, HcfX509CertificateArray *certs, bool allowEmptyFlag)
{
    bool flag = false;
    napi_status status = napi_is_array(env, object, &flag);
    if (status != napi_ok || !flag) {
        LOGE("not array!");
        return false;
    }
    uint32_t length;
    status = napi_get_array_length(env, object, &length);
    if (status != napi_ok || length == 0) {
        LOGI("array length is invalid!");
        return allowEmptyFlag;
    }
    if (length > MAX_LEN_OF_ARRAY) {
        LOGE("array length is invalid!");
        return false;
    }

    certs->data = static_cast<HcfX509Certificate **>(CfMalloc(length * sizeof(HcfX509Certificate *), 0));
    if (certs->data == nullptr) {
        LOGE("malloc failed");
        return false;
    }
    certs->count = length;
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        status = napi_get_element(env, object, i, &element);
        if (status != napi_ok) {
            LOGE("get element failed!");
            CF_FREE_PTR(certs->data);
            return false;
        }
        NapiX509Certificate *napiCertObj = nullptr;
        napi_unwrap(env, element, reinterpret_cast<void **>(&napiCertObj));
        if (napiCertObj == nullptr) {
            LOGE("napi cert object is nullptr!");
            CF_FREE_PTR(certs->data);
            return false;
        }
        certs->data[i] = napiCertObj->GetX509Cert();
    }
    return true;
}

bool GetArrayCRLFromNapiValue(napi_env env, napi_value object, HcfX509CrlArray *crls, bool allowEmptyFlag)
{
    napi_valuetype valueType;
    napi_typeof(env, object, &valueType);
    if (valueType == napi_undefined) {
        LOGI("crl list is undefined.");
        return true;
    }
    bool flag = false;
    napi_status status = napi_is_array(env, object, &flag);
    if (status != napi_ok || !flag) {
        LOGE("not array!");
        return false;
    }
    uint32_t length;
    status = napi_get_array_length(env, object, &length);
    if (status != napi_ok || length == 0) { /* empty arr is ok */
        LOGI("array length = 0!");
        return allowEmptyFlag;
    }
    if (length > MAX_LEN_OF_ARRAY) {
        LOGE("array length is invalid!");
        return false;
    }
    crls->data = static_cast<HcfX509Crl **>(CfMalloc(length * sizeof(HcfX509Crl *), 0));
    if (crls->data == nullptr) {
        LOGE("malloc failed");
        return false;
    }
    crls->count = length;
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        status = napi_get_element(env, object, i, &element);
        if (status != napi_ok) {
            LOGE("get element failed!");
            CF_FREE_PTR(crls->data);
            return false;
        }
        NapiX509Crl *napiCrlObj = nullptr;
        napi_unwrap(env, element, reinterpret_cast<void **>(&napiCrlObj));
        if (napiCrlObj == nullptr) {
            LOGE("napi cert object is nullptr!");
            CF_FREE_PTR(crls->data);
            return false;
        }
        crls->data[i] = napiCrlObj->GetX509Crl();
    }
    return true;
}

CfResult GetCertObject(HcfX509Certificate *x509Cert, CfObject **out)
{
    CfEncodingBlob encodingBlob = { 0 };
    CfResult res = x509Cert->base.getEncoded(&(x509Cert->base), &encodingBlob);
    if (res != CF_SUCCESS) {
        LOGE("Failed to getEncoded!");
        return res;
    }
    res = static_cast<CfResult>(CfCreate(CF_OBJ_TYPE_CERT, &encodingBlob, out));
    if (res != CF_SUCCESS) {
        LOGE("Failed to CfCreate!");
        CF_FREE_PTR(encodingBlob.data);
        return res;
    }
    CF_FREE_PTR(encodingBlob.data);
    return CF_SUCCESS;
}

} // namespace CertFramework
} // namespace OHOS
