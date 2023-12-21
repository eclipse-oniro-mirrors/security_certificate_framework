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

#include "napi_x509_crl_match_parameters.h"
#include "napi_x509_certificate.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_type.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_object.h"
#include "utils.h"

namespace OHOS {
namespace CertFramework {

static bool GetIssuer(napi_env env, napi_value arg, CfBlobArray *&out)
{
    napi_value obj = GetProp(env, arg, CRL_MATCH_TAG_PRIVATE_KEY_VALID.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetBlobArrFromArrUarrJSParams(env, obj);
    if (out == nullptr) {
        LOGE("out is nullptr");
        return false;
    }
    return true;
}

static bool GetX509Cert(napi_env env, napi_value arg, HcfCertificate *&out)
{
    napi_value obj = GetProp(env, arg, CRL_MATCH_TAG_X509CERT.c_str());
    if (obj == nullptr) {
        return true;
    }
    NapiX509Certificate *napiX509Cert = nullptr;
    napi_unwrap(env, obj, reinterpret_cast<void **>(&napiX509Cert));
    if (napiX509Cert == nullptr) {
        LOGE("napiX509Cert is null!");
        return false;
    }

    HcfX509Certificate *cert = napiX509Cert->GetX509Cert();
    if (cert == nullptr) {
        LOGE("cert is null!");
        return false;
    }
    LOGI("x509Cert is not null!");
    out = &(cert->base);

    return true;
}

bool BuildX509CrlMatchParams(napi_env env, napi_value arg, HcfX509CrlMatchParams *&matchParams)
{
    napi_valuetype type;
    napi_typeof(env, arg, &type);
    if (type != napi_object) {
        LOGE("wrong argument type. expect object type. [Type]: %d", type);
        return false;
    }
    if (!GetX509Cert(env, arg, matchParams->x509Cert)) {
        return false;
    }
    if (!GetIssuer(env, arg, matchParams->issuer)) {
        return false;
    }
    return true;
}

void FreeX509CrlMatchParams(HcfX509CrlMatchParams *&matchParams)
{
    if (matchParams == nullptr) {
        return;
    }

    if (matchParams->issuer != nullptr) {
        FreeCfBlobArray(matchParams->issuer->data, matchParams->issuer->count);
        CF_FREE_PTR(matchParams->issuer);
    }
    matchParams->x509Cert = nullptr;

    CF_FREE_PTR(matchParams);
}

} // namespace CertFramework
} // namespace OHOS