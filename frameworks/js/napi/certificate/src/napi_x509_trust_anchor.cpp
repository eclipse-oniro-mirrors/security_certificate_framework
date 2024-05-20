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

#include "napi_x509_trust_anchor.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_type.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_cert_crl_common.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_object.h"
#include "napi_x509_certificate.h"
#include "utils.h"

namespace OHOS {
namespace CertFramework {

static bool GetCACert(napi_env env, napi_value arg, HcfX509Certificate *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_TRUSTANCHOR_TAG_CACERT.c_str());
    if (obj == nullptr) {
        return true;
    }
    NapiX509Certificate *napiX509Cert = nullptr;
    napi_unwrap(env, obj, reinterpret_cast<void **>(&napiX509Cert));
    if (napiX509Cert == nullptr) {
        LOGE("napiX509Cert is null!");
        return false;
    }

    out = napiX509Cert->GetX509Cert();
    if (out == nullptr) {
        LOGE("out is null!");
        return false;
    }
    return true;
}

static bool GetCASubject(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_TRUSTANCHOR_TAG_CASUBJECT.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetBlobFromUint8ArrJSParams(env, obj);
    if (out == nullptr) {
        LOGE("out is null!");
        return false;
    }
    return true;
}

static bool GetNameConstraints(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_MATCH_TAG_NAME_CONSTRAINTS.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetBlobFromUint8ArrJSParams(env, obj);
    if (out == nullptr) {
        LOGE("out is null!");
        return false;
    }
    return true;
}

static bool GetCAPubKey(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_TRUSTANCHOR_TAG_CAPUBKEY.c_str());
    if (obj == nullptr) {
        return true;
    }
    out = CertGetBlobFromUint8ArrJSParams(env, obj);
    if (out == nullptr) {
        LOGE("out is null!");
        return false;
    }
    return true;
}

napi_value BuildX509TrustAnchorJS(napi_env env, const HcfX509TrustAnchor *trustAnchor)
{
    if (trustAnchor == nullptr) {
        LOGE("input param invalid!");
        return nullptr;
    }
    napi_value instance = nullptr;
    napi_create_object(env, &instance);
    if (trustAnchor->CAPubKey != nullptr) {
        napi_value CAPubKey = ConvertBlobToUint8ArrNapiValue(env, trustAnchor->CAPubKey);
        if (CAPubKey == nullptr) {
            LOGE("CA pub key convert failed!");
            return nullptr;
        }
        napi_set_named_property(env, instance, CERT_CHAIN_TRUSTANCHOR_TAG_CAPUBKEY.c_str(), CAPubKey);
    }

    if (trustAnchor->CASubject != nullptr) {
        napi_value CASubject = ConvertBlobToUint8ArrNapiValue(env, trustAnchor->CASubject);
        if (CASubject == nullptr) {
            LOGE("CA subject convert failed!");
            return nullptr;
        }
        napi_set_named_property(env, instance, CERT_CHAIN_TRUSTANCHOR_TAG_CASUBJECT.c_str(), CASubject);
    }

    if (trustAnchor->CACert != nullptr) {
        napi_value CACert = ConvertCertToNapiValue(env, trustAnchor->CACert);
        if (CACert == nullptr) {
            LOGE("CA cert convert failed!");
            return nullptr;
        }
        napi_set_named_property(env, instance, CERT_CHAIN_TRUSTANCHOR_TAG_CACERT.c_str(), CACert);
    }

    if (trustAnchor->nameConstraints != nullptr) {
        napi_value nameConstraints = ConvertBlobToUint8ArrNapiValue(env, trustAnchor->nameConstraints);
        if (nameConstraints == nullptr) {
            LOGE("Name constraints convert failed!");
            return nullptr;
        }
        napi_set_named_property(env, instance, CERT_MATCH_TAG_NAME_CONSTRAINTS.c_str(), nameConstraints);
    }

    return instance;
}

bool BuildX509TrustAnchorObj(napi_env env, napi_value arg, HcfX509TrustAnchor *&trustAnchor)
{
    napi_valuetype type;
    napi_typeof(env, arg, &type);
    if (type != napi_object) {
        LOGE("wrong argument type. expect string type. [Type]: %d", type);
        return false;
    }
    trustAnchor = static_cast<HcfX509TrustAnchor *>(CfMalloc(sizeof(HcfX509TrustAnchor), 0));
    if (trustAnchor == nullptr) {
        LOGE("Failed to allocate data memory!");
        return false;
    }

    if (!GetCAPubKey(env, arg, trustAnchor->CAPubKey)) {
        FreeX509TrustAnchorObj(trustAnchor);
        return false;
    }
    if (!GetCACert(env, arg, trustAnchor->CACert)) {
        FreeX509TrustAnchorObj(trustAnchor);
        return false;
    }
    if (!GetCASubject(env, arg, trustAnchor->CASubject)) {
        FreeX509TrustAnchorObj(trustAnchor);
        return false;
    }
    if (!GetNameConstraints(env, arg, trustAnchor->nameConstraints)) {
        FreeX509TrustAnchorObj(trustAnchor);
        return false;
    }
    return true;
}

/* [freeCertFlag] : if building a obj for RETURN failed, the cert object need to free manually. */
void FreeX509TrustAnchorObj(HcfX509TrustAnchor *&trustAnchor, bool freeCertFlag)
{
    if (trustAnchor == nullptr) {
        return;
    }
    CfBlobFree(&trustAnchor->CAPubKey);
    CfBlobFree(&trustAnchor->CASubject);
    CfBlobFree(&trustAnchor->nameConstraints);
    if (freeCertFlag) {
        CfObjDestroy(trustAnchor->CACert);
    }
    trustAnchor->CACert = nullptr;

    CF_FREE_PTR(trustAnchor);
}

} // namespace CertFramework
} // namespace OHOS
