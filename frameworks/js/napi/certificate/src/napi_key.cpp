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

#include "napi_key.h"

#include "securec.h"
#include "cf_log.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "blob.h"
#include "result.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiKey::classRef_ = nullptr;

NapiKey::NapiKey(HcfKey *hcfKey)
{
    this->hcfKey_ = hcfKey;
}

NapiKey::~NapiKey() {}

HcfKey *NapiKey::GetHcfKey() const
{
    return this->hcfKey_;
}

napi_value NapiKey::JsGetAlgorithm(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiKey *napiKey = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));

    NAPI_CALL(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKey)));
    HcfKey *key = napiKey->GetHcfKey();

    const char *algo = key->getAlgorithm(key);
    napi_value instance = nullptr;
    napi_create_string_utf8(env, algo, NAPI_AUTO_LENGTH, &instance);
    return instance;
}

napi_value NapiKey::JsGetFormat(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiKey *napiKey = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));

    NAPI_CALL(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKey)));
    HcfKey *key = napiKey->GetHcfKey();

    const char *format = key->getFormat(key);
    napi_value instance = nullptr;
    napi_create_string_utf8(env, format, NAPI_AUTO_LENGTH, &instance);
    return instance;
}

napi_value NapiKey::JsGetEncoded(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    NapiKey *napiKey = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr));

    NAPI_CALL(env, napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiKey)));
    HcfKey *key = napiKey->GetHcfKey();

    HcfBlob blob = { nullptr, 0 };
    HcfResult res = key->getEncoded(key, &blob);
    if (res != HCF_SUCCESS) {
        napi_throw(env, CertGenerateBusinessError(env, res, "getEncoded failed."));
        LOGE("getEncoded failed!");
        return nullptr;
    }
    CfBlob tmpCfBlob = { blob.len, blob.data };
    napi_value instance = ConvertBlobToNapiValue(env, &tmpCfBlob);
    HcfBlobDataFree(&blob);
    return instance;
}

napi_value NapiKey::KeyConstructor(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    return thisVar;
}

void NapiKey::DefineHcfKeyJSClass(napi_env env)
{
    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("getEncoded", NapiKey::JsGetEncoded),
        {.utf8name = "format", .getter = NapiKey::JsGetFormat},
        {.utf8name = "algName", .getter = NapiKey::JsGetAlgorithm},
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "HcfKey", NAPI_AUTO_LENGTH, KeyConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CertFramework
} // OHOS