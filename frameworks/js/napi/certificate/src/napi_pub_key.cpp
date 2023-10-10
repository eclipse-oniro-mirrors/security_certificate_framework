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

#include "napi_pub_key.h"

#include "cf_log.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "securec.h"
#include "blob.h"
#include "result.h"

namespace OHOS {
namespace CertFramework {
thread_local napi_ref NapiPubKey::classRef_ = nullptr;

NapiPubKey::NapiPubKey(HcfPubKey *pubKey) : NapiKey(reinterpret_cast<HcfKey *>(pubKey)) {}

NapiPubKey::~NapiPubKey() {}

__attribute__((no_sanitize("cfi"))) HcfPubKey *NapiPubKey::GetPubKey()
{
    return reinterpret_cast<HcfPubKey *>(NapiKey::GetHcfKey());
}

napi_value NapiPubKey::PubKeyConstructor(napi_env env, napi_callback_info info)
{
    LOGI("enter ...");

    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

    LOGI("out ...");
    return thisVar;
}

napi_value NapiPubKey::ConvertToJsPubKey(napi_env env)
{
    LOGI("enter ...");

    napi_value instance;
    napi_value constructor = nullptr;
    napi_get_reference_value(env, classRef_, &constructor);
    napi_new_instance(env, constructor, 0, nullptr, &instance);

    const char *algName = this->GetPubKey()->base.getAlgorithm(&(this->GetPubKey()->base));
    const char *format = this->GetPubKey()->base.getFormat(&(this->GetPubKey()->base));

    napi_value napiAlgName = nullptr;
    napi_create_string_utf8(env, algName, NAPI_AUTO_LENGTH, &napiAlgName);
    napi_set_named_property(env, instance, CRYPTO_TAG_ALG_NAME.c_str(), napiAlgName);

    napi_value napiFormat = nullptr;
    napi_create_string_utf8(env, format, NAPI_AUTO_LENGTH, &napiFormat);
    napi_set_named_property(env, instance, CRYPTO_TAG_FORMAT.c_str(), napiFormat);

    LOGI("out ...");
    return instance;
}

napi_value NapiPubKey::JsGetEncoded(napi_env env, napi_callback_info info)
{
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
    NapiPubKey *napiPubKey = nullptr;
    napi_unwrap(env, thisVar, reinterpret_cast<void **>(&napiPubKey));

    HcfPubKey *pubKey = napiPubKey->GetPubKey();
    HcfBlob returnBlob = { nullptr, 0 };
    HcfResult res = pubKey->base.getEncoded(&pubKey->base, &returnBlob);
    if (res != HCF_SUCCESS) {
        LOGE("c getEncoded fail.");
        return nullptr;
    }
    CfBlob tmpCfBlob = { returnBlob.len, returnBlob.data };
    napi_value instance = ConvertBlobToNapiValue(env, &tmpCfBlob);
    HcfBlobDataFree(&returnBlob);
    return instance;
}

void NapiPubKey::DefinePubKeyJSClass(napi_env env)
{
    napi_property_descriptor classDesc[] = {
        DECLARE_NAPI_FUNCTION("getEncoded", NapiPubKey::JsGetEncoded),
    };
    napi_value constructor = nullptr;
    napi_define_class(env, "PubKey", NAPI_AUTO_LENGTH, NapiPubKey::PubKeyConstructor, nullptr,
        sizeof(classDesc) / sizeof(classDesc[0]), classDesc, &constructor);
    napi_create_reference(env, constructor, 1, &classRef_);
}
} // CertFramework
} // OHOS
