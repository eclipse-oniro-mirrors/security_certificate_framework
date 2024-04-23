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

#ifndef CF_NAPI_KEY_H
#define CF_NAPI_KEY_H

#include <cstdint>
#include "cf_log.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "key.h"

namespace OHOS {
namespace CertFramework {
class NapiKey {
public:
    explicit NapiKey(HcfKey *hcfKey);
    virtual ~NapiKey();
    HcfKey *GetHcfKey() const;

    static void DefineHcfKeyJSClass(napi_env env);
    static napi_value KeyConstructor(napi_env env, napi_callback_info info);

    static napi_value JsGetAlgorithm(napi_env env, napi_callback_info info);
    static napi_value JsGetEncoded(napi_env env, napi_callback_info info);
    static napi_value JsGetFormat(napi_env env, napi_callback_info info);

    static thread_local napi_ref classRef_;
protected:
    HcfKey *hcfKey_;
};
}  // namespace CertFramework
}  // namespace OHOS
#endif
