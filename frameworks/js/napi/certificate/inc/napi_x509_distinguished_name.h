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

#ifndef NAPI_X509_DISTINGUISHED_NAME_H
#define NAPI_X509_DISTINGUISHED_NAME_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "x509_distinguished_name.h"

namespace OHOS {
namespace CertFramework {
class NapiX509DistinguishedName {
public:
    explicit NapiX509DistinguishedName(HcfX509DistinguishedName *x509Name_);
    ~NapiX509DistinguishedName();

    static void DefineX509DistinguishedNameJSClass(napi_env env, napi_value exports);
    static napi_value NapiCreateX509DistinguishedName(napi_env env, napi_callback_info info);
    static void CreateDistinguishedNameExecute(napi_env env, void *data);
    static void CreateDistinguishedNameComplete(napi_env env, napi_status status, void *data);
    static napi_value CreateX509DistinguishedName(napi_env env);

    napi_value GetName(napi_env env, napi_callback_info info);
    napi_value GetEncoded(napi_env env, napi_callback_info info);
    HcfX509DistinguishedName *GetX509DistinguishedName()
    {
        return x509Name_;
    }

    static thread_local napi_ref classRef_;

private:
    HcfX509DistinguishedName *x509Name_ = nullptr;
};
} // namespace CertFramework
} // namespace OHOS

#endif // NAPI_X509_DISTINGUISHED_NAME_H
