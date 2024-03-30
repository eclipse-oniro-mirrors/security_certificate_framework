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

#ifndef NAPI_X509_CRL_ENTRY_H
#define NAPI_X509_CRL_ENTRY_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "x509_crl_entry.h"

namespace OHOS {
namespace CertFramework {
class NapiX509CrlEntry {
public:
    explicit NapiX509CrlEntry(HcfX509CrlEntry *x509CrlEntry);
    ~NapiX509CrlEntry();

    static void DefineX509CrlEntryJSClass(napi_env env, std::string className);
    static napi_value CreateX509CrlEntry(napi_env env, std::string className);

    napi_value GetEncoded(napi_env env, napi_callback_info info);
    napi_value GetCrlEntrySerialNumber(napi_env env, napi_callback_info info);
    napi_value GetCRLEntrySerialNumber(napi_env env, napi_callback_info info);
    napi_value GetCertificateIssuer(napi_env env, napi_callback_info info);
    napi_value GetRevocationDate(napi_env env, napi_callback_info info);
    napi_value GetExtensions(napi_env env, napi_callback_info info);
    napi_value HasExtensions(napi_env env, napi_callback_info info);
    napi_value ToString(napi_env env, napi_callback_info info);
    napi_value HashCode(napi_env env, napi_callback_info info);
    napi_value GetExtensionsObject(napi_env env, napi_callback_info info);
    napi_value GetCertIssuerX500DistinguishedName(napi_env env, napi_callback_info info);
    HcfX509CrlEntry *GetX509CrlEntry()
    {
        return x509CrlEntry_;
    }

    static thread_local napi_ref classCrlRef_;
    static thread_local napi_ref classCRLRef_;

private:
    HcfX509CrlEntry *x509CrlEntry_ = nullptr;
};
} // namespace CertFramework
} // namespace OHOS

#endif // NAPI_X509_CRL_ENTRY_H
