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

#ifndef NAPI_X509_CRL_H
#define NAPI_X509_CRL_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "x509_crl.h"
#include "x509_crl_match_parameters.h"

namespace OHOS {
namespace CertFramework {
class NapiX509Crl {
public:
    explicit NapiX509Crl(HcfX509Crl *x509Crl);
    ~NapiX509Crl();

    static void DefineX509CrlJSClass(napi_env env, napi_value exports, std::string className);
    static void DefineX509CrlJS(napi_env env, napi_value exports, std::string className);
    static void DefineX509CRLJS(napi_env env, napi_value exports, std::string className);
    static napi_value NapiCreateX509CrlBase(napi_env env, napi_callback_info info, std::string createName);
    static napi_value NapiCreateX509Crl(napi_env env, napi_callback_info info);
    static napi_value NapiCreateX509CRL(napi_env env, napi_callback_info info);
    static void CreateX509CrlExecute(napi_env env, void *data);
    static void CreateX509CrlComplete(napi_env env, napi_status status, void *data);
    static napi_value CreateX509Crl(napi_env env, std::string createName);

    napi_value IsRevoked(napi_env env, napi_callback_info info);
    napi_value GetType(napi_env env, napi_callback_info info);
    napi_value GetEncoded(napi_env env, napi_callback_info info);
    napi_value Verify(napi_env env, napi_callback_info info);
    napi_value GetVersion(napi_env env, napi_callback_info info);
    napi_value GetIssuerDN(napi_env env, napi_callback_info info);
    napi_value GetThisUpdate(napi_env env, napi_callback_info info);
    napi_value GetNextUpdate(napi_env env, napi_callback_info info);
    napi_value GetRevokedCertificate(napi_env env, napi_callback_info info, std::string returnClassName);
    napi_value GetRevokedCertificateWithCert(napi_env env, napi_callback_info info, std::string returnClassName);
    napi_value GetRevokedCertificates(napi_env env, napi_callback_info info, std::string returnClassName);
    napi_value GetTBSCertList(napi_env env, napi_callback_info info);
    napi_value GetSignature(napi_env env, napi_callback_info info);
    napi_value GetSigAlgName(napi_env env, napi_callback_info info);
    napi_value GetSigAlgOID(napi_env env, napi_callback_info info);
    napi_value GetSigAlgParams(napi_env env, napi_callback_info info);
    napi_value GetExtensions(napi_env env, napi_callback_info info);
    napi_value ToString(napi_env env, napi_callback_info info);
    napi_value HashCode(napi_env env, napi_callback_info info);
    napi_value GetExtensionsObject(napi_env env, napi_callback_info info);
    napi_value GetIssuerX500DistinguishedName(napi_env env, napi_callback_info info);
    napi_value Match(napi_env env, napi_callback_info info);
    CfResult MatchProc(HcfX509CrlMatchParams *param, bool &boolFlag);

    HcfX509Crl *GetX509Crl()
    {
        return x509Crl_;
    }

    static thread_local napi_ref classCrlRef_;
    static thread_local napi_ref classCRLRef_;

private:
    HcfX509Crl *x509Crl_ = nullptr;
};
} // namespace CertFramework
} // namespace OHOS

#endif // NAPI_X509_CRL_H
