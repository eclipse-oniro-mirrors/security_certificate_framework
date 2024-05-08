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

#ifndef NAPI_X509_CERTIFICATE_H
#define NAPI_X509_CERTIFICATE_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "x509_certificate.h"
#include "cf_api.h"
#include "x509_cert_match_parameters.h"

namespace OHOS {
namespace CertFramework {
class NapiX509Certificate {
public:
    explicit NapiX509Certificate(HcfX509Certificate *x509Cert, CfObject *object);
    ~NapiX509Certificate();

    static void DefineX509CertJSClass(napi_env env, napi_value exports);
    static napi_value NapiCreateX509Cert(napi_env env, napi_callback_info info);
    static void CreateX509CertExecute(napi_env env, void *data);
    static void CreateX509CertComplete(napi_env env, napi_status status, void *data);
    static napi_value CreateX509Cert(napi_env env);

    napi_value Verify(napi_env env, napi_callback_info info);
    napi_value GetEncoded(napi_env env, napi_callback_info info);
    napi_value GetPublicKey(napi_env env, napi_callback_info info);
    napi_value CheckValidityWithDate(napi_env env, napi_callback_info info);
    napi_value GetVersion(napi_env env, napi_callback_info info);
    napi_value GetSerialNumber(napi_env env, napi_callback_info info);
    napi_value GetCertSerialNumber(napi_env env, napi_callback_info info);
    napi_value GetIssuerName(napi_env env, napi_callback_info info);
    napi_value GetSubjectName(napi_env env, napi_callback_info info);
    napi_value GetNotBeforeTime(napi_env env, napi_callback_info info);
    napi_value GetNotAfterTime(napi_env env, napi_callback_info info);
    napi_value GetSignature(napi_env env, napi_callback_info info);
    napi_value GetSigAlgName(napi_env env, napi_callback_info info);
    napi_value GetSigAlgOID(napi_env env, napi_callback_info info);
    napi_value GetSigAlgParams(napi_env env, napi_callback_info info);
    napi_value GetIssuerUniqueID(napi_env env, napi_callback_info info);
    napi_value GetSubjectUniqueID(napi_env env, napi_callback_info info);
    napi_value GetKeyUsage(napi_env env, napi_callback_info info);
    napi_value GetExtendedKeyUsage(napi_env env, napi_callback_info info);
    napi_value GetBasicConstraints(napi_env env, napi_callback_info info);
    napi_value GetSubjectAlternativeNames(napi_env env, napi_callback_info info);
    napi_value GetIssuerAlternativeNames(napi_env env, napi_callback_info info);
    napi_value Match(napi_env env, napi_callback_info info);
    napi_value ToString(napi_env env, napi_callback_info info);
    napi_value HashCode(napi_env env, napi_callback_info info);
    napi_value GetExtensionsObject(napi_env env, napi_callback_info info);
    napi_value GetIssuerX500DistinguishedName(napi_env env, napi_callback_info info);
    napi_value GetSubjectX500DistinguishedName(napi_env env, napi_callback_info info);
    napi_value GetCRLDistributionPointsURI(napi_env env, napi_callback_info info);
    CfResult MatchProc(HcfX509CertMatchParams *param, bool &boolFlag);

    HcfX509Certificate *GetX509Cert()
    {
        return x509Cert_;
    }

    CfObject *GetCertObject()
    {
        return certObject_;
    }

    static thread_local napi_ref classRef_;

private:
    HcfX509Certificate *x509Cert_ = nullptr;
    CfObject *certObject_ = nullptr;
};
} // namespace CertFramework
} // namespace OHOS

#endif // NAPI_X509_CERTIFICATE_H
