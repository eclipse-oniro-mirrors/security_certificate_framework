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

#ifndef NAPI_CERT_CRL_COMMON_H
#define NAPI_CERT_CRL_COMMON_H

#include <cstdint>
#include <string>

#include "cf_blob.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_cert_defines.h"
#include "x509_certificate.h"
#include "x509_crl.h"
#include "cf_api.h"

namespace OHOS {
namespace CertFramework {

napi_value ConvertCertArrToNapiValue(napi_env env, HcfX509CertificateArray *certs);
napi_value ConvertCertToNapiValue(napi_env env, HcfX509Certificate *certs);
bool GetArrayCertFromNapiValue(
    napi_env env, napi_value object, HcfX509CertificateArray *certs, bool allowEmptyFlag = true);
bool GetArrayCRLFromNapiValue(napi_env env, napi_value object, HcfX509CrlArray *crls, bool allowEmptyFlag = true);
CfResult GetCertObject(HcfX509Certificate *x509Cert, CfObject **out);
} // namespace CertFramework
} // namespace OHOS
#endif // NAPI_CERT_CRL_COMMON_H
