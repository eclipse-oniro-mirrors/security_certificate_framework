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

#ifndef NAPI_X509_CERT_MATCH_PARAMETERS_H
#define NAPI_X509_CERT_MATCH_PARAMETERS_H

#include "cf_blob.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_cert_defines.h"
#include "x509_cert_match_parameters.h"

namespace OHOS {
namespace CertFramework {

bool BuildX509CertMatchParams(napi_env env, napi_value arg, HcfX509CertMatchParams *&matchParams);
void FreeX509CertMatchParams(HcfX509CertMatchParams *matchParams);
void FreeX509CertMatchParamsInner(HcfX509CertMatchParams *matchParams);

} // namespace CertFramework
} // namespace OHOS
#endif // NAPI_X509_CERT_MATCH_PARAMETERS_H
