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

#include "napi_x509_cert_chain_validate_result.h"

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_type.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_cert_crl_collection.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_cert_crl_common.h"
#include "napi_object.h"
#include "napi_x509_trust_anchor.h"
#include "napi_x509_certificate.h"
#include "utils.h"
#include "x509_cert_chain_validate_result.h"

namespace OHOS {
namespace CertFramework {

napi_value BuildX509CertChainValidateResultJS(napi_env env, const HcfX509CertChainValidateResult *result)
{
    napi_value trustAnchor = BuildX509TrustAnchorJS(env, result->trustAnchor);
    if (trustAnchor == nullptr) {
        LOGE("trustAnchor is nullptr");
        return nullptr;
    }

    napi_value entityCert = ConvertCertToNapiValue(env, result->entityCert);
    if (entityCert == nullptr) {
        LOGE("entityCert is nullptr");
        return nullptr;
    }

    napi_value returnValue = nullptr;
    napi_create_object(env, &returnValue);
    napi_set_named_property(env, returnValue, CERT_CHAIN_VALIDATE_RESULLT_TAG_X509CERT.c_str(), entityCert);
    napi_set_named_property(env, returnValue, CERT_CHAIN_VALIDATE_RESULLT_TAG_TRUSTANCHOR.c_str(), trustAnchor);

    return returnValue;
}

/* [freeCertFlag] : if building a obj for return failed, the cert object need to free manually. */
void FreeX509CertChainValidateResult(HcfX509CertChainValidateResult &param, bool freeCertFlag)
{
    if (param.trustAnchor != nullptr) {
        FreeX509TrustAnchorObj(param.trustAnchor, freeCertFlag);
    }
    if (freeCertFlag) {
        CfObjDestroy(param.entityCert);
    }
    param.entityCert = nullptr;
}
} // namespace CertFramework
} // namespace OHOS