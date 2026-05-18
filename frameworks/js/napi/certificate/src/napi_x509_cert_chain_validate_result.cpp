/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
    if (returnValue == nullptr) {
        LOGE("create result obj failed");
        return nullptr;
    }
    napi_set_named_property(env, returnValue, CERT_CHAIN_VALIDATE_RESULT_TAG_X509CERT.c_str(), entityCert);
    napi_set_named_property(env, returnValue, CERT_CHAIN_VALIDATE_RESULT_TAG_TRUSTANCHOR.c_str(), trustAnchor);

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

CfResult BuildVerifyCertResultJS(napi_env env, HcfVerifyCertResult *result,
    CfObject **certObj, uint32_t certObjCount, napi_value *outValue)
{
    if (result == nullptr || result->certs.data == nullptr || certObj == nullptr || outValue == nullptr) {
        LOGE("result, certs.data, certObj or outValue is nullptr");
        return CF_INVALID_PARAMS;
    }
    if (result->certs.count != certObjCount) {
        LOGE("certs count mismatch: %{public}u vs %{public}u", result->certs.count, certObjCount);
        return CF_INVALID_PARAMS;
    }

    napi_value certChainArray = nullptr;
    napi_create_array(env, &certChainArray);
    if (certChainArray == nullptr) {
        LOGE("create certChain array failed");
        return CF_ERR_NAPI;
    }

    for (uint32_t i = 0; i < result->certs.count; i++) {
        napi_value napiCert = nullptr;
        CfResult ret = ConvertCertToNapiValueEx(env, &result->certs.data[i], &certObj[i], &napiCert);
        if (ret != CF_SUCCESS || napiCert == nullptr) {
            LOGE("convert cert to napi value failed at index %{public}u", i);
            /* Note: ownership of previously converted certs has been transferred to certChainArray.
             * certChainArray will be garbage collected by JS engine since it's not returned. */
            return ret;
        }
        napi_status status = napi_set_element(env, certChainArray, i, napiCert);
        if (status != napi_ok) {
            LOGE("set element to array failed at index %{public}u", i);
            /* Ownership already transferred to napiCert, it will be garbage collected. */
            return CF_ERR_NAPI;
        }
    }

    napi_value returnValue = nullptr;
    napi_create_object(env, &returnValue);
    if (returnValue == nullptr) {
        LOGE("create result obj failed");
        return CF_ERR_NAPI;
    }
    napi_status status = napi_set_named_property(env, returnValue,
        CERT_VALIDATION_RESULT_TAG_CERTCHAIN.c_str(), certChainArray);
    if (status != napi_ok) {
        LOGE("set named property failed");
        return CF_ERR_NAPI;
    }

    *outValue = returnValue;
    return CF_SUCCESS;
}

void FreeVerifyCertResult(HcfVerifyCertResult &param, CfObject **certObj, uint32_t certObjCount)
{
    if (param.certs.data != nullptr) {
        for (uint32_t i = 0; i < param.certs.count; i++) {
            /* Always destroy if not null (ownership not transferred) */
            if (param.certs.data[i] != nullptr) {
                CfObjDestroy(param.certs.data[i]);
                param.certs.data[i] = nullptr;
            }
        }
        CfFree(param.certs.data);
        param.certs.data = nullptr;
    }
    param.certs.count = 0;

    /* Free certObj array */
    if (certObj != nullptr) {
        for (uint32_t i = 0; i < certObjCount; i++) {
            if (certObj[i] != nullptr) {
                certObj[i]->destroy(&certObj[i]);
            }
        }
        CfFree(certObj);
    }
}

} // namespace CertFramework
} // namespace OHOS